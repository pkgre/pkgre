//! Deterministic end-to-end coverage for the complete update admission workflow.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use flate2::{Compression, write::GzEncoder};
use semver::Version;
use serde_json::json;

use super::inspect::InspectionResolver;
use super::workflow::PlannerResolver;
use super::{
    ApprovalKind, SourceEvidence, UtcTimestamp, apply::apply_update_plan_with, approve_update_plan,
    inspect::inspect_update_candidate_with, validate_admission_inventory,
    workflow::plan_exact_update_with,
};
use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::import::{CratesIoHistory, SparseIndexRow};
use crate::index::IndexRecord;
use crate::lock::{self, ReconcileSummary, ResolvedPackage, Resolver};
use crate::policy::validate_catalog;
use crate::schema::{Catalog, LockedSource, Source};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn exact_update_lifecycle_is_inert_evidence_bound_and_convergent() {
    let temporary = TemporaryDirectory::new("pkgre-update-e2e-success");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["demo"]);
    assert_eq!(
        lock::reconcile(&catalog_root).unwrap(),
        ReconcileSummary {
            changed: true,
            names_added: 9,
            ..ReconcileSummary::default()
        }
    );

    let marker = temporary.path().join("archive-code-must-not-run");
    let fixture = malicious_build_fixture(&marker);
    let version = Version::parse("1.0.0").unwrap();
    let approved_path =
        prepare_approved_plan(temporary.path(), &catalog_root, &fixture, &version, &marker);
    let admitted_at = UtcTimestamp::now().unwrap();
    let summary = apply_update_plan_with(
        &catalog_root,
        &approved_path,
        &fixture,
        &fixture,
        &admitted_at,
    )
    .unwrap();
    assert_eq!(
        summary,
        ReconcileSummary {
            changed: true,
            packages_added: 1,
            ..ReconcileSummary::default()
        }
    );
    assert_eq!(fixture.lock_calls.get(), 1);

    assert_admitted_catalog(&catalog_root, &fixture, &version);
    assert_render_and_lock_convergence(&catalog_root, &temporary.path().join("site"));
    assert!(!marker.exists());
}

fn malicious_build_fixture(marker: &Path) -> FixtureResolver {
    let payload = format!(
        "fn main() {{ std::fs::write({:?}, b\"executed\").unwrap(); }}\n",
        marker.display().to_string()
    );
    FixtureResolver::new(vec![FixturePackage::new(
        "demo",
        "1.0.0",
        "build.rs",
        payload.as_bytes(),
    )])
}

fn prepare_approved_plan(
    temporary: &Path,
    catalog_root: &Path,
    fixture: &FixtureResolver,
    version: &Version,
    marker: &Path,
) -> PathBuf {
    let plan_path = temporary.join("plan.toml");
    let plan = plan_exact_update_with(
        catalog_root,
        "demo",
        version,
        &plan_path,
        fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(fixture.source_calls.get(), 1);

    let review = temporary.join("review");
    inspect_update_candidate_with(&plan_path, "demo", version, &review, fixture).unwrap();
    assert!(!marker.exists());
    assert!(review.join("README.txt").is_file());
    assert!(review.join("inspection.toml").is_file());
    assert_eq!(
        fs::read(review.join("candidate.crate")).unwrap(),
        fixture.package("demo", version).unwrap().archive
    );
    assert!(!review.join("base.crate").exists());

    let note_path = temporary.join("review-note.txt");
    fs::write(
        &note_path,
        b"Reviewed every file in the checksum-bound candidate archive.\n",
    )
    .unwrap();
    let approved_path = temporary.join("approved.toml");
    let approved = approve_update_plan(
        &plan_path,
        &approved_path,
        "demo",
        version,
        ApprovalKind::FullArchive,
        &note_path,
    )
    .unwrap();
    assert_eq!(approved.candidates[0].approvals.len(), 1);
    approved_path
}

fn assert_admitted_catalog(root: &Path, fixture: &FixtureResolver, version: &Version) {
    let catalog = Catalog::load(root).unwrap();
    validate_catalog(&catalog).unwrap();
    ArtifactMap::load(&catalog).unwrap();
    validate_admission_inventory(&catalog).unwrap();
    assert_eq!(catalog.approvals.len(), 1);
    let locked = &catalog.approvals[0];
    let package = fixture.package("demo", version).unwrap();
    assert_eq!(locked.registry, "universe");
    assert_eq!(locked.category.to_string(), "universe/general");
    assert_eq!(locked.archive_sha256, sha256_bytes(&package.archive));
    assert_eq!(
        locked.index_record_sha256,
        sha256_bytes(&package.source_row)
    );
    assert!(matches!(locked.source, Source::CratesIo));
    assert_eq!(
        fs::read(
            root.join("objects/rows")
                .join(format!("{}.json", locked.index_record_sha256))
        )
        .unwrap(),
        package.source_row
    );
    assert_eq!(
        fs::read_dir(root.join("objects/crates")).unwrap().count(),
        0,
        "mirror archives must not be retained in the catalog"
    );
    assert_eq!(
        fs::read_dir(root.join("_reviews/admissions"))
            .unwrap()
            .count(),
        1
    );
    assert!(
        fs::read_to_string(root.join("universe.toml"))
            .unwrap()
            .contains("demo = [\"1.0.0\"]")
    );
}

fn assert_render_and_lock_convergence(root: &Path, site: &Path) {
    let catalog = Catalog::load(root).unwrap();
    let artifacts = ArtifactMap::load(&catalog).unwrap();
    crate::render::render(&catalog, &artifacts, site).unwrap();
    crate::render::verify(&catalog, &artifacts, site).unwrap();

    let fingerprint = super::catalog_fingerprint(root).unwrap();
    assert_eq!(lock::reconcile(root).unwrap(), ReconcileSummary::default());
    assert_eq!(super::catalog_fingerprint(root).unwrap(), fingerprint);
}

#[derive(Clone)]
struct FixturePackage {
    name: String,
    version: Version,
    archive: Vec<u8>,
    source_row: Vec<u8>,
    history: CratesIoHistory,
}

impl FixturePackage {
    fn new(name: &str, version: &str, file: &str, contents: &[u8]) -> Self {
        let version = Version::parse(version).unwrap();
        let archive = crate_archive(name, &version, file, contents);
        let checksum = sha256_bytes(&archive);
        let mut source_row = serde_json::to_vec(&json!({
            "name": name,
            "vers": version.to_string(),
            "deps": [],
            "cksum": checksum,
            "features": {},
            "yanked": false,
            "pubtime": "2020-01-01T00:00:00Z",
        }))
        .unwrap();
        source_row.push(b'\n');
        let record = IndexRecord::parse(&source_row).unwrap();
        record.validate_structure().unwrap();
        let history = CratesIoHistory {
            bytes: source_row.clone(),
            sha256: sha256_bytes(&source_row),
            rows: vec![SparseIndexRow {
                bytes: source_row.clone(),
                record,
            }],
        };
        Self {
            name: name.to_owned(),
            version,
            archive,
            source_row,
            history,
        }
    }
}

struct FixtureResolver {
    packages: BTreeMap<(String, Version), FixturePackage>,
    source_calls: Cell<usize>,
    lock_calls: Cell<usize>,
}

impl FixtureResolver {
    fn new(packages: Vec<FixturePackage>) -> Self {
        Self {
            packages: packages
                .into_iter()
                .map(|package| ((package.name.clone(), package.version.clone()), package))
                .collect(),
            source_calls: Cell::new(0),
            lock_calls: Cell::new(0),
        }
    }

    fn package(&self, name: &str, version: &Version) -> Result<&FixturePackage> {
        self.packages
            .get(&(name.to_owned(), version.clone()))
            .with_context(|| format!("fixture has no package {name} {version}"))
    }
}

impl PlannerResolver for FixtureResolver {
    fn history(&self, name: &str) -> Result<CratesIoHistory> {
        let mut matches = self
            .packages
            .values()
            .filter(|package| package.name == name);
        let package = matches
            .next()
            .with_context(|| format!("fixture has no history for {name}"))?;
        ensure!(
            matches.next().is_none(),
            "single-row fixture unexpectedly repeats package {name}"
        );
        Ok(package.history.clone())
    }

    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
        let package = self.package(name, version)?;
        ensure!(sha256_bytes(&package.archive) == checksum);
        Ok(package.archive.clone())
    }

    fn api(&self, _: &str) -> Result<Vec<u8>> {
        bail!("fixture intentionally has no crates.io API evidence")
    }

    fn source(
        &self,
        _: &super::ArchiveAnalysis,
        _: Option<&super::ApiVersionEvidence>,
    ) -> Result<SourceEvidence> {
        self.source_calls.set(self.source_calls.get() + 1);
        Ok(SourceEvidence::Unavailable {
            reason: "fixture-no-public-source".to_owned(),
        })
    }
}

impl InspectionResolver for FixtureResolver {
    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
        PlannerResolver::archive(self, name, version, checksum)
    }
}

impl Resolver for FixtureResolver {
    fn resolve_mirror(&self, name: &str, version: &Version) -> Result<ResolvedPackage> {
        self.lock_calls.set(self.lock_calls.get() + 1);
        let package = self.package(name, version)?;
        Ok(ResolvedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            archive_bytes: package.archive.clone(),
            source_row_bytes: package.source_row.clone(),
            source: LockedSource::CratesIo {},
        })
    }

    fn resolve_git_tag(&self, _: &str, _: &str, _: &str, _: &Version) -> Result<ResolvedPackage> {
        bail!("fixture does not resolve Git tags")
    }
}

fn write_catalog(root: &Path, general_names: &[&str]) {
    fs::create_dir_all(root).unwrap();
    let mut general_declarations = String::new();
    for name in general_names {
        writeln!(general_declarations, "{name} = []").unwrap();
    }
    let mut universe_categories = mirror_category(
        "general",
        &["universe/general"],
        &general_declarations,
        "reserved-general",
    );
    for (local, dependencies) in [
        ("acp", &["universe/acp", "universe/general"] as &[_]),
        (
            "filesystem",
            &["universe/filesystem", "universe/general"] as &[_],
        ),
        ("matrix", &["universe/matrix", "universe/general"] as &[_]),
        (
            "mcp",
            &["universe/mcp", "universe/sse", "universe/general"] as &[_],
        ),
        ("sse", &["universe/sse", "universe/general"] as &[_]),
        (
            "terminal",
            &["universe/terminal", "universe/general"] as &[_],
        ),
        ("yaml", &["universe/yaml", "universe/general"] as &[_]),
    ] {
        universe_categories.push_str(&mirror_category(
            local,
            dependencies,
            "",
            &format!("reserved-{local}"),
        ));
    }
    write_registry(
        root,
        "universe",
        crate::schema::MIRROR_DOWNLOAD,
        &universe_categories,
    );

    let pkgre_categories = concat!(
        "[categories.tooling]\n",
        "may-depend-on = [\"pkgre/tooling\", \"universe/general\"]\n\n",
        "[categories.tooling.publish.pkgre-category-anchor]\n",
        "git = \"https://github.com/pkgre/pkgre\"\n",
        "tags = []\n",
    );
    write_registry(
        root,
        "pkgre",
        crate::schema::PUBLISH_DOWNLOAD,
        pkgre_categories,
    );
}

fn mirror_category(
    local: &str,
    dependencies: &[&str],
    declarations: &str,
    fallback_name: &str,
) -> String {
    let dependencies = dependencies
        .iter()
        .map(|category| format!("\"{category}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let declarations = if declarations.trim().is_empty() {
        format!("{fallback_name} = []\n")
    } else {
        declarations.to_owned()
    };
    format!(
        "[categories.{local}]\nmay-depend-on = [{dependencies}]\n\n[categories.{local}.mirror]\n{declarations}\n"
    )
}

fn write_registry(root: &Path, name: &str, download: &str, categories: &str) {
    fs::write(
        root.join(format!("{name}.toml")),
        format!(
            "schema = 3\n\n[registry]\nname = {name:?}\nindex = \"sparse+https://rust.pkg.re/{name}/\"\ndownload = {download:?}\ncargo-version = \"1.95.0\"\n\n{categories}"
        ),
    )
    .unwrap();
}

fn crate_archive(name: &str, version: &Version, relative_path: &str, contents: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 512;
    let path = format!("{name}-{version}/{relative_path}");
    let mut header = [0_u8; BLOCK];
    set_string(&mut header[..100], &path);
    set_octal(&mut header[100..108], 0o644);
    set_octal(&mut header[108..116], 0);
    set_octal(&mut header[116..124], 0);
    set_octal(&mut header[124..136], contents.len() as u64);
    set_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    set_octal(&mut header[148..156], checksum);
    let mut tar = header.to_vec();
    tar.extend_from_slice(contents);
    tar.resize(tar.len() + (BLOCK - contents.len() % BLOCK) % BLOCK, 0);
    tar.resize(tar.len() + BLOCK * 2, 0);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

fn set_string(field: &mut [u8], value: &str) {
    assert!(value.len() < field.len());
    field[..value.len()].copy_from_slice(value.as_bytes());
}

fn set_octal(field: &mut [u8], value: u64) {
    let digits = format!("{:0width$o}", value, width = field.len() - 2);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[field.len() - 2] = 0;
    field[field.len() - 1] = b' ';
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
