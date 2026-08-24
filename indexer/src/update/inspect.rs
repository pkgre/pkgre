//! Inert materialization of exact admission-candidate archives and review evidence.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::Serialize;

use crate::import;

use super::workflow::{LivePlannerResolver, PlannerResolver, recompute_admission_plan_with};
use super::{
    AdmissionManifest, ArchiveAnalysis, ArchiveDelta, SourceEvidence, UpdateCandidate, UpdatePlan,
    UtcTimestamp, candidate_facts_sha256, compare_archive_analyses, inspect_crate_archive,
    load_admission_manifest,
};

const INSPECTION_SCHEMA: u32 = 1;
const README: &str = "pkgre inert admission inspection\n\nThe .crate files are untrusted upstream input retained for human review.\nDo not execute package files, build scripts, examples, binaries, or repository hooks.\ninspection.toml contains bounded parser results from a fresh recomputation of the admission request.\n";

/// Canonical bounded evidence emitted beside exact untrusted `.crate` archives.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct InspectionReport<'a> {
    schema: u32,
    indexer_version: &'a str,
    catalog_sha256: &'a str,
    evaluated_at: &'a UtcTimestamp,
    candidate_facts_sha256: String,
    candidate: &'a UpdateCandidate,
    candidate_analysis: &'a ArchiveAnalysis,
    base_analysis: Option<&'a ArchiveAnalysis>,
    archive_delta: Option<&'a ArchiveDelta>,
    source_evidence: &'a SourceEvidence,
}

pub(crate) trait InspectionResolver {
    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>>;
}

impl InspectionResolver for LivePlannerResolver {
    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
        import::fetch_crates_io_archive(name, version, checksum)
    }
}

/// Recomputes and inertly inspects one exact request from a compact admission manifest.
///
/// The command never invokes Cargo, a compiler, a build script, a package binary, or repository
/// code. It emits the checksum-verified candidate/base archives, a bounded canonical analysis
/// report, and a warning file. The output path must not already exist.
///
/// # Errors
///
/// Returns an error for a noncanonical manifest, missing request, blocked/young/yanked/drifted
/// candidate, unsafe archive, checksum/evidence mismatch, unsafe output parent, existing output, or
/// filesystem failure.
pub fn inspect_update_candidate(
    root: &Path,
    manifest_path: &Path,
    name: &str,
    version: &Version,
    output: &Path,
) -> Result<()> {
    inspect_update_candidate_with(
        root,
        manifest_path,
        name,
        version,
        output,
        &LivePlannerResolver,
        UtcTimestamp::now().context("read update inspection time")?,
    )
}

pub(crate) fn inspect_update_candidate_with<R: PlannerResolver + InspectionResolver>(
    root: &Path,
    manifest_path: &Path,
    name: &str,
    version: &Version,
    output: &Path,
    resolver: &R,
    evaluated_at: UtcTimestamp,
) -> Result<()> {
    let manifest =
        load_admission_manifest(manifest_path).context("load admission manifest for inspection")?;
    let mut requests = manifest.entries.iter().filter(|request| {
        request.name == name && request.version.as_ref() == Some(version) && request.tag.is_none()
    });
    let request = requests
        .next()
        .with_context(|| format!("admission manifest has no exact request {name} {version}"))?;
    ensure!(
        requests.next().is_none(),
        "admission manifest repeats exact request {name} {version}"
    );
    validate_output_destination(output)?;

    let exact_manifest = AdmissionManifest {
        schema: manifest.schema,
        entries: vec![request.clone()],
    };
    let plan = recompute_admission_plan_with(root, &exact_manifest, resolver, evaluated_at)
        .context("recompute exact admission facts for inspection")?;
    ensure!(
        plan.candidates.len() == 1,
        "exact admission recomputation did not produce one candidate"
    );
    materialize_recomputed_candidate(&plan, &plan.candidates[0], output, resolver)
}

fn materialize_recomputed_candidate<R: InspectionResolver>(
    plan: &UpdatePlan,
    candidate: &UpdateCandidate,
    output: &Path,
    resolver: &R,
) -> Result<()> {
    validate_output_destination(output)?;
    let name = &candidate.name;
    let version = &candidate.candidate.version;
    let candidate_archive = resolver
        .archive(name, version, &candidate.candidate.crate_sha256)
        .with_context(|| format!("fetch inspection candidate {name} {version}"))?;
    let candidate_analysis = inspect_crate_archive(name, version, &candidate_archive)
        .with_context(|| format!("inertly inspect candidate {name} {version}"))?;
    ensure!(
        super::ArchiveSummary::from_analysis(&candidate_analysis)? == candidate.candidate_archive,
        "candidate archive analysis differs from recomputed admission evidence"
    );

    let (base_archive, base_analysis, delta) = match (&candidate.base, &candidate.base_archive) {
        (Some(base), Some(expected_analysis)) => {
            let archive = resolver
                .archive(name, &base.version, &base.crate_sha256)
                .with_context(|| format!("fetch inspection base {name} {}", base.version))?;
            let analysis = inspect_crate_archive(name, &base.version, &archive)
                .with_context(|| format!("inertly inspect base {name} {}", base.version))?;
            ensure!(
                super::ArchiveSummary::from_analysis(&analysis)? == *expected_analysis,
                "base archive analysis differs from recomputed admission evidence"
            );
            let delta = compare_archive_analyses(&analysis, &candidate_analysis)?;
            ensure!(
                candidate.archive_delta.as_ref() == Some(&delta),
                "archive delta differs from recomputed admission evidence"
            );
            (Some(archive), Some(analysis), Some(delta))
        }
        (None, None) => {
            ensure!(
                candidate.archive_delta.is_none(),
                "candidate without a base unexpectedly carries an archive delta"
            );
            (None, None, None)
        }
        _ => anyhow::bail!("candidate base identity and archive analysis disagree"),
    };

    let report = InspectionReport {
        schema: INSPECTION_SCHEMA,
        indexer_version: &plan.indexer_version,
        catalog_sha256: &plan.catalog_sha256,
        evaluated_at: &plan.evaluated_at,
        candidate_facts_sha256: candidate_facts_sha256(candidate)?,
        candidate,
        candidate_analysis: &candidate_analysis,
        base_analysis: base_analysis.as_ref(),
        archive_delta: delta.as_ref(),
        source_evidence: &candidate.source,
    };
    let report = toml::to_string_pretty(&report)
        .context("serialize canonical update inspection report")?
        .into_bytes();
    write_inspection_directory(output, &report, &candidate_archive, base_archive.as_deref())
}

fn validate_output_destination(output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect review-output parent {}", parent.display()))?;
    ensure!(
        parent_metadata.file_type().is_dir(),
        "review-output parent is not a real directory: {}",
        parent.display()
    );
    ensure!(
        output.file_name().is_some(),
        "review-output path has no directory name"
    );
    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("review-output path already exists: {}", output.display()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", output.display())),
    }
}

fn write_inspection_directory(
    output: &Path,
    report: &[u8],
    candidate_archive: &[u8],
    base_archive: Option<&[u8]>,
) -> Result<()> {
    validate_output_destination(output)?;
    fs::create_dir(output)
        .with_context(|| format!("create absent review-output directory {}", output.display()))?;
    let result = (|| {
        write_new_file(&output.join("README.txt"), README.as_bytes())?;
        write_new_file(&output.join("inspection.toml"), report)?;
        write_new_file(&output.join("candidate.crate"), candidate_archive)?;
        if let Some(archive) = base_archive {
            write_new_file(&output.join("base.crate"), archive)?;
        }
        File::open(output)
            .with_context(|| format!("open review-output directory {}", output.display()))?
            .sync_all()
            .with_context(|| format!("sync review-output directory {}", output.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create review evidence {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write review evidence {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync review evidence {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use flate2::{Compression, write::GzEncoder};

    use super::*;
    use crate::artifact::sha256_bytes;
    use crate::update::{
        ArchiveSummary, DecisionReason, DependencyDelta, PackageActivity, PlannedIdentity,
        UpdateDecision, UpdatePlan,
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FakeResolver {
        archive: Vec<u8>,
    }

    impl InspectionResolver for FakeResolver {
        fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
            ensure!(name == "demo" && version == &Version::parse("1.0.0")?);
            ensure!(checksum == sha256_bytes(&self.archive));
            Ok(self.archive.clone())
        }
    }

    struct PanicResolver;

    impl InspectionResolver for PanicResolver {
        fn archive(&self, _: &str, _: &Version, _: &str) -> Result<Vec<u8>> {
            panic!("unsafe output must be rejected before network resolution")
        }
    }

    #[test]
    fn inspection_is_inert_exact_and_create_new() {
        let root = temporary_directory("success");
        let marker = root.join("must-not-exist");
        let payload = format!("fn main() {{ /* {} */ }}\n", marker.display());
        let archive = crate_archive("demo-1.0.0/build.rs", payload.as_bytes(), 0o755);
        let plan = make_plan(&archive);
        let output = root.join("review");

        materialize_recomputed_candidate(
            &plan,
            &plan.candidates[0],
            &output,
            &FakeResolver {
                archive: archive.clone(),
            },
        )
        .unwrap();

        assert!(!marker.exists());
        assert_eq!(fs::read(output.join("candidate.crate")).unwrap(), archive);
        assert!(!output.join("base.crate").exists());
        let report = fs::read_to_string(output.join("inspection.toml")).unwrap();
        assert!(report.contains("schema = 1"));
        assert!(report.contains("candidate-facts-sha256"));
        assert!(report.contains("build.rs"));
        assert!(
            fs::read_to_string(output.join("README.txt"))
                .unwrap()
                .contains("Do not execute")
        );

        assert!(
            materialize_recomputed_candidate(&plan, &plan.candidates[0], &output, &PanicResolver,)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_evidence_mismatch_leaves_no_output() {
        let root = temporary_directory("mismatch");
        let planned_archive = crate_archive("demo-1.0.0/lib.rs", b"planned\n", 0o644);
        let observed_archive = crate_archive("demo-1.0.0/lib.rs", b"changed\n", 0o644);
        let plan = make_plan(&planned_archive);
        let output = root.join("review");
        let error = materialize_recomputed_candidate(
            &plan,
            &plan.candidates[0],
            &output,
            &FakeResolver {
                archive: observed_archive,
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("checksum"));
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parent_is_rejected_before_resolution() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("symlink-parent");
        let archive = crate_archive("demo-1.0.0/lib.rs", b"safe\n", 0o644);
        let plan = make_plan(&archive);
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let linked = root.join("linked");
        symlink(&real, &linked).unwrap();
        let output = linked.join("review");
        assert!(
            materialize_recomputed_candidate(&plan, &plan.candidates[0], &output, &PanicResolver,)
                .is_err()
        );
        assert!(!real.join("review").exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn make_plan(archive: &[u8]) -> UpdatePlan {
        let version = Version::parse("1.0.0").unwrap();
        let analysis = inspect_crate_archive("demo", &version, archive).unwrap();
        let build_surface_changed = !analysis.build_surface.is_empty();
        let mut reasons = vec![DecisionReason::NewPackage];
        if build_surface_changed {
            reasons.push(DecisionReason::BuildSurfaceChanged);
        }
        reasons.push(DecisionReason::SourceUnavailable);
        reasons.push(DecisionReason::ExplicitCandidate);
        UpdatePlan {
            schema: super::super::UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "00".repeat(32),
            evaluated_at: UtcTimestamp::parse("2025-01-31T00:00:00Z").unwrap(),
            min_release_age_days: super::super::MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: super::super::DORMANT_RELEASE_GAP_DAYS,
            candidates: vec![UpdateCandidate {
                registry: "universe".to_owned(),
                category: "universe/general".to_owned(),
                name: "demo".to_owned(),
                activity: PackageActivity::New,
                lane: None,
                base: None,
                candidate: PlannedIdentity {
                    version,
                    published_at: UtcTimestamp::parse("2025-01-01T00:00:00Z").unwrap(),
                    source_row_sha256: "11".repeat(32),
                    crate_sha256: sha256_bytes(archive),
                },
                sparse_index_sha256: "22".repeat(32),
                decision_history_sha256: "33".repeat(32),
                age_seconds: 30 * 24 * 60 * 60,
                dormant_gap: None,
                base_archive: None,
                candidate_archive: ArchiveSummary::from_analysis(&analysis).unwrap(),
                archive_delta: None,
                dependencies: DependencyDelta {
                    added: Vec::new(),
                    removed: Vec::new(),
                    new_packages: Vec::new(),
                },
                api: None,
                source: SourceEvidence::Unavailable {
                    reason: "source-verification-error".to_owned(),
                },
                decision: UpdateDecision::ReviewRequired,
                reasons,
            }],
        }
    }

    fn crate_archive(path: &str, contents: &[u8], mode: u32) -> Vec<u8> {
        const BLOCK: usize = 512;
        let mut header = [0_u8; BLOCK];
        set_string(&mut header[..100], path);
        set_octal(&mut header[100..108], u64::from(mode));
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

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "pkgre-update-inspect-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        root
    }
}
