//! Immutable catalog-owned admission manifests and generated machine facts.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::artifact::sha256_bytes;
use crate::schema::{Approval, Catalog, Source, version_identity};

use super::plan::validate_historical_update_plan;
use super::{
    AdmissionEvidence, AdmissionManifest, AdmissionRequest, UpdateCandidate, UpdateDecision,
    UpdatePlan, UtcTimestamp,
};

/// Stable generated admission-lock wire schema.
const ADMISSION_LOCK_SCHEMA: u32 = 2;
const ADMISSIONS_DIRECTORY: &str = "admissions";

type AdmissionIdentity = (String, (u64, u64, u64, String));

/// Complete generated facts for one human admission batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct AdmissionLock {
    schema: u32,
    manifest_sha256: String,
    admitted_at: UtcTimestamp,
    plan: UpdatePlan,
    #[serde(rename = "admit")]
    requests: Vec<AdmissionRequest>,
}

/// Serializes a canonical generated admission lock and returns its complete-content SHA-256.
pub(crate) fn prepare_admission_lock(
    manifest: &AdmissionManifest,
    plan: &UpdatePlan,
    admitted_at: &UtcTimestamp,
) -> Result<(Vec<u8>, String)> {
    let manifest_bytes = super::serialize_admission_manifest(manifest)?;
    let lock = AdmissionLock {
        schema: ADMISSION_LOCK_SCHEMA,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        admitted_at: admitted_at.clone(),
        plan: plan.clone(),
        requests: manifest.entries.clone(),
    };
    let bytes = serialize_admission_lock(&lock, Some(manifest))?;
    let binding = sha256_bytes(&bytes);
    Ok((bytes, binding))
}

/// Writes one absent immutable manifest/lock pair and returns the catalog-relative manifest path.
pub(crate) fn write_admission_pair(
    root: &Path,
    filename: &Path,
    manifest_bytes: &[u8],
    lock_bytes: &[u8],
) -> Result<PathBuf> {
    super::manifest::validate_admission_filename(filename, "toml")?;
    let filename = filename
        .file_name()
        .context("admission manifest path has no filename")?;
    let relative = PathBuf::from(ADMISSIONS_DIRECTORY).join(filename);
    let lock_relative = relative.with_extension("lock");
    let directory = root.join(ADMISSIONS_DIRECTORY);
    create_or_validate_directory(&directory, "admission directory")?;
    let manifest_path = root.join(&relative);
    let lock_path = root.join(&lock_relative);
    ensure_absent(&manifest_path)?;
    ensure_absent(&lock_path)?;
    write_new(&manifest_path, manifest_bytes, "admission manifest")?;
    if let Err(error) = write_new(&lock_path, lock_bytes, "generated admission lock") {
        let _ = fs::remove_file(&manifest_path);
        return Err(error);
    }
    File::open(&directory)
        .with_context(|| format!("open admission directory {}", directory.display()))?
        .sync_all()
        .with_context(|| format!("sync admission directory {}", directory.display()))?;
    Ok(relative)
}

/// Validates that the optional admission tree contains only paired regular canonical files.
pub(crate) fn validate_admission_tree_structure(root: &Path) -> Result<()> {
    let directory = root.join(ADMISSIONS_DIRECTORY);
    let Some(()) = optional_real_directory(&directory, "admission directory")? else {
        return Ok(());
    };
    let entries = sorted_entries(&directory)?;
    ensure!(
        !entries.is_empty(),
        "admission directory is empty: {}",
        directory.display()
    );
    let mut pairs = HashMap::<String, u8>::with_capacity(entries.len());
    for path in entries {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect admission file {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "admission path is not a regular file: {}",
            path.display()
        );
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .with_context(|| {
                format!("admission extension is not valid UTF-8: {}", path.display())
            })?;
        let bit = match extension {
            "toml" => 1,
            "lock" => 2,
            _ => bail!(
                "admission file must have lowercase .toml or .lock extension: {}",
                path.display()
            ),
        };
        super::manifest::validate_admission_filename(&path, extension)?;
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("validated admission filename has a UTF-8 stem")
            .to_owned();
        let present = pairs.entry(stem).or_default();
        ensure!(
            *present & bit == 0,
            "admission pair repeats a .{extension} file: {}",
            path.display()
        );
        *present |= bit;
    }
    for (stem, present) in pairs {
        ensure!(
            present == 3,
            "admission batch {stem:?} must have exactly one .toml manifest and one .lock"
        );
    }
    Ok(())
}

/// Loads and validates every admission pair against all admission-bound catalog locks.
pub(crate) fn validate_admission_inventory(catalog: &Catalog) -> Result<()> {
    validate_admission_tree_structure(&catalog.root)?;
    let mut expected = admission_bound_approvals(catalog)?;
    let directory = catalog.root.join(ADMISSIONS_DIRECTORY);
    let Some(()) = optional_real_directory(&directory, "admission directory")? else {
        ensure!(
            expected.is_empty(),
            "generated locks reference missing admission batches"
        );
        return Ok(());
    };

    let mut stems = sorted_entries(&directory)?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|value| value == "toml"))
        .map(|path| path.with_extension(""))
        .collect::<Vec<_>>();
    stems.sort();
    let mut covered = HashSet::new();
    let mut batch_hashes = HashSet::new();
    for stem in stems {
        let manifest_path = stem.with_extension("toml");
        let lock_path = stem.with_extension("lock");
        let manifest = super::load_admission_manifest(&manifest_path)?;
        let manifest_bytes = super::serialize_admission_manifest(&manifest)?;
        let (lock, lock_bytes) = load_admission_lock(&lock_path, &manifest)?;
        ensure!(
            lock.manifest_sha256 == sha256_bytes(&manifest_bytes),
            "generated admission lock does not bind its adjacent manifest: {}",
            lock_path.display()
        );
        let batch_hash = sha256_bytes(&lock_bytes);
        ensure!(
            batch_hashes.insert(batch_hash.clone()),
            "two admission batches have identical generated lock bytes"
        );
        for candidate in &lock.plan.candidates {
            let identity = candidate_identity(candidate);
            ensure!(
                covered.insert(identity.clone()),
                "more than one admission batch covers {} {}",
                candidate.name,
                candidate.candidate.version
            );
            let approval = expected.remove(&identity).with_context(|| {
                format!(
                    "admission batch {} has no admission-bound locked identity {} {}",
                    lock_path.display(),
                    candidate.name,
                    candidate.candidate.version
                )
            })?;
            validate_candidate_lock(candidate, approval, &batch_hash, &lock_path)?;
        }
    }
    ensure!(
        expected.is_empty(),
        "generated locks contain identities not covered by an admission batch: {:?}",
        expected
            .values()
            .map(|approval| format!("{} {}", approval.name, approval.version))
            .collect::<Vec<_>>()
    );
    Ok(())
}

fn admission_bound_approvals(catalog: &Catalog) -> Result<HashMap<AdmissionIdentity, &Approval>> {
    let mut expected = HashMap::with_capacity(catalog.approvals.len());
    for approval in &catalog.approvals {
        let Some(binding) = &approval.admission_sha256 else {
            continue;
        };
        crate::policy::validate_sha256(binding).with_context(|| {
            format!(
                "invalid admission-lock binding for {} {}",
                approval.name, approval.version
            )
        })?;
        ensure!(
            matches!(approval.source, Source::CratesIo),
            "non-crates.io identity {} {} references mirror admission facts",
            approval.name,
            approval.version
        );
        let identity = approval_identity(approval);
        ensure!(
            expected.insert(identity, approval).is_none(),
            "generated locks repeat admission-bound identity {} {}",
            approval.name,
            approval.version
        );
    }
    Ok(expected)
}

fn validate_candidate_lock(
    candidate: &UpdateCandidate,
    approval: &Approval,
    batch_hash: &str,
    path: &Path,
) -> Result<()> {
    ensure!(
        approval.registry == candidate.registry
            && approval.category.to_string() == candidate.category
            && approval.name == candidate.name
            && version_identity(&approval.version)
                == version_identity(&candidate.candidate.version)
            && approval.archive_sha256 == candidate.candidate.crate_sha256
            && approval.index_record_sha256 == candidate.candidate.source_row_sha256
            && approval.admission_sha256.as_deref() == Some(batch_hash)
            && matches!(approval.source, Source::CratesIo),
        "admission facts {} differ from immutable locked route, identity, hashes, or batch binding",
        path.display()
    );
    Ok(())
}

fn load_admission_lock(
    path: &Path,
    manifest: &AdmissionManifest,
) -> Result<(AdmissionLock, Vec<u8>)> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect generated admission lock {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "generated admission lock is not a regular file: {}",
        path.display()
    );
    let bytes = fs::read(path)
        .with_context(|| format!("read generated admission lock {}", path.display()))?;
    let lock: AdmissionLock = toml::from_slice(&bytes)
        .with_context(|| format!("parse generated admission lock {}", path.display()))?;
    let canonical = serialize_admission_lock(&lock, Some(manifest))?;
    ensure!(
        bytes == canonical,
        "generated admission lock is not in canonical form: {}",
        path.display()
    );
    Ok((lock, bytes))
}

fn serialize_admission_lock(
    lock: &AdmissionLock,
    manifest: Option<&AdmissionManifest>,
) -> Result<Vec<u8>> {
    validate_admission_lock(lock, manifest)?;
    let text = toml::to_string_pretty(lock).context("serialize canonical admission lock")?;
    Ok(text.into_bytes())
}

fn validate_admission_lock(
    lock: &AdmissionLock,
    manifest: Option<&AdmissionManifest>,
) -> Result<()> {
    ensure!(
        lock.schema == ADMISSION_LOCK_SCHEMA,
        "unsupported admission-lock schema {}; expected {ADMISSION_LOCK_SCHEMA}",
        lock.schema
    );
    crate::policy::validate_sha256(&lock.manifest_sha256)
        .context("invalid admission manifest hash")?;
    validate_historical_update_plan(&lock.plan).context("validate generated admission facts")?;
    ensure!(
        !lock.plan.candidates.is_empty(),
        "generated admission lock contains no candidates"
    );
    lock.admitted_at
        .duration_since(&lock.plan.evaluated_at)
        .context("admission time predates evidence evaluation")?;
    let requests_manifest = AdmissionManifest {
        schema: super::ADMISSION_MANIFEST_SCHEMA,
        entries: lock.requests.clone(),
    };
    super::serialize_admission_manifest(&requests_manifest)
        .context("validate generated admission request bindings")?;
    if let Some(manifest) = manifest {
        ensure!(
            &requests_manifest == manifest,
            "generated admission request bindings differ from the adjacent manifest"
        );
        ensure!(
            lock.manifest_sha256 == sha256_bytes(&super::serialize_admission_manifest(manifest)?),
            "generated admission manifest hash is stale"
        );
    }

    let mut requests = HashMap::with_capacity(lock.requests.len());
    for request in &lock.requests {
        let identity = request_identity(request)?;
        ensure!(
            requests.insert(identity, request).is_none(),
            "generated admission requests repeat an identity"
        );
    }
    ensure!(
        requests.len() == lock.plan.candidates.len(),
        "generated admission request and candidate counts differ"
    );
    for candidate in &lock.plan.candidates {
        ensure!(
            candidate.decision != UpdateDecision::Blocked,
            "blocked candidate {} {} cannot be retained as admitted",
            candidate.name,
            candidate.candidate.version
        );
        ensure!(
            candidate.approvals.is_empty(),
            "generated admission candidate {} {} carries obsolete plan approvals",
            candidate.name,
            candidate.candidate.version
        );
        let identity = candidate_identity(candidate);
        let request = requests.remove(&identity).with_context(|| {
            format!(
                "generated facts have no matching request for {} {}",
                candidate.name, candidate.candidate.version
            )
        })?;
        ensure!(
            request.name == candidate.name && request.category.to_string() == candidate.category,
            "generated facts route differs from request for {} {}",
            candidate.name,
            candidate.candidate.version
        );
        validate_request_evidence(request, candidate)?;
    }
    ensure!(
        requests.is_empty(),
        "generated admission requests contain unmatched identities"
    );
    Ok(())
}

fn validate_request_evidence(
    request: &AdmissionRequest,
    candidate: &UpdateCandidate,
) -> Result<()> {
    for evidence in &request.evidence {
        match evidence {
            AdmissionEvidence::ManualFullArchive { .. } => {}
            AdmissionEvidence::ManualSourceDelta { base, .. } => {
                let candidate_base = candidate.base.as_ref().with_context(|| {
                    format!(
                        "manual source-delta evidence for {} {} has no exact base",
                        candidate.name, candidate.candidate.version
                    )
                })?;
                ensure!(
                    version_identity(base) == version_identity(&candidate_base.version)
                        && candidate.archive_delta.is_some(),
                    "manual source-delta base for {} {} differs from recomputed exact base {}",
                    candidate.name,
                    candidate.candidate.version,
                    candidate_base.version
                );
            }
        }
    }
    Ok(())
}

fn request_identity(request: &AdmissionRequest) -> Result<AdmissionIdentity> {
    match (&request.version, &request.tag) {
        (Some(version), None) => Ok((package_identity(&request.name), version_identity(version))),
        (None, Some(tag)) => bail!(
            "Git-tag admission for {} tag {tag:?} is not yet supported",
            request.name
        ),
        _ => bail!(
            "admission request for {} does not have exactly one target",
            request.name
        ),
    }
}

fn candidate_identity(candidate: &UpdateCandidate) -> AdmissionIdentity {
    (
        package_identity(&candidate.name),
        version_identity(&candidate.candidate.version),
    )
}

fn approval_identity(approval: &Approval) -> AdmissionIdentity {
    (
        package_identity(&approval.name),
        version_identity(&approval.version),
    )
}

fn package_identity(value: &str) -> String {
    value.to_ascii_lowercase().replace('-', "_")
}

fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("admission file already exists: {}", path.display()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn write_new(path: &Path, bytes: &[u8], description: &str) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {description} {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("write {description} {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync {description} {}", path.display()))
}

fn optional_real_directory(path: &Path, description: &str) -> Result<Option<()>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_dir(),
                "{description} is not a real directory: {}",
                path.display()
            );
            Ok(Some(()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn create_or_validate_directory(path: &Path, description: &str) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("inspect {}", path.display()))?;
            ensure!(
                metadata.file_type().is_dir(),
                "{description} is not a real directory: {}",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

fn sorted_entries(root: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(root)
        .with_context(|| format!("read directory {}", root.display()))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use semver::Version;

    use super::*;
    use crate::category::CategoryId;
    use crate::schema::{HomesFile, PackageState, RegistriesFile, SCHEMA_VERSION};
    use crate::update::{
        ArchiveSummary, DecisionReason, DependencyDelta, MIN_RELEASE_AGE_DAYS, PackageActivity,
        PlannedIdentity, SourceEvidence, UPDATE_PLAN_SCHEMA,
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn canonical_pair_is_complete_content_bound_and_inventory_checked() {
        let root = temporary_directory("pair");
        let manifest = manifest();
        let plan = plan();
        let manifest_bytes = super::super::serialize_admission_manifest(&manifest).unwrap();
        let (lock_bytes, binding) = prepare_admission_lock(
            &manifest,
            &plan,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        write_admission_pair(
            &root,
            Path::new("2025-02-01-demo.toml"),
            &manifest_bytes,
            &lock_bytes,
        )
        .unwrap();
        assert_eq!(sha256_bytes(&lock_bytes), binding);
        validate_admission_inventory(&catalog_for(&root, Some(binding))).unwrap();

        let path = root.join("admissions/2025-02-01-demo.lock");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(validate_admission_inventory(&catalog_for(&root, None)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_requires_exact_reverse_coverage_and_rejects_duplicate_batches() {
        let root = temporary_directory("reverse");
        let manifest = manifest();
        let plan = plan();
        let manifest_bytes = super::super::serialize_admission_manifest(&manifest).unwrap();
        let first_time = UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap();
        let (first, binding) = prepare_admission_lock(&manifest, &plan, &first_time).unwrap();
        write_admission_pair(&root, Path::new("first.toml"), &manifest_bytes, &first).unwrap();
        assert!(validate_admission_inventory(&catalog_for(&root, None)).is_err());

        let second_time = UtcTimestamp::parse("2025-02-01T03:00:00Z").unwrap();
        let (second, _) = prepare_admission_lock(&manifest, &plan, &second_time).unwrap();
        write_admission_pair(&root, Path::new("second.toml"), &manifest_bytes, &second).unwrap();
        assert!(validate_admission_inventory(&catalog_for(&root, Some(binding))).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tree_rejects_unpaired_nested_and_symlink_entries() {
        let root = temporary_directory("tree");
        fs::create_dir(root.join("admissions")).unwrap();
        fs::write(root.join("admissions/only.toml"), b"schema = 2\n").unwrap();
        assert!(validate_admission_tree_structure(&root).is_err());
        fs::remove_dir_all(&root).unwrap();

        let root = temporary_directory("nested");
        fs::create_dir_all(root.join("admissions/nested")).unwrap();
        assert!(validate_admission_tree_structure(&root).is_err());
        fs::remove_dir_all(&root).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let root = temporary_directory("symlink");
            fs::create_dir(root.join("target")).unwrap();
            symlink(root.join("target"), root.join("admissions")).unwrap();
            assert!(validate_admission_tree_structure(&root).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn source_delta_evidence_binds_the_recomputed_base() {
        let mut manifest = manifest();
        manifest.entries[0].evidence = vec![AdmissionEvidence::ManualSourceDelta {
            base: Version::parse("0.9.0").unwrap(),
            note: "Reviewed the complete source delta.".to_owned(),
        }];
        assert!(
            prepare_admission_lock(
                &manifest,
                &plan(),
                &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap()
            )
            .is_err()
        );
    }

    fn manifest() -> AdmissionManifest {
        AdmissionManifest {
            schema: super::super::ADMISSION_MANIFEST_SCHEMA,
            entries: vec![AdmissionRequest {
                category: "universe/general".parse().unwrap(),
                name: "demo".to_owned(),
                version: Some(Version::parse("1.0.0").unwrap()),
                tag: None,
                evidence: Vec::new(),
            }],
        }
    }

    fn plan() -> UpdatePlan {
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "07".repeat(32),
            evaluated_at: UtcTimestamp::parse("2025-02-01T00:00:00Z").unwrap(),
            min_release_age_days: MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: super::super::DORMANT_RELEASE_GAP_DAYS,
            candidates: vec![candidate()],
        }
    }

    fn candidate() -> UpdateCandidate {
        UpdateCandidate {
            registry: "universe".to_owned(),
            category: "universe/general".to_owned(),
            name: "demo".to_owned(),
            activity: PackageActivity::New,
            lane: None,
            base: None,
            candidate: PlannedIdentity {
                version: Version::parse("1.0.0").unwrap(),
                published_at: UtcTimestamp::parse("2025-01-02T00:00:00Z").unwrap(),
                source_row_sha256: "01".repeat(32),
                crate_sha256: "02".repeat(32),
            },
            sparse_index_sha256: "03".repeat(32),
            decision_history_sha256: "04".repeat(32),
            age_seconds: 30 * 24 * 60 * 60,
            dormant_gap: None,
            base_archive: None,
            candidate_archive: ArchiveSummary {
                analysis_sha256: "05".repeat(32),
                compressed_bytes: 1,
                unpacked_bytes: 1,
                files: 1,
                build_surface: BTreeMap::new(),
                vcs_commit: None,
                vcs_path: None,
            },
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
            reasons: vec![
                DecisionReason::NewPackage,
                DecisionReason::SourceUnavailable,
                DecisionReason::ExplicitCandidate,
            ],
            approvals: Vec::new(),
        }
    }

    fn catalog_for(root: &Path, binding: Option<String>) -> Catalog {
        Catalog {
            root: root.to_path_buf(),
            registries: RegistriesFile {
                schema: SCHEMA_VERSION,
                cname: "rust.pkg.re".to_owned(),
                cargo_version: Version::parse("1.95.0").unwrap(),
                registries: Vec::new(),
            },
            categories: BTreeMap::new(),
            homes: HomesFile {
                schema: SCHEMA_VERSION,
                homes: BTreeMap::new(),
            },
            name_sources: BTreeMap::new(),
            approvals: binding
                .map(|binding| Approval {
                    registry: "universe".to_owned(),
                    category: CategoryId::new("universe", "general").unwrap(),
                    name: "demo".to_owned(),
                    version: Version::parse("1.0.0").unwrap(),
                    archive_sha256: "02".repeat(32),
                    index_record_sha256: "01".repeat(32),
                    index_row_sha256: "08".repeat(32),
                    admission_sha256: Some(binding),
                    state: PackageState::Active,
                    source: Source::CratesIo,
                    declared_in: root.join("universe.lock"),
                })
                .into_iter()
                .collect(),
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pkgre-update-admission-{name}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }
}
