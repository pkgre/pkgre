//! Immutable catalog-owned evidence for crates.io update admissions.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::schema::{Catalog, Source, version_identity};

use super::plan::validate_historical_update_plan;
use super::{
    MAX_PLAN_AGE_DAYS, UpdateCandidate, UpdateDecision, UpdatePlan, UtcTimestamp,
    candidate_binding_sha256, required_approval_kind,
};

/// Stable admission-record wire schema.
const ADMISSION_RECORD_SCHEMA: u32 = 1;
const REVIEWS_DIRECTORY: &str = "_reviews";
const ADMISSIONS_DIRECTORY: &str = "admissions";

/// Immutable evidence retained beside the catalog lock admitted by one update plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct AdmissionRecord {
    pub(crate) schema: u32,
    pub(crate) indexer_version: String,
    pub(crate) catalog_sha256: String,
    pub(crate) evaluated_at: UtcTimestamp,
    pub(crate) admitted_at: UtcTimestamp,
    pub(crate) min_release_age_days: u64,
    pub(crate) dormant_release_gap_days: u64,
    pub(crate) candidate: UpdateCandidate,
}

/// Validates that the optional admission-evidence tree contains only expected real directories and regular files.
pub(crate) fn validate_admission_tree_structure(root: &Path) -> Result<()> {
    let review_root = root.join(REVIEWS_DIRECTORY);
    let Some(()) = optional_real_directory(&review_root, "admission review root")? else {
        return Ok(());
    };
    let entries = sorted_entries(&review_root)?;
    ensure!(
        entries.len() == 1 && entries[0].file_name() == Some(OsStr::new(ADMISSIONS_DIRECTORY)),
        "admission review root {} must contain only {ADMISSIONS_DIRECTORY}/",
        review_root.display()
    );
    let approvals = &entries[0];
    let metadata = fs::symlink_metadata(approvals)
        .with_context(|| format!("inspect admission directory {}", approvals.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "admission path is not a real directory: {}",
        approvals.display()
    );
    for path in sorted_entries(approvals)? {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect admission record {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "admission record is not a regular file: {}",
            path.display()
        );
        admission_binding_from_filename(&path)?;
    }
    Ok(())
}

/// Loads and validates all optional admission records against immutable locked identities.
pub(crate) fn validate_admission_inventory(catalog: &Catalog) -> Result<()> {
    validate_admission_tree_structure(&catalog.root)?;
    let approvals = catalog
        .root
        .join(REVIEWS_DIRECTORY)
        .join(ADMISSIONS_DIRECTORY);
    let Some(()) = optional_real_directory(&approvals, "admission directory")? else {
        return Ok(());
    };
    let mut bindings = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for path in sorted_entries(&approvals)? {
        let filename_binding = admission_binding_from_filename(&path)?;
        let record = load_admission_record(&path)?;
        let binding = candidate_binding_sha256(&record.candidate)?;
        ensure!(
            binding == filename_binding,
            "admission record filename does not match candidate binding: {}",
            path.display()
        );
        ensure!(
            bindings.insert(binding),
            "duplicate admission candidate binding in {}",
            path.display()
        );
        let identity = (
            record.candidate.name.to_ascii_lowercase().replace('-', "_"),
            version_identity(&record.candidate.candidate.version),
        );
        ensure!(
            identities.insert(identity),
            "more than one admission record covers {} {}",
            record.candidate.name,
            record.candidate.candidate.version
        );
        let locked = catalog
            .approvals
            .iter()
            .find(|approval| {
                approval.name == record.candidate.name
                    && version_identity(&approval.version)
                        == version_identity(&record.candidate.candidate.version)
            })
            .with_context(|| {
                format!(
                    "admission record {} has no locked identity {} {}",
                    path.display(),
                    record.candidate.name,
                    record.candidate.candidate.version
                )
            })?;
        ensure!(
            locked.registry == record.candidate.registry
                && locked.category.to_string() == record.candidate.category
                && locked.archive_sha256 == record.candidate.candidate.crate_sha256
                && locked.index_record_sha256 == record.candidate.candidate.source_row_sha256
                && matches!(locked.source, Source::CratesIo),
            "admission record {} differs from immutable locked route or hashes",
            path.display()
        );
    }
    Ok(())
}

/// Writes one canonical immutable admission record and returns its catalog-relative path.
pub(crate) fn write_admission_record(
    root: &Path,
    plan: &UpdatePlan,
    candidate: &UpdateCandidate,
    admitted_at: &UtcTimestamp,
) -> Result<PathBuf> {
    let record = AdmissionRecord {
        schema: ADMISSION_RECORD_SCHEMA,
        indexer_version: plan.indexer_version.clone(),
        catalog_sha256: plan.catalog_sha256.clone(),
        evaluated_at: plan.evaluated_at.clone(),
        admitted_at: admitted_at.clone(),
        min_release_age_days: plan.min_release_age_days,
        dormant_release_gap_days: plan.dormant_release_gap_days,
        candidate: candidate.clone(),
    };
    let bytes = serialize_admission_record(&record)?;
    let binding = candidate_binding_sha256(candidate)?;
    let relative = PathBuf::from(REVIEWS_DIRECTORY)
        .join(ADMISSIONS_DIRECTORY)
        .join(format!("{binding}.toml"));
    let review_root = root.join(REVIEWS_DIRECTORY);
    create_or_validate_directory(&review_root, "admission review root")?;
    let approvals = review_root.join(ADMISSIONS_DIRECTORY);
    create_or_validate_directory(&approvals, "admission directory")?;
    let path = root.join(&relative);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create immutable admission record {}", path.display()))?;
    output
        .write_all(&bytes)
        .with_context(|| format!("write admission record {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync admission record {}", path.display()))?;
    File::open(&approvals)
        .with_context(|| format!("open admission directory {}", approvals.display()))?
        .sync_all()
        .with_context(|| format!("sync admission directory {}", approvals.display()))?;
    File::open(&review_root)
        .with_context(|| format!("open admission root {}", review_root.display()))?
        .sync_all()
        .with_context(|| format!("sync admission root {}", review_root.display()))?;
    Ok(relative)
}

fn load_admission_record(path: &Path) -> Result<AdmissionRecord> {
    let bytes =
        fs::read(path).with_context(|| format!("read admission record {}", path.display()))?;
    let record: AdmissionRecord = toml::from_slice(&bytes)
        .with_context(|| format!("parse admission record {}", path.display()))?;
    let canonical = serialize_admission_record(&record)?;
    ensure!(
        bytes == canonical,
        "admission record is not in canonical form: {}",
        path.display()
    );
    Ok(record)
}

fn serialize_admission_record(record: &AdmissionRecord) -> Result<Vec<u8>> {
    validate_admission_record(record)?;
    let text = toml::to_string_pretty(record).context("serialize canonical admission record")?;
    Ok(text.into_bytes())
}

fn validate_admission_record(record: &AdmissionRecord) -> Result<()> {
    ensure!(
        record.schema == ADMISSION_RECORD_SCHEMA,
        "unsupported admission-record schema {}; expected {ADMISSION_RECORD_SCHEMA}",
        record.schema
    );
    let plan = UpdatePlan {
        schema: super::UPDATE_PLAN_SCHEMA,
        indexer_version: record.indexer_version.clone(),
        catalog_sha256: record.catalog_sha256.clone(),
        evaluated_at: record.evaluated_at.clone(),
        min_release_age_days: record.min_release_age_days,
        dormant_release_gap_days: record.dormant_release_gap_days,
        candidates: vec![record.candidate.clone()],
    };
    validate_historical_update_plan(&plan).context("validate admission candidate evidence")?;
    record
        .admitted_at
        .duration_since(&record.evaluated_at)
        .context("admission time predates plan evaluation")?;
    for approval in &record.candidate.approvals {
        record
            .admitted_at
            .duration_since(&approval.approved_at)
            .context("admission time predates candidate approval")?;
    }
    validate_admissible_candidate(&record.candidate)
}

pub(crate) fn validate_admissible_candidate(candidate: &UpdateCandidate) -> Result<()> {
    match candidate.decision {
        UpdateDecision::Blocked => bail!(
            "blocked candidate {} {} cannot be admitted",
            candidate.name,
            candidate.candidate.version
        ),
        UpdateDecision::Automatic => ensure!(
            candidate.approvals.is_empty(),
            "automatic candidate {} {} unexpectedly carries approvals",
            candidate.name,
            candidate.candidate.version
        ),
        UpdateDecision::ReviewRequired => {
            ensure!(
                candidate.approvals.len() == 1,
                "review-required candidate {} {} must carry exactly one approval",
                candidate.name,
                candidate.candidate.version
            );
            let expected = required_approval_kind(candidate);
            ensure!(
                candidate.approvals[0].kind == expected,
                "candidate {} {} requires {expected:?} approval",
                candidate.name,
                candidate.candidate.version
            );
        }
    }
    Ok(())
}

/// Rejects a plan evaluation time in the future or older than the compiled apply window.
pub(crate) fn validate_plan_age(plan: &UpdatePlan, now: &UtcTimestamp) -> Result<()> {
    let age = now
        .duration_since(&plan.evaluated_at)
        .context("update plan evaluation time is in the future")?;
    ensure!(
        age <= MAX_PLAN_AGE_DAYS * 24 * 60 * 60,
        "update plan is older than the {MAX_PLAN_AGE_DAYS}-day apply window"
    );
    Ok(())
}

fn admission_binding_from_filename(path: &Path) -> Result<String> {
    ensure!(
        path.extension() == Some(OsStr::new("toml")),
        "admission record must have lowercase .toml extension: {}",
        path.display()
    );
    let binding = path
        .file_stem()
        .and_then(|value| value.to_str())
        .with_context(|| format!("admission filename is not valid UTF-8: {}", path.display()))?;
    ensure!(
        binding.len() == 64
            && binding
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "admission filename is not a lowercase SHA-256 binding: {}",
        path.display()
    );
    Ok(binding.to_owned())
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
    use crate::schema::{
        Approval, HomesFile, PackageState, RegistriesFile, SCHEMA_VERSION, Source,
    };
    use crate::update::{
        ApprovalKind, ArchiveSummary, DecisionReason, DependencyDelta, MIN_RELEASE_AGE_DAYS,
        PackageActivity, PlannedIdentity, SourceEvidence, UPDATE_PLAN_SCHEMA, UpdateApproval,
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn admissibility_requires_exact_decision_specific_approval_set() {
        let automatic = candidate(UpdateDecision::Automatic);
        validate_admissible_candidate(&automatic).unwrap();
        let mut approved_automatic = automatic.clone();
        approved_automatic.approvals.push(approval_for(&automatic));
        assert!(validate_admissible_candidate(&approved_automatic).is_err());

        let reviewed = candidate(UpdateDecision::ReviewRequired);
        assert!(validate_admissible_candidate(&reviewed).is_err());
        let mut approved = reviewed.clone();
        approved.approvals.push(approval_for(&reviewed));
        validate_admissible_candidate(&approved).unwrap();
        approved.approvals.push(approval_for(&reviewed));
        assert!(validate_admissible_candidate(&approved).is_err());
        let mut wrong_kind = reviewed;
        let mut approval = approval_for(&wrong_kind);
        approval.kind = ApprovalKind::SourceDelta;
        wrong_kind.approvals.push(approval);
        assert!(validate_admissible_candidate(&wrong_kind).is_err());

        let mut blocked = candidate(UpdateDecision::Blocked);
        blocked.approvals.push(approval_for(&blocked));
        assert!(validate_admissible_candidate(&blocked).is_err());
    }

    #[test]
    fn plan_age_rejects_future_and_over_seven_days() {
        let mut plan = update_plan(approved_review_candidate());
        plan.evaluated_at = UtcTimestamp::parse("2025-01-01T00:00:00Z").unwrap();
        validate_plan_age(&plan, &UtcTimestamp::parse("2025-01-08T00:00:00Z").unwrap()).unwrap();
        assert!(
            validate_plan_age(&plan, &UtcTimestamp::parse("2025-01-08T00:00:01Z").unwrap())
                .is_err()
        );
        plan.evaluated_at = UtcTimestamp::parse("2025-01-09T00:00:00Z").unwrap();
        assert!(
            validate_plan_age(&plan, &UtcTimestamp::parse("2025-01-08T00:00:00Z").unwrap())
                .is_err()
        );
    }

    #[test]
    fn admission_record_is_canonical_content_addressed_and_inventory_bound() {
        let root = temporary_directory("record");
        let candidate = approved_review_candidate();
        let plan = update_plan(candidate.clone());
        let relative = write_admission_record(
            &root,
            &plan,
            &candidate,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        assert_eq!(
            relative,
            PathBuf::from("_reviews/admissions").join(format!(
                "{}.toml",
                candidate_binding_sha256(&candidate).unwrap()
            ))
        );
        let record = load_admission_record(&root.join(&relative)).unwrap();
        assert_eq!(record.candidate, candidate);

        let mut catalog = catalog_for(&root, &record.candidate);
        validate_admission_inventory(&catalog).unwrap();
        catalog.approvals[0].archive_sha256 = "ff".repeat(32);
        assert!(validate_admission_inventory(&catalog).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn historical_indexer_version_remains_valid_and_chronology_is_enforced() {
        let root = temporary_directory("historical");
        let candidate = approved_review_candidate();
        let mut plan = update_plan(candidate.clone());
        plan.indexer_version = "0.1.0".to_owned();
        write_admission_record(
            &root,
            &plan,
            &candidate,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        validate_admission_inventory(&catalog_for(&root, &candidate)).unwrap();

        let record = AdmissionRecord {
            schema: ADMISSION_RECORD_SCHEMA,
            indexer_version: plan.indexer_version,
            catalog_sha256: plan.catalog_sha256,
            evaluated_at: plan.evaluated_at,
            admitted_at: UtcTimestamp::parse("2025-02-01T00:30:00Z").unwrap(),
            min_release_age_days: plan.min_release_age_days,
            dormant_release_gap_days: plan.dormant_release_gap_days,
            candidate,
        };
        assert!(serialize_admission_record(&record).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_rejects_noncanonical_binding_and_duplicate_identity() {
        let root = temporary_directory("inventory");
        let candidate = approved_review_candidate();
        let plan = update_plan(candidate.clone());
        let relative = write_admission_record(
            &root,
            &plan,
            &candidate,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        let path = root.join(&relative);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(validate_admission_inventory(&catalog_for(&root, &candidate)).is_err());
        fs::remove_dir_all(&root).unwrap();

        let root = temporary_directory("duplicate");
        let candidate = approved_review_candidate();
        let plan = update_plan(candidate.clone());
        write_admission_record(
            &root,
            &plan,
            &candidate,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        let mut other = candidate.clone();
        other.sparse_index_sha256 = "09".repeat(32);
        other.approvals.clear();
        other.approvals.push(approval_for(&other));
        write_admission_record(
            &root,
            &update_plan(other.clone()),
            &other,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        assert!(validate_admission_inventory(&catalog_for(&root, &candidate)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn review_tree_rejects_unexpected_nested_and_non_regular_entries() {
        let root = temporary_directory("tree");
        fs::create_dir_all(root.join("_reviews/admissions/nested")).unwrap();
        assert!(validate_admission_tree_structure(&root).is_err());
        fs::remove_dir_all(&root).unwrap();

        let root = temporary_directory("unexpected");
        fs::create_dir(root.join("_reviews")).unwrap();
        fs::create_dir(root.join("_reviews/other")).unwrap();
        assert!(validate_admission_tree_structure(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn review_tree_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("symlink");
        fs::create_dir(root.join("target")).unwrap();
        symlink(root.join("target"), root.join("_reviews")).unwrap();
        assert!(validate_admission_tree_structure(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn update_plan(candidate: UpdateCandidate) -> UpdatePlan {
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "07".repeat(32),
            evaluated_at: UtcTimestamp::parse("2025-02-01T00:00:00Z").unwrap(),
            min_release_age_days: MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: super::super::DORMANT_RELEASE_GAP_DAYS,
            candidates: vec![candidate],
        }
    }

    fn approved_review_candidate() -> UpdateCandidate {
        let mut candidate = candidate(UpdateDecision::ReviewRequired);
        candidate.approvals.push(approval_for(&candidate));
        candidate
    }

    fn approval_for(candidate: &UpdateCandidate) -> UpdateApproval {
        UpdateApproval {
            kind: ApprovalKind::FullArchive,
            binding_sha256: candidate_binding_sha256(candidate).unwrap(),
            approved_at: UtcTimestamp::parse("2025-02-01T01:00:00Z").unwrap(),
            note: "Reviewed all files.".to_owned(),
            note_sha256: crate::artifact::sha256_bytes(b"Reviewed all files."),
        }
    }

    fn candidate(decision: UpdateDecision) -> UpdateCandidate {
        let (activity, source, reasons) = match decision {
            UpdateDecision::Automatic => (
                PackageActivity::Active,
                SourceEvidence::Unavailable {
                    reason: "not-promoted".to_owned(),
                },
                Vec::new(),
            ),
            UpdateDecision::ReviewRequired => (
                PackageActivity::New,
                SourceEvidence::Unavailable {
                    reason: "source-verification-error".to_owned(),
                },
                vec![
                    DecisionReason::NewPackage,
                    DecisionReason::SourceUnavailable,
                    DecisionReason::ExplicitCandidate,
                ],
            ),
            UpdateDecision::Blocked => (
                PackageActivity::Active,
                SourceEvidence::Mismatch {
                    comparison_sha256: "06".repeat(32),
                },
                vec![DecisionReason::SourceMismatch],
            ),
        };
        UpdateCandidate {
            registry: "universe".to_owned(),
            category: "universe/general".to_owned(),
            name: "demo".to_owned(),
            activity,
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
            source,
            decision,
            reasons,
            approvals: Vec::new(),
        }
    }

    fn catalog_for(root: &Path, candidate: &UpdateCandidate) -> Catalog {
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
            approvals: vec![Approval {
                registry: candidate.registry.clone(),
                category: CategoryId::new(&candidate.registry, "general").unwrap(),
                name: candidate.name.clone(),
                version: candidate.candidate.version.clone(),
                archive_sha256: candidate.candidate.crate_sha256.clone(),
                index_record_sha256: candidate.candidate.source_row_sha256.clone(),
                index_row_sha256: "08".repeat(32),
                state: PackageState::Active,
                source: Source::CratesIo,
                declared_in: root.join("universe.lock"),
            }],
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
