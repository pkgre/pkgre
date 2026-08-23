//! Exact evidence-bound human review assertions for canonical update plans.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::artifact::sha256_bytes;
use crate::schema::version_identity;

use super::{
    ApprovalKind, PackageActivity, UpdateApproval, UpdateCandidate, UpdateDecision, UpdatePlan,
    UtcTimestamp, candidate_binding_sha256, load_update_plan, serialize_update_plan,
};

const MAX_APPROVAL_NOTE_BYTES: u64 = 16 * 1024;

/// Adds one exact, evidence-bound human review assertion to a canonical plan.
///
/// The input plan and note remain unchanged. The output path must not exist. New and inactive
/// package admissions require complete-archive review; active packages with a meaningful base
/// require source-delta review.
///
/// # Errors
///
/// Returns an error for a noncanonical plan, absent or ambiguous candidate, non-review candidate,
/// wrong review scope, unsafe/empty/oversized note, existing output, or write failure.
pub fn approve_update_plan(
    input: &Path,
    output: &Path,
    name: &str,
    version: &Version,
    kind: ApprovalKind,
    note_path: &Path,
) -> Result<UpdatePlan> {
    crate::policy::validate_package_name(name).context("invalid approval package name")?;
    let mut plan = load_update_plan(input)?;
    let matches = plan
        .candidates
        .iter_mut()
        .filter(|candidate| {
            candidate.name == name
                && version_identity(&candidate.candidate.version) == version_identity(version)
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "update plan contains {} candidates for {name} {version}; expected exactly one",
        matches.len()
    );
    let candidate = matches
        .into_iter()
        .next()
        .context("exact approval candidate disappeared")?;
    ensure!(
        candidate.decision == UpdateDecision::ReviewRequired,
        "candidate {name} {version} is not review-required"
    );
    ensure!(
        candidate.approvals.is_empty(),
        "candidate {name} {version} already has an approval"
    );
    let required = required_approval_kind(candidate);
    ensure!(
        kind == required,
        "candidate {name} {version} requires {required:?} review, not {kind:?}"
    );
    let note = read_review_note(note_path)?;
    candidate.approvals.push(UpdateApproval {
        kind,
        binding_sha256: candidate_binding_sha256(candidate)?,
        approved_at: UtcTimestamp::now()?,
        note_sha256: sha256_bytes(note.as_bytes()),
        note,
    });
    let bytes = serialize_update_plan(&plan)?;
    write_new(output, &bytes)?;
    Ok(plan)
}

/// Returns the minimum review scope required for one candidate.
#[must_use]
pub fn required_approval_kind(candidate: &UpdateCandidate) -> ApprovalKind {
    if candidate.activity == PackageActivity::Active && candidate.archive_delta.is_some() {
        ApprovalKind::SourceDelta
    } else {
        ApprovalKind::FullArchive
    }
}

fn read_review_note(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect approval note {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "approval note is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_APPROVAL_NOTE_BYTES,
        "approval note exceeds {MAX_APPROVAL_NOTE_BYTES} bytes"
    );
    let bytes = fs::read(path).with_context(|| format!("read approval note {}", path.display()))?;
    ensure!(
        u64::try_from(bytes.len()).is_ok_and(|size| size <= MAX_APPROVAL_NOTE_BYTES),
        "approval note grew beyond {MAX_APPROVAL_NOTE_BYTES} bytes while being read"
    );
    let text = String::from_utf8(bytes).context("approval note is not valid UTF-8")?;
    let trimmed = text.trim();
    ensure!(!trimmed.is_empty(), "approval note is empty");
    Ok(trimmed.to_owned())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create approved update plan {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write approved update plan {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync approved update plan {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::update::{
        ArchiveDelta, ArchiveSummary, DORMANT_RELEASE_GAP_DAYS, DecisionReason, DependencyDelta,
        MIN_RELEASE_AGE_DAYS, PlannedIdentity, SourceEvidence, UPDATE_PLAN_SCHEMA,
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn candidate(activity: PackageActivity, with_base: bool) -> UpdateCandidate {
        let identity = PlannedIdentity {
            version: Version::parse("1.0.1").unwrap(),
            published_at: UtcTimestamp::parse("2025-01-01T00:00:00Z").unwrap(),
            source_row_sha256: "01".repeat(32),
            crate_sha256: "02".repeat(32),
        };
        let summary = ArchiveSummary {
            analysis_sha256: "03".repeat(32),
            compressed_bytes: 1,
            unpacked_bytes: 1,
            files: 1,
            build_surface: BTreeMap::new(),
            vcs_commit: None,
            vcs_path: None,
        };
        UpdateCandidate {
            registry: "universe".to_owned(),
            category: "universe/general".to_owned(),
            name: "demo".to_owned(),
            activity,
            lane: None,
            base: with_base.then(|| PlannedIdentity {
                version: Version::parse("1.0.0").unwrap(),
                ..identity.clone()
            }),
            candidate: identity,
            sparse_index_sha256: "04".repeat(32),
            decision_history_sha256: "05".repeat(32),
            age_seconds: 30 * 24 * 60 * 60,
            dormant_gap: None,
            base_archive: with_base.then(|| summary.clone()),
            candidate_archive: summary,
            archive_delta: with_base.then(|| ArchiveDelta {
                delta_sha256: "06".repeat(32),
                added: Vec::new(),
                removed: Vec::new(),
                changed: Vec::new(),
                build_surface_changed: false,
            }),
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
            reasons: vec![DecisionReason::SourceUnavailable],
            approvals: Vec::new(),
        }
    }

    #[test]
    fn review_scope_requires_full_archive_without_meaningful_active_base() {
        assert_eq!(
            required_approval_kind(&candidate(PackageActivity::New, false)),
            ApprovalKind::FullArchive
        );
        assert_eq!(
            required_approval_kind(&candidate(PackageActivity::Inactive, true)),
            ApprovalKind::FullArchive
        );
        assert_eq!(
            required_approval_kind(&candidate(PackageActivity::Active, true)),
            ApprovalKind::SourceDelta
        );
    }

    #[test]
    fn approval_is_trimmed_bound_and_written_without_mutating_input() {
        let root = temporary_directory("approve");
        let input = root.join("plan.toml");
        let output = root.join("approved.toml");
        let wrong_output = root.join("wrong.toml");
        let note = root.join("note.txt");
        let mut planned = candidate(PackageActivity::New, false);
        planned.reasons = vec![
            DecisionReason::NewPackage,
            DecisionReason::SourceUnavailable,
            DecisionReason::ExplicitCandidate,
        ];
        let plan = UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "07".repeat(32),
            evaluated_at: UtcTimestamp::parse("2025-01-31T00:00:00Z").unwrap(),
            min_release_age_days: MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: DORMANT_RELEASE_GAP_DAYS,
            candidates: vec![planned],
        };
        let input_bytes = serialize_update_plan(&plan).unwrap();
        fs::write(&input, &input_bytes).unwrap();
        fs::write(&note, b"  Reviewed every archive file.\n").unwrap();

        assert!(
            approve_update_plan(
                &input,
                &wrong_output,
                "demo",
                &Version::parse("1.0.1").unwrap(),
                ApprovalKind::SourceDelta,
                &note,
            )
            .is_err()
        );
        assert!(!wrong_output.exists());
        let approved = approve_update_plan(
            &input,
            &output,
            "demo",
            &Version::parse("1.0.1").unwrap(),
            ApprovalKind::FullArchive,
            &note,
        )
        .unwrap();

        assert_eq!(fs::read(&input).unwrap(), input_bytes);
        let assertion = &approved.candidates[0].approvals[0];
        assert_eq!(assertion.note, "Reviewed every archive file.");
        assert_eq!(
            assertion.binding_sha256,
            candidate_binding_sha256(&approved.candidates[0]).unwrap()
        );
        assert_eq!(load_update_plan(&output).unwrap(), approved);
        fs::remove_dir_all(root).unwrap();
    }

    fn temporary_directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pkgre-update-approval-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }
}
