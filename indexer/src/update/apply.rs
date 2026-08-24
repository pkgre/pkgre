//! Evidence-bound transactional application of approved update plans.

use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::category::CategoryId;
use crate::lock::{self, MirrorAdmission, ReconcileSummary};

use super::admission::{validate_admissible_candidate, validate_plan_age, write_admission_record};
use super::declaration::append_mirror_version;
use super::workflow::{LivePlannerResolver, revalidate_update_plan_with};
use super::{
    UpdatePlan, UtcTimestamp, candidate_binding_sha256, catalog_fingerprint, load_update_plan,
};

/// Revalidates and atomically admits every exact candidate in one canonical approved plan.
///
/// Network-backed evidence is recomputed at the plan's immutable evaluation time before a guarded
/// catalog transaction begins. The declaration edits, immutable admission records, generated locks,
/// and objects are installed as one complete directory replacement.
///
/// # Errors
///
/// Returns an error for an empty, stale, future-dated, blocked, incorrectly approved, or drifted
/// plan; catalog fingerprint drift; changed upstream evidence; reconciliation failure; or an invalid
/// staged catalog. Any failure before installation leaves the live catalog unchanged.
pub fn apply_update_plan(root: &Path, plan_path: &Path) -> Result<ReconcileSummary> {
    let admitted_at = UtcTimestamp::now().context("read update admission time")?;
    apply_update_plan_with(
        root,
        plan_path,
        &LivePlannerResolver,
        &lock::LiveResolver,
        &admitted_at,
    )
}

pub(crate) fn apply_update_plan_with<P: super::workflow::PlannerResolver, L: lock::Resolver>(
    root: &Path,
    plan_path: &Path,
    planner_resolver: &P,
    lock_resolver: &L,
    admitted_at: &UtcTimestamp,
) -> Result<ReconcileSummary> {
    let plan = load_update_plan(plan_path).context("load approved update plan")?;
    ensure!(
        !plan.candidates.is_empty(),
        "update plan contains no candidates"
    );

    validate_plan_age(&plan, admitted_at)?;
    for candidate in &plan.candidates {
        validate_admissible_candidate(candidate)?;
    }
    ensure!(
        catalog_fingerprint(root)? == plan.catalog_sha256,
        "catalog fingerprint differs from the approved update plan"
    );

    let recomputed = revalidate_update_plan_with(root, &plan, planner_resolver)
        .context("revalidate exact update-plan evidence")?;
    ensure_revalidation_matches(&plan, &recomputed)?;

    lock::transact_catalog(root, &plan.catalog_sha256, |staged| {
        let mut admissions = Vec::with_capacity(plan.candidates.len());
        for candidate in &plan.candidates {
            append_mirror_version(staged, candidate).with_context(|| {
                format!(
                    "declare admitted candidate {} {}",
                    candidate.name, candidate.candidate.version
                )
            })?;
            write_admission_record(staged, &plan, candidate, admitted_at).with_context(|| {
                format!(
                    "retain admission evidence for {} {}",
                    candidate.name, candidate.candidate.version
                )
            })?;
            admissions.push(MirrorAdmission {
                registry: candidate.registry.clone(),
                category: candidate
                    .category
                    .parse::<CategoryId>()
                    .context("parse admitted candidate category")?,
                name: candidate.name.clone(),
                version: candidate.candidate.version.clone(),
                crate_sha256: candidate.candidate.crate_sha256.clone(),
                source_row_sha256: candidate.candidate.source_row_sha256.clone(),
                binding_sha256: candidate_binding_sha256(candidate)?,
            });
        }
        lock::reconcile_admitted_with(staged, &admissions, lock_resolver)
            .context("reconcile exact admitted mirror identities")
    })
}

fn ensure_revalidation_matches(planned: &UpdatePlan, recomputed: &UpdatePlan) -> Result<()> {
    let mut approved_evidence = planned.clone();
    for candidate in &mut approved_evidence.candidates {
        candidate.approvals.clear();
    }

    let mut current_evidence = recomputed.clone();
    for (approved, current) in approved_evidence
        .candidates
        .iter()
        .zip(&mut current_evidence.candidates)
    {
        if let (Some(approved_api), Some(current_api)) = (&approved.api, &mut current.api) {
            // crates.io responses contain mutable counters and other non-decision fields. Retain the
            // raw-response hash as planning provenance while revalidating every parsed API field.
            current_api.response_sha256 = approved_api.response_sha256.clone();
        }
    }

    ensure!(
        approved_evidence == current_evidence,
        "recomputed update evidence differs from the approved plan"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::update::{
        ApiEvidence, ApiVersionEvidence, ArchiveSummary, DependencyDelta, PackageActivity,
        PlannedIdentity, SourceEvidence, TrustedPublishingEvidence, UPDATE_PLAN_SCHEMA,
        UpdateCandidate, UpdateDecision,
    };

    #[test]
    fn revalidation_ignores_approval_assertions_and_raw_api_response_hash() {
        let mut planned = plan();
        planned.candidates[0].api = Some(api_evidence());
        let mut recomputed = planned.clone();
        recomputed.candidates[0]
            .api
            .as_mut()
            .unwrap()
            .response_sha256 = "88".repeat(32);
        planned.candidates[0]
            .approvals
            .push(crate::update::UpdateApproval {
                kind: crate::update::ApprovalKind::FullArchive,
                binding_sha256: "66".repeat(32),
                approved_at: UtcTimestamp::parse("2025-02-01T00:00:00Z").unwrap(),
                note: "reviewed".to_owned(),
                note_sha256: "77".repeat(32),
            });

        ensure_revalidation_matches(&planned, &recomputed).unwrap();
    }

    #[test]
    fn revalidation_rejects_stable_api_evidence_drift() {
        let mut planned = plan();
        planned.candidates[0].api = Some(api_evidence());

        let mut publisher_drift = planned.clone();
        publisher_drift.candidates[0]
            .api
            .as_mut()
            .unwrap()
            .candidate
            .publisher_login = Some("different-publisher".to_owned());
        assert!(ensure_revalidation_matches(&planned, &publisher_drift).is_err());

        let mut repository_drift = planned.clone();
        repository_drift.candidates[0]
            .api
            .as_mut()
            .unwrap()
            .candidate
            .repository = Some("https://github.com/example/different".to_owned());
        assert!(ensure_revalidation_matches(&planned, &repository_drift).is_err());

        let mut trusted_publishing_drift = planned.clone();
        trusted_publishing_drift.candidates[0]
            .api
            .as_mut()
            .unwrap()
            .candidate
            .trusted_publishing
            .as_mut()
            .unwrap()
            .commit = "99".repeat(20);
        assert!(ensure_revalidation_matches(&planned, &trusted_publishing_drift).is_err());

        let mut missing_api = planned.clone();
        missing_api.candidates[0].api = None;
        assert!(ensure_revalidation_matches(&planned, &missing_api).is_err());
    }

    #[test]
    fn revalidation_rejects_archive_and_checksum_drift() {
        let planned = plan();

        let mut checksum_drift = planned.clone();
        checksum_drift.candidates[0].candidate.crate_sha256 = "99".repeat(32);
        assert!(ensure_revalidation_matches(&planned, &checksum_drift).is_err());

        let mut archive_drift = planned.clone();
        archive_drift.candidates[0]
            .candidate_archive
            .analysis_sha256 = "88".repeat(32);
        assert!(ensure_revalidation_matches(&planned, &archive_drift).is_err());
    }

    fn api_evidence() -> ApiEvidence {
        ApiEvidence {
            response_sha256: "aa".repeat(32),
            base: None,
            candidate: ApiVersionEvidence {
                publisher_id: Some(7),
                publisher_login: Some("publisher".to_owned()),
                repository: Some("https://github.com/example/demo".to_owned()),
                trusted_publishing: Some(TrustedPublishingEvidence {
                    provider: "github".to_owned(),
                    repository: "https://github.com/example/demo".to_owned(),
                    commit: "11".repeat(20),
                    evidence_sha256: "bb".repeat(32),
                }),
            },
        }
    }

    fn plan() -> UpdatePlan {
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
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
                    version: "1.0.0".parse().unwrap(),
                    published_at: UtcTimestamp::parse("2025-01-01T00:00:00Z").unwrap(),
                    source_row_sha256: "11".repeat(32),
                    crate_sha256: "22".repeat(32),
                },
                sparse_index_sha256: "33".repeat(32),
                decision_history_sha256: "44".repeat(32),
                age_seconds: 30 * 24 * 60 * 60,
                dormant_gap: None,
                base_archive: None,
                candidate_archive: ArchiveSummary {
                    analysis_sha256: "55".repeat(32),
                    compressed_bytes: 1,
                    unpacked_bytes: 1,
                    files: 1,
                    build_surface: BTreeMap::default(),
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
                    reason: "not promoted".to_owned(),
                },
                decision: UpdateDecision::ReviewRequired,
                reasons: vec![
                    crate::update::DecisionReason::NewPackage,
                    crate::update::DecisionReason::SourceUnavailable,
                    crate::update::DecisionReason::ExplicitCandidate,
                ],
                approvals: Vec::new(),
            }],
        }
    }
}
