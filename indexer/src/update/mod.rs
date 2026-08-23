//! Safe crates.io mirror update planning, review, and admission.

mod api;
mod approval;
mod archive;
mod plan;
mod policy;
mod source;
mod time;
mod workflow;

pub use api::parse_crates_io_api_evidence;
pub use approval::{approve_update_plan, required_approval_kind};
pub use archive::{ArchiveAnalysis, ArchiveFile, EmbeddedVcsInfo, inspect_crate_archive};
pub use plan::{
    ApiEvidence, ApiVersionEvidence, ApprovalKind, ArchiveDelta, ArchiveSummary, DecisionReason,
    DependencyDelta, MAX_PLAN_AGE_DAYS, PlannedIdentity, SourceEvidence, TrustedPublishingEvidence,
    UPDATE_PLAN_SCHEMA, UpdateApproval, UpdateCandidate, UpdateDecision, UpdatePlan,
    candidate_binding_sha256, catalog_fingerprint, compare_archive_analyses, load_update_plan,
    serialize_update_plan,
};
pub use policy::{
    CompatibilityLane, DORMANT_RELEASE_GAP_DAYS, LockedRelease, MIN_RELEASE_AGE_DAYS,
    PackageActivity, PolicyRelease, PublicationGap, SelectedCandidate, SelectedExactCandidate,
    classify_package, implicit_lane, select_exact_candidate, select_implicit_candidates,
};
pub use source::verify_source_correspondence;
pub use time::UtcTimestamp;
pub use workflow::{plan_exact_update, plan_updates};
