//! Safe crates.io mirror update planning, review, and admission.

mod admission;
mod api;
mod apply;
mod archive;
mod declaration;
mod inspect;
mod manifest;
mod plan;
mod policy;
mod source;
pub mod time;
mod workflow;

#[cfg(test)]
mod e2e_tests;

pub(crate) use admission::{validate_admission_inventory, validate_admission_tree_structure};
pub use api::parse_crates_io_api_evidence;
pub use apply::apply_admission_manifest;
pub use archive::{ArchiveAnalysis, ArchiveFile, EmbeddedVcsInfo, inspect_crate_archive};
pub use inspect::inspect_update_candidate;
pub use manifest::{
    ADMISSION_MANIFEST_SCHEMA, AdmissionEvidence, AdmissionManifest, AdmissionRequest,
    load_admission_manifest, serialize_admission_manifest,
};
pub use plan::{
    ApiEvidence, ApiVersionEvidence, ArchiveDelta, ArchiveSummary, DecisionReason, DependencyDelta,
    PlannedIdentity, SourceEvidence, TrustedPublishingEvidence, UPDATE_PLAN_SCHEMA,
    UpdateCandidate, UpdateDecision, UpdatePlan, candidate_facts_sha256, catalog_fingerprint,
    compare_archive_analyses, load_update_plan, serialize_update_plan,
};
pub use policy::{
    CompatibilityLane, DORMANT_RELEASE_GAP_DAYS, LockedRelease, MIN_RELEASE_AGE_DAYS,
    PackageActivity, PolicyRelease, PublicationGap, SelectedCandidate, SelectedExactCandidate,
    classify_package, implicit_lane, select_exact_candidate, select_implicit_candidates,
};
pub use source::verify_source_correspondence;
pub use time::UtcTimestamp;
pub use workflow::{plan_exact_update, plan_updates};
