//! Safe crates.io mirror update planning, review, and admission.

mod policy;
mod time;

pub use policy::{
    CompatibilityLane, DORMANT_RELEASE_GAP_DAYS, LockedRelease, MIN_RELEASE_AGE_DAYS,
    PackageActivity, PolicyRelease, PublicationGap, SelectedCandidate, classify_package,
    implicit_lane, select_implicit_candidates,
};
pub use time::UtcTimestamp;
