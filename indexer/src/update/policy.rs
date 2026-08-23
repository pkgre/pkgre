//! Pure release-selection and mandatory-review policy for crates.io updates.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::UtcTimestamp;

/// Minimum release age required by the automatic update path.
pub const MIN_RELEASE_AGE_DAYS: u64 = 30;
/// Publication gap that triggers dormant-wake-up review.
pub const DORMANT_RELEASE_GAP_DAYS: u64 = 365;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// Cargo-compatible stable release lane eligible for implicit updates.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum CompatibilityLane {
    /// Stable `0.minor.patch`, where `minor > 0`.
    ZeroMinor {
        /// Stable minor component.
        minor: u64,
    },
    /// Stable `major.x.y`, where `major >= 1`.
    Major {
        /// Stable major component.
        major: u64,
    },
}

/// One strictly parsed upstream publication used by update policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRelease {
    /// Exact Cargo version.
    pub version: Version,
    /// Canonical crates.io publication time.
    pub published_at: UtcTimestamp,
    /// Current upstream yank state.
    pub yanked: bool,
}

/// One exact identity retained by the generated catalog lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedRelease {
    /// Exact locked Cargo version.
    pub version: Version,
    /// Publication time recovered from the retained source row.
    pub published_at: UtcTimestamp,
    /// Whether the identity remains active.
    pub active: bool,
}

/// Whether a permanently reserved package name has admitted history and an active identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageActivity {
    /// No exact identity has ever been locked, including an empty reservation.
    New,
    /// Historical identities exist but every one is removed.
    Inactive,
    /// At least one locked identity is active.
    Active,
}

/// Exact adjacent publication gap that triggered dormant-wake-up review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicationGap {
    /// Publication immediately before the gap.
    pub before_version: Version,
    /// Time immediately before the gap.
    pub before_published_at: UtcTimestamp,
    /// First publication after the gap.
    pub after_version: Version,
    /// Time immediately after the gap.
    pub after_published_at: UtcTimestamp,
    /// Exact whole-second gap.
    pub seconds: u64,
}

/// One latest age-eligible candidate selected for an already-active compatibility lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedCandidate {
    /// Compatible release lane.
    pub lane: CompatibilityLane,
    /// Highest active version in this lane at planning time.
    pub active_lane_maximum: Version,
    /// Most recently published prior locked identity used as the review base.
    pub base: LockedRelease,
    /// Highest age-eligible, non-yanked, stable version greater than the active lane maximum.
    pub candidate: PolicyRelease,
    /// Exact candidate age at evaluation time.
    pub age_seconds: u64,
    /// First dormant gap since the locked base, if any.
    pub dormant_gap: Option<PublicationGap>,
}

/// Returns the implicit stable compatibility lane for a version.
///
/// Stable `0.0.z` and every prerelease intentionally return `None` and require an exact explicit request.
#[must_use]
pub fn implicit_lane(version: &Version) -> Option<CompatibilityLane> {
    if !version.pre.is_empty() {
        return None;
    }
    if version.major >= 1 {
        return Some(CompatibilityLane::Major {
            major: version.major,
        });
    }
    if version.minor > 0 {
        return Some(CompatibilityLane::ZeroMinor {
            minor: version.minor,
        });
    }
    None
}

/// Classifies a reserved name from its complete locked identity history.
#[must_use]
pub fn classify_package(locked: &[LockedRelease]) -> PackageActivity {
    if locked.is_empty() {
        PackageActivity::New
    } else if locked.iter().any(|release| release.active) {
        PackageActivity::Active
    } else {
        PackageActivity::Inactive
    }
}

/// Selects at most one implicit update per distinct active compatibility lane.
///
/// Selection is deterministic and considers only non-yanked stable candidates that are at least 30 exact UTC days old and greater than the highest active version in the same lane. Yanked and prerelease rows still participate in dormant-activity scans.
///
/// # Errors
///
/// Returns an error for a future upstream timestamp, duplicate upstream or locked Cargo identity, a locked identity missing from upstream history, or a lane without a usable prior locked base.
pub fn select_implicit_candidates(
    evaluation_time: &UtcTimestamp,
    history: &[PolicyRelease],
    locked: &[LockedRelease],
) -> Result<Vec<SelectedCandidate>> {
    validate_unique_versions(history, "upstream publication")?;
    validate_unique_locked_versions(locked)?;
    for release in history {
        evaluation_time
            .duration_since(&release.published_at)
            .with_context(|| {
                format!(
                    "upstream publication {} has future pubtime {} relative to evaluation time {}",
                    release.version, release.published_at, evaluation_time
                )
            })?;
    }

    let upstream = history
        .iter()
        .map(|release| (version_key(&release.version), release))
        .collect::<BTreeMap<_, _>>();
    for release in locked {
        let observed = upstream
            .get(&version_key(&release.version))
            .with_context(|| {
                format!(
                    "locked identity {} is absent from current upstream history",
                    release.version
                )
            })?;
        ensure!(
            observed.published_at == release.published_at,
            "locked identity {} publication time changed from {} to {}",
            release.version,
            release.published_at,
            observed.published_at
        );
    }

    let mut active_maxima = BTreeMap::<CompatibilityLane, &LockedRelease>::new();
    for release in locked.iter().filter(|release| release.active) {
        let Some(lane) = implicit_lane(&release.version) else {
            continue;
        };
        match active_maxima.get(&lane) {
            Some(previous) if previous.version >= release.version => {}
            _ => {
                active_maxima.insert(lane, release);
            }
        }
    }

    let minimum_age_seconds = MIN_RELEASE_AGE_DAYS * SECONDS_PER_DAY;
    let mut selected = Vec::new();
    for (lane, active_maximum) in active_maxima {
        let candidate = history
            .iter()
            .filter(|release| implicit_lane(&release.version).as_ref() == Some(&lane))
            .filter(|release| !release.yanked && release.version > active_maximum.version)
            .filter(|release| {
                evaluation_time
                    .duration_since(&release.published_at)
                    .is_ok_and(|age| age >= minimum_age_seconds)
            })
            .max_by(|left, right| left.version.cmp(&right.version));
        let Some(candidate) = candidate else {
            continue;
        };
        let base = locked
            .iter()
            .filter(|release| implicit_lane(&release.version).as_ref() == Some(&lane))
            .filter(|release| release.published_at <= candidate.published_at)
            .max_by(|left, right| {
                (&left.published_at, &left.version).cmp(&(&right.published_at, &right.version))
            })
            .context("active compatibility lane has no prior locked base")?
            .clone();
        let age_seconds = evaluation_time.duration_since(&candidate.published_at)?;
        let dormant_gap = first_dormant_gap(history, &base, candidate)?;
        selected.push(SelectedCandidate {
            lane,
            active_lane_maximum: active_maximum.version.clone(),
            base,
            candidate: candidate.clone(),
            age_seconds,
            dormant_gap,
        });
    }
    Ok(selected)
}

fn first_dormant_gap(
    history: &[PolicyRelease],
    base: &LockedRelease,
    candidate: &PolicyRelease,
) -> Result<Option<PublicationGap>> {
    ensure!(
        base.published_at <= candidate.published_at,
        "candidate predates its locked base"
    );
    let mut activity = history
        .iter()
        .filter(|release| {
            release.published_at >= base.published_at
                && release.published_at <= candidate.published_at
        })
        .collect::<Vec<_>>();
    activity.sort_by(|left, right| {
        (&left.published_at, &left.version).cmp(&(&right.published_at, &right.version))
    });
    ensure!(
        activity
            .iter()
            .any(|release| version_key(&release.version) == version_key(&candidate.version)),
        "selected candidate is absent from publication activity"
    );

    let mut previous_version = base.version.clone();
    let mut previous_time = base.published_at.clone();
    for release in activity {
        if release.published_at < previous_time
            || (release.published_at == previous_time
                && version_key(&release.version) == version_key(&previous_version))
        {
            continue;
        }
        let seconds = release.published_at.duration_since(&previous_time)?;
        if seconds >= DORMANT_RELEASE_GAP_DAYS * SECONDS_PER_DAY {
            return Ok(Some(PublicationGap {
                before_version: previous_version,
                before_published_at: previous_time,
                after_version: release.version.clone(),
                after_published_at: release.published_at.clone(),
                seconds,
            }));
        }
        previous_version.clone_from(&release.version);
        previous_time.clone_from(&release.published_at);
    }
    Ok(None)
}

fn validate_unique_versions(releases: &[PolicyRelease], description: &str) -> Result<()> {
    let mut versions = BTreeSet::new();
    for release in releases {
        ensure!(
            versions.insert(version_key(&release.version)),
            "duplicate {description} Cargo identity {}",
            release.version
        );
    }
    Ok(())
}

fn validate_unique_locked_versions(releases: &[LockedRelease]) -> Result<()> {
    let mut versions = BTreeSet::new();
    for release in releases {
        ensure!(
            versions.insert(version_key(&release.version)),
            "duplicate locked Cargo identity {}",
            release.version
        );
    }
    Ok(())
}

fn version_key(version: &Version) -> (u64, u64, u64, String) {
    (
        version.major,
        version.minor,
        version.patch,
        version.pre.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: &str) -> UtcTimestamp {
        UtcTimestamp::parse(value).unwrap()
    }

    fn release(version: &str, published_at: &str, yanked: bool) -> PolicyRelease {
        PolicyRelease {
            version: Version::parse(version).unwrap(),
            published_at: timestamp(published_at),
            yanked,
        }
    }

    fn locked(version: &str, published_at: &str, active: bool) -> LockedRelease {
        LockedRelease {
            version: Version::parse(version).unwrap(),
            published_at: timestamp(published_at),
            active,
        }
    }

    #[test]
    fn compatibility_lanes_exclude_zero_zero_and_prereleases() {
        assert_eq!(
            implicit_lane(&Version::parse("2.4.0").unwrap()),
            Some(CompatibilityLane::Major { major: 2 })
        );
        assert_eq!(
            implicit_lane(&Version::parse("0.7.4").unwrap()),
            Some(CompatibilityLane::ZeroMinor { minor: 7 })
        );
        assert_eq!(implicit_lane(&Version::parse("0.0.9").unwrap()), None);
        assert_eq!(implicit_lane(&Version::parse("1.2.0-rc.1").unwrap()), None);
    }

    #[test]
    fn package_activity_distinguishes_empty_reservation_and_inactive_history() {
        assert_eq!(classify_package(&[]), PackageActivity::New);
        assert_eq!(
            classify_package(&[locked("1.0.0", "2020-01-01T00:00:00Z", false)]),
            PackageActivity::Inactive
        );
        assert_eq!(
            classify_package(&[
                locked("1.0.0", "2020-01-01T00:00:00Z", false),
                locked("1.1.0", "2020-02-01T00:00:00Z", true),
            ]),
            PackageActivity::Active
        );
    }

    #[test]
    fn age_boundary_selects_exactly_thirty_days_but_not_one_second_before() {
        let history = vec![
            release("1.0.0", "2024-01-01T00:00:00Z", false),
            release("1.0.1", "2024-02-01T00:00:00Z", false),
        ];
        let locked = vec![locked("1.0.0", "2024-01-01T00:00:00Z", true)];
        let before = timestamp("2024-03-01T23:59:59Z");
        assert!(
            select_implicit_candidates(&before, &history, &locked)
                .unwrap()
                .is_empty()
        );
        let boundary = timestamp("2024-03-02T00:00:00Z");
        let selected = select_implicit_candidates(&boundary, &history, &locked).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].candidate.version,
            Version::parse("1.0.1").unwrap()
        );
        assert_eq!(selected[0].age_seconds, 30 * SECONDS_PER_DAY);
    }

    #[test]
    fn latest_eligible_non_yanked_candidate_is_selected_per_active_lane() {
        let history = vec![
            release("0.7.1", "2020-01-01T00:00:00Z", false),
            release("0.7.2", "2020-02-01T00:00:00Z", false),
            release("0.7.3", "2020-03-01T00:00:00Z", true),
            release("0.8.0", "2020-01-02T00:00:00Z", false),
            release("1.4.0", "2020-01-01T00:00:00Z", false),
            release("1.5.0-rc.1", "2020-02-01T00:00:00Z", false),
            release("1.5.0", "2020-03-01T00:00:00Z", false),
            release("2.0.0", "2020-03-01T00:00:00Z", false),
        ];
        let locked = vec![
            locked("0.7.1", "2020-01-01T00:00:00Z", true),
            locked("1.4.0", "2020-01-01T00:00:00Z", true),
        ];
        let selected =
            select_implicit_candidates(&timestamp("2021-01-01T00:00:00Z"), &history, &locked)
                .unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0].candidate.version,
            Version::parse("0.7.2").unwrap()
        );
        assert_eq!(
            selected[1].candidate.version,
            Version::parse("1.5.0").unwrap()
        );
    }

    #[test]
    fn exact_365_day_gap_including_yanked_and_prerelease_activity_is_gated() {
        let history = vec![
            release("1.0.0", "2020-01-01T00:00:00Z", false),
            release("2.0.0-alpha.1", "2020-12-30T00:00:00Z", true),
            release("1.0.1", "2021-12-30T00:00:00Z", false),
        ];
        let selected = select_implicit_candidates(
            &timestamp("2022-02-01T00:00:00Z"),
            &history,
            &[locked("1.0.0", "2020-01-01T00:00:00Z", true)],
        )
        .unwrap();
        let gap = selected[0].dormant_gap.as_ref().unwrap();
        assert_eq!(gap.before_version, Version::parse("2.0.0-alpha.1").unwrap());
        assert_eq!(gap.after_version, Version::parse("1.0.1").unwrap());
        assert_eq!(gap.seconds, 365 * SECONDS_PER_DAY);
    }

    #[test]
    fn post_gap_burst_remains_gated_until_one_post_gap_identity_is_locked() {
        let history = vec![
            release("1.0.0", "2020-01-01T00:00:00Z", false),
            release("1.0.1", "2022-01-01T00:00:00Z", false),
            release("1.0.2", "2022-01-02T00:00:00Z", false),
        ];
        let evaluation = timestamp("2022-03-01T00:00:00Z");
        let first = select_implicit_candidates(
            &evaluation,
            &history,
            &[locked("1.0.0", "2020-01-01T00:00:00Z", true)],
        )
        .unwrap();
        assert!(first[0].dormant_gap.is_some());
        assert_eq!(first[0].candidate.version, Version::parse("1.0.2").unwrap());

        let admitted = select_implicit_candidates(
            &evaluation,
            &history,
            &[
                locked("1.0.0", "2020-01-01T00:00:00Z", true),
                locked("1.0.1", "2022-01-01T00:00:00Z", true),
            ],
        )
        .unwrap();
        assert!(admitted[0].dormant_gap.is_none());
        assert_eq!(admitted[0].base.version, Version::parse("1.0.1").unwrap());
    }

    #[test]
    fn future_publication_blocks_selection() {
        let error = select_implicit_candidates(
            &timestamp("2024-01-01T00:00:00Z"),
            &[
                release("1.0.0", "2023-01-01T00:00:00Z", false),
                release("1.0.1", "2024-01-01T00:00:01Z", false),
            ],
            &[locked("1.0.0", "2023-01-01T00:00:00Z", true)],
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("future pubtime"));
    }
}
