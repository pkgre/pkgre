//! Canonical update-plan schema, content binding, and catalog fingerprints.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact::sha256_bytes;
use crate::index::IndexDependency;

use super::{ArchiveAnalysis, CompatibilityLane, PackageActivity, PublicationGap, UtcTimestamp};

/// Stable update-plan wire schema.
pub const UPDATE_PLAN_SCHEMA: u32 = 2;

/// Canonical, catalog-bound result of one read-only update-planning run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct UpdatePlan {
    /// Update-plan wire schema.
    pub schema: u32,
    /// Exact indexer version that calculated policy decisions.
    pub indexer_version: String,
    /// SHA-256 of the complete canonical catalog tree at planning time.
    pub catalog_sha256: String,
    /// Immutable UTC policy clock.
    pub evaluated_at: UtcTimestamp,
    /// Compiled minimum release age.
    pub min_release_age_days: u64,
    /// Compiled dormant publication gap.
    pub dormant_release_gap_days: u64,
    /// Selected exact candidates in canonical identity order.
    pub candidates: Vec<UpdateCandidate>,
}

/// Exact package identity and upstream row binding retained in a plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PlannedIdentity {
    /// Exact Cargo version.
    pub version: Version,
    /// Original crates.io publication time.
    pub published_at: UtcTimestamp,
    /// SHA-256 of the exact sparse-index JSON row bytes.
    pub source_row_sha256: String,
    /// Sparse-index archive checksum.
    pub crate_sha256: String,
}

/// Stable bounded summary of inert archive analysis.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ArchiveSummary {
    /// SHA-256 of the canonical complete analysis structure.
    pub analysis_sha256: String,
    /// Compressed archive size.
    pub compressed_bytes: u64,
    /// Decompressed tar-stream size.
    pub unpacked_bytes: u64,
    /// Number of regular files.
    pub files: usize,
    /// Complete security-relevant build surface.
    pub build_surface: BTreeMap<String, String>,
    /// Claimed embedded Git commit, when present.
    pub vcs_commit: Option<String>,
    /// Claimed repository-relative path, when present.
    pub vcs_path: Option<String>,
}

/// Stable archive change summary between the exact base and candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ArchiveDelta {
    /// SHA-256 of the complete canonical file delta.
    pub delta_sha256: String,
    /// Added file paths.
    pub added: Vec<String>,
    /// Removed file paths.
    pub removed: Vec<String>,
    /// Paths whose bytes or modes changed.
    pub changed: Vec<String>,
    /// Whether security-relevant build/executable surface changed.
    pub build_surface_changed: bool,
}

/// Stable Cargo index dependency delta.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyDelta {
    /// Exact normalized dependency edges added by the candidate.
    pub added: Vec<IndexDependency>,
    /// Exact normalized dependency edges removed from the base.
    pub removed: Vec<IndexDependency>,
    /// Package identities absent from the base dependency set.
    pub new_packages: Vec<String>,
}

/// Publisher/repository evidence for one version from the public crates.io API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ApiVersionEvidence {
    /// Stable crates.io account identifier, when available.
    pub publisher_id: Option<u64>,
    /// Public account login, when available.
    pub publisher_login: Option<String>,
    /// Version-scoped source repository, when available.
    pub repository: Option<String>,
    /// Trusted Publishing/OIDC context, when present.
    pub trusted_publishing: Option<TrustedPublishingEvidence>,
}

/// Normalized crates.io Trusted Publishing context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TrustedPublishingEvidence {
    /// OIDC provider (`github` or `gitlab`).
    pub provider: String,
    /// Provider repository/project identity.
    pub repository: String,
    /// Exact attested commit.
    pub commit: String,
    /// SHA-256 of the canonical complete Trusted Publishing object.
    pub evidence_sha256: String,
}

/// Parsed version-scoped API evidence plus raw-response provenance from planning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ApiEvidence {
    /// SHA-256 of the exact public API response bytes observed during planning.
    ///
    /// The response may contain mutable non-decision fields, so apply revalidates the parsed fields
    /// below rather than requiring this provenance hash to remain unchanged.
    pub response_sha256: String,
    /// Base version metadata, absent for a first-ever identity.
    pub base: Option<ApiVersionEvidence>,
    /// Candidate version metadata.
    pub candidate: ApiVersionEvidence,
}

/// Compact mechanical source-correspondence result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "level")]
pub enum SourceEvidence {
    /// Exact source correspondence was not obtainable or was not promoted.
    Unavailable {
        /// Public reason; never interpreted as a clean result.
        reason: String,
    },
    /// Publisher-asserted embedded VCS commit was compared to public Git history.
    PublisherAsserted {
        /// Credential-free repository URL.
        repository: String,
        /// Exact embedded commit.
        commit: String,
        /// Repository-relative package path.
        path: String,
        /// Hash of the deterministic comparison result.
        comparison_sha256: String,
    },
    /// Registry OIDC context, and any embedded VCS claim when present, were compared.
    RegistryContextAttested {
        /// Credential-free repository URL.
        repository: String,
        /// Exact attested commit.
        commit: String,
        /// Repository-relative package path.
        path: String,
        /// Hash of the deterministic comparison result.
        comparison_sha256: String,
        /// Hash of normalized Trusted Publishing evidence.
        attestation_sha256: String,
    },
    /// Mechanical archive-to-commit comparison found an unexplained mismatch.
    Mismatch {
        /// Deterministic mismatch report hash.
        comparison_sha256: String,
    },
}

/// Hard policy outcome for one exact candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateDecision {
    /// May be admitted by an automatic batch after ordinary protected review.
    Automatic,
    /// Merits prioritized human review before the complete registry PR is merged.
    ReviewRequired,
    /// Cannot be admitted by the routine update workflow.
    Blocked,
}

/// Machine-stable reason contributing to an update decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionReason {
    /// First-ever identity for a reserved name.
    NewPackage,
    /// Package has history but no active identity.
    InactiveRevival,
    /// Publication activity contains a 365-day wake-up gap.
    DormantWakeup,
    /// Candidate introduces a new dependency package identity.
    NewDependency,
    /// Candidate adds or modifies build-time executable/native surface.
    BuildSurfaceChanged,
    /// crates.io publisher account changed or is unavailable.
    PublisherDiscontinuity,
    /// Version-scoped repository changed or is unavailable.
    RepositoryDiscontinuity,
    /// Dependency package has no permanent catalog home.
    UnknownDependencyHome,
    /// Category policy forbids a candidate dependency edge.
    ForbiddenCategoryDependency,
    /// Promoted source correspondence is unavailable.
    SourceUnavailable,
    /// Mechanical source correspondence disagrees.
    SourceMismatch,
    /// Exact non-implicit identity was explicitly requested.
    ExplicitCandidate,
}

/// Complete evidence and outcome for one exact selected update.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct UpdateCandidate {
    /// Permanent registry home.
    pub registry: String,
    /// Permanent fully-qualified category home.
    pub category: String,
    /// Cargo package name.
    pub name: String,
    /// Name activity before this candidate.
    pub activity: PackageActivity,
    /// Implicit compatibility lane, absent for an exact explicit request.
    pub lane: Option<CompatibilityLane>,
    /// Exact locked review base, absent for a first identity.
    pub base: Option<PlannedIdentity>,
    /// Exact candidate identity.
    pub candidate: PlannedIdentity,
    /// SHA-256 of the complete sparse response observed while planning.
    pub sparse_index_sha256: String,
    /// Hash of decision-relevant publication rows from the base through candidate.
    pub decision_history_sha256: String,
    /// Candidate age at the fixed evaluation time.
    pub age_seconds: u64,
    /// First dormant gap since the approved base, if any.
    pub dormant_gap: Option<PublicationGap>,
    /// Base archive analysis, absent for a first identity.
    pub base_archive: Option<ArchiveSummary>,
    /// Candidate archive analysis.
    pub candidate_archive: ArchiveSummary,
    /// Exact archive change summary, absent for a first identity.
    pub archive_delta: Option<ArchiveDelta>,
    /// Exact Cargo dependency delta.
    pub dependencies: DependencyDelta,
    /// Version-scoped public crates.io API evidence.
    pub api: Option<ApiEvidence>,
    /// Mechanical source-correspondence evidence.
    pub source: SourceEvidence,
    /// Effective routine-update outcome.
    pub decision: UpdateDecision,
    /// Canonically sorted decision reasons.
    pub reasons: Vec<DecisionReason>,
}

impl ArchiveSummary {
    /// Builds a stable summary and content hash from complete archive analysis.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn from_analysis(analysis: &ArchiveAnalysis) -> Result<Self> {
        let canonical = serde_json::to_vec(analysis).context("serialize archive analysis")?;
        Ok(Self {
            analysis_sha256: sha256_bytes(&canonical),
            compressed_bytes: analysis.compressed_bytes,
            unpacked_bytes: analysis.unpacked_bytes,
            files: analysis.files.len(),
            build_surface: analysis.build_surface.clone(),
            vcs_commit: analysis.vcs.as_ref().map(|vcs| vcs.commit.clone()),
            vcs_path: analysis
                .vcs
                .as_ref()
                .and_then(|vcs| vcs.path_in_vcs.clone()),
        })
    }
}

/// Serializes one canonical update plan.
///
/// # Errors
///
/// Returns an error for invalid schema/policy constants, duplicate candidate identity, noncanonical nested ordering, malformed hashes, or TOML serialization failure.
pub fn serialize_update_plan(plan: &UpdatePlan) -> Result<Vec<u8>> {
    validate_update_plan(plan)?;
    let text = toml::to_string_pretty(plan).context("serialize canonical update plan")?;
    Ok(text.into_bytes())
}

/// Loads one regular canonical update-plan file.
///
/// # Errors
///
/// Returns an error for an unsafe path, malformed/unsupported plan, validation failure, or noncanonical bytes.
pub fn load_update_plan(path: &Path) -> Result<UpdatePlan> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect update plan {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "update plan is not a regular file: {}",
        path.display()
    );
    let bytes = fs::read(path).with_context(|| format!("read update plan {}", path.display()))?;
    let plan: UpdatePlan = toml::from_slice(&bytes)
        .with_context(|| format!("parse update plan {}", path.display()))?;
    let canonical = serialize_update_plan(&plan)?;
    ensure!(
        bytes == canonical,
        "update plan is not in canonical form: {}",
        path.display()
    );
    Ok(plan)
}

/// Calculates a stable hash of one complete candidate fact record.
///
/// # Errors
///
/// Returns an error if canonical JSON serialization fails.
pub fn candidate_facts_sha256(candidate: &UpdateCandidate) -> Result<String> {
    let canonical = serde_json::to_vec(candidate).context("serialize candidate facts")?;
    Ok(sha256_bytes(&canonical))
}

/// Calculates a location-independent hash of a complete catalog directory tree.
///
/// Entry type, relative UTF-8 path, byte length, and exact file contents are domain-separated and hashed in lexical order. Symlinks and special files fail closed.
///
/// # Errors
///
/// Returns an error for an unreadable tree, non-UTF-8 relative path, symlink/special entry, or hash framing overflow.
pub fn catalog_fingerprint(root: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect catalog root {}", root.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "catalog root is not a real directory: {}",
        root.display()
    );
    let mut hasher = Sha256::new();
    hasher.update(b"pkgre-catalog-fingerprint-v1\0");
    hash_directory(root, root, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn validate_update_plan(plan: &UpdatePlan) -> Result<()> {
    validate_update_plan_with(plan, true)
}

pub(crate) fn validate_historical_update_plan(plan: &UpdatePlan) -> Result<()> {
    validate_update_plan_with(plan, false)
}

fn validate_update_plan_with(plan: &UpdatePlan, require_current_indexer: bool) -> Result<()> {
    ensure!(
        plan.schema == UPDATE_PLAN_SCHEMA,
        "unsupported update-plan schema {}; expected {UPDATE_PLAN_SCHEMA}",
        plan.schema
    );
    let indexer_version = plan
        .indexer_version
        .parse::<Version>()
        .context("update plan indexer version is not SemVer")?;
    ensure!(
        plan.indexer_version == indexer_version.to_string(),
        "update plan indexer version is not canonical SemVer"
    );
    if require_current_indexer {
        ensure!(
            plan.indexer_version == env!("CARGO_PKG_VERSION"),
            "update plan indexer version {:?} differs from running version {:?}",
            plan.indexer_version,
            env!("CARGO_PKG_VERSION")
        );
    }
    if require_current_indexer {
        ensure!(
            plan.min_release_age_days == super::MIN_RELEASE_AGE_DAYS
                && plan.dormant_release_gap_days == super::DORMANT_RELEASE_GAP_DAYS,
            "update plan policy constants differ from this indexer"
        );
    } else {
        ensure!(
            plan.min_release_age_days > 0 && plan.dormant_release_gap_days > 0,
            "historical update plan contains a zero policy threshold"
        );
    }
    validate_hash(&plan.catalog_sha256, "catalog fingerprint")?;
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for candidate in &plan.candidates {
        let key = (
            candidate.registry.clone(),
            candidate.name.to_ascii_lowercase(),
            candidate.name.clone(),
            candidate.candidate.version.major,
            candidate.candidate.version.minor,
            candidate.candidate.version.patch,
            candidate.candidate.version.pre.to_string(),
        );
        ensure!(
            previous.as_ref().is_none_or(|value| value < &key),
            "update candidates are not in canonical unique identity order"
        );
        previous = Some(key);
        ensure!(
            identities.insert((
                candidate.registry.clone(),
                candidate.name.to_ascii_lowercase().replace('-', "_"),
                candidate.candidate.version.major,
                candidate.candidate.version.minor,
                candidate.candidate.version.patch,
                candidate.candidate.version.pre.to_string(),
            )),
            "update plan repeats Cargo package identity {} {}",
            candidate.name,
            candidate.candidate.version
        );
        validate_candidate(plan, candidate)?;
    }
    Ok(())
}

fn validate_candidate(plan: &UpdatePlan, candidate: &UpdateCandidate) -> Result<()> {
    validate_candidate_route(candidate)?;
    validate_candidate_release(plan, candidate)?;
    validate_hash(&candidate.sparse_index_sha256, "sparse index hash")?;
    validate_hash(&candidate.decision_history_sha256, "decision history hash")?;
    validate_candidate_archives(candidate)?;
    validate_dependency_delta(&candidate.dependencies)?;
    if let Some(gap) = &candidate.dormant_gap {
        validate_publication_gap(gap, candidate, plan.dormant_release_gap_days)?;
    }
    if let Some(api) = &candidate.api {
        validate_api_evidence(api, candidate.base.is_some())?;
    }
    validate_source_evidence(&candidate.source, candidate)?;
    ensure!(
        candidate
            .reasons
            .windows(2)
            .all(|window| window[0] < window[1]),
        "candidate reasons are not canonical and unique"
    );
    validate_reason_consistency(candidate)?;
    validate_decision(candidate)
}

fn validate_candidate_route(candidate: &UpdateCandidate) -> Result<()> {
    crate::policy::validate_package_name(&candidate.name)
        .context("invalid update candidate package name")?;
    let category = candidate
        .category
        .parse::<crate::category::CategoryId>()
        .context("invalid update candidate category")?;
    ensure!(
        category.registry() == candidate.registry,
        "candidate category {} does not belong to registry {:?}",
        candidate.category,
        candidate.registry
    );
    Ok(())
}

fn validate_candidate_release(plan: &UpdatePlan, candidate: &UpdateCandidate) -> Result<()> {
    validate_identity(&candidate.candidate)?;
    ensure!(
        candidate.age_seconds
            == plan
                .evaluated_at
                .duration_since(&candidate.candidate.published_at)
                .context("candidate publication is in the future")?,
        "candidate age does not match evaluation and publication times"
    );
    let release_age_floor = plan
        .min_release_age_days
        .checked_mul(24 * 60 * 60)
        .context("update-plan release-age threshold overflows seconds")?;
    ensure!(
        candidate.age_seconds >= release_age_floor,
        "candidate is younger than the recorded release-age floor"
    );
    if let Some(base) = &candidate.base {
        validate_identity(base)?;
        ensure!(
            base.version != candidate.candidate.version,
            "candidate repeats its review base identity"
        );
        ensure!(
            base.published_at <= candidate.candidate.published_at,
            "candidate was published before its review base"
        );
    }
    match candidate.activity {
        PackageActivity::New => ensure!(
            candidate.base.is_none(),
            "new package candidate unexpectedly has a locked base"
        ),
        PackageActivity::Inactive | PackageActivity::Active => ensure!(
            candidate.base.is_some(),
            "existing package candidate has no locked base"
        ),
    }
    validate_candidate_lane(candidate)
}

fn validate_candidate_lane(candidate: &UpdateCandidate) -> Result<()> {
    if let Some(lane) = &candidate.lane {
        ensure!(
            candidate.activity == PackageActivity::Active,
            "implicit update lane requires an active package"
        );
        ensure!(
            super::implicit_lane(&candidate.candidate.version).as_ref() == Some(lane),
            "candidate version does not belong to its implicit lane"
        );
        let base = candidate
            .base
            .as_ref()
            .expect("active implicit candidate has a base");
        ensure!(
            super::implicit_lane(&base.version).as_ref() == Some(lane),
            "candidate base does not belong to its implicit lane"
        );
        ensure!(
            candidate.candidate.version > base.version,
            "implicit candidate is not newer than its base"
        );
    }
    ensure!(
        candidate.lane.is_none()
            == candidate
                .reasons
                .contains(&DecisionReason::ExplicitCandidate),
        "explicit-candidate reason disagrees with compatibility lane"
    );
    Ok(())
}

fn validate_candidate_archives(candidate: &UpdateCandidate) -> Result<()> {
    validate_archive_summary(&candidate.candidate_archive)?;
    ensure!(
        candidate.base.is_some() == candidate.base_archive.is_some(),
        "base identity and base archive evidence disagree"
    );
    if let Some(summary) = &candidate.base_archive {
        validate_archive_summary(summary)?;
    }
    ensure!(
        candidate.base.is_some() == candidate.archive_delta.is_some(),
        "base identity and archive delta disagree"
    );
    if let Some(delta) = &candidate.archive_delta {
        validate_archive_delta(delta)?;
        ensure!(
            delta.build_surface_changed
                == (candidate
                    .base_archive
                    .as_ref()
                    .expect("archive delta requires a base archive")
                    .build_surface
                    != candidate.candidate_archive.build_surface),
            "archive delta build-surface flag is inconsistent"
        );
    }
    Ok(())
}

fn validate_archive_summary(summary: &ArchiveSummary) -> Result<()> {
    validate_hash(&summary.analysis_sha256, "archive analysis hash")?;
    ensure!(summary.compressed_bytes > 0, "archive is empty");
    ensure!(summary.unpacked_bytes > 0, "archive tar stream is empty");
    ensure!(summary.files > 0, "archive contains no regular files");
    for (surface, hash) in &summary.build_surface {
        ensure!(
            !surface.is_empty(),
            "archive build-surface identity is empty"
        );
        validate_hash(hash, "archive build-surface hash")?;
    }
    match (&summary.vcs_commit, &summary.vcs_path) {
        (None, Some(_)) => bail!("archive VCS path has no commit"),
        (Some(commit), _) => validate_git_commit(commit, "archive VCS commit")?,
        (None, None) => {}
    }
    if let Some(path) = &summary.vcs_path {
        validate_relative_path(path, "archive VCS path")?;
    }
    Ok(())
}

fn validate_archive_delta(delta: &ArchiveDelta) -> Result<()> {
    validate_hash(&delta.delta_sha256, "archive delta hash")?;
    for (description, paths) in [
        ("added", &delta.added),
        ("removed", &delta.removed),
        ("changed", &delta.changed),
    ] {
        ensure!(
            paths.windows(2).all(|window| window[0] < window[1]),
            "archive {description} paths are not canonical and unique"
        );
        for path in paths {
            validate_relative_path(path, "archive delta path")?;
        }
    }
    let added = delta.added.iter().collect::<BTreeSet<_>>();
    let removed = delta.removed.iter().collect::<BTreeSet<_>>();
    let changed = delta.changed.iter().collect::<BTreeSet<_>>();
    ensure!(
        added.is_disjoint(&removed) && added.is_disjoint(&changed) && removed.is_disjoint(&changed),
        "archive delta path classes overlap"
    );
    Ok(())
}

fn validate_dependency_delta(delta: &DependencyDelta) -> Result<()> {
    ensure!(
        delta.added.windows(2).all(|window| window[0] < window[1]),
        "added dependencies are not canonical and unique"
    );
    ensure!(
        delta.removed.windows(2).all(|window| window[0] < window[1]),
        "removed dependencies are not canonical and unique"
    );
    ensure!(
        delta
            .new_packages
            .windows(2)
            .all(|window| package_order(&window[0]) < package_order(&window[1])),
        "new dependency packages are not canonical and unique"
    );
    for dependency in delta.added.iter().chain(&delta.removed) {
        crate::policy::validate_package_name(&dependency.package)
            .context("invalid dependency package identity")?;
        ensure!(!dependency.name.is_empty(), "dependency alias is empty");
    }
    let added_packages = delta
        .added
        .iter()
        .map(|dependency| package_identity(&dependency.package))
        .collect::<BTreeSet<_>>();
    for package in &delta.new_packages {
        crate::policy::validate_package_name(package)
            .context("invalid new dependency package identity")?;
        ensure!(
            added_packages.contains(&package_identity(package)),
            "new dependency package {package:?} has no added edge"
        );
    }
    Ok(())
}

fn validate_publication_gap(
    gap: &PublicationGap,
    candidate: &UpdateCandidate,
    dormant_release_gap_days: u64,
) -> Result<()> {
    ensure!(
        gap.before_published_at < gap.after_published_at,
        "dormant publication gap is not chronological"
    );
    ensure!(
        gap.seconds
            == gap
                .after_published_at
                .duration_since(&gap.before_published_at)?,
        "dormant publication gap seconds are inconsistent"
    );
    let dormant_gap_floor = dormant_release_gap_days
        .checked_mul(24 * 60 * 60)
        .context("update-plan dormant-gap threshold overflows seconds")?;
    ensure!(
        gap.seconds >= dormant_gap_floor,
        "dormant publication gap is below the recorded policy threshold"
    );
    ensure!(
        gap.after_published_at <= candidate.candidate.published_at,
        "dormant publication gap follows the candidate"
    );
    Ok(())
}

fn validate_api_evidence(api: &ApiEvidence, has_base: bool) -> Result<()> {
    validate_hash(&api.response_sha256, "crates.io API response hash")?;
    ensure!(
        api.base.is_some() == has_base,
        "crates.io API base evidence disagrees with the candidate base"
    );
    if let Some(base) = &api.base {
        validate_api_version(base)?;
    }
    validate_api_version(&api.candidate)
}

fn validate_api_version(version: &ApiVersionEvidence) -> Result<()> {
    if let Some(login) = &version.publisher_login {
        ensure!(
            !login.trim().is_empty() && login == login.trim(),
            "crates.io publisher login is not canonical"
        );
    }
    if let Some(repository) = &version.repository {
        ensure!(
            !repository.trim().is_empty() && repository == repository.trim(),
            "crates.io repository is not canonical"
        );
    }
    if let Some(trusted) = &version.trusted_publishing {
        ensure!(
            matches!(trusted.provider.as_str(), "github" | "gitlab"),
            "unsupported Trusted Publishing provider {:?}",
            trusted.provider
        );
        ensure!(
            !trusted.repository.is_empty(),
            "Trusted Publishing repository is empty"
        );
        validate_git_commit(&trusted.commit, "Trusted Publishing commit")?;
        validate_hash(&trusted.evidence_sha256, "Trusted Publishing evidence hash")?;
    }
    Ok(())
}

fn validate_source_evidence(source: &SourceEvidence, candidate: &UpdateCandidate) -> Result<()> {
    match source {
        SourceEvidence::Unavailable { reason } => ensure!(
            !reason.trim().is_empty() && reason == reason.trim(),
            "source-unavailable reason is not canonical"
        ),
        SourceEvidence::PublisherAsserted {
            repository,
            commit,
            path,
            comparison_sha256,
        } => {
            ensure!(!repository.is_empty(), "source repository is empty");
            validate_git_commit(commit, "source commit")?;
            validate_relative_path(path, "source repository path")?;
            validate_hash(comparison_sha256, "source comparison hash")?;
            ensure!(
                candidate.candidate_archive.vcs_commit.as_ref() == Some(commit),
                "publisher-asserted source commit disagrees with the archive claim"
            );
            ensure!(
                candidate
                    .candidate_archive
                    .vcs_path
                    .as_deref()
                    .unwrap_or("")
                    == path,
                "publisher-asserted source path disagrees with the archive claim"
            );
        }
        SourceEvidence::RegistryContextAttested {
            repository,
            commit,
            path,
            comparison_sha256,
            attestation_sha256,
        } => {
            ensure!(!repository.is_empty(), "source repository is empty");
            validate_git_commit(commit, "source commit")?;
            validate_relative_path(path, "source repository path")?;
            validate_hash(comparison_sha256, "source comparison hash")?;
            validate_hash(attestation_sha256, "source attestation hash")?;
            if let Some(archive_commit) = candidate.candidate_archive.vcs_commit.as_ref() {
                ensure!(
                    archive_commit == commit,
                    "attested source commit disagrees with the archive claim"
                );
                ensure!(
                    candidate
                        .candidate_archive
                        .vcs_path
                        .as_deref()
                        .unwrap_or("")
                        == path,
                    "attested source path disagrees with the archive claim"
                );
            } else {
                ensure!(
                    path.is_empty(),
                    "attested source without an archive VCS claim has a non-root path"
                );
            }
            let trusted = candidate
                .api
                .as_ref()
                .and_then(|api| api.candidate.trusted_publishing.as_ref())
                .context("attested source evidence has no Trusted Publishing context")?;
            ensure!(
                trusted.repository == *repository
                    && trusted.commit == *commit
                    && trusted.evidence_sha256 == *attestation_sha256,
                "source evidence disagrees with Trusted Publishing context"
            );
        }
        SourceEvidence::Mismatch { comparison_sha256 } => {
            validate_hash(comparison_sha256, "source mismatch hash")?;
        }
    }
    Ok(())
}

fn validate_reason_consistency(candidate: &UpdateCandidate) -> Result<()> {
    ensure!(
        candidate.reasons.contains(&DecisionReason::NewPackage)
            == (candidate.activity == PackageActivity::New),
        "new-package reason disagrees with package activity"
    );
    ensure!(
        candidate.reasons.contains(&DecisionReason::InactiveRevival)
            == (candidate.activity == PackageActivity::Inactive),
        "inactive-revival reason disagrees with package activity"
    );
    ensure!(
        candidate.reasons.contains(&DecisionReason::DormantWakeup)
            == candidate.dormant_gap.is_some(),
        "dormant-wakeup reason disagrees with publication evidence"
    );
    ensure!(
        candidate.reasons.contains(&DecisionReason::NewDependency)
            != candidate.dependencies.new_packages.is_empty(),
        "new-dependency reason disagrees with dependency evidence"
    );
    let build_surface_changed = candidate.archive_delta.as_ref().map_or_else(
        || !candidate.candidate_archive.build_surface.is_empty(),
        |delta| delta.build_surface_changed,
    );
    ensure!(
        candidate
            .reasons
            .contains(&DecisionReason::BuildSurfaceChanged)
            == build_surface_changed,
        "build-surface reason disagrees with archive evidence"
    );

    let (publisher_discontinuity, repository_discontinuity) = if candidate.base.is_none() {
        (false, false)
    } else if let Some(api) = &candidate.api {
        let base = api
            .base
            .as_ref()
            .expect("API evidence for an existing candidate has a base");
        (
            base.publisher_id.is_none()
                || api.candidate.publisher_id.is_none()
                || base.publisher_id != api.candidate.publisher_id,
            base.repository.is_none()
                || api.candidate.repository.is_none()
                || base.repository != api.candidate.repository,
        )
    } else {
        (true, true)
    };
    ensure!(
        candidate
            .reasons
            .contains(&DecisionReason::PublisherDiscontinuity)
            == publisher_discontinuity,
        "publisher-discontinuity reason disagrees with API evidence"
    );
    ensure!(
        candidate
            .reasons
            .contains(&DecisionReason::RepositoryDiscontinuity)
            == repository_discontinuity,
        "repository-discontinuity reason disagrees with API evidence"
    );

    let promoted = candidate.reasons.iter().any(|reason| {
        matches!(
            reason,
            DecisionReason::NewPackage
                | DecisionReason::InactiveRevival
                | DecisionReason::DormantWakeup
                | DecisionReason::NewDependency
                | DecisionReason::BuildSurfaceChanged
                | DecisionReason::PublisherDiscontinuity
                | DecisionReason::RepositoryDiscontinuity
        )
    });
    ensure!(
        candidate
            .reasons
            .contains(&DecisionReason::SourceUnavailable)
            == (promoted && matches!(candidate.source, SourceEvidence::Unavailable { .. })),
        "source-unavailable reason disagrees with promoted source evidence"
    );
    ensure!(
        candidate.reasons.contains(&DecisionReason::SourceMismatch)
            == matches!(candidate.source, SourceEvidence::Mismatch { .. }),
        "source-mismatch reason disagrees with source evidence"
    );
    Ok(())
}

fn validate_decision(candidate: &UpdateCandidate) -> Result<()> {
    let blocked = candidate.reasons.iter().any(|reason| {
        matches!(
            reason,
            DecisionReason::UnknownDependencyHome
                | DecisionReason::ForbiddenCategoryDependency
                | DecisionReason::SourceMismatch
        )
    });
    let review = candidate.reasons.iter().any(|reason| {
        matches!(
            reason,
            DecisionReason::NewPackage
                | DecisionReason::InactiveRevival
                | DecisionReason::DormantWakeup
                | DecisionReason::NewDependency
                | DecisionReason::BuildSurfaceChanged
                | DecisionReason::PublisherDiscontinuity
                | DecisionReason::RepositoryDiscontinuity
                | DecisionReason::SourceUnavailable
        )
    });
    let expected = if blocked {
        UpdateDecision::Blocked
    } else if review {
        UpdateDecision::ReviewRequired
    } else {
        UpdateDecision::Automatic
    };
    ensure!(
        candidate.decision == expected,
        "candidate decision disagrees with its reasons"
    );
    Ok(())
}

fn validate_identity(identity: &PlannedIdentity) -> Result<()> {
    validate_hash(&identity.source_row_sha256, "source row hash")?;
    validate_hash(&identity.crate_sha256, "crate hash")
}

fn validate_git_commit(value: &str, description: &str) -> Result<()> {
    ensure!(
        matches!(value.len(), 40 | 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{description} is not a canonical Git object ID"
    );
    Ok(())
}

fn validate_relative_path(value: &str, description: &str) -> Result<()> {
    ensure!(!value.starts_with('/'), "{description} is absolute");
    ensure!(!value.contains('\\'), "{description} contains a backslash");
    if value.is_empty() {
        return Ok(());
    }
    ensure!(
        value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != ".."),
        "{description} is noncanonical or contains traversal"
    );
    Ok(())
}

fn package_order(value: &str) -> (String, &str) {
    (value.to_ascii_lowercase(), value)
}

fn package_identity(value: &str) -> String {
    value.to_ascii_lowercase().replace('-', "_")
}

fn validate_hash(value: &str, description: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{description} is not canonical lowercase SHA-256"
    );
    Ok(())
}

fn hash_directory(root: &Path, directory: &Path, hasher: &mut Sha256) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read catalog directory {}", directory.display()))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<io::Result<Vec<_>>>()
        .with_context(|| format!("read entries below {}", directory.display()))?;
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect catalog entry {}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .expect("catalog entry is below fingerprint root");
        let relative = relative
            .to_str()
            .with_context(|| format!("catalog path is not valid UTF-8: {}", relative.display()))?;
        if metadata.file_type().is_dir() {
            hash_frame(hasher, b'D', relative.as_bytes(), &[])?;
            hash_directory(root, &path, hasher)?;
        } else if metadata.file_type().is_file() {
            let bytes =
                fs::read(&path).with_context(|| format!("read catalog file {}", path.display()))?;
            hash_frame(hasher, b'F', relative.as_bytes(), &bytes)?;
        } else {
            bail!(
                "catalog fingerprint rejects special path {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn hash_frame(hasher: &mut Sha256, kind: u8, path: &[u8], contents: &[u8]) -> Result<()> {
    let path_len = u64::try_from(path.len()).context("catalog path length exceeds u64")?;
    let content_len = u64::try_from(contents.len()).context("catalog file length exceeds u64")?;
    hasher.update([kind]);
    hasher.update(path_len.to_be_bytes());
    hasher.update(path);
    hasher.update(content_len.to_be_bytes());
    hasher.update(contents);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::update::{DORMANT_RELEASE_GAP_DAYS, MIN_RELEASE_AGE_DAYS};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn catalog_fingerprint_is_location_independent_and_binds_paths_and_bytes() {
        let one = temporary_directory("fingerprint-one");
        let two = temporary_directory("fingerprint-two");
        for root in [&one, &two] {
            fs::create_dir(root.join("nested")).unwrap();
            fs::write(root.join("a.toml"), b"alpha\n").unwrap();
            fs::write(root.join("nested/value"), b"beta\n").unwrap();
        }
        assert_eq!(
            catalog_fingerprint(&one).unwrap(),
            catalog_fingerprint(&two).unwrap()
        );
        fs::write(two.join("nested/value"), b"changed\n").unwrap();
        assert_ne!(
            catalog_fingerprint(&one).unwrap(),
            catalog_fingerprint(&two).unwrap()
        );
        fs::remove_dir_all(one).unwrap();
        fs::remove_dir_all(two).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn catalog_fingerprint_rejects_symlinks() {
        let root = temporary_directory("fingerprint-symlink");
        fs::write(root.join("target"), b"value").unwrap();
        std::os::unix::fs::symlink("target", root.join("link")).unwrap();
        assert!(catalog_fingerprint(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn historical_plan_validation_uses_recorded_positive_policy_thresholds() {
        let mut plan = sample_plan();
        plan.min_release_age_days = 1;
        plan.dormant_release_gap_days = 2;

        assert!(validate_update_plan(&plan).is_err());
        validate_historical_update_plan(&plan).unwrap();

        plan.min_release_age_days = 0;
        assert!(validate_historical_update_plan(&plan).is_err());
    }

    #[test]
    fn candidate_facts_hash_binds_the_complete_approval_free_record() {
        let mut plan = sample_plan();
        let hash = candidate_facts_sha256(&plan.candidates[0]).unwrap();
        let text = String::from_utf8(serialize_update_plan(&plan).unwrap()).unwrap();
        assert!(!text.contains("approval"));
        assert!(!text.contains("binding-sha256"));
        plan.candidates[0].candidate.crate_sha256 = "22".repeat(32);
        assert_ne!(hash, candidate_facts_sha256(&plan.candidates[0]).unwrap());
    }

    #[test]
    fn attested_source_can_anchor_root_archive_without_embedded_vcs_claim() {
        let mut plan = sample_plan();
        let candidate = &mut plan.candidates[0];
        let trusted = TrustedPublishingEvidence {
            provider: "github".to_owned(),
            repository: "https://github.com/example/demo".to_owned(),
            commit: "11".repeat(20),
            evidence_sha256: "12".repeat(32),
        };
        candidate.api = Some(ApiEvidence {
            response_sha256: "13".repeat(32),
            base: None,
            candidate: ApiVersionEvidence {
                publisher_id: Some(1),
                publisher_login: Some("publisher".to_owned()),
                repository: Some(trusted.repository.clone()),
                trusted_publishing: Some(trusted.clone()),
            },
        });
        candidate.source = SourceEvidence::RegistryContextAttested {
            repository: trusted.repository,
            commit: trusted.commit,
            path: String::new(),
            comparison_sha256: "14".repeat(32),
            attestation_sha256: trusted.evidence_sha256,
        };
        candidate
            .reasons
            .retain(|reason| *reason != DecisionReason::SourceUnavailable);

        serialize_update_plan(&plan).unwrap();

        let SourceEvidence::RegistryContextAttested { path, .. } = &mut plan.candidates[0].source
        else {
            unreachable!();
        };
        *path = "nested".to_owned();
        assert!(serialize_update_plan(&plan).is_err());
    }

    #[test]
    fn candidate_cargo_identity_is_scoped_by_registry() {
        let mut plan = sample_plan();
        plan.candidates[0].registry = "main".to_owned();
        plan.candidates[0].category = "main/general".to_owned();
        plan.candidates[0].name = "shared-name".to_owned();
        let mut staging = plan.candidates[0].clone();
        staging.registry = "staging".to_owned();
        staging.category = "staging/general".to_owned();
        staging.name = "shared_name".to_owned();
        plan.candidates.push(staging);
        plan.candidates.sort_by(|left, right| {
            (
                left.registry.as_str(),
                left.name.to_ascii_lowercase(),
                left.name.as_str(),
                &left.candidate.version,
            )
                .cmp(&(
                    right.registry.as_str(),
                    right.name.to_ascii_lowercase(),
                    right.name.as_str(),
                    &right.candidate.version,
                ))
        });
        serialize_update_plan(&plan).unwrap();

        plan.candidates[1].registry = "main".to_owned();
        plan.candidates[1].category = "main/general".to_owned();
        plan.candidates.sort_by(|left, right| {
            (
                left.registry.as_str(),
                left.name.to_ascii_lowercase(),
                left.name.as_str(),
                &left.candidate.version,
            )
                .cmp(&(
                    right.registry.as_str(),
                    right.name.to_ascii_lowercase(),
                    right.name.as_str(),
                    &right.candidate.version,
                ))
        });
        let error = serialize_update_plan(&plan).unwrap_err();
        assert!(format!("{error:#}").contains("repeats Cargo package identity"));
    }

    fn sample_plan() -> UpdatePlan {
        let identity = PlannedIdentity {
            version: Version::parse("1.0.1").unwrap(),
            published_at: UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            source_row_sha256: "01".repeat(32),
            crate_sha256: "02".repeat(32),
        };
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "03".repeat(32),
            evaluated_at: UtcTimestamp::parse("2026-08-23T19:00:00Z").unwrap(),
            min_release_age_days: MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: DORMANT_RELEASE_GAP_DAYS,
            candidates: vec![UpdateCandidate {
                registry: "universe".to_owned(),
                category: "universe/general".to_owned(),
                name: "demo".to_owned(),
                activity: PackageActivity::New,
                lane: None,
                base: None,
                candidate: identity,
                sparse_index_sha256: "04".repeat(32),
                decision_history_sha256: "05".repeat(32),
                age_seconds: UtcTimestamp::parse("2026-08-23T19:00:00Z")
                    .unwrap()
                    .duration_since(&UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap())
                    .unwrap(),
                dormant_gap: None,
                base_archive: None,
                candidate_archive: ArchiveSummary {
                    analysis_sha256: "06".repeat(32),
                    compressed_bytes: 10,
                    unpacked_bytes: 20,
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
                    reason: "not-promoted".to_owned(),
                },
                decision: UpdateDecision::ReviewRequired,
                reasons: vec![
                    DecisionReason::NewPackage,
                    DecisionReason::SourceUnavailable,
                    DecisionReason::ExplicitCandidate,
                ],
            }],
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pkgre-plan-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }
}

/// Calculates a complete deterministic file/build-surface delta between two inert archive analyses.
///
/// `delta_sha256` binds the full before/after metadata for every added, removed, or changed file, not only the public path summary.
///
/// # Errors
///
/// Returns an error if either analysis repeats a path or canonical JSON serialization fails.
pub fn compare_archive_analyses(
    base: &ArchiveAnalysis,
    candidate: &ArchiveAnalysis,
) -> Result<ArchiveDelta> {
    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct ChangedFile<'a> {
        before: &'a super::ArchiveFile,
        after: &'a super::ArchiveFile,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct CompleteDelta<'a> {
        added: Vec<&'a super::ArchiveFile>,
        removed: Vec<&'a super::ArchiveFile>,
        changed: Vec<ChangedFile<'a>>,
        build_surface_before: &'a BTreeMap<String, String>,
        build_surface_after: &'a BTreeMap<String, String>,
    }

    let base_files = archive_files_by_path(base, "base")?;
    let candidate_files = archive_files_by_path(candidate, "candidate")?;
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (path, file) in &candidate_files {
        match base_files.get(path) {
            None => added.push(*file),
            Some(previous) if *previous != *file => changed.push(ChangedFile {
                before: previous,
                after: file,
            }),
            Some(_) => {}
        }
    }
    for (path, file) in &base_files {
        if !candidate_files.contains_key(path) {
            removed.push(*file);
        }
    }
    let added_paths = added.iter().map(|file| file.path.clone()).collect();
    let removed_paths = removed.iter().map(|file| file.path.clone()).collect();
    let changed_paths = changed.iter().map(|file| file.after.path.clone()).collect();
    let complete = CompleteDelta {
        added,
        removed,
        changed,
        build_surface_before: &base.build_surface,
        build_surface_after: &candidate.build_surface,
    };
    let canonical = serde_json::to_vec(&complete).context("serialize complete archive delta")?;
    Ok(ArchiveDelta {
        delta_sha256: sha256_bytes(&canonical),
        added: added_paths,
        removed: removed_paths,
        changed: changed_paths,
        build_surface_changed: base.build_surface != candidate.build_surface,
    })
}

fn archive_files_by_path<'a>(
    analysis: &'a ArchiveAnalysis,
    description: &str,
) -> Result<BTreeMap<&'a str, &'a super::ArchiveFile>> {
    let mut files = BTreeMap::new();
    for file in &analysis.files {
        ensure!(
            files.insert(file.path.as_str(), file).is_none(),
            "{description} archive analysis repeats path {:?}",
            file.path
        );
    }
    Ok(files)
}

#[cfg(test)]
mod archive_delta_tests {
    use super::*;
    use crate::update::ArchiveFile;

    fn file(path: &str, mode: u32, hash_byte: &str) -> ArchiveFile {
        ArchiveFile {
            path: path.to_owned(),
            size: 1,
            mode,
            sha256: hash_byte.repeat(32),
            binary: false,
        }
    }

    fn analysis(
        files: Vec<ArchiveFile>,
        build_surface: BTreeMap<String, String>,
    ) -> ArchiveAnalysis {
        ArchiveAnalysis {
            compressed_bytes: 1,
            unpacked_bytes: 1,
            files,
            build_surface,
            vcs: None,
        }
    }

    #[test]
    fn complete_archive_delta_is_canonical_and_binds_modes_and_surface() {
        let base = analysis(
            vec![file("changed", 0o644, "01"), file("removed", 0o644, "02")],
            BTreeMap::new(),
        );
        let candidate = analysis(
            vec![file("added", 0o644, "03"), file("changed", 0o755, "01")],
            BTreeMap::from([("manifest:Cargo.toml:build".to_owned(), "04".repeat(32))]),
        );
        let delta = compare_archive_analyses(&base, &candidate).unwrap();
        assert_eq!(delta.added, ["added"]);
        assert_eq!(delta.removed, ["removed"]);
        assert_eq!(delta.changed, ["changed"]);
        assert!(delta.build_surface_changed);

        let mut byte_changed = candidate.clone();
        byte_changed.files[1].sha256 = "05".repeat(32);
        assert_ne!(
            delta.delta_sha256,
            compare_archive_analyses(&base, &byte_changed)
                .unwrap()
                .delta_sha256
        );
    }

    #[test]
    fn duplicate_analysis_paths_fail_closed() {
        let repeated = analysis(
            vec![file("same", 0o644, "01"), file("same", 0o644, "01")],
            BTreeMap::new(),
        );
        assert!(compare_archive_analyses(&repeated, &repeated).is_err());
    }
}
