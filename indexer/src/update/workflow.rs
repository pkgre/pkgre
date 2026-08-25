//! Read-only crates.io update planning and policy-evidence integration.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::import::{self, CratesIoHistory, SparseIndexRow};
use crate::index::IndexDependency;
use crate::policy::{Policy, validate_catalog};
use crate::schema::{Catalog, PackageKey, PackageState, Source, version_identity};

use super::{
    ApiEvidence, ArchiveAnalysis, ArchiveSummary, CompatibilityLane, DecisionReason,
    DependencyDelta, LockedRelease, MIN_RELEASE_AGE_DAYS, PackageActivity, PlannedIdentity,
    PolicyRelease, PublicationGap, SourceEvidence, UPDATE_PLAN_SCHEMA, UpdateCandidate,
    UpdateDecision, UpdatePlan, UtcTimestamp, catalog_fingerprint, classify_package,
    compare_archive_analyses, inspect_crate_archive, parse_crates_io_api_evidence,
    select_exact_candidate, select_implicit_candidates, verify_source_correspondence,
};

/// Creates a canonical read-only plan for every eligible implicit compatibility-lane update.
///
/// The catalog is fingerprinted before and after all network work. The output is created only after
/// the complete catalog, retained source rows, upstream rows, archives, dependencies, and policy
/// evidence have been validated.
///
/// # Errors
///
/// Returns an error for catalog drift, invalid retained/upstream evidence, unsafe archives, policy
/// calculation failures, or an existing output path.
pub fn plan_updates(root: &Path, output: &Path) -> Result<UpdatePlan> {
    plan_updates_with(root, output, &LivePlannerResolver, UtcTimestamp::now()?)
}

pub(crate) fn plan_updates_with<R: PlannerResolver>(
    root: &Path,
    output: &Path,
    resolver: &R,
    evaluated_at: UtcTimestamp,
) -> Result<UpdatePlan> {
    plan_with(root, output, resolver, evaluated_at, &PlanRequest::Implicit)
}

/// Creates a canonical read-only plan for one exact age-eligible crates.io identity.
///
/// Exact requests support prereleases and stable `0.0.x` versions, while retaining every routine
/// update guardrail and adding an explicit-candidate evidence marker.
///
/// # Errors
///
/// Returns an error for an unknown/non-mirror package, missing/yanked/young/already-locked version,
/// catalog drift, invalid evidence, unsafe archive, or existing output path.
pub fn plan_exact_update(
    root: &Path,
    name: &str,
    version: &Version,
    output: &Path,
) -> Result<UpdatePlan> {
    plan_exact_update_with(
        root,
        name,
        version,
        output,
        &LivePlannerResolver,
        UtcTimestamp::now()?,
    )
}

pub(crate) fn plan_exact_update_with<R: PlannerResolver>(
    root: &Path,
    name: &str,
    version: &Version,
    output: &Path,
    resolver: &R,
    evaluated_at: UtcTimestamp,
) -> Result<UpdatePlan> {
    crate::policy::validate_package_name(name).context("invalid exact update package name")?;
    plan_with(
        root,
        output,
        resolver,
        evaluated_at,
        &PlanRequest::Exact {
            name: name.to_owned(),
            version: version.clone(),
        },
    )
}

pub(crate) trait PlannerResolver {
    fn history(&self, name: &str) -> Result<CratesIoHistory>;

    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>>;

    fn api(&self, name: &str) -> Result<Vec<u8>>;

    fn source(
        &self,
        archive: &ArchiveAnalysis,
        api: Option<&super::ApiVersionEvidence>,
    ) -> Result<SourceEvidence>;
}

pub(crate) struct LivePlannerResolver;

impl PlannerResolver for LivePlannerResolver {
    fn history(&self, name: &str) -> Result<CratesIoHistory> {
        import::fetch_crates_io_history(name)
    }

    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
        import::fetch_crates_io_archive(name, version, checksum)
    }

    fn api(&self, name: &str) -> Result<Vec<u8>> {
        let evidence = import::fetch_crates_io_api(name)?;
        ensure!(
            sha256_bytes(&evidence.bytes) == evidence.sha256,
            "crates.io API resolver returned inconsistent response hash for {name}"
        );
        Ok(evidence.bytes)
    }

    fn source(
        &self,
        archive: &ArchiveAnalysis,
        api: Option<&super::ApiVersionEvidence>,
    ) -> Result<SourceEvidence> {
        verify_source_correspondence(archive, api)
    }
}

#[derive(Clone, Debug)]
enum PlanRequest {
    Implicit,
    Exact { name: String, version: Version },
    Revalidate(Vec<RevalidationTarget>),
}

#[derive(Clone, Debug)]
struct RevalidationTarget {
    registry: String,
    name: String,
    version: Version,
    lane: Option<CompatibilityLane>,
}

#[derive(Clone, Debug)]
struct CandidateSelection {
    activity: PackageActivity,
    lane: Option<CompatibilityLane>,
    base: Option<LockedRelease>,
    candidate: PolicyRelease,
    age_seconds: u64,
    dormant_gap: Option<PublicationGap>,
    explicit: bool,
}

fn plan_with<R: PlannerResolver>(
    root: &Path,
    output: &Path,
    resolver: &R,
    evaluated_at: UtcTimestamp,
    request: &PlanRequest,
) -> Result<UpdatePlan> {
    validate_manifest_output(root, output)?;
    let plan = build_plan_with(root, resolver, evaluated_at, request)?;
    let manifest = super::manifest::manifest_from_candidates(&plan.candidates);
    ensure!(
        catalog_fingerprint(root)? == plan.catalog_sha256,
        "catalog changed before the admission template could be emitted"
    );
    super::manifest::write_admission_manifest(output, &manifest)?;
    Ok(plan)
}

/// Recomputes complete current machine facts for every exact request in a human manifest.
pub(crate) fn recompute_admission_plan_with<R: PlannerResolver>(
    root: &Path,
    manifest: &super::AdmissionManifest,
    resolver: &R,
    evaluated_at: UtcTimestamp,
) -> Result<UpdatePlan> {
    super::serialize_admission_manifest(manifest).context("validate admission manifest")?;
    let mut requests = BTreeMap::new();
    let mut targets = Vec::with_capacity(manifest.entries.len());
    for request in &manifest.entries {
        let version = match (&request.version, &request.tag) {
            (Some(version), None) => version.clone(),
            (None, Some(tag)) => anyhow::bail!(
                "Git-tag admission for {} tag {tag:?} is not supported by the mirror updater",
                request.name
            ),
            _ => unreachable!("validated admission request has exactly one target"),
        };
        let key = (
            request.category.registry().to_owned(),
            request.name.to_ascii_lowercase().replace('-', "_"),
            version_identity(&version),
        );
        ensure!(
            requests.insert(key, request).is_none(),
            "admission manifest repeats Cargo identity {} {version}",
            request.name
        );
        targets.push(RevalidationTarget {
            registry: request.category.registry().to_owned(),
            name: request.name.clone(),
            lane: super::implicit_lane(&version),
            version,
        });
    }
    let plan = build_plan_with(
        root,
        resolver,
        evaluated_at,
        &PlanRequest::Revalidate(targets),
    )?;
    ensure!(
        plan.candidates.len() == manifest.entries.len(),
        "recomputed candidate inventory differs from admission requests"
    );
    for candidate in &plan.candidates {
        let key = (
            candidate.registry.clone(),
            candidate.name.to_ascii_lowercase().replace('-', "_"),
            version_identity(&candidate.candidate.version),
        );
        let request = requests.get(&key).with_context(|| {
            format!(
                "recomputed candidate {} {} was not requested",
                candidate.name, candidate.candidate.version
            )
        })?;
        ensure!(
            request.name == candidate.name && request.category.to_string() == candidate.category,
            "admission route differs from permanent home for {} {}",
            candidate.name,
            candidate.candidate.version
        );
    }
    Ok(plan)
}

fn validate_manifest_output(root: &Path, output: &Path) -> Result<()> {
    super::manifest::validate_admission_filename(output, "toml")?;
    let catalog = fs::canonicalize(root)
        .with_context(|| format!("resolve catalog root {}", root.display()))?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .with_context(|| format!("resolve admission-template parent {}", parent.display()))?;
    ensure!(
        !parent.starts_with(&catalog),
        "admission template must be created outside the managed catalog"
    );
    Ok(())
}

fn build_plan_with<R: PlannerResolver>(
    root: &Path,
    resolver: &R,
    evaluated_at: UtcTimestamp,
    request: &PlanRequest,
) -> Result<UpdatePlan> {
    let initial_fingerprint = catalog_fingerprint(root)?;
    let catalog = Catalog::load(root).context("strictly load catalog for update planning")?;
    let policy = validate_catalog(&catalog).context("validate catalog update policy")?;
    let artifacts = ArtifactMap::load(&catalog).context("verify catalog objects for planning")?;
    ensure!(
        catalog_fingerprint(root)? == initial_fingerprint,
        "catalog changed while update planning initialized"
    );

    let targets = planning_targets(&catalog, request)?;
    let mut candidates = Vec::new();
    for (key, home) in targets {
        let history = resolver.history(&key.name).with_context(|| {
            format!(
                "fetch complete crates.io history for {}/{}",
                key.registry, key.name
            )
        })?;
        let policy_history = policy_history(&history)?;
        let locked = locked_releases(&catalog, &artifacts, &history, &key.registry, &key.name)?;
        let activity = classify_package(&locked);
        let selections = select_candidates(
            request,
            &key.registry,
            &key.name,
            &evaluated_at,
            &policy_history,
            &locked,
            activity,
        )?;
        for selection in selections {
            candidates.push(build_candidate(
                resolver,
                &catalog,
                &policy,
                &history,
                &key.name,
                &key.registry,
                &home.category.to_string(),
                selection,
            )?);
        }
    }
    candidates.sort_by_key(candidate_order);

    let plan = UpdatePlan {
        schema: UPDATE_PLAN_SCHEMA,
        indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
        catalog_sha256: initial_fingerprint.clone(),
        evaluated_at,
        min_release_age_days: MIN_RELEASE_AGE_DAYS,
        dormant_release_gap_days: super::DORMANT_RELEASE_GAP_DAYS,
        candidates,
    };
    ensure!(
        catalog_fingerprint(root)? == initial_fingerprint,
        "catalog changed during update planning; refusing to retain stale evidence"
    );
    Ok(plan)
}

fn planning_targets(
    catalog: &Catalog,
    request: &PlanRequest,
) -> Result<Vec<(PackageKey, crate::schema::PackageHome)>> {
    let mut targets = catalog
        .homes
        .homes
        .iter()
        .filter(|(key, _)| catalog.mirror_names.contains(*key))
        .filter(|(key, _)| match request {
            PlanRequest::Implicit => catalog.approvals.iter().any(|approval| {
                approval.registry == key.registry
                    && approval.name == key.name
                    && approval.state == PackageState::Active
                    && matches!(&approval.source, Source::CratesIo)
                    && super::implicit_lane(&approval.version).is_some()
            }),
            PlanRequest::Exact { name, .. } => key.name == *name,
            PlanRequest::Revalidate(requested) => requested
                .iter()
                .any(|target| target.registry == key.registry && target.name == key.name),
        })
        .map(|(key, home)| (key.clone(), home.clone()))
        .collect::<Vec<_>>();

    match request {
        PlanRequest::Implicit => {}
        PlanRequest::Exact { name, .. } => ensure!(
            targets.len() == 1,
            if targets.is_empty() {
                format!(
                    "requested update package {name:?} is not a permanently reserved crates.io mirror name"
                )
            } else {
                format!(
                    "requested update package {name:?} exists in multiple registries; use an admission manifest with a category-qualified target"
                )
            }
        ),
        PlanRequest::Revalidate(requested) => {
            let expected = requested
                .iter()
                .map(|target| (target.registry.as_str(), target.name.as_str()))
                .collect::<BTreeSet<_>>();
            let observed = targets
                .iter()
                .map(|(key, _)| (key.registry.as_str(), key.name.as_str()))
                .collect::<BTreeSet<_>>();
            ensure!(
                observed == expected,
                "requested update packages are not all permanently reserved registry-qualified crates.io mirror names"
            );
        }
    }
    targets.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(targets)
}

fn policy_history(history: &CratesIoHistory) -> Result<Vec<PolicyRelease>> {
    history
        .rows
        .iter()
        .map(|row| {
            Ok(PolicyRelease {
                version: row.record.version()?,
                published_at: UtcTimestamp::parse(row.record.pubtime()?)
                    .context("parse crates.io sparse-row pubtime")?,
                yanked: row.record.yanked()?,
            })
        })
        .collect()
}

fn locked_releases(
    catalog: &Catalog,
    artifacts: &ArtifactMap,
    history: &CratesIoHistory,
    registry: &str,
    name: &str,
) -> Result<Vec<LockedRelease>> {
    let mut locked = Vec::new();
    for approval in catalog
        .approvals
        .iter()
        .filter(|approval| approval.registry == registry && approval.name == name)
    {
        ensure!(
            matches!(approval.source, Source::CratesIo),
            "mirror name {name:?} has non-crates.io locked history"
        );
        let artifact = artifacts
            .get(&approval.registry, name, &approval.version)
            .context("verified artifact map omitted a locked source row")?;
        let retained_bytes = fs::read(&artifact.index_record)
            .with_context(|| format!("read retained sparse row for {name} {}", approval.version))?;
        let retained = crate::index::IndexRecord::parse(&retained_bytes)?;
        retained.validate_structure()?;
        ensure!(
            retained.name()? == name && retained.version()? == approval.version,
            "retained sparse row identity differs from locked {name} {}",
            approval.version
        );
        ensure!(
            retained.checksum()? == approval.archive_sha256,
            "retained sparse row checksum differs from locked {name} {}",
            approval.version
        );
        let upstream = exact_row(history, &approval.version).with_context(|| {
            format!(
                "locked identity {name} {} is absent from current crates.io history",
                approval.version
            )
        })?;
        ensure!(
            sha256_bytes(&upstream.bytes) == approval.index_record_sha256,
            "crates.io sparse row changed for locked identity {name} {}",
            approval.version
        );
        ensure!(
            upstream.record.checksum()? == approval.archive_sha256,
            "crates.io checksum changed for locked identity {name} {}",
            approval.version
        );
        let retained_pubtime = UtcTimestamp::parse(retained.pubtime()?)?;
        let upstream_pubtime = UtcTimestamp::parse(upstream.record.pubtime()?)?;
        ensure!(
            retained_pubtime == upstream_pubtime,
            "crates.io publication time changed for locked identity {name} {}",
            approval.version
        );
        locked.push(LockedRelease {
            version: approval.version.clone(),
            published_at: retained_pubtime,
            active: approval.state == PackageState::Active,
        });
    }
    Ok(locked)
}

fn select_candidates(
    request: &PlanRequest,
    registry: &str,
    name: &str,
    evaluated_at: &UtcTimestamp,
    history: &[PolicyRelease],
    locked: &[LockedRelease],
    activity: PackageActivity,
) -> Result<Vec<CandidateSelection>> {
    match request {
        PlanRequest::Implicit => Ok(select_implicit_candidates(evaluated_at, history, locked)?
            .into_iter()
            .map(|selected| CandidateSelection {
                activity,
                lane: Some(selected.lane),
                base: Some(selected.base),
                candidate: selected.candidate,
                age_seconds: selected.age_seconds,
                dormant_gap: selected.dormant_gap,
                explicit: false,
            })
            .collect()),
        PlanRequest::Exact {
            name: exact_name,
            version,
        } if exact_name == name => {
            let selected = select_exact_candidate(evaluated_at, history, locked, version)?;
            Ok(vec![CandidateSelection {
                activity,
                lane: None,
                base: selected.base,
                candidate: selected.candidate,
                age_seconds: selected.age_seconds,
                dormant_gap: selected.dormant_gap,
                explicit: true,
            }])
        }
        PlanRequest::Exact { .. } => Ok(Vec::new()),
        PlanRequest::Revalidate(targets) => targets
            .iter()
            .filter(|target| target.registry == registry && target.name == name)
            .map(|target| {
                let active_lane = target.lane.as_ref().filter(|lane| {
                    locked.iter().any(|release| {
                        release.active
                            && super::implicit_lane(&release.version).as_ref() == Some(*lane)
                    })
                });
                if let Some(lane) = active_lane {
                    let selected = super::policy::select_exact_implicit_candidate(
                        evaluated_at,
                        history,
                        locked,
                        lane,
                        &target.version,
                    )?;
                    Ok(CandidateSelection {
                        activity,
                        lane: Some(selected.lane),
                        base: Some(selected.base),
                        candidate: selected.candidate,
                        age_seconds: selected.age_seconds,
                        dormant_gap: selected.dormant_gap,
                        explicit: false,
                    })
                } else {
                    let selected =
                        select_exact_candidate(evaluated_at, history, locked, &target.version)?;
                    Ok(CandidateSelection {
                        activity,
                        lane: None,
                        base: selected.base,
                        candidate: selected.candidate,
                        age_seconds: selected.age_seconds,
                        dormant_gap: selected.dormant_gap,
                        explicit: true,
                    })
                }
            })
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_candidate<R: PlannerResolver>(
    resolver: &R,
    catalog: &Catalog,
    policy: &Policy,
    history: &CratesIoHistory,
    name: &str,
    registry: &str,
    category: &str,
    selection: CandidateSelection,
) -> Result<UpdateCandidate> {
    let candidate_row = exact_row(history, &selection.candidate.version)
        .context("selected candidate is absent from sparse history")?;
    let base_row = selection
        .base
        .as_ref()
        .map(|base| {
            exact_row(history, &base.version).context("selected base is absent from history")
        })
        .transpose()?;
    let archives = collect_archive_evidence(resolver, name, &selection, candidate_row, base_row)?;
    let candidate_dependencies = dependency_set(&candidate_row.record.dependencies()?)?;
    let base_dependencies = match base_row {
        Some(row) => dependency_set(&row.record.dependencies()?)?,
        None => BTreeSet::new(),
    };
    let dependencies = dependency_delta(&base_dependencies, &candidate_dependencies);
    let mut reasons = classify_candidate_reasons(
        catalog,
        policy,
        category,
        &selection,
        &archives,
        &candidate_dependencies,
        &dependencies,
    )?;
    let api = fetch_api_evidence(
        resolver,
        name,
        base_row,
        candidate_row,
        selection.base.as_ref(),
    );
    classify_api_discontinuity(&selection, api.as_ref(), &mut reasons);
    if selection.explicit {
        reasons.insert(DecisionReason::ExplicitCandidate);
    }
    let source = collect_source_evidence(
        resolver,
        name,
        &selection.candidate.version,
        &archives.candidate,
        api.as_ref(),
        &mut reasons,
    );
    let candidate_identity = planned_identity(candidate_row, &selection.candidate)?;
    let base_identity = planned_base_identity(selection.base.as_ref(), base_row)?;
    let decision_history_sha256 = decision_history_sha256(
        history,
        selection.base.as_ref().map(|base| &base.published_at),
        &selection.candidate,
    )?;
    let candidate_archive = ArchiveSummary::from_analysis(&archives.candidate)?;

    Ok(UpdateCandidate {
        registry: registry.to_owned(),
        category: category.to_owned(),
        name: name.to_owned(),
        activity: selection.activity,
        lane: selection.lane,
        base: base_identity,
        candidate: candidate_identity,
        sparse_index_sha256: history.sha256.clone(),
        decision_history_sha256,
        age_seconds: selection.age_seconds,
        dormant_gap: selection.dormant_gap,
        base_archive: archives.base_summary,
        candidate_archive,
        archive_delta: archives.delta,
        dependencies,
        api,
        source,
        decision: decision_for_reasons(&reasons),
        reasons: reasons.into_iter().collect(),
    })
}

struct ArchiveEvidence {
    candidate: ArchiveAnalysis,
    base_summary: Option<ArchiveSummary>,
    delta: Option<super::ArchiveDelta>,
}

fn collect_archive_evidence<R: PlannerResolver>(
    resolver: &R,
    name: &str,
    selection: &CandidateSelection,
    candidate_row: &SparseIndexRow,
    base_row: Option<&SparseIndexRow>,
) -> Result<ArchiveEvidence> {
    let candidate = fetch_and_inspect_archive(
        resolver,
        name,
        &selection.candidate.version,
        candidate_row,
        "candidate",
    )?;
    let (base_summary, delta) = match (selection.base.as_ref(), base_row) {
        (Some(base), Some(row)) => {
            let analysis = fetch_and_inspect_archive(resolver, name, &base.version, row, "base")?;
            let summary = ArchiveSummary::from_analysis(&analysis)?;
            let delta = compare_archive_analyses(&analysis, &candidate)?;
            (Some(summary), Some(delta))
        }
        (None, None) => (None, None),
        _ => anyhow::bail!("selected base and sparse row disagree"),
    };
    Ok(ArchiveEvidence {
        candidate,
        base_summary,
        delta,
    })
}

fn fetch_and_inspect_archive<R: PlannerResolver>(
    resolver: &R,
    name: &str,
    version: &Version,
    row: &SparseIndexRow,
    role: &str,
) -> Result<ArchiveAnalysis> {
    let checksum = row.record.checksum()?.to_owned();
    let bytes = resolver
        .archive(name, version, &checksum)
        .with_context(|| format!("fetch {role} archive {name} {version}"))?;
    ensure!(
        sha256_bytes(&bytes) == checksum,
        "{role} archive checksum differs from sparse row for {name} {version}"
    );
    inspect_crate_archive(name, version, &bytes)
        .with_context(|| format!("inspect {role} archive {name} {version}"))
}

#[allow(clippy::too_many_arguments)]
fn classify_candidate_reasons(
    catalog: &Catalog,
    policy: &Policy,
    category: &str,
    selection: &CandidateSelection,
    archives: &ArchiveEvidence,
    candidate_dependencies: &BTreeSet<IndexDependency>,
    dependencies: &DependencyDelta,
) -> Result<BTreeSet<DecisionReason>> {
    let mut reasons = BTreeSet::new();
    match selection.activity {
        PackageActivity::New => {
            reasons.insert(DecisionReason::NewPackage);
        }
        PackageActivity::Inactive => {
            reasons.insert(DecisionReason::InactiveRevival);
        }
        PackageActivity::Active => {}
    }
    if selection.dormant_gap.is_some() {
        reasons.insert(DecisionReason::DormantWakeup);
    }
    if !dependencies.new_packages.is_empty() {
        reasons.insert(DecisionReason::NewDependency);
    }
    let build_surface_changed = archives.delta.as_ref().map_or_else(
        || !archives.candidate.build_surface.is_empty(),
        |delta| delta.build_surface_changed,
    );
    if build_surface_changed {
        reasons.insert(DecisionReason::BuildSurfaceChanged);
    }
    classify_dependency_policy(
        catalog,
        policy,
        category,
        candidate_dependencies,
        &mut reasons,
    )?;
    Ok(reasons)
}

fn classify_api_discontinuity(
    selection: &CandidateSelection,
    api: Option<&ApiEvidence>,
    reasons: &mut BTreeSet<DecisionReason>,
) {
    if selection.base.is_none() {
        return;
    }
    let (publisher_discontinuity, repository_discontinuity) =
        api.map_or((true, true), |evidence| {
            let base = evidence
                .base
                .as_ref()
                .expect("existing candidate API evidence has a base");
            (
                base.publisher_id.is_none()
                    || evidence.candidate.publisher_id.is_none()
                    || base.publisher_id != evidence.candidate.publisher_id,
                base.repository.is_none()
                    || evidence.candidate.repository.is_none()
                    || base.repository != evidence.candidate.repository,
            )
        });
    if publisher_discontinuity {
        reasons.insert(DecisionReason::PublisherDiscontinuity);
    }
    if repository_discontinuity {
        reasons.insert(DecisionReason::RepositoryDiscontinuity);
    }
}

fn collect_source_evidence<R: PlannerResolver>(
    resolver: &R,
    name: &str,
    version: &Version,
    candidate: &ArchiveAnalysis,
    api: Option<&ApiEvidence>,
    reasons: &mut BTreeSet<DecisionReason>,
) -> SourceEvidence {
    let promoted = reasons
        .iter()
        .any(|reason| is_source_promotion_reason(*reason));
    let source = if promoted {
        resolver
            .source(candidate, api.map(|value| &value.candidate))
            .unwrap_or_else(|error| {
                warn!(
                    package = name,
                    version = %version,
                    error = %format_args!("{error:#}"),
                    "source verification could not produce evidence"
                );
                SourceEvidence::Unavailable {
                    reason: "source-verification-error".to_owned(),
                }
            })
    } else {
        SourceEvidence::Unavailable {
            reason: "not-promoted".to_owned(),
        }
    };
    if promoted && matches!(source, SourceEvidence::Unavailable { .. }) {
        reasons.insert(DecisionReason::SourceUnavailable);
    }
    if matches!(source, SourceEvidence::Mismatch { .. }) {
        reasons.insert(DecisionReason::SourceMismatch);
    }
    source
}

fn planned_base_identity(
    base: Option<&LockedRelease>,
    row: Option<&SparseIndexRow>,
) -> Result<Option<PlannedIdentity>> {
    match (base, row) {
        (Some(base), Some(row)) => planned_identity(
            row,
            &PolicyRelease {
                version: base.version.clone(),
                published_at: base.published_at.clone(),
                yanked: row.record.yanked().unwrap_or(true),
            },
        )
        .map(Some),
        (None, None) => Ok(None),
        _ => anyhow::bail!("selected base and sparse row disagree"),
    }
}

fn fetch_api_evidence<R: PlannerResolver>(
    resolver: &R,
    name: &str,
    base_row: Option<&SparseIndexRow>,
    candidate_row: &SparseIndexRow,
    base: Option<&LockedRelease>,
) -> Option<ApiEvidence> {
    let result = (|| {
        let bytes = resolver.api(name)?;
        let candidate_version = candidate_row.record.version()?;
        let candidate_checksum = candidate_row.record.checksum()?;
        let base_argument = match (base, base_row) {
            (Some(base), Some(row)) => Some((&base.version, row.record.checksum()?)),
            (None, None) => None,
            _ => anyhow::bail!("base identity and sparse row disagree"),
        };
        parse_crates_io_api_evidence(
            name,
            &bytes,
            base_argument,
            (&candidate_version, candidate_checksum),
        )
    })();
    match result {
        Ok(evidence) => Some(evidence),
        Err(error) => {
            warn!(
                package = name,
                error = %format_args!("{error:#}"),
                "crates.io API evidence unavailable; promoting review where required"
            );
            None
        }
    }
}

fn classify_dependency_policy(
    catalog: &Catalog,
    policy: &Policy,
    category: &str,
    dependencies: &BTreeSet<IndexDependency>,
    reasons: &mut BTreeSet<DecisionReason>,
) -> Result<()> {
    let source_category = category.parse::<crate::category::CategoryId>()?;
    for dependency in dependencies {
        match catalog
            .homes
            .resolve_dependency(source_category.registry(), &dependency.package)
        {
            Err(_) => {
                reasons.insert(DecisionReason::UnknownDependencyHome);
            }
            Ok(home) if !policy.permits_dependency(&source_category, &home.category) => {
                reasons.insert(DecisionReason::ForbiddenCategoryDependency);
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

fn dependency_set(dependencies: &[IndexDependency]) -> Result<BTreeSet<IndexDependency>> {
    let set = dependencies.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        set.len() == dependencies.len(),
        "sparse index repeats a normalized dependency edge"
    );
    Ok(set)
}

fn dependency_delta(
    base: &BTreeSet<IndexDependency>,
    candidate: &BTreeSet<IndexDependency>,
) -> DependencyDelta {
    let base_packages = base
        .iter()
        .map(|dependency| package_identity(&dependency.package))
        .collect::<BTreeSet<_>>();
    let added = candidate.difference(base).cloned().collect::<Vec<_>>();
    let removed = base.difference(candidate).cloned().collect::<Vec<_>>();
    let mut new_packages = added
        .iter()
        .filter(|dependency| !base_packages.contains(&package_identity(&dependency.package)))
        .map(|dependency| dependency.package.clone())
        .collect::<Vec<_>>();
    new_packages.sort_by(|left, right| package_order(left).cmp(&package_order(right)));
    new_packages.dedup_by(|left, right| package_identity(left) == package_identity(right));
    DependencyDelta {
        added,
        removed,
        new_packages,
    }
}

fn planned_identity(row: &SparseIndexRow, release: &PolicyRelease) -> Result<PlannedIdentity> {
    ensure!(
        row.record.version()? == release.version,
        "planned sparse row version differs from policy release"
    );
    ensure!(
        UtcTimestamp::parse(row.record.pubtime()?)? == release.published_at,
        "planned sparse row publication time differs from policy release"
    );
    Ok(PlannedIdentity {
        version: release.version.clone(),
        published_at: release.published_at.clone(),
        source_row_sha256: sha256_bytes(&row.bytes),
        crate_sha256: row.record.checksum()?.to_owned(),
    })
}

fn decision_history_sha256(
    history: &CratesIoHistory,
    base_time: Option<&UtcTimestamp>,
    candidate: &PolicyRelease,
) -> Result<String> {
    let mut rows = history
        .rows
        .iter()
        .map(|row| {
            Ok((
                UtcTimestamp::parse(row.record.pubtime()?)?,
                row.record.version()?,
                row,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    rows.retain(|(published_at, _, _)| {
        published_at <= &candidate.published_at && base_time.is_none_or(|base| published_at >= base)
    });
    rows.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    ensure!(
        rows.iter().any(|(_, version, _)| {
            version_identity(version) == version_identity(&candidate.version)
        }),
        "decision history omitted the selected candidate"
    );
    let mut hasher = Sha256::new();
    hasher.update(b"pkgre-update-decision-history-v1\0");
    for (published_at, version, row) in rows {
        hash_frame(&mut hasher, published_at.as_str().as_bytes())?;
        hash_frame(&mut hasher, version.to_string().as_bytes())?;
        hash_frame(&mut hasher, &row.bytes)?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_frame(hasher: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let length = u64::try_from(bytes.len()).context("decision-history frame exceeds u64")?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn exact_row<'a>(history: &'a CratesIoHistory, version: &Version) -> Option<&'a SparseIndexRow> {
    history.rows.iter().find(|row| {
        row.record
            .version()
            .is_ok_and(|candidate| version_identity(&candidate) == version_identity(version))
    })
}

fn is_source_promotion_reason(reason: DecisionReason) -> bool {
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
}

fn decision_for_reasons(reasons: &BTreeSet<DecisionReason>) -> UpdateDecision {
    if reasons.iter().any(|reason| {
        matches!(
            reason,
            DecisionReason::UnknownDependencyHome
                | DecisionReason::ForbiddenCategoryDependency
                | DecisionReason::SourceMismatch
        )
    }) {
        UpdateDecision::Blocked
    } else if reasons.iter().any(|reason| {
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
    }) {
        UpdateDecision::ReviewRequired
    } else {
        UpdateDecision::Automatic
    }
}

fn candidate_order(candidate: &UpdateCandidate) -> (String, String, String, Version) {
    (
        candidate.registry.clone(),
        candidate.name.to_ascii_lowercase(),
        candidate.name.clone(),
        candidate.candidate.version.clone(),
    )
}

fn package_identity(value: &str) -> String {
    value.to_ascii_lowercase().replace('-', "_")
}

fn package_order(value: &str) -> (String, &str) {
    (value.to_ascii_lowercase(), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::schema::{Approval, HomesFile, PackageHome, PackageKey, RegistriesFile};

    fn planning_catalog() -> Catalog {
        let category: crate::category::CategoryId = "universe/general".parse().unwrap();
        let names = ["active", "empty", "exact-only", "inactive"];
        let homes = names
            .iter()
            .map(|name| {
                (
                    PackageKey::new("universe", *name),
                    PackageHome {
                        registry: "universe".to_owned(),
                        category: category.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let approval = |name: &str, version: &str, state| Approval {
            registry: "universe".to_owned(),
            category: category.clone(),
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            archive_sha256: "00".repeat(32),
            index_record_sha256: "11".repeat(32),
            index_row_sha256: "22".repeat(32),
            admission_sha256: None,
            state,
            source: Source::CratesIo,
            declared_in: PathBuf::from("universe.lock"),
        };
        Catalog {
            root: PathBuf::from("unused"),
            registries: RegistriesFile {
                schema: crate::schema::SCHEMA_VERSION,
                cname: "rust.pkg.re".to_owned(),
                cargo_version: Version::parse("1.95.0").unwrap(),
                registries: Vec::new(),
            },
            categories: BTreeMap::new(),
            homes: HomesFile {
                schema: crate::schema::SCHEMA_VERSION,
                homes,
            },
            mirror_names: names
                .iter()
                .map(|name| PackageKey::new("universe", *name))
                .collect(),
            publish_names: BTreeSet::new(),
            approvals: vec![
                approval("active", "1.0.0", PackageState::Active),
                approval("exact-only", "0.0.1", PackageState::Active),
                approval("inactive", "1.0.0", PackageState::Removed),
            ],
        }
    }

    #[test]
    fn implicit_planning_targets_only_active_compatibility_lanes() {
        let catalog = planning_catalog();
        let implicit = planning_targets(&catalog, &PlanRequest::Implicit)
            .unwrap()
            .into_iter()
            .map(|(key, _)| key.name)
            .collect::<Vec<_>>();
        assert_eq!(implicit, ["active"]);

        let exact = planning_targets(
            &catalog,
            &PlanRequest::Exact {
                name: "inactive".to_owned(),
                version: Version::parse("2.0.0").unwrap(),
            },
        )
        .unwrap();
        assert_eq!(exact[0].0, PackageKey::new("universe", "inactive"));
    }

    fn timestamp(value: &str) -> UtcTimestamp {
        UtcTimestamp::parse(value).unwrap()
    }

    fn release(version: &str, published_at: &str) -> PolicyRelease {
        PolicyRelease {
            version: Version::parse(version).unwrap(),
            published_at: timestamp(published_at),
            yanked: false,
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
    fn admission_revalidation_preserves_implicit_lane_base() {
        let history = vec![
            release("1.0.0", "2024-01-01T00:00:00Z"),
            release("2.0.0", "2024-02-01T00:00:00Z"),
            release("1.1.0", "2024-03-01T00:00:00Z"),
        ];
        let locked = vec![
            locked("1.0.0", "2024-01-01T00:00:00Z", true),
            locked("2.0.0", "2024-02-01T00:00:00Z", true),
        ];
        let request = PlanRequest::Revalidate(vec![RevalidationTarget {
            registry: "universe".to_owned(),
            name: "demo".to_owned(),
            version: Version::parse("1.1.0").unwrap(),
            lane: Some(CompatibilityLane::Major { major: 1 }),
        }]);

        let selected = select_candidates(
            &request,
            "universe",
            "demo",
            &timestamp("2024-05-01T00:00:00Z"),
            &history,
            &locked,
            PackageActivity::Active,
        )
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].base.as_ref().unwrap().version,
            Version::parse("1.0.0").unwrap()
        );
        assert_eq!(
            selected[0].lane,
            Some(CompatibilityLane::Major { major: 1 })
        );
        assert!(!selected[0].explicit);
    }

    #[test]
    fn admission_revalidation_falls_back_to_exact_for_new_lane() {
        let history = vec![
            release("1.0.0", "2024-01-01T00:00:00Z"),
            release("2.0.0", "2024-02-01T00:00:00Z"),
        ];
        let locked = vec![locked("1.0.0", "2024-01-01T00:00:00Z", true)];
        let request = PlanRequest::Revalidate(vec![RevalidationTarget {
            registry: "universe".to_owned(),
            name: "demo".to_owned(),
            version: Version::parse("2.0.0").unwrap(),
            lane: Some(CompatibilityLane::Major { major: 2 }),
        }]);

        let selected = select_candidates(
            &request,
            "universe",
            "demo",
            &timestamp("2024-05-01T00:00:00Z"),
            &history,
            &locked,
            PackageActivity::Active,
        )
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].base.as_ref().unwrap().version,
            Version::parse("1.0.0").unwrap()
        );
        assert_eq!(selected[0].lane, None);
        assert!(selected[0].explicit);
    }

    #[test]
    fn admission_revalidation_supports_a_new_stable_package() {
        let history = vec![release("1.0.0", "2024-01-01T00:00:00Z")];
        let request = PlanRequest::Revalidate(vec![RevalidationTarget {
            registry: "universe".to_owned(),
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            lane: Some(CompatibilityLane::Major { major: 1 }),
        }]);

        let selected = select_candidates(
            &request,
            "universe",
            "demo",
            &timestamp("2024-05-01T00:00:00Z"),
            &history,
            &[],
            PackageActivity::New,
        )
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].base, None);
        assert_eq!(selected[0].lane, None);
        assert!(selected[0].explicit);
    }

    fn dependency(package: &str, requirement: &str) -> IndexDependency {
        IndexDependency {
            name: package.to_owned(),
            package: package.to_owned(),
            requirement: requirement.to_owned(),
            features: Vec::new(),
            optional: false,
            default_features: true,
            target: None,
            kind: "normal".to_owned(),
            registry: None,
        }
    }

    #[test]
    fn dependency_delta_distinguishes_new_identity_from_edge_changes() {
        let base = BTreeSet::from([dependency("same", "^1")]);
        let candidate = BTreeSet::from([dependency("same", "^2"), dependency("new-package", "^1")]);
        let delta = dependency_delta(&base, &candidate);
        assert_eq!(delta.added.len(), 2);
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.new_packages, ["new-package"]);
    }

    #[test]
    fn blocking_reasons_dominate_review_reasons() {
        let review = BTreeSet::from([DecisionReason::NewPackage]);
        assert_eq!(
            decision_for_reasons(&review),
            UpdateDecision::ReviewRequired
        );
        let blocked = BTreeSet::from([
            DecisionReason::NewPackage,
            DecisionReason::UnknownDependencyHome,
        ]);
        assert_eq!(decision_for_reasons(&blocked), UpdateDecision::Blocked);
    }
}
