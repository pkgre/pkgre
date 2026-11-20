//! Accepted-ref watcher: fixed-ref polling with last-known-good serving snapshots.
//!
//! The watcher owns the accepted-ref record on disk, a bare Git mirror of the
//! watched origin, and the shared serving snapshot. Every poll observes the
//! remote tip once and applies the shared transition policy
//! ([`pkgre_rust::accepted_ref`]): only strictly forward, semantically valid,
//! durably persisted candidates are published, and a failed reload never
//! changes the active snapshot or the accepted ref.
//!
//! Every refusal is classified by what failed. A refusal of the candidate's
//! own content, or of its relation to the accepted commit, is suppressed by
//! hash until the tip changes or the process restarts. A local failure, such
//! as a full temporary disk, a Git or tar time-out, a failed `fsync`, a host
//! read error or an incomplete archive store, is retried after 1, 2, 4 and 8
//! minutes and then every 15 minutes while the last-known-good snapshot keeps
//! serving. A failure that cannot be classified is suppressed like the
//! candidate's and reported as `unclassified`. Remote failures are not
//! refusals: they report `remote-unavailable` and are tried again at every
//! poll, without a backoff.
//!
//! Startup authority is the accepted record alone. A record bootstraps only when
//! the record path is absent; any present malformed or mismatched record forbids
//! bootstrap and fails the service. The remote tip is never startup authority.
//!
//! End-to-end tests below cover every rejection reachable through real Git
//! orchestration (remote outages, persistence failure and its retry,
//! suppression, a retry schedule, ancestry, semantic validation, a commit that
//! holds `.gitattributes`, a commit that deletes the catalog path, object
//! corruption, an accepted-tree materialization failure, catalog-path
//! normalization). The remaining transition reasons —
//! repository-identity mismatch, full-ref mismatch, malformed commits, unknown
//! ancestry, and candidate object unavailability on reload — are enforced by
//! [`evaluate_reload`] and covered by the shared transition-policy fixture tests
//! in [`pkgre_rust::accepted_ref`]; they are not realizable through a controlled
//! origin because the watcher derives candidate fields from operator
//! configuration and verified Git output only.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use pkgre_rust::accepted_ref::{
    AcceptedRecordState, AcceptedRef, Ancestry, ObjectState, Persistence, ReloadCandidate,
    RepositoryConfig, SemanticValidity, StartupInput, TransitionDecision, TransitionReason,
    canonical_accepted_ref_bytes, evaluate_reload, evaluate_startup,
};
use pkgre_rust::projection::{FirstPartyOrigin, ProjectionLimits};
use pkgre_rust::serve::{DeliveryMode, Snapshot, build_snapshot};
use pkgre_rust::transition::check_transition;
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::config::WatcherConfig;
use crate::web;

/// Exact accepted-ref record file name inside the watcher state directory.
const ACCEPTED_RECORD_FILE: &str = "accepted-ref.json";
/// Exact bare mirror directory name inside the watcher state directory.
const REPOSITORY_DIR: &str = "repository";
/// Exact temporary directory name inside the watcher state directory.
const TEMP_DIR: &str = "temp";
/// Exact local ref updated by every fetch of the watched remote ref.
const WATCH_REF: &str = "refs/pkgre/watch";
/// Exact wall-clock bound applied to every Git and tar invocation.
const GIT_TIMEOUT: Duration = Duration::from_secs(600);
/// Exact number of trailing bytes kept from failed command diagnostics.
const MAX_COMMAND_ERROR_BYTES: usize = 512;

/// Exact outcome of one watcher poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollReport {
    /// Exact transition decision applied for this poll.
    pub decision: TransitionDecision,
    /// Exact transition reason behind the decision.
    pub reason: TransitionReason,
    /// Classified failure for a refused or skipped candidate.
    pub refusal: Option<RefusalReport>,
}

/// Monotonic source shared by retry scheduling and admin status rendering.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Whether a refusal belongs to the candidate, the host, or neither proven class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    /// The commit's contents or ancestry cannot be accepted.
    Candidate,
    /// Local state can recover without changing the commit.
    Local,
    /// An internal failure cannot safely be classified as retryable.
    Unclassified,
}

impl FailureClass {
    /// Whether a failure of this class may pass on a later attempt of the same commit.
    const fn is_retryable(self) -> bool {
        matches!(self, Self::Local)
    }

    /// Stable lowercase name of this class in logs and `/status`.
    const fn code(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Local => "local",
            Self::Unclassified => "unclassified",
        }
    }
}

/// One failure code with the class it belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Failure {
    code: &'static str,
    class: FailureClass,
}

impl Failure {
    const fn new(code: &'static str, class: FailureClass) -> Self {
        Self { code, class }
    }

    const fn internal() -> Self {
        Self::new("internal-error", FailureClass::Unclassified)
    }
}

/// Failure details of a refused or skipped candidate, without paths or error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefusalReport {
    /// Stable failure code identifying the failed check.
    pub failure: &'static str,
    /// Classification controlling retry eligibility.
    pub class: FailureClass,
    /// Failed evaluations of this commit; skipped polls do not count.
    pub attempts: u64,
    /// Seconds until retry, or none for a permanent refusal.
    pub retry_in_seconds: Option<u64>,
}

/// How one refused commit is handled: refused for good, or waiting for a retry.
#[derive(Clone, Copy)]
struct Refusal {
    reason: TransitionReason,
    failure: Failure,
    attempts: u64,
    ended: Instant,
    retry_at: Option<Instant>,
}

impl Refusal {
    /// Renders this refusal against `now` without paths, error text or wall-clock times.
    fn report(self, now: Instant) -> RefusalReport {
        RefusalReport {
            failure: self.failure.code,
            class: self.failure.class,
            attempts: self.attempts,
            retry_in_seconds: self
                .retry_at
                .map(|due| due.saturating_duration_since(now).as_secs()),
        }
    }

    /// Whether this commit is still suppressed: refused for good, or waiting for its retry.
    fn is_waiting(self, now: Instant) -> bool {
        self.retry_at.is_none_or(|due| now < due)
    }
}

/// First retry wait after one local failure, in seconds.
const RETRY_BASE_SECS: u64 = 60;
/// Longest retry wait, in seconds.
const RETRY_MAX_SECS: u64 = 15 * 60;
/// Number of wait doublings before the wait reaches [`RETRY_MAX_SECS`].
const RETRY_DOUBLINGS: u32 = 4;

/// Returns the wait after the `attempts`-th consecutive local failure of one commit:
/// 1, 2, 4, 8, 15, 15, ... minutes.
fn retry_delay(attempts: u64) -> Duration {
    let doublings = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or(RETRY_DOUBLINGS)
        .min(RETRY_DOUBLINGS);
    Duration::from_secs((RETRY_BASE_SECS << doublings).min(RETRY_MAX_SECS))
}

#[derive(Default)]
struct WatchState {
    /// Refused commits by hash, with their class, attempts and next attempt.
    entries: HashMap<String, Refusal>,
    /// Last tip any poll observed, or none before the first observation.
    tip: Option<String>,
    /// Last poll's report and the time it ended.
    last_poll: Option<(PollReport, Instant)>,
    /// Last refused or skipped commit and its refusal.
    last_refusal: Option<(String, Refusal)>,
}

/// Published watcher state, rendered using the watcher's own monotonic clock.
#[derive(Clone)]
pub struct WatcherView {
    clock: Clock,
    accepted_commit: String,
    tip: Option<String>,
    last_poll: Option<(PollReport, Instant)>,
    last_refusal: Option<(String, Refusal)>,
}

/// Additive admin status of a dynamic catalog source.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatcherStatus {
    accepted_commit: String,
    tip: Option<String>,
    last_poll: Option<PollStatus>,
    last_refusal: Option<RefusalStatus>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PollStatus {
    decision: TransitionDecision,
    reason: TransitionReason,
    seconds_ago: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RefusalStatus {
    commit: String,
    reason: TransitionReason,
    #[serde(flatten)]
    report: RefusalReport,
    seconds_ago: u64,
}

impl WatcherView {
    /// Renders the admin `/status` member, with both ages from this view's clock.
    pub(crate) fn status(&self) -> WatcherStatus {
        let now = (self.clock)();
        WatcherStatus {
            accepted_commit: self.accepted_commit.clone(),
            tip: self.tip.clone(),
            last_poll: self.last_poll.map(|(report, ended)| PollStatus {
                decision: report.decision,
                reason: report.reason,
                seconds_ago: now.saturating_duration_since(ended).as_secs(),
            }),
            last_refusal: self
                .last_refusal
                .as_ref()
                .map(|(commit, refusal)| RefusalStatus {
                    commit: commit.clone(),
                    reason: refusal.reason,
                    report: refusal.report(now),
                    seconds_ago: now.saturating_duration_since(refusal.ended).as_secs(),
                }),
        }
    }
}

fn object_failure(state: ObjectState) -> Option<Failure> {
    match state {
        ObjectState::Valid | ObjectState::NotApplicable => None,
        ObjectState::Missing => Some(Failure::new("object-unavailable", FailureClass::Local)),
        ObjectState::Corrupt => Some(Failure::new("object-unreadable", FailureClass::Local)),
        ObjectState::Malformed => Some(Failure::new("not-a-commit", FailureClass::Candidate)),
    }
}

fn ancestry_failure(ancestry: Ancestry) -> Option<Failure> {
    match ancestry {
        Ancestry::Descendant | Ancestry::Equal | Ancestry::NotEvaluated => None,
        Ancestry::Unknown => Some(Failure::new("ancestry-unknown", FailureClass::Local)),
        Ancestry::Predecessor | Ancestry::Divergent => {
            Some(Failure::new("not-descendant", FailureClass::Candidate))
        }
    }
}

/// What the catalog-path probe found in one commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogEntry {
    /// No entry at the normalized catalog path.
    Missing,
    /// A tree at the normalized catalog path.
    Tree,
    /// A blob, symbolic link or submodule at the normalized catalog path.
    NotTree,
}

/// How one side's catalog tree failed to materialize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Materialization {
    /// The candidate's commit holds no entry at the catalog path.
    MissingEntry,
    /// The catalog-path probe could not answer, so nothing was materialized.
    Unprobed,
    /// A tree at the catalog path failed to materialize.
    TreeFailed,
    /// An entry that is not a tree failed to materialize.
    NotTreeFailed,
    /// The commit holds a `.gitattributes` file, which `git archive` would apply.
    AttributesPresent,
}

/// Classifies one failed materialization.
fn materialization_failure(accepted: bool, outcome: Materialization) -> Failure {
    match outcome {
        Materialization::MissingEntry | Materialization::NotTreeFailed if !accepted => {
            Failure::new("catalog-path-invalid", FailureClass::Candidate)
        }
        Materialization::AttributesPresent if !accepted => {
            Failure::new("gitattributes-present", FailureClass::Candidate)
        }
        Materialization::MissingEntry
        | Materialization::Unprobed
        | Materialization::TreeFailed
        | Materialization::NotTreeFailed
        | Materialization::AttributesPresent => {
            Failure::new("materialization-failed", FailureClass::Local)
        }
    }
}

/// Returns an invalid semantic validation carrying its classified failure.
fn invalid(failure: Option<Failure>) -> (SemanticValidity, Option<Arc<Snapshot>>, Option<Failure>) {
    (SemanticValidity::Invalid, None, failure)
}

/// What a failed accepted-side materialization observed.
///
/// The accepted tree materialized before, so every cause is local; a `.gitattributes` there
/// means the mirror's object changed under the process.
fn accepted_materialization(error: &anyhow::Error) -> Materialization {
    if error.downcast_ref::<GitAttributesPresent>().is_some() {
        Materialization::AttributesPresent
    } else {
        Materialization::TreeFailed
    }
}

/// What a failed candidate-side materialization observed, given the probed catalog entry.
fn candidate_materialization(entry: CatalogEntry, error: &anyhow::Error) -> Materialization {
    if error.downcast_ref::<GitAttributesPresent>().is_some() {
        Materialization::AttributesPresent
    } else if entry == CatalogEntry::NotTree {
        Materialization::NotTreeFailed
    } else {
        Materialization::TreeFailed
    }
}

fn transition_failure(reason: &pkgre_rust::transition::RejectReason) -> Failure {
    Failure::new(
        reason.code(),
        if reason.is_local() {
            FailureClass::Local
        } else {
            FailureClass::Candidate
        },
    )
}

/// Marks a candidate whose commit holds a `.gitattributes` file, which `git archive` would
/// apply to the materialized tree.
#[derive(Debug)]
struct GitAttributesPresent;

impl std::fmt::Display for GitAttributesPresent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("commit holds .gitattributes")
    }
}

impl std::error::Error for GitAttributesPresent {}

/// Marks a failure to build or serialize the accepted-ref record, which depends only on
/// fields that were already validated.
#[derive(Debug)]
struct RecordEncodingError;

impl std::fmt::Display for RecordEncodingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("accepted-ref record encoding")
    }
}

impl std::error::Error for RecordEncodingError {}

/// Classifies one failed snapshot build of the candidate.
fn snapshot_failure(error: &anyhow::Error) -> Failure {
    if error.downcast_ref::<tokio::task::JoinError>().is_some() {
        Failure::internal()
    } else if error
        .downcast_ref::<pkgre_rust::serve::ArchiveStoreError>()
        .is_some()
    {
        Failure::new("archive-store-incomplete", FailureClass::Local)
    } else if pkgre_rust::transition::host_io_failure(error) {
        Failure::new("catalog-unreadable", FailureClass::Local)
    } else {
        Failure::new("snapshot-invalid", FailureClass::Candidate)
    }
}

/// Classifies one failed persistence of the accepted-ref record.
fn persistence_failure(error: &anyhow::Error) -> Failure {
    if error.downcast_ref::<RecordEncodingError>().is_some() {
        Failure::internal()
    } else {
        Failure::new("persistence-failed", FailureClass::Local)
    }
}

/// Normalizes the configured catalog path to its plain components joined with `/`, so that
/// `git ls-tree` answers the entry itself rather than a directory's contents.
fn normalized_catalog_path(path: &str) -> String {
    Path::new(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Fixed-ref accepted-ref watcher with last-known-good snapshot publication.
pub struct Watcher {
    origin: String,
    catalog_path: String,
    bootstrap_commit: String,
    state_path: PathBuf,
    poll_interval: Duration,
    repository: RepositoryConfig,
    delivery: DeliveryMode,
    archive_store: Option<PathBuf>,
    first_party_origin: Option<FirstPartyOrigin>,
    shared: Arc<web::Shared>,
    accepted: RwLock<Option<AcceptedRef>>,
    state: Mutex<WatchState>,
    clock: Clock,
    temp_counter: AtomicU64,
}

impl Watcher {
    /// Creates the watcher without performing any I/O.
    #[must_use]
    pub fn new(
        config: &WatcherConfig,
        delivery: DeliveryMode,
        archive_store: Option<PathBuf>,
        first_party_origin: Option<FirstPartyOrigin>,
        shared: Arc<web::Shared>,
        clock: Clock,
    ) -> Self {
        Self {
            origin: config.origin.clone(),
            catalog_path: config.catalog_path.clone(),
            bootstrap_commit: config.bootstrap_commit.clone(),
            state_path: config.state_path.clone(),
            poll_interval: config.poll_interval,
            repository: config.repository.clone(),
            delivery,
            archive_store,
            first_party_origin,
            shared,
            accepted: RwLock::new(None),
            state: Mutex::new(WatchState::default()),
            clock,
            temp_counter: AtomicU64::new(0),
        }
    }

    /// Returns the exact delay between remote polls.
    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Establishes the initial accepted ref and installs the first snapshot.
    ///
    /// Bootstraps from the configured commit only when the accepted-record path
    /// is absent; any present malformed or mismatched record fails startup. The
    /// remote tip is never startup authority, and no fetch happens when a valid
    /// record is present.
    ///
    /// # Errors
    ///
    /// Returns an error for any state-directory, Git, catalog, or transition
    /// failure; the service must refuse to start.
    pub async fn startup(&self) -> Result<()> {
        self.prepare_state().await?;
        self.prepare_repository().await?;
        let (state, record) = self.load_startup_record()?;
        let bootstrap_object = match state {
            AcceptedRecordState::Absent => {
                let probed = self
                    .object_state(&self.bootstrap_commit)
                    .await
                    .context("probe bootstrap object")?;
                if probed == ObjectState::Missing {
                    if let Err(error) = self.fetch().await {
                        warn!(%error, "watcher bootstrap fetch failed");
                    }
                    self.object_state(&self.bootstrap_commit)
                        .await
                        .context("probe bootstrap object after fetch")?
                } else {
                    probed
                }
            }
            AcceptedRecordState::Malformed | AcceptedRecordState::Present => {
                ObjectState::NotApplicable
            }
        };
        let local_accepted_object = match (&state, &record) {
            (AcceptedRecordState::Present, Some(record)) => self
                .object_state(record.accepted_commit())
                .await
                .context("probe accepted object")?,
            _ => ObjectState::NotApplicable,
        };
        let outcome = evaluate_startup(
            StartupInput {
                accepted_record: record.as_ref(),
                accepted_record_state: state,
                bootstrap_commit: &self.bootstrap_commit,
                bootstrap_object,
                local_accepted_object,
            },
            &self.repository,
        )
        .context("evaluate watcher startup transition")?;
        match outcome.decision() {
            TransitionDecision::Bootstrap => {
                let commit = outcome
                    .active_commit()
                    .context("bootstrap outcome carries no active commit")?
                    .to_owned();
                let snapshot = self.initial_snapshot(&commit).await?;
                let record = self.build_record(&commit)?;
                self.persist_record(&record)
                    .context("persist bootstrap accepted-ref record")?;
                *self.accepted.write().await = Some(record);
                self.shared.install_snapshot(snapshot).await;
            }
            TransitionDecision::StartAccepted => {
                let record = record.context("accepted record is required to start accepted")?;
                let snapshot = self.initial_snapshot(record.accepted_commit()).await?;
                *self.accepted.write().await = Some(record);
                self.shared.install_snapshot(snapshot).await;
            }
            TransitionDecision::FailStartup => {
                bail!("watcher startup failed: {:?}", outcome.reason());
            }
            decision => bail!("watcher startup produced unexpected decision {decision:?}"),
        }
        self.publish_view().await;
        info!(
            decision = ?outcome.decision(),
            reason = ?outcome.reason(),
            commit = ?outcome.active_commit(),
            "watcher startup complete"
        );
        Ok(())
    }

    /// Observes the remote once and applies the transition policy.
    ///
    /// # Errors
    ///
    /// Never returns an error: every failure is reported as a retention decision.
    pub async fn poll_once(&self) -> PollReport {
        let accepted = self.accepted.read().await.clone();
        let report = if let Some(accepted) = accepted {
            self.reload(&accepted).await
        } else {
            error!("watcher poll reached without an accepted record; retaining");
            PollReport {
                decision: TransitionDecision::RetainAccepted,
                reason: TransitionReason::RemoteUnavailable,
                refusal: None,
            }
        };
        self.state.lock().await.last_poll = Some((report, (self.clock)()));
        self.publish_view().await;
        info!(
            decision = ?report.decision,
            reason = ?report.reason,
            "watcher poll complete"
        );
        report
    }

    /// Polls on the configured interval until `shutdown` resolves.
    pub async fn run(self: Arc<Self>, shutdown: impl Future<Output = ()>) {
        let shutdown = std::pin::pin!(shutdown);
        let mut interval = tokio::time::interval(self.poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let watcher = Arc::clone(&self);
        tokio::select! {
            () = shutdown => {}
            () = async move {
                loop {
                    interval.tick().await;
                    watcher.poll_once().await;
                }
            } => {}
        }
    }

    async fn reload(&self, accepted: &AcceptedRef) -> PollReport {
        let tip = match self.remote_tip().await {
            Ok(Some(tip)) => tip,
            Ok(None) => {
                self.state.lock().await.tip = None;
                debug!("watched ref is absent upstream");
                return self.apply(accepted, None, None, None).await;
            }
            Err(error) => {
                warn!(%error, "watcher remote observation failed");
                return self.apply(accepted, None, None, None).await;
            }
        };
        self.state.lock().await.tip = Some(tip.clone());
        if tip == accepted.accepted_commit() {
            return PollReport {
                decision: TransitionDecision::Unchanged,
                reason: TransitionReason::CandidateEqualsAccepted,
                refusal: None,
            };
        }
        if self
            .state
            .lock()
            .await
            .entries
            .get(&tip)
            .is_some_and(|entry| entry.is_waiting((self.clock)()))
        {
            let candidate = self.rejected_candidate(&tip);
            return self.apply(accepted, Some(candidate), None, None).await;
        }
        if let Err(error) = self.fetch().await {
            warn!(%error, "watcher fetch failed");
            return self.apply(accepted, None, None, None).await;
        }
        let observed = match self.watch_ref_commit().await {
            Ok(observed) => observed,
            Err(error) => {
                warn!(%error, "watcher fetch resolution failed");
                return self.apply(accepted, None, None, None).await;
            }
        };
        if observed != tip {
            debug!("watched ref moved during reload; retrying next poll");
            return self.apply(accepted, None, None, None).await;
        }
        let object_state = match self.object_state(&tip).await {
            Ok(object_state) => object_state,
            Err(error) => {
                warn!(%error, "watcher object probe failed");
                return self.apply(accepted, None, None, None).await;
            }
        };
        let ancestry = self
            .observed_ancestry(accepted.accepted_commit(), &tip, object_state)
            .await;
        let mut candidate = ReloadCandidate {
            ancestry,
            commit: tip,
            full_ref: self.repository.full_ref().to_owned(),
            object_state,
            persistence: Persistence::NotAttempted,
            repository_identity: self.repository.repository_identity().to_owned(),
            semantic_validity: SemanticValidity::NotEvaluated,
            suppressed: false,
        };
        let mut failure = object_failure(object_state).or_else(|| ancestry_failure(ancestry));
        let mut pending = None;
        if object_state == ObjectState::Valid && ancestry == Ancestry::Descendant {
            let (validity, snapshot, semantic_failure) = self
                .semantic_validation(accepted.accepted_commit(), &candidate.commit)
                .await;
            candidate.semantic_validity = validity;
            failure = failure.or(semantic_failure);
            if validity == SemanticValidity::Valid {
                let record = self
                    .build_record(&candidate.commit)
                    .context(RecordEncodingError)
                    .context("build forward accepted-ref record")
                    .and_then(|record| self.persist_record(&record).map(|()| record));
                match record {
                    Ok(_) => {
                        candidate.persistence = Persistence::Success;
                        pending = snapshot;
                    }
                    Err(error) => {
                        warn!(%error, "watcher accepted-ref persistence failed");
                        failure = Some(persistence_failure(&error));
                        candidate.persistence = Persistence::InterruptedBeforeRename;
                    }
                }
            }
        }
        self.apply(accepted, Some(candidate), pending, failure)
            .await
    }

    /// Probes the tip's ancestry against the accepted commit; a failed probe is `Unknown`.
    async fn observed_ancestry(
        &self,
        accepted: &str,
        tip: &str,
        object_state: ObjectState,
    ) -> Ancestry {
        if object_state != ObjectState::Valid {
            return Ancestry::NotEvaluated;
        }
        match self.ancestry(accepted, tip).await {
            Ok(ancestry) => ancestry,
            Err(error) => {
                warn!(%error, "watcher ancestry probe failed");
                Ancestry::Unknown
            }
        }
    }

    /// Records one failed evaluation of a commit: counts the attempt, schedules the retry of a
    /// local failure and logs the refusal line.
    fn record_refusal(
        state: &mut WatchState,
        commit: &str,
        reason: TransitionReason,
        failure: Failure,
        now: Instant,
    ) -> Refusal {
        let attempts = state
            .entries
            .get(commit)
            .map_or(1, |entry| entry.attempts.saturating_add(1));
        let entry = Refusal {
            reason,
            failure,
            attempts,
            ended: now,
            retry_at: failure
                .class
                .is_retryable()
                .then(|| now + retry_delay(attempts)),
        };
        let detail = entry.report(now);
        if failure.class == FailureClass::Candidate {
            info!(
                commit = %commit,
                reason = ?entry.reason,
                failure = failure.code,
                class = failure.class.code(),
                attempts,
                retry_in_seconds = ?detail.retry_in_seconds,
                "watcher refused candidate"
            );
        } else {
            warn!(
                commit = %commit,
                reason = ?entry.reason,
                failure = failure.code,
                class = failure.class.code(),
                attempts,
                retry_in_seconds = ?detail.retry_in_seconds,
                "watcher refused candidate"
            );
        }
        state.entries.insert(commit.to_owned(), entry);
        entry
    }

    /// Applies one evaluated candidate through the shared transition policy, recording how a
    /// refusal is handled and publishing the watcher's view for `/status`.
    async fn apply(
        &self,
        accepted: &AcceptedRef,
        candidate: Option<ReloadCandidate>,
        pending: Option<Arc<Snapshot>>,
        failure: Option<Failure>,
    ) -> PollReport {
        let outcome = evaluate_reload(accepted, candidate.as_ref(), &self.repository)
            .expect("watcher candidates are internally consistent");
        let now = (self.clock)();
        let mut refusal = None;
        match outcome.decision() {
            TransitionDecision::AcceptForward => {
                let commit = outcome
                    .active_commit()
                    .expect("accept decision carries an active commit");
                let record = self
                    .build_record(commit)
                    .expect("accepted fields are already validated");
                *self.accepted.write().await = Some(record);
                self.shared
                    .install_snapshot(pending.expect("accept decision carries a pending snapshot"))
                    .await;
                let mut state = self.state.lock().await;
                state.entries.retain(|_, entry| entry.retry_at.is_none());
                if let Some((_, entry)) = &mut state.last_refusal {
                    entry.retry_at = None;
                }
            }
            TransitionDecision::RetainAccepted => {
                if let Some(candidate) = candidate {
                    let mut state = self.state.lock().await;
                    let stored = if candidate.suppressed {
                        state.entries.get(&candidate.commit).copied()
                    } else {
                        None
                    };
                    if candidate.suppressed && stored.is_none() {
                        // A concurrent poll dropped this retry entry after the skip was
                        // observed. Evaluate the commit normally instead of reporting a stale
                        // skip; `reload` observes the tip again and will not skip it a second
                        // time unless another poll refused it meanwhile.
                        drop(state);
                        return Box::pin(self.reload(accepted)).await;
                    }
                    let entry = stored.unwrap_or_else(|| {
                        Self::record_refusal(
                            &mut state,
                            &candidate.commit,
                            outcome.reason(),
                            failure.unwrap_or_else(Failure::internal),
                            now,
                        )
                    });
                    refusal = Some(entry.report(now));
                    state.last_refusal = Some((candidate.commit, entry));
                }
            }
            _ => {}
        }
        PollReport {
            decision: outcome.decision(),
            reason: outcome.reason(),
            refusal,
        }
    }

    /// Publishes the accepted commit, the observed tip, the last poll and the last refusal for
    /// the admin listener, which renders the seconds with this watcher's clock.
    async fn publish_view(&self) {
        let accepted_commit = self
            .accepted
            .read()
            .await
            .as_ref()
            .map(|record| record.accepted_commit().to_owned())
            .unwrap_or_default();
        let state = self.state.lock().await;
        self.shared
            .install_watcher_view(WatcherView {
                clock: Arc::clone(&self.clock),
                accepted_commit,
                tip: state.tip.clone(),
                last_poll: state.last_poll,
                last_refusal: state.last_refusal.clone(),
            })
            .await;
    }

    fn rejected_candidate(&self, commit: &str) -> ReloadCandidate {
        ReloadCandidate {
            ancestry: Ancestry::NotEvaluated,
            commit: commit.to_owned(),
            full_ref: self.repository.full_ref().to_owned(),
            object_state: ObjectState::Missing,
            persistence: Persistence::NotAttempted,
            repository_identity: self.repository.repository_identity().to_owned(),
            semantic_validity: SemanticValidity::NotEvaluated,
            suppressed: true,
        }
    }

    fn build_record(&self, commit: &str) -> Result<AcceptedRef> {
        AcceptedRef::new(
            commit,
            self.repository.full_ref(),
            self.repository.repository_identity(),
        )
        .with_context(|| format!("build accepted-ref record for {commit}"))
    }

    fn accepted_record_path(&self) -> PathBuf {
        self.state_path.join(ACCEPTED_RECORD_FILE)
    }

    fn repository_dir(&self) -> PathBuf {
        self.state_path.join(REPOSITORY_DIR)
    }

    fn temp_root(&self) -> PathBuf {
        self.state_path.join(TEMP_DIR)
    }

    fn next_temp(&self, label: &str) -> PathBuf {
        self.temp_root().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            self.temp_counter.fetch_add(1, Ordering::Relaxed)
        ))
    }

    async fn prepare_state(&self) -> Result<()> {
        for directory in [self.state_path.as_path(), self.temp_root().as_path()] {
            tokio::fs::create_dir_all(directory)
                .await
                .with_context(|| format!("create watcher state {}", directory.display()))?;
        }
        Ok(())
    }

    async fn prepare_repository(&self) -> Result<()> {
        let repository = self.repository_dir();
        if repository.join("HEAD").exists() {
            return Ok(());
        }
        git_stdout(
            None,
            [
                OsStr::new("init"),
                OsStr::new("--bare"),
                OsStr::new("--quiet"),
                repository.as_os_str(),
            ],
            "initialize watcher mirror",
        )
        .await?;
        Ok(())
    }

    fn load_startup_record(&self) -> Result<(AcceptedRecordState, Option<AcceptedRef>)> {
        let path = self.accepted_record_path();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((AcceptedRecordState::Absent, None));
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read accepted-ref record {}", path.display()));
            }
        };
        match parse_startup_record(&bytes) {
            Ok(record) => Ok((AcceptedRecordState::Present, Some(record))),
            Err(error) => {
                warn!(%error, "watcher accepted-ref record is malformed");
                Ok((AcceptedRecordState::Malformed, None))
            }
        }
    }

    fn persist_record(&self, record: &AcceptedRef) -> Result<()> {
        let bytes = canonical_accepted_ref_bytes(record, &self.repository)
            .context(RecordEncodingError)
            .context("serialize accepted-ref record")?;
        let target = self.accepted_record_path();
        let temporary = self.state_path.join(format!(
            "{ACCEPTED_RECORD_FILE}.tmp-{}-{}",
            std::process::id(),
            self.temp_counter.fetch_add(1, Ordering::Relaxed)
        ));
        let result = publish_record(&bytes, &temporary, &target, &self.state_path);
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    async fn object_state(&self, commit: &str) -> Result<ObjectState> {
        let exists = git_exit(
            Some(&self.repository_dir()),
            ["cat-file", "-e", commit],
            "probe object existence",
        )
        .await?;
        if !exists.success() {
            return Ok(ObjectState::Missing);
        }
        match git_stdout(
            Some(&self.repository_dir()),
            ["cat-file", "-t", commit],
            "probe object type",
        )
        .await
        {
            Ok(kind) if kind == "commit" => Ok(ObjectState::Valid),
            Ok(kind) => {
                debug!(%kind, "watcher object is not a commit");
                Ok(ObjectState::Malformed)
            }
            Err(_) => Ok(ObjectState::Corrupt),
        }
    }

    async fn remote_tip(&self) -> Result<Option<String>> {
        let output = git_stdout(
            None,
            ["ls-remote", &self.origin, self.repository.full_ref()],
            "observe remote tip",
        )
        .await?;
        let Some(line) = output.lines().next() else {
            return Ok(None);
        };
        let token = line
            .split_whitespace()
            .next()
            .with_context(|| format!("ls-remote output {output:?} has no object name"))?;
        ensure!(
            valid_commit_name(token),
            "ls-remote returned a non-commit object name {token:?}"
        );
        Ok(Some(token.to_owned()))
    }

    async fn fetch(&self) -> Result<()> {
        let reference = format!("+{}:{WATCH_REF}", self.repository.full_ref());
        git_stdout(
            Some(&self.repository_dir()),
            ["fetch", "--no-tags", "--force", &self.origin, &reference],
            "fetch watched ref",
        )
        .await?;
        Ok(())
    }

    async fn watch_ref_commit(&self) -> Result<String> {
        let revision = format!("{WATCH_REF}^{{commit}}");
        git_stdout(
            Some(&self.repository_dir()),
            ["rev-parse", "--verify", &revision],
            "resolve watched ref",
        )
        .await
    }

    async fn ancestry(&self, accepted: &str, candidate: &str) -> Result<Ancestry> {
        let forward = git_exit(
            Some(&self.repository_dir()),
            ["merge-base", "--is-ancestor", accepted, candidate],
            "probe accepted ancestry",
        )
        .await?;
        let backward = git_exit(
            Some(&self.repository_dir()),
            ["merge-base", "--is-ancestor", candidate, accepted],
            "probe candidate ancestry",
        )
        .await?;
        Ok(match (forward.success(), backward.success()) {
            (true, _) => Ancestry::Descendant,
            (_, true) => Ancestry::Predecessor,
            (false, false) if forward.code() == Some(1) && backward.code() == Some(1) => {
                Ancestry::Divergent
            }
            _ => Ancestry::Unknown,
        })
    }

    /// Refuses a commit whose tree holds `.gitattributes` at any path.
    ///
    /// `git archive` applies the archived commit's own attribute files, unlike a
    /// plain checkout: `export-ignore` drops paths, `export-subst` rewrites
    /// placeholders, and `text`, `eol` and `ident` change content. A catalog
    /// repository's CI validates a checkout, so the origin refuses a commit the
    /// checkout cannot vouch for instead of serving a different tree.
    async fn refuse_git_attributes(&self, commit: &str) -> Result<()> {
        let output = git_output(
            Some(&self.repository_dir()),
            ["ls-tree", "-r", "-z", "--name-only", commit],
            "list commit tree",
        )
        .await?;
        ensure!(
            output.status.success(),
            "git list commit tree exited with {}\nstderr:\n{}",
            output.status,
            bounded_lossy(&output.stderr)
        );
        for path in output.stdout.split(|byte| *byte == 0) {
            let name = path.rsplit(|byte| *byte == b'/').next().unwrap_or(path);
            if name == b".gitattributes" {
                return Err(anyhow::Error::new(GitAttributesPresent).context(format!(
                    "catalog commit {commit} holds .gitattributes at {}; git archive would apply it to the catalog tree, so a catalog repository must hold none",
                    String::from_utf8_lossy(path)
                )));
            }
        }
        Ok(())
    }

    async fn materialize_tree(&self, commit: &str, label: &str) -> Result<TempTree> {
        self.refuse_git_attributes(commit).await?;
        let directory = TempDirectory::create(self.next_temp(label)).await?;
        let archive = directory.path().join("catalog.tar");
        git_stdout(
            Some(&self.repository_dir()),
            [
                "archive",
                "--format=tar",
                &format!("--output={}", archive.display()),
                commit,
                "--",
                &self.catalog_path,
            ],
            "archive catalog tree",
        )
        .await?;
        let tree = directory.path().join("tree");
        tokio::fs::create_dir_all(&tree)
            .await
            .with_context(|| format!("create extraction root {}", tree.display()))?;
        let mut extraction = Command::new("tar");
        extraction.kill_on_drop(true);
        extraction
            .args(["--extract", "--file"])
            .arg(&archive)
            .arg("--directory")
            .arg(&tree);
        let output = tokio::time::timeout(GIT_TIMEOUT, extraction.output())
            .await
            .context("catalog archive extraction timed out")?
            .context("start tar extraction")?;
        ensure!(
            output.status.success(),
            "extract catalog archive: {}\nstderr:\n{}",
            output.status,
            bounded_lossy(&output.stderr)
        );
        let root = tree.join(&self.catalog_path);
        ensure!(
            root.is_dir(),
            "materialized catalog {} is missing",
            root.display()
        );
        Ok(TempTree {
            root,
            _directory: directory,
        })
    }

    async fn build_snapshot_from(&self, root: &Path) -> Result<Snapshot> {
        let delivery = self.delivery;
        let archive_store = self.archive_store.clone();
        let first_party_origin = self.first_party_origin.clone();
        let root = root.to_owned();
        let display = root.display().to_string();
        tokio::task::spawn_blocking(move || {
            build_snapshot(
                &root,
                delivery,
                archive_store.as_deref(),
                first_party_origin.as_ref(),
                ProjectionLimits::default(),
            )
        })
        .await
        .context("snapshot build task")?
        .with_context(|| format!("build serving snapshot from {display}"))
    }

    async fn initial_snapshot(&self, commit: &str) -> Result<Arc<Snapshot>> {
        let tree = self
            .materialize_tree(commit, "startup")
            .await
            .with_context(|| format!("materialize startup catalog for {commit}"))?;
        let mut snapshot = self.build_snapshot_from(tree.root()).await?;
        commit.clone_into(&mut snapshot.source_commit);
        Ok(Arc::new(snapshot))
    }

    /// Probes the entry at the normalized catalog path of one commit.
    ///
    /// `git ls-tree` answers no entry for an absent path, expands no wildcard and fails only
    /// when Git fails, so it tells "the commit has no catalog path" from "Git failed".
    async fn catalog_entry(&self, commit: &str) -> Result<CatalogEntry> {
        let path = normalized_catalog_path(&self.catalog_path);
        let output = git_output(
            Some(&self.repository_dir()),
            ["ls-tree", "-z", commit, "--", path.as_str()],
            "probe catalog path",
        )
        .await?;
        ensure!(
            output.status.success(),
            "git probe catalog path exited with {}\nstderr:\n{}",
            output.status,
            bounded_lossy(&output.stderr)
        );
        for entry in output.stdout.split(|byte| *byte == 0) {
            let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
                continue;
            };
            if &entry[tab + 1..] == path.as_bytes() {
                return Ok(if entry.starts_with(b"040000 tree ") {
                    CatalogEntry::Tree
                } else {
                    CatalogEntry::NotTree
                });
            }
        }
        Ok(CatalogEntry::Missing)
    }

    /// Materializes both trees, probes the candidate's catalog path and runs the transition.
    ///
    /// Returns the validity, the candidate snapshot when valid, and the classified failure
    /// whenever the validity is invalid.
    async fn semantic_validation(
        &self,
        accepted_commit: &str,
        candidate_commit: &str,
    ) -> (SemanticValidity, Option<Arc<Snapshot>>, Option<Failure>) {
        let accepted_tree = match self.materialize_tree(accepted_commit, "accepted").await {
            Ok(tree) => tree,
            Err(error) => {
                warn!(%error, "watcher accepted-tree materialization failed");
                return invalid(Some(materialization_failure(
                    true,
                    accepted_materialization(&error),
                )));
            }
        };
        let entry = match self.catalog_entry(candidate_commit).await {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, "watcher catalog path probe failed");
                return invalid(Some(materialization_failure(
                    false,
                    Materialization::Unprobed,
                )));
            }
        };
        if entry == CatalogEntry::Missing {
            return invalid(Some(materialization_failure(
                false,
                Materialization::MissingEntry,
            )));
        }
        let candidate_tree = match self.materialize_tree(candidate_commit, "candidate").await {
            Ok(tree) => tree,
            Err(error) => {
                warn!(%error, "watcher candidate-tree materialization failed");
                return invalid(Some(materialization_failure(
                    false,
                    candidate_materialization(entry, &error),
                )));
            }
        };
        let accepted_root = accepted_tree.root().to_owned();
        let candidate_root = candidate_tree.root().to_owned();
        let transition =
            tokio::task::spawn_blocking(move || check_transition(&accepted_root, &candidate_root))
                .await;
        match transition {
            Ok(Ok(())) => match self.build_snapshot_from(candidate_tree.root()).await {
                Ok(mut snapshot) => {
                    candidate_commit.clone_into(&mut snapshot.source_commit);
                    (SemanticValidity::Valid, Some(Arc::new(snapshot)), None)
                }
                Err(error) => {
                    warn!(%error, "watcher candidate snapshot build failed");
                    invalid(Some(snapshot_failure(&error)))
                }
            },
            Ok(Err(reason)) => {
                info!(%reason, "watcher rejected candidate transition");
                invalid(Some(transition_failure(&reason)))
            }
            Err(error) => {
                warn!(%error, "watcher transition check failed");
                invalid(Some(Failure::internal()))
            }
        }
    }
}

/// Writes, fsyncs, atomically renames, and directory-fsyncs one accepted-ref record.
fn publish_record(bytes: &[u8], temporary: &Path, target: &Path, directory: &Path) -> Result<()> {
    let mut file = std::fs::File::create(temporary)
        .with_context(|| format!("create accepted-ref record {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write accepted-ref record {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync accepted-ref record {}", temporary.display()))?;
    drop(file);
    std::fs::rename(temporary, target)
        .with_context(|| format!("publish accepted-ref record {}", target.display()))?;
    std::fs::File::open(directory)
        .and_then(|handle| handle.sync_all())
        .with_context(|| format!("fsync accepted-ref state {}", directory.display()))
}

/// One temporary directory removed on drop.
struct TempDirectory(PathBuf);

impl TempDirectory {
    async fn create(path: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&path)
            .await
            .with_context(|| format!("create watcher temporary directory {}", path.display()))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One materialized catalog tree rooted inside a temporary directory.
struct TempTree {
    root: PathBuf,
    _directory: TempDirectory,
}

impl TempTree {
    fn root(&self) -> &Path {
        &self.root
    }
}

fn valid_commit_name(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_startup_record(bytes: &[u8]) -> Result<AcceptedRef> {
    let record: AcceptedRef = serde_json::from_slice(bytes).context("parse accepted-ref record")?;
    let revalidated = AcceptedRef::new(
        record.accepted_commit(),
        record.full_ref(),
        record.repository_identity(),
    )
    .context("validate accepted-ref record")?;
    let mut canonical =
        serde_json::to_vec_pretty(&revalidated).context("serialize accepted-ref record")?;
    canonical.push(b'\n');
    ensure!(
        canonical == bytes,
        "accepted-ref record is not canonical JSON"
    );
    Ok(revalidated)
}

fn watcher_git_command<I, S>(current_dir: Option<&Path>, arguments: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // The watcher origin is trusted operator configuration (it may be a local
    // path for LAN-public instances), unlike catalog-declared package sources,
    // so the file protocol is allowed for the mirror fetch.
    let mut command = Command::new("git");
    command
        .kill_on_drop(true)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_ASKPASS")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY");
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command
}

async fn git_output<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    action: &str,
) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = watcher_git_command(current_dir, arguments);
    tokio::time::timeout(GIT_TIMEOUT, command.output())
        .await
        .with_context(|| format!("git {action} timed out after {}s", GIT_TIMEOUT.as_secs()))?
        .with_context(|| format!("git {action} failed to start"))
}

async fn git_stdout<I, S>(current_dir: Option<&Path>, arguments: I, action: &str) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = git_output(current_dir, arguments, action).await?;
    if !output.status.success() {
        bail!(
            "git {action} exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            bounded_lossy(&output.stdout),
            bounded_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("git {action} produced non-UTF-8 stdout"))
        .map(|text| text.trim().to_owned())
}

async fn git_exit<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    action: &str,
) -> Result<ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Ok(git_output(current_dir, arguments, action).await?.status)
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Seek, SeekFrom};
    use std::sync::atomic::AtomicU64 as StdAtomicU64;
    use std::sync::atomic::Ordering as AtomicOrdering;

    use crate::config::{CatalogSource, Config};
    use pkgre_rust::accepted_ref::derive_repository_identity;
    use pkgre_rust::artifact::sha256_bytes;
    use pkgre_rust::http_response::{PreparedRoute, evaluate_request};

    use super::*;

    const FIXTURE_SHA256: &str = "d5d2ce2cf86fafcb52400677c6f020ce096132deb45a24d5535e98149b0baacc";
    const FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/rust-current-catalog-d778238.tar.gz");
    const GIT_IDENTITY: [&str; 4] = [
        "-c",
        "user.email=pkgre@example.invalid",
        "-c",
        "user.name=pkgre",
    ];

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: StdAtomicU64 = StdAtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, AtomicOrdering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(dir: &Path, arguments: &[&str]) {
        let status = std::process::Command::new("git")
            .args(arguments)
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?} failed");
    }

    fn rev_parse(dir: &Path, revision: &str) -> String {
        let output = std::process::Command::new("git")
            .args(["rev-parse", revision])
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success(), "git rev-parse {revision} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// One tiny Git origin carrying the frozen fixture catalog on `refs/heads/main`.
    struct Origin {
        directory: TempDir,
        root: String,
    }

    impl Origin {
        fn new(label: &str) -> Self {
            assert_eq!(sha256_bytes(FIXTURE), FIXTURE_SHA256);
            let directory = TempDir::new(label);
            let origin = directory.path().join("origin");
            std::fs::create_dir(&origin).unwrap();
            git(&origin, &["init", "--quiet", "--initial-branch=main"]);
            let archive = directory.path().join("catalog.tar.gz");
            std::fs::write(&archive, FIXTURE).unwrap();
            let status = std::process::Command::new("tar")
                .args(["--extract", "--gzip", "--file"])
                .arg(&archive)
                .arg("--directory")
                .arg(&origin)
                .status()
                .unwrap();
            assert!(status.success());
            git(&origin, &["add", "."]);
            git(
                &origin,
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "bootstrap catalog"],
                ]
                .concat(),
            );
            Self {
                root: rev_parse(&origin, "HEAD"),
                directory,
            }
        }

        fn path(&self) -> PathBuf {
            self.directory.path().join("origin")
        }

        fn identity(&self) -> String {
            derive_repository_identity(self.path().to_string_lossy().as_bytes(), b"refs/heads/main")
                .unwrap()
        }

        fn advance_empty(&self, message: &str) -> String {
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "--allow-empty", "-m", message],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        fn advance_removing_main_lock(&self) -> String {
            git(&self.path(), &["rm", "--quiet", "registry/main.lock"]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "drop main.lock"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Deletes the whole catalog path, so the commit holds no entry there.
        fn advance_removing_catalog(&self) -> String {
            git(&self.path(), &["rm", "--quiet", "-r", "registry"]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "drop the catalog path"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Changes the serving audience in both the declaration and the generated lock.
        fn advance_changing_audience(&self) -> String {
            for name in ["registry/main.toml", "registry/main.lock"] {
                let path = self.path().join(name);
                let text = std::fs::read_to_string(&path).unwrap();
                let edited = text.replace("audience = \"public\"", "audience = \"lan-public\"");
                assert_ne!(edited, text, "fixture {name} declares the public audience");
                std::fs::write(&path, edited).unwrap();
            }
            git(&self.path(), &["add", "."]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "change the audience"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Replaces the catalog path with a regular file, so the commit holds a blob there.
        fn advance_replacing_catalog_with_a_blob(&self) -> String {
            git(&self.path(), &["rm", "--quiet", "-r", "registry"]);
            std::fs::write(self.path().join("registry"), b"not a catalog\n").unwrap();
            git(&self.path(), &["add", "registry"]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &[
                        "commit",
                        "--quiet",
                        "-m",
                        "replace the catalog path with a file",
                    ],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Replaces the catalog path with a symbolic link to the extraction root, so the commit
        /// holds a link there that materializes and that the loader refuses.
        #[cfg(unix)]
        fn advance_replacing_catalog_with_a_link(&self) -> String {
            git(&self.path(), &["rm", "--quiet", "-r", "registry"]);
            std::os::unix::fs::symlink(".", self.path().join("registry")).unwrap();
            git(&self.path(), &["add", "registry"]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &[
                        "commit",
                        "--quiet",
                        "-m",
                        "replace the catalog path with a link",
                    ],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Removes one mirrored version from the fixture catalog the way `lock` does: the
        /// declaration drops the version and the generated lock records the tombstone.
        fn advance_removing_sse_stream(&self) -> String {
            let human = self.path().join("registry/main.toml");
            let declared = std::fs::read_to_string(&human).unwrap();
            let edited = declared.replace(
                "sse-stream = [\"0.2.1\", \"0.2.5\"]",
                "sse-stream = [\"0.2.1\"]",
            );
            assert_ne!(edited, declared, "fixture declares sse-stream 0.2.5");
            std::fs::write(&human, edited).unwrap();
            let lock = self.path().join("registry/main.lock");
            let text = std::fs::read_to_string(&lock).unwrap();
            let active =
                "[[packages]]\nname = \"sse-stream\"\nversion = \"0.2.5\"\nstate = \"active\"";
            assert!(text.contains(active), "fixture locks sse-stream 0.2.5");
            std::fs::write(
                &lock,
                text.replacen(active, &active.replace("active", "removed"), 1),
            )
            .unwrap();
            git(&self.path(), &["add", "."]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "remove sse-stream 0.2.5"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        fn advance_restoring_main_lock(&self) -> String {
            git(
                &self.path(),
                &[
                    "checkout",
                    "--quiet",
                    &self.root,
                    "--",
                    "registry/main.lock",
                ],
            );
            git(&self.path(), &["add", "registry/main.lock"]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "restore main.lock"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Adds a `.gitattributes` at `path` whose one rule `git archive` ignores, so
        /// only the watcher's rule against the file itself can refuse the commit.
        fn advance_adding_gitattributes(&self, path: &str) -> String {
            let path = self.path().join(path);
            assert!(
                !path.exists(),
                "fixture origin already holds {}",
                path.display()
            );
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "registry/main.lock -diff\n").unwrap();
            git(&self.path(), &["add", "."]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "add .gitattributes"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        /// Removes the `.gitattributes` at `path` again, restoring the bootstrap tree.
        fn advance_removing_gitattributes(&self, path: &str) -> String {
            git(&self.path(), &["rm", "--quiet", path]);
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "-m", "drop .gitattributes"],
                ]
                .concat(),
            );
            rev_parse(&self.path(), "HEAD")
        }

        fn move_remote(&self, commit: &str) {
            git(&self.path(), &["update-ref", "refs/heads/main", commit]);
        }

        fn divergent_tip(&self) -> String {
            git(
                &self.path(),
                &["checkout", "--quiet", "-b", "pkgre-side", &self.root],
            );
            git(
                &self.path(),
                &[
                    GIT_IDENTITY.as_slice(),
                    &["commit", "--quiet", "--allow-empty", "-m", "divergent"],
                ]
                .concat(),
            );
            let tip = rev_parse(&self.path(), "HEAD");
            git(&self.path(), &["checkout", "--quiet", "main"]);
            self.move_remote(&tip);
            tip
        }
    }

    fn watcher_config(directory: &TempDir, origin: &Origin, bootstrap: &str) -> Config {
        watcher_config_with_path(directory, origin, bootstrap, "registry")
    }

    fn watcher_config_with_path(
        directory: &TempDir,
        origin: &Origin,
        bootstrap: &str,
        catalog_path: &str,
    ) -> Config {
        let text = format!(
            r#"
schema = 1

[public]
bind = "127.0.0.1:30100"

[admin]
bind = "127.0.0.1:30101"

[registry]
delivery = "redirect"
first-party-origin = "https://rust.pkg.re"

[limits]
max-concurrency = 8

[watcher]
origin = "{}"
full-ref = "refs/heads/main"
catalog-path = "{catalog_path}"
bootstrap-commit = "{bootstrap}"
state-path = "{}"
poll-interval-secs = 1
"#,
            origin.path().display(),
            directory.path().join("state").display(),
        );
        let path = directory.path().join("serve.toml");
        std::fs::write(&path, text).unwrap();
        Config::from_file(&path).unwrap()
    }

    fn shared_for(config: &Config) -> Arc<web::Shared> {
        Arc::new(web::Shared::new(config.delivery, config.max_concurrency))
    }

    fn watcher_for(config: &Config, shared: &Arc<web::Shared>) -> Arc<Watcher> {
        watcher_for_clock(config, shared, Arc::new(Instant::now))
    }

    fn watcher_for_clock(config: &Config, shared: &Arc<web::Shared>, clock: Clock) -> Arc<Watcher> {
        let CatalogSource::Watcher(watcher_config) = &config.source else {
            panic!("watcher test configuration must select the watcher");
        };
        Arc::new(Watcher::new(
            watcher_config,
            config.delivery,
            config.archive_store.clone(),
            config.first_party_origin.clone(),
            Arc::clone(shared),
            clock,
        ))
    }

    /// Manual monotonic clock the test advances explicitly.
    #[derive(Clone)]
    struct ManualClock(Arc<std::sync::Mutex<Instant>>);

    impl ManualClock {
        fn new() -> Self {
            Self(Arc::new(std::sync::Mutex::new(Instant::now())))
        }

        fn clock(&self) -> Clock {
            let inner = Arc::clone(&self.0);
            Arc::new(move || *inner.lock().unwrap())
        }

        fn advance(&self, duration: Duration) {
            *self.0.lock().unwrap() += duration;
        }
    }

    /// Replaces the watcher's temporary directory with a regular file.
    fn break_temp_directory(directory: &TempDir) {
        let temp = directory.path().join("state").join(TEMP_DIR);
        std::fs::remove_dir_all(&temp).unwrap();
        std::fs::write(&temp, b"blocked").unwrap();
    }

    fn repair_temp_directory(directory: &TempDir) {
        let temp = directory.path().join("state").join(TEMP_DIR);
        std::fs::remove_file(&temp).unwrap();
        std::fs::create_dir(&temp).unwrap();
    }

    /// Reads `/status` from the admin application sharing this watcher's state.
    async fn status_json(shared: &Arc<web::Shared>) -> serde_json::Value {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/status")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = web::admin_application(Arc::clone(shared))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Renders one failure as its code and class for assertions.
    fn failure_of(failure: Option<Failure>) -> (&'static str, FailureClass) {
        let failure = failure.expect("expected a classified failure");
        (failure.code, failure.class)
    }

    fn record_path(directory: &TempDir) -> PathBuf {
        directory.path().join("state").join(ACCEPTED_RECORD_FILE)
    }

    fn stored_commit(directory: &TempDir) -> String {
        let bytes = std::fs::read(record_path(directory)).unwrap();
        parse_startup_record(&bytes)
            .unwrap()
            .accepted_commit()
            .to_owned()
    }

    fn write_canonical_record(directory: &TempDir, record: &AcceptedRef) {
        let mut bytes = serde_json::to_vec_pretty(record).unwrap();
        bytes.push(b'\n');
        std::fs::create_dir_all(directory.path().join("state")).unwrap();
        std::fs::write(record_path(directory), bytes).unwrap();
    }

    fn corrupt_loose_object(repository: &Path, commit: &str) {
        // Local-path fetches store large transfers as packs, and Git falls
        // back to a valid packed copy whenever a loose object fails to parse.
        // Rebuild the mirror store with exactly one damaged loose copy of the
        // accepted commit: the exists-but-unreadable object state the
        // transition contract calls Corrupt.
        let content = std::process::Command::new("git")
            .args(["cat-file", "commit", commit])
            .current_dir(repository)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(content.status.success(), "read commit content");
        let object = repository
            .join("objects")
            .join(&commit[..2])
            .join(&commit[2..]);
        std::fs::remove_dir_all(repository.join("objects/pack")).unwrap();
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        let mut writer = std::process::Command::new("git")
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .current_dir(repository)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        writer
            .stdin
            .take()
            .unwrap()
            .write_all(&content.stdout)
            .unwrap();
        let written = writer.wait_with_output().unwrap();
        assert!(written.status.success(), "write loose commit object");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&object, permissions).unwrap();
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&object)
            .unwrap();
        file.seek(SeekFrom::Start(8)).unwrap();
        file.write_all(&[0xff_u8; 8]).unwrap();
    }

    #[tokio::test]
    async fn fresh_install_bootstraps_and_ignores_a_remote_ahead() {
        let directory = TempDir::new("pkgre-watch-bootstrap");
        let origin = Origin::new("pkgre-watch-bootstrap-origin");
        let ahead = origin.advance_empty("remote ahead of bootstrap");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(shared.is_ready().await);
        assert!(directory.path().join("state/repository/HEAD").exists());
        // Startup adopted the configured bootstrap commit, never the ahead
        // remote tip; the next poll then evaluates the remote normally and
        // accepts the same-tree descendant.
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), ahead);
    }

    #[tokio::test]
    async fn restart_with_remote_unavailable_starts_from_the_accepted_record() {
        let directory = TempDir::new("pkgre-watch-restart");
        let origin = Origin::new("pkgre-watch-restart-origin");
        origin.advance_empty("forward");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        assert_eq!(stored_commit(&directory), origin.root);
        let hidden = directory.path().join("origin-hidden");
        std::fs::rename(origin.path(), &hidden).unwrap();
        let restarted_shared = shared_for(&config);
        let restarted = watcher_for(&config, &restarted_shared);
        restarted.startup().await.unwrap();
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(restarted_shared.is_ready().await);
    }

    #[tokio::test]
    async fn malformed_record_forbids_bootstrap() {
        let directory = TempDir::new("pkgre-watch-malformed");
        let origin = Origin::new("pkgre-watch-malformed-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        std::fs::create_dir_all(directory.path().join("state")).unwrap();
        std::fs::write(record_path(&directory), b"{ not json").unwrap();
        let watcher = watcher_for(&config, &shared);
        let error = watcher.startup().await.unwrap_err();
        assert!(
            format!("{error:#}").contains("AcceptedRecordMalformed"),
            "got: {error:#}"
        );
        assert!(!shared.is_ready().await);
        assert_eq!(
            std::fs::read(record_path(&directory)).unwrap(),
            b"{ not json"
        );
    }

    #[tokio::test]
    async fn identity_mismatch_forbids_bootstrap() {
        let directory = TempDir::new("pkgre-watch-identity");
        let origin = Origin::new("pkgre-watch-identity-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let foreign = AcceptedRef::new(&origin.root, "refs/heads/main", "a".repeat(64)).unwrap();
        write_canonical_record(&directory, &foreign);
        let watcher = watcher_for(&config, &shared);
        let error = watcher.startup().await.unwrap_err();
        assert!(
            format!("{error:#}").contains("RepositoryIdentityMismatch"),
            "got: {error:#}"
        );
        assert!(!shared.is_ready().await);
    }

    #[tokio::test]
    async fn full_ref_mismatch_forbids_bootstrap() {
        let directory = TempDir::new("pkgre-watch-fullref");
        let origin = Origin::new("pkgre-watch-fullref-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let foreign =
            AcceptedRef::new(&origin.root, "refs/heads/release", origin.identity()).unwrap();
        write_canonical_record(&directory, &foreign);
        let watcher = watcher_for(&config, &shared);
        let error = watcher.startup().await.unwrap_err();
        assert!(
            format!("{error:#}").contains("FullRefMismatch"),
            "got: {error:#}"
        );
        assert!(!shared.is_ready().await);
    }

    #[tokio::test]
    async fn missing_accepted_object_fails_startup_without_a_fetch() {
        let directory = TempDir::new("pkgre-watch-accepted-missing");
        let origin = Origin::new("pkgre-watch-accepted-missing-origin");
        origin.advance_empty("forward");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        std::fs::remove_dir_all(directory.path().join("state/repository")).unwrap();
        let restarted = watcher_for(&config, &shared_for(&config));
        let error = restarted.startup().await.unwrap_err();
        assert!(
            format!("{error:#}").contains("AcceptedObjectUnavailable"),
            "got: {error:#}"
        );
        assert!(
            !directory
                .path()
                .join("state/repository/refs/pkgre")
                .exists(),
            "startup with a valid record must not fetch"
        );
    }

    #[tokio::test]
    async fn missing_bootstrap_object_fails_startup() {
        let directory = TempDir::new("pkgre-watch-bootstrap-missing");
        let origin = Origin::new("pkgre-watch-bootstrap-missing-origin");
        let config = watcher_config(&directory, &origin, &"b".repeat(40));
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        let error = watcher.startup().await.unwrap_err();
        assert!(
            format!("{error:#}").contains("BootstrapObjectUnavailable"),
            "got: {error:#}"
        );
        assert!(!shared.is_ready().await);
    }

    /// A bootstrap commit that holds a `.gitattributes` above the catalog path cannot be
    /// materialized as the startup snapshot, and the failure names the path and the reason.
    #[tokio::test]
    async fn bootstrap_commit_holding_gitattributes_fails_startup() {
        let directory = TempDir::new("pkgre-watch-gitattributes-bootstrap");
        let origin = Origin::new("pkgre-watch-gitattributes-bootstrap-origin");
        let bootstrap = origin.advance_adding_gitattributes("tools/.gitattributes");
        let config = watcher_config(&directory, &origin, &bootstrap);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        let error = watcher.startup().await.unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("holds .gitattributes at tools/.gitattributes")
                && message.contains("must hold none"),
            "got: {message}"
        );
        assert!(!shared.is_ready().await);
        assert!(!record_path(&directory).exists());
    }

    #[tokio::test]
    async fn corrupt_accepted_object_fails_startup() {
        let directory = TempDir::new("pkgre-watch-corrupt");
        let origin = Origin::new("pkgre-watch-corrupt-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        corrupt_loose_object(&directory.path().join("state/repository"), &origin.root);
        let restarted = watcher_for(&config, &shared_for(&config));
        let error = restarted.startup().await.unwrap_err();
        assert!(
            format!("{error:#}").contains("AcceptedObjectInvalid"),
            "got: {error:#}"
        );
    }

    #[tokio::test]
    async fn forward_descendant_is_accepted() {
        let directory = TempDir::new("pkgre-watch-forward");
        let origin = Origin::new("pkgre-watch-forward-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        let child = origin.advance_empty("forward");
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), child);
        let after = shared.snapshot().await.unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
    }

    #[tokio::test]
    async fn semantic_failure_retains_then_suppresses() {
        let directory = TempDir::new("pkgre-watch-semantic");
        let origin = Origin::new("pkgre-watch-semantic-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        origin.advance_removing_main_lock();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "candidate-catalog-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.attempts, 1);
        assert_eq!(refusal.retry_in_seconds, None);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        let refusal = report
            .refusal
            .expect("a skipped candidate carries its refusal");
        assert_eq!(refusal.failure, "candidate-catalog-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.attempts, 1);
        assert_eq!(refusal.retry_in_seconds, None);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
    }

    /// A commit that adds only a root `.gitattributes` is refused before `git archive`
    /// reads it and suppressed by hash; the forward descendant that removes it again
    /// carries the accepted tree, so the origin serves it.
    #[tokio::test]
    async fn commit_holding_gitattributes_is_refused_then_suppressed() {
        let directory = TempDir::new("pkgre-watch-gitattributes");
        let origin = Origin::new("pkgre-watch-gitattributes-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();

        let refused = origin.advance_adding_gitattributes(".gitattributes");
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));

        let restored = origin.advance_removing_gitattributes(".gitattributes");
        assert_ne!(restored, refused);
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), restored);
        assert_eq!(shared.snapshot().await.unwrap().source_commit, restored);
    }

    /// A merged removal needs no fresh baseline: the watcher reloads the removal commit and
    /// serves the version as a yanked tombstone while every other route stays byte-identical.
    #[tokio::test]
    async fn removal_commit_is_reloaded_and_served_as_a_tombstone() {
        let directory = TempDir::new("pkgre-watch-removal");
        let origin = Origin::new("pkgre-watch-removal-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();

        let commit = origin.advance_removing_sse_stream();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), commit);
        let after = shared.snapshot().await.unwrap();
        assert_eq!(after.source_commit, commit);

        // The removed version's index row renders as yanked; the kept version stays selectable.
        let index = "/ss/e-/sse-stream";
        let response = evaluate_request(index.as_bytes(), "GET", &[], &after.routes);
        assert_eq!(response.status(), 200);
        let body = std::str::from_utf8(response.body().expect("index body")).unwrap();
        let removed = body
            .lines()
            .find(|line| line.contains("\"vers\":\"0.2.5\""))
            .expect("removed row is retained");
        assert!(
            removed.contains("\"yanked\":true"),
            "removed row must be yanked: {removed}"
        );
        let kept = body
            .lines()
            .find(|line| line.contains("\"vers\":\"0.2.1\""))
            .expect("kept row is retained");
        assert!(
            kept.contains("\"yanked\":false"),
            "kept row must stay active: {kept}"
        );

        // The release manifest records the same state change and nothing else.
        let release = "/release.json";
        let before_release = release_document(&before.routes);
        let after_release = release_document(&after.routes);
        let mut before_rest = before_release.clone();
        let mut after_rest = after_release.clone();
        let before_packages = before_rest["packages"].take();
        let after_packages = after_rest["packages"].take();
        assert_eq!(before_rest, after_rest, "release topology must not change");
        let before_packages = before_packages.as_array().expect("release packages");
        let after_packages = after_packages.as_array().expect("release packages");
        assert_eq!(before_packages.len(), after_packages.len());
        let mut removed_packages = 0;
        for (before_package, after_package) in before_packages.iter().zip(after_packages) {
            if before_package["name"] == "sse-stream" && before_package["version"] == "0.2.5" {
                removed_packages += 1;
                let mut expected = before_package.clone();
                expected["yanked"] = true.into();
                assert_eq!(after_package, &expected, "removed package must be yanked");
            } else {
                assert_eq!(
                    before_package, after_package,
                    "package {} {} must not change",
                    before_package["name"], before_package["version"]
                );
            }
        }
        assert_eq!(removed_packages, 1);

        // The tombstone route stays, and every other route is unchanged.
        let tombstone = "/v1/main/sse-stream/0.2.5/c123f296ade4ec4b8b0f6162116e6629f5146922ca5ab40ca9d3c2e73ab4761e";
        assert_eq!(
            before.routes.get(tombstone),
            after.routes.get(tombstone),
            "the removed version's route must stay unchanged"
        );
        assert_eq!(
            evaluate_request(tombstone.as_bytes(), "GET", &[], &after.routes).status(),
            302
        );
        assert_eq!(before.routes.len(), after.routes.len());
        for (path, route) in &before.routes {
            if path == index || path == release {
                continue;
            }
            assert_eq!(
                after.routes.get(path),
                Some(route),
                "route {path} must not change"
            );
        }
    }

    fn release_document(routes: &BTreeMap<String, PreparedRoute>) -> serde_json::Value {
        let response = evaluate_request(b"/release.json", "GET", &[], routes);
        assert_eq!(response.status(), 200);
        serde_json::from_slice(response.body().expect("release body")).expect("release JSON")
    }

    #[tokio::test]
    async fn predecessor_tip_is_rejected_then_suppressed() {
        let directory = TempDir::new("pkgre-watch-predecessor");
        let origin = Origin::new("pkgre-watch-predecessor-origin");
        let child = origin.advance_empty("forward");
        let config = watcher_config(&directory, &origin, &child);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        assert_eq!(stored_commit(&directory), child);
        origin.move_remote(&origin.root);
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::CandidateNotDescendant);
        assert_eq!(
            report.refusal.expect("a refusal is reported").failure,
            "not-descendant"
        );
        assert_eq!(stored_commit(&directory), child);
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        assert_eq!(
            report
                .refusal
                .expect("a skipped candidate carries its refusal")
                .failure,
            "not-descendant"
        );
    }

    #[tokio::test]
    async fn divergent_tip_is_rejected_then_suppressed() {
        let directory = TempDir::new("pkgre-watch-divergent");
        let origin = Origin::new("pkgre-watch-divergent-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let child = origin.advance_empty("forward");
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        origin.divergent_tip();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::CandidateNotDescendant);
        assert_eq!(
            report.refusal.expect("a refusal is reported").failure,
            "not-descendant"
        );
        assert_eq!(stored_commit(&directory), child);
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
    }

    #[tokio::test]
    async fn remote_outage_does_not_suppress_the_tip() {
        let directory = TempDir::new("pkgre-watch-outage");
        let origin = Origin::new("pkgre-watch-outage-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        let hidden = directory.path().join("origin-hidden");
        std::fs::rename(origin.path(), &hidden).unwrap();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::RemoteUnavailable);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        std::fs::rename(&hidden, origin.path()).unwrap();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::Unchanged);
        assert_eq!(report.reason, TransitionReason::CandidateEqualsAccepted);
    }

    #[tokio::test]
    async fn persistence_failure_is_retried() {
        let directory = TempDir::new("pkgre-watch-persist");
        let origin = Origin::new("pkgre-watch-persist-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        let child = origin.advance_empty("forward");
        let accepted_before = stored_commit(&directory);
        std::fs::remove_file(record_path(&directory)).unwrap();
        std::fs::create_dir(record_path(&directory)).unwrap();

        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::DurablePersistenceFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "persistence-failed");
        assert_eq!(refusal.class, FailureClass::Local);
        assert_eq!(refusal.attempts, 1);
        assert_eq!(refusal.retry_in_seconds, Some(60));
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        assert!(
            record_path(&directory).is_dir(),
            "a refused persistence must not replace the record path"
        );
        assert_eq!(accepted_before, origin.root);
        let leftovers: Vec<String> = std::fs::read_dir(directory.path().join("state"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");

        // Before the due time the tip is skipped without any Git or catalog work.
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        let refusal = report
            .refusal
            .expect("a skipped candidate carries its refusal");
        assert_eq!(refusal.failure, "persistence-failed");
        assert_eq!(refusal.attempts, 1);
        assert_eq!(refusal.retry_in_seconds, Some(60));
        assert!(record_path(&directory).is_dir());
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));

        // At the due time, with the record path repaired, the commit is accepted.
        std::fs::remove_dir(record_path(&directory)).unwrap();
        clock.advance(Duration::from_secs(60));
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert!(report.refusal.is_none());
        assert_eq!(stored_commit(&directory), child);
        assert!(!Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
    }

    #[tokio::test]
    async fn different_candidate_after_rejection_is_accepted() {
        let directory = TempDir::new("pkgre-watch-recovery");
        let origin = Origin::new("pkgre-watch-recovery-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        origin.advance_removing_main_lock();
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let grandchild = origin.advance_restoring_main_lock();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), grandchild);
        let after = shared.snapshot().await.unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
    }

    #[tokio::test]
    async fn concurrent_readers_observe_lkg_snapshots() {
        let directory = TempDir::new("pkgre-watch-lkg");
        let origin = Origin::new("pkgre-watch-lkg-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let initial = shared.snapshot().await.unwrap();
        origin.advance_empty("forward");
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let mut observed = Vec::new();
                    for _ in 0..64 {
                        if let Some(snapshot) = shared.snapshot().await {
                            observed.push(snapshot);
                        }
                        tokio::task::yield_now().await;
                    }
                    observed
                })
            })
            .collect();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        let updated = shared.snapshot().await.unwrap();
        assert!(!Arc::ptr_eq(&initial, &updated));
        origin.divergent_tip();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        let retained = shared.snapshot().await.unwrap();
        assert!(Arc::ptr_eq(&updated, &retained), "failed reload keeps LKG");
        let mut total = 0;
        for reader in readers {
            for snapshot in reader.await.unwrap() {
                total += 1;
                assert!(
                    Arc::ptr_eq(&snapshot, &initial) || Arc::ptr_eq(&snapshot, &updated),
                    "reader observed a foreign snapshot"
                );
            }
        }
        assert!(total > 0);
    }

    /// A failure to materialize the accepted tree is local and retried; the same commit is
    /// accepted at the due time once the host's fault has cleared.
    #[tokio::test]
    async fn accepted_materialization_failure_is_retried() {
        let directory = TempDir::new("pkgre-watch-accepted-temp");
        let origin = Origin::new("pkgre-watch-accepted-temp-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        let child = origin.advance_empty("forward");
        break_temp_directory(&directory);

        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "materialization-failed");
        assert_eq!(refusal.class, FailureClass::Local);
        assert_eq!(refusal.attempts, 1);
        assert_eq!(refusal.retry_in_seconds, Some(60));
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        assert_eq!(stored_commit(&directory), origin.root);

        repair_temp_directory(&directory);
        clock.advance(Duration::from_secs(60));
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), child);
        assert_eq!(shared.snapshot().await.unwrap().source_commit, child);
    }

    #[tokio::test]
    async fn local_failures_follow_the_retry_schedule() {
        let directory = TempDir::new("pkgre-watch-schedule");
        let origin = Origin::new("pkgre-watch-schedule-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        origin.advance_empty("forward");
        break_temp_directory(&directory);

        let mut waited = 0;
        for attempts in 1..=6 {
            clock.advance(Duration::from_secs(waited));
            let report = watcher.poll_once().await;
            let refusal = report
                .refusal
                .expect("a refused candidate carries its refusal");
            assert_eq!(refusal.class, FailureClass::Local);
            assert_eq!(refusal.attempts, attempts);
            let expected = match attempts {
                1 => 60,
                2 => 120,
                3 => 240,
                4 => 480,
                _ => 900,
            };
            assert_eq!(
                refusal.retry_in_seconds,
                Some(expected),
                "attempt {attempts}"
            );
            waited = expected;
        }
        assert_eq!(stored_commit(&directory), origin.root);
    }

    #[tokio::test]
    async fn newer_commit_while_a_retry_waits_is_accepted() {
        use serde_json::json;

        let directory = TempDir::new("pkgre-watch-newer");
        let origin = Origin::new("pkgre-watch-newer-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let waiting = origin.advance_empty("waiting commit");
        break_temp_directory(&directory);
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        assert_eq!(
            report
                .refusal
                .expect("a refused candidate carries its refusal")
                .class,
            FailureClass::Local
        );
        assert_eq!(
            status_json(&shared).await["watcher"]["lastRefusal"]["commit"],
            json!(waiting)
        );

        repair_temp_directory(&directory);
        let newer = origin.advance_empty("newer commit");
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert!(report.refusal.is_none());
        assert_eq!(stored_commit(&directory), newer);
        // The acceptance drops the waiting entry, and the last refusal keeps no retry.
        assert!(
            watcher.state.lock().await.entries.is_empty(),
            "an acceptance must drop every retrying entry"
        );
        let status = status_json(&shared).await;
        assert_eq!(status["watcher"]["lastRefusal"]["commit"], json!(waiting));
        assert_eq!(
            status["watcher"]["lastRefusal"]["retryInSeconds"],
            json!(null)
        );
    }

    #[tokio::test]
    async fn restart_while_a_retry_waits_evaluates_the_tip() {
        let directory = TempDir::new("pkgre-watch-restart-retry");
        let origin = Origin::new("pkgre-watch-restart-retry-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let child = origin.advance_empty("forward");
        break_temp_directory(&directory);
        let report = watcher.poll_once().await;
        assert_eq!(
            report
                .refusal
                .expect("a refused candidate carries its refusal")
                .class,
            FailureClass::Local
        );
        repair_temp_directory(&directory);

        // A restart forgets the retry map, so its first poll evaluates the tip at once.
        let restarted_shared = shared_for(&config);
        let restarted = watcher_for_clock(&config, &restarted_shared, clock.clock());
        restarted.startup().await.unwrap();
        let report = restarted.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(stored_commit(&directory), child);
        assert_eq!(
            restarted_shared.snapshot().await.unwrap().source_commit,
            child
        );
    }

    #[tokio::test]
    async fn a_due_retry_whose_fetch_fails_keeps_its_schedule() {
        let directory = TempDir::new("pkgre-watch-due-fetch");
        let origin = Origin::new("pkgre-watch-due-fetch-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let child = origin.advance_empty("forward");
        break_temp_directory(&directory);
        let report = watcher.poll_once().await;
        assert_eq!(
            report
                .refusal
                .expect("a refused candidate carries its refusal")
                .class,
            FailureClass::Local
        );
        repair_temp_directory(&directory);
        clock.advance(Duration::from_secs(60));
        let due = {
            let state = watcher.state.lock().await;
            let entry = state.entries.get(&child).expect("the tip is retrying");
            (entry.attempts, entry.retry_at)
        };

        // A due poll that cannot fetch leaves the entry, its attempts and its due time alone.
        let repository = directory.path().join("state").join(REPOSITORY_DIR);
        let hidden = directory.path().join("state/repository-hidden");
        std::fs::rename(&repository, &hidden).unwrap();
        std::fs::write(&repository, b"blocked").unwrap();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::RemoteUnavailable);
        assert!(report.refusal.is_none());
        {
            let state = watcher.state.lock().await;
            let entry = state
                .entries
                .get(&child)
                .expect("the tip is still retrying");
            assert_eq!((entry.attempts, entry.retry_at), due);
        }

        std::fs::remove_file(&repository).unwrap();
        std::fs::rename(&hidden, &repository).unwrap();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(stored_commit(&directory), child);
    }

    #[tokio::test]
    async fn a_commit_that_deletes_the_catalog_path_is_refused() {
        let directory = TempDir::new("pkgre-watch-no-catalog");
        let origin = Origin::new("pkgre-watch-no-catalog-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        origin.advance_removing_catalog();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "catalog-path-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.retry_in_seconds, None);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        // Nothing was materialized for the candidate.
        let leftovers = std::fs::read_dir(directory.path().join("state").join(TEMP_DIR))
            .unwrap()
            .count();
        assert_eq!(leftovers, 0, "the refused candidate must leave no tree");
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
    }

    #[tokio::test]
    async fn an_audience_change_is_refused_with_its_code() {
        let directory = TempDir::new("pkgre-watch-audience");
        let origin = Origin::new("pkgre-watch-audience-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        origin.advance_changing_audience();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "registry-topology-changed");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.retry_in_seconds, None);
    }

    #[tokio::test]
    async fn catalog_path_with_a_trailing_slash_accepts_a_forward_commit() {
        let directory = TempDir::new("pkgre-watch-catalog-slash");
        let origin = Origin::new("pkgre-watch-catalog-slash-origin");
        let config = watcher_config_with_path(&directory, &origin, &origin.root, "registry/");
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let child = origin.advance_empty("forward");
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::AcceptForward);
        assert_eq!(report.reason, TransitionReason::ValidForwardCandidate);
        assert_eq!(stored_commit(&directory), child);
    }

    #[tokio::test]
    async fn status_reports_watcher_refusals_with_the_watcher_clock() {
        use serde_json::json;

        let directory = TempDir::new("pkgre-watch-status");
        let origin = Origin::new("pkgre-watch-status-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let child = origin.advance_empty("forward");
        break_temp_directory(&directory);
        watcher.poll_once().await;

        let report = status_json(&shared).await;
        assert_eq!(report["watcher"]["acceptedCommit"], json!(origin.root));
        assert_eq!(report["watcher"]["tip"], json!(child));
        assert_eq!(
            report["watcher"]["lastPoll"],
            json!({
                "decision": "retain-accepted",
                "reason": "semantic-validation-failed",
                "secondsAgo": 0,
            })
        );
        assert_eq!(
            report["watcher"]["lastRefusal"],
            json!({
                "commit": child,
                "reason": "semantic-validation-failed",
                "failure": "materialization-failed",
                "class": "local",
                "attempts": 1,
                "secondsAgo": 0,
                "retryInSeconds": 60,
            })
        );

        // The seconds of both members come from the watcher's own clock.
        clock.advance(Duration::from_secs(20));
        let report = status_json(&shared).await;
        assert_eq!(report["watcher"]["lastPoll"]["secondsAgo"], json!(20));
        assert_eq!(report["watcher"]["lastRefusal"]["secondsAgo"], json!(20));
        assert_eq!(
            report["watcher"]["lastRefusal"]["retryInSeconds"],
            json!(40)
        );

        // A refusal of the candidate's own content has no retry, and a skip keeps it.
        repair_temp_directory(&directory);
        origin.advance_removing_main_lock();
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let status = status_json(&shared).await;
        assert_eq!(
            status["watcher"]["lastRefusal"]["failure"],
            json!("candidate-catalog-invalid")
        );
        assert_eq!(
            status["watcher"]["lastRefusal"]["class"],
            json!("candidate")
        );
        assert_eq!(
            status["watcher"]["lastRefusal"]["retryInSeconds"],
            json!(null)
        );
        let tip = status["watcher"]["tip"].as_str().unwrap().to_owned();
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        let status = status_json(&shared).await;
        assert_eq!(status["watcher"]["lastRefusal"]["commit"], json!(tip));
        assert_eq!(
            status["watcher"]["lastPoll"]["reason"],
            json!("rejected-hash-suppressed")
        );
        assert_eq!(
            status["watcher"]["lastRefusal"]["attempts"],
            json!(1),
            "a skipped poll does not count an attempt"
        );
    }

    #[test]
    fn every_object_and_ancestry_answer_has_a_class() {
        assert_eq!(object_failure(ObjectState::Valid), None);
        assert_eq!(object_failure(ObjectState::NotApplicable), None);
        assert_eq!(
            failure_of(object_failure(ObjectState::Missing)),
            ("object-unavailable", FailureClass::Local)
        );
        assert_eq!(
            failure_of(object_failure(ObjectState::Corrupt)),
            ("object-unreadable", FailureClass::Local)
        );
        assert_eq!(
            failure_of(object_failure(ObjectState::Malformed)),
            ("not-a-commit", FailureClass::Candidate)
        );
        assert_eq!(ancestry_failure(Ancestry::Descendant), None);
        assert_eq!(ancestry_failure(Ancestry::Equal), None);
        assert_eq!(ancestry_failure(Ancestry::NotEvaluated), None);
        assert_eq!(
            failure_of(ancestry_failure(Ancestry::Unknown)),
            ("ancestry-unknown", FailureClass::Local)
        );
        assert_eq!(
            failure_of(ancestry_failure(Ancestry::Predecessor)),
            ("not-descendant", FailureClass::Candidate)
        );
        assert_eq!(
            failure_of(ancestry_failure(Ancestry::Divergent)),
            ("not-descendant", FailureClass::Candidate)
        );
    }

    #[test]
    fn every_materialization_answer_has_a_class_and_code() {
        let failures = [
            Materialization::MissingEntry,
            Materialization::Unprobed,
            Materialization::TreeFailed,
            Materialization::NotTreeFailed,
            Materialization::AttributesPresent,
        ];
        for outcome in failures {
            assert_eq!(
                failure_of(Some(materialization_failure(true, outcome))),
                ("materialization-failed", FailureClass::Local),
                "the accepted side is always local: {outcome:?}"
            );
        }
        assert_eq!(
            failure_of(Some(materialization_failure(
                false,
                Materialization::MissingEntry
            ))),
            ("catalog-path-invalid", FailureClass::Candidate)
        );
        assert_eq!(
            failure_of(Some(materialization_failure(
                false,
                Materialization::NotTreeFailed
            ))),
            ("catalog-path-invalid", FailureClass::Candidate)
        );
        assert_eq!(
            failure_of(Some(materialization_failure(
                false,
                Materialization::Unprobed
            ))),
            ("materialization-failed", FailureClass::Local)
        );
        assert_eq!(
            failure_of(Some(materialization_failure(
                false,
                Materialization::TreeFailed
            ))),
            ("materialization-failed", FailureClass::Local)
        );
        assert_eq!(
            failure_of(Some(materialization_failure(
                false,
                Materialization::AttributesPresent
            ))),
            ("gitattributes-present", FailureClass::Candidate)
        );
    }

    #[test]
    fn catalog_paths_are_normalized_before_the_probe() {
        assert_eq!(normalized_catalog_path("registry"), "registry");
        assert_eq!(normalized_catalog_path("registry/"), "registry");
        assert_eq!(normalized_catalog_path("registry//sub"), "registry/sub");
        assert_eq!(normalized_catalog_path("registry/./sub"), "registry/sub");
    }

    #[test]
    fn snapshot_and_persistence_failures_name_their_class() {
        use std::io::{Error, ErrorKind};

        let io = |kind| anyhow::Error::new(Error::new(kind, "injected")).context("read catalog");
        for kind in [ErrorKind::StorageFull, ErrorKind::PermissionDenied] {
            assert_eq!(
                failure_of(Some(persistence_failure(&io(kind)))),
                ("persistence-failed", FailureClass::Local)
            );
            assert_eq!(
                failure_of(Some(snapshot_failure(&io(kind)))),
                ("catalog-unreadable", FailureClass::Local)
            );
        }
        assert_eq!(
            failure_of(Some(persistence_failure(
                &anyhow::Error::new(RecordEncodingError).context("serialize accepted-ref record")
            ))),
            ("internal-error", FailureClass::Unclassified)
        );
        // The uncategorized EIO is the host's; the six content kinds are the tree's.
        let raw = anyhow::Error::new(Error::from_raw_os_error(5)).context("read catalog");
        assert_eq!(
            failure_of(Some(snapshot_failure(&raw))),
            ("catalog-unreadable", FailureClass::Local)
        );
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::NotADirectory,
            ErrorKind::IsADirectory,
            ErrorKind::InvalidData,
            ErrorKind::InvalidInput,
            ErrorKind::InvalidFilename,
        ] {
            assert_eq!(
                failure_of(Some(snapshot_failure(&io(kind)))),
                ("snapshot-invalid", FailureClass::Candidate),
                "{kind:?} describes the tree's own bytes"
            );
        }
        assert_eq!(
            failure_of(Some(snapshot_failure(&anyhow::anyhow!(
                "catalog is invalid"
            )))),
            ("snapshot-invalid", FailureClass::Candidate)
        );
        let store = anyhow::Error::new(pkgre_rust::serve::ArchiveStoreError)
            .context("read body-mode archive for /v1/main/x/1.0.0/abc");
        assert_eq!(
            failure_of(Some(snapshot_failure(&store))),
            ("archive-store-incomplete", FailureClass::Local)
        );
    }

    #[tokio::test]
    async fn a_panicked_snapshot_task_is_unclassified() {
        let join = tokio::task::spawn_blocking(|| panic!("fixture panic"))
            .await
            .unwrap_err();
        let error = anyhow::Error::new(join).context("snapshot build task");
        assert_eq!(
            failure_of(Some(snapshot_failure(&error))),
            ("internal-error", FailureClass::Unclassified)
        );
    }

    #[test]
    fn every_transition_reason_keeps_its_code_and_class() {
        use pkgre_rust::transition::RejectReason;

        let candidates = [
            (
                RejectReason::InvalidCandidate(String::new()),
                "candidate-catalog-invalid",
            ),
            (
                RejectReason::RegistryTopology(String::new()),
                "registry-topology-changed",
            ),
            (
                RejectReason::MissingIdentity(String::new()),
                "identity-missing",
            ),
            (
                RejectReason::MutatedIdentity(String::new()),
                "identity-mutated",
            ),
            (RejectReason::CategoryMove(String::new()), "category-moved"),
            (
                RejectReason::MissingRetainedBody(String::new()),
                "retained-body-missing",
            ),
            (
                RejectReason::MutatedAdmissionFile(String::new()),
                "admission-file-changed",
            ),
            (
                RejectReason::MissingAdmissionEvidence(String::new()),
                "admission-evidence-missing",
            ),
            (
                RejectReason::AdmissionBatchNotNew(String::new()),
                "admission-batch-not-new",
            ),
            (
                RejectReason::CategoryRuleChanged(String::new()),
                "category-rule-changed",
            ),
            (RejectReason::HomeMoved(String::new()), "home-moved"),
            (RejectReason::MissingHome(String::new()), "home-missing"),
        ];
        for (reason, code) in candidates {
            assert_eq!(transition_failure(&reason).code, code);
            assert_eq!(transition_failure(&reason).class, FailureClass::Candidate);
        }
        let locals = [
            (
                RejectReason::AcceptedUnloadable(String::new()),
                "accepted-catalog-unloadable",
            ),
            (
                RejectReason::CatalogUnreadable(String::new()),
                "catalog-unreadable",
            ),
            (
                RejectReason::AdmissionEvidenceUnreadable(String::new()),
                "admission-evidence-unreadable",
            ),
        ];
        for (reason, code) in locals {
            assert_eq!(transition_failure(&reason).code, code);
            assert_eq!(transition_failure(&reason).class, FailureClass::Local);
        }
    }

    #[test]
    fn retry_delays_double_to_the_cap() {
        let waits = (1..=7)
            .map(|attempts| retry_delay(attempts).as_secs())
            .collect::<Vec<_>>();
        assert_eq!(waits, [60, 120, 240, 480, 900, 900, 900]);
    }

    /// A retry whose next evaluation refuses the commit's own content becomes suppressed for
    /// good, and the following poll reports it without evaluating again.
    #[tokio::test]
    async fn a_retried_commit_refused_for_its_content_is_suppressed_for_good() {
        let directory = TempDir::new("pkgre-watch-retry-content");
        let origin = Origin::new("pkgre-watch-retry-content-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let clock = ManualClock::new();
        let watcher = watcher_for_clock(&config, &shared, clock.clock());
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();

        // The commit's own content is refused, but the first evaluation fails locally before
        // the transition check reads it.
        let refused = origin.advance_removing_main_lock();
        break_temp_directory(&directory);
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "materialization-failed");
        assert_eq!(refusal.class, FailureClass::Local);
        assert_eq!(refusal.attempts, 1);
        assert_eq!(refusal.retry_in_seconds, Some(60));

        // At the due time the content decides: the commit is refused for good.
        repair_temp_directory(&directory);
        clock.advance(Duration::from_secs(60));
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "candidate-catalog-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.attempts, 2);
        assert_eq!(refusal.retry_in_seconds, None);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        assert_eq!(
            watcher
                .state
                .lock()
                .await
                .entries
                .get(&refused)
                .map(|entry| entry.retry_at),
            Some(None)
        );

        // A later poll reports the same suppression without evaluating the commit again.
        clock.advance(Duration::from_secs(3600));
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        let refusal = report
            .refusal
            .expect("a skipped candidate carries its refusal");
        assert_eq!(refusal.failure, "candidate-catalog-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.attempts, 2);
        assert_eq!(refusal.retry_in_seconds, None);
    }

    /// A blob and a symbolic link at the catalog path are probed as non-trees and refused: the
    /// blob is a catalog-path failure and the link materializes into a loader refusal.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_blob_and_a_symbolic_link_at_the_catalog_path_are_refused() {
        let directory = TempDir::new("pkgre-watch-catalog-entries");
        let origin = Origin::new("pkgre-watch-catalog-entries-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        assert_eq!(
            watcher.catalog_entry(&origin.root).await.unwrap(),
            CatalogEntry::Tree,
            "a tree at the catalog path is the one answer that materializes"
        );
        let before = shared.snapshot().await.unwrap();

        let blob = origin.advance_replacing_catalog_with_a_blob();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "catalog-path-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.retry_in_seconds, None);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        // The poll fetched the commit, so the probe reads its entry directly.
        assert_eq!(
            watcher.catalog_entry(&blob).await.unwrap(),
            CatalogEntry::NotTree
        );

        let link = origin.advance_replacing_catalog_with_a_link();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::SemanticValidationFailed);
        let refusal = report
            .refusal
            .expect("a refused candidate carries its refusal");
        assert_eq!(refusal.failure, "candidate-catalog-invalid");
        assert_eq!(refusal.class, FailureClass::Candidate);
        assert_eq!(refusal.retry_in_seconds, None);
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        assert_eq!(
            watcher.catalog_entry(&link).await.unwrap(),
            CatalogEntry::NotTree
        );
    }
}
