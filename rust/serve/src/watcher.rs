//! Accepted-ref watcher: fixed-ref polling with last-known-good serving snapshots.
//!
//! The watcher owns the accepted-ref record on disk, a bare Git mirror of the
//! watched origin, and the shared serving snapshot. Every poll observes the
//! remote tip once and applies the shared transition policy
//! ([`pkgre_rust::accepted_ref`]): only strictly forward, semantically valid,
//! durably persisted candidates are published, and every fresh-tip rejection is
//! suppressed by hash until the tip changes or the process restarts. A failed
//! reload never changes the active snapshot or the accepted ref.
//!
//! Startup authority is the accepted record alone. A record bootstraps only when
//! the record path is absent; any present malformed or mismatched record forbids
//! bootstrap and fails the service. The remote tip is never startup authority.
//!
//! End-to-end tests below cover every rejection reachable through real Git
//! orchestration (remote outages, persistence failure, suppression, ancestry,
//! semantic validation, object corruption). The remaining transition reasons —
//! repository-identity mismatch, full-ref mismatch, malformed commits, unknown
//! ancestry, and candidate object unavailability on reload — are enforced by
//! [`evaluate_reload`] and covered by the shared transition-policy fixture tests
//! in [`pkgre_rust::accepted_ref`]; they are not realizable through a controlled
//! origin because the watcher derives candidate fields from operator
//! configuration and verified Git output only.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use pkgre_rust::accepted_ref::{
    AcceptedRecordState, AcceptedRef, Ancestry, ObjectState, Persistence, ReloadCandidate,
    RepositoryConfig, SemanticValidity, StartupInput, TransitionDecision, TransitionReason,
    canonical_accepted_ref_bytes, evaluate_reload, evaluate_startup,
};
use pkgre_rust::projection::ProjectionLimits;
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
    shared: Arc<web::Shared>,
    accepted: RwLock<Option<AcceptedRef>>,
    suppressed: Mutex<HashSet<String>>,
    temp_counter: AtomicU64,
}

impl Watcher {
    /// Creates the watcher without performing any I/O.
    #[must_use]
    pub fn new(
        config: &WatcherConfig,
        delivery: DeliveryMode,
        archive_store: Option<PathBuf>,
        shared: Arc<web::Shared>,
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
            shared,
            accepted: RwLock::new(None),
            suppressed: Mutex::new(HashSet::new()),
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
        let Some(accepted) = self.accepted.read().await.clone() else {
            error!("watcher poll reached without an accepted record; retaining");
            return PollReport {
                decision: TransitionDecision::RetainAccepted,
                reason: TransitionReason::RemoteUnavailable,
            };
        };
        let report = self.reload(&accepted).await;
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
                debug!("watched ref is absent upstream");
                return self.apply(accepted, None, None).await;
            }
            Err(error) => {
                warn!(%error, "watcher remote observation failed");
                return self.apply(accepted, None, None).await;
            }
        };
        if tip == accepted.accepted_commit() {
            return PollReport {
                decision: TransitionDecision::Unchanged,
                reason: TransitionReason::CandidateEqualsAccepted,
            };
        }
        if self.suppressed.lock().await.contains(&tip) {
            let candidate = self.rejected_candidate(&tip);
            return self.apply(accepted, Some(candidate), None).await;
        }
        if let Err(error) = self.fetch().await {
            warn!(%error, "watcher fetch failed");
            return self.apply(accepted, None, None).await;
        }
        let observed = match self.watch_ref_commit().await {
            Ok(observed) => observed,
            Err(error) => {
                warn!(%error, "watcher fetch resolution failed");
                return self.apply(accepted, None, None).await;
            }
        };
        if observed != tip {
            debug!("watched ref moved during reload; retrying next poll");
            return self.apply(accepted, None, None).await;
        }
        let object_state = match self.object_state(&tip).await {
            Ok(object_state) => object_state,
            Err(error) => {
                warn!(%error, "watcher object probe failed");
                return self.apply(accepted, None, None).await;
            }
        };
        let ancestry = if object_state == ObjectState::Valid {
            match self.ancestry(accepted.accepted_commit(), &tip).await {
                Ok(ancestry) => ancestry,
                Err(error) => {
                    warn!(%error, "watcher ancestry probe failed");
                    Ancestry::Unknown
                }
            }
        } else {
            Ancestry::NotEvaluated
        };
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
        let mut pending = None;
        if object_state == ObjectState::Valid && ancestry == Ancestry::Descendant {
            let (validity, snapshot) = self
                .semantic_validation(accepted.accepted_commit(), &candidate.commit)
                .await;
            candidate.semantic_validity = validity;
            if validity == SemanticValidity::Valid {
                let record = self
                    .build_record(&candidate.commit)
                    .context("build forward accepted-ref record")
                    .and_then(|record| self.persist_record(&record).map(|()| record));
                match record {
                    Ok(_) => {
                        candidate.persistence = Persistence::Success;
                        pending = snapshot;
                    }
                    Err(error) => {
                        warn!(%error, "watcher accepted-ref persistence failed");
                        candidate.persistence = Persistence::InterruptedBeforeRename;
                    }
                }
            }
        }
        self.apply(accepted, Some(candidate), pending).await
    }

    async fn apply(
        &self,
        accepted: &AcceptedRef,
        candidate: Option<ReloadCandidate>,
        pending: Option<Arc<Snapshot>>,
    ) -> PollReport {
        let outcome = evaluate_reload(accepted, candidate.as_ref(), &self.repository)
            .expect("watcher candidates are internally consistent");
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
            }
            TransitionDecision::RetainAccepted => {
                if let Some(candidate) = candidate {
                    if !candidate.suppressed {
                        self.suppressed.lock().await.insert(candidate.commit);
                    }
                }
            }
            _ => {}
        }
        PollReport {
            decision: outcome.decision(),
            reason: outcome.reason(),
        }
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

    async fn materialize_tree(&self, commit: &str, label: &str) -> Result<TempTree> {
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
        let root = root.to_owned();
        let display = root.display().to_string();
        tokio::task::spawn_blocking(move || {
            build_snapshot(
                &root,
                delivery,
                archive_store.as_deref(),
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
        let snapshot = self.build_snapshot_from(tree.root()).await?;
        Ok(Arc::new(snapshot))
    }

    async fn semantic_validation(
        &self,
        accepted_commit: &str,
        candidate_commit: &str,
    ) -> (SemanticValidity, Option<Arc<Snapshot>>) {
        let accepted_tree = match self.materialize_tree(accepted_commit, "accepted").await {
            Ok(tree) => tree,
            Err(error) => {
                warn!(%error, "watcher accepted-tree materialization failed");
                return (SemanticValidity::Invalid, None);
            }
        };
        let candidate_tree = match self.materialize_tree(candidate_commit, "candidate").await {
            Ok(tree) => tree,
            Err(error) => {
                warn!(%error, "watcher candidate-tree materialization failed");
                return (SemanticValidity::Invalid, None);
            }
        };
        let accepted_root = accepted_tree.root().to_owned();
        let candidate_root = candidate_tree.root().to_owned();
        let transition =
            tokio::task::spawn_blocking(move || check_transition(&accepted_root, &candidate_root))
                .await;
        match transition {
            Ok(Ok(())) => match self.build_snapshot_from(candidate_tree.root()).await {
                Ok(snapshot) => (SemanticValidity::Valid, Some(Arc::new(snapshot))),
                Err(error) => {
                    warn!(%error, "watcher candidate snapshot build failed");
                    (SemanticValidity::Invalid, None)
                }
            },
            Ok(Err(reason)) => {
                info!(%reason, "watcher rejected candidate transition");
                (SemanticValidity::Invalid, None)
            }
            Err(error) => {
                warn!(%error, "watcher transition check failed");
                (SemanticValidity::Invalid, None)
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
    use std::io::{Seek, SeekFrom};
    use std::sync::atomic::AtomicU64 as StdAtomicU64;
    use std::sync::atomic::Ordering as AtomicOrdering;

    use crate::config::{CatalogSource, Config};
    use pkgre_rust::accepted_ref::derive_repository_identity;
    use pkgre_rust::artifact::sha256_bytes;

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
        let text = format!(
            r#"
schema = 1

[public]
bind = "127.0.0.1:30100"

[admin]
bind = "127.0.0.1:30101"

[registry]
delivery = "redirect"

[limits]
max-concurrency = 8

[watcher]
origin = "{}"
full-ref = "refs/heads/main"
catalog-path = "registry"
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
        let CatalogSource::Watcher(watcher_config) = &config.source else {
            panic!("watcher test configuration must select the watcher");
        };
        Arc::new(Watcher::new(
            watcher_config,
            config.delivery,
            config.archive_store.clone(),
            Arc::clone(shared),
        ))
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
        assert_eq!(stored_commit(&directory), origin.root);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
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
        assert_eq!(stored_commit(&directory), child);
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
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
    async fn persistence_failure_retains_then_suppresses() {
        let directory = TempDir::new("pkgre-watch-persist");
        let origin = Origin::new("pkgre-watch-persist-origin");
        let config = watcher_config(&directory, &origin, &origin.root);
        let shared = shared_for(&config);
        let watcher = watcher_for(&config, &shared);
        watcher.startup().await.unwrap();
        let before = shared.snapshot().await.unwrap();
        origin.advance_empty("forward");
        std::fs::remove_file(record_path(&directory)).unwrap();
        std::fs::create_dir(record_path(&directory)).unwrap();
        let report = watcher.poll_once().await;
        assert_eq!(report.decision, TransitionDecision::RetainAccepted);
        assert_eq!(report.reason, TransitionReason::DurablePersistenceFailed);
        assert!(Arc::ptr_eq(&shared.snapshot().await.unwrap(), &before));
        let report = watcher.poll_once().await;
        assert_eq!(report.reason, TransitionReason::RejectedHashSuppressed);
        let leftovers: Vec<String> = std::fs::read_dir(directory.path().join("state"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
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
}
