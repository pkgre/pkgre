use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::{Mutex, watch};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::catalog::RouteKey;
use crate::github::{CatalogFetcher, FetchFailure, FetchedCatalog};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbsenceState {
    KnownAbsent,
    Uncertain { retry_after: Duration },
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatus {
    pub ready: bool,
    pub source_commit: Option<String>,
    pub manifest_sha256: Option<String>,
    pub routes: usize,
    pub crates_io_routes: usize,
    pub git_tag_routes: usize,
    pub loaded_unix_seconds: Option<u64>,
    pub last_attempt_unix_seconds: Option<u64>,
    pub last_success_unix_seconds: Option<u64>,
    pub last_error: Option<String>,
    pub next_refresh_in_seconds: u64,
    pub refresh_in_flight: bool,
}

struct LoadedCatalog {
    fetched: FetchedCatalog,
    loaded_at: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptResult {
    Success,
    Failure,
}

struct CoordinatorState {
    catalog: Option<Arc<LoadedCatalog>>,
    in_flight: bool,
    last_attempt: Option<SystemTime>,
    last_success: Option<SystemTime>,
    last_result: Option<AttemptResult>,
    last_error: Option<String>,
    next_allowed: Instant,
}

#[derive(Clone)]
pub struct RefreshCoordinator {
    inner: Arc<CoordinatorInner>,
}

struct CoordinatorInner {
    fetcher: Arc<dyn CatalogFetcher>,
    minimum_interval: Duration,
    state: Mutex<CoordinatorState>,
    completed: watch::Sender<u64>,
}

impl RefreshCoordinator {
    #[must_use]
    pub fn new(fetcher: Arc<dyn CatalogFetcher>, minimum_interval: Duration) -> Self {
        Self {
            inner: Arc::new(CoordinatorInner {
                fetcher,
                minimum_interval,
                state: Mutex::new(CoordinatorState {
                    catalog: None,
                    in_flight: false,
                    last_attempt: None,
                    last_success: None,
                    last_result: None,
                    last_error: None,
                    next_allowed: Instant::now(),
                }),
                completed: watch::channel(0).0,
            }),
        }
    }

    /// Starts an eligible refresh or waits for the refresh already in flight.
    ///
    /// The actual fetch is owned by a detached supervisor task. Cancelling the caller therefore
    /// cannot strand the coordinator in its in-flight state, and a panicking fetcher is converted
    /// into a normal failed attempt.
    pub async fn refresh_if_eligible(&self) {
        let mut completed = self.inner.completed.subscribe();
        let started = {
            let mut state = self.inner.state.lock().await;
            if state.in_flight {
                drop(state);
                let _ = completed.changed().await;
                return;
            }
            let now = Instant::now();
            if now < state.next_allowed {
                return;
            }
            state.in_flight = true;
            state.last_attempt = Some(SystemTime::now());
            now
        };

        let coordinator = self.clone();
        let fetcher = Arc::clone(&self.inner.fetcher);
        let supervisor = tokio::spawn(async move {
            let worker = tokio::spawn(async move { fetcher.fetch().await });
            let result = match worker.await {
                Ok(result) => result,
                Err(error) => Err(FetchFailure {
                    message: format!("catalog fetch task failed: {error}"),
                    retry_after: None,
                }),
            };
            coordinator.finish(started, result).await;
        });
        drop(supervisor);
        let _ = completed.changed().await;
    }

    pub async fn refresh_for_miss(&self) -> AbsenceState {
        self.refresh_if_eligible().await;
        let state = self.inner.state.lock().await;
        match state.last_result {
            Some(AttemptResult::Success) => AbsenceState::KnownAbsent,
            Some(AttemptResult::Failure) | None => AbsenceState::Uncertain {
                retry_after: duration_until(state.next_allowed),
            },
        }
    }

    pub async fn destination(&self, key: &RouteKey) -> Option<String> {
        let catalog = {
            let state = self.inner.state.lock().await;
            state.catalog.clone()
        };
        catalog.and_then(|catalog| catalog.fetched.table.destination(key))
    }

    pub async fn status(&self) -> ServiceStatus {
        let state = self.inner.state.lock().await;
        let catalog = state.catalog.as_ref();
        let table = catalog.map(|catalog| &catalog.fetched.table);
        ServiceStatus {
            ready: catalog.is_some(),
            source_commit: catalog.map(|catalog| catalog.fetched.commit.clone()),
            manifest_sha256: catalog.map(|catalog| catalog.fetched.manifest_sha256.clone()),
            routes: table.map_or(0, |table| table.route_count()),
            crates_io_routes: table.map_or(0, |table| table.crates_io_route_count()),
            git_tag_routes: table.map_or(0, |table| table.git_tag_route_count()),
            loaded_unix_seconds: catalog.map(|catalog| unix_seconds(catalog.loaded_at)),
            last_attempt_unix_seconds: state.last_attempt.map(unix_seconds),
            last_success_unix_seconds: state.last_success.map(unix_seconds),
            last_error: state.last_error.clone(),
            next_refresh_in_seconds: seconds_until(state.next_allowed),
            refresh_in_flight: state.in_flight,
        }
    }

    async fn finish(
        &self,
        started: Instant,
        result: std::result::Result<FetchedCatalog, FetchFailure>,
    ) {
        let completed_at = Instant::now();
        let completed_wall = SystemTime::now();
        let mut state = self.inner.state.lock().await;
        state.in_flight = false;
        state.next_allowed = started + self.inner.minimum_interval;
        match result {
            Ok(fetched) => {
                info!(
                    source_commit = fetched.commit,
                    manifest_sha256 = fetched.manifest_sha256,
                    routes = fetched.table.route_count(),
                    crates_io_routes = fetched.table.crates_io_route_count(),
                    git_tag_routes = fetched.table.git_tag_route_count(),
                    "installed refreshed download catalog"
                );
                state.catalog = Some(Arc::new(LoadedCatalog {
                    fetched,
                    loaded_at: completed_wall,
                }));
                state.last_success = Some(completed_wall);
                state.last_result = Some(AttemptResult::Success);
                state.last_error = None;
            }
            Err(failure) => {
                warn!(error = %failure.message, "download catalog refresh failed; retaining last known good catalog");
                if let Some(retry_after) = failure.retry_after {
                    state.next_allowed = state.next_allowed.max(completed_at + retry_after);
                }
                state.last_result = Some(AttemptResult::Failure);
                state.last_error = Some(failure.message);
            }
        }
        drop(state);
        self.inner.completed.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }
}

fn duration_until(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn seconds_until(deadline: Instant) -> u64 {
    let duration = duration_until(deadline);
    let seconds = duration.as_secs();
    if duration.subsec_nanos() == 0 {
        seconds
    } else {
        seconds.saturating_add(1)
    }
}

#[must_use]
pub fn retry_after_seconds(duration: Duration) -> u64 {
    let seconds = duration.as_secs();
    if duration.subsec_nanos() == 0 {
        seconds.max(1)
    } else {
        seconds.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pkgre_indexer::download::{
        DOWNLOAD_CATALOG_SCHEMA, DownloadCatalog, DownloadRoute, DownloadSource,
    };
    use semver::Version;
    use tokio::sync::Notify;

    use super::*;
    use crate::catalog::RouteTable;
    use crate::github::FetchFuture;

    struct FakeFetcher {
        calls: AtomicUsize,
        responses: StdMutex<VecDeque<std::result::Result<FetchedCatalog, FetchFailure>>>,
    }

    impl FakeFetcher {
        fn new(responses: Vec<std::result::Result<FetchedCatalog, FetchFailure>>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                responses: StdMutex::new(VecDeque::from(responses)),
            })
        }
    }

    impl CatalogFetcher for FakeFetcher {
        fn fetch(&self) -> FetchFuture<'_> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = self.responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }
    }

    fn fetched(name: &str, commit_byte: &str) -> FetchedCatalog {
        let catalog = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![DownloadRoute {
                registry: "universe".to_owned(),
                name: name.to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                sha256: "01".repeat(32),
                source: DownloadSource::CratesIo,
            }],
        };
        FetchedCatalog {
            commit: commit_byte.repeat(40),
            manifest_sha256: commit_byte.repeat(64),
            table: Arc::new(RouteTable::from_catalog(catalog).unwrap()),
        }
    }

    fn failed(message: &str, retry_after: Option<Duration>) -> FetchFailure {
        FetchFailure {
            message: message.to_owned(),
            retry_after,
        }
    }

    fn key(name: &str) -> RouteKey {
        RouteKey::parse_canonical("universe", name, "1.0.0", &"01".repeat(32)).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn startup_failure_is_uncertain_and_later_success_becomes_ready() {
        let fetcher = FakeFetcher::new(vec![
            Err(failed("offline", None)),
            Ok(fetched("serde", "a")),
        ]);
        let coordinator = RefreshCoordinator::new(fetcher.clone(), Duration::from_secs(120));
        assert_eq!(
            coordinator.refresh_for_miss().await,
            AbsenceState::Uncertain {
                retry_after: Duration::from_secs(120)
            }
        );
        assert!(!coordinator.status().await.ready);
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);

        tokio::time::advance(Duration::from_secs(120)).await;
        coordinator.refresh_if_eligible().await;
        assert!(coordinator.status().await.ready);
        assert!(coordinator.destination(&key("serde")).await.is_some());
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn last_known_good_survives_failure_but_misses_are_uncertain() {
        let fetcher = FakeFetcher::new(vec![
            Ok(fetched("serde", "a")),
            Err(failed("rate limited", Some(Duration::from_secs(600)))),
        ]);
        let coordinator = RefreshCoordinator::new(fetcher, Duration::from_secs(120));
        coordinator.refresh_if_eligible().await;
        assert_eq!(
            coordinator.refresh_for_miss().await,
            AbsenceState::KnownAbsent
        );
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(
            matches!(
                coordinator.refresh_for_miss().await,
                AbsenceState::Uncertain { retry_after }
                    if retry_after == Duration::from_secs(600)
            ),
            "failure should apply upstream backoff"
        );
        assert!(coordinator.destination(&key("serde")).await.is_some());
        let status = coordinator.status().await;
        assert!(status.ready);
        assert_eq!(status.last_error.as_deref(), Some("rate limited"));
    }

    struct BlockingFetcher {
        calls: AtomicUsize,
        started: Notify,
        release: Notify,
    }

    impl CatalogFetcher for BlockingFetcher {
        fn fetch(
            &self,
        ) -> Pin<
            Box<dyn Future<Output = std::result::Result<FetchedCatalog, FetchFailure>> + Send + '_>,
        > {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                self.started.notify_waiters();
                self.release.notified().await;
                Ok(fetched("serde", "a"))
            })
        }
    }

    #[tokio::test]
    async fn concurrent_refreshes_are_single_flight() {
        let fetcher = Arc::new(BlockingFetcher {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Notify::new(),
        });
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        let first = tokio::spawn({
            let coordinator = Arc::clone(&coordinator);
            async move { coordinator.refresh_if_eligible().await }
        });
        while fetcher.calls.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        let second = tokio::spawn({
            let coordinator = Arc::clone(&coordinator);
            async move { coordinator.refresh_if_eligible().await }
        });
        tokio::task::yield_now().await;
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
        fetcher.release.notify_one();
        first.await.unwrap();
        second.await.unwrap();
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
        assert!(coordinator.status().await.ready);
    }

    #[tokio::test]
    async fn cancelling_initiator_does_not_cancel_or_strand_refresh() {
        let fetcher = Arc::new(BlockingFetcher {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Notify::new(),
        });
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        let initiator = tokio::spawn({
            let coordinator = Arc::clone(&coordinator);
            async move { coordinator.refresh_if_eligible().await }
        });
        while fetcher.calls.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        initiator.abort();
        assert!(initiator.await.unwrap_err().is_cancelled());
        assert!(coordinator.status().await.refresh_in_flight);

        let waiter = tokio::spawn({
            let coordinator = Arc::clone(&coordinator);
            async move { coordinator.refresh_if_eligible().await }
        });
        fetcher.release.notify_one();
        waiter.await.unwrap();
        assert!(coordinator.status().await.ready);
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
    }

    struct PanickingFetcher;

    impl CatalogFetcher for PanickingFetcher {
        fn fetch(&self) -> FetchFuture<'_> {
            Box::pin(async { panic!("simulated fetcher panic") })
        }
    }

    #[tokio::test]
    async fn panicking_fetcher_clears_in_flight_as_failure() {
        let coordinator =
            RefreshCoordinator::new(Arc::new(PanickingFetcher), Duration::from_millis(1));
        coordinator.refresh_if_eligible().await;
        let status = coordinator.status().await;
        assert!(!status.ready);
        assert!(!status.refresh_in_flight);
        assert!(
            status
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("catalog fetch task failed"))
        );
    }

    #[test]
    fn retry_after_rounds_up_and_never_returns_zero() {
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
        assert_eq!(retry_after_seconds(Duration::from_secs(2)), 2);
        assert_eq!(retry_after_seconds(Duration::from_millis(2_001)), 3);
    }
}
