use std::fmt::Write;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::origin::OriginErrorCode;
use crate::route::PublicHost;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkerOutcome {
    Redirect,
    NotFound,
    InvalidMarker,
    BadGateway,
    ServiceUnavailable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MarkerCounters {
    redirect: u64,
    not_found: u64,
    invalid_marker: u64,
    bad_gateway: u64,
    service_unavailable: u64,
}

impl MarkerCounters {
    fn increment(&mut self, outcome: MarkerOutcome) {
        let counter = match outcome {
            MarkerOutcome::Redirect => &mut self.redirect,
            MarkerOutcome::NotFound => &mut self.not_found,
            MarkerOutcome::InvalidMarker => &mut self.invalid_marker,
            MarkerOutcome::BadGateway => &mut self.bad_gateway,
            MarkerOutcome::ServiceUnavailable => &mut self.service_unavailable,
        };
        *counter = counter.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CanaryState {
    last_success: Option<Instant>,
    last_error: Option<OriginErrorCode>,
    success_total: u64,
    failure_total: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct HostState {
    canary: CanaryState,
    marker: MarkerCounters,
}

#[derive(Clone, Copy, Debug, Default)]
struct State {
    rust: HostState,
    javascript: HostState,
}

impl State {
    const fn host(self, host: PublicHost) -> HostState {
        match host {
            PublicHost::Rust => self.rust,
            PublicHost::JavaScript => self.javascript,
        }
    }

    const fn host_mut(&mut self, host: PublicHost) -> &mut HostState {
        match host {
            PublicHost::Rust => &mut self.rust,
            PublicHost::JavaScript => &mut self.javascript,
        }
    }
}

pub struct ServiceState {
    readiness_freshness: Duration,
    state: RwLock<State>,
}

impl ServiceState {
    #[must_use]
    pub fn new(readiness_freshness: Duration) -> Self {
        Self {
            readiness_freshness,
            state: RwLock::new(State::default()),
        }
    }

    pub async fn record_canary(&self, host: PublicHost, result: Result<(), OriginErrorCode>) {
        let mut state = self.state.write().await;
        let canary = &mut state.host_mut(host).canary;
        match result {
            Ok(()) => {
                canary.last_success = Some(Instant::now());
                canary.last_error = None;
                canary.success_total = canary.success_total.saturating_add(1);
            }
            Err(error) => {
                canary.last_error = Some(error);
                canary.failure_total = canary.failure_total.saturating_add(1);
            }
        }
    }

    pub async fn record_marker(&self, host: PublicHost, outcome: MarkerOutcome) {
        self.state
            .write()
            .await
            .host_mut(host)
            .marker
            .increment(outcome);
    }

    pub async fn is_ready(&self) -> bool {
        let now = Instant::now();
        let state = *self.state.read().await;
        [PublicHost::Rust, PublicHost::JavaScript]
            .into_iter()
            .all(|host| self.host_ready(state.host(host).canary, now))
    }

    pub async fn metrics(&self) -> String {
        let now = Instant::now();
        let state = *self.state.read().await;
        let mut output = String::from(
            "# HELP pkgre_ready Whether all fixed origin canaries succeeded within the readiness window.\n\
# TYPE pkgre_ready gauge\n",
        );
        let ready = [PublicHost::Rust, PublicHost::JavaScript]
            .into_iter()
            .all(|host| self.host_ready(state.host(host).canary, now));
        writeln!(output, "pkgre_ready {}", u8::from(ready)).unwrap();
        output.push_str(
            "# HELP pkgre_origin_ready Whether a fixed origin canary succeeded within the readiness window.\n\
# TYPE pkgre_origin_ready gauge\n\
# HELP pkgre_origin_canary_checks_total Fixed origin canary checks by result.\n\
# TYPE pkgre_origin_canary_checks_total counter\n\
# HELP pkgre_origin_canary_last_error Current closed origin error code,if any.\n\
# TYPE pkgre_origin_canary_last_error gauge\n\
# HELP pkgre_marker_requests_total Marker requests by fixed host and outcome.\n\
# TYPE pkgre_marker_requests_total counter\n",
        );
        for host in [PublicHost::Rust, PublicHost::JavaScript] {
            let host_state = state.host(host);
            let host_name = host.as_str();
            writeln!(
                output,
                "pkgre_origin_ready{{host=\"{host_name}\"}} {}",
                u8::from(self.host_ready(host_state.canary, now))
            )
            .unwrap();
            writeln!(
                output,
                "pkgre_origin_canary_checks_total{{host=\"{host_name}\",result=\"success\"}} {}",
                host_state.canary.success_total
            )
            .unwrap();
            writeln!(
                output,
                "pkgre_origin_canary_checks_total{{host=\"{host_name}\",result=\"failure\"}} {}",
                host_state.canary.failure_total
            )
            .unwrap();
            let error = host_state
                .canary
                .last_error
                .map_or("none", OriginErrorCode::as_str);
            writeln!(
                output,
                "pkgre_origin_canary_last_error{{host=\"{host_name}\",code=\"{error}\"}} 1"
            )
            .unwrap();
            for (outcome, value) in [
                ("redirect", host_state.marker.redirect),
                ("not_found", host_state.marker.not_found),
                ("invalid_marker", host_state.marker.invalid_marker),
                ("bad_gateway", host_state.marker.bad_gateway),
                ("service_unavailable", host_state.marker.service_unavailable),
            ] {
                writeln!(
                    output,
                    "pkgre_marker_requests_total{{host=\"{host_name}\",outcome=\"{outcome}\"}} {value}"
                )
                .unwrap();
            }
        }
        output
    }

    fn host_ready(&self, canary: CanaryState, now: Instant) -> bool {
        canary.last_success.is_some_and(|success| {
            now.checked_duration_since(success)
                .is_some_and(|age| age <= self.readiness_freshness)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn readiness_requires_both_recent_fixed_canaries() {
        let state = ServiceState::new(Duration::from_secs(180));
        assert!(!state.is_ready().await);
        state.record_canary(PublicHost::Rust, Ok(())).await;
        assert!(!state.is_ready().await);
        state.record_canary(PublicHost::JavaScript, Ok(())).await;
        assert!(state.is_ready().await);
        state
            .record_canary(
                PublicHost::JavaScript,
                Err(OriginErrorCode::UnexpectedContentType),
            )
            .await;
        assert!(state.is_ready().await);
        tokio::time::advance(Duration::from_secs(181)).await;
        assert!(!state.is_ready().await);
    }

    #[tokio::test]
    async fn metrics_use_only_closed_labels_and_saturating_counters() {
        let state = ServiceState::new(Duration::from_secs(180));
        state.record_canary(PublicHost::Rust, Ok(())).await;
        state
            .record_canary(PublicHost::JavaScript, Err(OriginErrorCode::Connection))
            .await;
        state
            .record_marker(PublicHost::Rust, MarkerOutcome::Redirect)
            .await;
        state
            .record_marker(PublicHost::JavaScript, MarkerOutcome::InvalidMarker)
            .await;
        let metrics = state.metrics().await;
        assert!(metrics.contains("pkgre_ready 0\n"));
        assert!(metrics.contains(
            "pkgre_origin_canary_last_error{host=\"js.pkg.re\",code=\"connection\"} 1\n"
        ));
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"rust.pkg.re\",outcome=\"redirect\"} 1\n"
        ));
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"js.pkg.re\",outcome=\"invalid_marker\"} 1\n"
        ));
    }
}
