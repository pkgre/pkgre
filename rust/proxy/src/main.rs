use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use pkgre_proxy::config::Config;
use pkgre_proxy::origin::PagesOrigin;
use pkgre_proxy::route::PublicHost;
use pkgre_proxy::state::ServiceState;
use pkgre_proxy::web;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = %format_args!("{error:#}"), "service failed");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let config = Config::parse(std::env::args_os().skip(1))?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime")?
        .block_on(serve(config))
}

async fn serve(config: Config) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind proxy service to {}", config.listen))?;
    let origin = Arc::new(PagesOrigin::new());
    let state = Arc::new(ServiceState::new(config.readiness_freshness));
    let probes = tokio::spawn({
        let origin = Arc::clone(&origin);
        let state = Arc::clone(&state);
        let interval = config.canary_interval;
        async move {
            loop {
                check_fixed_canaries(&origin, &state).await;
                tokio::time::sleep(interval).await;
            }
        }
    });

    info!(
        listen = %config.listen,
        canary_seconds = config.canary_interval.as_secs(),
        readiness_seconds = config.readiness_freshness.as_secs(),
        original_uri_header = %web::ORIGINAL_URI_HEADER,
        "serving static marker redirects"
    );
    let result = axum::serve(listener, web::application(origin, state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve static marker redirects");
    probes.abort();
    result
}

async fn check_fixed_canaries(origin: &PagesOrigin, state: &ServiceState) {
    tokio::join!(
        check_canary(origin, state, PublicHost::Rust),
        check_canary(origin, state, PublicHost::JavaScript)
    );
}

async fn check_canary(origin: &PagesOrigin, state: &ServiceState, host: PublicHost) {
    match origin.check_canary(host).await {
        Ok(()) => {
            state.record_canary(host, Ok(())).await;
            info!(host = host.as_str(), "fixed origin canary passed");
        }
        Err(error) => {
            state.record_canary(host, Err(error.code())).await;
            warn!(
                host = host.as_str(),
                origin_error = error.code().as_str(),
                error_class = ?error.class(),
                "fixed origin canary failed"
            );
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    error!(%error, "failed to listen for Ctrl-C");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        error!(%error, "failed to listen for Ctrl-C");
    }
    info!("shutdown requested");
}
