use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use pkgre_proxy::config::Config;
use pkgre_proxy::coordinator::RefreshCoordinator;
use pkgre_proxy::github::{CatalogFetcher, GitHubCatalogFetcher};
use pkgre_proxy::web;
use tokio::net::TcpListener;
use tracing::{error, info};

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
        .with_context(|| format!("bind download service to {}", config.listen))?;
    let fetcher: Arc<dyn CatalogFetcher> = Arc::new(GitHubCatalogFetcher::new()?);
    let coordinator = Arc::new(RefreshCoordinator::new(
        fetcher,
        config.minimum_refresh_interval,
    ));
    let initial = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move { coordinator.refresh_if_eligible().await }
    });
    let periodic = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        let interval = config.refresh_interval;
        async move {
            loop {
                tokio::time::sleep(interval).await;
                coordinator.refresh_if_eligible().await;
            }
        }
    });

    info!(
        listen = %config.listen,
        refresh_seconds = config.refresh_interval.as_secs(),
        minimum_refresh_seconds = config.minimum_refresh_interval.as_secs(),
        original_uri_header = %web::ORIGINAL_URI_HEADER,
        "serving immutable download redirects"
    );
    let result = axum::serve(listener, web::application(coordinator))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve download redirects");
    initial.abort();
    periodic.abort();
    result
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
