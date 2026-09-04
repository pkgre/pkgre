//! `pkgre-rust-serve` binary entry point.

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use pkgre_rust::projection::ProjectionLimits;
use pkgre_rust::serve::build_snapshot;
use tokio::net::TcpListener;
use tracing::{error, info};

use pkgre_rust_serve::config::Config;
use pkgre_rust_serve::web;

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
    let snapshot = build_snapshot(
        &config.catalog,
        config.delivery,
        config.archive_store.as_deref(),
        ProjectionLimits::default(),
    )
    .with_context(|| format!("build serving snapshot from {}", config.catalog.display()))?;
    let shared = Arc::new(web::Shared::new(config.delivery, config.max_concurrency));
    shared.install_snapshot(Arc::new(snapshot)).await;
    let public_listener = TcpListener::bind(config.public_bind)
        .await
        .with_context(|| format!("bind public registry to {}", config.public_bind))?;
    let admin_listener = TcpListener::bind(config.admin_bind)
        .await
        .with_context(|| format!("bind admin service to {}", config.admin_bind))?;
    info!(
        public = %config.public_bind,
        admin = %config.admin_bind,
        delivery = config.delivery.as_str(),
        catalog = %config.catalog.display(),
        "serving registry snapshot"
    );
    let public_shared = Arc::clone(&shared);
    let (public, admin) = tokio::try_join!(
        async {
            axum::serve(public_listener, web::public_application(public_shared))
                .with_graceful_shutdown(shutdown_signal())
                .await
                .context("serve public registry")
        },
        async {
            axum::serve(admin_listener, web::admin_application(shared))
                .with_graceful_shutdown(shutdown_signal())
                .await
                .context("serve admin service")
        },
    )?;
    let ((), ()) = (public, admin);
    Ok(())
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
