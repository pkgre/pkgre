use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use pkgre_indexer::artifact::ArtifactMap;
use pkgre_indexer::policy::validate_catalog;
use pkgre_indexer::render;
use pkgre_indexer::schema::Catalog;
use tracing::{error, info};

const USAGE: &str = "usage:\n  pkgre-indexer lock <catalog>\n  pkgre-indexer check <catalog>\n  pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>\n  pkgre-indexer render <catalog> <output>\n  pkgre-indexer verify <catalog> <output>\n  pkgre-indexer verify-monotonic <previous-site> <next-site>";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            error!(error = %format_args!("{failure:#}"), "command failed");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<()> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().context(USAGE)?;
    let values = arguments.collect::<Vec<_>>();
    match command.to_str() {
        Some("lock") => lock_catalog(&values),
        Some("check") => check(&values),
        Some("migrate-v2-to-v3") => migrate_v2_to_v3(&values),
        Some("render") => render_site(&values),
        Some("verify") => verify_site(&values),
        Some("verify-monotonic") => verify_monotonic(&values),
        Some("help" | "--help" | "-h") => bail!(USAGE),
        Some(value) => bail!("unknown command {value:?}\n{USAGE}"),
        None => bail!("command is not valid UTF-8\n{USAGE}"),
    }
}

fn lock_catalog(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 1)?;
    let root = Path::new(&arguments[0]);
    let summary = pkgre_indexer::lock::reconcile(root)?;
    info!(
        changed = summary.changed,
        names_added = summary.names_added,
        packages_added = summary.packages_added,
        packages_removed = summary.packages_removed,
        path = %root.display(),
        "reconciled catalog locks and objects"
    );
    Ok(())
}

fn check(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 1)?;
    let catalog = load_catalog(&arguments[0])?;
    validate_catalog(&catalog)?;
    ArtifactMap::load(&catalog)?;
    info!(packages = catalog.approvals.len(), "catalog is valid");
    Ok(())
}

fn migrate_v2_to_v3(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let source = Path::new(&arguments[0]);
    let destination = Path::new(&arguments[1]);
    let summary = pkgre_indexer::migration::migrate_v2_to_v3(source, destination)?;
    info!(
        names = summary.names,
        packages = summary.packages,
        routed_rows_changed = summary.routed_rows_changed,
        path = %destination.display(),
        "migrated schema-2 catalog to schema 3"
    );
    Ok(())
}

fn render_site(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let catalog = load_catalog(&arguments[0])?;
    let artifacts = ArtifactMap::load(&catalog)?;
    let output = Path::new(&arguments[1]);
    render::render(&catalog, &artifacts, output)?;
    info!(path = %output.display(), "rendered registry site");
    Ok(())
}

fn verify_site(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let catalog = load_catalog(&arguments[0])?;
    let artifacts = ArtifactMap::load(&catalog)?;
    let output = Path::new(&arguments[1]);
    render::verify(&catalog, &artifacts, output)?;
    info!(path = %output.display(), "registry site is reproducible");
    Ok(())
}

fn verify_monotonic(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let previous = Path::new(&arguments[0]);
    let next = Path::new(&arguments[1]);
    render::verify_monotonic(previous, next)?;
    info!("registry release is monotonic");
    Ok(())
}

fn load_catalog(path: &OsStr) -> Result<Catalog> {
    Catalog::load(Path::new(path))
}

fn ensure_arity(arguments: &[OsString], expected: usize) -> Result<()> {
    ensure!(
        arguments.len() == expected,
        "wrong number of arguments\n{USAGE}"
    );
    Ok(())
}
