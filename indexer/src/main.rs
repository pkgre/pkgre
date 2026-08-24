use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use pkgre_indexer::artifact::ArtifactMap;
use pkgre_indexer::policy::validate_catalog;
use pkgre_indexer::render;
use pkgre_indexer::schema::Catalog;
use tracing::{error, info};

const USAGE: &str = "usage:\n  pkgre-indexer lock <catalog>\n  pkgre-indexer check <catalog>\n  pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>\n  pkgre-indexer render <catalog> <output>\n  pkgre-indexer verify <catalog> <output>\n  pkgre-indexer verify-monotonic <previous-site> <next-site>\n  pkgre-indexer update-plan <catalog> <admission-manifest>\n  pkgre-indexer update-plan-exact <catalog> <package> <version> <admission-manifest>\n  pkgre-indexer update-inspect <catalog> <admission-manifest> <package> <version> <output-directory>\n  pkgre-indexer update-apply <catalog> <admission-manifest>";

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
        Some("update-plan") => update_plan(&values),
        Some("update-plan-exact") => update_plan_exact(&values),
        Some("update-inspect") => update_inspect(&values),
        Some("update-apply") => update_apply(&values),
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

fn update_plan(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let catalog = Path::new(&arguments[0]);
    let output = Path::new(&arguments[1]);
    let plan = pkgre_indexer::update::plan_updates(catalog, output)?;
    log_update_plan(&plan, output);
    Ok(())
}

fn update_plan_exact(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 4)?;
    let catalog = Path::new(&arguments[0]);
    let name = arguments[1]
        .to_str()
        .context("package name is not valid UTF-8")?;
    let version = arguments[2]
        .to_str()
        .context("package version is not valid UTF-8")?
        .parse()
        .context("package version is not valid SemVer")?;
    let output = Path::new(&arguments[3]);
    let plan = pkgre_indexer::update::plan_exact_update(catalog, name, &version, output)?;
    log_update_plan(&plan, output);
    Ok(())
}

fn update_inspect(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 5)?;
    let catalog = Path::new(&arguments[0]);
    let manifest = Path::new(&arguments[1]);
    let name = arguments[2]
        .to_str()
        .context("package name is not valid UTF-8")?;
    let version = arguments[3]
        .to_str()
        .context("package version is not valid UTF-8")?
        .parse()
        .context("package version is not valid SemVer")?;
    let output = Path::new(&arguments[4]);
    pkgre_indexer::update::inspect_update_candidate(catalog, manifest, name, &version, output)?;
    info!(
        package = name,
        version = %version,
        path = %output.display(),
        "materialized inert exact admission evidence"
    );
    Ok(())
}

fn update_apply(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let catalog = Path::new(&arguments[0]);
    let manifest = Path::new(&arguments[1]);
    let summary = pkgre_indexer::update::apply_admission_manifest(catalog, manifest)?;
    info!(
        changed = summary.changed,
        names_added = summary.names_added,
        packages_added = summary.packages_added,
        packages_removed = summary.packages_removed,
        path = %catalog.display(),
        "atomically applied admission manifest"
    );
    Ok(())
}

fn log_update_plan(plan: &pkgre_indexer::update::UpdatePlan, output: &Path) {
    use pkgre_indexer::update::UpdateDecision;

    let automatic = plan
        .candidates
        .iter()
        .filter(|candidate| candidate.decision == UpdateDecision::Automatic)
        .count();
    let review_required = plan
        .candidates
        .iter()
        .filter(|candidate| candidate.decision == UpdateDecision::ReviewRequired)
        .count();
    let blocked = plan
        .candidates
        .iter()
        .filter(|candidate| candidate.decision == UpdateDecision::Blocked)
        .count();
    info!(
        candidates = plan.candidates.len(),
        automatic,
        review_required,
        blocked,
        path = %output.display(),
        "created canonical admission template"
    );
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
