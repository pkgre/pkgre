use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use pkgre_rust::artifact::ArtifactMap;
use pkgre_rust::policy::validate_catalog;
use pkgre_rust::render;
use pkgre_rust::schema::Catalog;
use tracing::{error, info};

const USAGE: &str = "usage:\n  pkgre-rust lock <catalog>\n  pkgre-rust check <catalog>\n  pkgre-rust render <catalog> <output>\n  pkgre-rust verify <catalog> <output>\n  pkgre-rust verify-monotonic <previous-site> <next-site>\n  pkgre-rust update-plan <catalog> <admission-manifest>\n  pkgre-rust update-plan-exact <catalog> <package> <version> <admission-manifest>\n  pkgre-rust update-inspect <catalog> <admission-manifest> <package> <version> <output-directory>\n  pkgre-rust update-apply <catalog> <admission-manifest>
  pkgre-rust migrate-v4-to-v5 <input-catalog> <output-catalog> [--git-tag-time registry/name@tag=<timestamp>]...";

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
        Some("render") => render_site(&values),
        Some("verify") => verify_site(&values),
        Some("verify-monotonic") => verify_monotonic(&values),
        Some("update-plan") => update_plan(&values),
        Some("update-plan-exact") => update_plan_exact(&values),
        Some("update-inspect") => update_inspect(&values),
        Some("update-apply") => update_apply(&values),
        Some("migrate-v4-to-v5") => migrate_v4_to_v5(&values),
        Some("help" | "--help" | "-h") => bail!(USAGE),
        Some(value) => bail!("unknown command {value:?}\n{USAGE}"),
        None => bail!("command is not valid UTF-8\n{USAGE}"),
    }
}

fn lock_catalog(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 1)?;
    let root = Path::new(&arguments[0]);
    let summary = pkgre_rust::lock::reconcile(root)?;
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
    let plan = pkgre_rust::update::plan_updates(catalog, output)?;
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
    let plan = pkgre_rust::update::plan_exact_update(catalog, name, &version, output)?;
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
    pkgre_rust::update::inspect_update_candidate(catalog, manifest, name, &version, output)?;
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
    let summary = pkgre_rust::update::apply_admission_manifest(catalog, manifest)?;
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

fn log_update_plan(plan: &pkgre_rust::update::UpdatePlan, output: &Path) {
    use pkgre_rust::update::UpdateDecision;

    for candidate in &plan.candidates {
        info!(
            registry = candidate.registry,
            category = candidate.category,
            package = candidate.name,
            version = %candidate.candidate.version,
            decision = ?candidate.decision,
            reasons = ?candidate.reasons,
            "planned update candidate"
        );
    }
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

fn migrate_v4_to_v5(arguments: &[OsString]) -> Result<()> {
    if arguments.len() < 2 {
        bail!(USAGE);
    }
    let mut positional = Vec::new();
    let mut git_times = Vec::new();
    for argument in arguments {
        let value = argument.to_str().context("argument is not valid UTF-8")?;
        if let Some(entry) = value.strip_prefix("--git-tag-time=") {
            let (key, timestamp) = entry
                .split_once('=')
                .context("--git-tag-time must use registry/name@tag=<canonical-timestamp> form")?;
            let canonical =
                pkgre_rust::migrate::canonicalize_rfc3339(timestamp).with_context(|| {
                    format!("--git-tag-time timestamp {timestamp:?} is not RFC 3339")
                })?;
            git_times.push((key.to_string(), canonical.to_string()));
        } else {
            ensure!(
                !value.starts_with('-') || value == "-",
                "unknown argument {value:?}\n{USAGE}"
            );
            positional.push(argument.clone());
        }
    }
    ensure_arity(&positional, 2)?;
    let input = Path::new(&positional[0]);
    let output = Path::new(&positional[1]);
    let summary = pkgre_rust::migrate::migrate_v4_to_v5(input, output, &git_times)?;
    for registry in &summary.registries {
        info!(
            registry = %registry.name,
            packages = registry.packages,
            "migrated registry"
        );
    }
    info!(routes = summary.routes, "migration complete");
    Ok(())
}
