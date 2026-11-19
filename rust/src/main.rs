use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use pkgre_rust::artifact::ArtifactMap;
use pkgre_rust::policy::validate_catalog;
use pkgre_rust::projection::{FirstPartyOrigin, ProjectionLimits};
use pkgre_rust::render;
use pkgre_rust::schema::Catalog;
use pkgre_rust::serve::{DeliveryMode, build_snapshot};
use tracing::{error, info};

const USAGE: &str = "usage:\n  pkgre-rust lock <catalog>\n  pkgre-rust check <catalog>\n  pkgre-rust check-serve <catalog> --delivery=<body|redirect> [--archive-store=<directory>] [--first-party-origin=<url>]\n  pkgre-rust render <catalog> <output>\n  pkgre-rust verify <catalog> <output>\n  pkgre-rust verify-monotonic <previous-site> <next-site>\n  pkgre-rust update-plan <catalog> <admission-manifest>\n  pkgre-rust update-plan-exact <catalog> <package> <version> <admission-manifest>\n  pkgre-rust update-inspect <catalog> <admission-manifest> <package> <version> <output-directory>\n  pkgre-rust update-apply <catalog> <admission-manifest>
  pkgre-rust migrate-v4-to-v5 <input-catalog> <output-catalog> [--git-tag-time=<registry>/<name>@<tag>=<timestamp>]...
  pkgre-rust migrate-retained-delivery <catalog-root>
  pkgre-rust archive-inventory <catalog> <output.json>
  pkgre-rust archive-import <archive-store> <catalog>
  pkgre-rust check-transition <accepted-catalog> <candidate-catalog>
  pkgre-rust self-publish-check <repository> [<accepted-repository>]
  pkgre-rust self-publish-lock <repository>
  pkgre-rust self-publish <repository> <tag> [--upload] [--git=<url>]";

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
        Some("check-serve") => check_serve(&values),
        Some("render") => render_site(&values),
        Some("verify") => verify_site(&values),
        Some("verify-monotonic") => verify_monotonic(&values),
        Some("update-plan") => update_plan(&values),
        Some("update-plan-exact") => update_plan_exact(&values),
        Some("update-inspect") => update_inspect(&values),
        Some("update-apply") => update_apply(&values),
        Some("migrate-v4-to-v5") => migrate_v4_to_v5(&values),
        Some("migrate-retained-delivery") => migrate_retained_delivery(&values),
        Some("archive-inventory") => archive_inventory(&values),
        Some("archive-import") => archive_import_command(&values),
        Some("check-transition") => check_transition_command(&values),
        Some("self-publish-check") => self_publish_check(&values),
        Some("self-publish-lock") => self_publish_lock(&values),
        Some("self-publish") => self_publish(&values),
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
    let summary = pkgre_rust::check::check(Path::new(&arguments[0]))?;
    info!(
        packages = summary.usage.approvals,
        margins = %summary.margins(),
        "catalog is valid"
    );
    Ok(())
}

fn check_serve(arguments: &[OsString]) -> Result<()> {
    let mut positional = Vec::new();
    let mut delivery: Option<DeliveryMode> = None;
    let mut archive_store: Option<&Path> = None;
    let mut first_party_origin: Option<&str> = None;
    for argument in arguments {
        let value = argument.to_str().context("argument is not valid UTF-8")?;
        if let Some(mode) = value.strip_prefix("--delivery=") {
            ensure!(
                delivery.is_none(),
                "--delivery is given more than once\n{USAGE}"
            );
            delivery = Some(DeliveryMode::parse(mode)?);
        } else if let Some(store) = value.strip_prefix("--archive-store=") {
            ensure!(
                archive_store.is_none(),
                "--archive-store is given more than once\n{USAGE}"
            );
            ensure!(
                !store.is_empty(),
                "--archive-store needs the directory holding the archive store\n{USAGE}"
            );
            archive_store = Some(Path::new(store));
        } else if let Some(origin) = value.strip_prefix("--first-party-origin=") {
            ensure!(
                first_party_origin.is_none(),
                "--first-party-origin is given more than once\n{USAGE}"
            );
            ensure!(
                !origin.is_empty(),
                "--first-party-origin needs the origin of first-party archive redirects\n{USAGE}"
            );
            first_party_origin = Some(origin);
        } else {
            ensure!(
                !value.starts_with('-') || value == "-",
                "unknown argument {value:?}\n{USAGE}"
            );
            positional.push(argument.clone());
        }
    }
    ensure_arity(&positional, 1)?;
    let Some(mode) = delivery else {
        bail!("--delivery is required\n{USAGE}");
    };
    // An option that the selected mode never consults is refused instead of silently ignored.
    match mode {
        DeliveryMode::Body => ensure!(
            first_party_origin.is_none(),
            "--first-party-origin is only valid with --delivery=redirect\n{USAGE}"
        ),
        DeliveryMode::Redirect => ensure!(
            archive_store.is_none(),
            "--archive-store is only valid with --delivery=body\n{USAGE}"
        ),
    }
    let first_party_origin = first_party_origin
        .map(FirstPartyOrigin::parse)
        .transpose()?;
    // A mode whose required option is absent reaches `build_snapshot` without it, so the
    // command fails with the library's own message exactly where the service would.
    let snapshot = build_snapshot(
        Path::new(&positional[0]),
        mode,
        archive_store,
        first_party_origin.as_ref(),
        ProjectionLimits::default(),
    )?;
    let (inline_routes, archive_routes, redirect_routes) = snapshot.counts();
    info!(
        mode = mode.as_str(),
        inline_routes,
        archive_routes,
        redirect_routes,
        routes = snapshot.routes.len(),
        "catalog builds a valid serving snapshot"
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

fn archive_inventory(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let catalog = load_catalog(&arguments[0])?;
    validate_catalog(&catalog)?;
    let downloads = pkgre_rust::download::DownloadCatalog::load_from_root(&catalog.root)?;
    let inventory = pkgre_rust::archive::ArchiveInventory::from_catalog(&catalog, &downloads);
    let output = Path::new(&arguments[1]);
    pkgre_rust::artifact::require_absent(output)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(output, inventory.canonical_bytes()?)
        .with_context(|| format!("write {}", output.display()))?;
    info!(
        objects = inventory.objects.len(),
        path = %output.display(),
        "wrote archive inventory"
    );
    Ok(())
}

fn archive_import_command(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let store = Path::new(&arguments[0]);
    let catalog = Path::new(&arguments[1]);
    let summary = pkgre_rust::archive::archive_import(store, catalog)?;
    info!(
        imported = summary.imported,
        already_present = summary.already_present,
        path = %catalog.display(),
        "imported retained archives"
    );
    Ok(())
}

fn load_catalog(path: &OsStr) -> Result<Catalog> {
    Catalog::load(Path::new(path))
}

fn check_transition_command(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2)?;
    let accepted = Path::new(&arguments[0]);
    let candidate = Path::new(&arguments[1]);
    pkgre_rust::transition::check_transition(accepted, candidate)
        .map_err(|reason| anyhow::anyhow!("candidate rejected: {reason}"))?;
    info!(
        accepted = %accepted.display(),
        candidate = %candidate.display(),
        "candidate is a valid accepted-to-candidate transition"
    );
    Ok(())
}

fn self_publish_check(arguments: &[OsString]) -> Result<()> {
    ensure!(
        matches!(arguments.len(), 1 | 2),
        "wrong number of arguments\n{USAGE}"
    );
    let repository = Path::new(&arguments[0]);
    let accepted = arguments.get(1).map(Path::new);
    let summary = pkgre_rust::self_publish::check_repository(repository, accepted)?;
    info!(
        declared = summary.declared,
        repositories = summary.repositories,
        names = summary.names,
        entries = summary.entries,
        identities = summary.identities,
        accepted = summary.accepted,
        network_releases = summary.network_releases,
        path = %repository.display(),
        "checked self-publishing state"
    );
    Ok(())
}

fn self_publish_lock(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 1)?;
    let repository = Path::new(&arguments[0]);
    let summary = pkgre_rust::self_publish::self_publish_lock(repository)?;
    if !summary.changed {
        info!(
            path = %repository.display(),
            "every self-published identity has an entry; nothing to derive"
        );
        return Ok(());
    }
    for entry in &summary.entries {
        info!(
            package = %entry.name,
            version = %entry.version,
            crates_io_name = %entry.crates_io_name,
            crate_sha256 = %entry.crate_sha256,
            pkgre_crate_sha256 = %entry.pkgre_crate_sha256,
            tag = %entry.tag,
            "recorded a crates.io package"
        );
    }
    info!(
        entries = summary.entries.len(),
        releases = summary.releases,
        path = %repository.display(),
        "wrote self-publish/crates-io.lock"
    );
    Ok(())
}

fn self_publish(arguments: &[OsString]) -> Result<()> {
    let mut positional = Vec::new();
    let mut upload = false;
    let mut git: Option<&str> = None;
    for argument in arguments {
        let value = argument.to_str().context("argument is not valid UTF-8")?;
        if value == "--upload" {
            upload = true;
        } else if let Some(repository) = value.strip_prefix("--git=") {
            ensure!(
                !repository.is_empty(),
                "--git needs the URL of a self-publishing repository\n{USAGE}"
            );
            git = Some(repository);
        } else {
            ensure!(
                !value.starts_with('-') || value == "-",
                "unknown argument {value:?}\n{USAGE}"
            );
            positional.push(argument.clone());
        }
    }
    ensure_arity(&positional, 2)?;
    let repository = Path::new(&positional[0]);
    let tag = positional[1]
        .to_str()
        .context("release tag is not valid UTF-8")?;
    // The routine logs one record per crate version and the summary, also when
    // it fails, so the command adds no report of its own.
    pkgre_rust::self_publish::self_publish(repository, tag, upload, git)?;
    Ok(())
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
            let (key, timestamp) = entry.split_once('=').context(
                "--git-tag-time value must use <registry>/<name>@<tag>=<canonical-timestamp> form",
            )?;
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

fn migrate_retained_delivery(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 1)?;
    let root = Path::new(&arguments[0]);
    let summary = pkgre_rust::migrate::migrate_retained_delivery(root)?;
    info!(
        registries = summary.registries,
        changed = summary.changed,
        retained_routes = summary.retained_routes,
        total_routes = summary.total_routes,
        path = %root.display(),
        "declared retained delivery and recomputed the download catalog"
    );
    Ok(())
}
