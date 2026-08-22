use std::ffi::{OsStr, OsString};
use std::path::Path;

use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use pkgre_indexer::artifact::ArtifactMap;
use pkgre_indexer::import::{candidate_crates_io, load_crates_io_proposal};
use pkgre_indexer::package::{candidate_git, load_git_proposal, package_approved_git};
use pkgre_indexer::policy::validate_catalog;
use pkgre_indexer::render;
use pkgre_indexer::schema::Catalog;
use semver::Version;
use tracing::{error, info};

const USAGE: &str = "usage:\n  pkgre-indexer check <catalog> [artifact-map]\n  pkgre-indexer render <catalog> <artifact-map> <output>\n  pkgre-indexer verify <catalog> <artifact-map> <output>\n  pkgre-indexer verify-monotonic <previous-site> <next-site>\n  pkgre-indexer candidate-crates-io <proposal> <output>\n  pkgre-indexer candidate-git <proposal> <cargo-version> <output>\n  pkgre-indexer package-git <catalog> <package> <version> <output>";

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
        Some("check") => check(&values),
        Some("render") => render_site(&values),
        Some("verify") => verify_site(&values),
        Some("verify-monotonic") => verify_monotonic(&values),
        Some("candidate-crates-io") => candidate_crates_io_packages(&values),
        Some("candidate-git") => candidate_git_package(&values),
        Some("package-git") => package_git(&values),
        Some("help" | "--help" | "-h") => bail!(USAGE),
        Some(value) => bail!("unknown command {value:?}\n{USAGE}"),
        None => bail!("command is not valid UTF-8\n{USAGE}"),
    }
}

fn check(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 1, 2)?;
    let catalog = load_catalog(&arguments[0])?;
    validate_catalog(&catalog)?;
    if let Some(path) = arguments.get(1) {
        let artifacts = ArtifactMap::load(path)?;
        artifacts.verify(&catalog)?;
    }
    info!(approvals = catalog.approvals.len(), "catalog is valid");
    Ok(())
}

fn render_site(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 3, 3)?;
    let catalog = load_catalog(&arguments[0])?;
    let artifacts = ArtifactMap::load(&arguments[1])?;
    let output = Path::new(&arguments[2]);
    render::render(&catalog, &artifacts, output)?;
    info!(path = %output.display(), "rendered registry site");
    Ok(())
}

fn verify_site(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 3, 3)?;
    let catalog = load_catalog(&arguments[0])?;
    let artifacts = ArtifactMap::load(&arguments[1])?;
    let output = Path::new(&arguments[2]);
    render::verify(&catalog, &artifacts, output)?;
    info!(path = %output.display(), "registry site is reproducible");
    Ok(())
}

fn verify_monotonic(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2, 2)?;
    let previous = Path::new(&arguments[0]);
    let next = Path::new(&arguments[1]);
    render::verify_monotonic(previous, next)?;
    info!("registry release is monotonic");
    Ok(())
}

fn candidate_crates_io_packages(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 2, 2)?;
    let proposal = load_crates_io_proposal(Path::new(&arguments[0]))?;
    let output = Path::new(&arguments[1]);
    candidate_crates_io(&proposal, output)?;
    info!(
        packages = proposal.packages.len(),
        path = %output.display(),
        "materialized crates.io candidates"
    );
    Ok(())
}

fn candidate_git_package(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 3, 3)?;
    let proposal = load_git_proposal(Path::new(&arguments[0]))?;
    let cargo_version = parse_version(&arguments[1], "Cargo version")?;
    let output = Path::new(&arguments[2]);
    let materialization = candidate_git(&proposal, &cargo_version, output)?;
    info!(
        archive_sha256 = materialization.archive_sha256,
        index_record_sha256 = materialization.index_record_sha256,
        path = %output.display(),
        "materialized Git-tag candidate"
    );
    Ok(())
}

fn package_git(arguments: &[OsString]) -> Result<()> {
    ensure_arity(arguments, 4, 4)?;
    let catalog = load_catalog(&arguments[0])?;
    validate_catalog(&catalog)?;
    let name = utf8(&arguments[1], "package name")?;
    let version = parse_version(&arguments[2], "package version")?;
    let matching = catalog
        .approvals
        .iter()
        .filter(|approval| approval.name == name && approval.version == version)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "catalog contains {} approvals for {name} {version}; expected exactly one",
        matching.len()
    );
    let output = Path::new(&arguments[3]);
    let materialization =
        package_approved_git(matching[0], &catalog.registries.cargo_version, output)?;
    info!(
        archive_sha256 = materialization.archive_sha256,
        index_record_sha256 = materialization.index_record_sha256,
        path = %output.display(),
        "reproduced approved Git-tag package"
    );
    Ok(())
}

fn load_catalog(path: &OsStr) -> Result<Catalog> {
    Catalog::load(Path::new(path))
}

fn parse_version(value: &OsStr, description: &str) -> Result<Version> {
    let value = utf8(value, description)?;
    Version::parse(value).with_context(|| format!("invalid {description} {value:?}"))
}

fn utf8<'a>(value: &'a OsStr, description: &str) -> Result<&'a str> {
    value
        .to_str()
        .with_context(|| format!("{description} is not valid UTF-8"))
}

fn ensure_arity(arguments: &[OsString], minimum: usize, maximum: usize) -> Result<()> {
    ensure!(
        (minimum..=maximum).contains(&arguments.len()),
        "wrong number of arguments\n{USAGE}"
    );
    Ok(())
}
