//! The isolated Cargo home and the packaging of one release.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use tracing::debug;

use super::super::isolation::{ChildEnvironment, ensure_no_cargo_configuration};
use crate::package::read_bounded_archive;

/// The curated registry that the tagged manifests resolve from.
pub(super) const CURATED_REGISTRY: &str = "pkgre";
/// Index of the curated registry.
pub(super) const CURATED_INDEX: &str = "sparse+https://rust.pkg.re/";
/// Index of crates.io, as a Cargo lock file spells the full form.
pub(super) const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";
/// Directory of the isolated Cargo home inside a derivation's temporary root.
pub(super) const CARGO_HOME_DIRECTORY: &str = "cargo-home";
/// Target directories of the two packaging runs.
const TARGET_DIRECTORIES: [&str; 2] = ["target-one", "target-two"];

/// How the isolated Cargo home resolves the registries of one packaging run.
#[derive(Clone, Copy, Debug)]
pub(super) enum RegistrySources<'a> {
    /// Plain crates.io, as the derivation packages a release.
    CratesIo,
    /// A local directory source that replaces crates.io and the curated
    /// registry, so that a test needs no network.
    Local(&'a Path),
    /// A local directory source that replaces both registries and makes the
    /// curated registry the default, as the reconciler's own packaging
    /// configures a checkout whose manifests declare `registry = "pkgre"`.
    #[cfg_attr(not(test), allow(dead_code))]
    LocalCurated(&'a Path),
}

/// Writes the config of a fresh isolated Cargo home.
///
/// # Errors
///
/// Returns an error for a home that already exists, or for a config that cannot
/// be written.
pub(super) fn prepare_cargo_home(cargo_home: &Path, sources: RegistrySources<'_>) -> Result<()> {
    fs::create_dir(cargo_home)
        .with_context(|| format!("create isolated Cargo home {}", cargo_home.display()))?;
    let mut text = String::new();
    writeln!(text, "[registries]").expect("writing to a string");
    writeln!(
        text,
        "{CURATED_REGISTRY} = {{ index = \"{CURATED_INDEX}\" }}"
    )
    .expect("writing to a string");
    if matches!(sources, RegistrySources::LocalCurated(_)) {
        writeln!(text, "\n[registry]\ndefault = {CURATED_REGISTRY:?}")
            .expect("writing to a string");
    }
    match sources {
        RegistrySources::CratesIo => {}
        RegistrySources::Local(directory) | RegistrySources::LocalCurated(directory) => {
            let directory = directory.to_str().with_context(|| {
                format!("local Cargo source {} is not UTF-8", directory.display())
            })?;
            writeln!(text, "\n[source.crates-io]\nreplace-with = \"local\"")
                .expect("writing to a string");
            if matches!(sources, RegistrySources::LocalCurated(_)) {
                writeln!(
                    text,
                    "\n[source.{CURATED_REGISTRY}]\nregistry = \"{CURATED_INDEX}\"\nreplace-with = \"local\""
                )
                .expect("writing to a string");
            }
            writeln!(text, "\n[source.local]\ndirectory = {directory:?}")
                .expect("writing to a string");
            // A test that misses a dependency must fail rather than reach the
            // network of the machine that runs it.
            writeln!(text, "\n[net]\noffline = true").expect("writing to a string");
        }
    }
    let path = cargo_home.join("config.toml");
    fs::write(&path, text)
        .with_context(|| format!("write isolated Cargo config {}", path.display()))
}

/// Packages the named members of one checkout twice and returns the archives by
/// package name.
///
/// The working directory and the target directories are created below `root`,
/// which lies outside `checkout`. Both runs must produce identical bytes.
///
/// # Errors
///
/// Returns an error when Cargo configuration covers the working directory, when
/// Cargo fails, when an archive is missing or too large, or when the two runs
/// differ.
pub(super) fn package_members(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    targets: &Path,
    checkout: &Path,
    members: &[(String, Version)],
) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure_no_cargo_configuration(work)?;
    let manifest_path = checkout.join("Cargo.toml");
    let mut archives: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for directory in TARGET_DIRECTORIES {
        let target = targets.join(directory);
        let mut arguments = vec![
            OsString::from("package"),
            OsString::from("--no-verify"),
            OsString::from("--locked"),
            OsString::from("--allow-dirty"),
            OsString::from("--manifest-path"),
            manifest_path.as_os_str().to_owned(),
            OsString::from("--target-dir"),
            target.as_os_str().to_owned(),
        ];
        for (name, _) in members {
            arguments.push(OsString::from("--package"));
            arguments.push(OsString::from(name));
        }
        run_cargo(cargo, environment, work, arguments)?;
        for (name, version) in members {
            let archive = target
                .join("package")
                .join(format!("{name}-{version}.crate"));
            let bytes = read_bounded_archive(&archive)?;
            match archives.get(name) {
                Some(first) => ensure!(
                    first == &bytes,
                    "pinned Cargo produced non-deterministic archives for {name} {version}"
                ),
                None => {
                    archives.insert(name.clone(), bytes);
                }
            }
        }
    }
    Ok(archives)
}

/// Runs one Cargo command in the isolated environment and returns its output.
///
/// # Errors
///
/// Returns an error when the command cannot be started or exits unsuccessfully.
pub(super) fn run_cargo(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Vec<u8>> {
    let mut command = Command::new(cargo);
    command.current_dir(work).args(arguments);
    environment.apply_with(
        &mut command,
        &[
            ("CARGO_TERM_COLOR", OsStr::new("never")),
            ("CARGO_NET_GIT_FETCH_WITH_CLI", OsStr::new("false")),
        ],
    );
    debug!(?command, "running isolated Cargo command");
    let output = command.output().context("start the pinned Cargo")?;
    if !output.status.success() {
        let stdout = bounded_lossy(&output.stdout);
        let stderr = bounded_lossy(&output.stderr);
        bail!(
            "pinned Cargo exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
    Ok(output.stdout)
}

/// Returns the isolated Cargo home of one temporary root.
pub(super) fn cargo_home(root: &Path) -> PathBuf {
    root.join(CARGO_HOME_DIRECTORY)
}

/// Keeps the last bytes of a failed command's output in its error.
fn bounded_lossy(bytes: &[u8]) -> String {
    const LIMIT: usize = 16 * 1024;
    let start = bytes.len().saturating_sub(LIMIT);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}
