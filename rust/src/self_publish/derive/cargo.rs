//! The isolated Cargo home and the packaging of one release.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::JoinHandle;

use anyhow::{Context, Result, bail, ensure};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
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
/// Directory of the isolated Cargo home that uploads to crates.io.
pub(super) const UPLOAD_CARGO_HOME_DIRECTORY: &str = "upload-cargo-home";
/// Target directories of the two packaging runs.
const TARGET_DIRECTORIES: [&str; 2] = ["target-one", "target-two"];

/// How the isolated Cargo home resolves the registries of one packaging run.
#[derive(Clone, Debug)]
pub(super) enum RegistrySources {
    /// Plain crates.io, as the derivation packages a release.
    CratesIo,
    /// A local registry that serves both registries from one Git index, so that
    /// a test needs no network.
    #[cfg(test)]
    Local(PathBuf),
    /// The same local registry, and the curated registry as the default, as the
    /// reconciler's own packaging configures a checkout whose manifests declare
    /// `registry = "pkgre"`.
    #[cfg(test)]
    LocalCurated(PathBuf),
}

impl RegistrySources {
    /// Returns the root of the local registry, if a test named one.
    #[cfg(test)]
    pub(super) fn local_root(&self) -> Option<&Path> {
        match self {
            Self::Local(root) | Self::LocalCurated(root) => Some(root),
            Self::CratesIo => None,
        }
    }
}

/// Returns the registries that one derivation resolves its packages from.
#[cfg_attr(not(test), allow(unused_variables))]
pub(super) fn registry_sources(sources: super::Sources<'_>) -> RegistrySources {
    #[cfg(test)]
    if let Some(directory) = sources.directory() {
        return RegistrySources::Local(directory.to_path_buf());
    }
    RegistrySources::CratesIo
}

/// The variable through which Cargo's own test suite points crates.io at another
/// index.
///
/// It is Cargo's, not this program's: a test uses it so that crates.io keeps its
/// source id while resolving from a local Git index, which is what keeps Cargo's
/// temporary registry serving a crate of one release to the crates that depend on
/// it. A source replacement would bypass that registry, and production never sets
/// or passes this variable.
#[cfg(test)]
const CRATES_IO_TEST_VARIABLE: &str = "__CARGO_TEST_CRATES_IO_URL_DO_NOT_USE_THIS";

/// Points crates.io at a test's local index, which only a test does.
///
/// # Errors
///
/// Returns an error for a local source whose path is not UTF-8.
#[cfg(test)]
pub(super) fn with_test_crates_io(
    environment: ChildEnvironment,
    sources: &RegistrySources,
) -> Result<ChildEnvironment> {
    let Some(root) = sources.local_root() else {
        return Ok(environment);
    };
    Ok(environment.with_variable(CRATES_IO_TEST_VARIABLE, &local_index(root)?))
}

/// Writes the config of a fresh isolated Cargo home.
///
/// A test's home reads the curated registry from a local Git index, and crates.io
/// as a Git registry too, since Cargo's own testing hook points it at that index.
/// Neither registry is replaced, so Cargo's temporary registry still serves the
/// crates of one release to each other.
///
/// # Errors
///
/// Returns an error for a home that already exists, for a config that cannot be
/// written, or for a local index whose path is not UTF-8.
#[allow(clippy::needless_pass_by_value)]
#[cfg_attr(not(test), allow(unused_variables))]
pub(super) fn prepare_cargo_home(cargo_home: &Path, sources: RegistrySources) -> Result<()> {
    fs::create_dir(cargo_home)
        .with_context(|| format!("create isolated Cargo home {}", cargo_home.display()))?;
    #[cfg(test)]
    let local = sources.local_root().map(local_index).transpose()?;
    #[cfg(not(test))]
    let local: Option<String> = None;
    let index = local.as_deref().unwrap_or(CURATED_INDEX);
    let mut text = String::new();
    writeln!(text, "[registries]").expect("writing to a string");
    writeln!(text, "{CURATED_REGISTRY} = {{ index = \"{index}\" }}").expect("writing to a string");
    if local.is_some() {
        writeln!(text, "\n[registries.crates-io]\nprotocol = \"git\"")
            .expect("writing to a string");
    }
    #[cfg(test)]
    if matches!(sources, RegistrySources::LocalCurated(_)) {
        writeln!(text, "\n[registry]\ndefault = {CURATED_REGISTRY:?}")
            .expect("writing to a string");
    }
    let path = cargo_home.join("config.toml");
    fs::write(&path, text)
        .with_context(|| format!("write isolated Cargo config {}", path.display()))
}

/// Returns whether one Cargo source names one registry index.
///
/// Cargo writes a sparse registry's index URL without the `registry+` prefix in a
/// lock file, and a Git registry's with it; a manifest names the index alone.
pub(super) fn names_index(source: &str, index: &str) -> bool {
    source == index || source == format!("registry+{index}")
}

/// Returns the index that the run's Cargo home configures for the curated
/// registry.
///
/// A production run configures the registry's own sparse index; a test points it
/// at a local Git index, and the lock files then name that index.
///
/// # Errors
///
/// Returns an error for a local index whose path is not UTF-8.
#[cfg_attr(not(test), allow(clippy::unnecessary_wraps, unused_variables))]
pub(super) fn curated_index(sources: &RegistrySources) -> Result<String> {
    #[cfg(test)]
    if let Some(root) = sources.local_root() {
        return local_index(root);
    }
    Ok(CURATED_INDEX.to_owned())
}

/// Returns the `file:` URL of a test's local index.
///
/// # Errors
///
/// Returns an error for a path that is not UTF-8.
#[cfg(test)]
fn local_index(root: &Path) -> Result<String> {
    let index = root.join("index");
    let index = index
        .to_str()
        .with_context(|| format!("local index {} is not UTF-8", index.display()))?;
    Ok(format!("file://{index}"))
}

/// Writes the config of the isolated Cargo home that uploads to crates.io.
///
/// The home configures plain crates.io and the `cargo:token` credential
/// provider, and nothing else: no other registry, so `cargo publish` can only
/// reach crates.io, and the token comes from the environment of the one upload
/// process alone. A test points crates.io at its local index, so that the
/// packaging of the upload needs no network.
///
/// # Errors
///
/// Returns an error for a home that already exists, or for a config that cannot
/// be written.
pub(super) fn prepare_upload_cargo_home(
    cargo_home: &Path,
    sources: &RegistrySources,
) -> Result<()> {
    fs::create_dir(cargo_home)
        .with_context(|| format!("create isolated Cargo home {}", cargo_home.display()))?;
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut text = String::from("[registry]\ncredential-provider = [\"cargo:token\"]\n");
    #[cfg(test)]
    if sources.local_root().is_some() {
        write!(text, "\n[registries.crates-io]\nprotocol = \"git\"\n")
            .expect("writing to a string");
    }
    #[cfg(not(test))]
    let _ = sources;
    let path = cargo_home.join("config.toml");
    fs::write(&path, text)
        .with_context(|| format!("write isolated Cargo config {}", path.display()))
}

/// How one packaging run builds the crates it packages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Build {
    /// Package only, as `cargo publish` does, which runs no package code.
    Package,
    /// Package and build, which runs the package code of the release.
    Verify,
}

/// The flags of one packaging run: whether it builds, and whether it may
/// package a checkout whose manifests the derivation rewrote.
#[derive(Clone, Copy)]
pub(super) struct Options {
    pub(super) build: Build,
    pub(super) allow_dirty: bool,
}

/// Packages the named members of one checkout twice and returns the archives by
/// package name.
///
/// The working directory and the target directories are created below `root`,
/// which lies outside `checkout`. Both runs must produce identical bytes.
///
/// Cargo serves the crates of one packaging run to each other through a
/// temporary registry, so a crate of the release may depend on another one. A
/// test's directory source replaces that registry, and Cargo then looks the
/// sibling up in the directory alone, so [`package_once`] packages such a run
/// one crate at a time and lets the source serve each archive to the crates that
/// depend on it.
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
    allow_dirty: bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure_no_cargo_configuration(work)?;
    let manifest_path = checkout.join("Cargo.toml");
    let mut archives: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for directory in TARGET_DIRECTORIES {
        let target = targets.join(directory);
        package_once(
            cargo,
            environment,
            work,
            &target,
            &manifest_path,
            members,
            Options {
                build: Build::Package,
                allow_dirty,
            },
        )?;
        for (name, bytes) in read_archives(&target, members)? {
            match archives.get(&name) {
                Some(first) => ensure!(
                    first == &bytes,
                    "pinned Cargo produced non-deterministic archives for {name}"
                ),
                None => {
                    archives.insert(name, bytes);
                }
            }
        }
    }
    Ok(archives)
}

/// Packages the named members of one checkout into one target directory and
/// returns their archives by package name.
///
/// # Errors
///
/// Returns an error when Cargo fails, when an archive is missing or too large,
/// or, in a test, when the members cannot be ordered or added to the source.
pub(super) fn package_group(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    target: &Path,
    manifest_path: &Path,
    members: &[(String, Version)],
    options: Options,
) -> Result<BTreeMap<String, Vec<u8>>> {
    package_once(
        cargo,
        environment,
        work,
        target,
        manifest_path,
        members,
        options,
    )?;
    read_archives(target, members)
}

/// Packages the named members of one checkout into one target directory.
///
/// A production run packages them in one command, so that Cargo's temporary
/// registry serves each crate of the release to the crates that depend on it.
///
/// # Errors
///
/// Returns an error when Cargo fails, or, in a test, when the members cannot be
/// ordered or added to the source.
#[allow(clippy::too_many_arguments)]
fn package_once(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    target: &Path,
    manifest_path: &Path,
    members: &[(String, Version)],
    options: Options,
) -> Result<()> {
    let mut arguments = vec![
        OsString::from("package"),
        OsString::from("--locked"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
    ];
    if options.allow_dirty {
        arguments.push(OsString::from("--allow-dirty"));
    }
    if options.build == Build::Package {
        arguments.insert(1, OsString::from("--no-verify"));
    }
    for (name, _) in members {
        arguments.push(OsString::from("--package"));
        arguments.push(OsString::from(name));
    }
    run_build(cargo, environment, work, arguments, options.build)
}

/// Runs one packaging command, in its own process group when it builds.
///
/// # Errors
///
/// Returns an error when the command cannot be started or exits unsuccessfully.
fn run_build(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    arguments: Vec<OsString>,
    build: Build,
) -> Result<()> {
    match build {
        Build::Package => run_cargo(cargo, environment, work, arguments).map(|_| ()),
        Build::Verify => run_cargo_grouped(cargo, environment, work, arguments).map(|_| ()),
    }
}

/// Returns the archives that one packaging run wrote, by package name.
///
/// # Errors
///
/// Returns an error for an archive that is missing, not a regular file, or too
/// large.
fn read_archives(
    target: &Path,
    members: &[(String, Version)],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archives = BTreeMap::new();
    for (name, version) in members {
        let archive = target
            .join("package")
            .join(format!("{name}-{version}.crate"));
        ensure!(
            fs::symlink_metadata(&archive)
                .with_context(|| format!("inspect Cargo archive {}", archive.display()))?
                .file_type()
                .is_file(),
            "Cargo did not produce a regular archive at {}",
            archive.display()
        );
        archives.insert(name.clone(), read_bounded_archive(&archive)?);
    }
    Ok(archives)
}

/// Runs one Cargo command in the isolated environment and returns its output.
///
/// The command gets a null standard input, which `output` arranges, so that a
/// token piped to the routine is never in reach of Cargo: the derivation's
/// packaging and the no-verify packaging of the upload both run this way.
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
    let mut command = cargo_command(cargo, environment, work, arguments);
    debug!(?command, "running isolated Cargo command");
    let output = command.output().context("start the pinned Cargo")?;
    require_success(output)
}

/// Runs one Cargo command that executes package code in a process group of its
/// own, and ends whatever the package code left in that group.
///
/// The command gets a null standard input, so that a token piped to the routine
/// cannot be read through Cargo's own `/proc` entry, and its output is captured:
/// Cargo runs fresh and dumpable, and its environment is what the packages
/// build with. Both pipes are read on their own threads, so that a process the
/// package code left holding one of them cannot keep the routine from ending
/// the group.
///
/// A build script or a proc macro can start a process that keeps running after
/// Cargo returns. Such a process would still see the environment of the upload
/// that follows, so the run ends the group here rather than leaving it to the
/// end of the routine. A process that detaches itself from the group is out of
/// reach, which the security model records as a residual risk.
///
/// # Errors
///
/// Returns an error when the command cannot be started or exits unsuccessfully;
/// the error carries the last bytes of the captured output.
pub(super) fn run_cargo_grouped(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Vec<u8>> {
    let mut command = cargo_command(cargo, environment, work, arguments);
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    debug!(
        ?command,
        "running isolated Cargo command in its own process group"
    );
    let mut child = command.spawn().context("start the pinned Cargo")?;
    let group = i32::try_from(child.id()).context("a child process ID is out of range")?;
    let stdout = child
        .stdout
        .take()
        .context("the pinned Cargo has no standard output")?;
    let stderr = child
        .stderr
        .take()
        .context("the pinned Cargo has no standard error")?;
    let stdout = read_on_thread(stdout);
    let stderr = read_on_thread(stderr);
    let status = child.wait().context("wait for the pinned Cargo")?;
    // Whatever the package code started stays in the child's group, which is
    // now empty of Cargo itself. The readers are joined afterwards, so that a
    // process still holding a pipe cannot delay the kill.
    if let Err(error) = killpg(Pid::from_raw(group), Signal::SIGKILL) {
        debug!(%error, "the process group of the packaging had already ended");
    }
    require_success(Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// Reads one stream of a child process on its own thread.
fn read_on_thread(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        bytes
    })
}

/// Builds one Cargo command in the isolated environment.
fn cargo_command(
    cargo: &Path,
    environment: &ChildEnvironment,
    work: &Path,
    arguments: impl IntoIterator<Item = OsString>,
) -> Command {
    let mut command = Command::new(cargo);
    command.current_dir(work).args(arguments);
    environment.apply_with(
        &mut command,
        &[
            ("CARGO_TERM_COLOR", OsStr::new("never")),
            ("CARGO_NET_GIT_FETCH_WITH_CLI", OsStr::new("false")),
        ],
    );
    command
}

/// Returns the output of one successful Cargo command.
///
/// # Errors
///
/// Returns an error naming the exit status and the last bytes of the output when
/// the command failed.
fn require_success(output: Output) -> Result<Vec<u8>> {
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
