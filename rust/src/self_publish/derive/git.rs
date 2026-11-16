//! Fetching one immutable release tag into a fresh checkout.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail, ensure};
use tracing::debug;

use super::super::isolation::ChildEnvironment;
use crate::package::ensure_safe_checkout_tree;
use crate::policy::{validate_git_object_id, validate_git_tag, validate_https_repository};

/// Maximum number of bytes of a failed command's output that an error keeps.
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;

/// A checkout of exactly one tag, as immutable release evidence.
pub(super) struct TagCheckout {
    /// Root of the fresh checkout.
    pub(super) root: PathBuf,
    /// Exact tag object ID; equals the commit for a lightweight tag.
    pub(super) tag_oid: String,
    /// Full peeled commit object ID.
    pub(super) commit: String,
}

/// Fetches one tag into a fresh checkout and returns its exact object IDs.
///
/// `repository` is the credential-free HTTPS URL the catalog records;
/// `fetch_repository` is where Git fetches from, which differs from it only in
/// tests, where `allow_file` also permits a `file:` URL.
///
/// # Errors
///
/// Returns an error for an unsafe repository or tag, a fetch that fails, a tag
/// that is not an object ID, a checkout with submodules, symlinks, or unsafe
/// paths, or a checkout that is not clean.
pub(super) fn fetch_tag(
    repository: &str,
    tag: &str,
    checkout: &Path,
    fetch_repository: &str,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Result<TagCheckout> {
    validate_https_repository(repository)?;
    validate_git_tag(tag)?;
    run_git(
        None,
        [
            OsString::from("init"),
            OsString::from("--quiet"),
            checkout.as_os_str().to_owned(),
        ],
        environment,
        allow_file,
    )?;
    run_git(
        Some(checkout),
        [
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            OsString::from(fetch_repository),
        ],
        environment,
        allow_file,
    )?;
    let reference = format!("refs/tags/{tag}");
    run_git(
        Some(checkout),
        [
            OsString::from("fetch"),
            OsString::from("--quiet"),
            OsString::from("--no-tags"),
            OsString::from("--depth=1"),
            OsString::from("origin"),
            OsString::from(format!("{reference}:{reference}")),
        ],
        environment,
        allow_file,
    )?;
    let tag_oid = git_stdout(
        checkout,
        [
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(&reference),
        ],
        environment,
        allow_file,
    )?;
    let commit = git_stdout(
        checkout,
        [
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(format!("{reference}^{{commit}}")),
        ],
        environment,
        allow_file,
    )?;
    validate_git_object_id(&tag_oid).context("invalid fetched Git tag object ID")?;
    validate_git_object_id(&commit).context("invalid fetched Git commit ID")?;
    run_git(
        Some(checkout),
        [
            OsString::from("checkout"),
            OsString::from("--quiet"),
            OsString::from("--detach"),
            OsString::from(&commit),
            OsString::from("--"),
        ],
        environment,
        allow_file,
    )?;
    let gitlinks = git_stdout(
        checkout,
        [OsString::from("ls-files"), OsString::from("--stage")],
        environment,
        allow_file,
    )?;
    ensure!(
        !gitlinks.lines().any(|line| line.starts_with("160000 ")),
        "release tag checkout contains unsupported submodules"
    );
    ensure_safe_checkout_tree(checkout)?;
    ensure_clean_checkout(checkout, environment, allow_file)?;
    let root_manifest = checkout.join("Cargo.toml");
    ensure!(
        fs::symlink_metadata(&root_manifest)
            .with_context(|| format!("inspect root manifest {}", root_manifest.display()))?
            .file_type()
            .is_file(),
        "release tag checkout has no regular root Cargo.toml"
    );
    Ok(TagCheckout {
        root: checkout.to_path_buf(),
        tag_oid,
        commit,
    })
}

/// Refuses a checkout with unstaged, staged, or untracked changes.
///
/// # Errors
///
/// Returns an error when Git reports any change, so that only the exact tag
/// contents are read.
pub(super) fn ensure_clean_checkout(
    checkout: &Path,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Result<()> {
    let status = git_stdout(
        checkout,
        [
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
            OsString::from("--untracked-files=all"),
        ],
        environment,
        allow_file,
    )?;
    ensure!(status.is_empty(), "release tag checkout is dirty: {status}");
    Ok(())
}

fn run_git<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_command(
        git_command(current_dir, arguments, environment, allow_file),
        "run Git command",
    )?;
    Ok(())
}

fn git_stdout<I, S>(
    current_dir: &Path,
    arguments: I,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_command(
        git_command(Some(current_dir), arguments, environment, allow_file),
        "run Git command",
    )?;
    let value = String::from_utf8(output.stdout).context("Git command wrote non-UTF-8 output")?;
    Ok(value.trim().to_owned())
}

/// Builds one Git command with the safety policy of the tag fetch.
fn git_command<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let file_policy = if allow_file { "always" } else { "never" };
    let mut command = Command::new("git");
    command
        .args([
            OsStr::new("-c"),
            OsStr::new("core.hooksPath=/dev/null"),
            OsStr::new("-c"),
            OsStr::new("protocol.allow=never"),
            OsStr::new("-c"),
            OsStr::new("protocol.https.allow=always"),
            OsStr::new("-c"),
            OsStr::new(&format!("protocol.file.allow={file_policy}")),
        ])
        .args(arguments);
    environment.apply_with(
        &mut command,
        &[
            ("GIT_TERMINAL_PROMPT", OsStr::new("0")),
            ("GIT_CONFIG_NOSYSTEM", OsStr::new("1")),
            ("GIT_CONFIG_GLOBAL", OsStr::new("/dev/null")),
        ],
    );
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command
}

fn run_command(mut command: Command, action: &str) -> Result<Output> {
    debug!(?command, %action, "running isolated self-publishing command");
    let output = command
        .output()
        .with_context(|| format!("{action}: start command"))?;
    if !output.status.success() {
        let stdout = bounded_lossy(&output.stdout);
        let stderr = bounded_lossy(&output.stderr);
        bail!(
            "{action}: command exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
    Ok(output)
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}
