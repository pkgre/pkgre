//! Git child processes with the safety policy of the self-publishing workflow.
//!
//! Every Git command starts from an empty environment with the allowlist of
//! [`ChildEnvironment`], runs no hook, and reaches only HTTPS; only a test
//! permits a `file:` URL, so that a fixture repository needs no network.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use tracing::debug;

use super::isolation::ChildEnvironment;

/// Maximum number of bytes of a failed command's output that an error keeps.
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;

/// Builds one Git command with the safety policy of the workflow.
///
/// `current_dir` is where Git runs, absent for a command that names its
/// directory as an argument, such as `git init`. `allow_file` permits a
/// `file:` URL, which only a test does.
///
/// A transfer that stops making progress is aborted: `http.lowSpeedLimit` and
/// `http.lowSpeedTime` end an HTTP transfer below 1000 bytes per second for 60
/// seconds. Git has no overall time limit, so a transfer that keeps making
/// progress is not interrupted.
///
/// Automatic maintenance is off, so that no `git gc` or `git maintenance` runs
/// in the background after a fetch: such a process would outlive the command
/// that started it.
pub(super) fn command<I, S>(
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
            OsStr::new("gc.auto=0"),
            OsStr::new("-c"),
            OsStr::new("maintenance.auto=false"),
            OsStr::new("-c"),
            OsStr::new("protocol.allow=never"),
            OsStr::new("-c"),
            OsStr::new("protocol.https.allow=always"),
            OsStr::new("-c"),
            OsStr::new(&format!("protocol.file.allow={file_policy}")),
            OsStr::new("-c"),
            OsStr::new("http.lowSpeedLimit=1000"),
            OsStr::new("-c"),
            OsStr::new("http.lowSpeedTime=60"),
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

/// Runs one Git command and requires it to succeed.
///
/// # Errors
///
/// Returns an error when the command cannot be started or exits unsuccessfully.
pub(super) fn run<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = spawn(
        command(current_dir, arguments, environment, allow_file),
        "run Git command",
    )?;
    require_success(&output, "run Git command")
}

/// Runs one Git command and returns its trimmed standard output.
///
/// # Errors
///
/// Returns an error when the command cannot be started, exits unsuccessfully,
/// or writes output that is not UTF-8.
pub(super) fn stdout<I, S>(
    current_dir: &Path,
    arguments: I,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = spawn(
        command(Some(current_dir), arguments, environment, allow_file),
        "run Git command",
    )?;
    require_success(&output, "run Git command")?;
    let value = String::from_utf8(output.stdout).context("Git command wrote non-UTF-8 output")?;
    Ok(value.trim().to_owned())
}

/// Runs one Git command and returns its output, whatever its status.
///
/// # Errors
///
/// Returns an error when the command cannot be started.
pub(super) fn spawn(mut command: Command, action: &str) -> Result<Output> {
    debug!(?command, %action, "running isolated Git command");
    command
        .output()
        .with_context(|| format!("{action}: start command"))
}

/// Requires that one Git command succeeded.
///
/// # Errors
///
/// Returns an error naming the exit status and the last bytes of the command's
/// output when it failed.
pub(super) fn require_success(output: &Output, action: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stdout = bounded_lossy(&output.stdout);
    let stderr = bounded_lossy(&output.stderr);
    bail!(
        "{action}: command exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    )
}

/// Keeps the last bytes of a failed command's output in its error.
fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}
