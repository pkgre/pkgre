//! The live services of the upload routine: the token prompt and the upload.
//!
//! The token is read from a prompt that does not echo when standard input is a
//! terminal, and from one line of standard input otherwise; it is never read
//! from the routine's environment, its command line, or a file. It reaches one
//! child process at a time, through that process's environment alone, and every
//! occurrence of it in that process's output is replaced before the routine
//! reports anything.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};

use super::super::isolation::ChildEnvironment;
use super::{Token, TokenSource, UploadRequest, Uploader};

/// Maximum number of bytes of a failed upload's output that an error keeps.
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;

/// Uploads one crate version with `cargo publish`.
///
/// The command packages the crate in the rewritten workspace and uploads it
/// with `--no-verify`, so no package code runs while the token is in the
/// process's environment; its standard input is null, so a token piped to the
/// routine never reaches it. The isolated Cargo home configures plain crates.io
/// and the `cargo:token` credential provider, and the token is added to this one
/// process's environment.
pub(crate) struct LiveUploader;

impl Uploader for LiveUploader {
    fn publish(&self, request: &UploadRequest<'_>) -> Result<()> {
        let upload = request.environment;
        let mut command = Command::new(&upload.cargo);
        command.current_dir(&upload.work).args([
            OsStr::new("publish"),
            OsStr::new("--no-verify"),
            OsStr::new("--locked"),
            OsStr::new("--allow-dirty"),
            OsStr::new("--manifest-path"),
            upload.manifest.as_os_str(),
            OsStr::new("--target-dir"),
            upload.target.as_os_str(),
            OsStr::new("--package"),
            OsStr::new(request.crates_io_name),
        ]);
        upload.environment.apply_with(
            &mut command,
            &[
                ("CARGO_TERM_COLOR", OsStr::new("never")),
                ("CARGO_NET_GIT_FETCH_WITH_CLI", OsStr::new("false")),
                ("CARGO_REGISTRY_TOKEN", OsStr::new(request.token.expose())),
            ],
        );
        // The command's own `Debug` output carries the token, so the routine
        // logs what it uploads, never the command.
        tracing::info!(
            crates_io_name = request.crates_io_name,
            version = %request.version,
            "uploading a crate to crates.io"
        );
        let output = command.output().with_context(|| {
            format!(
                "start cargo publish for crate {} {}",
                request.crates_io_name, request.version
            )
        })?;
        if !output.status.success() {
            bail!(
                "cargo publish of crate {} {} exited with {}; the crate was not uploaded:\n{}",
                request.crates_io_name,
                request.version,
                output.status,
                redacted_tail(request.token, &output.stderr)
            );
        }
        Ok(())
    }
}

/// Reads the crates.io token from a prompt, or from standard input.
///
/// Standard input is read as one line, so a password manager can pipe the
/// token. On a terminal the prompt goes to standard error and `stty` turns the
/// terminal's echo off around the read, so the token never appears on screen.
pub(crate) struct PromptToken;

impl TokenSource for PromptToken {
    fn read(&self) -> Result<Token> {
        read_token()
    }
}

/// Reads one line of the token, hiding it on a terminal.
fn read_token() -> Result<Token> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.is_terminal() {
        write!(std::io::stderr(), "crates.io token: ").context("write the token prompt")?;
        std::io::stderr()
            .flush()
            .context("write the token prompt")?;
        let hidden = HiddenEcho::enable()?;
        let read = stdin.lock().read_line(&mut line);
        drop(hidden);
        writeln!(std::io::stderr()).context("write the token prompt")?;
        read.context("read the crates.io token from the terminal")?;
    } else {
        stdin
            .lock()
            .read_line(&mut line)
            .context("read the crates.io token from standard input")?;
    }
    Token::new(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Hides what the terminal echoes while it lives, and restores the terminal's
/// own state when dropped.
///
/// The state comes from `stty -g` before the echo is turned off, so a terminal
/// that started with the echo off keeps it off. The signals that would end the
/// process without unwinding stay blocked while the echo is off; they are
/// delivered as soon as the terminal is restored, so an interrupt at the prompt
/// still ends the run.
struct HiddenEcho {
    /// The terminal state that `stty -g` printed before the echo was turned off.
    saved: String,
    /// The signals that stay blocked while the echo is off.
    blocked: SigSet,
}

impl HiddenEcho {
    /// Turns the terminal's echo off.
    fn enable() -> Result<Self> {
        let saved = stty_stdout(&["-g"])?;
        ensure!(
            !saved.is_empty(),
            "stty printed no terminal state, so the token's echo cannot be hidden"
        );
        let blocked = block_terminal_signals()?;
        if let Err(error) = stty(&["-echo"]) {
            let _ = unblock_terminal_signals(&blocked);
            return Err(error);
        }
        Ok(Self { saved, blocked })
    }
}

impl Drop for HiddenEcho {
    fn drop(&mut self) {
        if let Err(error) = stty(&[self.saved.as_str()]) {
            writeln!(
                std::io::stderr(),
                "could not restore the terminal: {error:#}"
            )
            .ok();
        }
        if let Err(error) = unblock_terminal_signals(&self.blocked) {
            writeln!(
                std::io::stderr(),
                "could not unblock the terminal's signals: {error:#}"
            )
            .ok();
        }
    }
}

/// Blocks the signals that would end or stop the process without unwinding.
///
/// # Errors
///
/// Returns an error when the signal mask cannot be changed.
fn block_terminal_signals() -> Result<SigSet> {
    let mut signals = SigSet::empty();
    for signal in [
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGHUP,
        Signal::SIGQUIT,
        Signal::SIGTSTP,
    ] {
        signals.add(signal);
    }
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .context("block the terminal's signals while the echo is off")?;
    Ok(signals)
}

/// Unblocks the signals that [`block_terminal_signals`] blocked.
///
/// # Errors
///
/// Returns an error when the signal mask cannot be changed.
fn unblock_terminal_signals(signals: &SigSet) -> Result<()> {
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(signals), None)
        .context("unblock the terminal's signals")
}

/// Runs `stty` with one set of modes on the terminal behind `/dev/tty`.
fn stty(modes: &[&str]) -> Result<()> {
    let output = stty_command(modes)?.output().context("run stty")?;
    ensure!(
        output.status.success(),
        "stty exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Runs `stty` with one set of modes on the terminal and returns what it
/// printed.
fn stty_stdout(modes: &[&str]) -> Result<String> {
    let output = stty_command(modes)?.output().context("run stty")?;
    ensure!(
        output.status.success(),
        "stty exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)
        .context("stty wrote a non-UTF-8 terminal state")?
        .trim()
        .to_owned())
}

/// Builds one `stty` command on the terminal behind `/dev/tty`.
fn stty_command(modes: &[&str]) -> Result<Command> {
    let terminal = File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("open /dev/tty, which stty hides the token's echo with")?;
    let mut command = Command::new("stty");
    command
        .args(modes)
        .stdin(Stdio::from(terminal))
        .stdout(Stdio::piped());
    ChildEnvironment::plain().apply(&mut command);
    Ok(command)
}

/// Keeps the last bytes of an upload's output in its error, with every
/// occurrence of the token already replaced.
///
/// The replacement happens before the bound, so a cut never leaves part of a
/// token in the message.
fn redacted_tail(token: &Token, bytes: &[u8]) -> String {
    let text = token.redact(&String::from_utf8_lossy(bytes));
    let mut start = text.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}
