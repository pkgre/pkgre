//! Credential-free, inert archive-to-Git source correspondence.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::Serialize;
use tracing::debug;

use crate::artifact::sha256_bytes;

use super::{ApiVersionEvidence, ArchiveAnalysis, ArchiveFile, SourceEvidence};

const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;
const MAX_GIT_METADATA_BYTES: usize = 64 * 1024;
const MAX_GIT_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_GIT_FETCH_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const COMMAND_CLEANUP_GRACE: Duration = Duration::from_secs(5);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Attempts promoted mechanical correspondence between one inert crate analysis and an exact public Git commit.
///
/// Missing/unsupported anchors and public fetch failures produce `Unavailable`; an anchor disagreement or unexplained archive-to-tree difference produces `Mismatch`. Candidate code, hooks, checkouts, submodules, and build tools are never executed.
///
/// # Errors
///
/// Returns an error only when deterministic local evidence construction fails.
pub fn verify_source_correspondence(
    archive: &ArchiveAnalysis,
    api: Option<&ApiVersionEvidence>,
) -> Result<SourceEvidence> {
    let Some(api) = api else {
        return Ok(unavailable("crates-io-api-evidence-unavailable"));
    };
    let (repository, commit, path, attestation) = if let Some(trusted) = &api.trusted_publishing {
        let Ok(repository) = normalize_public_repository(&trusted.repository) else {
            return Ok(unavailable("trusted-publishing-repository-is-unsupported"));
        };
        if let Some(api_repository) = api.repository.as_deref() {
            let Ok(api_repository) = normalize_public_repository(api_repository) else {
                return Ok(mismatch("source-anchor-disagreement"));
            };
            if api_repository != repository {
                return Ok(mismatch("source-anchor-disagreement"));
            }
        }
        if archive
            .vcs
            .as_ref()
            .is_some_and(|vcs| vcs.commit != trusted.commit)
        {
            return Ok(mismatch("source-anchor-disagreement"));
        }
        (
            repository,
            trusted.commit.as_str(),
            archive
                .vcs
                .as_ref()
                .and_then(|vcs| vcs.path_in_vcs.as_deref())
                .unwrap_or(""),
            Some(trusted.evidence_sha256.as_str()),
        )
    } else {
        let Some(vcs) = &archive.vcs else {
            return Ok(unavailable("archive-has-no-vcs-commit"));
        };
        let Some(repository_value) = api.repository.as_deref() else {
            return Ok(unavailable("version-has-no-supported-repository"));
        };
        let Ok(repository) = normalize_public_repository(repository_value) else {
            return Ok(unavailable("version-repository-is-unsupported"));
        };
        (
            repository,
            vcs.commit.as_str(),
            vcs.path_in_vcs.as_deref().unwrap_or(""),
            None,
        )
    };
    let checkout = match PublicGitTree::fetch(&repository, commit) {
        Ok(value) => value,
        Err(error) => {
            debug!(%repository, %commit, error = %format_args!("{error:#}"), "public Git source fetch unavailable");
            return Ok(unavailable("public-git-fetch-failed"));
        }
    };
    let comparison = compare_archive_to_tree(archive, path, &checkout)?;
    if !comparison.matches {
        return Ok(SourceEvidence::Mismatch {
            comparison_sha256: comparison.sha256,
        });
    }
    if let Some(attestation_sha256) = attestation {
        Ok(SourceEvidence::RegistryContextAttested {
            repository,
            commit: commit.to_owned(),
            path: path.to_owned(),
            comparison_sha256: comparison.sha256,
            attestation_sha256: attestation_sha256.to_owned(),
        })
    } else {
        Ok(SourceEvidence::PublisherAsserted {
            repository,
            commit: commit.to_owned(),
            path: path.to_owned(),
            comparison_sha256: comparison.sha256,
        })
    }
}

fn unavailable(reason: &str) -> SourceEvidence {
    SourceEvidence::Unavailable {
        reason: reason.to_owned(),
    }
}

fn mismatch(reason: &str) -> SourceEvidence {
    SourceEvidence::Mismatch {
        comparison_sha256: sha256_bytes(reason.as_bytes()),
    }
}

fn normalize_public_repository(value: &str) -> Result<String> {
    ensure!(
        value == value.trim() && value.is_ascii(),
        "repository URL is noncanonical"
    );
    ensure!(
        !value.bytes().any(|byte| byte.is_ascii_whitespace()),
        "repository URL contains whitespace"
    );
    let rest = value
        .strip_prefix("https://")
        .context("repository does not use HTTPS")?;
    ensure!(
        !rest.contains(['?', '#', '@', '\\']),
        "repository URL contains unsupported syntax"
    );
    let (host, raw_path) = rest.split_once('/').context("repository URL has no path")?;
    ensure!(
        matches!(host, "github.com" | "gitlab.com"),
        "repository host is unsupported"
    );
    let path = raw_path.strip_suffix(".git").unwrap_or(raw_path);
    let components = path.split('/').collect::<Vec<_>>();
    ensure!(
        components.len() >= 2
            && components.iter().all(|component| {
                !component.is_empty()
                    && *component != "."
                    && *component != ".."
                    && component.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            }),
        "repository identity is unsafe or noncanonical"
    );
    Ok(format!("https://{host}/{path}"))
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ComparisonReport {
    path_in_vcs: String,
    files: Vec<FileComparison>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct FileComparison {
    archive_path: String,
    repository_path: Option<String>,
    archive_sha256: String,
    repository_sha256: Option<String>,
    archive_executable: bool,
    repository_executable: Option<bool>,
    disposition: &'static str,
}

struct ComparisonResult {
    matches: bool,
    sha256: String,
}

trait GitTree {
    fn blob(&self, path: &str) -> Result<Option<GitBlob>>;
}

struct GitBlob {
    sha256: String,
    executable: bool,
}

fn compare_archive_to_tree(
    archive: &ArchiveAnalysis,
    path_in_vcs: &str,
    tree: &impl GitTree,
) -> Result<ComparisonResult> {
    validate_vcs_path(path_in_vcs)?;
    let archive_paths = archive
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut files = Vec::with_capacity(archive.files.len());
    let mut matches = true;
    for file in &archive.files {
        if matches!(file.path.as_str(), ".cargo_vcs_info.json" | ".cargo-ok") {
            files.push(ignored_comparison(file));
            continue;
        }
        if is_generated_manifest(&file.path, &archive_paths) {
            files.push(ignored_comparison(file));
            continue;
        }
        let source_path = source_path_for_archive_file(&file.path);
        let repository_path = join_vcs_path(path_in_vcs, &source_path);
        let blob = tree.blob(&repository_path)?;
        let archive_executable = file.mode & 0o111 != 0;
        let disposition = match &blob {
            Some(blob) if blob.sha256 == file.sha256 && blob.executable == archive_executable => {
                "match"
            }
            Some(_) => {
                matches = false;
                "different"
            }
            None => {
                matches = false;
                "missing"
            }
        };
        files.push(FileComparison {
            archive_path: file.path.clone(),
            repository_path: Some(repository_path),
            archive_sha256: file.sha256.clone(),
            repository_sha256: blob.as_ref().map(|value| value.sha256.clone()),
            archive_executable,
            repository_executable: blob.as_ref().map(|value| value.executable),
            disposition,
        });
    }
    let report = ComparisonReport {
        path_in_vcs: path_in_vcs.to_owned(),
        files,
    };
    let canonical = serde_json::to_vec(&report).context("serialize source comparison report")?;
    Ok(ComparisonResult {
        matches,
        sha256: sha256_bytes(&canonical),
    })
}

fn ignored_comparison(file: &ArchiveFile) -> FileComparison {
    FileComparison {
        archive_path: file.path.clone(),
        repository_path: None,
        archive_sha256: file.sha256.clone(),
        repository_sha256: None,
        archive_executable: file.mode & 0o111 != 0,
        repository_executable: None,
        disposition: "cargo-generated",
    }
}

fn is_generated_manifest(path: &str, archive_paths: &BTreeSet<&str>) -> bool {
    let Some(directory) = path.strip_suffix("Cargo.toml") else {
        return false;
    };
    archive_paths.contains(format!("{directory}Cargo.toml.orig").as_str())
}

fn source_path_for_archive_file(path: &str) -> String {
    path.strip_suffix("Cargo.toml.orig")
        .map_or_else(|| path.to_owned(), |prefix| format!("{prefix}Cargo.toml"))
}

fn validate_vcs_path(path: &str) -> Result<()> {
    ensure!(!path.starts_with('/'), "VCS package path is absolute");
    ensure!(
        !path.contains('\\'),
        "VCS package path contains a backslash"
    );
    if path.is_empty() {
        return Ok(());
    }
    ensure!(
        path.split('/')
            .all(|component| !component.is_empty() && component != "." && component != ".."),
        "VCS package path is unsafe or noncanonical"
    );
    Ok(())
}

fn join_vcs_path(root: &str, path: &str) -> String {
    if root.is_empty() {
        path.to_owned()
    } else {
        format!("{root}/{path}")
    }
}

struct PublicGitTree {
    temporary: TemporaryDirectory,
    commit: String,
}

impl PublicGitTree {
    fn fetch(repository: &str, commit: &str) -> Result<Self> {
        ensure!(
            matches!(commit.len(), 40 | 64)
                && commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "source commit is not a canonical Git object ID"
        );
        let temporary = TemporaryDirectory::new("pkgre-source")?;
        run_git(
            None,
            [
                OsStr::new("init"),
                OsStr::new("--quiet"),
                temporary.path().as_os_str(),
            ],
        )?;
        run_git(
            Some(temporary.path()),
            [
                OsStr::new("fetch"),
                OsStr::new("--quiet"),
                OsStr::new("--no-tags"),
                OsStr::new("--depth=1"),
                OsStr::new(repository),
                OsStr::new(commit),
            ],
        )?;
        let resolved = run_git_output_with_limit(
            Some(temporary.path()),
            [
                OsStr::new("rev-parse"),
                OsStr::new("--verify"),
                OsStr::new("FETCH_HEAD^{commit}"),
            ],
            "resolve fetched Git commit",
            MAX_GIT_METADATA_BYTES,
        )?;
        let resolved = std::str::from_utf8(&resolved.stdout)
            .context("Git commit output is not UTF-8")?
            .trim_end_matches('\n');
        ensure!(
            resolved == commit,
            "fetched Git commit differs from exact anchor"
        );
        Ok(Self {
            temporary,
            commit: commit.to_owned(),
        })
    }
}

impl GitTree for PublicGitTree {
    fn blob(&self, path: &str) -> Result<Option<GitBlob>> {
        let pathspec = format!(":(literal){path}");
        let output = run_git_output_allow_failure_with_limit(
            Some(self.temporary.path()),
            [
                OsStr::new("ls-tree"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                OsStr::new(&self.commit),
                OsStr::new("--"),
                OsStr::new(&pathspec),
            ],
            "inspect exact Git tree path",
            MAX_GIT_METADATA_BYTES,
        )?;
        if !output.status.success() || output.stdout.is_empty() {
            return Ok(None);
        }
        ensure!(
            output.stdout.last() == Some(&0)
                && !output.stdout[..output.stdout.len() - 1].contains(&0),
            "Git tree lookup returned an ambiguous path"
        );
        let record = &output.stdout[..output.stdout.len() - 1];
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("Git tree record has no path separator")?;
        let metadata = &record[..separator];
        let observed_path = &record[separator + 1..];
        ensure!(
            observed_path == path.as_bytes(),
            "Git tree returned another path"
        );
        let metadata = std::str::from_utf8(metadata).context("Git tree metadata is not UTF-8")?;
        let mut fields = metadata.split(' ');
        let mode = fields.next().context("Git tree record has no mode")?;
        ensure!(fields.next() == Some("blob"), "Git tree path is not a blob");
        let object = fields.next().context("Git tree record has no object ID")?;
        ensure!(
            fields.next().is_none(),
            "Git tree record has extra metadata"
        );
        ensure!(
            matches!(mode, "100644" | "100755"),
            "Git tree path has unsupported mode"
        );
        let output = run_git_output_with_limit(
            Some(self.temporary.path()),
            [
                OsStr::new("cat-file"),
                OsStr::new("blob"),
                OsStr::new(object),
            ],
            "read exact Git blob",
            MAX_GIT_BLOB_BYTES,
        )?;
        ensure!(
            output.stdout.len() <= MAX_GIT_BLOB_BYTES,
            "Git blob exceeds {MAX_GIT_BLOB_BYTES} bytes"
        );
        Ok(Some(GitBlob {
            sha256: sha256_bytes(&output.stdout),
            executable: mode == "100755",
        }))
    }
}

fn run_git<I, S>(current_dir: Option<&Path>, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_git_output(current_dir, arguments, "run isolated Git command")?;
    Ok(())
}

fn run_git_output<I, S>(current_dir: Option<&Path>, arguments: I, action: &str) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_git_output_with_limit(current_dir, arguments, action, MAX_GIT_FETCH_OUTPUT_BYTES)
}

fn run_git_output_with_limit<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    action: &str,
    max_stdout_bytes: usize,
) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output =
        run_git_output_allow_failure_with_limit(current_dir, arguments, action, max_stdout_bytes)?;
    if output.status.success() {
        return Ok(output);
    }
    bail!(
        "{action}: Git exited with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        bounded_lossy(&output.stdout),
        bounded_lossy(&output.stderr)
    )
}

fn run_git_output_allow_failure_with_limit<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    action: &str,
    max_stdout_bytes: usize,
) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let command = git_command(current_dir, arguments);
    debug!(?command, %action, "running isolated source-verification command");
    run_bounded_command(
        command,
        action,
        GIT_COMMAND_TIMEOUT,
        max_stdout_bytes,
        MAX_GIT_FETCH_OUTPUT_BYTES,
    )
}

fn run_bounded_command(
    mut command: Command,
    action: &str,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("{action}: start command"))?;
    let process_group = Pid::from_raw(
        i32::try_from(child.id()).context("command process ID exceeds signed integer range")?,
    );
    let stdout = child.stdout.take().context("command has no stdout pipe")?;
    let stderr = child.stderr.take().context("command has no stderr pipe")?;
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let stdout_receiver = bounded_reader(stdout, max_stdout_bytes, Arc::clone(&stdout_overflow));
    let stderr_receiver = bounded_reader(stderr, max_stderr_bytes, Arc::clone(&stderr_overflow));
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("command timeout overflowed the monotonic clock")?;
    let status = loop {
        if stdout_overflow.load(Ordering::Acquire) || stderr_overflow.load(Ordering::Acquire) {
            terminate_process_group(&mut child, process_group);
            bail!("{action}: command output exceeded its configured bound");
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("{action}: wait for command"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_process_group(&mut child, process_group);
            bail!("{action}: command exceeded its {timeout:?} wall-clock timeout");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = receive_bounded_output(
        &stdout_receiver,
        action,
        "stdout",
        &mut child,
        process_group,
    )?;
    let stderr = receive_bounded_output(
        &stderr_receiver,
        action,
        "stderr",
        &mut child,
        process_group,
    )?;
    ensure!(
        !stdout_overflow.load(Ordering::Acquire) && !stderr_overflow.load(Ordering::Acquire),
        "{action}: command output exceeded its configured bound"
    );
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn bounded_reader(
    mut pipe: impl Read + Send + 'static,
    max_bytes: usize,
    overflow: Arc<AtomicBool>,
) -> Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(Ok(bytes));
                    return;
                }
                Ok(read) if read <= max_bytes.saturating_sub(bytes.len()) => {
                    bytes.extend_from_slice(&buffer[..read]);
                }
                Ok(_) => {
                    overflow.store(true, Ordering::Release);
                    let _ = sender.send(Err(io::Error::other(
                        "command stream exceeded its configured bound",
                    )));
                    return;
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
    });
    receiver
}

fn receive_bounded_output(
    receiver: &Receiver<io::Result<Vec<u8>>>,
    action: &str,
    stream: &str,
    child: &mut std::process::Child,
    process_group: Pid,
) -> Result<Vec<u8>> {
    match receiver.recv_timeout(COMMAND_CLEANUP_GRACE) {
        Ok(result) => result.with_context(|| format!("{action}: read command {stream}")),
        Err(error) => {
            terminate_process_group(child, process_group);
            bail!("{action}: command {stream} did not close after exit: {error}")
        }
    }
}

fn terminate_process_group(child: &mut std::process::Child, process_group: Pid) {
    let _ = killpg(process_group, Signal::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
}

fn git_command<I, S>(current_dir: Option<&Path>, arguments: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
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
            OsStr::new("protocol.file.allow=never"),
            OsStr::new("-c"),
            OsStr::new("credential.helper="),
            OsStr::new("-c"),
            OsStr::new("http.extraHeader="),
        ])
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_ASKPASS")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GITLAB_TOKEN")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY");
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Result<Self> {
        let parent = std::env::temp_dir();
        for _ in 0..100 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("{prefix}-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create temporary directory {}", path.display()));
                }
            }
        }
        bail!("could not allocate a unique source-verification directory")
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::update::EmbeddedVcsInfo;

    struct FakeTree {
        files: BTreeMap<String, GitBlob>,
    }

    impl GitTree for FakeTree {
        fn blob(&self, path: &str) -> Result<Option<GitBlob>> {
            Ok(self.files.get(path).map(|blob| GitBlob {
                sha256: blob.sha256.clone(),
                executable: blob.executable,
            }))
        }
    }

    fn file(path: &str, contents: &[u8]) -> ArchiveFile {
        ArchiveFile {
            path: path.to_owned(),
            size: contents.len() as u64,
            mode: 0o644,
            sha256: sha256_bytes(contents),
            binary: false,
        }
    }

    #[test]
    fn public_repository_normalization_is_narrow_and_canonical() {
        assert_eq!(
            normalize_public_repository("https://github.com/example/demo.git").unwrap(),
            "https://github.com/example/demo"
        );
        assert_eq!(
            normalize_public_repository("https://gitlab.com/group/subgroup/demo").unwrap(),
            "https://gitlab.com/group/subgroup/demo"
        );
        for value in [
            "http://github.com/example/demo",
            "https://user@github.com/example/demo",
            "https://example.com/example/demo",
            "https://github.com/example/../demo",
        ] {
            assert!(
                normalize_public_repository(value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn source_comparison_accounts_for_cargo_generated_files_and_manifest_original() {
        let archive = ArchiveAnalysis {
            compressed_bytes: 1,
            unpacked_bytes: 1,
            files: vec![
                file(".cargo_vcs_info.json", b"generated"),
                file("Cargo.toml", b"normalized"),
                file("Cargo.toml.orig", b"source manifest"),
                file("src/lib.rs", b"source"),
            ],
            build_surface: BTreeMap::new(),
            vcs: Some(EmbeddedVcsInfo {
                commit: "01".repeat(20),
                path_in_vcs: Some("crates/demo".to_owned()),
                file_sha256: sha256_bytes(b"generated"),
            }),
        };
        let tree = FakeTree {
            files: BTreeMap::from([
                (
                    "crates/demo/Cargo.toml".to_owned(),
                    GitBlob {
                        sha256: sha256_bytes(b"source manifest"),
                        executable: false,
                    },
                ),
                (
                    "crates/demo/src/lib.rs".to_owned(),
                    GitBlob {
                        sha256: sha256_bytes(b"source"),
                        executable: false,
                    },
                ),
            ]),
        };
        assert!(
            compare_archive_to_tree(&archive, "crates/demo", &tree)
                .unwrap()
                .matches
        );

        let mismatching = FakeTree {
            files: BTreeMap::new(),
        };
        assert!(
            !compare_archive_to_tree(&archive, "crates/demo", &mismatching)
                .unwrap()
                .matches
        );
    }

    #[test]
    fn bounded_command_rejects_excess_stdout() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 12345"]);
        let error =
            run_bounded_command(command, "test bounded output", Duration::from_secs(1), 4, 4)
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("configured bound"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn bounded_command_terminates_on_timeout() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let started = Instant::now();
        let error = run_bounded_command(command, "test timeout", Duration::from_millis(25), 4, 4)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("wall-clock timeout"),
            "unexpected error: {error:#}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
