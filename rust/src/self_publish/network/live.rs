//! The live crates.io documents and the live release repository.
//!
//! Every request is a read over HTTPS, bounded in size and time, with a fixed
//! user agent that names the project's repository, no proxy or token variable,
//! and the empty-environment allowlist of the workflow's child processes.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tracing::debug;

use super::super::git;
use super::super::isolation::ChildEnvironment;
use super::super::name;
use super::{CratesIo, CratesIoVersion, Owner, OwnerKind, ReleaseRepository, ReleaseTag};
use crate::index::{IndexRecord, index_path};
use crate::package::TemporaryDirectory;
use crate::policy::{validate_git_object_id, validate_git_tag, validate_https_repository};

/// Root of crates.io's sparse index.
const SPARSE_ROOT: &str = "https://index.crates.io";
/// Root of crates.io's API.
const API_ROOT: &str = "https://crates.io/api/v1";
/// Largest crates.io API document this crate reads.
const MAX_API_BYTES: usize = 4 * 1024 * 1024;
/// Largest crates.io sparse-index file this crate reads.
const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
/// Shortest interval between two crates.io API requests.
const API_INTERVAL: Duration = Duration::from_secs(1);
/// The exit status of `curl` when `--max-filesize` stops a response.
const CURL_TOO_LARGE: i32 = 63;
/// Keeps the API requests of one process modest.
static LAST_API_REQUEST: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
/// Maximum number of bytes of a failed command's output that an error keeps.
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;
/// The user agent of every request, which names the project's repository.
const USER_AGENT: &str = concat!(
    "pkgre-rust/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/pkgre/pkgre; self-publishing checks)"
);

/// crates.io, read over its API and its sparse index.
pub(crate) struct LiveCratesIo;

impl CratesIo for LiveCratesIo {
    fn owners(&self, name: &str) -> Result<Option<Vec<Owner>>> {
        name::validate_syntax(name).context("read the owners of a crates.io crate")?;
        wait_for_api_interval()?;
        let url = format!("{API_ROOT}/crates/{name}/owners");
        let response = request(&url, "read the crates.io owners", MAX_API_BYTES)
            .with_context(|| format!("the crates.io owners of {name:?} could not be read"))?;
        let body = match response.status {
            200 => response.body,
            404 => return Ok(None),
            status => bail!(
                "crates.io answered HTTP {status} for {url}, so the owners of {name:?} could not be read"
            ),
        };
        let document: OwnersDocument = serde_json::from_slice(&body)
            .with_context(|| format!("parse the crates.io owners of {name:?}"))?;
        document
            .users
            .into_iter()
            .map(OwnerDocument::into_owner)
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }

    fn versions(&self, name: &str) -> Result<Option<Vec<CratesIoVersion>>> {
        name::validate_syntax(name).context("read the versions of a crates.io crate")?;
        let url = format!("{SPARSE_ROOT}/{}", index_path(name));
        let response = request(&url, "read the crates.io sparse index", MAX_INDEX_BYTES)
            .with_context(|| format!("the crates.io versions of {name:?} could not be read"))?;
        let body = match response.status {
            200 => response.body,
            404 => return Ok(None),
            status => bail!(
                "crates.io answered HTTP {status} for {url}, so the versions of {name:?} could not be read"
            ),
        };
        parse_versions(name, &body).map(Some)
    }

    fn category_slugs(&self) -> Result<BTreeSet<String>> {
        wait_for_api_interval()?;
        let url = format!("{API_ROOT}/category_slugs");
        let response = request(&url, "read the crates.io category slugs", MAX_API_BYTES)
            .context("the crates.io category slugs could not be read")?;
        ensure!(
            response.status == 200,
            "crates.io answered HTTP {} for {url}, so its category slugs could not be read",
            response.status
        );
        let document: SlugsDocument =
            serde_json::from_slice(&response.body).context("parse the crates.io category slugs")?;
        Ok(document
            .category_slugs
            .into_iter()
            .map(|slug| slug.slug)
            .collect())
    }
}

/// A release repository, read over Git.
pub(crate) struct LiveReleaseRepository;

impl ReleaseRepository for LiveReleaseRepository {
    fn inspect_tag(&self, git: &str, tag: &str) -> Result<ReleaseTag> {
        validate_https_repository(git)?;
        validate_git_tag(tag)?;
        inspect_tag(git, tag, &ChildEnvironment::plain()).with_context(|| {
            format!("the release tag {tag:?} of the repository {git:?} could not be read")
        })
    }
}

/// One crates.io API response.
struct Response {
    /// HTTP status code.
    status: u16,
    /// Response body, bounded by the request's limit.
    body: Vec<u8>,
}

/// The owners document of one crates.io crate.
#[derive(Deserialize)]
struct OwnersDocument {
    /// The owners of the crate.
    users: Vec<OwnerDocument>,
}

/// One owner of one crates.io crate.
#[derive(Deserialize)]
struct OwnerDocument {
    /// The login of the owner.
    login: String,
    /// `user` or `team`.
    kind: String,
}

impl OwnerDocument {
    /// Returns the owner, refusing a kind this crate does not know.
    ///
    /// # Errors
    ///
    /// Returns an error for a kind other than `user` or `team`.
    fn into_owner(self) -> Result<Owner> {
        let kind = match self.kind.as_str() {
            "user" => OwnerKind::User,
            "team" => OwnerKind::Team,
            other => bail!(
                "crates.io reports the owner {:?} of the unknown kind {other:?}",
                self.login
            ),
        };
        Ok(Owner {
            login: self.login,
            kind,
        })
    }
}

/// The category-slug document of crates.io.
#[derive(Deserialize)]
struct SlugsDocument {
    /// The category slugs.
    category_slugs: Vec<SlugDocument>,
}

/// One category slug of crates.io.
#[derive(Deserialize)]
struct SlugDocument {
    /// The slug a manifest declares.
    slug: String,
}

/// Parses every published version of one crate from its sparse-index file.
///
/// # Errors
///
/// Returns an error for a malformed row, a row of another package, or two rows
/// of the same version.
fn parse_versions(name: &str, body: &[u8]) -> Result<Vec<CratesIoVersion>> {
    let mut versions = Vec::new();
    let mut identities = BTreeSet::new();
    for (number, line) in body.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record = IndexRecord::parse(line)
            .with_context(|| format!("parse crates.io sparse row {} of {name:?}", number + 1))?;
        ensure!(
            record.name()? == name,
            "crates.io sparse row {} names a package other than {name:?}",
            number + 1
        );
        let version = record.version()?;
        ensure!(
            identities.insert(version.clone()),
            "crates.io sparse index repeats Cargo identity {name} {version}"
        );
        versions.push(CratesIoVersion {
            version,
            checksum: record.checksum()?.to_owned(),
        });
    }
    Ok(versions)
}

/// Reads one release tag and its position in the repository.
fn inspect_tag(git: &str, tag: &str, environment: &ChildEnvironment) -> Result<ReleaseTag> {
    let branch = default_branch(git, environment)?;
    let temporary = TemporaryDirectory::new("pkgre-release-tag")?;
    let checkout = temporary.path().join("repository");
    let branch_reference = format!("refs/remotes/origin/{branch}");
    let tag_reference = format!("refs/tags/{tag}");
    fetch_tag_and_branch(
        &checkout,
        git,
        &branch,
        &branch_reference,
        &tag_reference,
        environment,
    )?;
    let kind = git::stdout(
        &checkout,
        [
            OsString::from("cat-file"),
            OsString::from("-t"),
            OsString::from(&tag_reference),
        ],
        environment,
        false,
    )?;
    ensure!(
        matches!(kind.as_str(), "tag" | "commit"),
        "the release tag {tag:?} is a {kind:?} object, not a tag"
    );
    let commit = git::stdout(
        &checkout,
        [
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(format!("{tag_reference}^{{commit}}")),
        ],
        environment,
        false,
    )?;
    validate_git_object_id(&commit).context("invalid fetched Git commit ID")?;
    let on_default_branch = is_ancestor(&checkout, &commit, &branch_reference, environment)?;
    Ok(ReleaseTag {
        commit,
        annotated: kind == "tag",
        on_default_branch,
        default_branch: branch,
    })
}

/// Fetches the default branch and the release tag into a fresh repository.
fn fetch_tag_and_branch(
    checkout: &Path,
    git: &str,
    branch: &str,
    branch_reference: &str,
    tag_reference: &str,
    environment: &ChildEnvironment,
) -> Result<()> {
    git::run(
        None,
        [
            OsString::from("init"),
            OsString::from("--quiet"),
            checkout.as_os_str().to_owned(),
        ],
        environment,
        false,
    )?;
    git::run(
        Some(checkout),
        [
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            OsString::from(git),
        ],
        environment,
        false,
    )?;
    git::run(
        Some(checkout),
        [
            OsString::from("fetch"),
            OsString::from("--quiet"),
            OsString::from("--no-tags"),
            OsString::from("origin"),
            OsString::from(format!("refs/heads/{branch}:{branch_reference}")),
        ],
        environment,
        false,
    )?;
    git::run(
        Some(checkout),
        [
            OsString::from("fetch"),
            OsString::from("--quiet"),
            OsString::from("--no-tags"),
            OsString::from("origin"),
            OsString::from(format!("{tag_reference}:{tag_reference}")),
        ],
        environment,
        false,
    )?;
    Ok(())
}

/// Returns whether one commit is an ancestor of one reference.
fn is_ancestor(
    checkout: &Path,
    commit: &str,
    reference: &str,
    environment: &ChildEnvironment,
) -> Result<bool> {
    let output = git::spawn(
        git::command(
            Some(checkout),
            [
                OsString::from("merge-base"),
                OsString::from("--is-ancestor"),
                OsString::from(commit),
                OsString::from(reference),
            ],
            environment,
            false,
        ),
        "test the ancestry of the release tag's commit",
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "git merge-base exited with {}: {}",
            output.status,
            bounded_lossy(&output.stderr)
        ),
    }
}

/// Returns the default branch that the repository's `HEAD` names.
fn default_branch(git: &str, environment: &ChildEnvironment) -> Result<String> {
    let output = git::spawn(
        git::command(
            None,
            [
                OsString::from("ls-remote"),
                OsString::from("--symref"),
                OsString::from(git),
                OsString::from("HEAD"),
            ],
            environment,
            false,
        ),
        "read the repository's default branch",
    )?;
    git::require_success(&output, "read the repository's default branch")?;
    let stdout = String::from_utf8(output.stdout).context("Git wrote non-UTF-8 output")?;
    for line in stdout.lines() {
        let Some(reference) = line.strip_prefix("ref: ") else {
            continue;
        };
        let Some((reference, name)) = reference.split_once('\t') else {
            continue;
        };
        if name.trim() != "HEAD" {
            continue;
        }
        let Some(branch) = reference.strip_prefix("refs/heads/") else {
            continue;
        };
        validate_branch(branch)?;
        return Ok(branch.to_owned());
    }
    bail!("the repository {git:?} names no default branch")
}

/// Refuses a branch name that cannot be fetched as one ref.
///
/// Git ref names are case-sensitive, so only the exact `.lock` suffix is
/// refused.
///
/// # Errors
///
/// Returns an error for a branch that is not ASCII, contains a character a Git
/// ref may not hold, or is not a safe ref name.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validate_branch(branch: &str) -> Result<()> {
    ensure!(
        !branch.is_empty(),
        "the repository's default branch is empty"
    );
    ensure!(
        branch.is_ascii(),
        "the repository's default branch {branch:?} is not ASCII"
    );
    ensure!(
        branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')),
        "the repository's default branch {branch:?} contains a disallowed character"
    );
    ensure!(
        !branch.contains("..")
            && !branch.contains("//")
            && !branch.starts_with('/')
            && !branch.ends_with('/')
            && !branch.ends_with('.')
            && !branch.ends_with(".lock"),
        "the repository's default branch {branch:?} is not a safe ref name"
    );
    Ok(())
}

/// Reads one HTTPS document with `curl` and returns its status and body.
///
/// # Errors
///
/// Returns an error when `curl` cannot run, reports a transport failure, or
/// reads a body larger than `max_bytes`.
fn request(url: &str, action: &str, max_bytes: usize) -> Result<Response> {
    let limit = max_bytes.to_string();
    let mut command = Command::new("curl");
    command.args([
        OsStr::new("--disable"),
        OsStr::new("--silent"),
        OsStr::new("--show-error"),
        OsStr::new("--location"),
        OsStr::new("--max-redirs"),
        OsStr::new("5"),
        OsStr::new("--proto"),
        OsStr::new("=https"),
        OsStr::new("--proto-redir"),
        OsStr::new("=https"),
        OsStr::new("--tlsv1.2"),
        OsStr::new("--connect-timeout"),
        OsStr::new("20"),
        OsStr::new("--max-time"),
        OsStr::new("120"),
        OsStr::new("--max-filesize"),
        OsStr::new(&limit),
        OsStr::new("--user-agent"),
        OsStr::new(USER_AGENT),
        OsStr::new("--write-out"),
        OsStr::new("%{http_code}"),
        OsStr::new(url),
    ]);
    ChildEnvironment::plain().apply(&mut command);
    debug!(%url, %action, "fetching a public crates.io document");
    let output = command
        .output()
        .with_context(|| format!("{action}: start curl"))?;
    if let Some(code) = output.status.code()
        && code == CURL_TOO_LARGE
    {
        bail!("{action}: the response exceeded {max_bytes} bytes");
    }
    ensure!(
        output.status.success(),
        "{action}: crates.io is unavailable: curl exited with {}\n{}",
        output.status,
        bounded_lossy(&output.stderr)
    );
    ensure!(
        output.stdout.len() >= 3,
        "{action}: curl reported no HTTP status"
    );
    let split = output.stdout.len() - 3;
    let (body, status) = output.stdout.split_at(split);
    let status = std::str::from_utf8(status)
        .context("curl wrote a non-UTF-8 HTTP status")?
        .parse::<u16>()
        .context("curl wrote an HTTP status that is not a number")?;
    ensure!(
        body.len() <= max_bytes,
        "{action}: the response exceeded {max_bytes} bytes"
    );
    Ok(Response {
        status,
        body: body.to_vec(),
    })
}

/// Waits until the interval between two crates.io API requests has passed.
fn wait_for_api_interval() -> Result<()> {
    let lock = LAST_API_REQUEST.get_or_init(|| Mutex::new(None));
    let mut last = lock
        .lock()
        .map_err(|_| anyhow::anyhow!("the crates.io API rate-limit lock is poisoned"))?;
    if let Some(previous) = *last
        && let Some(remaining) = API_INTERVAL.checked_sub(previous.elapsed())
    {
        std::thread::sleep(remaining);
    }
    *last = Some(Instant::now());
    Ok(())
}

/// Keeps the last bytes of a failed command's output in its error.
fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}
