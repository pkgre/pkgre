//! Credential-free, inert archive-to-Git source correspondence.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::artifact::sha256_bytes;

use super::{ApiVersionEvidence, ArchiveAnalysis, ArchiveFile, SourceEvidence};

const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;
const MAX_GIT_METADATA_BYTES: usize = 64 * 1024;
const MAX_GIT_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_GIT_TREE_BYTES: usize = 32 * 1024 * 1024;
const MAX_GIT_FETCH_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const COMMAND_CLEANUP_GRACE: Duration = Duration::from_secs(5);
const GITHUB_PREFIX: &str = "https://github.com/";
/// Symbolic links and submodules one path may be redirected through.
const MAX_PATH_REDIRECTS: usize = 16;
/// Submodule repositories one comparison may fetch.
const MAX_SUBMODULES: usize = 8;
/// `Cargo.toml` files one package-directory search may read.
const MAX_TREE_MANIFESTS: usize = 512;
/// Ancestor directories one `workspace = true` package field may be resolved through.
const MAX_WORKSPACE_ANCESTORS: usize = 32;
/// Differences one planning log line names.
const MAX_REPORTED_DIFFERENCES: usize = 20;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One archive-to-tree comparison: the compact evidence the plan promotes and, when a comparison
/// ran, the per-file report behind it.
#[derive(Clone, Debug)]
pub struct SourceCorrespondence {
    /// Compact source evidence for the admission plan.
    pub(crate) evidence: SourceEvidence,
    /// Per-file comparison result, absent when no comparison ran.
    pub(crate) comparison: Option<ComparisonReport>,
}

impl SourceCorrespondence {
    fn unavailable(reason: &str) -> Self {
        Self {
            evidence: SourceEvidence::Unavailable {
                reason: reason.to_owned(),
            },
            comparison: None,
        }
    }

    fn mismatch(reason: &str) -> Self {
        Self {
            evidence: SourceEvidence::Mismatch {
                comparison_sha256: sha256_bytes(reason.as_bytes()),
            },
            comparison: None,
        }
    }
}

/// Attempts promoted mechanical correspondence between one inert crate analysis and an exact public Git commit.
///
/// Missing/unsupported anchors and public fetch failures produce `Unavailable`; an anchor disagreement or unexplained archive-to-tree difference produces `Mismatch`. Candidate code, hooks, checkouts, submodules, and build tools are never executed.
///
/// # Errors
///
/// Returns an error only when deterministic local evidence construction fails.
pub fn verify_source_correspondence(
    archive: &ArchiveAnalysis,
    original_manifest: Option<&[u8]>,
    api: Option<&ApiVersionEvidence>,
) -> Result<SourceCorrespondence> {
    let Some(api) = api else {
        return Ok(SourceCorrespondence::unavailable(
            "crates-io-api-evidence-unavailable",
        ));
    };
    let (repository, commit, path_in_vcs, attestation) =
        if let Some(trusted) = &api.trusted_publishing {
            let Ok(repository) = normalize_public_repository(&trusted.repository) else {
                return Ok(SourceCorrespondence::unavailable(
                    "trusted-publishing-repository-is-unsupported",
                ));
            };
            if let Some(api_repository) = api.repository.as_deref() {
                let Ok(api_repository) = normalize_public_repository(api_repository) else {
                    return Ok(SourceCorrespondence::mismatch("source-anchor-disagreement"));
                };
                if !public_repositories_agree(&api_repository, &repository) {
                    return Ok(SourceCorrespondence::mismatch("source-anchor-disagreement"));
                }
            }
            if archive
                .vcs
                .as_ref()
                .is_some_and(|vcs| vcs.commit != trusted.commit)
            {
                return Ok(SourceCorrespondence::mismatch("source-anchor-disagreement"));
            }
            (
                repository,
                trusted.commit.as_str(),
                archive
                    .vcs
                    .as_ref()
                    .and_then(|vcs| vcs.path_in_vcs.as_deref()),
                Some(trusted.evidence_sha256.as_str()),
            )
        } else {
            let Some(vcs) = &archive.vcs else {
                return Ok(SourceCorrespondence::unavailable(
                    "archive-has-no-vcs-commit",
                ));
            };
            let Some(repository_value) = api.repository.as_deref() else {
                return Ok(SourceCorrespondence::unavailable(
                    "version-has-no-supported-repository",
                ));
            };
            let Ok(repository) = normalize_public_repository(repository_value) else {
                return Ok(SourceCorrespondence::unavailable(
                    "version-repository-is-unsupported",
                ));
            };
            (
                repository,
                vcs.commit.as_str(),
                vcs.path_in_vcs.as_deref(),
                None,
            )
        };
    let checkout = match GitRepository::fetch(&repository, commit) {
        Ok(value) => value,
        Err(error) => {
            debug!(%repository, %commit, error = %format_args!("{error:#}"), "public Git source fetch unavailable");
            return Ok(SourceCorrespondence::unavailable("public-git-fetch-failed"));
        }
    };
    let anchor = SourceAnchor {
        repository,
        commit,
        path_in_vcs,
        attestation_sha256: attestation,
    };
    promote_source(&anchor, archive, original_manifest, &checkout)
}

/// One resolved source anchor for a package archive.
struct SourceAnchor<'a> {
    /// Credential-free repository URL.
    repository: String,
    /// Exact embedded or attested commit.
    commit: &'a str,
    /// The archive's embedded package path, absent when the archive carries none.
    path_in_vcs: Option<&'a str>,
    /// Hash of the registry's Trusted Publishing evidence, when that anchor applies.
    attestation_sha256: Option<&'a str>,
}

/// Compares one archive with one already-fetched tree and promotes the result.
fn promote_source(
    anchor: &SourceAnchor<'_>,
    archive: &ArchiveAnalysis,
    original_manifest: Option<&[u8]>,
    tree: &dyn GitTree,
) -> Result<SourceCorrespondence> {
    let comparison =
        match compare_archive_to_tree(archive, original_manifest, anchor.path_in_vcs, tree) {
            Ok(comparison) => comparison,
            Err(error) => return unavailable_correspondence(error),
        };
    let evidence = if comparison.matches {
        match anchor.attestation_sha256 {
            Some(attestation_sha256) => SourceEvidence::RegistryContextAttested {
                repository: anchor.repository.clone(),
                commit: anchor.commit.to_owned(),
                path: anchor.path_in_vcs.unwrap_or("").to_owned(),
                comparison_sha256: comparison.sha256.clone(),
                attestation_sha256: attestation_sha256.to_owned(),
            },
            None => SourceEvidence::PublisherAsserted {
                repository: anchor.repository.clone(),
                commit: anchor.commit.to_owned(),
                path: anchor.path_in_vcs.unwrap_or("").to_owned(),
                comparison_sha256: comparison.sha256.clone(),
            },
        }
    } else {
        SourceEvidence::Mismatch {
            comparison_sha256: comparison.sha256.clone(),
        }
    };
    Ok(SourceCorrespondence {
        evidence,
        comparison: Some(comparison.report),
    })
}

/// Evidence that could not be produced, with its public reason.
#[derive(Debug)]
struct Unavailable {
    reason: &'static str,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for Unavailable {}

fn unavailable_error(reason: &'static str) -> anyhow::Error {
    anyhow::Error::new(Unavailable { reason })
}

/// Maps one unavailable-evidence error to `Unavailable` evidence, and propagates any other error.
fn unavailable_correspondence(error: anyhow::Error) -> Result<SourceCorrespondence> {
    match error.downcast::<Unavailable>() {
        Ok(unavailable) => Ok(SourceCorrespondence::unavailable(unavailable.reason)),
        Err(error) => Err(error),
    }
}

/// Reduces one publisher-declared repository URL to a fetchable public repository identity.
///
/// A GitHub URL may carry one trailing `/` and may name a path inside the repository through
/// `/tree/<ref>/…` or `/blob/<ref>/…`; both spell the repository itself. Other hosts are taken as
/// declared.
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
    let raw_path = raw_path.strip_suffix('/').unwrap_or(raw_path);
    let raw_path = raw_path.strip_suffix(".git").unwrap_or(raw_path);
    let mut components = raw_path.split('/').collect::<Vec<_>>();
    ensure!(
        components.len() >= 2,
        "repository URL has no owner and repository"
    );
    if host == "github.com" && matches!(components.get(2), Some(&"tree" | &"blob")) {
        components.truncate(2);
    }
    ensure!(
        components.iter().all(|component| {
            !component.is_empty()
                && *component != "."
                && *component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }),
        "repository identity is unsafe or noncanonical"
    );
    Ok(format!("https://{host}/{}", components.join("/")))
}

/// Returns whether two public repository identities name the same repository.
///
/// A GitHub owner and repository name compare without regard to case, because GitHub resolves them
/// that way; every other host compares exactly.
pub(crate) fn public_repositories_agree(left: &str, right: &str) -> bool {
    let canonical =
        |value: &str| normalize_public_repository(value).unwrap_or_else(|_| value.to_owned());
    let (left, right) = (canonical(left), canonical(right));
    left == right
        || (left.starts_with(GITHUB_PREFIX)
            && right.starts_with(GITHUB_PREFIX)
            && left.eq_ignore_ascii_case(&right))
}

/// Per-file result of one archive-to-tree comparison.
///
/// The report names paths and dispositions only; archive contents are never copied into it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ComparisonReport {
    /// The repository-relative package directory compared; empty for the repository root.
    pub(crate) path_in_vcs: String,
    /// Whether `path-in-vcs` was located by matching the archive's `Cargo.toml.orig`, the archive
    /// carrying no `path_in_vcs`.
    pub(crate) located_path: bool,
    /// Every archive member, in archive order.
    pub(crate) files: Vec<FileComparison>,
}

impl ComparisonReport {
    /// The archive members that differ from the tree or are missing from it.
    fn differences(&self) -> Vec<(&str, &str)> {
        self.files
            .iter()
            .filter(|file| matches!(file.disposition, "different" | "missing"))
            .map(|file| (file.archive_path.as_str(), file.disposition))
            .collect()
    }

    /// Names the first differences for the planning log.
    pub(crate) fn describe_differences(&self) -> String {
        let differences = self.differences();
        let mut description = differences
            .iter()
            .take(MAX_REPORTED_DIFFERENCES)
            .map(|(path, disposition)| format!("{path} ({disposition})"))
            .collect::<Vec<_>>()
            .join(", ");
        if differences.len() > MAX_REPORTED_DIFFERENCES {
            description.push_str(", and ");
            description.push_str(&(differences.len() - MAX_REPORTED_DIFFERENCES).to_string());
            description.push_str(" more");
        }
        description
    }
}

/// One archive member's place in the public tree.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FileComparison {
    /// Archive path, relative to the archive's `<name>-<version>/` root.
    pub(crate) archive_path: String,
    /// The repository path the member is expected at, absent for a Cargo-generated member.
    pub(crate) expected_path: Option<String>,
    /// The repository path compared, which differs from `expected-path` for a copied member.
    pub(crate) compared_path: Option<String>,
    /// The path read after following symbolic links, present only when it differs from
    /// `compared-path`; it is relative to `submodule` when that is present.
    pub(crate) resolved_path: Option<String>,
    /// The submodule repository the member was read from.
    pub(crate) submodule: Option<String>,
    /// Whether Cargo copied the member into the package root from outside it.
    pub(crate) copied: bool,
    pub(crate) archive_sha256: String,
    pub(crate) repository_sha256: Option<String>,
    pub(crate) archive_executable: bool,
    pub(crate) repository_executable: Option<bool>,
    pub(crate) disposition: &'static str,
}

struct ComparisonResult {
    matches: bool,
    sha256: String,
    report: ComparisonReport,
}

/// One Git tree entry, as the tree stores it and without following any symbolic link.
#[derive(Clone, Debug)]
enum TreeEntry {
    /// A regular file, with the SHA-256 of its bytes and its executable bit.
    File { sha256: String, executable: bool },
    /// A symbolic link, with its target text.
    Symlink { target: String },
    /// A directory.
    Directory,
    /// A submodule, with the exact commit it is checked out at.
    Gitlink { commit: String },
}

/// Read-only access to one fetched Git tree.
trait GitTree {
    /// The entry at exactly `path`, following no symbolic link.
    fn entry(&self, path: &str) -> Result<Option<TreeEntry>>;

    /// The bytes of the regular file at exactly `path`.
    fn file_content(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// Every `Cargo.toml` path in the tree.
    fn manifests(&self) -> Result<Vec<String>>;

    /// The tree of the submodule fetched from `repository` at `commit`, when that fetch succeeds.
    fn submodule(&self, repository: &str, commit: &str) -> Result<Option<Box<dyn GitTree>>>;
}

struct GitBlob {
    sha256: String,
    executable: bool,
}

/// Where one archive member was read, after following symbolic links and submodules.
struct Resolution {
    /// The path reached inside its tree, which differs from the requested path when a link or a
    /// submodule redirected it; it is relative to `submodule` when that is present.
    path: String,
    /// The submodule repository the path was read from.
    submodule: Option<String>,
    /// The regular file found, absent when the path does not exist.
    file: Option<GitBlob>,
}

/// Resolves archive-member paths against one tree, following links and submodules.
struct TreeResolver<'a> {
    root: &'a dyn GitTree,
    /// Submodule trees, by repository URL.
    submodules: RefCell<BTreeMap<String, Box<dyn GitTree>>>,
    /// Resolved directory prefixes, by tree and logical path.
    prefixes: RefCell<BTreeMap<(Option<String>, String), DirectoryState>>,
    /// The root `.gitmodules`, submodule path to URL.
    gitmodules: RefCell<Option<BTreeMap<String, String>>>,
    /// Submodule repositories fetched so far.
    fetched: Cell<usize>,
}

#[derive(Clone)]
enum DirectoryState {
    Absent,
    Directory,
    File,
    Symlink { target: String },
    Gitlink { commit: String },
}

impl<'a> TreeResolver<'a> {
    fn new(root: &'a dyn GitTree) -> Self {
        Self {
            root,
            submodules: RefCell::new(BTreeMap::new()),
            prefixes: RefCell::new(BTreeMap::new()),
            gitmodules: RefCell::new(None),
            fetched: Cell::new(0),
        }
    }

    fn manifests(&self) -> Result<Vec<String>> {
        self.root.manifests()
    }

    /// Resolves one repository-relative path through symbolic links and submodules.
    fn resolve(&self, path: &str) -> Result<Resolution> {
        self.resolve_from(None, path, 0)
    }

    fn resolve_from(
        &self,
        tree: Option<String>,
        path: &str,
        redirects: usize,
    ) -> Result<Resolution> {
        let mut tree = tree;
        let mut resolved = String::new();
        let mut pending = path
            .split('/')
            .map(str::to_owned)
            .collect::<VecDeque<String>>();
        let mut redirects = redirects;
        while let Some(component) = pending.pop_front() {
            let candidate = join_vcs_path(&resolved, &component);
            if pending.is_empty() {
                let Some(entry) = self.tree_entry(tree.as_deref(), &candidate)? else {
                    return Ok(Resolution {
                        path: path.to_owned(),
                        submodule: None,
                        file: None,
                    });
                };
                return match entry {
                    TreeEntry::File { sha256, executable } => Ok(Resolution {
                        path: candidate,
                        submodule: tree,
                        file: Some(GitBlob { sha256, executable }),
                    }),
                    TreeEntry::Symlink { target } => {
                        let redirects = redirects + 1;
                        check_redirects(redirects)?;
                        let target = resolve_link_target(&candidate, &target)?;
                        self.resolve_from(tree, &target, redirects)
                    }
                    TreeEntry::Directory | TreeEntry::Gitlink { .. } => Ok(Resolution {
                        path: path.to_owned(),
                        submodule: None,
                        file: None,
                    }),
                };
            }
            match self.directory_state(tree.as_deref(), &candidate)? {
                DirectoryState::Absent | DirectoryState::File => {
                    return Ok(Resolution {
                        path: path.to_owned(),
                        submodule: None,
                        file: None,
                    });
                }
                DirectoryState::Directory => resolved = candidate,
                DirectoryState::Symlink { target } => {
                    redirects += 1;
                    check_redirects(redirects)?;
                    let target = resolve_link_target(&candidate, &target)?;
                    resolved.clear();
                    for component in target.split('/').rev() {
                        pending.push_front(component.to_owned());
                    }
                }
                DirectoryState::Gitlink { commit } => {
                    if tree.is_some() {
                        return Err(unavailable_error("repository-submodule-is-nested"));
                    }
                    let repository = self.submodule_repository(&candidate)?;
                    self.load_submodule(&repository, &commit)?;
                    tree = Some(repository);
                    resolved.clear();
                }
            }
        }
        Ok(Resolution {
            path: path.to_owned(),
            submodule: None,
            file: None,
        })
    }

    /// The entry at `path` in the root tree or in one loaded submodule tree.
    fn tree_entry(&self, tree: Option<&str>, path: &str) -> Result<Option<TreeEntry>> {
        let Some(repository) = tree else {
            return self.root.entry(path);
        };
        let submodules = self.submodules.borrow();
        let submodule = submodules
            .get(repository)
            .with_context(|| format!("submodule tree {repository} is not loaded"))?;
        submodule.entry(path)
    }

    /// The kind of one directory prefix, cached for the files that share it.
    fn directory_state(&self, tree: Option<&str>, path: &str) -> Result<DirectoryState> {
        let key = (tree.map(str::to_owned), path.to_owned());
        if let Some(state) = self.prefixes.borrow().get(&key) {
            return Ok(state.clone());
        }
        let state = match self.tree_entry(tree, path)? {
            None => DirectoryState::Absent,
            Some(TreeEntry::Directory) => DirectoryState::Directory,
            Some(TreeEntry::File { .. }) => DirectoryState::File,
            Some(TreeEntry::Symlink { target }) => DirectoryState::Symlink { target },
            Some(TreeEntry::Gitlink { commit }) => DirectoryState::Gitlink { commit },
        };
        self.prefixes.borrow_mut().insert(key, state.clone());
        Ok(state)
    }

    /// The supported public repository URL `.gitmodules` gives for one submodule path.
    fn submodule_repository(&self, path: &str) -> Result<String> {
        let modules = self.gitmodules()?;
        let Some(url) = modules.get(path) else {
            return Err(unavailable_error("repository-submodule-has-no-url"));
        };
        normalize_public_repository(url)
            .map_err(|_| unavailable_error("repository-submodule-repository-is-unsupported"))
    }

    /// The root `.gitmodules`, submodule path to URL.
    fn gitmodules(&self) -> Result<BTreeMap<String, String>> {
        if let Some(modules) = self.gitmodules.borrow().as_ref() {
            return Ok(modules.clone());
        }
        let modules = match self.root.file_content(".gitmodules")? {
            Some(bytes) => parse_gitmodules(&bytes),
            None => BTreeMap::new(),
        };
        *self.gitmodules.borrow_mut() = Some(modules.clone());
        Ok(modules)
    }

    /// Fetches one submodule tree, once per repository and commit.
    fn load_submodule(&self, repository: &str, commit: &str) -> Result<()> {
        if self.submodules.borrow().contains_key(repository) {
            return Ok(());
        }
        if self.fetched.get() >= MAX_SUBMODULES {
            return Err(unavailable_error("repository-submodule-limit-exceeded"));
        }
        let Some(tree) = self.root.submodule(repository, commit)? else {
            return Err(unavailable_error("repository-submodule-fetch-failed"));
        };
        self.fetched.set(self.fetched.get() + 1);
        self.submodules
            .borrow_mut()
            .insert(repository.to_owned(), tree);
        Ok(())
    }
}

fn check_redirects(redirects: usize) -> Result<()> {
    if redirects > MAX_PATH_REDIRECTS {
        return Err(unavailable_error("repository-path-redirect-loop"));
    }
    Ok(())
}

/// Resolves one symbolic-link target to a repository-relative path.
fn resolve_link_target(link_path: &str, target: &str) -> Result<String> {
    if target.starts_with('/') || target.contains('\\') {
        return Err(unavailable_error("repository-symlink-escapes-repository"));
    }
    let base = link_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    resolve_repository_path(base, target)
        .ok_or_else(|| unavailable_error("repository-symlink-escapes-repository"))
}

/// Joins `relative` to `base` inside the repository, refusing an escape above its root.
fn resolve_repository_path(base: &str, relative: &str) -> Option<String> {
    if relative.starts_with('/') || relative.contains('\\') {
        return None;
    }
    let mut components = base
        .split('/')
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for component in relative.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            value => components.push(value.to_owned()),
        }
    }
    Some(components.join("/"))
}

fn compare_archive_to_tree(
    archive: &ArchiveAnalysis,
    original_manifest: Option<&[u8]>,
    path_in_vcs: Option<&str>,
    tree: &dyn GitTree,
) -> Result<ComparisonResult> {
    let (report, matches) = build_comparison_report(archive, original_manifest, path_in_vcs, tree)?;
    let canonical = serde_json::to_vec(&report).context("serialize source comparison report")?;
    Ok(ComparisonResult {
        matches,
        sha256: sha256_bytes(&canonical),
        report,
    })
}

/// Compares every archive member with the exact public tree, returning the report and whether
/// every compared member matched.
fn build_comparison_report(
    archive: &ArchiveAnalysis,
    original_manifest: Option<&[u8]>,
    path_in_vcs: Option<&str>,
    tree: &dyn GitTree,
) -> Result<(ComparisonReport, bool)> {
    let resolver = TreeResolver::new(tree);
    let (path_in_vcs, located_path) = resolve_package_path(archive, path_in_vcs, &resolver)?;
    let copied_files = cargo_copied_files(original_manifest, &path_in_vcs, tree)?;
    let archive_paths = archive
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut files = Vec::with_capacity(archive.files.len());
    let mut matches = true;
    for file in &archive.files {
        if is_cargo_generated(&file.path, &archive_paths) {
            files.push(ignored_comparison(file));
            continue;
        }
        let expected_path = join_vcs_path(&path_in_vcs, &source_path_for_archive_file(&file.path));
        let (compared_path, copied) = match copied_files.get(&file.path) {
            Some(source) => (source.clone(), true),
            None => (expected_path.clone(), false),
        };
        let resolution = resolver.resolve(&compared_path)?;
        let archive_executable = file.mode & 0o111 != 0;
        let disposition = match &resolution.file {
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
        let resolved_path = (resolution.path != compared_path).then_some(resolution.path);
        files.push(FileComparison {
            archive_path: file.path.clone(),
            expected_path: Some(expected_path),
            compared_path: Some(compared_path),
            resolved_path,
            submodule: resolution.submodule,
            copied,
            archive_sha256: file.sha256.clone(),
            repository_sha256: resolution.file.as_ref().map(|value| value.sha256.clone()),
            archive_executable,
            repository_executable: resolution.file.as_ref().map(|value| value.executable),
            disposition,
        });
    }
    let report = ComparisonReport {
        path_in_vcs,
        located_path,
        files,
    };
    Ok((report, matches))
}

/// The package directory the archive was packaged from, and whether it had to be located.
///
/// Cargo wrote `path_in_vcs` only from 1.58, so an archive that carries none is located by the one
/// directory whose `Cargo.toml` has the exact bytes of its `Cargo.toml.orig`. A directory that
/// cannot be located, or one of several, is unavailable evidence rather than a mismatch.
fn resolve_package_path(
    archive: &ArchiveAnalysis,
    path_in_vcs: Option<&str>,
    resolver: &TreeResolver<'_>,
) -> Result<(String, bool)> {
    if let Some(path) = path_in_vcs {
        validate_vcs_path(path)?;
        return Ok((path.to_owned(), false));
    }
    let Some(manifest) = archive
        .files
        .iter()
        .find(|file| file.path == "Cargo.toml.orig")
    else {
        return Err(unavailable_error("archive-has-no-original-manifest"));
    };
    let manifests = resolver.manifests()?;
    if manifests.len() > MAX_TREE_MANIFESTS {
        return Err(unavailable_error("repository-package-path-search-exceeded"));
    }
    let mut located = Vec::new();
    for manifest_path in &manifests {
        if located.len() > 1 {
            break;
        }
        let resolution = resolver.resolve(manifest_path)?;
        if resolution
            .file
            .as_ref()
            .is_some_and(|file| file.sha256 == manifest.sha256)
        {
            located.push(directory_of(manifest_path).to_owned());
        }
    }
    match located.len() {
        1 => Ok((located.remove(0), true)),
        0 => Err(unavailable_error("repository-package-path-not-located")),
        _ => Err(unavailable_error("repository-package-path-ambiguous")),
    }
}

fn directory_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

/// The archive members Cargo copied into the package root from outside the package directory.
///
/// `cargo package` copies the `readme` and `license-file` a package names when they live outside
/// its directory, placing each at the package root under its own file name. A path outside the
/// repository, or one it cannot resolve, is not copied: such a member stays missing.
fn cargo_copied_files(
    original_manifest: Option<&[u8]>,
    package_path: &str,
    tree: &dyn GitTree,
) -> Result<BTreeMap<String, String>> {
    let mut copies = BTreeMap::new();
    let Some(text) = original_manifest.and_then(|bytes| std::str::from_utf8(bytes).ok()) else {
        return Ok(copies);
    };
    let Ok(manifest) = toml::from_str::<OriginalManifest>(text) else {
        debug!("archive Cargo.toml.orig is not a package manifest");
        return Ok(copies);
    };
    let Some(package) = manifest.package else {
        return Ok(copies);
    };
    for (field, value) in [
        ("readme", package.readme),
        ("license-file", package.license_file),
    ] {
        let Some(value) = value else {
            continue;
        };
        let source = match &value {
            ManifestPath::Path(relative) => resolve_repository_path(package_path, relative),
            ManifestPath::Workspace { .. } => workspace_package_path(tree, package_path, field)?,
        };
        let Some(source) = source else {
            continue;
        };
        if is_within(package_path, &source) {
            continue;
        }
        let Some(name) = source.rsplit('/').next() else {
            continue;
        };
        copies.insert(name.to_owned(), source);
    }
    Ok(copies)
}

/// The repository path a `workspace = true` package field resolves to.
fn workspace_package_path(
    tree: &dyn GitTree,
    package_path: &str,
    field: &str,
) -> Result<Option<String>> {
    let mut directory = package_path.to_owned();
    for _ in 0..MAX_WORKSPACE_ANCESTORS {
        let manifest_path = join_vcs_path(&directory, "Cargo.toml");
        if let Some(bytes) = tree.file_content(&manifest_path)? {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                if let Ok(manifest) = toml::from_str::<toml::Value>(text) {
                    if let Some(workspace) = manifest.get("workspace") {
                        if !workspace_includes(workspace, package_path, &directory) {
                            return Ok(None);
                        }
                        let relative = workspace
                            .get("package")
                            .and_then(|package| package.get(field))
                            .and_then(toml::Value::as_str);
                        return Ok(relative
                            .and_then(|relative| resolve_repository_path(&directory, relative)));
                    }
                }
            }
        }
        if directory.is_empty() {
            break;
        }
        directory = directory_of(&directory).to_owned();
    }
    Ok(None)
}

/// Whether one workspace manifest includes the package directory, as Cargo resolves it.
fn workspace_includes(workspace: &toml::Value, package_path: &str, workspace_path: &str) -> bool {
    let Some(relative) = relative_path(workspace_path, package_path) else {
        return false;
    };
    if string_array(workspace.get("exclude")).is_some_and(|patterns| {
        patterns
            .iter()
            .any(|pattern| glob_matches(pattern, &relative))
    }) {
        return false;
    }
    if relative.is_empty() {
        return true;
    }
    string_array(workspace.get("members")).is_some_and(|patterns| {
        patterns
            .iter()
            .any(|pattern| glob_matches(pattern, &relative))
    })
}

fn string_array(value: Option<&toml::Value>) -> Option<Vec<&str>> {
    value?.as_array()?.iter().map(toml::Value::as_str).collect()
}

fn relative_path(base: &str, path: &str) -> Option<String> {
    if base.is_empty() {
        return Some(path.to_owned());
    }
    if path == base {
        return Some(String::new());
    }
    path.strip_prefix(base)
        .and_then(|rest| rest.strip_prefix('/'))
        .map(str::to_owned)
}

/// Whether one workspace path pattern matches one relative package directory.
fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let path = path.split('/').collect::<Vec<_>>();
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(&path)
            .all(|(pattern, value)| glob_component_matches(pattern, value))
}

fn glob_component_matches(pattern: &str, value: &str) -> bool {
    match pattern.as_bytes().first() {
        None => value.is_empty(),
        Some(b'*') => {
            (0..=value.len()).any(|split| glob_component_matches(&pattern[1..], &value[split..]))
        }
        Some(b'?') => value
            .get(1..)
            .is_some_and(|rest| glob_component_matches(&pattern[1..], rest)),
        Some(byte) => {
            value.as_bytes().first() == Some(byte)
                && glob_component_matches(&pattern[1..], &value[1..])
        }
    }
}

fn is_within(directory: &str, path: &str) -> bool {
    directory.is_empty()
        || path == directory
        || (path.starts_with(directory) && path.as_bytes().get(directory.len()) == Some(&b'/'))
}

/// One package manifest, as far as Cargo's copied files are concerned.
#[derive(Deserialize)]
struct OriginalManifest {
    #[serde(default)]
    package: Option<OriginalPackage>,
}

#[derive(Deserialize)]
struct OriginalPackage {
    #[serde(default)]
    readme: Option<ManifestPath>,
    #[serde(default, rename = "license-file")]
    license_file: Option<ManifestPath>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ManifestPath {
    Path(String),
    Workspace {
        #[expect(dead_code, reason = "the field only selects this variant")]
        workspace: bool,
    },
}

/// One root `.gitmodules`, submodule path to URL.
///
/// `.gitmodules` is Git configuration, not TOML: its section headers are bracketed and its values
/// may be unquoted, so it is read with the small reader below rather than a TOML parser.
fn parse_gitmodules(bytes: &[u8]) -> BTreeMap<String, String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        debug!(".gitmodules is not UTF-8");
        return BTreeMap::new();
    };
    let mut sections = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            current = git_config_section(header).and_then(|(kind, name)| {
                (kind == "submodule").then(|| {
                    sections.entry(name.clone()).or_default();
                    name
                })
            });
            continue;
        }
        let (Some(name), Some((key, value))) = (current.as_ref(), line.split_once('=')) else {
            continue;
        };
        if let Some(section) = sections.get_mut(name) {
            section.insert(key.trim().to_owned(), unquote(value.trim()).to_owned());
        }
    }
    sections
        .into_values()
        .filter_map(|section| Some((section.get("path")?.clone(), section.get("url")?.clone())))
        .collect()
}

/// Splits one Git configuration section header into its kind and optional name.
fn git_config_section(header: &str) -> Option<(&str, String)> {
    match header.split_once(char::is_whitespace) {
        Some((kind, name)) => Some((kind, unquote(name.trim()).to_owned())),
        None => header
            .split_once('.')
            .map(|(kind, name)| (kind, name.to_owned())),
    }
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn ignored_comparison(file: &ArchiveFile) -> FileComparison {
    FileComparison {
        archive_path: file.path.clone(),
        expected_path: None,
        compared_path: None,
        resolved_path: None,
        submodule: None,
        copied: false,
        archive_sha256: file.sha256.clone(),
        repository_sha256: None,
        archive_executable: file.mode & 0o111 != 0,
        repository_executable: None,
        disposition: "cargo-generated",
    }
}

/// Returns whether Cargo wrote one archive member while packaging it.
///
/// `cargo package` writes `.cargo_vcs_info.json`, `.cargo-ok`, a normalized `Cargo.toml` beside
/// the `Cargo.toml.orig` it packaged, and a `Cargo.lock` at the package root. Cargo generates
/// that root lock file at packaging time whether or not the repository tracks one, and rewrites
/// it when it does, so its bytes are not source. Cargo never reads the lock file of a dependency,
/// so it carries no code into a consumer's build either; the archive's bytes, the lock file
/// included, remain checksum-verified and retained, and its other analyses are unchanged.
///
/// Archive paths are relative to the archive's `<name>-<version>/` root, so only the root
/// `Cargo.toml` beside the root `Cargo.toml.orig` and the lock file directly beside them are
/// generated. Cargo writes that manifest pair only at the package root, so a nested `X/Cargo.toml`
/// is source even when `X/Cargo.toml.orig` sits beside it, and a `Cargo.lock` anywhere else in the
/// archive is source and is compared like any other file.
fn is_cargo_generated(path: &str, archive_paths: &BTreeSet<&str>) -> bool {
    matches!(path, ".cargo_vcs_info.json" | ".cargo-ok" | "Cargo.lock")
        || (path == "Cargo.toml" && archive_paths.contains("Cargo.toml.orig"))
}

/// The repository path the archive's `Cargo.toml.orig` was packaged from.
///
/// Cargo writes that pair only at the package root, so a nested `X/Cargo.toml.orig` is compared
/// like any other file.
fn source_path_for_archive_file(path: &str) -> String {
    if path == "Cargo.toml.orig" {
        "Cargo.toml".to_owned()
    } else {
        path.to_owned()
    }
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

/// One fetched commit of one public repository, read without checking it out.
struct GitRepository {
    temporary: Arc<TemporaryDirectory>,
    commit: String,
}

impl GitRepository {
    fn fetch(repository: &str, commit: &str) -> Result<Self> {
        validate_commit(commit)?;
        let temporary = Arc::new(TemporaryDirectory::new("pkgre-source")?);
        run_git(
            None,
            [
                OsStr::new("init"),
                OsStr::new("--quiet"),
                temporary.path().as_os_str(),
            ],
        )?;
        let checkout = Self {
            temporary,
            commit: commit.to_owned(),
        };
        checkout.run_fetch(repository, commit)?;
        Ok(checkout)
    }

    fn path(&self) -> &Path {
        self.temporary.path()
    }

    /// Fetches one more commit into this repository, when the fetch succeeds.
    fn fetch_commit(&self, repository: &str, commit: &str) -> Option<Self> {
        if let Err(error) = validate_commit(commit) {
            debug!(%repository, %commit, error = %format_args!("{error:#}"), "submodule commit is not a canonical Git object ID");
            return None;
        }
        if let Err(error) = self.run_fetch(repository, commit) {
            debug!(%repository, %commit, error = %format_args!("{error:#}"), "submodule fetch unavailable");
            return None;
        }
        Some(Self {
            temporary: Arc::clone(&self.temporary),
            commit: commit.to_owned(),
        })
    }

    fn run_fetch(&self, repository: &str, commit: &str) -> Result<()> {
        run_git(
            Some(self.path()),
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
            Some(self.path()),
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
        Ok(())
    }

    /// One `git ls-tree` record: its mode and object ID.
    fn tree_record(&self, path: &str) -> Result<Option<TreeRecord>> {
        let pathspec = format!(":(literal){path}");
        let output = run_git_output_allow_failure_with_limit(
            Some(self.path()),
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
        ensure!(
            &record[separator + 1..] == path.as_bytes(),
            "Git tree returned another path"
        );
        let metadata = std::str::from_utf8(metadata).context("Git tree metadata is not UTF-8")?;
        let mut fields = metadata.split(' ');
        let mode = fields.next().context("Git tree record has no mode")?;
        let kind = fields.next().context("Git tree record has no type")?;
        let object = fields.next().context("Git tree record has no object ID")?;
        ensure!(
            fields.next().is_none(),
            "Git tree record has extra metadata"
        );
        let expected_kind = match mode {
            "040000" => "tree",
            "160000" => "commit",
            "100644" | "100755" | "120000" => "blob",
            _ => bail!("Git tree path has unsupported mode {mode:?}"),
        };
        ensure!(kind == expected_kind, "Git tree record has an unknown type");
        Ok(Some(TreeRecord {
            mode: mode.to_owned(),
            object: object.to_owned(),
        }))
    }

    /// The bytes of one blob object.
    fn blob(&self, object: &str) -> Result<Vec<u8>> {
        let output = run_git_output_with_limit(
            Some(self.path()),
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
        Ok(output.stdout)
    }
}

struct TreeRecord {
    mode: String,
    object: String,
}

fn validate_commit(commit: &str) -> Result<()> {
    ensure!(
        matches!(commit.len(), 40 | 64)
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "source commit is not a canonical Git object ID"
    );
    Ok(())
}

impl GitTree for GitRepository {
    fn entry(&self, path: &str) -> Result<Option<TreeEntry>> {
        let Some(record) = self.tree_record(path)? else {
            return Ok(None);
        };
        match record.mode.as_str() {
            "100644" | "100755" => {
                let bytes = self.blob(&record.object)?;
                Ok(Some(TreeEntry::File {
                    sha256: sha256_bytes(&bytes),
                    executable: record.mode == "100755",
                }))
            }
            "120000" => {
                let bytes = self.blob(&record.object)?;
                let target =
                    String::from_utf8(bytes).context("Git symbolic-link target is not UTF-8")?;
                Ok(Some(TreeEntry::Symlink { target }))
            }
            "040000" => Ok(Some(TreeEntry::Directory)),
            "160000" => Ok(Some(TreeEntry::Gitlink {
                commit: record.object,
            })),
            mode => bail!("Git tree path has unsupported mode {mode:?}"),
        }
    }

    fn file_content(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let Some(record) = self.tree_record(path)? else {
            return Ok(None);
        };
        if !matches!(record.mode.as_str(), "100644" | "100755") {
            return Ok(None);
        }
        self.blob(&record.object).map(Some)
    }

    fn manifests(&self) -> Result<Vec<String>> {
        let output = run_git_output_with_limit(
            Some(self.path()),
            [
                OsStr::new("ls-tree"),
                OsStr::new("-r"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                OsStr::new(&self.commit),
            ],
            "list exact Git tree",
            MAX_GIT_TREE_BYTES,
        )?;
        let mut manifests = Vec::new();
        for record in output.stdout.split(|byte| *byte == 0) {
            let Some(separator) = record.iter().position(|byte| *byte == b'\t') else {
                continue;
            };
            let path = std::str::from_utf8(&record[separator + 1..])
                .context("Git tree path is not UTF-8")?;
            if path == "Cargo.toml" || path.ends_with("/Cargo.toml") {
                manifests.push(path.to_owned());
            }
        }
        Ok(manifests)
    }

    fn submodule(&self, repository: &str, commit: &str) -> Result<Option<Box<dyn GitTree>>> {
        Ok(self
            .fetch_commit(repository, commit)
            .map(|tree| Box::new(tree) as Box<dyn GitTree>))
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
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::update::EmbeddedVcsInfo;

    const COMMIT: &str = "0101010101010101010101010101010101010101";
    const SUBMODULE_COMMIT: &str = "0202020202020202020202020202020202020202";
    const SUBMODULE_REPOSITORY: &str = "https://github.com/example/vendored";

    /// One synthetic tree entry.
    #[derive(Clone)]
    enum FakeNode {
        File { contents: Vec<u8>, executable: bool },
        Symlink { target: String },
        Gitlink { commit: String },
    }

    fn text(contents: &str) -> FakeNode {
        FakeNode::File {
            contents: contents.as_bytes().to_vec(),
            executable: false,
        }
    }

    fn link(target: &str) -> FakeNode {
        FakeNode::Symlink {
            target: target.to_owned(),
        }
    }

    /// One synthetic repository tree.
    #[derive(Clone, Default)]
    struct FakeTree {
        files: BTreeMap<String, FakeNode>,
        submodules: BTreeMap<(String, String), FakeTree>,
    }

    impl FakeTree {
        fn new(files: impl IntoIterator<Item = (&'static str, FakeNode)>) -> Self {
            Self {
                files: files
                    .into_iter()
                    .map(|(path, node)| (path.to_owned(), node))
                    .collect(),
                submodules: BTreeMap::new(),
            }
        }

        fn with_submodule(mut self, tree: FakeTree) -> Self {
            self.submodules.insert(
                (SUBMODULE_REPOSITORY.to_owned(), SUBMODULE_COMMIT.to_owned()),
                tree,
            );
            self
        }
    }

    impl GitTree for FakeTree {
        fn entry(&self, path: &str) -> Result<Option<TreeEntry>> {
            match self.files.get(path) {
                Some(FakeNode::File {
                    contents,
                    executable,
                }) => Ok(Some(TreeEntry::File {
                    sha256: sha256_bytes(contents),
                    executable: *executable,
                })),
                Some(FakeNode::Symlink { target }) => Ok(Some(TreeEntry::Symlink {
                    target: target.clone(),
                })),
                Some(FakeNode::Gitlink { commit }) => Ok(Some(TreeEntry::Gitlink {
                    commit: commit.clone(),
                })),
                None if self
                    .files
                    .keys()
                    .any(|key| key.starts_with(&format!("{path}/"))) =>
                {
                    Ok(Some(TreeEntry::Directory))
                }
                None => Ok(None),
            }
        }

        fn file_content(&self, path: &str) -> Result<Option<Vec<u8>>> {
            match self.files.get(path) {
                Some(FakeNode::File { contents, .. }) => Ok(Some(contents.clone())),
                _ => Ok(None),
            }
        }

        fn manifests(&self) -> Result<Vec<String>> {
            Ok(self
                .files
                .keys()
                .filter(|path| *path == "Cargo.toml" || path.ends_with("/Cargo.toml"))
                .cloned()
                .collect())
        }

        fn submodule(&self, repository: &str, commit: &str) -> Result<Option<Box<dyn GitTree>>> {
            Ok(self
                .submodules
                .get(&(repository.to_owned(), commit.to_owned()))
                .map(|tree| Box::new(tree.clone()) as Box<dyn GitTree>))
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

    fn archive(files: Vec<ArchiveFile>, path_in_vcs: Option<&str>) -> ArchiveAnalysis {
        ArchiveAnalysis {
            compressed_bytes: 1,
            unpacked_bytes: 1,
            files,
            build_surface: BTreeMap::new(),
            vcs: Some(EmbeddedVcsInfo {
                commit: COMMIT.to_owned(),
                path_in_vcs: path_in_vcs.map(str::to_owned),
                file_sha256: sha256_bytes(b"generated"),
            }),
        }
    }

    fn anchor(path_in_vcs: Option<&str>) -> SourceAnchor<'_> {
        SourceAnchor {
            repository: "https://github.com/example/demo".to_owned(),
            commit: COMMIT,
            path_in_vcs,
            attestation_sha256: None,
        }
    }

    fn promoted(
        archive: &ArchiveAnalysis,
        original_manifest: Option<&[u8]>,
        path_in_vcs: Option<&str>,
        tree: &FakeTree,
    ) -> SourceCorrespondence {
        promote_source(&anchor(path_in_vcs), archive, original_manifest, tree).unwrap()
    }

    fn unavailable_reason(correspondence: &SourceCorrespondence) -> &str {
        match &correspondence.evidence {
            SourceEvidence::Unavailable { reason } => reason,
            evidence => panic!("expected unavailable evidence, got {evidence:?}"),
        }
    }

    fn report(correspondence: &SourceCorrespondence) -> &ComparisonReport {
        correspondence
            .comparison
            .as_ref()
            .expect("a comparison ran")
    }

    fn comparison<'a>(report: &'a ComparisonReport, archive_path: &str) -> &'a FileComparison {
        report
            .files
            .iter()
            .find(|file| file.archive_path == archive_path)
            .expect("the report covers the archive path")
    }

    #[test]
    fn public_repository_normalization_is_narrow_and_canonical() {
        for (value, expected) in [
            (
                "https://github.com/example/demo.git",
                "https://github.com/example/demo",
            ),
            (
                "https://github.com/example/demo/",
                "https://github.com/example/demo",
            ),
            (
                "https://github.com/example/demo.git/",
                "https://github.com/example/demo",
            ),
            (
                "https://github.com/RustCrypto/elliptic-curves/tree/master/k256",
                "https://github.com/RustCrypto/elliptic-curves",
            ),
            (
                "https://github.com/RustCrypto/elliptic-curves/blob/master/README.md",
                "https://github.com/RustCrypto/elliptic-curves",
            ),
            (
                "https://gitlab.com/group/subgroup/demo",
                "https://gitlab.com/group/subgroup/demo",
            ),
            (
                "https://gitlab.com/group/subgroup/demo/",
                "https://gitlab.com/group/subgroup/demo",
            ),
        ] {
            assert_eq!(
                normalize_public_repository(value).unwrap(),
                expected,
                "for {value:?}"
            );
        }
        for value in [
            "http://github.com/example/demo",
            "https://user@github.com/example/demo",
            "https://example.com/example/demo",
            "https://github.com/example/../demo",
            "https://github.com/example",
            "https://github.com/example/demo?ref=1",
        ] {
            assert!(
                normalize_public_repository(value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn repository_identities_compare_without_regard_to_case_on_github_only() {
        assert!(public_repositories_agree(
            "https://github.com/RustCrypto/elliptic-curves",
            "https://github.com/rustcrypto/elliptic-curves"
        ));
        assert!(public_repositories_agree(
            "https://github.com/example/demo/",
            "https://github.com/example/demo/tree/master/demo"
        ));
        assert!(!public_repositories_agree(
            "https://github.com/example/demo",
            "https://github.com/example/other"
        ));
        assert!(!public_repositories_agree(
            "https://gitlab.com/Group/demo",
            "https://gitlab.com/group/demo"
        ));
    }

    #[test]
    fn source_comparison_accounts_for_cargo_generated_files_and_manifest_original() {
        let archive = archive(
            vec![
                file(".cargo_vcs_info.json", b"generated"),
                file("Cargo.toml", b"normalized"),
                file("Cargo.toml.orig", b"source manifest"),
                file("src/lib.rs", b"source"),
            ],
            Some("crates/demo"),
        );
        let tree = FakeTree::new([
            ("crates/demo/Cargo.toml", text("source manifest")),
            ("crates/demo/src/lib.rs", text("source")),
        ]);
        let correspondence = promoted(
            &archive,
            Some(b"source manifest"),
            Some("crates/demo"),
            &tree,
        );
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        assert_eq!(report(&correspondence).path_in_vcs, "crates/demo");
        assert!(!report(&correspondence).located_path);
        assert_eq!(
            comparison(report(&correspondence), "Cargo.toml").disposition,
            "cargo-generated"
        );

        let mismatching = FakeTree::default();
        let correspondence = promoted(
            &archive,
            Some(b"source manifest"),
            Some("crates/demo"),
            &mismatching,
        );
        assert!(matches!(
            correspondence.evidence,
            SourceEvidence::Mismatch { .. }
        ));
        assert_eq!(
            report(&correspondence).describe_differences(),
            "Cargo.toml.orig (missing), src/lib.rs (missing)"
        );
    }

    /// One packaged archive whose repository tracks no lock file, as `cargo package` writes it.
    fn packaged_archive(source: &[u8]) -> ArchiveAnalysis {
        archive(
            vec![
                file(".cargo_vcs_info.json", b"generated"),
                file("Cargo.lock", b"packaged lock"),
                file("Cargo.toml", b"normalized"),
                file("Cargo.toml.orig", b"source manifest"),
                file("src/lib.rs", source),
            ],
            None,
        )
    }

    /// The tracked files of [`packaged_archive`]'s repository, which holds no `Cargo.lock`.
    fn packaged_tree(source: &[u8]) -> FakeTree {
        FakeTree::new([
            ("Cargo.toml", text("source manifest")),
            (
                "src/lib.rs",
                FakeNode::File {
                    contents: source.to_vec(),
                    executable: false,
                },
            ),
        ])
    }

    #[test]
    fn source_comparison_ignores_the_packaged_root_lock_file() {
        let archive = packaged_archive(b"source");
        let correspondence = promoted(
            &archive,
            Some(b"source manifest"),
            None,
            &packaged_tree(b"source"),
        );
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        let lock = comparison(report(&correspondence), "Cargo.lock");
        assert_eq!(lock.disposition, "cargo-generated");
        assert!(
            lock.expected_path.is_none(),
            "the lock file is not looked up"
        );
        assert!(lock.repository_sha256.is_none());
        assert_eq!(lock.archive_sha256, sha256_bytes(b"packaged lock"));
    }

    #[test]
    fn source_comparison_still_detects_a_changed_source_file_beside_the_lock_file() {
        let archive = packaged_archive(b"changed source");
        let correspondence = promoted(
            &archive,
            Some(b"source manifest"),
            None,
            &packaged_tree(b"source"),
        );
        assert!(matches!(
            correspondence.evidence,
            SourceEvidence::Mismatch { .. }
        ));
        let source = comparison(report(&correspondence), "src/lib.rs");
        assert_eq!(source.disposition, "different");
        assert_eq!(
            comparison(report(&correspondence), "Cargo.lock").disposition,
            "cargo-generated"
        );
    }

    #[test]
    fn source_comparison_still_compares_a_lock_file_below_the_package_root() {
        let mut archive = packaged_archive(b"source");
        archive
            .files
            .push(file("tests/fixtures/Cargo.lock", b"fixture lock"));
        let correspondence = promoted(
            &archive,
            Some(b"source manifest"),
            None,
            &packaged_tree(b"source"),
        );
        assert!(matches!(
            correspondence.evidence,
            SourceEvidence::Mismatch { .. }
        ));
        let nested = comparison(report(&correspondence), "tests/fixtures/Cargo.lock");
        assert_eq!(nested.disposition, "missing");
        assert_eq!(
            nested.expected_path.as_deref(),
            Some("tests/fixtures/Cargo.lock")
        );
    }

    #[test]
    fn package_without_a_vcs_path_is_located_by_its_original_manifest() {
        let archive = archive(
            vec![
                file(".cargo_vcs_info.json", b"generated"),
                file("Cargo.toml", b"normalized"),
                file("Cargo.toml.orig", b"member manifest"),
                file("src/lib.rs", b"member source"),
            ],
            None,
        );
        let tree = FakeTree::new([
            ("Cargo.toml", text("workspace manifest")),
            ("other/Cargo.toml", text("other manifest")),
            ("member/Cargo.toml", text("member manifest")),
            ("member/src/lib.rs", text("member source")),
        ]);
        let correspondence = promoted(&archive, Some(b"member manifest"), None, &tree);
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        assert_eq!(report(&correspondence).path_in_vcs, "member");
        assert!(report(&correspondence).located_path);
        let source = comparison(report(&correspondence), "src/lib.rs");
        assert_eq!(source.disposition, "match");
        assert_eq!(source.expected_path.as_deref(), Some("member/src/lib.rs"));
    }

    #[test]
    fn package_path_is_unavailable_when_several_manifests_match() {
        let archive = archive(
            vec![
                file("Cargo.toml.orig", b"member manifest"),
                file("src/lib.rs", b"member source"),
            ],
            None,
        );
        let tree = FakeTree::new([
            ("first/Cargo.toml", text("member manifest")),
            ("second/Cargo.toml", text("member manifest")),
            ("first/src/lib.rs", text("member source")),
            ("second/src/lib.rs", text("member source")),
        ]);
        let correspondence = promoted(&archive, Some(b"member manifest"), None, &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-package-path-ambiguous"
        );
    }

    #[test]
    fn package_path_is_unavailable_when_no_manifest_matches() {
        let archive = archive(
            vec![
                file("Cargo.toml.orig", b"member manifest"),
                file("src/lib.rs", b"member source"),
            ],
            None,
        );
        let tree = FakeTree::new([
            ("Cargo.toml", text("workspace manifest")),
            ("src/lib.rs", text("member source")),
        ]);
        let correspondence = promoted(&archive, Some(b"member manifest"), None, &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-package-path-not-located"
        );
    }

    /// One workspace member that copies its readme into the package root.
    fn member_archive(readme: &[u8], manifest: &[u8]) -> ArchiveAnalysis {
        archive(
            vec![
                file(".cargo_vcs_info.json", b"generated"),
                file("Cargo.toml", b"normalized"),
                file("Cargo.toml.orig", manifest),
                file("README.md", readme),
                file("src/lib.rs", b"member source"),
            ],
            Some("member"),
        )
    }

    fn member_tree(manifest: &str, readme: &str) -> FakeTree {
        FakeTree::new([
            ("Cargo.toml", text("workspace manifest")),
            ("README.md", text(readme)),
            ("member/Cargo.toml", text(manifest)),
            ("member/src/lib.rs", text("member source")),
        ])
    }

    #[test]
    fn readme_copied_from_the_parent_directory_is_compared_with_its_source() {
        let manifest = "[package]\nname = \"demo\"\nreadme = \"../README.md\"\n";
        let archive = member_archive(b"workspace readme", manifest.as_bytes());
        let correspondence = promoted(
            &archive,
            Some(manifest.as_bytes()),
            Some("member"),
            &member_tree(manifest, "workspace readme"),
        );
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        let readme = comparison(report(&correspondence), "README.md");
        assert_eq!(readme.disposition, "match");
        assert!(readme.copied, "the readme was copied from the workspace");
        assert_eq!(readme.compared_path.as_deref(), Some("README.md"));
        assert_eq!(readme.expected_path.as_deref(), Some("member/README.md"));
    }

    #[test]
    fn readme_copied_through_the_workspace_package_table_is_compared_with_its_source() {
        let manifest = "[package]\nname = \"demo\"\nreadme.workspace = true\n";
        let archive = member_archive(b"workspace readme", manifest.as_bytes());
        let tree = FakeTree::new([
            (
                "Cargo.toml",
                text(
                    "[workspace]\nmembers = [\"member\"]\n\n[workspace.package]\nreadme = \"README.md\"\n",
                ),
            ),
            ("README.md", text("workspace readme")),
            ("member/Cargo.toml", text(manifest)),
            ("member/src/lib.rs", text("member source")),
        ]);
        let correspondence = promoted(&archive, Some(manifest.as_bytes()), Some("member"), &tree);
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        let readme = comparison(report(&correspondence), "README.md");
        assert_eq!(readme.disposition, "match");
        assert!(readme.copied);
        assert_eq!(readme.compared_path.as_deref(), Some("README.md"));
    }

    #[test]
    fn copied_readme_that_differs_from_its_source_still_mismatches() {
        let manifest = "[package]\nname = \"demo\"\nreadme = \"../README.md\"\n";
        let archive = member_archive(b"archived readme", manifest.as_bytes());
        let correspondence = promoted(
            &archive,
            Some(manifest.as_bytes()),
            Some("member"),
            &member_tree(manifest, "workspace readme"),
        );
        assert!(matches!(
            correspondence.evidence,
            SourceEvidence::Mismatch { .. }
        ));
        let readme = comparison(report(&correspondence), "README.md");
        assert_eq!(readme.disposition, "different");
        assert!(readme.copied);
    }

    #[test]
    fn copied_readme_outside_the_repository_stays_missing() {
        let manifest = "[package]\nname = \"demo\"\nreadme = \"../../../README.md\"\n";
        let archive = member_archive(b"workspace readme", manifest.as_bytes());
        let correspondence = promoted(
            &archive,
            Some(manifest.as_bytes()),
            Some("member"),
            &member_tree(manifest, "workspace readme"),
        );
        assert!(matches!(
            correspondence.evidence,
            SourceEvidence::Mismatch { .. }
        ));
        let readme = comparison(report(&correspondence), "README.md");
        assert_eq!(readme.disposition, "missing");
        assert!(!readme.copied);
    }

    #[test]
    fn symbolic_link_file_is_compared_with_its_target() {
        let archive = archive(
            vec![
                file("Cargo.toml.orig", b"manifest"),
                file("LICENSE-MIT", b"license text"),
            ],
            Some("member"),
        );
        let tree = FakeTree::new([
            ("member/Cargo.toml", text("manifest")),
            ("legal/LICENSE-MIT", text("license text")),
            ("member/LICENSE-MIT", link("../legal/LICENSE-MIT")),
        ]);
        let correspondence = promoted(&archive, Some(b"manifest"), Some("member"), &tree);
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        let license = comparison(report(&correspondence), "LICENSE-MIT");
        assert_eq!(license.disposition, "match");
        assert_eq!(license.compared_path.as_deref(), Some("member/LICENSE-MIT"));
        assert_eq!(license.resolved_path.as_deref(), Some("legal/LICENSE-MIT"));
        assert!(license.submodule.is_none());
    }

    #[test]
    fn file_below_a_linked_directory_is_compared_with_its_target() {
        let archive = archive(
            vec![
                file("Cargo.toml.orig", b"manifest"),
                file("vendor/lib.rs", b"vendored source"),
            ],
            Some("member"),
        );
        let tree = FakeTree::new([
            ("member/Cargo.toml", text("manifest")),
            ("shared/lib.rs", text("vendored source")),
            ("member/vendor", link("../shared")),
        ]);
        let correspondence = promoted(&archive, Some(b"manifest"), Some("member"), &tree);
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        let vendored = comparison(report(&correspondence), "vendor/lib.rs");
        assert_eq!(vendored.disposition, "match");
        assert_eq!(vendored.resolved_path.as_deref(), Some("shared/lib.rs"));
    }

    #[test]
    fn symbolic_link_escaping_the_repository_is_unavailable() {
        let archive = archive(
            vec![
                file("Cargo.toml.orig", b"manifest"),
                file("escape", b"outside"),
            ],
            Some("member"),
        );
        let tree = FakeTree::new([
            ("member/Cargo.toml", text("manifest")),
            ("member/escape", link("../../outside")),
        ]);
        let correspondence = promoted(&archive, Some(b"manifest"), Some("member"), &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-symlink-escapes-repository"
        );
    }

    #[test]
    fn symbolic_link_loop_is_unavailable() {
        let archive = archive(
            vec![file("Cargo.toml.orig", b"manifest"), file("first", b"loop")],
            Some("member"),
        );
        let tree = FakeTree::new([
            ("member/Cargo.toml", text("manifest")),
            ("member/first", link("second")),
            ("member/second", link("first")),
        ]);
        let correspondence = promoted(&archive, Some(b"manifest"), Some("member"), &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-path-redirect-loop"
        );
    }

    #[test]
    fn nested_manifest_original_is_compared_like_any_other_file() {
        let archive = archive(
            vec![
                file("Cargo.toml", b"normalized"),
                file("Cargo.toml.orig", b"manifest"),
                file("src/Cargo.toml", b"nested bytes"),
                file("src/Cargo.toml.orig", b"nested source"),
            ],
            Some("member"),
        );
        let tree = FakeTree::new([
            ("member/Cargo.toml", text("manifest")),
            ("member/src/Cargo.toml.orig", text("nested source")),
        ]);
        let correspondence = promoted(&archive, Some(b"manifest"), Some("member"), &tree);
        assert!(matches!(
            correspondence.evidence,
            SourceEvidence::Mismatch { .. }
        ));
        let nested = comparison(report(&correspondence), "src/Cargo.toml");
        assert_eq!(nested.disposition, "missing");
        assert_eq!(
            nested.expected_path.as_deref(),
            Some("member/src/Cargo.toml")
        );
        assert_eq!(
            comparison(report(&correspondence), "Cargo.toml").disposition,
            "cargo-generated"
        );
    }

    /// One archive that packages a submodule's checked-out files below the package root.
    fn submodule_archive(contents: &[u8]) -> ArchiveAnalysis {
        archive(
            vec![
                file("Cargo.toml.orig", b"manifest"),
                file("vendor/lib.rs", contents),
            ],
            Some(""),
        )
    }

    /// The tree of [`submodule_archive`]'s repository, which mounts one submodule.
    fn submodule_tree(url: &str) -> FakeTree {
        FakeTree::new([
            ("Cargo.toml", text("manifest")),
            (
                ".gitmodules",
                text(&format!(
                    "[submodule \"vendor\"]\n\tpath = vendor\n\turl = {url}\n"
                )),
            ),
            (
                "vendor",
                FakeNode::Gitlink {
                    commit: SUBMODULE_COMMIT.to_owned(),
                },
            ),
        ])
        .with_submodule(FakeTree::new([("lib.rs", text("vendored source"))]))
    }

    #[test]
    fn submodule_members_are_compared_in_the_submodule_tree() {
        let archive = submodule_archive(b"vendored source");
        let tree = submodule_tree(SUBMODULE_REPOSITORY);
        let correspondence = promoted(&archive, Some(b"manifest"), Some(""), &tree);
        assert!(
            matches!(
                correspondence.evidence,
                SourceEvidence::PublisherAsserted { .. }
            ),
            "unexpected evidence {:?}",
            correspondence.evidence
        );
        let vendored = comparison(report(&correspondence), "vendor/lib.rs");
        assert_eq!(vendored.disposition, "match");
        assert_eq!(vendored.compared_path.as_deref(), Some("vendor/lib.rs"));
        assert_eq!(vendored.resolved_path.as_deref(), Some("lib.rs"));
        assert_eq!(vendored.submodule.as_deref(), Some(SUBMODULE_REPOSITORY));
    }

    #[test]
    fn submodule_without_a_supported_repository_is_unavailable() {
        let archive = submodule_archive(b"vendored source");
        let tree = submodule_tree("https://example.com/example/vendored.git");
        let correspondence = promoted(&archive, Some(b"manifest"), Some(""), &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-submodule-repository-is-unsupported"
        );
    }

    #[test]
    fn submodule_fetch_failure_is_unavailable() {
        let archive = submodule_archive(b"vendored source");
        let mut tree = submodule_tree(SUBMODULE_REPOSITORY);
        tree.submodules.clear();
        let correspondence = promoted(&archive, Some(b"manifest"), Some(""), &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-submodule-fetch-failed"
        );
    }

    #[test]
    fn nested_submodule_is_unavailable() {
        let archive = archive(
            vec![
                file("Cargo.toml.orig", b"manifest"),
                file("vendor/inner/lib.rs", b"nested source"),
            ],
            Some(""),
        );
        let mut tree = submodule_tree(SUBMODULE_REPOSITORY);
        let inner = FakeTree::new([
            (
                "inner",
                FakeNode::Gitlink {
                    commit: SUBMODULE_COMMIT.to_owned(),
                },
            ),
            (
                ".gitmodules",
                text(
                    "[submodule \"inner\"]\n\tpath = inner\n\turl = https://github.com/example/inner\n",
                ),
            ),
        ]);
        tree.submodules.insert(
            (SUBMODULE_REPOSITORY.to_owned(), SUBMODULE_COMMIT.to_owned()),
            inner,
        );
        let correspondence = promoted(&archive, Some(b"manifest"), Some(""), &tree);
        assert_eq!(
            unavailable_reason(&correspondence),
            "repository-submodule-is-nested"
        );
    }

    #[test]
    fn comparison_differences_are_bounded_and_named() {
        let mut files = vec![file("Cargo.toml.orig", b"manifest")];
        for index in 0..25 {
            files.push(file(&format!("src/file{index}.rs"), b"archived"));
        }
        let archive = archive(files, Some(""));
        let tree = FakeTree::new([("Cargo.toml", text("manifest"))]);
        let correspondence = promoted(&archive, Some(b"manifest"), Some(""), &tree);
        let described = report(&correspondence).describe_differences();
        assert_eq!(described.matches(" (missing)").count(), 20);
        assert!(described.ends_with(", and 5 more"), "{described}");
        assert!(described.starts_with("src/file0.rs (missing)"));
    }

    /// Runs one isolated Git command in a synthetic repository.
    fn test_git(directory: &Path, arguments: &[&str]) -> String {
        let mut command = git_command(
            Some(directory),
            arguments.iter().map(OsStr::new).collect::<Vec<&OsStr>>(),
        );
        let output = command.output().expect("run synthetic Git command");
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("synthetic Git output is UTF-8")
    }

    #[test]
    fn git_repository_reads_files_links_gitlinks_and_manifests() {
        let temporary = TemporaryDirectory::new("pkgre-source-test").unwrap();
        let root = temporary.path().to_owned();
        test_git(&root, &["init", "--quiet", "."]);
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("Cargo.toml"), b"manifest\n").unwrap();
        fs::write(root.join("sub/Cargo.toml"), b"member\n").unwrap();
        fs::create_dir_all(root.join("legal")).unwrap();
        fs::write(root.join("legal/LICENSE-MIT"), b"license\n").unwrap();
        fs::create_dir_all(root.join("member")).unwrap();
        symlink("../legal/LICENSE-MIT", root.join("member/LICENSE-MIT")).unwrap();
        test_git(&root, &["add", "-A"]);
        test_git(
            &root,
            &[
                "-c",
                "user.name=synthetic",
                "-c",
                "user.email=synthetic@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "synthetic",
            ],
        );
        let linked = test_git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
        test_git(
            &root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{linked},vendor"),
            ],
        );
        test_git(
            &root,
            &[
                "-c",
                "user.name=synthetic",
                "-c",
                "user.email=synthetic@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "submodule",
            ],
        );
        let commit = test_git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
        let repository = GitRepository {
            temporary: Arc::new(temporary),
            commit,
        };

        let manifest = repository.entry("Cargo.toml").unwrap().unwrap();
        assert!(
            matches!(
                &manifest,
                TreeEntry::File { sha256, executable } if sha256 == &sha256_bytes(b"manifest\n") && !executable
            ),
            "unexpected manifest entry {manifest:?}"
        );
        assert_eq!(
            repository
                .file_content("sub/Cargo.toml")
                .unwrap()
                .as_deref(),
            Some(&b"member\n"[..])
        );
        assert!(
            matches!(
                repository.entry("member").unwrap(),
                Some(TreeEntry::Directory)
            ),
            "member is a directory"
        );
        let license = repository.entry("member/LICENSE-MIT").unwrap().unwrap();
        assert!(
            matches!(&license, TreeEntry::Symlink { target } if target == "../legal/LICENSE-MIT"),
            "unexpected link entry {license:?}"
        );
        let gitlink = repository.entry("vendor").unwrap().unwrap();
        assert!(
            matches!(&gitlink, TreeEntry::Gitlink { commit } if commit == &linked),
            "unexpected gitlink entry {gitlink:?}"
        );
        assert_eq!(
            repository.manifests().unwrap(),
            ["Cargo.toml", "sub/Cargo.toml"]
        );
        assert!(repository.entry("absent").unwrap().is_none());
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
