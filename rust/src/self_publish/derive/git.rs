//! Fetching one immutable release tag into a fresh checkout.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::super::git;
use super::super::isolation::ChildEnvironment;
use crate::package::ensure_safe_checkout_tree;
use crate::policy::{validate_git_object_id, validate_git_tag, validate_https_repository};

/// A checkout of exactly one tag, as immutable release evidence.
pub(super) struct TagCheckout {
    /// Root of the fresh checkout.
    pub(super) root: PathBuf,
    /// Exact tag object ID; equals the commit for a lightweight tag.
    pub(super) tag_oid: String,
    /// Full peeled commit object ID.
    pub(super) commit: String,
    /// Repository-relative paths that the tag's index records as Gitlinks,
    /// which no submodule fetch initializes.
    pub(super) gitlinks: Vec<PathBuf>,
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
/// that is not an object ID, a checkout with symlinks or unsafe paths, or a
/// checkout that is not clean.
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
    git::run(
        None,
        [
            OsString::from("init"),
            OsString::from("--quiet"),
            checkout.as_os_str().to_owned(),
        ],
        environment,
        allow_file,
    )?;
    git::run(
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
    git::run(
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
    let tag_oid = git::stdout(
        checkout,
        [
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(&reference),
        ],
        environment,
        allow_file,
    )?;
    let commit = git::stdout(
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
    git::run(
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
    let gitlinks = crate::gitlinks::gitlinks_in_index(&git::stdout(
        checkout,
        [OsString::from("ls-files"), OsString::from("--stage")],
        environment,
        allow_file,
    )?);
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
        gitlinks,
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
    let status = git::stdout(
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
