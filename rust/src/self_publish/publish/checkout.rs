//! The checkout that a run publishes from.
//!
//! A release reaches crates.io only from a checkout whose `HEAD` is merged into
//! the remote-tracking `origin/main`, so that what an upload publishes is a
//! release that passed review, and only from a clean checkout, so that no
//! uncommitted change reaches `crates-io.lock` or the catalog. The routine never
//! fetches: a checkout that is behind says so, and the person who uploads runs
//! `git fetch` first.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

use super::super::git;
use super::super::isolation::ChildEnvironment;

/// The remote-tracking branch that a release has to be merged into.
const MERGED_INTO: &str = "refs/remotes/origin/main";
/// Most bytes of a dirty checkout's file listing that an error keeps.
const MAX_STATUS_BYTES: usize = 4 * 1024;

/// Requires a clean checkout whose `HEAD` is contained in `origin/main`.
///
/// # Errors
///
/// Returns an error when the directory is not a Git work tree, when the
/// checkout has staged, unstaged, or untracked changes, when it has no
/// remote-tracking `origin/main`, or when `HEAD` is not an ancestor of it.
pub(super) fn require_clean_merged_checkout(repository: &Path) -> Result<()> {
    let environment = ChildEnvironment::plain();
    let inside = git::stdout(
        repository,
        ["rev-parse", "--is-inside-work-tree"],
        &environment,
        false,
    )
    .with_context(|| {
        format!(
            "read the Git checkout {}; the routine publishes from a checkout of the catalog repository",
            repository.display()
        )
    })?;
    ensure!(
        inside == "true",
        "{} is not a Git checkout of the catalog repository",
        repository.display()
    );
    let status = git::stdout(
        repository,
        ["status", "--porcelain", "--untracked-files=normal"],
        &environment,
        false,
    )
    .with_context(|| format!("read the Git status of {}", repository.display()))?;
    ensure!(
        status.is_empty(),
        "the checkout {} has staged, unstaged, or untracked changes, and the routine publishes only from a clean checkout:\n{}",
        repository.display(),
        bounded(&status)
    );
    let head = git::stdout(
        repository,
        ["rev-parse", "--verify", "HEAD"],
        &environment,
        false,
    )
    .with_context(|| format!("read HEAD of the checkout {}", repository.display()))?;
    let merged_into = git::stdout(
        repository,
        ["rev-parse", "--verify", MERGED_INTO],
        &environment,
        false,
    )
    .with_context(|| {
        format!(
            "the checkout {} has no remote-tracking origin/main; run `git fetch origin main` first, since the routine never fetches",
            repository.display()
        )
    })?;
    let output = git::spawn(
        git::command(
            Some(repository),
            ["merge-base", "--is-ancestor", &head, MERGED_INTO],
            &environment,
            false,
        ),
        "test whether HEAD is merged into origin/main",
    )?;
    match output.status.code() {
        Some(0) => Ok(()),
        Some(1) => bail!(
            "HEAD {head} of {} is not contained in the remote-tracking origin/main ({merged_into}); only merged releases are published, so run `git fetch origin main` first, since the routine never fetches",
            repository.display()
        ),
        _ => bail!(
            "git merge-base exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

/// Keeps the start of a dirty checkout's listing in its error.
fn bounded(text: &str) -> &str {
    match text.char_indices().nth(MAX_STATUS_BYTES) {
        Some((cut, _)) => &text[..cut],
        None => text,
    }
}
