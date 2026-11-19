//! Reproduction of the Git-tag identities that a catalog change adds.
//!
//! [`crate::lock`] applies the Git-tag rules, a committed `Cargo.lock`, the packaged lock bound
//! to it, no `[patch]`, and no retired registry alias, only when it first locks a tag, and
//! [`crate::check`] never fetches a tag. A Git-tag identity that an older tool locked, or that a
//! hand edit wrote, therefore passes both. [`reproduce_added_git_tags`] fetches every Git-tag
//! identity the candidate adds, packages it again, and proves it against the archive and the
//! source row the candidate locks, so that a repository's CI applies the rules to just those
//! identities the way a first `lock` would.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::schema::{Approval, Catalog, PackageState, Source};

/// Summary of one `reproduce-git-tags` run.
#[derive(Clone, Copy, Debug)]
pub struct ReproduceSummary {
    /// Number of added Git-tag identities that the run reproduced.
    pub reproduced: usize,
}

/// Returns every Git-tag identity the candidate adds, ordered by registry, name, and version.
///
/// An identity the accepted catalog locks is not selected, whatever state either catalog records
/// for it: the reproduction answers for what a change adds, and an accepted identity is retained
/// byte for byte, so its archive and source row are the ones the earlier run locked.
///
/// A removed Git-tag identity that the accepted catalog does not lock is refused. `lock` writes a
/// tombstone only for an identity the generated lock already holds, so a change whose candidate
/// adds one was not produced by `lock`, and no reproduction could make it a self-consistent lock.
///
/// # Errors
///
/// Returns an error for a removed Git-tag identity that the accepted catalog does not lock.
pub fn added_git_tag_identities<'a>(
    accepted: &[Approval],
    candidate: &'a [Approval],
) -> Result<Vec<&'a Approval>> {
    let locked = accepted
        .iter()
        .map(identity_key)
        .collect::<BTreeSet<(String, String, Version)>>();
    let mut added: Vec<&Approval> = Vec::new();
    for approval in candidate {
        if !matches!(approval.source, Source::GitTag { .. })
            || locked.contains(&identity_key(approval))
        {
            continue;
        }
        ensure!(
            approval.state == PackageState::Active,
            "{} is a removed Git-tag identity that the accepted catalog does not lock; \
             a removal only follows an identity the accepted catalog locked, \
             so this lock was not produced by `lock`",
            identity_name(approval)
        );
        added.push(approval);
    }
    added.sort_by_key(|value| identity_key(value));
    Ok(added)
}

/// Reproduces every Git-tag identity that `candidate_root` adds to `accepted_root`.
///
/// Both catalogs are loaded and policy-checked as `check-transition` and `check` load them, and
/// every selected identity is reproduced by [`crate::package::reproduce_approved_git`], which
/// verifies the tag object, the peeled commit, the package directory, the archive, and the source
/// row. The first failure stops the run and names the identity, as the other commands report the
/// first thing that makes a catalog invalid.
///
/// A change that adds no Git-tag identity reads no network and succeeds.
///
/// # Errors
///
/// Returns an error for a catalog that fails to load or to pass policy, for a removed Git-tag
/// identity that the accepted catalog does not lock, and for the first identity that does not
/// reproduce.
pub fn reproduce_added_git_tags(
    accepted_root: &Path,
    candidate_root: &Path,
) -> Result<ReproduceSummary> {
    let accepted = Catalog::load(accepted_root)
        .with_context(|| format!("load accepted catalog {}", accepted_root.display()))?;
    crate::policy::validate_catalog(&accepted)
        .with_context(|| format!("validate accepted catalog {}", accepted_root.display()))?;
    let candidate = Catalog::load(candidate_root)
        .with_context(|| format!("load candidate catalog {}", candidate_root.display()))?;
    crate::policy::validate_catalog(&candidate)
        .with_context(|| format!("validate candidate catalog {}", candidate_root.display()))?;
    let added = added_git_tag_identities(&accepted.approvals, &candidate.approvals)?;
    let reproduced = reproduce_selected(&added, |approval| {
        crate::package::reproduce_approved_git(approval).map(|_| ())
    })?;
    Ok(ReproduceSummary { reproduced })
}

/// Reproduces the given approvals with `reproduce`, stopping at the first failure.
///
/// A test supplies its own reproducer, so that the selection and the report of a failure run
/// without network.
///
/// # Errors
///
/// Returns the first failure of `reproduce`, named with the identity it belongs to.
pub(crate) fn reproduce_selected(
    approvals: &[&Approval],
    mut reproduce: impl FnMut(&Approval) -> Result<()>,
) -> Result<usize> {
    for approval in approvals {
        reproduce(approval)
            .with_context(|| format!("reproduce added {}", identity_name(approval)))?;
    }
    Ok(approvals.len())
}

/// Returns the (registry, name, version) identity a catalog change adds or retains.
fn identity_key(approval: &Approval) -> (String, String, Version) {
    (
        approval.registry.clone(),
        approval.name.clone(),
        approval.version.clone(),
    )
}

/// Returns one identity as `registry/name/version`, as the catalogs name it in diagnostics.
fn identity_name(approval: &Approval) -> String {
    format!(
        "{}/{}/{}",
        approval.registry, approval.name, approval.version
    )
}

#[cfg(test)]
#[path = "../../tests/unit/reproduce/mod.rs"]
mod tests;
