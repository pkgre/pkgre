//! Reproduction of the Git-tag identities that a catalog change adds.
//!
//! [`crate::lock`] applies the Git-tag rules, a committed `Cargo.lock`, the packaged lock bound
//! to it, no `[patch]`, and no retired registry alias, only when it first locks a tag, and
//! [`crate::check`] never fetches a tag. A Git-tag identity that an older tool locked, or that a
//! hand edit wrote, therefore passes both. [`reproduce_added_git_tags`] fetches every Git-tag
//! identity the candidate adds, packages the identities of one tag again in one resolution as
//! `lock` packages them, and proves each against the archive and the source row the candidate
//! locks, so that a repository's CI applies the rules to just those identities the way a first
//! `lock` would.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
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
/// every selected identity is reproduced by [`crate::package::reproduce_approved_git_group`],
/// which verifies the tag object, the peeled commit, the package directory, the archive, and the
/// source row. The identities of one repository and tag are reproduced in one resolution, as
/// `lock` packages them, so that a package of the tag may depend on another one; the groups run in
/// registry, repository, and tag order. The first failure stops the run and names the group, as the
/// other commands report the first thing that makes a catalog invalid.
///
/// A change that adds no Git-tag identity reads no network and succeeds.
///
/// # Errors
///
/// Returns an error for a catalog that fails to load or to pass policy, for a removed Git-tag
/// identity that the accepted catalog does not lock, and for the first group that does not
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
    let groups = git_tag_groups(&added)?;
    let reproduced = reproduce_groups(&groups, |group| {
        crate::package::reproduce_approved_git_group(&candidate.approvals, group).map(|_| ())
    })?;
    Ok(ReproduceSummary { reproduced })
}

/// Returns the selected identities grouped by the registry, repository, and tag
/// that one resolution packages.
///
/// `lock` resolves the declarations of one repository and tag together, so that a
/// package of the tag may depend on another one, and a reproduction does the
/// same. The groups are ordered by registry, repository, and tag, and each keeps
/// the name-and-version order of the selection.
///
/// # Errors
///
/// Returns an error for a selected approval that is not a Git-tag publication.
fn git_tag_groups<'a>(approvals: &[&'a Approval]) -> Result<Vec<Vec<&'a Approval>>> {
    let mut groups: BTreeMap<(String, String, String), Vec<&'a Approval>> = BTreeMap::new();
    for &approval in approvals {
        let Source::GitTag {
            repository, tag, ..
        } = &approval.source
        else {
            bail!(
                "{} {} is not a Git-tag publication",
                approval.name,
                approval.version
            );
        };
        groups
            .entry((approval.registry.clone(), repository.clone(), tag.clone()))
            .or_default()
            .push(approval);
    }
    Ok(groups.into_values().collect())
}

/// Reproduces the given groups with `reproduce`, stopping at the first failure,
/// and returns the number of identities the groups hold.
///
/// A test supplies its own reproducer, so that the grouping and the report of a failure run
/// without network.
///
/// # Errors
///
/// Returns the first failure of `reproduce`, named with the group it belongs to.
pub(crate) fn reproduce_groups(
    groups: &[Vec<&Approval>],
    mut reproduce: impl FnMut(&[&Approval]) -> Result<()>,
) -> Result<usize> {
    let mut reproduced = 0;
    for group in groups {
        reproduce(group).with_context(|| group_name(group))?;
        reproduced += group.len();
    }
    Ok(reproduced)
}

/// Returns one group as the diagnostics name it.
fn group_name(group: &[&Approval]) -> String {
    let Some(first) = group.first() else {
        return "reproduce a Git-tag group that names no identity".to_owned();
    };
    let names = group
        .iter()
        .map(|approval| identity_name(approval))
        .collect::<Vec<_>>()
        .join(", ");
    let Source::GitTag { tag, .. } = &first.source else {
        return format!("reproduce added {names}");
    };
    format!("reproduce added {names} of tag {tag:?}")
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
