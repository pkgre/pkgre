//! Accepted-to-candidate semantic transition validation for serving catalog updates.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::download::DownloadCatalog;
use crate::schema::{Approval, Catalog, PackageState};

/// Exact semantic reason one candidate catalog must be rejected as an accepted successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// A candidate registry declaration changed topology relevant to serving.
    RegistryTopology(String),
    /// A package identity disappeared from the candidate locks.
    MissingIdentity(String),
    /// An accepted identity changed immutable archive, source, or admission evidence.
    MutatedIdentity(String),
    /// A package name moved to another category, changing its dependency scope.
    CategoryMove(String),
    /// A retained body object is missing or does not match its content hash.
    MissingRetainedBody(String),
}

impl fmt::Display for RejectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryTopology(detail) => {
                write!(formatter, "registry topology changed: {detail}")
            }
            Self::MissingIdentity(identity) => {
                write!(formatter, "identity disappeared: {identity}")
            }
            Self::MutatedIdentity(identity) => {
                write!(formatter, "identity mutated: {identity}")
            }
            Self::CategoryMove(identity) => {
                write!(formatter, "identity changed category: {identity}")
            }
            Self::MissingRetainedBody(detail) => {
                write!(formatter, "retained body missing: {detail}")
            }
        }
    }
}

/// Validates that `candidate` is a legal serving successor of `accepted`.
///
/// Both catalogs must strictly load as schema 5. Registry serving topology must be identical,
/// every accepted identity must be retained with immutable evidence, category homes must not
/// move, and every retained body must be present with a matching SHA-256.
///
/// # Errors
///
/// Returns the first [`RejectReason`] violated by the candidate, or a load/validation error.
pub fn check_transition(accepted_root: &Path, candidate_root: &Path) -> Result<(), RejectReason> {
    let accepted =
        Catalog::load(accepted_root).map_err(|error| RejectReason::load("accepted", &error))?;
    crate::policy::validate_catalog(&accepted)
        .map_err(|error| RejectReason::load("accepted", &error))?;
    let candidate =
        Catalog::load(candidate_root).map_err(|error| RejectReason::load("candidate", &error))?;
    crate::policy::validate_catalog(&candidate)
        .map_err(|error| RejectReason::load("candidate", &error))?;

    for accepted_registry in &accepted.registries.registries {
        let candidate_registry = candidate
            .registries
            .registries
            .iter()
            .find(|registry| registry.name == accepted_registry.name)
            .ok_or_else(|| {
                RejectReason::RegistryTopology(format!(
                    "registry {:?} disappeared",
                    accepted_registry.name
                ))
            })?;
        ensure_topology(accepted_registry, candidate_registry)?;
    }
    for candidate_registry in &candidate.registries.registries {
        if !accepted
            .registries
            .registries
            .iter()
            .any(|registry| registry.name == candidate_registry.name)
        {
            return Err(RejectReason::RegistryTopology(format!(
                "registry {:?} appeared",
                candidate_registry.name
            )));
        }
    }

    let candidate_index = candidate
        .approvals
        .iter()
        .map(|approval| (identity_key(approval), approval))
        .collect::<BTreeMap<_, _>>();
    for accepted_approval in &accepted.approvals {
        let identity = identity_key(accepted_approval);
        let candidate_approval = candidate_index.get(&identity).ok_or_else(|| {
            RejectReason::MissingIdentity(format!(
                "{}/{}/{}",
                accepted_approval.registry, accepted_approval.name, accepted_approval.version
            ))
        })?;
        if accepted_approval.archive_sha256 != candidate_approval.archive_sha256
            || accepted_approval.index_record_sha256 != candidate_approval.index_record_sha256
            || accepted_approval.index_row_sha256 != candidate_approval.index_row_sha256
            || accepted_approval.admitted_at != candidate_approval.admitted_at
            || accepted_approval.state != candidate_approval.state
            || accepted_approval.source != candidate_approval.source
        {
            return Err(RejectReason::MutatedIdentity(format!(
                "{}/{}/{}",
                accepted_approval.registry, accepted_approval.name, accepted_approval.version
            )));
        }
        if accepted_approval.category != candidate_approval.category {
            return Err(RejectReason::CategoryMove(format!(
                "{}/{}/{}",
                accepted_approval.registry, accepted_approval.name, accepted_approval.version
            )));
        }
    }

    verify_retained_bodies(&candidate)
        .map_err(|error| RejectReason::MissingRetainedBody(format!("{error:#}")))?;
    Ok(())
}

impl RejectReason {
    fn load(which: &str, error: &anyhow::Error) -> Self {
        Self::MissingRetainedBody(format!("{which} catalog failed to load: {error:#}"))
    }
}

fn ensure_topology(
    accepted: &crate::schema::Registry,
    candidate: &crate::schema::Registry,
) -> Result<(), RejectReason> {
    let detail = if accepted.name != candidate.name {
        Some(format!(
            "name {:?} became {:?}",
            accepted.name, candidate.name
        ))
    } else if accepted.index != candidate.index {
        Some(format!(
            "registry {:?} index {:?} became {:?}",
            accepted.name, accepted.index, candidate.index
        ))
    } else if accepted.download != candidate.download
        && !crate::schema::is_allowed_download_migration(
            &accepted.name,
            &accepted.download,
            &candidate.download,
        )
    {
        Some(format!(
            "registry {:?} download {:?} became {:?}",
            accepted.name, accepted.download, candidate.download
        ))
    } else if accepted.audience != candidate.audience {
        Some(format!(
            "registry {:?} audience {:?} became {:?}",
            accepted.name, accepted.audience, candidate.audience
        ))
    } else if accepted.cargo_version != candidate.cargo_version {
        Some(format!(
            "registry {:?} cargo-version {:?} became {:?}",
            accepted.name, accepted.cargo_version, candidate.cargo_version
        ))
    } else {
        None
    };
    detail.map_or(Ok(()), |detail| Err(RejectReason::RegistryTopology(detail)))
}

fn identity_key(approval: &Approval) -> (String, String, Version) {
    (
        approval.registry.clone(),
        approval.name.clone(),
        approval.version.clone(),
    )
}

fn verify_retained_bodies(catalog: &Catalog) -> Result<()> {
    let retained_identities = DownloadCatalog::retained_route_identities(catalog);
    for approval in &catalog.approvals {
        if approval.state != PackageState::Active {
            continue;
        }
        if !retained_identities.contains(&identity_key(approval)) {
            continue;
        }
        let path = catalog
            .root
            .join("objects")
            .join("crates")
            .join(format!("{}.crate", approval.archive_sha256));
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect retained body {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "retained body is not a regular file: {}",
            path.display()
        );
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read retained body {}", path.display()))?;
        ensure!(
            crate::artifact::sha256_bytes(&bytes) == approval.archive_sha256,
            "retained body hash mismatch for {} {}",
            approval.name,
            approval.version
        );
    }
    Ok(())
}
