//! Deterministic typed projections of validated Rust catalog routes.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::download::{DownloadCatalog, DownloadSource};
use crate::policy::validate_catalog;
use crate::render::projected_bodies;
use crate::schema::Catalog;

/// One complete deterministic route projection of a validated catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogProjection {
    routes: Vec<ProjectedRoute>,
}

impl CatalogProjection {
    /// Validates catalog policy and artifacts, then projects every current catalog route.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy or artifacts, projection collisions, or I/O failures.
    pub fn from_catalog(catalog: &Catalog, artifacts: &ArtifactMap) -> Result<Self> {
        let policy = validate_catalog(catalog)?;
        artifacts.verify(catalog)?;
        let mut routes = BTreeMap::new();

        for (path, body) in projected_bodies(catalog, artifacts, &policy)? {
            insert_route(
                &mut routes,
                ProjectedRoute {
                    path,
                    response: ProjectedResponse::Inline { body },
                },
            )?;
        }

        for route in DownloadCatalog::from_catalog(catalog).routes {
            let path = format!(
                "/v1/{}/{}/{}/{}",
                route.registry, route.name, route.version, route.sha256
            );
            let destination = match route.source {
                DownloadSource::CratesIo => RedirectDestination::CratesIo {
                    name: route.name,
                    version: route.version,
                },
                DownloadSource::GitTag => RedirectDestination::FirstParty {
                    sha256: route.sha256,
                },
            };
            insert_route(
                &mut routes,
                ProjectedRoute {
                    path,
                    response: ProjectedResponse::Redirect { destination },
                },
            )?;
        }

        let mut archive_bodies = BTreeMap::<String, Vec<u8>>::new();
        for approval in catalog.approvals.iter().filter(|approval| {
            !approval.is_removed()
                && matches!(&approval.source, crate::schema::Source::GitTag { .. })
        }) {
            let artifact = artifacts
                .get(&approval.registry, &approval.name, &approval.version)
                .with_context(|| {
                    format!(
                        "verified artifact map lost {} {} in {}",
                        approval.name, approval.version, approval.registry
                    )
                })?;
            let body = fs::read(&artifact.archive)
                .with_context(|| format!("read archive {}", artifact.archive.display()))?;
            let sha256 = sha256_bytes(&body);
            ensure!(
                sha256 == approval.archive_sha256,
                "archive hash changed after artifact verification for {} {}",
                approval.name,
                approval.version
            );
            insert_archive_body(&mut archive_bodies, sha256, body)?;
        }
        for (sha256, body) in archive_bodies {
            insert_route(
                &mut routes,
                ProjectedRoute {
                    path: format!("/crates/{sha256}.crate"),
                    response: ProjectedResponse::Archive { body, sha256 },
                },
            )?;
        }

        Ok(Self {
            routes: routes.into_values().collect(),
        })
    }

    /// Returns every route in strict bytewise path order.
    #[must_use]
    pub fn routes(&self) -> &[ProjectedRoute] {
        &self.routes
    }
}

/// One exact public path and its typed response source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedRoute {
    /// Canonical root-relative public path.
    pub path: String,
    /// Response source prepared before request handling.
    pub response: ProjectedResponse,
}

/// A route's complete response source without HTTP-server policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectedResponse {
    /// Deterministic metadata bytes held in the immutable projection.
    Inline { body: Vec<u8> },
    /// Validated immutable archive bytes retained in the projection.
    Archive { body: Vec<u8>, sha256: String },
    /// Closed compatibility redirect derived from catalog source type.
    Redirect { destination: RedirectDestination },
}

/// Closed archive redirect destinations; arbitrary URLs are unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedirectDestination {
    /// Byte-for-byte crates.io archive for the route identity.
    CratesIo { name: String, version: Version },
    /// Content-addressed first-party archive on the Rust registry origin.
    FirstParty { sha256: String },
}

fn insert_route(
    routes: &mut BTreeMap<String, ProjectedRoute>,
    route: ProjectedRoute,
) -> Result<()> {
    ensure!(
        route.path.starts_with('/') && !route.path.contains(['?', '#', '\\', '\0']),
        "projected route is not a canonical root-relative path: {:?}",
        route.path
    );
    match routes.entry(route.path.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(route);
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            anyhow::bail!("duplicate projected route {}", entry.key());
        }
    }
    Ok(())
}

fn insert_archive_body(
    archives: &mut BTreeMap<String, Vec<u8>>,
    sha256: String,
    body: Vec<u8>,
) -> Result<()> {
    match archives.entry(sha256) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(body);
        }
        std::collections::btree_map::Entry::Occupied(entry) => ensure!(
            entry.get() == &body,
            "content-addressed archive {} has conflicting bytes",
            entry.key()
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_content_addressed_archive_bodies_are_deduplicated() {
        let mut archives = BTreeMap::new();
        insert_archive_body(&mut archives, "a".repeat(64), b"same".to_vec()).unwrap();
        insert_archive_body(&mut archives, "a".repeat(64), b"same".to_vec()).unwrap();
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[&"a".repeat(64)], b"same");

        let error =
            insert_archive_body(&mut archives, "a".repeat(64), b"different".to_vec()).unwrap_err();
        assert!(format!("{error:#}").contains("conflicting bytes"));
    }
}
