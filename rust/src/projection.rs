//! Deterministic typed projections of validated Rust catalog routes.

use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::Serialize;

use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::download::{DOWNLOAD_CATALOG_FILE, Delivery, DownloadCatalog};
use crate::policy::{
    validate_catalog, validate_package_name, validate_registry_alias, validate_sha256,
};
use crate::render::{RELEASE_MANIFEST, projected_bodies};
use crate::schema::Catalog;

/// Wire-independent schema of the typed route projection.
pub const PROJECTION_SCHEMA_VERSION: u32 = 1;
/// Canonical JSON schema of a projection manifest export.
pub const PROJECTION_MANIFEST_SCHEMA: &str = "pkgre-rust-projection-manifest-v1";

/// Explicit bounds for one immutable projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum locked package approvals accepted from one catalog.
    pub max_approvals: u64,
    /// Maximum projected public routes of all response kinds.
    pub max_routes: u64,
    /// Maximum bytes retained by one inline metadata response.
    pub max_inline_body_bytes: u64,
    /// Maximum aggregate bytes retained by inline metadata responses.
    pub max_inline_bytes: u64,
    /// Maximum distinct content-addressed archives retained in one snapshot.
    pub max_archives: u64,
    /// Maximum bytes retained by one archive response.
    pub max_archive_body_bytes: u64,
    /// Maximum aggregate bytes retained by archive responses.
    pub max_archive_bytes: u64,
    /// Maximum aggregate inline-plus-archive bytes retained by one snapshot.
    pub max_snapshot_body_bytes: u64,
}

impl ProjectionLimits {
    /// Production defaults; operators may lower these but should review increases.
    pub const PRODUCTION: Self = Self {
        max_approvals: 10_000,
        max_routes: 20_000,
        max_inline_body_bytes: 16 * 1024 * 1024,
        max_inline_bytes: 128 * 1024 * 1024,
        max_archives: 1_000,
        max_archive_body_bytes: 100 * 1024 * 1024,
        max_archive_bytes: 512 * 1024 * 1024,
        max_snapshot_body_bytes: 512 * 1024 * 1024,
    };
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// One complete deterministic route projection of a validated catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogProjection {
    routes: Arc<Vec<ProjectedRoute>>,
    retained_body_bytes: u64,
}

impl CatalogProjection {
    /// Validates catalog policy and artifacts, then projects every current catalog route.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy or artifacts, projection collisions, resource-limit
    /// violations, or I/O failures.
    pub fn from_catalog(catalog: &Catalog, artifacts: &ArtifactMap) -> Result<Self> {
        Self::from_catalog_with_limits(catalog, artifacts, ProjectionLimits::default())
    }

    /// Builds a projection under explicit retained-state resource limits.
    ///
    /// Archive files are inspected and read through a bounded reader before becoming owned,
    /// immutable snapshot bytes, and their hashes are rechecked after the artifact-map pass.
    /// Metadata rendering currently completes before these retained-state checks run, so this API
    /// alone does not bound candidate-build peak memory. The serving loader must use a checked
    /// render sink before accepting untrusted candidates.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy or artifacts, projection collisions, resource-limit
    /// violations, or I/O failures.
    pub fn from_catalog_with_limits(
        catalog: &Catalog,
        artifacts: &ArtifactMap,
        limits: ProjectionLimits,
    ) -> Result<Self> {
        ensure_limit(
            "catalog approvals",
            usize_as_u64(catalog.approvals.len(), "catalog approval count")?,
            limits.max_approvals,
        )?;
        let policy = validate_catalog(catalog)?;
        artifacts.verify(catalog)?;
        let mut routes = BTreeMap::new();
        let mut accounting = ProjectionAccounting::default();

        for projected in projected_bodies(catalog, artifacts, &policy)? {
            accounting.add_inline(
                usize_as_u64(projected.body.len(), "inline body length")?,
                &limits,
            )?;
            insert_route(
                &mut routes,
                &mut accounting,
                &limits,
                ProjectedRoute::new(
                    projected.path,
                    ProjectedResponse::inline(projected.body, projected.representation),
                ),
            )?;
        }

        for route in DownloadCatalog::from_catalog(catalog).routes {
            let path = format!(
                "/v1/{}/{}/{}/{}",
                route.registry, route.name, route.version, route.sha256
            );
            let destination = match route.delivery {
                Delivery::Redirect { .. } => RedirectDestination::CratesIo {
                    name: route.name,
                    version: route.version,
                },
                Delivery::Retained { .. } => RedirectDestination::FirstParty {
                    sha256: route.sha256,
                },
            };
            insert_route(
                &mut routes,
                &mut accounting,
                &limits,
                ProjectedRoute::new(path, ProjectedResponse::redirect(destination)),
            )?;
        }

        let mut archive_bodies = BTreeMap::<String, Arc<Vec<u8>>>::new();
        let retained_identities = DownloadCatalog::retained_route_identities(catalog);
        for approval in catalog.approvals.iter().filter(|approval| {
            !approval.is_removed()
                && retained_identities.contains(&(
                    approval.registry.clone(),
                    approval.name.clone(),
                    approval.version.clone(),
                ))
        }) {
            if archive_bodies.contains_key(&approval.archive_sha256) {
                continue;
            }
            let artifact = artifacts
                .get(&approval.registry, &approval.name, &approval.version)
                .with_context(|| {
                    format!(
                        "verified artifact map lost {} {} in {}",
                        approval.name, approval.version, approval.registry
                    )
                })?;
            let body = read_bounded_regular_file(&artifact.archive, limits.max_archive_body_bytes)?;
            let body_len = usize_as_u64(body.len(), "archive body length")?;
            accounting.add_archive(body_len, &limits)?;
            let sha256 = sha256_bytes(&body);
            ensure!(
                sha256 == approval.archive_sha256,
                "archive hash changed after artifact verification for {} {}",
                approval.name,
                approval.version
            );
            archive_bodies.insert(sha256, Arc::new(body));
        }
        for (sha256, body) in archive_bodies {
            insert_route(
                &mut routes,
                &mut accounting,
                &limits,
                ProjectedRoute::new(
                    format!("/crates/{sha256}.crate"),
                    ProjectedResponse::archive(body, sha256),
                ),
            )?;
        }

        Ok(Self {
            routes: Arc::new(routes.into_values().collect()),
            retained_body_bytes: accounting.retained_body_bytes()?,
        })
    }

    /// Returns every route in strict bytewise path order.
    #[must_use]
    pub fn routes(&self) -> &[ProjectedRoute] {
        &self.routes
    }

    /// Returns aggregate inline-plus-archive body bytes retained by this snapshot.
    #[must_use]
    pub const fn retained_body_bytes(&self) -> u64 {
        self.retained_body_bytes
    }

    /// Derives deterministic evidence for every route in this immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if a body length cannot be represented as `u64`.
    pub fn manifest(&self) -> Result<ProjectionManifest> {
        let routes = self
            .routes()
            .iter()
            .map(ProjectedRoute::manifest)
            .collect::<Result<_>>()?;
        Ok(ProjectionManifest {
            schema: PROJECTION_MANIFEST_SCHEMA.to_owned(),
            projection_schema: PROJECTION_SCHEMA_VERSION,
            routes,
        })
    }

    /// Serializes the deterministic route manifest as pretty JSON plus one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error if manifest construction or JSON serialization fails.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>> {
        self.manifest()?.canonical_bytes()
    }
}

/// One exact public path and its typed response source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedRoute {
    path: String,
    response: ProjectedResponse,
}

impl ProjectedRoute {
    fn new(path: String, response: ProjectedResponse) -> Self {
        Self { path, response }
    }

    /// Returns the canonical root-relative public path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the immutable response descriptor prepared before request handling.
    #[must_use]
    pub const fn response(&self) -> &ProjectedResponse {
        &self.response
    }

    fn manifest(&self) -> Result<ProjectionManifestRoute> {
        Ok(ProjectionManifestRoute {
            path: self.path.clone(),
            response: self.response.manifest()?,
        })
    }
}

/// Closed representation class for projected response handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectedRepresentation {
    /// JSON metadata, including registry configuration and release/download manifests.
    MetadataJson,
    /// Newline-delimited sparse-index metadata.
    MetadataText,
    /// Immutable package archive bytes.
    Archive,
    /// Redirect response without a body.
    Redirect,
}

/// Stable response-type discriminator for manifests and request dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectedResponseKind {
    /// Deterministic metadata bytes.
    Inline,
    /// Validated retained archive bytes.
    Archive,
    /// Closed compatibility redirect.
    Redirect,
}

/// A route's immutable response source without HTTP-server policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedResponse {
    source: ProjectedResponseSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProjectedResponseSource {
    Inline {
        body: Arc<Vec<u8>>,
        representation: ProjectedRepresentation,
    },
    Archive {
        body: Arc<Vec<u8>>,
        sha256: String,
    },
    Redirect {
        destination: RedirectDestination,
    },
}

impl ProjectedResponse {
    pub(crate) fn inline(body: Vec<u8>, representation: ProjectedRepresentation) -> Self {
        debug_assert!(matches!(
            representation,
            ProjectedRepresentation::MetadataJson | ProjectedRepresentation::MetadataText
        ));
        Self {
            source: ProjectedResponseSource::Inline {
                body: Arc::new(body),
                representation,
            },
        }
    }

    pub(crate) fn archive(body: Arc<Vec<u8>>, sha256: String) -> Self {
        Self {
            source: ProjectedResponseSource::Archive { body, sha256 },
        }
    }

    pub(crate) fn redirect(destination: RedirectDestination) -> Self {
        Self {
            source: ProjectedResponseSource::Redirect { destination },
        }
    }

    /// Returns the stable typed response kind.
    #[must_use]
    pub const fn kind(&self) -> ProjectedResponseKind {
        match self.source {
            ProjectedResponseSource::Inline { .. } => ProjectedResponseKind::Inline,
            ProjectedResponseSource::Archive { .. } => ProjectedResponseKind::Archive,
            ProjectedResponseSource::Redirect { .. } => ProjectedResponseKind::Redirect,
        }
    }

    /// Returns the closed representation class used to serve this response.
    #[must_use]
    pub const fn representation(&self) -> ProjectedRepresentation {
        match self.source {
            ProjectedResponseSource::Inline { representation, .. } => representation,
            ProjectedResponseSource::Archive { .. } => ProjectedRepresentation::Archive,
            ProjectedResponseSource::Redirect { .. } => ProjectedRepresentation::Redirect,
        }
    }

    /// Returns inline or archive bytes, if this is a body response.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.shared_body().map(|body| body.as_slice())
    }

    /// Returns the shared immutable body allocation, if this is a body response.
    #[must_use]
    pub const fn shared_body(&self) -> Option<&Arc<Vec<u8>>> {
        match &self.source {
            ProjectedResponseSource::Inline { body, .. }
            | ProjectedResponseSource::Archive { body, .. } => Some(body),
            ProjectedResponseSource::Redirect { .. } => None,
        }
    }

    /// Returns the content-addressed SHA-256 only for an archive response.
    #[must_use]
    pub fn archive_sha256(&self) -> Option<&str> {
        match &self.source {
            ProjectedResponseSource::Archive { sha256, .. } => Some(sha256),
            ProjectedResponseSource::Inline { .. } | ProjectedResponseSource::Redirect { .. } => {
                None
            }
        }
    }

    /// Returns the closed destination only for a redirect response.
    #[must_use]
    pub const fn redirect_destination(&self) -> Option<&RedirectDestination> {
        match &self.source {
            ProjectedResponseSource::Redirect { destination } => Some(destination),
            ProjectedResponseSource::Inline { .. } | ProjectedResponseSource::Archive { .. } => {
                None
            }
        }
    }

    fn validate_route(&self, path: &str) -> Result<()> {
        match &self.source {
            ProjectedResponseSource::Inline { representation, .. } => {
                validate_inline_route(path, *representation)
            }
            ProjectedResponseSource::Archive { sha256, .. } => validate_archive_route(path, sha256),
            ProjectedResponseSource::Redirect { destination } => {
                validate_redirect_route(path, destination)
            }
        }
    }

    fn manifest(&self) -> Result<ProjectionManifestResponse> {
        match &self.source {
            ProjectedResponseSource::Inline {
                body,
                representation,
            } => Ok(ProjectionManifestResponse::Inline {
                representation: *representation,
                bytes: usize_as_u64(body.len(), "inline manifest body length")?,
                sha256: sha256_bytes(body),
            }),
            ProjectedResponseSource::Archive { body, sha256 } => {
                Ok(ProjectionManifestResponse::Archive {
                    representation: ProjectedRepresentation::Archive,
                    bytes: usize_as_u64(body.len(), "archive manifest body length")?,
                    sha256: sha256_bytes(body),
                    archive_sha256: sha256.clone(),
                })
            }
            ProjectedResponseSource::Redirect { destination } => {
                Ok(ProjectionManifestResponse::Redirect {
                    representation: ProjectedRepresentation::Redirect,
                    destination: destination.clone(),
                    location: destination.location(),
                })
            }
        }
    }
}

/// Closed archive redirect destinations; arbitrary catalog URLs are unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum RedirectDestination {
    /// Byte-for-byte crates.io archive for the route identity.
    CratesIo { name: String, version: Version },
    /// Content-addressed first-party archive on the Rust registry origin.
    FirstParty { sha256: String },
}

impl RedirectDestination {
    /// Resolves the closed typed destination to its exact HTTP `Location` value.
    ///
    /// Catalog-provided URLs are deliberately not accepted: the result is derived only from the
    /// validated crate identity or content hash stored in this descriptor.
    #[must_use]
    pub fn location(&self) -> String {
        match self {
            Self::CratesIo { name, version } => {
                format!("https://static.crates.io/crates/{name}/{version}/download")
            }
            Self::FirstParty { sha256 } => {
                format!("https://rust.pkg.re/crates/{sha256}.crate")
            }
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::CratesIo { name, .. } => {
                validate_package_name(name).context("invalid crates.io redirect package name")
            }
            Self::FirstParty { sha256 } => {
                validate_sha256(sha256).context("invalid first-party redirect archive SHA-256")
            }
        }
    }
}

/// Deterministic evidence for every route in one immutable projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionManifest {
    /// Manifest wire schema.
    pub schema: String,
    /// Typed projection schema represented by this manifest.
    pub projection_schema: u32,
    /// Every route in strict bytewise path order.
    pub routes: Vec<ProjectionManifestRoute>,
}

impl ProjectionManifest {
    /// Validates schema, canonical route ordering, hashes, and closed redirects.
    ///
    /// # Errors
    ///
    /// Returns an error if any manifest invariant is violated.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == PROJECTION_MANIFEST_SCHEMA,
            "projection manifest schema must be {PROJECTION_MANIFEST_SCHEMA}"
        );
        ensure!(
            self.projection_schema == PROJECTION_SCHEMA_VERSION,
            "projection schema must be {PROJECTION_SCHEMA_VERSION}"
        );
        let mut previous_path: Option<&str> = None;
        for route in &self.routes {
            validate_projected_path(&route.path)
                .with_context(|| format!("invalid projection manifest route {:?}", route.path))?;
            if let Some(previous) = previous_path {
                ensure!(
                    previous.as_bytes() < route.path.as_bytes(),
                    "projection manifest routes are not in strict bytewise order: {:?} then {:?}",
                    previous,
                    route.path
                );
            }
            route.response.validate(&route.path)?;
            previous_path = Some(&route.path);
        }
        Ok(())
    }

    /// Serializes canonical pretty JSON terminated by one newline.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self).context("serialize projection manifest")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// One exact projected route in a deterministic manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectionManifestRoute {
    /// Canonical root-relative public path.
    pub path: String,
    /// Typed response evidence derived from the immutable projection.
    pub response: ProjectionManifestResponse,
}

/// Body or redirect evidence for one projected route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "type"
)]
pub enum ProjectionManifestResponse {
    /// Deterministic inline metadata bytes.
    Inline {
        /// Metadata syntax carried by the inline body.
        representation: ProjectedRepresentation,
        /// Exact body length.
        bytes: u64,
        /// SHA-256 of the exact body bytes.
        sha256: String,
    },
    /// Retained content-addressed archive bytes.
    Archive {
        /// Fixed archive representation discriminator.
        representation: ProjectedRepresentation,
        /// Exact body length.
        bytes: u64,
        /// SHA-256 of the exact body bytes.
        sha256: String,
        /// Content-addressed descriptor retained by the projection.
        archive_sha256: String,
    },
    /// Closed redirect and its exact resolved HTTP location.
    Redirect {
        /// Fixed redirect representation discriminator.
        representation: ProjectedRepresentation,
        /// Typed destination fields; arbitrary URLs are unrepresentable.
        destination: RedirectDestination,
        /// Exact output derived from `destination`.
        location: String,
    },
}

impl ProjectionManifestResponse {
    fn validate(&self, path: &str) -> Result<()> {
        match self {
            Self::Inline {
                representation,
                sha256,
                ..
            } => {
                ensure!(
                    matches!(
                        representation,
                        ProjectedRepresentation::MetadataJson
                            | ProjectedRepresentation::MetadataText
                    ),
                    "inline response has non-metadata representation at {path}"
                );
                validate_sha256(sha256)
                    .with_context(|| format!("invalid inline response SHA-256 at {path}"))?;
                validate_inline_route(path, *representation)
            }
            Self::Archive {
                representation,
                sha256,
                archive_sha256,
                ..
            } => {
                ensure!(
                    *representation == ProjectedRepresentation::Archive,
                    "archive response has mismatched representation at {path}"
                );
                validate_sha256(sha256)
                    .with_context(|| format!("invalid archive body SHA-256 at {path}"))?;
                validate_sha256(archive_sha256)
                    .with_context(|| format!("invalid archive descriptor SHA-256 at {path}"))?;
                ensure!(
                    sha256 == archive_sha256,
                    "archive body and descriptor SHA-256 differ at {path}"
                );
                validate_archive_route(path, archive_sha256)
            }
            Self::Redirect {
                representation,
                destination,
                location,
            } => {
                ensure!(
                    *representation == ProjectedRepresentation::Redirect,
                    "redirect response has mismatched representation at {path}"
                );
                validate_redirect_route(path, destination)?;
                ensure!(
                    location == &destination.location(),
                    "redirect location does not match its typed destination at {path}"
                );
                Ok(())
            }
        }
    }
}

fn validate_inline_route(path: &str, representation: ProjectedRepresentation) -> Result<()> {
    ensure!(
        !is_reserved_route_namespace(path),
        "inline response uses a reserved route namespace at {path}"
    );
    let expected = if path == format!("/{DOWNLOAD_CATALOG_FILE}")
        || path == format!("/{RELEASE_MANIFEST}")
        || path.ends_with("/config.json")
    {
        ProjectedRepresentation::MetadataJson
    } else {
        ProjectedRepresentation::MetadataText
    };
    ensure!(
        representation == expected,
        "inline response has mismatched representation at {path}"
    );
    Ok(())
}

fn validate_archive_route(path: &str, archive_sha256: &str) -> Result<()> {
    validate_sha256(archive_sha256)
        .with_context(|| format!("invalid archive descriptor SHA-256 at {path}"))?;
    ensure!(
        path == format!("/crates/{archive_sha256}.crate"),
        "archive route path does not match its descriptor SHA-256 at {path}"
    );
    Ok(())
}

fn validate_redirect_route(path: &str, destination: &RedirectDestination) -> Result<()> {
    let route = parse_rust_download_path(path)
        .with_context(|| format!("invalid redirect route at {path}"))?;
    destination
        .validate()
        .with_context(|| format!("invalid redirect destination at {path}"))?;
    match destination {
        RedirectDestination::CratesIo { name, version } => {
            ensure!(
                name == route.name,
                "crates.io redirect package name does not match route at {path}"
            );
            ensure!(
                version == &route.version,
                "crates.io redirect version does not match route at {path}"
            );
        }
        RedirectDestination::FirstParty { sha256 } => ensure!(
            sha256 == route.sha256,
            "first-party redirect SHA-256 does not match route at {path}"
        ),
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct RustDownloadRoute<'a> {
    name: &'a str,
    version: Version,
    sha256: &'a str,
}

fn parse_rust_download_path(path: &str) -> Result<RustDownloadRoute<'_>> {
    let segments = path.split('/').collect::<Vec<_>>();
    let ["", "v1", registry, name, version, sha256] = segments.as_slice() else {
        anyhow::bail!(
            "Rust download route must be /v1/{{registry}}/{{name}}/{{version}}/{{sha256}}"
        );
    };
    validate_registry_alias(registry).context("invalid Rust download route registry")?;
    validate_package_name(name).context("invalid Rust download route package name")?;
    let parsed_version = Version::parse(version).context("invalid Rust download route version")?;
    ensure!(
        parsed_version.to_string() == *version,
        "Rust download route version is not canonical SemVer"
    );
    validate_sha256(sha256).context("invalid Rust download route SHA-256")?;
    Ok(RustDownloadRoute {
        name,
        version: parsed_version,
        sha256,
    })
}

fn is_reserved_route_namespace(path: &str) -> bool {
    path == "/v1" || path.starts_with("/v1/") || path == "/crates" || path.starts_with("/crates/")
}

fn validate_projected_path(path: &str) -> Result<()> {
    ensure!(path.is_ascii(), "path is not ASCII");
    ensure!(path.starts_with('/'), "path is not root-relative");
    ensure!(path != "/", "root path is not a projected route");
    ensure!(!path.ends_with('/'), "path has a trailing slash");
    ensure!(!path.contains("//"), "path has an empty segment");
    ensure!(
        !path.contains(['?', '#', '\\', '\0']),
        "path contains a query, fragment, backslash, or NUL"
    );
    ensure!(
        !path.bytes().any(|byte| byte.is_ascii_control()),
        "path contains an ASCII control character"
    );
    ensure!(
        path[1..]
            .split('/')
            .all(|segment| segment != "." && segment != ".."),
        "path contains a dot segment"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProjectionAccounting {
    routes: u64,
    inline_bytes: u64,
    archives: u64,
    archive_bytes: u64,
}

impl ProjectionAccounting {
    fn add_route(&mut self, limits: &ProjectionLimits) -> Result<()> {
        let routes = checked_add(self.routes, 1, "projected route count")?;
        ensure_limit("projected routes", routes, limits.max_routes)?;
        self.routes = routes;
        Ok(())
    }

    fn add_inline(&mut self, bytes: u64, limits: &ProjectionLimits) -> Result<()> {
        ensure_limit(
            "inline response body bytes",
            bytes,
            limits.max_inline_body_bytes,
        )?;
        let inline_bytes = checked_add(self.inline_bytes, bytes, "aggregate inline byte count")?;
        ensure_limit(
            "aggregate inline body bytes",
            inline_bytes,
            limits.max_inline_bytes,
        )?;
        ensure_snapshot_total(inline_bytes, self.archive_bytes, limits)?;
        self.inline_bytes = inline_bytes;
        Ok(())
    }

    fn add_archive(&mut self, bytes: u64, limits: &ProjectionLimits) -> Result<()> {
        ensure_limit(
            "archive response body bytes",
            bytes,
            limits.max_archive_body_bytes,
        )?;
        let archives = checked_add(self.archives, 1, "archive count")?;
        ensure_limit("retained archives", archives, limits.max_archives)?;
        let archive_bytes = checked_add(self.archive_bytes, bytes, "aggregate archive byte count")?;
        ensure_limit(
            "aggregate archive body bytes",
            archive_bytes,
            limits.max_archive_bytes,
        )?;
        ensure_snapshot_total(self.inline_bytes, archive_bytes, limits)?;
        self.archives = archives;
        self.archive_bytes = archive_bytes;
        Ok(())
    }

    fn retained_body_bytes(self) -> Result<u64> {
        checked_add(
            self.inline_bytes,
            self.archive_bytes,
            "snapshot retained body byte count",
        )
    }
}

fn insert_route(
    routes: &mut BTreeMap<String, ProjectedRoute>,
    accounting: &mut ProjectionAccounting,
    limits: &ProjectionLimits,
    route: ProjectedRoute,
) -> Result<()> {
    validate_projected_path(&route.path)
        .with_context(|| format!("invalid projected route {:?}", route.path))?;
    route
        .response
        .validate_route(&route.path)
        .with_context(|| format!("invalid projected response at {:?}", route.path))?;
    match routes.entry(route.path.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            accounting.add_route(limits)?;
            entry.insert(route);
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            anyhow::bail!("duplicate projected route {}", entry.key());
        }
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(nix::libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("open archive without following symlinks {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened archive {}", path.display()))?;
    read_opened_regular_file(file, &metadata, path, max_bytes)
}

fn read_opened_regular_file(
    mut file: File,
    metadata: &Metadata,
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    ensure!(
        metadata.file_type().is_file(),
        "archive is not a regular file: {}",
        path.display()
    );
    ensure_limit("archive file bytes", metadata.len(), max_bytes)
        .with_context(|| format!("inspect opened archive {}", path.display()))?;
    let initial_capacity = usize::try_from(metadata.len())
        .context("archive size does not fit the platform address space")?;
    let mut body = Vec::new();
    body.try_reserve_exact(initial_capacity)
        .context("reserve archive response body")?;
    let mut buffer = [0_u8; 16 * 1024];
    let buffer_bytes = usize_as_u64(buffer.len(), "archive read buffer length")?;
    loop {
        let current = usize_as_u64(body.len(), "archive body length")?;
        let remaining = max_bytes
            .checked_sub(current)
            .context("archive body length exceeded its read limit")?;
        let read_bytes = usize::try_from(remaining.min(buffer_bytes))
            .context("archive read window does not fit the platform address space")?;
        if read_bytes == 0 {
            let mut extra = [0_u8; 1];
            let count = file
                .read(&mut extra)
                .with_context(|| format!("check archive read limit {}", path.display()))?;
            ensure!(
                count == 0,
                "archive response body bytes exceed configured limit {max_bytes}"
            );
            break;
        }
        let count = file
            .read(&mut buffer[..read_bytes])
            .with_context(|| format!("read archive {}", path.display()))?;
        if count == 0 {
            break;
        }
        body.try_reserve_exact(count)
            .context("grow archive response body")?;
        body.extend_from_slice(&buffer[..count]);
    }
    Ok(body)
}

fn ensure_snapshot_total(
    inline_bytes: u64,
    archive_bytes: u64,
    limits: &ProjectionLimits,
) -> Result<()> {
    let total = checked_add(
        inline_bytes,
        archive_bytes,
        "snapshot retained body byte count",
    )?;
    ensure_limit(
        "snapshot retained body bytes",
        total,
        limits.max_snapshot_body_bytes,
    )
}

fn checked_add(left: u64, right: u64, description: &str) -> Result<u64> {
    left.checked_add(right)
        .with_context(|| format!("{description} overflow"))
}

fn ensure_limit(description: &str, actual: u64, limit: u64) -> Result<()> {
    ensure!(
        actual <= limit,
        "{description} {actual} exceeds configured limit {limit}"
    );
    Ok(())
}

fn usize_as_u64(value: usize, description: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{description} does not fit u64"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn tiny_limits() -> ProjectionLimits {
        ProjectionLimits {
            max_approvals: 1,
            max_routes: 1,
            max_inline_body_bytes: 3,
            max_inline_bytes: 3,
            max_archives: 1,
            max_archive_body_bytes: 5,
            max_archive_bytes: 5,
            max_snapshot_body_bytes: 8,
        }
    }

    #[test]
    fn resource_limits_accept_exact_values_and_reject_the_next_value() {
        let limits = tiny_limits();
        ensure_limit("catalog approvals", 1, limits.max_approvals).unwrap();
        assert!(ensure_limit("catalog approvals", 2, limits.max_approvals).is_err());

        let mut exact = ProjectionAccounting::default();
        exact.add_route(&limits).unwrap();
        exact.add_inline(3, &limits).unwrap();
        exact.add_archive(5, &limits).unwrap();
        assert_eq!(exact.retained_body_bytes().unwrap(), 8);

        let mut too_many_routes = ProjectionAccounting::default();
        too_many_routes.add_route(&limits).unwrap();
        assert!(too_many_routes.add_route(&limits).is_err());

        let mut too_large_inline = ProjectionAccounting::default();
        assert!(too_large_inline.add_inline(4, &limits).is_err());
        let mut too_much_inline = ProjectionAccounting {
            inline_bytes: 1,
            ..ProjectionAccounting::default()
        };
        assert!(too_much_inline.add_inline(3, &limits).is_err());

        let mut too_many_archives = ProjectionAccounting {
            archives: 1,
            ..ProjectionAccounting::default()
        };
        assert!(too_many_archives.add_archive(1, &limits).is_err());
        let mut too_large_archive = ProjectionAccounting::default();
        assert!(too_large_archive.add_archive(6, &limits).is_err());
        let mut too_much_archive = ProjectionAccounting {
            archive_bytes: 1,
            ..ProjectionAccounting::default()
        };
        assert!(too_much_archive.add_archive(5, &limits).is_err());

        let mut too_much_total = ProjectionAccounting {
            inline_bytes: 4,
            ..ProjectionAccounting::default()
        };
        assert!(too_much_total.add_archive(5, &limits).is_err());
    }

    #[test]
    fn arithmetic_overflow_is_rejected() {
        let limits = ProjectionLimits {
            max_inline_body_bytes: u64::MAX,
            max_inline_bytes: u64::MAX,
            max_snapshot_body_bytes: u64::MAX,
            ..tiny_limits()
        };
        let mut accounting = ProjectionAccounting {
            inline_bytes: u64::MAX,
            ..ProjectionAccounting::default()
        };
        assert!(accounting.add_inline(1, &limits).is_err());
    }

    #[test]
    fn duplicate_route_error_identifies_the_path() {
        let limits = tiny_limits();
        let mut accounting = ProjectionAccounting::default();
        let mut routes = BTreeMap::new();
        let path = "/same".to_owned();
        insert_route(
            &mut routes,
            &mut accounting,
            &limits,
            ProjectedRoute::new(
                path.clone(),
                ProjectedResponse::inline(Vec::new(), ProjectedRepresentation::MetadataText),
            ),
        )
        .unwrap();
        let before = accounting;
        let error = insert_route(
            &mut routes,
            &mut accounting,
            &limits,
            ProjectedRoute::new(
                path.clone(),
                ProjectedResponse::inline(Vec::new(), ProjectedRepresentation::MetadataText),
            ),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains(&path));
        assert_eq!(accounting, before);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn cloning_a_projection_shares_the_route_table_and_body_allocations() {
        let route = ProjectedRoute::new(
            "/body".to_owned(),
            ProjectedResponse::inline(b"immutable".to_vec(), ProjectedRepresentation::MetadataText),
        );
        let projection = CatalogProjection {
            routes: Arc::new(vec![route]),
            retained_body_bytes: 9,
        };
        let cloned = projection.clone();

        assert!(Arc::ptr_eq(&projection.routes, &cloned.routes));
        assert!(Arc::ptr_eq(
            projection.routes[0].response().shared_body().unwrap(),
            cloned.routes[0].response().shared_body().unwrap()
        ));
        assert_eq!(cloned.routes[0].path(), "/body");
        assert_eq!(cloned.routes[0].response().body().unwrap(), b"immutable");
    }

    #[test]
    fn redirect_locations_are_derived_from_typed_fields() {
        let crates_io = RedirectDestination::CratesIo {
            name: "crate_name-2".to_owned(),
            version: Version::parse("1.2.3-alpha.1+build.5").unwrap(),
        };
        assert_eq!(
            crates_io.location(),
            "https://static.crates.io/crates/crate_name-2/1.2.3-alpha.1+build.5/download"
        );

        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let first_party = RedirectDestination::FirstParty {
            sha256: sha256.to_owned(),
        };
        assert_eq!(
            first_party.location(),
            format!("https://rust.pkg.re/crates/{sha256}.crate")
        );
    }

    const METADATA_SHA256: &str =
        "45447b7afbd5e544f7d0f1df0fccd26014d9850130abd3f020b89ff96b82079f";
    const ARCHIVE_SHA256: &str = "0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3";

    fn inline_manifest_route(path: &str) -> ProjectionManifestRoute {
        ProjectionManifestRoute {
            path: path.to_owned(),
            response: ProjectionManifestResponse::Inline {
                representation: ProjectedRepresentation::MetadataText,
                bytes: 8,
                sha256: METADATA_SHA256.to_owned(),
            },
        }
    }

    fn test_manifest(routes: Vec<ProjectionManifestRoute>) -> ProjectionManifest {
        ProjectionManifest {
            schema: PROJECTION_MANIFEST_SCHEMA.to_owned(),
            projection_schema: PROJECTION_SCHEMA_VERSION,
            routes,
        }
    }

    fn projected_response_is_valid(path: &str, response: ProjectedResponse) -> bool {
        let mut routes = BTreeMap::new();
        let mut accounting = ProjectionAccounting::default();
        insert_route(
            &mut routes,
            &mut accounting,
            &ProjectionLimits::PRODUCTION,
            ProjectedRoute::new(path.to_owned(), response),
        )
        .is_ok()
    }

    #[test]
    fn projected_paths_reject_noncanonical_forms() {
        let invalid = [
            "relative",
            "/",
            "/a/",
            "/a//b",
            "/.",
            "/..",
            "/a/./b",
            "/a/../b",
            "/non-ascii-é",
            "/a?query",
            "/a#fragment",
            "/a\\b",
            "/a\0b",
            "/a\nb",
            "/a\rb",
            "/a\tb",
            "/a\u{7f}b",
        ];
        for path in invalid {
            assert!(
                validate_projected_path(path).is_err(),
                "invalid path was accepted: {path:?}"
            );
        }

        for path in ["/a", "/a/b", "/v10", "/crates-index", "/a/%2e"] {
            validate_projected_path(path).unwrap();
        }
        assert!(!projected_response_is_valid(
            "/a/../b",
            ProjectedResponse::inline(Vec::new(), ProjectedRepresentation::MetadataText)
        ));
    }

    #[test]
    fn response_kinds_are_bound_to_closed_route_namespaces() {
        for path in ["/metadata", "/v10", "/crates-index"] {
            assert!(projected_response_is_valid(
                path,
                ProjectedResponse::inline(Vec::new(), ProjectedRepresentation::MetadataText)
            ));
        }
        for path in ["/v1", "/v1/main", "/crates", "/crates/anything"] {
            assert!(!projected_response_is_valid(
                path,
                ProjectedResponse::inline(Vec::new(), ProjectedRepresentation::MetadataText)
            ));
        }

        let archive_body = Arc::new(b"archive".to_vec());
        assert!(projected_response_is_valid(
            &format!("/crates/{ARCHIVE_SHA256}.crate"),
            ProjectedResponse::archive(Arc::clone(&archive_body), ARCHIVE_SHA256.to_owned())
        ));
        for path in [
            "/metadata".to_owned(),
            format!("/crates/{METADATA_SHA256}.crate"),
            format!("/crates/{ARCHIVE_SHA256}.crate/extra"),
        ] {
            assert!(!projected_response_is_valid(
                &path,
                ProjectedResponse::archive(Arc::clone(&archive_body), ARCHIVE_SHA256.to_owned())
            ));
        }

        let crates_io = RedirectDestination::CratesIo {
            name: "crate_name-2".to_owned(),
            version: Version::parse("1.2.3-alpha.1+build.5").unwrap(),
        };
        assert!(projected_response_is_valid(
            &format!("/v1/main/crate_name-2/1.2.3-alpha.1+build.5/{METADATA_SHA256}"),
            ProjectedResponse::redirect(crates_io.clone())
        ));
        assert!(!projected_response_is_valid(
            "/metadata",
            ProjectedResponse::redirect(crates_io)
        ));

        let first_party = RedirectDestination::FirstParty {
            sha256: ARCHIVE_SHA256.to_owned(),
        };
        assert!(projected_response_is_valid(
            &format!("/v1/main/gitcrate/2.0.0/{ARCHIVE_SHA256}"),
            ProjectedResponse::redirect(first_party.clone())
        ));
        assert!(!projected_response_is_valid(
            &format!("/crates/{ARCHIVE_SHA256}.crate"),
            ProjectedResponse::redirect(first_party)
        ));
    }

    #[test]
    fn redirect_routes_require_exact_canonical_identity() {
        let crates_io = RedirectDestination::CratesIo {
            name: "serde".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
        };
        let location = crates_io.location();
        let response = || ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: crates_io.clone(),
            location: location.clone(),
        };
        assert!(
            response()
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"))
                .is_ok()
        );
        for path in [
            format!("/v1/Main/serde/1.0.0/{METADATA_SHA256}"),
            format!("/v1/main/bad%name/1.0.0/{METADATA_SHA256}"),
            format!("/v1/main/serde/01.0.0/{METADATA_SHA256}"),
            "/v1/main/serde/1.0.0/ABCDEF".to_owned(),
            format!("/v1/main/serde/1.0.0/{METADATA_SHA256}/extra"),
            "/v1/main/serde/1.0.0".to_owned(),
        ] {
            assert!(
                response().validate(&path).is_err(),
                "invalid redirect route was accepted: {path}"
            );
        }

        let wrong_name = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: RedirectDestination::CratesIo {
                name: "other".to_owned(),
                version: Version::parse("1.0.0").unwrap(),
            },
            location: "https://static.crates.io/crates/other/1.0.0/download".to_owned(),
        };
        assert!(
            wrong_name
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"))
                .is_err()
        );
        let wrong_version = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: RedirectDestination::CratesIo {
                name: "serde".to_owned(),
                version: Version::parse("2.0.0").unwrap(),
            },
            location: "https://static.crates.io/crates/serde/2.0.0/download".to_owned(),
        };
        assert!(
            wrong_version
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"))
                .is_err()
        );

        let wrong_sha = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: RedirectDestination::FirstParty {
                sha256: ARCHIVE_SHA256.to_owned(),
            },
            location: format!("https://rust.pkg.re/crates/{ARCHIVE_SHA256}.crate"),
        };
        assert!(
            wrong_sha
                .validate(&format!("/v1/main/gitcrate/2.0.0/{METADATA_SHA256}"))
                .is_err()
        );

        let wrong_location = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: crates_io,
            location: "https://example.invalid/archive".to_owned(),
        };
        assert!(
            wrong_location
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"))
                .is_err()
        );
    }

    #[test]
    fn manifest_rejects_response_representation_mismatches() {
        let mut inline = inline_manifest_route("/metadata");
        let ProjectionManifestResponse::Inline { representation, .. } = &mut inline.response else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::Archive;
        assert!(test_manifest(vec![inline]).validate().is_err());

        let mut config = inline_manifest_route("/config.json");
        let ProjectionManifestResponse::Inline { representation, .. } = &mut config.response else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataText;
        assert!(test_manifest(vec![config]).validate().is_err());

        let mut sparse = inline_manifest_route("/2/cc");
        let ProjectionManifestResponse::Inline { representation, .. } = &mut sparse.response else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataJson;
        assert!(test_manifest(vec![sparse]).validate().is_err());

        let mut archive = ProjectionManifestRoute {
            path: format!("/crates/{ARCHIVE_SHA256}.crate"),
            response: ProjectionManifestResponse::Archive {
                representation: ProjectedRepresentation::Archive,
                bytes: 7,
                sha256: ARCHIVE_SHA256.to_owned(),
                archive_sha256: ARCHIVE_SHA256.to_owned(),
            },
        };
        let ProjectionManifestResponse::Archive { representation, .. } = &mut archive.response
        else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataJson;
        assert!(test_manifest(vec![archive]).validate().is_err());

        let destination = RedirectDestination::FirstParty {
            sha256: ARCHIVE_SHA256.to_owned(),
        };
        let mut redirect = ProjectionManifestRoute {
            path: format!("/v1/main/gitcrate/2.0.0/{ARCHIVE_SHA256}"),
            response: ProjectionManifestResponse::Redirect {
                representation: ProjectedRepresentation::Redirect,
                location: destination.location(),
                destination,
            },
        };
        let ProjectionManifestResponse::Redirect { representation, .. } = &mut redirect.response
        else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataText;
        assert!(test_manifest(vec![redirect]).validate().is_err());
    }

    #[test]
    fn manifest_rejects_bad_hashes_ordering_and_duplicates() {
        let mut bad_inline = inline_manifest_route("/a");
        bad_inline.response = ProjectionManifestResponse::Inline {
            representation: ProjectedRepresentation::MetadataText,
            bytes: 0,
            sha256: "ABCDEF".to_owned(),
        };
        assert!(test_manifest(vec![bad_inline]).validate().is_err());

        let bad_archive = ProjectionManifestRoute {
            path: format!("/crates/{ARCHIVE_SHA256}.crate"),
            response: ProjectionManifestResponse::Archive {
                representation: ProjectedRepresentation::Archive,
                bytes: 7,
                sha256: METADATA_SHA256.to_owned(),
                archive_sha256: ARCHIVE_SHA256.to_owned(),
            },
        };
        assert!(test_manifest(vec![bad_archive]).validate().is_err());

        assert!(
            test_manifest(vec![
                inline_manifest_route("/b"),
                inline_manifest_route("/a")
            ])
            .validate()
            .is_err()
        );
        assert!(
            test_manifest(vec![
                inline_manifest_route("/a"),
                inline_manifest_route("/a")
            ])
            .validate()
            .is_err()
        );
        test_manifest(vec![
            inline_manifest_route("/A"),
            inline_manifest_route("/a"),
        ])
        .validate()
        .unwrap();
    }

    #[test]
    fn projection_manifest_is_exact_and_repeatable() {
        let crates_io = RedirectDestination::CratesIo {
            name: "crate_name-2".to_owned(),
            version: Version::parse("1.2.3-alpha.1+build.5").unwrap(),
        };
        let first_party = RedirectDestination::FirstParty {
            sha256: ARCHIVE_SHA256.to_owned(),
        };
        let projection = CatalogProjection {
            routes: Arc::new(vec![
                ProjectedRoute::new(
                    "/2/cc".to_owned(),
                    ProjectedResponse::inline(
                        b"metadata".to_vec(),
                        ProjectedRepresentation::MetadataText,
                    ),
                ),
                ProjectedRoute::new(
                    format!("/crates/{ARCHIVE_SHA256}.crate"),
                    ProjectedResponse::archive(
                        Arc::new(b"archive".to_vec()),
                        ARCHIVE_SHA256.to_owned(),
                    ),
                ),
                ProjectedRoute::new(
                    format!("/v1/main/crate_name-2/1.2.3-alpha.1+build.5/{METADATA_SHA256}"),
                    ProjectedResponse::redirect(crates_io),
                ),
                ProjectedRoute::new(
                    format!("/v1/main/gitcrate/2.0.0/{ARCHIVE_SHA256}"),
                    ProjectedResponse::redirect(first_party),
                ),
            ]),
            retained_body_bytes: 15,
        };

        let first = projection.manifest_bytes().unwrap();
        let second = projection.manifest_bytes().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.last(), Some(&b'\n'));
        assert_ne!(first.get(first.len() - 2), Some(&b'\n'));
        let expected = r#"{
  "schema": "pkgre-rust-projection-manifest-v1",
  "projectionSchema": 1,
  "routes": [
    {
      "path": "/2/cc",
      "response": {
        "type": "inline",
        "representation": "metadata-text",
        "bytes": 8,
        "sha256": "45447b7afbd5e544f7d0f1df0fccd26014d9850130abd3f020b89ff96b82079f"
      }
    },
    {
      "path": "/crates/0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3.crate",
      "response": {
        "type": "archive",
        "representation": "archive",
        "bytes": 7,
        "sha256": "0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3",
        "archiveSha256": "0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3"
      }
    },
    {
      "path": "/v1/main/crate_name-2/1.2.3-alpha.1+build.5/45447b7afbd5e544f7d0f1df0fccd26014d9850130abd3f020b89ff96b82079f",
      "response": {
        "type": "redirect",
        "representation": "redirect",
        "destination": {
          "kind": "crates-io",
          "name": "crate_name-2",
          "version": "1.2.3-alpha.1+build.5"
        },
        "location": "https://static.crates.io/crates/crate_name-2/1.2.3-alpha.1+build.5/download"
      }
    },
    {
      "path": "/v1/main/gitcrate/2.0.0/0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3",
      "response": {
        "type": "redirect",
        "representation": "redirect",
        "destination": {
          "kind": "first-party",
          "sha256": "0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3"
        },
        "location": "https://rust.pkg.re/crates/0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3.crate"
      }
    }
  ]
}
"#;
        assert_eq!(String::from_utf8(first).unwrap(), expected);
    }

    static TEMP_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pkgre-projection-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, path: &str) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn archive_reader_accepts_exact_limit_and_rejects_next_byte() {
        let directory = TestDirectory::new("reader-limits");
        let exact = directory.join("exact.crate");
        fs::write(&exact, b"12345").unwrap();
        assert_eq!(read_bounded_regular_file(&exact, 5).unwrap(), b"12345");

        let over = directory.join("over.crate");
        fs::write(&over, b"123456").unwrap();
        let error = read_bounded_regular_file(&over, 5).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds configured limit 5"));
    }

    #[test]
    fn archive_reader_rejects_final_component_symlinks() {
        let directory = TestDirectory::new("reader-symlink");
        let target = directory.join("target.crate");
        let link = directory.join("link.crate");
        fs::write(&target, b"archive").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_bounded_regular_file(&link, 7).unwrap_err();
        assert!(format!("{error:#}").contains("without following symlinks"));
    }

    #[test]
    fn archive_reader_rejects_non_regular_files() {
        let directory = TestDirectory::new("reader-directory");
        let error = read_bounded_regular_file(&directory.0, 1).unwrap_err();
        assert!(format!("{error:#}").contains("is not a regular file"));
    }

    #[test]
    fn archive_reader_rejects_growth_after_descriptor_inspection() {
        let directory = TestDirectory::new("reader-growth");
        let path = directory.join("growing.crate");
        fs::write(&path, b"123").unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let mut appender = OpenOptions::new().append(true).open(&path).unwrap();
        appender.write_all(b"4").unwrap();
        drop(appender);

        let error = read_opened_regular_file(file, &metadata, &path, 3).unwrap_err();
        assert!(format!("{error:#}").contains("exceed configured limit 3"));
    }

    #[test]
    fn archive_reader_accepts_small_file_at_u64_max_limit() {
        let directory = TestDirectory::new("reader-max-limit");
        let path = directory.join("small.crate");
        fs::write(&path, b"small").unwrap();
        assert_eq!(
            read_bounded_regular_file(&path, u64::MAX).unwrap(),
            b"small"
        );
    }
}
