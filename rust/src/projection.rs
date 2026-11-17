//! Deterministic typed projections of validated Rust catalog routes.

use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
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
    ///
    /// The archive count matches the approval count: the byte limits, not the
    /// number of archives, bound the memory a snapshot retains, since a download
    /// does not copy its archive.
    pub const PRODUCTION: Self = Self {
        max_approvals: 10_000,
        max_routes: 20_000,
        max_inline_body_bytes: 16 * 1024 * 1024,
        max_inline_bytes: 128 * 1024 * 1024,
        max_archives: 10_000,
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

/// Measured retained state of one projection, for comparison with `ProjectionLimits`.
///
/// Each field measures the quantity bounded by the limit of the same name without its `max_`
/// prefix, so an operator can see how much of every budget a catalog already spends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionUsage {
    /// Locked package approvals accepted from the catalog.
    pub approvals: u64,
    /// Projected public routes of all response kinds.
    pub routes: u64,
    /// Largest inline metadata response body retained by the projection.
    pub inline_body_bytes: u64,
    /// Aggregate inline metadata bytes retained by the projection.
    pub inline_bytes: u64,
    /// Distinct content-addressed archives retained by the projection.
    pub archives: u64,
    /// Largest archive response body retained by the projection.
    pub archive_body_bytes: u64,
    /// Aggregate archive bytes retained by the projection.
    pub archive_bytes: u64,
    /// Aggregate inline-plus-archive bytes retained by the projection.
    pub snapshot_body_bytes: u64,
}

/// One complete deterministic route projection of a validated catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogProjection {
    routes: Arc<Vec<ProjectedRoute>>,
    usage: ProjectionUsage,
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
        let approvals = usize_as_u64(catalog.approvals.len(), "catalog approval count")?;
        ensure_limit("catalog approvals", approvals, limits.max_approvals)?;
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
            usage: accounting.usage(approvals)?,
        })
    }

    /// Returns every route in strict bytewise path order.
    #[must_use]
    pub fn routes(&self) -> &[ProjectedRoute] {
        &self.routes
    }

    /// Returns the retained state this projection measured against its limits.
    #[must_use]
    pub const fn usage(&self) -> ProjectionUsage {
        self.usage
    }

    /// Returns aggregate inline-plus-archive body bytes retained by this snapshot.
    #[must_use]
    pub const fn retained_body_bytes(&self) -> u64 {
        self.usage.snapshot_body_bytes
    }

    /// Derives deterministic evidence for every route in this immutable snapshot.
    ///
    /// The `first_party_origin` is the serving origin's configuration, recorded only as the
    /// resolved `Location` of a first-party redirect; it never comes from the catalog.
    ///
    /// # Errors
    ///
    /// Returns an error if a body length cannot be represented as `u64`.
    pub fn manifest(&self, first_party_origin: &FirstPartyOrigin) -> Result<ProjectionManifest> {
        let routes = self
            .routes()
            .iter()
            .map(|route| route.manifest(first_party_origin))
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
    pub fn manifest_bytes(&self, first_party_origin: &FirstPartyOrigin) -> Result<Vec<u8>> {
        self.manifest(first_party_origin)?
            .canonical_bytes(first_party_origin)
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

    fn manifest(&self, first_party_origin: &FirstPartyOrigin) -> Result<ProjectionManifestRoute> {
        Ok(ProjectionManifestRoute {
            path: self.path.clone(),
            response: self.response.manifest(first_party_origin)?,
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

    fn manifest(
        &self,
        first_party_origin: &FirstPartyOrigin,
    ) -> Result<ProjectionManifestResponse> {
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
                    location: destination.location(Some(first_party_origin))?,
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

/// The `https` default port, which is never part of a canonical origin.
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Exact configured origin of the serving origin's first-party archive redirects.
///
/// The origin is operator configuration, never catalog data: a first-party
/// [`RedirectDestination`] resolves its `Location` against this value alone. The stored value is
/// canonical: a trailing `/` and the default port `443` are dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstPartyOrigin(String);

impl FirstPartyOrigin {
    /// Validates one exact `https` origin.
    ///
    /// Accepted: the `https` scheme, a lowercase DNS name or a canonical decimal IPv4 literal, an
    /// optional port, and no user information, path other than empty or `/`, query, or fragment.
    /// An IPv6 literal, an `xn--` label, and any numeric host form that URL parsers read as a
    /// different address are refused.
    ///
    /// # Errors
    ///
    /// Returns an error for any other value, naming the rule it breaks.
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.is_ascii(),
            "first-party origin must be ASCII: {value:?}"
        );
        ensure!(
            !value.bytes().any(|byte| byte.is_ascii_whitespace()),
            "first-party origin must not contain whitespace: {value:?}"
        );
        let Some(rest) = value.strip_prefix("https://") else {
            bail!("first-party origin must use the https scheme: {value:?}");
        };
        ensure!(
            !rest.contains(['?', '#']),
            "first-party origin must not have a query or fragment: {value:?}"
        );
        ensure!(
            !rest.contains('@'),
            "first-party origin must not have user information: {value:?}"
        );
        let (authority, path) = match rest.find('/') {
            Some(index) => rest.split_at(index),
            None => (rest, ""),
        };
        ensure!(
            path.is_empty() || path == "/",
            "first-party origin must not have a path: {value:?}"
        );
        ensure!(
            !authority.starts_with('['),
            "first-party origin must not be an IPv6 literal, which is not supported: {value:?}"
        );
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        validate_first_party_host(host)?;
        let port = match port {
            Some(port) => {
                ensure!(
                    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
                    "first-party origin port must be numeric: {value:?}"
                );
                let number = port.parse::<u16>().with_context(|| {
                    format!("first-party origin port is out of range: {value:?}")
                })?;
                ensure!(
                    number != 0 && number.to_string() == port,
                    "first-party origin port must be 1-65535 in canonical decimal: {value:?}"
                );
                // `https` defaults to 443, so the default port is not part of the origin.
                (number != DEFAULT_HTTPS_PORT).then_some(number)
            }
            None => None,
        };
        let origin = match port {
            Some(port) => format!("https://{host}:{port}"),
            None => format!("https://{host}"),
        };
        Ok(Self(origin))
    }

    /// Returns the canonical origin, which never ends in `/` or in the default port.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Rejects a host that is not a lowercase DNS name or a canonical decimal IPv4 literal.
///
/// A last label that is numeric or begins with `0x` must make the host exactly four decimal
/// octets from 0 to 255 without leading zeros, because URL parsers read every other numeric form
/// as a different IPv4 address. Every other host must carry a letter in its last label, so no
/// numeric form survives as a name. `xn--` labels are refused: this origin is not an
/// internationalized domain name, and an unchecked one would need a punycode decoder.
fn validate_first_party_host(host: &str) -> Result<()> {
    ensure!(!host.is_empty(), "first-party origin must have a host");
    ensure!(
        host.len() <= 253,
        "first-party origin host exceeds 253 bytes: {host:?}"
    );
    for label in host.split('.') {
        ensure!(
            !label.is_empty(),
            "first-party origin host has an empty label: {host:?}"
        );
        ensure!(
            label.len() <= 63,
            "first-party origin host label exceeds 63 bytes: {host:?}"
        );
        ensure!(
            !label.starts_with("xn--"),
            "first-party origin host must not use an internationalized `xn--` label: {host:?}"
        );
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "first-party origin host label must not begin or end with `-`: {host:?}"
        );
        ensure!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "first-party origin host must be a lowercase DNS name or IPv4 literal: {host:?}"
        );
    }
    let last = host
        .rsplit('.')
        .next()
        .expect("a nonempty host has a last label");
    if last.bytes().all(|byte| byte.is_ascii_digit()) || last.starts_with("0x") {
        validate_first_party_ipv4(host)
    } else {
        ensure!(
            last.bytes().any(|byte| byte.is_ascii_lowercase()),
            "first-party origin host last label must contain a letter: {host:?}"
        );
        Ok(())
    }
}

/// Requires exactly four decimal IPv4 octets from 0 to 255 with no leading zeros.
fn validate_first_party_ipv4(host: &str) -> Result<()> {
    let octets = host.split('.').collect::<Vec<_>>();
    ensure!(
        octets.len() == 4,
        "first-party origin host must be four decimal IPv4 octets: {host:?}"
    );
    for octet in octets {
        ensure!(
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit()),
            "first-party origin host must be decimal IPv4 octets: {host:?}"
        );
        ensure!(
            octet == "0" || !octet.starts_with('0'),
            "first-party origin host IPv4 octets must not have leading zeros: {host:?}"
        );
        ensure!(
            octet
                .parse::<u16>()
                .is_ok_and(|value| u8::try_from(value).is_ok()),
            "first-party origin host IPv4 octets must be 0 to 255: {host:?}"
        );
    }
    Ok(())
}

impl RedirectDestination {
    /// Resolves the closed typed destination to its exact HTTP `Location` value.
    ///
    /// Catalog-provided URLs are deliberately not accepted: the result is derived only from the
    /// validated crate identity or content hash stored in this descriptor, plus, for a first-party
    /// destination, the serving origin's configured [`FirstPartyOrigin`].
    ///
    /// # Errors
    ///
    /// Returns an error when a first-party destination is resolved without a configured origin.
    pub fn location(&self, first_party_origin: Option<&FirstPartyOrigin>) -> Result<String> {
        match self {
            Self::CratesIo { name, version } => Ok(format!(
                "https://static.crates.io/crates/{name}/{version}/download"
            )),
            Self::FirstParty { sha256 } => {
                let origin = first_party_origin.context(
                    "first-party archive redirect requires a configured first-party origin",
                )?;
                Ok(format!("{}/crates/{sha256}.crate", origin.as_str()))
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
    /// A first-party redirect location is checked against the serving origin's configured
    /// `first_party_origin`, the same value that resolved it.
    ///
    /// # Errors
    ///
    /// Returns an error if any manifest invariant is violated.
    pub fn validate(&self, first_party_origin: &FirstPartyOrigin) -> Result<()> {
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
            route.response.validate(&route.path, first_party_origin)?;
            previous_path = Some(&route.path);
        }
        Ok(())
    }

    /// Serializes canonical pretty JSON terminated by one newline.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or serialization fails.
    pub fn canonical_bytes(&self, first_party_origin: &FirstPartyOrigin) -> Result<Vec<u8>> {
        self.validate(first_party_origin)?;
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
        /// Exact output derived from `destination` and the serving origin's configured
        /// first-party origin.
        location: String,
    },
}

impl ProjectionManifestResponse {
    fn validate(&self, path: &str, first_party_origin: &FirstPartyOrigin) -> Result<()> {
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
                    location == &destination.location(Some(first_party_origin))?,
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
    inline_body_bytes: u64,
    inline_bytes: u64,
    archives: u64,
    archive_body_bytes: u64,
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
        self.inline_body_bytes = self.inline_body_bytes.max(bytes);
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
        self.archive_body_bytes = self.archive_body_bytes.max(bytes);
        self.archives = archives;
        self.archive_bytes = archive_bytes;
        Ok(())
    }

    fn usage(self, approvals: u64) -> Result<ProjectionUsage> {
        let snapshot_body_bytes = checked_add(
            self.inline_bytes,
            self.archive_bytes,
            "snapshot retained body byte count",
        )?;
        Ok(ProjectionUsage {
            approvals,
            routes: self.routes,
            inline_body_bytes: self.inline_body_bytes,
            inline_bytes: self.inline_bytes,
            archives: self.archives,
            archive_body_bytes: self.archive_body_bytes,
            archive_bytes: self.archive_bytes,
            snapshot_body_bytes,
        })
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

    /// The serving origin's configuration used wherever a first-party location is resolved.
    fn first_party_origin() -> FirstPartyOrigin {
        FirstPartyOrigin::parse("https://rust.pkg.re").unwrap()
    }

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
        assert_eq!(
            exact.usage(0).unwrap(),
            ProjectionUsage {
                approvals: 0,
                routes: 1,
                inline_body_bytes: 3,
                inline_bytes: 3,
                archives: 1,
                archive_body_bytes: 5,
                archive_bytes: 5,
                snapshot_body_bytes: 8,
            }
        );

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
            usage: ProjectionUsage {
                routes: 1,
                inline_body_bytes: 9,
                inline_bytes: 9,
                snapshot_body_bytes: 9,
                ..ProjectionUsage::default()
            },
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
        let origin = first_party_origin();
        let crates_io = RedirectDestination::CratesIo {
            name: "crate_name-2".to_owned(),
            version: Version::parse("1.2.3-alpha.1+build.5").unwrap(),
        };
        assert_eq!(
            crates_io.location(Some(&origin)).unwrap(),
            "https://static.crates.io/crates/crate_name-2/1.2.3-alpha.1+build.5/download"
        );
        assert_eq!(
            crates_io.location(None).unwrap(),
            "https://static.crates.io/crates/crate_name-2/1.2.3-alpha.1+build.5/download",
            "a crates.io destination needs no configured first-party origin"
        );

        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let first_party = RedirectDestination::FirstParty {
            sha256: sha256.to_owned(),
        };
        assert_eq!(
            first_party.location(Some(&origin)).unwrap(),
            format!("https://rust.pkg.re/crates/{sha256}.crate")
        );
        let alternative = FirstPartyOrigin::parse("https://registry.example:8443").unwrap();
        assert_eq!(
            first_party.location(Some(&alternative)).unwrap(),
            format!("https://registry.example:8443/crates/{sha256}.crate")
        );
        let default_port = FirstPartyOrigin::parse("https://rust.pkg.re:443").unwrap();
        assert_eq!(
            first_party.location(Some(&default_port)).unwrap(),
            first_party.location(Some(&origin)).unwrap(),
            "the default https port is not part of the origin"
        );
        let error = first_party.location(None).unwrap_err();
        assert!(
            format!("{error:#}").contains("requires a configured first-party origin"),
            "got: {error:#}"
        );
    }

    #[test]
    fn first_party_origin_accepts_only_an_exact_https_origin() {
        for accepted in [
            ("https://rust.pkg.re", "https://rust.pkg.re"),
            ("https://rust.pkg.re/", "https://rust.pkg.re"),
            ("https://rust.pkg.re:443", "https://rust.pkg.re"),
            ("https://rust.pkg.re:443/", "https://rust.pkg.re"),
            (
                "https://registry.example:8443",
                "https://registry.example:8443",
            ),
            ("https://registry.example", "https://registry.example"),
            ("https://127.0.0.1", "https://127.0.0.1"),
            ("https://127.0.0.1:8443", "https://127.0.0.1:8443"),
            ("https://0.0.0.0", "https://0.0.0.0"),
            ("https://255.255.255.255", "https://255.255.255.255"),
            ("https://localhost", "https://localhost"),
        ] {
            let origin = FirstPartyOrigin::parse(accepted.0).unwrap();
            assert_eq!(origin.as_str(), accepted.1, "{}", accepted.0);
        }
        for refused in [
            "",
            "rust.pkg.re",
            "http://rust.pkg.re",
            "HTTP://rust.pkg.re",
            "https://",
            "https:///crates",
            "https://rust.pkg.re/crates",
            "https://rust.pkg.re/crates/",
            "https://rust.pkg.re?query=1",
            "https://rust.pkg.re#fragment",
            "https://user@rust.pkg.re",
            "https://user:secret@rust.pkg.re",
            "https://Rust.pkg.re",
            "https://rust.pkg.re:",
            "https://rust.pkg.re:0",
            "https://rust.pkg.re:65536",
            "https://rust.pkg.re:08443",
            "https://rust.pkg.re:port",
            "https:// rust.pkg.re",
            "https://rust..pkg.re",
            "https://-rust.pkg.re",
            "https://rust.pkg.re-",
            "https://rust.pkg.re/.",
            // IPv6 literals are not accepted at all.
            "https://[::1]",
            "https://[::1]:8443",
            // Numeric host forms that URL parsers read as another IPv4 address.
            "https://010.0.0.1",
            "https://0x7f.0.0.1",
            "https://2130706433",
            "https://12345",
            "https://1.2.3",
            "https://1.2.3.4.5",
            "https://999.999.999.999",
            "https://256.0.0.1",
            "https://example.123",
            // An unchecked internationalized label.
            "https://xn--a.example",
            "https://rust.xn--pkg",
        ] {
            assert!(
                FirstPartyOrigin::parse(refused).is_err(),
                "first-party origin {refused:?} must be refused"
            );
        }
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
        let origin = first_party_origin();
        let location = crates_io.location(Some(&origin)).unwrap();
        let response = || ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: crates_io.clone(),
            location: location.clone(),
        };
        assert!(
            response()
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"), &origin)
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
                response().validate(&path, &origin).is_err(),
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
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"), &origin)
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
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"), &origin)
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
                .validate(
                    &format!("/v1/main/gitcrate/2.0.0/{METADATA_SHA256}"),
                    &origin
                )
                .is_err()
        );

        let wrong_location = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: crates_io,
            location: "https://example.invalid/archive".to_owned(),
        };
        assert!(
            wrong_location
                .validate(&format!("/v1/main/serde/1.0.0/{METADATA_SHA256}"), &origin)
                .is_err()
        );

        let first_party = RedirectDestination::FirstParty {
            sha256: ARCHIVE_SHA256.to_owned(),
        };
        let route = format!("/v1/main/gitcrate/2.0.0/{ARCHIVE_SHA256}");
        let resolved = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: first_party.clone(),
            location: first_party.location(Some(&origin)).unwrap(),
        };
        assert!(resolved.validate(&route, &origin).is_ok());

        let alternative = FirstPartyOrigin::parse("https://registry.example").unwrap();
        let foreign_location = ProjectionManifestResponse::Redirect {
            representation: ProjectedRepresentation::Redirect,
            destination: first_party.clone(),
            location: first_party.location(Some(&alternative)).unwrap(),
        };
        assert!(
            foreign_location.validate(&route, &origin).is_err(),
            "a first-party location resolved from another origin must be refused"
        );
    }

    #[test]
    fn manifest_rejects_response_representation_mismatches() {
        let mut inline = inline_manifest_route("/metadata");
        let ProjectionManifestResponse::Inline { representation, .. } = &mut inline.response else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::Archive;
        assert!(
            test_manifest(vec![inline])
                .validate(&first_party_origin())
                .is_err()
        );

        let mut config = inline_manifest_route("/config.json");
        let ProjectionManifestResponse::Inline { representation, .. } = &mut config.response else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataText;
        assert!(
            test_manifest(vec![config])
                .validate(&first_party_origin())
                .is_err()
        );

        let mut sparse = inline_manifest_route("/2/cc");
        let ProjectionManifestResponse::Inline { representation, .. } = &mut sparse.response else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataJson;
        assert!(
            test_manifest(vec![sparse])
                .validate(&first_party_origin())
                .is_err()
        );

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
        assert!(
            test_manifest(vec![archive])
                .validate(&first_party_origin())
                .is_err()
        );

        let destination = RedirectDestination::FirstParty {
            sha256: ARCHIVE_SHA256.to_owned(),
        };
        let mut redirect = ProjectionManifestRoute {
            path: format!("/v1/main/gitcrate/2.0.0/{ARCHIVE_SHA256}"),
            response: ProjectionManifestResponse::Redirect {
                representation: ProjectedRepresentation::Redirect,
                location: destination.location(Some(&first_party_origin())).unwrap(),
                destination,
            },
        };
        let ProjectionManifestResponse::Redirect { representation, .. } = &mut redirect.response
        else {
            unreachable!();
        };
        *representation = ProjectedRepresentation::MetadataText;
        assert!(
            test_manifest(vec![redirect])
                .validate(&first_party_origin())
                .is_err()
        );
    }

    #[test]
    fn manifest_rejects_bad_hashes_ordering_and_duplicates() {
        let mut bad_inline = inline_manifest_route("/a");
        bad_inline.response = ProjectionManifestResponse::Inline {
            representation: ProjectedRepresentation::MetadataText,
            bytes: 0,
            sha256: "ABCDEF".to_owned(),
        };
        assert!(
            test_manifest(vec![bad_inline])
                .validate(&first_party_origin())
                .is_err()
        );

        let bad_archive = ProjectionManifestRoute {
            path: format!("/crates/{ARCHIVE_SHA256}.crate"),
            response: ProjectionManifestResponse::Archive {
                representation: ProjectedRepresentation::Archive,
                bytes: 7,
                sha256: METADATA_SHA256.to_owned(),
                archive_sha256: ARCHIVE_SHA256.to_owned(),
            },
        };
        assert!(
            test_manifest(vec![bad_archive])
                .validate(&first_party_origin())
                .is_err()
        );

        assert!(
            test_manifest(vec![
                inline_manifest_route("/b"),
                inline_manifest_route("/a")
            ])
            .validate(&first_party_origin())
            .is_err()
        );
        assert!(
            test_manifest(vec![
                inline_manifest_route("/a"),
                inline_manifest_route("/a")
            ])
            .validate(&first_party_origin())
            .is_err()
        );
        test_manifest(vec![
            inline_manifest_route("/A"),
            inline_manifest_route("/a"),
        ])
        .validate(&first_party_origin())
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
            usage: ProjectionUsage {
                routes: 4,
                inline_body_bytes: 8,
                inline_bytes: 8,
                archives: 1,
                archive_body_bytes: 7,
                archive_bytes: 7,
                snapshot_body_bytes: 15,
                ..ProjectionUsage::default()
            },
        };

        let first = projection.manifest_bytes(&first_party_origin()).unwrap();
        let second = projection.manifest_bytes(&first_party_origin()).unwrap();
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
