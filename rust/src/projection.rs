//! Deterministic typed projections of validated Rust catalog routes.

use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::download::{DownloadCatalog, DownloadSource};
use crate::policy::validate_catalog;
use crate::render::projected_bodies;
use crate::schema::Catalog;

/// Wire-independent schema of the typed route projection.
pub const PROJECTION_SCHEMA_VERSION: u32 = 1;

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

        for (path, body) in projected_bodies(catalog, artifacts, &policy)? {
            accounting.add_inline(usize_as_u64(body.len(), "inline body length")?, &limits)?;
            insert_route(
                &mut routes,
                &mut accounting,
                &limits,
                ProjectedRoute::new(path, ProjectedResponse::inline(body)),
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
                &mut accounting,
                &limits,
                ProjectedRoute::new(path, ProjectedResponse::redirect(destination)),
            )?;
        }

        let mut archive_bodies = BTreeMap::<String, Arc<Vec<u8>>>::new();
        for approval in catalog.approvals.iter().filter(|approval| {
            !approval.is_removed()
                && matches!(&approval.source, crate::schema::Source::GitTag { .. })
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
    Inline { body: Arc<Vec<u8>> },
    Archive { body: Arc<Vec<u8>>, sha256: String },
    Redirect { destination: RedirectDestination },
}

impl ProjectedResponse {
    fn inline(body: Vec<u8>) -> Self {
        Self {
            source: ProjectedResponseSource::Inline {
                body: Arc::new(body),
            },
        }
    }

    fn archive(body: Arc<Vec<u8>>, sha256: String) -> Self {
        Self {
            source: ProjectedResponseSource::Archive { body, sha256 },
        }
    }

    fn redirect(destination: RedirectDestination) -> Self {
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

    /// Returns inline or archive bytes, if this is a body response.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.shared_body().map(|body| body.as_slice())
    }

    /// Returns the shared immutable body allocation, if this is a body response.
    #[must_use]
    pub const fn shared_body(&self) -> Option<&Arc<Vec<u8>>> {
        match &self.source {
            ProjectedResponseSource::Inline { body }
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
}

/// Closed archive redirect destinations; arbitrary catalog URLs are unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedirectDestination {
    /// Byte-for-byte crates.io archive for the route identity.
    CratesIo { name: String, version: Version },
    /// Content-addressed first-party archive on the Rust registry origin.
    FirstParty { sha256: String },
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
    ensure!(
        route.path.starts_with('/') && !route.path.contains(['?', '#', '\\', '\0']),
        "projected route is not a canonical root-relative path: {:?}",
        route.path
    );
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
            ProjectedRoute::new(path.clone(), ProjectedResponse::inline(Vec::new())),
        )
        .unwrap();
        let before = accounting;
        let error = insert_route(
            &mut routes,
            &mut accounting,
            &limits,
            ProjectedRoute::new(path.clone(), ProjectedResponse::inline(Vec::new())),
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
            ProjectedResponse::inline(b"immutable".to_vec()),
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
