//! Immutable serving snapshots assembled from strictly validated catalogs.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};

use crate::artifact::{ArtifactMap, sha256_file};
use crate::http_response::PreparedRoute;
use crate::policy::validate_sha256;
use crate::projection::{
    CatalogProjection, ProjectedResponseKind, ProjectionLimits, RedirectDestination,
};
use crate::schema::Catalog;

/// Exact archive delivery behavior for one serving snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryMode {
    /// Advertised archives redirect to their typed immutable upstream destinations.
    Redirect,
    /// Every advertised archive is served from this origin's verified body set.
    Body,
}

impl DeliveryMode {
    /// Parses the exact configuration spelling.
    ///
    /// # Errors
    ///
    /// Returns an error for any value other than `redirect` or `body`.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "redirect" => Ok(Self::Redirect),
            "body" => Ok(Self::Body),
            _ => bail!("delivery mode must be \"redirect\" or \"body\", found {value:?}"),
        }
    }

    /// Returns the exact configuration spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Redirect => "redirect",
            Self::Body => "body",
        }
    }
}

/// One immutable snapshot: exact prepared routes plus serving facts.
#[derive(Debug)]
pub struct Snapshot {
    /// Prepared application routes keyed by canonical public path.
    pub routes: BTreeMap<String, PreparedRoute>,
    /// Exact archive delivery behavior this snapshot was built for.
    pub mode: DeliveryMode,
    /// Number of inline metadata routes.
    pub inline_routes: usize,
    /// Number of archive-body routes served from this origin.
    pub archive_routes: usize,
    /// Number of typed redirect routes.
    pub redirect_routes: usize,
}

impl Snapshot {
    /// Returns inline, archive, and redirect route counts for admin diagnostics.
    #[must_use]
    pub const fn counts(&self) -> (usize, usize, usize) {
        (
            self.inline_routes,
            self.archive_routes,
            self.redirect_routes,
        )
    }
}

/// Builds one immutable snapshot from a strictly validated catalog tree.
///
/// Redirect mode serves the projection exactly. Body mode additionally replaces every
/// advertised upstream redirect with a locally served, hash-verified archive body and
/// refuses to publish when any body is missing or mismatched in the archive store.
///
/// # Errors
///
/// Returns an error for any invalid catalog, failed projection limit, missing retained
/// body, or an incomplete or hash-mismatched body-mode archive store.
pub fn build_snapshot(
    root: &Path,
    mode: DeliveryMode,
    archive_store: Option<&Path>,
    limits: ProjectionLimits,
) -> Result<Snapshot> {
    // Body mode fails closed before any catalog work when no store is configured.
    let store = match mode {
        DeliveryMode::Redirect => None,
        DeliveryMode::Body => Some(archive_store.with_context(
            || "body delivery mode requires an archive store path in the service configuration",
        )?),
    };
    let catalog = Catalog::load(root)
        .with_context(|| format!("validate serving catalog {}", root.display()))?;
    crate::policy::validate_catalog(&catalog)
        .with_context(|| format!("validate serving catalog {}", root.display()))?;
    let artifacts = ArtifactMap::load(&catalog)
        .with_context(|| format!("verify serving catalog objects {}", root.display()))?;
    let projection = CatalogProjection::from_catalog_with_limits(&catalog, &artifacts, limits)
        .with_context(|| format!("project serving catalog {}", root.display()))?;

    let mut routes = BTreeMap::new();
    let mut inline_routes = 0_usize;
    let mut archive_routes = 0_usize;
    let mut redirect_routes = 0_usize;
    let mut conversions = Vec::new();
    for route in projection.routes() {
        match route.response().kind() {
            ProjectedResponseKind::Inline => inline_routes += 1,
            ProjectedResponseKind::Archive => archive_routes += 1,
            ProjectedResponseKind::Redirect => redirect_routes += 1,
        }
        if mode == DeliveryMode::Body {
            if let Some(destination) = route.response().redirect_destination() {
                let sha256 = match destination {
                    RedirectDestination::CratesIo { .. } => redirect_archive_sha256(route.path())?,
                    RedirectDestination::FirstParty { sha256 } => sha256.clone(),
                };
                conversions.push((route.path().to_owned(), sha256));
                continue;
            }
        }
        let prepared = PreparedRoute::from_projected(route.response())
            .with_context(|| format!("prepare route {}", route.path()))?;
        routes.insert(route.path().to_owned(), prepared);
    }

    if let Some(store) = store {
        for (path, sha256) in &conversions {
            let body = body_bytes(&projection, store, path, sha256)?;
            let prepared = PreparedRoute::from_archive_body(&body)
                .with_context(|| format!("prepare body-mode route {path}"))?;
            routes.insert(path.clone(), prepared);
        }
        archive_routes += conversions.len();
        redirect_routes -= conversions.len();
    }

    Ok(Snapshot {
        routes,
        mode,
        inline_routes,
        archive_routes,
        redirect_routes,
    })
}

/// Returns one hash-verified archive body for a body-mode `/v1/...` route.
///
/// Crates.io redirects read the content-addressed archive store; first-party redirects
/// reuse the snapshot's own retained bytes, which the projection already hash-verified.
///
/// # Errors
///
/// Returns an error for a missing store object, a digest mismatch, or a snapshot that
/// somehow lacks the retained body its own projection references.
fn body_bytes(
    projection: &CatalogProjection,
    store: &Path,
    path: &str,
    sha256: &str,
) -> Result<Arc<Vec<u8>>> {
    let first_party_path = format!("/crates/{sha256}.crate");
    if let Some(route) = projection
        .routes()
        .iter()
        .find(|route| route.path() == first_party_path)
    {
        return route
            .response()
            .shared_body()
            .map(Arc::clone)
            .with_context(|| format!("snapshot lacks retained body {first_party_path}"));
    }
    let source = store.join(format!("{sha256}.crate"));
    let digest =
        sha256_file(&source).with_context(|| format!("read body-mode archive for {path}"))?;
    ensure!(
        digest == *sha256,
        "body-mode archive {} does not match its digest {sha256}",
        source.display()
    );
    let body = std::fs::read(&source)
        .with_context(|| format!("read body-mode archive {}", source.display()))?;
    Ok(Arc::new(body))
}

/// Extracts and validates the content-addressed hash of one crates.io `/v1/...` redirect route.
///
/// # Errors
///
/// Returns an error when the route's final segment is not a canonical SHA-256.
fn redirect_archive_sha256(path: &str) -> Result<String> {
    let sha256 = path
        .rsplit('/')
        .next()
        .with_context(|| format!("redirect route {path} has no hash segment"))?;
    validate_sha256(sha256)
        .with_context(|| format!("redirect route {path} has an invalid hash"))?;
    Ok(sha256.to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::artifact::sha256_bytes;
    use crate::http_response::evaluate_request;

    const FIXTURE_SHA256: &str = "d5d2ce2cf86fafcb52400677c6f020ce096132deb45a24d5535e98149b0baacc";
    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rust-current-catalog-d778238.tar.gz"
    ));

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "{label}-{}-{}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Extracts the frozen schema-5 catalog fixture and returns its registry root.
    fn fixture_root(temp: &TempDir) -> PathBuf {
        assert_eq!(sha256_bytes(FIXTURE), FIXTURE_SHA256);
        let extraction = temp.path().join("extracted");
        fs::create_dir(&extraction).unwrap();
        let archive = temp.path().join("catalog.tar.gz");
        fs::write(&archive, FIXTURE).unwrap();
        let status = Command::new("tar")
            .args(["--extract", "--gzip", "--file"])
            .arg(&archive)
            .arg("--directory")
            .arg(&extraction)
            .status()
            .unwrap();
        assert!(status.success());
        extraction.join("registry")
    }

    #[test]
    fn delivery_mode_parses_exact_spellings() {
        assert_eq!(
            DeliveryMode::parse("redirect").unwrap(),
            DeliveryMode::Redirect
        );
        assert_eq!(DeliveryMode::parse("body").unwrap(), DeliveryMode::Body);
        assert!(DeliveryMode::parse("both").is_err());
        assert_eq!(DeliveryMode::Redirect.as_str(), "redirect");
        assert_eq!(DeliveryMode::Body.as_str(), "body");
    }

    #[test]
    fn body_mode_requires_a_store_path_before_any_catalog_work() {
        let error = build_snapshot(
            Path::new("/nonexistent-catalog"),
            DeliveryMode::Body,
            None,
            ProjectionLimits::default(),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("requires an archive store"),
            "got: {error:#}"
        );
    }

    #[test]
    fn redirect_hash_extraction_is_closed() {
        let sha = "a".repeat(64);
        let path = format!("/v1/main/leaf/1.0.0/{sha}");
        assert_eq!(redirect_archive_sha256(&path).unwrap(), sha.clone());
        assert!(redirect_archive_sha256("/v1/main/leaf/1.0.0/short").is_err());
        assert!(redirect_archive_sha256("/v1/main/leaf/1.0.0").is_err());
    }

    #[test]
    fn frozen_catalog_builds_redirect_snapshot_serving_exact_bytes() {
        let temp = TempDir::new("pkgre-serve-snapshot");
        let root = fixture_root(&temp);

        let snapshot = build_snapshot(
            &root,
            DeliveryMode::Redirect,
            None,
            ProjectionLimits::default(),
        )
        .unwrap();
        assert_eq!(snapshot.mode, DeliveryMode::Redirect);
        assert_eq!(snapshot.counts(), (558, 3, 747));
        assert_eq!(snapshot.routes.len(), 1_308);

        let path = "/config.json";
        let get = evaluate_request(path.as_bytes(), "GET", &[], &snapshot.routes);
        assert_eq!(get.status(), 200);
        let body = get.body().expect("inline GET carries a body");
        let header = |name: &str| {
            get.headers()
                .iter()
                .find(|header| header.name() == name)
                .map(crate::http_response::ResponseHeader::value)
        };
        assert_eq!(
            header("Content-Length"),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(
            header("Content-Type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(
            header("Cache-Control"),
            Some("public, max-age=60, must-revalidate")
        );
        assert!(header("ETag").is_some());

        let head = evaluate_request(path.as_bytes(), "HEAD", &[], &snapshot.routes);
        assert_eq!(head.status(), 200);
        assert!(head.body().is_none(), "HEAD must not carry a body");
        assert_eq!(
            head.headers()
                .iter()
                .find(|header| header.name() == "Content-Length")
                .map(crate::http_response::ResponseHeader::value),
            header("Content-Length"),
            "HEAD retains the GET content length"
        );

        let post = evaluate_request(path.as_bytes(), "POST", &[], &snapshot.routes);
        assert_eq!(post.status(), 405);
        assert_eq!(
            post.headers()
                .iter()
                .find(|header| header.name() == "Allow")
                .map(crate::http_response::ResponseHeader::value),
            Some("GET, HEAD")
        );
        assert!(post.body().is_none());

        assert_eq!(
            evaluate_request(b"/absent", "GET", &[], &snapshot.routes).status(),
            404
        );
        assert_eq!(
            evaluate_request(b"/config.json?query=1", "GET", &[], &snapshot.routes).status(),
            400
        );
    }

    #[test]
    fn body_mode_refuses_an_incomplete_archive_store() {
        let temp = TempDir::new("pkgre-serve-body-missing");
        let root = fixture_root(&temp);
        let store = temp.path().join("store");
        fs::create_dir(&store).unwrap();

        let error = build_snapshot(
            &root,
            DeliveryMode::Body,
            Some(&store),
            ProjectionLimits::default(),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("read body-mode archive for"),
            "missing bodies must fail with the first missing route, got: {rendered}"
        );
    }
}
