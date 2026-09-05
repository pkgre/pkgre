//! Public registry and admin axum applications for snapshot serving.

use std::borrow::Cow;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::Response;
use serde::Serialize;
use tokio::sync::{RwLock, Semaphore};
use tracing::info;

use pkgre_rust::http_response::{
    ApplicationResponse, CONTENT_TYPE_METADATA_JSON, evaluate_request,
};
use pkgre_rust::serve::{DeliveryMode, Snapshot};

/// Frontend-supplied original request target that overrides the wire target.
pub const ORIGINAL_URI_HEADER: HeaderName = HeaderName::from_static("x-pkgre-original-uri");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const GET_HEAD: HeaderValue = HeaderValue::from_static("GET, HEAD");
const GET_ONLY: HeaderValue = HeaderValue::from_static("GET");
const MAX_LOGGED_TARGET_BYTES: usize = 160;

/// Shared readiness and dispatch state for the public and admin applications.
pub struct Shared {
    snapshot: RwLock<Option<Arc<Snapshot>>>,
    started: Instant,
    delivery: DeliveryMode,
    semaphore: Arc<Semaphore>,
}

impl Shared {
    /// Creates shared state that stays unready until the first snapshot installs.
    #[must_use]
    pub fn new(delivery: DeliveryMode, max_concurrency: NonZeroU32) -> Self {
        Self {
            snapshot: RwLock::new(None),
            started: Instant::now(),
            delivery,
            semaphore: Arc::new(Semaphore::new(
                usize::try_from(max_concurrency.get()).unwrap_or(usize::MAX),
            )),
        }
    }

    /// Atomically installs the current serving snapshot.
    pub async fn install_snapshot(&self, snapshot: Arc<Snapshot>) {
        *self.snapshot.write().await = Some(snapshot);
    }

    /// Returns the installed snapshot, or `None` before the first snapshot is ready.
    #[must_use]
    pub async fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.snapshot.read().await.clone()
    }

    /// Returns whether a serving snapshot is installed.
    #[must_use]
    pub async fn is_ready(&self) -> bool {
        self.snapshot.read().await.is_some()
    }

    /// Returns whole seconds elapsed since service start.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

/// Builds the public registry application served on the public listener.
pub fn public_application(shared: Arc<Shared>) -> Router {
    Router::new().fallback(dispatch).with_state(shared)
}

/// Builds the admin application served on the admin listener.
pub fn admin_application(shared: Arc<Shared>) -> Router {
    Router::new().fallback(admin_dispatch).with_state(shared)
}

async fn dispatch(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let raw_target = match request_target(request.headers(), request.uri()) {
        Some(target) => target.as_bytes().to_vec(),
        None => return empty_response(StatusCode::NOT_FOUND),
    };
    let Some(snapshot) = shared.snapshot().await else {
        return empty_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    if raw_target == b"/" {
        return index_response(&method, &snapshot);
    }
    let Ok(permit) = Arc::clone(&shared.semaphore).acquire_owned().await else {
        return empty_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let started = Instant::now();
    let application = evaluate_request(&raw_target, method.as_str(), &[], &snapshot.routes);
    let response = framework_response(&method, &application);
    drop(permit);
    info!(
        method = %method,
        status = application.status(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        target = %truncate_target(&raw_target),
        "served registry request"
    );
    response
}

async fn admin_dispatch(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response {
    let path = request.uri().path();
    let method = request.method();
    let get = method == Method::GET;
    let head = method == Method::HEAD;
    match path {
        "/healthz" | "/readyz" if get || head => {
            let status = if path == "/readyz" && !shared.is_ready().await {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            empty_response(status)
        }
        "/healthz" | "/readyz" => method_not_allowed(&GET_HEAD),
        "/status" if get => status_response(&shared).await,
        "/status" => method_not_allowed(&GET_ONLY),
        _ => empty_response(StatusCode::NOT_FOUND),
    }
}

async fn status_response(shared: &Shared) -> Response {
    let snapshot = shared.snapshot().await;
    let counts = snapshot.as_ref().map(|snapshot| StatusCounts {
        inline: snapshot.inline_routes,
        archive: snapshot.archive_routes,
        redirect: snapshot.redirect_routes,
    });
    let report = StatusResponse {
        schema: 1,
        ready: snapshot.is_some(),
        mode: shared.delivery.as_str(),
        counts,
        uptime_seconds: shared.uptime_seconds(),
    };
    let Ok(body) = serde_json::to_vec(&report) else {
        return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_METADATA_JSON),
    );
    response
}

/// Serves the minimal HTML index at "/" with live snapshot metadata.
fn index_response(method: &Method, snapshot: &Snapshot) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(&GET_HEAD);
    }
    let mut response = Response::new(Body::from(index_page(snapshot)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// Renders the no-JS index page: identity, source pin, delivery, route counts.
fn index_page(snapshot: &Snapshot) -> String {
    let (inline, archive, redirect) = snapshot.counts();
    let commit = if snapshot.source_commit.is_empty() {
        "unknown"
    } else {
        snapshot.source_commit.as_str()
    };
    let head = concat!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n",
        "<title>pkg.re Cargo registry</title>\n<style>\n",
        "body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1.25rem;line-height:1.55;color:#1b1f24;background:#fff}\n",
        "h1{font-size:1.35rem;margin:0 0 .2rem}\n",
        "p{margin:.5rem 0}\n",
        "dl{margin:.75rem 0}\n",
        "dt{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;margin-top:.5rem}\n",
        "dd{margin:.1rem 0 0}\n",
        "code{background:#f3f4f6;padding:.1rem .35rem;border-radius:4px;font-size:.925em;word-break:break-all}\n",
        "a{color:#0b57d0}\n",
        "footer{margin-top:3rem;font-size:.85rem;color:#6b7280}\n",
        "</style>\n</head>\n<body>\n",
    );
    let tail = "\n<footer>pkg.re — deterministic, read-only package install planes.</footer>\n</body>\n</html>\n";
    let mut page = String::from(head);
    page.push_str("<h1>pkg.re Cargo registry</h1>\n");
    page.push_str(
        "<p>Curated, read-only Cargo sparse registry served from an immutable, validated snapshot.</p>\n",
    );
    let metadata = format!(
        "<dl>\n<dt>source commit</dt><dd><code>{commit}</code></dd>\n<dt>delivery</dt><dd>{mode}</dd>\n<dt>routes</dt><dd>{inline} inline / {archive} archive / {redirect} redirect</dd>\n</dl>\n",
        mode = snapshot.mode.as_str(),
    );
    page.push_str(&metadata);
    page.push_str(
        "<p><a href=\"/config.json\">config.json</a> · <a href=\"https://github.com/pkgre\">pkgre on GitHub</a></p>",
    );
    page.push_str(tail);
    page
}

fn request_target<'a>(headers: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    let mut original_values = headers.get_all(&ORIGINAL_URI_HEADER).iter();
    match (original_values.next(), original_values.next()) {
        (Some(value), None) => value.to_str().ok(),
        (None, None) => uri
            .path_and_query()
            .map(axum::http::uri::PathAndQuery::as_str),
        _ => None,
    }
}

fn truncate_target(raw: &[u8]) -> Cow<'_, str> {
    if raw.len() <= MAX_LOGGED_TARGET_BYTES {
        return String::from_utf8_lossy(raw);
    }
    let mut truncated = String::from_utf8_lossy(&raw[..MAX_LOGGED_TARGET_BYTES]).into_owned();
    truncated.push_str("...");
    Cow::Owned(truncated)
}

fn framework_response(method: &Method, application: &ApplicationResponse) -> Response {
    let Ok(status) = StatusCode::from_u16(application.status()) else {
        return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut builder = Response::builder().status(status);
    for header in application.headers() {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name().as_bytes()),
            HeaderValue::from_str(header.value()),
        ) else {
            return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
        };
        builder = builder.header(name, value);
    }
    let body = if *method == Method::HEAD {
        Body::empty()
    } else {
        application
            .body()
            .map(|body| Body::from(body.to_vec()))
            .unwrap_or_default()
    };
    builder
        .body(body)
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn method_not_allowed(allow: &HeaderValue) -> Response {
    let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
    response.headers_mut().insert(ALLOW, allow.clone());
    response
}

fn empty_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    schema: u64,
    ready: bool,
    mode: &'static str,
    counts: Option<StatusCounts>,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct StatusCounts {
    inline: usize,
    archive: usize,
    redirect: usize,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use axum::http::header::{CONTENT_LENGTH, LOCATION};
    use http_body_util::BodyExt;
    use pkgre_rust::artifact::sha256_bytes;
    use pkgre_rust::projection::ProjectionLimits;
    use pkgre_rust::serve::build_snapshot;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    const FIXTURE_SHA256: &str = "d5d2ce2cf86fafcb52400677c6f020ce096132deb45a24d5535e98149b0baacc";
    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/rust-current-catalog-d778238.tar.gz"
    ));

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
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

    /// Builds one immutable redirect snapshot from the frozen fixture catalog.
    fn fixture_snapshot() -> Arc<Snapshot> {
        static SNAPSHOT: OnceLock<Arc<Snapshot>> = OnceLock::new();
        Arc::clone(SNAPSHOT.get_or_init(|| {
            assert_eq!(sha256_bytes(FIXTURE), FIXTURE_SHA256);
            let temp = TempDir::new("pkgre-serve-web-fixture");
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
            let root = extraction.join("registry");
            Arc::new(
                build_snapshot(
                    &root,
                    DeliveryMode::Redirect,
                    None,
                    ProjectionLimits::default(),
                )
                .unwrap(),
            )
        }))
    }

    async fn shared_with(snapshot: Option<Arc<Snapshot>>) -> Arc<Shared> {
        let shared = Arc::new(Shared::new(
            DeliveryMode::Redirect,
            NonZeroU32::new(8).unwrap(),
        ));
        if let Some(snapshot) = snapshot {
            shared.install_snapshot(snapshot).await;
        }
        shared
    }

    fn request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn request_with_header(method: Method, uri: &str, name: &str, value: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(name, value)
            .body(Body::empty())
            .unwrap()
    }

    async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    #[tokio::test]
    async fn index_route_serves_snapshot_pin_metadata() {
        let snapshot = Arc::new(Snapshot {
            routes: std::collections::BTreeMap::new(),
            mode: DeliveryMode::Body,
            inline_routes: 558,
            archive_routes: 747,
            redirect_routes: 0,
            source_commit: "0dec2a0a92c58a6b1aa92cdc9c49dac9f7b5f183".to_owned(),
        });
        let public = public_application(shared_with(Some(snapshot)).await);
        let (status, headers, body) = send(&public, request(Method::GET, "/")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        let page = String::from_utf8(body).unwrap();
        assert!(page.contains("0dec2a0a92c58a6b1aa92cdc9c49dac9f7b5f183"));
        assert!(page.contains("558 inline / 747 archive / 0 redirect"));
        assert!(page.contains(">body<"));

        let (status, headers, _) = send(&public, request(Method::POST, "/")).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[ALLOW], "GET, HEAD");

        let (status, _, _) = send(
            &public_application(shared_with(None).await),
            request(Method::GET, "/"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn unready_service_reports_unavailable_without_dispatch() {
        let shared = shared_with(None).await;
        let public = public_application(Arc::clone(&shared));
        let admin = admin_application(shared);
        for method in [Method::GET, Method::HEAD] {
            let (status, headers, body) = send(&public, request(method, "/config.json")).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
            assert!(body.is_empty());
        }
        let (status, _, _) = send(&admin, request(Method::GET, "/readyz")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _, _) = send(&admin, request(Method::GET, "/healthz")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) = send(&admin, request(Method::GET, "/status")).await;
        assert_eq!(status, StatusCode::OK);
        let report: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["ready"], json!(false));
        assert_eq!(report["mode"], json!("redirect"));
        assert_eq!(report["counts"], Value::Null);
    }

    #[tokio::test]
    async fn snapshot_policy_vectors_are_served_exactly() {
        let public = public_application(shared_with(Some(fixture_snapshot())).await);
        let (status, headers, body) = send(&public, request(Method::GET, "/config.json")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            headers.get(CACHE_CONTROL).unwrap(),
            "public, max-age=60, must-revalidate"
        );
        assert!(!body.is_empty());
        assert_eq!(
            headers.get(CONTENT_LENGTH).unwrap(),
            body.len().to_string().as_str()
        );
        assert!(headers.get("ETag").is_some());

        let (head_status, head_headers, head_body) =
            send(&public, request(Method::HEAD, "/config.json")).await;
        assert_eq!(head_status, StatusCode::OK);
        assert!(head_body.is_empty());
        assert_eq!(
            head_headers.get(CONTENT_LENGTH).unwrap(),
            headers.get(CONTENT_LENGTH).unwrap()
        );

        let archive_path = fixture_snapshot()
            .routes
            .keys()
            .find(|path| path.starts_with("/crates/"))
            .expect("fixture retains archive routes")
            .clone();
        let (status, headers, body) = send(&public, request(Method::GET, &archive_path)).await;
        assert_eq!(status, StatusCode::OK, "{archive_path}");
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            headers.get(CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert!(!body.is_empty());
        assert_eq!(
            headers.get(CONTENT_LENGTH).unwrap(),
            body.len().to_string().as_str()
        );
        let (head_status, head_headers, head_body) =
            send(&public, request(Method::HEAD, &archive_path)).await;
        assert_eq!(head_status, StatusCode::OK);
        assert!(head_body.is_empty());
        assert_eq!(
            head_headers.get(CONTENT_LENGTH).unwrap(),
            headers.get(CONTENT_LENGTH).unwrap()
        );

        let redirect_path = fixture_snapshot()
            .routes
            .keys()
            .find(|path| path.starts_with("/v1/"))
            .expect("fixture advertises redirects")
            .clone();
        let (status, headers, body) = send(&public, request(Method::GET, &redirect_path)).await;
        assert_eq!(status, StatusCode::FOUND, "{redirect_path}");
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(CONTENT_LENGTH).unwrap(), "0");
        assert!(
            headers
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("https://")
        );
        assert!(body.is_empty());
        let (head_status, _, head_body) =
            send(&public, request(Method::HEAD, &redirect_path)).await;
        assert_eq!(head_status, StatusCode::FOUND);
        assert!(head_body.is_empty());

        for (target, expected) in [
            ("/config.json?query=1", StatusCode::BAD_REQUEST),
            ("/absent", StatusCode::NOT_FOUND),
        ] {
            let (status, headers, body) = send(&public, request(Method::GET, target)).await;
            assert_eq!(status, expected, "{target}");
            assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
            assert!(body.is_empty());
        }
        let (status, headers, body) = send(&public, request(Method::POST, "/config.json")).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers.get(ALLOW).unwrap(), "GET, HEAD");
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn original_uri_header_has_precedence_and_strict_cardinality() {
        let public = public_application(shared_with(Some(fixture_snapshot())).await);
        let (status, _, body) = send(
            &public,
            request_with_header(
                Method::GET,
                "/frontend-normalized",
                "x-pkgre-original-uri",
                "/config.json",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.is_empty());

        let (status, _, _) = send(&public, request(Method::GET, "/config.json")).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send(
            &public,
            request_with_header(
                Method::GET,
                "/frontend-normalized",
                "x-pkgre-original-uri",
                "/config.json?query",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let duplicate = Request::builder()
            .method(Method::GET)
            .uri("/config.json")
            .header(&ORIGINAL_URI_HEADER, "/config.json")
            .header(&ORIGINAL_URI_HEADER, "/config.json")
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&public, duplicate).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn admin_endpoints_enforce_method_and_path_policy() {
        let shared = shared_with(Some(fixture_snapshot())).await;
        let admin = admin_application(Arc::clone(&shared));
        for method in [Method::GET, Method::HEAD] {
            let (status, _, _) = send(&admin, request(method.clone(), "/healthz")).await;
            assert_eq!(status, StatusCode::OK);
            let (status, _, _) = send(&admin, request(method.clone(), "/healthz?probe=1")).await;
            assert_eq!(status, StatusCode::OK);
            let (status, _, _) = send(&admin, request(method, "/readyz")).await;
            assert_eq!(status, StatusCode::OK);
        }
        for path in ["/healthz", "/readyz"] {
            let (status, headers, _) = send(&admin, request(Method::POST, path)).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
            assert_eq!(headers.get(ALLOW).unwrap(), "GET, HEAD");
        }
        let (status, headers, body) = send(&admin, request(Method::GET, "/status")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        let report: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["schema"], json!(1));
        assert_eq!(report["ready"], json!(true));
        assert_eq!(report["mode"], json!("redirect"));
        assert_eq!(
            report["counts"],
            json!({"inline": 558, "archive": 3, "redirect": 747})
        );
        assert!(report["uptimeSeconds"].is_u64());
        let snapshot = fixture_snapshot();
        assert_eq!(snapshot.counts(), (558, 3, 747));
        assert_eq!(snapshot.routes.len(), 1_308);
        for method in [Method::HEAD, Method::POST] {
            let (status, headers, _) = send(&admin, request(method, "/status")).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(headers.get(ALLOW).unwrap(), "GET");
        }
        let (status, _, _) = send(&admin, request(Method::GET, "/absent")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn snapshot_swap_is_atomic_and_updates_status() {
        let shared = shared_with(None).await;
        let public = public_application(Arc::clone(&shared));
        let admin = admin_application(Arc::clone(&shared));
        let (status, _, _) = send(&public, request(Method::GET, "/config.json")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let first = fixture_snapshot();
        shared.install_snapshot(Arc::clone(&first)).await;
        let (status, _, _) = send(&public, request(Method::GET, "/config.json")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) = send(&admin, request(Method::GET, "/status")).await;
        assert_eq!(status, StatusCode::OK);
        let report: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["ready"], json!(true));
        assert_eq!(
            report["counts"],
            json!({"inline": 558, "archive": 3, "redirect": 747})
        );

        let mut routes = BTreeMap::new();
        for (path, route) in &first.routes {
            if path == "/config.json" {
                continue;
            }
            routes.insert(path.clone(), route.clone());
        }
        let second = Arc::new(Snapshot {
            routes,
            mode: DeliveryMode::Redirect,
            inline_routes: first.inline_routes - 1,
            archive_routes: first.archive_routes,
            redirect_routes: first.redirect_routes,
            source_commit: String::new(),
        });
        assert_eq!(second.inline_routes, 557);
        shared.install_snapshot(second).await;
        let (status, _, _) = send(&public, request(Method::GET, "/config.json")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = send(&admin, request(Method::GET, "/status")).await;
        assert_eq!(status, StatusCode::OK);
        let report: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["ready"], json!(true));
        assert_eq!(
            report["counts"],
            json!({"inline": 557, "archive": 3, "redirect": 747})
        );
        let (status, _, _) = send(&admin, request(Method::GET, "/readyz")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn concurrency_limit_queues_public_dispatch() {
        let shared = Arc::new(Shared::new(
            DeliveryMode::Redirect,
            NonZeroU32::new(1).unwrap(),
        ));
        shared.install_snapshot(fixture_snapshot()).await;
        let public = public_application(Arc::clone(&shared));
        let permit = shared.semaphore.clone().acquire_owned().await.unwrap();
        let task =
            tokio::spawn(async move { send(&public, request(Method::GET, "/config.json")).await });
        let mut finished = false;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            finished = task.is_finished();
        }
        assert!(!finished, "dispatch must wait for an available permit");
        drop(permit);
        tokio::time::timeout(Duration::from_secs(10), async {
            while !task.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dispatch resumes after the permit releases");
        let (status, _, body) = task.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(!body.is_empty());
    }
}
