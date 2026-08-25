use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, LOCATION, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::Response;

use crate::catalog::RouteKey;
use crate::coordinator::{AbsenceState, RefreshCoordinator, retry_after_seconds};

pub const ORIGINAL_URI_HEADER: HeaderName = HeaderName::from_static("x-pkgre-original-uri");
const MAX_REQUEST_TARGET_BYTES: usize = 1024;
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const GET_HEAD: HeaderValue = HeaderValue::from_static("GET, HEAD");
const JSON: HeaderValue = HeaderValue::from_static("application/json");

pub fn application(coordinator: Arc<RefreshCoordinator>) -> Router {
    Router::new().fallback(handler).with_state(coordinator)
}

async fn handler(
    State(coordinator): State<Arc<RefreshCoordinator>>,
    request: Request<Body>,
) -> Response {
    let method = request.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed();
    }
    let Some(target) = request_target(request.headers(), request.uri()) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if target == "/healthz" {
        let status = coordinator.status().await;
        return if status.ready {
            empty_response(StatusCode::OK)
        } else {
            unavailable(status.next_refresh_in_seconds.max(1))
        };
    }
    if target == "/status" {
        if method == Method::HEAD {
            return empty_response(StatusCode::OK);
        }
        return json_response(&coordinator.status().await);
    }
    let Some(key) = parse_route(target) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if let Some(destination) = coordinator.destination(&key).await {
        return redirect(&destination);
    }
    let absence = coordinator.refresh_for_miss().await;
    if let Some(destination) = coordinator.destination(&key).await {
        return redirect(&destination);
    }
    match absence {
        AbsenceState::KnownAbsent => empty_response(StatusCode::NOT_FOUND),
        AbsenceState::Uncertain { retry_after } => unavailable(retry_after_seconds(retry_after)),
    }
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

fn parse_route(target: &str) -> Option<RouteKey> {
    if target.len() > MAX_REQUEST_TARGET_BYTES
        || !target.is_ascii()
        || target.contains(['?', '%', '#'])
    {
        return None;
    }
    let mut segments = target.split('/');
    if segments.next() != Some("") || segments.next() != Some("v1") {
        return None;
    }
    let registry = segments.next()?;
    let name = segments.next()?;
    let version = segments.next()?;
    let sha256 = segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    RouteKey::parse_canonical(registry, name, version, sha256).ok()
}

fn redirect(destination: &str) -> Response {
    let Ok(location) = HeaderValue::from_str(destination) else {
        return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = empty_response(StatusCode::TEMPORARY_REDIRECT);
    response.headers_mut().insert(LOCATION, location);
    response
}

fn method_not_allowed() -> Response {
    let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
    response.headers_mut().insert(ALLOW, GET_HEAD);
    response
}

fn unavailable(retry_after: u64) -> Response {
    let mut response = empty_response(StatusCode::SERVICE_UNAVAILABLE);
    let value = HeaderValue::from_str(&retry_after.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("1"));
    response.headers_mut().insert(RETRY_AFTER, value);
    response
}

fn json_response(status: &impl serde::Serialize) -> Response {
    match serde_json::to_vec(status) {
        Ok(body) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
            response.headers_mut().insert(CONTENT_TYPE, JSON);
            response
        }
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn empty_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use http_body_util::BodyExt;
    use pkgre_rust::download::{
        DOWNLOAD_CATALOG_SCHEMA, DownloadCatalog, DownloadRoute, DownloadSource,
    };
    use semver::Version;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    use super::*;
    use crate::catalog::RouteTable;
    use crate::github::{CatalogFetcher, FetchFailure, FetchFuture, FetchedCatalog};

    struct FakeFetcher {
        calls: AtomicUsize,
        responses: Mutex<VecDeque<std::result::Result<FetchedCatalog, FetchFailure>>>,
    }

    impl FakeFetcher {
        fn new(responses: Vec<std::result::Result<FetchedCatalog, FetchFailure>>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                responses: Mutex::new(VecDeque::from(responses)),
            })
        }
    }

    impl CatalogFetcher for FakeFetcher {
        fn fetch(&self) -> FetchFuture<'_> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = self.responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }
    }

    struct BlockingMissFetcher {
        calls: AtomicUsize,
        release: tokio::sync::Notify,
    }

    impl CatalogFetcher for BlockingMissFetcher {
        fn fetch(&self) -> FetchFuture<'_> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                if call == 0 {
                    Ok(fetched(&[], 'a'))
                } else {
                    self.release.notified().await;
                    Ok(fetched(&[("main", "new", DownloadSource::CratesIo)], 'b'))
                }
            })
        }
    }

    fn fetched(routes: &[(&str, &str, DownloadSource)], commit: char) -> FetchedCatalog {
        let catalog = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: routes
                .iter()
                .map(|(registry, name, source)| DownloadRoute {
                    registry: (*registry).to_owned(),
                    name: (*name).to_owned(),
                    version: Version::parse("1.0.0").unwrap(),
                    sha256: "01".repeat(32),
                    source: *source,
                })
                .collect(),
        };
        FetchedCatalog {
            commit: commit.to_string().repeat(40),
            manifest_sha256: commit.to_string().repeat(64),
            table: Arc::new(RouteTable::from_catalog(catalog).unwrap()),
        }
    }

    fn route_in(registry: &str, name: &str) -> String {
        format!("/v1/{registry}/{name}/1.0.0/{}", "01".repeat(32))
    }

    fn route(name: &str) -> String {
        route_in("main", name)
    }

    fn request(method: Method, target: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri("/normalized-by-frontend")
            .header(&ORIGINAL_URI_HEADER, target)
            .body(Body::empty())
            .unwrap()
    }

    async fn response(
        app: &Router,
        method: Method,
        target: &str,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = app.clone().oneshot(request(method, target)).await.unwrap();
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
    async fn known_get_and_head_routes_redirect_without_fetching() {
        let fetcher = FakeFetcher::new(vec![Ok(fetched(
            &[
                ("main", "mirror", DownloadSource::CratesIo),
                ("main", "published", DownloadSource::GitTag),
            ],
            'a',
        ))]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        coordinator.refresh_if_eligible().await;
        let app = application(coordinator);

        for method in [Method::GET, Method::HEAD] {
            let (status, headers, body) = response(&app, method, &route("mirror")).await;
            assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(
                headers.get(LOCATION).unwrap(),
                "https://static.crates.io/crates/mirror/1.0.0/download"
            );
            assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
            assert!(body.is_empty());
        }
        let (_, headers, _) = response(&app, Method::GET, &route_in("main", "published")).await;
        assert_eq!(
            headers.get(LOCATION).unwrap().to_str().unwrap(),
            format!("https://rust.pkg.re/crates/{}.crate", "01".repeat(32))
        );
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn exact_name_and_checksum_identity_are_required() {
        let fetcher = FakeFetcher::new(vec![Ok(fetched(
            &[("main", "Mirror", DownloadSource::CratesIo)],
            'a',
        ))]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        coordinator.refresh_if_eligible().await;
        let app = application(coordinator);

        let wrong_case = route("mirror");
        let wrong_checksum = format!("/v1/main/Mirror/1.0.0/{}", "02".repeat(32));
        for target in [wrong_case, wrong_checksum] {
            let (status, _, _) = response(&app, Method::GET, &target).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn malformed_targets_never_trigger_refresh() {
        let fetcher = FakeFetcher::new(vec![Ok(fetched(&[], 'a'))]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        coordinator.refresh_if_eligible().await;
        let app = application(coordinator);
        let digest = "01".repeat(32);
        for target in [
            "/",
            "/v1/main/name/1.0.0",
            &format!("/v1/main/name/1.0.0/{digest}/"),
            &format!("//v1/main/name/1.0.0/{digest}"),
            &format!("/v1//name/1.0.0/{digest}"),
            &format!("/v1/Main/name/1.0.0/{digest}"),
            &format!("/v1/main/Name%2fname/1.0.0/{digest}"),
            &format!("/v1/main/name/1.0.0/{digest}%3fignored"),
            &format!("/v1/main/name/01.0.0/{digest}"),
            &format!("/v1/main/name/1.0.0/{}", "AB".repeat(32)),
            &format!("/v1/main/name/1.0.0/{digest}?"),
            &format!("/v1/main/name/1.0.0/{digest}?query"),
            &format!("/v1/main/name/1.0.0/{digest}#fragment"),
        ] {
            let (status, headers, _) = response(&app, Method::GET, target).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{target}");
            assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn unsupported_methods_return_405_with_allow() {
        let fetcher = FakeFetcher::new(vec![]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        let app = application(coordinator);
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let (status, headers, _) = response(&app, method, &route("mirror")).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(headers.get(ALLOW).unwrap(), "GET, HEAD");
            assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn well_formed_miss_refreshes_once_and_retries_lookup() {
        let fetcher = FakeFetcher::new(vec![
            Ok(fetched(&[], 'a')),
            Ok(fetched(
                &[("staging", "new", DownloadSource::CratesIo)],
                'b',
            )),
        ]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        coordinator.refresh_if_eligible().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let app = application(coordinator);

        let (status, headers, _) = response(&app, Method::GET, &route_in("staging", "new")).await;
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            headers.get(LOCATION).unwrap(),
            "https://static.crates.io/crates/new/1.0.0/download"
        );
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn concurrent_well_formed_misses_share_one_refresh() {
        let fetcher = Arc::new(BlockingMissFetcher {
            calls: AtomicUsize::new(0),
            release: tokio::sync::Notify::new(),
        });
        let coordinator = Arc::new(RefreshCoordinator::new(fetcher.clone(), Duration::ZERO));
        coordinator.refresh_if_eligible().await;
        let app = application(coordinator);

        let requests = (0..8)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move { response(&app, Method::GET, &route("new")).await })
            })
            .collect::<Vec<_>>();
        while fetcher.calls.load(Ordering::Relaxed) < 2 {
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 2);
        fetcher.release.notify_one();

        for request in requests {
            let (status, headers, _) = request.await.unwrap();
            assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(
                headers.get(LOCATION).unwrap(),
                "https://static.crates.io/crates/new/1.0.0/download"
            );
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn uncertain_absence_is_503_while_recent_success_is_404() {
        let failed = FetchFailure {
            message: "offline".to_owned(),
            retry_after: Some(Duration::from_secs(30)),
        };
        let fetcher = FakeFetcher::new(vec![Err(failed)]);
        let coordinator = Arc::new(RefreshCoordinator::new(fetcher, Duration::from_secs(120)));
        let app = application(coordinator);
        let (status, headers, _) = response(&app, Method::GET, &route("missing")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "120");

        let fetcher = FakeFetcher::new(vec![Ok(fetched(&[], 'a'))]);
        let coordinator = Arc::new(RefreshCoordinator::new(fetcher, Duration::from_secs(120)));
        coordinator.refresh_if_eligible().await;
        let app = application(coordinator);
        let (status, _, _) = response(&app, Method::GET, &route("missing")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn health_and_status_reflect_readiness_without_refreshing() {
        let fetcher = FakeFetcher::new(vec![Ok(fetched(
            &[("main", "mirror", DownloadSource::CratesIo)],
            'a',
        ))]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        let app = application(Arc::clone(&coordinator));
        let (status, _, _) = response(&app, Method::GET, "/healthz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        coordinator.refresh_if_eligible().await;
        let (status, _, _) = response(&app, Method::GET, "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        let (status, headers, body) = response(&app, Method::GET, "/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/json");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["ready"], true);
        assert_eq!(value["routes"], 1);
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn tcp_requests_preserve_raw_targets_and_trusted_original_uri() {
        async fn raw_request(
            address: std::net::SocketAddr,
            target: &str,
            header: Option<&str>,
        ) -> String {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let original_uri = header.map_or_else(String::new, |value| {
                format!("X-Pkgre-Original-URI: {value}\r\n")
            });
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: localhost\r\n{original_uri}Connection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        }

        let fetcher = FakeFetcher::new(vec![Ok(fetched(
            &[("main", "mirror", DownloadSource::CratesIo)],
            'a',
        ))]);
        let coordinator = Arc::new(RefreshCoordinator::new(
            fetcher.clone(),
            Duration::from_secs(120),
        ));
        coordinator.refresh_if_eligible().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, application(coordinator))
                .await
                .unwrap();
        });
        let exact = route("mirror");

        let response = raw_request(address, "/frontend-normalized", Some(&exact)).await;
        assert!(response.starts_with("HTTP/1.1 307 "), "{response}");
        assert!(
            response
                .contains("location: https://static.crates.io/crates/mirror/1.0.0/download\r\n")
        );
        for (target, header) in [
            (format!("//v1/main/mirror/1.0.0/{}", "01".repeat(32)), None),
            (format!("{exact}?query"), None),
            (format!("{exact}%3fquery"), None),
            ("/frontend-normalized".to_owned(), Some(format!("{exact}?"))),
        ] {
            let response = raw_request(address, &target, header.as_deref()).await;
            assert!(
                response.starts_with("HTTP/1.1 404 "),
                "{target}: {response}"
            );
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 1);
        server.abort();
    }

    #[tokio::test]
    async fn duplicate_trusted_headers_fail_closed() {
        let fetcher = FakeFetcher::new(vec![]);
        let coordinator = Arc::new(RefreshCoordinator::new(fetcher, Duration::from_secs(120)));
        let request = Request::builder()
            .uri(route("missing"))
            .header(&ORIGINAL_URI_HEADER, route("missing"))
            .header(&ORIGINAL_URI_HEADER, route("missing"))
            .body(Body::empty())
            .unwrap();
        let response = application(coordinator).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
