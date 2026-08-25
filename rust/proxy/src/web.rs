use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, HOST, LOCATION};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::Response;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::marker::validate_marker;
use crate::origin::{MarkerFetcher, OriginErrorClass, OriginResponse};
use crate::route::{DownloadRoute, PublicHost};
use crate::state::{MarkerOutcome, ServiceState};

pub const ORIGINAL_URI_HEADER: HeaderName = HeaderName::from_static("x-pkgre-original-uri");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const GET_HEAD: HeaderValue = HeaderValue::from_static("GET, HEAD");
const PROMETHEUS_TEXT: HeaderValue =
    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8");

#[derive(Clone)]
struct AppState {
    fetcher: Arc<dyn MarkerFetcher>,
    service: Arc<ServiceState>,
}

pub fn application(fetcher: Arc<dyn MarkerFetcher>, service: Arc<ServiceState>) -> Router {
    Router::new()
        .fallback(handler)
        .with_state(AppState { fetcher, service })
}

async fn handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let method = request.method();
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed();
    }
    let Some(target) = request_target(request.headers(), request.uri()) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    match target {
        "/healthz" => return empty_response(StatusCode::OK),
        "/readyz" => {
            let status = if state.service.is_ready().await {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            return empty_response(status);
        }
        "/metrics" => return metrics_response(method, &state.service).await,
        _ => {}
    }
    let Some(route) = DownloadRoute::parse_canonical(target) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if !public_host_matches(request.headers(), route.public_host()) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    marker_response(&state, &route).await
}

async fn marker_response(state: &AppState, route: &DownloadRoute) -> Response {
    let host = route.public_host();
    let ecosystem = route.ecosystem();
    let route_id = route_identity(route);
    match state.fetcher.fetch(route).await {
        Ok(OriginResponse::NotFound) => {
            state
                .service
                .record_marker(host, MarkerOutcome::NotFound)
                .await;
            debug!(
                host = host.as_str(),
                ecosystem = ecosystem.as_str(),
                route_id,
                outcome = "not-found",
                "origin marker lookup completed"
            );
            empty_response(StatusCode::NOT_FOUND)
        }
        Ok(OriginResponse::Found(body)) => match validate_marker(route, &body) {
            Ok(marker) => {
                if let Ok(location) = HeaderValue::from_str(marker.location()) {
                    state
                        .service
                        .record_marker(host, MarkerOutcome::Redirect)
                        .await;
                    debug!(
                        host = host.as_str(),
                        ecosystem = ecosystem.as_str(),
                        route_id,
                        destination_kind = marker.kind().as_str(),
                        outcome = "redirect",
                        "origin marker lookup completed"
                    );
                    redirect(location)
                } else {
                    state
                        .service
                        .record_marker(host, MarkerOutcome::InvalidMarker)
                        .await;
                    warn!(
                        host = host.as_str(),
                        ecosystem = ecosystem.as_str(),
                        route_id,
                        marker_error = "invalid-location-header",
                        "origin marker rejected"
                    );
                    empty_response(StatusCode::BAD_GATEWAY)
                }
            }
            Err(error) => {
                state
                    .service
                    .record_marker(host, MarkerOutcome::InvalidMarker)
                    .await;
                warn!(
                    host = host.as_str(),
                    ecosystem = ecosystem.as_str(),
                    route_id,
                    marker_error = error.code(),
                    "origin marker rejected"
                );
                empty_response(StatusCode::BAD_GATEWAY)
            }
        },
        Err(error) => {
            let (status, outcome) = match error.class() {
                OriginErrorClass::BadGateway => {
                    (StatusCode::BAD_GATEWAY, MarkerOutcome::BadGateway)
                }
                OriginErrorClass::ServiceUnavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    MarkerOutcome::ServiceUnavailable,
                ),
            };
            state.service.record_marker(host, outcome).await;
            warn!(
                host = host.as_str(),
                ecosystem = ecosystem.as_str(),
                route_id,
                origin_error = error.code().as_str(),
                status = status.as_u16(),
                "origin marker fetch failed"
            );
            empty_response(status)
        }
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

fn public_host_matches(headers: &HeaderMap, expected: PublicHost) -> bool {
    let mut values = headers.get_all(HOST).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_str().as_bytes()
    )
}

fn route_identity(route: &DownloadRoute) -> String {
    format!("{:x}", Sha256::digest(route.canonical_path().as_bytes()))
}

fn redirect(location: HeaderValue) -> Response {
    let mut response = empty_response(StatusCode::TEMPORARY_REDIRECT);
    response.headers_mut().insert(LOCATION, location);
    response
}

fn method_not_allowed() -> Response {
    let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
    response.headers_mut().insert(ALLOW, GET_HEAD);
    response
}

async fn metrics_response(method: &Method, state: &ServiceState) -> Response {
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(state.metrics().await)
    };
    let mut response = response(StatusCode::OK, body);
    response.headers_mut().insert(CONTENT_TYPE, PROMETHEUS_TEXT);
    response
}

fn empty_response(status: StatusCode) -> Response {
    response(status, Body::empty())
}

fn response(status: StatusCode, body: Body) -> Response {
    let mut response = Response::new(body);
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    use super::*;
    use crate::origin::{MarkerFetchFuture, OriginError, OriginErrorCode};

    const RUST_ROUTE: &str =
        "/v1/main/serde/1.0.228/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const JS_ROUTE: &str =
        "/v1/js/main/00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const RUST_MARKER: &[u8] =
        include_bytes!("../../../fixtures/redirect-marker-v1/rust-crates-io.html");
    const JS_MARKER: &[u8] = include_bytes!("../../../fixtures/redirect-marker-v1/js-npmjs.html");

    struct FakeFetcher {
        calls: AtomicUsize,
        routes: Mutex<Vec<DownloadRoute>>,
        responses: Mutex<VecDeque<Result<OriginResponse, OriginError>>>,
    }

    impl FakeFetcher {
        fn new(responses: Vec<Result<OriginResponse, OriginError>>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                routes: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            })
        }
    }

    impl MarkerFetcher for FakeFetcher {
        fn fetch<'a>(&'a self, route: &'a DownloadRoute) -> MarkerFetchFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.routes.lock().unwrap().push(route.clone());
            let response = self.responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }
    }

    fn service() -> Arc<ServiceState> {
        Arc::new(ServiceState::new(Duration::from_secs(180)))
    }

    fn app(
        responses: Vec<Result<OriginResponse, OriginError>>,
    ) -> (Router, Arc<FakeFetcher>, Arc<ServiceState>) {
        let fetcher = FakeFetcher::new(responses);
        let service = service();
        (
            application(fetcher.clone(), Arc::clone(&service)),
            fetcher,
            service,
        )
    }

    fn request(method: Method, target: &str) -> Request<Body> {
        let host = DownloadRoute::parse_canonical(target)
            .map_or("localhost", |route| route.public_host().as_str());
        Request::builder()
            .method(method)
            .uri("/normalized-by-frontend")
            .header(HOST, host)
            .header(&ORIGINAL_URI_HEADER, target)
            .body(Body::empty())
            .unwrap()
    }

    async fn send(app: &Router, method: Method, target: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
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
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        (status, headers, body)
    }

    #[tokio::test]
    async fn canonical_rust_and_js_markers_redirect_for_get_and_head() {
        let responses = [RUST_MARKER, RUST_MARKER, JS_MARKER, JS_MARKER]
            .into_iter()
            .map(|body| Ok(OriginResponse::Found(body.to_vec())))
            .collect();
        let (app, fetcher, service) = app(responses);
        for (target, location) in [
            (
                RUST_ROUTE,
                "https://static.crates.io/crates/serde/1.0.228/download",
            ),
            (
                JS_ROUTE,
                "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
            ),
        ] {
            for method in [Method::GET, Method::HEAD] {
                let (status, headers, body) = send(&app, method, target).await;
                assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
                assert_eq!(headers.get(LOCATION).unwrap(), location);
                assert!(body.is_empty());
            }
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 4);
        assert_eq!(
            fetcher
                .routes
                .lock()
                .unwrap()
                .iter()
                .map(DownloadRoute::canonical_path)
                .collect::<Vec<_>>(),
            [RUST_ROUTE, RUST_ROUTE, JS_ROUTE, JS_ROUTE]
        );
        let metrics = service.metrics().await;
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"rust.pkg.re\",outcome=\"redirect\"} 2\n"
        ));
        assert!(
            metrics.contains(
                "pkgre_marker_requests_total{host=\"js.pkg.re\",outcome=\"redirect\"} 2\n"
            )
        );
    }

    #[tokio::test]
    async fn health_readiness_and_metrics_never_fetch_markers() {
        let (app, fetcher, service) = app(Vec::new());
        let (status, _, _) = send(&app, Method::GET, "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = send(&app, Method::HEAD, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        service.record_canary(PublicHost::Rust, Ok(())).await;
        service.record_canary(PublicHost::JavaScript, Ok(())).await;
        let (status, _, _) = send(&app, Method::GET, "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        let (status, headers, body) = send(&app, Method::GET, "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), PROMETHEUS_TEXT);
        assert!(body.starts_with(b"# HELP pkgre_ready"));
        let (_, _, body) = send(&app, Method::HEAD, "/metrics").await;
        assert!(body.is_empty());
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn malformed_targets_and_duplicate_trusted_headers_never_fetch() {
        let (app, fetcher, _) = app(Vec::new());
        for target in [
            "/",
            "/status",
            &format!("{RUST_ROUTE}?query"),
            &RUST_ROUTE.replace("/serde/", "/serde%2fother/"),
            &RUST_ROUTE.replace("/serde/", "//serde/"),
            &RUST_ROUTE.replace("1.0.228", "01.0.228"),
            &RUST_ROUTE.replace("0123", "ABCD"),
            &format!("{JS_ROUTE}/extra"),
        ] {
            let (status, _, _) = send(&app, Method::GET, target).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{target}");
        }
        let duplicate = Request::builder()
            .uri(RUST_ROUTE)
            .header(&ORIGINAL_URI_HEADER, RUST_ROUTE)
            .header(&ORIGINAL_URI_HEADER, RUST_ROUTE)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(duplicate).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn route_host_confusion_never_fetches_origin() {
        let (app, fetcher, _) = app(Vec::new());
        for (target, hosts) in [
            (RUST_ROUTE, &[][..]),
            (RUST_ROUTE, &["other.pkg.re"][..]),
            (RUST_ROUTE, &["js.pkg.re"][..]),
            (JS_ROUTE, &["rust.pkg.re"][..]),
            (RUST_ROUTE, &["rust.pkg.re:443"][..]),
            (RUST_ROUTE, &["Rust.pkg.re"][..]),
            (RUST_ROUTE, &["rust.pkg.re", "rust.pkg.re"][..]),
        ] {
            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/normalized-by-frontend")
                .header(&ORIGINAL_URI_HEADER, target)
                .body(Body::empty())
                .unwrap();
            for host in hosts {
                request
                    .headers_mut()
                    .append(HOST, HeaderValue::from_str(host).unwrap());
            }
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{target} {hosts:?}"
            );
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn origin_not_found_and_closed_error_classes_map_fail_closed() {
        let cases = [
            (Ok(OriginResponse::NotFound), StatusCode::NOT_FOUND),
            (
                Err(OriginErrorCode::UnexpectedStatus.into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                Err(OriginErrorCode::UnexpectedContentType.into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                Err(OriginErrorCode::UnexpectedContentEncoding.into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                Err(OriginErrorCode::BodyTooLarge.into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                Err(OriginErrorCode::Connection.into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Err(OriginErrorCode::RequestTimeout.into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Err(OriginErrorCode::BodyRead.into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Err(OriginErrorCode::RateLimited.into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Err(OriginErrorCode::ServerStatus.into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];
        let responses = cases.iter().map(|(response, _)| response.clone()).collect();
        let (app, fetcher, service) = app(responses);
        for (_, expected) in cases {
            let (status, _, body) = send(&app, Method::GET, RUST_ROUTE).await;
            assert_eq!(status, expected);
            assert!(body.is_empty());
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 10);
        let metrics = service.metrics().await;
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"rust.pkg.re\",outcome=\"not_found\"} 1\n"
        ));
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"rust.pkg.re\",outcome=\"bad_gateway\"} 4\n"
        ));
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"rust.pkg.re\",outcome=\"service_unavailable\"} 5\n"
        ));
    }

    #[tokio::test]
    async fn marker_route_replay_and_template_drift_are_bad_gateway() {
        let replayed = String::from_utf8(RUST_MARKER.to_vec())
            .unwrap()
            .replace(RUST_ROUTE, &RUST_ROUTE.replace("1.0.228", "1.0.229"));
        let drifted = String::from_utf8(JS_MARKER.to_vec())
            .unwrap()
            .replace("<title>pkg.re redirect</title>", "<title>changed</title>");
        let (app, fetcher, service) = app(vec![
            Ok(OriginResponse::Found(replayed.into_bytes())),
            Ok(OriginResponse::Found(drifted.into_bytes())),
        ]);
        for target in [RUST_ROUTE, JS_ROUTE] {
            let (status, _, _) = send(&app, Method::GET, target).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY);
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 2);
        let metrics = service.metrics().await;
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"rust.pkg.re\",outcome=\"invalid_marker\"} 1\n"
        ));
        assert!(metrics.contains(
            "pkgre_marker_requests_total{host=\"js.pkg.re\",outcome=\"invalid_marker\"} 1\n"
        ));
    }

    #[tokio::test]
    async fn unsupported_methods_return_405_without_origin_fetch() {
        let (app, fetcher, _) = app(Vec::new());
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let (status, headers, body) = send(&app, method, RUST_ROUTE).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(headers.get(ALLOW).unwrap(), GET_HEAD);
            assert!(body.is_empty());
        }
        assert_eq!(fetcher.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn tcp_boundary_preserves_raw_target_and_single_trusted_uri() {
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
                "GET {target} HTTP/1.1\r\nHost: rust.pkg.re\r\n{original_uri}Connection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        }

        let fetcher = FakeFetcher::new(vec![Ok(OriginResponse::Found(RUST_MARKER.to_vec()))]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn({
            let fetcher = fetcher.clone();
            async move {
                axum::serve(listener, application(fetcher, service()))
                    .await
                    .unwrap();
            }
        });
        let response = raw_request(address, "/frontend-normalized", Some(RUST_ROUTE)).await;
        assert!(response.starts_with("HTTP/1.1 307 "), "{response}");
        assert!(
            response
                .contains("location: https://static.crates.io/crates/serde/1.0.228/download\r\n")
        );
        for (target, header) in [
            (format!("/{RUST_ROUTE}"), None),
            (format!("{RUST_ROUTE}?query"), None),
            (format!("{RUST_ROUTE}%3fquery"), None),
            (
                "/frontend-normalized".to_owned(),
                Some(format!("{RUST_ROUTE}?")),
            ),
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
}
