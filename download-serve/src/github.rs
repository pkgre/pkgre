use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use pkgre_indexer::download::MAX_DOWNLOAD_CATALOG_BYTES;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::catalog::RouteTable;

const REF_URL: &str = "https://api.github.com/repos/pkgre/rust/git/ref/heads/main";
const RAW_BASE_URL: &str = "https://raw.githubusercontent.com/pkgre/rust";
const REF_BODY_LIMIT: usize = 128 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(15 * 60);

pub type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = std::result::Result<FetchedCatalog, FetchFailure>> + Send + 'a>>;

pub trait CatalogFetcher: Send + Sync + 'static {
    fn fetch(&self) -> FetchFuture<'_>;
}

#[derive(Clone, Debug)]
pub struct FetchedCatalog {
    pub commit: String,
    pub manifest_sha256: String,
    pub table: Arc<RouteTable>,
}

#[derive(Debug)]
pub struct FetchFailure {
    pub message: String,
    pub retry_after: Option<Duration>,
}

impl FetchFailure {
    fn error(error: impl std::fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            retry_after: None,
        }
    }
}

#[derive(Clone)]
pub struct GitHubCatalogFetcher {
    client: Client,
    ref_url: String,
    raw_base_url: String,
}

impl GitHubCatalogFetcher {
    /// Builds the fixed unauthenticated GitHub catalog client.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTPS client cannot be constructed.
    pub fn new() -> Result<Self> {
        Self::new_with_endpoints(REF_URL, RAW_BASE_URL, true)
    }

    fn new_with_endpoints(ref_url: &str, raw_base_url: &str, https_only: bool) -> Result<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .https_only(https_only)
            .no_proxy()
            .user_agent("pkgre-download-serve/0.1")
            .build()
            .context("build fixed GitHub HTTP client")?;
        Ok(Self {
            client,
            ref_url: ref_url.to_owned(),
            raw_base_url: raw_base_url.trim_end_matches('/').to_owned(),
        })
    }

    async fn fetch_inner(&self) -> std::result::Result<FetchedCatalog, FetchFailure> {
        let response = self
            .client
            .get(&self.ref_url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(FetchFailure::error)?;
        require_success(&response)?;
        let reference = read_bounded(response, REF_BODY_LIMIT)
            .await
            .map_err(FetchFailure::error)?;
        let reference: RefResponse =
            serde_json::from_slice(&reference).map_err(FetchFailure::error)?;
        validate_commit(&reference.object).map_err(FetchFailure::error)?;

        let manifest_url = format!(
            "{}/{}/registry/downloads.json",
            self.raw_base_url, reference.object.sha
        );
        let response = self
            .client
            .get(manifest_url)
            .send()
            .await
            .map_err(FetchFailure::error)?;
        require_success(&response)?;
        let bytes = read_bounded(response, MAX_DOWNLOAD_CATALOG_BYTES)
            .await
            .map_err(FetchFailure::error)?;
        let table = RouteTable::parse(&bytes).map_err(FetchFailure::error)?;
        let manifest_sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(FetchedCatalog {
            commit: reference.object.sha,
            manifest_sha256,
            table: Arc::new(table),
        })
    }
}

impl CatalogFetcher for GitHubCatalogFetcher {
    fn fetch(&self) -> FetchFuture<'_> {
        Box::pin(self.fetch_inner())
    }
}

#[derive(Debug, Deserialize)]
struct RefResponse {
    object: RefObject,
}

#[derive(Debug, Deserialize)]
struct RefObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

fn validate_commit(object: &RefObject) -> Result<()> {
    ensure!(
        object.kind == "commit",
        "GitHub ref does not resolve to a commit"
    );
    ensure!(
        object.sha.len() == 40,
        "GitHub commit SHA is not 40 characters"
    );
    ensure!(
        object
            .sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "GitHub commit SHA is not lowercase hexadecimal"
    );
    Ok(())
}

fn require_success(response: &Response) -> std::result::Result<(), FetchFailure> {
    if response.status() == StatusCode::OK {
        return Ok(());
    }
    let retry_after = retry_after(response.status(), response.headers(), SystemTime::now());
    Err(FetchFailure {
        message: format!("upstream returned HTTP {}", response.status()),
        retry_after,
    })
}

async fn read_bounded(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit as u64,
            "upstream response exceeds {limit} bytes"
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read upstream response body")?
    {
        ensure!(
            bytes.len() <= limit.saturating_sub(chunk.len()),
            "upstream response exceeds {limit} bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn retry_after(status: StatusCode, headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    if let Some(seconds) = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Some(Duration::from_secs(seconds.max(1)));
    }
    let exhausted = headers
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        == Some("0");
    if exhausted {
        if let Some(reset) = headers
            .get("x-ratelimit-reset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        {
            let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            return Some(Duration::from_secs(reset.saturating_sub(now).max(1)));
        }
        return Some(DEFAULT_RATE_LIMIT_BACKOFF);
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Some(DEFAULT_RATE_LIMIT_BACKOFF);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Response as HttpResponse, header};
    use axum::routing::get;
    use pkgre_indexer::download::{
        DOWNLOAD_CATALOG_SCHEMA, DownloadCatalog, DownloadRoute, DownloadSource,
    };
    use reqwest::header::HeaderValue;
    use semver::Version;

    use super::*;

    #[test]
    fn commit_validation_is_exact() {
        assert!(
            validate_commit(&RefObject {
                sha: "01".repeat(20),
                kind: "commit".to_owned(),
            })
            .is_ok()
        );
        for object in [
            RefObject {
                sha: "01".repeat(20),
                kind: "tag".to_owned(),
            },
            RefObject {
                sha: "A1".repeat(20),
                kind: "commit".to_owned(),
            },
            RefObject {
                sha: "01".repeat(19),
                kind: "commit".to_owned(),
            },
        ] {
            assert!(validate_commit(&object).is_err());
        }
    }

    #[test]
    fn retry_after_honors_seconds_and_rate_limit_reset() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("17"));
        assert_eq!(
            retry_after(StatusCode::SERVICE_UNAVAILABLE, &headers, now),
            Some(Duration::from_secs(17))
        );

        headers.remove(RETRY_AFTER);
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("1030"));
        assert_eq!(
            retry_after(StatusCode::FORBIDDEN, &headers, now),
            Some(Duration::from_secs(30))
        );
        headers.remove("x-ratelimit-reset");
        assert_eq!(
            retry_after(StatusCode::FORBIDDEN, &headers, now),
            Some(DEFAULT_RATE_LIMIT_BACKOFF)
        );
    }

    fn canonical_manifest() -> Vec<u8> {
        DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![DownloadRoute {
                registry: "main".to_owned(),
                name: "serde".to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                sha256: "01".repeat(32),
                source: DownloadSource::CratesIo,
            }],
        }
        .canonical_bytes()
        .unwrap()
    }

    async fn test_server(
        responses: Vec<HttpResponse<Body>>,
    ) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let application = Router::new().fallback(get({
            let responses = Arc::clone(&responses);
            let requests = Arc::clone(&requests);
            move |uri: axum::http::Uri| {
                let responses = Arc::clone(&responses);
                let requests = Arc::clone(&requests);
                async move {
                    requests.lock().unwrap().push(uri.to_string());
                    responses.lock().unwrap().pop_front().unwrap()
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, application).await.unwrap();
        });
        (format!("http://{address}"), requests, task)
    }

    fn response(status: StatusCode, body: impl Into<Body>) -> HttpResponse<Body> {
        HttpResponse::builder()
            .status(status)
            .body(body.into())
            .unwrap()
    }

    #[tokio::test]
    async fn fetches_ref_then_commit_pinned_canonical_manifest() {
        let commit = "01".repeat(20);
        let reference = format!(r#"{{"object":{{"sha":"{commit}","type":"commit"}}}}"#);
        let manifest = canonical_manifest();
        let (base, requests, task) = test_server(vec![
            response(StatusCode::OK, reference),
            response(StatusCode::OK, manifest.clone()),
        ])
        .await;
        let fetcher = GitHubCatalogFetcher::new_with_endpoints(
            &format!("{base}/ref"),
            &format!("{base}/raw"),
            false,
        )
        .unwrap();
        let result = fetcher.fetch().await.unwrap();
        assert_eq!(result.commit, commit);
        assert_eq!(
            result.manifest_sha256,
            format!("{:x}", Sha256::digest(&manifest))
        );
        assert_eq!(result.table.route_count(), 1);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                "/ref".to_owned(),
                format!("/raw/{commit}/registry/downloads.json"),
            ]
        );
        task.abort();
    }

    #[tokio::test]
    async fn redirects_invalid_refs_and_oversized_bodies_fail_closed() {
        let redirect = HttpResponse::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/elsewhere")
            .body(Body::empty())
            .unwrap();
        let (base, _, task) = test_server(vec![redirect]).await;
        let fetcher = GitHubCatalogFetcher::new_with_endpoints(&base, &base, false).unwrap();
        assert!(fetcher.fetch().await.unwrap_err().message.contains("302"));
        task.abort();

        let oversized = response(StatusCode::OK, vec![b'x'; REF_BODY_LIMIT + 1]);
        let (base, _, task) = test_server(vec![oversized]).await;
        let fetcher = GitHubCatalogFetcher::new_with_endpoints(&base, &base, false).unwrap();
        assert!(
            fetcher
                .fetch()
                .await
                .unwrap_err()
                .message
                .contains("exceeds")
        );
        task.abort();
    }

    #[tokio::test]
    async fn malformed_json_and_invalid_ref_objects_fail_closed() {
        let invalid_references = [
            "not json".to_owned(),
            format!(
                r#"{{"object":{{"sha":"{}","type":"tag"}}}}"#,
                "01".repeat(20)
            ),
            format!(
                r#"{{"object":{{"sha":"{}","type":"commit"}}}}"#,
                "A1".repeat(20)
            ),
            r#"{"object":{"type":"commit"}}"#.to_owned(),
        ];
        for reference in invalid_references {
            let (base, requests, task) =
                test_server(vec![response(StatusCode::OK, reference)]).await;
            let fetcher = GitHubCatalogFetcher::new_with_endpoints(&base, &base, false).unwrap();
            assert!(fetcher.fetch().await.is_err());
            assert_eq!(requests.lock().unwrap().len(), 1);
            task.abort();
        }
    }

    #[tokio::test]
    async fn raw_redirect_and_noncanonical_manifest_fail_closed() {
        let commit = "01".repeat(20);
        let reference = format!(r#"{{"object":{{"sha":"{commit}","type":"commit"}}}}"#);
        let redirect = HttpResponse::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(header::LOCATION, "/elsewhere")
            .body(Body::empty())
            .unwrap();
        let (base, _, task) =
            test_server(vec![response(StatusCode::OK, reference.clone()), redirect]).await;
        let fetcher = GitHubCatalogFetcher::new_with_endpoints(&base, &base, false).unwrap();
        assert!(fetcher.fetch().await.unwrap_err().message.contains("307"));
        task.abort();

        let mut noncanonical = canonical_manifest();
        noncanonical.push(b'\n');
        let (base, _, task) = test_server(vec![
            response(StatusCode::OK, reference),
            response(StatusCode::OK, noncanonical),
        ])
        .await;
        let fetcher = GitHubCatalogFetcher::new_with_endpoints(&base, &base, false).unwrap();
        assert!(
            fetcher
                .fetch()
                .await
                .unwrap_err()
                .message
                .contains("canonical")
        );
        task.abort();
    }

    #[tokio::test]
    async fn upstream_retry_headers_are_preserved_as_backoff() {
        let rate_limited = HttpResponse::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(RETRY_AFTER, "17")
            .body(Body::empty())
            .unwrap();
        let (base, _, task) = test_server(vec![rate_limited]).await;
        let fetcher = GitHubCatalogFetcher::new_with_endpoints(&base, &base, false).unwrap();
        let failure = fetcher.fetch().await.unwrap_err();
        assert_eq!(failure.retry_after, Some(Duration::from_secs(17)));
        task.abort();
    }
}
