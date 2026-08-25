use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::redirect::Policy;
use tokio::net::lookup_host;
use tokio::time::{Instant, timeout};

use crate::marker::MAX_MARKER_BYTES;
use crate::route::{DownloadRoute, MAX_REQUEST_TARGET_BYTES, PublicHost};

pub const PAGES_DNS_NAME: &str = "pkgre.github.io";
const MAX_DNS_ADDRESSES: usize = 16;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
const MARKER_CONTENT_TYPE: &str = "application/octet-stream";
const CANARY_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const RUST_CANARY: &[u8] = b"pkgre-origin rust v1\n";
const JS_CANARY: &[u8] = b"pkgre-origin js v1\n";
const CANARY_PATH: &str = "/origin-health/v1.txt";

pub type MarkerFetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OriginResponse, OriginError>> + Send + 'a>>;

pub trait MarkerFetcher: Send + Sync {
    fn fetch<'a>(&'a self, route: &'a DownloadRoute) -> MarkerFetchFuture<'a>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginResponse {
    Found(Vec<u8>),
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginErrorClass {
    BadGateway,
    ServiceUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginErrorCode {
    InvalidPath,
    DnsTimeout,
    DnsFailure,
    TooManyAddresses,
    NoPublicAddress,
    ClientConfiguration,
    Connection,
    RequestTimeout,
    BodyRead,
    RateLimited,
    ServerStatus,
    UnexpectedStatus,
    UnexpectedContentType,
    UnexpectedContentEncoding,
    BodyTooLarge,
    CanaryNotFound,
    CanaryMismatch,
}

impl OriginErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid-path",
            Self::DnsTimeout => "dns-timeout",
            Self::DnsFailure => "dns-failure",
            Self::TooManyAddresses => "too-many-addresses",
            Self::NoPublicAddress => "no-public-address",
            Self::ClientConfiguration => "client-configuration",
            Self::Connection => "connection",
            Self::RequestTimeout => "request-timeout",
            Self::BodyRead => "body-read",
            Self::RateLimited => "rate-limited",
            Self::ServerStatus => "server-status",
            Self::UnexpectedStatus => "unexpected-status",
            Self::UnexpectedContentType => "unexpected-content-type",
            Self::UnexpectedContentEncoding => "unexpected-content-encoding",
            Self::BodyTooLarge => "body-too-large",
            Self::CanaryNotFound => "canary-not-found",
            Self::CanaryMismatch => "canary-mismatch",
        }
    }

    #[must_use]
    pub const fn class(self) -> OriginErrorClass {
        match self {
            Self::InvalidPath
            | Self::UnexpectedStatus
            | Self::UnexpectedContentType
            | Self::UnexpectedContentEncoding
            | Self::BodyTooLarge
            | Self::CanaryNotFound
            | Self::CanaryMismatch => OriginErrorClass::BadGateway,
            Self::DnsTimeout
            | Self::DnsFailure
            | Self::TooManyAddresses
            | Self::NoPublicAddress
            | Self::ClientConfiguration
            | Self::Connection
            | Self::RequestTimeout
            | Self::BodyRead
            | Self::RateLimited
            | Self::ServerStatus => OriginErrorClass::ServiceUnavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginError {
    code: OriginErrorCode,
}

impl OriginError {
    const fn new(code: OriginErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> OriginErrorCode {
        self.code
    }

    #[must_use]
    pub const fn class(self) -> OriginErrorClass {
        self.code.class()
    }
}

impl From<OriginErrorCode> for OriginError {
    fn from(code: OriginErrorCode) -> Self {
        Self::new(code)
    }
}

impl Display for OriginError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for OriginError {}

#[derive(Clone)]
pub struct PagesOrigin {
    resolver: Arc<dyn AddressResolver>,
    address_fetcher: Arc<dyn AddressFetcher>,
}

impl PagesOrigin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            address_fetcher: Arc::new(ReqwestAddressFetcher),
        }
    }

    /// Fetches and validates the fixed origin canary for one closed public host.
    ///
    /// # Errors
    ///
    /// Returns a classified fail-closed error for DNS, TLS, transport, HTTP, MIME, size, or body mismatch.
    pub async fn check_canary(&self, host: PublicHost) -> Result<(), OriginError> {
        let response = self
            .fetch_path(
                host,
                CANARY_PATH,
                BodyContract {
                    content_type: CANARY_CONTENT_TYPE,
                    max_bytes: RUST_CANARY.len().max(JS_CANARY.len()),
                },
            )
            .await?;
        let expected = match host {
            PublicHost::Rust => RUST_CANARY,
            PublicHost::JavaScript => JS_CANARY,
        };
        match response {
            OriginResponse::Found(body) if body == expected => Ok(()),
            OriginResponse::Found(_) => Err(OriginError::new(OriginErrorCode::CanaryMismatch)),
            OriginResponse::NotFound => Err(OriginError::new(OriginErrorCode::CanaryNotFound)),
        }
    }

    async fn fetch_marker(&self, route: &DownloadRoute) -> Result<OriginResponse, OriginError> {
        self.fetch_path(
            route.public_host(),
            &route.canonical_path(),
            BodyContract {
                content_type: MARKER_CONTENT_TYPE,
                max_bytes: MAX_MARKER_BYTES,
            },
        )
        .await
    }

    async fn fetch_path(
        &self,
        host: PublicHost,
        path: &str,
        body_contract: BodyContract,
    ) -> Result<OriginResponse, OriginError> {
        if !valid_fixed_path(path) {
            return Err(OriginError::new(OriginErrorCode::InvalidPath));
        }
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let resolved = timeout(DNS_TIMEOUT, self.resolver.resolve())
            .await
            .map_err(|_| OriginError::new(OriginErrorCode::DnsTimeout))?
            .map_err(|_| OriginError::new(OriginErrorCode::DnsFailure))?;
        let addresses = validated_addresses(resolved).map_err(OriginError::new)?;
        let mut last_retryable = None;
        for address in addresses {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            let request = AddressRequest {
                host,
                path: path.to_owned(),
                address,
                body_contract,
                timeout: remaining,
            };
            match timeout(remaining, self.address_fetcher.fetch(request)).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(AttemptFailure::Final(code))) => return Err(OriginError::new(code)),
                Ok(Err(AttemptFailure::Retryable(code))) => last_retryable = Some(code),
                Err(_) => last_retryable = Some(OriginErrorCode::RequestTimeout),
            }
        }
        Err(OriginError::new(
            last_retryable.unwrap_or(OriginErrorCode::RequestTimeout),
        ))
    }

    #[cfg(test)]
    fn with_components(
        resolver: Arc<dyn AddressResolver>,
        address_fetcher: Arc<dyn AddressFetcher>,
    ) -> Self {
        Self {
            resolver,
            address_fetcher,
        }
    }
}

impl Default for PagesOrigin {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkerFetcher for PagesOrigin {
    fn fetch<'a>(&'a self, route: &'a DownloadRoute) -> MarkerFetchFuture<'a> {
        Box::pin(async move { self.fetch_marker(route).await })
    }
}

fn valid_fixed_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_REQUEST_TARGET_BYTES
        && path.starts_with('/')
        && path.is_ascii()
        && !path.contains(['?', '#', '%', '\\'])
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| component == "." || component == "..")
}

type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

trait AddressResolver: Send + Sync {
    fn resolve(&self) -> ResolveFuture<'_>;
}

struct SystemResolver;

impl AddressResolver for SystemResolver {
    fn resolve(&self) -> ResolveFuture<'_> {
        Box::pin(async {
            lookup_host((PAGES_DNS_NAME, 443))
                .await
                .map(|addresses| addresses.take(MAX_DNS_ADDRESSES + 1).collect())
        })
    }
}

fn validated_addresses(resolved: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, OriginErrorCode> {
    if resolved.len() > MAX_DNS_ADDRESSES {
        return Err(OriginErrorCode::TooManyAddresses);
    }
    let mut seen = HashSet::new();
    let addresses = resolved
        .into_iter()
        .map(|address| address.ip())
        .filter(|address| is_public_ip(*address))
        .filter(|address| seen.insert(*address))
        .map(|address| SocketAddr::new(address, 443))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        Err(OriginErrorCode::NoPublicAddress)
    } else {
        Ok(addresses)
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 198 && (b == 18 || b == 19))
        && a < 240
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    let global_unicast = value >> 125 == 0b001;
    global_unicast
        && value >> 96 != 0x2001_0db8
        && value >> 80 != 0x2001_0002_0000
        && value >> 96 != 0x2001_0000
        && value >> 100 != 0x0200_1002
        && value >> 112 != 0x2002
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BodyContract {
    content_type: &'static str,
    max_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AddressRequest {
    host: PublicHost,
    path: String,
    address: SocketAddr,
    body_contract: BodyContract,
    timeout: Duration,
}

type AddressFetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OriginResponse, AttemptFailure>> + Send + 'a>>;

trait AddressFetcher: Send + Sync {
    fn fetch(&self, request: AddressRequest) -> AddressFetchFuture<'_>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptFailure {
    Retryable(OriginErrorCode),
    Final(OriginErrorCode),
}

struct ReqwestAddressFetcher;

impl AddressFetcher for ReqwestAddressFetcher {
    fn fetch(&self, request: AddressRequest) -> AddressFetchFuture<'_> {
        Box::pin(fetch_address(request))
    }
}

async fn fetch_address(request: AddressRequest) -> Result<OriginResponse, AttemptFailure> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .connect_timeout(CONNECT_TIMEOUT.min(request.timeout))
        .timeout(request.timeout)
        .resolve(request.host.as_str(), request.address)
        .user_agent(concat!("pkgre-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| AttemptFailure::Final(OriginErrorCode::ClientConfiguration))?;
    let url = format!("https://{}{}", request.host.as_str(), request.path);
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| AttemptFailure::Retryable(OriginErrorCode::Connection))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(OriginResponse::NotFound);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(AttemptFailure::Final(OriginErrorCode::RateLimited));
    }
    if status.is_server_error() {
        return Err(AttemptFailure::Final(OriginErrorCode::ServerStatus));
    }
    if status != reqwest::StatusCode::OK {
        return Err(AttemptFailure::Final(OriginErrorCode::UnexpectedStatus));
    }
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Err(AttemptFailure::Final(
            OriginErrorCode::UnexpectedContentEncoding,
        ));
    }
    let mut content_types = response.headers().get_all(CONTENT_TYPE).iter();
    let content_type = match (content_types.next(), content_types.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    };
    if content_type != Some(request.body_contract.content_type) {
        return Err(AttemptFailure::Final(
            OriginErrorCode::UnexpectedContentType,
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > request.body_contract.max_bytes as u64)
    {
        return Err(AttemptFailure::Final(OriginErrorCode::BodyTooLarge));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AttemptFailure::Final(OriginErrorCode::BodyRead))?
    {
        if body.len().saturating_add(chunk.len()) > request.body_contract.max_bytes {
            return Err(AttemptFailure::Final(OriginErrorCode::BodyTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(OriginResponse::Found(body))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct FakeResolver {
        result: io::Result<Vec<SocketAddr>>,
    }

    impl AddressResolver for FakeResolver {
        fn resolve(&self) -> ResolveFuture<'_> {
            let result = self
                .result
                .as_ref()
                .map(Clone::clone)
                .map_err(|error| io::Error::new(error.kind(), "fake DNS failure"));
            Box::pin(async move { result })
        }
    }

    struct FakeAddressFetcher {
        responses: Mutex<VecDeque<Result<OriginResponse, AttemptFailure>>>,
        requests: Mutex<Vec<AddressRequest>>,
    }

    impl FakeAddressFetcher {
        fn new(responses: Vec<Result<OriginResponse, AttemptFailure>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    impl AddressFetcher for FakeAddressFetcher {
        fn fetch(&self, request: AddressRequest) -> AddressFetchFuture<'_> {
            self.requests.lock().unwrap().push(request);
            let response = self.responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }
    }

    fn socket(address: &str, port: u16) -> SocketAddr {
        SocketAddr::new(address.parse().unwrap(), port)
    }

    fn rust_route() -> DownloadRoute {
        DownloadRoute::parse_canonical(&format!("/v1/main/serde/1.0.0/{SHA256}")).unwrap()
    }

    fn js_route() -> DownloadRoute {
        DownloadRoute::parse_canonical(&format!("/v1/js/main/{SHA256}")).unwrap()
    }

    #[test]
    fn public_address_filter_is_conservative() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:192.0.2.1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2001:20::1",
            "2002::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(
                !is_public_ip(address.parse().unwrap()),
                "accepted {address}"
            );
        }
        for address in [
            "1.1.1.1",
            "185.199.108.153",
            "2606:4700:4700::1111",
            "2606:50c0:8000::153",
        ] {
            assert!(is_public_ip(address.parse().unwrap()), "rejected {address}");
        }
    }

    #[tokio::test]
    async fn retries_only_a_pre_response_failure_on_another_public_address() {
        let resolver = Arc::new(FakeResolver {
            result: Ok(vec![
                socket("127.0.0.1", 80),
                socket("185.199.108.153", 8443),
                socket("185.199.108.153", 443),
                socket("185.199.109.153", 443),
            ]),
        });
        let fetcher = FakeAddressFetcher::new(vec![
            Err(AttemptFailure::Retryable(OriginErrorCode::Connection)),
            Ok(OriginResponse::Found(b"marker".to_vec())),
        ]);
        let origin = PagesOrigin::with_components(resolver, fetcher.clone());
        assert_eq!(
            origin.fetch_marker(&rust_route()).await.unwrap(),
            OriginResponse::Found(b"marker".to_vec())
        );
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].address, socket("185.199.108.153", 443));
        assert_eq!(requests[1].address, socket("185.199.109.153", 443));
        assert_eq!(requests[0].host, PublicHost::Rust);
        assert_eq!(requests[0].path, rust_route().canonical_path());
        assert_eq!(requests[0].body_contract.content_type, MARKER_CONTENT_TYPE);
    }

    #[tokio::test]
    async fn semantic_response_failure_is_never_retried() {
        let resolver = Arc::new(FakeResolver {
            result: Ok(vec![
                socket("185.199.108.153", 443),
                socket("185.199.109.153", 443),
            ]),
        });
        let fetcher = FakeAddressFetcher::new(vec![Err(AttemptFailure::Final(
            OriginErrorCode::UnexpectedStatus,
        ))]);
        let origin = PagesOrigin::with_components(resolver, fetcher.clone());
        let error = origin.fetch_marker(&js_route()).await.unwrap_err();
        assert_eq!(error.code(), OriginErrorCode::UnexpectedStatus);
        assert_eq!(error.class(), OriginErrorClass::BadGateway);
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].host, PublicHost::JavaScript);
        assert_eq!(requests[0].path, js_route().canonical_path());
    }

    #[tokio::test]
    async fn invalid_or_excessive_dns_answers_fail_before_a_request() {
        let fetcher = FakeAddressFetcher::new(Vec::new());
        let private = PagesOrigin::with_components(
            Arc::new(FakeResolver {
                result: Ok(vec![socket("127.0.0.1", 443)]),
            }),
            fetcher.clone(),
        );
        assert_eq!(
            private
                .fetch_marker(&rust_route())
                .await
                .unwrap_err()
                .code(),
            OriginErrorCode::NoPublicAddress
        );
        let excessive = PagesOrigin::with_components(
            Arc::new(FakeResolver {
                result: Ok((1..=MAX_DNS_ADDRESSES + 1)
                    .map(|suffix| socket(&format!("8.8.8.{suffix}"), 443))
                    .collect()),
            }),
            fetcher.clone(),
        );
        assert_eq!(
            excessive
                .fetch_marker(&rust_route())
                .await
                .unwrap_err()
                .code(),
            OriginErrorCode::TooManyAddresses
        );
        assert!(fetcher.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn canary_contract_binds_host_path_mime_and_exact_body() {
        let resolver = Arc::new(FakeResolver {
            result: Ok(vec![socket("185.199.108.153", 443)]),
        });
        let fetcher = FakeAddressFetcher::new(vec![Ok(OriginResponse::Found(JS_CANARY.to_vec()))]);
        let origin = PagesOrigin::with_components(resolver, fetcher.clone());
        origin.check_canary(PublicHost::JavaScript).await.unwrap();
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests[0].host, PublicHost::JavaScript);
        assert_eq!(requests[0].path, CANARY_PATH);
        assert_eq!(requests[0].body_contract.content_type, CANARY_CONTENT_TYPE);
        assert_eq!(requests[0].body_contract.max_bytes, RUST_CANARY.len());
    }
}
