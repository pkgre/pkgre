//! Pure registry HTTP response preparation and dispatch policy.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::artifact::sha256_bytes;
use crate::projection::{ProjectedRepresentation, ProjectedResponse};
use crate::request_target::CanonicalRequestTarget;

/// Exact value returned with an unsupported-method response.
pub const ALLOW_METHODS: &str = "GET, HEAD";
/// Cache policy for deterministic application errors and redirects.
pub const CACHE_CONTROL_NO_STORE: &str = "no-store";
/// Cache policy for mutable-by-publication metadata bytes.
pub const CACHE_CONTROL_METADATA: &str = "public, max-age=60, must-revalidate";
/// Cache policy for content-addressed package archives.
pub const CACHE_CONTROL_ARCHIVE: &str = "public, max-age=31536000, immutable";
/// Media type for JSON metadata.
pub const CONTENT_TYPE_METADATA_JSON: &str = "application/json; charset=utf-8";
/// Media type for newline-delimited sparse-index metadata.
pub const CONTENT_TYPE_METADATA_TEXT: &str = "text/plain; charset=utf-8";
/// Media type for exact package archive bytes.
pub const CONTENT_TYPE_ARCHIVE: &str = "application/octet-stream";

/// One application-controlled HTTP response header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeader {
    name: &'static str,
    value: String,
}

impl ResponseHeader {
    fn new(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }

    /// Returns the fixed canonical header name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the exact header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A route prepared once from an immutable catalog projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRoute {
    representation: ProjectedRepresentation,
    body: Option<Arc<Vec<u8>>>,
    entity_tag: Option<String>,
    location: Option<String>,
}

impl PreparedRoute {
    /// Precomputes all body metadata and redirect output used during request dispatch.
    ///
    /// # Errors
    ///
    /// Returns an error if a retained body length cannot be represented by the HTTP policy.
    pub fn from_projected(response: &ProjectedResponse) -> Result<Self> {
        let representation = response.representation();
        if let Some(body) = response.shared_body() {
            let _ = u64::try_from(body.len()).context("projected response body is too large")?;
            return Ok(Self {
                representation,
                body: Some(Arc::clone(body)),
                entity_tag: Some(entity_tag(body)),
                location: None,
            });
        }
        Ok(Self {
            representation,
            body: None,
            entity_tag: None,
            location: response
                .redirect_destination()
                .map(crate::projection::RedirectDestination::location),
        })
    }

    fn respond(&self, head: bool) -> ApplicationResponse {
        if self.representation == ProjectedRepresentation::Redirect {
            return ApplicationResponse {
                body: None,
                headers: vec![
                    ResponseHeader::new("Cache-Control", CACHE_CONTROL_NO_STORE),
                    ResponseHeader::new("Content-Length", "0"),
                    ResponseHeader::new(
                        "Location",
                        self.location
                            .as_deref()
                            .expect("prepared redirect is missing its closed destination"),
                    ),
                ],
                status: 302,
            };
        }

        let body = self
            .body
            .as_ref()
            .expect("prepared body representation is missing body bytes");
        let content_type = match self.representation {
            ProjectedRepresentation::MetadataJson => CONTENT_TYPE_METADATA_JSON,
            ProjectedRepresentation::MetadataText => CONTENT_TYPE_METADATA_TEXT,
            ProjectedRepresentation::Archive => CONTENT_TYPE_ARCHIVE,
            ProjectedRepresentation::Redirect => unreachable!(),
        };
        let cache_control = match self.representation {
            ProjectedRepresentation::MetadataJson | ProjectedRepresentation::MetadataText => {
                CACHE_CONTROL_METADATA
            }
            ProjectedRepresentation::Archive => CACHE_CONTROL_ARCHIVE,
            ProjectedRepresentation::Redirect => unreachable!(),
        };
        ApplicationResponse {
            body: (!head).then(|| Arc::clone(body)),
            headers: vec![
                ResponseHeader::new("Cache-Control", cache_control),
                ResponseHeader::new("Content-Length", body.len().to_string()),
                ResponseHeader::new("Content-Type", content_type),
                ResponseHeader::new(
                    "ETag",
                    self.entity_tag
                        .as_deref()
                        .expect("prepared body representation is missing its entity tag"),
                ),
            ],
            status: 200,
        }
    }
}

/// A complete application-controlled response independent of an HTTP framework.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationResponse {
    status: u16,
    headers: Vec<ResponseHeader>,
    body: Option<Arc<Vec<u8>>>,
}

impl ApplicationResponse {
    /// Returns the exact HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns all and only application-controlled headers.
    #[must_use]
    pub fn headers(&self) -> &[ResponseHeader] {
        &self.headers
    }

    /// Returns response bytes, or `None` for HEAD, redirect, and error responses.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref().map(Vec::as_slice)
    }
}

/// Applies raw-target, method, and exact-route policy in that precedence order.
///
/// Request headers are deliberately ignored: v1 performs no range or content-coding
/// transformation. Callers must enforce independent transport resource bounds before dispatch.
#[must_use]
pub fn evaluate_request(
    raw_target: &[u8],
    method: &str,
    _request_headers: &[(String, String)],
    routes: &BTreeMap<String, PreparedRoute>,
) -> ApplicationResponse {
    let Some(target) = CanonicalRequestTarget::parse(raw_target) else {
        return application_error(400, false);
    };
    let head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return application_error(405, true),
    };
    let Some(route) = routes.get(target.as_str()) else {
        return application_error(404, false);
    };
    route.respond(head)
}

fn entity_tag(body: &[u8]) -> String {
    format!("\"sha256:{}\"", sha256_bytes(body))
}

fn application_error(status: u16, include_allow: bool) -> ApplicationResponse {
    let mut headers = Vec::with_capacity(usize::from(include_allow) + 2);
    if include_allow {
        headers.push(ResponseHeader::new("Allow", ALLOW_METHODS));
    }
    headers.extend([
        ResponseHeader::new("Cache-Control", CACHE_CONTROL_NO_STORE),
        ResponseHeader::new("Content-Length", "0"),
    ]);
    ApplicationResponse {
        status,
        headers,
        body: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use serde::Deserialize;

    use super::*;

    const FIXTURE: &str = include_str!("../../fixtures/dynamic-registry-v1/http/responses.json");

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        cases: Vec<Case>,
        policy: Policy,
        routes: Vec<Route>,
        schema: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Policy {
        allowed_methods: Vec<String>,
        application_error_body: String,
        application_error_cache_control: String,
        compression: String,
        entity_tag: String,
        head: String,
        method_rejection_allow: String,
        precedence: Vec<String>,
        range: String,
        representation_headers: RepresentationHeaders,
        transport_excluded_headers: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "kebab-case")]
    struct RepresentationHeaders {
        archive: RepresentationHeader,
        metadata_json: RepresentationHeader,
        metadata_text: RepresentationHeader,
        redirect: RepresentationHeader,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct RepresentationHeader {
        cache_control: String,
        content_type: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Route {
        path: String,
        response: FixtureResponse,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(
        rename_all = "kebab-case",
        rename_all_fields = "camelCase",
        tag = "type"
    )]
    enum FixtureResponse {
        Inline {
            body_hex: String,
            representation: Representation,
        },
        Archive {
            body_hex: String,
            representation: Representation,
            sha256: String,
        },
        Redirect {
            location: String,
            representation: Representation,
        },
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "kebab-case")]
    enum Representation {
        MetadataJson,
        MetadataText,
        Archive,
        Redirect,
    }

    impl Representation {
        const fn projected(self) -> ProjectedRepresentation {
            match self {
                Self::MetadataJson => ProjectedRepresentation::MetadataJson,
                Self::MetadataText => ProjectedRepresentation::MetadataText,
                Self::Archive => ProjectedRepresentation::Archive,
                Self::Redirect => ProjectedRepresentation::Redirect,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        expected: Expected,
        id: String,
        method: String,
        request_headers: Option<BTreeMap<String, String>>,
        target_ascii: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Expected {
        body_hex: String,
        headers: BTreeMap<String, String>,
        status: u16,
    }

    #[test]
    fn follows_shared_http_response_vectors() {
        let fixture: Fixture = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(fixture.schema, "pkgre-http-responses-v1");
        assert_policy(&fixture.policy);
        let routes = fixture_routes(fixture.routes);
        let mut ids = HashSet::new();
        for case in fixture.cases {
            assert!(ids.insert(case.id.clone()), "duplicate case {}", case.id);
            let request_headers = case
                .request_headers
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            let actual = evaluate_request(
                case.target_ascii.as_bytes(),
                &case.method,
                &request_headers,
                &routes,
            );
            assert_eq!(actual.status(), case.expected.status, "case {}", case.id);
            assert_eq!(
                actual
                    .headers()
                    .iter()
                    .map(|header| (header.name().to_owned(), header.value().to_owned()))
                    .collect::<BTreeMap<_, _>>(),
                case.expected.headers,
                "case {}",
                case.id
            );
            assert_eq!(
                actual.body().unwrap_or_default(),
                decode_hex(&case.expected.body_hex),
                "case {}",
                case.id
            );
        }
    }
    #[test]
    fn prepares_projected_body_and_redirect_descriptors_once() {
        use semver::Version;

        use crate::projection::RedirectDestination;

        let body = b"{}\n".to_vec();
        let expected_entity_tag = entity_tag(&body);
        let inline = ProjectedResponse::inline(body.clone(), ProjectedRepresentation::MetadataJson);
        let prepared = PreparedRoute::from_projected(&inline).unwrap();
        assert_eq!(
            prepared.representation,
            ProjectedRepresentation::MetadataJson
        );
        assert_eq!(
            prepared.body.as_deref().map(Vec::as_slice),
            Some(body.as_slice())
        );
        assert_eq!(
            prepared.entity_tag.as_deref(),
            Some(expected_entity_tag.as_str())
        );
        assert_eq!(prepared.location, None);

        let archive_sha256 = sha256_bytes(&body);
        let archive = ProjectedResponse::archive(Arc::new(body.clone()), archive_sha256);
        let prepared = PreparedRoute::from_projected(&archive).unwrap();
        assert_eq!(prepared.representation, ProjectedRepresentation::Archive);
        assert_eq!(
            prepared.body.as_deref().map(Vec::as_slice),
            Some(body.as_slice())
        );
        assert_eq!(
            prepared.entity_tag.as_deref(),
            Some(expected_entity_tag.as_str())
        );
        assert_eq!(prepared.location, None);

        let redirect = ProjectedResponse::redirect(RedirectDestination::CratesIo {
            name: "fixture".to_owned(),
            version: Version::new(1, 0, 0),
        });
        let prepared = PreparedRoute::from_projected(&redirect).unwrap();
        assert_eq!(prepared.representation, ProjectedRepresentation::Redirect);
        assert_eq!(prepared.body, None);
        assert_eq!(prepared.entity_tag, None);
        assert_eq!(
            prepared.location.as_deref(),
            Some("https://static.crates.io/crates/fixture/1.0.0/download")
        );
    }

    fn fixture_routes(records: Vec<Route>) -> BTreeMap<String, PreparedRoute> {
        let mut routes = BTreeMap::new();
        for record in records {
            assert!(CanonicalRequestTarget::parse(record.path.as_bytes()).is_some());
            let route = match record.response {
                FixtureResponse::Inline {
                    body_hex,
                    representation,
                } => {
                    assert!(matches!(
                        representation,
                        Representation::MetadataJson | Representation::MetadataText
                    ));
                    let body = decode_hex(&body_hex);
                    PreparedRoute {
                        representation: representation.projected(),
                        entity_tag: Some(entity_tag(&body)),
                        body: Some(Arc::new(body)),
                        location: None,
                    }
                }
                FixtureResponse::Archive {
                    body_hex,
                    representation,
                    sha256,
                } => {
                    assert_eq!(representation, Representation::Archive);
                    let body = decode_hex(&body_hex);
                    assert_eq!(sha256_bytes(&body), sha256);
                    PreparedRoute {
                        representation: representation.projected(),
                        entity_tag: Some(entity_tag(&body)),
                        body: Some(Arc::new(body)),
                        location: None,
                    }
                }
                FixtureResponse::Redirect {
                    location,
                    representation,
                } => {
                    assert_eq!(representation, Representation::Redirect);
                    PreparedRoute {
                        representation: representation.projected(),
                        entity_tag: None,
                        body: None,
                        location: Some(location),
                    }
                }
            };
            assert!(routes.insert(record.path, route).is_none());
        }
        routes
    }

    fn assert_policy(policy: &Policy) {
        assert_eq!(policy.allowed_methods, ["GET", "HEAD"]);
        assert_eq!(policy.application_error_body, "empty");
        assert_eq!(
            policy.application_error_cache_control,
            CACHE_CONTROL_NO_STORE
        );
        assert_eq!(
            policy.compression,
            "no content coding or Vary transformation"
        );
        assert_eq!(
            policy.entity_tag,
            "strong quoted lowercase SHA-256 of exact body bytes with sha256: prefix"
        );
        assert_eq!(
            policy.head,
            "same status and application-controlled headers as GET with no response body"
        );
        assert_eq!(policy.method_rejection_allow, ALLOW_METHODS);
        assert_eq!(
            policy.precedence,
            [
                "raw-target-validation",
                "method-validation",
                "exact-route-lookup"
            ]
        );
        assert_eq!(
            policy.range,
            "ignored; return the complete representation with status 200"
        );
        assert_eq!(
            policy.representation_headers.archive,
            RepresentationHeader {
                cache_control: CACHE_CONTROL_ARCHIVE.to_owned(),
                content_type: Some(CONTENT_TYPE_ARCHIVE.to_owned()),
            }
        );
        assert_eq!(
            policy.representation_headers.metadata_json,
            RepresentationHeader {
                cache_control: CACHE_CONTROL_METADATA.to_owned(),
                content_type: Some(CONTENT_TYPE_METADATA_JSON.to_owned()),
            }
        );
        assert_eq!(
            policy.representation_headers.metadata_text,
            RepresentationHeader {
                cache_control: CACHE_CONTROL_METADATA.to_owned(),
                content_type: Some(CONTENT_TYPE_METADATA_TEXT.to_owned()),
            }
        );
        assert_eq!(
            policy.representation_headers.redirect,
            RepresentationHeader {
                cache_control: CACHE_CONTROL_NO_STORE.to_owned(),
                content_type: None,
            }
        );
        assert_eq!(
            policy.transport_excluded_headers,
            ["Connection", "Date", "Server"]
        );
    }

    fn decode_hex(encoded: &str) -> Vec<u8> {
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
}
