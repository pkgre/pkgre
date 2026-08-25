use std::error::Error;
use std::fmt::{self, Display, Formatter};

use reqwest::Url;

use crate::route::{DownloadRoute, Ecosystem};

pub const MAX_MARKER_BYTES: usize = 4 * 1024;
const MAX_DESTINATION_BYTES: usize = 2048;
const MAX_NPM_COMPONENT_BYTES: usize = 214;
const MACHINE_PREFIX: &str = "<meta name=\"pkgre-redirect\" content=\"v1\" data-ecosystem=\"";
const ROUTE_SEPARATOR: &str = "\" data-route=\"";
const KIND_SEPARATOR: &str = "\" data-kind=\"";
const DESTINATION_SEPARATOR: &str = "\" data-destination=\"";
const MACHINE_SUFFIX: &str = "\" />";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationKind {
    CratesIo,
    Npmjs,
    FirstParty,
}

impl DestinationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CratesIo => "crates-io",
            Self::Npmjs => "npmjs",
            Self::FirstParty => "first-party",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkerError {
    TooLarge,
    NonAscii,
    MalformedTemplate,
    RouteMismatch,
    InvalidDestination,
}

impl MarkerError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "too-large",
            Self::NonAscii => "non-ascii",
            Self::MalformedTemplate => "malformed-template",
            Self::RouteMismatch => "route-mismatch",
            Self::InvalidDestination => "invalid-destination",
        }
    }
}

impl Display for MarkerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for MarkerError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMarker {
    kind: DestinationKind,
    location: String,
}

impl ValidatedMarker {
    #[must_use]
    pub const fn kind(&self) -> DestinationKind {
        self.kind
    }

    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }
}

/// Validates one exact redirect-marker-v1 document against its requested route.
///
/// # Errors
///
/// Returns a classified failure for an oversized, non-ASCII, noncanonical, replayed, or destination-invalid marker.
pub fn validate_marker(route: &DownloadRoute, body: &[u8]) -> Result<ValidatedMarker, MarkerError> {
    if body.len() > MAX_MARKER_BYTES {
        return Err(MarkerError::TooLarge);
    }
    if !body.is_ascii() {
        return Err(MarkerError::NonAscii);
    }
    let text = std::str::from_utf8(body).map_err(|_| MarkerError::NonAscii)?;
    let machine_line = text.lines().nth(4).ok_or(MarkerError::MalformedTemplate)?;
    let fields = parse_machine_line(machine_line)?;
    if fields.ecosystem != route.ecosystem().as_str() || fields.route != route.canonical_path() {
        return Err(MarkerError::RouteMismatch);
    }
    let kind = parse_kind(route.ecosystem(), fields.kind)?;
    validate_destination(route, kind, fields.destination)?;
    if render_marker(route, kind, fields.destination).as_bytes() != body {
        return Err(MarkerError::MalformedTemplate);
    }
    Ok(ValidatedMarker {
        kind,
        location: fields.destination.to_owned(),
    })
}

struct MarkerFields<'a> {
    ecosystem: &'a str,
    route: &'a str,
    kind: &'a str,
    destination: &'a str,
}

fn parse_machine_line(line: &str) -> Result<MarkerFields<'_>, MarkerError> {
    let remainder = line
        .strip_prefix(MACHINE_PREFIX)
        .ok_or(MarkerError::MalformedTemplate)?;
    let (ecosystem, remainder) = remainder
        .split_once(ROUTE_SEPARATOR)
        .ok_or(MarkerError::MalformedTemplate)?;
    let (route, remainder) = remainder
        .split_once(KIND_SEPARATOR)
        .ok_or(MarkerError::MalformedTemplate)?;
    let (kind, remainder) = remainder
        .split_once(DESTINATION_SEPARATOR)
        .ok_or(MarkerError::MalformedTemplate)?;
    let destination = remainder
        .strip_suffix(MACHINE_SUFFIX)
        .ok_or(MarkerError::MalformedTemplate)?;
    Ok(MarkerFields {
        ecosystem,
        route,
        kind,
        destination,
    })
}

fn parse_kind(ecosystem: Ecosystem, value: &str) -> Result<DestinationKind, MarkerError> {
    match (ecosystem, value) {
        (Ecosystem::Rust, "crates-io") => Ok(DestinationKind::CratesIo),
        (Ecosystem::JavaScript, "npmjs") => Ok(DestinationKind::Npmjs),
        (Ecosystem::Rust | Ecosystem::JavaScript, "first-party") => Ok(DestinationKind::FirstParty),
        _ => Err(MarkerError::InvalidDestination),
    }
}

fn validate_destination(
    route: &DownloadRoute,
    kind: DestinationKind,
    destination: &str,
) -> Result<(), MarkerError> {
    if destination.is_empty()
        || destination.len() > MAX_DESTINATION_BYTES
        || !destination.is_ascii()
        || destination.contains(['?', '#', '%', '\\', '"', '&'])
    {
        return Err(MarkerError::InvalidDestination);
    }
    match (route, kind) {
        (DownloadRoute::Rust { .. }, DestinationKind::CratesIo) => {
            let (name, version) = route
                .rust_identity()
                .ok_or(MarkerError::InvalidDestination)?;
            let expected = format!("https://static.crates.io/crates/{name}/{version}/download");
            (destination == expected)
                .then_some(())
                .ok_or(MarkerError::InvalidDestination)
        }
        (DownloadRoute::Rust { .. }, DestinationKind::FirstParty) => {
            let expected = format!("https://rust.pkg.re/crates/{}.crate", route.sha256());
            (destination == expected)
                .then_some(())
                .ok_or(MarkerError::InvalidDestination)
        }
        (DownloadRoute::JavaScript { .. }, DestinationKind::Npmjs) => {
            validate_npmjs_destination(destination)
        }
        (DownloadRoute::JavaScript { .. }, DestinationKind::FirstParty) => {
            let expected = format!("https://js.pkg.re/packages/{}.tgz", route.sha256());
            (destination == expected)
                .then_some(())
                .ok_or(MarkerError::InvalidDestination)
        }
        _ => Err(MarkerError::InvalidDestination),
    }
}

fn validate_npmjs_destination(destination: &str) -> Result<(), MarkerError> {
    let url = Url::parse(destination).map_err(|_| MarkerError::InvalidDestination)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.host_str() != Some("registry.npmjs.org")
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != destination
    {
        return Err(MarkerError::InvalidDestination);
    }
    let segments = url
        .path_segments()
        .ok_or(MarkerError::InvalidDestination)?
        .collect::<Vec<_>>();
    let (package, separator, filename) = match segments.as_slice() {
        [package, separator, filename] if valid_npm_component(package) => {
            (*package, *separator, *filename)
        }
        [scope, package, separator, filename]
            if scope.strip_prefix('@').is_some_and(valid_npm_component)
                && valid_npm_component(package) =>
        {
            (*package, *separator, *filename)
        }
        _ => return Err(MarkerError::InvalidDestination),
    };
    if separator != "-" {
        return Err(MarkerError::InvalidDestination);
    }
    let prefix = format!("{package}-");
    let Some(stem) = filename.strip_suffix(".tgz") else {
        return Err(MarkerError::InvalidDestination);
    };
    let Some(version) = stem.strip_prefix(&prefix) else {
        return Err(MarkerError::InvalidDestination);
    };
    if version.is_empty()
        || !version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
        })
    {
        return Err(MarkerError::InvalidDestination);
    }
    Ok(())
}

fn valid_npm_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NPM_COMPONENT_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'~' | b'-')
        })
}

fn render_marker(route: &DownloadRoute, kind: DestinationKind, destination: &str) -> String {
    format!(
        "<!doctype html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\" />\n\
<meta name=\"pkgre-redirect\" content=\"v1\" data-ecosystem=\"{}\" data-route=\"{}\" data-kind=\"{}\" data-destination=\"{}\" />\n\
<meta http-equiv=\"refresh\" content=\"0;url={}\" />\n\
<title>pkg.re redirect</title>\n\
</head>\n\
<body></body>\n\
</html>\n",
        route.ecosystem().as_str(),
        route.canonical_path(),
        kind.as_str(),
        destination,
        destination
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn route(path: &str) -> DownloadRoute {
        DownloadRoute::parse_canonical(path).unwrap()
    }

    fn rust_route() -> DownloadRoute {
        route(&format!("/v1/main/serde/1.0.228/{SHA256}"))
    }

    fn js_route() -> DownloadRoute {
        route(&format!("/v1/js/main/{SHA256}"))
    }

    #[test]
    fn validates_every_closed_destination_form() {
        let cases = [
            (
                rust_route(),
                DestinationKind::CratesIo,
                "https://static.crates.io/crates/serde/1.0.228/download".to_owned(),
            ),
            (
                rust_route(),
                DestinationKind::FirstParty,
                format!("https://rust.pkg.re/crates/{SHA256}.crate"),
            ),
            (
                js_route(),
                DestinationKind::Npmjs,
                "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz".to_owned(),
            ),
            (
                js_route(),
                DestinationKind::Npmjs,
                "https://registry.npmjs.org/@scope/package/-/package-1.2.3-beta.1+build.tgz"
                    .to_owned(),
            ),
            (
                js_route(),
                DestinationKind::FirstParty,
                format!("https://js.pkg.re/packages/{SHA256}.tgz"),
            ),
        ];
        for (route, kind, destination) in cases {
            let marker = render_marker(&route, kind, &destination);
            let validated = validate_marker(&route, marker.as_bytes()).unwrap();
            assert_eq!(validated.kind(), kind);
            assert_eq!(validated.location(), destination);
        }
    }

    #[test]
    fn rejects_template_and_route_replay_mutations() {
        let route = rust_route();
        let destination = "https://static.crates.io/crates/serde/1.0.228/download";
        let canonical = render_marker(&route, DestinationKind::CratesIo, destination);
        let another_route =
            DownloadRoute::parse_canonical(&format!("/v1/main/serde/1.0.229/{SHA256}")).unwrap();
        let oversized = vec![b'a'; MAX_MARKER_BYTES + 1];
        assert_eq!(
            validate_marker(&route, &oversized),
            Err(MarkerError::TooLarge)
        );
        assert_eq!(
            validate_marker(&route, "é".as_bytes()),
            Err(MarkerError::NonAscii)
        );
        for mutation in [
            canonical.replace("content=\"v1\"", "content=\"v2\""),
            canonical.replace("data-kind=\"crates-io\"", "data-kind=\"unknown\""),
            canonical.replace(" />\n<meta http", " data-extra=\"x\" />\n<meta http"),
            canonical.replace("<body></body>", "<body>extra</body>"),
            canonical.replace("</html>\n", "</html>\ntrailing"),
            canonical.replace(
                &format!("data-route=\"{}\"", route.canonical_path()),
                &format!("data-route=\"{}\"", another_route.canonical_path()),
            ),
            canonical.replacen(
                destination,
                "https://static.crates.io/crates/serde/1.0.227/download",
                1,
            ),
            canonical.replace("data-ecosystem=\"rust\"", "data-ecosystem=\"js\""),
        ] {
            assert!(
                validate_marker(&route, mutation.as_bytes()).is_err(),
                "accepted mutation {mutation:?}"
            );
        }
    }

    #[test]
    fn rejects_destinations_outside_the_closed_grammars() {
        let rust = rust_route();
        let js = js_route();
        let cases = [
            (
                &rust,
                DestinationKind::CratesIo,
                "http://static.crates.io/crates/serde/1.0.228/download",
            ),
            (
                &rust,
                DestinationKind::CratesIo,
                "https://static.crates.io/crates/other/1.0.228/download",
            ),
            (
                &rust,
                DestinationKind::FirstParty,
                "https://rust.pkg.re/crates/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.crate",
            ),
            (
                &js,
                DestinationKind::Npmjs,
                "https://user@registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
            ),
            (
                &js,
                DestinationKind::Npmjs,
                "https://registry.npmjs.org:443/is-number/-/is-number-7.0.0.tgz",
            ),
            (
                &js,
                DestinationKind::Npmjs,
                "https://registry.npmjs.org/is-number/-/other-7.0.0.tgz",
            ),
            (
                &js,
                DestinationKind::Npmjs,
                "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz?x=1",
            ),
            (
                &js,
                DestinationKind::Npmjs,
                "https://registry.npmjs.org/%69s-number/-/is-number-7.0.0.tgz",
            ),
            (
                &js,
                DestinationKind::Npmjs,
                "https://evil.example/is-number/-/is-number-7.0.0.tgz",
            ),
            (
                &js,
                DestinationKind::FirstParty,
                "https://js.pkg.re/packages/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.tgz",
            ),
        ];
        for (route, kind, destination) in cases {
            let marker = render_marker(route, kind, destination);
            assert_eq!(
                validate_marker(route, marker.as_bytes()),
                Err(MarkerError::InvalidDestination),
                "accepted {destination}"
            );
        }
    }
}
