use std::fs;
use std::path::Path;

use pkgre_proxy::marker::validate_marker;
use pkgre_proxy::route::DownloadRoute;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FIXTURE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/redirect-marker-v1"
);
const MAX_MARKER_BYTES: usize = 4 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    schema: String,
    cases: Vec<FixtureCase>,
    #[serde(rename = "hostileCases")]
    hostile_cases: Vec<HostileFixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    name: String,
    file: String,
    ecosystem: String,
    route: String,
    kind: String,
    destination: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostileFixtureCase {
    name: String,
    file: String,
    route: String,
    error: String,
    sha256: String,
}

#[test]
fn rust_renderer_matches_provider_neutral_marker_v1_fixtures() {
    let root = Path::new(FIXTURE_ROOT);
    let manifest: FixtureManifest =
        serde_json::from_slice(&fs::read(root.join("cases.json")).unwrap()).unwrap();
    assert_eq!(manifest.schema, "redirect-marker-v1");
    assert_eq!(
        manifest
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        [
            "rust-crates-io",
            "rust-first-party",
            "js-npmjs",
            "js-first-party"
        ]
    );

    for case in manifest.cases {
        let actual = fs::read(root.join(&case.file)).unwrap();
        let expected = render(&case);
        assert!(actual.is_ascii(), "{} is not ASCII", case.name);
        assert!(
            actual.len() <= MAX_MARKER_BYTES,
            "{} exceeds the marker size bound",
            case.name
        );
        assert_eq!(actual, expected, "{} renderer drift", case.name);
        let route = DownloadRoute::parse_canonical(&case.route).unwrap();
        let marker = validate_marker(&route, &actual).unwrap();
        assert_eq!(
            route.ecosystem().as_str(),
            case.ecosystem,
            "{} ecosystem drift",
            case.name
        );
        assert_eq!(
            marker.kind().as_str(),
            case.kind,
            "{} kind drift",
            case.name
        );
        assert_eq!(
            marker.location(),
            case.destination,
            "{} destination drift",
            case.name
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&actual)),
            case.sha256,
            "{} digest drift",
            case.name
        );
    }
}

#[test]
fn rust_parser_rejects_provider_neutral_hostile_marker_v1_fixtures() {
    let root = Path::new(FIXTURE_ROOT);
    let manifest: FixtureManifest =
        serde_json::from_slice(&fs::read(root.join("cases.json")).unwrap()).unwrap();
    assert_eq!(
        manifest
            .hostile_cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        [
            "unknown-version",
            "duplicate-field",
            "unknown-field",
            "route-replay",
            "destination-host",
            "destination-encoded",
            "machine-meta-mismatch",
            "trailing-bytes",
            "non-ascii",
            "oversize"
        ]
    );

    for case in manifest.hostile_cases {
        let actual = fs::read(root.join(&case.file)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&actual)),
            case.sha256,
            "{} digest drift",
            case.name
        );
        let route = DownloadRoute::parse_canonical(&case.route).unwrap();
        let error = validate_marker(&route, &actual).unwrap_err();
        assert_eq!(error.code(), case.error, "{} error drift", case.name);
    }
}

fn render(case: &FixtureCase) -> Vec<u8> {
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
        case.ecosystem, case.route, case.kind, case.destination, case.destination
    )
    .into_bytes()
}
