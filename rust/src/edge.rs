//! Trusted edge-to-protocol request boundary.

/// Edge-owned field carrying the exact ingress request-target.
pub const TRUSTED_ORIGINAL_URI_HEADER: &str = "X-Pkgre-Original-URI";
/// Maximum accepted trusted request-target size.
pub const MAX_TRUSTED_TARGET_BYTES: usize = 1024;

/// Authenticates the raw backend target against the closed edge-owned header envelope.
///
/// Exactly one `Host` field and one trusted-target field are required. Any duplicate,
/// missing, mismatched, or additional backend field fails closed.
#[must_use]
pub fn trusted_request_target<'a>(
    backend_target: &'a [u8],
    header_fields: &[(&[u8], &[u8])],
    configured_authority: &[u8],
) -> Option<&'a [u8]> {
    if !valid_target_envelope(backend_target) || header_fields.len() != 2 {
        return None;
    }
    let mut host = None;
    let mut trusted_target = None;
    for (name, value) in header_fields {
        if name.eq_ignore_ascii_case(b"host") {
            if host.replace(*value).is_some() {
                return None;
            }
        } else if name.eq_ignore_ascii_case(TRUSTED_ORIGINAL_URI_HEADER.as_bytes()) {
            if trusted_target.replace(*value).is_some() {
                return None;
            }
        } else {
            return None;
        }
    }
    if host == Some(configured_authority) && trusted_target == Some(backend_target) {
        Some(backend_target)
    } else {
        None
    }
}

fn valid_target_envelope(target: &[u8]) -> bool {
    !target.is_empty()
        && target.len() <= MAX_TRUSTED_TARGET_BYTES
        && target.first() == Some(&b'/')
        && target.is_ascii()
        && !target.contains(&b'#')
        && !target
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b' ' || *byte == 0x7f)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::*;

    const FIXTURE: &[u8] =
        include_bytes!("../../fixtures/dynamic-registry-v1/edge/forwarding.json");
    const RUST_HOST: &str = "rust.pkg.re";
    const JS_HOST: &str = "js.pkg.re";

    #[test]
    #[allow(clippy::too_many_lines)]
    fn follows_shared_edge_forwarding_vectors() {
        let fixture: Value = serde_json::from_slice(FIXTURE).unwrap();
        let mut canonical = serde_json::to_vec_pretty(&fixture).unwrap();
        canonical.push(b'\n');
        assert_eq!(canonical, FIXTURE);
        exact_keys(
            &fixture,
            &[
                "forwardingCases",
                "listenerCases",
                "policy",
                "protocolCases",
                "schema",
            ],
        );
        assert_eq!(fixture["schema"], "pkgre-edge-forwarding-v1");
        assert_eq!(
            fixture["policy"],
            json!({
                "authority": "one protocol-appropriate field with one lowercase canonical hostname and no port; H2 Host plus :authority is rejected",
                "backendRequest": "HTTP/1.1 with exact ingress target and exactly two edge-owned fields: Host and X-Pkgre-Original-URI; every client field is dropped",
                "backendSelection": "exact known SNI plus exact equal authority only; path and client fields never select a backend",
                "backendUnavailableResponse": empty_response(503),
                "hostRoutes": {"js.pkg.re": "js-protocol", "rust.pkg.re": "rust-protocol"},
                "httpBadRequestResponse": empty_response(400),
                "httpMisdirectedResponse": empty_response(421),
                "listenerExposure": {
                    "js-admin": "service-owned Unix socket",
                    "js-protocol": "edge-and-service Unix socket",
                    "public-edge": "public TLS TCP",
                    "rust-admin": "service-owned Unix socket",
                    "rust-protocol": "edge-and-service Unix socket"
                },
                "originalTarget": "unnormalized ingress request-target bytes including query",
                "precedence": ["tls-sni-validation", "authority-validation", "target-envelope-validation", "backend-availability", "forwarding"],
                "protocolBoundary": "raw Host and trusted fields must each occur exactly once; Host must equal configured authority; trusted value must byte-equal backend request target; normalized fallback is forbidden",
                "requestTargetEnvelope": "1..1024 ASCII bytes; origin-form beginning with /; fragment, SP, HTAB, CTL, DEL, and non-ASCII forbidden",
                "tlsRejection": "connection terminates before HTTP; no HTTP response observable",
                "transportRejection": "malformed or over-limit HTTP input is rejected before forwarding; status and framing are parser-specific and excluded",
                "trustedHeaderName": TRUSTED_ORIGINAL_URI_HEADER
            })
        );

        let mut forwarding_ids = HashSet::new();
        for case in fixture["forwardingCases"].as_array().unwrap() {
            let target_key = exclusive_encoding(case, "targetAscii", "targetHex");
            exact_keys(
                case,
                &sorted(&[
                    "authorityFields",
                    "backendAvailable",
                    "clientHeaderFields",
                    "expected",
                    "id",
                    "protocol",
                    "sni",
                    target_key,
                ]),
            );
            assert_id(case, &mut forwarding_ids);
            validate_authority_fields(&case["authorityFields"]);
            validate_header_fields(&case["clientHeaderFields"]);
            exact_keys(
                &case["expected"],
                &["decision", "edgeResponse", "forwarded", "selectedBackend"],
            );
            let actual = evaluate_edge(case);
            assert_eq!(actual, case["expected"], "case {}", case["id"]);
        }
        assert_eq!(forwarding_ids.len(), 36);

        let mut protocol_ids = HashSet::new();
        for case in fixture["protocolCases"].as_array().unwrap() {
            let target_key = exclusive_encoding(case, "backendTargetAscii", "backendTargetHex");
            exact_keys(
                case,
                &sorted(&[
                    "configuredAuthority",
                    "expected",
                    "headerFields",
                    "id",
                    target_key,
                ]),
            );
            assert_id(case, &mut protocol_ids);
            let target = decode(case, "backendTargetAscii", "backendTargetHex");
            let owned_fields = decode_header_fields(&case["headerFields"]);
            let fields = owned_fields
                .iter()
                .map(|(name, value)| (name.as_slice(), value.as_slice()))
                .collect::<Vec<_>>();
            let authority = case["configuredAuthority"].as_str().unwrap().as_bytes();
            let trusted = trusted_request_target(&target, &fields, authority);
            let actual = json!({
                "decision": if trusted.is_some() { "accept" } else { "reject" },
                "trustedTargetAscii": trusted.map(|bytes| std::str::from_utf8(bytes).unwrap())
            });
            assert_eq!(actual, case["expected"], "case {}", case["id"]);
        }
        assert_eq!(protocol_ids.len(), 21);

        let mut listener_ids = HashSet::new();
        for case in fixture["listenerCases"].as_array().unwrap() {
            exact_keys(case, &["expectedReachable", "id", "listener", "source"]);
            assert_id(case, &mut listener_ids);
            let reachable = listener_reachable(
                case["source"].as_str().unwrap(),
                case["listener"].as_str().unwrap(),
            );
            assert_eq!(
                reachable,
                case["expectedReachable"].as_bool().unwrap(),
                "case {}",
                case["id"]
            );
        }
        assert_eq!(listener_ids.len(), 15);
    }

    fn evaluate_edge(case: &Value) -> Value {
        let protocol = case["protocol"].as_str().unwrap();
        assert!(matches!(protocol, "h1" | "h2"));
        let sni = case["sni"].as_str();
        if !sni.is_some_and(known_host) {
            return edge_outcome("tls-reject", None, None);
        }
        let fields = case["authorityFields"].as_array().unwrap();
        let expected_kind = if protocol == "h1" {
            "host"
        } else {
            ":authority"
        };
        if fields.len() != 1 || fields[0]["kind"] != expected_kind {
            return edge_outcome("http-reject", Some(400), None);
        }
        let authority = fields[0]["valueAscii"].as_str().unwrap();
        if !canonical_authority(authority) {
            return edge_outcome("http-reject", Some(400), None);
        }
        if authority != sni.unwrap() {
            return edge_outcome("http-reject", Some(421), None);
        }
        let target = decode(case, "targetAscii", "targetHex");
        if !transport_accepts(&target) {
            return edge_outcome("transport-reject", None, None);
        }
        if target.first() != Some(&b'/') {
            return edge_outcome("http-reject", Some(400), None);
        }
        let backend = if authority == RUST_HOST {
            "rust-protocol"
        } else {
            assert_eq!(authority, JS_HOST);
            "js-protocol"
        };
        if !case["backendAvailable"].as_bool().unwrap() {
            return edge_outcome("backend-unavailable", Some(503), Some(backend));
        }
        let target = std::str::from_utf8(&target).unwrap();
        json!({
            "decision": "forward",
            "edgeResponse": null,
            "forwarded": {
                "authority": authority,
                "headerFields": [
                    {"nameAscii": "Host", "valueAscii": authority},
                    {"nameAscii": TRUSTED_ORIGINAL_URI_HEADER, "valueAscii": target}
                ],
                "protocol": "h1",
                "targetAscii": target
            },
            "selectedBackend": backend
        })
    }

    fn edge_outcome(decision: &str, response_status: Option<u16>, backend: Option<&str>) -> Value {
        json!({
            "decision": decision,
            "edgeResponse": response_status.map(empty_response),
            "forwarded": null,
            "selectedBackend": backend
        })
    }

    fn empty_response(status: u16) -> Value {
        json!({
            "bodyHex": "",
            "headers": {"Cache-Control": "no-store", "Content-Length": "0"},
            "status": status
        })
    }

    fn transport_accepts(target: &[u8]) -> bool {
        !target.is_empty()
            && target.len() <= MAX_TRUSTED_TARGET_BYTES
            && target.is_ascii()
            && !target.contains(&b'#')
            && !target
                .iter()
                .any(|byte| byte.is_ascii_control() || *byte == b' ' || *byte == 0x7f)
    }

    fn listener_reachable(source: &str, listener: &str) -> bool {
        matches!(
            (source, listener),
            ("public", "public-edge")
                | ("edge", "rust-protocol" | "js-protocol")
                | ("rust-service", "rust-admin")
                | ("js-service", "js-admin")
        )
    }

    fn validate_authority_fields(value: &Value) {
        for field in value.as_array().unwrap() {
            exact_keys(field, &["kind", "valueAscii"]);
            assert!(matches!(
                field["kind"].as_str(),
                Some("host" | ":authority")
            ));
            assert!(field["valueAscii"].is_string());
        }
    }

    fn validate_header_fields(value: &Value) {
        let _ = decode_header_fields(value);
    }

    fn decode_header_fields(value: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|field| {
                let value_key = exclusive_encoding(field, "valueAscii", "valueHex");
                exact_keys(field, &sorted(&["nameAscii", value_key]));
                let name = field["nameAscii"].as_str().unwrap().as_bytes().to_vec();
                let value = decode(field, "valueAscii", "valueHex");
                (name, value)
            })
            .collect()
    }

    fn decode(value: &Value, ascii_key: &str, hex_key: &str) -> Vec<u8> {
        match (value.get(ascii_key), value.get(hex_key)) {
            (Some(ascii), None) => ascii.as_str().unwrap().as_bytes().to_vec(),
            (None, Some(hex)) => decode_hex(hex.as_str().unwrap()),
            _ => panic!("exactly one byte encoding is required"),
        }
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

    fn exclusive_encoding<'a>(value: &Value, ascii_key: &'a str, hex_key: &'a str) -> &'a str {
        match (value.get(ascii_key), value.get(hex_key)) {
            (Some(ascii), None) if ascii.is_string() => ascii_key,
            (None, Some(hex)) if hex.is_string() => hex_key,
            _ => panic!("exactly one byte encoding is required"),
        }
    }

    fn exact_keys(value: &Value, expected: &[&str]) {
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(keys, expected);
    }

    fn sorted<'a>(keys: &[&'a str]) -> Vec<&'a str> {
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        keys
    }

    fn assert_id(case: &Value, ids: &mut HashSet<String>) {
        let id = case["id"].as_str().unwrap();
        let mut bytes = id.bytes();
        assert!(matches!(bytes.next(), Some(b'a'..=b'z')));
        assert!(
            bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );
        assert!(ids.insert(id.to_owned()), "duplicate case {id}");
    }

    fn canonical_authority(authority: &str) -> bool {
        !authority.is_empty()
            && authority.len() <= 253
            && authority.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    }

    fn known_host(host: &str) -> bool {
        matches!(host, RUST_HOST | JS_HOST)
    }
}
