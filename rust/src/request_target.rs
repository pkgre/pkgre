//! Byte-level validation for raw registry request targets.

/// Maximum accepted raw request-target size.
pub const MAX_REQUEST_TARGET_BYTES: usize = 1024;
const MAX_JS_PACKAGE_BYTES: usize = 214;

/// A canonical origin-form path suitable for exact route-map lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalRequestTarget<'a> {
    path: &'a str,
}

impl<'a> CanonicalRequestTarget<'a> {
    /// Validates raw request-target bytes without decoding or normalizing them.
    #[must_use]
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.is_empty()
            || raw.len() > MAX_REQUEST_TARGET_BYTES
            || !raw.is_ascii()
            || raw.first() != Some(&b'/')
        {
            return None;
        }
        if raw == b"/" {
            return Some(Self { path: "/" });
        }
        if raw.last() == Some(&b'/') || raw.windows(2).any(|pair| pair == b"//") {
            return None;
        }
        if raw
            .split(|byte| *byte == b'/')
            .skip(1)
            .any(|segment| segment.is_empty() || segment == b"." || segment == b"..")
        {
            return None;
        }

        let valid = if raw.starts_with(b"/@") {
            valid_scoped_js_metadata_target(raw)
        } else {
            !raw.contains(&b'%') && raw[1..].iter().copied().all(valid_generic_path_byte)
        };
        if !valid {
            return None;
        }
        Some(Self {
            path: std::str::from_utf8(raw).ok()?,
        })
    }

    /// Returns the exact validated path bytes as UTF-8 text.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.path
    }
}

fn valid_generic_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'~' | b'+' | b'@' | b'-')
}

fn valid_scoped_js_metadata_target(raw: &[u8]) -> bool {
    let encoded_name = &raw[2..];
    let Some(separator) = encoded_name.windows(3).position(|bytes| bytes == b"%2f") else {
        return false;
    };
    let scope = &encoded_name[..separator];
    let name = &encoded_name[separator + 3..];
    raw.len().checked_sub(3).is_some_and(|decoded_len| {
        decoded_len <= MAX_JS_PACKAGE_BYTES
            && !name.windows(3).any(|bytes| bytes == b"%2f")
            && valid_js_component(scope)
            && valid_js_component(name)
    })
}

fn valid_js_component(component: &[u8]) -> bool {
    component.first().is_some_and(u8::is_ascii_lowercase)
        && component[1..].iter().copied().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'~' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde::Deserialize;

    use super::*;

    const FIXTURE: &str = include_str!("../../fixtures/dynamic-registry-v1/http/raw-targets.json");

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        cases: Vec<Case>,
        policy: Policy,
        schema: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Policy {
        allowed_generic_segment_ascii: String,
        allowed_percent_escape: String,
        maximum_request_target_bytes: usize,
        scoped_java_script_component_pattern: String,
        scoped_java_script_maximum_package_bytes: usize,
        target_form: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        expected: Expected,
        id: String,
        target_ascii: Option<String>,
        target_hex: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Expected {
        kind: ExpectedKind,
        path: Option<String>,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "kebab-case")]
    enum ExpectedKind {
        Canonical,
        Reject,
    }

    #[test]
    fn follows_shared_raw_target_vectors() {
        let fixture: Fixture = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(fixture.schema, "pkgre-raw-request-targets-v1");
        assert_eq!(
            fixture.policy.maximum_request_target_bytes,
            MAX_REQUEST_TARGET_BYTES
        );
        assert_eq!(
            fixture.policy.scoped_java_script_maximum_package_bytes,
            MAX_JS_PACKAGE_BYTES
        );
        assert_eq!(
            fixture.policy.allowed_generic_segment_ascii,
            "A-Z a-z 0-9 . _ ~ + @ -"
        );
        assert_eq!(
            fixture.policy.allowed_percent_escape,
            "one lowercase %2f in a canonical scoped JavaScript metadata path only"
        );
        assert_eq!(
            fixture.policy.scoped_java_script_component_pattern,
            "^[a-z][a-z0-9._~-]*$"
        );
        assert_eq!(
            fixture.policy.target_form,
            "origin-form path without query or fragment"
        );

        let mut ids = HashSet::new();
        for case in fixture.cases {
            assert!(ids.insert(case.id.clone()), "duplicate case {}", case.id);
            let raw = match (case.target_ascii, case.target_hex) {
                (Some(target), None) => target.into_bytes(),
                (None, Some(target)) => decode_hex(&target),
                _ => panic!("{} must define exactly one target encoding", case.id),
            };
            let actual = CanonicalRequestTarget::parse(&raw).map(CanonicalRequestTarget::as_str);
            match case.expected.kind {
                ExpectedKind::Canonical => {
                    assert_eq!(actual, case.expected.path.as_deref(), "case {}", case.id);
                }
                ExpectedKind::Reject => {
                    assert!(
                        case.expected.path.is_none(),
                        "reject case {} has a path",
                        case.id
                    );
                    assert_eq!(actual, None, "case {}", case.id);
                }
            }
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
}
