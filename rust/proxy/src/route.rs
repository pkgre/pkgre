use semver::Version;

pub const MAX_REQUEST_TARGET_BYTES: usize = 1024;
const MAX_REGISTRY_ALIAS_BYTES: usize = 64;
const MAX_RUST_PACKAGE_NAME_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ecosystem {
    Rust,
    JavaScript,
}

impl Ecosystem {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::JavaScript => "js",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicHost {
    Rust,
    JavaScript,
}

impl PublicHost {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust.pkg.re",
            Self::JavaScript => "js.pkg.re",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DownloadRoute {
    Rust {
        registry: String,
        name: String,
        version: String,
        sha256: String,
    },
    JavaScript {
        registry: String,
        sha256: String,
    },
}

impl DownloadRoute {
    #[must_use]
    pub fn parse_canonical(target: &str) -> Option<Self> {
        if target.len() > MAX_REQUEST_TARGET_BYTES
            || !target.is_ascii()
            || target.contains(['?', '%', '#', '\\'])
        {
            return None;
        }

        let segments = target.split('/').collect::<Vec<_>>();
        match segments.as_slice() {
            ["", "v1", "js", registry, sha256]
                if valid_registry_alias(registry) && valid_sha256(sha256) =>
            {
                Some(Self::JavaScript {
                    registry: (*registry).to_owned(),
                    sha256: (*sha256).to_owned(),
                })
            }
            ["", "v1", registry, name, version, sha256]
                if valid_registry_alias(registry)
                    && valid_rust_package_name(name)
                    && valid_semver(version)
                    && valid_sha256(sha256) =>
            {
                Some(Self::Rust {
                    registry: (*registry).to_owned(),
                    name: (*name).to_owned(),
                    version: (*version).to_owned(),
                    sha256: (*sha256).to_owned(),
                })
            }
            _ => None,
        }
    }

    #[must_use]
    pub const fn ecosystem(&self) -> Ecosystem {
        match self {
            Self::Rust { .. } => Ecosystem::Rust,
            Self::JavaScript { .. } => Ecosystem::JavaScript,
        }
    }

    #[must_use]
    pub const fn public_host(&self) -> PublicHost {
        match self {
            Self::Rust { .. } => PublicHost::Rust,
            Self::JavaScript { .. } => PublicHost::JavaScript,
        }
    }

    #[must_use]
    pub fn canonical_path(&self) -> String {
        match self {
            Self::Rust {
                registry,
                name,
                version,
                sha256,
            } => format!("/v1/{registry}/{name}/{version}/{sha256}"),
            Self::JavaScript { registry, sha256 } => {
                format!("/v1/js/{registry}/{sha256}")
            }
        }
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        match self {
            Self::Rust { sha256, .. } | Self::JavaScript { sha256, .. } => sha256,
        }
    }

    #[must_use]
    pub fn rust_identity(&self) -> Option<(&str, &str)> {
        match self {
            Self::Rust { name, version, .. } => Some((name, version)),
            Self::JavaScript { .. } => None,
        }
    }
}

fn valid_registry_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REGISTRY_ALIAS_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn valid_rust_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUST_PACKAGE_NAME_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_semver(value: &str) -> bool {
    Version::parse(value).is_ok_and(|version| version.to_string() == value)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_only_the_two_canonical_route_forms() {
        let rust_path = format!("/v1/main/Serde_Json/1.0.0-beta.1/{A_SHA256}");
        let rust = DownloadRoute::parse_canonical(&rust_path).unwrap();
        assert_eq!(rust.ecosystem(), Ecosystem::Rust);
        assert_eq!(rust.public_host(), PublicHost::Rust);
        assert_eq!(rust.canonical_path(), rust_path);
        assert_eq!(rust.sha256(), A_SHA256);
        assert_eq!(rust.rust_identity(), Some(("Serde_Json", "1.0.0-beta.1")));

        let js_path = format!("/v1/js/main/{A_SHA256}");
        let js = DownloadRoute::parse_canonical(&js_path).unwrap();
        assert_eq!(js.ecosystem(), Ecosystem::JavaScript);
        assert_eq!(js.public_host(), PublicHost::JavaScript);
        assert_eq!(js.canonical_path(), js_path);
        assert_eq!(js.sha256(), A_SHA256);
        assert_eq!(js.rust_identity(), None);
    }

    #[test]
    fn rejects_ambiguous_or_noncanonical_targets() {
        let valid_rust = format!("/v1/main/crate/1.0.0/{A_SHA256}");
        let valid_js = format!("/v1/js/main/{A_SHA256}");
        let uppercase_sha = A_SHA256.to_ascii_uppercase();
        let long_registry = "a".repeat(MAX_REGISTRY_ALIAS_BYTES + 1);
        let long_target = format!("/v1/main/{}/1.0.0/{A_SHA256}", "a".repeat(950));
        for target in [
            "",
            "/",
            &format!("{valid_rust}?download=1"),
            &format!("{valid_rust}#fragment"),
            &valid_rust.replace("/crate/", "/crate%2fother/"),
            &valid_rust.replace("/crate/", "//crate/"),
            &valid_rust.replace("/crate/", "/./"),
            &valid_rust.replace("/crate/", "/../"),
            &valid_rust.replace("/crate/", "/crate\\other/"),
            &valid_rust.replace("/main/", "/Main/"),
            &valid_rust.replace("/crate/", "/-crate/"),
            &valid_rust.replace("/1.0.0/", "/01.0.0/"),
            &valid_rust.replace(A_SHA256, &uppercase_sha),
            &format!("/v1/{long_registry}/crate/1.0.0/{A_SHA256}"),
            &format!("{valid_rust}/extra"),
            &format!("/prefix{valid_rust}"),
            &valid_js.replace("/js/", "/JS/"),
            &format!("{valid_js}/extra"),
            &long_target,
            "/v1/main/craté/1.0.0/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(
                DownloadRoute::parse_canonical(target).is_none(),
                "accepted {target:?}"
            );
        }
    }
}
