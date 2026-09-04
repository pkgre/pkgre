//! Strict TOML configuration for the snapshot serving origin.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use pkgre_rust::accepted_ref::{RepositoryConfig, derive_repository_identity};
use pkgre_rust::serve::DeliveryMode;

/// Exact command-line usage for the serving origin.
pub const USAGE: &str = "usage: pkgre-rust-serve <config.toml>";

/// Exact validated snapshot source selected by the service configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogSource {
    /// Fixed on-disk catalog tree built once at startup.
    Static(PathBuf),
    /// Accepted-ref watcher owns the snapshot lifecycle across reloads.
    Watcher(WatcherConfig),
}

/// Exact validated accepted-ref watcher configuration.
///
/// The repository identity is derived from the canonical origin and full ref at
/// parse time; the origin bytes are used exactly as configured with no
/// normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatcherConfig {
    /// Credential-free canonical origin accepted by Git (URL or local path).
    pub origin: String,
    /// Repository binding: canonical full ref plus its derived identity.
    pub repository: RepositoryConfig,
    /// Catalog directory path inside the commit tree.
    pub catalog_path: String,
    /// Bootstrap commit adopted only when no accepted record exists.
    pub bootstrap_commit: String,
    /// Directory holding the accepted-ref record and the Git mirror.
    pub state_path: PathBuf,
    /// Exact delay between remote polls.
    pub poll_interval: Duration,
}

/// Exact validated service configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Public registry listener address.
    pub public_bind: SocketAddr,
    /// Admin listener address.
    pub admin_bind: SocketAddr,
    /// Exact snapshot source: static catalog tree or accepted-ref watcher.
    pub source: CatalogSource,
    /// Exact archive delivery behavior for the built snapshot.
    pub delivery: DeliveryMode,
    /// Content-addressed archive store required by body delivery.
    pub archive_store: Option<PathBuf>,
    /// Maximum concurrently dispatched public registry requests.
    pub max_concurrency: NonZeroU32,
}

impl Config {
    /// Parses the complete configuration from exactly one config-file argument.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, extra, or malformed arguments and for any
    /// unreadable, invalid, or inconsistent configuration file.
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut arguments = arguments.into_iter();
        let path = match (arguments.next(), arguments.next()) {
            (Some(argument), None) => match argument.to_str() {
                Some("--help" | "-h") => bail!(USAGE),
                Some(flag) if flag.starts_with('-') => {
                    bail!("unknown argument {flag:?}\n{USAGE}")
                }
                _ => PathBuf::from(argument),
            },
            _ => bail!(USAGE),
        };
        Self::from_file(&path)
    }

    /// Loads and validates the configuration file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed and when any
    /// value, unknown field, or cross-field constraint fails validation.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read serve config {}", path.display()))?;
        parse_text(&text).with_context(|| format!("parse serve config {}", path.display()))
    }
}

/// The exact on-disk configuration document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    schema: u64,
    public: EndpointSection,
    admin: EndpointSection,
    registry: RegistrySection,
    limits: LimitsSection,
    watcher: Option<WatcherSection>,
}

/// One listener address section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSection {
    bind: SocketAddr,
}

/// Registry catalog and delivery section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySection {
    catalog: Option<PathBuf>,
    delivery: String,
    #[serde(rename = "archive-store")]
    archive_store: Option<PathBuf>,
}

/// Accepted-ref watcher section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatcherSection {
    origin: String,
    #[serde(rename = "full-ref")]
    full_ref: String,
    #[serde(rename = "catalog-path")]
    catalog_path: String,
    #[serde(rename = "bootstrap-commit")]
    bootstrap_commit: String,
    #[serde(rename = "state-path")]
    state_path: PathBuf,
    #[serde(rename = "poll-interval-secs")]
    poll_interval_secs: u64,
}

/// Dispatch resource bounds.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    #[serde(rename = "max-concurrency")]
    max_concurrency: NonZeroU32,
}

fn parse_text(text: &str) -> Result<Config> {
    let file: ConfigFile = toml::from_str(text)?;
    file.validate()
}

impl ConfigFile {
    fn validate(self) -> Result<Config> {
        ensure!(
            self.schema == 1,
            "unsupported config schema {}, expected 1",
            self.schema
        );
        let delivery = DeliveryMode::parse(&self.registry.delivery)?;
        match (delivery, &self.registry.archive_store) {
            (DeliveryMode::Body, None) => {
                bail!("registry.archive-store is required when delivery = \"body\"")
            }
            (DeliveryMode::Redirect, Some(store)) => bail!(
                "registry.archive-store {} is only valid when delivery = \"body\"",
                store.display()
            ),
            _ => {}
        }
        ensure!(
            self.public.bind != self.admin.bind,
            "public and admin bind addresses must differ"
        );
        let source = match (self.watcher, self.registry.catalog) {
            (Some(watcher), None) => CatalogSource::Watcher(watcher.validate()?),
            (None, Some(catalog)) => CatalogSource::Static(catalog),
            (Some(_), Some(catalog)) => bail!(
                "registry.catalog {} is only valid when no [watcher] section is present",
                catalog.display()
            ),
            (None, None) => {
                bail!("registry.catalog is required when no [watcher] section is present")
            }
        };
        Ok(Config {
            public_bind: self.public.bind,
            admin_bind: self.admin.bind,
            source,
            delivery,
            archive_store: self.registry.archive_store,
            max_concurrency: self.limits.max_concurrency,
        })
    }
}

impl WatcherSection {
    fn validate(self) -> Result<WatcherConfig> {
        ensure!(
            !self.origin.is_empty() && self.origin.trim() == self.origin,
            "watcher.origin must be nonempty with no leading or trailing whitespace"
        );
        ensure!(
            valid_bootstrap_commit(&self.bootstrap_commit),
            "watcher.bootstrap-commit must be 40 lowercase hexadecimal characters"
        );
        ensure!(
            self.poll_interval_secs >= 1,
            "watcher.poll-interval-secs must be at least 1"
        );
        validate_catalog_path(&self.catalog_path)?;
        let repository_identity =
            derive_repository_identity(self.origin.as_bytes(), self.full_ref.as_bytes())
                .context("derive watcher repository identity")?;
        let repository = RepositoryConfig::new(&self.full_ref, &repository_identity)
            .context("validate watcher repository binding")?;
        Ok(WatcherConfig {
            origin: self.origin,
            repository,
            catalog_path: self.catalog_path,
            bootstrap_commit: self.bootstrap_commit,
            state_path: self.state_path,
            poll_interval: Duration::from_secs(self.poll_interval_secs),
        })
    }
}

/// Rejects catalog paths that are empty, absolute, or contain non-plain components.
fn validate_catalog_path(value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "watcher.catalog-path must not be empty");
    let path = Path::new(value);
    ensure!(
        !path.is_absolute(),
        "watcher.catalog-path {value:?} must be relative"
    );
    for component in path.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "watcher.catalog-path {value:?} must contain only plain path components"
        );
    }
    Ok(())
}

fn valid_bootstrap_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIRECT_TEXT: &str = r#"
schema = 1

[public]
bind = "127.0.0.1:3000"

[admin]
bind = "127.0.0.1:3001"

[registry]
catalog = "/srv/pkgre/registry"
delivery = "redirect"

[limits]
max-concurrency = 64
"#;

    fn body_text() -> String {
        REDIRECT_TEXT
            .replace(
                "delivery = \"redirect\"",
                "delivery = \"body\"\narchive-store = \"/srv/pkgre/archives\"",
            )
            .replace("bind = \"127.0.0.1:3001\"", "bind = \"127.0.0.1:3002\"")
    }

    fn watcher_text() -> String {
        String::from(
            r#"
schema = 1

[public]
bind = "127.0.0.1:3000"

[admin]
bind = "127.0.0.1:3001"

[registry]
delivery = "redirect"

[limits]
max-concurrency = 64

[watcher]
origin = "https://github.com/pkgre/fixture-catalog.git"
full-ref = "refs/heads/main"
catalog-path = "registry"
bootstrap-commit = "1111111111111111111111111111111111111111"
state-path = "/srv/pkgre/state"
poll-interval-secs = 30
"#,
        )
    }

    #[test]
    fn redirect_configuration_parses_exactly() {
        let config = parse_text(REDIRECT_TEXT).unwrap();
        assert_eq!(config.public_bind, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.admin_bind, "127.0.0.1:3001".parse().unwrap());
        assert_eq!(
            config.source,
            CatalogSource::Static(PathBuf::from("/srv/pkgre/registry"))
        );
        assert_eq!(config.delivery, DeliveryMode::Redirect);
        assert_eq!(config.archive_store, None);
        assert_eq!(config.max_concurrency.get(), 64);
    }

    #[test]
    fn body_configuration_keeps_the_store() {
        let config = parse_text(&body_text()).unwrap();
        assert_eq!(config.delivery, DeliveryMode::Body);
        assert_eq!(
            config.archive_store,
            Some(PathBuf::from("/srv/pkgre/archives"))
        );
        assert_ne!(config.public_bind, config.admin_bind);
    }

    #[test]
    fn watcher_configuration_parses_exactly() {
        let config = parse_text(&watcher_text()).unwrap();
        let CatalogSource::Watcher(watcher) = &config.source else {
            panic!("watcher section must select watcher mode");
        };
        assert_eq!(
            watcher.origin,
            "https://github.com/pkgre/fixture-catalog.git"
        );
        assert_eq!(watcher.repository.full_ref(), "refs/heads/main");
        assert_eq!(
            watcher.repository.repository_identity(),
            derive_repository_identity(
                b"https://github.com/pkgre/fixture-catalog.git",
                b"refs/heads/main"
            )
            .unwrap()
        );
        assert_eq!(watcher.catalog_path, "registry");
        assert_eq!(watcher.bootstrap_commit, "1".repeat(40));
        assert_eq!(watcher.state_path, PathBuf::from("/srv/pkgre/state"));
        assert_eq!(watcher.poll_interval, Duration::from_secs(30));
    }

    #[test]
    fn watcher_and_static_catalog_are_exclusive() {
        let both = watcher_text().replace(
            "delivery = \"redirect\"",
            "delivery = \"redirect\"\ncatalog = \"/srv/pkgre/registry\"",
        );
        let error = parse_text(&both).unwrap_err();
        assert!(
            format!("{error:#}").contains("only valid when no [watcher] section is present"),
            "got: {error:#}"
        );
        let neither = REDIRECT_TEXT.replace("catalog = \"/srv/pkgre/registry\"\n", "");
        let error = parse_text(&neither).unwrap_err();
        assert!(
            format!("{error:#}").contains("registry.catalog is required"),
            "got: {error:#}"
        );
    }

    #[test]
    fn invalid_watcher_fields_fail_closed() {
        let cases: [(&str, String); 11] = [
            (
                "origin-empty",
                watcher_text().replace(
                    "origin = \"https://github.com/pkgre/fixture-catalog.git\"",
                    "origin = \"\"",
                ),
            ),
            (
                "origin-padded",
                watcher_text().replace(
                    "origin = \"https://github.com/pkgre/fixture-catalog.git\"",
                    "origin = \" https://github.com/pkgre/fixture-catalog.git\"",
                ),
            ),
            (
                "full-ref-shape",
                watcher_text().replace("full-ref = \"refs/heads/main\"", "full-ref = \"main\""),
            ),
            (
                "bootstrap-commit-short",
                watcher_text().replace(
                    "bootstrap-commit = \"1111111111111111111111111111111111111111\"",
                    "bootstrap-commit = \"111111111111111111111111111111111111111\"",
                ),
            ),
            (
                "bootstrap-commit-case",
                watcher_text().replace(
                    "bootstrap-commit = \"1111111111111111111111111111111111111111\"",
                    "bootstrap-commit = \"111111111111111111111111111111111111111A\"",
                ),
            ),
            (
                "bootstrap-commit-shape",
                watcher_text().replace(
                    "bootstrap-commit = \"1111111111111111111111111111111111111111\"",
                    "bootstrap-commit = \"11111111111111111111111111111111111111g1\"",
                ),
            ),
            (
                "poll-interval-zero",
                watcher_text().replace("poll-interval-secs = 30", "poll-interval-secs = 0"),
            ),
            (
                "catalog-path-absolute",
                watcher_text().replace(
                    "catalog-path = \"registry\"",
                    "catalog-path = \"/srv/registry\"",
                ),
            ),
            (
                "catalog-path-parent",
                watcher_text().replace(
                    "catalog-path = \"registry\"",
                    "catalog-path = \"../registry\"",
                ),
            ),
            (
                "catalog-path-empty",
                watcher_text().replace("catalog-path = \"registry\"", "catalog-path = \"\""),
            ),
            (
                "unknown-watcher-field",
                watcher_text().replace(
                    "poll-interval-secs = 30",
                    "poll-interval-secs = 30\ninterval = 30",
                ),
            ),
        ];
        for (label, text) in cases {
            assert!(parse_text(&text).is_err(), "{label} must fail");
        }
    }

    #[test]
    fn invalid_documents_fail_closed() {
        let cases: [(&str, String); 12] = [
            ("empty", String::new()),
            ("schema", REDIRECT_TEXT.replace("schema = 1", "schema = 2")),
            (
                "unknown-top-level",
                format!("{REDIRECT_TEXT}\nextra = true\n"),
            ),
            (
                "unknown-registry-field",
                REDIRECT_TEXT.replace(
                    "delivery = \"redirect\"",
                    "delivery = \"redirect\"\nupstream = \"https://example.invalid\"",
                ),
            ),
            (
                "unknown-limits-field",
                REDIRECT_TEXT.replace(
                    "max-concurrency = 64",
                    "max-concurrency = 64\nmin-concurrency = 1",
                ),
            ),
            (
                "unknown-public-field",
                REDIRECT_TEXT.replace(
                    "bind = \"127.0.0.1:3000\"",
                    "bind = \"127.0.0.1:3000\"\ntls = false",
                ),
            ),
            (
                "delivery-spelling",
                REDIRECT_TEXT.replace("delivery = \"redirect\"", "delivery = \"both\""),
            ),
            (
                "body-without-store",
                REDIRECT_TEXT.replace("delivery = \"redirect\"", "delivery = \"body\""),
            ),
            (
                "redirect-with-store",
                REDIRECT_TEXT.replace(
                    "delivery = \"redirect\"",
                    "delivery = \"redirect\"\narchive-store = \"/srv/pkgre/archives\"",
                ),
            ),
            (
                "zero-concurrency",
                REDIRECT_TEXT.replace("max-concurrency = 64", "max-concurrency = 0"),
            ),
            (
                "bind-collision",
                REDIRECT_TEXT.replace("bind = \"127.0.0.1:3001\"", "bind = \"127.0.0.1:3000\""),
            ),
            (
                "invalid-bind",
                REDIRECT_TEXT.replace("bind = \"127.0.0.1:3000\"", "bind = \"127.0.0.1\""),
            ),
        ];
        for (label, text) in cases {
            assert!(parse_text(&text).is_err(), "{label} must fail");
        }
    }

    #[test]
    fn duplicate_keys_fail_closed() {
        let text = format!("{REDIRECT_TEXT}\nschema = 1\n");
        assert!(parse_text(&text).is_err());
    }

    #[test]
    fn missing_limits_section_fails_closed() {
        let text = REDIRECT_TEXT.replace("\n[limits]\nmax-concurrency = 64\n", "\n");
        assert!(parse_text(&text).is_err());
    }

    #[test]
    fn argument_handling_is_strict() {
        assert!(Config::parse(Vec::new()).is_err());
        assert!(Config::parse([OsString::from("a"), OsString::from("b")]).is_err());
        let help = Config::parse([OsString::from("--help")]).unwrap_err();
        assert_eq!(help.to_string(), USAGE);
        let unknown = Config::parse([OsString::from("--listen")]).unwrap_err();
        assert_eq!(
            unknown.to_string(),
            format!("unknown argument \"--listen\"\n{USAGE}")
        );
    }

    #[test]
    fn file_errors_name_the_config_path() {
        let error = Config::from_file(Path::new("/nonexistent/pkgre-serve.toml")).unwrap_err();
        assert!(format!("{error:#}").contains("read serve config /nonexistent/pkgre-serve.toml"));
    }
}
