//! Strict TOML configuration for the snapshot serving origin.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use pkgre_rust::serve::DeliveryMode;

/// Exact command-line usage for the serving origin.
pub const USAGE: &str = "usage: pkgre-rust-serve <config.toml>";

/// Exact validated service configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Public registry listener address.
    pub public_bind: SocketAddr,
    /// Admin listener address.
    pub admin_bind: SocketAddr,
    /// Root of the strictly validated registry catalog tree.
    pub catalog: PathBuf,
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
    catalog: PathBuf,
    delivery: String,
    #[serde(rename = "archive-store")]
    archive_store: Option<PathBuf>,
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
        Ok(Config {
            public_bind: self.public.bind,
            admin_bind: self.admin.bind,
            catalog: self.registry.catalog,
            delivery,
            archive_store: self.registry.archive_store,
            max_concurrency: self.limits.max_concurrency,
        })
    }
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

    #[test]
    fn redirect_configuration_parses_exactly() {
        let config = parse_text(REDIRECT_TEXT).unwrap();
        assert_eq!(config.public_bind, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.admin_bind, "127.0.0.1:3001".parse().unwrap());
        assert_eq!(config.catalog, PathBuf::from("/srv/pkgre/registry"));
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
