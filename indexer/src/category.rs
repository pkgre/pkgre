//! Validated fully qualified category identities.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Stable category identity in `<registry>/<local-category>` form.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CategoryId {
    registry: String,
    local: String,
}

impl CategoryId {
    /// Constructs a category identity from separately validated components.
    ///
    /// # Errors
    ///
    /// Returns an error unless the registry is a canonical lowercase alias and the local category is lowercase kebab-case.
    pub fn new(registry: impl Into<String>, local: impl Into<String>) -> Result<Self> {
        let registry = registry.into();
        let local = local.into();
        validate_registry(&registry)?;
        validate_local(&local)?;
        Ok(Self { registry, local })
    }

    /// Returns the registry component.
    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// Returns the registry-local category component.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }
}

/// Maps one canonical schema-2 package home to its schema-3 category.
///
/// # Errors
///
/// Returns an error for an unexpected schema-2 registry or first-party package name.
pub(crate) fn category_for_v2_home(registry: &str, package: &str) -> Result<CategoryId> {
    let local = match registry {
        "matrix" => "matrix",
        "pkgre" => {
            ensure!(
                package == "pkgre-indexer",
                "unexpected schema-2 pkgre package {package:?}"
            );
            "tooling"
        }
        "core" => match package {
            "agent-client-protocol"
            | "agent-client-protocol-derive"
            | "agent-client-protocol-schema" => "acp",
            "notify" | "notify-types" => "filesystem",
            "rmcp" | "rmcp-macros" => "mcp",
            "eventsource-stream" | "sse-stream" => "sse",
            "atty" | "portable-pty" => "terminal",
            "serde_yaml" | "serde_yaml_ng" => "yaml",
            _ => "general",
        },
        _ => anyhow::bail!("unexpected schema-2 registry {registry:?}"),
    };
    let target_registry = if registry == "pkgre" {
        "pkgre"
    } else {
        "universe"
    };
    CategoryId::new(target_registry, local)
}

impl fmt::Display for CategoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.registry, self.local)
    }
}

impl FromStr for CategoryId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let mut components = value.split('/');
        let registry = components.next().unwrap_or_default();
        let local = components.next().unwrap_or_default();
        ensure!(
            components.next().is_none() && !registry.is_empty() && !local.is_empty(),
            "category ID {value:?} must contain exactly one `/` as `<registry>/<category>`"
        );
        Self::new(registry, local)
    }
}

impl Serialize for CategoryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CategoryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn validate_registry(value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "category registry is empty");
    ensure!(value.len() <= 64, "category registry exceeds 64 bytes");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "category registry {value:?} must be lowercase ASCII kebab-case"
    );
    ensure!(
        value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "category registry {value:?} must start and end with an ASCII alphanumeric character"
    );
    Ok(())
}

fn validate_local(value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "local category name is empty");
    ensure!(value.len() <= 64, "local category name exceeds 64 bytes");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "local category name {value:?} must be lowercase ASCII kebab-case"
    );
    ensure!(
        value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "local category name {value:?} must start and end with an ASCII alphanumeric character"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_category_round_trips_through_serde() {
        let category = CategoryId::new("universe", "file-system").unwrap();
        assert_eq!(category.to_string(), "universe/file-system");
        let encoded = serde_json::to_string(&category).unwrap();
        assert_eq!(encoded, "\"universe/file-system\"");
        assert_eq!(
            serde_json::from_str::<CategoryId>(&encoded).unwrap(),
            category
        );
    }

    #[test]
    fn schema_two_homes_have_exact_schema_three_categories() {
        assert_eq!(
            category_for_v2_home("core", "serde").unwrap().to_string(),
            "universe/general"
        );
        assert_eq!(
            category_for_v2_home("core", "rmcp").unwrap().to_string(),
            "universe/mcp"
        );
        assert_eq!(
            category_for_v2_home("matrix", "matrix-sdk")
                .unwrap()
                .to_string(),
            "universe/matrix"
        );
        assert_eq!(
            category_for_v2_home("pkgre", "pkgre-indexer")
                .unwrap()
                .to_string(),
            "pkgre/tooling"
        );
        assert!(category_for_v2_home("pkgre", "other").is_err());
    }

    #[test]
    fn malformed_categories_are_rejected() {
        for value in [
            "general",
            "universe/",
            "/general",
            "universe/general/extra",
            "Universe/general",
            "universe/serde_yaml",
            "universe/-general",
            "universe/general-",
            "universe/general.main",
        ] {
            assert!(value.parse::<CategoryId>().is_err(), "accepted {value:?}");
        }
    }
}
