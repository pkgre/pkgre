//! Cargo registry index record handling.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use semver::{Version, VersionReq};
use serde_json::{Map, Value};

/// Parsed Cargo registry index record that retains all upstream fields.
#[derive(Clone, Debug)]
pub struct IndexRecord {
    value: Map<String, Value>,
}

impl IndexRecord {
    /// Parses exactly one JSON object from an index snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not one valid Cargo index JSON object.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes).context("parse index record JSON")?;
        let Value::Object(value) = value else {
            bail!("index record must be a JSON object");
        };
        Ok(Self { value })
    }

    /// Returns the package name.
    ///
    /// # Errors
    ///
    /// Returns an error when the mandatory field is absent or not a string.
    pub fn name(&self) -> Result<&str> {
        string_field(&self.value, "name")
    }

    /// Returns the parsed package version.
    ///
    /// # Errors
    ///
    /// Returns an error when the mandatory field is absent or invalid.
    pub fn version(&self) -> Result<Version> {
        let value = string_field(&self.value, "vers")?;
        Version::parse(value).with_context(|| format!("invalid index version {value:?}"))
    }

    /// Returns the archive checksum.
    ///
    /// # Errors
    ///
    /// Returns an error when the mandatory field is absent or not a string.
    pub fn checksum(&self) -> Result<&str> {
        string_field(&self.value, "cksum")
    }

    /// Returns whether the upstream record is yanked.
    ///
    /// # Errors
    ///
    /// Returns an error when the mandatory field is absent or not a Boolean.
    pub fn yanked(&self) -> Result<bool> {
        self.value
            .get("yanked")
            .context("index record missing yanked")?
            .as_bool()
            .context("index record yanked must be a Boolean")
    }

    /// Validates the Cargo index fields consumed or preserved by the renderer.
    ///
    /// Unknown top-level fields remain permitted and are retained byte-for-byte until rendering, preserving forward-compatible crates.io metadata. Known fields fail closed on malformed values.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or malformed mandatory fields, invalid dependency metadata, invalid feature maps, or unsupported index schema versions.
    pub fn validate_structure(&self) -> Result<()> {
        let name = self.name()?;
        ensure_nonempty_string(name, "index record name")?;
        self.version()?;
        let checksum = self.checksum()?;
        ensure!(
            checksum.len() == 64
                && checksum
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "index record cksum must be lowercase hexadecimal SHA-256"
        );
        self.yanked()?;
        validate_feature_map(&self.value, "features")?;
        if self.value.contains_key("features2") {
            validate_feature_map(&self.value, "features2")?;
        }
        if let Some(value) = self.value.get("links") {
            ensure!(
                value.is_null() || value.as_str().is_some(),
                "index record links must be null or a string"
            );
        }
        if let Some(value) = self.value.get("rust_version") {
            ensure!(
                value.is_null() || value.as_str().is_some(),
                "index record rust_version must be null or a string"
            );
        }
        if let Some(value) = self.value.get("v") {
            ensure!(value.as_u64() == Some(2), "unsupported index schema v");
        }

        let dependencies = self
            .value
            .get("deps")
            .context("index record missing deps")?
            .as_array()
            .context("index record deps must be an array")?;
        for dependency in dependencies {
            let object = dependency
                .as_object()
                .context("index dependency must be an object")?;
            ensure_nonempty_string(string_field(object, "name")?, "dependency name")?;
            let requirement = string_field(object, "req")?;
            VersionReq::parse(requirement)
                .with_context(|| format!("invalid dependency requirement {requirement:?}"))?;
            string_array_field(object, "features")?;
            bool_field(object, "optional")?;
            bool_field(object, "default_features")?;
            optional_string_field(object, "target")?;
            let kind = object
                .get("kind")
                .context("index dependency missing kind")?;
            ensure!(
                matches!(kind, Value::Null)
                    || kind
                        .as_str()
                        .is_some_and(|value| matches!(value, "normal" | "dev" | "build")),
                "index dependency kind must be null, normal, dev, or build"
            );
            optional_string_field(object, "registry")?;
            optional_string_field(object, "package")?;
            if let Some(value) = object.get("artifact") {
                ensure!(
                    value.is_null() || value.as_str().is_some(),
                    "index dependency artifact must be null or a string"
                );
            }
            if let Some(value) = object.get("bindep_target") {
                ensure!(
                    value.is_null() || value.as_str().is_some(),
                    "index dependency bindep_target must be null or a string"
                );
            }
            if let Some(value) = object.get("lib") {
                ensure!(
                    value.is_null() || value.as_bool().is_some(),
                    "index dependency lib must be null or a Boolean"
                );
            }
        }
        Ok(())
    }

    /// Sets lifecycle-derived yank state.
    pub fn set_yanked(&mut self, yanked: bool) {
        self.value.insert("yanked".to_owned(), Value::Bool(yanked));
    }

    /// Rewrites every dependency source from explicit package homes.
    ///
    /// Returns each referenced package name and resulting registry home.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed dependency metadata or a missing home.
    pub fn route_dependencies(
        &mut self,
        current_home: &str,
        homes: &BTreeMap<String, String>,
        registry_urls: &BTreeMap<String, String>,
    ) -> Result<BTreeSet<(String, String)>> {
        let dependencies = self
            .value
            .get_mut("deps")
            .context("index record missing deps")?
            .as_array_mut()
            .context("index record deps must be an array")?;
        let mut routed = BTreeSet::new();

        for dependency in dependencies {
            let object = dependency
                .as_object_mut()
                .context("index dependency must be an object")?;
            let alias = string_field(object, "name")?.to_owned();
            let package = match object.get("package") {
                None | Some(Value::Null) => alias,
                Some(Value::String(value)) => value.clone(),
                Some(_) => bail!("dependency package must be null or a string"),
            };
            let home = homes
                .get(&package)
                .with_context(|| format!("dependency {package:?} has no declared home"))?;
            let registry = if home == current_home {
                Value::Null
            } else {
                Value::String(
                    registry_urls
                        .get(home)
                        .with_context(|| {
                            format!("dependency {package:?} has unknown home {home:?}")
                        })?
                        .clone(),
                )
            };
            object.insert("registry".to_owned(), registry);
            routed.insert((package, home.clone()));
        }

        Ok(routed)
    }

    /// Serializes one compact JSON line with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_json_line(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(&self.value).context("serialize index record")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Returns the canonical sparse-index path for a Cargo package name.
#[must_use]
pub fn index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{}", &lower[..1], lower),
        _ => format!("{}/{}/{}", &lower[..2], &lower[2..4], lower),
    }
}

fn bool_field(object: &Map<String, Value>, name: &str) -> Result<bool> {
    object
        .get(name)
        .with_context(|| format!("index dependency missing {name}"))?
        .as_bool()
        .with_context(|| format!("index dependency {name} must be a Boolean"))
}

fn optional_string_field(object: &Map<String, Value>, name: &str) -> Result<()> {
    let Some(value) = object.get(name) else {
        return Ok(());
    };
    ensure!(
        value.is_null() || value.as_str().is_some(),
        "index dependency {name} must be null or a string"
    );
    Ok(())
}

fn string_array_field(object: &Map<String, Value>, name: &str) -> Result<()> {
    let values = object
        .get(name)
        .with_context(|| format!("index dependency missing {name}"))?
        .as_array()
        .with_context(|| format!("index dependency {name} must be an array"))?;
    ensure!(
        values.iter().all(|value| value.as_str().is_some()),
        "index dependency {name} must contain only strings"
    );
    Ok(())
}

fn validate_feature_map(object: &Map<String, Value>, name: &str) -> Result<()> {
    let features = object
        .get(name)
        .with_context(|| format!("index record missing {name}"))?
        .as_object()
        .with_context(|| format!("index record {name} must be an object"))?;
    for (feature, values) in features {
        ensure_nonempty_string(feature, "feature name")?;
        let values = values
            .as_array()
            .with_context(|| format!("feature {feature:?} must contain an array"))?;
        ensure!(
            values.iter().all(|value| value.as_str().is_some()),
            "feature {feature:?} must contain only strings"
        );
    }
    Ok(())
}

fn ensure_nonempty_string(value: &str, description: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{description} must not be empty");
    Ok(())
}

fn string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    object
        .get(name)
        .with_context(|| format!("index record missing {name}"))?
        .as_str()
        .with_context(|| format!("index record {name} must be a string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_index_paths_match_specification() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("AbC"), "3/a/abc");
        assert_eq!(index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn known_index_fields_are_validated_strictly() {
        let valid = IndexRecord::parse(
            br#"{"name":"demo","vers":"1.0.0","deps":[{"name":"dep","req":"^1","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal"}],"cksum":"0000000000000000000000000000000000000000000000000000000000000000","features":{},"yanked":false}"#,
        )
        .unwrap();
        valid.validate_structure().unwrap();

        let malformed = IndexRecord::parse(
            br#"{"name":"demo","vers":"1.0.0","deps":[{"name":"dep","req":"^1","features":[],"optional":"no","default_features":true,"target":null,"kind":"normal"}],"cksum":"0000000000000000000000000000000000000000000000000000000000000000","features":{},"yanked":false}"#,
        )
        .unwrap();
        assert!(malformed.validate_structure().is_err());
    }

    #[test]
    fn dependency_alias_routes_by_package_name() {
        let mut record = IndexRecord::parse(
            br#"{"name":"demo","vers":"1.0.0","deps":[{"name":"alias","package":"real","registry":"untrusted"}],"cksum":"00","features":{},"yanked":false}"#,
        )
        .unwrap();
        let homes = BTreeMap::from([
            ("demo".to_owned(), "one".to_owned()),
            ("real".to_owned(), "two".to_owned()),
        ]);
        let urls = BTreeMap::from([
            (
                "one".to_owned(),
                "sparse+https://example.test/one/".to_owned(),
            ),
            (
                "two".to_owned(),
                "sparse+https://example.test/two/".to_owned(),
            ),
        ]);

        let routed = record.route_dependencies("one", &homes, &urls).unwrap();
        assert!(routed.contains(&("real".to_owned(), "two".to_owned())));
        assert_eq!(
            record.value["deps"][0]["registry"],
            "sparse+https://example.test/two/"
        );
    }
}
