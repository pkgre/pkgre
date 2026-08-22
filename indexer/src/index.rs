//! Cargo registry index record handling.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use semver::Version;
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

    /// Replaces curator-owned yank state.
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
