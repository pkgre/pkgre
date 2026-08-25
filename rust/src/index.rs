//! Cargo registry index record handling.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::schema::{HomesFile, PackageHome};

/// One dependency edge from a Cargo index record, normalized for stable comparison.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IndexDependency {
    /// Dependency alias used by the manifest.
    pub name: String,
    /// Actual package identity after Cargo rename handling.
    pub package: String,
    /// Semantic-version requirement.
    pub requirement: String,
    /// Enabled dependency features in canonical order.
    pub features: Vec<String>,
    /// Whether the edge is optional.
    pub optional: bool,
    /// Whether default features are enabled.
    pub default_features: bool,
    /// Optional target expression.
    pub target: Option<String>,
    /// Cargo dependency kind (`normal`, `dev`, or `build`).
    pub kind: String,
    /// Upstream registry marker before pkgre routing.
    pub registry: Option<String>,
}

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

    /// Returns the original crates.io publication timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when `pubtime` is absent or not a string. Parsing and UTC canonicalization are update-policy responsibilities because first-party rows intentionally omit this field.
    pub fn pubtime(&self) -> Result<&str> {
        string_field(&self.value, "pubtime")
    }

    /// Returns normalized dependency metadata in stable order.
    ///
    /// Renamed dependencies are keyed by their actual `package` identity rather than their local alias.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed dependency metadata.
    pub fn dependencies(&self) -> Result<Vec<IndexDependency>> {
        let dependencies = self
            .value
            .get("deps")
            .context("index record missing deps")?
            .as_array()
            .context("index record deps must be an array")?;
        let mut normalized = Vec::with_capacity(dependencies.len());
        for dependency in dependencies {
            let object = dependency
                .as_object()
                .context("index dependency must be an object")?;
            let name = string_field(object, "name")?.to_owned();
            let package = match object.get("package") {
                None | Some(Value::Null) => name.clone(),
                Some(Value::String(value)) => value.clone(),
                Some(_) => bail!("dependency package must be null or a string"),
            };
            let requirement = string_field(object, "req")?.to_owned();
            VersionReq::parse(&requirement)
                .with_context(|| format!("invalid dependency requirement {requirement:?}"))?;
            let mut features = string_array_field(object, "features")?
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            features.sort();
            ensure!(
                features.windows(2).all(|window| window[0] != window[1]),
                "index dependency repeats a feature"
            );
            let kind = match object.get("kind") {
                Some(Value::Null) | None => "normal".to_owned(),
                Some(Value::String(value))
                    if matches!(value.as_str(), "normal" | "dev" | "build") =>
                {
                    value.clone()
                }
                Some(_) => bail!("index dependency kind must be null, normal, dev, or build"),
            };
            normalized.push(IndexDependency {
                name,
                package,
                requirement,
                features,
                optional: bool_field(object, "optional")?,
                default_features: bool_field(object, "default_features")?,
                target: nullable_string_field(object, "target")?,
                kind,
                registry: nullable_string_field(object, "registry")?,
            });
        }
        normalized.sort();
        Ok(normalized)
    }

    /// Returns the package's native-link identifier when present.
    ///
    /// # Errors
    ///
    /// Returns an error when `links` is malformed.
    pub fn links(&self) -> Result<Option<&str>> {
        match self.value.get("links") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value)),
            Some(_) => bail!("index record links must be null or a string"),
        }
    }

    /// Returns whether this record has at least one build dependency.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed dependency metadata.
    pub fn has_build_dependencies(&self) -> Result<bool> {
        Ok(self
            .dependencies()?
            .iter()
            .any(|dependency| dependency.kind == "build"))
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
        homes: &BTreeMap<String, PackageHome>,
        registry_urls: &BTreeMap<String, String>,
    ) -> Result<BTreeSet<(String, PackageHome)>> {
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
            let registry = if home.registry == current_home {
                Value::Null
            } else {
                Value::String(
                    registry_urls
                        .get(&home.registry)
                        .with_context(|| {
                            format!(
                                "dependency {package:?} has unknown registry home {:?}",
                                home.registry
                            )
                        })?
                        .clone(),
                )
            };
            object.insert("registry".to_owned(), registry);
            routed.insert((package, home.clone()));
        }

        Ok(routed)
    }

    /// Rewrites every dependency source using registry-qualified package homes.
    ///
    /// The current registry wins when a normalized package name is declared there. Otherwise the
    /// dependency must have exactly one matching home across all other registries.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed dependency metadata, a missing or ambiguous home, or an unknown registry URL.
    pub fn route_dependencies_scoped(
        &mut self,
        current_registry: &str,
        homes: &HomesFile,
        registry_urls: &BTreeMap<String, String>,
    ) -> Result<BTreeSet<(String, PackageHome)>> {
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
            let home = homes.resolve_dependency(current_registry, &package)?;
            let registry = if home.registry == current_registry {
                Value::Null
            } else {
                Value::String(
                    registry_urls
                        .get(&home.registry)
                        .with_context(|| {
                            format!(
                                "dependency {package:?} has unknown registry home {:?}",
                                home.registry
                            )
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

fn nullable_string_field(object: &Map<String, Value>, name: &str) -> Result<Option<String>> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("index dependency {name} must be null or a string"),
    }
}

fn string_array_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<Vec<&'a str>> {
    let values = object
        .get(name)
        .with_context(|| format!("index dependency missing {name}"))?
        .as_array()
        .with_context(|| format!("index dependency {name} must be an array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .with_context(|| format!("index dependency {name} must contain only strings"))
        })
        .collect()
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
            (
                "demo".to_owned(),
                PackageHome {
                    registry: "one".to_owned(),
                    category: "one/general".parse().unwrap(),
                },
            ),
            (
                "real".to_owned(),
                PackageHome {
                    registry: "two".to_owned(),
                    category: "two/general".parse().unwrap(),
                },
            ),
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
        assert!(routed.contains(&(
            "real".to_owned(),
            PackageHome {
                registry: "two".to_owned(),
                category: "two/general".parse().unwrap(),
            }
        )));
        assert_eq!(
            record.value["deps"][0]["registry"],
            "sparse+https://example.test/two/"
        );
    }

    #[test]
    fn scoped_dependency_routing_prefers_the_source_registry_and_rejects_ambiguity() {
        let record = || {
            IndexRecord::parse(
                br#"{"name":"demo","vers":"1.0.0","deps":[{"name":"alias","package":"shared-name","registry":"untrusted"}],"cksum":"00","features":{},"yanked":false}"#,
            )
            .unwrap()
        };
        let homes = HomesFile {
            schema: crate::schema::SCHEMA_VERSION,
            homes: BTreeMap::from([
                (
                    crate::schema::PackageKey::new("main", "shared_name"),
                    PackageHome {
                        registry: "main".to_owned(),
                        category: "main/general".parse().unwrap(),
                    },
                ),
                (
                    crate::schema::PackageKey::new("staging", "shared-name"),
                    PackageHome {
                        registry: "staging".to_owned(),
                        category: "staging/general".parse().unwrap(),
                    },
                ),
            ]),
        };
        let urls = BTreeMap::from([
            ("main".to_owned(), "sparse+https://example.test/".to_owned()),
            (
                "staging".to_owned(),
                "sparse+https://example.test/staging/".to_owned(),
            ),
        ]);

        let mut local = record();
        let routed = local
            .route_dependencies_scoped("main", &homes, &urls)
            .unwrap();
        assert_eq!(local.value["deps"][0]["registry"], Value::Null);
        assert!(routed.contains(&(
            "shared-name".to_owned(),
            PackageHome {
                registry: "main".to_owned(),
                category: "main/general".parse().unwrap(),
            }
        )));

        let error = record()
            .route_dependencies_scoped("preview", &homes, &urls)
            .unwrap_err();
        assert!(format!("{error:#}").contains("ambiguous homes"));
    }

    #[test]
    fn dependency_metadata_is_normalized_by_actual_package_identity() {
        let record = IndexRecord::parse(
            br#"{"name":"demo","vers":"1.0.0","deps":[{"name":"z-alias","package":"real-z","req":"^1","features":["two","one"],"optional":false,"default_features":true,"target":null,"kind":"normal","registry":null},{"name":"a-build","req":"=2.0.0","features":[],"optional":true,"default_features":false,"target":"cfg(unix)","kind":"build","registry":"https://example.test/index"}],"cksum":"0000000000000000000000000000000000000000000000000000000000000000","features":{},"yanked":false,"pubtime":"2026-01-02T03:04:05Z","links":"demo"}"#,
        )
        .unwrap();

        assert_eq!(record.pubtime().unwrap(), "2026-01-02T03:04:05Z");
        assert_eq!(record.links().unwrap(), Some("demo"));
        assert!(record.has_build_dependencies().unwrap());
        let dependencies = record.dependencies().unwrap();
        assert_eq!(dependencies[0].name, "a-build");
        assert_eq!(dependencies[0].package, "a-build");
        assert_eq!(dependencies[0].kind, "build");
        assert_eq!(dependencies[1].name, "z-alias");
        assert_eq!(dependencies[1].package, "real-z");
        assert_eq!(dependencies[1].features, ["one", "two"]);
    }

    #[test]
    fn publication_and_dependency_metadata_fail_closed() {
        let missing_pubtime = IndexRecord::parse(
            br#"{"name":"demo","vers":"1.0.0","deps":[],"cksum":"0000000000000000000000000000000000000000000000000000000000000000","features":{},"yanked":false}"#,
        )
        .unwrap();
        assert!(missing_pubtime.pubtime().is_err());

        let malformed_package = IndexRecord::parse(
            br#"{"name":"demo","vers":"1.0.0","deps":[{"name":"alias","package":false,"req":"^1","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal"}],"cksum":"0000000000000000000000000000000000000000000000000000000000000000","features":{},"yanked":false}"#,
        )
        .unwrap();
        assert!(malformed_package.dependencies().is_err());
    }
}
