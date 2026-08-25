//! Canonical immutable download-route catalog shared by the indexer and redirect service.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::policy::{validate_package_name, validate_registry_alias, validate_sha256};
use crate::schema::{Catalog, PackageState, Source};

/// Generated download catalog filename in both catalog and rendered-site roots.
pub const DOWNLOAD_CATALOG_FILE: &str = "downloads.json";
/// Download catalog wire schema.
pub const DOWNLOAD_CATALOG_SCHEMA: u32 = 1;
/// Public immutable download router origin and versioned path prefix.
pub const DOWNLOAD_ROUTER_ORIGIN: &str = "https://dl.rust.pkg.re";
/// Maximum accepted canonical download catalog size.
pub const MAX_DOWNLOAD_CATALOG_BYTES: usize = 16 * 1024 * 1024;

/// Exact generated route table for every active package identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadCatalog {
    /// Wire schema version.
    pub schema: u32,
    /// Canonically ordered immutable routes.
    pub routes: Vec<DownloadRoute>,
}

/// One exact immutable package route.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRoute {
    /// Cargo registry alias.
    pub registry: String,
    /// Exact Cargo package name.
    pub name: String,
    /// Canonical Cargo package version.
    pub version: Version,
    /// Lowercase SHA-256 from the curated index row.
    pub sha256: String,
    /// Locked archive origin class.
    pub source: DownloadSource,
}

/// Upstream selected for one immutable archive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadSource {
    /// Byte-for-byte crates.io archive.
    CratesIo,
    /// Archive produced from and retained for an immutable Git tag.
    GitTag,
}

impl DownloadCatalog {
    /// Derives the complete canonical route set from active generated-lock approvals.
    #[must_use]
    pub fn from_catalog(catalog: &Catalog) -> Self {
        Self::from_routes(
            catalog
                .approvals
                .iter()
                .filter(|approval| approval.state == PackageState::Active)
                .map(|approval| DownloadRoute {
                    registry: approval.registry.clone(),
                    name: approval.name.clone(),
                    version: approval.version.clone(),
                    sha256: approval.archive_sha256.clone(),
                    source: match approval.source {
                        Source::CratesIo => DownloadSource::CratesIo,
                        Source::GitTag { .. } => DownloadSource::GitTag,
                    },
                })
                .collect(),
        )
    }

    pub(crate) fn from_routes(mut routes: Vec<DownloadRoute>) -> Self {
        routes.sort_by(route_order);
        Self {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes,
        }
    }

    /// Parses, fully validates, and requires exact canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, malformed, unsupported, noncanonical, duplicate, or invalid route catalog.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DOWNLOAD_CATALOG_BYTES,
            "download catalog exceeds {MAX_DOWNLOAD_CATALOG_BYTES} bytes"
        );
        let catalog: Self =
            serde_json::from_slice(bytes).context("parse canonical download catalog JSON")?;
        catalog.validate()?;
        ensure!(
            bytes == catalog.canonical_bytes()?,
            "download catalog is not in canonical form"
        );
        Ok(catalog)
    }

    /// Validates the schema, every route field, ordering, and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error for any unsupported or noncanonical route-table value.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == DOWNLOAD_CATALOG_SCHEMA,
            "download catalog schema must be {DOWNLOAD_CATALOG_SCHEMA}"
        );
        let mut identities = BTreeSet::new();
        let mut previous = None;
        for route in &self.routes {
            validate_registry_alias(&route.registry)
                .with_context(|| format!("invalid download registry {:?}", route.registry))?;
            validate_package_name(&route.name)
                .with_context(|| format!("invalid download package name {:?}", route.name))?;
            validate_sha256(&route.sha256).with_context(|| {
                format!(
                    "invalid download checksum for {} {}",
                    route.name, route.version
                )
            })?;
            if let Some(prior) = previous {
                ensure!(
                    route_order(prior, route).is_lt(),
                    "download routes are not in strict canonical order"
                );
            }
            let identity = (route.registry.as_str(), route.name.as_str(), &route.version);
            ensure!(
                identities.insert(identity),
                "duplicate download identity for {}/{}/{}",
                route.registry,
                route.name,
                route.version
            );
            previous = Some(route);
        }
        Ok(())
    }

    /// Serializes canonical pretty JSON terminated by one newline.
    ///
    /// # Errors
    ///
    /// Returns an error when the route table is invalid or serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self).context("serialize download catalog")?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Loads a required regular canonical catalog file from a managed catalog root.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is missing, unsafe, unreadable, or invalid.
    pub fn load_from_root(root: &Path) -> Result<Self> {
        let path = root.join(DOWNLOAD_CATALOG_FILE);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect generated download catalog {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "generated download catalog is not a regular file: {}",
            path.display()
        );
        ensure!(
            metadata.len() <= MAX_DOWNLOAD_CATALOG_BYTES as u64,
            "download catalog exceeds {} bytes: {}",
            MAX_DOWNLOAD_CATALOG_BYTES,
            path.display()
        );
        let bytes = fs::read(&path)
            .with_context(|| format!("read generated download catalog {}", path.display()))?;
        Self::parse_canonical(&bytes)
            .with_context(|| format!("validate generated download catalog {}", path.display()))
    }

    /// Requires this route table to equal the exact active generated-lock projection.
    ///
    /// # Errors
    ///
    /// Returns an error when any route is missing, extra, or changed.
    pub fn validate_against_catalog(&self, catalog: &Catalog) -> Result<()> {
        ensure!(
            self == &Self::from_catalog(catalog),
            "generated download catalog differs from active generated locks; run `pkgre-rust lock`"
        );
        Ok(())
    }
}

/// Returns the exact Cargo `dl` template for one registry through the immutable router.
#[must_use]
pub fn router_download_template(registry: &str) -> String {
    format!("{DOWNLOAD_ROUTER_ORIGIN}/v1/{registry}/{{crate}}/{{version}}/{{sha256-checksum}}")
}

fn route_order(left: &DownloadRoute, right: &DownloadRoute) -> std::cmp::Ordering {
    (
        left.registry.as_str(),
        left.name.to_ascii_lowercase(),
        left.name.as_str(),
        &left.version,
        left.sha256.as_str(),
        left.source,
    )
        .cmp(&(
            right.registry.as_str(),
            right.name.to_ascii_lowercase(),
            right.name.as_str(),
            &right.version,
            right.sha256.as_str(),
            right.source,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, version: &str, sha256: &str, source: DownloadSource) -> DownloadRoute {
        DownloadRoute {
            registry: "universe".to_owned(),
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            sha256: sha256.to_owned(),
            source,
        }
    }

    #[test]
    fn canonical_round_trip_is_strict() {
        let catalog = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![route(
                "serde",
                "1.0.229",
                &"01".repeat(32),
                DownloadSource::CratesIo,
            )],
        };
        let bytes = catalog.canonical_bytes().unwrap();
        assert_eq!(DownloadCatalog::parse_canonical(&bytes).unwrap(), catalog);

        let compact = serde_json::to_vec(&catalog).unwrap();
        assert!(DownloadCatalog::parse_canonical(&compact).is_err());
        let unknown = String::from_utf8(bytes)
            .unwrap()
            .replace("\"schema\": 1", "\"schema\": 1,\n  \"extra\": true");
        assert!(DownloadCatalog::parse_canonical(unknown.as_bytes()).is_err());
    }

    #[test]
    fn ordering_identity_and_fields_are_guarded() {
        let first = route("alpha", "1.0.0", &"01".repeat(32), DownloadSource::CratesIo);
        let second = route("beta", "1.0.0", &"02".repeat(32), DownloadSource::GitTag);
        let reversed = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![second, first.clone()],
        };
        assert!(reversed.validate().is_err());

        let duplicate = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![first.clone(), first.clone()],
        };
        assert!(duplicate.validate().is_err());

        let conflicting_checksum = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![
                first.clone(),
                route("alpha", "1.0.0", &"03".repeat(32), DownloadSource::GitTag),
            ],
        };
        let error = conflicting_checksum.validate().unwrap_err();
        assert!(format!("{error:#}").contains("duplicate download identity"));

        let mut invalid = route("alpha", "1.0.0", &"AB".repeat(32), DownloadSource::CratesIo);
        let catalog = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![invalid.clone()],
        };
        assert!(catalog.validate().is_err());
        invalid.registry = "Universe".to_owned();
        let catalog = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![invalid],
        };
        assert!(catalog.validate().is_err());
    }

    #[test]
    fn schema_size_and_wire_source_are_strict() {
        let unsupported = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA + 1,
            routes: Vec::new(),
        };
        assert!(unsupported.validate().is_err());
        assert!(
            DownloadCatalog::parse_canonical(&vec![b' '; MAX_DOWNLOAD_CATALOG_BYTES + 1]).is_err()
        );

        let unknown_source = format!(
            "{{\n  \"schema\": 1,\n  \"routes\": [\n    {{\n      \"registry\": \"universe\",\n      \"name\": \"alpha\",\n      \"version\": \"1.0.0\",\n      \"sha256\": \"{}\",\n      \"source\": \"arbitrary-url\"\n    }}\n  ]\n}}\n",
            "01".repeat(32)
        );
        assert!(DownloadCatalog::parse_canonical(unknown_source.as_bytes()).is_err());
    }

    #[test]
    fn router_template_is_registry_bound() {
        assert_eq!(
            router_download_template("pkgre"),
            "https://dl.rust.pkg.re/v1/pkgre/{crate}/{version}/{sha256-checksum}"
        );
    }
}
