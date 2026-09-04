//! Canonical immutable download-route catalog shared by the indexer and redirect service.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::policy::{validate_package_name, validate_registry_alias, validate_sha256};
use crate::schema::{Catalog, Source};

/// Generated download catalog filename in both catalog and rendered-site roots.
pub const DOWNLOAD_CATALOG_FILE: &str = "downloads.json";
/// Download catalog wire schema.
pub const DOWNLOAD_CATALOG_SCHEMA: u32 = 2;
/// Public immutable download router origin and versioned path prefix.
pub const DOWNLOAD_ROUTER_ORIGIN: &str = "https://dl.rust.pkg.re";
/// Maximum accepted canonical download catalog size.
pub const MAX_DOWNLOAD_CATALOG_BYTES: usize = 16 * 1024 * 1024;

/// Exact generated route table for every locked package identity, including removed ones.
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
    /// Exact immutable archive delivery.
    pub delivery: Delivery,
}

/// Exact immutable archive delivery for one locked package identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "delivery", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Delivery {
    /// Immutable redirect to the original byte-for-byte upstream archive.
    Redirect {
        /// Exact canonical immutable upstream archive URL.
        url: String,
    },
    /// Archive retained in this registry's content-addressed object store.
    Retained {
        /// Exact canonical object-store path, relative to the site root.
        path: String,
    },
}

impl Delivery {
    /// Returns whether this delivery retains an archive in this registry's object store.
    #[must_use]
    pub fn is_retained(&self) -> bool {
        matches!(self, Self::Retained { .. })
    }
}

impl DownloadCatalog {
    /// Derives the complete canonical route set from every generated-lock approval, including removed ones.
    #[must_use]
    pub fn from_catalog(catalog: &Catalog) -> Self {
        Self::from_routes(
            catalog
                .approvals
                .iter()
                .map(|approval| DownloadRoute {
                    registry: approval.registry.clone(),
                    name: approval.name.clone(),
                    version: approval.version.clone(),
                    sha256: approval.archive_sha256.clone(),
                    delivery: match approval.source {
                        Source::CratesIo => Delivery::Redirect {
                            url: download_url(
                                &approval.registry,
                                &approval.name,
                                &approval.version,
                                &approval.archive_sha256,
                            ),
                        },
                        Source::GitTag { .. } => Delivery::Retained {
                            path: retained_object_path(
                                &approval.registry,
                                &approval.archive_sha256,
                            ),
                        },
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
            match &route.delivery {
                Delivery::Redirect { url } => ensure!(
                    *url == download_url(
                        &route.registry,
                        &route.name,
                        &route.version,
                        &route.sha256
                    ),
                    "download redirect for {}/{}/{} is not the exact canonical router URL",
                    route.registry,
                    route.name,
                    route.version
                ),
                Delivery::Retained { path } => ensure!(
                    *path == retained_object_path(&route.registry, &route.sha256),
                    "download retained path for {}/{} is not the exact canonical object path",
                    route.registry,
                    route.sha256
                ),
            }
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

/// Returns the exact canonical immutable redirect URL for one locked identity.
#[must_use]
pub fn download_url(registry: &str, name: &str, version: &Version, sha256: &str) -> String {
    router_download_template(registry)
        .replace("{crate}", name)
        .replace("{version}", &version.to_string())
        .replace("{sha256-checksum}", sha256)
}

/// Returns the exact canonical retained object-store path for one locked identity.
#[must_use]
pub fn retained_object_path(registry: &str, sha256: &str) -> String {
    format!("{registry}/objects/crates/{sha256}.crate")
}

fn route_order(left: &DownloadRoute, right: &DownloadRoute) -> std::cmp::Ordering {
    (
        left.registry.as_str(),
        left.name.to_ascii_lowercase(),
        left.name.as_str(),
        &left.version,
        left.sha256.as_str(),
        &left.delivery,
    )
        .cmp(&(
            right.registry.as_str(),
            right.name.to_ascii_lowercase(),
            right.name.as_str(),
            &right.version,
            right.sha256.as_str(),
            &right.delivery,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, version: &str, sha256: &str, delivery: Delivery) -> DownloadRoute {
        DownloadRoute {
            registry: "universe".to_owned(),
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            sha256: sha256.to_owned(),
            delivery,
        }
    }

    fn redirect(name: &str, version: &str, sha256: &str) -> DownloadRoute {
        route(
            name,
            version,
            sha256,
            Delivery::Redirect {
                url: download_url("universe", name, &Version::parse(version).unwrap(), sha256),
            },
        )
    }

    fn retained(name: &str, version: &str, sha256: &str) -> DownloadRoute {
        route(
            name,
            version,
            sha256,
            Delivery::Retained {
                path: retained_object_path("universe", sha256),
            },
        )
    }

    #[test]
    fn canonical_round_trip_is_strict() {
        let catalog = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes: vec![redirect("serde", "1.0.229", &"01".repeat(32))],
        };
        let bytes = catalog.canonical_bytes().unwrap();
        assert_eq!(DownloadCatalog::parse_canonical(&bytes).unwrap(), catalog);

        let compact = serde_json::to_vec(&catalog).unwrap();
        assert!(DownloadCatalog::parse_canonical(&compact).is_err());
        let unknown = String::from_utf8(bytes)
            .unwrap()
            .replace("\"schema\": 2", "\"schema\": 2,\n  \"extra\": true");
        assert!(DownloadCatalog::parse_canonical(unknown.as_bytes()).is_err());
    }

    #[test]
    fn ordering_identity_and_fields_are_guarded() {
        let first = redirect("alpha", "1.0.0", &"01".repeat(32));
        let second = retained("beta", "1.0.0", &"02".repeat(32));
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
            routes: vec![first.clone(), retained("alpha", "1.0.0", &"03".repeat(32))],
        };
        let error = conflicting_checksum.validate().unwrap_err();
        assert!(format!("{error:#}").contains("duplicate download identity"));

        let mut invalid = redirect("alpha", "1.0.0", &"AB".repeat(32));
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
    fn schema_size_and_wire_delivery_are_strict() {
        let unsupported = DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA + 1,
            routes: Vec::new(),
        };
        assert!(unsupported.validate().is_err());
        assert!(
            DownloadCatalog::parse_canonical(&vec![b' '; MAX_DOWNLOAD_CATALOG_BYTES + 1]).is_err()
        );

        let unknown_delivery = format!(
            "{{\n  \"schema\": 2,\n  \"routes\": [\n    {{\n      \"registry\": \"universe\",\n      \"name\": \"alpha\",\n      \"version\": \"1.0.0\",\n      \"sha256\": \"{}\",\n      \"delivery\": \"arbitrary-url\"\n    }}\n  ]\n}}\n",
            "01".repeat(32)
        );
        assert!(
            DownloadCatalog::parse_canonical(unknown_delivery.as_bytes()).is_err(),
            "non-object delivery must be rejected"
        );

        let wrong_redirect = format!(
            "{{\n  \"schema\": 2,\n  \"routes\": [\n    {{\n      \"registry\": \"universe\",\n      \"name\": \"alpha\",\n      \"version\": \"1.0.0\",\n      \"sha256\": \"{}\",\n      \"delivery\": {{\n        \"redirect\": {{\n          \"url\": \"https://dl.rust.pkg.re/v1/universe/other/1.0.0/{}\"\n        }}\n      }}\n    }}\n  ]\n}}\n",
            "01".repeat(32),
            "01".repeat(32)
        );
        assert!(
            DownloadCatalog::parse_canonical(wrong_redirect.as_bytes()).is_err(),
            "non-canonical redirect URL must be rejected"
        );

        let wrong_retained = format!(
            "{{\n  \"schema\": 2,\n  \"routes\": [\n    {{\n      \"registry\": \"universe\",\n      \"name\": \"alpha\",\n      \"version\": \"1.0.0\",\n      \"sha256\": \"{}\",\n      \"delivery\": {{\n        \"retained\": {{\n          \"path\": \"universe/objects/crates/{}\",\n          \"sha256\": \"{}\"\n        }}\n      }}\n    }}\n  ]\n}}\n",
            "02".repeat(32),
            "02".repeat(32),
            "02".repeat(32)
        );
        assert!(
            DownloadCatalog::parse_canonical(wrong_retained.as_bytes()).is_err(),
            "non-canonical retained path must be rejected"
        );
    }

    #[test]
    fn router_template_is_registry_bound() {
        assert_eq!(
            router_download_template("pkgre"),
            "https://dl.rust.pkg.re/v1/pkgre/{crate}/{version}/{sha256-checksum}"
        );
    }
}
