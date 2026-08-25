use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use pkgre_rust::download::{DownloadCatalog, DownloadSource};
use pkgre_rust::policy::{validate_package_name, validate_registry_alias, validate_sha256};
use semver::Version;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteKey {
    registry: String,
    name: String,
    version: Version,
    sha256: String,
}

impl RouteKey {
    /// Parses and validates one exact route identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless every component is in its canonical wire form.
    pub fn parse_canonical(
        registry: &str,
        name: &str,
        version_text: &str,
        sha256: &str,
    ) -> Result<Self> {
        validate_registry_alias(registry).context("invalid registry")?;
        validate_package_name(name).context("invalid package name")?;
        let version = Version::parse(version_text).context("invalid package version")?;
        ensure!(
            version.to_string() == version_text,
            "package version is not canonical"
        );
        validate_sha256(sha256).context("invalid package checksum")?;
        Ok(Self {
            registry: registry.to_owned(),
            name: name.to_owned(),
            version,
            sha256: sha256.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct RouteTable {
    routes: BTreeMap<RouteKey, DownloadSource>,
    crates_io_routes: usize,
    git_tag_routes: usize,
}

impl RouteTable {
    /// Parses and validates one canonical generated manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or duplicate route data.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let catalog = DownloadCatalog::parse_canonical(bytes)?;
        Self::from_catalog(catalog)
    }

    /// Builds a typed route table from one validated generated manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or duplicate route identities.
    pub fn from_catalog(catalog: DownloadCatalog) -> Result<Self> {
        catalog.validate()?;
        let mut routes = BTreeMap::new();
        let mut crates_io_routes = 0;
        let mut git_tag_routes = 0;
        for route in catalog.routes {
            let key = RouteKey::parse_canonical(
                &route.registry,
                &route.name,
                &route.version.to_string(),
                &route.sha256,
            )?;
            ensure!(
                routes.insert(key, route.source).is_none(),
                "duplicate route"
            );
            match route.source {
                DownloadSource::CratesIo => crates_io_routes += 1,
                DownloadSource::GitTag => git_tag_routes += 1,
            }
        }
        Ok(Self {
            routes,
            crates_io_routes,
            git_tag_routes,
        })
    }

    #[must_use]
    pub fn destination(&self, key: &RouteKey) -> Option<String> {
        self.routes.get(key).map(|source| match source {
            DownloadSource::CratesIo => format!(
                "https://static.crates.io/crates/{}/{}/download",
                key.name, key.version
            ),
            DownloadSource::GitTag => {
                format!("https://rust.pkg.re/crates/{}.crate", key.sha256)
            }
        })
    }

    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub fn crates_io_route_count(&self) -> usize {
        self.crates_io_routes
    }

    #[must_use]
    pub fn git_tag_route_count(&self) -> usize {
        self.git_tag_routes
    }
}

#[cfg(test)]
mod tests {
    use pkgre_rust::download::{DOWNLOAD_CATALOG_SCHEMA, DownloadRoute};

    use super::*;

    fn catalog(routes: Vec<DownloadRoute>) -> DownloadCatalog {
        DownloadCatalog {
            schema: DOWNLOAD_CATALOG_SCHEMA,
            routes,
        }
    }

    fn route(registry: &str, name: &str, source: DownloadSource) -> DownloadRoute {
        DownloadRoute {
            registry: registry.to_owned(),
            name: name.to_owned(),
            version: Version::parse("1.2.3").unwrap(),
            sha256: "01".repeat(32),
            source,
        }
    }

    #[test]
    fn exact_routes_derive_only_hardcoded_destinations() {
        let table = RouteTable::from_catalog(catalog(vec![
            route("main", "First_Party", DownloadSource::GitTag),
            route("main", "mirror-crate", DownloadSource::CratesIo),
            route("staging", "future-crate", DownloadSource::CratesIo),
        ]))
        .unwrap();
        assert_eq!(table.route_count(), 3);
        assert_eq!(table.crates_io_route_count(), 2);
        assert_eq!(table.git_tag_route_count(), 1);

        let mirror =
            RouteKey::parse_canonical("main", "mirror-crate", "1.2.3", &"01".repeat(32)).unwrap();
        assert_eq!(
            table.destination(&mirror).unwrap(),
            "https://static.crates.io/crates/mirror-crate/1.2.3/download"
        );
        let published =
            RouteKey::parse_canonical("main", "First_Party", "1.2.3", &"01".repeat(32)).unwrap();
        assert_eq!(
            table.destination(&published).unwrap(),
            format!("https://rust.pkg.re/crates/{}.crate", "01".repeat(32))
        );
        let future =
            RouteKey::parse_canonical("staging", "future-crate", "1.2.3", &"01".repeat(32))
                .unwrap();
        assert_eq!(
            table.destination(&future).unwrap(),
            "https://static.crates.io/crates/future-crate/1.2.3/download"
        );
        assert!(
            table
                .destination(
                    &RouteKey::parse_canonical("main", "first_party", "1.2.3", &"01".repeat(32))
                        .unwrap()
                )
                .is_none()
        );
    }

    #[test]
    fn route_keys_reject_noncanonical_components() {
        for (registry, name, version, sha256) in [
            ("Main", "crate", "1.2.3", "01".repeat(32)),
            ("main", "crate", "1.2.3+", "01".repeat(32)),
            ("main", "crate", "01.2.3", "01".repeat(32)),
            ("main", "Crate%2fother", "1.2.3", "01".repeat(32)),
            ("main", "crate", "1.2.3", "AB".repeat(32)),
        ] {
            assert!(
                RouteKey::parse_canonical(registry, name, version, &sha256).is_err(),
                "{registry}/{name}/{version}/{sha256}"
            );
        }
    }

    #[test]
    fn canonical_future_manifest_registry_is_supported() {
        let table = RouteTable::from_catalog(catalog(vec![route(
            "future",
            "crate",
            DownloadSource::CratesIo,
        )]))
        .unwrap();
        let key = RouteKey::parse_canonical("future", "crate", "1.2.3", &"01".repeat(32)).unwrap();
        assert_eq!(
            table.destination(&key).unwrap(),
            "https://static.crates.io/crates/crate/1.2.3/download"
        );
    }
}
