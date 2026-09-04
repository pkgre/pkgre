//! Retained-archive inventory and content-addressed import for body-mode closure.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::artifact::sha256_bytes;
use crate::download::DownloadCatalog;
use crate::schema::Catalog;

/// Archive store manifest inventory filename.
pub const ARCHIVE_INVENTORY_FILE: &str = "inventory.json";
/// Archive store inventory schema.
pub const ARCHIVE_INVENTORY_SCHEMA: u32 = 1;
/// Maximum accepted inventory size.
pub const MAX_INVENTORY_BYTES: usize = 16 * 1024 * 1024;

/// One retained archive object expected in an archive store.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct InventoryObject {
    /// Registry-qualified catalog identity.
    pub identity: String,
    /// Lowercase SHA-256 of the exact `.crate` archive.
    pub sha256: String,
}

/// Canonical inventory of every archive a full v5 serving body-mode requires.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArchiveInventory {
    /// Inventory schema version.
    pub schema: u32,
    /// Registry-qualified name of the catalog this inventory describes.
    pub catalog: String,
    /// Every retained route object, ordered by catalog route order.
    pub objects: Vec<InventoryObject>,
}

impl ArchiveInventory {
    /// Derives the retained-object inventory from a strictly loaded catalog and its downloads.
    ///
    /// Removed packages never require bodies: their routes are excluded from the inventory.
    #[must_use]
    pub fn from_catalog(catalog: &Catalog, downloads: &DownloadCatalog) -> Self {
        let active_identities: BTreeSet<(String, String, Version)> = catalog
            .approvals
            .iter()
            .filter(|approval| !approval.is_removed())
            .map(|approval| {
                (
                    approval.registry.clone(),
                    approval.name.clone(),
                    approval.version.clone(),
                )
            })
            .collect();
        let mut objects = Vec::new();
        for route in &downloads.routes {
            if route.delivery.is_retained()
                && active_identities.contains(&(
                    route.registry.clone(),
                    route.name.clone(),
                    route.version.clone(),
                ))
            {
                objects.push(InventoryObject {
                    identity: format!("{}/{}/{}", route.registry, route.name, route.version),
                    sha256: route.sha256.clone(),
                });
            }
        }
        Self {
            schema: ARCHIVE_INVENTORY_SCHEMA,
            catalog: catalog
                .registries
                .registries
                .iter()
                .map(|registry| registry.name.as_str())
                .collect::<Vec<_>>()
                .join(","),
            objects,
        }
    }

    /// Serializes canonical pretty JSON terminated by one newline.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self).context("serialize archive inventory")?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parses, validates, and requires exact canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, malformed, or noncanonical inventory.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_INVENTORY_BYTES,
            "archive inventory exceeds {MAX_INVENTORY_BYTES} bytes"
        );
        let inventory: Self = serde_json::from_slice(bytes).context("parse archive inventory")?;
        ensure!(
            inventory.schema == ARCHIVE_INVENTORY_SCHEMA,
            "archive inventory schema must be {ARCHIVE_INVENTORY_SCHEMA}"
        );
        ensure!(
            bytes == inventory.canonical_bytes()?,
            "archive inventory is not in canonical form"
        );
        Ok(inventory)
    }
}

/// Result of one `archive-import` run.
#[derive(Clone, Debug)]
pub struct ImportSummary {
    /// Objects copied into the catalog during this run.
    pub imported: usize,
    /// Objects already present and verified before this run.
    pub already_present: usize,
}

/// Copies every missing retained `.crate` from an archive store into the catalog and verifies all.
///
/// # Errors
///
/// Returns an error for a malformed store, unsafe paths, hash-mismatched objects, or a
/// catalog that fails full strict load, policy, and artifact verification after import.
pub fn archive_import(store: &Path, catalog_root: &Path) -> Result<ImportSummary> {
    let inventory_path = store.join(ARCHIVE_INVENTORY_FILE);
    let inventory_bytes = fs::read(&inventory_path)
        .with_context(|| format!("read archive inventory {}", inventory_path.display()))?;
    let inventory = ArchiveInventory::parse_canonical(&inventory_bytes)
        .with_context(|| format!("validate archive inventory {}", inventory_path.display()))?;

    let mut retained = Vec::new();
    for object in &inventory.objects {
        crate::policy::validate_sha256(&object.sha256).with_context(|| {
            format!(
                "inventory object {:?} is not a canonical SHA-256",
                object.sha256
            )
        })?;
        retained.push(object.sha256.clone());
    }
    ensure!(
        !retained.is_empty(),
        "archive inventory {} has no retained objects",
        inventory_path.display()
    );
    let mut retained_set = BTreeSet::new();
    for sha256 in &retained {
        ensure!(
            retained_set.insert(sha256.clone()),
            "archive inventory repeats object {sha256}"
        );
    }

    let catalog = Catalog::load(catalog_root)?;
    let expected = crate::artifact::retained_archive_hashes(&catalog);
    ensure!(
        expected == retained_set,
        "archive inventory retained set differs from catalog retained routes; missing={:?}, extra={:?}",
        expected.difference(&retained_set).collect::<Vec<_>>(),
        retained_set.difference(&expected).collect::<Vec<_>>()
    );

    let mut imported = 0;
    let mut already_present = 0;
    for sha256 in &retained {
        let source = store
            .join(format!("{sha256}.crate"))
            .canonicalize()
            .with_context(|| format!("inspect archive store object for {sha256}"))?;
        ensure!(
            source.is_absolute(),
            "archive store object path for {sha256} is not absolute"
        );
        ensure!(
            source.starts_with(store),
            "archive store object path for {sha256} escapes the store"
        );
        let bytes = fs::read(&source)
            .with_context(|| format!("read archive store object {}", source.display()))?;
        ensure!(
            sha256_bytes(&bytes) == *sha256,
            "archive store object {sha256} does not match its digest"
        );
        let destination = catalog_root
            .join("objects")
            .join("crates")
            .join(format!("{sha256}.crate"));
        if fs::symlink_metadata(&destination).is_ok() {
            let existing = fs::read(&destination)
                .with_context(|| format!("read existing object {}", destination.display()))?;
            ensure!(
                sha256_bytes(&existing) == *sha256,
                "existing object {} does not match its digest",
                destination.display()
            );
            already_present += 1;
            continue;
        }
        fs::write(&destination, &bytes)
            .with_context(|| format!("write object {}", destination.display()))?;
        imported += 1;
    }

    let catalog = Catalog::load(catalog_root)?;
    crate::policy::validate_catalog(&catalog)?;
    crate::artifact::ArtifactMap::load(&catalog)?;
    Ok(ImportSummary {
        imported,
        already_present,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use semver::Version;

    use crate::schema::{
        Approval, Audience, PackageState, RegistriesFile, Registry, RegistryDelivery, Source,
    };
    use crate::update::time::UtcTimestamp;

    use super::*;

    #[test]
    fn inventory_excludes_removed_retained_routes() {
        let catalog = catalog(vec![
            approval(
                "alpha",
                "1.0.0",
                &"01".repeat(32),
                PackageState::Active,
                Source::CratesIo,
            ),
            approval(
                "gone",
                "1.0.0",
                &"02".repeat(32),
                PackageState::Removed,
                Source::CratesIo,
            ),
            approval(
                "first-party",
                "1.0.0",
                &"03".repeat(32),
                PackageState::Active,
                git_tag(),
            ),
        ]);
        let downloads = DownloadCatalog::from_catalog(&catalog);
        let inventory = ArchiveInventory::from_catalog(&catalog, &downloads);
        assert_eq!(inventory.catalog, "main");
        assert_eq!(
            inventory
                .objects
                .iter()
                .map(|object| object.sha256.as_str())
                .collect::<Vec<_>>(),
            vec!["01".repeat(32), "03".repeat(32)]
        );
        assert_eq!(
            inventory.objects[0].identity,
            format!("main/alpha/{}", Version::parse("1.0.0").unwrap())
        );
    }

    fn git_tag() -> Source {
        Source::GitTag {
            repository: "https://example.com/repo".to_owned(),
            tag: "v1.0.0".to_owned(),
            tag_oid: "06".repeat(20),
            commit: "07".repeat(20),
            package: "first-party".to_owned(),
            subdir: PathBuf::from("."),
            cargo_version: Version::parse("1.95.0").unwrap(),
        }
    }

    fn catalog(approvals: Vec<Approval>) -> Catalog {
        Catalog {
            root: PathBuf::new(),
            registries: RegistriesFile {
                schema: crate::schema::SCHEMA_VERSION,
                cname: String::new(),
                cargo_version: Version::parse("1.95.0").unwrap(),
                registries: vec![Registry {
                    name: "main".to_owned(),
                    index: String::new(),
                    download: String::new(),
                    audience: Audience::Public,
                    cargo_version: Version::parse("1.95.0").unwrap(),
                    delivery: Some(RegistryDelivery::Retained),
                }],
            },
            categories: BTreeMap::new(),
            homes: crate::schema::HomesFile {
                schema: crate::schema::SCHEMA_VERSION,
                homes: BTreeMap::new(),
            },
            mirror_names: BTreeSet::new(),
            publish_names: BTreeSet::new(),
            approvals,
        }
    }

    fn approval(
        name: &str,
        version: &str,
        sha256: &str,
        state: PackageState,
        source: Source,
    ) -> Approval {
        Approval {
            registry: "main".to_owned(),
            category: "main/general".parse().unwrap(),
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            archive_sha256: sha256.to_owned(),
            index_record_sha256: "08".repeat(32),
            index_row_sha256: "09".repeat(32),
            admission_sha256: None,
            admitted_at: UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            state,
            source,
            declared_in: PathBuf::new(),
        }
    }
}
