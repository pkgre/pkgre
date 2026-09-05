//! Content-addressed package object store and integrity verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use sha2::{Digest, Sha256};

use crate::download::DownloadCatalog;
use crate::index::IndexRecord;
use crate::policy::validate_sha256;
use crate::schema::{Approval, Catalog};

/// One materialized archive and un-routed source index row.
#[derive(Debug)]
pub struct Artifact {
    /// Registry home.
    pub registry: String,
    /// Cargo package name.
    pub name: String,
    /// Exact version.
    pub version: Version,
    /// Content-addressed `.crate`; removed packages intentionally lack this file.
    pub archive: PathBuf,
    /// Content-addressed un-routed source index row.
    pub index_record: PathBuf,
}

/// Loaded object paths keyed by exact package identity.
#[derive(Debug)]
pub struct ArtifactMap {
    entries: BTreeMap<(String, String, Version), Artifact>,
}

impl ArtifactMap {
    /// Derives all object paths from a loaded catalog and strictly verifies the object store.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, extra, non-regular, or hash-mismatched objects.
    pub fn load(catalog: &Catalog) -> Result<Self> {
        let result = Self::from_catalog(catalog)?;
        result.verify(catalog)?;
        Ok(result)
    }

    /// Loads an existing catalog while accepting the exact pre-migration all-active archive set.
    ///
    /// This update-only compatibility path still verifies every retained archive and rejects any
    /// set other than strict active Git-tag archives or the exact legacy all-active set.
    pub(crate) fn load_for_update(catalog: &Catalog) -> Result<(Self, bool)> {
        let result = Self::from_catalog(catalog)?;
        let strict_archives = retained_archive_hashes(catalog);
        let legacy_archives = legacy_archive_hashes(catalog);
        let archive_root = catalog.root.join("objects/crates");
        let actual_archives = read_object_names(&archive_root, "crate")?;
        ensure!(
            actual_archives == strict_archives || actual_archives == legacy_archives,
            "object set below {} differs from generated locks; expected the strict Git-only set or exact legacy all-active set",
            archive_root.display()
        );
        let uses_legacy_archives = actual_archives != strict_archives;
        let accepted_archives = if uses_legacy_archives {
            legacy_archives
        } else {
            strict_archives
        };
        result.verify_with_archives(catalog, &accepted_archives)?;
        Ok((result, uses_legacy_archives))
    }

    fn from_catalog(catalog: &Catalog) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for approval in &catalog.approvals {
            let key = (
                approval.registry.clone(),
                approval.name.clone(),
                approval.version.clone(),
            );
            ensure!(
                entries
                    .insert(
                        key,
                        Artifact {
                            registry: approval.registry.clone(),
                            name: approval.name.clone(),
                            version: approval.version.clone(),
                            archive: catalog
                                .root
                                .join("objects/crates")
                                .join(format!("{}.crate", approval.archive_sha256)),
                            index_record: catalog
                                .root
                                .join("objects/rows")
                                .join(format!("{}.json", approval.index_record_sha256)),
                        },
                    )
                    .is_none(),
                "duplicate artifact identity"
            );
        }
        Ok(Self { entries })
    }

    /// Finds one exact materialized object pair.
    #[must_use]
    pub fn get(&self, registry: &str, name: &str, version: &Version) -> Option<&Artifact> {
        self.entries
            .get(&(registry.to_owned(), name.to_owned(), version.clone()))
    }

    /// Verifies object hashes, row identities, and the exact active Git archive/retained-row sets.
    ///
    /// Mirror archives are not retained. Removed Git archives must be absent unless the same content
    /// hash is still used by another active Git package. Source rows are retained for every locked identity.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, extra, non-regular, or hash-mismatched objects.
    pub fn verify(&self, catalog: &Catalog) -> Result<()> {
        self.verify_with_archives(catalog, &retained_archive_hashes(catalog))
    }

    fn verify_with_archives(
        &self,
        catalog: &Catalog,
        retained_archives: &BTreeSet<String>,
    ) -> Result<()> {
        ensure!(
            self.entries.len() == catalog.approvals.len(),
            "object map has {} entries but catalog has {} locked packages",
            self.entries.len(),
            catalog.approvals.len()
        );
        let retained_rows = catalog
            .approvals
            .iter()
            .map(|approval| approval.index_record_sha256.clone())
            .collect::<BTreeSet<_>>();
        verify_object_names(
            &catalog.root.join("objects/crates"),
            "crate",
            retained_archives,
        )?;
        verify_object_names(&catalog.root.join("objects/rows"), "json", &retained_rows)?;

        for sha256 in retained_archives {
            let path = catalog
                .root
                .join("objects/crates")
                .join(format!("{sha256}.crate"));
            let actual = sha256_file(&path)?;
            ensure!(
                actual == *sha256,
                "archive hash mismatch for {}: expected {sha256}, got {actual}",
                path.display()
            );
        }

        for approval in &catalog.approvals {
            let key = (
                approval.registry.clone(),
                approval.name.clone(),
                approval.version.clone(),
            );
            let artifact = self.entries.get(&key).with_context(|| {
                format!(
                    "no object paths for {} {} in {}",
                    approval.name, approval.version, approval.registry
                )
            })?;
            verify_artifact(approval, artifact)?;
        }
        Ok(())
    }
}

/// Returns the exact archive-hash set that must exist in `objects/crates`.
///
/// Delivery-driven: an active approval's archive is retained iff its download
/// route is retained, which follows each registry's delivery declaration.
/// Removed packages are never expected in the object store.
pub(crate) fn retained_archive_hashes(catalog: &Catalog) -> BTreeSet<String> {
    let retained_identities = DownloadCatalog::retained_route_identities(catalog);
    catalog
        .approvals
        .iter()
        .filter(|approval| {
            !approval.is_removed()
                && retained_identities.contains(&(
                    approval.registry.clone(),
                    approval.name.clone(),
                    approval.version.clone(),
                ))
        })
        .map(|approval| approval.archive_sha256.clone())
        .collect()
}

fn legacy_archive_hashes(catalog: &Catalog) -> BTreeSet<String> {
    catalog
        .approvals
        .iter()
        .filter(|approval| !approval.is_removed())
        .map(|approval| approval.archive_sha256.clone())
        .collect()
}

fn verify_artifact(approval: &Approval, artifact: &Artifact) -> Result<()> {
    let record_bytes = fs::read(&artifact.index_record)
        .with_context(|| format!("read source index row {}", artifact.index_record.display()))?;
    let record_hash = sha256_bytes(&record_bytes);
    ensure!(
        record_hash == approval.index_record_sha256,
        "source-row hash mismatch for {} {}: expected {}, got {record_hash}",
        approval.name,
        approval.version,
        approval.index_record_sha256
    );
    let record = IndexRecord::parse(&record_bytes)
        .with_context(|| format!("parse source index row {}", artifact.index_record.display()))?;
    record.validate_structure().with_context(|| {
        format!(
            "validate source index row structure {}",
            artifact.index_record.display()
        )
    })?;
    ensure!(
        record.name()? == approval.name,
        "source index row name mismatch for {} {}",
        approval.name,
        approval.version
    );
    ensure!(
        record.version()? == approval.version,
        "source index row version mismatch for {} {}",
        approval.name,
        approval.version
    );
    ensure!(
        record.checksum()? == approval.archive_sha256,
        "source index row checksum mismatch for {} {}",
        approval.name,
        approval.version
    );
    Ok(())
}

fn verify_object_names(root: &Path, suffix: &str, expected: &BTreeSet<String>) -> Result<()> {
    let actual = read_object_names(root, suffix)?;
    ensure!(
        actual == *expected,
        "object set below {} differs from generated locks; missing={:?}, extra={:?}",
        root.display(),
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(expected).collect::<Vec<_>>()
    );
    Ok(())
}

fn read_object_names(root: &Path, suffix: &str) -> Result<BTreeSet<String>> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect object directory {}", root.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "object path is not a real directory: {}",
        root.display()
    );
    let mut actual = BTreeSet::new();
    for entry in
        fs::read_dir(root).with_context(|| format!("read object directory {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read entry below {}", root.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect object {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "object is not a regular file: {}",
            path.display()
        );
        let name = entry.file_name();
        let name = name
            .to_str()
            .with_context(|| format!("object filename is not valid UTF-8: {}", path.display()))?;
        let hash = name
            .strip_suffix(&format!(".{suffix}"))
            .with_context(|| format!("object has unexpected suffix: {}", path.display()))?;
        validate_sha256(hash)
            .with_context(|| format!("invalid object filename {}", path.display()))?;
        actual.insert(hash.to_owned());
    }
    Ok(actual)
}

/// Computes the lowercase hexadecimal SHA-256 of bytes.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Computes the lowercase hexadecimal SHA-256 of one regular file.
///
/// # Errors
///
/// Returns an error if the file cannot be inspected or read.
pub fn sha256_file(path: &Path) -> Result<String> {
    require_regular_file(path)?;
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect materialized file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "materialized path is not a regular file: {}",
        path.display()
    );
    Ok(())
}

/// Refuses to overwrite an existing path, including a symlink.
///
/// # Errors
///
/// Returns an error if metadata inspection fails for a reason other than absence, or if the path exists.
pub fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to overwrite existing path {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use semver::Version;

    use crate::schema::{
        Audience, PackageState, RegistriesFile, Registry, RegistryDelivery, Source,
    };
    use crate::update::time::UtcTimestamp;

    use super::*;

    #[test]
    fn byte_hash_matches_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn retained_archive_hashes_follow_delivery() {
        let git_tag = || Source::GitTag {
            repository: "https://example.com/repo".to_owned(),
            tag: "v1.0.0".to_owned(),
            tag_oid: "06".repeat(20),
            commit: "07".repeat(20),
            package: "first-party".to_owned(),
            subdir: PathBuf::from("."),
            cargo_version: Version::parse("1.95.0").unwrap(),
        };
        let mut approvals = vec![
            approval(
                "first-party",
                "1.0.0",
                &"01".repeat(32),
                PackageState::Active,
                git_tag(),
            ),
            approval(
                "alpha",
                "1.0.0",
                &"02".repeat(32),
                PackageState::Active,
                Source::CratesIo,
            ),
            approval(
                "gone",
                "1.0.0",
                &"03".repeat(32),
                PackageState::Removed,
                git_tag(),
            ),
        ];
        let undeclared = retained_archive_hashes(&catalog(None, approvals.clone()));
        assert_eq!(undeclared, BTreeSet::from(["01".repeat(32)]));

        approvals.push(approval(
            "beta",
            "1.0.0",
            &"04".repeat(32),
            PackageState::Active,
            Source::CratesIo,
        ));
        let declared =
            retained_archive_hashes(&catalog(Some(RegistryDelivery::Retained), approvals));
        assert_eq!(
            declared,
            BTreeSet::from(["01".repeat(32), "02".repeat(32), "04".repeat(32)])
        );
    }

    fn catalog(delivery: Option<RegistryDelivery>, approvals: Vec<Approval>) -> Catalog {
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
                    delivery,
                }],
            },
            categories: BTreeMap::new(),
            homes: crate::schema::HomesFile {
                schema: crate::schema::SCHEMA_VERSION,
                homes: BTreeMap::new(),
            },
            mirror_names: std::collections::BTreeSet::new(),
            publish_names: std::collections::BTreeSet::new(),
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
