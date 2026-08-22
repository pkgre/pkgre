//! Content-addressed package object store and integrity verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use sha2::{Digest, Sha256};

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
    /// Derives all object paths from a loaded catalog and verifies the object store.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, extra, non-regular, or hash-mismatched objects.
    pub fn load(catalog: &Catalog) -> Result<Self> {
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
        let result = Self { entries };
        result.verify(catalog)?;
        Ok(result)
    }

    /// Finds one exact materialized object pair.
    #[must_use]
    pub fn get(&self, registry: &str, name: &str, version: &Version) -> Option<&Artifact> {
        self.entries
            .get(&(registry.to_owned(), name.to_owned(), version.clone()))
    }

    /// Verifies object hashes, row identities, and the exact active archive/retained-row sets.
    ///
    /// Removed archives must be absent unless the same content hash is still used by another active package. Source rows are retained for every locked identity.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, extra, non-regular, or hash-mismatched objects.
    pub fn verify(&self, catalog: &Catalog) -> Result<()> {
        ensure!(
            self.entries.len() == catalog.approvals.len(),
            "object map has {} entries but catalog has {} locked packages",
            self.entries.len(),
            catalog.approvals.len()
        );
        let active_archives = catalog
            .approvals
            .iter()
            .filter(|approval| !approval.is_removed())
            .map(|approval| approval.archive_sha256.as_str())
            .collect::<BTreeSet<_>>();
        let retained_rows = catalog
            .approvals
            .iter()
            .map(|approval| approval.index_record_sha256.as_str())
            .collect::<BTreeSet<_>>();
        verify_object_names(
            &catalog.root.join("objects/crates"),
            "crate",
            &active_archives,
        )?;
        verify_object_names(&catalog.root.join("objects/rows"), "json", &retained_rows)?;

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
            verify_artifact(
                approval,
                artifact,
                active_archives.contains(approval.archive_sha256.as_str()),
            )?;
        }
        Ok(())
    }
}

fn verify_artifact(approval: &Approval, artifact: &Artifact, archive_retained: bool) -> Result<()> {
    if archive_retained {
        let archive_hash = sha256_file(&artifact.archive)?;
        ensure!(
            archive_hash == approval.archive_sha256,
            "archive hash mismatch for {} {}: expected {}, got {archive_hash}",
            approval.name,
            approval.version,
            approval.archive_sha256
        );
    }
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

fn verify_object_names(root: &Path, suffix: &str, expected: &BTreeSet<&str>) -> Result<()> {
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
    let expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "object set below {} differs from generated locks; missing={:?}, extra={:?}",
        root.display(),
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(&expected).collect::<Vec<_>>()
    );
    Ok(())
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
    use super::*;

    #[test]
    fn byte_hash_matches_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
