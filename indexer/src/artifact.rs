//! Materialized package artifact map and integrity verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::index::IndexRecord;
use crate::policy::{validate_package_name, validate_relative_path};
use crate::schema::{Approval, Catalog, SCHEMA_VERSION, Source};

/// One materialized archive and un-routed index record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEntry {
    registry: String,
    name: String,
    version: Version,
    archive: PathBuf,
    index_record: PathBuf,
}

/// Top-level `artifacts.toml` document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactsFile {
    schema: u32,
    #[serde(default)]
    artifacts: Vec<ArtifactEntry>,
}

/// Validated materialized artifact.
#[derive(Debug)]
pub struct Artifact {
    /// Registry home.
    pub registry: String,
    /// Cargo package name.
    pub name: String,
    /// Exact version.
    pub version: Version,
    /// Absolute or invocation-relative path to the exact `.crate` file.
    pub archive: PathBuf,
    /// Absolute or invocation-relative path to the exact un-routed index record.
    pub index_record: PathBuf,
}

/// Loaded artifact map keyed by exact package identity.
#[derive(Debug)]
pub struct ArtifactMap {
    entries: BTreeMap<(String, String, Version), Artifact>,
}

impl ArtifactMap {
    /// Loads and structurally validates one artifact map.
    ///
    /// Paths are resolved relative to the map file's parent directory.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, unsafe paths, duplicate identities, or non-regular files.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read artifact map {}", path.display()))?;
        let file: ArtifactsFile = toml::from_str(&contents)
            .with_context(|| format!("parse artifact map {}", path.display()))?;
        ensure!(
            file.schema == SCHEMA_VERSION,
            "unsupported schema {} in {}; expected {SCHEMA_VERSION}",
            file.schema,
            path.display()
        );
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        let mut entries = BTreeMap::new();
        for entry in file.artifacts {
            validate_package_name(&entry.name)
                .with_context(|| format!("invalid artifact package name {:?}", entry.name))?;
            validate_relative_path(&entry.archive, false)
                .with_context(|| format!("invalid archive path {}", entry.archive.display()))?;
            validate_relative_path(&entry.index_record, false).with_context(|| {
                format!(
                    "invalid artifact index-record path {}",
                    entry.index_record.display()
                )
            })?;
            ensure!(
                entry.archive.extension().and_then(|value| value.to_str()) == Some("crate"),
                "artifact archive must have a .crate suffix: {}",
                entry.archive.display()
            );
            ensure!(
                entry
                    .index_record
                    .extension()
                    .and_then(|value| value.to_str())
                    == Some("json"),
                "artifact index record must have a .json suffix: {}",
                entry.index_record.display()
            );
            let archive = regular_file_beneath(root, &entry.archive)?;
            let index_record = regular_file_beneath(root, &entry.index_record)?;
            let key = (
                entry.registry.clone(),
                entry.name.clone(),
                entry.version.clone(),
            );
            ensure!(
                entries
                    .insert(
                        key,
                        Artifact {
                            registry: entry.registry,
                            name: entry.name,
                            version: entry.version,
                            archive,
                            index_record,
                        }
                    )
                    .is_none(),
                "duplicate artifact identity"
            );
        }
        Ok(Self { entries })
    }

    /// Finds one exact materialized artifact.
    #[must_use]
    pub fn get(&self, registry: &str, name: &str, version: &Version) -> Option<&Artifact> {
        self.entries
            .get(&(registry.to_owned(), name.to_owned(), version.clone()))
    }

    /// Verifies a one-to-one artifact mapping and all approval-bound hashes and metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or extra artifacts, non-regular files, hash mismatches, or index-record identity mismatches.
    pub fn verify(&self, catalog: &Catalog) -> Result<()> {
        ensure!(
            self.entries.len() == catalog.approvals.len(),
            "artifact map has {} entries but catalog has {} approvals",
            self.entries.len(),
            catalog.approvals.len()
        );
        let mut seen = BTreeSet::new();
        for approval in &catalog.approvals {
            let key = (
                approval.registry.clone(),
                approval.name.clone(),
                approval.version.clone(),
            );
            let artifact = self.entries.get(&key).with_context(|| {
                format!(
                    "no artifact for {} {} in {}",
                    approval.name, approval.version, approval.registry
                )
            })?;
            verify_artifact(approval, artifact, catalog)?;
            seen.insert(key);
        }
        for key in self.entries.keys() {
            ensure!(
                seen.contains(key),
                "artifact map contains an unapproved package"
            );
        }
        Ok(())
    }
}

fn verify_artifact(approval: &Approval, artifact: &Artifact, catalog: &Catalog) -> Result<()> {
    require_regular_file(&artifact.archive)?;
    require_regular_file(&artifact.index_record)?;
    let archive_hash = sha256_file(&artifact.archive)?;
    ensure!(
        archive_hash == approval.archive_sha256,
        "archive hash mismatch for {} {}: expected {}, got {archive_hash}",
        approval.name,
        approval.version,
        approval.archive_sha256
    );
    let record_bytes = fs::read(&artifact.index_record)
        .with_context(|| format!("read index record {}", artifact.index_record.display()))?;
    let record_hash = sha256_bytes(&record_bytes);
    ensure!(
        record_hash == approval.index_record_sha256,
        "index-record hash mismatch for {} {}: expected {}, got {record_hash}",
        approval.name,
        approval.version,
        approval.index_record_sha256
    );
    let record = IndexRecord::parse(&record_bytes)
        .with_context(|| format!("parse index record {}", artifact.index_record.display()))?;
    record.validate_structure().with_context(|| {
        format!(
            "validate index record structure {}",
            artifact.index_record.display()
        )
    })?;
    ensure!(
        record.name()? == approval.name,
        "index record name mismatch for {} {}",
        approval.name,
        approval.version
    );
    ensure!(
        record.version()? == approval.version,
        "index record version mismatch for {} {}",
        approval.name,
        approval.version
    );
    ensure!(
        record.checksum()? == approval.archive_sha256,
        "index record checksum mismatch for {} {}",
        approval.name,
        approval.version
    );

    if let Source::CratesIo { index_record } = &approval.source {
        let declared = regular_file_beneath(&catalog.root, index_record)?;
        let declared_hash = sha256_file(&declared).with_context(|| {
            format!(
                "verify declared crates.io index snapshot {}",
                declared.display()
            )
        })?;
        ensure!(
            declared_hash == record_hash,
            "crates.io approval for {} {} declares snapshot {}, but its bytes differ from the artifact map",
            approval.name,
            approval.version,
            declared.display()
        );
    }
    Ok(())
}

fn regular_file_beneath(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    ensure!(!components.is_empty(), "materialized path is empty");
    for (position, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect materialized path {}", current.display()))?;
        if position + 1 == components.len() {
            ensure!(
                metadata.file_type().is_file(),
                "materialized path is not a regular file: {}",
                current.display()
            );
        } else {
            ensure!(
                metadata.file_type().is_dir(),
                "materialized path parent is not a real directory: {}",
                current.display()
            );
        }
    }
    Ok(current)
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

    #[cfg(unix)]
    #[test]
    fn materialized_paths_reject_symlink_components() {
        let root =
            std::env::temp_dir().join(format!("pkgre-artifact-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real")).unwrap();
        fs::write(root.join("real/file.crate"), "crate").unwrap();
        std::os::unix::fs::symlink("real", root.join("linked")).unwrap();
        let error = regular_file_beneath(&root, Path::new("linked/file.crate")).unwrap_err();
        assert!(format!("{error:#}").contains("not a real directory"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_hash_matches_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
