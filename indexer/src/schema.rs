//! Declarative catalog schema and loader.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::Deserialize;

/// Supported catalog schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Fully loaded catalog assembled from the files below one catalog directory.
#[derive(Debug)]
pub struct Catalog {
    /// Catalog directory.
    pub root: PathBuf,
    /// Registry topology and output configuration.
    pub registries: RegistriesFile,
    /// Package-name-to-registry routing table.
    pub homes: HomesFile,
    /// Exact approved package versions.
    pub approvals: Vec<Approval>,
}

/// Top-level `registries.toml` document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistriesFile {
    /// Schema version.
    pub schema: u32,
    /// Custom domain written to the Pages `CNAME` file.
    pub cname: String,
    /// Download URL template shared by all registries.
    pub download: String,
    /// Pinned Cargo version used to package first-party Git tags.
    #[serde(rename = "cargo-version")]
    pub cargo_version: Version,
    /// Registry declarations.
    pub registries: Vec<Registry>,
}

/// One sparse registry and its permitted dependency layers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Stable manifest alias and output directory name.
    pub name: String,
    /// Canonical sparse index URL, including `sparse+` and trailing slash.
    pub index: String,
    /// Registry homes to which packages in this registry may depend.
    #[serde(rename = "may-depend-on")]
    pub may_depend_on: Vec<String>,
}

/// Top-level `homes.toml` document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomesFile {
    /// Schema version.
    pub schema: u32,
    /// Explicit home for every package name referenced by a published row.
    pub homes: BTreeMap<String, String>,
}

/// Top-level approval file stored below `approvals/`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalsFile {
    schema: u32,
    registry: String,
    #[serde(default)]
    packages: Vec<ApprovalEntry>,
}

/// Exact approved package version before its containing registry is attached.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalEntry {
    name: String,
    version: Version,
    archive_sha256: String,
    index_record_sha256: String,
    yanked: bool,
    source: Source,
}

/// Exact approved package version.
#[derive(Debug)]
pub struct Approval {
    /// Registry home.
    pub registry: String,
    /// Cargo package name.
    pub name: String,
    /// Exact `SemVer`.
    pub version: Version,
    /// SHA-256 of the exact `.crate` archive.
    pub archive_sha256: String,
    /// SHA-256 of the exact un-routed index record bytes.
    pub index_record_sha256: String,
    /// Curator-owned yanked state.
    pub yanked: bool,
    /// Immutable origin evidence.
    pub source: Source,
    /// Approval file used for diagnostics.
    pub declared_in: PathBuf,
}

/// Immutable origin of an approved package archive and index metadata.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    /// Exact package bytes and metadata imported from crates.io.
    CratesIo {
        /// Catalog-relative snapshot of the exact upstream index record.
        index_record: PathBuf,
    },
    /// First-party package produced from an approved immutable Git tag and commit.
    GitTag {
        /// HTTPS repository URL.
        repository: String,
        /// Human-readable immutable release tag.
        tag: String,
        /// Full lowercase hexadecimal Git commit ID to which the tag must peel.
        commit: String,
        /// Cargo package selected from the repository workspace.
        package: String,
        /// Repository-relative package directory.
        subdir: PathBuf,
    },
}

impl Catalog {
    /// Loads every declarative input below `root` without applying semantic policy.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, malformed, unsupported, or non-file inputs.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let registries: RegistriesFile = load_toml(&root.join("registries.toml"))?;
        check_schema(registries.schema, &root.join("registries.toml"))?;
        let homes: HomesFile = load_toml(&root.join("homes.toml"))?;
        check_schema(homes.schema, &root.join("homes.toml"))?;

        let approvals_dir = root.join("approvals");
        let approvals_metadata = fs::symlink_metadata(&approvals_dir)
            .with_context(|| format!("inspect {}", approvals_dir.display()))?;
        if !approvals_metadata.file_type().is_dir() {
            bail!(
                "approval path is not a real directory: {}",
                approvals_dir.display()
            );
        }
        let mut paths = fs::read_dir(&approvals_dir)
            .with_context(|| format!("read {}", approvals_dir.display()))?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("read entries below {}", approvals_dir.display()))?;
        paths.sort();

        let mut approvals = Vec::new();
        for path in paths {
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                bail!("unexpected non-TOML approval input: {}", path.display());
            }
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect {}", path.display()))?;
            if !metadata.file_type().is_file() {
                bail!("approval input is not a regular file: {}", path.display());
            }
            let file: ApprovalsFile = load_toml(&path)?;
            check_schema(file.schema, &path)?;
            approvals.extend(file.packages.into_iter().map(|entry| Approval {
                registry: file.registry.clone(),
                name: entry.name,
                version: entry.version,
                archive_sha256: entry.archive_sha256,
                index_record_sha256: entry.index_record_sha256,
                yanked: entry.yanked,
                source: entry.source,
                declared_in: path.clone(),
            }));
        }

        Ok(Self {
            root: root.to_path_buf(),
            registries,
            homes,
            approvals,
        })
    }
}

fn load_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("catalog input is not a regular file: {}", path.display());
    }
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&contents).with_context(|| format!("parse {}", path.display()))
}

fn check_schema(actual: u32, path: &Path) -> Result<()> {
    if actual != SCHEMA_VERSION {
        bail!(
            "unsupported schema {actual} in {}; expected {SCHEMA_VERSION}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_rejects_unknown_fields() {
        let result = toml::from_str::<Source>(
            r#"
kind = "crates-io"
index_record = "upstream/demo.json"
surprise = true
"#,
        );
        assert!(result.is_err());
    }
}
