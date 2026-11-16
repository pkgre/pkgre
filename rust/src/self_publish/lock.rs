//! Canonical generated `self-publish/crates-io.lock`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::name;
use crate::policy::{validate_git_tag, validate_https_repository, validate_sha256};

/// Supported `crates-io.lock` schema.
pub(crate) const CRATES_IO_LOCK_SCHEMA: u32 = 1;

/// Length of a full Git commit object ID, in hexadecimal characters.
const COMMIT_LENGTH: usize = 40;

/// The generated record of everything released to crates.io.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CratesIoLock {
    /// Wire schema.
    pub(crate) schema: u32,
    /// One entry per crate version released to crates.io, in canonical order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) packages: Vec<CratesIoPackage>,
}

/// One crate version released to crates.io.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct CratesIoPackage {
    /// Cargo package name in the `pkgre` registry.
    pub(crate) name: String,
    /// Exact Cargo version.
    pub(crate) version: Version,
    /// crates.io name of this exact version.
    pub(crate) crates_io_name: String,
    /// SHA-256 of the crates.io `.crate` archive.
    pub(crate) crate_sha256: String,
    /// SHA-256 of the identity's archive in `registry/main.lock`.
    pub(crate) pkgre_crate_sha256: String,
    /// Credential-free HTTPS Git repository of the release.
    pub(crate) git: String,
    /// Immutable release tag.
    pub(crate) tag: String,
    /// Full peeled commit object ID of the release tag.
    pub(crate) commit: String,
    /// Exact Cargo version that packaged the archive.
    pub(crate) cargo_version: Version,
}

impl CratesIoLock {
    /// Loads one regular canonical `crates-io.lock`.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, unsafe, unreadable, malformed,
    /// unsupported, invalid, or non-canonical file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect self-publishing lock {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "self-publishing lock is not a regular file: {}",
            path.display()
        );
        let bytes = fs::read(path)
            .with_context(|| format!("read self-publishing lock {}", path.display()))?;
        Self::parse_canonical(&bytes, path)
    }

    /// Parses one `crates-io.lock` and requires its exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported content, an invalid
    /// entry, or bytes that differ from the canonical form.
    pub(crate) fn parse_canonical(bytes: &[u8], path: &Path) -> Result<Self> {
        let lock: Self = toml::from_slice(bytes)
            .with_context(|| format!("parse self-publishing lock {}", path.display()))?;
        lock.validate()
            .with_context(|| format!("validate self-publishing lock {}", path.display()))?;
        ensure!(
            bytes == lock.serialize()?,
            "self-publishing lock is not in canonical form: {}",
            path.display()
        );
        Ok(lock)
    }

    /// Serializes the lock in canonical form and order.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid entry or a TOML serialization failure.
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.packages.sort_by(|left, right| {
            (
                left.name.to_ascii_lowercase(),
                left.name.as_str(),
                &left.version,
            )
                .cmp(&(
                    right.name.to_ascii_lowercase(),
                    right.name.as_str(),
                    &right.version,
                ))
        });
        let text = toml::to_string_pretty(&canonical).context("serialize self-publishing lock")?;
        Ok(text.into_bytes())
    }

    /// Returns the entry of one exact crate version.
    pub(crate) fn entry(&self, name: &str, version: &Version) -> Option<&CratesIoPackage> {
        self.packages
            .iter()
            .find(|package| package.name == name && package.version == *version)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CRATES_IO_LOCK_SCHEMA,
            "self-publishing lock schema must be {CRATES_IO_LOCK_SCHEMA}, not {}",
            self.schema
        );
        let mut identities = BTreeSet::new();
        for package in &self.packages {
            crate::policy::validate_package_name(&package.name)
                .with_context(|| format!("validate entry name {:?}", package.name))?;
            name::validate_syntax(&package.crates_io_name).with_context(|| {
                format!(
                    "validate crates.io name {:?} of {} {}",
                    package.crates_io_name, package.name, package.version
                )
            })?;
            validate_sha256(&package.crate_sha256).with_context(|| {
                format!(
                    "validate crates.io archive checksum of {} {}",
                    package.name, package.version
                )
            })?;
            validate_sha256(&package.pkgre_crate_sha256).with_context(|| {
                format!(
                    "validate pkgre archive checksum of {} {}",
                    package.name, package.version
                )
            })?;
            validate_https_repository(&package.git).with_context(|| {
                format!(
                    "validate repository of {} {}",
                    package.name, package.version
                )
            })?;
            validate_git_tag(&package.tag)
                .with_context(|| format!("validate tag of {} {}", package.name, package.version))?;
            ensure!(
                package.commit.len() == COMMIT_LENGTH
                    && package
                        .commit
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "commit of {} {} must be a full lowercase hexadecimal commit ID",
                package.name,
                package.version
            );
            ensure!(
                identities.insert((name::canonical(&package.name), package.version.clone())),
                "entry {} {} is declared twice",
                package.name,
                package.version
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: &str) -> CratesIoPackage {
        CratesIoPackage {
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            crates_io_name: format!("pkgre-pkgs-{name}"),
            crate_sha256: "1".repeat(64),
            pkgre_crate_sha256: "2".repeat(64),
            git: "https://git.example.invalid/example/project".to_owned(),
            tag: format!("rust/v{version}"),
            commit: "3".repeat(40),
            cargo_version: Version::parse("1.95.0").unwrap(),
        }
    }

    fn lock(names: &[(&str, &str)]) -> CratesIoLock {
        CratesIoLock {
            schema: CRATES_IO_LOCK_SCHEMA,
            packages: names
                .iter()
                .map(|(name, version)| package(name, version))
                .collect(),
        }
    }

    fn path() -> &'static Path {
        Path::new("crates-io.lock")
    }

    /// One mutation of a lock entry that the checks must refuse.
    type EntryChange = fn(&mut CratesIoPackage);

    #[test]
    fn canonical_bytes_round_trip_and_sort_by_crates_io_comparison() {
        let unsorted = lock(&[("Example-Bin", "1.0.0"), ("example-lib", "1.0.0")]);
        let bytes = unsorted.serialize().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("schema = 1\n\n[[packages]]\n"), "{text}");
        assert!(
            text.find("Example-Bin").unwrap() < text.find("example-lib").unwrap(),
            "canonical order sorts by crates.io's comparison: {text}"
        );
        let parsed = CratesIoLock::parse_canonical(&bytes, path()).unwrap();
        assert_eq!(parsed, unsorted);
    }

    #[test]
    fn an_empty_lock_carries_only_its_schema() {
        assert_eq!(lock(&[]).serialize().unwrap(), b"schema = 1\n".to_vec());
        let parsed = CratesIoLock::parse_canonical(b"schema = 1\n", path()).unwrap();
        assert!(parsed.packages.is_empty());
    }

    #[test]
    fn non_canonical_and_malformed_locks_are_refused() {
        let canonical = lock(&[("example-bin", "1.0.0"), ("example-lib", "1.0.0")]);
        let text = String::from_utf8(canonical.serialize().unwrap()).unwrap();

        // Swap the two canonical blocks to get the same entries in a foreign order.
        let marker = "\n[[packages]]\n";
        let (head, body) = text.split_once(marker).unwrap();
        let mut blocks = body.split(marker).collect::<Vec<_>>();
        assert_eq!(blocks.len(), 2);
        blocks.reverse();
        let text = format!("{head}{marker}{}", blocks.join(marker));
        let error = CratesIoLock::parse_canonical(text.as_bytes(), path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("not in canonical form"), "{error}");

        let unknown = b"schema = 1\n\n[[packages]]\nextra = true\n".to_vec();
        let error = CratesIoLock::parse_canonical(&unknown, path()).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn invalid_entries_are_refused() {
        let cases: &[(EntryChange, &str)] = &[
            (|p| p.crate_sha256 = "A".repeat(64), "lowercase hexadecimal"),
            (|p| p.pkgre_crate_sha256 = "0".repeat(63), "64 characters"),
            (|p| p.commit = "3".repeat(39), "full lowercase hexadecimal"),
            (|p| p.tag = "rust/v1.0.0..".to_owned(), "safe ref name"),
            (
                |p| p.crates_io_name = "9bad".to_owned(),
                "must start with an ASCII letter",
            ),
            (
                |p| p.git = "http://git.example.invalid/x".to_owned(),
                "must use HTTPS",
            ),
        ];
        for &(mutate, expected) in cases {
            let mut entry = package("example-lib", "1.0.0");
            mutate(&mut entry);
            let text = CratesIoLock {
                schema: CRATES_IO_LOCK_SCHEMA,
                packages: vec![entry.clone()],
            };
            let error = text.validate().unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{expected:?} not in {error}");
        }

        let duplicate = CratesIoLock {
            schema: CRATES_IO_LOCK_SCHEMA,
            packages: vec![
                package("example-lib", "1.0.0"),
                package("Example-Lib", "1.0.0"),
            ],
        };
        let error = duplicate.validate().unwrap_err().to_string();
        assert!(error.contains("declared twice"), "{error}");
    }
}
