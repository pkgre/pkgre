//! What the derived crates.io packages must be, computed from the catalog, the
//! mapping, and the entries of earlier releases.
//!
//! The derivation resolves every package of the checkout's `Cargo.lock` to its
//! exact identity here, once, so that the manifest rewrite, the lock
//! translation, and the comparison all read the same facts. The comparison
//! therefore proves the result against the catalog and `crates-io.lock`, not
//! against the translation that produced it.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;

use super::super::catalog::CatalogSnapshot;
use super::super::config::CratesIoConfig;
use super::super::lock::CratesIoLock;
use super::cargo_lock::LockIndex;

/// What one package of the lock must be on each side.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ExpectedPackage {
    /// crates.io name.
    pub(super) crates_io_name: String,
    /// SHA-256 that the curated archive's lock must record, absent for a
    /// workspace member that the release does not publish.
    pub(super) curated_checksum: Option<String>,
    /// SHA-256 that the derived archive's lock must record, absent for a
    /// workspace member that the release does not publish, and for a released
    /// crate until the derivation packaged it.
    pub(super) derived_checksum: Option<String>,
    /// Whether the package is a workspace member of the tag.
    pub(super) member: bool,
}

/// The catalog facts of one release, by curated package name and version.
pub(super) struct Expectations {
    packages: BTreeMap<(String, Version), ExpectedPackage>,
    /// The crates.io name of every curated package name, when all its versions
    /// agree.
    names: BTreeMap<String, String>,
    /// The index that the run's Cargo home configures for the curated registry,
    /// which every package of the curated registry names as its source.
    curated_index: String,
}

impl Expectations {
    /// Resolves every package of the lock and refuses what crates.io cannot
    /// serve.
    ///
    /// `published` are the crates that the release publishes, with their
    /// crates.io names; every other package of the lock is either a workspace
    /// member that the release does not publish, a mirrored identity, or a
    /// first-party identity of an earlier release.
    ///
    /// # Errors
    ///
    /// Returns an error for a package whose source crates.io cannot serve, an
    /// identity the catalog does not hold, a fork, an abandoned version, a
    /// first-party version without an entry in `crates-io.lock`, or one package
    /// name that would carry several crates.io names.
    pub(super) fn build(
        lock: &LockIndex,
        catalog: &CatalogSnapshot,
        config: &CratesIoConfig,
        earlier: &CratesIoLock,
        published: &BTreeMap<String, String>,
        curated_index: &str,
    ) -> Result<Self> {
        let mut packages = BTreeMap::new();
        let mut names: BTreeMap<String, String> = BTreeMap::new();
        for package in lock.packages() {
            let expected =
                resolve_package(catalog, config, earlier, published, package, curated_index)?;
            match names.get(&package.name) {
                Some(previous) => ensure!(
                    previous == &expected.crates_io_name,
                    "packages named {:?} would become both {previous:?} and {:?} on crates.io",
                    package.name,
                    expected.crates_io_name
                ),
                None => {
                    names.insert(package.name.clone(), expected.crates_io_name.clone());
                }
            }
            packages.insert((package.name.clone(), package.version.clone()), expected);
        }
        Ok(Self {
            packages,
            names,
            curated_index: curated_index.to_owned(),
        })
    }

    /// Returns the index that the curated lock names for a package of the
    /// curated registry.
    pub(super) fn curated_index(&self) -> &str {
        &self.curated_index
    }

    /// Returns what one exact package of the lock must be.
    ///
    /// # Errors
    ///
    /// Returns an error for a package that the lock does not hold.
    pub(super) fn package(&self, name: &str, version: &Version) -> Result<&ExpectedPackage> {
        self.packages
            .get(&(name.to_owned(), version.clone()))
            .with_context(|| format!("the lock holds no package {name} {version}"))
    }

    /// Returns the crates.io name of one package of the lock.
    ///
    /// # Errors
    ///
    /// Returns an error for a package that the lock does not hold.
    pub(super) fn crates_io_name(&self, name: &str) -> Result<&str> {
        self.names
            .get(name)
            .map(String::as_str)
            .with_context(|| format!("the lock holds no package named {name:?}"))
    }

    /// Returns whether the lock holds one package name.
    pub(super) fn contains(&self, name: &str) -> bool {
        self.names.contains_key(name)
    }

    /// Binds the archives of the crates that the release publishes.
    ///
    /// A crate of the release that another crate of the release depends on is a
    /// package of the curated registry in the curated archive, with the archive
    /// `registry/main.lock` records, and a crates.io package in the derived
    /// archive, with the archive this run packaged; the comparison needs both
    /// before it reads the first archive.
    ///
    /// # Errors
    ///
    /// Returns an error for a released crate without a derived archive, or for a
    /// package that the release does not publish.
    pub(super) fn bind_release(
        &mut self,
        released: &[super::ReleasedCrate],
        derived: &BTreeMap<(String, Version), String>,
    ) -> Result<()> {
        for package in released {
            let key = (package.name.clone(), package.version.clone());
            let archive_sha256 = derived.get(&key).with_context(|| {
                format!(
                    "the release packaged no archive for {} {}",
                    package.name, package.version
                )
            })?;
            let expected = self.packages.get_mut(&key).with_context(|| {
                format!(
                    "the lock holds no package {} {}, which the release publishes",
                    package.name, package.version
                )
            })?;
            ensure!(
                expected.member,
                "package {} {} is not a workspace member of the tag, so the release does not publish it",
                package.name,
                package.version
            );
            expected.curated_checksum = Some(package.crate_sha256.clone());
            expected.derived_checksum = Some(archive_sha256.clone());
        }
        Ok(())
    }

    /// Returns every package outside the release's workspace that crates.io
    /// must serve for the release, in name and version order.
    ///
    /// A workspace member that the release does not publish stays a path
    /// package, and a crate of the release is served by the release itself, so
    /// neither is one of them.
    pub(super) fn dependencies(&self) -> Vec<super::DerivedDependency> {
        self.packages
            .iter()
            .filter(|(_, expected)| !expected.member)
            .filter_map(|((_, version), expected)| {
                let crate_sha256 = expected.derived_checksum.clone()?;
                Some(super::DerivedDependency {
                    crates_io_name: expected.crates_io_name.clone(),
                    version: version.clone(),
                    crate_sha256,
                })
            })
            .collect()
    }
}

/// Resolves one package of the lock.
fn resolve_package(
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    published: &BTreeMap<String, String>,
    package: &super::cargo_lock::LockedPackage,
    curated_index: &str,
) -> Result<ExpectedPackage> {
    if package.source.is_none()
        && let Some(crates_io_name) = published.get(&package.name)
    {
        return Ok(ExpectedPackage {
            crates_io_name: crates_io_name.clone(),
            curated_checksum: None,
            derived_checksum: None,
            member: true,
        });
    }
    if package.source.is_none() {
        // A workspace member that the release does not publish keeps its name
        // and stays a path package.
        return Ok(ExpectedPackage {
            crates_io_name: package.name.clone(),
            member: true,
            ..ExpectedPackage::default()
        });
    }
    let source = package.source.as_deref().unwrap_or_default();
    ensure!(
        super::cargo::names_index(source, curated_index),
        "package {} {} comes from the unsupported source {source:?}; every package of the release comes from the curated registry",
        package.name,
        package.version
    );
    let identity = catalog
        .identity(&package.name, &package.version)
        .with_context(|| {
            format!(
                "registry/main.lock holds no identity for {} {}",
                package.name, package.version
            )
        })?;
    let checksum = package.checksum.as_deref().with_context(|| {
        format!(
            "the lock records no checksum for {} {}",
            package.name, package.version
        )
    })?;
    ensure!(
        checksum == identity.crate_sha256,
        "the lock records checksum {checksum:?} for {} {}, but registry/main.lock records {:?}; the curated registry serves the catalog's bytes",
        package.name,
        package.version,
        identity.crate_sha256
    );
    let Some(release) = &identity.release else {
        return Ok(ExpectedPackage {
            crates_io_name: identity.name.clone(),
            curated_checksum: Some(identity.crate_sha256.clone()),
            derived_checksum: Some(identity.crate_sha256.clone()),
            member: false,
        });
    };
    if catalog.is_mirror(&identity.name) {
        bail!(
            "registry/main mirrors {}, but the package is a Git publication of the same name, so the crates.io name belongs to someone else",
            identity.name
        );
    }
    ensure!(
        config.repository(&release.git).is_some(),
        "{} {} is a Git publication from {:?}, which does not self-publish, so crates.io does not have it",
        identity.name,
        identity.version,
        release.git
    );
    ensure!(
        config
            .abandoned_version(&identity.name, &identity.version)
            .is_none(),
        "{} {} is abandoned on crates.io, so nothing can depend on it",
        identity.name,
        identity.version
    );
    let entry = earlier
        .entry(&identity.name, &identity.version)
        .with_context(|| {
            format!(
                "{} {} comes from tag {:?} of {:?}, which has no entry in crates-io.lock; crates.io does not have it yet",
                identity.name, identity.version, release.tag, release.git
            )
        })?;
    ensure!(
        entry.pkgre_crate_sha256 == identity.crate_sha256,
        "entry {} {} records pkgre archive checksum {:?} but registry/main.lock records {:?}",
        identity.name,
        identity.version,
        entry.pkgre_crate_sha256,
        identity.crate_sha256
    );
    Ok(ExpectedPackage {
        crates_io_name: entry.crates_io_name.clone(),
        curated_checksum: Some(identity.crate_sha256.clone()),
        derived_checksum: Some(entry.crate_sha256.clone()),
        member: false,
    })
}
