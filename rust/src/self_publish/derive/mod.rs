//! Deriving the crates.io packages of one release tag.
//!
//! The derivation fetches the tag into a fresh checkout, resolves every package
//! of the workspace through its own `Cargo.lock`, rewrites the manifests for
//! crates.io, translates the lock file, packages every released crate with the
//! pinned Cargo in an isolated environment, and proves the result against the
//! archive that the catalog retains and the entries that `crates-io.lock`
//! records.

mod cargo;
mod cargo_lock;
mod compare;
mod expectations;
mod git;
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;

use super::catalog::{CatalogSnapshot, GitRelease};
use super::config::CratesIoConfig;
use super::isolation::{ChildEnvironment, ensure_no_cargo_configuration};
use super::lock::{CratesIoLock, CratesIoPackage};
use super::name;
use crate::artifact::sha256_bytes;
use crate::package::{TemporaryDirectory, pinned_cargo};
use crate::policy::validate_tag_version;
use cargo_lock::LockIndex;
use expectations::Expectations;

/// Where a derivation reads the release tag and its Cargo packages from.
///
/// A production run reads the network and crates.io; only a test can point it at
/// a local repository, a local directory source, and a working directory, which
/// the compiler drops from every other build.
#[derive(Clone, Copy)]
pub(super) struct Sources<'a> {
    /// A local repository to fetch the release tag from, instead of the
    /// repository URL of the catalog.
    #[cfg(test)]
    fetch_repository: Option<&'a Path>,
    /// A local directory source that replaces crates.io.
    #[cfg(test)]
    directory: Option<&'a Path>,
    /// The directory to work in, instead of the temporary directory of the
    /// caller's environment.
    #[cfg(test)]
    root: Option<&'a Path>,
    /// The lifetime of a local source, which only a test names.
    #[cfg_attr(not(test), allow(dead_code))]
    marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> Sources<'a> {
    /// The sources of a production run: the network and crates.io.
    pub(super) const fn network() -> Self {
        Self {
            #[cfg(test)]
            fetch_repository: None,
            #[cfg(test)]
            directory: None,
            #[cfg(test)]
            root: None,
            marker: std::marker::PhantomData,
        }
    }

    /// The sources of a test run.
    #[cfg(test)]
    pub(super) const fn local(
        fetch_repository: &'a Path,
        directory: Option<&'a Path>,
        root: &'a Path,
    ) -> Self {
        Self {
            fetch_repository: Some(fetch_repository),
            directory,
            root: Some(root),
            marker: std::marker::PhantomData,
        }
    }

    /// Returns the local repository to fetch the release tag from, if any.
    #[cfg(test)]
    fn fetch_repository(&self) -> Option<&'a Path> {
        self.fetch_repository
    }

    /// Returns the local repository to fetch the release tag from, if any.
    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::trivially_copy_pass_by_ref)]
    fn fetch_repository(&self) -> Option<&'a Path> {
        None
    }

    #[allow(clippy::unused_self)]
    /// Returns the local directory source that replaces crates.io, if any.
    #[cfg(test)]
    fn directory(&self) -> Option<&'a Path> {
        self.directory
    }

    #[allow(clippy::unused_self)]
    /// Returns the directory to work in, if the caller named one.
    #[cfg(test)]
    fn root(&self) -> Option<&'a Path> {
        self.root
    }

    /// Returns the directory to work in, if the caller named one.
    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::trivially_copy_pass_by_ref)]
    fn root(&self) -> Option<&'a Path> {
        None
    }
}

/// One crate of one release, as the catalog records it.
pub(super) struct ReleasedCrate {
    /// Cargo package name in the curated registry.
    pub(super) name: String,
    /// Exact version.
    pub(super) version: Version,
    /// SHA-256 of the curated archive, as `registry/main.lock` records it.
    pub(super) crate_sha256: String,
    /// The curated archive's exact bytes.
    pub(super) archive: Vec<u8>,
}

/// What the derivation writes for one crate.
#[derive(Debug)]
pub(super) struct DerivedPackage {
    /// The `crates-io.lock` entry of the crate version.
    pub(super) entry: CratesIoPackage,
    /// The derived crates.io archive's exact bytes.
    pub(super) archive: Vec<u8>,
}

/// Derives every crates.io package of one release from the given sources.
///
/// `released` are the catalog's identities of the release, with the archives
/// that the catalog retains. The result holds one package per released crate,
/// in name order.
///
/// # Errors
///
/// Returns an error when the tag cannot be fetched or does not match the
/// catalog's commit, when the workspace and the catalog disagree, when a
/// manifest or lock file cannot be translated, when the pinned Cargo fails or
/// packages twice differently, or when a derived archive differs from the
/// curated archive beyond the fields the derivation rewrites.
#[allow(clippy::too_many_lines)]
pub(super) fn derive_release_with(
    release: &GitRelease,
    released: &[ReleasedCrate],
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    sources: Sources<'_>,
) -> Result<Vec<DerivedPackage>> {
    ensure!(
        !released.is_empty(),
        "a release holds at least one crate, but {} {} has none",
        release.git,
        release.tag
    );
    let cargo = pinned_cargo(&release.cargo_version)?;
    let temporary = match sources.root() {
        Some(root) => TemporaryDirectory::new_in(root, "pkgre-self-publish")?,
        None => TemporaryDirectory::new("pkgre-self-publish")?,
    };
    let root = temporary.path();
    let cargo_home = cargo::cargo_home(root);
    cargo::prepare_cargo_home(&cargo_home, cargo::registry_sources(sources))?;
    let environment = ChildEnvironment::capture(&cargo_home, &cargo)?;
    let work = root.join("work");
    std::fs::create_dir(&work)
        .with_context(|| format!("create derivation directory {}", work.display()))?;
    ensure_no_cargo_configuration(&work)?;

    let (fetch_repository, allow_file) = match sources.fetch_repository() {
        Some(repository) => (
            repository
                .to_str()
                .with_context(|| format!("test repository {} is not UTF-8", repository.display()))?
                .to_owned(),
            true,
        ),
        None => (release.git.clone(), false),
    };
    let checkout = git::fetch_tag(
        &release.git,
        &release.tag,
        &root.join("repository"),
        &fetch_repository,
        &environment,
        allow_file,
    )?;
    ensure!(
        checkout.tag_oid == release.tag_oid,
        "release tag {:?} of {:?} is object {}, but registry/main.lock records {}",
        release.tag,
        release.git,
        checkout.tag_oid,
        release.tag_oid
    );
    ensure!(
        checkout.commit == release.commit,
        "release tag {:?} of {:?} names commit {}, but registry/main.lock records {}",
        release.tag,
        release.git,
        checkout.commit,
        release.commit
    );

    let workspace = workspace::Workspace::load(&cargo, &environment, &work, &checkout.root)?;
    ensure_release_members(&workspace, released, &release.tag)?;
    let lock = LockIndex::load(&checkout.root.join("Cargo.lock"))?;
    let published = published_crates(&workspace, released, config, &release.tag)?;
    let expectations = Expectations::build(&lock, catalog, config, earlier, &published)?;
    let plan = workspace::ReleasePlan::new(&workspace, &lock, &expectations, &published)?;
    workspace::rewrite_manifests(&workspace, &plan, &expectations)?;
    cargo_lock::translate_lock(&checkout.root, &expectations)?;

    let members = released
        .iter()
        .map(|package| {
            let crates_io_name = published
                .get(&package.name)
                .expect("every released crate has a crates.io name");
            (crates_io_name.clone(), package.version.clone())
        })
        .collect::<Vec<_>>();
    let archives = cargo::package_members(
        &cargo,
        &environment,
        &work,
        &root.join("targets"),
        &checkout.root,
        &members,
    )?;

    let mut packages = Vec::new();
    for package in released {
        let crates_io_name = published
            .get(&package.name)
            .expect("every released crate has a crates.io name")
            .clone();
        let archive = archives.get(&crates_io_name).with_context(|| {
            format!(
                "pinned Cargo produced no archive for {} {}",
                crates_io_name, package.version
            )
        })?;
        ensure!(
            sha256_bytes(&package.archive) == package.crate_sha256,
            "the curated archive of {} {} has SHA-256 {}, but registry/main.lock records {}",
            package.name,
            package.version,
            sha256_bytes(&package.archive),
            package.crate_sha256
        );
        compare::compare_archives(
            &package.version,
            &compare::ArchiveToCompare {
                name: package.name.as_str(),
                bytes: package.archive.as_slice(),
            },
            &compare::ArchiveToCompare {
                name: crates_io_name.as_str(),
                bytes: archive.as_slice(),
            },
            &expectations,
        )
        .with_context(|| {
            format!(
                "the crates.io archive of {} {} differs from the curated archive",
                package.name, package.version
            )
        })?;
        packages.push(DerivedPackage {
            entry: CratesIoPackage {
                name: package.name.clone(),
                version: package.version.clone(),
                crates_io_name,
                crate_sha256: sha256_bytes(archive),
                pkgre_crate_sha256: package.crate_sha256.clone(),
                git: release.git.clone(),
                tag: release.tag.clone(),
                commit: release.commit.clone(),
                cargo_version: release.cargo_version.clone(),
            },
            archive: archive.clone(),
        });
    }
    packages.sort_by(|left, right| {
        (
            left.entry.name.to_ascii_lowercase(),
            left.entry.name.as_str(),
            &left.entry.version,
        )
            .cmp(&(
                right.entry.name.to_ascii_lowercase(),
                right.entry.name.as_str(),
                &right.entry.version,
            ))
    });
    Ok(packages)
}

/// Requires the crates that the catalog publishes from the tag to be exactly
/// the tag's publishable members.
///
/// A release tag publishes the crates of its commit, no more and no fewer, so a
/// partial release cannot be repaired at the same tag.
///
/// # Errors
///
/// Returns an error naming the publishable members that the catalog does not
/// publish from the tag, and the catalog crates that the tag does not publish.
fn ensure_release_members(
    workspace: &workspace::Workspace,
    released: &[ReleasedCrate],
    tag: &str,
) -> Result<()> {
    let publishable = workspace.publishable_members();
    let published = released
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing = publishable
        .difference(&published)
        .copied()
        .collect::<Vec<_>>();
    let extra = published
        .difference(&publishable)
        .copied()
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty() && extra.is_empty(),
        "Git tag {tag:?} publishes exactly its publishable members, {publishable:?}, but registry/main.lock publishes {published:?} from it: publishable and missing from the catalog {missing:?}, in the catalog but not publishable at the tag {extra:?}"
    );
    Ok(())
}

/// Returns the crates.io name of every released crate, refusing a name that
/// crates.io would not take or that two crates share.
fn published_crates(
    workspace: &workspace::Workspace,
    released: &[ReleasedCrate],
    config: &CratesIoConfig,
    tag: &str,
) -> Result<BTreeMap<String, String>> {
    let mut published = BTreeMap::new();
    let mut used: BTreeMap<String, String> = BTreeMap::new();
    for package in released {
        let member = workspace.member(&package.name).with_context(|| {
            format!(
                "the tag's workspace does not hold {}, which registry/main.lock publishes",
                package.name
            )
        })?;
        ensure!(
            member.version == package.version,
            "the tag's workspace holds {} {}, but registry/main.lock records {}",
            package.name,
            member.version,
            package.version
        );
        validate_tag_version(tag, &member.version)?;
        let crates_io_name = config.effective_name(&package.name);
        name::validate(&crates_io_name)
            .with_context(|| format!("validate the crates.io name of {}", package.name))?;
        let key = name::canonical(&crates_io_name);
        if let Some(other) = used.get(&key) {
            bail!(
                "crates {other} and {} both use the crates.io name {crates_io_name:?}",
                package.name
            );
        }
        used.insert(key, package.name.clone());
        published.insert(package.name.clone(), crates_io_name);
    }
    Ok(published)
}

#[cfg(test)]
#[path = "../../../tests/unit/self_publish/derive/mod.rs"]
mod tests;
