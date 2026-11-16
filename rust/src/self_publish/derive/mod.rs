//! Deriving the crates.io packages of one release tag.
//!
//! The derivation fetches the tag into a fresh checkout, rewrites the workspace
//! manifests for crates.io, translates the lock file, packages every released
//! crate with the pinned Cargo in an isolated environment, and proves the result
//! against the archive that the catalog retains.

mod cargo;
mod cargo_lock;
mod compare;
mod git;
mod workspace;

use std::collections::BTreeMap;
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

/// Where a derivation reads the release tag and its Cargo packages from, which
/// differs from the network only in tests.
pub(super) struct DerivationSources<'a> {
    /// A local repository to fetch the release tag from, instead of the
    /// repository URL of the catalog.
    pub(super) fetch_repository: &'a Path,
    /// A local directory source that replaces crates.io, so that packaging needs
    /// no network; absent when packaging resolves from crates.io.
    pub(super) directory: Option<&'a Path>,
    /// The directory to work in, instead of the temporary directory of the
    /// caller's environment, which no Cargo configuration may cover.
    pub(super) root: &'a Path,
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

/// Derives every crates.io package of one release.
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
pub(super) fn derive_release(
    release: &GitRelease,
    released: &[ReleasedCrate],
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    sources: Option<&DerivationSources<'_>>,
) -> Result<Vec<DerivedPackage>> {
    ensure!(
        !released.is_empty(),
        "a release holds at least one crate, but {} {} has none",
        release.git,
        release.tag
    );
    let cargo = pinned_cargo(&release.cargo_version)?;
    let temporary = match sources {
        Some(sources) => TemporaryDirectory::new_in(sources.root, "pkgre-self-publish")?,
        None => TemporaryDirectory::new("pkgre-self-publish")?,
    };
    let root = temporary.path();
    let cargo_home = cargo::cargo_home(root);
    let registry_sources = match sources {
        Some(DerivationSources {
            directory: Some(directory),
            ..
        }) => cargo::RegistrySources::Local(directory),
        _ => cargo::RegistrySources::CratesIo,
    };
    cargo::prepare_cargo_home(&cargo_home, registry_sources)?;
    let environment = ChildEnvironment::capture(&cargo_home, &cargo)?;
    let work = root.join("work");
    std::fs::create_dir(&work)
        .with_context(|| format!("create derivation directory {}", work.display()))?;
    ensure_no_cargo_configuration(&work)?;

    let (fetch_repository, allow_file) = match sources {
        Some(sources) => (
            sources
                .fetch_repository
                .to_str()
                .with_context(|| {
                    format!(
                        "test repository {} is not UTF-8",
                        sources.fetch_repository.display()
                    )
                })?
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
    let published = published_crates(&workspace, released, config, &release.tag)?;
    let plan = workspace::ReleasePlan::new(&workspace, catalog, config, earlier, &published)?;
    workspace::rewrite_manifests(&workspace, &plan, catalog, config, earlier)?;
    let lock_renames =
        cargo_lock::translate_lock(&checkout.root, &workspace, &plan, catalog, config, earlier)?;

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
            &lock_renames,
        )
        .with_context(|| {
            format!(
                "the crates.io archive of {} {} differs from the curated archive",
                package.name, package.version
            )
        })?;
        let crate_sha256 = sha256_bytes(archive);
        packages.push(DerivedPackage {
            entry: CratesIoPackage {
                name: package.name.clone(),
                version: package.version.clone(),
                crates_io_name,
                crate_sha256,
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
