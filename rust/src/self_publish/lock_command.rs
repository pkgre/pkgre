//! The `self-publish-lock` command: deriving and recording crates.io packages.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use tracing::info;

use super::catalog::{CatalogIdentity, GitRelease, is_release_tag};
use super::check::check_state;
use super::derive::{ReleasedCrate, Sources, derive_release_with};
use super::lock::{CratesIoLock, CratesIoPackage};
use super::state::{LOCK_FILE, RepositoryState, STATE_DIRECTORY, SelfPublishState};
use crate::artifact::sha256_bytes;
use crate::package::read_bounded_archive;

/// One entry that one run derived and recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfPublishLockEntry {
    /// Cargo package name in the curated registry.
    pub name: String,
    /// Exact Cargo version.
    pub version: Version,
    /// crates.io name of the crate version.
    pub crates_io_name: String,
    /// SHA-256 of the derived crates.io archive.
    pub crate_sha256: String,
    /// SHA-256 of the identity's archive in `registry/main.lock`.
    pub pkgre_crate_sha256: String,
    /// The release tag the crate version comes from.
    pub tag: String,
}

/// What one run of `self-publish-lock` did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelfPublishLockSummary {
    /// The entries the run derived, in canonical order.
    pub entries: Vec<SelfPublishLockEntry>,
    /// The releases the run derived.
    pub releases: usize,
    /// Whether the run wrote `crates-io.lock`.
    pub changed: bool,
}

/// Derives and records every self-published crate version that
/// `self-publish/crates-io.lock` does not hold yet.
///
/// `repository` is the directory that holds `registry/` and `self-publish/`.
/// Every release tag is fetched and packaged once, and the offline checks of
/// [`super::check_repository`] run on the result before the file is written.
///
/// # Errors
///
/// Returns an error for a repository without self-publishing state, an
/// identity that cannot be derived, a release whose tag or archive disagrees
/// with the catalog, a derivation that fails, or a lock that the offline checks
/// would refuse.
pub fn self_publish_lock(repository: &Path) -> Result<SelfPublishLockSummary> {
    run_lock(repository, |_| Ok(Sources::network()))
}

/// Local stand-ins for the network, which only a test can build.
#[cfg(test)]
pub(super) struct LocalNetwork<'a> {
    /// Repository URL, as the catalog spells it, to the local repository to
    /// fetch the release tag from.
    pub(super) repositories: &'a BTreeMap<String, std::path::PathBuf>,
    /// A directory source that replaces crates.io.
    pub(super) source: &'a Path,
    /// The directory to work in, which no Cargo configuration may cover.
    pub(super) root: &'a Path,
}

/// Runs the command from local stand-ins for the network.
#[cfg(test)]
pub(super) fn self_publish_lock_in<'a>(
    repository: &Path,
    local: &'a LocalNetwork<'a>,
) -> Result<SelfPublishLockSummary> {
    run_lock(repository, |git| {
        Ok(Sources::local(
            local
                .repositories
                .get(git)
                .with_context(|| format!("no local test repository stands in for {git:?}"))?,
            Some(local.source),
            local.root,
        ))
    })
}

/// Runs the command, with one factory for the sources of each release.
fn run_lock<'a>(
    repository: &Path,
    sources_of: impl Fn(&str) -> Result<Sources<'a>>,
) -> Result<SelfPublishLockSummary> {
    let state = RepositoryState::load(repository)?;
    let Some(self_publish) = state.self_publish.as_ref() else {
        bail!(
            "repository {} has no {STATE_DIRECTORY} directory; there is no self-publishing state to lock",
            repository.display()
        );
    };
    let groups = unrecorded_releases(&state, self_publish)?;
    if groups.is_empty() {
        info!(
            path = %repository.display(),
            "every self-published identity has an entry in {LOCK_FILE}; nothing to derive"
        );
        return Ok(SelfPublishLockSummary::default());
    }
    let mut packages: Vec<CratesIoPackage> = Vec::new();
    let mut releases = 0;
    for ((git, tag), identities) in &groups {
        let release = release_of_group(git, tag, identities)?;
        let curated = identities
            .iter()
            .map(|identity| {
                read_released_crate(&state.catalog_root, identity).with_context(|| {
                    format!(
                        "read the curated archive of {} {}",
                        identity.name, identity.version
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let derivation_sources = sources_of(git)?;
        let derived = derive_release_with(
            &release,
            &curated,
            &state.catalog,
            &self_publish.config,
            &self_publish.lock,
            derivation_sources,
        )
        .with_context(|| format!("derive the crates.io packages of tag {tag:?} of {git:?}"))?;
        for package in derived {
            info!(
                package = %package.entry.name,
                version = %package.entry.version,
                crates_io_name = %package.entry.crates_io_name,
                archive_bytes = package.archive.len(),
                "derived a crates.io package"
            );
            packages.push(package.entry);
        }
        releases += 1;
    }
    let mut lock = self_publish.lock.clone();
    lock.packages.extend(packages.iter().cloned());
    let candidate = SelfPublishState {
        config: self_publish.config.clone(),
        lock,
    };
    let summary = check_state(&candidate, &state.catalog, None)
        .context("the derived lock must pass the offline self-publishing checks")?;
    write_lock(repository, &candidate.lock)?;
    let entries = packages.iter().map(entry).collect::<Vec<_>>();
    info!(
        entries = summary.entries,
        releases,
        path = %repository.display(),
        "derived crates.io packages and recorded their entries"
    );
    Ok(SelfPublishLockSummary {
        entries,
        releases,
        changed: true,
    })
}

/// Returns the summary of one derived entry.
fn entry(package: &CratesIoPackage) -> SelfPublishLockEntry {
    SelfPublishLockEntry {
        name: package.name.clone(),
        version: package.version.clone(),
        crates_io_name: package.crates_io_name.clone(),
        crate_sha256: package.crate_sha256.clone(),
        pkgre_crate_sha256: package.pkgre_crate_sha256.clone(),
        tag: package.tag.clone(),
    }
}

/// Returns the release tags whose crates have no `crates-io.lock` entry yet.
pub(super) fn unrecorded_releases(
    state: &RepositoryState,
    self_publish: &SelfPublishState,
) -> Result<BTreeMap<(String, String), Vec<CatalogIdentity>>> {
    let config = &self_publish.config;
    let mut groups: BTreeMap<(String, String), Vec<CatalogIdentity>> = BTreeMap::new();
    for identity in &state.catalog.identities {
        let Some(release) = &identity.release else {
            continue;
        };
        let Some(prefix) = config.prefix_for(&release.git) else {
            continue;
        };
        let recorded = self_publish
            .lock
            .entry(&identity.name, &identity.version)
            .is_some();
        ensure!(
            recorded || is_release_tag(prefix, identity, release),
            "Git identity {} {} was added from tag {:?} of {:?}, which is not a release tag of the repository: {prefix:?} followed by the version",
            identity.name,
            identity.version,
            release.tag,
            release.git
        );
        groups
            .entry((release.git.clone(), release.tag.clone()))
            .or_default()
            .push(identity.clone());
    }
    let mut unrecorded = BTreeMap::new();
    for (key, identities) in groups {
        let missing = identities
            .iter()
            .filter(|identity| {
                self_publish
                    .lock
                    .entry(&identity.name, &identity.version)
                    .is_none()
            })
            .collect::<Vec<_>>();
        if missing.is_empty() {
            continue;
        }
        ensure!(
            missing.len() == identities.len(),
            "the release tag {:?} of {:?} already has entries in {LOCK_FILE}, but {} has none; a release tag publishes the crates of its commit, so only a new version can add a crate",
            key.1,
            key.0,
            missing
                .iter()
                .map(|identity| format!("{} {}", identity.name, identity.version))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for identity in &identities {
            ensure!(
                !identity.removed,
                "the catalog removed {} {}, whose archive it no longer retains, so it cannot be derived; only an active identity can be",
                identity.name,
                identity.version
            );
            ensure!(
                config
                    .abandoned_version(&identity.name, &identity.version)
                    .is_none(),
                "{} {} is abandoned on crates.io, so the run derives no entry for it",
                identity.name,
                identity.version
            );
        }
        unrecorded.insert(key, identities);
    }
    Ok(unrecorded)
}

/// Returns the release of one group of identities, refusing disagreement.
fn release_of_group(git: &str, tag: &str, identities: &[CatalogIdentity]) -> Result<GitRelease> {
    let mut releases = identities
        .iter()
        .filter_map(|identity| identity.release.clone());
    let release = releases
        .next()
        .with_context(|| format!("the release tag {tag:?} of {git:?} has no Git publication"))?;
    for other in releases {
        ensure!(
            other.git == release.git
                && other.tag == release.tag
                && other.commit == release.commit
                && other.cargo_version == release.cargo_version,
            "the identities of tag {tag:?} of {git:?} disagree on their commit or on the Cargo version that packaged them"
        );
    }
    Ok(release)
}

/// Reads the curated archive that the catalog retains for one identity.
fn read_released_crate(catalog_root: &Path, identity: &CatalogIdentity) -> Result<ReleasedCrate> {
    let path = catalog_root
        .join("objects")
        .join("crates")
        .join(format!("{}.crate", identity.crate_sha256));
    let archive = read_bounded_archive(&path)?;
    ensure!(
        sha256_bytes(&archive) == identity.crate_sha256,
        "the retained archive {} has SHA-256 {}, but registry/main.lock records {}",
        path.display(),
        sha256_bytes(&archive),
        identity.crate_sha256
    );
    Ok(ReleasedCrate {
        name: identity.name.clone(),
        version: identity.version.clone(),
        crate_sha256: identity.crate_sha256.clone(),
        archive,
    })
}

/// Writes the lock file atomically: a temporary file in the same directory,
/// then a rename.
fn write_lock(repository: &Path, lock: &CratesIoLock) -> Result<()> {
    let directory = repository.join(STATE_DIRECTORY);
    let path = directory.join(LOCK_FILE);
    let bytes = lock.serialize()?;
    let permissions = fs::metadata(&path)
        .with_context(|| format!("inspect {}", path.display()))?
        .permissions();
    let temporary = directory.join(format!(".{LOCK_FILE}.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        fs::write(&temporary, &bytes).with_context(|| format!("write {}", temporary.display()))?;
        fs::set_permissions(&temporary, permissions)
            .with_context(|| format!("set permissions of {}", temporary.display()))?;
        fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
