//! Offline checks of the self-publishing state against the catalog and against
//! an accepted repository.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;

use super::config::CratesIoConfig;
use super::lock::CratesIoLock;
use super::name;
use crate::schema::{Catalog, Source};

/// The only catalog registry that `self-publish/` names.
const CATALOG_REGISTRY: &str = "main";
/// Human self-publishing declarations.
const CONFIG_FILE: &str = "crates-io.toml";
/// Generated self-publishing records.
const LOCK_FILE: &str = "crates-io.lock";
/// Directory of the self-publishing state.
const STATE_DIRECTORY: &str = "self-publish";
/// Directory of the catalog's own state.
const CATALOG_DIRECTORY: &str = "registry";

/// What one run of the offline self-publishing checks found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelfPublishCheckSummary {
    /// Whether the repository declares `self-publish/` at all.
    pub declared: bool,
    /// Declared self-publishing repositories.
    pub repositories: usize,
    /// Mapped crates.io names in `[names]`.
    pub names: usize,
    /// Entries in `crates-io.lock`.
    pub entries: usize,
    /// Self-published identities in `registry/main.lock`.
    pub identities: usize,
    /// Whether the candidate was compared with an accepted repository.
    pub accepted: bool,
}

/// Runs the offline self-publishing checks of one catalog repository.
///
/// `repository` is the directory that holds `registry/` and `self-publish/`.
/// When `accepted` is given, its `registry/` and `self-publish/` are the
/// accepted state: entries, repositories, tag prefixes and abandoned records
/// may only be added there, and versions have to increase. Without an accepted
/// repository the checks that compare against one are skipped, and a repository
/// that has no `self-publish/` directory has nothing to check.
///
/// # Errors
///
/// Returns an error for a missing or invalid catalog, a malformed or
/// non-canonical self-publishing state, or any violation of the name rules,
/// the identity and entry correspondence, the accepted-state comparison, the
/// release-tag convention, or the version rules.
pub fn check_repository(
    repository: &Path,
    accepted: Option<&Path>,
) -> Result<SelfPublishCheckSummary> {
    let candidate = RepositoryState::load(repository)?;
    let Some(self_publish) = candidate.self_publish else {
        tracing::info!(
            path = %repository.display(),
            "repository has no self-publish directory; the self-publishing checks are skipped"
        );
        return Ok(SelfPublishCheckSummary::default());
    };
    let accepted = accepted.map(RepositoryState::load).transpose()?;
    if accepted.is_none() {
        tracing::info!(
            "self-publishing checks that compare against an accepted state are skipped: no accepted repository was given"
        );
    }
    let accepted_view = accepted.as_ref().map(|state| AcceptedState {
        catalog: &state.catalog,
        config: state.self_publish.as_ref().map(|state| &state.config),
        lock: state.self_publish.as_ref().map(|state| &state.lock),
    });
    check(&self_publish, &candidate.catalog, accepted_view.as_ref())
}

/// One repository: its catalog facts and, when declared, its self-publishing state.
struct RepositoryState {
    catalog: CatalogSnapshot,
    self_publish: Option<SelfPublishState>,
}

/// The parsed self-publishing files of one repository.
struct SelfPublishState {
    config: CratesIoConfig,
    lock: CratesIoLock,
}

impl RepositoryState {
    fn load(repository: &Path) -> Result<Self> {
        let registry = repository.join(CATALOG_DIRECTORY);
        match fs::symlink_metadata(&registry) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => bail!(
                "repository {} has no {CATALOG_DIRECTORY} directory; the argument is the directory that holds {CATALOG_DIRECTORY}/ and {STATE_DIRECTORY}/",
                repository.display()
            ),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect catalog directory {}", registry.display()));
            }
        }
        let catalog = Catalog::load(&registry)
            .with_context(|| format!("load catalog {}", registry.display()))?;
        let catalog = CatalogSnapshot::from_catalog(&catalog);
        let directory = repository.join(STATE_DIRECTORY);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Self {
                    catalog,
                    self_publish: None,
                });
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect self-publishing directory {}", directory.display())
                });
            }
        };
        ensure!(
            metadata.file_type().is_dir(),
            "self-publishing directory is not a real directory: {}",
            directory.display()
        );
        Ok(Self {
            catalog,
            self_publish: Some(SelfPublishState::load(&directory)?),
        })
    }
}

impl SelfPublishState {
    fn load(directory: &Path) -> Result<Self> {
        let mut names = fs::read_dir(directory)
            .with_context(|| format!("read self-publishing directory {}", directory.display()))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("read self-publishing directory {}", directory.display()))?;
        names.sort();
        let found = names
            .iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        ensure!(
            found == [LOCK_FILE.to_owned(), CONFIG_FILE.to_owned()],
            "self-publishing directory {} must hold exactly {CONFIG_FILE} and {LOCK_FILE}, found {found:?}",
            directory.display()
        );
        for name in &names {
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect {}", path.display()))?;
            ensure!(
                metadata.file_type().is_file(),
                "self-publishing file is not a regular file: {}",
                path.display()
            );
        }
        Ok(Self {
            config: CratesIoConfig::load(&directory.join(CONFIG_FILE))?,
            lock: CratesIoLock::load(&directory.join(LOCK_FILE))?,
        })
    }
}

/// The accepted repository, as far as the candidate is compared with it.
struct AcceptedState<'a> {
    catalog: &'a CatalogSnapshot,
    config: Option<&'a CratesIoConfig>,
    lock: Option<&'a CratesIoLock>,
}

/// The catalog facts the checks need, taken from `registry/main.lock`.
#[derive(Clone, Debug, Default)]
struct CatalogSnapshot {
    identities: Vec<CatalogIdentity>,
    mirrors: Vec<String>,
}

/// One package identity of `registry/main.lock`, active or removed.
#[derive(Clone, Debug)]
struct CatalogIdentity {
    name: String,
    version: Version,
    crate_sha256: String,
    release: Option<GitRelease>,
}

/// One Git publication of a package identity.
#[derive(Clone, Debug)]
struct GitRelease {
    git: String,
    tag: String,
    commit: String,
    cargo_version: Version,
}

impl CatalogSnapshot {
    fn from_catalog(catalog: &Catalog) -> Self {
        let mut identities = Vec::new();
        for approval in &catalog.approvals {
            if approval.registry != CATALOG_REGISTRY {
                continue;
            }
            let release = match &approval.source {
                Source::CratesIo => None,
                Source::GitTag {
                    repository,
                    tag,
                    commit,
                    cargo_version,
                    ..
                } => Some(GitRelease {
                    git: repository.clone(),
                    tag: tag.clone(),
                    commit: commit.clone(),
                    cargo_version: cargo_version.clone(),
                }),
            };
            identities.push(CatalogIdentity {
                name: approval.name.clone(),
                version: approval.version.clone(),
                crate_sha256: approval.archive_sha256.clone(),
                release,
            });
        }
        let mirrors = catalog
            .mirror_names
            .iter()
            .filter(|key| key.registry == CATALOG_REGISTRY)
            .map(|key| key.name.clone())
            .collect();
        Self {
            identities,
            mirrors,
        }
    }
}

fn check(
    candidate: &SelfPublishState,
    catalog: &CatalogSnapshot,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<SelfPublishCheckSummary> {
    let config = &candidate.config;
    let published = published_crates(catalog, config);
    let self_published = self_published_identities(catalog, config);
    check_accepted_entries(candidate, accepted)?;
    check_accepted_repositories(candidate, accepted)?;
    check_abandoned(candidate, accepted)?;
    check_name_permanence(candidate, accepted)?;
    check_names(config, catalog, &published)?;
    check_entries(candidate, catalog, accepted)?;
    check_gained_release_tags(config, catalog, accepted)?;
    check_versions(config, &self_published, accepted)?;
    Ok(SelfPublishCheckSummary {
        declared: true,
        repositories: config.repositories.len(),
        names: config.names.len(),
        entries: candidate.lock.packages.len(),
        identities: self_published.len(),
        accepted: accepted.is_some(),
    })
}

/// Returns the release-tag prefix and Git publication of a self-publishing identity.
fn release_of<'a>(
    config: &'a CratesIoConfig,
    identity: &'a CatalogIdentity,
) -> Option<(&'a str, &'a GitRelease)> {
    let release = identity.release.as_ref()?;
    let prefix = config.prefix_for(&release.git)?;
    Some((prefix, release))
}

/// Returns the crate names that a self-publishing repository publishes.
fn published_crates<'a>(
    catalog: &'a CatalogSnapshot,
    config: &CratesIoConfig,
) -> BTreeSet<&'a str> {
    catalog
        .identities
        .iter()
        .filter(|identity| release_of(config, identity).is_some())
        .map(|identity| identity.name.as_str())
        .collect()
}

/// Returns the identities that come from a release tag of a self-publishing repository.
fn self_published_identities<'a>(
    catalog: &'a CatalogSnapshot,
    config: &CratesIoConfig,
) -> Vec<&'a CatalogIdentity> {
    catalog
        .identities
        .iter()
        .filter(|identity| {
            release_of(config, identity)
                .is_some_and(|(prefix, release)| is_release_tag(prefix, identity, release))
        })
        .collect()
}

fn is_release_tag(prefix: &str, identity: &CatalogIdentity, release: &GitRelease) -> bool {
    release.tag == format!("{prefix}{}", identity.version)
}

fn check_accepted_entries(
    candidate: &SelfPublishState,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    let Some(accepted_lock) = accepted.and_then(|state| state.lock) else {
        return Ok(());
    };
    for entry in &accepted_lock.packages {
        let Some(current) = candidate.lock.entry(&entry.name, &entry.version) else {
            bail!(
                "entry {} {} was removed from {LOCK_FILE}; entries are only ever added",
                entry.name,
                entry.version
            );
        };
        ensure!(
            current == entry,
            "entry {} {} changed in {LOCK_FILE}; entries are only ever added, never changed",
            entry.name,
            entry.version
        );
    }
    Ok(())
}

fn check_accepted_repositories(
    candidate: &SelfPublishState,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    let Some(accepted_config) = accepted.and_then(|state| state.config) else {
        return Ok(());
    };
    for repository in &accepted_config.repositories {
        let Some(current) = candidate.config.repository(&repository.git) else {
            bail!(
                "self-publishing repository {:?} was removed from [[repositories]]; repositories are only ever added",
                repository.git
            );
        };
        ensure!(
            current.tag_prefix == repository.tag_prefix,
            "self-publishing repository {:?} changed tag-prefix from {:?} to {:?}; prefixes are permanent",
            repository.git,
            repository.tag_prefix,
            current.tag_prefix
        );
    }
    Ok(())
}

fn check_abandoned(
    candidate: &SelfPublishState,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    for record in &candidate.config.abandoned {
        ensure!(
            candidate
                .lock
                .entry(&record.name, &record.version)
                .is_some(),
            "abandoned record {} {} names no entry of {LOCK_FILE}",
            record.name,
            record.version
        );
    }
    let Some(accepted_config) = accepted.and_then(|state| state.config) else {
        return Ok(());
    };
    for record in &accepted_config.abandoned {
        let Some(current) = candidate
            .config
            .abandoned_version(&record.name, &record.version)
        else {
            bail!(
                "abandoned record {} {} was removed; records are only ever added",
                record.name,
                record.version
            );
        };
        ensure!(
            current == record,
            "abandoned record {} {} changed; records are only ever added, never changed",
            record.name,
            record.version
        );
    }
    Ok(())
}

fn check_name_permanence(
    candidate: &SelfPublishState,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    let Some(accepted_state) = accepted else {
        return Ok(());
    };
    let (Some(accepted_config), Some(accepted_lock)) = (accepted_state.config, accepted_state.lock)
    else {
        return Ok(());
    };
    let mut crates = BTreeSet::new();
    for entry in &accepted_lock.packages {
        crates.insert(entry.name.as_str());
    }
    for crate_name in crates {
        let versions = accepted_lock
            .packages
            .iter()
            .filter(|entry| entry.name == crate_name)
            .map(|entry| &entry.version);
        if candidate.config.all_abandoned(crate_name, versions) {
            continue;
        }
        let before = accepted_config.names.get(crate_name);
        let after = candidate.config.names.get(crate_name);
        ensure!(
            before == after,
            "the crates.io name of {crate_name:?} is permanent while any of its {LOCK_FILE} entries is not abandoned; its [names] entry changed from {before:?} to {after:?}"
        );
        ensure!(
            accepted_config.effective_name(crate_name)
                == candidate.config.effective_name(crate_name),
            "the crates.io name of {crate_name:?} is permanent while any of its {LOCK_FILE} entries is not abandoned"
        );
    }
    Ok(())
}

fn check_entries(
    candidate: &SelfPublishState,
    catalog: &CatalogSnapshot,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    let config = &candidate.config;
    let accepted_lock = accepted.and_then(|state| state.lock);
    let mut identities: BTreeMap<(&str, &Version), &CatalogIdentity> = BTreeMap::new();
    for identity in self_published_identities(catalog, config) {
        identities.insert((identity.name.as_str(), &identity.version), identity);
    }
    for ((name, version), identity) in &identities {
        let Some(entry) = candidate.lock.entry(name, version) else {
            bail!(
                "self-published identity {name} {version} of registry/{CATALOG_REGISTRY}.lock has no entry in {LOCK_FILE}"
            );
        };
        let (_, release) = release_of(config, identity)
            .expect("a self-published identity comes from a release tag");
        ensure!(
            entry.pkgre_crate_sha256 == identity.crate_sha256,
            "entry {name} {version} records pkgre archive checksum {:?} but registry/{CATALOG_REGISTRY}.lock records {:?}",
            entry.pkgre_crate_sha256,
            identity.crate_sha256
        );
        ensure!(
            entry.git == release.git,
            "entry {name} {version} records repository {:?} but registry/{CATALOG_REGISTRY}.lock records {:?}",
            entry.git,
            release.git
        );
        ensure!(
            entry.tag == release.tag,
            "entry {name} {version} records tag {:?} but registry/{CATALOG_REGISTRY}.lock records {:?}",
            entry.tag,
            release.tag
        );
        ensure!(
            entry.commit == release.commit,
            "entry {name} {version} records commit {:?} but registry/{CATALOG_REGISTRY}.lock records {:?}",
            entry.commit,
            release.commit
        );
        ensure!(
            entry.cargo_version == release.cargo_version,
            "entry {name} {version} records cargo-version {} but registry/{CATALOG_REGISTRY}.lock records {}",
            entry.cargo_version,
            release.cargo_version
        );
        if accepted_lock.is_none_or(|lock| lock.entry(name, version).is_none()) {
            let effective = config.effective_name(name);
            ensure!(
                entry.crates_io_name == effective,
                "new entry {name} {version} records crates.io name {:?} but the mapping gives {effective:?}",
                entry.crates_io_name
            );
        }
    }
    for entry in &candidate.lock.packages {
        ensure!(
            identities.contains_key(&(entry.name.as_str(), &entry.version)),
            "entry {} {} has no self-published identity in registry/{CATALOG_REGISTRY}.lock",
            entry.name,
            entry.version
        );
    }
    Ok(())
}

fn check_names(
    config: &CratesIoConfig,
    catalog: &CatalogSnapshot,
    published: &BTreeSet<&str>,
) -> Result<()> {
    let mirrors = catalog
        .mirrors
        .iter()
        .map(|mirror| name::canonical(mirror))
        .collect::<BTreeSet<_>>();
    let mut used = BTreeMap::new();
    for &crate_name in published {
        let effective = config.effective_name(crate_name);
        name::validate(&effective)
            .with_context(|| format!("validate crates.io name of crate {crate_name:?}"))?;
        ensure!(
            !mirrors.contains(&name::canonical(&effective)),
            "crates.io name {effective:?} of crate {crate_name:?} is the name of a crate that registry/{CATALOG_REGISTRY} mirrors"
        );
        record_name(&mut used, &effective, crate_name)?;
    }
    for (crate_name, mapped) in &config.names {
        name::validate(mapped)
            .with_context(|| format!("validate mapped crates.io name of crate {crate_name:?}"))?;
        ensure!(
            !name::is_in_default_namespace(mapped),
            "mapped crates.io name {mapped:?} of crate {crate_name:?} is in the pkgre-pkgs- namespace, which the default rule owns"
        );
        ensure!(
            !mirrors.contains(&name::canonical(mapped)),
            "mapped crates.io name {mapped:?} of crate {crate_name:?} is the name of a crate that registry/{CATALOG_REGISTRY} mirrors"
        );
        record_name(&mut used, mapped, crate_name)?;
    }
    let catalog_names = catalog
        .identities
        .iter()
        .map(|identity| identity.name.as_str())
        .collect::<BTreeSet<_>>();
    for key in config.names.keys() {
        ensure!(
            published.contains(key.as_str()) || !catalog_names.contains(key.as_str()),
            "[names] key {key:?} names crate {key:?}, which registry/{CATALOG_REGISTRY} publishes from a mirror or from a repository that does not self-publish; the stale key must go"
        );
    }
    let mapped = config
        .names
        .values()
        .map(|name| name::canonical(name))
        .collect::<BTreeSet<_>>();
    for mirror in &catalog.mirrors {
        ensure!(
            !name::is_in_default_namespace(mirror),
            "registry/{CATALOG_REGISTRY} mirrors crate {mirror:?}, whose name is in the pkgre-pkgs- namespace that the default rule owns"
        );
        ensure!(
            !mapped.contains(&name::canonical(mirror)),
            "registry/{CATALOG_REGISTRY} mirrors crate {mirror:?}, which is also a mapped crates.io name"
        );
    }
    Ok(())
}

/// Records one crates.io name, refusing a name that another crate already uses.
fn record_name(
    used: &mut BTreeMap<String, String>,
    effective: &str,
    crate_name: &str,
) -> Result<()> {
    let key = name::canonical(effective);
    if let Some(previous) = used.get(&key) {
        ensure!(
            previous.as_str() == crate_name,
            "crates {previous:?} and {crate_name:?} both use the crates.io name {effective:?}: crates.io ignores case and treats `-` and `_` as the same character"
        );
    } else {
        used.insert(key, crate_name.to_owned());
    }
    Ok(())
}

fn check_gained_release_tags(
    config: &CratesIoConfig,
    catalog: &CatalogSnapshot,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    // Which identities a run adds is a comparison with the accepted state.
    let Some(accepted) = accepted else {
        return Ok(());
    };
    let accepted_identities: BTreeSet<(&str, &Version)> = accepted
        .catalog
        .identities
        .iter()
        .map(|identity| (identity.name.as_str(), &identity.version))
        .collect();
    for identity in &catalog.identities {
        if accepted_identities.contains(&(identity.name.as_str(), &identity.version)) {
            continue;
        }
        let Some((prefix, release)) = release_of(config, identity) else {
            continue;
        };
        let expected = format!("{prefix}{}", identity.version);
        ensure!(
            release.tag == expected,
            "Git identity {} {} was added from tag {:?} of {:?}, but a tag of a self-publishing repository is its tag-prefix followed by the version: {expected:?}",
            identity.name,
            identity.version,
            release.tag,
            release.git
        );
    }
    Ok(())
}

fn check_versions(
    config: &CratesIoConfig,
    self_published: &[&CatalogIdentity],
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    for identity in self_published {
        ensure!(
            identity.version.build.is_empty(),
            "release {} {} carries build metadata, which Cargo and crates.io ignore for identity",
            identity.name,
            identity.version
        );
    }
    let empty = CatalogSnapshot::default();
    let accepted_catalog = accepted.map_or(&empty, |state| state.catalog);
    let accepted_identities: BTreeSet<(&str, &Version)> = accepted_catalog
        .identities
        .iter()
        .map(|identity| (identity.name.as_str(), &identity.version))
        .collect();
    let mut crate_maxima: BTreeMap<&str, &Version> = BTreeMap::new();
    let mut repository_maxima: BTreeMap<&str, &Version> = BTreeMap::new();
    for identity in &accepted_catalog.identities {
        let current = crate_maxima.get(identity.name.as_str()).copied();
        if current.is_none_or(|maximum| maximum < &identity.version) {
            crate_maxima.insert(&identity.name, &identity.version);
        }
        let Some((prefix, release)) = release_of(config, identity) else {
            continue;
        };
        if !is_release_tag(prefix, identity, release) {
            continue;
        }
        let current = repository_maxima.get(release.git.as_str()).copied();
        if current.is_none_or(|maximum| maximum < &identity.version) {
            repository_maxima.insert(&release.git, &identity.version);
        }
    }
    for identity in self_published {
        if accepted_identities.contains(&(identity.name.as_str(), &identity.version)) {
            continue;
        }
        if let Some(maximum) = crate_maxima.get(identity.name.as_str()) {
            ensure!(
                identity.version > **maximum,
                "release {} {} does not increase the version of the crate: registry/{CATALOG_REGISTRY}.lock already holds {maximum}",
                identity.name,
                identity.version
            );
        }
        let (_, release) = release_of(config, identity)
            .expect("a self-published identity comes from a release tag");
        if let Some(maximum) = repository_maxima.get(release.git.as_str()) {
            ensure!(
                identity.version > **maximum,
                "release {} {} does not increase the release version of {:?}: registry/{CATALOG_REGISTRY}.lock already holds {maximum}",
                identity.name,
                identity.version,
                release.git
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
