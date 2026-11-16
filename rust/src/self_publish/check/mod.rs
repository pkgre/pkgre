//! The checks of the self-publishing state against the catalog, against an
//! accepted repository, and, for the releases a run adds, against the network.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

use super::catalog::{
    CATALOG_REGISTRY, CatalogIdentity, CatalogSnapshot, GitRelease, is_release_tag,
    published_names, release_of, self_published_identities,
};
use super::config::CratesIoConfig;
use super::lock::CratesIoLock;
use super::name;
use super::network::{self, Services};
use super::state::{LOCK_FILE, RepositoryState, STATE_DIRECTORY, SelfPublishState};

/// What one run of the self-publishing checks found.
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
    /// Releases whose network checks ran.
    pub network_releases: usize,
}

/// Runs the self-publishing checks of one catalog repository.
///
/// `repository` is the directory that holds `registry/` and `self-publish/`.
/// When `accepted` is given, its `registry/` and `self-publish/` are the
/// accepted state: entries, repositories, tag prefixes and abandoned records
/// may only be added there, and versions have to increase. Without an accepted
/// repository the checks that compare against one are skipped, and a repository
/// that has no `self-publish/` directory has nothing to check.
///
/// The network checks read only the releases that the run adds, which are the
/// self-published identities that the accepted catalog does not hold or whose
/// entry the accepted lock does not record, so that an unavailable crates.io or
/// release repository fails only a change that publishes something.
///
/// # Errors
///
/// Returns an error for a missing or invalid catalog, a malformed or
/// non-canonical self-publishing state, a removed self-publishing state, any
/// violation of the name rules, the identity and entry correspondence, the
/// accepted-state comparison, the release-tag convention, or the version rules,
/// and for any network check of an added release that fails.
pub fn check_repository(
    repository: &Path,
    accepted: Option<&Path>,
) -> Result<SelfPublishCheckSummary> {
    check_repository_with(repository, accepted, &Services::live())
}

/// Runs the self-publishing checks of one catalog repository with the given
/// network services.
pub(crate) fn check_repository_with(
    repository: &Path,
    accepted: Option<&Path>,
    services: &Services<'_>,
) -> Result<SelfPublishCheckSummary> {
    let candidate = RepositoryState::load(repository)?;
    let accepted = accepted.map(RepositoryState::load).transpose()?;
    check_state_not_removed(&candidate, accepted.as_ref())?;
    let Some(self_publish) = candidate.self_publish.as_ref() else {
        tracing::info!(
            path = %repository.display(),
            "repository has no self-publish directory; the self-publishing checks are skipped"
        );
        return Ok(SelfPublishCheckSummary::default());
    };
    if accepted.is_none() {
        tracing::info!(
            "self-publishing checks that compare against an accepted state are skipped: no accepted repository was given"
        );
        tracing::info!(
            "the network checks of the releases that a run adds are skipped: no accepted repository was given"
        );
    }
    let accepted_view = accepted.as_ref().map(|state| AcceptedState {
        catalog: &state.catalog,
        config: state.self_publish.as_ref().map(|state| &state.config),
        lock: state.self_publish.as_ref().map(|state| &state.lock),
    });
    let mut summary = check_state(self_publish, &candidate.catalog, accepted_view.as_ref())?;
    if let Some(accepted_view) = accepted_view.as_ref() {
        summary.network_releases =
            network::check_added_releases(&candidate, self_publish, accepted_view, services)?;
    }
    Ok(summary)
}

/// Refuses a candidate that removed the self-publishing state of the accepted repository.
fn check_state_not_removed(
    candidate: &RepositoryState,
    accepted: Option<&RepositoryState>,
) -> Result<()> {
    if candidate.self_publish.is_some() {
        return Ok(());
    }
    ensure!(
        accepted.is_none_or(|state| state.self_publish.is_none()),
        "the accepted repository has a {STATE_DIRECTORY} directory but the candidate does not; the self-publishing state is only ever added"
    );
    Ok(())
}

/// The accepted repository, as far as the candidate is compared with it.
pub(crate) struct AcceptedState<'a> {
    /// The accepted catalog facts.
    pub(crate) catalog: &'a CatalogSnapshot,
    /// The accepted declarations.
    pub(crate) config: Option<&'a CratesIoConfig>,
    /// The accepted entries.
    pub(crate) lock: Option<&'a CratesIoLock>,
}

pub(crate) fn check_state(
    candidate: &SelfPublishState,
    catalog: &CatalogSnapshot,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<SelfPublishCheckSummary> {
    let config = &candidate.config;
    let published = published_names(catalog, config);
    let self_published = self_published_identities(catalog, config);
    check_repository_spelling(config, catalog)?;
    check_accepted_repositories(candidate, accepted)?;
    check_accepted_entries(candidate, accepted)?;
    check_abandoned(candidate, accepted)?;
    check_names(config, catalog, &published)?;
    check_entries(candidate, catalog, accepted)?;
    check_gained_release_tags(config, catalog, accepted)?;
    check_versions(config, catalog, &self_published, accepted)?;
    Ok(SelfPublishCheckSummary {
        declared: true,
        repositories: config.repositories.len(),
        names: config.names.len(),
        entries: candidate.lock.packages.len(),
        identities: self_published.len(),
        accepted: accepted.is_some(),
        network_releases: 0,
    })
}

/// Refuses a repository URL that names a self-publishing repository in another spelling.
///
/// Repositories are matched by their normalized URL, so `https://HOST/owner/repo.git`
/// would otherwise escape the release-tag rule of its declaration; a catalog that
/// uses another spelling has to be corrected instead.
fn check_repository_spelling(config: &CratesIoConfig, catalog: &CatalogSnapshot) -> Result<()> {
    for identity in &catalog.identities {
        let Some(release) = &identity.release else {
            continue;
        };
        check_one_spelling(config, &release.git).with_context(|| {
            format!("check repository of {} {}", identity.name, identity.version)
        })?;
    }
    for (name, git) in &catalog.publish_declarations {
        check_one_spelling(config, git)
            .with_context(|| format!("check repository of the publish declaration of {name:?}"))?;
    }
    Ok(())
}

fn check_one_spelling(config: &CratesIoConfig, git: &str) -> Result<()> {
    let Some(declared) = config.repository(git) else {
        return Ok(());
    };
    ensure!(
        declared.git == git,
        "repository {git:?} is another spelling of the self-publishing repository {:?}; use the declared spelling",
        declared.git
    );
    Ok(())
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
            current.git == repository.git,
            "self-publishing repository {:?} was respelled {:?}; repositories are only ever added in one spelling",
            repository.git,
            current.git
        );
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
    // A version is abandoned after it was released, never in the change that
    // adds it: otherwise a new entry could carry any name, since abandoned
    // entries keep the name crates.io never took.
    if let Some(accepted) = accepted {
        for record in &candidate.config.abandoned {
            let established = accepted.config.is_some_and(|config| {
                config
                    .abandoned_version(&record.name, &record.version)
                    .is_some()
            });
            if established {
                continue;
            }
            ensure!(
                accepted
                    .lock
                    .is_some_and(|lock| { lock.entry(&record.name, &record.version).is_some() }),
                "abandoned record {} {} is new, but names no entry of the accepted {LOCK_FILE}; a version is abandoned in a later change than the one that released it",
                record.name,
                record.version
            );
        }
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

fn check_entries(
    candidate: &SelfPublishState,
    catalog: &CatalogSnapshot,
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    let config = &candidate.config;
    let accepted_lock = accepted.and_then(|state| state.lock);
    let mut identities = BTreeMap::new();
    for (identity, release) in self_published_identities(catalog, config) {
        identities.insert(
            (identity.name.as_str(), &identity.version),
            (identity, release),
        );
    }
    for ((name, version), (identity, release)) in &identities {
        let Some(entry) = candidate.lock.entry(name, version) else {
            bail!(
                "self-published identity {name} {version} of registry/{CATALOG_REGISTRY}.lock has no entry in {LOCK_FILE}"
            );
        };
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
        // An abandoned entry keeps the name crates.io never took, so a crate
        // may be renamed once every one of its entries is abandoned. Only an
        // entry the accepted lock has was released, and check_abandoned refuses
        // a version abandoned in the change that adds it.
        let exempt = config.abandoned_version(name, version).is_some()
            && accepted_lock.is_none_or(|lock| lock.entry(name, version).is_some());
        if !exempt {
            let effective = config.effective_name(name);
            ensure!(
                entry.crates_io_name == effective,
                "entry {name} {version} records crates.io name {:?} but the mapping gives {effective:?}; only an abandoned entry that was released may keep another name",
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
        // A mirror that carries an effective name is refused here; a mapped
        // name of a crate that has no identity yet is checked in the loop below.
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
    let published_canonical = published
        .iter()
        .map(|crate_name| (name::canonical(crate_name), *crate_name))
        .collect::<BTreeMap<_, _>>();
    let catalog_names = catalog
        .identities
        .iter()
        .map(|identity| name::canonical(&identity.name))
        .chain(catalog.mirrors.iter().map(|mirror| name::canonical(mirror)))
        .chain(
            catalog
                .publish_names
                .iter()
                .map(|name| name::canonical(name)),
        )
        .collect::<BTreeSet<_>>();
    for key in config.names.keys() {
        if published.contains(key.as_str()) {
            continue;
        }
        if let Some(actual) = published_canonical.get(&name::canonical(key)) {
            bail!(
                "[names] key {key:?} does not spell the crate name {actual:?} that a self-publishing repository publishes; use the catalog's spelling"
            );
        }
        ensure!(
            !catalog_names.contains(&name::canonical(key)),
            "[names] key {key:?} names a crate that registry/{CATALOG_REGISTRY} declares as a mirror or publishes from a repository that does not self-publish; the stale key must go"
        );
    }
    for mirror in &catalog.mirrors {
        ensure!(
            !name::is_in_default_namespace(mirror),
            "registry/{CATALOG_REGISTRY} mirrors crate {mirror:?}, whose name is in the pkgre-pkgs- namespace that the default rule owns"
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
    let accepted_identities = accepted
        .catalog
        .identities
        .iter()
        .map(|identity| (identity.name.as_str(), &identity.version))
        .collect::<BTreeSet<_>>();
    for identity in &catalog.identities {
        let Some((prefix, release)) = release_of(config, identity) else {
            continue;
        };
        if accepted_identities.contains(&(identity.name.as_str(), &identity.version)) {
            continue;
        }
        let expected = format!("{prefix}{}", identity.version);
        ensure!(
            release.tag == expected,
            "Git identity {} {} was added from tag {:?} of {:?}, but a tag of a self-publishing repository is its tag-prefix followed by the version: {expected:?}",
            identity.name,
            identity.version,
            release.tag,
            release.git
        );
        // A tag that the accepted catalog already released belongs to the crates
        // of its commit; a crate added later was not part of that release.
        if let Some(other) = accepted.catalog.identities.iter().find(|other| {
            release_of(config, other).is_some_and(|(_, other_release)| {
                other_release.git == release.git && other_release.tag == release.tag
            })
        }) {
            bail!(
                "crate {} {} was added to tag {:?} of {:?}, which registry/{CATALOG_REGISTRY}.lock already released for {} {}; a release tag publishes the crates of its commit",
                identity.name,
                identity.version,
                release.tag,
                release.git,
                other.name,
                other.version
            );
        }
    }
    Ok(())
}

fn check_versions(
    config: &CratesIoConfig,
    catalog: &CatalogSnapshot,
    self_published: &[(&CatalogIdentity, &GitRelease)],
    accepted: Option<&AcceptedState<'_>>,
) -> Result<()> {
    for (identity, _) in self_published {
        ensure!(
            identity.version.build.is_empty(),
            "release {} {} carries build metadata, which Cargo and crates.io ignore for identity",
            identity.name,
            identity.version
        );
    }
    // Which identities a run adds is a comparison with the accepted state.
    let Some(accepted) = accepted else {
        return Ok(());
    };
    let accepted_identities = accepted
        .catalog
        .identities
        .iter()
        .map(|identity| (identity.name.as_str(), &identity.version))
        .collect::<BTreeSet<_>>();
    for (identity, release) in self_published {
        if accepted_identities.contains(&(identity.name.as_str(), &identity.version)) {
            continue;
        }
        // The candidate catalog is the reference, not the accepted one, so that
        // two releases added in one change are ordered against each other too.
        for other in &catalog.identities {
            if other.name != identity.name || other.version == identity.version {
                continue;
            }
            ensure!(
                identity.version > other.version,
                "release {} {} does not increase the version of the crate: registry/{CATALOG_REGISTRY}.lock also holds {}",
                identity.name,
                identity.version,
                other.version
            );
        }
        for other in &catalog.identities {
            let Some((other_prefix, other_release)) = release_of(config, other) else {
                continue;
            };
            if other_release.git != release.git || other_release.tag == release.tag {
                continue;
            }
            if !is_release_tag(other_prefix, other, other_release) {
                continue;
            }
            ensure!(
                identity.version > other.version,
                "release {} {} does not increase the release version of {:?}: registry/{CATALOG_REGISTRY}.lock also holds {} from tag {:?}",
                identity.name,
                identity.version,
                release.git,
                other.version,
                other_release.tag
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
