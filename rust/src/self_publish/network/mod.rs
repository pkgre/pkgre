//! The network checks of the releases that a run adds.
//!
//! A run checks only the releases it adds: the self-published identities that
//! the candidate has and the accepted repository does not, so that an
//! unavailable crates.io or release repository fails only a change that
//! publishes something. Every network read sits behind [`CratesIo`] and
//! [`ReleaseRepository`], so that the tests run offline, and a run that adds no
//! release makes no request at all.

mod live;

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use semver::Version;

use super::catalog::{
    CatalogIdentity, CatalogSnapshot, release_of_group, self_published_identities,
};
use super::check::AcceptedState;
use super::config::CratesIoConfig;
use super::derive::{MemberFacts, Sources, derive_release_with, retained_crate};
use super::lock::CratesIoPackage;
use super::state::{RepositoryState, SelfPublishState};

pub(crate) use live::{LiveCratesIo, LiveReleaseRepository};

/// Most keywords that crates.io accepts on one crate.
const MAX_KEYWORDS: usize = 5;
/// Longest keyword, in bytes, that crates.io accepts.
const MAX_KEYWORD_BYTES: usize = 20;
/// Largest archive, in bytes, that crates.io accepts.
const MAX_ARCHIVE_BYTES: usize = 10 * 1024 * 1024;

/// One owner of one crates.io crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Owner {
    /// The login: a GitHub login for a user, `github:ORG:TEAM` for a team.
    pub(crate) login: String,
    /// Whether the owner is a user or a team.
    pub(crate) kind: OwnerKind,
}

/// The kind of one crates.io owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerKind {
    /// A user, whose login is a GitHub login.
    User,
    /// A team of an organization.
    Team,
}

/// One version of one crates.io crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CratesIoVersion {
    /// Exact published version.
    pub(crate) version: Version,
    /// SHA-256 of the published `.crate` archive.
    pub(crate) checksum: String,
}

/// crates.io, as the checks and the upload routine read it.
///
/// The upload routine reads the same facts to decide, for each crate version,
/// whether crates.io already has it with the recorded checksum, lacks it, or
/// holds different bytes.
pub(crate) trait CratesIo {
    /// Returns the owners of one crate name, or `None` when crates.io has no
    /// such crate.
    ///
    /// # Errors
    ///
    /// Returns an error when crates.io cannot be read or answers with a
    /// failure.
    fn owners(&self, name: &str) -> Result<Option<Vec<Owner>>>;

    /// Returns every published version of one crate name, or `None` when
    /// crates.io has no such crate.
    ///
    /// # Errors
    ///
    /// Returns an error when crates.io cannot be read, answers with a failure,
    /// or publishes a document this crate does not understand.
    fn versions(&self, name: &str) -> Result<Option<Vec<CratesIoVersion>>>;

    /// Returns the category slugs that crates.io knows.
    ///
    /// # Errors
    ///
    /// Returns an error when crates.io cannot be read or answers with a
    /// failure.
    fn category_slugs(&self) -> Result<BTreeSet<String>>;
}

/// What a release tag's repository says about the tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseTag {
    /// The peeled commit of the tag.
    pub(crate) commit: String,
    /// Whether the tag is annotated.
    pub(crate) annotated: bool,
    /// Whether the commit is on the repository's default branch.
    pub(crate) on_default_branch: bool,
    /// The default branch the commit was tested against.
    pub(crate) default_branch: String,
}

/// A release repository, as the checks read it.
pub(crate) trait ReleaseRepository {
    /// Reads one release tag and its position in the repository.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository cannot be reached or read, or when
    /// it does not hold the tag.
    fn inspect_tag(&self, git: &str, tag: &str) -> Result<ReleaseTag>;
}

/// How a run reads the sources of a release's derivation.
pub(crate) enum DerivationSources {
    /// Fetch the tag from the network and package against crates.io.
    Live,
    /// Local stand-ins, which only a test names.
    #[cfg(test)]
    Local(LocalSources),
}

/// Local stand-ins for the network, which only a test can build.
#[cfg(test)]
pub(crate) struct LocalSources {
    /// Repository URL, as the catalog spells it, to the local repository that
    /// stands in for it.
    pub(crate) repositories: BTreeMap<String, PathBuf>,
    /// A local directory source that replaces crates.io.
    pub(crate) directory: Option<PathBuf>,
    /// The directory to work in, which no Cargo configuration may cover.
    pub(crate) root: PathBuf,
}

impl DerivationSources {
    /// Returns the sources of the derivation of one release.
    ///
    /// # Errors
    ///
    /// Returns an error when a test names no local repository for `git`.
    #[cfg_attr(not(test), allow(unused_variables, clippy::unnecessary_wraps))]
    fn sources(&self, git: &str) -> Result<Sources<'_>> {
        match self {
            Self::Live => Ok(Sources::network()),
            #[cfg(test)]
            Self::Local(local) => Ok(Sources::local(
                local
                    .repositories
                    .get(git)
                    .with_context(|| format!("no local repository stands in for {git:?}"))?,
                local.directory.as_deref(),
                &local.root,
            )),
        }
    }
}

/// The services that the network checks read.
pub(crate) struct Services<'a> {
    /// crates.io.
    pub(crate) crates_io: &'a dyn CratesIo,
    /// The release repositories.
    pub(crate) repositories: &'a dyn ReleaseRepository,
    /// The sources of each release's derivation.
    pub(crate) derivation: DerivationSources,
}

static LIVE_CRATES_IO: LiveCratesIo = LiveCratesIo;
static LIVE_RELEASE_REPOSITORIES: LiveReleaseRepository = LiveReleaseRepository;

impl Services<'static> {
    /// Returns the services of a production run: the network and crates.io.
    pub(crate) fn live() -> Self {
        Self {
            crates_io: &LIVE_CRATES_IO,
            repositories: &LIVE_RELEASE_REPOSITORIES,
            derivation: DerivationSources::Live,
        }
    }
}

/// Runs the network checks of every release that the run adds.
///
/// Returns the number of releases that were checked. A run that adds no release
/// makes no request.
///
/// # Errors
///
/// Returns an error when a service cannot be read, when a release tag is
/// lightweight or off the default branch, when a crates.io name or version does
/// not match the recorded state, when a crate breaks crates.io's own rules, or
/// when the derivation does not reproduce the recorded archive.
pub(crate) fn check_added_releases(
    state: &RepositoryState,
    self_publish: &SelfPublishState,
    accepted: &AcceptedState<'_>,
    services: &Services<'_>,
) -> Result<usize> {
    let releases = added_releases(&state.catalog, &self_publish.config, accepted.catalog);
    if releases.is_empty() {
        tracing::info!("the run adds no release; the network checks make no request");
        return Ok(0);
    }
    let mut crates_io = CratesIoState::new(services.crates_io);
    for ((git, tag), identities) in &releases {
        check_release(
            git,
            tag,
            identities,
            state,
            self_publish,
            services,
            &mut crates_io,
        )
        .with_context(|| {
            format!("the network checks of release tag {tag:?} of {git:?} must pass")
        })?;
    }
    Ok(releases.len())
}

/// Returns the releases that the candidate adds, grouped by repository and tag.
fn added_releases(
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    accepted: &CatalogSnapshot,
) -> BTreeMap<(String, String), Vec<CatalogIdentity>> {
    let mut releases: BTreeMap<(String, String), Vec<CatalogIdentity>> = BTreeMap::new();
    for (identity, release) in self_published_identities(catalog, config) {
        if accepted
            .identity(&identity.name, &identity.version)
            .is_some()
        {
            continue;
        }
        releases
            .entry((release.git.clone(), release.tag.clone()))
            .or_default()
            .push(identity.clone());
    }
    releases
}

/// Runs every network check of one added release.
#[allow(clippy::too_many_lines)]
fn check_release(
    git: &str,
    tag: &str,
    identities: &[CatalogIdentity],
    state: &RepositoryState,
    self_publish: &SelfPublishState,
    services: &Services<'_>,
    crates_io: &mut CratesIoState<'_>,
) -> Result<()> {
    let release = release_of_group(git, tag, identities)?;
    let inspected = services.repositories.inspect_tag(git, tag)?;
    ensure!(
        inspected.annotated,
        "the release tag {tag:?} of {git:?} is lightweight; a release tag is an annotated tag"
    );
    ensure!(
        inspected.on_default_branch,
        "commit {} of release tag {tag:?} of {git:?} is not on the repository's default branch {:?}",
        inspected.commit,
        inspected.default_branch
    );

    let expected = expected_owners(&self_publish.config);
    for identity in identities {
        let entry = entry_of(self_publish, &identity.name, &identity.version)?;
        check_name(identity, entry, &expected, crates_io)?;
    }

    let curated = identities
        .iter()
        .map(|identity| {
            retained_crate(&state.catalog_root, identity).with_context(|| {
                format!(
                    "read the curated archive of {} {}",
                    identity.name, identity.version
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let derived = derive_release_with(
        &release,
        &curated,
        &state.catalog,
        &self_publish.config,
        &self_publish.lock,
        services.derivation.sources(git)?,
    )
    .with_context(|| format!("derive the crates.io packages of release tag {tag:?} of {git:?}"))?;

    let slugs = if derived
        .iter()
        .any(|package| !package.facts.categories.is_empty())
    {
        crates_io.category_slugs()?
    } else {
        BTreeSet::new()
    };
    for package in &derived {
        let entry = entry_of(self_publish, &package.entry.name, &package.entry.version)?;
        ensure!(
            package.entry.crate_sha256 == entry.crate_sha256,
            "the derivation of {} {} reproduces the crates.io archive {}, but crates-io.lock records {}",
            package.entry.name,
            package.entry.version,
            package.entry.crate_sha256,
            entry.crate_sha256
        );
        check_crates_io_rules(
            &package.entry.name,
            &package.entry.version,
            &package.facts,
            package.archive.len(),
            &slugs,
        )?;
    }
    Ok(())
}

/// Returns the `crates-io.lock` entry of one crate version.
fn entry_of<'a>(
    self_publish: &'a SelfPublishState,
    name: &str,
    version: &Version,
) -> Result<&'a CratesIoPackage> {
    self_publish.lock.entry(name, version).with_context(|| {
        format!("self-published identity {name} {version} has no entry in crates-io.lock")
    })
}

/// Checks the crates.io name and version of one added crate version.
fn check_name(
    identity: &CatalogIdentity,
    entry: &CratesIoPackage,
    expected_owners: &BTreeSet<String>,
    crates_io: &mut CratesIoState<'_>,
) -> Result<()> {
    if let Some(owners) = crates_io.owners(&entry.crates_io_name)? {
        check_owners(&entry.crates_io_name, expected_owners, owners).with_context(|| {
            format!(
                "the crates.io owners check of {} {} could not pass",
                identity.name, identity.version
            )
        })?;
    }
    if let Some(versions) = crates_io.versions(&entry.crates_io_name)?
        && let Some(published) = versions
            .iter()
            .find(|published| published.version == identity.version)
    {
        ensure!(
            published.checksum == entry.crate_sha256,
            "crates.io has crate {} version {} with archive checksum {}, but crates-io.lock records {} for {} {}",
            entry.crates_io_name,
            identity.version,
            published.checksum,
            entry.crate_sha256,
            identity.name,
            identity.version
        );
    }
    Ok(())
}

/// Checks that crates.io's owners of one crate name are the expected users.
fn check_owners(crates_io_name: &str, expected: &BTreeSet<String>, owners: &[Owner]) -> Result<()> {
    let teams = owners
        .iter()
        .filter(|owner| owner.kind == OwnerKind::Team)
        .map(|owner| owner.login.as_str())
        .collect::<Vec<_>>();
    ensure!(
        teams.is_empty(),
        "crates.io crate {crates_io_name:?} is also owned by the team {teams:?}, but self-publish/crates-io.toml expects only the users {expected:?}"
    );
    let found = owners
        .iter()
        .map(|owner| owner.login.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    ensure!(
        found == *expected,
        "crates.io crate {crates_io_name:?} is owned by {found:?}, but self-publish/crates-io.toml expects exactly the users {expected:?}"
    );
    Ok(())
}

/// Checks one crate version against crates.io's own rules for a package.
///
/// # Errors
///
/// Returns an error naming the crate, the version, the rule, and what the crate
/// has instead: a missing description or license, too many keywords or a
/// keyword that crates.io refuses, an archive over crates.io's upload limit, or
/// a category that crates.io does not know.
fn check_crates_io_rules(
    name: &str,
    version: &Version,
    facts: &MemberFacts,
    archive_bytes: usize,
    category_slugs: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        facts
            .description
            .as_deref()
            .is_some_and(|description| !description.trim().is_empty()),
        "crate {name} {version} has no description, which crates.io requires"
    );
    let licensed = facts
        .license
        .as_deref()
        .is_some_and(|license| !license.trim().is_empty());
    let license_file = facts
        .license_file
        .as_deref()
        .is_some_and(|path| !path.as_os_str().is_empty());
    ensure!(
        licensed || license_file,
        "crate {name} {version} has neither a license nor a license-file, one of which crates.io requires"
    );
    ensure!(
        facts.keywords.len() <= MAX_KEYWORDS,
        "crate {name} {version} has {} keywords, but crates.io takes at most {MAX_KEYWORDS}",
        facts.keywords.len()
    );
    for keyword in &facts.keywords {
        ensure!(
            keyword.len() <= MAX_KEYWORD_BYTES,
            "crate {name} {version} has the keyword {keyword:?}, which is longer than crates.io's {MAX_KEYWORD_BYTES} bytes"
        );
        ensure!(
            is_valid_keyword(keyword),
            "crate {name} {version} has the keyword {keyword:?}, which crates.io refuses: a keyword starts with an ASCII alphanumeric and continues with ASCII alphanumerics, `-`, `_` or `+`"
        );
    }
    ensure!(
        archive_bytes <= MAX_ARCHIVE_BYTES,
        "crate {name} {version} has a crates.io archive of {archive_bytes} bytes, but crates.io takes at most {MAX_ARCHIVE_BYTES}"
    );
    for category in &facts.categories {
        ensure!(
            category_slugs.contains(category),
            "crate {name} {version} declares the category {category:?}, which is not one of crates.io's category slugs"
        );
    }
    Ok(())
}

/// Returns whether crates.io accepts one keyword.
fn is_valid_keyword(keyword: &str) -> bool {
    let mut characters = keyword.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '+')
        })
}

/// Returns the crates.io logins that `crates-io.toml` expects, in comparison form.
fn expected_owners(config: &CratesIoConfig) -> BTreeSet<String> {
    config
        .owners
        .iter()
        .map(|login| login.to_ascii_lowercase())
        .collect()
}

/// The crates.io facts of one run, read once per crate name.
struct CratesIoState<'a> {
    /// crates.io.
    crates_io: &'a dyn CratesIo,
    /// Owners by crate name.
    owners: BTreeMap<String, Option<Vec<Owner>>>,
    /// Versions by crate name.
    versions: BTreeMap<String, Option<Vec<CratesIoVersion>>>,
    /// crates.io's category slugs, once a crate declares a category.
    category_slugs: Option<BTreeSet<String>>,
}

impl<'a> CratesIoState<'a> {
    /// Returns the state of one run.
    fn new(crates_io: &'a dyn CratesIo) -> Self {
        Self {
            crates_io,
            owners: BTreeMap::new(),
            versions: BTreeMap::new(),
            category_slugs: None,
        }
    }

    /// Returns the owners of one crate name, reading them at most once.
    fn owners(&mut self, name: &str) -> Result<&Option<Vec<Owner>>> {
        if !self.owners.contains_key(name) {
            let owners = self.crates_io.owners(name)?;
            self.owners.insert(name.to_owned(), owners);
        }
        Ok(&self.owners[name])
    }

    /// Returns the versions of one crate name, reading them at most once.
    fn versions(&mut self, name: &str) -> Result<&Option<Vec<CratesIoVersion>>> {
        if !self.versions.contains_key(name) {
            let versions = self.crates_io.versions(name)?;
            self.versions.insert(name.to_owned(), versions);
        }
        Ok(&self.versions[name])
    }

    /// Returns crates.io's category slugs, reading them at most once.
    fn category_slugs(&mut self) -> Result<BTreeSet<String>> {
        if let Some(slugs) = &self.category_slugs {
            return Ok(slugs.clone());
        }
        let slugs = self.crates_io.category_slugs()?;
        self.category_slugs = Some(slugs.clone());
        Ok(slugs)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/self_publish/network/mod.rs"]
mod tests;
