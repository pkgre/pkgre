//! The network checks of the releases that a run adds.
//!
//! A release is added when one of its self-published identities is missing from
//! the accepted catalog, or when its `crates-io.lock` entry is missing from the
//! accepted lock, which covers a new release, a repository newly declared in
//! `[[repositories]]`, and a newly declared `self-publish/` alike. Only such a
//! release is checked, so that an unavailable crates.io or release repository
//! fails only a change that publishes something. Every network read sits behind
//! [`CratesIo`] and [`ReleaseRepository`], so that the tests run offline, and a
//! run that adds no release makes no request at all.

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
use super::derive::{Derivation, MemberFacts, Sources, derive_release_in, retained_crate};
use super::lock::CratesIoPackage;
use super::state::{RepositoryState, SelfPublishState};

pub(crate) use live::{LiveCratesIo, LiveRegistryIndex, LiveReleaseRepository};

/// Most keywords that crates.io accepts on one crate.
const MAX_KEYWORDS: usize = 5;
/// Longest keyword, in bytes, that crates.io accepts.
const MAX_KEYWORD_BYTES: usize = 20;
/// Most categories that crates.io accepts on one crate.
const MAX_CATEGORIES: usize = 5;
/// Longest description, in bytes, that crates.io accepts.
const MAX_DESCRIPTION_BYTES: usize = 1000;
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
    /// Whether crates.io yanked the version.
    pub(crate) yanked: bool,
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

/// A sparse Cargo registry index, as the upload routine reads the `pkgre`
/// registry.
///
/// The routine publishes only what the `pkgre` registry already serves, so it
/// reads the registry's own sparse index with the same rules as crates.io's:
/// bounded documents, no token, and no fallback.
pub(crate) trait RegistryIndex {
    /// Returns every published version of one crate name at one sparse index,
    /// or `None` when the index does not have the crate.
    ///
    /// `index` is the registry's declared index URL, with or without the
    /// `sparse+` prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when the index cannot be read, answers with a failure,
    /// or publishes a document this crate does not understand.
    fn versions(&self, index: &str, name: &str) -> Result<Option<Vec<CratesIoVersion>>>;
}

/// The crate versions of one release, and how its network checks judge them.
pub(crate) struct ReleaseCrates<'a> {
    /// The crate versions of the release, in the order the run names them.
    pub(crate) identities: &'a [CatalogIdentity],
    /// Whether the checks judge a crate version that is abandoned.
    pub(crate) abandoned: Abandoned,
}

/// Whether the network checks of a release judge a crate version that
/// `crates-io.toml` records as abandoned.
///
/// crates.io never takes an abandoned version, so the reasons for abandoning it
/// are exactly the checks that fail for it: a name someone else owns, or a
/// version crates.io holds with another archive. The upload routine therefore
/// skips those checks, so that the rest of the release can still be published,
/// while `self-publish-check` judges every crate version it checks, since an
/// added release cannot be abandoned in the change that adds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Abandoned {
    /// Check the crate version like any other.
    Check,
    /// Skip crates.io's owners, version, and package-rule checks of it.
    Skip,
}

/// What a release tag's repository says about the tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseTag {
    /// The object the tag names, which is the tag object of an annotated tag.
    pub(crate) tag_oid: String,
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
    let releases = added_releases(&state.catalog, &self_publish.config, accepted);
    if releases.is_empty() {
        tracing::info!("the run adds no release; the network checks make no request");
        return Ok(0);
    }
    let mut crates_io = CratesIoState::new(services.crates_io);
    for ((git, tag), identities) in &releases {
        check_release(
            git,
            tag,
            &ReleaseCrates {
                identities,
                abandoned: Abandoned::Check,
            },
            state,
            self_publish,
            services,
            &mut crates_io,
        )
        .map(|_| ())
        .with_context(|| {
            format!("the network checks of release tag {tag:?} of {git:?} must pass")
        })?;
    }
    Ok(releases.len())
}

/// Runs the network checks of one release that the caller names, and returns
/// its derivation.
///
/// [`check_added_releases`] checks the releases that a run adds; the upload
/// routine checks the release it is about to publish, whether or not the run
/// adds it, and keeps the derived workspace for the packaging and the upload
/// that follow.
///
/// # Errors
///
/// Returns the error of [`check_added_releases`] for this release.
pub(crate) fn check_release_named(
    state: &RepositoryState,
    self_publish: &SelfPublishState,
    git: &str,
    tag: &str,
    crates: &ReleaseCrates<'_>,
    services: &Services<'_>,
    crates_io: &mut CratesIoState<'_>,
) -> Result<Derivation> {
    check_release(git, tag, crates, state, self_publish, services, crates_io)
        .with_context(|| format!("the network checks of release tag {tag:?} of {git:?} must pass"))
}

/// Returns the releases that the candidate adds, grouped by repository and tag.
///
/// A self-published identity is added when the accepted catalog does not hold
/// it, or when the accepted `crates-io.lock` does not record it. The second
/// case covers a repository newly declared in `[[repositories]]` and a newly
/// declared `self-publish/`: their identities are already in the accepted
/// catalog, but their entries are new, and entries are permanent once merged.
/// An accepted repository without `self-publish/` records no entry at all.
fn added_releases(
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    accepted: &AcceptedState<'_>,
) -> BTreeMap<(String, String), Vec<CatalogIdentity>> {
    let mut releases: BTreeMap<(String, String), Vec<CatalogIdentity>> = BTreeMap::new();
    for (identity, release) in self_published_identities(catalog, config) {
        let known = accepted
            .catalog
            .identity(&identity.name, &identity.version)
            .is_some();
        let recorded = accepted
            .lock
            .is_some_and(|lock| lock.entry(&identity.name, &identity.version).is_some());
        if known && recorded {
            continue;
        }
        releases
            .entry((release.git.clone(), release.tag.clone()))
            .or_default()
            .push(identity.clone());
    }
    releases
}

/// Runs every network check of one added release, and returns its derivation.
#[allow(clippy::too_many_lines)]
fn check_release(
    git: &str,
    tag: &str,
    crates: &ReleaseCrates<'_>,
    state: &RepositoryState,
    self_publish: &SelfPublishState,
    services: &Services<'_>,
    crates_io: &mut CratesIoState<'_>,
) -> Result<Derivation> {
    let identities = crates.identities;
    let abandoned = crates.abandoned;
    let release = release_of_group(git, tag, identities)?;
    for identity in identities {
        ensure!(
            !identity.removed,
            "the catalog removed {} {}, whose archive it no longer retains, so the release cannot be checked; only an active identity can be",
            identity.name,
            identity.version
        );
    }
    let inspected = services.repositories.inspect_tag(git, tag)?;
    ensure!(
        inspected.annotated,
        "the release tag {tag:?} of {git:?} is lightweight; a release tag is an annotated tag"
    );
    ensure!(
        inspected.tag_oid == release.tag_oid,
        "release tag {tag:?} of {git:?} is object {}, but registry/main.lock records {}",
        inspected.tag_oid,
        release.tag_oid
    );
    ensure!(
        inspected.commit == release.commit,
        "release tag {tag:?} of {git:?} names commit {}, but registry/main.lock records {}",
        inspected.commit,
        release.commit
    );
    ensure!(
        inspected.on_default_branch,
        "commit {} of release tag {tag:?} of {git:?} is not on the repository's default branch {:?}",
        inspected.commit,
        inspected.default_branch
    );

    let expected = expected_owners(&self_publish.config);
    for identity in identities {
        if abandoned == Abandoned::Skip && is_abandoned(self_publish, identity) {
            tracing::info!(
                package = %identity.name,
                version = %identity.version,
                "skipping the crates.io checks of an abandoned crate version, which crates.io never takes"
            );
            continue;
        }
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
    let derived = derive_release_in(
        &release,
        &curated,
        &state.catalog,
        &self_publish.config,
        &self_publish.lock,
        services.derivation.sources(git)?,
    )
    .with_context(|| format!("derive the crates.io packages of release tag {tag:?} of {git:?}"))?;

    let slugs = if derived
        .packages
        .iter()
        .any(|package| !package.facts.categories.is_empty())
    {
        crates_io.category_slugs()?
    } else {
        BTreeSet::new()
    };
    for package in &derived.packages {
        let entry = entry_of(self_publish, &package.entry.name, &package.entry.version)?;
        ensure!(
            package.entry.crate_sha256 == entry.crate_sha256,
            "the derivation of {} {} reproduces the crates.io archive {}, but crates-io.lock records {}",
            package.entry.name,
            package.entry.version,
            package.entry.crate_sha256,
            entry.crate_sha256
        );
        if abandoned == Abandoned::Skip
            && self_publish
                .config
                .abandoned_version(&package.entry.name, &package.entry.version)
                .is_some()
        {
            continue;
        }
        check_crates_io_rules(
            &package.entry.name,
            &package.entry.version,
            &package.facts,
            package.archive.len(),
            &slugs,
        )?;
    }
    Ok(derived)
}

/// Returns whether `crates-io.toml` records one crate version as abandoned.
fn is_abandoned(self_publish: &SelfPublishState, identity: &CatalogIdentity) -> bool {
    self_publish
        .config
        .abandoned_version(&identity.name, &identity.version)
        .is_some()
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
            .find(|published| same_version(&published.version, &identity.version))
    {
        ensure!(
            published.checksum == entry.crate_sha256,
            "crates.io has crate {} version {} with archive checksum {}, but crates-io.lock records {} for {} {}",
            entry.crates_io_name,
            published.version,
            published.checksum,
            entry.crate_sha256,
            identity.name,
            identity.version
        );
    }
    Ok(())
}

/// Returns whether two versions are the same published version.
///
/// Cargo and crates.io ignore build metadata for identity, so `0.5.0+build`
/// and `0.5.0` are one version there, and a sparse index lists one row for it.
pub(crate) fn same_version(left: &Version, right: &Version) -> bool {
    left.major == right.major
        && left.minor == right.minor
        && left.patch == right.patch
        && left.pre == right.pre
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
/// has instead: a missing or too long description, a missing license, too many
/// keywords or a keyword that crates.io refuses, too many categories or one
/// that crates.io does not know, an archive over crates.io's upload limit, a
/// dependency whose requirement is the wildcard `*`, or a homepage,
/// documentation, or repository URL that crates.io would refuse. The SPDX
/// license expression itself is not checked.
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
    if let Some(description) = &facts.description {
        ensure!(
            description.len() <= MAX_DESCRIPTION_BYTES,
            "crate {name} {version} has a description of {} bytes, but crates.io takes at most {MAX_DESCRIPTION_BYTES}",
            description.len()
        );
    }
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
        facts.wildcard_dependencies.is_empty(),
        "crate {name} {version} requires {:?} with the wildcard requirement \"*\", which crates.io refuses: a dependency requirement must name a version range",
        facts.wildcard_dependencies
    );
    ensure!(
        archive_bytes <= MAX_ARCHIVE_BYTES,
        "crate {name} {version} has a crates.io archive of {archive_bytes} bytes, but crates.io takes at most {MAX_ARCHIVE_BYTES}"
    );
    ensure!(
        facts.categories.len() <= MAX_CATEGORIES,
        "crate {name} {version} has {} categories, but crates.io takes at most {MAX_CATEGORIES}",
        facts.categories.len()
    );
    for category in &facts.categories {
        ensure!(
            category_slugs.contains(category),
            "crate {name} {version} declares the category {category:?}, which is not one of crates.io's category slugs"
        );
    }
    for (field, url) in [
        ("homepage", &facts.homepage),
        ("documentation", &facts.documentation),
        ("repository", &facts.repository),
    ] {
        if let Some(url) = url {
            ensure!(
                is_http_url(url),
                "crate {name} {version} has the {field} {url:?}, but crates.io requires an http or https URL with an authority"
            );
        }
    }
    Ok(())
}

/// Returns whether crates.io accepts one manifest URL.
///
/// crates.io requires `http://` or `https://` and a URL that parses; without a
/// URL parser this check requires the scheme, an authority, and no whitespace
/// or control character, which is what a manifest can carry into the package.
fn is_http_url(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .expect("a split yields at least one part");
    !authority.is_empty()
        && !url
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
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
pub(crate) struct CratesIoState<'a> {
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
    pub(crate) fn new(crates_io: &'a dyn CratesIo) -> Self {
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
    pub(crate) fn versions(&mut self, name: &str) -> Result<&Option<Vec<CratesIoVersion>>> {
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
