//! The `self-publish` command: publishing one release to crates.io from a local
//! checkout.
//!
//! A run reads a checkout of the catalog repository whose `HEAD` is merged into
//! the remote-tracking `origin/main`, checks the release with the same offline
//! and network checks as `self-publish-check`, requires the `pkgre` registry to
//! serve every crate version of the release, and reads crates.io's state for
//! each of them and for every package outside the release that it depends on.
//! A dry run stops there and reports what an upload would do.
//!
//! With `--upload`, and only once every check passed, a run builds the missing
//! crates with Cargo's verification while no token is in reach, reads the token,
//! uploads only the missing crates, waits until crates.io's index shows each of
//! them with the recorded checksum, and reports every crate version of the
//! release. A run after a partial failure uploads only what is still missing,
//! and a run whose crates crates.io all has reads no token and uploads nothing.
//!
//! The routine never yanks, deletes, or changes owners, and never replaces a
//! crates.io version that holds another archive.

mod checkout;
mod live;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use tracing::{info, warn};

use super::catalog::{CatalogIdentity, CatalogSnapshot, self_published_identities};
use super::check::check_state;
use super::config::{CratesIoConfig, normalized_git};
use super::derive::{Derivation, DerivedDependency, DerivedWorkspace};
use super::isolation::ChildEnvironment;
use super::lock::CratesIoPackage;
use super::network::{
    self, Abandoned, CratesIoState, RegistryIndex, Services as NetworkServices, same_version,
};
use super::state::{RepositoryState, SelfPublishState};
use crate::artifact::sha256_bytes;
use crate::policy::validate_git_tag;

/// Most times a run reads crates.io's index while waiting for one upload.
const LIVE_WAIT_ATTEMPTS: usize = 60;
/// Delay between two reads of crates.io's index while waiting for one upload.
const LIVE_WAIT_INTERVAL: Duration = Duration::from_secs(5);

/// What one run of `self-publish` found and did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfPublishSummary {
    /// The release tag the run published.
    pub tag: String,
    /// The self-publishing repository the tag belongs to.
    pub git: String,
    /// Whether the run could upload, which `--upload` asks for.
    pub upload: bool,
    /// One record per crate version of the release, in name order.
    pub crates: Vec<SelfPublishCrate>,
    /// Crate versions crates.io already had with the recorded checksum.
    pub published: usize,
    /// Crate versions crates.io already had, and yanked.
    pub yanked: usize,
    /// Crate versions a dry run would upload.
    pub would_upload: usize,
    /// Crate versions the run uploaded.
    pub uploaded: usize,
    /// Crate versions the run skipped because they are abandoned.
    pub abandoned: usize,
    /// Packages outside the release whose crates.io state the run checked.
    pub dependencies: usize,
    /// Dependencies whose crates.io version is yanked.
    pub yanked_dependencies: usize,
}

/// One crate version of a release, and what the run found for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfPublishCrate {
    /// Cargo package name in the `pkgre` registry.
    pub name: String,
    /// Exact version.
    pub version: Version,
    /// crates.io name of this exact version.
    pub crates_io_name: String,
    /// The state of the crate version on crates.io.
    pub state: SelfPublishCrateState,
}

/// The state of one crate version of a release on crates.io.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelfPublishCrateState {
    /// crates.io has the version with the recorded checksum.
    Published,
    /// crates.io has the version with the recorded checksum, and yanked it.
    PublishedYanked,
    /// crates.io does not have the version; a dry run would upload it.
    Missing,
    /// The run uploaded the version, and crates.io's index now shows it.
    Uploaded,
    /// `crates-io.toml` records the version as abandoned, so the run skipped it.
    Abandoned,
    /// crates.io has the version with another checksum, so the run refused.
    Different {
        /// The archive checksum that crates.io serves.
        found: String,
    },
}

impl SelfPublishCrateState {
    /// Returns one word for the state, as a report spells it.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::PublishedYanked => "published-yanked",
            Self::Missing => "missing",
            Self::Uploaded => "uploaded",
            Self::Abandoned => "abandoned",
            Self::Different { .. } => "different",
        }
    }
}

/// Publishes one release of a self-publishing repository to crates.io.
///
/// `repository` is a checkout of the catalog repository, the directory that
/// holds `registry/` and `self-publish/`; `tag` is a release tag such as
/// `rust/v0.5.0`. Without `upload` the run is a dry run: it runs every check an
/// upload needs and reports what the upload would do. `git` chooses among
/// several self-publishing repositories that use the same release tag, which
/// the run refuses without it.
///
/// # Errors
///
/// Returns an error when the environment holds a Cargo registry token, when the
/// checkout is dirty or its `HEAD` is not merged into `origin/main`, when the
/// repository has no self-publishing state, when an offline or network check of
/// the release fails, when the `pkgre` registry does not serve a crate version
/// of the release unyanked with its recorded checksum, when crates.io holds
/// another archive or lacks a dependency of the release, when a verified
/// package differs from `crates-io.lock`, when the token is empty, when an
/// upload fails, or when crates.io's index does not show an uploaded crate
/// within the bound.
pub fn self_publish(
    repository: &Path,
    tag: &str,
    upload: bool,
    git: Option<&str>,
) -> Result<SelfPublishSummary> {
    run(repository, tag, upload, git, &Services::live())
}

/// The services that one run reads, and how long it waits for an upload.
pub(crate) struct Services<'a> {
    /// crates.io and the release repositories.
    pub(crate) network: NetworkServices<'a>,
    /// The `pkgre` registry's sparse index.
    pub(crate) registry: &'a dyn RegistryIndex,
    /// How the run builds the crates it would upload.
    pub(crate) verification: Verification,
    /// The upload of one crate version.
    pub(crate) uploader: &'a dyn Uploader,
    /// The crates.io token of an upload.
    pub(crate) tokens: &'a dyn TokenSource,
    /// How long the run waits for crates.io to show an uploaded crate.
    pub(crate) wait: WaitPolicy,
    /// The variable names of the routine's own environment, which a run refuses
    /// a Cargo registry token in.
    pub(crate) environment: Vec<String>,
}

static LIVE_REGISTRY: network::LiveRegistryIndex = network::LiveRegistryIndex;
static LIVE_UPLOADER: live::LiveUploader = live::LiveUploader;
static LIVE_TOKENS: live::PromptToken = live::PromptToken;

impl Services<'static> {
    /// Returns the services of a production run.
    pub(crate) fn live() -> Self {
        Self {
            network: NetworkServices::live(),
            registry: &LIVE_REGISTRY,
            verification: verified_archives,
            uploader: &LIVE_UPLOADER,
            tokens: &LIVE_TOKENS,
            wait: WaitPolicy::live(),
            environment: std::env::vars_os()
                .filter_map(|(name, _)| name.into_string().ok())
                .collect(),
        }
    }
}

/// How a run builds the crates it would upload, with Cargo's verification.
///
/// The verified packaging runs package code, such as a build script or a proc
/// macro, so a run does it only while no token is in reach. A production run
/// names [`verified_archives`]; a test names a function of its own.
pub(crate) type Verification =
    fn(&DerivedWorkspace, &[(String, Version)]) -> Result<BTreeMap<String, Vec<u8>>>;

/// Builds the named crate versions with Cargo's verification and returns their
/// archives by crates.io name.
///
/// # Errors
///
/// Returns an error when Cargo configuration covers the working directory, when
/// Cargo fails, or when an archive is missing or too large.
fn verified_archives(
    workspace: &DerivedWorkspace,
    packages: &[(String, Version)],
) -> Result<BTreeMap<String, Vec<u8>>> {
    workspace.verified_archives(packages)
}

/// How long a run waits for crates.io's index to show an uploaded crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitPolicy {
    /// Most times the run reads the index of one crate.
    pub(crate) attempts: usize,
    /// Delay between two reads of the index.
    pub(crate) interval: Duration,
}

impl WaitPolicy {
    /// Returns the policy of a production run.
    pub(crate) fn live() -> Self {
        Self {
            attempts: LIVE_WAIT_ATTEMPTS,
            interval: LIVE_WAIT_INTERVAL,
        }
    }
}

/// What one run writes in place of a token in a child process's output.
const REDACTED: &str = "[redacted]";

/// A crates.io API token, which never prints.
///
/// The value reaches exactly one child process at a time, the upload of one
/// crate version, through that process's environment, and is dropped when the
/// uploads finish. Nothing logs it, writes it to a file, or puts it in an error.
pub(crate) struct Token(String);

impl Token {
    /// Returns a token, refusing an empty one.
    ///
    /// # Errors
    ///
    /// Returns an error for a token that is empty or carries a control
    /// character, which no crates.io token does.
    pub(crate) fn new(value: String) -> Result<Self> {
        ensure!(
            !value.trim().is_empty(),
            "the crates.io token is empty; the routine uploads nothing without one"
        );
        ensure!(
            !value.chars().any(char::is_control),
            "the crates.io token carries a control character"
        );
        Ok(Self(value))
    }

    /// Returns the token's value, for one upload process's environment.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// Replaces every occurrence of the token in one text.
    pub(crate) fn redact(&self, text: &str) -> String {
        text.replace(self.expose(), REDACTED)
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Token(<redacted>)")
    }
}

/// Reads the crates.io token of one upload.
///
/// A production run prompts for it when standard input is a terminal, and
/// otherwise reads one line of standard input; it never reads the token from
/// the routine's environment, its command line, or a file.
pub(crate) trait TokenSource {
    /// Returns the token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token cannot be read, or is empty.
    fn read(&self) -> Result<Token>;
}

/// Where one upload runs.
pub(crate) struct UploadEnvironment {
    /// The pinned Cargo.
    pub(crate) cargo: PathBuf,
    /// The environment of the upload process, without the token.
    pub(crate) environment: ChildEnvironment,
    /// The working directory outside the checkout.
    pub(crate) work: PathBuf,
    /// The workspace manifest of the rewritten checkout.
    pub(crate) manifest: PathBuf,
    /// The target directory of the upload.
    pub(crate) target: PathBuf,
}

/// One `cargo publish` of one crate version.
pub(crate) struct UploadRequest<'a> {
    /// Where the upload runs.
    pub(crate) environment: &'a UploadEnvironment,
    /// The crates.io name to publish.
    pub(crate) crates_io_name: &'a str,
    /// The exact version.
    pub(crate) version: &'a Version,
    /// The crates.io token, which only this process may see.
    pub(crate) token: &'a Token,
}

/// Publishes one crate version to crates.io.
pub(crate) trait Uploader {
    /// Runs one upload and requires it to succeed.
    ///
    /// # Errors
    ///
    /// Returns an error when the upload cannot run or fails; the error never
    /// carries the token.
    fn publish(&self, request: &UploadRequest<'_>) -> Result<()>;
}

/// One crate version of the release, with the entries that judge it.
#[derive(Clone, Copy)]
struct ReleaseCrate<'a> {
    /// The identity in `registry/main.lock`.
    identity: &'a CatalogIdentity,
    /// The `crates-io.lock` entry of the crate version.
    entry: &'a CratesIoPackage,
}

/// The crates of one release tag, and the repository that released them.
struct Release<'a> {
    /// The self-publishing repository's URL, as the catalog spells it.
    git: String,
    /// The crate versions of the release, in name order.
    identities: Vec<&'a CatalogIdentity>,
}

/// Runs one `self-publish` with the given services.
#[allow(clippy::too_many_lines)]
fn run(
    repository: &Path,
    tag: &str,
    upload: bool,
    git: Option<&str>,
    services: &Services<'_>,
) -> Result<SelfPublishSummary> {
    refuse_token_environment(&services.environment)
        .context("the routine must start without a Cargo registry token")?;
    if upload {
        // A token could be in reach from here on: no other process of this user
        // may open the routine's `/proc` files, its standard input among them.
        hide_process()?;
    }
    checkout::require_clean_merged_checkout(repository)
        .context("step 1: the checkout must be clean and merged into origin/main")?;
    let state = RepositoryState::load(repository)?;
    let Some(self_publish) = state.self_publish.as_ref() else {
        bail!(
            "repository {} has no self-publishing state, so there is no release to publish",
            repository.display()
        );
    };
    check_state(self_publish, &state.catalog, None)
        .context("step 2: the offline self-publishing checks of the repository must pass")?;
    let release = release_of_tag(&state.catalog, &self_publish.config, tag, git)?;
    info!(
        git = %release.git,
        tag,
        crates = release.identities.len(),
        "checking the release before publishing it"
    );

    let mut crates_io = CratesIoState::new(services.network.crates_io);
    let identities = release
        .identities
        .iter()
        .map(|identity| (*identity).clone())
        .collect::<Vec<_>>();
    let derivation = network::check_release_named(
        &state,
        self_publish,
        &release.git,
        tag,
        &network::ReleaseCrates {
            identities: &identities,
            // crates.io never takes an abandoned version, so the checks that
            // fail for one are exactly the reasons to abandon it; the rest of
            // the release still has to pass them.
            abandoned: Abandoned::Skip,
        },
        &services.network,
        &mut crates_io,
    )
    .context("step 2: the network checks of the release must pass")?;

    let release_crates = release
        .identities
        .iter()
        .map(|identity| {
            let entry = self_publish
                .lock
                .entry(&identity.name, &identity.version)
                .with_context(|| {
                    format!(
                        "self-published identity {} {} has no entry in crates-io.lock",
                        identity.name, identity.version
                    )
                })?;
            Ok(ReleaseCrate { identity, entry })
        })
        .collect::<Result<Vec<_>>>()?;
    require_registry(
        &state.catalog.registry_index,
        &release_crates,
        services.registry,
    )
    .context("step 3: the pkgre registry must serve every crate version of the release")?;

    let mut classified = Vec::new();
    for &crate_ in &release_crates {
        let name = &crate_.identity.name;
        let version = &crate_.identity.version;
        let state = state_on_crates_io(crate_, self_publish, &mut crates_io)
            .with_context(|| format!("step 4: the crates.io state of crate {name} {version}"))?;
        classified.push((crate_, state));
    }
    let dependencies = derivation.dependencies.len();
    let yanked_dependencies = check_dependencies(&derivation.dependencies, &mut crates_io)
        .context("step 4: every dependency of the release must be on crates.io")?;
    refuse_published_dependent_of_a_missing_sibling(&classified, &derivation.siblings).context(
        "step 4: a crate of the release cannot be on crates.io before the crates it depends on",
    )?;
    refuse_dependent_of_an_abandoned_sibling(&classified, &derivation.siblings).context(
        "step 4: a crate of the release cannot be published while a crate it depends on is abandoned",
    )?;
    if let Some((crate_, SelfPublishCrateState::Different { found })) = classified
        .iter()
        .find(|(_, state)| matches!(state, SelfPublishCrateState::Different { .. }))
    {
        log_crates(&classified);
        bail!(
            "crate {} {} of release tag {tag:?}: crates.io holds version {} with archive checksum {found}, but crates-io.lock records {}; a published crates.io version is never replaced, and the routine uploads nothing",
            crate_.identity.name,
            crate_.identity.version,
            crate_.entry.version,
            crate_.entry.crate_sha256
        );
    }

    let missing = classified
        .iter()
        .enumerate()
        .filter_map(|(position, (_, state))| {
            (*state == SelfPublishCrateState::Missing).then_some(position)
        })
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        verify_packages(&derivation, &classified, &missing, services)
            .context("step 5: the verified packages must reproduce crates-io.lock")?;
    }
    let order = upload_order(&classified, &missing, &derivation.siblings)
        .context("the crates of the release must be publishable in dependency order")?;
    if upload && !missing.is_empty() {
        let environment = upload_environment(&derivation)?;
        verify_publish_packages(&derivation, &environment, &classified, &missing).context(
            "step 6: the packages that cargo publish would upload must be the recorded ones",
        )?;
        if let Err(error) = upload_missing(
            &environment,
            &derivation.workspace,
            &mut classified,
            &order,
            &derivation.siblings,
            services,
        ) {
            // The records say which crates were uploaded before the failure.
            log_crates(&classified);
            return Err(error.context(format!(
                "steps 6 and 7: the upload and the wait for crates.io's index; {}",
                uploaded_before(&classified)
            )));
        }
    }
    let records = classified
        .iter()
        .map(|(crate_, state)| SelfPublishCrate {
            name: crate_.identity.name.clone(),
            version: crate_.identity.version.clone(),
            crates_io_name: crate_.entry.crates_io_name.clone(),
            state: state.clone(),
        })
        .collect::<Vec<_>>();
    log_crates(&classified);
    let count = |wanted: SelfPublishCrateState| {
        records
            .iter()
            .filter(|record| record.state == wanted)
            .count()
    };
    let summary = SelfPublishSummary {
        tag: tag.to_owned(),
        git: release.git.clone(),
        upload,
        published: count(SelfPublishCrateState::Published),
        yanked: count(SelfPublishCrateState::PublishedYanked),
        would_upload: count(SelfPublishCrateState::Missing),
        uploaded: count(SelfPublishCrateState::Uploaded),
        abandoned: count(SelfPublishCrateState::Abandoned),
        dependencies,
        yanked_dependencies,
        crates: records,
    };
    info!(
        tag,
        git = %summary.git,
        upload,
        published = summary.published,
        yanked = summary.yanked,
        would_upload = summary.would_upload,
        uploaded = summary.uploaded,
        abandoned = summary.abandoned,
        dependencies = summary.dependencies,
        yanked_dependencies = summary.yanked_dependencies,
        "self-published release"
    );
    Ok(summary)
}

/// Returns the crates of one release tag.
///
/// `git` chooses between several self-publishing repositories that use the same
/// release tag, which the run refuses without it.
fn release_of_tag<'a>(
    catalog: &'a CatalogSnapshot,
    config: &'a CratesIoConfig,
    tag: &str,
    git: Option<&str>,
) -> Result<Release<'a>> {
    validate_git_tag(tag).context("validate the release tag of the run")?;
    let wanted = git.map(normalized_git);
    let mut repositories: BTreeMap<String, Vec<&CatalogIdentity>> = BTreeMap::new();
    for (identity, release) in self_published_identities(catalog, config) {
        if release.tag != tag {
            continue;
        }
        if let Some(wanted) = &wanted
            && normalized_git(&release.git) != *wanted
        {
            continue;
        }
        repositories
            .entry(release.git.clone())
            .or_default()
            .push(identity);
    }
    if repositories.is_empty() {
        match git {
            Some(git) => bail!(
                "release tag {tag:?} is not a release tag of the self-publishing repository {git:?}; registry/main.lock has no crate version from it"
            ),
            None => bail!(
                "release tag {tag:?} is not a release tag of a self-publishing repository of registry/main.lock; check the tag, and that the release's pull request has merged"
            ),
        }
    }
    if repositories.len() > 1 {
        let names = repositories.keys().cloned().collect::<Vec<_>>();
        bail!(
            "release tag {tag:?} belongs to more than one self-publishing repository, {names:?}; pass --git=<url> to choose one"
        );
    }
    let (git, mut identities) = repositories.into_iter().next().expect("one repository");
    identities.sort_by(|left, right| {
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
    Ok(Release { git, identities })
}

/// Requires the `pkgre` registry to serve every crate version of the release
/// unyanked, with the checksum that `registry/main.lock` records.
fn require_registry(
    index: &str,
    release_crates: &[ReleaseCrate<'_>],
    registry: &dyn RegistryIndex,
) -> Result<()> {
    for crate_ in release_crates {
        let name = &crate_.identity.name;
        let version = &crate_.identity.version;
        let versions = registry
            .versions(index, name)
            .with_context(|| format!("read the pkgre registry's versions of {name}"))?;
        let Some(published) = versions.as_ref().and_then(|versions| {
            versions
                .iter()
                .find(|published| same_version(&published.version, version))
        }) else {
            bail!(
                "the pkgre registry {index} does not serve crate {name} version {version}; a release reaches crates.io only once the registry serves it"
            );
        };
        ensure!(
            !published.yanked,
            "the pkgre registry {index} serves crate {name} version {version} yanked; the routine publishes only what the registry serves unyanked"
        );
        ensure!(
            published.checksum == crate_.identity.crate_sha256,
            "the pkgre registry {index} serves crate {name} version {version} with archive checksum {}, but registry/main.lock records {}",
            published.checksum,
            crate_.identity.crate_sha256
        );
    }
    Ok(())
}

/// Returns the state of one crate version of the release on crates.io.
///
/// An abandoned version is skipped before crates.io is read, since the routine
/// never uploads it. The network checks already refuse a version that crates.io
/// holds with another checksum, so this classification is also the report that
/// an earlier refusal is built from.
fn state_on_crates_io(
    crate_: ReleaseCrate<'_>,
    self_publish: &SelfPublishState,
    crates_io: &mut CratesIoState<'_>,
) -> Result<SelfPublishCrateState> {
    if self_publish
        .config
        .abandoned_version(&crate_.identity.name, &crate_.identity.version)
        .is_some()
    {
        return Ok(SelfPublishCrateState::Abandoned);
    }
    let versions = crates_io.versions(&crate_.entry.crates_io_name)?;
    let published = versions.as_ref().and_then(|versions| {
        versions
            .iter()
            .find(|published| same_version(&published.version, &crate_.identity.version))
    });
    Ok(match published {
        None => SelfPublishCrateState::Missing,
        Some(published) if published.checksum == crate_.entry.crate_sha256 => {
            if published.yanked {
                SelfPublishCrateState::PublishedYanked
            } else {
                SelfPublishCrateState::Published
            }
        }
        Some(published) => SelfPublishCrateState::Different {
            found: published.checksum.clone(),
        },
    })
}

/// Requires crates.io to serve every package outside the release that it
/// depends on, with the checksum of the derived lock file, and returns the
/// number of yanked dependencies.
///
/// The derivation resolves each dependency through the tag's own `Cargo.lock`
/// to the catalog identity it pins: a mirrored identity keeps its name,
/// version, and crates.io checksum, and a crate of an earlier self-publishing
/// release takes its crates.io name and the checksum of its `crates-io.lock`
/// entry. It refuses a dependency on an abandoned version, on a fork, or on a
/// version without an entry, so this check sees only identities that crates.io
/// is expected to have.
///
/// A yanked dependency is reported rather than refused: Cargo accepts a yanked
/// version that a lock file pins, and the release does not re-resolve it.
fn check_dependencies(
    dependencies: &[DerivedDependency],
    crates_io: &mut CratesIoState<'_>,
) -> Result<usize> {
    let mut yanked = 0;
    for dependency in dependencies {
        let name = &dependency.crates_io_name;
        let version = &dependency.version;
        let versions = crates_io.versions(name)?;
        let Some(published) = versions.as_ref().and_then(|versions| {
            versions
                .iter()
                .find(|published| same_version(&published.version, version))
        }) else {
            bail!(
                "the release depends on crate {name} version {version}, which crates.io does not have; publish the dependency's release first"
            );
        };
        ensure!(
            published.checksum == dependency.crate_sha256,
            "crates.io has crate {name} version {version} with archive checksum {}, but the release's crates-io.lock records {}",
            published.checksum,
            dependency.crate_sha256
        );
        if published.yanked {
            yanked += 1;
            warn!(
                crates_io_name = %name,
                version = %version,
                "the release depends on a yanked crates.io version, which Cargo accepts because a lock file pins it"
            );
        }
    }
    Ok(yanked)
}

/// Builds the missing crate versions with Cargo's verification and requires the
/// recorded checksums.
///
/// This runs package code while no token is in reach: the token is read only
/// after it passed.
fn verify_packages(
    derivation: &Derivation,
    classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)],
    missing: &[usize],
    services: &Services<'_>,
) -> Result<()> {
    let packages = missing
        .iter()
        .map(|position| {
            let (crate_, _) = classified[*position];
            (
                crate_.entry.crates_io_name.clone(),
                crate_.identity.version.clone(),
            )
        })
        .collect::<Vec<_>>();
    let archives = (services.verification)(&derivation.workspace, &packages)?;
    for position in missing {
        let (crate_, _) = classified[*position];
        let name = &crate_.identity.name;
        let version = &crate_.identity.version;
        let archive = archives
            .get(&crate_.entry.crates_io_name)
            .with_context(|| {
                format!(
                    "the verified packaging produced no archive for crate {} {version}",
                    crate_.entry.crates_io_name
                )
            })?;
        let sha256 = sha256_bytes(archive);
        ensure!(
            sha256 == crate_.entry.crate_sha256,
            "the verified package of crate {name} {version} has SHA-256 {sha256}, but crates-io.lock records {}; the routine uploads nothing",
            crate_.entry.crate_sha256
        );
        info!(
            package = %name,
            %version,
            "verified the crates.io package of a crate"
        );
    }
    Ok(())
}

/// Uploads the missing crate versions, one process each, and waits until
/// crates.io's index shows every one of them with the recorded checksum.
///
/// The token is read here, after every check passed, and lives only while the
/// uploads run: each upload process gets it in its own environment, and no
/// other process does.
///
/// One `cargo publish` runs per crate, and a crate is uploaded after the crates
/// of the release it depends on, so that crates.io can resolve its
/// dependencies; name order decides among crates that do not depend on each
/// other, which leaves a release without such dependencies uploading as it
/// always did.
fn upload_missing(
    environment: &UploadEnvironment,
    workspace: &DerivedWorkspace,
    classified: &mut [(ReleaseCrate<'_>, SelfPublishCrateState)],
    order: &[usize],
    siblings: &BTreeMap<String, BTreeSet<String>>,
    services: &Services<'_>,
) -> Result<()> {
    let token = services.tokens.read()?;
    for position in order.iter().copied() {
        let (crate_, _) = classified[position];
        if siblings
            .get(&crate_.identity.name)
            .is_some_and(|dependencies| !dependencies.is_empty())
        {
            // crates.io serves the crates this one depends on by now, so the
            // package `cargo publish` builds is the one this home builds alone.
            workspace
                .verify_publish_archive(
                    &environment.environment,
                    &crate_.entry.crates_io_name,
                    &crate_.identity.version,
                    &crate_.entry.crate_sha256,
                )
                .with_context(|| {
                    format!(
                        "check the package that cargo publish would upload for crate {} {}",
                        crate_.identity.name, crate_.identity.version
                    )
                })?;
        }
        let request = UploadRequest {
            environment,
            crates_io_name: &crate_.entry.crates_io_name,
            version: &crate_.identity.version,
            token: &token,
        };
        services.uploader.publish(&request).with_context(|| {
            format!(
                "upload crate {} {} to crates.io",
                crate_.identity.name, crate_.identity.version
            )
        })?;
        wait_for_upload(&crate_, services)?;
        classified[position].1 = SelfPublishCrateState::Uploaded;
        info!(
            package = %crate_.identity.name,
            version = %crate_.identity.version,
            crates_io_name = %crate_.entry.crates_io_name,
            "uploaded a crate"
        );
    }
    drop(token);
    Ok(())
}

/// Returns the positions of the missing crate versions in upload order.
///
/// A crate follows the crates of the release it depends on that this run
/// uploads, and name order decides among crates that do not depend on each
/// other; a crate whose dependencies crates.io already has is ready at once.
///
/// # Errors
///
/// Returns an error for crates of the release that depend on each other in a
/// cycle.
fn upload_order(
    classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)],
    missing: &[usize],
    siblings: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<usize>> {
    let uploading = missing
        .iter()
        .map(|position| classified[*position].0.identity.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(missing.len());
    let mut uploaded: BTreeSet<&str> = BTreeSet::new();
    while order.len() < missing.len() {
        let next = missing
            .iter()
            .copied()
            .find(|position| {
                let name = classified[*position].0.identity.name.as_str();
                !uploaded.contains(name)
                    && siblings.get(name).is_none_or(|dependencies| {
                        dependencies
                            .iter()
                            .filter(|dependency| uploading.contains(dependency.as_str()))
                            .all(|dependency| uploaded.contains(dependency.as_str()))
                    })
            })
            .with_context(|| {
                let remaining = missing
                    .iter()
                    .map(|position| classified[*position].0.identity.name.as_str())
                    .filter(|name| !uploaded.contains(name))
                    .collect::<Vec<_>>();
                format!("the crates of the release {remaining:?} depend on each other in a cycle")
            })?;
        uploaded.insert(classified[next].0.identity.name.as_str());
        order.push(next);
    }
    Ok(order)
}

/// Refuses a run whose crates.io state has a crate of the release published
/// before a crate of the release that it depends on.
///
/// crates.io resolves a dependency when the dependent arrives, so this state
/// means the two records disagree: the dependent's crates.io version cannot be
/// the one `crates-io.lock` records for a sibling that crates.io never took.
///
/// # Errors
///
/// Returns an error naming the published crate and the missing crate it depends
/// on.
fn refuse_published_dependent_of_a_missing_sibling(
    classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)],
    siblings: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    for (crate_, state) in classified {
        if !matches!(
            state,
            SelfPublishCrateState::Published | SelfPublishCrateState::PublishedYanked
        ) {
            continue;
        }
        let Some(dependencies) = siblings.get(&crate_.identity.name) else {
            continue;
        };
        for dependency in dependencies {
            let missing = classified
                .iter()
                .find(|(other, _)| other.identity.name == *dependency)
                .is_some_and(|(_, state)| *state == SelfPublishCrateState::Missing);
            ensure!(
                !missing,
                "crate {} {} is published on crates.io as {}, but crate {dependency} {}, which it depends on, is missing; a crate of the release cannot be published before the crate it depends on, so the records and crates.io disagree",
                crate_.identity.name,
                crate_.identity.version,
                crate_.entry.crates_io_name,
                crate_.identity.version
            );
        }
    }
    Ok(())
}

/// Refuses a crate of the release that this run publishes while a crate of the
/// release it depends on is abandoned.
///
/// crates.io never takes the abandoned crate, so the dependent could not resolve
/// it; the remedy is to abandon the dependent too.
///
/// # Errors
///
/// Returns an error naming the dependent and the abandoned crate it depends on.
fn refuse_dependent_of_an_abandoned_sibling(
    classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)],
    siblings: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    for (crate_, state) in classified {
        if *state == SelfPublishCrateState::Abandoned {
            continue;
        }
        let Some(dependencies) = siblings.get(&crate_.identity.name) else {
            continue;
        };
        for dependency in dependencies {
            let abandoned = classified
                .iter()
                .find(|(other, _)| other.identity.name == *dependency)
                .is_some_and(|(_, state)| *state == SelfPublishCrateState::Abandoned);
            ensure!(
                !abandoned,
                "crate {} {} depends on {}, which crates-io.toml records as abandoned; crates.io never takes the abandoned crate, so the dependent cannot reach it either: abandon {} too",
                crate_.identity.name,
                crate_.identity.version,
                dependency,
                crate_.identity.name
            );
        }
    }
    Ok(())
}

/// Packages the missing crate versions the way `cargo publish` packages them,
/// in the upload's own Cargo home and environment, and requires the recorded
/// checksums.
///
/// This runs after the verified packaging and before the token is read, and the
/// command itself runs no package code, so the bytes the upload sends are the
/// bytes this check compared with `crates-io.lock`.
fn verify_publish_packages(
    derivation: &Derivation,
    environment: &UploadEnvironment,
    classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)],
    missing: &[usize],
) -> Result<()> {
    let packages = missing
        .iter()
        .map(|position| {
            let (crate_, _) = classified[*position];
            (
                crate_.entry.crates_io_name.clone(),
                crate_.identity.version.clone(),
            )
        })
        .collect::<Vec<_>>();
    let archives = derivation
        .workspace
        .publish_archives(&environment.environment, &packages)?;
    for position in missing {
        let (crate_, _) = classified[*position];
        let name = &crate_.identity.name;
        let version = &crate_.identity.version;
        let archive = archives
            .get(&crate_.entry.crates_io_name)
            .with_context(|| {
                format!(
                    "the packaging produced no archive for crate {} {version}",
                    crate_.entry.crates_io_name
                )
            })?;
        let sha256 = sha256_bytes(archive);
        ensure!(
            sha256 == crate_.entry.crate_sha256,
            "the package that cargo publish would upload for crate {name} {version} has SHA-256 {sha256}, but crates-io.lock records {}; the routine uploads nothing",
            crate_.entry.crate_sha256
        );
        info!(
            package = %name,
            %version,
            "checked the package that cargo publish would upload"
        );
    }
    Ok(())
}

/// Makes the routine's own process non-dumpable.
///
/// No other process of the same user can then open the routine's `/proc` files,
/// its standard input among them, while a token could be in reach; a token
/// piped on standard input is what this protects. The attribute is dropped by an
/// executed program, so it is set again for each run; Cargo's own null standard
/// input keeps a token out of the packages' reach.
///
/// # Errors
///
/// Returns an error when the kernel refuses the attribute.
#[cfg(target_os = "linux")]
fn hide_process() -> Result<()> {
    nix::sys::prctl::set_dumpable(false).context("make the routine's process non-dumpable")
}

/// Refuses an upload on a system where the routine cannot hide its process.
///
/// Hiding the process needs `prctl`, which only Linux has; a dry run holds no
/// token, so it runs everywhere.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(target_os = "linux"))]
fn hide_process() -> Result<()> {
    bail!(
        "`--upload` is supported on Linux only, where the routine hides its process while a token is in reach; a dry run runs on every system"
    )
}

/// Returns where the uploads run, from the release's rewritten workspace.
fn upload_environment(derivation: &Derivation) -> Result<UploadEnvironment> {
    let environment = derivation.workspace.upload_environment()?;
    Ok(UploadEnvironment {
        cargo: derivation.workspace.cargo().to_path_buf(),
        environment,
        work: derivation.workspace.work().to_path_buf(),
        manifest: derivation.workspace.manifest(),
        target: derivation.workspace.upload_target(),
    })
}

/// Waits until crates.io's index shows one uploaded crate version with the
/// recorded checksum.
///
/// The index is read afresh for every attempt, since the cache of the run holds
/// the state from before the upload.
fn wait_for_upload(crate_: &ReleaseCrate<'_>, services: &Services<'_>) -> Result<()> {
    let name = &crate_.entry.crates_io_name;
    let version = &crate_.identity.version;
    let recorded = &crate_.entry.crate_sha256;
    let mut last_error = None;
    for attempt in 0..services.wait.attempts {
        if attempt > 0 {
            std::thread::sleep(services.wait.interval);
        }
        let found = match services.network.crates_io.versions(name) {
            Ok(versions) => versions,
            Err(error) => {
                warn!(
                    crates_io_name = %name,
                    version = %version,
                    error = %format_args!("{error:#}"),
                    "reading crates.io's index failed; the wait reads it again"
                );
                last_error = Some(error);
                continue;
            }
        };
        let found = found
            .unwrap_or_default()
            .into_iter()
            .find(|published| same_version(&published.version, version));
        match found {
            Some(published) if published.checksum == *recorded => {
                info!(crates_io_name = %name, version = %version, "crates.io shows the uploaded crate");
                return Ok(());
            }
            Some(published) => bail!(
                "crates.io shows crate {name} version {version} with archive checksum {}, but crates-io.lock records {recorded}; the upload did not produce the recorded archive",
                published.checksum
            ),
            None => {}
        }
    }
    if let Some(error) = last_error {
        return Err(error).with_context(|| {
            format!(
                "crates.io could not be read for crate {name} version {version} in {} reads of its index",
                services.wait.attempts
            )
        });
    }
    bail!(
        "crates.io does not show crate {name} version {version} with archive checksum {recorded} after {} reads of its index; the upload may still be in flight, and a later run picks the crate up",
        services.wait.attempts
    )
}

/// Refuses a process environment that holds a Cargo registry token.
///
/// Cargo reads `CARGO_REGISTRY_TOKEN` and `CARGO_REGISTRIES_<NAME>_TOKEN` from
/// its environment, so a run refuses to start while either is set: no child
/// process of the routine may inherit a token, and the routine reads its own
/// token from its prompt alone.
///
/// # Errors
///
/// Returns an error naming the variable, never its value.
fn refuse_token_environment(names: &[String]) -> Result<()> {
    if let Some(name) = token_variable(names.iter().map(String::as_str)) {
        bail!(
            "the environment sets {name}, which a child process could inherit; unset it before running this command, which reads the crates.io token from its prompt alone"
        );
    }
    Ok(())
}

/// Returns the first Cargo registry token variable among some environment names.
///
/// The check reads one environment's variable names, which a test injects, so
/// that no test has to mutate its own environment.
pub(crate) fn token_variable<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    names.into_iter().find(|name| is_token_variable(name))
}

/// Returns whether one environment variable name carries a Cargo registry token.
fn is_token_variable(name: &str) -> bool {
    name == "CARGO_REGISTRY_TOKEN"
        || (name.starts_with("CARGO_REGISTRIES_") && name.ends_with("_TOKEN"))
}

/// Returns which crate versions the run uploaded before a failure.
fn uploaded_before(classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)]) -> String {
    let uploaded = classified
        .iter()
        .filter(|(_, state)| *state == SelfPublishCrateState::Uploaded)
        .map(|(crate_, _)| {
            format!(
                "{} {} as {}",
                crate_.identity.name, crate_.identity.version, crate_.entry.crates_io_name
            )
        })
        .collect::<Vec<_>>();
    if uploaded.is_empty() {
        "no crate version was uploaded before the failure".to_owned()
    } else {
        format!(
            "crate versions uploaded before the failure: {}",
            uploaded.join(", ")
        )
    }
}

/// Logs one record per crate version of the release.
fn log_crates(classified: &[(ReleaseCrate<'_>, SelfPublishCrateState)]) {
    for (crate_, state) in classified {
        let found = match state {
            SelfPublishCrateState::Different { found } => Some(found.as_str()),
            _ => None,
        };
        info!(
            package = %crate_.identity.name,
            version = %crate_.identity.version,
            crates_io_name = %crate_.entry.crates_io_name,
            state = state.label(),
            found,
            "crate version of the release"
        );
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/self_publish/publish/mod.rs"]
mod tests;
