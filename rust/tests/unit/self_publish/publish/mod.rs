//! Unit tests of the `self-publish` routine.
//!
//! Every test drives the routine with fakes for crates.io, the release
//! repository, the `pkgre` registry, the token, and the upload, so the suite
//! stays offline. The fixture release is the one of the derivation's tests: two
//! released crates, `example-lib` and `example-bin`, from the annotated tag
//! `rust/v1.0.0` of a local repository.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use semver::Version;

use super::super::catalog::{CatalogIdentity, GitRelease};
use super::super::config::CratesIoConfig;
use super::super::derive::tests::fixtures::{self, LocalSource, Release, Sibling, Variant};
use super::super::isolation::ChildEnvironment;
use super::super::lock::{CratesIoLock, CratesIoPackage};
use super::super::lock_command::{LocalNetwork, self_publish_lock_in};
use super::super::network::{
    CratesIo, CratesIoVersion, DerivationSources, LocalSources, Owner, OwnerKind, RegistryIndex,
    ReleaseRepository, ReleaseTag, Services as NetworkServices,
};
use super::super::state::LOCK_FILE;
use super::{
    SelfPublishCrate, SelfPublishCrateState, SelfPublishSummary, Services, Token, TokenSource,
    UploadEnvironment, UploadRequest, Uploader, Verification, WaitPolicy, live, run,
    token_variable, verified_archives,
};
use crate::artifact::sha256_bytes;
use crate::self_publish::catalog::CatalogSnapshot;
use crate::self_publish::derive::DerivedWorkspace;

/// The crate that the fixture maps to a crates.io name.
const LIB: &str = "example-lib";
/// The crate that the fixture gives the default crates.io name.
const BIN: &str = "example-bin";
/// The repository of the fixture.
const REPOSITORY: &str = fixtures::REPOSITORY;
/// The crates.io owner of the fixture release.
const OWNER: &str = "example-owner";
/// A token that no report lets through.
const TOKEN: &str = "example-crates-io-token";
/// How long a test waits for an upload, which the fakes answer at once.
const WAIT: WaitPolicy = WaitPolicy {
    attempts: 3,
    interval: Duration::ZERO,
};

/// One fixture catalog that publishes its release, as a clean Git checkout.
struct Fixture {
    /// The local source that replaces crates.io.
    source: LocalSource,
    /// The tagged repository.
    release: Release,
    /// The catalog repository, committed and merged into `origin/main`.
    candidate: fixtures::Catalog,
    /// The catalog facts of the candidate.
    catalog: CatalogSnapshot,
    /// The directory that derivations work in.
    work: fixtures::Temp,
}

/// Builds the fixture of one variant, with the abandoned records that
/// `abandoned` names.
fn build_with(parent: &Path, abandoned: &[(&str, &str, &str)], variant: Variant) -> Fixture {
    let source = LocalSource::build(&parent.join("local"));
    let release = fixtures::release(parent, &source, variant);
    let candidate = fixtures::catalog_at(parent, "candidate", &source, &release, variant, true);
    let work = fixtures::Temp::new("pkgre-publish-work");
    let repositories = BTreeMap::from([(REPOSITORY.to_owned(), release.root.clone())]);
    self_publish_lock_in(
        &candidate.root,
        &LocalNetwork {
            repositories: &repositories,
            source: &source.root,
            root: work.path(),
        },
    )
    .expect("derive the fixture release's entries");
    commit_checkout(&candidate.root);
    if !abandoned.is_empty() {
        abandon(&candidate.root, abandoned);
    }
    let catalog = CatalogSnapshot::load(&candidate.root).expect("load the fixture catalog");
    Fixture {
        source,
        release,
        candidate,
        catalog,
        work,
    }
}

/// Commits the catalog repository and marks its only commit as merged into
/// `origin/main`.
fn commit_checkout(root: &Path) {
    fixtures::git(root, &["init", "--quiet"]);
    fixtures::git(root, &["add", "."]);
    fixtures::git(root, &["commit", "--quiet", "-m", "release"]);
    fixtures::git(root, &["remote", "add", "origin", REPOSITORY]);
    fixtures::git(root, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
}

/// Records abandoned versions in a later commit, as a release is abandoned after
/// it was recorded, and keeps the checkout merged into `origin/main`.
fn abandon(root: &Path, abandoned: &[(&str, &str, &str)]) {
    let path = root.join("self-publish/crates-io.toml");
    let mut text = fs::read_to_string(&path).expect("read the fixture config");
    for (name, version, reason) in abandoned {
        writeln!(
            text,
            "\n[[abandoned]]\nname = {name:?}\nversion = {version:?}\nreason = {reason:?}"
        )
        .expect("write the abandoned record");
    }
    fs::write(&path, text).expect("write the fixture config");
    fixtures::git(root, &["commit", "--quiet", "-am", "abandon a version"]);
    fixtures::git(root, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
}

impl Fixture {
    /// Returns the version of one crate of the release.
    fn version(&self, name: &str) -> Version {
        self.release.version(name)
    }

    /// Returns the recorded `crates-io.lock` entry of one crate of the release.
    fn entry(&self, name: &str) -> CratesIoPackage {
        CratesIoLock::load(&self.candidate.root.join("self-publish").join(LOCK_FILE))
            .expect("load the fixture entries")
            .entry(name, &self.version(name))
            .unwrap_or_else(|| panic!("the fixture records {name} {}", self.version(name)))
            .clone()
    }

    /// Returns the checksum of one crate of the release in `registry/main.lock`.
    fn pkgre_checksum(&self, name: &str) -> String {
        self.catalog
            .identity(name, &self.version(name))
            .unwrap_or_else(|| panic!("the catalog holds {name} {}", self.version(name)))
            .crate_sha256
            .clone()
    }

    /// Returns the crates.io names and versions of the packages outside the
    /// release, with the checksums that crates.io must serve for them.
    fn dependencies(&self) -> Vec<(String, Version, String)> {
        let mut dependencies = [
            ("mirrored-dep", "0.3.0"),
            ("mirrored-dev", "0.1.0"),
            ("other-mirror", "0.2.0"),
        ]
        .into_iter()
        .map(|(name, version)| {
            (
                name.to_owned(),
                version.parse().expect("parse a fixture version"),
                self.source.checksum(name, version),
            )
        })
        .collect::<Vec<_>>();
        dependencies.push((
            fixtures::EARLIER_CRATES_IO_NAME.to_owned(),
            "0.9.0".parse().expect("parse a fixture version"),
            self.source
                .checksum(fixtures::EARLIER_CRATES_IO_NAME, "0.9.0"),
        ));
        dependencies
    }

    /// Returns the crates.io names of the released crates, in name order.
    fn crates_io_names(&self) -> Vec<String> {
        [BIN, LIB]
            .into_iter()
            .map(|name| self.entry(name).crates_io_name)
            .collect()
    }
}

/// A fake crates.io, whose versions a fake upload adds to.
#[derive(Clone, Default)]
struct FakeCratesIo {
    /// The shared state of the fakes.
    state: Rc<FakeCratesIoState>,
}

/// The state that the fake crates.io and the fake upload share.
#[derive(Default)]
struct FakeCratesIoState {
    /// Published versions by crate name; absent means crates.io lacks the crate.
    versions: RefCell<BTreeMap<String, Option<Vec<CratesIoVersion>>>>,
    /// Owners by crate name.
    owners: RefCell<BTreeMap<String, Vec<Owner>>>,
    /// How often crates.io was read.
    calls: Cell<usize>,
    /// Whether crates.io is unavailable.
    unavailable: Cell<bool>,
    /// How many of the next reads fail, as an unavailable service does.
    fail_reads: Cell<usize>,
}

impl FakeCratesIo {
    /// Sets the versions of one crates.io crate.
    fn set_versions(&self, name: &str, versions: Option<Vec<CratesIoVersion>>) {
        self.state
            .versions
            .borrow_mut()
            .insert(name.to_owned(), versions);
    }

    /// Sets the owners of one crates.io crate.
    fn set_owners(&self, name: &str, owners: Vec<Owner>) {
        self.state
            .owners
            .borrow_mut()
            .insert(name.to_owned(), owners);
    }

    /// Adds one published version, as an upload does.
    fn add_version(&self, name: &str, version: Version, checksum: String) {
        let mut versions = self.state.versions.borrow_mut();
        let published = versions
            .entry(name.to_owned())
            .or_insert_with(|| Some(Vec::new()));
        let list = published.get_or_insert_with(Vec::new);
        list.retain(|published| published.version != version);
        list.push(published_version(version, checksum, false));
    }

    /// Makes one published version yanked.
    fn yank(&self, name: &str, version: &Version) {
        let mut versions = self.state.versions.borrow_mut();
        if let Some(Some(list)) = versions.get_mut(name)
            && let Some(published) = list
                .iter_mut()
                .find(|published| published.version == *version)
        {
            published.yanked = true;
        }
    }

    /// Returns how often crates.io was read.
    fn calls(&self) -> usize {
        self.state.calls.get()
    }

    /// Fails the next `reads` reads of crates.io, as an unavailable service
    /// does.
    fn fail_reads(&self, reads: usize) {
        self.state.fail_reads.set(reads);
    }
}

impl CratesIo for FakeCratesIo {
    fn owners(&self, name: &str) -> Result<Option<Vec<Owner>>> {
        count_read(&self.state)?;
        Ok(self.state.owners.borrow().get(name).cloned())
    }

    fn versions(&self, name: &str) -> Result<Option<Vec<CratesIoVersion>>> {
        count_read(&self.state)?;
        Ok(self
            .state
            .versions
            .borrow()
            .get(name)
            .cloned()
            .unwrap_or(None))
    }

    fn category_slugs(&self) -> Result<BTreeSet<String>> {
        count_read(&self.state)?;
        Ok(BTreeSet::new())
    }
}

/// Counts one read of the fake crates.io, which refuses it when the fake is
/// unavailable or its failures are not used up.
fn count_read(state: &FakeCratesIoState) -> Result<()> {
    state.calls.set(state.calls.get() + 1);
    if state.unavailable.get() {
        bail!("crates.io is unavailable");
    }
    let remaining = state.fail_reads.get();
    if remaining > 0 {
        state.fail_reads.set(remaining - 1);
        bail!("crates.io is unavailable");
    }
    Ok(())
}

/// Returns one published version.
fn published_version(version: Version, checksum: String, yanked: bool) -> CratesIoVersion {
    CratesIoVersion {
        version,
        checksum,
        yanked,
    }
}

/// Returns one user owner of a crates.io crate.
fn user_owner(login: &str) -> Owner {
    Owner {
        login: login.to_owned(),
        kind: OwnerKind::User,
    }
}

/// A fake release repository that reports the fixture tag.
struct FakeRepository {
    /// The tag object of the fixture release.
    tag_oid: String,
    /// The peeled commit of the fixture release.
    commit: String,
    /// Whether the tag is annotated.
    annotated: Cell<bool>,
    /// Whether the tag's commit is on the default branch.
    merged: Cell<bool>,
    /// How often the repository was read.
    calls: Cell<usize>,
}

impl FakeRepository {
    /// Returns a fake that reports the fixture's release tag.
    fn new(fixture: &Fixture) -> Self {
        Self {
            tag_oid: fixture.release.tag_oid.clone(),
            commit: fixture.release.commit.clone(),
            annotated: Cell::new(true),
            merged: Cell::new(true),
            calls: Cell::new(0),
        }
    }
}

impl ReleaseRepository for FakeRepository {
    fn inspect_tag(&self, git: &str, tag: &str) -> Result<ReleaseTag> {
        self.calls.set(self.calls.get() + 1);
        if git != REPOSITORY || tag != fixtures::tag() {
            bail!("the fake repository holds no tag {tag:?} of {git:?}");
        }
        if !self.merged.get() {
            bail!("the tag's commit is not on the default branch");
        }
        Ok(ReleaseTag {
            tag_oid: self.tag_oid.clone(),
            commit: self.commit.clone(),
            annotated: self.annotated.get(),
            on_default_branch: self.merged.get(),
            default_branch: "main".to_owned(),
        })
    }
}

/// A fake `pkgre` registry.
#[derive(Default)]
struct FakeRegistry {
    /// Versions by crate name; absent means the registry lacks the crate.
    versions: RefCell<BTreeMap<String, Option<Vec<CratesIoVersion>>>>,
    /// How often the registry was read.
    calls: Cell<usize>,
}

impl FakeRegistry {
    /// Serves every crate of the release, as the registry does after a merge.
    fn serving(fixture: &Fixture) -> Self {
        let registry = Self::default();
        for name in [BIN, LIB] {
            registry.set(
                name,
                Some(vec![published_version(
                    fixture.version(name),
                    fixture.pkgre_checksum(name),
                    false,
                )]),
            );
        }
        registry
    }

    /// Sets the versions of one crate of the registry.
    fn set(&self, name: &str, versions: Option<Vec<CratesIoVersion>>) {
        self.versions.borrow_mut().insert(name.to_owned(), versions);
    }
}

impl RegistryIndex for FakeRegistry {
    fn versions(&self, _index: &str, name: &str) -> Result<Option<Vec<CratesIoVersion>>> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.versions.borrow().get(name).cloned().unwrap_or(None))
    }
}

/// A fake upload that publishes into the fake crates.io.
struct FakeUploader {
    /// crates.io, which the fake publishes into.
    crates_io: FakeCratesIo,
    /// The checksum that the fake publishes for each crates.io name.
    checksums: BTreeMap<String, String>,
    /// How many uploads succeed before the fake fails.
    fail_after: Cell<usize>,
    /// The crates.io names the fake uploaded.
    uploads: RefCell<Vec<String>>,
    /// The tokens the fake was given.
    tokens: RefCell<Vec<String>>,
}

impl FakeUploader {
    /// Returns a fake that never fails, publishing into `crates_io`.
    fn new(fixture: &Fixture, crates_io: FakeCratesIo) -> Self {
        let checksums = [BIN, LIB]
            .into_iter()
            .map(|name| {
                let entry = fixture.entry(name);
                (entry.crates_io_name, entry.crate_sha256)
            })
            .collect();
        Self {
            crates_io,
            checksums,
            fail_after: Cell::new(usize::MAX),
            uploads: RefCell::new(Vec::new()),
            tokens: RefCell::new(Vec::new()),
        }
    }

    /// Fails before the upload after `fail_after` successful ones.
    fn fail_after(&self, uploads: usize) {
        self.fail_after.set(uploads);
    }

    /// Forgets the uploads of an earlier run.
    fn reset(&self) {
        self.uploads.borrow_mut().clear();
        self.tokens.borrow_mut().clear();
    }

    /// Returns the crates.io names the fake uploaded.
    fn uploads(&self) -> Vec<String> {
        self.uploads.borrow().clone()
    }

    /// Returns the tokens the fake was given.
    fn tokens(&self) -> Vec<String> {
        self.tokens.borrow().clone()
    }
}

impl Uploader for FakeUploader {
    fn publish(&self, request: &UploadRequest<'_>) -> Result<()> {
        if self.uploads.borrow().len() >= self.fail_after.get() {
            bail!(
                "the fake uploader fails before uploading {}",
                request.crates_io_name
            );
        }
        let checksum = self
            .checksums
            .get(request.crates_io_name)
            .with_context(|| format!("the fake holds no checksum for {}", request.crates_io_name))?
            .clone();
        self.uploads
            .borrow_mut()
            .push(request.crates_io_name.to_owned());
        self.tokens
            .borrow_mut()
            .push(request.token.expose().to_owned());
        self.crates_io
            .add_version(request.crates_io_name, request.version.clone(), checksum);
        Ok(())
    }
}

/// A fake token source, which refuses a read when it has no token.
struct FakeTokens {
    /// The token to answer with.
    value: Option<String>,
    /// How often the token was read.
    reads: Cell<usize>,
}

impl FakeTokens {
    /// Returns a source that answers with the test token.
    fn with_token() -> Self {
        Self {
            value: Some(TOKEN.to_owned()),
            reads: Cell::new(0),
        }
    }

    /// Returns a source that must not be read.
    fn forbidden() -> Self {
        Self {
            value: None,
            reads: Cell::new(0),
        }
    }

    /// Returns how often the token was read.
    fn reads(&self) -> usize {
        self.reads.get()
    }
}

impl TokenSource for FakeTokens {
    fn read(&self) -> Result<Token> {
        self.reads.set(self.reads.get() + 1);
        match &self.value {
            Some(value) => Token::new(value.clone()),
            None => bail!("this run must not read a token"),
        }
    }
}

/// One fixture release and the fakes that judge it.
struct Setup {
    /// The fixture catalog.
    fixture: Fixture,
    /// crates.io.
    crates_io: FakeCratesIo,
    /// The release repository.
    repository: FakeRepository,
    /// The `pkgre` registry.
    registry: FakeRegistry,
    /// The upload.
    uploader: FakeUploader,
    /// The token.
    tokens: FakeTokens,
}

impl Setup {
    /// Builds a fixture whose crates.io lacks every crate of the release, has
    /// the release's dependencies, and has the registry's crates.
    fn new(parent: &Path) -> Self {
        Self::with_abandoned(parent, &[])
    }

    /// Builds the fixture of one variant, whose `crates-io.toml` records the
    /// abandoned versions that `abandoned` names.
    fn with_variant(parent: &Path, abandoned: &[(&str, &str, &str)], variant: Variant) -> Self {
        let fixture = build_with(parent, abandoned, variant);
        let crates_io = FakeCratesIo::default();
        for name in fixture.crates_io_names() {
            crates_io.set_owners(&name, vec![user_owner(OWNER)]);
        }
        for (name, version, checksum) in fixture.dependencies() {
            crates_io.set_versions(
                &name,
                Some(vec![published_version(version, checksum, false)]),
            );
        }
        let registry = FakeRegistry::serving(&fixture);
        let uploader = FakeUploader::new(&fixture, crates_io.clone());
        let repository = FakeRepository::new(&fixture);
        Self {
            fixture,
            crates_io,
            repository,
            registry,
            uploader,
            tokens: FakeTokens::with_token(),
        }
    }

    /// Builds a fixture whose `crates-io.toml` records abandoned versions.
    fn with_abandoned(parent: &Path, abandoned: &[(&str, &str, &str)]) -> Self {
        Self::with_variant(parent, abandoned, Variant::default())
    }

    /// Returns the services of one run.
    fn services(&self, verification: Verification) -> Services<'_> {
        Services {
            network: NetworkServices {
                crates_io: &self.crates_io,
                repositories: &self.repository,
                derivation: DerivationSources::Local(LocalSources {
                    repositories: BTreeMap::from([(
                        REPOSITORY.to_owned(),
                        self.fixture.release.root.clone(),
                    )]),
                    directory: Some(self.fixture.source.root.clone()),
                    root: self.fixture.work.path().to_path_buf(),
                }),
            },
            registry: &self.registry,
            verification,
            uploader: &self.uploader,
            tokens: &self.tokens,
            wait: WAIT,
            environment: Vec::new(),
        }
    }

    /// Runs the fixture's release, optionally with the upload.
    fn execute(&self, upload: bool) -> Result<SelfPublishSummary> {
        run(
            &self.fixture.candidate.root,
            &fixtures::tag(),
            upload,
            None,
            &self.services(verified_archives),
        )
    }

    /// Runs a dry run of the fixture's release.
    fn dry_run(&self) -> Result<SelfPublishSummary> {
        self.execute(false)
    }

    /// Publishes every crate of the release on crates.io with the recorded
    /// checksum, as a previous successful run leaves them.
    fn publish_everything(&self) {
        for name in [BIN, LIB] {
            self.publish(name);
        }
    }

    /// Publishes one crate of the release on crates.io with the recorded
    /// checksum.
    fn publish(&self, name: &str) {
        let entry = self.fixture.entry(name);
        self.crates_io.set_versions(
            &entry.crates_io_name,
            Some(vec![published_version(
                entry.version.clone(),
                entry.crate_sha256.clone(),
                false,
            )]),
        );
    }

    /// Returns the record of one crate of the release.
    fn record(summary: &SelfPublishSummary, name: &str) -> SelfPublishCrate {
        summary
            .crates
            .iter()
            .find(|record| record.name == name)
            .unwrap_or_else(|| panic!("the summary records {name}"))
            .clone()
    }
}

/// Returns the error text of a refusal.
fn refusal<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn a_dry_run_reports_the_crates_that_crates_io_lacks() {
    let temporary = fixtures::Temp::new("pkgre-publish-missing");
    let setup = Setup::new(temporary.path());
    let summary = setup.dry_run().expect("the dry run passes");
    assert_eq!(summary.tag, fixtures::tag());
    assert_eq!(summary.git, REPOSITORY);
    assert!(!summary.upload);
    assert_eq!(summary.crates.len(), 2);
    assert_eq!(summary.published, 0);
    assert_eq!(summary.yanked, 0);
    assert_eq!(summary.would_upload, 2);
    assert_eq!(summary.uploaded, 0);
    assert_eq!(summary.abandoned, 0);
    assert_eq!(summary.dependencies, 4);
    assert_eq!(summary.yanked_dependencies, 0);
    for name in [BIN, LIB] {
        let record = Setup::record(&summary, name);
        assert_eq!(record.version, setup.fixture.version(name));
        assert_eq!(record.state, SelfPublishCrateState::Missing);
        assert_eq!(
            record.crates_io_name,
            setup.fixture.entry(name).crates_io_name
        );
    }
    assert!(setup.uploader.uploads().is_empty());
    assert!(setup.uploader.tokens().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
    assert!(setup.crates_io.calls() > 0);
}

/// The variant whose binary depends on the library of the same tag.
fn sibling_release() -> Variant {
    Variant {
        sibling: Sibling::Accepted,
        ..Variant::default()
    }
}

#[test]
fn a_release_may_depend_on_a_sibling_that_crates_io_does_not_have_yet() {
    let temporary = fixtures::Temp::new("pkgre-publish-sibling-dry");
    let setup = Setup::with_variant(temporary.path(), &[], sibling_release());
    let summary = setup.dry_run().expect("the dry run passes");
    assert_eq!(summary.would_upload, 2);
    assert_eq!(
        summary.dependencies, 4,
        "a crate of the release is served by the release, not by crates.io"
    );
    assert_eq!(summary.yanked_dependencies, 0);
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn uploads_a_sibling_before_the_crate_that_depends_on_it() {
    let temporary = fixtures::Temp::new("pkgre-publish-sibling-order");
    let setup = Setup::with_variant(temporary.path(), &[], sibling_release());
    let summary = setup.execute(true).expect("the upload passes");
    assert_eq!(summary.uploaded, 2);
    assert_eq!(
        setup.uploader.uploads(),
        vec![
            setup.fixture.entry(LIB).crates_io_name,
            setup.fixture.entry(BIN).crates_io_name
        ],
        "the library is uploaded first, although the binary's name sorts before it"
    );
    for name in [BIN, LIB] {
        assert_eq!(
            Setup::record(&summary, name).state,
            SelfPublishCrateState::Uploaded
        );
    }
}

#[test]
fn a_resumed_run_uploads_a_dependent_whose_sibling_is_published() {
    let temporary = fixtures::Temp::new("pkgre-publish-sibling-resume");
    let setup = Setup::with_variant(temporary.path(), &[], sibling_release());
    // An earlier run uploaded the library and stopped before the binary.
    setup.publish(LIB);
    let summary = setup.execute(true).expect("the resumed upload passes");
    assert_eq!(summary.published, 1);
    assert_eq!(summary.uploaded, 1);
    assert_eq!(
        Setup::record(&summary, LIB).state,
        SelfPublishCrateState::Published
    );
    assert_eq!(
        Setup::record(&summary, BIN).state,
        SelfPublishCrateState::Uploaded
    );
    assert_eq!(
        setup.uploader.uploads(),
        vec![setup.fixture.entry(BIN).crates_io_name],
        "only the binary is uploaded, and its package reproduces the recorded bytes"
    );
}

#[test]
fn refuses_a_dependent_that_crates_io_has_before_its_sibling() {
    let temporary = fixtures::Temp::new("pkgre-publish-sibling-out-of-order");
    let setup = Setup::with_variant(temporary.path(), &[], sibling_release());
    // crates.io has the binary, and not the library it depends on.
    setup.publish(BIN);
    let error = refusal(setup.dry_run());
    assert!(error.contains(BIN), "{error}");
    assert!(error.contains(LIB), "{error}");
    assert!(error.contains("is missing"), "{error}");
}

#[test]
fn an_upload_publishes_the_missing_crates_and_reports_them_uploaded() {
    let temporary = fixtures::Temp::new("pkgre-publish-upload");
    let setup = Setup::new(temporary.path());
    let summary = setup.execute(true).expect("the upload passes");
    assert!(summary.upload);
    assert_eq!(summary.uploaded, 2);
    assert_eq!(summary.would_upload, 0);
    assert_eq!(summary.published, 0);
    for name in [BIN, LIB] {
        assert_eq!(
            Setup::record(&summary, name).state,
            SelfPublishCrateState::Uploaded
        );
    }
    assert_eq!(setup.uploader.uploads(), setup.fixture.crates_io_names());
    assert_eq!(setup.uploader.tokens(), vec![TOKEN.to_owned(); 2]);
    assert_eq!(setup.tokens.reads(), 1);
}

#[test]
fn an_upload_of_a_published_release_reads_no_token_and_uploads_nothing() {
    let temporary = fixtures::Temp::new("pkgre-publish-published");
    let setup = Setup::new(temporary.path());
    setup.publish_everything();
    let tokens = FakeTokens::forbidden();
    let services = Services {
        tokens: &tokens,
        ..setup.services(verified_archives)
    };
    let summary = run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &services,
    )
    .expect("a release that crates.io has needs no upload");
    assert_eq!(summary.published, 2);
    assert_eq!(summary.uploaded, 0);
    assert_eq!(summary.would_upload, 0);
    assert_eq!(tokens.reads(), 0);
    assert!(setup.uploader.uploads().is_empty());
}

#[test]
fn reports_a_yanked_crate_and_never_unyanks_it() {
    let temporary = fixtures::Temp::new("pkgre-publish-yanked");
    let setup = Setup::new(temporary.path());
    setup.publish_everything();
    let lib = setup.fixture.entry(LIB);
    setup.crates_io.yank(&lib.crates_io_name, &lib.version);
    let summary = setup.execute(true).expect("a yanked crate is a report");
    assert_eq!(summary.published, 1);
    assert_eq!(summary.yanked, 1);
    assert_eq!(summary.uploaded, 0);
    assert_eq!(
        Setup::record(&summary, LIB).state,
        SelfPublishCrateState::PublishedYanked
    );
    assert_eq!(
        Setup::record(&summary, BIN).state,
        SelfPublishCrateState::Published
    );
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn uploads_only_the_missing_crate_of_a_partially_published_release() {
    let temporary = fixtures::Temp::new("pkgre-publish-partial");
    let setup = Setup::new(temporary.path());
    setup.publish(LIB);
    let summary = setup.execute(true).expect("the upload passes");
    assert_eq!(summary.published, 1);
    assert_eq!(summary.uploaded, 1);
    assert_eq!(
        Setup::record(&summary, LIB).state,
        SelfPublishCrateState::Published
    );
    assert_eq!(
        Setup::record(&summary, BIN).state,
        SelfPublishCrateState::Uploaded
    );
    assert_eq!(
        setup.uploader.uploads(),
        vec![setup.fixture.entry(BIN).crates_io_name]
    );
}

#[test]
fn a_failed_upload_leaves_the_rest_to_the_next_run() {
    let temporary = fixtures::Temp::new("pkgre-publish-resume");
    let setup = Setup::new(temporary.path());
    setup.uploader.fail_after(1);
    let error = refusal(setup.execute(true));
    assert!(error.contains("the fake uploader fails"), "{error}");
    let first = setup.uploader.uploads();
    assert_eq!(first.len(), 1, "{first:?}");
    assert!(error.contains("uploaded before the failure"), "{error}");
    assert!(error.contains(&first[0]), "{error}");
    assert_eq!(setup.tokens.reads(), 1);
    // The resumed run sees the first crate on crates.io and uploads the second.
    setup.uploader.reset();
    setup.uploader.fail_after(usize::MAX);
    let summary = setup.execute(true).expect("the resumed run passes");
    assert_eq!(summary.published, 1);
    assert_eq!(summary.uploaded, 1);
    assert_eq!(setup.uploader.uploads().len(), 1);
    assert_ne!(setup.uploader.uploads(), first);
}

#[test]
fn refuses_a_published_version_with_another_checksum() {
    let temporary = fixtures::Temp::new("pkgre-publish-different");
    let setup = Setup::new(temporary.path());
    let lib = setup.fixture.entry(LIB);
    setup.crates_io.set_versions(
        &lib.crates_io_name,
        Some(vec![published_version(
            lib.version.clone(),
            "b".repeat(64),
            false,
        )]),
    );
    let error = refusal(setup.execute(true));
    assert!(error.contains(LIB), "{error}");
    assert!(error.contains(&"b".repeat(64)), "{error}");
    assert!(error.contains(&lib.crate_sha256), "{error}");
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn skips_an_abandoned_version() {
    let temporary = fixtures::Temp::new("pkgre-publish-abandoned");
    let setup = Setup::with_abandoned(
        temporary.path(),
        &[(LIB, fixtures::VERSION, "crates.io refused the upload")],
    );
    let summary = setup
        .execute(true)
        .expect("an abandoned version is skipped");
    assert_eq!(summary.abandoned, 1);
    assert_eq!(summary.uploaded, 1);
    assert_eq!(
        Setup::record(&summary, LIB).state,
        SelfPublishCrateState::Abandoned
    );
    assert_eq!(
        Setup::record(&summary, BIN).state,
        SelfPublishCrateState::Uploaded
    );
    assert_eq!(
        setup.uploader.uploads(),
        vec![setup.fixture.entry(BIN).crates_io_name]
    );
}

/// Returns a verification whose archives are never the recorded ones.
#[allow(clippy::unnecessary_wraps)]
fn unrecorded_verification(
    _workspace: &DerivedWorkspace,
    packages: &[(String, Version)],
) -> Result<BTreeMap<String, Vec<u8>>> {
    Ok(packages
        .iter()
        .map(|(name, _)| {
            (
                name.clone(),
                b"an archive that crates-io.lock does not record".to_vec(),
            )
        })
        .collect())
}

#[test]
fn a_verified_package_that_differs_from_the_lock_stops_the_run_before_the_token() {
    let temporary = fixtures::Temp::new("pkgre-publish-checksum");
    let setup = Setup::new(temporary.path());
    let error = refusal(run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &setup.services(unrecorded_verification),
    ));
    let unrecorded = sha256_bytes(b"an archive that crates-io.lock does not record");
    assert!(error.contains("verified package"), "{error}");
    assert!(error.contains(&unrecorded), "{error}");
    assert!(
        error.contains(&setup.fixture.entry(BIN).crate_sha256)
            || error.contains(&setup.fixture.entry(LIB).crate_sha256),
        "{error}"
    );
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn refuses_a_registry_that_does_not_serve_the_release() {
    let temporary = fixtures::Temp::new("pkgre-publish-registry");
    let setup = Setup::new(temporary.path());
    let lib = setup.fixture.entry(LIB);

    setup.registry.set(LIB, None);
    let error = refusal(setup.dry_run());
    assert!(error.contains("does not serve"), "{error}");
    assert!(error.contains(LIB), "{error}");

    setup.registry.set(
        LIB,
        Some(vec![published_version(
            lib.version.clone(),
            setup.fixture.pkgre_checksum(LIB),
            true,
        )]),
    );
    let error = refusal(setup.dry_run());
    assert!(error.contains("yanked"), "{error}");

    setup.registry.set(
        LIB,
        Some(vec![published_version(
            lib.version.clone(),
            "c".repeat(64),
            false,
        )]),
    );
    let error = refusal(setup.dry_run());
    assert!(error.contains(&"c".repeat(64)), "{error}");
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn refuses_a_dependency_that_crates_io_lacks() {
    let temporary = fixtures::Temp::new("pkgre-publish-dependency");
    let setup = Setup::new(temporary.path());
    setup.crates_io.set_versions("mirrored-dep", None);
    let error = refusal(setup.execute(true));
    assert!(error.contains("mirrored-dep"), "{error}");
    assert!(error.contains("which crates.io does not have"), "{error}");
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn refuses_an_empty_token_before_any_upload() {
    let temporary = fixtures::Temp::new("pkgre-publish-empty-token");
    let setup = Setup::new(temporary.path());
    let tokens = FakeTokens {
        value: Some(" \n".to_owned()),
        reads: Cell::new(0),
    };
    let services = Services {
        tokens: &tokens,
        ..setup.services(verified_archives)
    };
    let error = refusal(run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &services,
    ));
    assert!(error.contains("token is empty"), "{error}");
    assert_eq!(tokens.reads(), 1);
    assert!(setup.uploader.uploads().is_empty());
    assert!(Token::new(String::new()).is_err());
}

#[test]
fn a_wait_that_never_sees_the_recorded_archive_is_an_error() {
    let temporary = fixtures::Temp::new("pkgre-publish-wait");
    let setup = Setup::new(temporary.path());
    let identity = setup
        .fixture
        .catalog
        .identity(LIB, &setup.fixture.version(LIB))
        .expect("the catalog holds the release's identity")
        .clone();
    let entry = setup.fixture.entry(LIB);
    let crate_ = super::ReleaseCrate {
        identity: &identity,
        entry: &entry,
    };
    // crates.io does not have the crate at all.
    let error = refusal(super::wait_for_upload(
        &crate_,
        &setup.services(verified_archives),
    ));
    assert!(error.contains("does not show"), "{error}");
    assert!(error.contains(&entry.crate_sha256), "{error}");
    // crates.io has it with another checksum, so the upload did not produce the
    // recorded archive.
    setup.crates_io.set_versions(
        &entry.crates_io_name,
        Some(vec![published_version(
            entry.version.clone(),
            "d".repeat(64),
            false,
        )]),
    );
    let error = refusal(super::wait_for_upload(
        &crate_,
        &setup.services(verified_archives),
    ));
    assert!(error.contains(&"d".repeat(64)), "{error}");
}

#[test]
fn uploads_the_rest_of_a_release_whose_abandoned_name_someone_else_owns() {
    let temporary = fixtures::Temp::new("pkgre-publish-abandoned-taken");
    let setup = Setup::with_abandoned(
        temporary.path(),
        &[(LIB, fixtures::VERSION, "someone took the name")],
    );
    let lib = setup.fixture.entry(LIB);
    setup
        .crates_io
        .set_owners(&lib.crates_io_name, vec![user_owner("someone-else")]);
    let summary = setup
        .execute(true)
        .expect("the rest of the release is still uploaded");
    assert_eq!(summary.abandoned, 1);
    assert_eq!(summary.uploaded, 1);
    assert_eq!(
        Setup::record(&summary, LIB).state,
        SelfPublishCrateState::Abandoned
    );
    assert_eq!(
        Setup::record(&summary, BIN).state,
        SelfPublishCrateState::Uploaded
    );
    assert_eq!(
        setup.uploader.uploads(),
        vec![setup.fixture.entry(BIN).crates_io_name]
    );
}

#[test]
fn uploads_the_rest_of_a_release_whose_abandoned_version_crates_io_holds() {
    let temporary = fixtures::Temp::new("pkgre-publish-abandoned-other");
    let setup = Setup::with_abandoned(
        temporary.path(),
        &[(
            LIB,
            fixtures::VERSION,
            "crates.io published this version from other sources",
        )],
    );
    let lib = setup.fixture.entry(LIB);
    setup.crates_io.set_versions(
        &lib.crates_io_name,
        Some(vec![published_version(
            lib.version.clone(),
            "e".repeat(64),
            false,
        )]),
    );
    let summary = setup
        .execute(true)
        .expect("the rest of the release is still uploaded");
    assert_eq!(summary.abandoned, 1);
    assert_eq!(summary.uploaded, 1);
    assert_eq!(
        Setup::record(&summary, LIB).state,
        SelfPublishCrateState::Abandoned
    );
    assert_eq!(
        Setup::record(&summary, BIN).state,
        SelfPublishCrateState::Uploaded
    );
    assert_eq!(
        setup.uploader.uploads(),
        vec![setup.fixture.entry(BIN).crates_io_name]
    );
}

/// Returns a verification that changes the checkout once it packaged the
/// release, as a build script of the release could.
fn changed_after_verification(
    workspace: &DerivedWorkspace,
    packages: &[(String, Version)],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let archives = workspace.verified_archives(packages)?;
    let manifest = workspace.manifest();
    let root = manifest.parent().expect("the workspace has a directory");
    fs::write(
        root.join("bin/src/main.rs"),
        "fn main() { println!(\"changed after the verification\"); }\n",
    )
    .expect("change the checkout");
    Ok(archives)
}

#[test]
fn a_checkout_changed_after_the_verification_stops_the_run_before_the_token() {
    let temporary = fixtures::Temp::new("pkgre-publish-changed");
    let setup = Setup::new(temporary.path());
    let error = refusal(run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &setup.services(changed_after_verification),
    ));
    assert!(
        error.contains("the package that cargo publish would upload"),
        "{error}"
    );
    assert!(
        error.contains(&setup.fixture.entry(BIN).crate_sha256),
        "{error}"
    );
    assert!(setup.uploader.uploads().is_empty());
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn a_failed_index_read_during_the_wait_is_retried() {
    let temporary = fixtures::Temp::new("pkgre-publish-wait-retry");
    let setup = Setup::new(temporary.path());
    setup.publish(LIB);
    setup.crates_io.fail_reads(1);
    let identity = setup
        .fixture
        .catalog
        .identity(LIB, &setup.fixture.version(LIB))
        .expect("the catalog holds the release's identity")
        .clone();
    let entry = setup.fixture.entry(LIB);
    let crate_ = super::ReleaseCrate {
        identity: &identity,
        entry: &entry,
    };
    super::wait_for_upload(&crate_, &setup.services(verified_archives))
        .expect("the wait reads crates.io's index again within its bound");
}

#[test]
fn refuses_a_token_variable_in_the_routines_own_environment() {
    let temporary = fixtures::Temp::new("pkgre-publish-environment");
    let setup = Setup::new(temporary.path());
    // A dirty checkout, which the token refusal has to precede.
    fs::write(setup.fixture.candidate.root.join("untracked.txt"), "one\n")
        .expect("write an untracked file");
    let services = Services {
        environment: vec![
            "PATH".to_owned(),
            "CARGO_REGISTRIES_EXAMPLE_TOKEN".to_owned(),
        ],
        ..setup.services(verified_archives)
    };
    let error = refusal(run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &services,
    ));
    assert!(error.contains("CARGO_REGISTRIES_EXAMPLE_TOKEN"), "{error}");
    assert!(!error.contains("untracked"), "{error}");
    assert_eq!(setup.tokens.reads(), 0);
}

#[test]
fn reports_a_yanked_dependency_without_refusing_it() {
    let temporary = fixtures::Temp::new("pkgre-publish-yanked-dependency");
    let setup = Setup::new(temporary.path());
    let version: Version = "0.3.0".parse().expect("parse a fixture version");
    setup.crates_io.yank("mirrored-dep", &version);
    let summary = setup.dry_run().expect("a yanked dependency is a report");
    assert_eq!(summary.yanked_dependencies, 1);
    assert_eq!(summary.dependencies, 4);
}

#[test]
fn refuses_a_dirty_checkout() {
    let temporary = fixtures::Temp::new("pkgre-publish-dirty");
    let setup = Setup::new(temporary.path());
    let path = setup.fixture.candidate.root.join("registry/main.toml");
    let mut text = fs::read_to_string(&path).expect("read the registry file");
    text.push('\n');
    fs::write(&path, text).expect("write the registry file");
    let error = refusal(setup.dry_run());
    assert!(
        error.contains("has staged, unstaged, or untracked changes"),
        "{error}"
    );
    assert!(error.contains("registry/main.toml"), "{error}");
}

#[test]
fn refuses_an_untracked_file() {
    let temporary = fixtures::Temp::new("pkgre-publish-untracked");
    let setup = Setup::new(temporary.path());
    fs::write(setup.fixture.candidate.root.join("untracked.txt"), "one\n")
        .expect("write an untracked file");
    let error = refusal(setup.dry_run());
    assert!(error.contains("untracked.txt"), "{error}");
}

#[test]
fn refuses_a_head_that_is_not_merged_into_origin_main() {
    let temporary = fixtures::Temp::new("pkgre-publish-unmerged");
    let setup = Setup::new(temporary.path());
    fixtures::git(
        &setup.fixture.candidate.root,
        &["commit", "--quiet", "--allow-empty", "-m", "not merged"],
    );
    let error = refusal(setup.dry_run());
    assert!(
        error.contains("is not contained in the remote-tracking origin/main"),
        "{error}"
    );
    assert!(error.contains("git fetch origin main"), "{error}");
}

#[test]
fn refuses_a_release_tag_that_several_repositories_use() {
    let (catalog, config) = two_repositories();
    let error = refusal(super::release_of_tag(
        &catalog,
        &config,
        "rust/v1.0.0",
        None,
    ));
    assert!(
        error.contains("more than one self-publishing repository"),
        "{error}"
    );
    assert!(error.contains("--git="), "{error}");
    let release: super::Release<'_> = super::release_of_tag(
        &catalog,
        &config,
        "rust/v1.0.0",
        Some("https://git.example.invalid/second/repository"),
    )
    .expect("--git chooses one repository");
    assert_eq!(release.git, "https://git.example.invalid/second/repository");
    assert_eq!(release.identities.len(), 1);
    let error = refusal(super::release_of_tag(
        &catalog,
        &config,
        "rust/v9.9.9",
        None,
    ));
    assert!(error.contains("is not a release tag"), "{error}");
    let error = refusal(super::release_of_tag(
        &catalog,
        &config,
        "rust/v1.0.0",
        Some("https://git.example.invalid/third/repository"),
    ));
    assert!(error.contains("third/repository"), "{error}");
}

/// Returns a catalog whose two self-publishing repositories release the same
/// tag, and the matching declarations.
fn two_repositories() -> (CatalogSnapshot, CratesIoConfig) {
    let identities = [
        "https://git.example.invalid/first/repository",
        "https://git.example.invalid/second/repository",
    ]
    .into_iter()
    .map(|git| CatalogIdentity {
        name: "example-lib".to_owned(),
        version: "1.0.0".parse().expect("parse a version"),
        crate_sha256: "a".repeat(64),
        removed: false,
        release: Some(GitRelease {
            git: git.to_owned(),
            tag: "rust/v1.0.0".to_owned(),
            tag_oid: "1".repeat(40),
            commit: "2".repeat(40),
            cargo_version: "1.95.0".parse().expect("parse a version"),
        }),
    })
    .collect();
    let catalog = CatalogSnapshot {
        registry_index: "sparse+https://rust.pkg.re/".to_owned(),
        identities,
        ..CatalogSnapshot::default()
    };
    let config = CratesIoConfig::parse(
        b"schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = \"https://git.example.invalid/first/repository\"\ntag-prefix = \"rust/v\"\n\n[[repositories]]\ngit = \"https://git.example.invalid/second/repository\"\ntag-prefix = \"rust/v\"\n",
        Path::new("crates-io.toml"),
    )
    .expect("parse the fixture declarations");
    (catalog, config)
}

#[test]
fn refuses_a_lightweight_release_tag() {
    let temporary = fixtures::Temp::new("pkgre-publish-lightweight");
    let setup = Setup::new(temporary.path());
    setup.repository.annotated.set(false);
    let error = refusal(setup.dry_run());
    assert!(error.contains("lightweight"), "{error}");
    assert!(setup.uploader.uploads().is_empty());
}

#[test]
fn recognises_cargo_registry_token_variables() {
    assert_eq!(
        token_variable(["PATH", "CARGO_REGISTRY_TOKEN"]),
        Some("CARGO_REGISTRY_TOKEN")
    );
    assert_eq!(
        token_variable(["CARGO_REGISTRIES_EXAMPLE_TOKEN", "PATH"]),
        Some("CARGO_REGISTRIES_EXAMPLE_TOKEN")
    );
    assert_eq!(
        token_variable([
            "CARGO_REGISTRIES_EXAMPLE_INDEX",
            "PATH",
            "CARGO_SEARCH_TOKEN",
        ]),
        None
    );
    assert_eq!(
        token_variable(["CARGO_REGISTRIES_EXAMPLE_TOKEN_FILE"]),
        None
    );
}

#[test]
fn the_token_never_reaches_an_error() {
    let temporary = fixtures::Temp::new("pkgre-publish-token-error");
    let (upload, _) = fake_upload(&temporary, "print-token");
    let version: Version = "1.0.0".parse().expect("parse a version");
    let token = Token::new(TOKEN.to_owned()).expect("build the token");
    let request = UploadRequest {
        environment: &upload,
        crates_io_name: "example-library",
        version: &version,
        token: &token,
    };
    let error = live::LiveUploader
        .publish(&request)
        .expect_err("the fake upload fails");
    let text = format!("{error:#}");
    assert!(!text.contains(TOKEN), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
    assert!(text.contains("example-library"), "{text}");
    let debug = format!("{token:?}");
    assert!(!debug.contains(TOKEN), "{debug}");
    assert!(debug.contains("redacted"), "{debug}");
}

#[test]
fn only_the_upload_process_gets_the_token() {
    let temporary = fixtures::Temp::new("pkgre-publish-allowlist");
    let (upload, record) = fake_upload(&temporary, "record");
    let version: Version = "1.0.0".parse().expect("parse a version");
    let token = Token::new(TOKEN.to_owned()).expect("build the token");
    let request = UploadRequest {
        environment: &upload,
        crates_io_name: "example-library",
        version: &version,
        token: &token,
    };
    live::LiveUploader
        .publish(&request)
        .expect("the fake upload succeeds");
    let recorded = parse_environment(
        &fs::read_to_string(&record)
            .unwrap_or_else(|error| panic!("read {}: {error}", record.display())),
    );
    assert_allowlisted(&recorded, &["CARGO_REGISTRY_TOKEN"]);
    assert_eq!(
        recorded.get("CARGO_REGISTRY_TOKEN").map(String::as_str),
        Some(TOKEN)
    );
    assert!(recorded.contains_key("RUSTC"), "{recorded:?}");
}

/// Writes a fake toolchain of a `cargo` that acts as `action` says, with a
/// `rustc` beside it, and returns where one upload runs and where the fake
/// records its environment.
fn fake_upload(temporary: &fixtures::Temp, action: &str) -> (UploadEnvironment, PathBuf) {
    let root = temporary.path();
    let toolchain = root.join(format!("toolchain-{action}"));
    fs::create_dir_all(&toolchain).expect("create the fake toolchain");
    let record = root.join(format!("recorded-environment-{action}"));
    let script = if action == "record" {
        format!("#!/bin/sh\nenv | sort > '{}'\nexit 0\n", record.display())
    } else {
        "#!/bin/sh\necho \"$CARGO_REGISTRY_TOKEN\"\necho \"$CARGO_REGISTRY_TOKEN\" >&2\nexit 1\n"
            .to_owned()
    };
    let cargo = toolchain.join("cargo");
    fixtures::write_executable(&cargo, &script);
    fixtures::write_executable(&toolchain.join("rustc"), "#!/bin/sh\nexit 0\n");
    let home = root.join(format!("cargo-home-{action}"));
    fs::create_dir_all(&home).expect("create the fake Cargo home");
    let work = root.join(format!("work-{action}"));
    fs::create_dir_all(&work).expect("create the fake working directory");
    let environment = ChildEnvironment::capture(&home, &cargo).expect("capture the allowlist");
    (
        UploadEnvironment {
            cargo,
            environment,
            work,
            manifest: root.join("Cargo.toml"),
            target: root.join(format!("target-{action}")),
        },
        record,
    )
}

/// Parses one `env` listing.
fn parse_environment(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// Requires that a recorded environment carries the allowlist and nothing else.
fn assert_allowlisted(recorded: &BTreeMap<String, String>, extra: &[&str]) {
    // The shell that runs the fake adds `PWD`, `SHLVL` and `_` itself; every
    // other variable has to come from the allowlist.
    let mut allowed = vec![
        "PATH",
        "TMPDIR",
        "PWD",
        "SHLVL",
        "_",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "CURL_CA_BUNDLE",
        "CARGO_HTTP_CAINFO",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "NIX_SSL_CERT_FILE",
        "CARGO_HOME",
        "RUSTC",
        "CARGO_TERM_COLOR",
        "CARGO_NET_GIT_FETCH_WITH_CLI",
    ];
    allowed.extend(extra);
    for name in recorded.keys() {
        assert!(
            allowed.contains(&name.as_str()),
            "the child inherited {name}: {recorded:?}"
        );
    }
    assert!(recorded.contains_key("CARGO_HOME"), "{recorded:?}");
    assert!(!recorded.contains_key("HOME"), "{recorded:?}");
    assert!(
        !recorded.contains_key("CARGO_REGISTRY_TOKEN") || allowed.contains(&"CARGO_REGISTRY_TOKEN"),
        "{recorded:?}"
    );
}
