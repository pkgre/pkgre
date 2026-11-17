//! Unit tests of the network checks of the releases that a run adds.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use semver::Version;

use super::super::check::{AcceptedState, SelfPublishCheckSummary, check_repository_with};
use super::super::derive::MemberFacts;
use super::super::derive::tests::fixtures::{self, LocalSource, Release, Variant};
use super::super::lock::{CratesIoLock, CratesIoPackage};
use super::super::lock_command::{LocalNetwork, self_publish_lock_in};
use super::super::state::LOCK_FILE;
use super::live;
use super::{
    CratesIo, CratesIoVersion, DerivationSources, LiveCratesIo, LiveRegistryIndex,
    LiveReleaseRepository, LocalSources, Owner, OwnerKind, RegistryIndex, ReleaseRepository,
    ReleaseTag, Services, check_crates_io_rules,
};
use crate::artifact::sha256_bytes;

/// The crate that the fixture maps to a crates.io name.
const LIB: &str = "example-lib";
/// The crate that the fixture gives the default crates.io name.
const BIN: &str = "example-bin";
/// The repository of the fixture.
const REPOSITORY: &str = fixtures::REPOSITORY;

/// One answer of a fake service.
enum Answer<T> {
    /// The service answers with this value.
    Value(T),
    /// The service is unavailable.
    Unavailable,
}

/// A candidate and an accepted repository for one fixture release.
struct Fixture {
    /// The local source that replaces crates.io.
    source: LocalSource,
    /// The tagged repository.
    release: Release,
    /// The candidate, which publishes the release.
    candidate: fixtures::Catalog,
    /// The accepted repository, before the release.
    accepted: fixtures::Catalog,
    /// The directory that the derivation works in.
    work: fixtures::Temp,
}

/// Builds a fixture whose candidate records the release without deriving it,
/// for a check that fails before the derivation.
fn fixture_without_derivation(parent: &Path) -> Fixture {
    let fixture = build_fixture(parent, Variant::default());
    record_entries(&fixture.candidate, &fixture.release);
    fixture
}

/// Builds a fixture whose candidate records the release as `self-publish-lock`
/// does, by deriving it.
fn fixture_with_derivation(parent: &Path, variant: Variant) -> Fixture {
    let fixture = build_fixture(parent, variant);
    let repositories = BTreeMap::from([(REPOSITORY.to_owned(), fixture.release.root.clone())]);
    self_publish_lock_in(
        &fixture.candidate.root,
        &LocalNetwork {
            repositories: &repositories,
            source: &fixture.source.root,
            root: fixture.work.path(),
        },
    )
    .expect("derive the fixture release's entries");
    fixture
}

/// Builds both repositories of one fixture, without recording the release.
fn build_fixture(parent: &Path, variant: Variant) -> Fixture {
    let source = LocalSource::build(&parent.join("local"));
    let release = fixtures::release(parent, &source, variant);
    let candidate = fixtures::catalog_at(parent, "candidate", &source, &release, variant, true);
    let accepted = fixtures::catalog_at(parent, "accepted", &source, &release, variant, false);
    let work = fixtures::Temp::new("pkgre-network-work");
    Fixture {
        source,
        release,
        candidate,
        accepted,
        work,
    }
}

/// Records the entries of the fixture release without deriving them, so that a
/// check that fails before the derivation reaches the network checks.
fn record_entries(candidate: &fixtures::Catalog, release: &Release) {
    let path = candidate.root.join("self-publish").join(LOCK_FILE);
    let mut lock = CratesIoLock::load(&path).expect("load the fixture entries");
    for (name, crates_io_name) in [
        (BIN, fixtures::BIN_CRATES_IO_NAME),
        (LIB, fixtures::LIB_CRATES_IO_NAME),
    ] {
        let archive = candidate
            .curated
            .get(name)
            .unwrap_or_else(|| panic!("the catalog retains the archive of {name}"));
        lock.packages.push(CratesIoPackage {
            name: name.to_owned(),
            version: release.version(name),
            crates_io_name: crates_io_name.to_owned(),
            crate_sha256: fixtures::crate_checksum(crates_io_name, fixtures::VERSION),
            pkgre_crate_sha256: sha256_bytes(archive),
            git: REPOSITORY.to_owned(),
            tag: fixtures::tag(),
            commit: release.commit.clone(),
            cargo_version: Version::parse(fixtures::CARGO_VERSION)
                .expect("parse the pinned version"),
        });
    }
    fs::write(
        &path,
        lock.serialize().expect("serialize the fixture entries"),
    )
    .expect("write the fixture entries");
}

/// Copies every regular file of `from` to `to`, keeping the layout.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create the copy");
    let mut entries = fs::read_dir(from)
        .expect("read the tree")
        .map(|entry| entry.expect("read an entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path).expect("inspect an entry");
        let target = to.join(path.file_name().expect("an entry has a name"));
        if metadata.is_dir() {
            copy_tree(&path, &target);
        } else {
            assert!(metadata.is_file(), "{} is a regular file", path.display());
            fs::copy(&path, &target).expect("copy a file");
        }
    }
}

/// Builds an accepted repository with the candidate's catalog and no
/// self-publishing state: the change that adopts `self-publish/`.
fn accepted_without_self_publishing(fixture: &Fixture) -> PathBuf {
    let accepted = fixture
        .candidate
        .root
        .parent()
        .expect("the candidate has a parent")
        .join("accepted-adoption");
    copy_tree(
        &fixture.candidate.root.join("registry"),
        &accepted.join("registry"),
    );
    accepted
}

/// Builds an accepted repository that records the earlier release only and does
/// not declare the fixture repository: the change that adds the repository.
fn accepted_without_the_repository(fixture: &Fixture) -> PathBuf {
    let accepted = fixture
        .candidate
        .root
        .parent()
        .expect("the candidate has a parent")
        .join("accepted-repository");
    copy_tree(
        &fixture.candidate.root.join("registry"),
        &accepted.join("registry"),
    );
    fs::create_dir_all(accepted.join("self-publish")).expect("create the self-publishing state");
    fs::write(
        accepted.join("self-publish/crates-io.toml"),
        "schema = 1\n\nowners = [\"example-owner\"]\n\n[names]\nexample-lib = \"example-library\"\n",
    )
    .expect("write the accepted config");
    let mut lock = CratesIoLock::load(&fixture.candidate.root.join("self-publish").join(LOCK_FILE))
        .expect("load the fixture entries");
    lock.packages
        .retain(|package| package.name == "earlier-lib");
    fs::write(
        accepted.join("self-publish/crates-io.lock"),
        lock.serialize().expect("serialize the accepted entries"),
    )
    .expect("write the accepted entries");
    accepted
}

/// Records a `crate-sha256` that no derivation reproduces for one crate.
fn record_a_bogus_checksum(fixture: &Fixture, name: &str) {
    let path = fixture.candidate.root.join("self-publish").join(LOCK_FILE);
    let mut lock = CratesIoLock::load(&path).expect("load the fixture entries");
    let version = fixture.release.version(name);
    let entry = lock
        .packages
        .iter_mut()
        .find(|package| package.name == name && package.version == version)
        .unwrap_or_else(|| panic!("the fixture records {name} {version}"));
    entry.crate_sha256 = "c".repeat(64);
    fs::write(
        &path,
        lock.serialize().expect("serialize the fixture entries"),
    )
    .expect("write the fixture entries");
}

/// Returns the services of one fixture, with the given fakes.
fn services<'a>(
    fixture: &'a Fixture,
    crates_io: &'a FakeCratesIo,
    repositories: &'a FakeRepository,
) -> Services<'a> {
    Services {
        crates_io,
        repositories,
        derivation: DerivationSources::Local(LocalSources {
            repositories: BTreeMap::from([(REPOSITORY.to_owned(), fixture.release.root.clone())]),
            directory: Some(fixture.source.root.clone()),
            root: fixture.work.path().to_path_buf(),
        }),
    }
}

/// Runs the checks of one fixture against the given accepted repository.
fn check_against(
    fixture: &Fixture,
    accepted: &Path,
    crates_io: &FakeCratesIo,
    repositories: &FakeRepository,
) -> Result<SelfPublishCheckSummary> {
    check_repository_with(
        &fixture.candidate.root,
        Some(accepted),
        &services(fixture, crates_io, repositories),
    )
}

/// Runs the checks of one fixture against its own accepted repository.
fn check(
    fixture: &Fixture,
    crates_io: &FakeCratesIo,
    repositories: &FakeRepository,
) -> Result<SelfPublishCheckSummary> {
    check_against(fixture, &fixture.accepted.root, crates_io, repositories)
}

/// Returns the error text of a refusal.
fn error_text(result: Result<SelfPublishCheckSummary>) -> String {
    match result {
        Ok(summary) => panic!("expected a refusal, got {summary:?}"),
        Err(error) => format!("{error:#}"),
    }
}

/// Returns the recorded `crates-io.lock` entry of one crate version.
fn recorded_entry(fixture: &Fixture, name: &str) -> CratesIoPackage {
    let lock = CratesIoLock::load(&fixture.candidate.root.join("self-publish").join(LOCK_FILE))
        .expect("load the fixture entries");
    let version = fixture.release.version(name);
    lock.entry(name, &version)
        .unwrap_or_else(|| panic!("the fixture records {name} {version}"))
        .clone()
}

/// Returns one release tag, as a fake repository reports it.
fn release_tag(fixture: &Fixture, annotated: bool, on_default_branch: bool) -> ReleaseTag {
    ReleaseTag {
        tag_oid: fixture.release.tag_oid.clone(),
        commit: fixture.release.commit.clone(),
        annotated,
        on_default_branch,
        default_branch: "main".to_owned(),
    }
}

/// A fake crates.io.
#[derive(Default)]
struct FakeCratesIo {
    /// Refuse every request, for a run that must not read the network.
    forbidden: bool,
    /// Report crates.io as unavailable.
    unavailable: bool,
    /// Owners by crate name.
    owners: BTreeMap<String, Answer<Option<Vec<Owner>>>>,
    /// Versions by crate name.
    versions: BTreeMap<String, Answer<Option<Vec<CratesIoVersion>>>>,
    /// The category slugs, when a check reads them.
    slugs: Option<Answer<BTreeSet<String>>>,
    /// How often the fake was asked.
    calls: Cell<usize>,
}

impl FakeCratesIo {
    /// Returns a fake that has none of the given crate names.
    fn missing(names: &[&str]) -> Self {
        let mut fake = Self::default();
        for name in names {
            fake.owners.insert((*name).to_owned(), Answer::Value(None));
            fake.versions
                .insert((*name).to_owned(), Answer::Value(None));
        }
        fake
    }

    /// Returns a fake that refuses every request.
    fn forbidden() -> Self {
        Self {
            forbidden: true,
            ..Self::default()
        }
    }

    /// Returns a fake whose crates.io is unavailable.
    fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }

    /// Sets the owners of one crate name.
    fn with_owners(&mut self, name: &str, owners: Option<Vec<Owner>>) {
        self.owners.insert(name.to_owned(), Answer::Value(owners));
    }

    /// Sets the versions of one crate name.
    fn with_versions(&mut self, name: &str, versions: Option<Vec<CratesIoVersion>>) {
        self.versions
            .insert(name.to_owned(), Answer::Value(versions));
    }

    /// Sets the category slugs.
    fn with_slugs(&mut self, slugs: &[&str]) {
        self.slugs = Some(Answer::Value(
            slugs.iter().map(|slug| (*slug).to_owned()).collect(),
        ));
    }

    /// Returns how often the fake was asked.
    fn calls(&self) -> usize {
        self.calls.get()
    }

    /// Counts one request, and refuses it when the fake must not answer.
    fn count(&self) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        if self.forbidden {
            bail!("crates.io must not be read by this run");
        }
        if self.unavailable {
            bail!("crates.io is unavailable");
        }
        Ok(())
    }
}

impl CratesIo for FakeCratesIo {
    fn owners(&self, name: &str) -> Result<Option<Vec<Owner>>> {
        self.count()?;
        match self.owners.get(name) {
            Some(Answer::Value(owners)) => Ok(owners.clone()),
            Some(Answer::Unavailable) => bail!("crates.io is unavailable"),
            None => Ok(None),
        }
    }

    fn versions(&self, name: &str) -> Result<Option<Vec<CratesIoVersion>>> {
        self.count()?;
        match self.versions.get(name) {
            Some(Answer::Value(versions)) => Ok(versions.clone()),
            Some(Answer::Unavailable) => bail!("crates.io is unavailable"),
            None => Ok(None),
        }
    }

    fn category_slugs(&self) -> Result<BTreeSet<String>> {
        self.count()?;
        match &self.slugs {
            Some(Answer::Value(slugs)) => Ok(slugs.clone()),
            Some(Answer::Unavailable) => bail!("crates.io is unavailable"),
            None => bail!("the fake has no category slugs"),
        }
    }
}

/// A fake release repository.
#[derive(Default)]
struct FakeRepository {
    /// Refuse every request, for a run that must not read the network.
    forbidden: bool,
    /// The tags, by repository and tag.
    tags: BTreeMap<(String, String), Answer<ReleaseTag>>,
    /// How often the fake was asked.
    calls: Cell<usize>,
}

impl FakeRepository {
    /// Returns a fake that reports one tag of the fixture repository.
    fn of(tag: ReleaseTag) -> Self {
        let mut fake = Self::default();
        fake.tags
            .insert((REPOSITORY.to_owned(), fixtures::tag()), Answer::Value(tag));
        fake
    }

    /// Returns a fake that refuses every request.
    fn forbidden() -> Self {
        Self {
            forbidden: true,
            ..Self::default()
        }
    }

    /// Returns a fake whose repository is unavailable.
    fn unavailable() -> Self {
        let mut fake = Self::default();
        fake.tags.insert(
            (REPOSITORY.to_owned(), fixtures::tag()),
            Answer::Unavailable,
        );
        fake
    }

    /// Returns how often the fake was asked.
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl ReleaseRepository for FakeRepository {
    fn inspect_tag(&self, git: &str, tag: &str) -> Result<ReleaseTag> {
        self.calls.set(self.calls.get() + 1);
        if self.forbidden {
            bail!("the release repository must not be read by this run");
        }
        match self.tags.get(&(git.to_owned(), tag.to_owned())) {
            Some(Answer::Value(release)) => Ok(release.clone()),
            Some(Answer::Unavailable) => bail!("the repository {git:?} is unavailable"),
            None => bail!("the fake holds no tag {tag:?} of {git:?}"),
        }
    }
}

/// Returns the owners of a crate that one user owns.
fn user_owner(login: &str) -> Owner {
    Owner {
        login: login.to_owned(),
        kind: OwnerKind::User,
    }
}

#[test]
fn accepts_a_release_that_crates_io_does_not_have_yet() {
    let temporary = fixtures::Temp::new("pkgre-network-missing");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let crates_io =
        FakeCratesIo::missing(&[fixtures::LIB_CRATES_IO_NAME, fixtures::BIN_CRATES_IO_NAME]);
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let summary = check(&fixture, &crates_io, &repositories)
        .expect("the network checks accept a release that crates.io does not have");
    assert_eq!(summary.network_releases, 1);
    assert_eq!(summary.entries, 3);
    assert_eq!(repositories.calls(), 1);
    // Owners and versions of both crates.io names, and no category slugs.
    assert_eq!(crates_io.calls(), 4);
}

#[test]
fn accepts_a_name_with_the_expected_owners_and_the_recorded_version() {
    let temporary = fixtures::Temp::new("pkgre-network-recorded");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let entry = recorded_entry(&fixture, LIB);
    let mut crates_io = FakeCratesIo::missing(&[fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_owners(
        fixtures::LIB_CRATES_IO_NAME,
        Some(vec![user_owner("example-owner")]),
    );
    crates_io.with_versions(
        fixtures::LIB_CRATES_IO_NAME,
        Some(vec![CratesIoVersion {
            version: entry.version.clone(),
            checksum: entry.crate_sha256.clone(),
            yanked: false,
        }]),
    );
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let summary = check(&fixture, &crates_io, &repositories)
        .expect("crates.io holds the recorded version with the expected owners");
    assert_eq!(summary.network_releases, 1);
}

#[test]
fn refuses_a_published_version_with_build_metadata_and_another_checksum() {
    let temporary = fixtures::Temp::new("pkgre-network-build-metadata");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let entry = recorded_entry(&fixture, LIB);
    let mut crates_io = FakeCratesIo::missing(&[fixtures::BIN_CRATES_IO_NAME]);
    // crates.io ignores build metadata, so this is the release's version.
    crates_io.with_versions(
        fixtures::LIB_CRATES_IO_NAME,
        Some(vec![CratesIoVersion {
            version: Version::parse("1.0.0+build").expect("parse a version"),
            checksum: "b".repeat(64),
            yanked: false,
        }]),
    );
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("1.0.0+build"), "{error}");
    assert!(error.contains(&"b".repeat(64)), "{error}");
    assert!(error.contains(&entry.crate_sha256), "{error}");
}

#[test]
fn refuses_an_extra_owner() {
    let temporary = fixtures::Temp::new("pkgre-network-extra-owner");
    let fixture = fixture_without_derivation(temporary.path());
    let mut crates_io = FakeCratesIo::missing(&[fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_owners(
        fixtures::LIB_CRATES_IO_NAME,
        Some(vec![
            user_owner("example-owner"),
            user_owner("someone-else"),
        ]),
    );
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("someone-else"), "{error}");
    assert!(error.contains("expects exactly the users"), "{error}");
}

#[test]
fn refuses_a_missing_owner() {
    let temporary = fixtures::Temp::new("pkgre-network-missing-owner");
    let fixture = fixture_without_derivation(temporary.path());
    let mut crates_io = FakeCratesIo::missing(&[fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_owners(fixtures::LIB_CRATES_IO_NAME, Some(Vec::new()));
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("example-owner"), "{error}");
    assert!(error.contains("expects exactly the users"), "{error}");
}

#[test]
fn refuses_a_team_owner() {
    let temporary = fixtures::Temp::new("pkgre-network-team-owner");
    let fixture = fixture_without_derivation(temporary.path());
    let mut crates_io = FakeCratesIo::missing(&[fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_owners(
        fixtures::LIB_CRATES_IO_NAME,
        Some(vec![
            user_owner("example-owner"),
            Owner {
                login: "github:example:release".to_owned(),
                kind: OwnerKind::Team,
            },
        ]),
    );
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("github:example:release"), "{error}");
    assert!(error.contains("team"), "{error}");
}

#[test]
fn refuses_a_version_with_another_checksum() {
    let temporary = fixtures::Temp::new("pkgre-network-other-checksum");
    let fixture = fixture_without_derivation(temporary.path());
    let entry = recorded_entry(&fixture, LIB);
    let mut crates_io = FakeCratesIo::missing(&[fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_versions(
        fixtures::LIB_CRATES_IO_NAME,
        Some(vec![CratesIoVersion {
            version: entry.version.clone(),
            checksum: "b".repeat(64),
            yanked: false,
        }]),
    );
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("crates.io has crate"), "{error}");
    assert!(error.contains(&"b".repeat(64)), "{error}");
    assert!(error.contains(&entry.crate_sha256), "{error}");
}

#[test]
fn refuses_a_lightweight_tag() {
    let temporary = fixtures::Temp::new("pkgre-network-lightweight");
    let fixture = fixture_without_derivation(temporary.path());
    let crates_io = FakeCratesIo::forbidden();
    let repositories = FakeRepository::of(release_tag(&fixture, false, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("lightweight"), "{error}");
    assert!(error.contains("annotated"), "{error}");
    assert_eq!(crates_io.calls(), 0);
}

#[test]
fn refuses_a_tag_whose_commit_is_not_on_the_default_branch() {
    let temporary = fixtures::Temp::new("pkgre-network-off-branch");
    let fixture = fixture_without_derivation(temporary.path());
    let crates_io = FakeCratesIo::forbidden();
    let repositories = FakeRepository::of(release_tag(&fixture, true, false));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("default branch"), "{error}");
    assert!(error.contains("main"), "{error}");
    assert_eq!(crates_io.calls(), 0);
}

#[test]
fn refuses_a_tag_object_that_the_catalog_does_not_record() {
    let temporary = fixtures::Temp::new("pkgre-network-other-tag-object");
    let fixture = fixture_without_derivation(temporary.path());
    let crates_io = FakeCratesIo::forbidden();
    let mut tag = release_tag(&fixture, true, true);
    tag.tag_oid = "b".repeat(40);
    let repositories = FakeRepository::of(tag);
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("registry/main.lock records"), "{error}");
    assert!(error.contains(&"b".repeat(40)), "{error}");
    assert_eq!(crates_io.calls(), 0);
}

#[test]
fn refuses_a_commit_that_the_catalog_does_not_record() {
    let temporary = fixtures::Temp::new("pkgre-network-other-commit");
    let fixture = fixture_without_derivation(temporary.path());
    let crates_io = FakeCratesIo::forbidden();
    let mut tag = release_tag(&fixture, true, true);
    tag.commit = "d".repeat(40);
    let repositories = FakeRepository::of(tag);
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("registry/main.lock records"), "{error}");
    assert!(error.contains(&"d".repeat(40)), "{error}");
    assert_eq!(crates_io.calls(), 0);
}

#[test]
fn refuses_an_unavailable_release_repository() {
    let temporary = fixtures::Temp::new("pkgre-network-no-repository");
    let fixture = fixture_without_derivation(temporary.path());
    let crates_io = FakeCratesIo::forbidden();
    let repositories = FakeRepository::unavailable();
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("unavailable"), "{error}");
    assert!(error.contains(REPOSITORY), "{error}");
    assert_eq!(crates_io.calls(), 0);
}

#[test]
fn refuses_an_unavailable_crates_io() {
    let temporary = fixtures::Temp::new("pkgre-network-no-crates-io");
    let fixture = fixture_without_derivation(temporary.path());
    let crates_io = FakeCratesIo::unavailable();
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("crates.io is unavailable"), "{error}");
    assert!(error.contains("network checks of release tag"), "{error}");
}

#[test]
fn refuses_an_unknown_category() {
    let temporary = fixtures::Temp::new("pkgre-network-category");
    let fixture = fixture_with_derivation(
        temporary.path(),
        Variant {
            library_categories: Some("no-such-category"),
            ..Variant::default()
        },
    );
    let mut crates_io =
        FakeCratesIo::missing(&[fixtures::LIB_CRATES_IO_NAME, fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_slugs(&["development-tools", "command-line-utilities"]);
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("no-such-category"), "{error}");
    assert!(error.contains("category slugs"), "{error}");
}

#[test]
fn accepts_a_category_that_crates_io_knows() {
    let temporary = fixtures::Temp::new("pkgre-network-category-known");
    let fixture = fixture_with_derivation(
        temporary.path(),
        Variant {
            library_categories: Some("development-tools"),
            ..Variant::default()
        },
    );
    let mut crates_io =
        FakeCratesIo::missing(&[fixtures::LIB_CRATES_IO_NAME, fixtures::BIN_CRATES_IO_NAME]);
    crates_io.with_slugs(&["development-tools", "command-line-utilities"]);
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let summary = check(&fixture, &crates_io, &repositories)
        .expect("crates.io knows the category of the release");
    assert_eq!(summary.network_releases, 1);
    // Owners and versions of both names, and the category slugs once.
    assert_eq!(crates_io.calls(), 5);
}

#[test]
fn refuses_a_recorded_checksum_that_the_derivation_does_not_reproduce() {
    let temporary = fixtures::Temp::new("pkgre-network-recorded-checksum");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let derived = recorded_entry(&fixture, LIB).crate_sha256;
    record_a_bogus_checksum(&fixture, LIB);
    let crates_io =
        FakeCratesIo::missing(&[fixtures::LIB_CRATES_IO_NAME, fixtures::BIN_CRATES_IO_NAME]);
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(
        error.contains("reproduces the crates.io archive"),
        "{error}"
    );
    assert!(error.contains(&"c".repeat(64)), "{error}");
    assert!(error.contains(&derived), "{error}");
}

#[test]
fn checks_the_entries_that_adopting_self_publishing_adds() {
    let temporary = fixtures::Temp::new("pkgre-network-adoption");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let accepted = accepted_without_self_publishing(&fixture);
    let mut crates_io =
        FakeCratesIo::missing(&[fixtures::LIB_CRATES_IO_NAME, fixtures::BIN_CRATES_IO_NAME]);
    // The accepted repository records no entry at all, so the earlier release's
    // entry is new too, and its crates.io state is checked before the fixture
    // release is derived.
    crates_io.with_versions(
        fixtures::EARLIER_CRATES_IO_NAME,
        Some(vec![CratesIoVersion {
            version: Version::parse("0.9.0").expect("parse a version"),
            checksum: "e".repeat(64),
            yanked: false,
        }]),
    );
    let mut repositories = FakeRepository::of(release_tag(&fixture, true, true));
    repositories.tags.insert(
        (REPOSITORY.to_owned(), fixtures::EARLIER_TAG.to_owned()),
        Answer::Value(ReleaseTag {
            tag_oid: "9".repeat(40),
            commit: "9".repeat(40),
            annotated: true,
            on_default_branch: true,
            default_branch: "main".to_owned(),
        }),
    );
    let error = error_text(check_against(
        &fixture,
        &accepted,
        &crates_io,
        &repositories,
    ));
    assert!(error.contains(fixtures::EARLIER_CRATES_IO_NAME), "{error}");
    assert!(error.contains("0.9.0"), "{error}");
    assert!(error.contains(&"e".repeat(64)), "{error}");
}

#[test]
fn refuses_entries_of_a_repository_that_the_accepted_state_did_not_declare() {
    let temporary = fixtures::Temp::new("pkgre-network-repository-added");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let accepted = accepted_without_the_repository(&fixture);
    record_a_bogus_checksum(&fixture, LIB);
    let crates_io =
        FakeCratesIo::missing(&[fixtures::LIB_CRATES_IO_NAME, fixtures::BIN_CRATES_IO_NAME]);
    let repositories = FakeRepository::of(release_tag(&fixture, true, true));
    let error = error_text(check_against(
        &fixture,
        &accepted,
        &crates_io,
        &repositories,
    ));
    assert!(
        error.contains("reproduces the crates.io archive"),
        "{error}"
    );
    assert_eq!(repositories.calls(), 1);
}

#[test]
fn makes_no_request_when_the_run_adds_no_release() {
    let temporary = fixtures::Temp::new("pkgre-network-nothing-added");
    let fixture = fixture_with_derivation(temporary.path(), Variant::default());
    let crates_io = FakeCratesIo::forbidden();
    let repositories = FakeRepository::forbidden();
    let summary = check_repository_with(
        &fixture.candidate.root,
        Some(&fixture.candidate.root),
        &services(&fixture, &crates_io, &repositories),
    )
    .expect("a run that adds no release passes without a request");
    assert_eq!(summary.network_releases, 0);
    assert_eq!(crates_io.calls(), 0);
    assert_eq!(repositories.calls(), 0);
}

/// Returns the facts of a crate that meets crates.io's rules.
fn valid_facts() -> MemberFacts {
    MemberFacts {
        description: Some("An example crate".to_owned()),
        license: Some("MIT".to_owned()),
        license_file: None,
        homepage: Some("https://example.invalid/example".to_owned()),
        documentation: Some("http://example.invalid/docs".to_owned()),
        repository: Some("https://example.invalid/example/project".to_owned()),
        keywords: vec!["example".to_owned()],
        categories: Vec::new(),
    }
}

/// Returns a refusal text for one crate's facts.
fn rule_error(facts: &MemberFacts, archive_bytes: usize, slugs: &[&str]) -> String {
    let slugs = slugs.iter().map(|slug| (*slug).to_owned()).collect();
    match check_crates_io_rules(
        LIB,
        &Version::parse(fixtures::VERSION).expect("parse the fixture version"),
        facts,
        archive_bytes,
        &slugs,
    ) {
        Ok(()) => panic!("expected a refusal"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn crates_io_rules_accept_a_crate_that_meets_them() {
    let facts = MemberFacts {
        keywords: vec![
            "one".to_owned(),
            "two-words".to_owned(),
            "under_score".to_owned(),
            "c++".to_owned(),
            "k".repeat(20),
        ],
        categories: vec!["development-tools".to_owned()],
        license: None,
        license_file: Some(PathBuf::from("LICENSE")),
        description: Some("d".repeat(1000)),
        ..valid_facts()
    };
    check_crates_io_rules(
        LIB,
        &Version::parse(fixtures::VERSION).expect("parse the fixture version"),
        &facts,
        10 * 1024 * 1024,
        &["development-tools".to_owned()].into_iter().collect(),
    )
    .expect("the crate meets crates.io's rules");
}

#[test]
#[allow(clippy::too_many_lines)]
fn crates_io_rules_refuse_what_crates_io_refuses() {
    let cases: &[(MemberFacts, usize, &str, &str)] = &[
        (
            MemberFacts {
                description: None,
                ..valid_facts()
            },
            0,
            "no description",
            "description",
        ),
        (
            MemberFacts {
                description: Some("  ".to_owned()),
                ..valid_facts()
            },
            0,
            "no description",
            "description",
        ),
        (
            MemberFacts {
                description: Some("d".repeat(1001)),
                ..valid_facts()
            },
            0,
            "description of 1001 bytes",
            "at most 1000",
        ),
        (
            MemberFacts {
                license: None,
                ..valid_facts()
            },
            0,
            "neither a license nor a license-file",
            "license",
        ),
        (
            MemberFacts {
                keywords: vec![
                    "one".to_owned(),
                    "two".to_owned(),
                    "three".to_owned(),
                    "four".to_owned(),
                    "five".to_owned(),
                    "six".to_owned(),
                ],
                ..valid_facts()
            },
            0,
            "6 keywords",
            "at most 5",
        ),
        (
            MemberFacts {
                keywords: vec!["k".repeat(21)],
                ..valid_facts()
            },
            0,
            "longer than crates.io's 20 bytes",
            "keyword",
        ),
        (
            MemberFacts {
                keywords: vec!["two words".to_owned()],
                ..valid_facts()
            },
            0,
            "crates.io refuses",
            "keyword",
        ),
        (
            MemberFacts {
                keywords: vec!["-leading".to_owned()],
                ..valid_facts()
            },
            0,
            "crates.io refuses",
            "keyword",
        ),
        (
            valid_facts(),
            10 * 1024 * 1024 + 1,
            "crates.io takes at most 10485760",
            "archive",
        ),
        (
            MemberFacts {
                categories: vec![
                    "development-tools".to_owned(),
                    "development-tools::build-utils".to_owned(),
                    "development-tools::cargo-plugins".to_owned(),
                    "development-tools::debugging".to_owned(),
                    "development-tools::ffi".to_owned(),
                    "development-tools::procedural-macro-helpers".to_owned(),
                ],
                ..valid_facts()
            },
            0,
            "6 categories",
            "at most 5",
        ),
        (
            MemberFacts {
                categories: vec!["no-such-category".to_owned()],
                ..valid_facts()
            },
            0,
            "no-such-category",
            "category slugs",
        ),
        (
            MemberFacts {
                homepage: Some("example.invalid/example".to_owned()),
                ..valid_facts()
            },
            0,
            "homepage",
            "http or https",
        ),
        (
            MemberFacts {
                documentation: Some("ftp://example.invalid/docs".to_owned()),
                ..valid_facts()
            },
            0,
            "documentation",
            "http or https",
        ),
        (
            MemberFacts {
                repository: Some("https:///example/project".to_owned()),
                ..valid_facts()
            },
            0,
            "repository",
            "authority",
        ),
        (
            MemberFacts {
                homepage: Some("https://example.invalid/a b".to_owned()),
                ..valid_facts()
            },
            0,
            "homepage",
            "http or https",
        ),
    ];
    for (facts, archive_bytes, expected, also) in cases {
        let error = rule_error(facts, *archive_bytes, &["development-tools"]);
        assert!(error.contains(expected), "{expected:?} not in {error}");
        assert!(error.contains(also), "{also:?} not in {error}");
        assert!(error.contains(LIB), "the crate is named: {error}");
        assert!(
            error.contains(fixtures::VERSION),
            "the version is named: {error}"
        );
    }
}

#[test]
fn added_releases_cover_new_identities_and_new_entries_of_two_repositories() {
    let config = super::super::config::CratesIoConfig::parse(
        b"schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = \"https://git.example.invalid/a\"\ntag-prefix = \"a/v\"\n\n[[repositories]]\ngit = \"https://git.example.invalid/b\"\ntag-prefix = \"b/v\"\n",
        Path::new("crates-io.toml"),
    )
    .expect("parse the fixture config");
    let known = fixture_identity(
        "known",
        "1.0.0",
        "https://git.example.invalid/a",
        "a/v1.0.0",
    );
    let new_version = fixture_identity(
        "known",
        "1.1.0",
        "https://git.example.invalid/a",
        "a/v1.1.0",
    );
    let adopted = fixture_identity(
        "adopted",
        "1.0.0",
        "https://git.example.invalid/b",
        "b/v1.0.0",
    );
    let catalog = super::super::catalog::CatalogSnapshot {
        identities: vec![known.clone(), new_version.clone(), adopted.clone()],
        ..super::super::catalog::CatalogSnapshot::default()
    };
    let accepted = super::super::catalog::CatalogSnapshot {
        identities: vec![known.clone(), adopted.clone()],
        ..super::super::catalog::CatalogSnapshot::default()
    };
    let lock = CratesIoLock {
        schema: super::super::lock::CRATES_IO_LOCK_SCHEMA,
        packages: vec![fixture_entry(&known)],
    };
    let accepted_view = AcceptedState {
        catalog: &accepted,
        config: None,
        lock: Some(&lock),
    };
    let releases = super::added_releases(&catalog, &config, &accepted_view);
    assert_eq!(
        releases
            .iter()
            .map(|((git, tag), identities)| (git.as_str(), tag.as_str(), identities.len()))
            .collect::<Vec<_>>(),
        [
            ("https://git.example.invalid/a", "a/v1.1.0", 1),
            ("https://git.example.invalid/b", "b/v1.0.0", 1),
        ]
    );
}

/// Returns one Git identity of the fixture repository.
fn fixture_identity(
    name: &str,
    version: &str,
    git: &str,
    tag: &str,
) -> super::super::catalog::CatalogIdentity {
    super::super::catalog::CatalogIdentity {
        name: name.to_owned(),
        version: Version::parse(version).expect("parse a version"),
        crate_sha256: fixtures::crate_checksum(name, version),
        removed: false,
        release: Some(super::super::catalog::GitRelease {
            git: git.to_owned(),
            tag: tag.to_owned(),
            tag_oid: "a".repeat(40),
            commit: "a".repeat(40),
            cargo_version: Version::parse(fixtures::CARGO_VERSION)
                .expect("parse the pinned version"),
        }),
    }
}

/// Returns one `crates-io.lock` entry of a fixture identity.
fn fixture_entry(identity: &super::super::catalog::CatalogIdentity) -> CratesIoPackage {
    CratesIoPackage {
        name: identity.name.clone(),
        version: identity.version.clone(),
        crates_io_name: format!("pkgre-pkgs-{}", identity.name),
        crate_sha256: identity.crate_sha256.clone(),
        pkgre_crate_sha256: identity.crate_sha256.clone(),
        git: identity
            .release
            .as_ref()
            .expect("a fixture identity has a release")
            .git
            .clone(),
        tag: identity
            .release
            .as_ref()
            .expect("a fixture identity has a release")
            .tag
            .clone(),
        commit: "a".repeat(40),
        cargo_version: Version::parse(fixtures::CARGO_VERSION).expect("parse the pinned version"),
    }
}

#[test]
fn sparse_index_urls_follow_cargo_layout() {
    for (name, path) in [
        ("a", "1/a"),
        ("ab", "2/ab"),
        ("abc", "3/a/abc"),
        ("abcd", "ab/cd/abcd"),
        ("example-lib", "ex/am/example-lib"),
    ] {
        assert_eq!(
            live::sparse_url(name),
            format!("https://index.crates.io/{path}"),
            "{name:?}"
        );
    }
}

#[test]
fn parses_sparse_index_rows_and_refuses_an_ambiguous_one() {
    let row = |name: &str, version: &str, checksum: char, yanked: bool| {
        format!(
            "{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"{}\",\"features\":{{}},\"yanked\":{yanked}}}\n",
            checksum.to_string().repeat(64)
        )
    };
    let body = format!(
        "{}\n{}{}",
        row("demo", "1.0.0", 'a', false),
        row("demo", "1.1.0", 'b', true),
        row("demo", "1.2.0", 'c', false)
    );
    let versions = live::parse_versions("demo", body.as_bytes()).expect("parse the rows");
    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version, Version::parse("1.0.0").unwrap());
    assert_eq!(versions[0].checksum, "a".repeat(64));
    assert!(!versions[0].yanked);
    assert!(versions[1].yanked);
    assert_eq!(versions[2].checksum, "c".repeat(64));

    let duplicate = format!(
        "{}{}",
        row("demo", "1.0.0", 'a', false),
        row("demo", "1.0.0", 'b', false)
    );
    let error = live::parse_versions("demo", duplicate.as_bytes()).unwrap_err();
    assert!(format!("{error:#}").contains("repeats"), "{error:#}");

    let other = row("other", "1.0.0", 'a', false);
    let error = live::parse_versions("demo", other.as_bytes()).unwrap_err();
    assert!(
        format!("{error:#}").contains("names a package other than"),
        "{error:#}"
    );
}

#[test]
fn parses_the_owners_document_and_refuses_an_unknown_kind() {
    let body = br#"{"users":[{"kind":"user","id":1,"login":"example-owner"},{"kind":"team","id":2,"login":"github:example:release"}]}"#;
    let owners = live::parse_owners(body).expect("parse the owners");
    assert_eq!(
        owners,
        [
            Owner {
                login: "example-owner".to_owned(),
                kind: OwnerKind::User,
            },
            Owner {
                login: "github:example:release".to_owned(),
                kind: OwnerKind::Team,
            },
        ]
    );

    let unknown = br#"{"users":[{"kind":"robot","id":3,"login":"robot"}]}"#;
    let error = live::parse_owners(unknown).unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("unknown kind"), "{error}");

    let malformed = b"not a document";
    assert!(live::parse_owners(malformed).is_err());
}

#[test]
fn parses_the_category_slug_document() {
    let body = br#"{"category_slugs":[{"id":"a","slug":"development-tools","description":"d"},{"id":"b","slug":"command-line-utilities","description":"d"}]}"#;
    let slugs = live::parse_slugs(body).expect("parse the slugs");
    assert_eq!(
        slugs,
        BTreeSet::from([
            "command-line-utilities".to_owned(),
            "development-tools".to_owned(),
        ])
    );
    assert!(live::parse_slugs(b"{}").is_err());
}

#[test]
fn parses_the_default_branch_of_a_symref_listing() {
    let stdout = "ref: refs/heads/trunk\tHEAD\n0123456789abcdef0123456789abcdef01234567\tHEAD\n";
    assert_eq!(live::parse_default_branch(stdout).unwrap(), "trunk");
    assert!(live::parse_default_branch("").is_err());
    assert!(
        live::parse_default_branch("0123456789abcdef0123456789abcdef01234567\tHEAD\n").is_err()
    );
    let unsafe_branch = "ref: refs/heads/bad..name\tHEAD\n";
    assert!(live::parse_default_branch(unsafe_branch).is_err());
}

#[test]
fn splits_the_status_code_from_a_response_body() {
    let response = live::split_status(b"{}\n200").expect("split the response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{}\n");
    assert!(live::split_status(b"20").is_err());
    assert!(live::split_status(b"{}x20").is_err());
    assert!(live::split_status(b"{}abc").is_err());
}

#[test]
fn inspects_a_local_repository_whose_default_branch_is_not_main() {
    let temporary = fixtures::Temp::new("pkgre-network-local-repository");
    let root = temporary.path().join("origin");
    fs::create_dir_all(&root).expect("create the repository");
    fixtures::git(&root, &["init", "--quiet", "-b", "trunk"]);
    fs::write(root.join("file"), "one\n").expect("write a file");
    fixtures::git(&root, &["add", "."]);
    fixtures::git(&root, &["commit", "--quiet", "-m", "one"]);
    fixtures::git(&root, &["tag", "-a", "on/v1", "-m", "release"]);
    fixtures::git(&root, &["tag", "light/v1"]);
    fixtures::git(&root, &["checkout", "--quiet", "-b", "side"]);
    fs::write(root.join("file"), "two\n").expect("write a file");
    fixtures::git(&root, &["commit", "--quiet", "-am", "two"]);
    fixtures::git(&root, &["tag", "-a", "off/v1", "-m", "release"]);
    fixtures::git(&root, &["checkout", "--quiet", "trunk"]);
    let url = format!("file://{}", root.display());
    let environment = super::super::isolation::ChildEnvironment::plain();

    let annotated =
        live::inspect_tag(&url, "on/v1", &environment, true).expect("read the annotated tag");
    assert!(annotated.annotated);
    assert!(annotated.on_default_branch);
    assert_eq!(annotated.default_branch, "trunk");
    assert_ne!(annotated.tag_oid, annotated.commit);

    let lightweight =
        live::inspect_tag(&url, "light/v1", &environment, true).expect("read the lightweight tag");
    assert!(!lightweight.annotated);
    assert_eq!(lightweight.tag_oid, lightweight.commit);

    let off_branch =
        live::inspect_tag(&url, "off/v1", &environment, true).expect("read the off-branch tag");
    assert!(off_branch.annotated);
    assert!(!off_branch.on_default_branch);

    let error = live::inspect_tag(&url, "missing/v1", &environment, true).unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("missing/v1"), "{error}");
}

#[test]
fn an_unavailable_registry_names_the_registry() {
    // Nothing listens on that address, so the read fails before any document
    // arrives; the error has to name the registry and not crates.io.
    let error = LiveRegistryIndex
        .versions("sparse+https://127.0.0.1:9/", LIB)
        .expect_err("no registry listens at that address");
    let error = format!("{error:#}");
    assert!(error.contains("the pkgre registry"), "{error}");
    assert!(!error.contains("crates.io"), "{error}");
}

#[test]
#[ignore = "reads the live crates.io API and the live release repository"]
fn live_services_read_the_state_of_the_first_release() {
    let crates_io = LiveCratesIo;
    for name in ["pkgre", "pkgre-pkgs-pkgre-rust"] {
        let owners = crates_io
            .owners(name)
            .expect("read the live crates.io owners");
        let versions = crates_io
            .versions(name)
            .expect("read the live crates.io index");
        println!("live: {name} owners={owners:?} versions={versions:?}");
        assert!(
            owners.is_none(),
            "{name} is owned on crates.io already: {owners:?}"
        );
        assert!(
            versions.is_none(),
            "{name} is published on crates.io already: {versions:?}"
        );
    }
    let slugs = crates_io
        .category_slugs()
        .expect("read the live crates.io category slugs");
    println!("live: {} category slugs", slugs.len());
    for slug in ["development-tools", "command-line-utilities"] {
        assert!(slugs.contains(slug), "crates.io does not know {slug:?}");
    }
    let repositories = LiveReleaseRepository;
    let release = repositories
        .inspect_tag("https://github.com/pkgre/pkgre", "indexer/v0.3.0")
        .expect("read the live release tag");
    println!("live: {release:?}");
    assert!(release.annotated, "the live release tag is annotated");
    assert!(
        release.on_default_branch,
        "the live release tag is on the default branch"
    );
}
