//! Unit tests of the network checks of the releases that a run adds.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use semver::Version;

use super::super::check::{SelfPublishCheckSummary, check_repository_with};
use super::super::derive::MemberFacts;
use super::super::derive::tests::fixtures::{self, LocalSource, Release, Variant};
use super::super::lock::{CratesIoLock, CratesIoPackage};
use super::super::lock_command::{LocalNetwork, self_publish_lock_in};
use super::super::state::LOCK_FILE;
use super::{
    CratesIo, CratesIoVersion, DerivationSources, LiveCratesIo, LiveReleaseRepository,
    LocalSources, Owner, OwnerKind, ReleaseRepository, ReleaseTag, Services, check_crates_io_rules,
};
use crate::artifact::sha256_bytes;

/// The crate that the fixture maps to a crates.io name.
const LIB: &str = "example-lib";
/// The crate that the fixture gives the default crates.io name.
const BIN: &str = "example-bin";

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
    let repositories = BTreeMap::from([(
        fixtures::REPOSITORY.to_owned(),
        fixture.release.root.clone(),
    )]);
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
            git: fixtures::REPOSITORY.to_owned(),
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
            repositories: BTreeMap::from([(
                fixtures::REPOSITORY.to_owned(),
                fixture.release.root.clone(),
            )]),
            directory: Some(fixture.source.root.clone()),
            root: fixture.work.path().to_path_buf(),
        }),
    }
}

/// Runs the checks of one fixture against the given fakes.
fn check(
    fixture: &Fixture,
    crates_io: &FakeCratesIo,
    repositories: &FakeRepository,
) -> Result<SelfPublishCheckSummary> {
    check_repository_with(
        &fixture.candidate.root,
        Some(&fixture.accepted.root),
        &services(fixture, crates_io, repositories),
    )
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
fn release_tag(annotated: bool, on_default_branch: bool) -> ReleaseTag {
    ReleaseTag {
        commit: "a".repeat(40),
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
            forbidden: false,
            owners: BTreeMap::new(),
            versions: BTreeMap::new(),
            slugs: None,
            calls: Cell::new(0),
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

    /// Counts one request.
    fn count(&self) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        if self.forbidden {
            bail!("crates.io must not be read by this run");
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
        fake.tags.insert(
            (fixtures::REPOSITORY.to_owned(), fixtures::tag()),
            Answer::Value(tag),
        );
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
            (fixtures::REPOSITORY.to_owned(), fixtures::tag()),
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
    let repositories = FakeRepository::of(release_tag(true, true));
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
        }]),
    );
    let repositories = FakeRepository::of(release_tag(true, true));
    let summary = check(&fixture, &crates_io, &repositories)
        .expect("crates.io holds the recorded version with the expected owners");
    assert_eq!(summary.network_releases, 1);
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
    let repositories = FakeRepository::of(release_tag(true, true));
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
    let repositories = FakeRepository::of(release_tag(true, true));
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
    let repositories = FakeRepository::of(release_tag(true, true));
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
        }]),
    );
    let repositories = FakeRepository::of(release_tag(true, true));
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
    let repositories = FakeRepository::of(release_tag(false, true));
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
    let repositories = FakeRepository::of(release_tag(true, false));
    let error = error_text(check(&fixture, &crates_io, &repositories));
    assert!(error.contains("default branch"), "{error}");
    assert!(error.contains("main"), "{error}");
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
    assert!(error.contains(fixtures::REPOSITORY), "{error}");
    assert_eq!(crates_io.calls(), 0);
}

#[test]
fn refuses_an_unavailable_crates_io() {
    let temporary = fixtures::Temp::new("pkgre-network-no-crates-io");
    let fixture = fixture_without_derivation(temporary.path());
    let mut crates_io = FakeCratesIo::unavailable();
    crates_io
        .owners
        .insert(fixtures::LIB_CRATES_IO_NAME.to_owned(), Answer::Unavailable);
    let repositories = FakeRepository::of(release_tag(true, true));
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
    let repositories = FakeRepository::of(release_tag(true, true));
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
    let repositories = FakeRepository::of(release_tag(true, true));
    let summary = check(&fixture, &crates_io, &repositories)
        .expect("crates.io knows the category of the release");
    assert_eq!(summary.network_releases, 1);
    // Owners and versions of both names, and the category slugs once.
    assert_eq!(crates_io.calls(), 5);
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
                categories: vec!["no-such-category".to_owned()],
                ..valid_facts()
            },
            0,
            "no-such-category",
            "category slugs",
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
