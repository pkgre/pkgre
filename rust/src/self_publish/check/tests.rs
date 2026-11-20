//! Unit tests of the offline self-publishing checks.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use semver::Version;
use sha2::{Digest, Sha256};

use super::super::lock::{CRATES_IO_LOCK_SCHEMA, CratesIoPackage};
use super::super::state::CONFIG_FILE;
use super::*;

const REPOSITORY: &str = "https://git.example.invalid/example/project";
const PREFIX: &str = "rust/v";

fn checksum(label: &str) -> String {
    let digest = Sha256::digest(label.as_bytes());
    digest.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

fn config_text(
    repositories: &[(&str, &str)],
    names: &[(&str, &str)],
    abandoned: &[(&str, &str, &str)],
) -> String {
    let mut text = String::from("schema = 1\nowners = [\"example-owner\"]\n");
    for (git, prefix) in repositories {
        write!(
            text,
            "\n[[repositories]]\ngit = {git:?}\ntag-prefix = {prefix:?}\n"
        )
        .unwrap();
    }
    if !names.is_empty() {
        text.push_str("\n[names]\n");
        for (crate_name, crates_io_name) in names {
            writeln!(text, "{crate_name} = {crates_io_name:?}").unwrap();
        }
    }
    for (name, version, reason) in abandoned {
        write!(
            text,
            "\n[[abandoned]]\nname = {name:?}\nversion = {version:?}\nreason = {reason:?}\n"
        )
        .unwrap();
    }
    text
}

fn parse_config(text: &str) -> CratesIoConfig {
    CratesIoConfig::parse(text.as_bytes(), Path::new(CONFIG_FILE)).unwrap()
}

fn identity(name: &str, version: &str, tag: &str, commit: char) -> CatalogIdentity {
    CatalogIdentity {
        name: name.to_owned(),
        version: Version::parse(version).unwrap(),
        crate_sha256: checksum(&format!("pkgre {name} {version}")),
        removed: false,
        release: Some(GitRelease {
            git: REPOSITORY.to_owned(),
            tag: tag.to_owned(),
            tag_oid: commit.to_string().repeat(40),
            commit: commit.to_string().repeat(40),
            cargo_version: Version::parse("1.95.0").unwrap(),
        }),
        dependencies: Vec::new(),
    }
}

fn forked_identity(name: &str, version: &str, tag: &str) -> CatalogIdentity {
    let mut identity = identity(name, version, tag, '7');
    identity
        .release
        .as_mut()
        .expect("a forked identity is a Git identity")
        .git = "https://git.example.invalid/fork/project".to_owned();
    identity
}

fn mirror_identity(name: &str, version: &str) -> CatalogIdentity {
    CatalogIdentity {
        name: name.to_owned(),
        version: Version::parse(version).unwrap(),
        crate_sha256: checksum(&format!("crates.io {name} {version}")),
        removed: false,
        release: None,
        dependencies: Vec::new(),
    }
}

fn entry(identity: &CatalogIdentity, crates_io_name: &str) -> CratesIoPackage {
    let release = identity
        .release
        .as_ref()
        .expect("an entry comes from a Git identity");
    CratesIoPackage {
        name: identity.name.clone(),
        version: identity.version.clone(),
        crates_io_name: crates_io_name.to_owned(),
        crate_sha256: checksum(&format!(
            "crates.io archive {} {}",
            identity.name, identity.version
        )),
        pkgre_crate_sha256: identity.crate_sha256.clone(),
        git: release.git.clone(),
        tag: release.tag.clone(),
        commit: release.commit.clone(),
        cargo_version: release.cargo_version.clone(),
    }
}

fn lock_with(packages: Vec<CratesIoPackage>) -> CratesIoLock {
    CratesIoLock {
        schema: CRATES_IO_LOCK_SCHEMA,
        packages,
    }
}

/// Returns the entry of a crate whose release tag keeps its manifest: its archive
/// is both registries' package, so both checksums are the same.
fn native_entry(identity: &CatalogIdentity) -> CratesIoPackage {
    let mut entry = entry(identity, &identity.name);
    entry.crate_sha256 = entry.pkgre_crate_sha256.clone();
    entry
}

#[derive(Clone)]
struct State {
    config: String,
    lock: CratesIoLock,
    identities: Vec<CatalogIdentity>,
    mirrors: Vec<String>,
    publish_names: Vec<String>,
    publish_declarations: Vec<(String, String)>,
}

impl State {
    /// A repository that releases `example-lib` under a mapped name and
    /// `example-bin` under the default prefix, at `rust/v1.0.0`.
    fn base() -> Self {
        let lib = identity("example-lib", "1.0.0", "rust/v1.0.0", '3');
        let bin = identity("example-bin", "1.0.0", "rust/v1.0.0", '4');
        Self {
            config: config_text(
                &[(REPOSITORY, PREFIX)],
                &[("example-lib", "example-lib")],
                &[],
            ),
            lock: lock_with(vec![
                entry(&bin, "pkgre-pkgs-example-bin"),
                entry(&lib, "example-lib"),
            ]),
            identities: vec![bin, lib],
            mirrors: vec![
                "serde".to_owned(),
                "other-mirror".to_owned(),
                "reserved-mirror".to_owned(),
            ],
            publish_names: vec!["example-bin".to_owned(), "example-lib".to_owned()],
            publish_declarations: vec![
                ("example-bin".to_owned(), REPOSITORY.to_owned()),
                ("example-lib".to_owned(), REPOSITORY.to_owned()),
            ],
        }
    }

    /// A repository whose release tags keep crates.io manifests, releasing
    /// `example-lib` and `example-bin` under their own names, at `rust/v1.0.0`.
    fn native() -> Self {
        let lib = identity("example-lib", "1.0.0", "rust/v1.0.0", '3');
        let bin = identity("example-bin", "1.0.0", "rust/v1.0.0", '4');
        let mut state = Self::base();
        state.lock = lock_with(vec![native_entry(&bin), native_entry(&lib)]);
        state.identities = vec![bin, lib];
        state.set_names(&[]);
        state.set_manifests("crates-io");
        state
    }

    fn snapshot(&self) -> CatalogSnapshot {
        CatalogSnapshot {
            registry_index: "sparse+https://rust.pkg.re/".to_owned(),
            identities: self.identities.clone(),
            mirrors: self.mirrors.clone(),
            publish_names: self.publish_names.clone(),
            publish_declarations: self.publish_declarations.clone(),
        }
    }

    fn set_names(&mut self, names: &[(&str, &str)]) {
        self.config = config_text(&[(REPOSITORY, PREFIX)], names, &[]);
    }

    fn set_abandoned(&mut self, abandoned: &[(&str, &str, &str)]) {
        self.config = config_text(
            &[(REPOSITORY, PREFIX)],
            &[("example-lib", "example-lib")],
            abandoned,
        );
    }

    /// Declares the registry that the repository's release tags keep their
    /// manifests for, keeping the rest of the declaration as it is.
    fn set_manifests(&mut self, manifests: &str) {
        let anchor = format!("tag-prefix = {PREFIX:?}\n");
        let declared = format!("{anchor}manifests = {manifests:?}\n");
        let without = self
            .config
            .lines()
            .filter(|line| !line.starts_with("manifests = "))
            .fold(String::new(), |mut text, line| {
                text.push_str(line);
                text.push('\n');
                text
            });
        self.config = without.replace(&anchor, &declared);
    }

    fn add_release(
        &mut self,
        name: &str,
        version: &str,
        tag: &str,
        crates_io_name: &str,
        commit: char,
    ) {
        let identity = identity(name, version, tag, commit);
        self.lock.packages.push(entry(&identity, crates_io_name));
        self.identities.push(identity);
    }

    /// Moves every repository reference of the state to one spelling.
    fn respell_repository(&mut self, git: &str) {
        for identity in &mut self.identities {
            if let Some(release) = &mut identity.release {
                release.git = git.to_owned();
            }
        }
        for package in &mut self.lock.packages {
            package.git = git.to_owned();
        }
        for declaration in &mut self.publish_declarations {
            declaration.1 = git.to_owned();
        }
    }

    fn state(&self) -> SelfPublishState {
        SelfPublishState {
            config: parse_config(&self.config),
            lock: self.lock.clone(),
        }
    }
}

fn run_checks(candidate: &State, accepted: Option<&State>) -> Result<SelfPublishCheckSummary> {
    let candidate_snapshot = candidate.snapshot();
    let candidate_state = candidate.state();
    let accepted_config = accepted.map(|state| parse_config(&state.config));
    let accepted_snapshot = accepted.map(State::snapshot);
    let accepted_lock = accepted.map(|state| state.lock.clone());
    let accepted_view = accepted.map(|_| AcceptedState {
        catalog: accepted_snapshot
            .as_ref()
            .expect("an accepted state has a catalog"),
        config: accepted_config.as_ref(),
        lock: accepted_lock.as_ref(),
    });
    check_state(
        &candidate_state,
        &candidate_snapshot,
        accepted_view.as_ref(),
    )
}

fn error_text(result: Result<SelfPublishCheckSummary>) -> String {
    match result {
        Ok(summary) => panic!("expected a refusal, got {summary:?}"),
        Err(error) => format!("{error:#}"),
    }
}

fn simple_error_text(result: Result<()>) -> String {
    match result {
        Ok(()) => panic!("expected a refusal"),
        Err(error) => format!("{error:#}"),
    }
}

#[track_caller]
fn assert_refused(candidate: &State, accepted: Option<&State>, expected: &str) -> String {
    let error = error_text(run_checks(candidate, accepted));
    assert!(error.contains(expected), "{expected:?} not in {error}");
    error
}

#[test]
fn accepts_a_valid_state_and_the_canonical_lock_round_trips() {
    let state = State::base();
    let summary = run_checks(&state, None).unwrap();
    assert!(summary.declared);
    assert_eq!(summary.repositories, 1);
    assert_eq!(summary.names, 1);
    assert_eq!(summary.entries, 2);
    assert_eq!(summary.identities, 2);
    assert!(!summary.accepted);

    let summary = run_checks(&state, Some(&state)).unwrap();
    assert!(summary.accepted);

    let bytes = state.lock.serialize().unwrap();
    assert_eq!(
        CratesIoLock::parse_canonical(&bytes, Path::new(LOCK_FILE)).unwrap(),
        state.lock
    );
}

#[test]
fn accepts_an_earlier_non_release_identity_and_a_removed_identity() {
    let mut state = State::base();
    // An earlier identity of the same repository from a tag outside the
    // release convention, as the catalog has before a repository adopts
    // self-publishing: it has no entry of its own.
    state
        .identities
        .push(identity("example-indexer", "0.3.0", "indexer/v0.3.0", '5'));
    // A removed self-published identity keeps its entry.
    let removed = identity("example-lib", "0.9.0", "rust/v0.9.0", '6');
    state.lock.packages.push(entry(&removed, "example-lib"));
    state.identities.push(removed);
    run_checks(&state, Some(&state)).unwrap();
}

#[test]
fn accepts_a_new_mapping_after_every_entry_is_abandoned() {
    let mut accepted = State::base();
    accepted.set_abandoned(&[("example-lib", "1.0.0", "crates.io refused the upload")]);
    let mut candidate = accepted.clone();
    candidate.config = config_text(
        &[(REPOSITORY, PREFIX)],
        &[("example-lib", "example-renamed")],
        &[("example-lib", "1.0.0", "crates.io refused the upload")],
    );
    run_checks(&candidate, Some(&accepted)).unwrap();
    // Without an accepted repository the abandoned entry keeps its name too.
    run_checks(&candidate, None).unwrap();
}

#[test]
fn accepts_a_names_key_for_a_declared_crate_without_an_identity() {
    let mut state = State::base();
    state.publish_names.push("future-crate".to_owned());
    state
        .publish_declarations
        .push(("future-crate".to_owned(), REPOSITORY.to_owned()));
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("future-crate", "future-name"),
    ]);
    run_checks(&state, None).unwrap();
}

#[test]
fn refuses_a_mapped_name_in_the_default_namespace() {
    let mut state = State::base();
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("example-bin", "pkgre-pkgs-other"),
    ]);
    assert_refused(&state, None, "pkgre-pkgs- namespace");
}

#[test]
fn refuses_two_names_equal_under_crates_ios_comparison() {
    let mut state = State::base();
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("example-bin", "Example-Lib"),
    ]);
    assert_refused(&state, None, "both use the crates.io name");

    state.set_names(&[
        ("example-lib", "example-name"),
        ("example-bin", "Example_Name"),
    ]);
    assert_refused(&state, None, "both use the crates.io name");
}

#[test]
fn refuses_a_name_longer_than_64_characters() {
    let mut state = State::base();
    let long = "a".repeat(65);
    state.set_names(&[("example-lib", long.as_str())]);
    assert_refused(&state, None, "longer than 64 characters");

    // 60 characters plus the default prefix is longer than crates.io allows.
    let mut state = State::base();
    let long_crate = "b".repeat(60);
    let identity = identity(&long_crate, "1.0.0", "rust/v1.0.0", '5');
    let default = name::default_name(&long_crate);
    state.lock.packages.push(entry(&identity, &default));
    state.identities.push(identity);
    assert_refused(&state, None, "longer than 64 characters");
}

#[test]
fn refuses_a_reserved_name() {
    let mut state = State::base();
    state.set_names(&[("example-lib", "example-lib"), ("example-bin", "NUL")]);
    assert_refused(&state, None, "reserves the crate name");
}

#[test]
fn refuses_a_mapped_name_that_is_a_mirror() {
    let mut state = State::base();
    state.set_names(&[("example-lib", "serde")]);
    let error = assert_refused(&state, None, "registry/main mirrors");
    assert!(
        error.contains(
            "crates.io name \"serde\" of crate \"example-lib\" is the name of a crate that registry/main mirrors"
        ),
        "{error}"
    );
}

#[test]
fn refuses_a_mirror_in_the_default_namespace() {
    let mut state = State::base();
    state.mirrors.push("pkgre-pkgs-x".to_owned());
    assert_refused(&state, None, "pkgre-pkgs- namespace");
}

#[test]
fn refuses_a_mapped_name_of_an_undeclared_crate_that_a_mirror_uses() {
    let mut state = State::base();
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("future-crate", "reserved-mirror"),
    ]);
    let error = assert_refused(&state, None, "mapped crates.io name");
    assert!(
        error.contains(
            "mapped crates.io name \"reserved-mirror\" of crate \"future-crate\" is the name of a crate that registry/main mirrors"
        ),
        "{error}"
    );
}

#[test]
fn refuses_a_stale_names_key() {
    // A crate of the catalog that no self-publishing repository publishes.
    let mut state = State::base();
    state
        .identities
        .push(forked_identity("forked-crate", "1.0.0", "fork/v1.0.0"));
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("forked-crate", "forked-crate"),
    ]);
    assert_refused(&state, None, "the stale key must go");
}

#[test]
fn refuses_a_stale_keys_name_for_a_declared_mirror_without_versions() {
    let mut state = State::base();
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("reserved-mirror", "my-reserved"),
    ]);
    assert_refused(&state, None, "declares as a mirror");
}

#[test]
fn refuses_a_names_key_that_differs_from_the_catalogs_spelling() {
    let mut state = State::base();
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("example_bin", "example-binary"),
    ]);
    assert_refused(&state, None, "use the catalog's spelling");
}

#[test]
fn accepts_a_names_key_before_the_crates_first_release() {
    let mut state = State::base();
    state.set_names(&[
        ("example-lib", "example-lib"),
        ("future-crate", "future-name"),
    ]);
    run_checks(&state, None).unwrap();

    // A declared name follows the name rules even before its crate exists.
    state.set_names(&[("example-lib", "example-lib"), ("future-crate", "nul")]);
    assert_refused(&state, None, "reserves the crate name");
}

#[test]
fn refuses_a_missing_entry() {
    let mut state = State::base();
    state
        .lock
        .packages
        .retain(|entry| entry.name != "example-bin");
    assert_refused(&state, None, "has no entry in crates-io.lock");
}

#[test]
fn refuses_an_entry_without_a_self_published_identity() {
    let mut state = State::base();
    let other = identity("other-crate", "1.0.0", "rust/v1.0.0", '5');
    state
        .lock
        .packages
        .push(entry(&other, "pkgre-pkgs-other-crate"));
    assert_refused(&state, None, "has no self-published identity");
}

#[test]
fn refuses_an_entry_that_disagrees_with_its_identity() {
    let changes: &[fn(&mut CratesIoPackage)] = &[
        |entry| entry.pkgre_crate_sha256 = "0".repeat(64),
        |entry| entry.commit = "0".repeat(40),
        |entry| entry.tag = "rust/v1.0.1".to_owned(),
        |entry| entry.git = "https://git.example.invalid/other".to_owned(),
        |entry| entry.cargo_version = Version::parse("1.96.0").unwrap(),
    ];
    for change in changes {
        let mut state = State::base();
        let target = state
            .lock
            .packages
            .iter_mut()
            .find(|entry| entry.name == "example-lib")
            .unwrap();
        change(target);
        assert_refused(&state, None, "but registry/main.lock records");
    }
}

#[test]
fn refuses_a_new_entry_under_a_name_the_mapping_does_not_give() {
    let mut state = State::base();
    state.add_release("example-lib", "1.1.0", "rust/v1.1.0", "other-name", '5');
    assert_refused(&state, None, "but the mapping gives");
}

#[test]
fn refuses_removing_a_names_key_that_a_crate_falls_back_from() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.set_names(&[]);
    assert_refused(&candidate, Some(&accepted), "but the mapping gives");

    // Without an accepted state, the recorded name is still not the default one.
    let mut candidate = State::base();
    candidate.set_names(&[]);
    assert_refused(&candidate, None, "but the mapping gives");
}

#[test]
fn refuses_a_changed_or_removed_entry_against_the_accepted_state() {
    let accepted = State::base();

    let mut changed = State::base();
    let target = changed
        .lock
        .packages
        .iter_mut()
        .find(|entry| entry.name == "example-lib")
        .unwrap();
    target.crate_sha256 = "0".repeat(64);
    assert_refused(&changed, Some(&accepted), "changed in crates-io.lock");

    let mut removed = State::base();
    removed
        .lock
        .packages
        .retain(|entry| entry.name != "example-bin");
    assert_refused(&removed, Some(&accepted), "was removed from crates-io.lock");
}

#[test]
fn refuses_a_removed_repository_a_changed_prefix_or_a_respelled_repository() {
    let accepted = State::base();

    let mut removed = State::base();
    removed.config = config_text(&[], &[("example-lib", "example-lib")], &[]);
    assert_refused(
        &removed,
        Some(&accepted),
        "was removed from [[repositories]]",
    );

    let mut changed = State::base();
    changed.config = config_text(
        &[(REPOSITORY, "rust2/v")],
        &[("example-lib", "example-lib")],
        &[],
    );
    assert_refused(&changed, Some(&accepted), "changed tag-prefix");

    // A candidate whose catalog and config agree on a new spelling still
    // respelled the accepted declaration.
    let respelled_git = "https://git.example.invalid/example/project.git";
    let mut respelled = State::base();
    respelled.config = config_text(
        &[(respelled_git, PREFIX)],
        &[("example-lib", "example-lib")],
        &[],
    );
    respelled.respell_repository(respelled_git);
    assert_refused(&respelled, Some(&accepted), "was respelled");
}

#[test]
fn refuses_a_catalog_repository_spelled_differently_from_its_declaration() {
    let mut state = State::base();
    let other = CatalogIdentity {
        name: "example-tool".to_owned(),
        version: Version::parse("2.0.0").unwrap(),
        crate_sha256: checksum("pkgre example-tool 2.0.0"),
        removed: false,
        release: Some(GitRelease {
            git: "https://Git.Example.Invalid/example/project.git".to_owned(),
            tag: "rust/v2.0.0".to_owned(),
            tag_oid: "8".repeat(40),
            commit: "5".repeat(40),
            cargo_version: Version::parse("1.95.0").unwrap(),
        }),
        dependencies: Vec::new(),
    };
    state
        .lock
        .packages
        .push(entry(&other, "pkgre-pkgs-example-tool"));
    state.identities.push(other);
    assert_refused(
        &state,
        None,
        "is another spelling of the self-publishing repository",
    );

    // A publish declaration counts even before it has an identity.
    let mut state = State::base();
    state.publish_declarations.push((
        "future-crate".to_owned(),
        "https://git.example.invalid/example/project.git".to_owned(),
    ));
    assert_refused(&state, None, "publish declaration");
}

#[test]
fn refuses_an_abandoned_record_without_an_entry_or_one_that_disappears() {
    let mut state = State::base();
    state.set_abandoned(&[("example-lib", "2.0.0", "crates.io refused the upload")]);
    assert_refused(&state, None, "names no entry of crates-io.lock");

    let mut accepted = State::base();
    accepted.set_abandoned(&[("example-lib", "1.0.0", "crates.io refused the upload")]);
    let candidate = State::base();
    assert_refused(&candidate, Some(&accepted), "was removed");

    let mut candidate = accepted.clone();
    candidate.set_abandoned(&[("example-lib", "1.0.0", "a different reason")]);
    assert_refused(&candidate, Some(&accepted), "changed");
}

#[test]
fn refuses_abandoning_a_version_in_the_change_that_adds_it() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.add_release("example-tool", "1.1.0", "rust/v1.1.0", "another-name", '5');
    candidate.config = config_text(
        &[(REPOSITORY, PREFIX)],
        &[("example-lib", "example-lib")],
        &[("example-tool", "1.1.0", "crates.io refused the upload")],
    );
    assert_refused(
        &candidate,
        Some(&accepted),
        "names no entry of the accepted crates-io.lock",
    );
}

#[test]
fn accepts_abandoning_an_already_released_version() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.set_abandoned(&[("example-lib", "1.0.0", "crates.io refused the upload")]);
    run_checks(&candidate, Some(&accepted)).unwrap();
}

#[test]
fn refuses_a_changed_name_while_an_entry_is_not_abandoned() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.set_names(&[("example-lib", "example-renamed")]);
    assert_refused(&candidate, Some(&accepted), "but the mapping gives");
}

#[test]
fn refuses_an_identity_from_a_tag_outside_the_release_convention() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate
        .identities
        .push(identity("example-lib", "1.1.0", "cli/v1.1.0", '5'));
    assert_refused(
        &candidate,
        Some(&accepted),
        "a tag of a self-publishing repository is its tag-prefix followed by the version",
    );
}

#[test]
fn refuses_a_crate_added_to_an_already_released_tag() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.add_release(
        "example-tool",
        "1.0.0",
        "rust/v1.0.0",
        "pkgre-pkgs-example-tool",
        '5',
    );
    assert_refused(&candidate, Some(&accepted), "was added to tag");
}

#[test]
fn refuses_a_version_that_does_not_increase_per_crate() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.add_release("example-lib", "0.9.0", "rust/v0.9.0", "example-lib", '5');
    assert_refused(
        &candidate,
        Some(&accepted),
        "does not increase the version of the crate",
    );
}

#[test]
fn refuses_two_releases_added_in_one_change_without_order() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.add_release("example-lib", "1.2.0", "rust/v1.2.0", "example-lib", '5');
    candidate.add_release("example-lib", "1.1.0", "rust/v1.1.0", "example-lib", '6');
    assert_refused(
        &candidate,
        Some(&accepted),
        "does not increase the version of the crate",
    );
}

#[test]
fn refuses_a_version_that_does_not_increase_per_repository() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.add_release(
        "example-tool",
        "0.5.0",
        "rust/v0.5.0",
        "pkgre-pkgs-example-tool",
        '5',
    );
    assert_refused(
        &candidate,
        Some(&accepted),
        "does not increase the release version",
    );
}

#[test]
fn accepts_a_release_tag_that_publishes_several_crates() {
    let accepted = State::base();
    let mut candidate = State::base();
    candidate
        .identities
        .push(identity("example-tool", "1.1.0", "rust/v1.1.0", '5'));
    candidate.lock.packages.push(entry(
        candidate.identities.last().unwrap(),
        "pkgre-pkgs-example-tool",
    ));
    candidate.lock.packages.push(entry(
        &identity("example-lib", "1.1.0", "rust/v1.1.0", '6'),
        "example-lib",
    ));
    candidate
        .identities
        .push(identity("example-lib", "1.1.0", "rust/v1.1.0", '6'));
    candidate
        .identities
        .push(identity("example-bin", "1.1.0", "rust/v1.1.0", '8'));
    candidate.lock.packages.push(entry(
        candidate.identities.last().unwrap(),
        "pkgre-pkgs-example-bin",
    ));
    run_checks(&candidate, Some(&accepted)).unwrap();
}

#[test]
fn refuses_a_release_version_with_build_metadata() {
    let mut state = State::base();
    let release = identity("example-lib", "1.1.0+build.1", "rust/v1.1.0+build.1", '5');
    state.lock.packages.push(entry(&release, "example-lib"));
    state.identities.push(release);
    assert_refused(&state, None, "carries build metadata");
}

#[test]
fn refuses_removing_the_self_publishing_state_of_the_accepted_repository() {
    let state = State::base();
    let candidate = RepositoryState {
        catalog: CatalogSnapshot::default(),
        catalog_root: std::path::PathBuf::from("registry"),
        self_publish: None,
    };
    let accepted = RepositoryState {
        catalog: CatalogSnapshot::default(),
        catalog_root: std::path::PathBuf::from("registry"),
        self_publish: Some(state.state()),
    };
    let error = simple_error_text(check_state_not_removed(&candidate, Some(&accepted)));
    assert!(error.contains("is only ever added"), "{error}");
    check_state_not_removed(&candidate, None).unwrap();
    let declared = RepositoryState {
        catalog: CatalogSnapshot::default(),
        catalog_root: std::path::PathBuf::from("registry"),
        self_publish: Some(state.state()),
    };
    check_state_not_removed(&declared, Some(&accepted)).unwrap();
}

#[test]
fn an_accepted_catalog_without_self_publishing_state_still_bounds_versions() {
    let accepted = CatalogSnapshot {
        registry_index: String::new(),
        identities: vec![mirror_identity("example-lib", "1.0.0")],
        mirrors: Vec::new(),
        publish_names: Vec::new(),
        publish_declarations: Vec::new(),
    };
    let candidate_catalog = CatalogSnapshot {
        registry_index: String::new(),
        identities: vec![
            mirror_identity("example-lib", "1.0.0"),
            identity("example-lib", "0.9.0", "rust/v0.9.0", '5'),
        ],
        mirrors: Vec::new(),
        publish_names: Vec::new(),
        publish_declarations: Vec::new(),
    };
    let lock = lock_with(vec![entry(&candidate_catalog.identities[1], "example-lib")]);
    let candidate = SelfPublishState {
        config: parse_config(&State::base().config),
        lock,
    };
    let accepted_view = AcceptedState {
        catalog: &accepted,
        config: None,
        lock: None,
    };
    let error = error_text(check_state(
        &candidate,
        &candidate_catalog,
        Some(&accepted_view),
    ));
    assert!(
        error.contains("does not increase the version of the crate"),
        "{error}"
    );
}

#[test]
fn accepts_a_repository_whose_release_tags_keep_crates_io_manifests() {
    let state = State::native();
    let summary = run_checks(&state, None).unwrap();
    assert_eq!(summary.repositories, 1);
    assert_eq!(summary.names, 0);
    assert_eq!(summary.entries, 2);
    assert_eq!(summary.identities, 2);
    run_checks(&state, Some(&state)).unwrap();

    // Spelling the default value explicitly is no change: a declaration that had
    // no `manifests` key and now has `manifests = "pkgre"` is accepted.
    let accepted = State::base();
    let mut candidate = State::base();
    candidate.set_manifests("pkgre");
    run_checks(&candidate, Some(&accepted)).unwrap();

    // Removing it again is no change either.
    let mut accepted = State::base();
    accepted.set_manifests("pkgre");
    let candidate = State::base();
    run_checks(&candidate, Some(&accepted)).unwrap();
}

#[test]
fn refuses_a_renamed_abandoned_entry_of_a_native_repository() {
    let mut state = State::native();
    state.config = config_text(
        &[(REPOSITORY, PREFIX)],
        &[],
        &[("example-lib", "1.0.0", "crates.io refused the upload")],
    );
    state.set_manifests("crates-io");
    // The crate's own name is accepted, abandoned or not.
    run_checks(&state, None).unwrap();

    // An abandoned entry may keep another name only in the `pkgre` mode, where a
    // mapping can have changed; nothing rewrites a native tag's manifest.
    let target = state
        .lock
        .packages
        .iter_mut()
        .find(|entry| entry.name == "example-lib")
        .unwrap();
    target.crates_io_name = "example-renamed".to_owned();
    assert_refused(&state, None, "is its package name");
}

#[test]
fn refuses_a_changed_or_removed_manifests_value() {
    let accepted = State::native();

    let mut candidate = State::native();
    candidate.set_manifests("pkgre");
    assert_refused(&candidate, Some(&accepted), "changed manifests");

    let mut candidate = State::native();
    candidate.config = config_text(&[(REPOSITORY, PREFIX)], &[], &[]);
    assert_refused(&candidate, Some(&accepted), "changed manifests");

    let accepted = State::base();
    let candidate = State::native();
    assert_refused(&candidate, Some(&accepted), "changed manifests");
}

#[test]
fn refuses_a_names_key_for_a_crate_of_a_native_repository() {
    let mut state = State::native();
    state.set_names(&[("example-lib", "example-lib")]);
    state.set_manifests("crates-io");
    let error = assert_refused(&state, None, "its crates.io name is its package name");
    assert!(
        error.contains("[names] maps crate \"example-lib\""),
        "{error}"
    );

    // The same holds when the key would rename the crate.
    let mut state = State::native();
    state.set_names(&[("example-lib", "example-renamed")]);
    state.set_manifests("crates-io");
    assert_refused(&state, None, "its crates.io name is its package name");
}

#[test]
fn refuses_a_native_name_in_the_default_namespace() {
    let mut state = State::native();
    let crate_name = "pkgre-pkgs-example";
    let release = identity(crate_name, "1.0.0", "rust/v1.0.0", '5');
    state.lock.packages.push(native_entry(&release));
    state.identities.push(release);
    state.publish_names.push(crate_name.to_owned());
    state
        .publish_declarations
        .push((crate_name.to_owned(), REPOSITORY.to_owned()));
    assert_refused(&state, None, "pkgre-pkgs- namespace");
}

#[test]
fn refuses_a_native_name_that_is_a_mirror() {
    let mut state = State::native();
    let release = identity("serde", "1.0.0", "rust/v1.0.0", '5');
    state.lock.packages.push(native_entry(&release));
    state.identities.push(release);
    state.publish_names.push("serde".to_owned());
    state
        .publish_declarations
        .push(("serde".to_owned(), REPOSITORY.to_owned()));
    assert_refused(&state, None, "registry/main mirrors");
}

#[test]
fn refuses_a_native_entry_whose_name_or_checksums_differ() {
    let mut state = State::native();
    let target = state
        .lock
        .packages
        .iter_mut()
        .find(|entry| entry.name == "example-lib")
        .unwrap();
    target.crates_io_name = "example-renamed".to_owned();
    assert_refused(&state, None, "is its package name");

    let mut state = State::native();
    let target = state
        .lock
        .packages
        .iter_mut()
        .find(|entry| entry.name == "example-lib")
        .unwrap();
    target.crate_sha256 = "0".repeat(64);
    assert_refused(&state, None, "its archive is both registries' package");
}
