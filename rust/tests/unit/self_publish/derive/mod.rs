//! Unit tests of the crates.io derivation and of `self-publish-lock`.

mod fixtures;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use semver::Version;
use toml::Value as TomlValue;

use super::super::catalog::{CatalogIdentity, CatalogSnapshot, GitRelease};
use super::super::config::CratesIoConfig;
use super::super::isolation::ensure_no_cargo_configuration;
use super::super::lock::{CRATES_IO_LOCK_SCHEMA, CratesIoLock, CratesIoPackage};
use super::super::state::RepositoryState;
use super::{DerivationSources, DerivedPackage, ReleasedCrate, derive_release};
use crate::artifact::sha256_bytes;
use crate::update::read_crate_archive;
use fixtures::{LocalSource, Release, Variant};

/// The released crates of the fixture, by package name.
const RELEASED: [&str; 2] = ["example-lib", "example-bin"];

/// Derives the fixture release from a catalog repository.
fn derive_from_catalog(
    release: &Release,
    state: &RepositoryState,
    curated: &BTreeMap<String, Vec<u8>>,
    source: &Path,
) -> Result<Vec<DerivedPackage>> {
    let self_publish = state
        .self_publish
        .as_ref()
        .expect("the catalog declares state");
    let version = Version::parse(fixtures::VERSION).expect("parse the fixture version");
    let facts = state
        .catalog
        .identity("example-lib", &version)
        .and_then(|identity| identity.release.clone())
        .expect("the catalog holds the release");
    let released = released_crates(release, curated);
    let working = fixtures::Temp::new("pkgre-derive-work");
    derive_release(
        &facts,
        &released,
        &state.catalog,
        &self_publish.config,
        &self_publish.lock,
        Some(&DerivationSources {
            fetch_repository: &release.root,
            directory: Some(source),
            root: working.path(),
        }),
    )
}

/// Returns the released crates of one fixture release.
fn released_crates(release: &Release, curated: &BTreeMap<String, Vec<u8>>) -> Vec<ReleasedCrate> {
    RELEASED
        .iter()
        .map(|name| ReleasedCrate {
            name: (*name).to_owned(),
            version: release.version(name),
            crate_sha256: sha256_bytes(&curated[*name]),
            archive: curated[*name].clone(),
        })
        .collect()
}

/// Builds the release, its curated archives, and the catalog repository.
fn fixture(parent: &Path, variant: Variant) -> (LocalSource, Release, fixtures::Catalog) {
    let source = LocalSource::build(&parent.join("local"));
    let release = fixtures::release(parent, &source, variant);
    let catalog = fixtures::catalog(parent, &source, &release, variant);
    (source, release, catalog)
}

/// The catalog facts of a fixture release, built without a catalog repository.
struct MemoryState {
    catalog: CatalogSnapshot,
    config: CratesIoConfig,
    lock: CratesIoLock,
}

/// Builds the catalog facts of one fixture release in memory.
#[allow(clippy::too_many_lines)]
fn memory_state(release: &Release, variant: Variant) -> MemoryState {
    let mut identities = Vec::new();
    for (name, version) in [
        ("mirrored-dep", "0.3.0"),
        ("mirrored-dev", "0.1.0"),
        ("other-mirror", "0.2.0"),
    ] {
        identities.push(CatalogIdentity {
            name: name.to_owned(),
            version: Version::parse(version).expect("parse the fixture version"),
            crate_sha256: fixtures::crate_checksum(name, version),
            removed: false,
            release: None,
        });
    }
    identities.push(CatalogIdentity {
        name: "earlier-lib".to_owned(),
        version: Version::parse("0.9.0").expect("parse the fixture version"),
        crate_sha256: fixtures::crate_checksum("earlier-lib", "0.9.0"),
        removed: false,
        release: Some(GitRelease {
            git: fixtures::REPOSITORY.to_owned(),
            tag: "rust/v0.9.0".to_owned(),
            tag_oid: "9".repeat(40),
            commit: "9".repeat(40),
            cargo_version: Version::parse(fixtures::CARGO_VERSION).expect("parse the version"),
        }),
    });
    if variant.fork_dependency {
        identities.push(CatalogIdentity {
            name: "forked-dep".to_owned(),
            version: Version::parse("1.0.0").expect("parse the fixture version"),
            crate_sha256: fixtures::crate_checksum("forked-dep", "1.0.0"),
            removed: false,
            release: Some(GitRelease {
                git: fixtures::FORK.to_owned(),
                tag: "fork/v1.0.0".to_owned(),
                tag_oid: "7".repeat(40),
                commit: "7".repeat(40),
                cargo_version: Version::parse(fixtures::CARGO_VERSION).expect("parse the version"),
            }),
        });
    }
    for name in RELEASED {
        identities.push(CatalogIdentity {
            name: name.to_owned(),
            version: release.version(name),
            crate_sha256: "1".repeat(64),
            removed: false,
            release: Some(GitRelease {
                git: fixtures::REPOSITORY.to_owned(),
                tag: fixtures::tag(),
                tag_oid: release.tag_oid.clone(),
                commit: release.commit.clone(),
                cargo_version: Version::parse(fixtures::CARGO_VERSION)
                    .expect("parse the pinned version"),
            }),
        });
    }
    let mirrors = vec![
        "mirrored-dep".to_owned(),
        "mirrored-dev".to_owned(),
        "other-mirror".to_owned(),
    ];
    let publish_declarations = RELEASED
        .iter()
        .map(|name| ((*name).to_owned(), fixtures::REPOSITORY.to_owned()))
        .collect::<Vec<_>>();
    let publish_names = RELEASED.iter().map(|name| (*name).to_owned()).collect();
    let catalog = CatalogSnapshot {
        identities,
        mirrors,
        publish_names,
        publish_declarations,
    };
    let config = CratesIoConfig::parse(
        format!(
            "schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = {:?}\ntag-prefix = {:?}\n\n[names]\nexample-lib = {:?}\n",
            fixtures::REPOSITORY,
            fixtures::TAG_PREFIX,
            fixtures::LIB_CRATES_IO_NAME
        )
        .as_bytes(),
        Path::new("crates-io.toml"),
    )
    .expect("parse the fixture config");
    let mut lock = CratesIoLock {
        schema: CRATES_IO_LOCK_SCHEMA,
        packages: Vec::new(),
    };
    lock.packages.push(CratesIoPackage {
        name: "earlier-lib".to_owned(),
        version: Version::parse("0.9.0").expect("parse the fixture version"),
        crates_io_name: "pkgre-pkgs-earlier-lib".to_owned(),
        crate_sha256: fixtures::crate_checksum("earlier-lib", "0.9.0"),
        pkgre_crate_sha256: fixtures::crate_checksum("earlier-lib", "0.9.0"),
        git: fixtures::REPOSITORY.to_owned(),
        tag: "rust/v0.9.0".to_owned(),
        commit: "9".repeat(40),
        cargo_version: Version::parse(fixtures::CARGO_VERSION).expect("parse the pinned version"),
    });
    MemoryState {
        catalog,
        config,
        lock,
    }
}

/// Derives a fixture release against the catalog facts of `MemoryState`, with
/// archives that no refusal reads.
fn derive_from_memory(
    release: &Release,
    state: &MemoryState,
    source: &Path,
) -> Result<Vec<DerivedPackage>> {
    let version = Version::parse(fixtures::VERSION).expect("parse the fixture version");
    let facts = state
        .catalog
        .identity("example-lib", &version)
        .and_then(|identity| identity.release.clone())
        .expect("the facts hold the release");
    let released = RELEASED
        .iter()
        .map(|name| ReleasedCrate {
            name: (*name).to_owned(),
            version: release.version(name),
            crate_sha256: "0".repeat(64),
            archive: Vec::new(),
        })
        .collect::<Vec<_>>();
    let working = fixtures::Temp::new("pkgre-derive-work");
    derive_release(
        &facts,
        &released,
        &state.catalog,
        &state.config,
        &state.lock,
        Some(&DerivationSources {
            fetch_repository: &release.root,
            directory: Some(source),
            root: working.path(),
        }),
    )
}

#[test]
fn derives_the_release_and_compares_it_with_the_curated_archives() {
    let temporary = fixtures::Temp::new("pkgre-derive-base");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    let packages = derive_from_catalog(&release, &state, &catalog.curated, &source.root)
        .expect("derive the fixture release");
    assert_eq!(packages.len(), 2);
    let version = Version::parse(fixtures::VERSION).expect("parse the fixture version");
    let lib = packages
        .iter()
        .find(|package| package.entry.name == "example-lib")
        .expect("the library is derived");
    let bin = packages
        .iter()
        .find(|package| package.entry.name == "example-bin")
        .expect("the binary is derived");
    assert_eq!(lib.entry.crates_io_name, fixtures::LIB_CRATES_IO_NAME);
    assert_eq!(bin.entry.crates_io_name, fixtures::BIN_CRATES_IO_NAME);
    for package in &packages {
        assert_eq!(package.entry.version, version);
        assert_eq!(package.entry.git, fixtures::REPOSITORY);
        assert_eq!(package.entry.tag, fixtures::tag());
        assert_eq!(package.entry.commit, release.commit);
        assert_eq!(
            package.entry.cargo_version,
            Version::parse(fixtures::CARGO_VERSION).expect("parse the pinned version")
        );
        assert_eq!(
            package.entry.pkgre_crate_sha256,
            sha256_bytes(&catalog.curated[&package.entry.name])
        );
        assert_eq!(package.entry.crate_sha256, sha256_bytes(&package.archive));
        assert_ne!(
            package.entry.crate_sha256, package.entry.pkgre_crate_sha256,
            "the rewritten manifest differs, so the archives differ"
        );
    }

    // The library keeps its library name; the binary keeps its installed name and
    // publishes to crates.io only.
    let manifest = archived_manifest(&lib.entry, &lib.archive, &version);
    assert_eq!(
        manifest["package"]["name"].as_str(),
        Some(fixtures::LIB_CRATES_IO_NAME)
    );
    assert_eq!(
        manifest["lib"]["name"].as_str(),
        Some("example_lib"),
        "the library target keeps its curated name"
    );
    let manifest = archived_manifest(&bin.entry, &bin.archive, &version);
    assert_eq!(
        manifest["package"]["name"].as_str(),
        Some(fixtures::BIN_CRATES_IO_NAME)
    );
    assert_eq!(
        manifest["package"]["publish"][0].as_str(),
        Some("crates-io")
    );
    assert_eq!(manifest["bin"][0]["name"].as_str(), Some("example-bin"));
    assert_eq!(manifest["bin"][0]["path"].as_str(), Some("src/main.rs"));

    // The lock translation renames the earlier release to its crates.io name,
    // keeps the mirrored identity's name, and names crates.io for both.
    let lock = archived_lock(&bin.entry, &bin.archive, &version);
    let packages = lock["package"].as_array().expect("the lock holds packages");
    let earlier = packages
        .iter()
        .find(|package| package["name"].as_str() == Some("pkgre-pkgs-earlier-lib"))
        .expect("the earlier release is renamed in the lock");
    assert_eq!(earlier["version"].as_str(), Some("0.9.0"));
    assert_eq!(
        earlier["checksum"].as_str(),
        Some(fixtures::crate_checksum("earlier-lib", "0.9.0").as_str())
    );
    let mirrored = packages
        .iter()
        .find(|package| package["name"].as_str() == Some("mirrored-dep"))
        .expect("the mirrored dependency keeps its name");
    assert_eq!(
        mirrored["source"].as_str(),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );
}

/// Returns the normalized manifest of one derived archive.
fn archived_manifest(entry: &CratesIoPackage, archive: &[u8], version: &Version) -> TomlValue {
    let archive = read_crate_archive(&entry.crates_io_name, version, archive, &["Cargo.toml"])
        .expect("read the derived archive");
    toml::from_slice(archive.contents["Cargo.toml"].as_slice()).expect("parse the manifest")
}

/// Returns the packaged lock of one derived archive.
fn archived_lock(entry: &CratesIoPackage, archive: &[u8], version: &Version) -> TomlValue {
    let archive = read_crate_archive(&entry.crates_io_name, version, archive, &["Cargo.lock"])
        .expect("read the derived archive");
    toml::from_slice(archive.contents["Cargo.lock"].as_slice()).expect("parse the lock")
}

#[test]
fn refuses_a_changed_source_file() {
    let temporary = fixtures::Temp::new("pkgre-derive-changed");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    // Package the curated archives again from a working tree whose library source
    // changed without a commit, which only `src/lib.rs` and `dirty` can show.
    let tampered = temporary.path().join("tampered");
    copy_tree(&release.root, &tampered);
    fs::write(
        tampered.join("lib/src/lib.rs"),
        "pub fn answer() -> u32 { 43 }\n",
    )
    .expect("change the library source");
    let changed = RELEASED
        .iter()
        .map(|name| {
            let archive = fixtures::curated_archives(
                &tampered,
                &source.root,
                &[(name, release.version(name))],
            );
            ((*name).to_owned(), archive[*name].clone())
        })
        .collect::<BTreeMap<_, _>>();
    let error = derive_from_catalog(&release, &state, &changed, &source.root)
        .expect_err("the comparison must catch the changed source");
    let error = format!("{error:#}");
    assert!(error.contains("src/lib.rs"), "{error}");
}

#[test]
fn refuses_a_dependency_between_two_released_crates_of_one_tag() {
    let temporary = fixtures::Temp::new("pkgre-derive-sibling");
    let variant = Variant {
        sibling_dependency: true,
        ..Variant::default()
    };
    let source = LocalSource::build(&temporary.path().join("local"));
    let release = fixtures::release(temporary.path(), &source, variant);
    let state = memory_state(&release, variant);
    let error = derive_from_memory(&release, &state, &source.root)
        .expect_err("a dependency between two released crates is refused");
    let error = format!("{error:#}");
    assert!(error.contains("example-lib"), "{error}");
    assert!(
        error.contains("dependency between two released crates"),
        "{error}"
    );
}

#[test]
fn refuses_a_dependency_on_a_fork() {
    let temporary = fixtures::Temp::new("pkgre-derive-fork");
    let variant = Variant {
        fork_dependency: true,
        ..Variant::default()
    };
    let source = LocalSource::build(&temporary.path().join("local"));
    let release = fixtures::release(temporary.path(), &source, variant);
    let state = memory_state(&release, variant);
    let error = derive_from_memory(&release, &state, &source.root)
        .expect_err("a dependency on a fork is refused");
    let error = format!("{error:#}");
    assert!(error.contains("forked-dep"), "{error}");
    assert!(error.contains("does not self-publish"), "{error}");
}

#[test]
fn refuses_patch_tables() {
    let temporary = fixtures::Temp::new("pkgre-derive-patch");
    let variant = Variant {
        patch: true,
        ..Variant::default()
    };
    let source = LocalSource::build(&temporary.path().join("local"));
    let release = fixtures::release(temporary.path(), &source, variant);
    let state = memory_state(&release, variant);
    let error =
        derive_from_memory(&release, &state, &source.root).expect_err("a [patch] table is refused");
    let error = format!("{error:#}");
    assert!(error.contains("[patch]"), "{error}");
}

#[test]
fn refuses_cargo_configuration_above_the_working_directory() {
    let temporary = fixtures::Temp::new("pkgre-cargo-config");
    let working = temporary.path().join("covered/inside");
    fs::create_dir_all(&working).expect("create the working directory");
    ensure_no_cargo_configuration(&working).expect("a directory without configuration is accepted");

    let configuration = temporary.path().join("covered/.cargo");
    fs::create_dir_all(&configuration).expect("create the configuration directory");
    fs::write(configuration.join("config.toml"), "[net]\noffline = true\n")
        .expect("write the configuration");
    let error = ensure_no_cargo_configuration(&working)
        .expect_err("configuration above the working directory is refused");
    assert!(
        format!("{error:#}").contains("could replace crates.io"),
        "{error:#}"
    );
    fs::remove_file(configuration.join("config.toml")).expect("remove the configuration");

    // The older filename, as a directory, is refused as well.
    fs::create_dir(configuration.join("config")).expect("create a config directory");
    let error = ensure_no_cargo_configuration(&working)
        .expect_err("a config directory above the working directory is refused");
    assert!(
        format!("{error:#}").contains("Cargo configuration"),
        "{error:#}"
    );
    fs::remove_dir(configuration.join("config")).expect("remove the config directory");

    // A symbolic link of either name is refused, since it cannot be inspected.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/dev/null", configuration.join("config.toml"))
            .expect("create the symbolic link");
        let error = ensure_no_cargo_configuration(&working)
            .expect_err("a symbolic configuration is refused");
        assert!(
            format!("{error:#}").contains("Cargo configuration"),
            "{error:#}"
        );
    }
}

/// Copies every regular file of `source` to `destination`, keeping the layout.
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create the copy");
    let mut entries = fs::read_dir(source)
        .expect("read the source")
        .map(|entry| entry.expect("read the entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path).expect("inspect the entry");
        let target = destination.join(path.file_name().expect("the entry has a name"));
        if metadata.is_dir() {
            copy_tree(&path, &target);
        } else {
            assert!(metadata.is_file(), "{} is a regular file", path.display());
            fs::copy(&path, &target).expect("copy the file");
        }
    }
}

/// Returns the checkout of the repository that these tests belong to.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the manifest directory has a parent")
        .to_path_buf()
}

#[test]
fn self_publish_lock_records_the_entries_and_changes_nothing_twice() {
    let temporary = fixtures::Temp::new("pkgre-lock-command");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let repositories = BTreeMap::from([(fixtures::REPOSITORY.to_owned(), release.root.clone())]);
    let local = super::super::lock_command::LocalNetwork {
        repositories: &repositories,
        source: &source.root,
        root: temporary.path(),
    };
    let summary = super::super::lock_command::self_publish_lock_in(&catalog.root, Some(&local))
        .expect("record the release");
    assert!(summary.changed);
    assert_eq!(summary.releases, 1);
    assert_eq!(summary.entries.len(), 2);
    let lock = CratesIoLock::load(&catalog.root.join("self-publish/crates-io.lock"))
        .expect("load the written lock");
    assert_eq!(
        lock.packages.len(),
        3,
        "the earlier release keeps its entry"
    );
    for entry in &summary.entries {
        let recorded = lock
            .entry(&entry.name, &entry.version)
            .expect("the derived entry is recorded");
        assert_eq!(recorded.crates_io_name, entry.crates_io_name);
        assert_eq!(recorded.crate_sha256, entry.crate_sha256);
        assert_eq!(recorded.pkgre_crate_sha256, entry.pkgre_crate_sha256);
        assert_eq!(recorded.git, fixtures::REPOSITORY);
        assert_eq!(recorded.tag, fixtures::tag());
        assert_eq!(recorded.commit, release.commit);
    }
    crate::self_publish::check_repository(&catalog.root, None)
        .expect("the offline checks accept the written lock");

    let path = catalog.root.join("self-publish/crates-io.lock");
    let before = fs::read(&path).expect("read the written lock");
    let second = super::super::lock_command::self_publish_lock_in(&catalog.root, Some(&local))
        .expect("a second run derives nothing");
    assert!(!second.changed);
    assert!(second.entries.is_empty());
    assert_eq!(second.releases, 0);
    assert_eq!(fs::read(&path).expect("read the lock"), before);
}

#[test]
fn refuses_to_derive_a_removed_identity() {
    let config = CratesIoConfig::parse(
        format!(
            "schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = {:?}\ntag-prefix = {:?}\n",
            fixtures::REPOSITORY,
            fixtures::TAG_PREFIX
        )
        .as_bytes(),
        Path::new("crates-io.toml"),
    )
    .expect("parse the fixture config");
    let state = RepositoryState {
        catalog: CatalogSnapshot {
            identities: vec![CatalogIdentity {
                name: "example-lib".to_owned(),
                version: Version::parse(fixtures::VERSION).expect("parse the fixture version"),
                crate_sha256: "1".repeat(64),
                removed: true,
                release: Some(GitRelease {
                    git: fixtures::REPOSITORY.to_owned(),
                    tag: fixtures::tag(),
                    tag_oid: "2".repeat(40),
                    commit: "3".repeat(40),
                    cargo_version: Version::parse(fixtures::CARGO_VERSION)
                        .expect("parse the pinned version"),
                }),
            }],
            mirrors: Vec::new(),
            publish_names: vec!["example-lib".to_owned()],
            publish_declarations: vec![("example-lib".to_owned(), fixtures::REPOSITORY.to_owned())],
        },
        catalog_root: PathBuf::from("registry"),
        self_publish: Some(super::super::state::SelfPublishState {
            config,
            lock: CratesIoLock {
                schema: CRATES_IO_LOCK_SCHEMA,
                packages: Vec::new(),
            },
        }),
    };
    let self_publish = state.self_publish.as_ref().expect("the state is declared");
    let error = super::super::lock_command::unrecorded_releases(&state, self_publish)
        .expect_err("a removed identity without an entry cannot be derived");
    let error = format!("{error:#}");
    assert!(error.contains("removed"), "{error}");
    assert!(error.contains("cannot be derived"), "{error}");
}

#[test]
#[ignore = "needs the network: it reads crates.io's index and the pkgre registry"]
#[allow(clippy::too_many_lines)]
fn rehearsal_derives_the_current_tooling_against_live_crates_io() {
    let repository = repository_root();
    let temporary = fixtures::Temp::new("pkgre-rehearsal");
    let clone = temporary.path().join("clone");
    fixtures::git(
        temporary.path(),
        &[
            "clone",
            "--quiet",
            repository.to_str().expect("the repository path is UTF-8"),
            clone.to_str().expect("the clone path is UTF-8"),
        ],
    );
    fixtures::git(&clone, &["tag", "-a", "rust/v0.5.0", "-m", "pkgre 0.5.0"]);
    let cargo_version =
        Version::parse(crate::policy::CARGO_VERSION).expect("parse the pinned Cargo version");
    let mut released = Vec::new();
    let mut facts = None;
    for name in ["pkgre", "pkgre-rust"] {
        let materialization = crate::package::resolve_git_tag_from(
            "https://github.com/pkgre/pkgre",
            "rust/v0.5.0",
            name,
            &cargo_version,
            clone.to_str().expect("the clone path is UTF-8"),
            true,
        )
        .expect("package the release with the reconciler's own packaging");
        released.push(ReleasedCrate {
            name: name.to_owned(),
            version: materialization.version.clone(),
            crate_sha256: materialization.archive_sha256.clone(),
            archive: materialization.archive_bytes.clone(),
        });
        if facts.is_none() {
            facts = Some(GitRelease {
                git: "https://github.com/pkgre/pkgre".to_owned(),
                tag: "rust/v0.5.0".to_owned(),
                tag_oid: materialization.tag_oid.clone(),
                commit: materialization.commit.clone(),
                cargo_version: cargo_version.clone(),
            });
        }
    }
    let lock: TomlValue =
        toml::from_slice(&fs::read(clone.join("Cargo.lock")).expect("read the tag's own lock"))
            .expect("parse the tag's own lock");
    let mut identities = Vec::new();
    let mut mirrors = Vec::new();
    for package in lock["package"].as_array().expect("the lock holds packages") {
        if package.get("source").and_then(TomlValue::as_str) != Some("sparse+https://rust.pkg.re/")
        {
            continue;
        }
        let name = package["name"].as_str().expect("a name").to_owned();
        let version = package["version"]
            .as_str()
            .expect("a version")
            .parse()
            .expect("a version");
        mirrors.push(name.clone());
        identities.push(CatalogIdentity {
            name,
            version,
            crate_sha256: package["checksum"].as_str().expect("a checksum").to_owned(),
            removed: false,
            release: None,
        });
    }
    for package in &released {
        identities.push(CatalogIdentity {
            name: package.name.clone(),
            version: package.version.clone(),
            crate_sha256: package.crate_sha256.clone(),
            removed: false,
            release: facts.clone(),
        });
    }
    let config = CratesIoConfig::parse(
        b"schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = \"https://github.com/pkgre/pkgre\"\ntag-prefix = \"rust/v\"\n\n[names]\npkgre = \"pkgre\"\n",
        Path::new("crates-io.toml"),
    )
    .expect("parse the rehearsal config");
    let snapshot = CatalogSnapshot {
        identities,
        mirrors,
        publish_names: vec!["pkgre".to_owned(), "pkgre-rust".to_owned()],
        publish_declarations: vec![
            (
                "pkgre".to_owned(),
                "https://github.com/pkgre/pkgre".to_owned(),
            ),
            (
                "pkgre-rust".to_owned(),
                "https://github.com/pkgre/pkgre".to_owned(),
            ),
        ],
    };
    let packages = derive_release(
        &facts.expect("the release has facts"),
        &released,
        &snapshot,
        &config,
        &CratesIoLock {
            schema: CRATES_IO_LOCK_SCHEMA,
            packages: Vec::new(),
        },
        Some(&DerivationSources {
            fetch_repository: &clone,
            directory: None,
            root: temporary.path(),
        }),
    )
    .expect("derive the release against live crates.io");
    assert_eq!(packages.len(), 2);
    for package in &packages {
        println!(
            "rehearsal: {} {} -> {} crate-sha256={} pkgre-crate-sha256={} comparison=identical",
            package.entry.name,
            package.entry.version,
            package.entry.crates_io_name,
            package.entry.crate_sha256,
            package.entry.pkgre_crate_sha256,
        );
    }
}
