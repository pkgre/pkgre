//! Unit tests of the crates.io derivation and of `self-publish-lock`.

pub(crate) mod fixtures;

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
use super::cargo_lock::LockIndex;
use super::compare::{ArchiveToCompare, compare_archives};
use super::expectations::Expectations;
use super::{ReleasedCrate, Sources, derive_release_in, derive_release_with};
use crate::artifact::sha256_bytes;
use crate::update::read_crate_archive;
use fixtures::{LocalSource, Release, Variant};

/// The released crates of the fixture, by package name.
const RELEASED: [&str; 2] = ["example-lib", "example-bin"];

/// Builds the release, its curated archives, and the catalog repository.
fn fixture(parent: &Path, variant: Variant) -> (LocalSource, Release, fixtures::Catalog) {
    let source = LocalSource::build(&parent.join("local"));
    let release = fixtures::release(parent, &source, variant);
    let catalog = fixtures::catalog(parent, &source, &release, variant);
    (source, release, catalog)
}

/// Builds only the source and the release, for a refusal that needs no catalog.
fn release_only(parent: &Path, variant: Variant) -> (LocalSource, Release) {
    let source = LocalSource::build(&parent.join("local"));
    let release = fixtures::release(parent, &source, variant);
    (source, release)
}

/// Derives the fixture release from a catalog repository.
fn derive_from_catalog(
    release: &Release,
    state: &RepositoryState,
    curated: &BTreeMap<String, Vec<u8>>,
    source: &Path,
) -> Result<Vec<super::DerivedPackage>> {
    derive_with_members(release, state, curated, source, &RELEASED)
}

/// Derives the fixture release with the given catalog crates.
fn derive_with_members(
    release: &Release,
    state: &RepositoryState,
    curated: &BTreeMap<String, Vec<u8>>,
    source: &Path,
    members: &[&str],
) -> Result<Vec<super::DerivedPackage>> {
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
    let released = members
        .iter()
        .map(|name| {
            let archive = curated.get(*name).cloned().unwrap_or_default();
            ReleasedCrate {
                name: (*name).to_owned(),
                version: release.version(name),
                crate_sha256: sha256_bytes(&archive),
                archive,
            }
        })
        .collect::<Vec<_>>();
    let working = fixtures::Temp::new("pkgre-derive-work");
    derive_release_with(
        &facts,
        &released,
        &state.catalog,
        &self_publish.config,
        &self_publish.lock,
        Sources::local(&release.root, Some(source), working.path()),
    )
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
            tag: fixtures::EARLIER_TAG.to_owned(),
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
    if variant.server_needs_first_party {
        identities.push(CatalogIdentity {
            name: "unknown-lib".to_owned(),
            version: Version::parse("1.0.0").expect("parse the fixture version"),
            crate_sha256: fixtures::crate_checksum("unknown-lib", "1.0.0"),
            removed: false,
            release: Some(GitRelease {
                git: fixtures::REPOSITORY.to_owned(),
                tag: "rust/v0.8.0".to_owned(),
                tag_oid: "8".repeat(40),
                commit: "8".repeat(40),
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
        registry_index: String::new(),
        identities,
        mirrors,
        publish_names,
        publish_declarations,
    };
    let config = config_for(fixtures::REPOSITORY);
    let mut lock = CratesIoLock {
        schema: CRATES_IO_LOCK_SCHEMA,
        packages: Vec::new(),
    };
    lock.packages.push(earlier_entry());
    MemoryState {
        catalog,
        config,
        lock,
    }
}

/// Returns the `crates-io.lock` entry of the fixture's earlier release.
fn earlier_entry() -> CratesIoPackage {
    CratesIoPackage {
        name: "earlier-lib".to_owned(),
        version: Version::parse("0.9.0").expect("parse the fixture version"),
        crates_io_name: fixtures::EARLIER_CRATES_IO_NAME.to_owned(),
        crate_sha256: fixtures::crate_checksum(fixtures::EARLIER_CRATES_IO_NAME, "0.9.0"),
        pkgre_crate_sha256: fixtures::crate_checksum("earlier-lib", "0.9.0"),
        git: fixtures::REPOSITORY.to_owned(),
        tag: fixtures::EARLIER_TAG.to_owned(),
        commit: "9".repeat(40),
        cargo_version: Version::parse(fixtures::CARGO_VERSION).expect("parse the pinned version"),
    }
}

/// Returns the self-publishing config of one fixture repository.
fn config_for(repository: &str) -> CratesIoConfig {
    CratesIoConfig::parse(
        format!(
            "schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = {repository:?}\ntag-prefix = {:?}\n\n[names]\nexample-lib = {:?}\n",
            fixtures::TAG_PREFIX,
            fixtures::LIB_CRATES_IO_NAME
        )
        .as_bytes(),
        Path::new("crates-io.toml"),
    )
    .expect("parse the fixture config")
}

/// Derives a fixture release against the catalog facts of `MemoryState`, with
/// archives that no refusal reads.
fn derive_from_memory(
    release: &Release,
    state: &MemoryState,
    source: &Path,
) -> Result<Vec<super::DerivedPackage>> {
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
    derive_release_with(
        &facts,
        &released,
        &state.catalog,
        &state.config,
        &state.lock,
        Sources::local(&release.root, Some(source), working.path()),
    )
}

/// Returns the expectations of one fixture catalog, as the derivation builds
/// them.
fn expectations_for(release: &Release, state: &RepositoryState) -> Expectations {
    let self_publish = state
        .self_publish
        .as_ref()
        .expect("the catalog declares state");
    let lock = LockIndex::load(&release.root.join("Cargo.lock")).expect("load the fixture lock");
    let published = BTreeMap::from([
        (
            "example-lib".to_owned(),
            fixtures::LIB_CRATES_IO_NAME.to_owned(),
        ),
        (
            "example-bin".to_owned(),
            fixtures::BIN_CRATES_IO_NAME.to_owned(),
        ),
    ]);
    Expectations::build(
        &lock,
        &state.catalog,
        &self_publish.config,
        &self_publish.lock,
        &published,
    )
    .expect("build the expectations")
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
    // The earlier release is renamed in the inherited dependency and in the
    // build dependency, and both locks carry the checksum of their own registry.
    assert_eq!(
        manifest["dependencies"]["earlier-lib"]["package"].as_str(),
        Some(fixtures::EARLIER_CRATES_IO_NAME)
    );
    let lock = archived_lock(&bin.entry, &bin.archive, &version);
    let packages = lock["package"].as_array().expect("the lock holds packages");
    let earlier = packages
        .iter()
        .find(|package| package["name"].as_str() == Some(fixtures::EARLIER_CRATES_IO_NAME))
        .expect("the earlier release is renamed in the lock");
    assert_eq!(earlier["version"].as_str(), Some("0.9.0"));
    assert_eq!(
        earlier["checksum"].as_str(),
        Some(fixtures::crate_checksum(fixtures::EARLIER_CRATES_IO_NAME, "0.9.0").as_str())
    );
    assert_ne!(
        earlier["checksum"].as_str(),
        Some(fixtures::crate_checksum("earlier-lib", "0.9.0").as_str()),
        "the crates.io checksum is not the curated archive's"
    );
    let mirrored = packages
        .iter()
        .find(|package| package["name"].as_str() == Some("mirrored-dep"))
        .expect("the mirrored dependency keeps its name");
    assert_eq!(
        mirrored["source"].as_str(),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );
    // The unpublished server's build dependency is renamed as well.
    let serve_manifest = archived_manifest(&lib.entry, &lib.archive, &version);
    assert_eq!(
        serve_manifest["package"]["name"].as_str(),
        Some(fixtures::LIB_CRATES_IO_NAME)
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
fn derives_when_the_catalog_holds_older_versions_of_a_dependency() {
    let temporary = fixtures::Temp::new("pkgre-derive-versions");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    // The catalog keeps an older version of a dependency, which the tag's lock
    // does not use. The derivation must resolve the dependency through the lock.
    let mut snapshot = state.catalog.clone();
    snapshot.identities.push(CatalogIdentity {
        name: "mirrored-dep".to_owned(),
        version: Version::parse("0.3.1").expect("parse the fixture version"),
        crate_sha256: "5".repeat(64),
        removed: false,
        release: None,
    });
    snapshot.identities.push(CatalogIdentity {
        name: "earlier-lib".to_owned(),
        version: Version::parse("0.10.0").expect("parse the fixture version"),
        crate_sha256: "6".repeat(64),
        removed: false,
        release: Some(GitRelease {
            git: fixtures::REPOSITORY.to_owned(),
            tag: "rust/v0.10.0".to_owned(),
            tag_oid: "a".repeat(40),
            commit: "a".repeat(40),
            cargo_version: Version::parse(fixtures::CARGO_VERSION).expect("parse the version"),
        }),
    });
    let state = RepositoryState {
        catalog: snapshot,
        catalog_root: state.catalog_root.clone(),
        self_publish: state.self_publish,
    };
    let packages = derive_from_catalog(&release, &state, &catalog.curated, &source.root)
        .expect("older catalog versions do not change the resolution");
    assert_eq!(packages.len(), 2);
}

#[test]
fn refuses_a_release_that_the_catalog_publishes_partially() {
    let temporary = fixtures::Temp::new("pkgre-derive-partial");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    // The tag marks both members publishable, but the catalog publishes only
    // the library from it.
    let error = derive_with_members(
        &release,
        &state,
        &catalog.curated,
        &source.root,
        &["example-lib"],
    )
    .expect_err("a partial release is refused");
    let error = format!("{error:#}");
    assert!(
        error.contains("publishes exactly its publishable members"),
        "{error}"
    );
    assert!(error.contains("example-bin"), "{error}");
}

#[test]
fn refuses_a_catalog_crate_that_the_tag_does_not_publish() {
    let temporary = fixtures::Temp::new("pkgre-derive-extra");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    // `example-serve` is a member, but its `publish` is `false`.
    let error = derive_with_members(
        &release,
        &state,
        &catalog.curated,
        &source.root,
        &["example-lib", "example-bin", "example-serve"],
    )
    .expect_err("a catalog crate that the tag does not publish is refused");
    let error = format!("{error:#}");
    assert!(
        error.contains("publishes exactly its publishable members"),
        "{error}"
    );
    assert!(error.contains("example-serve"), "{error}");
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

/// One edit of a derived archive's files.
type ArchiveEdit = fn(&mut BTreeMap<String, fixtures::ArchiveFile>);

#[test]
#[allow(clippy::too_many_lines)]
fn refuses_a_redirected_dependency_or_lock_source() {
    let temporary = fixtures::Temp::new("pkgre-derive-redirect");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    let packages = derive_from_catalog(&release, &state, &catalog.curated, &source.root)
        .expect("derive the fixture release");
    let bin = packages
        .iter()
        .find(|package| package.entry.name == "example-bin")
        .expect("the binary is derived");
    let expectations = expectations_for(&release, &state);
    let version = Version::parse(fixtures::VERSION).expect("parse the fixture version");
    let curated = ArchiveToCompare {
        name: "example-bin",
        bytes: &catalog.curated["example-bin"],
    };
    let compare = |archive: &[u8]| {
        compare_archives(
            &version,
            &curated,
            &ArchiveToCompare {
                name: fixtures::BIN_CRATES_IO_NAME,
                bytes: archive,
            },
            &expectations,
        )
        .map_err(|error| format!("{error:#}"))
    };
    let files = fixtures::archive_files(fixtures::BIN_CRATES_IO_NAME, &version, &bin.archive);
    // An unchanged repack must still compare equal.
    compare(&fixtures::tar_gz(
        fixtures::BIN_CRATES_IO_NAME,
        &version,
        &files,
    ))
    .expect("an unchanged repack compares equal");

    let cases: &[(&str, ArchiveEdit, &str)] = &[
        (
            "dependency renamed to another crate",
            |files| {
                let text = manifest_text(files);
                files.insert(
                    "Cargo.toml".to_owned(),
                    fixtures::ArchiveFile {
                        contents: text
                            .replacen(
                                "[dependencies.mirrored-dep]\n",
                                "[dependencies.mirrored-dep]\npackage = \"evil-crate\"\n",
                                1,
                            )
                            .into_bytes(),
                        mode: 0o644,
                    },
                );
            },
            "is renamed to Some(\"evil-crate\")",
        ),
        (
            "dependency moved to another registry",
            |files| {
                let text = manifest_text(files);
                files.insert(
                    "Cargo.toml".to_owned(),
                    fixtures::ArchiveFile {
                        contents: text
                            .replacen(
                                "[dependencies.mirrored-dep]\n",
                                "[dependencies.mirrored-dep]\nregistry-index = \"sparse+https://evil.example/\"\n",
                                1,
                            )
                            .into_bytes(),
                        mode: 0o644,
                    },
                );
            },
            "names another registry",
        ),
        (
            "lock package moved to another registry without a checksum",
            |files| {
                let lock = lock_text(files);
                let mut out = String::new();
                let mut in_mirrored = false;
                for line in lock.lines() {
                    if line.starts_with("name = ") {
                        in_mirrored = line == "name = \"mirrored-dep\"";
                    }
                    if in_mirrored && line.starts_with("source = ") {
                        out.push_str("source = \"sparse+https://evil.example/\"\n");
                        continue;
                    }
                    if in_mirrored && line.starts_with("checksum = ") {
                        continue;
                    }
                    out.push_str(line);
                    out.push('\n');
                }
                files.insert(
                    "Cargo.lock".to_owned(),
                    fixtures::ArchiveFile {
                        contents: out.into_bytes(),
                        mode: 0o644,
                    },
                );
            },
            "comes from Some(\"sparse+https://evil.example/\")",
        ),
        (
            "source file made executable",
            |files| {
                let path = "src/main.rs";
                let file = files.get_mut(path).expect("the archive holds the source");
                file.mode = 0o755;
            },
            "differs in its permissions",
        ),
    ];
    for (label, edit, expected) in cases {
        let mut tampered = files.clone();
        edit(&mut tampered);
        let archive = fixtures::tar_gz(fixtures::BIN_CRATES_IO_NAME, &version, &tampered);
        let error = compare(&archive).expect_err(label);
        assert!(
            error.contains(expected),
            "{label}: {expected:?} not in {error}"
        );
    }
}

/// Returns the derived manifest of one set of archive files.
fn manifest_text(files: &BTreeMap<String, fixtures::ArchiveFile>) -> String {
    String::from_utf8(
        files
            .get("Cargo.toml")
            .expect("the archive holds a manifest")
            .contents
            .clone(),
    )
    .expect("the manifest is UTF-8")
}

/// Returns the derived lock of one set of archive files.
fn lock_text(files: &BTreeMap<String, fixtures::ArchiveFile>) -> String {
    String::from_utf8(
        files
            .get("Cargo.lock")
            .expect("the archive holds a lock")
            .contents
            .clone(),
    )
    .expect("the lock is UTF-8")
}

#[test]
fn rewrites_a_stale_package_key() {
    let temporary = fixtures::Temp::new("pkgre-derive-stale");
    let variant = Variant {
        stale_package: true,
        ..Variant::default()
    };
    let (source, release, catalog) = fixture(temporary.path(), variant);
    let state = RepositoryState::load(&catalog.root).expect("load the fixture catalog");
    let packages = derive_from_catalog(&release, &state, &catalog.curated, &source.root)
        .expect("the stale package key is rewritten");
    let version = Version::parse(fixtures::VERSION).expect("parse the fixture version");
    let bin = packages
        .iter()
        .find(|package| package.entry.name == "example-bin")
        .expect("the binary is derived");
    let manifest = archived_manifest(&bin.entry, &bin.archive, &version);
    assert_eq!(
        manifest["dependencies"]["earlier-lib"]["package"].as_str(),
        Some(fixtures::EARLIER_CRATES_IO_NAME),
        "the stale key becomes the crates.io name"
    );
    let lib = packages
        .iter()
        .find(|package| package.entry.name == "example-lib")
        .expect("the library is derived");
    let manifest = archived_manifest(&lib.entry, &lib.archive, &version);
    assert!(
        manifest["dependencies"]["mirrored-dep"]
            .get("package")
            .is_none(),
        "a resolved `[workspace.dependencies]` entry drops its stale package key"
    );
}

#[test]
fn refuses_a_dependency_between_two_released_crates_of_one_tag() {
    let temporary = fixtures::Temp::new("pkgre-derive-sibling");
    let variant = Variant {
        sibling_dependency: true,
        ..Variant::default()
    };
    let (source, release) = release_only(temporary.path(), variant);
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
    let (source, release) = release_only(temporary.path(), variant);
    let state = memory_state(&release, variant);
    let error = derive_from_memory(&release, &state, &source.root)
        .expect_err("a dependency on a fork is refused");
    let error = format!("{error:#}");
    assert!(error.contains("forked-dep"), "{error}");
    assert!(error.contains("does not self-publish"), "{error}");
}

#[test]
fn refuses_a_first_party_dependency_without_an_entry() {
    let temporary = fixtures::Temp::new("pkgre-derive-no-entry");
    let (source, release) = release_only(temporary.path(), Variant::default());
    let mut state = memory_state(&release, Variant::default());
    state.lock.packages.clear();
    let error = derive_from_memory(&release, &state, &source.root)
        .expect_err("a first-party dependency without an entry is refused");
    let error = format!("{error:#}");
    assert!(error.contains("earlier-lib"), "{error}");
    assert!(error.contains("has no entry in crates-io.lock"), "{error}");
}

#[test]
fn refuses_an_unreleased_members_dependency_that_crates_io_lacks() {
    let temporary = fixtures::Temp::new("pkgre-derive-server");
    let variant = Variant {
        server_needs_first_party: true,
        ..Variant::default()
    };
    let (source, release) = release_only(temporary.path(), variant);
    let state = memory_state(&release, variant);
    let error = derive_from_memory(&release, &state, &source.root)
        .expect_err("an unpublished member's unresolvable dependency is refused");
    let error = format!("{error:#}");
    assert!(error.contains("unknown-lib"), "{error}");
    assert!(error.contains("has no entry in crates-io.lock"), "{error}");
}

#[test]
fn refuses_patch_and_replace_tables() {
    for (label, variant) in [
        (
            "[patch]",
            Variant {
                patch: true,
                ..Variant::default()
            },
        ),
        (
            "[replace]",
            Variant {
                replace: true,
                ..Variant::default()
            },
        ),
    ] {
        let temporary = fixtures::Temp::new("pkgre-derive-table");
        let (source, release) = release_only(temporary.path(), variant);
        let state = memory_state(&release, variant);
        let error = derive_from_memory(&release, &state, &source.root)
            .expect_err("a table that crates.io cannot carry is refused");
        let error = format!("{error:#}");
        assert!(error.contains(label), "{error}");
    }
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
        fs::remove_file(configuration.join("config.toml")).expect("remove the link");
    }
}

#[test]
#[cfg(unix)]
fn refuses_configuration_above_a_symlinked_ancestor() {
    let temporary = fixtures::Temp::new("pkgre-cargo-symlink");
    let physical = temporary.path().join("physical");
    fs::create_dir_all(physical.join("sub")).expect("create the physical directory");
    let link = temporary.path().join("link");
    std::os::unix::fs::symlink(&physical, &link).expect("create the symbolic link");
    let working = link.join("sub/work");
    ensure_no_cargo_configuration(&working).expect("the physical directory has no configuration");
    fs::create_dir_all(physical.join(".cargo")).expect("create the configuration directory");
    fs::write(
        physical.join(".cargo/config.toml"),
        "[alias]\nprobe = \"version\"\n",
    )
    .expect("write the configuration");
    let error = ensure_no_cargo_configuration(&working)
        .expect_err("configuration behind a symbolic link is refused");
    assert!(
        format!("{error:#}").contains("could replace crates.io"),
        "{error:#}"
    );
}

#[test]
fn distinguishes_a_member_from_a_registry_package_of_its_name() {
    let lock = LockIndex::parse(
        b"version = 4\n\n[[package]]\nname = \"example-bin\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"example-bin\"\nversion = \"0.9.0\"\nsource = \"sparse+https://rust.pkg.re/\"\nchecksum = \"0111111111111111111111111111111111111111111111111111111111111111\"\n",
    )
    .expect("parse a lock with a member and a registry package of one name");
    let catalog = CatalogSnapshot {
        registry_index: String::new(),
        identities: vec![CatalogIdentity {
            name: "example-bin".to_owned(),
            version: Version::parse("0.9.0").expect("parse the fixture version"),
            crate_sha256: "0111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            removed: false,
            release: None,
        }],
        mirrors: vec!["example-bin".to_owned()],
        publish_names: Vec::new(),
        publish_declarations: Vec::new(),
    };
    let published = BTreeMap::from([("example-bin".to_owned(), "example-bin".to_owned())]);
    let expectations = Expectations::build(
        &lock,
        &catalog,
        &config_for(fixtures::REPOSITORY),
        &CratesIoLock {
            schema: CRATES_IO_LOCK_SCHEMA,
            packages: Vec::new(),
        },
        &published,
    )
    .expect("build the expectations");
    let member = expectations
        .package(
            "example-bin",
            &Version::parse("1.0.0").expect("parse the version"),
        )
        .expect("the member is expected");
    assert!(member.member);
    assert!(member.curated_checksum.is_none() && member.derived_checksum.is_none());
    let registry = expectations
        .package(
            "example-bin",
            &Version::parse("0.9.0").expect("parse the version"),
        )
        .expect("the registry package is expected");
    assert!(!registry.member);
    assert_eq!(
        registry.curated_checksum.as_deref(),
        Some("0111111111111111111111111111111111111111111111111111111111111111")
    );
    assert_eq!(
        registry.derived_checksum.as_deref(),
        Some("0111111111111111111111111111111111111111111111111111111111111111")
    );
}

#[test]
fn parses_lock_dependency_entries_with_a_source() {
    let lock = LockIndex::parse(
        b"version = 4\n\n[[package]]\nname = \"example-bin\"\nversion = \"1.0.0\"\ndependencies = [\n \"pinned 0.3.0\",\n \"qualified 0.2.0 (sparse+https://rust.pkg.re/)\",\n]\n\n[[package]]\nname = \"pinned\"\nversion = \"0.3.0\"\nsource = \"sparse+https://rust.pkg.re/\"\nchecksum = \"0111111111111111111111111111111111111111111111111111111111111111\"\n\n[[package]]\nname = \"qualified\"\nversion = \"0.2.0\"\nsource = \"sparse+https://rust.pkg.re/\"\nchecksum = \"0211111111111111111111111111111111111111111111111111111111111111\"\n",
    )
    .expect("parse a lock with a qualified dependency");
    let package = lock
        .package(
            "example-bin",
            &Version::parse("1.0.0").expect("parse the version"),
        )
        .expect("the lock holds the binary");
    assert_eq!(package.dependencies.len(), 2);
    assert_eq!(package.dependencies[0].0, "pinned");
    assert_eq!(package.dependencies[1].0, "qualified");
    assert_eq!(
        package.dependencies[1].1,
        Version::parse("0.2.0").expect("parse the version")
    );
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
    let summary = super::super::lock_command::self_publish_lock_in(&catalog.root, &local)
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
        assert_ne!(
            recorded.crate_sha256, recorded.pkgre_crate_sha256,
            "an earlier release's crates.io checksum is not its curated checksum"
        );
    }
    crate::self_publish::check_repository(&catalog.root, None)
        .expect("the offline checks accept the written lock");

    let path = catalog.root.join("self-publish/crates-io.lock");
    let before = fs::read(&path).expect("read the written lock");
    let second = super::super::lock_command::self_publish_lock_in(&catalog.root, &local)
        .expect("a second run derives nothing");
    assert!(!second.changed);
    assert!(second.entries.is_empty());
    assert_eq!(second.releases, 0);
    assert_eq!(fs::read(&path).expect("read the lock"), before);
}

#[test]
fn self_publish_lock_skips_an_identity_from_a_tag_outside_the_release_convention() {
    let temporary = fixtures::Temp::new("pkgre-lock-historical");
    let (source, release) = release_only(temporary.path(), Variant::default());
    let catalog = fixtures::catalog_at(
        temporary.path(),
        "catalog",
        &source,
        &release,
        Variant::default(),
        false,
    );
    // A catalog before its repository adopted self-publishing: one identity from
    // a tag outside the release convention, and no release.
    fixtures::add_non_release_identity(&catalog, "example-indexer", "0.3.0", "indexer/v0.3.0");
    let repositories = BTreeMap::from([(fixtures::REPOSITORY.to_owned(), release.root.clone())]);
    let local = super::super::lock_command::LocalNetwork {
        repositories: &repositories,
        source: &source.root,
        root: temporary.path(),
    };
    let path = catalog.root.join("self-publish/crates-io.lock");
    let before = fs::read(&path).expect("read the fixture lock");
    let summary = super::super::lock_command::self_publish_lock_in(&catalog.root, &local)
        .expect("an identity that predates self-publishing is no self-published identity");
    assert!(!summary.changed);
    assert!(summary.entries.is_empty());
    assert_eq!(summary.releases, 0);
    assert_eq!(
        fs::read(&path).expect("read the fixture lock"),
        before,
        "a run with nothing to derive writes nothing"
    );
}

#[test]
fn self_publish_lock_records_only_the_release_beside_a_historical_identity() {
    let temporary = fixtures::Temp::new("pkgre-lock-historical-release");
    let (source, release, catalog) = fixture(temporary.path(), Variant::default());
    fixtures::add_non_release_identity(&catalog, "example-indexer", "0.3.0", "indexer/v0.3.0");
    let repositories = BTreeMap::from([(fixtures::REPOSITORY.to_owned(), release.root.clone())]);
    let local = super::super::lock_command::LocalNetwork {
        repositories: &repositories,
        source: &source.root,
        root: temporary.path(),
    };
    let summary = super::super::lock_command::self_publish_lock_in(&catalog.root, &local)
        .expect("the release is recorded beside an identity that predates self-publishing");
    assert!(summary.changed);
    assert_eq!(summary.releases, 1);
    assert_eq!(summary.entries.len(), 2);
    assert!(
        summary
            .entries
            .iter()
            .all(|entry| entry.name != "example-indexer"),
        "the run derives nothing for the historical identity"
    );
    let lock = CratesIoLock::load(&catalog.root.join("self-publish/crates-io.lock"))
        .expect("load the written lock");
    assert_eq!(
        lock.packages.len(),
        3,
        "the earlier release and the release are recorded, and the historical identity is not"
    );
    assert!(
        lock.entry(
            "example-indexer",
            &Version::parse("0.3.0").expect("parse the fixture version")
        )
        .is_none(),
        "the historical identity has no entry"
    );
    crate::self_publish::check_repository(&catalog.root, None)
        .expect("the offline checks accept the written lock");
}

#[test]
fn refuses_to_derive_a_removed_identity() {
    let config = config_for(fixtures::REPOSITORY);
    let state = RepositoryState {
        catalog: CatalogSnapshot {
            registry_index: String::new(),
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
#[ignore = "needs the network and PKGRE_REHEARSAL_CATALOG"]
#[allow(clippy::too_many_lines)]
fn rehearsal_derives_the_current_tooling_against_live_crates_io() {
    let catalog_root = PathBuf::from(
        std::env::var_os("PKGRE_REHEARSAL_CATALOG")
            .expect("set PKGRE_REHEARSAL_CATALOG to a checkout of the catalog repository"),
    );
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
        let materialization = crate::package::resolve_git_tag_from_file(
            "https://github.com/pkgre/pkgre",
            "rust/v0.5.0",
            name,
            &cargo_version,
            clone.to_str().expect("the clone path is UTF-8"),
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
    // The catalog comes from the repository that holds it, read-only, so that
    // every dependency resolves against the real `registry/main.lock`, with its
    // several versions per name.
    let mut snapshot = CatalogSnapshot::load(&catalog_root).expect("load the production catalog");
    for package in &released {
        snapshot.identities.push(CatalogIdentity {
            name: package.name.clone(),
            version: package.version.clone(),
            crate_sha256: package.crate_sha256.clone(),
            removed: false,
            release: facts.clone(),
        });
        snapshot.publish_names.push(package.name.clone());
        snapshot.publish_declarations.push((
            package.name.clone(),
            "https://github.com/pkgre/pkgre".to_owned(),
        ));
    }
    let config = match std::fs::read(catalog_root.join("self-publish/crates-io.toml")) {
        Ok(bytes) => {
            CratesIoConfig::parse(&bytes, &catalog_root.join("self-publish/crates-io.toml"))
                .expect("parse the production self-publishing config")
        }
        Err(_) => rehearsal_config(),
    };
    let earlier = match std::fs::read(catalog_root.join("self-publish/crates-io.lock")) {
        Ok(bytes) => {
            CratesIoLock::parse_canonical(&bytes, &catalog_root.join("self-publish/crates-io.lock"))
                .expect("parse the production entries")
        }
        Err(_) => CratesIoLock {
            schema: CRATES_IO_LOCK_SCHEMA,
            packages: Vec::new(),
        },
    };
    let derived = derive_release_in(
        &facts.expect("the release has facts"),
        &released,
        &snapshot,
        &config,
        &earlier,
        Sources::local(&clone, None, temporary.path()),
    )
    .expect("derive the release against live crates.io");
    assert_eq!(derived.packages.len(), 2);
    // Step 5 of the upload routine: package the missing crates with Cargo's
    // verification, against live crates.io, and require the archives that the
    // derivation recorded. No token is read and nothing is uploaded.
    let packages = derived
        .packages
        .iter()
        .map(|package| {
            (
                package.entry.crates_io_name.clone(),
                package.entry.version.clone(),
            )
        })
        .collect::<Vec<_>>();
    let verified = derived
        .workspace
        .verified_archives(&packages)
        .expect("verify the release against live crates.io");
    for package in &derived.packages {
        let archive = verified
            .get(&package.entry.crates_io_name)
            .expect("the verified packaging produced the archive");
        assert_eq!(
            sha256_bytes(archive),
            package.entry.crate_sha256,
            "the verified package of {} {} differs from the derived archive",
            package.entry.name,
            package.entry.version
        );
    }
    // Step 6's packaging, in the upload's own Cargo home and without a token:
    // the archive that `cargo publish` would upload must be the recorded one.
    let upload_environment = derived
        .workspace
        .upload_environment()
        .expect("prepare the upload Cargo home");
    let published = derived
        .workspace
        .publish_archives(&upload_environment, &packages)
        .expect("package the release as cargo publish would");
    for package in &derived.packages {
        let archive = published
            .get(&package.entry.crates_io_name)
            .expect("the packaging produced the archive");
        assert_eq!(
            sha256_bytes(archive),
            package.entry.crate_sha256,
            "the package that cargo publish would upload for {} {} differs from the recorded archive",
            package.entry.name,
            package.entry.version
        );
    }
    for package in &derived.packages {
        println!(
            "rehearsal: {} {} -> {} crate-sha256={} pkgre-crate-sha256={} comparison=identical verified=identical upload=identical",
            package.entry.name,
            package.entry.version,
            package.entry.crates_io_name,
            package.entry.crate_sha256,
            package.entry.pkgre_crate_sha256,
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

/// Returns the self-publishing config of the rehearsal release.
fn rehearsal_config() -> CratesIoConfig {
    CratesIoConfig::parse(
        b"schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = \"https://github.com/pkgre/pkgre\"\ntag-prefix = \"rust/v\"\n\n[names]\npkgre = \"pkgre\"\n",
        Path::new("crates-io.toml"),
    )
    .expect("parse the rehearsal config")
}

/// Returns the checkout of the repository that these tests belong to.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the manifest directory has a parent")
        .to_path_buf()
}

#[test]
fn the_upload_cargo_home_configures_only_crates_io_and_the_token_provider() {
    let temporary = fixtures::Temp::new("pkgre-derive-upload-home");
    let home = temporary.path().join("upload-cargo-home");
    super::cargo::prepare_upload_cargo_home(&home, &super::cargo::RegistrySources::CratesIo)
        .expect("write the upload Cargo home");
    let text = fs::read_to_string(home.join("config.toml")).expect("read the upload config");
    assert_eq!(
        text,
        "[registry]\ncredential-provider = [\"cargo:token\"]\n"
    );
}

#[test]
fn the_packager_gets_only_the_environment_allowlist() {
    let temporary = fixtures::Temp::new("pkgre-derive-allowlist");
    let (cargo, record) = fake_cargo(temporary.path());
    let home = temporary.path().join("cargo-home");
    fs::create_dir(&home).expect("create the Cargo home");
    let environment =
        crate::isolation::ChildEnvironment::capture(&home, &cargo).expect("capture the allowlist");
    let work = temporary.path().join("work");
    fs::create_dir(&work).expect("create the working directory");
    super::cargo::run_cargo(
        &cargo,
        &environment,
        &work,
        [std::ffi::OsString::from("--version")],
    )
    .expect("run the fake cargo");
    let text = fs::read_to_string(&record).expect("read the recorded environment");
    let recorded = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect::<BTreeMap<_, _>>();
    // The shell that runs the fake adds `PWD`, `SHLVL` and `_` itself; every
    // other variable has to come from the allowlist.
    let allowed = [
        "PATH",
        "TMPDIR",
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
        "PWD",
        "SHLVL",
        "_",
    ];
    for name in recorded.keys() {
        assert!(
            allowed.contains(&name.as_str()),
            "the packager inherited {name}: {recorded:?}"
        );
    }
    assert!(recorded.contains_key("CARGO_HOME"), "{recorded:?}");
    assert!(recorded.contains_key("RUSTC"), "{recorded:?}");
    assert!(!recorded.contains_key("HOME"), "{recorded:?}");
    assert!(
        !recorded.keys().any(|name| name.contains("TOKEN")),
        "{recorded:?}"
    );
}

/// Writes a fake `cargo` that records its environment, with a `rustc` beside it.
fn fake_cargo(root: &Path) -> (PathBuf, PathBuf) {
    let toolchain = root.join("toolchain");
    fs::create_dir_all(&toolchain).expect("create the fake toolchain");
    let record = root.join("recorded-environment");
    let cargo = toolchain.join("cargo");
    fixtures::write_executable(
        &cargo,
        &format!("#!/bin/sh\nenv > '{}'\n", record.display()),
    );
    fixtures::write_executable(&toolchain.join("rustc"), "#!/bin/sh\nexit 0\n");
    (cargo, record)
}

#[test]
fn the_verified_packaging_ends_the_process_group_it_started() {
    let temporary = fixtures::Temp::new("pkgre-derive-group");
    let (grouped, grouped_survived) = fake_background_cargo(temporary.path(), "grouped");
    let (plain, plain_survived) = fake_background_cargo(temporary.path(), "plain");
    let home = temporary.path().join("cargo-home");
    fs::create_dir(&home).expect("create the Cargo home");
    let work = temporary.path().join("work");
    fs::create_dir(&work).expect("create the working directory");
    let arguments = [std::ffi::OsString::from("--version")];
    super::cargo::run_cargo_grouped(
        &grouped,
        &crate::isolation::ChildEnvironment::capture(&home, &grouped)
            .expect("capture the allowlist"),
        &work,
        arguments.clone(),
    )
    .expect("run the grouped fake cargo");
    // The same fake without a process group of its own, as a control.
    super::cargo::run_cargo(
        &plain,
        &crate::isolation::ChildEnvironment::capture(&home, &plain).expect("capture the allowlist"),
        &work,
        arguments,
    )
    .expect("run the plain fake cargo");
    // The control writes its file a moment after its fake Cargo returned; the
    // grouped one never does, because its process group ended.
    for _ in 0..100 {
        if plain_survived.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        plain_survived.exists(),
        "the fake without a process group leaves its process running"
    );
    assert!(
        !grouped_survived.exists(),
        "a process started by the package code outlived its process group"
    );
}

/// Writes a fake `cargo` that starts a process which writes a file a moment
/// later, and returns the fake with that file's path.
fn fake_background_cargo(root: &Path, label: &str) -> (PathBuf, PathBuf) {
    let toolchain = root.join(format!("toolchain-{label}"));
    fs::create_dir_all(&toolchain).expect("create the fake toolchain");
    let survived = root.join(format!("survived-{label}"));
    let cargo = toolchain.join("cargo");
    fixtures::write_executable(
        &cargo,
        &format!(
            "#!/bin/sh\n( sleep 0.3; touch '{}' ) &\nexit 0\n",
            survived.display()
        ),
    );
    fixtures::write_executable(&toolchain.join("rustc"), "#!/bin/sh\nexit 0\n");
    (cargo, survived)
}

/// The environment variable that makes the standard-input helper run.
const PACKAGING_STANDARD_INPUT: &str = "PKGRE_PACKAGING_STANDARD_INPUT";

#[test]
fn the_verified_packaging_gets_no_standard_input() {
    let temporary = fixtures::Temp::new("pkgre-derive-standard-input");
    let file = temporary.path().join("standard-input");
    fs::write(&file, "a-token-on-standard-input").expect("write the standard input");
    let executable = std::env::current_exe().expect("the test binary");
    let output = std::process::Command::new(executable)
        .args([
            "--exact",
            "self_publish::derive::tests::the_packaging_standard_input_helper",
            "--nocapture",
        ])
        .env(PACKAGING_STANDARD_INPUT, "1")
        .stdin(std::process::Stdio::from(
            fs::File::open(&file).expect("open the standard input"),
        ))
        .output()
        .expect("run this test binary with a token on its standard input");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("the packaging helper ran"),
        "the helper did not run: {stdout}{stderr}"
    );
    assert!(
        output.status.success(),
        "the helper failed: {stdout}{stderr}"
    );
}

#[test]
fn the_packaging_standard_input_helper() {
    if std::env::var_os(PACKAGING_STANDARD_INPUT).is_none() {
        // The helper runs only when the test above re-runs this binary with a
        // token on its standard input.
        return;
    }
    println!("the packaging helper ran");
    let temporary = fixtures::Temp::new("pkgre-derive-standard-input-helper");
    let (cargo, seen) = fake_standard_input_cargo(temporary.path());
    let home = temporary.path().join("cargo-home");
    fs::create_dir(&home).expect("create the Cargo home");
    let work = temporary.path().join("work");
    fs::create_dir(&work).expect("create the working directory");
    let environment =
        crate::isolation::ChildEnvironment::capture(&home, &cargo).expect("capture the allowlist");
    let stdout = super::cargo::run_cargo_grouped(
        &cargo,
        &environment,
        &work,
        [std::ffi::OsString::from("--version")],
    )
    .expect("run the fake cargo");
    assert_eq!(stdout, b"to-stdout\n");
    assert!(
        fs::read(&seen)
            .expect("read what the fake cargo read")
            .is_empty(),
        "the packaging inherited the standard input"
    );
    // The same fake started with an inherited standard input reads the token,
    // which makes the assertion above meaningful.
    std::process::Command::new(&cargo)
        .arg("--version")
        .status()
        .expect("run the fake cargo directly");
    assert_eq!(
        fs::read(&seen).expect("read what the fake cargo read"),
        b"a-token-on-standard-input"
    );
}

/// Writes a fake `cargo` that copies its standard input to a file and prints to
/// both streams, and returns it with that file's path.
fn fake_standard_input_cargo(root: &Path) -> (PathBuf, PathBuf) {
    let toolchain = root.join("toolchain");
    fs::create_dir_all(&toolchain).expect("create the fake toolchain");
    let seen = root.join("standard-input");
    let cargo = toolchain.join("cargo");
    fixtures::write_executable(
        &cargo,
        &format!(
            "#!/bin/sh\ncat > '{}'\necho to-stdout\necho to-stderr >&2\nexit 0\n",
            seen.display()
        ),
    );
    fixtures::write_executable(&toolchain.join("rustc"), "#!/bin/sh\nexit 0\n");
    (cargo, seen)
}
