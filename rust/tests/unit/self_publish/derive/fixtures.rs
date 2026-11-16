//! Fixture repositories, catalog state, and local Cargo sources for the
//! self-publishing tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use semver::Version;

use super::super::super::isolation::{ChildEnvironment, ensure_no_cargo_configuration};
use super::super::super::lock::{CRATES_IO_LOCK_SCHEMA, CratesIoLock, CratesIoPackage};
use super::super::cargo::{RegistrySources, package_members, prepare_cargo_home};
use crate::artifact::sha256_bytes;
use crate::package::pinned_cargo;
use crate::schema::{
    Audience, LockedName, LockedPackage, LockedRegistry, LockedSource, PackageState, RegistryLock,
    serialize_lock,
};
use crate::update::UtcTimestamp;

/// The repository URL that the fixture state declares.
pub(super) const REPOSITORY: &str = "https://git.example.invalid/example/project";
/// The URL of a fork, which does not self-publish.
pub(super) const FORK: &str = "https://git.example.invalid/other/fork";
/// The release tag prefix of the fixture.
pub(super) const TAG_PREFIX: &str = "rust/v";
/// The version of the fixture release.
pub(super) const VERSION: &str = "1.0.0";
/// The release tag of the fixture.
pub(super) fn tag() -> String {
    format!("{TAG_PREFIX}{VERSION}")
}
/// The Cargo version that packages the fixture.
pub(super) const CARGO_VERSION: &str = "1.95.0";
/// The crates.io name of `example-lib`, which the fixture maps.
pub(super) const LIB_CRATES_IO_NAME: &str = "example-library";
/// The crates.io name of `example-bin`, which the default rule gives.
pub(super) const BIN_CRATES_IO_NAME: &str = "pkgre-pkgs-example-bin";
/// The older release whose identities the fixture resolves through
/// `crates-io.lock`.
pub(super) const EARLIER_TAG: &str = "rust/v0.9.0";
/// The crates.io name of the earlier release.
pub(super) const EARLIER_CRATES_IO_NAME: &str = "pkgre-pkgs-earlier-lib";

/// A temporary directory that no Cargo configuration covers.
///
/// Cargo reads its configuration from the working directory and every directory
/// above it, and a development environment may point `TMPDIR` into a home that
/// holds one, so the tests use the first of `TMPDIR`, `/tmp`, and `/var/tmp`
/// that no configuration covers.
pub(super) struct Temp(PathBuf);

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Temp {
    /// Creates one temporary directory.
    pub(super) fn new(label: &str) -> Self {
        for root in [
            std::env::temp_dir(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ] {
            if ensure_no_cargo_configuration(&root).is_err() {
                continue;
            }
            let sequence = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("{label}-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => panic!("failed to create {}: {error}", path.display()),
            }
        }
        panic!("no temporary directory without Cargo configuration is available");
    }

    /// Returns the directory.
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One fixture release of a Git repository.
pub(super) struct Release {
    /// The git repository root.
    pub(super) root: PathBuf,
    /// Exact tag object ID.
    pub(super) tag_oid: String,
    /// Full peeled commit object ID.
    pub(super) commit: String,
    /// The workspace members, by package name and version.
    pub(super) members: Vec<(String, Version)>,
}

impl Release {
    /// Returns the version of one member.
    pub(super) fn version(&self, name: &str) -> Version {
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, version)| version.clone())
            .expect("the fixture holds the member")
    }
}

/// The changes that one fixture makes to the base workspace.
#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct Variant {
    /// Let the released binary depend on the released library by path.
    pub(super) sibling_dependency: bool,
    /// Declare a `[patch.crates-io]` table in the root manifest.
    pub(super) patch: bool,
    /// Declare a `[replace]` table in the root manifest.
    pub(super) replace: bool,
    /// Declare a stale `package` key on the earlier release.
    pub(super) stale_package: bool,
    /// Let the released binary depend on a Git identity of a fork.
    pub(super) fork_dependency: bool,
    /// Let the unpublished server depend on a first-party identity that
    /// `crates-io.lock` does not record.
    pub(super) server_needs_first_party: bool,
}

/// A local directory source that stands in for crates.io and the curated
/// registry, so that the tests need no network.
pub(super) struct LocalSource {
    /// Directory of the source.
    pub(super) root: PathBuf,
    /// Package checksums, by name and version.
    checksums: BTreeMap<(String, String), String>,
}

/// The crates that the local source offers, and that the fixture workspace
/// depends on.
pub(super) const LOCAL_CRATES: [(&str, &str); 6] = [
    ("mirrored-dep", "0.3.0"),
    ("mirrored-dev", "0.1.0"),
    ("other-mirror", "0.2.0"),
    ("earlier-lib", "0.9.0"),
    ("forked-dep", "1.0.0"),
    ("unknown-lib", "1.0.0"),
];

impl LocalSource {
    /// Builds the local source below `root`.
    pub(super) fn build(root: &Path) -> Self {
        fs::create_dir_all(root).expect("create the local source");
        let mut source = Self {
            root: root.to_path_buf(),
            checksums: BTreeMap::new(),
        };
        for (name, version) in LOCAL_CRATES {
            source.add(name, version);
        }
        // The crates.io package of the earlier release is the same source under
        // its crates.io name. Its manifest is rewritten, so its checksum differs
        // from the curated archive's, as it does in reality.
        source.add_alias(EARLIER_CRATES_IO_NAME, "0.9.0");
        source
    }

    /// Adds one crate to the source.
    fn add(&mut self, name: &str, version: &str) {
        let checksum = crate_checksum(name, version);
        self.add_with_checksum(name, version, checksum);
    }

    /// Adds one crate under another package name, with another checksum.
    fn add_alias(&mut self, alias: &str, version: &str) {
        let checksum = crate_checksum(alias, version);
        self.add_with_checksum(alias, version, checksum);
    }

    /// Writes one crate of the source with an exact package checksum.
    fn add_with_checksum(&mut self, name: &str, version: &str, checksum: String) {
        let directory = self.root.join(format!("{name}-{version}"));
        fs::create_dir_all(directory.join("src")).expect("create the crate directory");
        fs::write(
            directory.join("Cargo.toml"),
            format!(
                "[package]\nname = {name:?}\nversion = {version:?}\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"A fixture crate\"\n\n[lib]\nname = \"earlier_lib\"\n"
            ),
        )
        .expect("write the crate manifest");
        fs::write(
            directory.join("src/lib.rs"),
            "pub fn value() -> u32 { 7 }\n",
        )
        .expect("write the crate source");
        fs::write(
            directory.join(".cargo-checksum.json"),
            format!("{{\"files\":{{}},\"package\":\"{checksum}\"}}"),
        )
        .expect("write the crate checksum");
        self.checksums
            .insert((name.to_owned(), version.to_owned()), checksum);
    }

    /// Returns the package checksum of one crate of the source.
    pub(super) fn checksum(&self, name: &str, version: &str) -> String {
        self.checksums
            .get(&(name.to_owned(), version.to_owned()))
            .cloned()
            .unwrap_or_else(|| panic!("the local source holds {name} {version}"))
    }
}

/// Returns the checksum that the local source reports for one curated crate.
pub(super) fn crate_checksum(name: &str, version: &str) -> String {
    sha256_bytes(format!("{name} {version}").as_bytes())
}

/// Builds one fixture release repository below `parent`.
///
/// The annotated tag is `rust/v1.0.0`; the workspace holds the released
/// `example-lib` and `example-bin` and the unpublished `example-serve`.
pub(super) fn release(parent: &Path, source: &LocalSource, variant: Variant) -> Release {
    let root = parent.join("source-repository");
    fs::create_dir_all(root.join("lib/src")).expect("create the library");
    fs::create_dir_all(root.join("bin/src")).expect("create the binary");
    fs::create_dir_all(root.join("serve/src")).expect("create the server");
    write_manifests(&root, variant);
    fs::write(
        root.join("lib/src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )
    .expect("write the library source");
    fs::write(
        root.join("bin/src/main.rs"),
        "fn main() {\n    println!(\"{}\", earlier_lib::value() + mirrored_dep::value());\n}\n",
    )
    .expect("write the binary source");
    fs::write(
        root.join("serve/src/lib.rs"),
        "pub fn serve() -> u32 { example_lib::answer() + other_mirror::value() }\n",
    )
    .expect("write the server source");
    generate_lockfile(&root, &source.root);
    commit_and_tag(&root);
    let tag_oid = git(&root, &["rev-parse", &format!("refs/tags/{}", tag())]);
    let commit = git(
        &root,
        &["rev-parse", &format!("refs/tags/{}^{{commit}}", tag())],
    );
    let members = vec![
        ("example-bin".to_owned(), Version::parse(VERSION).unwrap()),
        ("example-lib".to_owned(), Version::parse(VERSION).unwrap()),
        ("example-serve".to_owned(), Version::parse("0.2.0").unwrap()),
    ];
    Release {
        root,
        tag_oid,
        commit,
        members,
    }
}

/// Writes the workspace manifests of one fixture release.
fn write_manifests(root: &Path, variant: Variant) {
    let mut workspace = String::from(
        "[workspace]\nmembers = [\"lib\", \"bin\", \"serve\"]\nresolver = \"3\"\n\n[workspace.package]\nversion = \"1.0.0\"\nedition = \"2021\"\nlicense = \"MIT\"\nrepository = \"https://git.example.invalid/example/project\"\n\n[workspace.dependencies]\nmirrored-dep = { version = \"0.3\", registry = \"pkgre\" }\n",
    );
    if variant.stale_package {
        workspace.push_str(
            "earlier-lib = { version = \"0.9\", registry = \"pkgre\", package = \"earlier-lib\" }\n",
        );
    } else {
        workspace.push_str("earlier-lib = { version = \"0.9\", registry = \"pkgre\" }\n");
    }
    if variant.patch || variant.replace {
        let vendor = root.join("vendor/mirrored-dep/src");
        fs::create_dir_all(&vendor).expect("create the vendor directory");
        fs::write(
            root.join("vendor/mirrored-dep/Cargo.toml"),
            "[package]\nname = \"mirrored-dep\"\nversion = \"0.3.0\"\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"A patched crate\"\n",
        )
        .expect("write the vendor manifest");
        fs::write(vendor.join("lib.rs"), "pub fn value() -> u32 { 0 }\n")
            .expect("write the vendor source");
    }
    if variant.patch {
        workspace
            .push_str("\n[patch.crates-io]\nmirrored-dep = { path = \"vendor/mirrored-dep\" }\n");
    }
    if variant.replace {
        workspace
            .push_str("\n[replace]\n\"mirrored-dep:0.3.0\" = { path = \"vendor/mirrored-dep\" }\n");
    }
    fs::write(root.join("Cargo.toml"), workspace).expect("write the root manifest");
    fs::write(
        root.join("lib/Cargo.toml"),
        "[package]\nname = \"example-lib\"\ndescription = \"An example library\"\nversion.workspace = true\nedition.workspace = true\nlicense.workspace = true\nrepository.workspace = true\npublish = [\"pkgre\"]\n\n[dependencies]\nmirrored-dep.workspace = true\n\n[dev-dependencies]\nmirrored-dev = { version = \"0.1\", registry = \"pkgre\" }\n\n[target.'cfg(unix)'.dependencies]\nother-mirror = { version = \"0.2\", registry = \"pkgre\" }\n",
    )
    .expect("write the library manifest");
    let mut binary = String::from(
        "[package]\nname = \"example-bin\"\ndescription = \"An example binary\"\nversion.workspace = true\nedition.workspace = true\nlicense.workspace = true\nrepository.workspace = true\npublish = [\"pkgre\"]\n\n[dependencies]\nmirrored-dep = { version = \"0.3\", registry = \"pkgre\" }\nearlier-lib.workspace = true\n",
    );
    if variant.sibling_dependency {
        binary.push_str("example-lib = { path = \"../lib\" }\n");
    }
    if variant.fork_dependency {
        binary.push_str("forked-dep = { version = \"1.0\", registry = \"pkgre\" }\n");
    }
    fs::write(root.join("bin/Cargo.toml"), binary).expect("write the binary manifest");
    let mut server = String::from(
        "[package]\nname = \"example-serve\"\ndescription = \"An example server\"\nversion = \"0.2.0\"\nedition = \"2021\"\nlicense = \"MIT\"\nrepository = \"https://git.example.invalid/example/project\"\npublish = false\n\n[dependencies]\nexample-lib = { path = \"../lib\" }\nother-mirror = { version = \"0.2\", registry = \"pkgre\" }\n\n[build-dependencies]\nearlier-lib = { version = \"0.9\", registry = \"pkgre\" }\n",
    );
    if variant.server_needs_first_party {
        server.push_str("unknown-lib = { version = \"1.0\", registry = \"pkgre\" }\n");
    }
    fs::write(root.join("serve/Cargo.toml"), server).expect("write the server manifest");
}

/// Generates the fixture's `Cargo.lock` against the local source.
fn generate_lockfile(root: &Path, source: &Path) {
    let temporary = Temp::new("pkgre-fixture-lock");
    let home = temporary.path().join("cargo-home");
    prepare_cargo_home(&home, RegistrySources::LocalCurated(source.to_path_buf()))
        .expect("prepare the fixture Cargo home");
    let cargo = pinned_cargo(&Version::parse(CARGO_VERSION).expect("parse the pinned version"))
        .expect("locate the pinned Cargo");
    let environment = ChildEnvironment::capture(&home, &cargo).expect("capture the environment");
    let mut command = Command::new(&cargo);
    command
        .current_dir(temporary.path())
        .args(["generate-lockfile", "--manifest-path"])
        .arg(root.join("Cargo.toml"));
    environment.apply(&mut command);
    let output = command.output().expect("run the pinned Cargo");
    assert!(
        output.status.success(),
        "generate-lockfile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Packages the curated archives of one checkout from the local source, and
/// returns them by package name.
pub(super) fn curated_archives(
    checkout: &Path,
    source: &Path,
    members: &[(&str, Version)],
) -> BTreeMap<String, Vec<u8>> {
    let temporary = Temp::new("pkgre-curated-archive");
    let home = temporary.path().join("cargo-home");
    prepare_cargo_home(&home, RegistrySources::LocalCurated(source.to_path_buf()))
        .expect("prepare the curated Cargo home");
    let cargo = pinned_cargo(&Version::parse(CARGO_VERSION).expect("parse the pinned version"))
        .expect("locate the pinned Cargo");
    let environment = ChildEnvironment::capture(&home, &cargo).expect("capture the environment");
    let work = temporary.path().join("work");
    fs::create_dir(&work).expect("create the working directory");
    let members = members
        .iter()
        .map(|(name, version)| ((*name).to_owned(), version.clone()))
        .collect::<Vec<_>>();
    package_members(
        &cargo,
        &environment,
        &work,
        &temporary.path().join("targets"),
        checkout,
        &members,
    )
    .expect("package the curated archives")
}

/// Initialises the fixture repository and puts the annotated release tag on its
/// only commit.
fn commit_and_tag(root: &Path) {
    git(root, &["init", "--quiet"]);
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "release"]);
    git(root, &["tag", "-a", &tag(), "-m", "example 1.0.0"]);
}

/// Runs one Git command in a directory and returns its output.
pub(super) fn git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=pkgre-test",
            "-c",
            "user.email=test@invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
        ])
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git writes UTF-8")
        .trim()
        .to_owned()
}

/// One catalog repository that describes a fixture release.
pub(super) struct Catalog {
    /// Directory that holds `registry/` and `self-publish/`.
    pub(super) root: PathBuf,
    /// The curated archive of every released crate, by package name.
    pub(super) curated: BTreeMap<String, Vec<u8>>,
}

/// Builds a catalog repository for one fixture release, with one entered earlier
/// release and no entry for the fixture release.
pub(super) fn catalog(
    parent: &Path,
    source: &LocalSource,
    release: &Release,
    variant: Variant,
) -> Catalog {
    let root = parent.join("catalog");
    let registry = root.join("registry");
    fs::create_dir_all(registry.join("objects/crates")).expect("create the catalog");
    fs::create_dir_all(root.join("self-publish")).expect("create the self-publishing state");
    let curated = curated_archives(
        &release.root,
        &source.root,
        &[
            ("example-bin", release.version("example-bin")),
            ("example-lib", release.version("example-lib")),
        ],
    );
    let mirrors = vec![
        ("mirrored-dep", "0.3.0"),
        ("mirrored-dev", "0.1.0"),
        ("other-mirror", "0.2.0"),
    ];
    write_registry_file(&registry.join("main.toml"), variant, &mirrors);
    let lock = registry_lock(release, variant, &mirrors, &curated, source);
    fs::write(
        registry.join("main.lock"),
        serialize_lock(&lock).expect("serialize the fixture lock"),
    )
    .expect("write the fixture lock");
    let routes = crate::download::DownloadCatalog::from_routes(
        lock.packages
            .iter()
            .map(|package| crate::download::DownloadRoute {
                registry: "main".to_owned(),
                name: package.name.clone(),
                version: package.version.clone(),
                sha256: package.crate_sha256.clone(),
                delivery: crate::download::Delivery::Retained {
                    path: crate::download::retained_object_path("main", &package.crate_sha256),
                },
            })
            .collect(),
    );
    fs::write(
        registry.join("downloads.json"),
        routes
            .canonical_bytes()
            .expect("serialize the fixture routes"),
    )
    .expect("write the fixture routes");
    for archive in curated.values() {
        fs::write(
            registry
                .join("objects/crates")
                .join(format!("{}.crate", sha256_bytes(archive))),
            archive,
        )
        .expect("write the curated archive");
    }
    fs::write(
        root.join("self-publish/crates-io.toml"),
        format!(
            "schema = 1\n\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = {REPOSITORY:?}\ntag-prefix = {TAG_PREFIX:?}\n\n[names]\nexample-lib = {LIB_CRATES_IO_NAME:?}\n"
        ),
    )
    .expect("write the self-publishing config");
    let mut earlier = CratesIoLock {
        schema: CRATES_IO_LOCK_SCHEMA,
        packages: Vec::new(),
    };
    earlier.packages.push(earlier_entry(source));
    fs::write(
        root.join("self-publish/crates-io.lock"),
        earlier.serialize().expect("serialize the fixture entries"),
    )
    .expect("write the fixture lock");
    Catalog { root, curated }
}

/// Returns the `crates-io.lock` entry of the fixture's earlier release.
pub(super) fn earlier_entry(source: &LocalSource) -> CratesIoPackage {
    CratesIoPackage {
        name: "earlier-lib".to_owned(),
        version: Version::parse("0.9.0").expect("parse a fixture version"),
        crates_io_name: EARLIER_CRATES_IO_NAME.to_owned(),
        crate_sha256: source.checksum(EARLIER_CRATES_IO_NAME, "0.9.0"),
        pkgre_crate_sha256: source.checksum("earlier-lib", "0.9.0"),
        git: REPOSITORY.to_owned(),
        tag: EARLIER_TAG.to_owned(),
        commit: "9".repeat(40),
        cargo_version: Version::parse(CARGO_VERSION).expect("parse the pinned version"),
    }
}

/// Writes the human registry file of one fixture catalog.
fn write_registry_file(path: &Path, variant: Variant, mirrors: &[(&str, &str)]) {
    let mut text = String::from(
        "schema = 5\n\n[registry]\nname = \"main\"\nindex = \"sparse+https://rust.pkg.re/\"\ndownload = \"https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}\"\naudience = \"public\"\ncargo-version = \"1.95.0\"\ndelivery = \"retained\"\n\n[categories.general]\nmay-depend-on = [\"main/general\"]\n\n[categories.general.mirror]\n",
    );
    for (name, version) in mirrors {
        writeln!(text, "{name} = [\"{version}\"]").expect("writing to a string");
    }
    write!(
        text,
        "\n[categories.pkgre]\nmay-depend-on = [\"main/general\", \"main/pkgre\"]\n\n[categories.pkgre.publish.earlier-lib]\ngit = \"{REPOSITORY}\"\ntags = [\"{EARLIER_TAG}\"]\n"
    )
    .expect("writing to a string");
    for name in ["example-bin", "example-lib"] {
        write!(
            text,
            "\n[categories.pkgre.publish.{name}]\ngit = \"{REPOSITORY}\"\ntags = [\"{}\"]\n",
            tag()
        )
        .expect("writing to a string");
    }
    if variant.fork_dependency {
        write!(
            text,
            "\n[categories.pkgre.publish.forked-dep]\ngit = \"{FORK}\"\ntags = [\"fork/v1.0.0\"]\n"
        )
        .expect("writing to a string");
    }
    if variant.server_needs_first_party {
        write!(
            text,
            "\n[categories.pkgre.publish.unknown-lib]\ngit = \"{REPOSITORY}\"\ntags = [\"rust/v0.8.0\"]\n"
        )
        .expect("writing to a string");
    }
    fs::write(path, text).expect("write the fixture registry file");
}

/// Builds the generated lock of one fixture catalog.
#[allow(clippy::too_many_lines)]
fn registry_lock(
    release: &Release,
    variant: Variant,
    mirrors: &[(&str, &str)],
    curated: &BTreeMap<String, Vec<u8>>,
    source: &LocalSource,
) -> RegistryLock {
    let mut names = Vec::new();
    let mut packages = Vec::new();
    for (name, version) in mirrors {
        names.push(LockedName {
            name: (*name).to_owned(),
            category: "general".to_owned(),
        });
        packages.push(LockedPackage {
            name: (*name).to_owned(),
            version: Version::parse(version).expect("parse a fixture version"),
            state: PackageState::Active,
            crate_sha256: source.checksum(name, version),
            source_row_sha256: checksum("row", name, version),
            index_row_sha256: checksum("index", name, version),
            admission_sha256: None,
            admitted_at: admitted_at(),
            source: LockedSource::CratesIo {},
        });
    }
    names.push(LockedName {
        name: "earlier-lib".to_owned(),
        category: "pkgre".to_owned(),
    });
    packages.push(LockedPackage {
        name: "earlier-lib".to_owned(),
        version: Version::parse("0.9.0").expect("parse a fixture version"),
        state: PackageState::Active,
        crate_sha256: source.checksum("earlier-lib", "0.9.0"),
        source_row_sha256: checksum("row", "earlier-lib", "0.9.0"),
        index_row_sha256: checksum("index", "earlier-lib", "0.9.0"),
        admission_sha256: None,
        admitted_at: admitted_at(),
        source: LockedSource::GitTag {
            git: REPOSITORY.to_owned(),
            tag: EARLIER_TAG.to_owned(),
            tag_oid: "9".repeat(40),
            commit: "9".repeat(40),
            package: "earlier-lib".to_owned(),
            path: PathBuf::from("lib"),
            cargo_version: Version::parse(CARGO_VERSION).expect("parse the pinned version"),
        },
    });
    if variant.fork_dependency {
        names.push(LockedName {
            name: "forked-dep".to_owned(),
            category: "pkgre".to_owned(),
        });
        packages.push(LockedPackage {
            name: "forked-dep".to_owned(),
            version: Version::parse("1.0.0").expect("parse a fixture version"),
            state: PackageState::Active,
            crate_sha256: source.checksum("forked-dep", "1.0.0"),
            source_row_sha256: checksum("row", "forked-dep", "1.0.0"),
            index_row_sha256: checksum("index", "forked-dep", "1.0.0"),
            admission_sha256: None,
            admitted_at: admitted_at(),
            source: LockedSource::GitTag {
                git: FORK.to_owned(),
                tag: "fork/v1.0.0".to_owned(),
                tag_oid: "7".repeat(40),
                commit: "7".repeat(40),
                package: "forked-dep".to_owned(),
                path: PathBuf::from("crates/forked-dep"),
                cargo_version: Version::parse(CARGO_VERSION).expect("parse the pinned version"),
            },
        });
    }
    if variant.server_needs_first_party {
        names.push(LockedName {
            name: "unknown-lib".to_owned(),
            category: "pkgre".to_owned(),
        });
        packages.push(LockedPackage {
            name: "unknown-lib".to_owned(),
            version: Version::parse("1.0.0").expect("parse a fixture version"),
            state: PackageState::Active,
            crate_sha256: source.checksum("unknown-lib", "1.0.0"),
            source_row_sha256: checksum("row", "unknown-lib", "1.0.0"),
            index_row_sha256: checksum("index", "unknown-lib", "1.0.0"),
            admission_sha256: None,
            admitted_at: admitted_at(),
            source: LockedSource::GitTag {
                git: REPOSITORY.to_owned(),
                tag: "rust/v0.8.0".to_owned(),
                tag_oid: "8".repeat(40),
                commit: "8".repeat(40),
                package: "unknown-lib".to_owned(),
                path: PathBuf::from("unknown"),
                cargo_version: Version::parse(CARGO_VERSION).expect("parse the pinned version"),
            },
        });
    }
    for name in ["example-bin", "example-lib"] {
        let archive = curated
            .get(name)
            .unwrap_or_else(|| panic!("the curated archive of {name} exists"));
        names.push(LockedName {
            name: name.to_owned(),
            category: "pkgre".to_owned(),
        });
        packages.push(LockedPackage {
            name: name.to_owned(),
            version: release.version(name),
            state: PackageState::Active,
            crate_sha256: sha256_bytes(archive),
            source_row_sha256: checksum("row", name, VERSION),
            index_row_sha256: checksum("index", name, VERSION),
            admission_sha256: None,
            admitted_at: admitted_at(),
            source: LockedSource::GitTag {
                git: REPOSITORY.to_owned(),
                tag: tag(),
                tag_oid: release.tag_oid.clone(),
                commit: release.commit.clone(),
                package: name.to_owned(),
                path: PathBuf::from(if name == "example-bin" { "bin" } else { "lib" }),
                cargo_version: Version::parse(CARGO_VERSION).expect("parse the pinned version"),
            },
        });
    }
    RegistryLock {
        schema: 5,
        registry: LockedRegistry {
            name: "main".to_owned(),
            index: "sparse+https://rust.pkg.re/".to_owned(),
            download: "https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}"
                .to_owned(),
            audience: Audience::Public,
        },
        names,
        packages,
    }
}

/// Returns one deterministic pseudo-checksum for a fixture row.
fn checksum(kind: &str, name: &str, version: &str) -> String {
    sha256_bytes(format!("{kind} {name} {version}").as_bytes())
}

/// Returns the deterministic admission timestamp of the fixture.
fn admitted_at() -> UtcTimestamp {
    UtcTimestamp::parse("2026-01-02T03:04:05Z").expect("parse the fixture timestamp")
}

/// One file of a repacked archive.
#[derive(Clone, Debug)]
pub(super) struct ArchiveFile {
    /// File contents.
    pub(super) contents: Vec<u8>,
    /// Portable permission bits.
    pub(super) mode: u32,
}

/// Reads every file of one derived archive, by path below the archive root.
pub(super) fn archive_files(
    name: &str,
    version: &Version,
    archive: &[u8],
) -> BTreeMap<String, ArchiveFile> {
    let analysis = crate::update::read_crate_archive(name, version, archive, &[])
        .expect("read the derived archive");
    let paths = analysis.files.keys().cloned().collect::<Vec<_>>();
    let wanted = paths.iter().map(String::as_str).collect::<Vec<_>>();
    let contents =
        crate::update::read_crate_archive(name, version, archive, &wanted).expect("read the files");
    analysis
        .files
        .into_iter()
        .map(|(path, file)| {
            let contents = contents
                .contents
                .get(&path)
                .unwrap_or_else(|| panic!("the archive holds {path}"))
                .clone();
            (
                path,
                ArchiveFile {
                    contents,
                    mode: file.mode,
                },
            )
        })
        .collect()
}

/// Writes one archive from a set of files, with the root `<name>-<version>`.
///
/// The archives are gzipped ustar streams, as Cargo writes them; the tests
/// rewrite one to prove that the comparison catches a changed field.
pub(super) fn tar_gz(
    name: &str,
    version: &Version,
    files: &BTreeMap<String, ArchiveFile>,
) -> Vec<u8> {
    let root = format!("{name}-{version}");
    let mut tar = Vec::new();
    for (path, file) in files {
        let full = format!("{root}/{path}");
        let mut header = [0_u8; 512];
        let name = full.as_bytes();
        assert!(
            name.len() < 100,
            "the test archive path is too long: {full}"
        );
        header[..name.len()].copy_from_slice(name);
        set_octal(&mut header[100..108], u64::from(file.mode));
        set_octal(&mut header[108..116], 0);
        set_octal(&mut header[116..124], 0);
        set_octal(&mut header[124..136], file.contents.len() as u64);
        set_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
        set_octal(&mut header[148..156], checksum);
        tar.extend_from_slice(&header);
        tar.extend_from_slice(&file.contents);
        let padding = (512 - file.contents.len() % 512) % 512;
        tar.resize(tar.len() + padding, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).expect("compress the archive");
    encoder.finish().expect("finish the archive")
}

/// Writes one octal tar field.
fn set_octal(field: &mut [u8], value: u64) {
    let digits = format!("{:0width$o}", value, width = field.len() - 2);
    assert_eq!(digits.len(), field.len() - 2);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[field.len() - 2] = 0;
    field[field.len() - 1] = b' ';
}

/// Reads the whole decompressed stream of one archive, for diagnostics.
#[allow(dead_code)]
pub(super) fn decompress(archive: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(archive);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes).expect("decompress");
    bytes
}
