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
pub(crate) const REPOSITORY: &str = "https://git.example.invalid/example/project";
/// The URL of a fork, which does not self-publish.
pub(crate) const FORK: &str = "https://git.example.invalid/other/fork";
/// The release tag prefix of the fixture.
pub(crate) const TAG_PREFIX: &str = "rust/v";
/// The version of the fixture release.
pub(crate) const VERSION: &str = "1.0.0";
/// The release tag of the fixture.
pub(crate) fn tag() -> String {
    format!("{TAG_PREFIX}{VERSION}")
}
/// The Cargo version that packages the fixture.
pub(crate) const CARGO_VERSION: &str = "1.95.0";
/// The crates.io name of `example-lib`, which the fixture maps.
pub(crate) const LIB_CRATES_IO_NAME: &str = "example-library";
/// The crates.io name of `example-bin`, which the default rule gives.
pub(crate) const BIN_CRATES_IO_NAME: &str = "pkgre-pkgs-example-bin";
/// The older release whose identities the fixture resolves through
/// `crates-io.lock`.
pub(crate) const EARLIER_TAG: &str = "rust/v0.9.0";
/// The crates.io name of the earlier release.
pub(crate) const EARLIER_CRATES_IO_NAME: &str = "pkgre-pkgs-earlier-lib";

/// A temporary directory that no Cargo configuration covers.
///
/// Cargo reads its configuration from the working directory and every directory
/// above it, and a development environment may point `TMPDIR` into a home that
/// holds one, so the tests use the first of `TMPDIR`, `/tmp`, and `/var/tmp`
/// that no configuration covers.
pub(crate) struct Temp(PathBuf);

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Temp {
    /// Creates one temporary directory.
    pub(crate) fn new(label: &str) -> Self {
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
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One fixture release of a Git repository.
pub(crate) struct Release {
    /// The git repository root.
    pub(crate) root: PathBuf,
    /// Exact tag object ID.
    pub(crate) tag_oid: String,
    /// Full peeled commit object ID.
    pub(crate) commit: String,
    /// The workspace members, by package name and version.
    pub(crate) members: Vec<(String, Version)>,
}

impl Release {
    /// Returns the version of one member.
    pub(crate) fn version(&self, name: &str) -> Version {
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, version)| version.clone())
            .expect("the fixture holds the member")
    }
}

/// The changes that one fixture makes to the base workspace.
/// The dependency that one released crate declares on another crate of the tag.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Sibling {
    /// No dependency between two crates of the release.
    #[default]
    None,
    /// The path dependency that the derivation accepts.
    Accepted,
    /// The accepted dependency, requiring another version.
    Requirement(&'static str),
    /// The accepted dependency, without the curated registry.
    WithoutRegistry,
    /// A path dependency on a member that the tag does not release.
    Unreleased,
    /// The accepted dependency under another key, which the rewrite keeps.
    Renamed,
    /// The accepted dependency, declared once in `[workspace.dependencies]` and
    /// inherited by the dependent.
    Inherited,
    /// A path dependency on a member that the tag does not release, which the
    /// catalog publishes from another tag.
    OtherTag,
}

/// The readme that one fixture's released library names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Readme {
    /// The manifest names no readme.
    #[default]
    None,
    /// The manifest names this path, relative to the package's directory.
    Relative(&'static str),
    /// The manifest names an absolute path below the fixture's own temporary
    /// directory, outside the checkout.
    Absolute,
    /// The manifest inherits `[workspace.package] readme`, which stays inside.
    Inherited,
}

/// The license file that one fixture's released library names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum LicenseFile {
    /// The manifest names a license identifier instead.
    #[default]
    None,
    /// The manifest names this license-file, relative to the package's directory.
    Relative(&'static str),
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Variant {
    /// The dependency that the released binary declares on the released library.
    pub(crate) sibling: Sibling,
    /// Declare a `[patch.crates-io]` table in the root manifest.
    pub(crate) patch: bool,
    /// Declare a `[replace]` table in the root manifest.
    pub(crate) replace: bool,
    /// Declare a stale `package` key on the earlier release.
    pub(crate) stale_package: bool,
    /// Let the released binary depend on a Git identity of a fork.
    pub(crate) fork_dependency: bool,
    /// Let the unpublished server depend on a first-party identity that
    /// `crates-io.lock` does not record.
    pub(crate) server_needs_first_party: bool,
    /// The categories that the released library declares, when it declares any.
    pub(crate) library_categories: Option<&'static str>,
    /// The repository-relative Gitlink that the tag records, when it records one.
    pub(crate) gitlink: Option<&'static str>,
    /// The readme that the released library's manifest names.
    pub(crate) library_readme: Readme,
    /// The license file that the released library's manifest names.
    pub(crate) library_license_file: LicenseFile,
}

/// A local registry that stands in for crates.io and the curated registry, so
/// that the tests need no network.
pub(crate) struct LocalSource {
    /// Directory that holds the registry index and the archives it serves.
    pub(crate) root: PathBuf,
    /// Package checksums, by name and version.
    checksums: std::cell::RefCell<BTreeMap<(String, String), String>>,
}

/// The crates that the local source offers, and that the fixture workspace
/// depends on.
pub(crate) const LOCAL_CRATES: [(&str, &str); 6] = [
    ("mirrored-dep", "0.3.0"),
    ("mirrored-dev", "0.1.0"),
    ("other-mirror", "0.2.0"),
    ("earlier-lib", "0.9.0"),
    ("forked-dep", "1.0.0"),
    ("unknown-lib", "1.0.0"),
];

impl LocalSource {
    /// Builds the local registry below `root`: one Git index, and the archives
    /// it serves.
    ///
    /// One index serves both the curated registry and crates.io, which a test
    /// points at it through Cargo's own testing hook, so that neither registry is
    /// replaced and Cargo's temporary registry still serves a crate of one
    /// release to the crates that depend on it.
    pub(crate) fn build(root: &Path) -> Self {
        fs::create_dir_all(root.join("index")).expect("create the index");
        fs::create_dir_all(root.join("crates")).expect("create the archive directory");
        let mut source = Self {
            root: root.to_path_buf(),
            checksums: std::cell::RefCell::new(BTreeMap::new()),
        };
        for (name, version) in LOCAL_CRATES {
            source.add(name, version);
        }
        // The crates.io package of the earlier release is the same source under
        // its crates.io name. Its manifest is rewritten, so its checksum differs
        // from the curated archive's, as it does in reality.
        source.add_alias(EARLIER_CRATES_IO_NAME, "0.9.0");
        source.write_index();
        source.commit_index();
        source
    }

    /// Adds one crate to the registry.
    fn add(&mut self, name: &str, version: &str) {
        self.add_with_checksum(name, version);
    }

    /// Adds one crate under another package name, with another checksum.
    fn add_alias(&mut self, alias: &str, version: &str) {
        self.add_with_checksum(alias, version);
    }

    /// Writes one crate of the registry: its archive, its index row, and the
    /// checksum the index reports for it.
    ///
    /// The archive's SHA-256 is the checksum, since a registry serves exactly the
    /// bytes its index names.
    fn add_with_checksum(&mut self, name: &str, version: &str) {
        let archive = crate_archive(name, version, &fixture_files(name, version));
        let checksum = sha256_bytes(&archive);
        fs::write(
            self.root
                .join("crates")
                .join(format!("{name}-{version}.crate")),
            &archive,
        )
        .expect("write the crate archive");
        self.checksums
            .borrow_mut()
            .insert((name.to_owned(), version.to_owned()), checksum);
    }

    /// Writes the index: its rows and its configuration.
    fn write_index(&self) {
        let index = self.root.join("index");
        for ((name, version), checksum) in self.checksums.borrow().iter() {
            let path = index.join(crate::index::index_path(name));
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create the index directory");
            }
            let mut row = serde_json::to_vec(&serde_json::json!({
                "name": name,
                "vers": version,
                "deps": [],
                "cksum": checksum,
                "features": {},
                "yanked": false,
            }))
            .expect("serialize a fixture index row");
            row.push(b'\n');
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open the index row");
            file.write_all(&row).expect("write the index row");
        }
        fs::write(
            index.join("config.json"),
            format!(
                "{{\"dl\":\"file://{}/crates/{{crate}}-{{version}}.crate\",\"api\":null}}\n",
                self.root.display()
            ),
        )
        .expect("write the index configuration");
    }

    /// Commits the index, which Cargo reads as a Git registry.
    fn commit_index(&self) {
        let index = self.root.join("index");
        git(&index, &["init", "--quiet"]);
        git(&index, &["add", "."]);
        git(&index, &["commit", "--quiet", "-m", "index"]);
    }

    /// Returns the package checksum of one crate of the source.
    pub(crate) fn checksum(&self, name: &str, version: &str) -> String {
        self.checksums
            .borrow()
            .get(&(name.to_owned(), version.to_owned()))
            .cloned()
            .unwrap_or_else(|| panic!("the local source holds {name} {version}"))
    }

    /// Adds one crate of the registry after the index was committed, as a
    /// registry that gains a version does, with the dependencies its index row
    /// names.
    pub(crate) fn publish_archive(
        &self,
        name: &str,
        version: &str,
        archive: &[u8],
        dependencies: &[(&str, &str)],
    ) {
        let checksum = sha256_bytes(archive);
        self.checksums
            .borrow_mut()
            .insert((name.to_owned(), version.to_owned()), checksum.clone());
        publish_archive(&self.root, name, version, archive, &checksum, dependencies);
        self.write_index();
        let path = self.root.join("index").join(crate::index::index_path(name));
        let mut row = serde_json::to_vec(&serde_json::json!({
            "name": name,
            "vers": version,
            "deps": dependencies
                .iter()
                .map(|(name, req)| serde_json::json!({
                    "name": name,
                    "req": req,
                    "features": [],
                    "optional": false,
                    "default_features": true,
                    "target": null,
                    "kind": "normal",
                    "registry": null,
                    "package": null,
                }))
                .collect::<Vec<_>>(),
            "cksum": self.checksum(name, version),
            "features": {},
            "yanked": false,
        }))
        .expect("serialize a published index row");
        row.push(b'\n');
        fs::write(&path, row).expect("write the published index row");
        self.commit_index();
    }
}

/// Returns the dependencies that one released crate of the fixture declares, as
/// its crates.io index row names them.
pub(crate) fn derived_dependencies(name: &str) -> Vec<(&'static str, &'static str)> {
    match name {
        "example-lib" => vec![("mirrored-dep", "0.3"), ("other-mirror", "0.2")],
        "example-bin" => vec![("mirrored-dep", "0.3"), (EARLIER_CRATES_IO_NAME, "0.9")],
        _ => Vec::new(),
    }
}

/// Returns the checksum that the local source reports for one crate.
pub(crate) fn crate_checksum(name: &str, version: &str) -> String {
    sha256_bytes(&crate_archive(name, version, &fixture_files(name, version)))
}

/// Returns the files of one crate of the local source.
fn fixture_files(name: &str, version: &str) -> Vec<(&'static str, String)> {
    // The library target is named after its own package, as a real crate's is, so
    // that a dependent resolves each dependency by its own name.
    let library = name.replace('-', "_");
    vec![
        (
            "Cargo.toml",
            format!(
                "[package]\nname = {name:?}\nversion = {version:?}\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"A fixture crate\"\n\n[lib]\nname = {library:?}\n"
            ),
        ),
        ("src/lib.rs", "pub fn value() -> u32 { 7 }\n".to_owned()),
    ]
}

/// Builds one `.crate` archive from the files below its root, `name-version`.
fn crate_archive(name: &str, version: &str, files: &[(&str, String)]) -> Vec<u8> {
    const BLOCK: usize = 512;
    let mut tar = Vec::new();
    for (path, contents) in files {
        let path = format!("{name}-{version}/{path}");
        let mut header = [0_u8; BLOCK];
        let name = path.as_bytes();
        assert!(name.len() < 100, "the fixture path {path:?} fits a header");
        header[..name.len()].copy_from_slice(name);
        set_octal(&mut header[100..108], 0o644);
        set_octal(&mut header[108..116], 0);
        set_octal(&mut header[116..124], 0);
        set_octal(&mut header[124..136], contents.len() as u64);
        set_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
        set_octal(&mut header[148..156], checksum);
        tar.extend_from_slice(&header);
        tar.extend_from_slice(contents.as_bytes());
        tar.resize(tar.len() + (BLOCK - contents.len() % BLOCK) % BLOCK, 0);
    }
    tar.resize(tar.len() + BLOCK * 2, 0);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).expect("compress the archive");
    encoder.finish().expect("finish the archive")
}

/// Builds one fixture release repository below `parent`.
///
/// The annotated tag is `rust/v1.0.0`; the workspace holds the released
/// `example-lib` and `example-bin` and the unpublished `example-serve`.
pub(crate) fn release(parent: &Path, source: &LocalSource, variant: Variant) -> Release {
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
    commit_and_tag(&root, variant);
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

/// Returns the `readme` line of `[workspace.package]`, and writes the readme
/// that the workspace inherits when the fixture inherits one.
fn workspace_readme(root: &Path, variant: Variant) -> &'static str {
    if variant.library_readme == Readme::Inherited {
        fs::write(root.join("README.md"), "# the workspace readme\n")
            .expect("write the workspace readme");
        "readme = \"README.md\"\n"
    } else {
        ""
    }
}

/// Returns the `license-file` and `readme` lines of the released library's
/// manifest, and writes the file that a path outside the checkout names.
fn library_path_fields(root: &Path, variant: Variant) -> (String, String) {
    let outside = || {
        let directory = root
            .parent()
            .expect("the fixture repository has a parent")
            .join("outside");
        fs::create_dir_all(&directory).expect("create the directory outside the checkout");
        directory
    };
    let readme = match variant.library_readme {
        Readme::None => String::new(),
        Readme::Relative(path) => format!("readme = {path:?}\n"),
        Readme::Absolute => {
            let path = outside().join("README.md");
            fs::write(&path, "# outside the checkout\n").expect("write the readme outside");
            format!(
                "readme = {:?}\n",
                path.to_str().expect("the fixture path is UTF-8")
            )
        }
        Readme::Inherited => "readme.workspace = true\n".to_owned(),
    };
    let license = match variant.library_license_file {
        LicenseFile::None => "license.workspace = true\n".to_owned(),
        LicenseFile::Relative(path) => {
            fs::write(outside().join("LICENSE"), "an outside license\n")
                .expect("write the license outside");
            format!("license-file = {path:?}\n")
        }
    };
    (license, readme)
}

/// Writes the workspace manifests of one fixture release.
fn write_manifests(root: &Path, variant: Variant) {
    let mirror = if variant.stale_package {
        "mirrored-dep = { version = \"0.3\", registry = \"pkgre\", package = \"mirrored-dep\" }\n"
    } else {
        "mirrored-dep = { version = \"0.3\", registry = \"pkgre\" }\n"
    };
    let workspace_readme = workspace_readme(root, variant);
    let mut workspace = format!(
        "[workspace]\nmembers = [\"lib\", \"bin\", \"serve\"]\nresolver = \"3\"\n\n[workspace.package]\nversion = \"1.0.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n{workspace_readme}repository = \"https://git.example.invalid/example/project\"\n\n[workspace.dependencies]\n{mirror}"
    );
    if variant.stale_package {
        workspace.push_str(
            "earlier-lib = { version = \"0.9\", registry = \"pkgre\", package = \"earlier-lib\" }\n",
        );
    } else {
        workspace.push_str("earlier-lib = { version = \"0.9\", registry = \"pkgre\" }\n");
    }
    if variant.sibling == Sibling::Inherited {
        workspace.push_str(
            "example-lib = { path = \"lib\", version = \"=1.0.0\", registry = \"pkgre\" }\n",
        );
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
    let categories = match variant.library_categories {
        Some(categories) => format!("categories = [{categories:?}]\n"),
        None => String::new(),
    };
    let (license, readme) = library_path_fields(root, variant);
    fs::write(
        root.join("lib/Cargo.toml"),
        format!(
            "[package]\nname = \"example-lib\"\ndescription = \"An example library\"\nversion.workspace = true\nedition.workspace = true\n{license}repository.workspace = true\npublish = [\"pkgre\"]\n{categories}{readme}\n[dependencies]\nmirrored-dep.workspace = true\n\n[dev-dependencies]\nmirrored-dev = {{ version = \"0.1\", registry = \"pkgre\" }}\n\n[target.'cfg(unix)'.dependencies]\nother-mirror = {{ version = \"0.2\", registry = \"pkgre\" }}\n"
        ),
    )
    .expect("write the library manifest");
    let mut binary = String::from(
        "[package]\nname = \"example-bin\"\ndescription = \"An example binary\"\nversion.workspace = true\nedition.workspace = true\nlicense.workspace = true\nrepository.workspace = true\npublish = [\"pkgre\"]\n\n[dependencies]\nmirrored-dep = { version = \"0.3\", registry = \"pkgre\" }\nearlier-lib.workspace = true\n",
    );
    match variant.sibling {
        Sibling::None => {}
        Sibling::Accepted => binary.push_str(
            "example-lib = { path = \"../lib\", version = \"=1.0.0\", registry = \"pkgre\" }\n",
        ),
        Sibling::Requirement(requirement) => {
            writeln!(
                binary,
                "example-lib = {{ path = \"../lib\", version = {requirement:?}, registry = \"pkgre\" }}"
            )
            .expect("writing to a string");
        }
        Sibling::WithoutRegistry => {
            binary.push_str("example-lib = { path = \"../lib\", version = \"=1.0.0\" }\n");
        }
        Sibling::Unreleased | Sibling::OtherTag => binary.push_str(
            "example-serve = { path = \"../serve\", version = \"=0.2.0\", registry = \"pkgre\" }\n",
        ),
        Sibling::Renamed => binary.push_str(
            "lib-alias = { package = \"example-lib\", path = \"../lib\", version = \"=1.0.0\", registry = \"pkgre\" }\n",
        ),
        Sibling::Inherited => binary.push_str("example-lib.workspace = true\n"),
    }
    if variant.fork_dependency {
        binary.push_str("forked-dep = { version = \"1.0\", registry = \"pkgre\" }\n");
    }
    fs::write(root.join("bin/Cargo.toml"), binary).expect("write the binary manifest");
    // The tag publishes the server in the variant whose sibling the catalog
    // publishes from another tag.
    let publish = if variant.sibling == Sibling::OtherTag {
        "publish = [\"pkgre\"]"
    } else {
        "publish = false"
    };
    let mut server = format!(
        "[package]\nname = \"example-serve\"\ndescription = \"An example server\"\nversion = \"0.2.0\"\nedition = \"2021\"\nlicense = \"MIT\"\nrepository = \"https://git.example.invalid/example/project\"\n{publish}\n\n[dependencies]\nexample-lib = {{ path = \"../lib\" }}\nother-mirror = {{ version = \"0.2\", registry = \"pkgre\" }}\n\n[build-dependencies]\nearlier-lib = {{ version = \"0.9\", registry = \"pkgre\" }}\n"
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
    let environment = super::super::cargo::with_test_crates_io(
        environment,
        &RegistrySources::LocalCurated(source.to_path_buf()),
    )
    .expect("point crates.io at the local index");
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
pub(crate) fn curated_archives(
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
    let environment = super::super::cargo::with_test_crates_io(
        environment,
        &RegistrySources::LocalCurated(source.to_path_buf()),
    )
    .expect("point crates.io at the local index");
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
fn commit_and_tag(root: &Path, variant: Variant) {
    git(root, &["init", "--quiet"]);
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "release"]);
    if let Some(gitlink) = variant.gitlink {
        // A Gitlink that is never initialized, recorded in the tag's own tree.
        let linked = git(root, &["rev-parse", "HEAD"]).trim().to_owned();
        git(
            root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{linked},{gitlink}"),
            ],
        );
        git(root, &["commit", "--quiet", "-m", "gitlink"]);
    }
    git(root, &["tag", "-a", &tag(), "-m", "example 1.0.0"]);
}

/// Runs one Git command in a directory and returns its output.
pub(crate) fn git(root: &Path, arguments: &[&str]) -> String {
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
pub(crate) struct Catalog {
    /// Directory that holds `registry/` and `self-publish/`.
    pub(crate) root: PathBuf,
    /// The curated archive of every released crate, by package name.
    pub(crate) curated: BTreeMap<String, Vec<u8>>,
}

/// Builds a catalog repository for one fixture release, with one entered earlier
/// release and no entry for the fixture release.
pub(crate) fn catalog(
    parent: &Path,
    source: &LocalSource,
    release: &Release,
    variant: Variant,
) -> Catalog {
    catalog_at(parent, "catalog", source, release, variant, true)
}

/// Builds one catalog repository below `parent`, before or after the fixture
/// release was added to it.
///
/// `released` adds the fixture release to the catalog: its publish
/// declarations, its identities and their retained archives. Either way the
/// `crates-io.lock` holds only the earlier release, as it does before
/// `self-publish-lock` runs.
pub(crate) fn catalog_at(
    parent: &Path,
    name: &str,
    source: &LocalSource,
    release: &Release,
    variant: Variant,
    released: bool,
) -> Catalog {
    let root = parent.join(name);
    let registry = root.join("registry");
    fs::create_dir_all(registry.join("objects/crates")).expect("create the catalog");
    fs::create_dir_all(root.join("self-publish")).expect("create the self-publishing state");
    let curated = if released {
        curated_archives(
            &release.root,
            &source.root,
            &[
                ("example-bin", release.version("example-bin")),
                ("example-lib", release.version("example-lib")),
            ],
        )
    } else {
        BTreeMap::new()
    };
    let mirrors = vec![
        ("mirrored-dep", "0.3.0"),
        ("mirrored-dev", "0.1.0"),
        ("other-mirror", "0.2.0"),
    ];
    write_registry_file(&registry.join("main.toml"), variant, &mirrors, released);
    fs::create_dir_all(registry.join("objects/rows")).expect("create the row objects");
    for (name, version) in &mirrors {
        let row = mirror_row(name, version, &source.checksum(name, version));
        fs::write(
            registry
                .join("objects/rows")
                .join(format!("{}.json", sha256_bytes(&row))),
            row,
        )
        .expect("write the mirror's source row");
    }
    let lock = registry_lock(release, variant, &mirrors, &curated, source, released);
    fs::write(
        registry.join("main.lock"),
        serialize_lock(&lock).expect("serialize the fixture lock"),
    )
    .expect("write the fixture lock");
    write_downloads(&registry, &lock);
    for package in &lock.packages {
        if mirrors
            .iter()
            .any(|(name, version)| *name == package.name && *version == package.version.to_string())
        {
            continue;
        }
        let dependencies = released_dependencies(&package.name, variant);
        let row = package_row(
            &package.name,
            &package.version.to_string(),
            &package.crate_sha256,
            &dependencies,
        );
        fs::write(
            registry
                .join("objects/rows")
                .join(format!("{}.json", sha256_bytes(&row))),
            row,
        )
        .expect("write the identity's source row");
    }
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

/// Writes the canonical download route table of one fixture registry lock.
fn write_downloads(registry: &Path, lock: &RegistryLock) {
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
}

/// Adds one identity from a tag outside the release convention to one catalog
/// repository, as a catalog holds a crate that its repository published before
/// it adopted self-publishing: the identity has no `crates-io.lock` entry of
/// its own.
pub(crate) fn add_non_release_identity(catalog: &Catalog, name: &str, version: &str, tag: &str) {
    let registry = catalog.root.join("registry");
    let mut declaration =
        fs::read_to_string(registry.join("main.toml")).expect("read the fixture registry file");
    write!(
        declaration,
        "\n[categories.pkgre.publish.{name}]\ngit = \"{REPOSITORY}\"\ntags = [\"{tag}\"]\n"
    )
    .expect("writing to a string");
    fs::write(registry.join("main.toml"), declaration).expect("write the fixture registry file");
    let mut lock: RegistryLock =
        toml::from_slice(&fs::read(registry.join("main.lock")).expect("read the fixture lock"))
            .expect("parse the fixture lock");
    lock.names.push(LockedName {
        name: name.to_owned(),
        category: "pkgre".to_owned(),
    });
    let row = package_row(name, version, &crate_checksum(name, version), &[]);
    fs::write(
        registry
            .join("objects/rows")
            .join(format!("{}.json", sha256_bytes(&row))),
        &row,
    )
    .expect("write the identity's source row");
    lock.packages.push(LockedPackage {
        name: name.to_owned(),
        version: Version::parse(version).expect("parse a fixture version"),
        state: PackageState::Active,
        crate_sha256: crate_checksum(name, version),
        source_row_sha256: sha256_bytes(&row),
        index_row_sha256: checksum("index", name, version),
        admission_sha256: None,
        admitted_at: admitted_at(),
        source: LockedSource::GitTag {
            git: REPOSITORY.to_owned(),
            tag: tag.to_owned(),
            tag_oid: "b".repeat(40),
            commit: "c".repeat(40),
            package: name.to_owned(),
            path: PathBuf::from("indexer"),
            cargo_version: Version::parse(CARGO_VERSION).expect("parse the pinned version"),
        },
    });
    fs::write(
        registry.join("main.lock"),
        serialize_lock(&lock).expect("serialize the fixture lock"),
    )
    .expect("write the fixture lock");
    write_downloads(&registry, &lock);
}

/// Returns the `crates-io.lock` entry of the fixture's earlier release.
pub(crate) fn earlier_entry(source: &LocalSource) -> CratesIoPackage {
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
fn write_registry_file(path: &Path, variant: Variant, mirrors: &[(&str, &str)], released: bool) {
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
    if released {
        for name in ["example-bin", "example-lib"] {
            write!(
                text,
                "\n[categories.pkgre.publish.{name}]\ngit = \"{REPOSITORY}\"\ntags = [\"{}\"]\n",
                tag()
            )
            .expect("writing to a string");
        }
    }
    if variant.sibling == Sibling::OtherTag {
        write!(
            text,
            "\n[categories.pkgre.publish.example-serve]\ngit = \"{REPOSITORY}\"\ntags = [\"rust/v0.2.0\"]\n"
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
    released: bool,
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
            source_row_sha256: sha256_bytes(&mirror_row(
                name,
                version,
                &source.checksum(name, version),
            )),
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
        source_row_sha256: sha256_bytes(&package_row(
            "earlier-lib",
            "0.9.0",
            &crate_checksum("earlier-lib", "0.9.0"),
            &[],
        )),
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
            source_row_sha256: sha256_bytes(&package_row(
                "forked-dep",
                "1.0.0",
                &crate_checksum("forked-dep", "1.0.0"),
                &[],
            )),
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
            source_row_sha256: sha256_bytes(&package_row(
                "unknown-lib",
                "1.0.0",
                &crate_checksum("unknown-lib", "1.0.0"),
                &[],
            )),
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
        if !released {
            continue;
        }
        let archive = curated
            .get(name)
            .unwrap_or_else(|| panic!("the curated archive of {name} exists"));
        names.push(LockedName {
            name: name.to_owned(),
            category: "pkgre".to_owned(),
        });
        let dependencies = released_dependencies(name, variant);
        let row = package_row(name, VERSION, &sha256_bytes(archive), &dependencies);
        packages.push(LockedPackage {
            name: name.to_owned(),
            version: release.version(name),
            state: PackageState::Active,
            crate_sha256: sha256_bytes(archive),
            source_row_sha256: sha256_bytes(&row),
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

/// The deterministic publication and admission time of the fixture.
const ADMITTED_AT: &str = "2026-01-02T03:04:05Z";

/// Returns the deterministic admission timestamp of the fixture.
fn admitted_at() -> UtcTimestamp {
    UtcTimestamp::parse(ADMITTED_AT).expect("parse the fixture timestamp")
}

/// Returns the retained crates.io source row of one mirror, whose `pubtime` is the
/// admission time that loading re-derives.
fn mirror_row(name: &str, version: &str, checksum: &str) -> Vec<u8> {
    let mut row = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "vers": version,
        "deps": [],
        "cksum": checksum,
        "features": {},
        "yanked": false,
        "pubtime": ADMITTED_AT,
    }))
    .expect("serialize a fixture row");
    row.push(b'\n');
    row
}

/// Publishes one crate on a local registry after its index was committed, as an
/// upload does.
pub(crate) fn publish_archive(
    root: &Path,
    name: &str,
    version: &str,
    archive: &[u8],
    checksum: &str,
    dependencies: &[(&str, &str)],
) {
    fs::write(
        root.join("crates").join(format!("{name}-{version}.crate")),
        archive,
    )
    .expect("write the crate archive");
    let mut row = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "vers": version,
        "deps": dependencies
            .iter()
            .map(|(name, req)| serde_json::json!({
                "name": name,
                "req": req,
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "package": null,
            }))
            .collect::<Vec<_>>(),
        "cksum": checksum,
        "features": {},
        "yanked": false,
    }))
    .expect("serialize a published index row");
    row.push(b'\n');
    let path = root.join("index").join(crate::index::index_path(name));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create the index directory");
    }
    fs::write(&path, row).expect("write the published index row");
    let index = root.join("index");
    git(&index, &["add", "."]);
    git(&index, &["commit", "--quiet", "-m", name]);
}

/// Returns the dependencies that one first-party crate of the fixture declares,
/// as its source row names them.
pub(crate) fn released_dependencies(name: &str, variant: Variant) -> Vec<&'static str> {
    match name {
        "example-bin" => {
            let mut dependencies = vec!["mirrored-dep", "earlier-lib"];
            match variant.sibling {
                Sibling::None | Sibling::Unreleased | Sibling::OtherTag => {}
                _ => dependencies.push("example-lib"),
            }
            dependencies
        }
        "example-lib" => vec!["mirrored-dep", "other-mirror"],
        _ => Vec::new(),
    }
}

/// Returns the source row of one first-party crate of the fixture.
fn package_row(name: &str, version: &str, checksum: &str, dependencies: &[&str]) -> Vec<u8> {
    let mut row = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "vers": version,
        "deps": dependencies
            .iter()
            .map(|dependency| serde_json::json!({
                "name": dependency,
                "req": format!("={VERSION}"),
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "package": null,
            }))
            .collect::<Vec<_>>(),
        "cksum": checksum,
        "features": {},
        "yanked": false,
    }))
    .expect("serialize a first-party row");
    row.push(b'\n');
    row
}

/// One file of a repacked archive.
#[derive(Clone, Debug)]
pub(crate) struct ArchiveFile {
    /// File contents.
    pub(crate) contents: Vec<u8>,
    /// Portable permission bits.
    pub(crate) mode: u32,
}

/// Reads every file of one derived archive, by path below the archive root.
pub(crate) fn archive_files(
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
pub(crate) fn tar_gz(
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
pub(crate) fn decompress(archive: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(archive);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes).expect("decompress");
    bytes
}

/// Writes one executable script, so that this process never holds a descriptor
/// for it.
///
/// The test harness runs tests on several threads, and a descriptor open for
/// writing here would be inherited by any child another test starts; executing
/// the script would then fail with `ETXTBSY` until that child execs. A child of
/// its own writes the script and makes it executable, and closes the descriptor
/// before it exits.
pub(crate) fn write_executable(path: &Path, contents: &str) {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut writer = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("start the writer of {}: {error}", path.display()));
    let mut stdin = writer
        .stdin
        .take()
        .expect("the writer of the script has a standard input");
    stdin
        .write_all(contents.as_bytes())
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    drop(stdin);
    let output = writer
        .wait_with_output()
        .unwrap_or_else(|error| panic!("wait for the writer of {}: {error}", path.display()));
    assert!(
        output.status.success(),
        "writing {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}
