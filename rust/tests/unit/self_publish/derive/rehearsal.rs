//! The rehearsal of a crates.io-native release, against live crates.io.
//!
//! The test builds a small repository of its own, tags it, and packages the tag
//! the ways a native release is packaged: as one group against crates.io, twice,
//! with Cargo's verification in a copy of the checkout, and again with the
//! upload's Cargo home. It uploads nothing and keeps every name neutral.

use super::*;

/// The version every crate of the rehearsal's tag has.
const REHEARSAL_VERSION: &str = "0.1.0";

/// Writes one file of the rehearsal's repository.
fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create a rehearsal directory");
    }
    fs::write(path, text).expect("write a rehearsal file");
}

/// Runs one Cargo command and requires success.
fn cargo_run(cargo: &Path, environment: &ChildEnvironment, work: &Path, arguments: &[&str]) {
    let mut command = std::process::Command::new(cargo);
    environment.apply(&mut command);
    let output = command
        .current_dir(work)
        .args(arguments)
        .output()
        .expect("run the pinned Cargo");
    assert!(
        output.status.success(),
        "cargo {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Builds the rehearsal's repository and returns its root.
fn repository(root: &Path) -> PathBuf {
    let repository = root.join("repository");
    write(
        &repository,
        "Cargo.toml",
        "[workspace]\nmembers = [\"lib\", \"bin\"]\nresolver = \"2\"\n",
    );
    write(
        &repository,
        "lib/Cargo.toml",
        "[package]\nname = \"rehearsal-lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"the library of a packaging rehearsal\"\n\n[dependencies]\nsemver = \"1\"\n",
    );
    write(
        &repository,
        "lib/src/lib.rs",
        "pub fn answer() -> u32 { 42 }\n",
    );
    write(
        &repository,
        "bin/Cargo.toml",
        "[package]\nname = \"rehearsal-bin\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"the binary of a packaging rehearsal\"\n\n[dependencies]\nrehearsal-lib = { path = \"../lib\", version = \"=0.1.0\" }\n",
    );
    write(
        &repository,
        "bin/src/main.rs",
        "fn main() { println!(\"{}\", rehearsal_lib::answer()); }\n",
    );
    fixtures::git(&repository, &["init", "--quiet"]);
    fixtures::git(&repository, &["add", "."]);
    fixtures::git(
        &repository,
        &[
            "commit",
            "--quiet",
            "-m",
            "the tag of a packaging rehearsal",
        ],
    );
    repository
}

#[test]
#[ignore = "packages against live crates.io; run it explicitly"]
fn live_native_release_rehearsal_keeps_one_archive_below_every_step() {
    let temporary = fixtures::Temp::new("native-rehearsal");
    let repository = repository(temporary.path());
    let cargo = crate::package::pinned_cargo(
        &crate::policy::CARGO_VERSION
            .parse()
            .expect("parse the pinned version"),
    )
    .expect("locate the pinned Cargo");
    let sources = super::super::cargo::RegistrySources::CratesIo;
    let home = temporary.path().join("cargo-home");
    super::super::cargo::prepare_cargo_home(&home, sources.clone())
        .expect("prepare a crates.io Cargo home");
    let environment = ChildEnvironment::capture(&home, &cargo).expect("capture the environment");
    let work = temporary.path().join("work");
    fs::create_dir_all(&work).expect("create the working directory");
    let manifest = repository.join("Cargo.toml");
    let manifest = manifest.to_str().expect("a UTF-8 manifest path");
    // The tag's own lock, resolved against live crates.io, as a preparation
    // pull request commits it.
    cargo_run(
        &cargo,
        &environment,
        &work,
        &["generate-lockfile", "--manifest-path", manifest],
    );
    fixtures::git(&repository, &["add", "Cargo.lock"]);
    fixtures::git(&repository, &["commit", "--quiet", "-m", "the tag's lock"]);
    fixtures::git(
        &repository,
        &["tag", "-a", "v0.1.0", "-m", "rehearsal v0.1.0"],
    );
    let version = || -> Version { REHEARSAL_VERSION.parse().expect("a version") };
    let members = vec![
        ("rehearsal-bin".to_owned(), version()),
        ("rehearsal-lib".to_owned(), version()),
    ];
    // The derivation's form: one group against crates.io, twice, clean.
    let archives = super::super::cargo::package_members(
        &cargo,
        &environment,
        &work,
        &temporary.path().join("group-targets"),
        &repository,
        &members,
        false,
    )
    .expect("package the group against live crates.io, twice");
    assert_eq!(
        fixtures::git(&repository, &["status", "--porcelain=v1"]),
        ""
    );
    // Step 5: Cargo's verification, in a copy of the checkout.
    let copy = temporary.path().join("verified-checkout");
    super::super::native::copy_checkout(&repository, &copy).expect("copy the checkout");
    let verified = super::super::cargo::package_group(
        &cargo,
        &environment,
        &work,
        &temporary.path().join("verified-target"),
        &copy.join("Cargo.toml"),
        &members,
        super::super::cargo::Options {
            build: super::super::cargo::Build::Verify,
            allow_dirty: false,
        },
    )
    .expect("verify the group in a copy of the checkout");
    assert_eq!(verified, archives);
    // Step 6: the upload's own Cargo home, without verification.
    let upload_home = temporary.path().join("upload-home");
    super::super::cargo::prepare_upload_cargo_home(&upload_home, &sources)
        .expect("prepare the upload's Cargo home");
    let upload_environment =
        ChildEnvironment::capture(&upload_home, &cargo).expect("capture the upload environment");
    let uploaded = super::super::cargo::package_group(
        &cargo,
        &upload_environment,
        &work,
        &temporary.path().join("upload-target"),
        Path::new(manifest),
        &members,
        super::super::cargo::Options {
            build: super::super::cargo::Build::Package,
            allow_dirty: false,
        },
    )
    .expect("package the group as the upload would");
    assert_eq!(uploaded, archives);
    assert_eq!(archives.len(), 2);
}
