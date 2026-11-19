//! Integration tests of `pkgre-rust check-serve`, which run the binary on frozen catalogs.

use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const FIXTURE_SHA256: &str = "d5d2ce2cf86fafcb52400677c6f020ce096132deb45a24d5535e98149b0baacc";
const FIXTURE: &[u8] = include_bytes!("fixtures/rust-current-catalog-d778238.tar.gz");

/// Direct dependency names of the fixture's three first-party Git tags.
///
/// The reduced catalog below declares them as empty reservations, because every routed dependency
/// edge of a locked package needs a declared home and the mirrors that would provide one are gone.
const RESERVED_DEPENDENCIES: [&str; 11] = [
    "anyhow",
    "flate2",
    "nix",
    "semver",
    "serde",
    "serde_json",
    "sha2",
    "toml",
    "toml_edit",
    "tracing",
    "tracing-subscriber",
];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pkgre-rust"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Returns the failure message the binary logs for one unsuccessful run.
fn failure_message(output: &Output) -> String {
    let error = stderr(output);
    assert!(!output.status.success(), "{error}");
    error
        .lines()
        .find_map(|line| {
            line.split_once("error=")
                .map(|(_, message)| message.to_owned())
        })
        .unwrap_or_else(|| panic!("no logged failure in {error}"))
}

/// Extracts the frozen catalog and returns its catalog root.
fn extract_fixture(destination: &Path) -> PathBuf {
    assert_eq!(pkgre_rust::artifact::sha256_bytes(FIXTURE), FIXTURE_SHA256);
    let archive = destination.with_extension("tar.gz");
    fs::write(&archive, FIXTURE).unwrap();
    fs::create_dir(destination).unwrap();
    let status = Command::new("tar")
        .arg("--extract")
        .arg("--gzip")
        .arg("--file")
        .arg(&archive)
        .arg("--directory")
        .arg(destination)
        .status()
        .unwrap();
    assert!(status.success());
    fs::remove_file(&archive).unwrap();
    destination.join("registry")
}

/// Builds a catalog whose every advertised archive is retained in the catalog itself.
///
/// The frozen production catalog retains only the three bodies of its first-party Git tags; every
/// other route is a crates.io redirect whose archive no test has. Body delivery accepts a catalog
/// without any stored archive only when the snapshot converts nothing, so the catalog is reduced
/// to those three identities: the declaration drops the mirrors, the generated lock keeps only
/// their blocks, and the unreferenced generated state is removed. `lock` then reconciles the
/// declaration without fetching anything, because the recorded Git tags are unchanged.
fn retained_catalog(parent: &Path, label: &str) -> PathBuf {
    let root = extract_fixture(&parent.join(label));
    write_retained_declaration(&root.join("main.toml"));
    prune_generated_lock(&root.join("main.lock"));
    fs::remove_dir_all(root.join("categories")).unwrap();
    fs::remove_dir_all(root.join("admissions")).unwrap();
    fs::remove_file(root.join("downloads.json")).unwrap();
    prune_row_objects(&root);
    run_lock(&root);
    root
}

/// Writes the reduced declaration: the frozen catalog's three Git tags and their reserved homes.
fn write_retained_declaration(path: &Path) {
    let mut reserved = String::new();
    for name in RESERVED_DEPENDENCIES {
        writeln!(reserved, "{name} = []").unwrap();
    }
    fs::write(
        path,
        format!(
            r#"schema = 5

[registry]
name = "main"
index = "sparse+https://rust.pkg.re/"
download = "https://dl.rust.pkg.re/v1/main/{{crate}}/{{version}}/{{sha256-checksum}}"
cargo-version = "1.95.0"
audience = "public"

[categories.general]
may-depend-on = ["main/general"]

[categories.general.mirror]
{reserved}
[categories.pkgre]
may-depend-on = ["main/general", "main/pkgre"]

[categories.pkgre.publish.pkgre-indexer]
git = "https://github.com/pkgre/pkgre"
tags = ["indexer/v0.1.1", "indexer/v0.2.0", "indexer/v0.3.0"]
"#
        ),
    )
    .unwrap();
}

/// Keeps the header and the blocks of the frozen catalog's first-party Git tags in one lock.
fn prune_generated_lock(lock: &Path) {
    let text = fs::read_to_string(lock).unwrap();
    let mut blocks = Vec::<String>::new();
    for line in text.lines() {
        if line.starts_with("[[") || blocks.is_empty() {
            blocks.push(String::new());
        }
        let block = blocks.last_mut().unwrap();
        block.push_str(line);
        block.push('\n');
    }
    let kept = blocks
        .into_iter()
        .filter(|block| {
            block.starts_with("schema = ")
                || ((block.starts_with("[[names]]") || block.starts_with("[[packages]]"))
                    && block.lines().any(|line| line == "name = \"pkgre-indexer\""))
        })
        .collect::<String>();
    fs::write(lock, format!("{}\n", kept.trim_end())).unwrap();
}

/// Removes every row object the reduced lock no longer references.
fn prune_row_objects(root: &Path) {
    let lock = fs::read_to_string(root.join("main.lock")).unwrap();
    let referenced = lock
        .lines()
        .filter_map(|line| line.strip_prefix("source-row-sha256 = \""))
        .map(|value| value.strip_suffix('"').unwrap().to_owned())
        .collect::<Vec<_>>();
    let rows = root.join("objects/rows");
    for entry in fs::read_dir(&rows).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !referenced
            .iter()
            .any(|sha256| name == format!("{sha256}.json"))
        {
            fs::remove_file(&path).unwrap();
        }
    }
}

/// Runs the real `lock` command, which must reconcile the reduced catalog without network access.
fn run_lock(catalog: &Path) {
    let output = command().arg("lock").arg(catalog).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
}

/// Returns one field's unquoted value from a locked package block.
fn locked_field(lock: &str, name: &str, version: &str, field: &str) -> String {
    let header = format!("[[packages]]\nname = {name:?}\nversion = {version:?}\n");
    let start = lock
        .find(&header)
        .unwrap_or_else(|| panic!("locked package {name} {version} not found"));
    let block = &lock[start + header.len()..];
    let end = block.find("\n[[packages]]").unwrap_or(block.len());
    let block = &block[..end];
    let prefix = format!("{field} = \"");
    let at = block
        .find(&prefix)
        .unwrap_or_else(|| panic!("locked package {name} {version} has no {field}"));
    let value = &block[at + prefix.len()..];
    value[..value.find('"').expect("locked field terminates")].to_owned()
}

#[test]
fn a_retained_catalog_builds_the_body_mode_snapshot_with_an_empty_archive_store() {
    let temporary = TemporaryDirectory::new("pkgre-check-serve-body");
    let catalog = retained_catalog(temporary.path(), "retained");
    let store = temporary.path().join("store");
    fs::create_dir(&store).unwrap();

    let output = command()
        .arg("check-serve")
        .arg(&catalog)
        .arg("--delivery=body")
        .arg(format!("--archive-store={}", store.display()))
        .output()
        .unwrap();

    let log = stderr(&output);
    assert!(output.status.success(), "{log}");
    // Every route the catalog advertises is retained, so body delivery converts all three
    // first-party redirects into bodies this origin serves and no archive comes from the store.
    assert!(
        log.contains(
            "catalog builds a valid serving snapshot mode=\"body\" inline_routes=4 \
             archive_routes=6 redirect_routes=0 routes=10"
        ),
        "{log}"
    );
}

#[test]
fn a_retained_catalog_builds_the_redirect_mode_snapshot_with_a_first_party_origin() {
    let temporary = TemporaryDirectory::new("pkgre-check-serve-redirect");
    let catalog = retained_catalog(temporary.path(), "retained");

    let output = command()
        .arg("check-serve")
        .arg(&catalog)
        .arg("--delivery=redirect")
        .arg("--first-party-origin=https://rust.pkg.re")
        .output()
        .unwrap();

    let log = stderr(&output);
    assert!(output.status.success(), "{log}");
    assert!(
        log.contains(
            "catalog builds a valid serving snapshot mode=\"redirect\" inline_routes=4 \
             archive_routes=3 redirect_routes=3 routes=10"
        ),
        "{log}"
    );
}

#[test]
fn each_delivery_mode_fails_as_the_service_does_without_its_required_option() {
    let temporary = TemporaryDirectory::new("pkgre-check-serve-missing-option");
    // Body delivery refuses a missing store, and redirect delivery a missing first-party origin,
    // before any catalog work, so what the catalog contains cannot change these two refusals.
    let catalog = extract_fixture(&temporary.path().join("frozen"));

    let body = command()
        .arg("check-serve")
        .arg(&catalog)
        .arg("--delivery=body")
        .output()
        .unwrap();
    assert_eq!(
        failure_message(&body),
        "body delivery mode requires an archive store path in the service configuration"
    );

    let redirect = command()
        .arg("check-serve")
        .arg(&catalog)
        .arg("--delivery=redirect")
        .output()
        .unwrap();
    assert_eq!(
        failure_message(&redirect),
        "redirect delivery mode requires a first-party origin in the service configuration"
    );
}

#[test]
fn a_locked_removal_leaves_the_body_mode_snapshot_unbuildable_today() {
    let temporary = TemporaryDirectory::new("pkgre-check-serve-removal");
    let catalog = retained_catalog(temporary.path(), "retained");

    // Remove one Git tag the way the catalog's removal workflow does; `lock` records the
    // tombstone and drops the retained archive the removed identity no longer shares.
    let declaration = catalog.join("main.toml");
    let declared = fs::read_to_string(&declaration).unwrap();
    let removed_tag = "\"indexer/v0.3.0\"";
    assert!(
        declared.contains(removed_tag),
        "fixture must declare {removed_tag}"
    );
    let edited = declared.replace(&format!(", {removed_tag}"), "");
    assert_ne!(edited, declared, "the removal must edit the declaration");
    fs::write(&declaration, edited).unwrap();
    run_lock(&catalog);

    let archive = locked_field(
        &fs::read_to_string(catalog.join("main.lock")).unwrap(),
        "pkgre-indexer",
        "0.3.0",
        "crate-sha256",
    );
    assert!(
        !catalog
            .join("objects/crates")
            .join(format!("{archive}.crate"))
            .exists(),
        "lock must drop the unshared retained archive"
    );

    // This pins today's body-delivery behavior for a removal rather than describing a desired
    // one: the tombstone route stays, its archive is gone, and the snapshot demands a body.
    let store = temporary.path().join("store");
    fs::create_dir(&store).unwrap();
    let body = command()
        .arg("check-serve")
        .arg(&catalog)
        .arg("--delivery=body")
        .arg(format!("--archive-store={}", store.display()))
        .output()
        .unwrap();
    let failure = failure_message(&body);
    assert!(
        failure.starts_with(&format!(
            "read body-mode archive for /v1/main/pkgre-indexer/0.3.0/{archive}"
        )),
        "{failure}"
    );

    // Redirect delivery keeps serving the tombstone, which the removal transition accepted.
    let redirect = command()
        .arg("check-serve")
        .arg(&catalog)
        .arg("--delivery=redirect")
        .arg("--first-party-origin=https://rust.pkg.re")
        .output()
        .unwrap();
    let log = stderr(&redirect);
    assert!(redirect.status.success(), "{log}");
    assert!(
        log.contains("archive_routes=2 redirect_routes=3"),
        "the removed identity keeps its redirect route only: {log}"
    );
}

#[test]
fn argument_errors_fail_closed() {
    let temporary = TemporaryDirectory::new("pkgre-check-serve-arguments");
    // Every refusal below is decided before the catalog is read.
    let catalog = temporary.path().join("absent");

    let cases: [(&str, &[&str], &str); 5] = [
        (
            "unknown",
            &["--delivery=redirect", "--platform=x86_64"],
            "unknown argument \"--platform=x86_64\"",
        ),
        (
            "repeated",
            &["--delivery=redirect", "--delivery=body"],
            "--delivery is given more than once",
        ),
        ("missing-delivery", &[], "--delivery is required"),
        (
            "store-outside-body",
            &["--delivery=redirect", "--archive-store=/srv/pkgre/archives"],
            "--archive-store is only valid with --delivery=body",
        ),
        (
            "origin-outside-redirect",
            &[
                "--delivery=body",
                "--first-party-origin=https://rust.pkg.re",
            ],
            "--first-party-origin is only valid with --delivery=redirect",
        ),
    ];
    for (label, arguments, expected) in cases {
        let output = command()
            .arg("check-serve")
            .arg(&catalog)
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{label} must fail");
        let log = stderr(&output);
        assert!(log.contains(expected), "{label}: {log}");
    }

    let arity = command().arg("check-serve").output().unwrap();
    assert_eq!(failure_message(&arity), "wrong number of arguments");
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{label}-{}-{sequence}", std::process::id()));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove stale temporary directory: {error}"),
        }
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
