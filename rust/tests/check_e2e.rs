//! Integration tests of `pkgre-rust check`, which run the binary on a frozen catalog.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The frozen production catalog, as a complete catalog tree below `registry/`.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust-current-catalog-d778238.tar.gz")
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pkgre-rust"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Extracts the frozen catalog into a fresh directory and returns its catalog root.
fn extract_fixture(temporary: &TemporaryDirectory) -> PathBuf {
    let archive = temporary.path().join("catalog.tar.gz");
    fs::copy(fixture(), &archive).unwrap();
    let extraction = temporary.path().join("extracted");
    fs::create_dir(&extraction).unwrap();
    let status = Command::new("tar")
        .arg("--extract")
        .arg("--gzip")
        .arg("--file")
        .arg(&archive)
        .arg("--directory")
        .arg(&extraction)
        .status()
        .unwrap();
    assert!(status.success());
    extraction.join("registry")
}

/// Copies every regular file of `source` to `destination`, keeping the layout.
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    let mut entries = fs::read_dir(source)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path).unwrap();
        let target = destination.join(path.file_name().unwrap());
        if metadata.is_dir() {
            copy_tree(&path, &target);
        } else {
            assert!(metadata.is_file(), "{}", path.display());
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// Replaces the first locked routed-row hash with a different valid digest.
fn with_stale_index_row_hash(lock: &str) -> String {
    const KEY: &str = "index-row-sha256 = \"";
    let start = lock.find(KEY).unwrap() + KEY.len();
    let digest = &lock[start..start + 64];
    let mut stale = digest.to_owned();
    stale.replace_range(..1, if digest.starts_with('0') { "1" } else { "0" });
    format!("{}{stale}{}", &lock[..start], &lock[start + 64..])
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

#[test]
fn accepts_the_frozen_catalog_and_logs_its_projection_margins() {
    let temporary = TemporaryDirectory::new("pkgre-check-frozen");
    let root = extract_fixture(&temporary);

    let output = command().arg("check").arg(&root).output().unwrap();

    let error = stderr(&output);
    assert!(output.status.success(), "{error}");
    assert!(
        error.contains("catalog is valid packages=747 margins="),
        "{error}"
    );
}

#[test]
fn refuses_a_stale_routed_row_hash_exactly_as_lock_refuses_it() {
    let temporary = TemporaryDirectory::new("pkgre-check-frozen-stale");
    let root = extract_fixture(&temporary);
    let stale = temporary.path().join("stale");
    copy_tree(&root, &stale);
    let lock_path = stale.join("main.lock");
    let lock = fs::read_to_string(&lock_path).unwrap();
    fs::write(&lock_path, with_stale_index_row_hash(&lock)).unwrap();

    let checked = command().arg("check").arg(&stale).output().unwrap();
    let locked = command().arg("lock").arg(&stale).output().unwrap();

    let failure = failure_message(&checked);
    assert!(
        failure.starts_with("routed index-row hash mismatch for "),
        "{failure}"
    );
    assert_eq!(failure, failure_message(&locked));
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
