//! Integration tests of `pkgre-rust reproduce-git-tags` on a frozen catalog.

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

#[test]
fn reproduces_nothing_between_a_catalog_and_itself() {
    let temporary = TemporaryDirectory::new("pkgre-reproduce-identical");
    let root = extract_fixture(&temporary);

    let output = command()
        .arg("reproduce-git-tags")
        .arg(&root)
        .arg(&root)
        .output()
        .unwrap();

    let error = stderr(&output);
    assert!(output.status.success(), "{error}");
    assert!(
        error.contains(
            "no Git-tag identity is new since the accepted catalog; nothing to reproduce"
        ),
        "{error}"
    );
}

#[test]
fn refuses_a_wrong_number_of_arguments() {
    let temporary = TemporaryDirectory::new("pkgre-reproduce-arity");
    let root = extract_fixture(&temporary);

    for arguments in [vec![root.clone()], vec![root.clone(), root.clone(), root]] {
        let output = command()
            .arg("reproduce-git-tags")
            .args(&arguments)
            .output()
            .unwrap();

        let error = stderr(&output);
        assert!(!output.status.success(), "{error}");
        assert!(
            error.contains("wrong number of arguments"),
            "arguments {arguments:?} must be refused:\n{error}"
        );
        assert!(
            error.contains("pkgre-rust reproduce-git-tags <accepted-catalog> <candidate-catalog>"),
            "the usage names the command:\n{error}"
        );
    }
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
