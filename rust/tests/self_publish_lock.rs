//! Integration tests of `pkgre-rust self-publish-lock`, which run the binary on
//! fixture catalog repositories.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

/// The fixture repository: a catalog that already records every identity of its
/// one release.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/self-publish-catalog")
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pkgre-rust"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_repository_whose_entries_are_complete_changes_nothing() {
    let lock = fixture().join("self-publish/crates-io.lock");
    let before = fs::read(&lock).expect("the fixture lock exists");
    let output = command()
        .arg("self-publish-lock")
        .arg(fixture())
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(output.status.success(), "{error}");
    assert!(error.contains("nothing to derive"), "{error}");
    assert_eq!(
        fs::read(&lock).expect("the fixture lock exists"),
        before,
        "a run with nothing to derive writes nothing"
    );
}

#[test]
fn a_repository_without_self_publishing_state_is_refused() {
    let output = command()
        .arg("self-publish-lock")
        .arg(fixture().join("registry"))
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(error.contains("self-publish"), "{error}");
}

#[test]
fn a_wrong_number_of_arguments_prints_the_usage() {
    let output = command()
        .arg("self-publish-lock")
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(error.contains("self-publish-lock <repository>"), "{error}");
}
