//! Integration tests of `pkgre-rust self-publish-check`, which run the binary on
//! fixture catalog repositories.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::symlink;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The fixture repository: a catalog that releases `example-lib` under a mapped
/// name and `example-bin` under the default prefix at `rust/v1.0.0`.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/self-publish-catalog")
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pkgre-rust"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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

/// Removes one `[[packages]]` block from canonical `crates-io.lock` text,
/// keeping the remaining blocks in canonical order and spacing.
fn remove_package_block(text: &str, name: &str) -> String {
    let marker = "\n[[packages]]\n";
    let start = text.find(marker).expect("the lock has at least one entry");
    let mut blocks = text[start + marker.len()..]
        .split(marker)
        .collect::<Vec<_>>();
    let identity = format!("name = {name:?}\n");
    let index = blocks
        .iter()
        .position(|block| block.contains(&identity))
        .unwrap_or_else(|| panic!("the lock has no entry for {name:?}"));
    blocks.remove(index);
    format!("{}{marker}{}", &text[..start], blocks.join(marker))
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

#[test]
fn accepts_the_fixture_repository_and_says_that_it_skipped_the_comparison() {
    let output = command()
        .arg("self-publish-check")
        .arg(fixture())
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(output.status.success(), "{error}");
    assert!(
        error.contains("checks that compare against an accepted state are skipped"),
        "{error}"
    );
    assert!(error.contains("declared=true"), "{error}");
    assert!(error.contains("repositories=1"), "{error}");
    assert!(error.contains("names=1"), "{error}");
    assert!(error.contains("entries=2"), "{error}");
    assert!(error.contains("identities=2"), "{error}");
    assert!(error.contains("accepted=false"), "{error}");
}

#[test]
fn refuses_an_entry_that_the_candidate_removed() {
    let temporary = TemporaryDirectory::new("pkgre-self-publish-removed");
    let candidate = temporary.path().join("candidate");
    copy_tree(&fixture(), &candidate);
    let lock = candidate.join("self-publish/crates-io.lock");
    let text = fs::read_to_string(&lock).unwrap();
    fs::write(&lock, remove_package_block(&text, "example-bin")).unwrap();

    let output = command()
        .arg("self-publish-check")
        .arg(&candidate)
        .arg(fixture())
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(
        error.contains("was removed from crates-io.lock"),
        "the entry must be checked before anything else fails: {error}"
    );
}

#[test]
fn accepts_a_repository_without_a_self_publish_directory() {
    let temporary = TemporaryDirectory::new("pkgre-self-publish-absent");
    let candidate = temporary.path().join("candidate");
    copy_tree(&fixture(), &candidate);
    fs::remove_dir_all(candidate.join("self-publish")).unwrap();

    let output = command()
        .arg("self-publish-check")
        .arg(&candidate)
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(output.status.success(), "{error}");
    assert!(error.contains("has no self-publish directory"), "{error}");
}

#[test]
fn refuses_a_directory_that_does_not_hold_a_catalog() {
    let temporary = TemporaryDirectory::new("pkgre-self-publish-no-catalog");
    let output = command()
        .arg("self-publish-check")
        .arg(temporary.path())
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(error.contains("has no registry directory"), "{error}");
}

#[test]
fn refuses_removing_the_self_publish_directory_of_the_accepted_repository() {
    let temporary = TemporaryDirectory::new("pkgre-self-publish-removal");
    let candidate = temporary.path().join("candidate");
    copy_tree(&fixture(), &candidate);
    fs::remove_dir_all(candidate.join("self-publish")).unwrap();

    let output = command()
        .arg("self-publish-check")
        .arg(&candidate)
        .arg(fixture())
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(
        error.contains("the self-publishing state is only ever added"),
        "{error}"
    );
}

#[test]
fn refuses_an_extra_file_in_the_self_publish_directory() {
    let temporary = TemporaryDirectory::new("pkgre-self-publish-extra");
    let candidate = temporary.path().join("candidate");
    copy_tree(&fixture(), &candidate);
    fs::write(candidate.join("self-publish/notes.txt"), "not state\n").unwrap();

    let output = command()
        .arg("self-publish-check")
        .arg(&candidate)
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(error.contains("must hold exactly"), "{error}");
}

#[cfg(unix)]
#[test]
fn refuses_a_symbolic_link_in_the_self_publish_directory() {
    let temporary = TemporaryDirectory::new("pkgre-self-publish-symlink");
    let candidate = temporary.path().join("candidate");
    copy_tree(&fixture(), &candidate);
    let config = candidate.join("self-publish/crates-io.toml");
    fs::remove_file(&config).unwrap();
    symlink("crates-io.lock", &config).unwrap();

    let output = command()
        .arg("self-publish-check")
        .arg(&candidate)
        .output()
        .expect("the pkgre-rust binary runs");
    let error = stderr(&output);
    assert!(!output.status.success(), "{error}");
    assert!(error.contains("is not a regular file"), "{error}");
}
