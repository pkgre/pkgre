//! Offline evidence for archive inventory, archive import, and accepted-to-candidate transitions.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_rust::archive::{ARCHIVE_INVENTORY_FILE, ArchiveInventory, archive_import};
use pkgre_rust::download::DownloadCatalog;
use pkgre_rust::migrate::migrate_v4_to_v5;
use pkgre_rust::schema::Catalog;
use pkgre_rust::transition::{RejectReason, check_transition};

const FIXTURE_SHA256: &str = "9c70bcffb58b92003f9c950656953b51844aeaa1d86183b86415f09da334f2fa";
const FIXTURE: &[u8] = include_bytes!("fixtures/rust-current-catalog-f9b5ffa.tar.gz");
const GIT_TAG_TIMES: [(&str, &str); 3] = [
    ("main/pkgre-indexer@indexer/v0.1.1", "2026-08-22T17:57:02Z"),
    ("main/pkgre-indexer@indexer/v0.2.0", "2026-08-22T22:38:36Z"),
    ("main/pkgre-indexer@indexer/v0.3.0", "2026-08-24T02:26:23Z"),
];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Migrates the frozen v4 fixture into a fresh v5 catalog with retained bodies present.
fn migrated_catalog(parent: &Path, label: &str) -> PathBuf {
    let extraction = parent.join(format!("{label}-extracted"));
    extract_fixture(FIXTURE, &extraction);
    let input = extraction.join("registry");
    let output = parent.join(label);
    let git_times = GIT_TAG_TIMES
        .iter()
        .map(|(key, time)| ((*key).to_owned(), (*time).to_owned()))
        .collect::<Vec<_>>();
    migrate_v4_to_v5(&input, &output, &git_times).unwrap();
    output
}

#[test]
fn archive_inventory_lists_and_import_restores_retained_bodies() {
    assert_eq!(
        pkgre_rust::artifact::sha256_bytes(FIXTURE),
        FIXTURE_SHA256,
        "frozen schema-4 catalog fixture must remain unchanged"
    );

    let temporary = TemporaryDirectory::new("pkgre-rust-archive");
    let catalog_path = migrated_catalog(temporary.path(), "catalog");

    // The migrated catalog already retains every body.
    let catalog = Catalog::load(&catalog_path).unwrap();
    let downloads = DownloadCatalog::load_from_root(&catalog_path).unwrap();
    let inventory = ArchiveInventory::from_catalog(&catalog, &downloads);
    assert_eq!(inventory.objects.len(), 3);
    assert_eq!(inventory.schema, 1);
    assert_eq!(inventory.catalog, "main");
    let first = &inventory.objects[0];
    assert_eq!(first.identity, "main/pkgre-indexer/0.1.1");
    assert_eq!(first.sha256.len(), 64);

    let store = temporary.path().join("store");
    fs::create_dir(&store).unwrap();
    let bytes = inventory.canonical_bytes().unwrap();
    assert_eq!(
        ArchiveInventory::parse_canonical(&bytes).unwrap(),
        inventory,
        "inventory canonical bytes must round-trip exactly"
    );
    fs::write(store.join(ARCHIVE_INVENTORY_FILE), &bytes).unwrap();
    for object in &inventory.objects {
        fs::write(
            store.join(format!("{}.crate", object.sha256)),
            fs::read(
                catalog_path
                    .join("objects/crates")
                    .join(format!("{}.crate", object.sha256)),
            )
            .unwrap(),
        )
        .unwrap();
    }

    // Import into the complete catalog is a verified no-op.
    let summary = archive_import(&store, &catalog_path).unwrap();
    assert_eq!(
        (summary.imported, summary.already_present),
        (0, 3),
        "complete catalog must import nothing"
    );

    // Import into a copy missing every retained body restores them byte-for-byte.
    let restored = copy_tree(&catalog_path, &temporary.path().join("restored"));
    for object in &inventory.objects {
        fs::remove_file(
            restored
                .join("objects/crates")
                .join(format!("{}.crate", object.sha256)),
        )
        .unwrap();
    }
    let summary = archive_import(&store, &restored).unwrap();
    assert_eq!(
        (summary.imported, summary.already_present),
        (3, 0),
        "stripped catalog must import every retained body"
    );
    assert!(trees_equal(&catalog_path, &restored));
    let summary = archive_import(&store, &restored).unwrap();
    assert_eq!((summary.imported, summary.already_present), (0, 3));
    let _ = summary;

    // A corrupted store object must be rejected without writing.
    let corrupted = copy_tree(&catalog_path, &temporary.path().join("corrupted"));
    for object in &inventory.objects {
        fs::remove_file(
            corrupted
                .join("objects/crates")
                .join(format!("{}.crate", object.sha256)),
        )
        .unwrap();
    }
    let bad_store = temporary.path().join("bad-store");
    fs::create_dir(&bad_store).unwrap();
    fs::write(bad_store.join(ARCHIVE_INVENTORY_FILE), &bytes).unwrap();
    for object in &inventory.objects {
        fs::write(
            bad_store.join(format!("{}.crate", object.sha256)),
            b"tampered bytes",
        )
        .unwrap();
    }
    let error = archive_import(&bad_store, &corrupted).unwrap_err();
    assert!(
        format!("{error:#}").contains("does not match its digest"),
        "tampered store object must fail hash verification, got: {error:#}"
    );
}

#[test]
fn check_transition_accepts_identity_and_rejects_mutations() {
    let temporary = TemporaryDirectory::new("pkgre-rust-transition");
    let accepted = migrated_catalog(temporary.path(), "accepted");

    // Identical trees are a valid transition.
    let identical = copy_tree(&accepted, &temporary.path().join("identical"));
    check_transition(&accepted, &identical).unwrap();

    // A fresh candidate adding one mirror identity while preserving everything else is valid.
    let candidate = copy_tree(&accepted, &temporary.path().join("candidate"));
    check_transition(&accepted, &candidate).unwrap();

    // Deleting a retained body must be rejected.
    let missing_body = copy_tree(&accepted, &temporary.path().join("missing-body"));
    let first_object = fs::read_dir(missing_body.join("objects/crates"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    fs::remove_file(missing_body.join("objects/crates").join(&first_object)).unwrap();
    let reason = check_transition(&accepted, &missing_body).unwrap_err();
    let detail = match &reason {
        RejectReason::MissingRetainedBody(detail) => detail.clone(),
        other => panic!("expected MissingRetainedBody, got {other:?}"),
    };
    let object_name = first_object.to_string_lossy().into_owned();
    assert!(
        detail.contains("inspect retained body") && detail.contains(&object_name),
        "missing retained body must be rejected with the object path, got: {detail}"
    );

    // Tampering a retained body must be rejected.
    let tampered_body = copy_tree(&accepted, &temporary.path().join("tampered-body"));
    let object = fs::read_dir(tampered_body.join("objects/crates"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let object_path = tampered_body.join("objects/crates").join(&object);
    fs::write(&object_path, b"tampered body").unwrap();
    let reason = check_transition(&accepted, &tampered_body).unwrap_err();
    let detail = match &reason {
        RejectReason::MissingRetainedBody(detail) => detail.clone(),
        other => panic!("expected MissingRetainedBody, got {other:?}"),
    };
    assert!(
        detail.contains("retained body hash mismatch for pkgre-indexer"),
        "tampered retained body must be rejected with a hash mismatch, got: {detail}"
    );

    // Removing a whole identity from a lock must be rejected (mutation check via lock rewrite
    // is enforced by byte-canonical load, so a truncated lock fails load and is rejected too).
    let removed_identity = copy_tree(&accepted, &temporary.path().join("removed-identity"));
    let lock_path = removed_identity.join("main.lock");
    let lock_text = fs::read_to_string(&lock_path).unwrap();
    let start = lock_text
        .find("[[packages]]\nname = \"pkgre-indexer\"\nversion = \"0.1.1\"")
        .unwrap_or_else(|| panic!("identity block not found"));
    let mut truncated = String::new();
    truncated.push_str(&lock_text[..start]);
    fs::write(&lock_path, truncated).unwrap();
    let reason = check_transition(&accepted, &removed_identity).unwrap_err();
    assert!(
        matches!(reason, RejectReason::MissingRetainedBody(_)),
        "truncated lock must be rejected, got {reason:?}"
    );

    // Changing the serving audience is a topology change.
    let audience = copy_tree(&accepted, &temporary.path().join("audience"));
    let human = audience.join("main.toml");
    let text = fs::read_to_string(&human).unwrap();
    fs::write(
        &human,
        text.replace("audience = \"public\"", "audience = \"lan-public\""),
    )
    .unwrap();
    let lock = audience.join("main.lock");
    let lock_text = fs::read_to_string(&lock).unwrap();
    fs::write(
        &lock,
        lock_text.replace("audience = \"public\"", "audience = \"lan-public\""),
    )
    .unwrap();
    let reason = check_transition(&accepted, &audience).unwrap_err();
    assert_eq!(
        reason,
        RejectReason::RegistryTopology(
            "registry \"main\" audience Public became LanPublic".to_owned()
        )
    );
}

fn extract_fixture(fixture: &[u8], destination: &Path) {
    let temporary = TemporaryDirectory::new("pkgre-rust-archive-extract");
    let archive = temporary.path().join("catalog.tar.gz");
    fs::write(&archive, fixture).unwrap();
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
}

fn copy_tree(source: &Path, destination: &Path) -> PathBuf {
    fs::create_dir_all(destination).unwrap();
    let status = Command::new("cp")
        .arg("--recursive")
        .arg(source.join("."))
        .arg(destination)
        .status()
        .unwrap();
    assert!(status.success());
    destination.to_path_buf()
}

fn trees_equal(left: &Path, right: &Path) -> bool {
    fn walk(left: &Path, right: &Path) -> Option<bool> {
        let left_entries = fs::read_dir(left).ok()?;
        let mut left_names = left_entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        left_names.sort();
        let right_entries = fs::read_dir(right).ok()?;
        let mut right_names = right_entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        right_names.sort();
        if left_names != right_names {
            return Some(false);
        }
        for name in left_names {
            let left_child = left.join(&name);
            let right_child = right.join(&name);
            if left_child.is_dir() {
                walk(&left_child, &right_child)?;
            } else if fs::read(&left_child).ok()? != fs::read(&right_child).ok()? {
                return Some(false);
            }
        }
        Some(true)
    }
    walk(left, right).unwrap_or(false)
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Self {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
