//! Offline evidence for the frozen production Rust catalog projection.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_rust::artifact::{ArtifactMap, sha256_bytes};
use pkgre_rust::projection::{CatalogProjection, ProjectedResponseKind};
use pkgre_rust::render;
use pkgre_rust::schema::{Catalog, Source};

const SOURCE_COMMIT: &str = "f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b";
const SOURCE_TREE: &str = "35cbdb0e7622506461ad0d4340e3c1f40f594526";
const FIXTURE_SHA256: &str = "9c70bcffb58b92003f9c950656953b51844aeaa1d86183b86415f09da334f2fa";
const FIXTURE: &[u8] = include_bytes!("fixtures/rust-current-catalog-f9b5ffa.tar.gz");
const EXPECTED_PROJECTION: &[u8] = include_bytes!("fixtures/rust-current-projection-f9b5ffa.json");
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn frozen_current_catalog_projects_exactly_and_matches_static_rendering() {
    assert_eq!(FIXTURE.len(), 621_318);
    assert_eq!(
        sha256_bytes(FIXTURE),
        FIXTURE_SHA256,
        "fixture must remain the registry tree {SOURCE_TREE} from commit {SOURCE_COMMIT}"
    );

    let temporary = TemporaryDirectory::new("pkgre-rust-current-projection");
    let archive = temporary.path().join("catalog.tar.gz");
    let extraction = temporary.path().join("extracted");
    fs::write(&archive, FIXTURE).unwrap();
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

    let root = extraction.join("registry");
    let (source_files, source_bytes) = regular_file_tree_stats(&root);
    assert_eq!((source_files, source_bytes), (757, 1_935_385));

    let catalog = Catalog::load(&root).unwrap();
    let artifacts = ArtifactMap::load(&catalog).unwrap();
    let active = catalog
        .approvals
        .iter()
        .filter(|approval| !approval.is_removed())
        .count();
    let crates_io = catalog
        .approvals
        .iter()
        .filter(|approval| !approval.is_removed() && matches!(approval.source, Source::CratesIo))
        .count();
    let git_tags = catalog
        .approvals
        .iter()
        .filter(|approval| {
            !approval.is_removed() && matches!(approval.source, Source::GitTag { .. })
        })
        .count();
    assert_eq!((active, crates_io, git_tags), (747, 744, 3));

    let projection = CatalogProjection::from_catalog(&catalog, &artifacts).unwrap();
    assert!(
        projection
            .routes()
            .windows(2)
            .all(|pair| pair[0].path().as_bytes() < pair[1].path().as_bytes())
    );
    let inline = count_kind(&projection, ProjectedResponseKind::Inline);
    let redirects = count_kind(&projection, ProjectedResponseKind::Redirect);
    let archives = count_kind(&projection, ProjectedResponseKind::Archive);
    assert_eq!(projection.routes().len(), 1_308);
    assert_eq!((inline, redirects, archives), (558, 747, 3));
    assert_eq!(projection.routes().first().unwrap().path(), "/2/cc");
    assert_eq!(projection.routes().last().unwrap().path(), "/zm/ij/zmij");

    let inline_bytes = retained_bytes(&projection, ProjectedResponseKind::Inline);
    let archive_bytes = retained_bytes(&projection, ProjectedResponseKind::Archive);
    assert_eq!((inline_bytes, archive_bytes), (1_899_988, 229_784));
    assert_eq!(projection.retained_body_bytes(), 2_129_772);

    let site = temporary.path().join("site");
    render::render(&catalog, &artifacts, &site).unwrap();
    render::verify(&catalog, &artifacts, &site).unwrap();
    for route in projection.routes() {
        let rendered = site.join(route.path().strip_prefix('/').unwrap());
        match route.response().kind() {
            ProjectedResponseKind::Inline | ProjectedResponseKind::Archive => {
                assert_eq!(
                    fs::read(&rendered).unwrap(),
                    route.response().body().unwrap(),
                    "static render differs at {}",
                    route.path()
                );
            }
            ProjectedResponseKind::Redirect => assert!(!rendered.exists()),
        }
    }

    let manifest = projection.manifest_bytes().unwrap();
    assert_eq!(manifest, EXPECTED_PROJECTION);
    assert_eq!(EXPECTED_PROJECTION.len(), 409_897);
    assert_eq!(
        sha256_bytes(EXPECTED_PROJECTION),
        "388383ddfab16101c90631c28fa95b19bcc0a5abd4efcee0660770be5e7a690e",
        "update only after independently reviewing an intentional projection change"
    );
}

fn count_kind(projection: &CatalogProjection, kind: ProjectedResponseKind) -> usize {
    projection
        .routes()
        .iter()
        .filter(|route| route.response().kind() == kind)
        .count()
}

fn retained_bytes(projection: &CatalogProjection, kind: ProjectedResponseKind) -> u64 {
    projection
        .routes()
        .iter()
        .filter(|route| route.response().kind() == kind)
        .map(|route| u64::try_from(route.response().body().unwrap().len()).unwrap())
        .sum()
}

fn regular_file_tree_stats(root: &Path) -> (usize, u64) {
    let mut files = 0;
    let mut bytes = 0;
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                assert!(metadata.is_file(), "fixture contains a non-regular entry");
                files += 1;
                bytes += metadata.len();
            }
        }
    }
    (files, bytes)
}

#[derive(Debug)]
struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{label}-{}-{sequence}", std::process::id()));
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
