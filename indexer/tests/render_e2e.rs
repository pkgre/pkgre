//! Deterministic renderer integration test across the three registry layers.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_indexer::artifact::{ArtifactMap, sha256_bytes};
use pkgre_indexer::index::index_path;
use pkgre_indexer::render;
use pkgre_indexer::schema::Catalog;
use serde_json::{Value, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn renderer_routes_dependencies_and_reproduces_exact_site() {
    let temporary = TemporaryDirectory::new("pkgre-render-e2e");
    let catalog_root = temporary.path().join("catalog");
    fs::create_dir_all(catalog_root.join("approvals")).unwrap();
    fs::write(
        catalog_root.join("registries.toml"),
        "schema = 1\ncname = \"rust.pkg.re\"\ndownload = \"https://rust.pkg.re/crates/{sha256-checksum}.crate\"\ncargo-version = \"1.95.0\"\n\n[[registries]]\nname = \"core\"\nindex = \"sparse+https://rust.pkg.re/core/\"\nmay-depend-on = [\"core\"]\n\n[[registries]]\nname = \"matrix\"\nindex = \"sparse+https://rust.pkg.re/matrix/\"\nmay-depend-on = [\"core\", \"matrix\"]\n\n[[registries]]\nname = \"pkgre\"\nindex = \"sparse+https://rust.pkg.re/pkgre/\"\nmay-depend-on = [\"core\", \"matrix\", \"pkgre\"]\n",
    )
    .unwrap();
    fs::write(
        catalog_root.join("homes.toml"),
        "schema = 1\n\n[homes]\nleaf-core = \"core\"\nmatrix-middle = \"matrix\"\npkgre-top = \"pkgre\"\n",
    )
    .unwrap();

    let core = add_artifact(&catalog_root, "core", "leaf-core", None);
    let matrix = add_artifact(&catalog_root, "matrix", "matrix-middle", Some("leaf-core"));
    let pkgre = add_artifact(&catalog_root, "pkgre", "pkgre-top", Some("matrix-middle"));
    write_approvals(&catalog_root, &core, &matrix, &pkgre);
    write_artifact_map(&catalog_root, [&core, &matrix, &pkgre]);

    let catalog = Catalog::load(&catalog_root).unwrap();
    let artifacts = ArtifactMap::load(catalog_root.join("artifacts.toml")).unwrap();
    let site = temporary.path().join("site");
    render::render(&catalog, &artifacts, &site).unwrap();
    render::verify(&catalog, &artifacts, &site).unwrap();
    render::verify_monotonic(&site, &site).unwrap();

    assert_dependency_registry(&site, "core", "leaf-core", None);
    assert_dependency_registry(
        &site,
        "matrix",
        "matrix-middle",
        Some("sparse+https://rust.pkg.re/core/"),
    );
    assert_dependency_registry(
        &site,
        "pkgre",
        "pkgre-top",
        Some("sparse+https://rust.pkg.re/matrix/"),
    );
    assert_eq!(
        fs::read_to_string(site.join("CNAME")).unwrap(),
        "rust.pkg.re\n"
    );
    assert!(site.join(".nojekyll").is_file());
    for artifact in [&core, &matrix, &pkgre] {
        assert_eq!(
            fs::read(
                site.join("crates")
                    .join(format!("{}.crate", artifact.archive_hash))
            )
            .unwrap(),
            artifact.archive_bytes
        );
    }

    fs::write(site.join("CNAME"), "tampered.example\n").unwrap();
    assert!(render::verify(&catalog, &artifacts, &site).is_err());
}

struct TestArtifact {
    registry: &'static str,
    name: &'static str,
    archive_hash: String,
    record_hash: String,
    archive_path: PathBuf,
    record_path: PathBuf,
    archive_bytes: Vec<u8>,
}

fn add_artifact(
    root: &Path,
    registry: &'static str,
    name: &'static str,
    dependency: Option<&str>,
) -> TestArtifact {
    let archive_bytes = format!("synthetic archive for {name} 1.0.0\n").into_bytes();
    let archive_hash = sha256_bytes(&archive_bytes);
    let archive_path = PathBuf::from("archives").join(format!("{archive_hash}.crate"));
    write_file(&root.join(&archive_path), &archive_bytes);
    let dependencies = dependency.map_or_else(Vec::new, |dependency| {
        vec![json!({
            "name": dependency,
            "req": "^1",
            "features": [],
            "optional": false,
            "default_features": true,
            "target": Value::Null,
            "kind": "normal",
            "registry": "untrusted-upstream-value",
            "package": Value::Null,
        })]
    });
    let mut record_bytes = serde_json::to_vec(&json!({
        "name": name,
        "vers": "1.0.0",
        "deps": dependencies,
        "cksum": archive_hash,
        "features": {},
        "yanked": false,
    }))
    .unwrap();
    record_bytes.push(b'\n');
    let record_hash = sha256_bytes(&record_bytes);
    let record_path = if registry == "pkgre" {
        PathBuf::from("records").join(format!("{record_hash}.json"))
    } else {
        PathBuf::from("upstream")
            .join(registry)
            .join(index_path(name))
            .join("1.0.0.json")
    };
    write_file(&root.join(&record_path), &record_bytes);
    TestArtifact {
        registry,
        name,
        archive_hash,
        record_hash,
        archive_path,
        record_path,
        archive_bytes,
    }
}

fn write_approvals(root: &Path, core: &TestArtifact, matrix: &TestArtifact, pkgre: &TestArtifact) {
    for artifact in [core, matrix] {
        fs::write(
            root.join("approvals")
                .join(format!("{}.toml", artifact.registry)),
            format!(
                "schema = 1\nregistry = {:?}\n\n[[packages]]\nname = {:?}\nversion = \"1.0.0\"\narchive_sha256 = {:?}\nindex_record_sha256 = {:?}\nyanked = false\n\n[packages.source]\nkind = \"crates-io\"\nindex_record = {:?}\n",
                artifact.registry,
                artifact.name,
                artifact.archive_hash,
                artifact.record_hash,
                artifact.record_path.to_string_lossy()
            ),
        )
        .unwrap();
    }
    fs::write(
        root.join("approvals/pkgre.toml"),
        format!(
            "schema = 1\nregistry = \"pkgre\"\n\n[[packages]]\nname = {:?}\nversion = \"1.0.0\"\narchive_sha256 = {:?}\nindex_record_sha256 = {:?}\nyanked = false\n\n[packages.source]\nkind = \"git-tag\"\nrepository = \"https://github.com/pkgre/pkgre\"\ntag = \"test/v1.0.0\"\ncommit = \"{}\"\npackage = {:?}\nsubdir = \".\"\n",
            pkgre.name,
            pkgre.archive_hash,
            pkgre.record_hash,
            "01".repeat(20),
            pkgre.name
        ),
    )
    .unwrap();
}

fn write_artifact_map<'a>(root: &Path, artifacts: impl IntoIterator<Item = &'a TestArtifact>) {
    let mut contents = String::from("schema = 1\n");
    for artifact in artifacts {
        write!(
            contents,
            "\n[[artifacts]]\nregistry = {:?}\nname = {:?}\nversion = \"1.0.0\"\narchive = {:?}\nindex_record = {:?}\n",
            artifact.registry,
            artifact.name,
            artifact.archive_path.to_string_lossy(),
            artifact.record_path.to_string_lossy()
        )
        .unwrap();
    }
    fs::write(root.join("artifacts.toml"), contents).unwrap();
}

fn assert_dependency_registry(site: &Path, registry: &str, name: &str, expected: Option<&str>) {
    let bytes = fs::read(site.join(registry).join(index_path(name))).unwrap();
    let row: Value = serde_json::from_slice(&bytes).unwrap();
    let actual = row["deps"]
        .as_array()
        .unwrap()
        .first()
        .map(|dependency| dependency["registry"].as_str().unwrap());
    assert_eq!(actual, expected);
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
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
        fs::remove_dir_all(&self.path).unwrap();
    }
}
