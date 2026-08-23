//! Deterministic schema-v2 renderer integration test across the three registry layers.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_indexer::artifact::{ArtifactMap, sha256_bytes};
use pkgre_indexer::index::{IndexRecord, index_path};
use pkgre_indexer::render;
use pkgre_indexer::schema::{
    Catalog, LockedName, LockedPackage, LockedRegistry, LockedSource, MIRROR_DOWNLOAD, NameSource,
    PUBLISH_DOWNLOAD, PackageState, RegistryLock, SCHEMA_VERSION, serialize_lock,
};
use semver::Version;
use serde_json::{Value, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn renderer_routes_dependencies_and_reproduces_exact_site() {
    let temporary = TemporaryDirectory::new("pkgre-render-e2e");
    let catalog_root = temporary.path().join("catalog");
    fs::create_dir(&catalog_root).unwrap();
    write_human_files(&catalog_root);

    let core = add_artifact(&catalog_root, "core", "leaf-core", None);
    let matrix = add_artifact(&catalog_root, "matrix", "matrix-middle", Some("leaf-core"));
    let pkgre = add_artifact(&catalog_root, "pkgre", "pkgre-top", Some("matrix-middle"));
    write_locks(&catalog_root, [&core, &matrix, &pkgre]);

    let catalog = Catalog::load(&catalog_root).unwrap();
    let artifacts = ArtifactMap::load(&catalog).unwrap();
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
    for (registry, expected) in [
        ("core", MIRROR_DOWNLOAD),
        ("matrix", MIRROR_DOWNLOAD),
        ("pkgre", PUBLISH_DOWNLOAD),
    ] {
        let config: Value =
            serde_json::from_slice(&fs::read(site.join(registry).join("config.json")).unwrap())
                .unwrap();
        assert_eq!(config["dl"], expected);
    }
    for artifact in [&core, &matrix] {
        assert!(
            !site
                .join("crates")
                .join(format!("{}.crate", artifact.archive_hash))
                .exists()
        );
    }
    assert_eq!(
        fs::read(
            site.join("crates")
                .join(format!("{}.crate", pkgre.archive_hash))
        )
        .unwrap(),
        pkgre.archive_bytes
    );

    fs::write(site.join("CNAME"), "tampered.example\n").unwrap();
    assert!(render::verify(&catalog, &artifacts, &site).is_err());
}

struct TestArtifact {
    registry: &'static str,
    name: &'static str,
    archive_hash: String,
    record_hash: String,
    record_bytes: Vec<u8>,
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
    if registry == "pkgre" {
        write_file(
            &root
                .join("objects/crates")
                .join(format!("{archive_hash}.crate")),
            &archive_bytes,
        );
    } else {
        fs::create_dir_all(root.join("objects/crates")).unwrap();
    }
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
        "yanked": true,
    }))
    .unwrap();
    record_bytes.push(b'\n');
    let record_hash = sha256_bytes(&record_bytes);
    write_file(
        &root
            .join("objects/rows")
            .join(format!("{record_hash}.json")),
        &record_bytes,
    );
    TestArtifact {
        registry,
        name,
        archive_hash,
        record_hash,
        record_bytes,
        archive_bytes,
    }
}

fn write_human_files(root: &Path) {
    write_registry(
        root,
        "core",
        &["core"],
        "[mirror]\nleaf-core = [\"1.0.0\"]\n",
    );
    write_registry(
        root,
        "matrix",
        &["core", "matrix"],
        "[mirror]\nmatrix-middle = [\"1.0.0\"]\n",
    );
    write_registry(
        root,
        "pkgre",
        &["core", "matrix", "pkgre"],
        "[publish.pkgre-top]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"test/v1.0.0\"]\n",
    );
}

fn write_registry(root: &Path, name: &str, layers: &[&str], packages: &str) {
    let layers = layers
        .iter()
        .map(|layer| format!("\"{layer}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let download = if name == "pkgre" {
        PUBLISH_DOWNLOAD
    } else {
        MIRROR_DOWNLOAD
    };
    fs::write(
        root.join(format!("{name}.toml")),
        format!(
            "schema = 2\n\n[registry]\nname = {name:?}\nindex = \"sparse+https://rust.pkg.re/{name}/\"\ndownload = {download:?}\nmay-depend-on = [{layers}]\ncargo-version = \"1.95.0\"\n\n{packages}"
        ),
    )
    .unwrap();
}

fn write_locks<'a>(root: &Path, artifacts: impl IntoIterator<Item = &'a TestArtifact>) {
    let artifacts = artifacts
        .into_iter()
        .map(|artifact| (artifact.registry, artifact))
        .collect::<BTreeMap<_, _>>();
    let homes = BTreeMap::from([
        ("leaf-core".to_owned(), "core".to_owned()),
        ("matrix-middle".to_owned(), "matrix".to_owned()),
        ("pkgre-top".to_owned(), "pkgre".to_owned()),
    ]);
    let registry_urls = ["core", "matrix", "pkgre"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                format!("sparse+https://rust.pkg.re/{name}/"),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (registry, artifact) in artifacts {
        let source = if registry == "pkgre" {
            LockedSource::GitTag {
                git: "https://github.com/pkgre/pkgre".to_owned(),
                tag: "test/v1.0.0".to_owned(),
                tag_oid: "01".repeat(20),
                commit: "02".repeat(20),
                package: artifact.name.to_owned(),
                path: PathBuf::from("."),
                cargo_version: Version::parse("1.95.0").unwrap(),
            }
        } else {
            LockedSource::CratesIo {}
        };
        let source_class = if registry == "pkgre" {
            NameSource::Publish
        } else {
            NameSource::Mirror
        };
        let lock = RegistryLock {
            schema: SCHEMA_VERSION,
            registry: LockedRegistry {
                name: registry.to_owned(),
                index: registry_urls[registry].clone(),
                download: if registry == "pkgre" {
                    PUBLISH_DOWNLOAD.to_owned()
                } else {
                    MIRROR_DOWNLOAD.to_owned()
                },
            },
            names: vec![LockedName {
                name: artifact.name.to_owned(),
                source: source_class,
            }],
            packages: vec![LockedPackage {
                name: artifact.name.to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                state: PackageState::Active,
                crate_sha256: artifact.archive_hash.clone(),
                source_row_sha256: artifact.record_hash.clone(),
                index_row_sha256: routed_hash(artifact, &homes, &registry_urls),
                source,
            }],
        };
        fs::write(
            root.join(format!("{registry}.lock")),
            serialize_lock(&lock).unwrap(),
        )
        .unwrap();
    }
}

fn routed_hash(
    artifact: &TestArtifact,
    homes: &BTreeMap<String, String>,
    registry_urls: &BTreeMap<String, String>,
) -> String {
    let mut record = IndexRecord::parse(&artifact.record_bytes).unwrap();
    record.set_yanked(false);
    record
        .route_dependencies(artifact.registry, homes, registry_urls)
        .unwrap();
    sha256_bytes(&record.to_json_line().unwrap())
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
    assert_eq!(row["yanked"], false);
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
