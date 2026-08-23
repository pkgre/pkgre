//! Deterministic schema-v3 renderer integration test across two registries and nine categories.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_indexer::artifact::{ArtifactMap, sha256_bytes};
use pkgre_indexer::category::CategoryId;
use pkgre_indexer::index::{IndexRecord, index_path};
use pkgre_indexer::render;
use pkgre_indexer::schema::{
    Catalog, LockedName, LockedPackage, LockedRegistry, LockedSource, MIRROR_DOWNLOAD, NameSource,
    PUBLISH_DOWNLOAD, PackageHome, PackageState, RegistryLock, SCHEMA_VERSION, serialize_lock,
};
use semver::Version;
use serde_json::{Value, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const UNIVERSE_URL: &str = "sparse+https://rust.pkg.re/universe/";
const PKGRE_URL: &str = "sparse+https://rust.pkg.re/pkgre/";

#[test]
fn renderer_routes_categories_and_inline_external_layouts_identically() {
    let temporary = TemporaryDirectory::new("pkgre-render-e2e");
    let external_root = temporary.path().join("catalog-external");
    let external_artifacts = prepare_catalog(&external_root, true);
    let external_catalog = Catalog::load(&external_root).unwrap();
    let external_objects = ArtifactMap::load(&external_catalog).unwrap();
    let external_site = temporary.path().join("site-external");
    render::render(&external_catalog, &external_objects, &external_site).unwrap();
    render::verify(&external_catalog, &external_objects, &external_site).unwrap();
    render::verify_monotonic(&external_site, &external_site).unwrap();

    let inline_root = temporary.path().join("catalog-inline");
    prepare_catalog(&inline_root, false);
    let inline_catalog = Catalog::load(&inline_root).unwrap();
    let inline_objects = ArtifactMap::load(&inline_catalog).unwrap();
    let inline_site = temporary.path().join("site-inline");
    render::render(&inline_catalog, &inline_objects, &inline_site).unwrap();
    assert_eq!(snapshot(&external_site), snapshot(&inline_site));

    assert_dependency_registry(&external_site, "universe", "leaf-core", None);
    assert_dependency_registry(&external_site, "universe", "matrix-middle", None);
    assert_dependency_registry(&external_site, "pkgre", "pkgre-top", Some(UNIVERSE_URL));
    assert_eq!(
        fs::read_to_string(external_site.join("CNAME")).unwrap(),
        "rust.pkg.re\n"
    );
    assert!(external_site.join(".nojekyll").is_file());
    for (registry, expected) in [("universe", MIRROR_DOWNLOAD), ("pkgre", PUBLISH_DOWNLOAD)] {
        let config: Value = serde_json::from_slice(
            &fs::read(external_site.join(registry).join("config.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(config["dl"], expected);
    }
    for artifact in external_artifacts
        .iter()
        .filter(|artifact| artifact.registry == "universe")
    {
        assert!(
            !external_site
                .join("crates")
                .join(format!("{}.crate", artifact.archive_hash))
                .exists()
        );
    }
    let published = external_artifacts
        .iter()
        .find(|artifact| artifact.registry == "pkgre")
        .unwrap();
    assert_eq!(
        fs::read(
            external_site
                .join("crates")
                .join(format!("{}.crate", published.archive_hash))
        )
        .unwrap(),
        published.archive_bytes
    );

    fs::write(external_site.join("CNAME"), "tampered.example\n").unwrap();
    assert!(render::verify(&external_catalog, &external_objects, &external_site).is_err());
}

fn prepare_catalog(root: &Path, external_large_categories: bool) -> Vec<TestArtifact> {
    fs::create_dir(root).unwrap();
    write_human_files(root, external_large_categories);
    let artifacts = vec![
        add_artifact(root, "universe", "general", "leaf-core", None),
        add_artifact(
            root,
            "universe",
            "matrix",
            "matrix-middle",
            Some("leaf-core"),
        ),
        add_artifact(root, "pkgre", "tooling", "pkgre-top", Some("leaf-core")),
    ];
    write_locks(root, &artifacts);
    artifacts
}

struct TestArtifact {
    registry: &'static str,
    category: &'static str,
    name: &'static str,
    archive_hash: String,
    record_hash: String,
    record_bytes: Vec<u8>,
    archive_bytes: Vec<u8>,
}

fn add_artifact(
    root: &Path,
    registry: &'static str,
    category: &'static str,
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
        category,
        name,
        archive_hash,
        record_hash,
        record_bytes,
        archive_bytes,
    }
}

fn write_human_files(root: &Path, external_large_categories: bool) {
    let mut universe = String::from(
        "schema = 3\n\n[registry]\nname = \"universe\"\nindex = \"sparse+https://rust.pkg.re/universe/\"\ndownload = \"https://static.crates.io/crates\"\ncargo-version = \"1.95.0\"\n\n",
    );
    for (local, dependencies, package) in [
        (
            "acp",
            &["universe/acp", "universe/general"] as &[_],
            "reserved-acp",
        ),
        (
            "filesystem",
            &["universe/filesystem", "universe/general"] as &[_],
            "reserved-filesystem",
        ),
        (
            "mcp",
            &["universe/mcp", "universe/sse", "universe/general"] as &[_],
            "reserved-mcp",
        ),
        (
            "sse",
            &["universe/sse", "universe/general"] as &[_],
            "reserved-sse",
        ),
        (
            "terminal",
            &["universe/terminal", "universe/general"] as &[_],
            "reserved-terminal",
        ),
        (
            "yaml",
            &["universe/yaml", "universe/general"] as &[_],
            "reserved-yaml",
        ),
    ] {
        universe.push_str(&inline_mirror_category(
            local,
            dependencies,
            &[(package, &[])],
        ));
    }
    if external_large_categories {
        universe.push_str(
            "[categories.general]\nfile = \"categories/universe/general.toml\"\n\n[categories.matrix]\nfile = \"categories/universe/matrix.toml\"\n",
        );
        fs::create_dir_all(root.join("categories/universe")).unwrap();
        fs::write(
            root.join("categories/universe/general.toml"),
            external_mirror_category(
                &["universe/general"],
                &[("leaf-core", &["1.0.0"]), ("reserved-general", &[])],
            ),
        )
        .unwrap();
        fs::write(
            root.join("categories/universe/matrix.toml"),
            external_mirror_category(
                &["universe/matrix", "universe/general"],
                &[("matrix-middle", &["1.0.0"]), ("reserved-matrix", &[])],
            ),
        )
        .unwrap();
    } else {
        universe.push_str(&inline_mirror_category(
            "general",
            &["universe/general"],
            &[("leaf-core", &["1.0.0"]), ("reserved-general", &[])],
        ));
        universe.push_str(&inline_mirror_category(
            "matrix",
            &["universe/matrix", "universe/general"],
            &[("matrix-middle", &["1.0.0"]), ("reserved-matrix", &[])],
        ));
    }
    fs::write(root.join("universe.toml"), universe).unwrap();
    fs::write(
        root.join("pkgre.toml"),
        "schema = 3\n\n[registry]\nname = \"pkgre\"\nindex = \"sparse+https://rust.pkg.re/pkgre/\"\ndownload = \"https://rust.pkg.re/crates/{sha256-checksum}.crate\"\ncargo-version = \"1.95.0\"\n\n[categories.tooling]\nmay-depend-on = [\"pkgre/tooling\", \"universe/general\"]\n\n[categories.tooling.publish.pkgre-top]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"test/v1.0.0\"]\n",
    )
    .unwrap();
}

fn inline_mirror_category(
    local: &str,
    dependencies: &[&str],
    packages: &[(&str, &[&str])],
) -> String {
    format!(
        "[categories.{local}]\nmay-depend-on = [{}]\n\n[categories.{local}.mirror]\n{}\n",
        quoted(dependencies),
        package_lines(packages)
    )
}

fn external_mirror_category(dependencies: &[&str], packages: &[(&str, &[&str])]) -> String {
    format!(
        "schema = 3\nmay-depend-on = [{}]\n\n[mirror]\n{}",
        quoted(dependencies),
        package_lines(packages)
    )
}

fn quoted(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn package_lines(packages: &[(&str, &[&str])]) -> String {
    packages
        .iter()
        .map(|(name, versions)| format!("{name} = [{}]", quoted(versions)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_locks(root: &Path, artifacts: &[TestArtifact]) {
    let homes = package_homes();
    let registry_urls = BTreeMap::from([
        ("universe".to_owned(), UNIVERSE_URL.to_owned()),
        ("pkgre".to_owned(), PKGRE_URL.to_owned()),
    ]);
    for registry in ["pkgre", "universe"] {
        let names = homes
            .iter()
            .filter(|(_, home)| home.registry == registry)
            .map(|(name, home)| LockedName {
                name: name.clone(),
                category: home.category.local().to_owned(),
                source: if registry == "pkgre" {
                    NameSource::Publish
                } else {
                    NameSource::Mirror
                },
            })
            .collect();
        let packages = artifacts
            .iter()
            .filter(|artifact| artifact.registry == registry)
            .map(|artifact| LockedPackage {
                name: artifact.name.to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                state: PackageState::Active,
                crate_sha256: artifact.archive_hash.clone(),
                source_row_sha256: artifact.record_hash.clone(),
                index_row_sha256: routed_hash(artifact, &homes, &registry_urls),
                admission_sha256: None,
                source: if registry == "pkgre" {
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
                },
            })
            .collect();
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
            names,
            packages,
        };
        fs::write(
            root.join(format!("{registry}.lock")),
            serialize_lock(&lock).unwrap(),
        )
        .unwrap();
    }
}

fn package_homes() -> BTreeMap<String, PackageHome> {
    [
        ("leaf-core", "universe/general"),
        ("matrix-middle", "universe/matrix"),
        ("pkgre-top", "pkgre/tooling"),
        ("reserved-acp", "universe/acp"),
        ("reserved-filesystem", "universe/filesystem"),
        ("reserved-general", "universe/general"),
        ("reserved-matrix", "universe/matrix"),
        ("reserved-mcp", "universe/mcp"),
        ("reserved-sse", "universe/sse"),
        ("reserved-terminal", "universe/terminal"),
        ("reserved-yaml", "universe/yaml"),
    ]
    .into_iter()
    .map(|(name, category)| {
        let category: CategoryId = category.parse().unwrap();
        (
            name.to_owned(),
            PackageHome {
                registry: category.registry().to_owned(),
                category,
            },
        )
    })
    .collect()
}

fn routed_hash(
    artifact: &TestArtifact,
    homes: &BTreeMap<String, PackageHome>,
    registry_urls: &BTreeMap<String, String>,
) -> String {
    assert_eq!(homes[artifact.name].category.local(), artifact.category);
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
        .and_then(|dependency| dependency["registry"].as_str());
    assert_eq!(actual, expected);
    assert_eq!(row["yanked"], false);
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut snapshot = BTreeMap::new();
    snapshot_below(root, root, &mut snapshot);
    snapshot
}

fn snapshot_below(base: &Path, root: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
    let mut entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let relative = path.strip_prefix(base).unwrap().to_path_buf();
        if path.is_dir() {
            snapshot.insert(relative, None);
            snapshot_below(base, &path, snapshot);
        } else {
            snapshot.insert(relative, Some(fs::read(path).unwrap()));
        }
    }
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
