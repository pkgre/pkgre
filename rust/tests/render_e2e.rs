//! Deterministic schema-v4 renderer integration test for a mixed-source root registry.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_indexer::artifact::{ArtifactMap, sha256_bytes};
use pkgre_indexer::category::CategoryId;
use pkgre_indexer::download::{
    DOWNLOAD_CATALOG_FILE, DOWNLOAD_CATALOG_SCHEMA, DownloadCatalog, DownloadRoute, DownloadSource,
    router_download_template,
};
use pkgre_indexer::index::{IndexRecord, index_path};
use pkgre_indexer::render;
use pkgre_indexer::schema::{
    Catalog, LockedName, LockedPackage, LockedRegistry, LockedSource, PackageHome, PackageState,
    RegistryLock, SCHEMA_VERSION, serialize_lock,
};
use semver::Version;
use serde_json::{Value, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAIN_URL: &str = "sparse+https://rust.pkg.re/";

#[test]
fn renderer_routes_mixed_sources_at_root_and_layouts_identically() {
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

    assert_dependency_registry(&external_site, "leaf-core", None);
    assert_dependency_registry(&external_site, "matrix-middle", None);
    assert_dependency_registry(&external_site, "pkgre-top", None);
    assert_eq!(
        fs::read_to_string(external_site.join("CNAME")).unwrap(),
        "rust.pkg.re\n"
    );
    assert!(external_site.join(".nojekyll").is_file());
    let config: Value =
        serde_json::from_slice(&fs::read(external_site.join("config.json")).unwrap()).unwrap();
    assert_eq!(config["dl"], router_download_template("main"));
    assert!(!external_site.join("main/config.json").exists());

    for artifact in external_artifacts
        .iter()
        .filter(|artifact| artifact.source == TestSource::Mirror)
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
        .find(|artifact| artifact.source == TestSource::Publish)
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

#[test]
fn renderer_keeps_main_at_root_and_future_registry_below_its_alias() {
    let temporary = TemporaryDirectory::new("pkgre-render-multi-registry");
    let root = temporary.path().join("catalog");
    prepare_catalog(&root, false);
    add_future_registry(&root);

    let catalog = Catalog::load(&root).unwrap();
    let artifacts = ArtifactMap::load(&catalog).unwrap();
    let site = temporary.path().join("site");
    render::render(&catalog, &artifacts, &site).unwrap();
    render::verify(&catalog, &artifacts, &site).unwrap();

    assert!(site.join("config.json").is_file());
    assert!(!site.join("main/config.json").exists());
    assert!(site.join(index_path("leaf-core")).is_file());
    assert!(site.join("staging/config.json").is_file());
    assert!(
        site.join("staging")
            .join(index_path("future-crate"))
            .is_file()
    );
    assert!(!site.join(index_path("future-crate")).exists());
    assert!(!site.join("staging").join(index_path("leaf-core")).exists());
}
fn prepare_catalog(root: &Path, external_large_categories: bool) -> Vec<TestArtifact> {
    fs::create_dir(root).unwrap();
    write_human_files(root, external_large_categories);
    let artifacts = vec![
        add_artifact(root, "general", "leaf-core", None, TestSource::Mirror),
        add_artifact(
            root,
            "matrix",
            "matrix-middle",
            Some("leaf-core"),
            TestSource::Mirror,
        ),
        add_artifact(
            root,
            "pkgre",
            "pkgre-top",
            Some("leaf-core"),
            TestSource::Publish,
        ),
    ];
    write_lock(root, &artifacts);
    write_downloads(root, &artifacts);
    artifacts
}

fn add_future_registry(root: &Path) {
    const NAME: &str = "future-crate";
    let archive_hash = sha256_bytes(b"future crate archive\n");
    let mut source_row = serde_json::to_vec(&json!({
        "name": NAME,
        "vers": "1.0.0",
        "deps": [],
        "cksum": archive_hash,
        "features": {},
        "yanked": true,
    }))
    .unwrap();
    source_row.push(b'\n');
    let source_row_hash = sha256_bytes(&source_row);
    write_file(
        &root
            .join("objects/rows")
            .join(format!("{source_row_hash}.json")),
        &source_row,
    );
    let mut routed = IndexRecord::parse(&source_row).unwrap();
    routed.set_yanked(false);
    routed
        .route_dependencies(
            "staging",
            &BTreeMap::new(),
            &BTreeMap::from([
                ("main".to_owned(), MAIN_URL.to_owned()),
                (
                    "staging".to_owned(),
                    "sparse+https://rust.pkg.re/staging/".to_owned(),
                ),
            ]),
        )
        .unwrap();
    let index_row_hash = sha256_bytes(&routed.to_json_line().unwrap());

    fs::write(
        root.join("staging.toml"),
        format!(
            "schema = 4\n\n[registry]\nname = \"staging\"\nindex = \"sparse+https://rust.pkg.re/staging/\"\ndownload = {:?}\ncargo-version = \"1.95.0\"\n\n[categories.experimental]\nmay-depend-on = [\"staging/experimental\"]\n\n[categories.experimental.mirror]\nfuture-crate = [\"1.0.0\"]\n",
            router_download_template("staging")
        ),
    )
    .unwrap();
    let lock = RegistryLock {
        schema: SCHEMA_VERSION,
        registry: LockedRegistry {
            name: "staging".to_owned(),
            index: "sparse+https://rust.pkg.re/staging/".to_owned(),
            download: router_download_template("staging"),
        },
        names: vec![LockedName {
            name: NAME.to_owned(),
            category: "experimental".to_owned(),
        }],
        packages: vec![LockedPackage {
            name: NAME.to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            state: PackageState::Active,
            crate_sha256: archive_hash.clone(),
            source_row_sha256: source_row_hash,
            index_row_sha256: index_row_hash,
            admission_sha256: None,
            source: LockedSource::CratesIo {},
        }],
    };
    fs::write(root.join("staging.lock"), serialize_lock(&lock).unwrap()).unwrap();

    let mut downloads = DownloadCatalog::load_from_root(root).unwrap();
    downloads.routes.push(DownloadRoute {
        registry: "staging".to_owned(),
        name: NAME.to_owned(),
        version: Version::parse("1.0.0").unwrap(),
        sha256: archive_hash,
        source: DownloadSource::CratesIo,
    });
    fs::write(
        root.join(DOWNLOAD_CATALOG_FILE),
        downloads.canonical_bytes().unwrap(),
    )
    .unwrap();
}
fn write_downloads(root: &Path, artifacts: &[TestArtifact]) {
    let routes = artifacts
        .iter()
        .map(|artifact| DownloadRoute {
            registry: "main".to_owned(),
            name: artifact.name.to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            sha256: artifact.archive_hash.clone(),
            source: match artifact.source {
                TestSource::Mirror => DownloadSource::CratesIo,
                TestSource::Publish => DownloadSource::GitTag,
            },
        })
        .collect();
    let downloads = DownloadCatalog {
        schema: DOWNLOAD_CATALOG_SCHEMA,
        routes,
    };
    fs::write(
        root.join(DOWNLOAD_CATALOG_FILE),
        downloads.canonical_bytes().unwrap(),
    )
    .unwrap();
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TestSource {
    Mirror,
    Publish,
}

struct TestArtifact {
    category: &'static str,
    name: &'static str,
    source: TestSource,
    archive_hash: String,
    record_hash: String,
    record_bytes: Vec<u8>,
    archive_bytes: Vec<u8>,
}

fn add_artifact(
    root: &Path,
    category: &'static str,
    name: &'static str,
    dependency: Option<&str>,
    source: TestSource,
) -> TestArtifact {
    let archive_bytes = format!("synthetic archive for {name} 1.0.0\n").into_bytes();
    let archive_hash = sha256_bytes(&archive_bytes);
    if source == TestSource::Publish {
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
        category,
        name,
        source,
        archive_hash,
        record_hash,
        record_bytes,
        archive_bytes,
    }
}

fn write_human_files(root: &Path, external_large_categories: bool) {
    let mut main = format!(
        "schema = 4\n\n[registry]\nname = \"main\"\nindex = \"{MAIN_URL}\"\ndownload = {:?}\ncargo-version = \"1.95.0\"\n\n",
        router_download_template("main")
    );
    for (local, dependencies, package) in [
        ("acp", &["main/acp", "main/general"] as &[_], "reserved-acp"),
        (
            "filesystem",
            &["main/filesystem", "main/general"] as &[_],
            "reserved-filesystem",
        ),
        (
            "mcp",
            &["main/mcp", "main/sse", "main/general"] as &[_],
            "reserved-mcp",
        ),
        ("sse", &["main/sse", "main/general"] as &[_], "reserved-sse"),
        (
            "terminal",
            &["main/terminal", "main/general"] as &[_],
            "reserved-terminal",
        ),
        (
            "yaml",
            &["main/yaml", "main/general"] as &[_],
            "reserved-yaml",
        ),
    ] {
        main.push_str(&inline_mirror_category(
            local,
            dependencies,
            &[(package, &[])],
        ));
    }
    if external_large_categories {
        main.push_str(
            "[categories.general]\nfile = \"categories/main/general.toml\"\n\n[categories.matrix]\nfile = \"categories/main/matrix.toml\"\n\n",
        );
        fs::create_dir_all(root.join("categories/main")).unwrap();
        fs::write(
            root.join("categories/main/general.toml"),
            external_mirror_category(
                &["main/general"],
                &[("leaf-core", &["1.0.0"]), ("reserved-general", &[])],
            ),
        )
        .unwrap();
        fs::write(
            root.join("categories/main/matrix.toml"),
            external_mirror_category(
                &["main/matrix", "main/general"],
                &[("matrix-middle", &["1.0.0"]), ("reserved-matrix", &[])],
            ),
        )
        .unwrap();
    } else {
        main.push_str(&inline_mirror_category(
            "general",
            &["main/general"],
            &[("leaf-core", &["1.0.0"]), ("reserved-general", &[])],
        ));
        main.push_str(&inline_mirror_category(
            "matrix",
            &["main/matrix", "main/general"],
            &[("matrix-middle", &["1.0.0"]), ("reserved-matrix", &[])],
        ));
    }
    main.push_str(
        "[categories.pkgre]\nmay-depend-on = [\"main/pkgre\", \"main/general\"]\n\n[categories.pkgre.publish.pkgre-top]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"test/v1.0.0\"]\n",
    );
    fs::write(root.join("main.toml"), main).unwrap();
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
        "schema = 4\nmay-depend-on = [{}]\n\n[mirror]\n{}",
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

fn write_lock(root: &Path, artifacts: &[TestArtifact]) {
    let homes = package_homes();
    let registry_urls = BTreeMap::from([("main".to_owned(), MAIN_URL.to_owned())]);
    let names = homes
        .iter()
        .map(|(name, home)| LockedName {
            name: name.clone(),
            category: home.category.local().to_owned(),
        })
        .collect();
    let packages = artifacts
        .iter()
        .map(|artifact| LockedPackage {
            name: artifact.name.to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            state: PackageState::Active,
            crate_sha256: artifact.archive_hash.clone(),
            source_row_sha256: artifact.record_hash.clone(),
            index_row_sha256: routed_hash(artifact, &homes, &registry_urls),
            admission_sha256: None,
            source: match artifact.source {
                TestSource::Publish => LockedSource::GitTag {
                    git: "https://github.com/pkgre/pkgre".to_owned(),
                    tag: "test/v1.0.0".to_owned(),
                    tag_oid: "01".repeat(20),
                    commit: "02".repeat(20),
                    package: artifact.name.to_owned(),
                    path: PathBuf::from("."),
                    cargo_version: Version::parse("1.95.0").unwrap(),
                },
                TestSource::Mirror => LockedSource::CratesIo {},
            },
        })
        .collect();
    let lock = RegistryLock {
        schema: SCHEMA_VERSION,
        registry: LockedRegistry {
            name: "main".to_owned(),
            index: MAIN_URL.to_owned(),
            download: router_download_template("main"),
        },
        names,
        packages,
    };
    fs::write(root.join("main.lock"), serialize_lock(&lock).unwrap()).unwrap();
}

fn package_homes() -> BTreeMap<String, PackageHome> {
    [
        ("leaf-core", "main/general"),
        ("matrix-middle", "main/matrix"),
        ("pkgre-top", "main/pkgre"),
        ("reserved-acp", "main/acp"),
        ("reserved-filesystem", "main/filesystem"),
        ("reserved-general", "main/general"),
        ("reserved-matrix", "main/matrix"),
        ("reserved-mcp", "main/mcp"),
        ("reserved-sse", "main/sse"),
        ("reserved-terminal", "main/terminal"),
        ("reserved-yaml", "main/yaml"),
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
        .route_dependencies("main", homes, registry_urls)
        .unwrap();
    sha256_bytes(&record.to_json_line().unwrap())
}

fn assert_dependency_registry(site: &Path, name: &str, expected: Option<&str>) {
    let bytes = fs::read(site.join(index_path(name))).unwrap();
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
