use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn bundle_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dynamic-registry-v1")
}

fn walk_regular_files(root: &Path, directory: &Path, files: &mut Vec<String>) {
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(!metadata.file_type().is_symlink(), "{}", path.display());
        if metadata.is_dir() {
            walk_regular_files(root, &path, files);
        } else {
            assert!(metadata.is_file(), "{}", path.display());
            files.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
        }
    }
}

fn exact_keys(value: &Value, expected: &[&str]) {
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(keys, expected);
}

#[test]
fn dynamic_registry_fixture_index_binds_every_bundle_file() {
    let root = bundle_root();
    let index_bytes = fs::read(root.join("index.json")).unwrap();
    let index: Value = serde_json::from_slice(&index_bytes).unwrap();
    let mut canonical = serde_json::to_vec_pretty(&index).unwrap();
    canonical.push(b'\n');
    assert_eq!(canonical, index_bytes);
    exact_keys(&index, &["bundle", "files", "indexExcludes", "schema"]);
    assert_eq!(index["bundle"], "dynamic-registry-v1");
    assert_eq!(index["schema"], "pkgre-fixture-bundle-index-v1");
    assert_eq!(index["indexExcludes"], serde_json::json!(["index.json"]));

    let mut actual_paths = Vec::new();
    walk_regular_files(&root, &root, &mut actual_paths);
    actual_paths.retain(|path| path != "index.json");
    actual_paths.sort_unstable();
    let indexed_paths = index["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(indexed_paths, actual_paths);
    assert_eq!(indexed_paths.len(), 9);

    for record in index["files"].as_array().unwrap() {
        exact_keys(record, &["bytes", "path", "sha256"]);
        let relative = record["path"].as_str().unwrap();
        assert!(relative.is_ascii() && !relative.starts_with('/'));
        assert!(!relative.split('/').any(|component| component == ".."));
        let bytes = fs::read(root.join(relative)).unwrap();
        assert_eq!(bytes.len() as u64, record["bytes"].as_u64().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            record["sha256"].as_str().unwrap()
        );
    }
}
