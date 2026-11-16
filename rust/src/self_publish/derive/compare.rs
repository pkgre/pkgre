//! Comparing a derived crates.io archive with the curated archive of the same
//! release.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use crate::update::{ComparedArchive, read_crate_archive};

/// The files whose bytes a comparison reads.
const READ_FILES: [&str; 3] = ["Cargo.toml", "Cargo.lock", ".cargo_vcs_info.json"];
/// The only files that may differ between the two archives.
const EXCEPTION_FILES: [&str; 4] = [
    "Cargo.toml",
    "Cargo.toml.orig",
    "Cargo.lock",
    ".cargo_vcs_info.json",
];
/// The dependency keys that the derivation rewrites.
const REWRITTEN_DEPENDENCY_KEYS: [&str; 3] = ["registry", "registry-index", "package"];

/// One crate of one release, as the comparison reads it.
pub(super) struct ArchiveToCompare<'a> {
    /// Cargo package name in the archive's own registry.
    pub(super) name: &'a str,
    /// Exact `.crate` bytes.
    pub(super) bytes: &'a [u8],
}

/// Compares one derived crates.io archive with the curated archive.
///
/// The archives must hold the same files below their root, with identical bytes
/// except in `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`, and
/// `.cargo_vcs_info.json`. The VCS claim may differ only by `dirty`, the
/// normalized manifest only in the fields the derivation rewrites, and the lock
/// files must list the same packages at the same versions under the mapped
/// names.
///
/// # Errors
///
/// Returns an error naming the file and the difference for an archive that
/// differs in any other way.
pub(super) fn compare_archives(
    version: &Version,
    curated: &ArchiveToCompare<'_>,
    derived: &ArchiveToCompare<'_>,
    lock_renames: &BTreeMap<String, String>,
) -> Result<()> {
    let curated_archive = read_crate_archive(curated.name, version, curated.bytes, &READ_FILES)
        .with_context(|| format!("read the curated archive of {}", curated.name))?;
    let derived_archive = read_crate_archive(derived.name, version, derived.bytes, &READ_FILES)
        .with_context(|| format!("read the crates.io archive of {}", derived.name))?;
    compare_file_sets(&curated_archive, &derived_archive)?;
    compare_file_bytes(&curated_archive, &derived_archive)?;
    compare_vcs_info(&curated_archive, &derived_archive)?;
    compare_manifests(
        curated.name,
        derived.name,
        &curated_archive,
        &derived_archive,
    )?;
    compare_lock_files(&curated_archive, &derived_archive, lock_renames)?;
    Ok(())
}

/// Compares the file names below the two archive roots.
fn compare_file_sets(curated: &ComparedArchive, derived: &ComparedArchive) -> Result<()> {
    let curated_paths = curated.files.keys().collect::<BTreeSet<_>>();
    let derived_paths = derived.files.keys().collect::<BTreeSet<_>>();
    if let Some(path) = curated_paths.difference(&derived_paths).next() {
        bail!("the curated archive holds {path}, which the crates.io archive does not");
    }
    if let Some(path) = derived_paths.difference(&curated_paths).next() {
        bail!("the crates.io archive holds {path}, which the curated archive does not");
    }
    Ok(())
}

/// Compares the bytes of every file that the derivation does not rewrite.
fn compare_file_bytes(curated: &ComparedArchive, derived: &ComparedArchive) -> Result<()> {
    for (path, curated_file) in &curated.files {
        if EXCEPTION_FILES.contains(&path.as_str()) {
            continue;
        }
        let derived_file = derived
            .files
            .get(path)
            .with_context(|| format!("the crates.io archive has no {path}"))?;
        ensure!(
            curated_file.sha256 == derived_file.sha256,
            "{path} differs: the curated archive holds {} bytes with SHA-256 {}, the crates.io archive {} bytes with SHA-256 {}",
            curated_file.size,
            curated_file.sha256,
            derived_file.size,
            derived_file.sha256
        );
    }
    Ok(())
}

/// Compares the two VCS claims, which may differ only by `dirty`.
fn compare_vcs_info(curated: &ComparedArchive, derived: &ComparedArchive) -> Result<()> {
    let curated = vcs_claim(curated)?;
    let derived = vcs_claim(derived)?;
    ensure!(
        curated.is_some() == derived.is_some(),
        ".cargo_vcs_info.json is present in only one of the two archives"
    );
    let (Some(curated), Some(derived)) = (curated, derived) else {
        return Ok(());
    };
    ensure!(
        curated == derived,
        ".cargo_vcs_info.json differs beyond `dirty`: the curated archive holds {curated}, the crates.io archive {derived}"
    );
    Ok(())
}

/// Parses the VCS claim of one archive, without its `dirty` flag.
fn vcs_claim(archive: &ComparedArchive) -> Result<Option<JsonValue>> {
    let Some(bytes) = archive.contents.get(".cargo_vcs_info.json") else {
        return Ok(None);
    };
    let value: JsonValue =
        serde_json::from_slice(bytes).context("parse the archived .cargo_vcs_info.json")?;
    let mut object = value
        .as_object()
        .cloned()
        .context("archived .cargo_vcs_info.json is not an object")?;
    object.remove("dirty");
    if let Some(git) = object.get_mut("git").and_then(JsonValue::as_object_mut) {
        git.remove("dirty");
    }
    Ok(Some(JsonValue::Object(object)))
}

/// Compares the two normalized manifests, which may differ only in the fields
/// the derivation rewrites.
fn compare_manifests(
    curated_name: &str,
    derived_name: &str,
    curated: &ComparedArchive,
    derived: &ComparedArchive,
) -> Result<()> {
    let curated_manifest = manifest(curated)?;
    let derived_manifest = manifest(derived)?;
    let manifest_name = package_name(&derived_manifest)?;
    ensure!(
        manifest_name == derived_name,
        "the crates.io manifest names the package {manifest_name:?}, not {derived_name:?}"
    );
    let curated_manifest_name = package_name(&curated_manifest)?;
    ensure!(
        curated_manifest_name == curated_name,
        "the curated manifest names the package {curated_manifest_name:?}, not {curated_name:?}"
    );
    let publish = publish_list(&derived_manifest)?;
    ensure!(
        publish == ["crates-io"],
        "the crates.io manifest does not publish to exactly [\"crates-io\"]: {publish:?}"
    );
    compare_library_names(&curated_manifest, &derived_manifest)?;
    compare_binary_names(&curated_manifest, &derived_manifest)?;
    compare_values(
        "Cargo.toml",
        &strip_manifest(&curated_manifest),
        &strip_manifest(&derived_manifest),
    )
}

/// Parses one archived `Cargo.toml`.
fn manifest(archive: &ComparedArchive) -> Result<TomlValue> {
    let bytes = archive
        .contents
        .get("Cargo.toml")
        .context("the archive holds no Cargo.toml")?;
    toml::from_slice(bytes).context("parse the archived Cargo.toml")
}

/// Returns the `[package] name` of one parsed manifest.
fn package_name(manifest: &TomlValue) -> Result<String> {
    manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
        .context("the manifest has no package.name")
}

/// Returns the `[package] publish` list of one parsed manifest.
fn publish_list(manifest: &TomlValue) -> Result<Vec<String>> {
    let Some(publish) = manifest
        .get("package")
        .and_then(|package| package.get("publish"))
    else {
        return Ok(Vec::new());
    };
    publish
        .as_array()
        .context("package.publish is not an array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("package.publish holds a non-string")
        })
        .collect()
}

/// Compares the library names of the two manifests.
fn compare_library_names(curated: &TomlValue, derived: &TomlValue) -> Result<()> {
    let curated = library_name(curated);
    let derived = library_name(derived);
    ensure!(
        curated == derived,
        "the library name differs: the curated manifest names {curated:?}, the crates.io archive {derived:?}"
    );
    Ok(())
}

/// Returns the `[lib] name` of one parsed manifest, when it has a library.
fn library_name(manifest: &TomlValue) -> Option<String> {
    manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
}

/// Compares the binary names of the two manifests, pairing them by path.
fn compare_binary_names(curated: &TomlValue, derived: &TomlValue) -> Result<()> {
    let curated = binary_names(curated);
    let derived = binary_names(derived);
    ensure!(
        curated == derived,
        "the binary names differ: the curated manifest holds {curated:?}, the crates.io archive {derived:?}"
    );
    Ok(())
}

/// Returns the `[[bin]]` names of one parsed manifest, by path.
fn binary_names(manifest: &TomlValue) -> BTreeMap<String, String> {
    manifest
        .get("bin")
        .and_then(TomlValue::as_array)
        .map(|binaries| {
            binaries
                .iter()
                .filter_map(|binary| {
                    let path = binary.get("path")?.as_str()?.to_owned();
                    let name = binary.get("name")?.as_str()?.to_owned();
                    Some((path, name))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Removes the fields that the derivation rewrites from one parsed manifest.
fn strip_manifest(manifest: &TomlValue) -> TomlValue {
    let mut manifest = manifest.clone();
    if let Some(package) = manifest
        .get_mut("package")
        .and_then(TomlValue::as_table_mut)
    {
        package.remove("name");
        package.remove("publish");
    }
    if let Some(library) = manifest.get_mut("lib").and_then(TomlValue::as_table_mut) {
        library.remove("name");
    }
    if let Some(binaries) = manifest.get_mut("bin").and_then(TomlValue::as_array_mut) {
        for binary in binaries {
            if let Some(binary) = binary.as_table_mut() {
                binary.remove("name");
            }
        }
    }
    strip_dependency_tables(&mut manifest);
    manifest
}

/// Removes the rewritten keys from every dependency table of one manifest.
fn strip_dependency_tables(manifest: &mut TomlValue) {
    let Some(table) = manifest.as_table_mut() else {
        return;
    };
    let keys = table.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let Some(item) = table.get_mut(&key) else {
            continue;
        };
        if is_dependency_table(&key) {
            strip_dependency_table(item);
            continue;
        }
        if key == "target"
            && let Some(targets) = item.as_table_mut()
        {
            for (_, target) in targets.iter_mut() {
                if let Some(target) = target.as_table_mut() {
                    let names = target.keys().cloned().collect::<Vec<_>>();
                    for name in names {
                        if is_dependency_table(&name)
                            && let Some(dependencies) = target.get_mut(&name)
                        {
                            strip_dependency_table(dependencies);
                        }
                    }
                }
            }
            continue;
        }
        if key == "workspace"
            && let Some(workspace) = item.as_table_mut()
            && let Some(dependencies) = workspace.get_mut("dependencies")
        {
            strip_dependency_table(dependencies);
        }
    }
}

/// Returns whether one table name is a Cargo dependency table.
fn is_dependency_table(name: &str) -> bool {
    matches!(
        name,
        "dependencies"
            | "dev-dependencies"
            | "dev_dependencies"
            | "build-dependencies"
            | "build_dependencies"
    )
}

/// Removes the rewritten keys from one dependency table.
fn strip_dependency_table(dependencies: &mut TomlValue) {
    let Some(table) = dependencies.as_table_mut() else {
        return;
    };
    for (_, dependency) in table.iter_mut() {
        if let Some(dependency) = dependency.as_table_mut() {
            for key in REWRITTEN_DEPENDENCY_KEYS {
                dependency.remove(key);
            }
        }
    }
}

/// Compares two parsed TOML documents, naming the first path that differs.
fn compare_values(path: &str, curated: &TomlValue, derived: &TomlValue) -> Result<()> {
    match (curated, derived) {
        (TomlValue::Table(curated), TomlValue::Table(derived)) => {
            let keys = curated
                .keys()
                .chain(derived.keys())
                .collect::<BTreeSet<&String>>();
            for key in keys {
                let child = format!("{path}.{key}");
                match (curated.get(key), derived.get(key)) {
                    (Some(left), Some(right)) => compare_values(&child, left, right)?,
                    (Some(left), None) => bail!(
                        "the normalized {child} is {} in the curated archive, and absent from the crates.io archive",
                        compact(left)
                    ),
                    (None, Some(right)) => bail!(
                        "the normalized {child} is absent from the curated archive, and {} in the crates.io archive",
                        compact(right)
                    ),
                    (None, None) => unreachable!("the key comes from one of the two tables"),
                }
            }
            Ok(())
        }
        (TomlValue::Array(curated), TomlValue::Array(derived)) => {
            ensure!(
                curated.len() == derived.len(),
                "the normalized {path} differs: the curated archive lists {} entries, the crates.io archive {}",
                curated.len(),
                derived.len()
            );
            for (index, (left, right)) in curated.iter().zip(derived).enumerate() {
                compare_values(&format!("{path}[{index}]"), left, right)?;
            }
            Ok(())
        }
        (curated, derived) => {
            ensure!(
                curated == derived,
                "the normalized {path} differs: the curated archive holds {}, the crates.io archive {}",
                compact(curated),
                compact(derived)
            );
            Ok(())
        }
    }
}

/// Renders one TOML value compactly for an error message.
fn compact(value: &TomlValue) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("{value:?}"))
}

/// Compares the two packaged lock files, which must list the same packages at
/// the same versions under the mapped names.
fn compare_lock_files(
    curated: &ComparedArchive,
    derived: &ComparedArchive,
    renames: &BTreeMap<String, String>,
) -> Result<()> {
    let curated = lock_packages(curated, renames)?;
    let derived = lock_packages(derived, &BTreeMap::new())?;
    for (identity, checksum) in &curated {
        let Some(derived_checksum) = derived.get(identity) else {
            bail!(
                "the curated Cargo.lock holds {} {}, which the crates.io lock does not",
                identity.0,
                identity.1
            );
        };
        if let (Some(left), Some(right)) = (checksum, derived_checksum) {
            ensure!(
                left == right,
                "the Cargo.lock checksum of {} {} differs: the curated archive holds {left}, the crates.io archive {right}",
                identity.0,
                identity.1
            );
        }
    }
    for identity in derived.keys() {
        ensure!(
            curated.contains_key(identity),
            "the crates.io Cargo.lock holds {} {}, which the curated lock does not",
            identity.0,
            identity.1
        );
    }
    Ok(())
}

/// Returns the packages of one archived `Cargo.lock`, mapped to crates.io names,
/// with their checksums.
fn lock_packages(
    archive: &ComparedArchive,
    renames: &BTreeMap<String, String>,
) -> Result<BTreeMap<(String, String), Option<String>>> {
    let bytes = archive
        .contents
        .get("Cargo.lock")
        .context("the archive holds no Cargo.lock")?;
    let lock: TomlValue = toml::from_slice(bytes).context("parse the archived Cargo.lock")?;
    let packages = lock
        .get("package")
        .and_then(TomlValue::as_array)
        .context("the archived Cargo.lock has no [[package]] array")?;
    let mut names = BTreeMap::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(TomlValue::as_str)
            .context("a Cargo.lock package has no name")?;
        let version = package
            .get("version")
            .and_then(TomlValue::as_str)
            .context("a Cargo.lock package has no version")?;
        let name = renames.get(name).map_or(name, String::as_str);
        names.insert(
            (name.to_owned(), version.to_owned()),
            package
                .get("checksum")
                .and_then(TomlValue::as_str)
                .map(str::to_owned),
        );
    }
    Ok(names)
}
