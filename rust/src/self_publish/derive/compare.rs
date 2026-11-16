//! Comparing a derived crates.io archive with the curated archive of the same
//! release.
//!
//! Everything the comparison expects comes from [`Expectations`], which resolves
//! the catalog, the mapping, and the entries of earlier releases directly. The
//! comparison therefore proves the archives against those facts, not against the
//! translation that produced them.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use super::cargo::{CRATES_IO_INDEX, CURATED_INDEX};
use super::expectations::Expectations;
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
/// The dependency keys that the rewrite removes or replaces.
const REWRITTEN_DEPENDENCY_KEYS: [&str; 2] = ["package", "registry"];
/// The dependency key that Cargo writes for a dependency of a named registry.
const REGISTRY_INDEX_KEY: &str = "registry-index";
/// The curated registry alias, as a manifest may spell it.
const CURATED_REGISTRY: &str = "pkgre";

/// One crate of one release, as the comparison reads it.
pub(super) struct ArchiveToCompare<'a> {
    /// Cargo package name in the archive's own registry.
    pub(super) name: &'a str,
    /// Exact `.crate` bytes.
    pub(super) bytes: &'a [u8],
}

/// Compares one derived crates.io archive with the curated archive.
///
/// # Errors
///
/// Returns an error naming the file and the difference for an archive that
/// differs from the curated one beyond the fields the derivation rewrites.
pub(super) fn compare_archives(
    version: &Version,
    curated: &ArchiveToCompare<'_>,
    derived: &ArchiveToCompare<'_>,
    expectations: &Expectations,
) -> Result<()> {
    ensure!(
        expectations.crates_io_name(curated.name)? == derived.name,
        "the crates.io name of {} is {:?}, not {:?}",
        curated.name,
        expectations.crates_io_name(curated.name)?,
        derived.name
    );
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
        expectations,
    )?;
    compare_lock_files(&curated_archive, &derived_archive, expectations)?;
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

/// Compares the bytes and the permissions of every file that the derivation does
/// not rewrite.
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
        ensure!(
            curated_file.mode == derived_file.mode,
            "{path} differs in its permissions: the curated archive holds mode {:04o}, the crates.io archive {:04o}",
            curated_file.mode,
            derived_file.mode
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

/// Compares the two normalized manifests.
fn compare_manifests(
    curated_name: &str,
    derived_name: &str,
    curated: &ComparedArchive,
    derived: &ComparedArchive,
    expectations: &Expectations,
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
    compare_dependencies(&curated_manifest, &derived_manifest, expectations)?;
    compare_values(
        "Cargo.toml",
        &strip_manifest(&curated_manifest),
        &strip_manifest(&derived_manifest),
    )
}

/// Compares every dependency of the two manifests against the expected names.
fn compare_dependencies(
    curated: &TomlValue,
    derived: &TomlValue,
    expectations: &Expectations,
) -> Result<()> {
    for (path, key, entry) in dependency_entries(curated) {
        let actual = entry
            .get("package")
            .and_then(TomlValue::as_str)
            .unwrap_or(&key);
        let expected = expectations.crates_io_name(actual).with_context(|| {
            format!("the curated dependency {key:?} names a package that the lock does not hold")
        })?;
        if let Some(registry) = entry.get(REGISTRY_INDEX_KEY).and_then(TomlValue::as_str) {
            ensure!(
                registry == CURATED_INDEX,
                "the curated dependency {key:?} names the registry {registry:?}, not the curated registry"
            );
        }
        if let Some(registry) = entry.get("registry").and_then(TomlValue::as_str) {
            ensure!(
                registry == CURATED_REGISTRY,
                "the curated dependency {key:?} names the registry {registry:?}, not the curated registry"
            );
        }
        let derived_entry = lookup(derived, &path, &key).with_context(|| {
            format!(
                "the crates.io manifest holds no dependency {key:?} in {}",
                path.join(".")
            )
        })?;
        for name in [REGISTRY_INDEX_KEY, "registry"] {
            ensure!(
                derived_entry.get(name).is_none(),
                "the crates.io dependency {key:?} in {} names another registry: {name} = {:?}",
                path.join("."),
                derived_entry.get(name)
            );
        }
        let derived_package = derived_entry.get("package").and_then(TomlValue::as_str);
        if expected == key {
            ensure!(
                derived_package.is_none(),
                "the crates.io dependency {key:?} in {} is renamed to {derived_package:?}, but crates.io has the crate under its own name",
                path.join(".")
            );
        } else {
            ensure!(
                derived_package == Some(expected),
                "the crates.io dependency {key:?} in {} names the package {derived_package:?}, not {expected:?}",
                path.join(".")
            );
        }
    }
    Ok(())
}

/// Returns every dependency entry of one manifest, with its table path and key.
fn dependency_entries(manifest: &TomlValue) -> Vec<(Vec<String>, String, &TomlValue)> {
    let mut entries = Vec::new();
    collect_dependency_entries(manifest, &mut Vec::new(), &mut entries);
    entries
}

/// Collects the dependency entries below one value.
fn collect_dependency_entries<'a>(
    value: &'a TomlValue,
    path: &mut Vec<String>,
    entries: &mut Vec<(Vec<String>, String, &'a TomlValue)>,
) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        path.push(key.clone());
        let is_dependency_table = path
            .last()
            .is_some_and(|last| is_dependency_table(last.as_str()));
        if is_dependency_table && child.is_table() {
            for (name, entry) in child.as_table().expect("the child is a table") {
                entries.push((path.clone(), name.clone(), entry));
            }
        } else if child.is_table() {
            collect_dependency_entries(child, path, entries);
        }
        path.pop();
    }
}

/// Looks up one dependency entry of one manifest.
fn lookup<'a>(manifest: &'a TomlValue, path: &[String], key: &str) -> Option<&'a TomlValue> {
    let mut value = manifest;
    for component in path {
        value = value.get(component)?;
    }
    value.get(key)
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
    let mut path = Vec::new();
    let keys = dependency_keys(manifest, &mut path);
    for (path, key) in keys {
        if let Some(entry) = lookup_mut(manifest, &path, &key).and_then(TomlValue::as_table_mut) {
            for name in REWRITTEN_DEPENDENCY_KEYS {
                entry.remove(name);
            }
            entry.remove(REGISTRY_INDEX_KEY);
        }
    }
}

/// Returns the table path and key of every dependency entry of one manifest.
fn dependency_keys(value: &TomlValue, path: &mut Vec<String>) -> Vec<(Vec<String>, String)> {
    let mut keys = Vec::new();
    let Some(table) = value.as_table() else {
        return keys;
    };
    for (key, child) in table {
        path.push(key.clone());
        let is_dependency_table = path
            .last()
            .is_some_and(|last| is_dependency_table(last.as_str()));
        if is_dependency_table && child.is_table() {
            for (name, _) in child.as_table().expect("the child is a table") {
                keys.push((path.clone(), name.clone()));
            }
        } else if child.is_table() {
            keys.extend(dependency_keys(child, path));
        }
        path.pop();
    }
    keys
}

/// Looks up one mutable dependency entry of one manifest.
fn lookup_mut<'a>(
    manifest: &'a mut TomlValue,
    path: &[String],
    key: &str,
) -> Option<&'a mut TomlValue> {
    let mut value = manifest;
    for component in path {
        value = value.get_mut(component)?;
    }
    value.get_mut(key)
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

/// The source that the curated lock records for an external package.
///
/// Cargo writes a sparse registry's index URL without the `registry+` prefix in
/// a lock file.
fn curated_lock_source() -> String {
    CURATED_INDEX.to_owned()
}

/// The source that the derived lock records for an external package.
fn crates_io_lock_source() -> String {
    format!("registry+{CRATES_IO_INDEX}")
}

/// One package of an archived `Cargo.lock`.
struct LockedPackage {
    name: String,
    version: Version,
    source: Option<String>,
    checksum: Option<String>,
}

/// Compares the two packaged lock files with the checksums that each side must
/// serve.
fn compare_lock_files(
    curated: &ComparedArchive,
    derived: &ComparedArchive,
    expectations: &Expectations,
) -> Result<()> {
    let curated_packages = lock_packages(curated)?;
    let derived_packages = lock_packages(derived)?;
    let mut matched = BTreeSet::new();
    for package in &curated_packages {
        let expected = expectations.package(&package.name, &package.version)?;
        let counterpart = derived_packages
            .iter()
            .find(|candidate| {
                candidate.name == expected.crates_io_name && candidate.version == package.version
            })
            .with_context(|| {
                format!(
                    "the crates.io Cargo.lock holds no {} {}",
                    expected.crates_io_name, package.version
                )
            })?;
        ensure!(
            matched.insert((expected.crates_io_name.clone(), package.version.clone())),
            "the crates.io Cargo.lock holds {} {} twice",
            expected.crates_io_name,
            package.version
        );
        match (&expected.curated_checksum, &expected.derived_checksum) {
            (None, None) => {
                ensure!(
                    package.source.is_none() && package.checksum.is_none(),
                    "{} {} is a workspace member, but the curated lock records source {:?} and checksum {:?}",
                    package.name,
                    package.version,
                    package.source,
                    package.checksum
                );
                ensure!(
                    counterpart.source.is_none() && counterpart.checksum.is_none(),
                    "{} {} is a workspace member, but the crates.io lock records source {:?} and checksum {:?}",
                    expected.crates_io_name,
                    package.version,
                    counterpart.source,
                    counterpart.checksum
                );
            }
            (curated_checksum, derived_checksum) => {
                ensure!(
                    package.source.as_deref() == Some(curated_lock_source().as_str()),
                    "{} {} comes from {:?} in the curated lock, not from the curated registry",
                    package.name,
                    package.version,
                    package.source
                );
                ensure!(
                    package.checksum.as_deref() == curated_checksum.as_deref(),
                    "the curated Cargo.lock records checksum {:?} for {} {}, not {:?}",
                    package.checksum,
                    package.name,
                    package.version,
                    curated_checksum
                );
                ensure!(
                    counterpart.source.as_deref() == Some(crates_io_lock_source().as_str()),
                    "{} {} comes from {:?} in the crates.io lock, not from crates.io",
                    expected.crates_io_name,
                    package.version,
                    counterpart.source
                );
                ensure!(
                    counterpart.checksum.as_deref() == derived_checksum.as_deref(),
                    "the crates.io Cargo.lock records checksum {:?} for {} {}, not {:?}",
                    counterpart.checksum,
                    expected.crates_io_name,
                    package.version,
                    derived_checksum
                );
            }
        }
    }
    for package in &derived_packages {
        ensure!(
            matched.contains(&(package.name.clone(), package.version.clone())),
            "the crates.io Cargo.lock holds {} {}, which the curated lock does not",
            package.name,
            package.version
        );
    }
    Ok(())
}

/// Returns the packages of one archived `Cargo.lock`.
fn lock_packages(archive: &ComparedArchive) -> Result<Vec<LockedPackage>> {
    let bytes = archive
        .contents
        .get("Cargo.lock")
        .context("the archive holds no Cargo.lock")?;
    let lock: TomlValue = toml::from_slice(bytes).context("parse the archived Cargo.lock")?;
    let packages = lock
        .get("package")
        .and_then(TomlValue::as_array)
        .context("the archived Cargo.lock has no [[package]] array")?;
    packages
        .iter()
        .map(|package| {
            let name = package
                .get("name")
                .and_then(TomlValue::as_str)
                .context("a Cargo.lock package has no name")?;
            let version = package
                .get("version")
                .and_then(TomlValue::as_str)
                .with_context(|| format!("Cargo.lock package {name:?} has no version"))?;
            Ok(LockedPackage {
                name: name.to_owned(),
                version: Version::parse(version)
                    .with_context(|| format!("parse the version of Cargo.lock package {name:?}"))?,
                source: package
                    .get("source")
                    .and_then(TomlValue::as_str)
                    .map(str::to_owned),
                checksum: package
                    .get("checksum")
                    .and_then(TomlValue::as_str)
                    .map(str::to_owned),
            })
        })
        .collect()
}
