//! Strict historical schema-3 catalog loader used only by the one-way migration.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::category::CategoryId;
use crate::download::{DOWNLOAD_CATALOG_FILE, router_download_template};

/// Supported human registry and generated lock schema version.
pub const SCHEMA_VERSION: u32 = 3;
/// Cargo download base for registries backed by crates.io archives.
pub const MIRROR_DOWNLOAD: &str = "https://static.crates.io/crates";
/// Cargo download template for registries backed by retained Git-tag archives.
pub const PUBLISH_DOWNLOAD: &str = "https://rust.pkg.re/crates/{sha256-checksum}.crate";
const CNAME: &str = "rust.pkg.re";

/// Fully loaded strict catalog.
#[derive(Debug)]
pub struct Catalog {
    /// Catalog directory.
    pub root: PathBuf,
    /// Registry topology and output configuration.
    pub registries: RegistriesFile,
    /// Canonical category dependency policy keyed by category identity.
    pub categories: BTreeMap<CategoryId, Vec<CategoryId>>,
    /// Package-name routing and category table derived from human declarations.
    pub homes: HomesFile,
    /// Permanent source class for every reserved package name.
    pub name_sources: BTreeMap<String, NameSource>,
    /// Every active or removed package identity retained by generated locks.
    pub approvals: Vec<Approval>,
}

/// Aggregate registry topology retained for policy and rendering.
#[derive(Debug)]
pub struct RegistriesFile {
    /// Schema version.
    pub schema: u32,
    /// GitHub Pages custom domain.
    pub cname: String,
    /// Pinned Cargo version for the `pkgre` registry.
    pub cargo_version: Version,
    /// Registry declarations.
    pub registries: Vec<Registry>,
}

/// One sparse Cargo registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Registry {
    /// Stable Cargo registry alias and output directory name.
    pub name: String,
    /// Canonical sparse index URL, including `sparse+` and a trailing slash.
    pub index: String,
    /// Cargo archive download base or template for this registry.
    pub download: String,
    /// Exact Cargo version used for newly published Git-tag packages.
    pub cargo_version: Version,
}

/// Expanded human-edited desired state for one registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryFile {
    /// Schema version.
    pub schema: u32,
    /// Registry topology and packaging configuration.
    pub registry: Registry,
    /// Category declarations keyed by registry-local category name.
    pub categories: BTreeMap<String, CategoryDeclaration>,
}

/// One category's dependency policy and desired package declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryDeclaration {
    /// Fully qualified stable identity.
    pub id: CategoryId,
    /// Exact direct dependency allowlist.
    pub may_depend_on: Vec<CategoryId>,
    /// Exact crates.io versions mirrored byte-for-byte; an empty list reserves the name.
    pub mirror: BTreeMap<String, Vec<Version>>,
    /// First-party packages produced from immutable Git tags.
    pub publish: BTreeMap<String, PublishDeclaration>,
    /// Inline registry file or external category file used for diagnostics.
    pub declared_in: PathBuf,
}

/// Human declaration for one first-party Git repository and its approved tags.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishDeclaration {
    /// Credential-free HTTPS Git repository.
    pub git: String,
    /// Literal immutable Git tags.
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistryFile {
    schema: u32,
    registry: Registry,
    categories: BTreeMap<String, RawCategoryInput>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawCategoryInput {
    External(CategoryReference),
    Inline(CategoryBody),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CategoryReference {
    file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct CategoryBody {
    may_depend_on: Vec<CategoryId>,
    #[serde(default)]
    mirror: BTreeMap<String, Vec<Version>>,
    #[serde(default)]
    publish: BTreeMap<String, PublishDeclaration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct CategoryFile {
    schema: u32,
    may_depend_on: Vec<CategoryId>,
    #[serde(default)]
    mirror: BTreeMap<String, Vec<Version>>,
    #[serde(default)]
    publish: BTreeMap<String, PublishDeclaration>,
}

/// One human registry file and its optional generated lock.
#[derive(Clone, Debug)]
pub struct RegistryInput {
    /// Human file path.
    pub path: PathBuf,
    /// Generated lock path.
    pub lock_path: PathBuf,
    /// Parsed and expanded human declaration.
    pub file: RegistryFile,
    /// Parsed generated lock, absent only before the first reconciliation.
    pub lock: Option<RegistryLock>,
}

/// Top-level generated registry lock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLock {
    /// Lock schema version.
    pub schema: u32,
    /// Immutable registry identity copied from the human file.
    pub registry: LockedRegistry,
    /// Permanent package-name homes and source classes.
    #[serde(default)]
    pub names: Vec<LockedName>,
    /// Permanent active or removed package identities.
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

/// Immutable registry identity embedded in a generated lock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRegistry {
    /// Registry alias.
    pub name: String,
    /// Canonical sparse index URL.
    pub index: String,
    /// Cargo archive download base or template.
    pub download: String,
}

/// Permanent package source class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameSource {
    /// Exact crates.io artifacts mirrored byte-for-byte.
    Mirror,
    /// First-party artifacts produced from Git tags.
    Publish,
}

/// Permanent package-name category and source-class anchor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedName {
    /// Cargo package name.
    pub name: String,
    /// Registry-local category identity.
    pub category: String,
    /// Mirrored or first-party-published source class.
    pub source: NameSource,
}

/// Lifecycle state of one locked package identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageState {
    /// Archive is served and the index row is selectable.
    Active,
    /// Archive is absent and the retained index row is rendered as yanked.
    Removed,
}

/// One immutable generated package lock entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct LockedPackage {
    /// Cargo package name.
    pub name: String,
    /// Exact Cargo version.
    pub version: Version,
    /// Active or irreversibly removed state.
    pub state: PackageState,
    /// SHA-256 of the exact `.crate` archive.
    pub crate_sha256: String,
    /// SHA-256 of the exact un-routed source index row.
    pub source_row_sha256: String,
    /// SHA-256 of the canonical routed row with `yanked = false`.
    pub index_row_sha256: String,
    /// SHA-256 of the complete generated admission lock that authorized this identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_sha256: Option<String>,
    /// Immutable origin evidence.
    pub source: LockedSource,
}

/// Immutable origin evidence stored in generated locks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LockedSource {
    /// Exact bytes and metadata imported from crates.io.
    CratesIo {},
    /// First-party package produced from an immutable Git tag.
    GitTag {
        /// Credential-free HTTPS repository URL.
        git: String,
        /// Literal immutable release tag.
        tag: String,
        /// Exact tag object ID; equals the commit for a lightweight tag.
        #[serde(rename = "tag-oid")]
        tag_oid: String,
        /// Full peeled commit object ID.
        commit: String,
        /// Cargo package selected from the repository workspace.
        package: String,
        /// Repository-relative package directory.
        path: PathBuf,
        /// Exact Cargo version used to produce the archive.
        #[serde(rename = "cargo-version")]
        cargo_version: Version,
    },
}

/// Permanent package home used for policy and Cargo registry routing.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageHome {
    /// Cargo registry alias.
    pub registry: String,
    /// Fully qualified policy category.
    pub category: CategoryId,
}

/// Package-name routing and category table derived from human files.
#[derive(Debug)]
pub struct HomesFile {
    /// Schema version.
    pub schema: u32,
    /// Explicit home for every reserved package name.
    pub homes: BTreeMap<String, PackageHome>,
}

/// One active or removed package identity used by policy, verification, and rendering.
#[derive(Clone, Debug)]
pub struct Approval {
    /// Registry home.
    pub registry: String,
    /// Category home.
    pub category: CategoryId,
    /// Cargo package name.
    pub name: String,
    /// Exact version.
    pub version: Version,
    /// SHA-256 of the exact `.crate` archive.
    pub archive_sha256: String,
    /// SHA-256 of the exact un-routed source index row.
    pub index_record_sha256: String,
    /// SHA-256 of the canonical routed row with `yanked = false`.
    pub index_row_sha256: String,
    /// SHA-256 of the complete generated admission lock that authorized this identity.
    pub admission_sha256: Option<String>,
    /// Active or irreversibly removed state.
    pub state: PackageState,
    /// Immutable origin evidence.
    pub source: Source,
    /// Generated lock used for diagnostics.
    pub declared_in: PathBuf,
}

/// Immutable origin of a locked package archive and source index row.
#[derive(Clone, Debug)]
pub enum Source {
    /// Exact package bytes and metadata imported from crates.io.
    CratesIo,
    /// First-party package produced from an immutable Git tag and commit.
    GitTag {
        /// HTTPS repository URL.
        repository: String,
        /// Literal immutable release tag.
        tag: String,
        /// Exact tag object ID.
        tag_oid: String,
        /// Full peeled commit object ID.
        commit: String,
        /// Cargo package selected from the repository workspace.
        package: String,
        /// Repository-relative package directory.
        subdir: PathBuf,
        /// Exact Cargo version used to produce the archive.
        cargo_version: Version,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DesiredName {
    category: String,
    source: NameSource,
}

impl RegistryFile {
    /// Iterates every category in canonical local-name order.
    pub fn category_values(&self) -> impl Iterator<Item = &CategoryDeclaration> {
        self.categories.values()
    }

    /// Finds the declaration for a published package name.
    #[must_use]
    pub fn publish_declaration(&self, name: &str) -> Option<&PublishDeclaration> {
        self.categories
            .values()
            .find_map(|category| category.publish.get(name))
    }
}

impl Catalog {
    /// Loads a strict catalog whose generated locks exactly represent human desired state.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, malformed, non-canonical, unsupported, or stale inputs.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let inputs = load_registry_inputs(root)?;
        ensure!(!inputs.is_empty(), "catalog has no registry declarations");
        for input in &inputs {
            validate_input_for_update(input)?;
            validate_input_strict(input)?;
        }
        let catalog = catalog_from_inputs(root, &inputs)?;
        Ok(catalog)
    }
}

/// Loads all human registry files, external category files, and adjacent generated locks.
///
/// # Errors
///
/// Returns an error for an unsafe root, malformed input, unsupported schema, duplicate registry, unsafe category reference, orphan category file, or non-canonical lock.
pub fn load_registry_inputs(root: &Path) -> Result<Vec<RegistryInput>> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect catalog root {}", root.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "catalog root is not a real directory: {}",
        root.display()
    );
    let mut paths = fs::read_dir(root)
        .with_context(|| format!("read catalog root {}", root.display()))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("read entries below {}", root.display()))?;
    paths.sort();
    validate_catalog_root_entries(&paths, root)?;

    let mut inputs = Vec::new();
    let mut registries = BTreeSet::new();
    let mut referenced_categories = BTreeSet::new();
    for path in &paths {
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let raw: RawRegistryFile = load_toml(path)?;
        check_schema(raw.schema, path)?;
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .with_context(|| format!("registry filename is not valid UTF-8: {}", path.display()))?;
        ensure!(
            stem == raw.registry.name,
            "registry file {} must be named {}.toml",
            path.display(),
            raw.registry.name
        );
        ensure!(
            registries.insert(raw.registry.name.clone()),
            "duplicate registry declaration {:?}",
            raw.registry.name
        );
        let (file, category_paths) = expand_registry_file(root, path, raw)?;
        for category_path in &category_paths {
            ensure!(
                referenced_categories.insert(category_path.clone()),
                "external category file {} is referenced more than once",
                category_path.display()
            );
        }
        validate_human_package_sets(&file, path)?;
        let lock_path = path.with_extension("lock");
        let lock = match fs::symlink_metadata(&lock_path) {
            Ok(_) => Some(load_lock(&lock_path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", lock_path.display()));
            }
        };
        inputs.push(RegistryInput {
            path: path.clone(),
            lock_path,
            file,
            lock,
        });
    }
    validate_category_inventory(root, &referenced_categories)?;
    Ok(inputs)
}

fn expand_registry_file(
    root: &Path,
    path: &Path,
    raw: RawRegistryFile,
) -> Result<(RegistryFile, Vec<PathBuf>)> {
    ensure!(
        !raw.categories.is_empty(),
        "registry {} must declare at least one category",
        raw.registry.name
    );
    let mut categories = BTreeMap::new();
    let mut category_paths = Vec::new();
    for (local, input) in raw.categories {
        let id = CategoryId::new(raw.registry.name.clone(), local.clone())
            .with_context(|| format!("invalid category {local:?} in {}", path.display()))?;
        let (body, declared_in) = match input {
            RawCategoryInput::Inline(body) => (body, path.to_path_buf()),
            RawCategoryInput::External(reference) => {
                let expected = PathBuf::from("categories")
                    .join(&raw.registry.name)
                    .join(format!("{local}.toml"));
                ensure!(
                    reference.file == expected,
                    "external category {id} in {} must use exact canonical path {}",
                    path.display(),
                    expected.display()
                );
                let absolute = root.join(&reference.file);
                let external: CategoryFile = load_toml(&absolute)?;
                check_schema(external.schema, &absolute)?;
                category_paths.push(reference.file);
                (
                    CategoryBody {
                        may_depend_on: external.may_depend_on,
                        mirror: external.mirror,
                        publish: external.publish,
                    },
                    absolute,
                )
            }
        };
        ensure!(
            categories
                .insert(
                    local,
                    CategoryDeclaration {
                        id,
                        may_depend_on: body.may_depend_on,
                        mirror: body.mirror,
                        publish: body.publish,
                        declared_in,
                    },
                )
                .is_none(),
            "duplicate category declaration"
        );
    }
    category_paths.sort();
    Ok((
        RegistryFile {
            schema: raw.schema,
            registry: raw.registry,
            categories,
        },
        category_paths,
    ))
}

fn validate_catalog_root_entries(paths: &[PathBuf], root: &Path) -> Result<()> {
    for path in paths {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect catalog entry {}", path.display()))?;
        if matches!(path.file_name(), Some(name) if name == OsStr::new("objects") || name == OsStr::new("categories") || name == OsStr::new("admissions"))
        {
            ensure!(
                metadata.file_type().is_dir(),
                "catalog managed path is not a real directory: {}",
                path.display()
            );
            continue;
        }
        match path.extension().and_then(|value| value.to_str()) {
            Some("json") if path.file_name() == Some(OsStr::new(DOWNLOAD_CATALOG_FILE)) => ensure!(
                metadata.file_type().is_file(),
                "generated download catalog is not a regular file: {}",
                path.display()
            ),
            Some("toml") => ensure!(
                metadata.file_type().is_file(),
                "human registry input is not a regular file: {}",
                path.display()
            ),
            Some("lock") => {
                ensure!(
                    metadata.file_type().is_file(),
                    "generated registry lock is not a regular file: {}",
                    path.display()
                );
                let human = path.with_extension("toml");
                ensure!(
                    paths.binary_search(&human).is_ok(),
                    "generated lock {} has no adjacent human registry file",
                    path.display()
                );
            }
            _ => bail!(
                "unexpected entry in catalog root {}: {}; only registry .toml/.lock files, {DOWNLOAD_CATALOG_FILE}, categories/, objects/, and admissions/ are allowed",
                root.display(),
                path.display()
            ),
        }
    }
    crate::update::validate_admission_tree_structure(root)?;
    Ok(())
}

fn validate_category_inventory(root: &Path, expected: &BTreeSet<PathBuf>) -> Result<()> {
    let category_root = root.join("categories");
    match fs::symlink_metadata(&category_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                expected.is_empty(),
                "referenced external category directory is missing"
            );
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", category_root.display()));
        }
        Ok(metadata) => ensure!(
            metadata.file_type().is_dir(),
            "category root is not a real directory: {}",
            category_root.display()
        ),
    }
    let mut actual = BTreeSet::new();
    let mut registry_directories = fs::read_dir(&category_root)
        .with_context(|| format!("read category root {}", category_root.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    registry_directories.sort_by_key(fs::DirEntry::file_name);
    for registry_entry in registry_directories {
        let registry_path = registry_entry.path();
        let metadata = fs::symlink_metadata(&registry_path)
            .with_context(|| format!("inspect category entry {}", registry_path.display()))?;
        ensure!(
            metadata.file_type().is_dir(),
            "unexpected non-directory category entry: {}",
            registry_path.display()
        );
        let registry = registry_entry.file_name();
        let registry = registry.to_str().with_context(|| {
            format!(
                "category registry directory is not valid UTF-8: {}",
                registry_path.display()
            )
        })?;
        CategoryId::new(registry, "placeholder")
            .with_context(|| format!("invalid category registry directory {registry:?}"))?;
        let mut files = fs::read_dir(&registry_path)
            .with_context(|| format!("read category directory {}", registry_path.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort_by_key(fs::DirEntry::file_name);
        ensure!(
            !files.is_empty(),
            "empty category directory {}",
            registry_path.display()
        );
        for file in files {
            let file_path = file.path();
            let metadata = fs::symlink_metadata(&file_path)
                .with_context(|| format!("inspect category file {}", file_path.display()))?;
            ensure!(
                metadata.file_type().is_file(),
                "external category is not a regular file: {}",
                file_path.display()
            );
            ensure!(
                file_path.extension() == Some(OsStr::new("toml")),
                "external category must have lowercase .toml extension: {}",
                file_path.display()
            );
            let local = file_path
                .file_stem()
                .and_then(|value| value.to_str())
                .with_context(|| {
                    format!(
                        "category filename is not valid UTF-8: {}",
                        file_path.display()
                    )
                })?;
            CategoryId::new(registry, local).with_context(|| {
                format!("invalid external category filename {}", file_path.display())
            })?;
            actual.insert(
                file_path
                    .strip_prefix(root)
                    .expect("category file is below catalog root")
                    .to_path_buf(),
            );
        }
    }
    ensure!(
        actual == *expected,
        "external category inventory differs from references; missing={:?}, orphan={:?}",
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(expected).collect::<Vec<_>>()
    );
    Ok(())
}

/// Loads one canonical generated lock file.
///
/// # Errors
///
/// Returns an error for missing, malformed, unsupported, non-regular, or non-canonical input.
pub fn load_lock(path: &Path) -> Result<RegistryLock> {
    let bytes = read_regular(path)?;
    let lock: RegistryLock = toml::from_slice(&bytes)
        .with_context(|| format!("parse generated lock {}", path.display()))?;
    check_schema(lock.schema, path)?;
    let canonical = serialize_lock(&lock)?;
    ensure!(
        bytes == canonical,
        "generated lock is not in canonical form: {}; run `pkgre-rust lock`",
        path.display()
    );
    Ok(lock)
}

/// Serializes a generated lock deterministically after canonical sorting.
///
/// # Errors
///
/// Returns an error if TOML serialization fails.
pub fn serialize_lock(lock: &RegistryLock) -> Result<Vec<u8>> {
    let mut canonical = lock.clone();
    canonical.names.sort_by(|left, right| {
        (left.name.to_ascii_lowercase(), left.name.as_str())
            .cmp(&(right.name.to_ascii_lowercase(), right.name.as_str()))
    });
    canonical.packages.sort_by(|left, right| {
        (
            left.name.to_ascii_lowercase(),
            left.name.as_str(),
            &left.version,
        )
            .cmp(&(
                right.name.to_ascii_lowercase(),
                right.name.as_str(),
                &right.version,
            ))
    });
    let text = toml::to_string_pretty(&canonical).context("serialize generated registry lock")?;
    Ok(text.into_bytes())
}

/// Validates every immutable old-lock anchor while allowing desired additions and removals.
///
/// This check is intended to run before any network operation.
///
/// # Errors
///
/// Returns an error for a missing lock invariant, changed registry/category/name/source anchor, duplicate identity, or attempted tombstone reactivation.
pub fn validate_input_for_update(input: &RegistryInput) -> Result<()> {
    let Some(lock) = &input.lock else {
        return Ok(());
    };
    validate_registry_identity(input, lock)?;
    let desired_names = desired_names(&input.file)?;
    let locked_names = validate_locked_names(input, lock, &desired_names)?;
    validate_locked_packages(input, lock, &locked_names)?;
    validate_desired_mirrors(input, lock)?;
    validate_desired_tags(input, lock)
}

fn validate_registry_identity(input: &RegistryInput, lock: &RegistryLock) -> Result<()> {
    ensure!(
        lock.registry.name == input.file.registry.name
            && lock.registry.index == input.file.registry.index,
        "immutable registry identity in {} differs from {}",
        input.lock_path.display(),
        input.path.display()
    );
    let before = lock.registry.download.as_str();
    let after = input.file.registry.download.as_str();
    let router = router_download_template(&input.file.registry.name);
    ensure!(
        before == after
            || (before == PUBLISH_DOWNLOAD && after == MIRROR_DOWNLOAD)
            || ((before == MIRROR_DOWNLOAD || before == PUBLISH_DOWNLOAD) && after == router),
        "registry download in {} differs from {}; only a retained historical {PUBLISH_DOWNLOAD:?}→{MIRROR_DOWNLOAD:?} migration or a one-way source-specific→{router:?} migration is allowed",
        input.lock_path.display(),
        input.path.display()
    );
    Ok(())
}

fn validate_locked_names(
    input: &RegistryInput,
    lock: &RegistryLock,
    desired_names: &BTreeMap<String, DesiredName>,
) -> Result<BTreeMap<String, DesiredName>> {
    let mut locked_names = BTreeMap::new();
    for name in &lock.names {
        let locked = DesiredName {
            category: name.category.clone(),
            source: name.source,
        };
        ensure!(
            locked_names
                .insert(name.name.clone(), locked.clone())
                .is_none(),
            "duplicate locked package name {:?} in {}",
            name.name,
            input.lock_path.display()
        );
        ensure!(
            desired_names.get(&name.name) == Some(&locked),
            "locked package name {:?} was removed or changed category/source class in {}; retain the key in its original category with an empty version/tag list",
            name.name,
            input.path.display()
        );
    }
    Ok(locked_names)
}

fn validate_locked_packages(
    input: &RegistryInput,
    lock: &RegistryLock,
    locked_names: &BTreeMap<String, DesiredName>,
) -> Result<()> {
    let mut identities = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for package in &lock.packages {
        let identity = (
            package.name.to_ascii_lowercase().replace('-', "_"),
            version_identity(&package.version),
        );
        ensure!(
            identities.insert(identity),
            "duplicate locked package identity {} {} in {}",
            package.name,
            package.version,
            input.lock_path.display()
        );
        let anchor = locked_names.get(&package.name).with_context(|| {
            format!(
                "locked package {} {} has no permanent name anchor in {}",
                package.name,
                package.version,
                input.lock_path.display()
            )
        })?;
        validate_locked_source(input, package, anchor, &mut tags)?;
    }
    Ok(())
}

fn validate_locked_source<'a>(
    input: &'a RegistryInput,
    package: &'a LockedPackage,
    anchor: &DesiredName,
    tags: &mut BTreeSet<(&'a str, &'a str)>,
) -> Result<()> {
    match &package.source {
        LockedSource::CratesIo {} => {
            ensure!(
                anchor.source == NameSource::Mirror,
                "locked crates.io package {} has non-mirror name anchor",
                package.name
            );
            if let Some(binding) = &package.admission_sha256 {
                super::v3_policy::validate_sha256(binding).with_context(|| {
                    format!(
                        "invalid update-admission binding for {} {}",
                        package.name, package.version
                    )
                })?;
            }
        }
        LockedSource::GitTag {
            git,
            tag,
            package: source_package,
            ..
        } => {
            ensure!(
                package.admission_sha256.is_none(),
                "locked Git package {} unexpectedly has update-admission evidence",
                package.name
            );
            ensure!(
                anchor.source == NameSource::Publish,
                "locked Git package {} has non-publish name anchor",
                package.name
            );
            ensure!(
                source_package == &package.name,
                "locked Git source package {:?} differs from identity {:?}",
                source_package,
                package.name
            );
            let declaration = input
                .file
                .publish_declaration(&package.name)
                .with_context(|| {
                    format!(
                        "locked Git package {:?} has no publish declaration in {}",
                        package.name,
                        input.path.display()
                    )
                })?;
            ensure!(
                declaration.git == *git,
                "Git repository for locked package {} changed",
                package.name
            );
            ensure!(
                tags.insert((package.name.as_str(), tag.as_str())),
                "Git tag {tag:?} is locked more than once for {}",
                package.name
            );
        }
    }
    Ok(())
}

fn validate_desired_mirrors(input: &RegistryInput, lock: &RegistryLock) -> Result<()> {
    for category in input.file.category_values() {
        for (name, versions) in &category.mirror {
            for version in versions {
                if let Some(package) = lock.packages.iter().find(|package| {
                    package.name == *name
                        && version_identity(&package.version) == version_identity(version)
                }) {
                    ensure!(
                        package.state == PackageState::Active,
                        "removed package {name} {version} cannot be reactivated"
                    );
                    ensure!(
                        matches!(package.source, LockedSource::CratesIo {}),
                        "desired mirror {name} {version} has a different locked source"
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_desired_tags(input: &RegistryInput, lock: &RegistryLock) -> Result<()> {
    for category in input.file.category_values() {
        for (name, declaration) in &category.publish {
            for tag in &declaration.tags {
                if let Some(package) = lock.packages.iter().find(|package| {
                    package.name == *name
                        && matches!(&package.source, LockedSource::GitTag { tag: locked, .. } if locked == tag)
                }) {
                    ensure!(
                        package.state == PackageState::Active,
                        "removed Git publication {name} tag {tag:?} cannot be reactivated"
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_input_strict(input: &RegistryInput) -> Result<()> {
    let lock = input.lock.as_ref().with_context(|| {
        format!(
            "generated lock is missing for {}; run `pkgre-rust lock`",
            input.path.display()
        )
    })?;
    ensure!(
        lock.registry.download == input.file.registry.download,
        "registry download in {} is stale; run `pkgre-rust lock`",
        input.lock_path.display()
    );
    let desired_names = desired_names(&input.file)?;
    let locked_names = lock
        .names
        .iter()
        .map(|name| (name.name.as_str(), (name.category.as_str(), name.source)))
        .collect::<BTreeMap<_, _>>();
    let desired_names_borrowed = desired_names
        .iter()
        .map(|(name, anchor)| (name.as_str(), (anchor.category.as_str(), anchor.source)))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        desired_names_borrowed == locked_names,
        "package-name anchors in {} are stale; run `pkgre-rust lock`",
        input.lock_path.display()
    );

    let active_mirrors = lock
        .packages
        .iter()
        .filter(|package| package.state == PackageState::Active)
        .filter_map(|package| match package.source {
            LockedSource::CratesIo {} => {
                Some((package.name.as_str(), version_identity(&package.version)))
            }
            LockedSource::GitTag { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let desired_mirrors = input
        .file
        .category_values()
        .flat_map(|category| &category.mirror)
        .flat_map(|(name, versions)| {
            versions
                .iter()
                .map(move |version| (name.as_str(), version_identity(version)))
        })
        .collect::<BTreeSet<_>>();
    ensure!(
        active_mirrors == desired_mirrors,
        "active mirrored versions in {} are stale; run `pkgre-rust lock`",
        input.lock_path.display()
    );

    let active_tags = lock
        .packages
        .iter()
        .filter(|package| package.state == PackageState::Active)
        .filter_map(|package| match &package.source {
            LockedSource::GitTag { tag, .. } => Some((package.name.as_str(), tag.as_str())),
            LockedSource::CratesIo {} => None,
        })
        .collect::<BTreeSet<_>>();
    let desired_tags = input
        .file
        .category_values()
        .flat_map(|category| &category.publish)
        .flat_map(|(name, declaration)| {
            declaration
                .tags
                .iter()
                .map(move |tag| (name.as_str(), tag.as_str()))
        })
        .collect::<BTreeSet<_>>();
    ensure!(
        active_tags == desired_tags,
        "active Git tags in {} are stale; run `pkgre-rust lock`",
        input.lock_path.display()
    );
    Ok(())
}

pub(crate) fn catalog_from_inputs(root: &Path, inputs: &[RegistryInput]) -> Result<Catalog> {
    ensure!(!inputs.is_empty(), "catalog has no registry declarations");
    let mut categories = BTreeMap::new();
    let mut homes = BTreeMap::new();
    let mut name_sources = BTreeMap::new();
    let mut approvals = Vec::new();
    let mut registries = Vec::new();
    for input in inputs {
        let lock = input
            .lock
            .as_ref()
            .with_context(|| format!("generated lock is missing: {}", input.lock_path.display()))?;
        registries.push(input.file.registry.clone());
        for category in input.file.category_values() {
            ensure!(
                categories
                    .insert(category.id.clone(), category.may_depend_on.clone())
                    .is_none(),
                "duplicate category {}",
                category.id
            );
        }
        for (name, anchor) in desired_names(&input.file)? {
            let category = CategoryId::new(&input.file.registry.name, &anchor.category)
                .expect("desired category identity was validated while loading");
            ensure!(
                homes
                    .insert(
                        name.clone(),
                        PackageHome {
                            registry: input.file.registry.name.clone(),
                            category,
                        },
                    )
                    .is_none(),
                "package {name:?} is declared in more than one category or registry"
            );
            ensure!(
                name_sources.insert(name.clone(), anchor.source).is_none(),
                "package {name:?} has more than one source class"
            );
        }
        let locked_categories = lock
            .names
            .iter()
            .map(|name| (name.name.as_str(), name.category.as_str()))
            .collect::<BTreeMap<_, _>>();
        for package in &lock.packages {
            let local = locked_categories
                .get(package.name.as_str())
                .with_context(|| {
                    format!(
                        "locked package {} {} has no permanent name anchor",
                        package.name, package.version
                    )
                })?;
            approvals.push(Approval {
                registry: input.file.registry.name.clone(),
                category: CategoryId::new(&input.file.registry.name, *local)
                    .expect("locked category was validated against desired declarations"),
                name: package.name.clone(),
                version: package.version.clone(),
                archive_sha256: package.crate_sha256.clone(),
                index_record_sha256: package.source_row_sha256.clone(),
                index_row_sha256: package.index_row_sha256.clone(),
                admission_sha256: package.admission_sha256.clone(),
                state: package.state,
                source: source_from_lock(&package.source),
                declared_in: input.lock_path.clone(),
            });
        }
    }
    registries.sort_by(|left, right| left.name.cmp(&right.name));
    sort_approvals(&mut approvals);
    let cargo_version = registries
        .iter()
        .find(|registry| registry.name == "pkgre")
        .context("catalog has no pkgre registry")?
        .cargo_version
        .clone();
    Ok(Catalog {
        root: root.to_path_buf(),
        registries: RegistriesFile {
            schema: SCHEMA_VERSION,
            cname: CNAME.to_owned(),
            cargo_version,
            registries,
        },
        categories,
        homes: HomesFile {
            schema: SCHEMA_VERSION,
            homes,
        },
        name_sources,
        approvals,
    })
}

fn sort_approvals(approvals: &mut [Approval]) {
    approvals.sort_by(|left, right| {
        (
            left.registry.as_str(),
            left.category.local(),
            left.name.to_ascii_lowercase(),
            left.name.as_str(),
            &left.version,
        )
            .cmp(&(
                right.registry.as_str(),
                right.category.local(),
                right.name.to_ascii_lowercase(),
                right.name.as_str(),
                &right.version,
            ))
    });
}

fn validate_human_package_sets(file: &RegistryFile, path: &Path) -> Result<()> {
    let mut all_names = BTreeSet::new();
    for category in file.category_values() {
        ensure!(
            !(category.mirror.is_empty() && category.publish.is_empty()),
            "category {} in {} must reserve at least one package name",
            category.id,
            category.declared_in.display()
        );
        let targets = category.may_depend_on.iter().collect::<BTreeSet<_>>();
        ensure!(
            targets.len() == category.may_depend_on.len(),
            "category {} repeats a may-depend-on target in {}",
            category.id,
            category.declared_in.display()
        );
        for name in category.mirror.keys() {
            ensure!(
                !category.publish.contains_key(name),
                "package {name:?} appears in both mirror and publish tables in {}",
                category.declared_in.display()
            );
        }
        for (name, versions) in &category.mirror {
            ensure!(
                all_names.insert(name),
                "package {name:?} appears in more than one category in {}",
                path.display()
            );
            let mut identities = BTreeSet::new();
            for version in versions {
                ensure!(
                    identities.insert(version_identity(version)),
                    "mirror package {name:?} repeats version {version} in {}",
                    category.declared_in.display()
                );
            }
        }
        for (name, declaration) in &category.publish {
            ensure!(
                all_names.insert(name),
                "package {name:?} appears in more than one category in {}",
                path.display()
            );
            let mut tags = BTreeSet::new();
            for tag in &declaration.tags {
                ensure!(
                    tags.insert(tag),
                    "publish package {name:?} repeats tag {tag:?} in {}",
                    category.declared_in.display()
                );
            }
        }
    }
    Ok(())
}

fn desired_names(file: &RegistryFile) -> Result<BTreeMap<String, DesiredName>> {
    let mut names = BTreeMap::new();
    for (local, category) in &file.categories {
        for name in category.mirror.keys() {
            ensure!(
                names
                    .insert(
                        name.clone(),
                        DesiredName {
                            category: local.clone(),
                            source: NameSource::Mirror,
                        },
                    )
                    .is_none(),
                "duplicate package {name:?}"
            );
        }
        for name in category.publish.keys() {
            ensure!(
                names
                    .insert(
                        name.clone(),
                        DesiredName {
                            category: local.clone(),
                            source: NameSource::Publish,
                        },
                    )
                    .is_none(),
                "duplicate package {name:?}"
            );
        }
    }
    Ok(names)
}

fn source_from_lock(source: &LockedSource) -> Source {
    match source {
        LockedSource::CratesIo {} => Source::CratesIo,
        LockedSource::GitTag {
            git,
            tag,
            tag_oid,
            commit,
            package,
            path,
            cargo_version,
        } => Source::GitTag {
            repository: git.clone(),
            tag: tag.clone(),
            tag_oid: tag_oid.clone(),
            commit: commit.clone(),
            package: package.clone(),
            subdir: path.clone(),
            cargo_version: cargo_version.clone(),
        },
    }
}

fn load_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = read_regular(path)?;
    toml::from_slice(&bytes).with_context(|| format!("parse TOML {}", path.display()))
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("input is not a regular file: {}", path.display());
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn check_schema(actual: u32, path: &Path) -> Result<()> {
    ensure!(
        actual == SCHEMA_VERSION,
        "unsupported schema {actual} in {}; expected {SCHEMA_VERSION}",
        path.display()
    );
    Ok(())
}

pub(crate) fn version_identity(version: &Version) -> (u64, u64, u64, String) {
    (
        version.major,
        version.minor,
        version.patch,
        version.pre.to_string(),
    )
}
