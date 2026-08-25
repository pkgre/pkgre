//! Strict historical schema-2 catalog loader used only by the one-way migration.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

/// Supported human registry and generated lock schema version.
pub const SCHEMA_VERSION: u32 = 2;
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
    /// Package-name-to-registry routing table derived from human declarations.
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

/// One sparse registry and its permitted dependency layers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Registry {
    /// Stable Cargo registry alias and output directory name.
    pub name: String,
    /// Canonical sparse index URL, including `sparse+` and a trailing slash.
    pub index: String,
    /// Cargo archive download base or template for this registry.
    pub download: String,
    /// Registry homes on which packages in this registry may depend.
    pub may_depend_on: Vec<String>,
    /// Exact Cargo version used for newly published Git-tag packages.
    pub cargo_version: Version,
}

/// Human-edited desired state for one registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryFile {
    /// Schema version.
    pub schema: u32,
    /// Registry topology and packaging configuration.
    pub registry: Registry,
    /// Exact crates.io versions mirrored byte-for-byte; an empty list reserves the name.
    #[serde(default)]
    pub mirror: BTreeMap<String, Vec<Version>>,
    /// First-party packages produced from immutable Git tags.
    #[serde(default)]
    pub publish: BTreeMap<String, PublishDeclaration>,
}

/// Human declaration for one first-party Git repository and its approved tags.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublishDeclaration {
    /// Credential-free HTTPS Git repository.
    pub git: String,
    /// Literal immutable Git tags.
    pub tags: Vec<String>,
}

/// One human registry file and its optional generated lock.
#[derive(Clone, Debug)]
pub struct RegistryInput {
    /// Human file path.
    pub path: PathBuf,
    /// Generated lock path.
    pub lock_path: PathBuf,
    /// Parsed human declaration.
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

/// Permanent source class for one package name.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameSource {
    /// Exact crates.io artifacts mirrored byte-for-byte.
    Mirror,
    /// First-party artifacts produced from Git tags.
    Publish,
}

/// Permanent package-name home and source class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedName {
    /// Cargo package name.
    pub name: String,
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

/// Package-name-to-registry routing table derived from human files.
#[derive(Debug)]
pub struct HomesFile {
    /// Schema version.
    pub schema: u32,
    /// Explicit home for every reserved package name.
    pub homes: BTreeMap<String, String>,
}

/// One active or removed package identity used by policy, verification, and rendering.
#[derive(Clone, Debug)]
pub struct Approval {
    /// Registry home.
    pub registry: String,
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
    /// Active or irreversibly removed state.
    pub state: PackageState,
    /// Immutable origin evidence.
    pub source: Source,
    /// Generated lock used for diagnostics.
    pub declared_in: PathBuf,
}

impl Approval {
    /// Returns whether this package identity has been removed from desired state.
    #[must_use]
    pub fn is_removed(&self) -> bool {
        self.state == PackageState::Removed
    }
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
        catalog_from_inputs(root, &inputs)
    }
}

/// Loads all human registry files and any adjacent generated locks.
///
/// # Errors
///
/// Returns an error for an unsafe root, malformed input, unsupported schema, duplicate registry, or non-canonical lock.
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
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let file: RegistryFile = load_toml(&path)?;
        check_schema(file.schema, &path)?;
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .with_context(|| format!("registry filename is not valid UTF-8: {}", path.display()))?;
        ensure!(
            stem == file.registry.name,
            "registry file {} must be named {}.toml",
            path.display(),
            file.registry.name
        );
        ensure!(
            registries.insert(file.registry.name.clone()),
            "duplicate registry declaration {:?}",
            file.registry.name
        );
        validate_human_package_sets(&file, &path)?;
        let lock_path = path.with_extension("lock");
        let lock = match fs::symlink_metadata(&lock_path) {
            Ok(_) => Some(load_lock(&lock_path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", lock_path.display()));
            }
        };
        inputs.push(RegistryInput {
            path,
            lock_path,
            file,
            lock,
        });
    }
    Ok(inputs)
}

fn validate_catalog_root_entries(paths: &[PathBuf], root: &Path) -> Result<()> {
    for path in paths {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect catalog entry {}", path.display()))?;
        if path.file_name() == Some(OsStr::new("objects")) {
            ensure!(
                metadata.file_type().is_dir(),
                "catalog object store is not a real directory: {}",
                path.display()
            );
            continue;
        }
        match path.extension().and_then(|value| value.to_str()) {
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
                "unexpected entry in catalog root {}: {}; only registry .toml/.lock files and objects/ are allowed",
                root.display(),
                path.display()
            ),
        }
    }
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
    canonical
        .names
        .sort_by(|left, right| left.name.cmp(&right.name));
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
/// Returns an error for a missing lock invariant, changed registry/name/source anchor, duplicate identity, or attempted tombstone reactivation.
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
    ensure!(
        lock.registry.download == input.file.registry.download
            || (lock.registry.download == PUBLISH_DOWNLOAD
                && input.file.registry.download == MIRROR_DOWNLOAD),
        "registry download in {} differs from {}; only the one-way mirror migration from {PUBLISH_DOWNLOAD:?} to {MIRROR_DOWNLOAD:?} is allowed",
        input.lock_path.display(),
        input.path.display()
    );
    Ok(())
}

fn validate_locked_names(
    input: &RegistryInput,
    lock: &RegistryLock,
    desired_names: &BTreeMap<String, NameSource>,
) -> Result<BTreeMap<String, NameSource>> {
    let mut locked_names = BTreeMap::new();
    for name in &lock.names {
        ensure!(
            locked_names
                .insert(name.name.clone(), name.source)
                .is_none(),
            "duplicate locked package name {:?} in {}",
            name.name,
            input.lock_path.display()
        );
        ensure!(
            desired_names.get(&name.name) == Some(&name.source),
            "locked package name {:?} was removed or changed source class in {}; retain the key with an empty version/tag list",
            name.name,
            input.path.display()
        );
    }
    Ok(locked_names)
}

fn validate_locked_packages(
    input: &RegistryInput,
    lock: &RegistryLock,
    locked_names: &BTreeMap<String, NameSource>,
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
        let source_class = locked_names.get(&package.name).with_context(|| {
            format!(
                "locked package {} {} has no permanent name anchor in {}",
                package.name,
                package.version,
                input.lock_path.display()
            )
        })?;
        validate_locked_source(input, package, *source_class, &mut tags)?;
    }
    Ok(())
}

fn validate_locked_source<'a>(
    input: &'a RegistryInput,
    package: &'a LockedPackage,
    source_class: NameSource,
    tags: &mut BTreeSet<(&'a str, &'a str)>,
) -> Result<()> {
    match &package.source {
        LockedSource::CratesIo {} => ensure!(
            source_class == NameSource::Mirror,
            "locked crates.io package {} has non-mirror name anchor",
            package.name
        ),
        LockedSource::GitTag {
            git,
            tag,
            package: source_package,
            ..
        } => {
            ensure!(
                source_class == NameSource::Publish,
                "locked Git package {} has non-publish name anchor",
                package.name
            );
            ensure!(
                source_package == &package.name,
                "locked Git source package {:?} differs from identity {:?}",
                source_package,
                package.name
            );
            let declaration = input.file.publish.get(&package.name).with_context(|| {
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
    for (name, versions) in &input.file.mirror {
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
    Ok(())
}

fn validate_desired_tags(input: &RegistryInput, lock: &RegistryLock) -> Result<()> {
    for (name, declaration) in &input.file.publish {
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
        .map(|name| (name.name.as_str(), name.source))
        .collect::<BTreeMap<_, _>>();
    let desired_names_borrowed = desired_names
        .iter()
        .map(|(name, source)| (name.as_str(), *source))
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
        .mirror
        .iter()
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
        .publish
        .iter()
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
        for (name, source) in desired_names(&input.file)? {
            ensure!(
                homes
                    .insert(name.clone(), input.file.registry.name.clone())
                    .is_none(),
                "package {name:?} is declared in more than one registry"
            );
            ensure!(
                name_sources.insert(name.clone(), source).is_none(),
                "package {name:?} has more than one source class"
            );
        }
        approvals.extend(lock.packages.iter().map(|package| Approval {
            registry: input.file.registry.name.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            archive_sha256: package.crate_sha256.clone(),
            index_record_sha256: package.source_row_sha256.clone(),
            index_row_sha256: package.index_row_sha256.clone(),
            state: package.state,
            source: source_from_lock(&package.source),
            declared_in: input.lock_path.clone(),
        }));
    }
    registries.sort_by(|left, right| left.name.cmp(&right.name));
    approvals.sort_by(|left, right| {
        (
            left.registry.as_str(),
            left.name.to_ascii_lowercase(),
            left.name.as_str(),
            &left.version,
        )
            .cmp(&(
                right.registry.as_str(),
                right.name.to_ascii_lowercase(),
                right.name.as_str(),
                &right.version,
            ))
    });
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
        homes: HomesFile {
            schema: SCHEMA_VERSION,
            homes,
        },
        name_sources,
        approvals,
    })
}

fn validate_human_package_sets(file: &RegistryFile, path: &Path) -> Result<()> {
    for name in file.mirror.keys() {
        ensure!(
            !file.publish.contains_key(name),
            "package {name:?} appears in both mirror and publish tables in {}",
            path.display()
        );
    }
    for (name, versions) in &file.mirror {
        let mut identities = BTreeSet::new();
        for version in versions {
            ensure!(
                identities.insert(version_identity(version)),
                "mirror package {name:?} repeats version {version} in {}",
                path.display()
            );
        }
    }
    for (name, declaration) in &file.publish {
        let mut tags = BTreeSet::new();
        for tag in &declaration.tags {
            ensure!(
                tags.insert(tag),
                "publish package {name:?} repeats tag {tag:?} in {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn desired_names(file: &RegistryFile) -> Result<BTreeMap<String, NameSource>> {
    let mut names = BTreeMap::new();
    for name in file.mirror.keys() {
        ensure!(
            names.insert(name.clone(), NameSource::Mirror).is_none(),
            "duplicate mirror package {name:?}"
        );
    }
    for name in file.publish.keys() {
        ensure!(
            names.insert(name.clone(), NameSource::Publish).is_none(),
            "package {name:?} appears in both mirror and publish tables"
        );
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
