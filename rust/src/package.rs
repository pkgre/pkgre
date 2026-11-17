//! Reproducible first-party package materialization from immutable Git tags.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::artifact::sha256_bytes;
use crate::isolation::{ChildEnvironment, ensure_no_cargo_configuration};
use crate::policy::{
    validate_git_object_id, validate_git_tag, validate_https_repository, validate_package_name,
    validate_relative_path, validate_tag_version,
};
use crate::schema::{Approval, Source};
use crate::update::time::UtcTimestamp;

const CARGO_REGISTRY: &str = "pkgre";
const REGISTRY_INDEX: &str = "sparse+https://rust.pkg.re/";
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 100 * 1024 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Exact bytes, hashes, and immutable Git evidence for one first-party package.
#[derive(Debug)]
pub struct GitTagMaterialization {
    /// Cargo package name.
    pub name: String,
    /// Manifest version discovered at the tag.
    pub version: Version,
    /// Exact tag object ID; equals the commit for a lightweight tag.
    pub tag_oid: String,
    /// Full peeled commit object ID.
    pub commit: String,
    /// Deterministic committer time of the published tag commit.
    pub commit_time: UtcTimestamp,
    /// Repository-relative package directory.
    pub path: PathBuf,
    /// Exact reproducible `.crate` bytes.
    pub archive_bytes: Vec<u8>,
    /// Generated un-routed source index row.
    pub source_row_bytes: Vec<u8>,
    /// SHA-256 of `archive_bytes`.
    pub archive_sha256: String,
    /// SHA-256 of `source_row_bytes`.
    pub source_row_sha256: String,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    name: String,
    version: Version,
    manifest_path: PathBuf,
    dependencies: Vec<MetadataDependency>,
    features: BTreeMap<String, Vec<String>>,
    links: Option<String>,
    rust_version: Option<String>,
    publish: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    source: Option<String>,
    req: String,
    kind: Option<String>,
    rename: Option<String>,
    optional: bool,
    uses_default_features: bool,
    features: Vec<String>,
    target: Option<String>,
    registry: Option<String>,
}

#[derive(Serialize)]
struct IsolatedCargoConfig<'a> {
    registries: BTreeMap<&'static str, CargoRegistry<'a>>,
    registry: CargoDefaultRegistry,
    source: BTreeMap<&'static str, CargoSource<'a>>,
}

#[derive(Serialize)]
struct CargoRegistry<'a> {
    index: &'a str,
}

#[derive(Serialize)]
struct CargoDefaultRegistry {
    default: &'static str,
}

#[derive(Serialize)]
struct CargoSource<'a> {
    #[serde(rename = "replace-with", skip_serializing_if = "Option::is_none")]
    replace_with: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
struct GeneratedIndexRecord<'a> {
    name: &'a str,
    vers: &'a Version,
    deps: Vec<GeneratedDependency>,
    cksum: &'a str,
    features: BTreeMap<String, Vec<String>>,
    yanked: bool,
    links: &'a Option<String>,
    rust_version: &'a Option<String>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct GeneratedDependency {
    name: String,
    req: String,
    features: Vec<String>,
    optional: bool,
    default_features: bool,
    target: Option<String>,
    kind: String,
    registry: Option<String>,
    package: Option<String>,
}

/// Resolves and reproducibly packages one declared first-party Git tag without mutating the catalog.
///
/// Package version and repository-relative path are discovered from the tagged workspace. The exact tag object ID and peeled commit are recorded independently. A path dependency is accepted only on another package that the tagged workspace publishes, since this entry point knows no catalog; [`resolve_git_tag_group`] takes the catalog's own set.
///
/// # Errors
///
/// Returns an error for an unsafe source, ambiguous package, malformed or moved tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty checkout, non-reproducible archive, or invalid package metadata.
pub fn resolve_git_tag(
    repository: &str,
    tag: &str,
    expected_package: &str,
    cargo_version: &Version,
) -> Result<GitTagMaterialization> {
    let packages = [expected_package];
    let mut materializations = resolve_tag(
        &std::env::temp_dir(),
        &TagRequest {
            repository,
            tag,
            packages: &packages,
            published: None,
        },
        &PackagingSource::live(repository),
        cargo_version,
    )?;
    single_materialization(&mut materializations)
}

/// Resolves and reproducibly packages every declared package of one first-party Git tag together.
///
/// One fetch, one metadata run, and one packaging run serve every package of the group, so that a package of the tag may depend on another one. `published` names every package the catalog publishes from this repository and tag, and a path dependency is accepted only on one of them.
///
/// The materializations are returned in the order the packages were requested.
///
/// # Errors
///
/// Returns an error for an empty group, a requested package outside `published`, an unsafe source, ambiguous package, malformed or moved tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty checkout, non-reproducible archive, or invalid package metadata.
pub fn resolve_git_tag_group(
    repository: &str,
    tag: &str,
    packages: &[&str],
    published: &[&str],
    cargo_version: &Version,
) -> Result<Vec<GitTagMaterialization>> {
    resolve_tag(
        &std::env::temp_dir(),
        &TagRequest {
            repository,
            tag,
            packages,
            published: Some(published),
        },
        &PackagingSource::live(repository),
        cargo_version,
    )
}

/// Reproduces one locked Git publication and verifies every immutable source and content field.
///
/// # Errors
///
/// Returns an error for a non-Git approval or any source, tag, package, toolchain, path, archive, or source-row mismatch.
pub fn reproduce_approved_git(approval: &Approval) -> Result<GitTagMaterialization> {
    let Source::GitTag {
        repository,
        tag,
        tag_oid,
        commit,
        package,
        subdir,
        cargo_version,
    } = &approval.source
    else {
        bail!(
            "{} {} is not a Git-tag publication",
            approval.name,
            approval.version
        );
    };
    let materialization = resolve_git_tag(repository, tag, package, cargo_version)?;
    verify_approved_materialization(approval, tag_oid, commit, subdir, &materialization)?;
    Ok(materialization)
}

/// One first-party Git tag whose packages a single resolution materializes.
struct TagRequest<'a> {
    /// Credential-free HTTPS repository the tag belongs to.
    repository: &'a str,
    /// Immutable tag whose packages are materialized.
    tag: &'a str,
    /// Cargo names of the packages to materialize.
    packages: &'a [&'a str],
    /// Every package the catalog publishes from this repository and tag, when
    /// the caller knows it; `None` derives them from the tagged workspace.
    published: Option<&'a [&'a str]>,
}

/// Where one resolution fetches its tag and which registry its manifests resolve from.
struct PackagingSource<'a> {
    /// Repository the packaging fetches, which a test names as a local one.
    fetch_repository: &'a str,
    /// Whether the packaging may fetch a `file:` repository.
    allow_file: bool,
    /// Index of the curated registry that every dependency must name.
    registry_index: &'a str,
}

impl<'a> PackagingSource<'a> {
    /// Returns the source of a live resolution: the network repository and the
    /// index of the curated registry.
    fn live(repository: &'a str) -> Self {
        Self {
            fetch_repository: repository,
            allow_file: false,
            registry_index: REGISTRY_INDEX,
        }
    }
}

/// Returns the only materialization of a one-package resolution.
///
/// # Errors
///
/// Returns an error unless exactly one materialization was produced.
fn single_materialization(
    materializations: &mut Vec<GitTagMaterialization>,
) -> Result<GitTagMaterialization> {
    ensure!(
        materializations.len() == 1,
        "one requested package resolved to {} materializations",
        materializations.len()
    );
    Ok(materializations.remove(0))
}

/// Resolves and reproducibly packages one declared tag from a local repository,
/// which a test names instead of the network.
///
/// # Errors
///
/// Returns an error for an unsafe source, ambiguous package, malformed or moved
/// tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty
/// checkout, non-reproducible archive, or invalid package metadata.
#[cfg(test)]
pub(crate) fn resolve_git_tag_from_file(
    repository: &str,
    tag: &str,
    expected_package: &str,
    cargo_version: &Version,
    fetch_repository: &str,
) -> Result<GitTagMaterialization> {
    resolve_git_tag_from_file_in(
        &std::env::temp_dir(),
        repository,
        tag,
        expected_package,
        cargo_version,
        fetch_repository,
    )
}

/// Resolves and reproducibly packages one declared tag from a local repository
/// below a temporary root a test chooses.
///
/// The root lets a test place Cargo configuration above the working directory
/// that the packaging uses.
///
/// # Errors
///
/// Returns an error for an unsafe source, ambiguous package, malformed or moved
/// tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty
/// checkout, non-reproducible archive, invalid package metadata, or a working
/// directory that Cargo configuration covers.
#[cfg(test)]
pub(crate) fn resolve_git_tag_from_file_in(
    root: &Path,
    repository: &str,
    tag: &str,
    expected_package: &str,
    cargo_version: &Version,
    fetch_repository: &str,
) -> Result<GitTagMaterialization> {
    let packages = [expected_package];
    let mut materializations = resolve_git_tag_group_from_file(&FileTagRequest {
        root,
        repository,
        tag,
        packages: &packages,
        published: None,
        cargo_version,
        fetch_repository,
        registry_index: REGISTRY_INDEX,
    })?;
    single_materialization(&mut materializations)
}

/// One tagged workspace that a test resolves from a local repository and a
/// local registry index.
#[cfg(test)]
pub(crate) struct FileTagRequest<'a> {
    /// Temporary root the packaging works below.
    pub(crate) root: &'a Path,
    /// Credential-free HTTPS repository the tag belongs to.
    pub(crate) repository: &'a str,
    /// Immutable tag whose packages are materialized.
    pub(crate) tag: &'a str,
    /// Cargo names of the packages to materialize.
    pub(crate) packages: &'a [&'a str],
    /// Every package the catalog publishes from this repository and tag.
    pub(crate) published: Option<&'a [&'a str]>,
    /// Pinned Cargo version of the tag.
    pub(crate) cargo_version: &'a Version,
    /// Local repository that a test fetches instead of the network.
    pub(crate) fetch_repository: &'a str,
    /// Local index of the curated registry, so that the packaging needs no network.
    pub(crate) registry_index: &'a str,
}

/// Resolves and reproducibly packages the packages of one tag from a local
/// repository and a local registry index.
///
/// # Errors
///
/// Returns an error for an unsafe source, ambiguous package, malformed or moved
/// tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty
/// checkout, non-reproducible archive, or invalid package metadata.
#[cfg(test)]
pub(crate) fn resolve_git_tag_group_from_file(
    request: &FileTagRequest<'_>,
) -> Result<Vec<GitTagMaterialization>> {
    resolve_tag(
        request.root,
        &TagRequest {
            repository: request.repository,
            tag: request.tag,
            packages: request.packages,
            published: request.published,
        },
        &PackagingSource {
            fetch_repository: request.fetch_repository,
            allow_file: true,
            registry_index: request.registry_index,
        },
        request.cargo_version,
    )
}

fn resolve_tag(
    root: &Path,
    request: &TagRequest<'_>,
    source: &PackagingSource<'_>,
    cargo_version: &Version,
) -> Result<Vec<GitTagMaterialization>> {
    validate_https_repository(request.repository)?;
    validate_git_tag(request.tag)?;
    ensure!(
        !request.packages.is_empty(),
        "no first-party package was named for tag {:?}",
        request.tag
    );
    for package in request.packages {
        validate_package_name(package)?;
    }
    if let Some(published) = request.published {
        for package in request.packages {
            ensure!(
                published.contains(package),
                "package {package:?} is not published from tag {:?}",
                request.tag
            );
        }
    }

    let temporary = TemporaryDirectory::new_in(root, "pkgre-git-package")?;
    let checkout = temporary.path().join("repository");
    let cargo_home = temporary.path().join("cargo-home");
    ensure_no_cargo_configuration(&cargo_home)?;
    let cargo = pinned_cargo(cargo_version)?;
    prepare_cargo_home(&cargo_home, source.registry_index)?;
    let environment = ChildEnvironment::capture(&cargo_home, &cargo)?;

    let (tag_oid, commit) = fetch_tag(
        &environment,
        request.tag,
        &checkout,
        source.fetch_repository,
        source.allow_file,
    )?;
    ensure_safe_checkout_tree(&checkout)?;
    let commit_time = tag_commit_time(&environment, &checkout, &commit)?;
    ensure_clean_checkout(&environment, &checkout)?;
    let root_manifest = checkout.join("Cargo.toml");
    ensure!(
        fs::symlink_metadata(&root_manifest)
            .with_context(|| format!("inspect root manifest {}", root_manifest.display()))?
            .file_type()
            .is_file(),
        "Git repository has no regular root Cargo.toml"
    );
    let metadata = cargo_metadata(&cargo, &cargo_home, &environment, &root_manifest)?;
    let (packages, paths) =
        validated_packages(&metadata, request, &checkout, source.registry_index)?;

    let archives_one = run_cargo_package(
        &cargo,
        &cargo_home,
        &environment,
        &root_manifest,
        &packages,
        &temporary.path().join("target-one"),
    )?;
    let archives_two = run_cargo_package(
        &cargo,
        &cargo_home,
        &environment,
        &root_manifest,
        &packages,
        &temporary.path().join("target-two"),
    )?;
    ensure_clean_checkout(&environment, &checkout)?;

    let mut materializations = Vec::with_capacity(packages.len());
    for (((package, path), archive_bytes), repeated_bytes) in packages
        .iter()
        .zip(paths)
        .zip(archives_one)
        .zip(archives_two)
    {
        ensure!(
            archive_bytes == repeated_bytes,
            "pinned Cargo produced non-deterministic archives for {} {}",
            package.name,
            package.version
        );
        let archive_sha256 = sha256_bytes(&archive_bytes);
        let source_row_bytes = generated_index_record(package, &archive_sha256)?;
        let source_row_sha256 = sha256_bytes(&source_row_bytes);
        materializations.push(GitTagMaterialization {
            name: package.name.clone(),
            version: package.version.clone(),
            tag_oid: tag_oid.clone(),
            commit: commit.clone(),
            commit_time: commit_time.clone(),
            path,
            archive_bytes,
            source_row_bytes,
            archive_sha256,
            source_row_sha256,
        });
    }
    Ok(materializations)
}

/// Reads the committer time of the published tag commit as a deterministic timestamp.
///
/// # Errors
///
/// Returns an error when Git output is malformed or the timestamp is invalid.
fn tag_commit_time(
    environment: &ChildEnvironment,
    repository: &Path,
    commit: &str,
) -> Result<UtcTimestamp> {
    let unix_seconds = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("show"),
                OsString::from("-s"),
                OsString::from("--format=%ct"),
                OsString::from("--no-patch"),
                OsString::from(commit),
            ],
            environment,
        ),
        "read published Git commit time",
    )?;
    let seconds = unix_seconds.trim().parse::<u64>().with_context(|| {
        format!("parse published Git commit time {unix_seconds:?} for commit {commit}")
    })?;
    UtcTimestamp::from_unix_seconds(seconds)
}

fn verify_approved_materialization(
    approval: &Approval,
    expected_tag_oid: &str,
    expected_commit: &str,
    expected_path: &Path,
    materialization: &GitTagMaterialization,
) -> Result<()> {
    ensure!(
        materialization.name == approval.name && materialization.version == approval.version,
        "Git publication identity changed for {} {}",
        approval.name,
        approval.version
    );
    ensure!(
        materialization.tag_oid == expected_tag_oid,
        "Git tag object changed for {} {}: expected {expected_tag_oid}, got {}",
        approval.name,
        approval.version,
        materialization.tag_oid
    );
    ensure!(
        materialization.commit == expected_commit,
        "Git tag commit changed for {} {}: expected {expected_commit}, got {}",
        approval.name,
        approval.version,
        materialization.commit
    );
    ensure!(
        materialization.path == expected_path,
        "Git package path changed for {} {}: expected {}, got {}",
        approval.name,
        approval.version,
        expected_path.display(),
        materialization.path.display()
    );
    ensure!(
        materialization.archive_sha256 == approval.archive_sha256,
        "Git archive hash changed for {} {}: expected {}, got {}",
        approval.name,
        approval.version,
        approval.archive_sha256,
        materialization.archive_sha256
    );
    ensure!(
        materialization.source_row_sha256 == approval.index_record_sha256,
        "Git source-row hash changed for {} {}: expected {}, got {}",
        approval.name,
        approval.version,
        approval.index_record_sha256,
        materialization.source_row_sha256
    );
    Ok(())
}

fn fetch_tag(
    environment: &ChildEnvironment,
    tag: &str,
    repository: &Path,
    fetch_repository: &str,
    allow_file: bool,
) -> Result<(String, String)> {
    run_git(
        None,
        [
            OsString::from("init"),
            OsString::from("--quiet"),
            path_arg(repository),
        ],
        environment,
    )?;
    run_git(
        Some(repository),
        [
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            OsString::from(fetch_repository),
        ],
        environment,
    )?;
    let reference = format!("refs/tags/{tag}");
    let fetch_arguments = [
        OsString::from("fetch"),
        OsString::from("--quiet"),
        OsString::from("--no-tags"),
        OsString::from("--depth=1"),
        OsString::from("origin"),
        OsString::from(format!("{reference}:{reference}")),
    ];
    let fetch_command =
        git_command_with_file_policy(Some(repository), fetch_arguments, environment, allow_file);
    run_command(fetch_command, "fetch exact Git tag")?;
    let tag_oid = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(&reference),
            ],
            environment,
        ),
        "resolve fetched Git tag object",
    )?;
    let commit = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(format!("{reference}^{{commit}}")),
            ],
            environment,
        ),
        "peel fetched Git tag",
    )?;
    validate_git_object_id(&tag_oid).context("invalid fetched Git tag object ID")?;
    validate_git_object_id(&commit).context("invalid fetched Git commit ID")?;
    run_git(
        Some(repository),
        [
            OsString::from("checkout"),
            OsString::from("--quiet"),
            OsString::from("--detach"),
            OsString::from(&commit),
            OsString::from("--"),
        ],
        environment,
    )?;
    let gitlinks = command_stdout(
        git_command(
            Some(repository),
            [OsString::from("ls-files"), OsString::from("--stage")],
            environment,
        ),
        "list checked-out Git files",
    )?;
    ensure!(
        !gitlinks.lines().any(|line| line.starts_with("160000 ")),
        "Git-tag checkout contains unsupported submodules"
    );
    Ok((tag_oid, commit))
}

pub(crate) fn ensure_safe_checkout_tree(repository: &Path) -> Result<()> {
    inspect_checkout_directory(repository, repository)
}

fn inspect_checkout_directory(repository: &Path, directory: &Path) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read Git checkout directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("read entries below {}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().with_context(|| {
            format!(
                "Git checkout contains a non-UTF-8 path below {}",
                directory.display()
            )
        })?;
        if directory == repository && name == ".git" {
            continue;
        }
        ensure!(
            name.is_ascii()
                && !name
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'\\')
                && !name.eq_ignore_ascii_case(".git"),
            "Git checkout contains an unsafe path component {name:?} below {}",
            directory.display()
        );
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect Git checkout path {}", path.display()))?;
        if metadata.file_type().is_dir() {
            inspect_checkout_directory(repository, &path)?;
        } else {
            ensure!(
                metadata.file_type().is_file(),
                "Git checkout contains a symlink or special file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn ensure_clean_checkout(environment: &ChildEnvironment, repository: &Path) -> Result<()> {
    let status = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("status"),
                OsString::from("--porcelain=v1"),
                OsString::from("--untracked-files=all"),
            ],
            environment,
        ),
        "inspect Git checkout cleanliness",
    )?;
    ensure!(status.is_empty(), "Git-tag checkout is dirty: {status}");
    Ok(())
}

fn package_path(repository: &Path, manifest_path: &Path) -> Result<PathBuf> {
    let repository = fs::canonicalize(repository)
        .with_context(|| format!("canonicalize repository {}", repository.display()))?;
    let manifest = fs::canonicalize(manifest_path)
        .with_context(|| format!("canonicalize manifest {}", manifest_path.display()))?;
    let directory = manifest
        .parent()
        .context("package manifest has no parent")?;
    let relative = directory.strip_prefix(&repository).with_context(|| {
        format!(
            "package manifest {} is outside repository {}",
            manifest.display(),
            repository.display()
        )
    })?;
    let relative = if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative.to_path_buf()
    };
    validate_relative_path(&relative, true)?;
    Ok(relative)
}

pub(crate) fn pinned_cargo(version: &Version) -> Result<PathBuf> {
    let path = if let Some(configured) = std::env::var_os("PKGRE_CARGO") {
        let configured = PathBuf::from(configured);
        ensure!(
            configured.is_absolute(),
            "PKGRE_CARGO must be an absolute path"
        );
        fs::canonicalize(&configured)
            .with_context(|| format!("canonicalize PKGRE_CARGO {}", configured.display()))?
    } else {
        let mut command = Command::new("rustup");
        command.args(["which", "--toolchain", &version.to_string(), "cargo"]);
        let path = command_stdout(command, "locate pinned Cargo")?;
        let path = PathBuf::from(path);
        ensure!(
            path.is_absolute(),
            "rustup returned a non-absolute Cargo path"
        );
        path
    };
    ensure!(
        fs::symlink_metadata(&path)
            .with_context(|| format!("inspect pinned Cargo {}", path.display()))?
            .file_type()
            .is_file(),
        "pinned Cargo is not a regular file: {}",
        path.display()
    );
    let mut version_command = Command::new(&path);
    version_command.arg("--version");
    let actual = command_stdout(version_command, "inspect pinned Cargo version")?;
    let expected_prefix = format!("cargo {version} ");
    ensure!(
        actual.starts_with(&expected_prefix),
        "Cargo version mismatch: expected {version}, got {actual:?}"
    );
    Ok(path)
}

fn prepare_cargo_home(cargo_home: &Path, registry_index: &str) -> Result<()> {
    fs::create_dir(cargo_home)
        .with_context(|| format!("create isolated Cargo home {}", cargo_home.display()))?;
    let disabled = cargo_home.join("disabled-crates-io");
    fs::create_dir(&disabled)
        .with_context(|| format!("create disabled Cargo source {}", disabled.display()))?;
    let registries = BTreeMap::from([(
        CARGO_REGISTRY,
        CargoRegistry {
            index: registry_index,
        },
    )]);
    let source = BTreeMap::from([
        (
            "crates-io",
            CargoSource {
                replace_with: Some("disabled"),
                directory: None,
            },
        ),
        (
            "disabled",
            CargoSource {
                replace_with: None,
                directory: Some(disabled.as_path()),
            },
        ),
    ]);
    let config = IsolatedCargoConfig {
        registries,
        registry: CargoDefaultRegistry {
            default: CARGO_REGISTRY,
        },
        source,
    };
    let contents = toml::to_string_pretty(&config).context("serialize isolated Cargo config")?;
    fs::write(cargo_home.join("config.toml"), contents)
        .with_context(|| format!("write isolated Cargo config below {}", cargo_home.display()))
}

fn is_curated_registry_source(source: &str, registry_indexes: &[&str]) -> bool {
    registry_indexes.contains(&source)
        || source
            .strip_prefix("registry+")
            .is_some_and(|index| registry_indexes.contains(&index))
}

fn cargo_metadata(
    cargo: &Path,
    cargo_home: &Path,
    environment: &ChildEnvironment,
    manifest_path: &Path,
) -> Result<Vec<MetadataPackage>> {
    let mut command = isolated_cargo(cargo, environment);
    command.current_dir(cargo_home).args([
        OsStr::new("metadata"),
        OsStr::new("--format-version"),
        OsStr::new("1"),
        OsStr::new("--no-deps"),
        OsStr::new("--locked"),
        OsStr::new("--manifest-path"),
        manifest_path.as_os_str(),
    ]);
    let output = run_command(command, "read Cargo package metadata")?;
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).context("parse pinned Cargo metadata output")?;
    ensure!(
        !metadata.packages.is_empty(),
        "Cargo metadata holds no package"
    );
    Ok(metadata.packages)
}

/// Selects and validates the requested packages of one tagged workspace.
///
/// Returns the packages and their repository-relative paths.
///
/// # Errors
///
/// Returns an error for a package the workspace does not hold exactly once, one
/// outside the tag's version or publication, or an invalid dependency.
fn validated_packages<'a>(
    metadata: &'a [MetadataPackage],
    request: &TagRequest<'_>,
    checkout: &Path,
    registry_index: &str,
) -> Result<(Vec<&'a MetadataPackage>, Vec<PathBuf>)> {
    let packages = select_packages(metadata, request.packages)?;
    let mut paths = Vec::with_capacity(packages.len());
    for package in &packages {
        validate_tag_version(request.tag, &package.version)?;
        ensure!(
            package.publish.as_deref() == Some(&[CARGO_REGISTRY.to_owned()]),
            "first-party package must set publish = [{CARGO_REGISTRY:?}] exactly"
        );
        paths.push(package_path(checkout, &package.manifest_path)?);
    }
    let tag_version = packages
        .first()
        .with_context(|| format!("tag {:?} names no package", request.tag))?
        .version
        .clone();
    let published = published_packages(request.published, metadata);
    for package in &packages {
        validate_dependencies(package, metadata, &published, &tag_version, registry_index)?;
    }
    Ok((packages, paths))
}

/// Selects the requested packages from the metadata of one tagged workspace.
///
/// # Errors
///
/// Returns an error for a requested package that the workspace does not hold
/// exactly once.
fn select_packages<'a>(
    metadata: &'a [MetadataPackage],
    packages: &[&str],
) -> Result<Vec<&'a MetadataPackage>> {
    let mut selected = Vec::with_capacity(packages.len());
    for name in packages {
        let mut matching = metadata.iter().filter(|package| package.name == *name);
        let package = matching
            .next()
            .with_context(|| format!("Cargo metadata has no package named {name:?}"))?;
        ensure!(
            matching.next().is_none(),
            "Cargo metadata contains more than one package named {name:?}"
        );
        selected.push(package);
    }
    Ok(selected)
}

/// Returns every package that a path dependency of one tag may point at.
///
/// The catalog's own set when the caller names it, and otherwise every package
/// the tagged workspace publishes to the curated registry.
fn published_packages(
    published: Option<&[&str]>,
    metadata: &[MetadataPackage],
) -> BTreeSet<String> {
    match published {
        Some(published) => published.iter().map(|name| (*name).to_owned()).collect(),
        None => metadata
            .iter()
            .filter(|package| package.publish.as_deref() == Some(&[CARGO_REGISTRY.to_owned()]))
            .map(|package| package.name.clone())
            .collect(),
    }
}

/// Validates every dependency of one first-party package of a tag.
///
/// A dependency must name the curated registry, whether Cargo takes it from
/// that registry or from a path inside the tagged workspace.
///
/// # Errors
///
/// Returns an error for an unpinned source, a path dependency outside the
/// packages the catalog publishes from this tag, a requirement that is not the
/// tag's own version, or a package of another version.
fn validate_dependencies(
    package: &MetadataPackage,
    metadata: &[MetadataPackage],
    published: &BTreeSet<String>,
    tag_version: &Version,
    registry_index: &str,
) -> Result<()> {
    let registry_indexes = [registry_index];
    for dependency in &package.dependencies {
        let Some(source) = &dependency.source else {
            validate_path_dependency(
                dependency,
                metadata,
                published,
                tag_version,
                &registry_indexes,
            )?;
            continue;
        };
        ensure!(
            is_curated_registry_source(source, &registry_indexes),
            "first-party package dependency {} uses unsupported source {source:?}; use registry = {CARGO_REGISTRY:?} explicitly",
            dependency.name
        );
        ensure!(
            dependency
                .registry
                .as_deref()
                .is_some_and(|index| registry_indexes.contains(&index)),
            "first-party package dependency {} does not declare a canonical curated registry",
            dependency.name
        );
    }
    Ok(())
}

/// Validates one dependency that Cargo takes from a path inside the tagged
/// workspace.
///
/// Such a dependency is accepted only on another package the catalog publishes
/// from the same repository and tag, at the tag's version, and only when it
/// names the curated registry and requires exactly the tag's version, since the
/// packaged manifest carries no path.
///
/// # Errors
///
/// Returns an error for a missing registry declaration, a requirement that is
/// not `=X.Y.Z` of the tag, a target outside the tagged workspace, a target the
/// catalog does not publish from this tag, or a target of another version.
fn validate_path_dependency(
    dependency: &MetadataDependency,
    metadata: &[MetadataPackage],
    published: &BTreeSet<String>,
    tag_version: &Version,
    registry_indexes: &[&str],
) -> Result<()> {
    ensure!(
        dependency
            .registry
            .as_deref()
            .is_some_and(|index| registry_indexes.contains(&index)),
        "first-party package dependency {} is a path dependency that does not declare registry = {CARGO_REGISTRY:?}; a package of the same tag must be required from the curated registry",
        dependency.name
    );
    let exact = format!("={tag_version}");
    let expected = VersionReq::parse(&exact).context("build the exact requirement of the tag")?;
    ensure!(
        VersionReq::parse(&dependency.req).is_ok_and(|requirement| requirement == expected),
        "first-party package dependency {} requires {:?}; a path dependency on a package of the same tag must require exactly {exact:?}",
        dependency.name,
        dependency.req
    );
    let target = metadata
        .iter()
        .find(|candidate| candidate.name == dependency.name)
        .with_context(|| {
            format!(
                "first-party package dependency {} is a path dependency on no package of the tagged workspace",
                dependency.name
            )
        })?;
    ensure!(
        published.contains(&target.name),
        "first-party package dependency {} is a path dependency on {}, which the catalog does not publish from this tag",
        dependency.name,
        target.name
    );
    ensure!(
        target.version == *tag_version,
        "first-party package dependency {} is a path dependency on {} {}, whose version is not the tag's version {tag_version}",
        dependency.name,
        target.name,
        target.version
    );
    Ok(())
}

/// Packages the requested members of one tagged workspace into one target
/// directory and returns their archives in the requested order.
///
/// # Errors
///
/// Returns an error when Cargo fails, or when an archive is missing, too large,
/// or not a regular file.
fn run_cargo_package(
    cargo: &Path,
    cargo_home: &Path,
    environment: &ChildEnvironment,
    manifest_path: &Path,
    packages: &[&MetadataPackage],
    target: &Path,
) -> Result<Vec<Vec<u8>>> {
    let mut command = isolated_cargo(cargo, environment);
    command.current_dir(cargo_home).args([
        OsStr::new("package"),
        OsStr::new("--no-verify"),
        OsStr::new("--locked"),
    ]);
    for package in packages {
        command
            .arg(OsStr::new("--package"))
            .arg(OsStr::new(&package.name));
    }
    command.args([
        OsStr::new("--manifest-path"),
        manifest_path.as_os_str(),
        OsStr::new("--target-dir"),
        target.as_os_str(),
    ]);
    run_command(command, "package first-party crates")?;
    let mut archives = Vec::with_capacity(packages.len());
    for package in packages {
        let archive = target
            .join("package")
            .join(format!("{}-{}.crate", package.name, package.version));
        ensure!(
            fs::symlink_metadata(&archive)
                .with_context(|| format!("inspect Cargo archive {}", archive.display()))?
                .file_type()
                .is_file(),
            "Cargo did not produce a regular archive at {}",
            archive.display()
        );
        archives.push(read_bounded_archive(&archive)?);
    }
    Ok(archives)
}

pub(crate) fn read_bounded_archive(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect package archive {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_ARCHIVE_BYTES,
        "package archive {} exceeds {} bytes",
        path.display(),
        MAX_ARCHIVE_BYTES
    );
    fs::read(path).with_context(|| format!("read package archive {}", path.display()))
}

fn isolated_cargo(cargo: &Path, environment: &ChildEnvironment) -> Command {
    let mut command = Command::new(cargo);
    environment.apply_with(
        &mut command,
        &[
            ("CARGO_TERM_COLOR", OsStr::new("never")),
            ("CARGO_NET_GIT_FETCH_WITH_CLI", OsStr::new("false")),
        ],
    );
    command
}

fn generated_index_record(package: &MetadataPackage, checksum: &str) -> Result<Vec<u8>> {
    let mut dependencies = Vec::new();
    for dependency in &package.dependencies {
        let kind = dependency.kind.as_deref().unwrap_or("normal");
        ensure!(
            matches!(kind, "normal" | "dev" | "build"),
            "unsupported Cargo dependency kind {kind:?}"
        );
        let mut features = dependency.features.clone();
        features.sort();
        ensure!(
            features.windows(2).all(|window| window[0] != window[1]),
            "dependency {} repeats a feature",
            dependency.name
        );
        let (name, renamed_package) = match &dependency.rename {
            Some(rename) => (rename.clone(), Some(dependency.name.clone())),
            None => (dependency.name.clone(), None),
        };
        dependencies.push(GeneratedDependency {
            name,
            req: dependency.req.clone(),
            features,
            optional: dependency.optional,
            default_features: dependency.uses_default_features,
            target: dependency.target.clone(),
            kind: kind.to_owned(),
            registry: dependency.registry.clone(),
            package: renamed_package,
        });
    }
    dependencies.sort();

    let mut features = package.features.clone();
    for values in features.values_mut() {
        values.sort();
        ensure!(
            values.windows(2).all(|window| window[0] != window[1]),
            "package feature repeats an enabled feature"
        );
    }
    let record = GeneratedIndexRecord {
        name: &package.name,
        vers: &package.version,
        deps: dependencies,
        cksum: checksum,
        features,
        yanked: false,
        links: &package.links,
        rust_version: &package.rust_version,
    };
    let mut bytes = serde_json::to_vec(&record).context("serialize generated index record")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn run_git<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    environment: &ChildEnvironment,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let command = git_command(current_dir, arguments, environment);
    run_command(command, "run Git command")?;
    Ok(())
}

fn git_command<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    environment: &ChildEnvironment,
) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    git_command_with_file_policy(current_dir, arguments, environment, false)
}

fn git_command_with_file_policy<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
    environment: &ChildEnvironment,
    allow_file: bool,
) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let file_policy = if allow_file { "always" } else { "never" };
    let mut command = Command::new("git");
    command
        .args([
            OsStr::new("-c"),
            OsStr::new("core.hooksPath=/dev/null"),
            OsStr::new("-c"),
            OsStr::new("protocol.allow=never"),
            OsStr::new("-c"),
            OsStr::new("protocol.https.allow=always"),
            OsStr::new("-c"),
            OsStr::new(&format!("protocol.file.allow={file_policy}")),
        ])
        .args(arguments);
    environment.apply_with(
        &mut command,
        &[
            ("GIT_TERMINAL_PROMPT", OsStr::new("0")),
            ("GIT_CONFIG_NOSYSTEM", OsStr::new("1")),
            ("GIT_CONFIG_GLOBAL", OsStr::new("/dev/null")),
        ],
    );
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command
}

fn run_command(mut command: Command, action: &str) -> Result<Output> {
    debug!(?command, %action, "running isolated package command");
    let output = command
        .output()
        .with_context(|| format!("{action}: start command"))?;
    if !output.status.success() {
        let stdout = bounded_lossy(&output.stdout);
        let stderr = bounded_lossy(&output.stderr);
        bail!(
            "{action}: command exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
    Ok(output)
}

fn command_stdout(command: Command, action: &str) -> Result<String> {
    let output = run_command(command, action)?;
    let value =
        String::from_utf8(output.stdout).with_context(|| format!("{action}: non-UTF-8 stdout"))?;
    Ok(value.trim().to_owned())
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn path_arg(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}

pub(crate) struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    pub(crate) fn new(prefix: &str) -> Result<Self> {
        Self::new_in(&std::env::temp_dir(), prefix)
    }

    /// Creates one unique temporary directory below `root`.
    pub(crate) fn new_in(root: &Path, prefix: &str) -> Result<Self> {
        for _ in 0..100 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("{prefix}-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create temporary directory {}", path.display()));
                }
            }
        }
        bail!("could not allocate a unique temporary directory")
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::PackageState;
    use serde_json::Value;

    #[test]
    fn curated_registry_source_accepts_sparse_metadata_forms() {
        let indexes = ["sparse+https://example.test/core/"];
        assert!(is_curated_registry_source(indexes[0], &indexes));
        assert!(is_curated_registry_source(
            "registry+sparse+https://example.test/core/",
            &indexes
        ));
        assert!(!is_curated_registry_source(
            "registry+https://github.com/rust-lang/crates.io-index",
            &indexes
        ));
    }

    #[test]
    fn generated_record_routes_renamed_dependency_identity() {
        let package = MetadataPackage {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            manifest_path: PathBuf::from("Cargo.toml"),
            dependencies: vec![MetadataDependency {
                name: "actual".to_owned(),
                source: Some("registry+https://example.test/index".to_owned()),
                req: "^1".to_owned(),
                kind: None,
                rename: Some("alias".to_owned()),
                optional: true,
                uses_default_features: false,
                features: vec!["feature".to_owned()],
                target: Some("cfg(unix)".to_owned()),
                registry: Some("sparse+https://example.test/core/".to_owned()),
            }],
            features: BTreeMap::new(),
            links: None,
            rust_version: Some("1.85".to_owned()),
            publish: Some(vec![CARGO_REGISTRY.to_owned()]),
        };
        let record = generated_index_record(&package, &"01".repeat(32)).unwrap();
        let value: Value = serde_json::from_slice(&record).unwrap();
        assert_eq!(value["deps"][0]["name"], "alias");
        assert_eq!(value["deps"][0]["package"], "actual");
        assert_eq!(value["deps"][0]["kind"], "normal");
    }

    const TEST_TAG: &str = "release/pkgre-demo/v1.2.3";

    #[test]
    fn git_tag_materialization_records_tag_and_is_reproducible() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-e2e").unwrap();
        let source = create_test_release(&temporary);
        let source_url = source.to_str().unwrap();
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let materialization = resolve_git_tag_from_file_in(
            &root,
            "https://example.invalid/pkgre-demo",
            TEST_TAG,
            "pkgre-demo",
            &cargo_version,
            source_url,
        )
        .unwrap();
        assert_eq!(materialization.name, "pkgre-demo");
        assert_eq!(materialization.version, Version::parse("1.2.3").unwrap());
        assert_eq!(materialization.path, Path::new("crates/demo"));
        assert_ne!(materialization.tag_oid, materialization.commit);
        assert_eq!(
            sha256_bytes(&materialization.archive_bytes),
            materialization.archive_sha256
        );
        assert_eq!(
            sha256_bytes(&materialization.source_row_bytes),
            materialization.source_row_sha256
        );

        let approval = test_approval(&materialization, &cargo_version);
        verify_approved_materialization(
            &approval,
            &materialization.tag_oid,
            &materialization.commit,
            &materialization.path,
            &materialization,
        )
        .unwrap();
    }

    #[test]
    fn git_tag_packaging_refuses_cargo_configuration_above_the_working_directory() {
        let temporary =
            TemporaryDirectory::new_in(&uncovered_temporary_root(), "pkgre-git-config").unwrap();
        let source = create_test_release(&temporary);
        let root = temporary.path().join("covered");
        let configuration = root.join(".cargo");
        fs::create_dir_all(&configuration).unwrap();
        let file = configuration.join("config.toml");
        fs::write(&file, "[net]\noffline = true\n").unwrap();
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let error = resolve_git_tag_from_file_in(
            &root,
            "https://example.invalid/pkgre-demo",
            TEST_TAG,
            "pkgre-demo",
            &cargo_version,
            source.to_str().unwrap(),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(&file.display().to_string()),
            "the error names the configuration it found: {message}"
        );
        assert!(
            message.contains("TMPDIR"),
            "the error says what to change: {message}"
        );
    }

    /// Returns the first of `TMPDIR`, `/tmp`, and `/var/tmp` that no Cargo
    /// configuration covers.
    ///
    /// The packaging refuses a temporary directory that Cargo configuration
    /// covers, and a development environment or a build sandbox may point
    /// `TMPDIR` into one.
    fn uncovered_temporary_root() -> PathBuf {
        for root in [
            std::env::temp_dir(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ] {
            if ensure_no_cargo_configuration(&root).is_ok() {
                return root;
            }
        }
        panic!("no temporary directory without Cargo configuration is available");
    }

    fn create_test_release(temporary: &TemporaryDirectory) -> PathBuf {
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("crates/demo/src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"pkgre-demo\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\npublish = [\"pkgre\"]\n",
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&source));
        test_git(&source, &["add", "."]);
        test_git(&source, &["commit", "--quiet", "-m", "release"]);
        run_test_command(
            Command::new("cargo")
                .current_dir(&source)
                .env("CARGO_HOME", temporary.path().join("lock-cargo-home"))
                .arg("generate-lockfile"),
        );
        test_git(&source, &["add", "Cargo.lock"]);
        test_git(&source, &["commit", "--quiet", "-m", "lock"]);
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre-demo 1.2.3"]);
        source
    }

    /// The dependency line that a sibling fixture's dependent crate carries.
    const SIBLING_DEPENDENCY: &str =
        "pkgre-base = { path = \"../base\", version = \"=1.2.3\", registry = \"pkgre\" }";

    /// Writes a local registry index for the curated registry and returns its
    /// `file:` URL.
    ///
    /// The packaging cannot reach the sparse index of the real registry, and
    /// Cargo loads the index of every registry that a packaged manifest names,
    /// so a test serves its own: an empty index that a test can add entries to.
    fn create_test_index(temporary: &TemporaryDirectory) -> String {
        let index = temporary.path().join("index");
        fs::create_dir_all(&index).unwrap();
        fs::write(
            index.join("config.json"),
            format!(
                "{{\"dl\":\"file://{}/crates\",\"api\":null}}\n",
                index.display()
            ),
        )
        .unwrap();
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&index));
        test_git(&index, &["add", "."]);
        test_git(&index, &["commit", "--quiet", "-m", "index"]);
        format!("file://{}", index.display())
    }

    /// Adds one package version to a test registry index.
    fn publish_test_index_entry(index: &str, name: &str, version: &Version, checksum: &str) {
        let root = Path::new(index.trim_start_matches("file://"));
        let entry = root.join(crate::index::index_path(name));
        fs::create_dir_all(entry.parent().unwrap()).unwrap();
        fs::write(
            &entry,
            format!(
                "{{\"name\":{name:?},\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}\n"
            ),
        )
        .unwrap();
        test_git(root, &["add", "."]);
        test_git(
            root,
            &["commit", "--quiet", "-m", &format!("{name} {version}")],
        );
    }

    /// Creates a tagged two-crate workspace where `pkgre-demo` depends on
    /// `pkgre-base` through `dependency`, and returns the repository.
    fn create_test_sibling_release(
        temporary: &TemporaryDirectory,
        index: &str,
        base_publish: &str,
        dependency: &str,
    ) -> PathBuf {
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("crates/demo/src")).unwrap();
        fs::create_dir_all(source.join("crates/base/src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\", \"crates/base\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        fs::write(
            source.join("crates/base/Cargo.toml"),
            format!(
                "[package]\nname = \"pkgre-base\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\n{base_publish}\n"
            ),
        )
        .unwrap();
        fs::write(
            source.join("crates/base/src/lib.rs"),
            "pub fn base() -> u32 { 1 }\n",
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/Cargo.toml"),
            format!(
                "[package]\nname = \"pkgre-demo\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\npublish = [\"pkgre\"]\n\n[dependencies]\n{dependency}\n"
            ),
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&source));
        test_git(&source, &["add", "."]);
        test_git(&source, &["commit", "--quiet", "-m", "release"]);
        let lock_home = temporary.path().join("lock-cargo-home");
        fs::create_dir_all(&lock_home).unwrap();
        fs::write(
            lock_home.join("config.toml"),
            format!("[registries.pkgre]\nindex = {index:?}\n"),
        )
        .unwrap();
        run_test_command(
            Command::new("cargo")
                .current_dir(&source)
                .env("CARGO_HOME", &lock_home)
                .arg("generate-lockfile"),
        );
        test_git(&source, &["add", "Cargo.lock"]);
        test_git(&source, &["commit", "--quiet", "-m", "lock"]);
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre 1.2.3"]);
        source
    }

    /// Resolves the named packages of the sibling fixture's tag.
    fn resolve_test_group(
        root: &Path,
        source: &Path,
        index: &str,
        packages: &[&str],
        published: &[&str],
    ) -> Result<Vec<GitTagMaterialization>> {
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        resolve_git_tag_group_from_file(&FileTagRequest {
            root,
            repository: "https://example.invalid/pkgre-demo",
            tag: TEST_TAG,
            packages,
            published: Some(published),
            cargo_version: &cargo_version,
            fetch_repository: source.to_str().unwrap(),
            registry_index: index,
        })
    }

    #[test]
    fn one_tag_packages_a_crate_that_depends_on_a_sibling() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let published = ["pkgre-demo", "pkgre-base"];

        let materializations =
            resolve_test_group(&root, &source, &index, &published, &published).unwrap();

        let [demo, base] = materializations.as_slice() else {
            panic!(
                "one tag of two packages resolved to {} materializations",
                materializations.len()
            );
        };
        assert_eq!(demo.name, "pkgre-demo");
        assert_eq!(demo.path, Path::new("crates/demo"));
        assert_eq!(base.name, "pkgre-base");
        assert_eq!(base.path, Path::new("crates/base"));
        assert_eq!(demo.version, Version::parse("1.2.3").unwrap());
        assert_eq!(base.version, demo.version);
        assert_eq!(demo.tag_oid, base.tag_oid);
        assert_eq!(demo.commit, base.commit);
        let row: Value = serde_json::from_slice(&demo.source_row_bytes).unwrap();
        assert_eq!(row["deps"][0]["name"], "pkgre-base");
        assert_eq!(row["deps"][0]["req"], "=1.2.3");
        assert_eq!(row["deps"][0]["registry"], index.as_str());

        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &demo.version,
            &demo.archive_bytes,
            &["Cargo.lock"],
        )
        .unwrap();
        let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
        assert!(
            lock.contains(&format!("checksum = \"{}\"", base.archive_sha256)),
            "the packaged lock records the sibling's archive checksum: {lock}"
        );

        let repeated = resolve_test_group(&root, &source, &index, &published, &published).unwrap();
        assert_eq!(repeated[0].archive_bytes, demo.archive_bytes);
        assert_eq!(repeated[1].archive_bytes, base.archive_bytes);
    }

    #[test]
    fn a_locked_sibling_of_the_same_tag_resolves_from_the_registry_index() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-locked").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let published = ["pkgre-demo", "pkgre-base"];
        let group = resolve_test_group(&root, &source, &index, &published, &published).unwrap();

        // The catalog already locked the sibling, so this tag's group packages
        // the dependent alone and Cargo takes the sibling from the registry.
        publish_test_index_entry(
            &index,
            "pkgre-base",
            &group[1].version,
            &group[1].archive_sha256,
        );
        let alone =
            resolve_test_group(&root, &source, &index, &["pkgre-demo"], &published).unwrap();

        assert_eq!(alone.len(), 1);
        assert_eq!(alone[0].archive_bytes, group[0].archive_bytes);
        assert_eq!(alone[0].archive_sha256, group[0].archive_sha256);
        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &alone[0].version,
            &alone[0].archive_bytes,
            &["Cargo.lock"],
        )
        .unwrap();
        let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
        assert!(
            lock.contains(&format!("checksum = \"{}\"", group[1].archive_sha256)),
            "the packaged lock records the locked sibling's archive checksum: {lock}"
        );
    }
    #[test]
    fn a_crate_without_sibling_dependencies_packages_to_the_same_bytes_alone_and_in_a_group() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-stable").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let published = ["pkgre-demo", "pkgre-base"];

        let alone =
            resolve_test_group(&root, &source, &index, &["pkgre-base"], &published).unwrap();
        let group = resolve_test_group(&root, &source, &index, &published, &published).unwrap();

        assert_eq!(alone.len(), 1);
        assert_eq!(alone[0].name, "pkgre-base");
        assert_eq!(alone[0].archive_bytes, group[1].archive_bytes);
        assert_eq!(alone[0].archive_sha256, group[1].archive_sha256);
        assert_eq!(alone[0].source_row_bytes, group[1].source_row_bytes);
        assert_eq!(alone[0].source_row_sha256, group[1].source_row_sha256);
    }

    #[test]
    fn git_tag_packaging_refuses_a_path_dependency_on_a_member_the_catalog_does_not_publish() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-unpublished").unwrap();
        let index = create_test_index(&temporary);
        let source =
            create_test_sibling_release(&temporary, &index, "publish = false", SIBLING_DEPENDENCY);

        let error = resolve_test_group(&root, &source, &index, &["pkgre-demo"], &["pkgre-demo"])
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("path dependency on pkgre-base")
                && message.contains("which the catalog does not publish from this tag"),
            "{message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_sibling_the_catalog_declares_for_another_tag() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-other-tag").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );

        // The catalog publishes the sibling from another tag, so this tag's
        // group does not name it.
        let error = resolve_test_group(&root, &source, &index, &["pkgre-demo"], &["pkgre-demo"])
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("path dependency on pkgre-base")
                && message.contains("which the catalog does not publish from this tag"),
            "{message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_path_dependency_that_is_not_the_tag_version() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-requirement").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            "pkgre-base = { path = \"../base\", version = \"1.2.3\", registry = \"pkgre\" }",
        );
        let published = ["pkgre-demo", "pkgre-base"];

        let error = resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains(
                "path dependency on a package of the same tag must require exactly \"=1.2.3\""
            ),
            "{message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_path_dependency_without_the_curated_registry() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-registry").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            "pkgre-base = { path = \"../base\", version = \"=1.2.3\" }",
        );
        let published = ["pkgre-demo", "pkgre-base"];

        let error = resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("is a path dependency that does not declare registry = \"pkgre\""),
            "{message}"
        );
    }
    fn test_approval(materialization: &GitTagMaterialization, cargo_version: &Version) -> Approval {
        Approval {
            registry: "main".to_owned(),
            category: "main/pkgre".parse().unwrap(),
            name: materialization.name.clone(),
            version: materialization.version.clone(),
            archive_sha256: materialization.archive_sha256.clone(),
            index_record_sha256: materialization.source_row_sha256.clone(),
            index_row_sha256: "01".repeat(32),
            admission_sha256: None,
            admitted_at: crate::update::time::UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            state: PackageState::Active,
            source: Source::GitTag {
                repository: "https://example.invalid/pkgre-demo".to_owned(),
                tag: TEST_TAG.to_owned(),
                tag_oid: materialization.tag_oid.clone(),
                commit: materialization.commit.clone(),
                package: materialization.name.clone(),
                subdir: materialization.path.clone(),
                cargo_version: cargo_version.clone(),
            },
            declared_in: PathBuf::from("main.lock"),
        }
    }

    fn test_git(repository: &Path, arguments: &[&str]) -> String {
        test_command_stdout(
            Command::new("git")
                .args([
                    "-c",
                    "user.name=pkgre-test",
                    "-c",
                    "user.email=test@invalid",
                ])
                .arg("-C")
                .arg(repository)
                .args(arguments),
        )
    }

    fn run_test_command(command: &mut Command) {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "test command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn test_command_stdout(command: &mut Command) -> String {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "test command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
    #[test]
    #[ignore = "needs the network and the released tag rust/v0.5.0"]
    fn live_release_tag_packages_to_the_locked_bytes_as_a_group_and_alone() {
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let repository = "https://github.com/pkgre/pkgre";
        let tag = "rust/v0.5.0";
        let locked = [
            (
                "pkgre",
                "a4f84f78d28fb40a02c8d0226e510ed5ecbbd5d0d070d3c53713bd71d54db377",
            ),
            (
                "pkgre-rust",
                "d48cf4d539bd76765021a3901fa8999ec3887e0a3df6c91f6cdc5298ff03c7cc",
            ),
        ];
        let packages = locked.map(|(name, _)| name);

        let group =
            resolve_git_tag_group(repository, tag, &packages, &packages, &cargo_version).unwrap();
        assert_eq!(group.len(), locked.len());
        for (materialization, (name, archive_sha256)) in group.iter().zip(locked) {
            println!(
                "live: group {} {} {}",
                materialization.name, materialization.version, materialization.archive_sha256
            );
            assert_eq!(materialization.name, name);
            assert_eq!(
                materialization.archive_sha256, archive_sha256,
                "{name} packages to the bytes the catalog locked while it is in its group"
            );
        }
        for (name, archive_sha256) in locked {
            let alone = resolve_git_tag(repository, tag, name, &cargo_version).unwrap();
            println!(
                "live: alone {} {} {}",
                alone.name, alone.version, alone.archive_sha256
            );
            assert_eq!(
                alone.archive_sha256, archive_sha256,
                "{name} packages to the bytes the catalog locked on its own"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn checkout_tree_rejects_symlinks() {
        let temporary = TemporaryDirectory::new("pkgre-symlink-test").unwrap();
        fs::write(temporary.path().join("real"), "contents").unwrap();
        std::os::unix::fs::symlink("real", temporary.path().join("link")).unwrap();
        let error = ensure_safe_checkout_tree(temporary.path()).unwrap_err();
        assert!(format!("{error:#}").contains("symlink or special file"));
    }
}
