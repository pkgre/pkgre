//! Reproducible first-party package materialization from immutable Git tags.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::artifact::sha256_bytes;
use crate::policy::{
    REGISTRIES, validate_git_object_id, validate_git_tag, validate_https_repository,
    validate_package_name, validate_relative_path, validate_tag_version,
};
use crate::schema::{Approval, Source};

const REGISTRY: &str = "pkgre";
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
    registries: BTreeMap<&'static str, CargoRegistry<'static>>,
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
/// Package version and repository-relative path are discovered from the tagged workspace. The exact tag object ID and peeled commit are recorded independently.
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
    resolve_git_tag_from(
        repository,
        tag,
        expected_package,
        cargo_version,
        repository,
        false,
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

fn resolve_git_tag_from(
    repository: &str,
    tag: &str,
    expected_package: &str,
    cargo_version: &Version,
    fetch_repository: &str,
    allow_file: bool,
) -> Result<GitTagMaterialization> {
    validate_https_repository(repository)?;
    validate_git_tag(tag)?;
    validate_package_name(expected_package)?;

    let temporary = TemporaryDirectory::new("pkgre-git-package")?;
    let checkout = temporary.path().join("repository");
    let (tag_oid, commit) = fetch_tag(tag, &checkout, fetch_repository, allow_file)?;
    ensure_safe_checkout_tree(&checkout)?;
    ensure_clean_checkout(&checkout)?;

    let cargo = pinned_cargo(cargo_version)?;
    let cargo_home = temporary.path().join("cargo-home");
    prepare_cargo_home(&cargo_home)?;
    let root_manifest = checkout.join("Cargo.toml");
    ensure!(
        fs::symlink_metadata(&root_manifest)
            .with_context(|| format!("inspect root manifest {}", root_manifest.display()))?
            .file_type()
            .is_file(),
        "Git repository has no regular root Cargo.toml"
    );
    let package = cargo_metadata(
        &cargo,
        &cargo_home,
        &root_manifest,
        expected_package,
        &checkout,
    )?;
    validate_tag_version(tag, &package.version)?;
    let path = package_path(&checkout, &package.manifest_path)?;

    let archive_one = run_cargo_package(
        &cargo,
        &cargo_home,
        &package.manifest_path,
        expected_package,
        &temporary.path().join("target-one"),
        &package.version,
    )?;
    let archive_two = run_cargo_package(
        &cargo,
        &cargo_home,
        &package.manifest_path,
        expected_package,
        &temporary.path().join("target-two"),
        &package.version,
    )?;
    let archive_bytes = read_bounded_archive(&archive_one)?;
    let repeated_bytes = read_bounded_archive(&archive_two)?;
    ensure!(
        archive_bytes == repeated_bytes,
        "pinned Cargo produced non-deterministic archives for {} {}",
        package.name,
        package.version
    );
    ensure_clean_checkout(&checkout)?;

    let archive_sha256 = sha256_bytes(&archive_bytes);
    let source_row_bytes = generated_index_record(&package, &archive_sha256)?;
    let source_row_sha256 = sha256_bytes(&source_row_bytes);
    Ok(GitTagMaterialization {
        name: package.name,
        version: package.version,
        tag_oid,
        commit,
        path,
        archive_bytes,
        source_row_bytes,
        archive_sha256,
        source_row_sha256,
    })
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
    )?;
    run_git(
        Some(repository),
        [
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            OsString::from(fetch_repository),
        ],
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
    let fetch_command = git_command_with_file_policy(Some(repository), fetch_arguments, allow_file);
    run_command(fetch_command, "fetch exact Git tag")?;
    let tag_oid = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(&reference),
            ],
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
    )?;
    let gitlinks = command_stdout(
        git_command(
            Some(repository),
            [OsString::from("ls-files"), OsString::from("--stage")],
        ),
        "list checked-out Git files",
    )?;
    ensure!(
        !gitlinks.lines().any(|line| line.starts_with("160000 ")),
        "Git-tag checkout contains unsupported submodules"
    );
    Ok((tag_oid, commit))
}

fn ensure_safe_checkout_tree(repository: &Path) -> Result<()> {
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

fn ensure_clean_checkout(repository: &Path) -> Result<()> {
    let status = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("status"),
                OsString::from("--porcelain=v1"),
                OsString::from("--untracked-files=all"),
            ],
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

fn pinned_cargo(version: &Version) -> Result<PathBuf> {
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

fn prepare_cargo_home(cargo_home: &Path) -> Result<()> {
    fs::create_dir(cargo_home)
        .with_context(|| format!("create isolated Cargo home {}", cargo_home.display()))?;
    let disabled = cargo_home.join("disabled-crates-io");
    fs::create_dir(&disabled)
        .with_context(|| format!("create disabled Cargo source {}", disabled.display()))?;
    let registries = REGISTRIES
        .iter()
        .map(|(name, index)| (*name, CargoRegistry { index }))
        .collect();
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
        registry: CargoDefaultRegistry { default: REGISTRY },
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
    manifest_path: &Path,
    expected_package: &str,
    repository: &Path,
) -> Result<MetadataPackage> {
    let mut command = isolated_cargo(cargo, cargo_home);
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
    let mut matching = metadata
        .packages
        .into_iter()
        .filter(|package| package.name == expected_package)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "Cargo metadata contains {} packages named {expected_package:?}; expected exactly one",
        matching.len()
    );
    let package = matching.pop().expect("length checked");
    package_path(repository, &package.manifest_path)?;
    ensure!(
        package.publish.as_deref() == Some(&[REGISTRY.to_owned()]),
        "first-party package must set publish = [{REGISTRY:?}] exactly"
    );
    let registry_indexes = REGISTRIES
        .iter()
        .map(|(_, index)| *index)
        .collect::<Vec<_>>();
    for dependency in &package.dependencies {
        let source = dependency.source.as_deref().unwrap_or("path");
        ensure!(
            is_curated_registry_source(source, &registry_indexes),
            "first-party package dependency {} uses unsupported source {source:?}; use universe or pkgre explicitly",
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
    Ok(package)
}

fn run_cargo_package(
    cargo: &Path,
    cargo_home: &Path,
    manifest_path: &Path,
    package: &str,
    target: &Path,
    version: &Version,
) -> Result<PathBuf> {
    let mut command = isolated_cargo(cargo, cargo_home);
    command.current_dir(cargo_home).args([
        OsStr::new("package"),
        OsStr::new("--no-verify"),
        OsStr::new("--locked"),
        OsStr::new("--package"),
        OsStr::new(package),
        OsStr::new("--manifest-path"),
        manifest_path.as_os_str(),
        OsStr::new("--target-dir"),
        target.as_os_str(),
    ]);
    run_command(command, "package first-party crate")?;
    let archive = target
        .join("package")
        .join(format!("{package}-{version}.crate"));
    ensure!(
        fs::symlink_metadata(&archive)
            .with_context(|| format!("inspect Cargo archive {}", archive.display()))?
            .file_type()
            .is_file(),
        "Cargo did not produce a regular archive at {}",
        archive.display()
    );
    Ok(archive)
}

fn read_bounded_archive(path: &Path) -> Result<Vec<u8>> {
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

fn isolated_cargo(cargo: &Path, cargo_home: &Path) -> Command {
    let mut command = Command::new(cargo);
    command
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "false")
        .env_remove("CARGO_REGISTRY_TOKEN")
        .env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN")
        .env_remove("CARGO_HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY");
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

fn run_git<I, S>(current_dir: Option<&Path>, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let command = git_command(current_dir, arguments);
    run_command(command, "run Git command")?;
    Ok(())
}

fn git_command<I, S>(current_dir: Option<&Path>, arguments: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    git_command_with_file_policy(current_dir, arguments, false)
}

fn git_command_with_file_policy<I, S>(
    current_dir: Option<&Path>,
    arguments: I,
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
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_ASKPASS")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY");
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

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Result<Self> {
        let root = std::env::temp_dir();
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

    fn path(&self) -> &Path {
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
            publish: Some(vec![REGISTRY.to_owned()]),
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
        let temporary = TemporaryDirectory::new("pkgre-git-e2e").unwrap();
        let source = create_test_release(&temporary);
        let source_url = source.to_str().unwrap();
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let materialization = resolve_git_tag_from(
            "https://example.invalid/pkgre-demo",
            TEST_TAG,
            "pkgre-demo",
            &cargo_version,
            source_url,
            true,
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

    fn test_approval(materialization: &GitTagMaterialization, cargo_version: &Version) -> Approval {
        Approval {
            registry: REGISTRY.to_owned(),
            category: "pkgre/tooling".parse().unwrap(),
            name: materialization.name.clone(),
            version: materialization.version.clone(),
            archive_sha256: materialization.archive_sha256.clone(),
            index_record_sha256: materialization.source_row_sha256.clone(),
            index_row_sha256: "01".repeat(32),
            admission_sha256: None,
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
            declared_in: PathBuf::from("pkgre.lock"),
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
