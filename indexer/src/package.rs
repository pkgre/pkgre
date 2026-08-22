//! First-party package materialization from immutable Git tags.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::artifact::{require_absent, sha256_bytes};
use crate::policy::{
    REGISTRIES, validate_git_commit, validate_git_tag, validate_https_repository,
    validate_package_name, validate_relative_path,
};
use crate::schema::{Approval, SCHEMA_VERSION, Source};

const REGISTRY: &str = "pkgre";
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Declarative, non-approved proposal used to compute reviewable Git-tag package artifacts.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitProposal {
    /// Schema version.
    pub schema: u32,
    /// Destination registry; must be `pkgre`.
    pub registry: String,
    /// Cargo package name.
    pub name: String,
    /// Exact manifest version.
    pub version: Version,
    /// HTTPS Git repository URL.
    pub repository: String,
    /// Immutable tag name.
    pub tag: String,
    /// Full peeled commit object ID.
    pub commit: String,
    /// Workspace package name.
    pub package: String,
    /// Repository-relative package directory.
    pub subdir: PathBuf,
}

/// Exact files and hashes produced by one Git-tag materialization.
#[derive(Debug)]
pub struct GitMaterialization {
    /// Content-addressed `.crate` path.
    pub archive: PathBuf,
    /// Content-addressed un-routed index-record path.
    pub index_record: PathBuf,
    /// Exact archive SHA-256.
    pub archive_sha256: String,
    /// Exact un-routed index-record SHA-256.
    pub index_record_sha256: String,
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

#[derive(Debug, Serialize)]
struct CandidateArtifacts<'a> {
    schema: u32,
    artifacts: [CandidateArtifact<'a>; 1],
}

#[derive(Debug, Serialize)]
struct CandidateArtifact<'a> {
    registry: &'static str,
    name: &'a str,
    version: &'a Version,
    archive: PathBuf,
    index_record: PathBuf,
}

#[derive(Debug, Serialize)]
struct CandidateApproval<'a> {
    schema: u32,
    registry: &'static str,
    packages: [CandidateApprovalPackage<'a>; 1],
}

#[derive(Debug, Serialize)]
struct CandidateApprovalPackage<'a> {
    name: &'a str,
    version: &'a Version,
    archive_sha256: &'a str,
    index_record_sha256: &'a str,
    yanked: bool,
    source: CandidateApprovalSource<'a>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CandidateApprovalSource<'a> {
    GitTag {
        repository: &'a str,
        tag: &'a str,
        commit: &'a str,
        package: &'a str,
        subdir: &'a Path,
    },
}

/// Loads one Git package proposal.
///
/// # Errors
///
/// Returns an error for a missing, malformed, or unsupported proposal.
pub fn load_git_proposal(path: &Path) -> Result<GitProposal> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read Git package proposal {}", path.display()))?;
    let proposal: GitProposal = toml::from_str(&contents)
        .with_context(|| format!("parse Git package proposal {}", path.display()))?;
    validate_proposal(&proposal)?;
    Ok(proposal)
}

/// Produces a candidate archive, un-routed index record, and complete approval stanza without trusting either hash in advance.
///
/// This is the review boundary: the generated files and hashes are candidates only. They do not alter a catalog or rendered registry.
///
/// # Errors
///
/// Returns an error if the tag does not peel to the declared commit, the checkout is dirty or unsafe, Cargo is not the pinned version, package metadata differs from the proposal, packaging is not reproducible, or output creation fails.
pub fn candidate_git(
    proposal: &GitProposal,
    cargo_version: &Version,
    output: &Path,
) -> Result<GitMaterialization> {
    candidate_git_from(proposal, cargo_version, output, &proposal.repository, false)
}

fn candidate_git_from(
    proposal: &GitProposal,
    cargo_version: &Version,
    output: &Path,
    fetch_repository: &str,
    allow_file: bool,
) -> Result<GitMaterialization> {
    validate_proposal(proposal)?;
    let materialization = materialize(
        proposal,
        cargo_version,
        output,
        fetch_repository,
        allow_file,
    )?;
    let approval = CandidateApproval {
        schema: SCHEMA_VERSION,
        registry: REGISTRY,
        packages: [CandidateApprovalPackage {
            name: &proposal.name,
            version: &proposal.version,
            archive_sha256: &materialization.archive_sha256,
            index_record_sha256: &materialization.index_record_sha256,
            yanked: false,
            source: CandidateApprovalSource::GitTag {
                repository: &proposal.repository,
                tag: &proposal.tag,
                commit: &proposal.commit,
                package: &proposal.package,
                subdir: &proposal.subdir,
            },
        }],
    };
    let result = (|| {
        let approval_toml =
            toml::to_string_pretty(&approval).context("serialize candidate approval")?;
        write_new(&output.join("approval.toml"), approval_toml.as_bytes())?;
        let artifacts = CandidateArtifacts {
            schema: SCHEMA_VERSION,
            artifacts: [CandidateArtifact {
                registry: REGISTRY,
                name: &proposal.name,
                version: &proposal.version,
                archive: PathBuf::from("archives")
                    .join(format!("{}.crate", materialization.archive_sha256)),
                index_record: PathBuf::from("records")
                    .join(format!("{}.json", materialization.index_record_sha256)),
            }],
        };
        let artifacts_toml =
            toml::to_string_pretty(&artifacts).context("serialize candidate artifact map")?;
        write_new(&output.join("artifacts.toml"), artifacts_toml.as_bytes())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result.map(|()| materialization)
}

/// Reproduces one approved Git-tag package and fails unless both exact hashes match the catalog.
///
/// # Errors
///
/// Returns an error for a non-Git approval or any source, package, toolchain, reproducibility, metadata, or hash mismatch.
pub fn package_approved_git(
    approval: &Approval,
    cargo_version: &Version,
    output: &Path,
) -> Result<GitMaterialization> {
    let Source::GitTag { repository, .. } = &approval.source else {
        bail!(
            "{} {} is not an approved Git-tag package",
            approval.name,
            approval.version
        );
    };
    package_approved_git_from(approval, cargo_version, output, repository, false)
}

fn package_approved_git_from(
    approval: &Approval,
    cargo_version: &Version,
    output: &Path,
    fetch_repository: &str,
    allow_file: bool,
) -> Result<GitMaterialization> {
    let Source::GitTag {
        repository,
        tag,
        commit,
        package,
        subdir,
        ..
    } = &approval.source
    else {
        bail!(
            "{} {} is not an approved Git-tag package",
            approval.name,
            approval.version
        );
    };
    let proposal = GitProposal {
        schema: SCHEMA_VERSION,
        registry: approval.registry.clone(),
        name: approval.name.clone(),
        version: approval.version.clone(),
        repository: repository.clone(),
        tag: tag.clone(),
        commit: commit.clone(),
        package: package.clone(),
        subdir: subdir.clone(),
    };
    validate_proposal(&proposal)?;
    let materialization = materialize(
        &proposal,
        cargo_version,
        output,
        fetch_repository,
        allow_file,
    )?;
    ensure!(
        materialization.archive_sha256 == approval.archive_sha256,
        "approved archive hash mismatch for {} {}: expected {}, got {}",
        approval.name,
        approval.version,
        approval.archive_sha256,
        materialization.archive_sha256
    );
    ensure!(
        materialization.index_record_sha256 == approval.index_record_sha256,
        "approved index-record hash mismatch for {} {}: expected {}, got {}",
        approval.name,
        approval.version,
        approval.index_record_sha256,
        materialization.index_record_sha256
    );
    Ok(materialization)
}

fn materialize(
    proposal: &GitProposal,
    cargo_version: &Version,
    output: &Path,
    fetch_repository: &str,
    allow_file: bool,
) -> Result<GitMaterialization> {
    require_absent(output)?;
    let temporary = TemporaryDirectory::new("pkgre-git-package")?;
    let repository = temporary.path().join("repository");
    fetch_tag(proposal, &repository, fetch_repository, allow_file)?;
    ensure_safe_checkout_tree(&repository)?;
    ensure_clean_checkout(&repository)?;
    let package_directory = checked_subdirectory(&repository, &proposal.subdir)?;
    let manifest_path = package_directory.join("Cargo.toml");
    ensure!(
        fs::symlink_metadata(&manifest_path)
            .with_context(|| format!("inspect package manifest {}", manifest_path.display()))?
            .file_type()
            .is_file(),
        "package manifest is not a regular file: {}",
        manifest_path.display()
    );

    let cargo = pinned_cargo(cargo_version)?;
    let cargo_home = temporary.path().join("cargo-home");
    prepare_cargo_home(&cargo_home)?;
    let metadata = cargo_metadata(&cargo, &cargo_home, &manifest_path, proposal)?;
    let archive_one = run_cargo_package(
        &cargo,
        &cargo_home,
        &manifest_path,
        &proposal.package,
        &temporary.path().join("target-one"),
        &proposal.version,
    )?;
    let archive_two = run_cargo_package(
        &cargo,
        &cargo_home,
        &manifest_path,
        &proposal.package,
        &temporary.path().join("target-two"),
        &proposal.version,
    )?;
    let archive_bytes = fs::read(&archive_one)
        .with_context(|| format!("read packaged archive {}", archive_one.display()))?;
    let repeated_bytes = fs::read(&archive_two)
        .with_context(|| format!("read repeated archive {}", archive_two.display()))?;
    ensure!(
        archive_bytes == repeated_bytes,
        "pinned Cargo produced non-deterministic archives for {} {}",
        proposal.name,
        proposal.version
    );
    ensure_clean_checkout(&repository)?;

    let archive_sha256 = sha256_bytes(&archive_bytes);
    let index_record = generated_index_record(&metadata, &archive_sha256)?;
    let index_record_sha256 = sha256_bytes(&index_record);

    fs::create_dir(output).with_context(|| format!("create output {}", output.display()))?;
    let result = (|| {
        let archive = output
            .join("archives")
            .join(format!("{archive_sha256}.crate"));
        let record = output
            .join("records")
            .join(format!("{index_record_sha256}.json"));
        write_new(&archive, &archive_bytes)?;
        write_new(&record, &index_record)?;
        Ok(GitMaterialization {
            archive,
            index_record: record,
            archive_sha256,
            index_record_sha256,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn validate_proposal(proposal: &GitProposal) -> Result<()> {
    ensure!(
        proposal.schema == SCHEMA_VERSION,
        "unsupported Git proposal schema {}; expected {SCHEMA_VERSION}",
        proposal.schema
    );
    ensure!(
        proposal.registry == REGISTRY,
        "Git package proposal registry must be {REGISTRY:?}"
    );
    validate_package_name(&proposal.name)?;
    validate_package_name(&proposal.package)?;
    ensure!(
        proposal.name == proposal.package,
        "proposal package name must match its approved name"
    );
    validate_https_repository(&proposal.repository)?;
    validate_git_tag(&proposal.tag)?;
    validate_git_commit(&proposal.commit)?;
    validate_relative_path(&proposal.subdir, true)?;
    Ok(())
}

fn fetch_tag(
    proposal: &GitProposal,
    repository: &Path,
    fetch_repository: &str,
    allow_file: bool,
) -> Result<()> {
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
    let source = OsString::from(format!("refs/tags/{}", proposal.tag));
    let destination = OsString::from(format!("refs/tags/{}", proposal.tag));
    let fetch_arguments = [
        OsString::from("fetch"),
        OsString::from("--quiet"),
        OsString::from("--no-tags"),
        OsString::from("--depth=1"),
        OsString::from("origin"),
        OsString::from(format!(
            "{}:{}",
            source.to_string_lossy(),
            destination.to_string_lossy()
        )),
    ];
    let fetch_command = git_command_with_file_policy(Some(repository), fetch_arguments, allow_file);
    run_command(fetch_command, "fetch exact Git tag")?;
    let peeled = command_stdout(
        git_command(
            Some(repository),
            [
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(format!("refs/tags/{}^{{commit}}", proposal.tag)),
            ],
        ),
        "peel fetched Git tag",
    )?;
    ensure!(
        peeled == proposal.commit,
        "Git tag {} peels to {peeled}, not declared commit {}",
        proposal.tag,
        proposal.commit
    );
    run_git(
        Some(repository),
        [
            OsString::from("checkout"),
            OsString::from("--quiet"),
            OsString::from("--detach"),
            OsString::from(&proposal.commit),
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
    Ok(())
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

fn checked_subdirectory(repository: &Path, subdir: &Path) -> Result<PathBuf> {
    let mut current = repository.to_path_buf();
    if subdir == Path::new(".") {
        return Ok(current);
    }
    for component in subdir.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect package path {}", current.display()))?;
        ensure!(
            metadata.file_type().is_dir(),
            "package path component is not a real directory: {}",
            current.display()
        );
    }
    Ok(current)
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
        .map(|(name, index, _)| (*name, CargoRegistry { index }))
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
    write_new(&cargo_home.join("config.toml"), contents.as_bytes())
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
    proposal: &GitProposal,
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
        .filter(|package| package.name == proposal.package)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "Cargo metadata contains {} packages named {:?}; expected exactly one",
        matching.len(),
        proposal.package
    );
    let package = matching.pop().expect("length checked");
    ensure!(
        package.version == proposal.version,
        "manifest version for {} is {}, not proposed {}",
        proposal.package,
        package.version,
        proposal.version
    );
    let expected_manifest = fs::canonicalize(manifest_path)
        .with_context(|| format!("canonicalize manifest {}", manifest_path.display()))?;
    let actual_manifest = fs::canonicalize(&package.manifest_path).with_context(|| {
        format!(
            "canonicalize metadata manifest {}",
            package.manifest_path.display()
        )
    })?;
    ensure!(
        actual_manifest == expected_manifest,
        "Cargo selected a package manifest outside the declared subdirectory"
    );
    ensure!(
        package.publish.as_deref() == Some(&[REGISTRY.to_owned()]),
        "first-party package must set publish = [{REGISTRY:?}] exactly"
    );
    let registry_indexes = REGISTRIES
        .iter()
        .map(|(_, index, _)| *index)
        .collect::<Vec<_>>();
    for dependency in &package.dependencies {
        let source = dependency.source.as_deref().unwrap_or("path");
        let expected_source = is_curated_registry_source(source, &registry_indexes);
        ensure!(
            expected_source,
            "first-party package dependency {} uses unsupported source {source:?}; use core, matrix, or pkgre explicitly",
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
        .env_remove("SSH_AUTH_SOCK");
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

fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
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
            "sparse+https://example.test/other/",
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
    fn git_tag_candidate_is_reproducible_and_commit_bound() {
        let temporary = TemporaryDirectory::new("pkgre-git-e2e").unwrap();
        let (source, proposal) = create_test_release(&temporary);
        let source_url = source.to_str().unwrap();
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let candidate_path = temporary.path().join("candidate");
        let candidate =
            candidate_git_from(&proposal, &cargo_version, &candidate_path, source_url, true)
                .unwrap();
        assert_candidate(&candidate_path, &candidate, &proposal);

        let approval = test_approval(&proposal, &candidate);
        let approved = package_approved_git_from(
            &approval,
            &cargo_version,
            &temporary.path().join("approved"),
            source_url,
            true,
        )
        .unwrap();
        assert_eq!(
            fs::read(candidate.archive).unwrap(),
            fs::read(approved.archive).unwrap()
        );
        assert_eq!(
            fs::read(candidate.index_record).unwrap(),
            fs::read(approved.index_record).unwrap()
        );

        move_test_tag(&source);
        let moved_output = temporary.path().join("moved-candidate");
        let error = candidate_git_from(&proposal, &cargo_version, &moved_output, source_url, true)
            .unwrap_err();
        assert!(format!("{error:#}").contains("not declared commit"));
        assert!(!moved_output.exists());
    }

    fn create_test_release(temporary: &TemporaryDirectory) -> (PathBuf, GitProposal) {
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
        let commit = test_git(&source, &["rev-parse", "HEAD"]);
        let proposal = GitProposal {
            schema: SCHEMA_VERSION,
            registry: REGISTRY.to_owned(),
            name: "pkgre-demo".to_owned(),
            version: Version::parse("1.2.3").unwrap(),
            repository: "https://example.invalid/pkgre-demo".to_owned(),
            tag: TEST_TAG.to_owned(),
            commit,
            package: "pkgre-demo".to_owned(),
            subdir: PathBuf::from("crates/demo"),
        };
        (source, proposal)
    }

    fn assert_candidate(
        candidate_path: &Path,
        candidate: &GitMaterialization,
        proposal: &GitProposal,
    ) {
        assert_eq!(
            sha256_bytes(&fs::read(&candidate.archive).unwrap()),
            candidate.archive_sha256
        );
        assert_eq!(
            sha256_bytes(&fs::read(&candidate.index_record).unwrap()),
            candidate.index_record_sha256
        );
        let record =
            crate::index::IndexRecord::parse(&fs::read(&candidate.index_record).unwrap()).unwrap();
        record.validate_structure().unwrap();
        assert_eq!(record.name().unwrap(), proposal.name);
        assert_eq!(record.version().unwrap(), proposal.version);
        assert!(candidate_path.join("approval.toml").is_file());
        crate::artifact::ArtifactMap::load(candidate_path.join("artifacts.toml")).unwrap();
        let vcs_info = test_command_stdout(
            Command::new("tar")
                .arg("-xOf")
                .arg(&candidate.archive)
                .arg("pkgre-demo-1.2.3/.cargo_vcs_info.json"),
        );
        let vcs: serde_json::Value = serde_json::from_str(&vcs_info).unwrap();
        assert_eq!(vcs["git"]["sha1"], proposal.commit);
    }

    fn test_approval(proposal: &GitProposal, candidate: &GitMaterialization) -> Approval {
        Approval {
            registry: REGISTRY.to_owned(),
            name: proposal.name.clone(),
            version: proposal.version.clone(),
            archive_sha256: candidate.archive_sha256.clone(),
            index_record_sha256: candidate.index_record_sha256.clone(),
            yanked: false,
            source: Source::GitTag {
                repository: proposal.repository.clone(),
                tag: proposal.tag.clone(),
                commit: proposal.commit.clone(),
                package: proposal.package.clone(),
                subdir: proposal.subdir.clone(),
            },
            declared_in: PathBuf::from("approvals/pkgre.toml"),
        }
    }

    fn move_test_tag(source: &Path) {
        fs::write(source.join("moved"), "different commit\n").unwrap();
        test_git(source, &["add", "moved"]);
        test_git(source, &["commit", "--quiet", "-m", "move tag target"]);
        test_git(source, &["tag", "--force", "-a", TEST_TAG, "-m", "moved"]);
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

    #[test]
    fn unsafe_proposal_source_is_rejected() {
        let proposal = GitProposal {
            schema: SCHEMA_VERSION,
            registry: REGISTRY.to_owned(),
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            repository: "https://token@example.test/repo".to_owned(),
            tag: "v1.0.0".to_owned(),
            commit: "01".repeat(20),
            package: "demo".to_owned(),
            subdir: PathBuf::from("."),
        };
        assert!(validate_proposal(&proposal).is_err());
    }
}
