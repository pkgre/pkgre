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
use crate::schema::{Approval, PackageState, Source};
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
    workspace_root: PathBuf,
}

/// The members of one tagged workspace, with the root Cargo resolved it from.
struct WorkspaceMetadata {
    /// Absolute path of the workspace root, which holds the lock file Cargo
    /// packages from.
    root: PathBuf,
    /// Every member of the workspace.
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
    /// Directory of a path dependency, which Cargo reports instead of a source.
    path: Option<PathBuf>,
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
    registry: Option<&'a str>,
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
/// A path dependency is accepted only on another package that the tagged workspace publishes, because this entry point knows no catalog: the set is every member of the tag whose manifest sets exactly `publish = ["pkgre"]`, which is the widest set the catalog can publish from that tag, and no identity is admitted from here. [`resolve_git_tag_group`] takes the catalog's own set, with the archive it locked for each package, and the callers that admit an identity use it. A sibling this entry point accepts is bound to the archive its own packaging produces, or, when Cargo takes it from the registry, to the archive that registry serves, so a caller that verifies the archive hash, as [`reproduce_approved_git`] does, binds the result end to end.
///
/// A tag that names a registry the catalog retired is refused here, since this entry point admits an identity without comparing it with a locked one. [`reproduce_approved_git`] is the only reproduction that may package such a tag, because it compares the archive and source row it produces with the ones the catalog locked; [`reproduce_approved_git_group`] reproduces the identities a change adds, which are new publications, so it refuses one.
///
/// # Errors
///
/// Returns an error for an unsafe source, a retired registry, ambiguous package, malformed or moved tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty checkout, a workspace without a committed lock or with a `[patch]` or `[replace]` section, non-reproducible archive, or invalid package metadata.
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
            allow_retired_registries: false,
        },
        &PackagingSource::live(repository),
        cargo_version,
    )?;
    single_materialization(&mut materializations)
}

/// Resolves and reproducibly packages every declared package of one first-party Git tag together.
///
/// One fetch, one metadata run, and one packaging run serve every package of the group, so that a package of the tag may depend on another one. `published` names every package the catalog publishes from this repository and tag, with the archive it locked for the ones it locked already, and a path dependency is accepted only on one of them.
///
/// A package of the group is bound to the archive this run produces, and a package the catalog locked already to the archive it locked, so the packaged lock of every dependent must name exactly that archive; a package that is neither in the group nor carries its locked archive is refused. A locked package is not packaged again: Cargo takes it from the registry index, which must serve that identity.
///
/// The materializations are returned in the order the packages were requested.
///
/// # Errors
///
/// Returns an error for an empty group, a requested package outside `published`, a published package that is neither packaged nor carries its locked archive, an unsafe source, a retired registry a new publication may not name, ambiguous package, malformed or moved tag, unsafe checkout, unpinned dependency source, wrong Cargo version, dirty checkout, a workspace without a committed lock or with a `[patch]` or `[replace]` section, non-reproducible archive, a packaged lock that departs from the tag's workspace lock, or invalid package metadata.
pub fn resolve_git_tag_group(
    repository: &str,
    tag: &str,
    packages: &[&str],
    published: &[PublishedPackage<'_>],
    cargo_version: &Version,
) -> Result<Vec<GitTagMaterialization>> {
    resolve_tag(
        &std::env::temp_dir(),
        &TagRequest {
            repository,
            tag,
            packages,
            published: Some(published),
            allow_retired_registries: false,
        },
        &PackagingSource::live(repository),
        cargo_version,
    )
}

/// Reproduces one locked Git publication and verifies every immutable source and content field.
///
/// The reproduction is the only resolution that may package a tag naming a
/// registry the catalog retired, since it is the only one that compares the
/// archive and source row it produces with the ones the catalog locked.
///
/// This entry point knows no catalog, so it packages one package and Cargo takes
/// a sibling that package depends on from the curated index.
/// [`reproduce_approved_git_group`] takes the catalog's own set and packages the
/// identities of one tag together, as `lock` does.
///
/// # Errors
///
/// Returns an error for a non-Git approval or any source, tag, package, toolchain, path, archive, or source-row mismatch.
pub fn reproduce_approved_git(approval: &Approval) -> Result<GitTagMaterialization> {
    let git = approved_git_tag(approval)?;
    let materialization = resolve_approved_git_tag(
        &std::env::temp_dir(),
        &git,
        &PackagingSource::live(git.repository),
    )?;
    verify_approved_materialization(
        approval,
        git.tag_oid,
        git.commit,
        git.subdir,
        &materialization,
    )?;
    Ok(materialization)
}

/// Reproduces every locked Git publication of one tag together, as
/// [`resolve_git_tag_group`] packages them.
///
/// `lock` resolves the declarations of one repository and tag in one resolution,
/// so that a package of the tag may depend on another one. A reproduction of one
/// identity alone cannot: Cargo takes a sibling that the resolution does not
/// package from the curated index, which serves no identity that the candidate
/// adds. This entry point reproduces a group as `lock` resolved it.
///
/// `catalog` holds every approval of the catalog that the group belongs to. Every
/// package it publishes from the group's registry, repository, and tag is passed
/// with the archive it locked, so that the packaged lock of a dependent must name
/// exactly its sibling's locked archive, and a package of the group must package
/// to the archive the catalog locked.
///
/// The identities a change adds are new publications, so a group follows the
/// first-publication rules: a tag that names a registry the catalog retired is
/// refused, as [`resolve_git_tag_group`] refuses it, and only
/// [`reproduce_approved_git`], which compares the archive and source row with a
/// locked identity, may package such a tag.
///
/// Every approval must be a Git-tag publication of the same repository and tag,
/// in the same registry, with one Cargo version, and the group must name every
/// package once. The materializations are returned in the order of `approvals`,
/// each verified against its approval as [`reproduce_approved_git`] verifies one.
///
/// # Errors
///
/// Returns an error for an empty group, an approval that is not a Git-tag
/// publication, approvals that disagree on the registry, repository, tag, or
/// Cargo version, a package the group names twice, a retired registry a new
/// publication may not name, or any source, tag, package, toolchain, path,
/// archive, or source-row mismatch.
pub fn reproduce_approved_git_group(
    catalog: &[Approval],
    approvals: &[&Approval],
) -> Result<Vec<GitTagMaterialization>> {
    reproduce_approved_git_group_in(
        &std::env::temp_dir(),
        catalog,
        approvals,
        PackagingSource::live,
    )
}

/// Reproduces the given group below `root`, fetching and resolving from the
/// packaging source that `packaging` names for the group's repository.
fn reproduce_approved_git_group_in<'a>(
    root: &Path,
    catalog: &'a [Approval],
    approvals: &[&'a Approval],
    packaging: impl FnOnce(&'a str) -> PackagingSource<'a>,
) -> Result<Vec<GitTagMaterialization>> {
    let first = *approvals
        .first()
        .context("a Git-tag group names no identity to reproduce")?;
    let first_git = approved_git_tag(first)?;
    let mut names = BTreeSet::new();
    let mut members = Vec::with_capacity(approvals.len());
    for &approval in approvals {
        let git = approved_git_tag(approval)?;
        ensure!(
            approval.registry == first.registry
                && git.repository == first_git.repository
                && git.tag == first_git.tag,
            "{} {} is not a Git-tag publication of tag {:?} in {}; one reproduction packages the identities of one tag together",
            approval.name,
            approval.version,
            first_git.tag,
            first.registry
        );
        ensure!(
            git.cargo_version == first_git.cargo_version,
            "{} {} pins Cargo {}, but {} of tag {:?} pins Cargo {}; one reproduction packages the tag with one Cargo version",
            approval.name,
            approval.version,
            git.cargo_version,
            first.name,
            first_git.tag,
            first_git.cargo_version
        );
        ensure!(
            names.insert(approval.name.as_str()),
            "Git tag {:?} names package {:?} twice in one reproduction",
            first_git.tag,
            approval.name
        );
        members.push((approval, git));
    }
    let packages = names.into_iter().collect::<Vec<_>>();
    let published = catalog
        .iter()
        .filter(|candidate| {
            candidate.state == PackageState::Active
                && candidate.registry == first.registry
                && matches!(
                    &candidate.source,
                    Source::GitTag {
                        repository: other_repository,
                        tag: other_tag,
                        ..
                    } if other_repository.as_str() == first_git.repository
                        && other_tag.as_str() == first_git.tag
                )
        })
        .map(|candidate| PublishedPackage {
            name: candidate.name.as_str(),
            locked_sha256: Some(candidate.archive_sha256.as_str()),
        })
        .collect::<Vec<_>>();
    let mut materializations = resolve_tag(
        root,
        &TagRequest {
            repository: first_git.repository,
            tag: first_git.tag,
            packages: &packages,
            published: Some(&published),
            allow_retired_registries: false,
        },
        &packaging(first_git.repository),
        first_git.cargo_version,
    )?;
    let mut by_name = BTreeMap::new();
    for materialization in materializations.drain(..) {
        let name = materialization.name.clone();
        ensure!(
            by_name.insert(name.clone(), materialization).is_none(),
            "tag {:?} reproduced package {name:?} more than once",
            first_git.tag
        );
    }
    let mut verified = Vec::with_capacity(members.len());
    for (approval, git) in members {
        let materialization = by_name.remove(&approval.name).with_context(|| {
            format!(
                "tag {:?} reproduced no package {:?} for {} {}",
                first_git.tag, approval.name, approval.name, approval.version
            )
        })?;
        verify_approved_materialization(
            approval,
            git.tag_oid,
            git.commit,
            git.subdir,
            &materialization,
        )?;
        verified.push(materialization);
    }
    Ok(verified)
}

/// The Git-tag evidence one approval records, which a reproduction packages and
/// verifies.
struct ApprovedGitTag<'a> {
    /// Credential-free HTTPS repository the tag belongs to.
    repository: &'a str,
    /// Immutable tag the approval locks.
    tag: &'a str,
    /// Exact tag object ID.
    tag_oid: &'a str,
    /// Peeled commit object ID.
    commit: &'a str,
    /// Cargo package name the approval locks.
    package: &'a str,
    /// Repository-relative package directory.
    subdir: &'a Path,
    /// Pinned Cargo version of the tag.
    cargo_version: &'a Version,
}

/// Returns the Git-tag evidence of one approval.
///
/// # Errors
///
/// Returns an error for an approval that is not a Git-tag publication.
fn approved_git_tag(approval: &Approval) -> Result<ApprovedGitTag<'_>> {
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
    Ok(ApprovedGitTag {
        repository,
        tag,
        tag_oid,
        commit,
        package,
        subdir,
        cargo_version,
    })
}

/// Resolves and reproducibly packages the package of one locked Git publication.
///
/// A reproduction may package a tag that names a registry the catalog retired,
/// because it is bound to the archive and source row the catalog locked.
fn resolve_approved_git_tag(
    root: &Path,
    git: &ApprovedGitTag<'_>,
    source: &PackagingSource<'_>,
) -> Result<GitTagMaterialization> {
    let packages = [git.package];
    let mut materializations = resolve_tag(
        root,
        &TagRequest {
            repository: git.repository,
            tag: git.tag,
            packages: &packages,
            published: None,
            allow_retired_registries: true,
        },
        source,
        git.cargo_version,
    )?;
    single_materialization(&mut materializations)
}

/// One package that the catalog publishes from one repository and tag.
#[derive(Clone, Copy, Debug)]
pub struct PublishedPackage<'a> {
    /// Cargo package name.
    pub name: &'a str,
    /// SHA-256 of the archive the catalog locked for this identity, when it
    /// locked it already.
    ///
    /// The packaging requires a dependency on this package to carry exactly
    /// this archive in the packaged lock. A package of the same resolution is
    /// bound to the archive that resolution produces instead, and `None` leaves
    /// it unbound, which only a caller that knows no catalog may ask for.
    pub locked_sha256: Option<&'a str>,
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
    published: Option<&'a [PublishedPackage<'a>]>,
    /// Whether a dependency may name a registry the catalog retired.
    ///
    /// Only a reproduction of an identity the catalog locked sets this: it
    /// compares the archive and source row it produces with the ones the
    /// catalog recorded, so the retired name cannot reach a new publication.
    allow_retired_registries: bool,
}

/// Every package a path dependency of one tag may point at, with the archive the
/// catalog locked for the ones it locked already.
type Siblings = BTreeMap<String, Option<String>>;

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
        allow_retired_registries: false,
    })?;
    single_materialization(&mut materializations)
}

/// Reproduces one locked tag from a local repository below a temporary root a
/// test chooses, as [`reproduce_approved_git`] does over the network.
///
/// # Errors
///
/// Returns an error for a non-Git approval, or for the source, tag, package,
/// toolchain, path, archive, or source-row mismatch that
/// [`reproduce_approved_git`] reports.
#[cfg(test)]
pub(crate) fn reproduce_approved_git_from_file_in(
    root: &Path,
    approval: &Approval,
    fetch_repository: &str,
    registry_index: &str,
) -> Result<GitTagMaterialization> {
    let git = approved_git_tag(approval)?;
    let materialization = resolve_approved_git_tag(
        root,
        &git,
        &PackagingSource {
            fetch_repository,
            allow_file: true,
            registry_index,
        },
    )?;
    verify_approved_materialization(
        approval,
        git.tag_oid,
        git.commit,
        git.subdir,
        &materialization,
    )?;
    Ok(materialization)
}

/// Reproduces the given group of one locked tag from a local repository and a
/// local registry index, as [`reproduce_approved_git_group`] does over the
/// network.
///
/// # Errors
///
/// Returns an error for a group that the entry point refuses, or for the source,
/// tag, package, toolchain, path, archive, or source-row mismatch that
/// [`reproduce_approved_git_group`] reports.
#[cfg(test)]
pub(crate) fn reproduce_approved_git_group_from_file_in(
    root: &Path,
    catalog: &[Approval],
    approvals: &[&Approval],
    fetch_repository: &str,
    registry_index: &str,
) -> Result<Vec<GitTagMaterialization>> {
    reproduce_approved_git_group_in(root, catalog, approvals, |_| PackagingSource {
        fetch_repository,
        allow_file: true,
        registry_index,
    })
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
    pub(crate) published: Option<&'a [PublishedPackage<'a>]>,
    /// Pinned Cargo version of the tag.
    pub(crate) cargo_version: &'a Version,
    /// Local repository that a test fetches instead of the network.
    pub(crate) fetch_repository: &'a str,
    /// Local index of the curated registry, so that the packaging needs no network.
    pub(crate) registry_index: &'a str,
    /// Whether a dependency may name a registry the catalog retired, as only a
    /// reproduction may.
    pub(crate) allow_retired_registries: bool,
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
            allow_retired_registries: request.allow_retired_registries,
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
                published.iter().any(|candidate| candidate.name == *package),
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
    ensure_workspace_root_inside(&checkout, &metadata.root)?;
    ensure_no_patch_or_replace(&metadata, &root_manifest)?;
    let packages = select_packages(&metadata.packages, request.packages)?;
    let tag_version = packages
        .first()
        .with_context(|| format!("tag {:?} names no package", request.tag))?
        .version
        .clone();
    let siblings = sibling_packages(request.published, &metadata.packages, &packages)?;
    let paths = validated_packages(
        &metadata.packages,
        &packages,
        request,
        &tag_version,
        &checkout,
        source.registry_index,
        &siblings,
    )?;

    let workspace_lock = read_workspace_lock(&metadata.root, request.tag)?;
    let archives = package_twice(
        &cargo,
        &cargo_home,
        &environment,
        &root_manifest,
        &packages,
        temporary.path(),
        request.tag,
        &siblings,
    )?;
    ensure_clean_checkout(&environment, &checkout)?;

    let mut expected = siblings
        .iter()
        .filter_map(|(name, locked)| locked.clone().map(|sha256| (name.clone(), sha256)))
        .collect::<BTreeMap<_, _>>();
    for (package, archive_bytes) in packages.iter().zip(&archives) {
        expected.insert(package.name.clone(), sha256_bytes(archive_bytes));
    }

    materialize_packages(
        &packages,
        paths,
        archives,
        &expected,
        &siblings,
        &workspace_lock,
        &tag_version,
        &TagEvidence {
            tag_oid: &tag_oid,
            commit: &commit,
            commit_time: &commit_time,
        },
    )
}

/// The immutable Git evidence every materialization of one resolution records.
struct TagEvidence<'a> {
    /// Exact tag object ID.
    tag_oid: &'a str,
    /// Peeled commit object ID.
    commit: &'a str,
    /// Committer time of the published tag commit.
    commit_time: &'a UtcTimestamp,
}

/// Verifies the packaged lock of every package and builds its materialization.
///
/// # Errors
///
/// Returns an error for a packaged lock that departs from the tag's evidence,
/// or for a source row that cannot be generated.
#[allow(clippy::too_many_arguments)]
fn materialize_packages(
    packages: &[&MetadataPackage],
    paths: Vec<PathBuf>,
    archives: Vec<Vec<u8>>,
    expected: &BTreeMap<String, String>,
    siblings: &Siblings,
    workspace_lock: &LockFile,
    tag_version: &Version,
    evidence: &TagEvidence<'_>,
) -> Result<Vec<GitTagMaterialization>> {
    let mut materializations = Vec::with_capacity(packages.len());
    for ((package, path), archive_bytes) in packages.iter().zip(paths).zip(archives) {
        verify_packaged_lock(
            package,
            &archive_bytes,
            expected,
            siblings,
            workspace_lock,
            tag_version,
        )?;
        let archive_sha256 = sha256_bytes(&archive_bytes);
        let source_row_bytes = generated_index_record(package, &archive_sha256)?;
        let source_row_sha256 = sha256_bytes(&source_row_bytes);
        materializations.push(GitTagMaterialization {
            name: package.name.clone(),
            version: package.version.clone(),
            tag_oid: evidence.tag_oid.to_owned(),
            commit: evidence.commit.to_owned(),
            commit_time: evidence.commit_time.clone(),
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

/// Refuses a tagged workspace whose manifests declare `[patch]` or `[replace]`.
///
/// Cargo drops both sections when it packages, so a patch that points at a path
/// would let the packaged archive name a version other than the one the tag's
/// lock records. The crates.io derivation refuses the same sections for the
/// same reason. Every manifest Cargo resolves is read: the root manifest of the
/// checkout, the manifest of the workspace root, which may sit below the
/// checkout, and each member's.
///
/// # Errors
///
/// Returns an error for a manifest that cannot be read or parsed, or that holds
/// either section.
fn ensure_no_patch_or_replace(metadata: &WorkspaceMetadata, root_manifest: &Path) -> Result<()> {
    let mut manifests = BTreeSet::from([
        root_manifest.to_path_buf(),
        metadata.root.join("Cargo.toml"),
    ]);
    manifests.extend(
        metadata
            .packages
            .iter()
            .map(|package| package.manifest_path.clone()),
    );
    for path in manifests {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("read workspace manifest {}", path.display()))?;
        let document: toml::Value = toml::from_str(&text)
            .with_context(|| format!("parse workspace manifest {}", path.display()))?;
        ensure!(
            document.get("patch").is_none() && document.get("replace").is_none(),
            "workspace manifest {} declares [patch] or [replace]; the packaging drops both, so the archive would not carry the versions the tag's lock records, and a tagged workspace must declare neither",
            path.display()
        );
    }
    Ok(())
}

/// Requires the workspace root Cargo reports to lie inside the checkout.
///
/// Cargo resolves the workspace from the root manifest and can only walk up, so
/// a root outside the checkout is unreachable from a tag; requiring it keeps a
/// lock or manifest outside the tag from standing in for the tag's own, and
/// fails closed when either path cannot be resolved.
///
/// # Errors
///
/// Returns an error when the checkout or the workspace root cannot be resolved,
/// or when the root is not below the checkout.
fn ensure_workspace_root_inside(checkout: &Path, workspace_root: &Path) -> Result<()> {
    let checkout = fs::canonicalize(checkout)
        .with_context(|| format!("canonicalize checkout {}", checkout.display()))?;
    let workspace_root = fs::canonicalize(workspace_root)
        .with_context(|| format!("canonicalize workspace root {}", workspace_root.display()))?;
    ensure!(
        workspace_root.starts_with(&checkout),
        "Cargo resolved the workspace root {} outside the tag's checkout {}",
        workspace_root.display(),
        checkout.display()
    );
    Ok(())
}

/// Reads the lock file of the workspace Cargo resolved the tag with, at the
/// root Cargo reports for it.
///
/// `cargo package --locked` accepts a workspace without a lock file and writes
/// one while it packages, so a tag that does not commit the lock of its
/// workspace root would publish the dependency versions the served index
/// resolves at packaging time instead of the versions the tag records. The
/// packaged lock of every archive is then compared with this file.
///
/// # Errors
///
/// Returns an error for a workspace root without a regular `Cargo.lock`, or for
/// one that cannot be read or parsed.
fn read_workspace_lock(workspace_root: &Path, tag: &str) -> Result<LockFile> {
    let path = workspace_root.join(PACKAGED_LOCK);
    ensure!(
        path.is_file(),
        "Git tag {tag:?} does not commit a {PACKAGED_LOCK} at its workspace root {}; a published tag must commit its {PACKAGED_LOCK}, so that it is packaged at the dependency versions it records",
        workspace_root.display()
    );
    let text = fs::read_to_string(&path)
        .with_context(|| format!("read workspace lock {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parse workspace lock {}", path.display()))
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
    let mut registries = BTreeMap::from([(
        CARGO_REGISTRY,
        CargoRegistry {
            index: registry_index,
        },
    )]);
    let mut source = BTreeMap::from([
        (
            "crates-io",
            CargoSource {
                replace_with: Some("disabled"),
                registry: None,
                directory: None,
            },
        ),
        (
            "disabled",
            CargoSource {
                replace_with: None,
                registry: None,
                directory: Some(disabled.as_path()),
            },
        ),
    ]);
    for (name, retired_index) in retired_registries() {
        registries.insert(
            name,
            CargoRegistry {
                index: retired_index,
            },
        );
        source.insert(
            retired_index,
            CargoSource {
                replace_with: Some(CARGO_REGISTRY),
                registry: Some(retired_index),
                directory: None,
            },
        );
    }
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
) -> Result<WorkspaceMetadata> {
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
    Ok(WorkspaceMetadata {
        root: metadata.workspace_root,
        packages: metadata.packages,
    })
}

/// Selects and validates the requested packages of one tagged workspace.
///
/// Returns the repository-relative path of each package.
///
/// # Errors
///
/// Returns an error for a package the workspace does not hold exactly once, one
/// outside the tag's version or publication, or an invalid dependency.
fn validated_packages(
    metadata: &[MetadataPackage],
    packages: &[&MetadataPackage],
    request: &TagRequest<'_>,
    tag_version: &Version,
    checkout: &Path,
    registry_index: &str,
    siblings: &Siblings,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::with_capacity(packages.len());
    for package in packages {
        validate_tag_version(request.tag, &package.version)?;
        ensure!(
            package.publish.as_deref() == Some(&[CARGO_REGISTRY.to_owned()]),
            "first-party package must set publish = [{CARGO_REGISTRY:?}] exactly"
        );
        paths.push(package_path(checkout, &package.manifest_path)?);
    }
    for package in packages {
        validate_dependencies(
            package,
            metadata,
            siblings,
            tag_version,
            registry_index,
            request.allow_retired_registries,
        )?;
    }
    Ok(paths)
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

/// Returns every package a path dependency of one tag may point at, with the
/// archive the catalog expects for the ones it locked already.
///
/// A published package that is not part of this resolution must carry the
/// archive the catalog locked for it, since nothing else would bind a
/// dependency on it.
///
/// # Errors
///
/// Returns an error for a published package that is neither packaged here nor
/// bound to the archive the catalog locked.
fn sibling_packages(
    published: Option<&[PublishedPackage<'_>]>,
    metadata: &[MetadataPackage],
    packages: &[&MetadataPackage],
) -> Result<Siblings> {
    let Some(published) = published else {
        return Ok(published_packages(metadata)
            .into_iter()
            .map(|name| (name, None))
            .collect());
    };
    let mut siblings = BTreeMap::new();
    for package in published {
        ensure!(
            package.locked_sha256.is_some()
                || packages
                    .iter()
                    .any(|candidate| candidate.name == package.name),
            "package {:?} is published from this tag but neither packaged here nor bound to the archive the catalog locked, so a dependency on it could not be verified",
            package.name
        );
        siblings.insert(
            package.name.to_owned(),
            package.locked_sha256.map(str::to_owned),
        );
    }
    Ok(siblings)
}

/// Returns every member of one tagged workspace that publishes to the curated
/// registry, which is the widest set the catalog can publish from its tag.
fn published_packages(metadata: &[MetadataPackage]) -> BTreeSet<String> {
    metadata
        .iter()
        .filter(|package| package.publish.as_deref() == Some(&[CARGO_REGISTRY.to_owned()]))
        .map(|package| package.name.clone())
        .collect()
}

/// Returns the dependency key that a manifest wrote, with the package it points
/// at when the two differ.
fn describe_dependency(dependency: &MetadataDependency) -> String {
    match &dependency.rename {
        Some(key) => format!("{key} (package {})", dependency.name),
        None => dependency.name.clone(),
    }
}

/// Returns the registry names that the catalog declared for the curated index
/// while it served it at another URL, each with the URL it named then.
///
/// A released tag may name one of them, and its committed `Cargo.lock` records
/// that URL as the source of every dependency. Only a reproduction of an
/// identity the catalog locked may package such a tag: the isolated Cargo home
/// declares each name at its old URL and replaces that source with the curated
/// index, so Cargo resolves the versions the tag locked from the index that
/// serves them now, while the packaged lock keeps the retired source and the
/// archive reproduces the bytes the catalog locked. A new publication must name
/// [`CARGO_REGISTRY`].
///
/// [`crate::policy::SCHEMA3_REGISTRIES`] records the name and index URL of
/// every schema-3 registry, `pkgre` among them at its schema-3 URL, which is
/// not today's [`REGISTRY_INDEX`]; that entry is filtered out here by name,
/// since `pkgre` is the curated registry's name and it now serves
/// [`REGISTRY_INDEX`]. `core` is the schema-2 registry that
/// [`crate::category::category_for_v2_home`] maps, and no table records its URL.
fn retired_registries() -> Vec<(&'static str, &'static str)> {
    let mut retired = vec![("core", "sparse+https://rust.pkg.re/core/")];
    retired.extend(
        crate::policy::SCHEMA3_REGISTRIES
            .iter()
            .filter(|(name, _)| *name != CARGO_REGISTRY)
            .copied(),
    );
    retired
}

/// Returns the index of the curated registry, followed by the URLs its retired
/// names declared, which a reproduction may package.
fn curated_registry_indexes(registry_index: &str) -> Vec<&str> {
    std::iter::once(registry_index)
        .chain(retired_registries().into_iter().map(|(_, index)| index))
        .collect()
}

/// Validates every dependency of one first-party package of a tag.
///
/// A dependency must name the curated registry, whether Cargo takes it from
/// that registry or from a path inside the tagged workspace. It may name one of
/// the registry's retired names only when the request reproduces an identity the
/// catalog locked, whose index the isolated Cargo home replaces with the curated
/// one.
///
/// # Errors
///
/// Returns an error for an unpinned source, a retired registry that a new
/// publication may not name, a path dependency outside the packages the catalog
/// publishes from this tag, a requirement that is not the tag's own version, or
/// a package of another version.
fn validate_dependencies(
    package: &MetadataPackage,
    metadata: &[MetadataPackage],
    siblings: &Siblings,
    tag_version: &Version,
    registry_index: &str,
    allow_retired_registries: bool,
) -> Result<()> {
    let curated = curated_registry_indexes(registry_index);
    let registry_indexes = if allow_retired_registries {
        curated.as_slice()
    } else {
        std::slice::from_ref(&registry_index)
    };
    for dependency in &package.dependencies {
        let Some(source) = &dependency.source else {
            validate_path_dependency(
                dependency,
                metadata,
                siblings,
                tag_version,
                registry_indexes,
            )?;
            continue;
        };
        ensure!(
            is_curated_registry_source(source, registry_indexes),
            "{}",
            unsupported_source(dependency, source)
        );
        ensure!(
            dependency
                .registry
                .as_deref()
                .is_some_and(|index| registry_indexes.contains(&index)),
            "first-party package dependency {} does not declare a canonical curated registry",
            describe_dependency(dependency)
        );
    }
    Ok(())
}

/// Returns the error for a dependency that names a registry the catalog
/// retired.
///
/// Only a reproduction of a locked identity may keep such a name, and the
/// message says so for a registry dependency and a path dependency alike.
fn retired_registry_error(described: &str, name: &str) -> String {
    format!(
        "first-party package dependency {described} names the retired registry {name:?}, which only a reproduction of a locked identity may use; a new publication must name registry = {CARGO_REGISTRY:?}"
    )
}

/// Returns the error for a dependency whose source the request does not admit.
///
/// A retired name has its own message, since its removal from the catalog is
/// the reason a new publication may not name it.
fn unsupported_source(dependency: &MetadataDependency, source: &str) -> String {
    let described = describe_dependency(dependency);
    let index = source.strip_prefix("registry+").unwrap_or(source);
    if let Some((name, _)) = retired_registries()
        .into_iter()
        .find(|(_, retired_index)| *retired_index == index)
    {
        return retired_registry_error(&described, name);
    }
    format!(
        "first-party package dependency {described} uses unsupported source {source:?}; use registry = {CARGO_REGISTRY:?} explicitly"
    )
}

/// Returns the error for a path dependency that does not name an admitted
/// registry.
///
/// A retired name has its own message, as for a registry dependency.
fn unsupported_path_registry(dependency: &MetadataDependency) -> String {
    let described = describe_dependency(dependency);
    let declared = dependency.registry.as_deref();
    if let Some((name, _)) = retired_registries()
        .into_iter()
        .find(|(_, retired_index)| Some(*retired_index) == declared)
    {
        return retired_registry_error(&described, name);
    }
    format!(
        "first-party package dependency {described} is a path dependency that does not declare registry = {CARGO_REGISTRY:?}; a package of the same tag must be required from the curated registry"
    )
}

/// Validates one dependency that Cargo takes from a path inside the tagged
/// workspace.
///
/// Such a dependency is accepted only on another package the catalog publishes
/// from the same repository and tag, at the tag's version, and only when it
/// names the curated registry, requires exactly the tag's version, and points
/// at that package's own directory, since the packaged manifest carries no
/// path.
///
/// # Errors
///
/// Returns an error for a missing registry declaration, a requirement that is
/// not `=X.Y.Z` of the tag, a target outside the tagged workspace, a target the
/// catalog does not publish from this tag, a target of another version, or a
/// directory that is not the target package's own.
fn validate_path_dependency(
    dependency: &MetadataDependency,
    metadata: &[MetadataPackage],
    siblings: &Siblings,
    tag_version: &Version,
    registry_indexes: &[&str],
) -> Result<()> {
    let described = describe_dependency(dependency);
    ensure!(
        dependency
            .registry
            .as_deref()
            .is_some_and(|index| registry_indexes.contains(&index)),
        "{}",
        unsupported_path_registry(dependency)
    );
    let exact = format!("={tag_version}");
    let expected = VersionReq::parse(&exact).context("build the exact requirement of the tag")?;
    ensure!(
        VersionReq::parse(&dependency.req).is_ok_and(|requirement| requirement == expected),
        "first-party package dependency {described} requires {:?}; a path dependency on a package of the same tag must require exactly {exact:?}",
        dependency.req
    );
    let target = metadata
        .iter()
        .find(|candidate| candidate.name == dependency.name)
        .with_context(|| {
            format!(
                "first-party package dependency {described} is a path dependency on no package of the tagged workspace"
            )
        })?;
    ensure!(
        siblings.contains_key(&target.name),
        "first-party package dependency {described} is a path dependency on {}, which the catalog does not publish from this tag",
        target.name
    );
    ensure!(
        target.version == *tag_version,
        "first-party package dependency {described} is a path dependency on {} {}, whose version is not the tag's version {tag_version}",
        target.name,
        target.version
    );
    let directory = dependency.path.as_deref().with_context(|| {
        format!(
            "first-party package dependency {described} is a path dependency without a directory"
        )
    })?;
    let target_directory = target
        .manifest_path
        .parent()
        .with_context(|| format!("the manifest of {} has no parent directory", target.name))?;
    ensure!(
        same_directory(directory, target_directory)?,
        "first-party package dependency {described} is a path dependency on {}, but the package {} the catalog publishes from this tag is at {}",
        directory.display(),
        target.name,
        target_directory.display()
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

/// Packages the group twice into distinct target directories and returns the
/// archives of the first run.
///
/// # Errors
///
/// Returns an error when a run fails, or when the two runs produced different
/// bytes for a package.
#[allow(clippy::too_many_arguments)]
fn package_twice(
    cargo: &Path,
    cargo_home: &Path,
    environment: &ChildEnvironment,
    manifest_path: &Path,
    packages: &[&MetadataPackage],
    temporary: &Path,
    tag: &str,
    siblings: &Siblings,
) -> Result<Vec<Vec<u8>>> {
    let mut archives = Vec::new();
    for directory in ["target-one", "target-two"] {
        let run = package_group(
            cargo,
            cargo_home,
            environment,
            manifest_path,
            packages,
            &temporary.join(directory),
            tag,
            siblings,
        )?;
        if archives.is_empty() {
            archives = run;
            continue;
        }
        for ((package, archive_bytes), repeated_bytes) in packages.iter().zip(&archives).zip(run) {
            ensure!(
                archive_bytes == &repeated_bytes,
                "pinned Cargo produced non-deterministic archives for {} {}",
                package.name,
                package.version
            );
        }
    }
    Ok(archives)
}

/// Packages the group and explains a failure when a package may depend on a
/// sibling the catalog locked already.
///
/// Cargo takes such a dependency from the registry index, which must serve the
/// identity the catalog locked, and its own message for a missing identity does
/// not say so.
///
/// # Errors
///
/// Returns an error when Cargo fails, or when an archive is missing, too large,
/// or not a regular file.
#[allow(clippy::too_many_arguments)]
fn package_group(
    cargo: &Path,
    cargo_home: &Path,
    environment: &ChildEnvironment,
    manifest_path: &Path,
    packages: &[&MetadataPackage],
    target: &Path,
    tag: &str,
    siblings: &Siblings,
) -> Result<Vec<Vec<u8>>> {
    run_cargo_package(
        cargo,
        cargo_home,
        environment,
        manifest_path,
        packages,
        target,
    )
    .map_err(|error| {
        let locked = siblings
            .iter()
            .filter(|(name, locked)| {
                locked.is_some() && !packages.iter().any(|package| package.name == **name)
            })
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        if locked.is_empty() {
            error
        } else {
            error.context(format!(
                "package the group of tag {tag:?}; a dependency on {} is taken from the registry index, which must serve the identity the catalog locked",
                locked.join(", ")
            ))
        }
    })
}

/// Verifies the packaged lock of one package against the tag's own evidence.
///
/// The lock must name the archives the tag publishes for its sibling
/// dependencies, and every registry package it records must be the one the
/// tag's workspace lock records, at the same source and checksum.
///
/// # Errors
///
/// Returns an error for a packaged lock that cannot be read or parsed, a
/// registry package the tag's lock does not record, one of another source or
/// checksum, a sibling entry of another archive, or a missing sibling entry.
fn verify_packaged_lock(
    package: &MetadataPackage,
    archive_bytes: &[u8],
    archives: &BTreeMap<String, String>,
    siblings: &Siblings,
    workspace_lock: &LockFile,
    tag_version: &Version,
) -> Result<()> {
    let lock = packaged_lock(package, archive_bytes)?;
    verify_sibling_archives(&lock, package, archives, tag_version)?;
    verify_locked_versions(&lock, package, siblings, workspace_lock)
}

/// Returns the lock file Cargo wrote into one packaged archive.
///
/// # Errors
///
/// Returns an error for an archive that cannot be read, holds no lock file, or
/// holds one that cannot be parsed.
fn packaged_lock(package: &MetadataPackage, archive_bytes: &[u8]) -> Result<LockFile> {
    let archive = crate::update::read_crate_archive(
        &package.name,
        &package.version,
        archive_bytes,
        &[PACKAGED_LOCK],
    )
    .with_context(|| {
        format!(
            "read the packaged archive of {} {}",
            package.name, package.version
        )
    })?;
    let lock = archive.contents.get(PACKAGED_LOCK).with_context(|| {
        format!(
            "the packaged archive of {} {} holds no {PACKAGED_LOCK}",
            package.name, package.version
        )
    })?;
    let lock = std::str::from_utf8(lock).context("parse the packaged lock as UTF-8")?;
    toml::from_str(lock).with_context(|| {
        format!(
            "parse the packaged lock of {} {}",
            package.name, package.version
        )
    })
}

/// Verifies the packaged lock of one package against the archives its sibling
/// dependencies must name.
///
/// A path dependency is packaged as a registry dependency, so Cargo records the
/// archive of the package it points at in the packaged lock, under the tag's
/// version of that package. The archive this tag publishes for it is the only
/// one that entry may name, so a lock that names another one is refused.
///
/// # Errors
///
/// Returns an error for a lock without exactly one entry for a sibling at the
/// tag's version, or an entry whose checksum is not the expected archive.
fn verify_sibling_archives(
    lock: &LockFile,
    package: &MetadataPackage,
    archives: &BTreeMap<String, String>,
    tag_version: &Version,
) -> Result<()> {
    let mut siblings = Vec::new();
    for dependency in &package.dependencies {
        if dependency.source.is_some() {
            continue;
        }
        if let Some(archive_sha256) = archives.get(&dependency.name) {
            siblings.push((dependency.name.as_str(), archive_sha256.as_str()));
        }
    }
    for (name, archive_sha256) in siblings {
        // The lock may hold another version of the same name, so the entry this
        // tag publishes is the one of the tag's version.
        let mut entries = lock
            .packages
            .iter()
            .filter(|entry| entry.name == name && entry.version == *tag_version);
        let entry = entries.next().with_context(|| {
            format!(
                "the packaged lock of {} {} records no {name} {tag_version}",
                package.name, package.version
            )
        })?;
        ensure!(
            entries.next().is_none(),
            "the packaged lock of {} {} records {name} {tag_version} more than once",
            package.name,
            package.version
        );
        ensure!(
            entry.checksum.as_deref() == Some(archive_sha256),
            "the packaged lock of {} {} records checksum {} for {name} {tag_version}; this tag publishes {name} as {archive_sha256}, so a dependency on another archive is refused",
            package.name,
            package.version,
            entry.checksum.as_deref().unwrap_or("none")
        );
    }
    Ok(())
}

/// Verifies that every registry package of one packaged lock is the one the
/// tag's workspace lock records.
///
/// `cargo package --locked` binds the versions of the tag's own lock, but the
/// archive is packaged from a resolution of its own: a workspace root below the
/// checkout root, or a `[patch]` that Cargo drops, can make it take a version
/// the tag never recorded. Comparing each registry entry with the workspace
/// lock closes that, since a registry dependency the tag's lock records at
/// another version, source, or checksum is refused.
///
/// A path dependency of the tag becomes a registry dependency in the packaged
/// lock, and the tag's lock records no archive for it: such an entry is accepted
/// only for a sibling of the tag, whose archive this run binds.
///
/// # Errors
///
/// Returns an error for a registry package the tag's lock does not record at
/// that version, one of another source or checksum, or a path package of the
/// tag that is not a sibling.
fn verify_locked_versions(
    lock: &LockFile,
    package: &MetadataPackage,
    siblings: &Siblings,
    workspace_lock: &LockFile,
) -> Result<()> {
    for entry in &lock.packages {
        if entry.source.is_none() {
            continue;
        }
        let recorded = workspace_lock
            .packages
            .iter()
            .filter(|locked| locked.name == entry.name);
        let Some(locked) = recorded
            .clone()
            .find(|locked| locked.version == entry.version)
        else {
            let versions = recorded
                .map(|locked| locked.version.to_string())
                .collect::<Vec<_>>();
            bail!(
                "the packaged lock of {} {} records {} {} from {}, which the tag's workspace lock does not record; a published tag is packaged at the versions its lock records{}",
                package.name,
                package.version,
                entry.name,
                entry.version,
                entry.source.as_deref().unwrap_or("nothing"),
                if versions.is_empty() {
                    String::new()
                } else {
                    format!(" ({}, which it records instead)", versions.join(", "))
                }
            );
        };
        let Some(checksum) = &locked.checksum else {
            ensure!(
                siblings.contains_key(&entry.name),
                "the packaged lock of {} {} records {} {} from {}, but the tag's workspace lock records it as a path package that is not a sibling the catalog publishes from this tag",
                package.name,
                package.version,
                entry.name,
                entry.version,
                entry.source.as_deref().unwrap_or("nothing")
            );
            continue;
        };
        let source = locked.source.as_deref().with_context(|| {
            format!(
                "the workspace lock records a checksum for {} {} without a source",
                locked.name, locked.version
            )
        })?;
        ensure!(
            entry.checksum.as_deref() == Some(checksum.as_str())
                && entry.source.as_deref() == Some(source),
            "the packaged lock of {} {} records {} {} from {} at checksum {}, but the tag's workspace lock records it from {source} at checksum {checksum}",
            package.name,
            package.version,
            entry.name,
            entry.version,
            entry.source.as_deref().unwrap_or("nothing"),
            entry.checksum.as_deref().unwrap_or("none")
        );
    }
    Ok(())
}

/// Returns whether two directories are the same directory, resolving symbolic
/// links in both.
///
/// # Errors
///
/// Returns an error for a directory that cannot be resolved.
fn same_directory(left: &Path, right: &Path) -> Result<bool> {
    let left = fs::canonicalize(left)
        .with_context(|| format!("resolve path dependency directory {}", left.display()))?;
    let right = fs::canonicalize(right)
        .with_context(|| format!("resolve package directory {}", right.display()))?;
    Ok(left == right)
}

/// The lock file Cargo writes into every packaged archive, and the one a tagged
/// workspace commits at its root.
const PACKAGED_LOCK: &str = "Cargo.lock";

/// One Cargo lock file: the workspace lock a tag commits, or the lock Cargo
/// writes into one packaged archive.
#[derive(Debug, Deserialize)]
struct LockFile {
    #[serde(default, rename = "package")]
    packages: Vec<LockedPackage>,
}

/// One package entry of a lock file.
#[derive(Debug, Deserialize)]
struct LockedPackage {
    name: String,
    version: Version,
    /// Registry or Git source of the package; a path package has none.
    source: Option<String>,
    /// SHA-256 of the archive the source serves, which a path package has not.
    checksum: Option<String>,
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
    use crate::lock::{ResolvedPackage, Resolver};
    use crate::schema::{LockedSource, PackageState};
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
                path: None,
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

    #[test]
    fn git_tag_packaging_refuses_a_tag_without_a_committed_lock_file() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-lock").unwrap();
        let source = create_test_release_with_lock(&temporary, false);
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
            message.contains("a published tag must commit its Cargo.lock"),
            "the error says what the tag must hold: {message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_lock_that_is_not_the_workspace_file() {
        for layout in ["directory", "member"] {
            let root = uncovered_temporary_root();
            let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-lock-shape").unwrap();
            let source = create_test_release_with_lock(&temporary, true);
            match layout {
                "directory" => {
                    fs::remove_file(source.join("Cargo.lock")).unwrap();
                    fs::create_dir(source.join("Cargo.lock")).unwrap();
                    fs::write(source.join("Cargo.lock/entry"), "x").unwrap();
                }
                "member" => {
                    fs::rename(
                        source.join("Cargo.lock"),
                        source.join("crates/demo/Cargo.lock"),
                    )
                    .unwrap();
                }
                other => panic!("unknown lock layout {other:?}"),
            }
            test_git(&source, &["add", "--all"]);
            test_git(&source, &["commit", "--quiet", "-m", "move the lock"]);
            retag(&source);
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
                message.contains("a published tag must commit its Cargo.lock"),
                "a {layout} lock is refused: {message}"
            );
        }
    }

    #[test]
    fn git_tag_packaging_reads_the_lock_of_the_workspace_root_cargo_uses() {
        for keep_lock_at_the_workspace_root in [true, false] {
            let root = uncovered_temporary_root();
            let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-workspace-below").unwrap();
            let index = create_test_index(&temporary);
            publish_test_index_versions(&index, "pkgre-dep", &["1.0.0"]);
            let source = create_workspace_below_release(&temporary, &index);
            // A newer version reaches the index after the tag's lock pinned
            // 1.0.0, so a packaging that resolves for itself takes 1.0.1.
            publish_test_index_versions(&index, "pkgre-dep", &["1.0.0", "1.0.1"]);
            // Moving the lock to the checkout root leaves the workspace root
            // without one, which a check of the checkout root would accept
            // while Cargo resolved 1.0.1 at packaging time.
            if !keep_lock_at_the_workspace_root {
                fs::rename(source.join("ws/Cargo.lock"), source.join("Cargo.lock")).unwrap();
                test_git(&source, &["add", "--all"]);
                test_git(&source, &["commit", "--quiet", "-m", "move the lock"]);
                retag(&source);
            }
            let published = ["pkgre-demo"];
            let result = resolve_test_group(&root, &source, &index, &published, &published);
            if !keep_lock_at_the_workspace_root {
                let error = result.unwrap_err();
                let message = format!("{error:#}");
                assert!(
                    message.contains("a published tag must commit its Cargo.lock"),
                    "the lock of the checkout root does not stand in for the workspace lock: {message}"
                );
                continue;
            }
            let materialization = result.unwrap().remove(0);
            let packaged = crate::update::read_crate_archive(
                "pkgre-demo",
                &materialization.version,
                &materialization.archive_bytes,
                &["Cargo.lock"],
            )
            .unwrap();
            let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
            assert!(
                lock.contains("name = \"pkgre-dep\"") && lock.contains("version = \"1.0.0\""),
                "the packaged lock records the version the workspace lock pins: {lock}"
            );
            assert!(
                !lock.contains("1.0.1"),
                "the packaged lock does not take the newer version the index serves: {lock}"
            );
        }
    }

    #[test]
    fn git_tag_packaging_refuses_a_patch_or_replace_section() {
        for section in ["patch", "replace"] {
            let root = uncovered_temporary_root();
            let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-patch").unwrap();
            let index = create_test_index(&temporary);
            publish_test_index_versions(&index, "pkgre-dep", &["1.0.0", "1.0.1"]);
            let patched = match section {
                "patch" => "\n[patch.pkgre]\npkgre-dep = { path = \"vendor/dep\" }\n".to_owned(),
                "replace" => {
                    "\n[replace]\n\"pkgre-dep:1.0.0\" = { path = \"vendor/dep\" }\n".to_owned()
                }
                other => panic!("unknown section {other:?}"),
            };
            let source = create_dependency_release(
                &temporary,
                &index,
                &patched,
                &[
                    (
                        "vendor/dep/Cargo.toml",
                        "[package]\nname = \"pkgre-dep\"\nversion = \"1.0.0\"\nedition = \"2024\"\n",
                    ),
                    ("vendor/dep/src/lib.rs", "pub fn vendored() {}\n"),
                ],
            );
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
                message.contains("declares [patch] or [replace]"),
                "the packaging drops a {section} section, so it refuses it: {message}"
            );
        }
    }

    #[test]
    fn git_tag_packaging_refuses_a_patch_in_the_workspace_root_below_the_checkout() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-patch-below").unwrap();
        let index = create_test_index(&temporary);
        publish_test_index_versions(&index, "pkgre-dep", &["1.0.0", "1.0.1"]);
        let source = create_workspace_below_patch_release(&temporary, &index);
        let published = ["pkgre-demo"];
        let error = resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("declares [patch] or [replace]") && message.contains("ws/Cargo.toml"),
            "the workspace root manifest below the checkout is read too: {message}"
        );
    }

    #[test]
    fn a_workspace_root_outside_the_checkout_is_refused() {
        let temporary = TemporaryDirectory::new("pkgre-workspace-root").unwrap();
        let checkout = temporary.path().join("repository");
        let inside = checkout.join("ws");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        ensure_workspace_root_inside(&checkout, &inside).unwrap();
        let error = ensure_workspace_root_inside(&checkout, &outside).unwrap_err();
        assert!(
            format!("{error:#}").contains("outside the tag's checkout"),
            "{error:#}"
        );
        let error = ensure_workspace_root_inside(&checkout, &checkout.join("missing")).unwrap_err();
        assert!(
            format!("{error:#}").contains("canonicalize workspace root"),
            "a workspace root that does not exist fails closed: {error:#}"
        );
    }

    #[test]
    fn a_new_publication_refuses_a_tag_that_names_a_retired_registry() {
        for registry_name in ["core", "universe"] {
            let root = uncovered_temporary_root();
            let temporary =
                TemporaryDirectory::new_in(&root, "pkgre-git-retired-admission").unwrap();
            let index = create_test_index(&temporary);
            publish_test_index_versions(&index, "pkgre-dep", &["1.0.0"]);
            let source = create_retired_registry_release(&temporary, &index, registry_name);
            let published = ["pkgre-demo"];
            let error =
                resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("names the retired registry {registry_name:?}"))
                    && message.contains("a new publication must name registry = \"pkgre\""),
                "an admission refuses the retired name and says what to declare: {message}"
            );
        }
    }

    #[test]
    fn a_new_publication_refuses_a_sibling_path_dependency_that_names_a_retired_registry() {
        for registry_name in ["core", "universe"] {
            let root = uncovered_temporary_root();
            let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-retired-sibling").unwrap();
            let index = create_test_index(&temporary);
            let source = create_retired_sibling_release(&temporary, &index, registry_name);
            let published = ["pkgre-demo", "pkgre-base"];
            let error =
                resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("names the retired registry {registry_name:?}"))
                    && message.contains("a new publication must name registry = \"pkgre\""),
                "an admission refuses a retired name on a path dependency too: {message}"
            );
        }
    }

    #[test]
    fn a_reproduction_packages_a_sibling_path_dependency_that_names_a_retired_registry() {
        let root = uncovered_temporary_root();
        let temporary =
            TemporaryDirectory::new_in(&root, "pkgre-git-retired-sibling-reproduce").unwrap();
        let index = create_test_index(&temporary);
        let source = create_retired_sibling_release(&temporary, &index, "core");
        let retired = retired_registries()
            .into_iter()
            .find(|(name, _)| *name == "core")
            .unwrap()
            .1;
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let published = [
            PublishedPackage {
                name: "pkgre-demo",
                locked_sha256: None,
            },
            PublishedPackage {
                name: "pkgre-base",
                locked_sha256: None,
            },
        ];
        let mut materializations = resolve_git_tag_group_from_file(&FileTagRequest {
            root: &root,
            repository: "https://example.invalid/pkgre-demo",
            tag: TEST_TAG,
            packages: &["pkgre-demo", "pkgre-base"],
            published: Some(&published),
            cargo_version: &cargo_version,
            fetch_repository: source.to_str().unwrap(),
            registry_index: &index,
            allow_retired_registries: true,
        })
        .unwrap();
        let base = materializations.remove(1);
        let demo = materializations.remove(0);
        let row: Value = serde_json::from_slice(&demo.source_row_bytes).unwrap();
        assert_eq!(
            row["deps"][0]["registry"], retired,
            "the path dependency keeps the retired name in the source row"
        );
        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &demo.version,
            &demo.archive_bytes,
            &["Cargo.lock"],
        )
        .unwrap();
        let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
        assert!(
            lock.contains(&format!("source = \"{retired}\""))
                && lock.contains(&format!("checksum = \"{}\"", base.archive_sha256)),
            "the packaged lock records the sibling from the retired source at its archive: {lock}"
        );

        let approval = test_approval(&demo, &cargo_version);
        // The reproduction packages the dependent alone, so Cargo takes the
        // sibling from the index, which must serve the archive this tag
        // publishes for it.
        publish_test_index_entry(&index, "pkgre-base", &base.version, &base.archive_sha256);
        let reproduced =
            reproduce_approved_git_from_file_in(&root, &approval, source.to_str().unwrap(), &index)
                .unwrap();
        assert_eq!(reproduced.archive_sha256, demo.archive_sha256);
    }

    #[test]
    fn a_reproduction_packages_a_tag_that_names_a_retired_registry() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-retired-reproduce").unwrap();
        let index = create_test_index(&temporary);
        publish_test_index_versions(&index, "pkgre-dep", &["1.0.0"]);
        let source = create_retired_registry_release(&temporary, &index, "core");
        let retired = retired_registries()
            .into_iter()
            .find(|(name, _)| *name == "core")
            .unwrap()
            .1;
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let mut materializations = resolve_git_tag_group_from_file(&FileTagRequest {
            root: &root,
            repository: "https://example.invalid/pkgre-demo",
            tag: TEST_TAG,
            packages: &["pkgre-demo"],
            published: None,
            cargo_version: &cargo_version,
            fetch_repository: source.to_str().unwrap(),
            registry_index: &index,
            allow_retired_registries: true,
        })
        .unwrap();
        let materialization = materializations.remove(0);
        let row: Value = serde_json::from_slice(&materialization.source_row_bytes).unwrap();
        assert_eq!(
            row["deps"][0]["registry"], retired,
            "the tag names the retired registry in the source row the catalog would lock"
        );

        let approval = test_approval(&materialization, &cargo_version);
        let reproduced =
            reproduce_approved_git_from_file_in(&root, &approval, source.to_str().unwrap(), &index)
                .unwrap();
        assert_eq!(reproduced.archive_sha256, materialization.archive_sha256);
        assert_eq!(
            reproduced.source_row_sha256,
            materialization.source_row_sha256
        );

        let mut tampered = approval.clone();
        tampered.archive_sha256 = "00".repeat(32);
        let error =
            reproduce_approved_git_from_file_in(&root, &tampered, source.to_str().unwrap(), &index)
                .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("Git archive hash changed"),
            "the reproduction compares the archive with the locked one: {message}"
        );
    }

    #[test]
    fn a_reproduction_of_an_added_git_tag_identity_passes_and_refuses_a_tampered_one() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-added-reproduce").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_release(&temporary);
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let mut materializations = resolve_git_tag_group_from_file(&FileTagRequest {
            root: &root,
            repository: "https://example.invalid/pkgre-demo",
            tag: TEST_TAG,
            packages: &["pkgre-demo"],
            published: None,
            cargo_version: &cargo_version,
            fetch_repository: source.to_str().unwrap(),
            registry_index: &index,
            allow_retired_registries: true,
        })
        .unwrap();
        let approval = test_approval(&materializations.remove(0), &cargo_version);
        let catalog = [approval.clone()];
        let mut reproduce = |group: &[&Approval]| {
            reproduce_approved_git_group_from_file_in(
                &root,
                &catalog,
                group,
                source.to_str().unwrap(),
                &index,
            )
            .map(|_| ())
        };

        let reproduced =
            crate::reproduce::reproduce_groups(&[vec![&approval]], &mut reproduce).unwrap();
        assert_eq!(
            reproduced, 1,
            "one added identity is packaged again and matched against the locked archive and row"
        );

        let mut tampered = approval.clone();
        tampered.archive_sha256 = "00".repeat(32);
        let error =
            crate::reproduce::reproduce_groups(&[vec![&tampered]], &mut reproduce).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("reproduce added main/pkgre-demo/1.2.3")
                && message.contains("Git archive hash changed"),
            "a tampered identity is reported with its identity and its cause: {message}"
        );
    }

    #[test]
    fn a_reproduction_of_one_tag_packages_its_identities_together() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-group-reproduce").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let published = ["pkgre-demo", "pkgre-base"];
        // The tag publishes both crates, and the index serves neither of them.
        let mut materializations =
            resolve_test_group(&root, &source, &index, &published, &published).unwrap();
        let base = materializations.remove(1);
        let demo = materializations.remove(0);
        let catalog = vec![
            test_approval(&demo, &cargo_version),
            test_approval(&base, &cargo_version),
        ];

        // The reproduction of one identity knows no catalog, so Cargo takes the
        // sibling it depends on from the index, which serves no added identity.
        let error = reproduce_approved_git_from_file_in(
            &root,
            &catalog[0],
            source.to_str().unwrap(),
            &index,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("no matching package named `pkgre-base` found"),
            "the dependent alone needs its sibling from the index: {message}"
        );

        // One resolution packages the identities of the tag together, so the
        // dependent needs no index entry for its sibling.
        let group = catalog.iter().collect::<Vec<_>>();
        let reproduced = reproduce_approved_git_group_from_file_in(
            &root,
            &catalog,
            &group,
            source.to_str().unwrap(),
            &index,
        )
        .unwrap();
        let [reproduced_demo, reproduced_base] = reproduced.as_slice() else {
            panic!(
                "one group of two identities reproduced {} materializations",
                reproduced.len()
            );
        };
        assert_eq!(reproduced_demo.name, "pkgre-demo");
        assert_eq!(reproduced_demo.archive_sha256, demo.archive_sha256);
        assert_eq!(reproduced_demo.source_row_sha256, demo.source_row_sha256);
        assert_eq!(reproduced_base.name, "pkgre-base");
        assert_eq!(reproduced_base.archive_sha256, base.archive_sha256);
        assert_eq!(reproduced_base.source_row_sha256, base.source_row_sha256);
        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &reproduced_demo.version,
            &reproduced_demo.archive_bytes,
            &["Cargo.lock"],
        )
        .unwrap();
        let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
        assert!(
            lock.contains(&format!("checksum = \"{}\"", base.archive_sha256)),
            "the packaged lock names the sibling's locked archive: {lock}"
        );
    }

    #[test]
    fn a_reproduction_of_a_group_refuses_a_sibling_archive_the_index_serves_another_way() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-group-sibling").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let published = ["pkgre-demo", "pkgre-base"];
        let mut materializations =
            resolve_test_group(&root, &source, &index, &published, &published).unwrap();
        let base = materializations.remove(1);
        let demo = materializations.remove(0);
        let catalog = vec![
            test_approval(&demo, &cargo_version),
            test_approval(&base, &cargo_version),
        ];
        // The accepted catalog locks the sibling already, so the group packages
        // the dependent alone and Cargo takes the sibling from the index.
        let group = [&catalog[0]];
        publish_test_index_entry(&index, "pkgre-base", &base.version, &base.archive_sha256);
        let reproduced = reproduce_approved_git_group_from_file_in(
            &root,
            &catalog,
            &group,
            source.to_str().unwrap(),
            &index,
        )
        .unwrap();
        assert_eq!(reproduced.len(), 1);
        assert_eq!(reproduced[0].archive_sha256, demo.archive_sha256);

        let other = "00".repeat(32);
        publish_test_index_entry(&index, "pkgre-base", &base.version, &other);
        let error = reproduce_approved_git_group_from_file_in(
            &root,
            &catalog,
            &group,
            source.to_str().unwrap(),
            &index,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!(
                "records checksum {other} for pkgre-base {}; this tag publishes pkgre-base as {}, so a dependency on another archive is refused",
                base.version, base.archive_sha256
            )),
            "the packaged lock must name the archive the candidate locks: {message}"
        );
    }

    #[test]
    fn a_group_reproduction_refuses_a_tag_that_names_a_retired_registry() {
        for registry_name in ["core", "universe"] {
            let root = uncovered_temporary_root();
            let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-group-retired").unwrap();
            let index = create_test_index(&temporary);
            publish_test_index_versions(&index, "pkgre-dep", &["1.0.0"]);
            let source = create_retired_registry_release(&temporary, &index, registry_name);
            let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
            let mut materializations = resolve_git_tag_group_from_file(&FileTagRequest {
                root: &root,
                repository: "https://example.invalid/pkgre-demo",
                tag: TEST_TAG,
                packages: &["pkgre-demo"],
                published: None,
                cargo_version: &cargo_version,
                fetch_repository: source.to_str().unwrap(),
                registry_index: &index,
                allow_retired_registries: true,
            })
            .unwrap();
            let catalog = [test_approval(&materializations.remove(0), &cargo_version)];
            let group = [&catalog[0]];

            let error = reproduce_approved_git_group_from_file_in(
                &root,
                &catalog,
                &group,
                source.to_str().unwrap(),
                &index,
            )
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("names the retired registry {registry_name:?}"))
                    && message.contains("a new publication must name registry = \"pkgre\""),
                "an identity a change adds follows the first-publication rules: {message}"
            );
        }
    }

    #[test]
    fn a_group_reproduction_publishes_only_the_packages_of_its_own_tag_and_registry() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-group-published").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let published = ["pkgre-demo", "pkgre-base"];
        let mut materializations =
            resolve_test_group(&root, &source, &index, &published, &published).unwrap();
        let demo = test_approval(&materializations.remove(0), &cargo_version);
        let base = test_approval(&materializations.remove(0), &cargo_version);
        let repository = "https://example.invalid/pkgre-demo";
        // The catalog holds the sibling's name under another tag, the tag under
        // another registry, and the sibling as a removed identity of the tag.
        let other_tag_archive = "11".repeat(32);
        let other_registry_archive = "22".repeat(32);
        let removed_archive = "33".repeat(32);
        let mut other_tag = at(
            base.clone(),
            "main",
            repository,
            "release/pkgre-base/v1.2.3",
        );
        other_tag.archive_sha256 = other_tag_archive.clone();
        let mut other_registry = at(base.clone(), "staging", repository, TEST_TAG);
        other_registry.archive_sha256 = other_registry_archive.clone();
        let mut removed = at(base.clone(), "main", repository, TEST_TAG);
        removed.state = PackageState::Removed;
        removed.archive_sha256 = removed_archive.clone();
        let catalog = vec![
            demo.clone(),
            base.clone(),
            other_tag,
            other_registry,
            removed,
        ];
        // The accepted catalog locks the sibling already, so the group packages
        // the dependent alone and Cargo takes the sibling from the index, which
        // serves the archive the sibling's own identity locks.
        let group = [&catalog[0]];
        publish_test_index_entry(&index, "pkgre-base", &base.version, &base.archive_sha256);
        let reproduced = reproduce_approved_git_group_from_file_in(
            &root,
            &catalog,
            &group,
            source.to_str().unwrap(),
            &index,
        )
        .unwrap();
        assert_eq!(reproduced.len(), 1);
        assert_eq!(reproduced[0].archive_sha256, demo.archive_sha256);
        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &reproduced[0].version,
            &reproduced[0].archive_bytes,
            &["Cargo.lock"],
        )
        .unwrap();
        let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
        assert!(
            lock.contains(&format!("checksum = \"{}\"", base.archive_sha256))
                && !lock.contains(&other_tag_archive)
                && !lock.contains(&other_registry_archive)
                && !lock.contains(&removed_archive),
            "the group binds the sibling to the archive its own identity locks: {lock}"
        );

        // A removed identity of the tag is no package the tag publishes, so a
        // path dependency on it is refused.
        let mut removed_catalog = vec![demo, base];
        removed_catalog[1].state = PackageState::Removed;
        let group = [&removed_catalog[0]];
        let error = reproduce_approved_git_group_from_file_in(
            &root,
            &removed_catalog,
            &group,
            source.to_str().unwrap(),
            &index,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(
                "is a path dependency on pkgre-base, which the catalog does not publish from this tag"
            ),
            "a removed sibling is not a package the tag publishes: {message}"
        );
    }

    #[test]
    fn a_packaged_lock_must_take_the_versions_the_tag_lock_records() {
        let lock = |entries: &[(&str, &str, Option<&str>, Option<&str>)]| LockFile {
            packages: entries
                .iter()
                .map(|(name, version, source, checksum)| LockedPackage {
                    name: (*name).to_owned(),
                    version: Version::parse(version).unwrap(),
                    source: source.map(str::to_owned),
                    checksum: checksum.map(str::to_owned),
                })
                .collect(),
        };
        let package = MetadataPackage {
            name: "pkgre-demo".to_owned(),
            version: Version::parse("1.2.3").unwrap(),
            manifest_path: PathBuf::from("Cargo.toml"),
            dependencies: Vec::new(),
            features: BTreeMap::new(),
            links: None,
            rust_version: None,
            publish: Some(vec![CARGO_REGISTRY.to_owned()]),
        };
        let index = "sparse+https://rust.pkg.re/";
        let workspace = lock(&[("pkgre-dep", "1.0.0", Some(index), Some(&"01".repeat(32)))]);
        let siblings = BTreeMap::new();
        verify_locked_versions(
            &lock(&[("pkgre-dep", "1.0.0", Some(index), Some(&"01".repeat(32)))]),
            &package,
            &siblings,
            &workspace,
        )
        .unwrap();

        let error = verify_locked_versions(
            &lock(&[("pkgre-dep", "1.0.1", Some(index), Some(&"02".repeat(32)))]),
            &package,
            &siblings,
            &workspace,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("which the tag's workspace lock does not record"),
            "a version the tag's lock does not record is refused: {error:#}"
        );

        let error = verify_locked_versions(
            &lock(&[("pkgre-dep", "1.0.0", Some(index), Some(&"02".repeat(32)))]),
            &package,
            &siblings,
            &workspace,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("but the tag's workspace lock records it from"),
            "another checksum is refused: {error:#}"
        );

        let other = "sparse+https://other.invalid/";
        let error = verify_locked_versions(
            &lock(&[("pkgre-dep", "1.0.0", Some(other), Some(&"01".repeat(32)))]),
            &package,
            &siblings,
            &workspace,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(other) && message.contains(index),
            "another source is refused even at the recorded checksum: {message}"
        );

        let patched = lock(&[("pkgre-dep", "1.0.0", None, None)]);
        let error = verify_locked_versions(
            &lock(&[("pkgre-dep", "1.0.0", Some(index), Some(&"01".repeat(32)))]),
            &package,
            &siblings,
            &patched,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("is not a sibling the catalog publishes from this tag"),
            "a packaged registry package the tag records as a path package is refused: {error:#}"
        );
    }

    #[test]
    fn isolated_cargo_home_replaces_every_retired_registry_name() {
        let temporary = TemporaryDirectory::new("pkgre-cargo-home").unwrap();
        let cargo_home = temporary.path().join("cargo-home");
        prepare_cargo_home(&cargo_home, REGISTRY_INDEX).unwrap();
        let config: toml::Value =
            toml::from_str(&fs::read_to_string(cargo_home.join("config.toml")).unwrap()).unwrap();
        assert_eq!(
            config["registries"][CARGO_REGISTRY]["index"].as_str(),
            Some(REGISTRY_INDEX)
        );
        for (name, index) in retired_registries() {
            assert_eq!(config["registries"][name]["index"].as_str(), Some(index));
            assert_eq!(config["source"][index]["registry"].as_str(), Some(index));
            assert_eq!(
                config["source"][index]["replace-with"].as_str(),
                Some(CARGO_REGISTRY)
            );
        }
    }

    #[test]
    fn only_a_reproduction_may_name_a_retired_registry() {
        let version = Version::parse("0.3.0").unwrap();
        let dependency = |index: &str| MetadataDependency {
            name: "anyhow".to_owned(),
            source: Some(index.to_owned()),
            req: "^1.0".to_owned(),
            kind: None,
            rename: None,
            optional: false,
            uses_default_features: true,
            features: Vec::new(),
            target: None,
            registry: Some(index.to_owned()),
            path: None,
        };
        let package = |dependency| MetadataPackage {
            name: "pkgre-indexer".to_owned(),
            version: version.clone(),
            manifest_path: PathBuf::from("Cargo.toml"),
            dependencies: vec![dependency],
            features: BTreeMap::new(),
            links: None,
            rust_version: None,
            publish: Some(vec![CARGO_REGISTRY.to_owned()]),
        };
        let siblings = BTreeMap::new();
        for (name, index) in retired_registries() {
            validate_dependencies(
                &package(dependency(index)),
                &[],
                &siblings,
                &version,
                REGISTRY_INDEX,
                true,
            )
            .unwrap();
            let error = validate_dependencies(
                &package(dependency(index)),
                &[],
                &siblings,
                &version,
                REGISTRY_INDEX,
                false,
            )
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("names the retired registry {name:?}"))
                    && message.contains("must name registry = \"pkgre\""),
                "an admission says which name it refuses and what to name instead: {message}"
            );
        }
        let error = validate_dependencies(
            &package(dependency("sparse+https://example.test/other/")),
            &[],
            &siblings,
            &version,
            REGISTRY_INDEX,
            true,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("uses unsupported source"),
            "{error:#}"
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
        create_test_release_with_lock(temporary, true)
    }

    /// Creates the same tagged release, either committing its lock file or
    /// leaving the tag without one.
    fn create_test_release_with_lock(temporary: &TemporaryDirectory, commit_lock: bool) -> PathBuf {
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
        if commit_lock {
            run_test_command(
                Command::new("cargo")
                    .current_dir(&source)
                    .env("CARGO_HOME", temporary.path().join("lock-cargo-home"))
                    .arg("generate-lockfile"),
            );
            test_git(&source, &["add", "Cargo.lock"]);
            test_git(&source, &["commit", "--quiet", "-m", "lock"]);
        }
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

    /// Adds several versions of one package to a test registry index, each with
    /// its own checksum.
    fn publish_test_index_versions(index: &str, name: &str, versions: &[&str]) {
        use std::fmt::Write as _;

        let root = Path::new(index.trim_start_matches("file://"));
        let entry = root.join(crate::index::index_path(name));
        fs::create_dir_all(entry.parent().unwrap()).unwrap();
        let mut lines = String::new();
        for (position, version) in versions.iter().enumerate() {
            let checksum = format!("{:064x}", position + 1);
            writeln!(
                lines,
                "{{\"name\":{name:?},\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}"
            )
            .unwrap();
        }
        fs::write(&entry, lines).unwrap();
        test_git(root, &["add", "."]);
        test_git(
            root,
            &["commit", "--quiet", "-m", &format!("{name} versions")],
        );
    }

    /// Points the test release's tag at its latest commit again.
    fn retag(repository: &Path) {
        test_git(repository, &["tag", "-d", TEST_TAG]);
        test_git(
            repository,
            &["tag", "-a", TEST_TAG, "-m", "pkgre-demo 1.2.3"],
        );
    }

    /// Generates the lock file of one fixture workspace through a Cargo home
    /// that declares the test index, and commits it.
    fn commit_test_lock(temporary: &TemporaryDirectory, source: &Path, configuration: &str) {
        let lock_home = temporary.path().join("lock-cargo-home");
        fs::create_dir_all(&lock_home).unwrap();
        fs::write(lock_home.join("config.toml"), configuration).unwrap();
        run_test_command(
            Command::new("cargo")
                .current_dir(source)
                .env("CARGO_HOME", &lock_home)
                .arg("generate-lockfile"),
        );
        test_git(source, &["add", "--all"]);
        test_git(source, &["commit", "--quiet", "-m", "lock"]);
    }

    /// Creates a tagged release whose root manifest joins a workspace one
    /// directory below it, and whose dependency the served index holds in two
    /// versions, and returns the repository.
    ///
    /// Cargo takes the lock of that layout from `ws`, not from the checkout
    /// root, and resolves the newest version the index serves when it finds
    /// none there.
    fn create_workspace_below_release(temporary: &TemporaryDirectory, index: &str) -> PathBuf {
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("src")).unwrap();
        fs::create_dir_all(source.join("ws")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"pkgre-demo\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\npublish = [\"pkgre\"]\nworkspace = \"ws\"\n\n[dependencies]\npkgre-dep = { version = \"1\", registry = \"pkgre\" }\n",
        )
        .unwrap();
        fs::write(source.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        fs::write(
            source.join("ws/Cargo.toml"),
            "[workspace]\nmembers = [\"..\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&source));
        test_git(&source, &["add", "."]);
        test_git(&source, &["commit", "--quiet", "-m", "release"]);
        commit_test_lock(
            temporary,
            &source,
            &format!("[registries.pkgre]\nindex = {index:?}\n"),
        );
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre-demo 1.2.3"]);
        source
    }

    /// Creates a tagged single-crate release that depends on `pkgre-dep` 1
    /// through the curated registry, with `extra_root` appended to the root
    /// manifest and `files` written beside it, and returns the repository.
    fn create_dependency_release(
        temporary: &TemporaryDirectory,
        index: &str,
        extra_root: &str,
        files: &[(&str, &str)],
    ) -> PathBuf {
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("crates/demo/src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            format!("[workspace]\nmembers = [\"crates/demo\"]\nresolver = \"3\"\n{extra_root}"),
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/Cargo.toml"),
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                "\n[dependencies]\npkgre-dep = { version = \"1\", registry = \"pkgre\" }\n",
            ),
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        for (path, contents) in files {
            let file = source.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, contents).unwrap();
        }
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&source));
        test_git(&source, &["add", "."]);
        test_git(&source, &["commit", "--quiet", "-m", "release"]);
        commit_test_lock(
            temporary,
            &source,
            &format!("[registries.pkgre]\nindex = {index:?}\n"),
        );
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre-demo 1.2.3"]);
        source
    }

    /// Creates a tagged release whose dependency names one retired registry of
    /// the curated index, and whose lock Cargo generated through the same
    /// replacement the packaging declares, and returns the repository.
    fn create_retired_registry_release(
        temporary: &TemporaryDirectory,
        index: &str,
        registry_name: &str,
    ) -> PathBuf {
        let retired = retired_registries()
            .into_iter()
            .find(|(name, _)| *name == registry_name)
            .unwrap_or_else(|| panic!("no retired registry is named {registry_name:?}"))
            .1;
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("crates/demo/src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        fs::write(
            source.join("crates/demo/Cargo.toml"),
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                &format!(
                    "\n[dependencies]\npkgre-dep = {{ version = \"1\", registry = \"{registry_name}\" }}\n"
                ),
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
        commit_test_lock(
            temporary,
            &source,
            &format!(
                "[registries.pkgre]\nindex = {index:?}\n\n[registries.{registry_name}]\nindex = {retired:?}\n\n[source.{registry_name}]\nregistry = {retired:?}\nreplace-with = \"pkgre\"\n"
            ),
        );
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre-demo 1.2.3"]);
        source
    }

    /// Creates the sibling fixture whose path dependency names one retired
    /// registry of the curated index, with the lock Cargo generated through the
    /// same replacement the packaging declares, and returns the repository.
    fn create_retired_sibling_release(
        temporary: &TemporaryDirectory,
        index: &str,
        registry_name: &str,
    ) -> PathBuf {
        let retired = retired_registries()
            .into_iter()
            .find(|(name, _)| *name == registry_name)
            .unwrap_or_else(|| panic!("no retired registry is named {registry_name:?}"))
            .1;
        let dependency = format!(
            "pkgre-base = {{ path = \"../base\", version = \"=1.2.3\", registry = \"{registry_name}\" }}"
        );
        create_sibling_release(
            temporary,
            index,
            "publish = [\"pkgre\"]",
            &dependency,
            &format!(
                "\n[registries.{registry_name}]\nindex = {retired:?}\n\n[source.{registry_name}]\nregistry = {retired:?}\nreplace-with = \"pkgre\"\n"
            ),
        )
    }

    /// Creates a tagged release whose root manifest joins a workspace one
    /// directory below it, whose workspace root is a virtual manifest, and whose
    /// workspace root manifest carries `[patch]` with a path.
    fn create_workspace_below_patch_release(
        temporary: &TemporaryDirectory,
        index: &str,
    ) -> PathBuf {
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("src")).unwrap();
        fs::create_dir_all(source.join("ws")).unwrap();
        fs::create_dir_all(source.join("vendor/dep/src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"pkgre-demo\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\npublish = [\"pkgre\"]\nworkspace = \"ws\"\n\n[dependencies]\npkgre-dep = { version = \"1\", registry = \"pkgre\" }\n",
        )
        .unwrap();
        fs::write(source.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        fs::write(
            source.join("ws/Cargo.toml"),
            "[workspace]\nmembers = [\"..\"]\nresolver = \"3\"\n\n[patch.pkgre]\npkgre-dep = { path = \"../vendor/dep\" }\n",
        )
        .unwrap();
        fs::write(
            source.join("vendor/dep/Cargo.toml"),
            "[package]\nname = \"pkgre-dep\"\nversion = \"1.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            source.join("vendor/dep/src/lib.rs"),
            "pub fn vendored() {}\n",
        )
        .unwrap();
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&source));
        test_git(&source, &["add", "."]);
        test_git(&source, &["commit", "--quiet", "-m", "release"]);
        commit_test_lock(
            temporary,
            &source,
            &format!("[registries.pkgre]\nindex = {index:?}\n"),
        );
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre-demo 1.2.3"]);
        source
    }

    /// Creates a tagged two-crate workspace where `pkgre-demo` depends on
    /// `pkgre-base` through `dependency`, and returns the repository.
    fn create_test_sibling_release(
        temporary: &TemporaryDirectory,
        index: &str,
        base_publish: &str,
        dependency: &str,
    ) -> PathBuf {
        create_sibling_release(temporary, index, base_publish, dependency, "")
    }

    /// Creates the sibling fixture with extra Cargo configuration in the home
    /// that generates its lock, such as the replacement a retired registry
    /// needs.
    fn create_sibling_release(
        temporary: &TemporaryDirectory,
        index: &str,
        base_publish: &str,
        dependency: &str,
        extra_configuration: &str,
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
            format!("[registries.pkgre]\nindex = {index:?}\n{extra_configuration}"),
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

    /// Resolves the named packages of the sibling fixture's tag, with every
    /// published package bound to the archive of this resolution.
    fn resolve_test_group(
        root: &Path,
        source: &Path,
        index: &str,
        packages: &[&str],
        published: &[&str],
    ) -> Result<Vec<GitTagMaterialization>> {
        let published = published
            .iter()
            .map(|name| PublishedPackage {
                name,
                locked_sha256: None,
            })
            .collect::<Vec<_>>();
        resolve_published_group(root, source, index, packages, &published)
    }

    /// Resolves the named packages of the sibling fixture's tag with the
    /// catalog's own published set.
    fn resolve_published_group(
        root: &Path,
        source: &Path,
        index: &str,
        packages: &[&str],
        published: &[PublishedPackage<'_>],
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
            allow_retired_registries: false,
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
        let alone = resolve_published_group(
            &root,
            &source,
            &index,
            &["pkgre-demo"],
            &[
                PublishedPackage {
                    name: "pkgre-demo",
                    locked_sha256: None,
                },
                PublishedPackage {
                    name: "pkgre-base",
                    locked_sha256: Some(&group[1].archive_sha256),
                },
            ],
        )
        .unwrap();

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
    /// The manifest of one first-party member of a test workspace.
    fn member_manifest(name: &str, publish: &str, dependencies: &str) -> String {
        format!(
            "[package]\nname = \"{name}\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\n{publish}\n{dependencies}"
        )
    }

    /// Creates a tagged workspace from `files`, with a committed lock file when
    /// `locked` is set, and returns the repository.
    ///
    /// A workspace whose members Cargo cannot hold in one lock, such as two path
    /// packages of one name and version, is tagged without a lock: the metadata
    /// run needs none, and the packaging refuses such a workspace before it
    /// would.
    fn create_test_workspace(
        temporary: &TemporaryDirectory,
        index: &str,
        files: &[(&str, String)],
        locked: bool,
    ) -> PathBuf {
        let source = temporary.path().join("source");
        for (path, contents) in files {
            let path = source.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        run_test_command(Command::new("git").arg("init").arg("--quiet").arg(&source));
        test_git(&source, &["add", "."]);
        test_git(&source, &["commit", "--quiet", "-m", "release"]);
        if locked {
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
        }
        test_git(&source, &["tag", "-a", TEST_TAG, "-m", "pkgre 1.2.3"]);
        source
    }

    /// The members of the sibling fixtures, without the dependent crate.
    fn sibling_members() -> Vec<(&'static str, String)> {
        vec![
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/demo\", \"crates/base\"]\nresolver = \"3\"\n"
                    .to_owned(),
            ),
            (
                "crates/base/Cargo.toml",
                member_manifest("pkgre-base", "publish = [\"pkgre\"]", ""),
            ),
            (
                "crates/base/src/lib.rs",
                "pub fn base() -> u32 { 1 }\n".to_owned(),
            ),
            (
                "crates/demo/src/lib.rs",
                "pub fn answer() -> u32 { 42 }\n".to_owned(),
            ),
        ]
    }

    #[test]
    fn a_locked_sibling_must_be_the_archive_the_catalog_locked() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-checksum").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );
        let published = ["pkgre-demo", "pkgre-base"];
        let group = resolve_test_group(&root, &source, &index, &published, &published).unwrap();

        // The registry serves another archive for the sibling than the one the
        // catalog locked, so the dependent's packaged lock would name it.
        let served = "cd".repeat(32);
        publish_test_index_entry(&index, "pkgre-base", &group[1].version, &served);
        let error = resolve_published_group(
            &root,
            &source,
            &index,
            &["pkgre-demo"],
            &[
                PublishedPackage {
                    name: "pkgre-demo",
                    locked_sha256: None,
                },
                PublishedPackage {
                    name: "pkgre-base",
                    locked_sha256: Some(&group[1].archive_sha256),
                },
            ],
        )
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains(&served),
            "the error names the served archive: {message}"
        );
        assert!(
            message.contains(&group[1].archive_sha256),
            "the error names the locked archive: {message}"
        );
    }

    #[test]
    fn a_dependent_may_depend_on_another_version_of_its_sibling_name() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-versions").unwrap();
        let index = create_test_index(&temporary);
        // An older, semver-incompatible version of the sibling's name, which the
        // dependent also depends on through a renamed registry dependency.
        let older = Version::parse("0.9.0").unwrap();
        let older_archive = "ab".repeat(32);
        publish_test_index_entry(&index, "pkgre-base", &older, &older_archive);
        let mut files = sibling_members();
        files.push((
            "crates/demo/Cargo.toml",
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                "\n[dependencies]\npkgre-base = { path = \"../base\", version = \"=1.2.3\", registry = \"pkgre\" }\nold-base = { package = \"pkgre-base\", version = \"=0.9.0\", registry = \"pkgre\" }\n",
            ),
        ));
        let source = create_test_workspace(&temporary, &index, &files, true);
        let published = ["pkgre-demo", "pkgre-base"];

        let materializations =
            resolve_test_group(&root, &source, &index, &published, &published).unwrap();

        let demo = &materializations[0];
        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &demo.version,
            &demo.archive_bytes,
            &["Cargo.lock"],
        )
        .unwrap();
        let lock = String::from_utf8(packaged.contents["Cargo.lock"].clone()).unwrap();
        assert!(
            lock.contains(&format!(
                "version = \"{older}\"\nsource = \"registry+{index}\"\nchecksum = \"{older_archive}\""
            )),
            "the lock keeps the other version of the name: {lock}"
        );
        assert!(
            lock.contains(&format!(
                "version = \"1.2.3\"\nsource = \"registry+{index}\"\nchecksum = \"{}\"",
                materializations[1].archive_sha256
            )),
            "the lock keeps the sibling's own archive: {lock}"
        );
    }

    #[test]
    fn a_renamed_path_dependency_is_judged_by_the_package_it_points_at() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-renamed").unwrap();
        let index = create_test_index(&temporary);
        let mut files = sibling_members();
        files.push((
            "crates/demo/Cargo.toml",
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                "\n[dependencies]\nalias = { package = \"pkgre-base\", path = \"../base\", version = \"=1.2.3\", registry = \"pkgre\" }\n",
            ),
        ));
        let source = create_test_workspace(&temporary, &index, &files, true);
        let published = ["pkgre-demo", "pkgre-base"];

        let materializations =
            resolve_test_group(&root, &source, &index, &published, &published).unwrap();

        let demo = &materializations[0];
        let row: Value = serde_json::from_slice(&demo.source_row_bytes).unwrap();
        assert_eq!(row["deps"][0]["name"], "alias");
        assert_eq!(row["deps"][0]["package"], "pkgre-base");
        assert_eq!(row["deps"][0]["req"], "=1.2.3");
        let packaged = crate::update::read_crate_archive(
            "pkgre-demo",
            &demo.version,
            &demo.archive_bytes,
            &["Cargo.toml"],
        )
        .unwrap();
        let manifest = String::from_utf8(packaged.contents["Cargo.toml"].clone()).unwrap();
        assert!(
            manifest.contains("package = \"pkgre-base\""),
            "the packaged manifest keeps the package the alias points at: {manifest}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_renamed_dependency_on_an_unpublished_package() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-rename-key").unwrap();
        let index = create_test_index(&temporary);
        let mut files = sibling_members();
        files.push((
            "crates/secret/Cargo.toml",
            member_manifest("pkgre-secret", "publish = false", ""),
        ));
        files.push((
            "crates/secret/src/lib.rs",
            "pub fn secret() -> u32 { 2 }\n".to_owned(),
        ));
        files.push((
            "crates/demo/Cargo.toml",
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                "\n[dependencies]\npkgre-base = { package = \"pkgre-secret\", path = \"../secret\", version = \"=1.2.3\", registry = \"pkgre\" }\n",
            ),
        ));
        let source = create_test_workspace(&temporary, &index, &files, true);

        let published = ["pkgre-demo", "pkgre-base"];
        let error = resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("pkgre-base (package pkgre-secret)"),
            "the error names the dependency key and the package: {message}"
        );
        assert!(
            message.contains("which the catalog does not publish from this tag"),
            "{message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_path_dependency_on_another_directory_of_the_same_name() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-impostor").unwrap();
        let index = create_test_index(&temporary);
        let mut files = sibling_members();
        files[0] = (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/demo\", \"crates/base\"]\nexclude = [\"crates/shadow\"]\nresolver = \"3\"\n".to_owned(),
        );
        files.push((
            "crates/shadow/Cargo.toml",
            member_manifest("pkgre-base", "publish = false", ""),
        ));
        files.push((
            "crates/shadow/src/lib.rs",
            "pub fn shadow() -> u32 { 3 }\n".to_owned(),
        ));
        files.push((
            "crates/demo/Cargo.toml",
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                "\n[dependencies]\npkgre-base = { path = \"../shadow\", version = \"=1.2.3\", registry = \"pkgre\" }\n",
            ),
        ));
        let source = create_test_workspace(&temporary, &index, &files, false);

        let published = ["pkgre-demo", "pkgre-base"];
        let error = resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("crates/shadow")
                && message
                    .contains("the package pkgre-base the catalog publishes from this tag is at")
                && message.contains("crates/base"),
            "{message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_dev_dependency_that_is_not_the_tag_version() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-dev").unwrap();
        let index = create_test_index(&temporary);
        let mut files = sibling_members();
        files.push((
            "crates/demo/Cargo.toml",
            member_manifest(
                "pkgre-demo",
                "publish = [\"pkgre\"]",
                "\n[dev-dependencies]\npkgre-base = { path = \"../base\", version = \"^1.2.3\", registry = \"pkgre\" }\n",
            ),
        ));
        let source = create_test_workspace(&temporary, &index, &files, true);

        let published = ["pkgre-demo", "pkgre-base"];
        let error = resolve_test_group(&root, &source, &index, &published, &published).unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("must require exactly \"=1.2.3\""),
            "{message}"
        );
    }

    #[test]
    fn git_tag_packaging_refuses_a_requested_package_outside_the_published_set() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-sibling-request").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_sibling_release(
            &temporary,
            &index,
            "publish = [\"pkgre\"]",
            SIBLING_DEPENDENCY,
        );

        let error = resolve_test_group(&root, &source, &index, &["pkgre-demo"], &["pkgre-base"])
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("package \"pkgre-demo\" is not published from tag"),
            "{message}"
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

        let group = resolve_test_group(&root, &source, &index, &published, &published).unwrap();
        let alone = resolve_published_group(
            &root,
            &source,
            &index,
            &["pkgre-base"],
            &[
                PublishedPackage {
                    name: "pkgre-demo",
                    locked_sha256: Some(&group[0].archive_sha256),
                },
                PublishedPackage {
                    name: "pkgre-base",
                    locked_sha256: None,
                },
            ],
        )
        .unwrap();

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

    /// Points one approval at another registry, repository, and tag.
    fn at(mut approval: Approval, registry: &str, repository: &str, tag: &str) -> Approval {
        approval.registry = registry.to_owned();
        approval.category = format!("{registry}/pkgre").parse().unwrap();
        let Source::GitTag {
            repository: current_repository,
            tag: current_tag,
            ..
        } = &mut approval.source
        else {
            panic!("the fixture approval is a Git tag");
        };
        *current_repository = repository.to_owned();
        *current_tag = tag.to_owned();
        approval
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
        // The archive and source-row SHA-256 values the production catalog locks.
        let locked = [
            (
                "pkgre",
                "a4f84f78d28fb40a02c8d0226e510ed5ecbbd5d0d070d3c53713bd71d54db377",
                "e2ab6f0ac77f99d84acc6fcd8a906435c39cb01984741f0c2dd89518b62f5d7d",
            ),
            (
                "pkgre-rust",
                "d48cf4d539bd76765021a3901fa8999ec3887e0a3df6c91f6cdc5298ff03c7cc",
                "23ab2adf90458baeddd2772da8ec58b8ab668586442296fcc594292b5af3351f",
            ),
        ];
        let published = locked
            .iter()
            .map(|(name, archive_sha256, _)| PublishedPackage {
                name,
                locked_sha256: Some(archive_sha256),
            })
            .collect::<Vec<_>>();
        let packages = published
            .iter()
            .map(|package| package.name)
            .collect::<Vec<_>>();

        let group =
            resolve_git_tag_group(repository, tag, &packages, &published, &cargo_version).unwrap();
        assert_eq!(group.len(), locked.len());
        for (materialization, (name, archive_sha256, source_row_sha256)) in group.iter().zip(locked)
        {
            println!(
                "live: group {} {} {} {}",
                materialization.name,
                materialization.version,
                materialization.archive_sha256,
                materialization.source_row_sha256
            );
            assert_eq!(materialization.name, name);
            assert_eq!(
                materialization.archive_sha256, archive_sha256,
                "{name} packages to the archive the catalog locked while it is in its group"
            );
            assert_eq!(
                materialization.source_row_sha256, source_row_sha256,
                "{name} generates the source row the catalog locked while it is in its group"
            );
        }
        for (name, archive_sha256, source_row_sha256) in locked {
            let alone = resolve_git_tag(repository, tag, name, &cargo_version).unwrap();
            println!(
                "live: alone {} {} {} {}",
                alone.name, alone.version, alone.archive_sha256, alone.source_row_sha256
            );
            assert_eq!(
                alone.archive_sha256, archive_sha256,
                "{name} packages to the archive the catalog locked on its own"
            );
            assert_eq!(
                alone.source_row_sha256, source_row_sha256,
                "{name} generates the source row the catalog locked on its own"
            );
        }
    }

    #[test]
    #[ignore = "needs the network and the released tags indexer/v0.1.1, indexer/v0.2.0 and indexer/v0.3.0"]
    fn live_retired_registry_tags_reproduce_the_locked_bytes() {
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let repository = "https://github.com/pkgre/pkgre";
        // Tag object, commit, archive, and source row the production catalog
        // locks for `pkgre-indexer`, whose tags name the retired `core`
        // (0.1.1, 0.2.0) or `universe` (0.3.0) registry.
        let locked = [
            (
                "indexer/v0.1.1",
                "0.1.1",
                "71cc5c5ad8f2b03c1b8bd984944f13593efb1ed3",
                "27d4cf7c657ef72283f9c61ec0c8ea572ed548d3",
                "3257df14bc1ae9d6f2eb99d5db90e5d2a9fbc13c870044c9db5ba89bcc0b96a2",
                "b12f0350b65d153f4073d2090dadbbfd497e5746315872d1230d530fc8e46f92",
            ),
            (
                "indexer/v0.2.0",
                "0.2.0",
                "a13d63c2ace403f8d9e079411407323522028036",
                "0c09d95f5debf9f3475c4828e5fb836f9f1cc22b",
                "9292cd7e7248ea3ee2a65184a492f107ae6af4a1186c41f57383973bc7686568",
                "22a932799227a0e62387095572fa0b3a40508b4d0f238c5d62796891bf84250f",
            ),
            (
                "indexer/v0.3.0",
                "0.3.0",
                "b47ccfda09ecf5a11d229037d58b5f320d783e58",
                "b08d2b9f7f486b0e0ec9c138730b241478f775f3",
                "467be746eb89eb14da496a5d95a2cf13d20652644cf4ef18355be0723d95a755",
                "f0a80df4bf810cb3a8f1b300e7637499f4dae72e2fb5f3bdbec636a59b30b28f",
            ),
        ];
        for (tag, version, tag_oid, commit, archive_sha256, source_row_sha256) in locked {
            let approval = Approval {
                registry: "main".to_owned(),
                category: "main/pkgre".parse().unwrap(),
                name: "pkgre-indexer".to_owned(),
                version: Version::parse(version).unwrap(),
                archive_sha256: archive_sha256.to_owned(),
                index_record_sha256: source_row_sha256.to_owned(),
                index_row_sha256: "01".repeat(32),
                admission_sha256: None,
                admitted_at: UtcTimestamp::parse("2026-08-22T17:57:02Z").unwrap(),
                state: PackageState::Active,
                source: Source::GitTag {
                    repository: repository.to_owned(),
                    tag: tag.to_owned(),
                    tag_oid: tag_oid.to_owned(),
                    commit: commit.to_owned(),
                    package: "pkgre-indexer".to_owned(),
                    subdir: PathBuf::from("indexer"),
                    cargo_version: cargo_version.clone(),
                },
                declared_in: PathBuf::from("main.lock"),
            };
            let materialization = reproduce_approved_git(&approval).unwrap();
            println!(
                "live: {} {} {} {}",
                tag,
                materialization.version,
                materialization.archive_sha256,
                materialization.source_row_sha256
            );
            assert_eq!(
                materialization.archive_sha256, archive_sha256,
                "{tag} reproduces the archive the catalog locked while its manifest names a retired registry"
            );
            assert_eq!(
                materialization.source_row_sha256, source_row_sha256,
                "{tag} reproduces the source row the catalog locked"
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

    /// The repository every test catalog publishes its Git tags from.
    const TEST_REPOSITORY: &str = "https://example.invalid/pkgre-demo";

    #[test]
    fn the_command_reproduces_the_added_identity_with_the_candidates_own_approvals() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-command-reproduce").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_release(&temporary);
        let added = tag_another_release(&temporary, &source, "1.2.4");
        let accepted_path = temporary.path().join("accepted");
        let candidate_path = temporary.path().join("candidate");
        write_test_catalog(
            &accepted_path,
            &root,
            &[TEST_TAG],
            source.to_str().unwrap(),
            &index,
        );
        copy_tree(&accepted_path, &candidate_path);
        write_test_catalog(
            &candidate_path,
            &root,
            &[TEST_TAG, added.as_str()],
            source.to_str().unwrap(),
            &index,
        );
        let mut reproduced = Vec::new();

        let summary = crate::reproduce::reproduce_added_git_tags_with(
            &accepted_path,
            &candidate_path,
            |catalog, group| {
                reproduced.push((
                    catalog
                        .iter()
                        .map(|approval| format!("{}/{}", approval.name, approval.version))
                        .collect::<Vec<_>>(),
                    group
                        .iter()
                        .map(|approval| format!("{}/{}", approval.name, approval.version))
                        .collect::<Vec<_>>(),
                ));
                reproduce_approved_git_group_from_file_in(
                    &root,
                    catalog,
                    group,
                    source.to_str().unwrap(),
                    &index,
                )
                .map(|_| ())
            },
        )
        .unwrap();

        assert_eq!(
            summary.reproduced, 1,
            "the one identity the candidate adds is packaged and matched against its lock"
        );
        assert_eq!(
            reproduced,
            [(
                vec!["pkgre-demo/1.2.3".to_owned(), "pkgre-demo/1.2.4".to_owned()],
                vec!["pkgre-demo/1.2.4".to_owned()],
            )],
            "one group of the added identity is reproduced against the candidate's own approvals"
        );
    }

    #[test]
    fn the_command_refuses_a_tampered_added_identity_and_names_it() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-command-tamper").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_release(&temporary);
        let added = tag_another_release(&temporary, &source, "1.2.4");
        let accepted_path = temporary.path().join("accepted");
        let candidate_path = temporary.path().join("candidate");
        write_test_catalog(
            &accepted_path,
            &root,
            &[TEST_TAG],
            source.to_str().unwrap(),
            &index,
        );
        copy_tree(&accepted_path, &candidate_path);
        write_test_catalog(
            &candidate_path,
            &root,
            &[TEST_TAG, added.as_str()],
            source.to_str().unwrap(),
            &index,
        );
        let (archive_sha256, source_row_sha256) = locked_hashes(&candidate_path, "1.2.4");
        let other = "00".repeat(32);
        let reproduce = |accepted: &Path, candidate: &Path| {
            crate::reproduce::reproduce_added_git_tags_with(
                accepted,
                candidate,
                |catalog, group| {
                    reproduce_approved_git_group_from_file_in(
                        &root,
                        catalog,
                        group,
                        source.to_str().unwrap(),
                        &index,
                    )
                    .map(|_| ())
                },
            )
        };

        let tampered_archive = temporary.path().join("tampered-archive");
        copy_tree(&candidate_path, &tampered_archive);
        replace_in_file(&tampered_archive.join("main.lock"), &archive_sha256, &other);
        replace_in_file(
            &tampered_archive.join(crate::download::DOWNLOAD_CATALOG_FILE),
            &archive_sha256,
            &other,
        );
        let error = reproduce(&accepted_path, &tampered_archive).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("reproduce added main/pkgre-demo/1.2.4")
                && message.contains("Git archive hash changed"),
            "a tampered archive hash is reported with its identity and its cause: {message}"
        );

        let tampered_row = temporary.path().join("tampered-row");
        copy_tree(&candidate_path, &tampered_row);
        replace_in_file(&tampered_row.join("main.lock"), &source_row_sha256, &other);
        let error = reproduce(&accepted_path, &tampered_row).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("reproduce added main/pkgre-demo/1.2.4")
                && message.contains("Git source-row hash changed"),
            "a tampered source-row hash is reported with its identity and its cause: {message}"
        );
    }

    #[test]
    fn the_command_refuses_a_catalog_that_fails_policy_before_reproducing() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-command-policy").unwrap();
        let index = create_test_index(&temporary);
        let source = create_test_release(&temporary);
        let accepted_path = temporary.path().join("accepted");
        let candidate_path = temporary.path().join("candidate");
        write_test_catalog(
            &accepted_path,
            &root,
            &[TEST_TAG],
            source.to_str().unwrap(),
            &index,
        );
        copy_tree(&accepted_path, &candidate_path);
        let unsupported = "cargo-version = \"1.94.0\"";
        let supported = format!("cargo-version = {:?}", crate::policy::CARGO_VERSION);
        let failing_accepted = temporary.path().join("accepted-policy");
        copy_tree(&accepted_path, &failing_accepted);
        replace_in_file(&failing_accepted.join("main.lock"), &supported, unsupported);
        let failing_candidate = temporary.path().join("candidate-policy");
        copy_tree(&candidate_path, &failing_candidate);
        replace_in_file(
            &failing_candidate.join("main.lock"),
            &supported,
            unsupported,
        );
        for (role, accepted, candidate) in [
            ("accepted", &failing_accepted, &candidate_path),
            ("candidate", &accepted_path, &failing_candidate),
        ] {
            let mut reproduced = false;

            let error =
                crate::reproduce::reproduce_added_git_tags_with(accepted, candidate, |_, _| {
                    reproduced = true;
                    Ok(())
                })
                .unwrap_err();
            let message = format!("{error:#}");

            assert!(
                message.contains(&format!("validate {role} catalog"))
                    && message.contains("used unsupported Cargo 1.94.0"),
                "the {role} catalog is refused by policy and named: {message}"
            );
            assert!(
                !reproduced,
                "a catalog that fails policy is refused before any reproduction"
            );
        }
    }

    #[test]
    fn a_materialization_verification_names_each_field_it_compares() {
        let root = uncovered_temporary_root();
        let temporary = TemporaryDirectory::new_in(&root, "pkgre-git-verify").unwrap();
        let source = create_test_release(&temporary);
        let cargo_version = Version::parse(crate::policy::CARGO_VERSION).unwrap();
        let materialization = resolve_git_tag_from_file_in(
            &root,
            TEST_REPOSITORY,
            TEST_TAG,
            "pkgre-demo",
            &cargo_version,
            source.to_str().unwrap(),
        )
        .unwrap();
        let approval = test_approval(&materialization, &cargo_version);
        let Source::GitTag {
            tag_oid,
            commit,
            subdir,
            ..
        } = &approval.source
        else {
            panic!("the fixture approval is a Git tag");
        };
        let verify = |materialization: &GitTagMaterialization| {
            verify_approved_materialization(&approval, tag_oid, commit, subdir, materialization)
        };
        verify(&materialization).expect("the materialization that matches its approval passes");

        let mut renamed = copy_of(&materialization);
        renamed.name = "pkgre-other".to_owned();
        let error = verify(&renamed).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git publication identity changed"),
            "{error:#}"
        );

        let mut reversioned = copy_of(&materialization);
        reversioned.version = Version::parse("9.9.9").unwrap();
        let error = verify(&reversioned).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git publication identity changed"),
            "{error:#}"
        );

        let mut other_tag = copy_of(&materialization);
        other_tag.tag_oid = "00".repeat(20);
        let error = verify(&other_tag).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git tag object changed"),
            "{error:#}"
        );

        let mut other_commit = copy_of(&materialization);
        other_commit.commit = "00".repeat(20);
        let error = verify(&other_commit).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git tag commit changed"),
            "{error:#}"
        );

        let mut other_path = copy_of(&materialization);
        other_path.path = PathBuf::from("crates/other");
        let error = verify(&other_path).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git package path changed"),
            "{error:#}"
        );

        let mut other_archive = copy_of(&materialization);
        other_archive.archive_sha256 = "00".repeat(32);
        let error = verify(&other_archive).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git archive hash changed"),
            "{error:#}"
        );

        let mut other_source_row = copy_of(&materialization);
        other_source_row.source_row_sha256 = "00".repeat(32);
        let error = verify(&other_source_row).unwrap_err();
        assert!(
            format!("{error:#}").contains("Git source-row hash changed"),
            "{error:#}"
        );
    }

    #[test]
    fn a_group_reproduction_refuses_a_member_of_another_registry() {
        let catalog = [
            test_group_approval("main", TEST_REPOSITORY, "rust/v0.5.0", "pkgre"),
            test_group_approval("staging", TEST_REPOSITORY, "rust/v0.5.0", "pkgre-indexer"),
        ];
        let group = catalog.iter().collect::<Vec<_>>();

        let error = reproduce_approved_git_group_in(
            &uncovered_temporary_root(),
            &catalog,
            &group,
            refuser_before_packaging,
        )
        .unwrap_err();
        let message = format!("{error:#}");

        assert!(
            message.contains(
                "pkgre-indexer 0.5.0 is not a Git-tag publication of tag \"rust/v0.5.0\" in main"
            ),
            "a group holds the identities of one registry: {message}"
        );
    }

    #[test]
    fn a_group_reproduction_refuses_a_member_of_another_repository() {
        let catalog = [
            test_group_approval("main", TEST_REPOSITORY, "rust/v0.5.0", "pkgre"),
            test_group_approval(
                "main",
                "https://example.invalid/other",
                "rust/v0.5.0",
                "pkgre-indexer",
            ),
        ];
        let group = catalog.iter().collect::<Vec<_>>();

        let error = reproduce_approved_git_group_in(
            &uncovered_temporary_root(),
            &catalog,
            &group,
            refuser_before_packaging,
        )
        .unwrap_err();
        let message = format!("{error:#}");

        assert!(
            message.contains(
                "pkgre-indexer 0.5.0 is not a Git-tag publication of tag \"rust/v0.5.0\" in main"
            ),
            "a group holds the identities of one repository: {message}"
        );
    }

    #[test]
    fn a_group_reproduction_refuses_a_member_of_another_tag() {
        let catalog = [
            test_group_approval("main", TEST_REPOSITORY, "rust/v0.5.0", "pkgre"),
            test_group_approval("main", TEST_REPOSITORY, "indexer/v0.5.0", "pkgre-indexer"),
        ];
        let group = catalog.iter().collect::<Vec<_>>();

        let error = reproduce_approved_git_group_in(
            &uncovered_temporary_root(),
            &catalog,
            &group,
            refuser_before_packaging,
        )
        .unwrap_err();
        let message = format!("{error:#}");

        assert!(
            message.contains(
                "pkgre-indexer 0.5.0 is not a Git-tag publication of tag \"rust/v0.5.0\" in main"
            ),
            "a group holds the identities of one tag: {message}"
        );
    }

    /// Builds one approval of a Git tag, for a group a test refuses before
    /// packaging.
    fn test_group_approval(registry: &str, repository: &str, tag: &str, name: &str) -> Approval {
        Approval {
            registry: registry.to_owned(),
            category: format!("{registry}/pkgre").parse().unwrap(),
            name: name.to_owned(),
            version: Version::parse("0.5.0").unwrap(),
            archive_sha256: "01".repeat(32),
            index_record_sha256: "02".repeat(32),
            index_row_sha256: "03".repeat(32),
            admission_sha256: None,
            admitted_at: crate::update::time::UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            state: PackageState::Active,
            source: Source::GitTag {
                repository: repository.to_owned(),
                tag: tag.to_owned(),
                tag_oid: "11".repeat(20),
                commit: "22".repeat(20),
                package: name.to_owned(),
                subdir: PathBuf::from("."),
                cargo_version: Version::parse(crate::policy::CARGO_VERSION).unwrap(),
            },
            declared_in: PathBuf::from("main.lock"),
        }
    }

    /// Refuses to name a packaging source: a group that is not one tag is
    /// refused before anything is packaged.
    fn refuser_before_packaging(_: &str) -> PackagingSource<'_> {
        panic!("a group that is not one tag must be refused before packaging")
    }

    /// Copies one materialization, so that a test changes one field of it.
    fn copy_of(materialization: &GitTagMaterialization) -> GitTagMaterialization {
        GitTagMaterialization {
            name: materialization.name.clone(),
            version: materialization.version.clone(),
            tag_oid: materialization.tag_oid.clone(),
            commit: materialization.commit.clone(),
            commit_time: materialization.commit_time.clone(),
            path: materialization.path.clone(),
            archive_bytes: materialization.archive_bytes.clone(),
            source_row_bytes: materialization.source_row_bytes.clone(),
            archive_sha256: materialization.archive_sha256.clone(),
            source_row_sha256: materialization.source_row_sha256.clone(),
        }
    }

    /// Commits another version of the test release's crate and tags it, and
    /// returns the tag.
    fn tag_another_release(temporary: &TemporaryDirectory, source: &Path, version: &str) -> String {
        let manifest = source.join("crates/demo/Cargo.toml");
        let current = fs::read_to_string(&manifest).unwrap();
        let next = current.replace("version = \"1.2.3\"", &format!("version = {version:?}"));
        assert_ne!(next, current, "the fixture crate starts at version 1.2.3");
        fs::write(&manifest, next).unwrap();
        run_test_command(
            Command::new("cargo")
                .current_dir(source)
                .env("CARGO_HOME", temporary.path().join("lock-cargo-home"))
                .arg("generate-lockfile"),
        );
        test_git(source, &["add", "--all"]);
        test_git(source, &["commit", "--quiet", "-m", "release"]);
        let tag = format!("release/pkgre-demo/v{version}");
        test_git(
            source,
            &["tag", "-a", &tag, "-m", &format!("pkgre-demo {version}")],
        );
        tag
    }

    /// Writes a catalog that publishes the given tags of the test repository,
    /// and reconciles its generated lock and objects from a local repository and
    /// registry index.
    fn write_test_catalog(
        catalog: &Path,
        root: &Path,
        tags: &[&str],
        fetch_repository: &str,
        index: &str,
    ) {
        fs::create_dir_all(catalog).unwrap();
        let index_url = crate::policy::canonical_registry_index("main");
        let download = crate::download::router_download_template("main");
        let tags = tags
            .iter()
            .map(|tag| format!("{tag:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            catalog.join("main.toml"),
            format!(
                "schema = 5\n\n[registry]\nname = \"main\"\nindex = {index_url:?}\n\
                 download = {download:?}\naudience = \"public\"\ncargo-version = {cargo_version:?}\n\n\
                 [categories.pkgre]\nmay-depend-on = [\"main/pkgre\"]\n\n\
                 [categories.pkgre.publish.pkgre-demo]\ngit = {repository:?}\ntags = [{tags}]\n",
                cargo_version = crate::policy::CARGO_VERSION,
                repository = TEST_REPOSITORY,
            ),
        )
        .unwrap();
        crate::lock::reconcile_admitted_with(
            catalog,
            &[],
            &TestCatalogResolver {
                root,
                fetch_repository,
                index,
            },
        )
        .unwrap();
    }

    /// Resolves the declarations of a test catalog from a local repository and
    /// registry index.
    struct TestCatalogResolver<'a> {
        root: &'a Path,
        fetch_repository: &'a str,
        index: &'a str,
    }

    impl Resolver for TestCatalogResolver<'_> {
        fn resolve_mirror(&self, name: &str, version: &Version) -> Result<ResolvedPackage> {
            bail!("a test catalog resolves no crates.io identity, not {name} {version}")
        }

        fn resolve_git_tag_group(
            &self,
            repository: &str,
            tag: &str,
            packages: &[&str],
            published: &[PublishedPackage<'_>],
            cargo_version: &Version,
        ) -> Result<Vec<ResolvedPackage>> {
            let materializations = resolve_git_tag_group_from_file(&FileTagRequest {
                root: self.root,
                repository,
                tag,
                packages,
                published: Some(published),
                cargo_version,
                fetch_repository: self.fetch_repository,
                registry_index: self.index,
                allow_retired_registries: false,
            })?;
            materializations
                .into_iter()
                .map(|materialization| {
                    Ok(ResolvedPackage {
                        name: materialization.name.clone(),
                        version: materialization.version.clone(),
                        archive_bytes: materialization.archive_bytes.clone(),
                        source_row_bytes: materialization.source_row_bytes.clone(),
                        published_at: Some(materialization.commit_time.clone()),
                        source: LockedSource::GitTag {
                            git: repository.to_owned(),
                            tag: tag.to_owned(),
                            tag_oid: materialization.tag_oid.clone(),
                            commit: materialization.commit.clone(),
                            package: materialization.name,
                            path: materialization.path,
                            cargo_version: cargo_version.clone(),
                        },
                    })
                })
                .collect()
        }
    }

    /// Returns the locked archive and source-row hashes of one version.
    fn locked_hashes(catalog: &Path, version: &str) -> (String, String) {
        let lock = crate::schema::load_lock(&catalog.join("main.lock")).unwrap();
        let version = Version::parse(version).unwrap();
        let package = lock
            .packages
            .iter()
            .find(|package| package.version == version)
            .unwrap_or_else(|| panic!("the catalog locks no identity at version {version}"));
        (
            package.crate_sha256.clone(),
            package.source_row_sha256.clone(),
        )
    }

    /// Copies every file of a directory tree into another directory.
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// Replaces every occurrence of `from` in one regular file.
    fn replace_in_file(path: &Path, from: &str, to: &str) {
        let contents = fs::read_to_string(path).unwrap();
        let replaced = contents.replace(from, to);
        assert_ne!(
            replaced,
            contents,
            "{} names no {from} to replace",
            path.display()
        );
        fs::write(path, replaced).unwrap();
    }
}
