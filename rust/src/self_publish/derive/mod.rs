//! Deriving the crates.io packages of one release tag.
//!
//! The derivation fetches the tag into a fresh checkout, resolves every package
//! of the workspace through its own `Cargo.lock`, rewrites the manifests for
//! crates.io, translates the lock file, packages every released crate with the
//! pinned Cargo in an isolated environment, and proves the result against the
//! archive that the catalog retains and the entries that `crates-io.lock`
//! records.

mod cargo;
mod cargo_lock;
mod compare;
mod expectations;
mod git;
mod native;
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;

use super::catalog::{CatalogIdentity, CatalogSnapshot, GitRelease};
use super::config::CratesIoConfig;
use super::isolation::{ChildEnvironment, ensure_no_cargo_configuration};
use super::lock::{CratesIoLock, CratesIoPackage};
use super::name;
use super::sandbox;
use crate::artifact::sha256_bytes;
use crate::package::{TemporaryDirectory, pinned_cargo, read_bounded_archive};
use crate::policy::validate_tag_version;
pub(super) use cargo::Runner;
#[cfg(test)]
pub(crate) use cargo::{copy_workspace, read_archives};
use cargo_lock::LockIndex;
use expectations::Expectations;

/// Where a derivation reads the release tag and its Cargo packages from.
///
/// A production run reads the network and crates.io; only a test can point it at
/// a local repository, a local directory source, and a working directory, which
/// the compiler drops from every other build.
#[derive(Clone, Copy)]
pub(super) struct Sources<'a> {
    /// A local repository to fetch the release tag from, instead of the
    /// repository URL of the catalog.
    #[cfg(test)]
    fetch_repository: Option<&'a Path>,
    /// A local directory source that replaces crates.io.
    #[cfg(test)]
    directory: Option<&'a Path>,
    /// The directory to work in, instead of the temporary directory of the
    /// caller's environment.
    #[cfg(test)]
    root: Option<&'a Path>,
    /// The lifetime of a local source, which only a test names.
    #[cfg_attr(not(test), allow(dead_code))]
    marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> Sources<'a> {
    /// The sources of a production run: the network and crates.io.
    pub(super) const fn network() -> Self {
        Self {
            #[cfg(test)]
            fetch_repository: None,
            #[cfg(test)]
            directory: None,
            #[cfg(test)]
            root: None,
            marker: std::marker::PhantomData,
        }
    }

    /// The sources of a test run.
    #[cfg(test)]
    pub(super) const fn local(
        fetch_repository: &'a Path,
        directory: Option<&'a Path>,
        root: &'a Path,
    ) -> Self {
        Self {
            fetch_repository: Some(fetch_repository),
            directory,
            root: Some(root),
            marker: std::marker::PhantomData,
        }
    }

    /// Returns the local repository to fetch the release tag from, if any.
    #[cfg(test)]
    fn fetch_repository(&self) -> Option<&'a Path> {
        self.fetch_repository
    }

    /// Returns the local repository to fetch the release tag from, if any.
    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::trivially_copy_pass_by_ref)]
    fn fetch_repository(&self) -> Option<&'a Path> {
        None
    }

    #[allow(clippy::unused_self)]
    /// Returns the local directory source that replaces crates.io, if any.
    #[cfg(test)]
    fn directory(&self) -> Option<&'a Path> {
        self.directory
    }

    #[allow(clippy::unused_self)]
    /// Returns the directory to work in, if the caller named one.
    #[cfg(test)]
    fn root(&self) -> Option<&'a Path> {
        self.root
    }

    /// Returns the directory to work in, if the caller named one.
    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::trivially_copy_pass_by_ref)]
    fn root(&self) -> Option<&'a Path> {
        None
    }
}

/// One crate of one release, as the catalog records it.
pub(super) struct ReleasedCrate {
    /// Cargo package name in the curated registry.
    pub(super) name: String,
    /// Exact version.
    pub(super) version: Version,
    /// SHA-256 of the curated archive, as `registry/main.lock` records it.
    pub(super) crate_sha256: String,
    /// The curated archive's exact bytes.
    pub(super) archive: Vec<u8>,
}

/// The manifest fields that crates.io's own rules read.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct MemberFacts {
    /// The `description` field.
    pub(super) description: Option<String>,
    /// The `license` field.
    pub(super) license: Option<String>,
    /// The `license-file` field.
    pub(super) license_file: Option<PathBuf>,
    /// The `homepage` field.
    pub(super) homepage: Option<String>,
    /// The `documentation` field.
    pub(super) documentation: Option<String>,
    /// The `repository` field.
    pub(super) repository: Option<String>,
    /// The `keywords` field.
    pub(super) keywords: Vec<String>,
    /// The `categories` field.
    pub(super) categories: Vec<String>,
    /// The dependencies whose requirement is the wildcard `*`, by the crate
    /// name crates.io records, sorted; the derivation reads them from the
    /// packaged manifest, which is the one crates.io reads.
    pub(super) wildcard_dependencies: Vec<String>,
}

/// What the derivation writes for one crate.
#[derive(Debug)]
pub(super) struct DerivedPackage {
    /// The `crates-io.lock` entry of the crate version.
    pub(super) entry: CratesIoPackage,
    /// The derived crates.io archive's exact bytes.
    pub(super) archive: Vec<u8>,
    /// The manifest fields of the crate, which crates.io's own rules read.
    pub(super) facts: MemberFacts,
}

/// One package outside the release's workspace that the release depends on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DerivedDependency {
    /// crates.io name.
    pub(super) crates_io_name: String,
    /// Exact version.
    pub(super) version: Version,
    /// SHA-256 that crates.io must serve for the package.
    pub(super) crate_sha256: String,
}

/// What one verified packaging of step 5 builds.
///
/// The crates of the release that crates.io lacks are packaged together, so that
/// Cargo serves each of them to the crates of the same run that depend on it; a
/// crate that depends on a sibling that an earlier run uploaded needs that
/// sibling fetched from crates.io first, since the workspace's lock names it as a
/// path package.
pub(super) struct VerifiedPackages {
    /// The crate versions that crates.io lacks, by crates.io name.
    pub(super) missing: Vec<(String, Version)>,
    /// The crate versions of the release that crates.io already has and that a
    /// missing crate depends on, by crates.io name.
    pub(super) published: Vec<(String, Version)>,
}

/// The derived crates.io packages of one release, with the workspace that
/// packaged them.
pub(super) struct Derivation {
    /// One package per released crate, in name order.
    pub(super) packages: Vec<DerivedPackage>,
    /// Every package outside the release's workspace that crates.io must serve
    /// for the release, in name and version order.
    pub(super) dependencies: Vec<DerivedDependency>,
    /// The crates of the release that each crate of the release depends on, by
    /// Cargo package name.
    pub(super) siblings: BTreeMap<String, BTreeSet<String>>,
    /// The rewritten workspace, which the verified packaging and the upload
    /// keep using.
    pub(super) workspace: DerivedWorkspace,
}

/// The rewritten workspace of one derivation, kept while it is used.
///
/// It holds the derivation's temporary directory, so the checkout, the isolated
/// Cargo home and the working directory stay on disk until it is dropped.
pub(super) struct DerivedWorkspace {
    /// The derivation's temporary root.
    temporary: TemporaryDirectory,
    /// The pinned Cargo that packaged the release.
    cargo: PathBuf,
    /// The environment that every child process inherits.
    environment: ChildEnvironment,
    /// The working directory outside the checkout.
    work: PathBuf,
    /// The rewritten checkout.
    workspace: PathBuf,
    /// The registries that the checkout resolves from, which the upload's Cargo
    /// home mirrors.
    sources: cargo::RegistrySources,
    /// Native tags stay clean; rewritten manifests need Cargo's dirty allowance.
    native: bool,
}

impl DerivedWorkspace {
    /// Returns the derivation's temporary root.
    pub(super) fn root(&self) -> &Path {
        self.temporary.path()
    }

    /// Returns the pinned Cargo.
    pub(super) fn cargo(&self) -> &Path {
        &self.cargo
    }

    /// Returns the working directory outside the checkout.
    pub(super) fn work(&self) -> &Path {
        &self.work
    }

    /// Returns the workspace manifest of the rewritten checkout.
    pub(super) fn manifest(&self) -> PathBuf {
        self.workspace.join("Cargo.toml")
    }

    /// Prepares the isolated Cargo home of an upload, and returns it with the
    /// environment of its child processes.
    ///
    /// The home configures plain crates.io and the `cargo:token` credential
    /// provider, and no other registry, so that `cargo publish` reaches
    /// crates.io with the token of its own environment alone. The derivation's
    /// own home keeps the `pkgre` registry its `cargo metadata` needs.
    ///
    /// # Errors
    ///
    /// Returns an error when the home cannot be written, when Cargo
    /// configuration covers the working directory, or when the pinned toolchain
    /// has no `rustc`.
    pub(super) fn upload_environment(&self) -> Result<ChildEnvironment> {
        ensure_no_cargo_configuration(&self.work)?;
        let cargo_home = self.root().join(cargo::UPLOAD_CARGO_HOME_DIRECTORY);
        cargo::prepare_upload_cargo_home(&cargo_home, &self.sources)?;
        let environment = ChildEnvironment::capture(&cargo_home, &self.cargo)?;
        #[cfg(test)]
        let environment = cargo::with_test_crates_io(environment, &self.sources)?;
        Ok(environment)
    }

    /// Whether the checkout is the unchanged native tag.
    pub(super) fn is_native(&self) -> bool {
        self.native
    }

    /// Returns the target directory of an upload.
    pub(super) fn upload_target(&self) -> PathBuf {
        self.root().join("upload-targets")
    }

    /// Packages the named crates the way `cargo publish` packages them, in the
    /// upload's own Cargo home and environment, and returns their archives by
    /// crates.io name.
    ///
    /// The crates are packaged together, so that a crate of the release whose
    /// sibling crates.io does not have yet is packaged against that sibling of
    /// the same run. The command packages without verifying, so it runs no
    /// package code: the upload routine calls it after the verified packaging
    /// and before it reads the token, so that the bytes it uploads are the bytes
    /// it compared with `crates-io.lock`.
    ///
    /// # Errors
    ///
    /// Returns an error when Cargo configuration covers the working directory,
    /// when Cargo fails, or when an archive is missing or too large.
    pub(super) fn publish_archives(
        &self,
        environment: &ChildEnvironment,
        packages: &[(String, Version)],
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        ensure_no_cargo_configuration(&self.work)?;
        let manifest = self.manifest();
        let target = self.upload_target();
        cargo::package_group(
            &self.cargo,
            environment,
            &self.work,
            &target,
            &manifest,
            packages,
            !self.native,
        )
        .context("package the crates of the release as cargo publish would")
    }

    /// Packages one crate alone in the upload's Cargo home and requires the
    /// archive that `crates-io.lock` records for it.
    ///
    /// The routine runs this just before `cargo publish`, once crates.io serves
    /// the crates the package depends on, so the bytes that reach crates.io are
    /// the bytes it compared. The command runs no package code, and the child
    /// process holds no token.
    ///
    /// # Errors
    ///
    /// Returns an error when Cargo fails, or when the archive differs from the
    /// recorded one.
    pub(super) fn verify_publish_archive(
        &self,
        environment: &ChildEnvironment,
        name: &str,
        version: &Version,
        recorded: &str,
    ) -> Result<()> {
        let archives = self.publish_archives(environment, &[(name.to_owned(), version.clone())])?;
        let archive = archives.get(name).with_context(|| {
            format!("the packaging produced no archive for crate {name} {version}")
        })?;
        let sha256 = sha256_bytes(archive);
        ensure!(
            sha256 == recorded,
            "the package that cargo publish would upload for crate {name} {version} has SHA-256 {sha256}, but crates-io.lock records {recorded}; the routine uploads nothing"
        );
        Ok(())
    }

    /// Packages the named crates with Cargo's verification, offline, in a build
    /// root of its own, and returns their archives by crates.io name.
    ///
    /// Step 5 runs package code, so it runs in a build sandbox nested in the run
    /// sandbox: the workspace goes into a fresh copy below the build root, a
    /// Cargo home is written there and holds what the two fetches bring in, and
    /// the verified build itself runs offline, with its target directory outside
    /// the copy. The build root goes once the archives are read, since nothing of
    /// the build can change it any more: `bwrap` returns only after the kernel
    /// has ended every process of the build's namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when Cargo configuration covers the working directory,
    /// when the copy, the fetches or the build fail, or when an archive is
    /// missing or too large.
    pub(super) fn verified_archives(
        &self,
        packages: &VerifiedPackages,
        runner: Runner,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let build = sandbox::BuildRoot::make_in(self.root(), "build")?;
        let result = self.build_in(&build, packages, runner);
        build.remove();
        result
    }

    /// Runs one verified packaging in a fresh build root.
    ///
    /// # Errors
    ///
    /// Returns an error when the copy, the fetches or the build fail, or when an
    /// archive is missing or too large.
    fn build_in(
        &self,
        build: &sandbox::BuildRoot,
        packages: &VerifiedPackages,
        runner: Runner,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        ensure_no_cargo_configuration(&build.work())?;
        let workspace = build.workspace();
        if self.native {
            #[cfg(test)]
            super::test_hooks::run(
                super::test_hooks::Point::BeforeVerifiedCopy,
                &self.workspace,
            );
            git::ensure_clean_checkout(&self.workspace, &self.environment, false)?;
            native::copy_checkout(&self.workspace, &workspace)?;
            #[cfg(test)]
            super::test_hooks::run(super::test_hooks::Point::VerifiedCopy, &workspace);
            git::ensure_clean_checkout(&workspace, &self.environment, false)?;
        } else {
            cargo::copy_workspace(&self.workspace, &workspace)?;
        }
        let manifest = workspace.join("Cargo.toml");
        cargo::prepare_fetch_cargo_home(&build.cargo_home(), &self.sources)?;
        let environment = ChildEnvironment::capture(&build.cargo_home(), &self.cargo)?;
        #[cfg(test)]
        let environment = cargo::with_test_crates_io(environment, &self.sources)?;
        // The workspace's own lock, which runs no package code, brings in every
        // package of the release that crates.io serves.
        cargo::run_cargo(
            &self.cargo,
            &environment,
            &build.work(),
            [
                std::ffi::OsString::from("fetch"),
                std::ffi::OsString::from("--locked"),
                std::ffi::OsString::from("--manifest-path"),
                manifest.as_os_str().to_owned(),
            ],
        )
        .context("fetch the packages of the release's lock")?;
        if !packages.published.is_empty() {
            cargo::fetch_published(
                &self.cargo,
                &environment,
                &build.work(),
                &build.published(),
                &workspace.join("Cargo.lock"),
                &packages.published,
            )?;
        }
        cargo::step5_package(
            &self.cargo,
            &environment,
            &build.work(),
            &build.target(),
            &manifest,
            &packages.missing,
            !self.native,
            runner,
            build.path(),
        )
        .context("verify the crates.io packages of the release")
    }
}

/// Derives every crates.io package of one release from the given sources.
///
/// `released` are the catalog's identities of the release, with the archives
/// that the catalog retains. The result holds one package per released crate,
/// in name order. The derived workspace is dropped when this returns; use
/// [`derive_release_in`] to keep it.
///
/// # Errors
///
/// Returns an error when the tag cannot be fetched or does not match the
/// catalog's commit, when the workspace and the catalog disagree, when a
/// manifest or lock file cannot be translated, when the pinned Cargo fails or
/// packages twice differently, or when a derived archive differs from the
/// curated archive beyond the fields the derivation rewrites.
pub(super) fn derive_release_with(
    release: &GitRelease,
    released: &[ReleasedCrate],
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    sources: Sources<'_>,
) -> Result<Vec<DerivedPackage>> {
    Ok(derive_release_in(release, released, catalog, config, earlier, sources)?.packages)
}

/// Derives one release and keeps the workspace that packaged it.
///
/// # Errors
///
/// Returns an error when the tag cannot be fetched or does not match the
/// catalog's commit, when the workspace and the catalog disagree, when a
/// manifest or lock file cannot be translated, when the pinned Cargo fails or
/// packages twice differently, or when a derived archive differs from the
/// curated archive beyond the fields the derivation rewrites.
#[allow(clippy::too_many_lines)]
pub(super) fn derive_release_in(
    release: &GitRelease,
    released: &[ReleasedCrate],
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    sources: Sources<'_>,
) -> Result<Derivation> {
    ensure!(
        !released.is_empty(),
        "a release holds at least one crate, but {} {} has none",
        release.git,
        release.tag
    );
    let cargo = pinned_cargo(&release.cargo_version)?;
    // Cargo reports every absolute path of its metadata as it sees it, and the
    // checkout is resolved here, so the temporary root is resolved once: Git,
    // Cargo and the path rules then see one form of every path, even below a
    // temporary directory that a symbolic link reaches.
    let temporary = match sources.root() {
        Some(root) => TemporaryDirectory::new_in(&temporary_root(root)?, "pkgre-self-publish")?,
        None => TemporaryDirectory::new_in(
            &temporary_root(&std::env::temp_dir())?,
            "pkgre-self-publish",
        )?,
    };
    let root = temporary.path();
    let cargo_home = cargo::cargo_home(root);
    let registry_sources = cargo::registry_sources(sources);
    cargo::prepare_cargo_home(&cargo_home, registry_sources.clone())?;
    let environment = ChildEnvironment::capture(&cargo_home, &cargo)?;
    #[cfg(test)]
    let environment = cargo::with_test_crates_io(environment, &registry_sources)?;
    let work = root.join("work");
    std::fs::create_dir(&work)
        .with_context(|| format!("create derivation directory {}", work.display()))?;
    ensure_no_cargo_configuration(&work)?;

    let (fetch_repository, allow_file) = match sources.fetch_repository() {
        Some(repository) => (
            repository
                .to_str()
                .with_context(|| format!("test repository {} is not UTF-8", repository.display()))?
                .to_owned(),
            true,
        ),
        None => (release.git.clone(), false),
    };
    let checkout = git::fetch_tag(
        &release.git,
        &release.tag,
        &root.join("repository"),
        &fetch_repository,
        &environment,
        allow_file,
    )?;
    ensure!(
        checkout.tag_oid == release.tag_oid,
        "release tag {:?} of {:?} is object {}, but registry/main.lock records {}",
        release.tag,
        release.git,
        checkout.tag_oid,
        release.tag_oid
    );
    ensure!(
        checkout.commit == release.commit,
        "release tag {:?} of {:?} names commit {}, but registry/main.lock records {}",
        release.tag,
        release.git,
        checkout.commit,
        release.commit
    );

    let native = config.is_native(&release.git);
    let workspace =
        workspace::Workspace::load(&cargo, &environment, &work, &checkout.root, native)?;
    crate::gitlinks::ensure_release_tag_paths(
        &checkout.root,
        &checkout.gitlinks,
        &workspace.tag_members(),
    )?;
    ensure_release_members(&workspace, released, &release.tag)?;
    let lock = LockIndex::load(&release_lock_path(native, &checkout.root, &workspace.root))?;
    let published = published_crates(&workspace, released, config, &release.tag, &release.git)?;
    let (mut expectations, native_dependencies) = if native {
        let dependencies = native::validate(
            &workspace,
            &lock,
            catalog,
            config,
            &release.git,
            &release.tag,
            &environment,
        )?;
        #[cfg(test)]
        super::test_hooks::run(
            super::test_hooks::Point::AfterNativeContract,
            &checkout.root,
        );
        git::ensure_clean_checkout(&checkout.root, &environment, allow_file)?;
        (None, dependencies)
    } else {
        let curated_index = cargo::curated_index(&registry_sources)?;
        let expectations =
            Expectations::build(&lock, catalog, config, earlier, &published, &curated_index)?;
        let plan = workspace::ReleasePlan::new(
            &workspace,
            &lock,
            &expectations,
            &published,
            &curated_index,
        )?;
        workspace::rewrite_manifests(&workspace, &plan, &expectations)?;
        cargo_lock::translate_lock(&checkout.root, &expectations)?;
        (Some(expectations), Vec::new())
    };

    let members = released
        .iter()
        .map(|package| {
            let crates_io_name = published
                .get(&package.name)
                .expect("every released crate has a crates.io name");
            (crates_io_name.clone(), package.version.clone())
        })
        .collect::<Vec<_>>();
    let archives = cargo::package_members(
        &cargo,
        &environment,
        &work,
        &root.join("targets"),
        &checkout.root,
        &members,
        !native,
    )?;
    #[cfg(test)]
    super::test_hooks::run(super::test_hooks::Point::AfterPackaging, &checkout.root);
    if native {
        git::ensure_clean_checkout(&checkout.root, &environment, allow_file)?;
    }
    // The comparison proves the packaged locks against the archives this run
    // packages, so a crate that depends on another crate of the release is
    // compared with the sibling's crates.io archive, not the curated one.
    let mut derived = BTreeMap::new();
    for package in released {
        let crates_io_name = published
            .get(&package.name)
            .expect("every released crate has a crates.io name");
        let archive = archives.get(crates_io_name).with_context(|| {
            format!(
                "pinned Cargo produced no archive for {} {}",
                crates_io_name, package.version
            )
        })?;
        derived.insert(
            (package.name.clone(), package.version.clone()),
            sha256_bytes(archive),
        );
    }
    if let Some(expectations) = &mut expectations {
        expectations.bind_release(released, &derived)?;
    }

    let mut packages = Vec::new();
    for package in released {
        let crates_io_name = published
            .get(&package.name)
            .expect("every released crate has a crates.io name")
            .clone();
        let archive = archives.get(&crates_io_name).with_context(|| {
            format!(
                "pinned Cargo produced no archive for {} {}",
                crates_io_name, package.version
            )
        })?;
        ensure!(
            sha256_bytes(&package.archive) == package.crate_sha256,
            "the curated archive of {} {} has SHA-256 {}, but registry/main.lock records {}",
            package.name,
            package.version,
            sha256_bytes(&package.archive),
            package.crate_sha256
        );
        crate::gitlinks::ensure_archive_outside_gitlinks(
            &checkout.gitlinks,
            &package_directory(&checkout.root, &workspace, &package.name)?,
            &crates_io_name,
            &package.version,
            archive,
        )?;
        if let Some(expectations) = &expectations {
            compare::compare_archives(
                &package.version,
                &compare::ArchiveToCompare {
                    name: package.name.as_str(),
                    bytes: package.archive.as_slice(),
                },
                &compare::ArchiveToCompare {
                    name: crates_io_name.as_str(),
                    bytes: archive.as_slice(),
                },
                expectations,
            )
            .with_context(|| {
                format!(
                    "the crates.io archive of {} {} differs from the curated archive",
                    package.name, package.version
                )
            })?;
        } else {
            ensure!(
                archive == &package.archive,
                "native crates.io archive of {} {} differs byte for byte from the retained archive",
                package.name,
                package.version
            );
        }
        let mut facts = workspace
            .member(&package.name)
            .expect("every released crate is a member of the tag's workspace")
            .facts
            .clone();
        facts.wildcard_dependencies =
            packaged_wildcard_dependencies(&crates_io_name, &package.version, archive)?;
        packages.push(DerivedPackage {
            entry: CratesIoPackage {
                name: package.name.clone(),
                version: package.version.clone(),
                crates_io_name,
                crate_sha256: sha256_bytes(archive),
                pkgre_crate_sha256: package.crate_sha256.clone(),
                git: release.git.clone(),
                tag: release.tag.clone(),
                commit: release.commit.clone(),
                cargo_version: release.cargo_version.clone(),
            },
            archive: archive.clone(),
            facts,
        });
    }
    packages.sort_by(|left, right| {
        (
            left.entry.name.to_ascii_lowercase(),
            left.entry.name.as_str(),
            &left.entry.version,
        )
            .cmp(&(
                right.entry.name.to_ascii_lowercase(),
                right.entry.name.as_str(),
                &right.entry.version,
            ))
    });
    let dependencies = expectations.map_or(native_dependencies, |expected| expected.dependencies());
    let siblings = sibling_dependencies(&workspace, &published);
    #[cfg(test)]
    super::test_hooks::record_checkout(&checkout.root);
    Ok(Derivation {
        packages,
        dependencies,
        siblings,
        workspace: DerivedWorkspace {
            temporary,
            cargo,
            environment,
            work,
            workspace: checkout.root,
            sources: registry_sources,
            native,
        },
    })
}

/// Returns the crates of the release that each crate of the release depends on.
///
/// The routine uploads a crate after the crates it depends on, so it needs these
/// edges, by Cargo package name.
fn sibling_dependencies(
    workspace: &workspace::Workspace,
    published: &BTreeMap<String, String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut siblings = BTreeMap::new();
    for member in &workspace.members {
        if !published.contains_key(&member.name) {
            continue;
        }
        let dependencies = member
            .dependencies
            .iter()
            .map(|dependency| dependency.package.as_str())
            .filter(|package| published.contains_key(*package) && *package != member.name)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        siblings.insert(member.name.clone(), dependencies);
    }
    siblings
}

/// Returns the canonical form of the temporary root the derivation works below.
///
/// # Errors
///
/// Returns an error for a root that cannot be resolved.
fn temporary_root(root: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(root)
        .with_context(|| format!("canonicalize the temporary root {}", root.display()))
}

/// Returns the repository-relative directory of one released crate.
///
/// # Errors
///
/// Returns an error for a crate that is not a member of the tag's workspace, for
/// a member manifest without a directory, or for a directory outside the
/// checkout.
fn package_directory(
    checkout: &Path,
    workspace: &workspace::Workspace,
    name: &str,
) -> Result<PathBuf> {
    let member = workspace.member(name).with_context(|| {
        format!("the tag's workspace does not hold {name}, which registry/main.lock publishes")
    })?;
    let directory = member
        .manifest_path
        .parent()
        .with_context(|| format!("the manifest of {name} has no directory"))?;
    let checkout = std::fs::canonicalize(checkout)
        .with_context(|| format!("canonicalize checkout {}", checkout.display()))?;
    let directory = std::fs::canonicalize(directory)
        .with_context(|| format!("canonicalize the directory of {name}"))?;
    let relative = directory.strip_prefix(&checkout).with_context(|| {
        format!(
            "the directory {} of {name} lies outside the checkout {}",
            directory.display(),
            checkout.display()
        )
    })?;
    Ok(if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative.to_path_buf()
    })
}

/// Returns the lock file of one release tag.
///
/// A crates.io-native tag commits its `Cargo.lock` at the workspace root that
/// Cargo reports, which may sit below the checkout; a `pkgre`-mode tag keeps its
/// lock at the checkout's root.
fn release_lock_path(native: bool, checkout: &Path, workspace: &Path) -> PathBuf {
    if native {
        workspace.join("Cargo.lock")
    } else {
        checkout.join("Cargo.lock")
    }
}

/// Requires the crates that the catalog publishes from the tag to be exactly
/// the tag's publishable members.
///
/// A release tag publishes the crates of its commit, no more and no fewer, so a
/// partial release cannot be repaired at the same tag.
///
/// # Errors
///
/// Returns an error naming the publishable members that the catalog does not
/// publish from the tag, and the catalog crates that the tag does not publish.
fn ensure_release_members(
    workspace: &workspace::Workspace,
    released: &[ReleasedCrate],
    tag: &str,
) -> Result<()> {
    let publishable = workspace.publishable_members();
    let published = released
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing = publishable
        .difference(&published)
        .copied()
        .collect::<Vec<_>>();
    let extra = published
        .difference(&publishable)
        .copied()
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty() && extra.is_empty(),
        "Git tag {tag:?} publishes exactly its publishable members, {publishable:?}, but registry/main.lock publishes {published:?} from it: publishable and missing from the catalog {missing:?}, in the catalog but not publishable at the tag {extra:?}"
    );
    Ok(())
}

/// Returns the crates.io name of every released crate, refusing a name that
/// crates.io would not take or that two crates share.
fn published_crates(
    workspace: &workspace::Workspace,
    released: &[ReleasedCrate],
    config: &CratesIoConfig,
    tag: &str,
    git: &str,
) -> Result<BTreeMap<String, String>> {
    let mut published = BTreeMap::new();
    let mut used: BTreeMap<String, String> = BTreeMap::new();
    for package in released {
        let member = workspace.member(&package.name).with_context(|| {
            format!(
                "the tag's workspace does not hold {}, which registry/main.lock publishes",
                package.name
            )
        })?;
        ensure!(
            member.version == package.version,
            "the tag's workspace holds {} {}, but registry/main.lock records {}",
            package.name,
            member.version,
            package.version
        );
        validate_tag_version(tag, &member.version)?;
        let crates_io_name = config.effective_name(&package.name, git);
        name::validate(&crates_io_name)
            .with_context(|| format!("validate the crates.io name of {}", package.name))?;
        let key = name::canonical(&crates_io_name);
        if let Some(other) = used.get(&key) {
            bail!(
                "crates {other} and {} both use the crates.io name {crates_io_name:?}",
                package.name
            );
        }
        used.insert(key, package.name.clone());
        published.insert(package.name.clone(), crates_io_name);
    }
    Ok(published)
}

/// Returns the dependencies whose requirement crates.io refuses as a wildcard.
///
/// The rule reads the manifest that the crates.io archive holds, which is the
/// manifest crates.io itself reads, so a dependency that Cargo left out of the
/// archive is not one of them.
///
/// # Errors
///
/// Returns an error when the archive cannot be read, holds no manifest, or
/// holds one that cannot be parsed.
fn packaged_wildcard_dependencies(
    crates_io_name: &str,
    version: &Version,
    archive: &[u8],
) -> Result<Vec<String>> {
    let context = || format!("read the packaged manifest of {crates_io_name} {version}");
    let read = crate::update::read_crate_archive(crates_io_name, version, archive, &["Cargo.toml"])
        .with_context(context)?;
    let Some(manifest) = read.contents.get("Cargo.toml") else {
        bail!("the crates.io archive of {crates_io_name} {version} holds no Cargo.toml");
    };
    let manifest = std::str::from_utf8(manifest).with_context(context)?;
    workspace::wildcard_dependencies(manifest).with_context(context)
}

/// Reads the curated archive that the catalog retains for one identity.
///
/// # Errors
///
/// Returns an error when the archive is missing or too large, or when its bytes
/// do not match the identity's recorded `crate-sha256`.
pub(super) fn retained_crate(
    catalog_root: &Path,
    identity: &CatalogIdentity,
) -> Result<ReleasedCrate> {
    let path = catalog_root
        .join("objects")
        .join("crates")
        .join(format!("{}.crate", identity.crate_sha256));
    let archive = read_bounded_archive(&path)?;
    ensure!(
        sha256_bytes(&archive) == identity.crate_sha256,
        "the retained archive {} has SHA-256 {}, but registry/main.lock records {}",
        path.display(),
        sha256_bytes(&archive),
        identity.crate_sha256
    );
    Ok(ReleasedCrate {
        name: identity.name.clone(),
        version: identity.version.clone(),
        crate_sha256: identity.crate_sha256.clone(),
        archive,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/self_publish/derive/mod.rs"]
pub(crate) mod tests;

/// Runs step 5 for a plain workspace in a build sandbox, with the fetches that
/// production runs, so that the sandbox tests can exercise the real Cargo path.
///
/// # Errors
///
/// Returns an error when the copy, the fetch, the build or the archives fail.
#[cfg(test)]
pub(crate) fn step5_in_build_sandbox(
    workspace: &Path,
    cargo: &Path,
    members: &[(String, Version)],
    allow_dirty: bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let build = sandbox::BuildRoot::make_in(&std::env::temp_dir(), "test-step5")?;
    let result = (|| {
        cargo::copy_workspace(workspace, &build.workspace())?;
        cargo::prepare_fetch_cargo_home(&build.cargo_home(), &cargo::RegistrySources::CratesIo)?;
        let environment = ChildEnvironment::capture(&build.cargo_home(), cargo)?;
        let manifest = build.workspace().join("Cargo.toml");
        cargo::run_cargo(
            cargo,
            &environment,
            &build.work(),
            [
                std::ffi::OsString::from("fetch"),
                std::ffi::OsString::from("--locked"),
                std::ffi::OsString::from("--manifest-path"),
                manifest.as_os_str().to_owned(),
            ],
        )
        .context("fetch the test workspace's lock")?;
        cargo::step5_package(
            cargo,
            &environment,
            &build.work(),
            &build.target(),
            &manifest,
            members,
            allow_dirty,
            cargo::Runner::Sandbox,
            build.path(),
        )
    })();
    build.remove();
    result
}
