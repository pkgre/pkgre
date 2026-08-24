//! Declarative generated-lock reconciliation and transactional catalog replacement.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use tracing::warn;

use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::category::CategoryId;
use crate::download::{DOWNLOAD_CATALOG_FILE, DownloadCatalog, MAX_DOWNLOAD_CATALOG_BYTES};
use crate::import;
use crate::index::IndexRecord;
use crate::package;
use crate::policy::{
    Policy, validate_catalog, validate_git_tag, validate_https_repository, validate_tag_version,
};
use crate::schema::{
    Catalog, LockedName, LockedPackage, LockedSource, NameSource, PackageState, RegistryInput,
    RegistryLock, Source, catalog_from_inputs, empty_lock, load_registry_inputs, serialize_lock,
    validate_input_for_update, version_identity,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Counts the changes made by one successful reconciliation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileSummary {
    /// Whether the catalog directory was replaced.
    pub changed: bool,
    /// Newly reserved permanent package names.
    pub names_added: usize,
    /// Newly materialized package identities.
    pub packages_added: usize,
    /// Package identities irreversibly transitioned to `removed`.
    pub packages_removed: usize,
}

/// Reconciles generated locks and the content-addressed object store with human declarations.
///
/// Every local immutable-anchor, topology, existing-object, and tombstone check completes before
/// any public artifact is fetched. A complete staged catalog is strictly reloaded and verified
/// before the existing catalog directory is replaced.
///
/// # Errors
///
/// Returns an error for invalid or stale inputs, immutable-anchor changes, tombstone reactivation,
/// resolution failures, non-reproducible artifacts, dependency-policy violations, or transactional
/// filesystem failures.
pub fn reconcile(root: &Path) -> Result<ReconcileSummary> {
    reconcile_with(root, &LiveResolver, &FilesystemRenamer)
}

/// Exact crates.io identity and upstream hashes admitted by the update workflow.
#[derive(Clone, Debug)]
pub(crate) struct MirrorAdmission {
    pub(crate) registry: String,
    pub(crate) category: CategoryId,
    pub(crate) name: String,
    pub(crate) version: Version,
    pub(crate) crate_sha256: String,
    pub(crate) source_row_sha256: String,
    pub(crate) binding_sha256: String,
}

/// Reconciles a catalog whose only new crates.io identities have exact update admission evidence.
// Kept crate-private until the update-apply entry point calls it.
#[allow(dead_code)]
pub(crate) fn reconcile_admitted(
    root: &Path,
    admissions: &[MirrorAdmission],
) -> Result<ReconcileSummary> {
    reconcile_admitted_with(root, admissions, &LiveResolver)
}

pub(crate) fn reconcile_admitted_with<R: Resolver>(
    root: &Path,
    admissions: &[MirrorAdmission],
    resolver: &R,
) -> Result<ReconcileSummary> {
    let mut indexed = BTreeMap::new();
    for admission in admissions {
        let identity = package_identity(&admission.name, &admission.version);
        ensure!(
            indexed.insert(identity, admission.clone()).is_none(),
            "update admission repeats Cargo identity {} {}",
            admission.name,
            admission.version
        );
    }
    reconcile_with_mode(
        root,
        resolver,
        &FilesystemRenamer,
        ReconciliationMode::Admitted(&indexed),
    )
}

/// Applies a complete catalog mutation to a private copy and atomically installs it.
///
/// The live catalog is guarded and must match `expected_sha256` both before copying and immediately
/// before installation. The callback may perform nested reconciliation against the private copy.
/// A strictly loaded, policy-checked, object-verified, test-rendered copy is the only tree installed.
///
/// # Errors
///
/// Returns an error for catalog drift, unsafe tree entries, callback failure, invalid staged output,
/// concurrent reconciliation, or transactional filesystem failure.
#[allow(dead_code)]
pub(crate) fn transact_catalog<T>(
    root: &Path,
    expected_sha256: &str,
    mutate: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    transact_catalog_with(root, expected_sha256, mutate, &FilesystemRenamer)
}

fn transact_catalog_with<T, N: Renamer>(
    root: &Path,
    expected_sha256: &str,
    mutate: impl FnOnce(&Path) -> Result<T>,
    renamer: &N,
) -> Result<T> {
    let root = canonical_catalog_root(root)?;
    let _guard = CatalogGuard::acquire(&root)?;
    ensure!(
        crate::update::catalog_fingerprint(&root)? == expected_sha256,
        "catalog fingerprint differs from the recomputed admission facts before transaction"
    );

    let staging = TemporaryCatalog::sibling_of(&root, "transaction")?;
    copy_optional_tree(&root, staging.path(), "catalog transaction tree")?;
    ensure!(
        crate::update::catalog_fingerprint(staging.path())? == expected_sha256,
        "private catalog copy differs from the recomputed admission facts"
    );

    let output = mutate(staging.path()).context("mutate private catalog transaction")?;
    validate_staged_catalog(staging.path()).context("validate private catalog transaction")?;
    ensure!(
        crate::update::catalog_fingerprint(&root)? == expected_sha256,
        "live catalog changed during update transaction"
    );
    install_staging(&root, staging.path(), renamer)?;
    Ok(output)
}

pub(crate) trait Resolver {
    fn resolve_mirror(&self, name: &str, version: &Version) -> Result<ResolvedPackage>;

    fn resolve_git_tag(
        &self,
        repository: &str,
        tag: &str,
        package_name: &str,
        cargo_version: &Version,
    ) -> Result<ResolvedPackage>;
}

pub(crate) struct LiveResolver;

impl Resolver for LiveResolver {
    fn resolve_mirror(&self, name: &str, version: &Version) -> Result<ResolvedPackage> {
        let materialization = import::resolve_crates_io(name, version)?;
        ensure!(
            sha256_bytes(&materialization.archive_bytes) == materialization.archive_sha256,
            "crates.io resolver returned inconsistent archive hash for {name} {version}"
        );
        ensure!(
            sha256_bytes(&materialization.source_row_bytes) == materialization.source_row_sha256,
            "crates.io resolver returned inconsistent source-row hash for {name} {version}"
        );
        Ok(ResolvedPackage {
            name: name.to_owned(),
            version: version.clone(),
            archive_bytes: materialization.archive_bytes,
            source_row_bytes: materialization.source_row_bytes,
            source: LockedSource::CratesIo {},
        })
    }

    fn resolve_git_tag(
        &self,
        repository: &str,
        tag: &str,
        package_name: &str,
        cargo_version: &Version,
    ) -> Result<ResolvedPackage> {
        let materialization =
            package::resolve_git_tag(repository, tag, package_name, cargo_version)?;
        ensure!(
            sha256_bytes(&materialization.archive_bytes) == materialization.archive_sha256,
            "Git resolver returned inconsistent archive hash for {package_name} tag {tag:?}"
        );
        ensure!(
            sha256_bytes(&materialization.source_row_bytes) == materialization.source_row_sha256,
            "Git resolver returned inconsistent source-row hash for {package_name} tag {tag:?}"
        );
        Ok(ResolvedPackage {
            name: materialization.name,
            version: materialization.version,
            archive_bytes: materialization.archive_bytes,
            source_row_bytes: materialization.source_row_bytes,
            source: LockedSource::GitTag {
                git: repository.to_owned(),
                tag: tag.to_owned(),
                tag_oid: materialization.tag_oid,
                commit: materialization.commit,
                package: package_name.to_owned(),
                path: materialization.path,
                cargo_version: cargo_version.clone(),
            },
        })
    }
}

#[derive(Debug)]
pub(crate) struct ResolvedPackage {
    pub(crate) name: String,
    pub(crate) version: Version,
    pub(crate) archive_bytes: Vec<u8>,
    pub(crate) source_row_bytes: Vec<u8>,
    pub(crate) source: LockedSource,
}

#[derive(Clone, Debug)]
struct DesiredMirror {
    registry: String,
    category: CategoryId,
    name: String,
    version: Version,
}

#[derive(Clone, Debug)]
struct DesiredGitTag {
    registry: String,
    category: CategoryId,
    name: String,
    repository: String,
    tag: String,
    cargo_version: Version,
}

#[derive(Default)]
struct DesiredState {
    mirrors: BTreeMap<Identity, DesiredMirror>,
    git_tags: BTreeMap<GitIdentity, DesiredGitTag>,
}

type VersionIdentity = (u64, u64, u64, String);
type Identity = (String, VersionIdentity);
type GitIdentity = (String, String, String, String);

type OldPackages = BTreeMap<Identity, (String, CategoryId, LockedPackage)>;

#[derive(Default)]
struct PendingObjects {
    crates: BTreeMap<String, Vec<u8>>,
    rows: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum ReconciliationMode<'a> {
    Direct,
    Admitted(&'a BTreeMap<Identity, MirrorAdmission>),
}

fn reconcile_with<R: Resolver, N: Renamer>(
    root: &Path,
    source_resolver: &R,
    renamer: &N,
) -> Result<ReconcileSummary> {
    reconcile_with_mode(root, source_resolver, renamer, ReconciliationMode::Direct)
}

fn reconcile_with_mode<R: Resolver, N: Renamer>(
    root: &Path,
    source_resolver: &R,
    renamer: &N,
    mode: ReconciliationMode<'_>,
) -> Result<ReconcileSummary> {
    let root = canonical_catalog_root(root)?;
    let _guard = CatalogGuard::acquire(&root)?;
    let inputs = load_registry_inputs(&root)?;
    ensure!(!inputs.is_empty(), "catalog has no registry declarations");

    for input in &inputs {
        validate_input_for_update(input)?;
    }

    let preflight_inputs = inputs_with_default_locks(&inputs);
    let preflight_catalog = catalog_from_inputs(&root, &preflight_inputs)?;
    let policy = validate_catalog(&preflight_catalog)?;
    let uses_legacy_archives = validate_existing_objects_and_rows(&preflight_catalog, &policy)?;

    let desired = collect_desired_packages(&inputs)?;
    let old = collect_old_packages(&inputs)?;
    validate_desired_against_history(&desired, &old)?;
    let bootstrap = inputs.iter().all(|input| input.lock.is_none());
    validate_mirror_admissions(&desired, &old, bootstrap, mode)?;

    let (mut next_locks, mut summary) = prepare_next_locks(&inputs, &desired)?;
    let pending = resolve_new_packages(
        source_resolver,
        &desired,
        &old,
        &preflight_catalog,
        &policy,
        mode,
        &mut next_locks,
        &mut summary,
    )?;

    let next_inputs = inputs_with_locks(&inputs, &next_locks);
    let next_catalog = catalog_from_inputs(&root, &next_inputs)?;
    validate_catalog(&next_catalog)?;
    let lock_changed = inputs
        .iter()
        .any(|input| input.lock.as_ref() != next_locks.get(&input.file.registry.name));
    let downloads = DownloadCatalog::from_catalog(&next_catalog).canonical_bytes()?;
    let downloads_changed = generated_download_catalog_differs(&root, &downloads)?;
    if !lock_changed && !uses_legacy_archives && !downloads_changed {
        Catalog::load(&root).context("strictly reload unchanged catalog")?;
        return Ok(summary);
    }

    let staging = stage_catalog(&root, &inputs, &next_inputs, &next_catalog, &pending)?;
    validate_staged_catalog(staging.path())?;
    install_staging(&root, staging.path(), renamer)?;
    summary.changed = true;
    Ok(summary)
}

fn mirror_admission<'a>(
    mode: ReconciliationMode<'a>,
    identity: &Identity,
) -> Option<&'a MirrorAdmission> {
    match mode {
        ReconciliationMode::Direct => None,
        ReconciliationMode::Admitted(admissions) => Some(
            admissions
                .get(identity)
                .expect("new mirror admissions were validated before resolution"),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_new_packages<R: Resolver>(
    source_resolver: &R,
    desired: &DesiredState,
    old: &OldPackages,
    catalog: &Catalog,
    policy: &Policy,
    mode: ReconciliationMode<'_>,
    next_locks: &mut BTreeMap<String, RegistryLock>,
    summary: &mut ReconcileSummary,
) -> Result<PendingObjects> {
    let mut pending = PendingObjects::default();
    let mut identities = old.keys().cloned().collect::<BTreeSet<_>>();
    for (identity, package) in &desired.mirrors {
        if old.contains_key(identity) {
            continue;
        }
        let resolved = source_resolver
            .resolve_mirror(&package.name, &package.version)
            .with_context(|| {
                format!(
                    "resolve new package {} {} for {}",
                    package.name, package.version, package.registry
                )
            })?;
        let admission = mirror_admission(mode, identity);
        if let Some(admission) = admission {
            ensure!(
                sha256_bytes(&resolved.archive_bytes) == admission.crate_sha256,
                "resolved archive hash differs from update admission for {} {}",
                package.name,
                package.version
            );
            ensure!(
                sha256_bytes(&resolved.source_row_bytes) == admission.source_row_sha256,
                "resolved source-row hash differs from update admission for {} {}",
                package.name,
                package.version
            );
        }
        let locked = lock_resolved_package(
            &package.registry,
            &package.category,
            &package.name,
            Some(&package.version),
            None,
            admission.map(|value| value.binding_sha256.as_str()),
            resolved,
            catalog,
            policy,
            &mut identities,
            &mut pending,
        )?;
        next_locks
            .get_mut(&package.registry)
            .expect("desired registry was loaded")
            .packages
            .push(locked);
        summary.packages_added += 1;
    }
    for (git_identity, package) in &desired.git_tags {
        if old
            .values()
            .any(|(registry, _, locked)| git_key(registry, locked).as_ref() == Some(git_identity))
        {
            continue;
        }
        let resolved = source_resolver
            .resolve_git_tag(
                &package.repository,
                &package.tag,
                &package.name,
                &package.cargo_version,
            )
            .with_context(|| {
                format!(
                    "resolve new Git tag {:?} for {} in {}",
                    package.tag, package.name, package.registry
                )
            })?;
        let locked = lock_resolved_package(
            &package.registry,
            &package.category,
            &package.name,
            None,
            Some((&package.repository, &package.tag, &package.cargo_version)),
            None,
            resolved,
            catalog,
            policy,
            &mut identities,
            &mut pending,
        )?;
        next_locks
            .get_mut(&package.registry)
            .expect("desired registry was loaded")
            .packages
            .push(locked);
        summary.packages_added += 1;
    }
    Ok(pending)
}

fn canonical_catalog_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect catalog root {}", root.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "catalog root is not a real directory: {}",
        root.display()
    );
    fs::canonicalize(root).with_context(|| format!("canonicalize catalog root {}", root.display()))
}

fn inputs_with_default_locks(inputs: &[RegistryInput]) -> Vec<RegistryInput> {
    inputs
        .iter()
        .cloned()
        .map(|mut input| {
            if input.lock.is_none() {
                input.lock = Some(empty_lock(&input.file));
            }
            input
        })
        .collect()
}

fn inputs_with_locks(
    inputs: &[RegistryInput],
    locks: &BTreeMap<String, RegistryLock>,
) -> Vec<RegistryInput> {
    inputs
        .iter()
        .cloned()
        .map(|mut input| {
            input.lock = Some(
                locks
                    .get(&input.file.registry.name)
                    .expect("every input has a next lock")
                    .clone(),
            );
            input
        })
        .collect()
}

fn collect_desired_packages(inputs: &[RegistryInput]) -> Result<DesiredState> {
    let mut desired = DesiredState::default();
    for input in inputs {
        let registry = &input.file.registry.name;
        for category in input.file.category_values() {
            for (name, versions) in &category.mirror {
                for version in versions {
                    let identity = package_identity(name, version);
                    ensure!(
                        desired
                            .mirrors
                            .insert(
                                identity,
                                DesiredMirror {
                                    registry: registry.clone(),
                                    category: category.id.clone(),
                                    name: name.clone(),
                                    version: version.clone(),
                                },
                            )
                            .is_none(),
                        "mirrored identity {name} {version} is desired more than once"
                    );
                }
            }
            for (name, declaration) in &category.publish {
                validate_https_repository(&declaration.git).with_context(|| {
                    format!(
                        "invalid Git repository for package {name:?} in {}",
                        category.declared_in.display()
                    )
                })?;
                for tag in &declaration.tags {
                    validate_git_tag(tag).with_context(|| {
                        format!(
                            "invalid Git tag for package {name:?} in {}",
                            category.declared_in.display()
                        )
                    })?;
                    let identity = (
                        registry.clone(),
                        name.clone(),
                        declaration.git.clone(),
                        tag.clone(),
                    );
                    ensure!(
                        desired
                            .git_tags
                            .insert(
                                identity,
                                DesiredGitTag {
                                    registry: registry.clone(),
                                    category: category.id.clone(),
                                    name: name.clone(),
                                    repository: declaration.git.clone(),
                                    tag: tag.clone(),
                                    cargo_version: input.file.registry.cargo_version.clone(),
                                },
                            )
                            .is_none(),
                        "Git tag {tag:?} for package {name:?} is desired more than once"
                    );
                }
            }
        }
    }
    Ok(desired)
}

fn collect_old_packages(inputs: &[RegistryInput]) -> Result<OldPackages> {
    let mut old = BTreeMap::new();
    for input in inputs {
        let Some(lock) = &input.lock else {
            continue;
        };
        let categories = lock
            .names
            .iter()
            .map(|name| (name.name.as_str(), name.category.as_str()))
            .collect::<BTreeMap<_, _>>();
        for package in &lock.packages {
            let local = categories.get(package.name.as_str()).with_context(|| {
                format!(
                    "locked package {} {} has no permanent name anchor",
                    package.name, package.version
                )
            })?;
            let category = CategoryId::new(&input.file.registry.name, *local)
                .context("locked package has invalid category anchor")?;
            let identity = package_identity(&package.name, &package.version);
            ensure!(
                old.insert(
                    identity,
                    (input.file.registry.name.clone(), category, package.clone(),),
                )
                .is_none(),
                "locked identity {} {} occurs in more than one registry",
                package.name,
                package.version
            );
        }
    }
    Ok(old)
}

fn validate_desired_against_history(desired: &DesiredState, old: &OldPackages) -> Result<()> {
    let mut old_tags = BTreeMap::new();
    for (identity, (registry, _, package)) in old {
        if let Some(key) = git_key(registry, package) {
            ensure!(
                old_tags.insert(key, identity).is_none(),
                "one Git package tag is locked to more than one package identity"
            );
        }
    }
    for (identity, package) in &desired.mirrors {
        if let Some((registry, category, locked)) = old.get(identity) {
            ensure!(
                registry == &package.registry
                    && category == &package.category
                    && locked.state == PackageState::Active
                    && matches!(locked.source, LockedSource::CratesIo {}),
                "desired mirror {} {} conflicts with immutable package history",
                package.name,
                package.version
            );
        }
    }
    for (key, package) in &desired.git_tags {
        if let Some(identity) = old_tags.get(key) {
            let (_, category, locked) = old
                .get(*identity)
                .expect("old Git tag map was derived from old packages");
            ensure!(
                category == &package.category && locked.state == PackageState::Active,
                "removed or recategorized Git publication {} tag {:?} cannot be reactivated",
                package.name,
                package.tag
            );
        }
    }
    Ok(())
}

fn validate_mirror_admissions(
    desired: &DesiredState,
    old: &OldPackages,
    bootstrap: bool,
    mode: ReconciliationMode<'_>,
) -> Result<()> {
    let new_identities = desired
        .mirrors
        .keys()
        .filter(|identity| !old.contains_key(*identity))
        .cloned()
        .collect::<BTreeSet<_>>();
    match mode {
        ReconciliationMode::Direct => {
            if let Some(identity) = new_identities.first() {
                let package = desired
                    .mirrors
                    .get(identity)
                    .expect("new identity came from desired mirrors");
                ensure!(
                    bootstrap,
                    "direct lock reconciliation cannot admit new crates.io identity {} {}; use update-plan and update-apply",
                    package.name,
                    package.version
                );
            }
        }
        ReconciliationMode::Admitted(admissions) => {
            let admitted_identities = admissions.keys().cloned().collect::<BTreeSet<_>>();
            ensure!(
                admitted_identities == new_identities,
                "update admissions must exactly match the new crates.io identities in the declarations"
            );
            for identity in new_identities {
                let package = desired
                    .mirrors
                    .get(&identity)
                    .expect("new identity came from desired mirrors");
                let admission = admissions
                    .get(&identity)
                    .expect("admitted identity set was checked above");
                ensure!(
                    admission.registry == package.registry
                        && admission.category == package.category
                        && admission.name == package.name
                        && admission.version == package.version,
                    "update admission route differs from declaration for {} {}",
                    package.name,
                    package.version
                );
            }
        }
    }
    Ok(())
}

fn prepare_next_locks(
    inputs: &[RegistryInput],
    desired: &DesiredState,
) -> Result<(BTreeMap<String, RegistryLock>, ReconcileSummary)> {
    let mut locks = BTreeMap::new();
    let mut summary = ReconcileSummary::default();
    for input in inputs {
        let registry = &input.file.registry.name;
        let mut next = input
            .lock
            .clone()
            .unwrap_or_else(|| empty_lock(&input.file));
        next.registry
            .download
            .clone_from(&input.file.registry.download);
        let previous_names = next
            .names
            .iter()
            .map(|name| name.name.clone())
            .collect::<BTreeSet<_>>();
        next.names = input
            .file
            .categories
            .iter()
            .flat_map(|(local, category)| {
                category
                    .mirror
                    .keys()
                    .map(|name| LockedName {
                        name: name.clone(),
                        category: local.clone(),
                        source: NameSource::Mirror,
                    })
                    .chain(category.publish.keys().map(|name| LockedName {
                        name: name.clone(),
                        category: local.clone(),
                        source: NameSource::Publish,
                    }))
            })
            .collect();
        next.names.sort_by(|left, right| {
            (left.name.to_ascii_lowercase(), left.name.as_str())
                .cmp(&(right.name.to_ascii_lowercase(), right.name.as_str()))
        });
        summary.names_added += next
            .names
            .iter()
            .filter(|name| !previous_names.contains(name.name.as_str()))
            .count();

        for package in &mut next.packages {
            let remains_desired = match &package.source {
                LockedSource::CratesIo {} => desired
                    .mirrors
                    .get(&package_identity(&package.name, &package.version))
                    .is_some_and(|declaration| {
                        declaration.registry == *registry
                            && declaration.category.registry() == registry
                    }),
                LockedSource::GitTag { .. } => git_key(registry, package).is_some_and(|key| {
                    desired.git_tags.get(&key).is_some_and(|declaration| {
                        declaration.registry == *registry
                            && declaration.category.registry() == registry
                    })
                }),
            };
            if !remains_desired && package.state == PackageState::Active {
                package.state = PackageState::Removed;
                summary.packages_removed += 1;
            }
        }
        ensure!(
            locks.insert(registry.clone(), next).is_none(),
            "duplicate next lock for registry {registry:?}"
        );
    }
    Ok((locks, summary))
}

#[allow(clippy::too_many_arguments)]
fn lock_resolved_package(
    registry: &str,
    category: &CategoryId,
    expected_name: &str,
    expected_version: Option<&Version>,
    expected_git: Option<(&str, &str, &Version)>,
    admission_sha256: Option<&str>,
    resolved: ResolvedPackage,
    catalog: &Catalog,
    policy: &Policy,
    identities: &mut BTreeSet<Identity>,
    pending: &mut PendingObjects,
) -> Result<LockedPackage> {
    ensure!(
        resolved.name == expected_name,
        "resolved package name {:?} differs from declaration {expected_name:?}",
        resolved.name
    );
    match (&resolved.source, expected_version, expected_git) {
        (LockedSource::CratesIo {}, Some(version), None) => ensure!(
            resolved.version == *version,
            "resolved mirror {expected_name} has version {}; expected {version}",
            resolved.version
        ),
        (
            LockedSource::GitTag {
                git,
                tag,
                package,
                cargo_version,
                ..
            },
            None,
            Some((expected_repository, expected_tag, expected_cargo)),
        ) => {
            ensure!(
                git == expected_repository
                    && tag == expected_tag
                    && package == expected_name
                    && cargo_version == expected_cargo,
                "resolved Git source evidence differs from declaration for {expected_name} tag {expected_tag:?}"
            );
            validate_tag_version(tag, &resolved.version)?;
        }
        _ => bail!("resolver returned the wrong source class for {expected_name}"),
    }
    ensure!(
        admission_sha256.is_none() || matches!(resolved.source, LockedSource::CratesIo {}),
        "only crates.io identities may carry update-admission evidence"
    );
    if let Some(binding) = admission_sha256 {
        crate::policy::validate_sha256(binding).context("validate update-admission binding")?;
    }

    let identity = package_identity(&resolved.name, &resolved.version);
    ensure!(
        identities.insert(identity),
        "new package {} {} conflicts with an existing Cargo package identity",
        resolved.name,
        resolved.version
    );
    let archive_sha256 = sha256_bytes(&resolved.archive_bytes);
    let source_row_sha256 = sha256_bytes(&resolved.source_row_bytes);
    ensure!(
        category.registry() == registry,
        "category {category} does not belong to registry {registry:?}"
    );
    let index_row_sha256 = routed_row_hash(
        category,
        &resolved.name,
        &resolved.version,
        &archive_sha256,
        &resolved.source_row_bytes,
        catalog,
        policy,
    )?;
    if matches!(&resolved.source, LockedSource::GitTag { .. }) {
        insert_pending_object(
            &mut pending.crates,
            &archive_sha256,
            resolved.archive_bytes,
            "crate",
        )?;
    }
    insert_pending_object(
        &mut pending.rows,
        &source_row_sha256,
        resolved.source_row_bytes,
        "source row",
    )?;
    Ok(LockedPackage {
        name: resolved.name,
        version: resolved.version,
        state: PackageState::Active,
        crate_sha256: archive_sha256,
        source_row_sha256,
        index_row_sha256,
        admission_sha256: admission_sha256.map(str::to_owned),
        source: resolved.source,
    })
}

fn insert_pending_object(
    objects: &mut BTreeMap<String, Vec<u8>>,
    hash: &str,
    bytes: Vec<u8>,
    description: &str,
) -> Result<()> {
    if let Some(previous) = objects.get(hash) {
        ensure!(
            previous == &bytes,
            "two different {description} objects claim SHA-256 {hash}"
        );
    } else {
        objects.insert(hash.to_owned(), bytes);
    }
    Ok(())
}

fn package_identity(name: &str, version: &Version) -> Identity {
    (
        name.to_ascii_lowercase().replace('-', "_"),
        version_identity(version),
    )
}

fn git_key(registry: &str, package: &LockedPackage) -> Option<GitIdentity> {
    match &package.source {
        LockedSource::GitTag { git, tag, .. } => Some((
            registry.to_owned(),
            package.name.clone(),
            git.clone(),
            tag.clone(),
        )),
        LockedSource::CratesIo {} => None,
    }
}

fn validate_existing_objects_and_rows(catalog: &Catalog, policy: &Policy) -> Result<bool> {
    if catalog.approvals.is_empty() && object_store_is_absent(catalog)? {
        return Ok(false);
    }
    let (artifacts, uses_legacy_archives) = ArtifactMap::load_for_update(catalog)?;
    validate_routed_rows(catalog, policy, &artifacts)?;
    Ok(uses_legacy_archives)
}

fn validate_strict_objects_and_rows(catalog: &Catalog, policy: &Policy) -> Result<()> {
    let artifacts = ArtifactMap::load(catalog)?;
    validate_routed_rows(catalog, policy, &artifacts)
}

fn validate_routed_rows(catalog: &Catalog, policy: &Policy, artifacts: &ArtifactMap) -> Result<()> {
    for approval in &catalog.approvals {
        let artifact = artifacts
            .get(&approval.registry, &approval.name, &approval.version)
            .expect("verified object map contains every approval");
        let source_row = fs::read(&artifact.index_record).with_context(|| {
            format!(
                "read existing source row for {} {}",
                approval.name, approval.version
            )
        })?;
        let actual = routed_row_hash(
            &approval.category,
            &approval.name,
            &approval.version,
            &approval.archive_sha256,
            &source_row,
            catalog,
            policy,
        )?;
        ensure!(
            actual == approval.index_row_sha256,
            "routed index-row hash mismatch for {} {}: expected {}, got {actual}",
            approval.name,
            approval.version,
            approval.index_row_sha256
        );
    }
    Ok(())
}

fn generated_download_catalog_differs(root: &Path, expected: &[u8]) -> Result<bool> {
    let path = root.join(DOWNLOAD_CATALOG_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    ensure!(
        metadata.file_type().is_file(),
        "generated download catalog is not a regular file: {}",
        path.display()
    );
    if metadata.len() > MAX_DOWNLOAD_CATALOG_BYTES as u64 {
        return Ok(true);
    }
    let actual = fs::read(&path)
        .with_context(|| format!("read generated download catalog {}", path.display()))?;
    Ok(actual != expected)
}

fn object_store_is_absent(catalog: &Catalog) -> Result<bool> {
    let objects = catalog.root.join("objects");
    match fs::symlink_metadata(&objects) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("inspect {}", objects.display())),
    }
}

fn routed_row_hash(
    source_category: &CategoryId,
    name: &str,
    version: &Version,
    archive_sha256: &str,
    source_row: &[u8],
    catalog: &Catalog,
    policy: &Policy,
) -> Result<String> {
    let mut record = IndexRecord::parse(source_row)
        .with_context(|| format!("parse source row for {name} {version}"))?;
    record
        .validate_structure()
        .with_context(|| format!("validate source row for {name} {version}"))?;
    ensure!(
        record.name()? == name && record.version()? == *version,
        "source row identity differs from {name} {version}"
    );
    ensure!(
        record.checksum()? == archive_sha256,
        "source row checksum for {name} {version} differs from archive hash {archive_sha256}"
    );
    record.set_yanked(false);
    let routes = record.route_dependencies(
        source_category.registry(),
        &catalog.homes.homes,
        &policy.registry_urls,
    )?;
    for (package, home) in routes {
        ensure!(
            policy.permits_dependency(source_category, &home.category),
            "{name} {version} in {source_category} may not depend on {package} in {}",
            home.category
        );
    }
    Ok(sha256_bytes(&record.to_json_line()?))
}

fn stage_catalog(
    root: &Path,
    inputs: &[RegistryInput],
    next_inputs: &[RegistryInput],
    catalog: &Catalog,
    pending: &PendingObjects,
) -> Result<TemporaryCatalog> {
    let staging = TemporaryCatalog::sibling_of(root, "stage")?;
    fs::create_dir(staging.path()).with_context(|| {
        format!(
            "create staged catalog directory {}",
            staging.path().display()
        )
    })?;
    for (input, next) in inputs.iter().zip(next_inputs) {
        let filename = input
            .path
            .file_name()
            .context("registry human file has no filename")?;
        copy_new(&input.path, &staging.path().join(filename))?;
        let lock_filename = input
            .lock_path
            .file_name()
            .context("registry lock path has no filename")?;
        let bytes = serialize_lock(
            next.lock
                .as_ref()
                .expect("next registry input always has a lock"),
        )?;
        write_new(&staging.path().join(lock_filename), &bytes)?;
    }
    let downloads = DownloadCatalog::from_catalog(catalog).canonical_bytes()?;
    write_new(&staging.path().join(DOWNLOAD_CATALOG_FILE), &downloads)?;
    copy_optional_tree(
        &root.join("categories"),
        &staging.path().join("categories"),
        "external category tree",
    )?;
    copy_optional_tree(
        &root.join("admissions"),
        &staging.path().join("admissions"),
        "admission batch tree",
    )?;

    let crates = catalog
        .approvals
        .iter()
        .filter(|approval| {
            !approval.is_removed() && matches!(&approval.source, Source::GitTag { .. })
        })
        .map(|approval| approval.archive_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let rows = catalog
        .approvals
        .iter()
        .map(|approval| approval.index_record_sha256.as_str())
        .collect::<BTreeSet<_>>();
    fs::create_dir_all(staging.path().join("objects/crates")).with_context(|| {
        format!(
            "create staged crate-object directory below {}",
            staging.path().display()
        )
    })?;
    fs::create_dir_all(staging.path().join("objects/rows")).with_context(|| {
        format!(
            "create staged row-object directory below {}",
            staging.path().display()
        )
    })?;
    for hash in crates {
        materialize_object(
            root,
            staging.path(),
            "crates",
            &format!("{hash}.crate"),
            hash,
            &pending.crates,
        )?;
    }
    for hash in rows {
        materialize_object(
            root,
            staging.path(),
            "rows",
            &format!("{hash}.json"),
            hash,
            &pending.rows,
        )?;
    }
    sync_directory(&staging.path().join("objects/crates"))?;
    sync_directory(&staging.path().join("objects/rows"))?;
    sync_directory(&staging.path().join("objects"))?;
    sync_directory(staging.path())?;
    Ok(staging)
}

fn materialize_object(
    old_root: &Path,
    staged_root: &Path,
    kind: &str,
    filename: &str,
    hash: &str,
    pending: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let destination = staged_root.join("objects").join(kind).join(filename);
    if let Some(bytes) = pending.get(hash) {
        ensure!(
            sha256_bytes(bytes) == hash,
            "pending object {filename} does not match its content address"
        );
        write_new(&destination, bytes)
    } else {
        let source = old_root.join("objects").join(kind).join(filename);
        copy_new(&source, &destination)
    }
}

fn validate_staged_catalog(root: &Path) -> Result<()> {
    let catalog = Catalog::load(root).context("strictly load staged catalog")?;
    let policy = validate_catalog(&catalog).context("validate staged catalog policy")?;
    validate_strict_objects_and_rows(&catalog, &policy)
        .context("verify staged catalog objects and routed rows")?;
    let artifacts = ArtifactMap::load(&catalog)?;
    let rendered = TemporaryCatalog::sibling_of(root, "render")?;
    crate::render::render(&catalog, &artifacts, rendered.path())
        .context("test-render staged catalog")
}

trait Renamer {
    fn rename(&self, source: &Path, destination: &Path) -> std::io::Result<()>;
}

struct FilesystemRenamer;

impl Renamer for FilesystemRenamer {
    fn rename(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
        fs::rename(source, destination)
    }
}

fn install_staging<N: Renamer>(root: &Path, staging: &Path, renamer: &N) -> Result<()> {
    let backup = unique_sibling(root, "backup")?;
    renamer.rename(root, &backup).with_context(|| {
        format!(
            "move existing catalog {} to backup {}",
            root.display(),
            backup.display()
        )
    })?;
    if let Err(install_error) = renamer.rename(staging, root) {
        return match renamer.rename(&backup, root) {
            Ok(()) => Err(install_error).with_context(|| {
                format!(
                    "install staged catalog {}; original catalog was restored",
                    staging.display()
                )
            }),
            Err(restore_error) => bail!(
                "install staged catalog {} failed ({install_error}); restoring backup {} also failed ({restore_error}); recover it manually",
                staging.display(),
                backup.display()
            ),
        };
    }
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    sync_directory(parent)?;
    if let Err(error) = fs::remove_dir_all(&backup) {
        warn!(
            path = %backup.display(),
            error = %error,
            "installed catalog but could not remove backup directory"
        );
    }
    Ok(())
}

fn unique_sibling(path: &Path, purpose: &str) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("catalog directory name is not valid UTF-8")?;
    for _ in 0..100 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{name}.pkgre-{purpose}-{}-{sequence}",
            std::process::id()
        ));
        match fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect temporary path {}", candidate.display()));
            }
        }
    }
    bail!(
        "could not allocate a unique {purpose} path for {}",
        path.display()
    )
}

fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    output
        .write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect source file {}", source.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "source path is not a regular file: {}",
        source.display()
    );
    let mut input = File::open(source).with_context(|| format!("open {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("create {}", destination.display()))?;
    std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy {} to {}", source.display(), destination.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync {}", destination.display()))
}

fn copy_optional_tree(source: &Path, destination: &Path, description: &str) -> Result<()> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", source.display())),
    };
    ensure!(
        metadata.file_type().is_dir(),
        "{description} is not a real directory: {}",
        source.display()
    );
    fs::create_dir(destination)
        .with_context(|| format!("create copied directory {}", destination.display()))?;
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("read {description} {}", source.display()))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    for entry in entries {
        let entry_metadata = fs::symlink_metadata(&entry)
            .with_context(|| format!("inspect {description} entry {}", entry.display()))?;
        let target = destination.join(
            entry
                .file_name()
                .context("copied catalog entry has no filename")?,
        );
        if entry_metadata.file_type().is_dir() {
            copy_optional_tree(&entry, &target, description)?;
        } else if entry_metadata.file_type().is_file() {
            copy_new(&entry, &target)?;
        } else {
            bail!(
                "{description} entry is not a real directory or regular file: {}",
                entry.display()
            );
        }
    }
    sync_directory(destination)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

struct CatalogGuard {
    path: PathBuf,
    _file: File,
}

impl CatalogGuard {
    fn acquire(root: &Path) -> Result<Self> {
        let parent = root.parent().unwrap_or_else(|| Path::new("."));
        let name = root
            .file_name()
            .and_then(|value| value.to_str())
            .context("catalog directory name is not valid UTF-8")?;
        let path = parent.join(format!(".{name}.pkgre-lock"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "acquire reconciliation guard {}; another reconciliation may be running",
                    path.display()
                )
            })?;
        Ok(Self { path, _file: file })
    }
}

impl Drop for CatalogGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct TemporaryCatalog {
    path: PathBuf,
}

impl TemporaryCatalog {
    fn sibling_of(path: &Path, purpose: &str) -> Result<Self> {
        Ok(Self {
            path: unique_sibling(path, purpose)?,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryCatalog {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                let _ = fs::remove_dir_all(&self.path);
            }
            Ok(_) => {
                let _ = fs::remove_file(&self.path);
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};

    use super::*;
    use crate::download::{DownloadSource, router_download_template};
    use crate::index::index_path;
    use crate::schema::{MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD, load_lock};

    const UNIVERSE_URL: &str = "sparse+https://rust.pkg.re/universe/";
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn bootstrap_routes_all_layers_and_second_run_is_an_exact_noop() {
        let temporary = TemporaryDirectory::new("pkgre-lock-bootstrap");
        let root = temporary.path().join("catalog");
        write_catalog(
            &root,
            "[mirror]\nleaf-core = [\"1.0.0\"]\n",
            "[mirror]\nmatrix-middle = [\"1.0.0\"]\n",
            "[publish.pkgre-tool]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"tool/v1.0.0\"]\n",
        );
        let resolver = FakeResolver::default();

        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert_eq!(
            summary,
            ReconcileSummary {
                changed: true,
                names_added: 9,
                packages_added: 3,
                packages_removed: 0,
            }
        );
        assert_eq!(resolver.calls(), 3);
        let catalog = Catalog::load(&root).unwrap();
        ArtifactMap::load(&catalog).unwrap();
        assert_eq!(catalog.approvals.len(), 3);
        assert!(
            catalog
                .approvals
                .iter()
                .all(|package| package.state == PackageState::Active)
        );
        assert_routed_registry(&temporary, &catalog, "universe", "matrix-middle", None);
        assert_routed_registry(
            &temporary,
            &catalog,
            "pkgre",
            "pkgre-tool",
            Some(UNIVERSE_URL),
        );

        let before = snapshot(temporary.path());
        let second = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert_eq!(second, ReconcileSummary::default());
        assert_eq!(resolver.calls(), 3);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn established_catalog_rejects_direct_new_mirror_before_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-direct-admission");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();

        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
            "",
            "",
        );
        let before = snapshot(temporary.path());
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();

        assert!(
            format!("{error:#}").contains(
                "direct lock reconciliation cannot admit new crates.io identity beta 1.0.0"
            )
        );
        assert_eq!(resolver.calls(), 1);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn generated_download_catalog_is_required_exact_regenerated_and_rendered() {
        let temporary = TemporaryDirectory::new("pkgre-lock-download-catalog");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert_eq!(resolver.calls(), 1);

        let expected = fs::read(root.join(DOWNLOAD_CATALOG_FILE)).unwrap();
        let parsed = DownloadCatalog::parse_canonical(&expected).unwrap();
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.routes[0].name, "alpha");
        assert_eq!(parsed.routes[0].source, DownloadSource::CratesIo);

        let catalog = Catalog::load(&root).unwrap();
        let artifacts = ArtifactMap::load(&catalog).unwrap();
        let site = temporary.path().join("download-site");
        crate::render::render(&catalog, &artifacts, &site).unwrap();
        assert_eq!(
            fs::read(site.join(DOWNLOAD_CATALOG_FILE)).unwrap(),
            expected
        );

        fs::remove_file(root.join(DOWNLOAD_CATALOG_FILE)).unwrap();
        assert_download_catalog_regenerated(&root, &resolver, None, &expected);
        assert_download_catalog_regenerated(
            &root,
            &resolver,
            Some(serde_json::to_vec(&parsed).unwrap()),
            &expected,
        );

        let mut changed = parsed.clone();
        changed.routes[0].sha256 = "03".repeat(32);
        assert_download_catalog_regenerated(
            &root,
            &resolver,
            Some(changed.canonical_bytes().unwrap()),
            &expected,
        );
        let mut changed = parsed.clone();
        changed.routes[0].source = DownloadSource::GitTag;
        assert_download_catalog_regenerated(
            &root,
            &resolver,
            Some(changed.canonical_bytes().unwrap()),
            &expected,
        );

        let mut extra = parsed;
        extra.routes.push(crate::download::DownloadRoute {
            registry: "universe".to_owned(),
            name: "zeta".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            sha256: "04".repeat(32),
            source: DownloadSource::CratesIo,
        });
        assert_download_catalog_regenerated(
            &root,
            &resolver,
            Some(extra.canonical_bytes().unwrap()),
            &expected,
        );
        assert_download_catalog_regenerated(
            &root,
            &resolver,
            Some(vec![b' '; MAX_DOWNLOAD_CATALOG_BYTES + 1]),
            &expected,
        );

        assert_eq!(
            reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap(),
            ReconcileSummary::default()
        );
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn nonregular_download_catalog_is_rejected_without_mutation() {
        let temporary = TemporaryDirectory::new("pkgre-lock-download-nonregular");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        let path = root.join(DOWNLOAD_CATALOG_FILE);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let before = snapshot(temporary.path());

        let error = Catalog::load(&root).unwrap_err();
        assert!(format!("{error:#}").contains("not a regular file"));
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("not a regular file"));
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn one_existing_lock_disables_direct_bootstrap() {
        let temporary = TemporaryDirectory::new("pkgre-lock-partial-bootstrap");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let inputs = load_registry_inputs(&root).unwrap();
        let pkgre = inputs
            .iter()
            .find(|input| input.file.registry.name == "pkgre")
            .unwrap();
        fs::write(
            root.join("pkgre.lock"),
            serialize_lock(&empty_lock(&pkgre.file)).unwrap(),
        )
        .unwrap();
        let resolver = FakeResolver::default();
        let before = snapshot(temporary.path());

        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();

        assert!(format!("{error:#}").contains(
            "direct lock reconciliation cannot admit new crates.io identity alpha 1.0.0"
        ));
        assert_eq!(resolver.calls(), 0);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn admitted_reconciliation_requires_catalog_owned_batch() {
        let temporary = TemporaryDirectory::new("pkgre-lock-exact-admission");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
            "",
            "",
        );
        let admissions = fake_admission_map(&[("universe", "general", "beta", "1.0.0")]);
        let before = snapshot(temporary.path());

        let error = reconcile_with_mode(
            &root,
            &resolver,
            &FilesystemRenamer,
            ReconciliationMode::Admitted(&admissions),
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("generated locks reference missing admission batches")
        );
        assert_eq!(resolver.calls(), 2);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn reconciliation_retains_external_categories() {
        let temporary = TemporaryDirectory::new("pkgre-lock-auxiliary-trees");
        let root = temporary.path().join("catalog");
        let declarations = "[mirror]\nalpha = [\"1.0.0\"]\n";
        write_catalog(&root, declarations, "", "");
        let inline = mirror_category(
            "general",
            &["universe/general"],
            declarations,
            "reserved-general",
        );
        let external_reference = concat!(
            "[categories.general]\n",
            "file = \"categories/universe/general.toml\"\n\n",
        );
        let universe_path = root.join("universe.toml");
        let universe = fs::read_to_string(&universe_path).unwrap();
        assert!(universe.contains(&inline));
        fs::write(
            &universe_path,
            universe.replacen(&inline, external_reference, 1),
        )
        .unwrap();
        fs::create_dir_all(root.join("categories/universe")).unwrap();
        let category = concat!(
            "schema = 3\n",
            "may-depend-on = [\"universe/general\"]\n\n",
            "[mirror]\n",
            "alpha = [\"1.0.0\"]\n",
        );
        let category_path = root.join("categories/universe/general.toml");
        fs::write(&category_path, category).unwrap();
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        let removed_category = category.replace("alpha = [\"1.0.0\"]", "alpha = []");
        fs::write(&category_path, &removed_category).unwrap();
        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();

        assert_eq!(summary.packages_removed, 1);
        assert_eq!(
            fs::read_to_string(&category_path).unwrap(),
            removed_category
        );
        let before = snapshot(temporary.path());
        assert_eq!(
            reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap(),
            ReconcileSummary::default()
        );
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn missing_or_extra_mirror_admissions_fail_before_resolution() {
        for (prefix, entries) in [
            ("pkgre-lock-missing-admission", Vec::new()),
            (
                "pkgre-lock-extra-admission",
                vec![
                    ("universe", "general", "beta", "1.0.0"),
                    ("universe", "general", "gamma", "1.0.0"),
                ],
            ),
        ] {
            let temporary = TemporaryDirectory::new(prefix);
            let root = temporary.path().join("catalog");
            write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
            let resolver = FakeResolver::default();
            reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
            write_catalog(
                &root,
                "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
                "",
                "",
            );
            let admissions = fake_admission_map(&entries);
            let before = snapshot(temporary.path());

            let error = reconcile_with_mode(
                &root,
                &resolver,
                &FilesystemRenamer,
                ReconciliationMode::Admitted(&admissions),
            )
            .unwrap_err();

            assert!(format!("{error:#}").contains(
                "update admissions must exactly match the new crates.io identities in the declarations"
            ));
            assert_eq!(resolver.calls(), 1);
            assert_eq!(snapshot(temporary.path()), before);
        }
    }

    #[test]
    fn wrong_mirror_admission_route_fails_before_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-wrong-admission-route");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
            "",
            "",
        );
        let admissions = fake_admission_map(&[("universe", "matrix", "beta", "1.0.0")]);
        let before = snapshot(temporary.path());

        let error = reconcile_with_mode(
            &root,
            &resolver,
            &FilesystemRenamer,
            ReconciliationMode::Admitted(&admissions),
        )
        .unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("update admission route differs from declaration for beta 1.0.0")
        );
        assert_eq!(resolver.calls(), 1);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn wrong_mirror_admission_hashes_leave_tree_unchanged() {
        for (prefix, wrong_archive) in [
            ("pkgre-lock-wrong-archive-admission", true),
            ("pkgre-lock-wrong-row-admission", false),
        ] {
            let temporary = TemporaryDirectory::new(prefix);
            let root = temporary.path().join("catalog");
            write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
            let resolver = FakeResolver::default();
            reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
            write_catalog(
                &root,
                "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
                "",
                "",
            );
            let mut admissions = fake_admission_map(&[("universe", "general", "beta", "1.0.0")]);
            let admission = admissions.values_mut().next().unwrap();
            if wrong_archive {
                admission.crate_sha256 = "00".repeat(32);
            } else {
                admission.source_row_sha256 = "00".repeat(32);
            }
            let before = snapshot(temporary.path());

            let error = reconcile_with_mode(
                &root,
                &resolver,
                &FilesystemRenamer,
                ReconciliationMode::Admitted(&admissions),
            )
            .unwrap_err();

            let expected = if wrong_archive {
                "resolved archive hash differs from update admission for beta 1.0.0"
            } else {
                "resolved source-row hash differs from update admission for beta 1.0.0"
            };
            assert!(format!("{error:#}").contains(expected));
            assert_eq!(resolver.calls(), 2);
            assert_eq!(snapshot(temporary.path()), before);
        }
    }

    #[test]
    fn established_catalog_allows_direct_new_git_tag() {
        let temporary = TemporaryDirectory::new("pkgre-lock-direct-git-tag");
        let root = temporary.path().join("catalog");
        write_catalog(
            &root,
            "",
            "",
            "[publish.beta]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"beta/v1.0.0\"]\n",
        );
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        write_catalog(
            &root,
            "",
            "",
            "[publish.beta]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"beta/v1.0.0\", \"beta/v1.1.0\"]\n",
        );

        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();

        assert_eq!(summary.packages_added, 1);
        assert_eq!(resolver.calls(), 2);
        assert_eq!(
            locked_package(&root, "pkgre", "beta").version.to_string(),
            "1.0.0"
        );
        assert!(
            load_lock(&root.join("pkgre.lock"))
                .unwrap()
                .packages
                .iter()
                .any(|package| package.name == "beta"
                    && package.version == Version::parse("1.1.0").unwrap())
        );
    }

    #[test]
    fn unexpected_catalog_entries_fail_before_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-unmanaged-entry");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        fs::write(root.join("notes.md"), b"not managed by the reconciler\n").unwrap();
        let resolver = FakeResolver::default();
        let before = snapshot(temporary.path());

        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("unexpected entry in catalog root"));
        assert_eq!(resolver.calls(), 0);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn mixed_mirror_and_publish_registry_requires_router_before_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-mixed-source");
        let root = temporary.path().join("catalog");
        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\n\n[publish.beta]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"beta/v1.0.0\"]\n",
            "",
            "",
        );
        let resolver = FakeResolver::default();
        let before = snapshot(temporary.path());

        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("requires download"));
        assert_eq!(resolver.calls(), 0);
        assert_eq!(snapshot(temporary.path()), before);

        let declaration = fs::read_to_string(root.join("universe.toml")).unwrap();
        fs::write(
            root.join("universe.toml"),
            declaration.replace(MIRROR_DOWNLOAD, &router_download_template("universe")),
        )
        .unwrap();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert_eq!(resolver.calls(), 2);

        let downloads = DownloadCatalog::load_from_root(&root).unwrap();
        assert_eq!(downloads.routes.len(), 2);
        assert_eq!(downloads.routes[0].name, "alpha");
        assert_eq!(downloads.routes[0].source, DownloadSource::CratesIo);
        assert_eq!(downloads.routes[1].name, "beta");
        assert_eq!(downloads.routes[1].source, DownloadSource::GitTag);
    }

    #[test]
    fn exact_legacy_archive_set_migrates_once_without_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-legacy-archives");
        let root = temporary.path().join("catalog");
        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\n",
            "",
            "[publish.beta]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"beta/v1.0.0\"]\n",
        );
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        let mirror = locked_package(&root, "universe", "alpha");
        let mirror_archive = root
            .join("objects/crates")
            .join(format!("{}.crate", mirror.crate_sha256));
        fs::write(
            &mirror_archive,
            fake_archive("alpha", &Version::parse("1.0.0").unwrap()),
        )
        .unwrap();

        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert_eq!(
            summary,
            ReconcileSummary {
                changed: true,
                ..ReconcileSummary::default()
            }
        );
        assert_eq!(resolver.calls(), 2);
        assert!(!mirror_archive.exists());
        let git = locked_package(&root, "pkgre", "beta");
        assert!(
            root.join("objects/crates")
                .join(format!("{}.crate", git.crate_sha256))
                .is_file()
        );

        let before = snapshot(temporary.path());
        assert_eq!(
            reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap(),
            ReconcileSummary::default()
        );
        assert_eq!(resolver.calls(), 2);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn legacy_download_lock_migrates_with_archive_cleanup() {
        let temporary = TemporaryDirectory::new("pkgre-lock-download-migration");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        let mut core_lock = load_lock(&root.join("universe.lock")).unwrap();
        core_lock.registry.download = PUBLISH_DOWNLOAD.to_owned();
        fs::write(
            root.join("universe.lock"),
            serialize_lock(&core_lock).unwrap(),
        )
        .unwrap();
        let mirror = locked_package(&root, "universe", "alpha");
        let mirror_archive = root
            .join("objects/crates")
            .join(format!("{}.crate", mirror.crate_sha256));
        fs::write(
            &mirror_archive,
            fake_archive("alpha", &Version::parse("1.0.0").unwrap()),
        )
        .unwrap();

        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert!(summary.changed);
        assert_eq!(resolver.calls(), 1);
        assert_eq!(
            load_lock(&root.join("universe.lock"))
                .unwrap()
                .registry
                .download,
            MIRROR_DOWNLOAD
        );
        assert!(!mirror_archive.exists());
    }

    #[test]
    fn source_specific_download_migrates_once_to_registry_router() {
        let temporary = TemporaryDirectory::new("pkgre-lock-router-migration");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();

        let declaration = fs::read_to_string(root.join("universe.toml")).unwrap();
        fs::write(
            root.join("universe.toml"),
            declaration.replace(MIRROR_DOWNLOAD, &router_download_template("universe")),
        )
        .unwrap();
        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert!(summary.changed);
        assert_eq!(resolver.calls(), 1);
        assert_eq!(
            load_lock(&root.join("universe.lock"))
                .unwrap()
                .registry
                .download,
            router_download_template("universe")
        );

        let routed = fs::read_to_string(root.join("universe.toml")).unwrap();
        fs::write(
            root.join("universe.toml"),
            routed.replace(&router_download_template("universe"), MIRROR_DOWNLOAD),
        )
        .unwrap();
        let before = snapshot(temporary.path());
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("one-way source-specific"));
        assert_eq!(snapshot(temporary.path()), before);
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn removal_retains_evidence_yanks_row_and_cannot_be_reversed() {
        let temporary = TemporaryDirectory::new("pkgre-lock-removal");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        let original = locked_package(&root, "universe", "alpha");
        let archive = root
            .join("objects/crates")
            .join(format!("{}.crate", original.crate_sha256));
        let row = root
            .join("objects/rows")
            .join(format!("{}.json", original.source_row_sha256));

        write_catalog(&root, "[mirror]\nalpha = []\n", "", "");
        let summary = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        assert_eq!(summary.packages_removed, 1);
        assert!(summary.changed);
        let removed = locked_package(&root, "universe", "alpha");
        assert_eq!(removed.state, PackageState::Removed);
        let mut retained = removed.clone();
        retained.state = PackageState::Active;
        assert_eq!(retained, original);
        assert!(!archive.exists());
        assert!(row.is_file());
        let catalog = Catalog::load(&root).unwrap();
        ArtifactMap::load(&catalog).unwrap();
        assert!(
            DownloadCatalog::load_from_root(&root)
                .unwrap()
                .routes
                .is_empty()
        );
        assert_rendered_yanked(&temporary, &catalog, "universe", "alpha");

        let removed_snapshot = snapshot(temporary.path());
        assert_eq!(
            reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap(),
            ReconcileSummary::default()
        );
        assert_eq!(snapshot(temporary.path()), removed_snapshot);

        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let before_reactivation = snapshot(temporary.path());
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("cannot be reactivated"));
        assert_eq!(resolver.calls(), 1);
        assert_eq!(snapshot(temporary.path()), before_reactivation);

        write_catalog(&root, "", "", "");
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("retain the key in its original category with an empty version/tag list")
        );
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn immutable_registry_and_routed_row_anchors_fail_before_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-anchors");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();

        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
            "",
            "",
        );
        let core = root.join("universe.toml");
        let changed = fs::read_to_string(&core)
            .unwrap()
            .replace(UNIVERSE_URL, "sparse+https://example.invalid/universe/");
        fs::write(&core, changed).unwrap();
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("immutable registry identity"));
        assert_eq!(resolver.calls(), 1);

        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
            "",
            "",
        );
        let mut lock = load_lock(&root.join("universe.lock")).unwrap();
        lock.packages[0].index_row_sha256 = "00".repeat(32);
        fs::write(root.join("universe.lock"), serialize_lock(&lock).unwrap()).unwrap();
        let before = snapshot(temporary.path());
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("routed index-row hash mismatch"));
        assert_eq!(resolver.calls(), 1);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn changed_git_repository_fails_before_resolving_a_new_tag() {
        let temporary = TemporaryDirectory::new("pkgre-lock-git-anchor");
        let root = temporary.path().join("catalog");
        write_catalog(
            &root,
            "",
            "",
            "[publish.pkgre-alone]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [\"alone/v1.0.0\"]\n",
        );
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();

        write_catalog(
            &root,
            "",
            "",
            "[publish.pkgre-alone]\ngit = \"https://github.com/pkgre/other\"\ntags = [\"alone/v1.0.0\", \"alone/v1.1.0\"]\n",
        );
        let before = snapshot(temporary.path());
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("Git repository for locked package"));
        assert_eq!(resolver.calls(), 1);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn existing_object_corruption_and_extras_fail_before_resolution() {
        let temporary = TemporaryDirectory::new("pkgre-lock-object-preflight");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap();
        let package = locked_package(&root, "universe", "alpha");
        write_catalog(
            &root,
            "[mirror]\nalpha = [\"1.0.0\"]\nbeta = [\"1.0.0\"]\n",
            "",
            "",
        );
        fs::write(
            root.join("objects/crates")
                .join(format!("{}.crate", package.crate_sha256)),
            b"tampered",
        )
        .unwrap();
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("archive hash mismatch"));
        assert_eq!(resolver.calls(), 1);

        fs::write(
            root.join("objects/crates")
                .join(format!("{}.crate", package.crate_sha256)),
            fake_archive("alpha", &Version::parse("1.0.0").unwrap()),
        )
        .unwrap();
        let extra = sha256_bytes(b"extra");
        fs::write(
            root.join("objects/crates").join(format!("{extra}.crate")),
            b"extra",
        )
        .unwrap();
        let error = reconcile_with(&root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("differs from generated locks"));
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn resolver_and_dependency_policy_failures_leave_the_tree_unchanged() {
        let failing = TemporaryDirectory::new("pkgre-lock-resolver-failure");
        let failing_root = failing.path().join("catalog");
        write_catalog(&failing_root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::failing();
        let before = snapshot(failing.path());
        let error = reconcile_with(&failing_root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("synthetic resolver failure"));
        assert_eq!(snapshot(failing.path()), before);

        let invalid = TemporaryDirectory::new("pkgre-lock-policy-failure");
        let invalid_root = invalid.path().join("catalog");
        write_catalog(
            &invalid_root,
            "[mirror]\ncore-invalid = [\"1.0.0\"]\n",
            "[mirror]\nmatrix-middle = [\"1.0.0\"]\n",
            "",
        );
        let resolver = FakeResolver::default();
        let before = snapshot(invalid.path());
        let error = reconcile_with(&invalid_root, &resolver, &FilesystemRenamer).unwrap_err();
        assert!(format!("{error:#}").contains("may not depend"));
        assert_eq!(resolver.calls(), 1);
        assert_eq!(snapshot(invalid.path()), before);
    }

    #[test]
    fn catalog_transaction_installs_only_a_valid_complete_private_copy() {
        let temporary = TemporaryDirectory::new("pkgre-catalog-transaction-success");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        reconcile_with(&root, &FakeResolver::default(), &FilesystemRenamer).unwrap();
        let expected = crate::update::catalog_fingerprint(&root).unwrap();

        let returned = transact_catalog(&root, &expected, |staged| {
            fs::OpenOptions::new()
                .append(true)
                .open(staged.join("universe.toml"))
                .unwrap()
                .write_all(b"\n# catalog transaction marker\n")
                .unwrap();
            Ok(42)
        })
        .unwrap();

        assert_eq!(returned, 42);
        Catalog::load(&root).unwrap();
    }

    #[test]
    fn catalog_transaction_failure_and_fingerprint_drift_leave_live_tree_unchanged() {
        let temporary = TemporaryDirectory::new("pkgre-catalog-transaction-failure");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        reconcile_with(&root, &FakeResolver::default(), &FilesystemRenamer).unwrap();
        let expected = crate::update::catalog_fingerprint(&root).unwrap();
        let before = snapshot(temporary.path());

        let error = transact_catalog(&root, &expected, |staged| -> Result<()> {
            fs::OpenOptions::new()
                .append(true)
                .open(staged.join("universe.toml"))
                .unwrap()
                .write_all(b"\n# failed transaction marker\n")
                .unwrap();
            bail!("synthetic private mutation failure")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("synthetic private mutation failure"));
        assert_eq!(snapshot(temporary.path()), before);

        let error = transact_catalog(&root, &"00".repeat(32), |_| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("catalog fingerprint differs"));
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn catalog_transaction_rejects_a_concurrent_guard() {
        let temporary = TemporaryDirectory::new("pkgre-catalog-transaction-guard");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        reconcile_with(&root, &FakeResolver::default(), &FilesystemRenamer).unwrap();
        let expected = crate::update::catalog_fingerprint(&root).unwrap();
        let canonical = canonical_catalog_root(&root).unwrap();
        let _guard = CatalogGuard::acquire(&canonical).unwrap();
        let before = snapshot(temporary.path());

        let error = transact_catalog(&root, &expected, |_| Ok(())).unwrap_err();

        assert!(format!("{error:#}").contains("another reconciliation may be running"));
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn failed_catalog_transaction_install_restores_the_exact_original() {
        let temporary = TemporaryDirectory::new("pkgre-catalog-transaction-install-failure");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        reconcile_with(&root, &FakeResolver::default(), &FilesystemRenamer).unwrap();
        let expected = crate::update::catalog_fingerprint(&root).unwrap();
        let before = snapshot(temporary.path());
        let renamer = FailSecondRename::default();

        let error = transact_catalog_with(
            &root,
            &expected,
            |staged| {
                fs::OpenOptions::new()
                    .append(true)
                    .open(staged.join("universe.toml"))
                    .unwrap()
                    .write_all(b"\n# failed install marker\n")
                    .unwrap();
                Ok(())
            },
            &renamer,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("original catalog was restored"));
        assert_eq!(renamer.calls.get(), 3);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn failed_staging_install_restores_the_exact_original_catalog() {
        let temporary = TemporaryDirectory::new("pkgre-lock-install-failure");
        let root = temporary.path().join("catalog");
        write_catalog(&root, "[mirror]\nalpha = [\"1.0.0\"]\n", "", "");
        let resolver = FakeResolver::default();
        let renamer = FailSecondRename::default();
        let before = snapshot(temporary.path());

        let error = reconcile_with(&root, &resolver, &renamer).unwrap_err();
        assert!(format!("{error:#}").contains("original catalog was restored"));
        assert_eq!(renamer.calls.get(), 3);
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[derive(Default)]
    struct FakeResolver {
        calls: Cell<usize>,
        fail: bool,
    }

    impl FakeResolver {
        fn failing() -> Self {
            Self {
                calls: Cell::new(0),
                fail: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }

        fn begin_resolution(&self) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                bail!("synthetic resolver failure");
            }
            Ok(())
        }
    }

    impl Resolver for FakeResolver {
        fn resolve_mirror(&self, name: &str, version: &Version) -> Result<ResolvedPackage> {
            self.begin_resolution()?;
            Ok(fake_resolved(
                name,
                version.clone(),
                LockedSource::CratesIo {},
            ))
        }

        fn resolve_git_tag(
            &self,
            repository: &str,
            tag: &str,
            package_name: &str,
            cargo_version: &Version,
        ) -> Result<ResolvedPackage> {
            self.begin_resolution()?;
            let component = tag
                .rsplit('/')
                .next()
                .context("test tag has no component")?;
            let version = Version::parse(component.strip_prefix('v').unwrap_or(component))?;
            Ok(fake_resolved(
                package_name,
                version,
                LockedSource::GitTag {
                    git: repository.to_owned(),
                    tag: tag.to_owned(),
                    tag_oid: "11".repeat(20),
                    commit: "22".repeat(20),
                    package: package_name.to_owned(),
                    path: PathBuf::from("."),
                    cargo_version: cargo_version.clone(),
                },
            ))
        }
    }

    fn fake_admission_map(
        entries: &[(&str, &str, &str, &str)],
    ) -> BTreeMap<Identity, MirrorAdmission> {
        entries
            .iter()
            .map(|(registry, category, name, version)| {
                let version = Version::parse(version).unwrap();
                let resolved = fake_resolved(name, version.clone(), LockedSource::CratesIo {});
                let admission = MirrorAdmission {
                    registry: (*registry).to_owned(),
                    category: CategoryId::new(*registry, *category).unwrap(),
                    name: (*name).to_owned(),
                    version: version.clone(),
                    crate_sha256: sha256_bytes(&resolved.archive_bytes),
                    source_row_sha256: sha256_bytes(&resolved.source_row_bytes),
                    binding_sha256: "ab".repeat(32),
                };
                (package_identity(name, &version), admission)
            })
            .collect()
    }

    fn fake_resolved(name: &str, version: Version, source: LockedSource) -> ResolvedPackage {
        let archive_bytes = fake_archive(name, &version);
        let checksum = sha256_bytes(&archive_bytes);
        let dependencies = fake_dependencies(name)
            .iter()
            .map(|dependency| {
                json!({
                    "name": dependency,
                    "req": "^1",
                    "features": [],
                    "optional": false,
                    "default_features": true,
                    "target": Value::Null,
                    "kind": "normal",
                    "registry": "sparse+https://untrusted.invalid/",
                    "package": Value::Null,
                })
            })
            .collect::<Vec<_>>();
        let mut source_row_bytes = serde_json::to_vec(&json!({
            "name": name,
            "vers": version.to_string(),
            "deps": dependencies,
            "cksum": checksum,
            "features": {},
            "yanked": true,
        }))
        .unwrap();
        source_row_bytes.push(b'\n');
        ResolvedPackage {
            name: name.to_owned(),
            version,
            archive_bytes,
            source_row_bytes,
            source,
        }
    }

    fn fake_archive(name: &str, version: &Version) -> Vec<u8> {
        format!("synthetic crate archive for {name} {version}\n").into_bytes()
    }

    fn fake_dependencies(name: &str) -> &'static [&'static str] {
        match name {
            "matrix-middle" | "pkgre-tool" => &["leaf-core"],
            "core-invalid" => &["matrix-middle"],
            _ => &[],
        }
    }

    fn assert_download_catalog_regenerated(
        root: &Path,
        resolver: &FakeResolver,
        replacement: Option<Vec<u8>>,
        expected: &[u8],
    ) {
        if let Some(bytes) = replacement {
            fs::write(root.join(DOWNLOAD_CATALOG_FILE), bytes).unwrap();
        }
        assert!(Catalog::load(root).is_err());
        assert!(
            reconcile_with(root, resolver, &FilesystemRenamer)
                .unwrap()
                .changed
        );
        assert_eq!(
            fs::read(root.join(DOWNLOAD_CATALOG_FILE)).unwrap(),
            expected
        );
    }

    fn write_catalog(root: &Path, general: &str, matrix: &str, pkgre: &str) {
        fs::create_dir_all(root).unwrap();
        let mut universe_categories = String::new();
        universe_categories.push_str(&mirror_category(
            "general",
            &["universe/general"],
            general,
            "reserved-general",
        ));
        universe_categories.push_str(&mirror_category(
            "matrix",
            &["universe/matrix", "universe/general"],
            matrix,
            "reserved-matrix",
        ));
        for (local, dependencies) in [
            ("acp", &["universe/acp", "universe/general"] as &[_]),
            (
                "filesystem",
                &["universe/filesystem", "universe/general"] as &[_],
            ),
            (
                "mcp",
                &["universe/mcp", "universe/sse", "universe/general"] as &[_],
            ),
            ("sse", &["universe/sse", "universe/general"] as &[_]),
            (
                "terminal",
                &["universe/terminal", "universe/general"] as &[_],
            ),
            ("yaml", &["universe/yaml", "universe/general"] as &[_]),
        ] {
            universe_categories.push_str(&mirror_category(
                local,
                dependencies,
                "",
                &format!("reserved-{local}"),
            ));
        }
        write_registry(root, "universe", MIRROR_DOWNLOAD, &universe_categories);

        let tooling = if pkgre.trim().is_empty() {
            "[categories.tooling.publish.pkgre-category-anchor]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = []\n"
                .to_owned()
        } else {
            scope_declarations("tooling", pkgre)
        };
        let pkgre_categories = format!(
            "[categories.tooling]\nmay-depend-on = [\"pkgre/tooling\", \"universe/general\"]\n\n{tooling}"
        );
        write_registry(root, "pkgre", PUBLISH_DOWNLOAD, &pkgre_categories);
    }

    fn mirror_category(
        local: &str,
        dependencies: &[&str],
        declarations: &str,
        fallback_name: &str,
    ) -> String {
        let dependencies = dependencies
            .iter()
            .map(|category| format!("\"{category}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let declarations = if declarations.trim().is_empty() {
            format!("[categories.{local}.mirror]\n{fallback_name} = []\n")
        } else {
            scope_declarations(local, declarations)
        };
        format!("[categories.{local}]\nmay-depend-on = [{dependencies}]\n\n{declarations}\n")
    }

    fn scope_declarations(local: &str, declarations: &str) -> String {
        declarations
            .replace("[mirror]", &format!("[categories.{local}.mirror]"))
            .replace("[publish.", &format!("[categories.{local}.publish."))
    }

    fn write_registry(root: &Path, name: &str, download: &str, categories: &str) {
        fs::write(
            root.join(format!("{name}.toml")),
            format!(
                "schema = 3\n\n[registry]\nname = {name:?}\nindex = \"sparse+https://rust.pkg.re/{name}/\"\ndownload = {download:?}\ncargo-version = \"1.95.0\"\n\n{categories}"
            ),
        )
        .unwrap();
    }

    fn locked_package(root: &Path, registry: &str, name: &str) -> LockedPackage {
        load_lock(&root.join(format!("{registry}.lock")))
            .unwrap()
            .packages
            .into_iter()
            .find(|package| package.name == name)
            .unwrap()
    }

    fn assert_routed_registry(
        temporary: &TemporaryDirectory,
        catalog: &Catalog,
        registry: &str,
        name: &str,
        expected: Option<&str>,
    ) {
        let artifacts = ArtifactMap::load(catalog).unwrap();
        let site = temporary.path().join(format!("site-{registry}-{name}"));
        crate::render::render(catalog, &artifacts, &site).unwrap();
        let row: Value =
            serde_json::from_slice(&fs::read(site.join(registry).join(index_path(name))).unwrap())
                .unwrap();
        assert_eq!(row["deps"][0]["registry"].as_str(), expected);
    }

    fn assert_rendered_yanked(
        temporary: &TemporaryDirectory,
        catalog: &Catalog,
        registry: &str,
        name: &str,
    ) {
        let artifacts = ArtifactMap::load(catalog).unwrap();
        let site = temporary.path().join("removed-site");
        crate::render::render(catalog, &artifacts, &site).unwrap();
        let row: Value =
            serde_json::from_slice(&fs::read(site.join(registry).join(index_path(name))).unwrap())
                .unwrap();
        assert_eq!(row["yanked"], true);
    }

    #[derive(Default)]
    struct FailSecondRename {
        calls: Cell<usize>,
    }

    impl Renamer for FailSecondRename {
        fn rename(&self, source: &Path, destination: &Path) -> io::Result<()> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == 2 {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic install failure",
                ))
            } else {
                fs::rename(source, destination)
            }
        }
    }

    type Snapshot = BTreeMap<PathBuf, Option<Vec<u8>>>;

    fn snapshot(root: &Path) -> Snapshot {
        let mut snapshot = BTreeMap::new();
        snapshot_below(root, root, &mut snapshot);
        snapshot
    }

    fn snapshot_below(base: &Path, root: &Path, snapshot: &mut Snapshot) {
        let mut entries = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let relative = path.strip_prefix(base).unwrap().to_path_buf();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.file_type().is_dir() {
                snapshot.insert(relative, None);
                snapshot_below(base, &path, snapshot);
            } else {
                assert!(metadata.file_type().is_file());
                snapshot.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
    }

    struct TemporaryDirectory {
        path: PathBuf,
    }

    impl TemporaryDirectory {
        fn new(prefix: &str) -> Self {
            let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()));
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove stale test directory: {error}"),
            }
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
