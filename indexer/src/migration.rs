//! Exact non-destructive schema-2 to schema-3 catalog migration.

mod v2;
mod v2_policy;
mod v3;
mod v3_policy;
mod v3_to_v4;

pub use v3_to_v4::{Schema4MigrationSummary, migrate_v3_to_v4};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;

use crate::artifact::{ArtifactMap, require_absent, sha256_bytes, sha256_file};
use crate::category::{CategoryId, category_for_v2_home};
use crate::download::{DOWNLOAD_CATALOG_FILE, DownloadCatalog};
use crate::index::IndexRecord;
use crate::policy::validate_sha256;
use crate::schema::PackageHome;

const UNIVERSE_INDEX: &str = "sparse+https://rust.pkg.re/universe/";
const PKGRE_INDEX: &str = "sparse+https://rust.pkg.re/pkgre/";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Counts immutable anchors and routing changes in one completed migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationSummary {
    /// Permanent package-name anchors migrated exactly once.
    pub names: usize,
    /// Locked package identities migrated exactly once.
    pub packages: usize,
    /// Routed active-row hashes changed by the registry merge or rename.
    pub routed_rows_changed: usize,
}

#[derive(Clone, Debug)]
struct TargetCategory {
    may_depend_on: Vec<CategoryId>,
    mirror: BTreeMap<String, Vec<Version>>,
    publish: BTreeMap<String, TargetPublish>,
}

#[derive(Clone, Debug)]
struct TargetPublish {
    git: String,
    tags: Vec<String>,
}

struct MigrationOutput {
    categories: BTreeMap<CategoryId, TargetCategory>,
    locks: BTreeMap<String, v3::RegistryLock>,
    summary: MigrationSummary,
}

/// Migrates one strict canonical schema-2 catalog into a new schema-3 catalog.
///
/// The source is read and authenticated but never modified. The destination and temporary sibling
/// paths must be absent. A complete staged catalog is strictly loaded, policy-checked, rendered,
/// and reproduced before one final rename installs it.
///
/// # Errors
///
/// Returns an error for an existing destination, noncanonical schema-2 input, object or row
/// corruption, unmappable identity, category-policy violation, invalid staged output, or I/O error.
pub fn migrate_v2_to_v3(source: &Path, destination: &Path) -> Result<MigrationSummary> {
    let source = canonical_source_root(source)?;
    let destination = canonical_absent_destination(destination, &source)?;

    let old_catalog = v2::Catalog::load(&source).context("strictly load schema-2 catalog")?;
    let old_policy =
        v2_policy::validate_catalog(&old_catalog).context("validate schema-2 catalog policy")?;
    verify_v2_objects_and_rows(&old_catalog, &old_policy)?;
    let inputs = v2::load_registry_inputs(&source).context("reload schema-2 human inputs")?;
    let output = build_output(&old_catalog, &inputs)?;

    let mut staging = TemporaryDirectory::new_sibling(&destination, "catalog")?;
    write_output(staging.path(), &source, &output)?;
    validate_staged_output(staging.path(), &destination)?;
    require_absent(&destination)?;
    fs::rename(staging.path(), &destination).with_context(|| {
        format!(
            "atomically install migrated catalog {} at {}",
            staging.path().display(),
            destination.display()
        )
    })?;
    staging.keep();
    Ok(output.summary)
}

fn canonical_source_root(source: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect schema-2 catalog root {}", source.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "schema-2 catalog root is not a real directory: {}",
        source.display()
    );
    fs::canonicalize(source)
        .with_context(|| format!("canonicalize schema-2 catalog root {}", source.display()))
}

fn canonical_absent_destination(destination: &Path, source: &Path) -> Result<PathBuf> {
    require_absent(destination)?;
    let name = destination.file_name().with_context(|| {
        format!(
            "destination has no final component: {}",
            destination.display()
        )
    })?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect destination parent {}", parent.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "destination parent is not a real directory: {}",
        parent.display()
    );
    let parent = fs::canonicalize(parent)
        .with_context(|| format!("canonicalize destination parent {}", parent.display()))?;
    ensure!(
        !parent.starts_with(source),
        "destination must not be inside schema-2 source catalog {}",
        source.display()
    );
    let destination = parent.join(name);
    require_absent(&destination)?;
    Ok(destination)
}

fn verify_v2_objects_and_rows(catalog: &v2::Catalog, policy: &v2_policy::Policy) -> Result<()> {
    let homes = catalog
        .homes
        .homes
        .iter()
        .map(|(name, registry)| {
            Ok((
                name.clone(),
                PackageHome {
                    registry: registry.clone(),
                    category: category_for_v2_home(registry, name)?,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let expected_rows = catalog
        .approvals
        .iter()
        .map(|approval| approval.index_record_sha256.clone())
        .collect::<BTreeSet<_>>();
    let expected_archives = catalog
        .approvals
        .iter()
        .filter(|approval| {
            !approval.is_removed() && matches!(approval.source, v2::Source::GitTag { .. })
        })
        .map(|approval| approval.archive_sha256.clone())
        .collect::<BTreeSet<_>>();
    verify_object_inventory(&catalog.root.join("objects/rows"), "json", &expected_rows)?;
    verify_object_inventory(
        &catalog.root.join("objects/crates"),
        "crate",
        &expected_archives,
    )?;

    for approval in &catalog.approvals {
        let path = catalog
            .root
            .join("objects/rows")
            .join(format!("{}.json", approval.index_record_sha256));
        let bytes = read_regular(&path)?;
        ensure!(
            sha256_bytes(&bytes) == approval.index_record_sha256,
            "schema-2 source-row hash mismatch for {} {}",
            approval.name,
            approval.version
        );
        let mut record = IndexRecord::parse(&bytes).with_context(|| {
            format!(
                "parse schema-2 source row for {} {}",
                approval.name, approval.version
            )
        })?;
        record.validate_structure()?;
        ensure!(
            record.name()? == approval.name && record.version()? == approval.version,
            "schema-2 source-row identity mismatch for {} {}",
            approval.name,
            approval.version
        );
        ensure!(
            record.checksum()? == approval.archive_sha256,
            "schema-2 source-row checksum mismatch for {} {}",
            approval.name,
            approval.version
        );
        record.set_yanked(false);
        let routed =
            record.route_dependencies(&approval.registry, &homes, &policy.registry_urls)?;
        for (dependency, home) in routed {
            ensure!(
                policy.permits_dependency(&approval.registry, &home.registry),
                "schema-2 package {} {} in {} may not depend on {dependency} in {}",
                approval.name,
                approval.version,
                approval.registry,
                home.registry
            );
        }
        let actual = sha256_bytes(&record.to_json_line()?);
        ensure!(
            actual == approval.index_row_sha256,
            "schema-2 routed-row hash mismatch for {} {}: expected {}, got {actual}",
            approval.name,
            approval.version,
            approval.index_row_sha256
        );

        if !approval.is_removed() && matches!(approval.source, v2::Source::GitTag { .. }) {
            let archive = catalog
                .root
                .join("objects/crates")
                .join(format!("{}.crate", approval.archive_sha256));
            ensure!(
                sha256_file(&archive)? == approval.archive_sha256,
                "schema-2 archive hash mismatch for {} {}",
                approval.name,
                approval.version
            );
        }
    }
    Ok(())
}

fn verify_object_inventory(root: &Path, suffix: &str, expected: &BTreeSet<String>) -> Result<()> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect schema-2 object directory {}", root.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "schema-2 object path is not a real directory: {}",
        root.display()
    );
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry.with_context(|| format!("read entry below {}", root.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect schema-2 object {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "schema-2 object is not a regular file: {}",
            path.display()
        );
        let filename = entry.file_name();
        let filename = filename
            .to_str()
            .with_context(|| format!("object filename is not valid UTF-8: {}", path.display()))?;
        let hash = filename
            .strip_suffix(&format!(".{suffix}"))
            .with_context(|| format!("object has unexpected suffix: {}", path.display()))?;
        validate_sha256(hash)
            .with_context(|| format!("invalid object filename {}", path.display()))?;
        actual.insert(hash.to_owned());
    }
    ensure!(
        actual == *expected,
        "schema-2 object set below {} differs from locks; missing={:?}, extra={:?}",
        root.display(),
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(expected).collect::<Vec<_>>()
    );
    Ok(())
}

fn build_output(catalog: &v2::Catalog, inputs: &[v2::RegistryInput]) -> Result<MigrationOutput> {
    let mut categories = empty_target_categories();
    let homes = migrate_homes(catalog)?;
    validate_v2_input_set(inputs)?;
    populate_target_categories(&mut categories, inputs)?;
    validate_category_population(&categories, &homes)?;
    let (locks, summary) = migrate_locks(catalog, inputs, &homes)?;
    Ok(MigrationOutput {
        categories,
        locks,
        summary,
    })
}

fn empty_target_categories() -> BTreeMap<CategoryId, TargetCategory> {
    v3_policy::canonical_category_dependencies()
        .into_iter()
        .map(|(id, dependencies)| {
            (
                id,
                TargetCategory {
                    may_depend_on: dependencies.into_iter().collect(),
                    mirror: BTreeMap::new(),
                    publish: BTreeMap::new(),
                },
            )
        })
        .collect()
}

fn migrate_homes(catalog: &v2::Catalog) -> Result<BTreeMap<String, PackageHome>> {
    let mut homes = BTreeMap::new();
    for (name, old_registry) in &catalog.homes.homes {
        let category = category_for_v2_home(old_registry, name)?;
        ensure!(
            homes
                .insert(
                    name.clone(),
                    PackageHome {
                        registry: category.registry().to_owned(),
                        category,
                    }
                )
                .is_none(),
            "schema-2 package {name:?} maps more than once"
        );
    }
    Ok(homes)
}

fn validate_v2_input_set(inputs: &[v2::RegistryInput]) -> Result<()> {
    let actual = inputs
        .iter()
        .map(|input| input.file.registry.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from(["core", "matrix", "pkgre"]);
    ensure!(
        inputs.len() == expected.len() && actual == expected,
        "schema-2 migration requires exactly one each of core, matrix, and pkgre inputs"
    );
    Ok(())
}

fn populate_target_categories(
    categories: &mut BTreeMap<CategoryId, TargetCategory>,
    inputs: &[v2::RegistryInput],
) -> Result<()> {
    for input in inputs {
        for (name, versions) in &input.file.mirror {
            let category = category_for_v2_home(&input.file.registry.name, name)?;
            let target = categories
                .get_mut(&category)
                .with_context(|| format!("no target category for {name:?}"))?;
            ensure!(
                target
                    .mirror
                    .insert(name.clone(), versions.clone())
                    .is_none(),
                "mirrored package {name:?} maps more than once"
            );
        }
        for (name, declaration) in &input.file.publish {
            let category = category_for_v2_home(&input.file.registry.name, name)?;
            let target = categories
                .get_mut(&category)
                .with_context(|| format!("no target category for {name:?}"))?;
            ensure!(
                target
                    .publish
                    .insert(
                        name.clone(),
                        TargetPublish {
                            git: declaration.git.clone(),
                            tags: declaration.tags.clone(),
                        }
                    )
                    .is_none(),
                "published package {name:?} maps more than once"
            );
        }
    }
    Ok(())
}

fn validate_category_population(
    categories: &BTreeMap<CategoryId, TargetCategory>,
    homes: &BTreeMap<String, PackageHome>,
) -> Result<()> {
    let desired_names = categories
        .values()
        .map(|category| category.mirror.len() + category.publish.len())
        .sum::<usize>();
    ensure!(
        desired_names == homes.len(),
        "schema-2 desired names do not map exactly once: desired={desired_names}, homes={}",
        homes.len()
    );
    ensure!(
        categories
            .values()
            .all(|category| !category.mirror.is_empty() || !category.publish.is_empty()),
        "schema-2 catalog cannot populate every canonical schema-3 category"
    );
    Ok(())
}

fn migrate_locks(
    catalog: &v2::Catalog,
    inputs: &[v2::RegistryInput],
    homes: &BTreeMap<String, PackageHome>,
) -> Result<(BTreeMap<String, v3::RegistryLock>, MigrationSummary)> {
    let registry_urls = BTreeMap::from([
        ("pkgre".to_owned(), PKGRE_INDEX.to_owned()),
        ("universe".to_owned(), UNIVERSE_INDEX.to_owned()),
    ]);
    let allowed = v3_policy::canonical_category_dependencies();
    let mut locks = empty_target_locks();
    let mut names = 0;
    let mut packages = 0;
    let mut routed_rows_changed = 0;
    for input in inputs {
        let old_lock = input
            .lock
            .as_ref()
            .with_context(|| format!("schema-2 lock is missing: {}", input.lock_path.display()))?;
        names += migrate_lock_names(old_lock, homes, &mut locks)?;
        let (migrated, changed) = migrate_lock_packages(
            catalog,
            old_lock,
            homes,
            &registry_urls,
            &allowed,
            &mut locks,
        )?;
        packages += migrated;
        routed_rows_changed += changed;
    }
    validate_migrated_lock_counts(catalog, homes, &locks, names, packages)?;
    Ok((
        locks,
        MigrationSummary {
            names,
            packages,
            routed_rows_changed,
        },
    ))
}

fn empty_target_locks() -> BTreeMap<String, v3::RegistryLock> {
    BTreeMap::from([
        (
            "pkgre".to_owned(),
            v3::RegistryLock {
                schema: v3::SCHEMA_VERSION,
                registry: v3::LockedRegistry {
                    name: "pkgre".to_owned(),
                    index: PKGRE_INDEX.to_owned(),
                    download: v3::PUBLISH_DOWNLOAD.to_owned(),
                },
                names: Vec::new(),
                packages: Vec::new(),
            },
        ),
        (
            "universe".to_owned(),
            v3::RegistryLock {
                schema: v3::SCHEMA_VERSION,
                registry: v3::LockedRegistry {
                    name: "universe".to_owned(),
                    index: UNIVERSE_INDEX.to_owned(),
                    download: v3::MIRROR_DOWNLOAD.to_owned(),
                },
                names: Vec::new(),
                packages: Vec::new(),
            },
        ),
    ])
}

fn migrate_lock_names(
    old_lock: &v2::RegistryLock,
    homes: &BTreeMap<String, PackageHome>,
    locks: &mut BTreeMap<String, v3::RegistryLock>,
) -> Result<usize> {
    for name in &old_lock.names {
        let home = homes
            .get(&name.name)
            .with_context(|| format!("locked name {:?} has no mapped home", name.name))?;
        let target = locks
            .get_mut(&home.registry)
            .with_context(|| format!("mapped registry {:?} has no target lock", home.registry))?;
        target.names.push(v3::LockedName {
            name: name.name.clone(),
            category: home.category.local().to_owned(),
            source: migrate_name_source(name.source),
        });
    }
    Ok(old_lock.names.len())
}

fn migrate_lock_packages(
    catalog: &v2::Catalog,
    old_lock: &v2::RegistryLock,
    homes: &BTreeMap<String, PackageHome>,
    registry_urls: &BTreeMap<String, String>,
    allowed: &BTreeMap<CategoryId, BTreeSet<CategoryId>>,
    locks: &mut BTreeMap<String, v3::RegistryLock>,
) -> Result<(usize, usize)> {
    let mut changed = 0;
    for package in &old_lock.packages {
        let home = homes
            .get(&package.name)
            .with_context(|| format!("locked package {:?} has no mapped home", package.name))?;
        let row_path = catalog
            .root
            .join("objects/rows")
            .join(format!("{}.json", package.source_row_sha256));
        let mut record = IndexRecord::parse(&read_regular(&row_path)?)?;
        record.set_yanked(false);
        let dependencies = record.route_dependencies(&home.registry, homes, registry_urls)?;
        for (dependency, dependency_home) in dependencies {
            ensure!(
                allowed
                    .get(&home.category)
                    .is_some_and(|targets| targets.contains(&dependency_home.category)),
                "schema-3 category {} for {} {} may not depend on {dependency} in {}",
                home.category,
                package.name,
                package.version,
                dependency_home.category
            );
        }
        let index_row_sha256 = sha256_bytes(&record.to_json_line()?);
        changed += usize::from(index_row_sha256 != package.index_row_sha256);
        let target = locks
            .get_mut(&home.registry)
            .with_context(|| format!("mapped registry {:?} has no target lock", home.registry))?;
        target.packages.push(v3::LockedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            state: migrate_package_state(package.state),
            crate_sha256: package.crate_sha256.clone(),
            source_row_sha256: package.source_row_sha256.clone(),
            index_row_sha256,
            admission_sha256: None,
            source: migrate_locked_source(&package.source),
        });
    }
    Ok((old_lock.packages.len(), changed))
}

fn validate_migrated_lock_counts(
    catalog: &v2::Catalog,
    homes: &BTreeMap<String, PackageHome>,
    locks: &BTreeMap<String, v3::RegistryLock>,
    names: usize,
    packages: usize,
) -> Result<()> {
    ensure!(
        names == homes.len(),
        "schema-2 permanent names did not migrate exactly once"
    );
    ensure!(
        packages == catalog.approvals.len(),
        "schema-2 locked packages did not migrate exactly once"
    );
    ensure!(
        locks.values().map(|lock| lock.names.len()).sum::<usize>() == homes.len(),
        "schema-3 name count differs after migration"
    );
    ensure!(
        locks
            .values()
            .map(|lock| lock.packages.len())
            .sum::<usize>()
            == catalog.approvals.len(),
        "schema-3 package count differs after migration"
    );
    Ok(())
}

fn migrate_name_source(source: v2::NameSource) -> v3::NameSource {
    match source {
        v2::NameSource::Mirror => v3::NameSource::Mirror,
        v2::NameSource::Publish => v3::NameSource::Publish,
    }
}

fn migrate_package_state(state: v2::PackageState) -> v3::PackageState {
    match state {
        v2::PackageState::Active => v3::PackageState::Active,
        v2::PackageState::Removed => v3::PackageState::Removed,
    }
}

fn migrate_locked_source(source: &v2::LockedSource) -> v3::LockedSource {
    match source {
        v2::LockedSource::CratesIo {} => v3::LockedSource::CratesIo {},
        v2::LockedSource::GitTag {
            git,
            tag,
            tag_oid,
            commit,
            package,
            path,
            cargo_version,
        } => v3::LockedSource::GitTag {
            git: git.clone(),
            tag: tag.clone(),
            tag_oid: tag_oid.clone(),
            commit: commit.clone(),
            package: package.clone(),
            path: path.clone(),
            cargo_version: cargo_version.clone(),
        },
    }
}

fn write_output(root: &Path, source: &Path, output: &MigrationOutput) -> Result<()> {
    write_new(
        &root.join("universe.toml"),
        universe_file(&output.categories)?.as_bytes(),
    )?;
    write_new(
        &root.join("pkgre.toml"),
        pkgre_file(&output.categories)?.as_bytes(),
    )?;
    let general: CategoryId = "universe/general".parse()?;
    let matrix: CategoryId = "universe/matrix".parse()?;
    write_new(
        &root.join("categories/universe/general.toml"),
        external_category(
            output
                .categories
                .get(&general)
                .expect("canonical general category exists"),
        )?
        .as_bytes(),
    )?;
    write_new(
        &root.join("categories/universe/matrix.toml"),
        external_category(
            output
                .categories
                .get(&matrix)
                .expect("canonical matrix category exists"),
        )?
        .as_bytes(),
    )?;
    for (registry, lock) in &output.locks {
        write_new(
            &root.join(format!("{registry}.lock")),
            &v3::serialize_lock(lock)?,
        )?;
    }

    fs::create_dir_all(root.join("objects/crates"))
        .with_context(|| format!("create staged archive directory below {}", root.display()))?;
    fs::create_dir_all(root.join("objects/rows"))
        .with_context(|| format!("create staged row directory below {}", root.display()))?;
    let row_hashes = output
        .locks
        .values()
        .flat_map(|lock| {
            lock.packages
                .iter()
                .map(|package| package.source_row_sha256.clone())
        })
        .collect::<BTreeSet<_>>();
    for hash in row_hashes {
        copy_new(
            &source.join("objects/rows").join(format!("{hash}.json")),
            &root.join("objects/rows").join(format!("{hash}.json")),
        )?;
    }
    let archive_hashes = output
        .locks
        .values()
        .flat_map(|lock| &lock.packages)
        .filter(|package| {
            package.state == v3::PackageState::Active
                && matches!(package.source, v3::LockedSource::GitTag { .. })
        })
        .map(|package| package.crate_sha256.clone())
        .collect::<BTreeSet<_>>();
    for hash in archive_hashes {
        copy_new(
            &source.join("objects/crates").join(format!("{hash}.crate")),
            &root.join("objects/crates").join(format!("{hash}.crate")),
        )?;
    }
    let inputs = v3::load_registry_inputs(root)?;
    let catalog = v3::catalog_from_inputs(root, &inputs)?;
    let compatibility = v3_to_v4::compatibility_catalog(&catalog);
    let downloads = DownloadCatalog::from_catalog(&compatibility).canonical_bytes()?;
    write_new(&root.join(DOWNLOAD_CATALOG_FILE), &downloads)?;
    Ok(())
}

fn universe_file(categories: &BTreeMap<CategoryId, TargetCategory>) -> Result<String> {
    let mut text = String::from(
        "schema = 3\n\n[registry]\nname = \"universe\"\nindex = \"sparse+https://rust.pkg.re/universe/\"\ndownload = \"https://static.crates.io/crates\"\ncargo-version = \"1.95.0\"\n\n",
    );
    for local in [
        "acp",
        "filesystem",
        "general",
        "matrix",
        "mcp",
        "sse",
        "terminal",
        "yaml",
    ] {
        let id = CategoryId::new("universe", local)?;
        let category = categories
            .get(&id)
            .with_context(|| format!("missing target category {id}"))?;
        if matches!(local, "general" | "matrix") {
            writeln!(text, "[categories.{local}]")?;
            writeln!(text, "file = \"categories/universe/{local}.toml\"\n")?;
        } else {
            write_inline_category(&mut text, local, category)?;
        }
    }
    Ok(text)
}

fn pkgre_file(categories: &BTreeMap<CategoryId, TargetCategory>) -> Result<String> {
    let id: CategoryId = "pkgre/tooling".parse()?;
    let category = categories
        .get(&id)
        .context("missing target category pkgre/tooling")?;
    let mut text = String::from(
        "schema = 3\n\n[registry]\nname = \"pkgre\"\nindex = \"sparse+https://rust.pkg.re/pkgre/\"\ndownload = \"https://rust.pkg.re/crates/{sha256-checksum}.crate\"\ncargo-version = \"1.95.0\"\n\n",
    );
    write_inline_category(&mut text, "tooling", category)?;
    Ok(text)
}

fn write_inline_category(text: &mut String, local: &str, category: &TargetCategory) -> Result<()> {
    writeln!(text, "[categories.{local}]")?;
    writeln!(
        text,
        "may-depend-on = [{}]\n",
        quoted_categories(&category.may_depend_on)?
    )?;
    if category.mirror.is_empty() {
        ensure!(
            !category.publish.is_empty(),
            "category {local} has no package names"
        );
        for (name, publication) in &category.publish {
            writeln!(text, "[categories.{local}.publish.{name}]")?;
            writeln!(text, "git = {}", quote(&publication.git)?)?;
            writeln!(text, "tags = [{}]\n", quoted(&publication.tags)?)?;
        }
    } else {
        ensure!(
            category.publish.is_empty(),
            "category {local} mixes mirror and publish declarations"
        );
        writeln!(text, "[categories.{local}.mirror]")?;
        write_mirror_entries(text, &category.mirror)?;
    }
    Ok(())
}

fn external_category(category: &TargetCategory) -> Result<String> {
    ensure!(
        category.publish.is_empty() && !category.mirror.is_empty(),
        "external migration categories must be nonempty mirrors"
    );
    let mut text = String::from("schema = 3\n");
    writeln!(
        text,
        "may-depend-on = [{}]\n\n[mirror]",
        quoted_categories(&category.may_depend_on)?
    )?;
    write_mirror_entries(&mut text, &category.mirror)?;
    Ok(text)
}

fn write_mirror_entries(
    text: &mut String,
    packages: &BTreeMap<String, Vec<Version>>,
) -> Result<()> {
    for (name, versions) in packages {
        let versions = versions.iter().map(ToString::to_string).collect::<Vec<_>>();
        writeln!(text, "{name} = [{}]", quoted(&versions)?)?;
    }
    text.push('\n');
    Ok(())
}

fn quoted_categories(values: &[CategoryId]) -> Result<String> {
    quoted(&values.iter().map(ToString::to_string).collect::<Vec<_>>())
}

fn quoted(values: &[String]) -> Result<String> {
    values
        .iter()
        .map(|value| quote(value))
        .collect::<Result<Vec<_>>>()
        .map(|values| values.join(", "))
}

fn quote(value: &str) -> Result<String> {
    serde_json::to_string(value).context("quote TOML string")
}

fn validate_staged_output(root: &Path, destination: &Path) -> Result<()> {
    let catalog = v3::Catalog::load(root).context("strictly load staged schema-3 catalog")?;
    let historical_policy =
        v3_policy::validate_catalog(&catalog).context("validate staged schema-3 policy")?;
    let compatibility = v3_to_v4::compatibility_catalog(&catalog);
    let policy = v3_to_v4::compatibility_policy(&historical_policy);
    let artifacts = ArtifactMap::load(&compatibility).context("verify staged schema-3 objects")?;
    DownloadCatalog::load_from_root(root)?
        .validate_against_catalog(&compatibility)
        .context("verify staged schema-3 download catalog")?;
    let mut temporary = TemporaryDirectory::new_sibling(destination, "site")?;
    let site = temporary.path().join("site");
    crate::render::render_with_policy(&compatibility, &artifacts, &policy, &site)
        .context("test-render staged catalog")?;
    crate::render::verify_with_policy(&compatibility, &artifacts, &policy, &site)
        .context("reproduce staged test render")?;
    temporary.remove()?;
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect regular file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "input is not a regular file: {}",
        path.display()
    );
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }
    require_absent(path)?;
    fs::write(path, contents).with_context(|| format!("write new file {}", path.display()))
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let contents = read_regular(source)?;
    write_new(destination, &contents)
}

struct TemporaryDirectory {
    path: PathBuf,
    retained: bool,
}

impl TemporaryDirectory {
    fn new_sibling(destination: &Path, purpose: &str) -> Result<Self> {
        let parent = destination
            .parent()
            .expect("canonical destination has a parent");
        for _ in 0..100 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".pkgre-migrate-{purpose}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        retained: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create temporary directory {}", path.display()));
                }
            }
        }
        bail!(
            "could not allocate a temporary sibling below {}",
            parent.display()
        )
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn keep(&mut self) {
        self.retained = true;
    }

    fn remove(&mut self) -> Result<()> {
        fs::remove_dir_all(&self.path)
            .with_context(|| format!("remove temporary directory {}", self.path.display()))?;
        self.retained = true;
        Ok(())
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if !self.retained {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};

    use super::*;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn exact_migration_preserves_source_objects_and_validates_output() {
        let temporary = TestDirectory::new("pkgre-v2-v3-migration");
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        let fixture = write_fixture(&source, "pkgre-indexer", None);
        let source_before = snapshot(&source);

        let summary = migrate_v2_to_v3(&source, &destination).unwrap();

        assert_eq!(
            summary,
            MigrationSummary {
                names: 9,
                packages: 9,
                routed_rows_changed: 1,
            }
        );
        assert_eq!(snapshot(&source), source_before);
        assert_eq!(
            snapshot(&source.join("objects/rows")),
            snapshot(&destination.join("objects/rows"))
        );
        assert_eq!(
            fs::read(
                destination
                    .join("objects/crates")
                    .join(format!("{}.crate", fixture.git_archive_hash))
            )
            .unwrap(),
            fixture.git_archive
        );
        assert!(
            destination
                .join("categories/universe/general.toml")
                .is_file()
        );
        assert!(
            destination
                .join("categories/universe/matrix.toml")
                .is_file()
        );

        let catalog = v3::Catalog::load(&destination).unwrap();
        let historical_policy = v3_policy::validate_catalog(&catalog).unwrap();
        let compatibility = v3_to_v4::compatibility_catalog(&catalog);
        let policy = v3_to_v4::compatibility_policy(&historical_policy);
        let artifacts = ArtifactMap::load(&compatibility).unwrap();
        let site = temporary.path().join("site");
        crate::render::render_with_policy(&compatibility, &artifacts, &policy, &site).unwrap();
        crate::render::verify_with_policy(&compatibility, &artifacts, &policy, &site).unwrap();
        let pkgre_row = fs::read(
            site.join("pkgre")
                .join(crate::index::index_path("pkgre-indexer")),
        )
        .unwrap();
        let row: Value = serde_json::from_slice(&pkgre_row).unwrap();
        assert_eq!(
            row["deps"][0]["registry"],
            Value::String(UNIVERSE_INDEX.to_owned())
        );
    }

    #[test]
    fn schema_three_to_four_migration_is_exact_and_rewrites_admissions() {
        let temporary = TestDirectory::new("pkgre-v3-v4-migration");
        let schema_two = temporary.path().join("schema-two");
        let schema_three = temporary.path().join("schema-three");
        let schema_four = temporary.path().join("schema-four");
        let fixture = write_fixture(&schema_two, "pkgre-indexer", None);
        migrate_v2_to_v3(&schema_two, &schema_three).unwrap();
        let old_binding = bind_schema_three_admission(&schema_three);
        let source_before = snapshot(&schema_three);

        let old_catalog = v3::Catalog::load(&schema_three).unwrap();
        let historical_policy = v3_policy::validate_catalog(&old_catalog).unwrap();
        let compatibility = v3_to_v4::compatibility_catalog(&old_catalog);
        let policy = v3_to_v4::compatibility_policy(&historical_policy);
        let artifacts = ArtifactMap::load(&compatibility).unwrap();
        let old_site = temporary.path().join("schema-three-site");
        crate::render::render_with_policy(&compatibility, &artifacts, &policy, &old_site).unwrap();

        let summary = migrate_v3_to_v4(&schema_three, &schema_four).unwrap();

        assert_eq!(
            summary,
            Schema4MigrationSummary {
                names: 9,
                packages: 9,
                routed_rows_changed: 1,
                admission_batches: 1,
            }
        );
        assert_eq!(snapshot(&schema_three), source_before);
        assert!(!schema_four.join("universe.toml").exists());
        assert!(!schema_four.join("pkgre.toml").exists());
        assert!(schema_four.join("main.toml").is_file());
        assert!(schema_four.join("main.lock").is_file());
        assert!(schema_four.join("categories/main/general.toml").is_file());
        assert!(schema_four.join("categories/main/matrix.toml").is_file());
        assert_eq!(
            snapshot(&schema_three.join("objects/rows")),
            snapshot(&schema_four.join("objects/rows"))
        );
        assert_eq!(
            fs::read(
                schema_four
                    .join("objects/crates")
                    .join(format!("{}.crate", fixture.git_archive_hash))
            )
            .unwrap(),
            fixture.git_archive
        );

        let catalog = crate::schema::Catalog::load(&schema_four).unwrap();
        crate::policy::validate_catalog(&catalog).unwrap();
        let artifacts = ArtifactMap::load(&catalog).unwrap();
        let migrated = catalog
            .approvals
            .iter()
            .find(|approval| approval.name == "serde")
            .unwrap();
        let new_binding = migrated.admission_sha256.as_ref().unwrap();
        assert_ne!(new_binding, &old_binding);
        let manifest = crate::update::load_admission_manifest(
            &schema_four.join("admissions/2025-02-01-serde.toml"),
        )
        .unwrap();
        assert_eq!(
            manifest.entries[0].category,
            CategoryId::new("main", "general").unwrap()
        );
        let admission_lock: Value = toml::from_slice(
            &fs::read(schema_four.join("admissions/2025-02-01-serde.lock")).unwrap(),
        )
        .unwrap();
        assert_eq!(admission_lock["plan"]["candidates"][0]["registry"], "main");
        assert_eq!(
            admission_lock["plan"]["candidates"][0]["category"],
            "main/general"
        );

        let new_site = temporary.path().join("schema-four-site");
        crate::render::render(&catalog, &artifacts, &new_site).unwrap();
        crate::render::verify_monotonic(&old_site, &new_site).unwrap();
        assert!(new_site.join("config.json").is_file());
        assert!(!new_site.join("main").exists());
        let row: Value = serde_json::from_slice(
            &fs::read(new_site.join(crate::index::index_path("pkgre-indexer"))).unwrap(),
        )
        .unwrap();
        assert_eq!(row["deps"][0]["registry"], Value::Null);
    }

    fn bind_schema_three_admission(root: &Path) -> String {
        use crate::update::{
            ADMISSION_MANIFEST_SCHEMA, ArchiveSummary, DecisionReason, DependencyDelta,
            PlannedIdentity, SourceEvidence, UPDATE_PLAN_SCHEMA, UpdateCandidate, UpdateDecision,
            UpdatePlan, UtcTimestamp,
        };

        let lock_path = root.join("universe.lock");
        let mut lock = v3::load_lock(&lock_path).unwrap();
        let package = lock
            .packages
            .iter_mut()
            .find(|package| {
                package.name == "serde" && package.version == Version::parse("1.0.0").unwrap()
            })
            .unwrap();
        let manifest = crate::update::AdmissionManifest {
            schema: ADMISSION_MANIFEST_SCHEMA,
            entries: vec![crate::update::AdmissionRequest {
                category: CategoryId::new("universe", "general").unwrap(),
                name: package.name.clone(),
                version: Some(package.version.clone()),
                tag: None,
                evidence: Vec::new(),
            }],
        };
        let plan = UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "07".repeat(32),
            evaluated_at: UtcTimestamp::parse("2025-02-01T00:00:00Z").unwrap(),
            min_release_age_days: crate::update::MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: crate::update::DORMANT_RELEASE_GAP_DAYS,
            candidates: vec![UpdateCandidate {
                registry: "universe".to_owned(),
                category: "universe/general".to_owned(),
                name: package.name.clone(),
                activity: crate::update::PackageActivity::New,
                lane: None,
                base: None,
                candidate: PlannedIdentity {
                    version: package.version.clone(),
                    published_at: UtcTimestamp::parse("2025-01-02T00:00:00Z").unwrap(),
                    source_row_sha256: package.source_row_sha256.clone(),
                    crate_sha256: package.crate_sha256.clone(),
                },
                sparse_index_sha256: "03".repeat(32),
                decision_history_sha256: "04".repeat(32),
                age_seconds: 30 * 24 * 60 * 60,
                dormant_gap: None,
                base_archive: None,
                candidate_archive: ArchiveSummary {
                    analysis_sha256: "05".repeat(32),
                    compressed_bytes: 1,
                    unpacked_bytes: 1,
                    files: 1,
                    build_surface: BTreeMap::new(),
                    vcs_commit: None,
                    vcs_path: None,
                },
                archive_delta: None,
                dependencies: DependencyDelta {
                    added: Vec::new(),
                    removed: Vec::new(),
                    new_packages: Vec::new(),
                },
                api: None,
                source: SourceEvidence::Unavailable {
                    reason: "source-verification-error".to_owned(),
                },
                decision: UpdateDecision::ReviewRequired,
                reasons: vec![
                    DecisionReason::NewPackage,
                    DecisionReason::SourceUnavailable,
                    DecisionReason::ExplicitCandidate,
                ],
            }],
        };
        let manifest_bytes = crate::update::serialize_admission_manifest(&manifest).unwrap();
        let (lock_bytes, binding) = crate::update::prepare_admission_lock(
            &manifest,
            &plan,
            &UtcTimestamp::parse("2025-02-01T02:00:00Z").unwrap(),
        )
        .unwrap();
        crate::update::write_admission_pair(
            root,
            Path::new("2025-02-01-serde.toml"),
            &manifest_bytes,
            &lock_bytes,
        )
        .unwrap();
        package.admission_sha256 = Some(binding.clone());
        fs::write(lock_path, v3::serialize_lock(&lock).unwrap()).unwrap();
        binding
    }

    #[test]
    fn existing_destination_is_refused_without_changing_either_tree() {
        let temporary = TestDirectory::new("pkgre-v2-v3-existing");
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        write_fixture(&source, "pkgre-indexer", None);
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("marker"), b"unchanged\n").unwrap();
        let before = snapshot(temporary.path());

        let error = migrate_v2_to_v3(&source, &destination).unwrap_err();

        assert!(format!("{error:#}").contains("refusing to overwrite existing path"));
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn corrupted_source_row_is_rejected_without_writing_output() {
        let temporary = TestDirectory::new("pkgre-v2-v3-corrupt");
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        write_fixture(&source, "pkgre-indexer", None);
        let row = fs::read_dir(source.join("objects/rows"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(row, b"tampered\n").unwrap();
        let before = snapshot(temporary.path());

        let error = migrate_v2_to_v3(&source, &destination).unwrap_err();

        assert!(format!("{error:#}").contains("source-row hash mismatch"));
        assert!(!destination.exists());
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn unmappable_schema_two_name_is_rejected_without_writing_output() {
        let temporary = TestDirectory::new("pkgre-v2-v3-unmappable");
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        write_fixture(&source, "other-tool", None);
        let before = snapshot(temporary.path());

        let error = migrate_v2_to_v3(&source, &destination).unwrap_err();

        assert!(format!("{error:#}").contains("unexpected schema-2 pkgre package"));
        assert!(!destination.exists());
        assert_eq!(snapshot(temporary.path()), before);
    }

    #[test]
    fn newly_forbidden_category_dependency_is_rejected_without_writing_output() {
        let temporary = TestDirectory::new("pkgre-v2-v3-policy");
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        write_fixture(&source, "pkgre-indexer", Some("rmcp"));
        let before = snapshot(temporary.path());

        let error = migrate_v2_to_v3(&source, &destination).unwrap_err();

        assert!(format!("{error:#}").contains("may not depend"));
        assert!(!destination.exists());
        assert_eq!(snapshot(temporary.path()), before);
    }

    struct Fixture {
        git_archive_hash: String,
        git_archive: Vec<u8>,
    }

    fn write_fixture(root: &Path, tooling_name: &str, general_dependency: Option<&str>) -> Fixture {
        fs::create_dir_all(root.join("objects/crates")).unwrap();
        fs::create_dir_all(root.join("objects/rows")).unwrap();
        let packages = fixture_packages(tooling_name);
        write_v2_human_files(root, tooling_name, &packages);
        let homes = packages
            .iter()
            .map(|(registry, name)| {
                let category = category_for_v2_home(registry, name)
                    .unwrap_or_else(|_| CategoryId::new("pkgre", "tooling").unwrap());
                (
                    (*name).to_owned(),
                    PackageHome {
                        registry: (*registry).to_owned(),
                        category,
                    },
                )
            })
            .collect();
        let registry_urls = v2_policy::REGISTRIES
            .iter()
            .map(|(name, index, _)| ((*name).to_owned(), (*index).to_owned()))
            .collect();
        let mut writer = FixtureWriter {
            root,
            general_dependency,
            homes,
            registry_urls,
            locks: empty_v2_locks(),
            git_archive_hash: String::new(),
            git_archive: Vec::new(),
        };
        for (registry, name) in packages {
            writer.write_package(registry, name);
        }
        writer.finish()
    }

    fn fixture_packages(tooling_name: &str) -> [(&str, &str); 9] {
        [
            ("core", "agent-client-protocol"),
            ("core", "notify"),
            ("core", "serde"),
            ("core", "rmcp"),
            ("core", "eventsource-stream"),
            ("core", "atty"),
            ("core", "serde_yaml"),
            ("matrix", "matrix-sdk"),
            ("pkgre", tooling_name),
        ]
    }

    fn empty_v2_locks() -> BTreeMap<String, v2::RegistryLock> {
        v2_policy::REGISTRIES
            .iter()
            .map(|(registry, index, _)| {
                (
                    (*registry).to_owned(),
                    v2::RegistryLock {
                        schema: v2::SCHEMA_VERSION,
                        registry: v2::LockedRegistry {
                            name: (*registry).to_owned(),
                            index: (*index).to_owned(),
                            download: if *registry == "pkgre" {
                                v2::PUBLISH_DOWNLOAD.to_owned()
                            } else {
                                v2::MIRROR_DOWNLOAD.to_owned()
                            },
                        },
                        names: Vec::new(),
                        packages: Vec::new(),
                    },
                )
            })
            .collect()
    }

    struct FixtureWriter<'a> {
        root: &'a Path,
        general_dependency: Option<&'a str>,
        homes: BTreeMap<String, PackageHome>,
        registry_urls: BTreeMap<String, String>,
        locks: BTreeMap<String, v2::RegistryLock>,
        git_archive_hash: String,
        git_archive: Vec<u8>,
    }

    impl FixtureWriter<'_> {
        fn write_package(&mut self, registry: &str, name: &str) {
            let published = registry == "pkgre";
            let version = Version::parse("1.0.0").unwrap();
            let archive = format!("synthetic crate archive for {name} {version}\n").into_bytes();
            let crate_sha256 = sha256_bytes(&archive);
            let dependency = if name == "serde" {
                self.general_dependency
            } else if published {
                Some("serde")
            } else {
                None
            };
            let source_row = source_row(name, &version, &crate_sha256, dependency);
            let source_row_sha256 = sha256_bytes(&source_row);
            fs::write(
                self.root
                    .join("objects/rows")
                    .join(format!("{source_row_sha256}.json")),
                &source_row,
            )
            .unwrap();
            let mut routed = IndexRecord::parse(&source_row).unwrap();
            routed.set_yanked(false);
            routed
                .route_dependencies(registry, &self.homes, &self.registry_urls)
                .unwrap();
            let index_row_sha256 = sha256_bytes(&routed.to_json_line().unwrap());
            let source = if published {
                self.git_archive_hash.clone_from(&crate_sha256);
                self.git_archive.clone_from(&archive);
                fs::write(
                    self.root
                        .join("objects/crates")
                        .join(format!("{crate_sha256}.crate")),
                    &archive,
                )
                .unwrap();
                v2::LockedSource::GitTag {
                    git: "https://github.com/pkgre/pkgre".to_owned(),
                    tag: "indexer/v1.0.0".to_owned(),
                    tag_oid: "11".repeat(20),
                    commit: "22".repeat(20),
                    package: name.to_owned(),
                    path: PathBuf::from("."),
                    cargo_version: Version::parse(v2_policy::CARGO_VERSION).unwrap(),
                }
            } else {
                v2::LockedSource::CratesIo {}
            };
            let lock = self.locks.get_mut(registry).unwrap();
            lock.names.push(v2::LockedName {
                name: name.to_owned(),
                source: if published {
                    v2::NameSource::Publish
                } else {
                    v2::NameSource::Mirror
                },
            });
            lock.packages.push(v2::LockedPackage {
                name: name.to_owned(),
                version,
                state: v2::PackageState::Active,
                crate_sha256,
                source_row_sha256,
                index_row_sha256,
                source,
            });
        }

        fn finish(self) -> Fixture {
            for (registry, lock) in self.locks {
                fs::write(
                    self.root.join(format!("{registry}.lock")),
                    v2::serialize_lock(&lock).unwrap(),
                )
                .unwrap();
            }
            Fixture {
                git_archive_hash: self.git_archive_hash,
                git_archive: self.git_archive,
            }
        }
    }

    fn write_v2_human_files(root: &Path, tooling_name: &str, packages: &[(&str, &str)]) {
        for (registry, index, dependencies) in v2_policy::REGISTRIES {
            let download = if registry == "pkgre" {
                v2::PUBLISH_DOWNLOAD
            } else {
                v2::MIRROR_DOWNLOAD
            };
            let dependency_text = dependencies
                .iter()
                .map(|dependency| format!("{dependency:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            let mut text = format!(
                "schema = 2\n\n[registry]\nname = {registry:?}\nindex = {index:?}\ndownload = {download:?}\nmay-depend-on = [{dependency_text}]\ncargo-version = {:?}\n\n",
                v2_policy::CARGO_VERSION
            );
            if registry == "pkgre" {
                writeln!(text, "[publish.{tooling_name}]").unwrap();
                writeln!(text, "git = {:?}", "https://github.com/pkgre/pkgre").unwrap();
                writeln!(text, "tags = [\"indexer/v1.0.0\"]").unwrap();
            } else {
                text.push_str("[mirror]\n");
                for (_, name) in packages
                    .iter()
                    .filter(|(package_registry, _)| *package_registry == registry)
                {
                    writeln!(text, "{name} = [\"1.0.0\"]").unwrap();
                }
            }
            fs::write(root.join(format!("{registry}.toml")), text).unwrap();
        }
    }

    fn source_row(
        name: &str,
        version: &Version,
        checksum: &str,
        dependency: Option<&str>,
    ) -> Vec<u8> {
        let dependencies = dependency
            .into_iter()
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
        let mut bytes = serde_json::to_vec(&json!({
            "name": name,
            "vers": version.to_string(),
            "deps": dependencies,
            "cksum": checksum,
            "features": {},
            "yanked": true,
        }))
        .unwrap();
        bytes.push(b'\n');
        bytes
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

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
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

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
