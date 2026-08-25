//! Exact non-destructive schema-3 to schema-4 single-main-registry migration.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;

use super::v3;
use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::category::CategoryId;
use crate::download::{DOWNLOAD_CATALOG_FILE, DownloadCatalog, router_download_template};
use crate::index::IndexRecord;
use crate::policy::{canonical_registry_index, validate_catalog};
use crate::render;
use crate::schema::{
    self, Catalog, LockedName, LockedPackage, LockedRegistry, LockedSource, PackageHome,
    PackageKey, PackageState, RegistryLock, Source,
};
use crate::update::{MigratedAdmissionInventory, migrate_admission_inventory};

const MAIN_REGISTRY: &str = "main";

/// Counts immutable anchors and routing changes in one completed schema-3 to schema-4 migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Schema4MigrationSummary {
    /// Permanent package-name anchors migrated exactly once.
    pub names: usize,
    /// Locked package identities migrated exactly once.
    pub packages: usize,
    /// Routed active-row hashes changed by the registry merge.
    pub routed_rows_changed: usize,
    /// Immutable admission batches rewritten and rebound.
    pub admission_batches: usize,
}

#[derive(Clone, Debug)]
struct TargetCategory {
    may_depend_on: Vec<CategoryId>,
    mirror: BTreeMap<String, Vec<Version>>,
    publish: BTreeMap<String, TargetPublish>,
    external: bool,
}

#[derive(Clone, Debug)]
struct TargetPublish {
    git: String,
    tags: Vec<String>,
}

struct MigrationOutput {
    categories: BTreeMap<CategoryId, TargetCategory>,
    lock: RegistryLock,
    admissions: MigratedAdmissionInventory,
    summary: Schema4MigrationSummary,
}

/// Migrates one strict canonical schema-3 catalog into a new schema-4 `main` catalog.
///
/// The source is authenticated but never modified. `universe/<category>` becomes
/// `main/<category>`, `pkgre/tooling` becomes `main/pkgre`, and every immutable package and
/// source object is retained while routed row hashes and admission bindings are recomputed.
/// The complete staged catalog is strictly loaded, policy-checked, rendered, and reproduced
/// before one final rename installs it.
///
/// # Errors
///
/// Returns an error for an existing destination, noncanonical or corrupt schema-3 input,
/// unmappable identity, category-policy violation, invalid admission binding, invalid staged
/// output, or I/O error.
pub fn migrate_v3_to_v4(source: &Path, destination: &Path) -> Result<Schema4MigrationSummary> {
    let source = super::canonical_source_root(source)?;
    let destination = super::canonical_absent_destination(destination, &source)?;

    let old_catalog = v3::Catalog::load(&source).context("strictly load schema-3 catalog")?;
    let old_policy =
        super::v3_policy::validate_catalog(&old_catalog).context("validate schema-3 policy")?;
    let compatibility = compatibility_catalog(&old_catalog);
    ArtifactMap::load(&compatibility).context("verify schema-3 object store")?;
    crate::update::validate_admission_inventory(&compatibility)
        .context("verify schema-3 admission inventory")?;
    DownloadCatalog::load_from_root(&source)?
        .validate_against_catalog(&compatibility)
        .context("verify schema-3 download catalog")?;
    let historical_homes = compatibility_homes(&old_catalog);
    verify_source_rows(&old_catalog, &historical_homes, &old_policy)?;

    let inputs = v3::load_registry_inputs(&source).context("reload schema-3 human inputs")?;
    let output = build_output(&old_catalog, &inputs)?;

    let mut staging = super::TemporaryDirectory::new_sibling(&destination, "catalog-v4")?;
    write_output(staging.path(), &source, &output)?;
    validate_staged_output(staging.path(), &destination)?;
    crate::artifact::require_absent(&destination)?;
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

pub(super) fn compatibility_catalog(catalog: &v3::Catalog) -> Catalog {
    let mirror_names = catalog
        .name_sources
        .iter()
        .filter(|(_, source)| **source == v3::NameSource::Mirror)
        .map(|(name, _)| {
            let home = catalog
                .homes
                .homes
                .get(name)
                .expect("validated schema-3 source declaration has a home");
            PackageKey::new(&home.registry, name)
        })
        .collect();
    let publish_names = catalog
        .name_sources
        .iter()
        .filter(|(_, source)| **source == v3::NameSource::Publish)
        .map(|(name, _)| {
            let home = catalog
                .homes
                .homes
                .get(name)
                .expect("validated schema-3 source declaration has a home");
            PackageKey::new(&home.registry, name)
        })
        .collect();
    Catalog {
        root: catalog.root.clone(),
        registries: schema::RegistriesFile {
            schema: v3::SCHEMA_VERSION,
            cname: catalog.registries.cname.clone(),
            cargo_version: catalog.registries.cargo_version.clone(),
            registries: catalog
                .registries
                .registries
                .iter()
                .map(|registry| schema::Registry {
                    name: registry.name.clone(),
                    index: registry.index.clone(),
                    download: registry.download.clone(),
                    cargo_version: registry.cargo_version.clone(),
                })
                .collect(),
        },
        categories: catalog.categories.clone(),
        homes: schema::HomesFile {
            schema: v3::SCHEMA_VERSION,
            homes: catalog
                .homes
                .homes
                .iter()
                .map(|(name, home)| {
                    (
                        PackageKey::new(&home.registry, name),
                        PackageHome {
                            registry: home.registry.clone(),
                            category: home.category.clone(),
                        },
                    )
                })
                .collect(),
        },
        mirror_names,
        publish_names,
        approvals: catalog
            .approvals
            .iter()
            .map(|approval| schema::Approval {
                registry: approval.registry.clone(),
                category: approval.category.clone(),
                name: approval.name.clone(),
                version: approval.version.clone(),
                archive_sha256: approval.archive_sha256.clone(),
                index_record_sha256: approval.index_record_sha256.clone(),
                index_row_sha256: approval.index_row_sha256.clone(),
                admission_sha256: approval.admission_sha256.clone(),
                state: migrate_state(approval.state),
                source: migrate_source(&approval.source),
                declared_in: approval.declared_in.clone(),
            })
            .collect(),
    }
}

fn compatibility_homes(catalog: &v3::Catalog) -> BTreeMap<String, PackageHome> {
    catalog
        .homes
        .homes
        .iter()
        .map(|(name, home)| {
            (
                name.clone(),
                PackageHome {
                    registry: home.registry.clone(),
                    category: home.category.clone(),
                },
            )
        })
        .collect()
}

pub(super) fn compatibility_policy(policy: &super::v3_policy::Policy) -> crate::policy::Policy {
    crate::policy::Policy {
        registry_urls: policy.registry_urls.clone(),
        category_dependencies: policy.category_dependencies.clone(),
    }
}

fn verify_source_rows(
    catalog: &v3::Catalog,
    homes: &BTreeMap<String, PackageHome>,
    policy: &super::v3_policy::Policy,
) -> Result<()> {
    for approval in &catalog.approvals {
        let path = catalog
            .root
            .join("objects/rows")
            .join(format!("{}.json", approval.index_record_sha256));
        let bytes = super::read_regular(&path)?;
        let mut record = IndexRecord::parse(&bytes).with_context(|| {
            format!(
                "parse schema-3 source row for {} {}",
                approval.name, approval.version
            )
        })?;
        record.set_yanked(false);
        let routed = record.route_dependencies(&approval.registry, homes, &policy.registry_urls)?;
        for (dependency, home) in routed {
            ensure!(
                policy.permits_dependency(&approval.category, &home.category),
                "schema-3 package {} {} in {} may not depend on {dependency} in {}",
                approval.name,
                approval.version,
                approval.category,
                home.category
            );
        }
        let actual = sha256_bytes(&record.to_json_line()?);
        ensure!(
            actual == approval.index_row_sha256,
            "schema-3 routed-row hash mismatch for {} {}: expected {}, got {actual}",
            approval.name,
            approval.version,
            approval.index_row_sha256
        );
    }
    Ok(())
}

fn build_output(catalog: &v3::Catalog, inputs: &[v3::RegistryInput]) -> Result<MigrationOutput> {
    validate_input_set(inputs)?;
    let categories = migrate_categories(inputs)?;
    let homes = migrate_homes(catalog)?;
    validate_category_population(&categories, &homes)?;
    let admissions = migrate_admission_inventory(&catalog.root, migrate_category)?;
    let (lock, routed_rows_changed) =
        migrate_lock(catalog, inputs, &homes, &categories, &admissions)?;
    let admission_batches = admissions.files.len() / 2;
    Ok(MigrationOutput {
        categories,
        lock,
        admissions,
        summary: Schema4MigrationSummary {
            names: catalog.homes.homes.len(),
            packages: catalog.approvals.len(),
            routed_rows_changed,
            admission_batches,
        },
    })
}

fn validate_input_set(inputs: &[v3::RegistryInput]) -> Result<()> {
    let actual = inputs
        .iter()
        .map(|input| input.file.registry.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        inputs.len() == 2 && actual == BTreeSet::from(["pkgre", "universe"]),
        "schema-3 migration requires exactly one each of pkgre and universe inputs"
    );
    Ok(())
}

fn migrate_categories(
    inputs: &[v3::RegistryInput],
) -> Result<BTreeMap<CategoryId, TargetCategory>> {
    let mut categories = BTreeMap::new();
    for input in inputs {
        for category in input.file.category_values() {
            let id = migrate_category(&category.id)?;
            let mut may_depend_on = category
                .may_depend_on
                .iter()
                .map(migrate_category)
                .collect::<Result<Vec<_>>>()?;
            may_depend_on.sort();
            ensure!(
                may_depend_on
                    .windows(2)
                    .all(|window| window[0] != window[1]),
                "mapped category {id} repeats a may-depend-on target"
            );
            let target = TargetCategory {
                may_depend_on,
                mirror: category.mirror.clone(),
                publish: category
                    .publish
                    .iter()
                    .map(|(name, publication)| {
                        (
                            name.clone(),
                            TargetPublish {
                                git: publication.git.clone(),
                                tags: publication.tags.clone(),
                            },
                        )
                    })
                    .collect(),
                external: category.declared_in != input.path,
            };
            ensure!(
                categories.insert(id.clone(), target).is_none(),
                "more than one schema-3 category maps to {id}"
            );
        }
    }
    Ok(categories)
}

fn migrate_homes(catalog: &v3::Catalog) -> Result<BTreeMap<String, PackageHome>> {
    catalog
        .homes
        .homes
        .iter()
        .map(|(name, home)| {
            Ok((
                name.clone(),
                PackageHome {
                    registry: MAIN_REGISTRY.to_owned(),
                    category: migrate_category(&home.category)?,
                },
            ))
        })
        .collect()
}

fn validate_category_population(
    categories: &BTreeMap<CategoryId, TargetCategory>,
    homes: &BTreeMap<String, PackageHome>,
) -> Result<()> {
    let declared = categories
        .values()
        .flat_map(|category| category.mirror.keys().chain(category.publish.keys()))
        .collect::<BTreeSet<_>>();
    ensure!(
        declared.len() == homes.len()
            && homes.keys().all(|name| declared.contains(name))
            && categories
                .keys()
                .all(|category| homes.values().any(|home| &home.category == category)),
        "schema-3 declarations, homes, or inhabited categories did not map exactly once"
    );
    Ok(())
}

type HistoricalPackageIdentity = (String, (u64, u64, u64, String));

struct LockMigrationContext<'a> {
    catalog: &'a v3::Catalog,
    homes: &'a BTreeMap<String, PackageHome>,
    allowed: BTreeMap<CategoryId, BTreeSet<CategoryId>>,
    registry_urls: BTreeMap<String, String>,
    admissions: &'a MigratedAdmissionInventory,
}

fn migrate_lock(
    catalog: &v3::Catalog,
    inputs: &[v3::RegistryInput],
    homes: &BTreeMap<String, PackageHome>,
    categories: &BTreeMap<CategoryId, TargetCategory>,
    admissions: &MigratedAdmissionInventory,
) -> Result<(RegistryLock, usize)> {
    let mut lock = RegistryLock {
        schema: schema::SCHEMA_VERSION,
        registry: LockedRegistry {
            name: MAIN_REGISTRY.to_owned(),
            index: canonical_registry_index(MAIN_REGISTRY),
            download: router_download_template(MAIN_REGISTRY),
        },
        names: Vec::new(),
        packages: Vec::new(),
    };
    let context = LockMigrationContext {
        catalog,
        homes,
        allowed: categories
            .iter()
            .map(|(category, declaration)| {
                (
                    category.clone(),
                    declaration
                        .may_depend_on
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect(),
        registry_urls: BTreeMap::from([(
            MAIN_REGISTRY.to_owned(),
            canonical_registry_index(MAIN_REGISTRY),
        )]),
        admissions,
    };
    let mut old_names = BTreeSet::new();
    let mut old_packages = BTreeSet::new();
    let mut changed = 0;

    for input in inputs {
        let old_lock = input
            .lock
            .as_ref()
            .with_context(|| format!("schema-3 lock is missing: {}", input.lock_path.display()))?;
        migrate_locked_names(old_lock, homes, &mut old_names, &mut lock.names)?;
        changed +=
            migrate_locked_packages(old_lock, &context, &mut old_packages, &mut lock.packages)?;
    }
    ensure!(
        old_names.len() == catalog.homes.homes.len(),
        "schema-3 permanent names did not migrate exactly once"
    );
    ensure!(
        old_packages.len() == catalog.approvals.len(),
        "schema-3 locked packages did not migrate exactly once"
    );
    Ok((lock, changed))
}

fn migrate_locked_names(
    old_lock: &v3::RegistryLock,
    homes: &BTreeMap<String, PackageHome>,
    seen: &mut BTreeSet<String>,
    target: &mut Vec<LockedName>,
) -> Result<()> {
    for name in &old_lock.names {
        ensure!(
            seen.insert(name.name.clone()),
            "schema-3 package name {:?} is locked more than once",
            name.name
        );
        let old_category = CategoryId::new(&old_lock.registry.name, &name.category)?;
        let category = migrate_category(&old_category)?;
        let home = homes
            .get(&name.name)
            .with_context(|| format!("locked name {:?} has no mapped home", name.name))?;
        ensure!(
            home.category == category,
            "locked name {:?} maps to a different category than its schema-3 home",
            name.name
        );
        target.push(LockedName {
            name: name.name.clone(),
            category: category.local().to_owned(),
        });
    }
    Ok(())
}

fn migrate_locked_packages(
    old_lock: &v3::RegistryLock,
    context: &LockMigrationContext<'_>,
    seen: &mut BTreeSet<HistoricalPackageIdentity>,
    target: &mut Vec<LockedPackage>,
) -> Result<usize> {
    let mut changed = 0;
    for package in &old_lock.packages {
        let identity = (
            package.name.to_ascii_lowercase().replace('-', "_"),
            v3::version_identity(&package.version),
        );
        ensure!(
            seen.insert(identity),
            "schema-3 package identity {} {} is locked more than once",
            package.name,
            package.version
        );
        let (migrated, row_changed) = migrate_locked_package(package, context)?;
        changed += usize::from(row_changed);
        target.push(migrated);
    }
    Ok(changed)
}

fn migrate_locked_package(
    package: &v3::LockedPackage,
    context: &LockMigrationContext<'_>,
) -> Result<(LockedPackage, bool)> {
    let home = context
        .homes
        .get(&package.name)
        .with_context(|| format!("locked package {:?} has no mapped home", package.name))?;
    let row_path = context
        .catalog
        .root
        .join("objects/rows")
        .join(format!("{}.json", package.source_row_sha256));
    let mut record = IndexRecord::parse(&super::read_regular(&row_path)?)?;
    record.set_yanked(false);
    let dependencies =
        record.route_dependencies(MAIN_REGISTRY, context.homes, &context.registry_urls)?;
    for (dependency, dependency_home) in dependencies {
        ensure!(
            context
                .allowed
                .get(&home.category)
                .is_some_and(|targets| targets.contains(&dependency_home.category)),
            "schema-4 category {} for {} {} may not depend on {dependency} in {}",
            home.category,
            package.name,
            package.version,
            dependency_home.category
        );
    }
    let index_row_sha256 = sha256_bytes(&record.to_json_line()?);
    let row_changed = index_row_sha256 != package.index_row_sha256;
    let admission_sha256 = package
        .admission_sha256
        .as_ref()
        .map(|old| {
            context
                .admissions
                .bindings
                .get(old)
                .cloned()
                .with_context(|| {
                    format!(
                        "admission binding for {} {} has no migrated batch",
                        package.name, package.version
                    )
                })
        })
        .transpose()?;
    Ok((
        LockedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            state: migrate_state(package.state),
            crate_sha256: package.crate_sha256.clone(),
            source_row_sha256: package.source_row_sha256.clone(),
            index_row_sha256,
            admission_sha256,
            source: migrate_locked_source(&package.source),
        },
        row_changed,
    ))
}

fn migrate_category(category: &CategoryId) -> Result<CategoryId> {
    match (category.registry(), category.local()) {
        ("pkgre", "tooling") => CategoryId::new(MAIN_REGISTRY, "pkgre"),
        ("universe", local) => CategoryId::new(MAIN_REGISTRY, local),
        _ => anyhow::bail!("unexpected schema-3 category {category}"),
    }
}

fn migrate_state(state: v3::PackageState) -> PackageState {
    match state {
        v3::PackageState::Active => PackageState::Active,
        v3::PackageState::Removed => PackageState::Removed,
    }
}

fn migrate_source(source: &v3::Source) -> Source {
    match source {
        v3::Source::CratesIo => Source::CratesIo,
        v3::Source::GitTag {
            repository,
            tag,
            tag_oid,
            commit,
            package,
            subdir,
            cargo_version,
        } => Source::GitTag {
            repository: repository.clone(),
            tag: tag.clone(),
            tag_oid: tag_oid.clone(),
            commit: commit.clone(),
            package: package.clone(),
            subdir: subdir.clone(),
            cargo_version: cargo_version.clone(),
        },
    }
}

fn migrate_locked_source(source: &v3::LockedSource) -> LockedSource {
    match source {
        v3::LockedSource::CratesIo {} => LockedSource::CratesIo {},
        v3::LockedSource::GitTag {
            git,
            tag,
            tag_oid,
            commit,
            package,
            path,
            cargo_version,
        } => LockedSource::GitTag {
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
    super::write_new(
        &root.join("main.toml"),
        main_file(&output.categories)?.as_bytes(),
    )?;
    for (id, category) in &output.categories {
        if category.external {
            super::write_new(
                &root
                    .join("categories")
                    .join(MAIN_REGISTRY)
                    .join(format!("{}.toml", id.local())),
                external_category(category)?.as_bytes(),
            )?;
        }
    }
    super::write_new(
        &root.join("main.lock"),
        &schema::serialize_lock(&output.lock)?,
    )?;
    for (relative, bytes) in &output.admissions.files {
        super::write_new(&root.join(relative), bytes)?;
    }

    fs::create_dir_all(root.join("objects/crates"))
        .with_context(|| format!("create staged archive directory below {}", root.display()))?;
    fs::create_dir_all(root.join("objects/rows"))
        .with_context(|| format!("create staged row directory below {}", root.display()))?;
    let row_hashes = output
        .lock
        .packages
        .iter()
        .map(|package| package.source_row_sha256.clone())
        .collect::<BTreeSet<_>>();
    for hash in row_hashes {
        super::copy_new(
            &source.join("objects/rows").join(format!("{hash}.json")),
            &root.join("objects/rows").join(format!("{hash}.json")),
        )?;
    }
    let archive_hashes = output
        .lock
        .packages
        .iter()
        .filter(|package| {
            package.state == PackageState::Active
                && matches!(package.source, LockedSource::GitTag { .. })
        })
        .map(|package| package.crate_sha256.clone())
        .collect::<BTreeSet<_>>();
    for hash in archive_hashes {
        super::copy_new(
            &source.join("objects/crates").join(format!("{hash}.crate")),
            &root.join("objects/crates").join(format!("{hash}.crate")),
        )?;
    }

    let inputs = schema::load_registry_inputs(root)?;
    let catalog = schema::catalog_from_inputs(root, &inputs)?;
    let downloads = DownloadCatalog::from_catalog(&catalog).canonical_bytes()?;
    super::write_new(&root.join(DOWNLOAD_CATALOG_FILE), &downloads)?;
    Ok(())
}

fn main_file(categories: &BTreeMap<CategoryId, TargetCategory>) -> Result<String> {
    let mut text = format!(
        "schema = {}\n\n[registry]\nname = \"main\"\nindex = {}\ndownload = {}\ncargo-version = {}\n\n",
        schema::SCHEMA_VERSION,
        quote(&canonical_registry_index(MAIN_REGISTRY))?,
        quote(&router_download_template(MAIN_REGISTRY))?,
        quote(super::v3_policy::CARGO_VERSION)?,
    );
    for (id, category) in categories {
        ensure!(
            id.registry() == MAIN_REGISTRY,
            "target category {id} is outside main"
        );
        if category.external {
            writeln!(text, "[categories.{}]", id.local())?;
            writeln!(text, "file = \"categories/main/{}.toml\"\n", id.local())?;
        } else {
            write_inline_category(&mut text, id.local(), category)?;
        }
    }
    Ok(text)
}

fn write_inline_category(text: &mut String, local: &str, category: &TargetCategory) -> Result<()> {
    writeln!(text, "[categories.{local}]")?;
    write_category_body(text, category, &format!("categories.{local}"))
}

fn external_category(category: &TargetCategory) -> Result<String> {
    let mut text = format!("schema = {}\n", schema::SCHEMA_VERSION);
    write_category_body(&mut text, category, "")?;
    Ok(text)
}

fn write_category_body(text: &mut String, category: &TargetCategory, prefix: &str) -> Result<()> {
    ensure!(
        !category.mirror.is_empty() || !category.publish.is_empty(),
        "target category has no package names"
    );
    writeln!(
        text,
        "may-depend-on = [{}]\n",
        quoted_categories(&category.may_depend_on)?
    )?;
    let section = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}.{name}")
        }
    };
    if !category.mirror.is_empty() {
        writeln!(text, "[{}]", section("mirror"))?;
        write_mirror_entries(text, &category.mirror)?;
    }
    for (name, publication) in &category.publish {
        writeln!(text, "[{}.{}]", section("publish"), name)?;
        writeln!(text, "git = {}", quote(&publication.git)?)?;
        writeln!(text, "tags = [{}]\n", quoted(&publication.tags)?)?;
    }
    Ok(())
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
    let catalog = Catalog::load(root).context("strictly load staged schema-4 catalog")?;
    validate_catalog(&catalog).context("validate staged schema-4 policy")?;
    let artifacts = ArtifactMap::load(&catalog).context("verify staged schema-4 objects")?;
    let mut temporary = super::TemporaryDirectory::new_sibling(destination, "site-v4")?;
    let site = temporary.path().join("site");
    render::render(&catalog, &artifacts, &site).context("test-render staged schema-4 catalog")?;
    render::verify(&catalog, &artifacts, &site).context("reproduce staged schema-4 test render")?;
    temporary.remove()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_mapping_is_exact() {
        assert_eq!(
            migrate_category(&"universe/general".parse().unwrap()).unwrap(),
            "main/general".parse().unwrap()
        );
        assert_eq!(
            migrate_category(&"pkgre/tooling".parse().unwrap()).unwrap(),
            "main/pkgre".parse().unwrap()
        );
        assert!(migrate_category(&"pkgre/other".parse().unwrap()).is_err());
    }

    #[test]
    fn serializer_allows_mirror_and_publish_in_one_category() {
        let category = TargetCategory {
            may_depend_on: vec!["main/general".parse().unwrap()],
            mirror: BTreeMap::from([("mixed".to_owned(), vec![Version::parse("1.0.0").unwrap()])]),
            publish: BTreeMap::from([(
                "mixed".to_owned(),
                TargetPublish {
                    git: "https://github.com/pkgre/mixed".to_owned(),
                    tags: vec!["v1.0.1".to_owned()],
                },
            )]),
            external: false,
        };
        let text = main_file(&BTreeMap::from([(
            "main/general".parse().unwrap(),
            category,
        )]))
        .unwrap();
        assert!(text.contains("[categories.general.mirror]"));
        assert!(text.contains("[categories.general.publish.mixed]"));
    }
}
