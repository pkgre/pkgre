//! Deterministic sparse-registry site rendering and verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactMap, require_absent, sha256_bytes};
use crate::category::{CategoryId, category_for_v2_home};
use crate::index::{IndexRecord, index_path};
use crate::policy::{
    CARGO_VERSION, REGISTRIES, canonical_category_dependencies, validate_catalog,
    validate_package_name, validate_sha256,
};
use crate::schema::{
    Approval, Catalog, MIRROR_DOWNLOAD, NameSource, PUBLISH_DOWNLOAD, RELEASE_SCHEMA_VERSION,
    Source,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Name of the deterministic release manifest within a rendered site.
pub const RELEASE_MANIFEST: &str = "release.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Release {
    schema: u32,
    cname: String,
    registries: Vec<ReleaseRegistry>,
    names: Vec<ReleaseName>,
    packages: Vec<ReleasePackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRegistry {
    name: String,
    index: String,
    download: String,
    categories: Vec<ReleaseCategory>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseCategory {
    id: CategoryId,
    #[serde(rename = "may-depend-on")]
    may_depend_on: Vec<CategoryId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseName {
    name: String,
    registry: String,
    category: CategoryId,
    source: NameSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleasePackage {
    registry: String,
    category: CategoryId,
    name: String,
    version: Version,
    archive_sha256: String,
    index_record_sha256: String,
    index_row_sha256: String,
    yanked: bool,
    source: ReleaseSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ReleaseSource {
    CratesIo,
    GitTag {
        repository: String,
        tag: String,
        tag_oid: String,
        commit: String,
        package: String,
        subdir: String,
        cargo_version: Version,
    },
}

impl ReleaseSource {
    fn name_source(&self) -> NameSource {
        match self {
            Self::CratesIo => NameSource::Mirror,
            Self::GitTag { .. } => NameSource::Publish,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseV2 {
    schema: u32,
    cname: String,
    registries: Vec<ReleaseRegistryV2>,
    packages: Vec<ReleasePackageV2>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRegistryV2 {
    name: String,
    index: String,
    download: String,
    #[serde(rename = "may-depend-on")]
    may_depend_on: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRelease {
    schema: u32,
    cname: String,
    download: String,
    registries: Vec<LegacyReleaseRegistry>,
    packages: Vec<ReleasePackageV2>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyReleaseRegistry {
    name: String,
    index: String,
    #[serde(rename = "may-depend-on")]
    may_depend_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleasePackageV2 {
    registry: String,
    name: String,
    version: Version,
    archive_sha256: String,
    index_record_sha256: String,
    yanked: bool,
    source: ReleaseSourceV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ReleaseSourceV2 {
    CratesIo,
    GitTag {
        repository: String,
        tag: String,
        commit: String,
        package: String,
        subdir: String,
    },
}

impl ReleaseSourceV2 {
    fn name_source(&self) -> NameSource {
        match self {
            Self::CratesIo => NameSource::Mirror,
            Self::GitTag { .. } => NameSource::Publish,
        }
    }
}

enum LoadedRelease {
    Schema1(LegacyRelease),
    Schema2(ReleaseV2),
    Schema3(Release),
}

impl LoadedRelease {
    fn schema(&self) -> u32 {
        match self {
            Self::Schema1(release) => release.schema,
            Self::Schema2(release) => release.schema,
            Self::Schema3(release) => release.schema,
        }
    }
}

/// Renders a complete immutable sparse-registry site at a new path.
///
/// # Errors
///
/// Returns an error for invalid policy or artifacts, unsafe filesystem state, dependency-category violations, or I/O failures. An existing output path is never overwritten.
pub fn render(catalog: &Catalog, artifacts: &ArtifactMap, output: &Path) -> Result<()> {
    let policy = validate_catalog(catalog)?;
    artifacts.verify(catalog)?;
    require_absent(output)?;
    fs::create_dir(output).with_context(|| format!("create output {}", output.display()))?;
    let result = render_into(catalog, artifacts, &policy, output);
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn render_into(
    catalog: &Catalog,
    artifacts: &ArtifactMap,
    policy: &crate::policy::Policy,
    output: &Path,
) -> Result<()> {
    write_new(&output.join(".nojekyll"), b"")?;
    write_new(
        &output.join("CNAME"),
        format!("{}\n", catalog.registries.cname).as_bytes(),
    )?;
    for registry in &catalog.registries.registries {
        let mut config = serde_json::to_vec(&serde_json::json!({
            "dl": registry.download,
        }))
        .context("serialize registry config")?;
        config.push(b'\n');
        write_new(&output.join(&registry.name).join("config.json"), &config)?;
    }

    let mut rows = BTreeMap::<(String, String), Vec<(Version, Vec<u8>)>>::new();
    let mut copied_archives = BTreeSet::new();
    for approval in sorted_approvals(catalog) {
        let artifact = artifacts
            .get(&approval.registry, &approval.name, &approval.version)
            .expect("artifact map was verified before rendering");
        let source = fs::read(&artifact.index_record).with_context(|| {
            format!(
                "read un-routed index record {}",
                artifact.index_record.display()
            )
        })?;
        let mut record = IndexRecord::parse(&source)?;
        record.set_yanked(false);
        let routed = record.route_dependencies(
            &approval.registry,
            &catalog.homes.homes,
            &policy.registry_urls,
        )?;
        for (package, home) in routed {
            ensure!(
                policy.permits_dependency(&approval.category, &home.category),
                "{} {} in {} may not depend on {package} in {}",
                approval.name,
                approval.version,
                approval.category,
                home.category
            );
        }
        let canonical_active_row = record.to_json_line()?;
        let routed_hash = sha256_bytes(&canonical_active_row);
        ensure!(
            routed_hash == approval.index_row_sha256,
            "routed index-row hash mismatch for {} {}: expected {}, got {routed_hash}",
            approval.name,
            approval.version,
            approval.index_row_sha256
        );
        record.set_yanked(approval.is_removed());
        rows.entry((approval.registry.clone(), index_path(&approval.name)))
            .or_default()
            .push((approval.version.clone(), record.to_json_line()?));

        if !approval.is_removed()
            && matches!(&approval.source, Source::GitTag { .. })
            && copied_archives.insert(approval.archive_sha256.clone())
        {
            copy_new(
                &artifact.archive,
                &output
                    .join("crates")
                    .join(format!("{}.crate", approval.archive_sha256)),
            )?;
        }
    }

    for ((registry, relative), mut versions) in rows {
        versions.sort_by(|left, right| left.0.cmp(&right.0));
        let mut contents = Vec::new();
        for (_, line) in versions {
            contents.extend_from_slice(&line);
        }
        write_new(&output.join(registry).join(relative), &contents)?;
    }

    let release = release_from_catalog(catalog);
    let mut release_json =
        serde_json::to_vec_pretty(&release).context("serialize release manifest")?;
    release_json.push(b'\n');
    write_new(&output.join(RELEASE_MANIFEST), &release_json)?;
    Ok(())
}

/// Re-renders into a temporary sibling directory and requires a byte-identical output tree.
///
/// # Errors
///
/// Returns an error when rendering fails or the existing output has any missing, extra, non-regular, or byte-different entry.
pub fn verify(catalog: &Catalog, artifacts: &ArtifactMap, output: &Path) -> Result<()> {
    let temporary = TemporaryDirectory::sibling_of(output)?;
    render(catalog, artifacts, temporary.path())?;
    compare_trees(temporary.path(), output)
}

/// Requires a release transition to preserve every permanent name and package invariant.
///
/// Supported transitions are historical `1→2`, exact catalog migration `2→3`, and normal monotonic `3→3`.
///
/// # Errors
///
/// Returns an error for malformed manifests, noncanonical topology, missing or changed anchors/packages, tombstone reactivation, or a rendered-row hash mismatch.
pub fn verify_monotonic(previous_site: &Path, next_site: &Path) -> Result<()> {
    let previous = load_release(&previous_site.join(RELEASE_MANIFEST))?;
    let next = load_release(&next_site.join(RELEASE_MANIFEST))?;
    match (&previous, &next) {
        (LoadedRelease::Schema1(previous), LoadedRelease::Schema2(next)) => {
            verify_v1_to_v2(previous, next)
        }
        (LoadedRelease::Schema2(previous), LoadedRelease::Schema3(next)) => {
            verify_v2_to_v3(previous, next, next_site)
        }
        (LoadedRelease::Schema3(previous), LoadedRelease::Schema3(next)) => {
            verify_v3_to_v3(previous, next, next_site)
        }
        _ => bail!(
            "unsupported release manifest schema transition {} -> {}",
            previous.schema(),
            next.schema()
        ),
    }
}

fn release_from_catalog(catalog: &Catalog) -> Release {
    let registries = catalog
        .registries
        .registries
        .iter()
        .map(|registry| ReleaseRegistry {
            name: registry.name.clone(),
            index: registry.index.clone(),
            download: registry.download.clone(),
            categories: catalog
                .categories
                .iter()
                .filter(|(category, _)| category.registry() == registry.name)
                .map(|(category, dependencies)| {
                    let mut may_depend_on = dependencies.clone();
                    may_depend_on.sort();
                    ReleaseCategory {
                        id: category.clone(),
                        may_depend_on,
                    }
                })
                .collect(),
        })
        .collect();
    let mut names = catalog
        .homes
        .homes
        .iter()
        .map(|(name, home)| ReleaseName {
            name: name.clone(),
            registry: home.registry.clone(),
            category: home.category.clone(),
            source: *catalog
                .name_sources
                .get(name)
                .expect("validated catalog has a source class for every name"),
        })
        .collect::<Vec<_>>();
    names.sort_by(|left, right| {
        (
            left.registry.as_str(),
            &left.category,
            left.name.to_ascii_lowercase(),
            left.name.as_str(),
        )
            .cmp(&(
                right.registry.as_str(),
                &right.category,
                right.name.to_ascii_lowercase(),
                right.name.as_str(),
            ))
    });
    let packages = sorted_approvals(catalog)
        .into_iter()
        .map(|approval| ReleasePackage {
            registry: approval.registry.clone(),
            category: approval.category.clone(),
            name: approval.name.clone(),
            version: approval.version.clone(),
            archive_sha256: approval.archive_sha256.clone(),
            index_record_sha256: approval.index_record_sha256.clone(),
            index_row_sha256: approval.index_row_sha256.clone(),
            yanked: approval.is_removed(),
            source: match &approval.source {
                Source::CratesIo => ReleaseSource::CratesIo,
                Source::GitTag {
                    repository,
                    tag,
                    tag_oid,
                    commit,
                    package,
                    subdir,
                    cargo_version,
                } => ReleaseSource::GitTag {
                    repository: repository.clone(),
                    tag: tag.clone(),
                    tag_oid: tag_oid.clone(),
                    commit: commit.clone(),
                    package: package.clone(),
                    subdir: subdir
                        .to_str()
                        .expect("validated source subdirectory is UTF-8")
                        .to_owned(),
                    cargo_version: cargo_version.clone(),
                },
            },
        })
        .collect();
    Release {
        schema: RELEASE_SCHEMA_VERSION,
        cname: catalog.registries.cname.clone(),
        registries,
        names,
        packages,
    }
}

fn sorted_approvals(catalog: &Catalog) -> Vec<&Approval> {
    let mut approvals = catalog.approvals.iter().collect::<Vec<_>>();
    approvals.sort_by(|left, right| {
        (
            left.registry.as_str(),
            &left.category,
            left.name.to_ascii_lowercase(),
            left.name.as_str(),
            &left.version,
        )
            .cmp(&(
                right.registry.as_str(),
                &right.category,
                right.name.to_ascii_lowercase(),
                right.name.as_str(),
                &right.version,
            ))
    });
    approvals
}

fn load_release(path: &Path) -> Result<LoadedRelease> {
    let bytes =
        fs::read(path).with_context(|| format!("read release manifest {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse release manifest {}", path.display()))?;
    match value.get("schema").and_then(serde_json::Value::as_u64) {
        Some(1) => serde_json::from_value(value)
            .map(LoadedRelease::Schema1)
            .with_context(|| format!("parse schema-1 release manifest {}", path.display())),
        Some(2) => serde_json::from_value(value)
            .map(LoadedRelease::Schema2)
            .with_context(|| format!("parse schema-2 release manifest {}", path.display())),
        Some(3) => serde_json::from_value(value)
            .map(LoadedRelease::Schema3)
            .with_context(|| format!("parse schema-3 release manifest {}", path.display())),
        Some(schema) => bail!(
            "unsupported release manifest schema {schema} in {}",
            path.display()
        ),
        None => bail!("release manifest has no integer schema: {}", path.display()),
    }
}

fn verify_v1_to_v2(previous: &LegacyRelease, next: &ReleaseV2) -> Result<()> {
    ensure!(
        previous.schema == 1 && next.schema == 2,
        "invalid 1→2 transition"
    );
    ensure!(
        previous.cname == next.cname,
        "CNAME changed across releases"
    );
    ensure!(
        previous.registries.len() == next.registries.len(),
        "registry topology changed across releases"
    );
    for (before, after) in previous.registries.iter().zip(&next.registries) {
        ensure!(
            before.name == after.name
                && before.index == after.index
                && before.may_depend_on == after.may_depend_on,
            "registry topology changed across releases"
        );
        let expected = match before.name.as_str() {
            "core" | "matrix" => MIRROR_DOWNLOAD,
            "pkgre" => PUBLISH_DOWNLOAD,
            name => bail!("unexpected registry {name:?} in schema-1 release migration"),
        };
        ensure!(
            previous.download == PUBLISH_DOWNLOAD && after.download == expected,
            "registry {:?} has an unsupported schema-1 download migration",
            before.name
        );
    }
    let next_packages = package_map_v2(&next.packages)?;
    for prior in &previous.packages {
        let key = release_key_v2(prior);
        let current = next_packages.get(&key).with_context(|| {
            format!(
                "previously published package {} {} in {} was removed",
                prior.name, prior.version, prior.registry
            )
        })?;
        ensure!(
            same_immutable_v2(prior, current),
            "immutable release identity changed for {} {} in {}",
            prior.name,
            prior.version,
            prior.registry
        );
        ensure!(
            !prior.yanked || current.yanked,
            "removed package {} {} in {} was reactivated",
            prior.name,
            prior.version,
            prior.registry
        );
    }
    package_map_v2(&previous.packages)?;
    Ok(())
}

fn verify_v2_to_v3(previous: &ReleaseV2, next: &Release, next_site: &Path) -> Result<()> {
    ensure!(
        previous.schema == 2 && next.schema == 3,
        "invalid 2→3 transition"
    );
    ensure!(
        previous.cname == next.cname,
        "CNAME changed across releases"
    );
    validate_v2_topology(previous)?;
    validate_v3_release(next)?;
    let next_names = name_map(&next.names)?;
    let next_packages = package_map(&next.packages)?;
    package_map_v2(&previous.packages)?;
    for prior in &previous.packages {
        let category = category_for_v2_home(&prior.registry, &prior.name)?;
        let registry = category.registry();
        let name = next_names.get(prior.name.as_str()).with_context(|| {
            format!(
                "schema-2 package name {:?} has no schema-3 anchor",
                prior.name
            )
        })?;
        ensure!(
            name.registry == registry
                && name.category == category
                && name.source == prior.source.name_source(),
            "schema-2 package name {:?} mapped to the wrong schema-3 home or source class",
            prior.name
        );
        let key = (
            registry.to_owned(),
            prior.name.clone(),
            prior.version.clone(),
        );
        let current = next_packages.get(&key).with_context(|| {
            format!(
                "schema-2 package {} {} in {} was not migrated",
                prior.name, prior.version, prior.registry
            )
        })?;
        ensure!(
            current.category == category && same_v2_v3_package(prior, current),
            "immutable schema-2 package changed while migrating {} {} from {}",
            prior.name,
            prior.version,
            prior.registry
        );
        ensure!(
            !prior.yanked || current.yanked,
            "removed schema-2 package {} {} in {} was reactivated",
            prior.name,
            prior.version,
            prior.registry
        );
    }
    verify_v3_rows(next, next_site)
}

fn verify_v3_to_v3(previous: &Release, next: &Release, next_site: &Path) -> Result<()> {
    ensure!(
        previous.schema == 3 && next.schema == 3,
        "invalid 3→3 transition"
    );
    ensure!(
        previous.cname == next.cname,
        "CNAME changed across releases"
    );
    validate_v3_release(previous)?;
    validate_v3_release(next)?;
    ensure!(
        previous.registries == next.registries,
        "registry/category topology changed across releases"
    );
    let previous_names = name_map(&previous.names)?;
    let next_names = name_map(&next.names)?;
    for (name, prior) in previous_names {
        let current = next_names
            .get(name)
            .with_context(|| format!("permanent package name {name:?} was removed"))?;
        ensure!(
            prior == *current,
            "permanent package name {name:?} changed registry, category, or source class"
        );
    }
    let previous_packages = package_map(&previous.packages)?;
    let next_packages = package_map(&next.packages)?;
    for (key, prior) in previous_packages {
        let current = next_packages.get(&key).with_context(|| {
            format!(
                "previously published package {} {} in {} was removed",
                prior.name, prior.version, prior.registry
            )
        })?;
        ensure!(
            same_immutable_package(prior, current),
            "immutable release identity changed for {} {} in {}",
            prior.name,
            prior.version,
            prior.registry
        );
        ensure!(
            !prior.yanked || current.yanked,
            "removed package {} {} in {} was reactivated",
            prior.name,
            prior.version,
            prior.registry
        );
    }
    verify_v3_rows(next, next_site)
}

fn validate_v2_topology(release: &ReleaseV2) -> Result<()> {
    let expected = [
        ReleaseRegistryV2 {
            name: "core".to_owned(),
            index: "sparse+https://rust.pkg.re/core/".to_owned(),
            download: MIRROR_DOWNLOAD.to_owned(),
            may_depend_on: vec!["core".to_owned()],
        },
        ReleaseRegistryV2 {
            name: "matrix".to_owned(),
            index: "sparse+https://rust.pkg.re/matrix/".to_owned(),
            download: MIRROR_DOWNLOAD.to_owned(),
            may_depend_on: vec!["core".to_owned(), "matrix".to_owned()],
        },
        ReleaseRegistryV2 {
            name: "pkgre".to_owned(),
            index: "sparse+https://rust.pkg.re/pkgre/".to_owned(),
            download: PUBLISH_DOWNLOAD.to_owned(),
            may_depend_on: vec!["core".to_owned(), "matrix".to_owned(), "pkgre".to_owned()],
        },
    ];
    ensure!(
        release.registries == expected,
        "schema-2 release does not have the canonical core/matrix/pkgre topology"
    );
    Ok(())
}

fn validate_v3_release(release: &Release) -> Result<()> {
    ensure!(
        release.schema == RELEASE_SCHEMA_VERSION,
        "schema-3 release has wrong schema"
    );
    ensure!(
        release.cname == "rust.pkg.re",
        "release CNAME is noncanonical"
    );
    let expected_categories = canonical_category_dependencies();
    let expected_registries = REGISTRIES
        .iter()
        .map(|(name, index)| ReleaseRegistry {
            name: (*name).to_owned(),
            index: (*index).to_owned(),
            download: if *name == "pkgre" {
                PUBLISH_DOWNLOAD.to_owned()
            } else {
                MIRROR_DOWNLOAD.to_owned()
            },
            categories: expected_categories
                .iter()
                .filter(|(category, _)| category.registry() == *name)
                .map(|(category, dependencies)| ReleaseCategory {
                    id: category.clone(),
                    may_depend_on: dependencies.iter().cloned().collect(),
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    ensure!(
        release.registries == expected_registries,
        "schema-3 release does not have the exact canonical registry/category topology"
    );
    let names = name_map(&release.names)?;
    for anchor in names.values() {
        ensure!(
            expected_categories.contains_key(&anchor.category),
            "release name {:?} has noncanonical category {}",
            anchor.name,
            anchor.category
        );
        match anchor.source {
            NameSource::Mirror => ensure!(
                anchor.registry == "universe",
                "mirrored release name {:?} must use the universe registry",
                anchor.name
            ),
            NameSource::Publish => ensure!(
                anchor.registry == "pkgre",
                "first-party release name {:?} must use the pkgre registry",
                anchor.name
            ),
        }
    }
    let packages = package_map(&release.packages)?;
    for package in packages.values() {
        validate_sha256(&package.archive_sha256)?;
        validate_sha256(&package.index_record_sha256)?;
        validate_sha256(&package.index_row_sha256)?;
        let anchor = names.get(package.name.as_str()).with_context(|| {
            format!(
                "release package {} {} has no permanent name anchor",
                package.name, package.version
            )
        })?;
        ensure!(
            anchor.registry == package.registry
                && anchor.category == package.category
                && anchor.source == package.source.name_source(),
            "release package {} {} differs from its permanent name anchor",
            package.name,
            package.version
        );
    }
    Ok(())
}

fn name_map(names: &[ReleaseName]) -> Result<BTreeMap<&str, &ReleaseName>> {
    let mut result = BTreeMap::new();
    for name in names {
        validate_package_name(&name.name)?;
        ensure!(
            name.registry == name.category.registry(),
            "release name {:?} has a category outside registry {:?}",
            name.name,
            name.registry
        );
        ensure!(
            result.insert(name.name.as_str(), name).is_none(),
            "duplicate permanent package name in release manifest: {:?}",
            name.name
        );
    }
    Ok(result)
}

fn package_map(
    packages: &[ReleasePackage],
) -> Result<BTreeMap<(String, String, Version), &ReleasePackage>> {
    let mut result = BTreeMap::new();
    for package in packages {
        let key = (
            package.registry.clone(),
            package.name.clone(),
            package.version.clone(),
        );
        ensure!(
            result.insert(key, package).is_none(),
            "duplicate package identity in release manifest: {} {} in {}",
            package.name,
            package.version,
            package.registry
        );
    }
    Ok(result)
}

fn package_map_v2(
    packages: &[ReleasePackageV2],
) -> Result<BTreeMap<(String, String, Version), &ReleasePackageV2>> {
    let mut result = BTreeMap::new();
    for package in packages {
        let key = release_key_v2(package);
        ensure!(
            result.insert(key, package).is_none(),
            "duplicate package identity in release manifest: {} {} in {}",
            package.name,
            package.version,
            package.registry
        );
    }
    Ok(result)
}

fn release_key_v2(package: &ReleasePackageV2) -> (String, String, Version) {
    (
        package.registry.clone(),
        package.name.clone(),
        package.version.clone(),
    )
}

fn same_immutable_package(left: &ReleasePackage, right: &ReleasePackage) -> bool {
    left.registry == right.registry
        && left.category == right.category
        && left.name == right.name
        && left.version == right.version
        && left.archive_sha256 == right.archive_sha256
        && left.index_record_sha256 == right.index_record_sha256
        && left.index_row_sha256 == right.index_row_sha256
        && left.source == right.source
}

fn same_immutable_v2(left: &ReleasePackageV2, right: &ReleasePackageV2) -> bool {
    left.registry == right.registry
        && left.name == right.name
        && left.version == right.version
        && left.archive_sha256 == right.archive_sha256
        && left.index_record_sha256 == right.index_record_sha256
        && left.source == right.source
}

fn same_v2_v3_package(previous: &ReleasePackageV2, next: &ReleasePackage) -> bool {
    previous.name == next.name
        && previous.version == next.version
        && previous.archive_sha256 == next.archive_sha256
        && previous.index_record_sha256 == next.index_record_sha256
        && same_v2_v3_source(&previous.source, &next.source)
}

fn same_v2_v3_source(previous: &ReleaseSourceV2, next: &ReleaseSource) -> bool {
    match (previous, next) {
        (ReleaseSourceV2::CratesIo, ReleaseSource::CratesIo) => true,
        (
            ReleaseSourceV2::GitTag {
                repository: previous_repository,
                tag: previous_tag,
                commit: previous_commit,
                package: previous_package,
                subdir: previous_subdir,
            },
            ReleaseSource::GitTag {
                repository,
                tag,
                commit,
                package,
                subdir,
                cargo_version,
                ..
            },
        ) => {
            previous_repository == repository
                && previous_tag == tag
                && previous_commit == commit
                && previous_package == package
                && previous_subdir == subdir
                && cargo_version.to_string() == CARGO_VERSION
        }
        _ => false,
    }
}

fn verify_v3_rows(release: &Release, site: &Path) -> Result<()> {
    for package in &release.packages {
        let path = site.join(&package.registry).join(index_path(&package.name));
        let bytes = fs::read(&path).with_context(|| {
            format!(
                "read rendered index row for {} {} at {}",
                package.name,
                package.version,
                path.display()
            )
        })?;
        ensure!(
            bytes.last() == Some(&b'\n'),
            "rendered index file does not end in a newline: {}",
            path.display()
        );
        let mut matches = 0;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            let mut record = IndexRecord::parse(line)
                .with_context(|| format!("parse rendered index record in {}", path.display()))?;
            record.validate_structure()?;
            if record.name()? != package.name || record.version()? != package.version {
                continue;
            }
            matches += 1;
            ensure!(
                record.yanked()? == package.yanked,
                "rendered yank state differs from release manifest for {} {}",
                package.name,
                package.version
            );
            record.set_yanked(false);
            let hash = sha256_bytes(&record.to_json_line()?);
            ensure!(
                hash == package.index_row_sha256,
                "rendered index-row hash differs from release manifest for {} {}",
                package.name,
                package.version
            );
        }
        ensure!(
            matches == 1,
            "rendered index contains {matches} records for {} {}; expected one",
            package.name,
            package.version
        );
    }
    Ok(())
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

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
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

fn compare_trees(expected: &Path, actual: &Path) -> Result<()> {
    let expected_entries = tree_entries(expected)?;
    let actual_entries = tree_entries(actual)?;
    ensure!(
        expected_entries == actual_entries,
        "rendered tree entry set differs from expected output"
    );
    for relative in expected_entries {
        let expected_path = expected.join(&relative);
        let actual_path = actual.join(&relative);
        let expected_metadata = fs::symlink_metadata(&expected_path)
            .with_context(|| format!("inspect {}", expected_path.display()))?;
        let actual_metadata = fs::symlink_metadata(&actual_path)
            .with_context(|| format!("inspect {}", actual_path.display()))?;
        ensure!(
            expected_metadata.file_type().is_file() && actual_metadata.file_type().is_file(),
            "rendered output contains a non-regular file: {}",
            relative.display()
        );
        ensure!(
            files_equal(&expected_path, &actual_path)?,
            "rendered output differs at {}",
            relative.display()
        );
    }
    Ok(())
}

fn tree_entries(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect output root {}", root.display()))?;
    ensure!(
        root_metadata.file_type().is_dir(),
        "output root is not a directory: {}",
        root.display()
    );
    let mut result = BTreeSet::new();
    collect_tree_entries(root, root, &mut result)?;
    Ok(result)
}

fn collect_tree_entries(
    root: &Path,
    directory: &Path,
    result: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("read entries below {}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("inspect {}", path.display()))?;
        if metadata.file_type().is_dir() {
            collect_tree_entries(root, &path, result)?;
        } else if metadata.file_type().is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("collected entry is below root")
                .to_path_buf();
            result.insert(relative);
        } else {
            bail!(
                "tree contains a symlink or special file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    let left_metadata =
        fs::metadata(left).with_context(|| format!("inspect {}", left.display()))?;
    let right_metadata =
        fs::metadata(right).with_context(|| format!("inspect {}", right.display()))?;
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }
    let mut left_file = File::open(left).with_context(|| format!("open {}", left.display()))?;
    let mut right_file = File::open(right).with_context(|| format!("open {}", right.display()))?;
    let mut left_buffer = [0_u8; 16 * 1024];
    let mut right_buffer = [0_u8; 16 * 1024];
    loop {
        let left_count = left_file
            .read(&mut left_buffer)
            .with_context(|| format!("read {}", left.display()))?;
        let right_count = right_file
            .read(&mut right_buffer)
            .with_context(|| format!("read {}", right.display()))?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Ok(false);
        }
        if left_count == 0 {
            return Ok(true);
        }
    }
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn sibling_of(path: &Path) -> Result<Self> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("render");
        for _ in 0..100 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(
                ".{name}.pkgre-tmp-{}-{sequence}",
                std::process::id()
            ));
            match fs::symlink_metadata(&candidate) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Self { path: candidate });
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("inspect temporary path {}", candidate.display())
                    });
                }
            }
        }
        bail!("could not allocate a unique temporary render path")
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn old_registries(downloads: [&str; 3]) -> Vec<ReleaseRegistryV2> {
        ["core", "matrix", "pkgre"]
            .into_iter()
            .zip(downloads)
            .map(|(name, download)| ReleaseRegistryV2 {
                name: name.to_owned(),
                index: format!("sparse+https://rust.pkg.re/{name}/"),
                download: download.to_owned(),
                may_depend_on: match name {
                    "core" => vec!["core".to_owned()],
                    "matrix" => vec!["core".to_owned(), "matrix".to_owned()],
                    "pkgre" => vec!["core".to_owned(), "matrix".to_owned(), "pkgre".to_owned()],
                    _ => unreachable!(),
                },
            })
            .collect()
    }

    fn legacy_registries() -> Vec<LegacyReleaseRegistry> {
        old_registries([PUBLISH_DOWNLOAD; 3])
            .into_iter()
            .map(|registry| LegacyReleaseRegistry {
                name: registry.name,
                index: registry.index,
                may_depend_on: registry.may_depend_on,
            })
            .collect()
    }

    fn write_manifest(path: &Path, value: &impl Serialize) {
        fs::create_dir_all(path).unwrap();
        fs::write(
            path.join(RELEASE_MANIFEST),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn schema_one_release_migrates_only_to_source_specific_downloads() {
        let root = temporary_test_root("v1-v2");
        let previous = root.join("previous");
        let next = root.join("next");
        write_manifest(
            &previous,
            &LegacyRelease {
                schema: 1,
                cname: "rust.pkg.re".to_owned(),
                download: PUBLISH_DOWNLOAD.to_owned(),
                registries: legacy_registries(),
                packages: Vec::new(),
            },
        );
        let mut next_release = ReleaseV2 {
            schema: 2,
            cname: "rust.pkg.re".to_owned(),
            registries: old_registries([MIRROR_DOWNLOAD, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD]),
            packages: Vec::new(),
        };
        write_manifest(&next, &next_release);
        verify_monotonic(&previous, &next).unwrap();

        next_release.registries[0].download = PUBLISH_DOWNLOAD.to_owned();
        fs::write(
            next.join(RELEASE_MANIFEST),
            serde_json::to_vec_pretty(&next_release).unwrap(),
        )
        .unwrap();
        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("unsupported schema-1 download migration"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsupported_release_transition_is_rejected() {
        let root = temporary_test_root("unsupported");
        let previous = root.join("previous");
        let next = root.join("next");
        let release = ReleaseV2 {
            schema: 2,
            cname: "rust.pkg.re".to_owned(),
            registries: old_registries([MIRROR_DOWNLOAD, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD]),
            packages: Vec::new(),
        };
        write_manifest(&previous, &release);
        write_manifest(&next, &release);
        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("unsupported release manifest schema transition"));
        fs::remove_dir_all(root).unwrap();
    }

    fn schema_three_registries() -> Vec<ReleaseRegistry> {
        let dependencies = canonical_category_dependencies();
        REGISTRIES
            .iter()
            .map(|(name, index)| ReleaseRegistry {
                name: (*name).to_owned(),
                index: (*index).to_owned(),
                download: if *name == "pkgre" {
                    PUBLISH_DOWNLOAD.to_owned()
                } else {
                    MIRROR_DOWNLOAD.to_owned()
                },
                categories: dependencies
                    .iter()
                    .filter(|(category, _)| category.registry() == *name)
                    .map(|(category, allowed)| ReleaseCategory {
                        id: category.clone(),
                        may_depend_on: allowed.iter().cloned().collect(),
                    })
                    .collect(),
            })
            .collect()
    }

    fn schema_two_crate(name: &str, yanked: bool) -> ReleasePackageV2 {
        ReleasePackageV2 {
            registry: "core".to_owned(),
            name: name.to_owned(),
            version: Version::new(1, 0, 0),
            archive_sha256: "a".repeat(64),
            index_record_sha256: "b".repeat(64),
            yanked,
            source: ReleaseSourceV2::CratesIo,
        }
    }

    fn schema_two_release(package: ReleasePackageV2) -> ReleaseV2 {
        ReleaseV2 {
            schema: 2,
            cname: "rust.pkg.re".to_owned(),
            registries: old_registries([MIRROR_DOWNLOAD, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD]),
            packages: vec![package],
        }
    }

    fn migrate_test_release(package: &ReleasePackageV2) -> Release {
        let category = category_for_v2_home(&package.registry, &package.name).unwrap();
        let registry = category.registry().to_owned();
        let mut release = Release {
            schema: 3,
            cname: "rust.pkg.re".to_owned(),
            registries: schema_three_registries(),
            names: vec![ReleaseName {
                name: package.name.clone(),
                registry: registry.clone(),
                category: category.clone(),
                source: package.source.name_source(),
            }],
            packages: vec![ReleasePackage {
                registry,
                category,
                name: package.name.clone(),
                version: package.version.clone(),
                archive_sha256: package.archive_sha256.clone(),
                index_record_sha256: package.index_record_sha256.clone(),
                index_row_sha256: String::new(),
                yanked: package.yanked,
                source: ReleaseSource::CratesIo,
            }],
        };
        let row = test_release_row(&release.packages[0]);
        release.packages[0].index_row_sha256 = active_row_hash(&row);
        release
    }

    fn test_release_row(package: &ReleasePackage) -> Vec<u8> {
        let mut row = serde_json::to_vec(&serde_json::json!({
            "name": package.name,
            "vers": package.version.to_string(),
            "deps": [],
            "cksum": package.archive_sha256,
            "features": {},
            "yanked": package.yanked,
        }))
        .unwrap();
        row.push(b'\n');
        row
    }

    fn active_row_hash(row: &[u8]) -> String {
        let mut record = IndexRecord::parse(row).unwrap();
        record.set_yanked(false);
        sha256_bytes(&record.to_json_line().unwrap())
    }

    fn write_schema_three_site(path: &Path, release: &Release) {
        write_manifest(path, release);
        let mut rows = BTreeMap::<PathBuf, Vec<Vec<u8>>>::new();
        for package in &release.packages {
            rows.entry(path.join(&package.registry).join(index_path(&package.name)))
                .or_default()
                .push(test_release_row(package));
        }
        for (path, versions) in rows {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, versions.concat()).unwrap();
        }
    }

    #[test]
    fn canonical_schema_two_release_migrates_to_schema_three() {
        let root = temporary_test_root("v2-v3");
        let previous = root.join("previous");
        let next = root.join("next");
        let package = schema_two_crate("serde", false);
        write_manifest(&previous, &schema_two_release(package.clone()));
        write_schema_three_site(&next, &migrate_test_release(&package));

        verify_monotonic(&previous, &next).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_two_release_cannot_remap_a_package_to_an_arbitrary_category() {
        let root = temporary_test_root("v2-v3-remap");
        let previous = root.join("previous");
        let next = root.join("next");
        let package = schema_two_crate("serde", false);
        write_manifest(&previous, &schema_two_release(package.clone()));
        let mut migrated = migrate_test_release(&package);
        let category = CategoryId::new("universe", "yaml").unwrap();
        migrated.names[0].category.clone_from(&category);
        migrated.packages[0].category = category;
        write_schema_three_site(&next, &migrated);

        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("mapped to the wrong schema-3 home"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_three_preserves_name_category_and_package_anchors() {
        let root = temporary_test_root("v3-anchors");
        let previous = root.join("previous");
        let next = root.join("next");
        let package = schema_two_crate("serde", false);
        let release = migrate_test_release(&package);
        write_schema_three_site(&previous, &release);

        let mut recategorized = release.clone();
        let category = CategoryId::new("universe", "yaml").unwrap();
        recategorized.names[0].category.clone_from(&category);
        recategorized.packages[0].category = category;
        write_schema_three_site(&next, &recategorized);
        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("permanent package name"));

        let mut changed_package = release.clone();
        changed_package.packages[0].index_record_sha256 = "c".repeat(64);
        write_schema_three_site(&next, &changed_package);
        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("immutable release identity changed"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_three_removed_package_cannot_be_reactivated() {
        let root = temporary_test_root("v3-reactivate");
        let previous = root.join("previous");
        let next = root.join("next");
        let package = schema_two_crate("serde", true);
        let removed = migrate_test_release(&package);
        write_schema_three_site(&previous, &removed);
        let mut reactivated = removed.clone();
        reactivated.packages[0].yanked = false;
        write_schema_three_site(&next, &reactivated);

        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("was reactivated"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_three_routed_row_hash_must_match_the_site() {
        let root = temporary_test_root("v3-row-hash");
        let previous = root.join("previous");
        let next = root.join("next");
        let package = schema_two_crate("serde", false);
        let mut release = migrate_test_release(&package);
        release.packages[0].index_row_sha256 = "d".repeat(64);
        write_schema_three_site(&previous, &release);
        write_schema_three_site(&next, &release);

        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("rendered index-row hash differs"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn content_comparison_detects_equal_and_different_files() {
        let root = temporary_test_root("compare");
        fs::write(root.join("one"), b"same").unwrap();
        fs::write(root.join("two"), b"same").unwrap();
        assert!(files_equal(&root.join("one"), &root.join("two")).unwrap());
        fs::write(root.join("two"), b"changed").unwrap();
        assert!(!files_equal(&root.join("one"), &root.join("two")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    fn temporary_test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "pkgre-render-{name}-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        root
    }
}
