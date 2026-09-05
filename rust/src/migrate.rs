//! Deterministic one-shot migration of a schema-4 catalog tree to schema 5.
//!
//! The migration copies the catalog tree, rewrites every human registry file with a
//! serving audience, rebuilds every generated lock in exact canonical schema-5 form
//! with deterministic `admitted-at` timestamps, replaces the download catalog with
//! the schema-2 delivery model, and gates the result through full strict validation.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::Deserialize;

use crate::download::{DOWNLOAD_CATALOG_FILE, Delivery, DownloadCatalog, DownloadRoute};
use crate::policy::validate_catalog;
use crate::schema::{
    Audience, LockedName, LockedPackage, LockedRegistry, LockedSource, PackageState, RegistryLock,
    catalog_from_inputs, load_registry_inputs, serialize_lock, validate_input_for_update,
};
use crate::update::UtcTimestamp;

/// Copies one catalog tree recursively into a fresh output directory.
fn copy_tree(input: &Path, output: &Path) -> Result<()> {
    ensure!(
        !output.exists(),
        "output directory {} already exists",
        output.display()
    );
    copy_entry(input, output)
}

fn copy_entry(input: &Path, output: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(input).with_context(|| format!("inspect {}", input.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "symlinks are not allowed in catalog trees: {}",
        input.display()
    );
    if metadata.is_dir() {
        fs::create_dir_all(output)
            .with_context(|| format!("create directory {}", output.display()))?;
        let mut entries = fs::read_dir(input)
            .with_context(|| format!("read directory {}", input.display()))?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("read directory {}", input.display()))?;
        entries.sort();
        for entry in entries {
            let name = entry
                .file_name()
                .context("catalog entry name is not valid UTF-8")?;
            copy_entry(&entry, &output.join(name))?;
        }
        Ok(())
    } else {
        ensure!(
            metadata.is_file(),
            "unsupported catalog entry kind: {}",
            input.display()
        );
        fs::copy(input, output)
            .with_context(|| format!("copy {} to {}", input.display(), output.display()))?;
        Ok(())
    }
}

/// Exact schema-4 shape of one generated lock registry identity.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4LockedRegistry {
    name: String,
    index: String,
    download: String,
}

/// Exact schema-4 shape of one generated lock package identity.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4LockedPackage {
    name: String,
    version: Version,
    state: PackageState,
    #[serde(rename = "crate-sha256")]
    crate_sha256: String,
    #[serde(rename = "source-row-sha256")]
    source_row_sha256: String,
    #[serde(rename = "index-row-sha256")]
    index_row_sha256: String,
    #[serde(
        rename = "admission-sha256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    admission_sha256: Option<String>,
    #[serde(rename = "source")]
    source: LockedSource,
}

/// Exact schema-4 shape of one generated lock.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4RegistryLock {
    schema: u32,
    registry: V4LockedRegistry,
    #[serde(default)]
    names: Vec<LockedName>,
    packages: Vec<V4LockedPackage>,
}

/// Exact schema-1 shape of one download catalog route.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1DownloadRoute {
    registry: String,
    name: String,
    version: Version,
    sha256: String,
    source: V1DownloadSource,
}

/// Exact schema-1 archive origin class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum V1DownloadSource {
    CratesIo,
    GitTag,
}

/// Exact schema-1 shape of the download catalog.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1DownloadCatalog {
    schema: u32,
    routes: Vec<V1DownloadRoute>,
}

/// Parses one raw crates.io index row object and its publication time.
#[derive(Debug, Deserialize)]
struct RawRowObject {
    pubtime: String,
}

/// Converts one RFC 3339 timestamp to a canonical UTC timestamp.
///
/// # Errors
///
/// Returns an error when the input is not a valid RFC 3339 timestamp with a
/// supported UTC offset or canonicalizes outside the supported year range.
pub fn canonicalize_rfc3339(raw: &str) -> Result<UtcTimestamp> {
    canonicalize_pubtime(raw)
}

/// Converts one crates.io RFC 3339 publication timestamp to canonical UTC seconds.
fn canonicalize_pubtime(raw: &str) -> Result<UtcTimestamp> {
    let bytes = raw.as_bytes();
    ensure!(
        bytes.len() >= 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':',
        "publication time {raw:?} is not an RFC 3339 timestamp"
    );
    let year = raw[0..4].parse::<i64>()?;
    let month = raw[5..7].parse::<i64>()?;
    let day = raw[8..10].parse::<i64>()?;
    let hour = raw[11..13].parse::<i64>()?;
    let minute = raw[14..16].parse::<i64>()?;
    let second = raw[17..19].parse::<i64>()?;
    ensure!(
        (1..=12).contains(&month) && (1..=31).contains(&day),
        "publication time {raw:?} has an invalid civil date"
    );
    let (offset_seconds, remainder) = match bytes[19] {
        b'Z' => (0, &raw[20..]),
        b'+' | b'-' => {
            ensure!(
                bytes.len() >= 25
                    && bytes[22] == b':'
                    && bytes[23].is_ascii_digit()
                    && bytes[24].is_ascii_digit(),
                "publication time {raw:?} has an invalid UTC offset"
            );
            let sign: i64 = if bytes[19] == b'+' { 1 } else { -1 };
            let hours = raw[20..22].parse::<i64>()?;
            let minutes = raw[23..25].parse::<i64>()?;
            (sign * (hours * 3600 + minutes * 60), &raw[25..])
        }
        _ => bail!("publication time {raw:?} has an invalid UTC offset"),
    };
    ensure!(
        remainder.is_empty() || remainder.starts_with('.'),
        "publication time {raw:?} has trailing garbage"
    );
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds;
    let canonical = format_unix_utc(seconds);
    UtcTimestamp::parse(&canonical)
        .with_context(|| format!("publication time {raw:?} canonicalizes to invalid {canonical:?}"))
}

/// Returns the number of days since 1970-01-01 for one proleptic Gregorian civil date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Formats one Unix whole-second timestamp as canonical `YYYY-MM-DDTHH:MM:SSZ`.
fn format_unix_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day / 60) % 60,
        seconds_of_day % 60
    )
}

/// Returns one proleptic Gregorian civil date for a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shift = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_shift + 2) / 5 + 1;
    let month = if month_shift < 10 {
        month_shift + 3
    } else {
        month_shift - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Parses one `registry/name@tag=<canonical-timestamp>` evidence mapping.
fn parse_git_time_entry(entry: &(String, String)) -> Result<(String, String, String)> {
    let (key, value) = (&entry.0, &entry.1);
    let (registry, name_tag) = key
        .split_once('/')
        .with_context(|| format!("git tag time key {key:?} must use registry/name@tag form"))?;
    let (name, tag) = name_tag
        .split_once('@')
        .with_context(|| format!("git tag time key {key:?} must use registry/name@tag form"))?;
    Ok((registry.to_string(), format!("{name}@{tag}"), value.clone()))
}

/// Derives the deterministic `admitted-at` timestamp for one package identity.
fn derive_admitted_at(
    registry: &str,
    package: &V4LockedPackage,
    objects: &Path,
    git_times: &BTreeMap<String, String>,
) -> Result<UtcTimestamp> {
    match &package.source {
        LockedSource::CratesIo {} => {
            ensure!(
                crate::policy::validate_sha256(&package.source_row_sha256).is_ok(),
                "source row digest {} is not a canonical SHA-256",
                package.source_row_sha256
            );
            let row_path = objects
                .join("rows")
                .join(format!("{}.json", package.source_row_sha256));
            let bytes = fs::read(&row_path)
                .with_context(|| format!("read row object {}", row_path.display()))?;
            let row: RawRowObject = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse row object {}", row_path.display()))?;
            canonicalize_pubtime(&row.pubtime).with_context(|| {
                format!(
                    "canonicalize publication time for {registry}/{}",
                    package.name
                )
            })
        }
        LockedSource::GitTag { tag, .. } => {
            let key = format!("{}@{tag}", package.name);
            let raw = git_times.get(&key).with_context(|| {
                format!(
                    "missing --git-tag-time mapping for {registry}/{} tag {tag:?}; expected --git-tag-time {registry}/{}@{tag}=<canonical-timestamp>",
                    package.name, package.name
                )
            })?;
            UtcTimestamp::parse(raw).with_context(|| {
                format!(
                    "git tag time for {registry}/{} tag {tag:?} is not canonical",
                    package.name
                )
            })
        }
    }
}

/// Rewrites one human registry file with the asserted serving audience.
fn rewrite_human_registry(path: &Path, audience: Audience) -> Result<()> {
    let raw = fs::read(path).with_context(|| format!("read human registry {}", path.display()))?;
    let text = String::from_utf8(raw)
        .with_context(|| format!("human registry {} is not UTF-8", path.display()))?;
    let mut document = text
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parse human registry {}", path.display()))?;
    let registry = document
        .get_mut("registry")
        .and_then(|value| value.as_table_mut())
        .with_context(|| format!("human registry {} has no [registry] table", path.display()))?;
    let audience_key = if audience == Audience::LanPublic {
        "lan-public"
    } else {
        "public"
    };
    registry.insert("audience", toml_edit::value(audience_key));
    document.insert("schema", toml_edit::Item::Value(toml_edit::Value::from(5)));
    fs::write(path, document.to_string())
        .with_context(|| format!("write human registry {}", path.display()))
}

/// One successfully migrated registry.
#[derive(Debug)]
pub struct MigratedRegistry {
    /// Registry alias.
    pub name: String,
    /// Migrated package identity count.
    pub packages: usize,
}

/// Full migration result summary.
#[derive(Debug)]
pub struct MigrationSummary {
    /// Migrated registry aliases with per-registry identity counts.
    pub registries: Vec<MigratedRegistry>,
    /// Schema-2 download routes emitted.
    pub routes: usize,
}

/// Migrates one schema-4 catalog tree to schema 5 in a fresh output directory.
///
/// # Errors
///
/// Returns an error for any unsupported, malformed, or inconsistent input or for any
/// failed validation gate on the migrated output.
pub fn migrate_v4_to_v5(
    input: &Path,
    output: &Path,
    git_times: &[(String, String)],
) -> Result<MigrationSummary> {
    copy_tree(input, output)?;
    let mut git_time_map = BTreeMap::<String, BTreeMap<String, String>>::new();
    for entry in git_times {
        let (registry, key, value) = parse_git_time_entry(entry)?;
        git_time_map.entry(registry).or_default().insert(key, value);
    }

    let mut human_paths = Vec::<PathBuf>::new();
    for entry in fs::read_dir(output).with_context(|| format!("read {}", output.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            human_paths.push(path);
        }
    }
    human_paths.sort();

    let mut category_paths = Vec::<PathBuf>::new();
    let categories_root = output.join("categories");
    if categories_root.is_dir() {
        for registry_dir in fs::read_dir(&categories_root)
            .with_context(|| format!("read {}", categories_root.display()))?
        {
            let registry_dir = registry_dir?.path();
            if !registry_dir.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&registry_dir)
                .with_context(|| format!("read {}", registry_dir.display()))?
            {
                let path = entry?.path();
                if path.extension().and_then(|value| value.to_str()) == Some("toml") {
                    category_paths.push(path);
                }
            }
        }
    }
    category_paths.sort();
    for path in &category_paths {
        let raw =
            fs::read(path).with_context(|| format!("read category file {}", path.display()))?;
        let mut document = String::from_utf8(raw)
            .with_context(|| format!("category file {} is not UTF-8", path.display()))?
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("parse category file {}", path.display()))?;
        document.insert("schema", toml_edit::Item::Value(toml_edit::Value::from(5)));
        fs::write(path, document.to_string())
            .with_context(|| format!("write category file {}", path.display()))?;
    }

    let mut migrated = Vec::new();
    for human_path in &human_paths {
        let migrated_lock = migrate_registry_lock(human_path, output, &git_time_map)?;
        migrated.push(MigratedRegistry {
            name: migrated_lock.registry.name.clone(),
            packages: migrated_lock.packages.len(),
        });
    }
    ensure!(!migrated.is_empty(), "catalog has no registry declarations");

    replace_download_catalog(input, output)?;

    let catalog = crate::schema::Catalog::load(output)
        .with_context(|| format!("validate migrated catalog {}", output.display()))?;
    validate_catalog(&catalog)
        .with_context(|| format!("validate migrated catalog {}", output.display()))?;
    let artifacts = crate::artifact::ArtifactMap::load(&catalog)?;
    let render_check = output.join(".migrate-render-check");
    crate::render::render(&catalog, &artifacts, &render_check)?;
    fs::remove_dir_all(&render_check)
        .with_context(|| format!("remove render check {}", render_check.display()))?;
    Ok(MigrationSummary {
        routes: catalog.approvals.len(),
        registries: migrated,
    })
}

/// Rewrites one human registry plus its generated lock to schema 5.
///
/// # Errors
///
/// Returns an error for any malformed input registry or a failed schema-5 rewrite.
fn migrate_registry_lock(
    human_path: &Path,
    output: &Path,
    git_time_map: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<RegistryLock> {
    rewrite_human_registry(human_path, Audience::Public)?;

    let lock_path = human_path.with_extension("lock");
    ensure!(
        lock_path.exists(),
        "generated lock is missing for {}: run `pkgre-rust lock`",
        human_path.display()
    );
    let lock_bytes = fs::read(&lock_path)
        .with_context(|| format!("read generated lock {}", lock_path.display()))?;
    let v4: V4RegistryLock = toml::from_slice(&lock_bytes)
        .with_context(|| format!("parse generated lock {}", lock_path.display()))?;
    ensure!(
        v4.schema == 4,
        "generated lock {} must use schema 4, found {}",
        lock_path.display(),
        v4.schema
    );

    let objects = output.join("objects");
    let registry_times = git_time_map
        .get(&v4.registry.name)
        .cloned()
        .unwrap_or_default();
    let mut packages = Vec::with_capacity(v4.packages.len());
    for package in &v4.packages {
        let admitted_at =
            derive_admitted_at(&v4.registry.name, package, &objects, &registry_times)?;
        packages.push(LockedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            state: package.state,
            crate_sha256: package.crate_sha256.clone(),
            source_row_sha256: package.source_row_sha256.clone(),
            index_row_sha256: package.index_row_sha256.clone(),
            admission_sha256: package.admission_sha256.clone(),
            admitted_at,
            source: package.source.clone(),
        });
    }
    let migrated_lock = RegistryLock {
        schema: 5,
        registry: LockedRegistry {
            name: v4.registry.name.clone(),
            index: v4.registry.index.clone(),
            download: v4.registry.download.clone(),
            audience: Audience::Public,
        },
        names: v4.names,
        packages,
    };
    let canonical = serialize_lock(&migrated_lock)?;
    fs::write(&lock_path, &canonical)
        .with_context(|| format!("write generated lock {}", lock_path.display()))?;
    Ok(migrated_lock)
}

/// Replaces the schema-1 download catalog with the derived schema-2 catalog.
fn replace_download_catalog(input: &Path, output: &Path) -> Result<()> {
    let input_downloads = input.join(DOWNLOAD_CATALOG_FILE);
    let v1_bytes = fs::read(&input_downloads)
        .with_context(|| format!("read download catalog {}", input_downloads.display()))?;
    let v1: V1DownloadCatalog = serde_json::from_slice(&v1_bytes)
        .with_context(|| format!("parse download catalog {}", input_downloads.display()))?;
    ensure!(
        v1.schema == 1,
        "download catalog {} must use schema 1, found {}",
        input_downloads.display(),
        v1.schema
    );

    let mut locks = Vec::new();
    for registry in fs::read_dir(output).with_context(|| format!("read {}", output.display()))? {
        let path = registry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("lock") {
            continue;
        }
        let bytes =
            fs::read(&path).with_context(|| format!("read generated lock {}", path.display()))?;
        let lock: RegistryLock = toml::from_slice(&bytes)
            .with_context(|| format!("parse generated lock {}", path.display()))?;
        locks.push(lock);
    }

    let mut routes = Vec::new();
    for lock in &locks {
        for package in &lock.packages {
            routes.push(DownloadRoute {
                registry: lock.registry.name.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
                sha256: package.crate_sha256.clone(),
                delivery: match &package.source {
                    LockedSource::CratesIo {} => Delivery::Redirect {
                        url: crate::download::download_url(
                            &lock.registry.name,
                            &package.name,
                            &package.version,
                            &package.crate_sha256,
                        ),
                    },
                    LockedSource::GitTag { .. } => Delivery::Retained {
                        path: crate::download::retained_object_path(
                            &lock.registry.name,
                            &package.crate_sha256,
                        ),
                    },
                },
            });
        }
    }
    let downloads = DownloadCatalog::from_routes(routes);
    let canonical = downloads.canonical_bytes()?;
    let output_downloads = output.join(DOWNLOAD_CATALOG_FILE);
    fs::write(&output_downloads, &canonical)
        .with_context(|| format!("write download catalog {}", output_downloads.display()))?;

    verify_v1_routes_covered(&v1, &downloads)
}

/// Verifies every schema-1 route is preserved with an equivalent schema-2 delivery.
fn verify_v1_routes_covered(v1: &V1DownloadCatalog, v2: &DownloadCatalog) -> Result<()> {
    let v2_index = v2
        .routes
        .iter()
        .map(|route| {
            (
                (
                    route.registry.as_str(),
                    route.name.as_str(),
                    &route.version,
                    route.sha256.as_str(),
                ),
                &route.delivery,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for route in &v1.routes {
        let delivery = v2_index
            .get(&(
                route.registry.as_str(),
                route.name.as_str(),
                &route.version,
                route.sha256.as_str(),
            ))
            .with_context(|| {
                format!(
                    "schema-1 route {}/{}/{} is missing from the schema-2 catalog",
                    route.registry, route.name, route.version
                )
            })?;
        let expected_redirect = route.source == V1DownloadSource::CratesIo;
        let actual_redirect = matches!(delivery, Delivery::Redirect { .. });
        ensure!(
            expected_redirect == actual_redirect,
            "schema-1 route {}/{}/{} delivery class changed",
            route.registry,
            route.name,
            route.version
        );
    }
    Ok(())
}

/// Summary of one in-place retained-delivery migration.
#[derive(Debug)]
pub struct MigrateRetainedDeliverySummary {
    /// Root registry declarations processed.
    pub registries: usize,
    /// Whether any catalog file changed.
    pub changed: bool,
    /// Download routes with retained delivery after the migration.
    pub retained_routes: usize,
    /// Total download routes after the migration.
    pub total_routes: usize,
}

/// Declares `delivery = "retained"` on every root registry and recomputes the download catalog in place.
///
/// Each root-level registry file is edited with `toml_edit` so comments and formatting survive, and
/// `downloads.json` is rewritten to exactly the bytes `DownloadCatalog::from_catalog` derives from
/// the edited declarations, so later strict loads and lock reconciliations accept the result.
/// Archive objects are deliberately not verified here: retained bodies are imported afterwards with
/// `archive-import`, and check/render/serve fail closed until that import lands. The reconciler's
/// `CatalogGuard` is private to `lock.rs` and is therefore intentionally not held.
///
/// # Errors
///
/// Returns an error for any unsafe root, malformed registry, failed edit validation, missing
/// generated lock, or a failed strict catalog or policy gate on the migrated result.
pub fn migrate_retained_delivery(catalog_root: &Path) -> Result<MigrateRetainedDeliverySummary> {
    let mut registry_paths = Vec::<PathBuf>::new();
    for entry in
        fs::read_dir(catalog_root).with_context(|| format!("read {}", catalog_root.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            registry_paths.push(path);
        }
    }
    registry_paths.sort();

    let mut changed = false;
    for path in &registry_paths {
        let raw = fs::read(path).with_context(|| format!("read registry {}", path.display()))?;
        let text = String::from_utf8(raw)
            .with_context(|| format!("registry {} is not UTF-8", path.display()))?;
        let mut document = text
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("parse registry {}", path.display()))?;
        let registry = document
            .get_mut("registry")
            .and_then(|value| value.as_table_mut())
            .with_context(|| format!("registry {} has no [registry] table", path.display()))?;
        registry.insert("delivery", toml_edit::value("retained"));
        let migrated = document.to_string();
        if migrated == text {
            continue;
        }
        write_bytes_when_changed(path, migrated.as_bytes())?;
        changed = true;
        let inputs = load_registry_inputs(catalog_root)?;
        let input = inputs
            .iter()
            .find(|input| input.path == *path)
            .with_context(|| format!("reload edited registry {}", path.display()))?;
        validate_input_for_update(input)
            .with_context(|| format!("validate edited registry {}", path.display()))?;
    }

    let inputs = load_registry_inputs(catalog_root)?;
    let catalog = catalog_from_inputs(catalog_root, &inputs)?;
    let downloads = DownloadCatalog::from_catalog(&catalog);
    let canonical = downloads.canonical_bytes()?;
    let downloads_path = catalog_root.join(DOWNLOAD_CATALOG_FILE);
    changed |= write_bytes_when_changed(&downloads_path, &canonical)?;

    let catalog = crate::schema::Catalog::load(catalog_root)
        .with_context(|| format!("validate migrated catalog {}", catalog_root.display()))?;
    validate_catalog(&catalog)
        .with_context(|| format!("validate migrated catalog {}", catalog_root.display()))?;

    let total_routes = downloads.routes.len();
    let retained_routes = downloads
        .routes
        .iter()
        .filter(|route| route.delivery.is_retained())
        .count();
    Ok(MigrateRetainedDeliverySummary {
        registries: registry_paths.len(),
        changed,
        retained_routes,
        total_routes,
    })
}

/// Atomically replaces one catalog file when its bytes differ.
///
/// Reports whether the file changed. Replacements land through a same-directory temporary file
/// plus `fs::rename`, so readers observe either the previous or the new bytes and a failed write
/// never truncates the catalog file.
///
/// # Errors
///
/// Returns an error when the temporary file cannot be written, synced, or renamed into place.
fn write_bytes_when_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(false);
        }
    }
    let parent = path
        .parent()
        .with_context(|| format!("file {} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .with_context(|| format!("file name {} is not valid UTF-8", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut file = fs::File::create(&temporary)
        .with_context(|| format!("create temporary {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write temporary {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync temporary {}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path).with_context(|| format!("install {}", path.display()))?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(true)
}
