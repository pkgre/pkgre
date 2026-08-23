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
use crate::index::{IndexRecord, index_path};
use crate::policy::{Policy, validate_catalog};
use crate::schema::{
    Approval, Catalog, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD, RELEASE_SCHEMA_VERSION, Source,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Name of the deterministic release manifest within a rendered site.
pub const RELEASE_MANIFEST: &str = "release.json";

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Release {
    schema: u32,
    cname: String,
    registries: Vec<ReleaseRegistry>,
    packages: Vec<ReleasePackage>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRegistry {
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
    packages: Vec<ReleasePackage>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyReleaseRegistry {
    name: String,
    index: String,
    #[serde(rename = "may-depend-on")]
    may_depend_on: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleasePackage {
    registry: String,
    name: String,
    version: Version,
    archive_sha256: String,
    index_record_sha256: String,
    yanked: bool,
    source: ReleaseSource,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ReleaseSource {
    CratesIo,
    GitTag {
        repository: String,
        tag: String,
        commit: String,
        package: String,
        subdir: String,
    },
}

/// Renders a complete immutable sparse-registry site at a new path.
///
/// # Errors
///
/// Returns an error for invalid policy or artifacts, unsafe filesystem state, dependency-layer violations, or I/O failures. An existing output path is never overwritten.
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
    policy: &Policy,
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
                policy.permits_dependency(&approval.registry, &home),
                "{} {} in {} may not depend on {package} in {home}",
                approval.name,
                approval.version,
                approval.registry
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

/// Requires a new rendered release to retain every previously published package identity and immutable field.
///
/// Curator-owned `yanked` state may change. New packages may be added. Package removal or archive, metadata, registry, or source mutation fails closed.
///
/// # Errors
///
/// Returns an error for malformed release manifests, duplicate package identities, removals, or immutable-field changes.
pub fn verify_monotonic(previous_site: &Path, next_site: &Path) -> Result<()> {
    let previous = load_release(&previous_site.join(RELEASE_MANIFEST))?;
    let next = load_release(&next_site.join(RELEASE_MANIFEST))?;
    ensure!(
        next.schema == RELEASE_SCHEMA_VERSION
            && matches!(previous.schema, 1 | RELEASE_SCHEMA_VERSION),
        "unsupported release manifest schema transition {} -> {}",
        previous.schema,
        next.schema
    );
    ensure!(
        previous.cname == next.cname,
        "CNAME changed across releases"
    );
    validate_registry_transition(&previous, &next)?;
    let next_packages = package_map(&next.packages)?;
    for prior in &previous.packages {
        let key = release_key(prior);
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
    package_map(&previous.packages)?;
    Ok(())
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
            may_depend_on: registry.may_depend_on.clone(),
        })
        .collect();
    let packages = sorted_approvals(catalog)
        .into_iter()
        .map(|approval| ReleasePackage {
            registry: approval.registry.clone(),
            name: approval.name.clone(),
            version: approval.version.clone(),
            archive_sha256: approval.archive_sha256.clone(),
            index_record_sha256: approval.index_record_sha256.clone(),
            yanked: approval.is_removed(),
            source: match &approval.source {
                Source::CratesIo => ReleaseSource::CratesIo,
                Source::GitTag {
                    repository,
                    tag,
                    commit,
                    package,
                    subdir,
                    ..
                } => ReleaseSource::GitTag {
                    repository: repository.clone(),
                    tag: tag.clone(),
                    commit: commit.clone(),
                    package: package.clone(),
                    subdir: subdir.to_string_lossy().into_owned(),
                },
            },
        })
        .collect();
    Release {
        schema: RELEASE_SCHEMA_VERSION,
        cname: catalog.registries.cname.clone(),
        registries,
        packages,
    }
}

fn sorted_approvals(catalog: &Catalog) -> Vec<&Approval> {
    let mut approvals = catalog.approvals.iter().collect::<Vec<_>>();
    approvals.sort_by(|left, right| {
        (
            left.registry.as_str(),
            left.name.to_ascii_lowercase(),
            &left.version,
        )
            .cmp(&(
                right.registry.as_str(),
                right.name.to_ascii_lowercase(),
                &right.version,
            ))
    });
    approvals
}

fn load_release(path: &Path) -> Result<Release> {
    let bytes =
        fs::read(path).with_context(|| format!("read release manifest {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse release manifest {}", path.display()))?;
    match value.get("schema").and_then(serde_json::Value::as_u64) {
        Some(1) => {
            let legacy: LegacyRelease = serde_json::from_value(value)
                .with_context(|| format!("parse schema-1 release manifest {}", path.display()))?;
            Ok(Release {
                schema: legacy.schema,
                cname: legacy.cname,
                registries: legacy
                    .registries
                    .into_iter()
                    .map(|registry| ReleaseRegistry {
                        name: registry.name,
                        index: registry.index,
                        download: legacy.download.clone(),
                        may_depend_on: registry.may_depend_on,
                    })
                    .collect(),
                packages: legacy.packages,
            })
        }
        Some(schema) if schema == u64::from(RELEASE_SCHEMA_VERSION) => {
            serde_json::from_value(value)
                .with_context(|| format!("parse release manifest {}", path.display()))
        }
        Some(schema) => bail!(
            "unsupported release manifest schema {schema} in {}",
            path.display()
        ),
        None => bail!("release manifest has no integer schema: {}", path.display()),
    }
}

fn validate_registry_transition(previous: &Release, next: &Release) -> Result<()> {
    ensure!(
        previous.registries.len() == next.registries.len(),
        "registry topology changed across releases"
    );
    for (previous_registry, next_registry) in previous.registries.iter().zip(&next.registries) {
        ensure!(
            previous_registry.name == next_registry.name
                && previous_registry.index == next_registry.index
                && previous_registry.may_depend_on == next_registry.may_depend_on,
            "registry topology changed across releases"
        );
        if previous.schema == RELEASE_SCHEMA_VERSION {
            ensure!(
                previous_registry.download == next_registry.download,
                "registry {:?} download changed across releases",
                previous_registry.name
            );
            continue;
        }
        let expected = match previous_registry.name.as_str() {
            "core" | "matrix" => MIRROR_DOWNLOAD,
            "pkgre" => PUBLISH_DOWNLOAD,
            name => bail!("unexpected registry {name:?} in schema-1 release migration"),
        };
        ensure!(
            previous_registry.download == PUBLISH_DOWNLOAD && next_registry.download == expected,
            "registry {:?} has an unsupported schema-1 download migration",
            previous_registry.name
        );
    }
    Ok(())
}

fn package_map(
    packages: &[ReleasePackage],
) -> Result<BTreeMap<(&str, &str, Version), &ReleasePackage>> {
    let mut result = BTreeMap::new();
    for package in packages {
        ensure!(
            result.insert(release_key(package), package).is_none(),
            "duplicate package identity in release manifest: {} {} in {}",
            package.name,
            package.version,
            package.registry
        );
    }
    Ok(result)
}

fn release_key(package: &ReleasePackage) -> (&str, &str, Version) {
    (
        package.registry.as_str(),
        package.name.as_str(),
        package.version.clone(),
    )
}

fn same_immutable_package(left: &ReleasePackage, right: &ReleasePackage) -> bool {
    left.registry == right.registry
        && left.name == right.name
        && left.version == right.version
        && left.archive_sha256 == right.archive_sha256
        && left.index_record_sha256 == right.index_record_sha256
        && left.source == right.source
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

    fn release_registries(downloads: [&str; 3]) -> Vec<ReleaseRegistry> {
        ["core", "matrix", "pkgre"]
            .into_iter()
            .zip(downloads)
            .map(|(name, download)| ReleaseRegistry {
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
        release_registries([PUBLISH_DOWNLOAD; 3])
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
        let root = std::env::temp_dir().join(format!(
            "pkgre-release-migration-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
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
        let mut next_release = Release {
            schema: RELEASE_SCHEMA_VERSION,
            cname: "rust.pkg.re".to_owned(),
            registries: release_registries([MIRROR_DOWNLOAD, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD]),
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
    fn schema_two_downloads_are_immutable_and_cannot_reverse_to_schema_one() {
        let root = std::env::temp_dir().join(format!(
            "pkgre-release-schema-two-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let previous = root.join("previous");
        let next = root.join("next");
        let release = Release {
            schema: RELEASE_SCHEMA_VERSION,
            cname: "rust.pkg.re".to_owned(),
            registries: release_registries([MIRROR_DOWNLOAD, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD]),
            packages: Vec::new(),
        };
        write_manifest(&previous, &release);
        let mut changed = release;
        changed.registries[0].download = PUBLISH_DOWNLOAD.to_owned();
        write_manifest(&next, &changed);
        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("download changed"));

        let legacy = LegacyRelease {
            schema: 1,
            cname: "rust.pkg.re".to_owned(),
            download: PUBLISH_DOWNLOAD.to_owned(),
            registries: legacy_registries(),
            packages: Vec::new(),
        };
        fs::write(
            next.join(RELEASE_MANIFEST),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let error = verify_monotonic(&previous, &next).unwrap_err();
        assert!(format!("{error:#}").contains("unsupported release manifest schema transition"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn content_comparison_detects_equal_and_different_files() {
        let root = std::env::temp_dir().join(format!(
            "pkgre-render-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("one"), b"same").unwrap();
        fs::write(root.join("two"), b"same").unwrap();
        assert!(files_equal(&root.join("one"), &root.join("two")).unwrap());
        fs::write(root.join("two"), b"changed").unwrap();
        assert!(!files_equal(&root.join("one"), &root.join("two")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }
}
