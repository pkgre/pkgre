//! Candidate import of exact crates.io archives and sparse-index rows.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use crate::artifact::{require_absent, sha256_bytes};
use crate::index::{IndexRecord, index_path};
use crate::policy::{validate_package_name, validate_sha256};
use crate::schema::SCHEMA_VERSION;

const SPARSE_ROOT: &str = "https://index.crates.io";
const ARCHIVE_ROOT: &str = "https://static.crates.io/crates";
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;

/// Sanitized, provenance-free list of exact crates.io versions to fetch for review.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CratesIoProposal {
    /// Schema version.
    pub schema: u32,
    /// Exact package candidates.
    pub packages: Vec<CratesIoPackage>,
}

/// One exact crates.io package candidate and its intended curated home.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CratesIoPackage {
    /// Destination registry: `core` or `matrix`.
    pub registry: String,
    /// Cargo package name.
    pub name: String,
    /// Exact package version.
    pub version: Version,
}

#[derive(Debug, Serialize)]
struct CandidateApprovals<'a> {
    schema: u32,
    registry: &'a str,
    packages: Vec<CandidateApproval<'a>>,
}

#[derive(Debug, Serialize)]
struct CandidateApproval<'a> {
    name: &'a str,
    version: &'a Version,
    archive_sha256: &'a str,
    index_record_sha256: &'a str,
    yanked: bool,
    source: CandidateSource<'a>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CandidateSource<'a> {
    CratesIo { index_record: &'a Path },
}

#[derive(Debug, Serialize)]
struct CandidateArtifacts<'a> {
    schema: u32,
    artifacts: Vec<CandidateArtifact<'a>>,
}

#[derive(Debug, Serialize)]
struct CandidateArtifact<'a> {
    registry: &'a str,
    name: &'a str,
    version: &'a Version,
    archive: &'a Path,
    index_record: &'a Path,
}

#[derive(Debug, Serialize)]
struct CandidateHomes<'a> {
    schema: u32,
    homes: BTreeMap<&'a str, &'a str>,
}

#[derive(Debug)]
struct ImportedPackage {
    package: CratesIoPackage,
    archive_sha256: String,
    index_record_sha256: String,
    archive: PathBuf,
    index_record: PathBuf,
    yanked: bool,
}

/// Loads and validates a sanitized crates.io candidate proposal.
///
/// # Errors
///
/// Returns an error for missing, malformed, unsupported, duplicate, colliding, or cross-home package declarations.
pub fn load_crates_io_proposal(path: &Path) -> Result<CratesIoProposal> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read crates.io proposal {}", path.display()))?;
    let proposal: CratesIoProposal = toml::from_str(&contents)
        .with_context(|| format!("parse crates.io proposal {}", path.display()))?;
    validate_proposal(&proposal)?;
    Ok(proposal)
}

/// Fetches exact crates.io sparse rows and archives into a non-approved candidate tree.
///
/// Candidate declarations contain package identities only, never root-project provenance. This operation never mutates an approved catalog.
///
/// # Errors
///
/// Returns an error for invalid input, network failure, missing or ambiguous upstream rows, checksum mismatch, or unsafe output state.
pub fn candidate_crates_io(proposal: &CratesIoProposal, output: &Path) -> Result<()> {
    validate_proposal(proposal)?;
    require_absent(output)?;
    fs::create_dir(output).with_context(|| format!("create output {}", output.display()))?;
    let result = candidate_crates_io_into(proposal, output);
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn candidate_crates_io_into(proposal: &CratesIoProposal, output: &Path) -> Result<()> {
    let mut packages = proposal.packages.clone();
    packages.sort_by(|left, right| {
        (left.registry.as_str(), left.name.as_str(), &left.version).cmp(&(
            right.registry.as_str(),
            right.name.as_str(),
            &right.version,
        ))
    });
    let mut imported = Vec::with_capacity(packages.len());
    for (position, package) in packages.into_iter().enumerate() {
        info!(
            package = package.name,
            version = %package.version,
            current = position + 1,
            total = proposal.packages.len(),
            "fetching crates.io candidate"
        );
        imported.push(import_package(package, output)?);
    }
    write_declarations(&imported, output)
}

fn import_package(package: CratesIoPackage, output: &Path) -> Result<ImportedPackage> {
    let sparse_url = format!("{SPARSE_ROOT}/{}", index_path(&package.name));
    let sparse = fetch(&sparse_url, "fetch crates.io sparse index")?;
    let index_bytes = select_index_record(&sparse, &package.name, &package.version)?;
    let record = IndexRecord::parse(&index_bytes)?;
    record.validate_structure()?;
    ensure!(
        record.name()? == package.name,
        "upstream package name changed"
    );
    ensure!(
        record.version()? == package.version,
        "upstream package version changed"
    );
    let expected_checksum = record.checksum()?.to_owned();
    validate_sha256(&expected_checksum).context("invalid upstream archive checksum")?;
    let yanked = record.yanked()?;

    let archive_url = format!(
        "{ARCHIVE_ROOT}/{name}/{name}-{version}.crate",
        name = package.name,
        version = package.version
    );
    let archive_bytes = fetch(&archive_url, "fetch crates.io archive")?;
    let archive_sha256 = sha256_bytes(&archive_bytes);
    ensure!(
        archive_sha256 == expected_checksum,
        "crates.io archive checksum mismatch for {} {}: index says {expected_checksum}, downloaded {archive_sha256}",
        package.name,
        package.version
    );
    let index_record_sha256 = sha256_bytes(&index_bytes);
    let archive = PathBuf::from("archives").join(format!("{archive_sha256}.crate"));
    let index_record = PathBuf::from("upstream")
        .join(&package.registry)
        .join(index_path(&package.name))
        .join(format!("{}.json", package.version));
    write_same_or_new(&output.join(&archive), &archive_bytes)?;
    write_same_or_new(&output.join(&index_record), &index_bytes)?;
    Ok(ImportedPackage {
        package,
        archive_sha256,
        index_record_sha256,
        archive,
        index_record,
        yanked,
    })
}

fn write_declarations(imported: &[ImportedPackage], output: &Path) -> Result<()> {
    let mut homes = BTreeMap::new();
    for package in imported {
        homes.insert(
            package.package.name.as_str(),
            package.package.registry.as_str(),
        );
    }
    let homes_toml = toml::to_string_pretty(&CandidateHomes {
        schema: SCHEMA_VERSION,
        homes,
    })
    .context("serialize candidate homes")?;
    write_new(&output.join("homes.toml"), homes_toml.as_bytes())?;

    for registry in ["core", "matrix"] {
        let packages = imported
            .iter()
            .filter(|package| package.package.registry == registry)
            .map(|package| CandidateApproval {
                name: &package.package.name,
                version: &package.package.version,
                archive_sha256: &package.archive_sha256,
                index_record_sha256: &package.index_record_sha256,
                yanked: package.yanked,
                source: CandidateSource::CratesIo {
                    index_record: &package.index_record,
                },
            })
            .collect();
        let toml = toml::to_string_pretty(&CandidateApprovals {
            schema: SCHEMA_VERSION,
            registry,
            packages,
        })
        .context("serialize candidate approvals")?;
        write_new(
            &output.join("approvals").join(format!("{registry}.toml")),
            toml.as_bytes(),
        )?;
    }

    let artifacts = imported
        .iter()
        .map(|package| CandidateArtifact {
            registry: &package.package.registry,
            name: &package.package.name,
            version: &package.package.version,
            archive: &package.archive,
            index_record: &package.index_record,
        })
        .collect();
    let artifacts_toml = toml::to_string_pretty(&CandidateArtifacts {
        schema: SCHEMA_VERSION,
        artifacts,
    })
    .context("serialize candidate artifact map")?;
    write_new(&output.join("artifacts.toml"), artifacts_toml.as_bytes())
}

fn validate_proposal(proposal: &CratesIoProposal) -> Result<()> {
    ensure!(
        proposal.schema == SCHEMA_VERSION,
        "unsupported crates.io proposal schema {}; expected {SCHEMA_VERSION}",
        proposal.schema
    );
    ensure!(!proposal.packages.is_empty(), "proposal has no packages");
    let mut identities = BTreeSet::new();
    let mut homes = BTreeMap::<String, String>::new();
    let mut collision_names = BTreeMap::<String, String>::new();
    for package in &proposal.packages {
        validate_package_name(&package.name)
            .with_context(|| format!("invalid candidate package name {:?}", package.name))?;
        ensure!(
            matches!(package.registry.as_str(), "core" | "matrix"),
            "crates.io candidate {} {} has unsupported registry {:?}",
            package.name,
            package.version,
            package.registry
        );
        let version_identity = (
            package.version.major,
            package.version.minor,
            package.version.patch,
            package.version.pre.to_string(),
        );
        ensure!(
            identities.insert((package.name.to_ascii_lowercase(), version_identity)),
            "duplicate crates.io candidate {} {} (build metadata does not distinguish versions)",
            package.name,
            package.version
        );
        if let Some(previous) = homes.insert(package.name.clone(), package.registry.clone()) {
            ensure!(
                previous == package.registry,
                "package {:?} is assigned to both {previous:?} and {:?}",
                package.name,
                package.registry
            );
        }
        let collision = package.name.to_ascii_lowercase().replace('-', "_");
        if let Some(previous) = collision_names.insert(collision, package.name.clone()) {
            ensure!(
                previous == package.name,
                "package names {previous:?} and {:?} collide under Cargo normalization",
                package.name
            );
        }
    }
    Ok(())
}

fn select_index_record(contents: &[u8], name: &str, version: &Version) -> Result<Vec<u8>> {
    let mut matching = Vec::new();
    for line in contents.split_inclusive(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = serde_json::from_slice(line).with_context(|| {
            format!("parse crates.io sparse row while selecting {name} {version}")
        })?;
        let row_name = value.get("name").and_then(Value::as_str);
        let row_version = value.get("vers").and_then(Value::as_str);
        if row_name == Some(name) && row_version == Some(version.to_string().as_str()) {
            matching.push(line.to_vec());
        }
    }
    ensure!(
        matching.len() == 1,
        "crates.io sparse index contains {} rows for {name} {version}; expected exactly one",
        matching.len()
    );
    Ok(matching.pop().expect("length checked"))
}

fn fetch(url: &str, action: &str) -> Result<Vec<u8>> {
    let mut command = Command::new("curl");
    command.args([
        OsStr::new("--disable"),
        OsStr::new("--fail"),
        OsStr::new("--silent"),
        OsStr::new("--show-error"),
        OsStr::new("--location"),
        OsStr::new("--max-redirs"),
        OsStr::new("5"),
        OsStr::new("--proto"),
        OsStr::new("=https"),
        OsStr::new("--proto-redir"),
        OsStr::new("=https"),
        OsStr::new("--tlsv1.2"),
        OsStr::new("--connect-timeout"),
        OsStr::new("30"),
        OsStr::new("--max-time"),
        OsStr::new("300"),
        OsStr::new("--retry"),
        OsStr::new("3"),
        OsStr::new("--retry-all-errors"),
        OsStr::new("--max-filesize"),
        OsStr::new("104857600"),
        OsStr::new(url),
    ]);
    command
        .env("CURL_HOME", "/dev/null")
        .env_remove("CARGO_REGISTRY_TOKEN")
        .env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN");
    debug!(%url, "fetching public package artifact");
    let output = command
        .output()
        .with_context(|| format!("{action}: start curl"))?;
    require_success(&output, action)?;
    Ok(output.stdout)
}

fn require_success(output: &Output, action: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stdout = bounded_lossy(&output.stdout);
    let stderr = bounded_lossy(&output.stderr);
    bail!(
        "{action}: curl exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    )
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_COMMAND_ERROR_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn write_same_or_new(path: &Path, contents: &[u8]) -> Result<()> {
    match fs::read(path) {
        Ok(existing) => {
            ensure!(
                existing == contents,
                "content-addressed candidate path has different bytes: {}",
                path.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => write_new(path, contents),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_sparse_row_bytes_are_preserved() {
        let input = b"{\"name\":\"demo\",\"vers\":\"1.0.0\"}\n{\"name\":\"demo\",\"vers\":\"2.0.0\",\"extra\":true}\n";
        let selected =
            select_index_record(input, "demo", &Version::parse("2.0.0").unwrap()).unwrap();
        assert_eq!(
            selected,
            b"{\"name\":\"demo\",\"vers\":\"2.0.0\",\"extra\":true}\n"
        );
    }

    #[test]
    fn proposal_rejects_cross_home_names() {
        let proposal = CratesIoProposal {
            schema: SCHEMA_VERSION,
            packages: vec![
                CratesIoPackage {
                    registry: "core".to_owned(),
                    name: "demo".to_owned(),
                    version: Version::parse("1.0.0").unwrap(),
                },
                CratesIoPackage {
                    registry: "matrix".to_owned(),
                    name: "demo".to_owned(),
                    version: Version::parse("2.0.0").unwrap(),
                },
            ],
        };
        assert!(validate_proposal(&proposal).is_err());
    }
}
