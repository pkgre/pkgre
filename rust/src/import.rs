//! Exact crates.io archive, sparse-history, and API resolution for declarative reconciliation.

use std::ffi::OsStr;
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use tracing::debug;

use crate::artifact::sha256_bytes;
use crate::index::{IndexRecord, index_path};
use crate::policy::{validate_package_name, validate_sha256};
use crate::schema::version_identity;

const SPARSE_ROOT: &str = "https://index.crates.io";
const ARCHIVE_ROOT: &str = "https://static.crates.io/crates";
const API_ROOT: &str = "https://crates.io/api/v1/crates";
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;
const MAX_FETCH_BYTES: usize = 100 * 1024 * 1024;
const USER_AGENT: &str = concat!(
    "pkgre-indexer/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/pkgre/pkgre; curated-registry update planner)"
);
static LAST_API_REQUEST: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();

/// One strictly parsed row from a complete crates.io sparse-index observation.
#[derive(Clone, Debug)]
pub struct SparseIndexRow {
    /// Exact source row bytes, including a trailing newline when supplied upstream.
    pub bytes: Vec<u8>,
    /// Strict parsed record.
    pub record: IndexRecord,
}

/// Complete observed sparse-index file for one crates.io package name.
#[derive(Clone, Debug)]
pub struct CratesIoHistory {
    /// Exact complete sparse response.
    pub bytes: Vec<u8>,
    /// SHA-256 of the complete sparse response.
    pub sha256: String,
    /// Every strictly parsed row in upstream order.
    pub rows: Vec<SparseIndexRow>,
}

/// Raw crates.io API evidence retained by update planning.
#[derive(Clone, Debug)]
pub struct CratesIoApiEvidence {
    /// Exact response bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of the exact response.
    pub sha256: String,
}

/// Exact upstream bytes and hashes for one crates.io package identity.
#[derive(Debug)]
pub struct CratesIoMaterialization {
    /// Exact `.crate` archive bytes.
    pub archive_bytes: Vec<u8>,
    /// Exact matching crates.io sparse-index row bytes.
    pub source_row_bytes: Vec<u8>,
    /// SHA-256 of `archive_bytes`.
    pub archive_sha256: String,
    /// SHA-256 of `source_row_bytes`.
    pub source_row_sha256: String,
}

/// Fetches and strictly parses the complete sparse history for one package.
///
/// # Errors
///
/// Returns an error for an invalid name, network failure, malformed row, wrong package name, or duplicate Cargo identity.
pub fn fetch_crates_io_history(name: &str) -> Result<CratesIoHistory> {
    validate_package_name(name).with_context(|| format!("invalid crates.io package {name:?}"))?;
    let sparse_url = format!("{SPARSE_ROOT}/{}", index_path(name));
    let bytes = fetch(&sparse_url, "fetch crates.io sparse index", MAX_FETCH_BYTES)?;
    parse_crates_io_history(name, bytes)
}

/// Fetches one exact archive and verifies the sparse-index checksum.
///
/// # Errors
///
/// Returns an error for an invalid identity/checksum, network failure, or checksum mismatch.
pub fn fetch_crates_io_archive(
    name: &str,
    version: &Version,
    expected_checksum: &str,
) -> Result<Vec<u8>> {
    validate_package_name(name).with_context(|| format!("invalid crates.io package {name:?}"))?;
    validate_sha256(expected_checksum).context("invalid upstream archive checksum")?;
    let archive_url = format!("{ARCHIVE_ROOT}/{name}/{name}-{version}.crate");
    let archive_bytes = fetch(&archive_url, "fetch crates.io archive", MAX_FETCH_BYTES)?;
    let actual = sha256_bytes(&archive_bytes);
    ensure!(
        actual == expected_checksum,
        "crates.io archive checksum mismatch for {name} {version}: index says {expected_checksum}, downloaded {actual}"
    );
    Ok(archive_bytes)
}

/// Fetches one package's public crates.io API response with a descriptive user agent and a process-wide one-request-per-second interval.
///
/// # Errors
///
/// Returns an error for an invalid name or network failure.
pub fn fetch_crates_io_api(name: &str) -> Result<CratesIoApiEvidence> {
    validate_package_name(name).with_context(|| format!("invalid crates.io package {name:?}"))?;
    wait_for_api_interval()?;
    let url = format!("{API_ROOT}/{name}");
    let bytes = fetch(&url, "fetch crates.io package API", MAX_FETCH_BYTES)?;
    let sha256 = sha256_bytes(&bytes);
    Ok(CratesIoApiEvidence { bytes, sha256 })
}

/// Resolves one exact crates.io package without mutating the catalog.
///
/// The exact upstream sparse row and archive bytes are retained. An upstream-yanked row is rejected because a desired mirrored package is rendered active.
///
/// # Errors
///
/// Returns an error for an invalid identity, network failure, missing or ambiguous sparse row, upstream yank, malformed metadata, or checksum mismatch.
pub fn resolve_crates_io(name: &str, version: &Version) -> Result<CratesIoMaterialization> {
    let history = fetch_crates_io_history(name)?;
    materialize_from_history(name, version, &history)
}

/// Materializes an exact row/archive from a previously fetched complete history.
///
/// # Errors
///
/// Returns an error for a missing/ambiguous/yanked row or archive checksum failure.
pub fn materialize_from_history(
    name: &str,
    version: &Version,
    history: &CratesIoHistory,
) -> Result<CratesIoMaterialization> {
    let row = select_index_record(&history.rows, name, version)?;
    ensure!(
        !row.record.yanked()?,
        "crates.io package {name} {version} is yanked upstream and cannot be activated"
    );
    let expected_checksum = row.record.checksum()?.to_owned();
    let archive_bytes = fetch_crates_io_archive(name, version, &expected_checksum)?;
    let archive_sha256 = sha256_bytes(&archive_bytes);
    let source_row_bytes = row.bytes.clone();
    let source_row_sha256 = sha256_bytes(&source_row_bytes);
    Ok(CratesIoMaterialization {
        archive_bytes,
        source_row_bytes,
        archive_sha256,
        source_row_sha256,
    })
}

fn parse_crates_io_history(name: &str, bytes: Vec<u8>) -> Result<CratesIoHistory> {
    let mut rows = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for (line_number, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record = IndexRecord::parse(line).with_context(|| {
            format!("parse crates.io sparse row {} for {name}", line_number + 1)
        })?;
        record.validate_structure().with_context(|| {
            format!(
                "validate crates.io sparse row {} for {name}",
                line_number + 1
            )
        })?;
        ensure!(
            record.name()? == name,
            "crates.io sparse row {} names a package other than {name:?}",
            line_number + 1
        );
        let version = record.version()?;
        ensure!(
            identities.insert(version_identity(&version)),
            "crates.io sparse index repeats Cargo identity {name} {version}"
        );
        rows.push(SparseIndexRow {
            bytes: line.to_vec(),
            record,
        });
    }
    ensure!(
        !rows.is_empty(),
        "crates.io sparse index for {name} is empty"
    );
    Ok(CratesIoHistory {
        sha256: sha256_bytes(&bytes),
        bytes,
        rows,
    })
}

fn select_index_record<'a>(
    rows: &'a [SparseIndexRow],
    name: &str,
    version: &Version,
) -> Result<&'a SparseIndexRow> {
    let matching = rows
        .iter()
        .filter(|row| {
            row.record.name().is_ok_and(|candidate| candidate == name)
                && row
                    .record
                    .version()
                    .is_ok_and(|candidate| candidate == *version)
        })
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "crates.io sparse index contains {} rows for {name} {version}; expected exactly one",
        matching.len()
    );
    Ok(matching[0])
}

fn wait_for_api_interval() -> Result<()> {
    let lock = LAST_API_REQUEST.get_or_init(|| Mutex::new(None));
    let mut last = lock
        .lock()
        .map_err(|_| anyhow::anyhow!("crates.io API rate-limit lock is poisoned"))?;
    if let Some(previous) = *last
        && let Some(remaining) = Duration::from_secs(1).checked_sub(previous.elapsed())
    {
        std::thread::sleep(remaining);
    }
    *last = Some(Instant::now());
    Ok(())
}

fn fetch(url: &str, action: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let max_bytes_argument = max_bytes.to_string();
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
        OsStr::new(&max_bytes_argument),
        OsStr::new("--user-agent"),
        OsStr::new(USER_AGENT),
        OsStr::new(url),
    ]);
    command
        .env("CURL_HOME", "/dev/null")
        .env_remove("CARGO_REGISTRY_TOKEN")
        .env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN")
        .env_remove("CARGO_HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY");
    debug!(%url, "fetching public package artifact");
    let output = command
        .output()
        .with_context(|| format!("{action}: start curl"))?;
    require_success(&output, action)?;
    ensure!(
        output.stdout.len() <= max_bytes,
        "{action}: response exceeded {max_bytes} bytes"
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn history(contents: &[u8]) -> CratesIoHistory {
        parse_crates_io_history("demo", contents.to_vec()).unwrap()
    }

    fn row(version: &str, extra: &str) -> String {
        format!(
            "{{\"name\":\"demo\",\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"{}\",\"features\":{{}},\"yanked\":false{extra}}}\n",
            "00".repeat(32)
        )
    }

    #[test]
    fn exact_sparse_row_bytes_are_preserved() {
        let input = format!("{}{}", row("1.0.0", ""), row("2.0.0", ",\"extra\":true"));
        let parsed = history(input.as_bytes());
        let selected =
            select_index_record(&parsed.rows, "demo", &Version::parse("2.0.0").unwrap()).unwrap();
        assert_eq!(selected.bytes, row("2.0.0", ",\"extra\":true").as_bytes());
        assert_eq!(parsed.bytes, input.as_bytes());
        assert_eq!(parsed.sha256, sha256_bytes(input.as_bytes()));
    }

    #[test]
    fn duplicate_sparse_rows_are_rejected() {
        let input = format!("{}{}", row("1.0.0", ""), row("1.0.0", ""));
        assert!(parse_crates_io_history("demo", input.into_bytes()).is_err());
    }

    #[test]
    fn sparse_rows_for_another_name_are_rejected() {
        let input = row("1.0.0", "").replace("\"demo\"", "\"other\"");
        assert!(parse_crates_io_history("demo", input.into_bytes()).is_err());
    }
}
