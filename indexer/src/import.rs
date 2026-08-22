//! Exact crates.io archive and sparse-row resolution for declarative reconciliation.

use std::ffi::OsStr;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde_json::Value;
use tracing::debug;

use crate::artifact::sha256_bytes;
use crate::index::{IndexRecord, index_path};
use crate::policy::{validate_package_name, validate_sha256};

const SPARSE_ROOT: &str = "https://index.crates.io";
const ARCHIVE_ROOT: &str = "https://static.crates.io/crates";
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;

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

/// Resolves one exact crates.io package without mutating the catalog.
///
/// The exact upstream sparse row and archive bytes are retained. An upstream-yanked row is rejected because a desired mirrored package is rendered active.
///
/// # Errors
///
/// Returns an error for an invalid identity, network failure, missing or ambiguous sparse row, upstream yank, malformed metadata, or checksum mismatch.
pub fn resolve_crates_io(name: &str, version: &Version) -> Result<CratesIoMaterialization> {
    validate_package_name(name).with_context(|| format!("invalid crates.io package {name:?}"))?;
    let sparse_url = format!("{SPARSE_ROOT}/{}", index_path(name));
    let sparse = fetch(&sparse_url, "fetch crates.io sparse index")?;
    let source_row_bytes = select_index_record(&sparse, name, version)?;
    let record = IndexRecord::parse(&source_row_bytes)?;
    record.validate_structure()?;
    ensure!(record.name()? == name, "upstream package name changed");
    ensure!(
        record.version()? == *version,
        "upstream package version changed"
    );
    ensure!(
        !record.yanked()?,
        "crates.io package {name} {version} is yanked upstream and cannot be activated"
    );
    let expected_checksum = record.checksum()?.to_owned();
    validate_sha256(&expected_checksum).context("invalid upstream archive checksum")?;

    let archive_url = format!("{ARCHIVE_ROOT}/{name}/{name}-{version}.crate");
    let archive_bytes = fetch(&archive_url, "fetch crates.io archive")?;
    let archive_sha256 = sha256_bytes(&archive_bytes);
    ensure!(
        archive_sha256 == expected_checksum,
        "crates.io archive checksum mismatch for {name} {version}: index says {expected_checksum}, downloaded {archive_sha256}"
    );
    let source_row_sha256 = sha256_bytes(&source_row_bytes);
    Ok(CratesIoMaterialization {
        archive_bytes,
        source_row_bytes,
        archive_sha256,
        source_row_sha256,
    })
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
    fn duplicate_sparse_rows_are_rejected() {
        let input =
            b"{\"name\":\"demo\",\"vers\":\"1.0.0\"}\n{\"name\":\"demo\",\"vers\":\"1.0.0\"}\n";
        assert!(select_index_record(input, "demo", &Version::parse("1.0.0").unwrap()).is_err());
    }
}
