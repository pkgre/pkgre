//! Bounded inert inspection of crates.io `.crate` tar-gzip archives.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

use anyhow::{Context, Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::artifact::sha256_bytes;

const TAR_BLOCK_BYTES: usize = 512;
const MAX_COMPRESSED_BYTES: usize = 100 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_COMPRESSION_RATIO: u64 = 200;
/// Largest accepted GNU long-name body, its NUL terminator included.
const MAX_LONG_NAME_BYTES: u64 = 4096;
/// Entry type of a GNU long-name header.
const GNU_LONG_NAME_TYPE: u8 = b'L';
/// Placeholder name GNU tar writes in the header of a long-name entry.
const GNU_LONG_NAME_PLACEHOLDER: &str = "././@LongLink";

/// Stable metadata for one regular archive file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ArchiveFile {
    /// UTF-8 path relative to the mandatory `<name>-<version>/` archive root.
    pub path: String,
    /// Exact file size.
    pub size: u64,
    /// Portable permission bits.
    pub mode: u32,
    /// SHA-256 of the file bytes.
    pub sha256: String,
    /// Whether the content contains a NUL byte or has a known prebuilt-binary suffix.
    pub binary: bool,
}

/// Publisher-provided Cargo VCS claim embedded in an archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct EmbeddedVcsInfo {
    /// Claimed exact Git object ID.
    pub commit: String,
    /// Optional repository-relative package path.
    pub path_in_vcs: Option<String>,
    /// Hash of the exact `.cargo_vcs_info.json` bytes.
    pub file_sha256: String,
}

/// Stable, content-only result of inert archive inspection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ArchiveAnalysis {
    /// Compressed `.crate` byte count.
    pub compressed_bytes: u64,
    /// Complete decompressed tar-stream byte count, including headers and padding.
    pub unpacked_bytes: u64,
    /// Regular files in canonical path order.
    pub files: Vec<ArchiveFile>,
    /// Security-relevant build/executable surface keyed by a stable descriptive identity.
    pub build_surface: BTreeMap<String, String>,
    /// Embedded publisher VCS claim, when present.
    pub vcs: Option<EmbeddedVcsInfo>,
}

/// Inspects one exact `.crate` archive without extracting or executing any content.
///
/// The parser accepts only one canonical root, regular files, and directories. It rejects traversal, absolute/non-canonical/non-UTF-8 paths, duplicate normalized paths, links, special/PAX/GNU-extension entries, unsafe mode bits, invalid tar checksums, concatenated nonzero data after the tar terminator, excessive sizes/counts, and compression ratios above 200:1.
///
/// A GNU long-name entry (`././@LongLink`, type `L`) is accepted as the path of the single file or directory entry that follows it, because Cargo's tar writer emits one for every member path over 100 bytes; the name it carries passes exactly the checks and limits a path in a header passes.
///
/// # Errors
///
/// Returns an error for an invalid expected identity, malformed or unsupported archive, or any resource/safety limit violation.
pub fn inspect_crate_archive(
    expected_name: &str,
    expected_version: &Version,
    archive: &[u8],
) -> Result<ArchiveAnalysis> {
    let (analysis, _) = inspect_with_limits(
        expected_name,
        expected_version,
        archive,
        ArchiveLimits::production(),
        &[],
    )?;
    Ok(analysis)
}

/// One `.crate` archive as a content comparison reads it.
pub(crate) struct ComparedArchive {
    /// Every regular file below the archive root, by path.
    pub(crate) files: BTreeMap<String, ArchiveFile>,
    /// The contents of the files the caller asked for, by path.
    pub(crate) contents: BTreeMap<String, Vec<u8>>,
}

/// Reads one `.crate` archive and captures the contents of the named files.
///
/// The archive is validated exactly as [`inspect_crate_archive`] validates it;
/// `wanted` names the files whose bytes the caller needs, since the analysis
/// keeps only their digests.
///
/// # Errors
///
/// Returns an error for an invalid expected identity, a malformed or
/// unsupported archive, or any resource or safety limit violation.
pub(crate) fn read_crate_archive(
    expected_name: &str,
    expected_version: &Version,
    archive: &[u8],
    wanted: &[&str],
) -> Result<ComparedArchive> {
    let (analysis, contents) = inspect_with_limits(
        expected_name,
        expected_version,
        archive,
        ArchiveLimits::production(),
        wanted,
    )?;
    Ok(ComparedArchive {
        files: analysis
            .files
            .into_iter()
            .map(|file| (file.path.clone(), file))
            .collect(),
        contents,
    })
}

#[derive(Clone, Copy)]
struct ArchiveLimits {
    compressed: usize,
    unpacked: u64,
    file: u64,
    entries: usize,
    ratio: u64,
}

impl ArchiveLimits {
    const fn production() -> Self {
        Self {
            compressed: MAX_COMPRESSED_BYTES,
            unpacked: MAX_UNPACKED_BYTES,
            file: MAX_FILE_BYTES,
            entries: MAX_ENTRIES,
            ratio: MAX_COMPRESSION_RATIO,
        }
    }
}

fn inspect_with_limits(
    expected_name: &str,
    expected_version: &Version,
    archive: &[u8],
    limits: ArchiveLimits,
    wanted: &[&str],
) -> Result<(ArchiveAnalysis, BTreeMap<String, Vec<u8>>)> {
    ensure!(!expected_name.is_empty(), "expected package name is empty");
    ensure!(!archive.is_empty(), "crate archive is empty");
    ensure!(
        archive.len() <= limits.compressed,
        "compressed crate archive exceeds {} bytes",
        limits.compressed
    );
    let compressed_bytes = u64::try_from(archive.len()).context("archive length exceeds u64")?;
    let decoder = MultiGzDecoder::new(archive);
    let mut reader = BoundedReader::new(decoder, limits.unpacked);
    let expected_root = format!("{expected_name}-{expected_version}");
    let mut contents = read_tar_entries(&mut reader, &expected_root, limits, wanted)?;
    require_zero_trailing_data(&mut reader)?;
    let unpacked_bytes = reader.bytes_read();
    ensure!(
        unpacked_bytes <= compressed_bytes.saturating_mul(limits.ratio),
        "crate archive compression ratio exceeds {}:1",
        limits.ratio
    );
    ensure!(
        !contents.files.is_empty(),
        "crate archive contains no regular files"
    );
    for (path, manifest) in contents.manifests {
        mark_manifest_surface(&path, &manifest, &mut contents.build_surface)
            .with_context(|| format!("inspect crate archive {expected_root}"))?;
    }
    let analysis = ArchiveAnalysis {
        compressed_bytes,
        unpacked_bytes,
        files: contents.files.into_values().collect(),
        build_surface: contents.build_surface,
        vcs: contents.vcs,
    };
    Ok((analysis, contents.captured))
}

#[derive(Default)]
struct ArchiveContents {
    files: BTreeMap<String, ArchiveFile>,
    seen_paths: BTreeSet<String>,
    build_surface: BTreeMap<String, String>,
    manifests: Vec<(String, Vec<u8>)>,
    vcs: Option<EmbeddedVcsInfo>,
    captured: BTreeMap<String, Vec<u8>>,
}

fn read_tar_entries<R: Read>(
    reader: &mut BoundedReader<R>,
    expected_root: &str,
    limits: ArchiveLimits,
    wanted: &[&str],
) -> Result<ArchiveContents> {
    let mut contents = ArchiveContents::default();
    let mut zero_blocks = 0_u8;
    let mut entries = 0_usize;
    let mut long_name: Option<String> = None;
    loop {
        let mut header = [0_u8; TAR_BLOCK_BYTES];
        reader
            .read_exact(&mut header)
            .context("read tar header from crate archive")?;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            if zero_blocks == 2 {
                ensure!(
                    long_name.is_none(),
                    "crate archive ends with a GNU long-name entry that names no entry"
                );
                return Ok(contents);
            }
            continue;
        }
        ensure!(zero_blocks == 0, "nonzero tar entry follows a zero block");
        entries = entries
            .checked_add(1)
            .context("archive entry count overflow")?;
        ensure!(
            entries <= limits.entries,
            "crate archive exceeds {} entries",
            limits.entries
        );
        if header[156] == GNU_LONG_NAME_TYPE {
            ensure!(
                long_name.is_none(),
                "crate archive repeats a GNU long-name entry"
            );
            long_name = Some(read_long_name(reader, &header)?);
            continue;
        }
        contents.read_entry(
            reader,
            &header,
            expected_root,
            limits.file,
            wanted,
            long_name.take(),
        )?;
    }
}

/// Reads one GNU long-name entry and returns the path it names.
///
/// GNU tar writes a type `L` header named [`GNU_LONG_NAME_PLACEHOLDER`] whose
/// body is the NUL-terminated path of the next entry, for any member path that
/// does not fit the 100-byte header name field. Cargo's tar writer emits one for
/// every such member, so ordinary crates.io archives carry them.
fn read_long_name<R: Read>(
    reader: &mut BoundedReader<R>,
    header: &[u8; TAR_BLOCK_BYTES],
) -> Result<String> {
    validate_tar_checksum(header)?;
    let mode = u32::try_from(parse_tar_number(&header[100..108], "mode")?)
        .context("tar mode exceeds u32")?;
    ensure!(
        mode & 0o7000 == 0,
        "tar entry uses unsafe special mode bits"
    );
    ensure!(
        tar_path(header)? == GNU_LONG_NAME_PLACEHOLDER,
        "crate archive contains an unsupported GNU long-name entry"
    );
    let size = parse_tar_number(&header[124..136], "size")?;
    ensure!(
        (1..=MAX_LONG_NAME_BYTES).contains(&size),
        "GNU long-name entry size {size} is outside 1..={MAX_LONG_NAME_BYTES}"
    );
    let mut body = vec![0_u8; usize::try_from(size).context("GNU long-name size exceeds usize")?];
    reader
        .read_exact(&mut body)
        .context("read GNU long-name entry")?;
    read_padding(reader, size)?;
    ensure!(
        body.last() == Some(&0),
        "GNU long-name entry is not NUL-terminated"
    );
    let name = &body[..body.len() - 1];
    ensure!(
        !name.contains(&0),
        "GNU long-name entry has data after its NUL terminator"
    );
    let name = std::str::from_utf8(name).context("GNU long-name entry is not valid UTF-8")?;
    Ok(name.to_owned())
}

impl ArchiveContents {
    fn read_entry<R: Read>(
        &mut self,
        reader: &mut BoundedReader<R>,
        header: &[u8; TAR_BLOCK_BYTES],
        expected_root: &str,
        file_limit: u64,
        wanted: &[&str],
        long_name: Option<String>,
    ) -> Result<()> {
        validate_tar_checksum(header)?;
        let mode = u32::try_from(parse_tar_number(&header[100..108], "mode")?)
            .context("tar mode exceeds u32")?;
        ensure!(
            mode & 0o7000 == 0,
            "tar entry uses unsafe special mode bits"
        );
        let size = parse_tar_number(&header[124..136], "size")?;
        let entry_type = header[156];
        if long_name.is_some() {
            ensure!(
                matches!(entry_type, 0 | b'0' | b'5'),
                "GNU long-name entry is not followed by a file or directory entry"
            );
        }
        // A long-name entry replaces the header name, which GNU truncates to the
        // first 100 bytes of the path it carries in full.
        let path = match long_name {
            Some(name) => name,
            None => tar_path(header)?,
        };
        let normalized = normalize_archive_path(&path, entry_type == b'5')?;
        ensure!(
            self.seen_paths.insert(normalized.clone()),
            "crate archive repeats normalized path {normalized:?}"
        );
        let relative = relative_to_root(&normalized, expected_root)?;
        match entry_type {
            0 | b'0' => self.read_regular(reader, relative, size, mode, file_limit, wanted),
            b'5' => {
                ensure!(size == 0, "tar directory entry has nonzero size");
                Ok(())
            }
            b'1' | b'2' => bail!("crate archive contains a link entry at {relative:?}"),
            b'3' | b'4' | b'6' => {
                bail!("crate archive contains a device/FIFO entry at {relative:?}")
            }
            b'x' | b'g' | b'K' => {
                bail!("crate archive contains unsupported extended tar metadata at {relative:?}")
            }
            other => bail!("crate archive contains unsupported tar type {other:#04x}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read_regular<R: Read>(
        &mut self,
        reader: &mut BoundedReader<R>,
        relative: String,
        size: u64,
        mode: u32,
        file_limit: u64,
        wanted: &[&str],
    ) -> Result<()> {
        ensure!(
            !relative.is_empty(),
            "archive root cannot be a regular file"
        );
        ensure!(
            size <= file_limit,
            "archive file {relative:?} exceeds {file_limit} bytes"
        );
        let size_usize = usize::try_from(size).context("archive file size exceeds usize")?;
        let mut bytes = vec![0_u8; size_usize];
        reader
            .read_exact(&mut bytes)
            .with_context(|| format!("read archive file {relative:?}"))?;
        read_padding(reader, size)?;
        let sha256 = sha256_bytes(&bytes);
        let file = ArchiveFile {
            path: relative.clone(),
            size,
            mode,
            sha256: sha256.clone(),
            binary: is_binary(&relative, &bytes),
        };
        mark_file_surface(&file, &mut self.build_surface);
        if relative == "Cargo.toml" || relative == "Cargo.toml.orig" {
            self.manifests.push((relative.clone(), bytes.clone()));
        }
        if relative == ".cargo_vcs_info.json" {
            ensure!(self.vcs.is_none(), "archive repeats VCS information file");
            self.vcs = Some(parse_vcs_info(&bytes, &sha256)?);
        }
        if wanted.contains(&relative.as_str()) {
            self.captured.insert(relative.clone(), bytes.clone());
        }
        self.files.insert(relative, file);
        Ok(())
    }
}

fn require_zero_trailing_data(reader: &mut impl Read) -> Result<()> {
    let mut trailing = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut trailing)
            .context("read trailing decompressed archive data")?;
        if read == 0 {
            return Ok(());
        }
        ensure!(
            trailing[..read].iter().all(|byte| *byte == 0),
            "crate archive has nonzero data after the tar terminator"
        );
    }
}

fn validate_tar_checksum(header: &[u8; TAR_BLOCK_BYTES]) -> Result<()> {
    let expected = parse_tar_number(&header[148..156], "checksum")?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    ensure!(actual == expected, "tar header checksum mismatch");
    Ok(())
}

fn parse_tar_number(field: &[u8], name: &str) -> Result<u64> {
    ensure!(
        field.first().is_none_or(|byte| byte & 0x80 == 0),
        "base-256 tar {name} is unsupported"
    );
    let text = std::str::from_utf8(field).with_context(|| format!("tar {name} is not ASCII"))?;
    let text = text.trim_matches(['\0', ' ']);
    if text.is_empty() {
        return Ok(0);
    }
    ensure!(
        text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
        "tar {name} is not canonical octal"
    );
    u64::from_str_radix(text, 8).with_context(|| format!("parse tar {name}"))
}

fn tar_path(header: &[u8; TAR_BLOCK_BYTES]) -> Result<String> {
    let name = tar_string(&header[..100], "name")?;
    let prefix = tar_string(&header[345..500], "prefix")?;
    ensure!(!name.is_empty(), "tar entry name is empty");
    if prefix.is_empty() {
        Ok(name)
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn tar_string(field: &[u8], name: &str) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    ensure!(
        field[end..].iter().all(|byte| *byte == 0),
        "tar {name} has data after NUL terminator"
    );
    let value = std::str::from_utf8(&field[..end])
        .with_context(|| format!("tar {name} is not valid UTF-8"))?;
    Ok(value.to_owned())
}

fn normalize_archive_path(path: &str, directory: bool) -> Result<String> {
    ensure!(!path.contains('\\'), "tar path contains a backslash");
    ensure!(!path.starts_with('/'), "tar path is absolute");
    let path = if directory {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    ensure!(!path.is_empty(), "tar path is empty");
    let components = path.split('/').collect::<Vec<_>>();
    ensure!(
        components
            .iter()
            .all(|component| !component.is_empty() && *component != "." && *component != ".."),
        "tar path is non-canonical or contains traversal"
    );
    Ok(components.join("/"))
}

fn relative_to_root(path: &str, expected_root: &str) -> Result<String> {
    if path == expected_root {
        return Ok(String::new());
    }
    let prefix = format!("{expected_root}/");
    let relative = path.strip_prefix(&prefix).with_context(|| {
        format!("archive path {path:?} is outside mandatory root {expected_root:?}")
    })?;
    ensure!(!relative.is_empty(), "archive path has empty relative name");
    Ok(relative.to_owned())
}

fn read_padding(reader: &mut impl Read, size: u64) -> Result<()> {
    let remainder = size % TAR_BLOCK_BYTES as u64;
    if remainder == 0 {
        return Ok(());
    }
    let padding = TAR_BLOCK_BYTES as u64 - remainder;
    let mut bytes = vec![0_u8; usize::try_from(padding).context("tar padding exceeds usize")?];
    reader.read_exact(&mut bytes).context("read tar padding")?;
    ensure!(
        bytes.iter().all(|byte| *byte == 0),
        "tar file padding is nonzero"
    );
    Ok(())
}

fn is_binary(path: &str, contents: &[u8]) -> bool {
    contents.contains(&0)
        || [
            ".a", ".dll", ".dylib", ".exe", ".lib", ".o", ".obj", ".so", ".wasm",
        ]
        .iter()
        .any(|suffix| path.to_ascii_lowercase().ends_with(suffix))
}

fn mark_file_surface(file: &ArchiveFile, surface: &mut BTreeMap<String, String>) {
    let lower = file.path.to_ascii_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    let native = [
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".s", ".asm",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix));
    let cargo_config = matches!(lower.as_str(), ".cargo/config" | ".cargo/config.toml");
    if basename == "build.rs" || native || cargo_config || file.binary || file.mode & 0o111 != 0 {
        surface.insert(
            format!("file:{}:{:04o}", file.path, file.mode),
            file.sha256.clone(),
        );
    }
}

fn mark_manifest_surface(
    path: &str,
    contents: &[u8],
    surface: &mut BTreeMap<String, String>,
) -> Result<()> {
    let manifest: toml::Value =
        toml::from_slice(contents).with_context(|| format!("parse archived manifest {path:?}"))?;
    if let Some(package) = manifest.get("package").and_then(toml::Value::as_table) {
        if let Some(build) = package.get("build") {
            let value = match build {
                toml::Value::Boolean(false) => None,
                toml::Value::Boolean(true) => Some("build.rs".to_owned()),
                toml::Value::String(value) => Some(value.clone()),
                _ => bail!("archived manifest {path:?} has malformed package.build"),
            };
            if let Some(value) = value {
                surface.insert(
                    format!("manifest:{path}:build"),
                    sha256_bytes(value.as_bytes()),
                );
            }
        }
        if let Some(links) = package.get("links") {
            let links = links.as_str().with_context(|| {
                format!("archived manifest {path:?} has malformed package.links")
            })?;
            surface.insert(
                format!("manifest:{path}:links"),
                sha256_bytes(links.as_bytes()),
            );
        }
    }
    if let Some(library) = manifest.get("lib").and_then(toml::Value::as_table) {
        // Cargo accepts the underscore spelling `proc_macro` before edition 2024 and keeps it in
        // the packaged manifest, so both spellings mark build-time code.
        let mut proc_macro = false;
        let mut declared = false;
        for key in ["proc-macro", "proc_macro"] {
            let Some(value) = library.get(key) else {
                continue;
            };
            ensure!(
                !declared,
                "archived manifest {path:?} declares both lib.proc-macro and lib.proc_macro"
            );
            declared = true;
            proc_macro = value
                .as_bool()
                .with_context(|| format!("archived manifest {path:?} has malformed lib.{key}"))?;
        }
        if proc_macro {
            surface.insert(format!("manifest:{path}:proc-macro"), sha256_bytes(b"true"));
        }
    }
    Ok(())
}

fn parse_vcs_info(contents: &[u8], file_sha256: &str) -> Result<EmbeddedVcsInfo> {
    let value: JsonValue =
        serde_json::from_slice(contents).context("parse archived .cargo_vcs_info.json")?;
    let object = value
        .as_object()
        .context("archived .cargo_vcs_info.json must be an object")?;
    let git = object
        .get("git")
        .and_then(JsonValue::as_object)
        .context("archived .cargo_vcs_info.json has no git object")?;
    let commit = git
        .get("sha1")
        .and_then(JsonValue::as_str)
        .context("archived .cargo_vcs_info.json has no git.sha1")?;
    ensure!(
        matches!(commit.len(), 40 | 64)
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "archived VCS commit is not a lowercase full Git object ID"
    );
    let path_in_vcs = match object.get("path_in_vcs") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => {
            let normalized = normalize_vcs_path(value)?;
            Some(normalized)
        }
        Some(_) => bail!("archived VCS path_in_vcs must be null or a string"),
    };
    Ok(EmbeddedVcsInfo {
        commit: commit.to_owned(),
        path_in_vcs,
        file_sha256: file_sha256.to_owned(),
    })
}

fn normalize_vcs_path(path: &str) -> Result<String> {
    ensure!(!path.starts_with('/'), "VCS path_in_vcs is absolute");
    ensure!(!path.contains('\\'), "VCS path_in_vcs contains backslash");
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    ensure!(
        trimmed
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != ".."),
        "VCS path_in_vcs is non-canonical or contains traversal"
    );
    Ok(trimmed.to_owned())
}

struct BoundedReader<R> {
    inner: R,
    bytes_read: u64,
    limit: u64,
}

impl<R> BoundedReader<R> {
    const fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            bytes_read: 0,
            limit,
        }
    }

    const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes_read >= self.limit {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decompressed crate archive exceeds resource limit",
                )),
            };
        }
        let remaining = self.limit - self.bytes_read;
        let permitted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("bounded read length exceeds usize"))?;
        let read = self.inner.read(&mut buffer[..permitted])?;
        self.bytes_read = self
            .bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("decompressed byte counter overflow"))?;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};

    use super::*;

    #[test]
    fn safe_archive_reports_stable_files_build_surface_and_vcs_claim() {
        let archive = archive(&[
            Entry::directory("demo-1.2.3/", 0o755),
            Entry::file(
                "demo-1.2.3/Cargo.toml",
                b"[package]\nname='demo'\nversion='1.2.3'\nbuild='build/custom.rs'\nlinks='demo'\n[lib]\nproc-macro=true\n",
                0o644,
            ),
            Entry::file("demo-1.2.3/build/custom.rs", b"fn main() {}\n", 0o644),
            Entry::file("demo-1.2.3/tool", b"#!/bin/sh\n", 0o755),
            Entry::file(
                "demo-1.2.3/.cargo_vcs_info.json",
                br#"{"git":{"sha1":"1111111111111111111111111111111111111111"},"path_in_vcs":"crates/demo"}"#,
                0o644,
            ),
        ]);
        let result =
            inspect_crate_archive("demo", &Version::parse("1.2.3").unwrap(), &archive).unwrap();
        assert_eq!(result.files.len(), 4);
        assert_eq!(
            result.vcs.as_ref().unwrap().commit,
            "1111111111111111111111111111111111111111"
        );
        assert_eq!(
            result.vcs.as_ref().unwrap().path_in_vcs.as_deref(),
            Some("crates/demo")
        );
        assert!(
            result
                .build_surface
                .keys()
                .any(|key| key.contains("manifest:Cargo.toml:build"))
        );
        assert!(
            result
                .build_surface
                .keys()
                .any(|key| key.contains("manifest:Cargo.toml:proc-macro"))
        );
        assert!(
            result
                .build_surface
                .keys()
                .any(|key| key.contains("file:tool"))
        );
    }

    #[test]
    fn underscore_proc_macro_spelling_marks_build_time_code() {
        let archive = archive(&[Entry::file(
            "demo-1.2.3/Cargo.toml",
            b"[package]\nname='demo'\nversion='1.2.3'\n[lib]\nproc_macro=true\n",
            0o644,
        )]);
        let result =
            inspect_crate_archive("demo", &Version::parse("1.2.3").unwrap(), &archive).unwrap();
        assert!(
            result
                .build_surface
                .keys()
                .any(|key| key.contains("manifest:Cargo.toml:proc-macro"))
        );
    }

    #[test]
    fn malformed_or_repeated_proc_macro_keys_name_the_archive_and_key() {
        for (manifest, key) in [
            (
                "[package]\nname='demo'\nversion='1.0.0'\n[lib]\nproc_macro=\"true\"\n",
                "lib.proc_macro",
            ),
            (
                "[package]\nname='demo'\nversion='1.0.0'\n[lib]\nproc-macro=1\n",
                "lib.proc-macro",
            ),
            (
                "[package]\nname='demo'\nversion='1.0.0'\n[lib]\nproc-macro=true\nproc_macro=true\n",
                "both lib.proc-macro and lib.proc_macro",
            ),
        ] {
            let archive = archive(&[Entry::file(
                "demo-1.0.0/Cargo.toml",
                manifest.as_bytes(),
                0o644,
            )]);
            let error = inspect_crate_archive("demo", &Version::parse("1.0.0").unwrap(), &archive)
                .unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("demo-1.0.0"), "{message}");
            assert!(message.contains(key), "{message}");
        }
    }

    #[test]
    fn traversal_links_duplicates_and_wrong_roots_are_rejected() {
        for malicious in [
            archive(&[Entry::file("demo-1.0.0/../escape", b"bad", 0o644)]),
            archive(&[Entry::link("demo-1.0.0/link", "target")]),
            archive(&[
                Entry::file("demo-1.0.0/a", b"one", 0o644),
                Entry::file("demo-1.0.0/a", b"two", 0o644),
            ]),
            archive(&[Entry::file("other-1.0.0/a", b"bad", 0o644)]),
        ] {
            assert!(
                inspect_crate_archive("demo", &Version::parse("1.0.0").unwrap(), &malicious)
                    .is_err()
            );
        }
    }

    #[test]
    fn gnu_long_name_entry_names_the_next_file() {
        assert!(LONG_PATH.len() > 100);
        let long_name = with_nul(LONG_PATH);
        let archive = archive(&[
            Entry::directory("demo-1.0.0/", 0o755),
            Entry::raw(GNU_LONG_NAME_PLACEHOLDER, b'L', &long_name, 0o644),
            Entry::raw(truncated(LONG_PATH), b'0', b"fn main() {}\n", 0o755),
        ]);
        let result =
            inspect_crate_archive("demo", &Version::parse("1.0.0").unwrap(), &archive).unwrap();
        let relative = LONG_PATH.strip_prefix("demo-1.0.0/").unwrap();
        assert_eq!(
            result.files,
            vec![ArchiveFile {
                path: relative.to_owned(),
                size: 13,
                mode: 0o755,
                sha256: sha256_bytes(b"fn main() {}\n"),
                binary: false,
            }]
        );
        assert_eq!(
            result.build_surface.get(&format!("file:{relative}:0755")),
            Some(&sha256_bytes(b"fn main() {}\n"))
        );
        assert!(
            inspect_with_limits(
                "demo",
                &Version::parse("1.0.0").unwrap(),
                &archive,
                ArchiveLimits {
                    file: 4,
                    ..ArchiveLimits::production()
                },
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn gnu_long_name_entry_names_the_next_directory() {
        let long_directory = "demo-1.0.0/tests/some_very_long_directory_name_that_does_not_fit_the_tar_header_name_field_of_one_hundred_bytes";
        assert!(long_directory.len() > 100);
        let long_name = with_nul(&format!("{long_directory}/"));
        let archive = archive(&[
            Entry::raw(GNU_LONG_NAME_PLACEHOLDER, b'L', &long_name, 0o644),
            Entry::raw(truncated(long_directory), b'5', b"", 0o755),
            Entry::file("demo-1.0.0/a", b"one", 0o644),
        ]);
        let result =
            inspect_crate_archive("demo", &Version::parse("1.0.0").unwrap(), &archive).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "a");
    }

    #[test]
    fn malformed_gnu_long_name_entries_are_rejected() {
        let member = Entry::raw(truncated(LONG_PATH), b'0', b"fn main() {}\n", 0o644);
        for (body, following, expected) in [
            (
                b"demo-1.0.0/../escape\0".to_vec(),
                vec![member],
                "non-canonical or contains traversal",
            ),
            (
                b"/demo-1.0.0/escape\0".to_vec(),
                vec![member],
                "tar path is absolute",
            ),
            (
                b"other-1.0.0/escape\0".to_vec(),
                vec![member],
                "outside mandatory root",
            ),
            (
                LONG_PATH.as_bytes().to_vec(),
                vec![member],
                "not NUL-terminated",
            ),
            (
                b"demo-1.0.0/escape\0trailing\0".to_vec(),
                vec![member],
                "data after its NUL terminator",
            ),
            (vec![0xff, 0xfe, 0], vec![member], "not valid UTF-8"),
            (
                with_nul(LONG_PATH),
                vec![Entry::link("demo-1.0.0/link", "target")],
                "not followed by a file or directory entry",
            ),
            (
                with_nul(LONG_PATH),
                vec![Entry::raw(
                    "demo-1.0.0/.cargo_vcs_info.json",
                    b'x',
                    b"1 comment=0\0",
                    0o644,
                )],
                "not followed by a file or directory entry",
            ),
            (vec![b'a'; 5000], vec![member], "outside 1..=4096"),
        ] {
            let mut entries = vec![Entry::raw(GNU_LONG_NAME_PLACEHOLDER, b'L', &body, 0o644)];
            entries.extend_from_slice(&following);
            assert_error(&archive(&entries), expected);
        }

        // A long-name header that is not GNU's placeholder.
        let long_name = with_nul(LONG_PATH);
        assert_error(
            &archive(&[
                Entry::raw("demo-1.0.0/escape", b'L', &long_name, 0o644),
                member,
            ]),
            "unsupported GNU long-name entry",
        );

        // Two long-name entries in a row.
        assert_error(
            &archive(&[
                Entry::raw(GNU_LONG_NAME_PLACEHOLDER, b'L', &long_name, 0o644),
                Entry::raw(GNU_LONG_NAME_PLACEHOLDER, b'L', &long_name, 0o644),
                member,
            ]),
            "repeats a GNU long-name entry",
        );

        // A long-name entry that names no entry.
        assert_error(
            &archive(&[Entry::raw(
                GNU_LONG_NAME_PLACEHOLDER,
                b'L',
                &long_name,
                0o644,
            )]),
            "names no entry",
        );

        // A long name that repeats a path the archive already holds.
        assert_error(
            &archive(&[
                Entry::file("demo-1.0.0/a", b"one", 0o644),
                Entry::raw(
                    GNU_LONG_NAME_PLACEHOLDER,
                    b'L',
                    &with_nul("demo-1.0.0/a"),
                    0o644,
                ),
                member,
            ]),
            "repeats normalized path",
        );
    }

    #[test]
    fn other_gnu_and_pax_extension_entries_are_still_rejected() {
        for entry_type in [b'K', b'x', b'g'] {
            let archive = archive(&[
                Entry::raw("demo-1.0.0/a", entry_type, b"target\0", 0o644),
                Entry::file("demo-1.0.0/a", b"fn main() {}\n", 0o644),
            ]);
            assert_error(&archive, "unsupported extended tar metadata");
        }
    }

    #[test]
    fn file_count_size_stream_and_ratio_limits_fail_closed() {
        let entries = [
            Entry::file("demo-1.0.0/a", b"one", 0o644),
            Entry::file("demo-1.0.0/b", b"two", 0o644),
        ];
        let compressed = archive(&entries);
        let base = ArchiveLimits {
            compressed: compressed.len(),
            unpacked: 4096,
            file: 16,
            entries: 10,
            ratio: 1000,
        };
        assert!(
            inspect_with_limits(
                "demo",
                &Version::parse("1.0.0").unwrap(),
                &compressed,
                ArchiveLimits { entries: 1, ..base },
                &[],
            )
            .is_err()
        );
        assert!(
            inspect_with_limits(
                "demo",
                &Version::parse("1.0.0").unwrap(),
                &compressed,
                ArchiveLimits { file: 2, ..base },
                &[],
            )
            .is_err()
        );
        assert!(
            inspect_with_limits(
                "demo",
                &Version::parse("1.0.0").unwrap(),
                &compressed,
                ArchiveLimits {
                    unpacked: 511,
                    ..base
                },
                &[],
            )
            .is_err()
        );
        assert!(
            inspect_with_limits(
                "demo",
                &Version::parse("1.0.0").unwrap(),
                &compressed,
                ArchiveLimits { ratio: 1, ..base },
                &[],
            )
            .is_err()
        );
    }

    /// A member path longer than the 100-byte tar header name field.
    const LONG_PATH: &str = "demo-1.0.0/tests/some_very_long_module_name_that_does_not_fit_the_tar_header_name_field_of_one_hundred_bytes.rs";

    /// The NUL-terminated body GNU writes for a long-name entry.
    fn with_nul(name: &str) -> Vec<u8> {
        let mut body = name.as_bytes().to_vec();
        body.push(0);
        body
    }

    /// The header name GNU writes beside a long-name entry: the first 99 bytes.
    fn truncated(path: &str) -> &str {
        &path[..99]
    }

    fn assert_error(archive: &[u8], expected: &str) {
        let error =
            inspect_crate_archive("demo", &Version::parse("1.0.0").unwrap(), archive).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
    }

    #[derive(Clone, Copy)]
    enum Entry<'a> {
        File {
            path: &'a str,
            contents: &'a [u8],
            mode: u32,
        },
        Directory {
            path: &'a str,
            mode: u32,
        },
        Link {
            path: &'a str,
            target: &'a str,
        },
        /// A header of an explicit type whose body is exactly `body`.
        Raw {
            path: &'a str,
            entry_type: u8,
            body: &'a [u8],
            mode: u32,
        },
    }

    impl<'a> Entry<'a> {
        const fn file(path: &'a str, contents: &'a [u8], mode: u32) -> Self {
            Self::File {
                path,
                contents,
                mode,
            }
        }

        const fn directory(path: &'a str, mode: u32) -> Self {
            Self::Directory { path, mode }
        }

        const fn link(path: &'a str, target: &'a str) -> Self {
            Self::Link { path, target }
        }

        const fn raw(path: &'a str, entry_type: u8, body: &'a [u8], mode: u32) -> Self {
            Self::Raw {
                path,
                entry_type,
                body,
                mode,
            }
        }
    }

    fn archive(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut tar = Vec::new();
        for entry in entries {
            let (path, contents, mode, kind, target) = match entry {
                Entry::File {
                    path,
                    contents,
                    mode,
                } => (*path, *contents, *mode, b'0', ""),
                Entry::Directory { path, mode } => (*path, &[][..], *mode, b'5', ""),
                Entry::Link { path, target } => (*path, &[][..], 0o777, b'2', *target),
                Entry::Raw {
                    path,
                    entry_type,
                    body,
                    mode,
                } => (*path, *body, *mode, *entry_type, ""),
            };
            let mut header = [0_u8; TAR_BLOCK_BYTES];
            set_string(&mut header[..100], path);
            set_octal(&mut header[100..108], u64::from(mode));
            set_octal(&mut header[108..116], 0);
            set_octal(&mut header[116..124], 0);
            set_octal(&mut header[124..136], contents.len() as u64);
            set_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = kind;
            set_string(&mut header[157..257], target);
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
            set_octal(&mut header[148..156], checksum);
            tar.extend_from_slice(&header);
            tar.extend_from_slice(contents);
            let padding = (TAR_BLOCK_BYTES - contents.len() % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
            tar.resize(tar.len() + padding, 0);
        }
        tar.resize(tar.len() + TAR_BLOCK_BYTES * 2, 0);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }

    fn set_string(field: &mut [u8], value: &str) {
        assert!(value.len() < field.len());
        field[..value.len()].copy_from_slice(value.as_bytes());
    }

    fn set_octal(field: &mut [u8], value: u64) {
        let digits = format!("{:0width$o}", value, width = field.len() - 2);
        assert_eq!(digits.len(), field.len() - 2);
        field[..digits.len()].copy_from_slice(digits.as_bytes());
        field[field.len() - 2] = 0;
        field[field.len() - 1] = b' ';
    }
}
