//! Compact human authority for one batch of package admissions.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::category::CategoryId;
use crate::schema::version_identity;

/// Stable human admission-manifest wire schema.
pub const ADMISSION_MANIFEST_SCHEMA: u32 = 2;
const MAX_NOTE_BYTES: usize = 16 * 1024;

/// One compact, human-maintained batch of exact package requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionManifest {
    /// Admission-manifest wire schema.
    pub schema: u32,
    /// Exact package versions or source tags requested by this batch.
    #[serde(rename = "admit")]
    pub entries: Vec<AdmissionRequest>,
}

/// One exact package admission request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AdmissionRequest {
    /// Permanent fully-qualified package category.
    pub category: CategoryId,
    /// Cargo package name.
    pub name: String,
    /// Exact crates.io version; mutually exclusive with `tag`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    /// Exact first-party Git tag; mutually exclusive with `version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Optional typed review or external-tool evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<AdmissionEvidence>,
}

/// Optional human/tool evidence. Unknown evidence kinds fail closed.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "kind")]
pub enum AdmissionEvidence {
    /// Human review of every regular archive member and relevant metadata.
    ManualFullArchive {
        /// Public, specific review summary.
        note: String,
    },
    /// Human review of the archive/source change relative to one exact base.
    ManualSourceDelta {
        /// Exact reviewed base version.
        base: Version,
        /// Public, specific review summary.
        note: String,
    },
}

impl AdmissionRequest {
    /// Returns a deterministic request key independent of optional evidence.
    fn key(&self) -> (String, String, String, String) {
        let target = self
            .version
            .as_ref()
            .map_or_else(|| self.tag.clone().unwrap_or_default(), ToString::to_string);
        (
            self.category.to_string(),
            self.name.to_ascii_lowercase(),
            self.name.clone(),
            target,
        )
    }
}

/// Builds the compact human template for every non-blocked mirror candidate in a machine plan.
#[must_use]
pub fn manifest_from_candidates(candidates: &[super::UpdateCandidate]) -> AdmissionManifest {
    let mut entries = candidates
        .iter()
        .filter(|candidate| candidate.decision != super::UpdateDecision::Blocked)
        .map(|candidate| AdmissionRequest {
            category: candidate
                .category
                .parse()
                .expect("validated update candidate category"),
            name: candidate.name.clone(),
            version: Some(candidate.candidate.version.clone()),
            tag: None,
            evidence: Vec::new(),
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(AdmissionRequest::key);
    AdmissionManifest {
        schema: ADMISSION_MANIFEST_SCHEMA,
        entries,
    }
}

/// Loads one regular canonical human admission manifest.
///
/// # Errors
///
/// Returns an error for an unsafe path, malformed/unsupported manifest, invalid request/evidence,
/// or noncanonical bytes.
pub fn load_admission_manifest(path: &Path) -> Result<AdmissionManifest> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect admission manifest {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "admission manifest is not a regular file: {}",
        path.display()
    );
    let bytes =
        fs::read(path).with_context(|| format!("read admission manifest {}", path.display()))?;
    let manifest: AdmissionManifest = toml::from_slice(&bytes)
        .with_context(|| format!("parse admission manifest {}", path.display()))?;
    let canonical = serialize_admission_manifest(&manifest)?;
    ensure!(
        bytes == canonical,
        "admission manifest is not in canonical form: {}",
        path.display()
    );
    Ok(manifest)
}

/// Serializes a canonical human admission manifest.
///
/// # Errors
///
/// Returns an error for malformed, duplicate, or noncanonical requests/evidence.
pub fn serialize_admission_manifest(manifest: &AdmissionManifest) -> Result<Vec<u8>> {
    validate_admission_manifest(manifest)?;
    let text =
        toml::to_string_pretty(manifest).context("serialize canonical admission manifest")?;
    Ok(text.into_bytes())
}

/// Creates one absent canonical human admission manifest.
///
/// # Errors
///
/// Returns an error for invalid content, an existing/unsafe output, or a write failure.
pub(crate) fn write_admission_manifest(path: &Path, manifest: &AdmissionManifest) -> Result<()> {
    let bytes = serialize_admission_manifest(manifest)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create admission manifest {}", path.display()))?;
    output
        .write_all(&bytes)
        .with_context(|| format!("write admission manifest {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync admission manifest {}", path.display()))
}

/// Validates a portable catalog-owned admission filename.
pub(crate) fn validate_admission_filename(path: &Path, extension: &str) -> Result<()> {
    ensure!(
        path.extension() == Some(OsStr::new(extension)),
        "admission file must have lowercase .{extension} extension: {}",
        path.display()
    );
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .with_context(|| format!("admission filename is not valid UTF-8: {}", path.display()))?;
    ensure!(
        !stem.is_empty() && stem.len() <= 128,
        "admission filename stem must contain 1..=128 bytes: {}",
        path.display()
    );
    ensure!(
        stem.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && stem
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && stem
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "admission filename stem must be lowercase ASCII kebab-case: {}",
        path.display()
    );
    Ok(())
}

fn validate_admission_manifest(manifest: &AdmissionManifest) -> Result<()> {
    ensure!(
        manifest.schema == ADMISSION_MANIFEST_SCHEMA,
        "unsupported admission-manifest schema {}; expected {ADMISSION_MANIFEST_SCHEMA}",
        manifest.schema
    );
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for request in &manifest.entries {
        let key = request.key();
        ensure!(
            previous.as_ref().is_none_or(|value| value < &key),
            "admission requests are not in canonical unique order"
        );
        previous = Some(key);
        crate::policy::validate_package_name(&request.name)
            .context("invalid admission package name")?;
        match (&request.version, &request.tag) {
            (Some(version), None) => {
                ensure!(
                    version.build.is_empty(),
                    "admission version {version} contains unsupported build metadata"
                );
                ensure!(
                    identities.insert((
                        request.name.to_ascii_lowercase().replace('-', "_"),
                        Some(version_identity(version)),
                        None,
                    )),
                    "admission repeats Cargo identity {} {}",
                    request.name,
                    version
                );
            }
            (None, Some(tag)) => {
                crate::policy::validate_git_tag(tag).context("invalid admission Git tag")?;
                ensure!(
                    identities.insert((
                        request.name.to_ascii_lowercase().replace('-', "_"),
                        None,
                        Some(tag.clone()),
                    )),
                    "admission repeats Git tag {:?} for {}",
                    tag,
                    request.name
                );
            }
            (Some(_), Some(_)) => bail!(
                "admission request for {} must not contain both version and tag",
                request.name
            ),
            (None, None) => bail!(
                "admission request for {} must contain exactly one version or tag",
                request.name
            ),
        }
        ensure!(
            request
                .evidence
                .windows(2)
                .all(|window| window[0] < window[1]),
            "admission evidence for {} is not canonical and unique",
            request.name
        );
        for evidence in &request.evidence {
            validate_evidence(evidence)?;
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &AdmissionEvidence) -> Result<()> {
    let note = match evidence {
        AdmissionEvidence::ManualFullArchive { note }
        | AdmissionEvidence::ManualSourceDelta { note, .. } => note,
    };
    ensure!(!note.trim().is_empty(), "admission evidence note is empty");
    ensure!(
        note == note.trim(),
        "admission evidence note has leading or trailing whitespace"
    );
    ensure!(
        note.len() <= MAX_NOTE_BYTES,
        "admission evidence note exceeds {MAX_NOTE_BYTES} bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_manifest_round_trips_and_contains_no_machine_hashes() {
        let manifest = AdmissionManifest {
            schema: ADMISSION_MANIFEST_SCHEMA,
            entries: vec![AdmissionRequest {
                category: "universe/general".parse().unwrap(),
                name: "demo".to_owned(),
                version: Some("1.2.3".parse().unwrap()),
                tag: None,
                evidence: vec![AdmissionEvidence::ManualFullArchive {
                    note: "Reviewed every regular archive member.".to_owned(),
                }],
            }],
        };
        let bytes = serialize_admission_manifest(&manifest).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("[[admit]]"));
        assert!(text.contains("version = \"1.2.3\""));
        assert!(text.contains("[[admit.evidence]]"));
        assert!(!text.contains("sha256"));
        assert_eq!(
            toml::from_slice::<AdmissionManifest>(&bytes).unwrap(),
            manifest
        );
    }

    #[test]
    fn request_target_and_canonical_order_are_strict() {
        let entry = |name: &str| AdmissionRequest {
            category: "universe/general".parse().unwrap(),
            name: name.to_owned(),
            version: Some("1.0.0".parse().unwrap()),
            tag: None,
            evidence: Vec::new(),
        };
        let mut manifest = AdmissionManifest {
            schema: ADMISSION_MANIFEST_SCHEMA,
            entries: vec![entry("zeta"), entry("alpha")],
        };
        assert!(serialize_admission_manifest(&manifest).is_err());
        manifest.entries.sort_by_key(AdmissionRequest::key);
        serialize_admission_manifest(&manifest).unwrap();
        manifest.entries[0].tag = Some("v1.0.0".to_owned());
        assert!(serialize_admission_manifest(&manifest).is_err());
    }

    #[test]
    fn evidence_and_portable_filenames_fail_closed() {
        let mut manifest = AdmissionManifest {
            schema: ADMISSION_MANIFEST_SCHEMA,
            entries: vec![AdmissionRequest {
                category: "universe/general".parse().unwrap(),
                name: "demo".to_owned(),
                version: Some("1.0.0".parse().unwrap()),
                tag: None,
                evidence: vec![AdmissionEvidence::ManualFullArchive {
                    note: " whitespace ".to_owned(),
                }],
            }],
        };
        assert!(serialize_admission_manifest(&manifest).is_err());
        manifest.entries[0].evidence.clear();
        serialize_admission_manifest(&manifest).unwrap();
        validate_admission_filename(Path::new("2026-08-24-routine.toml"), "toml").unwrap();
        assert!(validate_admission_filename(Path::new("Routine.toml"), "toml").is_err());
        assert!(validate_admission_filename(Path::new("routine.json"), "toml").is_err());
    }
}
