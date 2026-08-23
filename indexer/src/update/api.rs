//! Strict version-scoped crates.io API evidence parsing.

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde_json::{Map, Value};

use crate::artifact::sha256_bytes;
use crate::policy::{validate_package_name, validate_sha256};
use crate::schema::version_identity;

use super::{ApiEvidence, ApiVersionEvidence, TrustedPublishingEvidence};

/// Parses exact version-scoped publisher/repository/Trusted Publishing evidence from one crates.io package API response.
///
/// Unknown non-decision fields remain permitted. Every consumed field is type-checked; exact package/version/checksum identities are required.
///
/// # Errors
///
/// Returns an error for malformed JSON, missing/duplicate requested versions, identity/checksum mismatch, malformed publisher/repository evidence, or unsupported/malformed Trusted Publishing context.
pub fn parse_crates_io_api_evidence(
    name: &str,
    bytes: &[u8],
    base: Option<(&Version, &str)>,
    candidate: (&Version, &str),
) -> Result<ApiEvidence> {
    validate_package_name(name).context("invalid crates.io API package name")?;
    validate_sha256(candidate.1).context("invalid candidate checksum")?;
    if let Some((_, checksum)) = base {
        validate_sha256(checksum).context("invalid base checksum")?;
    }
    let root: Value = serde_json::from_slice(bytes).context("parse crates.io API response JSON")?;
    let root = root
        .as_object()
        .context("crates.io API response must be an object")?;
    let versions = root
        .get("versions")
        .context("crates.io API response has no versions")?
        .as_array()
        .context("crates.io API versions must be an array")?;
    let candidate = parse_exact_version(versions, name, candidate.0, candidate.1)?;
    let base = base
        .map(|(version, checksum)| parse_exact_version(versions, name, version, checksum))
        .transpose()?;
    Ok(ApiEvidence {
        response_sha256: sha256_bytes(bytes),
        base,
        candidate,
    })
}

fn parse_exact_version(
    versions: &[Value],
    name: &str,
    expected_version: &Version,
    expected_checksum: &str,
) -> Result<ApiVersionEvidence> {
    let mut matching = Vec::new();
    for value in versions {
        let object = value
            .as_object()
            .context("crates.io API version must be an object")?;
        let version_text = string_field(object, "num", "version")?;
        let version = Version::parse(version_text)
            .with_context(|| format!("invalid crates.io API version {version_text:?}"))?;
        if version_identity(&version) == version_identity(expected_version) {
            matching.push(object);
        }
    }
    ensure!(
        matching.len() == 1,
        "crates.io API contains {} entries for {name} {expected_version}; expected exactly one",
        matching.len()
    );
    let object = matching[0];
    ensure!(
        string_field(object, "crate", "version")? == name,
        "crates.io API version names another crate"
    );
    let checksum = string_field(object, "checksum", "version")?;
    validate_sha256(checksum).context("invalid crates.io API version checksum")?;
    ensure!(
        checksum == expected_checksum,
        "crates.io API checksum for {name} {expected_version} differs from sparse index"
    );
    let (publisher_id, publisher_login) = parse_publisher(object.get("published_by"))?;
    let repository = nullable_string(object, "repository", "version")?;
    let trusted_publishing = parse_trusted_publishing(object.get("trustpub_data"))?;
    Ok(ApiVersionEvidence {
        publisher_id,
        publisher_login,
        repository,
        trusted_publishing,
    })
}

fn parse_publisher(value: Option<&Value>) -> Result<(Option<u64>, Option<String>)> {
    match value {
        None | Some(Value::Null) => Ok((None, None)),
        Some(Value::Object(object)) => {
            let id = object
                .get("id")
                .context("crates.io API publisher has no id")?
                .as_u64()
                .context("crates.io API publisher id must be an unsigned integer")?;
            let login = string_field(object, "login", "publisher")?;
            ensure!(
                !login.trim().is_empty() && login == login.trim(),
                "crates.io API publisher login is not canonical"
            );
            Ok((Some(id), Some(login.to_owned())))
        }
        Some(_) => bail!("crates.io API published_by must be null or an object"),
    }
}

fn parse_trusted_publishing(value: Option<&Value>) -> Result<Option<TrustedPublishingEvidence>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .context("crates.io API trustpub_data must be null or an object")?;
    let provider = string_field(object, "provider", "Trusted Publishing")?;
    let (repository, commit, run_field) = match provider {
        "github" => (
            provider_repository(
                "https://github.com",
                string_field(object, "repository", "GitHub Trusted Publishing")?,
            )?,
            string_field(object, "sha", "GitHub Trusted Publishing")?,
            (
                "run_id",
                string_field(object, "run_id", "GitHub Trusted Publishing")?,
            ),
        ),
        "gitlab" => (
            provider_repository(
                "https://gitlab.com",
                string_field(object, "project_path", "GitLab Trusted Publishing")?,
            )?,
            string_field(object, "sha", "GitLab Trusted Publishing")?,
            (
                "job_id",
                string_field(object, "job_id", "GitLab Trusted Publishing")?,
            ),
        ),
        other => bail!("unsupported Trusted Publishing provider {other:?}"),
    };
    validate_commit(commit)?;
    ensure!(
        !run_field.1.is_empty() && run_field.1 == run_field.1.trim(),
        "Trusted Publishing {} is empty or noncanonical",
        run_field.0
    );
    let canonical = serde_json::to_vec(value).context("serialize Trusted Publishing evidence")?;
    Ok(Some(TrustedPublishingEvidence {
        provider: provider.to_owned(),
        repository,
        commit: commit.to_owned(),
        evidence_sha256: sha256_bytes(&canonical),
    }))
}

fn provider_repository(root: &str, identity: &str) -> Result<String> {
    ensure!(
        !identity.is_empty()
            && identity == identity.trim()
            && !identity.starts_with('/')
            && !identity.ends_with('/')
            && identity.split('/').count() >= 2
            && identity
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..")
            && identity.is_ascii()
            && !identity.bytes().any(|byte| byte.is_ascii_whitespace()),
        "Trusted Publishing repository identity is unsafe or noncanonical"
    );
    Ok(format!("{root}/{identity}"))
}

fn validate_commit(value: &str) -> Result<()> {
    ensure!(
        matches!(value.len(), 40 | 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Trusted Publishing commit is not a canonical Git object ID"
    );
    Ok(())
}

fn nullable_string(
    object: &Map<String, Value>,
    field: &str,
    description: &str,
) -> Result<Option<String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            ensure!(
                !value.trim().is_empty() && value == value.trim(),
                "crates.io API {description} {field} is empty or noncanonical"
            );
            Ok(Some(value.clone()))
        }
        Some(_) => bail!("crates.io API {description} {field} must be null or a string"),
    }
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    description: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .with_context(|| format!("crates.io API {description} has no {field}"))?
        .as_str()
        .with_context(|| format!("crates.io API {description} {field} must be a string"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn checksum(byte: &str) -> String {
        byte.repeat(32)
    }

    fn response(trustpub: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "crate": {"repository": "ignored-global-value"},
            "versions": [
                {
                    "num": "1.0.0",
                    "crate": "demo",
                    "checksum": checksum("01"),
                    "published_by": {"id": 7, "login": "old", "ignored": true},
                    "repository": "https://github.com/example/demo",
                    "trustpub_data": null
                },
                {
                    "num": "1.1.0",
                    "crate": "demo",
                    "checksum": checksum("02"),
                    "published_by": {"id": 8, "login": "new"},
                    "repository": "https://github.com/example/demo",
                    "trustpub_data": trustpub
                }
            ],
            "future-field": true
        }))
        .unwrap()
    }

    #[test]
    fn parses_exact_version_scoped_and_github_attestation_evidence() {
        let bytes = response(&json!({
            "provider": "github",
            "repository": "example/demo",
            "run_id": "12345",
            "sha": "ab".repeat(20)
        }));
        let evidence = parse_crates_io_api_evidence(
            "demo",
            &bytes,
            Some((&Version::parse("1.0.0").unwrap(), &checksum("01"))),
            (&Version::parse("1.1.0").unwrap(), &checksum("02")),
        )
        .unwrap();
        assert_eq!(evidence.response_sha256, sha256_bytes(&bytes));
        assert_eq!(evidence.base.unwrap().publisher_id, Some(7));
        let candidate = evidence.candidate;
        assert_eq!(candidate.publisher_login.as_deref(), Some("new"));
        let trusted = candidate.trusted_publishing.unwrap();
        assert_eq!(trusted.provider, "github");
        assert_eq!(trusted.repository, "https://github.com/example/demo");
        assert_eq!(trusted.commit, "ab".repeat(20));
    }

    #[test]
    fn missing_publisher_is_retained_as_unknown() {
        let mut value: Value = serde_json::from_slice(&response(&Value::Null)).unwrap();
        value["versions"][1]["published_by"] = Value::Null;
        let bytes = serde_json::to_vec(&value).unwrap();
        let evidence = parse_crates_io_api_evidence(
            "demo",
            &bytes,
            None,
            (&Version::parse("1.1.0").unwrap(), &checksum("02")),
        )
        .unwrap();
        assert_eq!(evidence.candidate.publisher_id, None);
        assert_eq!(evidence.candidate.publisher_login, None);
    }

    #[test]
    fn checksum_and_malformed_trusted_publishing_fail_closed() {
        let malformed = response(&json!({
            "provider": "github",
            "repository": "example/demo",
            "run_id": "12345",
            "sha": "NOT-A-COMMIT"
        }));
        assert!(
            parse_crates_io_api_evidence(
                "demo",
                &malformed,
                None,
                (&Version::parse("1.1.0").unwrap(), &checksum("02")),
            )
            .is_err()
        );
        let valid = response(&Value::Null);
        assert!(
            parse_crates_io_api_evidence(
                "demo",
                &valid,
                None,
                (&Version::parse("1.1.0").unwrap(), &checksum("03")),
            )
            .is_err()
        );
    }
}
