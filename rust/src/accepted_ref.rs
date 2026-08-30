//! Canonical accepted-ref records and pure restart/reload transition policy.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ACCEPTED_REF_SCHEMA: &str = "pkgre-accepted-ref-v1";
const IDENTITY_DOMAIN: &[u8] = b"pkgre-repository-identity-v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AcceptedRef {
    accepted_commit: String,
    full_ref: String,
    repository_identity: String,
    schema: String,
}

impl AcceptedRef {
    /// Constructs and validates an accepted-ref record.
    ///
    /// # Errors
    ///
    /// Returns an error when the commit, full ref, or repository identity is malformed.
    pub fn new(
        accepted_commit: impl Into<String>,
        full_ref: impl Into<String>,
        repository_identity: impl Into<String>,
    ) -> Result<Self> {
        let record = Self {
            accepted_commit: accepted_commit.into(),
            full_ref: full_ref.into(),
            repository_identity: repository_identity.into(),
            schema: ACCEPTED_REF_SCHEMA.to_owned(),
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub fn accepted_commit(&self) -> &str {
        &self.accepted_commit
    }

    #[must_use]
    pub fn full_ref(&self) -> &str {
        &self.full_ref
    }

    #[must_use]
    pub fn repository_identity(&self) -> &str {
        &self.repository_identity
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == ACCEPTED_REF_SCHEMA,
            "unsupported accepted-ref schema"
        );
        ensure!(
            valid_hex(&self.accepted_commit, 40),
            "accepted commit must be 40 lowercase hexadecimal characters"
        );
        ensure!(
            valid_full_ref(&self.full_ref),
            "accepted full ref is invalid"
        );
        ensure!(
            valid_hex(&self.repository_identity, 64),
            "repository identity must be 64 lowercase hexadecimal characters"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryConfig {
    full_ref: String,
    repository_identity: String,
}

impl RepositoryConfig {
    /// Constructs and validates repository binding configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the full ref or repository identity is malformed.
    pub fn new(
        full_ref: impl Into<String>,
        repository_identity: impl Into<String>,
    ) -> Result<Self> {
        let config = Self {
            full_ref: full_ref.into(),
            repository_identity: repository_identity.into(),
        };
        ensure!(
            valid_full_ref(&config.full_ref),
            "configured full ref is invalid"
        );
        ensure!(
            valid_hex(&config.repository_identity, 64),
            "configured repository identity must be 64 lowercase hexadecimal characters"
        );
        Ok(config)
    }

    fn validate_record(&self, record: &AcceptedRef) -> Result<()> {
        record.validate()?;
        ensure!(
            record.repository_identity == self.repository_identity,
            "accepted repository identity does not match configuration"
        );
        ensure!(
            record.full_ref == self.full_ref,
            "accepted full ref does not match configuration"
        );
        Ok(())
    }
}

/// Derives the repository binding identity from exact canonical-origin and full-ref bytes.
///
/// # Errors
///
/// Returns an error when either input is too large for the length-prefixed identity format.
pub fn derive_repository_identity(origin: &[u8], full_ref: &[u8]) -> Result<String> {
    let origin_length = u32::try_from(origin.len()).context("canonical origin is too large")?;
    let ref_length = u32::try_from(full_ref.len()).context("full ref is too large")?;
    let mut digest = Sha256::new();
    digest.update(IDENTITY_DOMAIN);
    digest.update(origin_length.to_be_bytes());
    digest.update(origin);
    digest.update(ref_length.to_be_bytes());
    digest.update(full_ref);
    Ok(format!("{:x}", digest.finalize()))
}

/// Parses a canonical accepted-ref record bound to `config`.
///
/// # Errors
///
/// Returns an error for malformed or noncanonical JSON, invalid fields, or a configuration mismatch.
pub fn parse_accepted_ref(bytes: &[u8], config: &RepositoryConfig) -> Result<AcceptedRef> {
    let record: AcceptedRef = serde_json::from_slice(bytes).context("parse accepted-ref record")?;
    config.validate_record(&record)?;
    ensure!(
        canonical_accepted_ref_bytes(&record, config)? == bytes,
        "accepted-ref record is not canonical JSON"
    );
    Ok(record)
}

/// Serializes a canonical accepted-ref record bound to `config`.
///
/// # Errors
///
/// Returns an error for invalid fields, a configuration mismatch, or serialization failure.
pub fn canonical_accepted_ref_bytes(
    record: &AcceptedRef,
    config: &RepositoryConfig,
) -> Result<Vec<u8>> {
    config.validate_record(record)?;
    let mut bytes = serde_json::to_vec_pretty(record).context("serialize accepted-ref record")?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcceptedRecordState {
    Absent,
    Malformed,
    Present,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectState {
    Corrupt,
    Malformed,
    Missing,
    NotApplicable,
    Valid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ancestry {
    Descendant,
    Divergent,
    Equal,
    NotEvaluated,
    Predecessor,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Persistence {
    InterruptedBeforeRename,
    NotAttempted,
    Success,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticValidity {
    Invalid,
    NotEvaluated,
    Valid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReloadCandidate {
    pub ancestry: Ancestry,
    pub commit: String,
    pub full_ref: String,
    pub object_state: ObjectState,
    pub persistence: Persistence,
    pub repository_identity: String,
    pub semantic_validity: SemanticValidity,
    pub suppressed: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct StartupInput<'a> {
    pub accepted_record: Option<&'a AcceptedRef>,
    pub accepted_record_state: AcceptedRecordState,
    pub bootstrap_commit: &'a str,
    pub bootstrap_object: ObjectState,
    pub local_accepted_object: ObjectState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionDecision {
    AcceptForward,
    Bootstrap,
    FailStartup,
    RetainAccepted,
    StartAccepted,
    Unchanged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionReason {
    AcceptedObjectInvalid,
    AcceptedObjectUnavailable,
    AcceptedRecordAbsent,
    AcceptedRecordAuthority,
    AcceptedRecordMalformed,
    BootstrapObjectInvalid,
    BootstrapObjectUnavailable,
    CandidateAncestryUnknown,
    CandidateCommitMalformed,
    CandidateEqualsAccepted,
    CandidateNotDescendant,
    CandidateObjectUnavailable,
    DurablePersistenceFailed,
    FullRefMismatch,
    RejectedHashSuppressed,
    RemoteUnavailable,
    RepositoryIdentityMismatch,
    SemanticValidationFailed,
    ValidForwardCandidate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransitionOutcome {
    accepted_commit: Option<String>,
    active_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_load: Option<bool>,
    decision: TransitionDecision,
    persist_record: bool,
    reason: TransitionReason,
}

impl TransitionOutcome {
    #[must_use]
    pub const fn decision(&self) -> TransitionDecision {
        self.decision
    }

    #[must_use]
    pub fn accepted_commit(&self) -> Option<&str> {
        self.accepted_commit.as_deref()
    }

    #[must_use]
    pub fn active_commit(&self) -> Option<&str> {
        self.active_commit.as_deref()
    }
}

/// Evaluates startup authority without performing I/O.
///
/// # Errors
///
/// Returns an error when the supplied accepted-record state and object states are inconsistent.
pub fn evaluate_startup(
    input: StartupInput<'_>,
    config: &RepositoryConfig,
) -> Result<TransitionOutcome> {
    match input.accepted_record_state {
        AcceptedRecordState::Malformed => {
            return Ok(startup_outcome(
                TransitionDecision::FailStartup,
                TransitionReason::AcceptedRecordMalformed,
                None,
                None,
                false,
            ));
        }
        AcceptedRecordState::Absent => {
            return match input.bootstrap_object {
                ObjectState::Valid if valid_hex(input.bootstrap_commit, 40) => Ok(startup_outcome(
                    TransitionDecision::Bootstrap,
                    TransitionReason::AcceptedRecordAbsent,
                    Some(input.bootstrap_commit),
                    Some(input.bootstrap_commit),
                    true,
                )),
                ObjectState::Missing => Ok(startup_outcome(
                    TransitionDecision::FailStartup,
                    TransitionReason::BootstrapObjectUnavailable,
                    None,
                    None,
                    false,
                )),
                ObjectState::Corrupt | ObjectState::Malformed | ObjectState::Valid => {
                    Ok(startup_outcome(
                        TransitionDecision::FailStartup,
                        TransitionReason::BootstrapObjectInvalid,
                        None,
                        None,
                        false,
                    ))
                }
                ObjectState::NotApplicable => bail!(
                    "bootstrap object state is not applicable when the accepted record is absent"
                ),
            };
        }
        AcceptedRecordState::Present => {}
    }

    let Some(record) = input.accepted_record else {
        bail!("present accepted-record state requires a record");
    };
    if record.validate().is_err() {
        return Ok(startup_outcome(
            TransitionDecision::FailStartup,
            TransitionReason::AcceptedRecordMalformed,
            None,
            None,
            false,
        ));
    }
    if record.repository_identity != config.repository_identity {
        return Ok(startup_outcome(
            TransitionDecision::FailStartup,
            TransitionReason::RepositoryIdentityMismatch,
            None,
            None,
            false,
        ));
    }
    if record.full_ref != config.full_ref {
        return Ok(startup_outcome(
            TransitionDecision::FailStartup,
            TransitionReason::FullRefMismatch,
            None,
            None,
            false,
        ));
    }
    match input.local_accepted_object {
        ObjectState::Valid => Ok(startup_outcome(
            TransitionDecision::StartAccepted,
            TransitionReason::AcceptedRecordAuthority,
            Some(&record.accepted_commit),
            Some(&record.accepted_commit),
            false,
        )),
        ObjectState::Missing => Ok(startup_outcome(
            TransitionDecision::FailStartup,
            TransitionReason::AcceptedObjectUnavailable,
            Some(&record.accepted_commit),
            None,
            false,
        )),
        ObjectState::Corrupt | ObjectState::Malformed => Ok(startup_outcome(
            TransitionDecision::FailStartup,
            TransitionReason::AcceptedObjectInvalid,
            Some(&record.accepted_commit),
            None,
            false,
        )),
        ObjectState::NotApplicable => {
            bail!("accepted object state is not applicable when a record is present")
        }
    }
}

/// Evaluates a reload candidate without performing I/O.
///
/// # Errors
///
/// Returns an error when the accepted record is invalid for `config` or candidate state is internally inconsistent.
#[allow(clippy::too_many_lines)]
pub fn evaluate_reload(
    accepted_record: &AcceptedRef,
    candidate: Option<&ReloadCandidate>,
    config: &RepositoryConfig,
) -> Result<TransitionOutcome> {
    config.validate_record(accepted_record)?;
    let accepted = accepted_record.accepted_commit();
    let Some(candidate) = candidate else {
        return Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::RemoteUnavailable,
            accepted,
            false,
            false,
        ));
    };
    if candidate.repository_identity != config.repository_identity {
        return Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::RepositoryIdentityMismatch,
            accepted,
            false,
            false,
        ));
    }
    if candidate.full_ref != config.full_ref {
        return Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::FullRefMismatch,
            accepted,
            false,
            false,
        ));
    }
    if !valid_hex(&candidate.commit, 40) || candidate.object_state == ObjectState::Malformed {
        return Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::CandidateCommitMalformed,
            accepted,
            false,
            false,
        ));
    }
    if candidate.suppressed {
        return Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::RejectedHashSuppressed,
            accepted,
            false,
            false,
        ));
    }
    if candidate.object_state != ObjectState::Valid {
        return Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::CandidateObjectUnavailable,
            accepted,
            false,
            false,
        ));
    }
    if candidate.commit == accepted {
        return Ok(reload_outcome(
            TransitionDecision::Unchanged,
            TransitionReason::CandidateEqualsAccepted,
            accepted,
            false,
            false,
        ));
    }
    match candidate.ancestry {
        Ancestry::Predecessor | Ancestry::Divergent => {
            return Ok(reload_outcome(
                TransitionDecision::RetainAccepted,
                TransitionReason::CandidateNotDescendant,
                accepted,
                false,
                false,
            ));
        }
        Ancestry::Unknown => {
            return Ok(reload_outcome(
                TransitionDecision::RetainAccepted,
                TransitionReason::CandidateAncestryUnknown,
                accepted,
                false,
                false,
            ));
        }
        Ancestry::Descendant => {}
        Ancestry::Equal | Ancestry::NotEvaluated => {
            bail!("reload candidate has inconsistent ancestry")
        }
    }
    match candidate.semantic_validity {
        SemanticValidity::Invalid => {
            return Ok(reload_outcome(
                TransitionDecision::RetainAccepted,
                TransitionReason::SemanticValidationFailed,
                accepted,
                true,
                false,
            ));
        }
        SemanticValidity::Valid => {}
        SemanticValidity::NotEvaluated => {
            bail!("reload candidate semantic validity was not evaluated")
        }
    }
    match candidate.persistence {
        Persistence::InterruptedBeforeRename => Ok(reload_outcome(
            TransitionDecision::RetainAccepted,
            TransitionReason::DurablePersistenceFailed,
            accepted,
            true,
            false,
        )),
        Persistence::Success => Ok(TransitionOutcome {
            accepted_commit: Some(candidate.commit.clone()),
            active_commit: Some(candidate.commit.clone()),
            candidate_load: Some(true),
            decision: TransitionDecision::AcceptForward,
            persist_record: true,
            reason: TransitionReason::ValidForwardCandidate,
        }),
        Persistence::NotAttempted => bail!("valid reload candidate persistence was not attempted"),
    }
}

fn startup_outcome(
    decision: TransitionDecision,
    reason: TransitionReason,
    accepted_commit: Option<&str>,
    active_commit: Option<&str>,
    persist_record: bool,
) -> TransitionOutcome {
    TransitionOutcome {
        accepted_commit: accepted_commit.map(str::to_owned),
        active_commit: active_commit.map(str::to_owned),
        candidate_load: None,
        decision,
        persist_record,
        reason,
    }
}

fn reload_outcome(
    decision: TransitionDecision,
    reason: TransitionReason,
    accepted_commit: &str,
    candidate_load: bool,
    persist_record: bool,
) -> TransitionOutcome {
    TransitionOutcome {
        accepted_commit: Some(accepted_commit.to_owned()),
        active_commit: Some(accepted_commit.to_owned()),
        candidate_load: Some(candidate_load),
        decision,
        persist_record,
        reason,
    }
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_full_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && value.len() > "refs/".len()
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    const FIXTURE: &[u8] =
        include_bytes!("../../fixtures/dynamic-registry-v1/state/accepted-ref-transitions.json");

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Fixture {
        accepted_records: Vec<NamedAcceptedRef>,
        full_ref_cases: Vec<FullRefCase>,
        policy: serde_json::Value,
        reload_cases: Vec<ReloadCase>,
        repository: Repository,
        schema: String,
        startup_cases: Vec<StartupCase>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct NamedAcceptedRef {
        accepted_commit: String,
        full_ref: String,
        id: String,
        repository_identity: String,
        schema: String,
    }

    impl NamedAcceptedRef {
        fn record(&self) -> AcceptedRef {
            AcceptedRef {
                accepted_commit: self.accepted_commit.clone(),
                full_ref: self.full_ref.clone(),
                repository_identity: self.repository_identity.clone(),
                schema: self.schema.clone(),
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct FullRefCase {
        expected: String,
        id: String,
        value: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Repository {
        bootstrap_commit: String,
        canonical_origin: String,
        full_ref: String,
        identity: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct StartupCase {
        accepted_record: Option<AcceptedRef>,
        accepted_record_state: AcceptedRecordState,
        bootstrap_object: ObjectState,
        expected: TransitionOutcome,
        id: String,
        local_accepted_object: ObjectState,
        remote_observation: RemoteObservation,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
    #[serde(rename_all = "kebab-case")]
    enum RemoteObservation {
        Descendant,
        Offline,
        Predecessor,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct ReloadCase {
        candidate: Option<ReloadCandidate>,
        expected: TransitionOutcome,
        id: String,
        starting_accepted_record: String,
    }

    #[test]
    fn follows_shared_accepted_ref_transitions() {
        let fixture: Fixture = serde_json::from_slice(FIXTURE).unwrap();
        assert_eq!(fixture.schema, "pkgre-accepted-ref-transitions-v1");
        assert_eq!(
            fixture.policy,
            json!({
                "acceptedRecordFields": ["acceptedCommit", "fullRef", "repositoryIdentity", "schema"],
                "acceptedRecordSchema": ACCEPTED_REF_SCHEMA,
                "bootstrap": "only when the accepted-record path is absent; any present malformed or mismatched record forbids bootstrap",
                "candidateValidationOrder": [
                    "candidate-shape",
                    "repository-identity",
                    "full-ref",
                    "commit-object",
                    "ancestry",
                    "semantic-validity",
                    "durable-persistence",
                    "publication"
                ],
                "fullRefGrammar": "starts with refs/;has a nonempty suffix;contains only ASCII bytes;contains no ASCII whitespace or control byte",
                "identityDerivation": "SHA-256(domain || u32be(origin length) || origin bytes || u32be(full-ref length) || full-ref bytes)",
                "identityDomain": "pkgre-repository-identity-v1\\0",
                "origin": "credential-free operator-supplied canonical UTF-8 bytes; no implementation-specific normalization",
                "persistence": "write temporary file,fsync file,atomic rename,fsync containing directory",
                "publication": "only after complete semantic validation and successful durable persistence",
                "restartAuthority": "accepted record only after bootstrap; remote and arbitrary local commits are never startup authority",
                "stateExcludes": ["rendered responses", "cache state", "origin URL", "credentials", "filesystem paths", "timestamps"]
            })
        );
        let mut canonical = serde_json::to_vec_pretty(&fixture).unwrap();
        canonical.push(b'\n');
        assert_eq!(canonical, FIXTURE);

        assert_full_ref_cases(&fixture.full_ref_cases);

        let config = RepositoryConfig::new(
            fixture.repository.full_ref.clone(),
            fixture.repository.identity.clone(),
        )
        .unwrap();
        assert_eq!(
            derive_repository_identity(
                fixture.repository.canonical_origin.as_bytes(),
                fixture.repository.full_ref.as_bytes()
            )
            .unwrap(),
            fixture.repository.identity
        );
        assert!(!fixture.repository.canonical_origin.contains('@'));

        let mut records = BTreeMap::new();
        for source in &fixture.accepted_records {
            assert!(valid_id(&source.id));
            let record = source.record();
            config.validate_record(&record).unwrap();
            assert!(records.insert(source.id.clone(), record).is_none());
        }

        let mut startup_ids = HashSet::new();
        let mut startup_remote_observations = HashSet::new();
        for case in &fixture.startup_cases {
            assert!(valid_id(&case.id));
            assert!(startup_ids.insert(case.id.clone()));
            startup_remote_observations.extend([case.remote_observation]);
            let actual = evaluate_startup(
                StartupInput {
                    accepted_record: case.accepted_record.as_ref(),
                    accepted_record_state: case.accepted_record_state,
                    bootstrap_commit: &fixture.repository.bootstrap_commit,
                    bootstrap_object: case.bootstrap_object,
                    local_accepted_object: case.local_accepted_object,
                },
                &config,
            )
            .unwrap();
            assert_eq!(actual, case.expected, "case {}", case.id);
        }
        assert_eq!(startup_remote_observations.len(), 3);

        let mut reload_ids = HashSet::new();
        for case in &fixture.reload_cases {
            assert!(valid_id(&case.id));
            assert!(reload_ids.insert(case.id.clone()));
            let accepted = records
                .get(&case.starting_accepted_record)
                .expect("reload case references an unknown accepted record");
            let actual = evaluate_reload(accepted, case.candidate.as_ref(), &config).unwrap();
            assert_eq!(actual, case.expected, "case {}", case.id);
            if !matches!(
                actual.decision(),
                TransitionDecision::AcceptForward | TransitionDecision::Unchanged
            ) {
                assert_eq!(actual.accepted_commit(), Some(accepted.accepted_commit()));
                assert_eq!(actual.active_commit(), Some(accepted.accepted_commit()));
            }
        }
    }

    #[test]
    fn accepted_ref_bytes_are_canonical_closed_and_configuration_bound() {
        let config = RepositoryConfig::new(
            "refs/heads/main",
            "b21a526d67a4251222f87dde72f2e6e99f0cdc4c9eb66d8e504aa0ed2483b456",
        )
        .unwrap();
        let record = AcceptedRef::new(
            "1".repeat(40),
            "refs/heads/main",
            "b21a526d67a4251222f87dde72f2e6e99f0cdc4c9eb66d8e504aa0ed2483b456",
        )
        .unwrap();
        let bytes = canonical_accepted_ref_bytes(&record, &config).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(parse_accepted_ref(&bytes, &config).unwrap(), record);

        let compact = serde_json::to_vec(&record).unwrap();
        assert!(parse_accepted_ref(&compact, &config).is_err());
        let duplicate = br#"{"acceptedCommit":"1111111111111111111111111111111111111111","acceptedCommit":"1111111111111111111111111111111111111111","fullRef":"refs/heads/main","repositoryIdentity":"b21a526d67a4251222f87dde72f2e6e99f0cdc4c9eb66d8e504aa0ed2483b456","schema":"pkgre-accepted-ref-v1"}
"#;
        assert!(parse_accepted_ref(duplicate, &config).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["extra"] = json!(true);
        let mut unknown = serde_json::to_vec_pretty(&value).unwrap();
        unknown.push(b'\n');
        assert!(parse_accepted_ref(&unknown, &config).is_err());
        assert!(
            AcceptedRef::new(
                "A".repeat(40),
                "refs/heads/main",
                "b21a526d67a4251222f87dde72f2e6e99f0cdc4c9eb66d8e504aa0ed2483b456"
            )
            .is_err()
        );
        let wrong = RepositoryConfig::new("refs/heads/main", "a".repeat(64)).unwrap();
        assert!(parse_accepted_ref(&bytes, &wrong).is_err());
        assert!(parse_accepted_ref(&[0xff], &config).is_err());
    }

    fn assert_full_ref_cases(cases: &[FullRefCase]) {
        let mut ids = HashSet::new();
        for case in cases {
            assert!(valid_id(&case.id));
            assert!(ids.insert(case.id.clone()));
            assert!(matches!(case.expected.as_str(), "valid" | "invalid"));
            assert_eq!(
                valid_full_ref(&case.value),
                case.expected == "valid",
                "case {}",
                case.id
            );
        }
    }

    fn valid_id(value: &str) -> bool {
        let mut bytes = value.bytes();
        matches!(bytes.next(), Some(b'a'..=b'z'))
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }
}
