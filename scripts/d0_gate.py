#!/usr/bin/env python3
"""Content-addressed D0 closure and live PRE_D1 gate verification."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

SCHEMA = "pkgre-d0-gate-state-v2"
AGGREGATE_PATH = "evidence/d0-basis-inventory-2026-08-26.md"
GATE_STATE_PATH = "evidence/d0-gate-state-2026-08-26.json"
D0_STATE_DRAFT_NAME = "d0-state-draft.json"
HISTORICAL_AGGREGATE_COMMIT = "5b7eb0f201dd9ea2a230d5dcefb6d085294a0cbf"
HISTORICAL_AGGREGATE_SHA256 = "43279e19d0173fbf62096142238d61d2278de548fdad17f07646253e2adbefdd"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
CLOSURE_SET_RE = re.compile(r"^d0-closure-[0-9a-f]{16,64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
PROCEDURAL_PRINCIPAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._:@-]{0,126}[a-z0-9])?$")
PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._@+=,-]+$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SEMVER_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
SSH_SHA256_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
UNIX_MODE_RE = re.compile(r"^0[0-7]{3}$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_SEMANTIC_INTEGER = 2**63 - 1
NIX_STORE_HASH_PATTERN = r"[0-9abcdfghijklmnpqrsvwxyz]{32}"
NIX_STORE_NAME_PATTERN = r"(?!(?:\.{1,2})(?:-|$))[A-Za-z0-9+._?=-]{1,211}"
NIX_DRV_NAME_PATTERN = r"(?!(?:\.{1,2})(?:-|$))[A-Za-z0-9+._?=-]{1,207}\.drv"
NIX_STORE_PATH_RE = re.compile(rf"^/nix/store/(?P<hash>{NIX_STORE_HASH_PATTERN})-(?P<name>{NIX_STORE_NAME_PATTERN})$")
NIX_DRV_RE = re.compile(rf"^/nix/store/{NIX_STORE_HASH_PATTERN}-{NIX_DRV_NAME_PATTERN}$")
RFC3986_PCHAR_RE = re.compile(r"^(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-F]{2})+$")
STRUCTURED_SOURCE_ENV_KEYS = frozenset({"hash", "outputHash", "outputHashMode", "src", "srcs", "urls"})
SRI_SHA256_RE = re.compile(r"^sha256-[A-Za-z0-9+/]{43}=$")
MAX_JSON_BYTES = 1024 * 1024
MAX_PROCEDURAL_AUTHORITY_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 4 * 1024 * 1024
MAX_PATH_BYTES = 1024
MAX_PATH_COMPONENT_BYTES = 255
MAX_DRV_BYTES = 4 * 1024 * 1024
MAX_DRV_DEPTH = 32
MAX_DRV_ITEMS = 100_000
MAX_DRV_STRING_BYTES = 2 * 1024 * 1024
RECEIPT_FUTURE_SKEW_SECONDS = 30
B18_RECEIPT_MAX_AGE_SECONDS = 600
PRE_D1_RECEIPT_MAX_AGE_SECONDS = 600
D0_LIVE_EVIDENCE_MAX_AGE_SECONDS = 24 * 60 * 60
D0_EVIDENCE_FUTURE_SKEW_SECONDS = 30
D0_CREDENTIAL_MAX_BYTES = 4 * 1024
D0_PRIVATE_KEY_MAX_BYTES = 64 * 1024
D0_CERTIFICATE_MAX_BYTES = 1024 * 1024
EVIDENCE_TREE_DOMAIN = b"pkgre-d0-evidence-tree-v1\0"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
B18_INCIDENT_SHA256 = "9d06853e9fa692c4b6347af8ac4bb85049d76322c41330768b5782e5df888efe"
B18_INCIDENT_PATH = "fixtures/d0-v1/basis-inventory/js-client-policy/raw/incident.txt"
B18_CONTACT = {"method": "GET", "url": "https://registry.npmjs.org/probe-missing", "responseStatus": 404}
B21_TARGETS = ["https://rust.pkg.re/config.json", "https://js.pkg.re/pkgre-js"]
B21_PROTOCOLS = ["HTTP/1.1", "HTTP/2"]
GITHUB_GOVERNANCE_BASELINE_PATH = "fixtures/d0-v1/basis-inventory/github-governance/actual-vs-d2.json"
GITHUB_GOVERNANCE_BASELINE_SHA256 = "f4522a842f9e041773014b3d7d7d78556536988a196918dc2e5c72ffd8b9d9e8"
GITHUB_CHECKOUT_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
GITHUB_APP_TOKEN_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
GITHUB_NIX_ACTION = "cachix/install-nix-action@13d8dd58da0234aa297dedd986986ccb8e7f3e24"
GITHUB_CONFIGURE_PAGES_ACTION = "actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b"
GITHUB_UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
GITHUB_DEPLOY_PAGES_ACTION = "actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e"
GITHUB_REST_API_VERSION = "2026-03-10"
GITHUB_REST_ACCEPT = "application/vnd.github+json"
GITHUB_REST_BASE = "https://api.github.com"
GITHUB_REST_OPENAPI_COMMIT = "7f6b9c117d7e720cb8dcbd6e650a20823f4b6f55"
GITHUB_REST_OPENAPI_SHA256 = "1d25fa69c37ecff6f515f592e1e178b6268adb09ec635177578f5c394ddef355"
GITHUB_REST_OPENAPI_DOCUMENT = "descriptions/api.github.com/api.github.com.json"
GITHUB_REST_OPENAPI_VERSION = "1.1.4"
GITHUB_OPENAPI_AUDIT_SCHEMA = "pkgre-d0-github-openapi-audit-v1"
GITHUB_OPENAPI_AUDIT_SCOPE = {"document": "EXACT_SHA256_PINNED_GITHUB_OPENAPI_DOCUMENT", "dialect": "FAIL_CLOSED_SECURITY_RELEVANT_OPENAPI_3_0_SUBSET", "parameters": "CONTRACT_PATH_QUERY_SERIALIZATION_SCHEMA_WITNESSES_AND_NO_OTHER_REQUIRED_LOCATIONS", "requestBodies": "CONCRETE_TYPED_REPRESENTATIVE_SCHEMA_WITNESS_OR_FRESH_CAPTURE_RECONSTRUCTION_CONTRACT", "responseBindings": "JSON_POINTER_AND_TYPE_SCHEMA_WITNESS_NOT_RUNTIME_VALUE_VALIDATION", "pinnedClaims": "EXACT_CONFIGURED_OPERATION_SET_OPERATION_ID_SUMMARY_APP_ELIGIBILITY_STATUS", "completeOpenApiValidation": False}
GITHUB_OPENAPI_REQUIRED_PINNED_CLAIMS = {"rust": frozenset({"list-user-installation-repositories"}), "js": frozenset({"list-user-installation-repositories"})}
GITHUB_PROVIDER_PROJECTION_DOMAIN = "pkgre-d0-github-provider-projection-v2"
GITHUB_VERIFIED_COMMIT_REASON = "valid"
GITHUB_FORK_PR_APPROVAL_POLICY = "first_time_contributors_new_to_github"
GITHUB_PROVIDER_EVIDENCE_KINDS = [
    "ACTIONS_POLICY_READBACK",
    "ADMISSION_RULESET_ID_AND_READBACK",
    "AUDIT_LOG_RECORDS",
    "BOOTSTRAP_COMMIT_AND_REF_ADVANCE",
    "CANDIDATE_CHECK_PRODUCER_ID_AND_RUN",
    "CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK",
    "CLASSIC_BRANCH_PROTECTION_FINAL_READBACK",
    "D2_PRE_MUTATION_CAPTURE",
    "EFFECTIVE_MAIN_RULES_READBACK",
    "FIRST_NORMAL_RELEASE_RUN",
    "INVARIANT_RULESET_ID_AND_READBACK",
    "PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK",
    "PROTECTED_ENVIRONMENT_ID_AND_READBACK",
    "PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING",
    "REF_UPDATE_AND_BYPASS_AUDIT",
    "RELEASE_APP_INSTALLATION_ID_AND_READBACK",
    "RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK",
    "SIGNING_KEY_REGISTRATION_AND_READBACK",
    "TRUSTED_SURFACE_TREE_READBACK",
]
GITHUB_PROVIDER_REQUIRED_BINDINGS = {
    "ACTIONS_POLICY_READBACK": ["repositoryId", "enabled", "allowedActions", "selectedPolicy", "requireFullLengthCommitSha", "defaultWorkflowPermissions", "canApprovePullRequestReviews", "forkPullRequestApprovalPolicy"],
    "ADMISSION_RULESET_ID_AND_READBACK": ["repositoryId", "rulesetId", "nodeId", "createdAt", "updatedAt", "source", "target", "enforcement", "conditions", "rulesAndParameters", "bypassActorId", "bypassActorType", "bypassMode"],
    "AUDIT_LOG_RECORDS": ["repositoryId", "requestId", "actorId", "actorLogin", "action", "resourceId", "createdAt", "result", "sourceArtifactSha256"],
    "BOOTSTRAP_COMMIT_AND_REF_ADVANCE": ["repositoryId", "requestId", "baselineA", "bootstrapCommitB", "bootstrapTreeOid", "soleParentOid", "temporaryRef", "signatureFormat", "signerPrincipal", "signerGithubLogin", "signerSshSha256Fingerprint", "signerProviderSshSigningKeyId", "localVerificationTranscriptSha256", "providerVerificationVerified", "providerVerificationReason", "providerVerifiedAt", "preUpdateOid", "postUpdateOid", "force", "result"],
    "CANDIDATE_CHECK_PRODUCER_ID_AND_RUN": ["repositoryId", "context", "renderedCheckRunName", "workflowName", "jobId", "jobNameLiteral", "integrationId", "candidateSha", "workflowId", "workflowRunId", "checkSuiteId", "checkRunId", "conclusion"],
    "CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK": ["repositoryId", "workflowId", "nodeId", "path", "name", "defaultBranchCommitOid", "gitBlobOid", "contentSha256", "triggers", "permissions"],
    "CLASSIC_BRANCH_PROTECTION_FINAL_READBACK": ["repositoryId", "sourceRef", "targetState", "httpStatus", "observedAt"],
    "D2_PRE_MUTATION_CAPTURE": ["evidenceKey", "capturedAt", "apiVersion", "repository", "repositoryId", "canonicalOrigin", "transport", "sourceRef", "sourceCommitOid", "workflowBindings", "canonicalSettingsDigest", "providerRequestDigest", "rawResponseDigest", "captureManifestSha256"],
    "EFFECTIVE_MAIN_RULES_READBACK": ["repositoryId", "sourceRef", "effectiveRules", "rulesetIds", "classicBranchProtectionState", "observedAt"],
    "FIRST_NORMAL_RELEASE_RUN": ["repositoryId", "workflowId", "workflowRunId", "deploymentId", "environmentId", "candidateTreeCommitOid", "signedReleaseCommitOid", "treeOid", "soleParentOid", "trustedWorkflowCommitOid", "trustedWorkflowBlobOid", "checkIntegrationId", "dispatcherUserId", "dispatchAuthenticatedActorUserId", "triggeringActorUserId", "reviewerUserId", "pendingDeploymentReviewerUserId", "pendingDeploymentCurrentUserCanApprove", "reviewAuthenticatedActorUserId", "reviewApprovalAuditActorUserId", "tokenRepositoryIds", "tokenPermissions", "tokenExpiresAt", "signerAccessInterfaceDesignId", "signerGithubLogin", "signerSshSha256Fingerprint", "signerProviderSshSigningKeyId", "providerVerificationVerified", "providerVerificationReason", "providerVerifiedAt", "preUpdateOid", "postUpdateOid", "localVerificationTranscriptSha256", "result"],
    "INVARIANT_RULESET_ID_AND_READBACK": ["repositoryId", "rulesetId", "nodeId", "createdAt", "updatedAt", "source", "target", "enforcement", "conditions", "rulesAndParameters", "bypassActors"],
    "PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK": ["repositoryId", "workflowId", "nodeId", "path", "name", "defaultBranchCommitOid", "gitBlobOid", "contentSha256", "triggers", "permissions"],
    "PROTECTED_ENVIRONMENT_ID_AND_READBACK": ["repositoryId", "environmentId", "nodeId", "name", "protectionRuleIds", "deploymentBranchPolicyIds", "reviewerProviderIds", "reviewerLogins", "preventSelfReview", "branchPolicy", "adminBypassUiReadbackSha256"],
    "PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING": ["repositoryId", "pullRequestId", "pullRequestNumber", "baseRef", "baseSha", "headSha", "reviewId", "reviewCommitId", "reviewerProviderId", "reviewerLogin", "reviewerAssociation", "codeOwnerReview", "lastPushApproval"],
    "REF_UPDATE_AND_BYPASS_AUDIT": ["repositoryId", "requestId", "sourceRef", "preUpdateOid", "postUpdateOid", "force", "fastForward", "actorType", "appId", "installationId", "rulesetId", "bypassMode", "auditRecordIds"],
    "RELEASE_APP_INSTALLATION_ID_AND_READBACK": ["repositoryId", "appId", "installationId", "slug", "owner", "repositorySelection", "selectedRepositoryIds", "selectedRepositoryCount", "installedPermissions", "requestedTokenPermissions", "tokenRepositoryIds"],
    "RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK": ["repositoryId", "workflowId", "nodeId", "path", "name", "defaultBranchCommitOid", "gitBlobOid", "contentSha256", "triggers", "permissions", "releaseAuthorityConsumers"],
    "SIGNING_KEY_REGISTRATION_AND_READBACK": ["repositoryId", "githubLogin", "sshEd25519PublicKey", "sshSha256Fingerprint", "title", "providerSshSigningKeyId", "providerCreatedAt", "baselinePresence", "createdByCeremony", "authenticatedUserReadbackSha256", "authenticatedKeyReadbackSha256", "publicKeyReadbackSha256", "result"],
    "TRUSTED_SURFACE_TREE_READBACK": ["repositoryId", "commitOid", "treeOid", "workflowManifest", "localActionManifest", "repositoryExecutableInputs", "externalRepositoryInputs", "externalActions", "canonicalSurfaceDigest"],
}
GITHUB_CANDIDATE_VALIDATION_SCOPE = ["ARCHIVE_HASHES", "CATALOG_POLICY", "CATALOG_SCHEMA", "PROJECTION"]
GITHUB_LOGIN_RE = re.compile(r"^[a-z0-9](?:(?!.*--)[a-z0-9-]{0,37}[a-z0-9])?$")
GITHUB_REPOSITORY_IDS = {"pkgre/rust": 1342904147, "pkgre/js": 1345630585}
GITHUB_CATALOG_TREE_OIDS = {"pkgre/rust": "c448a9f3560bf286bd89a52aab0e5f77a4c85553", "pkgre/js": "b8c0d5dae071cad4416795e5612c1ddb234bd104"}
GITHUB_PAGES_BASELINES = {
    "rust": {"commitOid": "f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b", "gitBlobOid": "0799e0070b7500dea5aa688c1898a92c2a907f93", "contentSha256": "cd46abf20d47894a4ffcc10550953848f6dcbc6c3703239cee0635e4c453a114"},
    "js": {"commitOid": "f43bd58bd3d4e36f8b3f4df3c002735c977acd17", "gitBlobOid": "dd19b88fa455c48eb2a3a817072c8b954e8c65f3", "contentSha256": "4c6aaf4fff2ee0a2f2d1f433d01d1e6f7d62f069b21b7017488539d48660f7e8"},
}
GITHUB_EXTERNAL_INDEXER = {"repository": "pkgre/pkgre", "commitOid": "066293df21743cbf41fb571a38f2bb94059e7274", "treeOid": "0326ff44970839b753dca8b1f9bbd649b54c004d", "transport": "HTTPS", "canonicalOrigin": "https://github.com/pkgre/pkgre.git", "credentialMode": "ANONYMOUS_READ_ONLY"}
GITHUB_JS_EXECUTABLE_INPUTS = [
    {"path": "scripts/build-site.sh", "gitBlobOid": "03c77e160c8b1e3b4b469020b7998d45e07299df", "contentSha256": "f981bb5579d23695962a782f8dabd3eee18412a99252798ac7adf4cbb3b03b01"},
    {"path": "scripts/check-bootstrap.sh", "gitBlobOid": "59be16f06d75de27796c79ce480945d9db4b1e3d", "contentSha256": "0bdfc67aaec370219a600012d85ee8e3f3d8d6ac733754ae5af11f9511604108"},
    {"path": "scripts/check-site.sh", "gitBlobOid": "3a639046793e39946d6fe428ae552efbf5d8321d", "contentSha256": "99c2d663715bac9a796547df50599458a5c43c0acbbb1964becd3c6c92a0e4ac"},
    {"path": "scripts/test-site.sh", "gitBlobOid": "7b2ef9aaccd65a07720dee64e2964f9d78cfcd33", "contentSha256": "4e804ad4bbb5bd5bf234373869a75c7b94352aa5feca1f4b76b498d3c90c5f39"},
]


@dataclass(frozen=True)
class RepositoryBasis:
    id: str
    path: str
    remote: str
    remote_url: str
    ref: str
    upstream: str
    reviewed_commit: str

    def state_row(self) -> dict[str, str]:
        return {
            "id": self.id,
            "path": self.path,
            "remote": self.remote,
            "remoteUrl": self.remote_url,
            "ref": self.ref,
            "upstream": self.upstream,
            "reviewedCommit": self.reviewed_commit,
        }


PRODUCTION_REPOSITORIES = (
    RepositoryBasis("pkgre/pkgre", "pkgre", "origin", "git@github.com:pkgre/pkgre.git", "refs/heads/main", "origin/main", "066293df21743cbf41fb571a38f2bb94059e7274"),
    RepositoryBasis("pkgre/rust", "pkgre-rust", "origin", "git@github.com:pkgre/rust.git", "refs/heads/main", "origin/main", "f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b"),
    RepositoryBasis("pkgre/js", "pkgre-js", "origin", "git@github.com:pkgre/js.git", "refs/heads/main", "origin/main", "f43bd58bd3d4e36f8b3f4df3c002735c977acd17"),
    RepositoryBasis("infra", "infra", "origin", "git@gitlab.pacna.net:infra/infra.git", "refs/heads/master", "origin/master", "5f68539bd99c6952b6d73fe2596c27ad4a319f57"),
)
EXPECTED_BASIS = [row.state_row() for row in PRODUCTION_REPOSITORIES]
INFRA_REVIEWED_COMMIT = next(row.reviewed_commit for row in PRODUCTION_REPOSITORIES if row.id == "infra")


@dataclass(frozen=True)
class GateConfig:
    historical_aggregate_commit: str = HISTORICAL_AGGREGATE_COMMIT
    historical_aggregate_sha256: str = HISTORICAL_AGGREGATE_SHA256
    repositories: tuple[RepositoryBasis, ...] = PRODUCTION_REPOSITORIES
    allow_git_transport_overrides: bool = False


PRODUCTION_CONFIG = GateConfig()

EXPECTED_FACT_STATES = {
    "D0-B01": "UNSAFE", "D0-B02": "UNPROVED", "D0-B03": "UNSAFE", "D0-B04": "ABSENT", "D0-B05": "UNPROVED", "D0-B06": "UNPROVED", "D0-B07": "ABSENT", "D0-B08": "ABSENT", "D0-B09": "UNPROVED", "D0-B10": "ABSENT", "D0-B11": "UNPROVED", "D0-B12": "UNPROVED", "D0-B13": "ABSENT", "D0-B14": "ABSENT", "D0-B15": "OBSERVED", "D0-B16": "ABSENT", "D0-B17": "ABSENT", "D0-B18": "OBSERVED", "D0-B19": "ABSENT", "D0-B20": "UNPROVED", "D0-B21": "ABSENT", "D0-B22": "UNPROVED",
}
IMMEDIATE_FINDINGS = set(EXPECTED_FACT_STATES) - {"D0-B14", "D0-B15", "D0-B19"}
LATER_FINDINGS = {"D0-B14", "D0-B15"}
DEFERRED_FINDINGS = {"D0-B19"}
HANDOFFS = {
    "OP-D0-01": (1, "Critical Gandi credential containment+TLS-key lifecycle", ["D0-B01"]),
    "OP-D0-02": (2, "Rain SSH attestation+lifecycle", ["D0-B02"]),
    "OP-D0-03": (3, "Exact deployed provenance", ["D0-B05"]),
    "OP-D0-04": (4, "Production signing authority design—no secret installation", ["D0-B04"]),
    "OP-D0-05": (5, "D2 GitHub target design—no settings action", ["D0-B03", "D0-B04"]),
    "OP-D0-06": (6, "Deployment identity decision or explicit phase-plan amendment", ["D0-B06", "D0-B07", "D0-B10", "D0-B13"]),
    "OP-D0-07": (7, "Proof-order amendment decisions", ["D0-B06", "D0-B08", "D0-B09", "D0-B10", "D0-B12", "D0-B16", "D0-B20", "D0-B21"]),
    "OP-D0-08": (8, "Storage policy inputs", ["D0-B11"]),
    "OP-D0-09": (9, "Client coverage timing", ["D0-B17", "D0-B18"]),
    "OP-D0-10": (10, "LAN deferral", ["D0-B19"]),
    "OP-D0-11": (11, "Original host-tool provenance", ["D0-B22"]),
}
FINDING_HANDOFFS = {finding: sorted(handoff for handoff, (_, _, findings) in HANDOFFS.items() if finding in findings) for finding in EXPECTED_FACT_STATES}
LATER_GATES = [
    {"id": "PRE_D1_REFETCH", "findingRefs": [], "conditionalOnAmendment": False, "requirement": "Fresh fetch --prune and live Git verification of all four repositories immediately before the first D1 edit"},
    {"id": "PRE_D2_STORAGE", "findingRefs": ["D0-B11"], "conditionalOnAmendment": False, "requirement": "Agent-owned provider and storage feasibility passes against operator-reviewed capacity ceilings"},
    {"id": "D2_SIGNING", "findingRefs": ["D0-B03", "D0-B04"], "conditionalOnAmendment": False, "requirement": "Commit the exact release workflow and close signer trust plus provider-governance evidence before the D2 signing handoff"},
    {"id": "PRE_D3_SERVER_CLOSURE", "findingRefs": ["D0-B15"], "conditionalOnAmendment": False, "requirement": "Admit the exact pkgre-rust-serve feature and lock closure before server implementation"},
    {"id": "PRE_D5_CARGO_OFFLINE", "findingRefs": ["D0-B15"], "conditionalOnAmendment": False, "requirement": "Set and prove Cargo net.offline for self-host and cold-replay fixtures"},
    {"id": "PRE_D6_CLIENT_MATRIX", "findingRefs": ["D0-B17"], "conditionalOnAmendment": False, "requirement": "Pin an independently current Deno and add the scoped npm production fixture unless a reviewed replacement contract says otherwise"},
    {"id": "PRE_D6_EDGE", "findingRefs": ["D0-B09", "D0-B21"], "conditionalOnAmendment": True, "requirement": "Complete production-equivalent edge and explicit no-1xx proof before D6 completion"},
    {"id": "D4_BEFORE_D7_RESOURCE_TIME_CLOCK_CRASH", "findingRefs": ["D0-B10", "D0-B12"], "conditionalOnAmendment": True, "requirement": "Complete native resource,time,clock,lifecycle,and crash proofs plus reviewed hard maxima before D7"},
    {"id": "PRE_D7_REAL_RAIN_EDGE", "findingRefs": ["D0-B06", "D0-B09", "D0-B21"], "conditionalOnAmendment": True, "requirement": "Complete real-Rain H1/H2 edge,identity,denial,and no-1xx integration proof before public cutover"},
    {"id": "PRE_D7_FRONTEND_CHANGE_ROLLBACK", "findingRefs": ["D0-B06", "D0-B08"], "conditionalOnAmendment": True, "requirement": "Complete compatibility and rollback identities plus immutable rollback bundles and restore rehearsal before the first frontend change"},
    {"id": "PRE_D8_RUST_ACCESS_LOG", "findingRefs": ["D0-B20"], "conditionalOnAmendment": True, "requirement": "Complete authorized bounded Rust access-log discovery and route reconciliation before D8"},
    {"id": "PRE_D9_RUST_BODIES", "findingRefs": ["D0-B07", "D0-B14"], "conditionalOnAmendment": False, "requirement": "Import and verify complete Rust archive bodies and freeze a distinct Rust body identity"},
    {"id": "PRE_D11_JS_INITIAL_ANCHOR", "findingRefs": ["D0-B08", "D0-B16"], "conditionalOnAmendment": False, "requirement": "Build,reconstruct,and prove the immutable JS-INITIAL-ANCHOR"},
    {"id": "PRE_D11_JS_ACCESS_LOG", "findingRefs": ["D0-B20"], "conditionalOnAmendment": True, "requirement": "Complete authorized bounded JS access-log discovery and route reconciliation before D11"},
    {"id": "PRE_D12_JS_BODIES", "findingRefs": ["D0-B07", "D0-B14"], "conditionalOnAmendment": False, "requirement": "Import and verify complete JS archive bodies and freeze a distinct JS body identity"},
    {"id": "D13_LAN_SELECTION", "findingRefs": ["D0-B19"], "conditionalOnAmendment": False, "requirement": "Select and freeze every LAN identity,authority,credential,network,DNS,TLS,and state row before any LAN edit"},
]
MUTATION_POLICY = {"id": "D0-MUTATION-POLICY-v1", "operatorEmergencyExceptions": [{"id": "GANDI_CREDENTIAL_CONTAINMENT", "scope": "credential-containment-only", "returnedEvidence": "metadata-only", "forbidden": ["token-bytes", "token-hash", "private-key-bytes", "private-key-hash"]}]}
AGENT_MUTATIONS = ["rainDeployment", "dnsChange", "githubSettingsChange", "signerInstallation", "catalogRefAdvance", "bodyImport", "cargoConfigEdit", "d1Implementation", "credentialValueRead", "credentialMutation", "privateKeyValueRead", "lanSourceEdit", "lanConfiguration", "lanCredential", "lanDns", "lanTls", "lanDeployment"]
OPERATOR_MUTATIONS = ["rainDeployment", "dnsChange", "githubSettingsChange", "signerInstallation", "catalogRefAdvance", "bodyImport", "cargoConfigEdit", "d1Implementation", "lanSourceEdit", "lanConfiguration", "lanCredential", "lanDns", "lanTls", "lanDeployment"]
PROCEDURAL_AUTHORITY_SCHEMA = "pkgre-d0-procedural-authority-v1"
PROCEDURAL_AUTHORITY_ASSURANCE = {"artifactAuthorshipProven": False, "cryptographicIdentityAuthentication": False, "roleAssignmentAuthority": "CALLER_OUT_OF_BAND_PROCEDURE", "verifierAssurance": "CONTENT_BINDING_ORDERING_AND_CONSISTENCY_WITH_EXTERNAL_ASSIGNMENT_ONLY"}
PROCEDURAL_ROLES = {"operatorReturn": "PROCEDURAL_OPERATOR_RETURNER", "agentVerification": "PROCEDURAL_AGENT_VERIFIER", "proceduralReview": "PROCEDURAL_REVIEWER"}
SEMANTIC_EVIDENCE_SCHEMA = "pkgre-d0-semantic-evidence-v1"
PHASE_AMENDMENT_SCHEMA = "pkgre-d0-phase-amendment-v1"
B13_APPROVAL_SCHEMA = "pkgre-d0-b13-approval-v1"
B13_APPROVAL_POLICY = {
    "protocol-enums": {"decision": "APPROVE_EXACT_PROTOCOL_ENUMS", "scope": "D0_B13_PROTOCOL_ENUMS", "projectionSchema": "pkgre-d0-protocol-enums-projection-v1"},
    "hard-maxima": {"decision": "APPROVE_EXACT_HARD_MAXIMA", "scope": "D0_B13_HARD_MAXIMA", "projectionSchema": "pkgre-d0-hard-maxima-projection-v1"},
    "instance-digests": {"decision": "APPROVE_EXACT_SIX_INSTANCE_PROFILES", "scope": "D0_B13_INSTANCE_DIGESTS", "projectionSchema": "pkgre-d0-instance-profiles-projection-v1"},
}
B13_PROTOCOL_ENUMS_PROJECTION = {
    "configSchema": "pkgre-dynamic-instance-config-v1",
    "protocolContract": "pkgre-public-http-contract-v1",
    "stateContracts": ["state-contract-v1"],
    "redirectMarkerSchemas": {"dynamic": [None], "legacyAdapter": ["redirect-marker-v1"]},
    "gitObjectFormats": ["sha1"],
    "ecosystems": ["rust", "js"],
    "modes": ["public"],
    "audiences": ["public"],
    "instanceRoles": ["compatibility", "body", "rollback"],
    "deliveryModes": ["redirect", "body"],
    "updatePolicies": ["watch-fixed-ref", "frozen-no-watcher"],
    "sourceTransports": ["https-anonymous"],
    "applicationProtocols": ["HTTP/1.1"],
    "networkTransports": ["tcp"],
    "methods": ["GET", "HEAD"],
    "responseStatuses": [200, 304, 307, 400, 404, 405, 408, 413, 414, 431, 503],
    "contentTypes": {"archive": "application/octet-stream", "json": "application/json; charset=utf-8", "rustSparse": "text/plain; charset=utf-8"},
    "unsupportedMethod": {"status": 405, "allow": "GET, HEAD"},
    "compatibilityRedirect": {"status": 307, "bodyBytes": 0},
    "boundedRejectCodes": ["TIME_CLOCK_UNTRUSTED", "FETCH_TIMEOUT", "FETCH_BYTES", "GIT_OBJECT_LIMIT", "TREE_LIMIT", "FILE_LIMIT", "CATALOG_LIMIT", "ARCHIVE_LIMIT", "ROUTE_LIMIT", "SNAPSHOT_LIMIT", "MEMORY_ESTIMATE", "RELOAD_TIMEOUT", "STATE_SPACE", "RESOURCE_FAILURE"],
}
SAT_EVIDENCE_BY_HANDOFF = {
    "D0-B01": {"OP-D0-01": {"credential-containment", "credential-lifecycle"}},
    "D0-B02": {"OP-D0-02": {"ssh-attestation", "ssh-lifecycle"}},
    "D0-B03": {"OP-D0-05": {"github-governance-proof"}},
    "D0-B04": {"OP-D0-04": {"signing-authority-design", "signing-lifecycle"}, "OP-D0-05": {"signing-workflow-binding"}},
    "D0-B05": {"OP-D0-03": {"deployment-provenance"}},
    "D0-B06": {"OP-D0-06": {"literal-service-identities"}, "OP-D0-07": {"network-tls-identities"}},
    "D0-B07": {"OP-D0-06": {"distinct-body-identities"}},
    "D0-B08": {"OP-D0-07": {"immutable-rollback-proof", "js-initial-anchor"}},
    "D0-B09": {"OP-D0-07": {"production-edge-proof"}},
    "D0-B10": {"OP-D0-06": {"approved-limits"}, "OP-D0-07": {"native-resource-proof"}},
    "D0-B11": {"OP-D0-08": {"storage-policy", "storage-feasibility-proof"}},
    "D0-B12": {"OP-D0-07": {"clock-policy", "clock-proof"}},
    "D0-B13": {"OP-D0-06": {"protocol-enums", "hard-maxima", "instance-digests"}},
    "D0-B16": {"OP-D0-07": {"js-continuity-proof", "js-initial-anchor"}},
    "D0-B17": {"OP-D0-09": {"deno-current-pin", "scoped-npm-fixture"}},
    "D0-B20": {"OP-D0-07": {"complete-access-log-reconciliation"}},
}
SAT_EVIDENCE = {finding_id: set().union(*by_handoff.values()) for finding_id, by_handoff in SAT_EVIDENCE_BY_HANDOFF.items()}
REPHASE_TARGETS = {
    "D0-B03": ["D2_SIGNING"], "D0-B04": ["D2_SIGNING"], "D0-B06": ["PRE_D7_FRONTEND_CHANGE_ROLLBACK", "PRE_D7_REAL_RAIN_EDGE"], "D0-B07": ["PRE_D9_RUST_BODIES", "PRE_D12_JS_BODIES"], "D0-B08": ["PRE_D7_FRONTEND_CHANGE_ROLLBACK", "PRE_D11_JS_INITIAL_ANCHOR"], "D0-B09": ["PRE_D6_EDGE", "PRE_D7_REAL_RAIN_EDGE"], "D0-B10": ["D4_BEFORE_D7_RESOURCE_TIME_CLOCK_CRASH"], "D0-B11": ["PRE_D2_STORAGE"], "D0-B12": ["D4_BEFORE_D7_RESOURCE_TIME_CLOCK_CRASH"], "D0-B16": ["PRE_D11_JS_INITIAL_ANCHOR"], "D0-B17": ["PRE_D6_CLIENT_MATRIX"], "D0-B20": ["PRE_D8_RUST_ACCESS_LOG", "PRE_D11_JS_ACCESS_LOG"],
}
LATER_GATES_BY_ID = {row["id"]: row for row in LATER_GATES}
RAIN_SSH_HOST = "rain.pacna.org"
RAIN_SSH_FINGERPRINT = "SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI"
INFRA_REPOSITORY_ID = "infra/infra"
RAIN_PKGRE_MODULE_PATH = "hosts/rain/containers/pkgre.nix"
ACME_NAMES = ["rust.pkg.re", "js.pkg.re", "dl.rust.pkg.re"]
FILE_METADATA_RETURNED_FIELDS = ["path", "fileType", "symlinkTarget", "owner", "group", "mode", "acl", "aclComplete", "sizeBytes", "purpose", "readerMechanism", "effectiveReaders", "observedAt", "sourceGeneration"]
ORIGINAL_PACKAGE_DRVS = {"git-host": "/nix/store/bny4hxrsvnaj060b6rbd68233x4fw32h-git-2.54.0.drv", "nix-host": "/nix/store/iza23qnw05vpa85g804b841rd4yqr1z5-nix-2.34.8.drv"}
OBSERVED_OUTPUTS = {"git-host": "/nix/store/k3wl6cg7q50zkx47af3msmg1yrg1f203-git-2.54.0", "nix-host": "/nix/store/kgwqirnzhflf9vmrkzgqz16z2bry397z-nix-2.34.8"}
KNOWN_SURROGATE_DRV_SHA256S = {
    "/nix/store/214n5nb1k4qzynzgw7xpsp4fp19vni8i-git-2.54.0.drv": "90f842d2f6793d3871d983cc3eb6863b54258cf02f2ff6db477349ddee885a89",
    "/nix/store/y9rx70ykgm2hqniaw2qrqp6kqc5n6xbf-nix-2.34.8.drv": "db0c02ca5edc3fc59bacca226fa77078e98ea2857c1059fce711ebdf75c78b0a",
    "/nix/store/cgrzc3wys8sljv5k23xfmmlzx0s21vjv-git-2.54.0.tar.xz.drv": "37085e2de8bfd72045da2e2da33bda0e93ec6cd47c91ab7219d4bdbc4d1bc9b3",
    "/nix/store/1gys5xmkzxr4qbycxl7ilkb15d35z1g2-source.drv": "9669d6daf85d974b7a7d71f591a557454a8abd0141553baad71e6ea3382b8e6d",
}
SURROGATE_PACKAGE_DRVS = {
    "/nix/store/214n5nb1k4qzynzgw7xpsp4fp19vni8i-git-2.54.0.drv",
    "/nix/store/y9rx70ykgm2hqniaw2qrqp6kqc5n6xbf-nix-2.34.8.drv",
}
SURROGATE_PACKAGE_DRV_SHA256S = {KNOWN_SURROGATE_DRV_SHA256S[path] for path in SURROGATE_PACKAGE_DRVS}
D0_ALLOWED_PATHS = {
    AGGREGATE_PATH,
    GATE_STATE_PATH,
    "fixtures/d0-v1/nix-derivation-vectors/README.md",
    "fixtures/d0-v1/nix-derivation-vectors/SHA256SUMS",
    "fixtures/d0-v1/nix-derivation-vectors/drvs/1gys5xmkzxr4qbycxl7ilkb15d35z1g2-source.drv",
    "fixtures/d0-v1/nix-derivation-vectors/drvs/cgrzc3wys8sljv5k23xfmmlzx0s21vjv-git-2.54.0.tar.xz.drv",
    "fixtures/d0-v1/nix-derivation-vectors/drvs/ji4chnn38m9yjm5fq9w624w63vwf456s-source.drv",
    "fixtures/d0-v1/nix-derivation-vectors/vectors.json",
    "scripts/d0_gate.py",
    "scripts/test-d0-gate.py",
    "scripts/test-verify-d0-evidence.py",
    "scripts/verify-d0-evidence.py",
}
D0_ALLOWED_PREFIXES = ("evidence/d0-closure/", "fixtures/d0-v1/basis-inventory/", "fixtures/d0-v1/archive-git-rehearsal/", "fixtures/d0-v1/d0-time-resource-proposal/")
GATE_SENSITIVE_PREFIXES = (b"evidence/", b"fixtures/d0-v1/", b"scripts/d0_gate.py", b"scripts/test-d0-gate.py", b"scripts/verify-d0-evidence.py", b"scripts/test-verify-d0-evidence.py")
FORBIDDEN_GIT_ENV = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_ATTR_NOSYSTEM", "GIT_CEILING_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM", "GIT_DIR", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_INDEX_FILE", "GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY", "GIT_PROTOCOL_FROM_USER", "GIT_REPLACE_REF_BASE", "GIT_SHALLOW_FILE", "GIT_SSH_VARIANT", "GIT_WORK_TREE",
)
FORBIDDEN_NONEMPTY_ENV = ("GIT_ASKPASS", "GIT_PROXY_COMMAND", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE")
TRANSPORT_OVERRIDE_ENV = ("GIT_SSH", "GIT_SSH_COMMAND")
TRUSTED_GIT_CANDIDATES = ("/run/current-system/sw/bin/git", "/nix/var/nix/profiles/default/bin/git", "/usr/bin/git", "/bin/git", "/home/dev0/.nix-profile/bin/git")
TRUSTED_SSH_CANDIDATES = ("/run/current-system/sw/bin/ssh", "/nix/var/nix/profiles/default/bin/ssh", "/usr/bin/ssh", "/bin/ssh", "/home/dev0/.nix-profile/bin/ssh")
INTERNAL_GIT_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "PAGER": "cat"}
FORBIDDEN_CONFIG_EXACT = {"core.alternaterefscommand", "core.alternaterefsprefixes", "core.fsmonitor", "core.hookspath", "core.sshcommand", "core.untrackedcache", "core.worktree", "extensions.partialclone", "extensions.worktreeconfig", "ssh.variant"}
FORBIDDEN_CONFIG_PREFIXES = ("filter.", "fsck.", "fetch.fsck.", "receive.fsck.", "include.", "includeif.", "protocol.", "transfer.fsck.", "url.")


class GateVerificationError(RuntimeError):
    pass


GitRunner = Callable[[Path, tuple[str, ...], Mapping[str, str]], subprocess.CompletedProcess[bytes]]


def trusted_executable(candidates: Sequence[str], label: str) -> Path:
    for candidate in candidates:
        path = Path(candidate)
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            continue
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        if not (str(resolved).startswith("/nix/store/") or str(resolved).startswith("/usr/") or str(resolved).startswith("/bin/")):
            continue
        return resolved
    raise GateVerificationError(f"no root-owned non-writable trusted {label} executable is available")


def default_git_runner(repo: Path, arguments: tuple[str, ...], environment: Mapping[str, str]) -> subprocess.CompletedProcess[bytes]:
    executable = trusted_executable(TRUSTED_GIT_CANDIDATES, "Git")
    return subprocess.run([str(executable), "-C", str(repo), *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=dict(environment))


class GitOps:
    def __init__(self, runner: GitRunner = default_git_runner, environment: Mapping[str, str] | None = None, allow_transport_overrides: bool = False) -> None:
        source = dict(os.environ if environment is None else environment)
        forbidden = sorted(
            key
            for key in source
            if key in FORBIDDEN_GIT_ENV or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_")
        )
        require(not forbidden, f"forbidden Git object/worktree/config environment overrides: {forbidden!r}")
        nonempty_overrides = sorted(key for key in FORBIDDEN_NONEMPTY_ENV if source.get(key, "") != "")
        require(not nonempty_overrides, f"forbidden Git askpass/proxy environment overrides: {nonempty_overrides!r}")
        transport_overrides = sorted(key for key in TRANSPORT_OVERRIDE_ENV if source.get(key, "") != "")
        require(allow_transport_overrides or not transport_overrides, f"forbidden Git transport environment overrides: {transport_overrides!r}")
        git_executable = trusted_executable(TRUSTED_GIT_CANDIDATES, "Git")
        ssh_executable = trusted_executable(TRUSTED_SSH_CANDIDATES, "SSH")
        clean = {key: source[key] for key in ("HOME", "LOGNAME", "SSH_AUTH_SOCK", "TMPDIR", "USER", "XDG_RUNTIME_DIR") if source.get(key, "") != ""}
        clean.update(INTERNAL_GIT_ENV)
        ssh_arguments = (
            str(ssh_executable),
            "-F", "/dev/null",
            "-oBatchMode=yes",
            "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no",
            "-oNumberOfPasswordPrompts=0",
            "-oProxyCommand=none",
            "-oProxyJump=none",
            "-oLocalCommand=none",
            "-oPermitLocalCommand=no",
            "-oCanonicalizeHostname=no",
            "-oControlMaster=no",
        )
        clean["GIT_SSH_COMMAND"] = shlex.join(ssh_arguments)
        clean["PATH"] = os.pathsep.join(dict.fromkeys((str(git_executable.parent), str(ssh_executable.parent), "/usr/bin", "/bin")))
        self.runner = runner
        self.environment = clean
        self.input_transport_overrides = transport_overrides
        self.git_executable = git_executable
        self.ssh_executable = ssh_executable

    def run(self, repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        process = self.runner(repo, tuple(arguments), self.environment)
        if check and process.returncode != 0:
            stderr = process.stderr.decode("utf-8", errors="replace").strip()
            raise GateVerificationError(f"git {' '.join(arguments)} failed in {repo}: exit={process.returncode}:{stderr}")
        return process

    def text(self, repo: Path, *arguments: str, check: bool = True) -> str:
        raw = self.run(repo, *arguments, check=check).stdout
        try:
            return raw.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"git {' '.join(arguments)} returned non-UTF-8 output") from error

    def blob(self, repo: Path, commit: str, relative: str, label: str, max_bytes: int = MAX_ARTIFACT_BYTES, expected_mode: str | None = None) -> bytes:
        require(HEX40_RE.fullmatch(commit) is not None, f"{label}: invalid commit")
        safe_path(relative, f"{label} path")
        output = self.run(repo, "ls-tree", "--full-tree", "-z", commit, "--", f":(literal){relative}").stdout
        rows = [row for row in output.split(b"\0") if row]
        require(len(rows) == 1, f"{label}: missing or ambiguous Git tree entry {commit}:{relative}")
        try:
            row = rows[0].decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}: Git tree entry is not UTF-8") from error
        match = re.fullmatch(r"(100644|100755) blob ([0-9a-f]{40})\t(.+)", row)
        require(match is not None and match.group(3) == relative, f"{label}: entry is not a regular Git blob")
        if expected_mode is not None:
            require(expected_mode in {"100644", "100755"}, f"{label}: invalid expected Git blob mode")
            require(match.group(1) == expected_mode, f"{label}: Git blob mode must be {expected_mode}")
        size_text = self.text(repo, "cat-file", "-s", match.group(2))
        require(size_text.isdigit() and int(size_text) <= max_bytes, f"{label}: Git blob exceeds {max_bytes} bytes")
        raw = self.run(repo, "cat-file", "blob", match.group(2)).stdout
        require(len(raw) == int(size_text), f"{label}: Git blob length changed while reading")
        return raw


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateVerificationError(message)


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(actual == expected, f"{label}: object-key mismatch;missing={sorted(expected - actual)!r};extra={sorted(actual - expected)!r}")


def obj(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label}: expected object")
    return value


def arr(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label}: expected array")
    return value


def nonempty(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.strip() == value and value != "", f"{label}: expected nonempty trimmed string")
    return value


def strict_bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label}: expected boolean")
    return value


def bounded_integer(value: Any, label: str, minimum: int = 0, maximum: int = MAX_SEMANTIC_INTEGER) -> int:
    require(type(minimum) is int and type(maximum) is int and 0 <= minimum <= maximum <= MAX_SEMANTIC_INTEGER, f"{label}: invalid verifier integer bounds")
    require(type(value) is int and minimum <= value <= maximum, f"{label}: expected integer in [{minimum},{maximum}]")
    return value


def checked_add(values: Sequence[int], label: str, maximum: int = MAX_SEMANTIC_INTEGER) -> int:
    bounded_integer(maximum, f"{label} maximum")
    total = 0
    require(len(values) > 0, f"{label}: expected at least one addend")
    for index, value in enumerate(values):
        addend = bounded_integer(value, f"{label}[{index}]")
        require(addend <= maximum - total, f"{label}: integer addition exceeds {maximum}")
        total += addend
    return total


def checked_multiply(values: Sequence[int], label: str, maximum: int = MAX_SEMANTIC_INTEGER) -> int:
    bounded_integer(maximum, f"{label} maximum")
    product = 1
    require(len(values) > 0, f"{label}: expected at least one factor")
    for index, value in enumerate(values):
        factor = bounded_integer(value, f"{label}[{index}]")
        require(product == 0 or factor <= maximum // product, f"{label}: integer multiplication exceeds {maximum}")
        product *= factor
    return product


def semantic_identifier(value: Any, label: str) -> str:
    text = nonempty(value, label)
    require(IDENTIFIER_RE.fullmatch(text) is not None, f"{label}: invalid identifier")
    return text


def procedural_principal(value: Any, label: str) -> str:
    text = nonempty(value, label)
    require(PROCEDURAL_PRINCIPAL_RE.fullmatch(text) is not None, f"{label}: expected canonical lower-case ASCII procedural principal label")
    return text


def hex_digest(value: Any, label: str, algorithm: str = "sha256") -> str:
    text = nonempty(value, label)
    pattern = HEX40_RE if algorithm == "sha1" else HEX64_RE if algorithm == "sha256" else None
    require(pattern is not None, f"{label}: unsupported digest algorithm {algorithm!r}")
    require(pattern.fullmatch(text) is not None, f"{label}: invalid {algorithm.upper()} digest")
    return text


def utc_text(value: Any, label: str) -> str:
    text = nonempty(value, label)
    parse_utc(text, label)
    return text


def semver(value: Any, label: str) -> str:
    text = nonempty(value, label)
    require(SEMVER_RE.fullmatch(text) is not None, f"{label}: expected canonical semantic version")
    return text


def ssh_sha256_fingerprint(value: Any, label: str) -> str:
    text = nonempty(value, label)
    require(SSH_SHA256_FINGERPRINT_RE.fullmatch(text) is not None, f"{label}: invalid SSH SHA-256 fingerprint")
    try:
        decoded = base64.b64decode(text.removeprefix("SHA256:") + "=", validate=True)
    except (binascii.Error, ValueError) as error:
        raise GateVerificationError(f"{label}: invalid SSH SHA-256 fingerprint: {error}") from error
    require(len(decoded) == 32 and base64.b64encode(decoded).decode("ascii").rstrip("=") == text.removeprefix("SHA256:"), f"{label}: noncanonical SSH SHA-256 fingerprint")
    return text


def absolute_path(value: Any, label: str) -> str:
    path = nonempty(value, label)
    require(path.startswith("/") and path != "/" and not path.endswith("/"), f"{label}: expected non-root canonical absolute path")
    require("\\" not in path and "\x00" not in path and "//" not in path, f"{label}: unsafe absolute path")
    parts = path.split("/")[1:]
    require(all(part not in {"", ".", ".."} for part in parts), f"{label}: noncanonical absolute path")
    for part in parts:
        require(len(part.encode("utf-8")) <= MAX_PATH_COMPONENT_BYTES and PATH_COMPONENT_RE.fullmatch(part) is not None, f"{label}: unsupported absolute-path component {part!r}")
    require(len(path.encode("utf-8")) <= MAX_PATH_BYTES, f"{label}: path exceeds {MAX_PATH_BYTES} UTF-8 bytes")
    return path


def dns_name(value: Any, label: str) -> str:
    name = nonempty(value, label)
    require(len(name) <= 253 and name == name.lower() and not name.endswith("."), f"{label}: expected canonical lower-case DNS name")
    labels = name.split(".")
    require(len(labels) >= 2 and all(DNS_LABEL_RE.fullmatch(part) is not None for part in labels), f"{label}: invalid DNS name")
    return name


def ip_address(value: Any, label: str) -> str:
    text = nonempty(value, label)
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as error:
        raise GateVerificationError(f"{label}: invalid IP address") from error
    require(str(parsed) == text, f"{label}: noncanonical IP address")
    return text


def ip_network(value: Any, label: str) -> str:
    text = nonempty(value, label)
    try:
        parsed = ipaddress.ip_network(text, strict=True)
    except ValueError as error:
        raise GateVerificationError(f"{label}: invalid canonical IP network") from error
    require(str(parsed) == text, f"{label}: noncanonical IP network")
    return text


def tcp_port(value: Any, label: str) -> int:
    return bounded_integer(value, label, 1, 65535)


def unix_mode(value: Any, label: str) -> str:
    text = nonempty(value, label)
    require(UNIX_MODE_RE.fullmatch(text) is not None, f"{label}: expected four-digit octal Unix mode")
    return text


def unique_strings(value: Any, label: str, *, minimum: int = 1, canonical_order: bool = False) -> list[str]:
    rows = arr(value, label)
    require(len(rows) >= minimum, f"{label}: expected at least {minimum} entries")
    strings = [nonempty(row, f"{label}[{index}]") for index, row in enumerate(rows)]
    require(len(strings) == len(set(strings)), f"{label}: duplicate string")
    if canonical_order:
        require(strings == sorted(strings), f"{label}: strings are not in canonical order")
    return strings


def nonnegative_integer(value: Any, label: str) -> int:
    require(type(value) is int and value >= 0, f"{label}: expected nonnegative integer")
    return value


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise GateVerificationError(f"non-finite JSON constant is forbidden: {value}")


def reject_json_float(value: str) -> None:
    raise GateVerificationError(f"JSON floating-point numbers are forbidden: {value}")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def parse_json(raw: bytes, label: str, canonical: bool = True) -> Any:
    require(len(raw) <= MAX_JSON_BYTES, f"{label}: JSON exceeds {MAX_JSON_BYTES} bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=no_duplicate_object, parse_constant=reject_json_constant, parse_float=reject_json_float)
    except (UnicodeDecodeError, json.JSONDecodeError, GateVerificationError) as error:
        raise GateVerificationError(f"invalid strict JSON in {label}: {error}") from error
    if canonical:
        try:
            normalized = canonical_json(value)
        except (UnicodeEncodeError, ValueError) as error:
            raise GateVerificationError(f"invalid Unicode scalar value in {label}: {error}") from error
        require(raw == normalized, f"{label}: JSON is not canonical")
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_regular(path: Path, label: str, max_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateVerificationError(f"{label}: cannot stat {path}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), f"{label}: expected regular non-symlink file: {path}")
    require(metadata.st_size <= max_bytes, f"{label}: file exceeds {max_bytes} bytes")
    raw = path.read_bytes()
    require(len(raw) == metadata.st_size, f"{label}: file length changed while reading")
    return raw


def load_external_gate_file(ops: GitOps, repo_root: Path, path: Path, label: str, max_bytes: int) -> bytes:
    repo = repo_root.resolve()
    direct_git = repo / ".git"
    gate_dir = direct_git / "pkgre-gates"
    try:
        git_metadata = direct_git.lstat()
        gate_metadata = gate_dir.lstat()
    except OSError as error:
        raise GateVerificationError(f"{label}: external gate directory is unavailable: {error}") from error
    require(stat.S_ISDIR(git_metadata.st_mode) and not stat.S_ISLNK(git_metadata.st_mode), f"{label}: .git must be a direct non-symlink directory")
    require(stat.S_ISDIR(gate_metadata.st_mode) and not stat.S_ISLNK(gate_metadata.st_mode), f"{label}: external gate directory must be a direct non-symlink directory")
    current_uid = os.geteuid()
    for metadata, metadata_label in ((git_metadata, ".git directory"), (gate_metadata, "external gate directory")):
        require(metadata.st_uid == current_uid, f"{label}: {metadata_label} must be owned by the verifier user")
        require(metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0, f"{label}: {metadata_label} must not be group- or world-writable")
    require(stat.S_IMODE(gate_metadata.st_mode) == 0o700, f"{label}: external gate directory mode must be 0700")
    git_dir = Path(ops.text(repo, "rev-parse", "--absolute-git-dir"))
    require(git_dir.resolve() == direct_git.resolve(), f"{label}: linked or indirect Git directory is forbidden")
    candidate = path if path.is_absolute() else Path.cwd() / path
    candidate = Path(os.path.abspath(candidate))
    require(candidate.parent == gate_dir, f"{label}: file must be directly under the external .git/pkgre-gates directory")
    name = safe_path(candidate.name, f"{label} file name")
    require("/" not in name, f"{label}: file name must be a single path component")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    git_fd = -1
    gate_fd = -1
    file_fd = -1
    try:
        git_fd = os.open(direct_git, directory_flags)
        opened_git = os.fstat(git_fd)
        require((opened_git.st_dev, opened_git.st_ino) == (git_metadata.st_dev, git_metadata.st_ino), f"{label}: .git directory changed before opening")
        gate_fd = os.open("pkgre-gates", directory_flags, dir_fd=git_fd)
        opened_gate = os.fstat(gate_fd)
        require((opened_gate.st_dev, opened_gate.st_ino) == (gate_metadata.st_dev, gate_metadata.st_ino), f"{label}: external gate directory changed before opening")
        file_fd = os.open(name, file_flags, dir_fd=gate_fd)
        before = os.fstat(file_fd)
        require(stat.S_ISREG(before.st_mode), f"{label}: expected regular non-symlink file")
        require(before.st_uid == current_uid, f"{label}: file must be owned by the verifier user")
        require(stat.S_IMODE(before.st_mode) == 0o600, f"{label}: external gate file mode must be 0600")
        require(before.st_nlink == 1, f"{label}: hard-linked external gate file is forbidden")
        require(before.st_size <= max_bytes, f"{label}: file exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(remaining, 64 * 1024))
            require(chunk != b"", f"{label}: file length changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(os.read(file_fd, 1) == b"", f"{label}: file grew while reading")
        after = os.fstat(file_fd)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, field) == getattr(after, field) for field in stable_fields), f"{label}: file metadata changed while reading")
        named_after = os.stat(name, dir_fd=gate_fd, follow_symlinks=False)
        require((named_after.st_dev, named_after.st_ino) == (after.st_dev, after.st_ino), f"{label}: external gate file name changed while reading")
        gate_after = os.stat("pkgre-gates", dir_fd=git_fd, follow_symlinks=False)
        git_after = direct_git.lstat()
        require((gate_after.st_dev, gate_after.st_ino) == (opened_gate.st_dev, opened_gate.st_ino), f"{label}: external gate directory name changed while reading")
        require((git_after.st_dev, git_after.st_ino) == (opened_git.st_dev, opened_git.st_ino), f"{label}: .git directory name changed while reading")
        raw = b"".join(chunks)
        require(len(raw) == before.st_size, f"{label}: file length changed while reading")
        return raw
    except OSError as error:
        raise GateVerificationError(f"{label}: cannot safely open external gate file: {error}") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if gate_fd >= 0:
            os.close(gate_fd)
        if git_fd >= 0:
            os.close(git_fd)


def create_external_gate_file(ops: GitOps, repo_root: Path, name: str, raw: bytes, label: str, max_bytes: int) -> Path:
    """Create one private external gate file without following links or replacing a name."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= max_bytes, f"{label}: content must be 1..{max_bytes} bytes")
    canonical_name = safe_path(name, f"{label} file name")
    require("/" not in canonical_name, f"{label}: file name must be a single path component")
    repo = repo_root.resolve()
    direct_git = repo / ".git"
    try:
        git_metadata = direct_git.lstat()
    except OSError as error:
        raise GateVerificationError(f"{label}: direct .git directory is unavailable: {error}") from error
    current_uid = os.geteuid()
    require(stat.S_ISDIR(git_metadata.st_mode) and not stat.S_ISLNK(git_metadata.st_mode), f"{label}: .git must be a direct non-symlink directory")
    require(git_metadata.st_uid == current_uid, f"{label}: .git directory must be owned by the current user")
    require(git_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0, f"{label}: .git directory must not be group- or world-writable")
    git_dir = Path(ops.text(repo, "rev-parse", "--absolute-git-dir"))
    require(git_dir.resolve() == direct_git.resolve(), f"{label}: linked or indirect Git directory is forbidden")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    git_fd = -1
    gate_fd = -1
    file_fd = -1
    temporary_name = f".pkgre-tmp-{os.getpid()}-{secrets.token_hex(16)}"
    temporary_exists = False
    published = False
    private_identity: tuple[int, int] | None = None
    succeeded = False
    try:
        git_fd = os.open(direct_git, directory_flags)
        opened_git = os.fstat(git_fd)
        require((opened_git.st_dev, opened_git.st_ino) == (git_metadata.st_dev, git_metadata.st_ino), f"{label}: .git directory changed before opening")
        try:
            os.mkdir("pkgre-gates", mode=0o700, dir_fd=git_fd)
            gate_created = True
        except FileExistsError:
            gate_created = False
        gate_fd = os.open("pkgre-gates", directory_flags, dir_fd=git_fd)
        gate_metadata = os.fstat(gate_fd)
        if gate_created:
            os.fchmod(gate_fd, 0o700)
            gate_metadata = os.fstat(gate_fd)
        require(stat.S_ISDIR(gate_metadata.st_mode), f"{label}: external gate directory must be a direct non-symlink directory")
        require(gate_metadata.st_uid == current_uid, f"{label}: external gate directory must be owned by the current user")
        require(stat.S_IMODE(gate_metadata.st_mode) == 0o700, f"{label}: external gate directory mode must be 0700")
        try:
            os.stat(canonical_name, dir_fd=gate_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise GateVerificationError(f"{label}: refusing to overwrite existing external gate file {canonical_name!r}")
        file_fd = os.open(temporary_name, file_flags, 0o600, dir_fd=gate_fd)
        temporary_exists = True
        os.fchmod(file_fd, 0o600)
        created_metadata = os.fstat(file_fd)
        private_identity = (created_metadata.st_dev, created_metadata.st_ino)
        offset = 0
        while offset < len(raw):
            written = os.write(file_fd, raw[offset:])
            require(written > 0, f"{label}: zero-length write to private temporary file")
            offset += written
        os.fsync(file_fd)
        temporary_metadata = os.fstat(file_fd)
        require((temporary_metadata.st_dev, temporary_metadata.st_ino) == private_identity, f"{label}: private temporary identity changed while writing")
        require(stat.S_ISREG(temporary_metadata.st_mode), f"{label}: private temporary is not a regular file")
        require(temporary_metadata.st_uid == current_uid and stat.S_IMODE(temporary_metadata.st_mode) == 0o600, f"{label}: private temporary ownership or mode mismatch")
        require(temporary_metadata.st_nlink == 1 and temporary_metadata.st_size == len(raw), f"{label}: private temporary link count or length mismatch")
        try:
            os.link(temporary_name, canonical_name, src_dir_fd=gate_fd, dst_dir_fd=gate_fd, follow_symlinks=False)
        except FileExistsError as error:
            raise GateVerificationError(f"{label}: refusing to overwrite existing external gate file {canonical_name!r}") from error
        published = True
        os.unlink(temporary_name, dir_fd=gate_fd)
        temporary_exists = False
        opened_final = os.fstat(file_fd)
        named_final = os.stat(canonical_name, dir_fd=gate_fd, follow_symlinks=False)
        require((opened_final.st_dev, opened_final.st_ino) == private_identity == (named_final.st_dev, named_final.st_ino), f"{label}: published external gate file identity mismatch")
        require(opened_final.st_nlink == named_final.st_nlink == 1 and opened_final.st_size == named_final.st_size == len(raw), f"{label}: published external gate file link count or length mismatch")
        require(stat.S_IMODE(opened_final.st_mode) == stat.S_IMODE(named_final.st_mode) == 0o600 and opened_final.st_uid == named_final.st_uid == current_uid, f"{label}: published external gate file ownership or mode mismatch")
        os.fsync(gate_fd)
        named_gate = os.stat("pkgre-gates", dir_fd=git_fd, follow_symlinks=False)
        named_git = direct_git.lstat()
        require((named_gate.st_dev, named_gate.st_ino) == (gate_metadata.st_dev, gate_metadata.st_ino), f"{label}: external gate directory name changed while writing")
        require((named_git.st_dev, named_git.st_ino) == (opened_git.st_dev, opened_git.st_ino), f"{label}: .git directory name changed while writing")
        os.fsync(git_fd)
        succeeded = True
        return direct_git / "pkgre-gates" / canonical_name
    except BaseException as error:
        cleanup_errors: list[str] = []
        cleanup_changed = False
        if gate_fd >= 0 and private_identity is not None:
            for present, candidate_name in ((published, canonical_name), (temporary_exists, temporary_name)):
                if not present:
                    continue
                try:
                    candidate_metadata = os.stat(candidate_name, dir_fd=gate_fd, follow_symlinks=False)
                    if (candidate_metadata.st_dev, candidate_metadata.st_ino) != private_identity:
                        cleanup_errors.append(f"{candidate_name!r} no longer names the private temporary inode")
                        continue
                    os.unlink(candidate_name, dir_fd=gate_fd)
                    cleanup_changed = True
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    cleanup_errors.append(f"cannot remove {candidate_name!r}: {cleanup_error}")
            if cleanup_changed:
                try:
                    os.fsync(gate_fd)
                except OSError as cleanup_error:
                    cleanup_errors.append(f"cannot sync cleanup: {cleanup_error}")
        if cleanup_errors:
            raise GateVerificationError(f"{label}: private external gate cleanup failed after {error}: {'; '.join(cleanup_errors)}") from error
        if isinstance(error, GateVerificationError):
            raise
        if isinstance(error, OSError):
            raise GateVerificationError(f"{label}: cannot safely create external gate file: {error}") from error
        raise
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if not succeeded and gate_fd >= 0 and (temporary_exists or published) and private_identity is None:
            # Creation failed before a stable inode identity was available; the O_EXCL name is private but cannot be safely identified for unlink.
            pass
        if gate_fd >= 0:
            os.close(gate_fd)
        if git_fd >= 0:
            os.close(git_fd)


def safe_path(value: Any, label: str, prefix: str | None = None) -> str:
    path = nonempty(value, label)
    require("\\" not in path and "\x00" not in path and not path.startswith("/") and not path.endswith("/"), f"{label}: unsafe path {path!r}")
    encoded = path.encode("utf-8", errors="strict")
    require(len(encoded) <= MAX_PATH_BYTES, f"{label}: path exceeds {MAX_PATH_BYTES} UTF-8 bytes")
    parts = path.split("/")
    require(all(part not in {"", ".", ".."} for part in parts), f"{label}: noncanonical path {path!r}")
    for part in parts:
        require(len(part.encode("utf-8")) <= MAX_PATH_COMPONENT_BYTES, f"{label}: component exceeds {MAX_PATH_COMPONENT_BYTES} UTF-8 bytes")
        require(PATH_COMPONENT_RE.fullmatch(part) is not None, f"{label}: unsupported path component {part!r}")
    if prefix is not None:
        require(prefix.endswith("/") and path.startswith(prefix) and path != prefix.removesuffix("/"), f"{label}: path must be strictly under {prefix!r}")
    return path


def parse_utc(value: Any, label: str) -> datetime:
    text = nonempty(value, label)
    require(UTC_RE.fullmatch(text) is not None, f"{label}: expected second-precision UTC timestamp")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise GateVerificationError(f"{label}: invalid UTC calendar timestamp") from error


def normalize_verification_time(value: datetime | None) -> datetime:
    current_time = datetime.now(timezone.utc) if value is None else value
    require(isinstance(current_time, datetime) and current_time.tzinfo is not None and current_time.utcoffset() == timedelta(0), "verification time must be a timezone-aware UTC datetime")
    return current_time.astimezone(timezone.utc)


def indexed(rows: list[Any], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        row = obj(raw, f"{label}[{index}]")
        row_id = nonempty(row.get(key), f"{label}[{index}].{key}")
        require(row_id not in result, f"{label}: duplicate {key} {row_id!r}")
        result[row_id] = row
    return result


def is_d0_path(path: str) -> bool:
    return path in D0_ALLOWED_PATHS or any(path.startswith(prefix) for prefix in D0_ALLOWED_PREFIXES)


def parse_nul_paths(raw: bytes, label: str) -> list[str]:
    require(raw == b"" or raw.endswith(b"\0"), f"{label}: expected NUL-delimited Git output")
    result: list[str] = []
    for value in raw.split(b"\0"):
        if not value:
            continue
        try:
            result.append(value.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}: non-UTF-8 path") from error
    return result


def parse_tree_rows(raw: bytes, label: str) -> list[dict[str, str]]:
    require(raw == b"" or raw.endswith(b"\0"), f"{label}: expected NUL-delimited ls-tree output")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, encoded_row in enumerate(raw.split(b"\0")):
        if encoded_row == b"":
            continue
        try:
            row = encoded_row.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}[{index}]: non-UTF-8 tree entry") from error
        match = re.fullmatch(r"([0-9]{6}) ([a-z]+) ([0-9a-f]{40})\t(.+)", row)
        require(match is not None, f"{label}[{index}]: malformed tree entry")
        mode, object_type, object_id, path = match.groups()
        if not is_d0_path(path):
            continue
        canonical = safe_path(path, f"{label}[{index}] path")
        require(canonical not in seen, f"{label}: duplicate canonical path {canonical!r}")
        seen.add(canonical)
        require(mode in {"100644", "100755"} and object_type == "blob", f"{label}: closure-relevant path is not a regular blob: {canonical!r}")
        rows.append({"mode": mode, "objectId": object_id, "path": canonical})
    require([row["path"].encode("utf-8") for row in rows] == sorted(row["path"].encode("utf-8") for row in rows), f"{label}: Git tree paths are not in canonical byte order")
    return rows


def committed_evidence_tree(ops: GitOps, repo: Path, commit: str) -> tuple[str, list[dict[str, Any]]]:
    require(HEX40_RE.fullmatch(commit) is not None, "evidence tree: invalid commit")
    raw = ops.run(repo, "ls-tree", "--full-tree", "-r", "-z", commit).stdout
    entries: list[dict[str, Any]] = []
    for row in parse_tree_rows(raw, f"evidence tree {commit}"):
        if row["path"] == GATE_STATE_PATH:
            continue
        size_text = ops.text(repo, "cat-file", "-s", row["objectId"])
        require(size_text.isdigit(), f"evidence tree: invalid blob length for {row['path']!r}")
        size = int(size_text)
        require(size <= MAX_ARTIFACT_BYTES, f"evidence tree: blob exceeds {MAX_ARTIFACT_BYTES} bytes: {row['path']!r}")
        raw_blob = ops.run(repo, "cat-file", "blob", row["objectId"]).stdout
        require(len(raw_blob) == size, f"evidence tree: blob length changed while reading {row['path']!r}")
        entries.append({"byteLength": size, "mode": row["mode"], "path": row["path"], "sha256": sha256(raw_blob)})
    require(entries, "evidence tree: no closure-relevant blobs")
    identity = sha256(EVIDENCE_TREE_DOMAIN + canonical_json(entries))
    return identity, entries


def parse_name_status(raw: bytes, label: str) -> list[tuple[str, str]]:
    require(raw == b"" or raw.endswith(b"\0"), f"{label}: expected NUL-delimited name-status output")
    fields = raw.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    require(len(fields) % 2 == 0, f"{label}: malformed name-status field count")
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii", errors="strict")
            path = fields[index + 1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}: non-UTF-8 name-status record") from error
        require(status in {"A", "D", "M"}, f"{label}: unsupported or rename/copy/unmerged status {status!r}")
        canonical = safe_path(path, f"{label} path")
        require(canonical not in seen, f"{label}: duplicate path {canonical!r}")
        seen.add(canonical)
        rows.append((status, canonical))
    return rows


def is_gate_state_alias(path: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", path.casefold())
    return "d0gatestate" in normalized


def validate_gate_state_history(ops: GitOps, repo: Path, base: str, head: str, state_raw: bytes, closure_evidence_commit: str | None, config: GateConfig) -> dict[str, Any]:
    for label, commit in (("historical", base), ("HEAD", head)):
        require(HEX40_RE.fullmatch(commit) is not None, f"gate-state history: invalid {label} commit")
    if closure_evidence_commit is not None:
        require(HEX40_RE.fullmatch(closure_evidence_commit) is not None, "gate-state history: invalid closure evidence commit")
    require(base != head, "gate-state history: tracked state must be introduced after the historical commit")
    require(ops.run(repo, "merge-base", "--is-ancestor", base, head, check=False).returncode == 0, "gate-state history: historical commit is not an ancestor of HEAD")
    base_paths = [safe_path(path, f"gate-state historical tree[{index}]") for index, path in enumerate(parse_nul_paths(ops.run(repo, "ls-tree", "--full-tree", "-r", "--name-only", "-z", base).stdout, "gate-state historical tree"))]
    base_aliases = sorted(path for path in base_paths if is_gate_state_alias(path))
    require(not base_aliases, f"gate-state history: historical tree contains gate-state path or alias: {base_aliases!r}")
    commit_ids = parse_nul_paths(ops.run(repo, "rev-list", "--reverse", "--ancestry-path", "-z", f"{base}..{head}").stdout, "gate-state history commits")
    require(commit_ids and commit_ids[-1] == head, "gate-state history: HEAD is not the validated tip")
    initial_raw = canonical_json(initial_gate_state(config))
    previous = base
    state_introduction_commit: str | None = None
    closure_state_commit: str | None = None
    evidence_changed_paths: list[str] = []
    commits: list[dict[str, Any]] = []
    for commit in commit_ids:
        require(HEX40_RE.fullmatch(commit) is not None, "gate-state history: invalid rev-list commit")
        parent_row = ops.text(repo, "rev-list", "--parents", "-n", "1", commit).split()
        require(parent_row == [commit, previous], f"gate-state history: merge, discontinuity, or unexpected parent at {commit}")
        raw_changes = ops.run(repo, "diff-tree", "--no-commit-id", "--name-status", "-r", "-z", "--no-renames", "--no-ext-diff", previous, commit).stdout
        changes = parse_name_status(raw_changes, f"gate-state history {commit}")
        require(changes, f"gate-state history: empty commit {commit} is forbidden")
        paths = [path for _status, path in changes]
        aliases = sorted(path for path in paths if is_gate_state_alias(path) and path != GATE_STATE_PATH)
        require(not aliases, f"gate-state history: alternate gate-state path is forbidden at {commit}: {aliases!r}")
        require(AGGREGATE_PATH not in paths, f"gate-state history: immutable historical aggregate changed at {commit}")
        state_changes = [(status, path) for status, path in changes if path == GATE_STATE_PATH]
        if state_changes:
            require(paths == [GATE_STATE_PATH] and len(state_changes) == 1, f"gate-state history: state commit must change only the canonical gate-state path at {commit}")
            status = state_changes[0][0]
            if state_introduction_commit is None:
                require(status == "A", f"gate-state history: initial gate state must be introduced exactly once at {commit}")
                committed_initial = ops.blob(repo, commit, GATE_STATE_PATH, "initial tracked gate state", MAX_JSON_BYTES, expected_mode="100644")
                require(committed_initial == initial_raw, "gate-state history: initial tracked gate state differs from the exact canonical blocked state")
                state_introduction_commit = commit
            else:
                require(closure_evidence_commit is not None and closure_state_commit is None and commit == head and status == "M", f"gate-state history: gate state changed outside the sole final closure-state commit {commit}")
                require(previous == closure_evidence_commit, "gate-state history: closure evidence commit must immediately precede the final state commit")
                closure_state_commit = commit
        else:
            forbidden = sorted(path for path in paths if not is_d0_path(path))
            require(not forbidden, f"gate-state history: forbidden non-D0 paths at {commit}: {forbidden!r}")
            evidence_changed_paths.extend(paths)
        commits.append({"commit": commit, "parent": previous, "changes": [{"status": status, "path": path} for status, path in changes]})
        previous = commit
    require(state_introduction_commit is not None, "gate-state history: canonical initial blocked state was never introduced")
    committed_head_state = ops.blob(repo, head, GATE_STATE_PATH, "current tracked gate state", MAX_JSON_BYTES, expected_mode="100644")
    require(committed_head_state == state_raw, "working gate state is not the exact HEAD gate-state blob")
    if closure_evidence_commit is None:
        require(closure_state_commit is None and state_raw == initial_raw, "gate-state history: blocked HEAD must retain the exact canonical initial state")
    else:
        require(closure_state_commit == head, "gate-state history: closure state must be the sole final HEAD state change")
        require(state_introduction_commit != head and closure_evidence_commit not in {base, state_introduction_commit, head}, "gate-state history: closure commits must be distinct from the base, introduction, and HEAD")
    return {
        "closureStateCommit": closure_state_commit,
        "commits": commits,
        "evidenceChangedPaths": sorted(set(evidence_changed_paths)),
        "stateIntroductionCommit": state_introduction_commit,
    }


def parse_aggregate(aggregate: bytes) -> tuple[set[str], dict[str, str]]:
    try:
        text = aggregate.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise GateVerificationError(f"historical aggregate is not UTF-8: {error}") from error
    require(text.startswith("# D0 basis+inventory aggregate — 2026-08-26\n\nStatus:gate=BLOCKED | D1 authorized=false"), "historical aggregate lost its blocked gate header")
    require("STOP:no dependent phase" in text and "D1 authorized=false" in text, "historical aggregate lost its stop boundary")
    finding_ids = set(re.findall(r"(?m)^\| (D0-B[0-9]{2}) \|", text))
    titles = {f"OP-D0-{int(number):02d}": title for number, title in re.findall(r"(?m)^(\d+)\. \*\*(.+?):\*\*", text)}
    return finding_ids, titles


def initial_gate_state(config: GateConfig = PRODUCTION_CONFIG) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for finding_id, fact_state in EXPECTED_FACT_STATES.items():
        if finding_id in LATER_FINDINGS:
            disposition = "PENDING"
            gate_class = "LATER_PHASE_GATE"
        elif finding_id in DEFERRED_FINDINGS:
            disposition = "DEFERRED"
            gate_class = "DEFERRED_ABSENT"
        else:
            disposition = "OPEN"
            gate_class = "IMMEDIATE_D1_BLOCKER"
        findings.append({
            "id": finding_id,
            "gateClass": gate_class,
            "factState": fact_state,
            "historicalFact": finding_id == "D0-B18",
            "handoffRefs": FINDING_HANDOFFS[finding_id],
            "closure": {"policyId": f"{finding_id}-v1", "disposition": disposition, "result": None},
        })
    items = []
    for handoff_id, (number, title, finding_refs) in HANDOFFS.items():
        items.append({"id": handoff_id, "aggregateItem": number, "title": title, "findingRefs": finding_refs, "evidence": None})
    return {
        "schema": SCHEMA,
        "aggregate": {"path": AGGREGATE_PATH, "historicalCommit": config.historical_aggregate_commit, "sha256": config.historical_aggregate_sha256, "requiredGate": "BLOCKED", "requiredD1Authorized": False},
        "basis": {"packetRoot": "fixtures/d0-v1/basis-inventory", "evidenceRefetch": {"completedAt": "2026-08-26T12:50:11Z", "purpose": "D0-evidence", "immediatelyBeforeD1FirstEdit": False}, "reviewedRepositories": [row.state_row() for row in config.repositories]},
        "closureSet": None,
        "findings": findings,
        "handoff": {"id": "OPERATOR-HANDOFF-D0", "phase": "D0", "items": items},
        "laterGates": copy.deepcopy(LATER_GATES),
        "preD1Refetch": {"evidence": None},
        "mutationPolicy": copy.deepcopy(MUTATION_POLICY),
    }


def validate_state_shape(state: dict[str, Any], aggregate: bytes, config: GateConfig) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    exact_keys(state, {"schema", "aggregate", "basis", "closureSet", "findings", "handoff", "laterGates", "preD1Refetch", "mutationPolicy"}, "gate state")
    require(state["schema"] == SCHEMA, "gate state: wrong schema")
    aggregate_binding = obj(state["aggregate"], "gate state aggregate")
    exact_keys(aggregate_binding, {"path", "historicalCommit", "sha256", "requiredGate", "requiredD1Authorized"}, "gate state aggregate")
    expected_aggregate = {"path": AGGREGATE_PATH, "historicalCommit": config.historical_aggregate_commit, "sha256": config.historical_aggregate_sha256, "requiredGate": "BLOCKED", "requiredD1Authorized": False}
    require(aggregate_binding == expected_aggregate, "gate state aggregate binding differs from verifier-pinned history")
    basis = obj(state["basis"], "gate state basis")
    exact_keys(basis, {"packetRoot", "evidenceRefetch", "reviewedRepositories"}, "gate state basis")
    require(basis["packetRoot"] == "fixtures/d0-v1/basis-inventory", "gate state: wrong packet root")
    require(basis["evidenceRefetch"] == {"completedAt": "2026-08-26T12:50:11Z", "purpose": "D0-evidence", "immediatelyBeforeD1FirstEdit": False}, "gate state: changed historical D0 refetch")
    require(basis["reviewedRepositories"] == [row.state_row() for row in config.repositories], "gate state: reviewed repository basis mismatch")
    require(state["laterGates"] == LATER_GATES, "gate state: later-gate contract mismatch")
    require(state["preD1Refetch"] == {"evidence": None}, "gate state: tracked PRE_D1 evidence must remain null")
    require(state["mutationPolicy"] == MUTATION_POLICY, "gate state: mutation policy mismatch")
    aggregate_findings, aggregate_titles = parse_aggregate(aggregate)
    require(aggregate_findings == set(EXPECTED_FACT_STATES), "historical aggregate finding set mismatch")
    require(aggregate_titles == {handoff: value[1] for handoff, value in HANDOFFS.items()}, "historical aggregate handoff titles mismatch")
    finding_rows = arr(state["findings"], "gate state findings")
    require([obj(row, "finding row").get("id") for row in finding_rows] == list(EXPECTED_FACT_STATES), "gate state findings must use canonical order")
    findings = indexed(finding_rows, "id", "gate state findings")
    for finding_id, finding in findings.items():
        exact_keys(finding, {"id", "gateClass", "factState", "historicalFact", "handoffRefs", "closure"}, f"finding {finding_id}")
        expected_class = "IMMEDIATE_D1_BLOCKER" if finding_id in IMMEDIATE_FINDINGS else ("LATER_PHASE_GATE" if finding_id in LATER_FINDINGS else "DEFERRED_ABSENT")
        require(finding["gateClass"] == expected_class, f"{finding_id}: wrong gate class")
        require(finding["factState"] == EXPECTED_FACT_STATES[finding_id], f"{finding_id}: changed historical fact state")
        require(finding["historicalFact"] is (finding_id == "D0-B18"), f"{finding_id}: wrong historical-fact flag")
        require(finding["handoffRefs"] == FINDING_HANDOFFS[finding_id], f"{finding_id}: handoff mapping mismatch")
        closure = obj(finding["closure"], f"{finding_id} closure")
        exact_keys(closure, {"policyId", "disposition", "result"}, f"{finding_id} closure")
        require(closure["policyId"] == f"{finding_id}-v1", f"{finding_id}: policy ID mismatch")
    handoff = obj(state["handoff"], "gate state handoff")
    exact_keys(handoff, {"id", "phase", "items"}, "gate state handoff")
    require(handoff["id"] == "OPERATOR-HANDOFF-D0" and handoff["phase"] == "D0", "gate state: wrong handoff identity")
    item_rows = arr(handoff["items"], "handoff items")
    require([obj(row, "handoff row").get("id") for row in item_rows] == list(HANDOFFS), "handoff items must use canonical order")
    items = indexed(item_rows, "id", "handoff items")
    for handoff_id, item in items.items():
        exact_keys(item, {"id", "aggregateItem", "title", "findingRefs", "evidence"}, f"handoff {handoff_id}")
        number, title, finding_refs = HANDOFFS[handoff_id]
        require(item["aggregateItem"] == number and item["title"] == title and item["findingRefs"] == finding_refs, f"{handoff_id}: immutable mapping mismatch")
        if item["evidence"] is not None:
            validate_attestation_reference_shape(obj(item["evidence"], f"{handoff_id} evidence"), f"{handoff_id} evidence")
    return findings, items


def validate_content_reference(raw: Any, label: str, prefix: str | None = None) -> dict[str, str]:
    reference = obj(raw, label)
    exact_keys(reference, {"path", "sha256"}, label)
    path = safe_path(reference["path"], f"{label}.path", prefix)
    digest = nonempty(reference["sha256"], f"{label}.sha256")
    require(HEX64_RE.fullmatch(digest) is not None, f"{label}: invalid SHA-256")
    return {"path": path, "sha256": digest}


def validate_attestation_reference_shape(raw: dict[str, Any], label: str) -> None:
    exact_keys(raw, {"operatorReturn", "agentVerification", "proceduralReview"}, label)
    for key in ("operatorReturn", "agentVerification", "proceduralReview"):
        validate_content_reference(raw[key], f"{label}.{key}")


def validate_procedural_authority_raw(raw: bytes, *, state_raw: bytes, closure_state_commit: str, label: str) -> dict[str, Any]:
    """Validate authority content against prevalidated canonical state bytes.

    This validates only the authority-relevant closure/handoff projection and byte binding;
    callers must establish the complete gate-state semantics separately. No filesystem assurance.
    """
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PROCEDURAL_AUTHORITY_BYTES, f"{label}: content must be 1..{MAX_PROCEDURAL_AUTHORITY_BYTES} bytes")
    require(isinstance(state_raw, bytes) and 0 < len(state_raw) <= MAX_JSON_BYTES, f"{label}: gate-state content must be 1..{MAX_JSON_BYTES} bytes")
    state = obj(parse_json(state_raw, f"{label} gate-state binding"), f"{label} gate-state binding")
    exact_keys(state, {"schema", "aggregate", "basis", "closureSet", "findings", "handoff", "laterGates", "preD1Refetch", "mutationPolicy"}, f"{label} gate-state binding")
    require(state["schema"] == SCHEMA, f"{label} gate-state binding: wrong schema")
    closure = obj(state["closureSet"], f"{label} gate-state closure set")
    exact_keys(closure, {"id", "closureEvidenceCommit", "evidenceTreeSha256"}, "closure set")
    closure_id = nonempty(closure["id"], "procedural authority closure ID")
    evidence_commit = hex_digest(closure["closureEvidenceCommit"], "procedural authority closure evidence commit", "sha1")
    evidence_tree_sha256 = hex_digest(closure["evidenceTreeSha256"], "procedural authority evidence-tree digest")
    require(CLOSURE_SET_RE.fullmatch(closure_id) is not None, "procedural authority: invalid closure ID")
    handoff = obj(state["handoff"], f"{label} gate-state handoff")
    exact_keys(handoff, {"id", "phase", "items"}, f"{label} gate-state handoff")
    require(handoff["id"] == "OPERATOR-HANDOFF-D0" and handoff["phase"] == "D0", f"{label} gate-state handoff: wrong identity")
    item_rows = arr(handoff["items"], f"{label} gate-state handoff items")
    require([obj(row, f"{label} gate-state handoff items[{index}]").get("id") for index, row in enumerate(item_rows)] == list(HANDOFFS), f"{label} gate-state handoff items must use canonical order")
    items = indexed(item_rows, "id", f"{label} gate-state handoff items")
    for handoff_id, item in items.items():
        exact_keys(item, {"id", "aggregateItem", "title", "findingRefs", "evidence"}, f"{label} gate-state handoff {handoff_id}")
        number, title, finding_refs = HANDOFFS[handoff_id]
        require(item["aggregateItem"] == number and item["title"] == title and item["findingRefs"] == finding_refs, f"{label} gate-state handoff {handoff_id}: immutable mapping mismatch")
        if item["evidence"] is not None:
            validate_attestation_reference_shape(obj(item["evidence"], f"{label} gate-state handoff {handoff_id} evidence"), f"{label} gate-state handoff {handoff_id} evidence")
    closure_state_commit = hex_digest(closure_state_commit, "procedural authority closure-state commit", "sha1")
    expected_name = f"d0-procedural-authority-{closure_id}.json"
    document = obj(parse_json(raw, label), "procedural authority")
    exact_keys(document, {"schema", "closureSet", "assurance", "handoffs"}, "procedural authority")
    require(document["schema"] == PROCEDURAL_AUTHORITY_SCHEMA, "procedural authority: wrong schema")
    require(document["assurance"] == PROCEDURAL_AUTHORITY_ASSURANCE, "procedural authority: assurance limitations must exactly disclaim identity authentication and artifact authorship")
    expected_closure = {
        "id": closure_id,
        "closureEvidenceCommit": evidence_commit,
        "evidenceTreeSha256": evidence_tree_sha256,
        "closureStateCommit": closure_state_commit,
        "gateStateSha256": sha256(state_raw),
    }
    closure_binding = obj(document["closureSet"], "procedural authority closure binding")
    exact_keys(closure_binding, set(expected_closure), "procedural authority closure binding")
    require(closure_binding == expected_closure, "procedural authority: closure ID, commit, state, or tree binding mismatch")
    rows = arr(document["handoffs"], "procedural authority handoffs")
    expected_handoff_ids = [handoff_id for handoff_id in HANDOFFS if items[handoff_id]["evidence"] is not None]
    require([obj(row, f"procedural authority handoffs[{index}]").get("handoffId") for index, row in enumerate(rows)] == expected_handoff_ids, "procedural authority: handoff rows must exactly cover completed handoffs in canonical order")
    assignments_by_handoff: dict[str, dict[str, dict[str, str]]] = {}
    principal_roles: dict[str, str] = {}
    for index, row_raw in enumerate(rows):
        row = obj(row_raw, f"procedural authority handoffs[{index}]")
        exact_keys(row, {"handoffId", "assignments"}, f"procedural authority handoffs[{index}]")
        handoff_id = row["handoffId"]
        require(handoff_id in HANDOFFS and handoff_id not in assignments_by_handoff, f"procedural authority: unknown or duplicate handoff {handoff_id!r}")
        evidence_reference = obj(items[handoff_id]["evidence"], f"{handoff_id} evidence reference")
        assignments = obj(row["assignments"], f"procedural authority {handoff_id} assignments")
        exact_keys(assignments, set(PROCEDURAL_ROLES), f"procedural authority {handoff_id} assignments")
        verified_assignments: dict[str, dict[str, str]] = {}
        handoff_principals: set[str] = set()
        for artifact_kind in ("operatorReturn", "agentVerification", "proceduralReview"):
            assignment_label = f"procedural authority {handoff_id}.{artifact_kind}"
            assignment = obj(assignments[artifact_kind], assignment_label)
            exact_keys(assignment, {"artifact", "principalLabel", "role"}, assignment_label)
            require(assignment["role"] == PROCEDURAL_ROLES[artifact_kind], f"{assignment_label}: wrong procedural role")
            principal = procedural_principal(assignment["principalLabel"], f"{assignment_label}.principalLabel")
            require(principal not in handoff_principals, f"procedural authority {handoff_id}: procedural roles must have pairwise-distinct principal labels")
            handoff_principals.add(principal)
            previous_role = principal_roles.setdefault(principal, assignment["role"])
            require(previous_role == assignment["role"], f"procedural authority: principal label {principal!r} is assigned conflicting roles across handoffs")
            artifact = validate_content_reference(assignment["artifact"], f"{assignment_label}.artifact", f"evidence/d0-closure/{closure_id}/{handoff_id}/")
            expected_artifact = validate_content_reference(evidence_reference[artifact_kind], f"{handoff_id} evidence reference.{artifact_kind}")
            require(artifact == expected_artifact, f"{assignment_label}: artifact path or digest differs from closure state")
            verified_assignments[artifact_kind] = {"principalLabel": principal, "role": assignment["role"]}
        assignments_by_handoff[handoff_id] = verified_assignments
    return {"assignments": assignments_by_handoff, "contentBindingVerified": True, "expectedExternalFile": expected_name, "sha256": sha256(raw)}


def verify_procedural_authority(ops: GitOps, repo: Path, state_raw: bytes, closure: dict[str, Any], items: dict[str, dict[str, Any]], authority_path: Path) -> dict[str, Any]:
    closure_id = nonempty(closure.get("id"), "procedural authority closure ID")
    expected_name = f"d0-procedural-authority-{closure_id}.json"
    require(authority_path.name == expected_name, f"procedural authority: file name must be {expected_name!r}")
    raw = load_external_gate_file(ops, repo, authority_path, "procedural authority", MAX_PROCEDURAL_AUTHORITY_BYTES)
    validated = validate_procedural_authority_raw(
        raw,
        state_raw=state_raw,
        closure_state_commit=ops.text(repo, "rev-parse", "HEAD"),
        label=str(authority_path),
    )
    state = obj(parse_json(state_raw, "procedural authority gate-state consistency"), "procedural authority gate-state consistency")
    state_closure = obj(state.get("closureSet"), "procedural authority gate-state closure consistency")
    state_handoff = obj(state.get("handoff"), "procedural authority gate-state handoff consistency")
    state_items = indexed(arr(state_handoff.get("items"), "procedural authority gate-state handoff consistency items"), "id", "procedural authority gate-state handoff consistency items")
    require(state_closure == closure, "procedural authority: caller closure view differs from canonical gate state")
    require(state_items == items, "procedural authority: caller handoff view differs from canonical gate state")
    require(validated["expectedExternalFile"] == expected_name, "procedural authority: derived external file name mismatch")
    require(set(validated["assignments"]) == {handoff_id for handoff_id, item in items.items() if item["evidence"] is not None}, "procedural authority: completed handoff assignment mismatch")
    return {
        "assignments": validated["assignments"],
        "report": {
            **PROCEDURAL_AUTHORITY_ASSURANCE,
            "externalFile": expected_name,
            "required": True,
            "sha256": validated["sha256"],
            "contentBindingVerified": validated["contentBindingVerified"],
        },
    }


def verify_reference(ops: GitOps, repo: Path, evidence_commit: str, raw: Any, label: str, prefix: str, max_bytes: int = MAX_ARTIFACT_BYTES) -> tuple[dict[str, str], bytes]:
    reference = validate_content_reference(raw, label, prefix)
    content = ops.blob(repo, evidence_commit, reference["path"], label, max_bytes=max_bytes)
    require(sha256(content) == reference["sha256"], f"{label}: digest mismatch")
    return reference, content


def validate_and_load_refs(ops: GitOps, repo: Path, evidence_commit: str, rows: Any, label: str, prefix: str) -> dict[str, dict[str, Any]]:
    references: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for index, raw in enumerate(arr(rows, label)):
        row = obj(raw, f"{label}[{index}]")
        exact_keys(row, {"id", "path", "sha256"}, f"{label}[{index}]")
        row_id = nonempty(row["id"], f"{label}[{index}].id")
        require(IDENTIFIER_RE.fullmatch(row_id) is not None and row_id not in references, f"{label}: invalid or duplicate ID {row_id!r}")
        reference, content = verify_reference(ops, repo, evidence_commit, {"path": row["path"], "sha256": row["sha256"]}, f"{label}[{index}]", prefix)
        require(reference["path"] not in paths, f"{label}: duplicate content path {reference['path']!r}")
        paths.add(reference["path"])
        references[row_id] = {"id": row_id, **reference, "raw": content}
    return references


def validate_evidence(rows: Any, references: dict[str, dict[str, Any]], label: str) -> dict[str, list[str]]:
    by_kind: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(arr(rows, label)):
        row = obj(raw, f"{label}[{index}]")
        exact_keys(row, {"kind", "refId"}, f"{label}[{index}]")
        kind = nonempty(row["kind"], f"{label}[{index}].kind")
        ref_id = nonempty(row["refId"], f"{label}[{index}].refId")
        require(IDENTIFIER_RE.fullmatch(kind) is not None, f"{label}[{index}]: invalid evidence kind")
        require(ref_id in references, f"{label}[{index}]: unknown evidence reference {ref_id!r}")
        require((kind, ref_id) not in seen, f"{label}: duplicate evidence row")
        seen.add((kind, ref_id))
        by_kind.setdefault(kind, []).append(ref_id)
    require(by_kind, f"{label}: empty evidence")
    return by_kind


def validate_finding_result(raw: Any, expected_finding: str, references: dict[str, dict[str, Any]], label: str) -> dict[str, Any]:
    source = obj(raw, label)
    exact_keys(source, {"findingId", "policyId", "disposition", "mode", "evidence", "claims"}, label)
    require(source["findingId"] == expected_finding and source["policyId"] == f"{expected_finding}-v1", f"{label}: identity mismatch")
    nonempty(source["disposition"], f"{label}.disposition")
    nonempty(source["mode"], f"{label}.mode")
    result = copy.deepcopy(source)
    result["_evidenceByKind"] = validate_evidence(source["evidence"], references, f"{label}.evidence")
    result["_references"] = references
    obj(source["claims"], f"{label}.claims")
    return result


def verify_handoff_evidence(ops: GitOps, repo: Path, evidence_commit: str, closure_id: str, aggregate_sha: str, handoff_id: str, raw_reference: Any, procedural_assignments: dict[str, dict[str, str]], verification_time: datetime) -> dict[str, Any]:
    evidence_reference = obj(raw_reference, f"{handoff_id} evidence reference")
    validate_attestation_reference_shape(evidence_reference, f"{handoff_id} evidence reference")
    prefix = f"evidence/d0-closure/{closure_id}/{handoff_id}/"
    operator_ref, operator_raw = verify_reference(ops, repo, evidence_commit, evidence_reference["operatorReturn"], f"{handoff_id} operator return", prefix, MAX_JSON_BYTES)
    agent_ref, agent_raw = verify_reference(ops, repo, evidence_commit, evidence_reference["agentVerification"], f"{handoff_id} agent verification", prefix, MAX_JSON_BYTES)
    review_ref, review_raw = verify_reference(ops, repo, evidence_commit, evidence_reference["proceduralReview"], f"{handoff_id} procedural review", prefix, MAX_JSON_BYTES)
    require(len({operator_ref["path"], agent_ref["path"], review_ref["path"]}) == 3, f"{handoff_id}: attestation paths must be distinct")
    require(set(procedural_assignments) == set(PROCEDURAL_ROLES), f"{handoff_id}: procedural authority assignment coverage mismatch")
    for artifact_kind, expected_role in PROCEDURAL_ROLES.items():
        assignment = obj(procedural_assignments[artifact_kind], f"{handoff_id} procedural assignment.{artifact_kind}")
        exact_keys(assignment, {"principalLabel", "role"}, f"{handoff_id} procedural assignment.{artifact_kind}")
        require(assignment["role"] == expected_role, f"{handoff_id}: procedural authority role mismatch for {artifact_kind}")
        procedural_principal(assignment["principalLabel"], f"{handoff_id} procedural assignment.{artifact_kind}.principalLabel")
    operator = obj(parse_json(operator_raw, operator_ref["path"]), f"{handoff_id} operator return")
    exact_keys(operator, {"schema", "closureSetId", "handoffId", "aggregateSha256", "returnedBy", "returnedAt", "artifactRefs", "decisionRefs", "findingResults"}, f"{handoff_id} operator return")
    require(operator["schema"] == "pkgre-d0-operator-return-v1" and operator["closureSetId"] == closure_id and operator["handoffId"] == handoff_id and operator["aggregateSha256"] == aggregate_sha, f"{handoff_id}: operator-return binding mismatch")
    returned_by = procedural_principal(operator["returnedBy"], f"{handoff_id}.returnedBy")
    require(returned_by == procedural_assignments["operatorReturn"]["principalLabel"], f"{handoff_id}: operator-return label disagrees with external procedural assignment")
    returned_at = parse_utc(operator["returnedAt"], f"{handoff_id}.returnedAt")
    artifact_refs = validate_and_load_refs(ops, repo, evidence_commit, operator["artifactRefs"], f"{handoff_id} artifactRefs", prefix)
    decision_refs = validate_and_load_refs(ops, repo, evidence_commit, operator["decisionRefs"], f"{handoff_id} decisionRefs", prefix)
    require(set(artifact_refs).isdisjoint(decision_refs), f"{handoff_id}: duplicate ID across artifact and decision references")
    references = {**artifact_refs, **decision_refs}
    attestation_paths = {operator_ref["path"], agent_ref["path"], review_ref["path"]}
    require(attestation_paths.isdisjoint(reference["path"] for reference in references.values()), f"{handoff_id}: attestation and content paths overlap")
    raw_results = arr(operator["findingResults"], f"{handoff_id} findingResults")
    expected_findings = HANDOFFS[handoff_id][2]
    require(len(raw_results) == len(expected_findings), f"{handoff_id}: finding-result coverage mismatch")
    results: dict[str, dict[str, Any]] = {}
    for index, expected_finding in enumerate(expected_findings):
        result = validate_finding_result(raw_results[index], expected_finding, references, f"{handoff_id} findingResults[{index}]")
        result["_handoffId"] = handoff_id
        results[expected_finding] = result
    used_reference_ids = {
        ref_id
        for result in results.values()
        for ref_ids in result["_evidenceByKind"].values()
        for ref_id in ref_ids
    }
    require(used_reference_ids == set(references), f"{handoff_id}: every declared artifact/decision reference must be used exactly by finding evidence")
    agent = obj(parse_json(agent_raw, agent_ref["path"]), f"{handoff_id} agent verification")
    exact_keys(agent, {"schema", "closureSetId", "handoffId", "aggregateSha256", "operatorReturnSha256", "actor", "completedAt", "result"}, f"{handoff_id} agent verification")
    require(agent == {"schema": "pkgre-d0-agent-verification-v1", "closureSetId": closure_id, "handoffId": handoff_id, "aggregateSha256": aggregate_sha, "operatorReturnSha256": operator_ref["sha256"], "actor": agent.get("actor"), "completedAt": agent.get("completedAt"), "result": "VERIFIED"}, f"{handoff_id}: agent-verification binding/result mismatch")
    actor = procedural_principal(agent["actor"], f"{handoff_id} agent actor")
    require(actor == procedural_assignments["agentVerification"]["principalLabel"], f"{handoff_id}: agent-verification label disagrees with external procedural assignment")
    completed_at = parse_utc(agent["completedAt"], f"{handoff_id}.completedAt")
    review = obj(parse_json(review_raw, review_ref["path"]), f"{handoff_id} procedural review")
    exact_keys(review, {"schema", "closureSetId", "handoffId", "aggregateSha256", "operatorReturnSha256", "agentVerificationSha256", "reviewer", "reviewedAt", "result"}, f"{handoff_id} procedural review")
    require(review == {"schema": "pkgre-d0-procedural-review-v1", "closureSetId": closure_id, "handoffId": handoff_id, "aggregateSha256": aggregate_sha, "operatorReturnSha256": operator_ref["sha256"], "agentVerificationSha256": agent_ref["sha256"], "reviewer": review.get("reviewer"), "reviewedAt": review.get("reviewedAt"), "result": "ACCEPTED"}, f"{handoff_id}: procedural-review binding/result mismatch")
    reviewer = procedural_principal(review["reviewer"], f"{handoff_id} procedural reviewer")
    require(reviewer == procedural_assignments["proceduralReview"]["principalLabel"], f"{handoff_id}: procedural-review label disagrees with external procedural assignment")
    reviewed_at = parse_utc(review["reviewedAt"], f"{handoff_id}.reviewedAt")
    require(len({returned_by, actor, reviewer}) == 3, f"{handoff_id}: externally assigned procedural principals must be pairwise distinct")
    require(returned_at <= completed_at <= reviewed_at, f"{handoff_id}: invalid attestation chronology")
    for when, name in ((returned_at, "operator return"), (completed_at, "agent verification"), (reviewed_at, "procedural review")):
        require(when <= verification_time + timedelta(seconds=D0_EVIDENCE_FUTURE_SKEW_SECONDS), f"{handoff_id}: {name} timestamp is too far in the future at verification time")
    for result in results.values():
        result["_operatorReturnedBy"] = operator["returnedBy"]
        result["_operatorReturnedAt"] = operator["returnedAt"]
    return {"reference": copy.deepcopy(evidence_reference), "results": results, "operator": operator, "proceduralPrincipalLabels": {"operatorReturn": returned_by, "agentVerification": actor, "proceduralReview": reviewer}}


def evidence_ids(result: dict[str, Any], kind: str) -> list[str]:
    return list(result["_evidenceByKind"].get(kind, []))


def require_claim_ref_ids(result: dict[str, Any], claim_value: Any, kind: str, label: str) -> list[str]:
    expected = sorted(evidence_ids(result, kind))
    require(expected and claim_value == expected, f"{label}: must exactly reference {kind!r} evidence IDs")
    return expected


def validate_semantic_documents(finding_id: str, disposition: str, result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    handoff_id = nonempty(result.get("_handoffId"), f"{finding_id} semantic handoff")
    require(handoff_id in FINDING_HANDOFFS[finding_id], f"{finding_id}: semantic result belongs to an unexpected handoff")
    if disposition == "SATISFIED":
        expected_kinds = SAT_EVIDENCE_BY_HANDOFF[finding_id].get(handoff_id)
        require(expected_kinds is not None, f"{finding_id}: no satisfaction evidence is assigned to {handoff_id}")
        expected_targets: list[str] = []
    elif disposition == "REPHASED":
        expected_kinds = {"phase-amendment"}
        expected_targets = REPHASE_TARGETS[finding_id]
    else:
        raise GateVerificationError(f"{finding_id}: disposition {disposition!r} has no semantic-document policy")
    evidence_by_kind = result["_evidenceByKind"]
    require(set(evidence_by_kind) == expected_kinds, f"{finding_id}/{handoff_id}: evidence-kind set must be exact;expected={sorted(expected_kinds)!r}")
    require(all(len(ref_ids) == 1 for ref_ids in evidence_by_kind.values()), f"{finding_id}/{handoff_id}: exactly one semantic document is required per evidence kind")
    all_ref_ids = [ref_id for ref_ids in evidence_by_kind.values() for ref_id in ref_ids]
    require(len(all_ref_ids) == len(set(all_ref_ids)), f"{finding_id}/{handoff_id}: an evidence reference cannot be reused across semantic kinds")
    claims = obj(result["claims"], f"{finding_id}/{handoff_id} claims")
    exact_keys(claims, {"evidenceByKind", "targetGates"}, f"{finding_id}/{handoff_id} claims")
    claimed_evidence = obj(claims["evidenceByKind"], f"{finding_id}/{handoff_id} claims.evidenceByKind")
    require(claimed_evidence == evidence_by_kind, f"{finding_id}/{handoff_id}: claims must exactly bind every evidence kind and reference")
    require(claims["targetGates"] == expected_targets, f"{finding_id}/{handoff_id}: target-gate claim mismatch")
    documents: dict[str, dict[str, Any]] = {}
    for kind in sorted(expected_kinds):
        ref_id = evidence_by_kind[kind][0]
        reference = result["_references"][ref_id]
        document = obj(parse_json(reference["raw"], f"{finding_id}/{handoff_id} {kind} semantic document"), f"{finding_id}/{handoff_id} {kind} semantic document")
        exact_keys(document, {"schema", "findingId", "kind", "payload"}, f"{finding_id}/{handoff_id} {kind} semantic document")
        expected_schema = PHASE_AMENDMENT_SCHEMA if kind == "phase-amendment" else SEMANTIC_EVIDENCE_SCHEMA
        require(document["schema"] == expected_schema and document["findingId"] == finding_id and document["kind"] == kind, f"{finding_id}/{handoff_id} {kind}: semantic envelope binding mismatch")
        payload = obj(document["payload"], f"{finding_id}/{handoff_id} {kind} payload")
        documents[kind] = payload
    result["_semanticPayloads"] = documents
    return documents


def semantic_text(value: Any, label: str, maximum_bytes: int = 512) -> str:
    text = nonempty(value, label)
    require(len(text.encode("utf-8")) <= maximum_bytes and all(character.isprintable() for character in text), f"{label}: invalid or overlong semantic text")
    return text


def security_text(value: Any, label: str, maximum_bytes: int = 512) -> str:
    text = semantic_text(value, label, maximum_bytes)
    require("PRIVATE KEY" not in text.upper() and "BEGIN OPENSSH" not in text.upper(), f"{label}: private-key-shaped text is forbidden")
    require(re.search(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])", text) is None, f"{label}: secret-shaped hexadecimal text is forbidden")
    require(re.search(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])", text) is None, f"{label}: secret-shaped base64 text is forbidden")
    return text


def security_identifier(value: Any, label: str) -> str:
    identifier = semantic_identifier(value, label)
    security_text(identifier, label, 128)
    return identifier


def operator_return_context(result: dict[str, Any], finding_id: str) -> tuple[str, datetime]:
    operator = security_text(result.get("_operatorReturnedBy"), f"{finding_id} operator return identity", 128)
    returned_at = parse_utc(result.get("_operatorReturnedAt"), f"{finding_id} operator return UTC")
    return operator, returned_at


def b13_projection_sha256(kind: str, projection: Any) -> str:
    policy = B13_APPROVAL_POLICY.get(kind)
    require(policy is not None, "D0-B13: unsupported approval kind")
    return sha256(canonical_json({"schema": policy["projectionSchema"], "projection": projection}))


def validate_b13_approval(result: dict[str, Any], kind: str, verification_time: datetime) -> tuple[dict[str, Any], str]:
    policy = B13_APPROVAL_POLICY.get(kind)
    require(policy is not None, "D0-B13: unsupported approval kind")
    label = f"D0-B13/OP-D0-06 {kind} approval"
    payload = obj(result.get("_semanticPayloads", {}).get(kind), label)
    exact_keys(payload, {"approvalSchema", "operatorDecision", "projection", "projectionSha256", "result"}, label)
    require(payload["approvalSchema"] == B13_APPROVAL_SCHEMA, f"{label}: approval schema mismatch")
    require(payload["result"] == "APPROVED", f"{label}: approval result mismatch")
    projection = obj(payload["projection"], f"{label}.projection")
    projection_digest = hex_digest(payload["projectionSha256"], f"{label}.projectionSha256")
    decision = obj(payload["operatorDecision"], f"{label}.operatorDecision")
    exact_keys(decision, {"decision", "returnedBy", "returnedAt", "scope", "projectionSha256"}, f"{label}.operatorDecision")
    require(decision["decision"] == policy["decision"], f"{label}: operator decision mismatch")
    require(decision["scope"] == policy["scope"], f"{label}: operator scope mismatch")
    decision_digest = hex_digest(decision["projectionSha256"], f"{label}.operatorDecision.projectionSha256")
    require(decision_digest == projection_digest, f"{label}: approval projection digest disagreement")
    operator, returned_at = operator_return_context(result, "D0-B13")
    require(security_text(decision["returnedBy"], f"{label}.operatorDecision.returnedBy", 128) == operator, f"{label}: operator identity mismatch")
    decision_time = parse_utc(decision["returnedAt"], f"{label}.operatorDecision.returnedAt")
    require(decision_time == returned_at, f"{label}: operator return time mismatch")
    require_fresh(decision_time, returned_at, verification_time, f"{label}.operatorDecision")
    expected_digest = b13_projection_sha256(kind, projection)
    require(projection_digest == expected_digest, f"{label}: projection digest mismatch")
    return projection, projection_digest


def validate_b13_protocol_enums(result: dict[str, Any], verification_time: datetime) -> tuple[dict[str, Any], str]:
    projection, projection_digest = validate_b13_approval(result, "protocol-enums", verification_time)
    exact_json_value(projection, B13_PROTOCOL_ENUMS_PROJECTION, "D0-B13 protocol-enums projection")
    return copy.deepcopy(projection), projection_digest


def require_no_later(when: datetime, upper_bound: datetime, label: str) -> None:
    require(when <= upper_bound, f"{label}: timestamp is later than its attested upper bound")


def require_fresh(when: datetime, returned_at: datetime, verification_time: datetime, label: str, maximum_age_seconds: int = D0_LIVE_EVIDENCE_MAX_AGE_SECONDS) -> None:
    require_no_later(when, returned_at, label)
    require((returned_at - when).total_seconds() <= maximum_age_seconds, f"{label}: evidence is older than {maximum_age_seconds} seconds at operator return")
    require(when <= verification_time + timedelta(seconds=D0_EVIDENCE_FUTURE_SKEW_SECONDS), f"{label}: timestamp is too far in the future at verification time")
    require((verification_time - when).total_seconds() <= maximum_age_seconds, f"{label}: evidence is older than {maximum_age_seconds} seconds at verification time")


def validate_credential_handle(raw: Any, label: str) -> dict[str, str]:
    handle = obj(raw, label)
    exact_keys(handle, {"kind", "value"}, label)
    require(handle["kind"] == "SAFE_SUFFIX", f"{label}: only a bounded safe credential suffix may be returned")
    value = security_text(handle["value"], f"{label}.value", 12)
    require(re.fullmatch(r"[A-Za-z0-9_.:-]+", value) is not None and 4 <= len(value) <= 12, f"{label}: safe suffix must contain 4..12 identifier characters")
    return {"kind": handle["kind"], "value": value}


def mode_permissions(mode: str) -> list[str]:
    value = int(mode, 8)
    return [
        "".join(letter if value & bit else "-" for letter, bit in (("r", 0o400), ("w", 0o200), ("x", 0o100))),
        "".join(letter if value & bit else "-" for letter, bit in (("r", 0o040), ("w", 0o020), ("x", 0o010))),
        "".join(letter if value & bit else "-" for letter, bit in (("r", 0o004), ("w", 0o002), ("x", 0o001))),
    ]


def account_name(value: Any, label: str) -> str:
    name = semantic_text(value, label, 64)
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", name) is not None, f"{label}: invalid account or group name")
    return name


def acl_permissions(value: Any, label: str) -> str:
    permissions = nonempty(value, label)
    require(re.fullmatch(r"[r-][w-][x-]", permissions) is not None, f"{label}: invalid ACL permissions")
    return permissions


def intersect_permissions(permissions: str, mask: str) -> str:
    return "".join(letter if permissions[index] == letter and mask[index] == letter else "-" for index, letter in enumerate("rwx"))


def validate_access_acl(raw: Any, owner: str, group: str, mode: str, label: str) -> list[str]:
    rows = arr(raw, label)
    require(3 <= len(rows) <= 67, f"{label}: invalid access ACL row count")
    validated: list[dict[str, Any]] = []
    identities: set[tuple[str, str | None]] = set()
    for index, raw_row in enumerate(rows):
        row_label = f"{label}[{index}]"
        row = obj(raw_row, row_label)
        exact_keys(row, {"tag", "qualifier", "permissions", "effectivePermissions"}, row_label)
        tag = nonempty(row["tag"], f"{row_label}.tag")
        require(tag in {"USER_OBJ", "USER", "GROUP_OBJ", "GROUP", "MASK", "OTHER"}, f"{row_label}: unsupported ACL tag")
        if tag in {"USER", "GROUP"}:
            qualifier = account_name(row["qualifier"], f"{row_label}.qualifier")
        else:
            require(row["qualifier"] is None, f"{row_label}: base ACL entry must have null qualifier")
            qualifier = None
        identity = (tag, qualifier)
        require(identity not in identities, f"{label}: duplicate ACL entry")
        identities.add(identity)
        permissions = acl_permissions(row["permissions"], f"{row_label}.permissions")
        effective = acl_permissions(row["effectivePermissions"], f"{row_label}.effectivePermissions")
        validated.append({"tag": tag, "qualifier": qualifier, "permissions": permissions, "effectivePermissions": effective})
    for required_tag in ("USER_OBJ", "GROUP_OBJ", "OTHER"):
        require(sum(row["tag"] == required_tag for row in validated) == 1, f"{label}: exactly one {required_tag} ACL entry is required")
    named = [row for row in validated if row["tag"] in {"USER", "GROUP"}]
    masks = [row for row in validated if row["tag"] == "MASK"]
    require((len(masks) == 1) if named else (len(masks) == 0), f"{label}: extended ACLs require exactly one mask and base ACLs forbid a mask")
    order = {"USER_OBJ": 0, "USER": 1, "GROUP_OBJ": 2, "GROUP": 3, "MASK": 4, "OTHER": 5}
    require(validated == sorted(validated, key=lambda row: (order[row["tag"]], "" if row["qualifier"] is None else row["qualifier"])), f"{label}: ACL entries are not in canonical order")
    mask = masks[0]["permissions"] if masks else None
    for row in validated:
        expected_effective = row["permissions"]
        if mask is not None and row["tag"] in {"USER", "GROUP_OBJ", "GROUP"}:
            expected_effective = intersect_permissions(row["permissions"], mask)
        require(row["effectivePermissions"] == expected_effective, f"{label}: ACL effective permissions disagree with the mask")
        if row["tag"] not in {"USER_OBJ", "MASK"}:
            require("w" not in row["permissions"] and "x" not in row["permissions"], f"{label}: non-owner ACL entry contains write or execute permission")
    by_tag = {row["tag"]: row for row in validated if row["tag"] not in {"USER", "GROUP"}}
    group_mode_permissions = masks[0]["permissions"] if masks else by_tag["GROUP_OBJ"]["permissions"]
    require(mode_permissions(mode) == [by_tag["USER_OBJ"]["permissions"], group_mode_permissions, by_tag["OTHER"]["permissions"]], f"{label}: access ACL disagrees with Unix mode")
    readers: list[str] = []
    for row in validated:
        if "r" not in row["effectivePermissions"] or row["tag"] == "MASK":
            continue
        reader = f"user:{owner}" if row["tag"] == "USER_OBJ" else f"user:{row['qualifier']}" if row["tag"] == "USER" else f"group:{group}" if row["tag"] == "GROUP_OBJ" else f"group:{row['qualifier']}" if row["tag"] == "GROUP" else "other"
        require(reader not in readers, f"{label}: duplicate effective reader principal")
        readers.append(reader)
    return sorted(readers)


def validate_rain_generation(value: Any, label: str) -> str:
    path = absolute_path(value, label)
    match = NIX_STORE_PATH_RE.fullmatch(path)
    require(match is not None and match.group("name").startswith("nixos-system-rain-"), f"{label}: expected a canonical Rain NixOS system generation")
    return path


def validate_metadata_collection(raw: Any, metadata: dict[str, Any], label: str, expected_collector: str) -> str:
    collection = obj(raw, label)
    exact_keys(collection, {"collectionId", "method", "collector", "targetPath", "observedAt", "returnedFields", "contentAccess", "result"}, label)
    collection_id = security_identifier(collection["collectionId"], f"{label}.collectionId")
    require(collection["method"] == "METADATA_SYSCALLS_AND_ACCESS_ACL_ONLY", f"{label}: unsupported metadata-only collection method")
    collector = security_text(collection["collector"], f"{label}.collector", 128)
    require(collector == expected_collector, f"{label}: collector does not match operator return")
    require(absolute_path(collection["targetPath"], f"{label}.targetPath") == metadata["path"], f"{label}: target path does not match returned metadata")
    require(utc_text(collection["observedAt"], f"{label}.observedAt") == metadata["observedAt"], f"{label}: observation time does not match returned metadata")
    require(arr(collection["returnedFields"], f"{label}.returnedFields") == FILE_METADATA_RETURNED_FIELDS, f"{label}: returned-field declaration must exactly cover the metadata-only schema")
    content_access = obj(collection["contentAccess"], f"{label}.contentAccess")
    exact_keys(content_access, {"opened", "read", "digested"}, f"{label}.contentAccess")
    for field in ("opened", "read", "digested"):
        require(strict_bool(content_access[field], f"{label}.contentAccess.{field}") is False, f"{label}: file content must not be opened, read, or digested")
    require(collection["result"] == "PASS", f"{label}: metadata-only collection did not pass")
    return collection_id


def validate_file_metadata(raw: Any, label: str, expected_path: str | None, expected_collector: str, *, private: bool, maximum_bytes: int) -> dict[str, Any]:
    metadata = obj(raw, label)
    exact_keys(metadata, {*FILE_METADATA_RETURNED_FIELDS, "collection"}, label)
    path = absolute_path(metadata["path"], f"{label}.path")
    if expected_path is not None:
        require(path == expected_path, f"{label}: unexpected file path")
    require(metadata["fileType"] == "REGULAR" and metadata["symlinkTarget"] is None, f"{label}: evidence must describe a non-symlink regular file")
    owner = account_name(metadata["owner"], f"{label}.owner")
    group = account_name(metadata["group"], f"{label}.group")
    mode = unix_mode(metadata["mode"], f"{label}.mode")
    allowed_modes = {"0400", "0440", "0600", "0640"} if private else {"0400", "0440", "0444", "0600", "0640", "0644"}
    require(mode in allowed_modes, f"{label}: file mode violates the {'private' if private else 'public-certificate'} policy")
    require(strict_bool(metadata["aclComplete"], f"{label}.aclComplete") is True, f"{label}: complete access ACL attestation is required")
    require(metadata["readerMechanism"] == "POSIX_MODE_AND_ACCESS_ACL", f"{label}: unsupported authorized-reader mechanism")
    actual_readers = validate_access_acl(metadata["acl"], owner, group, mode, f"{label}.acl")
    readers = unique_strings(metadata["effectiveReaders"], f"{label}.effectiveReaders", canonical_order=True)
    require(readers == actual_readers, f"{label}: declared readers do not equal effective access-ACL readers")
    if private:
        require("other" not in readers, f"{label}: private file grants read access to other")
    bounded_integer(metadata["sizeBytes"], f"{label}.sizeBytes", 1, maximum_bytes)
    security_identifier(metadata["purpose"], f"{label}.purpose")
    utc_text(metadata["observedAt"], f"{label}.observedAt")
    validate_rain_generation(metadata["sourceGeneration"], f"{label}.sourceGeneration")
    validate_metadata_collection(metadata["collection"], metadata, f"{label}.collection", expected_collector)
    return metadata


def validate_file_policy(raw: Any, label: str, expected_path: str, *, private: bool, maximum_bytes: int) -> dict[str, Any]:
    policy = obj(raw, label)
    exact_keys(policy, {"path", "owner", "group", "mode", "acl", "aclComplete", "purpose", "readerMechanism", "effectiveReaders", "maximumSizeBytes"}, label)
    path = absolute_path(policy["path"], f"{label}.path")
    require(path == expected_path, f"{label}: unexpected intended file path")
    owner = account_name(policy["owner"], f"{label}.owner")
    group = account_name(policy["group"], f"{label}.group")
    mode = unix_mode(policy["mode"], f"{label}.mode")
    allowed_modes = {"0400", "0440", "0600", "0640"} if private else {"0400", "0440", "0444", "0600", "0640", "0644"}
    require(mode in allowed_modes, f"{label}: intended file mode violates the {'private' if private else 'public-certificate'} policy")
    require(strict_bool(policy["aclComplete"], f"{label}.aclComplete") is True, f"{label}: complete intended access ACL is required")
    require(policy["readerMechanism"] == "POSIX_MODE_AND_ACCESS_ACL", f"{label}: unsupported intended authorized-reader mechanism")
    actual_readers = validate_access_acl(policy["acl"], owner, group, mode, f"{label}.acl")
    readers = unique_strings(policy["effectiveReaders"], f"{label}.effectiveReaders", canonical_order=True)
    require(readers == actual_readers, f"{label}: intended readers do not equal intended access-ACL readers")
    if private:
        require("other" not in readers, f"{label}: intended private file grants read access to other")
    bounded_integer(policy["maximumSizeBytes"], f"{label}.maximumSizeBytes", 1, maximum_bytes)
    security_identifier(policy["purpose"], f"{label}.purpose")
    return copy.deepcopy(policy)


def validate_declarative_credential_policy(raw: Any, label: str) -> dict[str, Any]:
    declaration = obj(raw, label)
    exact_keys(declaration, {"source", "deployedGeneration", "intendedMetadata"}, label)
    source = obj(declaration["source"], f"{label}.source")
    exact_keys(source, {"repositoryId", "commit", "path"}, f"{label}.source")
    require(source["repositoryId"] == INFRA_REPOSITORY_ID, f"{label}: declarative source repository mismatch")
    commit = hex_digest(source["commit"], f"{label}.source.commit", "sha1")
    require(commit == INFRA_REVIEWED_COMMIT, f"{label}: declarative source commit is not the reviewed production infra commit")
    require(safe_path(source["path"], f"{label}.source.path") == RAIN_PKGRE_MODULE_PATH, f"{label}: declarative source module mismatch")
    generation = validate_rain_generation(declaration["deployedGeneration"], f"{label}.deployedGeneration")
    intended = validate_file_policy(declaration["intendedMetadata"], f"{label}.intendedMetadata", "/var/lib/keys/pkgre-js-gandiv5-token", private=True, maximum_bytes=D0_CREDENTIAL_MAX_BYTES)
    require(intended["owner"] == "root" and intended["group"] == "root" and intended["purpose"] == "GANDI_LIVEDNS_DNS01", f"{label}: intended credential identity or purpose mismatch")
    require(intended["mode"] in {"0400", "0600"} and intended["effectiveReaders"] == ["user:root"], f"{label}: intended credential must be readable only by root")
    return {"source": copy.deepcopy(source), "deployedGeneration": generation, "intendedMetadata": intended}


def require_file_matches_policy(metadata: dict[str, Any], declaration: dict[str, Any], label: str) -> None:
    intended = declaration["intendedMetadata"]
    for field in ("path", "owner", "group", "mode", "acl", "aclComplete", "purpose", "readerMechanism", "effectiveReaders"):
        require(metadata[field] == intended[field], f"{label}: live credential {field} disagrees with declarative policy")
    require(metadata["sizeBytes"] <= intended["maximumSizeBytes"], f"{label}: live credential exceeds the declarative maximum size")
    require(metadata["sourceGeneration"] == declaration["deployedGeneration"], f"{label}: live credential generation disagrees with deployed declarative generation")


def validate_event_subject(raw: Any, label: str) -> dict[str, Any]:
    subject = obj(raw, label)
    subject_type = nonempty(subject.get("type"), f"{label}.type")
    if subject_type == "FILE_PATH":
        exact_keys(subject, {"type", "path"}, label)
        return {"type": subject_type, "path": absolute_path(subject["path"], f"{label}.path")}
    if subject_type == "CREDENTIAL_HANDLE":
        exact_keys(subject, {"type", "handle"}, label)
        return {"type": subject_type, "handle": validate_credential_handle(subject["handle"], f"{label}.handle")}
    raise GateVerificationError(f"{label}: unsupported event subject type")


def validate_event(raw: Any, label: str, expected_subject: dict[str, Any], expected_actor: str, upper_bound: datetime, returned_at: datetime, verification_time: datetime) -> dict[str, Any]:
    event = obj(raw, label)
    exact_keys(event, {"eventId", "occurredAt", "actor", "subject", "result"}, label)
    security_identifier(event["eventId"], f"{label}.eventId")
    occurred_at = parse_utc(event["occurredAt"], f"{label}.occurredAt")
    require_fresh(occurred_at, returned_at, verification_time, label)
    require_no_later(occurred_at, upper_bound, label)
    actor = security_text(event["actor"], f"{label}.actor", 128)
    require(actor == expected_actor, f"{label}: actor does not match operator return")
    require(validate_event_subject(event["subject"], f"{label}.subject") == expected_subject, f"{label}: event subject does not match the required object")
    require(event["result"] == "PASS", f"{label}: result must be 'PASS'")
    return event


def validate_procedure(raw: Any, label: str, expected_operations: list[str], expected_subject: dict[str, Any], expected_owner: str, returned_at: datetime, verification_time: datetime) -> dict[str, Any]:
    procedure = obj(raw, label)
    exact_keys(procedure, {"procedureId", "owner", "subject", "operations", "test"}, label)
    procedure_id = security_identifier(procedure["procedureId"], f"{label}.procedureId")
    owner = security_text(procedure["owner"], f"{label}.owner", 128)
    require(owner == expected_owner, f"{label}: owner does not match operator return")
    require(obj(procedure["subject"], f"{label}.subject") == expected_subject, f"{label}: procedure is not bound to the required subject")
    require(arr(procedure["operations"], f"{label}.operations") == expected_operations, f"{label}: required procedure operations are absent or out of order")
    test = obj(procedure["test"], f"{label}.test")
    exact_keys(test, {"eventId", "procedureId", "subject", "mode", "fixture", "environment", "testCase", "actor", "testedAt", "operations", "result"}, f"{label}.test")
    security_identifier(test["eventId"], f"{label}.test.eventId")
    require(test["procedureId"] == procedure_id, f"{label}: test event is not bound to its procedure")
    require(obj(test["subject"], f"{label}.test.subject") == expected_subject, f"{label}: test event is not bound to the required subject")
    require(test["mode"] in {"TABLETOP", "ISOLATED_REHEARSAL"}, f"{label}: procedure test mode must be TABLETOP or ISOLATED_REHEARSAL")
    fixture = obj(test["fixture"], f"{label}.test.fixture")
    exact_keys(fixture, {"fixtureId", "productionMaterialUsed", "replacementIdentity"}, f"{label}.test.fixture")
    security_identifier(fixture["fixtureId"], f"{label}.test.fixture.fixtureId")
    require(strict_bool(fixture["productionMaterialUsed"], f"{label}.test.fixture.productionMaterialUsed") is False, f"{label}: procedure test must not use production secret or private-key material")
    replacement = obj(fixture["replacementIdentity"], f"{label}.test.fixture.replacementIdentity")
    exact_keys(replacement, {"type", "value"}, f"{label}.test.fixture.replacementIdentity")
    require(replacement["type"] == "NONPRODUCTION_FIXTURE_ID", f"{label}: procedure test replacement identity must be explicitly nonproduction")
    security_identifier(replacement["value"], f"{label}.test.fixture.replacementIdentity.value")
    environment = obj(test["environment"], f"{label}.test.environment")
    exact_keys(environment, {"kind", "name", "productionEndpointUsed"}, f"{label}.test.environment")
    require(environment["kind"] in {"DOCUMENTED_TABLETOP", "ISOLATED_NONPRODUCTION"}, f"{label}: unsupported procedure test environment")
    require((test["mode"] == "TABLETOP" and environment["kind"] == "DOCUMENTED_TABLETOP") or (test["mode"] == "ISOLATED_REHEARSAL" and environment["kind"] == "ISOLATED_NONPRODUCTION"), f"{label}: procedure test mode and environment disagree")
    security_text(environment["name"], f"{label}.test.environment.name", 128)
    require(strict_bool(environment["productionEndpointUsed"], f"{label}.test.environment.productionEndpointUsed") is False, f"{label}: procedure test must not exercise a production endpoint")
    test_case = obj(test["testCase"], f"{label}.test.testCase")
    exact_keys(test_case, {"caseId"}, f"{label}.test.testCase")
    security_identifier(test_case["caseId"], f"{label}.test.testCase.caseId")
    actor = security_text(test["actor"], f"{label}.test.actor", 128)
    require(actor == expected_owner, f"{label}: test actor does not match operator return")
    tested_at = parse_utc(test["testedAt"], f"{label}.test.testedAt")
    require_fresh(tested_at, returned_at, verification_time, f"{label}.test")
    test_operations = arr(test["operations"], f"{label}.test.operations")
    require(len(test_operations) == len(expected_operations), f"{label}: test operation coverage mismatch")
    for index, expected_operation in enumerate(expected_operations):
        row = obj(test_operations[index], f"{label}.test.operations[{index}]")
        exact_keys(row, {"operation", "expectedOutcome", "observedOutcome", "result"}, f"{label}.test.operations[{index}]")
        require(row["operation"] == expected_operation, f"{label}: procedure test operation coverage or order mismatch")
        expected_outcome = security_text(row["expectedOutcome"], f"{label}.test.operations[{index}].expectedOutcome", 256)
        observed_outcome = security_text(row["observedOutcome"], f"{label}.test.operations[{index}].observedOutcome", 256)
        require(expected_outcome == observed_outcome and row["result"] == "PASS", f"{label}: procedure test operation outcome did not pass exactly")
    require(test["result"] == "PASS", f"{label}: procedure test must PASS")
    return procedure


def procedure_identity_rows(procedure: dict[str, Any], label: str) -> list[tuple[str, str]]:
    test = procedure["test"]
    return [
        (procedure["procedureId"], f"{label}.procedureId"),
        (test["eventId"], f"{label}.test.eventId"),
        (test["fixture"]["fixtureId"], f"{label}.test.fixture.fixtureId"),
        (test["fixture"]["replacementIdentity"]["value"], f"{label}.test.fixture.replacementIdentity.value"),
        (test["testCase"]["caseId"], f"{label}.test.testCase.caseId"),
    ]


def require_globally_distinct_identifiers(rows: list[tuple[str, str]], label: str) -> None:
    identities: dict[str, tuple[str, str]] = {}
    for raw_identifier, source_label in rows:
        identifier = security_identifier(raw_identifier, source_label)
        identity_key = identifier.casefold()
        previous = identities.get(identity_key)
        previous_label = None if previous is None else previous[1]
        require(previous is None, f"{label}: identifier {identifier!r} is reused by {previous_label} and {source_label}")
        identities[identity_key] = (identifier, source_label)


PAT_PROCEDURE_OPERATIONS = {
    "routineRotation": ["ISSUE_SUCCESSOR", "ACTIVATE_SUCCESSOR", "VERIFY_DNS01", "REVOKE_PREDECESSOR", "VERIFY_REVOCATION"],
    "compromiseResponse": ["CONTAIN_CREDENTIAL", "REVOKE_COMPROMISED", "ISSUE_RECOVERY_CREDENTIAL", "ACTIVATE_RECOVERY_CREDENTIAL", "AUDIT_PROVIDER_ACTIVITY"],
    "recovery": ["RESTORE_PROVIDER_ACCESS", "ISSUE_RECOVERY_CREDENTIAL", "ACTIVATE_RECOVERY_CREDENTIAL", "VERIFY_DNS01", "REVOKE_SUPERSEDED"],
}
KEY_LIFECYCLE_OPERATIONS = {
    "rotation": ["CREATE_SUCCESSOR", "ACTIVATE_WITH_OVERLAP", "VERIFY_SUCCESSOR", "RETIRE_PREDECESSOR"],
    "revocation": ["REVOKE_ACTIVE", "REMOVE_ACTIVE", "VERIFY_REJECTED"],
    "compromiseResponse": ["CONTAIN_COMPROMISE", "REVOKE_COMPROMISED", "ACTIVATE_RECOVERY", "AUDIT_IMPACT"],
    "recovery": ["RESTORE_AUTHORITY", "CREATE_SUCCESSOR", "ACTIVATE_SUCCESSOR", "VERIFY_SERVICE"],
}
SSH_LIFECYCLE_OPERATIONS = {
    "rotation": ["CREATE_SUCCESSOR", "PUBLISH_SUCCESSOR", "DISTRIBUTE_SUCCESSOR", "ACTIVATE_WITH_OVERLAP", "VERIFY_SUCCESSOR", "RETIRE_PREDECESSOR"],
    "revocationAndClientRemediation": ["REVOKE_ACTIVE", "DISTRIBUTE_CLIENT_REMEDIATION", "VERIFY_PREDECESSOR_REJECTED", "VERIFY_SUCCESSOR_ACCEPTED"],
    "compromiseResponse": ["ISOLATE_COMPROMISED_HOST", "REVOKE_COMPROMISED", "ACTIVATE_RECOVERY", "DISTRIBUTE_RECOVERY_TRUST", "AUDIT_IMPACT"],
    "recovery": ["ESTABLISH_CONSOLE_CONTROL", "CREATE_SUCCESSOR", "ACTIVATE_SUCCESSOR", "DISTRIBUTE_SUCCESSOR", "VERIFY_SERVICE"],
}


def validate_b01_containment(payload: dict[str, Any], label: str, operator: str, returned_at: datetime, verification_time: datetime) -> dict[str, Any]:
    exact_keys(payload, {"rotationId", "credential", "declarativePolicy", "provider", "events", "installation", "audit", "secretMaterial"}, label)
    security_identifier(payload["rotationId"], f"{label}.rotationId")
    credential = validate_file_metadata(payload["credential"], f"{label}.credential", "/var/lib/keys/pkgre-js-gandiv5-token", operator, private=True, maximum_bytes=D0_CREDENTIAL_MAX_BYTES)
    require(credential["owner"] == "root" and credential["group"] == "root" and credential["purpose"] == "GANDI_LIVEDNS_DNS01", f"{label}: credential identity or purpose mismatch")
    require(credential["mode"] in {"0400", "0600"} and credential["effectiveReaders"] == ["user:root"], f"{label}: credential must be readable only by root")
    declarative = validate_declarative_credential_policy(payload["declarativePolicy"], f"{label}.declarativePolicy")
    require_file_matches_policy(credential, declarative, label)
    observation_time = parse_utc(credential["observedAt"], f"{label}.credential.observedAt")
    require_fresh(observation_time, returned_at, verification_time, f"{label}.credential observation")
    provider = obj(payload["provider"], f"{label}.provider")
    exact_keys(provider, {"identity", "oldCredential", "activeCredential", "zoneScopes", "permissions", "expiry"}, f"{label}.provider")
    require(provider["identity"] == "GANDI_LIVEDNS", f"{label}: provider identity mismatch")
    old_handle = validate_credential_handle(provider["oldCredential"], f"{label}.provider.oldCredential")
    active_handle = validate_credential_handle(provider["activeCredential"], f"{label}.provider.activeCredential")
    require(old_handle["kind"] == active_handle["kind"] and old_handle["value"] != active_handle["value"], f"{label}: old and active credential handles must be comparable and distinct")
    require(unique_strings(provider["zoneScopes"], f"{label}.provider.zoneScopes", canonical_order=True) == ["pkg.re"], f"{label}: provider scope must be exactly pkg.re")
    require(unique_strings(provider["permissions"], f"{label}.provider.permissions", canonical_order=True) == ["DNS_READ", "DNS_WRITE"], f"{label}: exact DNS_READ,DNS_WRITE provider permissions required")
    if provider["expiry"] != "NO_EXPIRY":
        require(parse_utc(provider["expiry"], f"{label}.provider.expiry") > returned_at, f"{label}: active provider credential is already expired at operator return")
    events = obj(payload["events"], f"{label}.events")
    exact_keys(events, {"permissionRepair", "newCredentialActivation", "oldCredentialRevocation"}, f"{label}.events")
    repair = validate_event(events["permissionRepair"], f"{label}.events.permissionRepair", {"type": "FILE_PATH", "path": credential["path"]}, operator, observation_time, returned_at, verification_time)
    activation = validate_event(events["newCredentialActivation"], f"{label}.events.newCredentialActivation", {"type": "CREDENTIAL_HANDLE", "handle": active_handle}, operator, observation_time, returned_at, verification_time)
    revocation = validate_event(events["oldCredentialRevocation"], f"{label}.events.oldCredentialRevocation", {"type": "CREDENTIAL_HANDLE", "handle": old_handle}, operator, observation_time, returned_at, verification_time)
    event_ids = [event["eventId"] for event in (repair, activation, revocation)]
    require(len(event_ids) == len(set(event_ids)), f"{label}: containment event IDs must be distinct")
    repair_time = parse_utc(repair["occurredAt"], f"{label}.repair time")
    activation_time = parse_utc(activation["occurredAt"], f"{label}.activation time")
    revocation_time = parse_utc(revocation["occurredAt"], f"{label}.revocation time")
    require(repair_time < activation_time < revocation_time <= observation_time, f"{label}: credential containment chronology is invalid")
    installation = obj(payload["installation"], f"{label}.installation")
    exact_keys(installation, {"bindingId", "credentialPath", "sourceGeneration", "activeCredential", "activationEventId", "dns01Operation", "boundAt", "result"}, f"{label}.installation")
    binding_id = security_identifier(installation["bindingId"], f"{label}.installation.bindingId")
    require(absolute_path(installation["credentialPath"], f"{label}.installation.credentialPath") == credential["path"], f"{label}: installation binding uses the wrong canonical credential path")
    require(validate_rain_generation(installation["sourceGeneration"], f"{label}.installation.sourceGeneration") == credential["sourceGeneration"], f"{label}: installation binding uses the wrong Rain generation")
    require(validate_credential_handle(installation["activeCredential"], f"{label}.installation.activeCredential") == active_handle, f"{label}: installed credential does not match the active provider credential")
    require(installation["activationEventId"] == activation["eventId"], f"{label}: installation binding does not reference the active credential activation event")
    dns01 = obj(installation["dns01Operation"], f"{label}.installation.dns01Operation")
    exact_keys(dns01, {"operationId", "providerIdentity", "zone", "certificateName", "operation", "occurredAt", "result"}, f"{label}.installation.dns01Operation")
    operation_id = security_identifier(dns01["operationId"], f"{label}.installation.dns01Operation.operationId")
    require(dns01["providerIdentity"] == provider["identity"] and dns01["zone"] == "pkg.re" and dns01["certificateName"] in ACME_NAMES and dns01["operation"] == "DNS01_CHALLENGE_UPDATE" and dns01["result"] == "PASS", f"{label}: installation binding lacks a successful pkg.re provider DNS-01 operation")
    dns01_time = parse_utc(dns01["occurredAt"], f"{label}.installation.dns01Operation.occurredAt")
    require_fresh(dns01_time, returned_at, verification_time, f"{label}.installation DNS-01 operation")
    bound_at = parse_utc(installation["boundAt"], f"{label}.installation.boundAt")
    require_fresh(bound_at, returned_at, verification_time, f"{label}.installation binding")
    require(activation_time <= dns01_time <= bound_at <= observation_time, f"{label}: active credential installation/use chronology is invalid")
    require(installation["result"] == "PASS", f"{label}: active credential installation/use binding did not pass")
    require(binding_id not in event_ids and operation_id not in {*event_ids, binding_id}, f"{label}: installation/event identifiers must be distinct")
    audit = arr(payload["audit"], f"{label}.audit")
    require(len(audit) == 3, f"{label}: expected exactly three provider audit checks")
    checks_seen: set[str] = set()
    audit_ids: set[str] = set()
    ordering: list[tuple[datetime, str]] = []
    expected_audit_handle = {"SCOPE": active_handle, "RECENT_ACTIVITY": active_handle, "REVOCATION": old_handle}
    for index, raw_row in enumerate(audit):
        row_label = f"{label}.audit[{index}]"
        row = obj(raw_row, row_label)
        exact_keys(row, {"auditId", "occurredAt", "actor", "check", "credential", "result"}, row_label)
        audit_id = security_identifier(row["auditId"], f"{row_label}.auditId")
        require(audit_id not in audit_ids, f"{label}: duplicate provider audit ID")
        audit_ids.add(audit_id)
        audit_time = parse_utc(row["occurredAt"], f"{row_label}.occurredAt")
        require_fresh(audit_time, returned_at, verification_time, row_label)
        require(revocation_time <= audit_time <= observation_time, f"{label}: provider audit must follow revocation and precede observation")
        actor = security_text(row["actor"], f"{row_label}.actor", 128)
        require(actor == operator, f"{row_label}: actor does not match operator return")
        check = nonempty(row["check"], f"{row_label}.check")
        require(check in expected_audit_handle and row["result"] == "PASS", f"{label}: invalid or failed provider audit check")
        require(validate_credential_handle(row["credential"], f"{row_label}.credential") == expected_audit_handle[check], f"{label}: provider audit check is bound to the wrong credential")
        checks_seen.add(check)
        ordering.append((audit_time, audit_id))
    require(ordering == sorted(ordering), f"{label}: provider audit rows are not in canonical chronological order")
    require(checks_seen == set(expected_audit_handle), f"{label}: provider audit must cover each required category exactly once")
    require((set(event_ids) | {binding_id, operation_id}).isdisjoint(audit_ids), f"{label}: containment,installation,and provider audit IDs must be distinct")
    secret = obj(payload["secretMaterial"], f"{label}.secretMaterial")
    exact_keys(secret, {"credentialValueRead", "credentialDigestRecorded"}, f"{label}.secretMaterial")
    require(strict_bool(secret["credentialValueRead"], f"{label}.secretMaterial.credentialValueRead") is False and strict_bool(secret["credentialDigestRecorded"], f"{label}.secretMaterial.credentialDigestRecorded") is False, f"{label}: credential bytes or digest must not be returned")
    return payload


def validate_b01_lifecycle(payload: dict[str, Any], label: str, operator: str, returned_at: datetime, verification_time: datetime) -> dict[str, Any]:
    exact_keys(payload, {"rotationId", "providerIdentity", "activeCredential", "observedAt", "sourceGeneration", "files", "patProcedures", "lifecycles", "secretMaterial"}, label)
    security_identifier(payload["rotationId"], f"{label}.rotationId")
    require(payload["providerIdentity"] == "GANDI_LIVEDNS", f"{label}: ACME provider identity mismatch")
    active_handle = validate_credential_handle(payload["activeCredential"], f"{label}.activeCredential")
    observed_at = parse_utc(payload["observedAt"], f"{label}.observedAt")
    require_fresh(observed_at, returned_at, verification_time, f"{label} observation")
    source_generation = validate_rain_generation(payload["sourceGeneration"], f"{label}.sourceGeneration")
    expected_files = [(f"{name}-certificate", f"/var/lib/acme/{name}/fullchain.pem", "TLS_CERTIFICATE", False, D0_CERTIFICATE_MAX_BYTES) for name in ACME_NAMES] + [(f"{name}-private-key", f"/var/lib/acme/{name}/key.pem", "TLS_PRIVATE_KEY", True, D0_PRIVATE_KEY_MAX_BYTES) for name in ACME_NAMES] + [("acme-account-key", None, "ACME_ACCOUNT_KEY", True, D0_PRIVATE_KEY_MAX_BYTES)]
    files = arr(payload["files"], f"{label}.files")
    require(len(files) == len(expected_files), f"{label}: exact ACME certificate,key,and account-key rows required")
    file_paths: list[str] = []
    metadata_by_id: dict[str, dict[str, Any]] = {}
    for index, (expected_id, expected_path, expected_purpose, private, maximum_bytes) in enumerate(expected_files):
        row_label = f"{label}.files[{index}]"
        row = obj(files[index], row_label)
        exact_keys(row, {"id", "metadata"}, row_label)
        require(row["id"] == expected_id, f"{label}: ACME file row order or identity mismatch")
        metadata = validate_file_metadata(row["metadata"], f"{row_label}.metadata", expected_path, operator, private=private, maximum_bytes=maximum_bytes)
        require(metadata["purpose"] == expected_purpose and metadata["sourceGeneration"] == source_generation and metadata["observedAt"] == payload["observedAt"], f"{label}: ACME file purpose,generation,or observation mismatch")
        if expected_purpose == "TLS_CERTIFICATE":
            require(metadata["owner"] == "acme" and metadata["group"] == "nginx", f"{label}: TLS certificate owner/group mismatch")
        elif expected_purpose == "TLS_PRIVATE_KEY":
            group_reader = metadata["group"] == "nginx" and metadata["effectiveReaders"] == ["group:nginx", "user:acme"]
            named_reader = metadata["effectiveReaders"] == ["user:acme", "user:nginx"]
            require(metadata["owner"] == "acme" and (group_reader or named_reader), f"{label}: TLS private key readers must be exactly acme and nginx")
        else:
            require(metadata["path"].startswith("/var/lib/acme/") and metadata["owner"] in {"acme", "root"} and metadata["effectiveReaders"] == [f"user:{metadata['owner']}"], f"{label}: ACME account key must be owner-only under /var/lib/acme")
        file_paths.append(metadata["path"])
        metadata_by_id[expected_id] = metadata
    require(len(file_paths) == len(set(file_paths)), f"{label}: ACME certificate,key,and account-key paths must be globally distinct")
    pat = obj(payload["patProcedures"], f"{label}.patProcedures")
    exact_keys(pat, set(PAT_PROCEDURE_OPERATIONS), f"{label}.patProcedures")
    pat_subject = {"type": "PROVIDER_CREDENTIAL", "providerIdentity": payload["providerIdentity"], "credential": active_handle}
    procedures = [validate_procedure(pat[key], f"{label}.patProcedures.{key}", PAT_PROCEDURE_OPERATIONS[key], pat_subject, operator, returned_at, verification_time) for key in PAT_PROCEDURE_OPERATIONS]
    expected_subjects = [*ACME_NAMES, "ACME_ACCOUNT_KEY"]
    lifecycles = arr(payload["lifecycles"], f"{label}.lifecycles")
    require(len(lifecycles) == len(expected_subjects), f"{label}: exact certificate/account lifecycle coverage required")
    for index, subject in enumerate(expected_subjects):
        row_label = f"{label}.lifecycles[{index}]"
        row = obj(lifecycles[index], row_label)
        exact_keys(row, {"subject", "rotationOverlapSeconds", *KEY_LIFECYCLE_OPERATIONS}, row_label)
        require(row["subject"] == subject, f"{label}: lifecycle subject order or coverage mismatch")
        bounded_integer(row["rotationOverlapSeconds"], f"{row_label}.rotationOverlapSeconds", 1, 2_592_000)
        if subject == "ACME_ACCOUNT_KEY":
            procedure_subject = {"type": "ACME_ACCOUNT_KEY", "providerIdentity": payload["providerIdentity"], "path": metadata_by_id["acme-account-key"]["path"]}
        else:
            procedure_subject = {"type": "ACME_CERTIFICATE_KEY_PAIR", "name": subject, "certificatePath": metadata_by_id[f"{subject}-certificate"]["path"], "privateKeyPath": metadata_by_id[f"{subject}-private-key"]["path"]}
        procedures.extend(validate_procedure(row[key], f"{row_label}.{key}", KEY_LIFECYCLE_OPERATIONS[key], procedure_subject, operator, returned_at, verification_time) for key in KEY_LIFECYCLE_OPERATIONS)
    procedure_ids = [procedure["procedureId"] for procedure in procedures]
    require(len(procedure_ids) == len(set(procedure_ids)), f"{label}: lifecycle procedure IDs must be globally distinct")
    test_event_ids = [procedure["test"]["eventId"] for procedure in procedures]
    require(len(test_event_ids) == len(set(test_event_ids)), f"{label}: lifecycle procedure test-event IDs must be globally distinct")
    require(set(procedure_ids).isdisjoint(test_event_ids), f"{label}: lifecycle procedure and test-event IDs must be globally distinct")
    secret = obj(payload["secretMaterial"], f"{label}.secretMaterial")
    exact_keys(secret, {"privateKeyValueRead", "privateKeyDigestRecorded"}, f"{label}.secretMaterial")
    require(strict_bool(secret["privateKeyValueRead"], f"{label}.secretMaterial.privateKeyValueRead") is False and strict_bool(secret["privateKeyDigestRecorded"], f"{label}.secretMaterial.privateKeyDigestRecorded") is False, f"{label}: private-key material or digest must not be returned")
    return payload


def validate_b01_payloads(results: list[dict[str, Any]], verification_time: datetime) -> None:
    require(len(results) == 1, "D0-B01: exact single-handoff contribution required")
    operator, returned_at = operator_return_context(results[0], "D0-B01")
    payloads = results[0]["_semanticPayloads"]
    containment = validate_b01_containment(payloads["credential-containment"], "D0-B01 credential-containment", operator, returned_at, verification_time)
    lifecycle = validate_b01_lifecycle(payloads["credential-lifecycle"], "D0-B01 credential-lifecycle", operator, returned_at, verification_time)
    require(containment["rotationId"] == lifecycle["rotationId"], "D0-B01: containment and lifecycle rotation IDs disagree")
    require(containment["provider"]["identity"] == lifecycle["providerIdentity"], "D0-B01: containment and lifecycle ACME provider identities disagree")
    require(containment["provider"]["activeCredential"] == lifecycle["activeCredential"], "D0-B01: containment and lifecycle active credential handles disagree")
    require(containment["credential"]["sourceGeneration"] == lifecycle["sourceGeneration"], "D0-B01: containment and lifecycle source generations disagree")
    require(containment["credential"]["observedAt"] == lifecycle["observedAt"], "D0-B01: containment and lifecycle observation times disagree")
    containment_event_ids = {event["eventId"] for event in containment["events"].values()} | {row["auditId"] for row in containment["audit"]}
    lifecycle_test_event_ids = {procedure["test"]["eventId"] for procedure in lifecycle["patProcedures"].values()} | {procedure["test"]["eventId"] for row in lifecycle["lifecycles"] for key, procedure in row.items() if key in KEY_LIFECYCLE_OPERATIONS}
    require(containment_event_ids.isdisjoint(lifecycle_test_event_ids), "D0-B01: containment and lifecycle test-event IDs must be globally distinct")
    identity_rows = [
        (containment["rotationId"], "D0-B01 credential-containment.rotationId joined to credential-lifecycle.rotationId"),
        *[(event["eventId"], f"D0-B01 credential-containment.events.{name}.eventId") for name, event in containment["events"].items()],
        (containment["installation"]["bindingId"], "D0-B01 credential-containment.installation.bindingId"),
        (containment["installation"]["dns01Operation"]["operationId"], "D0-B01 credential-containment.installation.dns01Operation.operationId"),
        *[(row["auditId"], f"D0-B01 credential-containment.audit[{index}].auditId") for index, row in enumerate(containment["audit"])],
    ]
    for name, procedure in lifecycle["patProcedures"].items():
        identity_rows.extend(procedure_identity_rows(procedure, f"D0-B01 credential-lifecycle.patProcedures.{name}"))
    for index, row in enumerate(lifecycle["lifecycles"]):
        for name in KEY_LIFECYCLE_OPERATIONS:
            identity_rows.extend(procedure_identity_rows(row[name], f"D0-B01 credential-lifecycle.lifecycles[{index}].{name}"))
    require_globally_distinct_identifiers(identity_rows, "D0-B01 security-relevant identifiers")


def validate_b02_attestation(payload: dict[str, Any], label: str, operator: str, returned_at: datetime, verification_time: datetime) -> dict[str, Any]:
    exact_keys(payload, {"hostname", "port", "algorithm", "fingerprint", "authoritativeSource", "endpointObservation", "attestation", "secretMaterial"}, label)
    require(payload["hostname"] == RAIN_SSH_HOST and tcp_port(payload["port"], f"{label}.port") == 22, f"{label}: Rain SSH endpoint mismatch")
    require(payload["algorithm"] == "ssh-ed25519" and ssh_sha256_fingerprint(payload["fingerprint"], f"{label}.fingerprint") == RAIN_SSH_FINGERPRINT, f"{label}: pinned Rain SSH identity mismatch")
    source = obj(payload["authoritativeSource"], f"{label}.authoritativeSource")
    exact_keys(source, {"type", "sourceId", "method", "operator", "observedAt", "recordKind", "hostname", "algorithm", "fingerprint", "observedSshConnectionUsed"}, f"{label}.authoritativeSource")
    methods = {"PROVIDER_SERIAL_CONSOLE": "READ_PUBLIC_HOST_KEY_VIA_PROVIDER_SERIAL_CONSOLE", "PHYSICAL_CONSOLE": "READ_PUBLIC_HOST_KEY_VIA_PHYSICAL_CONSOLE"}
    require(source["type"] in methods and source["method"] == methods[source["type"]], f"{label}: unsupported or mismatched out-of-band authority method")
    source_id = security_identifier(source["sourceId"], f"{label}.authoritativeSource.sourceId")
    require(source["operator"] == operator, f"{label}: authoritative-source operator does not match operator return")
    source_time = parse_utc(source["observedAt"], f"{label}.authoritativeSource.observedAt")
    require_fresh(source_time, returned_at, verification_time, f"{label} authoritative source")
    require(source["recordKind"] == "PUBLIC_SSH_HOST_KEY_FINGERPRINT" and source["hostname"] == RAIN_SSH_HOST and source["algorithm"] == "ssh-ed25519" and ssh_sha256_fingerprint(source["fingerprint"], f"{label}.authoritativeSource.fingerprint") == RAIN_SSH_FINGERPRINT, f"{label}: authoritative source record does not bind the pinned public host key")
    require(strict_bool(source["observedSshConnectionUsed"], f"{label}.authoritativeSource.observedSshConnectionUsed") is False, f"{label}: authoritative source depends on the observed SSH connection")
    endpoint = obj(payload["endpointObservation"], f"{label}.endpointObservation")
    exact_keys(endpoint, {"observationId", "hostname", "port", "algorithm", "fingerprint", "observedAt", "method", "tool", "result"}, f"{label}.endpointObservation")
    endpoint_id = security_identifier(endpoint["observationId"], f"{label}.endpointObservation.observationId")
    require(endpoint["hostname"] == RAIN_SSH_HOST and tcp_port(endpoint["port"], f"{label}.endpointObservation.port") == 22, f"{label}: independently observed SSH endpoint mismatch")
    require(endpoint["algorithm"] == "ssh-ed25519" and ssh_sha256_fingerprint(endpoint["fingerprint"], f"{label}.endpointObservation.fingerprint") == RAIN_SSH_FINGERPRINT, f"{label}: independently observed endpoint does not match the pinned public host key")
    require(endpoint["method"] == "PUBLIC_SSH_HOST_KEY_SCAN" and endpoint["result"] == "PASS", f"{label}: endpoint observation method or result mismatch")
    tool = obj(endpoint["tool"], f"{label}.endpointObservation.tool")
    exact_keys(tool, {"name", "version", "networkPath"}, f"{label}.endpointObservation.tool")
    require(tool["name"] == "ssh-keyscan" and tool["networkPath"] == "PUBLIC_NETWORK_ENDPOINT", f"{label}: endpoint observation lacks public ssh-keyscan tool metadata")
    security_text(tool["version"], f"{label}.endpointObservation.tool.version", 128)
    endpoint_time = parse_utc(endpoint["observedAt"], f"{label}.endpointObservation.observedAt")
    require_fresh(endpoint_time, returned_at, verification_time, f"{label} endpoint observation")
    attestation = obj(payload["attestation"], f"{label}.attestation")
    exact_keys(attestation, {"eventId", "operator", "verifiedAt", "match"}, f"{label}.attestation")
    attestation_id = security_identifier(attestation["eventId"], f"{label}.attestation.eventId")
    require(attestation["operator"] == operator, f"{label}: attestation operator does not match operator return")
    verified_at = parse_utc(attestation["verifiedAt"], f"{label}.attestation.verifiedAt")
    require(max(source_time, endpoint_time) <= verified_at, f"{label}: authority or endpoint was observed after attestation")
    require_fresh(verified_at, returned_at, verification_time, f"{label} attestation")
    require(strict_bool(attestation["match"], f"{label}.attestation.match") is True, f"{label}: operator attestation did not match")
    require(len({source_id, endpoint_id, attestation_id}) == 3, f"{label}: authority,endpoint,and attestation IDs must be distinct")
    secret = obj(payload["secretMaterial"], f"{label}.secretMaterial")
    exact_keys(secret, {"privateKeyValueRead", "privateKeyDigestRecorded"}, f"{label}.secretMaterial")
    require(strict_bool(secret["privateKeyValueRead"], f"{label}.secretMaterial.privateKeyValueRead") is False and strict_bool(secret["privateKeyDigestRecorded"], f"{label}.secretMaterial.privateKeyDigestRecorded") is False, f"{label}: private host-key material or digest must not be returned")
    return payload


def validate_b02_lifecycle(payload: dict[str, Any], label: str, operator: str, returned_at: datetime, verification_time: datetime) -> dict[str, Any]:
    exact_keys(payload, {"hostname", "algorithm", "currentFingerprint", "rotationOverlapSeconds", *SSH_LIFECYCLE_OPERATIONS}, label)
    require(payload["hostname"] == RAIN_SSH_HOST and payload["algorithm"] == "ssh-ed25519" and ssh_sha256_fingerprint(payload["currentFingerprint"], f"{label}.currentFingerprint") == RAIN_SSH_FINGERPRINT, f"{label}: pinned Rain SSH lifecycle identity mismatch")
    bounded_integer(payload["rotationOverlapSeconds"], f"{label}.rotationOverlapSeconds", 1, 2_592_000)
    procedure_subject = {"type": "SSH_HOST_IDENTITY", "hostname": payload["hostname"], "algorithm": payload["algorithm"], "fingerprint": payload["currentFingerprint"]}
    procedures = [validate_procedure(payload[key], f"{label}.{key}", SSH_LIFECYCLE_OPERATIONS[key], procedure_subject, operator, returned_at, verification_time) for key in SSH_LIFECYCLE_OPERATIONS]
    procedure_ids = [procedure["procedureId"] for procedure in procedures]
    require(len(procedure_ids) == len(set(procedure_ids)), f"{label}: SSH lifecycle procedure IDs must be distinct")
    test_event_ids = [procedure["test"]["eventId"] for procedure in procedures]
    require(len(test_event_ids) == len(set(test_event_ids)), f"{label}: SSH lifecycle procedure test-event IDs must be distinct")
    require(set(procedure_ids).isdisjoint(test_event_ids), f"{label}: SSH lifecycle procedure and test-event IDs must be distinct")
    return payload


def validate_b02_payloads(results: list[dict[str, Any]], verification_time: datetime) -> None:
    require(len(results) == 1, "D0-B02: exact single-handoff contribution required")
    operator, returned_at = operator_return_context(results[0], "D0-B02")
    payloads = results[0]["_semanticPayloads"]
    attestation = validate_b02_attestation(payloads["ssh-attestation"], "D0-B02 ssh-attestation", operator, returned_at, verification_time)
    lifecycle = validate_b02_lifecycle(payloads["ssh-lifecycle"], "D0-B02 ssh-lifecycle", operator, returned_at, verification_time)
    require(attestation["hostname"] == lifecycle["hostname"] and attestation["algorithm"] == lifecycle["algorithm"] and attestation["fingerprint"] == lifecycle["currentFingerprint"], "D0-B02: attestation and lifecycle identities disagree")
    lifecycle_event_ids = {lifecycle[key]["test"]["eventId"] for key in SSH_LIFECYCLE_OPERATIONS}
    require(attestation["attestation"]["eventId"] not in lifecycle_event_ids, "D0-B02: attestation and lifecycle test-event IDs must be distinct")
    require(attestation["authoritativeSource"]["sourceId"] != attestation["attestation"]["eventId"], "D0-B02: authoritative-source and attestation IDs must be distinct")
    identity_rows = [
        (attestation["authoritativeSource"]["sourceId"], "D0-B02 ssh-attestation.authoritativeSource.sourceId"),
        (attestation["endpointObservation"]["observationId"], "D0-B02 ssh-attestation.endpointObservation.observationId"),
        (attestation["attestation"]["eventId"], "D0-B02 ssh-attestation.attestation.eventId"),
    ]
    for name in SSH_LIFECYCLE_OPERATIONS:
        identity_rows.extend(procedure_identity_rows(lifecycle[name], f"D0-B02 ssh-lifecycle.{name}"))
    require_globally_distinct_identifiers(identity_rows, "D0-B02 security-relevant identifiers")


def exact_json_value(value: Any, expected: Any, label: str) -> None:
    require(type(value) is type(expected), f"{label}: expected JSON type {type(expected).__name__}")
    if isinstance(expected, dict):
        actual_object = obj(value, label)
        exact_keys(actual_object, set(expected), label)
        for key, expected_value in expected.items():
            exact_json_value(actual_object[key], expected_value, f"{label}.{key}")
    elif isinstance(expected, list):
        actual_array = arr(value, label)
        require(len(actual_array) == len(expected), f"{label}: expected exactly {len(expected)} entries")
        for index, expected_value in enumerate(expected):
            exact_json_value(actual_array[index], expected_value, f"{label}[{index}]")
    else:
        require(value == expected, f"{label}: frozen value mismatch")


def github_project_exact_provider_value(raw: Any, expected: Any, label: str) -> Any:
    require(type(raw) is type(expected), f"{label}: provider field has wrong JSON type")
    if isinstance(expected, dict):
        raw_object = obj(raw, label)
        missing = set(expected) - set(raw_object)
        require(not missing, f"{label}: provider response is missing projected fields {sorted(missing)}")
        return {key: github_project_exact_provider_value(raw_object[key], expected_value, f"{label}.{key}") for key, expected_value in expected.items()}
    if isinstance(expected, list):
        raw_array = arr(raw, label)
        require(len(raw_array) == len(expected), f"{label}: provider projected array length mismatch")
        return [github_project_exact_provider_value(raw_value, expected_value, f"{label}[{index}]") for index, (raw_value, expected_value) in enumerate(zip(raw_array, expected))]
    require(raw == expected, f"{label}: provider projected value mismatch")
    return raw


def github_project_exact_provider_set(raw: Any, expected: Any, label: str) -> list[Any]:
    raw_array = arr(raw, label)
    expected_array = arr(expected, f"{label} expected")
    require(len(raw_array) == len(expected_array), f"{label}: provider projected set length mismatch")
    expected_keys = [canonical_json(value) for value in expected_array]
    require(len(expected_keys) == len(set(expected_keys)), f"{label}: expected provider set contains duplicate projected entries")
    projected: list[Any] = []
    projected_keys: set[bytes] = set()
    for raw_index, raw_value in enumerate(raw_array):
        matches: list[Any] = []
        for expected_index, expected_value in enumerate(expected_array):
            try:
                matches.append(github_project_exact_provider_value(raw_value, expected_value, f"{label}[{raw_index}]~expected[{expected_index}]"))
            except GateVerificationError:
                pass
        require(len(matches) == 1, f"{label}[{raw_index}]: provider set entry must match exactly one expected projection")
        key = canonical_json(matches[0])
        require(key not in projected_keys, f"{label}: provider set contains duplicate projected entries")
        projected_keys.add(key)
        projected.append(matches[0])
    require(projected_keys == set(expected_keys), f"{label}: provider projected set differs from expected set")
    return sorted(projected, key=canonical_json)


def github_login(value: Any, label: str) -> str:
    login = nonempty(value, label)
    require(GITHUB_LOGIN_RE.fullmatch(login) is not None, f"{label}: expected canonical lower-case GitHub login")
    return login


def github_provider_projection_digest(kind: str, value: Any) -> str:
    raw = GITHUB_PROVIDER_PROJECTION_DOMAIN.encode("ascii") + b"\0" + kind.encode("ascii") + b"\0" + canonical_json(value)
    return sha256(raw)



def github_admitted_status_semantics(status: int) -> dict[str, Any]:
    if status == 404:
        return {
            "status": 404,
            "outcome": "TYPED_ABSENCE_ONLY",
            "typedProjection": {"presence": "ABSENT"},
            "presentResourceProjectionAllowed": False,
            "providerIdBindingAllowed": False,
            "restoreRequestReconstructionAllowed": False,
            "responseBodyRestorationInputAllowed": False,
        }
    return {"status": status, "outcome": "PINNED_OPENAPI_OPERATION_SPECIFIC"}


def github_mutation_response_identity(operation_id: str, admitted_statuses: list[int], secret_response: bool) -> tuple[dict[str, Any], str, str]:
    provider_id_bindings = {
        "create-d0-b04-ssh-signing-key-if-baseline-absent": ("signerProviderSshSigningKeyId", "CREATE_RESPONSE_AND_IMMEDIATE_AUTHENTICATED_AND_PUBLIC_READBACK"),
        "put-release-environment": ("environmentId", "PUT_RESPONSE_AND_IMMEDIATE_GET_READBACK"),
        "create-environment-main-policy": ("environmentBranchPolicyId", "CREATE_RESPONSE_AND_IMMEDIATE_LIST_READBACK"),
        "create-admission-ruleset-bootstrap": ("admissionRulesetId", "CREATE_RESPONSE_AND_IMMEDIATE_GET_READBACK"),
        "update-admission-ruleset-to-final": ("admissionRulesetId", "UPDATE_RESPONSE_AND_IMMEDIATE_GET_READBACK_OF_SAME_BOUND_ID"),
        "create-invariant-ruleset": ("invariantRulesetId", "CREATE_RESPONSE_AND_IMMEDIATE_GET_READBACK"),
        "review-release-pending-deployment": ("releaseDeploymentId", "EXACT_MUTATION_RESPONSE_MEMBER_AND_IMMEDIATE_DEPLOYMENT_READBACK"),
    }
    provider_id_binding, provider_id_source = provider_id_bindings.get(operation_id, ("NOT_APPLICABLE_NO_NEW_PROVIDER_RESOURCE_ID", "NOT_APPLICABLE_NO_NEW_PROVIDER_RESOURCE"))
    if secret_response:
        response_identity = {
            "mode": "SECRET_TOKEN_RESPONSE_EXCLUDED_FROM_CAPTURE_AND_IDENTITY",
            "responseResourceIdentityClaimed": False,
            "responseBodyEntersIdentityPipeline": False,
            "secretResponseBodyCaptureOrHashAllowed": False,
            "ephemeralSafeMetadataMayValidateScopeAndExpiry": True,
        }
    elif operation_id == "review-release-pending-deployment":
        response_identity = {
            "mode": "ID_BEARING_RESPONSE_SET_AND_IMMEDIATE_READBACK",
            "responseResourceIdentityClaimed": True,
            "responseBodyEntersIdentityPipeline": True,
            "boundProviderId": provider_id_binding,
            "responseIdJsonPointer": "/EXACT_WORKFLOW_RUN_ENVIRONMENT_REF_AND_CANDIDATE_MATCH/id",
            "responseMemberSelection": "EXACTLY_ONE_DEPLOYMENT_MATCHING_RELEASE_WORKFLOW_RUN_ENVIRONMENT_REF_AND_CANDIDATE",
            "immediateReadbackMustRevalidateBoundId": True,
        }
    elif operation_id in {"patch-main-ref-bootstrap-force-false", "patch-main-ref-release-force-false"}:
        expected_oid_binding = "bootstrapCommitB" if operation_id == "patch-main-ref-bootstrap-force-false" else "signedReleaseCommitCPrime"
        response_identity = {
            "mode": "REF_RESPONSE_AND_IMMEDIATE_REF_COMMIT_READBACK",
            "responseResourceIdentityClaimed": True,
            "responseBodyEntersIdentityPipeline": True,
            "expectedOidBinding": expected_oid_binding,
            "responseRefAndOidMustMatchExactRequest": True,
            "immediateRefAndCommitReadbackRequired": True,
        }
    elif operation_id in provider_id_bindings:
        response_identity = {
            "mode": "ID_BEARING_RESPONSE_AND_IMMEDIATE_READBACK",
            "responseResourceIdentityClaimed": True,
            "responseBodyEntersIdentityPipeline": True,
            "boundProviderId": provider_id_binding,
            "responseIdJsonPointer": "/id",
            "authoritativeProviderIdSource": provider_id_source,
            "immediateReadbackMustRevalidateBoundId": True,
        }
    elif admitted_statuses == [204]:
        response_identity = {
            "mode": "BODYLESS_SUCCESS_SELECTOR_AND_IMMEDIATE_READBACK",
            "responseResourceIdentityClaimed": False,
            "responseBodyEntersIdentityPipeline": False,
            "selectorAndRequestBodyDefineMutationTarget": True,
        }
    elif 204 in admitted_statuses:
        response_identity = {
            "mode": "BODYLESS_SUCCESS_OR_TYPED_NONRESOURCE_RESULT_AND_IMMEDIATE_READBACK",
            "responseResourceIdentityClaimed": False,
            "responseBodyEntersIdentityPipeline": False,
            "selectorAndRequestBodyDefineMutationTarget": True,
            "non204StatusesCannotProduceResourceIdentity": True,
        }
    else:
        response_identity = {
            "mode": "RESOURCE_RESPONSE_AND_IMMEDIATE_READBACK",
            "responseResourceIdentityClaimed": True,
            "responseBodyEntersIdentityPipeline": True,
            "resourceIdentity": "EXACT_SELECTOR_AND_PINNED_OPENAPI_RESPONSE",
        }
    return response_identity, provider_id_binding, provider_id_source


def github_state_machine_operation_references(state_machine: dict[str, Any]) -> set[str]:
    references = {operation_id for transition in state_machine["transitions"] for operation_id in transition["operations"]}
    rollback = state_machine["rollback"]
    for section_name in ("beforeMainAdvance", "afterMainAdvance"):
        for step in rollback[section_name]:
            references.update(step["operationIds"])
            for group in step["conditionalOperationGroups"]:
                references.update(group["operationIds"])
    references.update(rollback["unknownRefIncident"]["immediateOperationIds"])
    for group in rollback["unknownRefIncident"]["conditionalOperationGroups"]:
        references.update(group["operationIds"])
    return references


def validate_github_operation_graph(catalog_id: str, rest_operations: list[dict[str, Any]], state_machine: dict[str, Any]) -> None:
    operation_ids = [operation["operationId"] for operation in rest_operations]
    require(len(operation_ids) == len(set(operation_ids)), f"{catalog_id}: REST operation IDs must be unique")
    mutation_ids = {
        operation["operationId"]
        for operation in rest_operations
        if operation["request"]["method"] in {"POST", "PUT", "PATCH", "DELETE"}
    }
    references = github_state_machine_operation_references(state_machine)
    unreferenced = mutation_ids - references
    require(not unreferenced, f"{catalog_id}: unreferenced REST mutations: {sorted(unreferenced)}")
    if catalog_id == "js":
        forbidden = {"delete-classic-branch-protection-if-baseline-present", "restore-classic-branch-protection-from-pre-capture"} & mutation_ids
        require(not forbidden, f"{catalog_id}: baseline-absent classic-protection mutations are forbidden: {sorted(forbidden)}")


def validate_github_pre_mutation_capture_contract(catalog_id: str, capture: dict[str, Any], rest_operations: list[dict[str, Any]]) -> None:
    operation_by_id = {operation["operationId"]: operation for operation in rest_operations}
    require(len(operation_by_id) == len(rest_operations), f"{catalog_id}: pre-mutation capture cannot resolve duplicate REST operation IDs")
    unconditional = arr(capture["unconditionalCaptureOperationIds"], f"{catalog_id}.preMutationCaptureContract.unconditionalCaptureOperationIds")
    all_capture = arr(capture["allCaptureOperationIds"], f"{catalog_id}.preMutationCaptureContract.allCaptureOperationIds")
    allowed_profiles = arr(capture["preConfigurationAllowedAuthProfiles"], f"{catalog_id}.preMutationCaptureContract.preConfigurationAllowedAuthProfiles")
    require(len(unconditional) == len(set(unconditional)), f"{catalog_id}: unconditional pre-mutation capture operations must be unique")
    require(len(all_capture) == len(set(all_capture)), f"{catalog_id}: all pre-mutation capture operations must be unique")
    require(len(allowed_profiles) == len(set(allowed_profiles)), f"{catalog_id}: pre-configuration auth profiles must be unique")
    conditional_ids: list[str] = []
    for index, raw_branch in enumerate(arr(capture["conditionalCapture"], f"{catalog_id}.preMutationCaptureContract.conditionalCapture")):
        branch = obj(raw_branch, f"{catalog_id}.preMutationCaptureContract.conditionalCapture[{index}]")
        selector_id = nonempty(branch["selectorOperationId"], f"{catalog_id}.preMutationCaptureContract.conditionalCapture[{index}].selectorOperationId")
        require(selector_id in unconditional, f"{catalog_id}: every conditional capture selector must be unconditional")
        required_ids = arr(branch["requiredOperationIds"], f"{catalog_id}.preMutationCaptureContract.conditionalCapture[{index}].requiredOperationIds")
        require(len(required_ids) == len(set(required_ids)), f"{catalog_id}: conditional pre-mutation capture operations must be unique within each branch")
        conditional_ids.extend(required_ids)
    overlap = set(unconditional) & set(conditional_ids)
    require(not overlap, f"{catalog_id}: capture operations cannot be both unconditional and conditional: {sorted(overlap)}")
    require(len(conditional_ids) == len(set(conditional_ids)), f"{catalog_id}: conditional pre-mutation capture branches cannot ambiguously require the same operation")
    expected_closure = [*unconditional, *conditional_ids]
    require(all_capture == expected_closure, f"{catalog_id}: allCaptureOperationIds must be the exact ordered unconditional and conditional union")
    for operation_id in all_capture:
        require(operation_id in operation_by_id, f"{catalog_id}: pre-mutation capture references unknown REST operation {operation_id}")
        operation = operation_by_id[operation_id]
        require(operation["request"]["method"] == "GET", f"{catalog_id}: pre-mutation capture operation {operation_id} must be read-only GET")
        require(operation["authProfile"] in allowed_profiles, f"{catalog_id}: pre-mutation capture operation {operation_id} requires unavailable pre-configuration auth profile {operation['authProfile']}")
    coverage_capture_ids = {
        operation_id
        for resource in arr(capture["mutableResourceCoverage"], f"{catalog_id}.preMutationCaptureContract.mutableResourceCoverage")
        for operation_id in arr(resource["captureOperationIds"], f"{catalog_id}.preMutationCaptureContract.mutableResourceCoverage.captureOperationIds")
    }
    require(coverage_capture_ids <= set(all_capture), f"{catalog_id}: mutable-resource coverage references reads outside the pre-mutation capture closure: {sorted(coverage_capture_ids - set(all_capture))}")


def github_binding(name: str, json_type: str = "POSITIVE_INT64") -> dict[str, str]:
    return {"$binding": name, "type": json_type}


def github_ruleset_request(name: str, rules: list[dict[str, Any]], bypass_actors: list[dict[str, Any]]) -> dict[str, Any]:
    return {"name": name, "target": "branch", "enforcement": "active", "bypass_actors": bypass_actors, "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}, "rules": rules}


def github_rest_operation(operation_id: str, phase: str, auth_profile: str, method: str, path_template: str, admitted_statuses: list[int], *, query_template: list[dict[str, Any]] | None = None, body_template: dict[str, Any] | None = None, pagination: bool = False, projection: str = "SUPPORTING_READBACK", secret_response: bool = False, follow_up_readbacks: list[str] | None = None, pre_capture_restore: dict[str, str] | None = None) -> dict[str, Any]:
    if body_template is None:
        body = {"kind": "NONE", "contentLength": 0, "sha256": EMPTY_SHA256}
    else:
        body = {"kind": "CANONICAL_JSON_BINDING_TEMPLATE", "template": body_template, "templateSha256": sha256(canonical_json(body_template)), "bindingSubstitution": "REPLACE_WHOLE_TYPED_BINDING_OBJECT_THEN_REVALIDATE_OPENAPI_SCHEMA", "transmittedEncoding": "UTF8_SORTED_KEYS_COMPACT_WITH_SINGLE_TRAILING_LF", "transmittedLength": "CAPTURE_AT_EXECUTION", "transmittedSha256": "CAPTURE_AT_EXECUTION"}
    pagination_policy = {"kind": "RFC8288_LINK", "perPage": 100, "firstPage": 1, "followOnlyRelNextFromSameOrigin": True, "bindPreviousResponseRequestIdAndRawSha256": True, "repeatPageOrItemIdRejected": True, "stopOnlyWhenRelNextAbsent": True, "missingOrMalformedLinkRejected": True, "allPagesRequired": True} if pagination else {"kind": "NONE", "linkHeaderMustBeAbsent": True}
    if secret_response:
        capture = {"mode": "SECRET_RESPONSE_BODY_NEVER_PERSISTED_OR_HASHED_FOR_ANY_STATUS", "allStatusBodyHandling": "CONSUME_EPHEMERALLY_INSIDE_TOKEN_CLIENT_ONLY_NEVER_ENTER_CAPTURE_PIPELINE", "bodyPersistenceAllowed": False, "bodyArtifactAllowed": False, "bodyLengthRecordingAllowed": False, "bodyHashingAllowed": False, "errorBodyPersistenceAllowed": False, "errorBodyArtifactAllowed": False, "errorBodyLengthRecordingAllowed": False, "errorBodyHashingAllowed": False, "forbiddenRawFields": ["token"], "allowedSuccessProjectionFields": ["expires_at", "permissions", "repository_selection", "repositories"], "successProjectionEphemeralUntilSecretFieldDiscarded": True, "safeEnvelopeFields": ["httpStatus", "responseStartedAtUtc", "responseCompletedAtUtc", "xGitHubRequestId", "xGitHubApiVersionSelected", "rateLimitLimit", "rateLimitRemaining", "rateLimitReset"], "safeEnvelopeClosedWorld": True, "safeEnvelopeBodyMetadataForbidden": True, "responseHeadersCaptured": True, "providerRequestIdRequired": True, "operatorAttestationCannotSubstitute": True}
        unexpected_status = "CAPTURE_ONLY_STATUS_SAFE_HEADERS_AND_REQUEST_ID_WITHOUT_BODY_LENGTH_DIGEST_OR_ARTIFACT_THEN_ABORT"
        projection_input = "HTTP_STATUS_SAFE_HEADERS_AND_EPHEMERAL_SECRET_SAFE_SUCCESS_METADATA"
    else:
        capture = {"mode": "RAW_BODY_AND_STRICT_PROJECTION", "rawBodyRequired": True, "rawBodyLengthRequired": True, "rawBodySha256Required": True, "projectionArtifactRequired": True, "projectionSha256Required": True, "providerRequestIdRequired": True, "operatorAttestationCannotSubstitute": True}
        unexpected_status = "CAPTURE_NONSECRET_ERROR_RESPONSE_THEN_ABORT"
        projection_input = "HTTP_STATUS_HEADERS_AND_RAW_BODY"
    follow_ups = [] if follow_up_readbacks is None else follow_up_readbacks
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        require(len(follow_ups) > 0, f"{operation_id}: every provider mutation requires an explicit immediate readback")
    operation = {"operationId": operation_id, "phase": phase, "authProfile": auth_profile, "request": {"method": method, "baseUrl": GITHUB_REST_BASE, "pathTemplate": path_template, "queryTemplate": [] if query_template is None else query_template, "headers": {"Accept": GITHUB_REST_ACCEPT, "X-GitHub-Api-Version": GITHUB_REST_API_VERSION, "User-Agent": "pkgre-d0-github-governance-contract-v1"}, "authorizationHeaderCapture": "FORBIDDEN", "redirectPolicy": "FORBIDDEN", "body": body}, "response": {"admittedStatuses": admitted_statuses, "admittedStatusSemantics": [github_admitted_status_semantics(status) for status in admitted_statuses], "unexpectedStatus": unexpected_status, "capture": capture, "pagination": pagination_policy, "projection": projection, "projectionInput": projection_input, "requiredFollowUpReadbackOperationIds": follow_ups, "followUpTiming": "IMMEDIATE_BEFORE_ANY_NEXT_MUTATION" if follow_ups else "NOT_APPLICABLE"}}
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        response_identity, provider_id_binding, provider_id_source = github_mutation_response_identity(operation_id, admitted_statuses, secret_response)
        before_sources = {
            "CONFIGURE": "FRESH_PRE_MUTATION_CAPTURE_AND_EXACT_SELECTOR_READBACK",
            "BOOTSTRAP": "FRESH_PRE_MUTATION_CAPTURE_CEREMONY_RESOURCE_LEDGER_AND_IMMEDIATE_EXACT_SELECTOR_READBACK",
            "NORMAL_RELEASE": "CURRENT_TRUSTED_RELEASE_BINDINGS_AND_IMMEDIATE_EXACT_SELECTOR_READBACK",
            "ROLLBACK": "FRESH_PRE_MUTATION_CAPTURE_CEREMONY_RESOURCE_LEDGER_AND_CURRENT_EXACT_SELECTOR_READBACK",
        }
        operation["mutationIdentity"] = {
            "resourceType": projection,
            "exactSelector": {"baseUrl": GITHUB_REST_BASE, "pathTemplate": path_template, "orderedQueryTemplate": [] if query_template is None else query_template, "requestBodyTemplateSha256": body.get("templateSha256", EMPTY_SHA256)},
            "beforeStateSource": before_sources.get(phase, "EXACT_DECLARED_STATE_AND_IMMEDIATE_SELECTOR_READBACK"),
            "providerAssignedIdBinding": provider_id_binding,
            "providerAssignedIdSource": provider_id_source,
            "responseIdentity": response_identity,
            "afterStateReadbackOperationIds": follow_ups,
            "responseAndReadbackIdentityMustMatch": response_identity["responseResourceIdentityClaimed"],
            "afterReadbackMustMatchExactSelector": True,
            "crossResourceSubstitutionRejected": True,
        }
    if pre_capture_restore is not None:
        require(phase == "ROLLBACK" and method in {"POST", "PUT", "PATCH", "DELETE"}, f"{operation_id}: pre-capture restore must be a rollback mutation")
        require(set(pre_capture_restore) == {"binding", "captureOperationId", "readbackOperationId"}, f"{operation_id}: invalid pre-capture restore declaration")
        require(pre_capture_restore["readbackOperationId"] in follow_ups, f"{operation_id}: pre-capture restore readback must be an immediate follow-up")
        operation["preCaptureRestore"] = {"rawFreshCaptureBinding": pre_capture_restore["binding"], "captureOperationId": pre_capture_restore["captureOperationId"], "typedRequestBodyReconstruction": "ALLOWLIST_PROVIDER_FIELDS_FROM_RAW_FRESH_CAPTURE_ONLY", "requestRevalidatedAgainstPinnedOpenApi": True, "immediateReadbackOperationId": pre_capture_restore["readbackOperationId"], "exactProjectedReadbackAndDigestMustEqualFreshCapture": True, "historicalD0BaselineMaySubstitute": False}
    return operation


def github_bootstrap_transition(catalog_id: str, repository: str, source_tip: str, source_ref: str, candidate_path: str, release_path: str, environment_name: str, invariant_name: str, admission_name: str, writer_slug: str, pre_mutation_capture_key: str, signing_key_evidence_key: str, bootstrap_evidence_key: str, normal_release_evidence_key: str) -> dict[str, Any]:
    states = [
        {"state": "S0_BASELINE_CAPTURED", "invariant": "FRESH_PROVIDER_CAPTURE_BINDS_EXACT_BASELINE_A_ALL_MUTABLE_SETTINGS_AND_SIGNING_KEY_BASELINE", "sourceRefExpected": source_tip},
        {"state": "S1_D0_B04_SIGNING_IDENTITY_AND_PROVIDER_KEY_READY", "invariant": "CATALOG_SPECIFIC_D0_B04_PUBLIC_TRUST_AND_EXACT_GITHUB_SSH_SIGNING_KEY_ARE_READ_BACK_WITHOUT_PRIVATE_KEY_CAPTURE", "sourceRefExpected": source_tip},
        {"state": "S2_ACTIONS_ENVIRONMENT_APP_READY", "invariant": "ACTIONS_POLICY_ENVIRONMENT_AND_REPOSITORY_SCOPED_WRITER_APP_READ_BACK", "sourceRefExpected": source_tip},
        {"state": "S3_BOOTSTRAP_B_SIGNED_AND_DUAL_VERIFIED", "invariant": "B_HAS_SOLE_PARENT_A_EXACT_REVIEWED_TREE_LOCAL_EXACT_KEY_VERIFICATION_AND_GITHUB_VERIFIED_VALID_READBACK", "sourceRefExpected": source_tip},
        {"state": "S4_INVARIANT_AND_BOOTSTRAP_ADMISSION_ACTIVE", "invariant": "BOOTSTRAP_ADMISSION_CLOSES_MAIN_TO_EXACT_APP_AND_NON_BYPASSABLE_INVARIANTS_ARE_EFFECTIVE", "sourceRefExpected": source_tip},
        {"state": "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE", "invariant": "CLASSIC_PROTECTION_ABSENT_ONLY_AFTER_REPLACEMENT_CONTROLS_ARE_ACTIVE_AND_EFFECTIVE", "sourceRefExpected": source_tip},
        {"state": "S6_BOOTSTRAP_TOKEN_MINTED", "invariant": "ONE_REPOSITORY_APP_TOKEN_EXISTS_ONLY_AFTER_BOOTSTRAP_ADMISSION_AND_INVARIANTS_ARE_EFFECTIVE", "sourceRefExpected": source_tip},
        {"state": "S7_MAIN_ADVANCED_A_TO_B_AND_BOOTSTRAP_TOKEN_REVOKED", "invariant": "EXACT_APP_FAST_FORWARDED_MAIN_A_TO_DUAL_VERIFIED_B_WITH_FORCE_FALSE_THEN_TOKEN_WAS_REVOKED", "sourceRefExpected": "BOOTSTRAP_COMMIT_B"},
        {"state": "S8_WORKFLOW_AND_CHECK_PRODUCER_READ_BACK", "invariant": "WORKFLOWS_ARE_READ_FROM_B_AND_CANDIDATE_CHECK_PRODUCER_IS_PROVIDER_BOUND", "sourceRefExpected": "BOOTSTRAP_COMMIT_B"},
        {"state": "S9_ADMISSION_RULESET_FINALIZED", "invariant": "SAME_ADMISSION_RULESET_ID_NOW_ENFORCES_UPDATE_PULL_REQUEST_AND_EXACT_STATUS_CHECK_WITH_SOLE_APP_BYPASS", "sourceRefExpected": "BOOTSTRAP_COMMIT_B"},
        {"state": "S10_FIRST_NORMAL_RELEASE_C_SUCCEEDED", "invariant": "TRUSTED_B_WORKFLOW_RELEASED_DUAL_VERIFIED_SIGNED_C_PRIME_FROM_REVIEWED_CANDIDATE_TREE_WITH_HUMAN_APPROVAL", "sourceRefExpected": "SIGNED_RELEASE_COMMIT_C_PRIME"},
        {"state": "S11_FINAL_CAPTURE_AND_AUDIT_COMPLETE", "invariant": "ALL_SETTINGS_EFFECTIVE_RULES_REF_SIGNATURE_SIGNING_KEY_AND_AUDIT_READBACKS_PASS", "sourceRefExpected": "SIGNED_RELEASE_COMMIT_C_PRIME"},
    ]
    def transition(source: str, target: str, preconditions: list[str], operations: list[str], postconditions: list[str], abort_conditions: list[str], evidence: list[str]) -> dict[str, Any]:
        return {"from": source, "to": target, "preconditions": preconditions, "operations": operations, "postconditions": postconditions, "abortConditions": abort_conditions, "auditEvidence": evidence}
    classic_pre_transition_readbacks = ["get-main-ref", "get-admission-ruleset", "get-invariant-ruleset", "list-effective-main-rules"]
    classic_transition_operations = ["delete-classic-branch-protection-if-baseline-present", "get-classic-branch-protection"] if catalog_id == "rust" else ["get-classic-branch-protection"]
    classic_post_transition_readbacks = ["get-admission-ruleset", "get-invariant-ruleset", "list-effective-main-rules", "get-main-ref"]
    classic_operations = classic_pre_transition_readbacks + classic_transition_operations + classic_post_transition_readbacks
    classic_handover = transition("S4_INVARIANT_AND_BOOTSTRAP_ADMISSION_ACTIVE", "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE", ["SOURCE_REF_EQUALS_A", "BOOTSTRAP_ADMISSION_AND_INVARIANTS_EFFECTIVE", "NO_UNGUARDED_MAIN_REF_WRITE_INTERVAL"], classic_operations, ["CLASSIC_PROTECTION_ABSENT", "SAME_ADMISSION_AND_INVARIANT_RULESET_IDS_REMAIN_ACTIVE", "ALL_REPLACEMENT_RULES_REMAIN_EFFECTIVE", "MAIN_REMAINS_A"], ["REPLACEMENT_RULE_LOST", "RULESET_ID_REPLACED", "SOURCE_REF_DRIFT"], ["CLASSIC_BRANCH_PROTECTION_FINAL_READBACK", "ADMISSION_RULESET_ID_AND_READBACK", "INVARIANT_RULESET_ID_AND_READBACK", "EFFECTIVE_MAIN_RULES_READBACK"])
    classic_handover["handoverSafety"] = {"preRemovalReadbackOperationIds": classic_pre_transition_readbacks, "transitionOperationIds": classic_transition_operations, "postRemovalReadbackOperationIds": classic_post_transition_readbacks, "beforeAndAfterReplacementControlReadbackRequired": True, "guardGapAllowed": False, "tokenMintAllowedDuringTransition": False, "refAdvanceAllowedDuringTransition": False, "failureDisposition": "ABORT_BEFORE_REMOVAL_OR_KEEP_REPLACEMENT_CONTROLS_ACTIVE_AND_ENTER_INCIDENT_FREEZE"}
    transitions = [
        transition("S0_BASELINE_CAPTURED", "S1_D0_B04_SIGNING_IDENTITY_AND_PROVIDER_KEY_READY", ["PRE_MUTATION_CAPTURE_FRESH_COMPLETE_AND_INCLUDES_SIGNING_KEY_SET", "D0_B04_OPERATOR_HANDOFF_AUTHORIZED_FOR_EXACT_CATALOG_SPECIFIC_PUBLIC_IDENTITY"], ["bind-d0-b04-catalog-signing-identity", "get-authenticated-signing-user", "list-authenticated-ssh-signing-keys", "list-public-ssh-signing-keys-for-d0-b04-user", "create-d0-b04-ssh-signing-key-if-baseline-absent", "get-d0-b04-ssh-signing-key", "list-public-ssh-signing-keys-for-d0-b04-user", "resolve-d0-b04-provider-signing-key-binding", "operator-install-public-trust-without-returning-private-material"], ["AUTHENTICATED_GITHUB_LOGIN_EQUALS_D0_B04_LOGIN", "PROVIDER_KEY_ID_TITLE_CREATED_AT_AND_EXACT_PUBLIC_KEY_BOUND", "PUBLIC_AND_AUTHENTICATED_KEY_READBACKS_IDENTICAL", "COMPUTED_SSH_SHA256_FINGERPRINT_EQUALS_D0_B04_FINGERPRINT", "CREATE_SKIPPED_IF_EXACT_KEY_PREEXISTED", "LOCAL_ALLOWED_SIGNERS_AND_REVOCATION_DIGESTS_MATCH_D0_B04"], ["MISSING_DUPLICATE_OR_WRONG_PROVIDER_KEY", "WRONG_GITHUB_LOGIN", "PUBLIC_KEY_OR_FINGERPRINT_MISMATCH", "PRIVATE_KEY_SECRET_BYTES_OR_DIGEST_ENTER_EVIDENCE", "SOURCE_REF_DRIFT"], [pre_mutation_capture_key, signing_key_evidence_key, "D0-B04"]),
        transition("S1_D0_B04_SIGNING_IDENTITY_AND_PROVIDER_KEY_READY", "S2_ACTIONS_ENVIRONMENT_APP_READY", ["SOURCE_REF_EQUALS_A", "EXACT_SIGNING_KEY_REMAINS_REGISTERED", "OPERATOR_ADMIN_AUTH_ACTIVE"], ["get-environment-reviewer-user", "get-environment-reviewer-permission", "get-release-dispatcher-user", "get-release-dispatcher-permission", "set-actions-permissions", "get-actions-permissions", "set-selected-actions", "get-selected-actions", "set-default-workflow-permissions", "get-default-workflow-permissions", "set-fork-pr-approval-policy", "get-fork-pr-approval-policy", "put-release-environment", "get-release-environment", "create-environment-main-policy", "list-environment-branch-policies", "operator-install-app-and-environment-secret", "get-release-app", "list-organization-app-installations", "get-release-app-installation", "list-user-installation-repositories", "capture-environment-admin-bypass-ui-readback", "capture-environment-secret-name-and-scope-ui-readback", "mint-release-installation-read-token", "list-installation-repositories", "revoke-release-installation-read-token", "prove-release-installation-read-token-revoked"], ["REVIEWER_EXACT_CONFIGURED_LOGIN_ID_AND_LEGACY_PERMISSION_READ_WRITE_OR_ADMIN", "DISPATCHER_EXACT_CONFIGURED_LOGIN_ID_AND_LEGACY_PERMISSION_WRITE_OR_ADMIN", "REVIEWER_AND_DISPATCHER_PROVIDER_IDS_DIFFER", "ACTIONS_EXACT_READBACK", "ENVIRONMENT_EXACT_REST_PROJECTION", "ADMIN_BYPASS_DISABLED_UI_READBACK", "APP_INTEGRATION_INSTALLATION_AND_REPOSITORY_IDS_DISTINCT_AND_BOUND", "READ_TOKEN_METADATA_ONLY_AND_EXACTLY_ONE_REPOSITORY"], ["ANY_ACTOR_LOOKUP_PERMISSION_OR_READBACK_MISMATCH", "APP_SCOPE_BROADER_THAN_ONE_REPOSITORY", "SIGNING_KEY_REMOVED_OR_CHANGED", "SOURCE_REF_DRIFT"], ["ACTIONS_POLICY_READBACK", "PROTECTED_ENVIRONMENT_ID_AND_READBACK", "RELEASE_APP_INSTALLATION_ID_AND_READBACK", "PROVIDER_UI_ENVIRONMENT_ADMIN_BYPASS"]),
        transition("S2_ACTIONS_ENVIRONMENT_APP_READY", "S3_BOOTSTRAP_B_SIGNED_AND_DUAL_VERIFIED", ["SOURCE_REF_EQUALS_A", "EXACT_BOOTSTRAP_TREE_FROZEN_BEFORE_SIGNING", "EXACT_SIGNING_KEY_REGISTERED_AND_LOCALLY_TRUSTED"], ["operator-create-ssh-ed25519-signed-bootstrap-b", "local-git-verify-commit-raw-bootstrap-b", "git-smart-protocol-upload-bootstrap-b-to-temporary-ref", "get-bootstrap-commit", "get-main-ref", "get-d0-b04-ssh-signing-key", "list-public-ssh-signing-keys-for-d0-b04-user"], ["B_SOLE_PARENT_EQUALS_A", "B_TREE_EQUALS_FROZEN_BOOTSTRAP_TREE", "TEMPORARY_REF_EQUALS_B", "LOCAL_GIT_VERIFY_COMMIT_PASS_WITH_EXACT_D0_B04_KEY_AND_PRINCIPAL", "GITHUB_COMMIT_VERIFICATION_VERIFIED_TRUE_REASON_VALID_AND_VERIFIED_AT_NON_NULL", "COMMIT_AND_KEY_EVIDENCE_BIND_EXACT_D0_B04_LOGIN_PUBLIC_KEY_FINGERPRINT_AND_PROVIDER_KEY_ID", "NO_CANDIDATE_WORKFLOW_EXECUTED"], ["B_PARENT_NOT_A", "TREE_OR_WORKFLOW_DIGEST_MISMATCH", "LOCAL_SIGNATURE_VERIFICATION_FAIL", "GITHUB_SIGNATURE_UNVERIFIED_WRONG_REASON_OR_MISSING_VERIFIED_AT", "SIGNING_KEY_REMOVED_OR_CHANGED", "CANDIDATE_CONTROLLED_WORKFLOW_EXECUTED", "SOURCE_REF_DRIFT"], [bootstrap_evidence_key, signing_key_evidence_key]),
        transition("S3_BOOTSTRAP_B_SIGNED_AND_DUAL_VERIFIED", "S4_INVARIANT_AND_BOOTSTRAP_ADMISSION_ACTIVE", ["SOURCE_REF_EQUALS_A", "B_REMAINS_DUAL_VERIFIED", "RELEASE_APP_INTEGRATION_AND_INSTALLATION_EXACTLY_BOUND"], ["create-admission-ruleset-bootstrap", "get-admission-ruleset", "create-invariant-ruleset", "get-invariant-ruleset", "list-effective-main-rules", "get-main-ref"], ["ADMISSION_RULESET_BOOTSTRAP_FORM_ACTIVE_WITH_EXACT_UPDATE_RULE_AND_SOLE_APP_BYPASS", "INVARIANT_RULESET_EXACT_ACTIVE_READBACK", "EFFECTIVE_RULES_INCLUDE_BOOTSTRAP_ADMISSION_SIGNATURE_LINEAR_HISTORY_DELETION_AND_NON_FAST_FORWARD", "MAIN_REMAINS_A", "NO_USER_TEAM_REPOSITORY_ROLE_ADMIN_OR_OTHER_INTEGRATION_BYPASS"], ["RULESET_ID_AMBIGUOUS", "EFFECTIVE_RULE_MISSING", "ADMISSION_AUTHORITY_BROADENED", "MAIN_REF_CHANGED_DURING_CONTROL_INSTALLATION"], ["ADMISSION_RULESET_ID_AND_READBACK", "INVARIANT_RULESET_ID_AND_READBACK", "EFFECTIVE_MAIN_RULES_READBACK"]),
        classic_handover,
        transition("S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE", "S6_BOOTSTRAP_TOKEN_MINTED", ["SOURCE_REF_EQUALS_A", "BOOTSTRAP_ADMISSION_AND_INVARIANTS_EFFECTIVE", "CLASSIC_PROTECTION_ABSENT"], ["mint-bootstrap-installation-token", "list-bootstrap-token-repositories"], ["BOOTSTRAP_TOKEN_EXACTLY_ONE_REPOSITORY_CONTENTS_WRITE_METADATA_READ_AND_TTL_AT_MOST_3600_SECONDS", "TOKEN_RESPONSE_BODY_AUTHORIZATION_AND_TOKEN_DIGEST_NEVER_PERSISTED", "TOKEN_MINT_OCCURRED_ONLY_AFTER_REPLACEMENT_RULES_EFFECTIVE"], ["TOKEN_SCOPE_PERMISSION_OR_TTL_BROADENED", "SECRET_RESPONSE_CAPTURED", "SOURCE_REF_DRIFT"], ["RELEASE_APP_INSTALLATION_ID_AND_READBACK"]),
        transition("S6_BOOTSTRAP_TOKEN_MINTED", "S7_MAIN_ADVANCED_A_TO_B_AND_BOOTSTRAP_TOKEN_REVOKED", ["IMMEDIATE_GET_MAIN_REF_EQUALS_A", "B_SOLE_PARENT_EQUALS_A", "B_LOCAL_AND_GITHUB_VERIFICATION_STILL_PASS", "BOOTSTRAP_TOKEN_SCOPE_STILL_EXACT"], ["get-main-ref", "patch-main-ref-bootstrap-force-false", "get-main-ref", "get-bootstrap-commit", "local-git-verify-commit-raw-bootstrap-b", "revoke-bootstrap-installation-token", "prove-bootstrap-installation-token-revoked"], ["PATCH_AUTHENTICATED_AS_EXACT_RELEASE_APP_INSTALLATION", "PATCH_BODY_SHA_EQUALS_B", "PATCH_FORCE_FALSE", "MAIN_EQUALS_B", "FAST_FORWARD_A_TO_B", "LOCAL_EXACT_KEY_SIGNATURE_VERIFICATION_PASS", "GITHUB_COMMIT_VERIFICATION_VERIFIED_TRUE_REASON_VALID_AND_VERIFIED_AT_NON_NULL", "BOOTSTRAP_TOKEN_REVOCATION_RETURNS_204_AND_SUBSEQUENT_AUTH_RETURNS_401"], ["PRE_UPDATE_REF_NOT_A", "HTTP_STATUS_NOT_200", "POST_UPDATE_REF_NOT_B", "SIGNATURE_OR_KEY_VERIFICATION_FAIL", "TOKEN_REVOCATION_OR_NEGATIVE_AUTH_PROOF_FAIL"], [bootstrap_evidence_key, signing_key_evidence_key, "REF_UPDATE_AND_BYPASS_AUDIT"]),
        transition("S7_MAIN_ADVANCED_A_TO_B_AND_BOOTSTRAP_TOKEN_REVOKED", "S8_WORKFLOW_AND_CHECK_PRODUCER_READ_BACK", ["MAIN_EQUALS_B", "BOOTSTRAP_TOKEN_REVOKED", "NO_HISTORY_REWRITE_ALLOWED"], ["list-workflows", "get-candidate-workflow", "get-release-workflow", "get-pages-workflow", "get-candidate-workflow-content-at-b", "get-release-workflow-content-at-b", "get-pages-workflow-content-at-b", "run-bootstrap-candidate-producer-probe", "list-candidate-check-runs"], ["WORKFLOW_PROVIDER_IDS_PATHS_BLOBS_AND_CONTENT_DIGESTS_BOUND_TO_B", "CHECK_CONTEXT_AND_CHECK_PRODUCER_INTEGRATION_ID_BOUND", "PROBE_DOES_NOT_AUTHORIZE_WORKFLOW_INTRODUCTION"], ["WORKFLOW_AMBIGUITY", "CONTENT_DIGEST_MISMATCH", "CHECK_PRODUCER_UNBOUND_OR_CHANGED"], ["CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK", "RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK", "PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK", "CANDIDATE_CHECK_PRODUCER_ID_AND_RUN"]),
        transition("S8_WORKFLOW_AND_CHECK_PRODUCER_READ_BACK", "S9_ADMISSION_RULESET_FINALIZED", ["MAIN_EQUALS_B", "CHECK_PRODUCER_ID_BOUND", "RELEASE_APP_INTEGRATION_ID_BOUND", "ADMISSION_RULESET_ID_EQUALS_BOOTSTRAP_RULESET_ID"], ["update-admission-ruleset-to-final", "get-admission-ruleset", "list-effective-main-rules"], ["SAME_ADMISSION_RULESET_ID_EXACT_FINAL_ACTIVE_READBACK", "ONLY_RELEASE_APP_BYPASSES_UPDATE_PULL_REQUEST_AND_STATUS_CHECK_RULES", "CLASSIC_PROTECTION_ABSENT", "ALL_INVARIANT_RULES_REMAIN_EFFECTIVE"], ["ADMISSION_RULESET_ID_REPLACED", "APP_CHECK_OR_RULESET_ID_MISMATCH", "EXTRA_BYPASS_ACTOR", "INVARIANT_RULE_LOST", "SOURCE_REF_DRIFT"], ["ADMISSION_RULESET_ID_AND_READBACK", "CLASSIC_BRANCH_PROTECTION_FINAL_READBACK", "EFFECTIVE_MAIN_RULES_READBACK"]),
        transition("S9_ADMISSION_RULESET_FINALIZED", "S10_FIRST_NORMAL_RELEASE_C_SUCCEEDED", ["MAIN_EQUALS_B", "TRUSTED_RELEASE_WORKFLOW_BLOB_EQUALS_B", "CANDIDATE_TREE_COMMIT_C0_HAS_BASE_B_AND_EXACT_SUCCESSFUL_CHECK_FROM_BOUND_INTEGRATION", "EXACT_OPEN_PR_REVIEWS_FILES_AND_LAST_PUSH_APPROVAL_BOUND", "EXACT_D0_B04_SIGNING_KEY_REGISTERED_AND_LOCALLY_TRUSTED", "DISPATCHER_EXACT_LOGIN_ID_AND_WRITE_OR_ADMIN_PERMISSION_READ_BACK", "REVIEWER_EXACT_LOGIN_ID_ENVIRONMENT_MEMBERSHIP_AND_READ_WRITE_OR_ADMIN_PERMISSION_READ_BACK"], ["dispatch-release-workflow-on-main", "list-release-workflow-runs", "get-release-workflow-run", "get-release-run-jobs", "get-release-pending-deployments", "get-release-pending-deployments-as-reviewer", "review-release-pending-deployment", "list-release-deployments", "list-release-deployment-statuses", "capture-provider-ui-audit-export", "mint-release-installation-token-after-approval", "list-release-token-repositories", "trusted-release-job-create-ssh-ed25519-signed-c-prime", "git-smart-protocol-upload-signed-release-c-prime-to-temporary-ref", "patch-main-ref-release-force-false", "get-main-ref", "get-signed-release-commit", "local-git-verify-commit-raw-release-c-prime", "get-d0-b04-ssh-signing-key", "list-public-ssh-signing-keys-for-d0-b04-user", "revoke-release-installation-token", "prove-release-installation-token-revoked"], ["DISPATCH_AUTHENTICATED_ACTOR_AND_WORKFLOW_TRIGGERING_ACTOR_EQUAL_EXACT_CONFIGURED_DISPATCHER_ID", "PENDING_DEPLOYMENT_REVIEWER_CURRENT_USER_CAN_APPROVE_TRUE", "REVIEW_AUTHENTICATED_ACTOR_AND_PROVIDER_AUDIT_ACTOR_EQUAL_EXACT_CONFIGURED_REVIEWER_ID", "REVIEWER_DIFFERS_FROM_DISPATCHER_AND_TRIGGERING_ACTOR", "TOKEN_MINT_OCCURRED_AFTER_PROVIDER_AUDITED_APPROVAL", "TOKEN_ONE_REPOSITORY_CONTENTS_WRITE_METADATA_READ_AND_EXPIRES_WITHIN_3600_SECONDS", "C_PRIME_TREE_EQUALS_C0_TREE", "C_PRIME_SOLE_PARENT_EQUALS_B", "MAIN_EQUALS_C_PRIME", "PATCH_FORCE_FALSE", "LOCAL_EXACT_KEY_SIGNATURE_VERIFICATION_PASS", "GITHUB_COMMIT_VERIFICATION_VERIFIED_TRUE_REASON_VALID_AND_VERIFIED_AT_NON_NULL", "COMMIT_AND_KEY_EVIDENCE_BIND_EXACT_D0_B04_IDENTITY", "RELEASE_TOKEN_REVOKED_AND_SUBSEQUENT_AUTH_RETURNS_401"], ["WORKFLOW_BLOB_DIFFERS_FROM_TRUSTED_B", "DISPATCHER_ID_OR_PERMISSION_MISMATCH", "REVIEWER_ID_PERMISSION_APPROVAL_OR_AUDIT_MISMATCH", "SELF_APPROVAL", "TOKEN_MINT_BEFORE_APPROVAL", "TOKEN_SCOPE_OR_TTL_BROADENED", "BASE_OR_CANDIDATE_DRIFT", "SIGNING_KEY_REMOVED_CHANGED_OR_REVOKED", "REF_UPDATE_OR_SIGNATURE_FAILURE"], [normal_release_evidence_key, signing_key_evidence_key, "PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING", "CANDIDATE_CHECK_PRODUCER_ID_AND_RUN", "REF_UPDATE_AND_BYPASS_AUDIT", "AUDIT_LOG_RECORDS"]),
        transition("S10_FIRST_NORMAL_RELEASE_C_SUCCEEDED", "S11_FINAL_CAPTURE_AND_AUDIT_COMPLETE", ["MAIN_EQUALS_C_PRIME", "LOCAL_AND_GITHUB_SIGNATURE_VERIFICATION_PASS", "EXACT_SIGNING_KEY_REMAINS_REGISTERED"], ["get-main-ref", "get-signed-release-commit", "get-d0-b04-ssh-signing-key", "list-public-ssh-signing-keys-for-d0-b04-user", "get-actions-permissions", "get-selected-actions", "get-default-workflow-permissions", "get-fork-pr-approval-policy", "get-invariant-ruleset", "get-admission-ruleset", "list-effective-main-rules", "get-release-environment", "list-environment-branch-policies", "get-release-app", "get-release-app-installation", "list-user-installation-repositories", "capture-provider-ui-audit-export"], ["ALL_EXACT_PROJECTIONS_MATCH", "SIGNING_KEY_AND_BOTH_COMMIT_VERIFICATIONS_MATCH_D0_B04", "AUDIT_WINDOW_COMPLETE", "NO_UNEXPLAINED_SETTINGS_OR_REF_MUTATION", "D2_ADMISSION_READY"], ["ANY_PROJECTION_MISMATCH", "SIGNING_KEY_REMOVED_CHANGED_OR_REVOKED", "AUDIT_SOURCE_UNAVAILABLE_OR_SELF_ATTESTED", "UNEXPECTED_ACTOR_OR_MUTATION"], ["AUDIT_LOG_RECORDS", "D2_PRE_MUTATION_CAPTURE", signing_key_evidence_key, "EFFECTIVE_MAIN_RULES_READBACK"]),
    ]
    before_advance_states = [state["state"] for state in states[:7]]
    after_advance_states = [state["state"] for state in states[7:]]
    def rollback_step(order: int, action: str, condition: str, baseline_effect: str, operation_ids: list[str], postcondition: str, *, applicable_states: list[str], applicable_ref_classes: list[str], required_bindings: list[str], baseline_presence_from: list[str], success_postconditions: list[str], failure_disposition: str, conditional_operation_groups: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {"order": order, "action": action, "condition": condition, "applicableStates": applicable_states, "applicableRefClasses": applicable_ref_classes, "requiredBindings": required_bindings, "baselinePresenceFrom": baseline_presence_from, "baselineEffect": baseline_effect, "operationIds": operation_ids, "conditionalOperationGroups": [] if conditional_operation_groups is None else conditional_operation_groups, "skipEvidenceRequired": True, "postcondition": postcondition, "successPostconditions": success_postconditions, "failureDisposition": failure_disposition}
    def conditional_operations(condition: str, required_bindings: list[str], operation_ids: list[str]) -> dict[str, Any]:
        return {"executeWhen": condition, "requiredBindings": required_bindings, "operationIds": operation_ids, "skipEvidenceRequired": True, "unresolvedBindingDisposition": "SKIP_WITH_EVIDENCE_ONLY_IF_RESOURCE_OR_CREDENTIAL_IS_PROVED_NOT_APPLICABLE;OTHERWISE_INCIDENT_FREEZE"}
    rollback_before = [
        rollback_step(1, "READ_AND_CLASSIFY_MAIN_THEN_REQUIRE_EXACT_BASELINE_A", "ALWAYS", "NO_RESTORATIVE_WEAKENING_MAY_BEGIN_UNTIL_FRESH_PROVIDER_READBACK_PROVES_MAIN_EQUALS_A", ["get-main-ref"], "FRESH_MAIN_REF_PRESENT_READABLE_AND_EQUALS_BASELINE_A", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["baselineA"], baseline_presence_from=[pre_mutation_capture_key], success_postconditions=["MAIN_EQUALS_A", "REF_CLASSIFICATION_EVIDENCE_RECORDED"], failure_disposition="ENTER_UNKNOWN_REF_INCIDENT;PROHIBIT_EVERY_REF_MUTATION"),
        rollback_step(2, "REVOKE_EACH_ACTIVE_CEREMONY_TOKEN_AND_PROVE_EXACT_NEGATIVE_AUTH", "FOR_EACH_EXACT_TOKEN_INSTANCE_MINTED_BY_THIS_CEREMONY_AND_NOT_ALREADY_PROVED_REVOKED", "NO_BASELINE_TOKEN_STATE_IS_RESTORED;ONLY_CEREMONY TOKENS ARE DESTROYED", [], "EVERY_MINTED_CEREMONY_TOKEN_IS_PROVED_REVOKED_OR_A PROVIDER-DOCUMENTED REVOCATION FAILURE ENTERS INCIDENT FREEZE", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["ceremonyCredentialLedger"], baseline_presence_from=[], success_postconditions=["NO_ACTIVE_CEREMONY_INSTALLATION_TOKEN", "EACH_REVOKED_TOKEN_INSTANCE_RETURNS_401"], failure_disposition="ABORT_RESTORATION_AND_ENTER_CREDENTIAL_INCIDENT_FREEZE", conditional_operation_groups=[conditional_operations("RELEASE_INSTALLATION_READ_TOKEN_MINTED_AND_NOT_PROVED_REVOKED", ["releaseInstallationReadTokenInstance"], ["revoke-release-installation-read-token", "prove-release-installation-read-token-revoked"]), conditional_operations("BOOTSTRAP_INSTALLATION_WRITE_TOKEN_MINTED_AND_NOT_PROVED_REVOKED", ["bootstrapInstallationWriteTokenInstance"], ["revoke-bootstrap-installation-token", "prove-bootstrap-installation-token-revoked"]), conditional_operations("RELEASE_INSTALLATION_WRITE_TOKEN_MINTED_AND_NOT_PROVED_REVOKED", ["releaseInstallationWriteTokenInstance"], ["revoke-release-installation-token", "prove-release-installation-token-revoked"])]),
        rollback_step(3, "SUSPEND_ONLY_THE_EXACT_BOUND_CEREMONY_APP_INSTALLATION_AND_BLOCK_MINTING", "EXACT_RELEASE_APP_INSTALLATION_ID_IS_BOUND_EXISTS_AND_IS_NOT_ALREADY_SUSPENDED", "TEMPORARY_CONTAINMENT;LATER RESTORE EXACT FRESH BASELINE SUSPENSION STATE OR REQUIRE SEPARATE REMOVAL FOR A CEREMONY-CREATED INSTALLATION", ["suspend-release-app-installation", "get-release-app-installation"], "EXACT_BOUND_INSTALLATION_SUSPENDED;NO_OTHER INSTALLATION CHANGED", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["releaseAppIntegrationId", "releaseAppInstallationId"], baseline_presence_from=[pre_mutation_capture_key], success_postconditions=["NEW_TOKEN_MINTING_BLOCKED", "EXACT_INSTALLATION_ID_UNCHANGED"], failure_disposition="ENTER_CREDENTIAL_INCIDENT_FREEZE_WITH_MAIN_STILL_REQUIRED_AT_A"),
        rollback_step(4, "DISABLE_ONLY_A_CEREMONY_CHANGED_WORKFLOW_BOUND_AT_CURRENT_DEFAULT_BRANCH", "EXACT_PROVIDER_WORKFLOW_ID_PATH_AND_CURRENT_DEFAULT_BRANCH_IDENTITY_EXIST_AND CEREMONY_CHANGED_OR_ACTIVATED_IT", "BASELINE-UNTOUCHED OR STALE-A OR NAME-SELECTED WORKFLOWS MUST NOT BE DISABLED", [], "ONLY_THE_EXACT_CEREMONY_CHANGED_CURRENT-BRANCH_WORKFLOW_IS_DISABLED", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["releaseWorkflowId"], baseline_presence_from=[pre_mutation_capture_key], success_postconditions=["OTHER_WORKFLOWS_UNCHANGED", "WORKFLOW_PROVIDER_ID_PATH_AND_DEFAULT_BRANCH_OID_REBOUND"], failure_disposition="SKIP_WITH_EVIDENCE_IF_NO_EXACT_CURRENT-BRANCH CEREMONY CHANGE;OTHERWISE INCIDENT FREEZE", conditional_operation_groups=[conditional_operations("EXACT_CURRENT_DEFAULT_BRANCH_RELEASE_WORKFLOW_WAS_CHANGED_OR_ACTIVATED_BY_CEREMONY", ["releaseWorkflowId", "baselineA"], ["disable-release-workflow", "get-release-workflow"])]),
        rollback_step(5, "REMOVE_ONLY_A_BASELINE-ABSENT_CEREMONY-CREATED_ENVIRONMENT_SECRET_WITHOUT_VALUE_CAPTURE", "EXACT_SECRET_NAME_WAS ABSENT AT FRESH BASELINE AND CREATED BY THIS CEREMONY", "BASELINE-EXISTING SECRET MUST HAVE REMAINED UNTOUCHED;VALUE DIGEST CIPHERTEXT AND MATERIAL ARE NEVER READ", [], "CEREMONY-CREATED SECRET NAME ABSENT WITH METADATA-ONLY READBACK", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["releaseEnvironmentSecretName"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["BASELINE_EXISTING_SECRET_UNCHANGED", "CEREMONY_CREATED_SECRET_ABSENT"], failure_disposition="IF_BASELINE_SECRET_WAS_OVERWRITTEN ENTER_NONRESTORABLE_SECRET_INCIDENT", conditional_operation_groups=[conditional_operations("SECRET_BASELINE_ABSENT_AND_CEREMONY_CREATED_AND_STILL_PRESENT", ["releaseEnvironmentSecretName"], ["operator-remove-environment-secret"])]),
        rollback_step(6, "RESTORE_CLASSIC_PROTECTION_FROM_FRESH_RAW_CAPTURE_BEFORE_REMOVING_REPLACEMENT_RULESETS", "CLASSIC_PROTECTION_WAS_PRESENT_IN_FRESH_BASELINE_AND_REMOVED_BY_THIS_CEREMONY", "RECONSTRUCT_TYPED_REQUEST_ONLY_FROM_FRESH_RAW_CAPTURE", [], "CLASSIC_PROTECTION_EXACTLY_EQUALS_FRESH_BASELINE_AND_EFFECTIVE_RULES_REMAIN_CLOSED", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["preCaptureClassicProtectionRequestBody"], baseline_presence_from=[pre_mutation_capture_key], success_postconditions=["CLASSIC_PROTECTION_EQUALS_FRESH_BASELINE", "NO_GUARD_GAP"], failure_disposition="ABORT_BEFORE_RULESET_WEAKENING;KEEP_REPLACEMENT_RULESETS_ACTIVE", conditional_operation_groups=[conditional_operations("CLASSIC_PROTECTION_BASELINE_PRESENT_AND_CEREMONY_REMOVED", ["preCaptureClassicProtectionRequestBody"], ["restore-classic-branch-protection-from-pre-capture", "get-classic-branch-protection", "list-effective-main-rules"])]) if catalog_id == "rust" else rollback_step(6, "CONFIRM_BASELINE_ABSENT_CLASSIC_PROTECTION_REMAINS_ABSENT", "CLASSIC_PROTECTION_WAS_ABSENT_IN_FRESH_BASELINE", "NO_CLASSIC_PROTECTION_MUTATION_IS_AUTHORIZED_FOR_THIS_CATALOG", ["get-classic-branch-protection", "list-effective-main-rules"], "CLASSIC_PROTECTION_REMAINS_TYPED_ABSENT_AND_REPLACEMENT_RULES_REMAIN_EFFECTIVE", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=[], baseline_presence_from=[pre_mutation_capture_key], success_postconditions=["CLASSIC_PROTECTION_REMAINS_ABSENT", "NO_GUARD_GAP"], failure_disposition="KEEP_REPLACEMENT_RULESETS_ACTIVE_AND_ENTER_MANUAL_PROVIDER_RESTORE_INCIDENT"),
        rollback_step(7, "RESTORE_ACTIONS_ENVIRONMENT_APP_AND_WORKFLOW_STATE_BY_EXACT_FRESH_BASELINE_IDENTITY", "FOR_EACH_RESOURCE_CHANGED_BY_THIS_CEREMONY", "RESTORE BASELINE-EXISTING RESOURCES EXACTLY;DELETE OR REMOVE ONLY BASELINE-ABSENT CEREMONY-CREATED RESOURCES;NEVER SELECT BY NAME ALONE", [], "ALL_APPLICABLE_PROVIDER PROJECTIONS MATCH FRESH CAPTURE INCLUDING EXACT IDS AND ABSENCE", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["ceremonyResourceLedger"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["ACTIONS_POLICY_EQUALS_FRESH_BASELINE", "ENVIRONMENT_APP_AND_WORKFLOW_STATE_EQUAL_FRESH_BASELINE", "EVERY_UNCHANGED_RESOURCE_SKIP_EVIDENCED"], failure_disposition="KEEP_STRONGER_CONTAINMENT_AND_ENTER_MANUAL_PROVIDER_RESTORE_INCIDENT", conditional_operation_groups=[conditional_operations("ACTIONS_PERMISSIONS_CHANGED_BY_CEREMONY", ["preCaptureActionsPermissionsRequestBody"], ["restore-actions-permissions-from-pre-capture", "get-actions-permissions"]), conditional_operations("SELECTED_ACTIONS_POLICY_CHANGED_BY_CEREMONY", ["preCaptureSelectedActionsRequestBody"], ["restore-selected-actions-from-pre-capture", "get-selected-actions"]), conditional_operations("DEFAULT_WORKFLOW_PERMISSIONS_CHANGED_BY_CEREMONY", ["preCaptureDefaultWorkflowPermissionsRequestBody"], ["restore-default-workflow-permissions-from-pre-capture", "get-default-workflow-permissions"]), conditional_operations("FORK_PR_APPROVAL_POLICY_CHANGED_BY_CEREMONY", ["preCaptureForkPrApprovalPolicyRequestBody"], ["restore-fork-pr-approval-policy-from-pre-capture", "get-fork-pr-approval-policy"]), conditional_operations("ENVIRONMENT_OR_BRANCH_POLICY_CHANGED_OR_BASELINE_ABSENT_RESOURCE_CREATED_BY_CEREMONY", ["ceremonyResourceLedger"], ["operator-restore-environment-resources-from-pre-capture"]), conditional_operations("APP_INSTALLATION_STATE_CHANGED_OR_BASELINE_ABSENT_INSTALLATION_CREATED_BY_CEREMONY", ["ceremonyResourceLedger"], ["operator-restore-app-installation-from-pre-capture"]), conditional_operations("EXACT_CURRENT_DEFAULT_BRANCH_WORKFLOW_STATE_CHANGED_BY_CEREMONY", ["releaseWorkflowId", "ceremonyResourceLedger"], ["operator-restore-workflow-state-from-pre-capture"])]),
        rollback_step(8, "DELETE_ONLY_CEREMONY-CREATED_RULESETS_AFTER_BASELINE_PROTECTION_IS RESTORED", "EACH_EXACT_RULESET_ID_WAS ABSENT AT FRESH BASELINE AND CREATED BY THIS CEREMONY", "BASELINE-EXISTING RULESETS ARE NEVER DELETED OR RESTORED FROM TARGET-STATE REQUESTS", [], "CEREMONY-CREATED RULESETS ABSENT AND FRESH BASELINE RULESET SET AND EFFECTIVE RULES RESTORED", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["admissionRulesetId", "invariantRulesetId"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["EXACT_BASELINE_RULESET_ID_SET_RESTORED", "EFFECTIVE_RULES_EQUAL_FRESH_BASELINE"], failure_disposition="KEEP_ANY_STRONGER_RULESET ACTIVE AND ENTER_MANUAL_PROVIDER_RESTORE_INCIDENT", conditional_operation_groups=[conditional_operations("ADMISSION_RULESET_BASELINE_ABSENT_AND_CEREMONY_CREATED", ["admissionRulesetId"], ["delete-admission-ruleset", "list-rulesets"]), conditional_operations("INVARIANT_RULESET_BASELINE_ABSENT_AND_CEREMONY_CREATED", ["invariantRulesetId"], ["delete-invariant-ruleset", "list-rulesets"]), conditional_operations("AFTER_ANY_RULESET_ROLLBACK_MUTATION", [], ["list-effective-main-rules"])]),
        rollback_step(9, "DELETE_ONLY_BASELINE-ABSENT_CEREMONY-CREATED_TEMPORARY_REFS_AND_CLOSE_ONLY_CEREMONY-CREATED_PULL_REQUESTS", "FOR_EACH EXACT RESOURCE PROVED ABSENT AT FRESH BASELINE AND CREATED BY THIS CEREMONY", "BASELINE-EXISTING REFS AND PULL REQUESTS ARE NEVER DELETED OR CLOSED", [], "EVERY APPLICABLE CEREMONY RESOURCE ABSENT OR CLOSED BY EXACT ID READBACK", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["ceremonyResourceLedger"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["NO_BASELINE_RESOURCE_DELETED", "ONLY_EXACT_CEREMONY_IDS_MUTATED"], failure_disposition="RETAIN_RESOURCE_AND_ENTER_MANUAL_CLEANUP_HANDOFF;DO_NOT_MUTATE_MAIN", conditional_operation_groups=[conditional_operations("BOOTSTRAP_TEMP_REF_BASELINE_ABSENT_AND_CEREMONY_CREATED", ["bootstrapCommitB"], ["delete-temporary-bootstrap-ref", "get-temporary-bootstrap-ref-presence"]), conditional_operations("RELEASE_TEMP_REF_BASELINE_ABSENT_AND_CEREMONY_CREATED", ["signedReleaseCommitCPrime"], ["delete-temporary-release-ref", "get-temporary-release-ref-presence"]), conditional_operations("PROBE_OR_BOOTSTRAP_PR_BASELINE_ABSENT_AND_CEREMONY_CREATED", ["ceremonyPullRequestId"], ["operator-close-bootstrap-pr-if-created"])]),
        rollback_step(10, "DELETE_EXACT_SIGNING_KEY_ONLY_IF_BASELINE-ABSENT_AND_CEREMONY-CREATED", "EXACT_D0_B04 KEY WAS ABSENT IN BOTH FRESH AUTHENTICATED AND PUBLIC SETS AND CREATED BY THIS CEREMONY", "PREEXISTING BASELINE SIGNING KEY IS NEVER DELETED", [], "CEREMONY-CREATED KEY ABSENT FROM AUTHENTICATED AND PUBLIC READBACKS", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["signerProviderSshSigningKeyId", "signerSshEd25519PublicKey"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["BASELINE_KEY_SET_PRESERVED", "CEREMONY_CREATED_KEY_ABSENT"], failure_disposition="RETAIN_KEY_AND_REQUIRE_SEPARATE_SIGNER_HANDOFF", conditional_operation_groups=[conditional_operations("SIGNING_KEY_BASELINE_ABSENT_AND_CEREMONY_CREATED", ["signerProviderSshSigningKeyId"], ["delete-d0-b04-ssh-signing-key", "get-d0-b04-ssh-signing-key-presence", "list-public-ssh-signing-keys-for-d0-b04-user"])]),
        rollback_step(11, "RE_READ_MAIN_AND_REQUIRE_EXACT_BASELINE_A", "ALWAYS", "NO REF MUTATION IS PERMITTED DURING PRE-ADVANCE ROLLBACK", ["get-main-ref"], "MAIN_STILL_EQUALS_A", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["baselineA"], baseline_presence_from=[pre_mutation_capture_key], success_postconditions=["MAIN_EQUALS_A", "NO_HISTORY_REWRITE"], failure_disposition="ENTER_UNKNOWN_REF_INCIDENT;DO_NOT_CONTINUE ORDINARY ROLLBACK"),
        rollback_step(12, "READ_BACK_ALL_RESOURCES_EFFECTIVE_RULES_TOKEN_DENIAL_AND_PROVIDER_AUDIT", "ALWAYS", "EVERY EXECUTED ACTION AND EVERY SKIP MUST BE PROVIDER OR CEREMONY-LEDGER EVIDENCED", ["get-actions-permissions", "get-selected-actions", "get-default-workflow-permissions", "get-fork-pr-approval-policy", "get-classic-branch-protection", "list-rulesets", "list-effective-main-rules", "list-environments", "list-environment-secrets", "get-release-app", "list-organization-app-installations", "capture-provider-ui-audit-export"], "MAIN_EQUALS_A_AND_EXACT_FRESH_PROVIDER_BASELINE_RESTORED_WITH_COMPLETE_ACTION_AND_SKIP EVIDENCE", applicable_states=before_advance_states, applicable_ref_classes=["MAIN_EQUALS_A"], required_bindings=["baselineA"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger", "ceremonyCredentialLedger"], success_postconditions=["ALL_PROJECTIONS_EQUAL_FRESH_BASELINE", "ALL_APPLICABLE_TOKENS_PROVED_DENIED", "AUDIT_WINDOW_COMPLETE", "EVERY_SKIP_EVIDENCED"], failure_disposition="D2_AND_LATER_BLOCKED;MANUAL_INCIDENT_HANDOFF_REQUIRED"),
    ]
    rollback_after = [
        rollback_step(1, "CONFIRM_EXACT_POST_ADVANCE_REF_CLASS_AND_SIGNED_ANCESTRY", "FRESH_CLASSIFICATION_IS MAIN_EQUALS_B OR MAIN_EQUALS_C_PRIME", "CLASSIFICATION IDENTIFIES KNOWN COMMITS BUT DOES NOT TREAT HISTORICAL GITHUB VERIFICATION AS CURRENT SIGNER AUTHORIZATION", ["get-main-ref", "get-bootstrap-commit", "local-git-verify-commit-raw-bootstrap-b"], "TIP_AND_ANCESTRY EXACTLY MATCH THE SELECTED B OR C_PRIME CLASS", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["baselineA", "bootstrapCommitB"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["B_SOLE_PARENT_A_AND_CREATION_VERIFICATION_EVIDENCE_MATCHES", "C_PRIME_IF_CLASSIFIED_SOLE_PARENT_B_AND_CREATION_VERIFICATION_EVIDENCE_MATCHES"], failure_disposition="ENTER_UNKNOWN_REF_INCIDENT;PROHIBIT_EVERY_REF_MUTATION", conditional_operation_groups=[conditional_operations("REF_CLASS_IS_C_PRIME", ["signedReleaseCommitCPrime"], ["get-signed-release-commit", "local-git-verify-commit-raw-release-c-prime"])]),
        rollback_step(2, "REVOKE_CEREMONY_TOKENS_AND_BLOCK_MINTING_THROUGH_THE_EXACT_BOUND_APP_INSTALLATION", "FOR_EACH ACTIVE CEREMONY CREDENTIAL AND THE EXACT INSTALLATION IF IT EXISTS", "INCIDENT CONTAINMENT MAY INTENTIONALLY DEVIATE FROM BASELINE;NO OTHER INSTALLATION OR CREDENTIAL IS MUTATED", ["operator-revoke-release-credentials"], "KNOWN CREDENTIALS REVOKED AND EXACT INSTALLATION SUSPENDED IF BOUND AND PRESENT", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["ceremonyCredentialLedger"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["NO_KNOWN_ACTIVE_CEREMONY_TOKEN", "NEW_TOKEN_MINTING_BLOCKED_IF_EXACT_INSTALLATION_EXISTS"], failure_disposition="KEEP_REF_IMMUTABLE_AND_ESCALATE_CREDENTIAL_INCIDENT", conditional_operation_groups=[conditional_operations("EXACT_RELEASE_APP_INSTALLATION_ID_BOUND_AND_PRESENT", ["releaseAppInstallationId"], ["suspend-release-app-installation", "get-release-app-installation"])]),
        rollback_step(3, "ENTER_FORWARD_RECOVERY_FREEZE_BEFORE_ANY_OPTIONAL_CLEANUP", "ALWAYS", "NO RESET FORCE PUSH BYPASS EXPANSION NORMAL RELEASE OR UNSIGNED CORRECTION", ["operator-enter-forward-recovery-freeze"], "WRITES FROZEN;ONLY A NEW SEPARATELY REVIEWED SIGNED-FORWARD CEREMONY MAY CONTINUE", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["baselineA", "bootstrapCommitB"], baseline_presence_from=[], success_postconditions=["NORMAL_RELEASES_BLOCKED", "MAIN_UNCHANGED"], failure_disposition="INCIDENT REMAINS OPEN;PROHIBIT EVERY REF MUTATION"),
        rollback_step(4, "CLASSIFY_AND_PRESERVE_THE_EXACT_ADMISSION_RULESET_ID_AND_FORM", "EXACT_ADMISSION_RULESET_ID BINDING EXISTS;OTHERWISE INCIDENT FREEZE", "FINAL FORM IS PRESERVED;BOOTSTRAP FORM IS PRESERVED AS CONTAINMENT WITH NORMAL RELEASE FORBIDDEN;MISSING WEAKENED WRONG-ID OR OTHER FORM IS AN INCIDENT", ["get-admission-ruleset-presence"], "ADMISSION CLASS IS EXACT_FINAL_FORM OR EXACT_BOOTSTRAP_FORM;NO RULESET REPLACEMENT", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["admissionRulesetId", "releaseAppIntegrationId"], baseline_presence_from=["ceremonyResourceLedger"], success_postconditions=["EXACT_FINAL_FORM_PRESERVED_OR_EXACT_BOOTSTRAP_FORM_PRESERVED", "BOOTSTRAP_FORM_PROHIBITS_NORMAL_RELEASE", "WRONG_ID_MISSING_OR_WEAKENED_FORM_ENTER_INCIDENT_FREEZE"], failure_disposition="KEEP_FORWARD_FREEZE;SEPARATE_ADMISSION_INCIDENT HANDOFF"),
        rollback_step(5, "PRESERVE_NON_BYPASSABLE_INVARIANT_RULESET_AND_PROVE_EFFECTIVE RULES", "EXACT_INVARIANT_RULESET_ID BINDING EXISTS AND RESOURCE IS PRESENT", "NEVER REMOVE OR WEAKEN DELETION NON_FAST_FORWARD LINEAR_HISTORY OR SIGNATURE PROTECTION", ["get-invariant-ruleset-presence", "list-effective-main-rules"], "EXACT_INVARIANT RULESET ID AND FORM REMAIN EFFECTIVE", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["invariantRulesetId"], baseline_presence_from=["ceremonyResourceLedger"], success_postconditions=["NON_BYPASSABLE_INVARIANTS_EFFECTIVE", "NO_BYPASS_ACTOR"], failure_disposition="KEEP_FORWARD_FREEZE;SEPARATE_INVARIANT_INCIDENT HANDOFF"),
        rollback_step(6, "CONDITIONALLY_DISABLE_EXACT_CURRENT-BRANCH_WORKFLOW_AND_REMOVE_ONLY_CEREMONY-CREATED SECRET", "EACH ACTION REQUIRES EXACT CURRENT IDENTITY AND CEREMONY CREATION OR CHANGE EVIDENCE", "NO STALE OR NAME-SELECTED WORKFLOW IS DISABLED;NO BASELINE-EXISTING SECRET IS REMOVED", [], "ONLY APPLICABLE EXACT CEREMONY RESOURCES ARE CONTAINED", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["ceremonyResourceLedger"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["OTHER_WORKFLOWS_UNCHANGED", "BASELINE_SECRET_UNCHANGED", "EACH_SKIP_EVIDENCED"], failure_disposition="KEEP_FORWARD_FREEZE_AND_RECORD_PARTIAL_CONTAINMENT", conditional_operation_groups=[conditional_operations("EXACT_RELEASE_WORKFLOW_ID_PATH_AND_CURRENT_DEFAULT_BRANCH_IDENTITY_EXIST_AND_CEREMONY_ACTIVATED_OR_CHANGED_IT", ["releaseWorkflowId"], ["disable-release-workflow", "get-release-workflow"]), conditional_operations("SECRET_BASELINE_ABSENT_AND_CEREMONY_CREATED_AND_STILL_PRESENT", ["releaseEnvironmentSecretName"], ["operator-remove-environment-secret"])]),
        rollback_step(7, "REVOKE_SIGNER_LOCALLY_BEFORE_PROVIDER KEY DELETION_ONLY_UNDER_SEPARATE_COMPROMISE AUTHORIZATION", "EXPLICIT SIGNER COMPROMISE OR REVOCATION HANDOFF AUTHORIZES THE EXACT BOUND KEY", "LOCAL CURRENT REVOCATION POLICY IS AUTHORITATIVE;HISTORICAL GITHUB VERIFIED STATUS IS NONAUTHORITATIVE FOR FUTURE USE", [], "LOCAL POLICY REJECTS THE KEY BEFORE EXACT PROVIDER KEY DELETION", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["signerProviderSshSigningKeyId", "signerSshEd25519PublicKey"], baseline_presence_from=[pre_mutation_capture_key, "ceremonyResourceLedger"], success_postconditions=["LOCAL_REVOCATION_PRECEDES_PROVIDER_DELETION", "EXACT_KEY_ABSENT_IF_AUTHORIZED", "HISTORICAL_VERIFICATION_RECORDED_AS_NONAUTHORITY"], failure_disposition="RETAIN_PROVIDER KEY;KEEP_FORWARD_FREEZE;REQUIRE_SIGNER_INCIDENT HANDOFF", conditional_operation_groups=[conditional_operations("SEPARATE_EXACT_SIGNER_COMPROMISE_OR_REVOCATION_AUTHORIZATION_PRESENT", ["signerProviderSshSigningKeyId", "signerRevocationHandoffId"], ["operator-revoke-d0-b04-signer-locally", "delete-d0-b04-ssh-signing-key", "get-d0-b04-ssh-signing-key-presence", "list-public-ssh-signing-keys-for-d0-b04-user"])]),
        rollback_step(8, "RETAIN_ONLY_ACTUALLY_CREATED COMMIT AND COMPLETE PROVIDER AUDIT EVIDENCE", "BOOTSTRAP B IS BOUND;READ C_PRIME ONLY IF IT WAS BOUND AND CREATED", "NO COMMIT OR AUDIT EVIDENCE DELETION;NO UNCONDITIONAL C_PRIME READ", ["get-bootstrap-commit", "capture-provider-ui-audit-export"], "B AND C_PRIME IF CREATED PLUS COMPLETE AUDIT WINDOW RETAINED", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["bootstrapCommitB"], baseline_presence_from=["ceremonyResourceLedger"], success_postconditions=["B_EVIDENCE_RETAINED", "C_PRIME_EVIDENCE_RETAINED_ONLY_IF_CREATED", "AUDIT_WINDOW_COMPLETE"], failure_disposition="KEEP_FORWARD_FREEZE;EVIDENCE_GAP INCIDENT", conditional_operation_groups=[conditional_operations("SIGNED_RELEASE_C_PRIME_WAS_BOUND_AND_CREATED", ["signedReleaseCommitCPrime"], ["get-signed-release-commit"])]),
        rollback_step(9, "REQUIRE_NEW_REVIEWED_SIGNED_FORWARD_RECOVERY HANDOFF", "ALWAYS", "CURRENT CEREMONY CANNOT SELF-AUTHORIZE RECOVERY", ["operator-open-forward-recovery-handoff"], "NEW OPERATOR HANDOFF REQUIRED;D2 AND LATER REMAIN BLOCKED", applicable_states=after_advance_states, applicable_ref_classes=["MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B"], required_bindings=["bootstrapCommitB"], baseline_presence_from=[], success_postconditions=["CURRENT_TIP_AND_INCIDENT_BOUNDARY_DECLARED", "NO_IMPLICIT_AUTHORIZATION"], failure_disposition="KEEP_FORWARD_FREEZE_INDEFINITELY"),
    ]
    ref_classification = {
        "operationId": "get-main-ref",
        "freshReadRequired": True,
        "classificationOccursBeforeAnyRollbackMutation": True,
        "outcomes": [
            {"class": "MAIN_EQUALS_A", "requirements": ["REF_PRESENT_AND_READABLE", "OID_EQUALS_FRESH_BASELINE_A"], "route": "beforeMainAdvance"},
            {"class": "MAIN_EQUALS_B_AND_B_IS_DUAL_VERIFIED_SOLE_PARENT_A", "requirements": ["REF_PRESENT_AND_READABLE", "OID_EQUALS_EXACT_BOUND_BOOTSTRAP_B", "B_SOLE_PARENT_EQUALS_A", "B_CREATION_LOCAL_EXACT_KEY_AND_GITHUB_VERIFIED_VALID_EVIDENCE_MATCH", "CURRENT_LOCAL_REVOCATION_STATE_RECORDED_SEPARATELY_AND_NOT_OVERRIDDEN_BY_HISTORICAL_GITHUB_VERIFICATION"], "route": "afterMainAdvance"},
            {"class": "MAIN_EQUALS_C_PRIME_AND_C_PRIME_IS_DUAL_VERIFIED_SOLE_PARENT_B", "requirements": ["REF_PRESENT_AND_READABLE", "OID_EQUALS_EXACT_BOUND_SIGNED_RELEASE_C_PRIME", "C_PRIME_SOLE_PARENT_EQUALS_B", "C_PRIME_CREATION_LOCAL_EXACT_KEY_AND_GITHUB_VERIFIED_VALID_EVIDENCE_MATCH", "CURRENT_LOCAL_REVOCATION_STATE_RECORDED_SEPARATELY_AND_NOT_OVERRIDDEN_BY_HISTORICAL_GITHUB_VERIFICATION"], "route": "afterMainAdvance"},
            {"class": "REF_ABSENT_UNREADABLE_OR_ANY_OTHER_OID_OR_ANCESTRY", "requirements": ["ANY_404_AUTH_FAILURE_PARSE_FAILURE_UNBOUND_OID_WRONG_PARENT_WRONG_ANCESTRY_OR_NONMATCHING_TIP"], "route": "unknownRefIncident"},
        ],
        "binaryAElseClassificationForbidden": True,
        "unresolvedCommitBindingRoutesToUnknownIncident": True,
    }
    admission_rollback_classification = {
        "operationId": "get-admission-ruleset-presence",
        "exactRulesetIdBinding": "admissionRulesetId",
        "outcomes": [
            {"class": "EXACT_FINAL_FORM", "requirements": ["HTTP_200", "EXACT_BOUND_RULESET_ID", "EXACT_FINAL_RULES_BYPASS_CONDITIONS_AND_ENFORCEMENT"], "action": "PRESERVE_AND_KEEP_FORWARD_FREEZE_UNTIL_NEW_HANDOFF"},
            {"class": "EXACT_BOOTSTRAP_FORM", "requirements": ["HTTP_200", "EXACT_BOUND_RULESET_ID", "EXACT_BOOTSTRAP_RULES_BYPASS_CONDITIONS_AND_ENFORCEMENT"], "action": "PRESERVE_AS_CONTAINMENT_AND_PROHIBIT_NORMAL_RELEASE"},
            {"class": "MISSING_WEAKENED_WRONG_ID_OR_OTHER_FORM", "requirements": ["HTTP_404_OR_ANY_NONEXACT_ID_FORM_OR_EFFECT"], "action": "KEEP_INCIDENT_FREEZE_AND_REQUIRE_SEPARATE_ADMISSION_RECOVERY"},
        ],
        "replacementForbidden": True,
    }
    unknown_ref_incident = {
        "triggerClass": "REF_ABSENT_UNREADABLE_OR_ANY_OTHER_OID_OR_ANCESTRY",
        "immediateOperationIds": ["operator-revoke-release-credentials", "operator-enter-unknown-ref-incident-freeze", "capture-provider-ui-audit-export"],
        "conditionalOperationGroups": [conditional_operations("EXACT_RELEASE_APP_INSTALLATION_ID_BOUND_AND_CURRENTLY_EXISTS", ["releaseAppInstallationId"], ["suspend-release-app-installation", "get-release-app-installation"])],
        "requiredResults": ["KNOWN_CREDENTIALS_REVOKED_OR_BLOCKED", "EVERY_REF_MUTATION_PROHIBITED", "PROVIDER_AND_AUDIT_EVIDENCE_PRESERVED", "SEPARATE_INCIDENT_HANDLING_REQUIRED"],
        "forbidden": ["ASSUME_TIP_IS_B_OR_C_PRIME", "ORDINARY_SIGNED_FORWARD_RECOVERY", "RESET_FORCE_PUSH_DELETE_OR_OTHER_REF_MUTATION", "BYPASS_EXPANSION", "AUDIT_EVIDENCE_DELETION"],
        "d2AndLaterBlocked": True,
    }
    auxiliary_rollback_bindings = [
        {"name": "ceremonyResourceLedger", "source": "ROLLBACK_EXECUTION_LEDGER_RESOURCE_ENTRIES", "valueClass": "APPEND_ONLY_NONSECRET_LEDGER", "missingOrContradictoryDisposition": "INCIDENT_FREEZE_NOT_DESTRUCTIVE_DEFAULT"},
        {"name": "ceremonyCredentialLedger", "source": "ROLLBACK_EXECUTION_LEDGER_CREDENTIAL_ENTRIES", "valueClass": "APPEND_ONLY_SECRET_FREE_LEDGER", "missingOrContradictoryDisposition": "INCIDENT_FREEZE_NOT_CREDENTIAL_GUESSING"},
        {"name": "releaseInstallationReadTokenInstance", "source": "EXACT_CEREMONY_CREDENTIAL_LEDGER_ENTRY_AND_EPHEMERAL_SECRET_STORE_HANDLE", "valueClass": "INTERNAL_TOKEN_INSTANCE_REFERENCE_NEVER_MATERIAL_OR_DIGEST", "missingOrContradictoryDisposition": "INCIDENT_FREEZE_NOT_CROSS_TOKEN_SUBSTITUTION"},
        {"name": "bootstrapInstallationWriteTokenInstance", "source": "EXACT_CEREMONY_CREDENTIAL_LEDGER_ENTRY_AND_EPHEMERAL_SECRET_STORE_HANDLE", "valueClass": "INTERNAL_TOKEN_INSTANCE_REFERENCE_NEVER_MATERIAL_OR_DIGEST", "missingOrContradictoryDisposition": "INCIDENT_FREEZE_NOT_CROSS_TOKEN_SUBSTITUTION"},
        {"name": "releaseInstallationWriteTokenInstance", "source": "EXACT_CEREMONY_CREDENTIAL_LEDGER_ENTRY_AND_EPHEMERAL_SECRET_STORE_HANDLE", "valueClass": "INTERNAL_TOKEN_INSTANCE_REFERENCE_NEVER_MATERIAL_OR_DIGEST", "missingOrContradictoryDisposition": "INCIDENT_FREEZE_NOT_CROSS_TOKEN_SUBSTITUTION"},
        {"name": "releaseEnvironmentSecretName", "source": "EXACT_CEREMONY_RESOURCE_LEDGER_ENTRY_WITH_FRESH_BASELINE_ABSENCE_AND_CREATE_READBACK", "valueClass": "NONSECRET_PROVIDER_RESOURCE_NAME", "missingOrContradictoryDisposition": "INCIDENT_FREEZE_NOT_SECRET_DELETION"},
        {"name": "ceremonyPullRequestId", "source": "EXACT_CEREMONY_RESOURCE_LEDGER_ENTRY_WITH_FRESH_BASELINE_ABSENCE_AND_CREATE_READBACK", "valueClass": "POSITIVE_PROVIDER_ID", "missingOrContradictoryDisposition": "RETAIN_RESOURCE_AND_REQUIRE_MANUAL_HANDOFF"},
        {"name": "signerRevocationHandoffId", "source": "SEPARATE_FRESH_OPERATOR_SIGNER_COMPROMISE_OR_REVOCATION_HANDOFF", "valueClass": "SECURITY_HANDOFF_ID", "missingOrContradictoryDisposition": "RETAIN_PROVIDER_KEY_AND_KEEP_FORWARD_FREEZE"},
    ]
    return {
        "schema": "pkgre-d0-github-bootstrap-state-machine-v2",
        "catalogId": catalog_id,
        "repository": repository,
        "sourceRef": source_ref,
        "baselineA": source_tip,
        "bootstrapB": {"temporaryRef": f"refs/heads/pkgre-{catalog_id}-bootstrap-b", "candidateWorkflowPath": candidate_path, "releaseWorkflowPath": release_path, "soleParent": "BASELINE_A", "tree": "EXACT_FROZEN_BOOTSTRAP_TREE", "signature": "SSH_ED25519_D0_B04_CATALOG_SPECIFIC", "localVerification": "GIT_VERIFY_COMMIT_RAW_WITH_FROZEN_ALLOWED_SIGNERS_AND_EXACT_FINGERPRINT", "providerVerification": {"verified": True, "reason": GITHUB_VERIFIED_COMMIT_REASON, "verifiedAtRequired": True}, "candidateWorkflowMayAuthorizeOwnIntroduction": False},
        "admissionEvolution": {"rulesetName": admission_name, "rulesetIdBinding": "admissionRulesetId", "bootstrapForm": "UPDATE_ONLY_SOLE_RELEASE_APP_BYPASS", "finalForm": "UPDATE_PULL_REQUEST_REQUIRED_STATUS_CHECKS_SOLE_RELEASE_APP_BYPASS", "sameProviderRulesetIdRequired": True, "replacementAllowed": False},
        "signingIdentity": {"authoritySource": "D0-B04", "scope": "CATALOG_SPECIFIC", "requiredBindings": ["signerGithubLogin", "signerSshEd25519PublicKey", "signerSshSha256Fingerprint", "signerSshKeyTitle", "signerProviderSshSigningKeyId", "signerProviderSshSigningKeyCreatedAt"], "githubPersistentVerificationAfterKeyRemoval": True, "runtimeExactKeyAndRevocationPolicyAuthoritative": True},
        "firstNormalRelease": {"trustedWorkflowCommit": "BOOTSTRAP_COMMIT_B", "candidateTreeCommit": "C0_UNTRUSTED_DATA_ONLY", "signedReleaseCommit": "C_PRIME_TREE_EQUALS_C0_SOLE_PARENT_B", "providerVerification": {"verified": True, "reason": GITHUB_VERIFIED_COMMIT_REASON, "verifiedAtRequired": True}, "environment": environment_name, "admissionRuleset": admission_name, "invariantRuleset": invariant_name, "writerApp": writer_slug},
        "states": states,
        "transitions": transitions,
        "rollback": {"decisionPoint": "FRESH_GET_MAIN_REF_EXACT_FOUR_WAY_CLASSIFICATION", "refClassification": ref_classification, "admissionRuleClassification": admission_rollback_classification, "executionLedger": {"schema": "pkgre-d0-github-rollback-execution-ledger-v1", "resourceEntryFields": ["resourceType", "exactProviderIdOrRef", "exactRepositoryId", "freshBaselinePresence", "freshBaselineCaptureOperationId", "freshBaselineRawArtifactSha256", "createdByCeremony", "changedByCeremony", "currentPresenceReadbackOperationId", "currentProjectionSha256"], "credentialEntryFields": ["credentialKind", "exactCeremonyInstanceInternalReference", "mintOperationId", "mintCompleted", "revokeOperationId", "revokeCompleted", "negativeAuthProofOperationId", "negativeAuthProofCompleted"], "credentialMaterialOrDigestAllowed": False, "conditionEvaluation": "FRESH_READBACK_PLUS_APPEND_ONLY_CEREMONY_LEDGER", "missingOrContradictoryEntryDisposition": "INCIDENT_FREEZE_NOT_DESTRUCTIVE_DEFAULT", "skipEvidenceFields": ["rollbackStepOrder", "conditionalGroupIndex", "condition", "evaluatedResult", "supportingReadbackOperationIds", "supportingArtifactSha256", "recordedAtUtc"], "everySkippedStepOrGroupRecorded": True}, "auxiliaryBindingRegistry": auxiliary_rollback_bindings, "beforeMainAdvanceStates": before_advance_states, "beforeMainAdvance": rollback_before, "afterMainAdvanceStates": after_advance_states, "afterMainAdvance": rollback_after, "unknownRefIncident": unknown_ref_incident, "forbidden": ["FORCE_PUSH", "RESET_MAIN_TO_A", "EXPAND_BYPASS_ACTORS", "REPLACE_ADMISSION_RULESET_ID", "UNSIGNED_OR_PROVIDER_UNVERIFIED_CORRECTIVE_COMMIT", "DELETE_AUDIT_EVIDENCE", "TREAT_GITHUB_PERSISTENT_VERIFICATION_AS_CURRENT_EXACT_KEY_AUTHORIZATION", "CLAIM_PAGES_CONTINUITY_RESTORED_WITHOUT_INDEPENDENT_TLS_HTTP_PROOF"]},
    }

def github_provider_contract(catalog_id: str, repository: str, repository_id: int, source_tip: str, source_ref: str, source_branch: str, candidate_path: str, release_path: str, pages_path: str, candidate_name: str, release_name: str, pages_name: str, check_context: str, environment_name: str, reviewer: str, dispatcher: str, writer_slug: str, admission_ruleset: dict[str, Any], invariant_ruleset: dict[str, Any], signing_identity: dict[str, Any], actions: dict[str, Any], pre_mutation_capture_key: str, signing_key_evidence_key: str, bootstrap_evidence_key: str, normal_release_evidence_key: str) -> dict[str, Any]:
    owner, repo = repository.split("/", 1)
    base = f"/repos/{owner}/{repo}"
    bindings = [
        {"name": "signerGithubLogin", "type": "GITHUB_LOGIN", "sourceOperation": "bind-d0-b04-catalog-signing-identity", "jsonPointer": "/githubLogin", "authoritySource": signing_identity["authoritySource"], "mustDifferFrom": []},
        {"name": "signerSshEd25519PublicKey", "type": "SSH_ED25519_PUBLIC_KEY", "sourceOperation": "bind-d0-b04-catalog-signing-identity", "jsonPointer": "/sshEd25519PublicKey", "authoritySource": signing_identity["authoritySource"], "mustDifferFrom": []},
        {"name": "signerSshSha256Fingerprint", "type": "SSH_SHA256_FINGERPRINT", "sourceOperation": "bind-d0-b04-catalog-signing-identity", "jsonPointer": "/sshSha256Fingerprint", "authoritySource": signing_identity["authoritySource"], "mustDifferFrom": []},
        {"name": "signerSshKeyTitle", "type": "NONEMPTY_STRING", "sourceOperation": "bind-d0-b04-catalog-signing-identity", "jsonPointer": "/providerKeyTitle", "authoritySource": signing_identity["authoritySource"], "mustDifferFrom": []},
        {"name": "signerProviderSshSigningKeyId", "type": "POSITIVE_INT64", "sourceOperation": "resolve-d0-b04-provider-signing-key-binding", "jsonPointer": "/id", "mustDifferFrom": []},
        {"name": "signerProviderSshSigningKeyCreatedAt", "type": "UTC_TIMESTAMP", "sourceOperation": "resolve-d0-b04-provider-signing-key-binding", "jsonPointer": "/created_at", "mustDifferFrom": []},
        {"name": "signerGithubUserId", "type": "POSITIVE_INT64", "sourceOperation": "get-authenticated-signing-user", "jsonPointer": "/id", "mustDifferFrom": ["reviewerUserId", "dispatcherUserId"]},
        {"name": "releaseAppIntegrationId", "type": "POSITIVE_INT64", "sourceOperation": "get-release-app", "jsonPointer": "/id", "mustDifferFrom": ["releaseAppInstallationId", "candidateCheckIntegrationId"]},
        {"name": "releaseAppInstallationId", "type": "POSITIVE_INT64", "sourceOperation": "list-organization-app-installations", "jsonPointer": "/installations/EXACT_APP_MATCH/id", "mustDifferFrom": ["releaseAppIntegrationId", "candidateCheckIntegrationId"]},
        {"name": "candidateCheckIntegrationId", "type": "POSITIVE_INT64", "sourceOperation": "list-candidate-check-runs", "jsonPointer": "/check_runs/EXACT_CONTEXT_HEAD_SHA_WORKFLOW_JOB_MATCH/app/id", "mustDifferFrom": ["releaseAppIntegrationId", "releaseAppInstallationId"]},
        {"name": "reviewerGithubLogin", "type": "GITHUB_LOGIN", "sourceOperation": "get-environment-reviewer-user", "jsonPointer": "/login", "frozenValue": reviewer, "mustDifferFrom": ["dispatcherGithubLogin"]},
        {"name": "reviewerUserId", "type": "POSITIVE_INT64", "sourceOperation": "get-environment-reviewer-user", "jsonPointer": "/id", "mustDifferFrom": ["dispatcherUserId", "triggeringActorUserId", "dispatchAuthenticatedActorUserId"]},
        {"name": "reviewerLegacyBasePermission", "type": "GITHUB_LEGACY_BASE_PERMISSION", "sourceOperation": "get-environment-reviewer-permission", "jsonPointer": "/permission", "allowedValues": ["read", "write", "admin"], "mustDifferFrom": []},
        {"name": "dispatcherGithubLogin", "type": "GITHUB_LOGIN", "sourceOperation": "get-release-dispatcher-user", "jsonPointer": "/login", "frozenValue": dispatcher, "mustDifferFrom": ["reviewerGithubLogin"]},
        {"name": "dispatcherUserId", "type": "POSITIVE_INT64", "sourceOperation": "get-release-dispatcher-user", "jsonPointer": "/id", "mustDifferFrom": ["reviewerUserId", "reviewAuthenticatedActorUserId", "reviewApprovalAuditActorUserId"], "mustEqual": ["dispatchAuthenticatedActorUserId", "triggeringActorUserId"]},
        {"name": "dispatcherLegacyBasePermission", "type": "GITHUB_LEGACY_BASE_PERMISSION", "sourceOperation": "get-release-dispatcher-permission", "jsonPointer": "/permission", "allowedValues": ["write", "admin"], "mustDifferFrom": []},
        {"name": "dispatchAuthenticatedActorUserId", "type": "POSITIVE_INT64", "sourceOperation": "dispatch-release-workflow-on-main", "jsonPointer": "/request/authenticatedActorProviderId", "mustDifferFrom": ["reviewerUserId"], "mustEqual": ["dispatcherUserId", "triggeringActorUserId"]},
        {"name": "triggeringActorUserId", "type": "POSITIVE_INT64", "sourceOperation": "get-release-workflow-run", "jsonPointer": "/triggering_actor/id", "mustDifferFrom": ["reviewerUserId"], "mustEqual": ["dispatcherUserId", "dispatchAuthenticatedActorUserId"]},
        {"name": "pendingDeploymentReviewerUserId", "type": "POSITIVE_INT64", "sourceOperation": "get-release-pending-deployments-as-reviewer", "jsonPointer": "/EXACT_ENVIRONMENT_MATCH/reviewers/EXACT_CONFIGURED_USER/reviewer/id", "mustDifferFrom": ["dispatcherUserId"], "mustEqual": ["reviewerUserId", "reviewAuthenticatedActorUserId", "reviewApprovalAuditActorUserId"]},
        {"name": "pendingDeploymentCurrentUserCanApprove", "type": "BOOLEAN", "sourceOperation": "get-release-pending-deployments-as-reviewer", "jsonPointer": "/EXACT_ENVIRONMENT_MATCH/current_user_can_approve", "frozenValue": True, "mustDifferFrom": []},
        {"name": "reviewAuthenticatedActorUserId", "type": "POSITIVE_INT64", "sourceOperation": "review-release-pending-deployment", "jsonPointer": "/request/authenticatedActorProviderId", "mustDifferFrom": ["dispatcherUserId"], "mustEqual": ["reviewerUserId", "pendingDeploymentReviewerUserId", "reviewApprovalAuditActorUserId"]},
        {"name": "reviewApprovalAuditActorUserId", "type": "POSITIVE_INT64", "sourceOperation": "capture-provider-ui-audit-export", "jsonPointer": "/records/EXACT_PENDING_DEPLOYMENT_REVIEW/actor_id", "mustDifferFrom": ["dispatcherUserId"], "mustEqual": ["reviewerUserId", "pendingDeploymentReviewerUserId", "reviewAuthenticatedActorUserId"]},
        {"name": "invariantRulesetId", "type": "POSITIVE_INT64", "sourceOperation": "create-invariant-ruleset", "jsonPointer": "/id", "mustDifferFrom": ["admissionRulesetId"]},
        {"name": "admissionRulesetId", "type": "POSITIVE_INT64", "sourceOperation": "create-admission-ruleset-bootstrap", "jsonPointer": "/id", "mustDifferFrom": ["invariantRulesetId"]},
        {"name": "environmentId", "type": "POSITIVE_INT64", "sourceOperation": "put-release-environment", "jsonPointer": "/id", "mustDifferFrom": []},
        {"name": "environmentBranchPolicyId", "type": "POSITIVE_INT64", "sourceOperation": "create-environment-main-policy", "jsonPointer": "/id", "mustDifferFrom": []},
        {"name": "candidateWorkflowId", "type": "POSITIVE_INT64", "sourceOperation": "list-workflows", "jsonPointer": "/workflows/EXACT_CANDIDATE_PATH_AND_NAME_MATCH/id", "mustDifferFrom": ["releaseWorkflowId", "pagesWorkflowId"]},
        {"name": "releaseWorkflowId", "type": "POSITIVE_INT64", "sourceOperation": "list-workflows", "jsonPointer": "/workflows/EXACT_RELEASE_PATH_AND_NAME_MATCH/id", "mustDifferFrom": ["candidateWorkflowId", "pagesWorkflowId"]},
        {"name": "pagesWorkflowId", "type": "POSITIVE_INT64", "sourceOperation": "list-workflows", "jsonPointer": "/workflows/EXACT_PAGES_PATH_AND_NAME_MATCH/id", "mustDifferFrom": ["candidateWorkflowId", "releaseWorkflowId"]},
        {"name": "pullRequestNumber", "type": "POSITIVE_INT64", "sourceOperation": "list-open-candidate-pull-requests", "jsonPointer": "/EXACT_BASE_HEAD_MATCH/number", "mustDifferFrom": []},
        {"name": "releaseWorkflowRunId", "type": "POSITIVE_INT64", "sourceOperation": "list-release-workflow-runs", "jsonPointer": "/workflow_runs/EXACT_DISPATCH_MATCH/id", "mustDifferFrom": []},
        {"name": "pendingDeploymentEnvironmentId", "type": "POSITIVE_INT64", "sourceOperation": "get-release-pending-deployments", "jsonPointer": "/EXACT_ENVIRONMENT_MATCH/environment/id", "mustDifferFrom": [], "mustEqual": ["environmentId"]},
        {"name": "releaseDeploymentId", "type": "POSITIVE_INT64", "sourceOperation": "review-release-pending-deployment", "jsonPointer": "/EXACT_WORKFLOW_RUN_ENVIRONMENT_REF_AND_CANDIDATE_MATCH/id", "mustDifferFrom": []},
        {"name": "candidateTreeCommitOid", "type": "LOWERCASE_SHA1_40", "sourceOperation": "get-candidate-pull-request", "jsonPointer": "/head/sha", "mustDifferFrom": ["baselineA", "bootstrapCommitB", "signedReleaseCommitCPrime"]},
        {"name": "bootstrapCommitB", "type": "LOWERCASE_SHA1_40", "sourceOperation": "operator-create-ssh-ed25519-signed-bootstrap-b", "jsonPointer": "/commitOid", "mustDifferFrom": ["baselineA", "candidateTreeCommitOid", "signedReleaseCommitCPrime"]},
        {"name": "signedReleaseCommitCPrime", "type": "LOWERCASE_SHA1_40", "sourceOperation": "git-smart-protocol-upload-signed-release-c-prime-to-temporary-ref", "jsonPointer": "/commitOid", "mustDifferFrom": ["baselineA", "bootstrapCommitB", "candidateTreeCommitOid"]},
        {"name": "baselineA", "type": "LOWERCASE_SHA1_40", "sourceOperation": "get-main-ref", "jsonPointer": "/object/sha", "frozenValue": source_tip, "mustDifferFrom": ["bootstrapCommitB", "candidateTreeCommitOid", "signedReleaseCommitCPrime"]},
        {"name": "preCaptureActionsPermissionsRequestBody", "type": "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", "sourceOperation": "get-actions-permissions", "jsonPointer": "/reconstructedRestoreRequest", "mustDifferFrom": []},
        {"name": "preCaptureSelectedActionsRequestBody", "type": "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", "sourceOperation": "get-selected-actions", "jsonPointer": "/reconstructedRestoreRequest", "mustDifferFrom": []},
        {"name": "preCaptureDefaultWorkflowPermissionsRequestBody", "type": "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", "sourceOperation": "get-default-workflow-permissions", "jsonPointer": "/reconstructedRestoreRequest", "mustDifferFrom": []},
        {"name": "preCaptureForkPrApprovalPolicyRequestBody", "type": "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", "sourceOperation": "get-fork-pr-approval-policy", "jsonPointer": "/reconstructedRestoreRequest", "mustDifferFrom": []},
        {"name": "preCaptureClassicProtectionRequestBody", "type": "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", "sourceOperation": "get-classic-branch-protection", "jsonPointer": "/reconstructedRestoreRequest", "mustDifferFrom": []},
    ]
    if catalog_id == "js":
        bindings = [binding for binding in bindings if binding["name"] != "preCaptureClassicProtectionRequestBody"]
    raw_capture = {"schema": "pkgre-d0-github-raw-capture-envelope-v1", "artifactRoot": f"evidence/d2-github/{catalog_id}/provider-captures", "manifestCanonicalization": "UTF8_SORTED_KEYS_COMPACT_WITH_SINGLE_TRAILING_LF", "requestFields": ["contractOperationId", "sequence", "requestStartedAtUtc", "requestCompletedAtUtc", "authProfileId", "authenticatedActorProviderId", "method", "absoluteUrl", "path", "orderedQuery", "headersWithoutAuthorization", "requestBodyLength", "requestBodySha256"], "responseFields": ["httpStatus", "responseStartedAtUtc", "responseCompletedAtUtc", "xGitHubRequestId", "xGitHubApiVersionSelected", "link", "etag", "rateLimitLimit", "rateLimitRemaining", "rateLimitReset", "responseBodyLength", "responseBodySha256", "rawBodyArtifactPath", "projectionArtifactPath", "projectionSha256", "pageIndex", "previousPageResponseSha256", "nextLink"], "requiredHeaders": {"request": ["Accept", "X-GitHub-Api-Version", "User-Agent"], "response": ["X-GitHub-Request-Id"]}, "errorPolicy": "CAPTURE_NONSECRET_ERROR_BODY_AND_HEADERS_THEN_ABORT", "secretPolicy": {"authorizationHeader": "NEVER_CAPTURE", "privateKeys": "NEVER_CAPTURE_OR_HASH", "secretValues": "NEVER_CAPTURE_OR_HASH", "secretCiphertexts": "NEVER_CAPTURE_OR_HASH", "secretResponseBodies": "NEVER_PERSIST_OR_HASH", "redactionMarkers": "CAPTURE_FIELD_NAME_AND_REASON_ONLY"}}
    projections = {"schema": "pkgre-d0-github-provider-projection-contract-v2", "domain": GITHUB_PROVIDER_PROJECTION_DOMAIN, "canonicalization": "UTF8_SORTED_KEYS_COMPACT_WITH_SINGLE_TRAILING_LF", "digestFormula": "SHA256(ASCII_DOMAIN_NUL_KIND_NUL_CANONICAL_JSON)", "rawProviderAdditiveFields": "ALLOWED_AND_IGNORED_ONLY_OUTSIDE_ALLOWLIST", "projectedRelevantFields": "CLOSED_WORLD_EXACT_MATCH", "arraySemantics": {"providerSets": "UNORDERED_EXACT_SET_SORT_BY_CANONICAL_PROJECTED_JSON", "orderedSequences": "EXPLICIT_OPERATION_SCHEMA_ONLY", "duplicates": "REJECT_BEFORE_CANONICALIZATION", "rawAdditiveObjectFields": "IGNORE_ONLY_OUTSIDE_PROJECTED_ALLOWLIST"}, "unorderedProviderSetOperations": ["list-authenticated-ssh-signing-keys", "list-public-ssh-signing-keys-for-d0-b04-user", "list-environments", "list-environment-branch-policies", "list-environment-secrets", "list-rulesets", "list-effective-main-rules", "list-organization-app-installations", "list-user-installation-repositories", "list-installation-repositories", "list-bootstrap-token-repositories", "list-release-token-repositories", "list-workflows", "list-open-candidate-pull-requests", "list-candidate-pull-request-reviews", "list-candidate-pull-request-files", "list-candidate-pull-request-commits", "list-candidate-check-runs", "list-release-workflow-runs", "get-release-run-jobs", "list-release-deployments", "list-release-deployment-statuses"], "reject": ["MISSING_REQUIRED_FIELD", "WRONG_JSON_TYPE", "UNKNOWN_ENUM", "DUPLICATE_ID_NAME_RULE_OR_BINDING", "AMBIGUOUS_MULTIPLE_MATCHING_RESOURCE", "INCOMPLETE_OR_UNBOUND_PAGINATION", "CROSS_RESOURCE_ID_MISMATCH", "WRONG_REPOSITORY_ID_OR_FULL_NAME", "STALE_REF_OID", "MISSING_PROVIDER_REQUEST_ID", "MISSING_API_VERSION", "RAW_BODY_DIGEST_MISMATCH", "PROJECTION_DIGEST_MISMATCH"], "contentReadback": {"bindGitBlobOid": True, "decodeBase64Strictly": True, "bindDecodedLength": True, "bindDecodedSha256": True, "rejectSymlinkSubmoduleOrDirectory": True}, "resourceSetRule": "EXACTLY_ONE_SELECTOR_MATCH_UNLESS_OPERATION_EXPLICITLY_PROJECTS_A_COMPLETE_SET"}
    page = [{"name": "per_page", "value": "100"}, {"name": "page", "value": "$page"}]
    common_reads = [
        github_rest_operation("get-repository", "ALL", "operatorAdmin", "GET", base, [200], projection="REPOSITORY_IDENTITY"),
        github_rest_operation("get-main-ref", "ALL", "operatorAdmin", "GET", f"{base}/git/ref/heads/{source_branch}", [200], projection="SOURCE_REF"),
        github_rest_operation("get-authenticated-signing-user", "ALL", "signerGithubUser", "GET", "/user", [200], projection="SIGNING_KEY_REGISTRATION_AND_READBACK"),
        github_rest_operation("list-authenticated-ssh-signing-keys", "ALL", "signerGithubUser", "GET", "/user/ssh_signing_keys", [200], query_template=page, pagination=True, projection="SIGNING_KEY_REGISTRATION_AND_READBACK"),
        github_rest_operation("list-public-ssh-signing-keys-for-d0-b04-user", "ALL", "publicAnonymous", "GET", "/users/$binding:signerGithubLogin/ssh_signing_keys", [200], query_template=page, pagination=True, projection="SIGNING_KEY_REGISTRATION_AND_READBACK"),
        github_rest_operation("get-d0-b04-ssh-signing-key", "ALL", "signerGithubUser", "GET", "/user/ssh_signing_keys/$binding:signerProviderSshSigningKeyId", [200], projection="SIGNING_KEY_REGISTRATION_AND_READBACK"),
        github_rest_operation("get-d0-b04-ssh-signing-key-presence", "ROLLBACK", "signerGithubUser", "GET", "/user/ssh_signing_keys/$binding:signerProviderSshSigningKeyId", [200, 404], projection="SIGNING_KEY_REGISTRATION_AND_READBACK"),
        github_rest_operation("list-environments", "ALL", "operatorAdmin", "GET", f"{base}/environments", [200], query_template=page, pagination=True, projection="ENVIRONMENT_SET"),
        github_rest_operation("list-environment-secrets", "ALL", "operatorAdmin", "GET", f"{base}/environments/{environment_name}/secrets", [200], query_template=page, pagination=True, projection="ENVIRONMENT_SECRET_METADATA_SET"),
        github_rest_operation("get-temporary-bootstrap-ref-presence", "ROLLBACK", "operatorAdmin", "GET", f"{base}/git/ref/heads/pkgre-{catalog_id}-bootstrap-b", [200, 404], projection="BOOTSTRAP_COMMIT_AND_REF_ADVANCE"),
        github_rest_operation("get-temporary-release-ref-presence", "ROLLBACK", "operatorAdmin", "GET", f"{base}/git/ref/heads/pkgre-{catalog_id}-release-c-prime", [200, 404], projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("get-bootstrap-commit", "BOOTSTRAP_OR_ROLLBACK_IF_BOUND", "operatorAdmin", "GET", f"{base}/git/commits/$binding:bootstrapCommitB", [200], projection="BOOTSTRAP_COMMIT_AND_REF_ADVANCE"),
        github_rest_operation("get-signed-release-commit", "NORMAL_RELEASE_OR_ROLLBACK_IF_BOUND", "operatorAdmin", "GET", f"{base}/git/commits/$binding:signedReleaseCommitCPrime", [200], projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("get-actions-permissions", "ALL", "operatorAdmin", "GET", f"{base}/actions/permissions", [200], projection="ACTIONS_POLICY_READBACK"),
        github_rest_operation("get-selected-actions", "ALL", "operatorAdmin", "GET", f"{base}/actions/permissions/selected-actions", [200], projection="ACTIONS_POLICY_READBACK"),
        github_rest_operation("get-default-workflow-permissions", "ALL", "operatorAdmin", "GET", f"{base}/actions/permissions/workflow", [200], projection="ACTIONS_POLICY_READBACK"),
        github_rest_operation("get-fork-pr-approval-policy", "ALL", "operatorAdmin", "GET", f"{base}/actions/permissions/fork-pr-contributor-approval", [200], projection="ACTIONS_POLICY_READBACK"),
        github_rest_operation("list-rulesets", "ALL", "operatorAdmin", "GET", f"{base}/rulesets", [200], query_template=[{"name": "includes_parents", "value": "false"}, {"name": "targets", "value": "branch"}, *page], pagination=True, projection="RULESET_SET"),
        github_rest_operation("get-invariant-ruleset", "ALL", "operatorAdmin", "GET", f"{base}/rulesets/$binding:invariantRulesetId", [200], projection="INVARIANT_RULESET_ID_AND_READBACK"),
        github_rest_operation("get-invariant-ruleset-presence", "ROLLBACK", "operatorAdmin", "GET", f"{base}/rulesets/$binding:invariantRulesetId", [200, 404], projection="INVARIANT_RULESET_ID_AND_READBACK"),
        github_rest_operation("get-admission-ruleset", "ALL", "operatorAdmin", "GET", f"{base}/rulesets/$binding:admissionRulesetId", [200], projection="ADMISSION_RULESET_ID_AND_READBACK"),
        github_rest_operation("get-admission-ruleset-presence", "ROLLBACK", "operatorAdmin", "GET", f"{base}/rulesets/$binding:admissionRulesetId", [200, 404], projection="ADMISSION_RULESET_ID_AND_READBACK"),
        github_rest_operation("list-effective-main-rules", "ALL", "operatorAdmin", "GET", f"{base}/rules/branches/{source_branch}", [200], query_template=page, pagination=True, projection="EFFECTIVE_MAIN_RULES_READBACK"),
        github_rest_operation("get-classic-branch-protection", "ALL", "operatorAdmin", "GET", f"{base}/branches/{source_branch}/protection", [200, 404], projection="CLASSIC_BRANCH_PROTECTION_FINAL_READBACK"),
        github_rest_operation("get-release-environment", "ALL", "operatorAdmin", "GET", f"{base}/environments/{environment_name}", [200], projection="PROTECTED_ENVIRONMENT_ID_AND_READBACK"),
        github_rest_operation("list-environment-branch-policies", "ALL", "operatorAdmin", "GET", f"{base}/environments/{environment_name}/deployment-branch-policies", [200], query_template=page, pagination=True, projection="PROTECTED_ENVIRONMENT_ID_AND_READBACK"),
        github_rest_operation("get-environment-reviewer-user", "ALL", "operatorAdmin", "GET", f"/users/{reviewer}", [200], projection="REVIEWER_IDENTITY"),
        github_rest_operation("get-environment-reviewer-permission", "ALL", "operatorAdmin", "GET", f"{base}/collaborators/{reviewer}/permission", [200], projection="REVIEWER_REPOSITORY_PERMISSION"),
        github_rest_operation("get-release-dispatcher-user", "ALL", "operatorAdmin", "GET", f"/users/{dispatcher}", [200], projection="DISPATCHER_IDENTITY"),
        github_rest_operation("get-release-dispatcher-permission", "ALL", "operatorAdmin", "GET", f"{base}/collaborators/{dispatcher}/permission", [200], projection="DISPATCHER_REPOSITORY_PERMISSION"),
        github_rest_operation("get-release-app", "ALL", "operatorAdmin", "GET", f"/apps/{writer_slug}", [200, 404], projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK"),
        github_rest_operation("get-release-app-installation", "ALL", "releaseAppJwt", "GET", "/app/installations/$binding:releaseAppInstallationId", [200], projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK"),
        github_rest_operation("list-organization-app-installations", "ALL", "operatorAdmin", "GET", f"/orgs/{owner}/installations", [200], query_template=page, pagination=True, projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK"),
        github_rest_operation("list-user-installation-repositories", "ALL", "operatorAdmin", "GET", "/user/installations/$binding:releaseAppInstallationId/repositories", [200], query_template=page, pagination=True, projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK"),
        github_rest_operation("list-installation-repositories", "ALL", "releaseInstallationReadToken", "GET", "/installation/repositories", [200], query_template=page, pagination=True, projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK"),
        github_rest_operation("prove-release-installation-read-token-revoked", "CONFIGURE", "revokedReleaseInstallationReadToken", "GET", "/installation/repositories", [401], projection="TOKEN_REVOCATION_NEGATIVE_AUTH"),
        github_rest_operation("list-bootstrap-token-repositories", "BOOTSTRAP", "bootstrapInstallationWriteToken", "GET", "/installation/repositories", [200], query_template=page, pagination=True, projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK"),
        github_rest_operation("list-release-token-repositories", "NORMAL_RELEASE", "releaseInstallationWriteToken", "GET", "/installation/repositories", [200], query_template=page, pagination=True, projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("prove-bootstrap-installation-token-revoked", "BOOTSTRAP", "revokedBootstrapInstallationWriteToken", "GET", "/installation/repositories", [401], projection="TOKEN_REVOCATION_NEGATIVE_AUTH"),
        github_rest_operation("prove-release-installation-token-revoked", "NORMAL_RELEASE", "revokedReleaseInstallationWriteToken", "GET", "/installation/repositories", [401], projection="TOKEN_REVOCATION_NEGATIVE_AUTH"),
        github_rest_operation("list-workflows", "ALL", "operatorAdmin", "GET", f"{base}/actions/workflows", [200], query_template=page, pagination=True, projection="WORKFLOW_SET"),
        github_rest_operation("get-candidate-workflow", "ALL", "operatorAdmin", "GET", f"{base}/actions/workflows/$binding:candidateWorkflowId", [200], projection="CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK"),
        github_rest_operation("get-release-workflow", "ALL", "operatorAdmin", "GET", f"{base}/actions/workflows/$binding:releaseWorkflowId", [200], projection="RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK"),
        github_rest_operation("get-pages-workflow", "ALL", "operatorAdmin", "GET", f"{base}/actions/workflows/$binding:pagesWorkflowId", [200], projection="PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK"),
        github_rest_operation("get-candidate-workflow-content-at-a", "PRE_MUTATION_CAPTURE", "operatorAdmin", "GET", f"{base}/contents/{candidate_path}", [200, 404], query_template=[{"name": "ref", "value": source_tip}], projection="D2_PRE_MUTATION_CAPTURE"),
        github_rest_operation("get-release-workflow-content-at-a", "PRE_MUTATION_CAPTURE", "operatorAdmin", "GET", f"{base}/contents/{release_path}", [200, 404], query_template=[{"name": "ref", "value": source_tip}], projection="D2_PRE_MUTATION_CAPTURE"),
        github_rest_operation("get-pages-workflow-content-at-a", "PRE_MUTATION_CAPTURE", "operatorAdmin", "GET", f"{base}/contents/{pages_path}", [200], query_template=[{"name": "ref", "value": source_tip}], projection="D2_PRE_MUTATION_CAPTURE"),
        github_rest_operation("get-candidate-workflow-content-at-b", "BOOTSTRAP", "operatorAdmin", "GET", f"{base}/contents/{candidate_path}", [200], query_template=[{"name": "ref", "value": "$binding:bootstrapCommitB"}], projection="CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK"),
        github_rest_operation("get-release-workflow-content-at-b", "BOOTSTRAP", "operatorAdmin", "GET", f"{base}/contents/{release_path}", [200], query_template=[{"name": "ref", "value": "$binding:bootstrapCommitB"}], projection="RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK"),
        github_rest_operation("get-pages-workflow-content-at-b", "BOOTSTRAP", "operatorAdmin", "GET", f"{base}/contents/{pages_path}", [200], query_template=[{"name": "ref", "value": "$binding:bootstrapCommitB"}], projection="PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK"),
        github_rest_operation("list-open-candidate-pull-requests", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/pulls", [200], query_template=[{"name": "state", "value": "open"}, {"name": "base", "value": source_branch}, *page], pagination=True, projection="PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING"),
        github_rest_operation("get-candidate-pull-request", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/pulls/$binding:pullRequestNumber", [200], projection="PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING"),
        github_rest_operation("list-candidate-pull-request-reviews", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/pulls/$binding:pullRequestNumber/reviews", [200], query_template=page, pagination=True, projection="PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING"),
        github_rest_operation("list-candidate-pull-request-files", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/pulls/$binding:pullRequestNumber/files", [200], query_template=page, pagination=True, projection="PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING"),
        github_rest_operation("list-candidate-pull-request-commits", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/pulls/$binding:pullRequestNumber/commits", [200], query_template=page, pagination=True, projection="PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING"),
        github_rest_operation("list-candidate-check-runs", "ALL", "operatorAdmin", "GET", f"{base}/commits/$binding:candidateTreeCommitOid/check-runs", [200], query_template=[{"name": "check_name", "value": check_context}, {"name": "filter", "value": "latest"}, *page], pagination=True, projection="CANDIDATE_CHECK_PRODUCER_ID_AND_RUN"),
        github_rest_operation("list-release-workflow-runs", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/actions/workflows/$binding:releaseWorkflowId/runs", [200], query_template=[{"name": "event", "value": "workflow_dispatch"}, {"name": "branch", "value": source_branch}, *page], pagination=True, projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("get-release-workflow-run", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/actions/runs/$binding:releaseWorkflowRunId", [200], projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("get-release-run-jobs", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/actions/runs/$binding:releaseWorkflowRunId/jobs", [200], query_template=page, pagination=True, projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("get-release-pending-deployments", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/actions/runs/$binding:releaseWorkflowRunId/pending_deployments", [200], projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("get-release-pending-deployments-as-reviewer", "NORMAL_RELEASE", "reviewerUser", "GET", f"{base}/actions/runs/$binding:releaseWorkflowRunId/pending_deployments", [200], projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("list-release-deployments", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/deployments", [200], query_template=[{"name": "environment", "value": environment_name}, *page], pagination=True, projection="FIRST_NORMAL_RELEASE_RUN"),
        github_rest_operation("list-release-deployment-statuses", "NORMAL_RELEASE", "operatorAdmin", "GET", f"{base}/deployments/$binding:releaseDeploymentId/statuses", [200], query_template=page, pagination=True, projection="FIRST_NORMAL_RELEASE_RUN"),
    ]
    operation_by_id = {operation["operationId"]: operation for operation in common_reads}
    operation_by_id["list-workflows"]["workflowBindingSelection"] = {
        "matchSemantics": "EXACTLY_ONE_PATH_AND_NAME_MATCH_PER_BINDING_FROM_COMPLETE_UNORDERED_PAGINATED_SET",
        "completePaginationRequiredBeforeBinding": True,
        "providerSetOrderSignificant": False,
        "duplicateIdPathOrNameRejected": True,
        "pathNameSubstitutionAllowed": False,
        "bindings": [
            {"binding": "candidateWorkflowId", "expectedPath": candidate_path, "expectedName": candidate_name},
            {"binding": "releaseWorkflowId", "expectedPath": release_path, "expectedName": release_name},
            {"binding": "pagesWorkflowId", "expectedPath": pages_path, "expectedName": pages_name},
        ],
    }
    for operation_id, binding_name, expected_path, expected_name in (
        ("get-candidate-workflow", "candidateWorkflowId", candidate_path, candidate_name),
        ("get-release-workflow", "releaseWorkflowId", release_path, release_name),
        ("get-pages-workflow", "pagesWorkflowId", pages_path, pages_name),
    ):
        operation_by_id[operation_id]["workflowIdentityReadback"] = {
            "requestPathUsesNumericIdBinding": True,
            "binding": binding_name,
            "expectedPath": expected_path,
            "expectedName": expected_name,
            "returnedNumericIdMustEqualBinding": True,
            "returnedPathAndNameMustMatchExactly": True,
            "returnedStateMustBeProjected": True,
            "filenameOrPathLookupForbidden": True,
        }
    operation_by_id["list-candidate-check-runs"]["checkProducerBindingSelection"] = {
        "matchSemantics": "EXACTLY_ONE_CONTEXT_HEAD_SHA_WORKFLOW_RUN_WORKFLOW_AND_JOB_PRODUCER_MATCH_FROM_COMPLETE_UNORDERED_PAGINATED_SET",
        "context": check_context,
        "headShaBinding": "candidateTreeCommitOid",
        "workflowIdBinding": "candidateWorkflowId",
        "bindWorkflowRunIdAndJobId": True,
        "arrayPositionSelectionForbidden": True,
        "selectedAppIdBinding": "candidateCheckIntegrationId",
    }
    user_installation_repository_read = next(operation for operation in common_reads if operation["operationId"] == "list-user-installation-repositories")
    user_installation_repository_read["pinnedOpenApiSemantics"] = {"operationId": "apps/list-installation-repos-for-authenticated-user", "summary": "List repositories accessible to the user access token", "githubAppsEnabled": False, "authentication": "GITHUB_USER_ACCESS_TOKEN_WITH_EXPLICIT_READ_WRITE_OR_ADMIN_PERMISSION_TO_EACH_RETURNED_REPOSITORY", "exactInstallationIdBinding": "releaseAppInstallationId", "admittedStatus": 200, "purpose": "CURRENT_INSTALLATION_REPOSITORY_READBACK_WITHOUT_REUSING_A_REVOKED_INSTALLATION_TOKEN", "operatorAdminProfileIsProceduralUserCredentialNotInstallationCredential": True}
    rest_mutations = [
        github_rest_operation("create-d0-b04-ssh-signing-key-if-baseline-absent", "CONFIGURE", "signerGithubUser", "POST", "/user/ssh_signing_keys", [201], body_template=signing_identity["providerRegistration"]["requestBody"], projection="SIGNING_KEY_REGISTRATION_AND_READBACK", follow_up_readbacks=["get-d0-b04-ssh-signing-key", "list-public-ssh-signing-keys-for-d0-b04-user"]),
        github_rest_operation("delete-d0-b04-ssh-signing-key", "ROLLBACK", "signerGithubUser", "DELETE", "/user/ssh_signing_keys/$binding:signerProviderSshSigningKeyId", [204], projection="SIGNING_KEY_REGISTRATION_AND_READBACK", follow_up_readbacks=["get-d0-b04-ssh-signing-key-presence", "list-public-ssh-signing-keys-for-d0-b04-user"]),
        github_rest_operation("set-actions-permissions", "CONFIGURE", "operatorAdmin", "PUT", f"{base}/actions/permissions", [204], body_template={"enabled": True, "allowed_actions": "selected", "sha_pinning_required": True}, projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-actions-permissions"]),
        github_rest_operation("set-selected-actions", "CONFIGURE", "operatorAdmin", "PUT", f"{base}/actions/permissions/selected-actions", [204], body_template={"github_owned_allowed": False, "verified_allowed": False, "patterns_allowed": actions["selectedPolicy"]["patternsAllowed"]}, projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-selected-actions"]),
        github_rest_operation("set-default-workflow-permissions", "CONFIGURE", "operatorAdmin", "PUT", f"{base}/actions/permissions/workflow", [204], body_template={"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}, projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-default-workflow-permissions"]),
        github_rest_operation("set-fork-pr-approval-policy", "CONFIGURE", "operatorAdmin", "PUT", f"{base}/actions/permissions/fork-pr-contributor-approval", [204], body_template=actions["providerRequestBodies"]["forkPullRequestApproval"], projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-fork-pr-approval-policy"]),
        github_rest_operation("restore-actions-permissions-from-pre-capture", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/actions/permissions", [204], body_template=github_binding("preCaptureActionsPermissionsRequestBody", "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE"), projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-actions-permissions"], pre_capture_restore={"binding": "preCaptureActionsPermissionsRequestBody", "captureOperationId": "get-actions-permissions", "readbackOperationId": "get-actions-permissions"}),
        github_rest_operation("restore-selected-actions-from-pre-capture", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/actions/permissions/selected-actions", [204], body_template=github_binding("preCaptureSelectedActionsRequestBody", "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE"), projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-selected-actions"], pre_capture_restore={"binding": "preCaptureSelectedActionsRequestBody", "captureOperationId": "get-selected-actions", "readbackOperationId": "get-selected-actions"}),
        github_rest_operation("restore-default-workflow-permissions-from-pre-capture", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/actions/permissions/workflow", [204], body_template=github_binding("preCaptureDefaultWorkflowPermissionsRequestBody", "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE"), projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-default-workflow-permissions"], pre_capture_restore={"binding": "preCaptureDefaultWorkflowPermissionsRequestBody", "captureOperationId": "get-default-workflow-permissions", "readbackOperationId": "get-default-workflow-permissions"}),
        github_rest_operation("restore-fork-pr-approval-policy-from-pre-capture", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/actions/permissions/fork-pr-contributor-approval", [204], body_template=github_binding("preCaptureForkPrApprovalPolicyRequestBody", "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE"), projection="ACTIONS_POLICY_READBACK", follow_up_readbacks=["get-fork-pr-approval-policy"], pre_capture_restore={"binding": "preCaptureForkPrApprovalPolicyRequestBody", "captureOperationId": "get-fork-pr-approval-policy", "readbackOperationId": "get-fork-pr-approval-policy"}),
        github_rest_operation("put-release-environment", "CONFIGURE", "operatorAdmin", "PUT", f"{base}/environments/{environment_name}", [200], body_template={"wait_timer": 0, "prevent_self_review": True, "reviewers": [{"type": "User", "id": github_binding("reviewerUserId")}], "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}, projection="PROTECTED_ENVIRONMENT_ID_AND_READBACK", follow_up_readbacks=["get-release-environment"]),
        github_rest_operation("create-environment-main-policy", "CONFIGURE", "operatorAdmin", "POST", f"{base}/environments/{environment_name}/deployment-branch-policies", [200], body_template={"name": source_branch, "type": "branch"}, projection="PROTECTED_ENVIRONMENT_ID_AND_READBACK", follow_up_readbacks=["list-environment-branch-policies"]),
        github_rest_operation("create-admission-ruleset-bootstrap", "BOOTSTRAP", "operatorAdmin", "POST", f"{base}/rulesets", [201], body_template=admission_ruleset["providerCreateRequestBody"], projection="ADMISSION_RULESET_ID_AND_READBACK", follow_up_readbacks=["get-admission-ruleset"]),
        github_rest_operation("update-admission-ruleset-to-final", "BOOTSTRAP", "operatorAdmin", "PUT", f"{base}/rulesets/$binding:admissionRulesetId", [200], body_template=admission_ruleset["providerFinalUpdateRequestBody"], projection="ADMISSION_RULESET_ID_AND_READBACK", follow_up_readbacks=["get-admission-ruleset", "list-effective-main-rules"]),
        github_rest_operation("create-invariant-ruleset", "BOOTSTRAP", "operatorAdmin", "POST", f"{base}/rulesets", [201], body_template=invariant_ruleset["providerCreateRequestBody"], projection="INVARIANT_RULESET_ID_AND_READBACK", follow_up_readbacks=["get-invariant-ruleset", "list-effective-main-rules"]),
        github_rest_operation("delete-classic-branch-protection-if-baseline-present", "BOOTSTRAP", "operatorAdmin", "DELETE", f"{base}/branches/{source_branch}/protection", [204], projection="CLASSIC_BRANCH_PROTECTION_FINAL_READBACK", follow_up_readbacks=["get-classic-branch-protection"]),
        github_rest_operation("restore-classic-branch-protection-from-pre-capture", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/branches/{source_branch}/protection", [200], body_template=github_binding("preCaptureClassicProtectionRequestBody", "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE"), projection="CLASSIC_BRANCH_PROTECTION_FINAL_READBACK", follow_up_readbacks=["get-classic-branch-protection", "list-effective-main-rules"], pre_capture_restore={"binding": "preCaptureClassicProtectionRequestBody", "captureOperationId": "get-classic-branch-protection", "readbackOperationId": "get-classic-branch-protection"}),
        github_rest_operation("mint-release-installation-read-token", "CONFIGURE", "releaseAppJwt", "POST", "/app/installations/$binding:releaseAppInstallationId/access_tokens", [201], body_template={"repository_ids": [repository_id], "permissions": {"metadata": "read"}}, projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK", secret_response=True, follow_up_readbacks=["list-installation-repositories"]),
        github_rest_operation("revoke-release-installation-read-token", "CONFIGURE", "releaseInstallationReadToken", "DELETE", "/installation/token", [204], projection="TOKEN_REVOCATION_NEGATIVE_AUTH", follow_up_readbacks=["prove-release-installation-read-token-revoked"]),
        github_rest_operation("mint-bootstrap-installation-token", "BOOTSTRAP", "releaseAppJwt", "POST", "/app/installations/$binding:releaseAppInstallationId/access_tokens", [201], body_template={"repository_ids": [repository_id], "permissions": {"contents": "write", "metadata": "read"}}, projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK", secret_response=True, follow_up_readbacks=["list-bootstrap-token-repositories"]),
        github_rest_operation("patch-main-ref-bootstrap-force-false", "BOOTSTRAP", "bootstrapInstallationWriteToken", "PATCH", f"{base}/git/refs/heads/{source_branch}", [200], body_template={"sha": github_binding("bootstrapCommitB", "LOWERCASE_SHA1_40"), "force": False}, projection="BOOTSTRAP_COMMIT_AND_REF_ADVANCE", follow_up_readbacks=["get-main-ref", "get-bootstrap-commit"]),
        github_rest_operation("revoke-bootstrap-installation-token", "BOOTSTRAP", "bootstrapInstallationWriteToken", "DELETE", "/installation/token", [204], projection="TOKEN_REVOCATION_NEGATIVE_AUTH", follow_up_readbacks=["prove-bootstrap-installation-token-revoked"]),
        github_rest_operation("dispatch-release-workflow-on-main", "NORMAL_RELEASE", "dispatcherUser", "POST", f"{base}/actions/workflows/$binding:releaseWorkflowId/dispatches", [204], body_template={"ref": source_branch, "inputs": {"candidate_sha": github_binding("candidateTreeCommitOid", "LOWERCASE_SHA1_40")}}, projection="FIRST_NORMAL_RELEASE_RUN", follow_up_readbacks=["list-release-workflow-runs"]),
        github_rest_operation("review-release-pending-deployment", "NORMAL_RELEASE", "reviewerUser", "POST", f"{base}/actions/runs/$binding:releaseWorkflowRunId/pending_deployments", [200], body_template={"environment_ids": [github_binding("pendingDeploymentEnvironmentId")], "state": "approved", "comment": "pkgre reviewed release approval"}, projection="FIRST_NORMAL_RELEASE_RUN", follow_up_readbacks=["list-release-deployments", "list-release-deployment-statuses"]),
        github_rest_operation("mint-release-installation-token-after-approval", "NORMAL_RELEASE", "releaseAppJwt", "POST", "/app/installations/$binding:releaseAppInstallationId/access_tokens", [201], body_template={"repository_ids": [repository_id], "permissions": {"contents": "write", "metadata": "read"}}, projection="FIRST_NORMAL_RELEASE_RUN", secret_response=True, follow_up_readbacks=["list-release-token-repositories"]),
        github_rest_operation("patch-main-ref-release-force-false", "NORMAL_RELEASE", "releaseInstallationWriteToken", "PATCH", f"{base}/git/refs/heads/{source_branch}", [200], body_template={"sha": github_binding("signedReleaseCommitCPrime", "LOWERCASE_SHA1_40"), "force": False}, projection="FIRST_NORMAL_RELEASE_RUN", follow_up_readbacks=["get-main-ref", "get-signed-release-commit"]),
        github_rest_operation("revoke-release-installation-token", "NORMAL_RELEASE", "releaseInstallationWriteToken", "DELETE", "/installation/token", [204], projection="TOKEN_REVOCATION_NEGATIVE_AUTH", follow_up_readbacks=["prove-release-installation-token-revoked"]),
        github_rest_operation("disable-release-workflow", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/actions/workflows/$binding:releaseWorkflowId/disable", [204], projection="RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK", follow_up_readbacks=["get-release-workflow"]),
        github_rest_operation("enable-release-workflow", "ROLLBACK", "operatorAdmin", "PUT", f"{base}/actions/workflows/$binding:releaseWorkflowId/enable", [204], projection="RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK", follow_up_readbacks=["get-release-workflow"]),
        github_rest_operation("suspend-release-app-installation", "ROLLBACK", "releaseAppJwt", "PUT", "/app/installations/$binding:releaseAppInstallationId/suspended", [204], projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK", follow_up_readbacks=["get-release-app-installation"]),
        github_rest_operation("unsuspend-release-app-installation", "ROLLBACK", "releaseAppJwt", "DELETE", "/app/installations/$binding:releaseAppInstallationId/suspended", [204], projection="RELEASE_APP_INSTALLATION_ID_AND_READBACK", follow_up_readbacks=["get-release-app-installation"]),
        github_rest_operation("delete-admission-ruleset", "ROLLBACK", "operatorAdmin", "DELETE", f"{base}/rulesets/$binding:admissionRulesetId", [204, 404], projection="ADMISSION_RULESET_ID_AND_READBACK", follow_up_readbacks=["list-rulesets"]),
        github_rest_operation("delete-invariant-ruleset", "ROLLBACK", "operatorAdmin", "DELETE", f"{base}/rulesets/$binding:invariantRulesetId", [204, 404], projection="INVARIANT_RULESET_ID_AND_READBACK", follow_up_readbacks=["list-rulesets"]),
        github_rest_operation("delete-environment-main-policy", "ROLLBACK", "operatorAdmin", "DELETE", f"{base}/environments/{environment_name}/deployment-branch-policies/$binding:environmentBranchPolicyId", [204], projection="PROTECTED_ENVIRONMENT_ID_AND_READBACK", follow_up_readbacks=["list-environment-branch-policies"]),
        github_rest_operation("delete-release-environment", "ROLLBACK", "operatorAdmin", "DELETE", f"{base}/environments/{environment_name}", [204], projection="PROTECTED_ENVIRONMENT_ID_AND_READBACK", follow_up_readbacks=["list-environments"]),
        github_rest_operation("delete-temporary-bootstrap-ref", "ROLLBACK", "operatorAdmin", "DELETE", f"{base}/git/refs/heads/pkgre-{catalog_id}-bootstrap-b", [204, 409, 422], projection="BOOTSTRAP_COMMIT_AND_REF_ADVANCE", follow_up_readbacks=["get-temporary-bootstrap-ref-presence"]),
        github_rest_operation("delete-temporary-release-ref", "ROLLBACK", "operatorAdmin", "DELETE", f"{base}/git/refs/heads/pkgre-{catalog_id}-release-c-prime", [204, 409, 422], projection="FIRST_NORMAL_RELEASE_RUN", follow_up_readbacks=["get-temporary-release-ref-presence"]),
    ]
    omitted_mutation_ids = {"enable-release-workflow", "unsuspend-release-app-installation", "delete-environment-main-policy", "delete-release-environment"}
    if catalog_id == "js":
        omitted_mutation_ids.update({"delete-classic-branch-protection-if-baseline-present", "restore-classic-branch-protection-from-pre-capture"})
    rest_mutations = [operation for operation in rest_mutations if operation["operationId"] not in omitted_mutation_ids]
    rest_operations = common_reads + rest_mutations
    non_rest_operations = [
        {"operationId": "bind-d0-b04-catalog-signing-identity", "phase": "CONFIGURE", "actorProfile": "operatorSigningAuthority", "channel": "D0_B04_OPERATOR_HANDOFF", "preconditions": ["D0_B04_EXACT_CATALOG_SIGNING_DESIGN_AUTHORIZED"], "procedure": ["READ_ONLY_PUBLIC_GITHUB_LOGIN_SSH_ED25519_PUBLIC_KEY_SHA256_FINGERPRINT_AND_PROVIDER_TITLE", "RECOMPUTE_FINGERPRINT_FROM_PUBLIC_KEY", "REJECT_SHARED_RUST_JS_SIGNING_IDENTITY", "DO_NOT_READ_PRIVATE_KEY_OR_SECRET_DIGEST"], "outputs": ["GITHUB_LOGIN", "SSH_ED25519_PUBLIC_KEY", "SSH_SHA256_FINGERPRINT", "PROVIDER_KEY_TITLE", "D0_B04_ARTIFACT_SHA256"], "forbiddenCapture": ["PRIVATE_KEY", "SECRET_VALUE", "SECRET_DIGEST"]},
        {"operationId": "resolve-d0-b04-provider-signing-key-binding", "phase": "CONFIGURE", "actorProfile": "signerGithubUser", "channel": "STRICT_PROVIDER_PROJECTION", "preconditions": ["FRESH_AUTHENTICATED_AND_PUBLIC_KEY_SETS_CAPTURED", "CREATE_COMPLETED_ONLY_IF_EXACT_KEY_ABSENT"], "procedure": ["SELECT_EXACTLY_ONE_KEY_MATCHING_D0_B04_PUBLIC_KEY_AND_TITLE", "BIND_ID_AND_CREATED_AT_FROM_AUTHENTICATED_READBACK", "REQUIRE_SAME_ID_KEY_TITLE_CREATED_AT_IN_PUBLIC_READBACK", "REJECT_AMBIGUOUS_DUPLICATE_OR_WRONG_LOGIN"], "outputs": ["PROVIDER_SSH_SIGNING_KEY_ID", "PROVIDER_CREATED_AT", "BASELINE_PRESENCE", "CREATED_BY_CEREMONY"], "forbiddenCapture": ["PRIVATE_KEY", "AUTHORIZATION_TOKEN", "SECRET_DIGEST"]},
        {"operationId": "operator-install-public-trust-without-returning-private-material", "phase": "CONFIGURE", "actorProfile": "operatorBootstrapWriter", "channel": "LOCAL_OPERATOR_CEREMONY", "preconditions": ["D0_B04_EXACT_PUBLIC_SIGNER_AND_REVOCATION_ARTIFACTS_AUTHORIZED"], "procedure": ["INSTALL_PUBLIC_ALLOWED_SIGNERS_AND_REVOCATION_SET_ONLY", "REJECT_PRIVATE_KEY_SECRET_OR_SECRET_DIGEST_IN_EVIDENCE"], "outputs": ["PUBLIC_ARTIFACT_PATH_LENGTH_SHA256", "INSTALLATION_TRANSCRIPT_SHA256"], "forbiddenCapture": ["PRIVATE_KEY", "SECRET_VALUE", "SECRET_DIGEST"]},
        {"operationId": "operator-install-app-and-environment-secret", "phase": "CONFIGURE", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI_AND_LOCAL_SECRET_STORE", "preconditions": ["APP_MANIFEST_AND_ONE_REPOSITORY_INSTALLATION_SCOPE_REVIEWED", "PROTECTED_ENVIRONMENT_EXISTS_OR_WILL_BE_CREATED_IN_SAME_CEREMONY"], "procedure": ["CREATE_OR_SELECT_CATALOG_SPECIFIC_GITHUB_APP", "INSTALL_ON_EXACT_REPOSITORY_ONLY", "STORE_PRIVATE_KEY_AS_PROTECTED_ENVIRONMENT_SECRET", "DO_NOT_RETURN_OR_HASH_SECRET_MATERIAL"], "outputs": ["APP_SLUG", "PROVIDER_APP_AND_INSTALLATION_READBACK_REFERENCES", "SECRET_NAME_AND_SCOPE_READBACK_REFERENCE"], "forbiddenCapture": ["APP_PRIVATE_KEY", "ENVIRONMENT_SECRET_VALUE", "SECRET_CIPHERTEXT", "SECRET_DIGEST"]},
        {"operationId": "capture-environment-admin-bypass-ui-readback", "phase": "CONFIGURE", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI", "preconditions": ["ENVIRONMENT_CREATED", "CORRECT_REPOSITORY_ID_VISIBLE"], "procedure": ["OPEN_EXACT_ENVIRONMENT_PROTECTION_SETTINGS", "CAPTURE_PROVIDER_RENDERED_ADMIN_BYPASS_DISABLED_STATE", "BIND_AUTHENTICATED_ACTOR_REPOSITORY_ENVIRONMENT_URL_AND_UTC", "CORRELATE_PROVIDER_AUDIT_WINDOW"], "outputs": ["PROVIDER_UI_ARCHIVE_SHA256", "REDACTED_DOM_PROJECTION_SHA256", "AUDIT_RECORD_IDS"], "forbiddenCapture": ["COOKIE", "AUTHORIZATION_TOKEN", "SECRET_VALUE", "OPERATOR_SELF_ATTESTATION_AS_SUBSTITUTE"]},
        {"operationId": "capture-environment-secret-name-and-scope-ui-readback", "phase": "CONFIGURE", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI", "preconditions": ["ENVIRONMENT_SECRET_INSTALLED"], "procedure": ["CAPTURE_ONLY_SECRET_NAME_SCOPE_AND_UPDATED_METADATA", "PROVE_SECRET_SCOPED_TO_EXACT_RELEASE_ENVIRONMENT"], "outputs": ["SECRET_METADATA_PROJECTION_SHA256", "PROVIDER_UI_ARCHIVE_SHA256"], "forbiddenCapture": ["SECRET_VALUE", "SECRET_CIPHERTEXT", "SECRET_DIGEST", "COOKIE", "AUTHORIZATION_TOKEN"]},
        {"operationId": "operator-create-ssh-ed25519-signed-bootstrap-b", "phase": "BOOTSTRAP", "actorProfile": "operatorBootstrapWriter", "channel": "LOCAL_GIT", "preconditions": ["FRESH_BASELINE_A_READBACK", "FROZEN_BOOTSTRAP_TREE_DIGEST_APPROVED", "D0_B04_SIGNER_AVAILABLE"], "procedure": ["CREATE_COMMIT_B_WITH_EXACT_FROZEN_TREE", "SET_SOLE_PARENT_TO_BASELINE_A", "SIGN_WITH_EXACT_D0_B04_SSH_ED25519_KEY"], "outputs": ["COMMIT_OID", "TREE_OID", "SOLE_PARENT_OID", "SIGNER_PRINCIPAL"], "forbiddenCapture": ["SIGNING_PRIVATE_KEY", "SIGNING_AGENT_SECRET"]},
        {"operationId": "local-git-verify-commit-raw-bootstrap-b", "phase": "BOOTSTRAP_OR_ROLLBACK_IF_BOUND", "actorProfile": "operatorBootstrapWriter", "channel": "LOCAL_GIT", "preconditions": ["BOOTSTRAP_B_OBJECT_AVAILABLE", "FROZEN_ALLOWED_SIGNERS_INSTALLED"], "procedure": ["RUN_GIT_CONFIG_GPG_FORMAT_SSH_ALLOWED_SIGNERS_VERIFY_COMMIT_RAW", "REQUIRE_EXACT_PRINCIPAL_KEY_FINGERPRINT_AND_GOOD_SIGNATURE"], "outputs": ["COMMAND_ARGV", "GIT_VERSION", "EXIT_STATUS_ZERO", "STDOUT_STDERR_TRANSCRIPT_SHA256"], "forbiddenCapture": ["PRIVATE_KEY", "SIGNING_AGENT_SECRET"]},
        {"operationId": "git-smart-protocol-upload-bootstrap-b-to-temporary-ref", "phase": "BOOTSTRAP", "actorProfile": "operatorBootstrapWriter", "channel": "GIT_SMART_PROTOCOL_SSH", "preconditions": ["LOCAL_BOOTSTRAP_SIGNATURE_VERIFICATION_PASS", "MAIN_STILL_EQUALS_A"], "procedure": ["PUSH_B_TO_EXACT_TEMPORARY_REF_WITHOUT_FORCE", "READ_BACK_TEMPORARY_REF_AND_COMMIT_OBJECT", "DO_NOT_UPDATE_MAIN"], "outputs": ["COMMIT_OID", "TEMPORARY_REF", "PUSH_TRANSCRIPT_SHA256", "PROVIDER_READBACK_SHA256"], "forbiddenCapture": ["SSH_PRIVATE_KEY", "SSH_AGENT_SECRET"]},
        {"operationId": "run-bootstrap-candidate-producer-probe", "phase": "BOOTSTRAP", "actorProfile": "dispatcherUser", "channel": "GITHUB_PULL_REQUEST_AND_ACTIONS", "preconditions": ["MAIN_EQUALS_B", "CANDIDATE_WORKFLOW_CONTENT_READ_FROM_B", "CANDIDATE_WORKFLOW_NAME_AND_VALIDATE_JOB_ID_LITERAL_FROZEN", "JOB_NAME_LITERAL_EQUALS_REQUIRED_STATUS_CONTEXT", "NO_MATRIX_DYNAMIC_JOB_NAME_OR_REUSABLE_WORKFLOW_CALL"], "procedure": ["OPEN_OR_UPDATE_NON_GOVERNANCE_PROBE_PULL_REQUEST", "WAIT_FOR_EXACT_RENDERED_CANDIDATE_CHECK_RUN_NAME", "BIND_CHECK_RUN_APP_INTEGRATION_WORKFLOW_RUN_WORKFLOW_AND_JOB_IDS", "REQUIRE_WORKFLOW_PATH_NAME_JOB_ID_LITERAL_JOB_NAME_AND_RENDERED_CONTEXT_MATCH_FROZEN_DERIVATION", "CLOSE_PROBE_WITHOUT_MERGE"], "outputs": ["PULL_REQUEST_ID", "WORKFLOW_ID", "WORKFLOW_RUN_ID", "JOB_ID", "RENDERED_CHECK_CONTEXT", "CHECK_SUITE_ID", "CHECK_RUN_ID", "CHECK_INTEGRATION_ID"], "forbiddenCapture": ["WORKFLOW_SECRET", "WRITE_TOKEN", "CANDIDATE_WORKFLOW_SELF_AUTHORIZATION", "MATRIX_OR_DYNAMIC_CHECK_CONTEXT"]},
        {"operationId": "trusted-release-job-create-ssh-ed25519-signed-c-prime", "phase": "NORMAL_RELEASE", "actorProfile": "protectedReleaseJob", "channel": "TRUSTED_WORKFLOW_FROM_BOOTSTRAP_B_VIA_D0_B04_OPAQUE_SIGNER_INTERFACE", "preconditions": ["ENVIRONMENT_HUMAN_APPROVAL_COMPLETE", "RELEASE_JOB_IS_RUNNING_FROM_TRUSTED_WORKFLOW_BLOB", "EXACT_CATALOG_SIGNER_ACCESS_INTERFACE_AVAILABLE_ONLY_TO_RELEASE_JOB", "INTERFACE_PUBLIC_IDENTITY_PRINCIPAL_AND_FINGERPRINT_MATCH_D0_B04", "CANDIDATE_C0_AND_BASE_B_REVALIDATED", "TRUSTED_WORKFLOW_BLOB_BOUND_TO_B"], "procedure": ["BUILD_UNSIGNED_COMMIT_PAYLOAD_WITH_EXACT_C0_TREE_AND_SOLE_PARENT_B", "SEND_ONLY_DOMAIN_SEPARATED_BOUND_GIT_COMMIT_SIGN_REQUEST_TO_OPAQUE_INTERFACE", "RECEIVE_SSH_SIGNATURE_AND_PUBLIC_METADATA_ONLY", "VERIFY_RESPONSE_PRINCIPAL_PUBLIC_KEY_FINGERPRINT_NAMESPACE_ALGORITHM_AND_PAYLOAD_LOCALLY", "CREATE_C_PRIME_WITH_TREE_EXACTLY_C0_TREE_AND_SOLE_PARENT_EXACTLY_B", "BIND_FINAL_COMMIT_OID_TREE_PARENT_AND_SIGNATURE_METADATA"], "outputs": ["COMMIT_OID", "TREE_OID", "SOLE_PARENT_OID", "SSH_SIGNATURE", "SIGNATURE_METADATA", "SIGNER_INTERFACE_DESIGN_ID"], "forbiddenCapture": ["SIGNING_PRIVATE_KEY", "SIGNING_PRIVATE_KEY_DIGEST", "SIGNING_PRIVATE_KEY_CIPHERTEXT", "OPAQUE_SIGNER_HANDLE_MATERIAL", "ENVIRONMENT_SECRET", "INSTALLATION_TOKEN"]},
        {"operationId": "git-smart-protocol-upload-signed-release-c-prime-to-temporary-ref", "phase": "NORMAL_RELEASE", "actorProfile": "releaseInstallationWriteToken", "channel": "GIT_SMART_PROTOCOL_HTTPS", "preconditions": ["C_PRIME_STRUCTURE_AND_SIGNATURE_LOCALLY_VALID", "INSTALLATION_TOKEN_MINTED_AFTER_APPROVAL"], "procedure": ["PUSH_C_PRIME_TO_EXACT_TEMPORARY_REF_WITHOUT_FORCE", "READ_BACK_COMMIT_AND_TEMPORARY_REF", "KEEP_MAIN_UNCHANGED"], "outputs": ["COMMIT_OID", "TEMPORARY_REF", "PUSH_TRANSCRIPT_SHA256", "PROVIDER_READBACK_SHA256"], "forbiddenCapture": ["INSTALLATION_TOKEN", "AUTHORIZATION_HEADER", "SIGNING_PRIVATE_KEY"]},
        {"operationId": "local-git-verify-commit-raw-release-c-prime", "phase": "NORMAL_RELEASE_OR_ROLLBACK_IF_BOUND", "actorProfile": "operatorBootstrapWriter", "channel": "LOCAL_GIT", "preconditions": ["PROVIDER_C_PRIME_OBJECT_FETCHED", "FROZEN_ALLOWED_SIGNERS_INSTALLED"], "procedure": ["RUN_GIT_CONFIG_GPG_FORMAT_SSH_ALLOWED_SIGNERS_VERIFY_COMMIT_RAW", "REQUIRE_EXACT_PRINCIPAL_KEY_FINGERPRINT_AND_GOOD_SIGNATURE"], "outputs": ["COMMAND_ARGV", "GIT_VERSION", "EXIT_STATUS_ZERO", "STDOUT_STDERR_TRANSCRIPT_SHA256"], "forbiddenCapture": ["PRIVATE_KEY", "SIGNING_AGENT_SECRET"]},
        {"operationId": "capture-provider-ui-audit-export", "phase": "ALL", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI_OR_PROVIDER_EXPORT", "preconditions": ["AUDIT_WINDOW_START_BOUND_TO_FRESH_PRE_MUTATION_CAPTURE"], "procedure": ["EXPORT_COMPLETE_PROVIDER_AUDIT_WINDOW", "BIND_EACH_MUTATION_TO_PROVIDER_ACTOR_RESOURCE_ACTION_RESULT_AND_UTC", "PROVE_NO_UNEXPLAINED_MUTATION", "REJECT_SELF_AUTHORED_SUMMARY_AS_EVIDENCE"], "outputs": ["PROVIDER_EXPORT_RAW_SHA256", "STRICT_AUDIT_PROJECTION_SHA256", "WINDOW_START_END", "RECORD_IDS"], "forbiddenCapture": ["COOKIE", "AUTHORIZATION_TOKEN", "OPERATOR_SELF_ATTESTATION_AS_SUBSTITUTE"]},
        {"operationId": "operator-remove-environment-secret", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI", "preconditions": ["ROLLBACK_TRIGGERED"], "procedure": ["DELETE_EXACT_RELEASE_ENVIRONMENT_SECRET", "CAPTURE_NAME_AND_ABSENCE_READBACK_ONLY"], "outputs": ["SECRET_NAME", "ABSENCE_READBACK_SHA256", "AUDIT_RECORD_IDS"], "forbiddenCapture": ["SECRET_VALUE", "SECRET_CIPHERTEXT", "SECRET_DIGEST"]},
        {"operationId": "operator-restore-environment-resources-from-pre-capture", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "REST_AND_AUTHENTICATED_PROVIDER_UI_FROM_FROZEN_PRE_CAPTURE", "preconditions": ["SOURCE_REF_FRESHLY_CLASSIFIED_AS_EXACT_A", "RAW_PRE_CAPTURE_COMPLETE", "CEREMONY_RESOURCE_LEDGER_COMPLETE"], "procedure": ["SELECT_EXACT_ENVIRONMENT_AND_BRANCH_POLICY_IDS_FROM_FRESH_CAPTURE_OR_CEREMONY_CREATE_RESPONSES", "RESTORE_BASELINE_EXISTING_ENVIRONMENT_AND_POLICY_FROM_TYPED_RAW_PRE_CAPTURE_REQUESTS", "DELETE_ONLY_BASELINE_ABSENT_CEREMONY_CREATED ENVIRONMENT_OR_POLICY", "PRESERVE_BASELINE SECRET METADATA_AND_NEVER_READ_VALUE_OR_DIGEST", "READ_BACK_EXACT IDS PROJECTIONS ABSENCE_AND_AUDIT"], "outputs": ["RESTORE_REQUEST_MANIFEST_SHA256", "RAW_READBACK_MANIFEST_SHA256", "PROJECTION_DIGEST_COMPARISON", "AUDIT_RECORD_IDS"], "forbiddenCapture": ["SECRET_VALUE", "SECRET_CIPHERTEXT", "SECRET_DIGEST", "HISTORICAL_D0_BASELINE_AS_FRESH_CAPTURE_SUBSTITUTE", "AMBIGUOUS_NAME_SELECTION"]},
        {"operationId": "operator-restore-app-installation-from-pre-capture", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI_AND_REST_FROM_FROZEN_PRE_CAPTURE", "preconditions": ["SOURCE_REF_FRESHLY_CLASSIFIED_AS_EXACT_A", "RAW_PRE_CAPTURE_COMPLETE", "CEREMONY_RESOURCE_LEDGER_COMPLETE"], "procedure": ["SELECT_EXACT APP INTEGRATION AND INSTALLATION IDS", "RESTORE BASELINE SUSPENSION AND ONE-REPOSITORY SELECTION STATE", "REMOVE A BASELINE-ABSENT CEREMONY-CREATED INSTALLATION ONLY THROUGH A SEPARATE EXPLICIT PROVIDER REMOVAL SUBCEREMONY", "READ_BACK APP INSTALLATION REPOSITORY IDS PERMISSIONS AND AUDIT"], "outputs": ["EXACT_APP_AND_INSTALLATION_IDS", "RAW_READBACK_MANIFEST_SHA256", "PROJECTION_DIGEST_COMPARISON", "AUDIT_RECORD_IDS"], "forbiddenCapture": ["APP_PRIVATE_KEY", "TOKEN", "SECRET_VALUE", "SECRET_DIGEST", "AMBIGUOUS_SLUG_OR_NAME_SELECTION"]},
        {"operationId": "operator-restore-workflow-state-from-pre-capture", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "REST_FROM_CURRENT_DEFAULT_BRANCH_AND_FROZEN_PRE_CAPTURE", "preconditions": ["SOURCE_REF_FRESHLY_CLASSIFIED_AS_EXACT_A", "RAW_PRE_CAPTURE_COMPLETE", "EXACT_WORKFLOW_PROVIDER_ID_PATH_AND_DEFAULT_BRANCH_OID_BOUND"], "procedure": ["REJECT STALE DEFAULT-BRANCH OR NAME-ONLY WORKFLOW SELECTION", "RESTORE ONLY CEREMONY-CHANGED ENABLED STATE", "REQUIRE BASELINE CONTENT IDENTITY OR ABSENCE TO MATCH CURRENT A", "READ_BACK EXACT PROVIDER ID PATH STATE DEFAULT-BRANCH OID AND AUDIT"], "outputs": ["WORKFLOW_ID_PATH_AND_DEFAULT_BRANCH_OID", "RAW_READBACK_SHA256", "PROJECTION_DIGEST_COMPARISON", "AUDIT_RECORD_IDS"], "forbiddenCapture": ["WORKFLOW_SECRET", "STALE_A_AS_CURRENT_IDENTITY", "NAME_ONLY_SELECTION"]},
        {"operationId": "operator-enter-unknown-ref-incident-freeze", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "SEPARATE_INCIDENT_CEREMONY", "preconditions": ["REF_ABSENT_UNREADABLE_OR_ANY_OTHER_OID_OR_ANCESTRY"], "procedure": ["PROHIBIT EVERY REF MUTATION", "BLOCK NORMAL WRITER TOKEN MINTING", "PRESERVE PROVIDER REF COMMIT RULESET AND AUDIT EVIDENCE", "DO NOT ASSUME B OR C_PRIME", "REQUIRE SEPARATE INCIDENT HANDLING"], "outputs": ["INCIDENT_FREEZE_READBACK_MANIFEST_SHA256", "AUDIT_RECORD_IDS", "UNKNOWN_REF_CLASSIFICATION_EVIDENCE"], "forbiddenCapture": ["RESET", "FORCE_PUSH", "DELETE_REF", "ORDINARY_SIGNED_FORWARD_RECOVERY", "BYPASS_EXPANSION", "EVIDENCE_DELETION"]},
        {"operationId": "operator-close-bootstrap-pr-if-created", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "AUTHENTICATED_PROVIDER_UI_OR_REST", "preconditions": ["BOOTSTRAP_OR_PROBE_PULL_REQUEST_EXISTS"], "procedure": ["CLOSE_WITHOUT_MERGE", "BIND_FINAL_PULL_REQUEST_STATE"], "outputs": ["PULL_REQUEST_ID", "FINAL_STATE", "AUDIT_RECORD_IDS"], "forbiddenCapture": []},
        {"operationId": "operator-revoke-release-credentials", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "PROVIDER_AND_LOCAL_SECRET_STORE", "preconditions": ["SOURCE_REF_ADVANCED_OR_CREDENTIAL_COMPROMISE_SUSPECTED"], "procedure": ["REVOKE_ACTIVE_INSTALLATION_TOKENS_WHERE_PROVIDER_SUPPORTS", "ROTATE_OR_REVOKE_APP_PRIVATE_KEY", "REMOVE_ENVIRONMENT_SECRET", "PROVE_NEW_TOKEN_MINTING_BLOCKED"], "outputs": ["REVOCATION_AUDIT_RECORD_IDS", "APP_SUSPENSION_READBACK_SHA256", "SECRET_ABSENCE_READBACK_SHA256"], "forbiddenCapture": ["TOKEN", "PRIVATE_KEY", "SECRET_VALUE", "SECRET_DIGEST"]},
        {"operationId": "operator-revoke-d0-b04-signer-locally", "phase": "ROLLBACK", "actorProfile": "operatorSigningAuthority", "channel": "D0_B04_LOCAL_TRUST_CEREMONY", "preconditions": ["SIGNER_COMPROMISE_OR_EXPLICIT_REVOCATION_AUTHORIZED"], "procedure": ["ADD_EXACT_PUBLIC_KEY_TO_FROZEN_REVOCATION_POLICY_BEFORE_PROVIDER_KEY_REMOVAL", "RECOMPUTE_AND_PERSIST_PUBLIC_REVOCATION_ARTIFACT_DIGEST", "PROVE_RUNTIME_REJECTS_BOTH_NEW_AND_HISTORIC_COMMITS_FROM_REVOKED_KEY", "ACKNOWLEDGE_GITHUB_MAY_KEEP_HISTORIC_COMMITS_VERIFIED"], "outputs": ["REVOCATION_ARTIFACT_PATH_LENGTH_SHA256", "LOCAL_REJECTION_TRANSCRIPT_SHA256", "GITHUB_PERSISTENT_VERIFICATION_ACKNOWLEDGEMENT"], "forbiddenCapture": ["PRIVATE_KEY", "SECRET_VALUE", "SECRET_DIGEST"]},
        {"operationId": "operator-enter-forward-recovery-freeze", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "SEPARATE_INCIDENT_CEREMONY", "preconditions": ["SOURCE_REF_HAS_ADVANCED_BEYOND_A"], "procedure": ["PRESERVE_OR_STRENGTHEN_INVARIANT_RULESET", "BLOCK_NORMAL_WRITER_AND_ALL_NEW RELEASES", "DO_NOT_RESET_OR_FORCE_PUSH_MAIN", "RETAIN_B_C_PRIME_AND_AUDIT_EVIDENCE"], "outputs": ["FREEZE_SETTINGS_READBACK_MANIFEST_SHA256", "AUDIT_RECORD_IDS"], "forbiddenCapture": ["HISTORY_REWRITE", "BYPASS_EXPANSION", "EVIDENCE_DELETION"]},
        {"operationId": "operator-open-forward-recovery-handoff", "phase": "ROLLBACK", "actorProfile": "operatorAdmin", "channel": "OPERATOR_HANDOFF", "preconditions": ["FORWARD_RECOVERY_FREEZE_EFFECTIVE"], "procedure": ["DECLARE_CURRENT_SIGNED_TIP_AND_INCIDENT_BOUNDARY", "REQUIRE_NEW_REVIEWED_SIGNED_FORWARD_COMMIT_CEREMONY", "KEEP_D2_AND_LATER_GATES_BLOCKED"], "outputs": ["HANDOFF_ID", "CURRENT_TIP", "EVIDENCE_MANIFEST_SHA256"], "forbiddenCapture": ["IMPLICIT_AUTHORIZATION", "RESET_TO_A", "UNSIGNED_CORRECTION"]},
    ]
    operation_ids = [operation["operationId"] for operation in rest_operations + non_rest_operations]
    require(len(operation_ids) == len(set(operation_ids)), f"{catalog_id}: provider-contract operation IDs must be unique")
    auth_profile_specs = {
        "publicAnonymous": {"credentialKind": "NONE", "providerAuthority": "PUBLIC_READ_ONLY", "constraints": ["NO_AUTHORIZATION_HEADER", "NO_CREDENTIAL_CAPTURE"]},
        "operatorAdmin": {"credentialKind": "GITHUB_USER_API_OR_UI_SESSION", "providerAuthority": "REPOSITORY_ADMIN", "constraints": ["SEPARATE_OPERATOR_CEREMONY", "NO_NORMAL_REF_WRITE", "MFA_ACTIVE", "USER_ACCESS_TOKEN_ENDPOINTS_REQUIRE_EXPLICIT_REPOSITORY_PERMISSION", "CREDENTIAL_NEVER_CAPTURED"]},
        "operatorSigningAuthority": {"credentialKind": "LOCAL_D0_B04_SIGNING_CEREMONY", "providerAuthority": "NO_PROVIDER_WRITE_BY_THIS_PROFILE", "constraints": ["CATALOG_SPECIFIC_EXACT_PUBLIC_IDENTITY", "PRIVATE_KEY_AND_SECRET_DIGEST_NEVER_CAPTURED"]},
        "signerGithubUser": {"credentialKind": "GITHUB_USER_API_CREDENTIAL", "providerAuthority": "OWN_SSH_SIGNING_KEYS_ONLY", "constraints": ["AUTHENTICATED_LOGIN_EQUALS_D0_B04_BINDING", "NO_REPOSITORY_SETTING_OR_REF_WRITE", "MFA_ACTIVE", "CREDENTIAL_NEVER_CAPTURED"]},
        "releaseAppJwt": {"credentialKind": "GITHUB_APP_JWT", "providerAuthority": "APP_INSTALLATION_ADMINISTRATION_ONLY", "constraints": ["APP_ID_EXACT_BINDING", "JWT_TTL_AT_MOST_600_SECONDS", "PRIVATE_KEY_NEVER_CAPTURED"]},
        "releaseInstallationReadToken": {"credentialKind": "GITHUB_APP_INSTALLATION_TOKEN", "providerAuthority": "ONE_REPOSITORY_METADATA_READ", "constraints": ["EXACT_REPOSITORY_ID", "METADATA_READ_ONLY", "TTL_AT_MOST_3600_SECONDS", "TOKEN_NEVER_CAPTURED", "REVOKE_AND_PROVE_401_AFTER_READBACK"]},
        "bootstrapInstallationWriteToken": {"credentialKind": "GITHUB_APP_INSTALLATION_TOKEN", "providerAuthority": "ONE_REPOSITORY_CONTENTS_WRITE_METADATA_READ_BOOTSTRAP_ONLY", "constraints": ["MINT_ONLY_AFTER_BOOTSTRAP_ADMISSION_AND_INVARIANTS_EFFECTIVE", "EXACT_REPOSITORY_ID", "A_TO_B_ONLY", "FORCE_FALSE", "TTL_AT_MOST_3600_SECONDS", "TOKEN_NEVER_CAPTURED", "REVOKE_AND_PROVE_401_IMMEDIATELY_AFTER_A_TO_B"]},
        "releaseInstallationWriteToken": {"credentialKind": "GITHUB_APP_INSTALLATION_TOKEN", "providerAuthority": "ONE_REPOSITORY_CONTENTS_WRITE_METADATA_READ_NORMAL_RELEASE", "constraints": ["MINT_ONLY_AFTER_ENVIRONMENT_APPROVAL", "EXACT_REPOSITORY_ID", "TTL_AT_MOST_3600_SECONDS", "TOKEN_NEVER_CAPTURED", "REVOKE_AND_PROVE_401_AFTER_REF_UPDATE"]},
        "protectedReleaseJob": {"credentialKind": "GITHUB_ACTIONS_PROTECTED_ENVIRONMENT_JOB_RUNTIME", "providerAuthority": "NO_INDEPENDENT_PROVIDER_SETTINGS_OR_REF_WRITE", "constraints": ["TRUSTED_WORKFLOW_BLOB_FROM_BOOTSTRAP_B", "EXACT_RELEASE_JOB_ONLY", "AVAILABLE_ONLY_AFTER_HUMAN_ENVIRONMENT_APPROVAL", "OPAQUE_D0_B04_SIGNER_INTERFACE_ONLY", "PRIVATE_KEY_HANDLE_SECRET_CIPHERTEXT_AND_DIGEST_NEVER_CAPTURED"]},
        "revokedReleaseInstallationReadToken": {"credentialKind": "REVOKED_GITHUB_APP_INSTALLATION_TOKEN", "providerAuthority": "NEGATIVE_AUTH_PROOF_ONLY", "constraints": ["EXACT_PREVIOUS_TOKEN_INSTANCE", "ONLY_401_ACCEPTED", "TOKEN_NEVER_CAPTURED"]},
        "revokedBootstrapInstallationWriteToken": {"credentialKind": "REVOKED_GITHUB_APP_INSTALLATION_TOKEN", "providerAuthority": "NEGATIVE_AUTH_PROOF_ONLY", "constraints": ["EXACT_PREVIOUS_TOKEN_INSTANCE", "ONLY_401_ACCEPTED", "TOKEN_NEVER_CAPTURED"]},
        "revokedReleaseInstallationWriteToken": {"credentialKind": "REVOKED_GITHUB_APP_INSTALLATION_TOKEN", "providerAuthority": "NEGATIVE_AUTH_PROOF_ONLY", "constraints": ["EXACT_PREVIOUS_TOKEN_INSTANCE", "ONLY_401_ACCEPTED", "TOKEN_NEVER_CAPTURED"]},
        "operatorBootstrapWriter": {"credentialKind": "GITHUB_USER_GIT_CREDENTIAL_AND_LOCAL_SIGNER_ACCESS", "providerAuthority": "TEMPORARY_NON_MAIN_REF_STAGING_ONLY_BY_PROCEDURE", "constraints": ["D0_B04_EXACT_SIGNER", "MAIN_REF_UPDATE_FORBIDDEN", "TEMPORARY_REF_ONLY", "CREDENTIAL_NEVER_CAPTURED"]},
        "dispatcherUser": {"credentialKind": "GITHUB_USER_ACTIONS_DISPATCH_CREDENTIAL", "providerAuthority": "EXACT_RELEASE_WORKFLOW_DISPATCH_ONLY", "constraints": ["AUTHENTICATED_USER_ID_EQUALS_EXACT_CONFIGURED_LOGIN_LOOKUP", "LEGACY_BASE_PERMISSION_WRITE_OR_ADMIN", "DISPATCH_ACTOR_EQUALS_WORKFLOW_TRIGGERING_ACTOR", "NO_SIGNER_OR_WRITER_SECRET_ACCESS", "CREDENTIAL_NEVER_CAPTURED"]},
        "reviewerUser": {"credentialKind": "GITHUB_USER_ENVIRONMENT_REVIEW_CREDENTIAL", "providerAuthority": "EXACT_PENDING_DEPLOYMENT_APPROVAL_ONLY", "constraints": ["HUMAN_USER", "AUTHENTICATED_USER_ID_EQUALS_EXACT_CONFIGURED_ENVIRONMENT_REVIEWER", "LEGACY_BASE_PERMISSION_READ_WRITE_OR_ADMIN", "CURRENT_USER_CAN_APPROVE_TRUE", "PROVIDER_AUDIT_ACTOR_EQUALS_REVIEWER", "DIFFERS_FROM_TRIGGERING_ACTOR_AND_DISPATCHER", "NO_SIGNER_OR_APP_PRIVATE_KEY_ACCESS", "CREDENTIAL_NEVER_CAPTURED"]},
    }
    authentication_profiles = [
        {"profileId": profile_id, **profile, "restOperationIds": [operation["operationId"] for operation in rest_operations if operation["authProfile"] == profile_id], "nonRestOperationIds": [operation["operationId"] for operation in non_rest_operations if operation["actorProfile"] == profile_id]}
        for profile_id, profile in auth_profile_specs.items()
    ]
    state_machine = github_bootstrap_transition(catalog_id, repository, source_tip, source_ref, candidate_path, release_path, environment_name, invariant_ruleset["name"], admission_ruleset["name"], writer_slug, pre_mutation_capture_key, signing_key_evidence_key, bootstrap_evidence_key, normal_release_evidence_key)
    resolved_operations = set(operation_ids)
    referenced_operations = {operation_id for transition in state_machine["transitions"] for operation_id in transition["operations"]}
    rollback_contract = state_machine["rollback"]
    rollback_sequences: list[list[str]] = []
    for section_name in ("beforeMainAdvance", "afterMainAdvance"):
        for step in rollback_contract[section_name]:
            rollback_sequences.append(step["operationIds"])
            rollback_sequences.extend(group["operationIds"] for group in step["conditionalOperationGroups"])
    rollback_sequences.append(rollback_contract["unknownRefIncident"]["immediateOperationIds"])
    rollback_sequences.extend(group["operationIds"] for group in rollback_contract["unknownRefIncident"]["conditionalOperationGroups"])
    referenced_operations.update(operation_id for sequence in rollback_sequences for operation_id in sequence)
    require(referenced_operations <= resolved_operations, f"{catalog_id}: bootstrap state machine references unknown provider operations: {sorted(referenced_operations - resolved_operations)}")
    validate_github_operation_graph(catalog_id, rest_operations, state_machine)
    operation_by_id = {operation["operationId"]: operation for operation in rest_operations}
    for operation in rest_mutations:
        operation_id = operation["operationId"]
        follow_ups = operation["response"]["requiredFollowUpReadbackOperationIds"]
        identity = operation["mutationIdentity"]
        require(identity["afterStateReadbackOperationIds"] == follow_ups, f"{catalog_id}: {operation_id} mutation identity/readback sequence mismatch")
        require(identity["crossResourceSubstitutionRejected"] is True and identity["afterReadbackMustMatchExactSelector"] is True, f"{catalog_id}: {operation_id} mutation resource identity must be exact")
        require(identity["responseAndReadbackIdentityMustMatch"] is identity["responseIdentity"]["responseResourceIdentityClaimed"], f"{catalog_id}: {operation_id} response/readback identity claim must match endpoint response semantics")
        require(identity["exactSelector"]["baseUrl"] == GITHUB_REST_BASE and identity["exactSelector"]["pathTemplate"] == operation["request"]["pathTemplate"], f"{catalog_id}: {operation_id} mutation selector mismatch")
        for follow_up_id in follow_ups:
            require(follow_up_id in operation_by_id, f"{catalog_id}: {operation_id} references unknown follow-up readback {follow_up_id}")
            require(operation_by_id[follow_up_id]["request"]["method"] == "GET", f"{catalog_id}: {operation_id} follow-up {follow_up_id} must be a provider GET readback")
    ordered_sequences = [(f"{transition['from']}->{transition['to']}", transition["operations"]) for transition in state_machine["transitions"]]
    ordered_sequences.extend((f"rollback[{index}]", sequence) for index, sequence in enumerate(rollback_sequences))
    for sequence_label, sequence in ordered_sequences:
        for index, operation_id in enumerate(sequence):
            operation = operation_by_id.get(operation_id)
            if operation is None or operation["request"]["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            follow_ups = operation["response"]["requiredFollowUpReadbackOperationIds"]
            require(sequence[index + 1:index + 1 + len(follow_ups)] == follow_ups, f"{catalog_id}: {sequence_label} must perform {operation_id} follow-up readbacks immediately and in declared order")
    binding_names = [binding["name"] for binding in bindings]
    require(len(binding_names) == len(set(binding_names)), f"{catalog_id}: provider typed-binding names must be unique")
    auxiliary_binding_registry = rollback_contract["auxiliaryBindingRegistry"]
    auxiliary_binding_names = [binding["name"] for binding in auxiliary_binding_registry]
    require(len(auxiliary_binding_names) == len(set(auxiliary_binding_names)), f"{catalog_id}: rollback auxiliary-binding names must be unique")
    declared_rollback_bindings = set(binding_names) | set(auxiliary_binding_names)
    required_rollback_bindings = {
        binding
        for section_name in ("beforeMainAdvance", "afterMainAdvance")
        for step in rollback_contract[section_name]
        for binding in step["requiredBindings"] + [item for group in step["conditionalOperationGroups"] for item in group["requiredBindings"]]
    }
    required_rollback_bindings.update(binding for group in rollback_contract["unknownRefIncident"]["conditionalOperationGroups"] for binding in group["requiredBindings"])
    require(required_rollback_bindings <= declared_rollback_bindings, f"{catalog_id}: rollback references undeclared bindings: {sorted(required_rollback_bindings - declared_rollback_bindings)}")
    require(all(re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+@[0-9a-f]{40}", action) is not None for action in actions["selectedPolicy"]["patternsAllowed"]), f"{catalog_id}: every selected Action must use an exact 40-character lowercase commit SHA")
    expected_invariant_rules = [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "required_linear_history"}, {"type": "required_signatures"}]
    require(invariant_ruleset["providerCreateRequestBody"] == github_ruleset_request(invariant_ruleset["name"], expected_invariant_rules, []), f"{catalog_id}: invariant ruleset provider request drift")
    expected_admission_bypass = [{"actor_id": github_binding("releaseAppIntegrationId"), "actor_type": "Integration", "bypass_mode": "always"}]
    expected_admission_bootstrap_rules = [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}]
    expected_admission_final_rules = [
        *expected_admission_bootstrap_rules,
        {"type": "pull_request", "parameters": {"allowed_merge_methods": ["squash", "rebase"], "dismiss_stale_reviews_on_push": True, "require_code_owner_review": True, "require_last_push_approval": True, "required_approving_review_count": 1, "required_review_thread_resolution": True}},
        {"type": "required_status_checks", "parameters": {"do_not_enforce_on_create": False, "required_status_checks": [{"context": check_context, "integration_id": github_binding("candidateCheckIntegrationId")}], "strict_required_status_checks_policy": True}},
    ]
    require(admission_ruleset["providerCreateRequestBody"] == github_ruleset_request(admission_ruleset["name"], expected_admission_bootstrap_rules, expected_admission_bypass), f"{catalog_id}: bootstrap admission ruleset provider request drift")
    require(admission_ruleset["providerFinalUpdateRequestBody"] == github_ruleset_request(admission_ruleset["name"], expected_admission_final_rules, expected_admission_bypass), f"{catalog_id}: final admission ruleset provider request drift")
    pre_configuration_auth_profiles = ["publicAnonymous", "operatorAdmin", "signerGithubUser"]
    unconditional_capture_operation_ids = [
        "get-repository", "get-main-ref", "get-temporary-bootstrap-ref-presence", "get-temporary-release-ref-presence",
        "get-authenticated-signing-user", "list-authenticated-ssh-signing-keys", "list-public-ssh-signing-keys-for-d0-b04-user",
        "get-actions-permissions", "get-selected-actions", "get-default-workflow-permissions", "get-fork-pr-approval-policy",
        "list-rulesets", "list-effective-main-rules", "get-classic-branch-protection",
        "list-environments", "get-release-app", "list-organization-app-installations",
        "list-workflows", "get-candidate-workflow-content-at-a", "get-release-workflow-content-at-a", "get-pages-workflow-content-at-a",
    ]
    conditional_capture = [
        {"selectorOperationId": "list-environments", "condition": "EXACT_RELEASE_ENVIRONMENT_PRESENT", "requiredOperationIds": ["get-release-environment", "list-environment-branch-policies", "list-environment-secrets"]},
        {"selectorOperationId": "list-environments", "condition": "EXACT_RELEASE_ENVIRONMENT_ABSENT", "requiredOperationIds": [], "absenceMustBeProjected": True},
        {"selectorOperationId": "get-release-app", "condition": "HTTP_200", "requiredOperationIds": []},
        {"selectorOperationId": "get-release-app", "condition": "HTTP_404", "requiredOperationIds": [], "absenceMustBeProjected": True},
        {"selectorOperationId": "list-organization-app-installations", "condition": "EXACT_RELEASE_APP_INSTALLATION_PRESENT", "requiredOperationIds": ["list-user-installation-repositories"]},
        {"selectorOperationId": "list-organization-app-installations", "condition": "EXACT_RELEASE_APP_INSTALLATION_ABSENT", "requiredOperationIds": [], "absenceMustBeProjected": True},
    ]
    all_capture_operation_ids = [*unconditional_capture_operation_ids, *(operation_id for branch in conditional_capture for operation_id in branch["requiredOperationIds"])]
    classic_mutation_operation_ids = ["delete-classic-branch-protection-if-baseline-present", "restore-classic-branch-protection-from-pre-capture"] if catalog_id == "rust" else []
    pre_mutation_capture_contract = {
        "schema": "pkgre-d0-github-pre-mutation-capture-v3",
        "maximumAgeSecondsAtFirstMutation": 600,
        "sourceRefMustRemain": source_tip,
        "captureBeforeAnyMutation": True,
        "preConfigurationAllowedAuthProfiles": pre_configuration_auth_profiles,
        "unconditionalCaptureOperationIds": unconditional_capture_operation_ids,
        "conditionalCapture": conditional_capture,
        "allCaptureOperationIds": all_capture_operation_ids,
        "mutableResourceCoverage": [
            {"resource": "D0_B04_GITHUB_SSH_SIGNING_KEY", "captureOperationIds": ["get-authenticated-signing-user", "list-authenticated-ssh-signing-keys", "list-public-ssh-signing-keys-for-d0-b04-user"], "mutationOperationIds": ["create-d0-b04-ssh-signing-key-if-baseline-absent", "delete-d0-b04-ssh-signing-key"], "rollbackRule": "DELETE_ONLY_IF_EXACT_KEY_ABSENT_AT_BASELINE_AND_CREATED_BY_THIS_CEREMONY"},
            {"resource": "REPOSITORY_ACTIONS_POLICY", "captureOperationIds": ["get-actions-permissions", "get-selected-actions", "get-default-workflow-permissions", "get-fork-pr-approval-policy"], "mutationOperationIds": ["set-actions-permissions", "set-selected-actions", "set-default-workflow-permissions", "set-fork-pr-approval-policy", "restore-actions-permissions-from-pre-capture", "restore-selected-actions-from-pre-capture", "restore-default-workflow-permissions-from-pre-capture", "restore-fork-pr-approval-policy-from-pre-capture"], "rollbackRule": "RESTORE_EACH_SETTING_VIA_DISTINCT_TYPED_REQUEST_FROM_RAW_FRESH_CAPTURE_AND_EXACT_READBACK_DIGEST"},
            {"resource": "RELEASE_ENVIRONMENT_BRANCH_POLICY_AND_SECRET_METADATA", "captureOperationIds": ["list-environments", "get-release-environment", "list-environment-branch-policies", "list-environment-secrets"], "mutationOperationIds": ["put-release-environment", "create-environment-main-policy", "operator-install-app-and-environment-secret", "operator-remove-environment-secret", "operator-restore-environment-resources-from-pre-capture"], "rollbackRule": "RESTORE_OR_DELETE_FROM_FRESH_PRESENCE_AND_METADATA_WITHOUT_SECRET_VALUE_CAPTURE"},
            {"resource": "RELEASE_APP_AND_INSTALLATION", "captureOperationIds": ["get-release-app", "list-organization-app-installations", "list-user-installation-repositories"], "mutationOperationIds": ["operator-install-app-and-environment-secret", "suspend-release-app-installation", "operator-restore-app-installation-from-pre-capture"], "rollbackRule": "RESTORE_EXACT_BASELINE_INSTALLATION_STATE_OR_REMOVE_NEW_RESOURCE_BY_SEPARATE_OPERATOR_CEREMONY"},
            {"resource": "RULESETS_AND_EFFECTIVE_MAIN_RULES", "captureOperationIds": ["list-rulesets", "list-effective-main-rules"], "mutationOperationIds": ["create-admission-ruleset-bootstrap", "update-admission-ruleset-to-final", "create-invariant-ruleset", "delete-admission-ruleset", "delete-invariant-ruleset"], "rollbackRule": "RESTORE_OR_DELETE_BY_EXACT_BASELINE_ID_WITH_NO_AMBIGUOUS_NAME_SELECTION"},
            {"resource": "CLASSIC_MAIN_BRANCH_PROTECTION", "captureOperationIds": ["get-classic-branch-protection"], "mutationOperationIds": classic_mutation_operation_ids, "rollbackRule": "RESTORE_TYPED_REQUEST_ONLY_FROM_RAW_FRESH_CAPTURE_WITH_EXACT_READBACK_DIGEST" if catalog_id == "rust" else "CONFIRM_FRESH_BASELINE_ABSENCE_AND_NEVER_MUTATE_CLASSIC_PROTECTION"},
            {"resource": "WORKFLOW_PROVIDER_STATE_AND_CONTENT", "captureOperationIds": ["list-workflows", "get-candidate-workflow-content-at-a", "get-release-workflow-content-at-a", "get-pages-workflow-content-at-a"], "mutationOperationIds": ["disable-release-workflow", "operator-restore-workflow-state-from-pre-capture"], "rollbackRule": "RESTORE_ENABLED_STATE_ONLY_BY_EXACT_PROVIDER_ID_PATH_AND_CURRENT_DEFAULT_BRANCH_IDENTITY"},
            {"resource": "MAIN_AND_TEMPORARY_REFS", "captureOperationIds": ["get-main-ref", "get-temporary-bootstrap-ref-presence", "get-temporary-release-ref-presence"], "mutationOperationIds": ["patch-main-ref-bootstrap-force-false", "patch-main-ref-release-force-false", "delete-temporary-bootstrap-ref", "delete-temporary-release-ref"], "rollbackRule": "PRE_ADVANCE_MAIN_MUST_REMAIN_A_POST_ADVANCE_NO_HISTORY_REWRITE"},
        ],
        "completeness": {"allPagesRequired": True, "rawBodiesAndStrictProjectionsRequired": True, "providerRequestIdsRequired": True, "sameCeremony": True, "abortOnDriftOrUncoveredMutableResource": True},
    }
    validate_github_pre_mutation_capture_contract(catalog_id, pre_mutation_capture_contract, rest_operations)
    actor_authorization_contract = {
        "schema": "pkgre-d0-github-procedural-actor-authorization-v1",
        "authorityNature": "PROVIDER_ACCOUNT_AND_REPOSITORY_PERMISSION_READBACK_PROCEDURAL_NOT_CRYPTOGRAPHIC_IDENTITY",
        "nonBypassableIdentityClaimed": False,
        "dispatcher": {
            "configuredLogin": dispatcher,
            "identityOperationId": "get-release-dispatcher-user",
            "identityPathTemplate": f"/users/{dispatcher}",
            "loginBinding": "dispatcherGithubLogin",
            "userIdBinding": "dispatcherUserId",
            "permissionOperationId": "get-release-dispatcher-permission",
            "permissionPathTemplate": f"{base}/collaborators/{dispatcher}/permission",
            "allowedLegacyBasePermissions": ["write", "admin"],
            "permissionSemantics": "MAINTAIN_MAPS_TO_WRITE_PER_PINNED_GITHUB_OPENAPI",
            "authorizedAction": "DISPATCH_EXACT_RELEASE_WORKFLOW_ON_MAIN",
            "dispatchAuthenticatedActorBinding": "dispatchAuthenticatedActorUserId",
            "workflowTriggeringActorBinding": "triggeringActorUserId",
            "allUserIdsMustEqual": True,
        },
        "reviewer": {
            "configuredLogin": reviewer,
            "identityOperationId": "get-environment-reviewer-user",
            "identityPathTemplate": f"/users/{reviewer}",
            "loginBinding": "reviewerGithubLogin",
            "userIdBinding": "reviewerUserId",
            "permissionOperationId": "get-environment-reviewer-permission",
            "permissionPathTemplate": f"{base}/collaborators/{reviewer}/permission",
            "allowedLegacyBasePermissions": ["read", "write", "admin"],
            "permissionSemantics": "TRIAGE_MAPS_TO_READ_PER_PINNED_GITHUB_OPENAPI",
            "mustBeExactConfiguredEnvironmentReviewer": True,
            "pendingDeploymentReviewerBinding": "pendingDeploymentReviewerUserId",
            "pendingDeploymentCurrentUserCanApproveBinding": "pendingDeploymentCurrentUserCanApprove",
            "pendingDeploymentCurrentUserCanApproveRequired": True,
            "reviewAuthenticatedActorBinding": "reviewAuthenticatedActorUserId",
            "providerAuditActorBinding": "reviewApprovalAuditActorUserId",
            "allUserIdsMustEqual": True,
        },
        "separation": {"reviewerMustDifferFromDispatcher": True, "providerUserIdsMustDiffer": True, "selfApprovalForbidden": True},
        "failurePolicy": "ABORT_ON_LOOKUP_LOGIN_ID_PERMISSION_PENDING_DEPLOYMENT_OR_AUDIT_ACTOR_MISMATCH",
    }
    return {
        "schema": "pkgre-d0-github-provider-contract-v2",
        "openApi": {"repository": "github/rest-api-description", "commit": GITHUB_REST_OPENAPI_COMMIT, "document": "descriptions/api.github.com/api.github.com.json", "sha256": GITHUB_REST_OPENAPI_SHA256, "schemaDialect": "OPENAPI_3_0", "validation": "REQUEST_AND_NONSECRET_RESPONSE_REVALIDATED_AGAINST_PINNED_DOCUMENT"},
        "http": {"baseUrl": GITHUB_REST_BASE, "accept": GITHUB_REST_ACCEPT, "apiVersion": GITHUB_REST_API_VERSION, "tlsRequired": True, "redirectsAllowed": False, "crossOriginRedirectsAllowed": False, "providerRequestIdRequired": True, "selectedApiVersionResponseEvidenceRequired": True},
        "repositoryBinding": {"fullName": repository, "repositoryId": repository_id, "owner": owner, "name": repo, "sourceRef": source_ref, "baselineA": source_tip},
        "catalogSignerSeparation": {"authorityFindingId": "D0-B04", "assignmentStatus": "NOT_YET_ASSIGNED_IN_D0_B03", "mustDifferFromEveryOtherCatalog": True, "concreteIdentityValuesPresent": False},
        "preMutationCaptureContract": pre_mutation_capture_contract,
        "typedBindings": bindings,
        "rawCapture": raw_capture,
        "projectionPolicy": projections,
        "authenticationProfiles": authentication_profiles,
        "actorAuthorization": actor_authorization_contract,
        "restOperations": rest_operations,
        "nonRestOperations": non_rest_operations,
        "proceduralReadbacks": [
            {"readbackId": "environment-admin-bypass-disabled", "operationId": "capture-environment-admin-bypass-ui-readback", "providerFact": "ENVIRONMENT_ADMIN_BYPASS_DISABLED", "restFieldOrRequestParameterExists": False, "requiredEvidence": ["PROVIDER_UI_ARCHIVE_SHA256", "REDACTED_DOM_PROJECTION_SHA256", "AUDIT_RECORD_IDS"], "operatorSelfAttestationAllowed": False},
            {"readbackId": "environment-secret-name-and-scope", "operationId": "capture-environment-secret-name-and-scope-ui-readback", "providerFact": "SECRET_EXISTS_ONLY_IN_EXACT_RELEASE_ENVIRONMENT", "restFieldOrRequestParameterExists": False, "requiredEvidence": ["SECRET_METADATA_PROJECTION_SHA256", "PROVIDER_UI_ARCHIVE_SHA256"], "secretValueOrDigestAllowed": False, "operatorSelfAttestationAllowed": False},
            {"readbackId": "complete-provider-audit-window", "operationId": "capture-provider-ui-audit-export", "providerFact": "ALL_PROVIDER_MUTATIONS_EXPLAINED", "requiredEvidence": ["PROVIDER_EXPORT_RAW_SHA256", "STRICT_AUDIT_PROJECTION_SHA256", "WINDOW_START_END", "RECORD_IDS"], "operatorSelfAttestationAllowed": False},
        ],
        "bootstrapStateMachine": state_machine,
    }


def expected_github_catalog(catalog_id: str, repository: str, repository_id: int, runtime_origin: str, source_tip: str, reviewer: str, dispatcher: str, candidate_digest: str, release_digest: str, pages_digest: str, codeowners_digest: str) -> dict[str, Any]:
    source_ref = "refs/heads/main"
    source_branch = "main"
    candidate_path = f".github/workflows/pkgre-{catalog_id}-candidate.yml"
    release_path = f".github/workflows/pkgre-{catalog_id}-release.yml"
    pages_path = ".github/workflows/pages.yml"
    candidate_name = f"pkgre-{catalog_id}-candidate"
    release_name = f"pkgre-{catalog_id}-release"
    pages_name = f"pkgre-{catalog_id}-pages-rollback"
    check_context = f"pkgre-{catalog_id}-candidate/validate"
    candidate_job_id = "validate"
    candidate_check_context_derivation = {
        "workflowPath": candidate_path,
        "workflowName": candidate_name,
        "jobId": candidate_job_id,
        "jobNameLiteral": check_context,
        "jobNameExpressionAllowed": False,
        "matrixStrategyAllowed": False,
        "reusableWorkflowCallAllowed": False,
        "renderedCheckRunName": check_context,
        "requiredStatusCheckContext": check_context,
        "providerProbeMustBindWorkflowIdRunIdJobIdCheckSuiteIdCheckRunIdAndIntegrationId": True,
        "abortOnRenderedNameOrProducerMismatch": True,
    }
    environment_name = f"pkgre-{catalog_id}-release"
    writer_slug = f"pkgre-{catalog_id}-release-writer"
    admission_name = f"pkgre-{catalog_id}-admission"
    invariant_name = f"pkgre-{catalog_id}-invariants"
    design_id = f"pkgre-{catalog_id}-github-governance-v1"
    signing_design_id = f"pkgre-{catalog_id}-signing-v1"
    provider_evidence_keys = {kind: f"{catalog_id}-{kind.lower().replace('_', '-')}" for kind in GITHUB_PROVIDER_EVIDENCE_KINDS}
    candidate_producer_key = provider_evidence_keys["CANDIDATE_CHECK_PRODUCER_ID_AND_RUN"]
    pre_mutation_capture_key = provider_evidence_keys["D2_PRE_MUTATION_CAPTURE"]
    bootstrap_evidence_key = provider_evidence_keys["BOOTSTRAP_COMMIT_AND_REF_ADVANCE"]
    normal_release_evidence_key = provider_evidence_keys["FIRST_NORMAL_RELEASE_RUN"]
    signing_key_evidence_key = provider_evidence_keys["SIGNING_KEY_REGISTRATION_AND_READBACK"]
    effective_rules_key = provider_evidence_keys["EFFECTIVE_MAIN_RULES_READBACK"]
    candidate_workflow_key = provider_evidence_keys["CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK"]
    release_workflow_key = provider_evidence_keys["RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK"]
    pages_workflow_key = provider_evidence_keys["PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK"]
    trusted_surface_key = provider_evidence_keys["TRUSTED_SURFACE_TREE_READBACK"]
    source_tree_oid = GITHUB_CATALOG_TREE_OIDS[repository]
    pages_baseline = GITHUB_PAGES_BASELINES[catalog_id]
    collection_remote = next(row.remote_url for row in PRODUCTION_REPOSITORIES if row.id == repository)
    permissions_candidate = {"actions": "none", "checks": "none", "contents": "read", "idToken": "none", "pages": "none", "pullRequests": "none", "allUnlisted": "none"}
    permissions_release = {"actions": "none", "checks": "read", "contents": "read", "idToken": "none", "pages": "none", "pullRequests": "read", "allUnlisted": "none"}
    permissions_pages_validate = {"actions": "none", "checks": "none", "contents": "read", "idToken": "none", "pages": "none", "pullRequests": "none", "allUnlisted": "none"}
    permissions_pages_deploy = {"actions": "none", "checks": "none", "contents": "none", "idToken": "write", "pages": "write", "pullRequests": "none", "allUnlisted": "none"}
    app_permissions = {"contents": "write", "metadata": "read", "allUnlisted": "none"}
    candidate_actions = [GITHUB_CHECKOUT_ACTION, GITHUB_NIX_ACTION]
    release_actions = [GITHUB_APP_TOKEN_ACTION, GITHUB_CHECKOUT_ACTION]
    pages_actions = [GITHUB_CHECKOUT_ACTION, GITHUB_CONFIGURE_PAGES_ACTION, GITHUB_DEPLOY_PAGES_ACTION, GITHUB_NIX_ACTION, GITHUB_UPLOAD_ARTIFACT_ACTION]
    all_actions = sorted(set(candidate_actions + release_actions + pages_actions))
    workflow_manifest = [
        {"path": pages_path, "name": pages_name, "purpose": "FROZEN_PAGES_ROLLBACK_PUBLICATION", "proposedContentSha256": pages_digest, "providerWorkflowEvidenceKey": pages_workflow_key, "providerWorkflowIdStatus": "NOT_YET_ASSIGNED", "targetGitBlobOidStatus": "NOT_YET_ASSIGNED"},
        {"path": candidate_path, "name": candidate_name, "purpose": "VALIDATE_EXACT_PULL_REQUEST_HEAD", "proposedContentSha256": candidate_digest, "providerWorkflowEvidenceKey": candidate_workflow_key, "providerWorkflowIdStatus": "NOT_YET_ASSIGNED", "targetGitBlobOidStatus": "NOT_YET_ASSIGNED"},
        {"path": release_path, "name": release_name, "purpose": "SIGN_AND_FAST_FORWARD_OPERATOR_APPROVED_CANDIDATE", "proposedContentSha256": release_digest, "providerWorkflowEvidenceKey": release_workflow_key, "providerWorkflowIdStatus": "NOT_YET_ASSIGNED", "targetGitBlobOidStatus": "NOT_YET_ASSIGNED"},
    ]
    repository_executable_inputs = copy.deepcopy(GITHUB_JS_EXECUTABLE_INPUTS if catalog_id == "js" else [])
    external_repository_inputs = [copy.deepcopy(GITHUB_EXTERNAL_INDEXER)]
    protected_governance_paths = [".github/CODEOWNERS", pages_path, candidate_path, release_path] + [entry["path"] for entry in repository_executable_inputs]
    protected_governance_paths = sorted(protected_governance_paths)
    trusted_surface = {
        "comparisonBase": {"sourceRef": source_ref, "commitOid": source_tip, "treeOid": source_tree_oid},
        "closedWorkflowManifest": {"root": ".github/workflows", "entries": workflow_manifest, "unlistedEntriesAllowed": False, "addRemoveRenameAllowedByNormalWriter": False},
        "closedLocalActionManifest": {"root": ".github/actions", "entries": [], "unlistedEntriesAllowed": False, "addRemoveRenameAllowedByNormalWriter": False},
        "repositoryExecutableInputs": repository_executable_inputs,
        "externalRepositoryInputs": external_repository_inputs,
        "externalActions": all_actions,
        "workflowExecutableContracts": [
            {"workflowPath": pages_path, "candidateTreeTreatment": "ACCEPTED_MAIN_DATA_ONLY", "repositoryExecutableInputs": [entry["path"] for entry in repository_executable_inputs], "externalRepositoryInputs": [GITHUB_EXTERNAL_INDEXER["repository"]], "externalActions": pages_actions, "pullRequestExecution": False, "unlistedExecutableInputAllowed": False},
            {"workflowPath": candidate_path, "candidateTreeTreatment": "UNTRUSTED_DATA_ONLY", "repositoryExecutableInputs": [], "externalRepositoryInputs": [GITHUB_EXTERNAL_INDEXER["repository"]], "externalActions": candidate_actions, "pullRequestExecution": True, "unlistedExecutableInputAllowed": False},
            {"workflowPath": release_path, "candidateTreeTreatment": "UNTRUSTED_DATA_ONLY", "repositoryExecutableInputs": [], "externalRepositoryInputs": [GITHUB_EXTERNAL_INDEXER["repository"]], "externalActions": release_actions, "pullRequestExecution": False, "unlistedExecutableInputAllowed": False},
        ],
        "normalWriterAdmission": {"compareEntireSurfaceToReviewedBase": True, "protectedPaths": protected_governance_paths, "manifestAbsenceIsProtected": True, "helperContentDigestRequired": True, "candidateMayModifySurface": False},
        "governanceChangeCeremony": {"normalCatalogWriterForbidden": True, "requiresSeparateOperatorReviewedHandoff": True, "requiresFreshTargetDesignAndProviderReadback": True, "requiresRulesetMutationAudit": True, "mayNotReuseCatalogAdmission": True},
        "evidenceKey": trusted_surface_key,
    }
    candidate_ci = {
        "path": candidate_path,
        "name": candidate_name,
        "purpose": "VALIDATE_EXACT_PULL_REQUEST_HEAD",
        "proposedContentSha256": candidate_digest,
        "targetCommitBinding": {"commitOidStatus": "NOT_YET_ASSIGNED", "gitBlobOidStatus": "NOT_YET_ASSIGNED", "providerWorkflowEvidenceKey": candidate_workflow_key},
        "trigger": {"pullRequest": True, "targetBranch": source_branch, "headShaSource": "GITHUB_EVENT_PULL_REQUEST_HEAD_SHA", "push": False, "pullRequestTarget": False, "workflowRun": False, "workflowCall": False, "workflowDispatch": False},
        "check": {"context": check_context, "conclusion": "success", "headShaEqualsCheckedOutCommit": True, "contextDerivation": candidate_check_context_derivation, "expectedProducerEvidenceKey": candidate_producer_key, "expectedProducerIdStatus": "NOT_YET_ASSIGNED"},
        "permissions": permissions_candidate,
        "checkout": {"detached": True, "fetchFullHistory": True, "persistCredentials": False, "submodules": False, "lfs": False},
        "validationScope": GITHUB_CANDIDATE_VALIDATION_SCOPE,
        "execution": {"candidateTreeIsDataOnly": True, "executeCandidateCode": False, "repositoryExecutableInputs": [], "externalRepositoryInputs": [GITHUB_EXTERNAL_INDEXER["repository"]], "actions": candidate_actions, "shellLogicSource": "INLINE_FROZEN_WORKFLOW_ONLY", "unlistedInputAllowed": False, "signerAccess": False},
        "untrustedPullRequests": {"secretsAvailable": False, "writeTokenAvailable": False, "pullRequestTargetUsed": False, "lifecycleScriptsExecuted": False},
    }
    admission_job = {
        "jobId": "admission",
        "environment": None,
        "needs": [],
        "permissions": permissions_release,
        "secretAccess": False,
        "writerTokenAccess": False,
        "candidate": {"input": "candidate_sha", "format": "LOWERCASE_SHA1_40", "fetchFullHistory": True, "checkoutDetached": True, "objectTypeCommit": True, "verifyHeadEqualsInput": True, "verifyDescendsFromCurrentBase": True, "verifyCandidateTreeAfterCheckout": True, "persistCredentials": False, "submodules": False, "lfs": False, "candidateTreeIsDataOnly": True, "executeCandidateCode": False},
        "pullRequest": {"exactlyOneOpen": True, "baseBranch": source_branch, "baseShaEqualsCurrentSourceTip": True, "headShaEqualsCandidate": True, "codeOwnerApprovalRequired": True, "lastPushApprovalRequired": True, "staleApprovalsDismissed": True, "conversationResolutionRequired": True, "reviewCommitIdEqualsCandidate": True, "providerReviewEvidenceKey": provider_evidence_keys["PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING"]},
        "candidateCheck": {"context": check_context, "conclusion": "success", "headShaEqualsCandidate": True, "contextDerivation": candidate_check_context_derivation, "expectedProducerEvidenceKey": candidate_producer_key, "expectedProducerIdStatus": "NOT_YET_ASSIGNED"},
        "trustedSurface": {"unchangedFromReviewedBase": True, "evidenceKey": trusted_surface_key, "closedWorkflowManifestRequired": True, "closedLocalActionManifestRequired": True, "executableInputDigestsRequired": True},
        "actions": candidate_actions,
        "result": "ADMISSION_DIGEST_BOUND_TO_BASE_CANDIDATE_AND_TRUSTED_SURFACE",
        "signerAccess": False,
    }
    signer_access_interface = {
        "designId": f"{signing_design_id}-protected-job-access-v1",
        "authoritySource": {"findingId": "D0-B04", "handoffId": "OP-D0-04", "catalogId": catalog_id},
        "implementationSelection": "D0_B04_OPERATOR_MUST_SELECT_EXACT_CATALOG_SPECIFIC_SIGNER_SERVICE_AGENT_OR_HANDLE",
        "assignmentStatus": "NOT_YET_ASSIGNED_IN_D0_B03_TARGET_DESIGN",
        "capabilityKind": "OPAQUE_SIGN_REQUEST_INTERFACE_NOT_PRIVATE_KEY_MATERIAL",
        "handleMaterial": {"availableToEvidence": False, "digestAvailableToEvidence": False, "ciphertextAvailableToEvidence": False, "persistedByWorkflow": False},
        "availability": {"workflowPath": release_path, "jobId": "release", "environment": environment_name, "onlyAfterProtectedEnvironmentApproval": True, "candidateJob": False, "admissionJob": False, "pagesJobs": False, "pullRequestJobs": False, "allOtherJobs": False},
        "identityBinding": {"signingDesignId": signing_design_id, "githubLoginBinding": github_binding("signerGithubLogin", "GITHUB_LOGIN"), "publicKeyBinding": github_binding("signerSshEd25519PublicKey", "SSH_ED25519_PUBLIC_KEY"), "fingerprintBinding": github_binding("signerSshSha256Fingerprint", "SSH_SHA256_FINGERPRINT"), "principalMustMatchD0B04": True},
        "requestContract": {"namespace": "git", "hashAlgorithm": "sha512", "signatureAlgorithm": "ssh-ed25519", "bindUnsignedCommitPayload": True, "bindTreeOid": True, "bindSoleParentOid": True, "bindRepositoryId": repository_id, "bindSourceRef": source_ref, "arbitraryPayloadSigningAllowed": False},
        "responseContract": {"sshSignatureOnly": True, "signatureMetadata": ["namespace", "hashAlgorithm", "signatureAlgorithm", "publicKeyFingerprint", "principal"], "privateKeyMaterial": False, "privateKeyDigest": False, "opaqueHandleMaterial": False, "bindFinalCommitOidTreeAndSoleParent": True},
        "githubAccountAuthority": {"usedForRepositoryWrite": False, "usedForRepositoryAdministration": False, "usedForEnvironmentApproval": False, "usedForWorkflowDispatch": False, "sshSigningKeyRegistrationOnly": True},
        "failurePolicy": "ABORT_IF_INTERFACE_IDENTITY_SCOPE_AVAILABILITY_REQUEST_OR_RESPONSE_BINDING_DIFFERS",
    }
    release_job = {
        "jobId": "release",
        "environment": environment_name,
        "needs": ["admission"],
        "permissions": permissions_release,
        "secretAccess": True,
        "writerTokenAccess": True,
        "revalidateAdmissionAgainstCurrentBase": True,
        "rejectChangedCandidateOrBase": True,
        "candidateTreeIsDataOnly": True,
        "executeCandidateCode": False,
        "repositoryExecutableInputs": [],
        "actions": release_actions,
        "signerAccess": copy.deepcopy(signer_access_interface),
        "signedCommit": {"treeEqualsCandidate": True, "soleParentEqualsFreshCapturedBase": True, "candidateShaTrailer": "Pkgre-Candidate", "signatureFormat": "SSH", "signatureAlgorithm": "ssh-ed25519", "exactSignerPolicySource": signing_design_id, "localExactKeyVerificationRequired": True, "githubVerification": {"verified": True, "reason": GITHUB_VERIFIED_COMMIT_REASON, "verifiedAtRequired": True}, "githubSigningKeyReadbackRequired": True},
        "refUpdate": {"targetRef": source_ref, "api": "PATCH_GIT_REF", "force": False, "compareBaseToFreshCaptureImmediatelyBeforeUpdate": True, "fastForwardOnly": True, "freshCaptureEvidenceKey": pre_mutation_capture_key},
    }
    release_authority_consumers = {
        "protectedEnvironment": [{"workflowPath": release_path, "jobId": "release", "environment": environment_name}],
        "writerAppCredentialSecret": [{"workflowPath": release_path, "jobId": "release", "purpose": "MINT_REPOSITORY_SCOPED_WRITER_TOKEN"}],
        "writerTokenMintingAction": [{"workflowPath": release_path, "jobId": "release", "action": GITHUB_APP_TOKEN_ACTION}],
        "signerAccessHandle": [{"workflowPath": release_path, "jobId": "release", "environment": environment_name, "interfaceDesignId": signer_access_interface["designId"], "assignmentStatus": signer_access_interface["assignmentStatus"], "purpose": "SIGN_EXACT_BOUND_GIT_COMMIT_PAYLOAD_WITHOUT_EXPOSING_PRIVATE_MATERIAL"}],
        "contentsWriteToken": [{"workflowPath": release_path, "jobId": "release", "targetRef": source_ref}],
        "allOtherConsumersForbidden": True,
        "closedWorldReferenceScanRequired": True,
        "closedWorldReferenceScan": {"scanWorkflowPaths": [pages_path, candidate_path, release_path], "scanRepositoryExecutableInputs": protected_governance_paths, "allowedSignerAccessReferences": [{"workflowPath": release_path, "jobId": "release"}], "rejectUnlistedSignerHandleSecretServiceAgentOrSocketReference": True},
    }
    release_workflow = {
        "path": release_path,
        "name": release_name,
        "purpose": "SIGN_AND_FAST_FORWARD_OPERATOR_APPROVED_CANDIDATE",
        "proposedContentSha256": release_digest,
        "targetCommitBinding": {"commitOidStatus": "NOT_YET_ASSIGNED", "gitBlobOidStatus": "NOT_YET_ASSIGNED", "providerWorkflowEvidenceKey": release_workflow_key},
        "triggers": {"workflowDispatch": {"enabled": True, "candidateShaInput": "candidate_sha", "candidateShaRequired": True, "requiredRef": source_ref, "workflowFileOnDefaultBranch": True, "verifyGithubRefExactly": True, "verifyGithubShaEqualsFreshCapturedBase": True, "verifyActorIsExactlyOneConfiguredDispatcher": True}, "push": False, "pullRequest": False, "pullRequestTarget": False, "workflowRun": False, "workflowCall": False},
        "dispatchers": [{"type": "USER", "login": dispatcher}],
        "jobs": {"admission": admission_job, "release": release_job},
        "releaseAuthorityConsumers": release_authority_consumers,
        "protectedGovernancePaths": protected_governance_paths,
        "signingAuthorityDesignId": signing_design_id,
    }
    pages_workflow = {
        "path": pages_path,
        "name": pages_name,
        "purpose": "FROZEN_PAGES_ROLLBACK_PUBLICATION",
        "baseline": copy.deepcopy(pages_baseline),
        "proposedContentSha256": pages_digest,
        "targetCommitBinding": {"commitOidStatus": "NOT_YET_ASSIGNED", "gitBlobOidStatus": "NOT_YET_ASSIGNED", "providerWorkflowEvidenceKey": pages_workflow_key},
        "triggers": {"push": {"enabled": True, "branches": [source_branch]}, "workflowDispatch": {"enabled": True, "requiredRef": source_ref}, "pullRequest": False, "pullRequestTarget": False, "workflowRun": False, "workflowCall": False},
        "jobs": {"validate": {"permissions": permissions_pages_validate, "environment": None, "candidateTreeIsDataOnly": True, "repositoryExecutableInputs": [entry["path"] for entry in repository_executable_inputs]}, "deploy": {"permissions": permissions_pages_deploy, "environment": "github-pages", "needs": ["validate"], "sourceRefRequired": source_ref}},
        "releaseAuthorityAccess": {"protectedReleaseEnvironment": False, "writerAppCredentialSecret": False, "writerTokenMintingAction": False, "contentsWriteToken": False, "signerAccessHandle": False},
        "pullRequestCandidateExecutionRemoved": True,
        "rollbackContinuityRetained": True,
    }
    environment_request = {"wait_timer": 0, "prevent_self_review": True, "reviewers": [{"type": "User", "id": github_binding("reviewerUserId")}], "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
    environment_branch_policy_request = {"name": source_branch, "type": "branch"}
    environment = {
        "name": environment_name,
        "reviewers": [{"type": "USER", "login": reviewer, "providerIdBinding": github_binding("reviewerUserId")}],
        "requiredReviewerApprovals": 1,
        "preventSelfReview": True,
        "providerCreateOrUpdateRequestBody": environment_request,
        "providerBranchPolicyCreateRequestBody": environment_branch_policy_request,
        "expectedRestReadbackProjection": {"repositoryId": repository_id, "environmentId": github_binding("environmentId"), "name": environment_name, "waitTimer": 0, "preventSelfReview": True, "reviewers": [{"type": "User", "id": github_binding("reviewerUserId"), "login": reviewer}], "deploymentBranchPolicy": {"protectedBranches": False, "customBranchPolicies": True}, "branchPolicies": [{"id": github_binding("environmentBranchPolicyId"), "name": source_branch, "type": "branch"}]},
        "proceduralReadback": {"adminBypassDisabled": True, "operationId": "capture-environment-admin-bypass-ui-readback", "providerEvidenceKey": provider_evidence_keys["PROTECTED_ENVIRONMENT_ID_AND_READBACK"], "operatorSelfAttestationAllowed": False},
        "secretsAvailableOnlyAfterApproval": True,
    }
    writer = {
        "kind": "GITHUB_APP",
        "slug": writer_slug,
        "appIntegrationIdBinding": github_binding("releaseAppIntegrationId"),
        "installation": {"installationIdBinding": github_binding("releaseAppInstallationId"), "repositorySelection": "SELECTED", "repositories": [repository], "repositoryIds": [repository_id], "repositoryCount": 1},
        "installedPermissions": app_permissions,
        "token": {"mintedOnlyInProtectedJob": "release", "mintedOnlyAfterHumanApproval": True, "maximumTtlSeconds": 3600, "repositories": [repository], "repositoryIds": [repository_id], "repositoryCount": 1, "requestedPermissions": app_permissions, "storedAfterJob": False, "responseBodyPersistedOrHashed": False},
        "credential": {"location": "PROTECTED_ENVIRONMENT_SECRET", "metadataReadbackOperationId": "capture-environment-secret-name-and-scope-ui-readback", "materialOrDigestReturnedInD0": False},
        "normalUse": {"workflowPath": release_path, "jobId": "release", "canApprovePullRequests": False, "canBeCodeOwner": False, "canAdministerRepository": False},
        "admissionBypass": {"ruleset": admission_name, "actorType": "Integration", "actor": writer_slug, "providerActorIdBinding": github_binding("releaseAppIntegrationId"), "mode": "always"},
        "invariantBypassAllowed": False,
    }
    admission_bypass = [{"actor_id": github_binding("releaseAppIntegrationId"), "actor_type": "Integration", "bypass_mode": "always"}]
    admission_bootstrap_request = github_ruleset_request(admission_name, [
        {"type": "update", "parameters": {"update_allows_fetch_and_merge": False}},
    ], admission_bypass)
    admission_final_request = github_ruleset_request(admission_name, [
        {"type": "update", "parameters": {"update_allows_fetch_and_merge": False}},
        {"type": "pull_request", "parameters": {"allowed_merge_methods": ["squash", "rebase"], "dismiss_stale_reviews_on_push": True, "require_code_owner_review": True, "require_last_push_approval": True, "required_approving_review_count": 1, "required_review_thread_resolution": True}},
        {"type": "required_status_checks", "parameters": {"do_not_enforce_on_create": False, "required_status_checks": [{"context": check_context, "integration_id": github_binding("candidateCheckIntegrationId")}], "strict_required_status_checks_policy": True}},
    ], admission_bypass)
    invariant_request = github_ruleset_request(invariant_name, [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "required_linear_history"}, {"type": "required_signatures"}], [])
    admission_ruleset = {
        "name": admission_name,
        "providerCreateRequestBody": admission_bootstrap_request,
        "providerFinalUpdateRequestBody": admission_final_request,
        "expectedBootstrapReadbackProjection": {"repositoryId": repository_id, "rulesetId": github_binding("admissionRulesetId"), "name": admission_name, "target": "branch", "enforcement": "active", "bypassActors": admission_bootstrap_request["bypass_actors"], "conditions": admission_bootstrap_request["conditions"], "rules": admission_bootstrap_request["rules"]},
        "expectedFinalReadbackProjection": {"repositoryId": repository_id, "rulesetId": github_binding("admissionRulesetId"), "name": admission_name, "target": "branch", "enforcement": "active", "bypassActors": admission_final_request["bypass_actors"], "conditions": admission_final_request["conditions"], "rules": admission_final_request["rules"]},
        "evolution": {"createAsBootstrapBeforeAtoB": True, "finalizeWithPutAfterCheckProducerBinding": True, "sameProviderRulesetIdRequired": True, "replacementAllowed": False},
        "normalMainWriterInvariant": {"exactlyOneActor": True, "actorType": "Integration", "actor": writer_slug, "actorIdBinding": github_binding("releaseAppIntegrationId"), "allUsersTeamsRepositoryRolesAndOtherIntegrationsDenied": True},
    }
    invariant_ruleset = {
        "name": invariant_name,
        "providerCreateRequestBody": invariant_request,
        "expectedReadbackProjection": {"repositoryId": repository_id, "rulesetId": github_binding("invariantRulesetId"), "name": invariant_name, "target": "branch", "enforcement": "active", "bypassActors": [], "conditions": invariant_request["conditions"], "rules": invariant_request["rules"]},
        "signatureAuthority": {"providerEnforcement": "ANY_GITHUB_VERIFIED_SIGNATURE", "providerPinsExactSshKey": False, "exactSshEd25519SignerEnforcedBy": "D0-B04_RUNTIME_LOCAL_GIT_VERIFY_COMMIT_AND_EXACT_GITHUB_SIGNING_KEY_READBACK", "providerVerificationRequired": {"verified": True, "reason": GITHUB_VERIFIED_COMMIT_REASON, "verifiedAtRequired": True}, "providerRuleDefenseInDepthOnly": True},
        "noBypassActorIncludingAdministrator": True,
    }
    signing_identity = {
        "designId": signing_design_id,
        "authoritySource": {"findingId": "D0-B04", "handoffId": "OP-D0-04", "catalogSpecific": True, "sharedAcrossCatalogsAllowed": False},
        "typedBindings": {"githubLogin": github_binding("signerGithubLogin", "GITHUB_LOGIN"), "sshEd25519PublicKey": github_binding("signerSshEd25519PublicKey", "SSH_ED25519_PUBLIC_KEY"), "sshSha256Fingerprint": github_binding("signerSshSha256Fingerprint", "SSH_SHA256_FINGERPRINT"), "providerKeyTitle": github_binding("signerSshKeyTitle", "NONEMPTY_STRING"), "providerSshSigningKeyId": github_binding("signerProviderSshSigningKeyId"), "providerCreatedAt": github_binding("signerProviderSshSigningKeyCreatedAt", "UTC_TIMESTAMP")},
        "providerRegistration": {"requestBody": {"key": github_binding("signerSshEd25519PublicKey", "SSH_ED25519_PUBLIC_KEY"), "title": github_binding("signerSshKeyTitle", "NONEMPTY_STRING")}, "authenticatedAndPublicReadbackRequired": True, "createOnlyIfExactKeyAbsentAtFreshBaseline": True, "deleteOnPreAdvanceRollbackOnlyIfCreatedByThisCeremony": True},
        "commitVerification": {"localExactKeyAndPrincipalRequired": True, "githubVerifiedRequired": True, "githubReason": GITHUB_VERIFIED_COMMIT_REASON, "githubVerifiedAtNonNullRequired": True, "bootstrapBRequired": True, "normalReleaseCPrimeRequired": True},
        "protectedJobAccess": copy.deepcopy(signer_access_interface),
        "revocation": {"localRevocationPolicyAuthoritative": True, "githubPersistentVerificationAfterKeyRemovalAcknowledged": True, "providerVerifiedHistoricalCommitDoesNotOverrideCurrentRevocation": True},
        "privateMaterial": {"providerRequestAllowed": False, "evidenceAllowed": False, "digestAllowed": False},
        "providerEvidenceKey": provider_evidence_keys["SIGNING_KEY_REGISTRATION_AND_READBACK"],
    }
    provider_authority_boundary = {
        "normalRefUpdateAuthority": "SOLE_CATALOG_SPECIFIC_WRITER_APP_VIA_PROTECTED_RELEASE_JOB",
        "rulesetMutationAuthority": "REPOSITORY_ADMINISTRATORS_AND_ORGANIZATION_OWNERS_AT_PROVIDER",
        "settingsAuthorityNature": "OPERATOR_CONTROLLED_AUDITED_PROCEDURAL_NOT_CRYPTOGRAPHIC",
        "nonBypassableIdentityClaimed": False,
        "adminDirectRefUpdateIsNormalPath": False,
        "settingsMutationRequiresSeparateOperatorHandoffAndAudit": True,
    }
    codeowners = {
        "path": ".github/CODEOWNERS",
        "proposedContentSha256": codeowners_digest,
        "sourceBranch": source_branch,
        "entries": [{"pattern": "*", "owners": [f"@pkgre/{catalog_id}-catalog-reviewers"]}, {"pattern": "/.github/CODEOWNERS", "owners": [f"@pkgre/{catalog_id}-security-reviewers"]}, {"pattern": "/.github/workflows/**", "owners": [f"@pkgre/{catalog_id}-security-reviewers"]}, {"pattern": "/.github/actions/**", "owners": [f"@pkgre/{catalog_id}-security-reviewers"]}],
        "ownersHaveWriteAccess": True,
        "writerAppIsOwner": False,
    }
    actions = {
        "enabled": True,
        "allowedActions": "SELECTED",
        "selectedPolicy": {"githubOwnedAllowed": False, "verifiedAllowed": False, "patternsAllowed": all_actions},
        "requireFullLengthCommitSha": True,
        "defaultWorkflowPermissions": "read",
        "canApprovePullRequestReviews": False,
        "forkPullRequestApprovalPolicy": GITHUB_FORK_PR_APPROVAL_POLICY,
        "forkPullRequestApprovalSemantics": {"goal": "AUTOMATIC_UNTRUSTED_READ_ONLY_FORK_VALIDATION_WHERE_PROVIDER_PERMITS", "leastRestrictivePinnedOpenApiEnum": True, "neverRequireApprovalEnumAvailable": False, "newGitHubAccountsMayStillRequireMaintainerApproval": True, "providerAntiAbuseBehaviorNotTrustAuthorization": True},
        "forkPullRequests": {"writeTokenAvailable": False, "secretsAvailable": False},
        "unlistedActionAllowed": False,
        "providerRequestBodies": {
            "permissions": {"enabled": True, "allowed_actions": "selected", "sha_pinning_required": True},
            "selectedActions": {"github_owned_allowed": False, "verified_allowed": False, "patterns_allowed": all_actions},
            "workflowPermissions": {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
            "forkPullRequestApproval": {"approval_policy": GITHUB_FORK_PR_APPROVAL_POLICY},
        },
        "expectedReadbackProjection": {"enabled": True, "allowedActions": "selected", "shaPinningRequired": True, "githubOwnedAllowed": False, "verifiedAllowed": False, "patternsAllowed": all_actions, "defaultWorkflowPermissions": "read", "canApprovePullRequestReviews": False, "forkPullRequestApprovalPolicy": GITHUB_FORK_PR_APPROVAL_POLICY},
    }
    classic_baseline = {"state": "PRESENT", "capturedConfigurationSource": GITHUB_GOVERNANCE_BASELINE_PATH, "requiredCheckContext": "validate"} if catalog_id == "rust" else {"state": "ABSENT", "capturedConfigurationSource": GITHUB_GOVERNANCE_BASELINE_PATH, "observedHttpStatus": 404}
    classic_transition = {
        "baseline": classic_baseline,
        "targetFinalState": "ABSENT",
        "stateMachineSubsequence": ["S3_BOOTSTRAP_B_SIGNED_AND_DUAL_VERIFIED", "S4_INVARIANT_AND_BOOTSTRAP_ADMISSION_ACTIVE", "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE"],
        "mutation": "REMOVE_ONLY_AFTER_INVARIANT_BOOTSTRAP_ADMISSION_AND_EFFECTIVE_RULES_READBACK" if catalog_id == "rust" else "CONFIRM_ABSENT_AFTER_INVARIANT_BOOTSTRAP_ADMISSION_AND_EFFECTIVE_RULES_READBACK",
        "orderedSteps": [
            {"order": 1, "action": "CAPTURE_FRESH_PRE_D2_SOURCE_SETTINGS_WORKFLOWS_AND_PROVE_MAIN_EQUALS_A", "evidenceKey": pre_mutation_capture_key},
            {"order": 2, "action": "INSTALL_AND_READ_BACK_BOOTSTRAP_ADMISSION_RULESET", "evidenceKey": provider_evidence_keys["ADMISSION_RULESET_ID_AND_READBACK"]},
            {"order": 3, "action": "INSTALL_AND_READ_BACK_NON_BYPASSABLE_INVARIANT_RULESET", "evidenceKey": provider_evidence_keys["INVARIANT_RULESET_ID_AND_READBACK"]},
            {"order": 4, "action": "READ_BACK_EFFECTIVE_MAIN_RULES_AND_PROVE_SOLE_APP_BYPASS_PLUS_INVARIANTS", "evidenceKey": effective_rules_key},
            {"order": 5, "action": "REMOVE_CLASSIC_PROTECTION" if catalog_id == "rust" else "CONFIRM_CLASSIC_PROTECTION_ABSENT", "evidenceKey": provider_evidence_keys["CLASSIC_BRANCH_PROTECTION_FINAL_READBACK"]},
            {"order": 6, "action": "READ_BACK_CLASSIC_PROTECTION_ABSENCE", "evidenceKey": provider_evidence_keys["CLASSIC_BRANCH_PROTECTION_FINAL_READBACK"]},
            {"order": 7, "action": "READ_BACK_EXACT_ADMISSION_AND_INVARIANT_RULESET_IDS_AND_FORMS", "evidenceKeys": [provider_evidence_keys["ADMISSION_RULESET_ID_AND_READBACK"], provider_evidence_keys["INVARIANT_RULESET_ID_AND_READBACK"]]},
            {"order": 8, "action": "REPEAT_EFFECTIVE_MAIN_RULES_PROOF_WITHOUT_GUARD_GAP", "evidenceKey": effective_rules_key},
            {"order": 9, "action": "PROVE_MAIN_STILL_EQUALS_FRESH_BASELINE_A", "evidenceKey": pre_mutation_capture_key},
        ],
        "refAdvanceAllowedDuringTransition": False,
        "tokenMintAllowedDuringTransition": False,
        "failureResult": "ABORT_AND_EXECUTE_PRE_ADVANCE_ROLLBACK;MAIN_MUST_EQUAL_FRESH_BASELINE_A",
    }
    pre_d2_capture = {
        "evidenceKey": pre_mutation_capture_key,
        "status": "NOT_YET_ASSIGNED",
        "captureRequiredAt": "IMMEDIATELY_BEFORE_FIRST_D2_PROVIDER_MUTATION",
        "maximumAgeSecondsAtFirstMutation": 600,
        "repository": repository,
        "repositoryId": repository_id,
        "canonicalOrigin": runtime_origin,
        "transport": "HTTPS",
        "credentialMode": "AUTHENTICATED_OPERATOR_ADMIN_WITHOUT_CREDENTIAL_CAPTURE",
        "sourceRef": source_ref,
        "sourceCommitOidStatus": "MUST_BE_CAPTURED_FRESH_NOT_COPIED_FROM_D0_BASELINE",
        "workflowPaths": [pages_path, candidate_path, release_path],
        "requiredFields": GITHUB_PROVIDER_REQUIRED_BINDINGS["D2_PRE_MUTATION_CAPTURE"],
        "abortOnAnyDrift": ["SOURCE_COMMIT_OID", "WORKFLOW_COMMIT_OR_BLOB_OR_CONTENT", "RULESETS", "EFFECTIVE_MAIN_RULES", "CLASSIC_BRANCH_PROTECTION", "ACTIONS_POLICY", "ENVIRONMENT", "APP_INSTALLATION_AND_PERMISSIONS"],
        "bindingUses": ["BOOTSTRAP_BASE", "CANDIDATE_ADMISSION", "REF_COMPARE_AND_SWAP", "ROLLBACK_BRANCH_SELECTION", "AUDIT_WINDOW_START", "FINAL_READBACK_COMPARISON"],
        "captureAndMutationSameOperatorCeremony": True,
    }
    resource_selectors: dict[str, dict[str, Any]] = {
        "ACTIONS_POLICY_READBACK": {"resourceType": "REPOSITORY_ACTIONS_POLICY", "repositoryId": repository_id},
        "ADMISSION_RULESET_ID_AND_READBACK": {"resourceType": "REPOSITORY_RULESET", "name": admission_name, "target": "branch"},
        "AUDIT_LOG_RECORDS": {"resourceType": "REPOSITORY_AUDIT_WINDOW", "repositoryId": repository_id, "startsAtCaptureEvidenceKey": pre_mutation_capture_key},
        "BOOTSTRAP_COMMIT_AND_REF_ADVANCE": {"resourceType": "SIGNED_BOOTSTRAP_AND_REF_TRANSITION", "sourceRef": source_ref, "baselineA": source_tip, "bootstrapCommitBinding": "bootstrapCommitB"},
        "CANDIDATE_CHECK_PRODUCER_ID_AND_RUN": {"resourceType": "CHECK_RUN", "context": check_context, "headShaSource": "CANDIDATE_SHA"},
        "CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK": {"resourceType": "WORKFLOW", "path": candidate_path, "name": candidate_name},
        "CLASSIC_BRANCH_PROTECTION_FINAL_READBACK": {"resourceType": "CLASSIC_BRANCH_PROTECTION", "sourceRef": source_ref, "targetState": "ABSENT"},
        "D2_PRE_MUTATION_CAPTURE": {"resourceType": "D2_PRE_MUTATION_CAPTURE", "repositoryId": repository_id, "sourceRef": source_ref},
        "EFFECTIVE_MAIN_RULES_READBACK": {"resourceType": "EFFECTIVE_BRANCH_RULES", "sourceRef": source_ref},
        "FIRST_NORMAL_RELEASE_RUN": {"resourceType": "TRUSTED_NORMAL_RELEASE_RUN", "workflowPath": release_path, "trustedWorkflowCommitBinding": "bootstrapCommitB", "sourceRef": source_ref},
        "INVARIANT_RULESET_ID_AND_READBACK": {"resourceType": "REPOSITORY_RULESET", "name": invariant_name, "target": "branch"},
        "PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK": {"resourceType": "WORKFLOW", "path": pages_path, "name": pages_name},
        "PROTECTED_ENVIRONMENT_ID_AND_READBACK": {"resourceType": "DEPLOYMENT_ENVIRONMENT", "name": environment_name},
        "PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING": {"resourceType": "PULL_REQUEST_REVIEW", "baseRef": source_ref, "headShaSource": "CANDIDATE_SHA"},
        "REF_UPDATE_AND_BYPASS_AUDIT": {"resourceType": "GIT_REF_UPDATE", "sourceRef": source_ref, "actorSlug": writer_slug},
        "RELEASE_APP_INSTALLATION_ID_AND_READBACK": {"resourceType": "GITHUB_APP_INSTALLATION", "appSlug": writer_slug, "repositoryId": repository_id},
        "RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK": {"resourceType": "WORKFLOW", "path": release_path, "name": release_name},
        "SIGNING_KEY_REGISTRATION_AND_READBACK": {"resourceType": "GITHUB_USER_SSH_SIGNING_KEY", "authorityDesignId": signing_design_id, "githubLoginBinding": "signerGithubLogin", "publicKeyBinding": "signerSshEd25519PublicKey"},
        "TRUSTED_SURFACE_TREE_READBACK": {"resourceType": "GIT_TRUSTED_SURFACE", "sourceRef": source_ref, "comparisonBaseCommitOid": source_tip},
    }
    resource_selectors = {kind: {"repositoryId": repository_id, **selector} for kind, selector in resource_selectors.items()}
    projection_inputs: dict[str, Any] = {
        "ACTIONS_POLICY_READBACK": actions,
        "ADMISSION_RULESET_ID_AND_READBACK": admission_ruleset,
        "AUDIT_LOG_RECORDS": {"repositoryId": repository_id, "startsAtCaptureEvidenceKey": pre_mutation_capture_key, "requiredActions": ["ACTIONS_POLICY_CHANGE", "APP_INSTALLATION_CHANGE", "BRANCH_PROTECTION_CHANGE", "ENVIRONMENT_CHANGE", "REF_UPDATE", "RULESET_CHANGE", "WORKFLOW_DISPATCH"]},
        "BOOTSTRAP_COMMIT_AND_REF_ADVANCE": {"sourceRef": source_ref, "baselineA": source_tip, "bootstrapB": {"soleParent": "BASELINE_A", "tree": "EXACT_FROZEN_BOOTSTRAP_TREE", "signature": "SSH_ED25519_D0_B04_CATALOG_SPECIFIC", "localVerification": "GIT_VERIFY_COMMIT_RAW_WITH_FROZEN_ALLOWED_SIGNERS_AND_EXACT_FINGERPRINT", "providerVerification": {"verified": True, "reason": GITHUB_VERIFIED_COMMIT_REASON, "verifiedAtRequired": True}, "signingIdentityEvidenceKey": signing_key_evidence_key}, "refUpdate": {"actor": "EXACT_RELEASE_APP_INSTALLATION", "force": False, "preUpdateOid": "BASELINE_A", "postUpdateOid": "BOOTSTRAP_COMMIT_B"}},
        "CANDIDATE_CHECK_PRODUCER_ID_AND_RUN": {"check": candidate_ci["check"], "workflow": {"path": candidate_path, "name": candidate_name, "contentSha256": candidate_digest}},
        "CANDIDATE_WORKFLOW_PROVIDER_ID_AND_READBACK": {"path": candidate_path, "name": candidate_name, "contentSha256": candidate_digest, "trigger": candidate_ci["trigger"], "permissions": permissions_candidate},
        "CLASSIC_BRANCH_PROTECTION_FINAL_READBACK": {"sourceRef": source_ref, "targetFinalState": "ABSENT", "transition": classic_transition},
        "D2_PRE_MUTATION_CAPTURE": pre_d2_capture,
        "EFFECTIVE_MAIN_RULES_READBACK": {"sourceRef": source_ref, "admission": admission_ruleset, "invariants": invariant_ruleset, "classicFinalState": "ABSENT"},
        "FIRST_NORMAL_RELEASE_RUN": {"releaseWorkflowPath": release_path, "trustedWorkflowCommit": "BOOTSTRAP_COMMIT_B", "candidateTreeCommit": "C0_UNTRUSTED_DATA_ONLY", "signedReleaseCommit": "C_PRIME_TREE_EQUALS_C0_SOLE_PARENT_B", "sourceRef": source_ref, "environment": environment, "writerToken": writer["token"], "signerAccess": signer_access_interface, "signedCommit": release_job["signedCommit"], "refUpdate": release_job["refUpdate"], "freshCaptureEvidenceKey": pre_mutation_capture_key},
        "INVARIANT_RULESET_ID_AND_READBACK": invariant_ruleset,
        "PAGES_WORKFLOW_PROVIDER_ID_AND_READBACK": {"path": pages_path, "name": pages_name, "contentSha256": pages_digest, "triggers": pages_workflow["triggers"], "jobs": pages_workflow["jobs"]},
        "PROTECTED_ENVIRONMENT_ID_AND_READBACK": environment,
        "PULL_REQUEST_REVIEW_AND_CANDIDATE_BINDING": admission_job["pullRequest"],
        "REF_UPDATE_AND_BYPASS_AUDIT": {"refUpdate": release_job["refUpdate"], "writer": {"slug": writer_slug, "installation": writer["installation"]}, "admissionBypass": writer["admissionBypass"]},
        "RELEASE_APP_INSTALLATION_ID_AND_READBACK": {"slug": writer_slug, "installation": writer["installation"], "installedPermissions": writer["installedPermissions"], "token": writer["token"]},
        "RELEASE_WORKFLOW_PROVIDER_ID_AND_READBACK": {"path": release_path, "name": release_name, "contentSha256": release_digest, "triggers": release_workflow["triggers"], "jobPermissions": {key: value["permissions"] for key, value in release_workflow["jobs"].items()}, "releaseAuthorityConsumers": release_authority_consumers},
        "SIGNING_KEY_REGISTRATION_AND_READBACK": signing_identity,
        "TRUSTED_SURFACE_TREE_READBACK": trusted_surface,
    }
    provider_contract = github_provider_contract(catalog_id, repository, repository_id, source_tip, source_ref, source_branch, candidate_path, release_path, pages_path, candidate_name, release_name, pages_name, check_context, environment_name, reviewer, dispatcher, writer_slug, admission_ruleset, invariant_ruleset, signing_identity, actions, pre_mutation_capture_key, signing_key_evidence_key, bootstrap_evidence_key, normal_release_evidence_key)
    provider_evidence = [
        {
            "evidenceKey": provider_evidence_keys[kind],
            "kind": kind,
            "catalogId": catalog_id,
            "designId": design_id,
            "repository": repository,
            "repositoryId": repository_id,
            "resourceSelector": resource_selectors[kind],
            "projectionSchema": f"pkgre-d2-github-{kind.lower().replace('_', '-')}-projection-v1",
            "projectionDomain": GITHUB_PROVIDER_PROJECTION_DOMAIN,
            "expectedProjectionSha256": github_provider_projection_digest(kind, {"catalogId": catalog_id, "designId": design_id, "repository": repository, "repositoryId": repository_id, "resourceSelector": resource_selectors[kind], "configuration": projection_inputs[kind]}),
            "requiredReturnedBindings": GITHUB_PROVIDER_REQUIRED_BINDINGS[kind],
            "allUnlistedReturnedFields": "REJECT",
            "providerAssignedIdStatus": "NOT_YET_ASSIGNED",
            "readbackRequiredAt": "D2_SIGNING",
        }
        for kind in GITHUB_PROVIDER_EVIDENCE_KINDS
    ]
    rollback = {
        "schema": "pkgre-d0-github-state-dependent-rollback-v2",
        "trigger": "ANY_PROVIDER_READBACK_MISMATCH_UNEXPECTED_REF_CHANGE_OR_TRUSTED_SURFACE_CHANGE",
        "freshCapture": {"evidenceKey": pre_mutation_capture_key, "sourceTipField": "sourceCommitOid", "required": True, "historicalD0BaselineMaySubstitute": False},
        "stateMachineRollback": copy.deepcopy(provider_contract["bootstrapStateMachine"]["rollback"]),
        "preAdvancePostcondition": "FRESH_GET_MAIN_REF_EQUALS_BASELINE_A;NO_REF_MUTATION;EXACT_PRE_CAPTURE_PROVIDER_STATE_RESTORED;EVERY_ACTION_AND_SKIP_EVIDENCED",
        "postAdvancePostcondition": "EXACT_B_OR_C_PRIME_CLASSIFIED;NO_HISTORY_REWRITE;WRITES_FROZEN;EXACT_ADMISSION_FORM_CLASSIFIED_AND_PRESERVED;ONLY_ACTUALLY_CREATED_COMMITS_AND_AUDIT_EVIDENCE_RETAINED;NEW_SIGNED_FORWARD_RECOVERY_CEREMONY_REQUIRED",
        "unknownRefPostcondition": "EVERY_REF_MUTATION_PROHIBITED;KNOWN_CREDENTIALS_REVOKED_OR_BLOCKED;PROVIDER_AND_AUDIT_EVIDENCE_PRESERVED;SEPARATE_INCIDENT_HANDLING_REQUIRED",
        "operatorReviewRequired": True,
    }
    return {
        "catalogId": catalog_id,
        "designId": design_id,
        "repository": repository,
        "repositoryId": repository_id,
        "sourceAuthority": {"canonicalRuntimeOrigin": runtime_origin, "transport": "HTTPS", "credentialMode": "ANONYMOUS_READ_ONLY", "redirectsAllowed": False, "credentialInUrlAllowed": False, "sourceRef": source_ref, "sourceBranch": source_branch, "symbolicHeadAllowed": False, "collectionRemote": {"origin": collection_remote, "transport": "SSH", "purpose": "REVIEWED_LOCAL_D0_COLLECTION_ONLY", "runtimeUseAllowed": False}},
        "sourceTipAtD0Baseline": source_tip,
        "sourceTreeOidAtD0Baseline": source_tree_oid,
        "preD2MutationCapture": pre_d2_capture,
        "candidateCI": candidate_ci,
        "releaseWorkflow": release_workflow,
        "pagesWorkflow": pages_workflow,
        "trustedSurface": trusted_surface,
        "environment": environment,
        "writer": writer,
        "rulesets": {"admission": admission_ruleset, "invariants": invariant_ruleset},
        "providerAuthorityBoundary": provider_authority_boundary,
        "classicBranchProtectionTransition": classic_transition,
        "codeowners": codeowners,
        "actions": actions,
        "providerAssignedEvidence": provider_evidence,
        "providerContract": provider_contract,
        "rollback": rollback,
    }


GITHUB_BINDING_REPRESENTATIVES: dict[str, Any] = {
    "BOOLEAN": True,
    "GITHUB_LEGACY_BASE_PERMISSION": "write",
    "GITHUB_LOGIN": "audit-user",
    "LOWERCASE_SHA1_40": "a" * 40,
    "NONEMPTY_STRING": "audit-value",
    "POSITIVE_INT64": 123,
    "SSH_ED25519_PUBLIC_KEY": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC audit",
    "SSH_SHA256_FINGERPRINT": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "UTC_TIMESTAMP": "2026-01-01T00:00:00Z",
}
GITHUB_OPENAPI_RESPONSE_BINDING_TYPES = frozenset({"BOOLEAN", "GITHUB_LEGACY_BASE_PERMISSION", "GITHUB_LOGIN", "LOWERCASE_SHA1_40", "POSITIVE_INT64"})
OPENAPI_SCHEMA_TYPES = frozenset({"array", "boolean", "integer", "number", "object", "string"})
OPENAPI_AUDITED_FORMATS = frozenset({"int32", "int64"})
OPENAPI_SCHEMA_SUPPORTED_KEYS = frozenset({"$ref", "additionalProperties", "allOf", "anyOf", "default", "deprecated", "description", "discriminator", "enum", "example", "format", "items", "maxItems", "maxLength", "maxProperties", "maximum", "minItems", "minLength", "minimum", "nullable", "oneOf", "pattern", "properties", "readOnly", "required", "title", "type", "uniqueItems", "writeOnly", "xml"})


def unsupported_openapi_schema_keys(schema: dict[str, Any]) -> set[str]:
    require(all(isinstance(key, str) for key in schema), "OpenAPI schema keys must be strings")
    return {key for key in schema if key not in OPENAPI_SCHEMA_SUPPORTED_KEYS and not key.startswith("x-")}


def parse_openapi_json(raw: bytes, label: str) -> dict[str, Any]:
    require(len(raw) <= MAX_ARTIFACT_BYTES, f"{label}: OpenAPI JSON exceeds {MAX_ARTIFACT_BYTES} bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=no_duplicate_object, parse_constant=reject_json_constant)
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError, json.JSONDecodeError, GateVerificationError) as error:
        raise GateVerificationError(f"invalid strict OpenAPI JSON in {label}: {error}") from error
    require(isinstance(value, dict), f"{label}: OpenAPI document must be an object")
    return value


def load_pinned_github_openapi(path: Path, expected_sha256: str = GITHUB_REST_OPENAPI_SHA256) -> tuple[bytes, dict[str, Any]]:
    require(HEX64_RE.fullmatch(expected_sha256) is not None, "pinned GitHub OpenAPI digest is invalid")
    raw = load_regular(path, "pinned GitHub OpenAPI document", MAX_ARTIFACT_BYTES)
    require(sha256(raw) == expected_sha256, "pinned GitHub OpenAPI digest mismatch")
    return raw, parse_openapi_json(raw, "pinned GitHub OpenAPI document")


class GitHubOpenApiDocument:
    def __init__(self, document: dict[str, Any]) -> None:
        self.document = obj(document, "GitHub OpenAPI document")
        require(isinstance(self.document.get("openapi"), str) and self.document["openapi"].startswith("3.0."), "GitHub OpenAPI document: expected OpenAPI 3.0.x")
        self.paths = obj(self.document.get("paths"), "GitHub OpenAPI paths")

    def resolve(self, value: Any, label: str) -> Any:
        seen: set[str] = set()
        while isinstance(value, dict) and "$ref" in value:
            require(set(value) == {"$ref"}, f"{label}: OpenAPI 3.0 $ref siblings are forbidden")
            reference = nonempty(value["$ref"], f"{label}.$ref")
            require(reference.startswith("#/"), f"{label}: only local OpenAPI references are supported")
            require(reference not in seen, f"{label}: cyclic direct OpenAPI reference")
            seen.add(reference)
            current: Any = self.document
            for raw_component in reference[2:].split("/"):
                require(re.fullmatch(r"(?:[^~]|~[01])*", raw_component) is not None, f"{label}: invalid JSON pointer escape in $ref")
                component = raw_component.replace("~1", "/").replace("~0", "~")
                if isinstance(current, dict):
                    require(component in current, f"{label}: unresolved OpenAPI reference {reference!r}")
                    current = current[component]
                elif isinstance(current, list):
                    require(component.isdigit() and int(component) < len(current), f"{label}: unresolved OpenAPI reference {reference!r}")
                    current = current[int(component)]
                else:
                    raise GateVerificationError(f"{label}: unresolved OpenAPI reference {reference!r}")
            value = current
        return value

    def operation(self, contract_path: str, method: str, label: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        require(method in {"get", "post", "put", "patch", "delete"}, f"{label}: unsupported HTTP method")
        candidates: list[tuple[int, str, dict[str, Any], dict[str, str]]] = []
        for openapi_path, raw_path_item in self.paths.items():
            require(isinstance(openapi_path, str), f"{label}: OpenAPI path key must be a string")
            path_item = obj(self.resolve(raw_path_item, f"OpenAPI path {openapi_path}"), f"OpenAPI path {openapi_path}")
            if method not in path_item:
                continue
            operation = obj(self.resolve(path_item[method], f"{label} OpenAPI operation"), f"{label} OpenAPI operation")
            parameter_map = openapi_parameter_map(self, path_item, operation, label)
            fragments = re.split(r"(\{[^{}]+\})", openapi_path)
            parameter_names: list[str] = []
            pattern_parts: list[str] = []
            for fragment in fragments:
                if fragment.startswith("{"):
                    parameter_name = fragment[1:-1]
                    parameter_names.append(parameter_name)
                    parameter = parameter_map.get(("path", parameter_name), {})
                    multi_segment = parameter.get("x-multi-segment", False)
                    require(type(multi_segment) is bool, f"{label}: OpenAPI path parameter {parameter_name!r} has malformed x-multi-segment")
                    pattern_parts.append("(.+?)" if multi_segment else "([^/]+)")
                else:
                    pattern_parts.append(re.escape(fragment))
            require(len(parameter_names) == len(set(parameter_names)), f"{label}: duplicate OpenAPI path placeholder")
            match = re.fullmatch("".join(pattern_parts), contract_path)
            if match is None:
                continue
            parameters = dict(zip(parameter_names, match.groups(), strict=True))
            literal_score = len(re.sub(r"\{[^{}]+\}", "", openapi_path))
            candidates.append((literal_score, openapi_path, path_item, parameters))
        require(candidates, f"{label}: missing OpenAPI method/path match for {method.upper()} {contract_path}")
        best_score = max(candidate[0] for candidate in candidates)
        best = [candidate for candidate in candidates if candidate[0] == best_score]
        require(len(best) == 1, f"{label}: ambiguous most-specific OpenAPI method/path match for {method.upper()} {contract_path}")
        _, openapi_path, path_item, parameters = best[0]
        operation = obj(self.resolve(path_item[method], f"{label} OpenAPI operation"), f"{label} OpenAPI operation")
        return openapi_path, operation, parameters


def openapi_schema_conjunctions(document: GitHubOpenApiDocument, schema: Any, label: str) -> list[list[dict[str, Any]]]:
    resolved = obj(document.resolve(schema, label), label)
    unknown = unsupported_openapi_schema_keys(resolved)
    require(not unknown, f"{label}: unsupported OpenAPI schema keywords {sorted(unknown)!r}")
    for boolean_key in ("deprecated", "nullable", "readOnly", "writeOnly"):
        if boolean_key in resolved:
            require(type(resolved[boolean_key]) is bool, f"{label}.{boolean_key}: expected boolean")
    if "type" in resolved:
        schema_type = nonempty(resolved["type"], f"{label}.type")
        require(schema_type in OPENAPI_SCHEMA_TYPES, f"{label}: unsupported OpenAPI schema type {schema_type!r}")
    base = {key: value for key, value in resolved.items() if key not in {"allOf", "anyOf", "oneOf"}}
    conjunctions: list[list[dict[str, Any]]] = [[base]]
    if "allOf" in resolved:
        components = arr(resolved["allOf"], f"{label}.allOf")
        require(components, f"{label}.allOf: expected nonempty array")
        for index, component in enumerate(components):
            component_alternatives = openapi_schema_conjunctions(document, component, f"{label}.allOf[{index}]")
            conjunctions = [left + right for left in conjunctions for right in component_alternatives]
    for composition in ("oneOf", "anyOf"):
        if composition not in resolved:
            continue
        alternatives = arr(resolved[composition], f"{label}.{composition}")
        require(alternatives, f"{label}.{composition}: expected nonempty array")
        expanded = [variant for index, alternative in enumerate(alternatives) for variant in openapi_schema_conjunctions(document, alternative, f"{label}.{composition}[{index}]")]
        conjunctions = [left + right for left in conjunctions for right in expanded]
    return conjunctions


def openapi_schema_conjunction_types(conjunction: list[dict[str, Any]], label: str) -> set[str] | None:
    allowed: set[str] | None = None
    for index, component in enumerate(conjunction):
        if "type" not in component:
            continue
        schema_type = nonempty(component["type"], f"{label}[{index}].type")
        require(schema_type in OPENAPI_SCHEMA_TYPES, f"{label}[{index}]: unsupported OpenAPI schema type {schema_type!r}")
        component_types = {schema_type}
        if component.get("nullable") is True:
            component_types.add("null")
        allowed = component_types if allowed is None else allowed & component_types
    return allowed


def openapi_schema_types(document: GitHubOpenApiDocument, schema: Any, label: str) -> set[str]:
    conjunctions = openapi_schema_conjunctions(document, schema, label)
    alternative_types = [openapi_schema_conjunction_types(conjunction, f"{label}.alternative[{index}]") for index, conjunction in enumerate(conjunctions)]
    if any(types is None for types in alternative_types):
        return set()
    return set().union(*(types for types in alternative_types if types is not None))


def openapi_value_errors(document: GitHubOpenApiDocument, value: Any, schema: Any, label: str, direction: str = "neutral") -> list[str]:
    require(direction in {"neutral", "request", "response"}, f"{label}: invalid OpenAPI validation direction")
    resolved = document.resolve(schema, label)
    if not isinstance(resolved, dict):
        return [f"{label}: schema is not an object"]
    unknown = unsupported_openapi_schema_keys(resolved)
    if unknown:
        return [f"{label}: unsupported OpenAPI schema keywords {sorted(unknown)!r}"]
    errors: list[str] = []
    for boolean_key in ("deprecated", "nullable", "readOnly", "writeOnly"):
        if boolean_key in resolved and type(resolved[boolean_key]) is not bool:
            errors.append(f"{label}.{boolean_key}: expected boolean")
    if direction == "request" and resolved.get("readOnly") is True:
        errors.append(f"{label}: readOnly value is forbidden in an OpenAPI request witness")
    if direction == "response" and resolved.get("writeOnly") is True:
        errors.append(f"{label}: writeOnly value is forbidden in an OpenAPI response witness")
    if "discriminator" in resolved:
        discriminator = resolved["discriminator"]
        if not isinstance(discriminator, dict) or not isinstance(discriminator.get("propertyName"), str) or not discriminator["propertyName"]:
            errors.append(f"{label}.discriminator: expected object with nonempty propertyName")
        elif set(discriminator) - {"propertyName", "mapping"}:
            errors.append(f"{label}.discriminator: unsupported fields")
        elif "mapping" in discriminator and (not isinstance(discriminator["mapping"], dict) or any(not isinstance(key, str) or not isinstance(target, str) or not target for key, target in discriminator["mapping"].items())):
            errors.append(f"{label}.discriminator.mapping: expected string-to-nonempty-string object")
    if "xml" in resolved and not isinstance(resolved["xml"], dict):
        errors.append(f"{label}.xml: expected object")
    if "format" in resolved:
        schema_format = resolved["format"]
        if not isinstance(schema_format, str) or schema_format not in OPENAPI_AUDITED_FORMATS:
            errors.append(f"{label}.format: unsupported OpenAPI format {schema_format!r}")
        elif schema_format == "int32" and (type(value) is not int or not -(2**31) <= value < 2**31):
            errors.append(f"{label}: int32 format violated")
        elif schema_format == "int64" and (type(value) is not int or not -(2**63) <= value < 2**63):
            errors.append(f"{label}: int64 format violated")
    all_of = resolved.get("allOf", [])
    if not isinstance(all_of, list) or ("allOf" in resolved and not all_of):
        errors.append(f"{label}.allOf: expected nonempty array")
        all_of = []
    for index, component in enumerate(all_of):
        errors.extend(openapi_value_errors(document, value, component, f"{label}.allOf[{index}]", direction))
    for composition in ("oneOf", "anyOf"):
        if composition not in resolved:
            continue
        alternatives = resolved[composition]
        if not isinstance(alternatives, list) or not alternatives:
            errors.append(f"{label}.{composition}: expected nonempty array")
            continue
        outcomes = [openapi_value_errors(document, value, alternative, f"{label}.{composition}[{index}]", direction) for index, alternative in enumerate(alternatives)]
        matches = sum(not outcome for outcome in outcomes)
        if (composition == "oneOf" and matches != 1) or (composition == "anyOf" and matches < 1):
            errors.append(f"{label}: {composition} matched {matches} alternatives")
    schema_type = resolved.get("type")
    predicates: dict[str, bool] = {
        "array": isinstance(value, list),
        "boolean": type(value) is bool,
        "integer": type(value) is int,
        "number": (type(value) is int or type(value) is float) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }
    if schema_type is not None:
        if not isinstance(schema_type, str) or not schema_type:
            errors.append(f"{label}.type: expected nonempty string")
        elif schema_type not in predicates:
            errors.append(f"{label}: unsupported OpenAPI schema type {schema_type!r}")
        elif not predicates[schema_type] and not (value is None and resolved.get("nullable") is True):
            errors.append(f"{label}: expected {schema_type};observed={type(value).__name__}")
            return errors
    if "enum" in resolved:
        enum_values = resolved["enum"]
        if not isinstance(enum_values, list) or not enum_values:
            errors.append(f"{label}.enum: expected nonempty array")
        elif value not in enum_values:
            errors.append(f"{label}: value is outside OpenAPI enum")
    if isinstance(value, dict):
        required = resolved.get("required", [])
        if not isinstance(required, list) or any(not isinstance(key, str) for key in required) or len(required) != len(set(required)):
            errors.append(f"{label}.required: expected unique string array")
            required = []
        missing = set(required) - set(value)
        if missing:
            errors.append(f"{label}: missing required properties {sorted(missing)!r}")
        properties = resolved.get("properties", {})
        if not isinstance(properties, dict):
            errors.append(f"{label}.properties: expected object")
            properties = {}
        additional = resolved.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                errors.extend(openapi_value_errors(document, item, properties[key], f"{label}.{key}", direction))
            elif additional is False:
                errors.append(f"{label}: additional property {key!r} is forbidden")
            elif isinstance(additional, dict):
                errors.extend(openapi_value_errors(document, item, additional, f"{label}.{key}", direction))
            elif additional is not True:
                errors.append(f"{label}.additionalProperties: expected boolean or schema")
        if "maxProperties" in resolved and (type(resolved["maxProperties"]) is not int or resolved["maxProperties"] < 0 or len(value) > resolved["maxProperties"]):
            errors.append(f"{label}: maxProperties violated")
    if isinstance(value, list):
        if "items" in resolved:
            for index, item in enumerate(value):
                errors.extend(openapi_value_errors(document, item, resolved["items"], f"{label}[{index}]", direction))
        if "minItems" in resolved and (type(resolved["minItems"]) is not int or resolved["minItems"] < 0 or len(value) < resolved["minItems"]):
            errors.append(f"{label}: minItems violated")
        if "maxItems" in resolved and (type(resolved["maxItems"]) is not int or resolved["maxItems"] < 0 or len(value) > resolved["maxItems"]):
            errors.append(f"{label}: maxItems violated")
        if "uniqueItems" in resolved and type(resolved["uniqueItems"]) is not bool:
            errors.append(f"{label}.uniqueItems: expected boolean")
        if resolved.get("uniqueItems") is True:
            try:
                encoded = [json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) for item in value]
            except (TypeError, ValueError) as error:
                errors.append(f"{label}: uniqueItems witness is not strict JSON:{error}")
            else:
                if len(encoded) != len(set(encoded)):
                    errors.append(f"{label}: uniqueItems violated")
    if type(value) in {int, float}:
        if type(value) is float and not math.isfinite(value):
            errors.append(f"{label}: non-finite number")
        if "minimum" in resolved:
            minimum = resolved["minimum"]
            if type(minimum) not in {int, float} or (type(minimum) is float and not math.isfinite(minimum)):
                errors.append(f"{label}.minimum: expected finite number")
            elif value < minimum:
                errors.append(f"{label}: minimum violated")
        if "maximum" in resolved:
            maximum = resolved["maximum"]
            if type(maximum) not in {int, float} or (type(maximum) is float and not math.isfinite(maximum)):
                errors.append(f"{label}.maximum: expected finite number")
            elif value > maximum:
                errors.append(f"{label}: maximum violated")
    if isinstance(value, str):
        if "minLength" in resolved and (type(resolved["minLength"]) is not int or resolved["minLength"] < 0 or len(value) < resolved["minLength"]):
            errors.append(f"{label}: minLength violated")
        if "maxLength" in resolved and (type(resolved["maxLength"]) is not int or resolved["maxLength"] < 0 or len(value) > resolved["maxLength"]):
            errors.append(f"{label}: maxLength violated")
        if "pattern" in resolved:
            try:
                matches = re.search(resolved["pattern"], value) is not None
            except (TypeError, re.error) as error:
                errors.append(f"{label}: unsupported OpenAPI regular expression:{error}")
            else:
                if not matches:
                    errors.append(f"{label}: pattern violated")
    return errors


def validate_openapi_schema_subset(document: GitHubOpenApiDocument, value: Any, schema: Any, label: str, direction: str = "neutral") -> None:
    errors = openapi_value_errors(document, value, schema, label, direction)
    if errors:
        raise GateVerificationError(f"{label}: OpenAPI schema mismatch:{errors[0]}")


def github_binding_registry(catalog: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    bindings: dict[str, dict[str, Any]] = {}
    for index, raw_binding in enumerate(arr(catalog["providerContract"]["typedBindings"], f"{label}.typedBindings")):
        binding = obj(raw_binding, f"{label}.typedBindings[{index}]")
        name = nonempty(binding.get("name"), f"{label}.typedBindings[{index}].name")
        require(name not in bindings, f"{label}: duplicate typed binding {name!r}")
        bindings[name] = binding
    return bindings


def github_binding_representative(name: str, bindings: dict[str, dict[str, Any]], label: str) -> Any:
    require(name in bindings, f"{label}: unknown typed binding {name!r}")
    binding_type = nonempty(bindings[name].get("type"), f"{label} binding type")
    require(binding_type in GITHUB_BINDING_REPRESENTATIVES, f"{label}: binding type {binding_type!r} has no safe audit representative")
    return copy.deepcopy(GITHUB_BINDING_REPRESENTATIVES[binding_type])


def substitute_github_body_bindings(value: Any, bindings: dict[str, dict[str, Any]], label: str) -> Any:
    if isinstance(value, dict):
        if "$binding" in value:
            require(set(value) == {"$binding", "type"}, f"{label}: malformed whole typed binding")
            name = nonempty(value["$binding"], f"{label}.$binding")
            declared_type = nonempty(value["type"], f"{label}.type")
            require(name in bindings and bindings[name].get("type") == declared_type, f"{label}: typed binding declaration mismatch for {name!r}")
            require(declared_type != "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", f"{label}: runtime-only OpenAPI request body binding cannot be nested")
            return github_binding_representative(name, bindings, label)
        return {key: substitute_github_body_bindings(item, bindings, f"{label}.{key}") for key, item in value.items()}
    if isinstance(value, list):
        return [substitute_github_body_bindings(item, bindings, f"{label}[{index}]") for index, item in enumerate(value)]
    return value


def openapi_parameter_map(document: GitHubOpenApiDocument, path_item: dict[str, Any], operation: dict[str, Any], label: str) -> dict[tuple[str, str], dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for layer_name, layer in (("path", path_item.get("parameters", [])), ("operation", operation.get("parameters", []))):
        rows = arr(layer, f"{label}.{layer_name}Parameters")
        seen: set[tuple[str, str]] = set()
        for index, raw_parameter in enumerate(rows):
            parameter = obj(document.resolve(raw_parameter, f"{label}.{layer_name}Parameters[{index}]"), f"{label}.{layer_name}Parameters[{index}]")
            location = nonempty(parameter.get("in"), f"{label}.{layer_name}Parameters[{index}].in")
            require(location in {"path", "query", "header", "cookie"}, f"{label}: unsupported OpenAPI parameter location {location!r}")
            name = nonempty(parameter.get("name"), f"{label}.{layer_name}Parameters[{index}].name")
            key = (location, name)
            require(key not in seen, f"{label}: duplicate {layer_name}-level OpenAPI parameter {key!r}")
            seen.add(key)
            merged[key] = parameter
    return merged


def coerce_openapi_parameter_value(document: GitHubOpenApiDocument, raw_value: Any, schema: Any, label: str) -> Any:
    if type(raw_value) is not str:
        validate_openapi_schema_subset(document, raw_value, schema, label)
        return raw_value
    schema_types = openapi_schema_types(document, schema, label)
    candidates: list[Any] = [raw_value] if not schema_types or "string" in schema_types else []
    if "integer" in schema_types and re.fullmatch(r"-?(?:0|[1-9][0-9]*)", raw_value):
        candidates.append(int(raw_value))
    if "number" in schema_types:
        try:
            number = float(raw_value)
        except ValueError:
            pass
        else:
            if math.isfinite(number):
                candidates.append(number)
    if "boolean" in schema_types and raw_value in {"true", "false"}:
        candidates.append(raw_value == "true")
    valid: list[Any] = []
    for candidate in candidates:
        if not openapi_value_errors(document, candidate, schema, label):
            valid.append(candidate)
    require(valid, f"{label}: serialized parameter is incompatible with OpenAPI schema")
    distinct = {(type(candidate).__name__, repr(candidate)) for candidate in valid}
    require(len(distinct) == 1, f"{label}: serialized parameter has ambiguous OpenAPI coercion")
    return valid[0]


def validate_openapi_parameter_encoding(parameter: dict[str, Any], location: str, name: str, label: str) -> None:
    require(location in {"path", "query"}, f"{label}: unsupported OpenAPI parameter location {location!r}")
    require("schema" in parameter and "content" not in parameter, f"{label}: unsupported OpenAPI {location} parameter encoding for {name!r}")
    for boolean_key in ("deprecated", "required"):
        if boolean_key in parameter:
            require(type(parameter[boolean_key]) is bool, f"{label}: OpenAPI {location} parameter {name!r} has non-boolean {boolean_key}")
    require("allowEmptyValue" not in parameter, f"{label}: OpenAPI {location} parameter {name!r} uses unsupported allowEmptyValue")
    require("allowReserved" not in parameter, f"{label}: OpenAPI {location} parameter {name!r} uses unsupported allowReserved")
    expected_style, expected_explode = ("simple", False) if location == "path" else ("form", True)
    if "style" in parameter:
        require(parameter["style"] == expected_style, f"{label}: OpenAPI {location} parameter {name!r} uses unsupported style")
    if "explode" in parameter:
        require(type(parameter["explode"]) is bool and parameter["explode"] is expected_explode, f"{label}: OpenAPI {location} parameter {name!r} uses unsupported explode")
    if location == "path":
        multi_segment = parameter.get("x-multi-segment", False)
        require(type(multi_segment) is bool, f"{label}: OpenAPI path parameter {name!r} has malformed x-multi-segment")
    else:
        require("x-multi-segment" not in parameter, f"{label}: OpenAPI query parameter {name!r} uses unsupported x-multi-segment")


def audit_github_openapi_parameters(document: GitHubOpenApiDocument, openapi_path: str, path_item: dict[str, Any], operation: dict[str, Any], captured_path_parameters: dict[str, str], contract_operation: dict[str, Any], bindings: dict[str, dict[str, Any]], label: str) -> int:
    parameters = openapi_parameter_map(document, path_item, operation, label)
    placeholders = re.findall(r"\{([^{}]+)\}", openapi_path)
    require(set(placeholders) == set(captured_path_parameters), f"{label}: internal OpenAPI path-parameter mismatch")
    declared_path_parameters = {name for location, name in parameters if location == "path"}
    require(declared_path_parameters == set(placeholders), f"{label}: OpenAPI path parameter declarations do not exactly match path placeholders")
    for (location, name), parameter in parameters.items():
        if "required" in parameter:
            require(type(parameter["required"]) is bool, f"{label}: OpenAPI {location} parameter {name!r} has non-boolean required")
        if location == "path":
            require(parameter.get("required") is True, f"{label}: OpenAPI path parameter {name!r} is not required")
        if location in {"header", "cookie"}:
            require(parameter.get("required") is not True, f"{label}: unsupported required OpenAPI {location} parameter {name!r}")
    audited = 0
    for name in placeholders:
        key = ("path", name)
        require(key in parameters, f"{label}: undeclared OpenAPI path parameter {name!r}")
        parameter = parameters[key]
        validate_openapi_parameter_encoding(parameter, "path", name, label)
        require(parameter.get("required") is True, f"{label}: OpenAPI path parameter {name!r} is not required")
        serialized = captured_path_parameters[name]
        require("/" not in serialized or parameter.get("x-multi-segment") is True, f"{label}: slash-containing value for non-multi-segment OpenAPI path parameter {name!r}")
        binding_match = re.fullmatch(r"\$binding:([A-Za-z0-9_.:-]+)", serialized)
        require(binding_match is not None or "$binding:" not in serialized, f"{label}: embedded path binding is unsupported")
        value = github_binding_representative(binding_match.group(1), bindings, label) if binding_match else serialized
        coerce_openapi_parameter_value(document, value, parameter["schema"], f"{label}.path.{name}")
        audited += 1
    query_rows = arr(contract_operation["request"].get("queryTemplate", []), f"{label}.queryTemplate")
    seen_query: set[str] = set()
    for index, raw_row in enumerate(query_rows):
        row = obj(raw_row, f"{label}.queryTemplate[{index}]")
        require(set(row) == {"name", "value"}, f"{label}.queryTemplate[{index}]: object-key mismatch")
        name = nonempty(row["name"], f"{label}.queryTemplate[{index}].name")
        require(name not in seen_query, f"{label}: duplicate query parameter {name!r}")
        seen_query.add(name)
        key = ("query", name)
        require(key in parameters, f"{label}: unknown OpenAPI query parameter {name!r}")
        parameter = parameters[key]
        validate_openapi_parameter_encoding(parameter, "query", name, label)
        raw_value = row["value"]
        if raw_value == "$page":
            value: Any = 1
        elif isinstance(raw_value, str) and re.fullmatch(r"\$binding:([A-Za-z0-9_.:-]+)", raw_value):
            value = github_binding_representative(raw_value.split(":", 1)[1], bindings, label)
        else:
            require(isinstance(raw_value, str) and "$binding:" not in raw_value, f"{label}: unsupported query binding serialization")
            value = raw_value
        coerce_openapi_parameter_value(document, value, parameter["schema"], f"{label}.query.{name}")
        audited += 1
    required_query: set[str] = set()
    for (location, name), parameter in parameters.items():
        if location == "query" and parameter.get("required") is True:
            validate_openapi_parameter_encoding(parameter, "query", name, label)
            required_query.add(name)
    require(required_query <= seen_query, f"{label}: missing required OpenAPI query parameters {sorted(required_query - seen_query)!r}")
    return audited


def openapi_schema_required_set(component: dict[str, Any], label: str) -> set[str]:
    required = component.get("required", [])
    require(isinstance(required, list) and all(isinstance(key, str) for key in required) and len(required) == len(set(required)), f"{label}.required: expected unique string array")
    return set(required)


def openapi_conjunction_container_compatible(conjunction: list[dict[str, Any]], container_type: str, label: str) -> bool:
    require(all(component.get("writeOnly") is not True for component in conjunction), f"{label}: writeOnly OpenAPI response container cannot be traversed")
    types = openapi_schema_conjunction_types(conjunction, label)
    require(types is None or container_type in types, f"{label}: OpenAPI schema conjunction is incompatible with {container_type} traversal")
    return types == {container_type}


def openapi_conjunction_property(document: GitHubOpenApiDocument, conjunction: list[dict[str, Any]], segment: str, label: str) -> tuple[list[list[dict[str, Any]]], bool]:
    container_is_definitely_object = openapi_conjunction_container_compatible(conjunction, "object", label)
    property_schemas: list[Any] = []
    required = False
    for index, component in enumerate(conjunction):
        component_label = f"{label}.component[{index}]"
        required_set = openapi_schema_required_set(component, component_label)
        required = required or segment in required_set
        properties = component.get("properties", {})
        require(isinstance(properties, dict), f"{component_label}.properties: expected object")
        additional = component.get("additionalProperties", True)
        require(type(additional) is bool or isinstance(additional, dict), f"{component_label}.additionalProperties: expected boolean or schema")
        if segment in properties:
            property_schemas.append(properties[segment])
        elif additional is False:
            raise GateVerificationError(f"{label}: response pointer segment {segment!r} is forbidden by OpenAPI schema conjunction")
        elif isinstance(additional, dict):
            property_schemas.append(additional)
    require(property_schemas, f"{label}: response pointer segment {segment!r} is absent from OpenAPI schema alternative")
    alternatives: list[list[dict[str, Any]]] = [[]]
    for index, property_schema in enumerate(property_schemas):
        variants = openapi_schema_conjunctions(document, property_schema, f"{label}.property[{index}]")
        alternatives = [left + right for left in alternatives for right in variants]
    return alternatives, required and container_is_definitely_object


def openapi_conjunction_items(document: GitHubOpenApiDocument, conjunction: list[dict[str, Any]], label: str) -> list[list[dict[str, Any]]]:
    openapi_conjunction_container_compatible(conjunction, "array", label)
    item_schemas = [component["items"] for component in conjunction if "items" in component]
    require(item_schemas, f"{label}: EXACT_* response pointer selector cannot traverse an OpenAPI schema alternative without array items")
    alternatives: list[list[dict[str, Any]]] = [[]]
    for index, item_schema in enumerate(item_schemas):
        variants = openapi_schema_conjunctions(document, item_schema, f"{label}.items[{index}]")
        alternatives = [left + right for left in alternatives for right in variants]
    return alternatives


def openapi_response_pointer(document: GitHubOpenApiDocument, schema: Any, pointer: str, label: str) -> tuple[list[list[dict[str, Any]]], bool]:
    require(pointer.startswith("/") and pointer != "/", f"{label}: invalid response JSON pointer")
    raw_segments = pointer[1:].split("/")
    segments: list[str] = []
    for raw_segment in raw_segments:
        require(re.fullmatch(r"(?:[^~]|~[01])*", raw_segment) is not None, f"{label}: invalid response JSON pointer escape")
        segments.append(raw_segment.replace("~1", "/").replace("~0", "~"))
    alternatives = openapi_schema_conjunctions(document, schema, f"{label}.response")
    openapi_required = True
    for index, segment in enumerate(segments):
        next_alternatives: list[list[dict[str, Any]]] = []
        if segment.startswith("EXACT_"):
            openapi_required = False
            for alternative_index, conjunction in enumerate(alternatives):
                next_alternatives.extend(openapi_conjunction_items(document, conjunction, f"{label}.segment[{index}].alternative[{alternative_index}]"))
        else:
            for alternative_index, conjunction in enumerate(alternatives):
                property_alternatives, property_required = openapi_conjunction_property(document, conjunction, segment, f"{label}.segment[{index}].alternative[{alternative_index}]")
                next_alternatives.extend(property_alternatives)
                openapi_required = openapi_required and property_required
        require(next_alternatives, f"{label}: response pointer segment {segment!r} is absent from OpenAPI schema")
        alternatives = next_alternatives
    return alternatives, openapi_required


def github_runtime_binding_consumers(binding_name: str, operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_template = {"$binding": binding_name, "type": "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE"}
    return [operation for operation in operations if operation.get("request", {}).get("body", {}).get("template") == expected_template]


def audit_github_typed_bindings(document: GitHubOpenApiDocument, catalog: dict[str, Any], matched_operations: dict[str, tuple[dict[str, Any], dict[str, Any]]], label: str) -> dict[str, int]:
    contract = obj(catalog["providerContract"], f"{label}.providerContract")
    operations = arr(contract["restOperations"], f"{label}.restOperations")
    operation_by_id = {nonempty(operation.get("operationId"), f"{label}.restOperation.operationId"): operation for operation in operations}
    require(len(operation_by_id) == len(operations), f"{label}: duplicate REST operation while classifying typed bindings")
    non_rest_operations = arr(contract.get("nonRestOperations"), f"{label}.nonRestOperations")
    non_rest_ids = [nonempty(obj(operation, f"{label}.nonRestOperations").get("operationId"), f"{label}.nonRestOperation.operationId") for operation in non_rest_operations]
    require(len(non_rest_ids) == len(set(non_rest_ids)), f"{label}: duplicate non-REST operation while classifying typed bindings")
    require(not (set(operation_by_id) & set(non_rest_ids)), f"{label}: REST and non-REST operation IDs overlap")
    raw_capture = obj(contract.get("rawCapture"), f"{label}.rawCapture")
    request_fields = set(unique_strings(raw_capture.get("requestFields"), f"{label}.rawCapture.requestFields"))
    counts = {"typedBindingCount": 0, "responseSchemaBindingWitnessCount": 0, "responseBindingsNotGuaranteedPresentByOpenApi": 0, "runtimeFreshCaptureReconstructionBindingCount": 0, "requestEnvelopeBindingCount": 0, "nonRestBindingCount": 0}
    for index, raw_binding in enumerate(arr(contract["typedBindings"], f"{label}.typedBindings")):
        binding = obj(raw_binding, f"{label}.typedBindings[{index}]")
        binding_name = nonempty(binding.get("name"), f"{label}.typedBindings[{index}].name")
        binding_type = nonempty(binding.get("type"), f"{label}.{binding_name}.type")
        source_id = nonempty(binding.get("sourceOperation"), f"{label}.{binding_name}.sourceOperation")
        pointer = nonempty(binding.get("jsonPointer"), f"{label}.{binding_name}.jsonPointer")
        require(pointer.startswith("/"), f"{label}.{binding_name}: typed binding JSON pointer must be absolute")
        counts["typedBindingCount"] += 1
        if binding_type == "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE":
            require(source_id in operation_by_id, f"{label}.{binding_name}: fresh-capture reconstruction source is not a REST operation")
            require(pointer == "/reconstructedRestoreRequest", f"{label}.{binding_name}: fresh-capture reconstruction has unexpected JSON pointer")
            source = operation_by_id[source_id]
            require(source_id in matched_operations and source["request"].get("method") == "GET", f"{label}.{binding_name}: fresh-capture reconstruction source must be an audited GET")
            capture = obj(source["response"].get("capture"), f"{label}.{binding_name}.source.capture")
            require(capture.get("mode") == "RAW_BODY_AND_STRICT_PROJECTION" and capture.get("rawBodyRequired") is True, f"{label}.{binding_name}: fresh-capture reconstruction source must retain a nonsecret raw response")
            consumers = github_runtime_binding_consumers(binding_name, operations)
            require(len(consumers) == 1, f"{label}.{binding_name}: fresh-capture reconstruction binding requires exactly one restore consumer")
            consumer = consumers[0]
            restore = obj(consumer.get("preCaptureRestore"), f"{label}.{binding_name}.preCaptureRestore")
            exact_keys(restore, {"rawFreshCaptureBinding", "captureOperationId", "typedRequestBodyReconstruction", "requestRevalidatedAgainstPinnedOpenApi", "immediateReadbackOperationId", "exactProjectedReadbackAndDigestMustEqualFreshCapture", "historicalD0BaselineMaySubstitute"}, f"{label}.{binding_name}.preCaptureRestore")
            require(restore.get("rawFreshCaptureBinding") == binding_name and restore.get("captureOperationId") == source_id, f"{label}.{binding_name}: restore declaration does not match fresh-capture binding source")
            require(restore.get("typedRequestBodyReconstruction") == "ALLOWLIST_PROVIDER_FIELDS_FROM_RAW_FRESH_CAPTURE_ONLY", f"{label}.{binding_name}: restore reconstruction allowlist contract mismatch")
            require(restore.get("requestRevalidatedAgainstPinnedOpenApi") is True and restore.get("historicalD0BaselineMaySubstitute") is False, f"{label}.{binding_name}: runtime-only request body lacks exact fresh-capture revalidation contract")
            readback_id = nonempty(restore.get("immediateReadbackOperationId"), f"{label}.{binding_name}.immediateReadbackOperationId")
            follow_ups = arr(consumer["response"].get("requiredFollowUpReadbackOperationIds"), f"{label}.{binding_name}.requiredFollowUpReadbackOperationIds")
            require(readback_id in follow_ups and readback_id == source_id, f"{label}.{binding_name}: restore immediate readback does not match the declared capture readback")
            require(restore.get("exactProjectedReadbackAndDigestMustEqualFreshCapture") is True, f"{label}.{binding_name}: restore must exactly equal the fresh projected readback and digest")
            counts["runtimeFreshCaptureReconstructionBindingCount"] += 1
            continue
        require(binding_type in GITHUB_BINDING_REPRESENTATIVES, f"{label}.{binding_name}: typed binding type {binding_type!r} is outside the explicit OpenAPI-audit classification")
        if source_id in operation_by_id and pointer.startswith("/request/"):
            pointer_field = pointer.removeprefix("/request/")
            require(pointer_field and "/" not in pointer_field and pointer_field in request_fields, f"{label}.{binding_name}: request-envelope binding is absent from the closed raw-capture request fields")
            require(source_id in matched_operations, f"{label}.{binding_name}: request-envelope source operation was not audited")
            counts["requestEnvelopeBindingCount"] += 1
            continue
        if source_id in non_rest_ids:
            counts["nonRestBindingCount"] += 1
            continue
        require(source_id in operation_by_id, f"{label}.{binding_name}: typed binding source cannot be classified as REST response, request envelope, or non-REST")
        require(binding_type in GITHUB_OPENAPI_RESPONSE_BINDING_TYPES, f"{label}.{binding_name}: REST response binding type {binding_type!r} lacks an explicit OpenAPI schema witness policy")
        require(source_id in matched_operations, f"{label}.{binding_name}: response binding source operation was not audited")
        _, openapi_operation = matched_operations[source_id]
        contract_operation = operation_by_id[source_id]
        response_schemas: list[Any] = []
        presence_results: list[bool] = []
        responses = obj(openapi_operation.get("responses"), f"{label}.{source_id}.responses")
        for status in contract_operation["response"]["admittedStatuses"]:
            if status < 200 or status >= 300:
                continue
            response = obj(document.resolve(responses[str(status)], f"{label}.{source_id}.response[{status}]"), f"{label}.{source_id}.response[{status}]")
            content = obj(response.get("content", {}), f"{label}.{source_id}.response[{status}].content")
            if "application/json" not in content:
                presence_results.append(False)
                continue
            media = obj(content["application/json"], f"{label}.{source_id}.response[{status}].application/json")
            require("schema" in media, f"{label}.{source_id}: JSON response has no OpenAPI schema")
            response_schemas.append(media["schema"])
        require(response_schemas, f"{label}.{source_id}: typed response binding has no admitted JSON success schema")
        final_alternatives: list[list[dict[str, Any]]] = []
        for schema in response_schemas:
            finals, required_presence = openapi_response_pointer(document, schema, pointer, f"{label}.{binding_name}")
            final_alternatives.extend(finals)
            presence_results.append(required_presence)
        expected_type = {"BOOLEAN": "boolean", "GITHUB_LEGACY_BASE_PERMISSION": "string", "GITHUB_LOGIN": "string", "LOWERCASE_SHA1_40": "string", "POSITIVE_INT64": "integer"}[binding_type]
        representative = GITHUB_BINDING_REPRESENTATIVES[binding_type]
        for alternative_index, conjunction in enumerate(final_alternatives):
            types = openapi_schema_conjunction_types(conjunction, f"{label}.{binding_name}.final[{alternative_index}]")
            require(types is not None and expected_type in types and types <= {expected_type, "null"}, f"{label}.{binding_name}: response pointer type is incompatible with binding type {binding_type}")
            for component_index, component in enumerate(conjunction):
                errors = openapi_value_errors(document, representative, component, f"{label}.{binding_name}.witness[{alternative_index}].component[{component_index}]", "response")
                require(not errors, f"{label}.{binding_name}: representative response-schema witness is incompatible:{errors[0] if errors else ''}")
        counts["responseSchemaBindingWitnessCount"] += 1
        if not all(presence_results):
            counts["responseBindingsNotGuaranteedPresentByOpenApi"] += 1
    require(counts["typedBindingCount"] == sum(counts[key] for key in ("responseSchemaBindingWitnessCount", "runtimeFreshCaptureReconstructionBindingCount", "requestEnvelopeBindingCount", "nonRestBindingCount")), f"{label}: typed-binding audit classification is not exhaustive")
    return counts


def audit_github_openapi_contracts(document_value: dict[str, Any], catalogs: list[dict[str, Any]], required_pinned_claims: dict[str, frozenset[str]] | None = None) -> dict[str, Any]:
    document = GitHubOpenApiDocument(document_value)
    require(catalogs, "GitHub OpenAPI audit requires at least one catalog")
    if required_pinned_claims is not None:
        require(isinstance(required_pinned_claims, dict), "GitHub OpenAPI required pinned claims must be a catalog map")
        for catalog_id, operation_ids in required_pinned_claims.items():
            require(isinstance(catalog_id, str) and catalog_id, "GitHub OpenAPI required pinned-claim catalog IDs must be nonempty strings")
            require(isinstance(operation_ids, frozenset) and all(isinstance(operation_id, str) and operation_id for operation_id in operation_ids), f"GitHub OpenAPI required pinned claims for {catalog_id!r} must be a frozenset of nonempty operation IDs")
    results: list[dict[str, Any]] = []
    catalog_ids: set[str] = set()
    for catalog_index, catalog in enumerate(catalogs):
        catalog = obj(catalog, f"catalog[{catalog_index}]")
        catalog_id = nonempty(catalog.get("catalogId"), f"catalog[{catalog_index}].catalogId")
        require(catalog_id not in catalog_ids, f"duplicate GitHub OpenAPI audit catalog {catalog_id!r}")
        if required_pinned_claims is not None:
            require(catalog_id in required_pinned_claims, "GitHub OpenAPI required pinned-claim catalog set mismatch")
        catalog_ids.add(catalog_id)
        label = f"GitHub OpenAPI audit {catalog_id}"
        contract = obj(catalog.get("providerContract"), f"{label}.providerContract")
        bindings = github_binding_registry(catalog, label)
        operations = arr(contract.get("restOperations"), f"{label}.restOperations")
        matched_operations: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        request_bodies = 0
        runtime_only_bodies = 0
        parameters = 0
        pinned_claim_operation_ids: set[str] = set()
        for operation_index, contract_operation_raw in enumerate(operations):
            contract_operation = obj(contract_operation_raw, f"{label}.restOperations[{operation_index}]")
            operation_id = nonempty(contract_operation.get("operationId"), f"{label}.restOperations[{operation_index}].operationId")
            require(operation_id not in matched_operations, f"{label}: duplicate REST operation {operation_id!r}")
            request = obj(contract_operation.get("request"), f"{label}.{operation_id}.request")
            method = nonempty(request.get("method"), f"{label}.{operation_id}.method").lower()
            contract_path = nonempty(request.get("pathTemplate"), f"{label}.{operation_id}.pathTemplate")
            openapi_path, openapi_operation, captured_path_parameters = document.operation(contract_path, method, f"{label}.{operation_id}")
            path_item = obj(document.resolve(document.paths[openapi_path], f"{label}.{operation_id}.pathItem"), f"{label}.{operation_id}.pathItem")
            matched_operations[operation_id] = (path_item, openapi_operation)
            parameters += audit_github_openapi_parameters(document, openapi_path, path_item, openapi_operation, captured_path_parameters, contract_operation, bindings, f"{label}.{operation_id}")
            responses = obj(openapi_operation.get("responses"), f"{label}.{operation_id}.responses")
            contract_response = obj(contract_operation.get("response"), f"{label}.{operation_id}.response")
            admitted_statuses = arr(contract_response.get("admittedStatuses"), f"{label}.{operation_id}.admittedStatuses")
            require(admitted_statuses and all(type(status) is int and 100 <= status <= 599 for status in admitted_statuses) and len(admitted_statuses) == len(set(admitted_statuses)), f"{label}.{operation_id}: admitted statuses must be a unique integer array of HTTP statuses and nonempty")
            for status in admitted_statuses:
                require(str(status) in responses, f"{label}.{operation_id}: admitted status {status!r} is undeclared by OpenAPI")
            body = obj(request.get("body"), f"{label}.{operation_id}.body")
            request_body = obj(document.resolve(openapi_operation["requestBody"], f"{label}.{operation_id}.requestBody"), f"{label}.{operation_id}.requestBody") if "requestBody" in openapi_operation else None
            if request_body is not None and "required" in request_body:
                require(type(request_body["required"]) is bool, f"{label}.{operation_id}.requestBody.required: expected boolean")
            if body.get("kind") == "NONE":
                if request_body is not None:
                    require(request_body.get("required") is not True, f"{label}.{operation_id}: contract omits required OpenAPI request body")
            else:
                require(body.get("kind") == "CANONICAL_JSON_BINDING_TEMPLATE" and "template" in body, f"{label}.{operation_id}: unsupported contract request body kind")
                require(request_body is not None, f"{label}.{operation_id}: contract sends a request body absent from OpenAPI")
                content = obj(request_body.get("content"), f"{label}.{operation_id}.requestBody.content")
                media = obj(content.get("application/json"), f"{label}.{operation_id}.requestBody.application/json")
                require("schema" in media, f"{label}.{operation_id}: request body has no OpenAPI schema")
                template = body["template"]
                if isinstance(template, dict) and set(template) == {"$binding", "type"} and template.get("type") == "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE":
                    binding_name = nonempty(template["$binding"], f"{label}.{operation_id}.runtimeBodyBinding")
                    require(binding_name in bindings and bindings[binding_name].get("type") == "OPENAPI_REQUEST_BODY_FROM_FRESH_CAPTURE", f"{label}.{operation_id}: runtime-only request body binding mismatch")
                    restore = obj(contract_operation.get("preCaptureRestore"), f"{label}.{operation_id}.preCaptureRestore")
                    require(restore.get("rawFreshCaptureBinding") == binding_name and restore.get("requestRevalidatedAgainstPinnedOpenApi") is True and restore.get("historicalD0BaselineMaySubstitute") is False, f"{label}.{operation_id}: runtime-only request body lacks exact fresh-capture revalidation contract")
                    runtime_only_bodies += 1
                else:
                    concrete_body = substitute_github_body_bindings(template, bindings, f"{label}.{operation_id}.bodyTemplate")
                    validate_openapi_schema_subset(document, concrete_body, media["schema"], f"{label}.{operation_id}.bodyTemplate", "request")
                    request_bodies += 1
            if "pinnedOpenApiSemantics" in contract_operation:
                claim = obj(contract_operation["pinnedOpenApiSemantics"], f"{label}.{operation_id}.pinnedOpenApiSemantics")
                require(claim.get("operationId") == openapi_operation.get("operationId"), f"{label}.{operation_id}: pinned OpenAPI operationId claim mismatch")
                require(claim.get("summary") == openapi_operation.get("summary"), f"{label}.{operation_id}: pinned OpenAPI summary claim mismatch")
                github_extension = obj(openapi_operation.get("x-github"), f"{label}.{operation_id}.x-github")
                require(type(github_extension.get("enabledForGitHubApps")) is bool and claim.get("githubAppsEnabled") == github_extension["enabledForGitHubApps"], f"{label}.{operation_id}: pinned enabledForGitHubApps claim mismatch")
                admitted_claim = claim.get("admittedStatus")
                require(type(admitted_claim) is int and admitted_claim in admitted_statuses, f"{label}.{operation_id}: pinned admitted-status claim mismatch")
                pinned_claim_operation_ids.add(operation_id)
        if required_pinned_claims is not None:
            require(pinned_claim_operation_ids == required_pinned_claims[catalog_id], f"{label}: pinned OpenAPI semantic claim operation set mismatch;expected={sorted(required_pinned_claims[catalog_id])!r};observed={sorted(pinned_claim_operation_ids)!r}")
        binding_counts = audit_github_typed_bindings(document, catalog, matched_operations, label)
        require(runtime_only_bodies == binding_counts["runtimeFreshCaptureReconstructionBindingCount"], f"{label}: runtime fresh-capture binding and request-body consumer counts differ")
        results.append({"catalogId": catalog_id, "operationCount": len(operations), "parameterSchemaWitnessCount": parameters, "pinnedClaimCount": len(pinned_claim_operation_ids), "concreteRequestBodySchemaWitnessCount": request_bodies, **binding_counts})
    if required_pinned_claims is not None:
        require(set(required_pinned_claims) == catalog_ids, "GitHub OpenAPI required pinned-claim catalog set mismatch")
    total_keys = ("operationCount", "parameterSchemaWitnessCount", "pinnedClaimCount", "concreteRequestBodySchemaWitnessCount", "typedBindingCount", "responseSchemaBindingWitnessCount", "responseBindingsNotGuaranteedPresentByOpenApi", "runtimeFreshCaptureReconstructionBindingCount", "requestEnvelopeBindingCount", "nonRestBindingCount")
    totals = {key: sum(result[key] for result in results) for key in total_keys}
    return {"schema": GITHUB_OPENAPI_AUDIT_SCHEMA, "scope": GITHUB_OPENAPI_AUDIT_SCOPE, "catalogs": results, "totals": totals, "result": "PASS"}


def expected_github_openapi_audit_catalogs() -> list[dict[str, Any]]:
    bases = {repository.id: repository.reviewed_commit for repository in PRODUCTION_REPOSITORIES}
    catalogs: list[dict[str, Any]] = []
    for catalog_id, repository, reviewer, dispatcher in (("rust", "pkgre/rust", "rust-reviewer", "rust-dispatcher"), ("js", "pkgre/js", "js-reviewer", "js-dispatcher")):
        digests = [sha256(f"github-openapi-audit-{catalog_id}-{kind}-v1".encode()) for kind in ("candidate", "release", "pages", "codeowners")]
        catalogs.append(expected_github_catalog(catalog_id, repository, GITHUB_REPOSITORY_IDS[repository], f"https://github.com/{repository}.git", bases[repository], reviewer, dispatcher, *digests))
    return catalogs


def audit_pinned_github_openapi(path: Path) -> dict[str, Any]:
    raw, document = load_pinned_github_openapi(path)
    require(document.get("openapi") == "3.0.3", "pinned GitHub OpenAPI version mismatch")
    info = obj(document.get("info"), "pinned GitHub OpenAPI info")
    require(info.get("title") == "GitHub v3 REST API" and info.get("version") == GITHUB_REST_OPENAPI_VERSION, "pinned GitHub OpenAPI identity mismatch")
    result = audit_github_openapi_contracts(document, expected_github_openapi_audit_catalogs(), GITHUB_OPENAPI_REQUIRED_PINNED_CLAIMS)
    result["document"] = {"repository": "github/rest-api-description", "commit": GITHUB_REST_OPENAPI_COMMIT, "path": GITHUB_REST_OPENAPI_DOCUMENT, "sha256": sha256(raw), "size": len(raw), "openapi": document["openapi"], "title": info["title"], "version": info["version"]}
    return result


def validate_b03_payloads(results: list[dict[str, Any]], verification_time: datetime) -> None:
    require(len(results) == 1, "D0-B03: exact single-handoff contribution required")
    result = results[0]
    operator, returned_at = operator_return_context(result, "D0-B03")
    payload = result["_semanticPayloads"]["github-governance-proof"]
    label = "D0-B03 github-governance-proof"
    exact_keys(payload, {"designId", "operatorDecision", "baseline", "catalogs", "crossCatalogSeparation", "d0Mutation", "result"}, label)
    decision = obj(payload["operatorDecision"], f"{label}.operatorDecision")
    exact_keys(decision, {"returnedBy", "returnedAt", "scope"}, f"{label}.operatorDecision")
    require(security_text(decision["returnedBy"], f"{label}.operatorDecision.returnedBy", 128) == operator, f"{label}: operator identity mismatch")
    decision_time = parse_utc(decision["returnedAt"], f"{label}.operatorDecision.returnedAt")
    require(decision_time == returned_at, f"{label}: operator return time mismatch")
    require_no_later(decision_time, verification_time + timedelta(seconds=D0_EVIDENCE_FUTURE_SKEW_SECONDS), f"{label}.operatorDecision")
    catalogs = arr(payload["catalogs"], f"{label}.catalogs")
    require(len(catalogs) == 2, f"{label}: exact Rust and JS catalog designs required")
    specifications = [
        ("rust", "pkgre/rust", "https://github.com/pkgre/rust.git"),
        ("js", "pkgre/js", "https://github.com/pkgre/js.git"),
    ]
    source_tips = {row.id: row.reviewed_commit for row in PRODUCTION_REPOSITORIES}
    expected_catalogs: list[dict[str, Any]] = []
    identities: list[tuple[str, str]] = []
    content_digests: list[tuple[str, str]] = []
    evidence_keys: list[tuple[str, str]] = []
    projection_digests: list[tuple[str, str]] = []
    catalog_keys = {"catalogId", "designId", "repository", "repositoryId", "sourceAuthority", "sourceTipAtD0Baseline", "sourceTreeOidAtD0Baseline", "preD2MutationCapture", "candidateCI", "releaseWorkflow", "pagesWorkflow", "trustedSurface", "environment", "writer", "rulesets", "providerAuthorityBoundary", "classicBranchProtectionTransition", "codeowners", "actions", "providerAssignedEvidence", "providerContract", "rollback"}
    for index, (catalog_id, repository, runtime_origin) in enumerate(specifications):
        row_label = f"{label}.catalogs[{index}]"
        catalog = obj(catalogs[index], row_label)
        exact_keys(catalog, catalog_keys, row_label)
        candidate = obj(catalog["candidateCI"], f"{row_label}.candidateCI")
        exact_keys(candidate, {"path", "name", "purpose", "proposedContentSha256", "targetCommitBinding", "trigger", "check", "permissions", "checkout", "validationScope", "execution", "untrustedPullRequests"}, f"{row_label}.candidateCI")
        release = obj(catalog["releaseWorkflow"], f"{row_label}.releaseWorkflow")
        exact_keys(release, {"path", "name", "purpose", "proposedContentSha256", "targetCommitBinding", "triggers", "dispatchers", "jobs", "releaseAuthorityConsumers", "protectedGovernancePaths", "signingAuthorityDesignId"}, f"{row_label}.releaseWorkflow")
        pages = obj(catalog["pagesWorkflow"], f"{row_label}.pagesWorkflow")
        exact_keys(pages, {"path", "name", "purpose", "baseline", "proposedContentSha256", "targetCommitBinding", "triggers", "jobs", "releaseAuthorityAccess", "pullRequestCandidateExecutionRemoved", "rollbackContinuityRetained"}, f"{row_label}.pagesWorkflow")
        dispatchers = arr(release["dispatchers"], f"{row_label}.releaseWorkflow.dispatchers")
        require(len(dispatchers) == 1, f"{row_label}: exact single dispatcher required")
        dispatcher_row = obj(dispatchers[0], f"{row_label}.releaseWorkflow.dispatchers[0]")
        exact_keys(dispatcher_row, {"type", "login"}, f"{row_label}.releaseWorkflow.dispatchers[0]")
        dispatcher = github_login(dispatcher_row["login"], f"{row_label}.releaseWorkflow.dispatchers[0].login")
        environment = obj(catalog["environment"], f"{row_label}.environment")
        exact_keys(environment, {"name", "reviewers", "requiredReviewerApprovals", "preventSelfReview", "providerCreateOrUpdateRequestBody", "providerBranchPolicyCreateRequestBody", "expectedRestReadbackProjection", "proceduralReadback", "secretsAvailableOnlyAfterApproval"}, f"{row_label}.environment")
        reviewers = arr(environment["reviewers"], f"{row_label}.environment.reviewers")
        require(len(reviewers) == 1, f"{row_label}: exact single environment reviewer required")
        reviewer_row = obj(reviewers[0], f"{row_label}.environment.reviewers[0]")
        exact_keys(reviewer_row, {"type", "login", "providerIdBinding"}, f"{row_label}.environment.reviewers[0]")
        reviewer = github_login(reviewer_row["login"], f"{row_label}.environment.reviewers[0].login")
        writer = obj(catalog["writer"], f"{row_label}.writer")
        writer_slug = security_identifier(writer.get("slug"), f"{row_label}.writer.slug")
        codeowners = obj(catalog["codeowners"], f"{row_label}.codeowners")
        exact_keys(codeowners, {"path", "proposedContentSha256", "sourceBranch", "entries", "ownersHaveWriteAccess", "writerAppIsOwner"}, f"{row_label}.codeowners")
        candidate_digest = hex_digest(candidate["proposedContentSha256"], f"{row_label}.candidateCI.proposedContentSha256")
        release_digest = hex_digest(release["proposedContentSha256"], f"{row_label}.releaseWorkflow.proposedContentSha256")
        pages_digest = hex_digest(pages["proposedContentSha256"], f"{row_label}.pagesWorkflow.proposedContentSha256")
        codeowners_digest = hex_digest(codeowners["proposedContentSha256"], f"{row_label}.codeowners.proposedContentSha256")
        identities.extend([(reviewer, f"{row_label}.environment reviewer"), (dispatcher, f"{row_label}.release dispatcher"), (writer_slug, f"{row_label}.writer app")])
        content_digests.extend([(candidate_digest, f"{row_label}.candidateCI content"), (release_digest, f"{row_label}.releaseWorkflow content"), (pages_digest, f"{row_label}.pagesWorkflow content"), (codeowners_digest, f"{row_label}.codeowners content")])
        provider_evidence = arr(catalog["providerAssignedEvidence"], f"{row_label}.providerAssignedEvidence")
        require(len(provider_evidence) == len(GITHUB_PROVIDER_EVIDENCE_KINDS), f"{row_label}: exact provider-evidence coverage required")
        observed_kinds: list[str] = []
        for evidence_index, raw_evidence in enumerate(provider_evidence):
            evidence_label = f"{row_label}.providerAssignedEvidence[{evidence_index}]"
            evidence = obj(raw_evidence, evidence_label)
            exact_keys(evidence, {"evidenceKey", "kind", "catalogId", "designId", "repository", "repositoryId", "resourceSelector", "projectionSchema", "projectionDomain", "expectedProjectionSha256", "requiredReturnedBindings", "allUnlistedReturnedFields", "providerAssignedIdStatus", "readbackRequiredAt"}, evidence_label)
            kind = nonempty(evidence["kind"], f"{evidence_label}.kind")
            observed_kinds.append(kind)
            evidence_key = security_identifier(evidence["evidenceKey"], f"{evidence_label}.evidenceKey")
            evidence_keys.append((evidence_key, f"{evidence_label}.evidenceKey"))
            selector = obj(evidence["resourceSelector"], f"{evidence_label}.resourceSelector")
            require(selector.get("repositoryId") == GITHUB_REPOSITORY_IDS[repository], f"{evidence_label}: resource selector must bind the exact repository ID")
            projection_digest = hex_digest(evidence["expectedProjectionSha256"], f"{evidence_label}.expectedProjectionSha256")
            projection_digests.append((projection_digest, f"{evidence_label}.expectedProjectionSha256"))
            returned_bindings = arr(evidence["requiredReturnedBindings"], f"{evidence_label}.requiredReturnedBindings")
            require(len(returned_bindings) == len(set(returned_bindings)), f"{evidence_label}: required returned bindings must be unique")
        require(observed_kinds == GITHUB_PROVIDER_EVIDENCE_KINDS, f"{row_label}: provider-evidence kinds are missing,duplicated,or out of canonical order")
        expected_catalogs.append(expected_github_catalog(catalog_id, repository, GITHUB_REPOSITORY_IDS[repository], runtime_origin, source_tips[repository], reviewer, dispatcher, candidate_digest, release_digest, pages_digest, codeowners_digest))
    require_globally_distinct_identifiers(identities, "D0-B03 reviewer,dispatcher,and writer identities")
    require(len({digest for digest, _ in content_digests}) == len(content_digests), "D0-B03 workflow and CODEOWNERS content digests must be globally distinct")
    require_globally_distinct_identifiers(evidence_keys, "D0-B03 provider evidence keys")
    require(len({digest for digest, _ in projection_digests}) == len(projection_digests), "D0-B03 provider projection digests must be globally distinct")
    expected = {
        "designId": "pkgre-public-catalog-github-governance-v1",
        "operatorDecision": {"returnedBy": operator, "returnedAt": result["_operatorReturnedAt"], "scope": "D2_GITHUB_TARGET_DESIGN_NO_SETTINGS_ACTION"},
        "baseline": {
            "path": GITHUB_GOVERNANCE_BASELINE_PATH,
            "sha256": GITHUB_GOVERNANCE_BASELINE_SHA256,
            "catalogConformance": [{"catalogId": "rust", "targetConforming": False}, {"catalogId": "js", "targetConforming": False}],
            "auditLogAvailable": False,
        },
        "catalogs": expected_catalogs,
        "crossCatalogSeparation": {"workflowPathsDistinct": True, "workflowNamesDistinct": True, "checkContextsDistinct": True, "environmentsDistinct": True, "writerAppsDistinct": True, "rulesetNamesDistinct": True, "providerEvidenceKeysDistinct": True, "writerTokensRepositoryScoped": True},
        "d0Mutation": {"githubSettingsChanged": False, "writerCredentialInstalled": False, "signerInstalled": False, "catalogRefAdvanced": False},
        "result": "APPROVED_TARGET_DESIGN",
    }
    exact_json_value(payload, expected, label)


def validate_phase_amendment_payloads(finding_id: str, results: list[dict[str, Any]], verification_time: datetime) -> None:
    expected_targets = REPHASE_TARGETS[finding_id]
    amendment_ids: list[tuple[str, str]] = []
    for result in results:
        handoff_id = result["_handoffId"]
        label = f"{finding_id}/{handoff_id} phase-amendment"
        payload = result["_semanticPayloads"]["phase-amendment"]
        exact_keys(payload, {"amendmentId", "decision", "findingId", "currentEvidenceSatisfied", "d0WorkAuthorized", "targetGates", "deferredRequirements", "operatorDecision", "rationale", "residualRisks", "result"}, label)
        amendment_id = security_identifier(payload["amendmentId"], f"{label}.amendmentId")
        amendment_ids.append((amendment_id, f"{label}.amendmentId"))
        require(payload["decision"] == "APPROVE_EXACT_REPHASE" and payload["result"] == "APPROVED", f"{label}: exact rephase approval decision/result mismatch")
        require(payload["findingId"] == finding_id, f"{label}: finding binding mismatch")
        require(strict_bool(payload["currentEvidenceSatisfied"], f"{label}.currentEvidenceSatisfied") is False, f"{label}: current evidence must remain unsatisfied")
        require(strict_bool(payload["d0WorkAuthorized"], f"{label}.d0WorkAuthorized") is False, f"{label}: phase amendment must not authorize D0 work")
        require(payload["targetGates"] == expected_targets, f"{label}: target-gate list mismatch")
        deferred = arr(payload["deferredRequirements"], f"{label}.deferredRequirements")
        require(len(deferred) == len(expected_targets), f"{label}: deferred-requirement coverage mismatch")
        for index, gate_id in enumerate(expected_targets):
            row_label = f"{label}.deferredRequirements[{index}]"
            row = obj(deferred[index], row_label)
            exact_keys(row, {"gateId", "requirement"}, row_label)
            require(row["gateId"] == gate_id and row["requirement"] == LATER_GATES_BY_ID[gate_id]["requirement"], f"{row_label}: must bind the exact later-gate requirement")
        operator, returned_at = operator_return_context(result, finding_id)
        decision = obj(payload["operatorDecision"], f"{label}.operatorDecision")
        exact_keys(decision, {"returnedBy", "returnedAt"}, f"{label}.operatorDecision")
        require(security_text(decision["returnedBy"], f"{label}.operatorDecision.returnedBy", 128) == operator, f"{label}: operator identity mismatch")
        decision_time = parse_utc(decision["returnedAt"], f"{label}.operatorDecision.returnedAt")
        require(decision_time == returned_at, f"{label}: operator return time mismatch")
        require_no_later(decision_time, verification_time + timedelta(seconds=D0_EVIDENCE_FUTURE_SKEW_SECONDS), f"{label}.operatorDecision")
        security_text(payload["rationale"], f"{label}.rationale", 1024)
        risks = arr(payload["residualRisks"], f"{label}.residualRisks")
        require(1 <= len(risks) <= 32, f"{label}.residualRisks: expected at least 1 entries and at most 32")
        normalized_risks = [security_text(risk, f"{label}.residualRisks[{index}]", 512) for index, risk in enumerate(risks)]
        require(len({risk.casefold() for risk in normalized_risks}) == len(normalized_risks), f"{label}.residualRisks: duplicate risk")
    require_globally_distinct_identifiers(amendment_ids, f"{finding_id} phase-amendment IDs")


def validate_generic_payloads(finding_id: str, disposition: str, results: list[dict[str, Any]], verification_time: datetime) -> None:
    if disposition == "REPHASED":
        validate_phase_amendment_payloads(finding_id, results, verification_time)
    elif disposition == "SATISFIED" and finding_id == "D0-B01":
        validate_b01_payloads(results, verification_time)
    elif disposition == "SATISFIED" and finding_id == "D0-B02":
        validate_b02_payloads(results, verification_time)
    elif disposition == "SATISFIED" and finding_id == "D0-B03":
        validate_b03_payloads(results, verification_time)
    elif disposition == "SATISFIED" and finding_id == "D0-B05":
        raise GateVerificationError("D0-B05: authenticated deployment-ledger and independent live-observer authorities are not installed")
    else:
        raise GateVerificationError(f"{finding_id}: strict semantic payload validation is not installed")


def validate_generic_policy(finding_id: str, disposition: str, mode: str, results: list[dict[str, Any]], verification_time: datetime) -> None:
    require(finding_id in SAT_EVIDENCE, f"{finding_id}: no generic terminal policy")
    if disposition == "SATISFIED":
        require(mode == "EVIDENCE_SATISFIED", f"{finding_id}: wrong satisfaction mode")
    elif disposition == "REPHASED":
        require(finding_id in REPHASE_TARGETS and mode == "EXACT_PHASE_AMENDMENT", f"{finding_id}: rephasing is not allowed by policy")
    else:
        raise GateVerificationError(f"{finding_id}: disposition {disposition!r} is forbidden")
    for result in results:
        validate_semantic_documents(finding_id, disposition, result)
    observed_handoffs = [result["_handoffId"] for result in results]
    require(observed_handoffs == FINDING_HANDOFFS[finding_id], f"{finding_id}: semantic contributions are not in canonical handoff order")
    if disposition == "SATISFIED":
        all_kinds = set().union(*(set(result["_semanticPayloads"]) for result in results))
        require(all_kinds == SAT_EVIDENCE[finding_id], f"{finding_id}: satisfaction evidence coverage mismatch")
    validate_generic_payloads(finding_id, disposition, results, verification_time)


def validate_b18(disposition: str, mode: str, results: list[dict[str, Any]]) -> None:
    require(disposition == "ACKNOWLEDGED_CONTAINED" and mode == "ACKNOWLEDGED_CONTAINED", "D0-B18: historical incident may only close as ACKNOWLEDGED_CONTAINED")
    required = {"historical-incident", "incident-acknowledgment", "containment", "remediation", "policy-disposition"}
    all_kinds = set().union(*(set(result["_evidenceByKind"]) for result in results))
    require(required <= all_kinds, "D0-B18: historical incident,acknowledgment,containment,remediation,and policy evidence are mandatory")
    for result in results:
        claims = obj(result["claims"], "D0-B18 claims")
        exact_keys(claims, {"historicalFactAcknowledged", "contact", "historicalIncidentRefId", "acknowledgmentRefIds", "containmentRefIds", "remediationRefIds", "policyDispositionRefIds"}, "D0-B18 claims")
        require(claims["historicalFactAcknowledged"] is True and claims["contact"] == B18_CONTACT, "D0-B18: exact historical contact was not acknowledged")
        incident_ids = evidence_ids(result, "historical-incident")
        require(len(incident_ids) == 1 and claims["historicalIncidentRefId"] == incident_ids[0], "D0-B18: historical incident reference mismatch")
        incident = result["_references"][incident_ids[0]]
        require(incident["sha256"] == B18_INCIDENT_SHA256 and sha256(incident["raw"]) == B18_INCIDENT_SHA256, "D0-B18: historical raw incident digest mismatch")
        require_claim_ref_ids(result, claims["acknowledgmentRefIds"], "incident-acknowledgment", "D0-B18 acknowledgment")
        require_claim_ref_ids(result, claims["containmentRefIds"], "containment", "D0-B18 containment")
        require_claim_ref_ids(result, claims["remediationRefIds"], "remediation", "D0-B18 remediation")
        require_claim_ref_ids(result, claims["policyDispositionRefIds"], "policy-disposition", "D0-B18 policy disposition")


def validate_b19(disposition: str, mode: str, results: list[dict[str, Any]]) -> None:
    require(disposition == "DEFERRED_REVIEWED" and mode == "NO_LAN_SELECTED", "D0-B19: wrong reviewed deferral mode")
    for result in results:
        claims = obj(result["claims"], "D0-B19 claims")
        exact_keys(claims, {"lanSelected", "allLanMutationsUnauthorized", "reentryGate", "confirmationRefIds", "reentryContractRefIds"}, "D0-B19 claims")
        require(claims["lanSelected"] is False and claims["allLanMutationsUnauthorized"] is True and claims["reentryGate"] == "D13_LAN_SELECTION", "D0-B19: no-LAN contract mismatch")
        require_claim_ref_ids(result, claims["confirmationRefIds"], "no-lan-confirmation", "D0-B19 confirmation")
        require_claim_ref_ids(result, claims["reentryContractRefIds"], "d13-reentry-contract", "D0-B19 reentry")


def decode_bounded_base64(value: Any, label: str, max_decoded: int = 1024 * 1024) -> bytes:
    text = nonempty(value, label)
    require(len(text) <= ((max_decoded + 2) // 3) * 4, f"{label}: base64 text is too large")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise GateVerificationError(f"{label}: invalid base64: {error}") from error
    require(len(raw) <= max_decoded, f"{label}: decoded content exceeds {max_decoded} bytes")
    require(base64.b64encode(raw).decode("ascii") == text, f"{label}: base64 is not canonical")
    return raw


@dataclass(frozen=True)
class ATermConstructor:
    name: str
    arguments: tuple[Any, ...]


class ATermParser:
    def __init__(self, raw: bytes, label: str) -> None:
        require(len(raw) <= MAX_DRV_BYTES, f"{label}: derivation exceeds {MAX_DRV_BYTES} bytes")
        self.raw = raw
        self.label = label
        self.offset = 0
        self.items = 0
        self.string_bytes = 0

    def fail(self, message: str) -> None:
        raise GateVerificationError(f"{self.label}: ATerm byte {self.offset}: {message}")

    def consume_item(self, depth: int) -> None:
        if depth > MAX_DRV_DEPTH:
            self.fail(f"nesting exceeds {MAX_DRV_DEPTH}")
        self.items += 1
        if self.items > MAX_DRV_ITEMS:
            self.fail(f"item count exceeds {MAX_DRV_ITEMS}")

    def parse(self) -> ATermConstructor:
        require(self.raw, f"{self.label}: empty derivation")
        value = self.value(0)
        require(self.offset == len(self.raw), f"{self.label}: trailing ATerm bytes at offset {self.offset}")
        require(isinstance(value, ATermConstructor), f"{self.label}: top-level ATerm value must be a constructor")
        return value

    def value(self, depth: int) -> Any:
        self.consume_item(depth)
        if self.offset >= len(self.raw):
            self.fail("unexpected end of input")
        byte = self.raw[self.offset]
        if byte == ord('"'):
            return self.string()
        if byte == ord('['):
            return self.sequence(ord('['), ord(']'), depth)
        if byte == ord('('):
            return tuple(self.sequence(ord('('), ord(')'), depth))
        if 65 <= byte <= 90 or 97 <= byte <= 122:
            return self.constructor(depth)
        self.fail(f"unexpected byte 0x{byte:02x}")

    def constructor(self, depth: int) -> ATermConstructor:
        start = self.offset
        while self.offset < len(self.raw) and (self.raw[self.offset:self.offset + 1].isalnum() or self.raw[self.offset] in b"_-"):
            self.offset += 1
        try:
            name = self.raw[start:self.offset].decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{self.label}: non-ASCII ATerm constructor") from error
        require(name != "", f"{self.label}: empty ATerm constructor")
        arguments = tuple(self.sequence(ord('('), ord(')'), depth))
        return ATermConstructor(name, arguments)

    def sequence(self, opener: int, closer: int, depth: int) -> list[Any]:
        if self.offset >= len(self.raw) or self.raw[self.offset] != opener:
            self.fail(f"expected {chr(opener)!r}")
        self.offset += 1
        result: list[Any] = []
        if self.offset < len(self.raw) and self.raw[self.offset] == closer:
            self.offset += 1
            return result
        while True:
            result.append(self.value(depth + 1))
            if self.offset >= len(self.raw):
                self.fail(f"unterminated {chr(opener)!r}")
            delimiter = self.raw[self.offset]
            self.offset += 1
            if delimiter == closer:
                return result
            if delimiter != ord(','):
                self.fail(f"expected ',' or {chr(closer)!r}")

    def string(self) -> str:
        self.offset += 1
        decoded = bytearray()
        escapes = {ord('"'): ord('"'), ord('\\'): ord('\\'), ord('n'): 10, ord('r'): 13, ord('t'): 9}
        while self.offset < len(self.raw):
            byte = self.raw[self.offset]
            self.offset += 1
            if byte == ord('"'):
                self.string_bytes += len(decoded)
                if self.string_bytes > MAX_DRV_STRING_BYTES:
                    self.fail(f"decoded string bytes exceed {MAX_DRV_STRING_BYTES}")
                try:
                    return decoded.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    raise GateVerificationError(f"{self.label}: ATerm string is not valid UTF-8: {error}") from error
            if byte == ord('\\'):
                if self.offset >= len(self.raw):
                    self.fail("trailing string escape")
                escaped = self.raw[self.offset]
                self.offset += 1
                if escaped in escapes:
                    decoded.append(escapes[escaped])
                else:
                    self.fail(f"unsupported string escape 0x{escaped:02x}")
            else:
                if byte < 0x20 or byte == 0x7F:
                    self.fail(f"noncanonical literal control byte 0x{byte:02x}")
                decoded.append(byte)
        self.fail("unterminated string")


def parse_derivation(raw: bytes, label: str) -> dict[str, Any]:
    term = ATermParser(raw, label).parse()
    require(term.name == "Derive" and len(term.arguments) == 7, f"{label}: expected exact Derive/7 constructor")
    outputs_raw, inputs_raw, sources_raw, platform, builder, arguments_raw, environment_raw = term.arguments
    require(isinstance(outputs_raw, list) and isinstance(inputs_raw, list) and isinstance(sources_raw, list) and isinstance(arguments_raw, list) and isinstance(environment_raw, list), f"{label}: malformed Derive collection fields")
    require(all(isinstance(value, str) for value in (platform, builder)), f"{label}: malformed Derive platform/builder")
    require(all(isinstance(value, str) for value in sources_raw) and all(isinstance(value, str) for value in arguments_raw), f"{label}: malformed Derive source/argument rows")
    outputs: dict[str, dict[str, str]] = {}
    for index, row in enumerate(outputs_raw):
        require(isinstance(row, tuple) and len(row) == 4 and all(isinstance(value, str) for value in row), f"{label}: malformed output tuple {index}")
        name, path, algorithm, digest = row
        require(name != "" and name not in outputs, f"{label}: empty or duplicate output name {name!r}")
        require(NIX_STORE_PATH_RE.fullmatch(path) is not None, f"{label}: invalid output store path for {name!r}")
        require((algorithm == "" and digest == "") or (algorithm in {"sha256", "r:sha256"} and HEX64_RE.fullmatch(digest) is not None), f"{label}: invalid output hash tuple for {name!r}")
        outputs[name] = {"path": path, "hashAlgorithm": algorithm, "hash": digest}
    require(outputs and list(outputs) == sorted(outputs), f"{label}: outputs are empty or not in canonical order")
    inputs: dict[str, list[str]] = {}
    for index, row in enumerate(inputs_raw):
        require(isinstance(row, tuple) and len(row) == 2 and isinstance(row[0], str) and isinstance(row[1], list) and all(isinstance(value, str) for value in row[1]), f"{label}: malformed input-derivation tuple {index}")
        path, output_names = row
        require(NIX_DRV_RE.fullmatch(path) is not None and path not in inputs and output_names and all(output_names) and len(output_names) == len(set(output_names)), f"{label}: invalid or duplicate input derivation {path!r}")
        require(output_names == sorted(output_names), f"{label}: input derivation outputs are not in canonical order for {path!r}")
        inputs[path] = output_names
    require(list(inputs) == sorted(inputs), f"{label}: input derivations are not in canonical order")
    require(list(sources_raw) == sorted(sources_raw) and len(sources_raw) == len(set(sources_raw)) and all(NIX_STORE_PATH_RE.fullmatch(value) is not None for value in sources_raw), f"{label}: input sources are invalid,duplicate,or not in canonical order")
    environment: dict[str, str] = {}
    for index, row in enumerate(environment_raw):
        require(isinstance(row, tuple) and len(row) == 2 and all(isinstance(value, str) for value in row), f"{label}: malformed environment tuple {index}")
        key, value = row
        require(key != "" and key not in environment, f"{label}: empty or duplicate environment key {key!r}")
        environment[key] = value
    require(list(environment) == sorted(environment), f"{label}: environment is not in canonical order")
    for output_name, output in outputs.items():
        require(environment.get(output_name) == output["path"], f"{label}: output environment binding mismatch for {output_name!r}")
    json_environment = None
    if "__json" in environment:
        overlaps = sorted(STRUCTURED_SOURCE_ENV_KEYS.intersection(environment))
        require(not overlaps, f"{label}: structured __json conflicts with ordinary source environment bindings {overlaps}")
        try:
            json_raw = environment["__json"].encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise GateVerificationError(f"{label}: __json environment is not valid UTF-8") from error
        json_environment = obj(parse_json(json_raw, f"{label} __json", canonical=False), f"{label} __json")
        try:
            canonical_json_raw = canonical_json(json_environment).removesuffix(b"\n")
        except UnicodeEncodeError as error:
            raise GateVerificationError(f"{label}: __json environment contains a non-Unicode scalar value") from error
        require(json_raw == canonical_json_raw, f"{label}: __json environment is not canonical")
    return {"outputs": outputs, "inputDerivations": inputs, "inputSources": list(sources_raw), "platform": platform, "builder": builder, "arguments": list(arguments_raw), "environment": environment, "jsonEnvironment": json_environment}


def nix32(raw: bytes) -> str:
    alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
    if not raw:
        return ""
    length = (len(raw) * 8 - 1) // 5 + 1
    result: list[str] = []
    for index in range(length - 1, -1, -1):
        bit = index * 5
        byte_index, shift = divmod(bit, 8)
        value = raw[byte_index] >> shift
        if byte_index < len(raw) - 1:
            value |= raw[byte_index + 1] << (8 - shift)
        result.append(alphabet[value & 0x1F])
    return "".join(result)


def nix_store_path(path_type: str, hash_hex: str, name: str, label: str) -> str:
    require(path_type != "" and HEX64_RE.fullmatch(hash_hex) is not None and re.fullmatch(NIX_STORE_NAME_PATTERN, name) is not None, f"{label}: invalid Nix store-path inputs")
    fingerprint = f"{path_type}:sha256:{hash_hex}:/nix/store:{name}".encode("ascii")
    full_hash = hashlib.sha256(fingerprint).digest()
    compressed = bytearray(20)
    for index, value in enumerate(full_hash):
        compressed[index % len(compressed)] ^= value
    return f"/nix/store/{nix32(bytes(compressed))}-{name}"


def derivation_store_path(raw: bytes, derivation: dict[str, Any], expected_path: str, label: str) -> str:
    match = NIX_STORE_PATH_RE.fullmatch(expected_path)
    require(match is not None and match.group("name").endswith(".drv"), f"{label}: invalid derivation store path")
    references = sorted(set(derivation["inputDerivations"]) | set(derivation["inputSources"]))
    path_type = "text" + "".join(f":{reference}" for reference in references)
    return nix_store_path(path_type, sha256(raw), match.group("name"), label)


def fixed_output_store_path(hash_hex: str, semantics: str, expected_path: str, label: str) -> str:
    match = NIX_STORE_PATH_RE.fullmatch(expected_path)
    require(match is not None, f"{label}: invalid fixed-output store path")
    if semantics == "recursive":
        return nix_store_path("source", hash_hex, match.group("name"), label)
    require(semantics == "flat", f"{label}: unsupported fixed-output hash semantics")
    fixed_fingerprint = f"fixed:out:sha256:{hash_hex}:".encode("ascii")
    fixed_digest = hashlib.sha256(fixed_fingerprint).hexdigest()
    return nix_store_path("output:out", fixed_digest, match.group("name"), label)


def parse_drv_record(raw: bytes, label: str, expected_schema: str) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    record = obj(parse_json(raw, label), label)
    exact_keys(record, {"schema", "derivationPath", "derivationSha256", "derivationBase64", "captureTool", "sourceDerivationPaths"}, label)
    require(record["schema"] == expected_schema, f"{label}: wrong derivation-record schema")
    derivation_path = nonempty(record["derivationPath"], f"{label}.derivationPath")
    require(NIX_DRV_RE.fullmatch(derivation_path) is not None, f"{label}: invalid derivation path")
    digest = nonempty(record["derivationSha256"], f"{label}.derivationSha256")
    require(HEX64_RE.fullmatch(digest) is not None, f"{label}: invalid derivation SHA-256")
    nonempty(record["captureTool"], f"{label}.captureTool")
    source_paths = arr(record["sourceDerivationPaths"], f"{label}.sourceDerivationPaths")
    require(source_paths and all(isinstance(path, str) and NIX_DRV_RE.fullmatch(path) is not None for path in source_paths) and len(source_paths) == len(set(source_paths)), f"{label}: invalid source-derivation path list")
    derivation_raw = decode_bounded_base64(record["derivationBase64"], f"{label}.derivationBase64", max_decoded=MAX_DRV_BYTES)
    require(sha256(derivation_raw) == digest, f"{label}: derivation digest mismatch")
    require(digest not in SURROGATE_PACKAGE_DRV_SHA256S, f"{label}: known surrogate package derivation bytes are forbidden as original proof")
    derivation = parse_derivation(derivation_raw, label)
    require(derivation_store_path(derivation_raw, derivation, derivation_path, label) == derivation_path, f"{label}: derivation bytes do not compute to the claimed Nix store path")
    return record, derivation_raw, derivation


def sri_from_drv_hash(value: str, label: str) -> str:
    require(HEX64_RE.fullmatch(value) is not None, f"{label}: derivation fixed-output hash must be 32-byte hexadecimal SHA-256")
    return "sha256-" + base64.b64encode(bytes.fromhex(value)).decode("ascii")


def parse_b21_wire_artifact(raw: bytes, expected_ref: str) -> tuple[str, str]:
    proof = obj(parse_json(raw, f"D0-B21 wire proof {expected_ref}"), f"D0-B21 wire proof {expected_ref}")
    exact_keys(proof, {"schema", "capturedAt", "captureTool", "target", "protocol", "rawResponseBase64", "rawResponseSha256", "finalStatus", "verificationResult"}, f"D0-B21 wire proof {expected_ref}")
    require(proof["schema"] == "pkgre-d0-no-1xx-wire-proof-v1" and proof["target"] in B21_TARGETS and proof["protocol"] in B21_PROTOCOLS and proof["verificationResult"] == "PASS", "D0-B21: wire-proof identity/result mismatch")
    parse_utc(proof["capturedAt"], "D0-B21 capturedAt")
    nonempty(proof["captureTool"], "D0-B21 captureTool")
    capture = decode_bounded_base64(proof["rawResponseBase64"], "D0-B21 rawResponseBase64")
    require(HEX64_RE.fullmatch(nonempty(proof["rawResponseSha256"], "D0-B21 rawResponseSha256")) is not None and sha256(capture) == proof["rawResponseSha256"], "D0-B21: raw response digest mismatch")
    if proof["protocol"] == "HTTP/1.1":
        statuses = [int(value) for value in re.findall(rb"(?m)^HTTP/1\.[01] ([0-9]{3})(?:[ \r]|$)", capture)]
    else:
        statuses = [int(value) for value in re.findall(rb"(?m)^:status: ([0-9]{3})\r?$", capture)]
    require(statuses and all(status < 100 or status >= 200 for status in statuses), "D0-B21: informational 1xx response observed or status evidence absent")
    require(nonnegative_integer(proof["finalStatus"], "D0-B21 finalStatus") == statuses[-1] == 200, "D0-B21: final response status must be exact 200")
    return proof["target"], proof["protocol"]


def changed_paths(ops: GitOps, repo: Path, base: str, head: str) -> list[str]:
    raw = ops.run(repo, "diff", "--no-ext-diff", "--name-only", "-z", f"{base}..{head}").stdout
    return sorted(parse_nul_paths(raw, "D0 changed paths"))


def validate_b21(disposition: str, mode: str, results: list[dict[str, Any]], history_changed_paths: list[str], config: GateConfig) -> None:
    if disposition == "SATISFIED":
        require(mode == "PRE_D1_NO_1XX_PROOF", "D0-B21: wrong pre-D1 proof mode")
        actual_paths = history_changed_paths
        require(actual_paths and all(is_d0_path(path) and path != GATE_STATE_PATH for path in actual_paths), "D0-B21: closure evidence contains forbidden D1-path history")
        coverage: dict[tuple[str, str], str] = {}
        for result in results:
            claims = obj(result["claims"], "D0-B21 proof claims")
            exact_keys(claims, {"targets", "protocols", "no1xxObserved", "verificationResult", "d1WorkExcluded", "wireProofRefIds", "noD1WorkRefId"}, "D0-B21 proof claims")
            require(claims["targets"] == B21_TARGETS and claims["protocols"] == B21_PROTOCOLS and claims["no1xxObserved"] is True and claims["verificationResult"] == "PASS" and claims["d1WorkExcluded"] is True, "D0-B21: incomplete no-1xx claims")
            wire_ids = sorted(evidence_ids(result, "raw-wire-http1") + evidence_ids(result, "raw-wire-http2"))
            require(claims["wireProofRefIds"] == wire_ids and len(wire_ids) == len(B21_TARGETS) * len(B21_PROTOCOLS), "D0-B21: wire proof reference coverage mismatch")
            for ref_id in wire_ids:
                target, protocol = parse_b21_wire_artifact(result["_references"][ref_id]["raw"], ref_id)
                expected_kind = "raw-wire-http1" if protocol == "HTTP/1.1" else "raw-wire-http2"
                require(ref_id in evidence_ids(result, expected_kind), "D0-B21: protocol evidence kind mismatch")
                require((target, protocol) not in coverage, "D0-B21: duplicate target/protocol proof")
                coverage[(target, protocol)] = ref_id
            no_d1_ids = evidence_ids(result, "no-d1-work-proof")
            require(len(no_d1_ids) == 1 and claims["noD1WorkRefId"] == no_d1_ids[0], "D0-B21: no-D1-work reference mismatch")
            proof = obj(parse_json(result["_references"][no_d1_ids[0]]["raw"], "D0-B21 no-D1-work proof"), "D0-B21 no-D1-work proof")
            exact_keys(proof, {"schema", "closureSetId", "historicalCommit", "changedPaths", "verificationResult"}, "D0-B21 no-D1-work proof")
            require(proof == {"schema": "pkgre-d0-no-d1-work-proof-v1", "closureSetId": result.get("_closureSetId"), "historicalCommit": config.historical_aggregate_commit, "changedPaths": actual_paths, "verificationResult": "PASS"}, "D0-B21: no-D1-work proof does not match independently computed diff")
        require(set(coverage) == {(target, protocol) for target in B21_TARGETS for protocol in B21_PROTOCOLS}, "D0-B21: HTTP/1.1+HTTP/2 target coverage is incomplete")
    elif disposition == "REPHASED":
        require(mode == "EXACT_PHASE_AMENDMENT", "D0-B21: invalid rephase mode")
        for result in results:
            claims = obj(result["claims"], "D0-B21 rephase claims")
            exact_keys(claims, {"targetGates", "reason", "amendmentRefIds"}, "D0-B21 rephase claims")
            require(claims["targetGates"] == ["PRE_D6_EDGE", "PRE_D7_REAL_RAIN_EDGE"], "D0-B21: wrong rephase targets")
            nonempty(claims["reason"], "D0-B21 rephase reason")
            require_claim_ref_ids(result, claims["amendmentRefIds"], "phase-amendment", "D0-B21 rephase")
    else:
        raise GateVerificationError("D0-B21: only bounded pre-D1 proof or exact D6/D7 rephase is allowed")


def validate_https_source_url(value: Any, label: str) -> str:
    url = nonempty(value, label)
    try:
        url.encode("ascii", errors="strict")
        split = urlsplit(url)
        hostname = split.hostname
        port = split.port
    except (UnicodeError, ValueError) as error:
        raise GateVerificationError(f"{label}: invalid canonical ASCII URL") from error
    require(all(0x20 < ord(character) < 0x7F for character in url), f"{label}: URL controls and non-ASCII bytes are forbidden")
    require(split.scheme == "https" and hostname is not None and split.username is None and split.password is None and port is None and split.fragment == "", f"{label}: exact HTTPS URL without userinfo,port,or fragment required")
    require(split.netloc == hostname and hostname == hostname.lower() and not hostname.endswith("."), f"{label}: canonical ASCII lowercase authority required")
    labels = hostname.split(".")
    require(len(labels) >= 2 and len(hostname) <= 253 and not all(part.isdigit() for part in labels) and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) is not None for part in labels), f"{label}: invalid canonical DNS authority")
    require(re.match(r"[a-z]", labels[-1]) is not None, f"{label}: DNS authority final label must begin with an ASCII letter")
    path = split.path
    require(path.startswith("/") and path != "/" and "\\" not in path and "//" not in path, f"{label}: nonempty canonical absolute URL path required")
    segments = path[1:].split("/")
    require(all(segment not in {"", ".", ".."} for segment in segments), f"{label}: empty or dot URL path segment is forbidden")
    require(all(RFC3986_PCHAR_RE.fullmatch(segment) is not None for segment in segments), f"{label}: URL path contains a byte outside canonical RFC 3986 pchar syntax")
    for escape in re.finditer(r"%([0-9A-Fa-f]{2})", path):
        encoded = int(escape.group(1), 16)
        require(escape.group(1) == escape.group(1).upper(), f"{label}: percent escapes must use uppercase hexadecimal")
        require(encoded > 0x20 and encoded != 0x7F and encoded not in b"/\\?#", f"{label}: percent-encoded separator or control byte is forbidden")
        require(not (ord("A") <= encoded <= ord("Z") or ord("a") <= encoded <= ord("z") or ord("0") <= encoded <= ord("9") or encoded in b"-._~"), f"{label}: percent-encoded unreserved byte is noncanonical")
    require(re.sub(r"%[0-9A-F]{2}", "", path).find("%") == -1, f"{label}: malformed percent escape")
    require(split.query == "", f"{label}: source URL queries are forbidden")
    require(split.geturl() == url, f"{label}: URL does not round-trip canonically")
    return url


def validate_b22_source_verification(raw: bytes, source_claim: dict[str, Any], tool_id: str, original_package_drv: str, label: str) -> dict[str, Any]:
    verification = obj(parse_json(raw, label), label)
    exact_keys(verification, {"schema", "toolId", "originalPackageDrv", "sourceDrv", "sourceOutput", "urls", "hashAlgorithm", "hashValue", "hashSemantics", "derivationSha256", "derivationBase64", "captureTool", "verificationResult"}, label)
    require(verification["schema"] == "pkgre-d0-source-verification-v2" and verification["toolId"] == tool_id and verification["originalPackageDrv"] == original_package_drv and verification["verificationResult"] == "PASS", f"{label}: source-verification identity/result mismatch")
    for key in ("sourceDrv", "sourceOutput", "urls", "hashAlgorithm", "hashValue", "hashSemantics"):
        require(verification[key] == source_claim[key], f"{label}: source-verification {key} disagrees with operator claim")
    source_drv = nonempty(verification["sourceDrv"], f"{label}.sourceDrv")
    require(NIX_DRV_RE.fullmatch(source_drv) is not None and source_drv not in SURROGATE_PACKAGE_DRVS, f"{label}: invalid source derivation path or known package surrogate")
    source_output = nonempty(verification["sourceOutput"], f"{label}.sourceOutput")
    require(NIX_STORE_PATH_RE.fullmatch(source_output) is not None, f"{label}: invalid source output path")
    digest = nonempty(verification["derivationSha256"], f"{label}.derivationSha256")
    require(HEX64_RE.fullmatch(digest) is not None, f"{label}: invalid source derivation SHA-256")
    if source_drv in KNOWN_SURROGATE_DRV_SHA256S:
        require(digest == KNOWN_SURROGATE_DRV_SHA256S[source_drv], f"{label}: known retained derivation path has unexpected bytes")
    nonempty(verification["captureTool"], f"{label}.captureTool")
    derivation_raw = decode_bounded_base64(verification["derivationBase64"], f"{label}.derivationBase64", max_decoded=MAX_DRV_BYTES)
    require(sha256(derivation_raw) == digest, f"{label}: source derivation digest mismatch")
    derivation = parse_derivation(derivation_raw, label)
    require(derivation_store_path(derivation_raw, derivation, source_drv, label) == source_drv, f"{label}: source derivation bytes do not compute to the claimed Nix store path")
    require(set(derivation["outputs"]) == {"out"}, f"{label}: source derivation must have exactly one out output")
    output = derivation["outputs"]["out"]
    semantics = nonempty(verification["hashSemantics"], f"{label}.hashSemantics")
    expected_drv_algorithm = {"flat": "sha256", "recursive": "r:sha256"}.get(semantics)
    require(expected_drv_algorithm is not None and output["path"] == source_output and output["hashAlgorithm"] == expected_drv_algorithm, f"{label}: source output tuple or hash mode mismatch")
    require(fixed_output_store_path(output["hash"], semantics, source_output, label) == source_output, f"{label}: fixed-output hash does not compute to the claimed source output path")
    require(verification["hashAlgorithm"] == "sha256" and SRI_SHA256_RE.fullmatch(nonempty(verification["hashValue"], f"{label}.hashValue")) is not None, f"{label}: exact SRI SHA-256 claim required")
    require(sri_from_drv_hash(output["hash"], label) == verification["hashValue"], f"{label}: ATerm fixed-output hash disagrees with SRI claim")
    urls = arr(verification["urls"], f"{label}.urls")
    require(urls and len(urls) == len(set(urls)), f"{label}: nonempty unique source URL list required")
    for index, url in enumerate(urls):
        validate_https_source_url(url, f"{label}.urls[{index}]")
    json_environment = derivation["jsonEnvironment"]
    if json_environment is not None:
        require(json_environment.get("urls") == urls, f"{label}: __json URLs disagree with source claim")
        require(json_environment.get("outputHash") == verification["hashValue"] and json_environment.get("hash") == verification["hashValue"], f"{label}: __json output/hash fields disagree with source claim")
        require(json_environment.get("outputHashMode") == semantics, f"{label}: __json outputHashMode disagrees with source claim")
    else:
        environment = derivation["environment"]
        urls_text = nonempty(environment.get("urls"), f"{label}: traditional source derivation urls")
        derived_urls = urls_text.split(" ")
        require(" ".join(derived_urls) == urls_text and all(derived_urls), f"{label}: traditional source URLs must be canonical single-space-separated values")
        require(derived_urls == urls, f"{label}: traditional source URLs disagree with source claim")
        require(environment.get("outputHash") == verification["hashValue"], f"{label}: traditional source outputHash disagrees with source claim")
        require(environment.get("outputHashMode") == semantics, f"{label}: traditional source outputHashMode disagrees with source claim")
    return derivation


def package_primary_source_outputs(derivation: dict[str, Any], label: str) -> list[str]:
    """Return exact src/srcs bindings; patches and other build inputs remain authenticated by the package .drv identity."""
    json_environment = derivation["jsonEnvironment"]
    if json_environment is not None:
        has_src = "src" in json_environment
        has_srcs = "srcs" in json_environment
        require(has_src != has_srcs, f"{label}: structured package must declare exactly one of src or srcs")
        if has_src:
            values = [json_environment["src"]]
        else:
            values = arr(json_environment["srcs"], f"{label}.__json.srcs")
    else:
        environment = derivation["environment"]
        has_src = "src" in environment
        has_srcs = "srcs" in environment
        require(has_src != has_srcs, f"{label}: traditional package must declare exactly one of src or srcs")
        if has_src:
            values = [environment["src"]]
        else:
            srcs = nonempty(environment["srcs"], f"{label}.srcs")
            values = srcs.split(" ")
            require(" ".join(values) == srcs and all(values), f"{label}: traditional srcs must be canonical single-space-separated paths")
    require(values and all(isinstance(value, str) and NIX_STORE_PATH_RE.fullmatch(value) is not None for value in values), f"{label}: invalid package source-output binding")
    require(len(values) == len(set(values)), f"{label}: duplicate package source-output binding")
    return values


def validate_b22(disposition: str, mode: str, results: list[dict[str, Any]]) -> None:
    if disposition == "SATISFIED":
        require(mode == "ORIGINAL_DERIVATION_PROOF", "D0-B22: wrong original-proof mode")
        for result in results:
            require(set(result["_evidenceByKind"]) == {"original-derivation-records", "source-verification"}, "D0-B22: original proof requires the exact package/source evidence-kind set")
            package_evidence_ids = evidence_ids(result, "original-derivation-records")
            source_evidence_ids = evidence_ids(result, "source-verification")
            require(set(package_evidence_ids).isdisjoint(source_evidence_ids), "D0-B22: an evidence reference cannot be reused across package/source kinds")
            claims = obj(result["claims"], "D0-B22 original-proof claims")
            exact_keys(claims, {"tools"}, "D0-B22 original-proof claims")
            tools = arr(claims["tools"], "D0-B22 tools")
            require([obj(tool, "D0-B22 tool").get("id") for tool in tools] == ["git-host", "nix-host"], "D0-B22: exact git-host,nix-host rows required")
            seen_package_refs: set[str] = set()
            seen_source_refs: set[str] = set()
            for tool in tools:
                tool_id = tool["id"]
                exact_keys(tool, {"id", "observedOutput", "originalPackageDrv", "packageRecordRefId", "sourceDerivations"}, f"D0-B22 {tool_id} row")
                package_drv = tool["originalPackageDrv"]
                require(tool["observedOutput"] == OBSERVED_OUTPUTS[tool_id] and package_drv == ORIGINAL_PACKAGE_DRVS[tool_id] and package_drv not in SURROGATE_PACKAGE_DRVS, f"D0-B22 {tool_id}: original output/package derivation chain mismatch")
                package_ref_id = nonempty(tool["packageRecordRefId"], f"D0-B22 {tool_id} packageRecordRefId")
                require(package_ref_id in evidence_ids(result, "original-derivation-records") and package_ref_id not in seen_package_refs, f"D0-B22 {tool_id}: package record is missing,wrong-kind,or reused")
                seen_package_refs.add(package_ref_id)
                package_record, _package_raw, package_derivation = parse_drv_record(result["_references"][package_ref_id]["raw"], f"D0-B22 {tool_id} package record", "pkgre-d0-original-package-derivation-v2")
                require(package_record["derivationPath"] == package_drv, f"D0-B22 {tool_id}: package record path mismatch")
                require("out" in package_derivation["outputs"] and package_derivation["outputs"]["out"] == {"path": tool["observedOutput"], "hashAlgorithm": "", "hash": ""}, f"D0-B22 {tool_id}: package ATerm out tuple mismatch")
                sources = arr(tool["sourceDerivations"], f"D0-B22 {tool_id} source derivations")
                require(sources, f"D0-B22 {tool_id}: source derivations are empty")
                source_outputs = package_primary_source_outputs(package_derivation, f"D0-B22 {tool_id} package")
                claimed_outputs = [obj(source, f"D0-B22 {tool_id} source[{source_index}]").get("sourceOutput") for source_index, source in enumerate(sources)]
                require(source_outputs == claimed_outputs, f"D0-B22 {tool_id}: package source-output binding mismatch")
                seen_drvs: set[str] = set()
                for source_index, source_raw in enumerate(sources):
                    source = obj(source_raw, f"D0-B22 {tool_id} source[{source_index}]")
                    exact_keys(source, {"sourceDrv", "sourceOutput", "urls", "hashAlgorithm", "hashValue", "hashSemantics", "verificationRefId", "verificationResult"}, f"D0-B22 {tool_id} source")
                    source_drv = nonempty(source["sourceDrv"], f"D0-B22 {tool_id} sourceDrv")
                    require(NIX_DRV_RE.fullmatch(source_drv) is not None and source_drv not in SURROGATE_PACKAGE_DRVS and source_drv not in seen_drvs, f"D0-B22 {tool_id}: invalid,duplicate,or package-surrogate source derivation")
                    seen_drvs.add(source_drv)
                    require(package_derivation["inputDerivations"].get(source_drv) is not None and "out" in package_derivation["inputDerivations"][source_drv], f"D0-B22 {tool_id}: package ATerm lacks claimed source input edge")
                    require(source["verificationResult"] == "PASS", f"D0-B22 {tool_id}: source claim did not pass")
                    verification_ref_id = nonempty(source["verificationRefId"], f"D0-B22 {tool_id} verificationRefId")
                    require(verification_ref_id in evidence_ids(result, "source-verification") and verification_ref_id not in seen_source_refs, f"D0-B22 {tool_id}: source verification is missing,wrong-kind,or reused")
                    seen_source_refs.add(verification_ref_id)
                    validate_b22_source_verification(result["_references"][verification_ref_id]["raw"], source, tool_id, package_drv, f"D0-B22 {tool_id} source verification")
                require(package_record["sourceDerivationPaths"] == [source["sourceDrv"] for source in sources], f"D0-B22 {tool_id}: package record source-edge list mismatch")
            require(seen_package_refs == set(evidence_ids(result, "original-derivation-records")), "D0-B22: unused or missing package derivation record")
            require(seen_source_refs == set(evidence_ids(result, "source-verification")), "D0-B22: unused or missing source verification record")
    elif disposition == "WAIVED_BY_POLICY":
        require(mode == "POLICY_WAIVER", "D0-B22: wrong waiver mode")
        for result in results:
            require(set(result["_evidenceByKind"]) == {"policy-waiver"}, "D0-B22: waiver requires exactly one policy-waiver evidence kind")
            waiver_ids = evidence_ids(result, "policy-waiver")
            require(len(waiver_ids) == 1, "D0-B22: waiver requires exactly one policy-waiver evidence document")
            claims = obj(result["claims"], "D0-B22 waiver claims")
            exact_keys(claims, {"decisionId", "decisionDocument", "scope", "missingEvidence", "acceptedSubstitutes", "rationale", "residualRisks", "approver", "approvedAt", "policyVersion", "independentAcceptance"}, "D0-B22 waiver claims")
            nonempty(claims["decisionId"], "D0-B22 decision ID")
            document = obj(claims["decisionDocument"], "D0-B22 decision document")
            exact_keys(document, {"refId", "sha256"}, "D0-B22 decision document")
            require(document["refId"] == waiver_ids[0], "D0-B22: decision document must be the sole policy-waiver evidence")
            reference = result["_references"][document["refId"]]
            require(document["sha256"] == reference["sha256"] and HEX64_RE.fullmatch(document["sha256"]) is not None, "D0-B22: decision-document digest mismatch")
            require(claims["scope"] == ["git-host", "nix-host"], "D0-B22: waiver scope must be exact")
            for field in ("missingEvidence", "acceptedSubstitutes", "residualRisks"):
                require(isinstance(claims[field], list) and claims[field] and all(isinstance(value, str) and value for value in claims[field]), f"D0-B22: nonempty {field} required")
            nonempty(claims["rationale"], "D0-B22 rationale")
            nonempty(claims["approver"], "D0-B22 approver")
            parse_utc(claims["approvedAt"], "D0-B22 approval UTC")
            nonempty(claims["policyVersion"], "D0-B22 policy version")
            require(claims["independentAcceptance"] is True, "D0-B22: independent acceptance required")
            waiver = obj(parse_json(reference["raw"], "D0-B22 policy waiver"), "D0-B22 policy waiver")
            expected = {"schema": "pkgre-d0-b22-policy-waiver-v1", **{key: value for key, value in claims.items() if key != "decisionDocument"}}
            require(waiver == expected, "D0-B22: immutable waiver document does not exactly match the approved tuple")
    else:
        raise GateVerificationError("D0-B22: only original proof or exact policy waiver is allowed")


def verify_closure(ops: GitOps, repo: Path, state_raw: bytes, state: dict[str, Any], findings: dict[str, dict[str, Any]], items: dict[str, dict[str, Any]], procedural_authority_path: Path | None, config: GateConfig, verification_time: datetime) -> dict[str, Any]:
    closure = state["closureSet"]
    handoff_evidence: dict[str, dict[str, Any]] = {}
    procedural_authority_report = {**PROCEDURAL_AUTHORITY_ASSURANCE, "externalFile": None, "required": False, "sha256": None, "contentBindingVerified": False}
    evidence_commit: str | None = None
    closure_id: str | None = None
    if closure is None:
        require(procedural_authority_path is None, "procedural authority input is forbidden without a closure set")
        require(all(item["evidence"] is None for item in items.values()), "gate state: handoff evidence requires a closure set")
    else:
        closure = obj(closure, "closure set")
        exact_keys(closure, {"id", "closureEvidenceCommit", "evidenceTreeSha256"}, "closure set")
        closure_id = nonempty(closure["id"], "closure set ID")
        evidence_commit = nonempty(closure["closureEvidenceCommit"], "closure evidence commit")
        evidence_tree_sha = nonempty(closure["evidenceTreeSha256"], "closure evidence-tree SHA-256")
        require(CLOSURE_SET_RE.fullmatch(closure_id) is not None and HEX40_RE.fullmatch(evidence_commit) is not None and HEX64_RE.fullmatch(evidence_tree_sha) is not None, "closure set: invalid ID, evidence commit, or evidence-tree SHA-256")
        computed_tree_sha, _tree_entries = committed_evidence_tree(ops, repo, evidence_commit)
        require(evidence_tree_sha == computed_tree_sha, "closure set: committed evidence-tree SHA-256 mismatch")
        require(procedural_authority_path is not None, "closure evidence requires an external procedural-authority assertion")
        procedural_authority = verify_procedural_authority(ops, repo, state_raw, closure, items, procedural_authority_path)
        procedural_authority_report = procedural_authority["report"]
        for handoff_id, item in items.items():
            if item["evidence"] is not None:
                verified = verify_handoff_evidence(ops, repo, evidence_commit, closure_id, config.historical_aggregate_sha256, handoff_id, item["evidence"], procedural_authority["assignments"][handoff_id], verification_time)
                for result in verified["results"].values():
                    result["_closureSetId"] = closure_id
                handoff_evidence[handoff_id] = verified
        require(handoff_evidence, "closure set must contain at least one reviewed operator return")
    current_head = ops.text(repo, "rev-parse", "HEAD")
    require(HEX40_RE.fullmatch(current_head) is not None, "repository HEAD is not SHA-1")
    history = validate_gate_state_history(ops, repo, config.historical_aggregate_commit, current_head, state_raw, evidence_commit, config)
    open_findings: list[str] = []
    waived_findings: list[str] = []
    terminal_dispositions = {"SATISFIED", "REPHASED", "ACKNOWLEDGED_CONTAINED", "DEFERRED_REVIEWED", "WAIVED_BY_POLICY"}
    for finding_id, finding in findings.items():
        finding_closure = finding["closure"]
        disposition = finding_closure["disposition"]
        result = finding_closure["result"]
        if finding_id in LATER_FINDINGS:
            require(disposition == "PENDING" and result is None, f"{finding_id}: later gate must remain pending in D0")
            continue
        initial = "DEFERRED" if finding_id == "D0-B19" else "OPEN"
        if result is None:
            require(disposition == initial, f"{finding_id}: nonterminal disposition must be {initial}")
            open_findings.append(finding_id)
            for handoff_id in FINDING_HANDOFFS[finding_id]:
                if handoff_id in handoff_evidence:
                    contribution = handoff_evidence[handoff_id]["results"][finding_id]
                    require(contribution["disposition"] == initial and contribution["mode"] == "CONTRIBUTION_ONLY", f"{finding_id}: partial operator return must remain CONTRIBUTION_ONLY")
            continue
        require(disposition in terminal_dispositions, f"{finding_id}: invalid terminal disposition")
        result = obj(result, f"{finding_id} closure result")
        exact_keys(result, {"mode", "contributions"}, f"{finding_id} closure result")
        mode = nonempty(result["mode"], f"{finding_id} closure mode")
        contributions = arr(result["contributions"], f"{finding_id} contributions")
        require(len(contributions) == len(FINDING_HANDOFFS[finding_id]), f"{finding_id}: contribution coverage mismatch")
        contribution_ids: list[str] = []
        result_rows: list[dict[str, Any]] = []
        for index, raw in enumerate(contributions):
            contribution = obj(raw, f"{finding_id} contribution[{index}]")
            exact_keys(contribution, {"handoffId", "evidence"}, f"{finding_id} contribution[{index}]")
            handoff_id = nonempty(contribution["handoffId"], f"{finding_id} contribution handoff")
            contribution_ids.append(handoff_id)
            require(handoff_id in handoff_evidence and contribution["evidence"] == handoff_evidence[handoff_id]["reference"], f"{finding_id}: contribution does not bind exact operator/agent/reviewer evidence")
            payload_result = handoff_evidence[handoff_id]["results"][finding_id]
            require(payload_result["disposition"] == disposition and payload_result["mode"] == mode, f"{finding_id}: operator return disagrees with gate state")
            result_rows.append(payload_result)
        require(contribution_ids == FINDING_HANDOFFS[finding_id], f"{finding_id}: contributions must exactly follow all handoff references")
        require(evidence_commit is not None, f"{finding_id}: terminal closure lacks evidence commit")
        if finding_id == "D0-B18":
            validate_b18(disposition, mode, result_rows)
        elif finding_id == "D0-B19":
            validate_b19(disposition, mode, result_rows)
        elif finding_id == "D0-B21":
            validate_b21(disposition, mode, result_rows, history["evidenceChangedPaths"], config)
        elif finding_id == "D0-B22":
            validate_b22(disposition, mode, result_rows)
        else:
            validate_generic_policy(finding_id, disposition, mode, result_rows, verification_time)
        if disposition == "WAIVED_BY_POLICY":
            waived_findings.append(finding_id)
    complete_handoffs = sorted(handoff_evidence)
    handoff_complete = set(complete_handoffs) == set(HANDOFFS)
    d0_pass = not open_findings and handoff_complete
    return {"d0Pass": d0_pass, "openFindings": sorted(open_findings), "completeHandoffs": complete_handoffs, "handoffComplete": handoff_complete, "waivedFindings": sorted(waived_findings), "proceduralAuthority": procedural_authority_report}


def canonical_worktree_file(repo: Path, supplied_path: Path, relative_path: str, label: str) -> Path:
    expected = repo / relative_path
    require(supplied_path.is_absolute() and supplied_path == expected, f"{label}: must use the exact canonical worktree path {expected}")
    current = repo
    for component in relative_path.split("/")[:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise GateVerificationError(f"{label}: cannot stat canonical parent {current}: {error}") from error
        require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), f"{label}: canonical parent must be a direct non-symlink directory: {current}")
    try:
        metadata = expected.lstat()
    except OSError as error:
        raise GateVerificationError(f"{label}: cannot stat canonical file {expected}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), f"{label}: canonical file must be a direct regular non-symlink file: {expected}")
    require(metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0, f"{label}: canonical data file must be non-executable: {expected}")
    return expected


def verify_repository_anchor(ops: GitOps, repo: Path, aggregate_path: Path, state_path: Path, config: GateConfig) -> tuple[bytes, bytes, dict[str, Any]]:
    require(repo.is_absolute() and repo == repo.resolve(), "repository anchor: supplied repository must be an absolute resolved path")
    require(ops.text(repo, "rev-parse", "--show-toplevel") == str(repo), "repository anchor: supplied repository is not the exact Git worktree root")
    aggregate_file = canonical_worktree_file(repo, aggregate_path, AGGREGATE_PATH, "aggregate")
    state_file = canonical_worktree_file(repo, state_path, GATE_STATE_PATH, "gate state")
    aggregate_raw = load_regular(aggregate_file, "aggregate", MAX_JSON_BYTES)
    require(sha256(aggregate_raw) == config.historical_aggregate_sha256, "aggregate digest differs from verifier-pinned historical record")
    committed_aggregate = ops.blob(repo, config.historical_aggregate_commit, AGGREGATE_PATH, "historical aggregate", MAX_JSON_BYTES, expected_mode="100644")
    require(committed_aggregate == aggregate_raw, "working aggregate differs from immutable historical aggregate blob")
    state_raw = load_regular(state_file, "gate state", MAX_JSON_BYTES)
    current_head = ops.text(repo, "rev-parse", "HEAD")
    require(HEX40_RE.fullmatch(current_head) is not None, "repository HEAD is not SHA-1")
    require(ops.blob(repo, current_head, GATE_STATE_PATH, "HEAD gate state", MAX_JSON_BYTES, expected_mode="100644") == state_raw, "working gate state is not the exact HEAD gate-state blob")
    state = obj(parse_json(state_raw, str(state_file)), "gate state")
    return aggregate_raw, state_raw, state


def direct_local_config(ops: GitOps, repository: Path, git_dir: Path, label: str) -> dict[str, list[str]]:
    config_path = git_dir / "config"
    config_raw = load_regular(config_path, f"{label} local Git config", MAX_JSON_BYTES)
    require(b"\0" not in config_raw, f"{label}: NUL byte in local Git config")
    process = ops.run(repository, "config", "--file", str(config_path), "--no-includes", "--null", "--list", check=False)
    require(process.returncode == 0, f"{label}: cannot parse direct local Git config")
    require(process.stdout == b"" or process.stdout.endswith(b"\0"), f"{label}: local Git config output is not NUL-delimited")
    result: dict[str, list[str]] = {}
    for index, raw_record in enumerate(process.stdout.split(b"\0")):
        if raw_record == b"":
            continue
        require(raw_record.count(b"\n") == 1, f"{label}: malformed local Git config record {index}")
        raw_key, raw_value = raw_record.split(b"\n", 1)
        try:
            key = raw_key.decode("utf-8", errors="strict").lower()
            value = raw_value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}: non-UTF-8 local Git config record {index}") from error
        require(key != "" and value.find("\x00") == -1, f"{label}: empty key or NUL value in local Git config")
        result.setdefault(key, []).append(value)
    return result


def singleton_config(config_values: dict[str, list[str]], key: str, label: str) -> str:
    values = config_values.get(key.lower(), [])
    require(len(values) == 1, f"{label}: local Git config {key!r} must occur exactly once")
    return values[0]


def validate_local_config(config_values: dict[str, list[str]], expected: RepositoryBasis, label: str) -> None:
    version = singleton_config(config_values, "core.repositoryformatversion", label)
    extensions = sorted(key for key in config_values if key.startswith("extensions."))
    if version == "0":
        require(not extensions, f"{label}: repository format 0 must not have extensions")
    elif version == "1":
        require(extensions == ["extensions.objectformat"] and singleton_config(config_values, "extensions.objectformat", label) == "sha1", f"{label}: repository format 1 requires only extensions.objectFormat=sha1")
    else:
        raise GateVerificationError(f"{label}: unsupported repository format {version!r}")
    require(singleton_config(config_values, "core.filemode", label) == "true", f"{label}: core.fileMode must be true")
    require(singleton_config(config_values, "core.bare", label) == "false", f"{label}: core.bare must be false")
    require(singleton_config(config_values, "core.logallrefupdates", label) == "true", f"{label}: core.logAllRefUpdates must be true")
    allowed_exact = {
        "core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
        f"remote.{expected.remote}.url", f"remote.{expected.remote}.fetch",
    }
    for key, values in config_values.items():
        require(len(values) == 1, f"{label}: duplicate local Git config key {key!r}")
        forbidden = key in FORBIDDEN_CONFIG_EXACT or any(key.startswith(prefix) for prefix in FORBIDDEN_CONFIG_PREFIXES)
        require(not forbidden, f"{label}: forbidden local Git config key {key!r}")
        if key in allowed_exact or key == "extensions.objectformat":
            continue
        branch = re.fullmatch(r"branch\.([A-Za-z0-9._/-]+)\.(remote|merge)", key)
        require(branch is not None, f"{label}: unrecognized local Git config key {key!r}")
        if branch.group(2) == "remote":
            require(values[0] == expected.remote, f"{label}: branch remote must be {expected.remote!r}")
        else:
            require(values[0].startswith("refs/heads/") and safe_path(values[0].removeprefix("refs/heads/"), f"{label} branch merge ref") != "", f"{label}: invalid branch merge ref")
    require(singleton_config(config_values, f"remote.{expected.remote}.url", label) == expected.remote_url, f"{label}: literal remote URL mismatch")
    expected_fetch = f"+refs/heads/*:refs/remotes/{expected.remote}/*"
    require(singleton_config(config_values, f"remote.{expected.remote}.fetch", label) == expected_fetch, f"{label}: remote fetch refspec mismatch")


def require_absent_path(path: Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise GateVerificationError(f"{label}: cannot inspect {path}: {error}") from error
    raise GateVerificationError(f"{label}: forbidden path exists: {path}")


def parse_ls_files_v(raw: bytes, label: str) -> list[str]:
    require(raw == b"" or raw.endswith(b"\0"), f"{label}: expected NUL-delimited ls-files output")
    paths: list[str] = []
    for index, record in enumerate(raw.split(b"\0")):
        if record == b"":
            continue
        require(len(record) >= 3 and record[1:2] == b" ", f"{label}[{index}]: malformed ls-files -v record")
        flag = chr(record[0])
        require(flag.isupper() and flag != "S", f"{label}: assume-unchanged or skip-worktree index flag {flag!r} is forbidden")
        try:
            path = record[2:].decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}[{index}]: non-UTF-8 index path") from error
        paths.append(safe_path(path, f"{label}[{index}] path"))
    require(len(paths) == len(set(paths)), f"{label}: duplicate index paths")
    return paths


def parse_ls_files_debug(raw: bytes, expected_paths: list[str], label: str) -> None:
    offset = 0
    parsed: list[str] = []
    metadata = re.compile(rb"  ctime: [0-9]+:[0-9]+\n  mtime: [0-9]+:[0-9]+\n  dev: [0-9]+\tino: [0-9]+\n  uid: [0-9]+\tgid: [0-9]+\n  size: [0-9]+\tflags: ([0-9a-fA-F]+)\n")
    while offset < len(raw):
        terminator = raw.find(b"\0", offset)
        require(terminator >= 0, f"{label}: missing index-path terminator")
        try:
            path = raw[offset:terminator].decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}: non-UTF-8 debug index path") from error
        path = safe_path(path, f"{label} path")
        match = metadata.match(raw, terminator + 1)
        require(match is not None, f"{label}: malformed debug metadata for {path!r}")
        require(int(match.group(1), 16) == 0, f"{label}: nonzero extended index flags for {path!r}")
        parsed.append(path)
        offset = match.end()
    require(parsed == expected_paths, f"{label}: debug/index path mismatch")


def parse_ls_files_stage(raw: bytes, expected_paths: list[str], label: str) -> None:
    require(raw == b"" or raw.endswith(b"\0"), f"{label}: expected NUL-delimited staged-index output")
    parsed: list[str] = []
    for index, record in enumerate(raw.split(b"\0")):
        if record == b"":
            continue
        try:
            text = record.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GateVerificationError(f"{label}[{index}]: non-UTF-8 staged-index record") from error
        match = re.fullmatch(r"(100644|100755) ([0-9a-f]{40}) ([0-3])\t(.+)", text)
        require(match is not None, f"{label}[{index}]: malformed or special-mode staged-index entry")
        require(match.group(3) == "0", f"{label}: unmerged index stage is forbidden")
        parsed.append(safe_path(match.group(4), f"{label}[{index}] path"))
    require(parsed == expected_paths, f"{label}: staged/index path mismatch")


def verify_index_safety(ops: GitOps, repository: Path, git_dir: Path, expected: RepositoryBasis) -> None:
    label = f"PRE_D1 {expected.id}"
    indexed_paths = parse_ls_files_v(ops.run(repository, "ls-files", "-v", "-z").stdout, f"{label} index flags")
    parse_ls_files_debug(ops.run(repository, "ls-files", "--debug", "-z").stdout, indexed_paths, f"{label} index debug")
    parse_ls_files_stage(ops.run(repository, "ls-files", "--stage", "-z").stdout, indexed_paths, f"{label} index stages")
    require_absent_path(git_dir / "info" / "sparse-checkout", f"{label} sparse-checkout patterns")
    sparse = ops.run(repository, "sparse-checkout", "list", check=False)
    require(sparse.returncode != 0 and sparse.stdout == b"", f"{label}: sparse checkout is forbidden")
    status = ops.run(repository, "status", "--porcelain=v2", "-z", "--untracked-files=all", check=False)
    require(status.returncode == 0 and status.stdout == b"", f"{label}: index or worktree is dirty")
    ignored = ops.run(repository, "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", check=False)
    require(ignored.returncode == 0, f"{label}: cannot inspect ignored paths")
    for record in ignored.stdout.split(b"\0"):
        if record.startswith(b"! ") and any(record[2:].startswith(prefix) for prefix in GATE_SENSITIVE_PREFIXES):
            raise GateVerificationError(f"{label}: ignored gate-sensitive path is forbidden: {record[2:]!r}")


def verify_repository_safety(ops: GitOps, repository: Path, config: GateConfig, expected: RepositoryBasis) -> None:
    label = f"PRE_D1 {expected.id}"
    require(not ops.input_transport_overrides or config.allow_git_transport_overrides, f"{label}: caller Git transport overrides are forbidden")
    require(repository.is_absolute(), f"{label}: repository path must be absolute")
    dot_git = repository / ".git"
    try:
        dot_git_mode = dot_git.lstat().st_mode
    except OSError as error:
        raise GateVerificationError(f"{label}: cannot inspect direct .git directory: {error}") from error
    require(stat.S_ISDIR(dot_git_mode) and not stat.S_ISLNK(dot_git_mode), f"{label}: .git must be a direct non-symlink directory")
    require_absent_path(dot_git / "config.worktree", f"{label} worktree config")
    config_values = direct_local_config(ops, repository, dot_git, label)
    validate_local_config(config_values, expected, label)
    require(ops.text(repository, "rev-parse", "--show-object-format") == "sha1", f"{label}: object format is not SHA-1")
    require(ops.text(repository, "rev-parse", "--is-shallow-repository") == "false", f"{label}: shallow repository is forbidden")
    git_dir = Path(ops.text(repository, "rev-parse", "--absolute-git-dir"))
    common_dir = Path(ops.text(repository, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    require(git_dir.resolve() == dot_git.resolve() == common_dir.resolve(), f"{label}: linked/common Git directories are forbidden")
    require_absent_path(git_dir / "shallow", f"{label} shallow boundary")
    require_absent_path(git_dir / "objects" / "info" / "alternates", f"{label} alternates")
    require_absent_path(git_dir / "info" / "grafts", f"{label} grafts")
    require_absent_path(git_dir / "commondir", f"{label} common-dir indirection")
    require_absent_path(git_dir / "worktrees", f"{label} linked worktrees")
    promisor_files = list((git_dir / "objects" / "pack").glob("*.promisor"))
    require(not promisor_files, f"{label}: promisor pack state is forbidden")
    hooks_dir = git_dir / "hooks"
    if hooks_dir.exists():
        for hook in hooks_dir.iterdir():
            mode = hook.lstat().st_mode
            if hook.name.endswith(".sample") and stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
                continue
            raise GateVerificationError(f"{label}: active or unrecognized Git hook is forbidden: {hook}")
    require(ops.text(repository, "for-each-ref", "--format=%(refname)", "refs/replace") == "", f"{label}: replace refs are forbidden")
    worktree_rows = [line.removeprefix("worktree ") for line in ops.text(repository, "worktree", "list", "--porcelain").splitlines() if line.startswith("worktree ")]
    require(worktree_rows == [str(repository)], f"{label}: unexpected registered worktrees")
    verify_index_safety(ops, repository, git_dir, expected)
    fsck = ops.run(repository, "fsck", "--strict", "--connectivity-only", "--no-dangling", check=False)
    require(fsck.returncode == 0, f"{label}: strict Git connectivity check failed")


def status_observation(ops: GitOps, repository: Path, expected: RepositoryBasis, label: str) -> tuple[dict[str, Any], bytes]:
    status = ops.run(repository, "status", "--porcelain=v2", "-z", "--untracked-files=all", check=False)
    ignored = ops.run(repository, "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", check=False)
    require(ignored.returncode == 0, f"PRE_D1 {expected.id}: cannot inspect ignored paths during {label}")
    for record in ignored.stdout.split(b"\0"):
        if record.startswith(b"! ") and any(record[2:].startswith(prefix) for prefix in GATE_SENSITIVE_PREFIXES):
            raise GateVerificationError(f"PRE_D1 {expected.id}: unexpected ignored gate-sensitive path: {record[2:]!r}")
    observation = {"head": ops.text(repository, "rev-parse", "HEAD"), "statusExit": status.returncode, "statusSha256": sha256(status.stdout), "clean": status.returncode == 0 and status.stdout == b""}
    require(observation["clean"], f"PRE_D1 {expected.id}: worktree is dirty during {label}")
    return observation, status.stdout


def observe_pre_d1_repository(ops: GitOps, workspace: Path, expected: RepositoryBasis, expected_head: str, config: GateConfig) -> dict[str, Any]:
    repository = (workspace / safe_path(expected.path, f"{expected.id} repository path")).resolve()
    require(repository.parent == workspace and repository.is_dir(), f"PRE_D1 {expected.id}: trusted repository path escapes workspace or is absent")
    require(ops.text(repository, "rev-parse", "--show-toplevel") == str(repository), f"PRE_D1 {expected.id}: wrong Git root")
    require(REMOTE_RE.fullmatch(expected.remote) is not None and expected.ref.startswith("refs/heads/"), f"PRE_D1 {expected.id}: unsafe remote/ref policy")
    verify_repository_safety(ops, repository, config, expected)
    branch = expected.ref.removeprefix("refs/heads/")
    require(ops.text(repository, "symbolic-ref", "--quiet", "HEAD") == expected.ref, f"PRE_D1 {expected.id}: checked-out branch mismatch")
    require(ops.text(repository, "rev-parse", "--abbrev-ref", "@{upstream}") == expected.upstream, f"PRE_D1 {expected.id}: upstream mismatch")
    before, _ = status_observation(ops, repository, expected, "pre-fetch observation")
    fetch_refspec = f"+{expected.ref}:refs/remotes/{expected.remote}/{branch}"
    fetch = ops.run(repository, "fetch", "--prune", "--no-tags", expected.remote, fetch_refspec, check=False)
    after, _ = status_observation(ops, repository, expected, "post-fetch observation")
    require(fetch.returncode == 0, f"PRE_D1 {expected.id}: fetch failed")
    require(before["head"] == after["head"] == expected_head and HEX40_RE.fullmatch(expected_head) is not None, f"PRE_D1 {expected.id}: HEAD changed or does not match expected closure/basis")
    remote_ref = f"refs/remotes/{expected.remote}/{branch}"
    remote_commit = ops.text(repository, "rev-parse", "--verify", f"{remote_ref}^{{commit}}")
    ancestry = ops.run(repository, "merge-base", "--is-ancestor", expected.reviewed_commit, expected_head, check=False)
    require(ancestry.returncode == 0, f"PRE_D1 {expected.id}: reviewed commit is not an ancestor")
    divergence = ops.text(repository, "rev-list", "--left-right", "--count", f"HEAD...{remote_ref}").split()
    require(len(divergence) == 2 and all(value.isdigit() for value in divergence), f"PRE_D1 {expected.id}: invalid divergence output")
    ahead, behind = map(int, divergence)
    require(behind == 0, f"PRE_D1 {expected.id}: repository is behind/diverged from fetched ref")
    if expected.id == "pkgre/pkgre":
        require(ops.run(repository, "merge-base", "--is-ancestor", remote_commit, expected_head, check=False).returncode == 0, "PRE_D1 pkgre: remote ref is not an ancestor of closure commit")
        paths = changed_paths(ops, repository, expected.reviewed_commit, expected_head)
        require(paths and all(is_d0_path(path) for path in paths), "PRE_D1 pkgre: ahead history contains non-D0 paths")
    else:
        require(remote_commit == expected.reviewed_commit and ahead == 0 and expected_head == expected.reviewed_commit, f"PRE_D1 {expected.id}: basis moved")
    return {
        **expected.state_row(),
        "expectedHead": expected_head,
        "currentHead": after["head"],
        "remoteRefCommit": remote_commit,
        "fetchExit": fetch.returncode,
        "statusExit": after["statusExit"],
        "ancestryExit": ancestry.returncode,
        "clean": after["clean"],
        "ahead": ahead,
        "behind": behind,
        "objectFormat": "sha1",
        "preFetch": before,
        "postFetch": after,
    }


def collect_pre_d1_rows(repo_root: Path, closure_commit: str, config: GateConfig = PRODUCTION_CONFIG, git_runner: GitRunner = default_git_runner, environment: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    ops = GitOps(git_runner, environment)
    workspace = repo_root.resolve().parent
    rows = []
    for expected in config.repositories:
        expected_head = closure_commit if expected.id == "pkgre/pkgre" else expected.reviewed_commit
        rows.append(observe_pre_d1_repository(ops, workspace, expected, expected_head, config))
    return rows


def validate_pre_d1_transcript(raw: bytes, *, closure_commit: str, created_at: str, receipt_rows: list[Any]) -> dict[str, Any]:
    """Require the transcript to be a canonical, exact binding of the receipt rows."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_TRANSCRIPT_BYTES, f"PRE_D1 transcript: content must be 1..{MAX_TRANSCRIPT_BYTES} bytes")
    closure_commit = hex_digest(closure_commit, "PRE_D1 transcript closure commit", "sha1")
    created_at = utc_text(created_at, "PRE_D1 transcript createdAt binding")
    transcript = obj(parse_json(raw, "PRE_D1 transcript"), "PRE_D1 transcript")
    exact_keys(transcript, {"schema", "d0ClosureCommit", "createdAt", "repositories"}, "PRE_D1 transcript")
    require(transcript["schema"] == "pkgre-pre-d1-refetch-transcript-v1", "PRE_D1 transcript: wrong schema")
    require(transcript["d0ClosureCommit"] == closure_commit, "PRE_D1 transcript: closure-commit binding mismatch")
    require(transcript["createdAt"] == created_at, "PRE_D1 transcript: timestamp binding mismatch")
    repositories = arr(transcript["repositories"], "PRE_D1 transcript repositories")
    require(repositories == receipt_rows, "PRE_D1 transcript: repository observations differ from receipt")
    return transcript


def verify_pre_d1_receipt(ops: GitOps, repo_root: Path, state_raw: bytes, closure_commit: str, receipt_path: Path, config: GateConfig, verification_time: datetime) -> None:
    gate_dir = repo_root.resolve() / ".git" / "pkgre-gates"
    receipt_raw = load_external_gate_file(ops, repo_root, receipt_path, "PRE_D1 receipt", MAX_JSON_BYTES)
    receipt = obj(parse_json(receipt_raw, str(receipt_path)), "PRE_D1 receipt")
    exact_keys(receipt, {"schema", "d0ClosureCommit", "createdAt", "immediatelyBeforeD1FirstEdit", "repositories", "transcript"}, "PRE_D1 receipt")
    require(receipt["schema"] == "pkgre-pre-d1-refetch-receipt-v2" and receipt["d0ClosureCommit"] == closure_commit and receipt["immediatelyBeforeD1FirstEdit"] is True, "PRE_D1 receipt binding mismatch")
    created_at = utc_text(receipt["createdAt"], "PRE_D1 receipt createdAt")
    created = parse_utc(created_at, "PRE_D1 receipt createdAt")
    require((created - verification_time).total_seconds() <= RECEIPT_FUTURE_SKEW_SECONDS, "PRE_D1 receipt timestamp is too far in the future")
    require((verification_time - created).total_seconds() <= PRE_D1_RECEIPT_MAX_AGE_SECONDS, "PRE_D1 receipt is stale")
    transcript = obj(receipt["transcript"], "PRE_D1 transcript reference")
    exact_keys(transcript, {"path", "sha256"}, "PRE_D1 transcript reference")
    transcript_name = safe_path(transcript["path"], "PRE_D1 transcript path")
    require("/" not in transcript_name and transcript_name != receipt_path.name, "PRE_D1 transcript must be a distinct sibling file")
    require(HEX64_RE.fullmatch(nonempty(transcript["sha256"], "PRE_D1 transcript digest")) is not None, "PRE_D1 transcript digest is invalid")
    transcript_raw = load_external_gate_file(ops, repo_root, gate_dir / transcript_name, "PRE_D1 transcript", MAX_TRANSCRIPT_BYTES)
    require(sha256(transcript_raw) == transcript["sha256"], "PRE_D1 transcript digest mismatch")
    rows = arr(receipt["repositories"], "PRE_D1 repositories")
    require(len(rows) == len(config.repositories), f"PRE_D1 receipt must contain exactly {len(config.repositories)} repositories")
    validate_pre_d1_transcript(transcript_raw, closure_commit=closure_commit, created_at=created_at, receipt_rows=rows)
    observed = []
    workspace = repo_root.resolve().parent
    for expected in config.repositories:
        expected_head = closure_commit if expected.id == "pkgre/pkgre" else expected.reviewed_commit
        observed.append(observe_pre_d1_repository(ops, workspace, expected, expected_head, config))
    require(rows == observed, "PRE_D1 receipt repository observations do not exactly match the verifier's live refetch")
    require(ops.blob(repo_root, closure_commit, GATE_STATE_PATH, "PRE_D1 closure state", MAX_JSON_BYTES, expected_mode="100644") == state_raw, "PRE_D1 closure commit does not contain the verified gate state")


def verify_gate(repo_root: Path, aggregate_path: Path, state_path: Path, receipt_path: Path | None = None, now: datetime | None = None, config: GateConfig = PRODUCTION_CONFIG, git_runner: GitRunner = default_git_runner, environment: Mapping[str, str] | None = None, procedural_authority_path: Path | None = None) -> dict[str, Any]:
    repo = repo_root.resolve()
    current_time = normalize_verification_time(now)
    ops = GitOps(git_runner, environment)
    aggregate_raw, state_raw, state = verify_repository_anchor(ops, repo, aggregate_path, state_path, config)
    findings, items = validate_state_shape(state, aggregate_raw, config)
    closure_result = verify_closure(ops, repo, state_raw, state, findings, items, procedural_authority_path, config, current_time)
    d0_pass = closure_result["d0Pass"]
    pre_d1_pass = False
    if receipt_path is not None:
        require(d0_pass, "PRE_D1 receipt cannot authorize while D0 is blocked")
        obj(state["closureSet"], "closure set")
        closure_commit = ops.text(repo, "rev-parse", "HEAD")
        verify_pre_d1_receipt(ops, repo, state_raw, closure_commit, receipt_path, config, current_time)
        pre_d1_pass = True
    d1_authorized = d0_pass and pre_d1_pass
    agent_mutation = {key: (d1_authorized if key == "d1Implementation" else False) for key in AGENT_MUTATIONS}
    operator_mutation = {key: False for key in OPERATOR_MUTATIONS}
    later_authority = {gate["id"]: (d1_authorized if gate["id"] == "PRE_D1_REFETCH" else False) for gate in LATER_GATES}
    return {
        "d0EvidenceVerdict": "PASS" if d0_pass else "BLOCKED",
        "preD1Verdict": "PASS" if d1_authorized else "BLOCKED",
        "d1Authorized": d1_authorized,
        "stop": not d1_authorized,
        "openD0Blockers": closure_result["openFindings"],
        "unsatisfiedPreD1Gates": [] if d1_authorized else ["PRE_D1_REFETCH"],
        "handoffComplete": closure_result["handoffComplete"],
        "completeHandoffs": closure_result["completeHandoffs"],
        "waivedFindings": closure_result["waivedFindings"],
        "proceduralAuthority": closure_result["proceduralAuthority"],
        "mutationAuthority": {"agent": agent_mutation, "operatorRollout": operator_mutation, "operatorEmergencyExceptions": MUTATION_POLICY["operatorEmergencyExceptions"]},
        "laterGateMutationAuthority": later_authority,
    }


def draft_gate_state(repo_root: Path, *, write_external: bool = False, config: GateConfig = PRODUCTION_CONFIG, git_runner: GitRunner = default_git_runner, environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Return the canonical blocked draft, or create its fixed private external artifact."""
    state = initial_gate_state(config)
    if not write_external:
        return state
    repo = repo_root.resolve()
    ops = GitOps(git_runner, environment)
    raw = canonical_json(state)
    path = create_external_gate_file(ops, repo, D0_STATE_DRAFT_NAME, raw, "D0 state draft", MAX_JSON_BYTES)
    return {
        "schema": "pkgre-d0-state-draft-write-v1",
        "artifact": {"path": path.relative_to(repo).as_posix(), "sha256": sha256(raw)},
        "d0EvidenceVerdict": "BLOCKED",
        "d1Authorized": False,
        "trackedGateStateWritten": False,
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pkgre D0 closure security tooling")
    subparsers = parser.add_subparsers(dest="command", required=True)
    draft_parser = subparsers.add_parser("draft-state", help="emit the canonical blocked D0 draft without writing tracked state")
    draft_parser.add_argument("--repo", type=Path, default=Path.cwd(), help="direct Git worktree root (default: current directory)")
    draft_parser.add_argument("--write-external", action="store_true", help=f"exclusively create .git/pkgre-gates/{D0_STATE_DRAFT_NAME} instead of emitting the draft")
    openapi_parser = subparsers.add_parser("audit-github-openapi", help="audit frozen D0 GitHub contracts against the exact pinned OpenAPI document")
    openapi_parser.add_argument("document", type=Path, help="path to the exact pinned api.github.com OpenAPI JSON document")
    namespace = parser.parse_args(arguments)
    try:
        if namespace.command == "draft-state":
            result = draft_gate_state(namespace.repo, write_external=namespace.write_external)
        elif namespace.command == "audit-github-openapi":
            result = audit_pinned_github_openapi(namespace.document)
        else:
            parser.error(f"unsupported command: {namespace.command}")
    except GateVerificationError as error:
        print(f"ERROR:{error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
