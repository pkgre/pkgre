#!/usr/bin/env python3
"""Adversarial regression tests for the content-addressed D0/PRE_D1 gate."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "scripts" / "d0_gate.py"
DRV_VECTOR_ROOT = REPO_ROOT / "fixtures" / "d0-v1" / "nix-derivation-vectors"
DRV_VECTOR_DRV_ROOT = DRV_VECTOR_ROOT / "drvs"
EXPECTED_DRV_VECTORS = {
    "drvs/1gys5xmkzxr4qbycxl7ilkb15d35z1g2-source.drv": (4318, "9669d6daf85d974b7a7d71f591a557454a8abd0141553baad71e6ea3382b8e6d"),
    "drvs/cgrzc3wys8sljv5k23xfmmlzx0s21vjv-git-2.54.0.tar.xz.drv": (3504, "37085e2de8bfd72045da2e2da33bda0e93ec6cd47c91ab7219d4bdbc4d1bc9b3"),
    "drvs/ji4chnn38m9yjm5fq9w624w63vwf456s-source.drv": (3601, "6c94c14d89f9f2b54138e79f4ba572f9ffe4a2f61599c617f0cbfe369422ff4f"),
}


def load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pkgre_d0_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load gate: {GATE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = load_gate()


def git(repository: Path, *arguments: str, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.run(["git", "-C", str(repository), *arguments], input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and process.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments)} failed:{process.stderr.decode(errors='replace')}")
    return process


def write(repository: Path, relative: str, content: bytes) -> None:
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def write_canonical_json(repository: Path, relative: str, value: object) -> dict[str, str]:
    raw = GATE.canonical_json(value)
    write(repository, relative, raw)
    return {"path": relative, "sha256": GATE.sha256(raw)}


def commit(repository: Path, message: str) -> str:
    git(repository, "add", "-A")
    git(repository, "commit", "-m", message)
    return git(repository, "rev-parse", "HEAD").stdout.decode().strip()


class RepositoryFixture:
    def __init__(self, root: Path) -> None:
        self.repository = root
        git(root, "init", "-b", "main")
        git(root, "config", "user.name", "D0 Test")
        git(root, "config", "user.email", "d0@example.invalid")
        git(root, "config", "--unset-all", "user.name")
        git(root, "config", "--unset-all", "user.email")
        git(root, "config", "remote.origin.url", "git@example.invalid:test/repo.git")
        git(root, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
        git(root, "config", "branch.main.remote", "origin")
        git(root, "config", "branch.main.merge", "refs/heads/main")
        self.environment = dict(os.environ)
        self.environment.update({"GIT_AUTHOR_NAME": "D0 Test", "GIT_AUTHOR_EMAIL": "d0@example.invalid", "GIT_COMMITTER_NAME": "D0 Test", "GIT_COMMITTER_EMAIL": "d0@example.invalid"})
        write(root, "scripts/d0_gate.py", b"base\n")
        git(root, "add", "-A")
        subprocess.run(["git", "-C", str(root), "commit", "-m", "base"], env=self.environment, check=True, stdout=subprocess.PIPE)
        self.base = git(root, "rev-parse", "HEAD").stdout.decode().strip()
        self.expected = GATE.RepositoryBasis("test/repo", root.name, "origin", "git@example.invalid:test/repo.git", "refs/heads/main", "origin/main", self.base)
        self.ops = GATE.GitOps(environment=self.environment)

    def commit(self, message: str) -> str:
        git(self.repository, "add", "-A")
        process = subprocess.run(["git", "-C", str(self.repository), "commit", "-m", message], env=self.environment, check=True, stdout=subprocess.PIPE)
        return git(self.repository, "rev-parse", "HEAD").stdout.decode().strip()


def aterm_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def synthetic_derivation(
    output_path: str,
    input_drvs: list[str],
    *,
    algorithm: str = "",
    digest: str = "",
    environment: dict[str, str] | None = None,
    json_environment: dict[str, object] | None = None,
) -> bytes:
    outputs = f'[("out",{aterm_string(output_path)},{aterm_string(algorithm)},{aterm_string(digest)})]'
    inputs = "[" + ",".join(f'({aterm_string(path)},["out"])' for path in sorted(input_drvs)) + "]"
    bindings = {"out": output_path, **(environment or {})}
    if json_environment is not None:
        bindings["__json"] = json.dumps(json_environment, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    encoded_bindings = "[" + ",".join(f'({aterm_string(key)},{aterm_string(value)})' for key, value in sorted(bindings.items())) + "]"
    return f'Derive({outputs},{inputs},[],"x86_64-linux","/bin/false",[],{encoded_bindings})'.encode()


def computed_drv_path(raw: bytes, name: str) -> str:
    placeholder = f"/nix/store/{'0' * 32}-{name}"
    derivation = GATE.parse_derivation(raw, f"synthetic {name}")
    return GATE.derivation_store_path(raw, derivation, placeholder, f"synthetic {name}")


def derivation_record(schema: str, path: str, raw: bytes, source_paths: list[str]) -> bytes:
    return GATE.canonical_json({"captureTool": "nix derivation show", "derivationBase64": base64.b64encode(raw).decode(), "derivationPath": path, "derivationSha256": GATE.sha256(raw), "schema": schema, "sourceDerivationPaths": source_paths})


def real_drv_vector(fixture_path: str) -> bytes:
    expected_length, expected_sha256 = EXPECTED_DRV_VECTORS[fixture_path]
    raw = (DRV_VECTOR_ROOT / fixture_path).read_bytes()
    if len(raw) != expected_length or GATE.sha256(raw) != expected_sha256:
        raise AssertionError(f"real derivation vector identity mismatch: {fixture_path}")
    return raw


def drv_vector_document() -> dict[str, object]:
    document = GATE.parse_json((DRV_VECTOR_ROOT / "vectors.json").read_bytes(), "real derivation vector metadata")
    if not isinstance(document, dict):
        raise AssertionError("real derivation vector metadata is not an object")
    return document


TEST_PACKAGE_DRV = f"/nix/store/{'a' * 32}-package.drv"


def source_verification_artifact(
    raw: bytes,
    source_drv: str,
    source_output: str,
    urls: list[str],
    hash_value: str,
    semantics: str,
    *,
    tool_id: str = "git-host",
    original_package_drv: str = TEST_PACKAGE_DRV,
) -> tuple[dict[str, object], bytes]:
    claim: dict[str, object] = {"hashAlgorithm": "sha256", "hashSemantics": semantics, "hashValue": hash_value, "sourceDrv": source_drv, "sourceOutput": source_output, "urls": urls, "verificationRefId": "source", "verificationResult": "PASS"}
    verification = {"captureTool": "read-only local Nix store fixture", "derivationBase64": base64.b64encode(raw).decode(), "derivationSha256": GATE.sha256(raw), "hashAlgorithm": "sha256", "hashSemantics": semantics, "hashValue": hash_value, "originalPackageDrv": original_package_drv, "schema": "pkgre-d0-source-verification-v2", "sourceDrv": source_drv, "sourceOutput": source_output, "toolId": tool_id, "urls": urls, "verificationResult": "PASS"}
    return claim, GATE.canonical_json(verification)


def build_synthetic_b22_result(
    *,
    package_styles: dict[str, str] | None = None,
    source_counts: dict[str, int] | None = None,
    package_extra_inputs: dict[str, list[str]] | None = None,
    package_source_inputs: dict[str, bool] | None = None,
    source_json: dict[str, bool] | None = None,
) -> tuple[dict[str, object], dict[str, str], dict[str, str]]:
    package_styles = package_styles or {"git-host": "structured-src", "nix-host": "traditional-src"}
    source_counts = source_counts or {"git-host": 1, "nix-host": 1}
    package_extra_inputs = package_extra_inputs or {}
    package_source_inputs = package_source_inputs or {}
    source_json = source_json or {}
    references: dict[str, dict[str, object]] = {}
    package_ids: list[str] = []
    source_ids: list[str] = []
    tools: list[dict[str, object]] = []
    package_paths: dict[str, str] = {}
    source_paths: dict[str, str] = {}
    observed_outputs = dict(GATE.OBSERVED_OUTPUTS)
    package_names = {"git-host": "git-2.54.0.drv", "nix-host": "nix-2.34.8.drv"}
    for tool_index, tool_id in enumerate(("git-host", "nix-host"), 1):
        source_claims: list[dict[str, object]] = []
        source_drvs: list[str] = []
        source_outputs: list[str] = []
        for source_index in range(source_counts.get(tool_id, 1)):
            source_key = f"{tool_id}-{source_index}"
            semantics = "flat" if (tool_index + source_index) % 2 else "recursive"
            drv_algorithm = "sha256" if semantics == "flat" else "r:sha256"
            fixed_hash = bytes([tool_index * 16 + source_index + 1]) * 32
            fixed_hash_hex = fixed_hash.hex()
            fixed_sri = GATE.sri_from_drv_hash(fixed_hash_hex, "fixture")
            source_name = f"{tool_id}-source-{source_index}"
            output_placeholder = f"/nix/store/{'0' * 32}-{source_name}"
            source_output = GATE.fixed_output_store_path(fixed_hash_hex, semantics, output_placeholder, "fixture")
            urls = [f"https://example.invalid/{tool_id}/source-{source_index}.tar.gz"]
            source_json_environment = None
            source_environment: dict[str, str] = {}
            if source_json.get(source_key, True):
                source_json_environment = {"hash": fixed_sri, "outputHash": fixed_sri, "outputHashMode": semantics, "urls": urls}
            else:
                source_environment = {"outputHash": fixed_sri, "outputHashMode": semantics, "urls": " ".join(urls)}
            source_raw = synthetic_derivation(source_output, [], algorithm=drv_algorithm, digest=fixed_hash_hex, environment=source_environment, json_environment=source_json_environment)
            source_drv = computed_drv_path(source_raw, f"{source_name}.drv")
            source_id = f"source-{source_key}"
            source_ids.append(source_id)
            source_paths[source_key] = source_drv
            source_drvs.append(source_drv)
            source_outputs.append(source_output)
            source_claim = {"hashAlgorithm": "sha256", "hashSemantics": semantics, "hashValue": fixed_sri, "sourceDrv": source_drv, "sourceOutput": source_output, "urls": urls, "verificationRefId": source_id, "verificationResult": "PASS"}
            source_claims.append(source_claim)
            references[source_id] = {"raw": (source_raw, source_claim, tool_id)}
        style = package_styles[tool_id]
        package_environment: dict[str, str] = {}
        package_json_environment: dict[str, object] | None = None
        if style == "structured-src":
            if len(source_outputs) != 1:
                raise ValueError("structured-src requires exactly one source")
            package_json_environment = {"src": source_outputs[0]}
        elif style == "structured-srcs":
            package_json_environment = {"srcs": source_outputs}
        elif style == "traditional-src":
            if len(source_outputs) != 1:
                raise ValueError("traditional-src requires exactly one source")
            package_environment = {"src": source_outputs[0]}
        elif style == "traditional-srcs":
            package_environment = {"srcs": " ".join(source_outputs)}
        elif style != "none":
            raise ValueError(f"unknown package style: {style}")
        package_inputs = (source_drvs if package_source_inputs.get(tool_id, True) else []) + package_extra_inputs.get(tool_id, [])
        package_raw = synthetic_derivation(observed_outputs[tool_id], package_inputs, environment=package_environment, json_environment=package_json_environment)
        package_drv = computed_drv_path(package_raw, package_names[tool_id])
        package_paths[tool_id] = package_drv
        package_id = f"package-{tool_id}"
        package_ids.append(package_id)
        references[package_id] = {"raw": derivation_record("pkgre-d0-original-package-derivation-v2", package_drv, package_raw, source_drvs)}
        for source_claim in source_claims:
            source_id = source_claim["verificationRefId"]
            source_raw, _, _ = references[source_id]["raw"]
            verification = {"captureTool": "nix derivation show", "derivationBase64": base64.b64encode(source_raw).decode(), "derivationSha256": GATE.sha256(source_raw), "hashAlgorithm": source_claim["hashAlgorithm"], "hashSemantics": source_claim["hashSemantics"], "hashValue": source_claim["hashValue"], "originalPackageDrv": package_drv, "schema": "pkgre-d0-source-verification-v2", "sourceDrv": source_claim["sourceDrv"], "sourceOutput": source_claim["sourceOutput"], "toolId": tool_id, "urls": source_claim["urls"], "verificationResult": "PASS"}
            references[source_id] = {"raw": GATE.canonical_json(verification)}
        tools.append({"id": tool_id, "observedOutput": observed_outputs[tool_id], "originalPackageDrv": package_drv, "packageRecordRefId": package_id, "sourceDerivations": source_claims})
    result: dict[str, object] = {"claims": {"tools": tools}, "_evidenceByKind": {"original-derivation-records": package_ids, "source-verification": source_ids}, "_references": references}
    return result, package_paths, source_paths


def b22_result(**kwargs: object) -> tuple[dict[str, object], dict[str, str], dict[str, str]]:
    result, package_paths, source_paths = build_synthetic_b22_result(**kwargs)
    return result, package_paths, source_paths


def b22_waiver_result() -> dict[str, object]:
    claims: dict[str, object] = {
        "decisionId": "D0-B22-WAIVER-TEST",
        "scope": ["git-host", "nix-host"],
        "missingEvidence": ["exact original package derivation bytes"],
        "acceptedSubstitutes": ["retained source derivation fixtures"],
        "rationale": "test-only policy decision",
        "residualRisks": ["original package provenance remains unproved"],
        "approver": "independent-test-approver",
        "approvedAt": "2026-08-26T00:00:00Z",
        "policyVersion": "test-v1",
        "independentAcceptance": True,
    }
    raw = GATE.canonical_json({"schema": "pkgre-d0-b22-policy-waiver-v1", **claims})
    digest = GATE.sha256(raw)
    claims["decisionDocument"] = {"refId": "waiver-1", "sha256": digest}
    return {"_evidenceByKind": {"policy-waiver": ["waiver-1"]}, "_references": {"waiver-1": {"raw": raw, "sha256": digest}}, "claims": claims}


SEMANTIC_SOURCE_GENERATION = f"/nix/store/{'a' * 32}-nixos-system-rain-test"
SEMANTIC_ALT_GENERATION = f"/nix/store/{'b' * 32}-nixos-system-rain-other"
SEMANTIC_OBSERVED_AT = "2026-08-26T00:06:00Z"
SEMANTIC_RETURNED_AT = "2026-08-26T00:10:00Z"
SEMANTIC_OPERATOR = "pkgre-operator"
SEMANTIC_VERIFICATION_TIME = GATE.parse_utc(SEMANTIC_RETURNED_AT, "semantic verification time")
ALT_SSH_FINGERPRINT = "SHA256:+uZsRMJhsMrNNuIpWh9wzwU8B9w5T6TMpEsmT2eBxvA"


def semantic_file_metadata(
    path: str,
    purpose: str,
    *,
    owner: str = "root",
    group: str = "root",
    mode: str = "0600",
    size_bytes: int = 64,
    observed_at: str = SEMANTIC_OBSERVED_AT,
    source_generation: str = SEMANTIC_SOURCE_GENERATION,
    named_user_readers: list[str] | None = None,
) -> dict[str, object]:
    permissions_by_mode = {
        "0400": ["r--", "---", "---"],
        "0440": ["r--", "r--", "---"],
        "0444": ["r--", "r--", "r--"],
        "0600": ["rw-", "---", "---"],
        "0640": ["rw-", "r--", "---"],
        "0644": ["rw-", "r--", "r--"],
    }
    owner_permissions, group_mode_permissions, other_permissions = permissions_by_mode[mode]
    named_users = sorted(named_user_readers or [])
    group_permissions = "---" if named_users else group_mode_permissions
    acl: list[dict[str, object]] = [{"tag": "USER_OBJ", "qualifier": None, "permissions": owner_permissions, "effectivePermissions": owner_permissions}]
    acl.extend({"tag": "USER", "qualifier": name, "permissions": "r--", "effectivePermissions": "r--"} for name in named_users)
    acl.append({"tag": "GROUP_OBJ", "qualifier": None, "permissions": group_permissions, "effectivePermissions": group_permissions})
    if named_users:
        acl.append({"tag": "MASK", "qualifier": None, "permissions": group_mode_permissions, "effectivePermissions": group_mode_permissions})
    acl.append({"tag": "OTHER", "qualifier": None, "permissions": other_permissions, "effectivePermissions": other_permissions})
    readers = [f"user:{owner}"] if "r" in owner_permissions else []
    readers.extend(f"user:{name}" for name in named_users)
    if "r" in group_permissions:
        readers.append(f"group:{group}")
    if "r" in other_permissions:
        readers.append("other")
    metadata: dict[str, object] = {
        "path": path,
        "fileType": "REGULAR",
        "symlinkTarget": None,
        "owner": owner,
        "group": group,
        "mode": mode,
        "acl": acl,
        "aclComplete": True,
        "sizeBytes": size_bytes,
        "purpose": purpose,
        "readerMechanism": "POSIX_MODE_AND_ACCESS_ACL",
        "effectiveReaders": sorted(readers),
        "observedAt": observed_at,
        "sourceGeneration": source_generation,
    }
    collection_id = "metadata-" + path.strip("/").replace("/", "-").replace(".", "-")
    metadata["collection"] = {
        "collectionId": collection_id,
        "method": "METADATA_SYSCALLS_AND_ACCESS_ACL_ONLY",
        "collector": SEMANTIC_OPERATOR,
        "targetPath": path,
        "observedAt": observed_at,
        "returnedFields": list(GATE.FILE_METADATA_RETURNED_FIELDS),
        "contentAccess": {"opened": False, "read": False, "digested": False},
        "result": "PASS",
    }
    return metadata


def semantic_file_policy(metadata: dict[str, object], maximum_size_bytes: int = GATE.D0_CREDENTIAL_MAX_BYTES) -> dict[str, object]:
    return {
        "path": metadata["path"],
        "owner": metadata["owner"],
        "group": metadata["group"],
        "mode": metadata["mode"],
        "acl": copy.deepcopy(metadata["acl"]),
        "aclComplete": metadata["aclComplete"],
        "purpose": metadata["purpose"],
        "readerMechanism": metadata["readerMechanism"],
        "effectiveReaders": copy.deepcopy(metadata["effectiveReaders"]),
        "maximumSizeBytes": maximum_size_bytes,
    }


def semantic_procedure(identifier: str, operations: list[str], subject: dict[str, object], *, tested_at: str = "2026-08-26T00:05:00Z", mode: str = "TABLETOP") -> dict[str, object]:
    procedure_id = f"procedure-{identifier}"
    outcome = "nonproduction fixture matched the documented expected outcome"
    return {
        "procedureId": procedure_id,
        "owner": SEMANTIC_OPERATOR,
        "subject": copy.deepcopy(subject),
        "operations": list(operations),
        "test": {
            "eventId": f"procedure-test-{identifier}",
            "procedureId": procedure_id,
            "subject": copy.deepcopy(subject),
            "mode": mode,
            "fixture": {
                "fixtureId": f"fixture-{identifier}",
                "productionMaterialUsed": False,
                "replacementIdentity": {"type": "NONPRODUCTION_FIXTURE_ID", "value": f"replacement-{identifier}"},
            },
            "environment": {
                "kind": "DOCUMENTED_TABLETOP" if mode == "TABLETOP" else "ISOLATED_NONPRODUCTION",
                "name": "documented nonproduction tabletop" if mode == "TABLETOP" else "isolated nonproduction rehearsal",
                "productionEndpointUsed": False,
            },
            "testCase": {"caseId": f"case-{identifier}"},
            "actor": SEMANTIC_OPERATOR,
            "testedAt": tested_at,
            "operations": [{"operation": operation, "expectedOutcome": outcome, "observedOutcome": outcome, "result": "PASS"} for operation in operations],
            "result": "PASS",
        },
    }


def credential_subject(handle: dict[str, str]) -> dict[str, object]:
    return {"type": "CREDENTIAL_HANDLE", "handle": copy.deepcopy(handle)}


def valid_b01_payloads() -> dict[str, dict[str, object]]:
    credential = semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "GANDI_LIVEDNS_DNS01")
    old_credential = {"kind": "SAFE_SUFFIX", "value": "old1"}
    active_credential = {"kind": "SAFE_SUFFIX", "value": "new1"}
    containment: dict[str, object] = {
        "rotationId": "gandi-rotation-20260826",
        "credential": credential,
        "declarativePolicy": {
            "source": {"repositoryId": GATE.INFRA_REPOSITORY_ID, "commit": "5f68539bd99c6952b6d73fe2596c27ad4a319f57", "path": GATE.RAIN_PKGRE_MODULE_PATH},
            "deployedGeneration": SEMANTIC_SOURCE_GENERATION,
            "intendedMetadata": semantic_file_policy(credential),
        },
        "provider": {
            "identity": "GANDI_LIVEDNS",
            "oldCredential": old_credential,
            "activeCredential": active_credential,
            "zoneScopes": ["pkg.re"],
            "permissions": ["DNS_READ", "DNS_WRITE"],
            "expiry": "2027-08-26T00:00:00Z",
        },
        "events": {
            "permissionRepair": {"eventId": "gandi-permission-repair", "occurredAt": "2026-08-26T00:00:00Z", "actor": SEMANTIC_OPERATOR, "subject": {"type": "FILE_PATH", "path": credential["path"]}, "result": "PASS"},
            "newCredentialActivation": {"eventId": "gandi-new-activation", "occurredAt": "2026-08-26T00:01:00Z", "actor": SEMANTIC_OPERATOR, "subject": credential_subject(active_credential), "result": "PASS"},
            "oldCredentialRevocation": {"eventId": "gandi-old-revocation", "occurredAt": "2026-08-26T00:02:00Z", "actor": SEMANTIC_OPERATOR, "subject": credential_subject(old_credential), "result": "PASS"},
        },
        "installation": {
            "bindingId": "gandi-active-installation",
            "credentialPath": credential["path"],
            "sourceGeneration": SEMANTIC_SOURCE_GENERATION,
            "activeCredential": copy.deepcopy(active_credential),
            "activationEventId": "gandi-new-activation",
            "dns01Operation": {
                "operationId": "gandi-dns01-operation",
                "providerIdentity": "GANDI_LIVEDNS",
                "zone": "pkg.re",
                "certificateName": "js.pkg.re",
                "operation": "DNS01_CHALLENGE_UPDATE",
                "occurredAt": "2026-08-26T00:01:30Z",
                "result": "PASS",
            },
            "boundAt": "2026-08-26T00:01:45Z",
            "result": "PASS",
        },
        "audit": [
            {"auditId": "gandi-audit-scope", "occurredAt": "2026-08-26T00:03:00Z", "actor": SEMANTIC_OPERATOR, "check": "SCOPE", "credential": copy.deepcopy(active_credential), "result": "PASS"},
            {"auditId": "gandi-audit-activity", "occurredAt": "2026-08-26T00:04:00Z", "actor": SEMANTIC_OPERATOR, "check": "RECENT_ACTIVITY", "credential": copy.deepcopy(active_credential), "result": "PASS"},
            {"auditId": "gandi-audit-revocation", "occurredAt": "2026-08-26T00:05:00Z", "actor": SEMANTIC_OPERATOR, "check": "REVOCATION", "credential": copy.deepcopy(old_credential), "result": "PASS"},
        ],
        "secretMaterial": {"credentialValueRead": False, "credentialDigestRecorded": False},
    }
    files: list[dict[str, object]] = []
    for name in GATE.ACME_NAMES:
        files.append({"id": f"{name}-certificate", "metadata": semantic_file_metadata(f"/var/lib/acme/{name}/fullchain.pem", "TLS_CERTIFICATE", owner="acme", group="nginx", mode="0644", size_bytes=2048)})
    for name in GATE.ACME_NAMES:
        files.append({"id": f"{name}-private-key", "metadata": semantic_file_metadata(f"/var/lib/acme/{name}/key.pem", "TLS_PRIVATE_KEY", owner="acme", group="nginx", mode="0640", size_bytes=227)})
    files.append({"id": "acme-account-key", "metadata": semantic_file_metadata("/var/lib/acme/account/private-key.pem", "ACME_ACCOUNT_KEY", size_bytes=227)})
    lifecycle: dict[str, object] = {
        "rotationId": containment["rotationId"],
        "providerIdentity": "GANDI_LIVEDNS",
        "activeCredential": copy.deepcopy(active_credential),
        "observedAt": SEMANTIC_OBSERVED_AT,
        "sourceGeneration": SEMANTIC_SOURCE_GENERATION,
        "files": files,
        "patProcedures": {key: semantic_procedure(f"pat-{key}", operations, {"type": "PROVIDER_CREDENTIAL", "providerIdentity": "GANDI_LIVEDNS", "credential": active_credential}) for key, operations in GATE.PAT_PROCEDURE_OPERATIONS.items()},
        "lifecycles": [],
        "secretMaterial": {"privateKeyValueRead": False, "privateKeyDigestRecorded": False},
    }
    for subject in [*GATE.ACME_NAMES, "ACME_ACCOUNT_KEY"]:
        slug = subject.lower().replace(".", "-").replace("_", "-")
        if subject == "ACME_ACCOUNT_KEY":
            procedure_subject = {"type": "ACME_ACCOUNT_KEY", "providerIdentity": "GANDI_LIVEDNS", "path": "/var/lib/acme/account/private-key.pem"}
        else:
            procedure_subject = {"type": "ACME_CERTIFICATE_KEY_PAIR", "name": subject, "certificatePath": f"/var/lib/acme/{subject}/fullchain.pem", "privateKeyPath": f"/var/lib/acme/{subject}/key.pem"}
        lifecycle["lifecycles"].append({
            "subject": subject,
            "rotationOverlapSeconds": 300,
            **{key: semantic_procedure(f"{slug}-{key}", operations, procedure_subject) for key, operations in GATE.KEY_LIFECYCLE_OPERATIONS.items()},
        })
    return {"credential-containment": containment, "credential-lifecycle": lifecycle}


def valid_b02_payloads() -> dict[str, dict[str, object]]:
    attestation: dict[str, object] = {
        "hostname": GATE.RAIN_SSH_HOST,
        "port": 22,
        "algorithm": "ssh-ed25519",
        "fingerprint": GATE.RAIN_SSH_FINGERPRINT,
        "authoritativeSource": {
            "type": "PROVIDER_SERIAL_CONSOLE",
            "sourceId": "rain-provider-serial-console-20260826",
            "method": "READ_PUBLIC_HOST_KEY_VIA_PROVIDER_SERIAL_CONSOLE",
            "operator": SEMANTIC_OPERATOR,
            "observedAt": "2026-08-26T00:04:00Z",
            "recordKind": "PUBLIC_SSH_HOST_KEY_FINGERPRINT",
            "hostname": GATE.RAIN_SSH_HOST,
            "algorithm": "ssh-ed25519",
            "fingerprint": GATE.RAIN_SSH_FINGERPRINT,
            "observedSshConnectionUsed": False,
        },
        "endpointObservation": {
            "observationId": "rain-public-keyscan-20260826",
            "hostname": GATE.RAIN_SSH_HOST,
            "port": 22,
            "algorithm": "ssh-ed25519",
            "fingerprint": GATE.RAIN_SSH_FINGERPRINT,
            "observedAt": "2026-08-26T00:04:30Z",
            "method": "PUBLIC_SSH_HOST_KEY_SCAN",
            "tool": {"name": "ssh-keyscan", "version": "OpenSSH_test", "networkPath": "PUBLIC_NETWORK_ENDPOINT"},
            "result": "PASS",
        },
        "attestation": {"eventId": "rain-ssh-attestation", "operator": SEMANTIC_OPERATOR, "verifiedAt": "2026-08-26T00:05:00Z", "match": True},
        "secretMaterial": {"privateKeyValueRead": False, "privateKeyDigestRecorded": False},
    }
    ssh_subject = {"type": "SSH_HOST_IDENTITY", "hostname": GATE.RAIN_SSH_HOST, "algorithm": "ssh-ed25519", "fingerprint": GATE.RAIN_SSH_FINGERPRINT}
    lifecycle: dict[str, object] = {
        "hostname": GATE.RAIN_SSH_HOST,
        "algorithm": "ssh-ed25519",
        "currentFingerprint": GATE.RAIN_SSH_FINGERPRINT,
        "rotationOverlapSeconds": 300,
        **{key: semantic_procedure(f"rain-ssh-{key}", operations, ssh_subject) for key, operations in GATE.SSH_LIFECYCLE_OPERATIONS.items()},
    }
    return {"ssh-attestation": attestation, "ssh-lifecycle": lifecycle}


B03_CATALOGS = [
    {"catalogId": "rust", "repository": "pkgre/rust", "runtimeOrigin": "https://github.com/pkgre/rust.git", "reviewer": "rust-reviewer", "dispatcher": "rust-dispatcher"},
    {"catalogId": "js", "repository": "pkgre/js", "runtimeOrigin": "https://github.com/pkgre/js.git", "reviewer": "js-reviewer", "dispatcher": "js-dispatcher"},
]


def b03_content_digest(catalog_id: str, kind: str) -> str:
    return GATE.sha256(f"synthetic-b03-{catalog_id}-{kind}-content-v1".encode())


def valid_b03_payloads() -> dict[str, dict[str, object]]:
    bases = {row.id: row.reviewed_commit for row in GATE.PRODUCTION_REPOSITORIES}
    catalogs = [
        GATE.expected_github_catalog(
            specification["catalogId"],
            specification["repository"],
            GATE.GITHUB_REPOSITORY_IDS[specification["repository"]],
            specification["runtimeOrigin"],
            bases[specification["repository"]],
            specification["reviewer"],
            specification["dispatcher"],
            b03_content_digest(specification["catalogId"], "candidate-workflow"),
            b03_content_digest(specification["catalogId"], "release-workflow"),
            b03_content_digest(specification["catalogId"], "pages-workflow"),
            b03_content_digest(specification["catalogId"], "codeowners"),
        )
        for specification in B03_CATALOGS
    ]
    payload = {
        "designId": "pkgre-public-catalog-github-governance-v1",
        "operatorDecision": {"returnedBy": SEMANTIC_OPERATOR, "returnedAt": SEMANTIC_RETURNED_AT, "scope": "D2_GITHUB_TARGET_DESIGN_NO_SETTINGS_ACTION"},
        "baseline": {
            "path": GATE.GITHUB_GOVERNANCE_BASELINE_PATH,
            "sha256": GATE.GITHUB_GOVERNANCE_BASELINE_SHA256,
            "catalogConformance": [{"catalogId": "rust", "targetConforming": False}, {"catalogId": "js", "targetConforming": False}],
            "auditLogAvailable": False,
        },
        "catalogs": catalogs,
        "crossCatalogSeparation": {"workflowPathsDistinct": True, "workflowNamesDistinct": True, "checkContextsDistinct": True, "environmentsDistinct": True, "writerAppsDistinct": True, "rulesetNamesDistinct": True, "providerEvidenceKeysDistinct": True, "writerTokensRepositoryScoped": True},
        "d0Mutation": {"githubSettingsChanged": False, "writerCredentialInstalled": False, "signerInstalled": False, "catalogRefAdvanced": False},
        "result": "APPROVED_TARGET_DESIGN",
    }
    return {"github-governance-proof": payload}


def b03_catalog(payloads: dict[str, dict[str, object]], index: int = 0) -> dict[str, object]:
    return payloads["github-governance-proof"]["catalogs"][index]


def b03_operation(catalog: dict[str, object], operation_id: str, kind: str = "restOperations") -> dict[str, object]:
    matches = [operation for operation in catalog["providerContract"][kind] if operation["operationId"] == operation_id]
    if len(matches) != 1:
        raise AssertionError(f"expected exact operation {operation_id!r}")
    return matches[0]


def b03_transition(catalog: dict[str, object], target_state: str) -> dict[str, object]:
    matches = [transition for transition in catalog["providerContract"]["bootstrapStateMachine"]["transitions"] if transition["to"] == target_state]
    if len(matches) != 1:
        raise AssertionError(f"expected exact transition to {target_state!r}")
    return matches[0]


def b03_rollback(catalog: dict[str, object]) -> dict[str, object]:
    return catalog["providerContract"]["bootstrapStateMachine"]["rollback"]


def b03_rollback_step(catalog: dict[str, object], section: str, action: str) -> dict[str, object]:
    matches = [step for step in b03_rollback(catalog)[section] if step["action"] == action]
    if len(matches) != 1:
        raise AssertionError(f"expected exact rollback step {action!r}")
    return matches[0]


def b03_auxiliary_binding(catalog: dict[str, object], name: str) -> dict[str, object]:
    matches = [binding for binding in b03_rollback(catalog)["auxiliaryBindingRegistry"] if binding["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected exact rollback auxiliary binding {name!r}")
    return matches[0]


def b03_conditional_group(step: dict[str, object], execute_when: str) -> dict[str, object]:
    matches = [group for group in step["conditionalOperationGroups"] if group["executeWhen"] == execute_when]
    if len(matches) != 1:
        raise AssertionError(f"expected exact rollback conditional group {execute_when!r}")
    return matches[0]


def b03_typed_binding(catalog: dict[str, object], name: str) -> dict[str, object]:
    matches = [binding for binding in catalog["providerContract"]["typedBindings"] if binding["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected exact provider typed binding {name!r}")
    return matches[0]


def b03_authentication_profile(catalog: dict[str, object], profile_id: str) -> dict[str, object]:
    matches = [profile for profile in catalog["providerContract"]["authenticationProfiles"] if profile["profileId"] == profile_id]
    if len(matches) != 1:
        raise AssertionError(f"expected exact provider authentication profile {profile_id!r}")
    return matches[0]


def valid_phase_amendment(finding_id: str, *, amendment_id: str | None = None) -> dict[str, object]:
    target_gates = GATE.REPHASE_TARGETS[finding_id]
    return {
        "amendmentId": amendment_id or f"amendment-{finding_id.lower()}",
        "decision": "APPROVE_EXACT_REPHASE",
        "findingId": finding_id,
        "currentEvidenceSatisfied": False,
        "d0WorkAuthorized": False,
        "targetGates": list(target_gates),
        "deferredRequirements": [{"gateId": gate_id, "requirement": GATE.LATER_GATES_BY_ID[gate_id]["requirement"]} for gate_id in target_gates],
        "operatorDecision": {"returnedBy": SEMANTIC_OPERATOR, "returnedAt": SEMANTIC_RETURNED_AT},
        "rationale": "The named proof remains unsatisfied and is explicitly moved to the exact later gates.",
        "residualRisks": ["The deferred requirement remains blocking at every named later gate."],
        "result": "APPROVED",
    }


class GateCoreTests(unittest.TestCase):
    def assertRejected(self, callable_object, text: str) -> None:
        with self.assertRaises(GATE.GateVerificationError) as caught:
            callable_object()
        self.assertIn(text, str(caught.exception))

    def validateB22(self, result: dict[str, object], package_paths: dict[str, str]) -> None:
        with mock.patch.object(GATE, "ORIGINAL_PACKAGE_DRVS", package_paths):
            GATE.validate_b22("SATISFIED", "ORIGINAL_DERIVATION_PROOF", [result])

    def validateSemanticPayloads(self, finding_id: str, handoff_id: str, payloads: dict[str, dict[str, object]]) -> None:
        result = self.semanticResult(finding_id, handoff_id, payloads)
        GATE.validate_generic_policy(finding_id, "SATISFIED", "EVIDENCE_SATISFIED", [result], SEMANTIC_VERIFICATION_TIME)

    def assertSemanticPayloadsRejected(self, finding_id: str, handoff_id: str, payloads: dict[str, dict[str, object]], text: str) -> None:
        self.assertRejected(lambda: self.validateSemanticPayloads(finding_id, handoff_id, payloads), text)

    def assertB22Rejected(self, result: dict[str, object], package_paths: dict[str, str], text: str) -> None:
        self.assertRejected(lambda: self.validateB22(result, package_paths), text)

    def assertB03MutationRejected(self, mutate, text: str = "frozen value mismatch") -> None:
        payloads = valid_b03_payloads()
        mutate(b03_catalog(payloads))
        self.assertSemanticPayloadsRejected("D0-B03", "OP-D0-05", payloads, text)

    def temporary_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], RepositoryFixture]:
        temporary = tempfile.TemporaryDirectory(prefix="pkgre-d0-gate-test-")
        return temporary, RepositoryFixture(Path(temporary.name))

    def finish_linear_history(self, fixture: RepositoryFixture) -> tuple[str, str]:
        write(fixture.repository, "evidence/d0-closure/set/proof.json", b"{}\n")
        evidence = fixture.commit("evidence")
        write(fixture.repository, GATE.GATE_STATE_PATH, b"{}\n")
        state = fixture.commit("state")
        return evidence, state

    def test_strict_semantic_primitives(self) -> None:
        self.assertTrue(GATE.strict_bool(True, "bool"))
        self.assertRejected(lambda: GATE.strict_bool(1, "bool"), "expected boolean")
        self.assertEqual(GATE.bounded_integer(GATE.MAX_SEMANTIC_INTEGER, "integer"), GATE.MAX_SEMANTIC_INTEGER)
        self.assertRejected(lambda: GATE.bounded_integer(True, "integer"), "expected integer")
        self.assertRejected(lambda: GATE.bounded_integer(-1, "integer"), "expected integer")
        self.assertEqual(GATE.checked_add([GATE.MAX_SEMANTIC_INTEGER - 1, 1], "sum"), GATE.MAX_SEMANTIC_INTEGER)
        self.assertRejected(lambda: GATE.checked_add([GATE.MAX_SEMANTIC_INTEGER, 1], "sum"), "addition exceeds")
        self.assertEqual(GATE.checked_multiply([3, 7], "product"), 21)
        self.assertRejected(lambda: GATE.checked_multiply([GATE.MAX_SEMANTIC_INTEGER, 2], "product"), "multiplication exceeds")
        self.assertEqual(GATE.semver("2.9.5", "version"), "2.9.5")
        self.assertRejected(lambda: GATE.semver("02.9.5", "version"), "canonical semantic version")
        fingerprint = "SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI"
        self.assertEqual(GATE.ssh_sha256_fingerprint(fingerprint, "fingerprint"), fingerprint)
        self.assertRejected(lambda: GATE.ssh_sha256_fingerprint(fingerprint + "=", "fingerprint"), "invalid SSH")
        self.assertEqual(GATE.absolute_path("/var/lib/pkgre/state", "path"), "/var/lib/pkgre/state")
        self.assertRejected(lambda: GATE.absolute_path("/var/lib/../secret", "path"), "noncanonical")
        self.assertRejected(lambda: GATE.absolute_path("/", "path"), "non-root canonical")
        self.assertRejected(lambda: GATE.utc_text("2026-02-30T00:00:00Z", "utc"), "invalid UTC calendar")
        self.assertEqual(GATE.dns_name("rain.pacna.org", "host"), "rain.pacna.org")
        self.assertRejected(lambda: GATE.dns_name("Rain.pacna.org", "host"), "lower-case")
        self.assertEqual(GATE.ip_address("10.131.7.4", "address"), "10.131.7.4")
        self.assertEqual(GATE.ip_network("10.131.7.1/32", "network"), "10.131.7.1/32")
        self.assertRejected(lambda: GATE.ip_network("10.131.7.1/24", "network"), "invalid canonical")
        self.assertEqual(GATE.tcp_port(9010, "port"), 9010)
        self.assertRejected(lambda: GATE.tcp_port(0, "port"), "expected integer")
        self.assertEqual(GATE.unix_mode("0640", "mode"), "0640")
        self.assertRejected(lambda: GATE.unix_mode("640", "mode"), "four-digit octal")
        self.assertEqual(GATE.unique_strings(["a", "b"], "strings", canonical_order=True), ["a", "b"])
        self.assertRejected(lambda: GATE.unique_strings(["a", "a"], "strings"), "duplicate string")

    def test_strict_json_and_paths(self) -> None:
        self.assertRejected(lambda: GATE.parse_json(b'{"x":1,"x":2}\n', "duplicate"), "duplicate JSON object key")
        self.assertRejected(lambda: GATE.parse_json(b'{"x":"\\ud800"}\n', "surrogate"), "invalid Unicode scalar value")
        self.assertRejected(lambda: GATE.safe_path("evidence/d0-closure/../x", "path"), "noncanonical")
        self.assertRejected(lambda: GATE.safe_path("evidence/d0-closureevil/x", "path", "evidence/d0-closure/"), "strictly under")
        self.assertRejected(lambda: GATE.safe_path("evidence/d0-closure/x y", "path"), "unsupported path component")
        self.assertEqual(GATE.decode_bounded_base64("YQ==", "base64", max_decoded=1), b"a")
        self.assertRejected(lambda: GATE.decode_bounded_base64("YR==", "base64", max_decoded=1), "base64 is not canonical")
        self.assertRejected(lambda: GATE.decode_bounded_base64("YQ===", "base64", max_decoded=4), "invalid base64")
        self.assertRejected(lambda: GATE.decode_bounded_base64("YQ==\n", "base64", max_decoded=2), "trimmed string")
        self.assertRejected(lambda: GATE.decode_bounded_base64("YWI=", "base64", max_decoded=1), "decoded content exceeds")

    def semanticResult(self, finding_id: str, handoff_id: str, payloads: dict[str, dict[str, object]], *, disposition: str = "SATISFIED", target_gates: list[str] | None = None) -> dict[str, object]:
        evidence_by_kind: dict[str, list[str]] = {}
        references: dict[str, dict[str, object]] = {}
        for index, (kind, payload) in enumerate(payloads.items(), 1):
            ref_id = f"semantic-{index}"
            schema = GATE.PHASE_AMENDMENT_SCHEMA if kind == "phase-amendment" else GATE.SEMANTIC_EVIDENCE_SCHEMA
            raw = GATE.canonical_json({"schema": schema, "findingId": finding_id, "kind": kind, "payload": payload})
            evidence_by_kind[kind] = [ref_id]
            references[ref_id] = {"raw": raw, "sha256": GATE.sha256(raw)}
        return {"_handoffId": handoff_id, "_operatorReturnedBy": SEMANTIC_OPERATOR, "_operatorReturnedAt": SEMANTIC_RETURNED_AT, "_evidenceByKind": evidence_by_kind, "_references": references, "claims": {"evidenceByKind": evidence_by_kind, "targetGates": [] if target_gates is None else target_gates}}

    def test_b01_and_b02_accept_exact_semantic_proof(self) -> None:
        self.validateSemanticPayloads("D0-B01", "OP-D0-01", valid_b01_payloads())
        payloads = valid_b01_payloads()
        payloads["credential-containment"]["provider"]["expiry"] = "NO_EXPIRY"
        self.validateSemanticPayloads("D0-B01", "OP-D0-01", payloads)
        self.validateSemanticPayloads("D0-B02", "OP-D0-02", valid_b02_payloads())

    def test_b03_accepts_exact_semantic_target_design(self) -> None:
        self.validateSemanticPayloads("D0-B03", "OP-D0-05", valid_b03_payloads())

    def test_b03_rejects_weakened_http_openapi_capture_and_projection_contract(self) -> None:
        def omit_api_version(catalog):
            b03_operation(catalog, "get-repository")["request"]["headers"].pop("X-GitHub-Api-Version")

        cases = [
            ("api-version-omitted", omit_api_version, "object-key mismatch"),
            ("api-version-changed", lambda catalog: catalog["providerContract"]["http"].__setitem__("apiVersion", "2022-11-28"), "frozen value mismatch"),
            ("openapi-commit", lambda catalog: catalog["providerContract"]["openApi"].__setitem__("commit", "0" * 40), "frozen value mismatch"),
            ("openapi-digest", lambda catalog: catalog["providerContract"]["openApi"].__setitem__("sha256", "0" * 64), "frozen value mismatch"),
            ("redirects", lambda catalog: catalog["providerContract"]["http"].__setitem__("redirectsAllowed", True), "frozen value mismatch"),
            ("request-id", lambda catalog: catalog["providerContract"]["http"].__setitem__("providerRequestIdRequired", False), "frozen value mismatch"),
            ("raw-body-digest", lambda catalog: b03_operation(catalog, "get-repository")["response"]["capture"].__setitem__("rawBodySha256Required", False), "frozen value mismatch"),
            ("projection-digest", lambda catalog: b03_operation(catalog, "get-repository")["response"]["capture"].__setitem__("projectionSha256Required", False), "frozen value mismatch"),
            ("pagination", lambda catalog: b03_operation(catalog, "list-rulesets")["response"]["pagination"].__setitem__("allPagesRequired", False), "frozen value mismatch"),
            ("ambiguous-selection", lambda catalog: catalog["providerContract"]["projectionPolicy"]["reject"].__setitem__(5, "AMBIGUOUS_RESOURCE_ALLOWED"), "frozen value mismatch"),
            ("raw-additions-not-isolated", lambda catalog: catalog["providerContract"]["projectionPolicy"].__setitem__("rawProviderAdditiveFields", "ALWAYS_REJECT"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_nonexact_github_requests_broadened_authority_and_id_confusion(self) -> None:
        def fake_environment_admin_field(catalog):
            b03_operation(catalog, "put-release-environment")["request"]["body"]["template"]["can_admins_bypass"] = False

        def wildcard_action(catalog):
            catalog["actions"]["selectedPolicy"]["patternsAllowed"][0] = "actions/checkout@v4"

        def broaden_writer_token(catalog):
            b03_operation(catalog, "mint-release-installation-token-after-approval")["request"]["body"]["template"]["permissions"]["issues"] = "write"

        cases = [
            ("fake-environment-admin-rest-field", fake_environment_admin_field, "object-key mismatch"),
            ("selected-action-tag", wildcard_action, "frozen value mismatch"),
            ("wrong-invariant-rule", lambda catalog: catalog["rulesets"]["invariants"]["providerCreateRequestBody"]["rules"][1].__setitem__("type", "creation"), "frozen value mismatch"),
            ("app-installation-id-as-integration-id", lambda catalog: catalog["rulesets"]["admission"]["providerCreateRequestBody"]["bypass_actors"][0]["actor_id"].__setitem__("$binding", "releaseAppInstallationId"), "frozen value mismatch"),
            ("check-id-as-app-id", lambda catalog: catalog["writer"]["appIntegrationIdBinding"].__setitem__("$binding", "candidateCheckIntegrationId"), "frozen value mismatch"),
            ("user-bypass", lambda catalog: catalog["rulesets"]["admission"]["providerCreateRequestBody"]["bypass_actors"][0].__setitem__("actor_type", "User"), "frozen value mismatch"),
            ("repository-role-bypass", lambda catalog: catalog["rulesets"]["admission"]["providerCreateRequestBody"]["bypass_actors"][0].__setitem__("actor_type", "RepositoryRole"), "frozen value mismatch"),
            ("writer-permission-broadened", broaden_writer_token, "object-key mismatch"),
            ("team-reviewer", lambda catalog: catalog["environment"]["providerCreateOrUpdateRequestBody"]["reviewers"][0].__setitem__("type", "Team"), "frozen value mismatch"),
            ("self-review", lambda catalog: b03_operation(catalog, "put-release-environment")["request"]["body"]["template"].__setitem__("prevent_self_review", False), "frozen value mismatch"),
            ("bootstrap-force", lambda catalog: b03_operation(catalog, "patch-main-ref-bootstrap-force-false")["request"]["body"]["template"].__setitem__("force", True), "frozen value mismatch"),
            ("release-force", lambda catalog: b03_operation(catalog, "patch-main-ref-release-force-false")["request"]["body"]["template"].__setitem__("force", True), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_fork_pr_approval_policy_uses_least_restrictive_pinned_enum_and_records_limitations(self) -> None:
        payloads = valid_b03_payloads()
        expected_semantics = {
            "goal": "AUTOMATIC_UNTRUSTED_READ_ONLY_FORK_VALIDATION_WHERE_PROVIDER_PERMITS",
            "leastRestrictivePinnedOpenApiEnum": True,
            "neverRequireApprovalEnumAvailable": False,
            "newGitHubAccountsMayStillRequireMaintainerApproval": True,
            "providerAntiAbuseBehaviorNotTrustAuthorization": True,
        }
        for catalog in payloads["github-governance-proof"]["catalogs"]:
            with self.subTest(catalogId=catalog["catalogId"]):
                actions = catalog["actions"]
                self.assertEqual(actions["forkPullRequestApprovalPolicy"], GATE.GITHUB_FORK_PR_APPROVAL_POLICY)
                self.assertEqual(actions["forkPullRequestApprovalSemantics"], expected_semantics)
                self.assertEqual(actions["providerRequestBodies"]["forkPullRequestApproval"], {"approval_policy": "first_time_contributors_new_to_github"})
                self.assertEqual(b03_operation(catalog, "set-fork-pr-approval-policy")["request"]["body"]["template"], {"approval_policy": "first_time_contributors_new_to_github"})
        cases = [
            ("broader-policy", lambda catalog: catalog["actions"].__setitem__("forkPullRequestApprovalPolicy", "all_external_contributors")),
            ("broader-operation-body", lambda catalog: b03_operation(catalog, "set-fork-pr-approval-policy")["request"]["body"]["template"].__setitem__("approval_policy", "all_external_contributors")),
            ("invent-never-require-approval-enum", lambda catalog: catalog["actions"]["forkPullRequestApprovalSemantics"].__setitem__("neverRequireApprovalEnumAvailable", True)),
            ("erase-new-account-provider-limit", lambda catalog: catalog["actions"]["forkPullRequestApprovalSemantics"].__setitem__("newGitHubAccountsMayStillRequireMaintainerApproval", False)),
            ("treat-provider-anti-abuse-as-trust", lambda catalog: catalog["actions"]["forkPullRequestApprovalSemantics"].__setitem__("providerAntiAbuseBehaviorNotTrustAuthorization", False)),
        ]
        for name, mutate in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate)

        def omit_local_bootstrap_verification(catalog):
            b03_transition(catalog, "S4_INVARIANT_AND_BOOTSTRAP_ADMISSION_ACTIVE")["preconditions"].remove("B_REMAINS_DUAL_VERIFIED")

        def mint_before_approval(catalog):
            operations = b03_transition(catalog, "S10_FIRST_NORMAL_RELEASE_C_SUCCEEDED")["operations"]
            mint = operations.pop(operations.index("mint-release-installation-token-after-approval"))
            operations.insert(operations.index("review-release-pending-deployment"), mint)

        def omit_signed_release_creation(catalog):
            b03_transition(catalog, "S10_FIRST_NORMAL_RELEASE_C_SUCCEEDED")["operations"].remove("trusted-release-job-create-ssh-ed25519-signed-c-prime")

        cases = [
            ("bootstrap-parent-not-a", lambda catalog: catalog["providerContract"]["bootstrapStateMachine"]["bootstrapB"].__setitem__("soleParent", "CANDIDATE_HEAD"), "frozen value mismatch"),
            ("workflow-authorizes-own-introduction", lambda catalog: catalog["providerContract"]["bootstrapStateMachine"]["bootstrapB"].__setitem__("candidateWorkflowMayAuthorizeOwnIntroduction", True), "frozen value mismatch"),
            ("trusted-workflow-not-b", lambda catalog: catalog["providerContract"]["bootstrapStateMachine"]["firstNormalRelease"].__setitem__("trustedWorkflowCommit", "C0_CANDIDATE"), "frozen value mismatch"),
            ("release-parent-not-b", lambda catalog: catalog["providerContract"]["bootstrapStateMachine"]["firstNormalRelease"].__setitem__("signedReleaseCommit", "C_PRIME_TREE_EQUALS_C0_SOLE_PARENT_C0"), "frozen value mismatch"),
            ("bootstrap-local-verification-omitted", omit_local_bootstrap_verification, "expected exactly"),
            ("token-minted-before-human-approval", mint_before_approval, "frozen value mismatch"),
            ("signed-release-creation-omitted", omit_signed_release_creation, "expected exactly"),
            ("candidate-workflow-used-as-release", lambda catalog: b03_operation(catalog, "dispatch-release-workflow-on-main")["request"].__setitem__("pathTemplate", "/repos/pkgre/rust/actions/workflows/$binding:candidateWorkflowId/dispatches"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_history_rewrite_incomplete_rollback_secret_leak_and_self_attestation(self) -> None:
        def reset_main_after_advance(catalog):
            step = catalog["providerContract"]["bootstrapStateMachine"]["rollback"]["afterMainAdvance"][4]
            step["action"] = "RESET_MAIN_TO_BASELINE_A"

        def omit_secret_cleanup(catalog):
            catalog["providerContract"]["bootstrapStateMachine"]["rollback"]["afterMainAdvance"].pop(2)

        def permit_secret_digest(catalog):
            b03_operation(catalog, "operator-remove-environment-secret", "nonRestOperations")["forbiddenCapture"].remove("SECRET_DIGEST")

        cases = [
            ("post-advance-reset", reset_main_after_advance, "frozen value mismatch"),
            ("history-rewrite-no-longer-forbidden", lambda catalog: catalog["providerContract"]["bootstrapStateMachine"]["rollback"]["forbidden"].__setitem__(1, "RESET_MAIN_TO_A_ALLOWED"), "frozen value mismatch"),
            ("secret-cleanup-omitted", omit_secret_cleanup, "expected exactly"),
            ("secret-digest-permitted", permit_secret_digest, "expected exactly"),
            ("audit-self-attestation", lambda catalog: catalog["providerContract"]["proceduralReadbacks"][2].__setitem__("operatorSelfAttestationAllowed", True), "frozen value mismatch"),
            ("audit-source-replaced", lambda catalog: b03_operation(catalog, "capture-provider-ui-audit-export", "nonRestOperations").__setitem__("channel", "OPERATOR_SELF_ATTESTATION"), "frozen value mismatch"),
            ("admin-bypass-self-attestation", lambda catalog: catalog["environment"]["proceduralReadback"].__setitem__("operatorSelfAttestationAllowed", True), "frozen value mismatch"),
            ("post-advance-postcondition-reset", lambda catalog: catalog["rollback"].__setitem__("postAdvancePostcondition", "RESET_MAIN_TO_A"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_unsafe_classic_protection_handover(self) -> None:
        def move_classic_removal_before_replacement_readbacks(catalog):
            transition = b03_transition(catalog, "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE")
            operation = transition["operations"].pop(transition["operations"].index("delete-classic-branch-protection-if-baseline-present"))
            transition["operations"].insert(0, operation)

        def add_operation_before_handover_completes(operation_id: str):
            def mutate(catalog):
                b03_transition(catalog, "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE")["operations"].append(operation_id)
            return mutate

        handover = lambda catalog: b03_transition(catalog, "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE")["handoverSafety"]
        cases = [
            ("ref-advance-during-transition", lambda catalog: handover(catalog).__setitem__("refAdvanceAllowedDuringTransition", True), "frozen value mismatch"),
            ("token-mint-during-transition", lambda catalog: handover(catalog).__setitem__("tokenMintAllowedDuringTransition", True), "frozen value mismatch"),
            ("guard-gap", lambda catalog: handover(catalog).__setitem__("guardGapAllowed", True), "frozen value mismatch"),
            ("single-sided-readback", lambda catalog: handover(catalog).__setitem__("beforeAndAfterReplacementControlReadbackRequired", False), "frozen value mismatch"),
            ("missing-pre-removal-readback", lambda catalog: handover(catalog)["preRemovalReadbackOperationIds"].pop(), "expected exactly"),
            ("reordered-post-removal-readback", lambda catalog: handover(catalog)["postRemovalReadbackOperationIds"].reverse(), "frozen value mismatch"),
            ("removal-before-replacement-readbacks", move_classic_removal_before_replacement_readbacks, "frozen value mismatch"),
            ("mint-before-s5-complete", add_operation_before_handover_completes("mint-bootstrap-installation-token"), "expected exactly"),
            ("ref-advance-before-s5-complete", add_operation_before_handover_completes("patch-main-ref-bootstrap-force-false"), "expected exactly"),
            ("failure-continues", lambda catalog: handover(catalog).__setitem__("failureDisposition", "CONTINUE_WITHOUT_REPLACEMENT_CONTROLS"), "frozen value mismatch"),
            ("replacement-loss-not-abort", lambda catalog: b03_transition(catalog, "S5_CLASSIC_PROTECTION_TRANSITION_COMPLETE")["abortConditions"].remove("REPLACEMENT_RULE_LOST"), "expected exactly"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_unsafe_rollback_ref_classification_and_coverage(self) -> None:
        def ref_classification(catalog):
            return b03_rollback(catalog)["refClassification"]

        def route_unknown_as_ordinary(catalog):
            ref_classification(catalog)["outcomes"][3]["route"] = "beforeMainAdvance"

        def treat_unreadable_as_a(catalog):
            outcome = ref_classification(catalog)["outcomes"][0]
            outcome["requirements"] = ["REF_ABSENT_OR_UNREADABLE_OR_OID_EQUALS_FRESH_BASELINE_A"]

        def add_post_advance_ref_mutation(catalog):
            b03_rollback_step(catalog, "afterMainAdvance", "ENTER_FORWARD_RECOVERY_FREEZE_BEFORE_ANY_OPTIONAL_CLEANUP")["operationIds"].append("patch-main-ref-bootstrap-force-false")

        cases = [
            ("unknown-routed-to-ordinary-rollback", route_unknown_as_ordinary, "frozen value mismatch"),
            ("binary-a-else", lambda catalog: ref_classification(catalog).__setitem__("binaryAElseClassificationForbidden", False), "frozen value mismatch"),
            ("unresolved-binding-not-incident", lambda catalog: ref_classification(catalog).__setitem__("unresolvedCommitBindingRoutesToUnknownIncident", False), "frozen value mismatch"),
            ("missing-or-unreadable-treated-as-a", treat_unreadable_as_a, "expected exactly"),
            ("missing-before-state", lambda catalog: b03_rollback(catalog)["beforeMainAdvanceStates"].pop(), "expected exactly"),
            ("post-state-routed-before", lambda catalog: b03_rollback(catalog)["beforeMainAdvanceStates"].append("S7_MAIN_ADVANCED_A_TO_B_AND_BOOTSTRAP_TOKEN_REVOKED"), "expected exactly"),
            ("missing-after-state", lambda catalog: b03_rollback(catalog)["afterMainAdvanceStates"].pop(), "expected exactly"),
            ("step-state-coverage-weakened", lambda catalog: b03_rollback_step(catalog, "beforeMainAdvance", "READ_AND_CLASSIFY_MAIN_THEN_REQUIRE_EXACT_BASELINE_A")["applicableStates"].pop(), "expected exactly"),
            ("post-advance-ref-mutation", add_post_advance_ref_mutation, "expected exactly"),
            ("unknown-incident-ref-mutation", lambda catalog: b03_rollback(catalog)["unknownRefIncident"]["immediateOperationIds"].append("delete-temporary-bootstrap-ref"), "expected exactly"),
            ("unknown-ref-mutation-not-forbidden", lambda catalog: b03_rollback(catalog)["unknownRefIncident"]["forbidden"].remove("RESET_FORCE_PUSH_DELETE_OR_OTHER_REF_MUTATION"), "expected exactly"),
            ("post-advance-reset-allowed", lambda catalog: b03_rollback(catalog)["forbidden"].remove("RESET_MAIN_TO_A"), "expected exactly"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_destructive_rollback_defaults_or_cross_instance_bindings(self) -> None:
        def resource_restore_step(catalog):
            return b03_rollback_step(catalog, "beforeMainAdvance", "RESTORE_ACTIONS_ENVIRONMENT_APP_AND_WORKFLOW_STATE_BY_EXACT_FRESH_BASELINE_IDENTITY")

        def secret_removal_group(catalog):
            step = b03_rollback_step(catalog, "beforeMainAdvance", "REMOVE_ONLY_A_BASELINE-ABSENT_CEREMONY-CREATED_ENVIRONMENT_SECRET_WITHOUT_VALUE_CAPTURE")
            return b03_conditional_group(step, "SECRET_BASELINE_ABSENT_AND_CEREMONY_CREATED_AND_STILL_PRESENT")

        def ruleset_deletion_group(catalog):
            step = b03_rollback_step(catalog, "beforeMainAdvance", "DELETE_ONLY_CEREMONY-CREATED_RULESETS_AFTER_BASELINE_PROTECTION_IS RESTORED")
            return b03_conditional_group(step, "ADMISSION_RULESET_BASELINE_ABSENT_AND_CEREMONY_CREATED")

        def temporary_ref_deletion_group(catalog):
            step = b03_rollback_step(catalog, "beforeMainAdvance", "DELETE_ONLY_BASELINE-ABSENT_CEREMONY-CREATED_TEMPORARY_REFS_AND_CLOSE_ONLY_CEREMONY-CREATED_PULL_REQUESTS")
            return b03_conditional_group(step, "BOOTSTRAP_TEMP_REF_BASELINE_ABSENT_AND_CEREMONY_CREATED")

        cases = [
            ("credential-material-in-ledger", lambda catalog: b03_rollback(catalog)["executionLedger"].__setitem__("credentialMaterialOrDigestAllowed", True), "frozen value mismatch"),
            ("missing-ledger-means-delete", lambda catalog: b03_rollback(catalog)["executionLedger"].__setitem__("missingOrContradictoryEntryDisposition", "ASSUME_BASELINE_ABSENT_AND_DELETE"), "frozen value mismatch"),
            ("skips-not-recorded", lambda catalog: b03_rollback(catalog)["executionLedger"].__setitem__("everySkippedStepOrGroupRecorded", False), "frozen value mismatch"),
            ("resource-ledger-binding-removed", lambda catalog: b03_rollback(catalog)["auxiliaryBindingRegistry"].pop(0), "expected exactly"),
            ("read-token-cross-instance-substitution", lambda catalog: b03_auxiliary_binding(catalog, "releaseInstallationReadTokenInstance").__setitem__("source", b03_auxiliary_binding(catalog, "bootstrapInstallationWriteTokenInstance")["source"] + "_SUBSTITUTE"), "frozen value mismatch"),
            ("credential-ledger-destructive-default", lambda catalog: b03_auxiliary_binding(catalog, "ceremonyCredentialLedger").__setitem__("missingOrContradictoryDisposition", "REVOKE_ANY_MATCHING_TOKEN"), "frozen value mismatch"),
            ("step-skip-without-evidence", lambda catalog: resource_restore_step(catalog).__setitem__("skipEvidenceRequired", False), "frozen value mismatch"),
            ("group-skip-without-evidence", lambda catalog: secret_removal_group(catalog).__setitem__("skipEvidenceRequired", False), "frozen value mismatch"),
            ("secret-baseline-presence-ignored", lambda catalog: secret_removal_group(catalog).__setitem__("executeWhen", "SECRET_PRESENT"), "frozen value mismatch"),
            ("ruleset-baseline-presence-ignored", lambda catalog: ruleset_deletion_group(catalog).__setitem__("executeWhen", "RULESET_PRESENT"), "frozen value mismatch"),
            ("ref-baseline-presence-ignored", lambda catalog: temporary_ref_deletion_group(catalog).__setitem__("executeWhen", "TEMP_REF_PRESENT"), "frozen value mismatch"),
            ("signing-key-baseline-presence-ignored", lambda catalog: b03_rollback_step(catalog, "beforeMainAdvance", "DELETE_EXACT_SIGNING_KEY_ONLY_IF_BASELINE-ABSENT_AND_CEREMONY-CREATED")["conditionalOperationGroups"][0].__setitem__("executeWhen", "SIGNING_KEY_PRESENT"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_inexact_mutation_identity_or_readback_sequences(self) -> None:
        def remove_declared_follow_up(catalog):
            b03_operation(catalog, "set-actions-permissions")["response"]["requiredFollowUpReadbackOperationIds"].clear()

        def reorder_follow_ups(catalog):
            b03_operation(catalog, "update-admission-ruleset-to-final")["response"]["requiredFollowUpReadbackOperationIds"].reverse()

        cases = [
            ("follow-up-omitted", remove_declared_follow_up, "expected exactly"),
            ("follow-ups-reordered", reorder_follow_ups, "frozen value mismatch"),
            ("follow-up-not-immediate", lambda catalog: b03_operation(catalog, "set-actions-permissions")["response"].__setitem__("followUpTiming", "EVENTUALLY"), "frozen value mismatch"),
            ("response-readback-id-mismatch-allowed", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"].__setitem__("responseAndReadbackIdentityMustMatch", False), "frozen value mismatch"),
            ("selector-readback-mismatch-allowed", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"].__setitem__("afterReadbackMustMatchExactSelector", False), "frozen value mismatch"),
            ("cross-resource-substitution-allowed", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"].__setitem__("crossResourceSubstitutionRejected", False), "frozen value mismatch"),
            ("identity-readbacks-disagree", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"]["afterStateReadbackOperationIds"].pop(), "expected exactly"),
            ("selector-path-broadened", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"]["exactSelector"].__setitem__("pathTemplate", "/repos/pkgre/rust/rulesets/by-name"), "frozen value mismatch"),
            ("provider-id-replaced-by-name", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"].__setitem__("providerAssignedIdBinding", "invariantRulesetName"), "frozen value mismatch"),
            ("provider-id-source-weakened", lambda catalog: b03_operation(catalog, "create-invariant-ruleset")["mutationIdentity"].__setitem__("providerAssignedIdSource", "NAME_LOOKUP"), "frozen value mismatch"),
            ("transition-readback-omitted", lambda catalog: b03_transition(catalog, "S4_INVARIANT_AND_BOOTSTRAP_ADMISSION_ACTIVE")["operations"].remove("get-invariant-ruleset"), "expected exactly"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_secret_response_or_credential_capture_weakening(self) -> None:
        def secret_capture(catalog):
            return b03_operation(catalog, "mint-bootstrap-installation-token")["response"]["capture"]

        cases = [
            ("success-body-persisted", lambda catalog: secret_capture(catalog).__setitem__("bodyPersistenceAllowed", True), "frozen value mismatch"),
            ("success-body-artifact", lambda catalog: secret_capture(catalog).__setitem__("bodyArtifactAllowed", True), "frozen value mismatch"),
            ("success-body-length", lambda catalog: secret_capture(catalog).__setitem__("bodyLengthRecordingAllowed", True), "frozen value mismatch"),
            ("success-body-hash", lambda catalog: secret_capture(catalog).__setitem__("bodyHashingAllowed", True), "frozen value mismatch"),
            ("error-body-persisted", lambda catalog: secret_capture(catalog).__setitem__("errorBodyPersistenceAllowed", True), "frozen value mismatch"),
            ("error-body-artifact", lambda catalog: secret_capture(catalog).__setitem__("errorBodyArtifactAllowed", True), "frozen value mismatch"),
            ("error-body-length", lambda catalog: secret_capture(catalog).__setitem__("errorBodyLengthRecordingAllowed", True), "frozen value mismatch"),
            ("error-body-hash", lambda catalog: secret_capture(catalog).__setitem__("errorBodyHashingAllowed", True), "frozen value mismatch"),
            ("not-all-statuses", lambda catalog: secret_capture(catalog).__setitem__("allStatusBodyHandling", "SUCCESS_ONLY"), "frozen value mismatch"),
            ("safe-envelope-open", lambda catalog: secret_capture(catalog).__setitem__("safeEnvelopeClosedWorld", False), "frozen value mismatch"),
            ("safe-envelope-body-metadata", lambda catalog: secret_capture(catalog).__setitem__("safeEnvelopeBodyMetadataForbidden", False), "frozen value mismatch"),
            ("secret-unexpected-status-body-captured", lambda catalog: b03_operation(catalog, "mint-bootstrap-installation-token")["response"].__setitem__("unexpectedStatus", "CAPTURE_ERROR_BODY_THEN_ABORT"), "frozen value mismatch"),
            ("authorization-header-captured", lambda catalog: b03_operation(catalog, "mint-bootstrap-installation-token")["request"].__setitem__("authorizationHeaderCapture", "SHA256"), "frozen value mismatch"),
            ("authorization-field-added-to-raw-envelope", lambda catalog: catalog["providerContract"]["rawCapture"]["requestFields"].append("authorizationHeaderSha256"), "expected exactly"),
            ("token-digest-allowed-in-install-procedure", lambda catalog: b03_operation(catalog, "operator-install-app-and-environment-secret", "nonRestOperations")["forbiddenCapture"].remove("SECRET_DIGEST"), "expected exactly"),
            ("token-profile-no-capture-removed", lambda catalog: b03_authentication_profile(catalog, "bootstrapInstallationWriteToken")["constraints"].remove("TOKEN_NEVER_CAPTURED"), "expected exactly"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_nonfresh_or_inexact_restore_inputs(self) -> None:
        def restore(catalog):
            return b03_operation(catalog, "restore-actions-permissions-from-pre-capture")["preCaptureRestore"]

        cases = [
            ("historical-d0-baseline", lambda catalog: restore(catalog).__setitem__("historicalD0BaselineMaySubstitute", True), "frozen value mismatch"),
            ("raw-capture-binding-removed", lambda catalog: restore(catalog).pop("rawFreshCaptureBinding"), "object-key mismatch"),
            ("typed-reconstruction-broadened", lambda catalog: restore(catalog).__setitem__("typedRequestBodyReconstruction", "COPY_WHOLE_HISTORICAL_RESPONSE"), "frozen value mismatch"),
            ("openapi-revalidation-disabled", lambda catalog: restore(catalog).__setitem__("requestRevalidatedAgainstPinnedOpenApi", False), "frozen value mismatch"),
            ("exact-projection-equality-disabled", lambda catalog: restore(catalog).__setitem__("exactProjectedReadbackAndDigestMustEqualFreshCapture", False), "frozen value mismatch"),
            ("capture-operation-substituted", lambda catalog: restore(catalog).__setitem__("captureOperationId", "get-repository"), "frozen value mismatch"),
            ("restore-readback-substituted", lambda catalog: restore(catalog).__setitem__("immediateReadbackOperationId", "get-repository"), "frozen value mismatch"),
            ("typed-binding-from-stale-source", lambda catalog: b03_typed_binding(catalog, "preCaptureActionsPermissionsRequestBody").__setitem__("sourceOperation", "D0_HISTORICAL_BASELINE"), "frozen value mismatch"),
            ("outer-rollback-allows-historical-baseline", lambda catalog: catalog["rollback"]["freshCapture"].__setitem__("historicalD0BaselineMaySubstitute", True), "frozen value mismatch"),
            ("fresh-capture-not-required", lambda catalog: catalog["rollback"]["freshCapture"].__setitem__("required", False), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_wrong_user_installation_endpoint_authentication(self) -> None:
        def user_installation_read(catalog):
            return b03_operation(catalog, "list-user-installation-repositories")

        cases = [
            ("installation-token-profile", lambda catalog: user_installation_read(catalog).__setitem__("authProfile", "releaseInstallationReadToken"), "frozen value mismatch"),
            ("app-endpoint-path", lambda catalog: user_installation_read(catalog)["request"].__setitem__("pathTemplate", "/installation/repositories"), "frozen value mismatch"),
            ("github-app-auth-enabled", lambda catalog: user_installation_read(catalog)["pinnedOpenApiSemantics"].__setitem__("githubAppsEnabled", True), "frozen value mismatch"),
            ("installation-access-token-semantics", lambda catalog: user_installation_read(catalog)["pinnedOpenApiSemantics"].__setitem__("authentication", "GITHUB_APP_INSTALLATION_ACCESS_TOKEN"), "frozen value mismatch"),
            ("procedural-user-token-requirement-removed", lambda catalog: user_installation_read(catalog)["pinnedOpenApiSemantics"].__setitem__("operatorAdminProfileIsProceduralUserCredentialNotInstallationCredential", False), "frozen value mismatch"),
            ("operator-profile-user-token-constraint-removed", lambda catalog: b03_authentication_profile(catalog, "operatorAdmin")["constraints"].remove("USER_ACCESS_TOKEN_ENDPOINTS_REQUIRE_EXPLICIT_REPOSITORY_PERMISSION"), "expected exactly"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_rejects_actor_signer_or_status_source_substitution(self) -> None:
        def required_status_binding(catalog):
            rules = catalog["rulesets"]["admission"]["providerFinalUpdateRequestBody"]["rules"]
            return next(rule for rule in rules if rule["type"] == "required_status_checks")["parameters"]["required_status_checks"][0]

        cases = [
            ("dispatcher-id-from-reviewer-read", lambda catalog: b03_typed_binding(catalog, "dispatcherUserId").__setitem__("sourceOperation", "get-environment-reviewer-user"), "frozen value mismatch"),
            ("reviewer-id-from-dispatcher-read", lambda catalog: b03_typed_binding(catalog, "reviewerUserId").__setitem__("sourceOperation", "get-release-dispatcher-user"), "frozen value mismatch"),
            ("dispatch-actor-from-run-read", lambda catalog: b03_typed_binding(catalog, "dispatchAuthenticatedActorUserId").__setitem__("sourceOperation", "get-release-workflow-run"), "frozen value mismatch"),
            ("review-audit-actor-from-self", lambda catalog: b03_typed_binding(catalog, "reviewApprovalAuditActorUserId").__setitem__("sourceOperation", "review-release-pending-deployment"), "frozen value mismatch"),
            ("candidate-check-app-id-from-installation", lambda catalog: b03_typed_binding(catalog, "candidateCheckIntegrationId").__setitem__("jsonPointer", "/check_runs/0/app/installation_id"), "frozen value mismatch"),
            ("candidate-check-id-from-release-app", lambda catalog: b03_typed_binding(catalog, "candidateCheckIntegrationId").__setitem__("sourceOperation", "get-release-app"), "frozen value mismatch"),
            ("signer-authority-not-d0-b04", lambda catalog: b03_typed_binding(catalog, "signerGithubLogin")["authoritySource"].__setitem__("findingId", "D0-B03"), "frozen value mismatch"),
            ("bootstrap-local-verification-weakened", lambda catalog: catalog["providerContract"]["bootstrapStateMachine"]["bootstrapB"].__setitem__("localVerification", "GITHUB_VERIFICATION_ONLY"), "frozen value mismatch"),
            ("release-local-verification-disabled", lambda catalog: catalog["releaseWorkflow"]["jobs"]["release"]["signedCommit"].__setitem__("localExactKeyVerificationRequired", False), "frozen value mismatch"),
            ("status-integration-app-substitution", lambda catalog: required_status_binding(catalog).__setitem__("integration_id", {"$binding": "releaseAppIntegrationId", "type": "POSITIVE_INT64"}), "frozen value mismatch"),
            ("status-context-broadened", lambda catalog: required_status_binding(catalog).__setitem__("context", "pkgre-*-candidate/validate"), "frozen value mismatch"),
            ("identity-made-nonbypassable-claim", lambda catalog: catalog["providerContract"]["actorAuthorization"].__setitem__("nonBypassableIdentityClaimed", True), "frozen value mismatch"),
            ("reviewer-dispatcher-separation-disabled", lambda catalog: catalog["providerContract"]["actorAuthorization"]["separation"].__setitem__("reviewerMustDifferFromDispatcher", False), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_provider_operation_graph_is_closed_and_catalog_specific(self) -> None:
        payloads = valid_b03_payloads()
        rust = b03_catalog(payloads, 0)
        js = b03_catalog(payloads, 1)
        for catalog in (rust, js):
            contract = catalog["providerContract"]
            GATE.validate_github_operation_graph(catalog["catalogId"], contract["restOperations"], contract["bootstrapStateMachine"])
            mutation_ids = {operation["operationId"] for operation in contract["restOperations"] if operation["request"]["method"] in {"POST", "PUT", "PATCH", "DELETE"}}
            self.assertNotIn("enable-release-workflow", mutation_ids)
            self.assertNotIn("unsuspend-release-app-installation", mutation_ids)
        rust_mutations = {operation["operationId"] for operation in rust["providerContract"]["restOperations"] if operation["request"]["method"] in {"POST", "PUT", "PATCH", "DELETE"}}
        js_mutations = {operation["operationId"] for operation in js["providerContract"]["restOperations"] if operation["request"]["method"] in {"POST", "PUT", "PATCH", "DELETE"}}
        self.assertIn("delete-classic-branch-protection-if-baseline-present", rust_mutations)
        self.assertIn("restore-classic-branch-protection-from-pre-capture", rust_mutations)
        self.assertNotIn("delete-classic-branch-protection-if-baseline-present", js_mutations)
        self.assertNotIn("restore-classic-branch-protection-from-pre-capture", js_mutations)
        rest_operations = copy.deepcopy(rust["providerContract"]["restOperations"])
        dead = copy.deepcopy(b03_operation(rust, "set-actions-permissions"))
        dead["operationId"] = "unreferenced-settings-mutation"
        rest_operations.append(dead)
        self.assertRejected(lambda: GATE.validate_github_operation_graph("rust", rest_operations, rust["providerContract"]["bootstrapStateMachine"]), "unreferenced REST mutations")

    def test_b03_mutation_response_identity_modes_are_explicit_and_noncontradictory(self) -> None:
        payloads = valid_b03_payloads()
        rust = b03_catalog(payloads)
        bodyless = b03_operation(rust, "set-actions-permissions")["mutationIdentity"]["responseIdentity"]
        self.assertEqual(bodyless["mode"], "BODYLESS_SUCCESS_SELECTOR_AND_IMMEDIATE_READBACK")
        self.assertFalse(bodyless["responseResourceIdentityClaimed"])
        id_bearing = b03_operation(rust, "put-release-environment")["mutationIdentity"]["responseIdentity"]
        self.assertEqual(id_bearing["mode"], "ID_BEARING_RESPONSE_AND_IMMEDIATE_READBACK")
        self.assertEqual(id_bearing["boundProviderId"], "environmentId")
        self.assertEqual(b03_typed_binding(rust, "environmentId")["sourceOperation"], "put-release-environment")
        secret = b03_operation(rust, "mint-bootstrap-installation-token")["mutationIdentity"]["responseIdentity"]
        self.assertEqual(secret["mode"], "SECRET_TOKEN_RESPONSE_EXCLUDED_FROM_CAPTURE_AND_IDENTITY")
        self.assertFalse(secret["responseBodyEntersIdentityPipeline"])
        ref = b03_operation(rust, "patch-main-ref-bootstrap-force-false")["mutationIdentity"]["responseIdentity"]
        self.assertEqual(ref["mode"], "REF_RESPONSE_AND_IMMEDIATE_REF_COMMIT_READBACK")
        self.assertEqual(ref["expectedOidBinding"], "bootstrapCommitB")
        deployment = b03_operation(rust, "review-release-pending-deployment")["mutationIdentity"]["responseIdentity"]
        self.assertEqual(deployment["mode"], "ID_BEARING_RESPONSE_SET_AND_IMMEDIATE_READBACK")
        self.assertEqual(deployment["boundProviderId"], "releaseDeploymentId")
        self.assertEqual(b03_typed_binding(rust, "releaseDeploymentId")["sourceOperation"], "review-release-pending-deployment")
        cases = [
            ("bodyless-claims-response-resource", lambda catalog: b03_operation(catalog, "set-actions-permissions")["mutationIdentity"]["responseIdentity"].__setitem__("responseResourceIdentityClaimed", True), "frozen value mismatch"),
            ("environment-id-from-get-only", lambda catalog: b03_typed_binding(catalog, "environmentId").__setitem__("sourceOperation", "get-release-environment"), "frozen value mismatch"),
            ("secret-body-enters-identity", lambda catalog: b03_operation(catalog, "mint-bootstrap-installation-token")["mutationIdentity"]["responseIdentity"].__setitem__("responseBodyEntersIdentityPipeline", True), "frozen value mismatch"),
            ("ref-response-treated-as-generic-id", lambda catalog: b03_operation(catalog, "patch-main-ref-bootstrap-force-false")["mutationIdentity"]["responseIdentity"].__setitem__("mode", "ID_BEARING_RESPONSE_AND_IMMEDIATE_READBACK"), "frozen value mismatch"),
            ("deployment-id-from-eventual-list-only", lambda catalog: b03_typed_binding(catalog, "releaseDeploymentId").__setitem__("sourceOperation", "list-release-deployments"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_workflow_ids_are_selected_from_complete_set_then_used_numerically(self) -> None:
        payloads = valid_b03_payloads()
        catalog = b03_catalog(payloads)
        list_workflows = b03_operation(catalog, "list-workflows")
        selection = list_workflows["workflowBindingSelection"]
        self.assertEqual(selection["matchSemantics"], "EXACTLY_ONE_PATH_AND_NAME_MATCH_PER_BINDING_FROM_COMPLETE_UNORDERED_PAGINATED_SET")
        for binding_name, operation_id in (("candidateWorkflowId", "get-candidate-workflow"), ("releaseWorkflowId", "get-release-workflow"), ("pagesWorkflowId", "get-pages-workflow")):
            binding = b03_typed_binding(catalog, binding_name)
            self.assertEqual(binding["sourceOperation"], "list-workflows")
            operation = b03_operation(catalog, operation_id)
            self.assertEqual(operation["request"]["pathTemplate"], f"/repos/pkgre/rust/actions/workflows/$binding:{binding_name}")
            self.assertTrue(operation["workflowIdentityReadback"]["requestPathUsesNumericIdBinding"])
        self.assertEqual(b03_typed_binding(catalog, "candidateCheckIntegrationId")["jsonPointer"], "/check_runs/EXACT_CONTEXT_HEAD_SHA_WORKFLOW_JOB_MATCH/app/id")
        cases = [
            ("workflow-id-from-individual-get", lambda row: b03_typed_binding(row, "candidateWorkflowId").__setitem__("sourceOperation", "get-candidate-workflow"), "frozen value mismatch"),
            ("workflow-get-by-full-path", lambda row: b03_operation(row, "get-candidate-workflow")["request"].__setitem__("pathTemplate", "/repos/pkgre/rust/actions/workflows/.github/workflows/pkgre-rust-candidate.yml"), "frozen value mismatch"),
            ("workflow-selector-filename-only", lambda row: b03_operation(row, "list-workflows")["workflowBindingSelection"].__setitem__("pathNameSubstitutionAllowed", True), "frozen value mismatch"),
            ("workflow-readback-path-substitution", lambda row: b03_operation(row, "get-candidate-workflow")["workflowIdentityReadback"].__setitem__("expectedPath", ".github/workflows/other.yml"), "frozen value mismatch"),
            ("check-first-array-entry", lambda row: b03_typed_binding(row, "candidateCheckIntegrationId").__setitem__("jsonPointer", "/check_runs/0/app/id"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_pre_mutation_capture_has_closed_conditional_coverage_without_app_jwt(self) -> None:
        payloads = valid_b03_payloads()
        catalog = b03_catalog(payloads)
        contract = catalog["providerContract"]
        capture = contract["preMutationCaptureContract"]
        GATE.validate_github_pre_mutation_capture_contract(catalog["catalogId"], capture, contract["restOperations"])
        unconditional = capture["unconditionalCaptureOperationIds"]
        self.assertNotIn("get-release-environment", unconditional)
        self.assertIn("list-organization-app-installations", unconditional)
        self.assertNotIn("get-release-app-installation", capture["allCaptureOperationIds"])
        self.assertIn("list-user-installation-repositories", capture["allCaptureOperationIds"])
        operation_by_id = {operation["operationId"]: operation for operation in contract["restOperations"]}
        self.assertTrue(all(operation_by_id[operation_id]["authProfile"] in capture["preConfigurationAllowedAuthProfiles"] for operation_id in capture["allCaptureOperationIds"]))
        invalid = copy.deepcopy(capture)
        invalid["unconditionalCaptureOperationIds"].append("get-release-environment")
        self.assertRejected(lambda: GATE.validate_github_pre_mutation_capture_contract("rust", invalid, contract["restOperations"]), "both unconditional and conditional")
        cases = [
            ("conditional-environment-read-made-unconditional", lambda row: row["providerContract"]["preMutationCaptureContract"]["unconditionalCaptureOperationIds"].append("get-release-environment"), "expected exactly"),
            ("app-jwt-required-before-configuration", lambda row: row["providerContract"]["preMutationCaptureContract"]["allCaptureOperationIds"].append("get-release-app-installation"), "expected exactly"),
            ("capture-closure-incomplete", lambda row: row["providerContract"]["preMutationCaptureContract"]["allCaptureOperationIds"].pop(), "expected exactly"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_404_projects_only_typed_absence_and_never_restore_input(self) -> None:
        payloads = valid_b03_payloads()
        catalog = b03_catalog(payloads)
        operation = b03_operation(catalog, "get-classic-branch-protection")
        absence = next(row for row in operation["response"]["admittedStatusSemantics"] if row["status"] == 404)
        self.assertEqual(absence["outcome"], "TYPED_ABSENCE_ONLY")
        self.assertEqual(absence["typedProjection"], {"presence": "ABSENT"})
        self.assertFalse(absence["presentResourceProjectionAllowed"])
        self.assertFalse(absence["providerIdBindingAllowed"])
        self.assertFalse(absence["restoreRequestReconstructionAllowed"])
        self.assertFalse(absence["responseBodyRestorationInputAllowed"])
        cases = [
            ("404-as-empty-present-object", lambda row: next(item for item in b03_operation(row, "get-classic-branch-protection")["response"]["admittedStatusSemantics"] if item["status"] == 404).__setitem__("typedProjection", {"presence": "PRESENT", "resource": {}}), "object-key mismatch"),
            ("404-provider-id-binding", lambda row: next(item for item in b03_operation(row, "get-release-app")["response"]["admittedStatusSemantics"] if item["status"] == 404).__setitem__("providerIdBindingAllowed", True), "frozen value mismatch"),
            ("404-restore-body", lambda row: next(item for item in b03_operation(row, "get-candidate-workflow-content-at-a")["response"]["admittedStatusSemantics"] if item["status"] == 404).__setitem__("responseBodyRestorationInputAllowed", True), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_b03_requires_catalog_specific_d0_b04_signer_separation_without_values(self) -> None:
        payloads = valid_b03_payloads()
        for catalog in payloads["github-governance-proof"]["catalogs"]:
            separation = catalog["providerContract"]["catalogSignerSeparation"]
            self.assertEqual(separation["authorityFindingId"], "D0-B04")
            self.assertEqual(separation["assignmentStatus"], "NOT_YET_ASSIGNED_IN_D0_B03")
            self.assertTrue(separation["mustDifferFromEveryOtherCatalog"])
            self.assertFalse(separation["concreteIdentityValuesPresent"])
        cases = [
            ("shared-signer-authorized", lambda row: row["providerContract"]["catalogSignerSeparation"].__setitem__("mustDifferFromEveryOtherCatalog", False), "frozen value mismatch"),
            ("concrete-signer-fabricated-in-b03", lambda row: row["providerContract"]["catalogSignerSeparation"].__setitem__("concreteIdentityValuesPresent", True), "frozen value mismatch"),
            ("authority-source-allows-shared", lambda row: row["rulesets"]["invariants"]["signatureAuthority"].__setitem__("exactSshEd25519SignerEnforcedBy", "SHARED_PROVIDER_VERIFICATION"), "frozen value mismatch"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                self.assertB03MutationRejected(mutate, expected)

    def test_github_provider_set_projection_is_exact_unordered_and_unambiguous(self) -> None:
        expected = [{"id": 7, "name": "admission"}, {"id": 9, "name": "invariants"}]
        raw = [{"id": 9, "name": "invariants", "providerAdded": True}, {"id": 7, "name": "admission", "providerAdded": {"future": 1}}]
        self.assertEqual(GATE.github_project_exact_provider_set(raw, expected, "provider-set"), sorted(expected, key=GATE.canonical_json))
        duplicate_raw = [copy.deepcopy(raw[0]), copy.deepcopy(raw[0])]
        self.assertRejected(lambda: GATE.github_project_exact_provider_set(duplicate_raw, expected, "provider-set"), "duplicate projected entries")
        duplicate_expected = [copy.deepcopy(expected[0]), copy.deepcopy(expected[0])]
        self.assertRejected(lambda: GATE.github_project_exact_provider_set(raw, duplicate_expected, "provider-set"), "expected provider set contains duplicate")
        ambiguous_expected = [{"id": 7}, {"id": 7, "name": "admission"}]
        ambiguous_raw = [{"id": 7, "name": "admission"}, {"id": 7}]
        self.assertRejected(lambda: GATE.github_project_exact_provider_set(ambiguous_raw, ambiguous_expected, "provider-set"), "must match exactly one expected projection")
        missing_match = [copy.deepcopy(raw[0]), {"id": 10, "name": "unexpected"}]
        self.assertRejected(lambda: GATE.github_project_exact_provider_set(missing_match, expected, "provider-set"), "must match exactly one expected projection")
        self.assertRejected(lambda: GATE.github_project_exact_provider_set(raw[:1], expected, "provider-set"), "set length mismatch")

    def test_github_provider_projection_ignores_only_additive_raw_object_fields(self) -> None:
        expected = {"id": 7, "name": "pkgre-rust-admission", "nested": {"state": "active"}, "actors": [{"id": 11, "type": "Integration"}]}
        raw = {"id": 7, "name": "pkgre-rust-admission", "providerAdded": {"future": True}, "nested": {"state": "active", "future": "ignored"}, "actors": [{"id": 11, "type": "Integration", "future": 1}]}
        self.assertEqual(GATE.github_project_exact_provider_value(raw, expected, "provider"), expected)
        wrong = copy.deepcopy(raw)
        wrong["nested"]["state"] = "evaluate"
        self.assertRejected(lambda: GATE.github_project_exact_provider_value(wrong, expected, "provider"), "provider projected value mismatch")
        missing = copy.deepcopy(raw)
        del missing["actors"][0]["id"]
        self.assertRejected(lambda: GATE.github_project_exact_provider_value(missing, expected, "provider"), "missing projected fields")
        wrong_type = copy.deepcopy(raw)
        wrong_type["id"] = "7"
        self.assertRejected(lambda: GATE.github_project_exact_provider_value(wrong_type, expected, "provider"), "wrong JSON type")
        extra_array_item = copy.deepcopy(raw)
        extra_array_item["actors"].append({"id": 12, "type": "Integration"})
        self.assertRejected(lambda: GATE.github_project_exact_provider_value(extra_array_item, expected, "provider"), "array length mismatch")

    def test_b01_rejects_nonexact_shapes_types_and_unsafe_semantic_text(self) -> None:
        cases = []

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["unexpected"] = True
        cases.append(("extra-key", payloads, "object-key mismatch"))

        payloads = valid_b01_payloads()
        del payloads["credential-containment"]["secretMaterial"]
        cases.append(("missing-key", payloads, "object-key mismatch"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["secretMaterial"]["credentialValueRead"] = 1
        cases.append(("integer-boolean", payloads, "expected boolean"))

        for name, actor, expected in (
            ("empty-text", "", "expected nonempty"),
            ("newline", "operator\nclaim", "invalid or overlong semantic text"),
            ("c1-control", "operator\x85claim", "invalid or overlong semantic text"),
            ("overlong", "x" * 129, "invalid or overlong semantic text"),
        ):
            payloads = valid_b01_payloads()
            payloads["credential-containment"]["events"]["permissionRepair"]["actor"] = actor
            cases.append((name, payloads, expected))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B01", "OP-D0-01", payloads, expected)

    def test_b01_rejects_incomplete_or_inconsistent_credential_containment(self) -> None:
        cases = []

        for name, metadata, expected in (
            ("owner", semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "GANDI_LIVEDNS_DNS01", owner="acme"), "intended credential identity or purpose mismatch"),
            ("group", semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "GANDI_LIVEDNS_DNS01", group="keys"), "intended credential identity or purpose mismatch"),
            ("mode", semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "GANDI_LIVEDNS_DNS01", mode="0400"), "live credential mode disagrees with declarative policy"),
            ("purpose", semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "OTHER"), "intended credential identity or purpose mismatch"),
            ("readers", semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "GANDI_LIVEDNS_DNS01", mode="0640"), "intended credential must be readable only by root"),
        ):
            payloads = valid_b01_payloads()
            payloads["credential-containment"]["declarativePolicy"]["intendedMetadata"] = semantic_file_policy(metadata)
            cases.append((f"declarative-{name}", payloads, expected))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["declarativePolicy"]["intendedMetadata"]["maximumSizeBytes"] = 63
        cases.append(("declarative-size", payloads, "live credential exceeds the declarative maximum size"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["declarativePolicy"]["deployedGeneration"] = SEMANTIC_ALT_GENERATION
        cases.append(("declarative-source-generation", payloads, "live credential generation disagrees with deployed declarative generation"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["provider"]["expiry"] = SEMANTIC_OBSERVED_AT
        cases.append(("expired-provider-credential", payloads, "already expired"))

        payloads = valid_b01_payloads()
        events = payloads["credential-containment"]["events"]
        events["oldCredentialRevocation"]["eventId"] = events["newCredentialActivation"]["eventId"]
        cases.append(("duplicate-event-id", payloads, "event IDs must be distinct"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["events"]["newCredentialActivation"]["occurredAt"] = "2026-08-26T00:03:00Z"
        cases.append(("event-chronology", payloads, "chronology is invalid"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["audit"][2]["check"] = "SCOPE"
        payloads["credential-containment"]["audit"][2]["credential"] = copy.deepcopy(payloads["credential-containment"]["provider"]["activeCredential"])
        cases.append(("duplicate-audit-category", payloads, "each required category exactly once"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["audit"].append(copy.deepcopy(payloads["credential-containment"]["audit"][-1]))
        cases.append(("extra-audit-row", payloads, "exactly three provider audit checks"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["audit"][0]["occurredAt"] = "2026-08-26T00:01:00Z"
        cases.append(("audit-before-revocation", payloads, "provider audit must follow revocation"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["audit"][2]["occurredAt"] = "2026-08-26T00:07:00Z"
        cases.append(("audit-after-observation", payloads, "provider audit must follow revocation"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["audit"][1]["auditId"] = payloads["credential-containment"]["events"]["permissionRepair"]["eventId"]
        cases.append(("audit-event-id-reuse", payloads, "containment,installation,and provider audit IDs must be distinct"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["secretMaterial"]["credentialDigestRecorded"] = True
        cases.append(("secret-digest", payloads, "credential bytes or digest must not be returned"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["provider"]["activeCredential"] = copy.deepcopy(payloads["credential-containment"]["provider"]["oldCredential"])
        cases.append(("same-credential-handle", payloads, "comparable and distinct"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["provider"]["activeCredential"] = {"kind": "PROVIDER_ID", "value": "0123456789abcdef0123456789abcdef01234567"}
        cases.append(("provider-id-could-smuggle-pat", payloads, "only a bounded safe credential suffix"))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B01", "OP-D0-01", payloads, expected)

    def test_b01_rejects_incomplete_or_inconsistent_credential_lifecycle(self) -> None:
        cases = []

        payloads = valid_b01_payloads()
        files = payloads["credential-lifecycle"]["files"]
        files[-1]["metadata"]["path"] = files[0]["metadata"]["path"]
        files[-1]["metadata"]["collection"]["targetPath"] = files[0]["metadata"]["path"]
        cases.append(("reused-account-key-path", payloads, "paths must be globally distinct"))

        payloads = valid_b01_payloads()
        pat = payloads["credential-lifecycle"]["patProcedures"]
        pat["recovery"]["procedureId"] = pat["routineRotation"]["procedureId"]
        pat["recovery"]["test"]["procedureId"] = pat["routineRotation"]["procedureId"]
        cases.append(("duplicate-procedure-id", payloads, "procedure IDs must be globally distinct"))

        payloads = valid_b01_payloads()
        pat = payloads["credential-lifecycle"]["patProcedures"]
        pat["recovery"]["test"]["eventId"] = pat["routineRotation"]["test"]["eventId"]
        cases.append(("duplicate-test-event-id", payloads, "test-event IDs must be globally distinct"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["lifecycles"][0]["rotation"]["test"]["result"] = "FAIL"
        cases.append(("failed-procedure-test", payloads, "procedure test must PASS"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["secretMaterial"]["privateKeyValueRead"] = True
        cases.append(("private-key-read", payloads, "private-key material or digest must not be returned"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["rotationId"] = "other-rotation"
        cases.append(("rotation-mismatch", payloads, "rotation IDs disagree"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["providerIdentity"] = "OTHER_PROVIDER"
        cases.append(("provider-mismatch", payloads, "ACME provider identity mismatch"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["sourceGeneration"] = SEMANTIC_ALT_GENERATION
        for row in payloads["credential-lifecycle"]["files"]:
            row["metadata"]["sourceGeneration"] = SEMANTIC_ALT_GENERATION
        cases.append(("generation-mismatch", payloads, "source generations disagree"))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B01", "OP-D0-01", payloads, expected)

    def test_b01_rejects_unsafe_file_metadata_size_and_time_attestations(self) -> None:
        cases = []

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["credential"]["sizeBytes"] = GATE.D0_CREDENTIAL_MAX_BYTES + 1
        cases.append(("oversize-credential", payloads, f"expected integer in [1,{GATE.D0_CREDENTIAL_MAX_BYTES}]"))

        for name, index, maximum in (
            ("oversize-certificate", 0, GATE.D0_CERTIFICATE_MAX_BYTES),
            ("oversize-private-key", len(GATE.ACME_NAMES), GATE.D0_PRIVATE_KEY_MAX_BYTES),
            ("oversize-account-key", -1, GATE.D0_PRIVATE_KEY_MAX_BYTES),
        ):
            payloads = valid_b01_payloads()
            payloads["credential-lifecycle"]["files"][index]["metadata"]["sizeBytes"] = maximum + 1
            cases.append((name, payloads, f"expected integer in [1,{maximum}]"))

        payloads = valid_b01_payloads()
        metadata = semantic_file_metadata("/var/lib/keys/pkgre-js-gandiv5-token", "GANDI_LIVEDNS_DNS01", mode="0640")
        payloads["credential-containment"]["credential"] = metadata
        payloads["credential-containment"]["declarativePolicy"]["intendedMetadata"] = semantic_file_policy(metadata)
        cases.append(("group-readable-credential", payloads, "readable only by root"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["credential"]["aclComplete"] = 1
        cases.append(("nonboolean-acl-completeness", payloads, "expected boolean"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["credential"]["fileType"] = "SYMLINK"
        payloads["credential-containment"]["credential"]["symlinkTarget"] = "/run/keys/gandi"
        cases.append(("symlink-credential", payloads, "non-symlink regular file"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["credential"]["acl"][1], payloads["credential-containment"]["credential"]["acl"][2] = payloads["credential-containment"]["credential"]["acl"][2], payloads["credential-containment"]["credential"]["acl"][1]
        cases.append(("noncanonical-acl", payloads, "ACL entries are not in canonical order"))

        for name, observed_at, expected in (
            ("stale-observation", "2026-08-25T00:09:59Z", "evidence is older"),
            ("future-observation", "2026-08-26T00:10:01Z", "later than its attested upper bound"),
        ):
            payloads = valid_b01_payloads()
            credential = payloads["credential-containment"]["credential"]
            credential["observedAt"] = observed_at
            credential["collection"]["observedAt"] = observed_at
            cases.append((name, payloads, expected))

        payloads = valid_b01_payloads()
        for index, event_name in enumerate(("permissionRepair", "newCredentialActivation", "oldCredentialRevocation")):
            payloads["credential-containment"]["events"][event_name]["occurredAt"] = f"2026-08-25T00:0{index}:00Z"
        for index, audit in enumerate(payloads["credential-containment"]["audit"], 3):
            audit["occurredAt"] = f"2026-08-25T00:0{index}:00Z"
        cases.append(("stale-containment-events-and-audits", payloads, "evidence is older"))

        for name, tested_at, expected in (
            ("stale-procedure-test", "2026-08-25T00:09:59Z", "evidence is older"),
            ("future-procedure-test", "2026-08-26T00:10:01Z", "later than its attested upper bound"),
        ):
            payloads = valid_b01_payloads()
            payloads["credential-lifecycle"]["patProcedures"]["recovery"]["test"]["testedAt"] = tested_at
            cases.append((name, payloads, expected))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B01", "OP-D0-01", payloads, expected)

    def test_b01_rejects_unbound_lifecycle_procedures_and_tests(self) -> None:
        cases = []

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["patProcedures"]["routineRotation"]["subject"]["providerIdentity"] = "OTHER_PROVIDER"
        cases.append(("pat-procedure-subject", payloads, "procedure is not bound to the required subject"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["patProcedures"]["routineRotation"]["test"]["subject"]["credential"]["value"] = "old1"
        cases.append(("pat-test-subject", payloads, "test event is not bound to the required subject"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["lifecycles"][0]["rotation"]["subject"]["privateKeyPath"] = "/var/lib/acme/other/key.pem"
        cases.append(("certificate-procedure-subject", payloads, "procedure is not bound to the required subject"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["lifecycles"][-1]["recovery"]["test"]["subject"]["path"] = "/var/lib/acme/other/key.pem"
        cases.append(("account-key-test-subject", payloads, "test event is not bound to the required subject"))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B01", "OP-D0-01", payloads, expected)

    def test_b01_rejects_cross_object_identifier_reuse_and_secret_shaped_text(self) -> None:
        cases = []

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["patProcedures"]["routineRotation"]["test"]["eventId"] = payloads["credential-containment"]["events"]["permissionRepair"]["eventId"]
        cases.append(("containment-lifecycle-event-reuse", payloads, "containment and lifecycle test-event IDs must be globally distinct"))

        payloads = valid_b01_payloads()
        pat = payloads["credential-lifecycle"]["patProcedures"]
        pat["recovery"]["procedureId"] = pat["routineRotation"]["test"]["eventId"]
        pat["recovery"]["test"]["procedureId"] = pat["recovery"]["procedureId"]
        cases.append(("procedure-test-event-reuse", payloads, "procedure and test-event IDs must be globally distinct"))

        payloads = valid_b01_payloads()
        procedure = payloads["credential-lifecycle"]["patProcedures"]["routineRotation"]
        procedure["procedureId"] = payloads["credential-containment"]["installation"]["dns01Operation"]["operationId"]
        procedure["test"]["procedureId"] = procedure["procedureId"]
        cases.append(("procedure-containment-operation-reuse", payloads, "is reused by"))

        payloads = valid_b01_payloads()
        pat = payloads["credential-lifecycle"]["patProcedures"]
        pat["recovery"]["test"]["fixture"]["fixtureId"] = pat["routineRotation"]["test"]["fixture"]["fixtureId"]
        cases.append(("fixture-reuse", payloads, "is reused by"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["patProcedures"]["routineRotation"]["test"]["fixture"]["replacementIdentity"]["value"] = payloads["credential-containment"]["audit"][0]["auditId"]
        cases.append(("replacement-identity-audit-reuse", payloads, "is reused by"))

        payloads = valid_b01_payloads()
        payloads["credential-lifecycle"]["patProcedures"]["routineRotation"]["test"]["fixture"]["fixtureId"] = payloads["credential-containment"]["events"]["permissionRepair"]["eventId"].upper()
        cases.append(("case-folded-identifier-reuse", payloads, "is reused by"))

        payloads = valid_b01_payloads()
        payloads["credential-containment"]["rotationId"] = payloads["credential-containment"]["audit"][0]["auditId"]
        payloads["credential-lifecycle"]["rotationId"] = payloads["credential-containment"]["rotationId"]
        cases.append(("rotation-audit-reuse", payloads, "is reused by"))

        for name, actor, expected in (
            ("private-key-shaped-text", "-----BEGIN PRIVATE KEY-----", "private-key-shaped text is forbidden"),
            ("hex-secret-shaped-text", "0123456789abcdef0123456789abcdef", "secret-shaped hexadecimal text is forbidden"),
            ("base64-secret-shaped-text", "Z" * 40, "secret-shaped base64 text is forbidden"),
        ):
            payloads = valid_b01_payloads()
            payloads["credential-containment"]["events"]["permissionRepair"]["actor"] = actor
            cases.append((name, payloads, expected))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B01", "OP-D0-01", payloads, expected)

    def test_b02_rejects_unpinned_tofu_or_inconsistent_ssh_proof(self) -> None:
        cases = []

        for field, value in (
            ("hostname", "other.pacna.org"),
            ("port", 2222),
            ("algorithm", "ssh-rsa"),
            ("fingerprint", ALT_SSH_FINGERPRINT),
        ):
            payloads = valid_b02_payloads()
            payloads["ssh-attestation"][field] = value
            cases.append((f"wrong-{field}", payloads, "Rain SSH"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["authoritativeSource"]["type"] = "TOFU"
        cases.append(("tofu-source", payloads, "unsupported or mismatched out-of-band authority method"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["authoritativeSource"]["type"] = "SIGNED_OFFLINE_INVENTORY"
        payloads["ssh-attestation"]["authoritativeSource"]["method"] = "COMPARE_PUBLIC_HOST_KEY_TO_SIGNED_OFFLINE_INVENTORY"
        cases.append(("unverified-signed-inventory-label", payloads, "unsupported or mismatched out-of-band authority method"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["authoritativeSource"]["observedSshConnectionUsed"] = 1
        cases.append(("nonboolean-independence", payloads, "expected boolean"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["attestation"]["match"] = False
        cases.append(("fingerprint-mismatch", payloads, "attestation did not match"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["secretMaterial"]["privateKeyDigestRecorded"] = True
        cases.append(("private-key-digest", payloads, "private host-key material or digest must not be returned"))

        payloads = valid_b02_payloads()
        lifecycle = payloads["ssh-lifecycle"]
        lifecycle["recovery"]["procedureId"] = lifecycle["rotation"]["procedureId"]
        lifecycle["recovery"]["test"]["procedureId"] = lifecycle["rotation"]["procedureId"]
        cases.append(("duplicate-procedure-id", payloads, "procedure IDs must be distinct"))

        payloads = valid_b02_payloads()
        lifecycle = payloads["ssh-lifecycle"]
        lifecycle["recovery"]["test"]["eventId"] = lifecycle["rotation"]["test"]["eventId"]
        cases.append(("duplicate-test-event-id", payloads, "test-event IDs must be distinct"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["rotation"]["test"]["eventId"] = payloads["ssh-attestation"]["attestation"]["eventId"]
        cases.append(("attestation-event-reuse", payloads, "attestation and lifecycle test-event IDs must be distinct"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["currentFingerprint"] = ALT_SSH_FINGERPRINT
        cases.append(("lifecycle-fingerprint", payloads, "pinned Rain SSH lifecycle identity mismatch"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["recovery"]["test"]["result"] = "FAIL"
        cases.append(("failed-lifecycle-test", payloads, "procedure test must PASS"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["rotation"]["subject"]["hostname"] = "other.pacna.org"
        cases.append(("lifecycle-procedure-subject", payloads, "procedure is not bound to the required subject"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["rotation"]["test"]["subject"]["fingerprint"] = ALT_SSH_FINGERPRINT
        cases.append(("lifecycle-test-subject", payloads, "test event is not bound to the required subject"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["authoritativeSource"]["observedSshConnectionUsed"] = True
        cases.append(("observed-ssh-used-as-authority", payloads, "depends on the observed SSH connection"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["authoritativeSource"]["operator"] = "different-operator"
        cases.append(("authority-operator-mismatch", payloads, "operator does not match operator return"))

        for name, observed_at, expected in (
            ("stale-authoritative-source", "2026-08-25T00:09:59Z", "evidence is older"),
            ("future-authoritative-source", "2026-08-26T00:10:01Z", "later than its attested upper bound"),
        ):
            payloads = valid_b02_payloads()
            payloads["ssh-attestation"]["authoritativeSource"]["observedAt"] = observed_at
            cases.append((name, payloads, expected))

        for name, tested_at, expected in (
            ("stale-lifecycle-test", "2026-08-25T00:09:59Z", "evidence is older"),
            ("future-lifecycle-test", "2026-08-26T00:10:01Z", "later than its attested upper bound"),
        ):
            payloads = valid_b02_payloads()
            payloads["ssh-lifecycle"]["recovery"]["test"]["testedAt"] = tested_at
            cases.append((name, payloads, expected))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["authoritativeSource"]["sourceId"] = payloads["ssh-attestation"]["attestation"]["eventId"]
        cases.append(("source-attestation-id-reuse", payloads, "authority,endpoint,and attestation IDs must be distinct"))

        payloads = valid_b02_payloads()
        lifecycle = payloads["ssh-lifecycle"]
        lifecycle["recovery"]["procedureId"] = lifecycle["rotation"]["test"]["eventId"]
        lifecycle["recovery"]["test"]["procedureId"] = lifecycle["recovery"]["procedureId"]
        cases.append(("procedure-test-event-reuse", payloads, "procedure and test-event IDs must be distinct"))

        payloads = valid_b02_payloads()
        procedure = payloads["ssh-lifecycle"]["rotation"]
        procedure["procedureId"] = payloads["ssh-attestation"]["endpointObservation"]["observationId"]
        procedure["test"]["procedureId"] = procedure["procedureId"]
        cases.append(("procedure-observation-reuse", payloads, "is reused by"))

        payloads = valid_b02_payloads()
        lifecycle = payloads["ssh-lifecycle"]
        lifecycle["recovery"]["test"]["fixture"]["fixtureId"] = lifecycle["rotation"]["test"]["fixture"]["fixtureId"]
        cases.append(("fixture-reuse", payloads, "is reused by"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["rotation"]["test"]["fixture"]["replacementIdentity"]["value"] = payloads["ssh-attestation"]["attestation"]["eventId"]
        cases.append(("replacement-identity-attestation-reuse", payloads, "is reused by"))

        payloads = valid_b02_payloads()
        payloads["ssh-lifecycle"]["rotation"]["test"]["testCase"]["caseId"] = payloads["ssh-attestation"]["authoritativeSource"]["sourceId"].upper()
        cases.append(("case-folded-identifier-reuse", payloads, "is reused by"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["secretMaterial"]["privateKeyValueRead"] = True
        cases.append(("private-key-read", payloads, "private host-key material or digest must not be returned"))

        payloads = valid_b02_payloads()
        payloads["ssh-attestation"]["unexpected"] = True
        cases.append(("extra-key", payloads, "object-key mismatch"))

        for name, payloads, expected in cases:
            with self.subTest(name=name):
                self.assertSemanticPayloadsRejected("D0-B02", "OP-D0-02", payloads, expected)

    def test_generic_semantic_envelopes_bind_exact_handoff_kinds_and_claims(self) -> None:
        limits = self.semanticResult("D0-B10", "OP-D0-06", {"approved-limits": {"test": True}})
        resources = self.semanticResult("D0-B10", "OP-D0-07", {"native-resource-proof": {"test": True}})
        self.assertEqual(GATE.validate_semantic_documents("D0-B10", "SATISFIED", limits), {"approved-limits": {"test": True}})
        self.assertEqual(GATE.validate_semantic_documents("D0-B10", "SATISFIED", resources), {"native-resource-proof": {"test": True}})
        self.assertRejected(lambda: GATE.validate_generic_policy("D0-B10", "SATISFIED", "EVIDENCE_SATISFIED", [limits, resources], SEMANTIC_VERIFICATION_TIME), "strict semantic payload validation is not installed")
        self.assertRejected(lambda: GATE.validate_generic_policy("D0-B10", "SATISFIED", "EVIDENCE_SATISFIED", [resources, limits], SEMANTIC_VERIFICATION_TIME), "semantic contributions are not in canonical handoff order")

        wrong_owner = self.semanticResult("D0-B10", "OP-D0-06", {"native-resource-proof": {"test": True}})
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B10", "SATISFIED", wrong_owner), "evidence-kind set must be exact")

        missing_claim = self.semanticResult("D0-B10", "OP-D0-06", {"approved-limits": {"test": True}})
        missing_claim["claims"] = {"summary": "labels are not proof", "targetGates": []}
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B10", "SATISFIED", missing_claim), "object-key mismatch")

    def test_generic_semantic_envelopes_reject_arbitrary_bytes_stuffing_and_reuse(self) -> None:
        result = self.semanticResult("D0-B01", "OP-D0-01", {"credential-containment": {}, "credential-lifecycle": {}})
        containment_id = result["_evidenceByKind"]["credential-containment"][0]
        result["_references"][containment_id]["raw"] = b"arbitrary text\n"
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B01", "SATISFIED", result), "invalid strict JSON")

        result = self.semanticResult("D0-B01", "OP-D0-01", {"credential-containment": {}, "credential-lifecycle": {}})
        containment_id = result["_evidenceByKind"]["credential-containment"][0]
        result["_references"][containment_id]["raw"] = GATE.canonical_json({})
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B01", "SATISFIED", result), "object-key mismatch")

        result = self.semanticResult("D0-B01", "OP-D0-01", {"credential-containment": {}, "credential-lifecycle": {}})
        shared = result["_evidenceByKind"]["credential-containment"][0]
        result["_evidenceByKind"]["credential-lifecycle"] = [shared]
        result["claims"]["evidenceByKind"] = result["_evidenceByKind"]
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B01", "SATISFIED", result), "cannot be reused")

        amendment_payload = valid_phase_amendment("D0-B09")
        amendment = self.semanticResult("D0-B09", "OP-D0-07", {"phase-amendment": amendment_payload}, disposition="REPHASED", target_gates=GATE.REPHASE_TARGETS["D0-B09"])
        self.assertEqual(GATE.validate_semantic_documents("D0-B09", "REPHASED", amendment), {"phase-amendment": amendment_payload})
        GATE.validate_generic_policy("D0-B09", "REPHASED", "EXACT_PHASE_AMENDMENT", [amendment], SEMANTIC_VERIFICATION_TIME)
        amendment["claims"]["targetGates"] = ["PRE_D6_EDGE"]
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B09", "REPHASED", amendment), "target-gate claim mismatch")

    def test_phase_amendment_accepts_every_policy_mapping_and_handoff(self) -> None:
        for finding_id, target_gates in GATE.REPHASE_TARGETS.items():
            with self.subTest(finding_id=finding_id):
                results = [
                    self.semanticResult(
                        finding_id,
                        handoff_id,
                        {"phase-amendment": valid_phase_amendment(finding_id, amendment_id=f"amendment-{finding_id.lower()}-{handoff_id.lower()}")},
                        disposition="REPHASED",
                        target_gates=target_gates,
                    )
                    for handoff_id in GATE.FINDING_HANDOFFS[finding_id]
                ]
                GATE.validate_generic_policy(finding_id, "REPHASED", "EXACT_PHASE_AMENDMENT", results, SEMANTIC_VERIFICATION_TIME)

    def test_phase_amendment_rejects_nonexact_or_unsafe_decisions(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []

        cases.append(("empty", {}, "object-key mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["unexpected"] = True
        cases.append(("extra-key", payload, "object-key mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["decision"] = "APPROVE_REPHASE"
        cases.append(("wrong-decision", payload, "decision/result mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["result"] = "REJECTED"
        cases.append(("wrong-result", payload, "decision/result mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["findingId"] = "D0-B08"
        cases.append(("wrong-finding", payload, "finding binding mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["targetGates"] = ["PRE_D6_EDGE"]
        cases.append(("missing-target", payload, "target-gate list mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["deferredRequirements"][0]["gateId"] = "PRE_D7_REAL_RAIN_EDGE"
        cases.append(("wrong-deferred-gate", payload, "exact later-gate requirement"))

        payload = valid_phase_amendment("D0-B09")
        payload["deferredRequirements"][0]["unexpected"] = True
        cases.append(("extra-deferred-key", payload, "object-key mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["deferredRequirements"][0]["requirement"] = "trust this label"
        cases.append(("wrong-requirement", payload, "exact later-gate requirement"))

        payload = valid_phase_amendment("D0-B09")
        payload["currentEvidenceSatisfied"] = True
        cases.append(("claims-satisfied", payload, "current evidence must remain unsatisfied"))

        payload = valid_phase_amendment("D0-B09")
        payload["currentEvidenceSatisfied"] = 0
        cases.append(("nonboolean-satisfaction", payload, "expected boolean"))

        payload = valid_phase_amendment("D0-B09")
        payload["d0WorkAuthorized"] = True
        cases.append(("authorizes-d0", payload, "must not authorize D0 work"))

        payload = valid_phase_amendment("D0-B09")
        payload["d0WorkAuthorized"] = "false"
        cases.append(("nonboolean-authorization", payload, "expected boolean"))

        payload = valid_phase_amendment("D0-B09")
        payload["operatorDecision"]["returnedBy"] = "other-operator"
        cases.append(("actor-mismatch", payload, "operator identity mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["operatorDecision"]["returnedAt"] = "2026-08-26T00:10:01Z"
        cases.append(("time-mismatch", payload, "operator return time mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["operatorDecision"]["unexpected"] = True
        cases.append(("extra-operator-decision-key", payload, "object-key mismatch"))

        payload = valid_phase_amendment("D0-B09")
        payload["residualRisks"] = []
        cases.append(("empty-risks", payload, "at least 1 entries"))

        payload = valid_phase_amendment("D0-B09")
        payload["residualRisks"] = ["Deferred proof remains open.", "DEFERRED PROOF REMAINS OPEN."]
        cases.append(("duplicate-risks", payload, "duplicate risk"))

        payload = valid_phase_amendment("D0-B09")
        payload["rationale"] = "-----BEGIN OPENSSH PRIVATE KEY-----"
        cases.append(("secret-shaped-rationale", payload, "private-key-shaped text"))

        for name, payload, expected in cases:
            with self.subTest(name=name):
                result = self.semanticResult("D0-B09", "OP-D0-07", {"phase-amendment": payload}, disposition="REPHASED", target_gates=GATE.REPHASE_TARGETS["D0-B09"])
                self.assertRejected(lambda: GATE.validate_generic_policy("D0-B09", "REPHASED", "EXACT_PHASE_AMENDMENT", [result], SEMANTIC_VERIFICATION_TIME), expected)

    def test_phase_amendment_ids_are_globally_casefold_unique_across_handoffs(self) -> None:
        first = self.semanticResult("D0-B04", "OP-D0-04", {"phase-amendment": valid_phase_amendment("D0-B04", amendment_id="amendment-shared")}, disposition="REPHASED", target_gates=GATE.REPHASE_TARGETS["D0-B04"])
        second = self.semanticResult("D0-B04", "OP-D0-05", {"phase-amendment": valid_phase_amendment("D0-B04", amendment_id="AMENDMENT-SHARED")}, disposition="REPHASED", target_gates=GATE.REPHASE_TARGETS["D0-B04"])
        self.assertRejected(lambda: GATE.validate_generic_policy("D0-B04", "REPHASED", "EXACT_PHASE_AMENDMENT", [first, second], SEMANTIC_VERIFICATION_TIME), "amendment ID")

    def test_gitops_rejects_caller_transport_and_builds_trusted_ssh(self) -> None:
        environment = dict(os.environ)
        environment["GIT_SSH_COMMAND"] = "/tmp/attacker"
        self.assertRejected(lambda: GATE.GitOps(environment=environment), "transport environment overrides")
        environment.pop("GIT_SSH_COMMAND")
        operations = GATE.GitOps(environment=environment)
        command = operations.environment["GIT_SSH_COMMAND"]
        self.assertIn("-oBatchMode=yes", command)
        self.assertIn("-oProxyCommand=none", command)
        self.assertTrue(str(operations.ssh_executable).startswith("/nix/store/") or str(operations.ssh_executable).startswith(("/usr/", "/bin/")))

    def test_history_rejects_intermediate_forbidden_edit_then_revert(self) -> None:
        temporary, fixture = self.temporary_fixture()
        try:
            write(fixture.repository, "docs/forbidden.md", b"forbidden\n")
            fixture.commit("forbidden")
            (fixture.repository / "docs/forbidden.md").unlink()
            fixture.commit("revert")
            evidence, state = self.finish_linear_history(fixture)
            self.assertRejected(lambda: GATE.validate_closure_history(fixture.ops, fixture.repository, fixture.base, evidence, state), "forbidden non-D0 paths")
        finally:
            temporary.cleanup()

    def test_history_rejects_merge(self) -> None:
        temporary, fixture = self.temporary_fixture()
        try:
            git(fixture.repository, "checkout", "-b", "side")
            write(fixture.repository, "evidence/d0-closure/set/side", b"side\n")
            fixture.commit("side")
            git(fixture.repository, "checkout", "main")
            write(fixture.repository, "evidence/d0-closure/set/main", b"main\n")
            fixture.commit("main")
            process = subprocess.run(["git", "-C", str(fixture.repository), "merge", "--no-ff", "side", "-m", "merge"], env=fixture.environment, check=True, stdout=subprocess.PIPE)
            self.assertEqual(process.returncode, 0)
            evidence, state = self.finish_linear_history(fixture)
            self.assertRejected(lambda: GATE.validate_closure_history(fixture.ops, fixture.repository, fixture.base, evidence, state), "merge, discontinuity")
        finally:
            temporary.cleanup()

    def test_history_rejects_second_state_path(self) -> None:
        temporary, fixture = self.temporary_fixture()
        try:
            write(fixture.repository, "evidence/d0-closure/set/proof", b"proof\n")
            evidence = fixture.commit("evidence")
            write(fixture.repository, GATE.GATE_STATE_PATH, b"{}\n")
            write(fixture.repository, "evidence/d0-closure/set/late", b"late\n")
            state = fixture.commit("state plus evidence")
            self.assertRejected(lambda: GATE.validate_closure_history(fixture.ops, fixture.repository, fixture.base, evidence, state), "state commit must change only")
        finally:
            temporary.cleanup()

    def test_evidence_tree_rejects_symlink_and_submodule(self) -> None:
        temporary, fixture = self.temporary_fixture()
        try:
            write(fixture.repository, "evidence/d0-closure/set/proof", b"proof\n")
            first = fixture.commit("proof")
            digest, entries = GATE.committed_evidence_tree(fixture.ops, fixture.repository, first)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertTrue(any(row["path"].endswith("proof") for row in entries))
            link = fixture.repository / "evidence/d0-closure/set/link"
            link.symlink_to("proof")
            symlink_commit = fixture.commit("symlink")
            self.assertRejected(lambda: GATE.committed_evidence_tree(fixture.ops, fixture.repository, symlink_commit), "not a regular blob")
            git(fixture.repository, "reset", "--hard", first)
            git(fixture.repository, "update-index", "--add", "--cacheinfo", f"160000,{fixture.base},fixtures/d0-v1/basis-inventory/submodule")
            subprocess.run(["git", "-C", str(fixture.repository), "commit", "-m", "submodule"], env=fixture.environment, check=True, stdout=subprocess.PIPE)
            submodule_commit = git(fixture.repository, "rev-parse", "HEAD").stdout.decode().strip()
            self.assertRejected(lambda: GATE.committed_evidence_tree(fixture.ops, fixture.repository, submodule_commit), "not a regular blob")
        finally:
            temporary.cleanup()

    def test_repository_safety_accepts_format_zero_and_rejects_config_attacks(self) -> None:
        for key, value, expected_error in (
            ("include.path", "/tmp/attacker", "forbidden local Git config"),
            ("url.ssh://attacker/.insteadof", "git@", "forbidden local Git config"),
            ("filter.attack.clean", "/tmp/attacker", "forbidden local Git config"),
            ("extensions.partialclone", "origin", "repository format 0 must not have extensions"),
        ):
            with self.subTest(key=key):
                temporary, fixture = self.temporary_fixture()
                try:
                    GATE.verify_repository_safety(fixture.ops, fixture.repository, GATE.GateConfig(repositories=(fixture.expected,)), fixture.expected)
                    git(fixture.repository, "config", key, value)
                    self.assertRejected(lambda: GATE.verify_repository_safety(fixture.ops, fixture.repository, GATE.GateConfig(repositories=(fixture.expected,)), fixture.expected), expected_error)
                finally:
                    temporary.cleanup()

    def test_repository_safety_rejects_alternates_and_promisor(self) -> None:
        for relative, expected_error in (("objects/info/alternates", "forbidden path exists"), ("objects/pack/attack.promisor", "promisor pack state")):
            with self.subTest(relative=relative):
                temporary, fixture = self.temporary_fixture()
                try:
                    write(fixture.repository / ".git", relative, b"/tmp/attacker\n")
                    self.assertRejected(lambda: GATE.verify_repository_safety(fixture.ops, fixture.repository, GATE.GateConfig(repositories=(fixture.expected,)), fixture.expected), expected_error)
                finally:
                    temporary.cleanup()

    def test_index_safety_rejects_assume_unchanged_skip_worktree_and_sparse(self) -> None:
        for arguments, expected_error in (
            (("update-index", "--assume-unchanged", "scripts/d0_gate.py"), "assume-unchanged or skip-worktree"),
            (("update-index", "--skip-worktree", "scripts/d0_gate.py"), "assume-unchanged or skip-worktree"),
            (("sparse-checkout", "set", "scripts"), "sparse-checkout"),
        ):
            with self.subTest(arguments=arguments):
                temporary, fixture = self.temporary_fixture()
                try:
                    git(fixture.repository, *arguments)
                    self.assertRejected(lambda: GATE.verify_index_safety(fixture.ops, fixture.repository, fixture.repository / ".git", fixture.expected), expected_error)
                finally:
                    temporary.cleanup()

    def test_index_safety_rejects_untracked_and_ignored_gate_shadow(self) -> None:
        temporary, fixture = self.temporary_fixture()
        try:
            write(fixture.repository, "evidence/shadow", b"shadow\n")
            self.assertRejected(lambda: GATE.verify_index_safety(fixture.ops, fixture.repository, fixture.repository / ".git", fixture.expected), "dirty")
        finally:
            temporary.cleanup()
        temporary, fixture = self.temporary_fixture()
        try:
            write(fixture.repository, ".gitignore", b"evidence/shadow\n")
            fixture.commit("ignore")
            write(fixture.repository, "evidence/shadow", b"shadow\n")
            self.assertRejected(lambda: GATE.verify_index_safety(fixture.ops, fixture.repository, fixture.repository / ".git", fixture.expected), "ignored gate-sensitive")
        finally:
            temporary.cleanup()

    def test_aterm_parser_enforces_canonical_shape_and_bounds(self) -> None:
        output = "/nix/store/" + "a" * 32 + "-output"
        raw = synthetic_derivation(output, [], json_environment={})
        parsed = GATE.parse_derivation(raw, "synthetic")
        self.assertEqual(parsed["outputs"]["out"]["path"], output)
        self.assertEqual(parsed["jsonEnvironment"], {})
        traditional = GATE.parse_derivation(synthetic_derivation(output, [], environment={"src": "/nix/store/" + "b" * 32 + "-source"}), "traditional")
        self.assertIsNone(traditional["jsonEnvironment"])
        self.assertRejected(lambda: GATE.ATermParser(b"[" * (GATE.MAX_DRV_DEPTH + 2) + b"]" * (GATE.MAX_DRV_DEPTH + 2), "deep").parse(), "nesting exceeds")
        self.assertRejected(lambda: GATE.ATermParser(b'"\\q"', "escape").parse(), "unsupported string escape")
        self.assertRejected(lambda: GATE.ATermParser(b'"a\x00b"', "control").parse(), "literal control byte")
        for invalid_utf8 in (b"\xff", b"\xed\xa0\x80", b"\xc0\xaf", b"\x80"):
            with self.subTest(invalid_utf8=invalid_utf8.hex()):
                self.assertRejected(lambda invalid_utf8=invalid_utf8: GATE.ATermParser(b'"' + invalid_utf8 + b'"', "invalid UTF-8").parse(), "ATerm string is not valid UTF-8")
        self.assertRejected(lambda: GATE.ATermParser(b"x" * (GATE.MAX_DRV_BYTES + 1), "large"), "derivation exceeds")
        self.assertRejected(lambda: GATE.parse_derivation(raw + b"garbage", "trailing"), "trailing ATerm bytes")
        self.assertRejected(lambda: GATE.parse_derivation(b'Derive([],[],[],"x","y",[],[])', "outputs"), "outputs are empty")
        noncanonical_json = synthetic_derivation(output, [], json_environment={"z": 0, "a": 0}).replace(b'{\\"a\\":0,\\"z\\":0}', b'{\\"z\\":0,\\"a\\":0}')
        self.assertRejected(lambda: GATE.parse_derivation(noncanonical_json, "json"), "__json environment is not canonical")
        surrogate_json = synthetic_derivation(output, [], environment={"__json": '{"x":"\\ud800"}'})
        self.assertRejected(lambda: GATE.parse_derivation(surrogate_json, "surrogate json"), "non-Unicode scalar value")

    def test_structured_derivation_rejects_all_ordinary_source_binding_overlaps(self) -> None:
        output = "/nix/store/" + "a" * 32 + "-output"
        source = "/nix/store/" + "b" * 32 + "-source"
        hash_value = "sha256-" + base64.b64encode(b"\x11" * 32).decode()
        url = "https://example.invalid/source.tar.gz"
        cases = {
            "hash": (hash_value, {"hash": hash_value}),
            "outputHash": (hash_value, {"outputHash": hash_value}),
            "outputHashMode": ("flat", {"outputHashMode": "flat"}),
            "src": (source, {"src": source}),
            "srcs": (source, {"srcs": [source]}),
            "urls": (url, {"urls": [url]}),
        }
        for key, (ordinary, structured) in cases.items():
            with self.subTest(key=key):
                raw = synthetic_derivation(output, [], environment={key: ordinary}, json_environment=structured)
                self.assertRejected(lambda raw=raw: GATE.parse_derivation(raw, "structured overlap"), "structured __json conflicts with ordinary source environment bindings")

    def test_nix_store_path_vectors_match_retained_derivations(self) -> None:
        self.assertEqual(GATE.fixed_output_store_path("f689162364c10de79ef89aa8dbf48731eb057e34edbbd20aca510ce0154681a3", "flat", "/nix/store/" + "0" * 32 + "-git-2.54.0.tar.xz", "git"), "/nix/store/drcyzlalnx264vlmp2js5vp2kkvyn132-git-2.54.0.tar.xz")
        self.assertEqual(GATE.fixed_output_store_path("46fcb53e6214306234212fe4c03c267ff56ba2b53cbf589961e8ecb1256ed6b6", "recursive", "/nix/store/" + "0" * 32 + "-source", "nix"), "/nix/store/2ijv0g6069dsh55z3bdr5ln2iv69mw7r-source")

    def test_real_derivation_vector_corpus_integrity(self) -> None:
        self.assertEqual({path.name for path in DRV_VECTOR_ROOT.iterdir()}, {"README.md", "SHA256SUMS", "vectors.json", "drvs"})
        expected_files = {"README.md", "SHA256SUMS", "vectors.json", *EXPECTED_DRV_VECTORS}
        observed_files: set[str] = set()
        for path in DRV_VECTOR_ROOT.rglob("*"):
            relative = path.relative_to(DRV_VECTOR_ROOT).as_posix()
            self.assertFalse(path.is_symlink(), relative)
            if path.is_dir():
                self.assertEqual(relative, "drvs")
            else:
                self.assertTrue(path.is_file(), relative)
                observed_files.add(relative)
        self.assertEqual(observed_files, expected_files)

        manifest_raw = (DRV_VECTOR_ROOT / "SHA256SUMS").read_bytes()
        self.assertTrue(manifest_raw.endswith(b"\n"))
        manifest: dict[str, str] = {}
        for line in manifest_raw.decode("ascii", errors="strict").splitlines():
            digest, relative = line.split("  ", 1)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(GATE.safe_path(relative, "derivation-vector manifest path"), relative)
            self.assertNotIn(relative, manifest)
            manifest[relative] = digest
        self.assertEqual(set(manifest), expected_files - {"SHA256SUMS"})
        for relative, digest in manifest.items():
            self.assertEqual(GATE.sha256((DRV_VECTOR_ROOT / relative).read_bytes()), digest, relative)

        document = drv_vector_document()
        self.assertEqual(set(document), {"capture", "evidenceDisposition", "schema", "scope", "vectors"})
        self.assertEqual(document["schema"], "pkgre-nix-derivation-vectors-v1")
        self.assertEqual(document["scope"], "test-only")
        self.assertEqual(document["evidenceDisposition"], "parser regression fixtures;not D0-B22 satisfaction evidence")
        self.assertEqual(document["capture"], {"capturedAt": "2026-08-26T21:39:32Z", "networkUsed": False, "nixVersion": "2.34.8", "source": "exact retained local /nix/store .drv bytes", "system": "x86_64-linux"})
        vectors = document["vectors"]
        self.assertIsInstance(vectors, list)
        self.assertEqual([row["class"] for row in vectors], ["structured-flat", "structured-recursive", "traditional-recursive"])
        self.assertEqual([row["id"] for row in vectors], ["git-2.54.0-structured-flat-source", "nix-2.34.8-structured-recursive-source", "zvbi-0.2.43-traditional-recursive-source"])
        vector_keys = {"byteLength", "class", "drvHashAlgorithm", "drvHashHex", "fixturePath", "hasTrailingNewline", "hashSRI", "hashSemantics", "id", "inputDerivationCount", "inputSourceCount", "originalStorePath", "outputName", "outputPath", "platform", "provenanceRole", "sha256", "structuredAttrs", "urls"}
        seen_ids: set[str] = set()
        seen_store_paths: set[str] = set()
        for row in vectors:
            self.assertEqual(set(row), vector_keys)
            self.assertRegex(row["id"], r"^[a-z0-9][a-z0-9.-]+$")
            self.assertNotIn(row["id"], seen_ids)
            seen_ids.add(row["id"])
            fixture_path = row["fixturePath"]
            self.assertIn(fixture_path, EXPECTED_DRV_VECTORS)
            expected_length, expected_sha256 = EXPECTED_DRV_VECTORS[fixture_path]
            self.assertEqual((row["byteLength"], row["sha256"]), (expected_length, expected_sha256))
            raw = real_drv_vector(fixture_path)
            self.assertEqual(len(raw), row["byteLength"])
            self.assertEqual(GATE.sha256(raw), row["sha256"])
            self.assertFalse(row["hasTrailingNewline"])
            self.assertFalse(raw.endswith(b"\n"))
            self.assertTrue(raw.endswith(b")"))
            self.assertRegex(row["originalStorePath"], GATE.NIX_DRV_RE)
            self.assertRegex(row["outputPath"], GATE.NIX_STORE_PATH_RE)
            self.assertNotIn(row["originalStorePath"], seen_store_paths)
            seen_store_paths.add(row["originalStorePath"])
            self.assertEqual(row["outputName"], "out")
            self.assertEqual(row["platform"], "x86_64-linux")
            self.assertEqual(row["inputDerivationCount"], 4)
            self.assertEqual(row["inputSourceCount"], 2)
            self.assertEqual(row["structuredAttrs"], row["class"].startswith("structured-"))
            self.assertEqual(row["drvHashAlgorithm"], "sha256" if row["hashSemantics"] == "flat" else "r:sha256")
            self.assertEqual(GATE.sri_from_drv_hash(row["drvHashHex"], row["id"]), row["hashSRI"])
            self.assertIsInstance(row["urls"], list)
            self.assertEqual(len(row["urls"]), 1)
            GATE.validate_https_source_url(row["urls"][0], row["id"])
        self.assertEqual(set(EXPECTED_DRV_VECTORS), {row["fixturePath"] for row in vectors})
        self.assertTrue(GATE.is_d0_path("fixtures/d0-v1/nix-derivation-vectors/vectors.json"))
        self.assertFalse(GATE.is_d0_path("fixtures/d0-v1/nix-derivation-vectors/unreviewed.drv"))

    def test_real_structured_and_traditional_derivation_vectors(self) -> None:
        for row in drv_vector_document()["vectors"]:
            with self.subTest(vector=row["id"]):
                raw = real_drv_vector(row["fixturePath"])
                derivation = GATE.parse_derivation(raw, row["id"])
                self.assertEqual(set(derivation["outputs"]), {"out"})
                self.assertEqual(derivation["outputs"]["out"], {"path": row["outputPath"], "hashAlgorithm": row["drvHashAlgorithm"], "hash": row["drvHashHex"]})
                self.assertEqual(derivation["platform"], row["platform"])
                self.assertEqual(len(derivation["inputDerivations"]), row["inputDerivationCount"])
                self.assertEqual(len(derivation["inputSources"]), row["inputSourceCount"])
                self.assertEqual(derivation["jsonEnvironment"] is not None, row["structuredAttrs"])
                self.assertEqual(GATE.derivation_store_path(raw, derivation, row["originalStorePath"], row["id"]), row["originalStorePath"])
                self.assertEqual(GATE.fixed_output_store_path(row["drvHashHex"], row["hashSemantics"], row["outputPath"], row["id"]), row["outputPath"])
                self.assertEqual(GATE.sri_from_drv_hash(row["drvHashHex"], row["id"]), row["hashSRI"])
                claim, artifact = source_verification_artifact(raw, row["originalStorePath"], row["outputPath"], row["urls"], row["hashSRI"], row["hashSemantics"])
                self.assertEqual(GATE.validate_b22_source_verification(artifact, claim, "git-host", TEST_PACKAGE_DRV, row["id"]), derivation)
                if row["structuredAttrs"]:
                    self.assertEqual(set(derivation["environment"]), {"__json", "out"})
                    json_environment = derivation["jsonEnvironment"]
                    self.assertEqual(json_environment["urls"], row["urls"])
                    self.assertEqual(json_environment["hash"], row["hashSRI"])
                    self.assertEqual(json_environment["outputHash"], row["hashSRI"])
                    self.assertEqual(json_environment["outputHashMode"], row["hashSemantics"])
                else:
                    self.assertIsNone(derivation["jsonEnvironment"])
                    environment = derivation["environment"]
                    self.assertEqual(environment["__structuredAttrs"], "")
                    self.assertEqual(environment["urls"], " ".join(row["urls"]))
                    self.assertEqual(environment["outputHash"], row["hashSRI"])
                    self.assertEqual(environment["outputHashMode"], row["hashSemantics"])

    def test_real_derivation_vectors_reject_byte_and_identity_mutations(self) -> None:
        for row in drv_vector_document()["vectors"]:
            with self.subTest(vector=row["id"], mutation="trailing-byte"):
                raw = real_drv_vector(row["fixturePath"])
                self.assertRejected(lambda raw=raw, row=row: GATE.parse_derivation(raw + b"\n", row["id"]), "trailing ATerm bytes")
            with self.subTest(vector=row["id"], mutation="stale-digest"):
                claim, artifact = source_verification_artifact(raw, row["originalStorePath"], row["outputPath"], row["urls"], row["hashSRI"], row["hashSemantics"])
                verification = GATE.parse_json(artifact, "source verification")
                verification["derivationBase64"] = base64.b64encode(raw + b"\n").decode()
                self.assertRejected(lambda verification=verification, claim=claim, row=row: GATE.validate_b22_source_verification(GATE.canonical_json(verification), claim, "git-host", TEST_PACKAGE_DRV, row["id"]), "source derivation digest mismatch")
            with self.subTest(vector=row["id"], mutation="rehashed-bytes-original-path"):
                original_url = row["urls"][0].encode()
                self.assertIn(original_url, raw)
                changed_raw = raw.replace(original_url, b"https://invalid.example/rehashed-source", 1)
                self.assertNotEqual(changed_raw, raw)
                claim, artifact = source_verification_artifact(changed_raw, row["originalStorePath"], row["outputPath"], row["urls"], row["hashSRI"], row["hashSemantics"])
                with mock.patch.object(GATE, "KNOWN_SURROGATE_DRV_SHA256S", {}):
                    self.assertRejected(lambda artifact=artifact, claim=claim, row=row: GATE.validate_b22_source_verification(artifact, claim, "git-host", TEST_PACKAGE_DRV, row["id"]), "source derivation bytes do not compute to the claimed Nix store path")

    def test_real_derivation_vectors_cannot_satisfy_original_package_records(self) -> None:
        for original_package_drv in GATE.ORIGINAL_PACKAGE_DRVS.values():
            for row in drv_vector_document()["vectors"]:
                with self.subTest(original_package_drv=original_package_drv, vector=row["id"]):
                    raw = real_drv_vector(row["fixturePath"])
                    record = derivation_record("pkgre-d0-original-package-derivation-v2", original_package_drv, raw, [row["originalStorePath"]])
                    self.assertRejected(lambda record=record: GATE.parse_drv_record(record, "production original package record", "pkgre-d0-original-package-derivation-v2"), "derivation bytes do not compute to the claimed Nix store path")

    def test_real_derivation_vectors_reject_declared_environment_mismatches(self) -> None:
        for row in drv_vector_document()["vectors"]:
            raw = real_drv_vector(row["fixturePath"])
            if row["structuredAttrs"]:
                escaped_url_key = b'\\"urls\\":['
                escaped_hash_key = b'\\"outputHash\\":\\"'
                escaped_mode = f'\\"outputHashMode\\":\\"{row["hashSemantics"]}\\"'.encode()
                self.assertIn(escaped_url_key, raw)
                self.assertIn(escaped_hash_key, raw)
                self.assertIn(escaped_mode, raw)
                mutations = (
                    (raw.replace(row["urls"][0].encode(), b"https://invalid.example/structured-source", 1), "__json URLs disagree"),
                    (raw.replace(row["hashSRI"].encode(), GATE.sri_from_drv_hash("ab" * 32, "changed hash").encode()), "__json output/hash fields disagree"),
                    (raw.replace(escaped_mode, f'\\"outputHashMode\\":\\"{"recursive" if row["hashSemantics"] == "flat" else "flat"}\\"'.encode(), 1), "__json outputHashMode disagrees"),
                )
            else:
                url_binding = f'("urls",{aterm_string(" ".join(row["urls"]))})'.encode()
                hash_binding = f'("outputHash",{aterm_string(row["hashSRI"])})'.encode()
                mode_binding = f'("outputHashMode",{aterm_string(row["hashSemantics"])})'.encode()
                self.assertIn(url_binding, raw)
                self.assertIn(hash_binding, raw)
                self.assertIn(mode_binding, raw)
                mutations = (
                    (raw.replace(url_binding, b'("urls","https://invalid.example/traditional-source")', 1), "traditional source URLs disagree"),
                    (raw.replace(hash_binding, f'("outputHash",{aterm_string(GATE.sri_from_drv_hash("cd" * 32, "changed hash"))})'.encode(), 1), "traditional source outputHash disagrees"),
                    (raw.replace(mode_binding, f'("outputHashMode",{aterm_string("flat")})'.encode(), 1), "traditional source outputHashMode disagrees"),
                )
            for changed_raw, expected_error in mutations:
                with self.subTest(vector=row["id"], expected_error=expected_error):
                    self.assertNotEqual(changed_raw, raw)
                    changed_derivation = GATE.parse_derivation(changed_raw, f'{row["id"]} changed')
                    changed_drv = GATE.derivation_store_path(changed_raw, changed_derivation, row["originalStorePath"], f'{row["id"]} changed')
                    claim, artifact = source_verification_artifact(changed_raw, changed_drv, row["outputPath"], row["urls"], row["hashSRI"], row["hashSemantics"])
                    self.assertRejected(lambda artifact=artifact, claim=claim, row=row: GATE.validate_b22_source_verification(artifact, claim, "git-host", TEST_PACKAGE_DRV, row["id"]), expected_error)

    def test_b22_accepts_structured_and_traditional_source_bindings(self) -> None:
        result, package_paths, _source_paths = b22_result()
        self.validateB22(result, package_paths)
        for style in ("structured-src", "traditional-src"):
            with self.subTest(style=style):
                result, package_paths, _ = b22_result(package_styles={"git-host": style, "nix-host": style})
                self.validateB22(result, package_paths)
        for style in ("structured-srcs", "traditional-srcs"):
            with self.subTest(style=style):
                result, package_paths, _ = b22_result(package_styles={"git-host": style, "nix-host": style}, source_counts={"git-host": 2, "nix-host": 2})
                self.validateB22(result, package_paths)
        patch_drv = f"/nix/store/{'b' * 32}-patch-helper.drv"
        result, package_paths, _ = b22_result(package_extra_inputs={"git-host": [patch_drv]})
        self.validateB22(result, package_paths)

    def test_b22_rejects_package_and_source_byte_or_path_substitution(self) -> None:
        result, package_paths, _ = b22_result()
        package = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package")
        package["derivationBase64"] = base64.b64encode(base64.b64decode(package["derivationBase64"]) + b"x").decode()
        result["_references"]["package-git-host"]["raw"] = GATE.canonical_json(package)
        self.assertB22Rejected(result, package_paths, "derivation digest mismatch")

        result, package_paths, _ = b22_result()
        package = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package")
        raw = base64.b64decode(package["derivationBase64"])
        changed_raw = raw.replace(b'"/bin/false"', b'"/bin/true"', 1)
        self.assertNotEqual(changed_raw, raw)
        package["derivationSha256"] = GATE.sha256(changed_raw)
        package["derivationBase64"] = base64.b64encode(changed_raw).decode()
        result["_references"]["package-git-host"]["raw"] = GATE.canonical_json(package)
        self.assertB22Rejected(result, package_paths, "derivation bytes do not compute to the claimed Nix store path")

        result, package_paths, _ = b22_result()
        source = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
        source["derivationBase64"] = base64.b64encode(base64.b64decode(source["derivationBase64"]) + b"x").decode()
        result["_references"]["source-git-host-0"]["raw"] = GATE.canonical_json(source)
        self.assertB22Rejected(result, package_paths, "source derivation digest mismatch")

        result, package_paths, _ = b22_result()
        source = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
        raw = base64.b64decode(source["derivationBase64"])
        changed_raw = raw.replace(b'"/bin/false"', b'"/bin/true"', 1)
        self.assertNotEqual(changed_raw, raw)
        source["derivationSha256"] = GATE.sha256(changed_raw)
        source["derivationBase64"] = base64.b64encode(changed_raw).decode()
        result["_references"]["source-git-host-0"]["raw"] = GATE.canonical_json(source)
        self.assertB22Rejected(result, package_paths, "source derivation bytes do not compute to the claimed Nix store path")

        result, package_paths, _ = b22_result()
        package = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package")
        package["derivationPath"] = package["derivationPath"].replace("git-2.54.0.drv", "other.drv")
        result["_references"]["package-git-host"]["raw"] = GATE.canonical_json(package)
        result["claims"]["tools"][0]["originalPackageDrv"] = package["derivationPath"]
        verification = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
        verification["originalPackageDrv"] = package["derivationPath"]
        result["_references"]["source-git-host-0"]["raw"] = GATE.canonical_json(verification)
        changed_paths = dict(package_paths)
        changed_paths["git-host"] = package["derivationPath"]
        self.assertB22Rejected(result, changed_paths, "derivation bytes do not compute to the claimed Nix store path")

    def test_b22_rejects_input_edge_without_exact_package_source_binding(self) -> None:
        result, package_paths, _ = b22_result(package_styles={"git-host": "none", "nix-host": "traditional-src"})
        self.assertB22Rejected(result, package_paths, "traditional package must declare exactly one")

        arbitrary = "/nix/store/" + "a" * 32 + "-arbitrary.drv"
        result, package_paths, _ = b22_result(package_source_inputs={"git-host": False}, package_extra_inputs={"git-host": [arbitrary]})
        self.assertB22Rejected(result, package_paths, "package ATerm lacks claimed source input edge")

    def test_b22_rejects_ambiguous_duplicate_invalid_and_reordered_bindings(self) -> None:
        result, package_paths, _ = b22_result()
        package = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package")
        raw = base64.b64decode(package["derivationBase64"])
        parsed = GATE.parse_derivation(raw, "package")
        source_output = result["claims"]["tools"][0]["sourceDerivations"][0]["sourceOutput"]
        ambiguous_raw = synthetic_derivation(GATE.OBSERVED_OUTPUTS["git-host"], list(parsed["inputDerivations"]), json_environment={"src": source_output, "srcs": [source_output]})
        ambiguous_path = computed_drv_path(ambiguous_raw, "git-2.54.0.drv")
        package["derivationPath"] = ambiguous_path
        package["derivationSha256"] = GATE.sha256(ambiguous_raw)
        package["derivationBase64"] = base64.b64encode(ambiguous_raw).decode()
        result["_references"]["package-git-host"]["raw"] = GATE.canonical_json(package)
        result["claims"]["tools"][0]["originalPackageDrv"] = ambiguous_path
        verification = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
        verification["originalPackageDrv"] = ambiguous_path
        result["_references"]["source-git-host-0"]["raw"] = GATE.canonical_json(verification)
        changed_paths = dict(package_paths)
        changed_paths["git-host"] = ambiguous_path
        self.assertB22Rejected(result, changed_paths, "structured package must declare exactly one")

        result, package_paths, _ = b22_result(package_styles={"git-host": "structured-srcs", "nix-host": "traditional-src"}, source_counts={"git-host": 2, "nix-host": 1})
        result["claims"]["tools"][0]["sourceDerivations"].reverse()
        self.assertB22Rejected(result, package_paths, "package source-output binding mismatch")

        result, package_paths, _ = b22_result(package_styles={"git-host": "structured-srcs", "nix-host": "traditional-src"}, source_counts={"git-host": 2, "nix-host": 1})
        package = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package")
        raw = base64.b64decode(package["derivationBase64"])
        parsed = GATE.parse_derivation(raw, "package")
        duplicate = result["claims"]["tools"][0]["sourceDerivations"][0]["sourceOutput"]
        duplicate_raw = synthetic_derivation(GATE.OBSERVED_OUTPUTS["git-host"], list(parsed["inputDerivations"]), json_environment={"srcs": [duplicate, duplicate]})
        duplicate_path = computed_drv_path(duplicate_raw, "git-2.54.0.drv")
        package["derivationPath"] = duplicate_path
        package["derivationSha256"] = GATE.sha256(duplicate_raw)
        package["derivationBase64"] = base64.b64encode(duplicate_raw).decode()
        result["_references"]["package-git-host"]["raw"] = GATE.canonical_json(package)
        result["claims"]["tools"][0]["originalPackageDrv"] = duplicate_path
        for source_id in ("source-git-host-0", "source-git-host-1"):
            verification = GATE.parse_json(result["_references"][source_id]["raw"], "source")
            verification["originalPackageDrv"] = duplicate_path
            result["_references"][source_id]["raw"] = GATE.canonical_json(verification)
        changed_paths = dict(package_paths)
        changed_paths["git-host"] = duplicate_path
        self.assertB22Rejected(result, changed_paths, "duplicate package source-output binding")

    def test_b22_rejects_source_fixed_output_and_json_mismatches(self) -> None:
        result, package_paths, _ = b22_result()
        source_ref = result["_references"]["source-git-host-0"]
        verification = GATE.parse_json(source_ref["raw"], "source")
        verification["hashValue"] = "sha256-" + base64.b64encode(b"\x22" * 32).decode()
        source_ref["raw"] = GATE.canonical_json(verification)
        self.assertB22Rejected(result, package_paths, "source-verification hashValue disagrees")

        result, package_paths, _ = b22_result()
        source_ref = result["_references"]["source-git-host-0"]
        verification = GATE.parse_json(source_ref["raw"], "source")
        verification["hashSemantics"] = "recursive"
        result["claims"]["tools"][0]["sourceDerivations"][0]["hashSemantics"] = "recursive"
        source_ref["raw"] = GATE.canonical_json(verification)
        self.assertB22Rejected(result, package_paths, "source output tuple or hash mode mismatch")

        result, package_paths, _ = b22_result(source_json={"git-host-0": False})
        self.validateB22(result, package_paths)

    def test_b22_rejects_traditional_source_environment_mismatches(self) -> None:
        output_hash = "31" * 32
        hash_value = GATE.sri_from_drv_hash(output_hash, "traditional fixture")
        output_placeholder = f"/nix/store/{'0' * 32}-traditional-source"
        source_output = GATE.fixed_output_store_path(output_hash, "flat", output_placeholder, "traditional fixture")
        urls = ["https://example.invalid/source.tar.gz"]
        cases = (
            ({"outputHash": hash_value, "outputHashMode": "flat", "urls": "https://example.invalid/other.tar.gz"}, "traditional source URLs disagree"),
            ({"outputHash": GATE.sri_from_drv_hash("32" * 32, "other hash"), "outputHashMode": "flat", "urls": urls[0]}, "traditional source outputHash disagrees"),
            ({"outputHash": hash_value, "outputHashMode": "recursive", "urls": urls[0]}, "traditional source outputHashMode disagrees"),
        )
        for environment, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                raw = synthetic_derivation(source_output, [], algorithm="sha256", digest=output_hash, environment=environment)
                source_drv = computed_drv_path(raw, "traditional-source.drv")
                claim, artifact = source_verification_artifact(raw, source_drv, source_output, urls, hash_value, "flat")
                self.assertRejected(lambda: GATE.validate_b22_source_verification(artifact, claim, "git-host", TEST_PACKAGE_DRV, "traditional fixture"), expected_error)

    def test_b22_rejects_noncanonical_or_unsafe_source_urls(self) -> None:
        self.assertEqual(GATE.validate_https_source_url("https://example.invalid/a:b@c!$&'()*+,;=~_-", "valid pchar URL"), "https://example.invalid/a:b@c!$&'()*+,;=~_-")
        invalid_urls = (
            "http://example.invalid/source.tar.gz",
            "https://EXAMPLE.invalid/source.tar.gz",
            "https://user@example.invalid/source.tar.gz",
            "https://example.invalid:443/source.tar.gz",
            "https://example.invalid/source.tar.gz?download=1",
            "https://example.invalid/a/../source.tar.gz",
            "https://example.invalid/a//source.tar.gz",
            "https://example.invalid/%2fsource.tar.gz",
            "https://example.invalid/%73ource.tar.gz",
            "https://example.invalid/%GGsource.tar.gz",
            "https://example.invalid/source.tar.gz#fragment",
            "https://127.0.0.1/source.tar.gz",
            "https://0x7f.1/source.tar.gz",
            "https://0177.0.0.1/source.tar.gz",
            "https://127.1/source.tar.gz",
            "https://2130706433/source.tar.gz",
            "https://example.invalid/a[b",
            "https://example.invalid/a]b",
            "https://example.invalid/a|b",
            "https://example.invalid/a^b",
            "https://example.invalid/a`b",
            "https://example.invalid/a{b",
            "https://example.invalid/a}b",
            "https://example.invalid/a\\b",
            "https://example.invalid/a b",
            "https://example.invalid/café",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                result, package_paths, _ = b22_result()
                result["claims"]["tools"][0]["sourceDerivations"][0]["urls"] = [url]
                verification = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
                verification["urls"] = [url]
                result["_references"]["source-git-host-0"]["raw"] = GATE.canonical_json(verification)
                self.assertB22Rejected(result, package_paths, ".urls[0]")

    def test_b22_rejects_known_package_surrogate_and_accepts_exact_known_source(self) -> None:
        result, package_paths, _ = b22_result()
        package = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package")
        digest = package["derivationSha256"]
        with mock.patch.object(GATE, "SURROGATE_PACKAGE_DRV_SHA256S", {digest}):
            self.assertB22Rejected(result, package_paths, "known surrogate package derivation bytes")

        result, package_paths, source_paths = b22_result()
        source = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
        known = dict(GATE.KNOWN_SURROGATE_DRV_SHA256S)
        known[source_paths["git-host-0"]] = source["derivationSha256"]
        with mock.patch.object(GATE, "KNOWN_SURROGATE_DRV_SHA256S", known):
            self.validateB22(result, package_paths)
            forged = GATE.parse_json(result["_references"]["source-git-host-0"]["raw"], "source")
            forged["derivationSha256"] = "0" * 64
            result["_references"]["source-git-host-0"]["raw"] = GATE.canonical_json(forged)
            self.assertB22Rejected(result, package_paths, "known retained derivation path has unexpected bytes")

    def test_b22_rejects_package_surrogate_path_as_source_and_unused_records(self) -> None:
        result, package_paths, source_paths = b22_result()
        surrogate = source_paths["git-host-0"]
        with mock.patch.object(GATE, "SURROGATE_PACKAGE_DRVS", {surrogate}):
            self.assertB22Rejected(result, package_paths, "package-surrogate source derivation")

        result, package_paths, _ = b22_result()
        result["_evidenceByKind"]["source-verification"].append("unused-source")
        result["_references"]["unused-source"] = result["_references"]["source-git-host-0"]
        self.assertB22Rejected(result, package_paths, "unused or missing source verification record")
    def test_b22_rejects_package_record_reference_and_source_edge_stuffing(self) -> None:
        result, package_paths, _ = b22_result()
        result["_evidenceByKind"]["original-derivation-records"].append("unused-package")
        result["_references"]["unused-package"] = result["_references"]["package-git-host"]
        self.assertB22Rejected(result, package_paths, "unused or missing package derivation record")

        result, package_paths, _ = b22_result()
        result["claims"]["tools"][1]["packageRecordRefId"] = "package-git-host"
        self.assertB22Rejected(result, package_paths, "package record is missing,wrong-kind,or reused")

        for mutation in ("missing", "extra", "reordered"):
            with self.subTest(mutation=mutation):
                result, package_paths, _ = b22_result(package_styles={"git-host": "structured-srcs", "nix-host": "traditional-src"}, source_counts={"git-host": 2, "nix-host": 1})
                record = GATE.parse_json(result["_references"]["package-git-host"]["raw"], "package record")
                paths = record["sourceDerivationPaths"]
                if mutation == "missing":
                    record["sourceDerivationPaths"] = paths[:-1]
                elif mutation == "extra":
                    record["sourceDerivationPaths"] = [*paths, result["claims"]["tools"][1]["sourceDerivations"][0]["sourceDrv"]]
                else:
                    record["sourceDerivationPaths"] = list(reversed(paths))
                result["_references"]["package-git-host"]["raw"] = GATE.canonical_json(record)
                self.assertB22Rejected(result, package_paths, "package record source-edge list mismatch")

    def test_b22_accepts_exact_waiver_and_rejects_waiver_mutations(self) -> None:
        GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [b22_waiver_result()])

        result = b22_waiver_result()
        result["_evidenceByKind"]["extra-kind"] = ["waiver-1"]
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "exactly one policy-waiver evidence kind")

        result = b22_waiver_result()
        result["_evidenceByKind"]["policy-waiver"].append("waiver-2")
        result["_references"]["waiver-2"] = result["_references"]["waiver-1"]
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "exactly one policy-waiver evidence document")

        result = b22_waiver_result()
        result["claims"]["decisionDocument"]["sha256"] = "0" * 64
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "decision-document digest mismatch")

        result = b22_waiver_result()
        result["claims"]["scope"] = ["nix-host", "git-host"]
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "waiver scope must be exact")

        result = b22_waiver_result()
        result["claims"]["missingEvidence"] = []
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "nonempty missingEvidence required")

        result = b22_waiver_result()
        result["claims"]["independentAcceptance"] = False
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "independent acceptance required")

        result = b22_waiver_result()
        altered = GATE.parse_json(result["_references"]["waiver-1"]["raw"], "waiver")
        altered["rationale"] = "different rationale"
        altered_raw = GATE.canonical_json(altered)
        altered_sha256 = GATE.sha256(altered_raw)
        result["_references"]["waiver-1"] = {"raw": altered_raw, "sha256": altered_sha256}
        result["claims"]["decisionDocument"]["sha256"] = altered_sha256
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [result]), "immutable waiver document does not exactly match")

    def test_b22_rejects_evidence_kind_and_reference_stuffing(self) -> None:
        result, package_paths, _ = b22_result()
        result["_evidenceByKind"]["arbitrary-extra"] = ["package-git-host"]
        self.assertB22Rejected(result, package_paths, "exact package/source evidence-kind set")

        result, package_paths, _ = b22_result()
        result["_evidenceByKind"]["source-verification"][0] = "package-git-host"
        result["claims"]["tools"][0]["sourceDerivations"][0]["verificationRefId"] = "package-git-host"
        self.assertB22Rejected(result, package_paths, "evidence reference cannot be reused across package/source kinds")

        overstuffed_waiver = {"_evidenceByKind": {"policy-waiver": ["waiver-1", "waiver-2"]}, "_references": {}, "claims": {}}
        self.assertRejected(lambda: GATE.validate_b22("WAIVED_BY_POLICY", "POLICY_WAIVER", [overstuffed_waiver]), "waiver requires exactly one policy-waiver evidence document")


if __name__ == "__main__":
    unittest.main(verbosity=2)
