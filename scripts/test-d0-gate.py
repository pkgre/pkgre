#!/usr/bin/env python3
"""Adversarial regression tests for the content-addressed D0/PRE_D1 gate."""

from __future__ import annotations

import base64
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


class GateCoreTests(unittest.TestCase):
    def assertRejected(self, callable_object, text: str) -> None:
        with self.assertRaises(GATE.GateVerificationError) as caught:
            callable_object()
        self.assertIn(text, str(caught.exception))

    def validateB22(self, result: dict[str, object], package_paths: dict[str, str]) -> None:
        with mock.patch.object(GATE, "ORIGINAL_PACKAGE_DRVS", package_paths):
            GATE.validate_b22("SATISFIED", "ORIGINAL_DERIVATION_PROOF", [result])

    def assertB22Rejected(self, result: dict[str, object], package_paths: dict[str, str], text: str) -> None:
        self.assertRejected(lambda: self.validateB22(result, package_paths), text)

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
        return {"_handoffId": handoff_id, "_evidenceByKind": evidence_by_kind, "_references": references, "claims": {"evidenceByKind": evidence_by_kind, "targetGates": [] if target_gates is None else target_gates}}

    def test_generic_semantic_envelopes_bind_exact_handoff_kinds_and_claims(self) -> None:
        limits = self.semanticResult("D0-B10", "OP-D0-06", {"approved-limits": {"test": True}})
        resources = self.semanticResult("D0-B10", "OP-D0-07", {"native-resource-proof": {"test": True}})
        self.assertEqual(GATE.validate_semantic_documents("D0-B10", "SATISFIED", limits), {"approved-limits": {"test": True}})
        self.assertEqual(GATE.validate_semantic_documents("D0-B10", "SATISFIED", resources), {"native-resource-proof": {"test": True}})
        self.assertRejected(lambda: GATE.validate_generic_policy("D0-B10", "SATISFIED", "EVIDENCE_SATISFIED", [limits, resources]), "strict semantic payload validation is not installed")
        self.assertRejected(lambda: GATE.validate_generic_policy("D0-B10", "SATISFIED", "EVIDENCE_SATISFIED", [resources, limits]), "semantic contributions are not in canonical handoff order")

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

        amendment = self.semanticResult("D0-B09", "OP-D0-07", {"phase-amendment": {}}, disposition="REPHASED", target_gates=GATE.REPHASE_TARGETS["D0-B09"])
        self.assertEqual(GATE.validate_semantic_documents("D0-B09", "REPHASED", amendment), {"phase-amendment": {}})
        amendment["claims"]["targetGates"] = ["PRE_D6_EDGE"]
        self.assertRejected(lambda: GATE.validate_semantic_documents("D0-B09", "REPHASED", amendment), "target-gate claim mismatch")

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
