#!/usr/bin/env python3
"""Content-addressed D0 closure and live PRE_D1 gate verification."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

SCHEMA = "pkgre-d0-gate-state-v2"
AGGREGATE_PATH = "evidence/d0-basis-inventory-2026-08-26.md"
GATE_STATE_PATH = "evidence/d0-gate-state-2026-08-26.json"
HISTORICAL_AGGREGATE_COMMIT = "5b7eb0f201dd9ea2a230d5dcefb6d085294a0cbf"
HISTORICAL_AGGREGATE_SHA256 = "43279e19d0173fbf62096142238d61d2278de548fdad17f07646253e2adbefdd"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
CLOSURE_SET_RE = re.compile(r"^d0-closure-[0-9a-f]{16,64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._@+=,-]+$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
NIX_DRV_RE = re.compile(r"^/nix/store/[0-9a-z]{32}-[^/]+\.drv$")
SRI_SHA256_RE = re.compile(r"^sha256-[A-Za-z0-9+/]{43}=$")
MAX_JSON_BYTES = 1024 * 1024
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
EVIDENCE_TREE_DOMAIN = b"pkgre-d0-evidence-tree-v1\0"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
B18_INCIDENT_SHA256 = "9d06853e9fa692c4b6347af8ac4bb85049d76322c41330768b5782e5df888efe"
B18_INCIDENT_PATH = "fixtures/d0-v1/basis-inventory/js-client-policy/raw/incident.txt"
B18_CONTACT = {"method": "GET", "url": "https://registry.npmjs.org/probe-missing", "responseStatus": 404}
B21_TARGETS = ["https://rust.pkg.re/config.json", "https://js.pkg.re/pkgre-js"]
B21_PROTOCOLS = ["HTTP/1.1", "HTTP/2"]


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
SAT_EVIDENCE = {
    "D0-B01": {"credential-containment", "credential-lifecycle"}, "D0-B02": {"ssh-attestation", "ssh-lifecycle"}, "D0-B03": {"github-governance-proof"}, "D0-B04": {"signing-authority-design", "signing-lifecycle"}, "D0-B05": {"deployment-provenance"}, "D0-B06": {"literal-service-identities", "network-tls-identities"}, "D0-B07": {"distinct-body-identities"}, "D0-B08": {"immutable-rollback-proof", "js-initial-anchor"}, "D0-B09": {"production-edge-proof"}, "D0-B10": {"native-resource-proof", "approved-limits"}, "D0-B11": {"storage-policy", "storage-feasibility-proof"}, "D0-B12": {"clock-policy", "clock-proof"}, "D0-B13": {"protocol-enums", "hard-maxima", "instance-digests"}, "D0-B16": {"js-continuity-proof", "js-initial-anchor"}, "D0-B17": {"deno-current-pin", "scoped-npm-fixture"}, "D0-B20": {"complete-access-log-reconciliation"},
}
REPHASE_TARGETS = {
    "D0-B03": ["D2_SIGNING"], "D0-B04": ["D2_SIGNING"], "D0-B06": ["PRE_D7_FRONTEND_CHANGE_ROLLBACK", "PRE_D7_REAL_RAIN_EDGE"], "D0-B07": ["PRE_D9_RUST_BODIES", "PRE_D12_JS_BODIES"], "D0-B08": ["PRE_D7_FRONTEND_CHANGE_ROLLBACK", "PRE_D11_JS_INITIAL_ANCHOR"], "D0-B09": ["PRE_D6_EDGE", "PRE_D7_REAL_RAIN_EDGE"], "D0-B10": ["D4_BEFORE_D7_RESOURCE_TIME_CLOCK_CRASH"], "D0-B11": ["PRE_D2_STORAGE"], "D0-B12": ["D4_BEFORE_D7_RESOURCE_TIME_CLOCK_CRASH"], "D0-B16": ["PRE_D11_JS_INITIAL_ANCHOR"], "D0-B17": ["PRE_D6_CLIENT_MATRIX"], "D0-B20": ["PRE_D8_RUST_ACCESS_LOG", "PRE_D11_JS_ACCESS_LOG"],
}
ORIGINAL_PACKAGE_DRVS = {"git-host": "/nix/store/bny4hxrsvnaj060b6rbd68233x4fw32h-git-2.54.0.drv", "nix-host": "/nix/store/iza23qnw05vpa85g804b841rd4yqr1z5-nix-2.34.8.drv"}
OBSERVED_OUTPUTS = {"git-host": "/nix/store/k3wl6cg7q50zkx47af3msmg1yrg1f203-git-2.54.0", "nix-host": "/nix/store/kgwqirnzhflf9vmrkzgqz16z2bry397z-nix-2.34.8"}
SURROGATE_DRVS = {"/nix/store/214n5nb1k4qzynzgw7xpsp4fp19vni8i-git-2.54.0.drv", "/nix/store/y9rx70ykgm2hqniaw2qrqp6kqc5n6xbf-nix-2.34.8.drv", "/nix/store/cgrzc3wys8sljv5k23xfmmlzx0s21vjv-git-2.54.0.tar.xz.drv", "/nix/store/1gys5xmkzxr4qbycxl7ilkb15d35z1g2-source.drv"}
D0_ALLOWED_PATHS = {AGGREGATE_PATH, GATE_STATE_PATH, "scripts/verify-d0-evidence.py", "scripts/test-verify-d0-evidence.py", "scripts/d0_gate.py", "scripts/test-d0-gate.py"}
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

    def blob(self, repo: Path, commit: str, relative: str, label: str, max_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
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
        require(raw == canonical_json(value), f"{label}: JSON is not canonical")
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
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


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


def validate_closure_history(ops: GitOps, repo: Path, base: str, evidence_commit: str, state_commit: str) -> dict[str, Any]:
    for label, commit in (("historical", base), ("evidence", evidence_commit), ("state", state_commit)):
        require(HEX40_RE.fullmatch(commit) is not None, f"closure history: invalid {label} commit")
    require(base != state_commit and evidence_commit != state_commit, "closure history: state commit must be distinct")
    require(ops.run(repo, "merge-base", "--is-ancestor", base, state_commit, check=False).returncode == 0, "closure history: historical commit is not an ancestor of state commit")
    commit_ids = parse_nul_paths(ops.run(repo, "rev-list", "--reverse", "--ancestry-path", "-z", f"{base}..{state_commit}").stdout, "closure history commits")
    require(commit_ids and commit_ids[-1] == state_commit, "closure history: state commit is not the validated tip")
    require((commit_ids[-2] if len(commit_ids) >= 2 else base) == evidence_commit, "closure history: evidence commit must immediately precede state commit")
    previous = base
    evidence_changed_paths: list[str] = []
    commits: list[dict[str, Any]] = []
    for commit in commit_ids:
        require(HEX40_RE.fullmatch(commit) is not None, "closure history: invalid rev-list commit")
        parent_row = ops.text(repo, "rev-list", "--parents", "-n", "1", commit).split()
        require(parent_row == [commit, previous], f"closure history: merge, discontinuity, or unexpected parent at {commit}")
        raw_changes = ops.run(repo, "diff-tree", "--no-commit-id", "--name-status", "-r", "-z", "--no-renames", "--no-ext-diff", previous, commit).stdout
        changes = parse_name_status(raw_changes, f"closure history {commit}")
        require(changes, f"closure history: empty commit {commit} is forbidden")
        paths = [path for _status, path in changes]
        if commit == state_commit:
            require(previous == evidence_commit and paths == [GATE_STATE_PATH], "closure history: state commit must change only the gate-state path")
        else:
            require(GATE_STATE_PATH not in paths, f"closure history: gate state changed before final state commit {commit}")
            require(AGGREGATE_PATH not in paths, f"closure history: immutable historical aggregate changed at {commit}")
            forbidden = sorted(path for path in paths if not is_d0_path(path))
            require(not forbidden, f"closure history: forbidden non-D0 paths at {commit}: {forbidden!r}")
            evidence_changed_paths.extend(paths)
        commits.append({"commit": commit, "parent": previous, "changes": [{"status": status, "path": path} for status, path in changes]})
        previous = commit
    return {"commits": commits, "evidenceChangedPaths": sorted(set(evidence_changed_paths))}


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
    exact_keys(raw, {"operatorReturn", "agentVerification", "independentReview"}, label)
    for key in ("operatorReturn", "agentVerification", "independentReview"):
        validate_content_reference(raw[key], f"{label}.{key}")


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


def verify_handoff_evidence(ops: GitOps, repo: Path, evidence_commit: str, closure_id: str, aggregate_sha: str, handoff_id: str, raw_reference: Any) -> dict[str, Any]:
    evidence_reference = obj(raw_reference, f"{handoff_id} evidence reference")
    validate_attestation_reference_shape(evidence_reference, f"{handoff_id} evidence reference")
    prefix = f"evidence/d0-closure/{closure_id}/{handoff_id}/"
    operator_ref, operator_raw = verify_reference(ops, repo, evidence_commit, evidence_reference["operatorReturn"], f"{handoff_id} operator return", prefix, MAX_JSON_BYTES)
    agent_ref, agent_raw = verify_reference(ops, repo, evidence_commit, evidence_reference["agentVerification"], f"{handoff_id} agent verification", prefix, MAX_JSON_BYTES)
    review_ref, review_raw = verify_reference(ops, repo, evidence_commit, evidence_reference["independentReview"], f"{handoff_id} independent review", prefix, MAX_JSON_BYTES)
    require(len({operator_ref["path"], agent_ref["path"], review_ref["path"]}) == 3, f"{handoff_id}: attestation paths must be distinct")
    operator = obj(parse_json(operator_raw, operator_ref["path"]), f"{handoff_id} operator return")
    exact_keys(operator, {"schema", "closureSetId", "handoffId", "aggregateSha256", "returnedBy", "returnedAt", "artifactRefs", "decisionRefs", "findingResults"}, f"{handoff_id} operator return")
    require(operator["schema"] == "pkgre-d0-operator-return-v1" and operator["closureSetId"] == closure_id and operator["handoffId"] == handoff_id and operator["aggregateSha256"] == aggregate_sha, f"{handoff_id}: operator-return binding mismatch")
    nonempty(operator["returnedBy"], f"{handoff_id}.returnedBy")
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
    actor = nonempty(agent["actor"], f"{handoff_id} agent actor")
    completed_at = parse_utc(agent["completedAt"], f"{handoff_id}.completedAt")
    review = obj(parse_json(review_raw, review_ref["path"]), f"{handoff_id} independent review")
    exact_keys(review, {"schema", "closureSetId", "handoffId", "aggregateSha256", "operatorReturnSha256", "agentVerificationSha256", "reviewer", "reviewedAt", "result"}, f"{handoff_id} independent review")
    require(review == {"schema": "pkgre-d0-independent-review-v1", "closureSetId": closure_id, "handoffId": handoff_id, "aggregateSha256": aggregate_sha, "operatorReturnSha256": operator_ref["sha256"], "agentVerificationSha256": agent_ref["sha256"], "reviewer": review.get("reviewer"), "reviewedAt": review.get("reviewedAt"), "result": "ACCEPTED"}, f"{handoff_id}: independent-review binding/result mismatch")
    reviewer = nonempty(review["reviewer"], f"{handoff_id} reviewer")
    reviewed_at = parse_utc(review["reviewedAt"], f"{handoff_id}.reviewedAt")
    require(actor != reviewer, f"{handoff_id}: agent and independent reviewer must be distinct")
    require(returned_at <= completed_at <= reviewed_at, f"{handoff_id}: invalid attestation chronology")
    return {"reference": copy.deepcopy(evidence_reference), "results": results, "operator": operator, "actor": actor, "reviewer": reviewer}


def evidence_ids(result: dict[str, Any], kind: str) -> list[str]:
    return list(result["_evidenceByKind"].get(kind, []))


def require_claim_ref_ids(result: dict[str, Any], claim_value: Any, kind: str, label: str) -> list[str]:
    expected = sorted(evidence_ids(result, kind))
    require(expected and claim_value == expected, f"{label}: must exactly reference {kind!r} evidence IDs")
    return expected


def validate_generic_policy(finding_id: str, disposition: str, mode: str, results: list[dict[str, Any]]) -> None:
    require(finding_id in SAT_EVIDENCE, f"{finding_id}: no generic terminal policy")
    all_kinds = set().union(*(set(result["_evidenceByKind"]) for result in results))
    for result in results:
        claims = obj(result["claims"], f"{finding_id} claims")
        exact_keys(claims, {"summary", "targetGates"}, f"{finding_id} claims")
        nonempty(claims["summary"], f"{finding_id} claims summary")
        arr(claims["targetGates"], f"{finding_id}.targetGates")
    if disposition == "SATISFIED":
        require(mode == "EVIDENCE_SATISFIED", f"{finding_id}: wrong satisfaction mode")
        require(all(result["claims"]["targetGates"] == [] for result in results), f"{finding_id}: satisfied evidence cannot rephase")
        require(SAT_EVIDENCE[finding_id] <= all_kinds, f"{finding_id}: missing mandatory satisfaction evidence kinds {sorted(SAT_EVIDENCE[finding_id] - all_kinds)!r}")
    elif disposition == "REPHASED":
        require(finding_id in REPHASE_TARGETS and mode == "EXACT_PHASE_AMENDMENT", f"{finding_id}: rephasing is not allowed by policy")
        require(all(result["claims"]["targetGates"] == REPHASE_TARGETS[finding_id] for result in results), f"{finding_id}: wrong rephase targets")
        require("phase-amendment" in all_kinds, f"{finding_id}: rephase lacks phase-amendment evidence")
    else:
        raise GateVerificationError(f"{finding_id}: disposition {disposition!r} is forbidden")


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


def decode_bounded_base64(value: Any, label: str) -> bytes:
    text = nonempty(value, label)
    require(len(text) <= 2 * 1024 * 1024, f"{label}: base64 text is too large")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise GateVerificationError(f"{label}: invalid base64: {error}") from error
    require(len(raw) <= 1024 * 1024, f"{label}: decoded capture is too large")
    return raw


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


def validate_b22(disposition: str, mode: str, results: list[dict[str, Any]]) -> None:
    if disposition == "SATISFIED":
        require(mode == "ORIGINAL_DERIVATION_PROOF", "D0-B22: wrong original-proof mode")
        for result in results:
            claims = obj(result["claims"], "D0-B22 original-proof claims")
            exact_keys(claims, {"tools"}, "D0-B22 original-proof claims")
            tools = arr(claims["tools"], "D0-B22 tools")
            require([obj(tool, "D0-B22 tool").get("id") for tool in tools] == ["git-host", "nix-host"], "D0-B22: exact git-host,nix-host rows required")
            for tool in tools:
                tool_id = tool["id"]
                exact_keys(tool, {"id", "observedOutput", "originalPackageDrv", "packageRecordRefId", "sourceDerivations"}, f"D0-B22 {tool_id} row")
                require(tool["observedOutput"] == OBSERVED_OUTPUTS[tool_id] and tool["originalPackageDrv"] == ORIGINAL_PACKAGE_DRVS[tool_id] and tool["originalPackageDrv"] not in SURROGATE_DRVS, f"D0-B22 {tool_id}: original output/package derivation chain mismatch")
                require(tool["packageRecordRefId"] in evidence_ids(result, "original-derivation-records"), f"D0-B22 {tool_id}: package record is not bound to original-derivation evidence")
                sources = arr(tool["sourceDerivations"], f"D0-B22 {tool_id} source derivations")
                require(sources, f"D0-B22 {tool_id}: source derivations are empty")
                seen_drvs: set[str] = set()
                for source in sources:
                    source = obj(source, f"D0-B22 {tool_id} source")
                    exact_keys(source, {"sourceDrv", "urls", "hashAlgorithm", "hashValue", "hashSemantics", "verificationRefId", "verificationResult"}, f"D0-B22 {tool_id} source")
                    source_drv = nonempty(source["sourceDrv"], f"D0-B22 {tool_id} sourceDrv")
                    require(NIX_DRV_RE.fullmatch(source_drv) is not None and source_drv not in SURROGATE_DRVS and source_drv not in seen_drvs, f"D0-B22 {tool_id}: invalid,duplicate,or surrogate source derivation")
                    seen_drvs.add(source_drv)
                    urls = arr(source["urls"], f"D0-B22 {tool_id} URLs")
                    require(urls and all(isinstance(url, str) and url.startswith("https://") for url in urls), f"D0-B22 {tool_id}: HTTPS source URLs required")
                    require(source["hashAlgorithm"] == "sha256" and isinstance(source["hashValue"], str) and (HEX64_RE.fullmatch(source["hashValue"]) or SRI_SHA256_RE.fullmatch(source["hashValue"])), f"D0-B22 {tool_id}: invalid SHA-256")
                    nonempty(source["hashSemantics"], f"D0-B22 {tool_id} hash semantics")
                    require(source["verificationResult"] == "PASS" and source["verificationRefId"] in evidence_ids(result, "source-verification"), f"D0-B22 {tool_id}: source verification is not bound or did not pass")
                    verification = obj(parse_json(result["_references"][source["verificationRefId"]]["raw"], f"D0-B22 {tool_id} source verification"), f"D0-B22 {tool_id} source verification")
                    exact_keys(verification, {"schema", "toolId", "originalPackageDrv", "sourceDrv", "urls", "hashAlgorithm", "hashValue", "hashSemantics", "verificationResult"}, f"D0-B22 {tool_id} source verification")
                    expected = {"schema": "pkgre-d0-source-verification-v1", "toolId": tool_id, "originalPackageDrv": tool["originalPackageDrv"], "sourceDrv": source_drv, "urls": urls, "hashAlgorithm": source["hashAlgorithm"], "hashValue": source["hashValue"], "hashSemantics": source["hashSemantics"], "verificationResult": "PASS"}
                    require(verification == expected, f"D0-B22 {tool_id}: verification artifact does not prove the claimed chain")
    elif disposition == "WAIVED_BY_POLICY":
        require(mode == "POLICY_WAIVER", "D0-B22: wrong waiver mode")
        for result in results:
            claims = obj(result["claims"], "D0-B22 waiver claims")
            exact_keys(claims, {"decisionId", "decisionDocument", "scope", "missingEvidence", "acceptedSubstitutes", "rationale", "residualRisks", "approver", "approvedAt", "policyVersion", "independentAcceptance"}, "D0-B22 waiver claims")
            nonempty(claims["decisionId"], "D0-B22 decision ID")
            document = obj(claims["decisionDocument"], "D0-B22 decision document")
            exact_keys(document, {"refId", "sha256"}, "D0-B22 decision document")
            require(document["refId"] in evidence_ids(result, "policy-waiver"), "D0-B22: decision document is not policy-waiver evidence")
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


def verify_closure(ops: GitOps, repo: Path, state_raw: bytes, state: dict[str, Any], findings: dict[str, dict[str, Any]], items: dict[str, dict[str, Any]], config: GateConfig) -> dict[str, Any]:
    closure = state["closureSet"]
    handoff_evidence: dict[str, dict[str, Any]] = {}
    evidence_commit: str | None = None
    closure_id: str | None = None
    history: dict[str, Any] | None = None
    if closure is None:
        require(all(item["evidence"] is None for item in items.values()), "gate state: handoff evidence requires a closure set")
    else:
        closure = obj(closure, "closure set")
        exact_keys(closure, {"id", "closureEvidenceCommit", "evidenceTreeSha256"}, "closure set")
        closure_id = nonempty(closure["id"], "closure set ID")
        evidence_commit = nonempty(closure["closureEvidenceCommit"], "closure evidence commit")
        evidence_tree_sha = nonempty(closure["evidenceTreeSha256"], "closure evidence-tree SHA-256")
        require(CLOSURE_SET_RE.fullmatch(closure_id) is not None and HEX40_RE.fullmatch(evidence_commit) is not None and HEX64_RE.fullmatch(evidence_tree_sha) is not None, "closure set: invalid ID, evidence commit, or evidence-tree SHA-256")
        current_head = ops.text(repo, "rev-parse", "HEAD")
        require(HEX40_RE.fullmatch(current_head) is not None, "repository HEAD is not SHA-1")
        history = validate_closure_history(ops, repo, config.historical_aggregate_commit, evidence_commit, current_head)
        computed_tree_sha, _tree_entries = committed_evidence_tree(ops, repo, evidence_commit)
        require(evidence_tree_sha == computed_tree_sha, "closure set: committed evidence-tree SHA-256 mismatch")
        require(ops.blob(repo, current_head, GATE_STATE_PATH, "closure gate state", MAX_JSON_BYTES) == state_raw, "working gate state is not the exact closure-state commit blob")
        for handoff_id, item in items.items():
            if item["evidence"] is not None:
                verified = verify_handoff_evidence(ops, repo, evidence_commit, closure_id, config.historical_aggregate_sha256, handoff_id, item["evidence"])
                for result in verified["results"].values():
                    result["_closureSetId"] = closure_id
                handoff_evidence[handoff_id] = verified
        require(handoff_evidence, "closure set must contain at least one reviewed operator return")
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
            require(history is not None, "D0-B21: validated closure history is absent")
            validate_b21(disposition, mode, result_rows, history["evidenceChangedPaths"], config)
        elif finding_id == "D0-B22":
            validate_b22(disposition, mode, result_rows)
        else:
            validate_generic_policy(finding_id, disposition, mode, result_rows)
        if disposition == "WAIVED_BY_POLICY":
            waived_findings.append(finding_id)
    complete_handoffs = sorted(handoff_evidence)
    handoff_complete = set(complete_handoffs) == set(HANDOFFS)
    d0_pass = not open_findings and handoff_complete
    return {"d0Pass": d0_pass, "openFindings": sorted(open_findings), "completeHandoffs": complete_handoffs, "handoffComplete": handoff_complete, "waivedFindings": sorted(waived_findings)}


def verify_repository_anchor(ops: GitOps, repo: Path, aggregate_path: Path, state_path: Path, config: GateConfig) -> tuple[bytes, bytes, dict[str, Any]]:
    aggregate_raw = load_regular(aggregate_path, "aggregate", MAX_JSON_BYTES)
    require(sha256(aggregate_raw) == config.historical_aggregate_sha256, "aggregate digest differs from verifier-pinned historical record")
    committed_aggregate = ops.blob(repo, config.historical_aggregate_commit, AGGREGATE_PATH, "historical aggregate", MAX_JSON_BYTES)
    require(committed_aggregate == aggregate_raw, "working aggregate differs from immutable historical aggregate blob")
    state_raw = load_regular(state_path, "gate state", MAX_JSON_BYTES)
    state = obj(parse_json(state_raw, str(state_path)), "gate state")
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


def verify_pre_d1_receipt(ops: GitOps, repo_root: Path, state_raw: bytes, closure_commit: str, receipt_path: Path, config: GateConfig, now: datetime | None = None) -> None:
    git_dir = Path(ops.text(repo_root, "rev-parse", "--absolute-git-dir")).resolve()
    gate_dir = git_dir / "pkgre-gates"
    try:
        gate_mode = gate_dir.lstat().st_mode
    except OSError as error:
        raise GateVerificationError(f"PRE_D1 gate directory is unavailable: {error}") from error
    require(stat.S_ISDIR(gate_mode) and not stat.S_ISLNK(gate_mode), "PRE_D1 gate directory must be a direct non-symlink directory")
    resolved_receipt = receipt_path.resolve()
    require(resolved_receipt.parent == gate_dir.resolve(), "PRE_D1 receipt must be an external file directly under .git/pkgre-gates")
    receipt_raw = load_regular(resolved_receipt, "PRE_D1 receipt", MAX_JSON_BYTES)
    receipt = obj(parse_json(receipt_raw, str(receipt_path)), "PRE_D1 receipt")
    exact_keys(receipt, {"schema", "d0ClosureCommit", "createdAt", "immediatelyBeforeD1FirstEdit", "repositories", "transcript"}, "PRE_D1 receipt")
    require(receipt["schema"] == "pkgre-pre-d1-refetch-receipt-v2" and receipt["d0ClosureCommit"] == closure_commit and receipt["immediatelyBeforeD1FirstEdit"] is True, "PRE_D1 receipt binding mismatch")
    created = parse_utc(receipt["createdAt"], "PRE_D1 receipt createdAt")
    current_time = now or datetime.now(timezone.utc)
    require((created - current_time).total_seconds() <= 30, "PRE_D1 receipt timestamp is too far in the future")
    require((current_time - created).total_seconds() <= 600, "PRE_D1 receipt is stale")
    transcript = obj(receipt["transcript"], "PRE_D1 transcript reference")
    exact_keys(transcript, {"path", "sha256"}, "PRE_D1 transcript reference")
    transcript_name = safe_path(transcript["path"], "PRE_D1 transcript path")
    require("/" not in transcript_name and transcript_name != resolved_receipt.name, "PRE_D1 transcript must be a distinct sibling file")
    require(HEX64_RE.fullmatch(nonempty(transcript["sha256"], "PRE_D1 transcript digest")) is not None, "PRE_D1 transcript digest is invalid")
    transcript_raw = load_regular(gate_dir / transcript_name, "PRE_D1 transcript", MAX_TRANSCRIPT_BYTES)
    require(sha256(transcript_raw) == transcript["sha256"], "PRE_D1 transcript digest mismatch")
    rows = arr(receipt["repositories"], "PRE_D1 repositories")
    require(len(rows) == len(config.repositories), "PRE_D1 receipt must contain exactly four repositories")
    observed = []
    workspace = repo_root.resolve().parent
    for expected in config.repositories:
        expected_head = closure_commit if expected.id == "pkgre/pkgre" else expected.reviewed_commit
        observed.append(observe_pre_d1_repository(ops, workspace, expected, expected_head, config))
    require(rows == observed, "PRE_D1 receipt repository observations do not exactly match the verifier's live refetch")
    require(ops.blob(repo_root, closure_commit, GATE_STATE_PATH, "PRE_D1 closure state", MAX_JSON_BYTES) == state_raw, "PRE_D1 closure commit does not contain the verified gate state")


def verify_gate(repo_root: Path, aggregate_path: Path, state_path: Path, receipt_path: Path | None = None, now: datetime | None = None, config: GateConfig = PRODUCTION_CONFIG, git_runner: GitRunner = default_git_runner, environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    repo = repo_root.resolve()
    ops = GitOps(git_runner, environment)
    aggregate_raw, state_raw, state = verify_repository_anchor(ops, repo, aggregate_path, state_path, config)
    findings, items = validate_state_shape(state, aggregate_raw, config)
    closure_result = verify_closure(ops, repo, state_raw, state, findings, items, config)
    d0_pass = closure_result["d0Pass"]
    pre_d1_pass = False
    if receipt_path is not None:
        require(d0_pass, "PRE_D1 receipt cannot authorize while D0 is blocked")
        obj(state["closureSet"], "closure set")
        closure_commit = ops.text(repo, "rev-parse", "HEAD")
        verify_pre_d1_receipt(ops, repo, state_raw, closure_commit, receipt_path, config, now)
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
        "mutationAuthority": {"agent": agent_mutation, "operatorRollout": operator_mutation, "operatorEmergencyExceptions": MUTATION_POLICY["operatorEmergencyExceptions"]},
        "laterGateMutationAuthority": later_authority,
    }
