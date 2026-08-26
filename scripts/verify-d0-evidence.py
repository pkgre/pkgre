#!/usr/bin/env python3
"""Offline integrity and semantic verifier for the committed D0 evidence gate."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

EXPECTED_PACKETS = {
    "basis-refetch",
    "github-governance",
    "git-storage",
    "js-catalog",
    "js-client-policy",
    "live-deployment-network",
    "nginx-raw-target",
    "public-routes",
    "rain-identity-design",
    "resource-time-lifecycle",
    "rust-catalog",
    "ssh-signing",
    "toolchain-closure",
}
MANIFEST_RE = re.compile(r"^([0-9a-f]{64}) ([ *])(.+)$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_CLASSIFICATIONS = {"observed", "proposed", "absent", "blocked"}
CURATED_CARGO_SOURCE = "sparse+https://rust.pkg.re/"


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def read_utf8(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as error:
        raise VerificationError(f"cannot read strict UTF-8 {path}: {error}") from error


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON constant is forbidden: {value}")


def parse_json_text(text: str, label: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=no_duplicate_object, parse_constant=reject_json_constant)
    except (json.JSONDecodeError, VerificationError) as error:
        raise VerificationError(f"invalid JSON in {label}: {error}") from error


def load_json(path: Path) -> Any:
    return parse_json_text(read_utf8(path), str(path))


def normalize_manifest_path(raw: str, manifest: Path, line_number: int) -> str:
    require(raw != "", f"{manifest}:{line_number}: empty manifest path")
    require("\x00" not in raw and "\r" not in raw and "\n" not in raw, f"{manifest}:{line_number}: control byte in path")
    require("\\" not in raw, f"{manifest}:{line_number}: backslash is forbidden in manifest path {raw!r}")
    require(not raw.startswith("/"), f"{manifest}:{line_number}: absolute path {raw!r}")
    require(not raw.endswith("/"), f"{manifest}:{line_number}: directory path {raw!r}")
    parts = raw.split("/")
    if parts and parts[0] == ".":
        parts = parts[1:]
    require(parts and all(part not in {"", ".", ".."} for part in parts), f"{manifest}:{line_number}: unsafe path {raw!r}")
    normalized = "/".join(parts)
    require(normalized != "SHA256SUMS", f"{manifest}:{line_number}: manifest self-reference")
    return normalized


def regular_files_without_symlinks(packet: Path) -> set[str]:
    files: set[str] = set()
    for current, directory_names, file_names in os.walk(packet, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(directory_names):
            path = current_path / name
            mode = path.lstat().st_mode
            require(not stat.S_ISLNK(mode), f"symlink directory forbidden: {path}")
            require(stat.S_ISDIR(mode), f"non-directory in directory list: {path}")
        for name in file_names:
            path = current_path / name
            mode = path.lstat().st_mode
            require(not stat.S_ISLNK(mode), f"symlink file forbidden: {path}")
            require(stat.S_ISREG(mode), f"non-regular evidence object forbidden: {path}")
            relative = path.relative_to(packet).as_posix()
            require(relative not in files, f"duplicate walked path: {packet.name}/{relative}")
            files.add(relative)
    return files


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def verify_packet_manifest(packet: Path) -> int:
    manifest = packet / "SHA256SUMS"
    require(manifest.is_file() and not manifest.is_symlink(), f"missing regular manifest: {manifest}")
    raw_bytes = manifest.read_bytes()
    require(raw_bytes.endswith(b"\n"), f"manifest must end with newline: {manifest}")
    require(b"\r" not in raw_bytes, f"manifest must use LF only: {manifest}")
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(f"manifest is not UTF-8: {manifest}: {error}") from error
    entries: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        require(line != "", f"{manifest}:{line_number}: blank manifest line")
        require(not line.startswith("\\"), f"{manifest}:{line_number}: escaped sha256sum names are unsupported")
        match = MANIFEST_RE.fullmatch(line)
        require(match is not None, f"{manifest}:{line_number}: malformed SHA256SUMS entry")
        expected, _mode, raw_path = match.groups()
        normalized = normalize_manifest_path(raw_path, manifest, line_number)
        require(normalized not in entries, f"{manifest}:{line_number}: duplicate normalized path {normalized!r}")
        entries[normalized] = expected
    actual_files = regular_files_without_symlinks(packet)
    require("SHA256SUMS" in actual_files, f"manifest disappeared while walking: {manifest}")
    covered_files = actual_files - {"SHA256SUMS"}
    require(set(entries) == covered_files, f"{packet.name}: checksum coverage mismatch;missing={sorted(covered_files - set(entries))!r};extra={sorted(set(entries) - covered_files)!r}")
    for relative, expected in entries.items():
        path = packet / Path(*relative.split("/"))
        require(path.is_file() and not path.is_symlink(), f"manifest path is not a regular non-symlink file: {path}")
        actual = sha256_file(path)
        require(actual == expected, f"SHA-256 mismatch: {packet.name}/{relative}: expected {expected},got {actual}")
    return len(entries)


def parse_all_json(packet_root: Path) -> tuple[int, int]:
    json_files = 0
    jsonl_records = 0
    for packet in sorted(packet_root.iterdir(), key=lambda item: item.name):
        for current, _directories, files in os.walk(packet, followlinks=False):
            for name in sorted(files):
                path = Path(current) / name
                if path.suffix == ".json":
                    load_json(path)
                    json_files += 1
                elif path.suffix == ".jsonl":
                    with path.open("r", encoding="utf-8", errors="strict", newline="") as source:
                        for line_number, line in enumerate(source, 1):
                            require("\r" not in line, f"JSONL must use LF only: {path}:{line_number}")
                            if line.strip() == "":
                                continue
                            parse_json_text(line, f"{path}:{line_number}")
                            jsonl_records += 1
    return json_files, jsonl_records


def assert_equal(actual: Any, expected: Any, label: str) -> None:
    require(actual == expected, f"{label}: expected {expected!r},got {actual!r}")


def verify_semantics(root: Path, aggregate: Path) -> None:
    routes = load_json(root / "public-routes" / "validation.json")
    assert_equal(routes["result"], "PASS", "route validation result")
    assert_equal(routes["counts"]["routes"], 2072, "route count")
    assert_equal(routes["counts"]["probeErrors"], 0, "route probe errors")
    assert_equal(routes["checks"]["noDuplicateMappings"], True, "route duplicate check")
    assert_equal(routes["checks"]["uniqueHostRawPath"], True, "route host/raw-path uniqueness")

    rust_validation = load_json(root / "rust-catalog" / "validation.json")
    assert_equal(rust_validation["result"], "PASS", "Rust validation result")
    assert_equal(
        rust_validation["rowCounts"],
        {
            "admissions.jsonl": 3,
            "catalog-homes.jsonl": 911,
            "rendered-routes.jsonl": 563,
            "versions-downloads.jsonl": 747,
        },
        "Rust JSONL row counts",
    )
    rust = load_json(root / "rust-catalog" / "inventory.json")["observedFacts"]
    assert_equal(rust["catalog"]["permanentHomeCount"], 911, "Rust catalog homes")
    assert_equal(rust["catalog"]["activeVersionCount"], 747, "Rust versions")
    assert_equal(rust["render"]["fileCount"], 563, "Rust render files")
    assert_equal(rust["archiveRehearsal"]["archiveCount"], 747, "Rust archive count")
    assert_equal(rust["archiveRehearsal"]["failedCount"], 0, "Rust archive failures")
    assert_equal(rust["archiveRehearsal"]["rawUniqueBytes"], 129833713, "Rust archive bytes")
    assert_equal(rust["archiveRehearsal"]["logicalRouteBytes"], 129833713, "Rust archive route bytes")

    js_validation = load_json(root / "js-catalog" / "validation.json")
    assert_equal(js_validation["result"], "PASS", "JS validation result")
    assert_equal(js_validation["counts"]["packages"], 1, "JS package count")
    assert_equal(js_validation["counts"]["versions"], 1, "JS version count")
    assert_equal(js_validation["counts"]["distTags"], 1, "JS dist-tag count")
    assert_equal(js_validation["counts"]["dependencyEdges"], 0, "JS dependency edges")
    js = load_json(root / "js-catalog" / "inventory.json")["observedFacts"]
    assert_equal(js["catalog"]["counts"]["packages"], 1, "JS inventory package count")
    assert_equal(js["catalog"]["counts"]["versions"], 1, "JS inventory version count")
    assert_equal(js["catalog"]["counts"]["distTags"], 1, "JS inventory dist-tag count")
    assert_equal(js["catalog"]["counts"]["dependencyEdges"], 0, "JS inventory dependency edges")
    assert_equal(js["archives"]["uniqueArchives"], 1, "JS archive count")
    assert_equal(js["archives"]["uniqueContentBytes"], 16717, "JS archive bytes")

    cargo = load_json(root / "rust-catalog" / "cargo-closure.json")
    assert_equal(cargo["lock_package_count"], 174, "Cargo lock package count")
    assert_equal(cargo["workspace_union"]["package_count_including_two_roots"], 174, "Cargo union package count")
    assert_equal(cargo["workspace_union"]["third_party_package_count"], 172, "Cargo union third-party count")
    union: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for root_record in cargo["roots"].values():
        for package in root_record["packages"]:
            key = (package["name"], package["version"], package["source"])
            union.setdefault(key, package)
    assert_equal(len(union), 174, "Cargo unique selected packages")
    local = [package for package in union.values() if package["source"] is None]
    third_party = [package for package in union.values() if package["source"] is not None]
    assert_equal(len(local), 2, "Cargo workspace-local package count")
    assert_equal(len(third_party), 172, "Cargo third-party rows")
    require(all(package["source"] == CURATED_CARGO_SOURCE for package in third_party), "Cargo closure contains a non-curated third-party source")

    signing = load_json(root / "ssh-signing" / "proof.json")
    assert_equal(signing["status"], "PASS", "SSH signing fixture status")
    assert_equal(signing["signing"]["fixtureOnly"], True, "SSH signing fixture-only classification")
    assert_equal(signing["signing"]["keyType"], "ssh-ed25519", "SSH signing key type")
    require(signing["signing"]["principal"].endswith("@example.invalid"), "SSH signing principal is not visibly non-production")
    assert_equal(signing["verification"]["pass"], True, "SSH signing verification")
    assert_equal(signing["verification"]["initialVerifyCommitExitCode"], 0, "initial SSH verification exit")
    assert_equal(signing["verification"]["publicBundleVerifyAfterPrivateDeletionExitCode"], 0, "post-deletion SSH verification exit")

    nginx = load_json(root / "nginx-raw-target" / "summary.json")
    assert_equal(nginx["status"], "primitive-pass-production-blocked", "nginx primitive status")
    assert_equal(nginx["productionBlocking"], True, "nginx production blocker")
    assert_equal(nginx["validation"]["ok"], True, "nginx validation status")
    assert_equal(nginx["validation"]["errorCount"], 0, "nginx validation errors")
    assert_equal(nginx["metrics"]["backendCaptureCount"], 174, "nginx backend captures")

    js_policy = load_json(root / "js-client-policy" / "REPORT.json")
    assert_equal(js_policy["d0Overall"], "BLOCKED", "JS client-policy D0 status")
    assert_equal(js_policy["d1Authorized"], False, "JS client-policy D1 authorization")
    assert_equal(js_policy["subrun"]["status"], "PASS", "JS client-policy subrun")
    assert_equal(js_policy["subrun"]["counts"]["cases"], 66, "JS client-policy cases")
    assert_equal(js_policy["subrun"]["counts"]["unexpectedNetworkConnects"], 0, "JS client-policy unexpected connects")
    assert_equal(js_policy["incident"]["status"], "FAIL-historical", "JS public-contact incident status")

    live = load_json(root / "live-deployment-network" / "REPORT.json")
    assert_equal(live["d0Overall"], "BLOCKED", "live deployment D0 status")
    assert_equal(live["d1Authorized"], False, "live deployment D1 authorization")
    assert_equal(live["classificationCounts"], {"absent": 5, "blocked": 13, "observed": 24, "proposed": 0}, "live claim classification counts")
    computed_classes = {classification: 0 for classification in ALLOWED_CLASSIFICATIONS}
    for claim in live["claims"]:
        classification = claim["classification"]
        require(classification in ALLOWED_CLASSIFICATIONS, f"invalid live claim classification: {classification!r}")
        computed_classes[classification] += 1
    assert_equal(computed_classes, live["classificationCounts"], "computed live claim classifications")
    assert_equal(live["operations"]["secretsRead"], False, "live evidence secret-read boundary")

    git_validation = load_json(root / "git-storage" / "validation.json")
    assert_equal(git_validation["status"], "blocked", "Git/storage D0 status")
    assert_equal(git_validation["d0_gate_pass"], False, "Git/storage D0 gate")
    assert_equal(git_validation["live_deployment_legacy"]["credential_metadata_pass"], False, "credential metadata status")
    critical = git_validation["live_deployment_legacy"]["critical_finding"]
    require("/var/lib/keys/pkgre-js-gandiv5-token" in critical and "0644 root:root" in critical and "value not read" in critical, "critical credential finding changed or disappeared")
    for repository in git_validation["local_git_inventory"]["repositories"]:
        require(HEX40_RE.fullmatch(repository["head"]) is not None, f"noncanonical Git head for {repository['name']}")

    legacy = load_json(root / "git-storage" / "deployment-legacy.json")
    unsafe = legacy["unsafe_credential_metadata"]
    assert_equal(len(unsafe), 1, "unsafe credential metadata row count")
    assert_equal(unsafe[0]["severity"], "critical", "credential severity")
    assert_equal(unsafe[0]["path"], "/var/lib/keys/pkgre-js-gandiv5-token", "credential path")
    require("0644" in unsafe[0]["metadata"] and "root:root" in unsafe[0]["metadata"], "credential owner/mode metadata changed")
    require("value was not read" in unsafe[0]["finding"], "credential no-read boundary missing")
    require("selected LAN instance" in legacy["absent_values"]["lan"], "LAN absence row missing")

    rain = load_json(root / "rain-identity-design" / "design.json")
    assert_equal(rain["document"]["deploymentReady"], False, "Rain proposal deployment readiness")
    assert_equal(rain["document"]["currentObservedDeployment"], False, "Rain proposal current deployment classification")
    require(rain["proposal"]["lanBoundary"].startswith("no LAN instance/config/credential"), "Rain LAN absence boundary changed")

    aggregate_text = read_utf8(aggregate)
    require("gate=BLOCKED" in aggregate_text, "aggregate lacks explicit gate=BLOCKED")
    require("D1 authorized=false" in aggregate_text, "aggregate lacks explicit D1 authorized=false")
    require("OPERATOR-HANDOFF D0" in aggregate_text, "aggregate lacks OPERATOR-HANDOFF D0")
    require("No secret, credential, or private-key value was read or recorded" in aggregate_text, "aggregate lacks secret/private-key boundary")
    for classification in ("OBSERVED", "PROPOSED", "ABSENT", "BLOCKED"):
        require(classification in aggregate_text, f"aggregate lacks {classification} classification")
    for packet in sorted(EXPECTED_PACKETS):
        reference = f"fixtures/d0-v1/basis-inventory/{packet}/"
        require(reference in aggregate_text, f"aggregate does not reference packet {packet}")
    for commit in (
        "066293df21743cbf41fb571a38f2bb94059e7274",
        "f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b",
        "f43bd58bd3d4e36f8b3f4df3c002735c977acd17",
        "5f68539bd99c6952b6d73fe2596c27ad4a319f57",
    ):
        require(commit in aggregate_text, f"aggregate lacks fixed basis {commit}")
    require("freshness limitation" in aggregate_text and "basis-refetch" in aggregate_text, "aggregate does not reconcile the later basis refetch with the older freshness limitation")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    packet_root = repo_root / "fixtures" / "d0-v1" / "basis-inventory"
    aggregate = repo_root / "evidence" / "d0-basis-inventory-2026-08-26.md"
    require(packet_root.is_dir() and not packet_root.is_symlink(), f"missing packet root: {packet_root}")
    children = list(packet_root.iterdir())
    require(all(child.is_dir() and not child.is_symlink() for child in children), "packet root may contain only non-symlink directories")
    actual_packets = {child.name for child in children}
    require(actual_packets == EXPECTED_PACKETS, f"packet directory mismatch;missing={sorted(EXPECTED_PACKETS - actual_packets)!r};extra={sorted(actual_packets - EXPECTED_PACKETS)!r}")
    require(aggregate.is_file() and not aggregate.is_symlink(), f"missing aggregate evidence: {aggregate}")

    covered_files = 0
    for packet_name in sorted(EXPECTED_PACKETS):
        covered_files += verify_packet_manifest(packet_root / packet_name)
    json_files, jsonl_records = parse_all_json(packet_root)
    verify_semantics(packet_root, aggregate)
    print(f"D0 evidence verification: PASS;packets={len(EXPECTED_PACKETS)};manifestFiles={covered_files};jsonFiles={json_files};jsonlRecords={jsonl_records};gate=BLOCKED;D1Authorized=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError) as error:
        print(f"D0 evidence verification: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
