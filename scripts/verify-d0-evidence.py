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
NPM_MINIMUM = "/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2/bin/npm"
NPM_CURRENT = "/nix/store/q72ykn5nq6f88dxvika5vpzj003p2wcz-pkgre-js-compat-node-npm-26.7.0-12.0.2/bin/npm"


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


def section_until_level_two(text: str, marker: str, label: str) -> str:
    require(marker.startswith("## ") or marker.startswith("### "), f"invalid section marker for {label}")
    token = f"{marker}\n"
    require(text.count(token) == 1, f"{label}: expected exactly one section marker {marker!r}")
    remainder = text.split(token, 1)[1]
    next_section = remainder.find("\n## ")
    if next_section != -1:
        remainder = remainder[:next_section]
    return remainder


def verify_semantics(root: Path, aggregate: Path) -> None:
    routes = load_json(root / "public-routes" / "validation.json")
    assert_equal(routes["result"], "PASS", "route validation result")
    assert_equal(routes["counts"]["routes"], 2072, "route count")
    assert_equal(routes["counts"]["probeErrors"], 0, "route probe errors")
    assert_equal(routes["checks"]["noDuplicateMappings"], True, "route duplicate check")
    assert_equal(routes["checks"]["uniqueHostRawPath"], True, "route host/raw-path uniqueness")
    route_report = read_utf8(root / "public-routes" / "REPORT.md")
    require("fixed source-publication routes" in route_report, "route report lacks source-derived scope boundary")
    require("access-log-only unknown aliases" in route_report, "route report lacks access-log-only alias blocker")
    require("none were guessed" in route_report, "route report lacks unknown-route no-invention boundary")

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
    assert_equal(rust["currentCatalogArchives"]["count"], 3, "Rust current catalog body count")
    assert_equal(rust["currentCatalogArchives"]["declaredRoutes"], 747, "Rust declared archive routes")
    assert_equal(rust["currentCatalogArchives"]["missingBodies"], 744, "Rust missing catalog bodies")
    assert_equal(rust["cargo"]["cargoConfig"]["offlineExplicit"], False, "Cargo explicit offline posture")

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

    toolchain = load_json(root / "toolchain-closure" / "inventory.json")
    tool_rows: dict[str, dict[str, Any]] = {}
    for tool in toolchain["tools"]:
        require(tool["id"] not in tool_rows, f"duplicate toolchain row ID: {tool['id']!r}")
        tool_rows[tool["id"]] = tool
    for tool_id in ("nix-host", "git-host"):
        source = tool_rows[tool_id]["source"]
        assert_equal(source["url"], None, f"{tool_id} direct source URL absence")
        assert_equal(source["hash"], None, f"{tool_id} direct source hash absence")
    for tool_id in ("git-flake", "rust-toolchain", "node-indexer", "dev-shell"):
        source = tool_rows[tool_id]["source"]
        assert_equal(source["direct_archive_url"], None, f"{tool_id} direct archive URL absence")
        assert_equal(source["direct_archive_hash"], None, f"{tool_id} direct archive hash absence")
    provenance_blockers = {blocker["id"]: blocker for blocker in toolchain["blockers"]}
    require("direct-source-provenance" in provenance_blockers, "toolchain direct-source-provenance blocker missing")
    require("do not substitute" in provenance_blockers["direct-source-provenance"]["detail"], "toolchain provenance blocker does not reject substitute identities")
    assert_equal(tool_rows["node-minimum"]["effective_executables"]["npm"], NPM_MINIMUM, "minimum npm executable")
    assert_equal(tool_rows["node-current"]["effective_executables"]["npm"], NPM_CURRENT, "current npm executable")
    for profile_name, expected_registry in (("loopback", "http://127.0.0.1:48730/"), ("production", "https://js.pkg.re/")):
        profile = load_json(root / "js-client-policy" / "configs" / profile_name / "profile.json")
        assert_equal(profile["registry"], expected_registry, f"{profile_name} JS registry")
        assert_equal(profile["clients"]["npm-minimum"]["binary"], NPM_MINIMUM, f"{profile_name} minimum npm binary")
        assert_equal(profile["clients"]["npm-current"]["binary"], NPM_CURRENT, f"{profile_name} current npm binary")

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
    live_claims: dict[str, dict[str, Any]] = {}
    for claim in live["claims"]:
        classification = claim["classification"]
        require(classification in ALLOWED_CLASSIFICATIONS, f"invalid live claim classification: {classification!r}")
        require(claim["id"] not in live_claims, f"duplicate live claim ID: {claim['id']!r}")
        live_claims[claim["id"]] = claim
        computed_classes[classification] += 1
    assert_equal(computed_classes, live["classificationCounts"], "computed live claim classifications")
    assert_equal(live["operations"]["secretsRead"], False, "live evidence secret-read boundary")
    retention = live_claims.get("pages-artifact-retention")
    require(retention is not None, "Pages artifact-retention claim missing")
    assert_equal(retention["classification"], "blocked", "Pages artifact-retention classification")
    assert_equal(retention["values"]["durableRollbackBundle"], False, "Pages durable rollback bundle status")
    require("one-day retention" in retention["summary"] and "do not constitute durable D7 rollback bundles" in retention["summary"], "Pages retention claim lost one-day/non-durable boundary")

    live_http = read_utf8(root / "live-deployment-network" / "raw" / "public-dns-tls-http-live.txt")
    rust_default_pages = section_until_level_two(live_http, "## http rust_default_pages", "direct Rust default Pages observation")
    require("status=301\n" in rust_default_pages, "direct Rust default Pages status is not 301")
    require("http_version=2\n" in rust_default_pages, "direct Rust default Pages HTTP version is not 2")
    require("HTTP/2 301 " in rust_default_pages, "direct Rust default Pages wire status is not HTTP/2 301")
    require("redirect_url=https://rust.pkg.re/origin-health/v1.txt\n" in rust_default_pages, "direct Rust default Pages redirect URL changed")
    require("location: https://rust.pkg.re/origin-health/v1.txt\n" in rust_default_pages, "direct Rust default Pages Location changed")
    require("status=200\n" not in rust_default_pages and "HTTP/2 200" not in rust_default_pages, "direct Rust default Pages observation was conflated with a 200 health response")

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
    require("OBSERVED within the enumerated source-derived universe:`2072` unique" in aggregate_text, "aggregate overstates or omits the bounded source-derived route universe")
    require("BLOCKED universal/access-log completeness:" in aggregate_text, "aggregate lacks universal/access-log blocker")
    require("Complete access logs were not captured;access-log-only unknown aliases" in aggregate_text, "aggregate lacks uncaptured access-log-only alias boundary")
    require("universal deployed-path completeness remain unproved" in aggregate_text, "aggregate lacks universal deployed-path blocker")
    require("ABSENT/BLOCKED interim/early-hints `1xx`:not tested or observed" in aggregate_text, "aggregate overstates interim/early-hints 1xx evidence")
    require("interim/early-hints `1xx` behavior was neither tested nor observed" in aggregate_text, "aggregate gate register lacks explicit no-1xx blocker")
    require("direct `https://pkgre.github.io/rust/origin-health/v1.txt`=`HTTP/2 301`" in aggregate_text, "aggregate misstates direct Rust default Pages result")
    require("provider artifacts expired same day" in aggregate_text and "not mirrored to operator-controlled immutable custody" in aggregate_text, "aggregate lacks non-durable Pages rollback boundary")
    require("ABSENT direct upstream archive provenance:" in aggregate_text and "do not substitute for uncaptured direct archive URL+hash rows" in aggregate_text, "aggregate lacks direct toolchain provenance gap")
    require(f"npm={NPM_MINIMUM}" in aggregate_text, "aggregate lacks exact minimum npm executable")
    require(f"npm={NPM_CURRENT}" in aggregate_text, "aggregate lacks exact current npm executable")
    require("it does not mutate a protected catalog to import bodies" in aggregate_text, "aggregate implies D0 archive-body import")
    require("Complete Rust body import is mandatory before D9" in aggregate_text, "aggregate changed Rust body-import phase")
    require("complete JS body import is mandatory before D12" in aggregate_text, "aggregate changed JS body-import phase")
    require("D0 inventories this posture and does not edit config" in aggregate_text, "aggregate implies D0 Cargo-config mutation")
    require("future `pkgre-rust-serve` feature/lock closure and removal of proxy-only `reqwest` closure must be admitted before server implementation" in aggregate_text, "aggregate changed pre-D3 Rust server-closure gate")
    require("`[net] offline=true` is mandatory for self-host/cold-replay fixtures" in aggregate_text, "aggregate changed pre-D5 Cargo offline gate")
    require("D0 does not authorize Rain deployment,DNS or GitHub-setting changes,signer installation,catalog-ref advance,body import,Cargo-config edit,or D1 implementation" in aggregate_text, "aggregate lost D0 mutation/phase stop")
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
