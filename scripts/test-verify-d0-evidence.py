#!/usr/bin/env python3
"""Adversarial regression tests for the D0 evidence semantic verifier."""

from __future__ import annotations

import importlib.util
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER_PATH = REPO_ROOT / "scripts" / "verify-d0-evidence.py"
SOURCE_PACKET_ROOT = REPO_ROOT / "fixtures" / "d0-v1" / "basis-inventory"
SOURCE_AGGREGATE = REPO_ROOT / "evidence" / "d0-basis-inventory-2026-08-26.md"


@dataclass(frozen=True)
class MutationCase:
    name: str
    target: str | None
    old: str
    new: str
    expected_error: str
    replace_all: bool = False


def load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_d0_evidence", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load verifier: {VERIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mutate_text(path: Path, case: MutationCase) -> tuple[bytes, int]:
    original = path.read_bytes()
    original_mode = stat.S_IMODE(path.stat().st_mode)
    text = original.decode("utf-8", errors="strict")
    occurrences = text.count(case.old)
    if occurrences == 0:
        raise RuntimeError(f"{case.name}: mutation source text is absent")
    if case.replace_all:
        mutated = text.replace(case.old, case.new)
    else:
        if occurrences != 1:
            raise RuntimeError(f"{case.name}: expected one mutation source occurrence,got {occurrences}")
        mutated = text.replace(case.old, case.new, 1)
    path.chmod(original_mode | stat.S_IWUSR)
    path.write_text(mutated, encoding="utf-8", newline="")
    return original, original_mode


def expect_rejection(verifier: ModuleType, packet_root: Path, aggregate: Path, case: MutationCase) -> None:
    target = aggregate if case.target is None else packet_root / case.target
    original, original_mode = mutate_text(target, case)
    try:
        try:
            verifier.verify_semantics(packet_root, aggregate)
        except verifier.VerificationError as error:
            if case.expected_error not in str(error):
                raise AssertionError(f"{case.name}: wrong rejection: {error}") from error
        else:
            raise AssertionError(f"{case.name}: semantic verifier accepted adversarial mutation")
    finally:
        target.chmod(original_mode | stat.S_IWUSR)
        target.write_bytes(original)
        target.chmod(original_mode)


CASES = (
    MutationCase(
        "route-source-universe",
        None,
        "OBSERVED within the enumerated source-derived universe:`2072` unique",
        "OBSERVED across the complete deployed universe:`2072` unique",
        "bounded source-derived route universe",
    ),
    MutationCase(
        "route-report-source-scope",
        "public-routes/REPORT.md",
        "Completeness covers fixed source-publication routes",
        "Completeness covers all deployed routes",
        "route report lacks source-derived scope boundary",
    ),
    MutationCase(
        "access-log-blocker",
        None,
        "BLOCKED universal/access-log completeness:",
        "Universal route completeness:",
        "aggregate lacks universal/access-log blocker",
    ),
    MutationCase(
        "interim-1xx-overclaim",
        None,
        "ABSENT/BLOCKED interim/early-hints `1xx`:not tested or observed",
        "OBSERVED interim/early-hints `1xx`:tested and observed",
        "aggregate overstates interim/early-hints 1xx evidence",
    ),
    MutationCase(
        "rust-default-pages-status",
        "live-deployment-network/raw/public-dns-tls-http-live.txt",
        "## http rust_default_pages\nurl=https://pkgre.github.io/rust/origin-health/v1.txt\nstatus=301",
        "## http rust_default_pages\nurl=https://pkgre.github.io/rust/origin-health/v1.txt\nstatus=200",
        "direct Rust default Pages status is not 301",
    ),
    MutationCase(
        "rust-default-pages-wire-status",
        "live-deployment-network/raw/public-dns-tls-http-live.txt",
        "redirect_url=https://rust.pkg.re/origin-health/v1.txt\ncurl_result=success\nHTTP/2 301 ",
        "redirect_url=https://rust.pkg.re/origin-health/v1.txt\ncurl_result=success\nHTTP/2 200 ",
        "direct Rust default Pages wire status is not HTTP/2 301",
    ),
    MutationCase(
        "pages-retention-window",
        "live-deployment-network/REPORT.json",
        "Captured Pages artifacts used one-day retention",
        "Captured Pages artifacts used permanent retention",
        "Pages retention claim lost one-day/non-durable boundary",
    ),
    MutationCase(
        "pages-rollback-durability",
        "live-deployment-network/REPORT.json",
        '"durableRollbackBundle": false',
        '"durableRollbackBundle": true',
        "Pages durable rollback bundle status",
    ),
    MutationCase(
        "direct-toolchain-provenance",
        "toolchain-closure/inventory.json",
        "do not substitute for per-tool direct source provenance",
        "substitute for per-tool direct source provenance",
        "toolchain provenance blocker does not reject substitute identities",
    ),
    MutationCase(
        "minimum-npm-executable",
        "toolchain-closure/inventory.json",
        '"npm": "/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2/bin/npm"',
        '"npm": "/tmp/unpinned-minimum-npm"',
        "minimum npm executable",
    ),
    MutationCase(
        "current-npm-executable",
        "toolchain-closure/inventory.json",
        '"npm": "/nix/store/q72ykn5nq6f88dxvika5vpzj003p2wcz-pkgre-js-compat-node-npm-26.7.0-12.0.2/bin/npm"',
        '"npm": "/tmp/unpinned-current-npm"',
        "current npm executable",
    ),
    MutationCase(
        "production-client-registry",
        "js-client-policy/configs/production/profile.json",
        '"registry": "https://js.pkg.re/"',
        '"registry": "https://registry.npmjs.org/"',
        "production JS registry",
    ),
    MutationCase(
        "production-minimum-npm-executable",
        "js-client-policy/configs/production/profile.json",
        '"binary": "/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2/bin/npm"',
        '"binary": "/tmp/unpinned-production-minimum-npm"',
        "production minimum npm binary",
    ),
    MutationCase(
        "rust-body-import-phase",
        None,
        "Complete Rust body import is mandatory before D9",
        "Complete Rust body import is mandatory before D8",
        "aggregate changed Rust body-import phase",
    ),
    MutationCase(
        "js-body-import-phase",
        None,
        "complete JS body import is mandatory before D12",
        "complete JS body import is mandatory before D11",
        "aggregate changed JS body-import phase",
    ),
    MutationCase(
        "d0-body-import-boundary",
        None,
        "it does not mutate a protected catalog to import bodies",
        "it mutates a protected catalog to import bodies",
        "aggregate implies D0 archive-body import",
    ),
    MutationCase(
        "rust-current-body-gap",
        "rust-catalog/inventory.json",
        '"missingBodies": 744',
        '"missingBodies": 0',
        "Rust missing catalog bodies",
    ),
    MutationCase(
        "cargo-current-offline-posture",
        "rust-catalog/inventory.json",
        '"offlineExplicit": false',
        '"offlineExplicit": true',
        "Cargo explicit offline posture",
    ),
    MutationCase(
        "cargo-d0-edit-boundary",
        None,
        "D0 inventories this posture and does not edit config",
        "D0 inventories this posture and edits config",
        "aggregate implies D0 Cargo-config mutation",
    ),
    MutationCase(
        "rust-server-closure-phase",
        None,
        "future `pkgre-rust-serve` feature/lock closure and removal of proxy-only `reqwest` closure must be admitted before server implementation",
        "future `pkgre-rust-serve` feature/lock closure may be admitted after server implementation",
        "aggregate changed pre-D3 Rust server-closure gate",
    ),
    MutationCase(
        "cargo-offline-phase",
        None,
        "`[net] offline=true` is mandatory for self-host/cold-replay fixtures",
        "`[net] offline=true` is optional for self-host/cold-replay fixtures",
        "aggregate changed pre-D5 Cargo offline gate",
    ),
    MutationCase(
        "d0-mutation-stop",
        None,
        "D0 does not authorize Rain deployment,DNS or GitHub-setting changes,signer installation,catalog-ref advance,body import,Cargo-config edit,or D1 implementation",
        "D0 authorizes deployment and D1 implementation",
        "aggregate lost D0 mutation/phase stop",
    ),
    MutationCase(
        "d1-authorization",
        None,
        "D1 authorized=false",
        "D1 authorized=true",
        "aggregate lacks explicit D1 authorized=false",
        replace_all=True,
    ),
)


def main() -> int:
    verifier = load_verifier()
    with tempfile.TemporaryDirectory(prefix="pkgre-d0-verifier-test-") as temporary:
        temporary_root = Path(temporary)
        packet_root = temporary_root / "basis-inventory"
        aggregate = temporary_root / SOURCE_AGGREGATE.name
        shutil.copytree(SOURCE_PACKET_ROOT, packet_root)
        shutil.copy2(SOURCE_AGGREGATE, aggregate)
        verifier.verify_semantics(packet_root, aggregate)
        for case in CASES:
            expect_rejection(verifier, packet_root, aggregate, case)
        verifier.verify_semantics(packet_root, aggregate)
    print(f"D0 semantic verifier self-test: PASS;mutations={len(CASES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
