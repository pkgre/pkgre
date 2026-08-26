#!/usr/bin/env python3
"""Adversarial regression tests for the content-addressed D0/PRE_D1 gate."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "scripts" / "d0_gate.py"


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


class GateCoreTests(unittest.TestCase):
    def assertRejected(self, callable_object, text: str) -> None:
        with self.assertRaises(GATE.GateVerificationError) as caught:
            callable_object()
        self.assertIn(text, str(caught.exception))

    def temporary_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], RepositoryFixture]:
        temporary = tempfile.TemporaryDirectory(prefix="pkgre-d0-gate-test-")
        return temporary, RepositoryFixture(Path(temporary.name))

    def finish_linear_history(self, fixture: RepositoryFixture) -> tuple[str, str]:
        write(fixture.repository, "evidence/d0-closure/set/proof.json", b"{}\n")
        evidence = fixture.commit("evidence")
        write(fixture.repository, GATE.GATE_STATE_PATH, b"{}\n")
        state = fixture.commit("state")
        return evidence, state

    def test_strict_json_and_paths(self) -> None:
        self.assertRejected(lambda: GATE.parse_json(b'{"x":1,"x":2}\n', "duplicate"), "duplicate JSON object key")
        self.assertRejected(lambda: GATE.safe_path("evidence/d0-closure/../x", "path"), "noncanonical")
        self.assertRejected(lambda: GATE.safe_path("evidence/d0-closureevil/x", "path", "evidence/d0-closure/"), "strictly under")
        self.assertRejected(lambda: GATE.safe_path("evidence/d0-closure/x y", "path"), "unsupported path component")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
