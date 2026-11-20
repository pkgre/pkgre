import assert from "node:assert/strict";
import test from "node:test";

import {
  failureForAncestry,
  failureForCatalogParse,
  failureForObjectState,
  failureForShowFailure,
  failureForSnapshotError,
  isRetryable,
  retryDelaySeconds,
} from "../src/serve/refusal.js";
import { ArchiveStoreError } from "../src/serve/snapshot.js";
import { catalogEntryKind, normalizedCatalogPath } from "../src/serve/watcher.js";

/** The shapes `execFile` fails with, as recorded from Node. */
const exitCode = Object.assign(new Error("Command failed: git show"), { code: 1 });
const timedOut = Object.assign(new Error("Command failed: git show"), { code: null, killed: true, signal: "SIGTERM" });
const spawnFailed = Object.assign(new Error("spawn git ENOENT"), { code: "ENOENT", syscall: "spawn git" });
const overBuffer = Object.assign(new RangeError("stdout maxBuffer length exceeded"), {
  code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
});

test("each object state and ancestry answer has its class", () => {
  assert.equal(failureForObjectState("valid"), null);
  assert.equal(failureForObjectState("not-applicable"), null);
  assert.deepEqual(failureForObjectState("missing"), { class: "local", code: "object-unavailable" });
  assert.deepEqual(failureForObjectState("corrupt"), { class: "local", code: "object-unreadable" });
  assert.deepEqual(failureForObjectState("malformed"), { class: "candidate", code: "not-a-commit" });

  assert.equal(failureForAncestry("descendant"), null);
  assert.equal(failureForAncestry("equal"), null);
  assert.equal(failureForAncestry("not-evaluated"), null);
  assert.deepEqual(failureForAncestry("unknown"), { class: "local", code: "ancestry-unknown" });
  assert.deepEqual(failureForAncestry("predecessor"), { class: "candidate", code: "not-descendant" });
  assert.deepEqual(failureForAncestry("divergent"), { class: "candidate", code: "not-descendant" });
});

test("every failed materialization is classified by its side and its entry", () => {
  for (const entry of ["missing", "blob", "other"]) {
    assert.deepEqual(
      failureForShowFailure({ accepted: true, entry, error: exitCode }),
      { class: "local", code: "materialization-failed" },
      `the accepted side with a ${entry} entry is local`,
    );
  }
  assert.deepEqual(
    failureForShowFailure({ accepted: false, entry: "missing", error: null }),
    { class: "candidate", code: "catalog-path-invalid" },
  );
  for (const error of [exitCode, timedOut, spawnFailed]) {
    assert.deepEqual(
      failureForShowFailure({ accepted: false, entry: "blob", error }),
      { class: "local", code: "materialization-failed" },
      "a regular blob that Git cannot show is local",
    );
  }
  assert.deepEqual(
    failureForShowFailure({ accepted: false, entry: "blob", error: overBuffer }),
    { class: "candidate", code: "candidate-catalog-invalid" },
    "a blob above the output bound is the commit's own",
  );
  for (const entry of ["other"]) {
    assert.deepEqual(
      failureForShowFailure({ accepted: false, entry, error: exitCode }),
      { class: "candidate", code: "catalog-path-invalid" },
      `a ${entry} entry is the commit's own`,
    );
  }
});

test("catalog bytes that are not JSON are classified by their side", () => {
  assert.deepEqual(failureForCatalogParse(false), { class: "candidate", code: "candidate-catalog-invalid" });
  assert.deepEqual(failureForCatalogParse(true), { class: "local", code: "accepted-catalog-unloadable" });
});

test("each snapshot error shape has its class", () => {
  assert.deepEqual(
    failureForSnapshotError(new ArchiveStoreError("serving snapshot body is absent for @scope/helper@1.2.3 at store")),
    { class: "local", code: "archive-store-incomplete" },
  );
  assert.deepEqual(
    failureForSnapshotError(new Error("catalog package @scope/helper has an unknown key")),
    { class: "candidate", code: "snapshot-invalid" },
  );
  assert.deepEqual(
    failureForSnapshotError(new TypeError("snapshot routes must be a Map")),
    { class: "unclassified", code: "internal-error" },
  );
  assert.deepEqual(
    failureForSnapshotError(new RangeError("out of range")),
    { class: "unclassified", code: "internal-error" },
  );
  assert.deepEqual(
    failureForSnapshotError("not an error"),
    { class: "unclassified", code: "internal-error" },
  );
});

test("the retry schedule doubles from one minute to fifteen", () => {
  const waited = [1, 2, 3, 4, 5, 6, 7, 8].map(retryDelaySeconds);
  assert.deepEqual(waited, [60, 120, 240, 480, 900, 900, 900, 900]);
  assert.equal(retryDelaySeconds(0), 60);
});

test("only a local failure is retryable", () => {
  assert.equal(isRetryable({ class: "local" }), true);
  assert.equal(isRetryable({ class: "candidate" }), false);
  assert.equal(isRetryable({ class: "unclassified" }), false);
});

test("the catalog path probe reads plain components", () => {
  assert.equal(normalizedCatalogPath("registry/catalog.json"), "registry/catalog.json");
  assert.equal(normalizedCatalogPath("registry/"), "registry");
  assert.equal(normalizedCatalogPath("registry//sub"), "registry/sub");
  assert.equal(normalizedCatalogPath("registry/./sub"), "registry/sub");
});

test("each catalog entry mode is classified from the ls-tree answer", () => {
  const path = "registry/catalog.json";
  const listed = (mode, type, entryPath) => `${mode} ${type} ${"a".repeat(40)}\t${entryPath}\0`;
  assert.equal(catalogEntryKind(listed("100644", "blob", path), path), "blob");
  assert.equal(catalogEntryKind(listed("100755", "blob", path), path), "blob");
  assert.equal(catalogEntryKind(listed("120000", "blob", path), path), "other", "a symbolic link");
  assert.equal(catalogEntryKind(listed("160000", "commit", path), path), "other", "a gitlink");
  assert.equal(catalogEntryKind(listed("040000", "tree", path), path), "other", "a tree");
  assert.equal(catalogEntryKind("", path), "missing", "no entry");
  assert.equal(catalogEntryKind(listed("100644", "blob", "registry/other.json"), path), "missing", "another path");
  assert.equal(
    catalogEntryKind(`${listed("100644", "blob", "registry/other.json")}${listed("100644", "blob", path)}`, path),
    "blob",
    "the entry at the path among others",
  );
});
