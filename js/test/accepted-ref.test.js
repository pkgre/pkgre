import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ACCEPTED_REF_SCHEMA,
  canonicalAcceptedRefBytes,
  deriveRepositoryIdentity,
  evaluateAcceptedRefReload,
  evaluateAcceptedRefStartup,
  parseAcceptedRef,
} from "../src/accepted-ref.js";
import { parseCanonicalJson } from "../src/canonical.js";

const fixtureUrl = new URL("../../fixtures/dynamic-registry-v1/state/accepted-ref-transitions.json", import.meta.url);

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value), expected, `${label} fields`);
}

function recordFromFixture(record) {
  exactKeys(record, ["acceptedCommit", "fullRef", "id", "repositoryIdentity", "schema"], record.id);
  return {
    acceptedCommit: record.acceptedCommit,
    fullRef: record.fullRef,
    repositoryIdentity: record.repositoryIdentity,
    schema: record.schema,
  };
}

function assertPolicy(policy) {
  exactKeys(policy, [
    "acceptedRecordFields",
    "acceptedRecordSchema",
    "bootstrap",
    "candidateValidationOrder",
    "identityDerivation",
    "identityDomain",
    "origin",
    "persistence",
    "publication",
    "restartAuthority",
    "stateExcludes",
  ], "policy");
  assert.deepEqual(policy, {
    acceptedRecordFields: ["acceptedCommit", "fullRef", "repositoryIdentity", "schema"],
    acceptedRecordSchema: ACCEPTED_REF_SCHEMA,
    bootstrap: "only when the accepted-record path is absent; any present malformed or mismatched record forbids bootstrap",
    candidateValidationOrder: [
      "candidate-shape",
      "repository-identity",
      "full-ref",
      "commit-object",
      "ancestry",
      "semantic-validity",
      "durable-persistence",
      "publication",
    ],
    identityDerivation: "SHA-256(domain || u32be(origin length) || origin bytes || u32be(full-ref length) || full-ref bytes)",
    identityDomain: "pkgre-repository-identity-v1\\0",
    origin: "credential-free operator-supplied canonical UTF-8 bytes; no implementation-specific normalization",
    persistence: "write temporary file,fsync file,atomic rename,fsync containing directory",
    publication: "only after complete semantic validation and successful durable persistence",
    restartAuthority: "accepted record only after bootstrap; remote and arbitrary local commits are never startup authority",
    stateExcludes: ["rendered responses", "cache state", "origin URL", "credentials", "filesystem paths", "timestamps"],
  });
}

test("accepted-ref startup and reload decisions follow shared vectors", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "accepted-ref fixture");
  exactKeys(fixture, ["acceptedRecords", "policy", "reloadCases", "repository", "schema", "startupCases"], "fixture");
  assert.equal(fixture.schema, "pkgre-accepted-ref-transitions-v1");
  assertPolicy(fixture.policy);
  exactKeys(fixture.repository, ["bootstrapCommit", "canonicalOrigin", "fullRef", "identity"], "repository");
  const config = {
    fullRef: fixture.repository.fullRef,
    repositoryIdentity: fixture.repository.identity,
  };
  assert.equal(
    deriveRepositoryIdentity(Buffer.from(fixture.repository.canonicalOrigin), Buffer.from(fixture.repository.fullRef)),
    fixture.repository.identity,
  );
  const parsedOrigin = new URL(fixture.repository.canonicalOrigin);
  assert.equal(parsedOrigin.username, "");
  assert.equal(parsedOrigin.password, "");

  const records = new Map();
  for (const source of fixture.acceptedRecords) {
    assert.match(source.id, /^[a-z][a-z0-9-]*$/);
    assert.ok(!records.has(source.id), `duplicate accepted record ${source.id}`);
    records.set(source.id, recordFromFixture(source));
  }

  const startupIds = new Set();
  for (const record of fixture.startupCases) {
    exactKeys(record, [
      "acceptedRecord",
      "acceptedRecordState",
      "bootstrapObject",
      "expected",
      "id",
      "localAcceptedObject",
      "remoteObservation",
    ], record.id);
    exactKeys(record.expected, ["acceptedCommit", "activeCommit", "decision", "persistRecord", "reason"], `${record.id}.expected`);
    assert.match(record.id, /^[a-z][a-z0-9-]*$/);
    assert.ok(!startupIds.has(record.id), `duplicate startup case ${record.id}`);
    startupIds.add(record.id);
    assert.ok(["absent", "malformed", "present"].includes(record.acceptedRecordState));
    assert.ok(["corrupt", "missing", "not-applicable", "valid"].includes(record.localAcceptedObject));
    assert.ok(["corrupt", "missing", "valid"].includes(record.bootstrapObject));
    assert.ok(["descendant", "offline", "predecessor"].includes(record.remoteObservation));
    if (record.acceptedRecord !== null) exactKeys(record.acceptedRecord, ["acceptedCommit", "fullRef", "repositoryIdentity", "schema"], `${record.id}.acceptedRecord`);
    const actual = evaluateAcceptedRefStartup({
      acceptedRecord: record.acceptedRecord,
      acceptedRecordState: record.acceptedRecordState,
      bootstrapCommit: fixture.repository.bootstrapCommit,
      bootstrapObject: record.bootstrapObject,
      localAcceptedObject: record.localAcceptedObject,
    }, config);
    assert.deepEqual(actual, record.expected, record.id);
  }

  const reloadIds = new Set();
  for (const record of fixture.reloadCases) {
    exactKeys(record, ["candidate", "expected", "id", "startingAcceptedRecord"], record.id);
    exactKeys(record.expected, ["acceptedCommit", "activeCommit", "candidateLoad", "decision", "persistRecord", "reason"], `${record.id}.expected`);
    assert.match(record.id, /^[a-z][a-z0-9-]*$/);
    assert.ok(!reloadIds.has(record.id), `duplicate reload case ${record.id}`);
    reloadIds.add(record.id);
    assert.ok(records.has(record.startingAcceptedRecord), `${record.id} references an unknown accepted record`);
    if (record.candidate !== null) {
      exactKeys(record.candidate, [
        "ancestry",
        "commit",
        "fullRef",
        "objectState",
        "persistence",
        "repositoryIdentity",
        "semanticValidity",
        "suppressed",
      ], `${record.id}.candidate`);
      assert.ok(["descendant", "divergent", "equal", "not-evaluated", "predecessor", "unknown"].includes(record.candidate.ancestry));
      assert.ok(["malformed", "missing", "valid"].includes(record.candidate.objectState));
      assert.ok(["interrupted-before-rename", "not-attempted", "success"].includes(record.candidate.persistence));
      assert.ok(["invalid", "not-evaluated", "valid"].includes(record.candidate.semanticValidity));
    }
    const actual = evaluateAcceptedRefReload(records.get(record.startingAcceptedRecord), record.candidate, config);
    assert.deepEqual(actual, record.expected, record.id);
    if (!["accept-forward", "unchanged"].includes(actual.decision)) {
      assert.equal(actual.acceptedCommit, records.get(record.startingAcceptedRecord).acceptedCommit, record.id);
      assert.equal(actual.activeCommit, records.get(record.startingAcceptedRecord).acceptedCommit, record.id);
    }
  }
});

test("accepted-ref record bytes are canonical, closed, and configuration-bound", () => {
  const config = {
    fullRef: "refs/heads/main",
    repositoryIdentity: "b21a526d67a4251222f87dde72f2e6e99f0cdc4c9eb66d8e504aa0ed2483b456",
  };
  const record = {
    acceptedCommit: "1".repeat(40),
    fullRef: config.fullRef,
    repositoryIdentity: config.repositoryIdentity,
    schema: ACCEPTED_REF_SCHEMA,
  };
  const bytes = canonicalAcceptedRefBytes(record, config);
  assert.equal(bytes.at(-1), 0x0a);
  assert.ok(Object.isFrozen(parseAcceptedRef(bytes, config)));
  assert.deepEqual(parseAcceptedRef(bytes, config), record);
  assert.throws(() => parseAcceptedRef(Buffer.from(JSON.stringify(record)), config), /not canonical JSON/);
  assert.throws(() => parseAcceptedRef(Buffer.from("{\"schema\":\"a\",\"schema\":\"b\"}\n"), config), /repeats object key/);
  assert.throws(() => canonicalAcceptedRefBytes({ ...record, extra: true }, config), /unexpected fields/);
  assert.throws(() => canonicalAcceptedRefBytes({ ...record, acceptedCommit: "A".repeat(40) }, config), /lowercase hexadecimal/);
  assert.throws(
    () => parseAcceptedRef(bytes, { ...config, repositoryIdentity: "a".repeat(64) }),
    /does not match configuration/,
  );
  assert.throws(() => parseAcceptedRef(Uint8Array.from([0xff]), config), /not UTF-8/);
});
