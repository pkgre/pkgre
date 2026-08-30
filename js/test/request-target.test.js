import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseCanonicalJson } from "../src/canonical.js";
import { MAX_REQUEST_TARGET_BYTES, canonicalRequestTarget } from "../src/request-target.js";

const fixtureUrl = new URL("../../fixtures/dynamic-registry-v1/http/raw-targets.json", import.meta.url);

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value), expected, `${label} fields`);
}

function decodeTarget(record) {
  const encodings = ["targetAscii", "targetHex"].filter((key) => Object.hasOwn(record, key));
  assert.deepEqual(encodings.length, 1, `${record.id} target encoding count`);
  if (encodings[0] === "targetAscii") {
    assert.equal(typeof record.targetAscii, "string");
    return Buffer.from(record.targetAscii, "ascii");
  }
  assert.match(record.targetHex, /^(?:[0-9a-f]{2})*$/);
  return Buffer.from(record.targetHex, "hex");
}

test("canonical raw request targets follow the shared vectors", async () => {
  const text = await readFile(fixtureUrl, "utf8");
  const fixture = parseCanonicalJson(text, "raw target fixture");
  exactKeys(fixture, ["cases", "policy", "schema"], "fixture");
  assert.equal(fixture.schema, "pkgre-raw-request-targets-v1");
  assert.deepEqual(fixture.policy, {
    allowedGenericSegmentAscii: "A-Z a-z 0-9 . _ ~ + @ -",
    allowedPercentEscape: "one lowercase %2f in a canonical scoped JavaScript metadata path only",
    maximumRequestTargetBytes: MAX_REQUEST_TARGET_BYTES,
    scopedJavaScriptComponentPattern: "^[a-z][a-z0-9._~-]*$",
    scopedJavaScriptMaximumPackageBytes: 214,
    targetForm: "origin-form path without query or fragment",
  });

  const ids = new Set();
  for (const record of fixture.cases) {
    assert.ok(!ids.has(record.id), `duplicate case ${record.id}`);
    ids.add(record.id);
    assert.match(record.id, /^[a-z][a-z0-9-]*$/);
    exactKeys(record.expected, record.expected.kind === "canonical" ? ["kind", "path"] : ["kind"], `${record.id}.expected`);
    exactKeys(record, Object.hasOwn(record, "targetAscii") ? ["expected", "id", "targetAscii"] : ["expected", "id", "targetHex"], record.id);
    const actual = canonicalRequestTarget(decodeTarget(record));
    if (record.expected.kind === "canonical") assert.equal(actual, record.expected.path, record.id);
    else {
      assert.equal(record.expected.kind, "reject", record.id);
      assert.equal(actual, undefined, record.id);
    }
  }
});

test("raw request target API requires bytes", () => {
  assert.throws(() => canonicalRequestTarget("/config.json"), /must be a Uint8Array/);
});
