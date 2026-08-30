import assert from "node:assert/strict";
import { Blob, Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseCanonicalJson } from "../src/canonical.js";
import {
  ALLOW_METHODS,
  CACHE_CONTROL_ARCHIVE,
  CACHE_CONTROL_METADATA,
  CACHE_CONTROL_NO_STORE,
  CONTENT_TYPE_ARCHIVE,
  CONTENT_TYPE_METADATA_JSON,
  CONTENT_TYPE_METADATA_TEXT,
  evaluateRequest,
  prepareResponse,
} from "../src/http-response.js";
import { canonicalRequestTarget } from "../src/request-target.js";

const fixtureUrl = new URL("../../fixtures/dynamic-registry-v1/http/responses.json", import.meta.url);

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value), expected, `${label} fields`);
}

function assertPolicy(policy) {
  exactKeys(policy, [
    "allowedMethods",
    "applicationErrorBody",
    "applicationErrorCacheControl",
    "compression",
    "entityTag",
    "head",
    "methodRejectionAllow",
    "precedence",
    "range",
    "representationHeaders",
    "transportExcludedHeaders",
  ], "policy");
  assert.deepEqual(policy, {
    allowedMethods: ["GET", "HEAD"],
    applicationErrorBody: "empty",
    applicationErrorCacheControl: CACHE_CONTROL_NO_STORE,
    compression: "no content coding or Vary transformation",
    entityTag: "strong quoted lowercase SHA-256 of exact body bytes with sha256: prefix",
    head: "same status and application-controlled headers as GET with no response body",
    methodRejectionAllow: ALLOW_METHODS,
    precedence: ["raw-target-validation", "method-validation", "exact-route-lookup"],
    range: "ignored; return the complete representation with status 200",
    representationHeaders: {
      archive: { cacheControl: CACHE_CONTROL_ARCHIVE, contentType: CONTENT_TYPE_ARCHIVE },
      "metadata-json": { cacheControl: CACHE_CONTROL_METADATA, contentType: CONTENT_TYPE_METADATA_JSON },
      "metadata-text": { cacheControl: CACHE_CONTROL_METADATA, contentType: CONTENT_TYPE_METADATA_TEXT },
      redirect: { cacheControl: CACHE_CONTROL_NO_STORE, contentType: null },
    },
    transportExcludedHeaders: ["Connection", "Date", "Server"],
  });
}

async function fixtureRoutes(records) {
  const routes = new Map();
  for (const record of records) {
    exactKeys(record, ["path", "response"], `route ${record.path}`);
    assert.equal(canonicalRequestTarget(Buffer.from(record.path, "ascii")), record.path);
    assert.ok(!routes.has(record.path), `duplicate route ${record.path}`);
    const { response } = record;
    let projected;
    if (response.type === "inline") {
      exactKeys(response, ["bodyHex", "representation", "type"], `response ${record.path}`);
      assert.ok(["metadata-json", "metadata-text"].includes(response.representation));
      projected = Object.freeze({
        body: Object.freeze(new Blob([Buffer.from(response.bodyHex, "hex")])),
        representation: response.representation,
        type: "inline",
      });
    } else if (response.type === "archive") {
      exactKeys(response, ["bodyHex", "representation", "sha256", "type"], `response ${record.path}`);
      assert.equal(response.representation, "archive");
      projected = Object.freeze({
        body: Object.freeze(new Blob([Buffer.from(response.bodyHex, "hex")])),
        representation: "archive",
        sha256: response.sha256,
        type: "archive",
      });
    } else {
      assert.equal(response.type, "redirect");
      exactKeys(response, ["location", "representation", "type"], `response ${record.path}`);
      assert.equal(response.representation, "redirect");
      projected = Object.freeze({ location: response.location, type: "redirect" });
    }
    routes.set(record.path, await prepareResponse(projected));
  }
  return routes;
}

async function bodyHex(response) {
  return response.body === undefined ? "" : Buffer.from(await response.body.arrayBuffer()).toString("hex");
}

test("HTTP responses follow the shared vectors", async () => {
  const text = await readFile(fixtureUrl, "utf8");
  const fixture = parseCanonicalJson(text, "HTTP response fixture");
  exactKeys(fixture, ["cases", "policy", "routes", "schema"], "fixture");
  assert.equal(fixture.schema, "pkgre-http-responses-v1");
  assertPolicy(fixture.policy);
  const routes = await fixtureRoutes(fixture.routes);
  const ids = new Set();
  for (const record of fixture.cases) {
    const caseKeys = Object.hasOwn(record, "requestHeaders")
      ? ["expected", "id", "method", "requestHeaders", "targetAscii"]
      : ["expected", "id", "method", "targetAscii"];
    exactKeys(record, caseKeys, record.id);
    exactKeys(record.expected, ["bodyHex", "headers", "status"], `${record.id}.expected`);
    assert.match(record.id, /^[a-z][a-z0-9-]*$/);
    assert.ok(!ids.has(record.id), `duplicate case ${record.id}`);
    ids.add(record.id);
    const actual = evaluateRequest(
      Buffer.from(record.targetAscii, "ascii"),
      record.method,
      record.requestHeaders,
      routes,
    );
    exactKeys(actual, record.expected.bodyHex === "" ? ["headers", "status"] : ["body", "headers", "status"], `${record.id}.actual`);
    assert.equal(actual.status, record.expected.status, record.id);
    assert.deepEqual(actual.headers, record.expected.headers, record.id);
    assert.equal(await bodyHex(actual), record.expected.bodyHex, record.id);
  }
});

test("response preparation computes descriptors once and rejects inconsistent archives", async () => {
  const body = Object.freeze(new Blob(["{}\n"]));
  const prepared = await prepareResponse(Object.freeze({
    body,
    representation: "metadata-json",
    type: "inline",
  }));
  assert.ok(Object.isFrozen(prepared));
  assert.ok(Object.isFrozen(prepared.get));
  assert.ok(Object.isFrozen(prepared.get.headers));
  assert.equal(prepared.get.body, body);
  assert.equal(prepared.head.body, undefined);
  assert.equal(prepared.get.headers, prepared.head.headers);
  assert.throws(() => {
    prepared.get.headers.ETag = "changed";
  }, TypeError);

  await assert.rejects(
    prepareResponse({
      body,
      representation: "archive",
      sha256: "0".repeat(64),
      type: "archive",
    }),
    /SHA-256 does not match/,
  );
});

test("HTTP dispatch validates raw targets before route-map shape", () => {
  assert.equal(evaluateRequest(Buffer.from("/known?query=1"), "GET", undefined, null).status, 400);
  assert.equal(evaluateRequest(Buffer.from("/known"), "POST", undefined, null).status, 405);
  assert.throws(
    () => evaluateRequest(Buffer.from("/known"), "GET", undefined, null),
    /prepared routes must be a Map/,
  );
});
