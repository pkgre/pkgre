import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseCanonicalJson } from "../src/canonical.js";
import {
  MAX_TRUSTED_TARGET_BYTES,
  TRUSTED_ORIGINAL_URI_HEADER,
  trustedRequestTarget,
} from "../src/edge.js";

const fixtureUrl = new URL("../../fixtures/dynamic-registry-v1/edge/forwarding.json", import.meta.url);
const RUST_HOST = "rust.pkg.re";
const JS_HOST = "js.pkg.re";

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value), expected, `${label} fields`);
}

function emptyResponse(status) {
  return {
    bodyHex: "",
    headers: { "Cache-Control": "no-store", "Content-Length": "0" },
    status,
  };
}

function decode(record, asciiKey, hexKey, label) {
  const present = [asciiKey, hexKey].filter((key) => Object.hasOwn(record, key));
  assert.equal(present.length, 1, `${label} encoding count`);
  if (present[0] === asciiKey) {
    assert.equal(typeof record[asciiKey], "string", `${label} ASCII encoding`);
    return Buffer.from(record[asciiKey], "ascii");
  }
  assert.match(record[hexKey], /^(?:[0-9a-f]{2})*$/, `${label} hex encoding`);
  return Buffer.from(record[hexKey], "hex");
}

function validateHeaderFields(fields, label) {
  assert.ok(Array.isArray(fields), `${label} must be an array`);
  return fields.map((field, index) => {
    const valueKey = Object.hasOwn(field, "valueAscii") ? "valueAscii" : "valueHex";
    exactKeys(field, ["nameAscii", valueKey], `${label}[${index}]`);
    assert.match(field.nameAscii, /^[\x21-\x7e]+$/, `${label}[${index}] name`);
    return [field.nameAscii, decode(field, "valueAscii", "valueHex", `${label}[${index}] value`)];
  });
}

function canonicalAuthority(authority) {
  return authority.length > 0 && authority.length <= 253 && authority.split(".").every((label) => label.length > 0
    && label.length <= 63
    && !label.startsWith("-")
    && !label.endsWith("-")
    && /^[a-z0-9-]+$/.test(label));
}

function knownHost(host) {
  return host === RUST_HOST || host === JS_HOST;
}

function transportAccepts(target) {
  return target.length > 0
    && target.length <= MAX_TRUSTED_TARGET_BYTES
    && target.every((byte) => byte <= 0x7f
      && byte !== 0x23
      && byte !== 0x20
      && byte !== 0x7f
      && !(byte <= 0x1f));
}

function edgeOutcome(decision, status = undefined, backend = undefined) {
  return {
    decision,
    edgeResponse: status === undefined ? null : emptyResponse(status),
    forwarded: null,
    selectedBackend: backend ?? null,
  };
}

function evaluateEdge(record) {
  assert.ok(record.protocol === "h1" || record.protocol === "h2");
  if (!knownHost(record.sni)) return edgeOutcome("tls-reject");
  const expectedKind = record.protocol === "h1" ? "host" : ":authority";
  if (record.authorityFields.length !== 1 || record.authorityFields[0].kind !== expectedKind) {
    return edgeOutcome("http-reject", 400);
  }
  const authority = record.authorityFields[0].valueAscii;
  if (!canonicalAuthority(authority)) return edgeOutcome("http-reject", 400);
  if (authority !== record.sni) return edgeOutcome("http-reject", 421);
  const target = decode(record, "targetAscii", "targetHex", `${record.id} target`);
  if (!transportAccepts(target)) return edgeOutcome("transport-reject");
  if (target[0] !== 0x2f) return edgeOutcome("http-reject", 400);
  const backend = authority === RUST_HOST ? "rust-protocol" : "js-protocol";
  if (!record.backendAvailable) return edgeOutcome("backend-unavailable", 503, backend);
  const targetAscii = target.toString("ascii");
  return {
    decision: "forward",
    edgeResponse: null,
    forwarded: {
      authority,
      headerFields: [
        { nameAscii: "Host", valueAscii: authority },
        { nameAscii: TRUSTED_ORIGINAL_URI_HEADER, valueAscii: targetAscii },
      ],
      protocol: "h1",
      targetAscii,
    },
    selectedBackend: backend,
  };
}

function listenerReachable(source, listener) {
  return (source === "public" && listener === "public-edge")
    || (source === "edge" && ["rust-protocol", "js-protocol"].includes(listener))
    || (source === "rust-service" && listener === "rust-admin")
    || (source === "js-service" && listener === "js-admin");
}

function validateId(record, ids) {
  assert.match(record.id, /^[a-z][a-z0-9-]*$/);
  assert.ok(!ids.has(record.id), `duplicate case ${record.id}`);
  ids.add(record.id);
}

test("edge forwarding follows the shared vectors", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "edge forwarding fixture");
  exactKeys(fixture, ["forwardingCases", "listenerCases", "policy", "protocolCases", "schema"], "fixture");
  assert.equal(fixture.schema, "pkgre-edge-forwarding-v1");
  assert.deepEqual(fixture.policy, {
    authority: "one protocol-appropriate field with one lowercase canonical hostname and no port; H2 Host plus :authority is rejected",
    backendRequest: "HTTP/1.1 with exact ingress target and exactly two edge-owned fields: Host and X-Pkgre-Original-URI; every client field is dropped",
    backendSelection: "exact known SNI plus exact equal authority only; path and client fields never select a backend",
    backendUnavailableResponse: emptyResponse(503),
    hostRoutes: { "js.pkg.re": "js-protocol", "rust.pkg.re": "rust-protocol" },
    httpBadRequestResponse: emptyResponse(400),
    httpMisdirectedResponse: emptyResponse(421),
    listenerExposure: {
      "js-admin": "service-owned Unix socket",
      "js-protocol": "edge-and-service Unix socket",
      "public-edge": "public TLS TCP",
      "rust-admin": "service-owned Unix socket",
      "rust-protocol": "edge-and-service Unix socket",
    },
    originalTarget: "unnormalized ingress request-target bytes including query",
    precedence: ["tls-sni-validation", "authority-validation", "target-envelope-validation", "backend-availability", "forwarding"],
    protocolBoundary: "raw Host and trusted fields must each occur exactly once; Host must equal configured authority; trusted value must byte-equal backend request target; normalized fallback is forbidden",
    requestTargetEnvelope: "1..1024 ASCII bytes; origin-form beginning with /; fragment, SP, HTAB, CTL, DEL, and non-ASCII forbidden",
    tlsRejection: "connection terminates before HTTP; no HTTP response observable",
    transportRejection: "malformed or over-limit HTTP input is rejected before forwarding; status and framing are parser-specific and excluded",
    trustedHeaderName: TRUSTED_ORIGINAL_URI_HEADER,
  });

  const ids = new Set();
  for (const record of fixture.forwardingCases) {
    validateId(record, ids);
    const targetKey = Object.hasOwn(record, "targetAscii") ? "targetAscii" : "targetHex";
    exactKeys(record, ["authorityFields", "backendAvailable", "clientHeaderFields", "expected", "id", "protocol", "sni", targetKey], record.id);
    for (const [index, field] of record.authorityFields.entries()) {
      exactKeys(field, ["kind", "valueAscii"], `${record.id}.authorityFields[${index}]`);
      assert.ok(field.kind === "host" || field.kind === ":authority");
      assert.equal(typeof field.valueAscii, "string");
    }
    validateHeaderFields(record.clientHeaderFields, `${record.id}.clientHeaderFields`);
    exactKeys(record.expected, ["decision", "edgeResponse", "forwarded", "selectedBackend"], `${record.id}.expected`);
    assert.deepEqual(evaluateEdge(record), record.expected, record.id);
  }
  assert.equal(ids.size, 37);
});

test("protocol boundary follows the shared vectors using raw header fields", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "edge forwarding fixture");
  const ids = new Set();
  for (const record of fixture.protocolCases) {
    validateId(record, ids);
    const targetKey = Object.hasOwn(record, "backendTargetAscii") ? "backendTargetAscii" : "backendTargetHex";
    exactKeys(record, [targetKey, "configuredAuthority", "expected", "headerFields", "id"], record.id);
    const target = decode(record, "backendTargetAscii", "backendTargetHex", `${record.id} target`);
    const rawHeaders = validateHeaderFields(record.headerFields, `${record.id}.headerFields`)
      .flatMap(([name, value]) => [name, value.toString("latin1")]);
    const trusted = trustedRequestTarget(target, rawHeaders, record.configuredAuthority);
    const actual = {
      decision: trusted === undefined ? "reject" : "accept",
      trustedTargetAscii: trusted?.toString("ascii") ?? null,
    };
    assert.deepEqual(actual, record.expected, record.id);
  }
  assert.equal(ids.size, 21);
});

test("listener isolation follows the shared vectors", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "edge forwarding fixture");
  const ids = new Set();
  for (const record of fixture.listenerCases) {
    validateId(record, ids);
    exactKeys(record, ["expectedReachable", "id", "listener", "source"], record.id);
    assert.equal(listenerReachable(record.source, record.listener), record.expectedReachable, record.id);
  }
  assert.equal(ids.size, 15);
});

test("protocol boundary API requires raw bytes and raw header fields", () => {
  assert.throws(() => trustedRequestTarget("/", [], RUST_HOST), /Uint8Array/);
  assert.throws(() => trustedRequestTarget(Buffer.from("/"), {}, RUST_HOST), /string array/);
  assert.throws(() => trustedRequestTarget(Buffer.from("/"), [], Buffer.from(RUST_HOST)), /must be a string/);
});
