import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  packageIdentity,
  packageMetadataPath,
  parseCanonicalJson,
  parseJsonNoDuplicateKeys,
  validatePackageName,
  validateVersion,
} from "../src/canonical.js";

test("canonical JSON recursively sorts keys and rejects unstable values", () => {
  assert.equal(canonicalJson({ z: 1, a: { z: false, a: ["x", null] } }), '{\n  "a": {\n    "a": [\n      "x",\n      null\n    ],\n    "z": false\n  },\n  "z": 1\n}\n');
  assert.deepEqual(parseCanonicalJson('{\n  "a": 1,\n  "b": 2\n}\n'), { a: 1, b: 2 });
  assert.throws(() => parseCanonicalJson('{"b":2,"a":1}\n'), /not canonical JSON/);
  assert.throws(() => canonicalJson({ value: 1.5 }), /non-safe-integer/);
  assert.throws(() => canonicalJson({ value: undefined }), /unsupported JSON value/);
});

test("strict JSON parsing rejects duplicate keys and parser ambiguities", () => {
  assert.deepEqual(parseJsonNoDuplicateKeys('{"escaped\\u006bey":1,"array":[true,false,null,-2.5e1]}'), {
    escapedkey: 1,
    array: [true, false, null, -25],
  });
  const prototypeKeys = parseJsonNoDuplicateKeys('{"__proto__":{"polluted":true},"constructor":1,"prototype":2}');
  assert.equal(Object.hasOwn(prototypeKeys, "__proto__"), true);
  assert.equal(prototypeKeys.__proto__.polluted, true);
  assert.equal({}.polluted, undefined);
  assert.equal(canonicalJson(prototypeKeys), '{\n  "__proto__": {\n    "polluted": true\n  },\n  "constructor": 1,\n  "prototype": 2\n}\n');
  for (const text of [
    '{"key":1,"key":2}',
    '{"key":1,"\\u006bey":2}',
    '{"nested":{"key":1,"key":2}}',
    '{"value":01}',
    '{"value":1} trailing',
    '{"value":"\\ud800"}',
    `[${"[".repeat(129)}null${"]".repeat(129)}]`,
  ]) {
    assert.throws(() => parseJsonNoDuplicateKeys(text), /JSON/);
  }
});

test("package names use one strict proxy-compatible canonical form", () => {
  for (const name of ["pkgre-js", "a", "a.b_c~d-1", "@pkgre/indexer", "@a1/pkg.name"]) {
    assert.equal(validatePackageName(name), name);
    assert.equal(packageMetadataPath(name), name);
  }
  for (const name of [
    "",
    "A",
    "1package",
    ".package",
    "_package",
    "package name",
    "package%2fname",
    "package/name",
    "@scope",
    "@scope/",
    "@Scope/package",
    "@1scope/package",
    "@scope/Package",
    "@scope/package/extra",
    "v1",
    "packages",
    "origin-health",
    "nonproduction",
    "index.html",
    "é",
  ]) {
    assert.throws(() => validatePackageName(name), /invalid/);
  }
  assert.throws(() => validatePackageName(`a${"b".repeat(214)}`), /invalid/);
  assert.throws(() => validatePackageName(`@${"s".repeat(107)}/${"p".repeat(107)}`), /invalid/);
});

test("versions are canonical SemVer 2.0 strings", () => {
  for (const version of ["0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3-0", "1.2.3+build.9", "1.2.3-alpha+build"]) {
    assert.equal(validateVersion(version), version);
  }
  for (const version of ["", "1", "1.2", "01.2.3", "1.02.3", "1.2.03", "v1.2.3", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3+bad_1", "1.2.3\n"]) {
    assert.throws(() => validateVersion(version), /invalid canonical SemVer/);
  }
  assert.equal(packageIdentity("@pkgre/indexer", "1.2.3"), "@pkgre/indexer@1.2.3");
});
