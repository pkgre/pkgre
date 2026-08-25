import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import test from "node:test";

import { inspectPackageArchive, verifyPackageArchive } from "../src/archive.js";

function writeString(buffer, offset, length, value) {
  const bytes = Buffer.from(value);
  assert.ok(bytes.length <= length);
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value) {
  writeString(buffer, offset, length, `${value.toString(8).padStart(length - 1, "0")}\0`);
}

function tarHeader({ linkName = "", mode = 0o644, name, prefix = "", size = 0, type = "0" }) {
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, mode);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeString(header, 157, 100, linkName);
  writeString(header, 257, 6, "ustar\0");
  writeString(header, 263, 2, "00");
  writeString(header, 265, 32, "root");
  writeString(header, 297, 32, "root");
  writeOctal(header, 329, 8, 0);
  writeOctal(header, 337, 8, 0);
  writeString(header, 345, 155, prefix);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeString(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

function tar(entries, { end = true } = {}) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? "");
    chunks.push(tarHeader({ ...entry, size: entry.size ?? data.length }), data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  if (end) chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function archive(entries, options) {
  return gzipSync(tar(entries, options), { level: 9 });
}

function sourceFor(bytes) {
  return {
    bytes: bytes.length,
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    sha1: createHash("sha1").update(bytes).digest("hex"),
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function packageJson(overrides = {}) {
  return JSON.stringify({
    bin: { "pkgre-js": "src/main.js" },
    description: "fixture",
    license: "Apache-2.0",
    name: "pkgre-js",
    repository: "https://example.invalid/ignored",
    scripts: { test: "node --test" },
    type: "module",
    version: "0.1.0",
    ...overrides,
  });
}

function validEntries(json = packageJson()) {
  return [
    { mode: 0o755, name: "package/", type: "5" },
    { data: json, name: "package/package.json" },
    { data: "#!/usr/bin/env node\n", mode: 0o755, name: "package/src/main.js" },
  ];
}

function record(bytes, manifest = {}) {
  return {
    manifest: {
      bin: { "pkgre-js": "src/main.js" },
      description: "fixture",
      license: "Apache-2.0",
      name: "pkgre-js",
      type: "module",
      version: "0.1.0",
      ...manifest,
    },
    source: sourceFor(bytes),
    version: "0.1.0",
  };
}

function verifyEntries(entries, manifest) {
  const bytes = archive(entries);
  return verifyPackageArchive(bytes, "pkgre-js", record(bytes, manifest));
}

test("verifies compressed hashes,bounded ustar,and the selected install manifest", () => {
  const bytes = archive(validEntries());
  const inspected = inspectPackageArchive(bytes, sourceFor(bytes));
  assert.deepEqual(inspected.entries.map(({ path, type }) => [path, type]), [
    ["package", "directory"],
    ["package/package.json", "file"],
    ["package/src/main.js", "file"],
  ]);
  assert.deepEqual(verifyPackageArchive(bytes, "pkgre-js", record(bytes)).manifest, record(bytes).manifest);
});

test("rejects compressed byte length and each cryptographic digest mismatch", () => {
  const bytes = archive(validEntries());
  for (const [key, value, expected] of [
    ["bytes", bytes.length + 1, /byte length/],
    ["sha1", "0".repeat(40), /SHA-1/],
    ["sha256", "0".repeat(64), /SHA-256/],
    ["integrity", `sha512-${Buffer.alloc(64).toString("base64")}`, /SHA-512/],
  ]) {
    assert.throws(() => inspectPackageArchive(bytes, { ...sourceFor(bytes), [key]: value }), expected);
  }
  assert.throws(() => inspectPackageArchive(Buffer.from("not gzip"), sourceFor(Buffer.from("not gzip"))), /valid gzip stream/);
});

test("rejects traversal,absolute,backslash,outside-root,and duplicate paths", () => {
  for (const name of ["package/../evil", "/package/evil", "package\\evil", "other/file"]) {
    const bytes = archive([...validEntries(), { data: "x", name }]);
    assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /unsafe path|outside package/);
  }
  const duplicate = archive([...validEntries(), { data: "again", name: "package/src/main.js" }]);
  assert.throws(() => inspectPackageArchive(duplicate, sourceFor(duplicate)), /repeats path/);
});

test("rejects links,special entries,and unsafe modes", () => {
  for (const entry of [
    { linkName: "package/src/main.js", name: "package/link", type: "2" },
    { name: "package/fifo", type: "6" },
    { data: "x", mode: 0o4755, name: "package/setuid" },
    { data: "x", mode: 0o666, name: "package/world-writable" },
    { mode: 0o775, name: "package/group-writable/", type: "5" },
  ]) {
    const bytes = archive([...validEntries(), entry]);
    assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /link name|unsupported type|setuid|mode must be/);
  }
});

test("rejects file-directory conflicts", () => {
  const conflict = archive([...validEntries(), { data: "x", name: "package/conflict/file" }, { data: "x", name: "package/conflict" }]);
  assert.throws(() => inspectPackageArchive(conflict, sourceFor(conflict)), /contains prior path/);
});

test("rejects malformed headers,padding,bounds,and termination", () => {
  const checksum = tar(validEntries());
  checksum[0] ^= 1;
  let bytes = gzipSync(checksum);
  assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /checksum/);

  const padding = tar([{ data: "x", name: "package/package.json" }]);
  padding[513] = 1;
  bytes = gzipSync(padding);
  assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /nonzero padding/);

  bytes = gzipSync(tar([{ name: "package/huge", size: 64 * 1024 * 1024 + 1 }]));
  assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /size exceeds/);

  bytes = archive(validEntries(), { end: false });
  assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /missing its end/);
});

test("requires one regular bounded package/package.json", () => {
  for (const entries of [
    [{ data: "x", name: "package/other" }],
    [{ mode: 0o755, name: "package/package.json", type: "5" }],
    [{ name: "package/package.json", data: "" }],
  ]) {
    const bytes = archive(entries);
    assert.throws(() => inspectPackageArchive(bytes, sourceFor(bytes)), /package\/package.json/);
  }
});

test("rejects ambiguous JSON and catalog-to-archive manifest drift", () => {
  assert.throws(() => verifyEntries(validEntries('{"name":"pkgre-js","name":"other","version":"0.1.0"}')), /repeats object key/);
  assert.throws(() => verifyEntries(validEntries(packageJson({ version: "0.2.0" }))), /manifest identity/);
  assert.throws(() => verifyEntries(validEntries(), { description: "different" }), /does not match catalog/);
});

test("rejects lifecycle hooks and hidden package-manager inputs", () => {
  for (const hook of ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare", "dependencies"]) {
    assert.throws(() => verifyEntries(validEntries(packageJson({ scripts: { [hook]: "do evil" } }))), new RegExp(`lifecycle hook ${hook}`));
  }
  for (const field of ["bundleDependencies", "bundledDependencies"]) {
    assert.throws(() => verifyEntries(validEntries(packageJson({ [field]: ["hidden-dependency"] }))), new RegExp(`forbidden ${field}`));
  }
  for (const entry of [
    { data: "registry=https://evil.invalid", name: "package/.npmrc" },
    { data: "{}", name: "package/npm-shrinkwrap.json" },
    { mode: 0o755, name: "package/node_modules/", type: "5" },
  ]) {
    assert.throws(() => verifyEntries([...validEntries(), entry]), /forbidden package-manager input/);
  }
});

test("rejects native-addon indicators and missing bin targets", () => {
  for (const entry of [
    { data: "{}", name: "package/binding.gyp" },
    { data: "native", name: "package/prebuilds/addon.node" },
  ]) {
    assert.throws(() => verifyEntries([...validEntries(), entry]), /native-addon indicator/);
  }
  assert.throws(() => verifyEntries(validEntries(packageJson({ gypfile: false }))), /gypfile declaration/);
  assert.throws(() => verifyEntries(validEntries().slice(0, 2)), /bin target/);
});
