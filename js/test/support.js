import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import { CATALOG_SCHEMA, MINIMUM_AGE_SECONDS, REGISTRY_ALIAS, canonicalNpmArchiveUrl } from "../src/catalog.js";

function writeString(buffer, offset, length, value) {
  const bytes = Buffer.from(value);
  assert.ok(bytes.length <= length);
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value) {
  writeString(buffer, offset, length, `${value.toString(8).padStart(length - 1, "0")}\0`);
}

function tarHeader({ mode = 0o644, name, size = 0, type = "0" }) {
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, mode);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeString(header, 257, 6, "ustar\0");
  writeString(header, 263, 2, "00");
  writeString(header, 265, 32, "root");
  writeString(header, 297, 32, "root");
  writeOctal(header, 329, 8, 0);
  writeOctal(header, 337, 8, 0);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeString(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

function tar(entries) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? "");
    chunks.push(tarHeader({ ...entry, size: data.length }), data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function packageArchive(packageJson, files = []) {
  const entries = [
    { mode: 0o755, name: "package/", type: "5" },
    { data: JSON.stringify(packageJson), name: "package/package.json" },
    ...files,
  ];
  return gzipSync(tar(entries), { level: 9 });
}

export function archiveDigests(bytes) {
  return {
    bytes: bytes.length,
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    sha1: createHash("sha1").update(bytes).digest("hex"),
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

export function fixtureCatalog() {
  const helperManifest = { license: "MIT", name: "@scope/helper", version: "1.2.3" };
  const helperArchive = packageArchive(helperManifest);
  const helperDigests = archiveDigests(helperArchive);
  const pkgreManifest = {
    bin: { "pkgre-js": "src/main.js" },
    engines: { node: ">=24.15.0", npm: ">=12.0.2" },
    license: "Apache-2.0",
    name: "pkgre-js",
    type: "module",
    version: "0.1.0",
  };
  const pkgreArchive = packageArchive(pkgreManifest, [{ data: "#!/usr/bin/env node\n", mode: 0o755, name: "package/src/main.js" }]);
  const pkgreDigests = archiveDigests(pkgreArchive);
  const catalog = {
    evaluationTime: "2026-08-25T00:00:00.000Z",
    minimumAgeSeconds: MINIMUM_AGE_SECONDS,
    packages: [
      {
        distTags: { latest: "1.2.3" },
        name: "@scope/helper",
        versions: [{
          admittedAt: "2026-08-25T00:00:00.000Z",
          manifest: helperManifest,
          publishedAt: "2020-01-01T00:00:00.000Z",
          source: {
            ...helperDigests,
            fetchedAt: "2026-08-24T00:00:00.000Z",
            kind: "npmjs",
            metadataSha256: "a".repeat(64),
            url: canonicalNpmArchiveUrl("@scope/helper", "1.2.3"),
          },
          version: "1.2.3",
        }],
      },
      {
        distTags: { latest: "0.1.0" },
        name: "pkgre-js",
        versions: [{
          admittedAt: "2026-08-25T00:00:00.000Z",
          manifest: pkgreManifest,
          publishedAt: "2026-08-25T00:00:00.000Z",
          source: {
            ...pkgreDigests,
            commit: "c".repeat(40),
            kind: "first-party",
            repository: "https://github.com/pkgre/pkgre",
            tag: "js/v0.1.0",
            tagObject: "d".repeat(40),
            url: `https://js.pkg.re/packages/${pkgreDigests.sha256}.tgz`,
          },
          version: "0.1.0",
        }],
      },
    ],
    registry: REGISTRY_ALIAS,
    schema: CATALOG_SCHEMA,
  };
  return {
    archives: new Map([
      [helperDigests.sha256, helperArchive],
      [pkgreDigests.sha256, pkgreArchive],
    ]),
    catalog,
    helperArchive,
    helperSha256: helperDigests.sha256,
    pkgreArchive,
    pkgreSha256: pkgreDigests.sha256,
  };
}
