import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../src/canonical.js";
import { packageMetadataUrl, renderPackument } from "../src/packument.js";

function record(version, publishedAt, byte) {
  return {
    admittedAt: "2026-08-25T00:00:00.000Z",
    manifest: { license: "MIT", name: "@scope/helper", type: "module", version },
    publishedAt,
    source: {
      bytes: 100,
      fetchedAt: "2026-08-24T00:00:00.000Z",
      integrity: `sha512-${Buffer.alloc(64, byte).toString("base64")}`,
      kind: "npmjs",
      metadataSha256: "a".repeat(64),
      sha1: byte.toString(16).repeat(40),
      sha256: byte.toString(16).repeat(64),
      url: `https://registry.npmjs.org/@scope/helper/-/helper-${version}.tgz`,
    },
    version,
  };
}

const catalog = {
  evaluationTime: "2026-08-25T00:00:00.000Z",
  packages: [{
    distTags: { latest: "2.0.0" },
    name: "@scope/helper",
    versions: [
      record("1.0.0", "2020-02-01T00:00:00.000Z", 1),
      record("2.0.0", "2021-03-04T05:06:07.008Z", 2),
    ],
  }],
};

test("renders one minimal deterministic scoped npm packument", () => {
  const actual = renderPackument(catalog, catalog.packages[0]);
  assert.deepEqual(actual, Buffer.from(canonicalJson({
    _id: "@scope/helper",
    "dist-tags": { latest: "2.0.0" },
    name: "@scope/helper",
    time: {
      "1.0.0": "2020-02-01T00:00:00.000Z",
      "2.0.0": "2021-03-04T05:06:07.008Z",
      created: "2020-02-01T00:00:00.000Z",
      modified: "2026-08-25T00:00:00.000Z",
    },
    versions: {
      "1.0.0": {
        _id: "@scope/helper@1.0.0",
        dist: {
          integrity: `sha512-${Buffer.alloc(64, 1).toString("base64")}`,
          shasum: "1".repeat(40),
          tarball: `https://js.pkg.re/v1/js/main/${"1".repeat(64)}`,
        },
        license: "MIT",
        name: "@scope/helper",
        type: "module",
        version: "1.0.0",
      },
      "2.0.0": {
        _id: "@scope/helper@2.0.0",
        dist: {
          integrity: `sha512-${Buffer.alloc(64, 2).toString("base64")}`,
          shasum: "2".repeat(40),
          tarball: `https://js.pkg.re/v1/js/main/${"2".repeat(64)}`,
        },
        license: "MIT",
        name: "@scope/helper",
        type: "module",
        version: "2.0.0",
      },
    },
  }), "utf8"));
  assert.equal(packageMetadataUrl("@scope/helper"), "https://js.pkg.re/@scope/helper");
});

test("packument output is independent of mutable object insertion order", () => {
  const reversedManifest = { version: "1.0.0", type: "module", name: "@scope/helper", license: "MIT" };
  const changed = structuredClone(catalog);
  changed.packages[0].versions[0].manifest = reversedManifest;
  assert.deepEqual(renderPackument(changed, changed.packages[0]), renderPackument(catalog, catalog.packages[0]));
});
