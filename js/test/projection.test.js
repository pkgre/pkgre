import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { renderJsRedirectMarker } from "../src/marker.js";
import {
  ImmutableBody,
  PROJECTION_SCHEMA,
  packageMetadataRoute,
  projectCatalog,
  verifyCatalogArchives,
} from "../src/projection.js";
import { fixtureCatalog } from "./support.js";

const fixtureRoot = new URL("../fixtures/projection-v1/", import.meta.url);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fixtureManifest() {
  return JSON.parse(await readFile(new URL("cases.json", fixtureRoot), "utf8"));
}

async function bodyBytes(body) {
  assert.ok(body instanceof ImmutableBody);
  return Buffer.from(await body.bytes());
}

async function streamBytes(body) {
  const chunks = [];
  for await (const chunk of body.stream()) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function assertImmutableBody(body, expected) {
  assert.ok(body instanceof ImmutableBody);
  assert.equal(Object.isFrozen(body), true);
  assert.equal(body.size, expected.length);

  const returned = await body.bytes();
  assert.deepEqual(Buffer.from(returned), expected);
  returned.fill(0);
  assert.deepEqual(await bodyBytes(body), expected, "mutating bytes() output changed retained body");

  const reader = body.stream().getReader();
  const first = await reader.read();
  assert.equal(first.done, false);
  first.value.fill(0);
  await reader.cancel();
  assert.deepEqual(await bodyBytes(body), expected, "mutating stream output changed retained body");
  assert.deepEqual(await streamBytes(body), expected);
}

async function summarize(projection, bodyFiles) {
  return {
    projectionSchema: projection.schema,
    routes: await Promise.all(projection.routes.map(async ({ path, response }) => {
      if (response.type === "inline") {
        const bytes = await bodyBytes(response.body);
        return {
          path,
          response: {
            bodyFile: bodyFiles.get(path),
            bytes: response.body.size,
            sha256: sha256(bytes),
            type: response.type,
          },
        };
      }
      if (response.type === "archive") {
        const bytes = await bodyBytes(response.body);
        return {
          path,
          response: {
            bytes: response.body.size,
            sha256: sha256(bytes),
            type: response.type,
          },
        };
      }
      return { path, response };
    })),
  };
}

function reverseObjectKeys(value) {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).reverse().map(([key, child]) => [key, reverseObjectKeys(child)]));
}

async function assertArchiveDescriptors(projection) {
  for (const { response } of projection.routes) {
    if (response.type === "archive") assert.equal(sha256(await bodyBytes(response.body)), response.sha256);
  }
}

test("projects one deterministic typed route snapshot", async () => {
  const fixture = fixtureCatalog();
  const projection = projectCatalog(fixture.catalog, fixture.archives);
  const manifest = await fixtureManifest();
  const bodyFiles = new Map(manifest.routes
    .filter(({ response }) => response.type === "inline")
    .map(({ path, response }) => [path, response.bodyFile]));

  assert.equal(manifest.schema, "pkgre-js-projection-fixture-v1");
  assert.equal(projection.schema, PROJECTION_SCHEMA);
  assert.deepEqual(await summarize(projection, bodyFiles), {
    projectionSchema: manifest.projectionSchema,
    routes: manifest.routes,
  });
  assert.deepEqual(projection.routes.map(({ path }) => path), [...projection.routes.map(({ path }) => path)].sort());
  assert.equal(Object.isFrozen(projection), true);
  assert.equal(Object.isFrozen(projection.routes), true);
  assert.equal(projection.routes.every((route) => Object.isFrozen(route) && Object.isFrozen(route.response)), true);

  for (const { path, response } of projection.routes) {
    if (response.type !== "inline") continue;
    await assertImmutableBody(response.body, await readFile(new URL(bodyFiles.get(path), fixtureRoot)));
  }

  const firstPartyBody = projection.routes.find(({ response }) => response.type === "archive").response;
  await assertImmutableBody(firstPartyBody.body, fixture.pkgreArchive);
  assert.equal(firstPartyBody.sha256, fixture.pkgreSha256);
  await assertArchiveDescriptors(projection);
  assert.equal(projection.routes.some(({ path }) => path === `/packages/${fixture.helperSha256}.tgz`), false);
});

test("uses one canonical raw metadata route for scoped and unscoped names", () => {
  assert.equal(packageMetadataRoute("pkgre-js"), "/pkgre-js");
  assert.equal(packageMetadataRoute("@scope/helper"), "/@scope%2fhelper");
  for (const name of ["Pkgre-js", "@scope/helper/extra", "packages"]) {
    assert.throws(() => packageMetadataRoute(name), /invalid/);
  }
});

test("projection is independent of input construction and later archive mutation", async () => {
  const left = fixtureCatalog();
  const right = fixtureCatalog();
  right.catalog = reverseObjectKeys(right.catalog);
  right.archives = new Map([...right.archives].reverse());
  const projected = projectCatalog(left.catalog, left.archives);
  const reconstructed = projectCatalog(right.catalog, right.archives);
  assert.deepEqual(await summarize(projected, new Map()), await summarize(reconstructed, new Map()));
  for (let index = 0; index < projected.routes.length; index += 1) {
    const leftResponse = projected.routes[index].response;
    const rightResponse = reconstructed.routes[index].response;
    if (leftResponse.type !== "redirect") assert.deepEqual(await bodyBytes(leftResponse.body), await bodyBytes(rightResponse.body));
  }

  left.archives.get(left.pkgreSha256).fill(0);
  const archive = projected.routes.find(({ response }) => response.type === "archive").response;
  assert.equal(sha256(await bodyBytes(archive.body)), archive.sha256);
});

test("fully verifies every archive before returning a projection", () => {
  const fixture = fixtureCatalog();
  const missing = new Map(fixture.archives);
  missing.delete(fixture.helperSha256);
  assert.throws(() => projectCatalog(fixture.catalog, missing), /archive is absent/);

  const corrupt = new Map(fixture.archives);
  corrupt.set(fixture.pkgreSha256, Buffer.from("corrupt"));
  assert.throws(() => projectCatalog(fixture.catalog, corrupt), /byte length|SHA|gzip/);
  assert.throws(() => verifyCatalogArchives(fixture.catalog, {}), /archives must be a Map/);
});

const currentFixtureRoot = new URL("../fixtures/projection-current-v1/", import.meta.url);

test("projects the frozen current catalog byte-for-byte like the static renderer", async () => {
  const manifest = JSON.parse(await readFile(new URL("cases.json", currentFixtureRoot), "utf8"));
  const catalogBytes = await readFile(new URL(manifest.source.catalogFile, currentFixtureRoot));
  const catalog = JSON.parse(catalogBytes);
  const archiveBytes = await readFile(new URL(manifest.source.archiveFile, currentFixtureRoot));
  const record = catalog.packages[0].versions[0];
  const archives = new Map([[record.source.sha256, archiveBytes]]);
  const projection = projectCatalog(catalog, archives);
  const bodyFiles = new Map(manifest.routes
    .filter(({ response }) => response.type === "inline")
    .map(({ path, response }) => [path, response.bodyFile]));

  assert.equal(manifest.schema, "pkgre-js-current-projection-fixture-v1");
  assert.equal(manifest.source.commit, "f43bd58bd3d4e36f8b3f4df3c002735c977acd17");
  assert.equal(sha256(catalogBytes), manifest.source.catalogSha256);
  assert.equal(sha256(archiveBytes), record.source.sha256);
  assert.equal(manifest.source.archiveFile, `${record.source.sha256}.tgz`);
  assert.deepEqual(await summarize(projection, bodyFiles), {
    projectionSchema: manifest.projectionSchema,
    routes: manifest.routes,
  });
  await assertArchiveDescriptors(projection);

  const metadata = projection.routes.find(({ path }) => path === packageMetadataRoute(catalog.packages[0].name));
  const archive = projection.routes.find(({ path }) => path === `/packages/${record.source.sha256}.tgz`);
  const redirect = projection.routes.find(({ path }) => path === `/v1/js/main/${record.source.sha256}`);
  const staticPackument = await readFile(new URL(manifest.staticEquivalence.packumentFile, currentFixtureRoot));
  const staticArchive = await readFile(new URL(manifest.staticEquivalence.archiveFile, currentFixtureRoot));
  const staticMarker = await readFile(new URL(manifest.staticEquivalence.markerFile, currentFixtureRoot));

  assert.deepEqual(await bodyBytes(metadata.response.body), staticPackument);
  assert.deepEqual(await bodyBytes(archive.response.body), staticArchive);
  assert.deepEqual(renderJsRedirectMarker(catalog.packages[0].name, record), staticMarker);
  assert.equal(sha256(staticMarker), manifest.staticEquivalence.markerSha256);
  assert.deepEqual(redirect.response, {
    destinationKind: record.source.kind,
    location: record.source.url,
    type: "redirect",
  });
});
