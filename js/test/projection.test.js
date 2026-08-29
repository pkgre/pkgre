import assert from "node:assert/strict";
import { Blob } from "node:buffer";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { MessageChannel } from "node:worker_threads";

import { renderJsRedirectMarker } from "../src/marker.js";
import {
  freezeTransferredProjection,
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
  assert.ok(body instanceof Blob);
  return Buffer.from(await body.arrayBuffer());
}

async function streamBytes(body) {
  const chunks = [];
  for await (const chunk of body.stream()) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function assertImmutableBody(body, expected) {
  assert.ok(body instanceof Blob);
  assert.equal(Object.isFrozen(body), true);
  assert.equal(body.size, expected.length);

  const returned = Buffer.from(await body.arrayBuffer());
  assert.deepEqual(returned, expected);
  returned.fill(0);
  assert.deepEqual(await bodyBytes(body), expected, "mutating arrayBuffer() output changed retained body");

  const reader = body.stream().getReader();
  const first = await reader.read();
  assert.equal(first.done, false);
  first.value.fill(0);
  await reader.cancel();
  assert.deepEqual(await bodyBytes(body), expected, "mutating stream output changed retained body");

  const [firstStream, secondStream, thirdStream] = await Promise.all([
    streamBytes(body),
    streamBytes(body),
    streamBytes(body),
  ]);
  assert.deepEqual(firstStream, expected);
  assert.deepEqual(secondStream, expected);
  assert.deepEqual(thirdStream, expected);
  assert.notStrictEqual(firstStream, secondStream);
  firstStream.fill(0);
  assert.deepEqual(secondStream, expected, "mutating one concurrent stream changed another");
  assert.deepEqual(await bodyBytes(body), expected, "mutating a concurrent stream changed retained body");
}

async function cloneThroughMessageChannel(value) {
  const { port1, port2 } = new MessageChannel();
  try {
    const received = new Promise((resolve) => port2.once("message", resolve));
    port1.postMessage(value);
    return await received;
  } finally {
    port1.close();
    port2.close();
  }
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

test("captures an archive subarray independently from its backing buffer", async () => {
  const fixture = fixtureCatalog();
  const backing = Buffer.alloc(fixture.pkgreArchive.length + 32, 0x5a);
  fixture.pkgreArchive.copy(backing, 16);
  const view = backing.subarray(16, 16 + fixture.pkgreArchive.length);
  const archives = new Map(fixture.archives);
  archives.set(fixture.pkgreSha256, view);

  const projection = projectCatalog(fixture.catalog, archives);
  const archive = projection.routes.find(({ response }) => response.type === "archive").response;
  backing.fill(0);

  assert.equal(archive.body.size, fixture.pkgreArchive.length);
  assert.equal(sha256(await bodyBytes(archive.body)), fixture.pkgreSha256);
});

test("worker transfer preserves Blob bytes and receiver rebuilds frozen descriptors", async () => {
  const fixture = fixtureCatalog();
  const projected = projectCatalog(fixture.catalog, fixture.archives);
  const transferred = await cloneThroughMessageChannel(projected);

  assert.equal(transferred.schema, PROJECTION_SCHEMA);
  assert.equal(Object.isFrozen(transferred), false, "structured clone unexpectedly preserved projection descriptors");
  assert.equal(Object.isFrozen(transferred.routes), false, "structured clone unexpectedly preserved route-array descriptors");
  assert.equal(Object.isFrozen(transferred.routes[0]), false, "structured clone unexpectedly preserved route descriptors");
  assert.equal(Object.isFrozen(transferred.routes[0].response), false, "structured clone unexpectedly preserved response descriptors");

  for (let index = 0; index < projected.routes.length; index += 1) {
    const original = projected.routes[index];
    const clone = transferred.routes[index];
    assert.equal(clone.path, original.path);
    assert.equal(clone.response.type, original.response.type);
    if (original.response.type === "redirect") continue;
    assert.ok(clone.response.body instanceof Blob);
    assert.equal(clone.response.body.size, original.response.body.size);
    assert.deepEqual(await bodyBytes(clone.response.body), await bodyBytes(original.response.body));
  }

  const reconstructed = freezeTransferredProjection(transferred);
  assert.equal(Object.isFrozen(reconstructed), true);
  assert.equal(Object.isFrozen(reconstructed.routes), true);
  assert.equal(reconstructed.routes.every((route) => Object.isFrozen(route) && Object.isFrozen(route.response)), true);
  for (const { response } of reconstructed.routes) {
    if (response.type !== "redirect") assert.equal(Object.isFrozen(response.body), true);
  }
  await assertArchiveDescriptors(reconstructed);
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
