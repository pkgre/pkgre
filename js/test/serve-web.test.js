import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";

import { canonicalNpmArchiveUrl } from "../src/catalog.js";
import {
  CACHE_CONTROL_ARCHIVE,
  CACHE_CONTROL_METADATA,
  CACHE_CONTROL_NO_STORE,
  CONTENT_TYPE_ARCHIVE,
  CONTENT_TYPE_METADATA_JSON,
} from "../src/http-response.js";
import { jsArchiveRoute } from "../src/marker.js";
import { renderPackument } from "../src/packument.js";
import { packageMetadataRoute } from "../src/projection.js";
import { buildServeSnapshot } from "../src/serve/snapshot.js";
import {
  adminRequestHandler,
  createShared,
  installSnapshot,
  publicRequestHandler,
  statusReport,
} from "../src/serve/web.js";
import { fixtureCatalog } from "./support.js";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const fixture = fixtureCatalog();
const helperRoute = jsArchiveRoute(fixture.helperSha256);
const pkgreRoute = jsArchiveRoute(fixture.pkgreSha256);
const pkgreEntry = fixture.catalog.packages.find((entry) => entry.name === "pkgre-js");

const tempRoots = [];
function tempStore(name, files = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), `pkgre-serve-${name}-`));
  for (const [file, bytes] of Object.entries(files)) writeFileSync(path.join(directory, file), bytes);
  tempRoots.push(directory);
  return directory;
}
after(() => {
  for (const directory of tempRoots) rmSync(directory, { force: true, recursive: true });
});

const store = tempStore("full", {
  [`${fixture.helperSha256}.tgz`]: fixture.helperArchive,
  [`${fixture.pkgreSha256}.tgz`]: fixture.pkgreArchive,
});
const redirectSnapshot = await buildServeSnapshot(fixture.catalog, store, "redirect");
const bodySnapshot = await buildServeSnapshot(fixture.catalog, store, "body");

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function request(server, { headers = {}, method = "GET", target = "/" } = {}) {
  const address = server.address();
  return new Promise((resolve, reject) => {
    const req = http.request({ headers, host: address.address, method, path: target, port: address.port }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ body: Buffer.concat(chunks), headers: res.headers, status: res.statusCode }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("serving snapshots count every route kind per delivery mode", () => {
  assert.deepEqual(redirectSnapshot.counts, { archive: 1, inline: 2, redirect: 2 });
  assert.deepEqual(bodySnapshot.counts, { archive: 3, inline: 2, redirect: 0 });
  assert.equal(redirectSnapshot.routes.size, 5);
  assert.equal(bodySnapshot.routes.size, 5);
  assert.ok(Object.isFrozen(redirectSnapshot.routes));
});

test("unready serving reports unavailable without dispatch", async () => {
  const shared = createShared({ delivery: "redirect", maxConcurrency: 4 });
  const server = await listen(publicRequestHandler(shared));
  try {
    const unavailable = await request(server, { target: "/pkgre-js" });
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.headers["cache-control"], CACHE_CONTROL_NO_STORE);
    assert.equal(unavailable.body.length, 0);
    const report = statusReport(shared);
    assert.equal(report.ready, false);
    assert.equal(report.counts, null);
    assert.equal(report.mode, "redirect");
    assert.equal(report.schema, 1);
    assert.equal(typeof report.uptimeSeconds, "number");
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("snapshot policy vectors are served exactly", async () => {
  const shared = createShared({ delivery: "redirect", maxConcurrency: 4 });
  installSnapshot(shared, redirectSnapshot);
  const server = await listen(publicRequestHandler(shared));
  try {
    const packument = await request(server, { target: packageMetadataRoute("pkgre-js") });
    assert.equal(packument.status, 200);
    assert.equal(packument.headers["cache-control"], CACHE_CONTROL_METADATA);
    assert.equal(packument.headers["content-type"], CONTENT_TYPE_METADATA_JSON);
    assert.match(packument.headers.etag, /^"sha256:[0-9a-f]{64}"$/);
    assert.ok(packument.body.equals(Buffer.from(await renderPackument(fixture.catalog, pkgreEntry))));

    const head = await request(server, { method: "HEAD", target: packageMetadataRoute("pkgre-js") });
    assert.equal(head.status, 200);
    assert.equal(head.headers["content-length"], packument.headers["content-length"]);
    assert.equal(head.body.length, 0);

    const scoped = await request(server, { target: packageMetadataRoute("@scope/helper") });
    assert.equal(scoped.status, 200);

    const npmRedirect = await request(server, { target: helperRoute });
    assert.equal(npmRedirect.status, 302);
    assert.equal(npmRedirect.headers.location, canonicalNpmArchiveUrl("@scope/helper", "1.2.3"));
    assert.equal(npmRedirect.headers["cache-control"], CACHE_CONTROL_NO_STORE);

    const firstPartyRedirect = await request(server, { target: pkgreRoute });
    assert.equal(firstPartyRedirect.status, 302);
    assert.equal(firstPartyRedirect.headers.location, `https://js.pkg.re/packages/${fixture.pkgreSha256}.tgz`);

    const firstPartyArchive = await request(server, { target: `/packages/${fixture.pkgreSha256}.tgz` });
    assert.equal(firstPartyArchive.status, 200);
    assert.equal(firstPartyArchive.headers["content-type"], CONTENT_TYPE_ARCHIVE);
    assert.equal(firstPartyArchive.headers["cache-control"], CACHE_CONTROL_ARCHIVE);
    assert.ok(firstPartyArchive.body.equals(fixture.pkgreArchive));

    const query = await request(server, { target: "/pkgre-js?x=1" });
    assert.equal(query.status, 400);
    assert.equal(query.headers["cache-control"], CACHE_CONTROL_NO_STORE);

    const absent = await request(server, { target: "/absent" });
    assert.equal(absent.status, 404);
    assert.equal(absent.headers["cache-control"], CACHE_CONTROL_NO_STORE);

    const rejected = await request(server, { method: "POST", target: "/pkgre-js" });
    assert.equal(rejected.status, 405);
    assert.equal(rejected.headers.allow, "GET, HEAD");
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("original-uri header has precedence and strict cardinality", async () => {
  const shared = createShared({ delivery: "redirect", maxConcurrency: 4 });
  installSnapshot(shared, redirectSnapshot);
  const server = await listen(publicRequestHandler(shared));
  try {
    const precedence = await request(server, { headers: { "x-pkgre-original-uri": "/pkgre-js" }, target: "/" });
    assert.equal(precedence.status, 200);

    const absent = await request(server, { headers: { "x-pkgre-original-uri": "/absent" }, target: "/" });
    assert.equal(absent.status, 404);

    const invalid = await request(server, { headers: { "x-pkgre-original-uri": "%2e%2e" }, target: "/" });
    assert.equal(invalid.status, 400);

    const duplicate = await request(server, {
      headers: { "x-pkgre-original-uri": ["/pkgre-js", "/pkgre-js"] },
      target: "/",
    });
    assert.equal(duplicate.status, 404);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("admin endpoints enforce method and path policy", async () => {
  const shared = createShared({ delivery: "redirect", maxConcurrency: 4 });
  installSnapshot(shared, redirectSnapshot);
  const server = await listen(adminRequestHandler(shared));
  try {
    const health = await request(server, { target: "/healthz" });
    assert.equal(health.status, 200);
    assert.equal(health.body.length, 0);
    assert.equal(health.headers["cache-control"], CACHE_CONTROL_NO_STORE);

    const ready = await request(server, { method: "HEAD", target: "/readyz" });
    assert.equal(ready.status, 200);

    const healthMethod = await request(server, { method: "POST", target: "/healthz" });
    assert.equal(healthMethod.status, 405);
    assert.equal(healthMethod.headers.allow, "GET, HEAD");

    const statusMethod = await request(server, { method: "POST", target: "/status" });
    assert.equal(statusMethod.status, 405);
    assert.equal(statusMethod.headers.allow, "GET");

    const status = await request(server, { target: "/status" });
    assert.equal(status.status, 200);
    assert.equal(status.headers["content-type"], CONTENT_TYPE_METADATA_JSON);
    const report = JSON.parse(status.body.toString("utf8"));
    assert.deepEqual(report, {
      counts: { archive: 1, inline: 2, redirect: 2 },
      mode: "redirect",
      ready: true,
      schema: 1,
      uptimeSeconds: report.uptimeSeconds,
    });
    assert.equal(typeof report.uptimeSeconds, "number");

    const statusQuery = await request(server, { target: "/status?verbose=1" });
    assert.equal(statusQuery.status, 404);
    const absent = await request(server, { target: "/nope" });
    assert.equal(absent.status, 404);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("body delivery serves archives locally", async () => {
  const shared = createShared({ delivery: "body", maxConcurrency: 4 });
  installSnapshot(shared, bodySnapshot);
  const server = await listen(publicRequestHandler(shared));
  try {
    const npmBody = await request(server, { target: helperRoute });
    assert.equal(npmBody.status, 200);
    assert.equal(npmBody.headers["content-type"], CONTENT_TYPE_ARCHIVE);
    assert.equal(npmBody.headers["cache-control"], CACHE_CONTROL_ARCHIVE);
    assert.ok(npmBody.body.equals(fixture.helperArchive));

    const firstPartyBody = await request(server, { target: pkgreRoute });
    assert.equal(firstPartyBody.status, 200);
    assert.ok(firstPartyBody.body.equals(fixture.pkgreArchive));

    const firstPartyArchive = await request(server, { target: `/packages/${fixture.pkgreSha256}.tgz` });
    assert.equal(firstPartyArchive.status, 200);
    assert.ok(firstPartyArchive.body.equals(fixture.pkgreArchive));

    const report = statusReport(shared);
    assert.deepEqual(report.counts, { archive: 3, inline: 2, redirect: 0 });
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("body delivery fails closed without a complete store", () => {
  const partial = tempStore("body-partial", {
    [`${fixture.pkgreSha256}.tgz`]: fixture.pkgreArchive,
  });
  assert.rejects(
    buildServeSnapshot(fixture.catalog, partial, "body"),
    new RegExp(`absent for @scope/helper@1\\.2\\.3 at .*${fixture.helperSha256}\\.tgz`),
  );

  const corrupt = tempStore("body-corrupt", {
    [`${fixture.helperSha256}.tgz`]: Buffer.from("corrupt"),
    [`${fixture.pkgreSha256}.tgz`]: fixture.pkgreArchive,
  });
  assert.rejects(
    buildServeSnapshot(fixture.catalog, corrupt, "body"),
    /digest mismatch for @scope\/helper@1\.2\.3/,
  );
});

test("redirect delivery fails closed without first-party bodies", () => {
  const empty = tempStore("redirect-empty");
  assert.rejects(
    buildServeSnapshot(fixture.catalog, empty, "redirect"),
    new RegExp(`absent for pkgre-js@0\\.1\\.0 at .*${fixture.pkgreSha256}\\.tgz`),
  );
  assert.rejects(
    buildServeSnapshot(fixture.catalog, null, "redirect"),
    new RegExp(`absent for pkgre-js@0\\.1\\.0`),
  );
});

test("snapshot swap is atomic and updates status", async () => {
  const shared = createShared({ delivery: "redirect", maxConcurrency: 4 });
  installSnapshot(shared, redirectSnapshot);
  const server = await listen(publicRequestHandler(shared));
  try {
    const before = await request(server, { target: "/pkgre-js" });
    assert.equal(before.status, 200);

    const routes = new Map(redirectSnapshot.routes);
    routes.delete("/pkgre-js");
    installSnapshot(shared, Object.freeze({
      counts: Object.freeze({ archive: 1, inline: 1, redirect: 2 }),
      delivery: "redirect",
      routes: Object.freeze(routes),
    }));

    const after = await request(server, { target: "/pkgre-js" });
    assert.equal(after.status, 404);
    const survivor = await request(server, { target: packageMetadataRoute("@scope/helper") });
    assert.equal(survivor.status, 200);
    assert.deepEqual(statusReport(shared).counts, { archive: 1, inline: 1, redirect: 2 });
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("concurrency limit queues public dispatch", async () => {
  const shared = createShared({ delivery: "redirect", maxConcurrency: 1 });
  installSnapshot(shared, redirectSnapshot);
  const server = await listen(publicRequestHandler(shared));
  try {
    await shared.semaphore.acquire();
    let settled = false;
    const blocked = request(server, { target: "/pkgre-js" }).then((result) => {
      settled = true;
      return result;
    });
    await delay(25);
    assert.equal(settled, false);
    shared.semaphore.release();
    const released = await blocked;
    assert.equal(released.status, 200);
    assert.equal(settled, true);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
