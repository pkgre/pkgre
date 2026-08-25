import assert from "node:assert/strict";
import test from "node:test";

import { SITE_INVENTORY_PATH, cloneSite, readSiteInventory, writeSiteInventory } from "../src/artifact.js";
import { renderFinal, renderRoutes, verifyCatalogArchives, verifyMonotonic, verifySite } from "../src/render.js";
import { fixtureCatalog } from "./support.js";

function route(sha256) {
  return `v1/js/main/${sha256}`;
}

function snapshot(site) {
  return [...site].map(([path, bytes]) => [path, bytes.toString("base64")]);
}

function withoutHelper(fixture) {
  return {
    ...fixture.catalog,
    packages: fixture.catalog.packages.filter((entry) => entry.name !== "@scope/helper"),
  };
}

test("bootstrap stages immutable routes and only first-party objects before metadata", () => {
  const fixture = fixtureCatalog();
  const base = new Map([
    [".nojekyll", Buffer.alloc(0)],
    ["index.html", Buffer.from("origin\n")],
  ]);
  const routes = renderRoutes(fixture.catalog, fixture.archives, base);
  const inventory = readSiteInventory(routes);

  assert.equal(inventory.stage, "routes");
  assert.deepEqual(inventory.metadata, []);
  assert.equal(routes.get("index.html").toString(), "origin\n");
  assert.equal(routes.get(".nojekyll").length, 0);
  assert.ok(routes.has(route(fixture.helperSha256)));
  assert.ok(routes.has(route(fixture.pkgreSha256)));
  assert.equal(routes.has(`packages/${fixture.helperSha256}.tgz`), false);
  assert.deepEqual(routes.get(`packages/${fixture.pkgreSha256}.tgz`), fixture.pkgreArchive);
  assert.equal(routes.has("@scope/helper"), false);
  assert.equal(routes.has("pkgre-js"), false);
  assert.deepEqual(verifySite(fixture.catalog, routes, "routes").inventory, inventory);
});

test("final stage changes only scoped and unscoped packuments", () => {
  const fixture = fixtureCatalog();
  const routes = renderRoutes(fixture.catalog, fixture.archives, new Map([["index.html", Buffer.from("origin\n")]]));
  const final = renderFinal(fixture.catalog, routes);
  const inventory = readSiteInventory(final);

  assert.equal(inventory.stage, "final");
  assert.deepEqual(inventory.metadata.map(({ name, path }) => [name, path]), [
    ["@scope/helper", "@scope/helper"],
    ["pkgre-js", "pkgre-js"],
  ]);
  assert.deepEqual(final.get(route(fixture.helperSha256)), routes.get(route(fixture.helperSha256)));
  assert.deepEqual(final.get(route(fixture.pkgreSha256)), routes.get(route(fixture.pkgreSha256)));
  assert.deepEqual(final.get(`packages/${fixture.pkgreSha256}.tgz`), routes.get(`packages/${fixture.pkgreSha256}.tgz`));
  assert.match(final.get("@scope/helper").toString(), new RegExp(`https://js\\.pkg\\.re/v1/js/main/${fixture.helperSha256}`));
  assert.match(final.get("pkgre-js").toString(), new RegExp(`https://js\\.pkg\\.re/v1/js/main/${fixture.pkgreSha256}`));
  assert.equal(verifyMonotonic(routes, final), true);
  verifySite(fixture.catalog, final, "final");
});

test("independent staged renders are byte-for-byte deterministic", () => {
  const left = fixtureCatalog();
  const right = fixtureCatalog();
  const leftRoutes = renderRoutes(left.catalog, left.archives, new Map([["index.html", Buffer.from("base")]]));
  const rightRoutes = renderRoutes(right.catalog, right.archives, new Map([["index.html", Buffer.from("base")]]));
  assert.deepEqual(snapshot(leftRoutes), snapshot(rightRoutes));
  assert.deepEqual(snapshot(renderFinal(left.catalog, leftRoutes)), snapshot(renderFinal(right.catalog, rightRoutes)));
});

test("removal drops metadata while retaining every immutable route and object", () => {
  const fixture = fixtureCatalog();
  const oldFinal = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives));
  const catalog = withoutHelper(fixture);
  const archives = new Map([[fixture.pkgreSha256, fixture.pkgreArchive]]);
  const routes = renderRoutes(catalog, archives, oldFinal);
  const final = renderFinal(catalog, routes);

  assert.equal(routes.has("@scope/helper"), true);
  assert.equal(final.has("@scope/helper"), false);
  assert.equal(final.has("pkgre-js"), true);
  for (const path of [route(fixture.helperSha256), route(fixture.pkgreSha256), `packages/${fixture.pkgreSha256}.tgz`]) {
    assert.deepEqual(final.get(path), oldFinal.get(path));
  }
});

test("requires every exact archive and verifies bytes without copying npmjs archives", () => {
  const fixture = fixtureCatalog();
  const missing = new Map(fixture.archives);
  missing.delete(fixture.helperSha256);
  assert.throws(() => verifyCatalogArchives(fixture.catalog, missing), /archive is absent/);

  const wrong = new Map(fixture.archives);
  wrong.set(fixture.helperSha256, Buffer.from("wrong"));
  assert.throws(() => renderRoutes(fixture.catalog, wrong), /byte length|gzip|SHA/);

  const routes = renderRoutes(fixture.catalog, fixture.archives);
  assert.equal([...routes.values()].some((bytes) => bytes.equals(fixture.helperArchive)), false);
});

test("refuses marker drift, base collisions, and metadata before route staging", () => {
  const fixture = fixtureCatalog();
  const final = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives));
  const drifted = cloneSite(final);
  drifted.set(route(fixture.helperSha256), Buffer.from("different marker"));
  const reinventoried = writeSiteInventory(drifted, {
    catalogHash: readSiteInventory(final).catalogSha256,
    metadataNames: ["@scope/helper", "pkgre-js"],
    stage: "final",
  });
  assert.throws(() => renderRoutes(fixture.catalog, fixture.archives, reinventoried), /immutable site file would change/);

  const collision = new Map([["pkgre-js", Buffer.from("base file")]]);
  const collisionRoutes = renderRoutes(fixture.catalog, fixture.archives, collision);
  assert.throws(() => renderFinal(fixture.catalog, collisionRoutes), /base file conflicts/);

  const missingRoute = cloneSite(renderRoutes(fixture.catalog, fixture.archives));
  missingRoute.delete(route(fixture.helperSha256));
  assert.throws(() => renderFinal(fixture.catalog, missingRoute), /file is absent|marker is absent/);
});

test("detects immutable loss, route-stage metadata edits, and final-stage extra files", () => {
  const fixture = fixtureCatalog();
  const oldFinal = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives));
  const catalog = withoutHelper(fixture);
  const archives = new Map([[fixture.pkgreSha256, fixture.pkgreArchive]]);
  const routes = renderRoutes(catalog, archives, oldFinal);

  const changedMetadata = cloneSite(routes);
  changedMetadata.set("@scope/helper", Buffer.from("changed"));
  const changedMetadataInventory = writeSiteInventory(changedMetadata, {
    catalogHash: readSiteInventory(routes).catalogSha256,
    metadataNames: ["@scope/helper", "pkgre-js"],
    stage: "routes",
  });
  assert.throws(() => verifyMonotonic(oldFinal, changedMetadataInventory), /changes package metadata inventory|changes existing nonstage file/);

  const lostImmutable = cloneSite(routes);
  lostImmutable.delete(route(fixture.helperSha256));
  const lostInventory = writeSiteInventory(lostImmutable, {
    catalogHash: readSiteInventory(routes).catalogSha256,
    metadataNames: ["@scope/helper", "pkgre-js"],
    stage: "routes",
  });
  assert.throws(() => verifyMonotonic(oldFinal, lostInventory), /does not retain immutable file/);

  const final = renderFinal(catalog, routes);
  const extra = cloneSite(final);
  extra.set("unexpected.txt", Buffer.from("unexpected"));
  const extraInventory = writeSiteInventory(extra, {
    catalogHash: readSiteInventory(final).catalogSha256,
    metadataNames: ["pkgre-js"],
    stage: "final",
  });
  assert.throws(() => verifyMonotonic(routes, extraInventory), /adds nonstage file|adds nonmetadata file/);
});

test("binds both stages to one catalog and detects inventory tampering", () => {
  const fixture = fixtureCatalog();
  const routes = renderRoutes(fixture.catalog, fixture.archives);
  const otherCatalog = { ...fixture.catalog, evaluationTime: "2026-08-26T00:00:00.000Z" };
  assert.throws(() => renderFinal(otherCatalog, routes), /does not match catalog/);

  const tampered = cloneSite(routes);
  const inventory = JSON.parse(tampered.get(SITE_INVENTORY_PATH));
  inventory.catalogSha256 = "0".repeat(64);
  tampered.set(SITE_INVENTORY_PATH, Buffer.from(`${JSON.stringify(inventory, null, 2)}\n`));
  assert.throws(() => verifySite(fixture.catalog, tampered, "routes"), /does not match catalog/);
});
