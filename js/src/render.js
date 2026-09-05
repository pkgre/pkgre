import { verifyPackageArchive } from "./archive.js";
import {
  SITE_INVENTORY_PATH,
  catalogSha256,
  cloneSite,
  isImmutableSitePath,
  readSiteInventory,
  writeSiteInventory,
} from "./artifact.js";
import { validateCatalog } from "./catalog.js";
import { renderJsRedirectMarker } from "./marker.js";
import { renderPackument } from "./packument.js";
import { verifyCatalogArchives } from "./projection.js";

export { verifyCatalogArchives } from "./projection.js";

function putImmutable(site, path, bytes) {
  const prior = site.get(path);
  if (prior && !prior.equals(bytes)) throw new Error(`immutable site file would change at ${path}`);
  if (!prior) site.set(path, Buffer.from(bytes));
}

function currentRecords(catalog) {
  return catalog.packages.flatMap((entry) => entry.versions.map((record) => ({ entry, record })));
}

export function verifySite(catalog, site, expectedStage) {
  validateCatalog(catalog);
  const files = cloneSite(site);
  const inventory = readSiteInventory(files);
  if (!inventory) throw new Error("generated site inventory is absent");
  if (inventory.catalogSha256 !== catalogSha256(catalog)) throw new Error("site inventory does not match catalog");
  if (expectedStage && inventory.stage !== expectedStage) throw new Error(`site stage is ${inventory.stage}, expected ${expectedStage}`);

  for (const { entry, record } of currentRecords(catalog)) {
    const routePath = `v1/js/main/${record.source.sha256}`;
    const marker = files.get(routePath);
    if (!marker) throw new Error(`site archive marker is absent at ${routePath}`);
    if (!marker.equals(renderJsRedirectMarker(entry.name, record))) throw new Error(`site archive marker differs at ${routePath}`);
    if (record.source.kind === "first-party") {
      const objectPath = `packages/${record.source.sha256}.tgz`;
      const object = files.get(objectPath);
      if (!object) throw new Error(`site first-party object is absent at ${objectPath}`);
      verifyPackageArchive(object, entry.name, record);
    }
  }

  if (inventory.stage === "final") {
    const expectedNames = catalog.packages.map((entry) => entry.name);
    if (JSON.stringify(inventory.metadata.map((record) => record.name)) !== JSON.stringify(expectedNames)) throw new Error("final site metadata inventory does not match catalog package names");
    for (const entry of catalog.packages) {
      const metadata = files.get(entry.name);
      if (!metadata || !metadata.equals(renderPackument(catalog, entry))) throw new Error(`site metadata differs at ${entry.name}`);
    }
  }
  return Object.freeze({ files: files.size, inventory });
}

export function renderRoutes(catalog, archives, previousSite = new Map()) {
  const available = verifyCatalogArchives(catalog, archives);
  let files = cloneSite(previousSite);
  const previousInventory = readSiteInventory(files);
  const metadataNames = previousInventory?.metadata.map((record) => record.name) ?? [];
  files.delete(SITE_INVENTORY_PATH);
  for (const { entry, record } of currentRecords(catalog)) {
    putImmutable(files, `v1/js/main/${record.source.sha256}`, renderJsRedirectMarker(entry.name, record));
    if (record.source.kind === "first-party") putImmutable(files, `packages/${record.source.sha256}.tgz`, available.get(record.source.sha256));
  }
  files = writeSiteInventory(files, { catalogHash: catalogSha256(catalog), metadataNames, stage: "routes" });
  verifySite(catalog, files, "routes");
  verifyMonotonic(previousSite, files);
  return files;
}

export function renderFinal(catalog, routesSite) {
  validateCatalog(catalog);
  let files = cloneSite(routesSite);
  const routeInventory = readSiteInventory(files);
  if (!routeInventory || routeInventory.stage !== "routes") throw new Error("final render requires a routes-stage site");
  if (routeInventory.catalogSha256 !== catalogSha256(catalog)) throw new Error("routes-stage site does not match catalog");
  verifySite(catalog, files, "routes");
  for (const record of routeInventory.metadata) files.delete(record.path);
  files.delete(SITE_INVENTORY_PATH);
  for (const entry of catalog.packages) {
    if (files.has(entry.name)) throw new Error(`site base file conflicts with package metadata at ${entry.name}`);
    files.set(entry.name, renderPackument(catalog, entry));
  }
  files = writeSiteInventory(files, { catalogHash: catalogSha256(catalog), metadataNames: catalog.packages.map((entry) => entry.name), stage: "final" });
  verifySite(catalog, files, "final");
  verifyMonotonic(routesSite, files);
  return files;
}

function compareUnchanged(previous, next, allowedChanges) {
  for (const [path, bytes] of previous) {
    if (path === SITE_INVENTORY_PATH || allowedChanges.has(path)) continue;
    const nextBytes = next.get(path);
    if (!nextBytes || !nextBytes.equals(bytes)) throw new Error(`staged publication changes existing nonstage file ${path}`);
  }
  for (const path of next.keys()) {
    if (path === SITE_INVENTORY_PATH || previous.has(path) || allowedChanges.has(path)) continue;
    if (!isImmutableSitePath(path)) throw new Error(`staged publication adds nonstage file ${path}`);
  }
}

export function verifyMonotonic(previousSite, nextSite) {
  const previous = cloneSite(previousSite);
  const next = cloneSite(nextSite);
  const previousInventory = readSiteInventory(previous);
  const nextInventory = readSiteInventory(next);
  if (!nextInventory) throw new Error("next site has no generated inventory");

  for (const [path, bytes] of previous) {
    if (isImmutableSitePath(path)) {
      const nextBytes = next.get(path);
      if (!nextBytes || !nextBytes.equals(bytes)) throw new Error(`next site does not retain immutable file ${path}`);
    }
  }

  if (nextInventory.stage === "routes") {
    const previousMetadata = previousInventory?.metadata ?? [];
    if (JSON.stringify(nextInventory.metadata) !== JSON.stringify(previousMetadata)) throw new Error("routes stage changes package metadata inventory");
    compareUnchanged(previous, next, new Set());
    return true;
  }

  if (!previousInventory || previousInventory.stage !== "routes" || nextInventory.stage !== "final") throw new Error("final stage must follow an inventoried routes stage");
  if (previousInventory.catalogSha256 !== nextInventory.catalogSha256) throw new Error("routes and final stages use different catalogs");
  const metadataPaths = new Set([...previousInventory.metadata, ...nextInventory.metadata].map((record) => record.path));
  compareUnchanged(previous, next, metadataPaths);
  for (const path of next.keys()) {
    if (!previous.has(path) && path !== SITE_INVENTORY_PATH && !metadataPaths.has(path)) throw new Error(`final stage adds nonmetadata file ${path}`);
  }
  return true;
}
