import { Blob } from "node:buffer";

import { verifyPackageArchive } from "./archive.js";
import { validatePackageName } from "./canonical.js";
import { validateCatalog } from "./catalog.js";
import { jsArchiveRoute, jsRedirectDestination } from "./marker.js";
import { renderPackument } from "./packument.js";

export const PROJECTION_SCHEMA = "pkgre-js-projection-v1";

/**
 * Captures immutable, structured-cloneable response bytes.
 * @param {Uint8Array} bytes
 * @returns {Blob}
 */
function immutableBody(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("immutable body requires bytes");
  return Object.freeze(new Blob([bytes]));
}

/** @typedef {{ body: Blob, representation: "metadata-json", type: "inline" }} InlineResponse */
/** @typedef {{ body: Blob, representation: "archive", sha256: string, type: "archive" }} ArchiveResponse */
/** @typedef {{ destinationKind: "first-party" | "npmjs", location: string, type: "redirect" }} RedirectResponse */
/** @typedef {InlineResponse | ArchiveResponse | RedirectResponse} ProjectedResponse */
/** @typedef {{ path: string, response: ProjectedResponse }} ProjectedRoute */
/** @typedef {{ routes: readonly ProjectedRoute[], schema: "pkgre-js-projection-v1" }} CatalogProjection */

function archiveMap(archives) {
  if (!(archives instanceof Map)) throw new Error("archives must be a Map from SHA-256 to bytes");
  const result = new Map();
  for (const [sha256, bytes] of archives) {
    if (!/^[0-9a-f]{64}$/.test(sha256) || !(bytes instanceof Uint8Array)) throw new Error("archives must map lowercase SHA-256 to bytes");
    result.set(sha256, Buffer.from(bytes));
  }
  return result;
}

export function verifyCatalogArchives(catalog, archives) {
  validateCatalog(catalog);
  const available = archiveMap(archives);
  for (const entry of catalog.packages) {
    for (const record of entry.versions) {
      const bytes = available.get(record.source.sha256);
      if (!bytes) throw new Error(`archive is absent for ${entry.name}@${record.version} at ${record.source.sha256}.tgz`);
      verifyPackageArchive(bytes, entry.name, record);
    }
  }
  return available;
}

export function packageMetadataRoute(name) {
  validatePackageName(name);
  if (!name.startsWith("@")) return `/${name}`;
  const [scope, packageName] = name.split("/");
  return `/${scope}%2f${packageName}`;
}

function redirectResponse(name, record) {
  return Object.freeze({
    ...jsRedirectDestination(name, record),
    type: "redirect",
  });
}

function addRoute(routes, paths, path, response) {
  if (paths.has(path)) throw new Error(`catalog projection repeats route ${path}`);
  paths.add(path);
  routes.push(Object.freeze({ path, response: Object.freeze(response) }));
}

function compareRoutes(left, right) {
  if (left.path < right.path) return -1;
  if (left.path > right.path) return 1;
  return 0;
}

/**
 * Reconstructs frozen route descriptors after a worker structured clone.
 * Structured cloning preserves Blob bytes but intentionally does not preserve
 * property descriptors, so receivers must call this before publication.
 * @param {CatalogProjection} projection
 * @returns {CatalogProjection}
 */
export function freezeTransferredProjection(projection) {
  if (projection.schema !== PROJECTION_SCHEMA || !Array.isArray(projection.routes)) {
    throw new Error("invalid transferred projection");
  }

  let previousPath;
  const routes = projection.routes.map((route) => {
    if (typeof route.path !== "string" || (previousPath !== undefined && route.path <= previousPath)) {
      throw new Error(`invalid transferred projection route ${route.path}`);
    }
    previousPath = route.path;

    let response;
    if (route.response.type === "inline") {
      if (!(route.response.body instanceof Blob) || route.response.representation !== "metadata-json") {
        throw new Error(`invalid inline response at ${route.path}`);
      }
      Object.freeze(route.response.body);
      response = Object.freeze({
        body: route.response.body,
        representation: "metadata-json",
        type: "inline",
      });
    } else if (route.response.type === "archive") {
      if (
        !(route.response.body instanceof Blob)
        || route.response.representation !== "archive"
        || !/^[0-9a-f]{64}$/.test(route.response.sha256)
      ) {
        throw new Error(`invalid archive response at ${route.path}`);
      }
      Object.freeze(route.response.body);
      response = Object.freeze({
        body: route.response.body,
        representation: "archive",
        sha256: route.response.sha256,
        type: "archive",
      });
    } else if (route.response.type === "redirect") {
      if (!["first-party", "npmjs"].includes(route.response.destinationKind) || typeof route.response.location !== "string") {
        throw new Error(`invalid redirect at ${route.path}`);
      }
      response = Object.freeze({
        destinationKind: route.response.destinationKind,
        location: route.response.location,
        type: "redirect",
      });
    } else {
      throw new Error(`invalid response at ${route.path}`);
    }
    return Object.freeze({ path: route.path, response });
  });

  return Object.freeze({
    routes: Object.freeze(routes),
    schema: PROJECTION_SCHEMA,
  });
}

/** @returns {CatalogProjection} */
export function projectCatalog(catalog, archives) {
  const available = verifyCatalogArchives(catalog, archives);
  const paths = new Set();
  const routes = [];

  for (const entry of catalog.packages) {
    addRoute(routes, paths, packageMetadataRoute(entry.name), {
      body: immutableBody(renderPackument(catalog, entry)),
      representation: "metadata-json",
      type: "inline",
    });
    for (const record of entry.versions) {
      const { sha256 } = record.source;
      addRoute(routes, paths, jsArchiveRoute(sha256), redirectResponse(entry.name, record));
      if (record.source.kind === "first-party") {
        addRoute(routes, paths, `/packages/${sha256}.tgz`, {
          body: immutableBody(available.get(sha256)),
          representation: "archive",
          sha256,
          type: "archive",
        });
      }
    }
  }

  routes.sort(compareRoutes);
  return freezeTransferredProjection({ routes, schema: PROJECTION_SCHEMA });
}
