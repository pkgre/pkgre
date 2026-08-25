import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import { canonicalJson, parseCanonicalJson, validatePackageName } from "./canonical.js";

const utf8 = new TextDecoder("utf-8", { fatal: true });

export const SITE_INVENTORY_PATH = ".pkgre-js-site.json";
export const SITE_SCHEMA = "pkgre-js-site-v1";

const SHA256 = /^[0-9a-f]{64}$/;
const ROUTE_PATH = /^v1\/js\/main\/[0-9a-f]{64}$/;
const OBJECT_PATH = /^packages\/([0-9a-f]{64})\.tgz$/;

function comparePaths(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function catalogSha256(catalog) {
  return sha256(Buffer.from(canonicalJson(catalog), "utf8"));
}

export function validateSitePath(path) {
  if (typeof path !== "string" || !path.length || Buffer.byteLength(path) > 4096 || !/^[A-Za-z0-9@._~-]+(?:\/[A-Za-z0-9@._~-]+)*$/.test(path)) throw new Error(`invalid site path ${JSON.stringify(path)}`);
  if (path.split("/").some((component) => component === "." || component === "..")) throw new Error(`invalid site path ${JSON.stringify(path)}`);
  return path;
}

export function cloneSite(site) {
  if (!(site instanceof Map)) throw new Error("site must be a Map of paths to bytes");
  const clone = new Map();
  for (const [path, bytes] of [...site].sort(([left], [right]) => comparePaths(left, right))) {
    validateSitePath(path);
    if (!(bytes instanceof Uint8Array)) throw new Error(`site file ${path} must be bytes`);
    clone.set(path, Buffer.from(bytes));
  }
  for (const path of clone.keys()) {
    const components = path.split("/");
    for (let end = 1; end < components.length; end += 1) {
      const parent = components.slice(0, end).join("/");
      if (clone.has(parent)) throw new Error(`site file ${parent} conflicts with descendant ${path}`);
    }
  }
  return clone;
}

function exactKeys(value, expected, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${path} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw new Error(`${path} keys must be exactly ${wanted.join(",")}`);
}

function validateRecords(records, kind, pattern) {
  if (!Array.isArray(records)) throw new Error(`site inventory ${kind} must be an array`);
  let previous;
  for (const record of records) {
    exactKeys(record, ["path", "sha256"], `site inventory ${kind} record`);
    validateSitePath(record.path);
    if (!pattern.test(record.path) || !SHA256.test(record.sha256)) throw new Error(`site inventory has invalid ${kind} record`);
    if (previous !== undefined && record.path <= previous) throw new Error(`site inventory ${kind} must be strictly sorted`);
    previous = record.path;
  }
}

function validateMetadata(records) {
  if (!Array.isArray(records)) throw new Error("site inventory metadata must be an array");
  let previous;
  for (const record of records) {
    exactKeys(record, ["name", "path", "sha256"], "site inventory metadata record");
    validatePackageName(record.name);
    if (record.path !== record.name || !SHA256.test(record.sha256)) throw new Error("site inventory has invalid metadata record");
    if (previous !== undefined && record.path <= previous) throw new Error("site inventory metadata must be strictly sorted");
    previous = record.path;
  }
}

function verifyRecordFiles(site, records, kind) {
  for (const record of records) {
    const bytes = site.get(record.path);
    if (!bytes) throw new Error(`site inventory ${kind} file is absent at ${record.path}`);
    if (sha256(bytes) !== record.sha256) throw new Error(`site inventory ${kind} hash mismatch at ${record.path}`);
  }
}

export function readSiteInventory(site) {
  const files = cloneSite(site);
  const bytes = files.get(SITE_INVENTORY_PATH);
  const managed = [...files.keys()].filter((path) => ROUTE_PATH.test(path) || OBJECT_PATH.test(path));
  if (!bytes) {
    if (managed.length) throw new Error("site has managed immutable files without an inventory");
    return undefined;
  }
  let text;
  try {
    text = utf8.decode(bytes);
  } catch {
    throw new Error("site inventory is not UTF-8");
  }
  const inventory = parseCanonicalJson(text, "site inventory");
  exactKeys(inventory, ["catalogSha256", "metadata", "objects", "routes", "schema", "stage"], "site inventory");
  if (inventory.schema !== SITE_SCHEMA) throw new Error(`site inventory schema must be ${SITE_SCHEMA}`);
  if (!SHA256.test(inventory.catalogSha256)) throw new Error("site inventory catalogSha256 must be lowercase SHA-256");
  if (!["routes", "final"].includes(inventory.stage)) throw new Error("site inventory stage must be routes or final");
  validateMetadata(inventory.metadata);
  validateRecords(inventory.routes, "routes", ROUTE_PATH);
  validateRecords(inventory.objects, "objects", OBJECT_PATH);
  verifyRecordFiles(files, inventory.metadata, "metadata");
  verifyRecordFiles(files, inventory.routes, "route");
  verifyRecordFiles(files, inventory.objects, "object");
  const listedImmutable = new Set([...inventory.routes, ...inventory.objects].map((record) => record.path));
  for (const path of managed) {
    if (!listedImmutable.has(path)) throw new Error(`site has unlisted immutable file ${path}`);
  }
  for (const record of inventory.objects) {
    const match = record.path.match(OBJECT_PATH);
    if (match[1] !== record.sha256) throw new Error(`site object path does not match content at ${record.path}`);
  }
  return inventory;
}

function recordsFor(site, pattern) {
  return [...site]
    .filter(([path]) => pattern.test(path))
    .map(([path, bytes]) => ({ path, sha256: sha256(bytes) }))
    .sort((left, right) => comparePaths(left.path, right.path));
}

export function writeSiteInventory(site, { catalogHash, metadataNames, stage }) {
  const files = cloneSite(site);
  if (!SHA256.test(catalogHash)) throw new Error("site inventory requires a catalog hash");
  if (!["routes", "final"].includes(stage)) throw new Error("site inventory requires routes or final stage");
  const metadata = [...metadataNames].sort(comparePaths).map((name) => {
    validatePackageName(name);
    const bytes = files.get(name);
    if (!bytes) throw new Error(`site metadata file is absent at ${name}`);
    return { name, path: name, sha256: sha256(bytes) };
  });
  const inventory = {
    catalogSha256: catalogHash,
    metadata,
    objects: recordsFor(files, OBJECT_PATH),
    routes: recordsFor(files, ROUTE_PATH),
    schema: SITE_SCHEMA,
    stage,
  };
  files.set(SITE_INVENTORY_PATH, Buffer.from(canonicalJson(inventory), "utf8"));
  readSiteInventory(files);
  return files;
}

export function isImmutableSitePath(path) {
  return ROUTE_PATH.test(path) || OBJECT_PATH.test(path);
}
