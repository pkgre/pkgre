import { readFileSync } from "node:fs";

import { deriveRepositoryIdentity, isValidFullRef } from "../accepted-ref.js";

export const USAGE = [
  "usage: pkgre-js-serve CONFIG",
  "       pkgre-js-serve --help",
  "",
  "Serves an immutable catalog snapshot for a dynamic pkgre JS registry.",
  "",
  "CONFIG is a strict JSON document:",
  '  {"schema":1,',
  '   "public":{"bind":"127.0.0.1:8080"},',
  '   "admin":{"bind":"127.0.0.1:8081"},',
  '   "registry":{"catalog":"CATALOG.json","delivery":"redirect"|"body",',
  '               "archive-store":"DIRECTORY"},',
  '   "limits":{"max-concurrency":64}}',
  "",
  'Exactly one snapshot source is required: [registry] catalog, or a "watcher"',
  "section that polls the accepted ref:",
  '  {"watcher":{"origin":"ORIGIN","fullRef":"refs/heads/main",',
  '              "catalogPath":"registry/catalog.json","bootstrapCommit":"40HEX",',
  '              "statePath":"STATE","pollIntervalSeconds":30}}',
  "",
  'delivery "body" requires archive-store; delivery "redirect" may omit it',
  "(first-party archive bodies then fail the snapshot closed).",
].join("\n");

const DELIVERY_MODES = ["redirect", "body"];
const BOOTSTRAP_COMMIT = /^[0-9a-f]{40}$/;

function reject(message) {
  throw new Error(message);
}

function exactKeys(object, expected, label, optional = []) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) reject(`${label} must be an object`);
  const keys = Object.keys(object);
  for (const key of keys) {
    if (!expected.includes(key)) reject(`${label} has unknown field ${key}`);
  }
  for (const key of expected) {
    if (optional.includes(key)) continue;
    if (!keys.includes(key)) reject(`${label} is missing field ${key}`);
  }
}

function parseBind(value, label) {
  if (typeof value !== "string") reject(`${label} must be a "host:port" string`);
  const separator = value.lastIndexOf(":");
  if (separator <= 0 || separator === value.length - 1) reject(`${label} must be a "host:port" string`);
  const host = value.slice(0, separator);
  const portText = value.slice(separator + 1);
  if (!/^[0-9]+$/.test(portText)) reject(`${label} port must be numeric`);
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port.toString() !== portText) {
    reject(`${label} port must be an integer between 1 and 65535`);
  }
  if (!host.length || /[^!-~]/.test(host)) reject(`${label} host must be printable ASCII without spaces`);
  return { host, port };
}

function validateCatalogPath(value, label) {
  if (typeof value !== "string" || !value.length) reject(`${label} catalogPath must be a non-empty relative path string`);
  if (value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value)) reject(`${label} catalogPath ${JSON.stringify(value)} must be relative`);
  if (value.split("/").includes("..")) reject(`${label} catalogPath ${JSON.stringify(value)} must not contain ".." components`);
}

/**
 * Validates the optional accepted-ref watcher section; the repository identity
 * is derived from the canonical origin and full ref with no normalization.
 * @param {object} document
 * @returns {object} frozen watcher configuration
 */
function validateWatcher(document) {
  exactKeys(document, ["bootstrapCommit", "catalogPath", "fullRef", "origin", "pollIntervalSeconds", "statePath"], "[watcher]");
  const { bootstrapCommit, catalogPath, fullRef, origin, pollIntervalSeconds, statePath } = document;
  if (typeof origin !== "string" || !origin.length || origin.trim() !== origin) {
    reject("[watcher] origin must be nonempty with no leading or trailing whitespace");
  }
  if (!isValidFullRef(fullRef)) reject("[watcher] fullRef must be a canonical Git full ref");
  if (typeof bootstrapCommit !== "string" || !BOOTSTRAP_COMMIT.test(bootstrapCommit)) {
    reject("[watcher] bootstrapCommit must be 40 lowercase hexadecimal characters");
  }
  validateCatalogPath(catalogPath, "[watcher]");
  if (typeof statePath !== "string" || !statePath.length) reject("[watcher] statePath must be a non-empty directory string");
  if (!Number.isInteger(pollIntervalSeconds) || pollIntervalSeconds < 1) {
    reject("[watcher] pollIntervalSeconds must be a positive integer");
  }
  const repositoryIdentity = deriveRepositoryIdentity(Buffer.from(origin, "utf8"), Buffer.from(fullRef, "utf8"));
  return Object.freeze({
    bootstrapCommit,
    catalogPath,
    fullRef,
    origin,
    pollIntervalSeconds,
    repository: Object.freeze({ fullRef, repositoryIdentity }),
    statePath,
  });
}

/**
 * Validates one parsed serve configuration document without defaults or coercion.
 * @param {unknown} document
 * @returns {object} frozen configuration
 */
export function validateConfig(document) {
  exactKeys(document, ["admin", "limits", "public", "registry", "schema", "watcher"], "serve configuration", ["watcher"]);
  if (typeof document.schema !== "number" || document.schema !== 1) reject("serve configuration schema must be 1");
  exactKeys(document.public, ["bind"], "[public]");
  const publicBind = Object.freeze(parseBind(document.public.bind, "[public] bind"));
  exactKeys(document.admin, ["bind"], "[admin]");
  const adminBind = Object.freeze(parseBind(document.admin.bind, "[admin] bind"));
  if (publicBind.host === adminBind.host && publicBind.port === adminBind.port) {
    reject("[public] bind and [admin] bind must differ");
  }
  exactKeys(document.registry, ["archive-store", "catalog", "delivery"], "[registry]", ["archive-store", "catalog"]);
  const { catalog, delivery } = document.registry;
  if (catalog !== undefined && (typeof catalog !== "string" || !catalog.length)) {
    reject("[registry] catalog must be a non-empty path string");
  }
  if (!DELIVERY_MODES.includes(delivery)) reject('[registry] delivery must be "redirect" or "body"');
  const archiveStore = document.registry["archive-store"];
  if (archiveStore !== undefined && (typeof archiveStore !== "string" || !archiveStore.length)) {
    reject("[registry] archive-store must be a non-empty directory string");
  }
  if (delivery === "body" && archiveStore === undefined) {
    reject('[registry] delivery "body" requires [registry] archive-store');
  }
  const watcher = document.watcher === undefined ? null : validateWatcher(document.watcher);
  if (watcher === null && catalog === undefined) reject("[registry] catalog is required when no watcher is configured");
  if (watcher !== null && catalog !== undefined) reject("[registry] catalog is only valid when no watcher is configured");
  exactKeys(document.limits, ["max-concurrency"], "[limits]");
  const maxConcurrency = document.limits["max-concurrency"];
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
    reject("[limits] max-concurrency must be a positive integer");
  }
  return Object.freeze({
    admin: adminBind,
    limits: Object.freeze({ maxConcurrency }),
    public: publicBind,
    registry: Object.freeze({ archiveStore: archiveStore ?? null, catalog: catalog ?? null, delivery }),
    watcher,
  });
}

/**
 * Parses strict serve configuration text; every failure names the config path.
 * @param {string} text
 * @param {string} sourcePath
 * @returns {object} frozen configuration
 */
export function parseConfig(text, sourcePath) {
  if (typeof text !== "string") reject("serve configuration text must be a string");
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    reject(`parse serve config ${sourcePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return validateConfig(document);
}

/**
 * Reads and parses one serve configuration file.
 * @param {string} path
 * @returns {object} frozen configuration
 */
export function loadConfig(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    reject(`read serve config ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseConfig(text, path);
}

/**
 * Resolves exactly one CONFIG positional; --help/-h is help; flags are unknown.
 * @param {unknown[]} argv
 * @returns {{kind: "help"} | {kind: "usage", message: string} | {kind: "config", path: string}}
 */
export function resolveArguments(argv) {
  if (!Array.isArray(argv) || argv.some((argument) => typeof argument !== "string")) {
    return { kind: "usage", message: "arguments must be strings" };
  }
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) return { kind: "help" };
  if (argv.length !== 1) return { kind: "usage", message: "exactly one CONFIG argument is required" };
  if (argv[0].startsWith("-")) return { kind: "usage", message: `unknown argument ${argv[0]}` };
  return { kind: "config", path: argv[0] };
}
