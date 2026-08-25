import { packageIdentity, validatePackageName, validateVersion } from "./canonical.js";

export const CATALOG_SCHEMA = "pkgre-js-catalog-v1";
export const REGISTRY_ALIAS = "main";
export const MINIMUM_AGE_SECONDS = 30 * 24 * 60 * 60;

const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SHA512_SRI = /^sha512-([A-Za-z0-9+/]{86}==)$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const TAG = /^js\/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const MANIFEST_KEYS = new Set([
  "bin",
  "cpu",
  "dependencies",
  "deprecated",
  "description",
  "engines",
  "exports",
  "imports",
  "libc",
  "license",
  "main",
  "module",
  "name",
  "optionalDependencies",
  "os",
  "peerDependencies",
  "peerDependenciesMeta",
  "type",
  "types",
  "typings",
  "version",
]);

function object(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${path} must be an object`);
  return value;
}

function exactKeys(value, expected, path) {
  object(value, path);
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(canonical)) {
    throw new Error(`${path} keys must be exactly ${canonical.join(",")}`);
  }
}

function allowedKeys(value, allowed, path) {
  object(value, path);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${path} has unsupported key ${JSON.stringify(key)}`);
  }
}

function timestamp(value, path) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) throw new Error(`${path} must be a canonical UTC timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${path} must be a real canonical UTC timestamp`);
  return milliseconds;
}

function boundedString(value, path, maximum = 4096) {
  if (typeof value !== "string" || !value.length || value.length > maximum || !value.isWellFormed()) throw new Error(`${path} must be a bounded nonempty string`);
  return value;
}

function relativePackagePath(value, path) {
  boundedString(value, path, 1024);
  if (!/^(?:\.\/)?[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*$/.test(value) || value.split("/").some((part) => part === "." || part === "..")) {
    throw new Error(`${path} must be a canonical package-relative path`);
  }
}

function validateDependencyMap(value, path) {
  object(value, path);
  for (const [name, version] of Object.entries(value)) {
    validatePackageName(name);
    try {
      validateVersion(version);
    } catch {
      throw new Error(`${path}.${name} must be one exact canonical version; URL,Git,file,directory,workspace,alias,and range sources are forbidden`);
    }
  }
}

function validateConditions(value, path, depth = 0) {
  if (depth > 16) throw new Error(`${path} exceeds maximum nesting`);
  if (value === null) return;
  if (typeof value === "string") {
    boundedString(value, path, 1024);
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(value) || value.includes("\\") || value.includes("\0")) throw new Error(`${path} contains a forbidden source or path`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 64) throw new Error(`${path} has too many entries`);
    value.forEach((item, index) => validateConditions(item, `${path}[${index}]`, depth + 1));
    return;
  }
  object(value, path);
  if (Object.keys(value).length > 128) throw new Error(`${path} has too many keys`);
  for (const [key, item] of Object.entries(value)) {
    boundedString(key, `${path} key`, 256);
    validateConditions(item, `${path}.${key}`, depth + 1);
  }
}

export function validateInstallManifest(manifest, expectedName, expectedVersion) {
  allowedKeys(manifest, MANIFEST_KEYS, "manifest");
  if (manifest.name !== expectedName || manifest.version !== expectedVersion) throw new Error(`manifest identity does not match ${packageIdentity(expectedName, expectedVersion)}`);
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    if (Object.hasOwn(manifest, field)) validateDependencyMap(manifest[field], `manifest.${field}`);
  }
  if (Object.hasOwn(manifest, "peerDependenciesMeta")) {
    object(manifest.peerDependenciesMeta, "manifest.peerDependenciesMeta");
    const peers = manifest.peerDependencies ?? {};
    for (const [name, metadata] of Object.entries(manifest.peerDependenciesMeta)) {
      if (!Object.hasOwn(peers, name)) throw new Error(`peer metadata names undeclared peer ${name}`);
      exactKeys(metadata, ["optional"], `manifest.peerDependenciesMeta.${name}`);
      if (metadata.optional !== true) throw new Error(`manifest.peerDependenciesMeta.${name}.optional must be true`);
    }
  }
  if (Object.hasOwn(manifest, "bin")) {
    object(manifest.bin, "manifest.bin");
    for (const [name, path] of Object.entries(manifest.bin)) {
      if (!/^[a-z][a-z0-9._~-]*$/.test(name)) throw new Error(`manifest.bin has invalid command ${JSON.stringify(name)}`);
      relativePackagePath(path, `manifest.bin.${name}`);
    }
  }
  if (Object.hasOwn(manifest, "engines")) {
    object(manifest.engines, "manifest.engines");
    for (const [name, range] of Object.entries(manifest.engines)) {
      if (!/^[a-z][a-z0-9._~-]*$/.test(name)) throw new Error(`manifest.engines has invalid engine ${JSON.stringify(name)}`);
      boundedString(range, `manifest.engines.${name}`, 256);
    }
  }
  for (const field of ["cpu", "libc", "os"]) {
    if (!Object.hasOwn(manifest, field)) continue;
    if (!Array.isArray(manifest[field]) || manifest[field].length > 64 || new Set(manifest[field]).size !== manifest[field].length) throw new Error(`manifest.${field} must be a bounded unique array`);
    for (const item of manifest[field]) {
      if (typeof item !== "string" || !/^!?[a-z0-9][a-z0-9._-]*$/.test(item)) throw new Error(`manifest.${field} has invalid selector`);
    }
  }
  for (const field of ["main", "module", "types", "typings"]) {
    if (Object.hasOwn(manifest, field)) relativePackagePath(manifest[field], `manifest.${field}`);
  }
  for (const field of ["deprecated", "description", "license"]) {
    if (Object.hasOwn(manifest, field)) boundedString(manifest[field], `manifest.${field}`);
  }
  if (Object.hasOwn(manifest, "type") && !["commonjs", "module"].includes(manifest.type)) throw new Error("manifest.type must be commonjs or module");
  for (const field of ["exports", "imports"]) {
    if (Object.hasOwn(manifest, field)) validateConditions(manifest[field], `manifest.${field}`);
  }
}

function npmArchiveUrl(name, version) {
  const segments = name.startsWith("@") ? name.split("/") : [name];
  const packageName = segments.at(-1);
  return `https://registry.npmjs.org/${segments.join("/")}/-/${packageName}-${version}.tgz`;
}

function validateSource(source, name, version) {
  const common = ["bytes", "integrity", "kind", "sha1", "sha256", "url"];
  if (source?.kind === "npmjs") {
    exactKeys(source, [...common, "fetchedAt", "metadataSha256"], "source");
    if (source.url !== npmArchiveUrl(name, version)) throw new Error(`source.url is not the canonical npm archive URL for ${packageIdentity(name, version)}`);
    timestamp(source.fetchedAt, "source.fetchedAt");
    if (!SHA256.test(source.metadataSha256)) throw new Error("source.metadataSha256 must be lowercase SHA-256");
  } else if (source?.kind === "first-party") {
    exactKeys(source, [...common, "commit", "repository", "tag", "tagObject"], "source");
    if (source.repository !== "https://github.com/pkgre/pkgre") throw new Error("first-party repository must be https://github.com/pkgre/pkgre");
    if (!TAG.test(source.tag) || source.tag !== `js/v${version}`) throw new Error(`first-party tag must be js/v${version}`);
    if (!GIT_OBJECT.test(source.tagObject) || !GIT_OBJECT.test(source.commit)) throw new Error("first-party Git objects must be lowercase SHA-1 object IDs");
  } else {
    throw new Error("source.kind must be npmjs or first-party");
  }
  if (!Number.isSafeInteger(source.bytes) || source.bytes <= 0 || source.bytes > 32 * 1024 * 1024) throw new Error("source.bytes must be between 1 and 33554432");
  if (!SHA1.test(source.sha1)) throw new Error("source.sha1 must be lowercase SHA-1");
  if (!SHA256.test(source.sha256)) throw new Error("source.sha256 must be lowercase SHA-256");
  const match = typeof source.integrity === "string" ? source.integrity.match(SHA512_SRI) : null;
  if (!match || Buffer.from(match[1], "base64").length !== 64 || Buffer.from(match[1], "base64").toString("base64") !== match[1]) {
    throw new Error("source.integrity must be one canonical SHA-512 SRI value");
  }
  if (source.kind === "first-party" && source.url !== `https://js.pkg.re/packages/${source.sha256}.tgz`) throw new Error("first-party source.url must be its content-addressed js.pkg.re object");
}

export function validateCatalog(catalog) {
  exactKeys(catalog, ["evaluationTime", "minimumAgeSeconds", "packages", "registry", "schema"], "catalog");
  if (catalog.schema !== CATALOG_SCHEMA) throw new Error(`catalog.schema must be ${CATALOG_SCHEMA}`);
  if (catalog.registry !== REGISTRY_ALIAS) throw new Error(`catalog.registry must be ${REGISTRY_ALIAS}`);
  if (catalog.minimumAgeSeconds !== MINIMUM_AGE_SECONDS) throw new Error(`catalog.minimumAgeSeconds must be ${MINIMUM_AGE_SECONDS}`);
  const evaluationTime = timestamp(catalog.evaluationTime, "catalog.evaluationTime");
  if (!Array.isArray(catalog.packages) || !catalog.packages.length || catalog.packages.length > 10000) throw new Error("catalog.packages must be a bounded nonempty array");

  const identities = new Set();
  const routes = new Set();
  let previousName;
  for (const entry of catalog.packages) {
    exactKeys(entry, ["distTags", "name", "versions"], "package");
    const name = validatePackageName(entry.name);
    if (previousName !== undefined && name <= previousName) throw new Error("catalog packages must be strictly sorted by name");
    previousName = name;
    exactKeys(entry.distTags, ["latest"], `${name}.distTags`);
    if (!Array.isArray(entry.versions) || !entry.versions.length || entry.versions.length > 10000) throw new Error(`${name}.versions must be a bounded nonempty array`);
    let previousVersion;
    const packageVersions = new Set();
    for (const record of entry.versions) {
      exactKeys(record, ["admittedAt", "manifest", "publishedAt", "source", "version"], `${name} version`);
      const version = validateVersion(record.version);
      if (previousVersion !== undefined && version <= previousVersion) throw new Error(`${name} versions must be strictly sorted by canonical string`);
      previousVersion = version;
      packageVersions.add(version);
      const identity = packageIdentity(name, version);
      if (identities.has(identity)) throw new Error(`duplicate identity ${identity}`);
      identities.add(identity);
      const publishedAt = timestamp(record.publishedAt, `${identity}.publishedAt`);
      const admittedAt = timestamp(record.admittedAt, `${identity}.admittedAt`);
      if (publishedAt > admittedAt || admittedAt > evaluationTime) throw new Error(`${identity} has nonmonotonic evidence timestamps`);
      validateSource(record.source, name, version);
      if (record.source.kind === "npmjs") {
        const fetchedAt = timestamp(record.source.fetchedAt, `${identity}.source.fetchedAt`);
        if (publishedAt > fetchedAt || fetchedAt > admittedAt) throw new Error(`${identity} has nonmonotonic npm evidence timestamps`);
        if ((admittedAt - publishedAt) / 1000 < MINIMUM_AGE_SECONDS) throw new Error(`${identity} is younger than 30 days at admission`);
      }
      if (routes.has(record.source.sha256)) throw new Error(`archive route collision at ${record.source.sha256}`);
      routes.add(record.source.sha256);
      validateInstallManifest(record.manifest, name, version);
    }
    if (!packageVersions.has(entry.distTags.latest)) throw new Error(`${name} latest tag names an absent version`);
  }

  for (const entry of catalog.packages) {
    for (const record of entry.versions) {
      for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
        for (const [name, version] of Object.entries(record.manifest[field] ?? {})) {
          if (!identities.has(packageIdentity(name, version))) throw new Error(`${packageIdentity(entry.name, record.version)} ${field} names absent ${packageIdentity(name, version)}`);
        }
      }
    }
  }
  return catalog;
}

export function canonicalNpmArchiveUrl(name, version) {
  validatePackageName(name);
  validateVersion(version);
  return npmArchiveUrl(name, version);
}
