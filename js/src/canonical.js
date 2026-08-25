const RESERVED_ROOT_NAMES = new Set([
  "index.html",
  "nonproduction",
  "origin-health",
  "packages",
  "v1",
]);
const NPM_COMPONENT = /^[a-z][a-z0-9._~-]*$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

function canonicalize(value, path) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${path} contains a non-safe-integer number`);
    return value;
  }
  if (Array.isArray(value)) return value.map((item, index) => canonicalize(item, `${path}[${index}]`));
  if (typeof value !== "object") throw new Error(`${path} contains unsupported JSON value`);
  const result = {};
  for (const key of Object.keys(value).sort()) {
    result[key] = canonicalize(value[key], `${path}.${key}`);
  }
  return result;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value, "$"), null, 2)}\n`;
}

export function parseCanonicalJson(text, label = "JSON") {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is not JSON: ${error.message}`);
  }
  if (canonicalJson(value) !== text) throw new Error(`${label} is not canonical JSON`);
  return value;
}

function validComponent(value) {
  return typeof value === "string" && value.length <= 214 && NPM_COMPONENT.test(value);
}

export function validatePackageName(name) {
  if (typeof name !== "string" || !name.length || name.length > 214 || !name.isWellFormed() || !/^[\x00-\x7f]+$/.test(name)) {
    throw new Error(`invalid package name ${JSON.stringify(name)}`);
  }
  if (name.startsWith("@")) {
    const segments = name.split("/");
    if (segments.length !== 2 || !validComponent(segments[0].slice(1)) || !validComponent(segments[1])) {
      throw new Error(`invalid scoped package name ${JSON.stringify(name)}`);
    }
  } else if (!validComponent(name) || RESERVED_ROOT_NAMES.has(name)) {
    throw new Error(`invalid unscoped package name ${JSON.stringify(name)}`);
  }
  return name;
}

export function validateVersion(version) {
  if (typeof version !== "string" || version.length > 256 || !SEMVER.test(version)) {
    throw new Error(`invalid canonical SemVer ${JSON.stringify(version)}`);
  }
  return version;
}

export function packageMetadataPath(name) {
  validatePackageName(name);
  return name;
}

export function packageIdentity(name, version) {
  return `${validatePackageName(name)}@${validateVersion(version)}`;
}
