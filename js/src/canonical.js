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
    Object.defineProperty(result, key, {
      configurable: true,
      enumerable: true,
      value: canonicalize(value[key], `${path}.${key}`),
      writable: true,
    });
  }
  return result;
}

export function parseJsonNoDuplicateKeys(text, label = "JSON") {
  if (typeof text !== "string") throw new Error(`${label} must be text`);
  let offset = 0;

  function fail(message) {
    throw new Error(`${label} ${message} at byte ${Buffer.byteLength(text.slice(0, offset))}`);
  }

  function whitespace() {
    while (offset < text.length && /[\t\n\r ]/.test(text[offset])) offset += 1;
  }

  function string() {
    if (text[offset] !== '"') fail("expected string");
    const start = offset;
    offset += 1;
    let escaped = false;
    while (offset < text.length) {
      const character = text[offset];
      if (!escaped && character === '"') {
        offset += 1;
        let value;
        try {
          value = JSON.parse(text.slice(start, offset));
        } catch {
          fail("contains invalid string");
        }
        if (!value.isWellFormed()) fail("contains an unpaired surrogate");
        return value;
      }
      if (!escaped && character.charCodeAt(0) < 0x20) fail("contains an unescaped control character");
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      offset += 1;
    }
    fail("has unterminated string");
  }

  function value(depth) {
    if (depth > 128) fail("exceeds maximum nesting");
    whitespace();
    if (text[offset] === '"') return string();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const result = {};
      const keys = new Set();
      if (text[offset] === "}") {
        offset += 1;
        return result;
      }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail(`repeats object key ${JSON.stringify(key)}`);
        keys.add(key);
        whitespace();
        if (text[offset] !== ":") fail("expected colon");
        offset += 1;
        Object.defineProperty(result, key, {
          configurable: true,
          enumerable: true,
          value: value(depth + 1),
          writable: true,
        });
        whitespace();
        if (text[offset] === "}") {
          offset += 1;
          return result;
        }
        if (text[offset] !== ",") fail("expected comma or closing brace");
        offset += 1;
      }
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      const result = [];
      if (text[offset] === "]") {
        offset += 1;
        return result;
      }
      while (true) {
        result.push(value(depth + 1));
        whitespace();
        if (text[offset] === "]") {
          offset += 1;
          return result;
        }
        if (text[offset] !== ",") fail("expected comma or closing bracket");
        offset += 1;
      }
    }
    for (const [token, result] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return result;
      }
    }
    const match = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail("contains invalid value");
    offset += match[0].length;
    const result = Number(match[0]);
    if (!Number.isFinite(result)) fail("contains non-finite number");
    return result;
  }

  const result = value(0);
  whitespace();
  if (offset !== text.length) fail("has trailing bytes");
  return result;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value, "$"), null, 2)}\n`;
}

export function parseCanonicalJson(text, label = "JSON") {
  let value;
  try {
    value = parseJsonNoDuplicateKeys(text, label);
  } catch (error) {
    if (error.message.startsWith(`${label} `)) throw error;
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
