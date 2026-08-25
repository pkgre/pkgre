import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { gunzipSync } from "node:zlib";

import { canonicalJson, packageIdentity, parseJsonNoDuplicateKeys } from "./canonical.js";
import { selectInstallManifest } from "./catalog.js";

const BLOCK_BYTES = 512;
const MAXIMUM_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_UNCOMPRESSED_BYTES = 256 * 1024 * 1024;
const MAXIMUM_ENTRY_BYTES = 64 * 1024 * 1024;
const MAXIMUM_ENTRIES = 10000;
const MAXIMUM_PATH_BYTES = 4096;
const MAXIMUM_PACKAGE_JSON_BYTES = 1024 * 1024;
const utf8 = new TextDecoder("utf-8", { fatal: true });

function digest(algorithm, bytes, encoding = "hex") {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function verifyCompressedBytes(bytes, source) {
  if (bytes.length === 0 || bytes.length > MAXIMUM_ARCHIVE_BYTES) throw new Error("archive compressed size is outside the supported bounds");
  if (!Number.isSafeInteger(source?.bytes) || source.bytes !== bytes.length) throw new Error("archive compressed byte length does not match source.bytes");
  if (digest("sha1", bytes) !== source.sha1) throw new Error("archive SHA-1 does not match source.sha1");
  if (digest("sha256", bytes) !== source.sha256) throw new Error("archive SHA-256 does not match source.sha256");
  if (`sha512-${digest("sha512", bytes, "base64")}` !== source.integrity) throw new Error("archive SHA-512 does not match source.integrity");
}

function tarString(header, offset, length, label, allowEmpty = true) {
  const field = header.subarray(offset, offset + length);
  const nul = field.indexOf(0);
  const content = nul === -1 ? field : field.subarray(0, nul);
  if (nul !== -1 && field.subarray(nul).some((byte) => byte !== 0)) throw new Error(`tar ${label} has bytes after its NUL terminator`);
  let value;
  try {
    value = utf8.decode(content);
  } catch {
    throw new Error(`tar ${label} is not UTF-8`);
  }
  if (!allowEmpty && !value.length) throw new Error(`tar ${label} is empty`);
  return value;
}

function tarNumber(header, offset, length, label, maximum, allowEmpty = false) {
  const field = header.subarray(offset, offset + length);
  if (field[0] & 0x80) throw new Error(`tar ${label} uses unsupported base-256 encoding`);
  const text = field.toString("ascii");
  if ([...field].some((byte) => byte > 0x7f)) throw new Error(`tar ${label} is not ASCII octal`);
  const match = text.match(/^ *([0-7]+)[ \0]*$/);
  if (!match) {
    if (allowEmpty && /^[ \0]*$/.test(text)) return 0;
    throw new Error(`tar ${label} is not canonical octal`);
  }
  const value = BigInt(`0o${match[1]}`);
  if (value > BigInt(maximum)) throw new Error(`tar ${label} exceeds its supported bound`);
  return Number(value);
}

function headerChecksum(header) {
  let checksum = 0;
  for (let index = 0; index < header.length; index += 1) checksum += index >= 148 && index < 156 ? 0x20 : header[index];
  return checksum;
}

function canonicalPath(prefix, name, type) {
  const raw = prefix.length ? `${prefix}/${name}` : name;
  if (!raw.length || Buffer.byteLength(raw) > MAXIMUM_PATH_BYTES) throw new Error("tar entry path is outside the supported bounds");
  if (raw.includes("\\") || raw.startsWith("/") || /[\u0000-\u001f\u007f]/.test(raw)) throw new Error(`tar entry has unsafe path ${JSON.stringify(raw)}`);
  const directory = type === "directory";
  const path = directory && raw.endsWith("/") ? raw.slice(0, -1) : raw;
  if (!directory && path.endsWith("/")) throw new Error(`tar regular file has directory path ${JSON.stringify(raw)}`);
  const components = path.split("/");
  if (components.some((component) => !component.length || component === "." || component === "..")) throw new Error(`tar entry has unsafe path ${JSON.stringify(raw)}`);
  if (components[0] !== "package" || components.length === 1 && !directory) throw new Error(`tar entry is outside package/ at ${JSON.stringify(raw)}`);
  if (path.normalize("NFC") !== path) throw new Error(`tar entry path is not NFC ${JSON.stringify(raw)}`);
  return path;
}

function validateHeader(header) {
  if (!header.subarray(257, 263).equals(Buffer.from("ustar\0")) || !header.subarray(263, 265).equals(Buffer.from("00"))) {
    throw new Error("tar entry is not POSIX ustar format");
  }
  const storedChecksum = tarNumber(header, 148, 8, "checksum", 0o777777);
  if (storedChecksum !== headerChecksum(header)) throw new Error("tar header checksum mismatch");
  const mode = tarNumber(header, 100, 8, "mode", 0o7777);
  if (mode & 0o7000) throw new Error("tar entry has setuid,setgid,or sticky mode bits");
  tarNumber(header, 108, 8, "uid", 0o7777777, true);
  tarNumber(header, 116, 8, "gid", 0o7777777, true);
  const size = tarNumber(header, 124, 12, "size", MAXIMUM_ENTRY_BYTES);
  tarNumber(header, 136, 12, "mtime", Number.MAX_SAFE_INTEGER, true);
  tarNumber(header, 329, 8, "device major", 0o7777777, true);
  tarNumber(header, 337, 8, "device minor", 0o7777777, true);
  tarString(header, 265, 32, "owner name");
  tarString(header, 297, 32, "group name");
  const name = tarString(header, 0, 100, "name", false);
  const prefix = tarString(header, 345, 155, "prefix");
  const linkName = tarString(header, 157, 100, "link name");
  if (linkName.length) throw new Error("tar regular files and directories must have an empty link name");
  const typeByte = header[156];
  let type;
  if (typeByte === 0 || typeByte === 0x30) type = "file";
  else if (typeByte === 0x35) type = "directory";
  else throw new Error(`tar entry has unsupported type 0x${typeByte.toString(16).padStart(2, "0")}`);
  const permissions = mode & 0o777;
  if (type === "file" && permissions !== 0o644 && permissions !== 0o755) throw new Error("tar regular-file mode must be 0644 or 0755");
  if (type === "directory" && permissions !== 0o755) throw new Error("tar directory mode must be 0755");
  if (type === "directory" && size !== 0) throw new Error("tar directory has nonzero size");
  return { mode, path: canonicalPath(prefix, name, type), size, type };
}

function addPath(pathTypes, path, type) {
  if (pathTypes.has(path)) throw new Error(`tar repeats path ${JSON.stringify(path)}`);
  const components = path.split("/");
  for (let end = 1; end < components.length; end += 1) {
    const parent = components.slice(0, end).join("/");
    if (pathTypes.get(parent) === "file") throw new Error(`tar places ${JSON.stringify(path)} below regular file ${JSON.stringify(parent)}`);
  }
  if (type === "file") {
    for (const prior of pathTypes.keys()) {
      if (prior.startsWith(`${path}/`)) throw new Error(`tar regular file ${JSON.stringify(path)} contains prior path ${JSON.stringify(prior)}`);
    }
  }
  pathTypes.set(path, type);
}

function parseTar(bytes) {
  if (bytes.length % BLOCK_BYTES !== 0) throw new Error("tar byte length is not block aligned");
  const entries = [];
  const pathTypes = new Map();
  let packageJson;
  let offset = 0;
  let ended = false;
  while (offset < bytes.length) {
    const header = bytes.subarray(offset, offset + BLOCK_BYTES);
    if (header.every((byte) => byte === 0)) {
      if (bytes.length - offset < 2 * BLOCK_BYTES || bytes.subarray(offset).some((byte) => byte !== 0)) throw new Error("tar has an invalid end-of-archive sequence");
      ended = true;
      break;
    }
    if (entries.length >= MAXIMUM_ENTRIES) throw new Error("tar has too many entries");
    const entry = validateHeader(header);
    addPath(pathTypes, entry.path, entry.type);
    const dataOffset = offset + BLOCK_BYTES;
    const dataEnd = dataOffset + entry.size;
    const nextOffset = dataOffset + Math.ceil(entry.size / BLOCK_BYTES) * BLOCK_BYTES;
    if (dataEnd > bytes.length || nextOffset > bytes.length) throw new Error(`tar entry ${JSON.stringify(entry.path)} exceeds archive bounds`);
    if (bytes.subarray(dataEnd, nextOffset).some((byte) => byte !== 0)) throw new Error(`tar entry ${JSON.stringify(entry.path)} has nonzero padding`);
    if (entry.path === "package/package.json") {
      if (entry.type !== "file") throw new Error("package/package.json is not a regular file");
      if (entry.size === 0 || entry.size > MAXIMUM_PACKAGE_JSON_BYTES) throw new Error("package/package.json size is outside the supported bounds");
      packageJson = Buffer.from(bytes.subarray(dataOffset, dataEnd));
    }
    entries.push(Object.freeze({ ...entry }));
    offset = nextOffset;
  }
  if (!ended) throw new Error("tar is missing its end-of-archive sequence");
  if (!packageJson) throw new Error("tar must contain exactly one package/package.json");
  return Object.freeze({ entries: Object.freeze(entries), packageJson });
}

export function inspectPackageArchive(archiveBytes, source) {
  if (!(archiveBytes instanceof Uint8Array)) throw new Error("archive must be bytes");
  const bytes = Buffer.from(archiveBytes);
  verifyCompressedBytes(bytes, source);
  let tar;
  try {
    tar = gunzipSync(bytes, { maxOutputLength: MAXIMUM_UNCOMPRESSED_BYTES });
  } catch (error) {
    throw new Error(`archive is not a bounded valid gzip stream: ${error.code ?? error.message}`);
  }
  return parseTar(tar);
}

export function verifyPackageArchive(archiveBytes, name, record) {
  const identity = packageIdentity(name, record?.version);
  const inspected = inspectPackageArchive(archiveBytes, record?.source);
  let packageJsonText;
  try {
    packageJsonText = utf8.decode(inspected.packageJson);
  } catch {
    throw new Error(`${identity} package/package.json is not UTF-8`);
  }
  const packageJson = parseJsonNoDuplicateKeys(packageJsonText, `${identity} package/package.json`);
  const manifest = selectInstallManifest(packageJson, name, record.version);
  if (canonicalJson(manifest) !== canonicalJson(record.manifest)) throw new Error(`${identity} archived install manifest does not match catalog manifest`);

  const scripts = packageJson?.scripts;
  if (scripts !== undefined && (scripts === null || typeof scripts !== "object" || Array.isArray(scripts))) throw new Error(`${identity} package scripts must be an object`);
  for (const hook of ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare", "dependencies"]) {
    if (scripts && Object.hasOwn(scripts, hook)) throw new Error(`${identity} archive contains forbidden lifecycle hook ${hook}`);
  }
  if (Object.hasOwn(packageJson, "gypfile")) throw new Error(`${identity} archive contains forbidden gypfile declaration`);
  for (const field of ["bundleDependencies", "bundledDependencies"]) {
    if (Object.hasOwn(packageJson, field)) throw new Error(`${identity} archive contains forbidden ${field} declaration`);
  }

  const files = new Set(inspected.entries.filter((entry) => entry.type === "file").map((entry) => entry.path));
  for (const path of files) {
    const base = path.slice(path.lastIndexOf("/") + 1);
    if (base === "binding.gyp" || base.endsWith(".node")) throw new Error(`${identity} archive contains native-addon indicator ${path}`);
    if (path === "package/.npmrc" || path === "package/npm-shrinkwrap.json" || path === "package/node_modules" || path.startsWith("package/node_modules/")) {
      throw new Error(`${identity} archive contains forbidden package-manager input ${path}`);
    }
  }
  for (const entry of inspected.entries) {
    if (entry.path === "package/node_modules" || entry.path.startsWith("package/node_modules/")) {
      throw new Error(`${identity} archive contains forbidden package-manager input ${entry.path}`);
    }
  }
  for (const path of Object.values(manifest.bin ?? {})) {
    const normalized = path.startsWith("./") ? path.slice(2) : path;
    if (!files.has(`package/${normalized}`)) throw new Error(`${identity} bin target ${JSON.stringify(path)} is not an archived regular file`);
  }

  return Object.freeze({ entries: inspected.entries, manifest });
}
