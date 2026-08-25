import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { TextDecoder } from "node:util";

import { cloneSite, readSiteInventory, validateSitePath } from "./artifact.js";
import { parseCanonicalJson } from "./canonical.js";
import { validateCatalog } from "./catalog.js";

export const MAXIMUM_CATALOG_BYTES = 64 * 1024 * 1024;
export const MAXIMUM_SITE_FILE_BYTES = 64 * 1024 * 1024;
export const MAXIMUM_SITE_BYTES = 512 * 1024 * 1024;
export const MAXIMUM_SITE_FILES = 50000;
export const MAXIMUM_SITE_DIRECTORIES = 50000;

const READ_CHUNK_BYTES = 64 * 1024;
const SHA256_ARCHIVE = /^([0-9a-f]{64})\.tgz$/;
const SAFE_OUTPUT_NAME = /^[A-Za-z0-9._~-]+$/;
const utf8 = new TextDecoder("utf-8", { fatal: true });

function requireLinuxFileFlags() {
  if (process.platform !== "linux" || constants.O_DIRECTORY === undefined || constants.O_NOFOLLOW === undefined || typeof process.geteuid !== "function") {
    throw new Error("pkgre-js filesystem operations require Linux O_DIRECTORY,O_NOFOLLOW,and geteuid support");
  }
}

function procDescriptorPath(handle, path = "") {
  return `/proc/self/fd/${handle.fd}${path ? `/${path}` : ""}`;
}

function permissionBits(stat) {
  return Number(stat.mode & 0o7777n);
}

function assertSafeDirectory(stat, label, { writable = false } = {}) {
  if (!stat.isDirectory()) throw new Error(`${label} is not a directory`);
  const mode = permissionBits(stat);
  if (mode & 0o7022) throw new Error(`${label} has unsafe directory mode ${mode.toString(8)}`);
  if ((mode & 0o500) !== 0o500) throw new Error(`${label} lacks owner read and search permission`);
  if (writable && (mode & 0o300) !== 0o300) throw new Error(`${label} lacks owner write and search permission`);
}

function assertSafeFile(stat, label) {
  if (!stat.isFile()) throw new Error(`${label} is not a regular file`);
  const mode = permissionBits(stat);
  if (mode & 0o7133) throw new Error(`${label} has unsafe regular-file mode ${mode.toString(8)}`);
  if (!(mode & 0o400)) throw new Error(`${label} lacks owner read permission`);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function openDirectory(path, label, options) {
  requireLinuxFileFlags();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    assertSafeDirectory(await handle.stat({ bigint: true }), label, options);
    return handle;
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error.message?.startsWith(label)) throw error;
    throw new Error(`cannot open ${label} without following symlinks: ${error.code ?? error.message}`);
  }
}

async function readHandleBounded(handle, maximum, label) {
  const chunks = [];
  let length = 0;
  while (true) {
    const buffer = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, maximum - length + 1));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    length += bytesRead;
    if (length > maximum) throw new Error(`${label} exceeds ${maximum} bytes`);
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
  }
  return Buffer.concat(chunks, length);
}

async function readRegularPath(path, maximum, label) {
  requireLinuxFileFlags();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    assertSafeFile(before, label);
    if (before.size > BigInt(maximum)) throw new Error(`${label} exceeds ${maximum} bytes`);
    const bytes = await readHandleBounded(handle, maximum, label);
    const after = await handle.stat({ bigint: true });
    if (!sameSnapshot(before, after) || after.size !== BigInt(bytes.length)) throw new Error(`${label} changed while it was read`);
    return bytes;
  } catch (error) {
    if (error.message?.startsWith(label)) throw error;
    throw new Error(`cannot read ${label} without following symlinks: ${error.code ?? error.message}`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function decodeUtf8(bytes, label) {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new Error(`${label} is not UTF-8`);
  }
}

function decodeName(name, label) {
  const text = decodeUtf8(name, `${label} name`);
  if (!text.length || Buffer.compare(Buffer.from(text), name) !== 0) throw new Error(`${label} name is not canonical UTF-8`);
  return text;
}

async function readDirectoryHandle(rootHandle, label) {
  const files = new Map();
  let totalBytes = 0;
  let totalDirectories = 0;
  let totalFiles = 0;

  async function walk(directoryHandle, prefix, depth) {
    if (depth > 64) throw new Error(`${label} exceeds maximum directory depth`);
    const before = await directoryHandle.stat({ bigint: true });
    assertSafeDirectory(before, prefix ? `${label}/${prefix}` : label);
    const directoryPath = procDescriptorPath(directoryHandle);
    const entries = await readdir(directoryPath, { encoding: "buffer", withFileTypes: true });
    entries.sort((left, right) => Buffer.compare(left.name, right.name));
    for (const entry of entries) {
      const name = decodeName(entry.name, prefix ? `${label}/${prefix}` : label);
      const path = prefix ? `${prefix}/${name}` : name;
      validateSitePath(path);
      const entryPath = procDescriptorPath(directoryHandle, name);
      if (entry.isSymbolicLink()) throw new Error(`${label}/${path} is a forbidden symbolic link`);
      if (entry.isDirectory()) {
        totalDirectories += 1;
        if (totalDirectories > MAXIMUM_SITE_DIRECTORIES) throw new Error(`${label} exceeds ${MAXIMUM_SITE_DIRECTORIES} directories`);
        const child = await openDirectory(entryPath, `${label}/${path}`);
        try {
          await walk(child, path, depth + 1);
        } finally {
          await child.close();
        }
      } else if (entry.isFile()) {
        totalFiles += 1;
        if (totalFiles > MAXIMUM_SITE_FILES) throw new Error(`${label} exceeds ${MAXIMUM_SITE_FILES} files`);
        const bytes = await readRegularPath(entryPath, MAXIMUM_SITE_FILE_BYTES, `${label}/${path}`);
        totalBytes += bytes.length;
        if (totalBytes > MAXIMUM_SITE_BYTES) throw new Error(`${label} exceeds ${MAXIMUM_SITE_BYTES} bytes`);
        files.set(path, bytes);
      } else {
        throw new Error(`${label}/${path} is not a regular file or directory`);
      }
    }
    const after = await directoryHandle.stat({ bigint: true });
    if (!sameSnapshot(before, after)) throw new Error(`${prefix ? `${label}/${prefix}` : label} changed while it was read`);
  }

  await walk(rootHandle, "", 0);
  return cloneSite(files);
}

async function readDirectory(path, label) {
  const root = await openDirectory(path, label);
  try {
    return await readDirectoryHandle(root, label);
  } finally {
    await root.close();
  }
}

export async function readCatalogFile(path) {
  const bytes = await readRegularPath(path, MAXIMUM_CATALOG_BYTES, "catalog");
  const catalog = parseCanonicalJson(decodeUtf8(bytes, "catalog"), "catalog");
  validateCatalog(catalog);
  return catalog;
}

export async function readArchiveDirectory(catalog, path) {
  validateCatalog(catalog);
  const files = await readDirectory(path, "archive directory");
  const expected = new Set(catalog.packages.flatMap((entry) => entry.versions.map((record) => `${record.source.sha256}.tgz`)));
  const actual = new Set(files.keys());
  for (const name of actual) {
    if (!SHA256_ARCHIVE.test(name)) throw new Error(`archive directory has invalid entry ${name}`);
    if (!expected.has(name)) throw new Error(`archive directory has unreferenced archive ${name}`);
  }
  for (const name of expected) {
    if (!actual.has(name)) throw new Error(`archive directory is missing ${name}`);
  }
  return new Map([...files].map(([name, bytes]) => [name.match(SHA256_ARCHIVE)[1], bytes]));
}

export async function readSiteDirectory(path) {
  const site = await readDirectory(path, "site directory");
  readSiteInventory(site);
  return site;
}

function compareSites(expected, actual) {
  if (expected.size !== actual.size) throw new Error("staged site file count differs after write");
  for (const [path, bytes] of expected) {
    const written = actual.get(path);
    if (!written || !written.equals(bytes)) throw new Error(`staged site bytes differ after write at ${path}`);
  }
}

function assertSiteBounds(site) {
  if (site.size > MAXIMUM_SITE_FILES) throw new Error(`generated site exceeds ${MAXIMUM_SITE_FILES} files`);
  let totalBytes = 0;
  for (const [path, bytes] of site) {
    if (bytes.length > MAXIMUM_SITE_FILE_BYTES) throw new Error(`generated site file ${path} exceeds ${MAXIMUM_SITE_FILE_BYTES} bytes`);
    totalBytes += bytes.length;
    if (totalBytes > MAXIMUM_SITE_BYTES) throw new Error(`generated site exceeds ${MAXIMUM_SITE_BYTES} bytes`);
  }
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function siteDirectories(site) {
  const directories = new Set();
  for (const path of site.keys()) {
    const components = path.split("/");
    for (let end = 1; end < components.length; end += 1) {
      directories.add(components.slice(0, end).join("/"));
      if (directories.size > MAXIMUM_SITE_DIRECTORIES) throw new Error(`generated site exceeds ${MAXIMUM_SITE_DIRECTORIES} directories`);
    }
  }
  return [...directories].sort((left, right) => left.split("/").length - right.split("/").length || compareStrings(left, right));
}

async function syncDirectory(path, label) {
  const handle = await openDirectory(path, label);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function outputAbsent(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw new Error(`cannot inspect output path: ${error.code ?? error.message}`);
  }
  throw new Error("output path already exists");
}

export async function writeSiteDirectory(outputPath, site) {
  requireLinuxFileFlags();
  const files = cloneSite(site);
  assertSiteBounds(files);
  if (!readSiteInventory(files)) throw new Error("generated site inventory is absent");
  const absoluteOutput = resolve(outputPath);
  const outputName = basename(absoluteOutput);
  if (!SAFE_OUTPUT_NAME.test(outputName) || outputName === "." || outputName === ".." || dirname(absoluteOutput) === absoluteOutput) throw new Error("output path has an unsafe basename");

  const parentPath = dirname(absoluteOutput);
  const parent = await openDirectory(parentPath, "output parent", { writable: true });
  let temporaryName;
  let temporaryHandle;
  let renamed = false;
  try {
    const parentStat = await parent.stat({ bigint: true });
    if (parentStat.uid !== BigInt(process.geteuid())) throw new Error("output parent is not owned by the current effective user");
    const parentDescriptor = procDescriptorPath(parent);
    await outputAbsent(`${parentDescriptor}/${outputName}`);
    const temporaryPath = await mkdtemp(`${parentDescriptor}/.${outputName}.pkgre-js-`);
    temporaryName = basename(temporaryPath);
    await chmod(temporaryPath, 0o700);
    temporaryHandle = await openDirectory(temporaryPath, "staged site");

    const directories = siteDirectories(files);
    for (const path of directories) {
      const pathOnDisk = procDescriptorPath(temporaryHandle, path);
      await mkdir(pathOnDisk, { mode: 0o755 });
      await chmod(pathOnDisk, 0o755);
    }
    for (const [path, bytes] of files) {
      const pathOnDisk = procDescriptorPath(temporaryHandle, path);
      const handle = await open(pathOnDisk, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
      try {
        await handle.chmod(0o644);
        await handle.writeFile(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    for (const path of [...directories].reverse()) await syncDirectory(procDescriptorPath(temporaryHandle, path), `staged site/${path}`);
    await temporaryHandle.sync();
    compareSites(files, await readDirectoryHandle(temporaryHandle, "staged site"));
    await temporaryHandle.chmod(0o755);
    await temporaryHandle.sync();

    await outputAbsent(`${parentDescriptor}/${outputName}`);
    await rename(`${parentDescriptor}/${temporaryName}`, `${parentDescriptor}/${outputName}`);
    renamed = true;
    await parent.sync();
  } finally {
    await temporaryHandle?.close().catch(() => {});
    if (temporaryName && !renamed) await rm(procDescriptorPath(parent, temporaryName), { force: true, recursive: true }).catch(() => {});
    await parent.close();
  }
}
