import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/canonical.js";
import {
  MAXIMUM_CATALOG_BYTES,
  readArchiveDirectory,
  readCatalogFile,
  readSiteDirectory,
  writeSiteDirectory,
} from "../src/filesystem.js";
import { renderFinal, renderRoutes } from "../src/render.js";
import { fixtureCatalog } from "./support.js";

async function temporary(t) {
  const path = await mkdtemp(join(tmpdir(), "pkgre-js-filesystem-"));
  await chmod(path, 0o700);
  t.after(() => rm(path, { force: true, recursive: true }));
  return path;
}

async function writeRegular(path, bytes) {
  await writeFile(path, bytes, { mode: 0o644 });
  await chmod(path, 0o644);
}

async function writeRawSite(root, site) {
  await mkdir(root, { mode: 0o755 });
  await chmod(root, 0o755);
  const directories = new Set();
  for (const path of site.keys()) {
    const components = path.split("/");
    for (let end = 1; end < components.length; end += 1) directories.add(components.slice(0, end).join("/"));
  }
  for (const path of [...directories].sort()) {
    await mkdir(join(root, path), { mode: 0o755, recursive: true });
    await chmod(join(root, path), 0o755);
  }
  for (const [path, bytes] of site) await writeRegular(join(root, path), bytes);
}

function assertSitesEqual(actual, expected) {
  assert.deepEqual([...actual.keys()].sort(), [...expected.keys()].sort());
  for (const [path, bytes] of expected) assert.deepEqual(actual.get(path), bytes, path);
}

async function writeFixtureInputs(root, fixture = fixtureCatalog()) {
  const catalogPath = join(root, "catalog.json");
  const archivePath = join(root, "archives");
  await writeRegular(catalogPath, canonicalJson(fixture.catalog));
  await mkdir(archivePath, { mode: 0o755 });
  await chmod(archivePath, 0o755);
  for (const [sha256, bytes] of fixture.archives) await writeRegular(join(archivePath, `${sha256}.tgz`), bytes);
  return { archivePath, catalogPath, fixture };
}

test("reads one canonical catalog and its exact closed archive directory", async (t) => {
  const root = await temporary(t);
  const { archivePath, catalogPath, fixture } = await writeFixtureInputs(root);
  const catalog = await readCatalogFile(catalogPath);
  const archives = await readArchiveDirectory(catalog, archivePath);
  assert.deepEqual(catalog, fixture.catalog);
  assertSitesEqual(archives, fixture.archives);
});

test("rejects noncanonical,non-UTF-8,oversize,and symlinked catalogs", async (t) => {
  const root = await temporary(t);
  const fixture = fixtureCatalog();
  const catalogPath = join(root, "catalog.json");

  await writeRegular(catalogPath, JSON.stringify(fixture.catalog));
  await assert.rejects(readCatalogFile(catalogPath), /not canonical JSON/);
  await writeRegular(catalogPath, Buffer.from([0xff]));
  await assert.rejects(readCatalogFile(catalogPath), /not UTF-8/);
  await truncate(catalogPath, MAXIMUM_CATALOG_BYTES + 1);
  await assert.rejects(readCatalogFile(catalogPath), /exceeds/);
  await rm(catalogPath);
  const target = join(root, "real-catalog.json");
  await writeRegular(target, canonicalJson(fixture.catalog));
  await symlink(target, catalogPath);
  await assert.rejects(readCatalogFile(catalogPath), /without following symlinks/);
});

test("rejects missing,extra,invalid,and symlinked archive entries", async (t) => {
  const root = await temporary(t);
  const { archivePath, fixture } = await writeFixtureInputs(root);
  const expectedName = `${fixture.helperSha256}.tgz`;

  await rm(join(archivePath, expectedName));
  await assert.rejects(readArchiveDirectory(fixture.catalog, archivePath), /is missing/);
  await writeRegular(join(archivePath, expectedName), fixture.helperArchive);
  await writeRegular(join(archivePath, `${"f".repeat(64)}.tgz`), Buffer.from("extra"));
  await assert.rejects(readArchiveDirectory(fixture.catalog, archivePath), /unreferenced archive/);
  await rm(join(archivePath, `${"f".repeat(64)}.tgz`));
  await writeRegular(join(archivePath, "README"), Buffer.from("extra"));
  await assert.rejects(readArchiveDirectory(fixture.catalog, archivePath), /invalid entry/);
  await rm(join(archivePath, "README"));
  await rm(join(archivePath, expectedName));
  await symlink(join(root, "catalog.json"), join(archivePath, expectedName));
  await assert.rejects(readArchiveDirectory(fixture.catalog, archivePath), /forbidden symbolic link/);
});

test("rejects symlinked ancestor components for every filesystem operation", async (t) => {
  const root = await temporary(t);
  const real = join(root, "real");
  await mkdir(real, { mode: 0o700 });
  await chmod(real, 0o700);
  const { fixture } = await writeFixtureInputs(real);
  const site = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives));
  await writeRawSite(join(real, "site"), site);
  await symlink("real", join(root, "linked"));

  await assert.rejects(readCatalogFile(join(root, "linked/catalog.json")), /without following symlinks/);
  await assert.rejects(readArchiveDirectory(fixture.catalog, join(root, "linked/archives")), /without following symlinks/);
  await assert.rejects(readSiteDirectory(join(root, "linked/site")), /without following symlinks/);
  await assert.rejects(writeSiteDirectory(join(root, "linked/output"), site), /without following symlinks/);
  await assert.rejects(lstat(join(real, "output")), { code: "ENOENT" });
});

test("walks sites without following links and enforces safe paths and modes", async (t) => {
  const root = await temporary(t);
  const fixture = fixtureCatalog();
  const basePath = join(root, "base");
  const base = new Map([["index.html", Buffer.from("base")]]);
  await writeRawSite(basePath, base);
  assertSitesEqual(await readSiteDirectory(basePath), base);

  const final = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives, base));
  const sitePath = join(root, "site");
  await writeRawSite(sitePath, final);
  assertSitesEqual(await readSiteDirectory(sitePath), final);

  await symlink("index.html", join(sitePath, "link"));
  await assert.rejects(readSiteDirectory(sitePath), /forbidden symbolic link/);
  await rm(join(sitePath, "link"));
  await chmod(join(sitePath, "index.html"), 0o755);
  await assert.rejects(readSiteDirectory(sitePath), /unsafe regular-file mode/);
  await chmod(join(sitePath, "index.html"), 0o644);
  await writeRegular(join(sitePath, "unsafe name"), Buffer.from("unsafe"));
  await assert.rejects(readSiteDirectory(sitePath), /invalid site path/);
  await rm(join(sitePath, "unsafe name"));
  await chmod(sitePath, 0o777);
  await assert.rejects(readSiteDirectory(sitePath), /unsafe directory mode/);
});

test("writes,fsyncs,verifies,and atomically installs a new site with fixed modes", async (t) => {
  const root = await temporary(t);
  const fixture = fixtureCatalog();
  const final = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives, new Map([["index.html", Buffer.from("base")]])));
  const output = join(root, "site-next");

  await writeSiteDirectory(output, final);
  assertSitesEqual(await readSiteDirectory(output), final);
  assert.equal(Number((await lstat(output, { bigint: true })).mode & 0o7777n), 0o755);
  assert.equal(Number((await lstat(join(output, "v1/js/main"), { bigint: true })).mode & 0o7777n), 0o755);
  assert.equal(Number((await lstat(join(output, "index.html"), { bigint: true })).mode & 0o7777n), 0o644);
  assert.equal(Number((await lstat(join(output, `packages/${fixture.pkgreSha256}.tgz`), { bigint: true })).mode & 0o7777n), 0o644);

  const before = await readFile(join(output, "index.html"));
  await assert.rejects(writeSiteDirectory(output, final), /already exists/);
  assert.deepEqual(await readFile(join(output, "index.html")), before);
  assert.deepEqual((await readdir(root)).sort(), ["site-next"]);
});

test("refuses unsafe parents,existing symlink outputs,and uninventoried generated sites", async (t) => {
  const root = await temporary(t);
  const fixture = fixtureCatalog();
  const final = renderFinal(fixture.catalog, renderRoutes(fixture.catalog, fixture.archives));

  const target = join(root, "target");
  await mkdir(target, { mode: 0o755 });
  await writeRegular(join(target, "sentinel"), Buffer.from("preserve"));
  const output = join(root, "site-link");
  await symlink(target, output);
  await assert.rejects(writeSiteDirectory(output, final), /already exists/);
  assert.equal((await readFile(join(target, "sentinel"))).toString(), "preserve");

  await chmod(root, 0o777);
  await assert.rejects(writeSiteDirectory(join(root, "unsafe-parent-output"), final), /unsafe directory mode/);
  await chmod(root, 0o700);

  await assert.rejects(writeSiteDirectory(join(root, "no-inventory"), new Map([["index.html", Buffer.from("base")]])), /inventory is absent/);
  assert.equal((await readdir(root)).some((name) => name.startsWith(".no-inventory.pkgre-js-")), false);
  await assert.rejects(writeSiteDirectory(join(root, "unsafe output"), final), /unsafe basename/);
});
