import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";

import { buildServeSnapshot } from "../src/serve/snapshot.js";
import { archiveDigests, fixtureCatalog, packageArchive } from "./support.js";

const tempRoots = [];

function tempStore(name, files) {
  const directory = mkdtempSync(path.join(tmpdir(), `pkgre-serve-${name}-`));
  for (const [file, bytes] of Object.entries(files)) writeFileSync(path.join(directory, file), bytes);
  tempRoots.push(directory);
  return directory;
}

after(() => {
  for (const directory of tempRoots) rmSync(directory, { force: true, recursive: true });
});

const fixture = fixtureCatalog();
const helper = fixture.catalog.packages.find((entry) => entry.name === "@scope/helper").versions[0];
const pkgre = fixture.catalog.packages.find((entry) => entry.name === "pkgre-js").versions[0];

/** Copies the fixture catalog with NAME's archive replaced by archiveBytes. */
function catalogWithArchive(name, archiveBytes) {
  const catalog = structuredClone(fixture.catalog);
  const record = catalog.packages.find((entry) => entry.name === name).versions[0];
  const digests = archiveDigests(archiveBytes);
  Object.assign(record.source, digests);
  if (record.source.kind === "first-party") record.source.url = `https://js.pkg.re/packages/${digests.sha256}.tgz`;
  return catalog;
}

test("body delivery refuses an archive with a lifecycle hook", async () => {
  const archive = packageArchive({ ...helper.manifest, scripts: { install: "node install.js" } });
  const store = tempStore("hooked", {
    [`${archiveDigests(archive).sha256}.tgz`]: archive,
    [`${fixture.pkgreSha256}.tgz`]: fixture.pkgreArchive,
  });
  await assert.rejects(
    buildServeSnapshot(catalogWithArchive("@scope/helper", archive), store, "body"),
    /serving snapshot refuses @scope\/helper@1\.2\.3: @scope\/helper@1\.2\.3 archive contains forbidden lifecycle hook install/,
  );
});

test("body delivery refuses an archive whose manifest identity differs", async () => {
  const archive = packageArchive({ ...helper.manifest, name: "@scope/other" });
  const store = tempStore("renamed", {
    [`${archiveDigests(archive).sha256}.tgz`]: archive,
    [`${fixture.pkgreSha256}.tgz`]: fixture.pkgreArchive,
  });
  await assert.rejects(
    buildServeSnapshot(catalogWithArchive("@scope/helper", archive), store, "body"),
    /serving snapshot refuses @scope\/helper@1\.2\.3: manifest identity does not match @scope\/helper@1\.2\.3/,
  );
});

test("redirect delivery refuses a first-party body that breaks the archive contract", async () => {
  const archive = packageArchive(
    { ...pkgre.manifest, scripts: { postinstall: "node postinstall.js" } },
    [{ data: "#!/usr/bin/env node\n", mode: 0o755, name: "package/src/main.js" }],
  );
  const store = tempStore("first-party-hooked", { [`${archiveDigests(archive).sha256}.tgz`]: archive });
  await assert.rejects(
    buildServeSnapshot(catalogWithArchive("pkgre-js", archive), store, "redirect"),
    /serving snapshot refuses pkgre-js@0\.1\.0: pkgre-js@0\.1\.0 archive contains forbidden lifecycle hook postinstall/,
  );
});

const bootstrapRoot = new URL("../fixtures/projection-current-v1/", import.meta.url);

test("the frozen bootstrap catalog builds in both delivery modes", async () => {
  const catalog = JSON.parse(await readFile(new URL("catalog.json", bootstrapRoot), "utf8"));
  const record = catalog.packages[0].versions[0];
  const archive = await readFile(new URL(`${record.source.sha256}.tgz`, bootstrapRoot));
  const packument = await readFile(new URL("packument.json", bootstrapRoot));
  const store = tempStore("bootstrap", { [`${record.source.sha256}.tgz`]: archive });

  const redirect = await buildServeSnapshot(catalog, store, "redirect");
  const body = await buildServeSnapshot(catalog, store, "body");
  assert.deepEqual(redirect.counts, { archive: 1, inline: 1, redirect: 1 });
  assert.deepEqual(body.counts, { archive: 2, inline: 1, redirect: 0 });

  const objectRoute = `/packages/${record.source.sha256}.tgz`;
  const archiveRoute = `/v1/js/main/${record.source.sha256}`;
  assert.equal(redirect.routes.get(archiveRoute).get.status, 302);
  assert.equal(redirect.routes.get(archiveRoute).get.headers.Location, record.source.url);
  assert.deepEqual(Buffer.from(await redirect.routes.get(objectRoute).get.body.arrayBuffer()), archive);
  assert.deepEqual(Buffer.from(await body.routes.get(archiveRoute).get.body.arrayBuffer()), archive);
  assert.deepEqual(Buffer.from(await redirect.routes.get("/pkgre-js").get.body.arrayBuffer()), packument);
});
