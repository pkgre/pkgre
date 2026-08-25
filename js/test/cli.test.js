import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../src/canonical.js";
import { run, USAGE } from "../src/cli.js";
import { readSiteDirectory } from "../src/filesystem.js";
import { verifySite } from "../src/render.js";
import { fixtureCatalog } from "./support.js";

const main = fileURLToPath(new URL("../src/main.js", import.meta.url));

async function temporary(t) {
  const path = await mkdtemp(join(tmpdir(), "pkgre-js-cli-"));
  await chmod(path, 0o700);
  t.after(() => rm(path, { force: true, recursive: true }));
  return path;
}

async function fixturePaths(t) {
  const root = await temporary(t);
  const fixture = fixtureCatalog();
  const catalog = join(root, "catalog.json");
  const archives = join(root, "archives");
  const previous = join(root, "previous");
  await writeFile(catalog, canonicalJson(fixture.catalog), { mode: 0o644 });
  await chmod(catalog, 0o644);
  await mkdir(archives, { mode: 0o755 });
  await chmod(archives, 0o755);
  for (const [sha256, bytes] of fixture.archives) {
    const path = join(archives, `${sha256}.tgz`);
    await writeFile(path, bytes, { mode: 0o644 });
    await chmod(path, 0o644);
  }
  await mkdir(previous, { mode: 0o755 });
  await chmod(previous, 0o755);
  await writeFile(join(previous, "index.html"), "base\n", { mode: 0o644 });
  await chmod(join(previous, "index.html"), 0o644);
  return { archives, catalog, fixture, previous, root };
}

function success(stdout) {
  return { status: 0, stderr: "", stdout };
}

test("reports deterministic help and rejects invalid invocations", async () => {
  assert.deepEqual(await run(["--help"]), success(`${USAGE}\n`));
  assert.deepEqual(await run(["-h"]), success(`${USAGE}\n`));
  assert.deepEqual(await run([]), { status: 2, stderr: `error: command is required\n${USAGE}\n`, stdout: "" });
  assert.deepEqual(await run(["unknown"]), { status: 2, stderr: `error: unknown command\n${USAGE}\n`, stdout: "" });
  assert.deepEqual(await run(["verify", "one"]), { status: 2, stderr: `error: verify requires 2 arguments\n${USAGE}\n`, stdout: "" });
  assert.deepEqual(await run([null]), { status: 2, stderr: `error: arguments must be strings\n${USAGE}\n`, stdout: "" });
});

test("checks,renders,and verifies one local staged publication", async (t) => {
  const { archives, catalog, fixture, previous, root } = await fixturePaths(t);
  const routes = join(root, "routes");
  const final = join(root, "final");

  assert.deepEqual(await run(["check", catalog, archives]), success("ok command=check packages=2 versions=2 archives=2\n"));
  assert.deepEqual(await run(["render-routes", catalog, archives, previous, routes]), success("ok command=render-routes stage=routes files=5\n"));
  assert.deepEqual(await run(["verify", catalog, routes]), success("ok command=verify stage=routes files=5\n"));
  assert.deepEqual(await run(["render-final", catalog, routes, final]), success("ok command=render-final stage=final files=7\n"));
  assert.deepEqual(await run(["verify", catalog, final]), success("ok command=verify stage=final files=7\n"));
  assert.deepEqual(await run(["verify-monotonic", routes, final]), success("ok command=verify-monotonic stage=final files=7\n"));
  verifySite(fixture.catalog, await readSiteDirectory(final), "final");
});

test("operational failures are concise and nonzero", async (t) => {
  const { archives, catalog, fixture } = await fixturePaths(t);
  await rm(join(archives, `${fixture.helperSha256}.tgz`));
  const result = await run(["check", catalog, archives]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /^error: archive directory is missing [0-9a-f]{64}\.tgz\n$/);
  assert.equal(result.stderr.includes(USAGE), false);
});

test("executable writes help to stdout", () => {
  const result = spawnSync(process.execPath, [main, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, `${USAGE}\n`);
  assert.equal(result.stderr, "");
});
