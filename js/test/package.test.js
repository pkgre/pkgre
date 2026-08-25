import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function readJson(name) {
  const text = await readFile(new URL(name, root), "utf8");
  return { text, value: JSON.parse(text) };
}

test("npm 12 lock is canonical and dependency-free", async () => {
  const manifest = await readJson("package.json");
  const lock = await readJson("package-lock.json");

  assert.equal(manifest.text, `${JSON.stringify(manifest.value, null, 2)}\n`);
  assert.equal(lock.text, `${JSON.stringify(lock.value, null, 2)}\n`);
  assert.equal(manifest.value.packageManager, "npm@12.0.2");
  assert.deepEqual(manifest.value.engines, { node: ">=24.15.0", npm: ">=12.0.2" });
  assert.equal(lock.value.lockfileVersion, 3);
  assert.equal(lock.value.requires, true);
  assert.deepEqual(Object.keys(lock.value.packages), [""]);
  assert.equal(lock.value.packages[""].name, manifest.value.name);
  assert.equal(lock.value.packages[""].version, manifest.value.version);

  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    assert.equal(Object.hasOwn(manifest.value, field), false);
    assert.equal(Object.hasOwn(lock.value.packages[""], field), false);
  }
});
