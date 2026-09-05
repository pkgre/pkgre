import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { basename } from "node:path";
import test from "node:test";

import { parseCanonicalJson } from "../src/canonical.js";

const root = new URL("../../fixtures/dynamic-registry-v1/", import.meta.url);
const indexUrl = new URL("index.json", root);

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value), expected, `${label} fields`);
}

async function regularFiles(directory = root, prefix = "") {
  const paths = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = `${prefix}${entry.name}`;
    const url = new URL(entry.isDirectory() ? `${entry.name}/` : entry.name, directory);
    if (entry.isDirectory()) paths.push(...await regularFiles(url, `${relative}/`));
    else {
      assert.ok(entry.isFile(), `${relative} must be a regular file`);
      assert.equal((await lstat(url)).isSymbolicLink(), false, `${relative} must not be a symlink`);
      paths.push(relative);
    }
  }
  return paths.sort();
}

test("dynamic registry fixture index binds every bundle file", async () => {
  const index = parseCanonicalJson(await readFile(indexUrl, "utf8"), "fixture bundle index");
  exactKeys(index, ["bundle", "files", "indexExcludes", "schema"], "index");
  assert.equal(index.bundle, "dynamic-registry-v1");
  assert.equal(index.schema, "pkgre-fixture-bundle-index-v1");
  assert.deepEqual(index.indexExcludes, ["index.json"]);

  const actualPaths = (await regularFiles()).filter((path) => !index.indexExcludes.includes(path));
  assert.deepEqual(index.files.map(({ path }) => path), actualPaths);
  assert.equal(index.files.length, 9);
  const seen = new Set();
  for (const record of index.files) {
    exactKeys(record, ["bytes", "path", "sha256"], record.path);
    assert.match(record.path, /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\x21-\x7e]+$/);
    assert.notEqual(basename(record.path), "index.json");
    assert.ok(!seen.has(record.path), `duplicate file ${record.path}`);
    seen.add(record.path);
    const bytes = await readFile(new URL(record.path, root));
    assert.equal(bytes.length, record.bytes, record.path);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), record.sha256, record.path);
  }
});
