import assert from "node:assert/strict";
import test from "node:test";

import {
  SITE_INVENTORY_PATH,
  catalogSha256,
  cloneSite,
  isImmutableSitePath,
  readSiteInventory,
  sha256,
  validateSitePath,
  writeSiteInventory,
} from "../src/artifact.js";

const route = `v1/js/main/${"a".repeat(64)}`;
const objectBytes = Buffer.from("object");
const object = `packages/${sha256(objectBytes)}.tgz`;
const catalogHash = "c".repeat(64);

function site() {
  return new Map([
    [".nojekyll", Buffer.alloc(0)],
    ["@scope/helper", Buffer.from("metadata")],
    [object, objectBytes],
    [route, Buffer.from("marker")],
  ]);
}

test("writes and validates one canonical content-bound site inventory", () => {
  const rendered = writeSiteInventory(site(), { catalogHash, metadataNames: ["@scope/helper"], stage: "final" });
  const inventory = readSiteInventory(rendered);
  assert.equal(inventory.catalogSha256, catalogHash);
  assert.equal(inventory.stage, "final");
  assert.deepEqual(inventory.metadata, [{ name: "@scope/helper", path: "@scope/helper", sha256: sha256(Buffer.from("metadata")) }]);
  assert.deepEqual(inventory.objects, [{ path: object, sha256: sha256(Buffer.from("object")) }]);
  assert.deepEqual(inventory.routes, [{ path: route, sha256: sha256(Buffer.from("marker")) }]);
  assert.deepEqual(writeSiteInventory(site(), { catalogHash, metadataNames: ["@scope/helper"], stage: "final" }), rendered);
  assert.equal(catalogSha256({ z: 1, a: 2 }), sha256(Buffer.from('{\n  "a": 2,\n  "z": 1\n}\n')));
  assert.equal(isImmutableSitePath(route), true);
  assert.equal(isImmutableSitePath(object), true);
  assert.equal(isImmutableSitePath("@scope/helper"), false);
});

test("rejects absent,tampered,or unlisted managed files", () => {
  const rendered = writeSiteInventory(site(), { catalogHash, metadataNames: ["@scope/helper"], stage: "final" });
  for (const [path, value, expected] of [
    [route, Buffer.from("changed"), /hash mismatch/],
    [object, undefined, /file is absent/],
    [SITE_INVENTORY_PATH, Buffer.from("{}\n"), /keys must be exactly/],
  ]) {
    const changed = cloneSite(rendered);
    if (value === undefined) changed.delete(path);
    else changed.set(path, value);
    assert.throws(() => readSiteInventory(changed), expected);
  }
  const unlisted = new Map([[route, Buffer.from("marker")]]);
  assert.throws(() => readSiteInventory(unlisted), /without an inventory/);
});

test("rejects unsafe paths and file-prefix conflicts", () => {
  for (const path of ["", "/absolute", "a//b", "a/../b", "a\\b", "a b", "é"]) assert.throws(() => validateSitePath(path), /invalid site path/);
  assert.throws(() => cloneSite(new Map([["a", Buffer.from("file")], ["a/b", Buffer.from("child")]])), /conflicts with descendant/);
  assert.throws(() => cloneSite(new Map([["safe", "not bytes"]])), /must be bytes/);
});
