import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../fixtures/redirect-marker-v1/", import.meta.url);
const maximumMarkerBytes = 4 * 1024;

function render(item) {
  return Buffer.from(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="pkgre-redirect" content="v1" data-ecosystem="${item.ecosystem}" data-route="${item.route}" data-kind="${item.kind}" data-destination="${item.destination}" />
<meta http-equiv="refresh" content="0;url=${item.destination}" />
<title>pkg.re redirect</title>
</head>
<body></body>
</html>
`, "ascii");
}

test("JavaScript renderer matches provider-neutral marker-v1 fixtures", async () => {
  const manifest = JSON.parse(await readFile(new URL("cases.json", root), "utf8"));
  assert.deepEqual(Object.keys(manifest), ["schema", "cases"]);
  assert.equal(manifest.schema, "redirect-marker-v1");
  assert.deepEqual(manifest.cases.map((item) => item.name), [
    "rust-crates-io",
    "rust-first-party",
    "js-npmjs",
    "js-first-party",
  ]);

  for (const item of manifest.cases) {
    assert.deepEqual(Object.keys(item), [
      "name",
      "file",
      "ecosystem",
      "route",
      "kind",
      "destination",
      "sha256",
    ]);
    const actual = await readFile(new URL(item.file, root));
    assert.ok(actual.length <= maximumMarkerBytes, `${item.name} exceeds the marker size bound`);
    assert.ok(actual.every((byte) => byte <= 0x7f), `${item.name} is not ASCII`);
    assert.deepEqual(actual, render(item), `${item.name} renderer drift`);
    assert.equal(createHash("sha256").update(actual).digest("hex"), item.sha256, `${item.name} digest drift`);
  }
});
