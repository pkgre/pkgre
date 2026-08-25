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

const machinePrefix = '<meta name="pkgre-redirect" content="v1" data-ecosystem="';
const routeSeparator = '" data-route="';
const kindSeparator = '" data-kind="';
const destinationSeparator = '" data-destination="';
const machineSuffix = '" />';

function splitOnce(value, separator) {
  const offset = value.indexOf(separator);
  if (offset < 0) return undefined;
  return [value.slice(0, offset), value.slice(offset + separator.length)];
}

function parseMachineLine(line) {
  if (!line.startsWith(machinePrefix) || !line.endsWith(machineSuffix)) return undefined;
  let pair = splitOnce(line.slice(machinePrefix.length, -machineSuffix.length), routeSeparator);
  if (!pair) return undefined;
  const [ecosystem, afterEcosystem] = pair;
  pair = splitOnce(afterEcosystem, kindSeparator);
  if (!pair) return undefined;
  const [route, afterRoute] = pair;
  pair = splitOnce(afterRoute, destinationSeparator);
  if (!pair) return undefined;
  const [kind, destination] = pair;
  return { ecosystem, route, kind, destination };
}

function routeIdentity(route) {
  const segments = route.split("/");
  if (segments.length === 5 && segments[0] === "" && segments[1] === "v1" && segments[2] === "js") {
    return { ecosystem: "js", sha256: segments[4] };
  }
  if (segments.length === 6 && segments[0] === "" && segments[1] === "v1") {
    return { ecosystem: "rust", name: segments[3], version: segments[4], sha256: segments[5] };
  }
  throw new Error(`invalid fixture route ${route}`);
}

function validNpmComponent(value) {
  return value.length <= 214 && /^[a-z][a-z0-9._~-]*$/.test(value);
}

function validNpmDestination(destination) {
  if (destination.includes("%")) return false;
  let url;
  try {
    url = new URL(destination);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.hostname !== "registry.npmjs.org" || url.port !== "" || url.search !== "" || url.hash !== "" || url.href !== destination) return false;
  const segments = url.pathname.slice(1).split("/");
  let packageName;
  let separator;
  let filename;
  if (segments.length === 3 && validNpmComponent(segments[0])) {
    [packageName, separator, filename] = segments;
  } else if (segments.length === 4 && segments[0].startsWith("@") && validNpmComponent(segments[0].slice(1)) && validNpmComponent(segments[1])) {
    [, packageName, separator, filename] = segments;
  } else {
    return false;
  }
  const prefix = `${packageName}-`;
  return separator === "-" && filename.startsWith(prefix) && filename.endsWith(".tgz") && /^[A-Za-z0-9._+~-]+$/.test(filename.slice(prefix.length, -4));
}

function validateDestination(route, kind, destination) {
  if (destination.length === 0 || destination.length > 2048 || !Buffer.from(destination).every((byte) => byte <= 0x7f) || /[?#%\\"&]/.test(destination)) return false;
  const identity = routeIdentity(route);
  if (identity.ecosystem === "rust" && kind === "crates-io") return destination === `https://static.crates.io/crates/${identity.name}/${identity.version}/download`;
  if (identity.ecosystem === "rust" && kind === "first-party") return destination === `https://rust.pkg.re/crates/${identity.sha256}.crate`;
  if (identity.ecosystem === "js" && kind === "npmjs") return validNpmDestination(destination);
  if (identity.ecosystem === "js" && kind === "first-party") return destination === `https://js.pkg.re/packages/${identity.sha256}.tgz`;
  return false;
}

function validateMarker(route, body) {
  if (body.length > maximumMarkerBytes) return "too-large";
  if (!body.every((byte) => byte <= 0x7f)) return "non-ascii";
  const fields = parseMachineLine(body.toString("ascii").split("\n")[4] ?? "");
  if (!fields) return "malformed-template";
  const identity = routeIdentity(route);
  if (fields.ecosystem !== identity.ecosystem || fields.route !== route) return "route-mismatch";
  if (!validateDestination(route, fields.kind, fields.destination)) return "invalid-destination";
  if (!body.equals(render(fields))) return "malformed-template";
  return undefined;
}

test("JavaScript renderer matches provider-neutral marker-v1 fixtures", async () => {
  const manifest = JSON.parse(await readFile(new URL("cases.json", root), "utf8"));
  assert.deepEqual(Object.keys(manifest), ["schema", "cases", "hostileCases"]);
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


test("JavaScript parser rejects provider-neutral hostile marker-v1 fixtures", async () => {
  const manifest = JSON.parse(await readFile(new URL("cases.json", root), "utf8"));
  assert.deepEqual(manifest.hostileCases.map((item) => item.name), [
    "unknown-version",
    "duplicate-field",
    "unknown-field",
    "route-replay",
    "destination-host",
    "destination-encoded",
    "machine-meta-mismatch",
    "trailing-bytes",
    "non-ascii",
    "oversize",
  ]);
  for (const item of manifest.hostileCases) {
    assert.deepEqual(Object.keys(item), ["name", "file", "route", "error", "sha256"]);
    const actual = await readFile(new URL(item.file, root));
    assert.equal(createHash("sha256").update(actual).digest("hex"), item.sha256, `${item.name} digest drift`);
    assert.equal(validateMarker(item.route, actual), item.error, `${item.name} error drift`);
  }
});
