#!/usr/bin/env node
// D5 offline-export versus live-server equivalence harness (rollout plan §D5).
//
// For each runtime (Rust sparse registry, JS npm registry):
//   1. render the current catalog offline into a temporary static tree,
//   2. start the native serve binary on the same catalog (redirect delivery,
//      127.0.0.1 only, canonical production Host header),
//   3. prove every offline route is served byte-identically, every Pages-only
//      artifact is absent from the server, typed redirect routes match the
//      fixture-pinned upstream Location, and admin route counts equal the
//      classification, plus HEAD parity on a bounded sample.
//
// usage: node harness/d5-equivalence.mjs
// env:   PKGRE_D5_RUST_CATALOG, PKGRE_D5_JS_SITE_ROOT, PKGRE_D5_RUST_PORT,
//        PKGRE_D5_JS_PORT (admin = public + 1)

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, openSync, closeSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = fileURLToPath(new URL("..", import.meta.url));
const rustCatalog = process.env.PKGRE_D5_RUST_CATALOG ?? "/home/dev0/repos/pkgre-rust/registry";
const jsSiteRoot = process.env.PKGRE_D5_JS_SITE_ROOT ?? "/home/dev0/repos/pkgre-js/bootstrap/js-v0.1.0";
const rustRenderBin = process.env.PKGRE_D5_RUST_RENDER_BIN ?? path.join(repo, "target/debug/pkgre-rust");
const rustServeBin = process.env.PKGRE_D5_RUST_SERVE_BIN ?? path.join(repo, "target/debug/pkgre-rust-serve");
const jsServeEntry = path.join(repo, "js/src/serve/main.js");
const rustPort = Number(process.env.PKGRE_D5_RUST_PORT ?? 30110);
const jsPort = Number(process.env.PKGRE_D5_JS_PORT ?? 30120);
const rustHost = "rust.pkg.re";
const jsHost = "js.pkg.re";
const readinessTimeoutMs = 20_000;

const tmp = mkdtempSync(path.join(os.tmpdir(), "pkgre-d5-"));
const children = [];
let stopping = false;
let failures = 0;
let checks = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL ${message}`);
}

function check(condition, message) {
  checks += 1;
  if (!condition) fail(message);
  return condition;
}

function walkFiles(root, prefix = "") {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...walkFiles(path.join(root, entry.name), relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files.sort();
}

function request(port, host, method, target) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: target, headers: { host } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.setTimeout(10_000, () => req.destroy(new Error(`timeout ${method} ${target}`)));
    req.end();
  });
}

async function waitReady(adminPort, label) {
  const deadline = Date.now() + readinessTimeoutMs;
  for (;;) {
    try {
      const response = await request(adminPort, "127.0.0.1", "GET", "/readyz");
      if (response.status === 200) return;
    } catch {
      // retry until the deadline
    }
    if (Date.now() > deadline) throw new Error(`${label} server did not become ready`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

function startServer(command, arguments_, logName) {
  const logPath = path.join(tmp, logName);
  const logFd = openSync(logPath, "a");
  let logClosed = false;
  const closeLog = () => {
    if (logClosed) return;
    logClosed = true;
    closeSync(logFd);
  };
  const child = spawn(command, arguments_, { stdio: ["ignore", logFd, logFd] });
  child.on("close", (code) => {
    closeLog();
    if (code !== null && code !== 0 && !stopping) fail(`${path.basename(command)} exited early code=${code} (log ${logPath})`);
  });
  child.on("error", closeLog);
  children.push(child);
  return child;
}

function cleanup() {
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  rmSync(tmp, { force: true, recursive: true });
}

function runOrThrow(command, arguments_, label) {
  const result = spawnSync(command, arguments_, { encoding: "buffer", timeout: 300_000 });
  if (result.status !== 0) {
    throw new Error(`${label} failed: ${result.stderr.toString().slice(0, 2000)}`);
  }
  return result;
}

async function verifyRust() {
  console.log("== rust offline export vs live server ==");
  const tree = path.join(tmp, "rust-tree");
  runOrThrow(rustRenderBin, ["render", rustCatalog, tree], "pkgre-rust render");

  const config = [
    "schema = 1",
    "[public]",
    `bind = "127.0.0.1:${rustPort}"`,
    "[admin]",
    `bind = "127.0.0.1:${rustPort + 1}"`,
    "[registry]",
    `catalog = "${rustCatalog}"`,
    'delivery = "redirect"',
    "[limits]",
    "max-concurrency = 64",
    "",
  ].join("\n");
  const configFile = path.join(tmp, "rust-serve.toml");
  writeFileSync(configFile, config);
  startServer(rustServeBin, [configFile], "rust-serve.log");
  await waitReady(rustPort + 1, "rust");

  const downloads = JSON.parse(readFileSync(path.join(rustCatalog, "downloads.json"), "utf8"));
  const redirectRoutes = downloads.routes.filter((route) => route.delivery.delivery === "redirect");
  const retainedRoutes = downloads.routes.filter((route) => route.delivery.delivery === "retained");
  const files = walkFiles(tree);
  const inline = files.filter((file) => file !== "CNAME" && file !== ".nojekyll" && !file.startsWith("crates/"));
  const archives = files.filter((file) => /^crates\/[0-9a-f]{64}\.crate$/.test(file));
  const artifacts = files.filter((file) => file === "CNAME" || file === ".nojekyll");
  check(inline.length + archives.length + artifacts.length === files.length, "rust tree classification is exhaustive");

  const status = await request(rustPort + 1, "127.0.0.1", "GET", "/status");
  const counts = JSON.parse(status.body.toString()).counts;
  check(counts.inline === inline.length, `rust admin inline count ${counts.inline} = offline ${inline.length}`);
  check(counts.archive === archives.length, `rust admin archive count ${counts.archive} = offline ${archives.length}`);
  check(counts.redirect === downloads.routes.length, `rust admin redirect count ${counts.redirect} = downloads routes ${downloads.routes.length}`);

  for (const file of inline) {
    const response = await request(rustPort, rustHost, "GET", `/${file}`);
    const expected = readFileSync(path.join(tree, file));
    const ok = check(
      response.status === 200 && response.body.equals(expected),
      `rust inline /${file} status=${response.status} bytes=${response.body.length} expected=${expected.length}`,
    );
    if (ok) check(Boolean(response.headers["content-type"]), `rust inline /${file} has content-type`);
  }
  for (const file of archives) {
    const response = await request(rustPort, rustHost, "GET", `/${file}`);
    const expected = readFileSync(path.join(tree, file));
    check(response.status === 200 && response.body.equals(expected), `rust archive /${file} byte equality`);
  }
  for (const route of redirectRoutes) {
    const target = `/v1/${route.registry}/${route.name}/${route.version}/${route.sha256}`;
    const response = await request(rustPort, rustHost, "GET", target);
    const location = `https://static.crates.io/crates/${route.name}/${route.version}/download`;
    check(
      response.status === 302 && response.headers.location === location && response.headers["cache-control"] === "no-store",
      `rust redirect ${target} -> ${response.status} ${response.headers.location ?? ""}`,
    );
  }
  for (const route of retainedRoutes) {
    const target = `/v1/${route.registry}/${route.name}/${route.version}/${route.sha256}`;
    const response = await request(rustPort, rustHost, "GET", target);
    const location = `https://${rustHost}/crates/${route.sha256}.crate`;
    check(
      response.status === 302 && response.headers.location === location && response.headers["cache-control"] === "no-store",
      `rust retained ${target} -> ${response.status} ${response.headers.location ?? ""}`,
    );
  }
  for (const file of artifacts) {
    const response = await request(rustPort, rustHost, "GET", `/${file}`);
    check(response.status === 404, `rust pages artifact /${file} must 404, got ${response.status}`);
  }

  const headSample = [inline[0], archives[0], `/v1/main/${redirectRoutes[0].name}/${redirectRoutes[0].version}/${redirectRoutes[0].sha256}`, "CNAME"];
  for (const target of headSample) {
    const head = await request(rustPort, rustHost, "HEAD", target);
    const get = await request(rustPort, rustHost, "GET", target);
    check(head.status === get.status && head.body.length === 0, `rust HEAD ${target} parity (${head.status})`);
  }
  console.log(`rust: ${inline.length} inline + ${archives.length} archive + ${retainedRoutes.length} retained + ${redirectRoutes.length} redirect routes equivalent`);
}

async function verifyJs() {
  console.log("== js offline export vs live server ==");
  const routesSite = path.join(tmp, "js-site-routes");
  const finalSite = path.join(tmp, "js-site-final");
  const node = process.execPath;
  const cli = path.join(repo, "js/src/main.js");
  runOrThrow(node, [cli, "render-routes", path.join(jsSiteRoot, "catalog.json"), path.join(jsSiteRoot, "archives"), path.join(jsSiteRoot, "site-previous"), routesSite], "pkgre-js render-routes");
  runOrThrow(node, [cli, "render-final", path.join(jsSiteRoot, "catalog.json"), routesSite, finalSite], "pkgre-js render-final");

  const committed = path.join(jsSiteRoot, "site-final");
  const rendered = walkFiles(finalSite);
  const committedFiles = walkFiles(committed);
  check(JSON.stringify(rendered) === JSON.stringify(committedFiles), "js re-render file set equals committed site-final");
  for (const file of rendered) {
    check(
      readFileSync(path.join(finalSite, file)).equals(readFileSync(path.join(committed, file))),
      `js re-rendered ${file} byte equality with committed site-final`,
    );
  }

  const manifest = JSON.parse(readFileSync(path.join(committed, ".pkgre-js-site.json"), "utf8"));
  const inline = rendered.filter((file) => manifest.metadata.some((entry) => entry.path === file));
  const archives = rendered.filter((file) => manifest.objects.some((entry) => entry.path === file));
  const redirects = rendered.filter((file) => manifest.routes.some((entry) => entry.path === file));
  const artifacts = rendered.filter((file) => !inline.includes(file) && !archives.includes(file) && !redirects.includes(file));
  check(inline.length + archives.length + redirects.length + artifacts.length === rendered.length, "js tree classification is exhaustive");

  const config = {
    schema: 1,
    public: { bind: `127.0.0.1:${jsPort}` },
    admin: { bind: `127.0.0.1:${jsPort + 1}` },
    limits: { "max-concurrency": 64 },
    registry: {
      catalog: path.join(jsSiteRoot, "catalog.json"),
      delivery: "redirect",
      "archive-store": path.join(jsSiteRoot, "archives"),
    },
  };
  const configFile = path.join(tmp, "js-serve.json");
  writeFileSync(configFile, JSON.stringify(config));
  startServer(node, [jsServeEntry, configFile], "js-serve.log");
  await waitReady(jsPort + 1, "js");

  const status = await request(jsPort + 1, "127.0.0.1", "GET", "/status");
  const counts = JSON.parse(status.body.toString()).counts;
  check(counts.inline === inline.length, `js admin inline count ${counts.inline} = offline ${inline.length}`);
  check(counts.archive === archives.length, `js admin archive count ${counts.archive} = offline ${archives.length}`);
  check(counts.redirect === redirects.length, `js admin redirect count ${counts.redirect} = offline ${redirects.length}`);

  for (const file of inline) {
    const response = await request(jsPort, jsHost, "GET", `/${file}`);
    check(response.status === 200 && response.body.equals(readFileSync(path.join(committed, file))), `js inline /${file} byte equality`);
  }
  for (const file of archives) {
    const response = await request(jsPort, jsHost, "GET", `/${file}`);
    check(response.status === 200 && response.body.equals(readFileSync(path.join(committed, file))), `js archive /${file} byte equality`);
  }
  for (const file of redirects) {
    const sha = path.basename(file);
    const object = manifest.objects.find((entry) => path.basename(entry.path, ".tgz") === sha);
    const response = await request(jsPort, jsHost, "GET", `/${file}`);
    const location = `https://${jsHost}/${object.path}`;
    check(
      response.status === 302 && response.headers.location === location && response.headers["cache-control"] === "no-store",
      `js redirect /${file} -> ${response.status} ${response.headers.location ?? ""}`,
    );
  }
  for (const file of artifacts) {
    const response = await request(jsPort, jsHost, "GET", `/${file}`);
    check(response.status === 404, `js pages artifact /${file} must 404, got ${response.status}`);
  }

  const headSample = [inline[0], archives[0], redirects[0], artifacts[0]];
  for (const target of headSample) {
    const head = await request(jsPort, jsHost, "HEAD", `/${target}`);
    const get = await request(jsPort, jsHost, "GET", `/${target}`);
    check(head.status === get.status && head.body.length === 0, `js HEAD /${target} parity (${head.status})`);
  }
  console.log(`js: ${inline.length} inline + ${archives.length} archive + ${redirects.length} redirect routes equivalent`);
}

try {
  await verifyRust();
  await verifyJs();
} finally {
  cleanup();
}
if (failures > 0) {
  console.error(`D5 equivalence FAILED: ${failures} failing of ${checks} checks`);
  process.exit(1);
}
console.log(`D5 equivalence PASSED: ${checks} checks`);
