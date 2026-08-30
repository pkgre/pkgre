import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import process from "node:process";
import { createServer } from "node:http";

import { renderRedirectMarker } from "../src/marker.js";
import { archiveDigests, packageArchive } from "../test/support.js";

const CLIENTS = new Set(["npm", "bun", "deno"]);
const COMMAND_TIMEOUT_MILLISECONDS = 60000;
const MAXIMUM_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const VERSION = "1.0.0";
const PUBLISHED_AT = "2020-01-01T00:00:00.000Z";
const UNKNOWN_PACKAGE = "fixture-unknown";

function parseArguments(args) {
  if (args.length !== 2 || !CLIENTS.has(args[0]) || !args[1].startsWith("/")) {
    throw new Error("usage: node js/compatibility/fixture.js <npm|bun|deno> /absolute/client/executable");
  }
  return { client: args[0], executable: resolve(args[1]) };
}

function assertLoopbackOnlyNetwork() {
  if (process.platform !== "linux") throw new Error("compatibility fixture requires an isolated Linux network namespace");
  for (const [name, addresses] of Object.entries(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (!address.internal) throw new Error(`compatibility fixture refuses nonloopback interface ${name}`);
    }
  }
}

function fixturePackages() {
  const manifests = new Map([
    [
      "@fixture/scoped",
      {
        license: "MIT",
        main: "index.js",
        name: "@fixture/scoped",
        version: VERSION,
      },
    ],
    [
      "fixture-root",
      {
        dependencies: { "@fixture/scoped": VERSION },
        license: "MIT",
        main: "index.js",
        name: "fixture-root",
        version: VERSION,
      },
    ],
  ]);
  const packages = new Map();
  for (const [name, manifest] of manifests) {
    const implementation = name === "fixture-root" ? "module.exports = require(\"@fixture/scoped\");\n" : `module.exports = ${JSON.stringify(name)};\n`;
    const archive = packageArchive(manifest, [{ data: implementation, name: "package/index.js" }]);
    packages.set(name, { archive, digests: archiveDigests(archive), manifest });
  }
  return packages;
}

function packument(name, record, registryOrigin) {
  const manifest = {
    ...record.manifest,
    _id: `${name}@${VERSION}`,
    dist: {
      integrity: record.digests.integrity,
      shasum: record.digests.sha1,
      tarball: `${registryOrigin}/v1/js/main/${record.digests.sha256}`,
    },
  };
  return Buffer.from(JSON.stringify({
    _id: name,
    "dist-tags": { latest: VERSION },
    name,
    time: { [VERSION]: PUBLISHED_AT, created: PUBLISHED_AT, modified: PUBLISHED_AT },
    versions: { [VERSION]: manifest },
  }), "utf8");
}

function writeResponse(request, response, status, headers, bytes = Buffer.alloc(0)) {
  response.writeHead(status, { "cache-control": "no-store", ...headers });
  if (request.method === "HEAD") response.end();
  else response.end(bytes);
}

function decodedPackagePath(pathname) {
  if (!pathname.startsWith("/") || pathname === "/") return undefined;
  try {
    return decodeURIComponent(pathname.slice(1));
  } catch {
    return undefined;
  }
}

async function listen(server) {
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolveListen();
    });
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server) {
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
}

async function startFixture() {
  const packages = fixturePackages();
  const routes = new Map();
  const requests = [];
  let state = "normal";
  let registryOrigin;
  let archiveOrigin;

  const archiveServer = createServer((request, response) => {
    requests.push({ host: request.headers.host, method: request.method, server: "archive", url: request.url });
    if (!request.url || !["GET", "HEAD"].includes(request.method)) return writeResponse(request, response, 405, { allow: "GET, HEAD" });
    const match = request.url.match(/^\/archives\/([0-9a-f]{64})\.tgz$/);
    const routeRecord = match ? routes.get(match[1]) : undefined;
    if (!routeRecord) return writeResponse(request, response, 404, { "content-type": "text/plain" }, Buffer.from("not found\n"));
    const bytes = state === "bad-archive" ? Buffer.from("corrupt archive bytes") : routeRecord.record.archive;
    return writeResponse(request, response, 200, { "content-length": String(bytes.length), "content-type": "application/octet-stream" }, bytes);
  });
  archiveOrigin = await listen(archiveServer);
  for (const record of packages.values()) {
    const route = `/v1/js/main/${record.digests.sha256}`;
    const destination = `${archiveOrigin}/archives/${record.digests.sha256}.tgz`;
    const marker = renderRedirectMarker({ destination, ecosystem: "js", kind: "npmjs", route });
    routes.set(record.digests.sha256, { destination, marker, record, route });
  }

  const registryServer = createServer((request, response) => {
    requests.push({ host: request.headers.host, method: request.method, server: "registry", url: request.url });
    if (!request.url || !["GET", "HEAD"].includes(request.method)) return writeResponse(request, response, 405, { allow: "GET, HEAD" });
    const url = new URL(request.url, registryOrigin);
    if (url.search || url.hash) return writeResponse(request, response, 400, { "content-type": "text/plain" }, Buffer.from("query forbidden\n"));
    const routeMatch = url.pathname.match(/^\/v1\/js\/main\/([0-9a-f]{64})$/);
    if (routeMatch) {
      const routeRecord = routes.get(routeMatch[1]);
      if (!routeRecord) return writeResponse(request, response, 404, { "content-type": "text/plain" }, Buffer.from("route absent\n"));
      if (state === "route-404") return writeResponse(request, response, 404, { "content-type": "text/plain" }, Buffer.from("route absent\n"));
      if (state === "route-503") return writeResponse(request, response, 503, { "content-type": "text/plain" }, Buffer.from("origin unavailable\n"));
      const marker = state === "redirect-drift" ? Buffer.concat([routeRecord.marker, Buffer.from("drift")]) : routeRecord.marker;
      if (!marker.equals(routeRecord.marker)) return writeResponse(request, response, 502, { "content-type": "text/plain" }, Buffer.from("marker rejected\n"));
      return writeResponse(request, response, 307, { location: routeRecord.destination });
    }
    const name = decodedPackagePath(url.pathname);
    const record = packages.get(name);
    if (!record || state === "metadata-removed") return writeResponse(request, response, 404, { "content-type": "text/plain" }, Buffer.from("metadata absent\n"));
    const bytes = packument(name, record, registryOrigin);
    return writeResponse(request, response, 200, { "content-length": String(bytes.length), "content-type": "application/octet-stream" }, bytes);
  });
  registryOrigin = await listen(registryServer);

  return {
    archiveOrigin,
    packages,
    registryOrigin,
    requests,
    setState(next) {
      state = next;
    },
    async stop() {
      await Promise.all([close(registryServer), close(archiveServer)]);
    },
  };
}

async function runCommand(executable, args, options) {
  return await new Promise((resolveCommand, reject) => {
    const child = spawn(executable, args, { ...options, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const chunks = { stderr: [], stdout: [] };
    const lengths = { stderr: 0, stdout: 0 };
    let outputExceeded = false;
    for (const stream of ["stdout", "stderr"]) {
      child[stream].on("data", (chunk) => {
        lengths[stream] += chunk.length;
        if (lengths[stream] > MAXIMUM_COMMAND_OUTPUT_BYTES) {
          outputExceeded = true;
          child.kill("SIGKILL");
        } else {
          chunks[stream].push(Buffer.from(chunk));
        }
      });
    }
    const timer = setTimeout(() => child.kill("SIGKILL"), COMMAND_TIMEOUT_MILLISECONDS);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolveCommand({
        code,
        outputExceeded,
        signal,
        stderr: Buffer.concat(chunks.stderr).toString("utf8"),
        stdout: Buffer.concat(chunks.stdout).toString("utf8"),
      });
    });
  });
}

function commandArguments(client, frozen, cache) {
  if (client === "npm") {
    return [
      frozen ? "ci" : "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--allow-directory=none",
      "--allow-file=none",
      "--allow-git=none",
      "--allow-remote=none",
      "--replace-registry-host=always",
      `--cache=${cache}`,
      "--fetch-retries=0",
      "--fetch-timeout=5000",
      "--loglevel=warn",
    ];
  }
  if (client === "bun") {
    return [
      "install",
      ...(frozen ? ["--frozen-lockfile"] : []),
      "--ignore-scripts",
      "--no-cache",
      "--no-progress",
      "--no-summary",
      `--cache-dir=${cache}`,
    ];
  }
  if (frozen) return ["ci", "--quiet"];
  return ["install", "--package-json", "--node-modules-dir=auto", "--lock=deno.lock", "--frozen=false", "--quiet"];
}

async function writeProject(root, name, dependency, registryOrigin) {
  const project = join(root, name);
  const home = join(project, ".home");
  const cache = join(project, ".cache");
  const temporary = join(project, ".tmp");
  await mkdir(project, { mode: 0o700 });
  await Promise.all([mkdir(home, { mode: 0o700 }), mkdir(cache, { mode: 0o700 }), mkdir(temporary, { mode: 0o700 })]);
  const packageJson = {
    dependencies: { [dependency]: VERSION },
    name: `pkgre-compat-${name}`,
    private: true,
    version: "0.0.0",
  };
  await writeFile(join(project, "package.json"), `${JSON.stringify(packageJson, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(project, ".npmrc"), [
    `registry=${registryOrigin}/`,
    "allow-directory=none",
    "allow-file=none",
    "allow-git=none",
    "allow-remote=none",
    "audit=false",
    "fetch-retries=0",
    "fetch-timeout=5000",
    "fund=false",
    "ignore-scripts=true",
    "replace-registry-host=always",
    "save-exact=true",
    "strict-ssl=true",
    "update-notifier=false",
    "",
  ].join("\n"), { mode: 0o600 });
  return { cache, home, project, temporary };
}

function commandEnvironment(paths) {
  return {
    ALL_PROXY: "http://127.0.0.1:9",
    BUN_INSTALL_CACHE_DIR: paths.cache,
    BUN_TELEMETRY_DISABLED: "1",
    CI: "true",
    DENO_DIR: paths.cache,
    DENO_NO_UPDATE_CHECK: "1",
    DO_NOT_TRACK: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    HOME: paths.home,
    HTTPS_PROXY: "http://127.0.0.1:9",
    HTTP_PROXY: "http://127.0.0.1:9",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NO_COLOR: "1",
    NO_PROXY: "127.0.0.1,localhost",
    PATH: process.env.PATH ?? "",
    TERM: "dumb",
    TMPDIR: paths.temporary,
    XDG_CACHE_HOME: paths.cache,
    XDG_CONFIG_HOME: join(paths.home, ".config"),
    XDG_DATA_HOME: join(paths.home, ".local/share"),
    all_proxy: "http://127.0.0.1:9",
    http_proxy: "http://127.0.0.1:9",
    https_proxy: "http://127.0.0.1:9",
    no_proxy: "127.0.0.1,localhost",
    npm_config_audit: "false",
    npm_config_cache: paths.cache,
    npm_config_fund: "false",
    npm_config_ignore_scripts: "true",
    npm_config_update_notifier: "false",
    npm_config_userconfig: join(paths.project, ".npmrc"),
  };
}

async function invoke(client, executable, paths, frozen) {
  return await runCommand(executable, commandArguments(client, frozen, paths.cache), {
    cwd: paths.project,
    env: commandEnvironment(paths),
  });
}

function assertSucceeded(result, label) {
  assert.equal(result.outputExceeded, false, `${label} output exceeded bound`);
  assert.equal(result.signal, null, `${label} terminated by ${result.signal}\n${result.stderr}`);
  assert.equal(result.code, 0, `${label} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
}

function assertFailed(result, label) {
  assert.equal(result.outputExceeded, false, `${label} output exceeded bound`);
  assert.equal(result.signal, null, `${label} terminated by ${result.signal}\n${result.stderr}`);
  assert.notEqual(result.code, 0, `${label} unexpectedly succeeded`);
}

function lockName(client, project) {
  if (client === "npm") return "package-lock.json";
  if (client === "deno") return "deno.lock";
  return basename(project) && "bun.lock";
}

async function readLock(client, project) {
  if (client !== "bun") return await readFile(join(project, lockName(client, project)));
  try {
    return await readFile(join(project, "bun.lock"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return await readFile(join(project, "bun.lockb"));
  }
}

function packageNameFromMetadataPath(rawUrl) {
  if (!rawUrl || rawUrl.includes("?")) return undefined;
  return decodedPackagePath(new URL(rawUrl, "http://fixture.invalid").pathname);
}

function assertKnownRequests(log, fixture, { unknown = false } = {}) {
  const registryHost = new URL(fixture.registryOrigin).host;
  const archiveHost = new URL(fixture.archiveOrigin).host;
  const digests = new Set([...fixture.packages.values()].map((record) => record.digests.sha256));
  for (const request of log) {
    assert.ok(["GET", "HEAD"].includes(request.method), `unexpected method ${request.method}`);
    assert.equal(request.host, request.server === "registry" ? registryHost : archiveHost);
    assert.ok(request.url.length <= 4096 && !request.url.includes("?"), `unexpected URL ${request.url}`);
    if (request.server === "archive") {
      const match = request.url.match(/^\/archives\/([0-9a-f]{64})\.tgz$/);
      assert.ok(match && digests.has(match[1]), `unexpected archive request ${request.url}`);
      continue;
    }
    const route = request.url.match(/^\/v1\/js\/main\/([0-9a-f]{64})$/);
    if (route) {
      assert.ok(digests.has(route[1]), `unexpected registry route ${request.url}`);
      continue;
    }
    const name = packageNameFromMetadataPath(request.url);
    assert.ok(fixture.packages.has(name) || unknown && name === UNKNOWN_PACKAGE, `unexpected metadata request ${request.url}`);
  }
}

function hasMetadata(log, name) {
  return log.some((request) => request.server === "registry" && packageNameFromMetadataPath(request.url) === name);
}

function hasRoute(log) {
  return log.some((request) => request.server === "registry" && /^\/v1\/js\/main\/[0-9a-f]{64}$/.test(request.url));
}

function hasArchive(log) {
  return log.some((request) => request.server === "archive");
}

async function freshFailure(root, fixture, client, executable, state) {
  fixture.setState(state);
  const paths = await writeProject(root, `failure-${state}`, "fixture-root", fixture.registryOrigin);
  const offset = fixture.requests.length;
  const result = await invoke(client, executable, paths, false);
  assertFailed(result, state);
  const log = fixture.requests.slice(offset);
  assertKnownRequests(log, fixture);
  assert.ok(hasMetadata(log, "fixture-root"), `${state} did not request metadata`);
  assert.ok(hasRoute(log), `${state} did not request a same-host route`);
  if (state === "bad-archive") assert.ok(hasArchive(log), "bad-archive did not reach the controlled archive endpoint");
  else assert.equal(hasArchive(log), false, `${state} unexpectedly reached the archive endpoint`);
}

async function main() {
  const { client, executable } = parseArguments(process.argv.slice(2));
  assertLoopbackOnlyNetwork();
  const root = await mkdtemp(join(tmpdir(), `pkgre-js-compat-${client}-`));
  await chmod(root, 0o700);
  const fixture = await startFixture();
  try {
    const versionResult = await runCommand(executable, ["--version"], { cwd: root, env: commandEnvironment({ cache: root, home: root, project: root, temporary: root }) });
    assertSucceeded(versionResult, `${client} --version`);
    const match = versionResult.stdout.match(/(?:^|\s)v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?:\s|$)/);
    assert.ok(match, `${client} --version did not report a semantic version`);
    const version = match[1];

    fixture.setState("normal");
    const happy = await writeProject(root, "happy", "fixture-root", fixture.registryOrigin);
    let offset = fixture.requests.length;
    assertSucceeded(await invoke(client, executable, happy, false), "fresh install");
    let log = fixture.requests.slice(offset);
    assertKnownRequests(log, fixture);
    assert.ok(hasMetadata(log, "fixture-root"), "fresh install did not request unscoped metadata");
    assert.ok(hasMetadata(log, "@fixture/scoped"), "fresh install did not request scoped metadata");
    assert.ok(hasRoute(log), "fresh install did not request same-host archive routes");
    assert.ok(hasArchive(log), "fresh install did not follow controlled redirects");
    await readFile(join(happy.project, "node_modules/fixture-root/index.js"));
    const execution = await runCommand(process.execPath, ["-e", "if(require('fixture-root')!=='@fixture/scoped')process.exit(1)"], {
      cwd: happy.project,
      env: commandEnvironment(happy),
    });
    assertSucceeded(execution, "installed dependency execution");
    const firstLock = await readLock(client, happy.project);

    await rm(join(happy.project, "node_modules"), { force: true, recursive: true });
    await rm(happy.cache, { force: true, recursive: true });
    await mkdir(happy.cache, { mode: 0o700 });
    fixture.setState("metadata-removed");
    offset = fixture.requests.length;
    assertSucceeded(await invoke(client, executable, happy, true), "empty-cache frozen install");
    log = fixture.requests.slice(offset);
    assertKnownRequests(log, fixture);
    assert.equal(hasMetadata(log, "fixture-root") || hasMetadata(log, "@fixture/scoped"), false, "cold lock replay requested removed metadata");
    assert.ok(hasRoute(log), "cold lock replay did not retain same-host routes");
    assert.ok(hasArchive(log), "cold lock replay did not follow controlled redirects");
    assert.deepEqual(await readLock(client, happy.project), firstLock, "frozen install changed its lock");

    fixture.setState("normal");
    const unknown = await writeProject(root, "unknown", UNKNOWN_PACKAGE, fixture.registryOrigin);
    offset = fixture.requests.length;
    assertFailed(await invoke(client, executable, unknown, false), "unknown metadata");
    log = fixture.requests.slice(offset);
    assertKnownRequests(log, fixture, { unknown: true });
    assert.ok(hasMetadata(log, UNKNOWN_PACKAGE), "unknown package did not request registry metadata");
    assert.equal(hasRoute(log) || hasArchive(log), false, "unknown metadata reached an archive route");

    for (const state of ["redirect-drift", "route-404", "route-503", "bad-archive"]) {
      await freshFailure(root, fixture, client, executable, state);
    }

    const digest = createHash("sha256").update(firstLock).digest("hex");
    process.stdout.write(`ok client=${client} version=${version} lock-sha256=${digest} requests=${fixture.requests.length}\n`);
  } finally {
    await fixture.stop();
    await rm(root, { force: true, recursive: true });
  }
}

await main();
