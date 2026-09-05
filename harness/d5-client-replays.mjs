#!/usr/bin/env node
// D5 client replay harness (rollout plan §D5).
//
// Proves the pinned client matrix (cargo 1.95.0, npm 12.0.2 on node 24.15/26.7,
// bun 1.3.14/1.4.0, deno 2.9.5) installs the fixture projects through the native
// registry servers and replays them from warm caches under OS-enforced zero
// egress (unshare -rn), with declaration admission validated against every
// sourceCase before any client invocation, lifecycle-script rejection, a
// poisoned-override probe, and full outbound destination capture (serve request
// logs + warm MITM proxy log + dead fast-fail proxies).
//
// Routing reality encoded here (established empirically):
// - cargo resolves the sparse index on the local redirect server, but downloads
//   follow the catalog dl template to production dl.rust.pkg.re (LIVE, 307 ->
//   static.crates.io). The cargo warm phase therefore runs with NO proxy env on
//   the host; it cannot be sandboxed.
// - npm and deno rewrite canonical js.pkg.re tarball origins to the configured
//   registry themselves, so they run against a dead proxy (127.0.0.1:9) that
//   fast-fails any foreign egress.
// - bun does not rewrite tarball origins: its warm phase runs through the MITM
//   proxy (CONNECT js.pkg.re:443 -> TLS-terminated relay to the local body-mode
//   server) with a harness-generated CA via NODE_EXTRA_CA_CERTS.
// - the js server must serve BODY delivery because production js.pkg.re is
//   currently dead (502); a redirect would bounce clients to the dead origin.
//
// HOST-ONLY by design (not nix-sandboxable): production download reachability
// for cargo warm + user/network namespaces for replays.
//
// usage:  node harness/d5-client-replays.mjs
// env:    PKGRE_D5_RUST_CATALOG (default /home/dev0/repos/pkgre-rust/registry)
//         PKGRE_D5_JS_SITE_ROOT (default /home/dev0/repos/pkgre-js/bootstrap/js-v0.1.0)
//         PKGRE_D5_RUST_PORT / PKGRE_D5_JS_PORT / PKGRE_D5_PROXY_PORT
//         PKGRE_D5_CARGO        (default pinned 1.95.0 rustup toolchain cargo)
//         PKGRE_D5_CLIENT_NODE_NPM / PKGRE_D5_CLIENT_NODE_CURRENT_NPM
//         PKGRE_D5_CLIENT_BUN_MINIMUM / PKGRE_D5_CLIENT_BUN_CURRENT
//         PKGRE_D5_CLIENT_DENO  (profile bin roots, defaults /tmp/d5/clients*)
//         PKGRE_D5_OPENSSL      (default: PATH openssl, else resolved once from
//                               `nix shell nixpkgs#openssl`, store path used directly)
//         PKGRE_D5_KEEP_TMP=1   (preserve the scratch dir instead of deleting it)


import { spawn, spawnSync } from "node:child_process";
import {
  closeSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";


const repo = fileURLToPath(new URL("..", import.meta.url));
const configuration = JSON.parse(
  readFileSync(path.join(repo, "fixtures/dynamic-registry-v1/client/configuration.json"), "utf8"),
);
const fixtureProject = path.join(repo, "fixtures/dynamic-registry-v1/client/project");

const rustCatalog = process.env.PKGRE_D5_RUST_CATALOG ?? "/home/dev0/repos/pkgre-rust/registry";
const jsSiteRoot = process.env.PKGRE_D5_JS_SITE_ROOT ?? "/home/dev0/repos/pkgre-js/bootstrap/js-v0.1.0";
const rustServeBin = process.env.PKGRE_D5_RUST_SERVE_BIN ?? path.join(repo, "target/debug/pkgre-rust-serve");
const jsServeEntry = path.join(repo, "js/src/serve/main.js");
const rustPort = Number(process.env.PKGRE_D5_RUST_PORT ?? 30110);
const jsPort = Number(process.env.PKGRE_D5_JS_PORT ?? 30120);
const proxyPort = Number(process.env.PKGRE_D5_PROXY_PORT ?? 3128);
const rustHost = "rust.pkg.re";
const jsHost = "js.pkg.re";
const deadProxy = "http://127.0.0.1:9";
const readinessTimeoutMs = 30_000;
const commandTimeoutMs = 600_000;
const maximumCommandOutputBytes = 8 * 1024 * 1024;

// Empirically pinned accessory =2.1.0 closure resolved exclusively through the
// local sparse index (cargo 1.95.0, catalog main @ d778238).
const cargoClosure = [
  ["accessory", "2.1.0"],
  ["macroific", "2.0.0"],
  ["macroific_attr_parse", "2.0.0"],
  ["macroific_core", "2.0.0"],
  ["macroific_macro", "2.0.0"],
  ["proc-macro2", "1.0.107"],
  ["quote", "1.0.47"],
  ["sealed", "0.6.0"],
  ["syn", "2.0.119"],
  ["unicode-ident", "1.0.24"],
];

const jsPackage = "pkgre-js";
const jsVersion = "0.1.0";

const profiles = [
  {
    client: "cargo",
    id: "cargo-1.95.0",
    version: "1.95.0",
    rootEnvVar: "PKGRE_D5_CARGO",
    defaultRoot: "/home/dev0/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin",
  },
  {
    client: "npm",
    id: "npm-node-minimum",
    version: "12.0.2",
    runtimeVersion: "24.15.0",
    rootEnvVar: "PKGRE_D5_CLIENT_NODE_NPM",
    defaultRoot: "/tmp/d5/clients",
  },
  {
    client: "npm",
    id: "npm-node-current",
    version: "12.0.2",
    runtimeVersion: "26.7.0",
    rootEnvVar: "PKGRE_D5_CLIENT_NODE_CURRENT_NPM",
    defaultRoot: "/tmp/d5/clients-1",
  },
  {
    client: "bun",
    id: "bun-minimum",
    version: "1.3.14",
    rootEnvVar: "PKGRE_D5_CLIENT_BUN_MINIMUM",
    defaultRoot: "/tmp/d5/clients-2",
  },
  {
    client: "bun",
    id: "bun-current",
    version: "1.4.0",
    rootEnvVar: "PKGRE_D5_CLIENT_BUN_CURRENT",
    defaultRoot: "/tmp/d5/clients-3",
  },
  {
    client: "deno",
    id: "deno-minimum-current",
    version: "2.9.5",
    rootEnvVar: "PKGRE_D5_CLIENT_DENO",
    defaultRoot: "/tmp/d5/clients-4",
  },
];

const tmp = mkdtempSync(path.join(os.tmpdir(), "pkgre-d5-clients-"));
const children = [];
let stopping = false;
let failures = 0;
let checks = 0;
let spawnedProcesses = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL ${message}`);
}

function check(condition, message) {
  checks += 1;
  if (!condition) fail(message);
  return condition;
}

function resolveExecutable(rootDirectory, binary) {
  const executable = path.join(rootDirectory, binary);
  if (!existsSync(executable)) throw new Error(`missing client executable ${executable}`);
  return executable;
}

function profileExecutable(profile) {
  const root = process.env[profile.rootEnvVar] ?? profile.defaultRoot;
  // js-client profile roots are nix package dirs (binaries under bin/); the
  // cargo root is already a toolchain bin directory.
  if (profile.client === "cargo") return resolveExecutable(root, "cargo");
  return resolveExecutable(path.join(root, "bin"), profile.client === "npm" ? "npm" : profile.client);
}

async function runCommand(executable, args, options, label) {
  spawnedProcesses += 1;
  return await new Promise((resolveCommand, reject) => {
    const child = spawn(executable, args, { ...options, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const chunks = { stdout: [], stderr: [] };
    const lengths = { stdout: 0, stderr: 0 };
    let outputExceeded = false;
    for (const stream of ["stdout", "stderr"]) {
      child[stream].on("data", (chunk) => {
        lengths[stream] += chunk.length;
        if (lengths[stream] > maximumCommandOutputBytes) {
          outputExceeded = true;
          child.kill("SIGKILL");
        } else {
          chunks[stream].push(Buffer.from(chunk));
        }
      });
    }
    const timer = setTimeout(() => child.kill("SIGKILL"), commandTimeoutMs);
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
        stdout: Buffer.concat(chunks.stdout).toString("utf8"),
        stderr: Buffer.concat(chunks.stderr).toString("utf8"),
      });
    });
  });
}

function assertSucceeded(result, label) {
  check(!result.outputExceeded, `${label} output exceeded bound`);
  check(result.signal === null, `${label} terminated by ${result.signal}\n${result.stderr}`);
  check(result.code === 0, `${label} failed\nstdout:\n${result.stdout.slice(0, 4000)}\nstderr:\n${result.stderr.slice(0, 4000)}`);
}

function logOffset(logPath) {
  try {
    return statSync(logPath).size;
  } catch {
    return 0;
  }
}

function logSlice(logPath, startOffset) {
  try {
    const buffer = readFileSync(logPath);
    return startOffset < buffer.length ? buffer.subarray(startOffset).toString("utf8") : "";
  } catch {
    return "";
  }
}

function request(port, method, target) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: target }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.setTimeout(15_000, () => req.destroy(new Error(`timeout ${method} ${target}`)));
    req.end();
  });
}

async function waitReady(adminPort, label) {
  const deadline = Date.now() + readinessTimeoutMs;
  for (;;) {
    try {
      const response = await request(adminPort, "GET", "/readyz");
      if (response.status === 200) return;
    } catch {
      // retry until the deadline
    }
    if (Date.now() > deadline) throw new Error(`${label} server did not become ready`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function assertPortFree(port, label) {
  try {
    const response = await request(port, "GET", "/readyz");
    throw new Error(`${label} port ${port} already serves (status ${response.status}); kill stale servers first`);
  } catch (error) {
    if (String(error.message).includes("already serves")) throw error;
  }
}

// TCP-level liveness probe for harness support processes without an HTTP
// surface (the warm MITM proxy): a refused connection here means the proxy
// process died at startup — fail with that instead of a confusing client
// "ConnectionRefused downloading tarball" later.
function waitTcpReady(port, label) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + readinessTimeoutMs;
    const attempt = () => {
      const socket = net.connect({ host: "127.0.0.1", port });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error(`${label} (127.0.0.1:${port}) never became reachable`));
        else setTimeout(attempt, 100);
      });
    };
    attempt();
  });
}


function startServer(command, args, logName) {
  const logPath = path.join(tmp, logName);
  const logFd = openSync(logPath, "a");
  let logClosed = false;
  const closeLog = () => {
    if (logClosed) return;
    logClosed = true;
    closeSync(logFd);
  };
  const child = spawn(command, args, { stdio: ["ignore", logFd, logFd] });
  child.on("close", (code) => {
    closeLog();
    if (code !== null && code !== 0 && !stopping) fail(`${path.basename(command)} exited early code=${code} (log ${logPath})`);
  });
  child.on("error", closeLog);
  children.push(child);
  return { child, logPath };
}

function resolveOpenssl() {
  const override = process.env.PKGRE_D5_OPENSSL;
  if (override) return { command: override, prefix: [] };
  const direct = spawnSync("openssl", ["version"], { encoding: "utf8" });
  if (direct.status === 0) return { command: "openssl", prefix: [] };
  // Resolve the nix openssl once and use the store path directly for every
  // cert command — per-invocation `nix shell -c <op>` wrappers are flaky
  // ("unable to execute 'genrsa'") and add ~seconds of evaluation per call.
  const probe = spawnSync("nix", ["shell", "nixpkgs#openssl", "-c", "sh", "-c", "command -v openssl"], { encoding: "utf8" });
  const storePath = probe.status === 0 ? probe.stdout.trim().split("\n").pop() : "";
  if (storePath.startsWith("/nix/store/") && spawnSync(storePath, ["version"], { encoding: "utf8" }).status === 0) {
    return { command: storePath, prefix: [] };
  }
  throw new Error(`openssl not found; install it or set PKGRE_D5_OPENSSL (nix probe: ${probe.stderr.toString().slice(0, 300)})`);
}


function opensslRun(openssl, args) {
  const result = spawnSync(openssl.command, [...openssl.prefix, ...args], { encoding: "buffer" });
  if (result.status !== 0) {
    throw new Error(`openssl ${args.join(" ")} failed: ${result.stderr.toString().slice(0, 2000)}`);
  }
  return result.stdout.toString("utf8");
}

function generateCertificates(directory) {
  const openssl = resolveOpenssl();
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    path.join(directory, "leaf.ext"),
    [
      "basicConstraints=CA:FALSE",
      "keyUsage = digitalSignature, keyEncipherment",
      "extendedKeyUsage = serverAuth",
      `subjectAltName = DNS:${jsHost}, IP:127.0.0.1`,
      "",
    ].join("\n"),
  );
  opensslRun(openssl, ["genrsa", "-out", path.join(directory, "ca-key.pem"), "2048"]);
  opensslRun(openssl, [
    "req", "-x509", "-new", "-nodes", "-key", path.join(directory, "ca-key.pem"),
    "-sha256", "-days", "2",
    "-subj", "/O=pkgre D5 Harness/CN=pkgre D5 Harness Root CA",
    "-out", path.join(directory, "ca.pem"),
  ]);
  opensslRun(openssl, ["genrsa", "-out", path.join(directory, "leaf-key.pem"), "2048"]);
  opensslRun(openssl, [
    "req", "-new", "-key", path.join(directory, "leaf-key.pem"),
    "-subj", `/O=pkgre D5 Harness/CN=${jsHost}`,
    "-out", path.join(directory, "leaf.csr"),
  ]);
  opensslRun(openssl, [
    "x509", "-req", "-in", path.join(directory, "leaf.csr"),
    "-CA", path.join(directory, "ca.pem"), "-CAkey", path.join(directory, "ca-key.pem"),
    "-CAcreateserial", "-days", "2", "-sha256",
    "-extfile", path.join(directory, "leaf.ext"),
    "-out", path.join(directory, "leaf.pem"),
  ]);
  const verification = opensslRun(openssl, ["verify", "-CAfile", path.join(directory, "ca.pem"), path.join(directory, "leaf.pem")]);
  check(verification.includes(": OK"), `harness leaf certificate verifies against harness CA (${verification.trim()})`);
  writeFileSync(
    path.join(directory, "leaf-chain.pem"),
    Buffer.concat([readFileSync(path.join(directory, "leaf.pem")), readFileSync(path.join(directory, "ca.pem"))]),
  );
  return {
    caCertificate: path.join(directory, "ca.pem"),
    leafKey: path.join(directory, "leaf-key.pem"),
    leafChain: path.join(directory, "leaf-chain.pem"),
  };
}

// Warm-phase interception proxy (harness support tool): maps CONNECT to an
// allowed host onto a local plain-HTTP upstream with TLS terminated here, and
// denies every other destination. Logs each attempt; dumps JSON on SIGTERM.
const proxyScript = `#!/usr/bin/env node
import { createServer } from "node:http";
import { connect as tcpConnect } from "node:net";
import { TLSSocket, createSecureContext } from "node:tls";
import { readFileSync } from "node:fs";


const [, , upstreamPortArg, keyPath, certPath, ...allowedHosts] = process.argv;
const upstreamPort = Number(upstreamPortArg);
const allowed = new Set(allowedHosts.length > 0 ? allowedHosts : ["js.pkg.re"]);
const secureContext = createSecureContext({ key: readFileSync(keyPath), cert: readFileSync(certPath) });
const targets = [];

function log(line) {
  targets.push(line);
  if (process.env.PKGRE_D5_PROXY_VERBOSE === "1") console.error(line);
}

const server = createServer((request, response) => {
  log("ABSOLUTE " + request.method + " " + request.url);
  response.writeHead(403, { "content-type": "text/plain" });
  response.end("denied by d5 warm proxy\\n");
});

server.on("connect", (request, clientSocket, head) => {
  const [host, port] = request.url.split(":");
  log("CONNECT " + host + ":" + (port || "443"));
  if (!allowed.has(host)) {
    clientSocket.write("HTTP/1.1 403 Destination Denied\\r\\n\\r\\n");
    clientSocket.destroy();
    return;
  }
  clientSocket.write("HTTP/1.1 200 Connection Established\\r\\n\\r\\n");
  if (head && head.length > 0) clientSocket.unshift(head);
  const secure = new TLSSocket(clientSocket, {
    isServer: true,
    secureContext,
    SNICallback: (servername, callback) => {
      log("SNI " + servername);
      callback(null, secureContext);
    },
  });
  secure.on("error", (error) => log("TLS-ERROR " + error.message));
  secure.once("secure", () => {
    const upstream = tcpConnect(upstreamPort, "127.0.0.1", () => {
      secure.pipe(upstream);
      upstream.pipe(secure);
    });
    upstream.on("error", (error) => {
      log("UPSTREAM-ERROR " + error.message);
      secure.destroy();
    });
    upstream.on("close", () => secure.destroy());
    secure.on("close", () => upstream.destroy());
  });
});

server.listen(Number(process.env.PKGRE_D5_PROXY_PORT || 3128), "127.0.0.1", () => {
  console.log("d5 warm proxy on 127.0.0.1:" + (process.env.PKGRE_D5_PROXY_PORT || 3128) + " -> 127.0.0.1:" + upstreamPort + " allowed=[" + [...allowed].join(",") + "]");
});

process.on("SIGTERM", () => {
  console.log(JSON.stringify({ proxyLog: targets }));
  process.exit(0);
});
process.on("SIGINT", () => {
  console.log(JSON.stringify({ proxyLog: targets }));
  process.exit(0);
});
`;

function startProxy(certificates) {
  const proxyPath = path.join(tmp, "d5-warm-proxy.mjs");
  writeFileSync(proxyPath, proxyScript);
  const logPath = path.join(tmp, "proxy.log");
  const logFd = openSync(logPath, "a");
  const child = spawn(process.execPath, [proxyPath, String(jsPort), certificates.leafKey, certificates.leafChain, jsHost], {
    env: { ...process.env, PKGRE_D5_PROXY_PORT: String(proxyPort), PKGRE_D5_PROXY_VERBOSE: "1" },
    stdio: ["ignore", logFd, logFd],
  });
  child.on("error", () => closeSync(logFd));
  children.push(child);
  return { child, logPath };
}

async function stopProxy(proxy) {
  await new Promise((resolve) => {
    proxy.child.once("close", resolve);
    setTimeout(resolve, 5_000);
    proxy.child.kill("SIGTERM");
  });
  // verbose stderr (and the SIGTERM JSON dump) both land in the proxy log
  const verbose = logSlice(proxy.logPath, 0);
  const entries = verbose.split("\n").filter((line) => /^(CONNECT|SNI|ABSOLUTE|TLS-ERROR|UPSTREAM-ERROR)/.test(line));
  return entries;
}

function parseRustLog(text) {
  const entries = [];
  for (const line of text.split("\n")) {
    const match = /INFO served registry request method=(\S+) status=(\d+).*target=(\S+)$/.exec(line);
    if (match) entries.push({ method: match[1], status: Number(match[2]), target: match[3] });
  }
  return entries;
}

function parseJsLog(text) {
  const entries = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("{")) continue;
    try {
      const record = JSON.parse(line);
      if (record.target) entries.push({ method: record.method, status: record.status, target: record.target });
    } catch {
      // ignore partial trailing lines
    }
  }
  return entries;
}

// cargo sparse-index layout: /config.json, /1/<name>, /2/<name>, /3/<c>/<name>,
// /<cc>/<cc>/<name>; nothing else may ever be requested from the rust server.
const sparseIndexTargetPattern = /^\/(?:config\.json|1\/[^/]+|2\/[^/]+|3\/[^/]+\/[^/]+|[^/]{2}\/[^/]{2}\/[^/]+)$/;

function assertRustWindow(entries, label, requireEmpty) {
  if (requireEmpty) {
    check(entries.length === 0, `${label}: rust registry received ${entries.length} requests, expected none (${entries.map((entry) => entry.target).join(", ")})`);
    return;
  }
  check(entries.length > 0, `${label}: expected rust registry requests, saw none`);
  for (const entry of entries) {
    check(sparseIndexTargetPattern.test(entry.target), `${label}: unexpected rust request ${entry.method} ${entry.target}`);
    check(entry.status === 200, `${label}: rust request ${entry.target} status ${entry.status}`);
    check(entry.method === "GET", `${label}: rust request ${entry.target} method ${entry.method}`);
  }
}

function assertJsWindow(entries, label, allowedTargets, requireEmpty) {
  if (requireEmpty) {
    check(entries.length === 0, `${label}: js registry received ${entries.length} requests, expected none (${entries.map((entry) => entry.target).join(", ")})`);
    return;
  }
  check(entries.length > 0, `${label}: expected js registry requests, saw none`);
  for (const entry of entries) {
    check(allowedTargets.has(entry.target), `${label}: unexpected js request ${entry.method} ${entry.target}`);
    check(entry.status === 200, `${label}: js request ${entry.target} status ${entry.status}`);
    check(entry.method === "GET", `${label}: js request ${entry.target} method ${entry.method}`);
  }
}

// ---- execution envelope: environment sanitization + override assertions ----

const forbiddenEnvironmentPatterns = [
  /^npm_config_(?!userconfig$|cache$)/i,
  /^NPM_CONFIG_/,
  /^YARN_/,
  /^BUN_CONFIG_/,
  /^CARGO_REGISTRIES_/,
  /^CARGO_REGISTRY_/,
  /^CARGO_SOURCE_/,
];

function sanitizeEnvironment(env) {
  const cleaned = {};
  for (const [key, value] of Object.entries(env)) {
    if (forbiddenEnvironmentPatterns.some((pattern) => pattern.test(key))) continue;
    cleaned[key] = value;
  }
  return cleaned;
}

function assertEnvelope(label, args, env) {
  for (const key of Object.keys(env)) {
    check(!/registr/i.test(key), `${label}: env override key present: ${key}`);
    check(!forbiddenEnvironmentPatterns.some((pattern) => pattern.test(key)), `${label}: forbidden env key present: ${key}`);
  }
  for (const arg of args) {
    check(!["--config", "--registry", "--userconfig"].includes(arg), `${label}: forbidden CLI override ${arg}`);
  }
}

function baseEnvironment(paths, extraPathHead) {
  const pathValue = [extraPathHead, process.env.PATH].filter(Boolean).join(":");
  return sanitizeEnvironment({
    CI: "true",
    DO_NOT_TRACK: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    HOME: paths.home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NO_COLOR: "1",
    PATH: pathValue,
    TERM: "dumb",
    TMPDIR: paths.temporary,
    XDG_CACHE_HOME: paths.cache,
    XDG_CONFIG_HOME: path.join(paths.home, ".config"),
    XDG_DATA_HOME: path.join(paths.home, ".local", "share"),
  });
}

function deadProxyEnvironment(env) {
  return {
    ...env,
    ALL_PROXY: deadProxy,
    all_proxy: deadProxy,
    HTTP_PROXY: deadProxy,
    http_proxy: deadProxy,
    HTTPS_PROXY: deadProxy,
    https_proxy: deadProxy,
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
  };
}

function clientEnvironment(profile, paths, certificates) {
  const executable = profileExecutable(profile);
  const base = baseEnvironment(paths, path.dirname(executable));
  if (profile.client === "cargo") {
    return { executable, env: { ...base, CARGO_HOME: paths.cache } };
  }
  if (profile.client === "npm") {
    return {
      executable,
      env: {
        ...deadProxyEnvironment(base),
        npm_config_userconfig: path.join(paths.project, ".npmrc"),
        // warm writes its cache via --cache=<paths.cache>; the env var keeps
        // replay (bare `npm ci --offline`, no cache flag) on the same cache
        npm_config_cache: paths.cache,
      },
    };
  }

  if (profile.client === "bun") {
    const proxyUrl = `http://127.0.0.1:${proxyPort}`;
    return {
      executable,
      env: {
        ...base,
        BUN_INSTALL_CACHE_DIR: paths.cache,
        BUN_TELEMETRY_DISABLED: "1",
        HTTP_PROXY: proxyUrl,
        http_proxy: proxyUrl,
        HTTPS_PROXY: proxyUrl,
        https_proxy: proxyUrl,
        NO_PROXY: "127.0.0.1,localhost",
        no_proxy: "127.0.0.1,localhost",
        NODE_EXTRA_CA_CERTS: certificates.caCertificate,
      },
    };
  }
  return {
    executable,
    env: {
      ...deadProxyEnvironment(base),
      DENO_DIR: paths.cache,
      DENO_NO_UPDATE_CHECK: "1",
      DENO_NO_PROMPT: "1",
    },
  };
}

// ---- project materialization ----

function rewriteFile(projectPath, relative, replacements) {
  const filePath = path.join(projectPath, relative);
  let text = readFileSync(filePath, "utf8");
  for (const [from, to] of replacements) text = text.split(from).join(to);
  writeFileSync(filePath, text);
}

function scratchDirectories(project) {
  for (const directory of ["home", "cache", "tmp"]) mkdirSync(path.join(project, `.${directory}`), { recursive: true });
  return {
    project,
    home: path.join(project, ".home"),
    cache: path.join(project, ".cache"),
    temporary: path.join(project, ".tmp"),
  };
}

function materializeProfile(project) {
  mkdirSync(project, { recursive: true });
  cpSync(fixtureProject, project, { recursive: true });
  rewriteFile(project, ".cargo/config.toml", [[`sparse+https://${rustHost}/`, `sparse+http://127.0.0.1:${rustPort}/`]]);
  rewriteFile(project, ".npmrc", [[`registry=https://${jsHost}/`, `registry=http://127.0.0.1:${jsPort}/`]]);
  writeFileSync(
    path.join(project, "package.json"),
    `${JSON.stringify({ name: "d5-js-client", private: true, version: "0.0.0", dependencies: { [jsPackage]: jsVersion } }, null, 2)}\n`,
  );
  writeFileSync(
    path.join(project, "Cargo.toml"),
    [
      "[package]",
      'name = "d5-cargo-client"',
      'version = "0.0.0"',
      'edition = "2021"',
      "",
      "[dependencies]",
      'accessory = { version = "=2.1.0", registry = "pkgre" }',
      "",
    ].join("\n"),
  );
  mkdirSync(path.join(project, "src"), { recursive: true });
  writeFileSync(path.join(project, "src", "lib.rs"), "");
  return scratchDirectories(project);
}

function warmArguments(profile, paths) {
  if (profile.client === "cargo") return ["fetch"];
  if (profile.client === "npm") {
    return [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--allow-directory=none",
      "--allow-file=none",
      "--allow-git=none",
      "--allow-remote=none",
      "--replace-registry-host=always",
      `--cache=${paths.cache}`,
      "--fetch-retries=0",
      "--fetch-timeout=5000",
      "--loglevel=warn",
    ];
  }
  if (profile.client === "bun") {
    return ["install", "--ignore-scripts", "--no-progress", "--no-summary", `--cache-dir=${paths.cache}`];
  }
  return ["install", "--quiet", "--node-modules-dir=auto", "--lock=deno.lock"];
}

function replayArguments(profile, paths) {
  if (profile.client === "cargo") return ["build", "--frozen", "--offline"];
  if (profile.client === "npm") return ["ci", "--offline"];
  if (profile.client === "bun") return ["install", "--frozen-lockfile", "--ignore-scripts", "--no-progress", "--no-summary", `--cache-dir=${paths.cache}`];
  return ["install", "--frozen", "--cached-only"];
}

function parseCargoLock(filePath) {
  const packages = [];
  for (const block of readFileSync(filePath, "utf8").split("[[package]]").slice(1)) {
    const name = /^name = "(.*)"$/m.exec(block)?.[1] ?? null;
    const version = /^version = "(.*)"$/m.exec(block)?.[1] ?? null;
    const source = /^source = "(.*)"$/m.exec(block)?.[1] ?? null;
    packages.push({ name, version, source });
  }
  return packages;
}

function assertCargoLock(profile, paths) {
  const lockPath = path.join(paths.project, "Cargo.lock");
  check(existsSync(lockPath), `cargo ${profile.id}: Cargo.lock committed by warm phase`);
  const packages = parseCargoLock(lockPath);
  check(packages.length === cargoClosure.length + 1, `cargo ${profile.id}: Cargo.lock package count ${packages.length} === closure ${cargoClosure.length} + root`);
  const sourced = packages.filter((entry) => entry.source !== null);
  const expectedSource = `sparse+http://127.0.0.1:${rustPort}/`;
  for (const entry of sourced) {
    check(entry.source === expectedSource, `cargo ${profile.id}: ${entry.name} source ${entry.source} === local registry`);
  }
  const closure = sourced.map((entry) => [entry.name, entry.version]).sort((a, b) => a[0].localeCompare(b[0]));
  const expected = [...cargoClosure].sort((a, b) => a[0].localeCompare(b[0]));
  check(
    JSON.stringify(closure) === JSON.stringify(expected),
    `cargo ${profile.id}: locked closure ${JSON.stringify(closure)} === pinned closure ${JSON.stringify(expected)}`,
  );
}

function assertNpmLock(profile, paths, tarballUrl) {
  const lockPath = path.join(paths.project, "package-lock.json");
  check(existsSync(lockPath), `npm ${profile.id}: package-lock.json committed by warm phase`);
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const entry = lock.packages?.["node_modules/pkgre-js"];
  check(Boolean(entry), `npm ${profile.id}: lockfile records node_modules/pkgre-js`);
  check(entry?.resolved === tarballUrl, `npm ${profile.id}: lockfile resolved ${entry?.resolved} === canonical ${tarballUrl}`);
  check(lock.packages?.[""]?.dependencies?.[jsPackage] === jsVersion, `npm ${profile.id}: root dependency pinned exact`);
}

function assertBunLock(profile, paths) {
  const lockPath = path.join(paths.project, "bun.lock");
  check(existsSync(lockPath), `bun ${profile.id}: bun.lock committed by warm phase`);
  const text = readFileSync(lockPath, "utf8");
  check(text.includes(`"${jsPackage}"`), `bun ${profile.id}: bun.lock records ${jsPackage}`);
  check(text.includes(jsVersion), `bun ${profile.id}: bun.lock records ${jsVersion}`);
}

function assertDenoLock(profile, paths) {
  const lockPath = path.join(paths.project, "deno.lock");
  check(existsSync(lockPath), `deno ${profile.id}: deno.lock committed by warm phase`);
  const text = readFileSync(lockPath, "utf8");
  check(text.includes(`${jsPackage}@${jsVersion}`), `deno ${profile.id}: deno.lock records ${jsPackage}@${jsVersion}`);
}

function assertSentinelAbsent(project, label) {
  check(!existsSync(path.join(project, "pkgre-lifecycle-sentinel")), `${label}: lifecycle sentinel absent`);
}

// ---- declaration admission (pure JS; zero processes, zero network) ----

const exactVersionPattern = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

function validateJsDependency(specifier) {
  if (typeof specifier !== "string" || specifier.length === 0) return { allowed: false, reason: "empty specifier" };
  const value = specifier;
  if (value.startsWith("npm:")) return { allowed: false, reason: "npm-alias" };
  if (/^(git|git\+ssh|git\+https|git\+file|github):/i.test(value)) return { allowed: false, reason: "git" };
  if (/^https?:\/\//i.test(value)) return { allowed: false, reason: "remote-url" };
  if (/^(file|link):/i.test(value)) return { allowed: false, reason: "file" };
  if (value.startsWith("workspace:")) return { allowed: false, reason: "workspace" };
  if (value.startsWith("jsr:")) return { allowed: false, reason: "jsr" };
  if (exactVersionPattern.test(value)) return { allowed: true, reason: "exact canonical version" };
  if (/^[a-z]/i.test(value) && !/[\^~><=*xX ]/.test(value)) return { allowed: false, reason: "dist-tag" };
  return { allowed: false, reason: "semver-range" };
}

function validateCargoDependency(declaration) {
  if (declaration.source?.git || declaration.git) return { allowed: false, reason: "git" };
  if (declaration.source?.path || declaration.path) return { allowed: false, reason: "path" };
  const registry = declaration.source?.registry ?? declaration.registry;
  if (registry !== "pkgre") return { allowed: false, reason: `foreign-registry:${registry ?? "implicit-crates-io"}` };
  const version = declaration.source?.version ?? declaration.version;
  if (typeof version !== "string" || !/^=\d+\.\d+\.\d+$/.test(version)) return { allowed: false, reason: "non-exact-version" };
  return { allowed: true, reason: "exact version on registry pkgre" };
}

function validateDeclarations(cargoDeclaration, jsSpecifier) {
  const cargo = validateCargoDependency(cargoDeclaration);
  const js = validateJsDependency(jsSpecifier);
  check(cargo.allowed, `admission accepts positive cargo declaration (${cargo.reason})`);
  check(js.allowed, `admission accepts positive js declaration (${js.reason})`);
  const sourceCases = configuration.sourceCases;
  check(sourceCases.length === 13, `configuration carries 13 sourceCases (${sourceCases.length})`);
  for (const sourceCase of sourceCases) {
    if (sourceCase.ecosystem === "javascript") {
      const verdict = validateJsDependency(sourceCase.declaration.specifier);
      check(!verdict.allowed, `${sourceCase.id}: rejected before client (${verdict.reason})`);
    } else {
      const verdict = validateCargoDependency(sourceCase.declaration.source ?? sourceCase.declaration);
      check(!verdict.allowed, `${sourceCase.id}: rejected before client (${verdict.reason})`);
    }
  }
}

// ---- lifecycle case ----

function materializeHostileProject(root) {
  mkdirSync(root, { recursive: true });
  cpSync(fixtureProject, root, { recursive: true });
  rewriteFile(root, ".npmrc", [[`registry=https://${jsHost}/`, `registry=http://127.0.0.1:${jsPort}/`]]);
  writeFileSync(
    path.join(root, "package.json"),
    `${JSON.stringify(
      {
        name: "d5-hostile-lifecycle",
        private: true,
        version: "0.0.0",
        scripts: { preinstall: "touch pkgre-lifecycle-sentinel" },
        dependencies: { [jsPackage]: jsVersion },
      },
      null,
      2,
    )}\n`,
  );
  return scratchDirectories(root);
}

// ---- poisoned override probe ----

function poisonedOverrideProbe(paths) {
  const poison = {
    NPM_CONFIG_REGISTRY: `http://127.0.0.1:${proxyPort}/`,
    npm_config_registry: `http://127.0.0.1:${proxyPort}/`,
    BUN_CONFIG_REGISTRY: `http://127.0.0.1:${proxyPort}/`,
    CARGO_REGISTRY_INDEX: `sparse+http://127.0.0.1:${proxyPort}/index/`,
    CARGO_REGISTRIES_PKGRE_INDEX: `sparse+http://127.0.0.1:${proxyPort}/index/`,
    YARN_ENABLE_NETWORK: "true",
  };
  const cleaned = sanitizeEnvironment({ ...baseEnvironment(paths), ...poison });
  for (const key of Object.keys(poison)) {
    check(!(key in cleaned), `poisoned override removed before client invocation: ${key}`);
  }
  for (const key of Object.keys(cleaned)) {
    check(!/registr/i.test(key), `sanitized environment free of registry overrides: ${key}`);
  }
}

// ---- phases ----

async function warmProfile(profile, paths, certificates, allowedJsTargets, logPaths) {
  const label = `warm ${profile.id}`;
  console.log(`== ${label} ==`);
  const rustOffset = logOffset(logPaths.rust);
  const jsOffset = logOffset(logPaths.js);
  if (profile.client !== "cargo") rmSync(path.join(paths.project, "node_modules"), { force: true, recursive: true });
  const { executable, env } = clientEnvironment(profile, paths, certificates);
  const args = warmArguments(profile, paths);
  assertEnvelope(label, args, env);
  const result = await runCommand(executable, args, { cwd: paths.project, env });
  assertSucceeded(result, label);
  if (profile.client === "cargo") {
    assertCargoLock(profile, paths);
    assertRustWindow(parseRustLog(logSlice(logPaths.rust, rustOffset)), label, false);
    assertJsWindow(parseJsLog(logSlice(logPaths.js, jsOffset)), label, allowedJsTargets.set, true);
  } else {
    if (profile.client === "npm") assertNpmLock(profile, paths, allowedJsTargets.tarballUrl);
    if (profile.client === "bun") assertBunLock(profile, paths);
    if (profile.client === "deno") assertDenoLock(profile, paths);
    assertJsWindow(parseJsLog(logSlice(logPaths.js, jsOffset)), label, allowedJsTargets.set, false);
    assertRustWindow(parseRustLog(logSlice(logPaths.rust, rustOffset)), label, true);
  }
  assertSentinelAbsent(paths.project, label);
}

async function replayProfile(profile, paths, certificates) {
  const label = `replay ${profile.id}`;
  console.log(`== ${label} ==`);
  const { executable, env } = clientEnvironment(profile, paths, certificates);
  const args = replayArguments(profile, paths);
  assertEnvelope(label, args, env);
  if (profile.client === "cargo") rmSync(path.join(paths.project, "target"), { force: true, recursive: true });
  if (profile.client === "deno") rmSync(path.join(paths.project, "node_modules"), { force: true, recursive: true });
  const result = await runCommand("unshare", ["-rn", executable, ...args], { cwd: paths.project, env });
  assertSucceeded(result, label);
  if (profile.client === "cargo") {
    const rlib = path.join(paths.project, "target", "debug", "libd5_cargo_client.rlib");
    check(existsSync(rlib), `${label}: compiled artifact present (${rlib})`);
    assertCargoLock(profile, paths);
  } else {
    check(existsSync(path.join(paths.project, "node_modules", jsPackage)), `${label}: ${jsPackage} present in node_modules`);
  }
}

async function runLifecycleCase(profile, certificates, allowedJsTargets, logPaths, workspace) {
  const label = `lifecycle ${profile.id}`;
  console.log(`== ${label} ==`);
  const paths = materializeHostileProject(path.join(workspace, "hostile", profile.client));
  rmSync(path.join(paths.project, "node_modules"), { force: true, recursive: true });
  const jsOffset = logOffset(logPaths.js);
  const { executable, env } = clientEnvironment(profile, paths, certificates);
  const args = warmArguments(profile, paths);
  assertEnvelope(label, args, env);
  const result = await runCommand(executable, args, { cwd: paths.project, env });
  assertSucceeded(result, label);
  assertSentinelAbsent(paths.project, label);
  assertJsWindow(parseJsLog(logSlice(logPaths.js, jsOffset)), label, allowedJsTargets.set, false);
}

async function verifyClientVersions() {
  for (const profile of profiles) {
    const executable = profileExecutable(profile);
    if (profile.client === "cargo") {
      const result = await runCommand(executable, ["--version"]);
      check(result.stdout.includes(`cargo ${profile.version}`), `cargo version ${result.stdout.trim()} === ${profile.version}`);
      continue;
    }
    const result = await runCommand(executable, ["--version"]);
    if (profile.client === "deno") {
      check(result.stdout.startsWith(`deno ${profile.version}`), `deno version ${result.stdout.split("\n")[0]} starts with ${profile.version}`);
    } else {
      check(result.stdout.trim() === profile.version, `${profile.client} version ${result.stdout.trim()} === ${profile.version}`);
    }
    if (profile.client === "npm") {
      const nodeResult = await runCommand(path.join(path.dirname(executable), "node"), ["--version"]);
      check(nodeResult.stdout.trim() === `v${profile.runtimeVersion}`, `node ${profile.id} ${nodeResult.stdout.trim()} === v${profile.runtimeVersion}`);
    }
  }
}

async function main() {
  for (const [port, label] of [[rustPort, "rust"], [rustPort + 1, "rust admin"], [jsPort, "js"], [jsPort + 1, "js admin"], [proxyPort, "proxy"]]) {
    await assertPortFree(port, label);
  }
  check(existsSync(rustCatalog), `rust catalog present: ${rustCatalog}`);
  check(existsSync(path.join(jsSiteRoot, "catalog.json")), `js site root present: ${jsSiteRoot}`);
  check(existsSync(rustServeBin), `rust serve binary present: ${rustServeBin}`);

  await verifyClientVersions();

  const certificates = generateCertificates(path.join(tmp, "certs"));

  const rustConfigPath = path.join(tmp, "rust-serve.toml");
  writeFileSync(
    rustConfigPath,
    [
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
    ].join("\n"),
  );
  const rustServer = startServer(rustServeBin, [rustConfigPath], "rust-serve.log");

  const jsConfigPath = path.join(tmp, "js-serve.json");
  writeFileSync(
    jsConfigPath,
    JSON.stringify({
      schema: 1,
      public: { bind: `127.0.0.1:${jsPort}` },
      admin: { bind: `127.0.0.1:${jsPort + 1}` },
      limits: { "max-concurrency": 64 },
      registry: {
        catalog: path.join(jsSiteRoot, "catalog.json"),
        delivery: "body",
        "archive-store": path.join(jsSiteRoot, "archives"),
      },
    }),
  );
  const jsServer = startServer(process.execPath, [jsServeEntry, jsConfigPath], "js-serve.log");
  const logPaths = { rust: rustServer.logPath, js: jsServer.logPath };

  await waitReady(rustPort + 1, "rust");
  await waitReady(jsPort + 1, "js");

  const proxy = startProxy(certificates);
  await new Promise((resolve) => setTimeout(resolve, 300));
  await waitTcpReady(proxyPort, "warm proxy");


  // the served packument defines the allowed js destination set + admission surface
  const packumentResponse = await request(jsPort, "GET", `/${jsPackage}`);
  check(packumentResponse.status === 200, "served packument /pkgre-js status 200");
  const packument = JSON.parse(packumentResponse.body.toString("utf8"));
  const versionMetadata = packument.versions?.[jsVersion];
  check(Boolean(versionMetadata), `packument exposes ${jsVersion}`);
  const tarballUrl = versionMetadata?.dist?.tarball;
  const tarballPath = tarballUrl ? new URL(tarballUrl).pathname : null;
  check(tarballUrl === `https://${jsHost}${tarballPath}`, `packument tarball ${tarballUrl} on approved authority https://${jsHost}/`);
  check(!Object.keys(versionMetadata ?? {}).includes("scripts"), "admitted packument version carries no scripts field");
  check(!Object.keys(packument).includes("scripts"), "admitted packument carries no scripts field");
  const allowedJsTargets = { set: new Set([`/${jsPackage}`, tarballPath]), tarballUrl };

  // admission validation BEFORE any client invocation: positives + all 13 sourceCases
  const admissionSpawnSnapshot = spawnedProcesses;
  validateDeclarations({ version: "=2.1.0", registry: "pkgre" }, jsVersion);
  check(spawnedProcesses === admissionSpawnSnapshot, "admission validation spawned zero processes");

  // warm phases: cargo direct production chain; npm/deno dead proxy; bun MITM
  const warmPaths = new Map();
  for (const profile of profiles) {
    const paths = materializeProfile(path.join(tmp, profile.id, "project"));
    warmPaths.set(profile.id, paths);
    await warmProfile(profile, paths, certificates, allowedJsTargets, logPaths);
  }

  // lifecycle case (npm, bun, deno): hostile fixture installs with scripts disabled
  for (const client of ["npm", "bun", "deno"]) {
    const profile = profiles.find((entry) => entry.client === client);
    await runLifecycleCase(profile, certificates, allowedJsTargets, logPaths, tmp);
  }

  const proxyEntries = await stopProxy(proxy);

  // poisoned override probe: disallowed inherited overrides are removed
  poisonedOverrideProbe(warmPaths.get("cargo-1.95.0"));

  // denied-source revalidation after proxy shutdown: still zero client invocation
  const rustOffset = logOffset(logPaths.rust);
  const jsOffset = logOffset(logPaths.js);
  const revalidationSpawnSnapshot = spawnedProcesses;
  validateDeclarations({ version: "=2.1.0", registry: "pkgre" }, jsVersion);
  check(spawnedProcesses === revalidationSpawnSnapshot, "denied-source revalidation spawned zero processes");
  check(logOffset(logPaths.rust) === rustOffset && logOffset(logPaths.js) === jsOffset, "denied-source validation generated zero registry requests");

  // replay phases: OS-enforced zero egress, cache-only modes
  for (const profile of profiles) {
    await replayProfile(profile, warmPaths.get(profile.id), certificates);
  }

  // final destination capture across the whole run
  const rustEntries = parseRustLog(logSlice(logPaths.rust, 0));
  const jsEntries = parseJsLog(logSlice(logPaths.js, 0));
  assertRustWindow(rustEntries, "capture rust", false);
  const foreignJs = jsEntries.filter((entry) => !allowedJsTargets.set.has(entry.target));
  check(foreignJs.length === 0, `capture js: unexpected requests (${foreignJs.map((entry) => entry.target).join(", ")})`);
  for (const entry of jsEntries) {
    check(entry.status === 200, `capture js: ${entry.target} status ${entry.status}`);
  }
  check(jsEntries.length > 0, "capture js: warm traffic observed");

  const proxyLogEntries = proxyEntries;
  const connectEntries = proxyLogEntries.filter((entry) => entry.startsWith("CONNECT"));
  check(
    connectEntries.length >= profiles.filter((profile) => profile.client === "bun").length,
    `proxy captured ${connectEntries.length} CONNECT attempts (>= bun profiles)`,
  );
  for (const entry of proxyLogEntries) {
    check(entry === `CONNECT ${jsHost}:443` || entry === `SNI ${jsHost}`, `proxy log entry allowed: ${entry}`);
  }
  check(proxyLogEntries.every((entry) => !entry.startsWith("TLS-ERROR")), "proxy captured zero TLS errors");
  check(proxyLogEntries.every((entry) => !entry.startsWith("UPSTREAM-ERROR")), "proxy captured zero upstream errors");
  check(proxyLogEntries.every((entry) => !entry.startsWith("ABSOLUTE")), "proxy captured zero absolute-form requests");

  console.log(`D5 client replays PASSED: ${checks} checks (${profiles.length} profiles warm+replay, ${configuration.sourceCases.length} sourceCases rejected, lifecycle + poisoned-override + destination capture)`);
}

function cleanup() {
  stopping = true;
  for (const child of children) {
    try {
      child.kill("SIGTERM");
    } catch {
      // already gone
    }
  }
}

try {
  await main();
} catch (error) {
  fail(error.stack ?? String(error));
} finally {
  cleanup();
  if (process.env.PKGRE_D5_KEEP_TMP === "1") {
    console.error(`PKGRE_D5_KEEP_TMP=1: preserving scratch at ${tmp}`);
  } else {
    try {
      rmSync(tmp, { force: true, recursive: true });
    } catch {
      // best effort
    }
  }
}

if (failures > 0) {
  console.error(`D5 client replays FAILED: ${failures} failing of ${checks} checks`);
  process.exit(1);
}
process.exit(0);
