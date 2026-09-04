import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import test from "node:test";

import { ACCEPTED_REF_SCHEMA, canonicalAcceptedRefBytes, deriveRepositoryIdentity } from "../src/accepted-ref.js";
import { validateConfig } from "../src/serve/config.js";
import { AcceptedRefWatcher } from "../src/serve/watcher.js";
import { createShared, isReady } from "../src/serve/web.js";
import { fixtureCatalog } from "./support.js";

const GIT_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
};

/** Catalog served by every test origin: external packages only, no archive store needed. */
function originCatalog() {
  const catalog = fixtureCatalog().catalog;
  return { ...catalog, packages: catalog.packages.filter((entry) => entry.name === "@scope/helper") };
}

function git(directory, arguments_, { input } = {}) {
  const result = spawnSync("git", arguments_, { cwd: directory, encoding: "buffer", env: GIT_ENV, input });
  if (result.status !== 0) {
    throw new Error(`git ${arguments_.join(" ")} failed: ${result.stderr?.toString("utf8") ?? ""}`);
  }
  return result.stdout.toString("utf8").trim();
}

function revParse(directory, revision) {
  return git(directory, ["rev-parse", revision]);
}

function commitAll(directory, message) {
  git(directory, ["add", "-A"]);
  git(directory, [
    "-c",
    "user.email=pkgre@example.invalid",
    "-c",
    "user.name=pkgre",
    "commit",
    "--quiet",
    "--allow-empty",
    "-m",
    message,
  ]);
  return revParse(directory, "HEAD");
}

/** One tiny Git origin carrying the fixture catalog file on refs/heads/main. */
class Origin {
  constructor(label) {
    this.directory = mkdtempSync(path.join(os.tmpdir(), `${label}-`));
    this.origin = path.join(this.directory, "origin");
    mkdirSync(path.join(this.origin, "registry"), { recursive: true });
    git(this.origin, ["init", "--quiet", "--initial-branch=main"]);
    writeFileSync(path.join(this.origin, "registry", "catalog.json"), `${JSON.stringify(originCatalog(), null, 2)}\n`);
    this.root = commitAll(this.origin, "bootstrap catalog");
  }

  path() {
    return this.origin;
  }

  identity() {
    return deriveRepositoryIdentity(Buffer.from(this.origin), Buffer.from("refs/heads/main"));
  }

  advanceEmpty(message) {
    return commitAll(this.origin, message);
  }

  /** A descendant whose catalog file is semantically invalid. */
  advanceInvalid() {
    const catalogPath = path.join(this.origin, "registry", "catalog.json");
    const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
    catalog.schema = "not-a-valid-schema";
    writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
    return commitAll(this.origin, "invalid catalog");
  }

  /** A further descendant restoring a valid catalog. */
  advanceRestored() {
    const catalogPath = path.join(this.origin, "registry", "catalog.json");
    const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
    catalog.schema = originCatalog().schema;
    writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
    return commitAll(this.origin, "restore catalog");
  }

  moveRemote(commit) {
    git(this.origin, ["update-ref", "refs/heads/main", commit]);
  }

  divergentTip() {
    git(this.origin, ["checkout", "--quiet", "-b", "pkgre-side", this.root]);
    const tip = commitAll(this.origin, "divergent");
    git(this.origin, ["checkout", "--quiet", "main"]);
    this.moveRemote(tip);
    return tip;
  }
}

function tempDirectory(label) {
  return mkdtempSync(path.join(os.tmpdir(), `${label}-`));
}

function watcherConfig(directory, origin, bootstrap) {
  return validateConfig({
    admin: { bind: "127.0.0.1:30101" },
    limits: { "max-concurrency": 8 },
    public: { bind: "127.0.0.1:30100" },
    registry: { delivery: "redirect" },
    schema: 1,
    watcher: {
      bootstrapCommit: bootstrap,
      catalogPath: "registry/catalog.json",
      fullRef: "refs/heads/main",
      origin: origin.path(),
      pollIntervalSeconds: 1,
      statePath: path.join(directory, "state"),
    },
  });
}

function watcherFor(config, shared) {
  assert.ok(config.watcher !== null, "watcher test configuration must select the watcher");
  return new AcceptedRefWatcher(config.watcher, {
    archiveStore: config.registry.archiveStore,
    delivery: config.registry.delivery,
    shared,
  });
}

function sharedFor(config) {
  return createShared({ delivery: config.registry.delivery, maxConcurrency: config.limits.maxConcurrency });
}

function recordPath(directory) {
  return path.join(directory, "state", "accepted-ref.json");
}

function storedCommit(directory) {
  return JSON.parse(readFileSync(recordPath(directory), "utf8")).acceptedCommit;
}

function writeCanonicalRecord(directory, record, binding) {
  mkdirSync(path.join(directory, "state"), { recursive: true });
  writeFileSync(recordPath(directory), canonicalAcceptedRefBytes(record, binding));
}

/** Rebuilds the mirror store with exactly one damaged loose commit object. */
function corruptLooseObject(repository, commit) {
  const content = execFileSync("git", ["cat-file", "commit", commit], { cwd: repository, env: GIT_ENV });
  rmSync(path.join(repository, "objects", "pack"), { force: true, recursive: true });
  const objectPath = path.join(repository, "objects", commit.slice(0, 2), commit.slice(2));
  mkdirSync(path.dirname(objectPath), { recursive: true });
  const written = spawnSync("git", ["hash-object", "-t", "commit", "-w", "--stdin"], {
    cwd: repository,
    encoding: "buffer",
    env: GIT_ENV,
    input: content,
  });
  assert.equal(written.status, 0, "write loose commit object");
  chmodSync(objectPath, 0o644);
  const damage = Buffer.alloc(8, 0xff);
  const fd = openSync(objectPath, "r+");
  try {
    writeSync(fd, damage, 0, damage.length, 8);
  } finally {
    closeSync(fd);
  }
}

test("fresh install bootstraps and ignores a remote ahead", async (t) => {
  const directory = tempDirectory("pkgre-watch-bootstrap");
  const origin = new Origin("pkgre-watch-bootstrap-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const ahead = origin.advanceEmpty("remote ahead of bootstrap");
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  assert.equal(storedCommit(directory), origin.root);
  assert.ok(isReady(shared));
  assert.ok(existsSync(path.join(directory, "state", "repository", "HEAD")));
  // Startup adopted the configured bootstrap commit, never the ahead remote
  // tip; the next poll then evaluates the remote normally and accepts the
  // same-tree descendant.
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate" });
  assert.equal(storedCommit(directory), ahead);
});

test("restart with remote unavailable starts from the accepted record", async (t) => {
  const directory = tempDirectory("pkgre-watch-restart");
  const origin = new Origin("pkgre-watch-restart-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  origin.advanceEmpty("forward");
  const config = watcherConfig(directory, origin, origin.root);
  const watcher = watcherFor(config, sharedFor(config));
  await watcher.startup();
  assert.equal(storedCommit(directory), origin.root);
  const hidden = path.join(directory, "origin-hidden");
  renameSync(origin.path(), hidden);
  const restarted = watcherFor(config, sharedFor(config));
  await restarted.startup();
  assert.equal(storedCommit(directory), origin.root);
  assert.ok(isReady(restarted.shared));
});

test("malformed record forbids bootstrap", async (t) => {
  const directory = tempDirectory("pkgre-watch-malformed");
  const origin = new Origin("pkgre-watch-malformed-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  mkdirSync(path.join(directory, "state"), { recursive: true });
  writeFileSync(recordPath(directory), "{ not json");
  const watcher = watcherFor(config, shared);
  await assert.rejects(watcher.startup(), /accepted-record-malformed/);
  assert.ok(!isReady(shared));
  assert.equal(readFileSync(recordPath(directory), "utf8"), "{ not json");
});

test("identity mismatch forbids bootstrap", async (t) => {
  const directory = tempDirectory("pkgre-watch-identity");
  const origin = new Origin("pkgre-watch-identity-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const binding = { fullRef: "refs/heads/main", repositoryIdentity: "a".repeat(64) };
  writeCanonicalRecord(
    directory,
    { acceptedCommit: origin.root, fullRef: binding.fullRef, repositoryIdentity: binding.repositoryIdentity, schema: ACCEPTED_REF_SCHEMA },
    binding,
  );
  const watcher = watcherFor(config, shared);
  await assert.rejects(watcher.startup(), /repository-identity-mismatch/);
  assert.ok(!isReady(shared));
});

test("full ref mismatch forbids bootstrap", async (t) => {
  const directory = tempDirectory("pkgre-watch-fullref");
  const origin = new Origin("pkgre-watch-fullref-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const binding = { fullRef: "refs/heads/release", repositoryIdentity: origin.identity() };
  writeCanonicalRecord(
    directory,
    { acceptedCommit: origin.root, fullRef: binding.fullRef, repositoryIdentity: binding.repositoryIdentity, schema: ACCEPTED_REF_SCHEMA },
    binding,
  );
  const watcher = watcherFor(config, shared);
  await assert.rejects(watcher.startup(), /full-ref-mismatch/);
  assert.ok(!isReady(shared));
});

test("missing accepted object fails startup without a fetch", async (t) => {
  const directory = tempDirectory("pkgre-watch-accepted-missing");
  const origin = new Origin("pkgre-watch-accepted-missing-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  origin.advanceEmpty("forward");
  const config = watcherConfig(directory, origin, origin.root);
  const watcher = watcherFor(config, sharedFor(config));
  await watcher.startup();
  rmSync(path.join(directory, "state", "repository"), { force: true, recursive: true });
  const restarted = watcherFor(config, sharedFor(config));
  await assert.rejects(restarted.startup(), /accepted-object-unavailable/);
  assert.ok(
    !existsSync(path.join(directory, "state", "repository", "refs", "pkgre")),
    "startup with a valid record must not fetch",
  );
});

test("missing bootstrap object fails startup", async (t) => {
  const directory = tempDirectory("pkgre-watch-bootstrap-missing");
  const origin = new Origin("pkgre-watch-bootstrap-missing-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, "b".repeat(40));
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await assert.rejects(watcher.startup(), /bootstrap-object-unavailable/);
  assert.ok(!isReady(shared));
});

test("corrupt accepted object fails startup", async (t) => {
  const directory = tempDirectory("pkgre-watch-corrupt");
  const origin = new Origin("pkgre-watch-corrupt-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const watcher = watcherFor(config, sharedFor(config));
  await watcher.startup();
  corruptLooseObject(path.join(directory, "state", "repository"), origin.root);
  const restarted = watcherFor(config, sharedFor(config));
  await assert.rejects(restarted.startup(), /accepted-object-invalid/);
});

test("forward descendant is accepted", async (t) => {
  const directory = tempDirectory("pkgre-watch-forward");
  const origin = new Origin("pkgre-watch-forward-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const before = shared.snapshot;
  const child = origin.advanceEmpty("forward");
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate" });
  assert.equal(storedCommit(directory), child);
  assert.notEqual(shared.snapshot, before);
});

test("semantic failure retains then suppresses", async (t) => {
  const directory = tempDirectory("pkgre-watch-semantic");
  const origin = new Origin("pkgre-watch-semantic-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const before = shared.snapshot;
  origin.advanceInvalid();
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "retain-accepted", reason: "semantic-validation-failed" });
  assert.equal(storedCommit(directory), origin.root);
  assert.equal(shared.snapshot, before);
  const suppressed = await watcher.pollOnce();
  assert.equal(suppressed.reason, "rejected-hash-suppressed");
  assert.equal(shared.snapshot, before);
});

test("predecessor tip is rejected then suppressed", async (t) => {
  const directory = tempDirectory("pkgre-watch-predecessor");
  const origin = new Origin("pkgre-watch-predecessor-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const child = origin.advanceEmpty("forward");
  const config = watcherConfig(directory, origin, child);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  assert.equal(storedCommit(directory), child);
  origin.moveRemote(origin.root);
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "retain-accepted", reason: "candidate-not-descendant" });
  assert.equal(storedCommit(directory), child);
  const suppressed = await watcher.pollOnce();
  assert.equal(suppressed.reason, "rejected-hash-suppressed");
});

test("divergent tip is rejected then suppressed", async (t) => {
  const directory = tempDirectory("pkgre-watch-divergent");
  const origin = new Origin("pkgre-watch-divergent-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const child = origin.advanceEmpty("forward");
  const accepted = await watcher.pollOnce();
  assert.equal(accepted.decision, "accept-forward");
  origin.divergentTip();
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "retain-accepted", reason: "candidate-not-descendant" });
  assert.equal(storedCommit(directory), child);
  const suppressed = await watcher.pollOnce();
  assert.equal(suppressed.reason, "rejected-hash-suppressed");
});

test("remote outage does not suppress the tip", async (t) => {
  const directory = tempDirectory("pkgre-watch-outage");
  const origin = new Origin("pkgre-watch-outage-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const before = shared.snapshot;
  const hidden = path.join(directory, "origin-hidden");
  renameSync(origin.path(), hidden);
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "retain-accepted", reason: "remote-unavailable" });
  assert.equal(storedCommit(directory), origin.root);
  assert.equal(shared.snapshot, before);
  renameSync(hidden, origin.path());
  const restored = await watcher.pollOnce();
  assert.deepEqual(restored, { decision: "unchanged", reason: "candidate-equals-accepted" });
});

test("persistence failure retains then suppresses", async (t) => {
  const directory = tempDirectory("pkgre-watch-persist");
  const origin = new Origin("pkgre-watch-persist-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const before = shared.snapshot;
  origin.advanceEmpty("forward");
  rmSync(recordPath(directory));
  mkdirSync(recordPath(directory));
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "retain-accepted", reason: "durable-persistence-failed" });
  assert.equal(shared.snapshot, before);
  const suppressed = await watcher.pollOnce();
  assert.equal(suppressed.reason, "rejected-hash-suppressed");
  const leftovers = readdirSync(path.join(directory, "state"))
    .map((entry) => String(entry))
    .filter((name) => name.includes(".tmp-"));
  assert.deepEqual(leftovers, []);
});

test("different candidate after rejection is accepted", async (t) => {
  const directory = tempDirectory("pkgre-watch-recovery");
  const origin = new Origin("pkgre-watch-recovery-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const before = shared.snapshot;
  origin.advanceInvalid();
  const rejected = await watcher.pollOnce();
  assert.equal(rejected.reason, "semantic-validation-failed");
  const grandchild = origin.advanceRestored();
  const report = await watcher.pollOnce();
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate" });
  assert.equal(storedCommit(directory), grandchild);
  assert.notEqual(shared.snapshot, before);
});
