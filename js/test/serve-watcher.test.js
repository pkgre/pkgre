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
import { canonicalNpmArchiveUrl } from "../src/catalog.js";
import { validateConfig } from "../src/serve/config.js";
import { AcceptedRefWatcher } from "../src/serve/watcher.js";
import { createShared, isReady, statusReport } from "../src/serve/web.js";
import { archiveDigests, fixtureCatalog, packageArchive } from "./support.js";

const fixture = fixtureCatalog();

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

  /** A descendant whose catalog file is not JSON at all. */
  advanceInvalidJson() {
    writeFileSync(path.join(this.origin, "registry", "catalog.json"), "{ not json\n");
    return commitAll(this.origin, "unparseable catalog");
  }

  /** A descendant that deletes the catalog file. */
  advanceDeletingCatalog() {
    git(this.origin, ["rm", "--quiet", "registry/catalog.json"]);
    return commitAll(this.origin, "delete catalog");
  }

  /** A descendant whose catalog adds one helper version the archive store may lack. */
  advanceCatalogVersion(version) {
    const catalogPath = path.join(this.origin, "registry", "catalog.json");
    const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
    const entry = catalog.packages.find((packageEntry) => packageEntry.name === "@scope/helper");
    entry.distTags = { latest: version.manifest.version };
    entry.versions = [...entry.versions, {
      admittedAt: "2026-08-25T00:00:00.000Z",
      manifest: version.manifest,
      publishedAt: "2020-01-01T00:00:00.000Z",
      source: {
        ...version.digests,
        fetchedAt: "2026-08-24T00:00:00.000Z",
        kind: "npmjs",
        metadataSha256: "b".repeat(64),
        url: canonicalNpmArchiveUrl("@scope/helper", version.manifest.version),
      },
      version: version.manifest.version,
    }];
    writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
    return commitAll(this.origin, `add helper ${version.manifest.version}`);
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

function watcherConfig(directory, origin, bootstrap, registry = { delivery: "redirect" }) {
  return validateConfig({
    admin: { bind: "127.0.0.1:30101" },
    limits: { "max-concurrency": 8 },
    public: { bind: "127.0.0.1:30100" },
    registry,
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

/** A manual monotonic clock in milliseconds, advanced by tests only. */
function manualClock() {
  let now = 0;
  return {
    advance(seconds) {
      now += seconds * 1000;
    },
    now() {
      return now;
    },
  };
}

function watcherFor(config, shared, clock) {
  assert.ok(config.watcher !== null, "watcher test configuration must select the watcher");
  return new AcceptedRefWatcher(config.watcher, {
    archiveStore: config.registry.archiveStore,
    delivery: config.registry.delivery,
    shared,
    ...(clock === undefined ? {} : { clock: () => clock.now() }),
  });
}

/** One more helper version with its own archive, which a test writes to the store. */
function helperVersion(version = "1.2.4") {
  const manifest = { license: "MIT", name: "@scope/helper", version };
  const archive = packageArchive(manifest);
  return { archive, digests: archiveDigests(archive), manifest };
}

/** A body-delivery configuration whose archive store a test fills. */
function bodyWatcherConfig(directory, origin, bootstrap, store) {
  return watcherConfig(directory, origin, bootstrap, { "archive-store": store, delivery: "body" });
}

/** Makes the accepted-ref record path a directory, so persisting a record fails. */
function breakRecordPath(directory) {
  rmSync(recordPath(directory), { force: true });
  mkdirSync(recordPath(directory));
}

/** Writes one archive body into a store, so the next snapshot build can read it. */
function storeBody(store, sha256, bytes) {
  writeFileSync(path.join(store, `${sha256}.tgz`), bytes);
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
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
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
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
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
  assert.deepEqual(report, {
    decision: "retain-accepted",
    reason: "semantic-validation-failed",
    refusal: { attempts: 1, class: "candidate", failure: "snapshot-invalid", retryInSeconds: null },
  });
  assert.equal(storedCommit(directory), origin.root);
  assert.equal(shared.snapshot, before);
  const suppressed = await watcher.pollOnce();
  assert.equal(suppressed.reason, "rejected-hash-suppressed");
  assert.deepEqual(
    suppressed.refusal,
    { attempts: 1, class: "candidate", failure: "snapshot-invalid", retryInSeconds: null },
    "a skipped poll keeps the entry and counts no attempt",
  );
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
  assert.deepEqual(report, {
    decision: "retain-accepted",
    reason: "candidate-not-descendant",
    refusal: { attempts: 1, class: "candidate", failure: "not-descendant", retryInSeconds: null },
  });
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
  assert.deepEqual(report, {
    decision: "retain-accepted",
    reason: "candidate-not-descendant",
    refusal: { attempts: 1, class: "candidate", failure: "not-descendant", retryInSeconds: null },
  });
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
  assert.deepEqual(report, { decision: "retain-accepted", reason: "remote-unavailable", refusal: null });
  assert.equal(storedCommit(directory), origin.root);
  assert.equal(shared.snapshot, before);
  renameSync(hidden, origin.path());
  const restored = await watcher.pollOnce();
  assert.deepEqual(restored, { decision: "unchanged", reason: "candidate-equals-accepted", refusal: null });
});

test("persistence failure is retried", async (t) => {
  const directory = tempDirectory("pkgre-watch-persist");
  const origin = new Origin("pkgre-watch-persist-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  const before = shared.snapshot;
  const child = origin.advanceEmpty("forward");
  rmSync(recordPath(directory));
  mkdirSync(recordPath(directory));

  const report = await watcher.pollOnce();
  assert.deepEqual(report, {
    decision: "retain-accepted",
    reason: "durable-persistence-failed",
    refusal: { attempts: 1, class: "local", failure: "persistence-failed", retryInSeconds: 60 },
  });
  assert.equal(shared.snapshot, before);
  assert.equal(watcher.accepted.acceptedCommit, origin.root, "the accepted ref is unchanged");
  assert.ok(existsSync(recordPath(directory)), "a refused persistence must not replace the record path");
  const leftovers = readdirSync(path.join(directory, "state"))
    .map((entry) => String(entry))
    .filter((name) => name.includes(".tmp-"));
  assert.deepEqual(leftovers, []);

  // Before the due time the tip is skipped, with no attempt of its own.
  const skipped = await watcher.pollOnce();
  assert.deepEqual(skipped, {
    decision: "retain-accepted",
    reason: "rejected-hash-suppressed",
    refusal: { attempts: 1, class: "local", failure: "persistence-failed", retryInSeconds: 60 },
  });
  assert.equal(shared.snapshot, before);

  // At the due time, with the record path repaired, the same commit is accepted.
  rmSync(recordPath(directory), { recursive: true });
  clock.advance(60);
  const accepted = await watcher.pollOnce();
  assert.deepEqual(accepted, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), child);
  assert.notEqual(shared.snapshot, before);
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
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), grandchild);
  assert.notEqual(shared.snapshot, before);
});

test("local failures follow the retry schedule", async (t) => {
  const directory = tempDirectory("pkgre-watch-schedule");
  const origin = new Origin("pkgre-watch-schedule-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  origin.advanceEmpty("forward");
  breakRecordPath(directory);

  let waited = 0;
  for (const attempts of [1, 2, 3, 4, 5, 6]) {
    clock.advance(waited);
    const report = await watcher.pollOnce();
    assert.equal(report.refusal.class, "local");
    assert.equal(report.refusal.attempts, attempts);
    const expected = [60, 120, 240, 480, 900, 900][attempts - 1];
    assert.equal(report.refusal.retryInSeconds, expected, `attempt ${attempts}`);
    waited = expected;
  }
  assert.equal(watcher.accepted.acceptedCommit, origin.root, "a lasting fault serves the last-known-good snapshot");
});

test("a newer commit while a retry waits is accepted", async (t) => {
  const directory = tempDirectory("pkgre-watch-newer");
  const origin = new Origin("pkgre-watch-newer-origin");
  const store = tempDirectory("pkgre-watch-newer-store");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
    rmSync(store, { force: true, recursive: true });
  });
  storeBody(store, fixture.helperSha256, fixture.helperArchive);
  const config = bodyWatcherConfig(directory, origin, origin.root, store);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  const version = helperVersion();
  origin.advanceCatalogVersion(version);
  const before = shared.snapshot;

  const refused = await watcher.pollOnce();
  assert.deepEqual(refused, {
    decision: "retain-accepted",
    reason: "semantic-validation-failed",
    refusal: { attempts: 1, class: "local", failure: "archive-store-incomplete", retryInSeconds: 60 },
  });
  assert.equal(shared.snapshot, before);

  // The body arrives and a newer commit follows; the newer tip is evaluated at once.
  storeBody(store, version.digests.sha256, version.archive);
  const newer = origin.advanceEmpty("newer commit");
  const accepted = await watcher.pollOnce();
  assert.deepEqual(accepted, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), newer);
  assert.notEqual(shared.snapshot, before);
  assert.equal(watcher.refusals.size, 0, "an acceptance drops the retrying entries");
});

test("a missing store body is taken up at the due time", async (t) => {
  const directory = tempDirectory("pkgre-watch-store-body");
  const origin = new Origin("pkgre-watch-store-body-origin");
  const store = tempDirectory("pkgre-watch-store-body-store");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
    rmSync(store, { force: true, recursive: true });
  });
  storeBody(store, fixture.helperSha256, fixture.helperArchive);
  const config = bodyWatcherConfig(directory, origin, origin.root, store);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  const version = helperVersion();
  const child = origin.advanceCatalogVersion(version);

  const refused = await watcher.pollOnce();
  assert.deepEqual(refused, {
    decision: "retain-accepted",
    reason: "semantic-validation-failed",
    refusal: { attempts: 1, class: "local", failure: "archive-store-incomplete", retryInSeconds: 60 },
  });
  assert.equal(storedCommit(directory), origin.root);

  // Writing the body first avoids the wait; writing it later is taken up at the due time.
  storeBody(store, version.digests.sha256, version.archive);
  clock.advance(60);
  const accepted = await watcher.pollOnce();
  assert.deepEqual(accepted, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), child);
  assert.equal(shared.snapshot.sourceCommit, child);
});

test("a restart while a retry waits evaluates the tip", async (t) => {
  const directory = tempDirectory("pkgre-watch-restart-retry");
  const origin = new Origin("pkgre-watch-restart-retry-origin");
  const store = tempDirectory("pkgre-watch-restart-retry-store");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
    rmSync(store, { force: true, recursive: true });
  });
  storeBody(store, fixture.helperSha256, fixture.helperArchive);
  const config = bodyWatcherConfig(directory, origin, origin.root, store);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  const version = helperVersion();
  const child = origin.advanceCatalogVersion(version);
  const refused = await watcher.pollOnce();
  assert.equal(refused.refusal.failure, "archive-store-incomplete");
  storeBody(store, version.digests.sha256, version.archive);

  // A restart forgets the retry map, so its first poll evaluates the tip at once.
  const restartedShared = sharedFor(config);
  const restarted = watcherFor(config, restartedShared, clock);
  await restarted.startup();
  const report = await restarted.pollOnce();
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), child);
  assert.equal(restartedShared.snapshot.sourceCommit, child);
});

test("a due retry whose fetch fails keeps its schedule", async (t) => {
  const directory = tempDirectory("pkgre-watch-due-fetch");
  const origin = new Origin("pkgre-watch-due-fetch-origin");
  const store = tempDirectory("pkgre-watch-due-fetch-store");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
    rmSync(store, { force: true, recursive: true });
  });
  storeBody(store, fixture.helperSha256, fixture.helperArchive);
  const config = bodyWatcherConfig(directory, origin, origin.root, store);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  const version = helperVersion();
  const child = origin.advanceCatalogVersion(version);
  const refused = await watcher.pollOnce();
  assert.equal(refused.refusal.failure, "archive-store-incomplete");
  clock.advance(60);
  const due = watcher.refusals.get(child);

  // A due poll that cannot fetch leaves the entry, its attempts and its due time alone.
  const repository = path.join(directory, "state", "repository");
  const hidden = path.join(directory, "state", "repository-hidden");
  renameSync(repository, hidden);
  writeFileSync(repository, "blocked");
  const failed = await watcher.pollOnce();
  assert.deepEqual(failed, { decision: "retain-accepted", reason: "remote-unavailable", refusal: null });
  assert.deepEqual(watcher.refusals.get(child), due, "the entry keeps its attempts and due time");

  rmSync(repository);
  renameSync(hidden, repository);
  storeBody(store, version.digests.sha256, version.archive);
  const accepted = await watcher.pollOnce();
  assert.deepEqual(accepted, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), child);
});

test("an unparseable catalog and a deleted catalog path stay suppressed", async (t) => {
  const directory = tempDirectory("pkgre-watch-candidate-codes");
  const origin = new Origin("pkgre-watch-candidate-codes-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const before = shared.snapshot;

  const unparseable = origin.advanceInvalidJson();
  const refused = await watcher.pollOnce();
  assert.deepEqual(refused, {
    decision: "retain-accepted",
    reason: "semantic-validation-failed",
    refusal: { attempts: 1, class: "candidate", failure: "candidate-catalog-invalid", retryInSeconds: null },
  });
  const skipped = await watcher.pollOnce();
  assert.deepEqual(skipped, {
    decision: "retain-accepted",
    reason: "rejected-hash-suppressed",
    refusal: { attempts: 1, class: "candidate", failure: "candidate-catalog-invalid", retryInSeconds: null },
  });
  assert.equal(storedCommit(directory), origin.root);

  const deleted = origin.advanceDeletingCatalog();
  const refusedAgain = await watcher.pollOnce();
  assert.deepEqual(refusedAgain, {
    decision: "retain-accepted",
    reason: "semantic-validation-failed",
    refusal: { attempts: 1, class: "candidate", failure: "catalog-path-invalid", retryInSeconds: null },
  });
  assert.notEqual(deleted, unparseable);
  assert.equal(storedCommit(directory), origin.root);
  assert.equal(shared.snapshot, before);
});

test("a second poll while one runs starts no second evaluation", async (t) => {
  const directory = tempDirectory("pkgre-watch-serialized");
  const origin = new Origin("pkgre-watch-serialized-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const watcher = watcherFor(config, shared);
  await watcher.startup();
  const child = origin.advanceEmpty("forward");

  const first = watcher.pollOnce();
  const second = watcher.pollOnce();
  assert.equal(second, first, "a poll requested while one runs returns the running poll's promise");
  const report = await first;
  assert.equal(await second, report);
  assert.deepEqual(report, { decision: "accept-forward", reason: "valid-forward-candidate", refusal: null });
  assert.equal(storedCommit(directory), child);
});

test("status reports the watcher with the watcher's clock", async (t) => {
  const directory = tempDirectory("pkgre-watch-status");
  const origin = new Origin("pkgre-watch-status-origin");
  t.after(() => {
    rmSync(directory, { force: true, recursive: true });
    rmSync(origin.directory, { force: true, recursive: true });
  });
  const config = watcherConfig(directory, origin, origin.root);
  const shared = sharedFor(config);
  const clock = manualClock();
  const watcher = watcherFor(config, shared, clock);
  await watcher.startup();
  assert.deepEqual(statusReport(shared).watcher, {
    acceptedCommit: origin.root,
    tip: null,
    lastPoll: null,
    lastRefusal: null,
  });
  const child = origin.advanceEmpty("forward");
  breakRecordPath(directory);
  await watcher.pollOnce();

  assert.deepEqual(statusReport(shared).watcher, {
    acceptedCommit: origin.root,
    tip: child,
    lastPoll: { decision: "retain-accepted", reason: "durable-persistence-failed", secondsAgo: 0 },
    lastRefusal: {
      commit: child,
      reason: "durable-persistence-failed",
      failure: "persistence-failed",
      class: "local",
      attempts: 1,
      secondsAgo: 0,
      retryInSeconds: 60,
    },
  });

  // Both ages and the wait come from the watcher's own clock.
  clock.advance(20);
  const later = statusReport(shared).watcher;
  assert.equal(later.lastPoll.secondsAgo, 20);
  assert.equal(later.lastRefusal.secondsAgo, 20);
  assert.equal(later.lastRefusal.retryInSeconds, 40);

  // At the due time the repaired host accepts the same commit, and the entry that
  // was retrying loses its wait; the refusal stays as history.
  rmSync(recordPath(directory), { recursive: true });
  clock.advance(40);
  const accepted = await watcher.pollOnce();
  assert.equal(accepted.decision, "accept-forward");
  assert.deepEqual(statusReport(shared).watcher, {
    acceptedCommit: child,
    tip: child,
    lastPoll: { decision: "accept-forward", reason: "valid-forward-candidate", secondsAgo: 0 },
    lastRefusal: {
      commit: child,
      reason: "durable-persistence-failed",
      failure: "persistence-failed",
      class: "local",
      attempts: 1,
      secondsAgo: 60,
      retryInSeconds: null,
    },
  });

  // A refusal of the candidate's own content has no retry either.
  const invalid = origin.advanceInvalid();
  const refused = await watcher.pollOnce();
  assert.equal(refused.refusal.retryInSeconds, null);
  assert.deepEqual(statusReport(shared).watcher.lastRefusal, {
    commit: invalid,
    reason: "semantic-validation-failed",
    failure: "snapshot-invalid",
    class: "candidate",
    attempts: 1,
    secondsAgo: 0,
    retryInSeconds: null,
  });
});
