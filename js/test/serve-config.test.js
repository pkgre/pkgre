import assert from "node:assert/strict";
import test from "node:test";

import { deriveRepositoryIdentity } from "../src/accepted-ref.js";
import { USAGE, loadConfig, parseConfig, resolveArguments, validateConfig } from "../src/serve/config.js";

function baseDocument() {
  return {
    admin: { bind: "127.0.0.1:8181" },
    limits: { "max-concurrency": 8 },
    public: { bind: "127.0.0.1:8080" },
    registry: { catalog: "/var/lib/pkgre/js-catalog.json", delivery: "redirect" },
    schema: 1,
  };
}

function withRegistry(overrides) {
  const document = baseDocument();
  Object.assign(document.registry, overrides);
  return document;
}

test("serve usage names the binary and CONFIG argument", () => {
  assert.match(USAGE, /usage: pkgre-js-serve CONFIG/);
  assert.match(USAGE, /pkgre-js-serve --help/);
});

test("serve configuration parses exactly", () => {
  const document = baseDocument();
  const config = parseConfig(JSON.stringify(document), "config.json");
  assert.ok(Object.isFrozen(config));
  assert.deepEqual(config, {
    admin: { host: "127.0.0.1", port: 8181 },
    limits: { maxConcurrency: 8 },
    public: { host: "127.0.0.1", port: 8080 },
    registry: { archiveStore: null, catalog: "/var/lib/pkgre/js-catalog.json", delivery: "redirect" },
    watcher: null,
  });
  assert.ok(Object.isFrozen(config.public));
  assert.ok(Object.isFrozen(config.registry));
});

test("serve configuration accepts every delivery mode and store shape", () => {
  assert.equal(validateConfig(baseDocument()).registry.archiveStore, null);
  assert.equal(
    validateConfig(withRegistry({ delivery: "redirect", "archive-store": "/var/lib/pkgre/archives" })).registry.archiveStore,
    "/var/lib/pkgre/archives",
  );
  const body = withRegistry({ delivery: "body", "archive-store": "/var/lib/pkgre/archives" });
  assert.equal(validateConfig(body).registry.delivery, "body");
});

test("serve configuration rejects unknown and missing fields", () => {
  assert.throws(() => validateConfig({ ...baseDocument(), extra: true }), /serve configuration has unknown field extra/);
  const missingLimits = baseDocument();
  delete missingLimits.limits;
  assert.throws(() => validateConfig(missingLimits), /serve configuration is missing field limits/);
  assert.throws(() => validateConfig({ ...baseDocument(), limits: {} }), /\[limits\] is missing field max-concurrency/);
  assert.throws(
    () => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1:8080", port: 1 } }),
    /\[public\] has unknown field port/,
  );
  assert.throws(
    () => validateConfig(withRegistry({ delivery: "redirect", store: "/x" })),
    /\[registry\] has unknown field store/,
  );
});

test("serve configuration fails closed on invalid values", () => {
  assert.throws(() => validateConfig({ ...baseDocument(), schema: 2 }), /schema must be 1/);
  assert.throws(() => validateConfig({ ...baseDocument(), schema: "1" }), /schema must be 1/);
  assert.throws(() => validateConfig(withRegistry({ delivery: "proxy" })), /delivery must be "redirect" or "body"/);
  assert.throws(
    () => validateConfig(withRegistry({ delivery: "body" })),
    /delivery "body" requires \[registry\] archive-store/,
  );
  assert.throws(
    () => validateConfig(withRegistry({ delivery: "body", "archive-store": "" })),
    /archive-store must be a non-empty directory string/,
  );
  const collision = baseDocument();
  collision.admin.bind = "127.0.0.1:8080";
  assert.throws(() => validateConfig(collision), /bind and \[admin\] bind must differ/);
  assert.throws(() => validateConfig({ ...baseDocument(), limits: { "max-concurrency": 0 } }), /positive integer/);
  assert.throws(() => validateConfig({ ...baseDocument(), limits: { "max-concurrency": 1.5 } }), /positive integer/);
  assert.throws(() => validateConfig({ ...baseDocument(), limits: { "max-concurrency": "8" } }), /positive integer/);
  assert.throws(() => validateConfig({ ...baseDocument(), limits: { "max-concurrency": -1 } }), /positive integer/);
});

test("serve binds parse strictly", () => {
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1" } }), /"host:port" string/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: ":8080" } }), /"host:port" string/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1:" } }), /"host:port" string/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1:0" } }), /between 1 and 65535/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1:70000" } }), /between 1 and 65535/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1:08080" } }), /between 1 and 65535/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1:80 80" } }), /port must be numeric/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: "127.0.0.1 :8080" } }), /host must be printable/);
  assert.throws(() => validateConfig({ ...baseDocument(), public: { bind: 8080 } }), /"host:port" string/);
  assert.equal(validateConfig({ ...baseDocument(), public: { bind: "[::1]:8080" } }).public.host, "[::1]");
});

test("serve arguments are strict", () => {
  assert.deepEqual(resolveArguments(["--help"]), { kind: "help" });
  assert.deepEqual(resolveArguments(["-h"]), { kind: "help" });
  assert.deepEqual(resolveArguments(["config.json"]), { kind: "config", path: "config.json" });
  assert.deepEqual(resolveArguments([]), { kind: "usage", message: "exactly one CONFIG argument is required" });
  assert.deepEqual(resolveArguments(["a", "b"]), { kind: "usage", message: "exactly one CONFIG argument is required" });
  assert.deepEqual(resolveArguments(["-x"]), { kind: "usage", message: "unknown argument -x" });
  assert.deepEqual(resolveArguments(["--version"]), { kind: "usage", message: "unknown argument --version" });
  assert.deepEqual(resolveArguments([42]), { kind: "usage", message: "arguments must be strings" });
  assert.deepEqual(resolveArguments(undefined), { kind: "usage", message: "arguments must be strings" });
});

test("serve configuration file errors name the config path", () => {
  assert.throws(() => loadConfig("/nonexistent/pkgre-serve-config.json"), /read serve config \/nonexistent\/pkgre-serve-config\.json/);
  assert.throws(() => parseConfig("{not json", "config.json"), /parse serve config config\.json/);
  assert.throws(() => parseConfig("{}", "config.json"), /serve configuration is missing field admin/);
});

function watcherDocument() {
  return {
    admin: { bind: "127.0.0.1:8181" },
    limits: { "max-concurrency": 8 },
    public: { bind: "127.0.0.1:8080" },
    registry: { delivery: "redirect" },
    schema: 1,
    watcher: {
      bootstrapCommit: "1".repeat(40),
      catalogPath: "registry/catalog.json",
      fullRef: "refs/heads/main",
      origin: "https://github.com/pkgre/fixture-catalog.git",
      pollIntervalSeconds: 30,
      statePath: "/srv/pkgre/state",
    },
  };
}

test("watcher configuration parses exactly and derives its identity", () => {
  const config = validateConfig(watcherDocument());
  assert.equal(config.registry.catalog, null);
  const watcher = config.watcher;
  assert.ok(Object.isFrozen(watcher));
  assert.deepEqual(watcher, {
    bootstrapCommit: "1".repeat(40),
    catalogPath: "registry/catalog.json",
    fullRef: "refs/heads/main",
    origin: "https://github.com/pkgre/fixture-catalog.git",
    pollIntervalSeconds: 30,
    repository: {
      fullRef: "refs/heads/main",
      repositoryIdentity: deriveRepositoryIdentity(
        Buffer.from("https://github.com/pkgre/fixture-catalog.git"),
        Buffer.from("refs/heads/main"),
      ),
    },
    statePath: "/srv/pkgre/state",
  });
});

test("watcher and static catalog are exclusive", () => {
  const both = watcherDocument();
  both.registry.catalog = "/srv/pkgre/js-catalog.json";
  assert.throws(() => validateConfig(both), /\[registry\] catalog is only valid when no watcher is configured/);
  const neither = baseDocument();
  delete neither.registry.catalog;
  assert.throws(() => validateConfig(neither), /\[registry\] catalog is required when no watcher is configured/);
});

test("invalid watcher fields fail closed", () => {
  const cases = [
    ["origin-empty", "origin must be nonempty", (document) => { document.watcher.origin = ""; }],
    ["origin-padded", "origin must be nonempty", (document) => { document.watcher.origin = ` ${document.watcher.origin}`; }],
    ["full-ref-shape", "fullRef must be a canonical Git full ref", (document) => { document.watcher.fullRef = "main"; }],
    ["full-ref-empty", "fullRef must be a canonical Git full ref", (document) => { document.watcher.fullRef = "refs/"; }],
    ["bootstrap-commit-short", "bootstrapCommit must be 40 lowercase hexadecimal", (document) => { document.watcher.bootstrapCommit = "1".repeat(39); }],
    ["bootstrap-commit-case", "bootstrapCommit must be 40 lowercase hexadecimal", (document) => { document.watcher.bootstrapCommit = "A".repeat(40); }],
    ["bootstrap-commit-shape", "bootstrapCommit must be 40 lowercase hexadecimal", (document) => { document.watcher.bootstrapCommit = `${"1".repeat(39)}g`; }],
    ["poll-interval-zero", "pollIntervalSeconds must be a positive integer", (document) => { document.watcher.pollIntervalSeconds = 0; }],
    ["catalog-path-absolute", 'catalogPath "/srv/registry/catalog.json" must be relative', (document) => { document.watcher.catalogPath = "/srv/registry/catalog.json"; }],
    ["catalog-path-parent", 'must not contain ".." components', (document) => { document.watcher.catalogPath = "../registry/catalog.json"; }],
    ["catalog-path-empty", "non-empty relative path", (document) => { document.watcher.catalogPath = ""; }],
    ["state-path-empty", "statePath must be a non-empty directory string", (document) => { document.watcher.statePath = ""; }],
    ["unknown-watcher-field", "has unknown field interval", (document) => { document.watcher.interval = 30; }],
  ];
  for (const [label, expected, mutate] of cases) {
    const document = watcherDocument();
    mutate(document);
    assert.throws(() => validateConfig(document), new RegExp(expected), label);
  }
});

test("watcher state path and poll interval accept only sane values", () => {
  const fractional = watcherDocument();
  fractional.watcher.pollIntervalSeconds = 1.5;
  assert.throws(() => validateConfig(fractional), /pollIntervalSeconds must be a positive integer/);
  const relativeState = watcherDocument();
  relativeState.watcher.statePath = "state";
  assert.equal(validateConfig(relativeState).watcher.statePath, "state");
  const parentCatalogPath = watcherDocument();
  parentCatalogPath.watcher.catalogPath = "registry/../catalog.json";
  assert.throws(() => validateConfig(parentCatalogPath), /must not contain "\.\." components/);
});
