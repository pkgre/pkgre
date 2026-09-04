import assert from "node:assert/strict";
import test from "node:test";

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
