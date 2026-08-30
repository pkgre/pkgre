import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

import { parseCanonicalJson, validateVersion } from "../src/canonical.js";

const fixtureRoot = new URL("../../fixtures/dynamic-registry-v1/client/", import.meta.url);
const fixtureUrl = new URL("configuration.json", fixtureRoot);
const expectedCargoConfiguration = `[registries.pkgre]
index = "sparse+https://rust.pkg.re/"

[registry]
default = "pkgre"

[source.crates-io]
replace-with = "disabled-crates-io"

[source.disabled-crates-io]
directory = ".cargo/disabled-crates-io"
`;
const expectedNpmConfiguration = `registry=https://js.pkg.re/
allow-directory=none
allow-file=none
allow-git=none
allow-remote=none
audit=false
fund=false
ignore-scripts=true
replace-registry-host=always
save-exact=true
strict-ssl=true
update-notifier=false
`;

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value), expected, `${label} fields`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateId(record, ids) {
  assert.match(record.id, /^[a-z][a-z0-9-]*$/);
  assert.ok(!ids.has(record.id), `duplicate ID ${record.id}`);
  ids.add(record.id);
}

function sourceAllowed(record) {
  if (record.ecosystem === "javascript") {
    exactKeys(record.declaration, ["dependency", "specifier"], `${record.id}.declaration`);
    try {
      validateVersion(record.declaration.specifier);
      return true;
    } catch {
      return false;
    }
  }
  assert.equal(record.ecosystem, "rust");
  exactKeys(record.declaration, ["dependency", "source"], `${record.id}.declaration`);
  const source = record.declaration.source;
  return Object.keys(source).join(",") === "registry,version"
    && source.registry === "pkgre"
    && typeof source.version === "string"
    && source.version.startsWith("=")
    && (() => {
      try {
        validateVersion(source.version.slice(1));
        return true;
      } catch {
        return false;
      }
    })();
}

test("client configuration artifacts and profiles are exact", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "client configuration fixture");
  exactKeys(fixture, [
    "artifacts",
    "cacheReplayModes",
    "clientOptionMatrix",
    "clientProfiles",
    "executionEnvelope",
    "lifecycleCases",
    "policy",
    "schema",
    "sourceCases",
  ], "fixture");
  assert.equal(fixture.schema, "pkgre-client-configuration-v1");

  assert.deepEqual(fixture.artifacts, [
    { bytes: 212, path: "project/.cargo/config.toml", sha256: "4398de6da884b0608ee094415e109f469d737e29ca66dd3236a0dad0e7e62b4a" },
    { bytes: 0, path: "project/.cargo/disabled-crates-io/.gitkeep", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { bytes: 224, path: "project/.npmrc", sha256: "65f2d168c79e5c802215df19811983f3eb1b824b89f2dea3156e5ee98a4c5bf5" },
  ]);
  for (const artifact of fixture.artifacts) {
    const bytes = await readFile(new URL(artifact.path, fixtureRoot));
    assert.equal(bytes.length, artifact.bytes, artifact.path);
    assert.equal(sha256(bytes), artifact.sha256, artifact.path);
  }
  assert.equal(await readFile(new URL("project/.cargo/config.toml", fixtureRoot), "utf8"), expectedCargoConfiguration);
  assert.equal(await readFile(new URL("project/.npmrc", fixtureRoot), "utf8"), expectedNpmConfiguration);

  assert.deepEqual(fixture.clientProfiles, [
    { client: "cargo", id: "cargo-minimum-current", roles: ["minimum", "current"], runtime: null, runtimeVersion: null, version: "1.95.0" },
    { client: "npm", id: "npm-node-minimum", roles: ["minimum"], runtime: "node", runtimeVersion: "24.15.0", version: "12.0.2" },
    { client: "npm", id: "npm-node-current", roles: ["current"], runtime: "node", runtimeVersion: "26.7.0", version: "12.0.2" },
    { client: "bun", id: "bun-minimum", roles: ["minimum"], runtime: null, runtimeVersion: null, version: "1.3.14" },
    { client: "bun", id: "bun-current", roles: ["current"], runtime: null, runtimeVersion: null, version: "1.4.0" },
    { client: "deno", id: "deno-minimum-current", roles: ["minimum", "current"], runtime: null, runtimeVersion: null, version: "2.9.5" },
  ]);
  const profileIds = new Set();
  for (const profile of fixture.clientProfiles) {
    exactKeys(profile, ["client", "id", "roles", "runtime", "runtimeVersion", "version"], profile.id);
    validateId(profile, profileIds);
    assert.ok(["cargo", "npm", "bun", "deno"].includes(profile.client));
    assert.ok(profile.roles.length > 0 && profile.roles.every((role) => role === "minimum" || role === "current"));
  }
});

test("client defaults close metadata authority and configuration overrides", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "client configuration fixture");
  assert.deepEqual(fixture.policy, {
    approvedMetadataAuthorities: ["sparse+https://rust.pkg.re/", "https://js.pkg.re/"],
    archiveDelivery: "integrity-bound redirects from canonical registry archive routes are allowed; redirect destinations never become metadata authorities",
    cargo: {
      cratesIoFallback: "replace crates-io with the committed empty project/.cargo/disabled-crates-io directory; never replace it with pkgre",
      dependencyDeclaration: "every registry dependency explicitly sets registry = \"pkgre\" and an exact version",
      registryAlias: "pkgre",
    },
    configurationFiles: fixture.artifacts.map(({ path }) => path),
    javascript: {
      allowedDependencySpecifier: "one exact canonical registry version",
      deniedDependencySpecifiers: ["semver range", "dist-tag", "npm alias", "Git", "HTTP(S) URL", "file", "directory", "workspace", "JSR"],
      deniedMetadataAuthorities: ["https://registry.npmjs.org/", "https://registry.yarnpkg.com/", "https://jsr.io/", "scope-specific registry override"],
      lifecyclePolicy: "package lifecycle scripts are rejected during admission and disabled during npm installation",
      lockPolicy: "committed lockfiles are required for frozen installs and warm-cache replay",
    },
    npmConfiguration: "project/.npmrc options are normative for npm; only registry is assumed effective for Bun and Deno; all other behavior is D5 observation",
    sourceEnforcement: "validate every declaration against sourceCases before invoking a package client; outbound isolation is defense in depth, not the primary denied-source boundary",
  });
  assert.deepEqual(fixture.executionEnvelope, {
    forbiddenConfigurationFiles: ["bunfig.toml", "deno.json", "deno.jsonc"],
    forbiddenOverrides: ["Cargo --config", "Cargo registry/source environment variables", "NPM_CONFIG_REGISTRY", "BUN_CONFIG_REGISTRY", "client command-line registry override", "parent, user, or global .npmrc"],
    isolation: ["clean HOME", "clean XDG_CONFIG_HOME", "clean client cache", "outbound destination capture", "OS-enforced zero egress except the fixture registry when a scenario requires it"],
    poisonedOverrideProbe: "each harness must prove a disallowed inherited override is detected or removed before client invocation",
  });
  for (const name of fixture.executionEnvelope.forbiddenConfigurationFiles) {
    await assert.rejects(stat(new URL(`project/${name}`, fixtureRoot)), { code: "ENOENT" });
  }

  assert.deepEqual(fixture.clientOptionMatrix, [
    { client: "npm", effectiveProjectOptions: ["allow-directory", "allow-file", "allow-git", "allow-remote", "audit", "fund", "ignore-scripts", "registry", "replace-registry-host", "save-exact", "strict-ssl", "update-notifier"], observedOnlyOptions: [] },
    { client: "bun", effectiveProjectOptions: ["registry"], observedOnlyOptions: ["all other project .npmrc options"] },
    { client: "deno", effectiveProjectOptions: ["registry"], observedOnlyOptions: ["all other project .npmrc options"] },
  ]);
  assert.deepEqual(fixture.cacheReplayModes, [
    { client: "cargo", clientFlags: ["--frozen", "--offline"], networkEnforcement: "client cache-only mode plus OS-enforced zero egress", requireSuccess: true },
    { client: "npm", clientFlags: ["ci", "--offline"], networkEnforcement: "client cache-only mode plus OS-enforced zero egress", requireSuccess: true },
    { client: "bun", clientFlags: ["install", "--frozen-lockfile"], networkEnforcement: "OS-enforced zero egress; pinned Bun versions have no reliable offline mode", requireSuccess: true },
    { client: "deno", clientFlags: ["install", "--frozen", "--cached-only"], networkEnforcement: "client cache-only mode plus OS-enforced zero egress", requireSuccess: true },
  ]);
});

test("denied source and lifecycle cases are closed before client invocation", async () => {
  const fixture = parseCanonicalJson(await readFile(fixtureUrl, "utf8"), "client configuration fixture");
  const ids = new Set();
  const expectedDenied = {
    clientInvocation: "forbidden",
    decision: "reject-before-client",
    foreignNetworkRequests: 0,
    gitProcesses: 0,
    lifecycleSentinelCreated: false,
  };
  const expectedKinds = new Set(["semver-range", "dist-tag", "npm-alias", "git", "remote-url", "file", "directory", "workspace", "jsr", "foreign-registry", "path"]);
  const seenKinds = new Set();
  for (const record of fixture.sourceCases) {
    exactKeys(record, ["clients", "declaration", "ecosystem", "expected", "id", "sourceKind"], record.id);
    validateId(record, ids);
    assert.deepEqual(record.expected, expectedDenied, record.id);
    assert.equal(sourceAllowed(record), false, record.id);
    seenKinds.add(record.sourceKind);
    if (record.ecosystem === "javascript") assert.deepEqual(record.clients, ["npm", "bun", "deno"]);
    else assert.deepEqual(record.clients, ["cargo"]);
  }
  assert.deepEqual(seenKinds, expectedKinds);
  assert.equal(fixture.sourceCases.length, 13);

  assert.equal(fixture.lifecycleCases.length, 1);
  const lifecycle = fixture.lifecycleCases[0];
  exactKeys(lifecycle, ["clients", "declaration", "expected", "id"], lifecycle.id);
  validateId(lifecycle, ids);
  assert.deepEqual(lifecycle.clients, ["npm", "bun", "deno"]);
  assert.deepEqual(lifecycle.declaration, { field: "scripts.preinstall", value: "touch pkgre-lifecycle-sentinel" });
  assert.deepEqual(lifecycle.expected, {
    admission: "reject",
    hostileClientFixture: "if admission is deliberately bypassed, disable lifecycle scripts and require zero sentinel execution",
    lifecycleSentinelCreated: false,
  });
});

test("profile declarations match project and Nix pins", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.engines.node, ">=24.15.0");
  assert.equal(packageJson.engines.npm, ">=12.0.2");
  assert.equal(packageJson.packageManager, "npm@12.0.2");
  const nix = await readFile(new URL("../../nix/js-compatibility-clients.nix", import.meta.url), "utf8");
  for (const declaration of [
    'npmVersion = "12.0.2";',
    'nodeVersion = "24.15.0";',
    'nodeVersion = "26.7.0";',
    'version = "1.3.14";',
    'version = "1.4.0";',
    'version = "2.9.5";',
    "denoCurrent = denoMinimum;",
  ]) assert.ok(nix.includes(declaration), declaration);
});
