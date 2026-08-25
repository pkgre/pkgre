import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { USAGE, run } from "../src/cli.js";

const main = fileURLToPath(new URL("../src/main.js", import.meta.url));

test("help is the only accepted skeleton command", () => {
  assert.deepEqual(run(["--help"]), { status: 0, output: `${USAGE}\n` });
  assert.deepEqual(run(["-h"]), { status: 0, output: `${USAGE}\n` });
  assert.deepEqual(run([]), { status: 1, output: `${USAGE}\n` });
  assert.deepEqual(run(["unknown"]), { status: 1, output: `${USAGE}\n` });
});

test("executable reports deterministic help", () => {
  const result = spawnSync(process.execPath, [main, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, `${USAGE}\n`);
});
