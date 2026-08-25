#!/usr/bin/env node

import process from "node:process";

import { run } from "./cli.js";

const result = run(process.argv.slice(2));
process.stderr.write(result.output);
process.exitCode = result.status;
