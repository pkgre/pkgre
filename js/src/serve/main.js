#!/usr/bin/env node

import http from "node:http";
import process from "node:process";

import { USAGE, loadConfig, resolveArguments } from "./config.js";
import { buildServeSnapshot, loadCatalog } from "./snapshot.js";
import {
  adminRequestHandler,
  createShared,
  installSnapshot,
  publicRequestHandler,
} from "./web.js";
import { AcceptedRefWatcher } from "./watcher.js";

function errorMessage(error) {
  return error instanceof Error ? error.message : "unknown operational failure";
}

function listen(server, { host, port }) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    server.closeIdleConnections();
    server.close(() => resolve());
  });
}

function stopSignal() {
  return new Promise((resolve) => {
    process.once("SIGTERM", resolve);
    process.once("SIGINT", resolve);
  });
}

async function serve(config) {
  const shared = createShared({
    delivery: config.registry.delivery,
    maxConcurrency: config.limits.maxConcurrency,
  });
  let watcher = null;
  let pollTimer = undefined;
  let source;
  if (config.watcher === null) {
    // Build the snapshot before binding: fail fast, no silent fallback.
    const catalog = loadCatalog(config.registry.catalog);
    const snapshot = await buildServeSnapshot(catalog, config.registry.archiveStore, config.registry.delivery);
    installSnapshot(shared, snapshot);
    source = config.registry.catalog;
  } else {
    // The watcher publishes its own first snapshot before any listener binds.
    watcher = new AcceptedRefWatcher(config.watcher, {
      archiveStore: config.registry.archiveStore,
      delivery: config.registry.delivery,
      shared,
    });
    await watcher.startup();
    pollTimer = setInterval(() => {
      watcher.pollOnce().catch((error) => {
        process.stderr.write(`error: watcher poll failed: ${errorMessage(error)}\n`);
      });
    }, config.watcher.pollIntervalSeconds * 1000);
    source = `${config.watcher.origin}#${config.watcher.repository.fullRef}`;
  }

  const publicServer = http.createServer(publicRequestHandler(shared));
  const adminServer = http.createServer(adminRequestHandler(shared));
  await listen(publicServer, config.public);
  await listen(adminServer, config.admin);
  process.stderr.write(
    `ok pkgre-js-serve delivery=${config.registry.delivery}`
      + ` public=${config.public.host}:${config.public.port}`
      + ` admin=${config.admin.host}:${config.admin.port}`
      + ` source=${source}`
      + ` routes=${shared.snapshot === null ? 0 : shared.snapshot.routes.size}\n`,
  );

  await stopSignal();
  if (pollTimer !== undefined) clearInterval(pollTimer);
  await Promise.all([closeServer(publicServer), closeServer(adminServer)]);
}

const resolved = resolveArguments(process.argv.slice(2));
if (resolved.kind === "help") {
  process.stdout.write(`${USAGE}\n`);
} else if (resolved.kind === "usage") {
  process.stderr.write(`error: ${resolved.message}\n${USAGE}\n`);
  process.exitCode = 2;
} else {
  try {
    await serve(loadConfig(resolved.path));
  } catch (error) {
    process.stderr.write(`error: ${errorMessage(error)}\n`);
    process.exitCode = 1;
  }
}

