import {
  CACHE_CONTROL_NO_STORE,
  CONTENT_TYPE_METADATA_JSON,
  evaluateRequest,
} from "../http-response.js";

export const ORIGINAL_URI_HEADER = "x-pkgre-original-uri";
const MAX_LOGGED_TARGET_BYTES = 160;
const EMPTY_HEADERS = Object.freeze({ "Cache-Control": CACHE_CONTROL_NO_STORE, "Content-Length": "0" });
const NOT_FOUND_RESPONSE = Object.freeze({ headers: EMPTY_HEADERS, status: 404 });
const UNAVAILABLE_RESPONSE = Object.freeze({ headers: EMPTY_HEADERS, status: 503 });

class Semaphore {
  constructor(permits) {
    this.inUse = 0;
    this.permits = permits;
    this.waiting = [];
  }

  acquire() {
    if (this.inUse < this.permits) {
      this.inUse += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.waiting.push(resolve));
  }

  release() {
    const next = this.waiting.shift();
    if (next) next();
    else this.inUse -= 1;
  }
}

/**
 * Creates the shared serving state with an unready (absent) snapshot.
 * @param {{delivery: "redirect" | "body", maxConcurrency: number}} options
 * @returns {object}
 */
export function createShared({ delivery, maxConcurrency }) {
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new Error("shared serving state requires a positive integer maxConcurrency");
  }
  return { delivery, semaphore: new Semaphore(maxConcurrency), snapshot: null, startedAt: Date.now() };
}

/**
 * Atomically publishes one snapshot; later swaps replace it wholesale (D4 watcher).
 * @param {object} shared
 * @param {object | null} snapshot
 */
export function installSnapshot(shared, snapshot) {
  if (snapshot !== null && !(snapshot.routes instanceof Map)) throw new Error("serving snapshot routes must be a Map");
  shared.snapshot = snapshot;
}

export function isReady(shared) {
  return shared.snapshot !== null;
}

export function uptimeSeconds(shared) {
  return Math.floor((Date.now() - shared.startedAt) / 1000);
}

/**
 * Frozen admin /status document: counts stay null until the snapshot is ready.
 * @param {object} shared
 * @returns {object}
 */
export function statusReport(shared) {
  const snapshot = shared.snapshot;
  return Object.freeze({
    counts: snapshot === null ? null : snapshot.counts,
    mode: shared.delivery,
    ready: snapshot !== null,
    schema: 1,
    uptimeSeconds: uptimeSeconds(shared),
  });
}

/**
 * Raw request target: exactly one trusted x-pkgre-original-uri header, else the
 * request-line target; duplicates and absent targets yield undefined (404).
 * @param {import("node:http").IncomingMessage} req
 * @returns {Buffer | undefined}
 */
function requestTarget(req) {
  let trusted;
  const rawHeaders = req.rawHeaders;
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index].toLowerCase() !== ORIGINAL_URI_HEADER) continue;
    if (trusted !== undefined) return undefined;
    trusted = Buffer.from(rawHeaders[index + 1], "latin1");
  }
  if (trusted !== undefined) return trusted;
  return typeof req.url === "string" ? Buffer.from(req.url, "latin1") : undefined;
}

function methodNotAllowed(allow) {
  return Object.freeze({
    headers: Object.freeze({ Allow: allow, "Cache-Control": CACHE_CONTROL_NO_STORE, "Content-Length": "0" }),
    status: 405,
  });
}

async function writeApplicationResponse(res, method, response) {
  res.once("error", () => {});
  for (const [name, value] of Object.entries(response.headers)) res.setHeader(name, value);
  res.statusCode = response.status;
  if (method === "HEAD" || response.body === undefined) {
    res.end();
    return;
  }
  res.end(Buffer.from(await response.body.arrayBuffer()));
}

function logDispatch(req, status, startedAt, target) {
  const truncated = target === undefined
    ? "-"
    : target.length > MAX_LOGGED_TARGET_BYTES
    ? `${target.subarray(0, MAX_LOGGED_TARGET_BYTES).toString("latin1")}...`
    : target.toString("latin1");
  const durationMs = Math.round((Number(process.hrtime.bigint() - startedAt) / 1e6) * 1000) / 1000;
  process.stderr.write(`${JSON.stringify({ durationMs, method: req.method ?? "-", status, target: truncated })}\n`);
}

async function dispatchPublic(shared, req, res) {
  const startedAt = process.hrtime.bigint();
  const target = requestTarget(req);
  let response;
  if (target === undefined) {
    response = NOT_FOUND_RESPONSE;
  } else if (!isReady(shared)) {
    response = UNAVAILABLE_RESPONSE;
  } else {
    await shared.semaphore.acquire();
    try {
      response = evaluateRequest(target, req.method, req.headers, shared.snapshot.routes);
    } finally {
      shared.semaphore.release();
    }
  }
  await writeApplicationResponse(res, req.method, response);
  logDispatch(req, res.statusCode, startedAt, target);
}

/**
 * Public application handler: raw-target policy dispatch over the live snapshot.
 * @param {object} shared
 * @returns {import("node:http").RequestListener}
 */
export function publicRequestHandler(shared) {
  return (req, res) => {
    dispatchPublic(shared, req, res);
  };
}

async function dispatchAdmin(shared, req, res) {
  const route = typeof req.url === "string" ? req.url : "";
  if (route === "/healthz" || route === "/readyz") {
    if (req.method !== "GET" && req.method !== "HEAD") {
      await writeApplicationResponse(res, req.method, methodNotAllowed("GET, HEAD"));
      return;
    }
    res.setHeader("Cache-Control", CACHE_CONTROL_NO_STORE);
    res.setHeader("Content-Length", "0");
    res.statusCode = route === "/readyz" && !isReady(shared) ? 503 : 200;
    res.end();
    return;
  }
  if (route === "/status") {
    if (req.method !== "GET") {
      await writeApplicationResponse(res, req.method, methodNotAllowed("GET"));
      return;
    }
    const body = Buffer.from(JSON.stringify(statusReport(shared)), "utf8");
    res.setHeader("Cache-Control", CACHE_CONTROL_NO_STORE);
    res.setHeader("Content-Type", CONTENT_TYPE_METADATA_JSON);
    res.setHeader("Content-Length", body.length.toString());
    res.statusCode = 200;
    res.end(body);
    return;
  }
  await writeApplicationResponse(res, req.method, NOT_FOUND_RESPONSE);
}

/**
 * Admin application handler: /healthz, /readyz, and GET-only /status.
 * @param {object} shared
 * @returns {import("node:http").RequestListener}
 */
export function adminRequestHandler(shared) {
  return (req, res) => {
    dispatchAdmin(shared, req, res);
  };
}
