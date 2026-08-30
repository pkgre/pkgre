import { Blob, Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { canonicalRequestTarget } from "./request-target.js";

export const ALLOW_METHODS = "GET, HEAD";
export const CACHE_CONTROL_NO_STORE = "no-store";
export const CACHE_CONTROL_METADATA = "public, max-age=60, must-revalidate";
export const CACHE_CONTROL_ARCHIVE = "public, max-age=31536000, immutable";
export const CONTENT_TYPE_METADATA_JSON = "application/json; charset=utf-8";
export const CONTENT_TYPE_METADATA_TEXT = "text/plain; charset=utf-8";
export const CONTENT_TYPE_ARCHIVE = "application/octet-stream";

/** @typedef {Readonly<Record<string, string>>} ResponseHeaders */
/** @typedef {{ body?: Blob, headers: ResponseHeaders, status: number }} ApplicationResponse */
/** @typedef {{ get: ApplicationResponse, head: ApplicationResponse }} PreparedResponse */

function frozenHeaders(entries) {
  return Object.freeze(Object.fromEntries(entries));
}

function frozenResponse(status, headers, body) {
  const response = body === undefined ? { headers, status } : { body, headers, status };
  return Object.freeze(response);
}

const BAD_REQUEST = frozenResponse(400, frozenHeaders([
  ["Cache-Control", CACHE_CONTROL_NO_STORE],
  ["Content-Length", "0"],
]));
const NOT_FOUND = frozenResponse(404, frozenHeaders([
  ["Cache-Control", CACHE_CONTROL_NO_STORE],
  ["Content-Length", "0"],
]));
const METHOD_NOT_ALLOWED = frozenResponse(405, frozenHeaders([
  ["Allow", ALLOW_METHODS],
  ["Cache-Control", CACHE_CONTROL_NO_STORE],
  ["Content-Length", "0"],
]));

function bodyPolicy(response) {
  if (!(response.body instanceof Blob)) throw new Error("projected body response requires a Blob");
  if (response.type === "inline" && response.representation === "metadata-json") {
    return [CACHE_CONTROL_METADATA, CONTENT_TYPE_METADATA_JSON];
  }
  if (response.type === "inline" && response.representation === "metadata-text") {
    return [CACHE_CONTROL_METADATA, CONTENT_TYPE_METADATA_TEXT];
  }
  if (response.type === "archive" && response.representation === "archive") {
    return [CACHE_CONTROL_ARCHIVE, CONTENT_TYPE_ARCHIVE];
  }
  throw new Error("projected body response has an invalid representation");
}

async function bodySha256(body) {
  return createHash("sha256").update(Buffer.from(await body.arrayBuffer())).digest("hex");
}

/**
 * Precomputes immutable GET and HEAD descriptors from one projected response.
 * @param {object} response
 * @returns {Promise<PreparedResponse>}
 */
export async function prepareResponse(response) {
  if (response === null || typeof response !== "object") throw new TypeError("projected response must be an object");
  if (response.type === "redirect") {
    if (typeof response.location !== "string" || !response.location.length) throw new Error("projected redirect requires a location");
    const descriptor = frozenResponse(302, frozenHeaders([
      ["Cache-Control", CACHE_CONTROL_NO_STORE],
      ["Content-Length", "0"],
      ["Location", response.location],
    ]));
    return Object.freeze({ get: descriptor, head: descriptor });
  }

  const [cacheControl, contentType] = bodyPolicy(response);
  const sha256 = await bodySha256(response.body);
  if (response.type === "archive" && response.sha256 !== undefined && response.sha256 !== sha256) {
    throw new Error("projected archive SHA-256 does not match its body");
  }
  Object.freeze(response.body);
  const headers = frozenHeaders([
    ["Cache-Control", cacheControl],
    ["Content-Length", response.body.size.toString()],
    ["Content-Type", contentType],
    ["ETag", `"sha256:${sha256}"`],
  ]);
  return Object.freeze({
    get: frozenResponse(200, headers, response.body),
    head: frozenResponse(200, headers),
  });
}

/**
 * Applies raw-target, method, and exact-route policy in that precedence order.
 * Request headers are ignored: v1 performs no range/content-coding transformation.
 * @param {Uint8Array} rawTarget
 * @param {string} method
 * @param {object | Map<string, string> | undefined} _requestHeaders
 * @param {Map<string, PreparedResponse>} routes
 * @returns {ApplicationResponse}
 */
export function evaluateRequest(rawTarget, method, _requestHeaders, routes) {
  const target = canonicalRequestTarget(rawTarget);
  if (target === undefined) return BAD_REQUEST;
  if (method !== "GET" && method !== "HEAD") return METHOD_NOT_ALLOWED;
  if (!(routes instanceof Map)) throw new TypeError("prepared routes must be a Map");
  const route = routes.get(target);
  if (route === undefined) return NOT_FOUND;
  return method === "HEAD" ? route.head : route.get;
}
