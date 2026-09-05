import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { validateCatalog } from "../catalog.js";
import { prepareResponse } from "../http-response.js";
import { jsArchiveRoute, jsRedirectDestination } from "../marker.js";
import { renderPackument } from "../packument.js";
import { packageMetadataRoute } from "../projection.js";

export const SERVE_DELIVERY_MODES = ["redirect", "body"];

/**
 * Reads and parses one catalog file for serving.
 * @param {string} catalogPath
 * @returns {object} parsed catalog (validated by buildServeSnapshot)
 */
export function loadCatalog(catalogPath) {
  let text;
  try {
    text = readFileSync(catalogPath, "utf8");
  } catch (error) {
    throw new Error(`read serving catalog ${catalogPath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`parse serving catalog ${catalogPath}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Reads one content-addressed archive body and digest-verifies it.
 * Any absence or mismatch fails the whole snapshot closed.
 */
function storeArchive(storePath, sha256, label) {
  const file = typeof storePath === "string" ? path.join(storePath, `${sha256}.tgz`) : `<no archive-store>/${sha256}.tgz`;
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch {
    throw new Error(`serving snapshot body is absent for ${label} at ${file}`);
  }
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== sha256) throw new Error(`serving snapshot body digest mismatch for ${label} at ${file}`);
  return bytes;
}

function frozenArchiveBody(bytes) {
  return Object.freeze(new Blob([bytes]));
}

/**
 * Builds the immutable serving snapshot for one delivery mode.
 *
 * redirect: packuments inline, /v1/js/main/<sha> redirects as projected, and
 * first-party /packages/<sha>.tgz archive bodies read from the store.
 * body: every /v1/js/main/<sha> redirect converts to a local digest-verified
 * archive body; ANY missing or mismatched body fails the whole snapshot.
 * @param {object} catalog validated catalog
 * @param {string | null} storePath content-addressed archive-store directory
 * @param {"redirect" | "body"} delivery
 * @param {string} [sourceCommit] watched source commit pin for the index page
 * @returns {Promise<object>} frozen snapshot {counts, delivery, routes, sourceCommit}
 */
export async function buildServeSnapshot(catalog, storePath, delivery, sourceCommit = "") {
  if (!SERVE_DELIVERY_MODES.includes(delivery)) throw new Error(`unknown serving delivery mode ${delivery}`);
  if (delivery === "body" && typeof storePath !== "string") throw new Error('serving delivery "body" requires an archive store');
  if (typeof sourceCommit !== "string") throw new Error("serving snapshot sourceCommit must be a string");
  validateCatalog(catalog);
  const projected = [];
  const paths = new Set();
  const add = (route, response) => {
    if (paths.has(route)) throw new Error(`serving snapshot repeats route ${route}`);
    paths.add(route);
    projected.push([route, response]);
  };

  for (const entry of catalog.packages) {
    add(packageMetadataRoute(entry.name), {
      body: frozenArchiveBody(renderPackument(catalog, entry)),
      representation: "metadata-json",
      type: "inline",
    });
    for (const record of entry.versions) {
      const { sha256 } = record.source;
      const label = `${entry.name}@${record.version}`;
      if (delivery === "redirect") {
        add(jsArchiveRoute(sha256), Object.freeze({ ...jsRedirectDestination(entry.name, record), type: "redirect" }));
        if (record.source.kind === "first-party") {
          add(`/packages/${sha256}.tgz`, {
            body: frozenArchiveBody(storeArchive(storePath, sha256, label)),
            representation: "archive",
            sha256,
            type: "archive",
          });
        }
      } else {
        const bytes = storeArchive(storePath, sha256, label);
        add(jsArchiveRoute(sha256), {
          body: frozenArchiveBody(bytes),
          representation: "archive",
          sha256,
          type: "archive",
        });
        if (record.source.kind === "first-party") {
          add(`/packages/${sha256}.tgz`, {
            body: frozenArchiveBody(bytes),
            representation: "archive",
            sha256,
            type: "archive",
          });
        }
      }
    }
  }

  const routes = new Map();
  const counts = { archive: 0, inline: 0, redirect: 0 };
  for (const [route, response] of projected) {
    routes.set(route, await prepareResponse(response));
    counts[response.type] += 1;
  }
  return Object.freeze({
    counts: Object.freeze(counts),
    delivery,
    routes: Object.freeze(routes),
    sourceCommit,
  });
}
