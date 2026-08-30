import { Buffer } from "node:buffer";

export const TRUSTED_ORIGINAL_URI_HEADER = "X-Pkgre-Original-URI";
export const MAX_TRUSTED_TARGET_BYTES = 1024;

function validTargetEnvelope(target) {
  return target.length > 0
    && target.length <= MAX_TRUSTED_TARGET_BYTES
    && target[0] === 0x2f
    && target.every((byte) => byte <= 0x7f
      && byte !== 0x23
      && byte !== 0x20
      && byte !== 0x7f
      && !(byte <= 0x1f));
}

/**
 * Authenticates a raw backend request target against a closed edge-owned header envelope.
 * Callers must pass Node's request.rawHeaders rather than the merged request.headers view.
 * @param {Uint8Array} backendTarget
 * @param {string[]} rawHeaders
 * @param {string} configuredAuthority
 * @returns {Buffer | undefined}
 */
export function trustedRequestTarget(backendTarget, rawHeaders, configuredAuthority) {
  if (!(backendTarget instanceof Uint8Array)) throw new TypeError("backend target must be a Uint8Array");
  if (!Array.isArray(rawHeaders) || !rawHeaders.every((value) => typeof value === "string")) {
    throw new TypeError("raw headers must be a string array");
  }
  if (typeof configuredAuthority !== "string") throw new TypeError("configured authority must be a string");
  const target = Buffer.from(backendTarget.buffer, backendTarget.byteOffset, backendTarget.byteLength);
  if (!validTargetEnvelope(target) || rawHeaders.length !== 4) return undefined;

  let host;
  let trusted;
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase();
    const value = rawHeaders[index + 1];
    if (name === "host") {
      if (host !== undefined) return undefined;
      host = value;
    } else if (name === TRUSTED_ORIGINAL_URI_HEADER.toLowerCase()) {
      if (trusted !== undefined) return undefined;
      trusted = Buffer.from(value, "latin1");
    } else return undefined;
  }
  return host === configuredAuthority && trusted?.equals(target) ? target : undefined;
}
