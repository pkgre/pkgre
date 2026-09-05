import { Buffer } from "node:buffer";

export const MAX_REQUEST_TARGET_BYTES = 1024;
const MAX_JS_PACKAGE_BYTES = 214;

function validGenericPathByte(byte) {
  return (byte >= 0x30 && byte <= 0x39)
    || (byte >= 0x41 && byte <= 0x5a)
    || (byte >= 0x61 && byte <= 0x7a)
    || [0x2f, 0x2e, 0x5f, 0x7e, 0x2b, 0x40, 0x2d].includes(byte);
}

function validJsComponent(component) {
  if (!component.length || component[0] < 0x61 || component[0] > 0x7a) return false;
  return component.subarray(1).every((byte) => (byte >= 0x61 && byte <= 0x7a)
    || (byte >= 0x30 && byte <= 0x39)
    || [0x2e, 0x5f, 0x7e, 0x2d].includes(byte));
}

function encodedSlashOffset(bytes) {
  for (let index = 0; index + 2 < bytes.length; index += 1) {
    if (bytes[index] === 0x25 && bytes[index + 1] === 0x32 && bytes[index + 2] === 0x66) return index;
  }
  return -1;
}

function validScopedJsMetadataTarget(bytes) {
  const encodedName = bytes.subarray(2);
  const separator = encodedSlashOffset(encodedName);
  if (separator < 0 || encodedSlashOffset(encodedName.subarray(separator + 3)) >= 0) return false;
  return bytes.length - 3 <= MAX_JS_PACKAGE_BYTES
    && validJsComponent(encodedName.subarray(0, separator))
    && validJsComponent(encodedName.subarray(separator + 3));
}

/**
 * Validates raw request-target bytes without decoding or normalization.
 * @param {Uint8Array} raw
 * @returns {string | undefined}
 */
export function canonicalRequestTarget(raw) {
  if (!(raw instanceof Uint8Array)) throw new TypeError("raw request target must be a Uint8Array");
  const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  if (!bytes.length || bytes.length > MAX_REQUEST_TARGET_BYTES || bytes[0] !== 0x2f || bytes.some((byte) => byte > 0x7f)) return undefined;
  if (bytes.length === 1) return "/";
  if (bytes.at(-1) === 0x2f) return undefined;

  let segmentStart = 1;
  for (let index = 1; index <= bytes.length; index += 1) {
    if (index !== bytes.length && bytes[index] !== 0x2f) continue;
    const segment = bytes.subarray(segmentStart, index);
    if (!segment.length || segment.equals(Buffer.from(".")) || segment.equals(Buffer.from(".."))) return undefined;
    segmentStart = index + 1;
  }

  const valid = bytes[1] === 0x40
    ? validScopedJsMetadataTarget(bytes)
    : !bytes.includes(0x25) && bytes.subarray(1).every(validGenericPathByte);
  return valid ? bytes.toString("ascii") : undefined;
}
