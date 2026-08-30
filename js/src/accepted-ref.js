import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import { canonicalJson, parseCanonicalJson } from "./canonical.js";

export const ACCEPTED_REF_SCHEMA = "pkgre-accepted-ref-v1";
const COMMIT = /^[0-9a-f]{40}$/;
const IDENTITY = /^[0-9a-f]{64}$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const canonicalExpected = [...expected].sort();
  if (actual.length !== canonicalExpected.length || actual.some((key, index) => key !== canonicalExpected[index])) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function validFullRef(value) {
  if (typeof value !== "string" || !value.startsWith("refs/") || value.length === "refs/".length) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code > 0x7f || code <= 0x20 || code === 0x7f) return false;
  }
  return true;
}

function validateConfig(config) {
  exactKeys(config, ["fullRef", "repositoryIdentity"], "accepted-ref configuration");
  if (!validFullRef(config.fullRef) || !IDENTITY.test(config.repositoryIdentity)) {
    throw new Error("invalid accepted-ref configuration");
  }
}

function validateRecord(record) {
  exactKeys(record, ["acceptedCommit", "fullRef", "repositoryIdentity", "schema"], "accepted-ref record");
  if (record.schema !== ACCEPTED_REF_SCHEMA) throw new Error("unsupported accepted-ref schema");
  if (!COMMIT.test(record.acceptedCommit)) throw new Error("accepted commit must be 40 lowercase hexadecimal characters");
  if (!validFullRef(record.fullRef)) throw new Error("accepted full ref is invalid");
  if (!IDENTITY.test(record.repositoryIdentity)) throw new Error("repository identity must be 64 lowercase hexadecimal characters");
}

function checkedRecord(record, config) {
  validateRecord(record);
  validateConfig(config);
  if (record.repositoryIdentity !== config.repositoryIdentity) throw new Error("accepted repository identity does not match configuration");
  if (record.fullRef !== config.fullRef) throw new Error("accepted full ref does not match configuration");
  return Object.freeze({ ...record });
}

function framedLength(length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > 0xffffffff) throw new Error("repository identity input is too large");
  const result = Buffer.alloc(4);
  result.writeUInt32BE(length);
  return result;
}

/** Derives a repository identity from already-canonical, credential-free byte strings. */
export function deriveRepositoryIdentity(originBytes, fullRefBytes) {
  if (!(originBytes instanceof Uint8Array) || !(fullRefBytes instanceof Uint8Array)) {
    throw new TypeError("repository identity inputs must be Uint8Array values");
  }
  const origin = Buffer.from(originBytes.buffer, originBytes.byteOffset, originBytes.byteLength);
  const fullRef = Buffer.from(fullRefBytes.buffer, fullRefBytes.byteOffset, fullRefBytes.byteLength);
  return createHash("sha256")
    .update(Buffer.from("pkgre-repository-identity-v1\0", "ascii"))
    .update(framedLength(origin.length))
    .update(origin)
    .update(framedLength(fullRef.length))
    .update(fullRef)
    .digest("hex");
}

/** Parses exact canonical accepted-ref bytes and binds them to fixed configuration. */
export function parseAcceptedRef(bytes, config) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("accepted-ref bytes must be a Uint8Array");
  let text;
  try {
    text = UTF8.decode(bytes);
  } catch {
    throw new Error("accepted-ref record is not UTF-8");
  }
  return checkedRecord(parseCanonicalJson(text, "accepted-ref record"), config);
}

/** Returns canonical UTF-8 bytes for one validated accepted-ref record. */
export function canonicalAcceptedRefBytes(record, config) {
  return Buffer.from(canonicalJson(checkedRecord(record, config)), "utf8");
}

function outcome(decision, reason, acceptedCommit, activeCommit, persistRecord, candidateLoad = undefined) {
  const value = { acceptedCommit, activeCommit };
  if (candidateLoad !== undefined) value.candidateLoad = candidateLoad;
  value.decision = decision;
  value.persistRecord = persistRecord;
  value.reason = reason;
  return Object.freeze(value);
}

/** Evaluates restart/bootstrap authority without consulting a remote ref. */
export function evaluateAcceptedRefStartup(input, config) {
  validateConfig(config);
  if (input.acceptedRecordState === "malformed") {
    return outcome("fail-startup", "accepted-record-malformed", null, null, false);
  }
  if (input.acceptedRecordState === "absent") {
    if (input.bootstrapObject === "valid" && COMMIT.test(input.bootstrapCommit)) {
      return outcome("bootstrap", "accepted-record-absent", input.bootstrapCommit, input.bootstrapCommit, true);
    }
    const reason = input.bootstrapObject === "missing" ? "bootstrap-object-unavailable" : "bootstrap-object-invalid";
    return outcome("fail-startup", reason, null, null, false);
  }
  if (input.acceptedRecordState !== "present") throw new Error("unknown accepted-record state");

  try {
    validateRecord(input.acceptedRecord);
  } catch {
    return outcome("fail-startup", "accepted-record-malformed", null, null, false);
  }
  if (input.acceptedRecord.repositoryIdentity !== config.repositoryIdentity) {
    return outcome("fail-startup", "repository-identity-mismatch", null, null, false);
  }
  if (input.acceptedRecord.fullRef !== config.fullRef) {
    return outcome("fail-startup", "full-ref-mismatch", null, null, false);
  }
  const record = Object.freeze({ ...input.acceptedRecord });
  if (input.localAcceptedObject !== "valid") {
    const reason = input.localAcceptedObject === "missing" ? "accepted-object-unavailable" : "accepted-object-invalid";
    return outcome("fail-startup", reason, record.acceptedCommit, null, false);
  }
  return outcome("start-accepted", "accepted-record-authority", record.acceptedCommit, record.acceptedCommit, false);
}

/** Evaluates a supplied reload observation while preserving the current LKG on every rejection. */
export function evaluateAcceptedRefReload(acceptedRecord, candidate, config) {
  const accepted = checkedRecord(acceptedRecord, config).acceptedCommit;
  const retain = (reason, candidateLoad = false) => outcome("retain-accepted", reason, accepted, accepted, false, candidateLoad);
  if (candidate === null) return retain("remote-unavailable");
  if (candidate.repositoryIdentity !== config.repositoryIdentity) return retain("repository-identity-mismatch");
  if (candidate.fullRef !== config.fullRef) return retain("full-ref-mismatch");
  if (!COMMIT.test(candidate.commit) || candidate.objectState === "malformed") return retain("candidate-commit-malformed");
  if (candidate.suppressed) return retain("rejected-hash-suppressed");
  if (candidate.objectState !== "valid") return retain("candidate-object-unavailable");
  if (candidate.commit === accepted) {
    return outcome("unchanged", "candidate-equals-accepted", accepted, accepted, false, false);
  }
  if (["predecessor", "divergent"].includes(candidate.ancestry)) return retain("candidate-not-descendant");
  if (candidate.ancestry === "unknown") return retain("candidate-ancestry-unknown");
  if (candidate.ancestry !== "descendant") throw new Error("reload candidate has inconsistent ancestry");
  if (candidate.semanticValidity === "invalid") return retain("semantic-validation-failed", true);
  if (candidate.semanticValidity !== "valid") throw new Error("reload candidate semantic validity was not evaluated");
  if (candidate.persistence === "interrupted-before-rename") return retain("durable-persistence-failed", true);
  if (candidate.persistence !== "success") throw new Error("valid reload candidate persistence was not attempted");
  return outcome("accept-forward", "valid-forward-candidate", candidate.commit, candidate.commit, true, true);
}
