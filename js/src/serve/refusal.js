/**
 * Failure codes, their classes, the retry schedule, and the pure classifiers of
 * one watcher refusal.
 *
 * Every refusal names what failed with one stable code, and every code belongs to
 * exactly one class: the candidate's own content or its relation to the accepted
 * commit, the host's state, or a failure that neither can be shown for. Only a
 * local failure may pass on a later attempt of the same commit, so only a local
 * one is retried; the candidate's and the unclassified ones stay suppressed.
 */

import { ArchiveStoreError } from "./snapshot.js";

/** Seconds of the first retry wait after one local failure. */
export const RETRY_BASE_SECONDS = 60;
/** Longest retry wait, in seconds. */
export const RETRY_MAX_SECONDS = 15 * 60;
/** Number of wait doublings before the wait reaches {@link RETRY_MAX_SECONDS}. */
const RETRY_DOUBLINGS = 4;

/**
 * Retry wait after the n-th consecutive local failure of one commit: 60, 120,
 * 240, 480, 900, 900, ... seconds. There is no limit on attempts.
 * @param {number} attempts failed evaluations of one commit, at least 1
 * @returns {number} seconds until the next attempt
 */
export function retryDelaySeconds(attempts) {
  const doublings = Math.min(Math.max(attempts - 1, 0), RETRY_DOUBLINGS);
  return Math.min(RETRY_BASE_SECONDS * 2 ** doublings, RETRY_MAX_SECONDS);
}

/** One failure code with the class it belongs to. */
function failure(code, failureClass) {
  return Object.freeze({ class: failureClass, code });
}

/** The tip is absent from the mirror after the fetch resolved it. */
export const OBJECT_UNAVAILABLE = failure("object-unavailable", "local");
/** The object probe cannot read the tip's object. */
export const OBJECT_UNREADABLE = failure("object-unreadable", "local");
/** The probed object is not a commit. */
export const NOT_A_COMMIT = failure("not-a-commit", "candidate");
/** The ancestry probe cannot answer. */
export const ANCESTRY_UNKNOWN = failure("ancestry-unknown", "local");
/** The tip is a predecessor of, or divergent from, the accepted commit. */
export const NOT_DESCENDANT = failure("not-descendant", "candidate");
/** The commit holds no catalog file at the configured path. */
export const CATALOG_PATH_INVALID = failure("catalog-path-invalid", "candidate");
/** A catalog file could not be materialized from the mirror. */
export const MATERIALIZATION_FAILED = failure("materialization-failed", "local");
/** The archive store lacks a body the snapshot needs, or holds another digest. */
export const ARCHIVE_STORE_INCOMPLETE = failure("archive-store-incomplete", "local");
/** The candidate's catalog is semantically invalid. */
export const SNAPSHOT_INVALID = failure("snapshot-invalid", "candidate");
/** The candidate's catalog file is not JSON. */
export const CANDIDATE_CATALOG_INVALID = failure("candidate-catalog-invalid", "candidate");
/** The accepted catalog cannot be loaded again, which it was before. */
export const ACCEPTED_CATALOG_UNLOADABLE = failure("accepted-catalog-unloadable", "local");
/** The accepted-ref record could not be written, fsynced or renamed. */
export const PERSISTENCE_FAILED = failure("persistence-failed", "local");
/** An internal failure that cannot safely be classified as retryable. */
export const INTERNAL_ERROR = failure("internal-error", "unclassified");

/**
 * Classifies one object probe answer.
 * @param {string} state "valid", "missing", "corrupt", "malformed" or "not-applicable"
 * @returns {{class: string, code: string} | null} failure, or null for a usable commit
 */
export function failureForObjectState(state) {
  switch (state) {
    case "missing":
      return OBJECT_UNAVAILABLE;
    case "corrupt":
      return OBJECT_UNREADABLE;
    case "malformed":
      return NOT_A_COMMIT;
    default:
      return null;
  }
}

/**
 * Classifies one ancestry answer.
 * @param {string} ancestry "descendant", "predecessor", "divergent", "unknown" or "not-evaluated"
 * @returns {{class: string, code: string} | null} failure, or null for a descendant
 */
export function failureForAncestry(ancestry) {
  switch (ancestry) {
    case "predecessor":
    case "divergent":
      return NOT_DESCENDANT;
    case "unknown":
      return ANCESTRY_UNKNOWN;
    default:
      return null;
  }
}

/**
 * Classifies one failed materialization of a catalog file.
 *
 * The accepted catalog materialized before, so every cause there is local. On the
 * candidate's side the probed entry decides: a regular blob that Git cannot show is
 * a local failure, while a path that holds no entry, or an entry that is not a
 * regular blob, is the commit's own; a blob above the output bound is the commit's
 * too, since its size is its content.
 * @param {{accepted: boolean, entry: string, error: Error}} observed
 *   `entry` is "missing", "blob" or "other"; `error` is the failed `git show`
 * @returns {{class: string, code: string}} classified failure
 */
export function failureForShowFailure({ accepted, entry, error }) {
  if (accepted) return MATERIALIZATION_FAILED;
  if (entry === "missing") return CATALOG_PATH_INVALID;
  if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return CANDIDATE_CATALOG_INVALID;
  return entry === "blob" ? MATERIALIZATION_FAILED : CATALOG_PATH_INVALID;
}

/**
 * Classifies catalog bytes that are not JSON.
 * @param {boolean} accepted whether the accepted side's catalog failed to parse
 * @returns {{class: string, code: string}} classified failure
 */
export function failureForCatalogParse(accepted) {
  return accepted ? ACCEPTED_CATALOG_UNLOADABLE : CANDIDATE_CATALOG_INVALID;
}

/**
 * Classifies one failed snapshot build of the candidate.
 *
 * An error of another class than `Error`, such as a `TypeError` or a `RangeError`,
 * is an internal failure: it is a programming error rather than a verdict on the
 * catalog, so it must not be retried either.
 * @param {unknown} error what `buildServeSnapshot` threw
 * @returns {{class: string, code: string}} classified failure
 */
export function failureForSnapshotError(error) {
  if (error instanceof ArchiveStoreError) return ARCHIVE_STORE_INCOMPLETE;
  if (error instanceof Error && error.constructor === Error) return SNAPSHOT_INVALID;
  return INTERNAL_ERROR;
}

/**
 * Whether a failure of this class may pass on a later attempt of the same commit.
 * @param {{class: string}} failed
 * @returns {boolean}
 */
export function isRetryable(failed) {
  return failed.class === "local";
}
