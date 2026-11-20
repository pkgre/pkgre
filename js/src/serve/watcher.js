// Accepted-ref watcher: fixed-ref polling with last-known-good serving snapshots.
//
// The watcher owns the accepted-ref record on disk, a bare Git mirror of the
// watched origin, and the shared serving snapshot. Every poll observes the
// remote tip once and applies the shared transition policy (accepted-ref.js):
// only strictly forward, semantically valid, durably persisted candidates are
// published, and a failed reload never changes the active snapshot or the
// accepted ref.
//
// Every refusal is classified by what failed. A refusal of the candidate's own
// content, or of its relation to the accepted commit, is suppressed by hash
// until the tip changes or the process restarts. A local failure, such as a
// full disk, a Git time-out, a failed fsync, a host read error or an
// incomplete archive store, is retried after 1, 2, 4 and 8 minutes and then
// every 15 minutes while the last-known-good snapshot keeps serving. A failure
// that cannot be classified is suppressed like the candidate's and reported as
// unclassified. Remote failures are not refusals: they report
// remote-unavailable and are tried again at every poll, without a backoff.
//
// Polls run one at a time: a poll requested while another runs returns the
// running poll's promise instead of starting a second evaluation.
//
// The watcher publishes its view of the accepted commit, the observed tip, the
// last poll and the last refusal for /status after startup and after each poll;
// the admin listener renders their ages with the same injected clock.
//
// Startup authority is the accepted record alone. A record bootstraps only when
// the record path is absent; any present malformed or mismatched record forbids
// bootstrap and fails the service. The remote tip is never startup authority.
//
// Semantic-gate deviation from the Rust watcher (recorded so the two can be
// compared for equivalence): the JS runtime has no transition module, so
// semantic validity is candidate snapshot construction success plus
// re-validation of the materialized accepted catalog. Repository-identity
// mismatch, full-ref mismatch, malformed commits, unknown ancestry, and
// candidate object unavailability stay policy-covered by accepted-ref.js
// fixture tests; the watcher derives candidate fields from operator
// configuration and verified Git output only.

import { execFile } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
  fsyncSync,
} from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { promisify } from "node:util";

import {
  ACCEPTED_REF_SCHEMA,
  canonicalAcceptedRefBytes,
  evaluateAcceptedRefReload,
  evaluateAcceptedRefStartup,
  parseAcceptedRef,
} from "../accepted-ref.js";
import { validateCatalog } from "../catalog.js";
import {
  ACCEPTED_CATALOG_UNLOADABLE,
  CATALOG_PATH_INVALID,
  failureForAncestry,
  failureForCatalogParse,
  failureForObjectState,
  failureForShowFailure,
  failureForSnapshotError,
  INTERNAL_ERROR,
  isRetryable,
  MATERIALIZATION_FAILED,
  PERSISTENCE_FAILED,
  retryDelaySeconds,
} from "./refusal.js";
import { buildServeSnapshot } from "./snapshot.js";
import { installSnapshot, installWatcherView } from "./web.js";

const execFileAsync = promisify(execFile);

/** Exact accepted-ref record file name inside the watcher state directory. */
const ACCEPTED_RECORD_FILE = "accepted-ref.json";
/** Exact bare mirror directory name inside the watcher state directory. */
const REPOSITORY_DIR = "repository";
/** Exact temporary directory name inside the watcher state directory. */
const TEMP_DIR = "temp";
/** Exact local ref updated by every fetch of the watched remote ref. */
const WATCH_REF = "refs/pkgre/watch";
/** Exact wall-clock bound applied to every Git invocation. */
const GIT_TIMEOUT_MS = 600_000;
/** Exact stdout/stderr bound for captured Git output. */
const MAX_BUFFER_BYTES = 512 * 1024 * 1024;
/** Exact number of trailing bytes kept from failed command diagnostics. */
const MAX_COMMAND_ERROR_BYTES = 512;
const COMMIT_NAME = /^[0-9a-f]{40}$/;
const GIT_GLOBAL_ARGS = [
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "protocol.allow=never",
  "-c",
  "protocol.https.allow=always",
  "-c",
  "protocol.file.allow=always",
];

// The watcher origin is trusted operator configuration (it may be a local path
// for LAN-public instances), unlike catalog-declared package sources, so the
// file protocol is allowed for the mirror fetch.
function gitEnvironment() {
  const env = { ...process.env };
  delete env.GIT_ASKPASS;
  delete env.SSH_ASKPASS;
  delete env.SSH_AUTH_SOCK;
  delete env.HTTPS_PROXY;
  delete env.HTTP_PROXY;
  delete env.ALL_PROXY;
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_TERMINAL_PROMPT = "0";
  return env;
}

function boundedLossy(bytes) {
  if (bytes === undefined) return "";
  const text = bytes.toString("utf8");
  return text.length > MAX_COMMAND_ERROR_BYTES ? text.slice(-MAX_COMMAND_ERROR_BYTES) : text;
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/** Runs one isolated Git invocation; resolves with stdout bytes. */
async function gitRun(arguments_, { action, cwd } = {}) {
  try {
    const { stdout } = await execFileAsync("git", [...GIT_GLOBAL_ARGS, ...arguments_], {
      cwd,
      env: gitEnvironment(),
      maxBuffer: MAX_BUFFER_BYTES,
      timeout: GIT_TIMEOUT_MS,
    });
    return stdout;
  } catch (error) {
    if (action !== undefined && error instanceof Error) {
      error.message = `git ${action} failed: ${error.message}\nstderr:\n${boundedLossy(error.stderr)}`;
    }
    throw error;
  }
}

/** Exit code of one isolated Git invocation; null when Git never produced one. */
async function gitExitCode(arguments_, cwd) {
  try {
    await execFileAsync("git", [...GIT_GLOBAL_ARGS, ...arguments_], {
      cwd,
      env: gitEnvironment(),
      maxBuffer: MAX_BUFFER_BYTES,
      timeout: GIT_TIMEOUT_MS,
    });
    return 0;
  } catch (error) {
    return typeof error?.code === "number" ? error.code : null;
  }
}

function stdoutText(bytes) {
  return bytes.toString("utf8").trim();
}

/** Whole seconds from one monotonic reading to a later one, never negative. */
function secondsBetween(from, to) {
  return Math.max(0, Math.floor((to - from) / 1000));
}

/**
 * Attaches the classified failure to the error a materialization throws, so the
 * caller reports the class that its stage observed.
 * @param {unknown} error
 * @param {{class: string, code: string}} failure
 * @returns {Error}
 */
function classified(error, failure) {
  if (error instanceof Error) {
    error.failure = failure;
    return error;
  }
  const wrapped = new Error(String(error));
  wrapped.failure = failure;
  return wrapped;
}

/**
 * Renders one refusal for a report or /status, without paths, error text or
 * wall-clock times: the time to the next attempt is 0 once it is due and null when
 * the commit is suppressed for good.
 * @param {object} entry refusal entry
 * @param {number} now monotonic milliseconds
 * @returns {{attempts: number, class: string, failure: string, retryInSeconds: number | null}}
 */
function refusalReport(entry, now) {
  return {
    attempts: entry.attempts,
    class: entry.class,
    failure: entry.failure,
    retryInSeconds: entry.retryAt === null ? null : Math.max(0, Math.floor((entry.retryAt - now) / 1000)),
  };
}

/**
 * Normalizes the configured catalog path to its plain components joined with
 * `/`, so that `git ls-tree` answers the entry itself rather than a directory's
 * contents: `registry/` names the entry `registry`, not the directory's listing.
 * @param {string} catalogPath configured relative catalog path
 * @returns {string} normalized path
 */
export function normalizedCatalogPath(catalogPath) {
  return catalogPath
    .split("/")
    .filter((component) => component !== "" && component !== ".")
    .join("/");
}

/**
 * Classifies the entry at the catalog path from one `git ls-tree -z` answer.
 *
 * `git ls-tree` answers no entry for an absent path and expands no wildcard, so an
 * answer with no entry for the path means the commit holds no catalog file. The JS
 * catalog is a single file, so only a regular blob is one: a tree, a symbolic link
 * or a gitlink at the path is refused once Git cannot show it as a file.
 * @param {Buffer | string} output `git ls-tree -z` output
 * @param {string} normalizedPath the normalized catalog path
 * @returns {"blob" | "missing" | "other"} the entry's kind
 */
export function catalogEntryKind(output, normalizedPath) {
  for (const entry of output.toString("utf8").split("\0")) {
    const tab = entry.indexOf("\t");
    if (tab < 0 || entry.slice(tab + 1) !== normalizedPath) continue;
    const [mode, type] = entry.slice(0, tab).split(" ");
    return type === "blob" && (mode === "100644" || mode === "100755") ? "blob" : "other";
  }
  return "missing";
}

/**
 * Fixed-ref accepted-ref watcher with last-known-good snapshot publication.
 * The shared state comes from createShared(); installSnapshot publishes every
 * accepted candidate and failed reloads keep the previous snapshot in place.
 */
export class AcceptedRefWatcher {
  /**
   * Creates the watcher without performing any I/O.
   * @param {object} watcherConfig frozen [watcher] configuration
   * @param {{archiveStore: string | null, delivery: "redirect" | "body",
   *   shared: object, clock?: () => number}} options
   *   `clock` is a monotonic source in milliseconds, `performance.now` by default
   */
  constructor(watcherConfig, { archiveStore, delivery, shared, clock }) {
    this.origin = watcherConfig.origin;
    this.catalogPath = watcherConfig.catalogPath;
    this.bootstrapCommit = watcherConfig.bootstrapCommit;
    this.statePath = watcherConfig.statePath;
    this.pollIntervalSeconds = watcherConfig.pollIntervalSeconds;
    this.repository = watcherConfig.repository;
    this.archiveStore = archiveStore;
    this.delivery = delivery;
    this.shared = shared;
    this.clock = clock ?? (() => performance.now());
    this.accepted = null;
    /** Refused commits by hash: refused for good, or waiting for a retry. */
    this.refusals = new Map();
    /** Last tip any poll observed, or null before the first observation. */
    this.tip = null;
    /** Last poll's decision, reason and end time. */
    this.lastPoll = null;
    /** Last refused or skipped commit and its entry. */
    this.lastRefusal = null;
    /** The poll in flight, whose promise every poll requested meanwhile returns. */
    this.running = null;
    this.tempCounter = 0;
  }

  emit(level, event, extra = {}) {
    process.stderr.write(`${JSON.stringify({ event, level, ...extra })}\n`);
  }

  warn(event, error) {
    this.emit("warn", event, { error: errorMessage(error) });
  }

  /** Establishes the initial accepted ref and installs the first snapshot. */
  async startup() {
    this.prepareState();
    await this.prepareRepository();
    const { record, state } = this.loadStartupRecord();
    let bootstrapObject = "not-applicable";
    if (state === "absent") {
      const probed = await this.probeObject(this.bootstrapCommit, "probe bootstrap object");
      if (probed === "missing") {
        try {
          await this.fetchWatchedRef();
        } catch (error) {
          this.warn("watcher bootstrap fetch failed", error);
        }
        bootstrapObject = await this.probeObject(this.bootstrapCommit, "probe bootstrap object after fetch");
      } else {
        bootstrapObject = probed;
      }
    }
    let localAcceptedObject = "not-applicable";
    if (state === "present" && record !== null) {
      localAcceptedObject = await this.probeObject(record.acceptedCommit, "probe accepted object");
    }
    const outcome = evaluateAcceptedRefStartup(
      {
        acceptedRecord: record,
        acceptedRecordState: state,
        bootstrapCommit: this.bootstrapCommit,
        bootstrapObject,
        localAcceptedObject,
      },
      this.repository,
    );
    switch (outcome.decision) {
      case "bootstrap": {
        const commit = outcome.activeCommit;
        const snapshot = await this.initialSnapshot(commit);
        const bootstrapRecord = this.buildRecord(commit);
        this.persistRecord(bootstrapRecord);
        this.accepted = bootstrapRecord;
        installSnapshot(this.shared, snapshot);
        break;
      }
      case "start-accepted": {
        const acceptedRecord = record;
        const snapshot = await this.initialSnapshot(acceptedRecord.acceptedCommit);
        this.accepted = acceptedRecord;
        installSnapshot(this.shared, snapshot);
        break;
      }
      case "fail-startup":
        throw new Error(`watcher startup failed: ${outcome.reason}`);
      default:
        throw new Error(`watcher startup produced unexpected decision ${outcome.decision}`);
    }
    this.emit("info", "watcher startup complete", { decision: outcome.decision, reason: outcome.reason });
    this.publishView();
  }

  /**
   * Observes the remote once and applies the transition policy.
   *
   * Polls run one at a time: a poll requested while another runs returns the
   * running poll's promise, so a timer that fires during a slow evaluation starts
   * no second one.
   * @returns {Promise<object>} this poll's report
   */
  pollOnce() {
    if (this.running !== null) return this.running;
    this.running = this.pollAndRecord().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  async pollAndRecord() {
    let report;
    if (this.accepted === null) {
      this.emit("error", "watcher poll reached without an accepted record; retaining");
      report = { decision: "retain-accepted", reason: "remote-unavailable", refusal: null };
    } else {
      report = await this.reload(this.accepted);
    }
    this.lastPoll = { decision: report.decision, ended: this.clock(), reason: report.reason };
    this.publishView();
    this.emit("info", "watcher poll complete", report);
    return report;
  }

  /**
   * Publishes the accepted commit, the observed tip, the last poll and the last
   * refusal for the admin listener, which renders the ages with this clock.
   */
  publishView() {
    installWatcherView(this.shared, { status: () => this.watcherStatus() });
  }

  /** Renders the /status member: codes only, no error text, paths or wall-clock times. */
  watcherStatus() {
    const now = this.clock();
    return {
      acceptedCommit: this.accepted === null ? "" : this.accepted.acceptedCommit,
      tip: this.tip,
      lastPoll: this.lastPoll === null
        ? null
        : {
          decision: this.lastPoll.decision,
          reason: this.lastPoll.reason,
          secondsAgo: secondsBetween(this.lastPoll.ended, now),
        },
      lastRefusal: this.lastRefusal === null
        ? null
        : {
          commit: this.lastRefusal.commit,
          reason: this.lastRefusal.entry.reason,
          ...refusalReport(this.lastRefusal.entry, now),
          secondsAgo: secondsBetween(this.lastRefusal.entry.ended, now),
        },
    };
  }

  async reload(accepted) {
    let tip;
    try {
      tip = await this.remoteTip();
    } catch (error) {
      this.warn("watcher remote observation failed", error);
      return this.apply(accepted, null, null, null);
    }
    if (tip === null) {
      this.tip = null;
      this.emit("debug", "watched ref is absent upstream");
      return this.apply(accepted, null, null, null);
    }
    this.tip = tip;
    if (tip === accepted.acceptedCommit) {
      return { decision: "unchanged", reason: "candidate-equals-accepted", refusal: null };
    }
    if (this.isWaiting(tip)) {
      return this.apply(accepted, this.rejectedCandidate(tip), null, null);
    }
    try {
      await this.fetchWatchedRef();
    } catch (error) {
      this.warn("watcher fetch failed", error);
      return this.apply(accepted, null, null, null);
    }
    let observed;
    try {
      observed = await this.watchRefCommit();
    } catch (error) {
      this.warn("watcher fetch resolution failed", error);
      return this.apply(accepted, null, null, null);
    }
    if (observed !== tip) {
      this.emit("debug", "watched ref moved during reload; retrying next poll");
      return this.apply(accepted, null, null, null);
    }
    let objectState;
    try {
      objectState = await this.objectState(tip);
    } catch (error) {
      this.warn("watcher object probe failed", error);
      return this.apply(accepted, null, null, null);
    }
    let ancestry = "not-evaluated";
    if (objectState === "valid") {
      try {
        ancestry = await this.ancestry(accepted.acceptedCommit, tip);
      } catch (error) {
        this.warn("watcher ancestry probe failed", error);
        ancestry = "unknown";
      }
    }
    const candidate = {
      ancestry,
      commit: tip,
      fullRef: this.repository.fullRef,
      objectState,
      persistence: "not-attempted",
      repositoryIdentity: this.repository.repositoryIdentity,
      semanticValidity: "not-evaluated",
      suppressed: false,
    };
    let failure = failureForObjectState(objectState) ?? failureForAncestry(ancestry);
    let pending = null;
    if (objectState === "valid" && ancestry === "descendant") {
      const validation = await this.semanticValidation(accepted.acceptedCommit, tip);
      candidate.semanticValidity = validation.validity;
      failure = failure ?? validation.failure;
      if (validation.validity === "valid") {
        let record;
        try {
          record = this.buildRecord(tip);
        } catch (error) {
          this.warn("watcher accepted-ref record encoding failed", error);
          failure = INTERNAL_ERROR;
          candidate.persistence = "interrupted-before-rename";
        }
        if (record !== undefined) {
          try {
            this.persistRecord(record);
            candidate.persistence = "success";
            pending = validation.snapshot;
          } catch (error) {
            this.warn("watcher accepted-ref persistence failed", error);
            failure = PERSISTENCE_FAILED;
            candidate.persistence = "interrupted-before-rename";
          }
        }
      }
    }
    return this.apply(accepted, candidate, pending, failure);
  }

  /**
   * Applies one evaluated candidate through the shared transition policy and
   * records how a refusal is handled: a retrying entry with its next attempt, or
   * an entry refused for good.
   * @param {object} accepted accepted-ref record
   * @param {object | null} candidate evaluated candidate, or null for a poll that observed none
   * @param {object | null} pending snapshot of an accepted candidate
   * @param {{class: string, code: string} | null} failure classified failure of a refused candidate
   * @returns {{decision: string, reason: string, refusal: object | null}} this poll's report
   */
  apply(accepted, candidate, pending, failure) {
    const outcome = evaluateAcceptedRefReload(accepted, candidate ?? null, this.repository);
    const now = this.clock();
    let refusal = null;
    switch (outcome.decision) {
      case "accept-forward": {
        const record = this.buildRecord(outcome.activeCommit);
        this.accepted = record;
        installSnapshot(this.shared, pending);
        this.dropRetrying();
        break;
      }
      case "retain-accepted":
        if (candidate !== null) {
          const entry = candidate.suppressed
            ? this.refusals.get(candidate.commit)
            : this.recordRefusal(candidate.commit, outcome.reason, failure, now);
          refusal = refusalReport(entry, now);
          this.lastRefusal = { commit: candidate.commit, entry };
        }
        break;
      default:
        break;
    }
    return { decision: outcome.decision, reason: outcome.reason, refusal };
  }

  /**
   * Records one failed evaluation of a commit and logs it: one more attempt than
   * the commit's entry, a retry due after the schedule for a local failure, and no
   * retry at all for a candidate's or an unclassified one.
   */
  recordRefusal(commit, reason, failure, now) {
    const failed = failure ?? INTERNAL_ERROR;
    const previous = this.refusals.get(commit);
    const attempts = previous === undefined ? 1 : previous.attempts + 1;
    const entry = {
      attempts,
      class: failed.class,
      ended: now,
      failure: failed.code,
      reason,
      retryAt: isRetryable(failed) ? now + retryDelaySeconds(attempts) * 1000 : null,
    };
    const detail = refusalReport(entry, now);
    this.emit(failed.class === "candidate" ? "info" : "warn", "watcher refused candidate", {
      attempts,
      class: failed.class,
      commit,
      failure: failed.code,
      reason,
      retryInSeconds: detail.retryInSeconds,
    });
    this.refusals.set(commit, entry);
    return entry;
  }

  /** Whether this commit is suppressed: refused for good, or waiting for its retry. */
  isWaiting(commit) {
    const entry = this.refusals.get(commit);
    return entry !== undefined && (entry.retryAt === null || this.clock() < entry.retryAt);
  }

  /** Drops every retrying entry after an acceptance; refused ones stay for the process. */
  dropRetrying() {
    for (const [commit, entry] of this.refusals) {
      if (entry.retryAt !== null) this.refusals.delete(commit);
    }
    if (this.lastRefusal !== null && this.lastRefusal.entry.retryAt !== null) {
      this.lastRefusal = { commit: this.lastRefusal.commit, entry: { ...this.lastRefusal.entry, retryAt: null } };
    }
  }

  rejectedCandidate(commit) {
    return {
      ancestry: "not-evaluated",
      commit,
      fullRef: this.repository.fullRef,
      objectState: "missing",
      persistence: "not-attempted",
      repositoryIdentity: this.repository.repositoryIdentity,
      semanticValidity: "not-evaluated",
      suppressed: true,
    };
  }

  buildRecord(commit) {
    const record = Object.freeze({
      acceptedCommit: commit,
      fullRef: this.repository.fullRef,
      repositoryIdentity: this.repository.repositoryIdentity,
      schema: ACCEPTED_REF_SCHEMA,
    });
    canonicalAcceptedRefBytes(record, this.repository);
    return record;
  }

  acceptedRecordPath() {
    return path.join(this.statePath, ACCEPTED_RECORD_FILE);
  }

  repositoryDir() {
    return path.join(this.statePath, REPOSITORY_DIR);
  }

  tempRoot() {
    return path.join(this.statePath, TEMP_DIR);
  }

  nextTemp(label) {
    return path.join(this.tempRoot(), `${label}-${process.pid}-${this.tempCounter++}`);
  }

  prepareState() {
    mkdirSync(this.statePath, { recursive: true });
    mkdirSync(this.tempRoot(), { recursive: true });
  }

  async prepareRepository() {
    if (existsSync(path.join(this.repositoryDir(), "HEAD"))) return;
    await gitRun(["init", "--bare", "--quiet", this.repositoryDir()], { action: "initialize watcher mirror" });
  }

  loadStartupRecord() {
    let bytes;
    try {
      bytes = readFileSync(this.acceptedRecordPath());
    } catch (error) {
      if (error?.code === "ENOENT") return { record: null, state: "absent" };
      throw new Error(`read accepted-ref record ${this.acceptedRecordPath()}: ${errorMessage(error)}`);
    }
    const record = parseStartupRecord(bytes);
    if (record === null) {
      this.warn("watcher accepted-ref record is malformed", new Error("accepted-ref record is malformed"));
      return { record: null, state: "malformed" };
    }
    return { record, state: "present" };
  }

  persistRecord(record) {
    const bytes = canonicalAcceptedRefBytes(record, this.repository);
    const target = this.acceptedRecordPath();
    const temporary = path.join(this.statePath, `${ACCEPTED_RECORD_FILE}.tmp-${process.pid}-${this.tempCounter++}`);
    try {
      const fd = openSync(temporary, "w");
      try {
        let offset = 0;
        while (offset < bytes.length) offset += writeSync(fd, bytes, offset);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(temporary, target);
      const directory = openSync(this.statePath, "r");
      try {
        fsyncSync(directory);
      } finally {
        closeSync(directory);
      }
    } catch (error) {
      try {
        rmSync(temporary, { force: true });
      } catch {
        // The original persistence failure is the reportable error.
      }
      throw error;
    }
  }

  /** Existence-then-type probe: missing, malformed, corrupt, or valid. */
  async probeObject(commit, action) {
    const exists = await gitExitCode(["cat-file", "-e", commit], this.repositoryDir());
    if (exists === null) throw new Error(`git ${action} failed: git could not run`);
    if (exists !== 0) return "missing";
    try {
      const kind = stdoutText(await gitRun(["cat-file", "-t", commit], { cwd: this.repositoryDir() }));
      return kind === "commit" ? "valid" : "malformed";
    } catch {
      return "corrupt";
    }
  }

  async objectState(commit) {
    return this.probeObject(commit, "probe object");
  }

  async remoteTip() {
    const output = stdoutText(await gitRun(["ls-remote", this.origin, this.repository.fullRef], { action: "observe remote tip" }));
    if (output.length === 0) return null;
    const token = output.split("\n", 1)[0].split(/\s+/)[0] ?? "";
    if (!COMMIT_NAME.test(token)) {
      throw new Error(`ls-remote returned a non-commit object name ${JSON.stringify(token)}`);
    }
    return token;
  }

  async fetchWatchedRef() {
    const reference = `+${this.repository.fullRef}:${WATCH_REF}`;
    await gitRun(["fetch", "--no-tags", "--force", this.origin, reference], {
      action: "fetch watched ref",
      cwd: this.repositoryDir(),
    });
  }

  async watchRefCommit() {
    return stdoutText(
      await gitRun(["rev-parse", "--verify", `${WATCH_REF}^{commit}`], {
        action: "resolve watched ref",
        cwd: this.repositoryDir(),
      }),
    );
  }

  async ancestry(acceptedCommit, candidateCommit) {
    const forward = await gitExitCode(["merge-base", "--is-ancestor", acceptedCommit, candidateCommit], this.repositoryDir());
    const backward = await gitExitCode(["merge-base", "--is-ancestor", candidateCommit, acceptedCommit], this.repositoryDir());
    if (forward === 0) return "descendant";
    if (backward === 0) return "predecessor";
    if (forward === 1 && backward === 1) return "divergent";
    return "unknown";
  }

  /**
   * Probes the entry at the normalized catalog path of one commit.
   *
   * `git ls-tree` answers no entry for an absent path, expands no wildcard and
   * fails only when Git fails, so it tells "the commit has no catalog file" from
   * "Git failed".
   * @param {string} commit
   * @returns {Promise<"blob" | "missing" | "other">} the entry's kind
   */
  async catalogEntry(commit) {
    const normalized = normalizedCatalogPath(this.catalogPath);
    const output = await gitRun(["ls-tree", "-z", commit, "--", normalized], {
      action: "probe catalog path",
      cwd: this.repositoryDir(),
    });
    return catalogEntryKind(output, normalized);
  }

  /**
   * Reads and parses the catalog file of one commit, classifying a failure.
   *
   * A thrown error carries its classified failure as `failure`. Every failure on
   * the accepted side is local, since this process loaded that catalog before; the
   * candidate's side is the commit's own unless Git could not show a regular blob.
   * @param {string} commit
   * @param {{accepted: boolean}} side whether the accepted or the candidate side reads
   * @returns {Promise<object>} parsed catalog
   */
  async materializeCatalog(commit, { accepted }) {
    let entry = "blob";
    if (!accepted) {
      try {
        entry = await this.catalogEntry(commit);
      } catch (error) {
        throw classified(error, MATERIALIZATION_FAILED);
      }
      if (entry === "missing") {
        throw classified(
          new Error(`commit ${commit} holds no catalog file at ${normalizedCatalogPath(this.catalogPath)}`),
          CATALOG_PATH_INVALID,
        );
      }
    }
    let bytes;
    try {
      bytes = await gitRun(["show", `${commit}:${this.catalogPath}`], {
        action: "materialize catalog",
        cwd: this.repositoryDir(),
      });
    } catch (error) {
      throw classified(error, failureForShowFailure({ accepted, entry, error }));
    }
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      throw classified(error, failureForCatalogParse(accepted));
    }
  }

  /**
   * Materializes both catalogs and builds the candidate's snapshot.
   * @param {string} acceptedCommit
   * @param {string} candidateCommit
   * @returns {Promise<{failure: object | null, snapshot: object | null, validity: string}>}
   *   the validity, the candidate snapshot when valid, and the classified failure
   *   whenever the validity is invalid
   */
  async semanticValidation(acceptedCommit, candidateCommit) {
    let acceptedCatalog;
    try {
      acceptedCatalog = await this.materializeCatalog(acceptedCommit, { accepted: true });
    } catch (error) {
      this.warn("watcher accepted catalog materialization failed", error);
      return { failure: error?.failure ?? MATERIALIZATION_FAILED, snapshot: null, validity: "invalid" };
    }
    let candidateCatalog;
    try {
      candidateCatalog = await this.materializeCatalog(candidateCommit, { accepted: false });
    } catch (error) {
      this.warn("watcher candidate catalog materialization failed", error);
      return { failure: error?.failure ?? MATERIALIZATION_FAILED, snapshot: null, validity: "invalid" };
    }
    try {
      validateCatalog(acceptedCatalog);
    } catch (error) {
      this.warn("watcher rejected accepted catalog", error);
      return { failure: ACCEPTED_CATALOG_UNLOADABLE, snapshot: null, validity: "invalid" };
    }
    try {
      const snapshot = await buildServeSnapshot(candidateCatalog, this.archiveStore, this.delivery, candidateCommit);
      return { failure: null, snapshot, validity: "valid" };
    } catch (error) {
      const failure = failureForSnapshotError(error);
      if (failure.class === "candidate") {
        this.emit("info", "watcher rejected candidate snapshot", { error: errorMessage(error) });
      } else {
        this.warn("watcher rejected candidate snapshot", error);
      }
      return { failure, snapshot: null, validity: "invalid" };
    }
  }

  async initialSnapshot(commit) {
    const catalog = await this.materializeCatalog(commit, { accepted: true });
    return buildServeSnapshot(catalog, this.archiveStore, this.delivery, commit);
  }
}

/**
 * Parses exact canonical accepted-ref bytes without binding them to the
 * configured repository; evaluateAcceptedRefStartup owns that comparison, so a
 * structurally valid record from a different repository still parses here.
 * Returns null for any malformed record.
 * @param {Buffer} bytes
 * @returns {object | null} frozen accepted-ref record
 */
function parseStartupRecord(bytes) {
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  const selfBinding = { fullRef: document.fullRef, repositoryIdentity: document.repositoryIdentity };
  try {
    return parseAcceptedRef(bytes, selfBinding);
  } catch {
    return null;
  }
}
