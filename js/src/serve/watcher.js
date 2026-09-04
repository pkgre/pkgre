// Accepted-ref watcher: fixed-ref polling with last-known-good serving snapshots.
//
// The watcher owns the accepted-ref record on disk, a bare Git mirror of the
// watched origin, and the shared serving snapshot. Every poll observes the
// remote tip once and applies the shared transition policy (accepted-ref.js):
// only strictly forward, semantically valid, durably persisted candidates are
// published, and every fresh-tip rejection is suppressed by hash until the tip
// changes or the process restarts. A failed reload never changes the active
// snapshot or the accepted ref.
//
// Startup authority is the accepted record alone. A record bootstraps only when
// the record path is absent; any present malformed or mismatched record forbids
// bootstrap and fails the service. The remote tip is never startup authority.
//
// Semantic-gate deviation from the Rust watcher (documented for D5
// equivalence): the JS runtime has no transition module, so semantic validity
// is candidate snapshot construction success plus re-validation of the
// materialized accepted catalog. Repository-identity mismatch, full-ref
// mismatch, malformed commits, unknown ancestry, and candidate object
// unavailability stay policy-covered by accepted-ref.js fixture tests; the
// watcher derives candidate fields from operator configuration and verified
// Git output only.

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
import { buildServeSnapshot } from "./snapshot.js";
import { installSnapshot } from "./web.js";

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

/**
 * Fixed-ref accepted-ref watcher with last-known-good snapshot publication.
 * The shared state comes from createShared(); installSnapshot publishes every
 * accepted candidate and failed reloads keep the previous snapshot in place.
 */
export class AcceptedRefWatcher {
  /**
   * Creates the watcher without performing any I/O.
   * @param {object} watcherConfig frozen [watcher] configuration
   * @param {{archiveStore: string | null, delivery: "redirect" | "body", shared: object}} options
   */
  constructor(watcherConfig, { archiveStore, delivery, shared }) {
    this.origin = watcherConfig.origin;
    this.catalogPath = watcherConfig.catalogPath;
    this.bootstrapCommit = watcherConfig.bootstrapCommit;
    this.statePath = watcherConfig.statePath;
    this.pollIntervalSeconds = watcherConfig.pollIntervalSeconds;
    this.repository = watcherConfig.repository;
    this.archiveStore = archiveStore;
    this.delivery = delivery;
    this.shared = shared;
    this.accepted = null;
    this.suppressed = new Set();
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
  }

  /** Observes the remote once and applies the transition policy. */
  async pollOnce() {
    if (this.accepted === null) {
      this.emit("error", "watcher poll reached without an accepted record; retaining");
      return { decision: "retain-accepted", reason: "remote-unavailable" };
    }
    const report = await this.reload(this.accepted);
    this.emit("info", "watcher poll complete", report);
    return report;
  }

  async reload(accepted) {
    let tip;
    try {
      tip = await this.remoteTip();
    } catch (error) {
      this.warn("watcher remote observation failed", error);
      return this.apply(accepted, null, null);
    }
    if (tip === null) {
      this.emit("debug", "watched ref is absent upstream");
      return this.apply(accepted, null, null);
    }
    if (tip === accepted.acceptedCommit) {
      return { decision: "unchanged", reason: "candidate-equals-accepted" };
    }
    if (this.suppressed.has(tip)) {
      return this.apply(accepted, this.rejectedCandidate(tip), null);
    }
    try {
      await this.fetchWatchedRef();
    } catch (error) {
      this.warn("watcher fetch failed", error);
      return this.apply(accepted, null, null);
    }
    let observed;
    try {
      observed = await this.watchRefCommit();
    } catch (error) {
      this.warn("watcher fetch resolution failed", error);
      return this.apply(accepted, null, null);
    }
    if (observed !== tip) {
      this.emit("debug", "watched ref moved during reload; retrying next poll");
      return this.apply(accepted, null, null);
    }
    let objectState;
    try {
      objectState = await this.objectState(tip);
    } catch (error) {
      this.warn("watcher object probe failed", error);
      return this.apply(accepted, null, null);
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
    let pending = null;
    if (objectState === "valid" && ancestry === "descendant") {
      const { snapshot, validity } = await this.semanticValidation(accepted.acceptedCommit, tip);
      candidate.semanticValidity = validity;
      if (validity === "valid") {
        try {
          const record = this.buildRecord(tip);
          this.persistRecord(record);
          candidate.persistence = "success";
          pending = snapshot;
        } catch (error) {
          this.warn("watcher accepted-ref persistence failed", error);
          candidate.persistence = "interrupted-before-rename";
        }
      }
    }
    return this.apply(accepted, candidate, pending);
  }

  apply(accepted, candidate, pending) {
    const outcome = evaluateAcceptedRefReload(accepted, candidate ?? null, this.repository);
    switch (outcome.decision) {
      case "accept-forward": {
        const record = this.buildRecord(outcome.activeCommit);
        this.accepted = record;
        installSnapshot(this.shared, pending);
        break;
      }
      case "retain-accepted":
        if (candidate !== null && !candidate.suppressed) this.suppressed.add(candidate.commit);
        break;
      default:
        break;
    }
    return { decision: outcome.decision, reason: outcome.reason };
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

  /** `git show <commit>:<catalogPath>` — the JS catalog is a single file, no tar. */
  async materializeCatalog(commit) {
    const bytes = await gitRun(["show", `${commit}:${this.catalogPath}`], {
      action: "materialize catalog",
      cwd: this.repositoryDir(),
    });
    return JSON.parse(bytes.toString("utf8"));
  }

  async semanticValidation(acceptedCommit, candidateCommit) {
    let acceptedCatalog;
    let candidateCatalog;
    try {
      acceptedCatalog = await this.materializeCatalog(acceptedCommit);
      candidateCatalog = await this.materializeCatalog(candidateCommit);
    } catch (error) {
      this.warn("watcher catalog materialization failed", error);
      return { snapshot: null, validity: "invalid" };
    }
    try {
      validateCatalog(acceptedCatalog);
      const snapshot = await buildServeSnapshot(candidateCatalog, this.archiveStore, this.delivery);
      return { snapshot, validity: "valid" };
    } catch (error) {
      this.emit("info", "watcher rejected candidate snapshot", { error: errorMessage(error) });
      return { snapshot: null, validity: "invalid" };
    }
  }

  async initialSnapshot(commit) {
    const catalog = await this.materializeCatalog(commit);
    return buildServeSnapshot(catalog, this.archiveStore, this.delivery);
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
