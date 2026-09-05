# Dynamic registry migration readiness

Status:`READY_FOR_D1` | captured:`2026-08-29` | scope:source-only migration from the current static registries to native Git-backed Rust+JavaScript services | deployment,DNS,secrets:operator-only

## Decision

No standalone D0 gate program is required. Readiness is a reviewed record plus ordinary repository validation; checks that depend on code,packaged binaries,Rain configuration,live traffic,or imported archives run at the phase that creates those facts. This avoids a second authorization system whose behavior is unrelated to package serving.

D1 source work may proceed. Readiness does not authorize deployment,GitHub setting changes,DNS changes,secret access,or a public cutover.

Unavailable historical Rain deployment metadata and provider audit history are non-blocking and must not be reconstructed or represented as observed. Before D7,the deployment handoff will identify the exact new source+infra commits,built generation,configuration,and validation results produced for this rollout;the new deployment record is the provenance boundary.

Monitoring remains desirable long-term operational work,but is not a serving dependency or phase prerequisite. No bare-Wind monitoring change belongs to this rollout.

## Reviewed source basis

| Repository | Role | Commit | Required branch/ref | Origin |
|---|---|---|---|---|
| `pkgre/pkgre` | implementation | `066293df21743cbf41fb571a38f2bb94059e7274` | `refs/heads/main` | `git@github.com:pkgre/pkgre.git` |
| `pkgre/rust` | public Rust catalog | `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` | `refs/heads/main` | `git@github.com:pkgre/rust.git` |
| `pkgre/js` | public JavaScript catalog | `f43bd58bd3d4e36f8b3f4df3c002735c977acd17` | `refs/heads/main` | `git@github.com:pkgre/js.git` |

These commits are migration baselines,not permanent runtime pins. A later phase records the exact candidate commit it validates and deploys. `infra` is intentionally absent:current live-generation provenance is unavailable and current `master` will be reviewed at D7 rather than guessed here.

## Reproducible migration facts

| Fact | Current value | Consequence |
|---|---|---|
| Rust catalogs | one schema-4 registry=`main`;747 active download routes;3 retained first-party `.crate` objects | root sparse routing remains valid initially;mirror bodies must be imported+verified before body-mode cutover,not before D1 |
| Rust download topology | metadata advertises `dl.rust.pkg.re`;current proxy/marker design remains the rollback baseline | native service first preserves redirect behavior;same-host/body changes use later explicit cutovers |
| JavaScript catalogs | one schema-v1 registry=`main`;one dependency-free first-party package+one retained `.tgz`;minimum age=`2592000s`=30d | initial native projection is small;30d remains server-side admission policy for npmjs packages |
| JavaScript public state | dormant bootstrap exists;no dependable live registry continuity is assumed | first activation requires a tested local rollback artifact or accepts bounded downtime;no historical-provider proof is needed |
| LAN registries | no concrete instance selected | public implementation must support configuration reuse,but no LAN hostname,ref,credential,DNS,TLS,or deployment value is invented now |
| Authentication | none planned;private registries are LAN-public | network isolation belongs to the later LAN deployment phase;no package protocol auth layer is added |
| Serving snapshot | immutable validated projection held only in memory;Git+accepted commit/state provide recovery | no rendered serving tree or renderer state is persisted;cache remains optional |
| Reload trigger | internal watcher polls the configured full branch ref and swaps only a fully validated candidate | no systemd timer or watcher/child split is required initially |
| Commit admission | every accepted catalog commit must pass SSH-Ed25519 Git signature verification using a pinned Git implementation plus deployment-owned `allowedSigners`,trust,and revocation inputs | production principals,keys,settings,and secret installation remain operator-owned D7 inputs;unsigned or untrusted candidates never become active |

Large generated route dumps,raw command transcripts,live host snapshots,and cryptographic D0 ceremony state are not source artifacts. Route sets are regenerated from catalogs;protocol behavior is captured as small executable fixtures in D1;resource and deployment claims are measured against the built services in D4–D7.

## Phase-local validation

| Phase | Must pass before leaving the phase |
|---|---|
| D1 contracts | versioned Rust+JS projections;raw-target/path grammar;GET/HEAD/status/header/body fixtures;typed redirect/body descriptors;deterministic current-catalog export;client configuration policy;shared accepted-ref/LKG vectors proving durable accepted state is the sole restart authority and forbidding arbitrary newest/predecessor selection |
| D2 catalog migration | forward+rollback schema tests;current catalogs migrate without identity loss;archive metadata is checksum-bound;the fixed SSH-Ed25519 commit-admission contract is implemented+tested with a pinned Git implementation and deployment-owned `allowedSigners`,trust,and revocation inputs |
| D3–D4 services | native Rust server+JS server;full candidate validation before atomic in-memory swap;last-known-good restart/reload behavior;bounded fetch/input/request/concurrency/resource tests;no request-time upstream metadata lookup;candidate builders must enforce limits while materializing responses rather than only after a complete render is allocated |
| D5–D6 ecosystem proof | offline/self-host tests;Cargo/npm/Bun/Deno clean-cache+locked-cache matrix;default crates.io/npmjs metadata fallback disabled;redirect compatibility then local-body behavior tested separately |
| D7 deployment preparation | current `~/repos/infra` master reviewed;exact source/catalog/infra commits+Nix closures+ports+state paths+nginx policy+HTTP-01 certificate plan recorded;local and deployment-build checks pass;rollback command sequence prepared |
| Operator deployment | operator deploys Rain and performs DNS changes;returned unit/log/TLS/HTTP/client evidence is reviewed before any next cutover |
| Body cutovers | 100% referenced archive bodies present+verified;storage budget+backup/restore checked;rollback exercised;legacy redirect endpoints retained until their observation horizon closes |
| Optional LAN rollout | exact instance origin+full ref,network range,service/state isolation,TLS/DNS,and read-only Git credential policy selected before configuration;external reachability denied |

A failed phase check blocks only the dependent transition. It does not retroactively invalidate unrelated source work or require a global signed waiver.

## Baseline commands

Run from `pkgre/` with clean sibling checkouts at `../pkgre-rust` and `../pkgre-js`:

```console
$ git -C . status --short --branch
$ git -C ../pkgre-rust status --short --branch
$ git -C ../pkgre-js status --short --branch
$ nix develop -c cargo test --workspace --all-targets
$ nix develop -c node --test js/test/*.test.js
$ nix run .#rust -- check ../pkgre-rust/registry
$ nix run .#js -- check ../pkgre-js/bootstrap/js-v0.1.0/catalog.json ../pkgre-js/bootstrap/js-v0.1.0/archives
$ nix flake check --print-build-logs
```

Record changed commits and rerun the affected command before using a later checkout as a migration input. Network/provider/live-host observations are never silently substituted for missing history.
