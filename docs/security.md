# Security model

## Goal

Reduce ambient Cargo supply-chain authority from “anything resolvable on crates.io/Git” to “exact source rows/checksums + explicit registry/category routes committed in a small public catalog.” Unexpected package/version/source/registry/category edges should stop at absent desired state, admission/reconciliation failure, or consumer resolution failure instead of falling back to crates.io.

## Trust anchors

- Curators: choose package/version/category home, inspect selected bytes/evidence proportionately, review generated catalog changes, authorize protected merges/removals.
- Public catalog/index repository: reviewable desired state + immutable registry locks, generated download catalog, row/archive objects, human admission manifests, generated admission locks; branch administration remains privileged.
- Human admission manifest: compact authorization intent containing exact category/name/version or tag + optional typed evidence; no mutable machine hashes.
- Generated admission lock: complete current network-backed evidence recomputed at apply and bound by SHA-256 into every admitted package lock.
- `pkgre-indexer`: enforces schema, update selection/policy, manifest↔batch↔package binding, lifecycle, artifact, dependency routing, download-catalog generation, rendering, migration, and release invariants; bugs can invalidate guarantees.
- `pkgre-download-serve`: maps an exact checksum-bearing route from a fully validated commit-pinned catalog to one of two hardcoded upstream forms; service/proxy bugs can invalidate availability or redirect guarantees.
- Nix pins + Rust/Cargo `1.95.0`: tooling build inputs + first-party packaging semantics.
- GitHub Pages + TLS/DNS: row/Git-archive availability/delivery; GitHub ref/raw endpoints: router catalog freshness; download router + nginx: route authorization/delivery; crates.io CDN: mirror-archive availability/delivery; Cargo checksums reject bytes differing from curated row.
- crates.io sparse/API/archive + public Git during plan/apply: candidate evidence origins; their current observations remain uncommitted until exact recomputation + transaction + protected PR review.

## Authority boundaries

Human declarations/manifests select only:

```text
mirror declaration: (universe, category, package, exact version)
publish declaration: (pkgre, tooling, package, credential-free HTTPS Git, immutable tag)
category policy: exact may-depend-on set
admission request: (qualified category, package, exact version|tag, optional typed evidence)
removal: omission from retained package key's version/tag list
```

Generated registry locks select permanently:

```text
(registry, category, normalized Cargo identity, version, source class, lifecycle state, archive hash, source-row hash, routed-active-row hash, origin provenance, optional admission-batch hash)
```

Planning is candidate discovery, not authority. `update-plan` performs full current evaluation but outputs a compact manifest. `update-apply` treats only requested identities as intent, independently recomputes machine facts at current time, and commits intent + facts atomically. `automatic`/`review-required` prioritize human attention; neither bypasses complete registry diff review + protected merge. Existing identities need no network during local `check`.

## Enforced invariants

- Exactly two canonical registries/URLs. A single-source registry may use its canonical direct source endpoint; mirror+publish in one registry requires its exact `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}` template. Arbitrary download origins/templates fail.
- Router route identity is exact registry + case-sensitive package name + canonical SemVer + lowercase 64-hex checksum. Only `GET|HEAD` can return `307`; destination is derived exclusively from `crates-io|git-tag`, never catalog/user URL data. Query/fragment/percent-encoding/malformed/oversized targets fail `404` without refresh.
- Service catalog fetch is fixed HTTPS GitHub main-ref → validated 40-hex commit → immutable raw `registry/downloads.json`; redirects + environment proxies are disabled; bodies/timeouts are bounded; only canonical valid data replaces in-memory last-known-good. Refresh is minimum-interval/single-flight/cancellation-safe; failed freshness makes unknown routes `503`, not authoritative `404`.
- Backend trusts one original-request-target header only across a private fixed nginx boundary. Backend exposure, forwarding a client-selected duplicate header, URI rewrite/normalization, or variable/user-controlled proxy upstream is forbidden; nginx must overwrite it with raw `$request_uri`.
- New mirror candidates: non-yanked + at least 30 exact days old. Implicit planning selects only latest eligible stable release per active lane (`major≥1` by major; stable `0.minor`, `minor>0`, by minor). New/inactive names, prereleases, and `0.0.x` require exact planning.
- A candidate after a ≥365-day adjacent publication gap from locked base is review-required; yanked/prerelease rows count as activity; gate persists through post-gap burst until one post-gap identity is locked.
- New/inactive name, dormant wake-up, new dependency identity, build-surface change, publisher/repository discontinuity promote best-effort Git source correspondence. Unavailable promoted source = review-required; archive/source mismatch = blocked.
- Unknown dependency home or forbidden category edge = blocked. Unsafe/malformed archives, checksum/history inconsistency, catalog drift, or duplicate identities fail rather than downgrade.
- Plan template includes automatic + review-required requests; blocked candidates are omitted. The template itself is applyable; protected registry-PR review authorizes the batch. Typed `manual-full-archive`/`manual-source-delta` evidence is optional, canonical, public, and exact-base checked.
- Apply re-fetches exact current sparse history, rows, archives, API fields, dependency/source evidence, age, route, and decisions; it rejects yanked/young/blocked/drifted/evidence-invalid requests and never substitutes another version.
- Apply executes through catalog fingerprint guard + whole-catalog staging/rollback; declaration edits, rows, registry locks, human manifest, generated batch lock, and package batch bindings install together or not at all.
- Every generated admission pair is immutable, canonical, regular, paired, and catalog-owned. Its `.lock` binds adjacent manifest hash + exact requests + complete plan; every package in that batch binds SHA-256 of complete `.lock`; exact reverse coverage is required with no duplicates/orphans.
- Validation is indexed/linear over batch candidates + package locks rather than rescanning the entire catalog per candidate. Historical generated facts validate recorded positive policy thresholds.
- Established catalogs reject ordinary `lock` admission of new mirror identities; bootstrap, empty name anchors, removals, and Git tags remain permitted.
- Exact canonical category topology: `universe/{general,acp,filesystem,matrix,mcp,sse,terminal,yaml}` + `pkgre/tooling`; each category inhabited + complete fixed direct-dependency allowlist.
- Category edges: `general→general`; each universe feature category→itself+general; `mcp→mcp|sse|general`; `tooling→tooling|general`; same registry grants no implicit edge.
- One permanent registry/category home + `mirror|publish` source class per normalized package name; Cargo ASCII case + `-`/`_` collision defense.
- Explicit home required for every dependency; routing overwrites every source-row registry field, including optional/dev/build/target-specific + renamed edges; category policy checked before URL routing.
- Mirrored archive = crates.io artifact checksum in exact retained row; archive verified then discarded; upstream-yanked versions rejected.
- First-party package binds HTTPS repository + literal tag + tag object + peeled commit + package/version/path + pinned Cargo version + reproducible archive.
- First-party manifest sets exactly `publish = ["pkgre"]`; every dependency explicitly names `universe` or `pkgre`; path/Git/crates.io/unknown sources fail.
- Exact archive/source-row/routed-active-row SHA-256 binds every package; only active Git-tag archive bytes retained locally. Canonical generated `downloads.json` must equal the exact active-lock projection `(registry, case-sensitive name, canonical version, archive hash, closed source enum)` and is authenticated again by rendered-release verification.
- Lifecycle append-only: additions + `active→removed`; removal retains source row + yanked history, removes unshared Git archive, cannot reverse.
- Existing locks/objects/rows/admissions/category/name anchors pass complete local preflight before public fetch.
- Complete replacement staged, strict-loaded, object-verified, test-rendered, then same-parent installed with rollback.
- Root/category/admission/object boundaries reject unrelated entries, traversal, symlink substitution, nonregular inputs, missing/extra objects, orphan files, noncanonical generated files; generated download catalogs are size-bounded + canonical + exact.
- Render output goes to absent path; `verify` requires byte identity; `verify-monotonic` rejects identity disappearance, immutable/category mutation, topology change, tombstone reactivation.
- Schema-2→3 migration authenticates canonical old catalog, exact mapping, source objects, old/new routed hashes, and staged render; source never modified.

## Review boundary

Adding a version/tag is a new trust decision even for an existing name. `automatic` = no configured escalation signal; `review-required` = prioritize review/source verification; `blocked` = impossible. A generated manifest with no inline evidence is deliberately valid: authorization is review/merge of exact human requests + generated machine-lock/catalog diff under protected branch policy. Optional typed evidence records genuine work without forcing 700 repetitive files/notes.

Suggested review priority:

```text
source-mismatch(block) > source-unavailable > dormant/publisher/repository discontinuity > build-time executable code > proc macros > native-link code > new dependency/category/feature edges > large source delta > ordinary leaf update
```

For mirrors, inspect exact checksum-bound `.crate`, not only Git: archive can differ. Check `Cargo.toml` + normalized manifest, `build.rs`, proc-macro status, bundled executables/generated data, unsafe/native/network/process code, archive paths/types, features/targets, licensing, dependency changes. Verify SHA-256 against generated facts/curated row. `update-inspect` is inert but emitted archives remain untrusted.

For first-party tags, review tagged commit before reconciliation + produced archive/row afterward. Tag object + peeled commit prevent provenance ambiguity; retained content-addressed bytes survive upstream disappearance/tag mutation.

## Consumer failure-closed configuration

- Every direct dependency uses `registry = "universe"|"pkgre"`; category is curator metadata, not Cargo alias.
- `.cargo/config.toml` defines both aliases, chooses curated default, and replaces crates.io with committed empty directory.
- Commit lockfiles; CI/build/install use `--locked`/`--frozen` from clean Cargo homes.
- Nix/Crane mappings recognize both sparse URLs.
- CI rejects crates.io index sources, old `rust.pkg.re/core|matrix` URLs, unapproved Git sources, and unknown registry URLs.

Cargo has no universal registry allowlist and cannot enforce pkg.re categories: a custom row can direct transitives to arbitrary registries. pkg.re closes that path only by generating + validating every hosted row against permanent homes. Do not trust another custom registry without equivalent routing controls.

## Non-goals + residual risk

- No claim admitted code is benign, correct, maintained, vulnerability-free, or adequately reviewed.
- No defense against malicious toolchain/kernel/hardware, compromised curator/repository/DNS/Pages credentials, or malicious protected-merge approval.
- No registry authentication/write API, private-package ACL, or mutable `cargo publish` endpoint.
- Mixed mirror+Git is supported only through the fixed immutable router; this does not permit a package name to move/switch source class or let catalog data choose an arbitrary URL.
- Source correspondence is best-effort mechanical evidence, not semantic audit/provenance proof. Successful match cannot prove benign/complete source; unavailable public Git becomes review-required; mismatch blocks.
- Planning/apply requires current crates.io sparse/API/archive + promoted public Git availability; outage/deletion/rate limit can stop admission.
- No automatic re-fetch/reproduction of already locked Git tag during `check`; retained archive/row is operational authority.
- No prevention of network/process behavior by admitted build scripts/proc macros/native/runtime code; isolate builds/credentials separately.
- SHA-256 provides integrity, not availability; Pages/DNS outage stops index/Git archive; crates.io outage/removal stops mirror archive; router/GitHub ref/raw outage can stop unknown/new routes while last-known-good known routes continue in memory.
- Removed rows remain visible as yanked; shared active Git content can keep identical archive downloadable; crates.io controls mirror availability.
- Git dependencies bypass registry routing + remain unsupported.
- Generated locks cannot distinguish authorized reviewed change from privileged actor replacing lock + matching objects without history review; branch protection, signed human commits if desired, monotonic releases, retained history provide boundary.

## Operational controls

- Protect `main`; require CI + review; never force-push/bypass; minimize workflow permissions; pin actions/tooling by full SHA.
- Keep catalog public + provenance-free: no consumer names, private paths/manifests/lockfiles/discovery output, credentials, or tokens.
- Keep transient manifests, inspection trees, logs, notes outside `registry/`; `update-apply` copies exact final manifest into `admissions/` + generates its lock atomically.
- Treat category declarations, registry locks, generated download catalog, row/Git objects, and admission pairs as security-sensitive; reject hand edits/unexplained churn.
- Bind `pkgre-download-serve` only to loopback/private namespace; nginx uses fixed `proxy_pass`, overwrites `X-Pkgre-Original-URI` from `$request_uri`, and exposes `/healthz` + `/status`; alert on not-ready/stale commit/refresh errors.
- Publish catalog before deploying the service, verify service before switching any `dl`, and revert `dl` first during rollback; never make the live index depend on an unready router.
- Compare candidate site with deployed `release.json` via `verify-monotonic` before publication.
- Preserve prior rendered releases/backups; periodically verify live hashes + router status/redirects + clean-cache builds across both registries/categories.
- Confirm no active reconciliation before deleting stale guard.
- Enable GitHub secret scanning/push protection; architecture requires no publication token.
