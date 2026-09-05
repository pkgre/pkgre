# Security model

## Goal

Reduce ambient Cargo supply-chain authority from “anything resolvable on crates.io/Git” to “exact source rows/checksums + explicit registry/category routes committed in a public catalog.” Unexpected package/version/source/registry/category edges stop at absent desired state, admission/reconciliation failure, or consumer resolution failure instead of falling back to crates.io.

## Trust anchors

- Curators:choose registry/category/name/version/tag, inspect evidence proportionately, review generated catalog diffs, authorize protected merges/removals.
- Public catalog/index:reviewable desired state + immutable registry locks, download catalog, row/archive objects, human admissions, generated admission locks; branch administration remains privileged.
- Human admission:compact exact category/name/version + optional typed evidence; no mutable machine hashes.
- Generated admission lock:complete network-backed facts recomputed at apply + hash-bound into every admitted package lock.
- `pkgre-rust`:enforces schema, admission policy/binding, lifecycle, artifacts, routing, downloads, rendering, migration, and release invariants; bugs can invalidate guarantees.
- `pkgre-proxy`:maps exact canonical Rust/JS routes to same-path static Pages markers,validates marker-v1+closed destination grammars,and returns only fresh `307` responses;origin/proxy bugs can invalidate availability/redirect guarantees.
- Nix pins + Rust/Cargo `1.95.0`:tooling inputs + Git-package semantics.
- GitHub Pages custom-host TLS+static content,DNS,rain/nginx,and the proxy are route-authorization/delivery dependencies;crates.io CDN+registry.npmjs.org are admitted third-party archive dependencies;Cargo checksum/npm SRI reject bytes differing from curated metadata.
- crates.io sparse/API/archive + public Git during plan/apply:candidate evidence origins; observations gain authority only after exact recomputation + transaction + protected PR review.

## Authority boundaries

Human files select:

```text
mirror declaration: (catalog registry, category, package, exact version)
publish declaration: (catalog registry, category, package, HTTPS Git, immutable tag)
category policy: exact may-depend-on set
admission request: (qualified category, package, exact version|tag, optional evidence)
removal: omission from retained package key's version/tag list
```

Generated locks select permanently:

```text
(registry, category, normalized Cargo identity, version, source class, lifecycle, archive hash, source-row hash, routed-row hash, provenance, optional admission hash)
```

Planning is discovery, not authority. `update-plan` performs current evaluation but outputs compact intent. `update-apply` independently recomputes facts at current time + commits intent/facts atomically. `automatic`/`review-required` prioritize attention; neither bypasses registry PR review.

## Enforced invariants

### Registry/category/identity

- Catalog must contain `main` at `sparse+https://rust.pkg.re/`; every other canonical alias `<name>` maps exactly to `sparse+https://rust.pkg.re/r/<name>/`; additions allowed, released registry identity/index cannot disappear/change.
- Current production categories:`main/{general,acp,filesystem,matrix,mcp,pkgre,sse,terminal,yaml}`. Each category is inhabited + has exact committed direct-dependency allowlist; additions allowed, released category/rule cannot disappear/change.
- Current edges:`general→general`; feature category→itself+general; `mcp→general|mcp|sse`; `pkgre→general|pkgre`; same registry grants no implicit edge.
- One permanent registry/category home per normalized package name within a registry; Cargo ASCII case + `-`/`_` collision defense. Each `name + version` has one immutable `mirror|publish` source class/checksum; one name may use both classes across distinct versions. Same normalized name in another registry is a distinct home.
- Dependency home resolution prefers the source registry; if absent, exactly one external-registry home is required; multiple external homes are ambiguous + blocked.
- Routing overwrites every dependency registry field, including optional/dev/build/target-specific + renamed edges; category policy checked before URL routing.

### Download proxy

- Current pre-P9 Rust production metadata still advertises `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}`;the gated target changes only the host to `rust.pkg.re`. JS uses same-host `https://js.pkg.re/v1/js/<registry>/<sha256>` from first publication. No `dl.js.pkg.re` exists.
- Runtime route authority=exact static marker at the canonical route on the route-selected Pages custom host. No request-time `downloads.json`,GitHub API/raw,live registry metadata,refresh/LKG state,or caller-selected origin exists.
- Route identity=Rust exact canonical registry alias+case-sensitive name+canonical SemVer+lowercase 64-hex checksum;JS exact canonical registry alias+lowercase 64-hex checksum. Query/fragment/percent encoding/non-ASCII/duplicate or dot segments/malformed/oversized targets fail `404` before origin access.
- Origin mapping is closed:resolve only `pkgre.github.io`;connect only to answers:443 admitted by a conservative global-unicast/special-purpose filter whose range boundaries+current Pages addresses are fixture-tested;URL/TLS SNI/WebPKI hostname verification/HTTP Host remain route-selected `rust.pkg.re|js.pkg.re`;root-relative path unchanged;environment proxies+redirects disabled;timeouts,MIME,and body are bounded.
- Both public `GET|HEAD` issue one origin `GET`. Marker route binding+exact template+closed kind/destination grammar are mandatory. Origin marker `404`→404;malformed/protocol/semantic origin error→502;DNS/connect/TLS/body-read/429/5xx→503;valid marker→307;unsupported method→405.
- Rust destinations are exact `static.crates.io` crate/version grammar or route-hash same-host object;JS destinations are exact bounded `registry.npmjs.org` archive grammar or route-hash same-host object. No marker/catalog/user field supplies an unrestricted URL.
- Backend trusts at most one original-target header only across private fixed nginx;nginx overwrites raw `$request_uri` and one literal public Host selected by its fixed vhost,strips credentials,and uses fixed upstreams. Service requires exact route↔Host binding;missing,duplicate,case/port variant,or cross-ecosystem Host fails before origin access. Backend exposure,client-selected Host/header forwarding,URI rewrite/normalization,or variable upstream is forbidden.
- `/healthz` checks process/config;`/readyz` requires recent successes for both fixed origin canaries;`/metrics` has only closed labels. These local signals do not replace isolated long-term certificate+contract monitoring before renewal/production Rust cutover.

### Mirror admission

- Candidate non-yanked + at least 30 exact days old. Implicit planning selects latest eligible stable per active compatibility lane:`major≥1` by major; stable `0.minor` (`minor>0`) by minor. New/inactive names, prereleases, and `0.0.x` require exact planning.
- ≥365-day adjacent publication gap after locked base triggers review; yanked/prerelease rows count as activity; gate persists through post-gap burst until one post-gap identity locks.
- New/inactive name, dormant wake-up, new dependency identity, build-surface change, publisher/repository discontinuity promote best-effort Git source correspondence. Unavailable promoted source=`review-required`; mismatch=`blocked`.
- Unknown/ambiguous dependency home or forbidden category edge=`blocked`. Unsafe/malformed archive, checksum/history inconsistency, catalog drift, or duplicate identity fails rather than downgrades.
- Plan includes automatic + review-required requests; blocked omitted. Generated template is directly applyable; protected PR review authorizes batch. Typed `manual-full-archive`/`manual-source-delta` is optional.
- Apply re-fetches sparse history/rows/archives/API/dependency/source evidence, age, route, decisions; rejects yanked/young/blocked/drifted/evidence-invalid request; never substitutes version.
- Apply transaction fingerprint-guards + stages declaration edits, rows, registry locks, human manifest, generated batch lock, package bindings, and downloads together or not at all.
- Admission pairs are immutable/canonical/regular/paired/catalog-owned. Lock binds adjacent manifest hash + exact requests + complete plan; each package binds full lock hash; reverse coverage exact, no duplicates/orphans.
- Established catalog rejects ordinary `lock` admission of new mirror identities; bootstrap, empty name anchors, removals, and Git tags remain permitted.

### Artifacts/lifecycle/rendering

- Mirror archive = crates.io artifact checksum in exact retained row; archive verified then discarded; upstream-yanked versions rejected.
- First-party package binds HTTPS repo + literal tag + tag object + peeled commit + package/version/path + pinned Cargo + reproducible archive.
- Current first-party manifest sets exactly `publish = ["pkgre"]`; every dependency explicitly names `registry = "pkgre"`; path/Git/crates.io/unknown sources fail.
- Archive/source-row/routed-active-row SHA-256 binds every package; only active Git-tag archives retained locally.
- `downloads.json` equals exact active-lock projection `(registry, case-sensitive name, version, archive hash, closed source enum)` + is reauthenticated by release verification.
- Lifecycle append-only:additions + `active→removed`; removal retains source row + yanked history, removes unshared Git archive, cannot reverse.
- Existing locks/objects/rows/admissions/homes pass local preflight before public fetch.
- Complete replacement staged, strict-loaded, object-verified, test-rendered, then same-parent installed with rollback.
- Catalog/category/admission/object boundaries reject unrelated paths, traversal, symlinks, nonregular inputs, missing/extra objects, orphan/noncanonical files; downloads are size-bounded + exact.
- Render output must be absent; `verify` requires byte identity; `verify-monotonic` rejects prior registry/category/home/identity disappearance or mutation, tombstone reactivation, and unauthenticated migration.
- Schema-3→4 migration authenticates canonical source; maps `universe/*→main/*`, `pkgre/tooling→main/pkgre`; preserves immutable artifacts; recomputes registry-dependent routing/admission bindings; never modifies source.

## Review boundary

Adding version/tag is a new trust decision even for an existing name. `automatic`=no configured escalation; `review-required`=prioritize review/source verification; `blocked`=impossible. A manifest without inline evidence is deliberately valid:authorization is review/merge of exact requests + generated facts/catalog diff. Optional evidence records genuine work without hundreds of repetitive notes.

Priority:

```text
source-mismatch(block) > source-unavailable > dormant/publisher/repository discontinuity > build-time executable code > proc macros > native-link code > new dependency/category/feature edges > large source delta > ordinary leaf update
```

For mirrors inspect checksum-bound `.crate`, not only Git. Check original + normalized manifests, `build.rs`, proc-macro status, bundled executables/data, unsafe/native/network/process code, paths/types, features/targets, licensing, dependency delta. `update-inspect` is inert but emitted archives remain untrusted.

For Git tags review commit before reconciliation + archive/row afterward. Tag object + peeled commit prevent provenance ambiguity; retained content-addressed bytes survive upstream disappearance/tag mutation.

## Consumer failure-closed configuration

- Every direct dependency uses `registry = "pkgre"`; category/catalog alias `main` is curator metadata, not Cargo alias.
- `.cargo/config.toml` defines `registries.pkgre.index = "sparse+https://rust.pkg.re/"`, chooses it as default, and replaces crates.io with committed empty directory.
- Do not replace crates.io with pkgre. Explicit alternate-registry dependencies preserve source identity in `Cargo.lock`; source replacement can silently reinterpret crates.io identities when clone configuration differs.
- Commit lockfiles; CI/build/install use `--locked`/`--frozen` from clean Cargo homes.
- Nix/Crane mappings recognize root sparse URL.
- CI rejects crates.io index sources, old `rust.pkg.re/{core,matrix,universe,pkgre}` registry URLs, unapproved Git sources, and unknown registry URLs.

Cargo has no universal registry allowlist and cannot enforce pkg.re categories:a custom row can direct transitives elsewhere. pkg.re closes that path only by generating/validating every hosted row against homes/policy. Do not trust another custom registry without equivalent controls.

## Non-goals + residual risk

- No claim admitted code is benign, correct, maintained, vulnerability-free, or adequately reviewed.
- No defense against malicious toolchain/kernel/hardware, compromised curator/repository/DNS/Pages credentials, or malicious protected-merge approval.
- No registry authentication/write API, private-package ACL, or mutable `cargo publish` endpoint.
- Same-registry fork cannot reuse already admitted `name + version`; patched bytes require a new version and upstream version conflicts require curator remapping/version policy.
- Source correspondence is best-effort evidence, not semantic audit/provenance proof. Match cannot prove benign/complete source; unavailable Git becomes review-required; mismatch blocks.
- Planning/apply requires current crates.io sparse/API/archive + promoted public Git availability; outage/deletion/rate limit can stop admission.
- Existing Git tag is not re-fetched/reproduced during `check`; retained archive/row is operational authority.
- No prevention of admitted build-script/proc-macro/native/runtime network/process behavior; isolate builds/credentials separately.
- SHA-256/SRI provide integrity,not availability;Pages custom-host TLS/DNS/rain/nginx/proxy/crates.io/npmjs outage can stop delivery. Runtime authorization has no independent LKG:an unavailable marker origin fails `503`;a missing marker fails `404`.
- Removed rows remain visible as yanked; shared active Git content can remain downloadable; crates.io controls mirror availability.
- Git dependencies bypass registry routing + remain unsupported.
- Locks cannot distinguish legitimate reviewed replacement from privileged actor replacing locks + matching objects without history review; branch protection, protected merge, monotonic releases, and retained history provide boundary.

## Operational controls

- Protect `main`; require CI + review; never force-push/bypass; minimize workflow permissions; pin actions/tooling by full SHA.
- Keep catalog public + provenance-free:no consumer names, private paths/manifests/lockfiles/discovery output, credentials, or tokens.
- Keep transient manifests/inspections/logs outside `registry/`; `update-apply` copies final manifest + generates lock atomically.
- Treat declarations, locks, downloads, objects, and admissions as security-sensitive; reject hand edits/unexplained churn.
- Bind proxy only loopback/private;nginx fixed proxy overwrites `X-Pkgre-Original-URI`;inspect `/healthz`,`/readyz`,`/metrics`. Treat these local signals as service telemetry only;complete the isolated fixed-target certificate/contract monitoring gate before renewal observation or production Rust cutover.
- Compare candidate site with deployed release using `verify-monotonic`; preserve prior releases/backups; periodically verify live rows/routes/checksums + clean-cache build across mirror/Git sources.
- Confirm no reconciliation active before deleting stale guard.
- Enable GitHub secret scanning/push protection; architecture requires no publication token.
