# Security model

## Goal

Reduce ambient Cargo supply-chain authority from “anything resolvable on crates.io/Git” to “exact source rows/checksums + explicit registry/category routes committed in a public catalog.” Unexpected package/version/source/registry/category edges stop at absent desired state, admission/reconciliation failure, or consumer resolution failure instead of falling back to crates.io.

## Trust anchors

- Curators:choose registry/category/name/version/tag, inspect evidence proportionately, review generated catalog diffs, authorize protected merges/removals.
- Public catalog/index:reviewable desired state + immutable registry locks, download catalog, row/archive objects, human admissions, generated admission locks; branch administration remains privileged.
- Human admission:compact exact category/name/version + optional typed evidence; no mutable machine hashes.
- Generated admission lock:complete network-backed facts recomputed at apply + hash-bound into every admitted package lock.
- `pkgre-rust`:enforces schema, admission policy/binding, lifecycle, artifacts, routing, downloads, rendering, migration, and release invariants; bugs can invalidate guarantees.
- Nix pins + Rust/Cargo `1.95.0`:tooling inputs + Git-package semantics.
- TLS,DNS,and the deployment front end are reachability/delivery dependencies;crates.io CDN+registry.npmjs.org are admitted third-party archive dependencies for redirect-delivered archives;Cargo checksum/npm SRI reject bytes differing from curated metadata.
- crates.io sparse/API/archive + public Git during plan/apply:candidate evidence origins; observations gain authority only after exact recomputation + transaction + protected PR review.

## Authority boundaries

Human files select:

```text
registry declaration: (catalog registry, index, download template, audience, optional delivery)
mirror declaration: (catalog registry, category, package, exact version)
publish declaration: (catalog registry, category, package, HTTPS Git, immutable tag)
category policy: exact may-depend-on set
admission request: (qualified category, package, exact version|tag, optional evidence)
removal: omission from retained package key's version/tag list
```

Generated locks select permanently:

```text
(registry, category, normalized Cargo identity, version, source class, lifecycle, archive hash, source-row hash, routed-row hash, origin time, provenance, optional admission hash)
```

`origin time` is written when an identity is first locked (admission, Git publication, or migration):a mirror value is its retained source row `pubtime` and loading re-derives it, refusing a mismatch;a Git-tag value is the tag commit time, or the operator's `--git-tag-time` input for a migrated tag, and no catalog file records it, so only `check-transition` rejects a change of it.

Planning is discovery, not authority. `update-plan` performs current evaluation but outputs compact intent. `update-apply` independently recomputes facts at current time + commits intent/facts atomically. `automatic`/`review-required` prioritize attention; neither bypasses registry PR review.

## Enforced invariants

### Registry/category/identity

- Catalog must contain `main` at `sparse+https://rust.pkg.re/`; every other canonical alias `<name>` maps exactly to `sparse+https://rust.pkg.re/r/<name>/`; additions allowed, released registry identity/index cannot disappear/change.
- `audience` is a lock invariant:a lock copies the declared value when it is created or migrated and is permanent; loading refuses a lock whose recorded `audience` differs from its declaration, so `check` and `lock` fail before a merge, `release.json` does not carry it, and `check-transition` additionally compares the accepted + candidate declarations.
- Current production categories:`main/{general,acp,filesystem,matrix,mcp,pkgre,sse,terminal,yaml}`. Each category is inhabited + has exact committed direct-dependency allowlist; additions allowed, released category/rule cannot disappear/change. The serving gate `check_transition` compares every accepted category's `may-depend-on` rule and every accepted package home, with or without versions, so a widened or narrowed rule and a moved or removed reserved name are refused.
- Current edges:`general→general`; feature category→itself+general; `mcp→general|mcp|sse`; `pkgre→general|pkgre`; same registry grants no implicit edge.
- One permanent registry/category home per normalized package name within a registry; Cargo ASCII case + `-`/`_` collision defense. Each `name + version` has one immutable `mirror|publish` source class/checksum; one name may use both classes across distinct versions. Same normalized name in another registry is a distinct home.
- Dependency home resolution prefers the source registry; if absent, exactly one external-registry home is required; multiple external homes are ambiguous + blocked.
- Routing overwrites every dependency registry field, including optional/dev/build/target-specific + renamed edges; category policy checked before URL routing.

### Serving origin

- Current Rust production metadata advertises the same-host `https://rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}` template and declares `delivery = "retained"`;the `dl.rust.pkg.re` router remains an allowed alternative template + the canonical redirect-route origin. JS uses same-host `https://js.pkg.re/v1/js/<registry>/<sha256>` from first publication. No `dl.js.pkg.re` exists.
- JS route authority (exact marker-v1 bytes behind the edge proxy) is specified in [`js-registry.md`](js-registry.md).
- `pkgre-rust-serve` serves one immutable in-memory snapshot built by `build_snapshot` from a strictly validated catalog:a fixed on-disk tree or a fixed Git ref watched by the service. A watched candidate is published only after the accepted-ref policy and `check_transition` accept it and its snapshot builds;a rejection or failed reload keeps the last-known-good snapshot + accepted ref. No request-time `downloads.json`,GitHub API/raw,live registry metadata,or refresh path exists.
- Raw targets are canonical ASCII origin-form paths only:no query,fragment,trailing slash,empty/`.`/`..` segment,non-ASCII,or percent-encoding except the single `%2f` separator in a `/@scope%2fname` target;anything else answers `400` before method or route lookup. Route identity=Rust exact canonical registry alias+case-sensitive name+canonical SemVer+lowercase 64-hex checksum;an absent canonical path answers `404`.
- Redirect mode answers `GET|HEAD` on a `/v1/...` route with `302` to the route's closed destination (`static.crates.io` crate grammar,or the serving origin's own `crates/<sha256>.crate`);body mode replaces every `/v1/...` redirect with the same-host hash-verified archive body (`200`),and that body is answered from the snapshot's own buffer,so concurrent downloads share one allocation per archive instead of one copy each. Metadata answers `200` with `ETag`+60-second revalidation;archives answer `200` with an immutable one-year cache policy;redirects + errors are `no-store`. Any other method answers `405` with `Allow: GET, HEAD`.
- Destinations are closed:the crates.io redirect is derived from the locked name/version and the first-party redirect from the archive SHA-256;no catalog/user field supplies an unrestricted URL. Body mode fails closed when a store body is missing or does not match its digest.
- The first-party origin is the serving origin's own configuration,never catalog data:`[registry] first-party-origin` is an exact `https` origin (lowercase DNS name or IPv4 literal,optional port;no user information,path beyond `/`,query,or fragment) and every first-party redirect's `Location` is `<first-party-origin>/crates/<sha256>.crate`. `delivery = "redirect"` requires the key and `delivery = "body"` refuses it,so an instance on another host sends its clients to that host and only the production instance names `https://rust.pkg.re`. The projection manifest records the resolved `Location` as evidence only;no rendered or catalog file carries it.
- The service bounds raw target bytes (1024),projection sizes,and concurrent dispatch;the public listener serves a no-JS index at `/`,the admin listener serves `/healthz`,`/readyz`(`503` until a snapshot is installed;the binary installs one before it binds any listener),and `/status` (`schema`,`ready`,`mode`,route counts,uptime);unknown admin paths answer `404`. It listens on configured plain TCP binds (public + admin must differ),ignores Host,and trusts at most one `X-Pkgre-Original-URI` header as the request target (duplicates answer `404`);TLS + transport bounds are deployment-front-end concerns.
- `/healthz` answers `200` while the process runs;`/readyz` requires an installed snapshot;`/status` is local process telemetry. These signals do not replace independent availability monitoring.

### Mirror admission

- Candidate non-yanked + at least 30 exact days old. Implicit planning selects latest eligible stable per active compatibility lane:`major≥1` by major; stable `0.minor` (`minor>0`) by minor. New/inactive names, prereleases, and `0.0.x` require exact planning.
- ≥365-day adjacent publication gap after locked base triggers review; yanked/prerelease rows count as activity; gate persists through post-gap burst until one post-gap identity locks.
- New/inactive name, dormant wake-up, new dependency identity, build-surface change, publisher/repository discontinuity promote best-effort Git source correspondence. Unavailable promoted source=`review-required`; mismatch=`blocked`.
- Unknown/ambiguous dependency home or forbidden category edge=`blocked`. Unsafe/malformed archive, checksum/history inconsistency, catalog drift, or duplicate identity fails rather than downgrades.
- Plan includes automatic + review-required requests; blocked omitted. Generated template is directly applyable; protected PR review authorizes batch. Typed `manual-full-archive`/`manual-source-delta` is optional.
- Apply re-fetches sparse history/rows/archives/API/dependency/source evidence, age, route, decisions; rejects yanked/young/blocked/drifted/evidence-invalid request; never substitutes version.
- Apply transaction fingerprint-guards + stages declaration edits, rows, registry locks, human manifest, generated batch lock, package bindings, and downloads together or not at all.
- Admission pairs are immutable/canonical/regular/paired/catalog-owned. Lock binds adjacent manifest hash + exact requests + complete plan; each package binds full lock hash; reverse coverage exact, no duplicates/orphans. The serving gate `check_transition` keeps every accepted pair byte-identical, keeps every accepted package's binding exactly as it was (present or absent), and requires every crates.io identity new since the accepted catalog to be bound to an admission batch that is new in the candidate; Git-tag identities carry no admission evidence.
- Established catalog rejects ordinary `lock` admission of new mirror identities; bootstrap, empty name anchors, removals, and Git tags remain permitted.

### Artifacts/lifecycle/rendering

- Mirror archive = crates.io artifact checksum in exact retained row; archive verified then discarded unless the registry declares `delivery = "retained"`, which stores it as `objects/crates/<sha256>.crate`; upstream-yanked versions rejected.
- First-party package binds HTTPS repo + literal tag + tag object + peeled commit + package/version/path + pinned Cargo + reproducible archive.
- The Git-tag packaging runs its pinned Cargo and Git from an empty environment with a short allowlist (`PATH`, `TMPDIR`, the certificate variables, an isolated `CARGO_HOME`, and the `rustc` beside the pinned `cargo`), and refuses to run Cargo when its temporary working directory or any directory above it holds `.cargo/config.toml` or `.cargo/config`, which could replace crates.io; `TMPDIR` must point to a directory that no Cargo configuration covers, with symbolic links on the way resolved too.
- Current first-party manifest sets exactly `publish = ["pkgre"]`; every dependency explicitly names `registry = "pkgre"`; path/Git/crates.io/unknown sources fail.
- Archive/source-row/routed-active-row SHA-256 binds every package; only active retained-delivery archives are stored locally: Git tags always, crates.io archives when the registry declares `retained`.
- `downloads.json` equals exact locked-identity projection `(registry, case-sensitive name, version, archive hash, closed redirect|retained delivery)` + is reauthenticated by release verification.
- Lifecycle append-only:additions + `active→removed`; removal retains source row + yanked history, removes unshared retained archive, cannot reverse.
- Existing locks/objects/rows/admissions/homes pass local preflight before public fetch.
- Complete replacement staged, strict-loaded, object-verified, test-rendered, then same-parent installed with rollback.
- Catalog/category/admission/object boundaries reject unrelated paths, traversal, symlinks, nonregular inputs, missing/extra objects, orphan/noncanonical files; downloads are size-bounded + exact.
- Render output must be absent; `verify` requires byte identity; `verify-monotonic` rejects prior registry/category/home/identity disappearance or mutation, tombstone reactivation, and unauthenticated migration.
- Historical schema-3→4 migration (removed command) authenticated canonical source; mapped `universe/*→main/*`, `pkgre/tooling→main/pkgre`; preserved immutable artifacts; recomputed registry-dependent routing/admission bindings; never modified source.
- Historical schema-4→5 migration parsed schema-4 generated locks, the schema-1 download catalog, and every registry/category file strictly, refusing a registry or category file whose `schema` was not 4; it asserted `audience = "public"`, wrote one `admitted-at` per package (crates.io `pubtime`, or the operator's `--git-tag-time`, which is not verified), and replaced the download catalog with the schema-2 delivery model; it wrote only to an absent destination, staged the whole output in a private directory beside it, installed it by one rename only after strict load/policy check/artifact verification/test render, and so left no destination at all on failure. It never modified its source.
- The in-place retained-delivery migration declares `delivery = "retained"` without verifying bodies, and `archive-import` verifies every imported digest before `check`/render/serve accept the catalog; both rewrite the target catalog in place.

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
- No defense against malicious toolchain/kernel/hardware, compromised curator/repository/DNS/hosting credentials, or malicious protected-merge approval.
- No registry authentication/write API, private-package ACL, or mutable `cargo publish` endpoint.
- Same-registry fork cannot reuse already admitted `name + version`; patched bytes require a new version and upstream version conflicts require curator remapping/version policy.
- Source correspondence is best-effort evidence, not semantic audit/provenance proof. Match cannot prove benign/complete source; unavailable Git becomes review-required; mismatch blocks.
- Planning/apply requires current crates.io sparse/API/archive + promoted public Git availability; outage/deletion/rate limit can stop admission.
- Existing Git tag is not re-fetched/reproduced during `check`; retained archive/row is operational authority.
- No prevention of admitted build-script/proc-macro/native/runtime network/process behavior; isolate builds/credentials separately.
- SHA-256/SRI provide integrity,not availability;a front end,DNS,or serving-process outage + any then-required archive origin outage can stop delivery. The last-known-good snapshot lives only in the running process;a restart rebuilds it from the persisted accepted ref,and if that build fails the service exits before it listens,so delivery stops.
- Removed rows remain visible as yanked; shared active retained content can remain downloadable; a `redirect` mirror's availability follows crates.io, a `retained` body follows the registry's own storage.
- Git dependencies bypass registry routing + remain unsupported.
- Locks cannot distinguish legitimate reviewed replacement from privileged actor replacing locks + matching objects without history review; branch protection, protected merge, monotonic releases, and retained history provide boundary.

## Operational controls

- Protect `main`; require CI + review; never force-push/bypass; minimize workflow permissions; pin actions/tooling by full SHA.
- Keep catalog public + provenance-free:no consumer names, private paths/manifests/lockfiles/discovery output, credentials, or tokens.
- Keep transient manifests/inspections/logs outside `registry/`; `update-apply` copies final manifest + generates lock atomically.
- Treat declarations, locks, downloads, objects, and admissions as security-sensitive; reject hand edits/unexplained churn.
- Keep the admin listener private;the service ignores Host and trusts at most one `X-Pkgre-Original-URI` header,so the front end must set or strip it;inspect `/healthz`,`/readyz`,`/status`. Treat these local signals as service telemetry only;maintain independent availability monitoring.
- Compare candidate site with deployed release using `verify-monotonic`; preserve prior releases/backups; periodically verify live rows/routes/checksums + clean-cache build across mirror/Git sources.
- Confirm no reconciliation active before deleting stale guard.
- Enable GitHub secret scanning/push protection; architecture requires no publication token.
