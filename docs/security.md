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
- The first-party origin is the serving origin's own configuration,never catalog data:`[registry] first-party-origin` is an exact `https` origin (a lowercase DNS name or four decimal IPv4 octets,an optional port other than the dropped default `443`,no `xn--` label,no IPv6 literal,no user information,path beyond `/`,query,or fragment) and every first-party redirect's `Location` is `<first-party-origin>/crates/<sha256>.crate`. `delivery = "redirect"` requires the key and `delivery = "body"` refuses it,so each redirect-mode instance sends its clients to its own configured origin. The projection manifest records the resolved `Location` as evidence only;no rendered or catalog file carries it.
- The service bounds raw target bytes (1024),projection sizes,and concurrent dispatch;the public listener serves a no-JS index at `/`,the admin listener serves `/healthz`,`/readyz`(`503` until a snapshot is installed;the binary installs one before it binds any listener),and `/status` (`schema`,`ready`,`mode`,route counts,uptime);unknown admin paths answer `404`. It listens on configured plain TCP binds (public + admin must differ),ignores Host,and trusts at most one `X-Pkgre-Original-URI` header as the request target (duplicates answer `404`);TLS + transport bounds are deployment-front-end concerns.
- `/healthz` answers `200` while the process runs;`/readyz` requires an installed snapshot;`/status` is local process telemetry. These signals do not replace independent availability monitoring.

### Mirror admission

- Candidate non-yanked + at least 30 exact days old. Implicit planning selects latest eligible stable per active compatibility lane:`major≥1` by major; stable `0.minor` (`minor>0`) by minor. New/inactive names, prereleases, and `0.0.x` require exact planning.
- ≥365-day adjacent publication gap after locked base triggers review; yanked/prerelease rows count as activity; gate persists through post-gap burst until one post-gap identity locks.
- New/inactive name, dormant wake-up, new dependency identity, build-surface change, publisher/repository discontinuity promote best-effort Git source correspondence. Unavailable promoted source=`review-required`; mismatch=`blocked`.
- Source correspondence compares every archive member with the public tree at the exact commit, except the files Cargo writes while packaging:`.cargo_vcs_info.json`,`.cargo-ok`,the root `Cargo.toml` that has a root `Cargo.toml.orig` beside it,and the package root `Cargo.lock`. Cargo writes that manifest pair only at the package root,so a nested `X/Cargo.toml` is compared like any other file even when `X/Cargo.toml.orig` sits beside it. Cargo generates the root lock file at packaging time whether or not the repository tracks one,rewrites it when it does,and never reads a dependency's lock file,so it carries no code into a consumer's build;the archive's bytes,lock file included,remain checksum-verified + retained. The comparison report records each such member as `cargo-generated`;a `Cargo.lock` anywhere else in the archive is compared like any other file.
- The compared package directory is the archive's `path_in_vcs`. Cargo wrote that field only from 1.58,so an archive that carries none is located instead:the one directory whose `Cargo.toml` has the exact bytes of the archive's `Cargo.toml.orig`,over at most 512 manifests,each read within 1 MiB (a larger one is `Unavailable` with `repository-package-manifest-exceeds-its-bound`). None,or several,is `Unavailable` with `repository-package-path-not-located`/`-ambiguous` rather than a mismatch. The located directory is evidence for the reviewer,not a claim about the archive:a generated admission lock's source evidence keeps `path` as the archive's own `path_in_vcs` (empty when it carries none),and the located directory appears in the planning log + in `update-inspect`'s `inspection.toml`,both of which name it beside the compared members.
- Cargo copies `readme` and `license-file` into the package root when they live outside the package directory,including `readme.workspace = true`/`license-file.workspace = true` resolved through the workspace root's `[workspace.package]` (the nearest ancestor whose `[workspace]` members include the package). Such a member is compared with the repository file Cargo copied it from and recorded as `copied`;a copy that differs is still a mismatch,and a path outside the repository is never followed,so that member stays missing. A copy never takes a name Cargo generates in the package root (`.cargo_vcs_info.json`,`.cargo-ok`,`Cargo.toml`,`Cargo.toml.orig`,`Cargo.lock`),and two fields that would copy different files to one name copy neither,so those members are compared like any other.
- Symbolic links are resolved inside the repository,as Cargo follows them when packaging:a linked file is compared with its target's bytes + mode,and a file below a linked directory at its target path. An escape above the repository root,a loop,or a chain longer than 16 redirects is `Unavailable` with a specific reason.
- A submodule's checked-out files are compared in the submodule's own tree:the tree's root `.gitmodules` gives the URL,that URL must name a supported public repository,and it is fetched at the gitlink's exact commit with the same bounded fetch. The tree is identified by repository + commit,so two gitlinks to one repository at different commits are read at their own commits,and the report records the commit it read. At most 8 submodule commits + no nesting beyond one level. Each fetch is followed by a size + file-count check of the temporary repository (256 MiB + 100,000 files over the root fetch and all its submodules),and the whole comparison is bounded in wall-clock time (900 s; once a member has already differed,a budget that runs out leaves the result a mismatch rather than unavailable). An unsupported URL,a missing `.gitmodules` entry,a failed or oversized fetch,or an exhausted budget is `Unavailable` with a specific reason.
- A repository URL is normalized before use:one trailing `/`,a GitHub `/tree/<ref>/…` or `/blob/<ref>/…` path reduced to the repository,and a `.git` suffix dropped. A GitHub owner and repository name compare without regard to case;other hosts compare exactly,so a Trusted Publishing repository + a version `repository` still agree only when they name the same repository.
- The comparison report names each member's expected path,compared path,resolved path,submodule,copied flag,digests + disposition (`match`,`different`,`missing`,`cargo-generated`). Planning logs the reason of every `Unavailable` + the first 20 differing or missing archive paths;`update-inspect` writes the complete report into `inspection.toml` beside the digest.
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
- Current first-party manifest sets exactly `publish = ["pkgre"]`; every dependency explicitly names `registry = "pkgre"`; Git/crates.io/unknown sources fail; a `path` dependency is accepted only on a package the catalog publishes from the same repository and tag at that tag's version, required as exactly `=X.Y.Z`, so a `path` dependency cannot reach outside its own tag.
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

### Self-publishing to crates.io

- crates.io packages are derived from the release tag and proven against the curated archive; the routine then builds each missing crate with Cargo's verification, and finally packages each of them the way `cargo publish` packages them and requires that archive, the one it uploads, to equal `self-publish/crates-io.lock`. A crates.io version is therefore the curated package with a mechanically rewritten manifest, not a second build of the repository.
- The routine publishes only what the `pkgre` registry already serves, unyanked, with the checksum that `registry/main.lock` records, and only from a clean checkout whose `HEAD` is contained in the remote-tracking `origin/main`, so an uploaded crate is merged and served before it reaches crates.io.
- crates.io may hold a version with another archive, or lack one that a release depends on: the routine refuses rather than force anything, and never yanks, deletes, or changes owners. A version that `crates-io.toml` records as abandoned is skipped, so the rest of its release still reaches crates.io.
- The crates.io API token is created by the person who uploads, with only the `publish-new` and `publish-update` endpoint scopes, restricted to the crate names this workflow publishes, and a short expiry. It stays on the machine of the person who uploads: it never enters a repository, CI, a log, or the catalog, and the architecture requires no publication token.
- The routine reads the token only with `--upload`, after every check passed, from a prompt that does not echo or from one line of standard input, never from its environment, its command line, or a file. The prompt is the recommended way to give it: a token piped on standard input waits in the routine's standard input while the crates' build scripts and proc macros run. It refuses to start while `CARGO_REGISTRY_TOKEN` or a `CARGO_REGISTRIES_<NAME>_TOKEN` is set, names the variable when it refuses, and never names a value.
- With `--upload`, the routine makes its own process non-dumpable (`PR_SET_DUMPABLE`, 0) before it starts any child, so that no other process of the same user can open its `/proc` files, its standard input among them, while a token could be in reach.
- Every child process of the routine, Git, Cargo, and `curl` alike, starts from an empty environment with the allowlist of the catalog's own packaging: `PATH`, `TMPDIR`, the certificate variables, an isolated `CARGO_HOME`, and the `rustc` beside the pinned `cargo`, with no `RUSTC_WRAPPER`. Only one upload process at a time also gets the token, through its own environment; its output has every occurrence of the token replaced before the routine reports anything, and the token is dropped once the uploads finish.
- The dry run and step 5 of an upload build the crates, so they run the build scripts and proc macros of the release and of its dependencies, as the same user. Step 5 runs Cargo in a process group of its own, with a null standard input, and ends that group when Cargo returns, so that no process the package code started outlives it or reads the routine's standard input through Cargo. An interrupt during step 5 ends the routine without unwinding, so Cargo and the package code it started keep running until they finish, in the derivation's temporary directory, which stays behind; no token is in reach at that point, and the next run compares the packages again. The residual risk is a process that package code detaches from its group: such a process can still read the environment of the upload process, which holds the token.
- `cargo publish --no-verify` keeps package code from running while the token is in the environment; the verified packaging and the packaging the upload compares with `crates-io.lock` both happen earlier, while no token is in reach, and no package code runs between that comparison and the upload.
- A consumer who does not pass `--locked` gets crates.io's own resolution, not the curated one: the catalog's guarantees cover the bytes of the packages it serves, and crates.io resolves the dependencies of a build that skips the lock file.

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
