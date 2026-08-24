# Security model

## Goal

Reduce ambient Cargo supply-chain authority from “anything resolvable on crates.io/Git” to “exact reviewed artifacts + explicit registry/category dependency routes committed in a small public catalog.” Unexpected package/version/source/registry/category edges should stop at missing desired state, reconciliation failure, or consumer resolution failure rather than silently fall back to crates.io.

## Trust anchors

- Curators: decide package/version/category home, inspect exact planned bytes/evidence, add evidence-bound approvals when policy requires one, review generated catalog changes, and authorize removal.
- Public catalog/index repository: reviewable desired state + immutable lock/object/admission history; branch/repository administration remains privileged.
- Canonical update plan: binds catalog fingerprint, original evaluation time, exact sparse history/candidate/base, API/archive/dependency/source evidence, policy result, and later human approval assertions; plans/notes remain outside the trusted catalog until successful admission.
- `pkgre-indexer`: resolves candidates, recomputes evidence, and enforces schema, update policy, approval/admission binding, lifecycle, artifact, category routing, rendering, migration, and release invariants; implementation bugs can invalidate guarantees.
- Nix pins + Rust/Cargo `1.95.0`: tooling build inputs and first-party packaging semantics.
- GitHub Pages + TLS/DNS: availability + delivery of rows/Git-tag archives; crates.io CDN: availability + delivery of mirror archives; Cargo checksums reject bytes that differ from a trusted curated row.
- crates.io sparse/API/archive + public Git upstreams during planning/apply: metadata/source origins whose security-relevant observations are bound into the plan, revalidated before admission, and remain uncommitted until policy/review passes; the raw crates.io API response hash is retained as planning provenance but is not required to remain stable because responses include mutable non-decision fields; crates.io remains the mirror-byte availability provider, constrained by the permanently locked checksum.

## Authority boundaries

Human registry/category TOML selects only:

```text
mirror: (universe, category, package, exact version)
publish: (pkgre, tooling, package, credential-free HTTPS Git repository, immutable tag)
category policy: exact canonical may-depend-on set
removal: omission from retained package key's version/tag list
```

Generated locks permanently select:

```text
(registry, category, normalized Cargo package identity, version, source class, lifecycle state, archive hash, source-row hash, routed-active-row hash, origin provenance)
```

Network planning/materialization is candidate generation outside authoritative catalog state. `automatic` means no separate approval assertion is required, not that the change bypasses source-control review: a result gains authority only after exact generated diff + evidence review and protected-branch merge. Existing identities require no network access during local `check`/reconciliation.

## Enforced invariants

- Exactly two canonical registries/URLs/source-class downloads: mirror-only `universe` uses `https://static.crates.io/crates`; publish-only `pkgre` uses the pkg.re content-addressed template; mixed classes fail because Cargo provides one `dl` URL per registry.
- New mirror candidates must be non-yanked + at least 30 exact days old. Implicit planning selects only the latest eligible stable release in each active compatibility lane (`major≥1` by major; stable `0.minor`, `minor>0`, by minor); prereleases, `0.0.x`, new names, and inactive names require exact selection.
- A candidate after a ≥365-day adjacent publication gap from its locked base requires review; yanked/prerelease publications count as activity, and the gate persists through a post-gap burst until one post-gap identity is locked.
- New/inactive names, dormant wake-ups, new dependency identities, build-surface changes, and publisher/repository discontinuities promote best-effort Git source correspondence. Unavailable promoted source requires review; archive/source mismatch blocks admission.
- Update outcomes are exact: `automatic` carries no approval assertion, `review-required` carries exactly one candidate/note/time-bound assertion of the required scope, and `blocked` cannot be admitted. All outcomes still require ordinary catalog diff review + protected merge.
- Plans bind canonical policy/evidence + an exact catalog fingerprint. Apply accepts only nonfuture plans no more than seven exact days old, re-plans the same identities at the original evaluation time, rejects upstream/catalog drift, and installs declarations/rows/locks/admissions through the same guarded whole-catalog transaction + rollback boundary.
- Every updater-admitted mirror lock reverse-binds exactly one immutable canonical `_reviews/admissions/<candidate-binding-sha256>.toml` record, and every record maps back to exactly one matching lock identity/route/archive/row. Established catalogs reject direct-lock admission of new mirror identities; bootstrap, empty name anchors, removals, and Git tags remain permitted.
- Exact canonical category topology: `universe/{general,acp,filesystem,matrix,mcp,sse,terminal,yaml}` + `pkgre/tooling`; every category is inhabited and declares its complete fixed direct-dependency allowlist.
- Category edges: `general→general`; each universe feature category → itself + `general`; `mcp` additionally → `sse`; `tooling→tooling|general`; no implicit permission arises merely because two packages share `universe`.
- One permanent registry/category home + `mirror|publish` source class for every reserved package name; global collision defense under Cargo ASCII case + `-`/`_` normalization.
- Explicit home required for every dependency identity; routing overwrites all source-row registry fields, including optional/dev/build/target-specific + renamed edges; category policy is checked before registry URL routing.
- Every mirrored archive is byte-identical to its crates.io artifact when locked; exact selected upstream row retained; archive checksum cross-checked with row `cksum`; bytes then discarded; upstream-yanked versions rejected at import.
- Every first-party package binds credential-free HTTPS repository + literal tag + tag object + peeled commit + package/version/path + pinned Cargo version + byte-identical double packaging.
- Every first-party manifest sets exactly `publish = ["pkgre"]`; every dependency explicitly names canonical curated registry `universe` or `pkgre`; path/Git/crates.io/unknown dependency sources fail.
- Exact archive/source-row/routed-active-row SHA-256 permanently binds every package identity; only active Git-tag archive bytes are retained locally.
- Lifecycle is append-only: additions + `active→removed` only; removal retains source evidence + yanked row, removes an unshared retained Git archive, and cannot be reversed.
- Existing retained objects, locks, source rows, category/name anchors, and routed rows pass complete local preflight before any new public artifact fetch.
- Complete replacement catalog is staged, strictly reloaded, object-verified, and test-rendered before same-parent transactional install with rollback.
- Catalog root/category/object boundaries reject unrelated entries, traversal, symlink substitution, non-regular inputs, missing/extra content-addressed objects, orphan category files, and noncanonical generated locks.
- Render output is built at a new path; `verify` requires byte-for-byte tree identity; `verify-monotonic` rejects published identity disappearance, immutable/category mutation, topology change, and tombstone reactivation.
- Schema-2→3 migration strictly authenticates the canonical old catalog, exact package/category mapping, source object bytes, old/new routed hashes, and staged render before installing to an absent destination; it never modifies source.

## Review boundary

Adding a version/tag is a new trust decision even when package name/home already exists. `automatic` means policy found no configured escalation reason and therefore requires no explicit approval assertion; it still requires review of the exact generated catalog diff under protected-branch policy. `review-required` requires one evidence-bound `source-delta` approval for an active package with a meaningful base, or `full-archive` approval for a new/inactive package; `blocked` is inadmissible. “Package absent until explicitly listed” defeats surprise namespace insertion but does not establish source safety.

Suggested review priority:

```text
build-time executable code > proc macros > native-link code > direct/runtime deps > new dependency/category edges/features > ordinary leaf updates
```

For mirrors, separately fetch + inspect the exact crates.io `.crate`, not only an upstream Git repository: archive source can differ. Verify its SHA-256 equals `crate-sha256`; inspect `Cargo.toml`, normalized `Cargo.toml`, `build.rs`, proc-macro status, bundled executables/generated data, unsafe/native/network/process code, archive paths/types, feature/target edges, and licensing. Compare dependency rows between approved versions.

For first-party tags, review the tagged commit before reconciliation and the produced archive/row afterward. Locking both tag object + peeled commit prevents ambiguity in committed provenance; exact package bytes remain usable even if upstream later disappears or mutates a tag.

## Consumer failure-closed configuration

- Every direct manifest dependency uses `registry = "universe"|"pkgre"`; category is curator metadata and does not create another Cargo alias.
- `.cargo/config.toml` defines both aliases, chooses a curated default, and replaces `[source.crates-io]` with a committed empty directory.
- Lockfiles are committed; CI/build/install use `--locked` or `--frozen` from clean Cargo homes.
- Nix/Crane source mappings recognize both sparse registry URLs.
- CI rejects `registry+https://github.com/rust-lang/crates.io-index`, `sparse+https://index.crates.io/`, old `rust.pkg.re/core|matrix` URLs, unapproved Git sources, and unknown registry URLs in lockfiles.

Cargo has no universal registry allowlist, and Cargo cannot enforce pkg.re categories: a custom-registry row can direct transitive dependencies to arbitrary registry URLs. pkg.re closes that path only because it generates + validates every hosted row against permanent category homes. Never treat an unrelated custom registry as a trusted layer without equivalent transparent routing controls.

## Non-goals + residual risk

- No claim that approved code is benign, correct, maintained, vulnerability-free, or adequately reviewed.
- No defense against malicious compiler/toolchain/kernel/hardware, compromised curator/repository/DNS/Pages credentials, or malicious changes approved through protected review.
- No registry authentication/write API, private-package access control, or mutable `cargo publish` endpoint.
- No support yet for mirror + Git publications in one registry; doing so safely requires a pkg.re dispatch/redirect download endpoint while retaining permanent source-class/checksum semantics.
- Source correspondence is mechanical + best-effort, not a semantic audit or cryptographic provenance proof. A successful comparison cannot prove benign/complete source, and unavailable/unsupported public Git trees degrade to review-required evidence rather than silently passing; a byte mismatch blocks.
- Planning/apply depends on current crates.io sparse/API/archive and promoted public-Git availability. An outage, deletion, rate limit, or unsupported Git tree can prevent exact evidence creation/revalidation even when previously observed bytes were sound.
- No automatic re-fetch/reproduction of an already locked Git tag during `check`; the retained content-addressed archive/row, not continuing upstream tag availability, is operational authority.
- No prevention of arbitrary network/process behavior by approved build scripts/proc macros/native tools/runtime code; isolate builds and credentials separately.
- SHA-256/content addressing provides integrity, not availability; Pages/DNS/repository outages stop index/Git-tag access, while crates.io CDN outages or archive removal stop mirror downloads.
- Removed sparse rows remain visible as yanked historical evidence; shared active Git content can keep an identical retained archive hash downloadable; crates.io controls continued mirror-byte availability.
- Git dependencies bypass registry routing and are outside the supported dependency model for curated consumers and first-party publication.
- Generated locks cannot distinguish an authorized reviewed repository change from a privileged actor replacing lock + matching objects before history review; branch protection, review, signed human commits if desired, release monotonicity, and retained releases provide the history boundary.

## Operational controls

- Protect `main`; require CI + review; never force-push/bypass; minimize workflow permissions; pin actions by full commit SHA.
- Keep catalog repository public + provenance-free: no consuming-project names, private paths/manifests/lockfiles, discovery output, credentials, or tokens.
- Keep plans, approval notes, and inert inspection trees outside managed `registry/`; they are review inputs, not catalog files. Admit declaration/row/lock plus canonical `_reviews/admissions/` evidence in one indexer transaction and commit/review that complete diff atomically.
- Treat category declaration/generated lock/object/admission changes as security-sensitive; reject hand-edited locks/admissions, unexplained source-row churn, or unexplained retained Git-archive churn.
- Compare candidate site with prior deployed `release.json` via `verify-monotonic` before deployment.
- Preserve prior rendered releases/backups; periodically verify live hashes and perform clean-cache recovery builds across both registries + representative categories.
- Confirm no reconciliation is active before manually deleting a stale sibling guard.
- Enable GitHub secret scanning/push protection where available; this read-only architecture should contain no registry publication token.
