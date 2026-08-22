# Security model

## Goal

Reduce ambient Cargo supply-chain authority from “anything resolvable on crates.io/Git” to “exact reviewed artifacts + explicit dependency routes committed in a small public catalog.” Unexpected package/version/source/registry edges should stop at missing desired state, reconciliation failure, or consumer resolution failure rather than silently fall back to crates.io.

## Trust anchors

- Curators: decide package/version/home, inspect newly materialized exact bytes, approve permanent source evidence, review dependency/capability changes, and authorize removal.
- Public catalog/index repository: reviewable desired state + immutable lock/object history; branch/repository administration remains privileged.
- `pkgre-indexer`: resolves new declarations and enforces schema, lifecycle, artifact, routing, rendering, and release invariants; implementation bugs can invalidate guarantees.
- Nix pins + Rust/Cargo `1.95.0`: tooling build inputs and first-party packaging semantics.
- GitHub Pages + TLS/DNS: availability + delivery of rows/archives; Cargo archive checksums detect modified archives after a trusted row is obtained.
- crates.io/Git upstreams during first materialization: origins, not continuing ambient authorities; their exact output remains uncommitted until audit + catalog review.

## Authority boundaries

Human `<registry>.toml` selects only:

```text
mirror: (registry, package, exact version)
publish: (pkgre, package, credential-free HTTPS Git repository, immutable tag)
removal: omission from retained package key's version/tag list
```

Generated locks permanently select:

```text
(registry, normalized Cargo package identity, version, source class, lifecycle state, archive hash, source-row hash, routed-active-row hash, origin provenance)
```

Network materialization is candidate generation inside an uncommitted working tree. A successful `lock` proves internal consistency, not code safety; the result gains authority only after exact object/lock review + protected-branch merge. Existing identities require no network access during reconciliation.

## Enforced invariants

- Exactly three canonical registries/URLs/download template: `core`, `matrix`, `pkgre`.
- Fixed edge layers: `core→core`; `matrix→core|matrix`; `pkgre→core|matrix|pkgre`.
- One permanent registry home + `mirror|publish` source class for every reserved package name; global collision defense under Cargo ASCII case + `-`/`_` normalization.
- Explicit home required for every dependency identity; routing overwrites all source-row registry fields, including optional/dev/build/target-specific + renamed edges.
- Every mirrored archive is byte-identical to its crates.io artifact; exact selected upstream row retained; archive checksum cross-checked with row `cksum`; upstream-yanked versions rejected at import.
- Every first-party package binds credential-free HTTPS repository + literal tag + tag object + peeled commit + package/version/path + pinned Cargo version + byte-identical double packaging.
- Every first-party manifest sets exactly `publish = ["pkgre"]`; every dependency explicitly names one canonical curated registry; path/Git/crates.io/unknown dependency sources fail.
- Exact archive/source-row/routed-active-row SHA-256 permanently binds every package identity.
- Lifecycle is append-only: additions + `active→removed` only; removal retains source evidence + yanked row, removes unshared archive, and cannot be reversed.
- Existing objects, locks, source rows, and routed rows pass complete local preflight before any new public artifact fetch.
- Complete replacement catalog is staged, strictly reloaded, object-verified, and test-rendered before same-parent transactional install with rollback.
- Catalog root and object boundaries reject unrelated entries, traversal, symlink substitution, non-regular inputs, missing/extra content-addressed objects, and non-canonical generated locks.
- Render output is built at a new path; `verify` requires byte-for-byte tree identity; `verify-monotonic` rejects published identity disappearance, immutable mutation, topology change, and tombstone reactivation.

## Review boundary

Adding a version/tag is a new trust decision even when package name/home already exists. Review exact generated diff + object bytes before commit. “Package absent until explicitly listed” defeats surprise namespace insertion but does not establish source safety.

Suggested review priority:

```text
build-time executable code > proc macros > native-link code > direct/runtime deps > new dependency edges/features > ordinary leaf updates
```

For mirrors, inspect the exact `.crate`, not only an upstream Git repository: archive source can differ. Inspect `Cargo.toml`, normalized `Cargo.toml`, `build.rs`, proc-macro status, bundled executables/generated data, unsafe/native/network/process code, archive paths/types, feature/target edges, and licensing. Compare dependency rows between approved versions.

For first-party tags, review the tagged commit before reconciliation and the produced archive/row afterward. Locking both tag object + peeled commit prevents ambiguity in committed provenance; exact package bytes remain usable even if upstream later disappears or mutates a tag.

## Consumer failure-closed configuration

- Every direct manifest dependency uses `registry = "core"|"matrix"|"pkgre"`.
- `.cargo/config.toml` defines all aliases, chooses a curated default, and replaces `[source.crates-io]` with a committed empty directory.
- Lockfiles are committed; CI/build/install use `--locked` or `--frozen` from clean Cargo homes.
- Nix/Crane source mappings recognize all three sparse registry URLs.
- CI rejects `registry+https://github.com/rust-lang/crates.io-index`, `sparse+https://index.crates.io/`, unapproved Git sources, and unknown registry URLs in lockfiles.

Cargo has no universal registry allowlist: a custom-registry row can direct transitive dependencies to arbitrary registry URLs. pkg.re closes that path only because it generates + validates every hosted row. Never treat an unrelated custom registry as a trusted layer without equivalent transparent routing controls.

## Non-goals + residual risk

- No claim that approved code is benign, correct, maintained, vulnerability-free, or adequately reviewed.
- No defense against malicious compiler/toolchain/kernel/hardware, compromised curator/repository/DNS/Pages credentials, or malicious changes approved through protected review.
- No registry authentication/write API, private-package access control, or mutable `cargo publish` endpoint.
- No cryptographic proof connecting crates.io archives to an upstream Git repository beyond the exact crates.io row/checksum/archive identity.
- No automatic re-fetch/reproduction of an already locked Git tag during `check`; the retained content-addressed archive/row, not continuing upstream tag availability, is operational authority.
- No prevention of arbitrary network/process behavior by approved build scripts/proc macros/native tools/runtime code; isolate builds and credentials separately.
- SHA-256/content addressing provides integrity, not availability; Pages/DNS/repository outages can stop clean builds.
- Removed sparse rows remain visible as yanked historical evidence; shared active content can keep an identical archive hash downloadable.
- Git dependencies bypass registry routing and are outside the supported dependency model for curated consumers and first-party publication.
- Generated locks cannot distinguish an authorized reviewed repository change from a privileged actor replacing lock + matching objects before history review; branch protection, review, signed human commits if desired, release monotonicity, and retained releases provide the history boundary.

## Operational controls

- Protect `main`; require CI + review; never force-push/bypass; minimize workflow permissions; pin actions by full commit SHA.
- Keep catalog repository public + provenance-free: no consuming-project names, private paths/manifests/lockfiles, discovery output, credentials, or tokens.
- Treat generated lock/object changes as security-sensitive; reject hand-edited locks and unexplained object churn.
- Compare candidate site with prior deployed `release.json` via `verify-monotonic` before deployment.
- Preserve prior rendered releases/backups; periodically verify live hashes and perform clean-cache recovery builds across all registry layers.
- Confirm no reconciliation is active before manually deleting a stale sibling guard.
- Enable GitHub secret scanning/push protection where available; this read-only architecture should contain no registry publication token.
