# Security model

## Goal

Reduce ambient Cargo supply-chain authority from “anything resolvable on crates.io/Git” to “exact artifacts + dependency routes explicitly approved in a small public catalog.” Failure mode should be missing-package/build failure rather than silent fallback to crates.io.

## Trust anchors

- Curators: decide package/version/home, inspect exact candidate bytes, approve immutable source evidence, review dependency changes.
- Public catalog/index repository: reviewable declaration + historical release record; branch/repository administration remains privileged.
- GitHub Pages + TLS/DNS: availability + delivery of index rows/archives; Cargo archive checksums detect modified package bytes after a trusted index row is obtained.
- GitHub/crates.io/Git upstreams during candidacy: origins, not automatic authorities; resulting exact bytes/hashes require explicit catalog approval.
- Nix input pins + Rust/Cargo `1.95.0`: build/toolchain trust anchor for the indexer and first-party packaging.
- `pkgre-indexer`: enforces declared policy; bugs can invalidate guarantees.

## Enforced invariants

- Exact fixed registry topology + canonical URLs; no catalog-defined hidden registry.
- Explicit home for every approved/referenced package name.
- Registry-layer edge policy: `core→core`; `matrix→matrix|core`; `pkgre→pkgre|matrix|core`.
- Dependency routing overwrites upstream registry fields, including optional/dev/build/target-specific + renamed dependencies.
- Exact archive SHA-256 + un-routed-row SHA-256 bind every approval.
- Imported archives byte-identical to crates.io artifacts; upstream checksum cross-checked.
- First-party Git packages bind HTTPS repository + tag + full peeled commit + package/subdir/version + deterministic pinned-Cargo output.
- Global package-name collision defense under Cargo ASCII case + `-`/`_` normalization.
- Output built from scratch; render verification is byte-for-byte; published identities are monotonic except yank state.
- Filesystem boundaries reject traversal, symlink substitution, and non-regular inputs.

## Candidate/approval boundary

Candidate generation is deliberately non-authoritative. Network-fetched bytes, generated hashes, approval stanzas, and homes remain candidates until a curator audits + commits them. “Clicked approve” can prevent namespace surprise/new-package insertion, but does not prove source safety; review depth should track capability (build script/proc macro/native code/runtime exposure).

Suggested review priority:

```text
build-time executable code > native-link code > direct/runtime deps > new dependency edges > ordinary leaf updates
```

Review exact `.crate` bytes: upstream Git source alone can differ from the published artifact. Inspect `Cargo.toml` + normalized `Cargo.toml`, `build.rs`, proc-macro crates, bundled binaries/generated data, unsafe/native code, tests/examples excluded from compilation assumptions, and archive path/type safety.

## Consumer failure-closed configuration

- Every direct manifest dependency uses `registry = "core"|"matrix"|"pkgre"`.
- `.cargo/config.toml` defines all aliases, chooses a non-crates.io default, and replaces `[source.crates-io]` with a committed empty directory.
- Lockfiles are committed; builds use `--locked`/`--frozen` in a clean Cargo home.
- Nix/Crane source mappings recognize all three sparse registry URLs.
- CI asserts no `registry+https://github.com/rust-lang/crates.io-index` or `sparse+https://index.crates.io/` source remains in lockfiles.

Cargo does not provide a universal registry allowlist: an approved custom-registry row can route a dependency to another registry URL. This design prevents that by controlling + validating every published row. Do not consume third-party custom registries as trusted layers unless they provide equivalent transparent routing guarantees.

## Non-goals / residual risk

- No claim that approved code is benign, correct, maintained, or vulnerability-free.
- No defense against malicious compiler/toolchain/kernel/hardware, compromised curator/admin credentials, or malicious changes approved by review.
- No registry authentication API, private-package access control, or mutable `cargo publish` endpoint.
- No automatic source-code provenance proof for crates.io imports beyond exact sparse-row/archive identity.
- No prevention of arbitrary network/process behavior by package build scripts once approved and compiled; isolate builds separately.
- SHA-256/content addressing provides integrity, not availability; Pages outage/DNS failure can stop clean builds.
- Yank state is advisory + intentionally mutable; lockfile and Cargo behavior still apply.
- Git dependencies bypass registry policy and are therefore outside the supported dependency model for curated projects.

## Operational controls

- Protect `main`; require CI + review; minimize Actions permissions; pin actions by full commit SHA.
- Keep deployment repository public + provenance-free: never include consuming-project names, private paths/manifests/lockfiles, or discovery reports.
- Compare each candidate site with prior `release.json` via `verify-monotonic` before deploy.
- Preserve prior rendered releases/backups; periodically perform clean-cache recovery builds.
- Enable GitHub secret scanning/push protection where plan supports it; never place registry tokens in this read-only architecture.
- Treat a new package name, new version, new build-time edge, home change, or source change as a fresh trust decision.
