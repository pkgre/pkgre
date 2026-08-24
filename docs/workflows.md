# Curator workflows

## Commands

```text
pkgre-indexer update-plan <catalog> <new-admission-manifest>
pkgre-indexer update-plan-exact <catalog> <package> <version> <new-admission-manifest>
pkgre-indexer update-inspect <catalog> <admission-manifest> <package> <version> <new-review-directory>
pkgre-indexer update-apply <catalog> <admission-manifest>
pkgre-indexer lock <catalog>
pkgre-indexer check <catalog>
pkgre-indexer render <catalog> <new-output>
pkgre-indexer verify <catalog> <existing-output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>
```

`update-plan`, `update-plan-exact`, and `update-inspect` never mutate the catalog; every output must be absent and outside managed `registry/`. `update-apply` is the only established-catalog path for new mirror identities: it re-fetches/recomputes exact facts + mutates transactionally. `lock` mutates only for initial bootstrap, empty name reservations, removals, first-party Git tags, and canonical download-catalog convergence; it rejects direct new-mirror admission after any registry lock exists. `check` is local-only. `migrate-v2-to-v3` never modifies source. Render output must be absent. Use the registry directory itself as `<catalog>`, not its repository parent.

## Admit crates.io mirror updates

### Selection + guardrails

- Release-age floor: every implicit/exact candidate must be non-yanked + ≥30×24 hours old at the command's UTC evaluation time; future timestamps fail.
- Implicit lanes: `update-plan` considers only active existing mirror packages and selects at most one latest eligible stable update per active compatibility lane: one lane per `major` for `major≥1`; one lane per `minor` for stable `0.minor.patch`, `minor>0`.
- Exact selection: `update-plan-exact` supports new/inactive reserved names, prereleases, and `0.0.x`; it cannot select locked, yanked, young, or history-inconsistent identities.
- Dormancy: a ≥365-day adjacent publication gap between locked base and candidate requires review; yanked/prerelease publications count as activity; a post-gap burst stays gated until one post-gap identity is admitted.
- Evidence: complete crates.io sparse history; exact candidate/base rows + checksum-verified archives; bounded path/type/size/mode/hash/build-surface analysis; dependency delta + category routes; version-scoped publisher/repository/API facts; promoted public-source correspondence.
- Source promotion triggers: new/inactive package, dormant wake-up, new dependency package, build-surface change, publisher discontinuity, repository discontinuity.

Decision policy:

| Decision | Meaning in generated facts | Manifest/apply behavior |
|---|---|---|
| `automatic` | no configured escalation reason | included in template; applyable |
| `review-required` | one or more escalation reasons, including promoted source unavailable | included in template; applyable; prioritize human review + optionally record typed evidence |
| `blocked` | unknown dependency home, forbidden category edge, or source mismatch | omitted from template; impossible to apply until catalog/upstream issue is fixed |

Every registry PR requires protected source-control review regardless of decision. `review-required` does not require repetitive per-crate approval records: reviewing/merging the complete generated catalog PR is authorization. Optional manifest evidence records useful additional work and enables future integrations such as cargo-vet. Unsafe/malformed archives, changed locked history, checksum inconsistency, duplicate identities, or catalog drift fail the command rather than producing a candidate.

### Compact admission workflow

The standalone live-production procedure is [`production-update-runbook.md`](production-update-runbook.md). Policy-level synopsis:

1. Choose/permanently reserve each package's `universe/<category>` home. For a first identity, add only an empty name anchor and reconcile it separately:

```toml
[mirror]
new-package = []
```

```console
$ pkgre-indexer lock registry
```

2. Create one canonical, hash-free manifest outside `registry/`. Implicit planning scans active existing mirror lanes; exact planning targets one reserved package/version:

```console
$ pkgre-indexer update-plan registry 2026-08-24-routine.toml
$ pkgre-indexer update-plan-exact registry new-package 1.2.3 2026-08-24-new-package.toml
```

Generated template:

```toml
schema = 2

[[admit]]
category = "universe/general"
name = "example"
version = "1.2.3"
```

The command performs full current evaluation but writes only category/name/version requests. It includes automatic + review-required candidates, omits blocked candidates, refuses an existing output, and proves the catalog fingerprint stayed stable before writing.

3. Review planner counts/logs and manifest scope. Remove any candidate not intended for this batch. Keep canonical ordering. For suspicious/review-required identities, materialize a private inert inspection tree:

```console
$ pkgre-indexer update-inspect registry 2026-08-24-routine.toml example 1.2.3 review-example-1.2.3
```

The tree contains `candidate.crate`, optional `base.crate`, `inspection.toml`, and `README.txt`. The indexer re-plans that exact request, re-fetches checksum-bound archives, verifies analyses/delta, and never invokes Cargo, compilers, build scripts, package binaries, repository hooks, or package code. Treat archive files as untrusted input.

4. Optionally record specific review/tool evidence directly beneath an `[[admit]]` entry:

```toml
[[admit.evidence]]
kind = "manual-full-archive"
note = "Reviewed every archive member, manifest, and build surface."
```

or:

```toml
[[admit.evidence]]
kind = "manual-source-delta"
base = "1.2.2"
note = "Reviewed the complete archive delta from 1.2.2."
```

`manual-source-delta` must match the exact base + archive delta recomputed during apply. Evidence is optional; an unedited generated template is valid + mergeable.

5. Apply the exact manifest:

```console
$ pkgre-indexer update-apply registry 2026-08-24-routine.toml
```

Apply loads only canonical human requests, re-fetches/recomputes all current facts, rejects any young/yanked/blocked/route-invalid/evidence-invalid request, then executes one catalog transaction. It appends versions, generates one complete admission lock, hashes that complete lock, assigns the shared hash to every admitted package, writes `admissions/2026-08-24-routine.{toml,lock}`, reconciles rows/registry locks + canonical `downloads.json`, strict-loads + test-renders staging, and atomically installs it. Failure before installation leaves live catalog unchanged. Apply never substitutes a newer version.

6. Review + commit declarations, registry locks, canonical `downloads.json`, row objects, and exactly one admission pair together. Verify every added active identity has one exact route and no `.crate` mirror objects exist. Every new package's `admission-sha256` must equal `sha256sum admissions/<batch>.lock`. Then prove validity + convergence:

```console
$ pkgre-indexer check registry
$ git diff --check
$ pkgre-indexer lock registry
$ git diff --check
```

The second `lock` must report `changed=false` + preserve the exact diff. Missing/tampered/orphan admission files or wrong/reused bindings fail ordinary load/check. Reapplying the identical installed manifest is a validated no-op; same filename with different content fails.

### Bulk-update review strategy

For hundreds of routine existing-package updates, avoid per-crate ceremony:

1. Generate one broad manifest; count automatic/review-required/blocked from structured planner logs.
2. Confirm manifest entry count = automatic + review-required; blocked = omitted.
3. Prioritize inspection: source mismatch never appears because blocked; inspect source-unavailable, dormant wake-ups, publisher/repository discontinuities, build/proc-macro/native surface changes, new dependencies, and unusually large deltas.
4. Keep optional evidence only where useful; do not manufacture boilerplate notes for every package.
5. Apply once; review one generated lock + shared batch binding + exact catalog diff.
6. Open one registry PR and leave it unmerged for curator review.

## Publish a first-party Git tag

Tagged source preconditions:

- credential-free HTTPS repository + immutable reviewed release tag;
- selected package version = tag final component with optional `v` prefix;
- selected manifest declares exactly `publish = ["pkgre"]`;
- every dependency explicitly names `registry = "universe"|"pkgre"`; path/Git/crates.io/unknown sources fail, including optional/dev/build/target-specific;
- every dependency category allowed by `pkgre/tooling` (`pkgre/tooling` or `universe/general`);
- lockfile present; no submodules, symlinks, special/unsafe paths, ambiguous package names, or generated dirty state;
- reproducible archive under Cargo `1.95.0`.

Workflow:

1. Review + merge release commit through protected `main`; create/push immutable tag after merge.
2. Add tag to retained declaration:

```toml
[categories.tooling.publish.pkgre-indexer]
git = "https://github.com/pkgre/pkgre"
tags = ["indexer/v0.3.0"]
```

3. Set `PKGRE_CARGO=/absolute/path/to/cargo` or provide rustup toolchain `1.95.0`; executable must report `cargo 1.95.0 ...`.
4. Run `pkgre-indexer lock registry`. It fetches exact tag, locks tag object + peeled commit, discovers package/path/version, runs isolated locked metadata, packages twice into distinct targets, requires byte-identical archives, generates source row, routes dependencies, and locks all hashes.
5. Verify URL/tag/object/commit/package/path/Cargo version + exact archive/row; compare with reviewed tag.
6. Run `check`, second no-op `lock`, verify the added exact Git route in `downloads.json`, render/release validation, then commit declaration/lock/catalog/objects together.

Pinned Cargo selection: absolute canonical regular-file `PKGRE_CARGO` first; otherwise absolute result of `rustup which --toolchain <cargo-version> cargo`. Nix builds set `PKGRE_CARGO` to the pinned toolchain. Existing Git identities validate retained bytes/provenance locally without recontacting upstream.

Self-publication: normally reconcile a new indexer tag with the prior immutable release. A schema/bootstrap release unreadable by its predecessor uses a reviewed build from the exact merged/tagged release commit, then locks that same tag.

## Remove a version/tag

1. Remove exact version/tag from its array; never delete/move package key.
2. Run `pkgre-indexer lock registry`.
3. Verify only intended lock entries changed `active→removed`; source rows remain; unshared Git archive disappears; mirror archive set remains empty.
4. Rendered history retains row as `yanked = true`; reactivation is permanently rejected.
5. Run `check`, second no-op `lock`, `render`, `verify`, `verify-monotonic`; commit.

Changing package home/source class, changing locked publisher URL, deleting key, or re-adding removed identity fails before network access.

## Migrate canonical schema 2

1. Require clean source catalog + record sorted file hashes.
2. Choose absent sibling destination.
3. Run `pkgre-indexer migrate-v2-to-v3 registry registry-v3`.
4. Require strict old-catalog authentication, exact old→new category mapping, object byte preservation, policy validation, staged render/reproduction.
5. Inspect new declarations/locks/category membership/counts + exact retained Git archives.
6. Run `check`, `render`, `verify`, and `verify-monotonic` against old rendered site.
7. Replace source only after review + rerun validation at final path; commit. Source is never modified by migration.

## Migrate registry downloads to the immutable router

A download-configuration migration is staged separately from service deployment; full contract + rollback: [`download-routing.md`](download-routing.md).

1. Generate + merge `registry/downloads.json` while current direct `dl` endpoints remain live; render/verify/monotonicity must prove no package/topology mutation.
2. Deploy `pkgre-download-serve` behind fixed nginx without changing registry declarations. Require readiness + expected catalog commit/hash + exact redirect/malformed-path probes.
3. Replace each `[registry].download` with its own exact router template. Never reuse another registry alias or use an arbitrary hostname/path.
4. Run `lock`; only declaration/registry-lock download fields + regenerated release/config bytes may change; exact routes/checksums/sources must not. Run `check`, exact second-lock no-op, render, verify, and `verify-monotonic`.
5. Merge/publish, validate live config/router, then run clean-cache Cargo E2E across representative crates.io + Git-tag packages.

Rollback:revert/publish `dl` values first; current direct endpoints are safe only for single-source registries. After no live config references the router, service rollback is independent. Never mutate checksum/source routes as a routing workaround.

## Release gate

```console
$ pkgre-indexer check registry
$ pkgre-indexer render registry site-next
$ pkgre-indexer verify registry site-next
$ pkgre-indexer verify-monotonic site-current site-next
```

Required: `git diff --check`; exact second-lock no-op; tooling format/test/lint/Nix checks; prior release name/package identities retained; additions/removals intentional; topology/anchors/immutable fields unchanged; every active package has one exact canonical generated route; each registry uses its canonical source-specific or exact router `dl`; rendered inventory limited to expected files; protected CI passes; normal merge without force/bypass.

Deploy only rendered `site/`, never `registry/`. Workflow should independently run check/render/verify, fetch prior live `release.json`, run `verify-monotonic`, then publish with read-only source + minimum Pages permissions.

## Post-deployment verification

- Fetch `https://rust.pkg.re/{universe,pkgre}/config.json`; after router migration require exact registry-bound `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}` values.
- Fetch representative rows across categories; compare checksum/routes/yank state with `release.json`.
- Fetch `https://dl.rust.pkg.re/healthz` + `/status`; require ready, expected source commit/manifest hash/route counts, and no refresh error.
- Request representative exact mirror + Git-tag router URLs; require `307` to static.crates.io + content-addressed pkg.re respectively; independently download + verify SHA-256. Alter case/checksum and add query/encoding; require `404`; unsupported method → `405`.
- Compare live `release.json` + `downloads.json` with committed candidate; require schema/topology/anchors + exact active route projection.
- Use fresh Cargo home/cache + failure-closed config; build `--locked`/`--frozen` across both registries.

Keep consumer validation private: public commits/logs/issues must not expose consumer repositories, paths, manifests, lockfiles, dependency-discovery output, credentials, or tokens.

## Interrupted reconciliation recovery

Normal failure removes guard/staging + leaves original exact. A killed process can leave `.registry.pkgre-lock`, staging, or backup siblings.

1. Confirm no indexer process active.
2. Inspect `registry/` + siblings; preserve/restore last reviewed complete catalog if installation interrupted.
3. Remove only verified stale guard + disposable `.registry.pkgre-stage-*`/`.registry.pkgre-render-*`; retain `.registry.pkgre-backup-*` until integrity confirmed.
4. Run `check`, compare source control, retry.
