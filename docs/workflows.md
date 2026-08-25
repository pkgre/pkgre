# Curator workflows

## Commands

```text
pkgre-rust update-plan <catalog> <new-admission-manifest>
pkgre-rust update-plan-exact <catalog> <package> <version> <new-admission-manifest>
pkgre-rust update-inspect <catalog> <admission-manifest> <package> <version> <new-review-directory>
pkgre-rust update-apply <catalog> <admission-manifest>
pkgre-rust lock <catalog>
pkgre-rust check <catalog>
pkgre-rust render <catalog> <new-output>
pkgre-rust verify <catalog> <existing-output>
pkgre-rust verify-monotonic <previous-site> <next-site>
pkgre-rust migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>
pkgre-rust migrate-v3-to-v4 <schema-3-catalog> <new-schema-4-catalog>
```

Planning/inspection never mutates catalog; output must be absent + outside `registry/`. `update-apply` is the established-catalog path for mirror additions. `lock` mutates only bootstrap, empty reservations, removals, Git tags, and downloads convergence. `check` is local-only. Migrations never modify source. Render output must be absent. `<catalog>` is the registry directory, not repository parent.

## Admit crates.io mirror updates

### Guardrails

- Release age:non-yanked + ≥30×24 hours at command UTC time; future timestamps fail.
- Implicit lanes:`update-plan` scans active mirror names + selects at most latest eligible stable per compatibility lane:major for `major≥1`; minor for stable `0.minor.patch` where `minor>0`.
- Exact mode:`update-plan-exact` supports reserved new/inactive names, prereleases, `0.0.x`; locked/yanked/young/history-inconsistent identity rejected.
- Dormancy:≥365-day adjacent publication gap after locked base requires review; yanked/prerelease activity counts; gate persists until one post-gap identity admitted.
- Evidence:complete sparse history; exact base/candidate rows + checksum-verified archives; bounded path/type/size/mode/hash/build analysis; dependency/category delta; version-scoped publisher/repository/API facts; promoted source correspondence.
- Promotion triggers:new/inactive package, dormant wake-up, new dependency package, build-surface change, publisher/repository discontinuity.

| Decision | Meaning | Manifest/apply |
|---|---|---|
| `automatic` | no escalation signal | included; applyable |
| `review-required` | escalation/source unavailable | included; applyable; prioritize review/evidence |
| `blocked` | missing/ambiguous home, forbidden edge, source mismatch | omitted; impossible until fixed |

Every registry PR requires review. `review-required` does not require per-crate approval files; complete generated PR review authorizes batch. Optional evidence records genuine extra work. Unsafe/malformed archives, changed history, checksum inconsistency, duplicate identity, or catalog drift fail command.

### Compact single-PR workflow

Standalone production procedure:[`production-update-runbook.md`](production-update-runbook.md).

1. Choose permanent `main/<category>` home. New package:add empty anchor + reconcile separately:

```toml
[mirror]
new-package = []
```

```console
$ pkgre-rust lock registry
```

2. Generate one hash-free manifest outside catalog:

```console
$ pkgre-rust update-plan registry 2026-08-24-routine.toml
$ pkgre-rust update-plan-exact registry new-package 1.2.3 2026-08-24-new-package.toml
```

```toml
schema = 2

[[admit]]
category = "main/general"
name = "example"
version = "1.2.3"
```

Template includes automatic + review-required, omits blocked, refuses existing output, and proves catalog fingerprint stable.

3. Review scope/logs; remove unwanted complete request blocks; keep canonical order. Inspect selected exact request:

```console
$ pkgre-rust update-inspect registry 2026-08-24-routine.toml example 1.2.3 review-example-1.2.3
```

Output=`candidate.crate`, optional `base.crate`, `inspection.toml`, `README.txt`; no Cargo/compiler/build/package/repository code executes. Treat archives as untrusted.

4. Optionally add typed evidence beneath request:

```toml
[[admit.evidence]]
kind = "manual-full-archive"
note = "Reviewed every archive member, manifest, and build surface."
```

```toml
[[admit.evidence]]
kind = "manual-source-delta"
base = "1.2.2"
note = "Reviewed the complete archive delta from 1.2.2."
```

Unedited template remains valid. Delta base must equal apply's recomputation.

5. Apply exact manifest once:

```console
$ pkgre-rust update-apply registry 2026-08-24-routine.toml
```

Apply re-fetches/recomputes every request; rejects young/yanked/blocked/route/evidence failures; appends declarations; writes source rows, registry locks, downloads, `admissions/<batch>.{toml,lock}`; binds full batch-lock hash into packages; strict-loads + test-renders staging; atomically installs. It never substitutes another version.

6. Review + commit all catalog changes together. Required:a new active package/request; one exact `main` crates.io route/request; one row object/request; exactly one admission pair/batch; no mirror `.crate`; every new package `admission-sha256 = sha256(admissions/<batch>.lock)`.

```console
$ pkgre-rust check registry
$ git diff --check
$ pkgre-rust lock registry
$ git diff --check
```

Second `lock` must report `changed=false` + preserve exact diff. CI must run `check`, no-op `lock`, render, `verify`, and `verify-monotonic`; this enforces that a PR cannot merge a manifest/template without fully applied state. Reapplying identical installed manifest no-ops; same filename/different content fails.

### Bulk review

1. Generate one broad manifest; count automatic/review-required/blocked logs.
2. Require manifest entries=`automatic + review-required`; blocked absent.
3. Prioritize source-unavailable, dormancy, publisher/repository discontinuity, build/proc-macro/native changes, new dependencies, large deltas.
4. Keep evidence only where useful; no boilerplate notes.
5. Apply once; review one generated lock + shared binding + exact diff.
6. Open one registry PR; leave unmerged for curator.

## Publish first-party/fork Git tag

Preconditions:

- credential-free HTTPS repository + immutable reviewed tag;
- selected package version = tag final component, optional `v` prefix;
- source manifest exactly `publish = ["pkgre"]`;
- every dependency explicitly `registry = "pkgre"`; path/Git/crates.io/unknown sources fail, including optional/dev/build/target-specific;
- catalog home:use `main/pkgre` for a new first-party/standalone-fork name; an existing mirrored-name fork stays in that name's original category, retains its `[mirror]` declaration, and adds a same-name `[publish]` declaration there;
- fork Cargo version must be unique across every locked mirror/publish identity for that name; never reuse `name + version` for different bytes/source;
- after the first published identity, retain the `[publish]` key + exact Git URL forever; removal empties `tags` rather than deleting/changing the declaration;
- lockfile present; no submodules, symlinks, unsafe/special paths, ambiguity, or generated dirty state;
- reproducible archive under Cargo `1.95.0`.

Workflow:

1. Review + merge release commit; create/push immutable tag after merge.
2. Add tag:

```toml
[categories.pkgre.publish.pkgre-rust]
git = "https://github.com/pkgre/pkgre"
tags = ["rust/v0.5.0"]
```

3. Set absolute `PKGRE_CARGO` or provide rustup toolchain `1.95.0`; reported version must match.
4. Run `lock`:fetch tag; lock tag object/commit; discover package/path/version; run isolated locked metadata; package twice; require byte identity; generate source row; route dependencies; lock hashes.
5. Verify URL/tag/object/commit/package/path/Cargo + archive/row against reviewed tag.
6. Run `check`, no-op `lock`, verify exact Git route in downloads, render/verify/monotonicity; commit declaration/lock/catalog/objects together.

Self-publication normally uses prior immutable Rust indexer release. A schema/bootstrap release unreadable by its predecessor uses a reviewed build from the exact merged/tagged release commit,then locks the same tag. Rename transition:`pkgre-indexer`+`indexer/v*` remain immutable historical catalog identities;add `pkgre-rust` only after publishing the exact `rust/v0.5.0` tag,then update the production catalog+workflow pin in one reviewed release transaction.

## Remove version/tag

1. Remove exact version/tag from array; retain key in original registry/category.
2. Run `lock`.
3. Verify only intended packages become `active→removed`; rows remain; unshared Git archive disappears; mirror archive set remains empty.
4. Rendered history retains `yanked = true`; reactivation forbidden.
5. Run `check`, no-op `lock`, render, `verify`, `verify-monotonic`; commit.

Changing a package name's registry/category home, changing any locked identity's source/checksum, changing a retained Git publisher URL, deleting a required declaration key, or re-adding a removed identity fails before fetch.

## Migrations

### Schema 2→3 historical

```console
$ pkgre-rust migrate-v2-to-v3 registry-v2 registry-v3
```

Require clean strict source + absent destination. Authenticate inventory/objects/rows/hashes; inspect old→new category mapping; run check/render/verify/monotonicity; source remains unchanged.

### Schema 3→4 single root main

```console
$ pkgre-rust migrate-v3-to-v4 registry-v3 registry-v4
```

Exact mapping:`universe/<category>→main/<category>`; `pkgre/tooling→main/pkgre`; files become `main.toml`/`main.lock`; index becomes root; download becomes `v1/main`. Migration preserves immutable artifacts/provenance, recomputes registry-dependent routed hashes, rewrites/rebinds admissions, strict-loads/renders/reproduces staging, installs absent destination only.

Validation:

```console
$ pkgre-rust check registry-v4
$ pkgre-rust lock registry-v4            # changed=false
$ pkgre-rust render registry-v4 site-next
$ pkgre-rust verify registry-v4 site-next
$ pkgre-rust verify-monotonic site-v3 site-next
```

Replace source catalog only after review + rerun at final path. Never hand-edit migration output.

## Add future registry/category

Schema 4 allows additions without weakening prior identities:

1. Add `<alias>.toml` with exact index `sparse+https://rust.pkg.re/<alias>/`, categories, and inhabited package reservations; `main` remains.
2. Use exact router template or one allowed single-source endpoint.
3. Ensure every cross-registry dependency category edge is explicit. Same-name resolution prefers local registry; a dependency originating in a third registry fails if multiple external homes exist.
4. Bootstrap/reconcile, then check/render/verify/monotonicity. New alias renders below `/<alias>/`; download route uses `/v1/<alias>/...`.
5. Add consumer Cargo alias only where that registry should be selected directly.

## Release gate

```console
$ pkgre-rust check registry
$ pkgre-rust lock registry                  # exact no-op
$ pkgre-rust render registry site-next
$ pkgre-rust verify registry site-next
$ pkgre-rust verify-monotonic site-current site-next
```

Require:`git diff --check`; tool format/test/lint/Nix checks; prior registries/categories/homes/packages retained; additions/removals intentional; active routes exact; mixed registries use own router; rendered inventory expected; protected CI passes; normal merge without force/bypass.

Deploy only rendered site, never catalog. Workflow independently checks/renders/verifies, fetches prior live release, verifies monotonicity, then publishes with read-only source + minimum Pages permission.

## Post-deployment verification

- Fetch root `https://rust.pkg.re/config.json`; require `https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}`.
- Fetch rows across categories; compare checksums/routes/yank state with `release.json`.
- Current pre-P9 production check:fetch router `/healthz`+`/status`;require ready,expected commit/hash/counts,no refresh error. Target P9 check replaces `/status` with `pkgre-proxy` `/readyz`+`/metrics` and exact marker-origin evidence.
- Exact mirror + Git routes→`307` to static.crates.io + content-addressed pkg.re; download + verify SHA-256. Alter case/checksum/query/encoding→`404`; unsupported method→`405`.
- Compare live release/downloads with committed candidate; require exact active projection.
- Fresh Cargo home/cache + only `[registries.pkgre] index = "sparse+https://rust.pkg.re/"`; build `--locked` across mirror + Git packages; confirm `Cargo.lock` source is root URL.

Keep consumer validation private:no consumer names/paths/manifests/locks/dependency discovery/credentials/tokens in public logs/issues.

## Interrupted reconciliation

Failure normally removes staging + leaves original. Killed process can leave `.registry.pkgre-lock`, stage, backup.

1. Confirm no indexer process active.
2. Inspect catalog + siblings; preserve/restore last reviewed complete catalog if installation interrupted.
3. Remove only verified stale guard/disposable stage; retain backup until integrity confirmed.
4. Run `check`, compare Git, retry.
