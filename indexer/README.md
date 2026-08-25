# pkgre-indexer

Transactional declarative reconciler + deterministic renderer for schema-4 pkg.re Cargo registries/categories.

## Interface

```text
pkgre-indexer update-plan <catalog> <new-admission-manifest>
pkgre-indexer update-plan-exact <catalog> <package> <version> <new-admission-manifest>
pkgre-indexer update-inspect <catalog> <admission-manifest> <package> <version> <new-review-directory>
pkgre-indexer update-apply <catalog> <admission-manifest>
pkgre-indexer lock <catalog>
pkgre-indexer check <catalog>
pkgre-indexer render <catalog> <output>
pkgre-indexer verify <catalog> <output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>
pkgre-indexer migrate-v3-to-v4 <schema-3-catalog> <new-schema-4-catalog>
```

- `update-plan`:evaluate all active mirror compatibility lanes; create an absent compact canonical manifest containing every nonblocked exact request.
- `update-plan-exact`:evaluate one reserved mirror name/version, including new/inactive names, prereleases, and stable `0.0.x`; create an absent one-request manifest.
- `update-inspect`:recompute one manifest request + materialize checksum-verified candidate/base archives and bounded inert evidence without executing package code.
- `update-apply`:recompute every exact request at current time; reject young/yanked/blocked/invalid candidates; atomically install declaration additions, source rows, registry locks, canonical download catalog, and one immutable human-manifest/generated-lock admission pair.
- `lock`:preflight locally; reconcile initial bootstrap, empty reservations, removals, new first-party Git tags, and canonical `downloads.json`; direct new-mirror admission fails once registry locks exist.
- `check`:local-only strict schema/category/registry/admission/download/object/hash/row validation; never fetch crates.io or reproduce Git tags.
- `render`:write a new complete Pages tree. Catalog registry `main` renders at the site root; other registry aliases render below `/<alias>/`; output must be absent.
- `verify`:re-render + require exact entry/byte equality with an existing site.
- `verify-monotonic`:permit registries/categories/package identities to be added, `active→removed`, and source-specific→exact-router `dl`; reject removal/mutation/reactivation; authenticate exact schema-2→3 + schema-3→4 migrations.
- `migrate-v2-to-v3`:strictly authenticate canonical schema 2; map `core`/`matrix`/`pkgre` into schema-3 `universe`/`pkgre`; preserve source rows + Git archives; install only to an absent destination.
- `migrate-v3-to-v4`:strictly authenticate canonical schema 3; map `universe/<category>→main/<category>` + `pkgre/tooling→main/pkgre`; rewrite routed rows/admission bindings exactly; retain immutable artifacts; install only to an absent destination.

`<catalog>` is exclusive managed state:one `<registry>.toml` + generated `<registry>.lock` per registry; canonical generated `downloads.json`; exact referenced `categories/<registry>/<category>.toml`; paired `admissions/<batch>.{toml,lock}`; content-addressed `objects/{crates,rows}/`. Rows cover all locked identities; crate objects contain active Git-tag archives only. Retain every package key after its desired version/tag list becomes empty; deletion or registry/category/source-class change fails closed.

Schema 4 requires catalog alias `main` at `sparse+https://rust.pkg.re/`; another canonical alias `staging` maps to `sparse+https://rust.pkg.re/staging/`. Registry/category/package identities are scoped by catalog registry. Dependency routing prefers a same-registry package home; absent that, exactly one external-registry home is required. The source category must explicitly permit the resolved target category. Existing registries/categories/homes are monotonic; future ones may be added.

One registry may contain mirror + publish names only when `download = "https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}"`. A single-source registry may use its fixed direct source endpoint. `downloads.json` is deterministically projected from active locks as exact `(registry, case-sensitive name, canonical version, archive SHA-256, crates-io|git-tag)` routes; the router never takes arbitrary destination URLs from this file.

Human admission manifests contain exact category/name/version or tag + optional typed evidence. Mirror apply currently accepts versions only. Generated admission locks retain complete recomputed facts; every package in a batch binds the SHA-256 of the same generated lock. Protected review/merge of the complete catalog PR is authorization; `automatic`/`review-required` only prioritize attention; `blocked` candidates cannot be applied.

Documentation:[`catalog schema`](../docs/catalog.md) | [`download routing`](../docs/download-routing.md) | [`production mirror-update runbook`](../docs/production-update-runbook.md) | [`curator workflows`](../docs/workflows.md) | [`security model`](../docs/security.md).
