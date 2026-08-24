# pkgre-indexer

Transactional declarative reconciler + deterministic renderer for the fixed pkg.re Cargo registry/category topology.

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
```

- `update-plan`: perform complete network-backed evaluation for all active mirror compatibility lanes; create an absent compact canonical manifest containing every nonblocked exact request.
- `update-plan-exact`: evaluate one reserved mirror name/version, including new/inactive names, prereleases, and stable `0.0.x`; create an absent one-request manifest.
- `update-inspect`: recompute one manifest request + materialize checksum-verified candidate/base archives and bounded inert evidence without executing package code.
- `update-apply`: recompute every exact request at current time; reject young/yanked/blocked/invalid candidates; atomically install declaration additions, source rows, registry locks, canonical download catalog, and one immutable human-manifest/generated-lock admission pair.
- `lock`: preflight locally; reconcile initial bootstrap, empty reservations, removals, new first-party Git tags, and canonical `downloads.json`; direct new-mirror admission fails once registry locks exist.
- `check`: local-only strict schema, category policy, registry/admission/download locks, objects, checksums, source rows, and routed rows; never fetch crates.io or reproduce Git tags.
- `render`: write a new complete sparse-registry Pages tree including canonical top-level `downloads.json`; output path must be absent.
- `verify`: re-render + require exact entry/byte equality with an existing site.
- `verify-monotonic`: permit additions + `active→removed` + source-specific→exact-router `dl` migration; reject release identity removal, immutable mutation, topology/category/source-class change, router downgrade in a mixed registry, or reactivation; authenticate one-time schema-2→3 migration.
- `migrate-v2-to-v3`: strictly authenticate canonical `core`/`matrix`/`pkgre` schema 2; map permanent identities into `universe`/`pkgre` categories; preserve source rows + Git archives byte-for-byte; reproduce staging; install only to an absent destination.

`<catalog>` is exclusive managed state: one `<registry>.toml` declaration + adjacent generated `<registry>.lock` per registry; canonical generated `downloads.json`; exact referenced `categories/<registry>/<category>.toml`; paired canonical `admissions/<batch>.{toml,lock}`; content-addressed `objects/{crates,rows}/`. Rows cover all locked identities; crate objects contain active Git-tag archives only. Retain every package key after its desired version/tag list becomes empty; deletion or registry/category/source-class change fails closed.

One registry may contain mirror + publish names only when its declared `download` equals `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}` exactly. A single-source registry may instead retain its fixed direct source endpoint. `downloads.json` is deterministically projected from active locks as exact `(registry, case-sensitive name, canonical version, archive SHA-256, crates-io|git-tag)` routes; it is canonical, required, size-bounded, and validated locally on every load. The router never takes arbitrary destination URLs from this file.

Human admission manifests contain only exact category/name/version or tag + optional typed evidence. Mirror apply currently accepts versions only. Generated admission locks retain complete recomputed facts; every package in a batch binds the SHA-256 of the same generated lock. Protected review/merge of the complete catalog PR is authorization; `automatic`/`review-required` only prioritize attention, while `blocked` candidates cannot be applied.

Documentation: [`catalog schema`](../docs/catalog.md) | [`download routing`](../docs/download-routing.md) | [`production mirror-update runbook`](../docs/production-update-runbook.md) | [`curator workflows`](../docs/workflows.md) | [`security model`](../docs/security.md).
