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
- `update-apply`: recompute every exact request at current time; reject young/yanked/blocked/invalid candidates; atomically install declaration additions, source rows, registry locks, and one immutable human-manifest/generated-lock admission pair.
- `lock`: preflight locally; reconcile initial bootstrap, empty reservations, removals, and new first-party Git tags; direct new-mirror admission fails once registry locks exist.
- `check`: local-only strict schema, category policy, lock, admission, object, checksum, source-row, and routed-row validation; never fetch crates.io or reproduce Git tags.
- `render`: write a new complete sparse-registry Pages tree; output path must be absent.
- `verify`: re-render + require exact entry/byte equality with an existing site.
- `verify-monotonic`: permit additions + `active→removed`; reject release identity removal, immutable mutation, topology/category change, or reactivation; authenticate the one-time schema-2→3 migration.
- `migrate-v2-to-v3`: strictly authenticate canonical `core`/`matrix`/`pkgre` schema 2; map permanent identities into `universe`/`pkgre` categories; preserve source rows + Git archives byte-for-byte; reproduce staging; install only to an absent destination.

`<catalog>` is exclusive managed state: one `<registry>.toml` declaration + adjacent generated `<registry>.lock` per registry; exact referenced `categories/<registry>/<category>.toml`; paired canonical `admissions/<batch>.{toml,lock}`; content-addressed `objects/{crates,rows}/`. Rows cover all locked identities; crate objects contain active Git-tag archives only. Retain every package key after its desired version/tag list becomes empty; deletion, category/source-class change, or mirror/Git mix within one registry fails closed.

Human admission manifests contain only exact category/name/version or tag + optional typed evidence. Mirror apply currently accepts versions only. Generated admission locks retain complete recomputed facts; every package in a batch binds the SHA-256 of the same generated lock. Protected review/merge of the complete catalog PR is authorization; `automatic`/`review-required` only prioritize attention, while `blocked` candidates cannot be applied.

Documentation: [`catalog schema`](../docs/catalog.md) | [`production mirror-update runbook`](../docs/production-update-runbook.md) | [`curator workflows`](../docs/workflows.md) | [`security model`](../docs/security.md).
