# pkgre-indexer

Transactional declarative reconciler + deterministic renderer for the fixed pkg.re Cargo registry/category topology.

## Interface

```text
pkgre-indexer lock <catalog>
pkgre-indexer check <catalog>
pkgre-indexer render <catalog> <output>
pkgre-indexer verify <catalog> <output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>
```

- `lock`: preflight existing locks/retained objects locally; resolve only newly desired crates.io versions + first-party Git tags; verify mirror bytes without retaining them; route dependency rows; build, strictly reload, verify, test-render, and transactionally install a complete replacement catalog.
- `check`: local-only strict schema, category policy, lock, object, checksum, source-row, and routed-row validation; does not fetch crates.io or reproduce Git tags.
- `render`: write a new complete sparse-registry Pages tree; output path must be absent.
- `verify`: re-render + require exact entry/byte equality with an existing site.
- `verify-monotonic`: permit additions + `active→removed`; reject release identity removal, immutable mutation, or reactivation; authenticate the one-time schema-2→3 category migration.
- `migrate-v2-to-v3`: strictly authenticate an existing canonical `core`/`matrix`/`pkgre` schema-2 catalog; map every permanent identity into `universe`/`pkgre` categories; preserve source rows + Git archives byte-for-byte; reproduce staged output; atomically install only to an absent destination.

`<catalog>` is exclusive managed state containing one `<registry>.toml` human declaration + adjacent generated `<registry>.lock` per registry, optional referenced `categories/<registry>/<category>.toml`, and `objects/{crates,rows}/`. Rows cover all locked identities; crates contain active Git-tag archives only. Retain every approved package key even when its desired version/tag list becomes empty; deletion, category/source-class change, or mirror/Git mix within one registry fails closed.

Documentation: [`catalog schema`](../docs/catalog.md) | [`curator workflows`](../docs/workflows.md) | [`security model`](../docs/security.md).
