# pkgre-indexer

Transactional declarative reconciler + deterministic renderer for the fixed pkg.re Cargo registry topology.

## Interface

```text
pkgre-indexer lock <catalog>
pkgre-indexer check <catalog>
pkgre-indexer render <catalog> <output>
pkgre-indexer verify <catalog> <output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
```

- `lock`: preflight existing locks/objects locally; resolve only newly desired crates.io versions + first-party Git tags; route dependency rows; build, strictly reload, verify, test-render, and transactionally install a complete replacement catalog.
- `check`: local-only strict schema, policy, lock, object, checksum, source-row, and routed-row validation; does not fetch crates.io or reproduce Git tags.
- `render`: write a new complete sparse-registry Pages tree; output path must be absent.
- `verify`: re-render + require exact entry/byte equality with an existing site.
- `verify-monotonic`: permit additions + `active→removed`; reject release identity removal, immutable mutation, or reactivation.

`<catalog>` is an exclusive managed-state directory containing only one `<registry>.toml` human declaration + adjacent generated `<registry>.lock` per registry and `objects/{crates,rows}/`. Retain every approved package key even when its desired version/tag list becomes empty; deletion of a key or source-class change fails closed.

Documentation: [`catalog schema`](../docs/catalog.md) | [`curator workflows`](../docs/workflows.md) | [`security model`](../docs/security.md).
