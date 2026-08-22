# pkgre-indexer

Deterministic validator/materializer/renderer for the fixed pkg.re Cargo registry topology.

## Interface

```text
pkgre-indexer check <catalog> [artifact-map]
pkgre-indexer render <catalog> <artifact-map> <output>
pkgre-indexer verify <catalog> <artifact-map> <output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer candidate-crates-io <proposal> <output>
pkgre-indexer candidate-git <proposal> <cargo-version> <output>
pkgre-indexer package-git <catalog> <package> <version> <output>
```

- `check`: validate catalog policy; optional artifact map adds exact file/hash/index-row verification.
- `render`: create a new complete sparse-registry Pages tree; refuses overwrite.
- `verify`: re-render + require exact tree/file equality.
- `verify-monotonic`: reject removal/mutation of published package identities; `yanked` may change.
- `candidate-crates-io`: download exact crates.io row/archive into a non-approved candidate tree.
- `candidate-git`: package one proposed immutable Git tag twice with pinned Cargo + emit a non-approved candidate.
- `package-git`: independently reproduce one approved Git-tag package + require both approved hashes.

Documentation: [`catalog schema`](../docs/catalog.md) | [`curator workflows`](../docs/workflows.md) | [`security model`](../docs/security.md).
