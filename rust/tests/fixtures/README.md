# Frozen Rust current-catalog fixtures

## Current schema-5 catalog (d778238)

| Field | Value |
|---|---|
| Source repo | `github:pkgre/rust` |
| Source commit | `d778238d266d0b47ab61ba2b78ec9a38d29586e6` (branch `registry/schema-5-migration`) |
| `registry` tree | `e8b757b723f40e15c4800bca8b02ef4698cf8543` |
| Uncompressed tar bytes | `2682880` |
| Uncompressed tar SHA-256 | `9932c78f55475537ea2976e716a755a1c0617d5f2d6411143a11eb2486645eda` |
| Gzip bytes | `636157` |
| Gzip SHA-256 | `d5d2ce2cf86fafcb52400677c6f020ce096132deb45a24d5535e98149b0baacc` |
| Projection bytes | `462388` |
| Projection SHA-256 | `838cf2660ade22b86208e8a217ca25944981ba36815dc697360ebb37ac05f5da` |

## Historical schema-4 catalog (f9b5ffa) — migration input

| Field | Value |
|---|---|
| Source repo | `github:pkgre/rust` |
| Source commit | `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` |
| `registry` tree | `35cbdb0e7622506461ad0d4340e3c1f40f594526` |
| Uncompressed tar bytes | `2529280` |
| Uncompressed tar SHA-256 | `06e75adf3bf4669cd619cab8415ff9e08bee44560f7a0dc1128378d16231aa98` |
| Gzip bytes | `621318` |
| Gzip SHA-256 | `9c70bcffb58b92003f9c950656953b51844aeaa1d86183b86415f09da334f2fa` |

## Reproduction

```sh
commit=d778238d266d0b47ab61ba2b78ec9a38d29586e6
test "$(git -C /path/to/pkgre-rust rev-parse "$commit:registry")" = e8b757b723f40e15c4800bca8b02ef4698cf8543
git -C /path/to/pkgre-rust archive --format=tar "$commit" -- registry > registry.tar
gzip -n -9 < registry.tar > rust-current-catalog-d778238.tar.gz
sha256sum registry.tar rust-current-catalog-d778238.tar.gz
```

Projection manifest: regenerate the `EXPECTED_PROJECTION` fixture by running the
`current_catalog_projection` projection path over the extracted catalog (see
`CatalogProjection::manifest_bytes`); only `/downloads.json` differs from the f9b5ffa projection
because the schema-2 download catalog is larger than the schema-1 one.

The f9b5ffa schema-4 fixture is retained as the frozen `migrate-v4-to-v5` input; the d778238
schema-5 fixture is the current production projection evidence.