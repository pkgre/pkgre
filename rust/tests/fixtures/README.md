# Frozen Rust current-catalog fixture

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
commit=f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b
git -C /path/to/pkgre-rust archive --format=tar "$commit" -- registry > registry.tar
gzip -n -9 < registry.tar > rust-current-catalog-f9b5ffa.tar.gz
sha256sum registry.tar rust-current-catalog-f9b5ffa.tar.gz
```
