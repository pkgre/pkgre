# Real Nix derivation vectors

Status:test-only parser/provenance regression corpus | format:exact raw Nix ATerm `.drv` bytes | scope:D0-B22 gate hardening

## Integrity+capture

- `drvs/`:exact files copied read-only from the root-owned local Nix store;no newline or text normalization permitted.
- `vectors.json`:canonical semantic expectations,original store identities,byte lengths,SHA-256 hashes,fixed-output tuples,and source declarations.
- `SHA256SUMS`:complete integrity inventory for every regular file below this directory except the manifest itself.
- Tests require only repository bytes+Python stdlib;no `/nix/store`,network,or `nix` executable dependency.

## Evidence disposition

- Git+Nix structured vectors:retained surrogate source derivations corresponding to the historical host-tool rows.
- zvbi traditional vector:unrelated compatibility sample covering a recursive fixed-output derivation without `__json`.
- These vectors do not recover the missing original Git package derivation `/nix/store/bny4hxrsvnaj060b6rbd68233x4fw32h-git-2.54.0.drv` or Nix package derivation `/nix/store/iza23qnw05vpa85g804b841rd4yqr1z5-nix-2.34.8.drv`.
- Therefore they do not satisfy D0-B22,authorize D1,or alter the frozen historical evidence disposition.
- Changes require coordinated raw-byte,metadata,manifest,allowlist,and regression-test review.
