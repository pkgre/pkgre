# P4 mechanical reorganization baseline

Captured:`2026-08-25T18:12Z`;tool source:`98ecd3b6866da4a23ccf7101dd6dbc4fb5402aaf`;production infra rollback pin:`ae1dfbfd4e965dffb538e356f005e4fbb32fdb77`;catalog source:`pkgre/rust@0fa205c9ec610cc31b7551f224ab8ff5a90450c3`,registry tree `35cbdb0e7622506461ad0d4340e3c1f40f594526`.

| Contract | Baseline |
|---|---|
| `nix flake check --print-build-logs` | pass;x86_64-linux packages/checks/dev shell/formatter evaluate;build checks pass;aarch64-linux omitted on x86 evaluator. |
| `.#indexer` | `/bin/pkgre-indexer`;version `0.4.0`;binary SHA-256 `ee5150c6498e92d5bbab383bafd01137417fe94fbfda6f0d154af16f7910a3c1`;no-argument/help contract exits 1 with command list. |
| `.#download-serve` | `/bin/pkgre-download-serve`;version `0.1.0`;binary SHA-256 `6637c496cac3d05e855a5f0c6d700e792aa0908a2bb766f28548d9b223a1239b`;no-argument/help contract exits 1 with three options. |
| Catalog check/render/verify | pass;563 files;sorted `(content SHA-256,path)` manifest SHA-256 `b2f68b4da9869c364b4d4296547396eb58215d9b2fd86bb05d9f77b9a9d96c1a`. |
| Existing package tests | included in Nix package checks:unit,integration,clippy;download router fixtures remain authoritative for route/status/redirect behavior. |

Equivalence rule:directory-only moves must preserve package/bin/version,CLI bytes,render-manifest hash,and current tests. Intentional renames occur only in later isolated commits;transitional `.#indexer`+`.#download-serve` outputs remain until rain deployment+rollback horizon.
