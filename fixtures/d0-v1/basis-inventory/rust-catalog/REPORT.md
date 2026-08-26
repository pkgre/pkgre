# Rust D0 catalog+render inventory

Status:artifact-complete for fixed Rust catalog/render scope;broader plan D0 remains blocked | catalog:`f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` | implementation/render:`066293df21743cbf41fb571a38f2bb94059e7274` | repository mutation:none

## Classification

- Observed facts:fixed-commit catalog bytes;fixed-render output;point-in-time public route evidence;committed archive rehearsal;validated Cargo/Nix evidence. Machine source:`inventory.json.observedFacts`+JSONL rows.
- Plan requirements:normative target routes/MIME/state fields copied into `inventory.json.planRequirements`;not claimed current.
- Proposals:none promoted here. Resource/time proposals remain separate and require operator+reviewer approval.

## Exact inventory

| Field | Result |
|---|---|
| Registry | schema=4;exactly one `main`;index=`sparse+https://rust.pkg.re/`;download=`https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}`;Cargo=1.95.0 |
| Categories/homes | 9 categories;911 permanent homes;555 names have versions;356 reserved empty homes |
| Versions/graph | 747 active;0 removed;5,518 dependency edges;744 crates.io+3 Git-tag;full source row retained per `versions-downloads.jsonl` |
| Admissions | 1 batch;3 identities;complete manifest+candidate evidence in `admissions.jsonl` |
| Catalog hashes | `main.lock`=075a97b50ca504492fa3c133987b9e61f8c270b95a36819e2b56835c9837cd54/320,545B;`downloads.json`=9c0cb103f61caeb95a52f76fc3cd479d94c261aef86a7b5d96711e902e26fe94/154,344B |
| Current catalog bodies | 3/747 `.crate`;229,784B;744 bodies absent from source tree |
| Fixed render | 563 files/2,129,784B;555 sparse rows/747 JSON records;3 archives;3 JSON docs;2 provider adapters |
| Largest render | `release.json`=459,017B;largest sparse `/we/b-/web-sys`=107,745B |
| Core hashes | config=9a591cbdb924a588f69f88170e52be8d52b0d08e2261dc1b1b0732171e35ebcc;downloads=9c0cb103f61caeb95a52f76fc3cd479d94c261aef86a7b5d96711e902e26fe94;release=2be183106bc9e055a7a1167edad498dae92adbe09c752d9b7927c9ee90542354 |
| Current public route closure | 563 fixed renderer routes+3 extra published routes=566 `rust.pkg.re` 200;747 same-host `/v1` 404;747 `dl.rust.pkg.re` 307;2 legacy admin 200;2,062 Rust inventory rows |
| Cargo closure | lock v4;174 packages;172 third-party,all exact `sparse+https://rust.pkg.re/`;indexer=55 packages/113 feature pairs;proxy=155/305;full rows=`cargo-closure.json` |
| Toolchain/tests | rustc/Cargo 1.95.0;`.#rust`+`.#proxy` exact drv/out in `inventory.json`;173 workspace tests passed;no `.#rust-serve` yet |

## Authoritative archive rehearsal cross-check

Committed authority:`/home/dev0/repos/pkgre@1d44dfeaeafef2b1a5341c13bf73647dcbc925ec/fixtures/d0-v1/archive-git-rehearsal`;its `SHA256SUMS` passed. Exact closure=747 routes=747 unique hashes=747 verified archives;failures=0;raw unique bytes=`129,833,713`;logical route bytes=`129,833,713`;largest=`9,679,450B` (`f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483`). `download-summary.json` SHA-256=`53e1a700d3c7ca0d9314bf2364e0387477388c25a6bcce386af28c602a63c68c`;`git-metrics.json`=`a79b6d9f617e6a4b45727205b104f29b33c7bca009513f15c8f00e67f4804e00`;`download-results.json`=`76c01873b2c30caf7c631acf6fd7f16da0336172cc5ebaca5a21fd408939b72b`.

Ordinary-Git tmpfs measurement:loose repo apparent=136,370,257B;packed repo apparent/allocated=129,497,688/129,585,152B;bare repo apparent/allocated=129,367,206/129,429,504B;checkout repo+tree apparent=259,463,809B;allocated=261,058,560B;strict fsck+checkout rehash passed. This proves one-host current-closure feasibility only. It does not prove append-only history growth,provider/Rain quota,production filesystem behavior,or backup/restore. Any stale `1.6GB raw archives` claim is rejected;fixed-basis authority is exactly `129,833,713B`.

## Render/routes+headers

`rendered-routes.jsonl` enumerates all 563 fixed bytes with path,length,SHA-256,current observed content type/semantic headers,planned dynamic MIME,and D8–D14 mapping. Current Pages sparse MIME=`application/octet-stream`;plan target=`text/plain; charset=utf-8`,an intentional D1 fixture decision. JSON currently=`application/json; charset=utf-8`;archives=`application/octet-stream`. Current Pages validators/cache headers are deployment-derived;plan requires deterministic source-owned validators. `versions-downloads.jsonl` enumerates all 747 identities,full source record,archive byte measurement,retrieval URL,current body presence,and exact observed legacy 307/canonical 404.

## Git/storage+dependency facts

Catalog basis is clean/current locally;Git object format=SHA-1/40-hex;773 tree entries;763 unique blobs/1,958,607B;canonical tree SHA-256=`ebb632e21d7553d46da4b3db0c4dac5be1cdd6ec2b51a1c21a3c59e511492355`;strict full fsck/connectivity passed in cited D0 storage evidence;no shallow/alternates/grafts/promisor/replace/gitlinks/LFS/filter/tree-symlink finding. This is a non-bare development checkout with SSH origin and does not prove production bare mirror ownership/quota/layout.

Current exact Cargo closure is frozen in `cargo-closure.json`;all 172 third-party nodes use curated `rust.pkg.re`. Current `.cargo/config.toml` replaces crates.io and has `offlineExplicit=false`;the operator-approved plan amendment makes `[net] offline=true` plus its self-host/cold-replay proof a mandatory pre-D5 gate,not a D0 mutation or blocker. The planned server should reuse admitted Axum/Tokio/tracing/anyhow utilities and remove `reqwest`/TLS/client closure;the exact future lock diff is not an observed fact and remains blocked until authorized implementation.

## Blocking unknowns

1. `D0-SCOPE`:This Rust catalog/render inventory is not the complete cross-domain D0 gate;deployment/network/TLS/governance/signing/raw-target rows remain separate.
2. `FRESH-REFETCH`:No fetch was run in this reconstruction; D0 requires immediate fetch/prune/upstream verification before first edit.
3. `AUDIENCE-SCHEMA`:Schema 4 has no audience field; public classifications here are provisional migration classifications.
4. `BODY-IN-SOURCE`:Catalog basis contains 3/747 archive bodies; 744 verified bodies remain to be imported by an authorized future migration.
5. `ARCHIVE-CAPACITY`:Rehearsal proves current closure on one tmpfs host only; append-only history growth, provider ceiling, production quota, and backup/restore remain unproved.
6. `SIGNATURE-AUTHORITY`:Exact protected writer/check/environment rows and v1 SSH-Ed25519 allowedSigners production authority remain separate blockers.
7. `HEADER-FREEZE`:Current sparse Content-Type is application/octet-stream while plan requires text/plain; deterministic validators/owned headers require D1 fixtures.
8. `DOWNLOAD-RAW-EDGE`:Known 747 legacy redirects were observed, but malformed/raw-target/alias/nginx H1/H2 behavior is a separate D0 proof.
9. `CARGO-OFFLINE-PRE-D5`:Current .cargo/config.toml has offlineExplicit=false;the operator-approved plan amendment makes [net] offline=true plus its self-host/cold-replay proof a mandatory pre-D5 gate,not a D0 mutation or blocker.
10. `REQWEST-DELTA`:Exact current proxy/indexer feature closures are frozen; proposed post-reqwest lock/feature delta does not exist until an authorized change.
11. `DYNAMIC-SERVER`:No pkgre-rust-serve package/Nix attribute or live two-snapshot resource measurement exists at the fixed implementation basis.

## Files+validation

- `inventory.json`:bounded summary;observed/plan/proposal separation;all counts,hashes,toolchain,Nix,Git,archive facts+blockers.
- `catalog-homes.jsonl`:911 permanent home declarations including empty reservations,mirror versions,publish tags/source.
- `admissions.jsonl`:3 admitted identities with full candidate evidence.
- `versions-downloads.jsonl`:747 active identities with full retained source row+download/archive/current route evidence.
- `rendered-routes.jsonl`:563 fixed rendered representations.
- `cargo-closure.json`:feature-selected exact lock closure.
- `validation.json`:machine validation results.
- `SHA256SUMS`:all final artifacts except itself.
- `build_inventory.py`:read-only reconstruction;writes only this artifact directory.

Exact final validation:`python3 -m json.tool inventory.json cargo-closure.json validation.json`;parse every JSONL line;assert row counts 911/3/747/563;assert fixed bases+catalog/rehearsal/render invariants;`sha256sum -c SHA256SUMS`;recheck both project repositories with `git status --porcelain=v2`. No network/provider/deployment operation and no project repository write occurred.
