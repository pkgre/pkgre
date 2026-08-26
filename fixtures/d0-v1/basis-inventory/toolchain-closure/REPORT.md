# `pkgre` D0 toolchain/build/dependency-closure/performance evidence

Status:distilled+machine-validated | scope:surviving read-only local artifacts only | system:`x86_64-linux` | implementation:`066293df21743cbf41fb571a38f2bb94059e7274` | inventory schema:`pkgre-d0-toolchain-closure-v1`

## Evidence semantics

Observed:values in `inventory.json` derive from the pre-existing D0 artifact tree;this distillation did not access/modify a project repository,did not rerun builds/tests/renders,and performed no network/deployment/settings/credential operation. Independently revalidated here:all JSON parsing;flake/Cargo/npm lock versions+pins;Cargo metadata reachability;complete root/union package+feature counts;Cargo lock/metadata/closure equivalence;all 172 third-party Cargo sources exactly `sparse+https://rust.pkg.re/`;time/log result consistency;render-inventory hashes/line counts/byte sums;artifact hashes;secret scan. Collection-record-only:not independently recaptured because source repositories were out of scope:primary branch/status/upstream divergence and performance-input cleanliness/commits. Proposed/future:no deployment or production design proposed;blockers state evidence still required outside this bounded inventory.

## Exact basis+pins+schemas

- Commit:`066293df21743cbf41fb571a38f2bb94059e7274`;proof=`logs/commit`;referenced-not-copied source tar SHA-256=`33526e0f3276a5dd79f2f7d8d54580547957bcb21a3a8941c7ba7b6153d30b26`,archive bytes=1,464,320,total members=126,regular files=105/1,366,202 B;original extraction equivalence=105 paths/1,366,202 B/0 missing/extra/hash mismatch. Full archive/source omitted intentionally;fixed Git identity+hash+selected exact configs retained.
- Flake lock v7:`nixpkgs@2c423e03bbafcff28bfadc6781a4a8257f205cb5`,narHash=`sha256-dt4WdcvsA8/RCe+VZZwqU0X+XMM3wBbGCWA0/sFWzGo=`;`rust-overlay@fd2ebb9cc4323d0c5a1336138dab5c3c5a5d8bd9`,narHash=`sha256-YT4Fs2k7bi+7YzuLt93EtIRgjpwHK5ZfsQEIh5dEQSk=`.
- Versions:Cargo lock=4;Cargo metadata=1;Cargo packages=174;npm lockfile=3;Rust catalog/release=4;Rust download catalog=1;JS catalog=`pkgre-js-catalog-v1`;JS site=`pkgre-js-site-v1`;redirect marker=`redirect-marker-v1`.
- Cargo config:`config/cargo-config.toml`;default=`pkgre`;index exact=`sparse+https://rust.pkg.re/`;crates.io replaced by empty `vendor/empty` source.

## Toolchain+wrappers

`inventory.json.tools[]` is authoritative machine detail:role,exact version,Nix attr/context,`.drv`,output,source disposition,and wrapper/config paths;`source-provenance.json` freezes retained source-derivation rows,hash method,source-output presence,and local rehash status. Headline versions:Nix 2.34.8;host Git 2.54.0;flake Git 2.55.0;rustc/Cargo 1.95.0;indexer Node/npm 24.19.0/11.17.0;compat Node/npm minimum 24.15.0/12.0.2,current 26.7.0/12.0.2;Bun minimum/current 1.3.14/1.4.0;Deno 2.9.5;`pkgre-rust` 0.5.0;`pkgre-proxy` 0.2.0;`pkgre-js` 0.1.0. Effective minimum executables=`/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2/bin/{node,npm}`;effective current executables=`/nix/store/q72ykn5nq6f88dxvika5vpzj003p2wcz-pkgre-js-compat-node-npm-26.7.0-12.0.2/bin/{node,npm}`. Explicit Deno limitation:`denoCurrent = denoMinimum`;both attrs resolve to identical drv `/nix/store/2dg3w9blih7bhjlqrhnqi7k2h0ss3pmh-pkgre-js-compat-deno-2.9.5.drv` and output `/nix/store/fiysiphwgvj51dbanh0b9wlczidx4j10-pkgre-js-compat-deno-2.9.5`;“current” is an alias,not independently newer coverage.

Source-provenance resolution:flake Git 2.55.0 has retained flat source derivation URL+SHA-256;Rust 1.95.0 is a six-archive composition(Cargo,rustc,rust-std,rust-docs,Clippy,rustfmt),all six retained archive bytes were locally rehashed;Node 24.19.0 has retained flat source derivation URL+SHA-256 and npm 11.17.0 is bundled in that Node source,not a separate npm source;`devShell` is a composition of Rust,curl,Git,GNU tar,nixfmt,Node plus stdenv/Bash machinery and therefore has no single upstream archive. Flat hashes identify exact archive bytes;the nixfmt recursive NAR hash identifies the unpacked source tree,not GitHub tarball bytes;flake `narHash`,`.drv` path,and package output path are not tool archive hashes.

Remaining provenance blocker is narrower but real:the captured original host Nix 2.34.8 and Git 2.54.0 `.drv` files were garbage-collected. Current surrogate derivations produce the same observed output paths and expose plausible source rows(Nix recursive source NAR;Git flat archive),but cannot prove the missing original derivations used those source declarations. `source-provenance.json` classifies both as `blocked-original-derivation-missing`;surrogate rows are corroboration only.

## Exact feature-selected Cargo closure

Method:`cargo metadata --locked --offline --format-version 1`+root reachability through `resolve.nodes[].dependencies`;features=`resolve.nodes[].features`;original human confirmation used `cargo tree --locked --offline -p <root> -e features`. Complete rows:`closure/cargo-closure-summary.json`;source/graph proof:`closure/cargo-metadata.json`;lock proof:`closure/Cargo.lock`.

| Root/union | Packages incl root(s) | Third-party | Selected `(package,feature)` pairs |
|---|---:|---:|---:|
| `pkgre-rust` | 55 | 54 | 113 |
| `pkgre-proxy` | 155 | 154 | 305 |
| workspace union | 174 | 172 | 347 |

Independent reproduction:every root row `(name,version,source,sorted features)` exactly equals metadata reachability;lock packages=metadata packages=174;only source-less packages=`pkgre-rust 0.5.0`,`pkgre-proxy 0.2.0`;every other source exactly `sparse+https://rust.pkg.re/`.

## Builds+tests

- PASS `nix build --no-link` for Rust/proxy/JS+all minimum/current client attrs:exit=0,elapsed=0.8666725061 s,Nix-client max RSS=205,304 KiB;outputs cached/store-available;RSS excludes daemon builders.
- PASS `nix flake check --print-build-logs`:exit=0,elapsed=3.5485330750 s,Nix-client max RSS=557,388 KiB;`all checks passed!`;all x86_64 outputs cached→`running 0 flake checks`;aarch64 omitted incompatible;this proves evaluation/cached-output validation,not fresh builder execution/RSS.
- PASS clean Rust workspace test:exit=0,elapsed=15.9146318301 s,max child RSS=1,188,220 KiB;groups=23+0+2+145+0+1+2+0+0=173 passed/0 failed. Earlier exit=101 retained as bounded exact excerpt:external `CARGO_TARGET_DIR` redirected binaries while `registry_e2e` expected nested local `target/debug/consumer`;clean rerun without override passed;classification=collection explanation corroborated by paths+rerun,not product failure.
- PASS JS `node --test` under Node 24.19.0:exit=0,elapsed=0.1856218833 s,max RSS=53,564 KiB;47 pass/0 fail.

## Performance+artifacts

Single warm-cache wall samples;RSS=`resource.getrusage(RUSAGE_CHILDREN).ru_maxrss`;not production capacity bounds. Inputs recorded by original collector:`pkgre-rust@f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`,`pkgre-js@f43bd58bd3d4e36f8b3f4df3c002735c977acd17`,claimed clean before/after;no surviving independent commit/status transcript.

| Operation | Result | Elapsed | RSS | Output evidence |
|---|---|---:|---:|---|
| Rust `check` | PASS;747 packages | 0.0255178688 s | 11,592 KiB | log only |
| Rust `render`+`verify` | PASS | 1.4841489950 s | 11,560 KiB | 563 files/2,129,784 B;inventory SHA-256=`3bb3bb68f3b1b7335050d2ad254bb32dcee1e35208c6f6c1b80fe22a1bef8dce`;555 index files/747 JSON records/3 crates/5 metadata files/747 routes |
| JS `render-routes`+`verify`+canonical diff | PASS | 0.0951067633 s | 43,856 KiB | 7 files/18,640 B;inventory SHA-256=`b8afe7d5ed2664e81278f7ac366820a5dcb0a18cab2150afef4f43963e92f94e` |
| JS `render-final`+`verify`+canonical diff | PASS | 0.0890561412 s | 45,160 KiB | 8 files/19,785 B;inventory SHA-256=`fbc5ccb289a61182502217ae170034e170f3073fbe9c7bfbc411c1c05701595b` |

Rendered trees omitted;exact inventories retained and independently checked for their own hash,line count,byte sum. Original logs state tree verification+canonical diffs passed. Rust/JS exact-tip CLIs have no `export`;measured equivalents are `render`,`render-routes`,`render-final`.

## Layout+validation

- `inventory.json`:complete normalized facts+classification+blockers.
- `closure/`:complete rows,metadata graph,Cargo lock.
- `config/`:exact selected fixed-basis lock/tool/wrapper/registry configuration;not full source.
- `logs/`:exact selected provenance;successful full test summaries;bounded exact first-failure excerpt;time records.
- `performance/`:render tree inventories only.
- `validate.py`:Python-stdlib deterministic validator;rewrites `validation.json` then `SHA256SUMS` (all regular evidence files except `SHA256SUMS`;excludes no substantive artifact).
- `validation.json`:machine result;`SHA256SUMS`:artifact integrity manifest.

## Blockers/caveats

1. No fresh-builder/daemon peak RSS;cached Nix validation only.
2. No native aarch64 execution.
3. No export timing because subcommands absent.
4. Source-repository cleanliness/upstream divergence+performance input identities remain collection-record claims;not independently re-queried.
5. Flake-supplied Git/Rust/Node/devShell source provenance is resolved in `source-provenance.json`;the captured original host Nix 2.34.8 and Git 2.54.0 derivations are absent,so same-output surrogate derivations are corroboration only and cannot prove the missing original source declarations.
6. This is bounded toolchain/build/closure/performance D0 evidence,not complete rollout D0;network/deployment/TLS/ruleset/signing/raw-nginx/archive-import/quota/time/lifecycle gates remain separate.
7. Harness issues:none observed.
