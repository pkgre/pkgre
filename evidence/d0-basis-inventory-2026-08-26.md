# D0 basis+inventory aggregate — 2026-08-26

Status:gate=BLOCKED | D1 authorized=false | record=committed blocked-gate evidence,not a D0 pass | scope=public Rust+JS registries+shared deferred-LAN contract | mutations=repository evidence only;no deployment,DNS,GitHub-setting,credential,or protected-catalog-ref mutation

## 1. Claim boundary+classification

Classification vocabulary:OBSERVED=captured fact at the stated basis/time;PROPOSED=exact review candidate,not deployed or approved;ABSENT=confirmed not present/selected;BLOCKED=required fact,authority,proof,or operator decision is missing or unsafe. Packet-level PASS means artifact integrity/bounded subproof only;it never overrides this aggregate gate.

No secret, credential, or private-key value was read or recorded

Safety boundary:credential/private-key path metadata and public certificate bytes/hashes were inspected where stated;the Gandi token value and every private-key value were not read,printed,hashed,or retained. Monitoring is long-term operational work only and is not a runtime,readiness,D0,or launch dependency;the rejected bare-Wind blackbox branch remains excluded.

## 2. Evidence packet index+integrity authority

All substantive machine evidence is under `fixtures/d0-v1/basis-inventory/`;each packet has complete `SHA256SUMS` coverage and a bounded report or machine result. The repository verifier is `scripts/verify-d0-evidence.py`.

| Packet | Classification | Authority/use |
|---|---|---|
| `fixtures/d0-v1/basis-inventory/basis-refetch/` | OBSERVED | four immediate fetch/prune/upstream/ancestry/status records |
| `fixtures/d0-v1/basis-inventory/github-governance/` | OBSERVED+ABSENT+BLOCKED | GitHub identity,rulesets,protection,Actions,workflows,environments,Pages,deployments,artifacts,audit capability |
| `fixtures/d0-v1/basis-inventory/git-storage/` | OBSERVED+ABSENT+BLOCKED | Git objects/paths/filesystem,public ref probes,Rain deployment,credential metadata,Pages/rollback gaps |
| `fixtures/d0-v1/basis-inventory/js-catalog/` | OBSERVED+ABSENT+BLOCKED | complete fixed-basis JS catalog/archive/render closure |
| `fixtures/d0-v1/basis-inventory/js-client-policy/` | OBSERVED+BLOCKED | npm/Bun/Deno policy profiles,precedence,loopback matrix,historical public-contact incident |
| `fixtures/d0-v1/basis-inventory/live-deployment-network/` | OBSERVED+ABSENT+BLOCKED | live Rain/container/nginx/ACME/DNS/TLS/HTTP/listener/firewall/time/credential metadata |
| `fixtures/d0-v1/basis-inventory/nginx-raw-target/` | OBSERVED+BLOCKED | isolated nginx raw-target/private-field transport primitive;production policy/integration gap |
| `fixtures/d0-v1/basis-inventory/public-routes/` | OBSERVED+BLOCKED | source-derived current public URL universe,bytes,headers,redirects,audience,source,and intended D8–D14 mapping;access-log-only alias completeness unproved |
| `fixtures/d0-v1/basis-inventory/rain-identity-design/` | PROPOSED+ABSENT+BLOCKED | future compatibility/rollback identities,ports,state datasets,permissions,quotas,limits;not deployed |
| `fixtures/d0-v1/basis-inventory/resource-time-lifecycle/` | OBSERVED+PROPOSED+BLOCKED | exact current sizes+samples,review-candidate maxima/time/lifecycle vectors,missing native proofs |
| `fixtures/d0-v1/basis-inventory/rust-catalog/` | OBSERVED+ABSENT+BLOCKED | complete fixed-basis Rust catalog/render/archive/Cargo closure |
| `fixtures/d0-v1/basis-inventory/ssh-signing/` | OBSERVED+BLOCKED | isolated v1 Git SSH-Ed25519 compatibility proof;fixture identity only |
| `fixtures/d0-v1/basis-inventory/toolchain-closure/` | OBSERVED+BLOCKED | exact Nix/toolchain/derivation/output/config/schema/feature-selected closure evidence |

## 3. Fixed bases+refetch chronology

The renderer/indexer basis remains the reviewed upstream commit;later implementation-repository commits are evidence-only forward commits and do not silently replace the reviewed renderer basis.

| Repository | Role | Fixed reviewed basis | Refetch result at `2026-08-26T12:50:06Z..12:50:11Z` | Object format |
|---|---|---|---|---|
| `pkgre/pkgre` | implementation | `066293df21743cbf41fb571a38f2bb94059e7274` | local evidence HEAD then=`1d44dfeaeafef2b1a5341c13bf73647dcbc925ec`;upstream=`066293df21743cbf41fb571a38f2bb94059e7274`;divergence=`1 0`;reviewed ancestor=true;clean except intentional ahead commit | `sha1`;40 hex |
| `pkgre/rust` | public Rust catalog | `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` | HEAD=upstream=fixed basis;divergence=`0 0`;clean;reviewed ancestor=true | `sha1`;40 hex |
| `pkgre/js` | public JS catalog | `f43bd58bd3d4e36f8b3f4df3c002735c977acd17` | HEAD=upstream=fixed basis;divergence=`0 0`;clean;reviewed ancestor=true | `sha1`;40 hex |
| `infra` | Rain declaration | `5f68539bd99c6952b6d73fe2596c27ad4a319f57` | HEAD=upstream=fixed basis;divergence=`0 0`;clean;reviewed ancestor=true | `sha1`;40 hex |

Reconciliation:the older `fixtures/d0-v1/basis-inventory/git-storage/source-network.json` accurately records its own `fresh_fetch_performed=false` freshness limitation. The later successful `fixtures/d0-v1/basis-inventory/basis-refetch/` run supersedes only that freshness limitation;it does not close governance,signing,deployment,storage,edge,time,resource,rollback,or credential blockers. Continue from current evidence tip while preserving the four fixed bases above as content authority.

## 4. Catalog+route closure

### 4.1 Rust

| Classification | Fact |
|---|---|
| OBSERVED | schema=4;one registry=`main`;9 categories;911 permanent homes;555 names with versions;356 reserved empty homes;747 active versions;0 removed;5,518 dependency edges;744 crates.io sources+3 Git-tag sources |
| OBSERVED | index=`sparse+https://rust.pkg.re/`;current download template=`https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}`;declared Cargo=1.95.0 |
| OBSERVED | fixed render=563 files/2,129,784 B;555 sparse rows/747 JSON records;largest inline=`release.json` 459,017 B;largest sparse row=`/we/b-/web-sys` 107,745 B |
| OBSERVED | current source tree contains 3/747 `.crate` bodies=229,784 B;744 bodies are absent from the catalog tree |
| OBSERVED | authoritative scratch rehearsal fetched+verified 747/747 unique archives;failures=0;raw/logical bytes=129,833,713;largest=9,679,450 B;repo+checkout allocated peak=261,058,560 B |
| BLOCKED | scratch current-closure success does not prove append-only history growth,provider ceiling,Rain/ZFS quota,power-loss semantics,backup capacity,or restore duration |
| BLOCKED | schema 4 has no audience field;current public classification is a migration classification,not an observed schema value |

### 4.2 JavaScript

| Classification | Fact |
|---|---|
| OBSERVED | schema=`pkgre-js-catalog-v1`;registry=`main`;package/version/dist-tag=`1/1/1`;dependency edges=0;only `pkgre-js@0.1.0`;source kind=first-party |
| OBSERVED | evaluation/published/admitted=`2026-08-25T23:27:24.000Z`;minimum age=2,592,000 s;current validator applies age only to npmjs;first-party exclusion is implicit |
| OBSERVED | one `.tgz`=16,717 B;SHA-256=`07e3bbe05bffd0994601324a6519621dd93c6990e9350b04019c8366942207e3`;packument `/pkgre-js`=996 B;SHA-256=`6cd8e81ee6efebfbed3f8df101ef9fc174672e7855933c6ec4d989697f06722d` |
| OBSERVED | legacy marker `/v1/js/main/07e3bbe05bffd0994601324a6519621dd93c6990e9350b04019c8366942207e3`=561 B HTML;dynamic target will use typed redirect and `redirectMarkerSchema:null` |
| ABSENT | scoped-package production fixture;audience,append-only retained-route,terminal-state,and dynamic-state fields |
| BLOCKED | live public origin captured 9 ordinary `502` responses+one marker `503`;repository bytes remain authority but are not live-continuity evidence |

### 4.3 Enumerated source-derived old→intended public URL map

OBSERVED within the enumerated source-derived universe:`2072` unique `(origin,rawPath)` keys;duplicate mappings=`0`;probe transport errors=`0`;every enumerated key has one audience,source,external observation,and D8–D14 descriptor. Rust:566 repository-backed `rust.pkg.re` routes=`200`;747 canonical same-host `/v1/...`=`404`;747 `dl.rust.pkg.re` aliases=`307` with zero body and catalog-derived closed `Location`;2 legacy public admin routes=`200`. JS:9 ordinary routes=`502`;one marker route=`503`. Rust workflow pin `ae1dfbfd4e965dffb538e356f005e4fbb32fdb77` and reviewed renderer `066293df21743cbf41fb571a38f2bb94059e7274` produced byte-identical 563-file output. Source-of-truth route data:`fixtures/d0-v1/basis-inventory/public-routes/routes.json`;compact transition map:`fixtures/d0-v1/basis-inventory/public-routes/old-to-intended.jsonl`.

BLOCKED universal/access-log completeness:the enumerated universe covers fixed source-publication routes,known GitHub Pages `index.html` aliases,current nginx host routing,and catalog-derived identities only. Complete access logs were not captured;access-log-only unknown aliases and otherwise unenumerated deployed paths remain unproved and cannot be claimed absent.

PROPOSED intentional changes:D8 Rust same-host `/v1` `404→307`;D9/D10 `307→body`;D11 JS packument/object activation and HTML marker→typed `307`;D12 JS `307→body`;D14 provider/control/admin/legacy paths retire only after independent operator gates. No enumerated old key is unclassified or silently omitted.

## 5. Toolchain+provenance+locked closure

Flake lock v7 pins `nixpkgs=2c423e03bbafcff28bfadc6781a4a8257f205cb5` (`narHash=sha256-dt4WdcvsA8/RCe+VZZwqU0X+XMM3wBbGCWA0/sFWzGo=`) and `rust-overlay=fd2ebb9cc4323d0c5a1336138dab5c3c5a5d8bd9` (`narHash=sha256-YT4Fs2k7bi+7YzuLt93EtIRgjpwHK5ZfsQEIh5dEQSk=`). Machine-authoritative per-row versions,Nix attributes/contexts,derivations,outputs,wrappers,config paths,and direct source URLs/SRI hashes only where captured are in `fixtures/d0-v1/basis-inventory/toolchain-closure/inventory.json`. ABSENT direct upstream archive provenance:host Nix 2.34.8+Git 2.54.0 and flake-supplied Git 2.55.0,Rust 1.95.0,indexer Node 24.19.0,and devShell;their observed Nix/flake identities do not substitute for uncaptured direct archive URL+hash rows.

| Role/version | Nix attribute/context | Derivation→output | Source/config note |
|---|---|---|---|
| rustc+Cargo 1.95.0 | `pkgs.rust-bin.stable."1.95.0".default.override { extensions=["clippy" "rustfmt"]; }` | `/nix/store/hpi7bjzbbz2ilfdcjwyckvjl2x5x3k00-rust-default-1.95.0.drv`→`/nix/store/n4d5w91wqhiisr5rkjxhfssllbcdwai5-rust-default-1.95.0` | flake-pinned;`config/rust-toolchain.toml`,`config/flake.nix` |
| indexer Node 24.19.0/npm 11.17.0 | `pkgs.nodejs_24` | `/nix/store/px8hj7awj6ffpcamsaf95ywrmnn8n6aq-nodejs-24.19.0.drv`→`/nix/store/glcp73hgagq2b24i80jlgbvj28vdb6kk-nodejs-24.19.0` | bundled npm;flake-pinned |
| npm minimum Node 24.15.0/npm 12.0.2 | `packages.x86_64-linux.js-client-node-minimum` | `/nix/store/99x4lfl8mr0d44k1w7hhkcj97jpkmgpq-pkgre-js-compat-node-npm-24.15.0-12.0.2.drv`→`/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2` | Node archive SRI=`sha256-RyZVWB+4UVWXMMSHY+DJ07wll1xZ1RgAP8CEnT5LoPY=`;npm 12.0.2 separately overlaid from npm tarball SRI=`sha256-XbuGxx0HoZV/LpBzQJLdali9zZ68LY1ByhxuaiHTZOE=`;effective `node=/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2/bin/node`,`npm=/nix/store/m204igzgcqxgs4glkqjhdk8fyw8gs7id-pkgre-js-compat-node-npm-24.15.0-12.0.2/bin/npm`;direct execution=`v24.15.0`,`12.0.2` |
| npm current Node 26.7.0/npm 12.0.2 | `packages.x86_64-linux.js-client-node-current` | `/nix/store/k275mh0nrpwd36q1nk926bmpz6lxx8ch-pkgre-js-compat-node-npm-26.7.0-12.0.2.drv`→`/nix/store/q72ykn5nq6f88dxvika5vpzj003p2wcz-pkgre-js-compat-node-npm-26.7.0-12.0.2` | Node archive SRI=`sha256-mCqiTdi+TIicaoqzN93/OwiWZFsg9COTVugFUsFid+4=`;same separately overlaid npm 12.0.2;effective `node=/nix/store/q72ykn5nq6f88dxvika5vpzj003p2wcz-pkgre-js-compat-node-npm-26.7.0-12.0.2/bin/node`,`npm=/nix/store/q72ykn5nq6f88dxvika5vpzj003p2wcz-pkgre-js-compat-node-npm-26.7.0-12.0.2/bin/npm`;direct execution=`v26.7.0`,`12.0.2` |
| Bun 1.3.14 minimum | `packages.x86_64-linux.js-client-bun-minimum` | `/nix/store/xh6ybvw0dnv7v5lgrvdmmvn9s1i0ym89-pkgre-js-compat-bun-1.3.14.drv`→`/nix/store/97nqn1lwdhhc995sfni0zrfxi3xpaq00-pkgre-js-compat-bun-1.3.14` | archive SRI=`sha256-lR7iruhV8IWVruxiJSJqKY0/6oOj3NZGXAnLzN9+hI8=` |
| Bun 1.4.0 current | `packages.x86_64-linux.js-client-bun-current` | `/nix/store/jvj8fg55y3c2a90jn4fyb3prm6xlg7p4-pkgre-js-compat-bun-1.4.0.drv`→`/nix/store/4a3ipscbmyb712xb9yzb5aypwz26ldb3-pkgre-js-compat-bun-1.4.0` | archive SRI=`sha256-LQP7X7g6yLVnrKCigbLOGhoZ1Ij1bClo2Iw/Jekv5FI=` |
| Deno 2.9.5 minimum+current alias | `packages.x86_64-linux.js-client-deno-{minimum,current}` | `/nix/store/2dg3w9blih7bhjlqrhnqi7k2h0ss3pmh-pkgre-js-compat-deno-2.9.5.drv`→`/nix/store/fiysiphwgvj51dbanh0b9wlczidx4j10-pkgre-js-compat-deno-2.9.5` | archive SRI=`sha256-iwEKOxpKAYimfNuKeic0iypQGveK7H/HTyrOFnNo1TA=`;current is not independently newer coverage |
| `pkgre-rust` 0.5.0 | `packages.x86_64-linux.rust` | `/nix/store/6c2aa3pzzdm5k5nalk1crdcinynwwvzj-pkgre-rust-0.5.0.drv`→`/nix/store/bqiaxi9lhg0a8mva3qwmnys70mhnx1wk-pkgre-rust-0.5.0` | fixed Git basis `066293df…`;Cargo config+lock captured |
| `pkgre-proxy` 0.2.0 | `packages.x86_64-linux.proxy` | `/nix/store/a0950b3qzcanrcalvwlp1b45nrya39xn-pkgre-proxy-0.2.0.drv`→`/nix/store/1a25f3q7qvdxgcbcjs267h395xzy4016-pkgre-proxy-0.2.0` | fixed Git basis `066293df…` |
| `pkgre-js` 0.1.0 | `packages.x86_64-linux.js` | `/nix/store/wvjs6v8qlpsjmg7vh569kabnax4bslvx-pkgre-js-0.1.0.drv`→`/nix/store/w571i59xsy6xabx7xp4n7mkxn6w76fv5-pkgre-js-0.1.0` | fixed Git basis `066293df…`;npm lock v3 |

OBSERVED Cargo closure:lock v4;174 selected packages including two local roots;172 third-party packages;every third-party source is exactly `sparse+https://rust.pkg.re/`;indexer=55 packages/113 feature pairs;proxy=155/305;union=174/347. OBSERVED current `.cargo/config.toml` replaces crates.io but lacks mandatory `[net] offline=true`. BLOCKED:future `pkgre-rust-serve` feature/lock delta and removal of proxy-only `reqwest` closure do not exist;D3 admission remains blocked. Build/test evidence:173 Rust tests pass;47 JS tests pass;cached Nix outputs/checks pass;fresh-builder daemon RSS and native aarch64 execution are absent.

## 6. JS client policy

OBSERVED profiles:production registry=`https://js.pkg.re/`;authoritative test registry=`http://127.0.0.1:48730/`;distinct read-only npm/Bun/Deno configs+controlled HOME/cache per client. The dependency-free wrapper rejects caller CLI extras,registry/config/cache/token/proxy/TLS environment,discoverable configs,foreign/non-registry sources,lifecycle scripts,extensions,and trusted-dependency hazards before client execution. Exact files+hashes:`fixtures/d0-v1/basis-inventory/js-client-policy/configs/`,`wrappers/policy_wrapper.py`,`inventory.json`.

| Client | OBSERVED precedence+frozen command |
|---|---|
| npm 12.0.2 | `CLI --registry`>`NPM_CONFIG_REGISTRY`>project `.npmrc`>selected user config;`CLI --userconfig`>`NPM_CONFIG_USERCONFIG`;wrapper supplies validated npmrc+empty global config;command=`npm ci` |
| Bun 1.4.0 | CLI>`BUN_CONFIG_REGISTRY`/`NPM_CONFIG_REGISTRY`>bunfig>project `.npmrc`>user/global;command=`bun --config=/absolute/path install --frozen-lockfile --ignore-scripts` |
| Bun 1.3.14 | project `.npmrc` can override even explicit bunfig;wrapper therefore rejects discoverable `.npmrc`;same safe `--config=` command |
| Deno 2.9.5 | registry=`NPM_CONFIG_REGISTRY`>project `.npmrc`>`$HOME/.npmrc`;`NPM_CONFIG_USERCONFIG` ignored;age CLI>`deno.json` while `deno ci` has no age override and rejects `--config`;wrapper supplies controlled project config+HOME `.npmrc`;command=`deno ci` |

OBSERVED authoritative loopback run:6 pinned client instances;66 cases=36 accepted+30 fail-before-exec;36 loopback connects/GETs;unexpected connects=0;cache-only connects/requests=0. BLOCKED historical incident:a superseded Bun invocation misparsed `--config /tmp/policy.toml` and made one `GET https://registry.npmjs.org/probe-missing`→404;no install,publish,login,token,or mutation. This cannot be erased by the later isolated PASS. Server-side 30-day admission remains authoritative;locked replay is not claimed to reevaluate age.

## 7. Git+filesystem+archive feasibility

OBSERVED all four bases:Git 2.54.0 local inventory;SHA-1/40-hex;strict full fsck+connectivity pass;complete/non-shallow;no missing objects,alternates,grafts,promisor/partial clone,replace refs,namespaces,gitlinks,submodules,LFS pointers/filters,active hooks,tree symlinks,or special modes;current paths pass UTF-8/NFC and bytewise case/NFC/NFD collision checks. Development filesystem=`zfs` `/home`,idmapped+xattr+posixacl+casesensitive;artifact-only rename+file/dir fsync and distinct case/NFC/NFD/invalid-UTF-8 probes pass.

| Repo | Tree entries;unique blobs/bytes | Reachable objects/decompressed bytes | Canonical tree SHA-256 |
|---|---|---|---|
| `pkgre` | `139;116/2,198,793` | `572/5,933,962` | `a300d0d16f80e69616cd5f6f2cb1c6346e8e528861252df722e9cfb3a709f487` |
| `pkgre-rust` | `773;763/1,958,607` | `905/4,268,529` | `ebb632e21d7553d46da4b3db0c4dac5be1cdd6ec2b51a1c21a3c59e511492355` |
| `pkgre-js` | `67;22/57,651` | `76/79,350` | `437e0a2c702e933d82fbbfad1cc89d68d17266e2cf56bedcb9a479c3ce425fdd` |
| `infra` | `348;275/769,434` | `16,091/17,819,872` | `236b4017dfdf691e31eba76041a6ad491ceca512145b350f9ab4ab864c424499` |

BLOCKED production layout:local repos are non-bare development worktrees with broad SSH origins/refspecs and developer-owned readable storage;production exact-ref bare mirrors,ownership,modes,quotas,disablement policy,crash semantics,and backup/restore do not exist. Public exact-ref anonymous HTTPS probes passed without redirect for Rust+JS;canonical runtime origins are frozen below. Archive rehearsal proves current Rust closure on tmpfs only;append-only history model,provider quota,Rain quota,reserve,production clone/fetch/checkout amplification,backup/restore capacity+time remain absent. No LFS,submodule,request-time fetch,shared CAS,or external mutable object store is authorized as an implicit workaround.

## 8. Source/admission authority+signing/governance

### 8.1 Public catalog authority table

| Instance | Canonical origin/transport/full ref | OBSERVED current writer+checks+environment | OBSERVED current signature | PROPOSED runtime refs+bootstrap+contract | ABSENT/BLOCKED authority fields |
|---|---|---|---|---|---|
| Rust public | `https://github.com/pkgre/rust.git`;anonymous HTTPS;`refs/heads/main` | sole collaborator=`sorpaas` admin;legacy protection requires strict `validate` app `15368`,admins enforced,linear history,no force/delete;0 approvals;`github-pages` env ID `20395247571`,reviewers=[];admin bypass=true | tip `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`;GitHub verified PGP;not v1 SSH | refspec=`+refs/heads/main:refs/pkgre/remotes/main`;remote=`refs/pkgre/remotes/main`;candidate=`refs/pkgre/candidates/<40hex>`;accepted=`refs/pkgre/accepted/<40hex>`;bootstrap proposal=fixed tip;`state-contract-v1`;public credential=`null` | D2 ruleset,CODEOWNERS,release workflow/check,protected release env+reviewers,distinct writer/token permissions,SSH signer principal/fingerprint,allowed-signers+revocation digests,instance digest |
| JS public | `https://github.com/pkgre/js.git`;anonymous HTTPS;`refs/heads/main` | sole collaborator=`sorpaas` admin;main unprotected;required checks absent;`github-pages` env ID `20594913798`,reviewers=[];admin bypass=true | tip `f43bd58bd3d4e36f8b3f4df3c002735c977acd17`;unsigned | same refspec/remote/candidate/accepted grammar;bootstrap proposal=fixed tip;`state-contract-v1`;public credential=`null` | all Rust-absent fields plus any branch protection;Actions currently allow all and do not require SHA pinning |

OBSERVED Actions:Rust selected actions+SHA pinning required;JS all actions+no SHA pinning;default workflow token=`read`;workflows use pinned action SHAs. Current Pages workflows are publication/rollback workflows,not signed protected catalog-release writers. CODEOWNERS absent in all supported locations. Organization audit retrieval returned 404/unavailable. Provider-assigned future IDs must be returned after operator action and keyed to frozen names/settings/SHAs;they must never be guessed.

OBSERVED isolated signature compatibility:Git 2.55.0+OpenSSH 10.5p1 created and verified an SSH-Ed25519 signed SHA-1 commit against `allowedSigners`,then reverified a public-only bundle after key/repository deletion. Fixture principal=`state-contract-v1-compat@example.invalid`;fingerprint=`SHA256:+uZsRMJhsMrNNuIpWh9wzwU8B9w5T6TMpEsmT2eBxvA`;fixture-only and forbidden for production. BLOCKED production principal,fingerprint,custody,rotation,recovery,allowed-signers digest,revocation digest,and release identity are absent.

## 9. Deployment identity+network/TLS

### 9.1 OBSERVED current Rain topology

Host generation=`/nix/store/bhfadnwczhfsd6zadxhl04jqfp1spp9v-nixos-system-rain-26.11.20260818.9588f1a`;container generation=`/nix/store/jai70s8kdn3jc71qvsn9l20zma9aam4g-nixos-system-pkgre-26.11.20260818.9588f1a`;nixpkgs=`9588f1a6c197ae61c6222a3baa6ac220ec1cc4d9`;nginx 1.30.4 binary=`/nix/store/qzihfqlvbzx0zhjvmx6zimxdz9ghvwm0-nginx-1.30.4/bin/nginx`;config=`/nix/store/nnqs127xdnxi93772sgmgfy7a890alxb-nginx.conf`;config SHA-256=`eeb69be6aebb5e69fdbc12c9019e648f64308b1738c153715411db607d701d51`. Exact deployed infra source commit is BLOCKED:the live generation does not expose it;`5f68539bd99c6952b6d73fe2596c27ad4a319f57` is matching source declaration,not proven deployed provenance.

| Unit | Listener | Identity/state | Status |
|---|---|---|---|
| `pkgre-download-serve.service` 0.1.0 | `10.131.7.4:9008/tcp/http` | DynamicUser;observed `64206:64206`;no StateDirectory | active;747 legacy redirect routes |
| `pkgre-proxy.service` 0.2.0 | `10.131.7.4:9009/tcp/http` | DynamicUser;observed `61225:61225`;no StateDirectory | active;Rust canary passed;JS origin connection/ServiceUnavailable |

Host frontend=`65.21.163.108:80,443`;container addresses=`10.22.2.5`,`10.131.7.4`;host peer=`10.131.7.1`;declared firewall allows source `10.131.7.1` to TCP `{9008,9009}` only. One external vantage timed out against backends;universal future-denial proof is BLOCKED.

### 9.2 PROPOSED dynamic filesystem identities—not deployed

These are review candidates from `fixtures/d0-v1/basis-inventory/rain-identity-design/`,not current units,users,ports,state,or authority. Public body-mode identities are ABSENT and explicitly excluded by that proposal;this alone prevents a complete §11 identity table.

| Variant | Unit/user/group;UID:GID;supplementary groups | Protocol/admin | State root+dataset+quota | Config/trust/credential | Classification |
|---|---|---|---|---|---|
| Rust compatibility | `pkgre-rust-serve-public.service`;`pkgre-rust-serve-public`;`1976:1976`;none | `10.131.7.4:9010`;`127.0.0.1:9110` | `/var/lib/pkgre-rust-serve-public`;`zroot/root/varlib/machine-states/pkgre/pkgre-rust-serve-public`;4 GiB | `/etc/pkgre/pkgre-rust-serve-public.json`;`/etc/pkgre/trust/pkgre-rust-serve-public/{allowed-signers,revocations}`;credential=`null` | PROPOSED |
| Rust body | ABSENT | ABSENT | ABSENT;must use distinct instance digest+state root | ABSENT | BLOCKED |
| Rust rollback compatibility | `pkgre-rust-serve-public-rollback.service`;`pkgre-rust-serve-public-rollback`;`1978:1978`;none | `10.131.7.4:9012`;`127.0.0.1:9112` | `/var/lib/pkgre-rust-serve-public-rollback`;`zroot/root/varlib/machine-states/pkgre/pkgre-rust-serve-public-rollback`;4 GiB | `/etc/pkgre/pkgre-rust-serve-public-rollback.json`;per-instance trust;credential=`null`;watcher disabled | PROPOSED |
| JS compatibility | `pkgre-js-serve-public.service`;`pkgre-js-serve-public`;`1977:1977`;none | `10.131.7.4:9011`;`127.0.0.1:9111` | `/var/lib/pkgre-js-serve-public`;`zroot/root/varlib/machine-states/pkgre/pkgre-js-serve-public`;2 GiB | `/etc/pkgre/pkgre-js-serve-public.json`;`/etc/pkgre/trust/pkgre-js-serve-public/{allowed-signers,revocations}`;credential=`null` | PROPOSED |
| JS body | ABSENT | ABSENT | ABSENT;must use distinct instance digest+state root | ABSENT | BLOCKED |
| JS rollback compatibility | `pkgre-js-serve-public-rollback.service`;`pkgre-js-serve-public-rollback`;`1979:1979`;none | `10.131.7.4:9013`;`127.0.0.1:9113` | `/var/lib/pkgre-js-serve-public-rollback`;`zroot/root/varlib/machine-states/pkgre/pkgre-js-serve-public-rollback`;2 GiB | `/etc/pkgre/pkgre-js-serve-public-rollback.json`;per-instance trust;credential=`null`;watcher disabled | PROPOSED |

PROPOSED shared storage row:idmapped state bind maps guest numeric UID/GID to the same host numeric UID/GID;parent `/var/lib/machine-states/pkgre`=`root:root 0711`;instance dataset/root=`instance:instance 0700` with backup ACL `u:pkgre-state-backup:r-X`+matching default ACL;state directories=`0700`;state files/records/lock=`0600`;`/etc/pkgre`+`/etc/pkgre/trust`=`root:root 0755`;config/trust leaves=`root:<instance-group> 0640`;sole writer=own daemon;readers=daemon,root,ACL-only proposed backup identity `1980:1980`;root is administrative reader,not ordinary live writer;cross-instance reads forbidden. State subpaths=`mirror.git`,`checkouts`,`generations`,`retired-generation-ids`,`staging`,`lock`,`instance`,`accepted`;all commands use `<state>/lock` via pinned exclusive nonblocking `flock`;sandbox writable path=own state root only. BLOCKED:datasets,mounts,quotas,ACLs,idmap,rename/fsync/power-loss,backup reader,restore,and user/port collision recheck are not deployed/proved.

### 9.3 Public network/TLS rows

| Service/vhost | DNS+frontend+required authority | Current/proposed backend | TLS | Classification/gap |
|---|---|---|---|---|
| Rust compatibility + `rust.pkg.re` | OBSERVED `CNAME pkgre.github.io.` TTL 300;Rain cert available;frontend `65.21.163.108:443`;target requires exact SNI=`rust.pkg.re`+authority/Host=`rust.pkg.re` | OBSERVED current `/v1/→10.131.7.4:9009`,other→strict Pages;PROPOSED `9010` after later gate | Let's Encrypt YR2;Gandi DNS-01;`/var/lib/acme/rust.pkg.re/{fullchain.pem,key.pem}`;directory `0750 acme:nginx`;leaves `0640 acme:nginx`;valid `2026-08-22..2026-11-20` | BLOCKED current SNI/Host mismatch selects unrelated default vhost;dynamic edge rewrite+raw-wire probe absent |
| Rust body + `rust.pkg.re` | same canonical origin | ABSENT listener/instance/root | same vhost certificate | BLOCKED complete row absent |
| Rust rollback + `rust.pkg.re` | same canonical origin;not public until explicit switch | PROPOSED `9012`;admin `9112` loopback | same vhost certificate when selected | PROPOSED;no deployed isolated canary/denial/restore proof |
| JS compatibility + `js.pkg.re` | OBSERVED `CNAME rain.pacna.org.` TTL 300→`65.21.163.108`;target exact SNI+authority/Host=`js.pkg.re` | OBSERVED current `/v1/js/→9009`,other→strict Pages;PROPOSED `9011` | Let's Encrypt YE1;Gandi DNS-01;`/var/lib/acme/js.pkg.re/{fullchain.pem,key.pem}`;directory `0750 acme:nginx`;leaves `0640 acme:nginx`;valid `2026-08-25..2026-11-23` | BLOCKED public metadata=`502`,marker=`503`;same authority/default-vhost gap |
| JS body + `js.pkg.re` | same canonical origin | ABSENT listener/instance/root | same vhost certificate | BLOCKED complete row absent |
| JS rollback + `js.pkg.re` | same canonical origin;not public until explicit switch | PROPOSED `9013`;admin `9113` loopback | same vhost certificate when selected | PROPOSED;no deployed initial anchor/canary/denial/restore proof |

Legacy `dl.rust.pkg.re`:OBSERVED `CNAME rain.pacna.org.` TTL 10800;frontend Rain→`9008`;Let's Encrypt YE1;HTTP-01/webroot;`/var/lib/acme/dl.rust.pkg.re/{fullchain.pem,key.pem}`;valid `2026-08-24..2026-11-22`;known route=`307`. It remains rollback/compatibility input through its plan horizon and is not a target dynamic instance.

BLOCKED edge identity:required exact SNI/vhost/authority agreement and literal backend Host overwrite are not implemented;raw target/private verdict is not wired to a production-protected boundary;allowed destination/source ranges and firewall identity for proposed ports are proposal-only;external-denial proof has one vantage only. Permanent `js.pkg.re CNAME rain.pacna.org.` is accepted topology;no A-record conversion is requested.

## 10. Pages+legacy+rollback inventory

| Repo | Pages/source/environment/deploy identity | Retained commit+latest artifact | Direct/custom result | Rollback classification |
|---|---|---|---|---|
| Rust | workflow build;`main:/`;workflow `.github/workflows/pages.yml` ID `340152007`;`github-pages` env ID `20395247571`;job has `pages:write,id-token:write`;custom=`rust.pkg.re`;HTTPS enforced | `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`;deployment `6092749507`;artifact `9583758375`;digest=`sha256:2510e9d77f459d066261a88efe9005d5358c8a9a401aba7042d45fe6f1c2448c`;551,735 B;expired `2026-08-26T21:48:27Z` | custom config/sparse=`200`;strict TLS valid;direct `https://pkgre.github.io/rust/origin-health/v1.txt`=`HTTP/2 301`→`https://rust.pkg.re/origin-health/v1.txt`;162 B;SHA-256=`9e17cb15dd75bbbd5dbb984eda674863c3b10ab72613cf8a39a00c3e11a8492a`;curl success | OBSERVED continuity now;BLOCKED durable bundle,independent custody/readback/restore rehearsal,owner+horizon |
| JS | workflow build;`main:/`;workflow ID `342430387`;`github-pages` env ID `20594913798`;custom=`js.pkg.re`;HTTPS not enforced;Pages certificate absent | `f43bd58bd3d4e36f8b3f4df3c002735c977acd17`;deployment `6094120375`;artifact `9586702051`;digest=`sha256:ba7bb13b843d585898552ecd68d2e9caee55ee27644f3721b48b63d29a5e32c5`;791 B;expired `2026-08-26T23:37:29Z` | default origin redirects to insecure custom origin;custom Rain=`502` | containment-only;never continuity;BLOCKED hash-pinned default-origin publication,legacy-static profile,and `JS-INITIAL-ANCHOR` |

OBSERVED legacy binaries/closures:`pkgre-download-serve 0.1.0` store `/nix/store/wjrvwfxnxzwjvkvcl3j53wkbrgvbkznf-pkgre-download-serve-0.1.0`,closure 6,178,808 B;`pkgre-proxy 0.2.0` store `/nix/store/1a25f3q7qvdxgcbcjs267h395xzy4016-pkgre-proxy-0.2.0`,closure 5,613,352 B. BLOCKED rollback authority:provider artifacts expired same day;mutable refs/artifacts are not mirrored to operator-controlled immutable custody;no hash/readback/isolated restore;restore command order,retention owner,expiry gate,and exact deployed infra source generation mapping are absent.

## 11. HTTP edge proof

OBSERVED primitive PASS:nginx 1.30.4 isolated TLS harness forwarded 174/174 exchanges with exact private raw target+request-form fields;H1 observe/policy=`55/55`,`36/36`;H2=`47/47`,`36/36`;95 captures differed from normalized `$uri`;caller private headers were stripped/overwritten;backend AF_UNIX socket=`0600`;1,725 validator checks,0 errors,174 captures. HTTP/2 proof concerns submitted `:path` semantics,not HPACK bytes.

BLOCKED production admission:the proof policy deliberately forwarded duplicate slash,backslash,dot/encoded/double-encoded separators,raw fragment marker,invalid UTF-8,and scoped npm variants;it also forwarded an H2 pseudoheader-after-regular case. It proves transport only,not the byte-level canonical allowlist. Production Unix/private boundary,missing/duplicate field rejection,exact SNI/Host/authority matching,413/414/431,body/framing/header ownership,compression/range/error behavior,and real Rain H1/H2 ingress→backend proof remain absent. ABSENT/BLOCKED interim/early-hints `1xx`:not tested or observed;D1 must freeze explicit no-`1xx` fixtures and later production-equivalent/real-edge proof must demonstrate the contract before deployment/cutover. No normalized-path fallback is allowed.

## 12. Resources+time+lifecycle

### 12.1 OBSERVED baselines

| Item | Rust | JS |
|---|---:|---:|
| registries/categories/packages/versions/edges | `1/9/911/747/5,518` | `1/0/1/1/0` |
| catalog bytes | 1,705,601 excluding archives | 1,650 |
| Git tree entries/logical bytes | `773/1,958,607` | `67/93,998` |
| target descriptors | 2,055 | 3 |
| largest inline | 459,017 B | 996 B |
| renderer warm sample | 1.4841 s/11,560 KiB RSS | 0.0891 s/45,160 KiB RSS |
| archive closure | 747/129,833,713 B;largest 9,679,450 B | 1/16,717 B;inflated tar 77,824 B |

ABSENT native-server facts:steady RSS;two-snapshot peak;three-snapshot+old-stream peak;peak FDs/tasks;100-cycle reload distribution;SIGTERM/SIGKILL/drain/lease measurement;canonical active manifest+actual `snapshotBytes`. Renderer/legacy RSS is not a native-server bound.

### 12.2 PROPOSED review envelope—not approved

Rust/JS ZFS quota=`4,294,967,296/2,147,483,648 B`;MemoryHigh=`402,653,184/536,870,912 B`;MemoryMax=`536,870,912/805,306,368 B`;TasksMax=64;LimitNOFILE=2,048;request concurrency=256;archive streams=64;stream buffer=65,536 B;raw target=4,096 B;headers=64 fields/32,768 B total/8,192 B each;request body=0;archive each=134,217,728 B;archive count=`4,096/32,768`;archive total=`402,653,184/201,326,592 B`;snapshot=`16,777,216/33,554,432 B`;routes=`32,768/65,536`;packages=`8,192/4,096`;versions=`16,384/32,768`;edges=`131,072/262,144`;fetch network+pack=`536,870,912/536,870,912 B` Rust and `268,435,456/268,435,456 B` JS;inflated objects=`1,073,741,824/536,870,912 B`;objects=65,536;checkout=`536,870,912/268,435,456 B`. Complete limit/limit+1 vectors are in `fixtures/d0-v1/basis-inventory/resource-time-lifecycle/resource-limit-fixtures.json`.

PROPOSED watcher:60 s±15 s;connect=10 s;fetch wall=30 s/CPU=20 s;backoff 30→900 s;reload wall=120 s;SIGTERM drain=30 s;systemd stop=35 s;request/generation lease=120 s. PROPOSED clock:future skew≤300 s;synchronized for 600 s before acceptance;offset≤1 s;within-boot realtime/monotonic delta bounds=`-5 s` and `2 s`;failure rejects candidate,LKG remains ready. OBSERVED one Rain sample:timesyncd active;synchronized;NTP active;offset `-198us`;root distance `831us`. BLOCKED 24-hour dual-clock proof,fault injection,source/config pin,and operator approval.

Resource proposal still contains implementation-dependent/null hard-maxima inputs in the broader instance design;it is not a frozen instance digest or D0 pass. Operator must either provide+approve complete D0 bounds and production capacity evidence or explicitly amend the phase plan so native-server empirical measurements close in D4 before D7 while D1 proceeds only on conservative design ceilings.

## 13. Credential+key inventory

| Classification | Path/identity | Owner/mode/readers/purpose | Finding/action |
|---|---|---|---|
| BLOCKED critical | `/var/lib/keys/pkgre-js-gandiv5-token` | regular file;`root:root`;`0644`;ACL=`user::rw-,group::r--,other::r--`;41 B;shared Gandi DNS-01 PAT source for Rust+JS ACME | group/other readable;shared blast radius;treat as exposed;permission repair,rotation/revocation,provider scope+audit are unproved;documented compromise response+recovery procedure are ABSENT;value was not read |
| OBSERVED+BLOCKED | `/var/lib/acme/{rust.pkg.re,js.pkg.re,dl.rust.pkg.re}/{fullchain.pem,key.pem}`+ACME account key | current unprivileged collection observed parent directories only and could not traverse leaves;bounded same-generation historical metadata reported directories=`acme:nginx 0750`,certificate/key leaves=`acme:nginx 0640`,TLS keys=227 B;nginx reader;no private bytes read | current leaf metadata is unavailable;historical metadata is not a current attestation;ACME account-key path/owner/mode/readers plus certificate/account-key rotation,revocation,compromise response,and recovery procedure are ABSENT |
| BLOCKED | production catalog SSH-Ed25519 signer+`allowedSigners`+revocations | paths/principal/fingerprint/digests/custody/readers absent | operator must freeze public trust data+private custody/rotation/revocation/compromise response/recovery;fixture identity cannot be reused |
| OBSERVED+BLOCKED | Rain SSH host key | `rain.pacna.org`;SSH-Ed25519 fingerprint=`SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI`;10 matching scans;strict TOFU fixture | continuity only;operator out-of-band attestation plus host-key rotation,revocation/client-remediation,compromise response,and recovery procedure are ABSENT |
| ABSENT | public runtime Git credential | `null`;public exact HTTPS fetch is anonymous | desired public mode;no generic credential slot |
| ABSENT | selected LAN credential | no LAN instance/config/credential exists | D13 must define per-instance reader,provider,scope,path,rotation/revocation/compromise response/recovery before any LAN edit |

## 14. LAN boundary

ABSENT:no LAN-public instance,hostname,origin,vhost,listener,address,range,firewall row,DNS view,TLS identity,catalog origin/full ref/bootstrap,config,state root,credential,signer,trust set,or public-base mode is selected. This is an explicit D0 deferral,not an invented placeholder and not authorization. Shared contract only:separate service identity,state root,trust set,credential path/readers,read-only provider,network admission,no public-instance reuse,and no catalog-selected trust/credential mechanism. D13 must create every concrete identity row before the first LAN source,implementation,configuration,credential,DNS,TLS,or deployment edit.

## 15. Blocking register

| ID | Classification | Blocking fact | Primary evidence |
|---|---|---|---|
| D0-B01 | BLOCKED critical | Gandi PAT metadata=`0644 root:root` with group/other read;permission repair,rotation/revocation,provider scope+audit,and documented compromise response+recovery are absent | `fixtures/d0-v1/basis-inventory/live-deployment-network/`;`fixtures/d0-v1/basis-inventory/git-storage/` |
| D0-B02 | BLOCKED | Rain SSH key has TOFU continuity only;operator out-of-band fingerprint attestation and host-key rotation/revocation/client-remediation/compromise/recovery lifecycle are absent | `fixtures/d0-v1/basis-inventory/live-deployment-network/` |
| D0-B03 | BLOCKED | JS `main` unprotected/unsigned;Actions allow all/no SHA pinning;Rust lacks complete D2 ruleset/CODEOWNERS/release environment/distinct writer/SSH requirement | `fixtures/d0-v1/basis-inventory/github-governance/` |
| D0-B04 | BLOCKED | production signer principal/fingerprint,allowed-signers path+digest,revocation digest,custody/rotation/recovery,workflow/check/environment/reviewers/writer permissions are unfrozen | `fixtures/d0-v1/basis-inventory/github-governance/`;`fixtures/d0-v1/basis-inventory/ssh-signing/` |
| D0-B05 | BLOCKED | exact deployed infra source commit cannot be derived from live Rain generation | `fixtures/d0-v1/basis-inventory/live-deployment-network/` |
| D0-B06 | BLOCKED | dynamic static identities,state datasets/mounts/quotas/reserves,ACL/idmap,backup reader,lock wrapper,writable paths,rename/fsync/power-loss and restore proof absent;current exact rows are proposal-only | `fixtures/d0-v1/basis-inventory/rain-identity-design/` |
| D0-B07 | BLOCKED | body-mode public filesystem/network identities are absent;compatibility/rollback proposals cannot stand in for them | `fixtures/d0-v1/basis-inventory/rain-identity-design/` |
| D0-B08 | BLOCKED | immutable Rust+JS rollback bundles,independent custody/readback/restore rehearsals,retention owner+horizon,and `JS-INITIAL-ANCHOR` absent | `fixtures/d0-v1/basis-inventory/github-governance/`;`fixtures/d0-v1/basis-inventory/git-storage/` |
| D0-B09 | BLOCKED | raw-target primitive passes but production byte grammar,private boundary,SNI/authority contract,and deployed H1/H2 integration fail/are unproved | `fixtures/d0-v1/basis-inventory/nginx-raw-target/`;`fixtures/d0-v1/basis-inventory/live-deployment-network/` |
| D0-B10 | BLOCKED | native steady/two-/three-snapshot RSS,FD,reload,drain/lease,HTTP-limit,and 100-cycle results absent;proposed maxima not approved | `fixtures/d0-v1/basis-inventory/resource-time-lifecycle/` |
| D0-B11 | BLOCKED | append-only archive growth,provider/Rain ceilings,production quota/failure recovery,and backup/restore capacity+time absent | `fixtures/d0-v1/basis-inventory/rust-catalog/`;`fixtures/d0-v1/basis-inventory/resource-time-lifecycle/` |
| D0-B12 | BLOCKED | acceptance clock policy unapproved;actual source/config and 24-hour Rain dual-clock/fault proof absent | `fixtures/d0-v1/basis-inventory/resource-time-lifecycle/`;`fixtures/d0-v1/basis-inventory/live-deployment-network/` |
| D0-B13 | BLOCKED | protocol/header/config enums,complete hard maxima,trust digests,and compatibility/body/rollback instance digests remain absent/null | `fixtures/d0-v1/basis-inventory/rain-identity-design/`;`fixtures/d0-v1/basis-inventory/resource-time-lifecycle/` |
| D0-B14 | BLOCKED | Rust catalog has only 3/747 bodies;authorized append-only import has not occurred;schema lacks audience;body mode cannot start | `fixtures/d0-v1/basis-inventory/rust-catalog/` |
| D0-B15 | BLOCKED | Cargo curated closure passes but mandatory `[net] offline=true` and future server lock/feature delta are absent | `fixtures/d0-v1/basis-inventory/rust-catalog/`;`fixtures/d0-v1/basis-inventory/toolchain-closure/` |
| D0-B16 | BLOCKED | JS live origin is unavailable and strict static rollback continuity/initial anchor is absent | `fixtures/d0-v1/basis-inventory/js-catalog/`;`fixtures/d0-v1/basis-inventory/public-routes/`;`fixtures/d0-v1/basis-inventory/git-storage/` |
| D0-B17 | BLOCKED | Deno “current” is an alias of minimum 2.9.5,not independently newer coverage;scoped npm production fixture absent | `fixtures/d0-v1/basis-inventory/toolchain-closure/`;`fixtures/d0-v1/basis-inventory/js-catalog/` |
| D0-B18 | BLOCKED historical constraint | one superseded Bun command contacted npmjs metadata;later loopback proof cannot erase incident | `fixtures/d0-v1/basis-inventory/js-client-policy/` |
| D0-B19 | ABSENT deferred | no LAN instance selected;must re-enter full D13 gate before any LAN edit | `fixtures/d0-v1/basis-inventory/live-deployment-network/`;`fixtures/d0-v1/basis-inventory/rain-identity-design/` |
| D0-B20 | BLOCKED | enumerated route uniqueness+mapping covers only the source-derived current public URL universe;complete access logs were not captured,so access-log-only aliases and universal deployed-path completeness remain unproved | `fixtures/d0-v1/basis-inventory/public-routes/`;`fixtures/d0-v1/basis-inventory/live-deployment-network/` |
| D0-B21 | ABSENT/BLOCKED | interim/early-hints `1xx` behavior was neither tested nor observed;D1 fixtures+later production-equivalent/real-edge proof must demonstrate the explicit no-`1xx` contract | `fixtures/d0-v1/basis-inventory/nginx-raw-target/`;`fixtures/d0-v1/basis-inventory/live-deployment-network/` |

Closed bounded findings:fixed-basis refetch;route uniqueness+one-to-one mapping within the enumerated source-derived universe;current Rust+JS catalog closures;current Rust archive byte total;Cargo selected closure;isolated SSH signing compatibility;isolated nginx raw-field transport primitive;JS loopback client-policy subrun. Universal/access-log route completeness and `1xx` behavior remain blocked. None closes the blocking register above.

## 16. OPERATOR-HANDOFF D0

Phase:D0

Source commits:`pkgre/pkgre=066293df21743cbf41fb571a38f2bb94059e7274` fixed renderer basis;this aggregate+verifier will be an evidence-only descendant.

Catalog commits:`pkgre/rust=f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`;`pkgre/js=f43bd58bd3d4e36f8b3f4df3c002735c977acd17`.

Infra commit:`5f68539bd99c6952b6d73fe2596c27ad4a319f57` matching declaration only;return exact deployed-source provenance separately.

Validated:all 13 packet manifests+strict JSON/JSONL semantics via `python3 scripts/verify-d0-evidence.py`;enumerated source-derived route rows=`2072` while universal/access-log completeness remains BLOCKED;Rust archives=`747/129833713 B`;Cargo=`174/172 curated`;JS policy=`66` cases;nginx=`174` captures/`1725` checks;interim/early-hints `1xx` remains ABSENT/BLOCKED;expected aggregate result is verifier PASS with `gate=BLOCKED;D1Authorized=false`.

State+limits:no dynamic active manifest,instance digest,quota,MemoryHigh,or MemoryMax is deployed. Proposal only:Rust quota/MemoryHigh/Max=`4GiB/384MiB/512MiB`;JS=`2GiB/512MiB/768MiB`;TasksMax/NOFILE=`64/2048`;do not treat these as approved production facts.

Secrets/files:`/var/lib/keys/pkgre-js-gandiv5-token=root:root 0644`,ACL group/other read,purpose=shared Gandi DNS-01 source;critical. Never return the token value. Current unprivileged collection could not traverse ACME certificate/key leaves;only bounded same-generation historical metadata reported `/var/lib/acme/{rust.pkg.re,js.pkg.re,dl.rust.pkg.re}/{fullchain.pem,key.pem}=acme:nginx 0640` and 227-B TLS keys. ACME account-key metadata+lifecycle are absent;no private value was read.

Deploy:none. Do not deploy Rain,change DNS,change GitHub settings,install/rotate signer material,advance catalog refs,or start D1 from this record.

Current generation+rollback anchor:Rain=`/nix/store/bhfadnwczhfsd6zadxhl04jqfp1spp9v-nixos-system-rain-26.11.20260818.9588f1a`;container=`/nix/store/jai70s8kdn3jc71qvsn9l20zma9aam4g-nixos-system-pkgre-26.11.20260818.9588f1a`;dynamic accepted/generation IDs=ABSENT;Rust Pages is current continuity but not durable custody;JS Pages is containment-only;`JS-INITIAL-ANCHOR`=ABSENT.

DNS before:`rust.pkg.re CNAME pkgre.github.io. TTL 300`;`js.pkg.re CNAME rain.pacna.org. TTL 300`;`dl.rust.pkg.re CNAME rain.pacna.org. TTL 10800`.

DNS after:no change requested;permanent JS CNAME topology remains accepted.

GitHub settings:do not mutate during D0. Return exact intended D2 non-provider-assigned values first;agent will prepare the separate `OPERATOR-HANDOFF D2-SIGNING` before any settings action.

### Operator actions+required returned metadata

1. **Critical credential containment+complete TLS-key lifecycle:**(a) repair the declarative source and live metadata so the Gandi credential has no unauthorized group/other read and only the required system credential loader can access it;rotate/revoke the exposed PAT;inspect provider scope+audit;define compromise response+recovery. Return:path,owner,group,mode,ACL,size,purpose,authorized reader mechanism;old credential provider ID or safe suffix only,revocation timestamp/result;new credential provider ID or safe suffix only,creation/activation timestamp,scope/zone permissions,expiry;bounded audit-event IDs/timestamps/actors/results;compromise-response+recovery owner/steps/test date. (b) Return current metadata-only certificate/key rows for all three ACME names and the ACME account-key path/owner/group/mode/ACL/readers/provider identity plus rotation,revocation,compromise-response,recovery procedure/test metadata. Never return token bytes,hashes of secret/private material,or private material.
2. **Rain SSH attestation+lifecycle:**out-of-band verify `rain.pacna.org` SSH-Ed25519 fingerprint `SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI`. Return:authoritative source/method,operator,UTC timestamp,algorithm,fingerprint,match result;host-key rotation overlap,revocation/client-remediation,compromise response,recovery procedure+test metadata;no private host key.
3. **Exact deployed provenance:**return the infra repository full SHA and build/deploy record that produced both live NixOS generations,or explicitly state it is irrecoverable. Include generation symlink/store paths,deployment timestamp/actor,and evidence linking source SHA→derivation→generation.
4. **Freeze production signing authority without installing secrets:**choose per catalog the SSH-Ed25519 principal+public SHA-256 fingerprint,root-owned `allowedSigners` path+file SHA-256,revocation path+file SHA-256,release identity,private-key custodian,rotation overlap,break-glass/recovery,and compromise procedure. Return public data+metadata only;never private key. Confirm fixture principal/fingerprint will not be reused.
5. **Freeze D2 GitHub target values without applying them:**return exact release workflow path/name/content commit/blob/check context;protected environment name+human reviewers+admin-bypass policy;distinct writer identity+minimal token permissions;ruleset name/target/bypass actors/review counts/CODEOWNERS/signature/FF/force/delete/admin rules;rollback order. Provider IDs remain future returned evidence after the separately gated operator action.
6. **Approve deployment identities or amend D0:**review proposed static UIDs/GIDs `1976..1980`,ports `9010..9013`+`9110..9113`,state roots,datasets,quotas,ACLs,backup reader,and limits. Return approval/replacements plus fresh collision evidence. Supply complete body-mode rows,or approve an explicit plan amendment moving body identity freeze to the pre-D9/D12 gate while preserving distinct roots/digests. No infra edit yet.
7. **Resolve empirical-proof phase ordering:**either return D0-native server RSS/FD/reload/drain measurements and approve every exact resource/time integer,or approve a written plan amendment that classifies current values as conservative D1 design ceilings and moves implementation-dependent measurement closure to D4 before D7. Do the same for production edge integration proof if it cannot exist before D7;the isolated transport primitive alone is insufficient.
8. **Storage+archive capacity:**return GitHub/provider repository/object/transfer ceilings;Rain dataset quota/reserve/free-space policy;append-only growth model+horizon;backup destination capacity/reader/retention;measured clone/fetch/checkout/backup/empty-root restore time;power-loss/rename/fsync result. If ordinary Git fails a reviewed ceiling,stop and request architecture review before D2.
9. **Rollback custody:**create or authorize immutable Rust+JS static source/workflow/artifact/proxy/download/infra/DNS/TLS bundles in operator-controlled storage;return bundle inventory SHA-256,storage owner,readback,isolated restore transcript,retention owner+horizon. For JS return strict default-origin publication+legacy-static profile proof or preserve classification=containment-only;`JS-INITIAL-ANCHOR` remains a later dynamic gate.
10. **Clock policy:**approve/revise max future skew,dual-clock tolerances,synchronization source/config,and horizons;return 24-hour Rain clock capture+forward/backward/lost-sync fault evidence or approve a phase amendment moving empirical capture to D4 before D7.
11. **Client coverage:**provide an independently pinned current Deno version when newer than the minimum is selected,or explicitly approve that current=minimum for this dated D0 while requiring an independent pin before D6;confirm scoped npm fixture timing.
12. **LAN deferral:**confirm `no LAN instance selected` for this rollout stage. This requests no LAN source/configuration/credential/DNS/TLS/deployment action and authorizes none.

Returned evidence:the metadata-only results for items 1–12,each keyed to this aggregate commit and UTC timestamp. Agent will verify them,commit supplements separately,and request a new independent review. Partial results leave the corresponding blocker open.

Observe:none requested for public traffic;monitoring redesign remains deferred and non-gating.

Rollback trigger:any unexpected operator-side service,DNS,GitHub,credential,or catalog mutation while answering D0.

Rollback:no public change is authorized;restore any accidentally changed setting through operator procedure and report before/after+audit evidence.

STOP:no dependent phase until evidence is reviewed. D1 authorized=false remains true after this aggregate commit;this file records a blocked gate,not permission to implement.
