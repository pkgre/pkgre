# D0 Git/storage/deployment/legacy blocking inventory

Status:**BLOCKED**;agent-local read-only inventory complete enough to identify blocking facts;not a complete D0 gate;no project repository,provider,DNS,Pages,deployment,credential,or host state modified;no secret/private-key value read.

## Scope+basis

Artifact root:`/home/dev0/.talent/agents/01a0368b-4cd1-7930-b789-daf0a9a11164/workspace/d0-git-storage-inventory/` | local inventory:`2026-08-26T12:13:42Z–12:13:46Z` | GitHub governance:`2026-08-26T12:19:56Z` | fresh strict read-only Rain SSH:`2026-08-26T12:33:35Z` | public wire:`2026-08-26T11:55:44Z–11:58:29Z`.

Bases:`pkgre main=1d44dfeaeafef2b1a5341c13bf73647dcbc925ec` on reviewed `066293df21743cbf41fb571a38f2bb94059e7274`;`pkgre-rust main=f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`;`pkgre-js main=f43bd58bd3d4e36f8b3f4df3c002735c977acd17`;`infra master=5f68539bd99c6952b6d73fe2596c27ad4a319f57`;all clean;`pkgre` ahead cached upstream `1/0`,others `0/0`;no fetch performed.

Safety:Git commands scrubbed object/config/namespace overrides,set `GIT_OPTIONAL_LOCKS=0`;network Git probes were exact-ref anonymous HTTPS reads with redirects disabled;filesystem writes confined to artifact root;Rain used `BatchMode=yes`,`StrictHostKeyChecking=yes`,explicit TOFU fixture;remote commands were read-only metadata/status/hash operations;Gandi token/private-key contents were never read or hashed.

## Git/tree/storage results

| Repo | Tree entries;unique blobs/bytes | Reachable objects/decompressed bytes | All local objects;object-store file bytes;dangling | Worktrees | Max path/component bytes | Canonical tree SHA-256 |
|---|---:|---:|---:|---:|---:|---|
| `pkgre` | 139;116/2,198,793 | 572/5,933,962 | 1,213;1,158,179;109 | 6 | 58/31 | `a300d0d16f80e69616cd5f6f2cb1c6346e8e528861252df722e9cfb3a709f487` |
| `pkgre-rust` | 773;763/1,958,607 | 905/4,268,529 | 1,021;1,949,410;97 | 1 | 94/70 | `ebb632e21d7553d46da4b3db0c4dac5be1cdd6ec2b51a1c21a3c59e511492355` |
| `pkgre-js` | 67;22/57,651 | 76/79,350 | 126;65,358;47 | 1 | 109/68 | `437e0a2c702e933d82fbbfad1cc89d68d17266e2cf56bedcb9a479c3ce425fdd` |
| `infra` | 348;275/769,434 | 16,091/17,819,872 | 16,173;2,830,995;75 | 1 | 64/41 | `236b4017dfdf691e31eba76041a6ad491ceca512145b350f9ab4ab864c424499` |

PASS:Git `2.54.0`;all storage/input/output object formats=`sha1`,40-hex;strict `fsck --full --strict`+HEAD connectivity exit `0`;complete/non-shallow;no missing objects,alternates,grafts,promisor/partial clone,replace refs,namespaces,gitlinks,submodule definitions,LFS pointers/filters,active hooks,tree symlinks,or special tree modes;all current paths pass proposed NFC UTF-8 bytewise grammar+NFC/NFD/case-fold collision checks. Dangling objects are fsck notices,not connectivity failures. `infra` tracks an empty `.gitmodules` blob only.

FAIL production layout:all are non-bare development worktrees;`pkgre` has five extra detached `/tmp` worktrees;all origin fetch refspecs are broad `+refs/heads/*:refs/remotes/origin/*`;origins are SSH development URLs;runtime exact-ref/redirect-safe configs absent;roots/gitdirs/objects/refs are development-owned `uid=1000,gid=100,0755`,broadly readable. Public read probes proved `rust.git refs/heads/main→f9b5…6518b` and `js.git refs/heads/main→f43b…cd17`,HTTP/2 `200`,no redirect,TLS verified;canonical runtime origin bytes remain operator-frozen inputs.

Local filesystem:`zfs` `/home`,options `rw,relatime,idmapped,xattr,posixacl,casesensitive`,NAME_MAX=`255`,PATH_MAX=`4096`;safe artifact-only probe proved distinct case+NFC/NFD names,invalid-UTF-8 byte roundtrip,and same-directory rename+file/dir fsync. This is development behavior only;it does not prove Rain quota/power-loss durability.

## Rain live deployment

Fresh strict SSH facts:host system=`/nix/store/bhfadnwczhfsd6zadxhl04jqfp1spp9v-nixos-system-rain-26.11.20260818.9588f1a`;container system=`/nix/store/jai70s8kdn3jc71qvsn9l20zma9aam4g-nixos-system-pkgre-26.11.20260818.9588f1a`;nixpkgs=`9588f1a6c197ae61c6222a3baa6ac220ec1cc4d9`;nginx/container/both legacy units active.

nginx=`1.30.4` `/nix/store/qzihfqlvbzx0zhjvmx6zimxdz9ghvwm0-nginx-1.30.4/bin/nginx`;config=`/nix/store/nnqs127xdnxi93772sgmgfy7a890alxb-nginx.conf`;SHA-256=`eeb69be6aebb5e69fdbc12c9019e648f64308b1738c153715411db607d701d51`;public listeners=`65.21.163.108:80,443`;host-local peer=`10.131.7.1`;container=`10.22.2.5`,`10.131.7.4`;firewall admits only host-local peer→TCP `{9008,9009}`.

| Unit | Binary | Listener | Identity/state | Current fact |
|---|---|---|---|---|
| `pkgre-download-serve` | `…/wjrv…-pkgre-download-serve-0.1.0/bin/pkgre-download-serve` | `10.131.7.4:9008` | DynamicUser;observed container `64206:64206`;no StateDirectory | catalog commit=`f9b5…6518b`;manifest=`9c0cb103f61caeb95a52f76fc3cd479d94c261aef86a7b5d96711e902e26fe94`;routes=`747`=`744` crates.io+`3` Git-tag |
| `pkgre-proxy` | `…/1a25…-pkgre-proxy-0.2.0/bin/pkgre-proxy` | `10.131.7.4:9009` | DynamicUser;observed container `61225:61225`;no StateDirectory | Rust canary passed;JS canary failed connection/ServiceUnavailable |

Absent,not placeholders:dynamic Rust/JS/rollback units;static service users/groups+stable nspawn UID/GID mapping;state roots,bare mirrors,checkouts,generations,retired IDs,staging,locks,accepted refs,active manifests;allowedSigners/revocation/runtime-Git config+credential paths;pkg.re ZFS dataset/quota/reservation;backup reader;same-filesystem crash/power-loss proof;MemoryHigh/MemoryMax/FD/fetch/state ceilings;selected LAN instance/config/credential.

## Critical credential finding

**FAIL/critical:**`/var/lib/keys/pkgre-js-gandiv5-token` exists as regular file `0644 root:root`,UID/GID `0:0`,41 bytes,ACL=`user::rw-,group::r--,other::r--`;source uses it as shared Gandi DNS-01 PAT input for Rust+JS ACME. Secret value was never read. This is world-readable secret-bearing metadata+shared blast radius;operator must treat as exposed,restrict via operator-managed deployment,rotate/revoke,verify scope/audit access,and return metadata/scope/rotation evidence without token value.

Certificate directories=`0750 acme:nginx 993:60`;public fullchains=`0640`;private keys=`0640 acme:nginx`,227-byte metadata only. Fullchain SHA-256:`rust=f16dbbf491092749712e1382463012196b9502311859c9dfa5645ba00ad0f3e3`,`js=649746880014a9164bde3144244718b14c883e310478e3ad5fdf93e7670c5b13`,`dl=049ce655d412f206bcf5b570b7570dbec04c22ec960b0287249928bc373fcd17`. Public leaf DER SHA-256/validity:`rust=7e4459…f85,2026-08-22..11-20`;`js=7a1a0a…09b6,2026-08-25..11-23`;`dl=714e12…05d8,2026-08-24..11-22`.

SSH host=`rain.pacna.org`,Ed25519 fingerprint=`SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI`;strictly matched existing TOFU fixture;operator out-of-band host-key attestation remains absent.

## Public topology+Pages/legacy limits

| Host | DNS/public state | Rain route | Continuity/rollback classification |
|---|---|---|---|
| `rust.pkg.re` | `CNAME pkgre.github.io.`;Pages config/sparse `200`;TLS valid | dormant Rain vhost;`/v1/→9009`,other→strict Pages | Current continuity works,but rollback bundle incomplete |
| `js.pkg.re` | `CNAME rain.pacna.org.`;strict `502`;TLS valid | `/v1/js/→9009`,other→strict Pages custom origin | **Containment-only;never continuity anchor** |
| `dl.rust.pkg.re` | `CNAME rain.pacna.org.`;known route `307`,zero body | `/→9008` | Legacy compatibility active;retire only after D10/D14 horizon |

GitHub Pages observed:Rust workflow source=`main:/`,CNAME=`rust.pkg.re`,HTTPS enforced,certificate approved,deployment=`6092749507`,artifact=`9583758375`,digest=`sha256:2510e9d77f459d066261a88efe9005d5358c8a9a401aba7042d45fe6f1c2448c`,551,735 bytes,expires `2026-08-26T21:48:27Z`;JS workflow source=`main:/`,CNAME=`js.pkg.re`,HTTPS not enforced,certificate absent,deployment=`6094120375`,artifact=`9586702051`,digest=`sha256:ba7bb13b843d585898552ecd68d2e9caee55ee27644f3721b48b63d29a5e32c5`,791 bytes,expires `2026-08-26T23:37:29Z`.

Rollback limits:provider artifacts expire within one day;build listing empty/latest build 404 despite successful workflow deployment;mutable default refs+artifacts are not mirrored/readback-tested in operator-controlled storage;no isolated restore rehearsal or retention owner/horizon;JS needs hash-pinned default-origin publication+legacy-static Rain profile+`JS-INITIAL-ANCHOR`;DNS,custom-domain,deployment,credential,and retirement actions remain operator-only.

Current edge is not target-safe:missing strict SNI/Host/`:authority` agreement;no ingress raw-target+independent request-form verdict→backend-byte proof;legacy externally accepts/normalizes some absolute forms,duplicate slash,dot segments,query,and duplicate Host;fixed `405/413/414/431`,body/framing/header ownership,compression/range behavior,and resource ceilings remain unproved.

## Gate+operator blockers

PASS scope:exact local bases;Git object/tree/path/connectivity inventory;development filesystem behavior;public Rust/JS exact-ref HTTPS observations;live Rain generation/config/listeners/unit/certificate+credential metadata;current Pages/deployment/artifact metadata;no mutations/secrets read.

BLOCK D1:1)contain+rotate world-readable Gandi PAT;2)out-of-band attest Rain host key;3)freeze/deploy bare exact-ref mirrors,static users,stable UID/GID,state/ACL/quota/backup/locks/crash semantics;4)freeze SSH-Ed25519 principal+fingerprint/allowedSigners/revocation/runtime credential authority;5)operator apply+return GitHub rulesets/checks/release environment/reviewers/writer/token/audit evidence;6)build immutable Rust+JS rollback bundles+readback+isolated restore,including strict JS initial anchor;7)prove raw H1/H2 ingress→backend bytes+authority matching+fixed limits/errors;8)complete archive-in-Git import/pack/fetch/quota rehearsal;9)perform fresh D0 refetch immediately before first edit.

## Artifacts+reproduction

Machine fixtures:`repositories.json`(full path/object/ref/config/owner/mode data),`filesystem.json`,`source-network.json`,`run-metadata.json`,`deployment-legacy.json`,`validation.json`;script=`inventory.py`;integrity=`SHA256SUMS`. Reproduce local inventory in a fresh directory containing only `inventory.py`:`./inventory.py --output .`;the script intentionally refuses overwrite. Validate:`for f in *.json;do python3 -m json.tool "$f" >/dev/null;done;sha256sum -c SHA256SUMS`.

Rain strict-read command policy:`ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=../evidence/rain-d0-known-hosts root@rain.pacna.org '<bounded status/stat/readlink/sha256sum of public config/fullchain only>'`;never cat/hash credential or private-key files. Exact historical live/public/GitHub evidence paths+hashes are enumerated in `deployment-legacy.json`.

Harness issues:default SSH known_hosts lacked `rain.pacna.org`,so first strict attempt failed safely;existing explicit TOFU fixture then worked with no trust-store mutation. One read-only remote public-certificate command stopped because `openssl` is absent on Rain;no change resulted;prior public-wire certificate evidence+safe fullchain hashes were used.
