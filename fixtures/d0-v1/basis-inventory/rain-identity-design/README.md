# D0 Rain identity/resource design:dynamic public compatibility services

Status:`proposal-only;incomplete-D0-input` | current-observed-deployment:`no` | D0-completion-claim:`no` | created:`2026-08-26T12:24:32Z` | deployment-ready:`no` | implementation/deployment/secret reads:`none`

## Scope+decision

Scope:future `pkgre-rust-serve`+`pkgre-js-serve` public redirect-compatibility units and two dormant isolated rollback anchors in Rain's existing `pkgre` nspawn container;body-mode+LAN identities excluded. Decision:static per-instance UID/GID;four unique host-local protocol ports+four container-loopback admin ports;one quota-backed ZFS dataset/state root per unit;read-only ACL backup identity;measured systemd caps;exact public Git origins+full refs+bootstrap proposals. Existing `9008/9009`,nginx public routing,Pages/legacy services remain untouched.

Machine authority:`design.json`;all `observedFacts`=read-only evidence;all identity/resource/config rows under `proposal`=`future proposal`,not current observed deployment. This bounded artifact does not claim D0 completion;all listed blockers remain hard gates.

## Basis

| basis | identity |
|---|---|
| plan | `plans/pkgre-dynamic-registry-rollout.md` §§5,11,18 |
| infra | `/home/dev0/repos/infra` `master@5f68539bd99c6952b6d73fe2596c27ad4a319f57`,clean |
| server source | `/home/dev0/repos/pkgre@1d44dfeaeafef2b1a5341c13bf73647dcbc925ec` |
| Rust catalog | `https://github.com/pkgre/rust.git` `refs/heads/main@f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`;fresh `ls-remote` confirmed |
| JS catalog | `https://github.com/pkgre/js.git` `refs/heads/main@f43bd58bd3d4e36f8b3f4df3c002735c977acd17`;fresh `ls-remote` confirmed |
| Rain evidence | `evidence/d0-rain-live-2026-08-26/` |

## Observed facts

- Container:`pkgre`;addresses:server/public-side=`10.22.2.5`,host-local guest=`10.131.7.4`,host-local host=`10.131.7.1`;`PrivateUsers=pick`;observed ordinary-root UID shift=`1164705792`.
- Current backends:`10.131.7.4:9008` legacy,`:9009` proxy;current firewall admits host-local source only;proposed design never reuses these ports.
- Existing units:`DynamicUser=yes`;no `StateDirectory`;`MemoryHigh/Max=infinity`;`TasksMax=308853`;`LimitNOFILE=524288`;observed RSS≈9008KiB legacy/6988KiB proxy.
- Container root:ephemeral idmapped ZFS snapshot;host `/var/lib` dataset=`zroot/root/varlib`,quota/refquota=`0`,available≈3.522TB in captured evidence.
- Existing nspawn `states` support:host `/var/lib/machine-states/<container>/<state>`→configurable guest path via `idmap`;current module only creates host directories `0755`,insufficient for this design.
- ID allocation:max defined static ID=`1975`;checked `1976..1980` absent. Port allocation=`9001..9009`;checked definitions+captured live listeners show `9010..9013`,`9110..9113` absent. Mandatory recheck before any future edit.
- Idmapped state-bind rule:guest UID/GID `z`↔host UID/GID `z`;do not add the `1164705792` ordinary-root shift to state-dataset ownership.

## Proposed exact identity+network matrix—not current deployment

| role | unit/user/group | UID:GID | protocol listener | admin listener | state root | quota | MemoryHigh/Max | Tasks/NOFILE |
|---|---|---:|---|---|---|---:|---|---|
| Rust compatibility | `pkgre-rust-serve-public.service` / `pkgre-rust-serve-public` | `1976:1976` | `10.131.7.4:9010` | `127.0.0.1:9110` | `/var/lib/pkgre-rust-serve-public` | 4GiB | 384/512MiB | 64/2048 |
| JS compatibility | `pkgre-js-serve-public.service` / `pkgre-js-serve-public` | `1977:1977` | `10.131.7.4:9011` | `127.0.0.1:9111` | `/var/lib/pkgre-js-serve-public` | 2GiB | 512/768MiB | 64/2048 |
| Rust rollback | `pkgre-rust-serve-public-rollback.service` / `pkgre-rust-serve-public-rollback` | `1978:1978` | `10.131.7.4:9012` | `127.0.0.1:9112` | `/var/lib/pkgre-rust-serve-public-rollback` | 4GiB | 384/512MiB | 64/2048 |
| JS rollback | `pkgre-js-serve-public-rollback.service` / `pkgre-js-serve-public-rollback` | `1979:1979` | `10.131.7.4:9013` | `127.0.0.1:9113` | `/var/lib/pkgre-js-serve-public-rollback` | 2GiB | 512/768MiB | 64/2048 |
| backup reader | `pkgre-state-backup` | `1980:1980` | none | none | ACL-only read/traverse | none | separately bounded backup unit | no service supplementary group |

Accounts:static system accounts;`DynamicUser=false`;no login/home;primary group only;no supplementary groups. Protocol admission:source=`10.131.7.1/32`,destination=`10.131.7.4`,ports=`9010..9013` only. Admin isolation:container loopback only;no nginx target;no firewall admission;never public. Server-side interface `10.22.2.5` and public network deny direct access to all proposed protocol/admin ports. Existing nginx/TLS/public routes remain unchanged at D7;host-local canaries may target protocol ports only.

## Proposed storage+permissions

Dataset per row:`zroot/root/varlib/machine-states/pkgre/<instance>`;host mount=`/var/lib/machine-states/pkgre/<instance>`;ZFS native `quota=`=row value;`mountpoint=legacy`;idmapped bind→guest state root. This avoids unproved systemd project-quota behavior on current ZFS and gives every instance a separate capacity/failure boundary.

State layout under each root:`mirror.git/`,`checkouts/<commit>/`,`generations/<commit>-<projection>.json`,`retired-generation-ids/<id>`,`instance`,`accepted`,`lock`,`staging/`;all transaction temporaries remain here. Same-filesystem proof:record matching `statfs`/device identities+successful staged temp→final atomic rename+parent fsync per dataset. Candidate preflight checks quota+free space;quota failure rejects candidate and never evicts active/required rollback.

| object | owner:group | mode/ACL |
|---|---|---|
| `/var/lib/machine-states/pkgre` | `root:root` | `0711` |
| instance dataset/root | instance UID:GID | `0700`;backup access ACL `u:pkgre-state-backup:r-X`;matching default ACL;no backup write |
| state dirs | instance | `0700` |
| state files/records/lock | instance | `0600` |
| `/etc/pkgre`,`/etc/pkgre/trust` | `root:root` | `0755` |
| instance config+ecosystem trust leaves | `root:<instance-group>` | `0640`;daemon read-only |

Sole writer=own daemon;readers=own daemon,root,ACL-only backup identity;cross-instance reads=`forbidden`. Root is administrative reader,not live writer. Lock=`<state>/lock`;all production/test/repair/reseed/GC commands enter through Nix-pinned `flock --exclusive --nonblock --no-fork` before any state read. Sandbox:`ProtectSystem=strict`;writable path=own state root only(+dedicated runtime dir only if implementation requires a socket);no shared writable tree. Backup consistency:exclusive-lock backup or separately reviewed atomic ZFS snapshot;backup account writes only to a separately reviewed destination.

Rollback anchors:independent users,datasets,configs+trust inputs;`updatePolicy=frozen-no-watcher`;bootstrap/freeze exact accepted compatibility generation at the reviewed rollback lease;never copy mutable live compatibility state. Body mode later requires new roots+complete identities and must never reinterpret these redirect roots.

## Resource evidence+proposal

Rust archive rehearsal committed authority:`download-summary.json.raw_unique_bytes=129,833,713B`,`git-metrics.json.raw_unique_bytes=129,833,713B`,`git-metrics.json.checkout_verified_bytes=129,833,713B`;747 unique archives;largest=`9,679,450B`;packed repo apparent=`129,497,688B`;checkout repo+tree apparent=`129,475,752+129,988,057=259,463,809B`,allocated=`129,560,576+131,497,984=261,058,560B`. Source SHA-256:`download-summary.json=53e1a700d3c7ca0d9314bf2364e0387477388c25a6bcce386af28c602a63c68c`,`git-metrics.json=a79b6d9f617e6a4b45727205b104f29b33c7bca009513f15c8f00e67f4804e00`. Rust render≈0.77s/15MiB RSS/2.13MB output;check≈0.12s. JS check≈45MiB Node baseline. Rehearsal proves one-host feasibility only;not production quota or dynamic two-snapshot peaks.

Exact D0 proposals:Rust quota=4GiB;JS quota=2GiB;Rust units `MemoryHigh=384MiB`,`MemoryMax=512MiB`;JS units `512MiB`,`768MiB`;all `TasksMax=64`,`LimitNOFILE=2048`;request concurrency=`256`;stream buffer=`65536B`;overload=`bounded 503+Retry-After`;max archive=`134217728B`;reload deadline=`120s`. Same caps apply to same-ecosystem rollback. D4 must measure live+candidate+old-in-flight+runtime/request buffers,FDs,reload and drain;exceeding or unproved cap blocks D7 rather than silently raising it.

## Proposed D7 config values

| key | Rust | JS | freeze status |
|---|---|---|---|
| canonical origin | `https://github.com/pkgre/rust.git` | `https://github.com/pkgre/js.git` | exact;refetch/review |
| transport/credential | anonymous HTTPS/`null` | anonymous HTTPS/`null` | exact;no public Git secret |
| full source ref | `refs/heads/main` | `refs/heads/main` | exact |
| refspec | `+refs/heads/main:refs/pkgre/remotes/main` | same | exact |
| remote-tracking ref | `refs/pkgre/remotes/main` | same | exact |
| bootstrap proposal | `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` | `f43bd58bd3d4e36f8b3f4df3c002735c977acd17` | current reviewed tips;D7 refetch required |
| Git object format | `sha1` | `sha1` | exact v1 |
| state contract | `state-contract-v1` | same | canonical plan exact |
| config schema/protocol contract | `null` | `null` | blocker:binary enums not frozen |
| ecosystem/audience/mode | `rust/public/public` | `js/public/public` | exact |
| delivery/marker | `redirect`/`null` | `redirect`/`null` | exact compatibility semantics |
| signing | Git SSH-Ed25519;root-owned ecosystem paths | same | blocker:principal/fingerprint/digests absent |
| compatibility watcher | 60s interval,≤15s jitter,30s timeout,30→900s backoff | same | proposed operational timing;not in instance digest |
| rollback watcher | disabled/frozen | disabled/frozen | exact design |
| concurrency/buffer/reload | 256/65536B/120s | same | proposed;D4 proof required |
| instance digest | `null` | `null` | blocker until all semantic/trust/maxima inputs frozen |

Config paths:`/etc/pkgre/<instance>.json`;trust paths:`/etc/pkgre/trust/<instance>/{allowed-signers,revocations}` (per-instance copies allow `root:<instance-group>` `0640` without supplementary groups);public credential paths=`null`. Dynamic compatibility watches exact full ref;rollback watcher disabled. Git disables tags,default refspecs,hooks,submodules/LFS/filters,ambient credentials,maintenance+GC and remote helpers per plan.

`design.json` lists every plan-required hard maximum not yet supported by evidence as `null` under `proposal.hardMaximaFreeze.fields`,not as an invented value. D7 cannot activate until D4 replaces every null with reviewed exact integers for fetch/pack/inflation/object/tree/file/checkout,count/response/header/request/snapshot/time/drain ceilings and tests rejection. `instance` digest is computed only after actual config schema/protocol enum,trust digests,all maxima and update policy are canonical.

## Future implementation sequence(no action authorized here)

1. Reserve `1976..1980` in `modules/definitions/ids.nix`;reserve `9010..9013`,`9110..9113` in `modules/definitions/ports.nix`;separate commits.
2. Extend `modules/virtualisation/nspawn/host.nix` or add reviewed host declarations for datasets,mounts,static owner/mode+ACL;do not rely on current `0755` state creation.
3. Operator creates/mounts four datasets and proves quota failure/recovery,idmap ownership,ACL,atomic rename/fsync and backup restore before services start.
4. Pin exact reviewed new `pkgre` input in `flake.nix`;add static accounts,root-owned configs/trust,firewall+four units in `hosts/rain/containers/pkgre.nix`;preserve `9008/9009`,legacy,Pages,all public routes.
5. Build/eval full Rain+container;inspect generated users/groups,nspawn binds,mounts,units,sandbox,ports,firewall,nginx,quotas,limits+closure;rerun collision validator.
6. Operator activates only after all blockers close and returns D7 evidence;no agent deployment,DNS/GitHub setting or secret action.

## Blockers

- `TRUST`:exact ecosystem SSH-Ed25519 principal,key SHA-256 fingerprint,allowed-signers digest,revocation digest+isolated version-pinned Git verification proof.
- `CONFIG-SCHEMA`:actual schema version,protocol/header enum,canonical config grammar+unknown-key rejection;then instance digests.
- `MAXIMA`:all `null` limits+dynamic two-snapshot/old-stream RSS,FD,reload/drain evidence;confirm caps.
- `STORAGE`:operator-reviewed ZFS create/mount/quota/ACL/idmap/same-filesystem+backup/restore proof;current module is insufficient.
- `COLLISION-RECHECK`:fresh full Rain evaluation+live IDs/listeners/paths immediately before implementation.
- `BOOTSTRAP-REFETCH`:review current tips at D7;freeze rollback generation at lease creation.
- `NGINX-WIRE`:exact vhost/SNI/authority/Host rewrite,raw-wire canary+external denial before any frontend change.
- `ROLLBACK-BUNDLE`:independent legacy bundle/readback/restore rehearsal required by plan §18.

LAN status:instance/config/credential=`absent`;D13 must supply complete isolated identity/network/storage/trust/credential rows before any LAN edit.

## Validation

Run:`python3 -m json.tool evidence/d0-rain-identity-design/design.json >/dev/null`;custom validator checks 4 unique unit/user/UID/GID/protocol/admin/state/dataset/config rows,disjoint protocol/admin sets,loopback-only admin,static IDs,backup read-only ACL and expected tips. Result:`PASS`;details+UTC stamp in `design.json.validation`;`SHA256SUMS` covers final `README.md`+`design.json` and verifies with `sha256sum -c SHA256SUMS`.

## Harness issues

- One read-only `exec_command` was rejected because workdir `/home/dev0` itself is outside authorized roots;rerun from authorized root succeeded.
- One accidental broad grep emitted 181779B truncated output;process exited successfully;no edits.
