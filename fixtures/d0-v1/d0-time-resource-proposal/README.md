# D0 time/lifecycle/resource-limit proposal

Status:`proposal-not-approved-not-deployment-authority` | machine authority:`proposal.json` | scope:public Rust+JS compatibility/body/rollback envelopes;distinct instance digests+state roots required | mutations:none

## Decision boundary

Purpose:freeze concrete candidate integers for review+production-equivalent proof;not claim D0 complete,not authorize D1/implementation/deployment. Classification is explicit:measured facts=`M`;conservative formula=`F`;operator-policy choice=`P`;hard missing evidence=`B`. Any over-limit candidate rejects before `accepted`,preserves LKG,and suppresses same-hash retry until hash change/operator retry.

## M — measured facts

| ecosystem | catalog/tree | graph/routes | renderer/check | responses | archives/storage |
|---|---|---|---|---|---|
| Rust@`f9b5ff` | 1 registry;9 categories;911 names;773 tree entries;1,958,607B tree;320,545B largest source file | 747 versions;5,518 dependency edges;555 sparse rows;2,062 public inventory rows/2,055 target descriptors | check=0.0255s/11,592KiB;render=1.4841s/11,560KiB;563 files/2,129,784B | max inline=459,017B;max sparse row=107,745B | complete scratch closure=747/129,833,713B;max=9,679,450B;packed repo≈129.50MB;repo+checkout peak=261,058,560B allocated;fetch=0.522s;checkout=0.152s;download=19.13s@8 |
| JS@`f43bd58` | 1 registry;0 categories;1,650B catalog;67 tree entries;93,998B tree | 1 package;1 version;0 edges;10 public inventory rows/3 target descriptors | routes=0.0951s/43,856KiB;final=0.0891s/45,160KiB;8 files/19,785B | max inline+packument=996B | 1 archive/16,717B;tar inflated=77,824B;checkout apparent=200,483B |

M caveats:single warm-cache/local samples;Rust archive closure was imported into synthetic tmpfs Git,not the current catalog tree or production ZFS/network;no dynamic manifest/current `snapshotBytes`;no live+candidate+old-stream RSS/FD/drain measurement;current archive-in-Git history growth+backup/restore/provider ceiling unmeasured.

## F — conservative formulas

- `singleSnapshotResident=2MiB+2*snapshotBytes+256*routes+128*versions+96*edges+256*packages+96*archives`;archive payload bytes excluded→file-backed+bounded stream only.
- `candidatePeak=3*singleSnapshotResident+runtimeReserve+loaderWorkerResidentEnvelope+256*32KiB+64*64KiB`;3 snapshots=`live+candidate+old leased`;admit only when `candidatePeak<=MemoryMax-64MiB`.
- Rust maxima→single snapshot estimate=`61,210,624B`;candidate peak=`397,541,376B`;admission ceiling=`469,762,048B`.
- JS maxima→single snapshot estimate=`119,537,664B`;candidate peak=`861,929,472B`;admission ceiling=`1,006,632,960B`;exactly one Node Worker:resident envelope=`390,070,272B`=`192MiB old+32MiB young+16MiB near-limit allowance+4MiB stack+128MiB nonheap reserve`;32MiB code range is virtual-address reservation,excluded from RSS arithmetic;resource limits cover only the JS engine,so the nonheap reserve remains mandatory. Snapshot≤32MiB uses an exclusively owned `ArrayBuffer` listed in `transferList`;clone and `SharedArrayBuffer` paths forbidden.
- FD budget=`64 fixed+256 sockets+64 archive FDs+128 Git/loader+16 admin+512 reserve=1,040<2,048`;tasks=`16 runtime+1 watcher+8 loader/Git+4 worker+35 reserve=64`.
- ZFS Rust=`512MiB mirror+5*512MiB checkout slots(active,rollback,old lease,candidate,staging)+128MiB audit+896MiB reserve=4GiB`;JS=`256MiB mirror+5*256MiB slots+64MiB audit+448MiB reserve=2GiB`;preflight requires `used+2*maxCheckout<=85% quota` and equal filesystem free bytes.

## P — exact policy

### Time+watcher+reload

| key | exact value |
|---|---:|
| `maxFutureSkew` | 300s |
| trusted-sync qualification before acceptance | 600s;kernel synchronized;reported offset≤1s |
| realtime↔monotonic deviation | ≤2s |
| permitted realtime backward movement | ≤5s;larger→`TIME_CLOCK_UNTRUSTED`,LKG stays ready |
| poll | 60s±15s deterministic per-instance jitter |
| Git connect/fetch wall/CPU | 10s/30s/20s |
| retry | 30s exponential×2,cap=900s,jitter=±20% |
| materialize/strict-Git/archive+snapshot/durable commit phase caps | 45s/30s/90s/10s;all post-fetch phases share 120s deadline |
| reload wall | 120s |

Clock rule:sample candidate start+pre-linearization;`deltaRealtime>=-5s && abs(deltaRealtime-deltaMonotonic)<=2s`;post-boot acceptance waits 600s trusted sync;startup never reevaluates accepted generation against current clock.

### Lifecycle+HTTP

| key | exact value |
|---|---:|
| SIGTERM HTTP drain / systemd stop / SIGKILL margin | 30s/35s/5s |
| request header / idle / total lease | 10s/15s/120s |
| archive stream / old-generation lease | 120s/120s;shutdown override=30s |
| target / header count / total headers / field | 4,096B/64/32,768B/8,192B |
| request body | 0B;nonzero or framed→413 |
| request/archive-stream concurrency | 256/64 |
| request/stream buffer | 32,768B/65,536B |
| conditional tags/header | 16/4,096B |
| saturation | fixed 503,`Retry-After: 1`,0B body |
| over target/headers | 414/431 |

Lease expiry:canceled connection+closed immutable FD+released snapshot/checkout;online unlink forbidden;GC remains offline/quiesced+reference-aware. Restart overlap prevented by lifetime exclusive state lock.

### Admission maxima

| limit | Rust | JS |
|---|---:|---:|
| fetch network/pack | 512MiB/512MiB | 256MiB/256MiB |
| inflated Git objects/tree logical | 1GiB/512MiB | 512MiB/256MiB |
| tree entries/directories/depth | 16,384/4,096/16 | 16,384/4,096/16 |
| regular/nonarchive file | 128MiB/16MiB | 128MiB/16MiB |
| checkout allocated | 512MiB | 256MiB |
| catalog/registries/categories | 32MiB/8/128 | 64MiB/8/128 |
| packages/versions/edges | 8,192/16,384/131,072 | 4,096/32,768/262,144 |
| routes | 32,768 | 65,536 |
| inline/packument/sparse row | 1MiB/0/512KiB | 4MiB/4MiB/0 |
| archive each/count/total | 128MiB/4,096/384MiB | 128MiB/32,768/192MiB |
| `snapshotBytes` | 16MiB | 32MiB |
| state/ZFS `quota` | 4GiB | 2GiB |
| `MemoryHigh`/`MemoryMax` | 384MiB/512MiB | 768MiB/1GiB |
| `TasksMax`/`LimitNOFILE` | 64/2,048 | 64/2,048 |

Rust material headroom:archive total=3.10×;max inline=2.28×;sparse row=4.87×;archives=5.48×;versions=21.93×;edges=23.75×;rehearsed repo+checkout peak→quota=16.45×. JS bootstrap ratios are intentionally large initial room,not empirical growth support.

### Observation horizons

| gate | minimum |
|---|---:|
| clock sync+dual-clock qualification | 24h |
| resource stress | 100 reload cycles+6h/instance |
| pre-cutover canary | 72h |
| each archive body cutover | 7d |
| public sustained operations | 14d |
| legacy retirement after last successful rollback rehearsal | 30d |

Qualification:no unexplained restart/OOM/quota failure/state mismatch;bounded rejects;RSS p99<75% `MemoryHigh`;state<70% quota;archive/route completeness=100%;controlled-probe unexpected HTTP 5xx=0. Operator timestamps each horizon only after prerequisites+rollback rehearsal pass.

## B — hard blockers before freeze/activation

1. `DYNAMIC-MEASUREMENTS`:native Rust+JS live/candidate/old-stream RSS,FD,100-cycle reload,shutdown/drain/lease-expiry proof absent;JS proof must measure one Worker including heap,near-limit,stack,native/external memory and owned-`ArrayBuffer` transfer with clone/`SharedArrayBuffer` forbidden.
2. `PROJECTION-BASELINE`:canonical manifest not implemented;current `snapshotBytes` unknown;prove≤16MiB Rust/32MiB JS.
3. `HTTP-LIMIT-PROOF`:production-equivalent raw edge/backend 413/414/431/body-framing/256+64 overload evidence absent.
4. `ARCHIVE-HISTORY-CAPACITY`:append-only history growth,provider ceiling,production ZFS create/fill/failure/recovery,backup+restore timing absent;successful current-closure rehearsal is insufficient.
5. `BODY-CLOSURE-IN-SOURCE`:forward catalogs containing every retained body absent;body mode unauthorized.
6. `CLOCK-PROOF`:24h live sync capture+clock fault fixtures absent.
7. `RESTORE-HORIZON`:empty-root,remote-offline exact projection restore absent.

## Operator decisions

Required before config/instance digest:approve integers independently;pin actual Rain clock source/config;affirm compatibility/body roots stay distinct;record horizon starts only after objective criteria. A failed proof lowers workload/maxima or raises limits through explicit rereview;never silently changes an instance-bound limit.

## Validation

Run:`python3 validate.py`;expected:JSON parse+schema/status/unit checks;formula arithmetic;limits>baselines;Memory/FD/task/quota invariants;Markdown exact-value tokens;read-only source status fingerprints;output containment. Detailed result:`validation.json`.

## Sources

Canonical:`plans/pkgre-dynamic-registry-rollout.md` §§5,11,24 | measurements:`d0-pkgre-066293df/REPORT.md`,`d0-route-inventory/`,`d0-git-storage-inventory/`,`d0-js-child-report.md`,`~/repos/pkgre/fixtures/d0-v1/archive-git-rehearsal/` | prior resource identity proposal:`evidence/d0-rain-identity-design/` | HTTP limitation:`evidence/d0-public-http-edge-2026-08-26/REPORT.md` | Node Worker semantics:`https://nodejs.org/docs/latest-v24.x/api/worker_threads.html#new-workerfilename-options`,`#portpostmessagevalue-transferlist`;near-limit allowance:`https://github.com/nodejs/node/blob/v24.19.0/src/node_worker.cc`

## Harness issues

No material Talent harness issue in this task;one inherited broad grep/large extraction was noisy/truncated but did not affect values or write outside the proposal directory.
