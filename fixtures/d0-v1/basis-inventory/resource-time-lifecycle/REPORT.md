# D0 resource/time/lifecycle evidence

Status:`proposal-not-approved-not-deployment-authority` | scope:public Rust+JS compatibility/body/rollback instance envelopes | LAN:`no instance selected` | source-repository mutation:`none`

Classification:`OBSERVED`=captured bounded measurement/inventory;`PROPOSED`=exact review candidate,not production fact;`UNRESOLVED`=operator/implementation/proof input still missing. Dynamic state enum=`state-contract-v1`;`redirectMarkerSchema=null`. This bundle does not close D0,authorize D1,freeze an instance digest,or authorize implementation/deployment.

## Evidence basis

- Plan:`plans/pkgre-dynamic-registry-rollout.md` §§5,7,11,15,26.
- Reused proposal:`d0-time-resource-proposal/{README.md,proposal.json,validate.py,validation.json}`;no expensive rerun.
- Rust inventory+renderer:`d0-pkgre-066293df/REPORT.md`;basis commit=`f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`.
- JS inventory+renderer:`d0-js-child-report.md`;basis commit=`f43bd58bd3d4e36f8b3f4df3c002735c977acd17`.
- Git/filesystem:`d0-git-storage-inventory/{REPORT.md,filesystem.json,repositories.json,validation.json}`.
- Archive rehearsal:`~/repos/pkgre/fixtures/d0-v1/archive-git-rehearsal/{README.md,download-summary.json,git-metrics.json,checkout-timing.json}`.
- Timestamp implementation evidence:`d0-pkgre-066293df/source/rust/src/update/{time.rs,apply.rs,admission.rs}`,`d0-pkgre-066293df/source/js/src/catalog.js`,current Rust admission lock+JS bootstrap catalog.
- Rain baseline/proposal:`evidence/d0-rain-live-2026-08-26/`,`evidence/d0-rain-identity-design/{README.md,design.json}`.

## OBSERVED — bounded current facts

### Catalog/Git/route/response/render inventory

| item | Rust | JS |
|---|---:|---:|
| registries/categories/packages/versions/edges | 1/9/911/747/5,518 | 1/0/1/1/0 |
| catalog bytes | 1,705,601 excluding crate objects | 1,650 |
| Git tree entries/logical bytes | 773/1,958,607 | 67/93,998 |
| largest current source file | 320,545B | 16,717B |
| route inventory observed/target descriptors | 2,062/2,055 | 10/3 |
| largest inline response | 459,017B | 996B |
| largest sparse row/packument | 107,745B/none | none/996B |
| offline output files/bytes | 563/2,129,784 | 8/19,785 |
| warm-cache offline phase elapsed/peak RSS | check=0.0255s/11,592KiB;render=1.4841s/11,560KiB | routes=0.0951s/43,856KiB;final=0.0891s/45,160KiB |

Interpretation:renderer/check RSS+elapsed are offline one-shot samples,not native-server steady RSS,reload duration,or live+candidate/old-snapshot peaks. Route observed rows include negative/control probes;target descriptors are the intended dynamic body/redirect count.

### Authoritative Rust archive-in-Git rehearsal

| measure | exact observation |
|---|---:|
| unique archives verified | 747/747 |
| raw unique archive bytes=logical route bytes=verified checkout bytes | 129,833,713B |
| largest archive | 9,679,450B |
| packed repository apparent bytes | 129,497,688B |
| bare clone apparent bytes | 129,367,206B |
| repository+checkout peak apparent/allocated | 259,463,809B/261,058,560B |
| download | 19.133080821s@concurrency 8 |
| bare clone/fixed-ref fetch/explicit checkout | 0.516673151s/0.522072294s/0.151895077s |

Scope limitation:scratch tmpfs+synthetic ordinary-Git current-closure rehearsal;proves neither append-only retained-history capacity nor provider/Rain/ZFS quota,production transport,failure recovery,backup,or restore. The stale `1.6GB` claim is rejected and not used anywhere in this bundle.

JS archive observation:1 archive=16,717B;inflated tar=77,824B;checkout apparent=200,483B.

### Existing deployed-service baseline and dynamic measurement gap

Current deployed legacy/proxy observations are not dynamic-server limits:legacy RSS≈9,008KiB;proxy RSS≈6,988KiB;`MemoryHigh=infinity`;`MemoryMax=infinity`;`TasksMax=308853`;`LimitNOFILE=524288`.

| required native-server measure | state |
|---|---|
| steady RSS, Rust+JS | `UNRESOLVED`;not measured |
| live+candidate two-snapshot peak RSS | `UNRESOLVED`;not measured |
| live+candidate+old-leased three-snapshot/stream peak RSS | `UNRESOLVED`;not measured |
| peak open FDs+tasks under request/archive/fetch/reload overlap | `UNRESOLVED`;not measured |
| reload duration distribution+100-cycle result | `UNRESOLVED`;not measured |
| SIGTERM drain,SIGKILL recovery,120s lease expiry | `UNRESOLVED`;not measured |

## PROPOSED — exact production envelope for review

All integer maxima are inclusive;`limit+1` rejects before durable `accepted` mutation. Bytes=exact integer bytes;seconds=wall seconds unless explicitly CPU;RSS samples=KiB only in observed facts;systemd values=bytes.

### Git/catalog/archive/response/state ceilings

| ceiling | Rust | JS |
|---|---:|---:|
| Git fetch network/pack bytes | 536,870,912/536,870,912 | 268,435,456/268,435,456 |
| inflated Git-object bytes/Git objects | 1,073,741,824/65,536 | 536,870,912/65,536 |
| tree logical bytes/entries/directories/depth | 536,870,912/16,384/4,096/16 | 268,435,456/16,384/4,096/16 |
| path component/raw path bytes | 255/4,095 | 255/4,095 |
| regular/nonarchive file bytes | 134,217,728/16,777,216 | 134,217,728/16,777,216 |
| materialized checkout allocated bytes | 536,870,912 | 268,435,456 |
| catalog bytes/registries/categories | 33,554,432/8/128 | 67,108,864/8/128 |
| packages/versions/dependency edges | 8,192/16,384/131,072 | 4,096/32,768/262,144 |
| routes | 32,768 | 65,536 |
| inline/packument/sparse-row bytes | 1,048,576/0/524,288 | 4,194,304/4,194,304/0 |
| archive each/count/total bytes | 134,217,728/4,096/402,653,184 | 134,217,728/32,768/201,326,592 |
| canonical snapshot bytes | 16,777,216 | 33,554,432 |
| instance state bytes=ZFS quota | 4,294,967,296 | 2,147,483,648 |

Archive total excludes history-growth authority:these are candidate maxima,not evidence that the proposed quota fits retained append-only production history.

### Memory, FD,tasks,concurrency,HTTP

| item | Rust | JS |
|---|---:|---:|
| one-snapshot conservative resident estimate at maxima | 61,210,624B | 119,537,664B |
| three-snapshot candidate peak estimate at maxima | 397,541,376B | 606,076,928B |
| admission ceiling=`MemoryMax-67,108,864B` | 469,762,048B | 738,197,504B |
| `MemoryHigh`/`MemoryMax` | 402,653,184B/536,870,912B | 536,870,912B/805,306,368B |
| `TasksMax`/`LimitNOFILE` | 64/2,048 | 64/2,048 |
| ZFS quota | 4,294,967,296B | 2,147,483,648B |

Formula:`singleSnapshot=2,097,152+2*snapshotBytes+256*routes+128*versions+96*edges+256*packages+96*archives`;archive payload excluded/file-backed. Formula:`candidatePeak=3*singleSnapshot+runtimeReserve+loaderWorkerReserve+256*32,768+64*65,536`;three snapshots=`live+candidate+old leased`. JS loader worker proposal:`192MiB old+32MiB young+32MiB code`;transferable snapshot≤33,554,432B. `MemoryHigh`=alert+candidate throttle,not kill/admission threshold;any `MemoryMax` OOM fails qualification.

FD estimate:`64 fixed/listeners/logs+256 request sockets+64 archive FDs+128 Git/loader+16 admin/status+512 reserve=1,040<2,048`;task estimate=`16 runtime+1 watcher+8 loader/Git+4 JS-worker allowance+35 reserve=64`. These are formulas,not measurements.

Shared HTTP proposal:raw target≤4,096B;headers≤64 fields/32,768B total/8,192B each;conditional tags≤16+header≤4,096B;request body=0B;request buffer=32,768B;stream buffer=65,536B;requests≤256;archive streams≤64. Nonzero/framed body→`413`;target excess→`414`;header excess→`431`;saturation→fixed `503`,`Retry-After: 1`,0B body;header timeout=10s→`408`;idle timeout=15s;total request lease=120s.

State preflight:`usedBytes+2*maxCheckoutAllocatedBytes<=floor(85%*quota)` and filesystem free bytes≥that same sum;failure=`STATE_SPACE`,no eviction. Exact floor:Rust=3,650,722,201B;JS=1,825,361,100B.

### Timestamp sources,spellings,order,clock

OBSERVED Rust current lock:`admitted-at="2026-08-24T02:39:41Z"`,`evaluated-at="2026-08-24T02:39:41Z"`;package rows retain upstream `pubtime`;admission evaluation uses `SystemTime` truncated to whole seconds. Rust parser spelling=`YYYY-MM-DDTHH:MM:SSZ`,exactly 20 ASCII bytes,UTC whole-second,year 1970..9999,real civil instant;reject lowercase `t/z`,offsets,fractions including `.000Z`,leap second,invalid dates,pre-epoch.

OBSERVED JS current catalog:`evaluationTime="2026-08-25T23:27:24.000Z"`;`publishedAt`/`fetchedAt`/`admittedAt` use exact millisecond-zero UTC. Third-party order=`publishedAt<=fetchedAt<=admittedAt<=evaluationTime`;first-party order=`publishedAt<=admittedAt<=evaluationTime`. Proposed JS migration retains exact `.000Z` spelling;nonzero fractions invalid. Ecosystem/schema binding is mandatory;Rust and JS spellings are never interchangeable.

PROPOSED source rule:typed catalog evidence only;startup/reload/filesystem/Git time never enters response bytes. Candidate samples realtime+monotonic at candidate start and immediately pre-linearization. `evaluationTime<=observedNow+300s`;trusted sync required for 600s before post-boot acceptance;kernel synchronized=true;reported offset≤1s. Within boot:`deltaRealtime>=-5s && abs(deltaRealtime-deltaMonotonic)<=2s`;violation,backward movement beyond bound,lost sync,or untrusted clock→`TIME_CLOCK_UNTRUSTED`,candidate rejected,LKG remains ready,`accepted` unchanged. Startup validates persisted observations+source order but never reevaluates an already accepted generation against current clock;time is not serving readiness. Actual Rain sync daemon,sources,config,boot ID capture,and 24h offset evidence remain `UNRESOLVED`.

### Watcher,reload,signals,leases

Watcher proposal:poll=60s with deterministic per-instance uniform jitter ±15s;connect timeout=10s;fetch wall=30s;fetch CPU=20s;retry=30s×2 capped 900s with ±20% jitter;timeout terminates fetch process group+deletes only recognized staging temp;rejected hash suppressed until hash changes or explicit operator retry.

Reload proposal:materialize≤45s;strict Git verify≤30s;archive verify+snapshot build≤90s;durable commit≤10s;all post-fetch phases share 120s wall deadline. Timeout before linearization→reject+LKG;timeout after durable `accepted` rename→publish exact prepared pointer or exit immediately for restart reconstruction.

Signal/lifecycle proposal:SIGTERM stops watcher,cancels pre-linearization candidate work,stops new public accepts,drains existing HTTP≤30s,and never rewrites `accepted`;systemd stop=35s;SIGKILL margin=5s. A lifetime-exclusive state lock prevents a new process from reading state until the old process exits. SIGKILL/restart chooses only durable `accepted`:pre-linearization kill reconstructs old;post-rename+dir-fsync kill reconstructs new;no candidate/newest/predecessor promotion.

Response lifecycle:request pins exactly one immutable snapshot;archive response opens only its prevalidated immutable-checkout file and holds generation lease+FD through completion. Ordinary request/archive/old-generation leases=120s;shutdown override=30s. Swap:after publication,new requests=new;already-started requests=old under lease+FD;never mixed. Lease/drain expiry cancels connection,closes FD,releases snapshot+checkout lease;online unlink/GC forbidden. Offline/quiesced reference-aware GC must retain active,complete accepted chain,rollback,in-flight/leased,remote-tip,and locked-candidate state.

Reject invariant:any candidate over resource/time/reload/state limits rejects before `accepted` mutation;delete only recognized staging temp;record one bounded result;serve LKG;do not evict active/rollback/leased state;do not automatically retry the same hash. Allocation failure=`RESOURCE_FAILURE`;quota/preflight=`STATE_SPACE`;specific proposed resource codes are frozen in `resource-limit-fixtures.json`. HTTP request rejection never mutates generation state.

### Minimum proof horizons

Clock qualification=86,400s(24h);resource stress=100 reload cycles+21,600s(6h)/instance;pre-cutover canary=259,200s(72h);each archive-body cutover=604,800s(7d);public sustained operation=1,209,600s(14d);legacy retirement≥2,592,000s(30d) after last successful rollback rehearsal. Pass criteria:no unexplained restart/OOM/quota/state mismatch;all rejects bounded;RSS p99<75% `MemoryHigh`;state<70% quota;archive+route completeness=100%;unexpected controlled-probe HTTP 5xx=0. Operator records horizon start/end only after prerequisites pass.

## UNRESOLVED — blockers/decisions

1. `DYNAMIC-MEASUREMENTS`:native steady/two-snapshot/three-snapshot RSS,FD peak,100-cycle reload distribution,SIGTERM/SIGKILL/drain/lease evidence absent.
2. `PROJECTION-BASELINE`:canonical active manifest absent;actual current `snapshotBytes` unknown;prove Rust≤16,777,216B and JS≤33,554,432B.
3. `HTTP-LIMIT-PROOF`:production-equivalent raw edge/backend 413/414/431,body-framing,header,target,and 256/64 saturation evidence absent.
4. `ARCHIVE-HISTORY-CAPACITY`:append-only growth model,provider ceiling,production ZFS create/fill/failure/recovery,backup+restore duration absent.
5. `BODY-CLOSURE-IN-SOURCE`:forward catalogs do not yet contain every retained body;body instances unauthorized.
6. `CLOCK-PROOF`:actual Rain clock source/config+24h dual-clock capture+forward/backward/lost-sync fault proof absent.
7. `RESTORE-HORIZON`:empty-root,remote-offline exact accepted-projection restore proof absent.
8. Operator decisions:independent approval of every exact integer;pin clock source/config;freeze distinct compatibility/body instance digests+state roots;record objective horizon timestamps.
9. Implementation decisions:map catalog timestamp syntax/order/future-skew fixture reasons to a fixed bounded runtime code vocabulary;prove filesystem power-loss old-or-new result at `accepted` rename boundary.

## Fixtures+validation

- `timestamp-fixtures.json`:observed ecosystem-specific spellings/order+proposed syntax,future-skew,sync,rollback,startup vectors.
- `shutdown-drain-fixtures.json`:proposed signal/cut-point,drain,old-snapshot FD/lease,state-lock,restart vectors;explicitly not measured behavior.
- `resource-limit-fixtures.json`:observed baselines+exact proposed ceilings,limit/limit+1 rejects,quota,Memory,HTTP saturation vectors.
- Validation:`python3 validate.py && sha256sum -c SHA256SUMS`;`validation.json` records JSON/schema,exact state enum,archive byte total,fixture boundaries,formulas/invariants,classification,and secret-scan checks;`SHA256SUMS` intentionally excludes itself.

## Harness

No material Talent harness issue affected this result. One read-only probe targeted a nonexistent captured JS source path and failed harmlessly;one inherited broad grep was noisy/truncated;no source repository was modified.
