# D0 JavaScript catalog/bootstrap inventory

Status:**PASS** for the complete fixed-basis JavaScript catalog/bootstrap scope;broader dynamic-rollout D0 remains blocked by the explicitly recorded external/future-contract gaps. No repository,settings,service,credential,or secret mutation occurred.

## Basis+method

- Implementation:`pkgre:066293df21743cbf41fb571a38f2bb94059e7274` tree `0326ff44970839b753dca8b1f9bbd649b54c004d`;all applicable JS bytes read explicitly with `git cat-file` at this basis despite current worktree HEAD `5a67e8d76ec8a8dd85ff9167455e58b45e9994c6`.
- Catalog:`pkgre-js:f43bd58bd3d4e36f8b3f4df3c002735c977acd17` tree `b8c0d5dae071cad4416795e5612c1ddb234bd104`.
- Builder:`build_inventory.py`;Python stdlib+read-only Git object/status commands;no network;deterministic outputs;no timestamps generated.
- Prior analysis SHA-256:`cb158b3e3b2c763e8720ae176d6ac8a574ec5cb1b0eae2fdfebd7eeb1b1e5ca5`. Public-route evidence SHA-256:`5ea936ccf5de7861564728e738912a2e646ba0c87c73afa2a7d05f3d0b2b5801`.

## Exact observed closure

| Item | Count/identity |
|---|---|
| Catalog | schema `pkgre-js-catalog-v1`;registry `main`;1 package;1 version;1 dist-tag;0 dependency edges |
| Source kinds | first-party=1;npmjs=0 |
| Package | `pkgre-js@0.1.0`;`latest=0.1.0`;dependency-free |
| Minimum-age inputs | evaluation/published/admitted=`2026-08-25T23:27:24.000Z`;minimum=`2592000`;age=0;validator applies age only to npmjs;first-party exclusion is implicit in current code |
| Archive | 1 unique;16,717 bytes;SHA-256 `07e3bbe05bffd0994601324a6519621dd93c6990e9350b04019c8366942207e3`;3 tree/checkout copies=50,151 logical bytes;11 members match implementation-basis bytes |
| Rendered stage rows | 19 total:previous=4,routes=7,final=8 |
| Packument | `/pkgre-js`;996 bytes;SHA-256 `6cd8e81ee6efebfbed3f8df101ef9fc174672e7855933c6ec4d989697f06722d` |
| Legacy marker | `/v1/js/main/07e3bbe05bffd0994601324a6519621dd93c6990e9350b04019c8366942207e3`;561 bytes;SHA-256 `86a9005390094d14eb9411bfb1351b349b5dd94486b5dee541b6f6bd7a802e7c`;destination `https://js.pkg.re/packages/07e3bbe05bffd0994601324a6519621dd93c6990e9350b04019c8366942207e3.tgz` |
| Catalog checksum fixture | all 22 pinned `SHA256SUMS` rows validated |

Exact schemas,all catalog records,archive members/copies/Git-object storage,rendered bytes,live observations,requirements,and absent future fields are in the machine-readable artifacts.

## Audience+live-state boundary

The current catalog has no `audience` field. The independent D0 old-to-new route mapping classifies every current JS URL here as `public`;this is evidence classification,not a hidden catalog value. Captured live evidence is nine ordinary-route **502** responses and one marker-route **503** response. These are labeled point-in-time outage/non-readiness evidence;they do **not** show the fixed packument,archive,or marker bytes were served.

## Requirements,not observed current schema

Accepted plan requirements are represented separately:explicit `public|lan-public|control-only` audience;append-only retained routes+`.tgz` bodies;terminal state;immutable accepted-generation+predecessor records;dynamic `stateContract:"state-contract-v1"` plus literal `redirectMarkerSchema:null`. The current HTML marker is the independent legacy `redirect-marker-v1` adapter. None is misreported as an observed catalog field.

## Blockers outside this fixed inventory

Live JS origin readiness;future dynamic schema/state;fresh upstream fetch proof;SSH-Ed25519/`allowedSigners` admission;archive history/pack/fetch/clone/quota/backup/Rain ceiling rehearsal;scoped production fixture;D13 LAN decision. These block later/broader gates but do not turn this complete fixed-scope inventory into a failure.

## Reproduce+verify

```sh
python3 /home/dev0/.talent/agents/01a0368b-4cd1-7930-b789-daf0a9a11164/workspace/d0-js-inventory/build_inventory.py --output /home/dev0/.talent/agents/01a0368b-4cd1-7930-b789-daf0a9a11164/workspace/d0-js-inventory
(cd /home/dev0/.talent/agents/01a0368b-4cd1-7930-b789-daf0a9a11164/workspace/d0-js-inventory && sha256sum --check --strict SHA256SUMS)
```

Repositories were clean before+after and their observed states were identical. Secret values and credential files were not read;network was not used.

## Harness issues

None encountered while building this artifact set.
