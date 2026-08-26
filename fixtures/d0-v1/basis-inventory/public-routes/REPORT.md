# D0 public route inventory

Status:PASS for fixed-commit route closure+point-in-time public-edge observation;no repository,service,DNS,GitHub setting,or deployment mutation performed.

## Basis

| Basis | Fixed commit | Use |
|---|---|---|
| `pkgre/pkgre` | `066293df21743cbf41fb571a38f2bb94059e7274` | reviewed renderer+legacy marker/route semantics |
| `pkgre/pkgre-rust` | `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` | Rust catalog+publication sources |
| `pkgre/pkgre-js` | `f43bd58bd3d4e36f8b3f4df3c002735c977acd17` | JS catalog+`site-final` rendered sources |

Rust publication workflow at the fixed catalog commit pins older implementation `ae1dfbfd4e965dffb538e356f005e4fbb32fdb77`; independent renders from that pin and reviewed `066293df` are byte-identical:563 files;sorted path/length/SHA-256 inventory hash=`74fca0feee12753226ba8c5cebeb272cf8863b157879dcccfdc0a52650018f8e` (`renderer-equivalence.json`). Canonical bytes always mean fixed-repository/rendered bytes;`observed` always means a no-follow public HTTPS probe and is never source authority.

## Closure+counts

Total old URL keys=`2072`;unique `(origin,rawPath)`=`2072`;duplicate mapping=`0`;probe transport errors=`0`. Every old key has exactly one audience,source record,external observation,and intended D8–D14 descriptor;legacy `dl.rust.pkg.re` aliases intentionally converge on the matching canonical `rust.pkg.re` path.

| Set | Rows | Closure/result |
|---|---:|---|
| Rust fixed renderer files | 563 | 555 sparse rows+`config.json`+`downloads.json`+`release.json`+`CNAME`+`.nojekyll`+3 retained `.crate` objects;all mapped |
| Rust extra published URL aliases/files | 3 | `/`,`/index.html`,`/origin-health/v1.txt` |
| Rust catalog names | 911 | 555 names w/ versions produce rows;356 reserved empty names correctly produce no current URL |
| Rust active identities | 747 | lock=`downloads.json`;744 crates.io+3 Git-tag;each has one current `dl.rust.pkg.re` alias+one same-path `rust.pkg.re` route |
| Legacy public admin URLs | 2 | `dl.rust.pkg.re/healthz`,`/status`;captured;remain legacy-only until D14 removal |
| JS rendered URL keys | 10 | 8 `site-final` files+root index alias+fixture directory index alias;1 unscoped packument,1 marker,1 object;scoped packuments=`0` |

Current observation matrix:

| Origin | Status/count | Exact result summary |
|---|---|---|
| `rust.pkg.re` | `200×566` | all repository-backed bytes equal fixed source SHA-256+length |
| `rust.pkg.re` | `404×747` | every current canonical `/v1/main/<crate>/<version>/<sha256>`;common 9,379-byte body SHA-256=`b620507312c5e97566a3c6cfaf99144fefc18a0da7d941401dfa0f5f58fb0368` |
| `dl.rust.pkg.re` | `307×747` | empty body SHA-256=`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;every `Location` equals catalog-derived crates.io or retained first-party object destination;`Cache-Control:no-store` |
| `dl.rust.pkg.re` | `200×2` | public `/healthz` empty;`/status` 397 bytes at capture;exact per-row hashes+headers retained |
| `js.pkg.re` | `502×9` | common 150-byte body SHA-256=`61b30d408583991fd69f3dec694e154cb652471e663328ad9c8482c9021ab5db` |
| `js.pkg.re` | `503×1` | `/v1/js/main/07e3…`;empty body;`Cache-Control:no-store` |

Probe window=`2026-08-26T12:14:15.287541+00:00`…`2026-08-26T12:35:23.181534+00:00`;redirects not followed;one transient Rust-path `503` was immediately re-probed and frozen as stable `404`. `routes.json` retains exact timestamps,status,all returned header values,body SHA-256+length,redirect destinations,and semantic/edge/unclassified header splits per URL.

## Intended D8–D14 mapping

- D8 Rust:exact current bytes for config/downloads/release+555 sparse rows;3 `/crates/<sha>.crate` objects remain exact;747 `rust.pkg.re/v1/...` routes intentionally change current `404`→typed empty `307`;747 `dl.rust.pkg.re` aliases remain exact `307` during compatibility.
- D9–D10 Rust:canonical `/v1/...` transitions `307`→exact archive body;metadata later changes its `dl` template to same-host;legacy host becomes dormant after horizon.
- D11 JS:packument+object activate from fixed rendered bytes despite current edge failure;HTML marker is not served by dynamic code and intentionally becomes direct typed empty `307`;landing/provider/control/canary/nonproduction/site-inventory paths become fixed `404` on protocol-only vhost.
- D12 JS:canonical `/v1/js/...` transitions `307`→exact archive body;`/packages/...` remains exact.
- D14:Pages/provider files,HTML-marker adapter,public legacy admin surface,and `dl.rust.pkg.re` removed only after the plan’s independent operator gates+horizon;no current URL is silently omitted from this mapping.

## Gaps/blockers requiring later operator/edge evidence

1. JS public origin is not serving fixed rendered bytes:all ordinary routes=`502`,marker proxy=`503`. D11 remains blocked on `JS-INITIAL-ANCHOR`/strict origin continuity and operator-returned deployment evidence;repository bytes here are not claimed live.
2. Rust same-host `/v1/...` is uniformly `404` because fixed Rust publication renders no marker files;D8’s typed `307` is an explicit intentional activation,not current-byte equivalence.
3. Deterministic future end-to-end headers remain D1/edge work. Observed edge-owned names are `accept-ranges,access-control-allow-origin,age,content-security-policy,date,etag,expires,last-modified,server,vary,via,x-cache,x-cache-hits,x-fastly-request-id,x-github-edge-region,x-github-request-id,x-origin-cache,x-proxy-cache,x-served-by,x-timer`;`connection` is separately unclassified/hop-by-hop. Exact per-route observations are preserved,not promoted into future backend ownership.
4. Rust catalog’s actual workflow pin differs from reviewed implementation commit although outputs are proved byte-identical; any pin/settings correction is outside this read-only inventory.
5. Completeness covers fixed source-publication routes,known GitHub Pages `index.html` aliases,current nginx host routing,and catalog-derived identities. Provider-assigned artifact/settings IDs,raw nginx transform proof,access-log-only unknown aliases,and deployment ownership require operator/live-edge evidence under the broader D0 gate;none were guessed.
6. `/status` is live operational state;its captured hash is exact only for the recorded instant and is not canonical catalog/rendered data.

## Artifacts

- `routes.json`:authoritative expanded manifest;2072 mappings+canonical source+full external observations.
- `old-to-intended.jsonl`:one compact deterministic old→intended fixture per route;2072 newline-terminated JSON records.
- `sources.json`:closed Rust+JS catalog identities/provenance.
- `validation.json`:machine-readable assertions+counts.
- `renderer-equivalence.json`:reviewed-vs-workflow Rust renderer proof.
- `build_inventory.py`,`reproduce.sh`:read-only regeneration/check tooling;`reproduce.sh --probe` refreshes external observations.
- `SHA256SUMS`:hashes every final artifact except itself.
