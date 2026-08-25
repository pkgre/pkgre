# Immutable download routing

## State and migration boundary

`pkgre-proxy` v0.2 implements the target cross-ecosystem same-host marker contract. It is not deployed. Current Rust production metadata still advertises `https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}` and the current Rust renderer still treats `downloads.json` as its generated route inventory. P9 will add Rust marker generation,publish markers before references,move `config.json` to `https://rust.pkg.re/v1/...`,and retain the legacy host through its cache+rollback horizon. JS has no published package routes before P7.

Target runtime authority is one exact static marker at the requested route in the route-selected GitHub Pages site. The service does not fetch `downloads.json`,GitHub refs/API/raw content,or live npm/crates metadata;it has no refresh loop,mutable route database,or last-known-good route table. Marker existence authorizes the route;origin `404` means absent.

## Canonical routes

| Ecosystem | Public route | Static marker host |
|---|---|---|
| Rust | `https://rust.pkg.re/v1/<registry>/<crate>/<canonical-semver>/<sha256>` | `rust.pkg.re` |
| JavaScript | `https://js.pkg.re/v1/js/<registry>/<sha256>` | `js.pkg.re` |

Bounds/grammar:request target≤1024 bytes;ASCII only;no query,fragment,percent encoding,backslash,duplicate/extra segment,or dot segment;registry=1–64 lowercase ASCII alphanumeric/`-`/`_`;Rust crate=1–64 ASCII alphanumeric/`-`/`_`,starting alphanumeric;Rust version parses+reserializes as the identical canonical SemVer;digest=64 lowercase hex. Noncanonical/unknown targets return `404` without origin access.

The JS hash route avoids scoped-name escaping;the exact npm package/version/archive path remains bound inside the marker. Route-selected host/ecosystem is closed code,not a marker field decision. Every download request must also contain exactly one byte-exact matching `Host` (`rust.pkg.re` or `js.pkg.re`);missing,duplicate,case/port variants,and cross-ecosystem hosts fail before origin access.

## Redirect marker v1

Canonical bytes live under [`fixtures/redirect-marker-v1/`](../fixtures/redirect-marker-v1/). The ≤4KiB ASCII document has one exact template;its machine line binds schema `v1`,ecosystem,canonical route,destination kind,destination,and the meta-refresh line repeats the identical destination. Unknown/missing/extra fields,whitespace/template drift,trailing bytes,non-ASCII,oversize,route replay,or machine/meta mismatch fail `502`.

Closed destinations:

| Ecosystem/kind | Exact destination grammar |
|---|---|
| Rust `crates-io` | `https://static.crates.io/crates/<route-crate>/<route-version>/download` |
| Rust `first-party` | `https://rust.pkg.re/crates/<route-sha256>.crate` |
| JS `npmjs` | `https://registry.npmjs.org/<package>/-/<package>-<version>.tgz` or scoped `https://registry.npmjs.org/@<scope>/<package>/-/<package>-<version>.tgz`;bounded lowercase npm components;no alternate port,userinfo,query,fragment,or encoding |
| JS `first-party` | `https://js.pkg.re/packages/<route-sha256>.tgz` |

No document field may authorize another scheme,authority,port,first-party hash,or Rust identity. npm/Cargo integrity remains the final byte check;the marker controls availability+the location within a closed archive grammar,not arbitrary URL authority.

Ordinary package removal omits metadata but retains marker/object availability for existing exact locks. Emergency revocation/tombstone behavior is not part of marker-v1 v0.2;deleting the marker yields `404`. A future `410` form requires a new fixture-locked protocol decision.

## Origin adapter

Every canary/marker operation:

1. Resolves only literal `pkgre.github.io:443`;accepts at most 16 answers;deduplicates IPs;admits only global-unicast addresses after a conservative local special-purpose filter. IPv4 rejects all of `0/8`,`100.64/10`,`192.0.0/24`,`192.88.99/24`,`198.18/15`,private,loopback,link-local,documentation,multicast,and reserved ranges;the whole `192.0.0/24` is rejected despite globally reachable `.9`/`.10`. IPv6 admits only `2000::/3` after rejecting the whole `2001::/23` despite its global exceptions,`2001:db8::/32`,`2002::/16`,and `3fff::/20`;boundaries+current GitHub Pages IPv4/IPv6 answers are fixture-tested.
2. Selects public host only from the parsed route:Rust→`rust.pkg.re`;JS→`js.pkg.re`.
3. Connects to a validated resolved Pages IP on port 443 while URL authority,TLS SNI,WebPKI certificate hostname verification,and HTTP Host all remain the selected public host.
4. Sends `GET` for the unchanged canonical root-relative path,including when the public request is `HEAD`;forwards no client body,authorization,cookies,or arbitrary headers.
5. Disables environment proxies and redirects;requires HTTPS+TLS≥1.2;uses 3s DNS,5s connect,and 15s total bounds;retries another current public Pages answer only after a pre-response transport/TLS failure and within the one total deadline.
6. Requires marker `200`+exact single `Content-Type:application/octet-stream`+no `Content-Encoding`+body≤4KiB. A semantic status/header/body failure is final and is never retried on another address.

Fixed readiness canary path=`/origin-health/v1.txt`;MIME=`text/plain; charset=utf-8`;exact bodies=`pkgre-origin rust v1\n` and `pkgre-origin js v1\n`. A mismatched/missing custom-host certificate always fails TLS;there is no insecure fallback or alternate SNI/Host.

## Public response contract

All responses carry `Cache-Control:no-store`;response bodies are empty except `GET /metrics`.

| Condition | Response |
|---|---|
| Canonical `GET|HEAD`+valid marker | `307 Temporary Redirect`+validated `Location` |
| Origin marker `404` | `404 Not Found` |
| Noncanonical/unknown local path;missing/duplicate/mismatched public Host | `404 Not Found`;no origin fetch |
| Malformed marker;unexpected origin redirect/non-200/non-404;wrong/duplicate MIME;content encoding;oversize body | `502 Bad Gateway` |
| DNS/connect/TLS/timeout/body-read/429/5xx/client-construction failure | `503 Service Unavailable` |
| Method other than `GET|HEAD` | `405 Method Not Allowed`+`Allow: GET, HEAD`;no origin fetch |

Both public methods perform an origin `GET`;a Pages `HEAD` cannot authorize a body it did not return. The service never fetches an archive or follows its emitted destination.

## Health and bounded local telemetry

| Endpoint | Contract |
|---|---|
| `GET|HEAD /healthz` | `200`;process/config handler health only |
| `GET|HEAD /readyz` | `200` only after both fixed host canaries have a success no older than the configured freshness;otherwise `503` |
| `GET /metrics` | Prometheus text with closed host/result/error/outcome labels |
| `HEAD /metrics` | Same status/headers;empty body |

Defaults:listen=`127.0.0.1:3000`;canary interval=`60s`;readiness freshness=`180s`;positive values required;freshness≥interval. A later failed canary increments failure/error metrics but the last success remains readiness authority until expiry,avoiding instantaneous flapping while still failing closed after the window.

```console
$ nix build .#proxy
$ ./result/bin/pkgre-proxy --help
$ ./result/bin/pkgre-proxy --listen 127.0.0.1:3000 --canary-seconds 60 --readiness-seconds 180
```

Transitional `.#download-serve` aliases `.#proxy` through the rain deployment+rollback horizon. Local readiness/metrics are service signals only;they do not constitute the independently isolated persistent certificate+HTTP contract monitoring required before the renewal and production Rust cutover gates.

## Reverse-proxy boundary

Backend trusts at most one `X-Pkgre-Original-URI` so it can reject query/encoding ambiguities after frontend parsing. Never expose it directly or forward a client-selected value. Bind/publish only on loopback/private namespace behind fixed nginx. nginx must overwrite the raw URI and public Host with literals from the enclosing vhost,preserve method,strip client credentials/forwarding headers,avoid normalization,and use a fixed upstream. Example Rust block:

```nginx
# inside server_name rust.pkg.re
location /v1/ {
    proxy_http_version 1.1;
    proxy_set_header Host rust.pkg.re;
    proxy_set_header Connection "";
    proxy_set_header Authorization "";
    proxy_set_header Cookie "";
    proxy_set_header X-Pkgre-Original-URI $request_uri;
    proxy_pass http://127.0.0.1:3000;
}
```

The separate JS vhost uses the same fixed upstream pattern but only `location /v1/js/` and literal `proxy_set_header Host js.pkg.re;`. Do not use `$host`/`$http_host`:the backend requires exactly one byte-exact route-matching Host and returns `404` before origin access for a missing,duplicate,case/port variant,or cross-ecosystem value. A duplicate trusted URI header likewise fails `404`;without that header the service validates the server-observed path+query. Forbidden:variable/user-controlled `proxy_pass`;rewrite/`try_files`;URI suffix on backend `proxy_pass`;public backend port;forwarded client `Host` or `X-Pkgre-Original-URI`.

Ordinary static traffic uses separate literal nginx configuration per public vhost with the same origin invariant:resolve `pkgre.github.io`;connect to that Pages address;TLS SNI+verification+Host equal the fixed matching public host;root-relative path unchanged;origin redirects fail rather than recurse. Client host/path/header input may not select an upstream authority.

## Publication,migration,rollback

Addition order:publish archive objects+markers first;read back exact bytes through strict custom-host origin+public proxy;wait the measured Pages cache horizon;only then publish metadata referring to routes. GitHub Pages path caches are not cross-path atomic.

Rust P9 order:deploy/test rain frontend by explicit resolve while production DNS still targets Pages;publish all markers;move DNS to rain;hold while current metadata still advertises `dl.rust.pkg.re`;publish same-host `config.json` only after public+origin+Cargo tests pass. Before metadata change,DNS rollback restores Pages. After metadata change,keep rain serving or first republish last-known-good legacy-host metadata+wait propagation before restoring Pages;never strand same-host metadata on direct Pages,where a marker would be returned instead of a `307`.

JS P7 publication requires the already verified custom-host origin+rain frontend,strict marker readback,and clean npm/Bun/Deno install matrices. npmjs may be a third-party archive destination but is never a metadata fallback.
