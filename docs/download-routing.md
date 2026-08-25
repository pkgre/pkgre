# Immutable download routing

## Contract

Cargo substitutes `{crate}`, `{version}`, and `{sha256-checksum}` into each registry's index-wide `dl` template. pkg.re uses `https://dl.rust.pkg.re/v1/<catalog-registry>/{crate}/{version}/{sha256-checksum}`. Current production root registry:`main`; future aliases such as `staging` require no router redeploy because accepted aliases/routes come from the authenticated catalog.

Exact route identity = canonical catalog registry alias + case-sensitive Cargo package name + canonical SemVer + lowercase 64-hex SHA-256. A route must exist exactly in `downloads.json`; accepting an alias does not authorize absent package/version/checksum tuples.

Successful `GET`/`HEAD` returns `307 Temporary Redirect` + `Cache-Control: no-store` to a destination derived from the closed source enum:

| Source | Destination |
|---|---|
| `crates-io` | `https://static.crates.io/crates/<name>/<version>/download` |
| `git-tag` | `https://rust.pkg.re/crates/<sha256>.crate` |

No catalog field supplies a URL/hostname. The service never redirects an unknown checksum, alternate spelling/case, noncanonical alias/version, query-bearing target, percent-encoded target, fragment, extra/missing segment, or target >1024 bytes. Malformed targets return `404` without refresh. Non-`GET`/`HEAD` methods return `405` + `Allow: GET, HEAD`.

## Generated catalog

`pkgre-indexer lock`, `update-apply`, and migration maintain canonical `registry/downloads.json`; load/check require it to equal the exact projection of all active generated package locks. Removed identities are absent. Each entry contains only `registry`, exact `name`, canonical `version`, locked archive `sha256`, and `source = crates-io|git-tag`. Ordering, uniqueness, schema, aliases, canonical JSON bytes, file type, and 16 MiB limit are strict. `render` copies the same bytes to top-level `downloads.json`; `verify`/`verify-monotonic` authenticate it against release identities.

A registry may retain its source-specific `dl` while all names use one source class. Mixed sources require that registry's exact router template; an arbitrary router/redirect URL fails validation. Switching source-specific `dl`→exact router is monotonic because route identity includes the already locked checksum/source class. Changing an existing registry-qualified name's source class remains forbidden.

## Service state + refresh

`pkgre-download-serve` is process-stateless. It fetches only:

1. `https://api.github.com/repos/pkgre/rust/git/ref/heads/main`;
2. `https://raw.githubusercontent.com/pkgre/rust/<validated-40-hex-commit>/registry/downloads.json`.

HTTP requires HTTPS, disables redirects + environment proxies, uses fixed endpoints, bounds bodies, and applies connect/request timeouts. The ref must resolve directly to lowercase 40-hex commit; manifest fetch is pinned to that immutable commit. Only a fully parsed canonical catalog replaces in-memory last-known-good.

Defaults:listen `127.0.0.1:3000`; periodic refresh 300s; minimum interval 120s. One initial refresh starts after binding. Periodic + well-formed route misses share one detached single-flight attempt. Cancellation cannot cancel/strand it. Upstream `Retry-After`/rate-limit reset can extend backoff. Successful prior refresh + still-unknown route→`404`; failed/never-successful freshness + unknown route→`503` + `Retry-After`; known LKG routes remain available after failure. Restart discards LKG by design.

Observability:`GET|HEAD /healthz` returns `503` until one valid catalog loads, then `200`; `GET /status` returns no-store JSON with readiness, source commit, manifest hash, route/source counts, timestamps, last error, next refresh delay, and in-flight state; `HEAD /status` omits body.

```console
$ nix build .#download-serve
$ ./result/bin/pkgre-download-serve --help
$ ./result/bin/pkgre-download-serve --listen 127.0.0.1:3000 --refresh-seconds 300 --minimum-refresh-seconds 120
```

## Reverse-proxy boundary

Backend trusts exactly one `X-Pkgre-Original-URI` so it can reject query/encoding ambiguities after frontend parsing. Never expose backend directly or forward a client-selected value. Bind/publish only on loopback/private namespace behind fixed nginx. nginx must overwrite from raw `$request_uri`, preserve method, avoid normalization, and use fixed upstream:

```nginx
location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header X-Pkgre-Original-URI $request_uri;
    proxy_pass http://127.0.0.1:3000;
}
```

Forbidden:variable/user-controlled `proxy_pass`; `rewrite`; `try_files`; URI suffix on `proxy_pass`; public backend port; forwarded client `X-Pkgre-Original-URI`. TLS, hostname routing, request/body limits, and logging remain nginx responsibilities.

## Deployment + rollback

Safe order:

1. Merge/publish canonical `registry/downloads.json` while any current source-specific `dl` remains live.
2. Deploy service + fixed nginx; wait for `/healthz = 200`; require `/status` source commit to contain published catalog.
3. Probe exact mirror + Git routes; require hardcoded destinations; probe altered checksum/case/query/encoding/method.
4. Change each target registry declaration to its own exact router template; run `lock`, `check`, render/verify/monotonicity, merge/publish.
5. Run clean-cache Cargo E2E across both source classes + independently hash archives.

Current `main` is already mixed and therefore always requires `https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}`. If routing fails, no direct endpoint can safely serve mixed sources. Roll back the index/site to the last known-good release + keep the router's known routes available; do not mutate route identities/checksums or point mixed `main` at crates.io/Git directly.
