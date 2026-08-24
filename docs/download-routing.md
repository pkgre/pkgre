# Immutable download routing

## Contract

Cargo substitutes `{crate}`, `{version}`, and `{sha256-checksum}` into each registry's index-wide `dl` template. pkg.re uses `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}`. Exact route identity = registry alias + case-sensitive Cargo package name + canonical SemVer + lowercase 64-hex SHA-256. Only `universe` + `pkgre` are accepted.

Successful `GET`/`HEAD` returns `307 Temporary Redirect` + `Cache-Control: no-store` to a destination derived from the catalog's closed source enum:

| Source | Destination |
|---|---|
| `crates-io` | `https://static.crates.io/crates/<name>/<version>/download` |
| `git-tag` | `https://rust.pkg.re/crates/<sha256>.crate` |

No catalog field supplies a URL/hostname. Route identity must match exactly; the service never redirects an unknown checksum, alternate spelling/case, noncanonical version, unsupported registry, query-bearing target, percent-encoded target, fragment, extra/missing segment, or target >1024 bytes. Malformed targets return `404` without refresh. Non-`GET`/`HEAD` methods return `405` + `Allow: GET, HEAD`.

## Generated catalog

`pkgre-indexer lock`, `update-apply`, and migration maintain canonical `registry/downloads.json`; `Catalog::load`/`check` require it to equal the exact projection of all active generated package locks. Removed identities are absent. Each entry contains only `registry`, exact `name`, canonical `version`, locked archive `sha256`, and `source = crates-io|git-tag`. Ordering, uniqueness, schema, canonical JSON bytes, file type, and 16 MiB limit are strict. `render` copies the same projection to top-level `downloads.json`; `verify` and `verify-monotonic` authenticate it against release identities.

A registry may retain its source-specific `dl` while all names use one source class. A registry containing both source classes must use its exact registry-bound router template; an arbitrary router/redirect URL fails validation. Switching a source-specific `dl` to the exact router is monotonic because route identity includes the already locked checksum and source class. Changing an existing name's permanent source class remains forbidden.

## Service state + refresh

`pkgre-download-serve` is stateless across processes. It fetches only:

1. `https://api.github.com/repos/pkgre/rust/git/ref/heads/main`;
2. `https://raw.githubusercontent.com/pkgre/rust/<validated-40-hex-commit>/registry/downloads.json`.

The HTTP client requires HTTPS, disables redirects + environment proxies, uses fixed endpoints, bounds response bodies, and applies connect/request timeouts. The ref must resolve directly to a lowercase 40-hex commit; the manifest fetch is pinned to that immutable commit. Only a fully parsed canonical catalog replaces the in-memory last-known-good table.

Defaults: listen `127.0.0.1:3000`; periodic refresh 300s; minimum interval 120s. One initial refresh starts after binding. Periodic + well-formed miss refreshes share one detached single-flight attempt. Cancelling a request cannot cancel/strand the attempt. Upstream `Retry-After`/rate-limit reset can extend backoff. Successful prior refresh + still-unknown route → `404`; failed/never-successful freshness + unknown route → `503` + `Retry-After`; known last-known-good routes remain available after refresh failure. Restart intentionally discards last-known-good state.

Observability: `GET|HEAD /healthz` returns `503` until one valid catalog is loaded, then `200`; `GET /status` returns no-store JSON containing readiness, source commit, manifest hash, route counts, timestamps, last error, next refresh delay, and in-flight state; `HEAD /status` returns `200` without a body. Status exposes public catalog metadata only.

CLI:

```console
$ nix build .#download-serve
$ ./result/bin/pkgre-download-serve --help
$ ./result/bin/pkgre-download-serve --listen 127.0.0.1:3000 --refresh-seconds 300 --minimum-refresh-seconds 120
```

## Reverse-proxy boundary

The backend trusts exactly one `X-Pkgre-Original-URI` value so it can reject query/encoding ambiguities after a frontend parses the request target. Therefore never expose the backend directly to untrusted clients and never forward a client-selected value. Bind/publish it only on loopback or a private namespace reachable by the fixed nginx frontend. nginx must overwrite the header from raw `$request_uri`, preserve the method, avoid path rewrites/normalization, and use a fixed upstream:

```nginx
location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header X-Pkgre-Original-URI $request_uri;
    proxy_pass http://127.0.0.1:3000;
}
```

Do not use a variable/user-controlled `proxy_pass`, `rewrite`, `try_files`, URI suffix on `proxy_pass`, public backend port, or forwarded client `X-Pkgre-Original-URI`. TLS, hostname routing, request/body limits, and access logging remain nginx responsibilities.

## Migration + rollback

Safe order:

1. Merge/publish `registry/downloads.json` while current source-specific registry `dl` values remain live.
2. Deploy service + fixed nginx proxy; wait for `/healthz = 200`; require `/status` source commit to contain the published catalog.
3. Probe exact representative mirror + Git routes; require `307` to hardcoded destinations; probe altered checksum/case/query/encoding/method behavior.
4. Change each registry declaration to its exact router template; run `lock`, `check`, render/verify/monotonicity, merge/publish.
5. Run clean-cache Cargo E2E across both sources and independently hash downloaded archives.

If routing fails after step 4, first revert registry `dl` values to their source-specific endpoints and republish the index; do not mutate route catalog identities or locked checksums. The pre-router values remain valid only while that registry still contains one source class. Service rollback is safe after all live `dl` values stop referencing it.
