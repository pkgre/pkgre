# Cargo vendoring with pkgre-vendor

Status:`v1` | scope:`nix/pkgre-vendor.py` + flake API `lib.<system>.rust.cargoDeps` | tag:`vendor/v0.1.0`

## What it does

A nix fetcher that vendors Cargo dependencies for projects resolving any dependency from a non-crates.io registry (for example `sparse+https://rust.pkg.re/`):

1. runs real `cargo vendor --locked` inside a fixed-output derivation against the live registry,
2. patches the vendored dependency manifests with `nix/pkgre-vendor.py` so non-crates.io lock rows keep their `registry-index` URL keys after cargo's vendoring rewrite,
3. emits the consumer `.cargo/config.toml` with the `@vendor@` placeholder INTACT, so `cargoSetupPostUnpackHook` substitutes the actual store path at build time,
4. passes `Cargo.lock` through UNMODIFIED — the consumer's lock-diff check compares byte-identical locks (stronger than rewriting the lock to match vendored sources).

Dependencies outside the resolved graph (for example untracked dev-dependencies of vendored crates) are left unqualified and reported on stderr.

## API

```nix
pkgre.lib.${system}.rust.cargoDeps {
  src;            # source fileset for the vendoring input (see contract below)
  lockFile ? null;# optional lock override copied over src/Cargo.lock
  cargoHash;      # output hash of the vendored tree (see bootstrap)
  name ? "cargo-deps";
  registriesFrom ? null; # explicit registry-definition source; default: src .cargo/config.toml, else empty
}
```

The result is consumable directly as `cargoDeps` by `rustPlatform.buildRustPackage` (the `cargoSetupPostUnpackHook` contract).

## Input contract

- `src` must contain the workspace `Cargo.toml`, `Cargo.lock`, all member manifests, and member sources.
- Member manifests must reference dependencies in name form (`registry = "<name>"`), not URL form; URL-form members would make the unmodified-lock pass-through invalid.
- Registry definitions live under `[registries]` in `src/.cargo/config.toml` (or are supplied via `registriesFrom`).
- If the consumer's build source itself ships a `.cargo/config.toml`, the hook appends the emitted config; pkgre's own build excludes `.cargo` from its build source fileset to avoid duplicate sections.

## Output layout

```text
<crate dirs>/
Cargo.lock
.cargo/config.toml      # @vendor@ placeholder intact
```

## Checksum bootstrap

```nix
cargoHash = pkgs.lib.fakeSha256; # first build fails with: got: sha256-...
```

Copy the `got:` value into `cargoHash` and rebuild; the hash is deterministic for a given lock + patch script + toolchain.

## Tradeoffs

- The FOD fetches from the live registry at build time. Registry availability is a build-time dependency of every rebuild of the vendored output; the hash pins the content after the first successful fetch.
- Proxy variables (`http_proxy`, `https_proxy`, ...) are passed through via `fetchers.proxyImpureEnvVars`.
- The pkg.re registry edge currently rejects parallel sparse-index request bursts with transient `503`s; the fetcher therefore sets `CARGO_HTTP_MULTIPLEXING=false` and `CARGO_NET_RETRY=20` to ride through. Consumers hitting other registries keep these settings; they are safe defaults.

## Dogfood

The pkgre flake consumes its own function for `rust` + `serve`:

```nix
pkgreCargoDeps = self.lib.${system}.rust.cargoDeps {
  src = cargoDepsSrc; # .cargo/config.toml + Cargo.lock + Cargo.toml + rust/
  cargoHash = "sha256-...";
  name = "pkgre-rust-cargo-deps";
};
```
