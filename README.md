# pkg.re

Declarative tooling + policy for small, curated Cargo registries.

## Purpose

pkg.re converts an explicitly reviewed catalog into deterministic Cargo sparse registries. The catalog, not an imperative publish command, is authoritative: exact package versions, exact artifact hashes, immutable origins, package homes, registry layering, and curator-owned yank state are all committed declarations.

Registries:

| Alias | URL | Contents | May depend on |
|---|---|---|---|
| `core` | `sparse+https://rust.pkg.re/core/` | General-purpose curated crates | `core` |
| `matrix` | `sparse+https://rust.pkg.re/matrix/` | Matrix ecosystem | `matrix`, `core` |
| `pkgre` | `sparse+https://rust.pkg.re/pkgre/` | First-party pkg.re packages | `pkgre`, `matrix`, `core` |

## Components

- `indexer/`: Rust validator, candidate materializer, deterministic renderer, release verifier.
- [`docs/catalog.md`](docs/catalog.md): v1 declarative schema + routing semantics.
- [`docs/workflows.md`](docs/workflows.md): crates.io import + first-party Git-tag release procedures.
- [`docs/security.md`](docs/security.md): trust model, invariants, exclusions.
- Registry catalog/site: [`pkgre/rust`](https://github.com/pkgre/rust).

## Build

```console
$ nix flake check --print-build-logs
$ nix build .#pkgre-indexer
$ nix run .#pkgre-indexer -- --help
```

Pinned build semantics: Cargo `1.95.0`; Nix flake locks Rust + all build inputs; Cargo inputs become fixed-output Nix fetches; checks build/test/lint offline after fetching.

## Consumer configuration

Project manifests name every alternate registry explicitly:

```toml
[dependencies]
serde = { version = "=1.0.229", registry = "core" }
matrix-sdk = { version = "=0.16.0", registry = "matrix" }
```

Project `.cargo/config.toml` defines aliases and fails closed on implicit crates.io access:

```toml
[registries.core]
index = "sparse+https://rust.pkg.re/core/"

[registries.matrix]
index = "sparse+https://rust.pkg.re/matrix/"

[registries.pkgre]
index = "sparse+https://rust.pkg.re/pkgre/"

[registry]
default = "pkgre"

[source.crates-io]
replace-with = "disabled-crates-io"

[source.disabled-crates-io]
directory = ".cargo/disabled-crates-io"
```

Create `.cargo/disabled-crates-io/` in the project. Registry dependencies embedded in approved index rows are routed by the renderer; a consumer need only declare the registry containing its direct package.

## License

Apache-2.0.
