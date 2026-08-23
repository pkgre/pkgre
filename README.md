# pkg.re

Declarative tooling + policy for small, curated Cargo registries.

## Purpose

pkg.re converts three human-edited registry files into deterministic Cargo sparse registries. Human TOML declares exact mirrored versions + immutable first-party Git tags; `pkgre-indexer lock` materializes new identities, generates immutable provenance locks, and transactionally converges retained source rows + Git-tag archives. Mirror archives are fetched + checksum-verified during locking but served later by crates.io; metadata + integrity remain controlled by the curated row. No mutable registry API or `cargo publish` operation is authoritative.

Removal replaces curator-controlled yanking: delete a version/tag from desired state but retain its package key; reconciliation preserves an irreversible tombstone + source evidence, removes an unshared retained Git archive, and renders the retained row as yanked.

Registries:

| Alias | URL | Contents | Archive download | May depend on |
|---|---|---|---|---|
| `core` | `sparse+https://rust.pkg.re/core/` | General-purpose mirrored crates | `https://static.crates.io/crates` | `core` |
| `matrix` | `sparse+https://rust.pkg.re/matrix/` | Matrix ecosystem mirrors | `https://static.crates.io/crates` | `matrix`, `core` |
| `pkgre` | `sparse+https://rust.pkg.re/pkgre/` | First-party pkg.re Git-tag packages | `https://rust.pkg.re/crates/{sha256-checksum}.crate` | `pkgre`, `matrix`, `core` |

## Components

- `indexer/`: Rust reconciler, validator, deterministic renderer, release verifier.
- [`docs/catalog.md`](docs/catalog.md): schema-v2 human files, generated locks, objects, routing, removal.
- [`docs/workflows.md`](docs/workflows.md): mirror review, Git-tag publication, removal, release procedures.
- [`docs/security.md`](docs/security.md): trust model, enforced invariants, exclusions.
- Registry catalog/site: [`pkgre/rust`](https://github.com/pkgre/rust).

## Build

```console
$ nix flake check --print-build-logs
$ nix build .#pkgre-indexer
$ nix run .#pkgre-indexer -- --help
```

Pinned build semantics: Cargo `1.95.0`; Nix flake locks Rust + build inputs; Cargo inputs become fixed-output Nix fetches; checks build/test/lint offline after fetching.

## Catalog operation

```console
$ pkgre-indexer lock registry
$ pkgre-indexer check registry
$ pkgre-indexer render registry site-next
$ pkgre-indexer verify registry site-next
$ pkgre-indexer verify-monotonic site-current site-next
```

`registry/` is an exclusive managed-state directory: only `<registry>.toml`, generated `<registry>.lock`, and `objects/` are permitted.

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

Create `.cargo/disabled-crates-io/` in the project. Approved index rows contain explicit cross-registry routes; consumers only declare the registry containing each direct package.

## License

Apache-2.0.
