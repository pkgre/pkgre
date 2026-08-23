# pkg.re

Declarative tooling + policy for small curated Cargo registries.

## Purpose

pkg.re converts human registry/category declarations into deterministic Cargo sparse registries. Human TOML declares exact mirrored versions + immutable first-party Git tags; evidence-bound update commands admit new mirrors, while `pkgre-indexer lock` handles bootstrap/removal/Git tags and transactionally converges generated locks + retained objects. Mirror archives are fetched + checksum-verified during admission but served later by crates.io; metadata + integrity remain controlled by the curated row. No mutable registry API or `cargo publish` operation is authoritative.

Removal replaces curator-controlled yanking: delete a version/tag from desired state but retain its package key; reconciliation preserves an irreversible tombstone + source evidence, removes an unshared retained Git archive, and renders the retained row as yanked.

Registries:

| Alias | URL | Source class | Archive download |
|---|---|---|---|
| `universe` | `sparse+https://rust.pkg.re/universe/` | crates.io mirrors | `https://static.crates.io/crates` |
| `pkgre` | `sparse+https://rust.pkg.re/pkgre/` | First-party pkg.re Git-tag packages | `https://rust.pkg.re/crates/{sha256-checksum}.crate` |

A registry is mirror-only or Git-only because Cargo exposes one index-wide `dl` URL; mixed source classes fail closed. Category policy is finer-grained than Cargo registries:

| Category | May depend on |
|---|---|
| `universe/general` | `universe/general` |
| `universe/acp` | `universe/acp`, `universe/general` |
| `universe/filesystem` | `universe/filesystem`, `universe/general` |
| `universe/matrix` | `universe/matrix`, `universe/general` |
| `universe/mcp` | `universe/mcp`, `universe/sse`, `universe/general` |
| `universe/sse` | `universe/sse`, `universe/general` |
| `universe/terminal` | `universe/terminal`, `universe/general` |
| `universe/yaml` | `universe/yaml`, `universe/general` |
| `pkgre/tooling` | `pkgre/tooling`, `universe/general` |

## Components

- `indexer/`: Rust reconciler, validator, schema-2→3 migrator, deterministic renderer, release verifier.
- [`docs/catalog.md`](docs/catalog.md): schema-3 human files, inline/external categories, generated locks, objects, routing, removal.
- [`docs/workflows.md`](docs/workflows.md): mirror review, Git-tag publication, removal, migration, release procedures.
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
$ pkgre-indexer update-plan registry plan.toml
$ pkgre-indexer update-plan-exact registry <package> <version> plan.toml
$ pkgre-indexer update-inspect plan.toml <package> <version> review
$ pkgre-indexer update-approve plan.toml approved.toml <package> <version> <source-delta|full-archive> note.txt
$ pkgre-indexer update-apply registry <plan-or-approved-plan.toml>
$ pkgre-indexer lock registry
$ pkgre-indexer check registry
$ pkgre-indexer render registry site-next
$ pkgre-indexer verify registry site-next
$ pkgre-indexer verify-monotonic site-current site-next
$ pkgre-indexer migrate-v2-to-v3 registry-v2 registry-v3
```

Update planning/inspection is read-only; keep plans, notes, and inert review trees outside `registry/`. `update-apply` is the only established-catalog path for new mirror identities; it revalidates ≤7-day-old evidence and atomically adds declarations, generated locks/objects, and `_reviews/admissions/` records. `lock` remains valid for bootstrap, empty name reservations, removals, and Git tags. `registry/` is exclusive managed state: only `<registry>.toml`, generated `<registry>.lock`, referenced `categories/<registry>/<category>.toml`, `_reviews/admissions/<candidate-binding-sha256>.toml`, and `objects/` are permitted.

## Consumer configuration

Project manifests name every alternate registry explicitly; categories do not change Cargo's registry alias:

```toml
[dependencies]
serde = { version = "=1.0.229", registry = "universe" }
matrix-sdk = { version = "=0.18.0", registry = "universe" }
pkgre-indexer = { version = "=0.2.0", registry = "pkgre" }
```

Project `.cargo/config.toml` defines aliases and fails closed on implicit crates.io access:

```toml
[registries.universe]
index = "sparse+https://rust.pkg.re/universe/"

[registries.pkgre]
index = "sparse+https://rust.pkg.re/pkgre/"

[registry]
default = "universe"

[source.crates-io]
replace-with = "disabled-crates-io"

[source.disabled-crates-io]
directory = ".cargo/disabled-crates-io"
```

Create `.cargo/disabled-crates-io/` in the project. Approved index rows contain explicit cross-registry routes; consumers only declare the registry containing each direct package.

## License

Apache-2.0.
