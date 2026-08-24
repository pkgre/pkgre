# pkg.re

Declarative tooling + policy for small curated Cargo registries.

## Purpose

pkg.re converts human registry/category declarations into deterministic Cargo sparse registries. Human TOML declares exact crates.io mirror versions + immutable first-party Git tags; compact admission manifests authorize mirror batches; generated locks retain machine-verifiable evidence. Mirror archives are fetched + checksum-verified but served by crates.io rather than retained. No mutable registry API or `cargo publish` operation is authoritative.

Removal replaces curator-controlled yanking: delete a version/tag from desired state but retain its package key; reconciliation preserves an irreversible tombstone + source evidence and renders the retained row as yanked.

Current registry topology:

| Alias | URL | Current package sources | Immutable router template |
|---|---|---|---|
| `universe` | `sparse+https://rust.pkg.re/universe/` | crates.io mirrors | `https://dl.rust.pkg.re/v1/universe/{crate}/{version}/{sha256-checksum}` |
| `pkgre` | `sparse+https://rust.pkg.re/pkgre/` | first-party pkg.re Git-tag packages | `https://dl.rust.pkg.re/v1/pkgre/{crate}/{version}/{sha256-checksum}` |

Cargo provides one index-wide `dl` URL. A single-source registry may use its source-specific endpoint (`https://static.crates.io/crates` or `https://rust.pkg.re/crates/{sha256-checksum}.crate`); a mixed mirror/Git registry must use its exact registry-bound immutable router. The generated checksum-bearing route catalog makes mixed operation safe without storing crates.io archives. Category policy remains finer-grained than Cargo registries:

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

- `indexer/`: Rust reconciler, validator, mirror admission planner/applicator, schema-2→3 migrator, deterministic renderer, download-catalog generator, release verifier.
- `download-serve/`: stateless exact-route service; fetches a commit-pinned generated catalog and returns only hardcoded crates.io/content-addressed redirects.
- [`docs/catalog.md`](docs/catalog.md): schema-3 declarations, inline/external categories, generated locks/catalogs, admission batches, objects, routing, removal.
- [`docs/download-routing.md`](docs/download-routing.md): router wire contract, fetch/refresh/LKG semantics, reverse-proxy boundary, deployment + rollback.
- [`docs/production-update-runbook.md`](docs/production-update-runbook.md): standalone production mirror-update procedure from deployed-pin selection through an unmerged curator-review PR.
- [`docs/workflows.md`](docs/workflows.md): mirror, Git-tag, removal, migration, release workflows.
- [`docs/security.md`](docs/security.md): trust model, enforced invariants, exclusions.
- Production catalog/site: [`pkgre/rust`](https://github.com/pkgre/rust).

## Build

```console
$ nix flake check --print-build-logs
$ nix build .#indexer
$ nix build .#download-serve
$ nix run .#indexer -- --help
$ nix run .#download-serve -- --help
```

Pinned build semantics: Cargo `1.95.0`; Nix locks Rust + build inputs; Cargo inputs become fixed-output Nix fetches; checks build/test/lint offline after fetching.

## Catalog operation

```console
$ pkgre-indexer update-plan registry batch-name.toml
$ pkgre-indexer update-plan-exact registry <package> <version> batch-name.toml
$ pkgre-indexer update-inspect registry batch-name.toml <package> <version> review
$ pkgre-indexer update-apply registry batch-name.toml
$ pkgre-indexer lock registry
$ pkgre-indexer check registry
$ pkgre-indexer render registry site-next
$ pkgre-indexer verify registry site-next
$ pkgre-indexer verify-monotonic site-current site-next
$ pkgre-indexer migrate-v2-to-v3 registry-v2 registry-v3
```

`update-plan` performs current network-backed evaluation but emits only a compact, hash-free human manifest containing category/name/exact version. Every nonblocked generated manifest is directly applyable; optional typed review evidence may be added. `update-apply` re-fetches + recomputes all machine facts, then atomically adds declarations, source rows, registry locks, canonical `downloads.json`, and an immutable `admissions/<batch>.toml` + generated `admissions/<batch>.lock` pair. Package `admission-sha256` fields bind the complete generated batch lock. `lock` handles bootstrap, empty name reservations, removals, Git tags, and download-catalog convergence; it cannot directly add mirror identities to an established catalog.

`registry/` is exclusive managed state: only `<registry>.toml`, generated `<registry>.lock`, canonical generated `downloads.json`, referenced `categories/<registry>/<category>.toml`, paired `admissions/<batch>.{toml,lock}`, and `objects/` are permitted. Keep transient manifests, inspection trees, logs, and rendered sites outside it until `update-apply` installs the immutable admission pair transactionally.

## Consumer configuration

Project manifests name alternate registries explicitly; categories do not create Cargo aliases:

```toml
[dependencies]
serde = { version = "=1.0.229", registry = "universe" }
matrix-sdk = { version = "=0.18.0", registry = "universe" }
pkgre-indexer = { version = "=0.4.0", registry = "pkgre" }
```

Project `.cargo/config.toml` defines aliases and disables implicit crates.io index access:

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

Create `.cargo/disabled-crates-io/` in the project. Curated index rows contain explicit cross-registry routes; consumers declare only the registry containing each direct package.

## License

Apache-2.0.
