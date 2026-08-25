# pkg.re

Declarative tooling + policy for a curated Cargo sparse registry.

## Purpose

pkg.re converts human registry/category declarations into deterministic sparse indexes. Human TOML declares exact crates.io mirror versions + immutable first-party Git tags; compact admission manifests authorize mirror batches; generated locks retain machine-verifiable evidence. Mirror archives are fetched + checksum-verified but served by crates.io rather than retained. No mutable registry API or `cargo publish` operation is authoritative.

Removal replaces curator-controlled yanking:delete a version/tag from desired state but retain its package key; reconciliation preserves an irreversible tombstone + source evidence and renders the row as yanked.

## Production topology

One Cargo registry:

| Cargo alias | Catalog alias | Sparse URL | Sources | Download template |
|---|---|---|---|---|
| `pkgre` | `main` | `sparse+https://rust.pkg.re/` | crates.io mirrors + first-party/fork Git tags | `https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}` |

Cargo aliases are consumer-local; `main` is the catalog/index identity. Schema 4 remains multi-registry capable:an additional catalog registry such as `staging` renders below `https://rust.pkg.re/staging/`, has its own categories/locks/routes, and does not move existing `main` identities.

Current categories:

| Category | Exact `may-depend-on` |
|---|---|
| `main/general` | `main/general` |
| `main/acp` | `main/acp`, `main/general` |
| `main/filesystem` | `main/filesystem`, `main/general` |
| `main/matrix` | `main/general`, `main/matrix` |
| `main/mcp` | `main/general`, `main/mcp`, `main/sse` |
| `main/pkgre` | `main/general`, `main/pkgre` |
| `main/sse` | `main/general`, `main/sse` |
| `main/terminal` | `main/general`, `main/terminal` |
| `main/yaml` | `main/general`, `main/yaml` |

`main/pkgre` currently contains first-party packages + is the default home for new standalone forks. A fork of a name already reserved by a mirrored package stays in that name's existing category; category is dependency policy, not source class. A same-registry patched fork uses a new Cargo version; the locked checksum/source remains immutable for each `name + version`.

## Components

- `rust/`:Rust reconciler, validator, admission planner/applicator, schema migrators, deterministic renderer, download-catalog generator, release verifier.
- `rust/proxy/`:stateless exact-route service; fetches a commit-pinned generated catalog and returns only hardcoded crates.io/content-addressed redirects.
- `js/`:dependency-free plain-ESM `pkgre-js` indexer skeleton with built-in Node tests.
- [`docs/catalog.md`](docs/catalog.md):schema-4 declarations, inline/external categories, locks, admissions, routing, removal, exact migration.
- [`docs/download-routing.md`](docs/download-routing.md):router wire contract, fetch/refresh/LKG semantics, proxy boundary, deployment + rollback.
- [`docs/production-update-runbook.md`](docs/production-update-runbook.md):standalone production mirror-update procedure ending in an unmerged curator-review PR.
- [`docs/workflows.md`](docs/workflows.md):mirror, Git-tag, removal, migration, release workflows.
- [`docs/security.md`](docs/security.md):trust model, enforced invariants, exclusions.
- Production catalog/site:[`pkgre/rust`](https://github.com/pkgre/rust).

## Build

```console
$ nix flake check --print-build-logs
$ nix build .#rust
$ nix build .#js
$ nix build .#proxy
$ nix run .#rust -- --help
$ nix run .#js -- --help
$ nix run .#proxy -- --help
```

Transitional `.#indexer` aliases `.#rust`;`.#download-serve` aliases `.#proxy` through the deployment rollback horizon.

Pinned semantics:Cargo `1.95.0`;Node 24;JS minimum metadata Node `24.15.0`+npm `12.0.2`;Nix locks build inputs;Cargo inputs become fixed-output Nix fetches;Rust+JS checks run offline after fetching.

## Catalog operation

```console
$ pkgre-rust update-plan registry batch-name.toml
$ pkgre-rust update-plan-exact registry <package> <version> batch-name.toml
$ pkgre-rust update-inspect registry batch-name.toml <package> <version> review
$ pkgre-rust update-apply registry batch-name.toml
$ pkgre-rust lock registry
$ pkgre-rust check registry
$ pkgre-rust render registry site-next
$ pkgre-rust verify registry site-next
$ pkgre-rust verify-monotonic site-current site-next
$ pkgre-rust migrate-v2-to-v3 registry-v2 registry-v3
$ pkgre-rust migrate-v3-to-v4 registry-v3 registry-v4
```

`update-plan` evaluates current network evidence but emits only a compact, hash-free human manifest containing category/name/exact version. Every nonblocked generated manifest is directly applyable; optional typed evidence may be added. `update-apply` re-fetches + recomputes all facts, then atomically adds declarations, source rows, registry locks, canonical `downloads.json`, and immutable `admissions/<batch>.{toml,lock}`. Package `admission-sha256` fields bind the complete generated batch lock. `lock` handles bootstrap, empty name reservations, removals, Git tags, and download-catalog convergence; it cannot directly add mirror identities to an established catalog.

`registry/` is exclusive managed state:only `<registry>.toml`, generated `<registry>.lock`, canonical `downloads.json`, referenced `categories/<registry>/<category>.toml`, paired admissions, and `objects/` are permitted. Keep transient manifests, inspections, logs, and rendered sites outside it until `update-apply` installs the immutable pair transactionally.

## Consumer configuration

Every dependency explicitly names the one consumer alias:

```toml
[dependencies]
serde = { version = "=1.0.229", registry = "pkgre" }
matrix-sdk = { version = "=0.18.0", registry = "pkgre" }
pkgre-rust = { version = "=0.5.0", registry = "pkgre" }
```

Project `.cargo/config.toml`:

```toml
[registries.pkgre]
index = "sparse+https://rust.pkg.re/"

[registry]
default = "pkgre"

[source.crates-io]
replace-with = "disabled-crates-io"

[source.disabled-crates-io]
directory = ".cargo/disabled-crates-io"
```

Create + commit `.cargo/disabled-crates-io/`. Do not use `source.crates-io.replace-with = "pkgre"`:source replacement is local configuration and Cargo can reinterpret crates.io identities when another user lacks it. Explicit `registry = "pkgre"` records the root sparse source in `Cargo.lock` and fails closed when a clone omits the alias configuration.

## License

Apache-2.0.
