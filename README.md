# pkg.re

Security-oriented tooling + policy for curated Rust and JavaScript package registries.

## Purpose

pkg.re builds deterministic,read-only package install planes from reviewed declarations+immutable evidence. The Rust implementation converts exact crates.io mirror versions+immutable first-party Git tags into a Cargo sparse index. The JavaScript implementation validates a closed exact-version catalog+audited archives,then deterministically renders npm-compatible packuments,same-host immutable redirect markers,and first-party content-addressed objects. No mutable registry API,package-manager publish operation,or upstream metadata fallback is authoritative.

Rust removal replaces curator-controlled yanking:delete a version/tag from desired state but retain its package key;reconciliation preserves an irreversible tombstone+source evidence and renders the row as yanked. Target P9 marker publication retains ordinary removed identities so exact historical locks stay cold-installable;emergency route revocation remains a separate explicit operation.

## Public topology

Current Rust production state before the gated P9 migration:

| Cargo alias | Catalog alias | Sparse URL | Sources | Advertised download template |
|---|---|---|---|---|
| `pkgre` | `main` | `sparse+https://rust.pkg.re/` | crates.io mirrors+first-party/fork Git tags | `https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}` |

Target same-host state after the ecosystem-specific publication gates:

| Ecosystem | Static index | Canonical archive route | Runtime route authority |
|---|---|---|---|
| Rust | `github.com/pkgre/rust`→`rust.pkg.re` | `https://rust.pkg.re/v1/<registry>/<crate>/<canonical-semver>/<sha256>` | Exact static marker at the same Pages path |
| JavaScript | `github.com/pkgre/js`→`js.pkg.re` | `https://js.pkg.re/v1/js/<registry>/<sha256>` | Exact static marker at the same Pages path |

Cargo aliases are consumer-local;`main` is the catalog/index identity. Schema 4 remains multi-registry capable:an additional catalog registry such as `staging` renders below `https://rust.pkg.re/r/staging/`,has its own categories/locks/routes,and does not move existing `main` identities.

Current Rust categories:

| Category | Exact `may-depend-on` |
|---|---|
| `main/general` | `main/general` |
| `main/acp` | `main/acp`,`main/general` |
| `main/filesystem` | `main/filesystem`,`main/general` |
| `main/matrix` | `main/general`,`main/matrix` |
| `main/mcp` | `main/general`,`main/mcp`,`main/sse` |
| `main/pkgre` | `main/general`,`main/pkgre` |
| `main/sse` | `main/general`,`main/sse` |
| `main/terminal` | `main/general`,`main/terminal` |
| `main/yaml` | `main/general`,`main/yaml` |

`main/pkgre` currently contains first-party packages+is the default home for new standalone forks. A fork of a name already reserved by a mirrored package stays in that name's existing category;category is dependency policy,not source class. A same-registry patched fork uses a new Cargo version;the locked checksum/source remains immutable for each `name+version`.

## Components

- `rust/`:Rust reconciler,validator,admission planner/applicator,schema migrators,deterministic renderer,download-catalog generator,release verifier.
- `js/`:dependency-free plain-ESM `pkgre-js` catalog/archive validator,deterministic packument+marker renderer,monotonic publication verifier,and isolated npm/Bun/Deno fixture.
- [`docs/js-registry.md`](docs/js-registry.md):JS catalog/archive policy,two-stage publication,consumer configuration,compatibility matrix,bootstrap+activation gate.
- `fixtures/redirect-marker-v1/`:provider-neutral exact marker bytes consumed independently by Rust+JavaScript tests;synthetic routes only.
- [`docs/catalog.md`](docs/catalog.md):current schema-4 Rust declarations,categories,locks,admissions,routing,removal,migration.
- [`docs/production-update-runbook.md`](docs/production-update-runbook.md):standalone production Rust mirror-update procedure ending in an unmerged curator-review PR.
- [`docs/workflows.md`](docs/workflows.md):mirror,Git-tag,removal,migration,release workflows.
- [`docs/security.md`](docs/security.md):trust model,enforced invariants,exclusions.
- [`docs/dynamic-registry-readiness.md`](docs/dynamic-registry-readiness.md):minimal migration basis+phase-local validation policy for native Git-backed Rust/JavaScript serving.
- Production Rust catalog/site:[`pkgre/rust`](https://github.com/pkgre/rust).

## Build

```console
$ nix flake check --print-build-logs
$ nix build .#rust
$ nix build .#js
$ nix run .#rust -- --help
$ nix run .#js -- --help
```

Transitional `.#indexer` aliases `.#rust`.

Pinned semantics:Cargo `1.95.0`;JS index authority=Node `24.15.0`+npm `12.0.2`;compatibility floors=Bun `1.3.14`+Deno `2.9.5`;current snapshots separately pinned;Nix locks build inputs;Cargo+compatibility-client inputs use fixed-output Nix fetches;checks run offline after fetching. GitHub CI runs the full flake on native x86_64+aarch64.

## JavaScript catalog operation

```console
$ pkgre-js check catalog.json archives
$ pkgre-js render-routes catalog.json archives site-current site-routes
$ pkgre-js verify catalog.json site-routes
$ pkgre-js verify-monotonic site-current site-routes
$ pkgre-js render-final catalog.json site-routes site-final
$ pkgre-js verify catalog.json site-final
$ pkgre-js verify-monotonic site-routes site-final
```

The exact 30d catalog+archive policy,atomic filesystem boundary,route-first publication protocol,client matrix,and activation gate are documented in [`docs/js-registry.md`](docs/js-registry.md). Production JS metadata,markers,and objects remain unpublished until the P3/P6 operator gate succeeds;source-only/offline P7 work does not launch `js.pkg.re`.

## Rust catalog operation

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

`update-plan` evaluates current network evidence but emits only a compact,hash-free human manifest containing category/name/exact version. Every nonblocked generated manifest is directly applyable;optional typed evidence may be added. `update-apply` re-fetches+recomputes all facts,then atomically adds declarations,source rows,registry locks,canonical `downloads.json`,and immutable `admissions/<batch>.{toml,lock}`. Package `admission-sha256` fields bind the complete generated batch lock. `lock` handles bootstrap,empty name reservations,removals,Git tags,and download-catalog convergence;it cannot directly add mirror identities to an established catalog.

`registry/` is exclusive managed state:only `<registry>.toml`,generated `<registry>.lock`,canonical `downloads.json`,referenced `categories/<registry>/<category>.toml`,paired admissions,and `objects/` are permitted. Keep transient manifests,inspections,logs,and rendered sites outside it until `update-apply` installs the immutable pair transactionally.

## JavaScript consumer configuration

Project `.npmrc`:

```ini
registry=https://js.pkg.re/
allow-directory=none
allow-file=none
allow-git=none
allow-remote=none
audit=false
fund=false
ignore-scripts=true
replace-registry-host=always
save-exact=true
strict-ssl=true
update-notifier=false
```

Commit the configuration;do not add npmjs scope overrides. Catalog dependencies are exact+recursively closed;consumer lockfiles remain required. Bun+Deno use the same registry endpoint but their security evidence comes from the isolated compatibility fixture rather than an assumption that they implement every npm-specific `.npmrc` key.

## Rust consumer configuration

Every Rust dependency explicitly names the one consumer alias:

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

Create+commit `.cargo/disabled-crates-io/`. Do not use `source.crates-io.replace-with = "pkgre"`:source replacement is local configuration and Cargo can reinterpret crates.io identities when another user lacks it. Explicit `registry = "pkgre"` records the root sparse source in `Cargo.lock` and fails closed when a clone omits the alias configuration.

## License

Apache-2.0.
