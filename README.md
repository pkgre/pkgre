# pkg.re

Security-oriented tooling + policy for curated Rust and JavaScript package registries.

## Purpose

pkg.re builds deterministic,read-only package install planes from reviewed declarations+immutable evidence. The Rust implementation converts exact crates.io mirror versions+immutable first-party Git tags into a Cargo sparse index. The JavaScript implementation is currently a dependency-free skeleton;P7 will add the minimal self-hosting npm-compatible catalog. No mutable registry API or package-manager publish operation is authoritative.

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

`pkgre-proxy` converts an exact validated marker into a fresh `307`;it has no route catalog,GitHub API/raw lookup,mutable database,or last-known-good route table. It resolves only `pkgre.github.io`,connects to validated public answers,and keeps URL/TLS SNI/certificate verification/HTTP Host fixed to the route-selected `rust.pkg.re` or `js.pkg.re`. No `dl.js.pkg.re` is planned. `dl.rust.pkg.re` remains the current production+rollback endpoint until P9 publishes same-host Rust metadata and a later retirement gate is met.

Cargo aliases are consumer-local;`main` is the catalog/index identity. Schema 4 remains multi-registry capable:an additional catalog registry such as `staging` renders below `https://rust.pkg.re/staging/`,has its own categories/locks/routes,and does not move existing `main` identities.

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
- `rust/proxy/`:cross-ecosystem static-marker translator+fixed GitHub Pages custom-host origin adapter;closed Rust/JS routes and destinations only.
- `js/`:dependency-free plain-ESM `pkgre-js` indexer skeleton with built-in Node tests.
- `fixtures/redirect-marker-v1/`:provider-neutral exact marker bytes consumed independently by Rust+JavaScript tests;synthetic routes only.
- [`docs/catalog.md`](docs/catalog.md):current schema-4 Rust declarations,categories,locks,admissions,routing,removal,migration.
- [`docs/download-routing.md`](docs/download-routing.md):same-host marker wire contract,origin adapter,proxy boundary,publication+migration rules.
- [`docs/production-update-runbook.md`](docs/production-update-runbook.md):standalone production Rust mirror-update procedure ending in an unmerged curator-review PR.
- [`docs/workflows.md`](docs/workflows.md):mirror,Git-tag,removal,migration,release workflows.
- [`docs/security.md`](docs/security.md):trust model,enforced invariants,exclusions.
- Production Rust catalog/site:[`pkgre/rust`](https://github.com/pkgre/rust).

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

## Proxy operation

```console
$ pkgre-proxy --listen 127.0.0.1:3000 --canary-seconds 60 --readiness-seconds 180
```

Local endpoints:`/healthz`=process/config health;`/readyz`=both fixed origin canaries succeeded within the readiness window;`/metrics`=bounded-label Prometheus text. A transient failed canary is reported in metrics but does not revoke readiness until the last success expires. These local signals do not replace the separately gated isolated long-term certificate/contract monitoring design.

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

## Consumer configuration

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
