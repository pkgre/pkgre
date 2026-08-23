# Catalog schema v2

## Principles

- Human authority: one committed `<registry>.toml` per registry declares exact desired mirrored versions + immutable first-party Git tags; no imperative publish API.
- Generated evidence: adjacent canonical `<registry>.lock` permanently binds package home/source class, Cargo identity, lifecycle state, exact artifact hashes, and origin provenance.
- Declarative convergence: `pkgre-indexer lock` resolves only new desired identities, then transactionally makes locks + objects equal the declaration/history.
- Irreversible history: existing immutable lock fields are preserved; only additions + `active→removed` are valid; removed identities cannot reactivate.
- Explicit routing: every reserved package name has one permanent registry home; every dependency edge is rewritten to that home + checked against the fixed layer policy.
- Exact artifacts: mirrored `.crate` bytes are fetched + checksum-verified against the retained exact crates.io row but not stored; Git-tag packages are reproduced twice with pinned Cargo + retained by content hash.

## Managed layout

```text
registry/
├── core.toml
├── core.lock
├── matrix.toml
├── matrix.lock
├── pkgre.toml
├── pkgre.lock
└── objects/
    ├── crates/<active-git-archive-sha256>.crate
    └── rows/<source-row-sha256>.json
```

`registry/` is exclusive indexer-managed state: only real regular registry `.toml` files, adjacent real regular `.lock` files, and the real `objects/` directory are accepted. Orphan locks, unrelated files/directories, symlinks, and special files fail before network resolution. Keep proposals, review notes, scripts, and rendered sites outside this directory.

## Human registry file

```toml
schema = 2

[registry]
name = "core"
index = "sparse+https://rust.pkg.re/core/"
download = "https://static.crates.io/crates"
may-depend-on = ["core"]
cargo-version = "1.95.0"

[mirror]
serde = ["1.0.228", "1.0.229"]
reserved-package = []
```

First-party declaration:

```toml
schema = 2

[registry]
name = "pkgre"
index = "sparse+https://rust.pkg.re/pkgre/"
download = "https://rust.pkg.re/crates/{sha256-checksum}.crate"
may-depend-on = ["core", "matrix", "pkgre"]
cargo-version = "1.95.0"

[publish.pkgre-indexer]
git = "https://github.com/pkgre/pkgre"
tags = ["indexer/v0.2.0"]
```

Rules:

- Filename stem must equal `[registry].name`; schema, fields, aliases, URLs, source-class download, layer policy, and Cargo version are strict.
- Fixed topology: `core→core`; `matrix→core|matrix`; `pkgre→core|matrix|pkgre`.
- `[mirror]`: map package name → exact semver list; accepted only in `core`/`matrix`; bytes come from crates.io.
- `[publish]`: map package name → credential-free HTTPS Git URL + literal tag list; accepted only in `pkgre`.
- One registry is mirror-only or publish-only, including empty permanent name anchors; mixing classes fails because Cargo provides one index-wide `dl` URL.
- Package names are permanent reservations under Cargo ASCII case + `-`/`_` normalization; a name cannot move registries or switch `mirror`/`publish` source class.
- Retain a removed mirror key with `[]`; retain a removed publisher key, unchanged `git`, with `tags = []`.
- Build metadata does not distinguish Cargo registry version identities.

## Generated lock

Canonical lock shape:

```toml
schema = 2

[registry]
name = "core"
index = "sparse+https://rust.pkg.re/core/"
download = "https://static.crates.io/crates"

[[names]]
name = "serde"
source = "mirror"

[[packages]]
name = "serde"
version = "1.0.229"
state = "active"
crate-sha256 = "<64 lowercase hex>"
source-row-sha256 = "<64 lowercase hex>"
index-row-sha256 = "<64 lowercase hex>"

[packages.source]
kind = "crates-io"
```

Git-tag provenance additionally records:

```toml
[packages.source]
kind = "git-tag"
git = "https://github.com/pkgre/pkgre"
tag = "indexer/v0.2.0"
tag-oid = "<full Git object ID>"
commit = "<full peeled commit object ID>"
package = "pkgre-indexer"
path = "indexer"
cargo-version = "1.95.0"
```

Hash meanings:

| Field | Binds |
|---|---|
| `crate-sha256` | exact `.crate` archive bytes + Cargo row `cksum`; mirror bytes are re-fetched from crates.io, Git bytes use the retained content-addressed object |
| `source-row-sha256` | exact un-routed crates.io row or deterministically generated Git-package row |
| `index-row-sha256` | canonical routed row with `yanked = false`; removal does not alter this immutable active-row identity |

Locks are generated artifacts: never hand-edit them. Reconciliation copies every prior immutable package entry verbatim except the one-way state transition; local preflight verifies canonical form, provenance shape, object hashes, source-row identity/checksum, and routed-row hash before any fetch. Source control review + `verify-monotonic` bind updates to already deployed history.

## Reconciliation

`pkgre-indexer lock registry`:

1. Acquire sibling guard `.registry.pkgre-lock`; concurrent or stale guard fails closed.
2. Load human files + optional locks; validate all old anchors, tombstones, topology, root entries, retained objects, source rows, and routed rows locally.
3. Resolve only desired identities absent from permanent history: exact crates.io version or declared Git tag.
4. Route dependency rows against permanent package homes; reject missing homes or forbidden registry-layer edges.
5. Generate next canonical locks; preserve old entries; mark no-longer-desired active entries `removed`.
6. Build complete sibling staging catalog; retain every source-row object; retain archive objects used by ≥1 active Git-tag identity; omit all mirror archives + unshared removed Git archives.
7. Strictly reload, object-verify, and test-render staging.
8. Install by same-parent rename with rollback; sync files/directories; remove guard.

A successful second run with unchanged declarations is an exact no-op. A process crash can leave `.registry.pkgre-lock`; after confirming no reconciliation is active, remove that guard manually before retrying. Staging/backup siblings use `.registry.pkgre-*` names and are not valid catalog entries.

## Mirror materialization

For each new `[mirror]` identity, the resolver fetches `https://index.crates.io/<Cargo index path>` + `https://static.crates.io/crates/<name>/<name>-<version>.crate` over HTTPS, selects exactly one matching sparse row, rejects upstream-yanked rows, validates known Cargo metadata, and requires archive SHA-256 = row `cksum`. The exact selected row including trailing newline becomes a retained content-addressed object; archive bytes are verified then discarded. Cargo later downloads through `https://static.crates.io/crates/<name>/<version>/download` + validates those bytes against the curated row `cksum`; crates.io controls availability, not accepted metadata or integrity.

## First-party Git-tag materialization

For each new `[publish]` tag, package version/path/tag object/peeled commit are discovered and locked rather than supplied by human TOML. Preconditions:

- Tag final component equals package version or `v<version>`; e.g. `indexer/v0.2.0` for version `0.2.0`.
- Tagged workspace contains exactly one selected package name; its manifest declares exactly `publish = ["pkgre"]`.
- Every dependency, including optional/dev/build/target-specific dependencies, explicitly names canonical registry `core`, `matrix`, or `pkgre`; path/Git/crates.io/unknown sources fail.
- Checkout has no submodules, symlinks, special files, unsafe paths, manifest mismatch, or dirty generated changes.
- Pinned Cargo selection: absolute `PKGRE_CARGO` when present, otherwise `rustup which --toolchain <cargo-version> cargo`; exact `cargo <version> ...` prefix required.
- `cargo metadata --no-deps --locked` runs in an isolated Cargo home with crates.io replaced by an empty directory.
- `cargo package --no-verify --locked` runs twice with distinct targets; archives must be byte-identical.

The generated source row records normalized package metadata; package identity/version/path, tag object, peeled commit, Cargo version, archive hash, source-row hash, and routed-row hash become permanent.

## Routing + rendering

For each dependency:

```text
identity = dependency.package ?? dependency.name
home = permanent home[identity]                 # required
registry = null                                 # same home
registry = canonical sparse URL for home        # cross-home
```

Routing covers normal/dev/build/optional/target-specific and renamed dependencies, overwrites any source-row registry value, and rejects an edge outside the source registry's allowed layers. Unknown top-level row fields are retained; malformed known fields fail. Active routed rows are hashed permanently; a removed row reuses the same routed content with only `yanked = true`.

Rendered output:

```text
site/
├── .nojekyll
├── CNAME
├── release.json
├── core/config.json
├── matrix/config.json
├── pkgre/config.json
├── <registry>/<Cargo sparse-index package paths>
└── crates/<active-git-archive-sha256>.crate
```

`core/config.json` + `matrix/config.json` use `https://static.crates.io/crates`; `pkgre/config.json` uses the content-addressed pkg.re template. `release.json` schema 2 records download per registry. `verify-monotonic` permits the one-time schema-1 global-template migration, then requires downloads + topology immutable; it permits new identities + `active→removed` while forbidding package disappearance, immutable mutation, and `removed→active`.

## Removal

Removal is not mutable curator yanking:

1. Delete the version/tag from its desired list; keep the package key.
2. Run `lock`; the permanent lock entry changes only `state = "active"` → `state = "removed"`.
3. Source-row evidence remains in `objects/rows/`; mirror archives were never retained; a Git archive disappears from `objects/crates/` unless another active Git identity has the same content hash.
4. Rendered index row remains as `yanked = true`; no Git archive is served for that identity unless shared by active Git content; crates.io may still retain mirror bytes independently.
5. Re-adding the version/tag fails permanently; publish a new version/tag instead.
