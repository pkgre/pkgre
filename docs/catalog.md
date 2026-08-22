# Catalog schema v1

## Principles

- Declarative convergence: committed catalog = complete desired registry state; no mutable registry API or `cargo publish` operation.
- Exact approval identity: `(registry,name,version,archive_sha256,index_record_sha256,immutable source)`.
- Explicit routing: every package name referenced by any approved row has exactly one home; no implicit fallback to `core` or crates.io.
- Exact artifacts: imported crates.io `.crate` bytes + selected un-routed sparse-index row are retained unchanged; first-party artifacts are reproduced from an immutable Git tag/commit with pinned Cargo.
- Deterministic output: one catalog + one artifact map → one byte-identical three-registry site.

## Layout

```text
catalog/
├── registries.toml
├── homes.toml
├── approvals/
│   ├── core.toml
│   ├── matrix.toml
│   └── pkgre.toml
└── upstream/
    ├── core/<cargo-index-path>/<version>.json
    └── matrix/<cargo-index-path>/<version>.json
artifacts/
├── artifacts.toml
├── archives/<archive-sha256>.crate
└── records/<index-record-sha256>.json
```

Approval files may be split into any number of `.toml` files; every direct child of `approvals/` must be a real regular `.toml` file. Artifact paths are relative to `artifacts.toml`; crates.io snapshot paths are relative to the catalog root. Symlinks + special files are rejected at trust boundaries.

## `registries.toml`

The topology is policy-frozen in schema v1:

```toml
schema = 1
cname = "rust.pkg.re"
download = "https://rust.pkg.re/crates/{sha256-checksum}.crate"
cargo-version = "1.95.0"

[[registries]]
name = "core"
index = "sparse+https://rust.pkg.re/core/"
may-depend-on = ["core"]

[[registries]]
name = "matrix"
index = "sparse+https://rust.pkg.re/matrix/"
may-depend-on = ["core", "matrix"]

[[registries]]
name = "pkgre"
index = "sparse+https://rust.pkg.re/pkgre/"
may-depend-on = ["core", "matrix", "pkgre"]
```

## `homes.toml`

One explicit registry per package name, including dependencies referenced only by optional/dev/build/target-specific edges:

```toml
schema = 1

[homes]
anyhow = "core"
matrix-sdk = "matrix"
pkgre-indexer = "pkgre"
serde = "core"
```

Rules: names are ASCII Cargo package names; comparison rejects global ASCII-case + `-`/`_` normalization collisions; every approval must match its home; every dependency identity must have a home. For renamed dependencies, routing uses Cargo's `package` identity rather than the local alias in `name`.

## Approval: crates.io import

```toml
schema = 1
registry = "core"

[[packages]]
name = "serde"
version = "1.0.229"
archive_sha256 = "<64 lowercase hex>"
index_record_sha256 = "<64 lowercase hex>"
yanked = false
source = { kind = "crates-io", index_record = "upstream/core/se/rd/serde/1.0.229.json" }
```

`archive_sha256` must equal upstream row `cksum`. `index_record_sha256` binds the exact selected un-routed crates.io row. Build metadata does not distinguish registry versions. The same snapshot path cannot back multiple approvals.

## Approval: first-party Git tag

```toml
schema = 1
registry = "pkgre"

[[packages]]
name = "pkgre-indexer"
version = "0.1.0"
archive_sha256 = "<64 lowercase hex>"
index_record_sha256 = "<64 lowercase hex>"
yanked = false

[packages.source]
kind = "git-tag"
repository = "https://github.com/pkgre/pkgre"
tag = "indexer/v0.1.0"
commit = "<full lowercase peeled commit object ID>"
package = "pkgre-indexer"
subdir = "indexer"
```

Only `pkgre` accepts Git-tag sources; only `core`/`matrix` accept crates.io imports. Repository URL must be credential-free HTTPS. Tag + full peeled commit are both bound. Workspace package must equal approved name, manifest version must equal approved version, and manifest must declare exactly `publish = ["pkgre"]`.

## `artifacts.toml`

```toml
schema = 1

[[artifacts]]
registry = "core"
name = "serde"
version = "1.0.229"
archive = "archives/<archive-sha256>.crate"
index_record = "records/<index-record-sha256>.json"
```

The map is one-to-one with approvals: missing + extra entries fail. Every archive/row is rehashed; row name/version/checksum/known Cargo fields are validated. A crates.io row must also byte-match its catalog snapshot.

## Rendering

For each un-routed dependency row:

```text
identity = dependency.package ?? dependency.name
home = homes[identity]                        # required
registry = null                               # same home
registry = canonical sparse URL for home      # cross-home
```

Every edge must satisfy source registry `may-depend-on`. Renderer changes only dependency `registry` fields + curator-owned `yanked`, then serializes compact JSON lines sorted by semantic version. Unknown top-level row fields are retained; malformed known fields fail.

Output:

```text
site/
├── .nojekyll
├── CNAME
├── release.json
├── core/config.json
├── matrix/config.json
├── pkgre/config.json
├── <registry>/<Cargo sparse-index package paths>
└── crates/<archive-sha256>.crate
```

`release.json` is the deployment/immutability manifest. Monotonic verification permits new identities + `yanked` changes; rejects removal or mutation of any prior registry/name/version/archive hash/row hash/source.
