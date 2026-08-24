# Catalog schema v3

## Principles

- Human authority: one committed `<registry>.toml` per registry declares fixed settings + categories; each category declares exact dependency policy + desired mirrored versions or immutable first-party Git tags.
- Small/large category ergonomics: a category body may be inline or stored at its exact referenced `categories/<registry>/<category>.toml` path.
- Compact mirror authority: `admissions/<batch>.toml` contains only category/name/exact version or tag + optional typed evidence; generated `admissions/<batch>.lock` contains recomputed machine facts.
- Generated package history: adjacent `<registry>.lock` files permanently bind category/source class, Cargo identity, lifecycle state, hashes, origin provenance, and optional admission-batch hash.
- Declarative convergence: `update-apply` admits mirror batches; `lock` handles bootstrap/removal/Git tags; both stage + validate a complete replacement catalog before atomic installation.
- Irreversible history: old immutable lock fields remain exact; only additions + `active→removed` are valid; removed identities cannot reactivate.
- Explicit routing: every reserved package name has one permanent registry/category home; every dependency edge is rewritten to that registry home + checked against the source category's exact `may-depend-on` set.
- Exact artifacts: crates.io `.crate` bytes are fetched + checksum-verified but not stored; Git-tag packages are reproduced twice with pinned Cargo + retained by content hash.
- Source-aware downloads: Cargo exposes one `dl` URL per registry; a mixed mirror/Git registry must use its exact checksum-bearing immutable-router template, while a single-source registry may retain its fixed source-specific endpoint.

## Managed layout

```text
registry/
├── universe.toml
├── universe.lock
├── pkgre.toml
├── pkgre.lock
├── downloads.json
├── categories/
│   └── universe/
│       ├── general.toml
│       └── matrix.toml
├── admissions/
│   ├── 2026-08-24-routine.toml
│   └── 2026-08-24-routine.lock
└── objects/
    ├── crates/<active-git-archive-sha256>.crate
    └── rows/<source-row-sha256>.json
```

`registry/` is exclusive managed state. Accepted entries: real regular registry `.toml` + adjacent `.lock` files; canonical generated `downloads.json`; exact referenced category files; paired canonical admission `.toml`/`.lock` regular files; exact content-addressed objects. Orphan files/directories, nested admission entries, symlinks, special files, noncanonical content, locks without declarations, missing/extra admission pairs, and unexpected objects fail before network resolution. Keep proposals, transient admission manifests, inspection trees, scripts, logs, and rendered sites outside this directory.

## Human registry/category declarations

Inline mirror category:

```toml
schema = 3

[registry]
name = "universe"
index = "sparse+https://rust.pkg.re/universe/"
download = "https://static.crates.io/crates"
cargo-version = "1.95.0"

[categories.acp]
may-depend-on = ["universe/acp", "universe/general"]

[categories.acp.mirror]
agent-client-protocol = ["2.0.0"]
reserved-package = []
```

External category reference in `universe.toml`:

```toml
[categories.general]
file = "categories/universe/general.toml"
```

Referenced `categories/universe/general.toml`:

```toml
schema = 3
may-depend-on = ["universe/general"]

[mirror]
serde = ["1.0.228", "1.0.229"]
reserved-package = []
```

First-party Git publication category:

```toml
schema = 3

[registry]
name = "pkgre"
index = "sparse+https://rust.pkg.re/pkgre/"
download = "https://rust.pkg.re/crates/{sha256-checksum}.crate"
cargo-version = "1.95.0"

[categories.tooling]
may-depend-on = ["pkgre/tooling", "universe/general"]

[categories.tooling.publish.pkgre-indexer]
git = "https://github.com/pkgre/pkgre"
tags = ["indexer/v0.3.0"]
```

Declaration rules:

- Filename stem = `[registry].name`; schema, aliases, URLs, source-class download, topology, and Cargo version are strict.
- Category identity = `<registry>/<local-category>`; components are lowercase ASCII kebab-case, ≤64 bytes each, start/end alphanumeric, and qualified form contains exactly one `/`.
- Inline category = `may-depend-on` + optional `mirror`/`publish`; external reference = only `file`; external file = `schema`, `may-depend-on`, optional `mirror`/`publish`.
- `[mirror]`: package name → exact SemVer list; current production mirror names live in `universe`; source bytes + row come from crates.io.
- `[publish]`: package name → credential-free HTTPS Git URL + literal tags; current production publishers live in `pkgre`.
- Mirror + publish names may coexist in one registry only when `[registry].download` is exactly `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}`; a single-source registry may instead use its canonical source-specific endpoint.
- Package names are permanent reservations under Cargo ASCII case + `-`/`_` normalization; a name cannot move registry/category or switch source class.
- Retain a removed mirror key with `[]`; retain a removed publisher key, unchanged `git`, with `tags = []`.
- Every canonical category must reserve ≥1 package name; SemVer build metadata does not distinguish Cargo registry identities.

Mixed-source declaration example:

```toml
[registry]
name = "universe"
index = "sparse+https://rust.pkg.re/universe/"
download = "https://dl.rust.pkg.re/v1/universe/{crate}/{version}/{sha256-checksum}"
cargo-version = "1.95.0"

[categories.general]
may-depend-on = ["universe/general"]

[categories.general.mirror]
serde = ["1.0.229"]

[categories.general.publish.example-first-party]
git = "https://github.com/pkgre/example-first-party"
tags = ["v1.0.0"]
```

The router template is registry-bound; copying the `universe` template into `pkgre`, omitting the checksum component, using another hostname/path, or retaining a direct source endpoint for a mixed registry fails locally before resolution/rendering. Existing permanent names still cannot switch source class.

Canonical category policy:

| Category | Exact `may-depend-on` |
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

## Generated registry locks

Canonical mirror package example:

```toml
schema = 3

[registry]
name = "universe"
index = "sparse+https://rust.pkg.re/universe/"
download = "https://static.crates.io/crates"

[[names]]
name = "serde"
category = "general"
source = "mirror"

[[packages]]
name = "serde"
version = "1.0.229"
state = "active"
crate-sha256 = "<64-lowercase-hex>"
source-row-sha256 = "<64-lowercase-hex>"
index-row-sha256 = "<64-lowercase-hex>"
admission-sha256 = "<sha256-of-complete-admission-lock>"

[packages.source]
kind = "crates-io"
```

Git-tag provenance additionally records:

```toml
[packages.source]
kind = "git-tag"
git = "https://github.com/pkgre/pkgre"
tag = "indexer/v0.3.0"
tag-oid = "<full-git-object-id>"
commit = "<full-peeled-commit-id>"
package = "pkgre-indexer"
path = "indexer"
cargo-version = "1.95.0"
```

| Field | Binds |
|---|---|
| `crate-sha256` | Exact `.crate` bytes + Cargo row `cksum`; mirrors re-fetch from crates.io, Git uses retained content-addressed bytes |
| `source-row-sha256` | Exact unrouted crates.io row or deterministic Git-package row |
| `index-row-sha256` | Canonical routed row with `yanked = false`; removal changes only rendered yank state |
| `admission-sha256` | SHA-256 of the complete generated admission-batch `.lock`; all candidates in one batch share it; forbidden on Git identities |

Never hand-edit generated locks. Local load validates canonical form, category/source anchors, provenance, object hashes, source-row identity/checksum, routed-row hash, and exact bidirectional batch↔package coverage before any fetch. Legacy/bootstrap mirror identities may omit `admission-sha256`; ordinary `lock` cannot create another unbound mirror identity once a catalog has any registry lock.

## Generated download catalog

Canonical `registry/downloads.json` is generated from active package locks only:

```json
{
  "schema": 1,
  "routes": [
    {
      "registry": "universe",
      "name": "serde",
      "version": "1.0.229",
      "sha256": "<64-lowercase-hex>",
      "source": "crates-io"
    }
  ]
}
```

Route sort order + identity are strict; name remains case-sensitive; version must be canonical SemVer; source is closed to `crates-io|git-tag`; duplicate `(registry,name,version)`, unknown fields/schema/registry, noncanonical JSON, nonregular file, wrong/extra/missing routes, or >16 MiB fails `Catalog::load`/`check`. `lock` regenerates missing/stale catalog bytes transactionally. `render` writes the exact same active projection to the Pages root. Removed identities are excluded; archive/source-row objects remain governed by their existing retention rules. Destinations are not stored: the service derives one of two hardcoded origins from the closed source enum. Full service/proxy contract: [`download-routing.md`](download-routing.md).

## Human admission manifest

`update-plan` emits a directly applyable compact template outside the catalog:

```toml
schema = 2

[[admit]]
category = "universe/general"
name = "demo"
version = "1.2.3"

[[admit]]
category = "universe/matrix"
name = "matrix-sdk"
version = "0.19.0"
```

The human file intentionally contains no checksum, sparse-row hash, archive analysis, policy snapshot, timestamp, or mutable API observation. Requests are canonical + uniquely ordered. Exact Git tags are representable with `tag = "..."`, but mirror apply currently rejects them explicitly; first-party Git publication uses category declarations + `lock`.

Optional evidence can be added without making it mandatory for merge/apply:

```toml
[[admit.evidence]]
kind = "manual-full-archive"
note = "Reviewed every regular archive member and normalized manifest."
```

or:

```toml
[[admit.evidence]]
kind = "manual-source-delta"
base = "1.2.2"
note = "Reviewed the complete archive delta from 1.2.2."
```

Evidence notes are nonempty trimmed UTF-8 ≤16 KiB; entries are canonical + unique. `manual-source-delta` must name the exact base recomputed at apply and requires a complete archive delta. Protected source-control review of the full registry PR remains the authorization boundary; typed evidence is supplemental and supports later integrations such as cargo-vet.

## Generated admission lock

`update-apply` creates `admissions/<batch>.lock` beside the exact human manifest. It contains:

- lock schema + SHA-256 of canonical adjacent human manifest;
- admission UTC time;
- complete fresh network-backed plan: indexer version, catalog fingerprint, evaluation time, positive policy thresholds, exact candidates, sparse/history hashes, base/candidate row + archive hashes, bounded archive analyses/deltas, dependency delta, API/source evidence, decision + reasons;
- exact copied human requests + optional evidence.

The complete canonical `.lock` byte string is hashed. Every resulting package lock receives that hash in `admission-sha256`; one batch therefore binds many package identities without one file per crate. Validation builds indexed identity maps, validates each batch once, rejects duplicate/orphan coverage, and requires each candidate's immutable route/version/archive/source-row facts + batch hash to equal its package lock. Historical locks validate their recorded positive policy thresholds rather than silently adopting a future binary's constants.

Admission pairs are immutable. Reapplying the identical already-installed filename/content validates the catalog + returns a no-op. Reusing a filename with different content, deleting/tampering either file, adding an orphan, or changing a package binding fails ordinary `Catalog::load`/`check`.

## Mirror admission lifecycle

1. `update-plan <catalog> <new-manifest>` scans active mirror compatibility lanes, evaluates all current evidence, excludes blocked candidates, and writes the compact manifest only after proving catalog stability.
2. Reviewer may remove requests, inspect selected requests with `update-inspect`, or add optional evidence. Any edited manifest must remain canonical.
3. `update-apply <catalog> <manifest>` validates the human file, re-fetches exact current sparse/API/archive/source facts for every request, rejects young/yanked/blocked/route-invalid/evidence-invalid identities, and computes one generated batch lock.
4. A guarded transaction checks the starting catalog fingerprint, appends exact requested versions, installs the immutable pair, reconciles exact mirror identities with the shared batch hash, strictly reloads + renders staging, then atomically installs it.
5. A second `lock` must be an exact no-op; `check`, `render`, `verify`, and `verify-monotonic` validate publication.

Planning facts are intentionally not authority: there is no stale machine-plan file to approve. Apply always recomputes at its own current UTC time, so the 30-day minimum age and all current upstream facts are checked immediately before mutation. The compact manifest may be carried/reviewed without an expiry clock; route/catalog drift is detected during apply.

## Mirror materialization

For each selected/admitted mirror identity, the indexer fetches the complete sparse history + exact `.crate` over HTTPS, selects exactly one matching row, rejects upstream-yanked/young/malformed identities, validates Cargo metadata, and requires archive SHA-256 = row `cksum`. Planning/apply also analyze bounded archive/dependency/API/source evidence. The exact selected row including trailing newline becomes a retained content-addressed object; verified archive bytes are discarded. Cargo later reaches `https://static.crates.io/crates/<name>/<version>/download` directly or through the immutable router and validates against the curated row checksum; crates.io controls availability, not accepted metadata/integrity.

## Reconciliation

`pkgre-indexer lock registry` is the direct declarative reconciler. In an established catalog it may reserve empty names, materialize new Git tags, and remove active identities, but cannot admit a new mirror identity.

1. Acquire sibling guard `.registry.pkgre-lock`; concurrent/stale guard fails closed.
2. Load declarations, generated registry locks, admissions, categories, and objects; validate complete local invariants.
3. Resolve only permitted absent desired identities: all source classes during initial no-lock bootstrap, or declared Git tags in an established catalog. A direct new mirror fails before resolution; updater reconciliation requires exact supplied admission descriptors backed by the newly installed batch.
4. Route dependencies against permanent homes; reject missing homes or forbidden category edges.
5. Generate canonical locks; preserve old entries; mark no-longer-desired active entries `removed`.
6. Build a complete sibling staging catalog; retain all source rows; retain archives used by ≥1 active Git identity; omit all mirror archives + unshared removed Git archives.
7. Regenerate canonical `downloads.json`; strictly reload, object-verify, and test-render staging.
8. Install by same-parent rename with rollback + sync; remove guard.

Unchanged second reconciliation = exact no-op. A crash can leave `.registry.pkgre-lock`; remove it only after confirming no reconciliation is active. Staging/backup siblings use `.registry.pkgre-*` names and are recovery state, not catalog entries.

## First-party Git-tag materialization

For each new publish tag, package version/path/tag object/peeled commit are discovered + locked rather than supplied in TOML. Preconditions:

- Tag final component = package version or `v<version>`; e.g. `indexer/v0.3.0` for `0.3.0`.
- Tagged workspace contains exactly one selected package name; manifest declares exactly `publish = ["pkgre"]`.
- Every dependency, including optional/dev/build/target-specific, explicitly names registry `universe` or `pkgre`; path/Git/crates.io/unknown sources fail.
- Checkout has no submodules, symlinks, special files, unsafe paths, manifest mismatch, or dirty generated changes.
- Pinned Cargo: absolute `PKGRE_CARGO` when set, otherwise `rustup which --toolchain <cargo-version> cargo`; exact reported version required.
- `cargo metadata --no-deps --locked` runs in an isolated Cargo home with crates.io replaced by an empty directory.
- `cargo package --no-verify --locked` runs twice with distinct targets; archives must be byte-identical.

Generated source row + archive are retained; package identity/version/path, tag object, peeled commit, Cargo version, archive hash, source-row hash, and routed-row hash become permanent.

## Routing + rendering

For every dependency:

```text
identity = dependency.package ?? dependency.name
home = permanent home[identity]                       # required registry + category
permit(source.category, home.category)                # exact category edge required
registry = null                                       # same registry
registry = canonical sparse URL for home.registry     # cross-registry
```

Routing covers normal/dev/build/optional/target-specific + renamed dependencies, overwrites source-row registry values, and rejects edges outside category policy. Unknown top-level row fields are retained; malformed known fields fail. Active routed rows are hashed permanently; removed rows reuse routed content with only `yanked = true`.

Rendered output:

```text
site/
├── .nojekyll
├── CNAME
├── release.json
├── downloads.json
├── universe/config.json
├── pkgre/config.json
├── <registry>/<Cargo sparse-index package paths>
└── crates/<active-git-archive-sha256>.crate
```

`release.json` schema 3 records exact topology, permanent name category/source anchors, and package identities. Top-level `downloads.json` is the exact active-package route projection. Schema-3→3 `verify-monotonic` requires topology + anchors + immutable fields unchanged, authenticates the route projection, permits additions + `active→removed` + source-specific→exact-router `dl` migration, and forbids arbitrary download endpoints.

## Exact schema-2→3 migration

```console
$ pkgre-indexer migrate-v2-to-v3 registry-v2 registry-v3
```

Source must be a strict canonical schema-2 `core`/`matrix`/`pkgre` catalog; destination must not exist. Migration verifies complete inventory/locks/objects/rows/hashes, maps `matrix/*→universe/matrix`, `pkgre/pkgre-indexer→pkgre/tooling`, selected `core` families to canonical categories, and remaining `core/*→universe/general`. It copies source rows + retained Git archives byte-for-byte, recomputes category-aware routed hashes, rejects forbidden edges/unmappable names, strictly reloads + renders + reproduces staging, then installs by one rename. Source is never modified.

## Removal

1. Delete exact version/tag from desired list; retain package key in original category.
2. Run `lock`; permanent package state changes only `active→removed`.
3. Source-row evidence remains; mirror archives were never retained; unshared Git archive disappears.
4. Rendered row remains with `yanked = true`.
5. Re-adding identity fails permanently; publish/admit a new version instead.
