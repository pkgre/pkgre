# Catalog schema v4

## Principles

- Human authority:one committed `<registry>.toml` per catalog registry declares fixed settings + categories; each category declares exact direct-dependency policy + desired crates.io versions or immutable Git tags.
- Root-main convention:catalog registry `main` renders at `sparse+https://rust.pkg.re/`; another alias `<name>` renders at `sparse+https://rust.pkg.re/<name>/`.
- Small/large category ergonomics:a category body may be inline or stored at its exact referenced `categories/<registry>/<category>.toml` path.
- Compact mirror authority:`admissions/<batch>.toml` contains category/name/exact version + optional typed evidence; generated `.lock` contains recomputed machine facts.
- Generated history:adjacent `<registry>.lock` files bind name→category homes plus package identity→source class/lifecycle/hashes/provenance/optional admission-batch hash.
- Irreversible history:old immutable lock fields remain exact; only additions + `active→removed` are valid; removed identities cannot reactivate.
- Registry-scoped identity:a package name/home/version belongs to one catalog registry; the same normalized name may exist in another registry without collision.
- Explicit routing:dependencies prefer a same-registry home; absent that, exactly one external-registry home is required; the source category's `may-depend-on` must permit the target category.
- Exact artifacts:crates.io `.crate` bytes are fetched + checksum-verified but not stored; Git-tag packages are reproduced twice with pinned Cargo + retained by content hash.
- Source-aware downloads:a mixed mirror/Git registry must use its exact checksum-bearing immutable-router template; a single-source registry may use its fixed source endpoint.

## Managed layout

```text
registry/
├── main.toml
├── main.lock
├── downloads.json
├── categories/
│   └── main/
│       ├── general.toml
│       └── matrix.toml
├── admissions/
│   ├── 2026-08-24-routine.toml
│   └── 2026-08-24-routine.lock
└── objects/
    ├── crates/<active-git-archive-sha256>.crate
    └── rows/<source-row-sha256>.json
```

A future registry adds `<alias>.toml`, `<alias>.lock`, and optional `categories/<alias>/...`; it does not rename `main` files. `registry/` is exclusive managed state. Orphan paths, nested admission entries, symlinks, special files, noncanonical content, missing/extra pairs, locks without declarations, and unexpected objects fail before network resolution. Keep proposals, transient manifests, inspections, logs, and rendered sites outside this directory.

## Human declarations

Current mixed-source root registry with inline + external categories:

```toml
schema = 4

[registry]
name = "main"
index = "sparse+https://rust.pkg.re/"
download = "https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}"
cargo-version = "1.95.0"

[categories.acp]
may-depend-on = ["main/acp", "main/general"]

[categories.acp.mirror]
agent-client-protocol = ["2.0.0"]

[categories.general]
file = "categories/main/general.toml"

[categories.pkgre]
may-depend-on = ["main/general", "main/pkgre"]

[categories.pkgre.publish.pkgre-rust]
git = "https://github.com/pkgre/pkgre"
tags = ["rust/v0.5.0"]
```

Referenced `categories/main/general.toml`:

```toml
schema = 4
may-depend-on = ["main/general"]

[mirror]
serde = ["1.0.228", "1.0.229"]
reserved-package = []
```

Future registry example:

```toml
schema = 4

[registry]
name = "staging"
index = "sparse+https://rust.pkg.re/staging/"
download = "https://dl.rust.pkg.re/v1/staging/{crate}/{version}/{sha256-checksum}"
cargo-version = "1.95.0"

[categories.experimental]
may-depend-on = ["main/general", "staging/experimental"]

[categories.experimental.mirror]
example = ["1.0.0"]
```

Declaration rules:

- Filename stem = `[registry].name`; `main` index is root; every other alias index is `sparse+https://rust.pkg.re/<alias>/`; Cargo version is `1.95.0` across registries.
- Catalog must contain `main`; additional canonical aliases are allowed. Once released, registry identity/index, categories/rules, package homes, and existing package identities/sources cannot be removed/mutated; additions are allowed.
- Category identity = `<registry>/<local>`; components are canonical lowercase ASCII aliases/kebab-case, ≤64 bytes each, start/end alphanumeric, and the category registry must exist.
- Inline category = `may-depend-on` + optional `mirror`/`publish`; external reference = only `file`; external file = `schema`, `may-depend-on`, optional `mirror`/`publish`.
- Every `may-depend-on` target must be an existing category; same registry grants no implicit permission; every category must reserve ≥1 package name.
- `[mirror]`:package name → exact SemVer list; source row/archive come from crates.io.
- `[publish]`:package name → credential-free HTTPS Git URL + literal immutable tags.
- Mirror + publish names may coexist in one registry only with `https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}`. Mirror-only may use `https://static.crates.io/crates`; publish-only may use `https://rust.pkg.re/crates/{sha256-checksum}.crate`.
- Package names are permanent per-registry reservations under Cargo ASCII case + `-`/`_` normalization. Same normalized name in another registry is allowed; one registry-qualified name cannot move category. A name may occur under both `mirror` + `publish` for distinct versions; an existing `registry + name + version` cannot change source/checksum.
- Retain removed mirror key with `[]`; retain removed publisher key + unchanged `git` with `tags = []`.
- SemVer build metadata does not distinguish Cargo registry identities; different bytes require a distinct Cargo version.

Current production category policy:

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

## Generated registry locks

Canonical mirror package example:

```toml
schema = 4

[registry]
name = "main"
index = "sparse+https://rust.pkg.re/"
download = "https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}"

[[names]]
name = "serde"
category = "general"

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

The containing lock supplies registry identity; package/name entries are therefore registry-scoped even though they omit a repeated registry field. Git provenance additionally records:

```toml
[packages.source]
kind = "git-tag"
git = "https://github.com/pkgre/pkgre"
tag = "rust/v0.5.0"
tag-oid = "<full-git-object-id>"
commit = "<full-peeled-commit-id>"
package = "pkgre-rust"
path = "rust"
cargo-version = "1.95.0"
```

| Field | Binds |
|---|---|
| `crate-sha256` | Exact `.crate` bytes + Cargo row `cksum`; mirrors re-fetch from crates.io, Git uses retained bytes |
| `source-row-sha256` | Exact unrouted crates.io row or deterministic Git-package row |
| `index-row-sha256` | Canonical routed row with `yanked = false`; removal changes only rendered yank state |
| `admission-sha256` | SHA-256 of complete generated admission `.lock`; all candidates in a batch share it; forbidden on Git identities |

Never hand-edit locks. Load validates canonical form, registry/category/source anchors, provenance, object hashes, row identity/checksum, routed-row hash, and exact admission↔package coverage. Historical/bootstrap mirrors may omit `admission-sha256`; ordinary `lock` cannot create another unbound mirror identity after bootstrap.

## Generated download catalog

`registry/downloads.json` is generated from active locks only:

```json
{
  "schema": 1,
  "routes": [
    {
      "registry": "main",
      "name": "serde",
      "version": "1.0.229",
      "sha256": "<64-lowercase-hex>",
      "source": "crates-io"
    }
  ]
}
```

Route sort order + identity are strict; registry aliases are catalog-defined; name remains case-sensitive; version is canonical SemVer; source is closed to `crates-io|git-tag`. Duplicate identity, unknown fields/schema, noncanonical JSON, nonregular file, wrong/extra/missing routes, or >16 MiB fails load/check. `lock` regenerates missing/stale bytes transactionally. `render` copies the exact projection to the Pages root. Removed identities are excluded. Destinations are not stored; the service derives one of two hardcoded origins. See [`download-routing.md`](download-routing.md).

## Human admission manifest

`update-plan` emits a directly applyable compact template outside the catalog:

```toml
schema = 2

[[admit]]
category = "main/general"
name = "demo"
version = "1.2.3"

[[admit]]
category = "main/matrix"
name = "matrix-sdk"
version = "0.19.0"
```

The file intentionally omits checksums, row/archive analysis, policy snapshots, timestamps, and mutable API observations. Requests are canonical + uniquely ordered. Exact Git tags are representable with `tag`, but mirror apply rejects them; Git publication uses category declarations + `lock`.

Optional evidence:

```toml
[[admit.evidence]]
kind = "manual-full-archive"
note = "Reviewed every regular archive member and normalized manifest."
```

```toml
[[admit.evidence]]
kind = "manual-source-delta"
base = "1.2.2"
note = "Reviewed the complete archive delta from 1.2.2."
```

Evidence is optional, canonical, public, and exact-base checked. Protected review of the complete registry PR remains authorization; typed evidence is supplemental + supports later integrations such as cargo-vet.

## Generated admission lock + lifecycle

`update-apply` creates `admissions/<batch>.lock` beside the exact human manifest. It contains adjacent-manifest hash, admission UTC time, indexer version, catalog fingerprint, recorded positive policy thresholds, exact candidates, histories/rows/archives/hashes, bounded analyses/deltas, dependency/API/source evidence, decisions/reasons, and copied requests/evidence.

The canonical lock bytes are hashed; every resulting package receives the hash in `admission-sha256`. Validation indexes candidates/packages, rejects duplicate/orphan coverage, and requires each candidate route/version/archive/source-row fact to equal its package lock. Pairs are immutable. Identical reapply validates + no-ops; filename reuse with different content, deletion/tampering, orphaning, or package-binding change fails.

Mirror workflow:

1. `update-plan <catalog> <new-manifest>` scans active compatibility lanes, evaluates current evidence, omits blocked candidates, and writes compact requests only after proving catalog stability.
2. Reviewer may remove requests, run `update-inspect`, or add evidence; generated unedited manifest is valid.
3. `update-apply` validates the human file, re-fetches exact current sparse/API/archive/source facts, rejects young/yanked/blocked/route-invalid/evidence-invalid identities, and computes one batch lock.
4. Guarded whole-catalog transaction checks the starting fingerprint, appends requested versions, installs the pair, reconciles rows/locks/downloads, strictly reloads + test-renders staging, then atomically installs it.
5. A second `lock` must be byte-for-byte no-op; `check`, `render`, `verify`, and `verify-monotonic` validate publication.

Planning facts are not authority:apply always recomputes using its own current UTC time, including the 30-day floor. Route/catalog drift is detected during apply.

## Mirror materialization

For each candidate, the indexer fetches complete sparse history + exact `.crate`, selects one matching non-yanked ≥30-day row, validates Cargo metadata, and requires archive SHA-256 = row `cksum`. Planning/apply also analyze bounded archive/dependency/API/source evidence. Exact selected row + newline becomes a retained row object; verified archive bytes are discarded. Cargo later follows the checksum-bound router to `static.crates.io` and validates against the curated checksum; crates.io controls availability, not accepted metadata/integrity.

## Reconciliation

`pkgre-rust lock registry` handles bootstrap/removal/Git tags; established catalogs require `update-apply` for new mirror identities.

1. Acquire sibling guard `.registry.pkgre-lock`; concurrent/stale guard fails closed.
2. Load declarations, registry locks, admissions, categories, downloads, and objects; validate complete local invariants.
3. Resolve only permitted absent identities:all sources during initial no-lock bootstrap, or declared Git tags afterward. Direct new mirror fails.
4. Route dependencies with registry-scoped homes; prefer same-registry home, otherwise require one external home; enforce category edge.
5. Generate canonical locks; preserve old entries; mark no-longer-desired active entries `removed`.
6. Build complete sibling staging; retain rows; retain archives used by active Git identities; omit mirror archives + unshared removed Git archives.
7. Regenerate `downloads.json`; strictly reload, object-verify, and test-render staging.
8. Install by same-parent rename with rollback + sync; remove guard.

Unchanged second reconciliation = exact no-op. A crash can leave guard/staging/backup siblings; remove only after confirming no process is active.

## First-party Git-tag materialization

For each new publish tag, package version/path/tag object/peeled commit are discovered + locked. Current production source contract:

- Tag final component = package version or `v<version>`; e.g. `rust/v0.5.0`.
- Tagged workspace contains exactly one selected package name; manifest declares exactly `publish = ["pkgre"]`.
- Every dependency, including optional/dev/build/target-specific, explicitly names `registry = "pkgre"`; path/Git/crates.io/unknown sources fail.
- Checkout has no submodules, symlinks, special files, unsafe paths, manifest mismatch, or dirty generated changes.
- Pinned Cargo:absolute `PKGRE_CARGO` when set, otherwise `rustup which --toolchain <cargo-version> cargo`; reported version must match.
- `cargo metadata --no-deps --locked` runs in isolated Cargo home with crates.io replaced by empty directory.
- `cargo package --no-verify --locked` runs twice with distinct targets; archives must be byte-identical.

Generated row + archive are retained; identity/version/path, tag object, commit, Cargo version, archive hash, source-row hash, and routed-row hash become permanent. Catalog category—not the source manifest alias—chooses the final registry home; dependency routing is recalculated from catalog homes.

## Routing + rendering

For each dependency:

```text
identity = dependency.package ?? dependency.name
home = same-registry permanent home(identity) if present
     | sole external-registry permanent home(identity)
     | error(absent or ambiguous)
permit(source.category, home.category)
registry = null                                       # same registry
registry = canonical sparse URL for home.registry     # cross-registry
```

Routing covers normal/dev/build/optional/target-specific + renamed dependencies, overwrites source-row registry values, and rejects forbidden/ambiguous/unknown edges. Unknown top-level row fields are retained; malformed known fields fail. Active routed rows are hashed permanently; removed rows reuse routed content with only `yanked = true`.

Rendered output:

```text
site/
├── .nojekyll
├── CNAME
├── config.json                    # main
├── release.json
├── downloads.json
├── <main sparse package paths>
├── staging/config.json            # only if staging exists
├── staging/<sparse package paths>
└── crates/<active-git-archive-sha256>.crate
```

`release.json` schema 4 records registry/category topology, registry-scoped permanent name homes, and package identities. `verify-monotonic` requires every prior registry/category/home/immutable identity to remain exact, permits new registry/category/home/package identities + `active→removed` + source-specific→router transition, authenticates routes, and rejects reactivation.

## Exact migrations

Historical schema 2→3:

```console
$ pkgre-rust migrate-v2-to-v3 registry-v2 registry-v3
```

Source must be strict canonical schema-2 `core`/`matrix`/`pkgre`; destination absent. It maps into schema-3 `universe`/`pkgre`, authenticates all rows/objects/hashes, reproduces staging, and never modifies source.

Production schema 3→4:

```console
$ pkgre-rust migrate-v3-to-v4 registry-v3 registry-v4
```

Source must be strict canonical schema 3; destination absent. Exact mapping:`universe/<category>→main/<category>`; `pkgre/tooling→main/pkgre`; both old registries collapse into root `main`; current direct download endpoints become `https://dl.rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}`. It preserves names/package identities/source rows/Git archives/checksums/provenance; recomputes only registry-dependent routed-row hashes; rewrites admission categories/routes + generated admission-lock hashes and rebinds package `admission-sha256`; validates bidirectional coverage; strict-loads/renders/reproduces staging; installs by one rename. Source is never modified. `verify-monotonic` explicitly authenticates the 3→4 mapping.

## Removal

1. Delete exact version/tag from desired list; retain package key in original registry/category.
2. Run `lock`; permanent package state changes only `active→removed`.
3. Source-row evidence remains; mirror archives were never retained; unshared Git archive disappears.
4. Rendered row remains with `yanked = true`.
5. Re-adding identity fails permanently; publish/admit a new version instead.
