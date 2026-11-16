# pkgre-rust

Transactional declarative reconciler + deterministic renderer for schema-5 pkg.re Cargo registries/categories.

## Interface

```text
pkgre-rust update-plan <catalog> <new-admission-manifest>
pkgre-rust update-plan-exact <catalog> <package> <version> <new-admission-manifest>
pkgre-rust update-inspect <catalog> <admission-manifest> <package> <version> <new-review-directory>
pkgre-rust update-apply <catalog> <admission-manifest>
pkgre-rust lock <catalog>
pkgre-rust check <catalog>
pkgre-rust render <catalog> <output>
pkgre-rust verify <catalog> <output>
pkgre-rust verify-monotonic <previous-site> <next-site>
pkgre-rust migrate-v4-to-v5 <schema-4-catalog> <new-schema-5-catalog> [--git-tag-time=<registry>/<name>@<tag>=<timestamp>]...
pkgre-rust migrate-retained-delivery <catalog-root>
pkgre-rust archive-inventory <catalog> <output.json>
pkgre-rust archive-import <archive-store> <catalog>
pkgre-rust check-transition <accepted-catalog> <candidate-catalog>
pkgre-rust self-publish-check <repository> [<accepted-repository>]
```

- `update-plan`:evaluate all active mirror compatibility lanes; create an absent compact canonical manifest containing every nonblocked exact request.
- `update-plan-exact`:evaluate one reserved mirror name/version, including new/inactive names, prereleases, and stable `0.0.x`; create an absent one-request manifest.
- `update-inspect`:recompute one manifest request + materialize checksum-verified candidate/base archives and bounded inert evidence without executing package code.
- `update-apply`:recompute every exact request at current time; reject young/yanked/blocked/invalid candidates; atomically install declaration additions, source rows, registry locks, canonical download catalog, and one immutable human-manifest/generated-lock admission pair.
- `lock`:preflight locally; reconcile initial bootstrap, empty reservations, removals, new first-party Git tags, and canonical `downloads.json`; direct new-mirror admission fails once registry locks exist.
- `check`:local-only strict schema/category/registry/admission/download/object/hash/row validation; never fetch crates.io or reproduce Git tags.
- `render`:write a new complete site tree. Catalog registry `main` renders at the site root; other registry aliases render below `/r/<alias>/`; output must be absent.
- `verify`:re-render + require exact entry/byte equality with an existing site.
- `verify-monotonic`:permit registries/categories/package identities to be added, `active→removed`, and source-specific→exact-router `dl`; reject removal/mutation/reactivation; authenticate exact release-manifest schema-2→3 + schema-3→4 migrations.
- `migrate-v4-to-v5`:parse every generated schema-4 lock strictly (exact fields, `schema = 4`), the schema-1 download catalog strictly, and every registry + external category file, refusing one whose `schema` is not 4; rewrite those files to schema 5 with `audience = "public"`; rebuild every lock with one `admitted-at` per package (crates.io row `pubtime`, or a required `--git-tag-time=<registry>/<name>@<tag>=<timestamp>` per Git tag, which is the operator's value and is not verified); replace the download catalog with the schema-2 `redirect` delivery model; write only to an absent destination, by migrating into a private staging directory beside it and renaming it into place only after the output was strictly loaded, policy-checked, artifact-verified and test-rendered, so a failed run leaves no destination; the source is never modified.
- `migrate-retained-delivery`:add `delivery = "retained"` to every root registry in place and rewrite `downloads.json` to the exact derived schema-2 bytes; archive bodies are imported separately and deliberately not verified here.
- `archive-inventory`:write the canonical retained-object inventory of one catalog for an archive store.
- `archive-import`:require the store's canonical `inventory.json` to equal the catalog's retained set, copy every missing `<sha256>.crate`, verify every digest, then re-run strict load/policy/artifact checks.
- `check-transition`:strictly load + policy-check accepted and candidate schema-5 catalogs; reject an added or removed registry, a changed registry name/index/audience/cargo-version, a download change other than the allowed one-way migrations, a missing identity, a changed archive/source-row/routed-row hash, source, `admitted-at` or state (`active→removed` included), and a moved category; require every active retained identity's body to exist in `objects/crates/` with a matching SHA-256. It does not compare `delivery`, read row objects, or verify archive bytes beyond that retained-body check.
- `self-publish-check`:offline checks of `self-publish/crates-io.toml` and `self-publish/crates-io.lock` against `registry/main.lock`, and against an accepted repository when one is given; no network. `<repository>` is the directory that holds `registry/` and `self-publish/`. A repository without `self-publish/` has nothing to check, unless the accepted repository has one: removing the state is refused.

`<catalog>` is exclusive managed state:one `<registry>.toml` + generated `<registry>.lock` per registry; canonical generated `downloads.json`; exact referenced `categories/<registry>/<category>.toml`; paired `admissions/<batch>.{toml,lock}`; content-addressed `objects/{crates,rows}/`. Rows cover all locked identities; crate objects contain active retained-delivery archives:Git tags always, crates.io archives only when the registry declares `delivery = "retained"`. Retain every package key after its desired version/tag list becomes empty; deleting a required key, changing a name's registry/category home, or changing an existing identity's source fails closed.

Schema 5 requires catalog alias `main` at `sparse+https://rust.pkg.re/`; another canonical alias `staging` maps to `sparse+https://rust.pkg.re/r/staging/`. Every registry declares `audience` (`public` or `lan-public`) and may declare `delivery` (`redirect`, the default, or `retained`). Registry/category/package identities are scoped by catalog registry. Dependency routing prefers a same-registry package home; absent that, exactly one external-registry home is required. The source category must explicitly permit the resolved target category. Existing registries/categories/homes are monotonic; future ones may be added.

One registry may contain mirror + publish names only when `download = "https://dl.rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}"` or same-host `"https://rust.pkg.re/v1/<registry>/{crate}/{version}/{sha256-checksum}"`. A single-source registry may use its fixed direct source endpoint. `downloads.json` is deterministically projected from every locked identity as exact `(registry, case-sensitive name, canonical version, archive SHA-256, closed redirect|retained delivery)` routes; the router never takes arbitrary destination URLs from this file.

Human admission manifests contain exact category/name/version or tag + optional typed evidence. Mirror apply currently accepts versions only. Generated admission locks retain complete recomputed facts; every package in a batch binds the SHA-256 of the same generated lock. Protected review/merge of the complete catalog PR is authorization; `automatic`/`review-required` only prioritize attention; `blocked` candidates cannot be applied.

Documentation:[`catalog schema`](../docs/catalog.md) | [`production mirror-update runbook`](../docs/production-update-runbook.md) | [`curator workflows`](../docs/workflows.md) | [`self-publishing`](../docs/self-publish.md) | [`security model`](../docs/security.md).
