# Curator workflows

## Commands

```text
pkgre-indexer lock <catalog>
pkgre-indexer check <catalog>
pkgre-indexer render <catalog> <new-output>
pkgre-indexer verify <catalog> <existing-output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>
```

`lock` is the only command that mutates a schema-3 catalog. `migrate-v2-to-v3` reads but never modifies its source and installs only to an absent destination. `check` is local-only and never re-fetches crates.io or Git tags. Render output must be absent; no command overwrites a site tree. Use the registry directory itself as `<catalog>` (for example `registry`), never its repository parent.

## Add mirrored versions

1. Choose the package's permanent `universe/<category>` home from the canonical policy; inspect all direct dependency homes because an edge absent from that category's `may-depend-on` set will fail.
2. Add exact versions under the category's `mirror` table. Inline example in `universe.toml`:

```toml
[categories.acp.mirror]
agent-client-protocol = ["2.0.0"]
```

External example in `categories/universe/general.toml`:

```toml
[mirror]
serde = ["1.0.228", "1.0.229"]
```

3. Run reconciliation from outside the managed catalog directory:

```console
$ pkgre-indexer lock registry
```

4. Reconciler validates all existing history locally before fetching each new exact crates.io sparse row + `.crate`; it rejects missing/duplicate/yanked/malformed rows, checksum mismatch, permanent-home changes, and forbidden category edges; it routes dependencies, generates lock entries, retains the content-addressed source row, discards verified mirror bytes, test-renders staging, then transactionally replaces `registry/`.
5. Review the complete diff before commit: declaration/category, generated lock identity/provenance/hashes, new source-row object, dependency category routes, build-time capability, proc macros, native/unsafe code, features/targets, and licensing. Separately fetch `https://static.crates.io/crates/<name>/<name>-<version>.crate`, require SHA-256 = locked `crate-sha256`, and inspect exact archive contents. Generated success is integrity evidence, not approval.
6. Verify locally and prove convergence:

```console
$ pkgre-indexer check registry
$ git status --short
$ pkgre-indexer lock registry
$ git status --short
```

The second `lock` must produce no diff. Any unexpected changed/deleted object or lock entry blocks approval.

## Publish a first-party Git tag

Tagged source preconditions:

- committed credential-free HTTPS repository + immutable release tag;
- selected package version equals the tag's final component with optional `v` prefix;
- selected manifest declares exactly `publish = ["pkgre"]`;
- every dependency explicitly names `registry = "universe"|"pkgre"`; path/Git/crates.io/unknown sources fail, including optional/dev/build/target-specific edges;
- every dependency category is allowed by `pkgre/tooling` (`pkgre/tooling` or `universe/general`);
- lockfile present + compatible with isolated curated registries;
- no submodules, symlinks, special files, unsafe paths, ambiguous package names, or generated dirty checkout state;
- package can be reproducibly archived by Cargo `1.95.0`.

Workflow:

1. Review + merge the release commit through protected `main`; create + push the immutable tag only after merge.
2. Add the tag to the retained `pkgre.toml` declaration:

```toml
[categories.tooling.publish.pkgre-indexer]
git = "https://github.com/pkgre/pkgre"
tags = ["indexer/v0.2.0"]
```

3. Select pinned Cargo: set `PKGRE_CARGO=/absolute/path/to/cargo` or install rustup toolchain `1.95.0`. The executable must report a version beginning `cargo 1.95.0 `.
4. Run `pkgre-indexer lock registry`. It fetches only the exact tag, records tag object + peeled commit, discovers the package version + repository-relative path, runs isolated locked metadata, packages twice into distinct targets, requires byte-identical archives, generates the source row, routes dependencies, and locks every identity/hash.
5. Confirm the locked Git URL/tag/tag object/commit/package/path/Cargo version match the reviewed release; inspect the exact `.crate` + source row; compare archive contents with the tagged tree and normalized manifest.
6. Run local `check` + a second no-op `lock`, then commit declaration, lock, and objects together.

Pinned Cargo selection order:

1. `PKGRE_CARGO`: must be absolute, canonicalizable, and a regular file.
2. `rustup which --toolchain <cargo-version> cargo`: returned path must be absolute.

Nix builds set `PKGRE_CARGO` to the flake-pinned toolchain. `check` validates retained bytes/provenance locally but deliberately does not contact/reproduce a locked Git tag.

Self-publication rule: normally reconcile a new indexer tag with the prior immutable indexer release. A schema/bootstrap release that cannot be read by its predecessor must use a reviewed build from the exact merged/tagged release commit, then lock that same immutable tag and retain the resulting provenance.

## Remove a version/tag

1. Remove the exact version/tag from its array; never delete or move the package key.

External mirror category:

```toml
[mirror]
obsolete-mirror = []
```

Inline publisher category:

```toml
[categories.tooling.publish.obsolete-first-party]
git = "https://github.com/pkgre/example"
tags = []
```

2. Run `pkgre-indexer lock registry`.
3. Review that only the intended lock entries transitioned `state = "active"` → `state = "removed"`; source-row evidence remains; a retained Git archive object disappears only if no active Git identity shares its hash; mirror archives are never retained.
4. Rendered history retains the row with `yanked = true` and omits an unshared Git archive. Reactivation is permanently rejected; restoring functionality requires a new version/tag.
5. Run `check`, a second no-op `lock`, render, and `verify-monotonic` before commit/deploy.

Removing a package key, changing its registry/category/source class, changing a locked publisher Git URL, or re-adding a removed identity fails before network access.

## Migrate a canonical schema-2 catalog

1. Require a clean source catalog + working tree; record a sorted SHA-256 manifest of every source file.
2. Choose an absent sibling destination; never point migration at the source or an existing path.
3. Run:

```console
$ pkgre-indexer migrate-v2-to-v3 registry registry-v3
```

4. Require successful strict schema-2 source authentication, exact `core`/`matrix`/`pkgre`→`universe`/`pkgre` mapping, source-row/Git-archive byte preservation, category policy validation, staged schema-3 render, and reproduction. Any corrupt/unmappable/forbidden identity aborts before installation; source remains untouched.
5. Compare source objects byte-for-byte, inspect `universe.toml`, `pkgre.toml`, external category files, locks, category membership, package counts, and exactly retained Git archives.
6. Validate transition before replacing source:

```console
$ pkgre-indexer check registry-v3
$ pkgre-indexer render registry-v3 site-v3
$ pkgre-indexer verify registry-v3 site-v3
$ pkgre-indexer verify-monotonic site-v2 site-v3
```

7. Replace the working-tree catalog only after review, retain version-control recovery, rerun validation at the final path, then commit. Do not squash away already-published catalog history merely for this metadata migration; mirror archives were never retained by schema 2.

## Release gate

Prepare candidate at an absent path:

```console
$ pkgre-indexer check registry
$ pkgre-indexer render registry site-next
$ pkgre-indexer verify registry site-next
$ pkgre-indexer verify-monotonic site-current site-next
```

Required review:

- `git diff --check`; generated declaration/lock/object diff fully explained; second `lock` exact no-op;
- tooling format/build/test/lint/Nix checks pass with locked inputs;
- prior `release.json` name/package identities all retained; additions/removals intentional; immutable fields unchanged;
- exact canonical registry/category topology + source-class downloads;
- rendered site contains only `.nojekyll`, `CNAME`, `release.json`, canonical registry configs/rows, and active content-addressed Git-tag archives;
- branch protection/required CI passes; merge normally with no force/bypass.

Deploy only the rendered site, never `registry/`. A release workflow should independently run `check`, `render`, `verify`, fetch the prior live `release.json`, run `verify-monotonic`, and publish with read-only source permissions + only the minimum Pages permissions.

## Post-deployment verification

- Fetch `https://rust.pkg.re/{universe,pkgre}/config.json`; require crates.io `dl` for `universe` + the pkg.re content-addressed template for `pkgre`.
- Fetch representative package rows from every category; validate expected checksum/routes/yank state against `release.json`.
- Fetch representative mirror archives through `static.crates.io` + Git-tag archives through pkg.re; recompute SHA-256 against curated rows; confirm removed unshared Git archives return not found.
- Compare live `release.json` with the committed candidate; require schema 3 + exact category topology/name anchors.
- Use a fresh Cargo home/cache and committed failure-closed `.cargo/config.toml`; run metadata/build/install with `--locked`/`--frozen` across both registries and representative categories.
- Capture network/source evidence that no crates.io index, Git dependency, or unknown registry was contacted; mirror archive traffic may target only `static.crates.io`.

Keep consumer validation results private: public commits/logs/issues must not include consumer repository names, filesystem paths, manifests, lockfiles, dependency-discovery output, tokens, or credentials.

## Interrupted reconciliation recovery

A normal failure removes its sibling guard/staging tree and leaves the original catalog exact; installation failure attempts rollback. A killed process can leave `.registry.pkgre-lock`, staging, or backup siblings beside `registry/`.

1. Confirm no indexer process is active.
2. Inspect `registry/` + siblings; preserve/restore the last reviewed complete catalog if installation was interrupted.
3. Remove only verified stale `.registry.pkgre-lock` and disposable `.registry.pkgre-stage-*`/`.registry.pkgre-render-*`; treat `.registry.pkgre-backup-*` as recovery evidence until integrity is confirmed.
4. Run `pkgre-indexer check registry`, compare source control, then retry `lock`.
