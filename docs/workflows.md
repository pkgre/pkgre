# Curator workflows

## Commands

```text
pkgre-indexer update-plan <catalog> <new-plan>
pkgre-indexer update-plan-exact <catalog> <package> <version> <new-plan>
pkgre-indexer update-inspect <plan> <package> <version> <new-review-directory>
pkgre-indexer update-approve <plan> <new-approved-plan> <package> <version> <source-delta|full-archive> <note-file>
pkgre-indexer update-apply <catalog> <plan-or-approved-plan>
pkgre-indexer lock <catalog>
pkgre-indexer check <catalog>
pkgre-indexer render <catalog> <new-output>
pkgre-indexer verify <catalog> <existing-output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer migrate-v2-to-v3 <schema-2-catalog> <new-schema-3-catalog>
```

`update-plan`, `update-plan-exact`, and `update-inspect` never mutate the catalog; every output must be absent and outside the managed catalog. `update-approve` leaves its input plan/note unchanged and creates a new plan. `update-apply` is the evidence-bound mutator for new mirror identities in an established catalog. `lock` mutates only for bootstrap, empty name reservations, removals, and first-party Git tags; it rejects direct admission of a new mirror identity after any registry lock exists. `migrate-v2-to-v3` reads but never modifies its source and installs only to an absent destination. `check` is local-only and never re-fetches crates.io or Git tags. Render output must be absent; no command overwrites a site tree. Use the registry directory itself as `<catalog>` (for example `registry`), never its repository parent.

## Admit crates.io mirror updates

### Selection + guardrails

- Release-age floor: every implicit/exact candidate must be non-yanked and ≥30×24 hours old at the plan's UTC evaluation time; future timestamps fail.
- Implicit lanes: `update-plan` selects at most one latest eligible stable update for each active compatibility lane: one lane per `major` for `major≥1`, or per `minor` for stable `0.minor.patch` with `minor>0`; prereleases + `0.0.x` require `update-plan-exact`.
- Exact selection: supports new names, inactive names, prereleases, and `0.0.x`, but cannot select a locked identity, an upstream-yanked/young identity, or an identity predating every existing review base.
- Dormancy: a ≥365-day adjacent publication gap between the locked base and candidate requires review; all publications, including yanked/prerelease rows, count as activity. A post-gap burst stays gated until one post-gap identity is admitted.
- Evidence: full crates.io sparse history, selected/base rows + checksum-verified archives, bounded path/type/size/mode/hash/build-surface analysis, dependency delta + category routes, version-scoped publisher/repository/API facts, and promoted source correspondence. New/inactive/dormant releases, new dependency packages, changed build surface, or publisher/repository discontinuity promote source verification.

Decision policy:

| Decision | Reasons | Admission |
|---|---|---|
| `automatic` | no policy reason | no human approval assertion |
| `review-required` | new package, inactive revival, dormant wake-up, new dependency package, changed build surface, publisher/repository discontinuity, or promoted source unavailable | exactly one evidence-bound approval |
| `blocked` | unknown dependency home, forbidden category edge, or source mismatch | impossible; fix catalog/upstream evidence + create a new plan |

`explicit-candidate` records selection mode but alone does not force review. Unsafe/malformed archives, changed locked crates.io history, checksum/evidence inconsistency, duplicate identities, or catalog drift fail planning rather than yielding a candidate.

### Workflow

The standalone production procedure—including deployed-pin selection, external evidence workspace, read-only proofs, complete archive review, transactional apply, diff/convergence/release audits, and curator-review PR boundary—is [`production-update-runbook.md`](production-update-runbook.md). The steps below are the policy-level command synopsis; use the runbook for a real catalog update.

1. Choose the package's permanent `universe/<category>` home; inspect every direct dependency home + the category's exact `may-depend-on` set. For a first package identity, reserve only the name, then lock the empty anchor:

```toml
[mirror]
new-package = []
```

```console
$ pkgre-indexer lock registry
```

2. Create one canonical plan outside `registry/`. Implicit planning scans all permanently reserved mirror names with active lanes; exact planning targets one requested identity and is required for a new/inactive name, prerelease, or `0.0.x`:

```console
$ pkgre-indexer update-plan registry plan.toml
$ pkgre-indexer update-plan-exact registry new-package 1.2.3 plan.toml
```

The plan binds the catalog fingerprint, evaluation time, exact candidate/base, decision history, archive/dependency/API/source evidence, and policy constants. It never edits declarations and refuses an existing output path.

3. Review every candidate + decision. Materialize bounded inert evidence for any exact candidate into an absent directory:

```console
$ pkgre-indexer update-inspect plan.toml new-package 1.2.3 review-new-package-1.2.3
```

The review tree contains `candidate.crate`, optional `base.crate`, `inspection.toml`, and `README.txt`; hashes/analyses must equal the plan. The indexer does not extract archives to disk or invoke Cargo, compilers, build scripts, examples, binaries, repository hooks, or package code. Treat retained archives as untrusted input.

4. For each `review-required` candidate, write a specific nonempty UTF-8 note (≤16 KiB) and create a new approved plan; chain outputs when a multi-candidate plan needs multiple approvals:

```console
$ pkgre-indexer update-approve plan.toml approved-1.toml new-package 1.2.3 full-archive note.txt
$ pkgre-indexer update-approve approved-1.toml approved-2.toml existing-package 2.4.1 source-delta other-note.txt
```

`source-delta` is required only for an active package with a meaningful base/archive delta; new or inactive packages require `full-archive`. The assertion binds exact candidate evidence + review note hash/time. Automatic candidates carry no approval; blocked candidates remain inadmissible.

5. Apply the plan within seven exact days of evaluation (the boundary is inclusive):

```console
$ pkgre-indexer update-apply registry approved-2.toml
```

Apply requires an unchanged catalog fingerprint; recomputes complete upstream evidence for the exact planned identities at the original evaluation time; rejects any difference except approval assertions and the raw crates.io API response hash; then uses a guarded whole-catalog transaction to edit only the target category declarations, retain rows/admission evidence, generate locks, strict-load/object-verify/test-render staging, and atomically install with rollback. crates.io API responses contain mutable non-decision fields, so the raw hash remains planning provenance; planned identities/checksums must still agree with the current API response, and parsed publishers, repositories, and Trusted Publishing evidence must match exactly. Apply never substitutes a newer candidate.

6. Review + commit each declaration/lock/row/admission change together. Every admitted updater identity has `admission-sha256` in its generated lock and exactly one canonical `_reviews/admissions/<candidate-binding-sha256>.toml`; `check` rejects missing, modified, duplicate, or unexpected records. Then prove validity + convergence:

```console
$ pkgre-indexer check registry
$ git status --short
$ pkgre-indexer lock registry
$ git status --short
```

The second `lock` must report `changed=false` + produce no diff. Do not manually append a mirror version and run `lock`: once any lock exists, direct new-mirror resolution fails before network access. `lock` remains the correct path for empty name anchors, removals, first-party Git tags, and initial catalog bootstrap.

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
