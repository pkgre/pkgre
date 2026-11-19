# Curator workflows

## Commands

```text
pkgre-rust update-plan <catalog> <new-admission-manifest>
pkgre-rust update-plan-exact <catalog> <package> <version> <new-admission-manifest>
pkgre-rust update-inspect <catalog> <admission-manifest> <package> <version> <new-review-directory>
pkgre-rust update-apply <catalog> <admission-manifest>
pkgre-rust lock <catalog>
pkgre-rust check <catalog>
pkgre-rust check-serve <catalog> --delivery=<body|redirect> [--archive-store=<directory>] [--first-party-origin=<url>]
pkgre-rust render <catalog> <new-output>
pkgre-rust verify <catalog> <existing-output>
pkgre-rust verify-monotonic <previous-site> <next-site>
pkgre-rust migrate-v4-to-v5 <schema-4-catalog> <new-schema-5-catalog> [--git-tag-time=<registry>/<name>@<tag>=<timestamp>]...
pkgre-rust migrate-retained-delivery <catalog-root>
pkgre-rust archive-inventory <catalog> <output.json>
pkgre-rust archive-import <archive-store> <catalog>
pkgre-rust check-transition <accepted-catalog> <candidate-catalog>
pkgre-rust reproduce-git-tags <accepted-catalog> <candidate-catalog>
pkgre-rust self-publish-check <repository> [<accepted-repository>]
pkgre-rust self-publish-lock <repository>
pkgre-rust self-publish <repository> <tag> [--upload] [--git=<url>]
```

Planning/inspection never mutates catalog; output must be absent + outside `registry/`. `update-apply` is the established-catalog path for mirror additions. `lock` mutates only bootstrap, empty reservations, removals, Git tags, and downloads convergence. `check` is local-only. Migrations never modify source. Render output must be absent. `<catalog>` is the registry directory, not repository parent; the `self-publish` commands take `<repository>`, the directory that holds `registry/` and `self-publish/`.

## Admit crates.io mirror updates

### Guardrails

- Release age:non-yanked + ≥30×24 hours at command UTC time; future timestamps fail.
- Implicit lanes:`update-plan` scans active mirror names + selects at most latest eligible stable per compatibility lane:major for `major≥1`; minor for stable `0.minor.patch` where `minor>0`.
- Exact mode:`update-plan-exact` supports reserved new/inactive names, prereleases, `0.0.x`; locked/yanked/young/history-inconsistent identity rejected; a request inside a compatibility lane that holds an active identity must be newer than that lane's active maximum and must have a locked release of that lane published no later than it, the rules `update-apply` applies, so the planner refuses what application would refuse with the same message; a request whose lane holds no active identity and which was published before every locked release of its name is planned without a review base as `review-required`, so its review covers the whole archive instead of a delta.
- Dormancy:≥365-day adjacent publication gap after locked base requires review; yanked/prerelease activity counts; gate persists until one post-gap identity admitted.
- Evidence:complete sparse history; exact candidate row + checksum-verified archive, with the base row and archive beside it whenever the request has a review base; bounded path/type/size/mode/hash/build analysis; dependency/category delta; version-scoped publisher/repository/API facts; promoted source correspondence,which compares every archive member except Cargo's packaging-generated `.cargo_vcs_info.json`,`.cargo-ok`,normalized `Cargo.toml` + package root `Cargo.lock`.
- Promotion triggers:new/inactive package, dormant wake-up, new dependency package, build-surface change, publisher/repository discontinuity, request older than every locked release of its name in a lane without an active identity.

| Decision | Meaning | Manifest/apply |
|---|---|---|
| `automatic` | no escalation signal | included; applyable |
| `review-required` | escalation/source unavailable | included; applyable; prioritize review/evidence |
| `blocked` | missing/ambiguous home, forbidden edge, source mismatch | omitted; impossible until fixed |

Every registry PR requires review. `review-required` does not require per-crate approval files; complete generated PR review authorizes batch. Optional evidence records genuine extra work. Unsafe/malformed archives, changed history, checksum inconsistency, duplicate identity, or catalog drift fail command.

### Compact single-PR workflow

Standalone production procedure:[`production-update-runbook.md`](production-update-runbook.md).

1. Choose permanent `main/<category>` home. New package:add empty anchor + reconcile separately:

```toml
[mirror]
new-package = []
```

```console
$ pkgre-rust lock registry
```

2. Generate one hash-free manifest outside catalog:

```console
$ pkgre-rust update-plan registry 2026-08-24-routine.toml
$ pkgre-rust update-plan-exact registry new-package 1.2.3 2026-08-24-new-package.toml
```

```toml
schema = 2

[[admit]]
category = "main/general"
name = "example"
version = "1.2.3"
```

Template includes automatic + review-required, omits blocked, refuses existing output, and proves catalog fingerprint stable. Each candidate's log line names its decision and reasons; a promoted source comparison also logs why its evidence is `Unavailable` (for example `repository-package-path-ambiguous`, `repository-symlink-escapes-repository`, `repository-submodule-fetch-failed`) or the first 20 archive paths that differ from the public tree or are missing from it, and the package directory it located when the archive carried no `path_in_vcs`.

3. Review scope/logs; remove unwanted complete request blocks; keep canonical order. Inspect selected exact request:

```console
$ pkgre-rust update-inspect registry 2026-08-24-routine.toml example 1.2.3 review-example-1.2.3
```

Output=`candidate.crate`, optional `base.crate`, `inspection.toml`, `README.txt`; no Cargo/compiler/build/package/repository code executes. Treat archives as untrusted. `inspection.toml` carries the complete source comparison report beside its digest: every archive member's expected path, compared path, resolved path after a symbolic link or submodule, the submodule it was read from, whether Cargo copies it into the package root, whether the package's own file of that name was kept instead (`copy-skipped`), whether that file could equally have been packaged (`copy-ambiguous`), whether it holds a symbolic link's own text (`link-text`), both digests and modes, and its disposition (`match`, `different`, `missing`, `cargo-generated`, `line-endings`, `file-mode`); the last two are the members that differ from the tree only in their line endings or only in their executable bit, which make the admission `review-required` rather than blocked and which the review checks against the ways the package reads or runs them. The planning log names the members read through a copy or a link's own text, with their flags, disposition and the file each was compared with, and the members that differ only in line endings or the executable bit with their kind, so the review sees them without the report.

4. Optionally add typed evidence beneath request:

```toml
[[admit.evidence]]
kind = "manual-full-archive"
note = "Reviewed every archive member, manifest, and build surface."
```

```toml
[[admit.evidence]]
kind = "manual-source-delta"
base = "1.2.2"
note = "Reviewed the complete archive delta from 1.2.2."
```

Unedited template remains valid. Delta base must equal apply's recomputation.

5. Apply exact manifest once:

```console
$ pkgre-rust update-apply registry 2026-08-24-routine.toml
```

Apply re-fetches/recomputes every request; rejects young/yanked/blocked/route/evidence failures; appends declarations; writes source rows, registry locks, downloads, `admissions/<batch>.{toml,lock}`; binds full batch-lock hash into packages; strict-loads + test-renders staging; atomically installs. It never substitutes another version.

6. Review + commit all catalog changes together. Required:a new active package/request; one exact `main` route/request; one row object/request; exactly one admission pair/batch; a mirror `.crate` object only where the registry declares `delivery = "retained"`; every new package `admission-sha256 = sha256(admissions/<batch>.lock)`.

```console
$ pkgre-rust check registry
$ git diff --check
$ pkgre-rust lock registry
$ git diff --check
```

Second `lock` must report `changed=false` + preserve exact diff. CI must run `check`, no-op `lock`, render, `verify`, `verify-monotonic`, `check-serve` in the delivery mode of the serving origin, and `check-transition` from the pull request's base catalog to its head; this enforces that a PR cannot merge a manifest/template without fully applied state. It must also run `reproduce-git-tags` between those two catalogs, which re-fetches the Git-tag identities the change adds, one resolution per tag, as `lock` packages it, and proves each archive and source row against the locked ones and each dependent's packaged lock against the sibling archives the candidate locks, so that a tag this repository locked without its first-publication rules cannot merge. Reapplying identical installed manifest no-ops; same filename/different content fails.

### Exact admission templates

A batch of exact identities takes one `update-plan-exact` run per identity, each writing one template outside the catalog, and the templates are merged by hand into one manifest; `update-apply` runs once on that merged file, so the whole batch shares one admission pair and one `admission-sha256` binding. A merge keeps one `schema = 2` header and concatenates the `[[admit]]` blocks with their evidence. The merged file's stem is the batch name:`update-apply` installs `admissions/<stem>.toml` + `admissions/<stem>.lock`.

Two rules are enforced by the tool, not only by convention:

- filename:the stem is lowercase ASCII kebab-case:1–128 bytes of `a`–`z`, digits and `-`, starting and ending alphanumeric, and the extension is lowercase `.toml`. `update-plan`/`update-plan-exact` refuse to write any other template name, `update-apply` refuses any other input name, and `check` re-validates every installed pair:`rustc_version-0-3-3.toml` is refused (underscore), `rustc-version-0-3-3.toml` is accepted.
- order:requests sort by category, then ASCII-lowercased name, then the exact name as a tie-break, then the target (`version`, or `tag`) compared as a string. The version comparison is lexical, not SemVer:`uint` `0.10.2` precedes `uint` `0.9.5` because `"0.10.2" < "0.9.5"`. `update-apply` and `update-inspect` refuse a manifest whose requests are not in strict canonical order or repeat an identity, so re-sort after every merge; an exact version carries no build metadata.

Merged manifest of two identities:

```toml
schema = 2

[[admit]]
category = "main/general"
name = "uint"
version = "0.10.2"

[[admit]]
category = "main/general"
name = "uint"
version = "0.9.5"
```

### Bulk review

1. Generate one broad manifest; count automatic/review-required/blocked logs.
2. Require manifest entries=`automatic + review-required`; blocked absent.
3. Prioritize source-unavailable, dormancy, publisher/repository discontinuity, build/proc-macro/native changes, line-ending or executable-bit differences, new dependencies, large deltas.
4. Keep evidence only where useful; no boilerplate notes.
5. Apply once; review one generated lock + shared binding + exact diff.
6. Open one registry PR; leave unmerged for curator.

## Release Rust crates

One version releases every crate published to the `pkgre` registry. `[workspace.package] version` in the root `Cargo.toml` is that version; `pkgre` (`cli/`) and `pkgre-rust` (`rust/`) set `version.workspace = true` and inherit it. A member that is not published, now `pkgre-rust-serve`, keeps its own version.

A release is one annotated Git tag `rust/vX.Y.Z` on a commit of `main`, created after the pull request that sets the version has merged with CI passing. Its final component is the version, so the tag rule below holds for every crate of the release.

- Version is SemVer without build metadata, which Cargo ignores for identity; a prerelease such as `0.6.0-rc.1` is allowed and, once published, as permanent as a release.
- Versions only increase: greater than every version the catalog holds of each released crate, and than the version of every earlier release tag.
- A release tag never moves and is never deleted.

The flake check `release-metadata`, run by CI on every pull request, refuses a published member that does not inherit the workspace version, that lacks `description`, `license` or `repository` (an inherited value counts when the root manifest sets it), or whose `keywords` crates.io would refuse: more than 5, longer than 20 characters, or not ASCII letters, digits, `_`, `-` and `+` starting with a letter or digit.

## Self-publish to crates.io

A release of a self-publishing repository also reaches crates.io, locally, from a checkout of this repository: a dry run first, then the upload. [`self-publish.md`](self-publish.md) describes the state, the checks and the routine in full.

```console
git -C /path/to/pkgre/rust fetch origin main
# in a checkout of this repository, whose development shell builds the tool
export TMPDIR="$(mktemp -d /tmp/pkgre-self-publish.XXXXXX)"
nix develop -c cargo run --locked --release -p pkgre-rust -- self-publish /path/to/pkgre/rust rust/v0.5.0
nix develop -c cargo run --locked --release -p pkgre-rust -- self-publish /path/to/pkgre/rust rust/v0.5.0 --upload
```

The development shell provides the pinned Cargo that the routine packages with (it sets `PKGRE_CARGO`), and `TMPDIR` must name a directory that no Cargo configuration covers: the routine refuses to run Cargo below one, with a message that names the file it found, so a home that holds `~/.cargo/config.toml` needs a `TMPDIR` below `/tmp`, as above.

The upload is supported on Linux only, where the routine makes its own process non-dumpable while a token can be in reach; a dry run runs on every system.

The first command is the dry run: it checks everything an upload needs and reports what the upload would do, and it uploads nothing. The second adds `--upload`: it reads the crates.io token at a prompt (or from one line of standard input, though the prompt is recommended), uploads only the crates that crates.io still lacks, and waits until crates.io's index shows each of them.

The dry run builds the crates with Cargo's verification, and so does step 5 of an upload, so both run the build scripts and proc macros of the release and of its dependencies, as the user who runs the command. Give the token at the prompt rather than piping it: a piped token waits in standard input while that code runs.

The checkout must be clean and its `HEAD` must be contained in the remote-tracking `origin/main`, so that only a merged release is published. The routine never fetches: when the containment check fails, run `git fetch origin main` first. `<tag>` is a release tag of a self-publishing repository, such as `rust/v0.5.0`; when two self-publishing repositories use the same tag, `--git=<url>` chooses one, and without it such a tag is refused.

Each crate version of the release is reported in one of these states:

| State | Meaning |
|---|---|
| `published` | crates.io has the version with the recorded checksum; nothing to do |
| `published-yanked` | crates.io has the version and yanked it; the run reports it and never un-yanks it |
| `missing` | crates.io does not have the version; the dry run would upload it |
| `uploaded` | the run uploaded the version, and crates.io's index shows it |
| `abandoned` | `[[abandoned]]` records the version; the run skipped it |
| `different` | crates.io holds the version with another archive; the run refuses and uploads nothing |

The summary counts the release's crate versions per state, and the packages outside the release whose crates.io state the run checked, with the yanked dependencies among them.

**Resuming after a partial failure.** A run that failed halfway uploaded some crates and left the rest; run the same command again. A run uploads only what crates.io still lacks, so it carries on with the remaining crates, and a run whose crates are all published reads no token and uploads nothing.

**When crates.io cannot take a release.** A release can reach the `pkgre` registry and still fail on crates.io, for example when someone takes a name in the meantime, or when crates.io refuses a package for a rule the checks did not know. The tag cannot move, so the way forward is a new version: a pull request appends an `[[abandoned]]` record to `self-publish/crates-io.toml`, with the reason crates.io gave, which the checks accept and the routine never uploads, and the next release goes to both registries as usual. When the name itself is lost, a crate whose entries are all abandoned may get another crates.io name in `[names]`, for its later versions.

## Publish first-party/fork Git tag

Preconditions:

- credential-free HTTPS repository + immutable reviewed tag;
- selected package version = tag final component, optional `v` prefix;
- source manifest exactly `publish = ["pkgre"]`;
- every dependency explicitly `registry = "pkgre"`, including optional/dev/build/target-specific and a `path` dependency on a sibling; Git/crates.io/unknown sources fail; the retired alias `core`/`universe` of the same index is accepted only when reproducing an identity the catalog locked, never for a new publication; a `path` dependency is accepted only on a package the catalog publishes from the same repository and tag, at that package's own directory, required as exactly `=X.Y.Z` of that tag's version, and every other path dependency fails;
- a `path` dependency on a package the catalog locked already is taken from the registry index, which must serve that identity while the dependent is locked, and the packaged `Cargo.lock` must name its locked archive;
- catalog home:use `main/pkgre` for a new first-party/standalone-fork name; an existing mirrored-name fork stays in that name's original category, retains its `[mirror]` declaration, and adds a same-name `[publish]` declaration there;
- fork Cargo version must be unique across every locked mirror/publish identity for that name; never reuse `name + version` for different bytes/source;
- after the first published identity, retain the `[publish]` key + exact Git URL forever; removal empties `tags` rather than deleting/changing the declaration;
- the tag commits the `Cargo.lock` of the workspace root Cargo reports for it, which may sit below the checkout root; `cargo package --locked` accepts a workspace without one and resolves the dependency versions from the served index while it packages, so a tag that does not commit that lock is refused, and every registry package of each packaged `Cargo.lock` must then be the one it records, at the same source and checksum; no manifest declares `[patch]` or `[replace]`; no submodules, symlinks, unsafe/special paths, ambiguity, or generated dirty state;
- reproducible archive under Cargo `1.95.0`.

Workflow:

1. Review + merge release commit; create/push immutable tag after merge.
2. Add tag:

```toml
[categories.pkgre.publish.pkgre-rust]
git = "https://github.com/pkgre/pkgre"
tags = ["rust/v0.5.0"]
```

3. Set absolute `PKGRE_CARGO` or provide rustup toolchain `1.95.0`; reported version must match.
4. Run `lock`:fetch tag once; lock tag object/commit; discover package/path/version of every absent package of the tag; run isolated locked metadata; package the whole group twice; require byte identity for each archive; generate source rows; route dependencies; lock hashes.
5. Verify URL/tag/object/commit/package/path/Cargo + archive/row against reviewed tag.
6. Run `check`, no-op `lock`, verify exact Git route in downloads, render/verify/monotonicity; commit declaration/lock/catalog/objects together.

Every Git and Cargo process of the packaging starts from an empty environment and inherits only `PATH`, `TMPDIR`, the certificate variables, an isolated `CARGO_HOME`, and `RUSTC` pointing at the `rustc` beside the pinned `cargo`; no wrapper and no token variable reaches it. The packaging works in a temporary directory and refuses to run Cargo when that directory or any directory above it holds Cargo configuration, since such configuration could replace crates.io, so set `TMPDIR` to a directory that no Cargo configuration covers; a symbolic link on the way is resolved too, since Cargo follows it.

Self-publication normally uses prior immutable Rust indexer release. A schema/bootstrap release unreadable by its predecessor uses a reviewed build from the exact merged/tagged release commit,then locks the same tag. Rename transition:`pkgre-indexer`+`indexer/v*` remain immutable historical catalog identities;add `pkgre-rust` only after publishing the exact `rust/v0.5.0` tag,then update the production catalog+workflow pin in one reviewed release transaction.

## Remove version/tag

1. Remove exact version/tag from array; retain key in original registry/category.
2. Run `lock`.
3. Verify only intended packages become `active→removed`; rows remain; an unshared retained archive disappears; a `redirect` mirror archive set remains empty.
4. Rendered history retains `yanked = true`; reactivation forbidden.
5. Run `check`, no-op `lock`, render, `verify`, `verify-monotonic`; commit.
6. The serving gate `check-transition` accepts exactly this removal, so the service reloads the merged commit and serves the tombstone at once: the retained row renders as yanked, the tombstone route stays, and every other route is unchanged. It refuses a reactivated identity and every other change.

Changing a package name's registry/category home, changing any locked identity's source/checksum, changing a retained Git publisher URL, deleting a required declaration key, or re-adding a removed identity fails before fetch.

## Migrations

### Schema 2→3 historical (removed command)

```console
$ pkgre-rust migrate-v2-to-v3 registry-v2 registry-v3
```

`migrate-v2-to-v3` is no longer a command of the current tool, which answers `unknown command`. The procedure required a clean strict source + absent destination, authenticated inventory/objects/rows/hashes, inspected the old→new category mapping, ran check/render/verify/monotonicity with the historical tool revision, and left the source unchanged.

### Schema 3→4 single root main (removed command)

```console
$ pkgre-rust migrate-v3-to-v4 registry-v3 registry-v4
```

`migrate-v3-to-v4` is no longer a command of the current tool; this section records the historical procedure. Exact mapping:`universe/<category>→main/<category>`; `pkgre/tooling→main/pkgre`; files become `main.toml`/`main.lock`; index becomes root; download becomes `v1/main`. Migration preserves immutable artifacts/provenance, recomputes registry-dependent routed hashes, rewrites/rebinds admissions, strict-loads/renders/reproduces staging, installs absent destination only.

Validation with the historical tool revision, which still accepted schema 4 (the current tool rejects schema-4 catalogs, whose files lack `audience` and whose schema is unsupported):

```console
$ pkgre-rust check registry-v4
$ pkgre-rust lock registry-v4            # changed=false
$ pkgre-rust render registry-v4 site-next
$ pkgre-rust verify registry-v4 site-next
$ pkgre-rust verify-monotonic site-v3 site-next
```

Replace source catalog only after review + rerun at final path. Never hand-edit migration output.

### Schema 4→5 (production, completed)

```console
$ pkgre-rust migrate-v4-to-v5 registry-v4 registry-v5 \
    --git-tag-time=main/pkgre-indexer@indexer/v0.1.1=2026-08-22T17:57:02Z
# repeat --git-tag-time for every Git tag of the source
```

It parses the schema-4 generated locks, the schema-1 download catalog, and every registry + external category file strictly, refusing any registry or category file whose `schema` is not 4 by naming it; it rewrites those files to schema 5, asserts `audience = "public"`, rebuilds every lock with one `admitted-at` per package (crates.io row `pubtime`, or a required `--git-tag-time=<registry>/<name>@<tag>=<timestamp>` per Git tag, the operator's value, not verified), and replaces the download catalog with the schema-2 `redirect` delivery model. It writes only to an absent destination, and it migrates into a private staging directory beside that destination and renames it into place only after the output was strictly loaded, policy-checked, artifact-verified and test-rendered; a failed run removes the staging directory and leaves no destination. The source is never modified.

Validation:

```console
$ pkgre-rust check registry-v5
$ pkgre-rust lock registry-v5            # changed=false
$ pkgre-rust render registry-v5 site-next
$ pkgre-rust verify registry-v5 site-next
$ pkgre-rust verify-monotonic site-current site-next
```

`site-current` was the deployed schema-4 site; this revision renders schema 5 only. Both sides carry a schema-4 `release.json`, so `verify-monotonic` checks identity/topology monotonicity, not the catalog schema bump.

Retained delivery (completed for production):

```console
$ pkgre-rust migrate-retained-delivery registry-v5
$ pkgre-rust archive-inventory registry-v5 /absolute/path/to/archive-store/inventory.json
$ pkgre-rust archive-import /absolute/path/to/archive-store registry-v5
```

`migrate-retained-delivery` declares `delivery = "retained"` + rewrites `downloads.json` in place; it does not verify archive bodies. `archive-inventory` writes the canonical inventory of the migrated catalog's retained set. Place one `<sha256>.crate` for every inventoried object in the store, Git-tag archives included, and pass the store as an absolute path: `archive-import` requires the store inventory to equal the retained set, verifies every digest, and re-runs strict load/policy/artifact checks; a relative store path is rejected as escaping the store. Commit the imported `objects/crates/*` with the declarations. Never hand-edit migration output.

## Add future registry/category

Schema 5 allows additions without weakening prior identities:

1. Add `<alias>.toml` with exact index `sparse+https://rust.pkg.re/r/<alias>/`, categories, and inhabited package reservations; `main` remains.
2. Use an exact checksum-bearing template (router or same-host native) or one allowed single-source endpoint.
3. Ensure every cross-registry dependency category edge is explicit. Same-name resolution prefers local registry; a dependency originating in a third registry fails if multiple external homes exist.
4. Bootstrap/reconcile, then check/render/verify/monotonicity. The serving gate `check-transition` rejects an added registry, so a new alias needs a fresh accepted baseline/deployment before the service publishes it. New alias renders below `/r/<alias>/`; download route uses `/v1/<alias>/...`.
5. Add consumer Cargo alias only where that registry should be selected directly.

## Release gate

```console
$ pkgre-rust check registry
$ pkgre-rust lock registry                  # exact no-op
$ pkgre-rust render registry site-next
$ pkgre-rust verify registry site-next
$ pkgre-rust verify-monotonic site-current site-next
```

Require:`git diff --check`; tool format/test/lint/Nix checks; prior registries/categories/homes/packages retained; additions/removals intentional; active routes exact; mixed registries use their router or same-host native template; rendered inventory expected; protected CI passes; normal merge without force/bypass.

Serving reads the catalog directly:`pkgre-rust-serve` serves a validated in-memory snapshot from a static catalog path or the accepted Git ref it watches,so no rendered site is deployed. CI checks/renders/verifies and compares monotonicity;the serving origin accepts a new commit only when it fast-forwards the accepted commit, passes `check-transition`, builds a snapshot, and persists its accepted-ref record; a rejected or interrupted candidate keeps the last-known-good snapshot.

## Post-deployment verification

- Fetch root `https://rust.pkg.re/config.json`; require `https://rust.pkg.re/v1/main/{crate}/{version}/{sha256-checksum}`.
- Fetch rows across categories; compare checksums/routes/yank state with `release.json`.
- A `redirect` mirror route→`302` to static.crates.io; a `retained` mirror or Git route→`302` to `<first-party-origin>/crates/<sha256>.crate`,where `[registry] first-party-origin` is the serving instance's own configured origin (body mode serves that body with `200` instead). Download + verify SHA-256. A query, fragment, or percent-encoding other than the allowed `%2f`→`400`; an unknown canonical path (changed case or checksum)→`404`; unsupported method→`405`.
- Compare live release/downloads with committed candidate; require the exact projection, including routes for removed identities.
- Fresh Cargo home/cache + only `[registries.pkgre] index = "sparse+https://rust.pkg.re/"`; build `--locked` across mirror + Git packages; confirm `Cargo.lock` source is root URL.

Keep consumer validation private:no consumer names/paths/manifests/locks/dependency discovery/credentials/tokens in public logs/issues.

## Interrupted reconciliation

Failure normally removes staging + leaves original. Killed process can leave `.registry.pkgre-lock`, stage, backup.

1. Confirm no indexer process active.
2. Inspect catalog + siblings; preserve/restore last reviewed complete catalog if installation interrupted.
3. Remove only verified stale guard/disposable stage; retain backup until integrity confirmed.
4. Run `check`, compare Git, retry.
