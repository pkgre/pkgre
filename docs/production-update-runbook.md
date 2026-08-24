# Production mirror-update runbook

Purpose: admit crates.io mirror identities into the production `pkgre/rust` catalog with the exact indexer revision deployed by its main-branch Pages workflow; preserve read-only planning, checksum-bound review, transactional catalog mutation, reproducibility, monotonic publication, and curator control.

Scope: mirror updates only. First-party Git tags, removals, catalog migration, and category/name reservation use the procedures in [`workflows.md`](workflows.md). `automatic` means no separate approval assertion; every catalog change still requires complete source-control review + protected-branch CI. The actual catalog PR must remain unmerged until a curator explicitly reviews it.

## 1. Preconditions

Required:

- Linux; Bash; Nix with flakes; Git; GitHub CLI (`gh`); `curl`; `jq`; GNU `tar`; standard coreutils; public network access.
- Authenticated push access to the tooling/catalog remotes + authenticated `gh` access for PR creation.
- Existing clean catalog checkout at current `origin/main`; no local/untracked files.
- Existing clean tooling checkout able to resolve the workflow-pinned commit.
- Candidate package names already permanently reserved in the correct registry/category. Routing/category changes are separate reviewed work and invalidate an existing plan.
- Public-safe operation: no credentials, tokens, consuming-project names, private repository names, private paths, manifests, lockfiles, dependency-discovery output, or consumer metadata in commits, PR text, public issues, or published logs/artifacts. Keep local plans, notes, review trees, and logs private under the mode-`0700` workspace; approval-note text becomes public catalog evidence.

Start one Bash session:

```bash
set -euo pipefail
umask 077

CATALOG_REPO=/absolute/path/to/pkgre-rust
TOOL_REPO=/absolute/path/to/pkgre
CATALOG_DIR="$CATALOG_REPO/registry"
PAGES_WORKFLOW=.github/workflows/pages.yml

for command in sh git gh nix curl jq tar sha256sum stat realpath mktemp date sort comm sed grep awk cmp wc chmod cut mkdir tee cat; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done

git -C "$CATALOG_REPO" fetch --prune origin
test "$(git -C "$CATALOG_REPO" branch --show-current)" = main
test "$(git -C "$CATALOG_REPO" rev-parse HEAD)" = "$(git -C "$CATALOG_REPO" rev-parse origin/main)"
test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"
CATALOG_BASE="$(git -C "$CATALOG_REPO" rev-parse origin/main^{commit})"

INDEXER_REV="$(git -C "$CATALOG_REPO" show "$CATALOG_BASE:$PAGES_WORKFLOW" | sed -n 's/^[[:space:]]*ref:[[:space:]]*\([0-9a-f]\{40\}\)[[:space:]]*$/\1/p')"
test "$(printf '%s\n' "$INDEXER_REV" | grep -c .)" -eq 1
printf '%s\n' "$INDEXER_REV" | grep -Eq '^[0-9a-f]{40}$'
git -C "$TOOL_REPO" fetch origin "$INDEXER_REV"
test "$(git -C "$TOOL_REPO" rev-parse "$INDEXER_REV^{commit}")" = "$INDEXER_REV"

ARTIFACTS="$(mktemp -d "${TMPDIR:-/tmp}/pkgre-production-update.XXXXXX")"
chmod 0700 "$ARTIFACTS"
ARTIFACTS="$(realpath "$ARTIFACTS")"
case "$ARTIFACTS/" in
  "$CATALOG_REPO/"*|"$TOOL_REPO/"*) echo "artifact workspace must be outside both repositories" >&2; exit 1 ;;
esac
printf 'catalog-base=%s\nindexer-rev=%s\nstarted-at=%s\n' "$CATALOG_BASE" "$INDEXER_REV" "$(date -u +%FT%TZ)" > "$ARTIFACTS/session.txt"
```

`INDEXER_REV` is authority: read the one full commit SHA from the production catalog's main-branch Pages workflow. Never substitute local `HEAD`, tooling `main`, a tag, a PR head, or “latest.” Record `CATALOG_BASE` + `INDEXER_REV` in private session evidence and the public-safe PR summary.

## 2. Build + identify the deployed tool

Use a detached worktree outside the catalog and build the exact workflow pin:

```bash
TOOL_WORKTREE="$ARTIFACTS/tooling"
git -C "$TOOL_REPO" worktree add --detach "$TOOL_WORKTREE" "$INDEXER_REV"
nix build --print-build-logs --out-link "$ARTIFACTS/indexer-result" "$TOOL_WORKTREE#indexer" 2>&1 | tee "$ARTIFACTS/indexer-build.log"
INDEXER="$ARTIFACTS/indexer-result/bin/pkgre-indexer"
test -x "$INDEXER"
INDEXER_VERSION="$(nix eval --raw "$TOOL_WORKTREE#indexer.version")"
INDEXER_SHA256="$(sha256sum "$INDEXER" | cut -d' ' -f1)"
INDEXER_STORE_PATH="$(realpath "$ARTIFACTS/indexer-result")"
EXPECTED_CARGO_VERSION="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"[[:space:]]*$/\1/p' "$TOOL_WORKTREE/rust-toolchain.toml")"
test "$(printf '%s\n' "$EXPECTED_CARGO_VERSION" | grep -c .)" -eq 1
PKGRE_CARGO="$(nix develop "$TOOL_WORKTREE" --command sh -c 'printf "%s\n" "$PKGRE_CARGO"')"
test -x "$PKGRE_CARGO"
CARGO_VERSION="$($PKGRE_CARGO --version)"
printf '%s\n' "$CARGO_VERSION" | grep -Eq '^cargo [0-9]+\.[0-9]+\.[0-9]+ \([0-9a-f]{9} [0-9]{4}-[0-9]{2}-[0-9]{2}\)$'
test "$(printf '%s\n' "$CARGO_VERSION" | awk '{print $2}')" = "$EXPECTED_CARGO_VERSION"
export PKGRE_CARGO
printf 'indexer-version=%s\nindexer-binary-sha256=%s\nindexer-store-path=%s\ncargo=%s\ncargo-version=%s\n' "$INDEXER_VERSION" "$INDEXER_SHA256" "$INDEXER_STORE_PATH" "$PKGRE_CARGO" "$CARGO_VERSION" >> "$ARTIFACTS/session.txt"
"$INDEXER" check "$CATALOG_DIR" 2>&1 | tee "$ARTIFACTS/preflight-check.log"
test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"
```

`PKGRE_CARGO` comes from the exact revision's pinned Nix development shell, is version-checked, exported before any indexer command, and prevents Git-package lock convergence from falling back to ambient `rustup`. Build/version/hash mismatch, invalid catalog, dirty checkout, absent pin, Cargo mismatch, or pin drift → abort; do not fall forward to another indexer/Cargo revision.

## 3. Catalog read-only guard

Hash every tracked catalog file before/after planning and inspection; Git cleanliness detects added/deleted/untracked paths:

```bash
catalog_manifest() {
  local output=$1 path hash size
  (
    cd "$CATALOG_REPO"
    git ls-files -z -- registry | LC_ALL=C sort -z | while IFS= read -r -d '' path; do
      test -f "$path" && test ! -L "$path" || { echo "unsafe tracked catalog entry: $path" >&2; exit 1; }
      hash="$(sha256sum -- "$path" | cut -d' ' -f1)"
      size="$(stat -c '%s' -- "$path")"
      printf '%s\0%s\0%s\0' "$hash" "$size" "$path"
    done
  ) > "$output"
}

assert_catalog_clean() {
  test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"
}

catalog_manifest "$ARTIFACTS/catalog-before-plan.manifest"
assert_catalog_clean
```

All plans, approved-plan variants, approval notes, inert review trees, logs, patches, and rendered sites stay under mode-`0700` `$ARTIFACTS`, never under `registry/`. Every indexer output path must be absent; the commands fail rather than overwrite evidence.

## 4. Plan without mutation

Choose exactly one mode:

```bash
PLAN="$ARTIFACTS/plan.toml"

# Broad: latest eligible stable candidate per active compatibility lane.
"$INDEXER" update-plan "$CATALOG_DIR" "$PLAN" 2>&1 | tee "$ARTIFACTS/plan.log"

# Exact alternative: required for a new/inactive reserved name, prerelease, or 0.0.x identity.
# PACKAGE=example
# VERSION=1.2.3
# "$INDEXER" update-plan-exact "$CATALOG_DIR" "$PACKAGE" "$VERSION" "$PLAN" 2>&1 | tee "$ARTIFACTS/plan.log"
```

Selection rules:

- Every candidate: non-yanked + at least 30 exact days old at `evaluated-at`; future publication times fail.
- Broad planning: at most one latest eligible stable candidate per active lane (`major` for `major≥1`; `minor` for stable `0.minor.patch`, `minor>0`).
- Exact planning: one requested eligible identity; mandatory for new/inactive reservations, prereleases, and `0.0.x`.
- Every plan binds exact catalog fingerprint, fixed evaluation time, policy constants, sparse history, base/candidate rows, archive/dependency/API/source evidence, decision, and reasons. The raw crates.io API response hash is planning provenance; security-relevant version-scoped API fields are separately parsed and bound.
- Apply deadline: no more than seven exact days after `evaluated-at` (inclusive). Approval does not extend it; an expired plan requires complete replanning/reinspection/reapproval.

Prove planning read-only:

```bash
catalog_manifest "$ARTIFACTS/catalog-after-plan.manifest"
cmp "$ARTIFACTS/catalog-before-plan.manifest" "$ARTIFACTS/catalog-after-plan.manifest"
assert_catalog_clean
test -s "$PLAN"
```

Zero candidates → stop without a catalog PR. Any catalog byte/status change → preserve evidence, abort, and investigate.

## 5. Review every candidate

Read the complete canonical plan, not only command counts/logs. For every `[[candidates]]` entry record + inspect:

- Exact `registry`, `category`, `name`, `activity`, compatibility `lane`, `base`, `candidate`, age, sparse/history hashes, and dormant gap.
- `decision` + every `reason`; `blocked` makes the plan inadmissible. Fix routing/upstream evidence separately and create a new plan; never approve around a block.
- Candidate/base checksum + source-row hashes; candidate/base archive summaries; complete archive delta.
- Complete dependency delta including optional/dev/build/target-specific/renamed edges; every dependency's permanent home; exact category `may-depend-on` permission.
- crates.io API publisher/repository/Trusted Publishing evidence + discontinuities.
- Promoted source evidence: verified correspondence, unavailable reason, or mismatch. `source-mismatch` blocks. `source-unavailable` requires human judgment; never treat source correspondence as a substitute for reviewing crates.io archive bytes.

Materialize inert evidence for every exact candidate into a separate absent directory:

```bash
PACKAGE=exact-name
VERSION=exact.version
REVIEW="$ARTIFACTS/review-$PACKAGE-$VERSION"
"$INDEXER" update-inspect "$PLAN" "$PACKAGE" "$VERSION" "$REVIEW" 2>&1 | tee "$ARTIFACTS/inspect-$PACKAGE-$VERSION.log"
```

Repeat for every candidate. `update-inspect` downloads checksum-bound candidate/base archives, reparses them without extraction/execution, and requires equality with plan evidence. Then prove inspection did not touch the catalog:

```bash
catalog_manifest "$ARTIFACTS/catalog-after-inspection.manifest"
cmp "$ARTIFACTS/catalog-before-plan.manifest" "$ARTIFACTS/catalog-after-inspection.manifest"
assert_catalog_clean
```

For each review tree:

1. Read `README.txt` + complete `inspection.toml`; match candidate binding, identity, plan/catalog hashes, file list, file sizes/modes/hashes/binary flags, build surface, delta, and source evidence.
2. Recompute `sha256sum candidate.crate`; require the plan's `candidate.crate-sha256`. Do the same for `base.crate` when present.
3. List archive metadata without extraction or execution: `tar --list --verbose --file "$REVIEW/candidate.crate" | sed -n l`. Reconcile every regular member with `candidate-analysis.files`.
4. Review every regular member. Read one exact member without writing archive-controlled paths: `tar --extract --to-stdout --file "$REVIEW/candidate.crate" -- 'exact/root/member' | sed -n l`; use inert hex/string inspection for binary members. Never run Cargo, compiler/linker, tests, examples, binaries, build scripts, proc macros, repository hooks, or package code.
5. Inspect publisher `Cargo.toml.orig` + normalized `Cargo.toml`: identity/version/repository/license; package/build settings; libraries/binaries/examples/tests/benches; proc-macro status; features; targets; all dependency kinds/sources/versions/features.
6. Inspect `build.rs`, executable-mode files, proc-macro/native-link surface, bundled binaries/generated data, unsafe code, process spawning, filesystem/network behavior, environment/credential access, and licensing. Absence from the plan's bounded build-surface summary is not proof of benign runtime behavior.
7. For a base, compare every added/removed/changed file + mode and the dependency/build-surface/API/source deltas. For `full-archive`, review the complete candidate independently; for `source-delta`, still account for the complete candidate and scrutinize every delta.

Review disagreement, unexplained file/hash/mode, unsafe archive, suspicious code, unavailable evidence that cannot be judged safely, wrong route, or stale/mismatched evidence → abort. Never edit the plan.

## 6. Add required approval assertions

Decision handling:

| Decision | Approval action |
|---|---|
| `automatic` | No `update-approve`; retain ordinary evidence review + full catalog diff review. |
| `review-required`, active identity with meaningful base/archive delta | Exactly one `source-delta` assertion. |
| `review-required`, new/inactive identity or no meaningful base | Exactly one `full-archive` assertion. |
| `blocked` | Abort; approval impossible. |

Write one specific public-safe UTF-8 note ≤16 KiB per review-required candidate. State exact identity/checksum; review scope; files/delta/build surface; dependency/category result; publisher/repository/source result; material risks + why accepted. Generic “looks good” is insufficient. Keep the note outside the catalog; its trimmed text is copied into immutable admission evidence.

Chain absent approved-plan outputs for multiple candidates:

```bash
INPUT_PLAN="$PLAN"
NOTE="$ARTIFACTS/note-$PACKAGE-$VERSION.txt"
printf '%s\n' 'Specific public-safe review conclusion for this exact checksum-bound candidate.' > "$NOTE"
OUTPUT_PLAN="$ARTIFACTS/approved-001.toml"
"$INDEXER" update-approve "$INPUT_PLAN" "$OUTPUT_PLAN" "$PACKAGE" "$VERSION" full-archive "$NOTE" 2>&1 | tee "$ARTIFACTS/approve-$PACKAGE-$VERSION.log"
INPUT_PLAN="$OUTPUT_PLAN"

# Repeat with a new absent OUTPUT_PLAN for each remaining review-required candidate.
APPLY_PLAN="$INPUT_PLAN"
EXPECTED_CANDIDATES="$(grep -c '^\[\[candidates\]\]$' "$APPLY_PLAN")"
test "$EXPECTED_CANDIDATES" -gt 0
printf 'candidate-count=%s\n' "$EXPECTED_CANDIDATES" >> "$ARTIFACTS/session.txt"
```

Use `source-delta` instead of `full-archive` only when the table requires it. Automatic-only plan: `APPLY_PLAN="$PLAN"`, then run the same `EXPECTED_CANDIDATES` count/recording commands. Read the final plan and require exactly one correct assertion per review-required candidate, none for automatic candidates, no blocked candidates, and no evidence changes other than approval assertions. `EXPECTED_CANDIDATES` must equal the number of canonical top-level `[[candidates]]` entries; retain it for generated-path and release-count proofs.

## 7. Reconfirm base + create the catalog branch

Do not create/mutate a catalog branch until evidence review is complete:

```bash
git -C "$CATALOG_REPO" fetch --prune origin
CURRENT_MAIN="$(git -C "$CATALOG_REPO" rev-parse origin/main^{commit})"
test "$CURRENT_MAIN" = "$CATALOG_BASE" || { echo "catalog main drifted; discard plan and restart" >&2; exit 1; }
catalog_manifest "$ARTIFACTS/catalog-before-apply.manifest"
cmp "$ARTIFACTS/catalog-before-plan.manifest" "$ARTIFACTS/catalog-before-apply.manifest"
assert_catalog_clean

BRANCH=registry/update-descriptive-name
git -C "$CATALOG_REPO" switch --create "$BRANCH" "$CATALOG_BASE"
```

Main/catalog drift → abort and restart from the new base. Never rebase an evidence-bound plan onto changed catalog bytes.

## 8. Apply transactionally

```bash
"$INDEXER" update-apply "$CATALOG_DIR" "$APPLY_PLAN" 2>&1 | tee "$ARTIFACTS/apply.log"
```

Apply requirements/enforcement:

- Catalog fingerprint exactly equals the plan.
- Plan is nonfuture + ≤7 days old.
- Complete evidence is recomputed for only the planned identities at original `evaluated-at`; upstream/candidate/evidence drift fails rather than substituting a newer release. The sole upstream exception is the raw crates.io API response hash because responses contain mutable non-decision fields; planned base/candidate identities and checksums must still agree with the current API response, and parsed publishers, repositories, and Trusted Publishing evidence must remain identical.
- All decisions/approvals valid; blocked candidates rejected.
- Whole replacement catalog staged, strictly loaded, object-verified, test-rendered, then atomically installed with rollback.
- Human declarations, generated locks, source-row objects, and immutable admission records installed together; no hand editing.

Failure → do not repair locks/rows/admissions manually. Confirm recovery per `workflows.md`, restore a clean base if needed, and replan when required.

## 9. Audit the complete catalog diff

Expose newly created files to `git diff` without staging their contents yet:

```bash
git -C "$CATALOG_REPO" add --intent-to-add -- registry
git -C "$CATALOG_REPO" status --short
OUTSIDE="$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all | grep -vE '^.. registry/' || true)"
test -z "$OUTSIDE" || { printf '%s\n' "$OUTSIDE" >&2; exit 1; }
git -C "$CATALOG_REPO" diff --check
git -C "$CATALOG_REPO" diff --stat -- registry
git -C "$CATALOG_REPO" diff --binary --full-index -- registry > "$ARTIFACTS/catalog.patch"
test -s "$ARTIFACTS/catalog.patch"
git -C "$CATALOG_REPO" diff --name-only --diff-filter=A -- registry/objects/rows | LC_ALL=C sort > "$ARTIFACTS/new-rows.txt"
git -C "$CATALOG_REPO" diff --name-only --diff-filter=A -- registry/_reviews/admissions | LC_ALL=C sort > "$ARTIFACTS/new-admissions.txt"
test "$(wc -l < "$ARTIFACTS/new-rows.txt")" -eq "$EXPECTED_CANDIDATES"
test "$(wc -l < "$ARTIFACTS/new-admissions.txt")" -eq "$EXPECTED_CANDIDATES"
test -z "$(git -C "$CATALOG_REPO" diff --name-only -- registry/objects/crates)"
```

Account for every byte/path:

- Only intended category declarations change; each candidate adds its exact version under its permanent reserved name.
- Generated registry lock adds one active crates.io identity per candidate with exact route/version/archive/source-row/routed-row hashes + `admission-sha256`.
- Exactly one new canonical `objects/rows/<source-row-sha256>.json` per candidate; row checksum/identity/dependencies match the plan and declaration.
- Exactly one new canonical `_reviews/admissions/<candidate-binding-sha256>.toml` per candidate; filename matches candidate binding; record identity/route/checksum/row hash/decision/reasons/approval match the final plan; lock `admission-sha256` points back to it.
- Mirror admissions add no `objects/crates/*`; mirror bytes remain served by `https://static.crates.io/crates` and are integrity-bound by curated row checksum.
- No registry/category topology, `may-depend-on`, index URL, download URL, existing identity, existing object, tombstone, first-party archive, landing page, workflow, or unrelated file changes.

Unexplained churn, missing/extra row/admission, retained mirror archive, route/hash mismatch, or unrelated change → abort; do not normalize by hand.

## 10. Prove validity + convergence

```bash
"$INDEXER" check "$CATALOG_DIR" 2>&1 | tee "$ARTIFACTS/check.log"
git -C "$CATALOG_REPO" diff --binary --full-index -- registry > "$ARTIFACTS/diff-before-lock.patch"
"$INDEXER" lock "$CATALOG_DIR" 2>&1 | tee "$ARTIFACTS/lock.log"
grep -Eq 'changed=false' "$ARTIFACTS/lock.log"
git -C "$CATALOG_REPO" diff --binary --full-index -- registry > "$ARTIFACTS/diff-after-lock.patch"
cmp "$ARTIFACTS/diff-before-lock.patch" "$ARTIFACTS/diff-after-lock.patch"
git -C "$CATALOG_REPO" diff --check
```

The second lock must report `changed=false` + preserve the exact complete diff. Any mutation/failure means nonconvergence → abort.

## 11. Render, reproduce, and compare the release

All output paths must be absent:

```bash
SITE_NEXT="$ARTIFACTS/site-next"
SITE_CURRENT="$ARTIFACTS/site-current"
"$INDEXER" render "$CATALOG_DIR" "$SITE_NEXT" 2>&1 | tee "$ARTIFACTS/render.log"
"$INDEXER" verify "$CATALOG_DIR" "$SITE_NEXT" 2>&1 | tee "$ARTIFACTS/verify.log"
mkdir "$SITE_CURRENT"
curl --fail --silent --show-error --retry 3 https://rust.pkg.re/release.json --output "$SITE_CURRENT/release.json"
"$INDEXER" verify-monotonic "$SITE_CURRENT" "$SITE_NEXT" 2>&1 | tee "$ARTIFACTS/verify-monotonic.log"

jq -S '.registries' "$SITE_CURRENT/release.json" > "$ARTIFACTS/registries-current.json"
jq -S '.registries' "$SITE_NEXT/release.json" > "$ARTIFACTS/registries-next.json"
cmp "$ARTIFACTS/registries-current.json" "$ARTIFACTS/registries-next.json"
jq -cS '.names[]' "$SITE_CURRENT/release.json" | LC_ALL=C sort > "$ARTIFACTS/names-current.ndjson"
jq -cS '.names[]' "$SITE_NEXT/release.json" | LC_ALL=C sort > "$ARTIFACTS/names-next.ndjson"
cmp "$ARTIFACTS/names-current.ndjson" "$ARTIFACTS/names-next.ndjson"
jq -cS '.packages[]' "$SITE_CURRENT/release.json" | LC_ALL=C sort > "$ARTIFACTS/packages-current.ndjson"
jq -cS '.packages[]' "$SITE_NEXT/release.json" | LC_ALL=C sort > "$ARTIFACTS/packages-next.ndjson"
comm -23 "$ARTIFACTS/packages-current.ndjson" "$ARTIFACTS/packages-next.ndjson" > "$ARTIFACTS/packages-missing.ndjson"
comm -13 "$ARTIFACTS/packages-current.ndjson" "$ARTIFACTS/packages-next.ndjson" > "$ARTIFACTS/packages-added.ndjson"
test ! -s "$ARTIFACTS/packages-missing.ndjson"
CURRENT_NAME_COUNT="$(jq '.names|length' "$SITE_CURRENT/release.json")"
NEXT_NAME_COUNT="$(jq '.names|length' "$SITE_NEXT/release.json")"
CURRENT_PACKAGE_COUNT="$(jq '.packages|length' "$SITE_CURRENT/release.json")"
NEXT_PACKAGE_COUNT="$(jq '.packages|length' "$SITE_NEXT/release.json")"
ADDED_PACKAGE_COUNT="$(wc -l < "$ARTIFACTS/packages-added.ndjson")"
test "$NEXT_NAME_COUNT" -eq "$CURRENT_NAME_COUNT"
test "$NEXT_PACKAGE_COUNT" -eq "$((CURRENT_PACKAGE_COUNT + EXPECTED_CANDIDATES))"
test "$ADDED_PACKAGE_COUNT" -eq "$EXPECTED_CANDIDATES"
printf 'current names=%s packages=%s\nnext names=%s packages=%s\nadded packages=%s expected candidates=%s\n' "$CURRENT_NAME_COUNT" "$CURRENT_PACKAGE_COUNT" "$NEXT_NAME_COUNT" "$NEXT_PACKAGE_COUNT" "$ADDED_PACKAGE_COUNT" "$EXPECTED_CANDIDATES"
cat "$ARTIFACTS/packages-added.ndjson"
```

Require:

- `verify` exact byte-for-byte reproduction.
- `verify-monotonic` success; every prior identity retained unchanged.
- Exact registry/category topology, index URLs, download URLs, + category `may-depend-on` arrays unchanged (`.registries` byte-equivalent after canonical JSON sorting).
- Exact reserved name inventory unchanged (`.names` equivalent).
- Package count increases by exactly admitted candidate count; `packages-added.ndjson` contains only reviewed identities with exact category/checksum/row/source/yank fields; `packages-missing.ndjson` empty.
- Complete rendered tree contains only expected registry output; mirror rows route dependencies only to canonical curated registries and config keeps universe download at crates.io.

Any release/count/topology/download mismatch, missing prior package, unexpected addition, failed reproduction, or failed monotonicity → abort.

## 12. Stage + commit the atomic catalog change

```bash
git -C "$CATALOG_REPO" add -- registry
git -C "$CATALOG_REPO" diff --cached --check
test -z "$(git -C "$CATALOG_REPO" diff --name-only --cached -- . ':(exclude)registry/**')"
git -C "$CATALOG_REPO" diff --cached --binary --full-index -- registry > "$ARTIFACTS/staged.patch"
cmp "$ARTIFACTS/diff-after-lock.patch" "$ARTIFACTS/staged.patch"
git -C "$CATALOG_REPO" diff --quiet
git -C "$CATALOG_REPO" diff --cached --stat
```

Commit declaration + lock + row + admission evidence together. Follow repository attribution policy: `Assisted-by:` lists only models/specialized analysis tools that materially contributed; never use `Co-Authored-By:` or agent-generated `Signed-off-by:`.

```bash
git -C "$CATALOG_REPO" commit -m "registry: admit reviewed mirror update" -m "Assisted-by: actual-model-id"
test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"
```

## 13. Push + open the curator-review PR

Create `$ARTIFACTS/pr-body.md` before pushing; include the public-safe fields below and inspect the complete file. Then:

```bash
git -C "$CATALOG_REPO" push --set-upstream origin "$BRANCH"
cd "$CATALOG_REPO"
PR_BODY="$ARTIFACTS/pr-body.md"
test -s "$PR_BODY"
PR_URL="$(gh pr create --base main --head "$BRANCH" --title 'registry: admit reviewed mirror update' --body-file "$PR_BODY")"
printf '%s\n' "$PR_URL"
gh pr checks --watch "$PR_URL"
```

Public PR body: exact candidate identities; catalog base SHA; deployed indexer SHA + binary hash/version; decisions/reasons; approval scope; archive/dependency/build/source conclusions; exact generated path summary; `check`/no-op `lock`/`verify`/`verify-monotonic` results; release count delta. Exclude artifact paths, raw plans/logs, credentials, and all private consumer data.

CI must pass. Do not enable auto-merge, do not merge the actual catalog/index update PR, and do not bypass protection. Ask the curator to review the PR; retain private artifacts until review resolves. If `origin/main`, upstream evidence, or the PR diff changes, rerun the applicable workflow from a fresh plan rather than force-updating trusted evidence.

## 14. Abort matrix

Abort + preserve evidence on any of:

- Wrong/non-full tooling pin; pin/build/version/hash uncertainty; attempted fallback to unpinned tooling.
- Dirty/stale catalog base; catalog bytes/status changed during planning/inspection; main drift before apply.
- Expired/future/noncanonical plan; zero intended candidates; unexpected identity; upstream/catalog/evidence drift.
- `blocked` decision; source mismatch; unknown dependency home; forbidden category edge; wrong registry/category/source class.
- Unexplained archive file/hash/mode/binary/build surface/dependency/API/source evidence; unsafe or unacceptable package behavior/license.
- Missing/wrong/duplicate approval; vague/private note; wrong `source-delta`/`full-archive` scope.
- Apply/recovery error; hand-edit temptation; unexpected file/object/admission/lock/declaration churn; any mirror `.crate` addition.
- Failed `check`; second `lock` not `changed=false`; diff changed after lock; failed render/reproduction/monotonicity.
- Registry/category/index/download/name topology drift; unexpected package count/identity/hash/yank/source change.
- Secret/private-data exposure; CI failure; protected-base change; curator rejects or requests material changes.

No failure permits switching candidates, relaxing policy, editing generated state, bypassing review, or merging the catalog PR automatically.
