# Production mirror-admission runbook

Purpose:execute one live crates.io mirror batch against `pkgre/rust` with the exact `pkgre-indexer` revision deployed by the catalog's main-branch Pages workflow; leave one complete registry-index PR unmerged for curator review.

Scope:routine existing-package mirror updates. New/inactive names, prereleases, stable `0.0.x`, first-party Git tags, removals, name/category changes, and topology changes use targeted procedures in [`workflows.md`](workflows.md). `automatic` and `review-required` are review-priority labels, not merge authority; the protected review of the complete generated registry PR authorizes every admitted identity. Never auto-merge the final registry-index PR.

## 1. Preconditions + immutable inputs

Required:Linux; Bash; Nix flakes; Git; authenticated GitHub CLI; `curl`; `jq`; `sha256sum`; GNU coreutils/tar; public network; clean checkouts; push/PR permission. Privacy:never publish credentials/tokens, consumer names, private repository/path/manifest/lock/dependency data, or raw private logs. Transient manifests, inspections, logs, patches, and rendered trees stay in a mode-`0700` external workspace.

Start one Bash session; set absolute paths if different:

```bash
set -euo pipefail
umask 077

CATALOG_REPO=/absolute/path/to/pkgre-rust
TOOL_REPO=/absolute/path/to/pkgre
CATALOG_DIR="$CATALOG_REPO/registry"
PAGES_WORKFLOW=.github/workflows/pages.yml
BATCH="$(date -u +%F)-bulk"
BRANCH="registry/$BATCH"

for command in sh git gh nix curl jq sha256sum stat realpath mktemp date sort comm sed grep awk cmp wc chmod cut head mkdir tee tar find uniq; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done
printf '%s\n' "$BATCH" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,126}[a-z0-9])?$'

git -C "$CATALOG_REPO" fetch --prune origin
git -C "$TOOL_REPO" fetch --prune origin
test "$(git -C "$CATALOG_REPO" branch --show-current)" = main
test "$(git -C "$CATALOG_REPO" rev-parse HEAD)" = "$(git -C "$CATALOG_REPO" rev-parse origin/main)"
test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"
CATALOG_BASE="$(git -C "$CATALOG_REPO" rev-parse origin/main^{commit})"

INDEXER_REV="$(git -C "$CATALOG_REPO" show "$CATALOG_BASE:$PAGES_WORKFLOW" | sed -n 's/^[[:space:]]*ref:[[:space:]]*\([0-9a-f]\{40\}\)[[:space:]]*$/\1/p')"
test "$(printf '%s\n' "$INDEXER_REV" | grep -c .)" -eq 1
printf '%s\n' "$INDEXER_REV" | grep -Eq '^[0-9a-f]{40}$'
git -C "$TOOL_REPO" fetch origin "$INDEXER_REV"
test "$(git -C "$TOOL_REPO" rev-parse "$INDEXER_REV^{commit}")" = "$INDEXER_REV"

ARTIFACTS="$(mktemp -d "${TMPDIR:-/tmp}/pkgre-production-admission.XXXXXX")"
chmod 0700 "$ARTIFACTS"
ARTIFACTS="$(realpath "$ARTIFACTS")"
case "$ARTIFACTS/" in "$CATALOG_REPO/"*|"$TOOL_REPO/"*) echo 'artifact workspace must be outside both repositories' >&2; exit 1;; esac
test ! -e "$CATALOG_DIR/admissions/$BATCH.toml"
test ! -e "$CATALOG_DIR/admissions/$BATCH.lock"
printf 'catalog-base=%s\nindexer-rev=%s\nbatch=%s\nstarted-at=%s\n' "$CATALOG_BASE" "$INDEXER_REV" "$BATCH" "$(date -u +%FT%TZ)" > "$ARTIFACTS/session.txt"
```

If `$BATCH` already exists, choose a new descriptive lowercase kebab-case suffix; never overwrite/reuse an admission filename. `CATALOG_BASE` + the exact 40-hex `INDEXER_REV` are immutable session inputs. Never substitute local tooling `HEAD`, a tag, a PR head, or “latest.”

## 2. Build + identify the deployed indexer

Build the exact workflow pin in the external workspace; obtain Cargo from that revision's Nix shell:

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

Abort on pin/build/version/Cargo mismatch, invalid catalog, dirty checkout, or fallback temptation. All indexer commands below use this `$INDEXER` and exported `$PKGRE_CARGO`.

## 3. Prove planning/inspection read-only

Hash every tracked catalog file; Git status separately detects additions/deletions/untracked paths:

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
assert_catalog_clean() { test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"; }

catalog_manifest "$ARTIFACTS/catalog-before-plan.manifest"
assert_catalog_clean
```

Every transient output path must be absent. Do not place the template under `registry/`; `update-apply` installs the final exact manifest only after recomputation.

## 4. Generate one broad directly-applyable template

Broad mode scans every active mirror compatibility lane and chooses at most the latest eligible stable release per lane:

```bash
MANIFEST="$ARTIFACTS/$BATCH.toml"
PLAN_LOG="$ARTIFACTS/plan.log"
"$INDEXER" update-plan "$CATALOG_DIR" "$MANIFEST" 2>&1 | tee "$PLAN_LOG"

test -f "$MANIFEST"
catalog_manifest "$ARTIFACTS/catalog-after-plan.manifest"
cmp "$ARTIFACTS/catalog-before-plan.manifest" "$ARTIFACTS/catalog-after-plan.manifest"
assert_catalog_clean

AUTOMATIC="$(grep -c 'planned update candidate.*decision=Automatic' "$PLAN_LOG" || true)"
REVIEW_REQUIRED="$(grep -c 'planned update candidate.*decision=ReviewRequired' "$PLAN_LOG" || true)"
BLOCKED="$(grep -c 'planned update candidate.*decision=Blocked' "$PLAN_LOG" || true)"
TOTAL_LOGGED="$(grep -c 'planned update candidate' "$PLAN_LOG" || true)"
EXPECTED_CANDIDATES="$(grep -c '^\[\[admit\]\]$' "$MANIFEST" || true)"
test "$TOTAL_LOGGED" -eq "$((AUTOMATIC + REVIEW_REQUIRED + BLOCKED))"
test "$EXPECTED_CANDIDATES" -eq "$((AUTOMATIC + REVIEW_REQUIRED))"
printf 'automatic=%s\nreview-required=%s\nblocked=%s\nlogged=%s\nmanifest=%s\n' "$AUTOMATIC" "$REVIEW_REQUIRED" "$BLOCKED" "$TOTAL_LOGGED" "$EXPECTED_CANDIDATES" | tee "$ARTIFACTS/counts.txt"
```

Selection/guardrails:

- candidate non-yanked + at least 30×24 hours old at command UTC time; future timestamps fail;
- broad mode only active stable lanes: `major` for `major≥1`; `minor` for stable `0.minor.patch` where `minor>0`;
- dormant wake-up = first ≥365-day adjacent publication gap after locked base; all upstream rows, including yanked/prerelease, count as activity;
- evidence = complete sparse history, exact base/candidate rows + checksum-verified archives, bounded archive/build/dependency delta, version-scoped crates.io API facts, and promoted public-source correspondence;
- `automatic`:no escalation reason; included;
- `review-required`:new/inactive/dormant/new-dependency/build-surface/publisher/repository/source-unavailable escalation; included and directly applyable;
- `blocked`:unknown dependency home, forbidden category edge, or source mismatch; logged but omitted; never add it manually.

`EXPECTED_CANDIDATES=0` → stop without branch/catalog PR. `BLOCKED>0` → preserve log, verify every blocked identity is absent from the manifest, report/fix separately; the nonblocked batch may proceed only if its scope remains intended. Count mismatch/catalog mutation → abort.

## 5. Review scope without per-crate ceremony

Read the complete manifest + every structured candidate log line:

```bash
cat "$MANIFEST"
grep 'planned update candidate' "$PLAN_LOG" | tee "$ARTIFACTS/candidates.log"
grep 'decision=ReviewRequired\|decision=Blocked' "$PLAN_LOG" | tee "$ARTIFACTS/escalated.log" || true
```

Verify each requested name/version/category is intended; remove unwanted complete `[[admit]]` blocks while preserving canonical ordering/format. Do not add a blocked identity. Prioritize review-required identities, especially `SourceUnavailable`, `DormantWakeup`, publisher/repository discontinuity, build/proc-macro/native surface change, new dependency packages, and unusually large/risky projects. A generated template needs no repetitive approval notes.

Optional inert inspection for any exact manifest request:

```bash
PACKAGE=exact-package
VERSION=exact.version
REVIEW="$ARTIFACTS/review-$PACKAGE-$VERSION"
"$INDEXER" update-inspect "$CATALOG_DIR" "$MANIFEST" "$PACKAGE" "$VERSION" "$REVIEW" 2>&1 | tee "$ARTIFACTS/inspect-$PACKAGE-$VERSION.log"
```

Inspection re-plans one exact request, emits checksum-bound `candidate.crate`, optional `base.crate`, `inspection.toml`, and `README.txt`, and never executes Cargo/compiler/package/repository code. Treat archives as untrusted. Review relevant manifest/build/dependency/source fields and archive members with inert tools only; never run build scripts, proc macros, tests, examples, binaries, or hooks.

Optional typed evidence belongs under its request and must preserve canonical TOML:

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

`manual-source-delta` must match the exact recomputed base. Evidence notes:public-safe, specific, trimmed, nonempty UTF-8, ≤16 KiB. Unknown evidence fails. Optional evidence strengthens the record; absence does not make the generated template invalid.

After any edit, recount + prove read-only:

```bash
EXPECTED_CANDIDATES="$(grep -c '^\[\[admit\]\]$' "$MANIFEST" || true)"
test "$EXPECTED_CANDIDATES" -gt 0
catalog_manifest "$ARTIFACTS/catalog-after-review.manifest"
cmp "$ARTIFACTS/catalog-before-plan.manifest" "$ARTIFACTS/catalog-after-review.manifest"
assert_catalog_clean
printf 'final-manifest-count=%s\n' "$EXPECTED_CANDIDATES" >> "$ARTIFACTS/session.txt"
```

Manifest parse/canonicality is enforced again by inspection/apply. Suspicious/unexplained evidence, unsafe archive, wrong route, source mismatch, or unacceptable package behavior/license → remove candidate or abort; never weaken policy/generated facts.

## 6. Reconfirm base + create catalog branch

Do not mutate/create the catalog branch until template review is complete:

```bash
git -C "$CATALOG_REPO" fetch --prune origin
CURRENT_MAIN="$(git -C "$CATALOG_REPO" rev-parse origin/main^{commit})"
test "$CURRENT_MAIN" = "$CATALOG_BASE" || { echo 'catalog main drifted; restart from a fresh plan' >&2; exit 1; }
catalog_manifest "$ARTIFACTS/catalog-before-apply.manifest"
cmp "$ARTIFACTS/catalog-before-plan.manifest" "$ARTIFACTS/catalog-before-apply.manifest"
assert_catalog_clean
git -C "$CATALOG_REPO" switch --create "$BRANCH" "$CATALOG_BASE"
```

Never rebase/carry a prepared manifest onto an unreviewed catalog base; restart planning when main changes.

## 7. Apply once transactionally

```bash
"$INDEXER" update-apply "$CATALOG_DIR" "$MANIFEST" 2>&1 | tee "$ARTIFACTS/apply.log"
grep -Eq "packages_added=$EXPECTED_CANDIDATES([^0-9]|$)" "$ARTIFACTS/apply.log"
```

Apply behavior:load canonical human requests; use current UTC policy clock; re-fetch/recompute every exact identity; reject young/yanked/locked/blocked/route-invalid/evidence-invalid requests; never substitute versions; calculate one generated batch lock; stage declarations, source rows, registry locks, exact human manifest, and generated lock; strict-load/object-verify/test-render complete staged catalog; atomically install with rollback. Failure → do not hand-edit generated state; restore/verify clean base and replan when needed.

## 8. Audit the exact catalog diff + batch binding

Make added files visible to ordinary `git diff` without staging their content:

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
git -C "$CATALOG_REPO" diff --name-only --diff-filter=A -- registry/admissions | LC_ALL=C sort > "$ARTIFACTS/new-admission-files.txt"
test "$(wc -l < "$ARTIFACTS/new-rows.txt")" -eq "$EXPECTED_CANDIDATES"
test "$(wc -l < "$ARTIFACTS/new-admission-files.txt")" -eq 2
test "$(grep -c "^registry/admissions/$BATCH.toml$" "$ARTIFACTS/new-admission-files.txt")" -eq 1
test "$(grep -c "^registry/admissions/$BATCH.lock$" "$ARTIFACTS/new-admission-files.txt")" -eq 1
test -z "$(git -C "$CATALOG_REPO" diff --name-only -- registry/objects/crates)"

BATCH_LOCK="$CATALOG_DIR/admissions/$BATCH.lock"
BATCH_HASH="$(sha256sum "$BATCH_LOCK" | cut -d' ' -f1)"
git -C "$CATALOG_REPO" diff --unified=0 -- 'registry/*.lock' | sed -n 's/^+admission-sha256 = "\([0-9a-f]\{64\}\)"$/\1/p' > "$ARTIFACTS/new-admission-hashes.txt"
test "$(wc -l < "$ARTIFACTS/new-admission-hashes.txt")" -eq "$EXPECTED_CANDIDATES"
test "$(LC_ALL=C sort -u "$ARTIFACTS/new-admission-hashes.txt" | wc -l)" -eq 1
test "$(head -n 1 "$ARTIFACTS/new-admission-hashes.txt")" = "$BATCH_HASH"
printf 'batch-lock-sha256=%s\n' "$BATCH_HASH" >> "$ARTIFACTS/session.txt"
```

Account for every path/byte:

- only intended category declaration arrays gain the exact manifest versions;
- root generated registry locks gain exactly one active crates.io identity/request with exact route/archive/source-row/routed-row hashes + shared `$BATCH_HASH`;
- exactly one new canonical source-row object/request;
- exactly one immutable `admissions/$BATCH.toml` + `admissions/$BATCH.lock` pair for the complete batch;
- no `objects/crates/*` diff:mirror `.crate` bytes are verified then discarded and Cargo downloads through `https://static.crates.io/crates`;
- no topology, `may-depend-on`, registry URL/download, name-home, prior identity/object, first-party archive, workflow/site, or unrelated change.

Unexpected churn/count/hash/route/object mismatch → abort; never normalize generated files by hand.

## 9. Prove catalog validity + convergence

```bash
"$INDEXER" check "$CATALOG_DIR" 2>&1 | tee "$ARTIFACTS/check.log"
git -C "$CATALOG_REPO" diff --binary --full-index -- registry > "$ARTIFACTS/diff-before-lock.patch"
"$INDEXER" lock "$CATALOG_DIR" 2>&1 | tee "$ARTIFACTS/lock.log"
grep -Eq 'changed=false' "$ARTIFACTS/lock.log"
git -C "$CATALOG_REPO" diff --binary --full-index -- registry > "$ARTIFACTS/diff-after-lock.patch"
cmp "$ARTIFACTS/diff-before-lock.patch" "$ARTIFACTS/diff-after-lock.patch"
git -C "$CATALOG_REPO" diff --check
```

Second `lock` must be exact no-op. Optional idempotence check:rerun `update-apply` with the identical external manifest; it must report `changed=false` and preserve the exact diff. Do not rerun under a different manifest with the same filename.

## 10. Render, reproduce, compare live release

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
LC_ALL=C comm -23 "$ARTIFACTS/packages-current.ndjson" "$ARTIFACTS/packages-next.ndjson" > "$ARTIFACTS/packages-missing.ndjson"
LC_ALL=C comm -13 "$ARTIFACTS/packages-current.ndjson" "$ARTIFACTS/packages-next.ndjson" > "$ARTIFACTS/packages-added.ndjson"
test ! -s "$ARTIFACTS/packages-missing.ndjson"
CURRENT_NAME_COUNT="$(jq '.names|length' "$SITE_CURRENT/release.json")"
NEXT_NAME_COUNT="$(jq '.names|length' "$SITE_NEXT/release.json")"
CURRENT_PACKAGE_COUNT="$(jq '.packages|length' "$SITE_CURRENT/release.json")"
NEXT_PACKAGE_COUNT="$(jq '.packages|length' "$SITE_NEXT/release.json")"
ADDED_PACKAGE_COUNT="$(wc -l < "$ARTIFACTS/packages-added.ndjson")"
test "$NEXT_NAME_COUNT" -eq "$CURRENT_NAME_COUNT"
test "$NEXT_PACKAGE_COUNT" -eq "$((CURRENT_PACKAGE_COUNT + EXPECTED_CANDIDATES))"
test "$ADDED_PACKAGE_COUNT" -eq "$EXPECTED_CANDIDATES"
printf 'current names=%s packages=%s\nnext names=%s packages=%s\nadded=%s expected=%s\n' "$CURRENT_NAME_COUNT" "$CURRENT_PACKAGE_COUNT" "$NEXT_NAME_COUNT" "$NEXT_PACKAGE_COUNT" "$ADDED_PACKAGE_COUNT" "$EXPECTED_CANDIDATES" | tee "$ARTIFACTS/release-counts.txt"
cat "$ARTIFACTS/packages-added.ndjson"
```

Require byte reproduction, monotonicity, unchanged registry/category/index/download/allowlist topology, unchanged name inventory, no missing package, and exact intended additions/count. Any live/current-base mismatch → investigate/restart; do not bypass.

## 11. Stage + commit one atomic registry change

```bash
git -C "$CATALOG_REPO" add -- registry
git -C "$CATALOG_REPO" diff --cached --check
test -z "$(git -C "$CATALOG_REPO" diff --name-only --cached -- . ':(exclude)registry/**')"
git -C "$CATALOG_REPO" diff --cached --binary --full-index -- registry > "$ARTIFACTS/staged.patch"
cmp "$ARTIFACTS/diff-after-lock.patch" "$ARTIFACTS/staged.patch"
git -C "$CATALOG_REPO" diff --quiet
git -C "$CATALOG_REPO" diff --cached --stat

git -C "$CATALOG_REPO" commit -m "registry: admit $BATCH mirror updates" -m 'Assisted-by: actual-contributing-model-ids'
test -z "$(git -C "$CATALOG_REPO" status --porcelain=v1 --untracked-files=all)"
```

Commit exact declarations + root locks + row objects + admission pair together. Attribution:one `Assisted-by:` trailer listing only actual contributing models/specialized analysis tools; never `Co-Authored-By:` or agent-generated `Signed-off-by:`.

## 12. Push + open final curator-review PR

Create a public-safe body. Include:batch manifest link/path; complete identity list or exact generated diff reference; candidate/automatic/review-required/blocked counts; catalog base SHA; deployed indexer SHA/version/binary SHA-256; review prioritization/optional evidence performed; admission-pair/shared-hash proof; exact added row/package counts; `check`; second-lock no-op; render/verify/verify-monotonic; no mirror archive objects; issue-closing statement when applicable. Exclude transient paths/raw logs/private data.

```bash
git -C "$CATALOG_REPO" push --set-upstream origin "$BRANCH"
PR_BODY="$ARTIFACTS/pr-body.md"
test -s "$PR_BODY"
cd "$CATALOG_REPO"
PR_URL="$(gh pr create --base main --head "$BRANCH" --title "registry: admit $BATCH mirror updates" --body-file "$PR_BODY")"
printf '%s\n' "$PR_URL"
gh pr checks --watch "$PR_URL"
```

After CI:inspect remote PR head/base/diff/checks one final time. Do **not** enable auto-merge; do **not** merge; do **not** bypass protection. Send the PR URL to the curator and request review. If main/upstream evidence/PR diff changes materially, rerun from a fresh base/template rather than force-updating trusted generated facts.

## 13. Recovery + abort matrix

Normal command failure removes staging + leaves the original catalog exact; installation failure attempts rollback. Killed reconciliation may leave sibling `.registry.pkgre-lock`, `.registry.pkgre-stage-*`, or `.registry.pkgre-backup-*` paths. Confirm no indexer process is active; preserve backup evidence; restore last complete catalog if needed; remove only verified stale guard/disposable stage; run `check`; compare Git; then restart. Never delete a guard while another process is active.

Abort/preserve evidence on:wrong/non-full pin; build/version/Cargo uncertainty; dirty/stale/drifted base; catalog mutation during planning/inspection; malformed/noncanonical/empty unintended manifest; blocked identity manually present; young/yanked/locked/wrong identity; source mismatch; unknown/forbidden dependency route; unexplained archive/build/API/source evidence; apply/recovery failure; hand-edit temptation; missing/extra row/admission/hash binding; mirror `.crate` addition; topology/name/prior-history drift; failed check/no-op/reproduction/monotonicity/count; secret/private-data exposure; CI failure; curator rejection.

No failure permits identity substitution, policy relaxation, generated-file editing, force push, branch-protection bypass, or automatic merge of the registry-index PR.

## 14. Private evidence retention + cleanup

Retain `$ARTIFACTS` privately until curator review resolves. After merge/closure and any needed audit extraction, remove the detached worktree before deleting artifacts:

```bash
git -C "$TOOL_REPO" worktree remove "$TOOL_WORKTREE"
# Review retention requirements, then securely remove ordinary transient artifacts as appropriate.
```
