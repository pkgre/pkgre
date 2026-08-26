# D0 GitHub governance/Pages/Actions inventory — 2026-08-26

Status:read-only authenticated collection complete;D2 governance gate=BLOCKED;no Git repository or remote/provider state changed.

## Scope+basis

- Collected:`2026-08-26T12:19:56.329913Z`;API:`GET` only via `gh api`;authenticated principal recorded as `sorpaas`;credential/token value never requested,printed,or stored.
- Repositories:`pkgre/rust`,`pkgre/js`;`pkgre/pkgre` included because both catalog workflows pin it as implementation/indexer source.
- Intended D2 comparison source:`plans/pkgre-dynamic-registry-rollout.md` §§3.1,11,13:public source=`refs/heads/main`;pinned exact-SHA CI;FF-only;v1 SSH-Ed25519 signed tip;protected release workflow+distinct writer;operator-reviewed protected environment;CODEOWNERS/ruleset review;no contributor/admin direct push,force push,unsigned tip,or workflow self-approval.
- Evidence separation:`workflows-*.json`=provider default-ref source+provider workflow IDs;`local-source.json`=local current-ref `.github` bytes only,never treated as provider settings.
- API calls:`123`:HTTP 200=`96`,404=`20`,409=`1`,422=`6`;every result/error+GitHub request ID is indexed in `http-index.json`.

## Actual governance

| Repo | Provider identity/default tip | Branch governance | Current tip signature | Actions |
|---|---|---|---|---|
| `pkgre/rust` ID `1342904147` | public;`refs/heads/main`=`f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b`;caller admin | branch rulesets=`[]`;legacy protection present;strict required check=`validate`,GitHub Actions app `15368`;admins enforced;linear history;force push/deletion disabled;conversation resolution;PR-review rule count=`0`;code-owner review=`false`;last-push approval=`false`;required signatures=`false` | GitHub verified=`true`;kind=`PGP`;not required v1 SSH-Ed25519 | enabled;allowed=`selected`;SHA pinning required;GitHub-owned allowed;verified Marketplace disallowed;pattern=`cachix/install-nix-action@*`;default token=`read`;PR review approval=`false` |
| `pkgre/js` ID `1345630585` | public;`refs/heads/main`=`f43bd58bd3d4e36f8b3f4df3c002735c977acd17`;caller admin | branch rulesets=`[]`;branch protection explicitly absent:HTTP 404 `Branch not protected`;required checks absent | verified=`false`;reason=`unsigned` | enabled;allowed=`all`;SHA pinning not required;selected-actions endpoint HTTP 409 because policy is not selected;default token=`read`;PR review approval=`false` |
| `pkgre/pkgre` ID `1342903573` | public;`refs/heads/main`=`066293df21743cbf41fb571a38f2bb94059e7274`;caller admin | one active tag ruleset ID `21205882`,`refs/tags/indexer/v*`,update+deletion forbidden,no bypass;legacy `main` protection requires strict `check`,app `15368`;otherwise materially like Rust | verified=`true`;kind=`PGP` | enabled;selected+SHA-pinned;same selected policy as Rust;default token=`read` |

- Principals,all three repos:collaborators=`sorpaas` only,role=`admin`;teams=`[]`;ruleset bypass actors=`[]` where a ruleset exists.
- CODEOWNERS:`absent` in `.github/CODEOWNERS`,`CODEOWNERS`,`docs/CODEOWNERS` for all three repos;each absence is a separate HTTP 404 record.
- Effective branch-rules endpoint returned `[]` for every `main`;legacy branch-protection details are separately captured and remain the effective observed main protection for Rust/implementation.

## Workflows+checks

| Repo | Provider workflow | Source identity | Triggers | Declared permissions/checks |
|---|---|---|---|---|
| Rust | ID `340152007`,`Validate and deploy registries`,active | `.github/workflows/pages.yml`;blob `0799e0070b7500dea5aa688c1898a92c2a907f93`;SHA-256 `cd46abf20d47894a4ffcc10550953848f6dcbc6c3703239cee0635e4c453a114` | `pull_request`;`push`→`main`;`workflow_dispatch` | workflow `contents:read`;job `deploy`=`pages:write,id-token:write`;jobs/checks=`validate`,`deploy`;main protection requires `validate` |
| JS | ID `342430387`,`Validate and deploy default Pages origin`,active | `.github/workflows/pages.yml`;blob `dd19b88fa455c48eb2a3a817072c8b954e8c65f3`;SHA-256 `4c6aaf4fff2ee0a2f2d1f433d01d1e6f7d62f069b21b7017488539d48660f7e8` | `pull_request`;`push`→`main`;`workflow_dispatch` | same declared permissions;observed checks=`validate`,`deploy`;neither required |
| implementation | ID `340147927`,`CI`,active | `.github/workflows/ci.yml`;blob `fc54b978bde4e7925bd1671746c11223ded4f86b`;SHA-256 `928a98bdfbbb8fd81f03983514973865d4539ad377a21a797b5b165cd3a92a45` | `pull_request`;`push`→`main` | workflow `contents:read`;checks=`check (x86_64-linux)`,`check (aarch64-linux)`,aggregate required=`check` |

- Every repository workflow action reference is commit-SHA pinned;catalog workflows pin implementation commits:Rust=`ae1dfbfd4e965dffb538e356f005e4fbb32fdb77`;JS=`066293df21743cbf41fb571a38f2bb94059e7274`.
- Provider-managed CodeQL:Rust workflow ID `340179788`,default setup=`configured`,languages=`actions`,suite=`extended`;implementation ID `340179776`,configured,languages=`actions,javascript,javascript-typescript,typescript`,suite=`extended`;JS default setup=`not-configured`. Dynamic path=`dynamic/github-code-scanning/codeql`;repository Contents returns 404 because GitHub generates it;no repository file/blob SHA or exact generated triggers/permissions are exposed by these REST endpoints—recorded as provider-managed limitation,not a placeholder.
- Local refs:Rust/JS clean and equal provider tips;implementation local `main`=`1d44dfeaeafef2b1a5341c13bf73647dcbc925ec`,ahead of provider by one commit,while `.github/workflows/ci.yml` blob/hash still exactly matches provider source.

## Environments+Pages+operations

| Repo | Environment | Pages actual | Latest deployment/artifact |
|---|---|---|---|
| Rust | only `github-pages`,ID `20395247571`;branch policy exact `main`,ID `58004732`;reviewers=`[]`;admins may bypass | workflow build;source=`main` `/`;custom domain=`rust.pkg.re`;domain verified;HTTPS enforced;certificate approved for `rust.pkg.re`,expiry `2026-11-20`;settings status=`null` | deployment `6092749507`,SHA=current tip,status=`success`;artifact `9583758375`,digest `sha256:2510e9d77f459d066261a88efe9005d5358c8a9a401aba7042d45fe6f1c2448c`,551735 bytes,expires `2026-08-26T21:48:27Z` |
| JS | only `github-pages`,ID `20594913798`;branch policy exact `main`,ID `58257515`;reviewers=`[]`;admins may bypass | workflow build;source=`main` `/`;custom domain=`js.pkg.re`;domain verified;HTTPS not enforced;certificate field absent;settings status=`null` | deployment `6094120375`,SHA=current tip,status=`success`;artifact `9586702051`,digest `sha256:ba7bb13b843d585898552ecd68d2e9caee55ee27644f3721b48b63d29a5e32c5`,791 bytes,expires `2026-08-26T23:37:29Z` |
| implementation | environments=`[]` | Pages endpoint HTTP 404/not configured | deployments=`[]`;non-Pages CodeQL artifacts captured |

- Pages builds endpoints:Rust/JS list calls HTTP 200 with `[]`;latest-build calls HTTP 404,despite successful workflow deployments+Actions artifacts;implementation settings/build/latest all HTTP 404.
- Operations inventory bounded at 20 deployments and 100 artifacts;actual returned counts:Rust deployments/artifacts=`16/16`;JS=`4/4`;implementation=`0/2`. Full deployment status histories and artifact digest/expiry metadata are in `operations-*.json`.

## D2 comparison+blockers

1. `pkgre/js` is the immediate critical blocker:`main` unprotected,no required check,rulesets absent,Actions allow all/no SHA-pinning,and tip unsigned.
2. Rust is not D2-ready despite partial legacy protection:no branch ruleset/CODEOWNERS/protected release environment/distinct release writer;zero required approvals;code-owner+last-push approval disabled;required signatures disabled;current PGP signature cannot satisfy v1 SSH-Ed25519.
3. Neither catalog has the D2 release workflow or protected operator-reviewed release environment;existing `github-pages` environments have no reviewers and allow admin bypass,and Pages workflows are publication/rollback workflows rather than signed catalog-release writers.
4. Exact D2 values are not yet frozen in the plan/source:release workflow path/name/blob/check;release environment name/reviewers;release writer identity+token permissions;SSH-Ed25519 principal+public fingerprint;trusted/revoked key-set digest;rollback order. These are operator-handoff inputs,not provider-generated IDs;D2 handoff is blocked until frozen.
5. Organization audit-log retrieval unavailable:all three bounded repo-filtered calls returned HTTP 404 `Not Found`;token/user or organization plan lacks access. D2 therefore requires operator-returned audit/settings evidence.
6. Provider-assigned values that cannot pre-exist operator action and must be returned afterward:ruleset IDs/node IDs/timestamps;release-environment+protection-rule+branch-policy IDs;release-workflow ID/node ID;producer app/integration ID if different from GitHub Actions `15368`;first-bootstrap deployment/run/check-suite/check-run IDs. They must be keyed to frozen names/config/blob SHA/candidate SHA and never guessed.
7. Current Pages artifacts have one-day expiry;the newest Rust/JS rollback artifacts expire on 2026-08-26,so the D2/D14 frozen rollback-artifact retention requirement is not met by current mutable short-lived artifacts.

## Artifacts+verification

- Machine-readable files:`auth.json`,`identity-{rust,js,pkgre}.json`,`governance-{rust,js,pkgre}.json`,`actions-{rust,js,pkgre}.json`,`workflows-{rust,js,pkgre}.json`,`codeql-default-setup-{rust,js,pkgre}.json`,`environments-{rust,js,pkgre}.json`,`pages-{rust,js,pkgre}.json`,`operations-{rust,js,pkgre}.json`,`tip-{rust,js,pkgre}.json`,`principals-{rust,js,pkgre}.json`,`audit-log.json`,`local-source.json`,`actual-vs-d2.json`,`http-index.json`.
- Integrity:`SHA256SUMS` covers `REPORT.md`+all JSON evidence;all JSON parsed with `jq`;manifest verified with `sha256sum -c`.
