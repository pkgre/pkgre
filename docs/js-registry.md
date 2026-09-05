# JavaScript registry

Status:P7 implementation complete for offline/source use;production metadata+markers+objects remain unpublished until P3/P6 operator evidence permits activation.

## Authority+scope

- `pkgre-js` is the deterministic validator+renderer for one curated npm-protocol registry at `https://js.pkg.re/`;canonical runtime=Node/npm;Bun+Deno are conformance clients.
- Catalog input is reviewed authority;public packuments are derived artifacts;no mutable publish API,upstream metadata fallback,dynamic proxy catalog,or package-manager resolution decision is authoritative.
- v1 registry alias=`main`;minimum upstream npm age=`2592000s`=30d;first-party `pkgre-js` is explicitly age-exempt and bound to `github.com/pkgre/pkgre` tag `js/v<version>`.
- Initial closure=`{pkgre-js@0.1.0}`;runtime+development dependencies=none;future additions require exact recursively closed dependencies and reviewed immutable evidence.

## Public protocol after activation

| Artifact | Path | Rule |
|---|---|---|
| Unscoped packument | `/<name>` | Minimal deterministic npm metadata;current admitted versions only. |
| Scoped packument | `/@scope/name` | Same contract;clients may percent-encode the scope separator on requests. |
| Archive route | `/v1/js/main/<sha256>` | Exact marker-v1 bytes;Rain proxy validates bytes+returns fresh `307`. |
| First-party object | `/packages/<sha256>.tgz` | Content-addressed immutable archive. |

Every packument tarball URL is same-host `https://js.pkg.re/v1/js/main/<sha256>`. npmjs-backed marker destination is the one canonical npm archive URL;first-party marker destination is the same-host content-addressed object. Unknown metadata/route→hard failure;no npmjs metadata passthrough.

## Catalog contract

- Input=canonical UTF-8 JSON;duplicate keys,noncanonical escaping/order,nonscalar ambiguity,unknown schema keys,unsafe names,and noncanonical SemVer fail.
- Identity=`name+exact version`;package+version arrays strictly sorted;`distTags.latest` must select an included version;duplicate identities/archive hashes fail.
- Source evidence=kind,canonical URL,bytes,SHA-1,SHA-256,SHA-512 SRI,published/admitted times;third-party adds npm-metadata SHA-256+fetch time;first-party adds repository,tag,tag object,commit.
- Third-party evidence order=`publishedAt≤fetchedAt≤admittedAt≤evaluationTime`;`admittedAt-publishedAt≥30d`;first-party order=`publishedAt≤admittedAt≤evaluationTime`.
- Install manifests retain an explicit bounded field allowlist;dependencies/optionalDependencies/peerDependencies require exact canonical versions;every target identity must exist in this catalog.
- URL,Git,file,directory,workspace,alias,and version-range dependencies fail;registry closure cannot escape through dependency metadata.

## Archive contract

- Archive filename=`<source.sha256>.tgz`;archive directory contains exactly one file per catalog record and no extras.
- Verify compressed size+SHA-1+SHA-256+SHA-512 before content use;maximum archive=32MiB;bounded gzip/tar expansion+entry counts.
- Require one canonical `package/package.json`;selected manifest must exactly match reviewed catalog identity+install fields.
- Reject traversal,absolute/noncanonical paths,duplicates,links,special files,unsafe modes,package-local npm configuration,lifecycle scripts,and native-addon indicators.

## Deterministic publication

Addition is two-stage and each command writes a new sibling directory atomically;output paths must not exist:

```console
$ pkgre-js check catalog.json archives
$ pkgre-js render-routes catalog.json archives site-current site-routes
$ pkgre-js verify catalog.json site-routes
$ pkgre-js verify-monotonic site-current site-routes
# Deploy site-routes;read back exact route/object bytes;wait the measured Pages cache horizon.
$ pkgre-js render-final catalog.json site-routes site-final
$ pkgre-js verify catalog.json site-final
$ pkgre-js verify-monotonic site-routes site-final
# Deploy site-final only after route/object evidence succeeds.
```

- Routes stage adds immutable marker/object bytes while preserving the previous metadata inventory byte-for-byte.
- Final stage changes only inventoried packuments and binds the exact same catalog hash;it cannot add/change immutable bytes.
- Removal omits package metadata in the final stage;previous archive marker/object bytes remain forever immutable+retained,so frozen historical locks can stay cold-installable.
- `.pkgre-js-site.json` binds catalog SHA-256,stage,and every managed metadata/route/object file hash;unlisted managed files fail verification.
- Linux filesystem operations reject symlinked inputs/ancestors,unsafe writable modes,file mutation during reads,unowned output parents,and nonregular files;temporary output is fsynced,read back,and atomically renamed.

## Client policy

Project `.npmrc`:

```ini
registry=https://js.pkg.re/
allow-directory=none
allow-file=none
allow-git=none
allow-remote=none
audit=false
fund=false
ignore-scripts=true
replace-registry-host=always
save-exact=true
strict-ssl=true
update-notifier=false
```

Commit this configuration;do not add a scope-specific npmjs override. Exact dependency versions are required by catalog policy;consumer lockfiles remain required for frozen/cold replay. `allow-*` settings are npm-specific defense-in-depth;Bun+Deno compatibility is proven by observed closed-registry behavior,redirect/integrity checks,and outbound network isolation rather than assuming they implement every npm option.

## Compatibility matrix

Pinned minimum policy:Node `24.15.0`+npm `12.0.2`;Bun `1.3.14`;Deno `2.9.5`. Pinned current snapshot at implementation:Node `26.7.0`+npm `12.0.2`;Bun `1.4.0`;Deno `2.9.5`. Minimum Node is selected by npm 12.0.2's engine floor;Bun/Deno floors are the earliest versions explicitly pinned+tested for this contract,not claims about older releases.

Each x86_64+aarch64 Nix check runs with network disabled except loopback and proves:scoped+unscoped recursive install;same-host route+controlled `307`;fresh install;empty-cache frozen lock replay after metadata removal;unknown metadata failure without archive access;redirect-marker drift failure;route `404`/`503` failure;corrupt archive failure;bounded command time/output;expected methods,hosts,and paths only. `nix/js-compatibility-clients.nix` pins official archives+hashes;GitHub CI runs both native architectures.

Local full verification:

```console
$ nix develop -c node --test js/test/*.test.js
$ nix flake check --print-build-logs
$ nix build .#js
```

## Bootstrap+activation gate

- Source implementation/PR/tag and dormant bootstrap artifacts may be published;do not place production catalog,packuments,markers,or objects in `pkgre/js` Pages output before successful P3 issuance+P6 deployed frontend evidence.
- After merge:tag `js/v0.1.0`;pack twice from clean source under pinned Node/npm and require identical bytes;build+render `C0` twice;store reviewed catalog/archive/render dormant outside Pages output.
- After operator gate:route/object deploy→direct-origin+edge readback/hash→cache wait→metadata deploy→two independent clean-HOME/cache self-host installs/tests/repacks with only admitted registry/archive egress.
- Rain deployment,DNS,Gandi credential handling,and GitHub Pages custom-domain changes are operator-only;offline P7 completion does not imply a live registry launch.
