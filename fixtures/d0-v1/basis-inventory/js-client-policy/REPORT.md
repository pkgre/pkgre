# D0 JavaScript client-policy evidence packet

Verdict:client-policy packet:PASS | historical no-public-contact constraint:FAIL | D0 overall:BLOCKED | D1 authorized:false

## Incident—preserve permanently

Historical superseded Bun invocation:`bun install --config /tmp/policy.toml ...` misparsed the post-subcommand,space-separated config path as a dependency;policy registry was not applied;observed:`GET https://registry.npmjs.org/probe-missing`→`404`. Impact:one public metadata GET;no package installation,publish,login,token,or mutation. Authoritative later evidence excludes that probe and uses loopback only. Record:`raw/incident.txt`;SHA-256:`9d06853e9fa692c4b6347af8ac4bb85049d76322c41330768b5782e5df888efe`. This historical constraint failure is irreversible.

## Exact precedence findings

- npm 12.0.2:`CLI --registry` > `NPM_CONFIG_REGISTRY` > project `.npmrc` > selected user config;CLI `--userconfig` > `NPM_CONFIG_USERCONFIG`. Wrapper consequence:reject all caller CLI extras,all `NPM_CONFIG_*`,token/proxy/TLS environment,and discoverable project/user/global configs before exec;then provide a validated read-only npmrc and empty global config.
- Bun 1.4.0:CLI registry > `BUN_CONFIG_REGISTRY`/`NPM_CONFIG_REGISTRY` > explicit/project bunfig > project `.npmrc` > user/global sources. Bun 1.3.14 exception:project `.npmrc` overrides even explicit `--config=` bunfig;environment+CLI registry still outrank it. Wrapper consequence:reject discoverable `.npmrc`/bunfig and caller env/CLI before exec;safe spelling:`bun --config=/absolute/path install ...`.
- Deno 2.9.5 registry:`NPM_CONFIG_REGISTRY` > project `.npmrc` > `$HOME/.npmrc`;`NPM_CONFIG_USERCONFIG` ignored. Age:`deno install --minimum-dependency-age` > `deno.json` > `.npmrc`/`NPM_CONFIG_MIN_RELEASE_AGE`;`deno ci` exposes no equivalent override and rejects `--config`. Wrapper consequence:exact controlled project `deno.json`,controlled HOME `.npmrc`,no caller env/CLI.

## Frozen profiles+wrapper

- Production:`configs/production/profile.json`→`https://js.pkg.re/`;loopback test-only:`configs/loopback/profile.json`→`http://127.0.0.1:48730/`;each has distinct read-only npm/Bun CI/Bun resolve/Deno/Deno-npmrc files.
- Clients:npm minimum/current=`Node 24.15.0/26.7.0+npm 12.0.2`;Bun=`1.3.14/1.4.0`;Deno minimum/current=`2.9.5`,with independently instantiated current derivation recorded under `provenance/`.
- `wrappers/policy_wrapper.py`:dependency-free,validated exact profiles/configs+binaries;rejects CLI extras,registry/config/cache/token/proxy/TLS env,project/user/global config,non-registry manifest sources,lifecycle/trusted-dependency hazards,lock extensions/foreign URLs/scripts/schema drift;constructs minimal env+controlled HOME/cache;uses exact frozen commands (`npm ci`,`bun --config=… install --frozen-lockfile --ignore-scripts`,`deno ci`). Production profile was structurally verified only;no production request was made.
- Age settings are defense in depth;Git-backed server catalog admission is authoritative. Existing-lock replay does not re-evaluate package age.

## Existing clean loopback-only validation

`raw/subrun/RESULT.json`+per-case audit/stdout/stderr/strace evidence:status PASS;unshare user+network namespace;loopback registry only;6 pinned clients;66 cases=36 accepted+30 fail-before-client-exec rejections;36 loopback socket connects;36 loopback GETs;0 unexpected connects;cache-only cases=0 connects/requests. Invariants:age selections,pre-exec rejection,loopback-only destination,cold registry use,warm boundedness,exact frozen commands,cache-only zero-network all true. Hostile matrix per client:project `.npmrc`,user `.npmrc`,registry/config env,token env,CLI override. Fixture:`fixtures/run_authoritative_subrun.py`;registry:`raw/controlled_registry.py`;wrapper:`wrappers/policy_wrapper.py`.

## Offline verification

- Strict verifier:`./verify_artifact.py`;checks exact checksum coverage,incident hash/disclosure,profiles/configs,66-case structure,all referenced file hashes,rejection/acceptance invariants,loopback destinations,and report verdict.
- Integrity:`sha256sum -c SHA256SUMS`;manifest covers every regular file except itself,sorted exactly once.
- Whitespace:`git diff --no-index --check /dev/null <file>` for every packet file;result:303/313 clean,10 preserved generated Deno stderr transcripts report `new blank line at EOF`;no trailing-whitespace errors;raw evidence was not rewritten.
- Secret scan:offline regex/high-entropy scan;expected synthetic policy names,public URLs,Nix hashes and `(protected)` npm defaults are not credentials;no private-key/token/credential assignment found.

## Blockers+limitations

- D0 overall remains BLOCKED:packet covers only JS client policy;it cannot establish plan-wide identities,Git authority/signature admission,route/edge/time/resource/dependency inventories,operator deployment,independent review+Git commit. D1 is not authorized.
- Historical public-contact constraint remains FAIL despite the later clean isolated subrun.
- The clean subrun is existing evidence and was not rerun during finalization per operator instruction;final report,verifier and checksum operations were offline. `strace` proves observed process sockets,not a formal proof against every possible covert channel;the network namespace claim is part of the captured harness result.
- Packet directory is not a Git repository;no repository was modified or committed.
