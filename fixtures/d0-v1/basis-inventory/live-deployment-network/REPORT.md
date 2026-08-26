# D0 live deployment+network+legacy evidence packet

Verdict:packet integrity:PASS | D0 overall:BLOCKED | D1 authorized:false | collection:read-only | finalization network:none

## Scope+classification

Scope:Rain host+`pkgre` container;deployed nginx/ACME/legacy units;public DNS/TLS/HTTP;GitHub Pages+Actions deployment metadata;filesystem/time;credential metadata only. Every material claim is typed in `REPORT.json` as `observed`,`proposed`,`absent`,or `blocked`;counts:`observed=24`,`proposed=0`,`absent=5`,`blocked=13`. `observed` means captured during the bounded 2026-08-26 collection or explicitly labeled repository/historical observation;it does not convert into future deployment authority. Finalization used only preserved `raw/` bytes:no new network,API,SSH,provider,or deployment action.

## Rain+container

| Classification | Claim | Evidence |
|---|---|---|
| observed | Rain generation:`/nix/store/bhfadnwczhfsd6zadxhl04jqfp1spp9v-nixos-system-rain-26.11.20260818.9588f1a`;nixpkgs:`9588f1a6c197ae61c6222a3baa6ac220ec1cc4d9` | `raw/rain-host-live.txt#identity` |
| observed | Container generation:`/nix/store/jai70s8kdn3jc71qvsn9l20zma9aam4g-nixos-system-pkgre-26.11.20260818.9588f1a`;ephemeral read-only idmapped snapshot;addresses:`10.22.2.5`,`10.131.7.4`;declared host peer:`10.131.7.1` | `raw/rain-container-{declaration,live}.txt`;`raw/infra-repository-declared.txt` |
| blocked | Exact deployed infra source commit is not exposed by the live generations;`5f68539bd99c6952b6d73fe2596c27ad4a319f57` is the matching repository declaration,not a proven deployed-source identity | `raw/infra-repository-declared.txt#classification`;`raw/rain-host-live.txt#identity` |
| observed | nginx `1.30.4`;config:`/nix/store/nnqs127xdnxi93772sgmgfy7a890alxb-nginx.conf`;SHA-256:`eeb69be6aebb5e69fdbc12c9019e648f64308b1738c153715411db607d701d51` | `raw/rain-host-live.txt#nginx_unit` |

## Legacy services+network boundary

| Classification | Claim | Evidence |
|---|---|---|
| observed | `pkgre-download-serve 0.1.0` at `10.131.7.4:9008`;store:`/nix/store/wjrvwfxnxzwjvkvcl3j53wkbrgvbkznf-pkgre-download-serve-0.1.0`;closure:`6178808` B | `raw/rain-container-{live,units-live}.txt` |
| observed | `pkgre-proxy 0.2.0` at `10.131.7.4:9009`;store:`/nix/store/1a25f3q7qvdxgcbcjs267h395xzy4016-pkgre-proxy-0.2.0`;closure:`5613352` B | `raw/rain-container-{live,units-live}.txt` |
| observed | Both legacy units:`DynamicUser=true`;empty capabilities;`NoNewPrivileges=true`;`ProtectSystem=strict`;seccomp active;declared firewall admits `9008/9009` only from `10.131.7.1`;external worker probes timed out | `raw/rain-container-units-live.txt`;`raw/infra-repository-declared.txt`;`raw/public-dns-tls-http-live.txt#external_backend_denial` |
| absent | Legacy units declare no explicit `StateDirectory`,`MemoryHigh`,`MemoryMax`,`TasksMax`,or `LimitNOFILE`;no dynamic server units/listeners/state roots/accepted manifests exist | `raw/rain-container-units-live.txt`;`raw/rain-container-live.txt` |
| blocked | One external timeout vantage cannot prove universal denial or the future dynamic listener boundary | `raw/public-dns-tls-http-live.txt#external_backend_denial` |

## DNS+TLS+ACME

| Classification | Claim | Evidence |
|---|---|---|
| observed | Authoritative+recursive DNS:`rust.pkg.re CNAME pkgre.github.io.` TTL `300`;`js.pkg.re CNAME rain.pacna.org.` TTL `300`;`dl.rust.pkg.re CNAME rain.pacna.org.` TTL `10800`;Rain IPv4:`65.21.163.108` | `raw/public-dns-tls-http-live.txt#dns` |
| observed | TLS chain+hostname verification passed for all three public names;direct Rain SNI also presented a valid `rust.pkg.re` certificate | `raw/public-dns-tls-http-live.txt#tls_verify_brief`;`#rain_direct_rust_tls` |
| observed | Rain ACME units for Rust+JS exited `0`;all three declarations run `acme:nginx` with per-name `StateDirectory`;credential fields remained unprintable | `raw/rain-host-live.txt#acme_unit_metadata`;`raw/rain-acme-declaration-live.txt` |
| blocked | Current unprivileged SSH could not traverse certificate/key leaves;bounded same-generation historical metadata separately reported directories `0750 acme:nginx`,certificate/key leaves `0640 acme:nginx`;no contents read | `raw/rain-host-live.txt#certificate_and_key_path_metadata_only`;`raw/prior-privileged-path-metadata.txt` |

## Pages+public behavior

| Classification | Claim | Evidence |
|---|---|---|
| observed | Rust Pages:workflow from `main /`;custom domain verified;HTTPS enforced;certificate approved;deployment `6092749507` at `f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` succeeded;public canary/config=`200` | `raw/github-pages-provider-live.json#/repositories/rust`;`raw/public-dns-tls-http-live.txt` |
| observed | JS Pages:workflow from `main /`;custom domain saved+verified;deployment `6094120375` at `f43bd58bd3d4e36f8b3f4df3c002735c977acd17` succeeded;Rain public canary=`502` | `raw/github-pages-provider-live.json#/repositories/js`;`raw/public-dns-tls-http-live.txt` |
| absent | JS Pages `https_enforced=false`;default Pages origin redirected to `http://js.pkg.re/...`;therefore this is containment-only,not a continuity rollback anchor | same |
| observed | Rust Actions:selected+SHA-pinning required;JS Actions:all+SHA-pinning not required;Rust tip:verified PGP;JS tip:unsigned;neither proves required v1 SSH-Ed25519 release admission | `raw/github-pages-provider-live.json` |
| blocked | One-day Pages artifacts are not durable rollback bundles;independent custody+restore sequence+rehearsal remain unresolved | `raw/github-pages-provider-live.json#/repositories/{rust,js}/artifacts/0` |
| observed | Legacy download health/status=`200`;sample `/v1/main/accessory/2.1.0/28e…` returned zero-body `307` to crates.io then `13195` B with exact SHA-256 `28e416a3ab45838bac2ab2d81b1088d738d7b2d2c5272a54d39366565a29bd80` | `raw/public-dns-tls-http-live.txt#http legacy_*` |
| observed | Registry SNI plus `Host: invalid.example` selected an unrelated default vhost and returned `302 Location: https://admin.keycloak.pacna.net/admin/` for Rust,JS,and legacy download | `raw/public-dns-tls-http-live.txt#raw_host_sni_mismatch` |
| absent | Required exact SNI/vhost/authority fail-closed rejection is not implemented by this edge;D1 must freeze it before future deployment | same;`raw/rain-host-live.txt#nginx_target_config` |

## Filesystem+time+credentials

| Classification | Claim | Evidence |
|---|---|---|
| observed | Host `/`,`/nix`,`/var/lib`:ZFS `xattr,posixacl,casesensitive`;ephemeral container snapshot:read-only+idmapped | `raw/rain-host-live.txt#filesystem_mount_zfs`;`raw/rain-container-live.txt` |
| blocked | Intended dynamic state dataset/subvolume,quota,reserve,free-space ceiling,persistent bind layout,static UID/GID mapping,parent+leaf ACL/mode/idmap,sole writer/readers,backup reader,writable paths,same-filesystem rename+fsync/power-loss proof,backup+restore sequence and rehearsal are unresolved | `raw/rain-host-live.txt`;`raw/rain-container-declaration-live.txt` |
| observed | `systemd-timesyncd` active;clock synchronized;NTP active;captured offset `-198us`;root distance `831us` | `raw/rain-host-live.txt#time_services` |
| blocked | One sample does not define the production acceptance dual-clock/future-skew policy or tolerance | `raw/rain-host-live.txt#dual_clock_sample` |
| observed | Credential metadata only:`/var/lib/keys/pkgre-js-gandiv5-token`;`root:root`;mode `0644`;size `41`;ACL group/other read;value not read | `raw/rain-host-live.txt#credential_path_metadata_only` |
| blocked | Operator must restrict permission,rotate/revoke the exposed credential,inspect provider scope+audit logs,and return metadata-only evidence | same |
| observed | Rain SSH continuity:10 matching SSH-Ed25519 scans;fingerprint `SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI`;SSH succeeded as `wei`;classification remains TOFU/continuity | `raw/ssh-host-key-continuity.txt` |
| blocked | Operator out-of-band host-key attestation remains absent | same |

## Blocking operator-owned values

- Rain SSH-Ed25519 host-key out-of-band attestation.
- Gandi token permission repair+rotation/revocation+provider scope/audit evidence;metadata only,never token value.
- Production signer principal+public fingerprint;`allowedSigners` path+digest;revocation-set digest;release identity/custody;intended rulesets/checks/environment reviewers/writer permissions.
- Rain state dataset/quota/reserve/persistent binds;static UID/GID map;all parent+leaf ownership/modes/ACL/idmap;sole writer/readers+backup reader;same-filesystem rename+fsync/power-loss proof;backup/restore policy+rehearsal.
- Approval/replacement of resource proposals+rollout horizons;exact acceptance clock policy/config.

LAN status:absent;no LAN-public instance,hostname,listener,state root,catalog ref,credential,DNS view,or TLS identity is selected;D13 remains the authority gate.

## Integrity+gate

- `./verify_artifact.py`:offline strict validation of fixed raw hashes+sizes,complete sorted checksum coverage,JSON parsing,claim vocabulary+exact classification map,critical values,raw cross-evidence markers,no symlinks,no credential/private-key value patterns,and split verdict.
- `sha256sum --check --strict SHA256SUMS`:all regular files except the manifest itself are covered exactly once.
- Packet integrity may pass while plan D0 remains **BLOCKED**. D1 authorized:`false`;no D1 extraction,D2 migration,server implementation,or infra edit is authorized by this packet.
