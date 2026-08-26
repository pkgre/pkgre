# D0 nginx raw-target/private-field proof

Status:primitive PASS;production rollout BLOCKED

## Exact conclusion

nginx 1.30.4 (`/nix/store/qzihfqlvbzx0zhjvmx6zimxdz9ghvwm0-nginx-1.30.4`, derivation `/nix/store/7d0a3gqn59b9j58gly11b7qaisch0ikk-nginx-1.30.4.drv`) can preserve each accepted request target byte-for-byte without normalized reconstruction and place it with a raw-derived request-form verdict into singleton private backend fields. Evidence:all 174 forwarded exchanges matched fixture bytes exactly:HTTP/1 observe=55/55,HTTP/1 policy=36/36,HTTP/2 observe=47/47,HTTP/2 policy=36/36. In 95 forwarded exchanges the protected raw field differed from nginx's normalized `$uri` diagnostic, directly proving the field did not fall back to normalized reconstruction. Caller attempts to set either private field were stripped and overwritten for H1+H2 in observe+policy modes.

H1 verdict:PASS for nginx-accepted requests. `$request` retains the exact HTTP/1 request-target token; the map extracts the middle token and classifies origin/absolute/authority/asterisk before proxying. Observe mode demonstrated exact origin+absolute preservation. Authority/asterisk/malformed forms were not forwarded by proposed policy (some were rejected earlier by nginx).

H2 verdict:PASS for nginx-accepted request semantics, with a precise scope:HTTP/2 has no wire request-line; nginx constructs `$request` from decoded pseudoheaders. The protected target exactly matched the submitted `:path` byte sequence for every forwarded case, and form=`h2-origin` was derived from that constructed raw target. This proves no `$uri`/`$request_uri` normalized reconstruction; it does not claim preservation of HPACK bytes or rejected pseudoheader sets.

Private boundary:PASS in this isolated harness. Backend was an AF_UNIX socket mode 0600 owned by the test uid. `proxy_pass_request_headers off` denied caller headers; nginx emitted fixed Host/Connection, empty body/CL/TE/Trailer/Expect, and exactly one `X-Pkgre-Edge-Raw-Target` plus one `X-Pkgre-Edge-Request-Form`. Every backend capture was referenced once; sequences 1..174 are contiguous.

Normalized fallback:PROHIBITED and absent. Authority source=`$request` capture only. `$request_uri` and `$uri` are diagnostic fields only. Production must fail closed when capture/form is empty; it must never substitute `$uri`, `$request_uri`, a rewritten location URI, or a decoded/re-encoded value.

## Production-blocking gap

**BLOCKED:**the included `proxy-policy.conf.template` is a proof policy, not an adequate production admission policy. It deliberately admits multiple normalization-sensitive or unsafe spellings while proving preservation:duplicate slash, raw/encoded backslash, raw/encoded dot segments, encoded/double-encoded separators/dots, raw fragment marker, invalid UTF-8, and multiple scoped npm variants. nginx also accepted and the proof policy forwarded H2 pseudoheaders ordered after a regular header (`h2_pseudo_after_regular`). Therefore the raw/private-field transport primitive passes, but production serving must not proceed until the application/edge contract defines and tests a fail-closed byte-level allowlist/canonicalization policy (and H2 protocol-conformance stance) over the protected raw field. No normalized fallback may close this gap.

Additional production integration blocker:this isolated proof demonstrates a 0600 Unix-socket boundary, not the actual deployed topology. The real backend must be equivalently unreachable/untrusted-header-free (Unix peer permissions or authenticated private transport), must trust these fields only from that boundary, and must reject missing/duplicate/invalid form fields.

## Coverage and outcomes

Fixtures:H1=82,H2=68. Modes:observe records nginx behavior;policy adds proposed SNI/form/method/query/authority/body rejection. Covered origin/absolute/authority/asterisk forms; malformed percent/space/CTL/DEL/NUL; empty/value queries and raw/encoded fragment; slash/backslash/dot/UTF-8 variants; exact and variant scoped npm spellings; Host/:authority mismatch, duplicate/coalesced/generic headers, obs-fold/invalid names; CL/TE/chunking/trailers/Expect and hop-by-hop inputs; 9 KiB target/header, 256/4096 headers, 2 KiB body; H2 duplicate/missing/empty pseudoheaders, pseudoheader ordering, uppercase names, CONNECT; private-field overwrite; SNI missing/unknown/uppercase/mismatch.

Observe is not an allow policy. Examples:observe forwards H1 absolute forms, bodies (body suppressed at backend), many questionable raw targets, and H2 connection/transfer-encoding inputs accepted by nginx. Proposed policy rejects non-origin forms, non-GET/HEAD, any query, non-exact authority, CL/TE/Expect/Trailer, unknown/missing SNI, and over-limit inputs. nginx parser rejection remains visible separately in per-case captures.

H2 transport notes:overlong header/path produced GOAWAY error 11; invalid trailing HEADERS construction produced GOAWAY error 1 in observe; malformed/missing/duplicate pseudoheaders were generally 400 or connection errors. These are expected captured outcomes, not validator failures.

## Reproduction, identity, integrity

Run:`./scripts/run.sh` (loopback TLS only; ephemeral self-signed key is created under a temporary directory and deleted; no private key is retained). Validate:`./scripts/validate_results.py`. Integrity:`sha256sum -c SHA256SUMS`. Validator result:`ok=true`,1725 checks,0 errors,501 hashed payload files,174 backend captures. Effective config hash is recorded in `results/toolchain.txt`; all source/config/fixture/result/root artifacts are covered by `SHA256SUMS` except the checksum file itself.

Binary SHA-256:`8d61b66b1b71e5021d1d3e6378f9e400f83f897d292a7fb535c37556d85787c1`. Effective instantiated nginx config SHA-256:`a0ec792c13a07f25746ef79301d42a73f7f09d5222bc07ed07812ce869440d2b`; template SHA-256:`aeb49d58c131c178499e53febdabe79f1260ef04cf2ef8f5efa0f4f01889a263`. Complete modules/build arguments are in `results/toolchain.txt` and manifests.

## Harness issues

Prior artifacts mixed older plaintext captures with newer TLS templates and a repository-dependent/broken runner (`@CERT@`/`@KEY@` unsubstituted). Final runner is repository-independent, uses pinned Nix store executables with overrides available, generates only an ephemeral test certificate, and reran the bounded local proof. HTTP/1 policy SNI missing/unknown cases correctly fail during TLS handshake and therefore have no HTTP status; this is modeled as expected rejection. No project/infra repository, public service, DNS, setting, or credential was modified.
