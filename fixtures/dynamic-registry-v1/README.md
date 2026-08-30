# Dynamic registry contract fixtures v1

Purpose:shared,versioned,implementation-independent observables for native Rust+JavaScript registry services. Rust+JavaScript tests must consume the same fixture bytes; generated language-local copies are forbidden.

## Scope

| Path | Contract |
|---|---|
| `index.json` | bundle identity,fixture inventory,SHA-256 digests |
| `http/raw-targets.json` | raw request-target grammar,canonical route classes,rejection vectors |
| `http/responses.json` | method precedence,status,application-controlled headers,body behavior |
| `state/accepted-ref-transitions.json` | durable accepted-ref identity,restart authority,candidate transition vectors |
| `edge/forwarding.json` | trusted original-target boundary between edge and service |
| `client/configuration.json` | exact Cargo/npm/Bun/Deno registry and no-fallback policy |

## Rules

- JSON encoding:UTF-8;canonical pretty JSON;object keys bytewise sorted;2-space indent;one trailing LF;no duplicate keys.
- Fixture schemas are closed:unknown fields,unknown enum values,duplicate case IDs,and missing referenced IDs are errors.
- Raw target vectors are bytes,not decoded URLs. `targetAscii` and `targetHex` are mutually exclusive. No framework-normalized path may substitute for the trusted raw target.
- HTTP fixtures cover only application-controlled observables. HTTP version framing,header ordering,`Date`,`Server`,`Connection`,and transport-generated fields are excluded.
- Target validation precedes exact immutable-map lookup;request handling performs no upstream metadata lookup,Git access,rendering,or mutation.
- Durable accepted state is the sole restart authority after bootstrap. Remote tips,local descendants,predecessors,and rejected candidates cannot silently replace it.
- Client fixtures describe production policy. Loopback test harness details and client cache implementation details are not protocol contracts.
- Any incompatible observable change requires a new sibling fixture version;v1 files are immutable after D1 closes except to correct a demonstrably inconsistent vector before implementation release.
