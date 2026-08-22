# Curator workflows

## Commands

```text
pkgre-indexer check <catalog> [artifact-map]
pkgre-indexer render <catalog> <artifact-map> <new-output>
pkgre-indexer verify <catalog> <artifact-map> <existing-output>
pkgre-indexer verify-monotonic <previous-site> <next-site>
pkgre-indexer candidate-crates-io <proposal> <new-output>
pkgre-indexer candidate-git <proposal> <cargo-version> <new-output>
pkgre-indexer package-git <catalog> <package> <version> <new-output>
```

All materialization/render output paths must be absent. Failures remove partially created output where possible. Candidate commands never mutate approved catalogs.

## Import crates.io versions

1. Prepare a provenance-free exact proposal; no consuming-project name/path/manifest/lockfile belongs in public inputs:

```toml
schema = 1

[[packages]]
registry = "core"
name = "serde"
version = "1.0.229"

[[packages]]
registry = "matrix"
name = "matrix-sdk"
version = "0.16.0"
```

2. Materialize candidates:

```console
$ pkgre-indexer candidate-crates-io proposal.toml candidate
```

3. The importer fetches the exact crates.io sparse row + archive over HTTPS, selects exactly one name/version row, validates Cargo metadata, checks archive SHA-256 against upstream `cksum`, then writes only candidate files:

```text
candidate/
├── approvals/{core,matrix}.toml
├── homes.toml
├── artifacts.toml
├── archives/<sha256>.crate
└── upstream/<registry>/<index path>/<version>.json
```

4. Audit exact archive contents, build-time behavior, proc macros, native code, repository/release correspondence, maintainer provenance, row dependency changes, and licensing. Importer verification is integrity evidence, not a safety judgment.
5. Merge approved homes, approval stanzas, snapshots, archives, and artifact entries into the committed public catalog/artifact tree. Do not copy private discovery provenance.
6. Run `check`, render to a new directory, verify byte identity, and compare monotonically with the prior published site.

## Publish first-party Git tag

Release preconditions:

- committed HTTPS repository + immutable release tag;
- declared tag peels to a recorded full commit ID;
- no submodules, symlinks, special files, unsafe paths, or dirty generated changes;
- selected package has exact name/version + `publish = ["pkgre"]`;
- every dependency explicitly names one of `core`, `matrix`, `pkgre` in `Cargo.toml`;
- lockfile present + compatible with isolated curated registries;
- pinned Cargo version equals catalog `cargo-version`.

Proposal:

```toml
schema = 1
registry = "pkgre"
name = "pkgre-indexer"
version = "0.1.0"
repository = "https://github.com/pkgre/pkgre"
tag = "indexer/v0.1.0"
commit = "<full peeled commit>"
package = "pkgre-indexer"
subdir = "indexer"
```

Candidate:

```console
$ pkgre-indexer candidate-git proposal.toml 1.95.0 candidate
```

Materializer behavior:

1. Create fresh isolated checkout; fetch exact tag; require tag peel = declared commit.
2. Reject submodules, symlinks, special files, unsafe path components, unexpected VCS state, or manifest mismatch.
3. Create isolated Cargo home defining only the three canonical registries; replace crates.io with an empty directory.
4. Run pinned `cargo metadata`; require every dependency to declare a canonical curated registry.
5. Run pinned `cargo package --no-verify --locked` twice in separate target directories; require byte-identical archives.
6. Generate un-routed Cargo index row; emit archive, row, hashes, artifact map, and approval candidate.

Review candidate; copy approved declaration/artifacts into catalog. Reproduce an approved release independently:

```console
$ pkgre-indexer package-git catalog pkgre-indexer 0.1.0 reproduced
```

The command re-fetches the declared tag, checks the peeled commit, repeats deterministic packaging, and fails unless archive + un-routed-row hashes equal the approval.

## Pinned Cargo selection

`candidate-git` + `package-git` select Cargo in this order:

1. `PKGRE_CARGO=/absolute/path/to/cargo` if set; path must be absolute.
2. `rustup run <version> cargo` fallback.

Exact `cargo --version` must begin with declared `cargo <version> `. Nix builds set `PKGRE_CARGO` to the flake-pinned toolchain.

## Release gate

```console
$ pkgre-indexer check catalog artifacts/artifacts.toml
$ pkgre-indexer render catalog artifacts/artifacts.toml site-next
$ pkgre-indexer verify catalog artifacts/artifacts.toml site-next
$ pkgre-indexer verify-monotonic site-current site-next
```

Deploy only `site-next`; never serve the source catalog as a sparse registry. After deployment, test all `config.json` endpoints, representative index rows, content-addressed archives, and one clean-cache `cargo build --locked` spanning every registry layer.
