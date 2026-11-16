# Self-publishing to crates.io

## Scope

`self-publish/` declares which first-party crates of a catalog repository also reach
crates.io, under which names, and what crates.io holds. It sits at the top of the catalog
repository, beside `registry/`, which stays the reconciler's exclusive state.

| Path | Authority |
|---|---|
| `self-publish/crates-io.toml` | Human authority:owners, self-publishing repositories, name mappings, abandoned versions |
| `self-publish/crates-io.lock` | Generated authority:one entry per crate version released to crates.io |

Both files carry `schema = 1`, belong to catalog registry `main`, and are strict:an unknown
field fails. A repository without `self-publish/` has no self-publishing state; the checks
report that and check nothing, unless the accepted repository has one, because removing the
state is not allowed.

## Principles

- Opt-in per repository:`[[repositories]]` names each repository whose releases also go to
  crates.io. A repository that is not listed keeps publishing to the `pkgre` registry only.
- One release tag per release:the tag is the repository's `tag-prefix` followed by the
  version, so the version can be read from the tag and matches the registry's own tag rule.
- Names differ, versions do not:on crates.io a crate has its mapped name, or
  `pkgre-pkgs-` followed by its `pkgre` name; both registries carry the same versions,
  except the versions recorded as abandoned.
- Permanence:a crates.io version cannot be replaced and a name is hardly ever freed, so
  lock entries are never edited or removed, and a crate's crates.io name does not change
  once it has entries, unless every one of them is abandoned.
- History is append-only:repositories, tag prefixes, lock entries and abandoned records are
  only ever added.
- The offline checks need no network:they compare the candidate state with
  `registry/main.lock` and with an accepted state, and never contact crates.io or GitHub.

## Managed layout

```text
self-publish/
├── crates-io.toml
└── crates-io.lock
```

`self-publish/` holds exactly these two regular files. Another entry, a subdirectory or a
symbolic link fails the checks. Keep notes, proposals and logs outside it.

## Human declarations

`self-publish/crates-io.toml`:

```toml
schema = 1

# crates.io owners expected on every crate this workflow publishes.
owners = ["LOGIN"]

# A self-publishing repository: its releases also go to crates.io.
[[repositories]]
git = "https://github.com/pkgre/pkgre"
tag-prefix = "rust/v"

# Optional crates.io names; other crates get "pkgre-pkgs-" + name.
[names]
pkgre = "pkgre"

# Versions that crates.io never took.
[[abandoned]]
name = "pkgre"
version = "0.5.0"
reason = "crates.io refused the upload: <its message>"
```

`owners` lists the crates.io logins, which are GitHub logins, that must own every crate this
workflow publishes; at least one is required and a login appears once.

### Repositories and tag prefixes

`[[repositories]]` names a self-publishing repository by the same credential-free HTTPS URL
that its publish declarations in `registry/` use. `tag-prefix` turns a version into a
release tag:`tag-prefix` is empty or `v`, or ends with `/` or `/v`, so that the tag's final
component is the version, or `v` and the version. Prefix and version together are a safe Git
ref. Repositories are declared once each, and a repository and its prefix are permanent.
Repositories are compared in a normalized form:the scheme and host are lowercased, a trailing
`.git` is dropped, and for GitHub the path is lowercased too. A Git identity or publish
declaration that names a self-publishing repository in another spelling is refused, so that
it cannot escape the release rules of its declaration.

### Names

`[names]` maps a crate's `pkgre` name to its crates.io name. Without an entry the crates.io
name is `pkgre-pkgs-` followed by the `pkgre` name as the catalog spells it:`pkgre-rust`
becomes `pkgre-pkgs-pkgre-rust`. A key either spells a crate name that a self-publishing
repository publishes or declares, exactly as the catalog spells it, or names no crate of the
catalog at all, so that a name can be declared before the crate's first release. A key that
names a crate the catalog publishes from a mirror or from a repository that does not
self-publish is stale, and refused. The crates.io name rules below apply to every name the
workflow uses.

### Abandoned versions

`[[abandoned]]` records a crate version that reached the `pkgre` registry but will never
reach crates.io, with the reason crates.io gave. A record names an entry of
`self-publish/crates-io.lock`, which stays as it is; the checks accept that the version
exists in one registry only. Records are only ever added and never changed. A crate whose
entries are all abandoned may get another crates.io name in `[names]`, for its later
versions.

## Generated records

`self-publish/crates-io.lock` holds one entry per crate version released to crates.io, in
canonical form and order. Its bytes are exact:the checks refuse a file that differs from the
canonical serialization, which orders entries by lowercased name, then by the exact name,
then by version, as `registry/main.lock` does. An empty lock is exactly:

```toml
schema = 1
```

One entry:

```toml
[[packages]]
name = "pkgre"
version = "0.5.0"
crates-io-name = "pkgre"
crate-sha256 = "<SHA-256 of the crates.io archive>"
pkgre-crate-sha256 = "<crate-sha256 of the identity in registry/main.lock>"
git = "https://github.com/pkgre/pkgre"
tag = "rust/v0.5.0"
commit = "<peeled commit>"
cargo-version = "1.95.0"
```

| Field | Meaning |
|---|---|
| `name`, `version` | The identity in `registry/main.lock` |
| `crates-io-name` | The crates.io name this exact version carries |
| `crate-sha256` | SHA-256 of the crates.io `.crate` archive |
| `pkgre-crate-sha256` | The identity's `crate-sha256` in `registry/main.lock` |
| `git`, `tag`, `commit` | The release:repository, immutable tag, and full peeled commit |
| `cargo-version` | Exact Cargo version that packaged the archive |

Entries are never edited and never removed, not even when the catalog removes the identity.
An entry names one crate version and one release, and each release has one entry.

## Name rules

Checked offline, on every run:

- A crates.io name is at most 64 characters long, contains only ASCII letters, digits, `-`
  and `_`, starts with an ASCII letter, and is not a name crates.io reserves. crates.io
  reserves the names of the Rust project (`std`, `core`, `alloc`, `proc_macro`, …) and the
  Windows device names (`nul`, `con`, `prn`, `aux`, `com0` to `com9`, `lpt0` to `lpt9` and
  the like). A crate with the default prefix can therefore have a `pkgre` name of at most 53
  characters.
- crates.io names are unique among themselves under crates.io's comparison, which ignores
  case and treats `-` and `_` as equal:`foo-bar` and `Foo_Bar` are one name.
- A mapped name does not start with `pkgre-pkgs-`. That namespace belongs to the default
  rule, which keeps the two kinds of names apart.
- A crates.io name is not the name of a crate that `registry/main` mirrors, which belongs to
  someone else on crates.io. Conversely, a mirror may not carry a name the workflow uses,
  mapped or default, or be named `pkgre-pkgs-…`, which readers would take for one of ours.
- Every key of `[names]` either spells a crate name that a self-publishing repository
  publishes or declares, exactly as the catalog spells it, or names no crate of the catalog
  at all, so that a name can be declared before its crate's first release. A key that names
  a crate the catalog publishes from a mirror or from a repository that does not
  self-publish is stale, and refused: the mapping would claim a name that belongs to someone
  else.
- Once a crate has an entry in `self-publish/crates-io.lock`, its crates.io name never
  changes, and neither does its entry in `[names]`, unless every entry of that crate is
  abandoned.

## Offline checks

```text
pkgre-rust self-publish-check <repository> [<accepted-repository>]
```

`<repository>` is a checkout of the catalog repository, the directory that holds `registry/`
and `self-publish/`. The command loads the catalog with the ordinary catalog loader and
runs these checks:

- `crates-io.toml` parses strictly and declares valid owners, repositories, tag prefixes and
  abandoned records; `crates-io.lock` is in canonical form and every entry is well formed.
- The name rules above hold.
- Each self-published identity of `registry/main.lock`, active or removed, has exactly one
  entry in `crates-io.lock` whose fields agree with it, and each entry has exactly one
  identity. An identity is self-published when it comes from a self-publishing repository
  and its tag is that repository's `tag-prefix` followed by the version.
- Each abandoned record names an entry of `crates-io.lock`.
- Compared with the accepted state, each Git identity that the candidate gains from a
  self-publishing repository comes from a release tag of that repository. A tag outside the
  convention, such as `cli/v0.1.0`, is refused, so that no crate of a self-publishing
  repository reaches only one registry.
- Compared with the accepted state, versions only increase, per crate and per repository:a
  new release's version is greater than every version that `registry/main.lock` already
  holds of the crate, and greater than every earlier release version of the repository.
- A release version carries no build metadata, which Cargo and crates.io ignore for
  identity.

`<accepted-repository>` is an earlier checkout of the same repository whose state is
accepted, such as the base of a change. With it, the command also checks that the accepted
lock entries, repositories, tag prefixes and abandoned records are unchanged and only
added, that a crate's crates.io name is permanent while any of its entries is not
abandoned, that each Git identity the candidate gains comes from a release tag, and that
versions increase. Without an accepted repository those comparisons are skipped, and the
command says so; the candidate's own files, name rules, entry correspondence and abandoned
records are still checked. A repository without `self-publish/` is accepted with a message
that there is nothing to check, unless the accepted repository has one: removing the state is
refused. A directory that does not hold `registry/` is refused, so a wrong path does not pass
silently.
