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
  Only the network checks of the releases a run adds read crates.io and the release
  repositories, and they run only when an accepted repository is given.

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
# Optional: the registry that its release tags keep their manifests for.
# "pkgre", the default, rewrites them for the pkgre registry; "crates-io"
# keeps plain crates.io manifests, so that one archive serves both.
# manifests = "crates-io"

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
Repositories are compared in a normalized form:the scheme and host are lowercased, a default
`:443` port and empty or `.` path segments are dropped, `..` segments are resolved, and a
trailing `.git` is dropped; for GitHub the path is lowercased too. A Git identity or publish
declaration that names a self-publishing repository in another spelling is refused, so that
it cannot escape the release rules of its declaration.

### The manifests of a release tag

`manifests` says for which registry a repository's release tags are written. It is optional,
and `"pkgre"`, the default, is the mode above: a release tag with manifests that `pkgre`
rewrites for its own registry, and a derived, separate crates.io archive. `"crates-io"` is
the other mode: the tag's manifests stay plain crates.io manifests, and the tag's own
packaging serves both registries, the `pkgre` one and crates.io, with one archive.

```toml
[[repositories]]
git = "https://github.com/example/workspace"
tag-prefix = "v"
manifests = "crates-io"
```

Since an absent key means the default, a declaration that has no `manifests` keeps its
meaning and the schema stays 1, and a strict parser of an older tool refuses the key. The
value is permanent from the declaration, as the prefix is: the checks refuse a changed or
removed value against the accepted state. Spelling the default, `manifests = "pkgre"`, is
no change.

### Names

`[names]` maps a crate's `pkgre` name to its crates.io name. Without an entry the crates.io
name is `pkgre-pkgs-` followed by the `pkgre` name as the catalog spells it:`pkgre-rust`
becomes `pkgre-pkgs-pkgre-rust`. A key either spells a crate name that a self-publishing
repository publishes or declares, exactly as the catalog spells it, or names no crate of the
catalog at all, so that a name can be declared before the crate's first release. A key that
names a crate the catalog publishes from a mirror or from a repository that does not
self-publish is stale, and refused. The crates.io name rules below apply to every name the
workflow uses.

A crate of a repository whose `manifests` is `"crates-io"` keeps its own name on crates.io,
since nothing rewrites its manifest: its crates.io name is its package name, the default
prefix never applies, and `[names]` may not hold a key for it, because such a key could only
repeat the name that the crate already has.

### Abandoned versions

`[[abandoned]]` records a crate version that reached the `pkgre` registry but will never
reach crates.io, with the reason crates.io gave. A record names an entry of
`self-publish/crates-io.lock`, which stays as it is; the checks accept that the version
exists in one registry only. Records are only ever added and never changed. A version is
abandoned only after it was released:a new record names an entry of the accepted
`crates-io.lock`, so a release cannot be added and abandoned in the same change. A crate
whose entries are all abandoned may get another crates.io name in `[names]`, for its later
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
An entry names one crate version and one release, and each release has one entry. An entry
of a repository whose `manifests` is `"crates-io"` records `crates-io-name` equal to `name`
and `crate-sha256` equal to `pkgre-crate-sha256`, since the tag's own archive is both
registries' package, and the checks refuse any other value.

## The derivation

For one release tag, `self-publish-lock` derives the crates.io package of every crate
that the catalog publishes from it:

1. It fetches the tag into a fresh checkout with the same safety checks as the catalog's
   own tag publication and requires the tag object and the commit that
   `registry/main.lock` records.
2. It reads the workspace with `cargo metadata --no-deps --locked` and requires the crates
   the catalog publishes from the tag to be exactly its publishable members, whose
   `publish` is exactly `["pkgre"]`. It applies the Gitlink rule of `docs/catalog.md` to
   that workspace: a Gitlink is accepted when the innermost member whose directory
   contains it is not a released crate, or when no member's directory contains it, and
   is refused otherwise, naming the Gitlink and the crate; a released crate's `readme`,
   `license-file`, `build` or target `path` that resolves at or below a Gitlink is
   refused; and no derived archive may hold a path at or below one. A path that a released
   crate's manifest names must resolve inside the tag's checkout and outside its `.git`
   directory: an absolute `readme` or `license-file`, or one that `..` components take outside
   the checkout, is refused. Submodules are never initialized or fetched.
3. It rewrites every manifest of the workspace with `toml_edit`, the released members' and
   the others' alike, since Cargo loads the whole workspace:
   - for each released crate, its crates.io name and `publish = ["crates-io"]`, and
     explicit names for its library and for the binary of `src/main.rs`, which Cargo would
     otherwise derive from the package name, so that code and installed programs keep
     their names;
   - in every dependency table of every member (normal, dev, build, target-specific, and
     `[workspace.dependencies]`), no `registry` key, and `package = "<crates.io name>"`
     under the unchanged dependency key for a first-party dependency, a path dependency on
     a renamed member included;
   - it accepts a dependency of one released crate on another released crate of the same tag
     when the manifest declares it as a path dependency of that crate's own directory,
     requires exactly the tag's version `=X.Y.Z`, and names `registry = "pkgre"`, which is
     what the reconciler accepts; the rewrite keeps the path and the version, gives it
     `package = "<crates.io name>"` under the unchanged key, and removes `registry`;
   - it refuses `[patch]` and `[replace]`, a dependency between two released crates of one
     tag that does not meet those rules, a dependency on a crate the tag does not release, a
     dependency on a fork, a member that is not released but depends on something crates.io
     does not have, and a first-party version without an entry in `crates-io.lock`.
4. It translates `Cargo.lock`: a source of the `pkgre` registry becomes crates.io; a
   mirrored identity keeps its name, version and checksum; a first-party identity of an
   earlier release takes its crates.io name and the `crate-sha256` of its `crates-io.lock`
   entry; a workspace member takes its crates.io name, also in the dependency lists of
   other packages, and stays a path package, since the rewritten manifest keeps the path and
   Cargo packages the release's crates together.
5. It packages the release with the pinned Cargo, in a fresh isolated Cargo home that uses
   plain crates.io, from a working directory outside the checkout:
   `cargo package --no-verify --locked --allow-dirty`, with one `-p` for each released
   crate, twice, requiring identical bytes. One run packages every crate of the release, so
   Cargo serves a crate of the tag to the crates that depend on it through the temporary
   registry it builds from the archives of that run, and the packaged `Cargo.lock` of a
   dependent names its sibling under the sibling's crates.io name, crates.io's source, and
   the archive of that same run. `--locked` proves that crates.io resolves the
   translated lock without a change. The derivation refuses to run Cargo when the working
   directory or a directory above it holds `.cargo/config.toml` or `.cargo/config`, as a
   file, directory or symbolic link, since such configuration could replace crates.io.
6. It compares each derived archive with the archive that the catalog retains: the same
   files below the top directory, identical bytes and permissions for every file except
   `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock` and `.cargo_vcs_info.json`; a VCS claim
   that differs only by `dirty`; a normalized manifest that differs only in the fields the
   rewrite changed, where every dependency's `package` is exactly its expected crates.io
   name and no `registry` or `registry-index` remains; and two lock files that list the
   same packages at the same versions under the mapped names, every package outside the
   workspace with its own registry's source and expected checksum: the catalog's
   `crate-sha256` in the retained archive, and crates.io's, for a first-party identity the
   `crate-sha256` of its `crates-io.lock` entry, in the derived one. A crate of the release
   that another crate of the release depends on is such a package too: the retained archive
   names it under the `pkgre` registry with the catalog's `crate-sha256`, and the derived
   archive under crates.io with the archive this run packaged, which is the entry the run
   records for it.
7. It records the result.

Deriving from the tag and proving the result against the retained archive is what lets
`cargo publish` work from ordinary sources, and what guarantees that the crates.io package
is the curated package with a mechanically rewritten manifest.

Every Git and Cargo process of the derivation starts from an empty environment and inherits
only `PATH`, `TMPDIR`, the certificate variables, `CARGO_HOME`, and `RUSTC` pointing at the
`rustc` beside the pinned `cargo`; no wrapper and no token variable reaches it. The
derivation works in a temporary directory and refuses to run when that directory or any
directory above it holds Cargo configuration, so set `TMPDIR` to a directory that no Cargo
configuration covers; a symbolic link on the way is resolved too, since Cargo follows it.

## Recording entries

```text
pkgre-rust self-publish-lock <repository>
```

`<repository>` is a checkout of the catalog repository, the directory that holds
`registry/` and `self-publish/`. The command derives every self-published identity of
`registry/main.lock` that has no entry in `crates-io.lock` yet, grouped by release so that
each tag is fetched and packaged once, and writes the new entries in canonical form. It
runs the offline checks above on the result before it writes, so it never writes a lock
that `self-publish-check` refuses, and it writes the file atomically.

- A run with nothing to derive changes nothing and says so.
- An identity the catalog removed cannot be derived, because the catalog no longer retains
  its archive; it needs an entry, which only a release could add while the identity was
  active.
- A crate added to a tag that `crates-io.lock` already records is refused:a release tag
  publishes the crates of its commit, so only a new version can add one.
- An identity from a tag that is not a release tag is skipped, because it predates the
  repository's self-publishing and has no entry of its own; the offline checks refuse one
  that a change adds.

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
- A mapped name does not start with `pkgre-pkgs-`, and neither does the name of a crate
  whose release tags keep crates.io manifests, which is its package name. That namespace
  belongs to the default rule, which keeps the two kinds of names apart.
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

## Checks

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
  and its tag is that repository's `tag-prefix` followed by the version. An entry of a
  repository whose `manifests` is `"crates-io"` records the crate's own name as its
  crates.io name and one archive for both registries, so `crates-io-name` equals `name` and
  `crate-sha256` equals `pkgre-crate-sha256`.
- Each abandoned record names an entry of `crates-io.lock`, and a record that the accepted
  state does not have names an entry of the accepted lock, so that a version is abandoned
  only after it was released.
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
lock entries, repositories, tag prefixes, `manifests` values and abandoned records are
unchanged and only added, that a crate's crates.io name is permanent while any of its entries
is not abandoned, that each Git identity the candidate gains comes from a release tag, and
that versions increase. Without an accepted repository those comparisons are skipped, and the
command says so; the candidate's own files, name rules, entry correspondence and abandoned
records are still checked. A repository without `self-publish/` is accepted with a message
that there is nothing to check, unless the accepted repository has one: removing the state is
refused. A directory that does not hold `registry/` is refused, so a wrong path does not pass
silently.

## Network checks

With an accepted repository, the command also checks the releases that the run adds. A
release is added when one of its self-published identities is missing from the accepted
catalog, or when its `crates-io.lock` entry is missing from the accepted lock. The second
case covers a repository newly declared in `[[repositories]]` and a newly declared
`self-publish/` as well as a new release: their identities are already in the accepted
catalog, but their entries are new, and an entry is permanent once it is merged. An accepted
repository without `self-publish/` records no entry at all.

A run without an accepted repository, and a run that adds no release, makes no request at
all, so an unavailable crates.io or release repository fails only a change that publishes
something. For each added release, one repository and tag, and each of its crates:

- The release repository's default branch, read with `git ls-remote --symref`. The branch and
  the tag are fetched into a temporary repository with the workflow's Git safety settings.
  The tag must be annotated, its object and its commit must be the ones that
  `registry/main.lock` records, and its commit must be an ancestor of the default branch, so
  that a release is a deliberate, reviewed commit of the branch that is published.
- crates.io's sparse index, `https://index.crates.io/`, for the published versions of each
  crates.io name, and crates.io's API, `https://crates.io/api/v1/crates/<name>/owners`, for
  its owners. A name either does not exist, or is owned by exactly the users of `owners` and
  by no team; a version either does not exist, or exists with the recorded `crate-sha256`,
  compared without build metadata, which crates.io ignores. A missing crate is a 404, not an
  error.
- crates.io's category slugs, `https://crates.io/api/v1/category_slugs`. Every category a
  crate declares is one of them, which is stricter than crates.io, which only drops an
  unknown category with a warning.
- crates.io's own rules for a package: a description of at most 1000 bytes, a license or a
  `license-file`, at most 5 keywords of at most 20 bytes each and of the characters crates.io
  accepts, at most 5 categories, a `homepage`, `documentation` and `repository` that are
  `http` or `https` URLs with an authority, a derived archive of at most 10 MB, and the
  categories above. The license expression itself is not validated as SPDX: crates.io refuses
  an expression it cannot parse, and that refusal reaches the upload, not the checks.
- The derivation of the release, exactly as `self-publish-lock` runs it: the catalog
  publishes exactly the tag's publishable members, the manifests and the lock file are
  rewritten, the crates are packaged twice with the pinned Cargo, every derived archive is
  compared with the archive the catalog retains, and the derived `crate-sha256` is the one
  `crates-io.lock` records.

Every request is a read over HTTPS with a fixed user agent that names this repository, no
proxy or token variable, and the empty environment of the workflow's child processes.
crates.io's documents are bounded: `curl` reads at most 4 MiB of an API document and 16 MiB
of a sparse-index file, with a 20-second connection timeout and a 120-second overall limit,
and crates.io's API is read at most once a second. The Git transfers are bounded differently:
`http.lowSpeedLimit` and `http.lowSpeedTime` abort a transfer that stays below 1000 bytes per
second for 60 seconds, so a stalled server ends the check, but a transfer that keeps making
progress has no overall time limit. The fetches ask for commits and trees only, so the blobs
of the default branch never cross the network. Each crate name is read once per run, and the
category slugs only when a crate declares a category.

A failed check is a refusal that names the crate, the version, the check and what was found.
An unavailable crates.io or release repository is an error that names the service and says
that the check could not run.

## The upload routine

```text
pkgre-rust self-publish <repository> <tag> [--upload] [--git=<url>]
```

`<repository>` is a checkout of the catalog repository, the directory that holds `registry/`
and `self-publish/`, and `<tag>` is a release tag of a self-publishing repository, such as
`rust/v0.5.0`. Without `--upload` the command is a dry run: it runs every check an upload
needs and reports what the upload would do, and it uploads nothing. The dry run builds the
crates with Cargo's verification, so it runs their build scripts and proc macros, as the same
user, as step 5 of an upload does.

For one release, a run:

1. requires a clean checkout, with no staged, unstaged or untracked change, whose `HEAD` is
   contained in the remote-tracking `origin/main`, so that only a merged release is published.
   The routine never fetches: when the containment check fails, it says to run
   `git fetch origin main` first.
2. runs the offline checks of this document, and the network checks above for this release:
   the annotated tag on the repository's default branch, the tag's crates, the crates.io owners
   and versions, crates.io's own package rules, and the derivation that reproduces the recorded
   `crate-sha256` and compares the result with the retained archive.
3. requires the `pkgre` registry, at the catalog's own `[registry] index`, to serve every crate
   version of the release, unyanked, with the checksum that `registry/main.lock` records. The
   index is read with the same rules as crates.io's: bounded documents, no token, no fallback.
4. reads each crate version from crates.io's sparse index: published with the recorded checksum,
   so there is nothing to do; published and yanked, which the run reports and never un-yanks;
   missing, which it would upload; or different, which it refuses and never forces. A version
   recorded in `[[abandoned]]` is skipped and reported. It also requires crates.io to serve every
   package outside the release that the release depends on: a mirrored identity under its name,
   version and checksum, and a crate of an earlier release under its crates.io name and the
   `crate-sha256` of its `crates-io.lock` entry. The derivation refuses a dependency on an
   abandoned version, on a fork, or on a version without an entry, so this check sees only
   identities that crates.io is expected to have. A crate of the release is not one of them:
   the release itself serves it, so crates.io may lack it, and a crate of the release that
   crates.io already has while a crate it depends on is missing is refused, since crates.io
   cannot have taken the dependent before its sibling. A yanked dependency is reported rather
   than refused, since Cargo accepts a yanked version that a lock file pins.
5. builds the missing crates with Cargo's verification, `cargo package --locked --allow-dirty`
   in the derived, rewritten workspace, against plain crates.io, in an isolated Cargo home, from
   a working directory that no Cargo configuration covers, and requires each archive's SHA-256
   to equal its `crates-io.lock` entry. The missing crates are packaged in one run, so a crate
   whose sibling crates.io does not have yet is packaged against that sibling of the same run.
   This is the only step in which package code, such as a build script or a proc macro, runs,
   and it happens while no token is in reach. The step runs
   Cargo in a process group of its own, with a null standard input, so that a token piped to the
   routine never reaches Cargo or the packages, and ends that group once Cargo returns, so that
   no process the package code started outlives it.
6. with `--upload`, and only after steps 1 to 5 passed, packages the missing crates the way
   `cargo publish` packages them, `cargo package --no-verify --locked --allow-dirty`, in the same
   derived workspace and in the upload's own isolated Cargo home, which configures plain
   crates.io with the `cargo:token` credential provider and no other registry; they are
   packaged in one run, as in step 5, so a dependent whose sibling crates.io does not have yet
   is packaged against that sibling of the same run, and it requires each of those archives to
   equal its `crates-io.lock` entry. Only then does it read the token and run
   `cargo publish --no-verify --locked --allow-dirty` for each missing crate, with the token in
   the environment of that one process alone. A crate of the release is published after the
   crates it depends on, and name order decides among crates that do not depend on each other,
   so a release whose crates do not depend on each other uploads in name order, as it always
   did. `--no-verify` keeps package code from
   running while the token is present, and the routine starts no package code between the
   comparison and the upload. A process that step 5's package code detached could still change
   the workspace before `cargo publish` packages it again (see the residual risk below); step 7
   then finds crates.io's checksum differing from the record, after the upload.
7. waits, with a bound, until crates.io's index shows each uploaded crate with the recorded
   checksum, and reports every crate version of the release.

A run after a partial failure uploads only what crates.io still lacks, so running the same
command again finishes the release, including one whose library is published and whose binary
is missing; a run whose crates are all published reads no token and uploads nothing, and a run
that finds a dependent published while a crate it depends on is missing refuses, naming both.
The routine never yanks, deletes, or changes owners.

`--git=<url>` chooses between several self-publishing repositories that use the same release
tag; without it such a tag is refused, and the refusal names the repositories.

### Reports

Each crate version of the release is reported in one state:

| State | Meaning |
|---|---|
| `published` | crates.io has the version with the recorded checksum |
| `published-yanked` | crates.io has the version with the recorded checksum, and yanked it |
| `missing` | crates.io does not have the version; a dry run would upload it |
| `uploaded` | the run uploaded the version, and crates.io's index shows it |
| `abandoned` | `[[abandoned]]` records the version; the run skipped it |
| `different` | crates.io holds the version with another archive; the run refused |

The summary counts the release's crate versions per state, the packages outside the release
whose crates.io state the run checked, and the yanked dependencies among them. An error names
the crate, the version, the step, and what was found; an unavailable crates.io, release
repository or registry is an error that names the service and says that the step could not run,
never a pass.

### The token

The token is created by the person who uploads, as described in
[`security.md`](security.md): the endpoint scopes `publish-new` and `publish-update` only,
limited to the crate names this workflow publishes, with a short expiry. The routine reads it
only with `--upload`, and only after every check passed: from a prompt that does not echo when
standard input is a terminal, otherwise from one line of standard input. The prompt is the
recommended way to give it, since a token piped on standard input waits there while the
crates' build scripts and proc macros run. It is never read from the routine's environment, its
command line, or a file, and an empty token is refused.

The routine refuses to start, before any other work and for a dry run too, while
`CARGO_REGISTRY_TOKEN` or any `CARGO_REGISTRIES_<NAME>_TOKEN` is set in its own environment: it
names the variable and never its value, since a child process could otherwise inherit it.
With `--upload`, the routine makes its own process non-dumpable before it starts any child, so
that no other process of the same user can open its `/proc` files, its standard input among
them, while a token could be in reach. Every child process starts from an empty environment
with the allowlist of the derivation (`PATH`, `TMPDIR`, the certificate variables, an isolated
`CARGO_HOME`, and the `rustc` beside the pinned `cargo`), and only the upload process also gets
the token. The token is never printed, logged, written to a file, or placed in an error, and
any output of the upload process that the routine relays has every occurrence of it replaced;
it is dropped once the uploads finish.

The residual risk is package code: the dry run and step 5 run the crates' build scripts and proc
macros as the same user, and a process that such code detaches from its process group survives
it. Such a process can read the environment of the upload process, which holds the token, and
it can change the rewritten workspace or the upload's Cargo home after step 6's comparison, so
that `cargo publish` uploads other bytes than the recorded ones, which step 7 detects only after
the upload. The prompt keeps the token
out of that reach until the uploads begin. An interrupt during step 5 ends the routine without
unwinding, so Cargo and the package code it started keep running until they finish, in the
derivation's temporary directory, which stays behind; the next run compares the packages again
before it uploads anything.
