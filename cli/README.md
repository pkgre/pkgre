# pkgre

The `pkgre` command-line tool for the [pkgre](https://github.com/pkgre/pkgre) curated Cargo registries.

## `pkgre install`

```text
pkgre install [--dry-run]
```

`pkgre install` adds the public `pkgre` registry to the Cargo configuration that applies to every project of the user:

```toml
[registries.pkgre]
index = "sparse+https://rust.pkg.re/"
```

It writes that table to the file Cargo reads first: `config` in the Cargo home when that file exists, `config.toml` beside it otherwise, creating the file and the Cargo home when they are absent. The Cargo home is the value of `CARGO_HOME`, with a relative value taken relative to the current directory, and `$HOME/.cargo` (`%USERPROFILE%\.cargo` on Windows) when `CARGO_HOME` is not set.

Dependencies can then name the registry:

```toml
[dependencies]
anyhow = { version = "1.0", registry = "pkgre" }
```

and programs install from it with `cargo install --registry pkgre NAME`.

Nothing else changes. The command does not make `pkgre` the default registry, and a dependency without `registry = "pkgre"` still resolves crates.io.

### What it refuses

The command changes nothing and exits with status 1, after printing the fix, when:

- the configuration file is not a regular file, such as a symbolic link into a read-only store;
- the file is not valid TOML;
- `registries` or `registries.pkgre` is not a table;
- `registries.pkgre` exists with another index, or with none. A registry named `pkgre` that resolves somewhere else is either the user's own or an old address of this one, and replacing it silently would change what their locked projects resolve.

Everything else about an existing file survives: comments, ordering, formatting and other keys of `[registries.pkgre]`, such as `credential-provider`. A second run changes nothing and says so.

`--dry-run` prints the file it would write and the text it would write, and writes nothing.

The exit status is 0 when the registry is configured, then or before; 1 on a refusal or an error; and 2 on a usage error.

## Undoing it

Delete the two lines the command added:

```toml
[registries.pkgre]
index = "sparse+https://rust.pkg.re/"
```
