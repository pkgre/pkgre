//! Isolation of the child processes that run Git and Cargo for a package.
//!
//! The reconciler's Git-tag packaging and the self-publishing derivation share
//! it. Every Git and Cargo process starts from an empty environment and
//! inherits a short allowlist, so that no token, wrapper, or proxy variable of
//! the caller reaches it. Cargo additionally never runs inside a directory that
//! Cargo configuration covers, since such configuration could replace
//! crates.io.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

/// Cargo configuration filenames, which Cargo reads from a `.cargo` directory.
const CARGO_CONFIGURATION_FILES: [&str; 2] = ["config.toml", "config"];

/// The variables of the certification authorities a child may verify TLS with.
const CERTIFICATE_VARIABLES: [&str; 7] = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "CARGO_HTTP_CAINFO",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "NIX_SSL_CERT_FILE",
];

/// Refuses to run Cargo when its working directory or a directory above it
/// holds Cargo configuration.
///
/// Cargo reads `.cargo/config.toml` and the older `.cargo/config` from the
/// working directory and every directory above it, and such configuration can
/// replace crates.io. A file, directory, or symbolic link of either name is
/// refused, because a symbolic link cannot be inspected portably.
///
/// # Errors
///
/// Returns an error for a working directory that cannot be resolved, or for the
/// first Cargo configuration that covers it.
pub(crate) fn ensure_no_cargo_configuration(directory: &Path) -> Result<()> {
    let directory = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve the current directory")?
            .join(directory)
    };
    let mut candidates = vec![directory.clone()];
    let physical = physical_path(&directory);
    if physical != directory {
        candidates.push(physical);
    }
    for candidate in candidates {
        for ancestor in candidate.ancestors() {
            for name in CARGO_CONFIGURATION_FILES {
                let path = ancestor.join(".cargo").join(name);
                match fs::symlink_metadata(&path) {
                    Ok(_) => bail!(
                        "Cargo configuration {} covers {} and could replace crates.io; run the command from a directory that no Cargo configuration covers",
                        path.display(),
                        directory.display()
                    ),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("inspect Cargo configuration {}", path.display())
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Returns the physical path of one directory, with every symbolic link of the
/// part that exists resolved.
///
/// Cargo finds its configuration from the working directory the operating
/// system gives it, so the directories behind symbolic links are searched too.
fn physical_path(directory: &Path) -> PathBuf {
    let mut existing = directory.to_path_buf();
    let mut suffix: Vec<OsString> = Vec::new();
    loop {
        if let Ok(canonical) = fs::canonicalize(&existing) {
            let mut path = canonical;
            for component in suffix.iter().rev() {
                path.push(component);
            }
            return path;
        }
        let Some(name) = existing.file_name().map(OsStr::to_owned) else {
            return directory.to_path_buf();
        };
        suffix.push(name);
        if !existing.pop() {
            return directory.to_path_buf();
        }
    }
}

/// The fixed environment of every Git and Cargo child process.
#[derive(Clone, Debug)]
pub(crate) struct ChildEnvironment {
    /// The variables every child inherits.
    variables: Vec<(OsString, OsString)>,
}

impl ChildEnvironment {
    /// Captures the allowlist for children that use one isolated Cargo home and
    /// one pinned toolchain.
    ///
    /// The child inherits `PATH` and `TMPDIR`, the certificate variables when
    /// the caller sets them, and nothing else; `CARGO_HOME` and `RUSTC` are
    /// added, the latter pointing at the `rustc` beside the pinned `cargo`, so
    /// that Cargo never falls back to the `rustc` of `PATH`.
    ///
    /// # Errors
    ///
    /// Returns an error when the pinned toolchain has no `rustc` beside its
    /// `cargo`.
    pub(crate) fn capture(cargo_home: &Path, cargo: &Path) -> Result<Self> {
        let rustc = rustc_beside(cargo)?;
        let mut variables = Vec::new();
        for name in ["PATH", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                variables.push((OsString::from(name), value));
            }
        }
        for name in CERTIFICATE_VARIABLES {
            if let Some(value) = std::env::var_os(name) {
                variables.push((OsString::from(name), value));
            }
        }
        variables.push((
            OsString::from("CARGO_HOME"),
            cargo_home.as_os_str().to_owned(),
        ));
        variables.push((OsString::from("RUSTC"), rustc.into_os_string()));
        Ok(Self { variables })
    }

    /// Starts a command from an empty environment and applies the allowlist.
    pub(crate) fn apply(&self, command: &mut Command) {
        command.env_clear();
        for (name, value) in &self.variables {
            command.env(name, value);
        }
    }

    /// Starts a command from the allowlist and adds the variables of one tool.
    pub(crate) fn apply_with(&self, command: &mut Command, extra: &[(&str, &OsStr)]) {
        self.apply(command);
        for (name, value) in extra {
            command.env(name, value);
        }
    }
}

/// Returns the `rustc` of the pinned toolchain, which sits beside its `cargo`.
fn rustc_beside(cargo: &Path) -> Result<PathBuf> {
    let directory = cargo
        .parent()
        .with_context(|| format!("pinned Cargo {} has no parent directory", cargo.display()))?;
    let rustc = directory.join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
    let metadata = fs::symlink_metadata(&rustc)
        .with_context(|| format!("inspect the pinned toolchain's rustc {}", rustc.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "the pinned toolchain's rustc is not a regular file: {}",
        rustc.display()
    );
    Ok(rustc)
}
