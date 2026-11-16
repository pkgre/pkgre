//! crates.io crate-name rules and crates.io's comparison of names.

use anyhow::{Result, ensure};

/// Maximum length of a crates.io crate name, in characters.
pub(crate) const MAX_CRATES_IO_NAME_LENGTH: usize = 64;

/// Prefix that a crate without a mapping gets on crates.io.
pub(crate) const DEFAULT_NAME_PREFIX: &str = "pkgre-pkgs-";

/// Names that crates.io refuses, in crates.io's own comparison.
///
/// crates.io keeps these in its `reserved_crate_names` table: names the Rust
/// project reserves for itself, and Windows device names that a package could
/// not create on Windows.
const RESERVED_NAMES: &[&str] = &[
    "alloc",
    "arena",
    "ast",
    "builtins",
    "collections",
    "compiler-builtins",
    "compiler-rt",
    "compiletest",
    "core",
    "coretest",
    "debug",
    "driver",
    "flate",
    "fmt_macros",
    "grammar",
    "graphviz",
    "macro",
    "macros",
    "proc_macro",
    "rbml",
    "rust-installer",
    "rustbook",
    "rustc",
    "rustc_back",
    "rustc_borrowck",
    "rustc_driver",
    "rustc_llvm",
    "rustc_resolve",
    "rustc_trans",
    "rustc_typeck",
    "rustdoc",
    "rustllvm",
    "rustuv",
    "serialize",
    "std",
    "syntax",
    "test",
    "unicode",
    "nul",
    "con",
    "prn",
    "aux",
    "com0",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt0",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
];

/// Returns crates.io's comparison key for a name.
///
/// crates.io compares names after lowercasing them and treating `-` and `_` as
/// the same character, so `Foo-Bar` and `foo_bar` are one name there.
#[must_use]
pub(crate) fn canonical(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

/// Returns crates.io's name for a crate that has no mapping.
#[must_use]
pub(crate) fn default_name(crate_name: &str) -> String {
    format!("{DEFAULT_NAME_PREFIX}{crate_name}")
}

/// Returns whether a name is in the namespace of the default rule.
///
/// A mapped name may not be, so that a reader can tell the two kinds of names
/// apart; the comparison is crates.io's.
#[must_use]
pub(crate) fn is_in_default_namespace(name: &str) -> bool {
    canonical(name).starts_with(&canonical(DEFAULT_NAME_PREFIX))
}

/// Returns whether crates.io reserves a name.
#[must_use]
pub(crate) fn is_reserved(name: &str) -> bool {
    let key = canonical(name);
    RESERVED_NAMES
        .iter()
        .any(|reserved| canonical(reserved) == key)
}

/// Validates a crates.io crate name as crates.io does.
///
/// # Errors
///
/// Returns an error when the name is empty, longer than 64 characters, starts
/// with anything but an ASCII letter, contains a character other than an ASCII
/// alphanumeric, `-` or `_`, or is reserved.
pub(crate) fn validate(name: &str) -> Result<()> {
    validate_syntax(name)?;
    ensure!(
        !is_reserved(name),
        "crates.io reserves the crate name {name:?}"
    );
    Ok(())
}

/// Validates the syntax of a crates.io crate name, without the reserved list.
///
/// The reserved list changes with crates.io, so a name already recorded in the
/// generated lock only keeps valid syntax.
///
/// # Errors
///
/// Returns an error when the name is empty, longer than 64 characters, starts
/// with anything but an ASCII letter, or contains a character other than an
/// ASCII alphanumeric, `-` or `_`.
pub(crate) fn validate_syntax(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "crates.io crate name is empty");
    ensure!(
        name.chars().count() <= MAX_CRATES_IO_NAME_LENGTH,
        "crates.io crate name {name:?} is longer than {MAX_CRATES_IO_NAME_LENGTH} characters"
    );
    ensure!(
        name.is_ascii(),
        "crates.io crate name {name:?} is not ASCII"
    );
    let first = name.chars().next().expect("checked for an empty name");
    ensure!(
        first.is_ascii_alphabetic(),
        "crates.io crate name {name:?} must start with an ASCII letter"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "crates.io crate name {name:?} contains a character other than an ASCII alphanumeric, `-`, or `_`"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_io_comparison_ignores_case_and_separators() {
        assert_eq!(canonical("Foo-Bar"), canonical("foo_bar"));
        assert_eq!(canonical("pkgre-pkgs-x"), "pkgre_pkgs_x");
        assert_ne!(canonical("foo-bar"), canonical("foobar"));
    }

    #[test]
    fn valid_names_follow_crates_io_rules() {
        let longest = "o".repeat(MAX_CRATES_IO_NAME_LENGTH);
        for name in ["serde", "foo-bar", "foo_bar", "a", longest.as_str()] {
            validate(name).unwrap();
        }
    }

    #[test]
    fn invalid_names_are_refused() {
        let too_long = "o".repeat(MAX_CRATES_IO_NAME_LENGTH + 1);
        for (name, expected) in [
            ("", "is empty"),
            (too_long.as_str(), "longer than 64 characters"),
            ("1foo", "must start with an ASCII letter"),
            ("-foo", "must start with an ASCII letter"),
            ("_foo", "must start with an ASCII letter"),
            ("foo+bar", "contains a character"),
            ("f\u{e9}o", "is not ASCII"),
        ] {
            let error = validate(name).unwrap_err().to_string();
            assert!(error.contains(expected), "{name:?}: {error}");
        }
    }

    #[test]
    fn reserved_names_are_refused_in_any_spelling() {
        for name in ["nul", "NUL", "con", "Std", "proc-macro", "com0", "lpt9"] {
            let error = validate(name).unwrap_err().to_string();
            assert!(error.contains("reserves"), "{name:?}: {error}");
        }
        for name in ["nuls", "stdx", "proc-macro-extension", "com10"] {
            validate(name).unwrap();
        }
    }

    #[test]
    fn the_default_namespace_covers_every_spelling() {
        for name in ["pkgre-pkgs-x", "PKGRE-PKGS-x", "pkgre_pkgs_x"] {
            assert!(is_in_default_namespace(name), "{name:?}");
        }
        for name in ["pkgre-pkgs", "pkgre-pkg-x", "xpkgre-pkgs-x"] {
            assert!(!is_in_default_namespace(name), "{name:?}");
        }
        assert_eq!(default_name("pkgre-rust"), "pkgre-pkgs-pkgre-rust");
    }
}
