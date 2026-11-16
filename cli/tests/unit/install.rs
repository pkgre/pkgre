//! Unit tests of the configuration text edit.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::*;

/// The two lines that configure the registry.
const TABLE: &str = concat!(
    "[registries.pkgre]\n",
    "index = \"sparse+https://rust.pkg.re/\""
);

/// The text that `configure` adds to `text`, which must be a change.
fn added(text: &str) -> String {
    match configure(text) {
        Ok(Change::Added { text }) => text,
        Ok(Change::Unchanged) => panic!("{text:?}: expected an addition, got no change"),
        Err(refusal) => panic!("{text:?}: expected an addition, got {}", refusal.explain()),
    }
}

/// Asserts that `configure` leaves `text` as it is.
fn unchanged(text: &str) {
    match configure(text) {
        Ok(Change::Unchanged) => {}
        Ok(Change::Added { text }) => panic!("expected no change, got {text:?}"),
        Err(refusal) => panic!("expected no change, got {}", refusal.explain()),
    }
}

/// The refusal that `configure` gives for `text`.
fn refusal(text: &str) -> Refusal {
    match configure(text) {
        Ok(Change::Unchanged) => panic!("{text:?}: expected a refusal, got no change"),
        Ok(Change::Added { text: changed }) => {
            panic!("{text:?}: expected a refusal, got {changed:?}");
        }
        Err(refusal) => refusal,
    }
}

/// Asserts that `text` is refused for its `registries.pkgre` index, if any.
fn refused_index(text: &str, expected: Option<&str>) {
    match refusal(text) {
        Refusal::DifferentIndex { current } => {
            assert_eq!(current.as_deref(), expected, "in {text:?}");
        }
        other => panic!(
            "{text:?}: expected a different index, got {}",
            other.explain()
        ),
    }
}

#[test]
fn empty_text_gets_the_registry_table() {
    assert_eq!(added(""), format!("{TABLE}\n"));
}

#[test]
fn comments_and_other_tables_keep_every_byte() {
    let before = "# Cargo configuration\n[build]\njobs = 4\n\n[net]\nretry = 2\n";
    assert_eq!(added(before), format!("{before}\n{TABLE}\n"));
}

#[test]
fn a_file_without_a_final_newline_gains_a_table() {
    assert_eq!(
        added("[build]\njobs = 4"),
        format!("[build]\njobs = 4\n\n{TABLE}\n")
    );
}

#[test]
fn an_empty_registries_table_gains_the_registry_table() {
    assert_eq!(
        added("[registries]\n"),
        format!("[registries]\n\n{TABLE}\n")
    );
}

#[test]
fn a_registries_table_with_another_registry_gains_the_registry_table() {
    let before = "[registries.crates-io]\nindex = \"sparse+https://index.crates.io/\"\n";
    assert_eq!(added(before), format!("{before}\n{TABLE}\n"));
}

#[test]
fn the_registry_table_follows_the_last_registries_table() {
    let before = "[registries.crates-io]\nindex = \"sparse+https://index.crates.io/\"\n\n\
                  [registries.other]\nindex = \"https://example.invalid/\"\n\n\
                  [build]\njobs = 4\n";
    let after = added(before);
    let expected = "[registries.crates-io]\nindex = \"sparse+https://index.crates.io/\"\n\n\
                    [registries.other]\nindex = \"https://example.invalid/\"\n\n\
                    [registries.pkgre]\nindex = \"sparse+https://rust.pkg.re/\"\n\n\
                    [build]\njobs = 4\n";
    assert_eq!(after, expected);
}

#[test]
fn an_inline_registries_table_gains_an_entry() {
    let before = "registries = { crates-io = { index = \"sparse+https://index.crates.io/\" } }\n";
    let expected = "registries = { crates-io = { index = \"sparse+https://index.crates.io/\" }, \
                    pkgre = { index = \"sparse+https://rust.pkg.re/\" } }\n";
    assert_eq!(added(before), expected);
}

#[test]
fn an_empty_inline_registries_table_gains_an_entry() {
    assert_eq!(
        added("registries = {}\n"),
        "registries = { pkgre = { index = \"sparse+https://rust.pkg.re/\" } }\n"
    );
}

#[test]
fn dotted_registries_keys_gain_dotted_keys() {
    let before = "registries.crates-io.index = \"sparse+https://index.crates.io/\"\n";
    let expected = "registries.crates-io.index = \"sparse+https://index.crates.io/\"\n\
                    registries.pkgre.index = \"sparse+https://rust.pkg.re/\"\n";
    assert_eq!(added(before), expected);
}

#[test]
fn a_table_with_the_index_is_unchanged() {
    unchanged("[registries.pkgre]\nindex = \"sparse+https://rust.pkg.re/\"\n");
}

#[test]
fn a_table_with_the_index_keeps_its_other_keys() {
    unchanged(
        "[registries.pkgre]\n\
         index = \"sparse+https://rust.pkg.re/\"\n\
         credential-provider = \"cargo:token\"\n",
    );
}

#[test]
fn a_table_with_another_index_is_refused() {
    refused_index(
        "[registries.pkgre]\nindex = \"https://example.invalid/\"\n",
        Some("\"https://example.invalid/\""),
    );
}

#[test]
fn a_table_without_an_index_is_refused() {
    refused_index(
        "[registries.pkgre]\ncredential-provider = \"cargo:token\"\n",
        None,
    );
}

#[test]
fn an_inline_table_with_the_index_is_unchanged() {
    unchanged("registries = { pkgre = { index = \"sparse+https://rust.pkg.re/\" } }\n");
}

#[test]
fn an_inline_table_with_another_index_is_refused() {
    refused_index(
        "registries = { pkgre = { index = \"https://example.invalid/\" } }\n",
        Some("\"https://example.invalid/\""),
    );
}

#[test]
fn an_inline_table_without_an_index_is_refused() {
    refused_index("registries = { pkgre = {} }\n", None);
}

#[test]
fn dotted_keys_with_the_index_are_unchanged() {
    unchanged("registries.pkgre.index = \"sparse+https://rust.pkg.re/\"\n");
}

#[test]
fn dotted_keys_with_another_index_are_refused() {
    refused_index(
        "registries.pkgre.index = \"https://example.invalid/\"\n",
        Some("\"https://example.invalid/\""),
    );
}

#[test]
fn dotted_keys_without_an_index_are_refused() {
    refused_index(
        "registries.pkgre.credential-provider = \"cargo:token\"\n",
        None,
    );
}

#[test]
fn a_pkgre_entry_that_is_not_a_table_is_refused() {
    assert!(matches!(
        refusal("registries = { pkgre = \"sparse+https://rust.pkg.re/\" }\n"),
        Refusal::PkgreNotATable
    ));
    assert!(matches!(
        refusal("registries.pkgre = 3\n"),
        Refusal::PkgreNotATable
    ));
}

#[test]
fn a_registries_value_that_is_not_a_table_is_refused() {
    assert!(matches!(
        refusal("registries = 3\n"),
        Refusal::RegistriesNotATable
    ));
    assert!(matches!(
        refusal("registries = \"sparse+https://rust.pkg.re/\"\n"),
        Refusal::RegistriesNotATable
    ));
}

#[test]
fn invalid_toml_is_refused() {
    assert!(matches!(
        refusal("registries =\n"),
        Refusal::InvalidToml { .. }
    ));
    assert!(matches!(
        refusal("[registries.pkgre\nindex = \"x\"\n"),
        Refusal::InvalidToml { .. }
    ));
}

#[test]
fn cargo_home_takes_an_absolute_value() {
    let found = cargo_home_of(
        Some(OsStr::new("/opt/cargo")),
        Some(Path::new("/home/user")),
        Path::new("/work"),
    );
    assert_eq!(found.unwrap(), PathBuf::from("/opt/cargo"));
}

#[test]
fn cargo_home_takes_a_relative_value_from_the_current_directory() {
    let found = cargo_home_of(
        Some(OsStr::new("cache/cargo")),
        Some(Path::new("/home/user")),
        Path::new("/work"),
    );
    assert_eq!(found.unwrap(), PathBuf::from("/work/cache/cargo"));
}

#[test]
fn cargo_home_falls_back_to_the_home_directory() {
    let found = cargo_home_of(None, Some(Path::new("/home/user")), Path::new("/work"));
    assert_eq!(found.unwrap(), PathBuf::from("/home/user/.cargo"));
}

#[test]
fn an_empty_cargo_home_falls_back_to_the_home_directory() {
    let found = cargo_home_of(
        Some(OsStr::new("")),
        Some(Path::new("/home/user")),
        Path::new("/work"),
    );
    assert_eq!(found.unwrap(), PathBuf::from("/home/user/.cargo"));
}

#[test]
fn a_missing_cargo_home_and_home_directory_is_an_error() {
    let found = cargo_home_of(Some(OsStr::new("")), None, Path::new("/work"));
    assert!(found.is_err());
}
