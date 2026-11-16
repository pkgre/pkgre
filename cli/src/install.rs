//! `pkgre install`: add the `pkgre` registry to the user's Cargo configuration.
//!
//! The edit of the configuration text is [`configure`], a pure function of
//! the text, so that every form of the file can be tested without a file
//! system. The rest of this module finds the file, reads it, writes it back
//! atomically, and describes what it found.

use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

/// The index of the public `pkgre` registry, the one value this command writes.
pub(crate) const INDEX: &str = "sparse+https://rust.pkg.re/";

/// The environment variable that overrides the configured index.
const INDEX_OVERRIDE: &str = "CARGO_REGISTRIES_PKGRE_INDEX";

/// What `pkgre install` did, or would do.
pub(crate) struct Outcome {
    /// The configuration file that was read, or that would be written.
    pub(crate) file: PathBuf,
    /// What became of that file.
    pub(crate) state: State,
    /// Warnings that qualify the result, in the order they were found.
    pub(crate) notes: Vec<String>,
    /// Whether the user asked for the result without a write.
    pub(crate) dry_run: bool,
}

/// What became of the configuration file.
pub(crate) enum State {
    /// The registry was added; the field holds the whole new text of the file.
    Added { text: String },
    /// The file already configured the registry, so it was not touched.
    AlreadyConfigured,
    /// The file was left alone, because the refusal says why.
    Refused(Refusal),
}

/// Why a configuration file cannot be changed automatically.
pub(crate) enum Refusal {
    /// The file exists but is not a regular file, such as a symbolic link.
    NotARegularFile { kind: &'static str },
    /// The file is not valid TOML, with the parser's message.
    InvalidToml { detail: String },
    /// `registries` holds something other than a table.
    RegistriesNotATable,
    /// `registries.pkgre` holds something other than a table.
    PkgreNotATable,
    /// `registries.pkgre` exists, but with another index or with none.
    DifferentIndex { current: Option<String> },
}

impl Refusal {
    /// The message that says what was left alone and how to fix it by hand.
    pub(crate) fn explain(&self) -> String {
        match self {
            Self::NotARegularFile { kind } => format!(
                "it is {kind}, and this command only rewrites a regular file.\n\
                 \n\
                 Add these lines to it by hand:\n\
                 \n\
                 {}",
                table_to_add()
            ),
            Self::InvalidToml { detail } => format!(
                "it is not valid TOML: {detail}\n\
                 \n\
                 Fix that first, then run `pkgre install` again. \
                 The table it adds is:\n\
                 \n\
                 {}",
                table_to_add()
            ),
            Self::RegistriesNotATable => format!(
                "`registries` is not a table.\n\
                 \n\
                 Make it a table and add this table to it by hand:\n\
                 \n\
                 {}",
                table_to_add()
            ),
            Self::PkgreNotATable => format!(
                "`registries.pkgre` is not a table.\n\
                 \n\
                 Make it a table and add this entry to it by hand:\n\
                 \n\
                 {}",
                table_to_add()
            ),
            Self::DifferentIndex {
                current: Some(current),
            } => format!(
                "`registries.pkgre` already exists, with index = {current}.\n\
                 The `pkgre` registry resolves from index = \"{INDEX}\".\n\
                 \n\
                 If that entry is a different registry that happens to be named \
                 `pkgre`, leave it as it is. Otherwise change it by hand to:\n\
                 \n\
                 {}",
                table_to_add()
            ),
            Self::DifferentIndex { current: None } => format!(
                "`registries.pkgre` already exists, without an index.\n\
                 The `pkgre` registry resolves from index = \"{INDEX}\".\n\
                 \n\
                 Add that index to the entry by hand:\n\
                 \n\
                 {}",
                table_to_add()
            ),
        }
    }
}

/// Runs `pkgre install`, writing the result unless `dry_run` is set.
pub(crate) fn run(dry_run: bool) -> Result<Outcome> {
    let cargo_home = user_cargo_home()?;
    let mut notes = Vec::new();
    let file = config_file(&cargo_home, &mut notes);
    if let Some(note) = index_override_note() {
        notes.push(note);
    }

    let kind = match fs::symlink_metadata(&file) {
        Ok(metadata) => Some(metadata.file_type()),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", file.display()));
        }
    };
    if let Some(kind) = &kind {
        if !kind.is_file() {
            let refusal = Refusal::NotARegularFile {
                kind: describe(*kind),
            };
            return Ok(refused(file, notes, dry_run, refusal));
        }
    }
    let existing = match &kind {
        Some(_) => Some(
            fs::read_to_string(&file).with_context(|| format!("cannot read {}", file.display()))?,
        ),
        None => None,
    };

    let text = existing.as_deref().unwrap_or_default();
    match configure(text) {
        Ok(Change::Unchanged) => Ok(Outcome {
            file,
            state: State::AlreadyConfigured,
            notes,
            dry_run,
        }),
        Ok(Change::Added { text }) => {
            if !dry_run {
                write(&file, &text)?;
            }
            Ok(Outcome {
                file,
                state: State::Added { text },
                notes,
                dry_run,
            })
        }
        Err(refusal) => Ok(refused(file, notes, dry_run, refusal)),
    }
}

/// The outcome of a refusal, which leaves the file as it was.
fn refused(file: PathBuf, notes: Vec<String>, dry_run: bool, refusal: Refusal) -> Outcome {
    Outcome {
        file,
        state: State::Refused(refusal),
        notes,
        dry_run,
    }
}

/// The change that a configuration file's text needs.
pub(crate) enum Change {
    /// The text already configures the registry and is left as it is.
    Unchanged,
    /// The whole text to write instead, with the registry added.
    Added { text: String },
}

/// Adds the `pkgre` registry to a configuration file's text.
///
/// The text keeps every byte it had, apart from the addition, because
/// `toml_edit` preserves comments, order and formatting. The entry is added
/// in the form the file already uses for its other registries.
///
/// # Errors
///
/// Returns a [`Refusal`] when the text is not valid TOML, when `registries` or
/// `registries.pkgre` is not a table, or when `registries.pkgre` exists with
/// another index or with none.
pub(crate) fn configure(text: &str) -> Result<Change, Refusal> {
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|error| Refusal::InvalidToml {
            detail: error.message().to_owned(),
        })?;

    let Some(registries) = document.get_mut("registries") else {
        document.insert("registries", Item::Table(implicit_table_of_pkgre()));
        return Ok(Change::Added {
            text: document.to_string(),
        });
    };

    match registries {
        Item::Table(table) => {
            let dotted = table.is_dotted();
            let Some(entry) = table.get_mut("pkgre") else {
                table.insert("pkgre", Item::Table(entry_table(dotted)));
                return Ok(Change::Added {
                    text: document.to_string(),
                });
            };
            match entry {
                Item::Table(entry) => verify(documented_item(entry.get("index"))),
                Item::Value(Value::InlineTable(entry)) => {
                    verify(documented_value(entry.get("index")))
                }
                _ => Err(Refusal::PkgreNotATable),
            }
        }
        Item::Value(Value::InlineTable(table)) => {
            let Some(entry) = table.get_mut("pkgre") else {
                insert_inline_entry(table);
                return Ok(Change::Added {
                    text: document.to_string(),
                });
            };
            match entry {
                Value::InlineTable(entry) => verify(documented_value(entry.get("index"))),
                _ => Err(Refusal::PkgreNotATable),
            }
        }
        _ => Err(Refusal::RegistriesNotATable),
    }
}

/// Whether an existing `registries.pkgre` index leaves the text alone.
fn verify(current: Option<String>) -> Result<Change, Refusal> {
    match current {
        Some(current) if current == quoted(INDEX) => Ok(Change::Unchanged),
        current => Err(Refusal::DifferentIndex { current }),
    }
}

/// A `registries.pkgre` table entry's index, as it would appear in the file.
fn documented_item(index: Option<&Item>) -> Option<String> {
    match index? {
        Item::Value(index) => documented_value(Some(index)),
        Item::None => None,
        other => Some(other.to_string().trim().to_owned()),
    }
}

/// A `registries.pkgre` inline table entry's index, as it would appear in the
/// file.
fn documented_value(index: Option<&Value>) -> Option<String> {
    let index = index?;
    Some(
        index
            .as_str()
            .map_or_else(|| index.to_string().trim().to_owned(), quoted),
    )
}

/// A string as TOML would quote it.
fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

/// The two lines that configure the registry, indented for a message.
fn table_to_add() -> String {
    format!("    [registries.pkgre]\n    index = \"{INDEX}\"")
}

/// A table that holds `pkgre` and no key of its own, so that it renders only
/// as the header of the table below it.
fn implicit_table_of_pkgre() -> Table {
    let mut table = Table::new();
    table.set_implicit(true);
    table.insert("pkgre", Item::Table(entry_table(false)));
    table
}

/// `pkgre = { index = "…" }`.
fn entry_inline() -> InlineTable {
    let mut table = InlineTable::new();
    table.insert("index", Value::from(INDEX));
    table
}

/// Adds `pkgre` to an inline `registries` table, and moves the whitespace that
/// ended its last entry to the end of the new one, so that the closing brace
/// stays where the file had it.
fn insert_inline_entry(table: &mut InlineTable) {
    let trailing = table
        .iter()
        .last()
        .and_then(|(_, value)| value.decor().suffix().cloned());
    if let Some((_, last)) = table.iter_mut().last() {
        last.decor_mut().set_suffix("");
    }
    let mut entry = Value::InlineTable(entry_inline());
    if let Some(trailing) = trailing {
        entry.decor_mut().set_suffix(trailing);
    }
    table.insert("pkgre", entry);
}

/// `[registries.pkgre]` as a table, or its dotted-key form.
fn entry_table(dotted: bool) -> Table {
    let mut table = Table::new();
    table.insert("index", toml_edit::value(INDEX));
    table.set_dotted(dotted);
    table
}

/// The Cargo home of the user running the command.
fn user_cargo_home() -> Result<PathBuf> {
    let cargo_home = std::env::var_os("CARGO_HOME");
    let home = std::env::home_dir();
    let current_dir = std::env::current_dir().context("cannot read the current directory")?;
    cargo_home_of(cargo_home.as_deref(), home.as_deref(), &current_dir)
}

/// The Cargo home, from the values Cargo itself reads.
///
/// `CARGO_HOME` wins when it is set and not empty, and a relative value is
/// taken relative to the current directory. Otherwise the home directory
/// holds `.cargo`.
fn cargo_home_of(
    cargo_home: Option<&OsStr>,
    home: Option<&Path>,
    current_dir: &Path,
) -> Result<PathBuf> {
    if let Some(value) = cargo_home.filter(|value| !value.is_empty()) {
        let path = Path::new(value);
        return Ok(if path.is_absolute() {
            path.to_path_buf()
        } else {
            current_dir.join(path)
        });
    }
    let Some(home) = home else {
        return Err(anyhow!(
            "cannot find the Cargo home: CARGO_HOME is not set and no home directory is \
             known; set CARGO_HOME to the directory that holds the configuration"
        ));
    };
    Ok(home.join(".cargo"))
}

/// The configuration file Cargo reads, preferring the name it prefers.
///
/// Cargo reads `config` and, when both exist, ignores `config.toml`; the note
/// says so when both exist.
fn config_file(cargo_home: &Path, notes: &mut Vec<String>) -> PathBuf {
    let config = cargo_home.join("config");
    let config_toml = cargo_home.join("config.toml");
    if !config.exists() {
        return config_toml;
    }
    if config_toml.exists() {
        notes.push(format!(
            "both {} and {} exist; Cargo reads the first and ignores the second, \
             so this command changes only the first",
            config.display(),
            config_toml.display()
        ));
    }
    config
}

/// A note about an index that the environment sets instead of the file.
fn index_override_note() -> Option<String> {
    let value = std::env::var_os(INDEX_OVERRIDE)?;
    if value == OsStr::new(INDEX) {
        return None;
    }
    Some(format!(
        "{INDEX_OVERRIDE} is \"{}\" in this shell and overrides the configuration \
         file; unset it to use the index this command configures",
        value.to_string_lossy()
    ))
}

/// What a path is, for the message about a file that is not one.
fn describe(kind: fs::FileType) -> &'static str {
    if kind.is_symlink() {
        "a symbolic link"
    } else if kind.is_dir() {
        "a directory"
    } else {
        "not a regular file"
    }
}

/// Replaces the file with `text`, and leaves it as it was on failure.
fn write(file: &Path, text: &str) -> Result<()> {
    let directory = file
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", file.display()))?;
    fs::create_dir_all(directory)
        .with_context(|| format!("cannot create {}", directory.display()))?;

    let permissions = fs::metadata(file)
        .ok()
        .map(|metadata| metadata.permissions());
    let temporary = temporary_path(file);
    let written = write_temporary(&temporary, text, permissions.as_ref()).and_then(|()| {
        fs::rename(&temporary, file).with_context(|| {
            format!(
                "cannot move {} onto {}",
                temporary.display(),
                file.display()
            )
        })
    });
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

/// Writes `text` to a new file, with `permissions` when the old file had them.
fn write_temporary(path: &Path, text: &str, permissions: Option<&fs::Permissions>) -> Result<()> {
    let mut handle = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    handle
        .write_all(text.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    if let Some(permissions) = permissions {
        handle
            .set_permissions(permissions.clone())
            .with_context(|| format!("cannot set the permissions of {}", path.display()))?;
    }
    handle
        .sync_all()
        .with_context(|| format!("cannot flush {}", path.display()))?;
    Ok(())
}

/// A path beside `file`, so that a rename replaces it without a copy.
fn temporary_path(file: &Path) -> PathBuf {
    let mut name = file
        .file_name()
        .unwrap_or(OsStr::new("config"))
        .to_os_string();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    name.push(format!(".pkgre-{}-{nanos}.tmp", std::process::id()));
    file.with_file_name(name)
}

#[cfg(test)]
#[path = "../tests/unit/install.rs"]
mod tests;
