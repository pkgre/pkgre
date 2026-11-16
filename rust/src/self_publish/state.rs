//! The self-publishing state of one catalog repository.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::catalog::{CATALOG_DIRECTORY, CatalogSnapshot};
use super::config::CratesIoConfig;
use super::lock::CratesIoLock;

/// Human self-publishing declarations.
pub(crate) const CONFIG_FILE: &str = "crates-io.toml";
/// Generated self-publishing records.
pub(crate) const LOCK_FILE: &str = "crates-io.lock";
/// Directory of the self-publishing state.
pub(crate) const STATE_DIRECTORY: &str = "self-publish";

/// One repository: its catalog facts and, when declared, its self-publishing
/// state.
pub(crate) struct RepositoryState {
    /// The facts of `registry/main`.
    pub(crate) catalog: CatalogSnapshot,
    /// The catalog's own state, the directory that holds `objects/`.
    pub(crate) catalog_root: PathBuf,
    /// The declared self-publishing state.
    pub(crate) self_publish: Option<SelfPublishState>,
}

/// The parsed self-publishing files of one repository.
pub(crate) struct SelfPublishState {
    /// Human declarations.
    pub(crate) config: CratesIoConfig,
    /// Generated records.
    pub(crate) lock: CratesIoLock,
}

impl RepositoryState {
    /// Loads one catalog repository.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or invalid catalog, or a malformed or
    /// non-canonical self-publishing state.
    pub(crate) fn load(repository: &Path) -> Result<Self> {
        let catalog = CatalogSnapshot::load(repository)?;
        let directory = repository.join(STATE_DIRECTORY);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Self {
                    catalog,
                    catalog_root: repository.join(CATALOG_DIRECTORY),
                    self_publish: None,
                });
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect self-publishing directory {}", directory.display())
                });
            }
        };
        ensure!(
            metadata.file_type().is_dir(),
            "self-publishing directory is not a real directory: {}",
            directory.display()
        );
        Ok(Self {
            catalog,
            catalog_root: repository.join(CATALOG_DIRECTORY),
            self_publish: Some(SelfPublishState::load(&directory)?),
        })
    }
}

impl SelfPublishState {
    /// Loads `crates-io.toml` and `crates-io.lock` of one self-publishing
    /// directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory holds anything but the two regular
    /// files, or when either file is malformed, invalid, or not canonical.
    pub(crate) fn load(directory: &Path) -> Result<Self> {
        let mut names = fs::read_dir(directory)
            .with_context(|| format!("read self-publishing directory {}", directory.display()))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("read self-publishing directory {}", directory.display()))?;
        names.sort();
        let found = names
            .iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        ensure!(
            found == [LOCK_FILE.to_owned(), CONFIG_FILE.to_owned()],
            "self-publishing directory {} must hold exactly {CONFIG_FILE} and {LOCK_FILE}, found {found:?}",
            directory.display()
        );
        for name in &names {
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect {}", path.display()))?;
            ensure!(
                metadata.file_type().is_file(),
                "self-publishing file is not a regular file: {}",
                path.display()
            );
        }
        Ok(Self {
            config: CratesIoConfig::load(&directory.join(CONFIG_FILE))?,
            lock: CratesIoLock::load(&directory.join(LOCK_FILE))?,
        })
    }
}
