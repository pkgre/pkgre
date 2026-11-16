//! Read-only remote facts for the self-publishing checks that need the network.

use anyhow::{Result, bail};

/// Read-only access to the registries that a release reaches.
///
/// The offline checks of [`check_repository`](super::check_repository) never
/// call it. The checks that need the network run only for the releases a run
/// adds, and are later work; tests run against [`NoNetwork`], which refuses
/// every call.
pub trait NetworkAccess {
    /// Returns the tag `tag` of the repository `git`.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository or tag cannot be read.
    fn release_tag(&self, git: &str, tag: &str) -> Result<ReleaseTag>;

    /// Returns the crates.io crate `name`, or `None` when crates.io lacks it.
    ///
    /// # Errors
    ///
    /// Returns an error when crates.io cannot be read.
    fn crates_io_crate(&self, name: &str) -> Result<Option<CratesIoCrate>>;
}

/// A Git tag as the network sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseTag {
    /// Whether the tag is annotated.
    pub annotated: bool,
    /// The commit the tag peels to.
    pub commit: String,
}

/// A crates.io crate as the network sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CratesIoCrate {
    /// Logins that own the crate.
    pub owners: Vec<String>,
}

/// Network access that refuses every call.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoNetwork;

impl NetworkAccess for NoNetwork {
    fn release_tag(&self, git: &str, tag: &str) -> Result<ReleaseTag> {
        bail!("network access is not available to read tag {tag:?} of {git:?}")
    }

    fn crates_io_crate(&self, name: &str) -> Result<Option<CratesIoCrate>> {
        bail!("network access is not available to read crates.io crate {name:?}")
    }
}
