//! Self-publishing state: the crates.io names of a catalog's own crates, the
//! generated record of what was released to crates.io, and the checks,
//! derivations, and upload that read the network.
//!
//! The state lives in `self-publish/crates-io.toml`, written by people, and
//! `self-publish/crates-io.lock`, generated and never edited by hand. Both
//! belong to the catalog repository that holds `registry/`, and all names here
//! belong to the catalog registry `main`.
//!
//! [`check_repository`] reads a repository's catalog with the ordinary catalog
//! loader and runs the checks that need no network, and then the network checks
//! of the releases that the run adds. [`self_publish_lock`] derives the
//! crates.io package of every release that has no `crates-io.lock` entry yet and
//! records it. [`self_publish`] is the local routine that publishes one release
//! to crates.io: a dry run, or, with `--upload`, the upload of the crates that
//! crates.io still lacks.

mod catalog;
mod check;
mod config;
mod derive;
mod git;
mod isolation;
mod lock;
mod lock_command;
mod name;
mod native;
mod network;
mod publish;
mod state;

pub use check::{SelfPublishCheckSummary, check_repository};
pub use lock_command::{SelfPublishLockEntry, SelfPublishLockSummary, self_publish_lock};
pub(crate) use native::NativeRepositories;
pub use publish::{SelfPublishCrate, SelfPublishCrateState, SelfPublishSummary, self_publish};
