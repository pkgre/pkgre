//! Self-publishing state: the crates.io names of a catalog's own crates, the
//! generated record of what was released to crates.io, and the checks and
//! derivations that need no network.
//!
//! The state lives in `self-publish/crates-io.toml`, written by people, and
//! `self-publish/crates-io.lock`, generated and never edited by hand. Both
//! belong to the catalog repository that holds `registry/`, and all names here
//! belong to the catalog registry `main`.
//!
//! [`check_repository`] reads a repository's catalog with the ordinary catalog
//! loader and runs the checks that need no network. [`self_publish_lock`] derives
//! the crates.io package of every release that has no `crates-io.lock` entry yet
//! and records it. The checks that need the network, and the upload, are later
//! work; the derivation and the canonical form of `crates-io.lock` are the seam
//! for them.

mod catalog;
mod check;
mod config;
mod derive;
mod isolation;
mod lock;
mod lock_command;
mod name;
mod state;

pub use check::{SelfPublishCheckSummary, check_repository};
pub use lock_command::{SelfPublishLockEntry, SelfPublishLockSummary, self_publish_lock};
