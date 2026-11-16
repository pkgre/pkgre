//! Self-publishing state: the crates.io names of a catalog's own crates, the
//! generated record of what was released to crates.io, and the checks that need
//! no network.
//!
//! The state lives in `self-publish/crates-io.toml`, written by people, and
//! `self-publish/crates-io.lock`, generated and never edited by hand. Both
//! belong to the catalog repository that holds `registry/`, and all names here
//! belong to the catalog registry `main`.
//!
//! [`check_repository`] reads a repository's catalog with the ordinary catalog
//! loader and runs the checks that need no network. The checks that need the
//! network, and the generation of lock entries, are later work; the canonical
//! form of `crates-io.lock` is the seam for the second.

mod check;
mod config;
mod lock;
mod name;

pub use check::{SelfPublishCheckSummary, check_repository};
