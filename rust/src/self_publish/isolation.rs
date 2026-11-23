//! Isolation of the child processes of the self-publishing workflow.
//!
//! The reconciler's own Git-tag packaging runs the same Git and Cargo children,
//! so the implementation lives beside it in [`crate::isolation`] and this
//! module re-exports what the workflow uses.

pub(crate) use crate::isolation::{
    CERTIFICATE_VARIABLES, ChildEnvironment, ensure_no_cargo_configuration,
};
