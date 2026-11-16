//! Declarative Cargo registry validation and rendering.

pub mod accepted_ref;
pub mod archive;
pub mod artifact;
pub mod category;
pub mod check;
pub mod download;
pub mod http_response;
pub mod import;
pub mod index;
mod isolation;
pub mod lock;
pub mod migrate;
pub mod package;
pub mod policy;
pub mod projection;
pub mod render;
pub mod request_target;
pub mod schema;
pub mod self_publish;
pub mod serve;
pub mod transition;
pub mod update;
