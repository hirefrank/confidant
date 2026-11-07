//! Command handlers, one module per command family.
//!
//! `main.rs` keeps the clap surface, the `run` dispatch, and the shared JSON
//! envelope/error path. Each subcommand handler lives in the module named for
//! its area in the README's "Area | Commands" table.

pub(crate) mod agents;
pub(crate) mod bench;
pub(crate) mod check;
pub(crate) mod context;
pub(crate) mod corrections;
pub(crate) mod doctor;
pub(crate) mod find;
pub(crate) mod help;
pub(crate) mod import;
pub(crate) mod init;
pub(crate) mod install;
pub(crate) mod log;
pub(crate) mod note;
pub(crate) mod pack;
pub(crate) mod record;
pub(crate) mod schema;
pub(crate) mod scratch;
pub(crate) mod setup;
pub(crate) mod shared;
pub(crate) mod status;
pub(crate) mod sync;
pub(crate) mod update;
