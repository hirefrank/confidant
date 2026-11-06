//! Declarative rule kinds that read the ledger (#446-#448).
//!
//! The kinds live here rather than in `declarative.rs` because they share
//! one arithmetic core ([`ledger`]): the `ledger-balance`, `session-checks`
//! and `activity-gap` kinds must agree exactly, so the per-person
//! opens/consumption accumulation and its merge-aware queries exist once.
//!
//! PD9: this module is an evaluator source. It reads the vault `check`
//! already loaded and emits findings only — no filesystem, network or
//! process APIs (enforced by `evaluator_sources_have_no_io_apis`).

pub(crate) mod balance;
pub(crate) mod gap;
pub(crate) mod ledger;
pub(crate) mod session;
