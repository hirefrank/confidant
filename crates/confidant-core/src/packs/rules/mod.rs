//! Declarative rule kinds that read the ledger (#446).
//!
//! The kinds live here rather than in `declarative.rs` because they share
//! one arithmetic core ([`ledger`]): the compiled `coaching@0.1` pack and
//! the `ledger-balance` rule kind must agree exactly, so the per-person
//! opens/sessions accumulation and its merge-aware queries exist once.
//!
//! PD9: this module is an evaluator source. It reads the vault `check`
//! already loaded and emits findings only — no filesystem, network or
//! process APIs (enforced by `evaluator_sources_have_no_io_apis`).

pub(crate) mod balance;
pub(crate) mod ledger;
