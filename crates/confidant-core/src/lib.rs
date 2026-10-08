//! Parse, model, derived values, and the check engine for Confidant vaults.
//!
//! The file format is specified independently in `spec/0.1.md` (ADR-1).

// Unsafe is denied crate-wide. The Unix `openat` / `O_NOFOLLOW` walk in
// `paths` is the only exception, matching cr (ADR-13).
#![deny(unsafe_code)]

pub mod bench;
pub mod check;
pub mod config;
pub mod discover;
pub mod error;
pub mod id;
pub mod ledger;
pub mod paths;
pub mod record;
pub mod search;
pub mod vault;

pub mod packs;

pub use check::{
    run as check_vault, CheckOptions, CheckReport, Finding, FindingCode, Severity,
    JSON_SCHEMA_VERSION,
};
pub use config::{VaultConfig, SPEC_VERSION};
pub use discover::{resolve as resolve_vault, Discovery};
pub use error::DomainError;
pub use id::RecordId;
pub use ledger::{format_entry, parse_ledger, parse_line, LedgerEntry, ParseErrorKind};
pub use record::{format_record, parse_record, Record};
pub use search::{search, SearchHit};
pub use vault::{load_vault, Vault};
