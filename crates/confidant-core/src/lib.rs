//! Parse, model, derived values, and the check engine for Confidant vaults.
//!
//! The file format is specified independently in `spec/0.1.md` (ADR-1).

// Unsafe is denied crate-wide. The Unix `openat` / `O_NOFOLLOW` walk in
// `paths` is the only exception, matching cr (ADR-13).
#![deny(unsafe_code)]
// Large hand-authored `json!` schema literals need a deeper macro expansion.
#![recursion_limit = "256"]

pub mod bench;
pub mod check;
pub mod config;
pub mod context;
pub mod discover;
pub mod error;
pub mod id;
pub mod inbox;
pub mod ledger;
pub mod paths;
pub mod record;
pub mod schema;
pub mod search;
pub mod vault;
pub mod write;

pub mod packs;

pub use check::{
    run as check_vault, CheckOptions, CheckReport, Finding, FindingCode, Severity,
    JSON_SCHEMA_VERSION,
};
pub use config::{InboxConfig, TrustConfig, VaultConfig, SPEC_VERSION};
pub use discover::{resolve as resolve_vault, Discovery};
pub use error::DomainError;
pub use id::RecordId;
pub use inbox::{
    inbox_decrypt, run_inbox, DecryptFn, InboxOptions, InboxReport, ItemOutcome, INBOX_BRANCH,
};
pub use ledger::{format_entry, parse_ledger, parse_line, LedgerEntry, ParseErrorKind};
pub use record::{format_record, parse_record, Record};
pub use search::{allowlist_is_fixed_point, cleared_record_ids, search, SearchHit, SearchResult};
pub use vault::{load_vault, Vault};
