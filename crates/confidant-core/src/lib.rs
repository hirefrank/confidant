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
pub mod conflict;
pub mod context;
pub mod crypto_mode;
pub mod discover;
pub mod error;
pub mod id;
pub mod inbox;
pub mod ledger;
pub mod paths;
pub mod record;
pub mod schema;
pub mod search;
pub mod touch;
pub mod vault;
pub mod write;

pub mod packs;
pub mod scope;

pub use check::{
    run as check_vault, CheckOptions, CheckReport, Finding, FindingCode, Severity,
    JSON_SCHEMA_VERSION,
};
pub use config::{InboxConfig, TrustConfig, VaultConfig, SPEC_VERSION};
pub use discover::{resolve as resolve_vault, Discovery};
pub use error::DomainError;
pub use id::RecordId;
#[cfg(test)]
pub use inbox::inbox_decrypt;
pub use inbox::{
    discard_inbox_items, queue_items, queue_signing_configured, read_inbox_item, run_inbox,
    run_inbox_rotate, verify_inbox_trust, DecryptExistingFn, DecryptFn, EncryptFn,
    InboxItemContent, InboxKeys, InboxOptions, InboxReport, InboxRotateOptions, InboxRotateOutcome,
    ItemOutcome, QueueItem, SkippedItem, ALLOW_UNSIGNED_WARNING, INBOX_BRANCH,
};
pub use ledger::{format_entry, parse_ledger, parse_line, LedgerEntry, ParseErrorKind};
pub use record::{format_record, parse_record, Record};
pub use scope::{
    intersect_scope, note_linkage_owners, owner_labels, owners_of_ledger_text, parse_pack_list,
    record_owners, resolve_scope, OwnerKey, PackScope,
};
pub use search::{
    allowlist_is_fixed_point, cleared_ledger_line_owners, cleared_ledger_lines, cleared_record_ids,
    cleared_record_owners, cleared_record_paths, search, SearchHit, SearchResult,
};
pub use vault::{load_vault, load_vault_with_hook, ContentHook, ContentOutcome, Vault};
