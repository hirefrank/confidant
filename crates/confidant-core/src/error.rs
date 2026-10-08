// Portions adapted from cr (https://github.com/AnandChowdhary/cr) at f29f8d4,
// MIT License, Copyright (c) 2026 Anand Chowdhary.
//
// DomainError taxonomy, typed downcast via DomainError::of (never a match on
// message text), stable codes, internal_error for unclassified failures, and
// usage-error exit 2. Confidant adds file/line/fix fields and E_* codes
// (ADR-7, ADR-13).

//! Typed domain errors for the CLI and library.
//!
//! Library code returns [`anyhow::Result`] so diagnostic context is never
//! discarded, and attaches a [`DomainError`] whenever a failure has a stable
//! meaning a caller must act on. Consumers classify with [`DomainError::of`],
//! which walks the error chain and downcasts, rather than matching on message
//! text.

use std::fmt::{self, Display, Formatter};

/// Stable classification for failures that are not check findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// The caller named something that does not exist.
    NotFound,
    /// Vault discovery (ADR-11) found nothing.
    VaultNotFound,
    /// The caller asked to create something that already exists.
    AlreadyExists,
    /// The request conflicts with stored vault state.
    Conflict,
    /// The request is well formed but not valid for this vault.
    Invalid,
    /// `confidant.toml` cannot be interpreted (command-level E_CONFIG).
    Config,
    /// Vault `spec` is not implemented by this CLI.
    SpecUnsupported,
    /// `find` refuses because a ledger file could not be read.
    LedgerUnreadable,
    /// Flags or arguments cannot be interpreted. Exit 2.
    Usage,
    /// An idempotency key was reused with different content.
    IdempotencyConflict,
    /// `confidant inbox` refused: the working tree is not clean.
    InboxDirty,
    /// `confidant inbox` refused: the inbox branch tip is not signed by a
    /// trusted signer.
    InboxUntrusted,
    /// `confidant inbox` refused: an inbox item is malformed or undecryptable.
    InboxItem,
    /// `confidant inbox` refused: an item targets a path that already exists
    /// with different content.
    InboxConflict,
    /// `confidant inbox` refused: the merged content fails `check`.
    InboxCheckFailed,
    /// `confidant inbox` cannot decrypt: milestone 2 crypto is a stub.
    InboxCrypto,
    /// Unclassified failure. Reserved; never match on its message.
    Internal,
}

impl ErrorKind {
    /// Stable machine-readable code.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotFound => "E_NOT_FOUND",
            Self::VaultNotFound => "E_VAULT_NOT_FOUND",
            Self::AlreadyExists => "E_ALREADY_EXISTS",
            Self::Conflict => "E_CONFLICT",
            Self::Invalid => "E_INVALID",
            Self::Config => "E_CONFIG",
            Self::SpecUnsupported => "E_SPEC_UNSUPPORTED",
            Self::LedgerUnreadable => "E_LEDGER_UNREADABLE",
            Self::Usage => "usage_error",
            Self::IdempotencyConflict => "E_IDEMPOTENCY_CONFLICT",
            Self::InboxDirty => "E_INBOX_DIRTY",
            Self::InboxUntrusted => "E_INBOX_UNTRUSTED",
            Self::InboxItem => "E_INBOX_ITEM",
            Self::InboxConflict => "E_INBOX_CONFLICT",
            Self::InboxCheckFailed => "E_INBOX_CHECK_FAILED",
            Self::InboxCrypto => "E_INBOX_CRYPTO",
            Self::Internal => "internal_error",
        }
    }
}

/// A classified failure with optional file, line, and fix (ADR-7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainError {
    kind: ErrorKind,
    message: String,
    file: Option<String>,
    line: Option<u32>,
    fix: Option<String>,
}

impl DomainError {
    /// Construct a classified error with a caller-facing message.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            file: None,
            line: None,
            fix: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Invalid, message)
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    pub fn spec_unsupported(spec: impl Display) -> Self {
        Self::new(
            ErrorKind::SpecUnsupported,
            format!("vault spec '{spec}' is not supported (this CLI implements 0.1)"),
        )
        .with_fix("Use spec = \"0.1\" or upgrade the CLI")
        .with_file("confidant.toml")
    }

    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AlreadyExists, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    pub fn vault_not_found() -> Self {
        Self::new(ErrorKind::VaultNotFound, "no vault found")
            .with_fix("Pass --vault, set CONFIDANT_VAULT, or run from a vault directory")
    }

    pub fn ledger_unreadable(count: u32) -> Self {
        Self::new(ErrorKind::LedgerUnreadable, format!("{count} items"))
            .with_fix(
                "Fix permissions or replace the unreadable ledger file, then run `confidant check` to locate it",
            )
    }

    pub fn inbox_dirty() -> Self {
        Self::new(
            ErrorKind::InboxDirty,
            "working tree is not clean; `confidant inbox` refuses to merge",
        )
        .with_fix("Commit or stash your changes, then run `confidant inbox` again")
    }

    pub fn inbox_untrusted(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::InboxUntrusted, detail.into()).with_fix(
            "Push the inbox branch from a device whose signing key is in [trust] signers, or add the signer",
        )
    }

    pub fn inbox_item(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::InboxItem, detail.into()).with_fix(
            "Fix or remove the item on the inbox branch, then run `confidant inbox` again",
        )
    }

    pub fn inbox_conflict(path: impl Into<String>) -> Self {
        Self::new(
            ErrorKind::InboxConflict,
            format!("inbox item targets '{}' which already exists with different content", path.into()),
        )
        .with_fix("Resolve the conflict manually (merge the two versions), then run `confidant inbox` again")
    }

    pub fn inbox_check_failed(summary: impl Into<String>) -> Self {
        Self::new(ErrorKind::InboxCheckFailed, summary.into()).with_fix(
            "Fix the inbox items so `confidant check` passes, then run `confidant inbox` again",
        )
    }

    pub fn inbox_crypto(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::InboxCrypto, detail.into()).with_fix(
            "Inbox decryption needs the milestone 2 crypto implementation; until then the inbox cannot be merged",
        )
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    /// The domain classification carried anywhere in `error`'s chain, if it
    /// has one. This is a typed downcast, never a match on message text.
    pub fn of(error: &anyhow::Error) -> Option<&Self> {
        error.downcast_ref::<Self>()
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// A stable machine-readable code for this classification.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    pub fn line(&self) -> Option<u32> {
        self.line
    }

    pub fn fix(&self) -> Option<&str> {
        self.fix.as_deref()
    }

    /// Process exit code: 2 for usage, 1 otherwise.
    pub fn exit_code(&self) -> i32 {
        if self.kind == ErrorKind::Usage {
            2
        } else {
            1
        }
    }

    /// JSON object for the ADR-7 error envelope (the `error` field).
    pub fn to_json(&self) -> serde_json::Value {
        let mut err = serde_json::json!({
            "code": self.code(),
            "message": self.message,
        });
        if let Some(file) = &self.file {
            err["file"] = serde_json::Value::String(file.clone());
        }
        if let Some(line) = self.line {
            err["line"] = serde_json::Value::from(line);
        }
        if let Some(fix) = &self.fix {
            err["fix"] = serde_json::Value::String(fix.clone());
        }
        err
    }
}

impl Display for DomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for DomainError {}

/// Build an invalid-request failure for `bail!`-style returns.
pub fn invalid(message: impl Display) -> anyhow::Error {
    anyhow::Error::new(DomainError::invalid(message.to_string()))
}

/// Build a usage failure (exit 2).
pub fn usage(message: impl Display) -> anyhow::Error {
    anyhow::Error::new(DomainError::usage(message.to_string()))
}

/// True when `error` was caused by a missing filesystem entry.
pub fn is_missing(error: &anyhow::Error) -> bool {
    io_kind_matches(error, std::io::ErrorKind::NotFound)
}

fn io_kind_matches(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == kind)
    })
}

#[cfg(test)]
mod tests {
    use super::{invalid, is_missing, usage, DomainError, ErrorKind};
    use anyhow::anyhow;

    #[test]
    fn classification_survives_additional_context() {
        let error = anyhow!("could not read a private path")
            .context(DomainError::not_found("record p-01 does not exist"))
            .context("while loading a vault");

        let domain = DomainError::of(&error).expect("classification is preserved");
        assert_eq!(domain.code(), "E_NOT_FOUND");
        assert_eq!(domain.message(), "record p-01 does not exist");
        assert!(format!("{error:#}").contains("could not read a private path"));
    }

    #[test]
    fn untagged_errors_have_no_classification() {
        assert!(DomainError::of(&anyhow!("could not sync directory")).is_none());
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(ErrorKind::Usage.code(), "usage_error");
        assert_eq!(ErrorKind::Internal.code(), "internal_error");
        assert_eq!(
            ErrorKind::IdempotencyConflict.code(),
            "E_IDEMPOTENCY_CONFLICT"
        );
        assert_eq!(
            DomainError::spec_unsupported("9.9").code(),
            "E_SPEC_UNSUPPORTED"
        );
        assert_eq!(
            DomainError::ledger_unreadable(2).code(),
            "E_LEDGER_UNREADABLE"
        );
        assert_eq!(DomainError::ledger_unreadable(2).message(), "2 items");
        assert!(DomainError::ledger_unreadable(2).file().is_none());
        assert_eq!(
            DomainError::ledger_unreadable(2).fix(),
            Some(
                "Fix permissions or replace the unreadable ledger file, then run `confidant check` to locate it"
            )
        );
        assert_eq!(DomainError::vault_not_found().code(), "E_VAULT_NOT_FOUND");
        assert_eq!(DomainError::vault_not_found().exit_code(), 1);
        assert_eq!(
            DomainError::of(&usage("bad flag")).map(DomainError::exit_code),
            Some(2)
        );
        assert_eq!(
            DomainError::of(&invalid("bad field")).map(DomainError::code),
            Some("E_INVALID")
        );
        assert_eq!(DomainError::config("bad toml").code(), "E_CONFIG");
        assert_eq!(DomainError::conflict("busy").code(), "E_CONFLICT");
        assert_eq!(DomainError::inbox_dirty().code(), "E_INBOX_DIRTY");
        assert_eq!(
            DomainError::inbox_untrusted("x").code(),
            "E_INBOX_UNTRUSTED"
        );
        assert_eq!(DomainError::inbox_item("x").code(), "E_INBOX_ITEM");
        assert_eq!(DomainError::inbox_conflict("p").code(), "E_INBOX_CONFLICT");
        assert_eq!(
            DomainError::inbox_check_failed("x").code(),
            "E_INBOX_CHECK_FAILED"
        );
        assert_eq!(DomainError::inbox_crypto("x").code(), "E_INBOX_CRYPTO");
        assert_eq!(
            DomainError::spec_unsupported("9.9").code(),
            "E_SPEC_UNSUPPORTED"
        );
    }

    #[test]
    fn json_includes_file_line_fix() {
        let err = DomainError::invalid("broken")
            .with_file("ledger/2026/10.cfd")
            .with_line(4)
            .with_fix("delete the extra token");
        let json = err.to_json();
        assert_eq!(json["code"], "E_INVALID");
        assert_eq!(json["file"], "ledger/2026/10.cfd");
        assert_eq!(json["line"], 4);
        assert_eq!(json["fix"], "delete the extra token");
    }

    #[test]
    fn filesystem_causes_are_detected_by_kind_not_message() {
        let missing = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("could not read record");
        assert!(is_missing(&missing));
    }
}
