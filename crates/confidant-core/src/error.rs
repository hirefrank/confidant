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
    /// `confidant sync` found no remote or no upstream branch to compare
    /// with. Local-only is a valid setup, so this is not a vault defect.
    NoRemote,
    /// `confidant sync` refused a diverged branch (local and remote have
    /// commits the other does not). The operator must merge or rebase
    /// explicitly; auto-merge is never offered.
    NotFastForward,
    /// An external pack directory failed validation (bad manifest, disallowed
    /// file, symlink, size limit, or hash mismatch). Packs ship data and
    /// agent-facing text, never executables.
    PackInvalid,
    /// `--person` / `resolve` matched more than one cleared person by exact
    /// display name. Fail closed: the caller must disambiguate.
    AmbiguousPerson,
    /// A person lookup could not search the vault: person record files were
    /// unreadable. A miss against that partial set must never be reported as
    /// `NotFound` (#717).
    CannotSearch,
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
            Self::NoRemote => "E_NO_REMOTE",
            Self::NotFastForward => "E_NOT_FAST_FORWARD",
            Self::PackInvalid => "E_PACK_INVALID",
            Self::AmbiguousPerson => "E_AMBIGUOUS_PERSON",
            Self::CannotSearch => "E_CANNOT_SEARCH",
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

    pub fn pack_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PackInvalid, message)
    }

    /// A `--person` / `resolve` display-name query matched more than one
    /// cleared person. Only cleared people are searched, so naming the
    /// candidates leaks no `no-ai` content; they are opaque ids, never
    /// names. Fail closed rather than guess.
    pub fn ambiguous_person(query: impl Display, candidates: &[String]) -> Self {
        Self::new(
            ErrorKind::AmbiguousPerson,
            format!(
                "person name '{query}' matches {} people: {}",
                candidates.len(),
                candidates.join(", ")
            ),
        )
        .with_fix("Pass the exact p-<ULID> of the intended person")
    }

    /// An alias `kind:value` matched more than one cleared person. The raw
    /// value is deliberately absent from the message (it is PII, and the
    /// caller only ever holds its HMAC): only the kind and the opaque
    /// candidate ids appear. Fail closed rather than guess.
    pub fn ambiguous_alias(kind: impl Display, candidates: &[String]) -> Self {
        Self::new(
            ErrorKind::AmbiguousPerson,
            format!(
                "alias kind '{kind}' matches {} people: {}",
                candidates.len(),
                candidates.join(", ")
            ),
        )
        .with_fix("Pass the exact p-<ULID> of the intended person")
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

    /// A person lookup miss against a vault that did not load in full
    /// (#717). The message names the cause and the count, and states
    /// plainly that the miss does not establish absence; it never claims
    /// the person is not in the vault. The fix names the actual remedy:
    /// restore the affected record from git history (or a backup, for a
    /// vault without git history).
    ///
    /// `skipped` and `refused` are the record-reading counters callers
    /// already carry; both mean "this person record file could not be
    /// read", so the message reports their sum.
    pub fn cannot_search(skipped: u32, refused: u32) -> Self {
        let unreadable = skipped.saturating_add(refused);
        let cause = if unreadable > 0 {
            format!("{unreadable} person record file(s) unreadable")
        } else {
            // The constructor is public, so a (0, 0) call can happen even
            // though every real caller passes a nonzero count; never
            // render an empty cause list.
            "the vault could not be fully searched".to_owned()
        };
        Self::new(
            ErrorKind::CannotSearch,
            format!(
                "cannot search the vault: {cause}; a miss against a partially unread \
                 vault does not mean the person is absent"
            ),
        )
        .with_fix(
            "Restore the affected record from git history, or from a backup if the \
             vault has no git history; then retry",
        )
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

    /// `confidant sync` has nothing to compare against: no remote, or a
    /// remote with no upstream branch for the current branch. Local-only is
    /// a valid setup, so this is informational, not a vault defect.
    pub fn no_remote(detail: impl Display) -> Self {
        Self::new(ErrorKind::NoRemote, detail.to_string()).with_fix(
            "Add a remote with `git remote add origin <url>` and set an upstream \
             (`git push -u origin <branch>`), then re-run `confidant sync`",
        )
    }

    /// `confidant sync` refused a diverged branch. Pull is fast-forward-only
    /// and push is never forced, so the operator must reconcile explicitly.
    pub fn not_fast_forward(ahead: u64, behind: u64) -> Self {
        Self::new(
            ErrorKind::NotFastForward,
            format!(
                "branch has diverged from its upstream ({ahead} local commit(s) \
                 not on the remote, {behind} remote commit(s) not local)"
            ),
        )
        .with_fix(
            "Merge or rebase the branch explicitly, then re-run `confidant sync`; \
             auto-merge and forced pushes are never used",
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

    /// Escape control and Unicode format characters in the message, fix and
    /// file. Used at the `pack add` boundary: the pack reader, manifest
    /// parser and git stderr all quote untrusted repository text, and that
    /// text reaches the operator's terminal (#499).
    pub fn escape_untrusted(mut self) -> Self {
        use crate::packs::untrusted::escape_line;
        self.message = escape_line(&self.message);
        self.fix = self.fix.map(|fix| escape_line(&fix));
        self.file = self.file.map(|file| escape_line(&file));
        self
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
        assert_eq!(DomainError::no_remote("x").code(), "E_NO_REMOTE");
        assert_eq!(
            DomainError::not_fast_forward(1, 2).code(),
            "E_NOT_FAST_FORWARD"
        );
        assert!(DomainError::not_fast_forward(1, 2)
            .message()
            .contains("1 local commit(s)"));
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
        assert_eq!(
            DomainError::spec_unsupported("9.9").code(),
            "E_SPEC_UNSUPPORTED"
        );
        let ambiguous = DomainError::ambiguous_person(
            "Ada Example",
            &["p-01HZZZ".to_owned(), "p-01HYYY".to_owned()],
        );
        assert_eq!(ambiguous.code(), "E_AMBIGUOUS_PERSON");
        assert_eq!(ambiguous.exit_code(), 1);
        assert!(ambiguous.message().contains("p-01HZZZ, p-01HYYY"));
        assert!(ambiguous.fix().unwrap().contains("p-<ULID>"));
        let unsearchable = DomainError::cannot_search(19, 0);
        assert_eq!(unsearchable.code(), "E_CANNOT_SEARCH");
        assert_eq!(unsearchable.exit_code(), 1);
        assert!(unsearchable
            .message()
            .contains("19 person record file(s) unreadable"));
        assert!(unsearchable.message().contains("does not mean"));
        assert!(!unsearchable.message().contains("no person matches"));
        assert!(unsearchable.fix().unwrap().contains("git history"));
        assert!(unsearchable.fix().unwrap().contains("backup"));
        assert!(!unsearchable.fix().unwrap_or("").contains("trust.toml"));
        assert!(!unsearchable
            .fix()
            .unwrap_or("")
            .contains("CONFIDANT_DEVICE_KEY"));
        let refused_only = DomainError::cannot_search(0, 2);
        assert_eq!(refused_only.code(), "E_CANNOT_SEARCH");
        assert!(refused_only
            .message()
            .contains("2 person record file(s) unreadable"));
        assert!(refused_only.fix().unwrap().contains("git history"));
        assert!(refused_only.fix().unwrap().contains("backup"));
        assert!(!refused_only.fix().unwrap_or("").contains("trust.toml"));
        // A (0, 0) construction still renders a cause and a fix, never an
        // empty list or a fix of "; then retry".
        let empty = DomainError::cannot_search(0, 0);
        assert_eq!(empty.code(), "E_CANNOT_SEARCH");
        assert!(empty.message().contains("cannot search the vault: "));
        assert!(!empty.message().contains("cannot search the vault: ;"));
        assert!(empty.message().contains("could not be fully searched"));
        let empty_fix = empty.fix().unwrap();
        assert!(!empty_fix.starts_with(';'));
        assert!(!empty_fix.contains(";;"));
        assert!(empty_fix.contains("then retry"));
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
