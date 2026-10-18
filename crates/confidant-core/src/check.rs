// Portions adapted from cr (https://github.com/AnandChowdhary/cr) at f29f8d4,
// MIT License, Copyright (c) 2026 Anand Chowdhary.
//
// Severity (two levels), Finding with a stable code(), CheckSummary::fails,
// CheckReport deterministic order, and parse_fail_on / --fail-on. The scanner
// itself is original (ADR-13). Confidant adds file, line, id, and fix.

//! Whole-vault integrity checking.
//!
//! `confidant check` answers one question — *is this vault coherent?* — and
//! answers it exhaustively. It never propagates a per-record failure. It
//! collects [`Finding`]s and keeps scanning, and a vault with a damaged
//! ledger file is still fully inspectable for unknown IDs and gap rules.
//!
//! It is strictly read-only. There is no repair mode.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{Datelike, NaiveDate};
use serde::Serialize;

use crate::config::{parse_iso_date, SPEC_VERSION};
use crate::error::DomainError;
use crate::id::{scan_id_tokens, Prefix, RecordId};
use crate::ledger::{parse_duration_minutes, Arg, LedgerEntry};
use crate::packs::{find_conflict, OrphanOwners, Pack, PackState, CORE_EDGE_KINDS};

/// #438: external pack problems, for the fail-closed finding conversion.
use crate::packs::external as packs_external;
use crate::packs::lock as packs_lock;
use crate::record::{parse_ref_id, parse_with_list, FrontmatterRef, RecordKind};
use crate::vault::Vault;

/// How serious a finding is.
///
/// Two levels rather than four. The only decision a caller makes from a
/// severity is whether to fail, and every extra level would be a judgement
/// Confidant is not entitled to make about somebody else's vault.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Reported for completeness; the vault is still usable.
    Warning,
    /// The vault is not coherent.
    Error,
}

impl Severity {
    /// The stable lowercase label used in output and in `--fail-on`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// Parse `--fail-on` / `parse_fail_on`.
pub fn parse_fail_on(s: &str) -> Result<Severity, DomainError> {
    match s {
        "error" => Ok(Severity::Error),
        "warning" | "warn" => Ok(Severity::Warning),
        other => Err(DomainError::usage(format!(
            "unknown --fail-on '{other}' (use error or warning)"
        ))),
    }
}

/// Stable finding code. Serialized as the `E_*` string. Callers branch on
/// this, never on message text.
///
/// `Pack` carries a pack-defined code (#434). It is the last variant so the
/// derived `Ord` keeps all enum variants first (declaration order), then
/// `Pack` codes by string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FindingCode {
    Parse,
    Unreadable,
    Config,
    SpecUnsupported,
    PackUnknown,
    PackConflict,
    PackOrphan,
    PackHash,
    PackInvalid,
    PackVersion,
    InvalidId,
    InvalidFilename,
    IdPathMismatch,
    TypePathMismatch,
    DuplicateId,
    Frontmatter,
    UnknownVerb,
    UnknownRecord,
    UnknownMetric,
    LedgerPath,
    LedgerDate,
    BalanceMismatch,
    AliasPlaintext,
    AliasCollision,
    UnresolvedMerge,
    SelfMerge,
    MergeCycle,
    Symlink,
    MergeConflict,
    MissingDuration,
    OpenMalformed,
    NegativeBalance,
    SessionWithoutNotes,
    PaidSessionGap,
    WrongIdType,
    DuplicateUlid,
    MergeFork,
    DanglingRef,
    DuplicateSrc,
    SessionUntagged,
    SessionTags,
    InboxKeyMismatch,
    SelfEdge,
    DuplicateEdge,
    UnknownEdgeKind,
    TouchMalformed,
    CadenceOverdue,
    DateUpcoming,
    Pack(&'static str),
}

impl FindingCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "E_PARSE",
            Self::Unreadable => "E_UNREADABLE",
            Self::Config => "E_CONFIG",
            Self::SpecUnsupported => "E_SPEC_UNSUPPORTED",
            Self::PackUnknown => "E_PACK_UNKNOWN",
            Self::PackConflict => "E_PACK_CONFLICT",
            Self::PackOrphan => "W_PACK_ORPHAN",
            Self::PackHash => "E_PACK_HASH",
            Self::PackInvalid => "E_PACK_INVALID",
            Self::PackVersion => "E_PACK_VERSION",
            Self::InvalidId => "E_INVALID_ID",
            Self::InvalidFilename => "E_INVALID_FILENAME",
            Self::IdPathMismatch => "E_ID_PATH_MISMATCH",
            Self::TypePathMismatch => "E_TYPE_PATH_MISMATCH",
            Self::DuplicateId => "E_DUPLICATE_ID",
            Self::Frontmatter => "E_FRONTMATTER",
            Self::UnknownVerb => "E_UNKNOWN_VERB",
            Self::UnknownRecord => "E_UNKNOWN_RECORD",
            Self::UnknownMetric => "E_UNKNOWN_METRIC",
            Self::LedgerPath => "E_LEDGER_PATH",
            Self::LedgerDate => "E_LEDGER_DATE",
            Self::BalanceMismatch => "E_BALANCE_MISMATCH",
            Self::AliasPlaintext => "E_ALIAS_PLAINTEXT",
            Self::AliasCollision => "E_ALIAS_COLLISION",
            Self::UnresolvedMerge => "E_UNRESOLVED_MERGE",
            Self::SelfMerge => "E_SELF_MERGE",
            Self::MergeCycle => "E_MERGE_CYCLE",
            Self::Symlink => "E_SYMLINK",
            Self::MergeConflict => "E_MERGE_CONFLICT",
            Self::MissingDuration => "E_MISSING_DURATION",
            Self::OpenMalformed => "E_OPEN_MALFORMED",
            Self::NegativeBalance => "E_NEGATIVE_BALANCE",
            Self::SessionWithoutNotes => "E_SESSION_WITHOUT_NOTES",
            Self::PaidSessionGap => "E_PAID_SESSION_GAP",
            Self::WrongIdType => "E_WRONG_ID_TYPE",
            Self::DuplicateUlid => "E_DUPLICATE_ULID",
            Self::MergeFork => "E_MERGE_FORK",
            Self::DanglingRef => "E_DANGLING_REF",
            Self::DuplicateSrc => "E_DUPLICATE_SRC",
            Self::SessionUntagged => "W_SESSION_UNTAGGED",
            Self::SessionTags => "E_SESSION_TAGS",
            Self::InboxKeyMismatch => "E_INBOX_KEY_MISMATCH",
            Self::SelfEdge => "E_SELF_EDGE",
            Self::DuplicateEdge => "E_DUPLICATE_EDGE",
            Self::UnknownEdgeKind => "E_UNKNOWN_EDGE_KIND",
            Self::TouchMalformed => "E_TOUCH_MALFORMED",
            Self::CadenceOverdue => "W_CADENCE_OVERDUE",
            Self::DateUpcoming => "W_DATE_UPCOMING",
            Self::Pack(code) => code,
        }
    }

    /// All builtin code strings, in declaration order. Used to reject
    /// pack-declared codes that collide with an existing code.
    const ALL_BUILTIN_STRS: &[&str] = &[
        "E_PARSE",
        "E_UNREADABLE",
        "E_CONFIG",
        "E_SPEC_UNSUPPORTED",
        "E_PACK_UNKNOWN",
        "E_PACK_CONFLICT",
        "W_PACK_ORPHAN",
        "E_PACK_HASH",
        "E_PACK_INVALID",
        "E_PACK_VERSION",
        "E_INVALID_ID",
        "E_INVALID_FILENAME",
        "E_ID_PATH_MISMATCH",
        "E_TYPE_PATH_MISMATCH",
        "E_DUPLICATE_ID",
        "E_FRONTMATTER",
        "E_UNKNOWN_VERB",
        "E_UNKNOWN_RECORD",
        "E_UNKNOWN_METRIC",
        "E_LEDGER_PATH",
        "E_LEDGER_DATE",
        "E_BALANCE_MISMATCH",
        "E_ALIAS_PLAINTEXT",
        "E_ALIAS_COLLISION",
        "E_UNRESOLVED_MERGE",
        "E_SELF_MERGE",
        "E_MERGE_CYCLE",
        "E_SYMLINK",
        "E_MERGE_CONFLICT",
        "E_MISSING_DURATION",
        "E_OPEN_MALFORMED",
        "E_NEGATIVE_BALANCE",
        "E_SESSION_WITHOUT_NOTES",
        "E_PAID_SESSION_GAP",
        "E_WRONG_ID_TYPE",
        "E_DUPLICATE_ULID",
        "E_MERGE_FORK",
        "E_DANGLING_REF",
        "E_DUPLICATE_SRC",
        "W_SESSION_UNTAGGED",
        "E_SESSION_TAGS",
        "E_INBOX_KEY_MISMATCH",
        "E_SELF_EDGE",
        "E_DUPLICATE_EDGE",
        "E_UNKNOWN_EDGE_KIND",
        "E_TOUCH_MALFORMED",
        "W_CADENCE_OVERDUE",
        "W_DATE_UPCOMING",
    ];

    /// Whether `s` is the string of a builtin enum variant (not a `Pack` code).
    pub fn is_builtin_code(s: &str) -> bool {
        Self::ALL_BUILTIN_STRS.contains(&s)
    }

    /// Build a `Pack` code from a pack-declared string (#434). The string
    /// must match `^[EW]_[A-Z0-9_]{2,40}$` and must not collide with any
    /// existing builtin code. The caller leaks the string once at load time
    /// (same `Box::leak` pattern as pack manifests).
    pub fn from_pack_str(code: &'static str) -> Result<FindingCode, DomainError> {
        if !is_valid_pack_code(code) {
            return Err(DomainError::invalid(format!(
                "invalid pack finding code '{code}' (must match ^[EW]_[A-Z0-9_]{{2,40}}$)"
            )));
        }
        if Self::is_builtin_code(code) {
            return Err(DomainError::invalid(format!(
                "pack finding code '{code}' collides with an existing code"
            )));
        }
        Ok(FindingCode::Pack(code))
    }

    /// Build the finding code a pack's `finding_codes` entry stands for.
    /// Builtin codes are accepted as *emission claims* only where the
    /// merged v2 spec example needs it: `E_FRONTMATTER` (a pack's field
    /// errors render through its own template shell,
    /// spec/pack-manifest.md §2). Every other builtin is refused —
    /// PD13 forbids shadowing core codes, and a rule that could emit
    /// `E_PACK_HASH` or friends would let a pack forge security
    /// findings (#494 review). Pack-own codes still go through the
    /// collision rule of [`FindingCode::from_pack_str`].
    pub fn from_pack_str_or_builtin(code: &'static str) -> Result<FindingCode, DomainError> {
        if !is_valid_pack_code(code) {
            return Err(DomainError::invalid(format!(
                "invalid pack finding code '{code}' (must match ^[EW]_[A-Z0-9_]{{2,40}}$)"
            )));
        }
        if code == "E_FRONTMATTER" {
            return Ok(FindingCode::Frontmatter);
        }
        if Self::is_builtin_code(code) {
            return Err(DomainError::invalid(format!(
                "pack finding code '{code}' collides with an existing code"
            )));
        }
        Ok(FindingCode::Pack(code))
    }

    /// The builtin variant whose string is `s`, if any.
    pub fn builtin_from_str(s: &str) -> Option<FindingCode> {
        Some(match s {
            "E_PARSE" => Self::Parse,
            "E_UNREADABLE" => Self::Unreadable,
            "E_CONFIG" => Self::Config,
            "E_SPEC_UNSUPPORTED" => Self::SpecUnsupported,
            "E_PACK_UNKNOWN" => Self::PackUnknown,
            "E_PACK_CONFLICT" => Self::PackConflict,
            "W_PACK_ORPHAN" => Self::PackOrphan,
            "E_PACK_HASH" => Self::PackHash,
            "E_PACK_INVALID" => Self::PackInvalid,
            "E_PACK_VERSION" => Self::PackVersion,
            "E_INVALID_ID" => Self::InvalidId,
            "E_INVALID_FILENAME" => Self::InvalidFilename,
            "E_ID_PATH_MISMATCH" => Self::IdPathMismatch,
            "E_TYPE_PATH_MISMATCH" => Self::TypePathMismatch,
            "E_DUPLICATE_ID" => Self::DuplicateId,
            "E_FRONTMATTER" => Self::Frontmatter,
            "E_UNKNOWN_VERB" => Self::UnknownVerb,
            "E_UNKNOWN_RECORD" => Self::UnknownRecord,
            "E_UNKNOWN_METRIC" => Self::UnknownMetric,
            "E_LEDGER_PATH" => Self::LedgerPath,
            "E_LEDGER_DATE" => Self::LedgerDate,
            "E_BALANCE_MISMATCH" => Self::BalanceMismatch,
            "E_ALIAS_PLAINTEXT" => Self::AliasPlaintext,
            "E_ALIAS_COLLISION" => Self::AliasCollision,
            "E_UNRESOLVED_MERGE" => Self::UnresolvedMerge,
            "E_SELF_MERGE" => Self::SelfMerge,
            "E_MERGE_CYCLE" => Self::MergeCycle,
            "E_SYMLINK" => Self::Symlink,
            "E_MERGE_CONFLICT" => Self::MergeConflict,
            "E_MISSING_DURATION" => Self::MissingDuration,
            "E_OPEN_MALFORMED" => Self::OpenMalformed,
            "E_NEGATIVE_BALANCE" => Self::NegativeBalance,
            "E_SESSION_WITHOUT_NOTES" => Self::SessionWithoutNotes,
            "E_PAID_SESSION_GAP" => Self::PaidSessionGap,
            "E_WRONG_ID_TYPE" => Self::WrongIdType,
            "E_DUPLICATE_ULID" => Self::DuplicateUlid,
            "E_MERGE_FORK" => Self::MergeFork,
            "E_DANGLING_REF" => Self::DanglingRef,
            "E_DUPLICATE_SRC" => Self::DuplicateSrc,
            "W_SESSION_UNTAGGED" => Self::SessionUntagged,
            "E_SESSION_TAGS" => Self::SessionTags,
            "E_INBOX_KEY_MISMATCH" => Self::InboxKeyMismatch,
            "E_SELF_EDGE" => Self::SelfEdge,
            "E_DUPLICATE_EDGE" => Self::DuplicateEdge,
            "E_UNKNOWN_EDGE_KIND" => Self::UnknownEdgeKind,
            "E_TOUCH_MALFORMED" => Self::TouchMalformed,
            "W_CADENCE_OVERDUE" => Self::CadenceOverdue,
            "W_DATE_UPCOMING" => Self::DateUpcoming,
            _ => return None,
        })
    }
}

/// A pack-declared finding code must match `^[EW]_[A-Z0-9_]{2,40}$`.
fn is_valid_pack_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    // E/W + _ + 2..40 of [A-Z0-9_] = 4..42 bytes total.
    if bytes.len() < 4 || bytes.len() > 42 {
        return false;
    }
    if bytes[0] != b'E' && bytes[0] != b'W' {
        return false;
    }
    if bytes[1] != b'_' {
        return false;
    }
    bytes[2..]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl Serialize for FindingCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One problem found in the vault.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Finding {
    pub fn new(code: FindingCode, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            file: None,
            line: None,
            id: None,
            message: message.into(),
            fix: None,
        }
    }

    pub fn at_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn at_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    pub fn for_id(mut self, id: impl ToString) -> Self {
        self.id = Some(id.to_string());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// How much of the vault a run looked at, and what it concluded.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CheckSummary {
    pub records: usize,
    pub ledger_entries: usize,
    pub errors: usize,
    pub warnings: usize,
}

impl CheckSummary {
    /// Whether any finding reached `threshold`.
    pub fn fails(&self, threshold: Severity) -> bool {
        match threshold {
            Severity::Error => self.errors > 0,
            Severity::Warning => self.errors > 0 || self.warnings > 0,
        }
    }
}

/// JSON report schema version. Independent of the vault spec version.
pub const JSON_SCHEMA_VERSION: &str = "1";

/// The complete result of one `check` run.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CheckReport {
    pub schema_version: String,
    pub ok: bool,
    pub vault: String,
    pub spec: String,
    pub summary: CheckSummary,
    /// Findings in deterministic order: severity (errors first), then code,
    /// file, line, message.
    pub findings: Vec<Finding>,
}

/// Options that do not come from the vault files themselves.
#[derive(Clone, Debug, Default)]
pub struct CheckOptions {
    pub as_of: Option<NaiveDate>,
    pub fail_on: Option<Severity>,
    /// The operator's out-of-band pin of the vault's inbox public key. When
    /// set and the vault's `[inbox].pubkey` differs, an error finding is
    /// reported (possible key substitution; see `docs/inbox.md`).
    pub pinned_inbox_pubkey: Option<String>,
}

/// Run every check against `vault`, collecting rather than propagating.
pub fn run(vault: &Vault, options: &CheckOptions) -> CheckReport {
    let mut findings = vault.load_findings.clone();

    if vault.config.spec != SPEC_VERSION {
        findings.push(
            Finding::new(
                FindingCode::SpecUnsupported,
                Severity::Error,
                format!("vault spec is not supported (this CLI implements {SPEC_VERSION})"),
            )
            .at_file("confidant.toml")
            .with_fix("Use spec = \"0.1\" or upgrade the CLI"),
        );
    }

    // Spec 3 (§2.2): a `mode = "plaintext"` declaration combined with a
    // structurally encrypted vault (any `enc:` envelope or any `keys/`
    // tree) is E_CONFIG — the declaration can never downgrade an
    // encrypted vault.
    if vault.config.crypto.mode.as_deref() == Some("plaintext")
        && crate::crypto_mode::is_structurally_encrypted(&vault.root)
    {
        findings.push(
            Finding::new(
                FindingCode::Config,
                Severity::Error,
                "confidant.toml declares [crypto] mode = \"plaintext\" but the vault \
                 is structurally encrypted (it has an `enc:` envelope or a `keys/` tree); \
                 the declaration cannot downgrade an encrypted vault",
            )
            .at_file("confidant.toml")
            .with_fix("Remove the `[crypto] mode = \"plaintext\"` line"),
        );
    }

    // Key-substitution defense: the vault's advertised inbox key must match
    // the operator's out-of-band pin. Anyone with git write access can change
    // confidant.toml; only the local pin is trustworthy.
    if let Some(pinned) = options
        .pinned_inbox_pubkey
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match vault
            .config
            .inbox
            .pubkey
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(vault_key) if vault_key != pinned => {
                findings.push(
                    Finding::new(
                        FindingCode::InboxKeyMismatch,
                        Severity::Error,
                        "vault [inbox].pubkey does not match the pinned key in user config; possible key substitution",
                    )
                    .at_file("confidant.toml")
                    .with_fix("Restore the pinned public key, or update the pin in ~/.config/confidant/config.toml after verifying the key out of band"),
                );
            }
            _ => {}
        }
    }

    let spec_ok = vault.config.spec == SPEC_VERSION;
    let (enabled_packs, unknown_packs) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    // #497: on an unsupported spec external packs are never resolved (see
    // `vault.rs`), so the compiled-only registry would report every listed
    // external as `E_PACK_UNKNOWN` — noise on top of the spec finding,
    // which already fails `check` and returns below.
    if spec_ok {
        for listed in &unknown_packs {
            // #438: a listed pack that exists but failed to load becomes its
            // specific finding (fail closed, PD12; problem packs are not
            // folded). One that is neither compiled nor resolvable at all
            // stays E_PACK_UNKNOWN.
            match vault.pack_problems.iter().find(|p| p.name == *listed) {
                Some(problem) => findings.push(pack_problem_finding(problem)),
                None => findings.push(
                    Finding::new(
                        FindingCode::PackUnknown,
                        Severity::Error,
                        "unknown pack".to_owned(),
                    )
                    .at_file("confidant.toml")
                    .with_fix("Remove the pack or use a CLI that implements it"),
                ),
            }
        }
    }

    if !spec_ok {
        sort_findings(&mut findings);
        return finish_report(vault, options, findings);
    }

    // Conflicting pack claims make the pack set incoherent: report the
    // conflict and skip all pack folding (core checks still run). The
    // conflicting verbs stay known so this does not cascade into
    // E_UNKNOWN_VERB noise.
    let conflict = find_conflict(&enabled_packs);
    if let Some(conflict) = &conflict {
        findings.push(
            Finding::new(
                FindingCode::PackConflict,
                Severity::Error,
                format!(
                    "packs {} and {} both claim {} '{}'",
                    conflict.first, conflict.second, conflict.kind, conflict.name
                ),
            )
            .at_file("confidant.toml")
            .with_fix("Remove one of the packs or resolve the overlap"),
        );
    }

    // The set borrows every claim string: pack verbs are already
    // `'static` and problem-pack verbs live in `vault` for the whole run,
    // so nothing needs leaking (#497 item 1).
    let mut known_verbs = known_verbs(&enabled_packs);
    // Problem packs are not folded, but their claimed verbs stay known
    // (spec/pack-lock.md §5) so the failure does not cascade into
    // E_UNKNOWN_VERB noise.
    for problem in &vault.pack_problems {
        for verb in &problem.known_verbs {
            known_verbs.insert(verb.as_str());
        }
    }
    let orphans = vault.pack_registry().orphan_owners(&enabled_packs);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();

    check_ledger_paths(vault, &mut findings);
    let as_of = resolve_as_of(vault, options);
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut findings);
    check_verbs_and_refs(
        vault,
        &known_verbs,
        &orphans,
        &enabled_packs,
        &known_ids,
        &mut findings,
    );
    check_orphan_fields_and_types(vault, &orphans, &mut findings);
    check_duplicate_ulids(vault, &mut findings);
    check_dangling_refs(vault, &known_ids, &mut findings);
    check_edges(vault, &known_ids, &enabled_packs, &orphans, &mut findings);
    check_with_lists(vault, &known_ids, &mut findings);
    check_duplicate_src(vault, &mut findings);

    if conflict.is_none() {
        let mut states: Vec<(&dyn Pack, Box<dyn PackState>)> = Vec::new();
        for pack in &enabled_packs {
            states.push((*pack, pack.fold(vault, &merges, as_of, &mut findings)));
        }
        for (pack, state) in &states {
            pack.findings(vault, state.as_ref(), as_of, &mut findings);
        }
        check_balances(vault, &states, &orphans, &mut findings);
    }

    sort_findings(&mut findings);
    finish_report(vault, options, findings)
}

/// #438/#490: one failed external-pack load becomes its stable finding
/// (PD12, fail closed). The message names the failing `name@version`
/// exactly as listed in `confidant.toml` — the operator wrote that id
/// themselves, and identifying the broken pin is the point. `E_PACK_HASH`
/// and `E_PACK_INVALID` also point at the vendored path
/// `packs/<name>@<version>` in `file`. Everything else stays name-free:
/// never file contents, never absolute paths, never record/ledger free
/// text anywhere.
fn pack_problem_finding(problem: &packs_external::PackProblem) -> Finding {
    use packs_external::PackProblemKind as Kind;
    // Invariant behind the echo: `load_external_packs` only emits `Unknown`
    // for an id with no lockfile entry; every other kind comes from a
    // matching lockfile entry, so its `problem.name` is a lockfile-validated
    // `name@version` pin and may be echoed (#490) and turned into the
    // vendored `file` path. If the loader ever emits a non-`Unknown` kind
    // for a malformed id, that echo becomes a leak (see #499 for escaping
    // untrusted pack-manifest text). A `debug_assert!` is deliberately not
    // used: a hand-edited lockfile could trip it, and `check` must fail
    // closed with a finding, never panic.
    let (code, message, fix) = match problem.kind {
        Kind::Unknown => {
            // The echo carve-out (#490) is for a real `name@version` pin
            // only. `load_external_packs` also emits `Unknown` for a listed
            // id that is not of that shape — no `@`, an `@` split that is
            // not a valid name or a version (e.g. `ada@example.com`), or an
            // embedded newline. That raw string is operator free text and
            // must stay name-free (#501).
            let is_pin = packs_lock::is_valid_pack_pin(&problem.name);
            (
                FindingCode::PackUnknown,
                if is_pin {
                    format!(
                        "external pack {} listed in confidant.toml has no lockfile pin",
                        problem.name
                    )
                } else {
                    "a pack listed in confidant.toml is not a name@version pin".to_owned()
                },
                "Run `confidant pack add <https-url>` or remove the pack",
            )
        }
        Kind::Hash => (
            FindingCode::PackHash,
            format!(
                "external pack {}'s vendored files do not match its lockfile pin",
                problem.name
            ),
            "Reinstall the pack (`confidant pack add`) or fix confidant.lock",
        ),
        Kind::Invalid => (
            FindingCode::PackInvalid,
            format!(
                "external pack {}'s manifest or contents fail validation",
                problem.name
            ),
            "Fix the vendored files or reinstall the pack",
        ),
        Kind::Version => (
            FindingCode::PackVersion,
            format!(
                "external pack {}'s spec compatibility does not include this vault",
                problem.name
            ),
            "Upgrade this CLI or pin a version the pack supports",
        ),
    };
    let file = match problem.kind {
        Kind::Hash | Kind::Invalid => packs_external::vendored_rel_of(&problem.name),
        Kind::Unknown | Kind::Version => "confidant.toml".to_owned(),
    };
    Finding::new(code, Severity::Error, message)
        .at_file(file)
        .with_fix(fix)
}

fn finish_report(vault: &Vault, options: &CheckOptions, findings: Vec<Finding>) -> CheckReport {
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let summary = CheckSummary {
        records: vault.records.len(),
        ledger_entries: vault.entries.len(),
        errors,
        warnings,
    };
    let fail_on = options.fail_on.unwrap_or(Severity::Error);
    CheckReport {
        schema_version: JSON_SCHEMA_VERSION.to_owned(),
        ok: !summary.fails(fail_on),
        vault: vault.root.display().to_string(),
        spec: vault.config.spec.clone(),
        summary,
        findings,
    }
}

fn resolve_as_of(vault: &Vault, options: &CheckOptions) -> NaiveDate {
    if let Some(d) = options.as_of {
        return d;
    }
    resolve_as_of_date(vault)
}

/// The effective as-of date for coaching folds: config override, else today.
pub fn resolve_as_of_date(vault: &Vault) -> NaiveDate {
    if let Some(raw) = vault.config.checks.as_of.as_deref() {
        if let Ok(d) = parse_iso_date(raw) {
            return d;
        }
        // Invalid as_of in config is reported as E_CONFIG at load time.
    }
    chrono::Utc::now().date_naive()
}

/// Best-effort pack states for read commands (e.g. `context`).
///
/// Merge/alias problems are still reported by [`run`]; here they are folded
/// best-effort and the findings discarded. One entry per enabled pack, in
/// config order. Packs with conflicting claims are still folded here —
/// `run` is the gate that refuses them; read commands degrade gracefully.
pub fn pack_snapshots(
    vault: &Vault,
    as_of: NaiveDate,
) -> Vec<(&'static dyn Pack, Box<dyn PackState>)> {
    let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut findings);
    enabled
        .into_iter()
        .map(|pack| {
            let state = pack.fold(vault, &merges, as_of, &mut findings);
            (pack as &'static dyn Pack, state)
        })
        .collect()
}

/// The verb names a vault may use, borrowing from the packs and the
/// core list rather than leaking copies (#497 item 1). The `'a` lifetime
/// is unconstrained because the pack trait's `'static` claims coerce to
/// it; the caller unifies it with the `vault` borrow it also inserts.
fn known_verbs<'a>(enabled_packs: &[&dyn Pack]) -> HashSet<&'a str> {
    // `touch` is core (#179): a mirrored touchpoint carries only a date
    // and the participant's own id, no pack data.
    let mut verbs: HashSet<&'a str> =
        HashSet::from(["alias", "merge", "stage", "balance", "touch"]);
    for pack in enabled_packs {
        verbs.extend(pack.verbs().iter().copied());
    }
    verbs
}

fn check_ledger_paths(vault: &Vault, findings: &mut Vec<Finding>) {
    for entry in &vault.entries {
        if let Some((year, month)) = parse_ledger_file(&entry.file) {
            if entry.entry.date.year() != year || entry.entry.date.month() != month {
                findings.push(
                    Finding::new(
                        FindingCode::LedgerDate,
                        Severity::Error,
                        "entry date does not belong in this monthly file".to_owned(),
                    )
                    .at_file(&entry.file)
                    .at_line(entry.line)
                    .for_id(&entry.entry.id)
                    .with_fix("Move the line to ledger/YYYY/MM.cfd for its date"),
                );
            }
        }
    }
}

fn parse_ledger_file(file: &str) -> Option<(i32, u32)> {
    // ledger/YYYY/MM.cfd
    let rest = file.strip_prefix("ledger/")?;
    let (year, rest) = rest.split_once('/')?;
    let month = rest.strip_suffix(".cfd")?;
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    Some((year, month))
}

fn check_verbs_and_refs(
    vault: &Vault,
    known_verbs: &HashSet<&str>,
    orphans: &OrphanOwners,
    enabled_packs: &[&dyn Pack],
    known_ids: &HashSet<RecordId>,
    findings: &mut Vec<Finding>,
) {
    for sourced in &vault.entries {
        let e = &sourced.entry;
        if !known_verbs.contains(e.verb.as_str()) {
            if let Some(owner) = orphans.verbs.get(e.verb.as_str()) {
                // Owned by a registered pack that is not enabled: warn,
                // never error (#177 Q2, matching the #183 warning rule).
                // The message does not echo the verb.
                findings.push(
                    Finding::new(
                        FindingCode::PackOrphan,
                        Severity::Warning,
                        "ledger verb belongs to a disabled pack".to_owned(),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix(format!("Enable {owner} or remove the line")),
                );
            } else {
                findings.push(
                    Finding::new(
                        FindingCode::UnknownVerb,
                        Severity::Error,
                        "unknown verb".to_owned(),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix("Use a core verb or enable the pack that defines it"),
                );
            }
        }
        // #179: a touchpoint is a mirrored cadence marker, not a record of
        // an association. It carries at most one `kind:` pair and nothing
        // else — no other participant ids, no primary id, no interaction
        // id. Anything else is E_TOUCH_MALFORMED.
        //
        // Validation lives on the pack that owns the verb (#185/#296):
        // when the owning pack is enabled it validates the args; when it
        // is disabled, core applies the mirrored shape above and asks the
        // registered pack whether a non-mirrored line is the pack's shape
        // (`W_PACK_ORPHAN`) or malformed (`E_TOUCH_MALFORMED`).
        if e.verb == "touch" {
            if let Some(owner) = enabled_packs
                .iter()
                .find(|p| p.verbs().contains(&e.verb.as_str()))
            {
                let valid = owner.validate_verb_args(&e.verb, e).unwrap_or(true);
                if !valid {
                    findings.push(
                        Finding::new(
                            FindingCode::TouchMalformed,
                            Severity::Error,
                            "touch line must be: DATE touch ID <call|text|email|meet|meal|event|gift|other> [note:N-ID] [src:…]".to_owned(),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&e.id)
                        .with_fix("Use one of call, text, email, meet, meal, event, gift, or other (plus optional note: and src:)"),
                    );
                }
            } else {
                let mirrored_ok = match e.args.as_slice() {
                    [] => true,
                    [arg] => matches!(arg.pair(), Some(("kind", _))),
                    _ => false,
                };
                if !mirrored_ok {
                    let pack_shape = vault
                        .pack_registry()
                        .all()
                        .iter()
                        .find(|p| p.verbs().contains(&e.verb.as_str()))
                        .and_then(|p| p.validate_verb_args(&e.verb, e));
                    if pack_shape == Some(true) {
                        findings.push(
                            Finding::new(
                                FindingCode::PackOrphan,
                                Severity::Warning,
                                "ledger verb belongs to a disabled pack".to_owned(),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&e.id)
                            .with_fix("Enable personal@0.1 or remove the line"),
                        );
                    } else {
                        findings.push(
                            Finding::new(
                                FindingCode::TouchMalformed,
                                Severity::Error,
                                "touch line must be: DATE touch ID [kind:NAME]".to_owned(),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&e.id)
                            .with_fix("Remove every argument except an optional kind:NAME"),
                        );
                    }
                }
            }
        }
        // The ID-type rule is a property of the verb's definition, so it
        // applies for verbs owned by any registered pack, enabled or not.
        let expected = match e.verb.as_str() {
            "stage" => Some(Prefix::Deal),
            "touch" => Some(Prefix::Person),
            _ => enabled_packs
                .iter()
                .find_map(|p| p.verb_id_type(e.verb.as_str()))
                .or_else(|| {
                    vault
                        .pack_registry()
                        .all()
                        .iter()
                        .find_map(|p| p.verb_id_type(e.verb.as_str()))
                }),
        };
        if let Some(want) = expected {
            if e.id.prefix() != want {
                findings.push(
                    Finding::new(
                        FindingCode::WrongIdType,
                        Severity::Error,
                        format!("requires a {} id", want.as_str()),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix(format!("Use a {}-<ULID> id", want.as_str())),
                );
                continue;
            }
        }
        if e.id.prefix() != Prefix::Package
            && !known_ids.contains(&e.id)
            && !vault.conflicted_ids.contains(&e.id)
        {
            findings.push(
                Finding::new(
                    FindingCode::UnknownRecord,
                    Severity::Error,
                    "ledger id has no record file".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id)
                .with_fix("Create the record or fix the id"),
            );
        }
    }
}

pub(crate) type MergeMap = HashMap<RecordId, (RecordId, NaiveDate)>;

pub(crate) fn check_aliases_and_merges(
    vault: &Vault,
    known_ids: &HashSet<RecordId>,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) -> MergeMap {
    let mut parent: MergeMap = HashMap::new();
    for sourced in &vault.entries {
        if sourced.entry.verb != "merge" {
            continue;
        }
        let e = &sourced.entry;
        match parse_merge(e) {
            MergeParse::Malformed => findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    "merge line must be: DATE merge FROM into TO".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id)
                .with_fix("Write: merge <from-id> into <to-id>"),
            ),
            MergeParse::InvalidTo => findings.push(
                Finding::new(
                    FindingCode::InvalidId,
                    Severity::Error,
                    "merge destination is not a record ID".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id)
                .with_fix("Use a prefixed 26-character Crockford ULID"),
            ),
            MergeParse::Ok { from, to } => {
                if from.prefix() != to.prefix() {
                    findings.push(
                        Finding::new(
                            FindingCode::WrongIdType,
                            Severity::Error,
                            format!(
                                "merge requires the same record type, got {} into {}",
                                from, to
                            ),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&from)
                        .with_fix("Merge two records of the same type"),
                    );
                    continue;
                }
                if from == to {
                    findings.push(
                        Finding::new(
                            FindingCode::SelfMerge,
                            Severity::Error,
                            format!("cannot merge {} into itself", from),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&from)
                        .with_fix("Remove the self-merge or merge into a different record"),
                    );
                    continue;
                }
                for id in [&from, &to] {
                    if !known_ids.contains(id) && !vault.conflicted_ids.contains(id) {
                        findings.push(
                            Finding::new(
                                FindingCode::UnresolvedMerge,
                                Severity::Error,
                                format!("merge names unknown id '{id}'"),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(id)
                            .with_fix("Create the record or fix the id"),
                        );
                    }
                }
                if let Some((existing, _)) = parent.get(&from) {
                    if existing != &to {
                        findings.push(
                            Finding::new(
                                FindingCode::MergeFork,
                                Severity::Error,
                                format!(
                                    "merge of {from} names two destinations ({existing} and {to})"
                                ),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&from)
                            .with_fix("Keep a single merge FROM into TO"),
                        );
                    }
                } else {
                    // First wins on fork.
                    parent.insert(from, (to, e.date));
                }
            }
        }
    }

    if let Some(cycle) = detect_cycle(&parent) {
        let mut finding = Finding::new(
            FindingCode::MergeCycle,
            Severity::Error,
            format!("merge entries form a cycle involving {cycle}"),
        )
        .with_fix("Remove one merge so every id has a single canonical root");
        if let Some(sourced) = vault.entries.iter().find(|s| {
            s.entry.verb == "merge"
                && matches!(
                    parse_merge(&s.entry),
                    MergeParse::Ok { from, to } if from == cycle || to == cycle
                )
        }) {
            finding = finding
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&cycle);
        }
        findings.push(finding);
    }

    let mut seen_alias: BTreeMap<(String, String), RecordId> = BTreeMap::new();
    for sourced in &vault.entries {
        if sourced.entry.verb != "alias" {
            continue;
        }
        let e = &sourced.entry;
        match parse_alias(e) {
            Err(msg) => findings.push(
                Finding::new(FindingCode::AliasPlaintext, Severity::Error, msg)
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix("Store HMAC(vault lookup key, normalized value) as hmac:<hex>"),
            ),
            Ok((kind, hmac)) => {
                let canon = canonical_on(&e.id, &parent, as_of);
                let key = (kind.clone(), hmac);
                if let Some(existing) = seen_alias.get(&key) {
                    if existing != &canon {
                        findings.push(
                            Finding::new(
                                FindingCode::AliasCollision,
                                Severity::Warning,
                                format!("alias {kind} hmac is shared by {existing} and {canon}"),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&canon)
                            .with_fix("Merge the duplicate records or drop one alias"),
                        );
                    }
                } else {
                    seen_alias.insert(key, canon);
                }
            }
        }
    }
    parent
}

pub(crate) enum MergeParse {
    Ok { from: RecordId, to: RecordId },
    InvalidTo,
    Malformed,
}

pub(crate) fn parse_merge(entry: &LedgerEntry) -> MergeParse {
    // FROM is entry.id; then token "into" then TO token.
    let mut toks = entry.args.iter().filter_map(Arg::as_token);
    match toks.next() {
        Some("into") => {}
        _ => return MergeParse::Malformed,
    }
    let Some(raw) = toks.next() else {
        return MergeParse::Malformed;
    };
    match RecordId::parse(raw) {
        Ok(to) => MergeParse::Ok {
            from: entry.id.clone(),
            to,
        },
        Err(_) => MergeParse::InvalidTo,
    }
}

const ALIAS_HMAC_MIN_HEX: usize = 32;

fn parse_alias(entry: &LedgerEntry) -> Result<(String, String), String> {
    if entry.args.len() != 2 {
        return Err("alias line must be exactly KIND hmac:HEX".to_owned());
    }
    let kind = entry.args[0]
        .as_token()
        .ok_or_else(|| "alias kind must be a token (email, phone, or handle)".to_owned())?;
    if !matches!(kind, "email" | "phone" | "handle") {
        return Err("alias kind must be email, phone, or handle".to_owned());
    }
    let hmac = match &entry.args[1] {
        Arg::Token(s) if s.starts_with("hmac:") => s.clone(),
        Arg::Pair { key, value } if key == "hmac" => format!("hmac:{value}"),
        _ => return Err("alias value is not hmac:<hex>".to_owned()),
    };
    let hex = hmac.strip_prefix("hmac:").unwrap_or("");
    if hex.len() < ALIAS_HMAC_MIN_HEX || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "alias HMAC must be hmac: plus at least {ALIAS_HMAC_MIN_HEX} hex characters"
        ));
    }
    Ok((kind.to_owned(), hex.to_ascii_lowercase()))
}

pub(crate) fn canonical_on(id: &RecordId, parent: &MergeMap, on: NaiveDate) -> RecordId {
    let mut seen = HashSet::new();
    let mut cur = id.clone();
    while let Some((next, date)) = parent.get(&cur) {
        if *date > on {
            break;
        }
        if next.prefix() != cur.prefix() {
            break;
        }
        if !seen.insert(cur.clone()) {
            return id.clone();
        }
        cur = next.clone();
    }
    cur
}

fn detect_cycle(parent: &MergeMap) -> Option<RecordId> {
    for start in parent.keys() {
        let mut seen = HashSet::new();
        let mut cur = start.clone();
        while let Some((next, _)) = parent.get(&cur) {
            if !seen.insert(cur.clone()) {
                return Some(start.clone());
            }
            cur = next.clone();
        }
    }
    None
}

/// `W_PACK_ORPHAN` warnings for record fields and record types owned by a
/// registered pack that is not enabled (#177 Q2). Messages name no field,
/// type, or value — the finding's file, line, and ID locate the data.
fn check_orphan_fields_and_types(
    vault: &Vault,
    orphans: &OrphanOwners,
    findings: &mut Vec<Finding>,
) {
    if orphans.fields.is_empty() && orphans.record_types.is_empty() {
        return;
    }
    for rec in vault.records.values() {
        if let Some(owner) = orphans.record_types.get(rec.kind.as_str()) {
            findings.push(
                Finding::new(
                    FindingCode::PackOrphan,
                    Severity::Warning,
                    "record type belongs to a disabled pack".to_owned(),
                )
                .at_file(&rec.path)
                .for_id(&rec.id)
                .with_fix(format!("Enable {owner} or remove the record")),
            );
        }
        for key in rec.fields.keys() {
            if let Some(owner) = orphans.fields.get(key.as_str()) {
                let mut finding = Finding::new(
                    FindingCode::PackOrphan,
                    Severity::Warning,
                    "record field belongs to a disabled pack".to_owned(),
                )
                .at_file(&rec.path)
                .for_id(&rec.id)
                .with_fix(format!("Enable {owner} or remove the field"));
                if let Some(line) = rec.field_lines.get(key) {
                    finding = finding.at_line(*line);
                }
                findings.push(finding);
            }
        }
    }
}

fn check_balances(
    vault: &Vault,
    states: &[(&dyn Pack, Box<dyn PackState>)],
    orphans: &OrphanOwners,
    findings: &mut Vec<Finding>,
) {
    for sourced in &vault.entries {
        if sourced.entry.verb != "balance" {
            continue;
        }
        let e = &sourced.entry;
        let Some(metric) = e.args.first().and_then(Arg::as_token) else {
            findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    "balance line must be: DATE balance ID METRIC NUMBER".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id),
            );
            continue;
        };
        if e.args.get(1).and_then(Arg::as_token).is_none() {
            findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    "balance line is missing a number".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id),
            );
            continue;
        };
        if let Some((pack, state)) = states
            .iter()
            .find(|(pack, _)| pack.balance_metrics().contains(&metric))
        {
            pack.check_balance(vault, state.as_ref(), sourced, findings);
            continue;
        }
        if let Some(owner) = orphans.balance_metrics.get(metric) {
            // Owned by a registered pack that is not enabled: warn, never
            // error (#177 Q2). The message does not echo the metric.
            findings.push(
                Finding::new(
                    FindingCode::PackOrphan,
                    Severity::Warning,
                    "balance metric belongs to a disabled pack".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id)
                .with_fix(format!("Enable {owner} or remove the assertion")),
            );
            continue;
        }
        findings.push(
            Finding::new(
                FindingCode::UnknownMetric,
                Severity::Error,
                "unknown metric".to_owned(),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&e.id)
            .with_fix("Use a metric an enabled pack defines, or remove the balance line"),
        );
    }
}

fn check_duplicate_ulids(vault: &Vault, findings: &mut Vec<Finding>) {
    let mut by_ulid: HashMap<&str, Vec<&RecordId>> = HashMap::new();
    for id in vault.records.keys() {
        by_ulid.entry(id.ulid()).or_default().push(id);
    }
    for (ulid, ids) in by_ulid {
        if ids.len() < 2 {
            continue;
        }
        let mut ids = ids;
        ids.sort();
        let file = vault
            .records
            .get(ids[1])
            .map(|r| r.path.clone())
            .or_else(|| vault.records.get(ids[0]).map(|r| r.path.clone()));
        let mut finding = Finding::new(
            FindingCode::DuplicateUlid,
            Severity::Error,
            format!(
                "ULID {ulid} is used under more than one prefix ({})",
                ids.iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .for_id(ids[0]);
        if let Some(path) = file {
            finding = finding.at_file(&path);
        }
        findings.push(finding);
    }
}

fn check_dangling_refs(vault: &Vault, known_ids: &HashSet<RecordId>, findings: &mut Vec<Finding>) {
    for rec in vault.records.values() {
        // Every field whose key is a `person` / `org` / `deal` reference —
        // including ASCII case variants (`Person:`, #5) — must hold a
        // record ID. Alias or custom keys are not references.
        for (key, raw) in &rec.fields {
            if crate::record::canonical_ref_key(key).is_none() {
                continue;
            };
            match parse_ref_id(raw) {
                FrontmatterRef::Absent => {}
                FrontmatterRef::Invalid => {
                    if scan_id_tokens(raw).iter().any(|tok| tok.is_malformed()) {
                        continue;
                    }
                    findings.push(
                        Finding::new(
                            FindingCode::InvalidId,
                            Severity::Error,
                            format!("front matter key '{key}' is not a record ID"),
                        )
                        .at_file(&rec.path)
                        .for_id(&rec.id)
                        .with_fix("Use a prefixed 26-character Crockford ULID"),
                    );
                }
                FrontmatterRef::Id(id)
                    if !known_ids.contains(&id) && !vault.conflicted_ids.contains(&id) =>
                {
                    let mut finding = Finding::new(
                        FindingCode::DanglingRef,
                        Severity::Error,
                        format!("front matter key '{key}' has no record"),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Create the record or fix the reference");
                    if let Some(line) = rec.field_lines.get(key) {
                        finding = finding.at_line(*line);
                    }
                    findings.push(finding);
                }
                FrontmatterRef::Id(_) => {}
            }
        }
    }
}

/// Edge rules (#179). Runs on records `check` can read: in an encrypted
/// vault an edge is an envelope, so these rules do not run there — the
/// same visibility limit as every other record rule. Kind symmetry is
/// looked up over enabled packs, core, and all registered packs (a kind
/// owned by a disabled pack is still a known kind for duplicate
/// detection; the edge itself warns as `W_PACK_ORPHAN`).
/// The closed edge-kind list for this vault: core kinds plus every enabled
/// pack's kinds, sorted and deduped (#299).
fn edge_kind_names(enabled_packs: &[&dyn Pack]) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = CORE_EDGE_KINDS.iter().map(|k| k.name).collect();
    for pack in enabled_packs {
        names.extend(pack.edge_kinds().iter().map(|k| k.name));
    }
    names.sort_unstable();
    names.dedup();
    names
}

fn check_edges(
    vault: &Vault,
    known_ids: &HashSet<RecordId>,
    enabled_packs: &[&dyn Pack],
    orphans: &OrphanOwners,
    findings: &mut Vec<Finding>,
) {
    // Canonical key for duplicate detection: the pair plus the kind.
    // Sorted ends for symmetric kinds (so (a, b) and (b, a) collide),
    // as-written ends for directed kinds — plus the first record's
    // as-written ends, to tell an exact duplicate from a reversed one.
    // Two edges on the same pair with different kinds are different
    // relations, not duplicates (#179 review).
    let mut seen_pairs: HashMap<(RecordId, RecordId, String), (RecordId, RecordId)> =
        HashMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Edge {
            continue;
        }
        // Envelope shells (`enc:` present) carry no inner fields
        // keylessly: `a` / `b` / `kind` sit inside the ciphertext, so
        // the missing-field rules would false-positive on every edge
        // envelope. Edge rules run on visible records only.
        if rec.field("enc").is_some() {
            continue;
        }
        let mut ends: Vec<RecordId> = Vec::new();
        for key in ["a", "b"] {
            match rec.field(key) {
                None => findings.push(
                    Finding::new(
                        FindingCode::Frontmatter,
                        Severity::Error,
                        format!("front matter key '{key}' is missing"),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix(format!("Add {key}: p-<ULID>")),
                ),
                Some(raw) => match parse_ref_id(raw) {
                    FrontmatterRef::Absent => findings.push(
                        Finding::new(
                            FindingCode::Frontmatter,
                            Severity::Error,
                            format!("front matter key '{key}' is missing"),
                        )
                        .at_file(&rec.path)
                        .for_id(&rec.id)
                        .with_fix(format!("Add {key}: p-<ULID>")),
                    ),
                    FrontmatterRef::Invalid => {
                        // A malformed ID token is already flagged at load
                        // time; skip to avoid double-reporting (#5).
                        if scan_id_tokens(raw).iter().any(|tok| tok.is_malformed()) {
                            continue;
                        }
                        findings.push(
                            Finding::new(
                                FindingCode::InvalidId,
                                Severity::Error,
                                format!("front matter key '{key}' is not a record ID"),
                            )
                            .at_file(&rec.path)
                            .for_id(&rec.id)
                            .with_fix("Use a prefixed 26-character Crockford ULID"),
                        );
                    }
                    FrontmatterRef::Id(id) => {
                        if id.prefix() != Prefix::Person {
                            findings.push(
                                Finding::new(
                                    FindingCode::WrongIdType,
                                    Severity::Error,
                                    format!("edge end '{key}' must be a person id"),
                                )
                                .at_file(&rec.path)
                                .for_id(&rec.id)
                                .with_fix("Use a p-<ULID> id"),
                            );
                        } else if !known_ids.contains(&id) && !vault.conflicted_ids.contains(&id) {
                            let mut finding = Finding::new(
                                FindingCode::DanglingRef,
                                Severity::Error,
                                format!("front matter key '{key}' has no record"),
                            )
                            .at_file(&rec.path)
                            .for_id(&rec.id)
                            .with_fix("Create the record or fix the reference");
                            if let Some(line) = rec.field_lines.get(key) {
                                finding = finding.at_line(*line);
                            }
                            findings.push(finding);
                        }
                        ends.push(id);
                    }
                },
            }
        }
        if ends.len() == 2 && ends[0] == ends[1] {
            findings.push(
                Finding::new(
                    FindingCode::SelfEdge,
                    Severity::Error,
                    "edge links a person to themself".to_owned(),
                )
                .at_file(&rec.path)
                .for_id(&rec.id)
                .with_fix("Remove the edge or link two different people"),
            );
        }
        // Kind: closed list (core + enabled packs). A kind owned by a
        // disabled pack is W_PACK_ORPHAN, never an unknown-kind error.
        let mut symmetric: Option<bool> = None;
        match rec.field("kind") {
            None => findings.push(
                Finding::new(
                    FindingCode::Frontmatter,
                    Severity::Error,
                    "front matter key 'kind' is missing".to_owned(),
                )
                .at_file(&rec.path)
                .for_id(&rec.id)
                .with_fix(format!(
                    "Add kind: {}",
                    edge_kind_names(enabled_packs).join(", ")
                )),
            ),
            Some(kind) => {
                let in_enabled = enabled_packs
                    .iter()
                    .find_map(|p| p.edge_kinds().iter().find(|k| k.name == kind));
                let in_core = CORE_EDGE_KINDS.iter().find(|k| k.name == kind);
                if let Some(k) = in_enabled.or(in_core) {
                    symmetric = Some(k.symmetric);
                } else if let Some(owner) = orphans.edge_kinds.get(kind) {
                    // Owned by a registered pack that is not enabled:
                    // warn, never error (#177 Q2). Symmetry still comes
                    // from the registry for duplicate detection.
                    findings.push(
                        Finding::new(
                            FindingCode::PackOrphan,
                            Severity::Warning,
                            "edge kind belongs to a disabled pack".to_owned(),
                        )
                        .at_file(&rec.path)
                        .for_id(&rec.id)
                        .with_fix(format!("Enable {owner} or remove the edge")),
                    );
                    symmetric = vault
                        .pack_registry()
                        .all()
                        .iter()
                        .find_map(|p| p.edge_kinds().iter().find(|k| k.name == kind))
                        .map(|k| k.symmetric);
                } else {
                    let mut finding = Finding::new(
                        FindingCode::UnknownEdgeKind,
                        Severity::Error,
                        "edge kind is not in the closed kind list".to_owned(),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Use a core kind or enable the pack that defines it");
                    if let Some(line) = rec.field_lines.get("kind") {
                        finding = finding.at_line(*line);
                    }
                    findings.push(finding);
                }
            }
        }
        // Reversed / exact duplicates, per kind. Only for valid person ends:
        // a wrong-type or missing end is already flagged above. The kind
        // joins the key: two edges on the same pair with different kinds
        // are different relations, not duplicates. A missing or unknown
        // kind already errors above; it still keys separately here so the
        // duplicate rule stays total.
        if ends.len() == 2 && ends.iter().all(|id| id.prefix() == Prefix::Person) {
            let kind_key = rec.field("kind").unwrap_or("").to_string();
            let pair = if symmetric == Some(true) {
                if ends[0] <= ends[1] {
                    (ends[0].clone(), ends[1].clone(), kind_key)
                } else {
                    (ends[1].clone(), ends[0].clone(), kind_key)
                }
            } else {
                (ends[0].clone(), ends[1].clone(), kind_key)
            };
            if let Some(first) = seen_pairs.get(&pair) {
                let reversed = first.0 != ends[0] || first.1 != ends[1];
                findings.push(
                    Finding::new(
                        FindingCode::DuplicateEdge,
                        Severity::Error,
                        if reversed {
                            "reversed duplicate edge for a symmetric kind".to_owned()
                        } else {
                            "duplicate edge".to_owned()
                        },
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Keep one edge for the relation"),
                );
            } else {
                seen_pairs.insert(pair, (ends[0].clone(), ends[1].clone()));
            }
        }
    }
}

/// `with:` rules (#179) on interactions. Existence is a keyed check: it
/// runs on records `check` can read. In an encrypted vault the interaction
/// is an envelope with `with:` inside the ciphertext, so these rules do
/// not run there.
fn check_with_lists(vault: &Vault, known_ids: &HashSet<RecordId>, findings: &mut Vec<Finding>) {
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Interaction {
            continue;
        }
        let Some(raw) = rec.field("with") else {
            continue;
        };
        let list = match parse_with_list(raw) {
            Some(list) => list,
            None => {
                findings.push(
                    Finding::new(
                        FindingCode::Frontmatter,
                        Severity::Error,
                        "front matter key 'with' is not a bracketed list of person IDs".to_owned(),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Use with: [p-<ULID>, p-<ULID>]"),
                );
                continue;
            }
        };
        let primary = rec.person();
        let mut seen: HashSet<RecordId> = HashSet::new();
        for id in &list {
            if id.prefix() != Prefix::Person {
                findings.push(
                    Finding::new(
                        FindingCode::WrongIdType,
                        Severity::Error,
                        "with: entries must be person ids".to_owned(),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Use p-<ULID> ids in with:"),
                );
                continue;
            }
            if Some(id) == primary.as_ref() {
                findings.push(
                    Finding::new(
                        FindingCode::Frontmatter,
                        Severity::Error,
                        "with: lists the interaction's own person".to_owned(),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Remove the primary person from with:"),
                );
                continue;
            }
            if !seen.insert(id.clone()) {
                findings.push(
                    Finding::new(
                        FindingCode::Frontmatter,
                        Severity::Error,
                        "with: lists the same participant twice".to_owned(),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("List each participant once in with:"),
                );
                continue;
            }
            if !known_ids.contains(id) && !vault.conflicted_ids.contains(id) {
                findings.push(
                    Finding::new(
                        FindingCode::DanglingRef,
                        Severity::Error,
                        "with: entry has no record".to_owned(),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Create the record or fix the reference"),
                );
            }
        }
    }
}

fn check_duplicate_src(vault: &Vault, findings: &mut Vec<Finding>) {
    let mut seen: BTreeMap<String, (String, u32)> = BTreeMap::new();
    for sourced in &vault.entries {
        let Some(src) = sourced.entry.pair("src") else {
            continue;
        };
        if seen.contains_key(src) {
            findings.push(
                Finding::new(
                    FindingCode::DuplicateSrc,
                    Severity::Error,
                    "src: already appears on another line".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&sourced.entry.id)
                .with_fix("Keep one src: provenance per import"),
            );
        } else {
            seen.insert(src.to_owned(), (sourced.file.clone(), sourced.line));
        }
    }
}

pub(crate) fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.code.as_str().cmp(b.code.as_str()))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
            .then(a.id.cmp(&b.id))
            .then(a.message.cmp(&b.message))
    });
}

pub(crate) fn duration_of(entry: &LedgerEntry) -> Option<u32> {
    entry
        .args
        .iter()
        .filter_map(Arg::as_token)
        .find_map(parse_duration_minutes)
}

#[cfg(test)]
mod tests {
    use super::{parse_fail_on, CheckSummary, Finding, FindingCode, Severity};

    #[test]
    fn fail_on_and_summary() {
        assert_eq!(parse_fail_on("error").unwrap(), Severity::Error);
        assert_eq!(parse_fail_on("warn").unwrap(), Severity::Warning);
        assert!(parse_fail_on("info").is_err());
        let s = CheckSummary {
            records: 1,
            ledger_entries: 1,
            errors: 0,
            warnings: 1,
        };
        assert!(!s.fails(Severity::Error));
        assert!(s.fails(Severity::Warning));
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(FindingCode::BalanceMismatch.as_str(), "E_BALANCE_MISMATCH");
        assert_eq!(
            FindingCode::SessionWithoutNotes.as_str(),
            "E_SESSION_WITHOUT_NOTES"
        );
        assert_eq!(FindingCode::PaidSessionGap.as_str(), "E_PAID_SESSION_GAP");
        assert_eq!(FindingCode::WrongIdType.as_str(), "E_WRONG_ID_TYPE");
        assert_eq!(FindingCode::Config.as_str(), "E_CONFIG");
        assert_eq!(FindingCode::InvalidId.as_str(), "E_INVALID_ID");
        assert_eq!(FindingCode::SessionUntagged.as_str(), "W_SESSION_UNTAGGED");
        assert_eq!(FindingCode::SessionTags.as_str(), "E_SESSION_TAGS");
        assert_eq!(FindingCode::PackConflict.as_str(), "E_PACK_CONFLICT");
        assert_eq!(FindingCode::PackOrphan.as_str(), "W_PACK_ORPHAN");
        assert_eq!(FindingCode::PackHash.as_str(), "E_PACK_HASH");
        assert_eq!(FindingCode::PackInvalid.as_str(), "E_PACK_INVALID");
    }

    #[test]
    fn from_pack_str_accepts_valid() {
        assert_eq!(
            FindingCode::from_pack_str("W_EXAMPLE_THING").unwrap(),
            FindingCode::Pack("W_EXAMPLE_THING")
        );
        assert_eq!(
            FindingCode::from_pack_str("E_AB1").unwrap(),
            FindingCode::Pack("E_AB1")
        );
        // Boundary lengths: 2 and 40 chars after the E_/W_ prefix.
        assert!(FindingCode::from_pack_str("E_AB").is_ok());
        assert!(FindingCode::from_pack_str("E_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
    }

    #[test]
    fn from_pack_str_rejects_bad_shape() {
        assert!(FindingCode::from_pack_str("w_lower").is_err());
        assert!(FindingCode::from_pack_str("X_NOPE").is_err());
        assert!(FindingCode::from_pack_str("E_").is_err());
        assert!(FindingCode::from_pack_str("E_A").is_err());
        // 41 chars after the prefix: too long.
        assert!(FindingCode::from_pack_str("E_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(FindingCode::from_pack_str("E_BAD-CODE").is_err());
        assert!(FindingCode::from_pack_str("").is_err());
    }

    #[test]
    fn from_pack_str_rejects_core_collision() {
        assert!(FindingCode::from_pack_str("E_PARSE").is_err());
        assert!(FindingCode::from_pack_str("W_CADENCE_OVERDUE").is_err());
        assert!(FindingCode::from_pack_str("E_PACK_HASH").is_err());
        assert!(FindingCode::from_pack_str("E_PACK_INVALID").is_err());
        assert!(FindingCode::from_pack_str("W_PACK_ORPHAN").is_err());
    }

    #[test]
    fn pack_code_serializes_as_string() {
        let finding = Finding::new(
            FindingCode::Pack("W_EXAMPLE_THING"),
            Severity::Warning,
            "example",
        );
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"code\":\"W_EXAMPLE_THING\""), "{json}");
        assert_eq!(
            FindingCode::Pack("W_EXAMPLE_THING").as_str(),
            "W_EXAMPLE_THING"
        );
    }

    #[test]
    fn findings_sort_is_stable_with_pack_codes() {
        // Enum variants sort by declaration order (via derived Ord), then
        // Pack codes sort by string. sort_findings itself orders by as_str().
        assert!(FindingCode::Parse < FindingCode::Pack("W_AAA"));
        assert!(FindingCode::DateUpcoming < FindingCode::Pack("E_AAA"));
        assert!(FindingCode::Pack("E_AAA") < FindingCode::Pack("W_AAA"));
        assert!(FindingCode::Pack("W_AAA") < FindingCode::Pack("W_AAB"));

        let mut findings = vec![
            Finding::new(FindingCode::Pack("W_ZZZ"), Severity::Warning, "z"),
            Finding::new(FindingCode::Parse, Severity::Error, "p"),
            Finding::new(FindingCode::Pack("E_AAA"), Severity::Warning, "a"),
        ];
        super::sort_findings(&mut findings);
        // sort_findings orders by severity desc, then as_str().
        assert_eq!(findings[0].code, FindingCode::Parse);
        assert_eq!(findings[1].code, FindingCode::Pack("E_AAA"));
        assert_eq!(findings[2].code, FindingCode::Pack("W_ZZZ"));
    }

    /// `ALL_BUILTIN_STRS` is a second hand-maintained copy of the builtin
    /// `as_str()` values, so a new variant could be missing from it and
    /// `from_pack_str` would then accept a colliding pack code. This keeps
    /// the two in step: the match below lists every variant with no
    /// wildcard arm, so adding one fails to compile until it is added
    /// here too, and the assertion compares the full sequence (order and
    /// length included) against the constant.
    #[test]
    fn all_builtin_strs_lists_every_builtin_variant() {
        let variants = [
            FindingCode::Parse,
            FindingCode::Unreadable,
            FindingCode::Config,
            FindingCode::SpecUnsupported,
            FindingCode::PackUnknown,
            FindingCode::PackConflict,
            FindingCode::PackOrphan,
            FindingCode::PackHash,
            FindingCode::PackInvalid,
            FindingCode::PackVersion,
            FindingCode::InvalidId,
            FindingCode::InvalidFilename,
            FindingCode::IdPathMismatch,
            FindingCode::TypePathMismatch,
            FindingCode::DuplicateId,
            FindingCode::Frontmatter,
            FindingCode::UnknownVerb,
            FindingCode::UnknownRecord,
            FindingCode::UnknownMetric,
            FindingCode::LedgerPath,
            FindingCode::LedgerDate,
            FindingCode::BalanceMismatch,
            FindingCode::AliasPlaintext,
            FindingCode::AliasCollision,
            FindingCode::UnresolvedMerge,
            FindingCode::SelfMerge,
            FindingCode::MergeCycle,
            FindingCode::Symlink,
            FindingCode::MergeConflict,
            FindingCode::MissingDuration,
            FindingCode::OpenMalformed,
            FindingCode::NegativeBalance,
            FindingCode::SessionWithoutNotes,
            FindingCode::PaidSessionGap,
            FindingCode::WrongIdType,
            FindingCode::DuplicateUlid,
            FindingCode::MergeFork,
            FindingCode::DanglingRef,
            FindingCode::DuplicateSrc,
            FindingCode::SessionUntagged,
            FindingCode::SessionTags,
            FindingCode::InboxKeyMismatch,
            FindingCode::SelfEdge,
            FindingCode::DuplicateEdge,
            FindingCode::UnknownEdgeKind,
            FindingCode::TouchMalformed,
            FindingCode::CadenceOverdue,
            FindingCode::DateUpcoming,
        ];
        for code in &variants {
            match code {
                FindingCode::Parse
                | FindingCode::Unreadable
                | FindingCode::Config
                | FindingCode::SpecUnsupported
                | FindingCode::PackUnknown
                | FindingCode::PackConflict
                | FindingCode::PackOrphan
                | FindingCode::PackHash
                | FindingCode::PackInvalid
                | FindingCode::PackVersion
                | FindingCode::InvalidId
                | FindingCode::InvalidFilename
                | FindingCode::IdPathMismatch
                | FindingCode::TypePathMismatch
                | FindingCode::DuplicateId
                | FindingCode::Frontmatter
                | FindingCode::UnknownVerb
                | FindingCode::UnknownRecord
                | FindingCode::UnknownMetric
                | FindingCode::LedgerPath
                | FindingCode::LedgerDate
                | FindingCode::BalanceMismatch
                | FindingCode::AliasPlaintext
                | FindingCode::AliasCollision
                | FindingCode::UnresolvedMerge
                | FindingCode::SelfMerge
                | FindingCode::MergeCycle
                | FindingCode::Symlink
                | FindingCode::MergeConflict
                | FindingCode::MissingDuration
                | FindingCode::OpenMalformed
                | FindingCode::NegativeBalance
                | FindingCode::SessionWithoutNotes
                | FindingCode::PaidSessionGap
                | FindingCode::WrongIdType
                | FindingCode::DuplicateUlid
                | FindingCode::MergeFork
                | FindingCode::DanglingRef
                | FindingCode::DuplicateSrc
                | FindingCode::SessionUntagged
                | FindingCode::SessionTags
                | FindingCode::InboxKeyMismatch
                | FindingCode::SelfEdge
                | FindingCode::DuplicateEdge
                | FindingCode::UnknownEdgeKind
                | FindingCode::TouchMalformed
                | FindingCode::CadenceOverdue
                | FindingCode::DateUpcoming => {}
                FindingCode::Pack(_) => panic!("Pack is not a builtin variant"),
            }
        }
        // The str→builtin mapping covers every builtin, both ways (#441).
        for s in FindingCode::ALL_BUILTIN_STRS {
            let code = FindingCode::builtin_from_str(s)
                .unwrap_or_else(|| panic!("builtin_from_str misses {s}"));
            assert_eq!(code.as_str(), *s, "builtin_from_str roundtrip: {s}");
        }
        assert_eq!(
            variants.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            FindingCode::ALL_BUILTIN_STRS.to_vec(),
            "ALL_BUILTIN_STRS must list every builtin variant, in declaration order"
        );
    }
}
