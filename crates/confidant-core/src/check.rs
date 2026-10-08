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

use crate::config::{parse_iso_date, VaultConfig, SPEC_VERSION};
use crate::error::DomainError;
use crate::id::{scan_id_tokens, Prefix, RecordId};
use crate::ledger::{parse_decimal_hundredths, parse_duration_minutes, Arg, LedgerEntry};
use crate::packs::coaching::{self, CoachingState};
use crate::record::{parse_ref_id, FrontmatterRef};
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FindingCode {
    Parse,
    Unreadable,
    Config,
    SpecUnsupported,
    PackUnknown,
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
}

impl FindingCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "E_PARSE",
            Self::Unreadable => "E_UNREADABLE",
            Self::Config => "E_CONFIG",
            Self::SpecUnsupported => "E_SPEC_UNSUPPORTED",
            Self::PackUnknown => "E_PACK_UNKNOWN",
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
        }
    }
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
}

/// Run every check against `vault`, collecting rather than propagating.
pub fn run(vault: &Vault, options: &CheckOptions) -> CheckReport {
    let mut findings = vault.load_findings.clone();

    if vault.config.spec != SPEC_VERSION {
        findings.push(
            Finding::new(
                FindingCode::SpecUnsupported,
                Severity::Error,
                format!(
                    "vault spec '{}' is not supported (this CLI implements {SPEC_VERSION})",
                    vault.config.spec
                ),
            )
            .at_file("confidant.toml")
            .with_fix("Use spec = \"0.1\" or upgrade the CLI"),
        );
    }

    for pack in &vault.config.packs {
        if pack != crate::config::COACHING_PACK {
            findings.push(
                Finding::new(
                    FindingCode::PackUnknown,
                    Severity::Error,
                    format!("unknown pack '{pack}'"),
                )
                .at_file("confidant.toml")
                .with_fix("Remove the pack or use a CLI that implements it"),
            );
        }
    }

    let spec_ok = vault.config.spec == SPEC_VERSION;
    if !spec_ok {
        sort_findings(&mut findings);
        return finish_report(vault, options, findings);
    }

    let known_verbs = known_verbs(&vault.config);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();

    check_ledger_paths(vault, &mut findings);
    let as_of = resolve_as_of(vault, options);
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut findings);
    check_verbs_and_refs(vault, &known_verbs, &known_ids, &mut findings);
    check_duplicate_ulids(vault, &mut findings);
    check_dangling_refs(vault, &known_ids, &mut findings);
    check_duplicate_src(vault, &mut findings);

    let coaching = if vault.config.coaching_enabled() {
        Some(coaching::fold(vault, merges, as_of, &mut findings))
    } else {
        None
    };

    check_balances(vault, coaching.as_ref(), &mut findings);

    if let Some(state) = coaching.as_ref() {
        coaching::session_note_integrity(vault, state, &mut findings);
        coaching::gap_rules(vault, state, as_of, &mut findings);
    }

    sort_findings(&mut findings);
    finish_report(vault, options, findings)
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
    if let Some(raw) = vault.config.checks.as_of.as_deref() {
        if let Ok(d) = parse_iso_date(raw) {
            return d;
        }
        // Invalid as_of in config is reported as E_CONFIG at load time.
    }
    chrono::Utc::now().date_naive()
}

fn known_verbs(config: &VaultConfig) -> HashSet<&'static str> {
    let mut verbs = HashSet::from(["alias", "merge", "stage", "balance"]);
    if config.coaching_enabled() {
        verbs.insert("open");
        verbs.insert("session");
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
                        format!(
                            "entry date {} does not belong in {}",
                            entry.entry.date, entry.file
                        ),
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
    known_ids: &HashSet<RecordId>,
    findings: &mut Vec<Finding>,
) {
    for sourced in &vault.entries {
        let e = &sourced.entry;
        if !known_verbs.contains(e.verb.as_str()) {
            findings.push(
                Finding::new(
                    FindingCode::UnknownVerb,
                    Severity::Error,
                    format!("unknown verb '{}'", e.verb),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id)
                .with_fix("Use a core verb or enable the pack that defines it"),
            );
        }
        let expected = match e.verb.as_str() {
            "stage" => Some(Prefix::Deal),
            "open" | "session" => Some(Prefix::Person),
            _ => None,
        };
        if let Some(want) = expected {
            if e.id.prefix() != want {
                findings.push(
                    Finding::new(
                        FindingCode::WrongIdType,
                        Severity::Error,
                        format!("{} requires a {} id, got '{}'", e.verb, want.as_str(), e.id),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix(format!("Use a {}-<ULID> id", want.as_str())),
                );
                continue;
            }
        }
        if e.id.prefix() != Prefix::Package && !known_ids.contains(&e.id) {
            findings.push(
                Finding::new(
                    FindingCode::UnknownRecord,
                    Severity::Error,
                    format!("ledger id '{}' has no record file", e.id),
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

fn check_aliases_and_merges(
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
                        .for_id(&from),
                    );
                    continue;
                }
                for id in [&from, &to] {
                    if !known_ids.contains(id) {
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
        findings.push(
            Finding::new(
                FindingCode::MergeCycle,
                Severity::Error,
                format!("merge entries form a cycle involving {cycle}"),
            )
            .with_fix("Remove one merge so every id has a single canonical root"),
        );
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

fn check_balances(vault: &Vault, coaching: Option<&CoachingState>, findings: &mut Vec<Finding>) {
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
        let Some(number) = e.args.get(1).and_then(Arg::as_token) else {
            findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    format!("balance '{metric}' is missing a number"),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id),
            );
            continue;
        };
        match metric {
            "sessions_remaining" | "icf_hours" => {
                if coaching.is_none() {
                    findings.push(
                        Finding::new(
                            FindingCode::UnknownMetric,
                            Severity::Error,
                            format!("metric '{metric}' requires packs = [\"coaching@0.1\"]"),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&e.id)
                        .with_fix("Enable the coaching pack or remove the assertion"),
                    );
                    continue;
                }
            }
            other => {
                findings.push(
                    Finding::new(
                        FindingCode::UnknownMetric,
                        Severity::Error,
                        format!("unknown metric '{other}'"),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id),
                );
                continue;
            }
        }
        let Some(state) = coaching else { continue };
        let person = state.canonical_on(&e.id, e.date);
        if metric == "sessions_remaining" {
            let asserted: i64 = match number.parse() {
                Ok(n) => n,
                Err(_) => {
                    findings.push(
                        Finding::new(
                            FindingCode::Parse,
                            Severity::Error,
                            format!("'{number}' is not an integer"),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&e.id),
                    );
                    continue;
                }
            };
            let computed = state.sessions_remaining_on(&person, e.date);
            if asserted != computed {
                findings.push(
                    Finding::new(
                        FindingCode::BalanceMismatch,
                        Severity::Error,
                        format!("sessions_remaining asserted {asserted}, computed {computed}"),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&person)
                    .with_fix(format!(
                        "Check for a missing 'open' entry or a duplicated 'session' entry for {person}"
                    )),
                );
            }
        } else if metric == "icf_hours" {
            let Some(asserted) = parse_decimal_hundredths(number) else {
                findings.push(
                    Finding::new(
                        FindingCode::Parse,
                        Severity::Error,
                        format!("'{number}' is not a decimal number"),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id),
                );
                continue;
            };
            let computed = state.icf_hours_hundredths_on(&person, e.date);
            if asserted != computed {
                findings.push(
                    Finding::new(
                        FindingCode::BalanceMismatch,
                        Severity::Error,
                        format!(
                            "icf_hours asserted {number}, computed {}",
                            format_hundredths(computed)
                        ),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&person)
                    .with_fix(format!(
                        "Check session durations for {person} or correct the assertion"
                    )),
                );
            }
        }
    }
}

fn format_hundredths(n: i64) -> String {
    let sign = if n < 0 { "-" } else { "" };
    let Some(n) = n.checked_abs() else {
        return n.to_string();
    };
    format!("{sign}{}.{:02}", n / 100, n % 100)
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
        findings.push(
            Finding::new(
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
            .for_id(ids[0]),
        );
    }
}

fn check_dangling_refs(vault: &Vault, known_ids: &HashSet<RecordId>, findings: &mut Vec<Finding>) {
    const REF_KEYS: &[&str] = &["person", "org", "deal"];
    for rec in vault.records.values() {
        for key in REF_KEYS {
            let Some(raw) = rec.field(key) else { continue };
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
                FrontmatterRef::Id(id) if !known_ids.contains(&id) => findings.push(
                    Finding::new(
                        FindingCode::DanglingRef,
                        Severity::Error,
                        format!("front matter key '{key}' has no record"),
                    )
                    .at_file(&rec.path)
                    .for_id(&rec.id)
                    .with_fix("Create the record or fix the reference"),
                ),
                FrontmatterRef::Id(_) => {}
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
        if let Some((file, line)) = seen.get(src) {
            findings.push(
                Finding::new(
                    FindingCode::DuplicateSrc,
                    Severity::Error,
                    format!("src:{src} already appears at {file}:{line}"),
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
    use super::{parse_fail_on, CheckSummary, FindingCode, Severity};

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
    }
}
