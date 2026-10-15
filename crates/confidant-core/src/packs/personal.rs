//! Personal relationships schema pack 0.1 (#184, #182): birthdays, important
//! dates, relationship edge kinds, keep-in-touch cadence, and the `touch`
//! ledger verb.

use std::collections::{BTreeMap, HashMap};

use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::check::{Finding, FindingCode, MergeMap, Severity};
use crate::config::{MAX_GAP_DAYS, PERSONAL_PACK};
use crate::id::{Prefix, RecordId};
use crate::ledger::{parse_strict_date, Arg, LedgerEntry};
use crate::packs::{EdgeKind, Pack, PackState};
use crate::record::{parse_with_list, Record, RecordKind};
use crate::search::cleared_record_ids;
use crate::vault::{SourcedEntry, Vault};

/// Closed list of touchpoint kinds for `touch` (#182, #227 Q1).
pub const TOUCH_KINDS: &[&str] = &["call", "text", "coffee", "gift", "meet"];

/// Edge kinds introduced by `personal@0.1` (#179, #184).
pub const PERSONAL_EDGE_KINDS: &[EdgeKind] = &[
    EdgeKind {
        name: "friend",
        symmetric: true,
    },
    EdgeKind {
        name: "family",
        symmetric: true,
    },
    EdgeKind {
        name: "sibling",
        symmetric: true,
    },
    EdgeKind {
        name: "partner",
        symmetric: true,
    },
    EdgeKind {
        name: "parent",
        symmetric: false,
    },
    EdgeKind {
        name: "mentor",
        symmetric: false,
    },
];

fn is_valid_touch_kind(kind: &str) -> bool {
    TOUCH_KINDS.contains(&kind)
}

/// Extract the touchpoint kind from either a positional `KIND` token
/// (`2026-10-12 touch p-… call`) or a `kind:KIND` pair (`2026-10-12 touch p-… kind:call`).
/// Pack-internal; core reaches it through [`Pack::verb_kind`] (#185/#296).
fn extract_touch_kind(entry: &LedgerEntry) -> Option<String> {
    if let Some(k) = entry.pair("kind") {
        return Some(k.to_owned());
    }
    if let Some(tok) = entry.args.first().and_then(Arg::as_token) {
        if is_valid_touch_kind(tok) {
            return Some(tok.to_owned());
        }
    }
    None
}

/// Validate a `touch` line's arguments when `personal@0.1` is enabled.
/// Accepts either:
/// - `DATE touch P-ID` (mirrored touchpoint with no kind)
/// - `DATE touch P-ID kind:<call|text|coffee|gift|meet>` (mirrored touchpoint with kind)
/// - `DATE touch P-ID <call|text|coffee|gift|meet> [note:N-ID] [src:…]` (`log touch` syntax)
///
/// Pack-internal; core reaches it through [`Pack::validate_verb_args`]
/// (#185/#296). On non-mirrored inputs this agrees with the shape core
/// used to ask `is_personal_touch_shape` about, so the disabled-pack
/// branch of `check` can use it as the pack-shape check behind
/// `W_PACK_ORPHAN`.
fn validate_touch_args_enabled(args: &[Arg]) -> bool {
    match args {
        [] => true,
        [arg] => match arg.pair() {
            Some(("kind", k)) => is_valid_touch_kind(k),
            None => arg.as_token().is_some_and(is_valid_touch_kind),
            _ => false,
        },
        _ => parse_personal_touch_args(args).is_some(),
    }
}

fn parse_personal_touch_args(args: &[Arg]) -> Option<&str> {
    let first = args.first()?.as_token()?;
    if !is_valid_touch_kind(first) {
        return None;
    }
    let mut seen_note = false;
    let mut seen_src = false;
    for arg in &args[1..] {
        match arg.pair() {
            Some(("note", _)) if !seen_note => seen_note = true,
            Some(("src", _)) if !seen_src => seen_src = true,
            _ => return None,
        }
    }
    Some(first)
}

/// Parsed calendar month/day with optional year (`YYYY-MM-DD` or `--MM-DD`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringDate {
    pub label: String,
    pub raw: String,
    pub year: Option<i32>,
    pub month: u32,
    pub day: u32,
}

impl RecurringDate {
    /// Parse `YYYY-MM-DD` or `--MM-DD`.
    pub fn parse(label: impl Into<String>, raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_prefix("--") {
            let (m_str, d_str) = rest.split_once('-')?;
            if m_str.len() != 2 || d_str.len() != 2 {
                return None;
            }
            if !m_str.bytes().all(|b| b.is_ascii_digit())
                || !d_str.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let month: u32 = m_str.parse().ok()?;
            let day: u32 = d_str.parse().ok()?;
            // Validate month/day against leap year 2024 so `--02-29` is valid
            // while `--02-30` and `--13-01` are rejected.
            NaiveDate::from_ymd_opt(2024, month, day)?;
            Some(Self {
                label: label.into(),
                raw: trimmed.to_owned(),
                year: None,
                month,
                day,
            })
        } else {
            let date = parse_strict_date(trimmed)?;
            Some(Self {
                label: label.into(),
                raw: trimmed.to_owned(),
                year: Some(date.year()),
                month: date.month(),
                day: date.day(),
            })
        }
    }

    /// Next occurrence of this month/day on or after `as_of`, respecting
    /// `self.year` (an event with a year cannot occur before that year).
    pub fn next_occurrence_on_or_after(&self, as_of: NaiveDate) -> Option<NaiveDate> {
        for cy in [
            as_of.year(),
            as_of.year() + 1,
            as_of.year() + 2,
            as_of.year() + 3,
            as_of.year() + 4,
        ] {
            if self.year.is_some_and(|y| cy < y) {
                continue;
            }
            if let Some(occ) = NaiveDate::from_ymd_opt(cy, self.month, self.day) {
                if occ >= as_of {
                    return Some(occ);
                }
            }
        }
        None
    }
}

/// Parse `cadence` (`<N>d`, where `1 <= N <= 3650`).
pub fn parse_cadence_days(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    let num_str = trimmed.strip_suffix('d')?;
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let days: u64 = num_str.parse().ok()?;
    if days == 0 || days > MAX_GAP_DAYS {
        return None;
    }
    u32::try_from(days).ok()
}

/// Parse `dates:` (`[label:DATE, ...]` or `label:DATE, ...`).
pub fn parse_dates_list(raw: &str) -> Option<Vec<RecurringDate>> {
    let trimmed = raw.trim();
    let inner = if let Some(stripped) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        stripped.trim()
    } else if trimmed.starts_with('[') || trimmed.ends_with(']') {
        return None;
    } else {
        trimmed
    };
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let token = item.trim();
        if token.is_empty() {
            return None;
        }
        let (label_raw, date_raw) = token.split_once(':')?;
        let label = label_raw.trim();
        if label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
        let rd = RecurringDate::parse(label, date_raw)?;
        out.push(rd);
    }
    Some(out)
}

#[derive(Clone, Debug)]
struct TouchEvent {
    date: NaiveDate,
}

#[derive(Clone, Debug, Default)]
struct PersonPersonal {
    touches: Vec<TouchEvent>,
    cadence_days: Option<u32>,
    birthday: Option<RecurringDate>,
    relationship_to_me: Option<String>,
    dates: Vec<RecurringDate>,
}

impl PersonPersonal {
    fn last_touch_on(&self, on: NaiveDate) -> Option<NaiveDate> {
        self.touches
            .iter()
            .map(|t| t.date)
            .filter(|d| *d <= on)
            .max()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PersonalState {
    merge: crate::packs::groups::MergeGroups,
    people: HashMap<RecordId, PersonPersonal>,
}

impl PackState for PersonalState {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PersonalState {
    pub fn canonical_on(&self, id: &RecordId, on: NaiveDate) -> RecordId {
        self.merge.canonical_on(id, on)
    }

    fn ensure_members(&self, on: NaiveDate) {
        self.merge.ensure_members(self.people.keys().cloned(), on);
    }

    fn group_people<'a>(
        &'a self,
        groups: &'a HashMap<RecordId, Vec<RecordId>>,
        root: &RecordId,
    ) -> impl Iterator<Item = &'a PersonPersonal> {
        groups
            .get(root)
            .into_iter()
            .flat_map(|members| members.iter())
            .filter_map(|m| self.people.get(m))
    }

    pub fn last_touch_on(&self, canonical: &RecordId, on: NaiveDate) -> Option<NaiveDate> {
        self.ensure_members(on);
        let groups = self.merge.groups();
        let groups = groups.get(&on).expect("members cached");
        self.group_people(groups, canonical)
            .filter_map(|p| p.last_touch_on(on))
            .max()
    }

    pub fn cadence_days_for(&self, canonical: &RecordId, on: NaiveDate) -> Option<u32> {
        if let Some(days) = self.people.get(canonical).and_then(|p| p.cadence_days) {
            return Some(days);
        }
        self.ensure_members(on);
        let borrow = self.merge.groups();
        let groups = borrow.get(&on).expect("members cached");
        let members = groups.get(canonical)?;
        for m in members {
            if let Some(days) = self.people.get(m).and_then(|p| p.cadence_days) {
                return Some(days);
            }
        }
        None
    }
}

/// One important date entry in `context` (`packs["personal@0.1"].dates`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportantDateView {
    pub label: String,
    pub date: String,
}

/// One recent touchpoint in `context` (`packs["personal@0.1"].recent_touches`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentTouch {
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Personal pack context view (`packs["personal@0.1"]`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonalView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthday: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship_to_me: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub dates: Vec<ImportantDateView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cadence_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_touch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_since_touch: Option<i64>,
    pub overdue: bool,
    pub recent_touches: Vec<RecentTouch>,
}

/// The compiled personal pack (#184). Registered in [`crate::packs::ALL_PACKS`].
pub struct PersonalPack;

impl Pack for PersonalPack {
    fn name(&self) -> &'static str {
        PERSONAL_PACK
    }

    fn verbs(&self) -> &'static [&'static str] {
        &["touch"]
    }

    fn record_types(&self) -> &'static [&'static str] {
        &[]
    }

    fn fields(&self) -> &'static [&'static str] {
        &["birthday", "cadence", "relationship_to_me", "dates"]
    }

    fn balance_metrics(&self) -> &'static [&'static str] {
        &[]
    }

    fn finding_codes(&self) -> &'static [&'static str] {
        // Codes this pack's `fold` / `findings` emit. `E_TOUCH_MALFORMED`
        // is a core code (emitted by `check`, not this pack), so it is not
        // listed here; it is documented in `spec/findings.md`.
        &[
            "E_FRONTMATTER",
            "E_INVALID_ID",
            "E_WRONG_ID_TYPE",
            "E_UNKNOWN_RECORD",
            "W_CADENCE_OVERDUE",
            "W_DATE_UPCOMING",
        ]
    }

    fn edge_kinds(&self) -> &'static [EdgeKind] {
        PERSONAL_EDGE_KINDS
    }

    fn verb_id_type(&self, verb: &str) -> Option<Prefix> {
        match verb {
            "touch" => Some(Prefix::Person),
            _ => None,
        }
    }

    fn validate_verb_args(&self, verb: &str, entry: &LedgerEntry) -> Option<bool> {
        match verb {
            "touch" => Some(validate_touch_args_enabled(&entry.args)),
            _ => None,
        }
    }

    fn verb_kind(&self, verb: &str, entry: &LedgerEntry) -> Option<String> {
        match verb {
            "touch" => extract_touch_kind(entry),
            _ => None,
        }
    }

    fn fold(
        &self,
        vault: &Vault,
        merges: &MergeMap,
        as_of: NaiveDate,
        findings: &mut Vec<Finding>,
    ) -> Box<dyn PackState> {
        Box::new(fold(vault, merges.clone(), as_of, findings))
    }

    fn findings(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        as_of: NaiveDate,
        findings: &mut Vec<Finding>,
    ) {
        let state = state
            .as_any()
            .downcast_ref::<PersonalState>()
            .expect("PersonalPack state");
        touch_note_integrity(vault, state, findings);
        cadence_and_date_rules(vault, state, as_of, findings);
    }

    fn check_balance(
        &self,
        _vault: &Vault,
        _state: &dyn PackState,
        _sourced: &SourcedEntry,
        _findings: &mut Vec<Finding>,
    ) {
    }

    fn context_view(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        person: &RecordId,
        canonical: &RecordId,
        as_of: NaiveDate,
    ) -> Option<serde_json::Value> {
        let state = state
            .as_any()
            .downcast_ref::<PersonalState>()
            .expect("PersonalPack state");
        let cleared = cleared_record_ids(vault);
        let person_cleared = cleared.contains(person);

        let cadence_days = state.cadence_days_for(canonical, as_of);
        let last_touch_date = state.last_touch_on(canonical, as_of);
        let days_since_touch = last_touch_date.map(|d| as_of.signed_duration_since(d).num_days());
        let overdue = match (cadence_days, days_since_touch) {
            (Some(cad), Some(days)) => days > i64::from(cad),
            (Some(_), None) => true,
            (None, _) => false,
        };

        let (birthday, relationship_to_me, dates) = if person_cleared {
            let p = state.people.get(canonical);
            (
                p.and_then(|pp| pp.birthday.as_ref().map(|b| b.raw.clone())),
                p.and_then(|pp| pp.relationship_to_me.clone()),
                p.map(|pp| {
                    pp.dates
                        .iter()
                        .map(|d| ImportantDateView {
                            label: d.label.clone(),
                            date: d.raw.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            )
        } else {
            (None, None, Vec::new())
        };

        let mut recent_touches: Vec<RecentTouch> = vault
            .entries
            .iter()
            .filter(|s| {
                s.entry.verb == "touch"
                    && s.entry.date <= as_of
                    && state.canonical_on(&s.entry.id, as_of) == *canonical
            })
            .map(|s| RecentTouch {
                date: s.entry.date.to_string(),
                kind: extract_touch_kind(&s.entry),
            })
            .collect();
        recent_touches.sort_by(|a, b| b.date.cmp(&a.date).then(a.kind.cmp(&b.kind)));
        recent_touches.truncate(10);

        let view = PersonalView {
            birthday,
            relationship_to_me,
            dates,
            cadence_days,
            last_touch: last_touch_date.map(|d| d.to_string()),
            days_since_touch,
            overdue,
            recent_touches,
        };
        serde_json::to_value(view).ok()
    }

    fn private_context_fields(&self) -> &'static [&'static str] {
        // `birthday`, `relationship_to_me`, and `dates` are the person's own
        // PII; `context` strips them when private data is excluded. The
        // cadence/touch fields are derived metadata and stay.
        &["birthday", "relationship_to_me", "dates"]
    }
}

fn person_mut<'a>(state: &'a mut PersonalState, id: &RecordId) -> &'a mut PersonPersonal {
    state.people.entry(id.clone()).or_default()
}

fn fold(
    vault: &Vault,
    merges: MergeMap,
    _as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) -> PersonalState {
    let mut state = PersonalState {
        merge: crate::packs::groups::MergeGroups::new(merges),
        ..Default::default()
    };

    // 1. Validate and fold personal fields on records, and fold interaction
    //    records into touchpoints.
    let mut records: Vec<&Record> = vault.records.values().collect();
    records.sort_by(|a, b| a.id.cmp(&b.id));
    for rec in records {
        if rec.kind == RecordKind::Person {
            let entry = person_mut(&mut state, &rec.id);
            if let Some(raw) = rec.field("birthday") {
                match RecurringDate::parse("birthday", raw) {
                    Some(bd) => entry.birthday = Some(bd),
                    None => push_field_error(
                        rec,
                        "birthday",
                        "front matter key 'birthday' must be YYYY-MM-DD or --MM-DD",
                        "Use YYYY-MM-DD (e.g. 1990-05-14) or --MM-DD (e.g. --05-14)",
                        findings,
                    ),
                }
            }
            if let Some(raw) = rec.field("cadence") {
                match parse_cadence_days(raw) {
                    Some(days) => entry.cadence_days = Some(days),
                    None => push_field_error(
                        rec,
                        "cadence",
                        "front matter key 'cadence' must be <N>d (1..=3650)",
                        "Use a positive day count such as 30d or 90d",
                        findings,
                    ),
                }
            }
            if let Some(raw) = rec.field("relationship_to_me") {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    push_field_error(
                        rec,
                        "relationship_to_me",
                        "front matter key 'relationship_to_me' must not be empty",
                        "Provide a non-empty relationship label or remove the key",
                        findings,
                    );
                } else {
                    entry.relationship_to_me = Some(trimmed.to_owned());
                }
            }
            if let Some(raw) = rec.field("dates") {
                match parse_dates_list(raw) {
                    Some(list) => entry.dates = list,
                    None => push_field_error(
                        rec,
                        "dates",
                        "front matter key 'dates' must be a comma-separated list of label:YYYY-MM-DD or label:--MM-DD",
                        "Example: dates: [anniversary:2020-06-15, graduation:--05-20]",
                        findings,
                    ),
                }
            }
        } else if rec.kind == RecordKind::Interaction {
            if let Some(date) = rec.field("date").and_then(parse_strict_date) {
                if let Some(primary) = rec.person() {
                    person_mut(&mut state, &primary)
                        .touches
                        .push(TouchEvent { date });
                }
                if let Some(raw_with) = rec.field("with") {
                    if let Some(participants) = parse_with_list(raw_with) {
                        for p in participants {
                            if p.prefix() == Prefix::Person {
                                person_mut(&mut state, &p).touches.push(TouchEvent { date });
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Fold ledger touchpoints (`touch` and coaching `session` per #227 Q2).
    for sourced in &vault.entries {
        let e = &sourced.entry;
        if e.id.prefix() != Prefix::Person {
            continue;
        }
        match e.verb.as_str() {
            "touch" => {
                person_mut(&mut state, &e.id)
                    .touches
                    .push(TouchEvent { date: e.date });
            }
            "session" => {
                // #227 Q2: coaching `session` counts as a touchpoint so a
                // coaching client who is also a friend does not get a false
                // cadence overdue warning.
                person_mut(&mut state, &e.id)
                    .touches
                    .push(TouchEvent { date: e.date });
            }
            _ => {}
        }
    }

    state
}

fn push_field_error(
    rec: &Record,
    key: &str,
    problem: &str,
    fix: &str,
    findings: &mut Vec<Finding>,
) {
    let mut f = Finding::new(
        FindingCode::Frontmatter,
        Severity::Error,
        problem.to_owned(),
    )
    .at_file(&rec.path)
    .for_id(&rec.id)
    .with_fix(fix.to_owned());
    if let Some(line) = rec.field_lines.get(key) {
        f = f.at_line(*line);
    }
    findings.push(f);
}

/// `note:` ID/type/existence/ownership on `touch` lines, mirroring coaching's
/// `session_note_integrity`.
fn touch_note_integrity(vault: &Vault, state: &PersonalState, findings: &mut Vec<Finding>) {
    for sourced in &vault.entries {
        if sourced.entry.verb != "touch" {
            continue;
        }
        let e = &sourced.entry;
        if e.id.prefix() != Prefix::Person {
            continue;
        }
        let person = state.canonical_on(&e.id, NaiveDate::MAX);
        let Some(note_id) = e.pair("note") else {
            continue;
        };
        match RecordId::parse(note_id) {
            Err(_) => findings.push(
                Finding::new(
                    FindingCode::InvalidId,
                    Severity::Error,
                    "touch note is not a record ID".to_owned(),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix("Point note: at an existing n-<ULID> note"),
            ),
            Ok(nid) if nid.prefix() != Prefix::Note => findings.push(
                Finding::new(
                    FindingCode::WrongIdType,
                    Severity::Error,
                    format!("touch note '{nid}' is not a note id"),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix("Use note:n-<ULID>"),
            ),
            Ok(nid) => match vault.records.get(&nid) {
                None => findings.push(
                    Finding::new(
                        FindingCode::UnknownRecord,
                        Severity::Error,
                        format!("touch note '{nid}' does not exist"),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&person)
                    .with_fix("Point note: at an existing n-<ULID> note"),
                ),
                Some(rec) => {
                    let note_person = rec
                        .person()
                        .or_else(|| crate::id::person_id_from_path(&rec.path))
                        .map(|p| state.canonical_on(&p, NaiveDate::MAX));
                    if note_person.as_ref() != Some(&person) {
                        findings.push(
                            Finding::new(
                                FindingCode::UnknownRecord,
                                Severity::Error,
                                format!("touch note '{nid}' does not belong to {person}"),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&person)
                            .with_fix("Point note: at a note for this person"),
                        );
                    }
                }
            },
        }
    }
}

fn cadence_and_date_rules(
    vault: &Vault,
    state: &PersonalState,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) {
    state.ensure_members(as_of);

    // Collect canonical person IDs in deterministic order.
    let mut canonical_people: BTreeMap<RecordId, &Record> = BTreeMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Person {
            continue;
        }
        let canon = state.canonical_on(&rec.id, as_of);
        if canon == rec.id {
            canonical_people.insert(canon, rec);
        }
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("personal.cadence_overdue", Severity::Warning)
    {
        for (id, rec) in &canonical_people {
            let Some(cadence_days) = state.cadence_days_for(id, as_of) else {
                continue;
            };
            let window = chrono::Duration::days(i64::from(cadence_days));
            let last = state.last_touch_on(id, as_of);
            if let Some(d) = last {
                if as_of.signed_duration_since(d) <= window {
                    continue;
                }
            }
            let start = as_of - window;
            let message = match last {
                Some(d) => format!(
                    "person {id} has no touchpoint on or after {start} (last was {d}, cadence {cadence_days}d)"
                ),
                None => format!(
                    "person {id} has no touchpoint logged (cadence {cadence_days}d)"
                ),
            };
            findings.push(
                Finding::new(FindingCode::CadenceOverdue, sev, message)
                    .at_file(&rec.path)
                    .for_id(id)
                    .with_fix(format!(
                        "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
                    )),
            );
        }
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("personal.date_upcoming", Severity::Warning)
    {
        let lookahead = vault.config.checks.date_upcoming_days();
        let lookahead_i = i64::try_from(lookahead).unwrap_or(i64::MAX);
        for (id, rec) in &canonical_people {
            let Some(pp) = state.people.get(id) else {
                continue;
            };
            let mut all_dates: Vec<&RecurringDate> = Vec::new();
            if let Some(ref bd) = pp.birthday {
                all_dates.push(bd);
            }
            all_dates.extend(pp.dates.iter());
            for rd in all_dates {
                let Some(occ) = rd.next_occurrence_on_or_after(as_of) else {
                    continue;
                };
                let delta = occ.signed_duration_since(as_of).num_days();
                if (0..=lookahead_i).contains(&delta) {
                    findings.push(
                        Finding::new(
                            FindingCode::DateUpcoming,
                            sev,
                            format!("upcoming date for {id} on {occ} (in {delta}d)"),
                        )
                        .at_file(&rec.path)
                        .for_id(id)
                        .with_fix(format!(
                            "Reach out to {id} or set `[checks] personal.date_upcoming = \"off\"`"
                        )),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recurring_date_parses_iso_and_yearless() {
        let full = RecurringDate::parse("birthday", "1990-05-14").unwrap();
        assert_eq!(full.year, Some(1990));
        assert_eq!(full.month, 5);
        assert_eq!(full.day, 14);

        let yearless = RecurringDate::parse("birthday", "--10-12").unwrap();
        assert_eq!(yearless.year, None);
        assert_eq!(yearless.month, 10);
        assert_eq!(yearless.day, 12);

        let leap = RecurringDate::parse("birthday", "--02-29").unwrap();
        assert_eq!(leap.month, 2);
        assert_eq!(leap.day, 29);

        assert!(RecurringDate::parse("birthday", "10-12").is_none());
        assert!(RecurringDate::parse("birthday", "--02-30").is_none());
        assert!(RecurringDate::parse("birthday", "--13-01").is_none());
    }

    #[test]
    fn cadence_parser_accepts_positive_days_within_cap() {
        assert_eq!(parse_cadence_days("30d"), Some(30));
        assert_eq!(parse_cadence_days("3650d"), Some(3650));
        assert_eq!(parse_cadence_days("0d"), None);
        assert_eq!(parse_cadence_days("3651d"), None);
        assert_eq!(parse_cadence_days("30"), None);
        assert_eq!(parse_cadence_days("30w"), None);
    }

    #[test]
    fn dates_list_parser_accepts_bracketed_and_plain() {
        let list = parse_dates_list("[anniversary:2020-06-15, graduation:--05-20]").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].label, "anniversary");
        assert_eq!(list[0].year, Some(2020));
        assert_eq!(list[1].label, "graduation");
        assert_eq!(list[1].year, None);

        assert!(parse_dates_list("[]").unwrap().is_empty());
        assert!(parse_dates_list("[bad]").is_none());
        assert!(parse_dates_list("[anniversary:2020-13-01]").is_none());
    }
}
