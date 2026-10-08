//! Coaching schema pack 0.1: sessions, packages, ICF hours, gap rules.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{canonical_on, duration_of, Finding, FindingCode, MergeMap, Severity};
use crate::id::{Prefix, RecordId};
use crate::ledger::{minutes_to_hundredths, parse_strict_date, Arg, LedgerEntry};
use crate::record::RecordKind;
use crate::vault::Vault;

const MAX_OPEN_N: i64 = 100_000;

#[derive(Clone, Debug)]
struct OpenEvent {
    date: NaiveDate,
    n: i64,
}

#[derive(Clone, Debug)]
struct SessionEvent {
    date: NaiveDate,
    minutes: Option<u32>,
    pps: bool,
    consumes: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PersonCoaching {
    opens: Vec<OpenEvent>,
    sessions: Vec<SessionEvent>,
}

impl PersonCoaching {
    fn remaining_on(&self, on: NaiveDate) -> Option<i64> {
        let mut opened: i64 = 0;
        for o in self.opens.iter().filter(|o| o.date <= on) {
            opened = opened.checked_add(o.n)?;
        }
        let used = i64::try_from(
            self.sessions
                .iter()
                .filter(|s| s.date <= on && s.consumes)
                .count(),
        )
        .ok()?;
        opened.checked_sub(used)
    }

    fn minutes_on(&self, on: NaiveDate) -> u32 {
        self.sessions
            .iter()
            .filter(|s| s.date <= on)
            .filter_map(|s| s.minutes)
            .fold(0u32, |acc, m| acc.saturating_add(m))
    }

    fn last_session_on(&self, on: NaiveDate) -> Option<NaiveDate> {
        self.sessions
            .iter()
            .map(|s| s.date)
            .filter(|d| *d <= on)
            .max()
    }

    fn last_open_on(&self, on: NaiveDate) -> Option<NaiveDate> {
        self.opens.iter().map(|o| o.date).filter(|d| *d <= on).max()
    }

    fn pps_in_lookback(&self, as_of: NaiveDate, window: chrono::Duration) -> bool {
        self.sessions
            .iter()
            .any(|s| s.pps && s.date <= as_of && as_of.signed_duration_since(s.date) <= window)
    }

    fn any_session_in_window(&self, as_of: NaiveDate, window: chrono::Duration) -> bool {
        self.sessions
            .iter()
            .any(|s| s.date <= as_of && as_of.signed_duration_since(s.date) <= window)
    }
}

type MembersByRoot = HashMap<NaiveDate, HashMap<RecordId, Vec<RecordId>>>;

#[derive(Clone, Debug, Default)]
pub struct CoachingState {
    pub parent: MergeMap,
    people: HashMap<RecordId, PersonCoaching>,
    pub packages: HashSet<RecordId>,
    members_by_root: RefCell<MembersByRoot>,
}

impl CoachingState {
    pub fn canonical_on(&self, id: &RecordId, on: NaiveDate) -> RecordId {
        canonical_on(id, &self.parent, on)
    }

    fn members_on(&self, on: NaiveDate) -> HashMap<RecordId, Vec<RecordId>> {
        if let Some(existing) = self.members_by_root.borrow().get(&on) {
            return existing.clone();
        }
        let mut map: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
        for pid in self.people.keys() {
            let root = canonical_on(pid, &self.parent, on);
            map.entry(root).or_default().push(pid.clone());
        }
        for members in map.values_mut() {
            members.sort();
        }
        self.members_by_root.borrow_mut().insert(on, map.clone());
        map
    }

    fn group_people<'a>(
        &'a self,
        groups: &'a HashMap<RecordId, Vec<RecordId>>,
        id: &RecordId,
        on: NaiveDate,
    ) -> impl Iterator<Item = &'a PersonCoaching> {
        let root = canonical_on(id, &self.parent, on);
        let members = groups.get(&root).map(Vec::as_slice).unwrap_or(&[]);
        members.iter().filter_map(|pid| self.people.get(pid))
    }

    pub fn sessions_remaining(&self, id: &RecordId) -> i64 {
        self.sessions_remaining_on(id, NaiveDate::MAX)
    }

    pub fn sessions_remaining_on(&self, id: &RecordId, on: NaiveDate) -> i64 {
        let groups = self.members_on(on);
        let mut total: i64 = 0;
        for person in self.group_people(&groups, id, on) {
            let Some(n) = person.remaining_on(on) else {
                continue;
            };
            match total.checked_add(n) {
                Some(sum) => total = sum,
                None => return total,
            }
        }
        total
    }

    pub fn icf_hours_hundredths(&self, id: &RecordId) -> i64 {
        self.icf_hours_hundredths_on(id, NaiveDate::MAX)
    }

    pub fn icf_hours_hundredths_on(&self, id: &RecordId, on: NaiveDate) -> i64 {
        let groups = self.members_on(on);
        let mut minutes: u32 = 0;
        for person in self.group_people(&groups, id, on) {
            minutes = minutes.saturating_add(person.minutes_on(on));
        }
        minutes_to_hundredths(minutes)
    }

    fn group_pps_in_lookback(
        &self,
        id: &RecordId,
        as_of: NaiveDate,
        window: chrono::Duration,
    ) -> bool {
        let groups = self.members_on(as_of);
        let found = self
            .group_people(&groups, id, as_of)
            .any(|person| person.pps_in_lookback(as_of, window));
        found
    }

    fn group_any_session_in_window(
        &self,
        id: &RecordId,
        as_of: NaiveDate,
        window: chrono::Duration,
    ) -> bool {
        let groups = self.members_on(as_of);
        let found = self
            .group_people(&groups, id, as_of)
            .any(|person| person.any_session_in_window(as_of, window));
        found
    }

    fn group_last_session_on(&self, id: &RecordId, as_of: NaiveDate) -> Option<NaiveDate> {
        let groups = self.members_on(as_of);
        let last = self
            .group_people(&groups, id, as_of)
            .filter_map(|person| person.last_session_on(as_of))
            .max();
        last
    }

    fn group_last_open_on(&self, id: &RecordId, as_of: NaiveDate) -> Option<NaiveDate> {
        let groups = self.members_on(as_of);
        let last = self
            .group_people(&groups, id, as_of)
            .filter_map(|person| person.last_open_on(as_of))
            .max();
        last
    }
}

pub fn fold(
    vault: &Vault,
    parent: MergeMap,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) -> CoachingState {
    let mut state = CoachingState {
        parent,
        people: HashMap::new(),
        packages: HashSet::new(),
        members_by_root: RefCell::new(HashMap::new()),
    };

    let mut events: Vec<_> = vault
        .entries
        .iter()
        .filter(|s| s.entry.verb == "open" || s.entry.verb == "session")
        .collect();
    events.sort_by_key(|s| {
        (
            s.entry.date,
            u8::from(s.entry.verb != "open"),
            s.line,
            s.file.clone(),
        )
    });

    for sourced in events {
        let e = &sourced.entry;
        if e.id.prefix() != Prefix::Person {
            continue;
        }
        match e.verb.as_str() {
            "open" => apply_open(&mut state, sourced.file.as_str(), sourced.line, e, findings),
            "session" => {
                apply_session(&mut state, sourced.file.as_str(), sourced.line, e, findings)
            }
            _ => {}
        }
    }

    let nonnegative = vault
        .config
        .checks
        .severity("coaching.balance_nonnegative", Severity::Error);
    if let Some(sev) = nonnegative {
        let groups = state.members_on(as_of);
        let mut roots: Vec<_> = groups.keys().cloned().collect();
        roots.sort();
        for id in roots {
            let remaining = state.sessions_remaining_on(&id, as_of);
            if remaining < 0 {
                findings.push(
                    Finding::new(
                        FindingCode::NegativeBalance,
                        sev,
                        format!("sessions_remaining for {id} is {remaining}"),
                    )
                    .for_id(&id)
                    .with_fix("Add an open/renewal or remove extra session lines"),
                );
            }
        }
    }
    state
}

fn person_mut<'a>(state: &'a mut CoachingState, id: &RecordId) -> &'a mut PersonCoaching {
    state.people.entry(id.clone()).or_default()
}

fn apply_open(
    state: &mut CoachingState,
    file: &str,
    line: u32,
    entry: &LedgerEntry,
    findings: &mut Vec<Finding>,
) {
    match parse_open(entry) {
        None => findings.push(
            Finding::new(
                FindingCode::OpenMalformed,
                Severity::Error,
                "open line must be: DATE open PERSON-ID package PKG-ID N sessions".to_owned(),
            )
            .at_file(file)
            .at_line(line)
            .for_id(&entry.id)
            .with_fix("Example: 2026-10-01 open p-… package pkg-… 6 sessions"),
        ),
        Some(Err(OpenIssue::InvalidId(raw))) => findings.push(
            Finding::new(
                FindingCode::InvalidId,
                Severity::Error,
                format!("package id '{raw}' is not a record ID"),
            )
            .at_file(file)
            .at_line(line)
            .for_id(&entry.id)
            .with_fix("Use a pkg-<ULID> package id"),
        ),
        Some(Err(OpenIssue::Malformed(msg))) => findings.push(
            Finding::new(FindingCode::OpenMalformed, Severity::Error, msg)
                .at_file(file)
                .at_line(line)
                .for_id(&entry.id),
        ),
        Some(Ok((pkg, n))) => {
            if pkg.prefix() != Prefix::Package {
                findings.push(
                    Finding::new(
                        FindingCode::WrongIdType,
                        Severity::Error,
                        format!("package id '{pkg}' must use the pkg- prefix"),
                    )
                    .at_file(file)
                    .at_line(line)
                    .for_id(&entry.id),
                );
            }
            if n > MAX_OPEN_N {
                findings.push(
                    Finding::new(
                        FindingCode::OpenMalformed,
                        Severity::Error,
                        format!("open N {n} exceeds the cap of {MAX_OPEN_N}"),
                    )
                    .at_file(file)
                    .at_line(line)
                    .for_id(&entry.id)
                    .with_fix(format!("Use a package size between 1 and {MAX_OPEN_N}")),
                );
                return;
            }
            {
                let person = person_mut(state, &entry.id);
                let opened: Option<i64> = person
                    .opens
                    .iter()
                    .try_fold(0i64, |acc, o| acc.checked_add(o.n));
                if opened.and_then(|acc| acc.checked_add(n)).is_none() {
                    findings.push(
                        Finding::new(
                            FindingCode::OpenMalformed,
                            Severity::Error,
                            format!("open total for {} overflows", entry.id),
                        )
                        .at_file(file)
                        .at_line(line)
                        .for_id(&entry.id),
                    );
                    return;
                }
                person.opens.push(OpenEvent {
                    date: entry.date,
                    n,
                });
            }
            state.packages.insert(pkg);
        }
    }
}

#[derive(Debug)]
enum OpenIssue {
    InvalidId(String),
    Malformed(String),
}

fn parse_open(entry: &LedgerEntry) -> Option<Result<(RecordId, i64), OpenIssue>> {
    let tokens: Vec<&str> = entry.args.iter().filter_map(Arg::as_token).collect();
    if tokens.len() < 4 {
        return None;
    }
    if tokens[0] != "package" || tokens[3] != "sessions" {
        return None;
    }
    let pkg = match RecordId::parse(tokens[1]) {
        Ok(id) => id,
        Err(_) => return Some(Err(OpenIssue::InvalidId(tokens[1].to_owned()))),
    };
    let n: i64 = match tokens[2].parse() {
        Ok(n) if n > 0 => n,
        Ok(_) => return None,
        Err(_) => {
            return Some(Err(OpenIssue::Malformed(format!(
                "'{}' is not a positive integer",
                tokens[2]
            ))))
        }
    };
    Some(Ok((pkg, n)))
}

fn apply_session(
    state: &mut CoachingState,
    file: &str,
    line: u32,
    entry: &LedgerEntry,
    findings: &mut Vec<Finding>,
) {
    let duration = duration_of(entry);
    if duration.is_none() {
        findings.push(
            Finding::new(
                FindingCode::MissingDuration,
                Severity::Error,
                format!("session for {} has no parseable duration", entry.id),
            )
            .at_file(file)
            .at_line(line)
            .for_id(&entry.id)
            .with_fix("Add a duration such as 60m or 1h30m"),
        );
    }
    let paid = entry.has_token("paid");
    let pps = entry.has_token("pps");
    let comp = entry.has_token("comp");
    let tag_count = [paid, pps, comp].into_iter().filter(|tag| *tag).count();
    if tag_count > 1 {
        findings.push(
            Finding::new(
                FindingCode::SessionTags,
                Severity::Error,
                format!(
                    "session for {} has more than one of paid, pps, comp",
                    entry.id
                ),
            )
            .at_file(file)
            .at_line(line)
            .for_id(&entry.id)
            .with_fix("Keep exactly one billing tag: paid, pps, or comp"),
        );
    }
    if tag_count == 0 {
        findings.push(
            Finding::new(
                FindingCode::SessionUntagged,
                Severity::Warning,
                format!("session for {} has no paid, pps, or comp tag", entry.id),
            )
            .at_file(file)
            .at_line(line)
            .for_id(&entry.id)
            .with_fix("Tag the session paid, pps (pay-per-session), or comp (complimentary)"),
        );
    }
    // `paid` consumes. `pps` and `comp` never do. Untagged still consumes so
    // balances cannot silently drop a session.
    let consumes = paid || tag_count == 0;
    let person = person_mut(state, &entry.id);
    if let Some(mins) = duration {
        let current = person.minutes_on(NaiveDate::MAX);
        if current.checked_add(mins).is_none() {
            findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    format!("session minutes for {} overflow", entry.id),
                )
                .at_file(file)
                .at_line(line)
                .for_id(&entry.id),
            );
        }
    }
    person.sessions.push(SessionEvent {
        date: entry.date,
        minutes: duration,
        pps,
        consumes,
    });
}

pub fn gap_rules(
    vault: &Vault,
    state: &CoachingState,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) {
    apply_duration_off(vault, findings);
    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.require_duration", Severity::Error)
    {
        for finding in findings.iter_mut() {
            if finding.code == FindingCode::MissingDuration {
                finding.severity = sev;
            }
        }
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.session_notes", Severity::Warning)
    {
        session_without_notes(vault, state, as_of, sev, findings);
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.paid_session_gap", Severity::Warning)
    {
        let days = vault.config.checks.paid_session_gap_days();
        let lookback = vault.config.checks.pps_lookback_days();
        paid_session_gap(state, as_of, days, lookback, sev, findings);
    }
}

/// `note:` ID/type/existence/ownership. Always on; ignores `session_notes` and `as_of`.
pub fn session_note_integrity(vault: &Vault, state: &CoachingState, findings: &mut Vec<Finding>) {
    for sourced in &vault.entries {
        if sourced.entry.verb != "session" {
            continue;
        }
        let e = &sourced.entry;
        let person = state.canonical_on(&e.id, NaiveDate::MAX);
        let Some(note_id) = e.pair("note") else {
            continue;
        };
        match RecordId::parse(note_id) {
            Err(_) => findings.push(
                Finding::new(
                    FindingCode::InvalidId,
                    Severity::Error,
                    format!("session note '{note_id}' is not a record ID"),
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
                    format!("session note '{nid}' is not a note id"),
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
                        format!("session note '{nid}' does not exist"),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&person)
                    .with_fix("Point note: at an existing n-<ULID> note"),
                ),
                Some(rec) => {
                    let note_person = rec
                        .person()
                        .or_else(|| person_from_path(&rec.path))
                        .map(|p| state.canonical_on(&p, NaiveDate::MAX));
                    if note_person.as_ref() != Some(&person) {
                        findings.push(
                            Finding::new(
                                FindingCode::UnknownRecord,
                                Severity::Error,
                                format!("session note '{nid}' does not belong to {person}"),
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

fn session_without_notes(
    vault: &Vault,
    state: &CoachingState,
    as_of: NaiveDate,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let notes_by_person_date = note_coverage(vault, state, as_of);
    for sourced in &vault.entries {
        if sourced.entry.verb != "session" {
            continue;
        }
        let e = &sourced.entry;
        if e.date > as_of {
            continue;
        }
        let person = state.canonical_on(&e.id, as_of);
        if e.pair("note").is_some() {
            continue;
        }
        let covered = notes_by_person_date
            .get(&person)
            .is_some_and(|dates| dates.contains(&e.date));
        if covered {
            continue;
        }
        findings.push(
            Finding::new(
                FindingCode::SessionWithoutNotes,
                severity,
                format!("session on {} for {} has no notes", e.date, person),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&person)
            .with_fix("Add a note for that person and date, or note:n-<ULID> on the session line"),
        );
    }
}

fn note_coverage(
    vault: &Vault,
    state: &CoachingState,
    as_of: NaiveDate,
) -> HashMap<RecordId, HashSet<NaiveDate>> {
    let mut map: HashMap<RecordId, HashSet<NaiveDate>> = HashMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Note {
            continue;
        }
        let Some(person) = rec.person().or_else(|| person_from_path(&rec.path)) else {
            continue;
        };
        let person = state.canonical_on(&person, as_of);
        let mut dates = HashSet::new();
        if let Some(d) = rec.field("date").and_then(parse_strict_date) {
            dates.insert(d);
        }
        if let Some(d) = rec.field("session").and_then(parse_strict_date) {
            dates.insert(d);
        }
        if dates.is_empty() {
            continue;
        }
        map.entry(person).or_default().extend(dates);
    }
    map
}

fn person_from_path(path: &str) -> Option<RecordId> {
    let mut parts = path.split('/');
    if parts.next()? != "people" {
        return None;
    }
    RecordId::parse(parts.next()?).ok()
}

fn paid_session_gap(
    state: &CoachingState,
    as_of: NaiveDate,
    days: u64,
    lookback: u64,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let days_i = i64::try_from(days).unwrap_or(i64::MAX);
    let lookback_i = i64::try_from(lookback).unwrap_or(i64::MAX);
    let window = chrono::Duration::days(days_i);
    let lookback_window = chrono::Duration::days(lookback_i);
    let groups = state.members_on(as_of);
    let mut ids: Vec<_> = groups.keys().cloned().collect();
    ids.sort();
    for id in ids {
        let remaining = state.sessions_remaining_on(&id, as_of);
        let pps_client = state.group_pps_in_lookback(&id, as_of, lookback_window);
        if remaining <= 0 && !pps_client {
            continue;
        }
        if state.group_any_session_in_window(&id, as_of, window) {
            continue;
        }
        let last = state.group_last_session_on(&id, as_of);
        if last.is_none() {
            if let Some(opened) = state.group_last_open_on(&id, as_of) {
                if as_of.signed_duration_since(opened) <= window {
                    continue;
                }
            }
        }
        let start = as_of - window;
        let message = match (last, remaining > 0) {
            (None, _) => format!("paid client {id} has no session logged"),
            (Some(d), true) => format!(
                "paid client {id} has remaining sessions and no session on or after {start} (last was {d})"
            ),
            (Some(d), false) => {
                format!("paid client {id} has no session on or after {start} (last was {d})")
            }
        };
        findings.push(
            Finding::new(FindingCode::PaidSessionGap, severity, message)
                .for_id(&id)
                .with_fix(format!(
                    "Log a session, close the package, or widen coaching.paid_session_gap_days (currently {days})"
                )),
        );
    }
}

/// Drop MissingDuration findings when the rule is off. Called from gap_rules
/// after fold pushed them as errors.
pub fn apply_duration_off(vault: &Vault, findings: &mut Vec<Finding>) {
    if vault
        .config
        .checks
        .severity("coaching.require_duration", Severity::Error)
        .is_none()
    {
        findings.retain(|f| f.code != FindingCode::MissingDuration);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_open;
    use crate::ledger::parse_line;

    #[test]
    fn open_grammar() {
        let e = parse_line(
            "2026-10-01 open p-01M3TC5H00MPJG000000000000 package pkg-01M3TC5H00MPJG004SK4000009 6 sessions",
        )
        .unwrap()
        .unwrap();
        let (pkg, n) = parse_open(&e).unwrap().unwrap();
        assert_eq!(n, 6);
        assert_eq!(pkg.to_string(), "pkg-01M3TC5H00MPJG004SK4000009");
        let bad = parse_line("2026-10-01 open p-01M3TC5H00MPJG000000000000 6")
            .unwrap()
            .unwrap();
        assert!(parse_open(&bad).is_none());
    }
}
