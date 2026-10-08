//! Coaching schema pack 0.1: sessions, packages, ICF hours, gap rules.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{canonical, duration_of, parse_merge, Finding, FindingCode, Severity};
use crate::id::{Prefix, RecordId};
use crate::ledger::{minutes_to_hundredths, Arg, LedgerEntry};
use crate::record::RecordKind;
use crate::vault::Vault;

#[derive(Clone, Debug)]
struct OpenEvent {
    date: NaiveDate,
    n: i64,
}

#[derive(Clone, Debug)]
struct SessionEvent {
    date: NaiveDate,
    minutes: Option<u32>,
    paid: bool,
    consumes: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PersonCoaching {
    opens: Vec<OpenEvent>,
    sessions: Vec<SessionEvent>,
}

impl PersonCoaching {
    fn remaining_on(&self, on: NaiveDate) -> i64 {
        let opened: i64 = self
            .opens
            .iter()
            .filter(|o| o.date <= on)
            .map(|o| o.n)
            .sum();
        let used = self
            .sessions
            .iter()
            .filter(|s| s.date <= on && s.consumes)
            .count() as i64;
        opened - used
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

    fn paid_session_in_window(&self, as_of: NaiveDate, window: chrono::Duration) -> bool {
        self.sessions
            .iter()
            .any(|s| s.paid && s.date <= as_of && as_of.signed_duration_since(s.date) <= window)
    }

    fn any_session_in_window(&self, as_of: NaiveDate, window: chrono::Duration) -> bool {
        self.sessions
            .iter()
            .any(|s| s.date <= as_of && as_of.signed_duration_since(s.date) <= window)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CoachingState {
    pub parent: HashMap<RecordId, RecordId>,
    people: HashMap<RecordId, PersonCoaching>,
    pub packages: HashSet<RecordId>,
}

impl CoachingState {
    pub fn canonical(&self, id: &RecordId) -> RecordId {
        canonical(id, &self.parent)
    }

    pub fn sessions_remaining(&self, id: &RecordId) -> i64 {
        self.sessions_remaining_on(id, NaiveDate::MAX)
    }

    pub fn sessions_remaining_on(&self, id: &RecordId, on: NaiveDate) -> i64 {
        let id = self.canonical(id);
        self.people
            .get(&id)
            .map(|p| p.remaining_on(on))
            .unwrap_or(0)
    }

    pub fn icf_hours_hundredths(&self, id: &RecordId) -> i64 {
        self.icf_hours_hundredths_on(id, NaiveDate::MAX)
    }

    pub fn icf_hours_hundredths_on(&self, id: &RecordId, on: NaiveDate) -> i64 {
        let id = self.canonical(id);
        self.people
            .get(&id)
            .map(|p| minutes_to_hundredths(p.minutes_on(on)))
            .unwrap_or(0)
    }
}

pub fn fold(vault: &Vault, findings: &mut Vec<Finding>) -> CoachingState {
    let mut state = CoachingState::default();
    for sourced in &vault.entries {
        if sourced.entry.verb == "merge" {
            if let Some((from, to)) = parse_merge(&sourced.entry) {
                state.parent.insert(from, to);
            }
        }
    }

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
        let mut ids: Vec<_> = state.people.keys().cloned().collect();
        ids.sort();
        for id in ids {
            let remaining = state.sessions_remaining(&id);
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
    let canon = state.canonical(id);
    state.people.entry(canon).or_default()
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
        Some(Err(msg)) => findings.push(
            Finding::new(FindingCode::OpenMalformed, Severity::Error, msg)
                .at_file(file)
                .at_line(line)
                .for_id(&entry.id),
        ),
        Some(Ok((pkg, n))) => {
            if pkg.prefix() != Prefix::Package {
                findings.push(
                    Finding::new(
                        FindingCode::OpenMalformed,
                        Severity::Error,
                        format!("package id '{pkg}' must use the pkg- prefix"),
                    )
                    .at_file(file)
                    .at_line(line)
                    .for_id(&entry.id),
                );
            }
            state.packages.insert(pkg);
            person_mut(state, &entry.id).opens.push(OpenEvent {
                date: entry.date,
                n,
            });
        }
    }
}

fn parse_open(entry: &LedgerEntry) -> Option<Result<(RecordId, i64), String>> {
    let tokens: Vec<&str> = entry.args.iter().filter_map(Arg::as_token).collect();
    if tokens.len() < 4 {
        return None;
    }
    if tokens[0] != "package" || tokens[3] != "sessions" {
        return None;
    }
    let pkg = match RecordId::parse(tokens[1]) {
        Ok(id) => id,
        Err(_) => {
            return Some(Err(format!(
                "package id '{}' is not a record ID",
                tokens[1]
            )))
        }
    };
    let n: i64 = match tokens[2].parse() {
        Ok(n) if n > 0 => n,
        Ok(_) => return None,
        Err(_) => return Some(Err(format!("'{}' is not a positive integer", tokens[2]))),
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
    let remaining_now = {
        let person = person_mut(state, &entry.id);
        person.remaining_on(entry.date)
    };
    // A `paid` session with no remaining package does not consume a package
    // slot and must not raise E_NEGATIVE_BALANCE (pay-per-session).
    let consumes = remaining_now > 0 || !paid;
    let person = person_mut(state, &entry.id);
    if consumes {
        // Overflow of the used-count is reported as E_PARSE rather than wrapping.
        if person
            .sessions
            .iter()
            .filter(|s| s.consumes)
            .count()
            .checked_add(1)
            .is_none()
        {
            findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    format!("session count for {} overflows", entry.id),
                )
                .at_file(file)
                .at_line(line)
                .for_id(&entry.id),
            );
        }
    }
    if let Some(mins) = duration {
        if person
            .minutes_on(NaiveDate::MAX)
            .checked_add(mins)
            .is_none()
        {
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
        paid,
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
        paid_session_gap(state, as_of, days, sev, findings);
    }
}

fn session_without_notes(
    vault: &Vault,
    state: &CoachingState,
    as_of: NaiveDate,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let notes_by_person_date = note_coverage(vault, state);
    for sourced in &vault.entries {
        if sourced.entry.verb != "session" {
            continue;
        }
        let e = &sourced.entry;
        if e.date > as_of {
            continue;
        }
        let person = state.canonical(&e.id);
        if let Some(note_id) = e.pair("note") {
            match RecordId::parse(note_id) {
                Err(_) => {
                    findings.push(
                        Finding::new(
                            FindingCode::InvalidId,
                            Severity::Error,
                            format!("session note '{note_id}' is not a record ID"),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&person)
                        .with_fix("Point note: at an existing n-<ULID> note"),
                    );
                    continue;
                }
                Ok(nid) if nid.prefix() != Prefix::Note => {
                    findings.push(
                        Finding::new(
                            FindingCode::WrongIdType,
                            Severity::Error,
                            format!("session note '{nid}' is not a note id"),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&person)
                        .with_fix("Use note:n-<ULID>"),
                    );
                    continue;
                }
                Ok(nid) => match vault.records.get(&nid) {
                    None => {
                        findings.push(
                            Finding::new(
                                FindingCode::UnknownRecord,
                                Severity::Error,
                                format!("session note '{nid}' does not exist"),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&person)
                            .with_fix("Point note: at an existing n-<ULID> note"),
                        );
                        continue;
                    }
                    Some(rec) => {
                        let note_person = rec
                            .person()
                            .or_else(|| person_from_path(&rec.path))
                            .map(|p| state.canonical(&p));
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
                        continue;
                    }
                },
            }
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

fn note_coverage(vault: &Vault, state: &CoachingState) -> HashMap<RecordId, HashSet<NaiveDate>> {
    let mut map: HashMap<RecordId, HashSet<NaiveDate>> = HashMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Note {
            continue;
        }
        let Some(person) = rec.person().or_else(|| person_from_path(&rec.path)) else {
            continue;
        };
        let person = state.canonical(&person);
        let mut dates = HashSet::new();
        if let Some(d) = rec.field("date").and_then(parse_date) {
            dates.insert(d);
        }
        if let Some(d) = rec.field("session").and_then(parse_date) {
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

fn parse_date(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

fn paid_session_gap(
    state: &CoachingState,
    as_of: NaiveDate,
    days: u64,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let days_i = i64::try_from(days).unwrap_or(i64::MAX);
    let window = chrono::Duration::days(days_i);
    let mut ids: Vec<_> = state.people.keys().cloned().collect();
    ids.sort();
    for id in ids {
        let remaining = state.sessions_remaining_on(&id, as_of);
        let person = state.people.get(&id);
        let paid_in_window = person.is_some_and(|p| p.paid_session_in_window(as_of, window));
        // Paid client: remaining package sessions, or a pay-per-session
        // client with a `paid` session inside the window.
        if remaining <= 0 && !paid_in_window {
            continue;
        }
        let in_window = person.is_some_and(|p| p.any_session_in_window(as_of, window));
        if in_window {
            continue;
        }
        let last = person.and_then(|p| p.last_session_on(as_of));
        let message = match last {
            None => format!(
                "paid client {id} has remaining sessions but no session has been logged"
            ),
            Some(d) => format!(
                "paid client {id} has remaining sessions and no session on or after {} (last was {d})",
                as_of - window
            ),
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
