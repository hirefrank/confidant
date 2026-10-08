//! Coaching schema pack 0.1: sessions, packages, ICF hours, gap rules.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{canonical, duration_of, parse_merge, Finding, FindingCode, Severity};
use crate::id::{Prefix, RecordId};
use crate::ledger::{minutes_to_hundredths, Arg, LedgerEntry};
use crate::record::RecordKind;
use crate::vault::Vault;

#[derive(Clone, Debug, Default)]
pub struct PersonCoaching {
    pub opened: i64,
    pub used: i64,
    pub minutes: u32,
    pub last_session: Option<NaiveDate>,
    pub session_dates: Vec<NaiveDate>,
}

impl PersonCoaching {
    pub fn remaining(&self) -> i64 {
        self.opened - self.used
    }
}

#[derive(Clone, Debug, Default)]
pub struct CoachingState {
    pub parent: HashMap<RecordId, RecordId>,
    pub people: HashMap<RecordId, PersonCoaching>,
    pub packages: HashSet<RecordId>,
}

impl CoachingState {
    pub fn canonical(&self, id: &RecordId) -> RecordId {
        canonical(id, &self.parent)
    }

    pub fn sessions_remaining(&self, id: &RecordId) -> i64 {
        let id = self.canonical(id);
        self.people
            .get(&id)
            .map(PersonCoaching::remaining)
            .unwrap_or(0)
    }

    pub fn icf_hours_hundredths(&self, id: &RecordId) -> i64 {
        let id = self.canonical(id);
        self.people
            .get(&id)
            .map(|p| minutes_to_hundredths(p.minutes))
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

    for sourced in &vault.entries {
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
        Some((pkg, n)) => {
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
            person_mut(state, &entry.id).opened += n;
        }
    }
}

fn parse_open(entry: &LedgerEntry) -> Option<(RecordId, i64)> {
    let tokens: Vec<&str> = entry.args.iter().filter_map(Arg::as_token).collect();
    if tokens.len() < 4 {
        return None;
    }
    if tokens[0] != "package" || tokens[3] != "sessions" {
        return None;
    }
    let pkg = RecordId::parse(tokens[1]).ok()?;
    let n: i64 = tokens[2].parse().ok()?;
    if n <= 0 {
        return None;
    }
    Some((pkg, n))
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
                Severity::Error, // severity adjusted by caller via config after fold? we handle below
                format!("session for {} has no parseable duration", entry.id),
            )
            .at_file(file)
            .at_line(line)
            .for_id(&entry.id)
            .with_fix("Add a duration such as 60m or 1h30m"),
        );
        // Still consume a session so balances stay honest about the line existing.
    }
    let person = person_mut(state, &entry.id);
    person.used += 1;
    if let Some(mins) = duration {
        person.minutes = person.minutes.saturating_add(mins);
    }
    person.session_dates.push(entry.date);
    person.last_session = Some(
        person
            .last_session
            .map(|d| d.max(entry.date))
            .unwrap_or(entry.date),
    );
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
        session_without_notes(vault, sev, findings);
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.paid_session_gap", Severity::Warning)
    {
        let days = vault
            .config
            .checks
            .u64_or("coaching.paid_session_gap_days", 45);
        paid_session_gap(state, as_of, days, sev, findings);
    }
}

fn session_without_notes(vault: &Vault, severity: Severity, findings: &mut Vec<Finding>) {
    let notes_by_person_date = note_coverage(vault);
    for sourced in &vault.entries {
        if sourced.entry.verb != "session" {
            continue;
        }
        let e = &sourced.entry;
        if let Some(note_id) = e.pair("note") {
            if let Ok(nid) = RecordId::parse(note_id) {
                if vault.records.contains_key(&nid) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        FindingCode::UnknownRecord,
                        Severity::Error,
                        format!("session note '{nid}' does not exist"),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix("Point note: at an existing n-<ULID> note"),
                );
                continue;
            }
        }
        let covered = notes_by_person_date
            .get(&e.id)
            .is_some_and(|dates| dates.contains(&e.date));
        if covered {
            continue;
        }
        findings.push(
            Finding::new(
                FindingCode::SessionWithoutNotes,
                severity,
                format!("session on {} for {} has no notes", e.date, e.id),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&e.id)
            .with_fix("Add a note for that person and date, or note:n-<ULID> on the session line"),
        );
    }
}

fn note_coverage(vault: &Vault) -> HashMap<RecordId, HashSet<NaiveDate>> {
    let mut map: HashMap<RecordId, HashSet<NaiveDate>> = HashMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Note {
            continue;
        }
        let Some(person) = rec.person().or_else(|| person_from_path(&rec.path)) else {
            continue;
        };
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
    // people/p-ULID/notes/n-ULID.md
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
    let window = chrono::Duration::days(days as i64);
    let mut ids: Vec<_> = state.people.keys().cloned().collect();
    ids.sort();
    for id in ids {
        if state.sessions_remaining(&id) <= 0 {
            continue;
        }
        let last = state.people.get(&id).and_then(|p| p.last_session);
        let in_window = match last {
            Some(d) => as_of.signed_duration_since(d) <= window,
            None => false,
        };
        if in_window {
            continue;
        }
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
        let (pkg, n) = parse_open(&e).unwrap();
        assert_eq!(n, 6);
        assert_eq!(pkg.to_string(), "pkg-01M3TC5H00MPJG004SK4000009");
        let bad = parse_line("2026-10-01 open p-01M3TC5H00MPJG000000000000 6")
            .unwrap()
            .unwrap();
        assert!(parse_open(&bad).is_none());
    }
}
