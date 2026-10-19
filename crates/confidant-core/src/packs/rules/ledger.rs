//! Shared ledger arithmetic for the coaching rule kinds (#446-#448).
//!
//! The shipped `coaching@0.1` pack's `ledger-balance` rule and the
//! `session-checks` and `activity-gap` kinds must agree exactly, so this
//! module owns the accumulation and the merge-aware queries. The rules and
//! messages stay in their own modules; only the arithmetic and the fold
//! ordering live here.
//!
//! Semantics:
//! - events are ordered by date, then opens before the consuming verb,
//!   then line, then file;
//! - only person-prefixed ids take part;
//! - a consuming entry consumes unless it is tagged `pps` or `comp`; an
//!   untagged entry consumes so a balance cannot silently drop a session;
//! - `open` lines are `package <pkg-id> <positive integer> sessions` with
//!   a per-entry cap and a checked total;
//! - hours are hundredths of an hour, never floating point.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::duration_of;
use crate::id::{Prefix, RecordId};
use crate::ledger::{minutes_to_hundredths, Arg, LedgerEntry};
use crate::packs::groups::MergeGroups;
use crate::packs::PackState;
use crate::vault::{SourcedEntry, Vault};

/// How many of `tags` the entry carries.
pub(crate) fn billing_tag_count(entry: &LedgerEntry, tags: &[&str]) -> usize {
    tags.iter().filter(|tag| entry.has_token(tag)).count()
}

/// Format hundredths of an hour as a decimal with two places (`150` ->
/// `"1.50"`). Two decimal places, no floating point: the balance rule
/// renders an `icf_hours` mismatch from it.
pub(crate) fn format_hundredths(n: i64) -> String {
    let sign = if n < 0 { "-" } else { "" };
    let Some(n) = n.checked_abs() else {
        return n.to_string();
    };
    format!("{sign}{}.{:02}", n / 100, n % 100)
}

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

/// One person's ledger events, before merge grouping.
#[derive(Clone, Debug, Default)]
pub(crate) struct PersonLedger {
    opens: Vec<OpenEvent>,
    sessions: Vec<SessionEvent>,
}

impl PersonLedger {
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

    /// Total minutes accumulated so far, used for the compiled overflow
    /// check before appending a session.
    fn total_minutes(&self) -> u32 {
        self.minutes_on(NaiveDate::MAX)
    }
}

/// Merge-aware per-person ledger state.
#[derive(Clone, Debug, Default)]
pub(crate) struct LedgerFacts {
    merge: MergeGroups,
    people: HashMap<RecordId, PersonLedger>,
    /// Package ids seen on well-formed `open` lines. The compiled state
    /// carried this set; no rule reads it today, but keeping it preserves
    /// the fold's observable bookkeeping.
    pub(crate) packages: HashSet<RecordId>,
}

impl PackState for LedgerFacts {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl LedgerFacts {
    pub(crate) fn new(merge: MergeGroups) -> Self {
        Self {
            merge,
            people: HashMap::new(),
            packages: HashSet::new(),
        }
    }

    pub(crate) fn canonical_on(&self, id: &RecordId, on: NaiveDate) -> RecordId {
        self.merge.canonical_on(id, on)
    }

    fn ensure_members(&self, on: NaiveDate) {
        self.merge.ensure_members(self.people.keys().cloned(), on);
    }

    fn group_people<'a>(
        &'a self,
        groups: &'a HashMap<RecordId, Vec<RecordId>>,
        id: &RecordId,
        on: NaiveDate,
    ) -> impl Iterator<Item = &'a PersonLedger> {
        let root = self.merge.canonical_on(id, on);
        let members = groups.get(&root).map(Vec::as_slice).unwrap_or(&[]);
        members.iter().filter_map(|pid| self.people.get(pid))
    }

    fn remaining_with(
        &self,
        groups: &HashMap<RecordId, Vec<RecordId>>,
        id: &RecordId,
        on: NaiveDate,
    ) -> i64 {
        let mut total: i64 = 0;
        for person in self.group_people(groups, id, on) {
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

    /// Canonical person ids for `on`, sorted. Caches the merge groups
    /// (idempotent per date).
    pub(crate) fn roots_on(&self, on: NaiveDate) -> Vec<RecordId> {
        self.ensure_members(on);
        let groups = self.merge.groups();
        let groups = groups.get(&on).expect("members cached");
        let mut roots: Vec<_> = groups.keys().cloned().collect();
        roots.sort();
        roots
    }

    pub(crate) fn sessions_remaining_on(&self, id: &RecordId, on: NaiveDate) -> i64 {
        self.ensure_members(on);
        let groups = self.merge.groups();
        self.remaining_with(groups.get(&on).expect("members cached"), id, on)
    }

    pub(crate) fn icf_hours_hundredths_on(&self, id: &RecordId, on: NaiveDate) -> i64 {
        self.ensure_members(on);
        let groups = self.merge.groups();
        let mut minutes: u32 = 0;
        for person in self.group_people(groups.get(&on).expect("members cached"), id, on) {
            minutes = minutes.saturating_add(person.minutes_on(on));
        }
        minutes_to_hundredths(minutes)
    }

    /// Whether anyone in `id`'s merge group has a `pps` session inside the
    /// lookback window ending at `as_of` (inclusive).
    pub(crate) fn pps_in_lookback(
        &self,
        id: &RecordId,
        as_of: NaiveDate,
        window: chrono::Duration,
    ) -> bool {
        self.ensure_members(as_of);
        let groups = self.merge.groups();
        let group = groups.get(&as_of).expect("members cached");
        let any = self
            .group_people(group, id, as_of)
            .any(|person| person.pps_in_lookback(as_of, window));
        any
    }

    /// `id`'s merge group members for `on`, sorted.
    pub(crate) fn group_members(&self, id: &RecordId, on: NaiveDate) -> Vec<RecordId> {
        self.ensure_members(on);
        let groups = self.merge.groups();
        let root = self.merge.canonical_on(id, on);
        groups
            .get(&on)
            .expect("members cached")
            .get(&root)
            .cloned()
            .unwrap_or_default()
    }

    /// The latest open-verb date on or before `on` for `id`'s group.
    pub(crate) fn last_open_on(&self, id: &RecordId, on: NaiveDate) -> Option<NaiveDate> {
        self.ensure_members(on);
        let groups = self.merge.groups();
        self.group_people(groups.get(&on).expect("members cached"), id, on)
            .filter_map(|person| person.last_open_on(on))
            .max()
    }

    /// The latest consuming-verb date on or before `on` for `id`'s group.
    pub(crate) fn last_session_on(&self, id: &RecordId, on: NaiveDate) -> Option<NaiveDate> {
        self.ensure_members(on);
        let groups = self.merge.groups();
        self.group_people(groups.get(&on).expect("members cached"), id, on)
            .filter_map(|person| person.last_session_on(on))
            .max()
    }

    fn person_mut(&mut self, id: &RecordId) -> &mut PersonLedger {
        self.people.entry(id.clone()).or_default()
    }
}

/// The verbs and cap one fold uses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FoldParams<'a> {
    /// The verb that adds units (`open` for coaching).
    pub(crate) open_verb: &'a str,
    /// The verb that consumes a unit (`session` for coaching).
    pub(crate) consume_verb: &'a str,
    /// Per-entry cap on one `open` line.
    pub(crate) max_open_n: i64,
}

/// A fold problem the calling kind renders with its own codes and
/// messages. The entry is carried alongside, so the caller keeps the
/// ledger file, line and entry id.
#[derive(Clone, Debug)]
pub(crate) enum LedgerIssue {
    /// The `open` line is not `package <pkg-id> <N> sessions`.
    OpenShape,
    /// The package id does not parse as a record id.
    OpenInvalidPackageId,
    /// The unit count is not an integer.
    OpenNotInteger,
    /// The package id parses but is not a `pkg-` id (still counted).
    OpenWrongPackageType(RecordId),
    /// The unit count exceeds the fold's cap (not counted).
    OpenExceedsCap(i64),
    /// The person's open total would overflow (not counted).
    OpenTotalOverflow,
    /// A session's minutes would overflow the total (still counted).
    MinutesOverflow,
}

/// The result of one fold: facts plus the problems to render.
pub(crate) struct Folded<'a> {
    pub(crate) facts: LedgerFacts,
    pub(crate) issues: Vec<(&'a SourcedEntry, LedgerIssue)>,
}

/// Fold the vault's opens and consuming entries into per-person facts.
/// Purely descriptive: the caller decides which issues become findings
/// (a pack with no `ledger-balance` rule emits none).
pub(crate) fn fold<'a>(
    vault: &'a Vault,
    merges: &MergeGroups,
    params: FoldParams<'_>,
) -> Folded<'a> {
    let mut facts = LedgerFacts::new(merges.clone());
    let mut issues = Vec::new();

    let mut events: Vec<&'a SourcedEntry> = vault
        .entries
        .iter()
        .filter(|s| s.entry.verb == params.open_verb || s.entry.verb == params.consume_verb)
        .collect();
    // Opens before sessions on the same date (compiled fold order).
    events.sort_by_key(|s| {
        (
            s.entry.date,
            u8::from(s.entry.verb != params.open_verb),
            s.line,
            s.file.clone(),
        )
    });

    for sourced in events {
        let e = &sourced.entry;
        if e.id.prefix() != Prefix::Person {
            continue;
        }
        if e.verb == params.open_verb {
            apply_open(&mut facts, sourced, params.max_open_n, &mut issues);
        } else {
            apply_session(&mut facts, sourced, &mut issues);
        }
    }

    Folded { facts, issues }
}

fn apply_open<'a>(
    facts: &mut LedgerFacts,
    sourced: &'a SourcedEntry,
    max_open_n: i64,
    issues: &mut Vec<(&'a SourcedEntry, LedgerIssue)>,
) {
    let entry = &sourced.entry;
    match parse_open(entry) {
        None => issues.push((sourced, LedgerIssue::OpenShape)),
        Some(Err(OpenIssue::InvalidId)) => {
            issues.push((sourced, LedgerIssue::OpenInvalidPackageId))
        }
        Some(Err(OpenIssue::Malformed)) => issues.push((sourced, LedgerIssue::OpenNotInteger)),
        Some(Ok((pkg, n))) => {
            if pkg.prefix() != Prefix::Package {
                issues.push((sourced, LedgerIssue::OpenWrongPackageType(pkg.clone())));
            }
            if n > max_open_n {
                issues.push((sourced, LedgerIssue::OpenExceedsCap(n)));
                return;
            }
            let person = facts.person_mut(&entry.id);
            let opened: Option<i64> = person
                .opens
                .iter()
                .try_fold(0i64, |acc, o| acc.checked_add(o.n));
            if opened.and_then(|acc| acc.checked_add(n)).is_none() {
                issues.push((sourced, LedgerIssue::OpenTotalOverflow));
                return;
            }
            person.opens.push(OpenEvent {
                date: entry.date,
                n,
            });
            facts.packages.insert(pkg);
        }
    }
}

#[derive(Debug)]
enum OpenIssue {
    InvalidId,
    Malformed,
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
        Err(_) => return Some(Err(OpenIssue::InvalidId)),
    };
    let n: i64 = match tokens[2].parse() {
        Ok(n) if n > 0 => n,
        Ok(_) => return None,
        Err(_) => return Some(Err(OpenIssue::Malformed)),
    };
    Some(Ok((pkg, n)))
}

fn apply_session<'a>(
    facts: &mut LedgerFacts,
    sourced: &'a SourcedEntry,
    issues: &mut Vec<(&'a SourcedEntry, LedgerIssue)>,
) {
    let entry = &sourced.entry;
    let duration = duration_of(entry);
    let paid = entry.has_token("paid");
    let pps = entry.has_token("pps");
    let comp = entry.has_token("comp");
    let tag_count = [paid, pps, comp].into_iter().filter(|tag| *tag).count();
    // `paid` consumes. `pps` and `comp` never do. Untagged still consumes
    // so balances cannot silently drop a session.
    let consumes = paid || tag_count == 0;
    let person = facts.person_mut(&entry.id);
    if let Some(mins) = duration {
        if person.total_minutes().checked_add(mins).is_none() {
            issues.push((sourced, LedgerIssue::MinutesOverflow));
        }
    }
    person.sessions.push(SessionEvent {
        date: entry.date,
        minutes: duration,
        pps,
        consumes,
    });
}

#[cfg(test)]
mod tests {
    use super::{format_hundredths, parse_open};
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

    #[test]
    fn hundredths_format_two_places() {
        assert_eq!(format_hundredths(150), "1.50");
        assert_eq!(format_hundredths(5), "0.05");
        assert_eq!(format_hundredths(-125), "-1.25");
    }
}
