//! Field grammars: a fixed named list (spec §6, #295 step 3).
//!
//! A manifest *names* a grammar for each front-matter field; Rust supplies
//! the parser. This is a fixed list of named parsers, not a grammar
//! language: adding a grammar is a spec change plus a Rust parser here,
//! never a manifest-only change, so manifests cannot smuggle in new
//! validation semantics.
//!
//! [`KNOWN_GRAMMARS`] is the frozen list the manifest loader validates
//! against; [`parse_field_grammar`] dispatches a name to its parser. A
//! test pins the two together.

use chrono::{Datelike, NaiveDate};

use crate::config::MAX_GAP_DAYS;
use crate::ledger::parse_strict_date;

/// Field grammars a manifest may name (spec §6). Fixed list: adding a
/// grammar is a spec change plus a Rust parser — never a manifest-only
/// change, so manifests cannot smuggle in new validation semantics.
///
/// Use the named constants below at call sites, never string literals:
/// a typo in a literal compiles fine and surfaces only as a field-error
/// finding at runtime.
pub const GRAMMAR_RECURRING_DATE: &str = "recurring-date";
pub const GRAMMAR_CADENCE: &str = "cadence";
pub const GRAMMAR_DATES_LIST: &str = "dates-list";
pub const GRAMMAR_NON_EMPTY_STRING: &str = "non-empty-string";
pub const GRAMMAR_LIST: &str = "list";
pub const GRAMMAR_LABELED_LIST: &str = "labeled-list";
pub const GRAMMAR_DATE: &str = "date";
pub const GRAMMAR_ALIAS_LIST: &str = "alias-list";
pub const GRAMMAR_ROLE_HISTORY: &str = "role-history";
pub const GRAMMAR_PROVENANCE_LIST: &str = "provenance-list";

/// The alias kinds an `alias-list` entry may name.
pub const ALIAS_KINDS: &[&str] = &["email", "phone", "handle", "name"];

/// The statuses an `alias-list` entry may name: the value in use now, or a
/// former value kept for archaeology.
pub const ALIAS_STATUSES: &[&str] = &["current", "historical"];

pub const KNOWN_GRAMMARS: &[&str] = &[
    GRAMMAR_RECURRING_DATE,
    GRAMMAR_CADENCE,
    GRAMMAR_DATES_LIST,
    GRAMMAR_NON_EMPTY_STRING,
    GRAMMAR_LIST,
    GRAMMAR_LABELED_LIST,
    GRAMMAR_DATE,
    GRAMMAR_ALIAS_LIST,
    GRAMMAR_ROLE_HISTORY,
    GRAMMAR_PROVENANCE_LIST,
];

/// A front-matter field value parsed by one of the [`KNOWN_GRAMMARS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    /// `recurring-date`: `YYYY-MM-DD` or `--MM-DD`.
    RecurringDate(RecurringDate),
    /// `cadence`: `<N>d` (`1 <= N <= 3650`) or the literal `never`.
    Cadence(Cadence),
    /// `dates-list`: comma-separated `LABEL:DATE` entries.
    DatesList(Vec<RecurringDate>),
    /// `list`: comma-separated values, whitespace-trimmed, non-empty,
    /// unique.
    List(Vec<String>),
    /// `labeled-list`: comma-separated `LABEL:VALUE` entries.
    LabeledList(Vec<(String, String)>),
    /// `alias-list`: comma-separated `KIND|VALUE|STATUS[|SOURCE]` entries.
    AliasList(Vec<AliasEntry>),
    /// `role-history`: comma-separated `PERIOD|ROLE|COMPANY[|SOURCE]`
    /// entries.
    RoleHistory(Vec<RoleHistoryEntry>),
    /// `provenance-list`: comma-separated `KEY|SOURCE|DATE` entries.
    ProvenanceList(Vec<ProvenanceEntry>),
    /// `date`: one strict `YYYY-MM-DD`.
    Date(NaiveDate),
    /// `non-empty-string`: whitespace-trimmed text.
    Text(String),
}

/// One typed alias (`alias-list`): a contact value, whether it is current
/// or historical, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasEntry {
    /// One of [`ALIAS_KINDS`].
    pub kind: String,
    /// The alias value (an address, number, handle, or former name).
    pub value: String,
    /// One of [`ALIAS_STATUSES`].
    pub status: String,
    /// Optional provenance (`linkedin-export`, `email-signature`, …).
    pub source: Option<String>,
}

/// One fact's provenance (`provenance-list`): which profile fact, where it
/// came from, and the month it was recorded. A repeated key with a newer
/// date supersedes the older entry for context reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceEntry {
    /// The profile fact this entry describes (`title`, `company`, `profile`,
    /// `relationship_context`, …).
    pub key: String,
    /// Where the fact came from (`linkedin-export`, `operator`, …).
    pub source: String,
    /// `YYYY-MM`, month precision.
    pub date: String,
}

/// One role/company chapter (`role-history`): what the person did, where,
/// when, and where the fact came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleHistoryEntry {
    /// `YYYY-YYYY` or `YYYY-` (still current).
    pub period: String,
    /// The role at the time.
    pub role: String,
    /// The company or organization at the time.
    pub company: String,
    /// Optional provenance.
    pub source: Option<String>,
}

/// A `cadence` value (spec §6): a day window, or `never`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cadence {
    /// `<N>d`, `1 <= N <= 3650`.
    Days(u32),
    /// The literal `never`: the person is never overdue.
    Never,
}

/// Parse a front-matter field value with the named grammar.
///
/// `label` is the field name; it becomes [`RecurringDate::label`] for
/// `recurring-date` (the `dates-list` labels come from its entries).
/// Returns `None` for an unknown grammar name or a value the grammar
/// rejects. The manifest loader rejects unknown names at load time, so
/// an unknown name reaching here is belt-and-braces.
pub fn parse_field_grammar(
    grammar: &str,
    label: impl Into<String>,
    raw: &str,
) -> Option<FieldValue> {
    match grammar {
        GRAMMAR_RECURRING_DATE => RecurringDate::parse(label, raw).map(FieldValue::RecurringDate),
        GRAMMAR_CADENCE => parse_cadence(raw).map(FieldValue::Cadence),
        GRAMMAR_DATES_LIST => parse_dates_list(raw).map(FieldValue::DatesList),
        GRAMMAR_LIST => parse_list(raw).map(FieldValue::List),
        GRAMMAR_LABELED_LIST => parse_labeled_list(raw).map(FieldValue::LabeledList),
        GRAMMAR_DATE => parse_date(raw).map(FieldValue::Date),
        GRAMMAR_ALIAS_LIST => parse_alias_list(raw).map(FieldValue::AliasList),
        GRAMMAR_ROLE_HISTORY => parse_role_history(raw).map(FieldValue::RoleHistory),
        GRAMMAR_PROVENANCE_LIST => parse_provenance_list(raw).map(FieldValue::ProvenanceList),
        GRAMMAR_NON_EMPTY_STRING => {
            let trimmed = raw.trim();
            (!trimmed.is_empty()).then(|| FieldValue::Text(trimmed.to_owned()))
        }
        _ => None,
    }
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

/// Parse `cadence` (`<N>d`, where `1 <= N <= 3650`, or the literal `never`).
pub fn parse_cadence(raw: &str) -> Option<Cadence> {
    if raw.trim() == "never" {
        return Some(Cadence::Never);
    }
    parse_cadence_days(raw).map(Cadence::Days)
}

/// Parse the `<N>d` half of `cadence` (`1 <= N <= 3650`).
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

/// Strip one optional `[...]` wrapper, mirroring `dates-list`. Rejects a
/// value with a lone leading `[` or trailing `]`.
fn strip_optional_brackets(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if let Some(stripped) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(stripped.trim())
    } else if trimmed.starts_with('[') || trimmed.ends_with(']') {
        None
    } else {
        Some(trimmed)
    }
}

/// Parse `list`: comma-separated values, optionally wrapped in `[...]`.
/// Entries are whitespace-trimmed, must be non-empty, and must be unique
/// (spec §6). No quoting, so a comma inside an entry is not supported.
pub fn parse_list(raw: &str) -> Option<Vec<String>> {
    let inner = strip_optional_brackets(raw)?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let token = item.trim();
        if token.is_empty() || out.iter().any(|e| e == token) {
            return None;
        }
        out.push(token.to_owned());
    }
    Some(out)
}

/// Parse `labeled-list`: comma-separated `LABEL:VALUE` entries, optionally
/// wrapped in `[...]`. Each entry splits at the **first** `:`; `LABEL`
/// matches `[a-zA-Z0-9_-]+`; `VALUE` is whitespace-trimmed, non-empty, may
/// contain `:` but not a newline; labels must be unique (spec §6).
pub fn parse_labeled_list(raw: &str) -> Option<Vec<(String, String)>> {
    let inner = strip_optional_brackets(raw)?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for item in inner.split(',') {
        let token = item.trim();
        let (label_raw, value_raw) = token.split_once(':')?;
        let label = label_raw.trim();
        if label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
        let value = value_raw.trim();
        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            return None;
        }
        if out.iter().any(|(l, _)| l == label) {
            return None;
        }
        out.push((label.to_owned(), value.to_owned()));
    }
    Some(out)
}

/// Parse `date`: one strict `YYYY-MM-DD` (reused from the ledger parser).
pub fn parse_date(raw: &str) -> Option<NaiveDate> {
    parse_strict_date(raw.trim())
}

/// Parse `dates:` (`[label:DATE, ...]` or `label:DATE, ...`).
pub fn parse_dates_list(raw: &str) -> Option<Vec<RecurringDate>> {
    let inner = strip_optional_brackets(raw)?;
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

/// Split one pipe-separated list entry into 3 or 4 trimmed, non-empty
/// fields. Used by the structured list grammars; a component may not
/// contain `|`, so a wrong field count fails closed (spec §6).
fn split_pipe_fields(token: &str) -> Option<Vec<String>> {
    if token.is_empty() || token.contains('\n') || token.contains('\r') {
        return None;
    }
    let parts: Vec<String> = token.split('|').map(|p| p.trim().to_owned()).collect();
    if !(3..=4).contains(&parts.len()) || parts.iter().any(String::is_empty) {
        return None;
    }
    Some(parts)
}

/// Parse `alias_history:` (`[KIND|VALUE|STATUS|SOURCE, ...]`).
///
/// `KIND` is one of [`ALIAS_KINDS`], `STATUS` one of [`ALIAS_STATUSES`], and
/// `SOURCE` is optional. Entries are comma-separated, optionally wrapped in
/// `[...]`, and a repeated `(KIND, VALUE)` fails closed. `VALUE` is matched
/// case-insensitively by `alias resolve`.
pub fn parse_alias_list(raw: &str) -> Option<Vec<AliasEntry>> {
    let inner = strip_optional_brackets(raw)?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out: Vec<AliasEntry> = Vec::new();
    for item in inner.split(',') {
        let parts = split_pipe_fields(item)?;
        let (kind, value, status) = (parts[0].clone(), parts[1].clone(), parts[2].clone());
        if !ALIAS_KINDS.contains(&kind.as_str()) || !ALIAS_STATUSES.contains(&status.as_str()) {
            return None;
        }
        if out
            .iter()
            .any(|e| e.kind == kind && e.value.eq_ignore_ascii_case(&value))
        {
            return None;
        }
        out.push(AliasEntry {
            kind,
            value,
            status,
            source: parts.get(3).cloned(),
        });
    }
    Some(out)
}

/// Parse `role_history:` (`[PERIOD|ROLE|COMPANY|SOURCE, ...]`).
///
/// `PERIOD` is `YYYY-YYYY` or `YYYY-` (still current). `SOURCE` is optional.
/// Entries are comma-separated, optionally wrapped in `[...]`, and must be
/// unique.
pub fn parse_role_history(raw: &str) -> Option<Vec<RoleHistoryEntry>> {
    let inner = strip_optional_brackets(raw)?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out: Vec<RoleHistoryEntry> = Vec::new();
    for item in inner.split(',') {
        let parts = split_pipe_fields(item)?;
        let (period, role, company) = (parts[0].clone(), parts[1].clone(), parts[2].clone());
        if !is_valid_role_period(&period) {
            return None;
        }
        let entry = RoleHistoryEntry {
            period,
            role,
            company,
            source: parts.get(3).cloned(),
        };
        if out.contains(&entry) {
            return None;
        }
        out.push(entry);
    }
    Some(out)
}

/// Parse `profile_provenance:` (`[KEY|SOURCE|YYYY-MM, ...]`).
///
/// `KEY` matches `[a-z][a-z0-9_]{0,40}` and names the profile fact the entry
/// describes (`profile` for the body, a declared field name otherwise).
/// `SOURCE` is non-empty free text without `|`. The date is `YYYY-MM`; a
/// fact is aged at month precision. A repeated key is allowed and supersedes
/// a newer entry; two entries for the same key and date are rejected so the
/// "newest wins" rule is never a tie.
pub fn parse_provenance_list(raw: &str) -> Option<Vec<ProvenanceEntry>> {
    let inner = strip_optional_brackets(raw)?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out: Vec<ProvenanceEntry> = Vec::new();
    for item in inner.split(',') {
        let parts = split_pipe_fields(item)?;
        if parts.len() != 3 {
            return None;
        }
        let (key, source, date) = (parts[0].clone(), parts[1].clone(), parts[2].clone());
        let mut chars = key.chars();
        let first = chars.next()?;
        if !first.is_ascii_lowercase()
            || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            || key.len() > 41
            || !is_valid_provenance_month(&date)
        {
            return None;
        }
        if out.iter().any(|e| e.key == key && e.date == date) {
            return None;
        }
        out.push(ProvenanceEntry { key, source, date });
    }
    Some(out)
}

/// Whether `date` is a month-precision provenance date (`YYYY-MM`, with a
/// four-digit year in `1000..=2999` and a real month).
fn is_valid_provenance_month(date: &str) -> bool {
    let Some((year, month)) = date.split_once('-') else {
        return false;
    };
    if year.len() != 4
        || !year.bytes().all(|b| b.is_ascii_digit())
        || month.len() != 2
        || !month.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = year.parse::<u32>() else {
        return false;
    };
    let Ok(month) = month.parse::<u32>() else {
        return false;
    };
    (1000..=2999).contains(&year) && (1..=12).contains(&month)
}

/// Whether `period` is `YYYY-YYYY` or `YYYY-` (current), with a sane year
/// range and a start not after the end.
fn is_valid_role_period(period: &str) -> bool {
    let Some((start, end)) = period.split_once('-') else {
        return false;
    };
    let year = |s: &str| -> Option<u32> {
        if s.len() == 4 && s.bytes().all(|b| b.is_ascii_digit()) {
            let year: u32 = s.parse().ok()?;
            (1000..=2999).contains(&year).then_some(year)
        } else {
            None
        }
    };
    let Some(start) = year(start) else {
        return false;
    };
    if end.is_empty() {
        return true;
    }
    let Some(end) = year(end) else {
        return false;
    };
    start <= end
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
    fn cadence_never_parses() {
        assert_eq!(parse_cadence("never"), Some(Cadence::Never));
        assert_eq!(parse_cadence("  never  "), Some(Cadence::Never));
        assert_eq!(parse_cadence("90d"), Some(Cadence::Days(90)));
        // Only the literal `never`; `off`/`0d` stay rejected.
        assert_eq!(parse_cadence("off"), None);
        assert_eq!(parse_cadence("neverr"), None);
        assert_eq!(parse_cadence("NEVER"), None);
    }

    #[test]
    fn cadence_zero_and_over_max_rejected() {
        assert_eq!(parse_cadence("0d"), None);
        assert_eq!(parse_cadence("3651d"), None);
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

    #[test]
    fn list_parser_accepts_plain_and_bracketed() {
        assert_eq!(
            parse_list("[friend, family]"),
            Some(vec!["friend".to_owned(), "family".to_owned()])
        );
        assert_eq!(
            parse_list("friend, family"),
            Some(vec!["friend".to_owned(), "family".to_owned()])
        );
        // Whitespace around entries is trimmed.
        assert_eq!(
            parse_list("  work ,  school "),
            Some(vec!["work".to_owned(), "school".to_owned()])
        );
        // `[]` (and an empty value) is a valid, empty list.
        assert_eq!(parse_list("[]"), Some(Vec::new()));
        assert_eq!(parse_list("  "), Some(Vec::new()));
    }

    #[test]
    fn list_parser_rejects_empty_entry() {
        assert_eq!(parse_list("[a,,b]"), None);
        assert_eq!(parse_list("[a,]"), None);
        assert_eq!(parse_list("[,a]"), None);
        assert_eq!(parse_list("a,,b"), None);
    }

    #[test]
    fn list_parser_rejects_duplicate_entry() {
        assert_eq!(parse_list("[friend, friend]"), None);
        assert_eq!(parse_list("[friend, family, friend]"), None);
    }

    #[test]
    fn list_parser_preserves_order() {
        assert_eq!(
            parse_list("[c, a, b]"),
            Some(vec!["c".to_owned(), "a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn labeled_list_splits_on_first_colon() {
        // The value may contain `:`; only the first `:` is the separator.
        assert_eq!(
            parse_labeled_list("[linkedin:https://example.test/a:b]"),
            Some(vec![(
                "linkedin".to_owned(),
                "https://example.test/a:b".to_owned()
            )])
        );
        assert_eq!(
            parse_labeled_list("site:https://example.test/x, gh:github"),
            Some(vec![
                ("site".to_owned(), "https://example.test/x".to_owned()),
                ("gh".to_owned(), "github".to_owned()),
            ])
        );
        assert_eq!(parse_labeled_list("[]"), Some(Vec::new()));
    }

    #[test]
    fn labeled_list_rejects_bad_label() {
        // No colon at all, and an empty/illegal label.
        assert_eq!(parse_labeled_list("[linkedin]"), None);
        assert_eq!(
            parse_labeled_list("[linkedin:https://example.test,extra]"),
            None
        );
        assert_eq!(parse_labeled_list("[:https://example.test]"), None);
        assert_eq!(parse_labeled_list("[bad label:value]"), None);
        assert_eq!(parse_labeled_list("[bad.label:value]"), None);
    }

    #[test]
    fn labeled_list_rejects_empty_value() {
        assert_eq!(parse_labeled_list("[linkedin:]"), None);
        assert_eq!(parse_labeled_list("[linkedin:   ]"), None);
        assert_eq!(parse_labeled_list("linkedin:"), None);
    }

    #[test]
    fn labeled_list_rejects_comma_in_value() {
        // No quoting: a comma always splits, so the tail has no label.
        assert_eq!(
            parse_labeled_list("[linkedin:https://example.test/a,b]"),
            None
        );
    }

    #[test]
    fn labeled_list_rejects_duplicate_label() {
        assert_eq!(parse_labeled_list("[linkedin:a, linkedin:b]"), None);
    }

    #[test]
    fn date_parser_is_strict() {
        assert_eq!(
            parse_date(" 2026-10-18 "),
            NaiveDate::from_ymd_opt(2026, 10, 18)
        );
        // Not a one-off date: year-less and impossible dates are rejected.
        assert_eq!(parse_date("--10-18"), None);
        assert_eq!(parse_date("2026-02-29"), None);
        assert_eq!(parse_date("2026-13-01"), None);
        assert_eq!(parse_date("2026-10-18extra"), None);
    }

    #[test]
    fn registry_dispatches_each_known_grammar() {
        assert!(matches!(
            parse_field_grammar("recurring-date", "birthday", "1990-05-14"),
            Some(FieldValue::RecurringDate(_))
        ));
        assert!(matches!(
            parse_field_grammar("cadence", "cadence", "30d"),
            Some(FieldValue::Cadence(Cadence::Days(30)))
        ));
        assert!(matches!(
            parse_field_grammar("dates-list", "dates", "[anniversary:2020-06-15]"),
            Some(FieldValue::DatesList(_))
        ));
        assert!(matches!(
            parse_field_grammar("non-empty-string", "relationship_to_me", "  friend  "),
            Some(FieldValue::Text(t)) if t == "friend"
        ));
        assert!(matches!(
            parse_field_grammar("list", "tags", "[friend, family]"),
            Some(FieldValue::List(v)) if v == vec!["friend", "family"]
        ));
        assert!(matches!(
            parse_field_grammar("labeled-list", "links", "[linkedin:https://example.test/a]"),
            Some(FieldValue::LabeledList(v)) if v == vec![("linkedin".to_owned(), "https://example.test/a".to_owned())]
        ));
        assert!(matches!(
            parse_field_grammar("date", "snooze_until", "2026-10-18"),
            Some(FieldValue::Date(d)) if d == NaiveDate::from_ymd_opt(2026, 10, 18).unwrap()
        ));
    }

    #[test]
    fn registry_rejects_bad_values_per_grammar() {
        assert!(parse_field_grammar("recurring-date", "birthday", "--02-30").is_none());
        assert!(parse_field_grammar("cadence", "cadence", "0d").is_none());
        assert!(parse_field_grammar("dates-list", "dates", "[bad]").is_none());
        assert!(parse_field_grammar("non-empty-string", "relationship_to_me", "   ").is_none());
        assert!(parse_field_grammar("list", "tags", "[a,,b]").is_none());
        assert!(parse_field_grammar("labeled-list", "links", "[linkedin]").is_none());
        assert!(parse_field_grammar("date", "snooze_until", "2026-13-01").is_none());
    }

    #[test]
    fn registry_rejects_unknown_grammar_names() {
        assert!(parse_field_grammar("birthday", "birthday", "1990-05-14").is_none());
        assert!(parse_field_grammar("", "birthday", "1990-05-14").is_none());
    }

    #[test]
    fn known_grammars_is_the_frozen_spec_list() {
        // Adding a grammar is a spec change (spec §6); pin the list so it
        // fails loudly here too, not just in the manifest loader. The 0.2
        // spec edit (#509) appended `list`, `labeled-list` and `date`; the
        // 0.4 personal-fields edits (#739, #740) appended the two structured
        // list grammars; #738 appended the provenance list.
        assert_eq!(
            KNOWN_GRAMMARS,
            &[
                "recurring-date",
                "cadence",
                "dates-list",
                "non-empty-string",
                "list",
                "labeled-list",
                "date",
                "alias-list",
                "role-history",
                "provenance-list",
            ]
        );
    }

    #[test]
    fn grammar_constants_match_known_grammars() {
        // Call sites use the constants, not literals; they must stay glued
        // to the frozen list in the same order.
        assert_eq!(
            KNOWN_GRAMMARS,
            &[
                GRAMMAR_RECURRING_DATE,
                GRAMMAR_CADENCE,
                GRAMMAR_DATES_LIST,
                GRAMMAR_NON_EMPTY_STRING,
                GRAMMAR_LIST,
                GRAMMAR_LABELED_LIST,
                GRAMMAR_DATE,
                GRAMMAR_ALIAS_LIST,
                GRAMMAR_ROLE_HISTORY,
                GRAMMAR_PROVENANCE_LIST,
            ]
        );
    }

    #[test]
    fn alias_list_parses_kind_value_status_and_source() {
        let list = parse_alias_list(
            "[email|ada@example.com|current|email-signature, \
             email|ada@old.example|historical|linkedin-export, \
             name|Ada Former|historical]",
        )
        .unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].kind, "email");
        assert_eq!(list[0].value, "ada@example.com");
        assert_eq!(list[0].status, "current");
        assert_eq!(list[0].source.as_deref(), Some("email-signature"));
        assert_eq!(list[2].kind, "name");
        assert_eq!(list[2].source, None);
        assert!(parse_alias_list("[]").unwrap().is_empty());
        assert!(
            parse_field_grammar(GRAMMAR_ALIAS_LIST, "alias_history", "phone|+1555|current")
                .is_some_and(|v| matches!(v, FieldValue::AliasList(_)))
        );
    }

    #[test]
    fn alias_list_rejects_malformed_entries() {
        for bad in [
            // Unknown kind or status.
            "fax|ada@example.com|current",
            "email|ada@example.com|live",
            // Missing fields / empty field.
            "email|ada@example.com",
            "email||current",
            // Too many fields (a `|` inside a value is not supported).
            "email|ada|example|current|source",
            // Repeated (kind, value).
            "[email|ada@example.com|current, email|ADA@EXAMPLE.COM|historical]",
            // A newline can never be part of a list entry.
            "email|ada@example.com|current\nname|x|historical",
        ] {
            assert!(parse_alias_list(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn role_history_parses_period_role_company_and_source() {
        let list = parse_role_history(
            "[2019-2021|Product manager|Example Co|linkedin-export, \
             2021-|Founder|Example Studio]",
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].period, "2019-2021");
        assert_eq!(list[0].role, "Product manager");
        assert_eq!(list[0].company, "Example Co");
        assert_eq!(list[0].source.as_deref(), Some("linkedin-export"));
        assert_eq!(list[1].period, "2021-");
        assert_eq!(list[1].source, None);
        assert!(parse_role_history("[]").unwrap().is_empty());
    }

    #[test]
    fn provenance_list_parses_key_source_and_month() {
        let list = parse_provenance_list(
            "[title|linkedin-export|2026-03, company|linkedin-export|2026-03, profile|operator|2026-10]",
        )
        .unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].key, "title");
        assert_eq!(list[0].source, "linkedin-export");
        assert_eq!(list[0].date, "2026-03");
        assert!(parse_provenance_list("[]").unwrap().is_empty());
        // A repeated key with a newer date is allowed: the newer entry wins.
        let superseding =
            parse_provenance_list("[title|linkedin-export|2025-01, title|operator|2026-03]")
                .unwrap();
        assert_eq!(superseding.len(), 2);
    }

    #[test]
    fn provenance_list_rejects_malformed_entries() {
        for bad in [
            // Wrong field count.
            "title|linkedin-export",
            "title|linkedin-export|2026-03|extra",
            // Bad key shape.
            "Title|linkedin-export|2026-03",
            "1title|linkedin-export|2026-03",
            "pro-file|linkedin-export|2026-03",
            "|linkedin-export|2026-03",
            // Empty source.
            "title||2026-03",
            // Bad date.
            "title|linkedin-export|2026",
            "title|linkedin-export|2026-13",
            "title|linkedin-export|2026-00",
            "title|linkedin-export|26-03",
            // Same key and date is a tie, even with a different source.
            "[title|linkedin-export|2026-03, title|operator|2026-03]",
            // Exact duplicate.
            "[title|linkedin-export|2026-03, title|linkedin-export|2026-03]",
        ] {
            assert!(parse_provenance_list(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn role_history_rejects_malformed_periods_and_entries() {
        for bad in [
            "2019|Product manager|Example Co",
            "2019-202|Product manager|Example Co",
            "2021-2019|Product manager|Example Co",
            "abcd-efgh|Product manager|Example Co",
            "2019-2021||Example Co",
            "2019-2021|Product manager",
            "2019-2021|Product manager|Example Co|linkedin|export",
            "[2019-2021|Product manager|Example Co, 2019-2021|Product manager|Example Co]",
        ] {
            assert!(parse_role_history(bad).is_none(), "{bad:?}");
        }
    }
}
