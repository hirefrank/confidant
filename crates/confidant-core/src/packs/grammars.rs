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

pub const KNOWN_GRAMMARS: &[&str] = &[
    GRAMMAR_RECURRING_DATE,
    GRAMMAR_CADENCE,
    GRAMMAR_DATES_LIST,
    GRAMMAR_NON_EMPTY_STRING,
    GRAMMAR_LIST,
    GRAMMAR_LABELED_LIST,
    GRAMMAR_DATE,
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
    /// `date`: one strict `YYYY-MM-DD`.
    Date(NaiveDate),
    /// `non-empty-string`: whitespace-trimmed text.
    Text(String),
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
        // spec edit (#509) appended `list`, `labeled-list` and `date`.
        assert_eq!(
            KNOWN_GRAMMARS,
            &[
                "recurring-date",
                "cadence",
                "dates-list",
                "non-empty-string",
                "list",
                "labeled-list",
                "date"
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
            ]
        );
    }
}
