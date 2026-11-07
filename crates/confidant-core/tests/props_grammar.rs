//! Property-based tests for the ledger and record grammars (#886).
//!
//! The serializers are canonical: `parse(format(e)) == e`. These strategies
//! generate well-formed values directly (rather than filtering random text
//! until it parses) so proptest's shrinker can always produce a minimal
//! counterexample. The character sets deliberately include the grammar's
//! punctuation landmines (`:`, `;`, quotes, backslashes, whitespace, and
//! non-ASCII) because quoting is exactly where a serializer stops inverting
//! its parser.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use confidant_core::id::{ulid_from_parts, Prefix, RecordId};
use confidant_core::ledger::{format_entry, parse_line, Arg, LedgerEntry};
use confidant_core::record::{format_record, parse_record, Record, RecordKind};
use proptest::prelude::*;

/// Characters that can appear inside a canonical single-line token without
/// splitting the line. Everything except newlines is fair game; the
/// serializer quotes whitespace, `;`, `:`, and quotes as needed.
fn token_char() -> impl Strategy<Value = char> {
    prop::sample::select(vec![
        'a', 'Z', '0', '7', '-', '_', '.', '/', '#', ':', ';', '"', '\\', ' ', '\t', 'é', '日',
    ])
}

fn token(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(token_char(), 0..=max).prop_map(|chars| chars.into_iter().collect())
}

/// A pair key the parser accepts: lowercase start, then `[a-z0-9_-]`.
fn pair_key() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!['a', 'b', 'z']),
        prop::collection::vec(prop::sample::select(vec!['a', '0', '_', '-']), 0..=8),
    )
        .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
}

fn arg() -> impl Strategy<Value = Arg> {
    prop_oneof![
        token(12).prop_map(Arg::Token),
        (pair_key(), token(12)).prop_map(|(key, value)| Arg::Pair { key, value }),
    ]
}

fn comment_word() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec!['a', 'Z', '0', '-', '_', '#', ':', '/', '.', 'é', '日']),
        1..=8,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Non-empty and with no leading/trailing whitespace: the parser trims a
/// comment, so anything else would not round-trip by construction.
fn comment() -> impl Strategy<Value = String> {
    prop::collection::vec(comment_word(), 1..=4).prop_map(|words| words.join(" "))
}

fn date() -> impl Strategy<Value = NaiveDate> {
    // Day <= 28 keeps every month valid without a rejection filter, which
    // would weaken shrinking.
    (1970i32..2100, 1u32..=12, 1u32..=28).prop_map(|(year, month, day)| {
        NaiveDate::from_ymd_opt(year, month, day).expect("generated day <= 28 is valid")
    })
}

fn prefix() -> impl Strategy<Value = Prefix> {
    prop::sample::select(vec![
        Prefix::Person,
        Prefix::Org,
        Prefix::Deal,
        Prefix::Interaction,
        Prefix::Note,
        Prefix::Edge,
        Prefix::Package,
    ])
}

fn record_id(prefix: Prefix, ulid: u128) -> RecordId {
    RecordId::new(prefix, ulid_from_parts(1_790_812_800_000, ulid))
        .expect("ulid_from_parts is canonical")
}

fn ledger_entry() -> impl Strategy<Value = LedgerEntry> {
    (
        date(),
        pair_key(),
        prefix(),
        any::<u128>(),
        prop::collection::vec(arg(), 0..=6),
        prop::option::of(comment()),
    )
        .prop_map(|(date, verb, prefix, ulid, args, comment)| LedgerEntry {
            date,
            verb,
            id: record_id(prefix, ulid),
            args,
            comment,
        })
}

fn record_kind() -> impl Strategy<Value = (RecordKind, Prefix)> {
    prop::sample::select(vec![
        (RecordKind::Person, Prefix::Person),
        (RecordKind::Org, Prefix::Org),
        (RecordKind::Deal, Prefix::Deal),
        (RecordKind::Interaction, Prefix::Interaction),
        (RecordKind::Note, Prefix::Note),
    ])
}

/// Keys start with `x` so they can never collide with `id`, `type`, `name`,
/// `no-ai`, or a date/ref key with its extra validation. Unknown scalar keys
/// are the forward-compatible part of the format, so they are the interesting
/// ones to round-trip.
fn field_key() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(vec!['a', 'z', '0', '-', '_']), 0..=6)
        .prop_map(|rest| format!("x{}", rest.into_iter().collect::<String>()))
}

fn name() -> impl Strategy<Value = String> {
    prop::collection::vec(comment_word(), 1..=3).prop_map(|words| words.join(" "))
}

/// Empty, or newline-terminated: `format_record` adds the trailing newline
/// for a non-empty body, so this is the shape that survives a round-trip.
fn body() -> impl Strategy<Value = String> {
    prop::collection::vec(comment_word(), 0..=3).prop_map(|words| {
        if words.is_empty() {
            String::new()
        } else {
            format!("{}\n", words.join(" "))
        }
    })
}

fn record() -> impl Strategy<Value = Record> {
    (
        record_kind(),
        any::<u128>(),
        prop::collection::vec((field_key(), token(20)), 0..=4),
        prop::option::of(name()),
        body(),
    )
        .prop_map(|((kind, prefix), ulid, generated, name, body)| {
            let id = record_id(prefix, ulid);
            let mut fields = BTreeMap::new();
            fields.insert("id".to_owned(), id.to_string());
            fields.insert("type".to_owned(), kind.as_str().to_owned());
            for (key, value) in generated {
                fields.insert(key, value);
            }
            if let Some(name) = name {
                fields.insert("name".to_owned(), name);
            }
            let name = fields.get("name").cloned().filter(|s| !s.is_empty());
            let path = format!(
                "{}/{}/profile.md",
                prefix.collection().expect("core kinds have collections"),
                id
            );
            Record {
                id,
                kind,
                path,
                name,
                fields,
                body,
                source: String::new(),
                body_start_line: 1,
                field_lines: BTreeMap::new(),
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    /// `parse_line(format_entry(e)) == e` for generated `DATE VERB ID ARGS`.
    #[test]
    fn ledger_lines_round_trip(entry in ledger_entry()) {
        let text = format_entry(&entry);
        let parsed = parse_line(&text)
            .unwrap_or_else(|err| panic!("canonical line failed to parse: {err:?}\n{text}"))
            .expect("canonical line is not blank");
        prop_assert_eq!(&parsed, &entry, "round-trip failed for {:?}", text);
    }

    /// `parse_record(format_record(e)) == e` for generated front matter and
    /// bodies (comparing every field a parse can derive).
    #[test]
    fn records_round_trip(record in record()) {
        let text = format_record(&record);
        let parsed = parse_record(&text, &record.path)
            .unwrap_or_else(|err| panic!("canonical record failed to parse: {err:?}\n{text}"));
        prop_assert_eq!(&parsed.id, &record.id);
        prop_assert_eq!(parsed.kind, record.kind);
        prop_assert_eq!(&parsed.path, &record.path);
        prop_assert_eq!(&parsed.name, &record.name);
        prop_assert_eq!(&parsed.fields, &record.fields);
        prop_assert_eq!(&parsed.body, &record.body);

        // Re-serializing the parsed record is a fixed point too: a second
        // round-trip must not drift.
        let again = parse_record(&format_record(&parsed), &parsed.path).unwrap();
        prop_assert_eq!(&again.fields, &parsed.fields);
        prop_assert_eq!(&again.body, &parsed.body);
    }
}
