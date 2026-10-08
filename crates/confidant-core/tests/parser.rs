use confidant_core::ledger::{format_entry, parse_ledger, parse_line};
use confidant_core::record::{format_record, parse_record};

#[test]
fn ledger_file_collects_errors_and_entries() {
    let text = "\
; comment
2026-10-01 stage d-01M3TC5H00MPJG00248G000004 proposal
not a line
2026-10-02 alias p-01M3TC5H00MPJG000000000000 email hmac:abcdef12
";
    let (entries, errors) = parse_ledger(text);
    assert_eq!(entries.len(), 2);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].line, 3);
}

#[test]
fn record_round_trip_keeps_optional_fields() {
    let src = "---\n\
id: n-01M3TC5H00MPJG002NAM000005\n\
type: note\n\
person: p-01M3TC5H00MPJG000000000000\n\
date: 2026-10-01\n\
---\n\nHello.\n";
    let rec = parse_record(src, "notes/n-01M3TC5H00MPJG002NAM000005/note.md").unwrap();
    let rec2 = parse_record(&format_record(&rec), &rec.path).unwrap();
    assert_eq!(rec.fields.get("date"), rec2.fields.get("date"));
    assert_eq!(rec.body.trim(), rec2.body.trim());
}

#[test]
fn parse_line_rejects_unclosed_quote() {
    let err = parse_line(r#"2026-10-01 stage d-01M3TC5H00MPJG00248G000004 "won"#).unwrap_err();
    assert!(err.contains("unterminated"), "{err}");
}

#[test]
fn format_then_parse_preserves_pairs() {
    let e = parse_line(
        "2026-10-08 session p-01M3TC5H00MPJG000000000000 45m paid src:transcript/t-01M3TC5H00MPJG0048H0000008",
    )
    .unwrap()
    .unwrap();
    let e2 = parse_line(&format_entry(&e)).unwrap().unwrap();
    assert_eq!(e, e2);
    assert_eq!(
        e.pair("src").unwrap(),
        "transcript/t-01M3TC5H00MPJG0048H0000008"
    );
}
