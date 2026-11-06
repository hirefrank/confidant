use confidant_core::ledger::{
    format_entry, line_fingerprint, line_ref, parse_ledger, parse_line, parse_retract,
    RetractParse, RetractReason,
};
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

/// #746: the line fingerprint is part of the format contract. These vectors
/// are pinned so a `format_entry` change fails CI before it breaks vaults.
#[test]
fn ledger_line_fingerprints_are_pinned() {
    let vectors = [
        (
            "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call",
            "87d93568b0d238e8e63086bdf1703f496a2824bc829655b1238332f31c8016c7",
        ),
        (
            "2026-10-08 touch p-01M3TC5H00MPJG000H24000001 call",
            "2642a35021892041b6260e563e0b384074abeb98cbe2f18fee50c4fe25cfe637",
        ),
        (
            "2026-10-09 stage d-01M3TC5H00MPJG00248G000004 proposal",
            "6e55eaa4233f86ce6a1af9ab6fd93106f3018911a1b290089c7ee0798dc06a51",
        ),
    ];
    for (line, expected) in vectors {
        let entry = parse_line(line).unwrap().unwrap();
        let hex: String = line_fingerprint(&entry)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, expected, "{line}");
        assert_eq!(line_ref(&entry, 1).to_string(), format!("line:{expected}"));
        assert_eq!(
            line_ref(&entry, 2).to_string(),
            format!("line:{expected}#2")
        );
    }
}

#[test]
fn parse_retract_accepts_the_closed_grammar() {
    let hash = "87d93568b0d238e8e63086bdf1703f496a2824bc829655b1238332f31c8016c7";
    let entry = parse_line(&format!(
        "2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:{hash} occurrence:2 reason:duplicate"
    ))
    .unwrap()
    .unwrap();
    let RetractParse::Ok(spec) = parse_retract(&entry) else {
        panic!("expected a valid retraction");
    };
    assert_eq!(spec.reason, RetractReason::Duplicate);
    assert_eq!(spec.target.occurrence(), 2);
    assert!(spec.replacement.is_none());

    let with_replace = parse_line(&format!(
        "2026-11-02 retract p-01M3TC5H00MPJG000H24000001 line:{hash} reason:wrong-kind replace:{hash}"
    ))
    .unwrap()
    .unwrap();
    let RetractParse::Ok(spec) = parse_retract(&with_replace) else {
        panic!("expected a valid replacement");
    };
    assert_eq!(spec.reason, RetractReason::WrongKind);
    assert_eq!(spec.replacement.unwrap().occurrence(), 1);
}

#[test]
fn parse_retract_rejects_open_grammar() {
    let hash = "87d93568b0d238e8e63086bdf1703f496a2824bc829655b1238332f31c8016c7";
    for line in [
        format!("2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:{hash} reason:duplicate extra:1"),
        format!("2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:{hash} reason:Duplicate"),
        format!("2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:{hash} reason:duplicate occurrence:0"),
        "2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:nothex reason:duplicate".to_owned(),
        "2026-11-02 retract p-01M3TC5H00MPJG000000000000 reason:duplicate".to_owned(),
        "2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:87D93568B0D238E8E63086BDF1703F496A2824BC829655B1238332F31C8016C7 reason:duplicate".to_owned(),
    ] {
        let entry = parse_line(&line).unwrap().unwrap();
        assert!(
            matches!(parse_retract(&entry), RetractParse::Malformed),
            "{line}"
        );
    }
}

#[test]
fn parse_retract_round_trips_through_format_entry() {
    let entry = parse_line(
        "2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:87d93568b0d238e8e63086bdf1703f496a2824bc829655b1238332f31c8016c7 reason:duplicate",
    )
    .unwrap()
    .unwrap();
    let again = parse_line(&format_entry(&entry)).unwrap().unwrap();
    assert_eq!(entry, again);
}
