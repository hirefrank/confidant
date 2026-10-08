//! Check-engine cases: golden JSON, gap-rule edges, malformed input.

use std::fs;
use std::path::{Path, PathBuf};

use confidant_core::check::{CheckOptions, FindingCode, Severity};
use confidant_core::{check_vault, load_vault};
use serde_json::{json, Value};

const ADA: &str = "p-01M3TC5H00MPJG000000000000";
const BEA: &str = "p-01M3TC5H00MPJG000H24000001";
const CAM: &str = "p-01M3TC5H00MPJG001248000002";
const PKG: &str = "pkg-01M3TC5H00MPJG004SK4000009";
const PKG2: &str = "pkg-01M3TC5H00MPJG007ZZ000000E";
const NOTE: &str = "n-01M3TC5H00MPJG002NAM000005";
const ORG: &str = "o-01M3TC5H00MPJG001K6C000003";
const DEAL: &str = "d-01M3TC5H00MPJG00248G000004";
const DEAL2: &str = "d-01M3TC5H00MPJG005VQC00000B";
const NOTE2: &str = "n-01M3TC5H00MPJG00600000000D";
const NOTE3: &str = "n-01M3TC5H00MPJG00800000000F";
const IXN: &str = "i-01M3TC5H00MPJG0048H0000008";
const SHADOW: &str = "p-01M3TC5H00MPJG001K6C00000A";
const GHOST: &str = "p-01M3TC5H00MPJG000H2400000Z";

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn person(root: &Path, id: &str, name: &str) {
    write(
        root,
        &format!("people/{id}/profile.md"),
        &format!("---\nid: {id}\ntype: person\nname: {name}\n---\n\nFake person.\n"),
    );
}

fn note(root: &Path, id: &str, person: &str, date: &str) {
    write(
        root,
        &format!("people/{person}/notes/{id}.md"),
        &format!("---\nid: {id}\ntype: note\nperson: {person}\ndate: {date}\n---\n\nFake note.\n"),
    );
}

fn vault_toml(root: &Path, checks: &str) {
    write(
        root,
        "confidant.toml",
        &format!(
            r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "test-vault"

[checks]
as_of = "2026-10-08"
{checks}
"#
        ),
    );
}

const DEFAULT_CHECKS: &str = r#"coaching.require_duration = "error"
coaching.balance_nonnegative = "error"
coaching.session_notes = "warning"
coaching.paid_session_gap = "warning"
coaching.paid_session_gap_days = 45
coaching.pps_lookback_days = 180
"#;

fn report_json(root: &Path, as_of: Option<&str>) -> Value {
    let vault = load_vault(root).unwrap();
    let as_of = as_of.map(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap());
    let report = check_vault(
        &vault,
        &CheckOptions {
            as_of,
            fail_on: Some(Severity::Warning),
        },
    );
    let mut v = serde_json::to_value(&report).unwrap();
    v.as_object_mut().unwrap().remove("vault");
    v
}

fn codes(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_owned())
        .collect()
}

fn assert_golden(name: &str, actual: &Value) {
    let path = golden_path(name);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        fs::write(&path, serde_json::to_string_pretty(actual).unwrap() + "\n").unwrap();
    }
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing golden {path:?}; run with UPDATE_GOLDEN=1")),
    )
    .unwrap();
    assert_eq!(expected, *actual, "golden mismatch for {name}");
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/golden")
        .join(name)
}

#[test]
fn demo_vault_is_clean() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault");
    let vault = load_vault(&root).unwrap();
    let report = check_vault(&vault, &CheckOptions::default());
    assert!(
        report.ok && report.findings.is_empty(),
        "demo vault findings: {:#?}",
        report.findings
    );
    assert!(report.summary.records >= 8);
}

#[test]
fn balance_mismatch_golden() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
             2026-10-08 balance {ADA} sessions_remaining 4\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_BALANCE_MISMATCH"]);
    assert_golden("balance_mismatch.json", &json);
}

#[test]
fn session_without_notes_golden() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_SESSION_WITHOUT_NOTES"]);
    assert_golden("session_without_notes.json", &json);
}

#[test]
fn same_day_note_covers_session() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid\n\
             2026-10-01 balance {ADA} sessions_remaining 5\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn paid_gap_boundary() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-08-24");
    write(
        dir.path(),
        "ledger/2026/08.cfd",
        &format!(
            "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
             2026-08-24 session {ADA} 60m paid note:{NOTE}\n"
        ),
    );
    // 2026-10-08 minus 45 days = 2026-08-24 (inclusive → clean)
    let json = report_json(dir.path(), Some("2026-10-08"));
    assert!(
        !codes(&json).contains(&"E_PAID_SESSION_GAP".into()),
        "{json}"
    );

    // one day older → gap
    let dir2 = tempfile::tempdir().unwrap();
    vault_toml(dir2.path(), DEFAULT_CHECKS);
    person(dir2.path(), ADA, "Ada Example");
    note(dir2.path(), NOTE, ADA, "2026-08-23");
    write(
        dir2.path(),
        "ledger/2026/08.cfd",
        &format!(
            "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
             2026-08-23 session {ADA} 60m paid note:{NOTE}\n"
        ),
    );
    let json = report_json(dir2.path(), Some("2026-10-08"));
    assert_eq!(codes(&json), vec!["E_PAID_SESSION_GAP"]);
    assert_golden("paid_session_gap.json", &json);
}

#[test]
fn paid_gap_never_started_and_spent() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 open {ADA} package {PKG} 6 sessions\n"),
    );
    let json = report_json(dir.path(), Some("2026-10-08"));
    // Gap clock starts at the most recent open; 7 days is inside the 45-day window.
    assert!(
        !codes(&json).contains(&"E_PAID_SESSION_GAP".into()),
        "{json}"
    );

    // spent: 1 open, 1 session, remaining 0, last session old → not a paid client
    let dir2 = tempfile::tempdir().unwrap();
    vault_toml(dir2.path(), DEFAULT_CHECKS);
    person(dir2.path(), ADA, "Ada Example");
    note(dir2.path(), NOTE, ADA, "2026-01-01");
    write(
        dir2.path(),
        "ledger/2026/01.cfd",
        &format!(
            "2026-01-01 open {ADA} package {PKG} 1 sessions\n\
             2026-01-01 session {ADA} 60m paid note:{NOTE}\n"
        ),
    );
    let json = report_json(dir2.path(), Some("2026-10-08"));
    assert!(
        !codes(&json).contains(&"E_PAID_SESSION_GAP".into()),
        "{json}"
    );
}

#[test]
fn gap_rule_off() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(
        dir.path(),
        r#"coaching.require_duration = "error"
coaching.balance_nonnegative = "error"
coaching.session_notes = "off"
coaching.paid_session_gap = "off"
coaching.paid_session_gap_days = 45
"#,
    );
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn malformed_ledger_and_bad_filename() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "people/not-an-id.md",
        "---\nid: x\ntype: person\n---\n",
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        "this is not an entry\n2026-13-01 session p-01M3TC5H00MPJG000000000000 60m\n",
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.contains(&"E_PARSE".into()), "{c:?}");
    assert!(c.contains(&"E_INVALID_FILENAME".into()), "{c:?}");
}

#[test]
fn alias_plaintext_and_collision() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let bea = "p-01M3TC5H00MPJG000H24000001";
    person(dir.path(), bea, "Bea Demo");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "             2026-10-01 alias {ADA} email not-an-hmac\n\
             2026-10-02 alias {ADA} email hmac:abcdef12abcdef12abcdef12abcdef12\n\
             2026-10-02 alias {bea} email hmac:abcdef12abcdef12abcdef12abcdef12\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.contains(&"E_ALIAS_PLAINTEXT".into()), "{c:?}");
    assert!(c.contains(&"E_ALIAS_COLLISION".into()), "{c:?}");
}

#[test]
fn json_shape_has_stable_keys() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let json = report_json(dir.path(), None);
    assert_eq!(json["spec"], "0.1");
    assert_eq!(json["schema_version"], "1");
    assert_eq!(json["ok"], true);
    assert_eq!(json["summary"]["errors"], 0);
    assert_eq!(json["findings"], json!([]));
}

#[test]
fn finding_code_enum_round_trips_in_json() {
    assert_eq!(FindingCode::BalanceMismatch.as_str(), "E_BALANCE_MISMATCH");
}

#[test]
fn balance_as_of_date_ignores_later_sessions() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
             2026-10-08 balance {ADA} sessions_remaining 5\n\
             2026-10-08 balance {ADA} icf_hours 1.00\n\
             2026-10-15 session {ADA} 60m paid note:{NOTE}\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(
        !codes(&json).contains(&"E_BALANCE_MISMATCH".into()),
        "{json}"
    );
}

#[test]
fn paid_without_package_is_negative_balance() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_NEGATIVE_BALANCE".into()),
        "{json}"
    );
}

#[test]
fn pps_does_not_consume_package() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 session {ADA} 60m pps note:{NOTE}\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(
        !codes(&json).contains(&"E_NEGATIVE_BALANCE".into()),
        "{json}"
    );
}

#[test]
fn pps_client_can_be_flagged_for_gap() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-05-01");
    write(
        dir.path(),
        "ledger/2026/05.cfd",
        &format!("2026-05-01 session {ADA} 60m pps note:{NOTE}\n"),
    );
    // lookback 180: 2026-05-01 is within 180 days of 2026-10-08;
    // gap 45: last session is outside the 45-day window → E_PAID_SESSION_GAP.
    let json = report_json(dir.path(), Some("2026-10-08"));
    assert!(
        codes(&json).contains(&"E_PAID_SESSION_GAP".into()),
        "{json}"
    );
}

#[test]
fn later_merge_does_not_change_earlier_assertions() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let cam = "p-01M3TC5H00MPJG001248000002";
    person(dir.path(), cam, "Cam");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    let cam_note = "n-01M3TC5H000068T0000000000C";
    note(dir.path(), cam_note, cam, "2026-10-07");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
             2026-10-01 open {cam} package {PKG} 4 sessions\n\
             2026-10-07 session {cam} 45m paid note:{cam_note}\n\
             2026-10-08 session {ADA} 45m paid note:{NOTE}\n\
             2026-10-08 balance {ADA} sessions_remaining 4\n\
             2026-10-08 balance {ADA} icf_hours 1.75\n\
             2026-10-12 merge {cam} into {ADA}\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(
        !codes(&json).contains(&"E_BALANCE_MISMATCH".into()),
        "{json}"
    );
}

#[test]
fn note_integrity_runs_when_session_notes_off() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(
        dir.path(),
        r#"coaching.require_duration = "error"
coaching.balance_nonnegative = "off"
coaching.session_notes = "off"
coaching.paid_session_gap = "off"
"#,
    );
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:not-an-id\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn alias_unknown_kind_does_not_echo_raw_token() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 alias {ADA} secret-pii hmac:abcdef12abcdef12abcdef12abcdef12\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_ALIAS_PLAINTEXT".into()), "{json}");
    let messages: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["message"].as_str())
        .collect();
    assert!(
        messages.iter().all(|m| !m.contains("secret-pii")),
        "{messages:?}"
    );
}

#[test]
fn invalid_open_pkg_id_is_e_invalid_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 open {ADA} package not-a-pkg 6 sessions\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn invalid_merge_to_is_e_invalid_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {ADA} into not-an-id\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn leftover_tmp_is_a_finding() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(dir.path(), ".confidant-tmp-deadbeef", "leftover");
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_INVALID_FILENAME".into()),
        "{json}"
    );
}

#[test]
fn malformed_note_date_is_frontmatter() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!("---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-1-1\n---\n\nBad date.\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_FRONTMATTER".into()), "{json}");
}

#[test]
fn no_ai_is_boolean() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada\nno-ai: yes\n---\n\nNope.\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_FRONTMATTER".into()), "{json}");
    let messages: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["message"].as_str())
        .collect();
    assert!(messages.iter().all(|m| !m.contains("yes")), "{messages:?}");
}

#[test]
fn no_ai_people_are_excluded_from_search() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Secret Ada\nno-ai: true\n---\n\nsecret-token\n"
        ),
    );
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!("---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nsecret-token in a note\n"),
    );
    let vault = load_vault(dir.path()).unwrap();
    let hits = confidant_core::search(&vault, "secret-token")
        .expect("search")
        .hits;
    assert!(hits.is_empty(), "{hits:?}");
}

#[test]
fn unparsable_ledger_lines_are_searchable() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        "this-unique-garbage-token is not an entry\n",
    );
    let vault = load_vault(dir.path()).unwrap();
    let hits = confidant_core::search(&vault, "this-unique-garbage-token")
        .expect("search")
        .hits;
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].line, 1);
}

#[test]
fn unsupported_spec_stops_after_spec_findings() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"9.9\"\npacks = [\"nope@1\"]\nvault_id = \"x\"\n",
    );
    person(dir.path(), ADA, "Ada");
    write(dir.path(), "ledger/2026/10.cfd", "this is not an entry\n");
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.contains(&"E_SPEC_UNSUPPORTED".into()), "{c:?}");
    assert!(c.contains(&"E_PACK_UNKNOWN".into()), "{c:?}");
    assert!(!c.contains(&"E_PARSE".into()), "{c:?}");
}

#[test]
fn wrong_id_type_and_invalid_note_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 stage {ADA} proposal\n\
             2026-10-01 session {ADA} 60m paid note:not-an-id\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.contains(&"E_WRONG_ID_TYPE".into()), "{c:?}");
    assert!(c.contains(&"E_INVALID_ID".into()), "{c:?}");
}

#[test]
fn merge_cycle_self_unresolved_and_balances() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let bea = "p-01M3TC5H00MPJG000H24000001";
    person(dir.path(), bea, "Bea");
    let ghost = "p-01M3TC5H00MPJG000H2400000Z";
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {bea} package {PKG} 2 sessions\n\
             2026-10-01 session {bea} 60m paid note:{NOTE}\n\
             2026-10-02 merge {ADA} into {ADA}\n\
             2026-10-03 merge {ghost} into {ADA}\n\
             2026-10-04 merge {ADA} into {bea}\n\
             2026-10-05 merge {bea} into {ADA}\n\
             2026-10-08 balance {bea} sessions_remaining 1\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.contains(&"E_SELF_MERGE".into()), "{c:?}");
    assert!(c.contains(&"E_UNRESOLVED_MERGE".into()), "{c:?}");
    assert!(c.contains(&"E_MERGE_CYCLE".into()), "{c:?}");
}

#[test]
fn merge_fork_duplicate_ulid_and_src() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let bea = "p-01M3TC5H00MPJG000H24000001";
    person(dir.path(), bea, "Bea");
    let org = "o-01M3TC5H00MPJG000000000000";
    write(
        dir.path(),
        &format!("orgs/{org}/org.md"),
        &format!("---\nid: {org}\ntype: org\nname: Dup\n---\n"),
    );
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 merge {bea} into {ADA}\n\
             2026-10-02 merge {bea} into p-01M3TC5H00MPJG001248000002\n\
             2026-10-08 session {ADA} 45m paid note:{NOTE} src:transcript/t-1\n\
             2026-10-08 session {ADA} 45m paid note:{NOTE} src:transcript/t-1\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.contains(&"E_DUPLICATE_ULID".into()), "{c:?}");
    assert!(c.contains(&"E_MERGE_FORK".into()), "{c:?}");
    assert!(c.contains(&"E_DUPLICATE_SRC".into()), "{c:?}");
}

#[test]
fn config_errors_are_e_config() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "x"
[checks]
coaching.session_notes = "warn"
coaching.paid_session_gap_days = -3
typo_key = 1
"#,
    );
    person(dir.path(), ADA, "Ada");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_CONFIG".into()), "{json}");
}

#[cfg(unix)]
#[test]
fn symlinks_at_every_level_are_findings() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    std::os::unix::fs::symlink("/tmp", dir.path().join("people").join("linkdir")).unwrap();
    std::os::unix::fs::symlink(
        "profile.md",
        dir.path().join("people").join(ADA).join(".hidden-link"),
    )
    .unwrap();
    std::os::unix::fs::symlink("x", dir.path().join(".dotlink")).unwrap();
    std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
    std::os::unix::fs::symlink("10.cfd", dir.path().join("ledger/2026/link.cfd")).unwrap();
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.iter().filter(|x| *x == "E_SYMLINK").count() >= 3, "{c:?}");
}

fn search_q(root: &Path, q: &str) -> confidant_core::SearchResult {
    confidant_core::search(&load_vault(root).unwrap(), q).expect("search")
}

fn person_no_ai(root: &Path, id: &str, name: &str) {
    write(
        root,
        &format!("people/{id}/profile.md"),
        &format!("---\nid: {id}\ntype: person\nname: {name}\nno-ai: true\n---\n\nFake person.\n"),
    );
}

fn token_in_hits(result: &confidant_core::SearchResult, token: &str) -> bool {
    result.hits.iter().any(|h| h.excerpt.contains(token))
}

#[test]
fn find_excludes_no_ai_yes_profile() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada\nno-ai: yes\n---\n\nno-ai-yes-token\n"),
    );
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nno-ai-yes-token in a note\n"
        ),
    );
    let result = search_q(dir.path(), "no-ai-yes-token");
    assert!(!token_in_hits(&result, "no-ai-yes-token"), "{result:?}");
}

#[test]
fn find_excludes_duplicate_key_profile() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada\nid: {ADA}\n---\n\ndup-key-token\n"),
    );
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\ndup-key-token in a note\n"
        ),
    );
    let result = search_q(dir.path(), "dup-key-token");
    assert!(!token_in_hits(&result, "dup-key-token"), "{result:?}");
}

#[test]
fn find_excludes_bad_syntax_profile() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nthis is not key value\n---\n\nbad-syntax-token\n"),
    );
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nbad-syntax-token in a note\n"
        ),
    );
    let result = search_q(dir.path(), "bad-syntax-token");
    assert!(!token_in_hits(&result, "bad-syntax-token"), "{result:?}");
}

#[test]
fn find_excludes_unparsable_ledger_mentioning_excluded_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    person(dir.path(), BEA, "Bea");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("not-an-entry unparsed-ledger-token {ADA}\n"),
    );
    let result = search_q(dir.path(), "unparsed-ledger-token");
    assert!(
        !token_in_hits(&result, "unparsed-ledger-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_non_subject_ledger_mentioning_excluded_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    person(dir.path(), BEA, "Bea");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 alias {BEA} email hmac:abcdef12abcdef12abcdef12abcdef12 ; non-subject-token {ADA}\n"
        ),
    );
    let result = search_q(dir.path(), "non-subject-token");
    assert!(!token_in_hits(&result, "non-subject-token"), "{result:?}");
}

#[test]
fn find_excludes_merged_member_of_no_ai_group() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    person(dir.path(), CAM, "Cam");
    write(
        dir.path(),
        &format!("people/{CAM}/profile.md"),
        &format!("---\nid: {CAM}\ntype: person\nname: Cam\n---\n\nmerged-member-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-12 merge {CAM} into {ADA}\n"),
    );
    let result = search_q(dir.path(), "merged-member-token");
    assert!(!token_in_hits(&result, "merged-member-token"), "{result:?}");
}

#[test]
fn find_excludes_interaction_linked_to_excluded_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("interactions/{IXN}/interaction.md"),
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: Call\nperson: {ADA}\n---\n\nixn-secret-token\n"
        ),
    );
    let result = search_q(dir.path(), "ixn-secret-token");
    assert!(!token_in_hits(&result, "ixn-secret-token"), "{result:?}");
}

#[test]
fn find_excludes_deal_linked_to_excluded_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("deals/{DEAL}/deal.md"),
        &format!(
            "---\nid: {DEAL}\ntype: deal\nname: Deal\nperson: {ADA}\n---\n\ndeal-secret-token\n"
        ),
    );
    let result = search_q(dir.path(), "deal-secret-token");
    assert!(!token_in_hits(&result, "deal-secret-token"), "{result:?}");
}

#[test]
fn find_excludes_note_with_no_ai() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\nno-ai: true\n---\n\nnote-no-ai-token\n"
        ),
    );
    let result = search_q(dir.path(), "note-no-ai-token");
    assert!(!token_in_hits(&result, "note-no-ai-token"), "{result:?}");
    let ada = search_q(dir.path(), "Ada Example");
    assert!(token_in_hits(&ada, "Ada Example"), "{ada:?}");
}

#[test]
fn comp_session_does_not_consume_package() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 1 sessions\n\
             2026-10-01 session {ADA} 60m comp note:{NOTE}\n\
             2026-10-01 balance {ADA} sessions_remaining 1\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(
        !codes(&json).contains(&"E_NEGATIVE_BALANCE".into()),
        "{json}"
    );
    assert!(
        !codes(&json).contains(&"E_BALANCE_MISMATCH".into()),
        "{json}"
    );
    assert!(!codes(&json).contains(&"E_SESSION_TAGS".into()), "{json}");
}

#[test]
fn untagged_session_consumes_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m note:{NOTE}\n\
             2026-10-01 balance {ADA} sessions_remaining 5\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["W_SESSION_UNTAGGED"], "{json}");
}

#[test]
fn double_tagged_session_is_e_session_tags() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid pps note:{NOTE}\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_SESSION_TAGS".into()), "{json}");
}

#[test]
fn never_started_package_measured_from_open_date() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/08.cfd",
        &format!("2026-08-01 open {ADA} package {PKG} 6 sessions\n"),
    );
    let json = report_json(dir.path(), Some("2026-10-08"));
    assert_eq!(codes(&json), vec!["E_PAID_SESSION_GAP"], "{json}");
}

#[test]
fn cross_type_merge_is_e_wrong_id_type() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("orgs/{ORG}/org.md"),
        &format!("---\nid: {ORG}\ntype: org\nname: Org\n---\n\nFake org.\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {ADA} into {ORG}\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_WRONG_ID_TYPE".into()), "{json}");
    assert!(
        !codes(&json).contains(&"E_UNRESOLVED_MERGE".into()),
        "{json}"
    );
}

#[test]
fn later_merge_includes_from_history_on_or_after_merge_date() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    person(dir.path(), CAM, "Cam");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    let cam_note = "n-01M3TC5H000068T0000000000C";
    note(dir.path(), cam_note, CAM, "2026-10-07");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
             2026-10-01 open {CAM} package {PKG} 4 sessions\n\
             2026-10-07 session {CAM} 45m paid note:{cam_note}\n\
             2026-10-12 merge {CAM} into {ADA}\n\
             2026-10-12 balance {ADA} sessions_remaining 8\n"
        ),
    );
    let json = report_json(dir.path(), Some("2026-10-12"));
    assert!(
        !codes(&json).contains(&"E_BALANCE_MISMATCH".into()),
        "{json}"
    );
}

#[test]
fn find_json_findings_omit_raw_profile_text() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: unique-fm-secret-token\nno-ai: yes\n---\n\nunique-body-secret\n"
        ),
    );
    let result = search_q(dir.path(), "unique-fm-secret-token");
    let dumped = serde_json::to_string(&result.findings).unwrap();
    assert!(!dumped.contains("unique-fm-secret-token"), "{dumped}");
    assert!(!dumped.contains("unique-body-secret"), "{dumped}");
    assert!(!dumped.contains("yes"), "{dumped}");
    assert!(!dumped.contains(&format!("people/{ADA}")), "{dumped}");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == FindingCode::Frontmatter
                && f.file.is_none()
                && f.line.is_none()
                && f.id.is_none()
                && f.fix.is_none()
                && f.message.contains("items")),
        "{result:?}"
    );
}

#[test]
fn find_excludes_merged_no_ai_deal() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("deals/{DEAL}/deal.md"),
        &format!(
            "---\nid: {DEAL}\ntype: deal\nname: Secret Deal\nno-ai: true\n---\n\nmerged-deal-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("deals/{DEAL2}/deal.md"),
        &format!(
            "---\nid: {DEAL2}\ntype: deal\nname: Other Deal\n---\n\nmerged-deal-partner-token\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {DEAL} into {DEAL2}\n"),
    );
    let a = search_q(dir.path(), "merged-deal-token");
    let b = search_q(dir.path(), "merged-deal-partner-token");
    assert!(!token_in_hits(&a, "merged-deal-token"), "{a:?}");
    assert!(!token_in_hits(&b, "merged-deal-partner-token"), "{b:?}");
}

#[test]
fn find_excludes_merged_no_ai_note() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nno-ai: true\n---\n\nmerged-note-token\n"),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE2}/note.md"),
        &format!("---\nid: {NOTE2}\ntype: note\n---\n\nmerged-note-partner-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {NOTE} into {NOTE2}\n"),
    );
    let a = search_q(dir.path(), "merged-note-token");
    let b = search_q(dir.path(), "merged-note-partner-token");
    assert!(!token_in_hits(&a, "merged-note-token"), "{a:?}");
    assert!(!token_in_hits(&b, "merged-note-partner-token"), "{b:?}");
}

#[test]
fn find_excludes_flat_file_plus_directory_no_ai_shadow() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Flat Ada\nno-ai: true\n---\n\nflat-person-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Dir Ada\n---\n\ndir-person-token\n"),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nunder-dup-token\n"
        ),
    );
    let flat = search_q(dir.path(), "flat-person-token");
    let dir_tok = search_q(dir.path(), "dir-person-token");
    let under = search_q(dir.path(), "under-dup-token");
    assert!(!token_in_hits(&flat, "flat-person-token"), "{flat:?}");
    assert!(!token_in_hits(&dir_tok, "dir-person-token"), "{dir_tok:?}");
    assert!(!token_in_hits(&under, "under-dup-token"), "{under:?}");
}

#[test]
fn find_excludes_mismatched_id_shadowing_real_profile() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nreal-ada-token\n"),
    );
    write(
        dir.path(),
        &format!("people/{SHADOW}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Shadow\n---\n\nshadow-id-token\n"),
    );
    let real = search_q(dir.path(), "real-ada-token");
    let shadow = search_q(dir.path(), "shadow-id-token");
    assert!(!token_in_hits(&real, "real-ada-token"), "{real:?}");
    assert!(!token_in_hits(&shadow, "shadow-id-token"), "{shadow:?}");
}

fn find_excludes_noai_key_typo(key: &str, token: &str) {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada\n{key}: true\n---\n\n{token}\n"),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\n{token} in a note\n"
        ),
    );
    let result = search_q(dir.path(), token);
    assert!(!token_in_hits(&result, token), "{key} {result:?}");
}

#[test]
fn find_excludes_no_ai_pascal_key_typo() {
    find_excludes_noai_key_typo("No-AI", "no-ai-pascal-token");
}

#[test]
fn find_excludes_no_ai_underscore_key_typo() {
    find_excludes_noai_key_typo("no_ai", "no-ai-underscore-token");
}

#[test]
fn find_excludes_noai_compact_key_typo() {
    find_excludes_noai_key_typo("noai", "noai-compact-token");
}

#[test]
fn find_excludes_no_ai_unicode_dash_key_typo() {
    find_excludes_noai_key_typo("no\u{2013}ai", "no-ai-en-dash-token");
}

#[test]
fn find_excludes_obsidian_wikilink_to_uncleared_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\nsee: \"[[{ADA}]]\"\n---\n\nobsidian-bea-token\n"
        ),
    );
    let result = search_q(dir.path(), "obsidian-bea-token");
    assert!(!token_in_hits(&result, "obsidian-bea-token"), "{result:?}");
}

#[test]
fn find_excludes_note_linked_only_by_deal_to_excluded_deal() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("deals/{DEAL}/deal.md"),
        &format!(
            "---\nid: {DEAL}\ntype: deal\nname: Secret\nno-ai: true\n---\n\nexcluded-deal-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\ndeal: {DEAL}\n---\n\ndeal-linked-note-token\n"),
    );
    let result = search_q(dir.path(), "deal-linked-note-token");
    assert!(
        !token_in_hits(&result, "deal-linked-note-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_dangling_person_reference() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {GHOST}\ndate: 2026-10-01\n---\n\ndangling-person-token\n"
        ),
    );
    let result = search_q(dir.path(), "dangling-person-token");
    assert!(
        !token_in_hits(&result, "dangling-person-token"),
        "{result:?}"
    );
}

#[test]
fn find_json_omits_filename_under_excluded_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nhidden-under-person\n"
        ),
    );
    let result = search_q(dir.path(), "hidden-under-person");
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains(NOTE), "{dumped}");
    assert!(!dumped.contains(&format!("people/{ADA}")), "{dumped}");
}

#[test]
fn find_json_findings_omit_excluded_id_on_malformed_ledger_line() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("not-an-entry malformed-ledger-token {ADA}\n"),
    );
    let result = search_q(dir.path(), "malformed-ledger-token");
    assert!(
        !token_in_hits(&result, "malformed-ledger-token"),
        "{result:?}"
    );
    let dumped = serde_json::to_string(&result.findings).unwrap();
    assert!(!dumped.contains(ADA), "{dumped}");
    assert!(!dumped.contains("malformed-ledger-token"), "{dumped}");
}

#[test]
fn returning_client_new_package_resets_gap_clock() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-01-01");
    write(
        dir.path(),
        "ledger/2026/01.cfd",
        &format!(
            "2026-01-01 open {ADA} package {PKG} 6 sessions\n\
             2026-01-01 session {ADA} 60m paid note:{NOTE}\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 open {ADA} package {PKG} 6 sessions\n"),
    );
    let json = report_json(dir.path(), Some("2026-10-08"));
    assert!(
        !codes(&json).contains(&"E_PAID_SESSION_GAP".into()),
        "{json}"
    );
}

#[test]
fn find_json_omits_unparsable_note_outside_people() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        "this is not front matter\nunparsable-outside-people-token\n",
    );
    let result = search_q(dir.path(), "unparsable-outside-people-token");
    assert!(
        !token_in_hits(&result, "unparsable-outside-people-token"),
        "{result:?}"
    );
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains(NOTE), "{dumped}");
    assert!(!dumped.contains(&format!("notes/{NOTE}")), "{dumped}");
    assert!(!dumped.contains("note.md"), "{dumped}");
}

#[test]
fn find_json_omits_non_record_filename() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "zz-hidden-nonrecord-filename.txt",
        "hidden-nonrecord-token\n",
    );
    let result = search_q(dir.path(), "hidden-nonrecord-token");
    assert!(
        !token_in_hits(&result, "hidden-nonrecord-token"),
        "{result:?}"
    );
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(
        !dumped.contains("zz-hidden-nonrecord-filename.txt"),
        "{dumped}"
    );
}

#[test]
fn find_excludes_quoted_double_no_ai_key() {
    find_excludes_noai_key_typo("\"no-ai\"", "quoted-double-no-ai-token");
}

#[test]
fn find_excludes_quoted_single_no_ai_key() {
    find_excludes_noai_key_typo("'no-ai'", "quoted-single-no-ai-token");
}

#[test]
fn find_excludes_nbsp_no_ai_key() {
    find_excludes_noai_key_typo("no\u{00a0}ai", "nbsp-no-ai-token");
}

#[test]
fn find_excludes_zero_width_no_ai_key() {
    find_excludes_noai_key_typo("no\u{200b}ai", "zwsp-no-ai-token");
}

#[test]
fn find_excludes_dotted_no_ai_key() {
    find_excludes_noai_key_typo("no.ai", "dotted-no-ai-token");
}

#[test]
fn find_drops_body_line_with_excluded_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-bea-token\nsee excluded {ADA} dropped-body-line-token\nstill-visible-token\n"
        ),
    );
    let dropped = search_q(dir.path(), "dropped-body-line-token");
    let visible = search_q(dir.path(), "visible-bea-token");
    let still = search_q(dir.path(), "still-visible-token");
    assert!(
        !token_in_hits(&dropped, "dropped-body-line-token"),
        "{dropped:?}"
    );
    assert!(token_in_hits(&visible, "visible-bea-token"), "{visible:?}");
    assert!(token_in_hits(&still, "still-visible-token"), "{still:?}");
}

#[test]
fn find_excludes_line_naming_only_excluded_person_pkg() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    person(dir.path(), BEA, "Bea");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             not-an-entry pkg-only-token {PKG}\n"
        ),
    );
    let result = search_q(dir.path(), "pkg-only-token");
    assert!(!token_in_hits(&result, "pkg-only-token"), "{result:?}");
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains(PKG), "{dumped}");
}

#[test]
fn find_excludes_unopened_pkg() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("not-an-entry unopened-pkg-token {PKG2}\n"),
    );
    let result = search_q(dir.path(), "unopened-pkg-token");
    assert!(!token_in_hits(&result, "unopened-pkg-token"), "{result:?}");
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains(PKG2), "{dumped}");
}

#[test]
fn find_excludes_record_with_malformed_id_typo() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada\nsee: p-01M3TC5H00MPJG00000000000I\n---\n\nmalformed-id-typo-token\n"
        ),
    );
    let result = search_q(dir.path(), "malformed-id-typo-token");
    assert!(
        !token_in_hits(&result, "malformed-id-typo-token"),
        "{result:?}"
    );
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains("01M3TC5H00MPJG00000000000I"), "{dumped}");
}

const TYPO_25: &str = "p-01M3TC5H00MPJG00000000000";

#[test]
fn find_drops_bom_record_body_line_with_excluded_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    let body = format!(
        "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-bom-token\nsee excluded {ADA} dropped-bom-line-token\nstill-bom-token\n"
    );
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("\u{feff}{body}"),
    );
    let dropped = search_q(dir.path(), "dropped-bom-line-token");
    let visible = search_q(dir.path(), "visible-bom-token");
    let still = search_q(dir.path(), "still-bom-token");
    assert!(
        !token_in_hits(&dropped, "dropped-bom-line-token"),
        "{dropped:?}"
    );
    assert!(token_in_hits(&visible, "visible-bom-token"), "{visible:?}");
    assert!(token_in_hits(&still, "still-bom-token"), "{still:?}");
}

#[test]
fn find_excludes_frontmatter_comment_with_hidden_ulid() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n# hidden {ADA}\n---\n\nfm-comment-hidden-token\n"
        ),
    );
    let result = search_q(dir.path(), "fm-comment-hidden-token");
    assert!(
        !token_in_hits(&result, "fm-comment-hidden-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_frontmatter_key_that_is_a_hidden_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n{ADA}: true\n---\n\nfm-key-hidden-token\n"
        ),
    );
    let result = search_q(dir.path(), "fm-key-hidden-token");
    assert!(!token_in_hits(&result, "fm-key-hidden-token"), "{result:?}");
}

#[test]
fn find_excludes_top_level_note_linked_only_by_hidden_session() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nhidden-session-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    let result = search_q(dir.path(), "hidden-session-note-token");
    assert!(
        !token_in_hits(&result, "hidden-session-note-token"),
        "{result:?}"
    );
}

fn find_excludes_note_named_on_ledger_with_hidden_person(line: &str, token: &str) {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\n{token}\n"),
    );
    write(dir.path(), "ledger/2026/10.cfd", &format!("{line}\n"));
    let result = search_q(dir.path(), token);
    assert!(!token_in_hits(&result, token), "{line} {result:?}");
}

#[test]
fn find_excludes_note_named_uppercase_on_unparsed_ledger_line() {
    find_excludes_note_named_on_ledger_with_hidden_person(
        &format!("not-an-entry {ADA} {}", NOTE.to_ascii_uppercase()),
        "uppercase-note-link-token",
    );
}

#[test]
fn find_excludes_note_named_in_wikilink_on_ledger_line() {
    find_excludes_note_named_on_ledger_with_hidden_person(
        &format!("not-an-entry {ADA} [[{NOTE}]]"),
        "wikilink-note-link-token",
    );
}

#[test]
fn find_excludes_note_named_quoted_on_ledger_line() {
    find_excludes_note_named_on_ledger_with_hidden_person(
        &format!("not-an-entry {ADA} \"{NOTE}\""),
        "quoted-note-link-token",
    );
}

#[test]
fn find_excludes_note_named_on_unparsable_ledger_line() {
    find_excludes_note_named_on_ledger_with_hidden_person(
        &format!("not-an-entry {ADA} {NOTE}"),
        "unparsable-note-link-token",
    );
}

#[test]
fn find_keeps_top_level_note_with_no_ledger_mention() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\ncontrol-unlinked-note-token\n"),
    );
    let result = search_q(dir.path(), "control-unlinked-note-token");
    assert!(
        token_in_hits(&result, "control-unlinked-note-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_note_linked_by_cleared_and_hidden_sessions() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    person(dir.path(), BEA, "Bea");
    write(
        dir.path(),
        &format!("notes/{NOTE3}/note.md"),
        &format!("---\nid: {NOTE3}\ntype: note\n---\n\nmixed-session-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 session {ADA} 60m paid note:{NOTE3}\n\
             2026-10-02 session {BEA} 60m paid note:{NOTE3}\n"
        ),
    );
    let result = search_q(dir.path(), "mixed-session-note-token");
    assert!(
        !token_in_hits(&result, "mixed-session-note-token"),
        "{result:?}"
    );
}

fn find_keeps_false_positive_id_shape(phrase: &str, token: &str) {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\n{phrase} {token}\n"),
    );
    let result = search_q(dir.path(), token);
    assert!(token_in_hits(&result, token), "{phrase} {result:?}");
}

#[test]
fn find_keeps_i95_false_positive() {
    find_keeps_false_positive_id_shape("I-95", "i95-false-positive-token");
}

#[test]
fn find_keeps_d_day_false_positive() {
    find_keeps_false_positive_id_shape("D-Day", "dday-false-positive-token");
}

#[test]
fn find_keeps_p_value_false_positive() {
    find_keeps_false_positive_id_shape("P-value", "pvalue-false-positive-token");
}

#[test]
fn find_keeps_o1_false_positive() {
    find_keeps_false_positive_id_shape("O-1", "o1-false-positive-token");
}

#[test]
fn find_keeps_i9_false_positive() {
    find_keeps_false_positive_id_shape("I-9", "i9-false-positive-token");
}

#[test]
fn find_keeps_i140_false_positive() {
    find_keeps_false_positive_id_shape("I-140", "i140-false-positive-token");
}

#[test]
fn find_keeps_n400_false_positive() {
    find_keeps_false_positive_id_shape("N-400", "n400-false-positive-token");
}

#[test]
fn find_keeps_lin_i_chen_false_positive() {
    find_keeps_false_positive_id_shape("Lin I-Chen", "lin-ichen-false-positive-token");
}

#[test]
fn find_keeps_em_dash_i_false_positive() {
    find_keeps_false_positive_id_shape("I\u{2014}I", "emdash-i-false-positive-token");
}

#[test]
fn find_drops_only_body_line_with_25_char_id_typo() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-25-token\nsee {TYPO_25} dropped-25-token\nstill-25-token\n"
        ),
    );
    let dropped = search_q(dir.path(), "dropped-25-token");
    let visible = search_q(dir.path(), "visible-25-token");
    let still = search_q(dir.path(), "still-25-token");
    assert!(!token_in_hits(&dropped, "dropped-25-token"), "{dropped:?}");
    assert!(token_in_hits(&visible, "visible-25-token"), "{visible:?}");
    assert!(token_in_hits(&still, "still-25-token"), "{still:?}");
}

#[test]
fn find_and_check_frontmatter_25_char_id_typo() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada\nsee: {TYPO_25}\n---\n\nfm-25-typo-token\n"
        ),
    );
    let result = search_q(dir.path(), "fm-25-typo-token");
    assert!(!token_in_hits(&result, "fm-25-typo-token"), "{result:?}");
    let dumped = serde_json::to_string(&result.findings).unwrap();
    assert!(!dumped.contains(TYPO_25), "{dumped}");
    assert!(!dumped.contains(&format!("people/{ADA}")), "{dumped}");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == FindingCode::InvalidId && f.file.is_none() && f.id.is_none()),
        "{:?}",
        result.findings
    );

    let json = report_json(dir.path(), None);
    let invalid: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "E_INVALID_ID")
        .collect();
    assert_eq!(invalid.len(), 1, "{json}");
    assert_eq!(invalid[0]["line"], 5);
    let msg = invalid[0]["message"].as_str().unwrap();
    assert!(msg.contains("line 5"), "{msg}");
    assert!(!msg.contains(TYPO_25), "{msg}");
    assert!(!msg.contains("see"), "{msg}");
}

#[test]
fn check_frontmatter_person_25_char_id_typo_names_key() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {TYPO_25}\ndate: 2026-10-01\n---\n\nnote-25-typo-token\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let invalid: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "E_INVALID_ID")
        .collect();
    assert_eq!(invalid.len(), 1, "{json}");
    let msg = invalid[0]["message"].as_str().unwrap();
    assert!(msg.contains("person"), "{msg}");
    assert!(msg.contains("line 4"), "{msg}");
    assert!(!msg.contains(TYPO_25), "{msg}");
    let result = search_q(dir.path(), "note-25-typo-token");
    assert!(!token_in_hits(&result, "note-25-typo-token"), "{result:?}");
}

#[test]
fn find_drops_body_line_with_overlong_ulid_run() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-overlong-token\nsee {ADA}abcdefg dropped-overlong-token\nstill-overlong-token\n"
        ),
    );
    let dropped = search_q(dir.path(), "dropped-overlong-token");
    let visible = search_q(dir.path(), "visible-overlong-token");
    let still = search_q(dir.path(), "still-overlong-token");
    assert!(
        !token_in_hits(&dropped, "dropped-overlong-token"),
        "{dropped:?}"
    );
    assert!(
        token_in_hits(&visible, "visible-overlong-token"),
        "{visible:?}"
    );
    assert!(token_in_hits(&still, "still-overlong-token"), "{still:?}");
}

#[test]
fn find_drops_body_line_with_glued_prefix_excluded_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-glued-token\nsee x{ADA} dropped-glued-token\nstill-glued-token\n"
        ),
    );
    let dropped = search_q(dir.path(), "dropped-glued-token");
    let visible = search_q(dir.path(), "visible-glued-token");
    let still = search_q(dir.path(), "still-glued-token");
    assert!(
        !token_in_hits(&dropped, "dropped-glued-token"),
        "{dropped:?}"
    );
    assert!(
        token_in_hits(&visible, "visible-glued-token"),
        "{visible:?}"
    );
    assert!(token_in_hits(&still, "still-glued-token"), "{still:?}");
}

const NOTION_URL: &str = "https://www.notion.so/Coaching-Plan-0123456789abcdef0123456789abcdef";

#[test]
fn find_keeps_notion_url_in_body() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\n{NOTION_URL} notion-body-token\nKickoff-session-abcdefghijklmnopqrstuvwx kickoff-body-token\n"
        ),
    );
    let notion = search_q(dir.path(), "notion-body-token");
    let kickoff = search_q(dir.path(), "kickoff-body-token");
    assert!(token_in_hits(&notion, "notion-body-token"), "{notion:?}");
    assert!(token_in_hits(&kickoff, "kickoff-body-token"), "{kickoff:?}");
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn find_keeps_notion_url_in_front_matter() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\nsee: {NOTION_URL}\n---\n\nnotion-fm-token\n"
        ),
    );
    let result = search_q(dir.path(), "notion-fm-token");
    assert!(token_in_hits(&result, "notion-fm-token"), "{result:?}");
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn find_keeps_notion_url_in_ledger_src() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 session {ADA} 60m paid note:{NOTE} src:{NOTION_URL}  ; notion-src-token\n"
        ),
    );
    let result = search_q(dir.path(), "notion-src-token");
    assert!(token_in_hits(&result, "notion-src-token"), "{result:?}");
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn find_excludes_lookalike_unicode_dash_note_on_hidden_line() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nunicode-dash-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 session {ADA} 60m paid note:n\u{2010}{}\n",
            &NOTE[2..]
        ),
    );
    let result = search_q(dir.path(), "unicode-dash-note-token");
    assert!(
        !token_in_hits(&result, "unicode-dash-note-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_lookalike_note_v2_on_hidden_line() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nnote-v2-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}v2\n"),
    );
    let result = search_q(dir.path(), "note-v2-token");
    assert!(!token_in_hits(&result, "note-v2-token"), "{result:?}");
}

#[test]
fn find_excludes_note_named_in_misnamed_month_cfd() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nmisnamed-month-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/9.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    let result = search_q(dir.path(), "misnamed-month-note-token");
    assert!(
        !token_in_hits(&result, "misnamed-month-note-token"),
        "{result:?}"
    );
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains("9.cfd"), "{dumped}");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_LEDGER_PATH".into()), "{json}");
}

#[test]
fn find_excludes_note_named_in_nested_ledger_cfd() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nnested-ledger-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/old/09.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    let result = search_q(dir.path(), "nested-ledger-note-token");
    assert!(
        !token_in_hits(&result, "nested-ledger-note-token"),
        "{result:?}"
    );
    let dumped = serde_json::to_string(&result).unwrap();
    assert!(!dumped.contains("old/09.cfd"), "{dumped}");
}

#[test]
fn find_refuses_when_ledger_file_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nunread-toplevel-note-token\n"),
    );
    std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
    std::fs::write(dir.path().join("ledger/2026/08.cfd"), [0xff, 0xfe, 0xfd]).unwrap();
    let err = confidant_core::search(
        &load_vault(dir.path()).unwrap(),
        "unread-toplevel-note-token",
    )
    .expect_err("find refuses");
    assert_eq!(err.code(), "E_LEDGER_UNREADABLE");
    assert_eq!(err.message(), "1 items");
    assert!(err.file().is_none(), "{err:?}");
    assert_eq!(
        err.fix(),
        Some(
            "Fix permissions or replace the unreadable ledger file, then run `confidant check` to locate it"
        )
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_UNREADABLE".into()), "{json}");
    let dumped = json.to_string();
    assert!(dumped.contains("08.cfd"), "{dumped}");
}

#[test]
fn find_excludes_wikilink_merge_into_no_ai() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nwikilink-merge-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {BEA} into [[{ADA}]]\n"),
    );
    let result = search_q(dir.path(), "wikilink-merge-token");
    assert!(
        !token_in_hits(&result, "wikilink-merge-token"),
        "{result:?}"
    );
}

#[test]
fn find_drops_body_line_with_zwsp_in_excluded_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-zwsp-token\nsee p-\u{200b}{} dropped-zwsp-token\nstill-zwsp-token\n",
            &ADA[2..]
        ),
    );
    let dropped = search_q(dir.path(), "dropped-zwsp-token");
    let visible = search_q(dir.path(), "visible-zwsp-token");
    let still = search_q(dir.path(), "still-zwsp-token");
    assert!(
        !token_in_hits(&dropped, "dropped-zwsp-token"),
        "{dropped:?}"
    );
    assert!(token_in_hits(&visible, "visible-zwsp-token"), "{visible:?}");
    assert!(token_in_hits(&still, "still-zwsp-token"), "{still:?}");
}

#[test]
fn find_excludes_person_jane_doe_frontmatter() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: \"Jane Doe\"\n---\n\njane-doe-note-token\n",
    );
    let result = search_q(dir.path(), "jane-doe-note-token");
    assert!(!token_in_hits(&result, "jane-doe-note-token"), "{result:?}");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
    let messages: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["message"].as_str())
        .collect();
    assert!(
        messages.iter().all(|m| !m.contains("Jane Doe")),
        "{messages:?}"
    );
}

fn hidden_note_named_in(root: &Path, ledger_rel: &str) {
    person_no_ai(root, ADA, "Ada");
    write(
        root,
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nhidden-extra-ledger-note-token\n"),
    );
    write(
        root,
        ledger_rel,
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
}

#[test]
fn find_keeps_uppercase_cfd_searchable() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/09.CFD",
        &format!("2026-09-01 session {ADA} 60m paid note:{NOTE}  ; uppercase-cfd-token\n"),
    );
    let result = search_q(dir.path(), "uppercase-cfd-token");
    assert!(token_in_hits(&result, "uppercase-cfd-token"), "{result:?}");
}

#[test]
fn find_excludes_note_named_in_orig_ledger() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    hidden_note_named_in(dir.path(), "ledger/2026/10.cfd.orig");
    let result = search_q(dir.path(), "hidden-extra-ledger-note-token");
    assert!(
        !token_in_hits(&result, "hidden-extra-ledger-note-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_note_named_in_tilde_ledger() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    hidden_note_named_in(dir.path(), "ledger/2026/10.cfd~");
    let result = search_q(dir.path(), "hidden-extra-ledger-note-token");
    assert!(
        !token_in_hits(&result, "hidden-extra-ledger-note-token"),
        "{result:?}"
    );
}

#[test]
fn find_excludes_note_named_in_bak_ledger() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    hidden_note_named_in(dir.path(), "ledger/2026/10.cfd.bak");
    let result = search_q(dir.path(), "hidden-extra-ledger-note-token");
    assert!(
        !token_in_hits(&result, "hidden-extra-ledger-note-token"),
        "{result:?}"
    );
}

#[cfg(unix)]
#[test]
fn find_excludes_note_named_in_in_vault_symlink_file() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nsymlink-file-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/payload.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    std::os::unix::fs::symlink("payload.cfd", dir.path().join("ledger/2026/10.cfd.bak")).unwrap();
    let result = search_q(dir.path(), "symlink-file-note-token");
    assert!(
        !token_in_hits(&result, "symlink-file-note-token"),
        "{result:?}"
    );
}

#[cfg(unix)]
#[test]
fn find_refuses_outside_vault_symlink_file() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
    let outside = dir.path().parent().unwrap().join("outside.cfd");
    std::fs::write(&outside, "2026-10-01 merge p-x into p-y\n").unwrap();
    std::os::unix::fs::symlink(&outside, dir.path().join("ledger/2026/10.cfd.bak")).unwrap();
    let err = confidant_core::search(&load_vault(dir.path()).unwrap(), "Ada Example")
        .expect_err("outside symlink unread");
    assert_eq!(err.code(), "E_LEDGER_UNREADABLE");
}

#[cfg(unix)]
#[test]
fn find_excludes_note_named_in_in_vault_symlink_year_dir() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nsymlink-year-note-token\n"),
    );
    write(
        dir.path(),
        "alt/2026/10.cfd",
        &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    std::fs::create_dir_all(dir.path().join("ledger")).unwrap();
    std::os::unix::fs::symlink("../alt/2026", dir.path().join("ledger/2026")).unwrap();
    let result = search_q(dir.path(), "symlink-year-note-token");
    assert!(
        !token_in_hits(&result, "symlink-year-note-token"),
        "{result:?}"
    );
}

#[cfg(unix)]
#[test]
fn find_refuses_outside_vault_symlink_year_dir() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let outside = dir.path().parent().unwrap().join("outside-year");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("10.cfd"), "x\n").unwrap();
    std::fs::create_dir_all(dir.path().join("ledger")).unwrap();
    std::os::unix::fs::symlink(&outside, dir.path().join("ledger/2026")).unwrap();
    let err = confidant_core::search(&load_vault(dir.path()).unwrap(), "Ada Example")
        .expect_err("outside year unread");
    assert_eq!(err.code(), "E_LEDGER_UNREADABLE");
}

fn merge_hides_bea(root: &Path, line: &str) {
    vault_toml(root, DEFAULT_CHECKS);
    person_no_ai(root, ADA, "Ada");
    write(
        root,
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nundated-merge-token\n"),
    );
    write(root, "ledger/2026/10.cfd", line);
}

#[test]
fn find_joins_merge_with_short_date() {
    let dir = tempfile::tempdir().unwrap();
    merge_hides_bea(dir.path(), &format!("2026-10-3 merge {BEA} into {ADA}\n"));
    let result = search_q(dir.path(), "undated-merge-token");
    assert!(!token_in_hits(&result, "undated-merge-token"), "{result:?}");
}

#[test]
fn find_joins_merge_with_slash_date() {
    let dir = tempfile::tempdir().unwrap();
    merge_hides_bea(dir.path(), &format!("2026/10/03 merge {BEA} into {ADA}\n"));
    let result = search_q(dir.path(), "undated-merge-token");
    assert!(!token_in_hits(&result, "undated-merge-token"), "{result:?}");
}

#[test]
fn find_joins_merge_with_no_date() {
    let dir = tempfile::tempdir().unwrap();
    merge_hides_bea(dir.path(), &format!("merge {BEA} into {ADA}\n"));
    let result = search_q(dir.path(), "undated-merge-token");
    assert!(!token_in_hits(&result, "undated-merge-token"), "{result:?}");
}

#[test]
fn find_joins_merge_with_trailing_colon() {
    let dir = tempfile::tempdir().unwrap();
    merge_hides_bea(dir.path(), &format!("merge: {BEA} into {ADA}\n"));
    let result = search_q(dir.path(), "undated-merge-token");
    assert!(!token_in_hits(&result, "undated-merge-token"), "{result:?}");
}

#[test]
fn find_excludes_soft_hyphen_note_on_hidden_line() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\n---\n\nsoft-hyphen-note-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 session {ADA} 60m paid note:n\u{00ad}{}\n",
            &NOTE[2..]
        ),
    );
    let result = search_q(dir.path(), "soft-hyphen-note-token");
    assert!(
        !token_in_hits(&result, "soft-hyphen-note-token"),
        "{result:?}"
    );
}

#[test]
fn find_keeps_phase_i_32hex_and_page_p_32hex() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    let hex32 = "0123456789abcdef0123456789abcdef";
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nPhase-I-{hex32} phase-i-token\nMy-Page-p-{hex32} page-p-token\n"
        ),
    );
    let a = search_q(dir.path(), "phase-i-token");
    let b = search_q(dir.path(), "page-p-token");
    assert!(token_in_hits(&a, "phase-i-token"), "{a:?}");
    assert!(token_in_hits(&b, "page-p-token"), "{b:?}");
}

#[test]
fn find_keeps_underscore_p_and_dash_n_drive_ids() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nsee _p-1BxiMVs0XRA5nFMdKvBdBZjgmUU underscore-drive-token\nsee -n-1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms dash-n-drive-token\n"
        ),
    );
    let a = search_q(dir.path(), "underscore-drive-token");
    let b = search_q(dir.path(), "dash-n-drive-token");
    assert!(token_in_hits(&a, "underscore-drive-token"), "{a:?}");
    assert!(token_in_hits(&b, "dash-n-drive-token"), "{b:?}");
}

#[test]
fn find_keeps_wikilink_alias_and_tilde_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: \"[[{ADA}|Ada]]\"\n---\n\nwikilink-alias-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE2}/note.md"),
        &format!("---\nid: {NOTE2}\ntype: note\nperson: ~\n---\n\ntilde-person-token\n"),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE3}/note.md"),
        &format!(
            "---\nid: {NOTE3}\ntype: note\nperson: \"{ADA} # comment\"\n---\n\ncomment-person-token\n"
        ),
    );
    let alias = search_q(dir.path(), "wikilink-alias-token");
    let tilde = search_q(dir.path(), "tilde-person-token");
    let comment = search_q(dir.path(), "comment-person-token");
    assert!(token_in_hits(&alias, "wikilink-alias-token"), "{alias:?}");
    assert!(token_in_hits(&tilde, "tilde-person-token"), "{tilde:?}");
    assert!(
        token_in_hits(&comment, "comment-person-token"),
        "{comment:?}"
    );
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn wikilink_and_comment_person_count_for_ownership_and_coverage() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: \"[[{ADA}|Ada]]\"\ndate: 2026-10-01\n---\n\nsession note\n"
        ),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE2}.md"),
        &format!(
            "---\nid: {NOTE2}\ntype: note\nperson: \"{ADA} # comment\"\ndate: 2026-10-02\n---\n\ncoverage note\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 session {ADA} 60m paid note:{NOTE}\n2026-10-02 session {ADA} 60m paid\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(!c.contains(&"E_UNKNOWN_RECORD".into()), "{json}");
    assert!(!c.contains(&"E_SESSION_WITHOUT_NOTES".into()), "{json}");
    assert!(!c.contains(&"E_ID_PATH_MISMATCH".into()), "{json}");
}

#[test]
fn bare_pipe_person_is_invalid_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nperson: {ADA}|Ada\n---\n\nbare-pipe-note-token\n"),
    );
    let result = search_q(dir.path(), "bare-pipe-note-token");
    assert!(
        !token_in_hits(&result, "bare-pipe-note-token"),
        "{result:?}"
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
}

#[test]
fn yaml_null_person_is_not_a_reference() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nperson: null\n---\n\nnull-person-token\n"),
    );
    let result = search_q(dir.path(), "null-person-token");
    assert!(token_in_hits(&result, "null-person-token"), "{result:?}");
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
    assert!(!codes(&json).contains(&"E_DANGLING_REF".into()), "{json}");
}

#[test]
fn find_keeps_docs_and_drive_url_lookalikes() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nsee https://docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit docs-url-token\nsee drive.google.com/file/d/1b3Yf11-n-m7vpfukD0SPao3NxJ7dDYgq/view drive-url-token\n"
        ),
    );
    let a = search_q(dir.path(), "docs-url-token");
    let b = search_q(dir.path(), "drive-url-token");
    assert!(token_in_hits(&a, "docs-url-token"), "{a:?}");
    assert!(token_in_hits(&b, "drive-url-token"), "{b:?}");
}

#[test]
fn find_drops_line_when_hidden_person_id_is_inside_url() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nvisible-drive-hidden-token\nsee https://drive.google.com/file/d/{ADA}/view dropped-drive-hidden-token\nstill-drive-hidden-token\n"
        ),
    );
    let dropped = search_q(dir.path(), "dropped-drive-hidden-token");
    let visible = search_q(dir.path(), "visible-drive-hidden-token");
    let still = search_q(dir.path(), "still-drive-hidden-token");
    assert!(
        !token_in_hits(&dropped, "dropped-drive-hidden-token"),
        "{dropped:?}"
    );
    assert!(
        token_in_hits(&visible, "visible-drive-hidden-token"),
        "{visible:?}"
    );
    assert!(
        token_in_hits(&still, "still-drive-hidden-token"),
        "{still:?}"
    );
}

#[test]
fn find_excludes_bulleted_merge_into_no_ai() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nbulleted-merge-token\n"),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("- 2026-10-01 merge {BEA} into {ADA}\n"),
    );
    let result = search_q(dir.path(), "bulleted-merge-token");
    assert!(
        !token_in_hits(&result, "bulleted-merge-token"),
        "{result:?}"
    );
}

#[test]
fn find_keeps_person_when_misfiled_note_has_path_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nada-profile-token\n"),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nada-ok-note-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE2}.md"),
        &format!(
            "---\nid: {NOTE2}\ntype: note\nperson: {BEA}\ndate: 2026-10-02\n---\n\nmisfiled-note-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nbea-profile-token\n"),
    );
    let profile = search_q(dir.path(), "ada-profile-token");
    let ok_note = search_q(dir.path(), "ada-ok-note-token");
    let misfiled = search_q(dir.path(), "misfiled-note-token");
    let bea = search_q(dir.path(), "bea-profile-token");
    assert!(token_in_hits(&profile, "ada-profile-token"), "{profile:?}");
    assert!(token_in_hits(&ok_note, "ada-ok-note-token"), "{ok_note:?}");
    assert!(
        !token_in_hits(&misfiled, "misfiled-note-token"),
        "{misfiled:?}"
    );
    assert!(token_in_hits(&bea, "bea-profile-token"), "{bea:?}");
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_ID_PATH_MISMATCH".into()),
        "{json}"
    );
}
