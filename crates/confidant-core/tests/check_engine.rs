//! Check-engine cases: golden JSON, gap-rule edges, malformed input.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod common;

use common::{install_shipped_coaching, shipped_coaching_dir};
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
const CAM_NOTE: &str = "n-01M3TC5H000068T0000000000C";

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

/// A vault enabling the shipped `coaching@0.1` external pack. Every test
/// that checks coaching behaviour vendors the pack: the compiled path is
/// gone (#449), so a listed pack without bytes is `E_PACK_UNKNOWN`.
fn vault_toml(root: &Path, checks: &str) {
    install_shipped_coaching(root);
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
            pinned_inbox_pubkey: None,
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

fn finding_by_code<'a>(v: &'a Value, code: &str) -> &'a Value {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == code)
        .unwrap_or_else(|| panic!("expected {code} finding in {v}"))
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

/// The `balance_mismatch` golden vault's records and ledger, shared by the
/// golden test and the #449 fixture parity test.
fn balance_mismatch_vault(root: &Path) {
    person(root, ADA, "Ada Example");
    note(root, NOTE, ADA, "2026-10-01");
    write(
        root,
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
             2026-10-08 balance {ADA} sessions_remaining 4\n"
        ),
    );
}

#[test]
fn balance_mismatch_golden() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    balance_mismatch_vault(dir.path());
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_COACHING_BALANCE_MISMATCH"]);
    assert_golden("balance_mismatch.json", &json);
}

/// The `session_without_notes` golden vault's records and ledger (shared
/// with the #449 fixture parity test).
fn session_without_notes_vault(root: &Path) {
    person(root, ADA, "Ada Example");
    write(
        root,
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
             2026-10-01 session {ADA} 60m paid\n"
        ),
    );
}

#[test]
fn session_without_notes_golden() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    session_without_notes_vault(dir.path());
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_COACHING_SESSION_WITHOUT_NOTES"]);
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
        !codes(&json).contains(&"E_COACHING_PAID_SESSION_GAP".into()),
        "{json}"
    );

    // one day older → gap
    let dir2 = tempfile::tempdir().unwrap();
    vault_toml(dir2.path(), DEFAULT_CHECKS);
    paid_session_gap_vault(dir2.path());
    let json = report_json(dir2.path(), Some("2026-10-08"));
    assert_eq!(codes(&json), vec!["E_COACHING_PAID_SESSION_GAP"]);
    assert_golden("paid_session_gap.json", &json);
}

/// The `paid_session_gap` golden vault's records and ledger: one day past
/// the 45-day window (shared with the #449 fixture parity test).
fn paid_session_gap_vault(root: &Path) {
    person(root, ADA, "Ada Example");
    note(root, NOTE, ADA, "2026-08-23");
    write(
        root,
        "ledger/2026/08.cfd",
        &format!(
            "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
             2026-08-23 session {ADA} 60m paid note:{NOTE}\n"
        ),
    );
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
        !codes(&json).contains(&"E_COACHING_PAID_SESSION_GAP".into()),
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
        !codes(&json).contains(&"E_COACHING_PAID_SESSION_GAP".into()),
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
        !codes(&json).contains(&"E_COACHING_BALANCE_MISMATCH".into()),
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
        codes(&json).contains(&"E_COACHING_NEGATIVE_BALANCE".into()),
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
        !codes(&json).contains(&"E_COACHING_NEGATIVE_BALANCE".into()),
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
    // gap 45: last session is outside the 45-day window → E_COACHING_PAID_SESSION_GAP.
    let json = report_json(dir.path(), Some("2026-10-08"));
    assert!(
        codes(&json).contains(&"E_COACHING_PAID_SESSION_GAP".into()),
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
        !codes(&json).contains(&"E_COACHING_BALANCE_MISMATCH".into()),
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
    assert!(
        codes(&json).contains(&"E_COACHING_NOTE_INVALID_ID".into()),
        "{json}"
    );
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
fn invalid_open_pkg_id_is_a_pack_code() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 open {ADA} package not-a-pkg 6 sessions\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_COACHING_INVALID_ID".into()),
        "{json}"
    );
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
    let hits = confidant_core::search(&vault, "secret-token", &confidant_core::PackScope::All)
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
    let hits = confidant_core::search(
        &vault,
        "this-unique-garbage-token",
        &confidant_core::PackScope::All,
    )
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
    // #497: external packs are not resolved on an unsupported spec, so the
    // compiled-only registry must not report the listed pack as unknown.
    assert!(!c.contains(&"E_PACK_UNKNOWN".into()), "{c:?}");
    assert!(!c.contains(&"E_PARSE".into()), "{c:?}");
}

/// #497: an unsupported spec skips external-pack resolution entirely, so a
/// listed external must not surface as `E_PACK_UNKNOWN` (or as any other
/// pack finding) — the spec finding already fails `check`. Even a fully
/// installed, hash-valid external pack stays unreported.
#[test]
fn unsupported_spec_does_not_report_listed_externals_as_unknown() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-05 greet {ADA} kind:wave\n"),
    );
    let hash = install_external_pack(dir.path(), "example-pack", "0.1", "greet");
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"9.9\"\npacks = [\"coaching@0.1\", \"example-pack@0.1\"]\nvault_id = \"x\"\n",
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert_eq!(c, vec!["E_SPEC_UNSUPPORTED".to_string()], "{json}");
    for code in [
        "E_PACK_UNKNOWN",
        "E_PACK_HASH",
        "E_PACK_INVALID",
        "E_UNKNOWN_VERB",
    ] {
        assert!(!c.contains(&code.to_string()), "{code} in {json}");
    }
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
    assert!(c.contains(&"E_COACHING_NOTE_INVALID_ID".into()), "{c:?}");
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
    confidant_core::search(
        &load_vault(root).unwrap(),
        q,
        &confidant_core::PackScope::All,
    )
    .expect("search")
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
fn find_drops_no_ai_id_split_by_unassigned_ignorables() {
    // #115 must-fix: the unassigned Default_Ignorable ranges (U+2065,
    // U+FFF0–FFF8, U+E0000, U+E0002–E001F, U+E0080–E00FF, U+E01F0–E0FFF)
    // are stripped before scanning. A no-ai person's ID glued with one of
    // them mid-ULID is still recognized as that person's ID, so a line
    // naming them stays out of `find` instead of leaking past the no-ai
    // exclusion. (The note belongs to an ordinary person so it stays
    // cleared; only the glued-ID line is dropped.)
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), ADA, "Ada");
    person(dir.path(), BEA, "Bea Example");
    let ulid = &ADA["p-".len()..];
    let (head, tail) = ulid.split_at(10);
    let mut body = String::new();
    for (lo, hi) in [(0x2060u32, 0x206Fu32), (0xFFF0, 0xFFFB), (0xE0000, 0xE0FFF)] {
        for cp in lo..=hi {
            let ch = char::from_u32(cp).expect("valid scalar value");
            body.push_str(&format!("see p-{head}{ch}{tail} token\n"));
        }
    }
    write(
        dir.path(),
        &format!("people/{BEA}/notes/{NOTE}.md"),
        &format!("---\nid: {NOTE}\ntype: note\nperson: {BEA}\ndate: 2026-10-01\n---\n\n{body}"),
    );
    let result = search_q(dir.path(), "token");
    assert!(
        result.hits.is_empty(),
        "glued no-ai ID lines must be dropped from find, got: {:?}",
        result.hits.iter().map(|h| &h.excerpt).collect::<Vec<_>>()
    );
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
        !codes(&json).contains(&"E_COACHING_NEGATIVE_BALANCE".into()),
        "{json}"
    );
    assert!(
        !codes(&json).contains(&"E_COACHING_BALANCE_MISMATCH".into()),
        "{json}"
    );
    assert!(
        !codes(&json).contains(&"E_COACHING_SESSION_TAGS".into()),
        "{json}"
    );
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
    assert_eq!(codes(&json), vec!["W_COACHING_SESSION_UNTAGGED"], "{json}");
}

// Issue #181 Q3: agent-facing findings must never surface a no-ai person's
// name (or other PII) — suppress the warning or reduce it to code + count.
#[test]
fn findings_never_name_no_ai_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    // Distinctive fake name: must not appear anywhere in the report.
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: \"Zephyr Hiddenperson\"\nno-ai: true\n---\n\nFake person.\n",
    );
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
    assert!(
        codes(&json).contains(&"W_COACHING_SESSION_UNTAGGED".to_string()),
        "{json}"
    );
    let text = serde_json::to_string(&json).unwrap();
    assert!(
        !text.contains("Zephyr"),
        "no-ai person's name leaked into findings: {text}"
    );
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
    assert!(
        codes(&json).contains(&"E_COACHING_SESSION_TAGS".into()),
        "{json}"
    );
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
    assert_eq!(codes(&json), vec!["E_COACHING_PAID_SESSION_GAP"], "{json}");
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
        !codes(&json).contains(&"E_COACHING_BALANCE_MISMATCH".into()),
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

/// Marker note + deep unexpected dir, checked for one location. Without
/// the deep file the marker line is searchable (control); once a file
/// whose name carries CAM's bare ULID lands in the unexpected dir, the
/// path seed drops the line. Fails if the seed walk skips collection
/// subtrees that scan_collections never lists (#116 hold).
fn deep_seed_location(dir: &Path, deep_rel: &str, token: &str) {
    vault_toml(dir, DEFAULT_CHECKS);
    person(dir, ADA, "Ada Example");
    person(dir, CAM, "Cam Example");
    write(
        dir,
        &format!("notes/{NOTE2}/note.md"),
        &format!(
            "---\nid: {NOTE2}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\n{token} bare {} here\n",
            &CAM[2..]
        ),
    );
    // Control: no deep file yet, the cleared note's line is searchable.
    let result = search_q(dir, token);
    assert!(token_in_hits(&result, token), "{result:?}");
    // The deep file's name seeds CAM's ULID for bare-window matching.
    write(dir, deep_rel, "fake deep file\n");
    let result = search_q(dir, token);
    assert!(!token_in_hits(&result, token), "{result:?}");
    let json = report_json(dir, None);
    assert!(
        codes(&json).contains(&"E_INVALID_FILENAME".into()),
        "unexpected dir must still be flagged: {json}"
    );
}

#[test]
fn find_drops_line_seeded_from_deep_extra_dir() {
    let dir = tempfile::tempdir().unwrap();
    deep_seed_location(
        dir.path(),
        "people/p-01M3TC5H00MPJG001248000002/extra/deep/x01M3TC5H00MPJG001248000002.txt",
        "extra-deep-token",
    );
}

#[test]
fn find_drops_line_seeded_from_notes_sub_dir() {
    let dir = tempfile::tempdir().unwrap();
    deep_seed_location(
        dir.path(),
        "people/p-01M3TC5H00MPJG001248000002/notes/sub/x01M3TC5H00MPJG001248000002.txt",
        "notes-sub-token",
    );
}

#[test]
fn find_drops_line_seeded_from_interactions_junk_dir() {
    let dir = tempfile::tempdir().unwrap();
    deep_seed_location(
        dir.path(),
        "interactions/zz/x/x01M3TC5H00MPJG001248000002.txt",
        "junk-dir-token",
    );
}

#[test]
fn find_drops_line_seeded_from_deep_dangling_name() {
    // Parity: a deep filename carrying a dangling (record-less) ULID
    // seeds bare-window matching the same way — the line is dropped.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    person(dir.path(), CAM, "Cam Example");
    write(
        dir.path(),
        &format!("notes/{NOTE2}/note.md"),
        &format!(
            "---\nid: {NOTE2}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\ndangling-deep-token bare {} here\n",
            &GHOST[2..]
        ),
    );
    let result = search_q(dir.path(), "dangling-deep-token");
    assert!(token_in_hits(&result, "dangling-deep-token"), "{result:?}");
    write(
        dir.path(),
        &format!("people/{CAM}/extra/deep/x{}.txt", &GHOST[2..]),
        "fake deep file\n",
    );
    let result = search_q(dir.path(), "dangling-deep-token");
    assert!(!token_in_hits(&result, "dangling-deep-token"), "{result:?}");
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
        !codes(&json).contains(&"E_COACHING_PAID_SESSION_GAP".into()),
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
        &confidant_core::PackScope::All,
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
    let err = confidant_core::search(
        &load_vault(dir.path()).unwrap(),
        "Ada Example",
        &confidant_core::PackScope::All,
    )
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
    let err = confidant_core::search(
        &load_vault(dir.path()).unwrap(),
        "Ada Example",
        &confidant_core::PackScope::All,
    )
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
    assert!(
        !c.contains(&"E_COACHING_SESSION_WITHOUT_NOTES".into()),
        "{json}"
    );
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

fn finding_messages(v: &Value, code: &str) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == code)
        .map(|f| f["message"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn capitalised_person_key_with_name_is_invalid_id() {
    // #5: `Person: Ada Example` is a reference under identical rules — a
    // name value is E_INVALID_ID (naming the key as written) and the note
    // stays out of find.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nPerson: Ada Example\ndate: 2026-10-01\n---\n\ncapitalised-person-token\n"),
    );
    let result = search_q(dir.path(), "capitalised-person-token");
    assert!(
        !token_in_hits(&result, "capitalised-person-token"),
        "{result:?}"
    );
    let json = report_json(dir.path(), None);
    let msgs = finding_messages(&json, "E_INVALID_ID");
    assert!(
        msgs.iter().any(|m| m.contains("'Person'")),
        "expected the key named as written: {json}"
    );
}

#[test]
fn capitalised_person_key_with_id_links() {
    // #5: `Person: <id>` is a clean link — searchable, no findings.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nPerson: {ADA}\ndate: 2026-10-01\n---\n\nlinked-capitalised-token\n"),
    );
    let result = search_q(dir.path(), "linked-capitalised-token");
    assert!(
        token_in_hits(&result, "linked-capitalised-token"),
        "{result:?}"
    );
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
    assert!(!codes(&json).contains(&"E_DANGLING_REF".into()), "{json}");
}

#[test]
fn alias_client_key_is_still_ignored() {
    // #5: `client:` is not a spec key, so it is not a reference even when
    // it holds a name — no E_INVALID_ID, note stays searchable.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nclient: Ada Example\ndate: 2026-10-01\n---\n\nalias-client-token\n"),
    );
    let result = search_q(dir.path(), "alias-client-token");
    assert!(token_in_hits(&result, "alias-client-token"), "{result:?}");
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
    assert!(!codes(&json).contains(&"E_DANGLING_REF".into()), "{json}");
}

#[test]
fn dangling_capitalised_org_is_dangling_ref() {
    // #5: `Org: <missing>` is E_DANGLING_REF, naming the key as written.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nOrg: {GHOST}\ndate: 2026-10-01\n---\n\ndangling-org-token\n"),
    );
    let json = report_json(dir.path(), None);
    let msgs = finding_messages(&json, "E_DANGLING_REF");
    assert!(
        msgs.iter().any(|m| m.contains("'Org'")),
        "expected the key named as written: {json}"
    );
}

#[test]
fn malformed_id_on_capitalised_key_names_the_key() {
    // #5: a malformed token on a `Person:` line is E_INVALID_ID with the
    // key name (a variant key is a known ref key), and the note is uncleared.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!("---\nid: {NOTE}\ntype: note\nPerson: p-01M3TC5H00MPJG0000000\ndate: 2026-10-01\n---\n\nmalformed-variant-token\n"),
    );
    let result = search_q(dir.path(), "malformed-variant-token");
    assert!(
        !token_in_hits(&result, "malformed-variant-token"),
        "{result:?}"
    );
    let json = report_json(dir.path(), None);
    let msgs = finding_messages(&json, "E_INVALID_ID");
    assert!(
        msgs.iter().any(|m| m.contains("'Person'")),
        "expected the key named as written: {json}"
    );
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

#[test]
fn find_drops_glued_cam_id_tails_and_keeps_drive_urls() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    let cam_ulid = &CAM[2..];
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\n\
visible-cam-glue-token\n\
see https://example.com/x/{CAM}abc dropped-cam-url-short-token\n\
see https://example.com/{CAM}abcdefghijk dropped-cam-url-long-token\n\
see Ana-{CAM}s dropped-cam-ana-s-token\n\
see Ana-{CAM}abcdefghij dropped-cam-ana-long-token\n\
see Ana-p\u{2013}{cam_ulid} dropped-cam-en-dash-token\n\
still-cam-glue-token\n\
see https://docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit docs-url-token\n\
see drive.google.com/file/d/1b3Yf11-n-m7vpfukD0SPao3NxJ7dDYgq/view drive-url-token\n"
        ),
    );
    for token in [
        "dropped-cam-url-short-token",
        "dropped-cam-url-long-token",
        "dropped-cam-ana-s-token",
        "dropped-cam-ana-long-token",
        "dropped-cam-en-dash-token",
    ] {
        let result = search_q(dir.path(), token);
        assert!(!token_in_hits(&result, token), "{token} {result:?}");
    }
    let visible = search_q(dir.path(), "visible-cam-glue-token");
    let still = search_q(dir.path(), "still-cam-glue-token");
    let docs = search_q(dir.path(), "docs-url-token");
    let drive = search_q(dir.path(), "drive-url-token");
    assert!(
        token_in_hits(&visible, "visible-cam-glue-token"),
        "{visible:?}"
    );
    assert!(token_in_hits(&still, "still-cam-glue-token"), "{still:?}");
    assert!(token_in_hits(&docs, "docs-url-token"), "{docs:?}");
    assert!(token_in_hits(&drive, "drive-url-token"), "{drive:?}");
}

#[test]
fn quoted_person_with_trailing_hash_comment_parses() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    person(dir.path(), BEA, "Bea");
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: \"{ADA}\" # Ada\n---\n\nquoted-hash-person-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE2}/note.md"),
        &format!(
            "---\nid: {NOTE2}\ntype: note\nperson: '[[{ADA}|Ada]]' # c\n---\n\nquoted-wikilink-hash-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE3}/note.md"),
        &format!(
            "---\nid: {NOTE3}\ntype: note\nperson: \"{BEA}\"  # Bea\n---\n\nquoted-spaces-hash-token\n"
        ),
    );
    let note4 = "n-01M3TC5H00MPJG00900000000G";
    write(
        dir.path(),
        &format!("notes/{note4}/note.md"),
        &format!(
            "---\nid: {note4}\ntype: note\nperson: \"{BEA}\" \t# Bea\n---\n\nquoted-tab-hash-token\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {BEA} package {PKG} 6 sessions\n\
             2026-10-02 session {BEA} 60m paid note:{NOTE3}\n\
             2026-10-03 session {BEA} 45m paid note:{note4}\n"
        ),
    );
    let a = search_q(dir.path(), "quoted-hash-person-token");
    let b = search_q(dir.path(), "quoted-wikilink-hash-token");
    let c = search_q(dir.path(), "quoted-spaces-hash-token");
    let d = search_q(dir.path(), "quoted-tab-hash-token");
    assert!(token_in_hits(&a, "quoted-hash-person-token"), "{a:?}");
    assert!(token_in_hits(&b, "quoted-wikilink-hash-token"), "{b:?}");
    assert!(token_in_hits(&c, "quoted-spaces-hash-token"), "{c:?}");
    assert!(token_in_hits(&d, "quoted-tab-hash-token"), "{d:?}");
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_INVALID_ID".into()), "{json}");
    assert!(!codes(&json).contains(&"E_UNKNOWN_RECORD".into()), "{json}");
}

#[test]
fn find_drops_unicode_dash_runs_and_keeps_drive_i95() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    let cam_ulid = &CAM[2..];
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\n\
visible-dash-run-token\n\
see p\u{058a}{cam_ulid} dropped-armenian-hyphen-token\n\
see p\u{05be}{cam_ulid} dropped-maqaf-token\n\
see p\u{1806}{cam_ulid} dropped-mongolian-hyphen-token\n\
see p\u{2e17}{cam_ulid} dropped-double-oblique-token\n\
see p\u{2e3a}{cam_ulid} dropped-two-em-token\n\
see p\u{301c}{cam_ulid} dropped-wave-dash-token\n\
see p\u{fe31}{cam_ulid} dropped-vertical-em-token\n\
see p\u{2043}{cam_ulid} dropped-hyphen-bullet-token\n\
see p\u{30fc}{cam_ulid} dropped-kana-prolonged-token\n\
see p--{cam_ulid} dropped-double-hyphen-token\n\
see p\u{00ad}-{cam_ulid} dropped-soft-hyphen-ascii-token\n\
see I-95 i95-highway-token\n\
see https://docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit docs-url-dash-token\n\
see drive.google.com/file/d/1b3Yf11-n-m7vpfukD0SPao3NxJ7dDYgq/view drive-url-dash-token\n\
see https://www.notion.so/Coaching-Plan-0123456789abcdef0123456789abcdef notion-url-dash-token\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("; p--{cam_ulid} dropped-ledger-dash-run-token\n"),
    );
    for token in [
        "dropped-armenian-hyphen-token",
        "dropped-maqaf-token",
        "dropped-mongolian-hyphen-token",
        "dropped-double-oblique-token",
        "dropped-two-em-token",
        "dropped-wave-dash-token",
        "dropped-vertical-em-token",
        "dropped-hyphen-bullet-token",
        "dropped-kana-prolonged-token",
        "dropped-double-hyphen-token",
        "dropped-soft-hyphen-ascii-token",
        "dropped-ledger-dash-run-token",
    ] {
        let result = search_q(dir.path(), token);
        assert!(!token_in_hits(&result, token), "{token} {result:?}");
    }
    for token in [
        "visible-dash-run-token",
        "i95-highway-token",
        "docs-url-dash-token",
        "drive-url-dash-token",
        "notion-url-dash-token",
    ] {
        let result = search_q(dir.path(), token);
        assert!(token_in_hits(&result, token), "{token} {result:?}");
    }
}

#[test]
fn find_drops_cam_dash_in_nonref_front_matter_key() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    let cam_ulid = &CAM[2..];
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\nsee: p--{cam_ulid}\n---\n\nhidden-fm-dash-run-token\n"
        ),
    );
    let result = search_q(dir.path(), "hidden-fm-dash-run-token");
    assert!(
        !token_in_hits(&result, "hidden-fm-dash-run-token"),
        "{result:?}"
    );
}

#[test]
fn find_unclears_interaction_and_deal_named_on_hidden_ledger_line() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    person(dir.path(), BEA, "Bea");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nbea-named-ledger-token\n"),
    );
    write(
        dir.path(),
        &format!("interactions/{IXN}/interaction.md"),
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: Call\nperson: {BEA}\n---\n\nixn-named-on-cam-line-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("deals/{DEAL}/deal.md"),
        &format!(
            "---\nid: {DEAL}\ntype: deal\nname: Deal\nperson: {BEA}\n---\n\ndeal-named-on-cam-line-token\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-02 session {CAM} 60m paid src:{IXN}\n\
             2026-10-03 stage {DEAL} proposal ; for {CAM}\n"
        ),
    );
    let ixn = search_q(dir.path(), "ixn-named-on-cam-line-token");
    let deal = search_q(dir.path(), "deal-named-on-cam-line-token");
    let bea = search_q(dir.path(), "bea-named-ledger-token");
    assert!(
        !token_in_hits(&ixn, "ixn-named-on-cam-line-token"),
        "{ixn:?}"
    );
    assert!(
        !token_in_hits(&deal, "deal-named-on-cam-line-token"),
        "{deal:?}"
    );
    assert!(token_in_hits(&bea, "bea-named-ledger-token"), "{bea:?}");
}

#[test]
fn find_drops_bare_uncleared_ulid_in_body_and_src() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    let cam_ulid = &CAM[2..];
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\n\
visible-bare-ulid-token\n\
see {cam_ulid} dropped-bare-ulid-token\n\
still-bare-ulid-token\n"
        ),
    );
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {BEA}\ndate: 2026-10-01\nsee: {cam_ulid}\n---\n\nhidden-fm-bare-ulid-token\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 session {BEA} 60m paid src:\"zoom/{cam_ulid}.vtt\" dropped-src-bare-ulid-token\n"
        ),
    );
    let dropped = search_q(dir.path(), "dropped-bare-ulid-token");
    let src = search_q(dir.path(), "dropped-src-bare-ulid-token");
    let fm = search_q(dir.path(), "hidden-fm-bare-ulid-token");
    let visible = search_q(dir.path(), "visible-bare-ulid-token");
    let still = search_q(dir.path(), "still-bare-ulid-token");
    assert!(
        !token_in_hits(&dropped, "dropped-bare-ulid-token"),
        "{dropped:?}"
    );
    assert!(
        !token_in_hits(&src, "dropped-src-bare-ulid-token"),
        "{src:?}"
    );
    assert!(!token_in_hits(&fm, "hidden-fm-bare-ulid-token"), "{fm:?}");
    assert!(
        token_in_hits(&visible, "visible-bare-ulid-token"),
        "{visible:?}"
    );
    assert!(token_in_hits(&still, "still-bare-ulid-token"), "{still:?}");
}

#[test]
fn check_messages_do_not_echo_vault_free_text() {
    let dir = tempfile::tempdir().unwrap();
    install_shipped_coaching(dir.path());
    write(
        dir.path(),
        "confidant.toml",
        r#"spec = "0.1"
packs = ["coaching@0.1", "zxqvleakpack@0.1"]
vault_id = "test-vault"

[checks]
as_of = "2026-10-08"
coaching.require_duration = "error"
coaching.balance_nonnegative = "error"
coaching.session_notes = "off"
coaching.paid_session_gap = "off"
"#,
    );
    person(dir.path(), ADA, "Ada Example");
    note(dir.path(), NOTE, ADA, "2026-10-01");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} ZXQVLEAKN sessions\n\
             2026-10-01 ZXQVLEAKVERB {ADA}\n\
             2026-10-02 session {ADA} 60m paid note:{NOTE} src:ZXQVLEAKSRC\n\
             2026-10-03 session {ADA} 45m paid note:{NOTE} src:ZXQVLEAKSRC\n\
             2026-10-04 balance {ADA} ZXQVLEAKMETRIC 1\n\
             2026-10-05 balance {ADA} sessions_remaining ZXQVLEAKINT\n\
             2026-10-06 balance {ADA} icf_hours ZXQVLEAKDEC\n\
             2026-10-07 balance {ADA} sessions_remaining\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let dumped = serde_json::to_string(&json).unwrap();
    // Record bodies, ledger lines, and file contents never echo into
    // findings. The one carve-out (#490): an external pack's own
    // `name@version` — written by the operator in confidant.toml — may
    // join the E_PACK_UNKNOWN message, as the full pin, never bare, and
    // only when it is a real pin (#501).
    for leak in [
        "ZXQVLEAKN",
        "ZXQVLEAKVERB",
        "ZXQVLEAKSRC",
        "ZXQVLEAKMETRIC",
        "ZXQVLEAKINT",
        "ZXQVLEAKDEC",
    ] {
        assert!(!dumped.contains(leak), "{leak} leaked in {dumped}");
    }
    let pack_unknown = finding_by_code(&json, "E_PACK_UNKNOWN");
    assert_eq!(
        pack_unknown["message"].as_str().unwrap(),
        "external pack zxqvleakpack@0.1 listed in confidant.toml has no lockfile pin"
    );
    assert_eq!(pack_unknown["file"].as_str().unwrap(), "confidant.toml");
    let c = codes(&json);
    assert!(c.contains(&"E_PACK_UNKNOWN".into()), "{c:?}");
    assert!(c.contains(&"E_UNKNOWN_VERB".into()), "{c:?}");
    assert!(c.contains(&"E_DUPLICATE_SRC".into()), "{c:?}");
    assert!(c.contains(&"E_UNKNOWN_METRIC".into()), "{c:?}");
    assert!(c.contains(&"E_PARSE".into()), "{c:?}");
    assert!(c.contains(&"E_COACHING_OPEN_MALFORMED".into()), "{c:?}");
}

fn ada_coaching_client(root: &Path) {
    write(
        root,
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nFake coaching client\n"),
    );
}

#[test]
fn find_hides_ada_merged_into_cam_bare_ulid() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    ada_coaching_client(dir.path());
    person_no_ai(dir.path(), CAM, "Cam");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-02 merge {ADA} into {}\n", &CAM[2..]),
    );
    let result = search_q(dir.path(), "Fake coaching client");
    assert!(
        !token_in_hits(&result, "Fake coaching client"),
        "{result:?}"
    );
}

#[test]
fn find_hides_bea_merged_from_lowercase_cam_bare_ulid() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    ada_coaching_client(dir.path());
    person_no_ai(dir.path(), CAM, "Cam");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nbea-lowercase-bare-merge-token\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        "merge 01m3tc5h00mpjg001248000002 into p-01M3TC5H00MPJG000H24000001\n",
    );
    let bea = search_q(dir.path(), "bea-lowercase-bare-merge-token");
    let ada = search_q(dir.path(), "Fake coaching client");
    assert!(
        !token_in_hits(&bea, "bea-lowercase-bare-merge-token"),
        "{bea:?}"
    );
    assert!(
        token_in_hits(&ada, "Fake coaching client"),
        "Ada is not in this merge group: {ada:?}"
    );
}

#[test]
fn find_hides_ada_merged_from_t_prefixed_cam_ulid() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    ada_coaching_client(dir.path());
    person_no_ai(dir.path(), CAM, "Cam");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("merge t-{} into {ADA}\n", &CAM[2..]),
    );
    let result = search_q(dir.path(), "Fake coaching client");
    assert!(
        !token_in_hits(&result, "Fake coaching client"),
        "{result:?}"
    );
}

#[test]
fn find_hides_pkg_opened_by_bare_cam_ulid() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), BEA, "Bea");
    person_no_ai(dir.path(), CAM, "Cam");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {BEA} package {PKG} 4 sessions\n\
             2026-10-01 open {} package {PKG} 4 sessions\n\
             2026-10-02 session {BEA} 60m paid src:{PKG} pkg-bare-open-token\n",
            &CAM[2..]
        ),
    );
    let result = search_q(dir.path(), "pkg-bare-open-token");
    assert!(!token_in_hits(&result, "pkg-bare-open-token"), "{result:?}");
}

#[test]
fn find_drops_bareline_of_unloaded_no_ai_yes_path() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{CAM}/profile.md"),
        &format!("---\nid: {CAM}\ntype: person\nname: Cam\nno-ai: yes\n---\n\nCam secret\n"),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nBare ref BARELINE {} here\n",
            &CAM[2..]
        ),
    );
    let bare = search_q(dir.path(), "BARELINE");
    assert!(!token_in_hits(&bare, "BARELINE"), "{bare:?}");
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!("---\nid: {BEA}\ntype: person\nname: Bea\n---\n\nprefixed {CAM} PREFIXEDHIDE\n"),
    );
    let prefixed = search_q(dir.path(), "PREFIXEDHIDE");
    assert!(!token_in_hits(&prefixed, "PREFIXEDHIDE"), "{prefixed:?}");
}

#[test]
fn find_drops_glued_bare_ulid_windows() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    let ulid = &CAM[2..];
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea\n---\n\n\
visible-window-token\n\
src:zoom/rec_{ulid}.vtt rec-window-token\n\
p_{ulid} p-underscore-window-token\n\
p{ulid} p-glued-window-token\n\
{ulid}abc suffix-window-token\n\
still-window-token\n"
        ),
    );
    for token in [
        "rec-window-token",
        "p-underscore-window-token",
        "p-glued-window-token",
        "suffix-window-token",
    ] {
        let result = search_q(dir.path(), token);
        assert!(!token_in_hits(&result, token), "{token} {result:?}");
    }
    let visible = search_q(dir.path(), "visible-window-token");
    let still = search_q(dir.path(), "still-window-token");
    assert!(
        token_in_hits(&visible, "visible-window-token"),
        "{visible:?}"
    );
    assert!(token_in_hits(&still, "still-window-token"), "{still:?}");
}

#[test]
fn check_messages_do_not_echo_seeded_filenames() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let leaks = [
        "ZXQVLEAKTOP.md",
        "ZXQVLEAKFILE.md",
        "ZXQVLEAKDIR",
        "ZXQVLEAKEXTRA.md",
        "ZXQVLEAKNOTE.txt",
        "ZXQVLEAKTMP",
        "ZXQVLEAKYEAR",
        "ZXQVLEAKLEDGER.txt",
        "ZXQVLEAKLINK",
        "10.cfd",
        "ledger/2026/10.cfd",
    ];
    write(dir.path(), "ZXQVLEAKTOP.md", "not a vault file\n");
    write(
        dir.path(),
        "people/ZXQVLEAKFILE.md",
        "---\nid: x\ntype: person\n---\n",
    );
    write(
        dir.path(),
        "people/ZXQVLEAKDIR/profile.md",
        "---\nid: x\ntype: person\n---\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/ZXQVLEAKEXTRA.md"),
        "extra\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/notes/ZXQVLEAKNOTE.txt"),
        "note leftover\n",
    );
    write(dir.path(), "people/.confidant-tmp-ZXQVLEAKTMP", "tmp\n");
    write(dir.path(), "ledger/ZXQVLEAKYEAR/01.cfd", "x\n");
    write(dir.path(), "ledger/2026/ZXQVLEAKLEDGER.txt", "x\n");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-09-01 session {ADA} 60m paid note:{NOTE}\n"),
    );
    #[cfg(unix)]
    std::os::unix::fs::symlink("profile.md", dir.path().join("people/ZXQVLEAKLINK")).unwrap();
    let json = report_json(dir.path(), None);
    let messages: Vec<String> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {}",
                f["message"].as_str().unwrap_or(""),
                f["fix"].as_str().unwrap_or("")
            )
        })
        .collect();
    let joined = messages.join("\n");
    for leak in leaks {
        assert!(
            !joined.contains(leak),
            "{leak} leaked in check messages: {joined}"
        );
    }
    let files: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["file"].as_str())
        .collect();
    // #7: the file field must not carry a name either — only trusted
    // path components plus the redaction marker, so the operator can
    // locate it. Valid paths (like ledger/2026/10.cfd) still appear; only
    // the seeded bad names must be absent.
    let bad_names = leaks
        .iter()
        .filter(|l| l.contains("ZXQVLEAK"))
        .collect::<Vec<_>>();
    for leak in bad_names {
        assert!(
            !files.iter().any(|f| f.contains(leak)),
            "{leak} leaked in check file field: {files:?}"
        );
    }
    assert!(
        files.contains(&"people/<invalid-filename>"),
        "redacted file field should name the parent dir: {files:?}"
    );
    assert!(
        files.contains(&"ledger/<invalid-filename>"),
        "bad ledger year dir should redact to ledger/: {files:?}"
    );
    assert!(codes(&json).contains(&"E_LEDGER_DATE".into()), "{json}");
    let date_msgs: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "E_LEDGER_DATE")
        .map(|f| f["message"].as_str().unwrap_or(""))
        .collect();
    assert!(
        date_msgs
            .iter()
            .all(|m| *m == "entry date does not belong in this monthly file"),
        "{date_msgs:?}"
    );
    assert!(
        files.contains(&"ledger/2026/10.cfd"),
        "E_LEDGER_DATE keeps the path in file: {files:?}"
    );
}

/// #7: a valid record that is merely unreadable (bad permissions) keeps its
/// exact vault-relative path — it is not redacted and gains no marker.
#[test]
#[cfg(unix)]
fn check_unreadable_valid_record_keeps_exact_path() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    let rel = format!("people/{ADA}.md");
    write(
        dir.path(),
        &rel,
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nFake.\n"),
    );
    let path = dir.path().join(&rel);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    // Self-calibrating root check: root bypasses permission bits, so the
    // file stays readable and the test would be vacuous.
    if fs::File::open(&path).is_ok() {
        eprintln!("skipping: running as root, chmod 000 has no effect");
        return;
    }
    let json = report_json(dir.path(), None);
    let finding = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "E_UNREADABLE")
        .expect("expected an E_UNREADABLE finding");
    assert_eq!(
        finding["file"].as_str().unwrap(),
        format!("people/{ADA}.md"),
        "valid-but-unreadable record must keep its exact path: {finding:?}"
    );
}

/// #7: the EntryKind::Other arm (FIFO, socket, …) redacts a leaky name.
#[test]
#[cfg(unix)]
fn check_fifo_entry_does_not_leak_name() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let fifo = dir.path().join("people/ZXQVLEAKFIFO");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must run");
    assert!(status.success(), "mkfifo failed");
    let json = report_json(dir.path(), None);
    let dumped = json.to_string();
    assert!(
        !dumped.contains("ZXQVLEAKFIFO"),
        "FIFO name leaked in check output: {dumped}"
    );
    let files: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["file"].as_str())
        .collect();
    assert!(
        files.contains(&"people/<invalid-filename>"),
        "expected the redacted Other-arm finding: {files:?}"
    );
}

/// #7 (round 2): a non-canonical ledger file with conflict markers redacts
/// both the LedgerPath finding and the E_MERGE_CONFLICT file field.
#[test]
fn check_ledger_merge_conflict_does_not_leak_name() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        "ledger/2026/ZXQVLEAK.cfd",
        "<<<<<<< HEAD\n2026-09-01 session\n=======\n>>>>>>> branch\n",
    );
    let json = report_json(dir.path(), None);
    let dumped = json.to_string();
    assert!(
        !dumped.contains("ZXQVLEAK"),
        "ledger filename leaked in check output: {dumped}"
    );
    assert!(codes(&json).contains(&"E_LEDGER_PATH".into()), "{json}");
    assert!(codes(&json).contains(&"E_MERGE_CONFLICT".into()), "{json}");
    let files: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["file"].as_str())
        .collect();
    assert!(
        files.contains(&"ledger/2026/<invalid-filename>"),
        "expected the redacted ledger path on both findings: {files:?}"
    );
}

/// #391 (part of #219): a git conflict on an encrypted record — an `enc:`
/// envelope — is detected from the raw bytes, before anything tries to
/// decrypt it. Both devices rewrote the envelope, so the conflict spans
/// the outer front matter (the `nonce:` line) as well as the body, which
/// is the case that makes the markers unparseable by `parse_record`.
#[test]
fn check_envelope_merge_conflict_reports_the_conflict() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    // A `keys/` tree is what makes the vault structurally encrypted.
    write(dir.path(), "keys/operator.toml", "# placeholder\n");
    write(
        dir.path(),
        "people/p-01M3TC5H00MPJG000000000000/profile.md",
        "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nno-ai: false\n\
         <<<<<<< HEAD\nenc: xchacha20poly1305\nkey_id: p-01M3TC5H00MPJG000000000000/e1\n\
         nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n=======\nenc: xchacha20poly1305\n\
         key_id: p-01M3TC5H00MPJG000000000000/e1\nnonce: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\
         >>>>>>> other\n---\nAQID\n",
    );
    let json = report_json(dir.path(), None);
    let found = codes(&json);
    assert!(found.contains(&"E_MERGE_CONFLICT".to_string()), "{json}");
    assert!(
        !found.contains(&"E_FRONTMATTER".to_string()),
        "conflict markers produced a derived E_FRONTMATTER: {json}"
    );
}

/// #452: a conflicted file whose two sides are both encrypted envelopes
/// reports the encrypted-record message, with the record id and a
/// `record resolve` fix. Synthetic envelopes with fake base64 (keyless).
#[test]
fn conflicted_envelope_reports_encrypted_message_and_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(dir.path(), "keys/operator.toml", "# placeholder\n");
    let id = "p-01M3TC5H00MPJG000000000000";
    let ours = fake_envelope(id, &"A".repeat(32), "QUJD");
    let theirs = fake_envelope(id, &"B".repeat(32), "REVG");
    let conflicted = format!("<<<<<<< HEAD\n{ours}=======\n{theirs}>>>>>>> other\n");
    write(dir.path(), &format!("people/{id}/profile.md"), &conflicted);
    let json = report_json(dir.path(), None);
    let findings: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"].as_str() == Some("E_MERGE_CONFLICT"))
        .collect();
    assert_eq!(findings.len(), 1, "expected one E_MERGE_CONFLICT: {json}");
    let f = findings[0];
    assert_eq!(
        f["message"].as_str(),
        Some("encrypted record has two versions after a merge conflict"),
        "{json}"
    );
    assert_eq!(f["id"].as_str(), Some(id), "{json}");
    let fix = f["fix"].as_str().unwrap_or("");
    assert!(
        fix.contains(&format!("confidant record resolve {id} --show")),
        "fix should point at record resolve: {fix}"
    );
}

/// #452: a conflicted plaintext record keeps the generic message and fix,
/// with no id set.
#[test]
fn conflicted_plaintext_record_keeps_generic_message() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    let id = "p-01M3TC5H00MPJG000000000000";
    write(
        dir.path(),
        &format!("people/{id}/profile.md"),
        "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: Ada Example\n---\n<<<<<<< HEAD\nOurs.\n=======\nTheirs.\n>>>>>>> other\n",
    );
    let json = report_json(dir.path(), None);
    let findings: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"].as_str() == Some("E_MERGE_CONFLICT"))
        .collect();
    assert_eq!(findings.len(), 1, "expected one E_MERGE_CONFLICT: {json}");
    let f = findings[0];
    assert_eq!(
        f["message"].as_str(),
        Some("file contains git conflict markers"),
        "{json}"
    );
    assert_eq!(
        f["fix"].as_str(),
        Some("Resolve the conflict; check keeps both sides visible until you do"),
        "{json}"
    );
    assert!(
        f.get("id").is_none() || f["id"].is_null(),
        "no id expected: {json}"
    );
}

/// #452: a conflicted ledger file keeps the generic message (ledger
/// behaviour is out of scope).
#[test]
fn conflicted_ledger_keeps_generic_message() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        "ledger/2026/01.cfd",
        "<<<<<<< HEAD\n2026-09-01 session\n=======\n2026-09-02 session\n>>>>>>> branch\n",
    );
    let json = report_json(dir.path(), None);
    let findings: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"].as_str() == Some("E_MERGE_CONFLICT"))
        .collect();
    assert_eq!(findings.len(), 1, "expected one E_MERGE_CONFLICT: {json}");
    assert_eq!(
        findings[0]["message"].as_str(),
        Some("file contains git conflict markers"),
        "{json}"
    );
}

/// #452: when only one conflict side is an envelope, the generic message
/// is kept.
#[test]
fn conflict_with_only_one_envelope_side_keeps_generic_message() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(dir.path(), "keys/operator.toml", "# placeholder\n");
    let id = "p-01M3TC5H00MPJG000000000000";
    let ours = fake_envelope(id, &"A".repeat(32), "QUJD");
    let conflicted = format!("<<<<<<< HEAD\n{ours}=======\nnot an envelope\n>>>>>>> other\n");
    write(dir.path(), &format!("people/{id}/profile.md"), &conflicted);
    let json = report_json(dir.path(), None);
    let findings: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"].as_str() == Some("E_MERGE_CONFLICT"))
        .collect();
    assert_eq!(findings.len(), 1, "expected one E_MERGE_CONFLICT: {json}");
    assert_eq!(
        findings[0]["message"].as_str(),
        Some("file contains git conflict markers"),
        "{json}"
    );
}

/// #452: the JSON report for a conflicted encrypted record carries no
/// plaintext and no ciphertext — only code, severity, path, id, message,
/// fix.
#[test]
fn conflicted_envelope_json_has_no_ciphertext_or_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(dir.path(), "keys/operator.toml", "# placeholder\n");
    let id = "p-01M3TC5H00MPJG000000000000";
    // Distinctive fake base64 body and a sentinel in the nonce area are
    // both absent from the report.
    let body_b64 = "U0VOVElORUxDQUtF"; // "SENTINELCAKE"
    let ours = fake_envelope(id, &"A".repeat(32), body_b64);
    let theirs = fake_envelope(id, &"B".repeat(32), body_b64);
    let conflicted = format!("<<<<<<< HEAD\n{ours}=======\n{theirs}>>>>>>> other\n");
    write(dir.path(), &format!("people/{id}/profile.md"), &conflicted);
    let json = report_json(dir.path(), None);
    let dumped = json.to_string();
    assert!(
        !dumped.contains(body_b64),
        "ciphertext body leaked in check output"
    );
    assert!(
        !dumped.contains("SENTINELCAKE"),
        "decoded body leaked in check output"
    );
}

/// #452: a note referencing a conflicted encrypted record does not cascade
/// into E_DANGLING_REF (existing #396 suppression behaviour, unchanged).
#[test]
fn conflicted_envelope_does_not_cascade_dangling_refs() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(dir.path(), "keys/operator.toml", "# placeholder\n");
    let id = "p-01M3TC5H00MPJG000000000000";
    let ours = fake_envelope(id, &"A".repeat(32), "QUJD");
    let theirs = fake_envelope(id, &"B".repeat(32), "REVG");
    let conflicted = format!("<<<<<<< HEAD\n{ours}=======\n{theirs}>>>>>>> other\n");
    write(dir.path(), &format!("people/{id}/profile.md"), &conflicted);
    note(dir.path(), NOTE, id, "2026-10-01");
    let json = report_json(dir.path(), None);
    let found = codes(&json);
    assert!(found.contains(&"E_MERGE_CONFLICT".to_string()), "{json}");
    assert!(
        !found.contains(&"E_DANGLING_REF".to_string()),
        "conflicted record cascaded into E_DANGLING_REF: {json}"
    );
}

/// A synthetic envelope with fake base64. Parses via `envelope::parse`
/// but carries no real ciphertext (keyless test).
fn fake_envelope(id: &str, nonce_b64: &str, body_b64: &str) -> String {
    format!(
        "---\nid: {id}\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: {id}/e1\nnonce: {nonce_b64}\n---\n{body_b64}\n"
    )
}

/// #7 (round 2): an unreadable ledger subdirectory redacts the directory
/// name in the directory-level Unreadable finding.
#[test]
#[cfg(unix)]
fn check_unreadable_ledger_dir_does_not_leak_name() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    let sub = dir.path().join("ledger/2026/ZXQVLEAKDIR");
    fs::create_dir_all(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).unwrap();
    // Self-calibrating root check: root bypasses permission bits, so the
    // directory stays listable and the test would be vacuous.
    if std::fs::read_dir(&sub).is_ok() {
        eprintln!("skipping: running as root, chmod 000 has no effect");
        return;
    }
    let json = report_json(dir.path(), None);
    let dumped = json.to_string();
    assert!(
        !dumped.contains("ZXQVLEAKDIR"),
        "ledger directory name leaked in check output: {dumped}"
    );
    let files: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "E_UNREADABLE")
        .filter_map(|f| f["file"].as_str())
        .collect();
    assert!(
        files.contains(&"ledger/2026/<invalid-filename>"),
        "expected the redacted ledger dir path: {files:?}"
    );
}

fn ulid_of(id: &str) -> &str {
    id.rsplit_once('-').unwrap().1
}

fn id_spellings(id: &str) -> Vec<(&'static str, String)> {
    let ulid = ulid_of(id);
    vec![
        ("prefixed", id.to_owned()),
        ("bare", ulid.to_owned()),
        ("lower", ulid.to_ascii_lowercase()),
        ("tprefix", format!("t-{ulid}")),
        ("recvtt", format!("src:zoom/rec_{ulid}.vtt")),
        ("punder", format!("p_{ulid}")),
        ("pglued", format!("p{ulid}")),
        ("suffix", format!("{ulid}abc")),
    ]
}

fn src_spellings(id: &str) -> Vec<(&'static str, String)> {
    let ulid = ulid_of(id);
    vec![
        ("prefixed", id.to_owned()),
        ("bare", ulid.to_owned()),
        ("lower", ulid.to_ascii_lowercase()),
        ("recvtt", format!("zoom/rec_{ulid}.vtt")),
        ("tprefix", format!("t-{ulid}")),
        ("punder", format!("p_{ulid}")),
        ("pglued", format!("p{ulid}")),
        ("suffix", format!("{ulid}abc")),
    ]
}

fn write_ada_mentions(root: &Path, id: &str, marker_prefix: &str) -> Vec<String> {
    let mut body = format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\n");
    let mut markers = Vec::new();
    for (label, spelling) in id_spellings(id) {
        let marker = format!("{marker_prefix}{label}");
        body.push_str(&format!("{marker} {spelling}\n"));
        markers.push(marker);
    }
    write(root, &format!("people/{ADA}/profile.md"), &body);
    markers
}

fn assert_markers_hidden(root: &Path, markers: &[String]) {
    for marker in markers {
        let result = search_q(root, marker);
        assert!(
            !token_in_hits(&result, marker),
            "{marker} leaked {result:?}"
        );
    }
}

#[test]
fn find_hides_bare_ulid_of_note_renamed_to_uppercase_md() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    note(dir.path(), CAM_NOTE, CAM, "2026-10-07");
    let notes = dir.path().join(format!("people/{CAM}/notes"));
    fs::rename(
        notes.join(format!("{CAM_NOTE}.md")),
        notes.join(format!("{CAM_NOTE}.MD")),
    )
    .unwrap();
    let markers = write_ada_mentions(dir.path(), CAM_NOTE, "ZNOTE");
    assert_markers_hidden(dir.path(), &markers);
}

#[test]
fn find_hides_bare_ulid_of_flat_uppercase_md_no_ai_person() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(
        dir.path(),
        &format!("people/{CAM}.MD"),
        &format!("---\nid: {CAM}\ntype: person\nname: Cam\nno-ai: true\n---\n\nCam secret\n"),
    );
    let markers = write_ada_mentions(dir.path(), CAM, "ZFLAT");
    assert_markers_hidden(dir.path(), &markers);
}

#[cfg(unix)]
#[test]
fn find_hides_bare_ulid_of_person_dir_symlink() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person_no_ai(dir.path(), CAM, "Cam");
    let people = dir.path().join("people");
    let real = people.join(format!("{CAM}-real"));
    fs::rename(people.join(CAM), &real).unwrap();
    std::os::unix::fs::symlink(&real, people.join(CAM)).unwrap();
    let markers = write_ada_mentions(dir.path(), CAM, "ZLINK");
    assert_markers_hidden(dir.path(), &markers);
}

#[cfg(unix)]
#[test]
fn find_hides_bare_ulid_of_fifo_named_as_record_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    let fifo = dir.path().join("people").join(CAM);
    fs::create_dir_all(fifo.parent().unwrap()).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
    let markers = write_ada_mentions(dir.path(), CAM, "ZFIFO");
    assert_markers_hidden(dir.path(), &markers);
}

#[cfg(unix)]
#[test]
fn find_hides_bare_ulid_of_non_file_note_entry() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), CAM, "Cam");
    let notes = dir.path().join(format!("people/{CAM}/notes"));
    fs::create_dir_all(&notes).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(notes.join(CAM_NOTE))
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
    let markers = write_ada_mentions(dir.path(), CAM_NOTE, "ZNFIFO");
    assert_markers_hidden(dir.path(), &markers);
}

#[test]
fn find_hides_session_line_naming_no_ai_package_by_bare_ulid() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    person_no_ai(dir.path(), CAM, "Cam");
    let mut ledger = format!("2026-10-01 open {CAM} package {PKG2} 4 sessions\n");
    let mut markers = Vec::new();
    for (label, spelling) in src_spellings(PKG2) {
        let marker = format!("KLINE{label}");
        ledger.push_str(&format!(
            "2026-10-12 session {ADA} 60m paid {marker} src:{spelling}\n"
        ));
        markers.push(marker);
    }
    write(dir.path(), "ledger/2026/10.cfd", &ledger);
    assert_markers_hidden(dir.path(), &markers);
}

#[test]
fn find_hides_note_named_on_session_with_bare_package_src() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    person_no_ai(dir.path(), CAM, "Cam");
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nNA1TOKEN in ada note\n"
        ),
    );
    let mut ledger = format!("2026-10-01 open {CAM} package {PKG2} 4 sessions\n");
    for (label, spelling) in src_spellings(PKG2) {
        ledger.push_str(&format!(
            "2026-10-12 session {ADA} 60m paid note:{NOTE} src:{spelling} {label}\n"
        ));
    }
    write(dir.path(), "ledger/2026/10.cfd", &ledger);
    let result = search_q(dir.path(), "NA1TOKEN");
    assert!(!token_in_hits(&result, "NA1TOKEN"), "{result:?}");
}

#[test]
fn find_bare_package_ulid_matches_prefixed_when_package_is_cleared() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let mut ledger = format!("2026-10-01 open {ADA} package {PKG} 6 sessions\n");
    let mut markers = Vec::new();
    for (label, spelling) in src_spellings(PKG) {
        let marker = format!("KCLEAR{label}");
        ledger.push_str(&format!(
            "2026-10-12 session {ADA} 60m paid {marker} src:{spelling}\n"
        ));
        markers.push(marker);
    }
    write(dir.path(), "ledger/2026/10.cfd", &ledger);
    for marker in &markers {
        let result = search_q(dir.path(), marker);
        assert!(
            token_in_hits(&result, marker),
            "{marker} should stay searchable when the package is cleared: {result:?}"
        );
    }
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for ent in fs::read_dir(src).unwrap() {
        let ent = ent.unwrap();
        let to = dst.join(ent.file_name());
        if ent.file_type().unwrap().is_dir() {
            copy_dir(&ent.path(), &to);
        } else {
            fs::copy(ent.path(), to).unwrap();
        }
    }
}

fn demo_vault() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

fn copy_demo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_dir(&demo_vault(), dir.path());
    dir
}

fn append_ledger(root: &Path, extra: &str) {
    let path = root.join("ledger/2026/10.cfd");
    let mut text = fs::read_to_string(&path).unwrap();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(extra);
    fs::write(path, text).unwrap();
}

fn hit_fingerprint(result: &confidant_core::SearchResult) -> Vec<(String, u32, String, String)> {
    result
        .hits
        .iter()
        .map(|h| {
            (
                h.path.clone(),
                h.line,
                h.excerpt.clone(),
                h.id.clone().unwrap_or_default(),
            )
        })
        .collect()
}

fn write_merge_pkg_leak_lines(root: &Path, pkg_spelling: &str) {
    append_ledger(
        root,
        &format!(
            "2026-10-09 merge {BEA} into {pkg_spelling}\n\
             2026-10-09 merge {ADA} into {CAM}\n"
        ),
    );
}

#[test]
fn find_hides_bea_merged_into_package_when_opener_merges_into_no_ai() {
    for (label, pkg_spelling) in [
        ("prefixed", PKG.to_owned()),
        ("bare", ulid_of(PKG).to_owned()),
    ] {
        let dir = copy_demo();
        write_merge_pkg_leak_lines(dir.path(), &pkg_spelling);
        let vault = load_vault(dir.path()).unwrap();
        assert!(
            confidant_core::allowlist_is_fixed_point(&vault),
            "{label} allowlist is not a fixed point"
        );
        let cleared: Vec<String> = confidant_core::cleared_record_ids(&vault)
            .iter()
            .map(|id| id.to_string())
            .collect();
        assert!(
            !cleared.iter().any(|id| id == BEA),
            "{label}: Bea stayed cleared: {cleared:?}"
        );
        for q in ["Bea Demo", "pay-per-session", "Bea"] {
            let result = search_q(dir.path(), q);
            assert!(
                !token_in_hits(&result, "Bea"),
                "{label} query {q:?} leaked Bea: {result:?}"
            );
        }
        let mut first = None;
        for _ in 0..16 {
            let result = search_q(dir.path(), "Demo");
            let fp = hit_fingerprint(&result);
            assert!(
                fp.iter()
                    .all(|(_, _, excerpt, id)| { !excerpt.contains("Bea") && id.as_str() != BEA }),
                "{label} Demo search leaked Bea: {fp:?}"
            );
            match &first {
                None => first = Some(fp),
                Some(prev) => assert_eq!(prev, &fp, "{label} find was not deterministic"),
            }
        }
    }
}

#[test]
fn find_is_deterministic_on_shuffled_ledger_insertion() {
    let mut lines = [
        format!("2026-10-01 open {ADA} package {PKG} 6 sessions"),
        format!("2026-10-01 open {CAM} package {PKG2} 4 sessions"),
        format!("2026-10-09 merge {BEA} into {PKG}"),
        format!("2026-10-09 merge {ADA} into {CAM}"),
        format!("2026-10-05 session {BEA} 60m pps bea-shuffle-token"),
        format!("2026-10-08 session {ADA} 45m paid ada-shuffle-token"),
    ];
    let mut expected: Option<Vec<String>> = None;
    for seed in 1u64..=16 {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for i in (1..lines.len()).rev() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let j = (x as usize) % (i + 1);
            lines.swap(i, j);
        }
        let dir = tempfile::tempdir().unwrap();
        vault_toml(dir.path(), DEFAULT_CHECKS);
        person(dir.path(), ADA, "Ada Example");
        person(dir.path(), BEA, "Bea");
        person_no_ai(dir.path(), CAM, "Cam");
        write(
            dir.path(),
            "ledger/2026/10.cfd",
            &format!("{}\n", lines.join("\n")),
        );
        let vault = load_vault(dir.path()).unwrap();
        assert!(
            confidant_core::allowlist_is_fixed_point(&vault),
            "shuffled seed {seed} is not a fixed point"
        );
        let mut found = Vec::new();
        for (q, token) in [
            ("ada-shuffle-token", "ada-shuffle-token"),
            ("bea-shuffle-token", "bea-shuffle-token"),
            ("Ada Example", "Ada Example"),
            ("Bea", "Bea"),
        ] {
            if token_in_hits(&search_q(dir.path(), q), token) {
                found.push(token.to_owned());
            }
        }
        found.sort();
        assert!(
            found.is_empty(),
            "seed {seed} leaked searchable tokens: {found:?}"
        );
        match &expected {
            None => expected = Some(found),
            Some(prev) => assert_eq!(prev, &found, "seed {seed} disagreed"),
        }
    }
}

#[test]
fn find_keeps_bea_when_ada_mentions_dangling_note_with_bea_ulid() {
    let dir = copy_demo();
    let profile = dir.path().join(format!("people/{ADA}/profile.md"));
    let mut text = fs::read_to_string(&profile).unwrap();
    text.push_str(&format!(
        "\nMentioned n-{} once by mistake.\n",
        ulid_of(BEA)
    ));
    fs::write(&profile, text).unwrap();
    let baseline = search_q(&demo_vault(), "Bea");
    let after = search_q(dir.path(), "Bea");
    assert!(
        token_in_hits(&baseline, "Bea Demo"),
        "demo vault should mention Bea: {baseline:?}"
    );
    assert_eq!(
        baseline.hits.len(),
        after.hits.len(),
        "dangling n-Bea ULID hid Bea: baseline {} after {} {after:?}",
        baseline.hits.len(),
        after.hits.len()
    );
    assert_eq!(
        hit_fingerprint(&baseline),
        hit_fingerprint(&after),
        "dangling n-Bea ULID changed Bea's hits"
    );
    assert!(confidant_core::allowlist_is_fixed_point(
        &load_vault(dir.path()).unwrap()
    ));
}

#[test]
fn find_keeps_ada_when_interaction_mentions_dangling_note_with_ada_ulid() {
    let dir = copy_demo();
    let ixn = dir
        .path()
        .join(format!("interactions/{IXN}/interaction.md"));
    let mut text = fs::read_to_string(&ixn).unwrap();
    text.push_str(&format!("\nn-{}\n", ulid_of(ADA)));
    fs::write(&ixn, text).unwrap();
    let ada = search_q(dir.path(), "Ada Example");
    assert!(
        token_in_hits(&ada, "Ada Example"),
        "dangling n-Ada ULID hid Ada: {ada:?}"
    );
    assert!(confidant_core::allowlist_is_fixed_point(
        &load_vault(dir.path()).unwrap()
    ));
}

#[test]
fn find_open_line_with_thousands_of_ids_is_fast() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let mut line = String::from("2026-10-01 open");
    for i in 0..2000u128 {
        let pid = confidant_core::id::RecordId::new(
            confidant_core::id::Prefix::Person,
            confidant_core::id::ulid_from_parts(1_790_812_800_000, 10_000 + i),
        )
        .unwrap();
        line.push(' ');
        line.push_str(&pid.to_string());
    }
    line.push_str(" package");
    for i in 0..2000u128 {
        let pkg = confidant_core::id::RecordId::new(
            confidant_core::id::Prefix::Package,
            confidant_core::id::ulid_from_parts(1_790_812_800_000, 80_000 + i),
        )
        .unwrap();
        line.push(' ');
        line.push_str(&pkg.to_string());
    }
    line.push_str(" 1 sessions\n");
    write(dir.path(), "ledger/2026/10.cfd", &line);
    let vault = load_vault(dir.path()).unwrap();
    let t0 = Instant::now();
    let _ = confidant_core::search(&vault, "Ada Example", &confidant_core::PackScope::All).unwrap();
    let elapsed = t0.elapsed();
    let budget = if cfg!(debug_assertions) {
        Duration::from_secs(20)
    } else {
        Duration::from_millis(500)
    };
    assert!(
        elapsed < budget,
        "open 2000×2000 took {elapsed:?} (budget {budget:?})"
    );
}

fn junk_name_hides_cam_note(root: &Path, rel: &str) {
    vault_toml(root, DEFAULT_CHECKS);
    person_no_ai(root, CAM, "Cam");
    write(root, rel, "leftover copy\n");
    person(root, ADA, "Ada Example");
    let markers = write_ada_mentions(root, CAM_NOTE, "ZJUNK");
    assert_markers_hidden(root, &markers);
    let ada = search_q(root, "Ada Example");
    assert!(
        token_in_hits(&ada, "Ada Example"),
        "junk name {rel} hid Ada's own profile: {ada:?}"
    );
}

#[test]
fn find_hides_bare_ulid_of_note_named_md_bak() {
    let dir = tempfile::tempdir().unwrap();
    junk_name_hides_cam_note(dir.path(), &format!("notes/{CAM_NOTE}.md.bak"));
}

#[test]
fn find_hides_bare_ulid_of_note_named_copy() {
    let dir = tempfile::tempdir().unwrap();
    junk_name_hides_cam_note(dir.path(), &format!("notes/{CAM_NOTE} (copy).md"));
}

#[test]
fn find_hides_bare_ulid_of_uppercase_prefix_filename() {
    let dir = tempfile::tempdir().unwrap();
    junk_name_hides_cam_note(dir.path(), &format!("notes/N-{}.md", ulid_of(CAM_NOTE)));
}

#[test]
fn find_hides_bare_ulid_of_bare_ulid_filename() {
    let dir = tempfile::tempdir().unwrap();
    junk_name_hides_cam_note(dir.path(), &format!("notes/{}.md", ulid_of(CAM_NOTE)));
}

#[test]
fn find_hides_bare_ulid_of_dotfile_swp_name() {
    let dir = tempfile::tempdir().unwrap();
    junk_name_hides_cam_note(dir.path(), &format!("notes/.{CAM_NOTE}.md.swp"));
}

#[test]
fn find_hides_bare_ulid_of_note_nested_under_sub() {
    let dir = tempfile::tempdir().unwrap();
    junk_name_hides_cam_note(dir.path(), &format!("notes/sub/{CAM_NOTE}.md"));
}

#[test]
fn find_keeps_ada_when_only_her_own_filenames_contain_her_id() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    let ada = search_q(dir.path(), "Ada Example");
    assert!(token_in_hits(&ada, "Ada Example"), "{ada:?}");
    assert!(confidant_core::allowlist_is_fixed_point(
        &load_vault(dir.path()).unwrap()
    ));
}

// ---------------------------------------------------------------------------
// #179: relationship edges, `with:` lists, touchpoints.
// ---------------------------------------------------------------------------

const EDGE1: &str = "e-01M3TC5H00MPJG00E100000000";
const EDGE2: &str = "e-01M3TC5H00MPJG00E200000000";
const EDGE3: &str = "e-01M3TC5H00MPJG00E300000000";
const IXN2: &str = "i-01M3TC5H00MPJG00F100000000";

fn edge(root: &Path, id: &str, a: &str, b: &str, kind: &str) {
    write(
        root,
        &format!("edges/{id}/edge.md"),
        &format!("---\nid: {id}\ntype: edge\na: {a}\nb: {b}\nkind: {kind}\n---\n"),
    );
}

fn edge_with_body(root: &Path, id: &str, a: &str, b: &str, kind: &str) {
    write(
        root,
        &format!("edges/{id}/edge.md"),
        &format!("---\nid: {id}\ntype: edge\na: {a}\nb: {b}\nkind: {kind}\n---\n\nThis body must not be here.\n"),
    );
}

fn interaction_with(root: &Path, id: &str, person: &str, date: &str, with: &str) {
    write(
        root,
        &format!("interactions/{id}/interaction.md"),
        &format!("---\nid: {id}\ntype: interaction\nname: Group dinner\ndate: {date}\nperson: {person}\nwith: {with}\n---\n\nFake group dinner.\n"),
    );
}

fn two_people(dir: &Path) {
    vault_toml(dir, DEFAULT_CHECKS);
    person(dir, ADA, "Ada Example");
    person(dir, BEA, "Bea Demo");
}

#[test]
fn edge_valid_passes() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "married");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn edge_body_is_rejected() {
    // #179 Q1.1: edges carry only ids, kind, and dates — no body.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge_with_body(dir.path(), EDGE1, ADA, BEA, "married");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn edge_no_ai_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!(
            "---\nid: {EDGE1}\ntype: edge\na: {ADA}\nb: {BEA}\nkind: married\nno-ai: true\n---\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn edge_extra_front_matter_key_is_rejected() {
    // #390: an edge carries only ids, kind, and dates. An extra front-matter
    // key is the same shared-key residue as a body — the value would be
    // encrypted under `vault:shared` and survive a shred — so it is rejected
    // rather than silently ignored like unknown keys elsewhere (spec §4).
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    for (key, value) in [
        ("name", "sensitive context in a spec key"),
        ("zz_probe_key", "zz_probe_value"),
    ] {
        write(
            dir.path(),
            &format!("edges/{EDGE1}/edge.md"),
            &format!(
                "---\nid: {EDGE1}\ntype: edge\na: {ADA}\nb: {BEA}\nkind: married\n{key}: {value}\n---\n"
            ),
        );
        let json = report_json(dir.path(), None);
        assert_eq!(
            codes(&json),
            vec!["E_FRONTMATTER"],
            "key {key:?} was not rejected: {json}"
        );
        let message = json["findings"][0]["message"].as_str().unwrap();
        assert!(
            !message.contains(key),
            "the error must not echo the offending key: {message}"
        );
        assert!(
            !message.contains(value),
            "the error must not echo the offending value: {message}"
        );
    }
}

#[test]
fn edge_dates_are_still_allowed() {
    // The whitelist must not reject the fields an edge legitimately has.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!(
            "---\nid: {EDGE1}\ntype: edge\na: {ADA}\nb: {BEA}\nkind: married\n\
             since: 2026-01-01\nuntil: 2026-06-01\n---\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn edge_envelope_shell_is_exempt_from_the_whitelist() {
    // #390 carve-out: an encrypted edge's outer header belongs to the
    // envelope (id/type/no-ai/enc/key_id/nonce), not to the record, so the
    // edge field whitelist must not apply to the shell.
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    write(dir.path(), "keys/operator.toml", "# placeholder\n");
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!(
            "---\nid: {EDGE1}\ntype: edge\nno-ai: false\nenc: xchacha20poly1305\n\
             key_id: vault:shared/e1\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(
        !codes(&json).contains(&"E_FRONTMATTER".to_string()),
        "the edge envelope shell was rejected as a record: {json}"
    );
}

#[test]
fn edge_self_edge_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, ADA, "married");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_SELF_EDGE"]);
}

#[test]
fn edge_unknown_kind_is_rejected() {
    // The kind list is closed: an unknown kind is an error, not free text.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "nemesis");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_UNKNOWN_EDGE_KIND"]);
}

#[test]
fn edge_symmetric_reversed_duplicate_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "married");
    edge(dir.path(), EDGE2, BEA, ADA, "married");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_DUPLICATE_EDGE"]);
    // The finding names the second edge (the reversed duplicate).
    assert_eq!(json["findings"][0]["id"], EDGE2);
}

#[test]
fn edge_symmetric_exact_duplicate_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "married");
    edge(dir.path(), EDGE2, ADA, BEA, "married");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_DUPLICATE_EDGE"]);
}

#[test]
fn edge_directed_reversed_is_not_a_duplicate() {
    // `introduced` is directed: (A, B) and (B, A) are different relations.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "introduced");
    edge(dir.path(), EDGE2, BEA, ADA, "introduced");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn edge_same_pair_different_kinds_is_not_a_duplicate() {
    // #179 review: two edges on the SAME pair with different kinds
    // (married + colleague) are different relations, not duplicates.
    // The pair key must include the kind.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "married");
    edge(dir.path(), EDGE2, ADA, BEA, "colleague");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn edge_same_pair_same_kind_reversed_is_rejected() {
    // Same pair, same kind, reversed ends: still a duplicate (control for
    // the test above — the kind key must not mask real duplicates).
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, BEA, "colleague");
    edge(dir.path(), EDGE2, BEA, ADA, "colleague");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_DUPLICATE_EDGE"]);
}

#[test]
fn edge_dangling_end_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, GHOST, "married");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_DANGLING_REF"]);
}

#[test]
fn edge_missing_end_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!("---\nid: {EDGE1}\ntype: edge\na: {ADA}\nkind: married\n---\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn edge_missing_kind_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!("---\nid: {EDGE1}\ntype: edge\na: {ADA}\nb: {BEA}\n---\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn edge_missing_kind_fix_lists_pack_kinds() {
    // #299: the missing-kind fix message must list the closed kind list —
    // core kinds plus every enabled pack's kinds — not just core.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.1\"\npacks = [\"personal@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    );
    person(dir.path(), ADA, "Ada Example");
    person(dir.path(), BEA, "Bea Demo");
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!("---\nid: {EDGE1}\ntype: edge\na: {ADA}\nb: {BEA}\n---\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
    let fix = json["findings"][0]["fix"].as_str().unwrap();
    // Core kinds plus personal's kinds are all named.
    for want in [
        "married",
        "introduced",
        "colleague",
        "friend",
        "family",
        "mentor",
    ] {
        assert!(fix.contains(want), "fix must name {want}: {fix}");
    }
}

#[test]
fn edge_wrong_type_end_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    edge(dir.path(), EDGE1, ADA, ORG, "married");
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_WRONG_ID_TYPE"]);
}

#[test]
fn edge_bad_since_date_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        &format!("edges/{EDGE1}/edge.md"),
        &format!("---\nid: {EDGE1}\ntype: edge\na: {ADA}\nb: {BEA}\nkind: married\nsince: 2026-13-01\n---\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn with_list_valid_passes() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    person(dir.path(), CAM, "Cam Sample");
    interaction_with(
        dir.path(),
        IXN2,
        ADA,
        "2026-10-06",
        &format!("[{BEA}, {CAM}]"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn with_list_self_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    interaction_with(dir.path(), IXN2, ADA, "2026-10-06", &format!("[{ADA}]"));
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn with_list_duplicate_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    interaction_with(
        dir.path(),
        IXN2,
        ADA,
        "2026-10-06",
        &format!("[{BEA}, {BEA}]"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn with_list_dangling_is_rejected() {
    // Existence is a keyed check: it runs on records check can read.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    interaction_with(dir.path(), IXN2, ADA, "2026-10-06", &format!("[{GHOST}]"));
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_DANGLING_REF"]);
}

#[test]
fn with_list_wrong_type_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    interaction_with(dir.path(), IXN2, ADA, "2026-10-06", &format!("[{ORG}]"));
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_WRONG_ID_TYPE"]);
}

#[test]
fn with_list_malformed_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    interaction_with(dir.path(), IXN2, ADA, "2026-10-06", BEA);
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_FRONTMATTER"]);
}

#[test]
fn with_list_empty_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    interaction_with(dir.path(), IXN2, ADA, "2026-10-06", "[]");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn touch_line_shape_rules() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    // Minimal: date + verb + own id only. With an optional kind:.
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-06 touch {BEA}\n2026-10-07 touch {BEA} kind:call\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn touch_line_with_extra_arg_is_rejected() {
    // Q3: no other participant ids, no primary id, no interaction id.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-06 touch {BEA} {ADA}\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_TOUCH_MALFORMED"]);
}

#[test]
fn touch_line_on_non_person_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-06 touch {ORG}\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_WRONG_ID_TYPE"]);
}

#[test]
fn edge_with_three_people_is_independent() {
    // A third edge (Cam–Ada, colleague) alongside a married edge: no
    // cross-kind duplicate, no interference.
    let dir = tempfile::tempdir().unwrap();
    two_people(dir.path());
    person(dir.path(), CAM, "Cam Sample");
    edge(dir.path(), EDGE1, ADA, BEA, "married");
    edge(dir.path(), EDGE2, CAM, ADA, "colleague");
    edge(dir.path(), EDGE3, BEA, CAM, "introduced");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

// ---------------------------------------------------------------------------
// #184 + #182: the built-in personal pack and the `touch` verb. The
// `packs = ["personal@0.1"]` listing is a no-op (#551): the pack is implicit.
// ---------------------------------------------------------------------------

const PERSONAL_TOML: &str = r#"spec = "0.1"
packs = ["personal@0.1"]
vault_id = "test-vault"

[checks]
as_of = "2026-10-08"
"#;

fn personal_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    dir
}

#[test]
fn personal_touch_accepts_positional_and_mirrored_forms_when_enabled() {
    let dir = personal_vault();
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 touch {ADA} call\n\
             2026-10-02 touch {ADA} kind:meal\n\
             2026-10-03 touch {ADA} text src:zoom/t-01\n\
             2026-10-04 touch {ADA}\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn personal_touch_unknown_kind_is_malformed_when_enabled() {
    let dir = personal_vault();
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 touch {ADA} smoke\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_TOUCH_MALFORMED"]);
}

#[test]
fn personal_touch_positional_form_valid_with_empty_packs() {
    // #551: the built-in personal pack is implicit, so `packs = []` still
    // enables the richer `touch` grammar and there is no W_PACK_ORPHAN.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", "spec = \"0.1\"\npacks = []\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n");
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 touch {ADA} call\n"),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    assert!(c.is_empty(), "{c:?}");
}

/// #551: the built-in personal pack is implicit — `packs = []` enables it —
/// and a `personal@…` listing at any version is a no-op, never
/// `E_PACK_UNKNOWN` and never a `W_PACK_ORPHAN` for personal fields.
#[test]
fn personal_is_implicit_and_listings_are_noops() {
    let build = |packs: &str| -> Value {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "confidant.toml",
            &PERSONAL_TOML.replace("packs = [\"personal@0.1\"]", &format!("packs = [{packs}]")),
        );
        write(
            dir.path(),
            &format!("people/{ADA}/profile.md"),
            &format!(
                "---\nid: {ADA}\ntype: person\nname: Ada Example\nbirthday: --10-10\ncadence: 30d\n---\n\nFake person.\n"
            ),
        );
        report_json(dir.path(), None)
    };
    let empty = build("");
    // The fixture really fires personal's own rules, so the comparison is
    // meaningful.
    assert!(
        codes(&empty)
            .iter()
            .any(|c| c == "W_DATE_UPCOMING" || c == "W_CADENCE_OVERDUE"),
        "{empty:?}"
    );
    for listed in ["\"personal@0.1\"", "\"personal@0.2\"", "\"personal@9.9\""] {
        let json = build(listed);
        assert_eq!(codes(&json), codes(&empty), "{listed}: {json:?}");
        assert!(
            !codes(&json).contains(&"E_PACK_UNKNOWN".to_owned()),
            "{listed}: {json:?}"
        );
        assert!(
            !codes(&json).contains(&"W_PACK_ORPHAN".to_owned()),
            "{listed}: {json:?}"
        );
    }
}

/// #551: the `personal.*` `[checks]` keys are accepted without the vault
/// listing the pack, because the implicit pack's manifest is always in the
/// config manifest set.
#[test]
fn personal_check_keys_accepted_without_listing() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.1\"\npacks = []\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\npersonal.cadence_overdue = \"off\"\npersonal.date_upcoming = \"off\"\npersonal.date_upcoming_days = 14\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nbirthday: --10-10\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert!(!codes(&json).contains(&"E_CONFIG".to_owned()), "{json:?}");
    // Both personal rules are off, so the fixture is clean.
    assert!(codes(&json).is_empty(), "{json:?}");
}

#[test]
fn personal_cadence_overdue_fires_when_no_touchpoint() {
    let dir = personal_vault();
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["W_CADENCE_OVERDUE"]);

    // A touchpoint inside the window clears the warning.
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 touch {ADA} call\n"),
    );
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn personal_cadence_counts_sessions_as_touchpoints() {
    // #227 Q2: a coaching session counts as a touchpoint, so a coaching
    // client who is also a friend does not get a false overdue.
    let dir = tempfile::tempdir().unwrap();
    install_shipped_coaching(dir.path());
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.1\"\npacks = [\"coaching@0.1\", \"personal@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 6 sessions\n2026-10-01 session {ADA} 60m paid\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    // The session (a touchpoint per #227 Q2) suppresses the cadence nudge.
    assert!(!c.contains(&"W_CADENCE_OVERDUE".to_string()), "{c:?}");
}

#[test]
fn personal_date_upcoming_fires_for_yearless_birthday() {
    let dir = personal_vault();
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\nbirthday: --10-10\n---\n\nFake person.\n"),
    );
    // as_of 2026-10-08; birthday --10-10 is 2 days away.
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["W_DATE_UPCOMING"]);
}

#[test]
fn personal_field_validation_rejects_malformed_values() {
    let dir = personal_vault();
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\nbirthday: 05-14\ncadence: 30\nrelationship: \"\"\ndates: [bad]\n---\n\nFake person.\n"),
    );
    let json = report_json(dir.path(), None);
    let c = codes(&json);
    let count = c.iter().filter(|code| *code == "E_FRONTMATTER").count();
    assert_eq!(count, 4, "{c:?}");
}

#[test]
fn personal_edge_kind_is_valid_when_enabled() {
    let dir = personal_vault();
    person(dir.path(), ADA, "Ada Example");
    person(dir.path(), BEA, "Bea Demo");
    edge(dir.path(), EDGE1, ADA, BEA, "friend");
    let json = report_json(dir.path(), None);
    assert!(codes(&json).is_empty(), "{json}");
}

#[test]
fn personal_touch_note_integrity_checks_note_owner() {
    let dir = personal_vault();
    person(dir.path(), ADA, "Ada Example");
    person(dir.path(), BEA, "Bea Demo");
    note(dir.path(), NOTE, BEA, "2026-10-01");
    // `touch` names a note that belongs to Bea, not Ada.
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 touch {ADA} call note:{NOTE}\n"),
    );
    let json = report_json(dir.path(), None);
    assert_eq!(codes(&json), vec!["E_UNKNOWN_RECORD"]);
}

#[test]
fn plaintext_vault_notes_mode_hides_unflagged_notes_and_interactions_from_find_and_context() {
    use confidant_core::context::build_context;
    use confidant_core::scope::PackScope;
    use confidant_core::search::{allowlist_is_fixed_point, search};

    let dir = tempfile::tempdir().unwrap();
    install_shipped_coaching(dir.path());
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[crypto]\nmode = \"plaintext\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nno-ai: notes\n---\nAda profile prose searchabletoken\n"
        ),
    );
    // Un-flagged note under a no-ai: notes person -> uncleared on plaintext vault.
    let note_default = "n-01M3TC5H00MPJG000000000021";
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{note_default}.md"),
        &format!(
            "---\nid: {note_default}\ntype: note\ndate: 2026-10-01\nperson: {ADA}\n---\nhidden_default_note_token searchabletoken\n"
        ),
    );
    // Explicit no-ai: false note under a no-ai: notes person -> cleared override.
    let note_explicit_false = "n-01M3TC5H00MPJG000000000022";
    write(
        dir.path(),
        &format!("people/{ADA}/notes/{note_explicit_false}.md"),
        &format!(
            "---\nid: {note_explicit_false}\ntype: note\ndate: 2026-10-02\nperson: {ADA}\nno-ai: false\n---\nvisible_override_note_token searchabletoken\n"
        ),
    );
    // Un-flagged interaction under a no-ai: notes person -> uncleared.
    let ixn_default = "i-01M3TC5H00MPJG000000000023";
    write(
        dir.path(),
        &format!("interactions/{ixn_default}/interaction.md"),
        &format!(
            "---\nid: {ixn_default}\ntype: interaction\nname: Kickoff\ndate: 2026-10-03\nperson: {ADA}\n---\nhidden_default_ixn_token searchabletoken\n"
        ),
    );
    // Un-flagged deal under a no-ai: notes person -> stays cleared (notes mode scopes to notes + interactions).
    let deal_id = "d-01M3TC5H00MPJG000000000024";
    write(
        dir.path(),
        &format!("deals/{deal_id}/deal.md"),
        &format!(
            "---\nid: {deal_id}\ntype: deal\nname: Renewal\nperson: {ADA}\n---\nvisible_deal_token searchabletoken\n"
        ),
    );

    let vault = load_vault(dir.path()).unwrap();
    assert!(allowlist_is_fixed_point(&vault));

    // find: person profile, explicit-false note, and deal match; un-flagged note and interaction do not.
    let hits = search(&vault, "searchabletoken", &PackScope::All)
        .unwrap()
        .hits;
    let hit_ids: Vec<&str> = hits.iter().filter_map(|h| h.id.as_deref()).collect();
    assert!(
        hit_ids.contains(&ADA),
        "person profile must stay searchable: {hit_ids:?}"
    );
    assert!(
        hit_ids.contains(&note_explicit_false),
        "explicit no-ai: false note must override notes default: {hit_ids:?}"
    );
    assert!(
        hit_ids.contains(&deal_id),
        "deal must stay searchable under notes-mode person: {hit_ids:?}"
    );
    assert!(
        !hit_ids.contains(&note_default),
        "un-flagged note under notes-mode person leaked in find: {hit_ids:?}"
    );
    assert!(
        !hit_ids.contains(&ixn_default),
        "un-flagged interaction under notes-mode person leaked in find: {hit_ids:?}"
    );

    // context: person name and profile are shown; only the explicit-false note is included.
    let ada_id = confidant_core::id::RecordId::parse(ADA).unwrap();
    let ctx = build_context(&vault, &ada_id, true, &PackScope::All, false).unwrap();
    assert_eq!(ctx.person.name.as_deref(), Some("Ada Example"));
    assert!(!ctx.person.no_ai);
    assert!(ctx
        .person
        .profile
        .as_deref()
        .unwrap_or("")
        .contains("Ada profile prose"));
    let ctx_note_ids: Vec<&str> = ctx.notes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ctx_note_ids, vec![note_explicit_false]);
    assert!(ctx.interactions.is_empty(), "{:?}", ctx.interactions);
}

/// #396 (part of #219): a note referencing a conflicted person record
/// reports E_MERGE_CONFLICT on the conflicted file, but NOT a misleading
/// E_DANGLING_REF on the note. The record isn't missing — it just can't
/// be parsed until the conflict is resolved.
#[test]
fn check_conflicted_person_ref_is_not_dangling() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    // ADA's profile carries git conflict markers: unparseable, so ADA
    // never lands in the record set.
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\n<<<<<<< HEAD\nname: Ada\n=======\nname: Ada Lovelace\n>>>>>>> branch\n---\n\nFake person.\n"),
    );
    note(dir.path(), NOTE, ADA, "2026-10-01");
    let json = report_json(dir.path(), None);
    let found = codes(&json);
    assert!(
        found.contains(&"E_MERGE_CONFLICT".to_string()),
        "expected E_MERGE_CONFLICT on the conflicted profile: {json}"
    );
    assert!(
        !found.contains(&"E_DANGLING_REF".to_string()),
        "conflicted target must not report E_DANGLING_REF: {json}"
    );
}

/// #396 control: a genuinely missing record (no conflict markers anywhere)
/// still reports E_DANGLING_REF at error severity.
#[test]
fn check_missing_person_ref_is_still_dangling() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), BEA, "Bea Example");
    // NOTE references GHOST, which has no file at all.
    note(dir.path(), NOTE, GHOST, "2026-10-01");
    let json = report_json(dir.path(), None);
    let dangling: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "E_DANGLING_REF")
        .collect();
    assert_eq!(dangling.len(), 1, "{json}");
    assert_eq!(dangling[0]["severity"], "error", "{json}");
}

/// #396: the suppression covers `with:` references too, not just
/// front-matter `person:`.
#[test]
fn check_conflicted_person_in_with_list_is_not_dangling() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), BEA, "Bea Example");
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\n<<<<<<< HEAD\nname: Ada\n=======\nname: Ada Lovelace\n>>>>>>> branch\n---\n\nFake person.\n"),
    );
    // An interaction whose with: list names the conflicted person.
    write(
        dir.path(),
        &format!("people/{BEA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nperson: {BEA}\ndate: 2026-10-01\nwith:\n  - {ADA}\n---\n\nFake note.\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let found = codes(&json);
    assert!(
        found.contains(&"E_MERGE_CONFLICT".to_string()),
        "expected E_MERGE_CONFLICT on the conflicted profile: {json}"
    );
    assert!(
        !found.contains(&"E_DANGLING_REF".to_string()),
        "conflicted target must not report E_DANGLING_REF: {json}"
    );
}

/// #399: conflict markers confined to the body still parse. The front
/// matter is intact, so ADA stays in the record set: front-matter refs,
/// `with:` lists, and ledger lines referencing ADA all resolve, and the
/// only finding is E_MERGE_CONFLICT on the conflicted profile.
#[test]
fn check_body_only_conflict_keeps_record_and_refs_resolve() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    // Clean front matter; the conflict lives entirely in the body.
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\n<<<<<<< HEAD\nBio A.\n=======\nBio B.\n>>>>>>> branch\n"
        ),
    );
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
    let found = codes(&json);
    assert!(
        found.contains(&"E_MERGE_CONFLICT".to_string()),
        "expected E_MERGE_CONFLICT on the conflicted profile: {json}"
    );
    for code in ["E_DANGLING_REF", "E_UNKNOWN_RECORD", "E_FRONTMATTER"] {
        assert!(
            !found.contains(&code.to_string()),
            "body-only conflict must not cascade into {code}: {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// External packs (#438)
// ---------------------------------------------------------------------------

use confidant_core::packs::dir::read_pack_dir;

/// Vendor a minimal valid external pack into `dir` and return the
/// canonical tree hash the lockfile must pin (all fake data).
fn install_external_pack(root: &Path, name: &str, version: &str, verb: &str) -> String {
    install_external_pack_with_manifest(
        root,
        name,
        version,
        &format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["W_{GREET_CODE}"]

[pack]
name = "{name}"
version = "{version}"
skill = "SKILL.md"
requires_spec = ["0.1"]

[messages."W_{GREET_CODE}"]
default = "stale greeting"

[[verbs]]
name = "{verb}"
"#,
            GREET_CODE = "GREET_STALE",
        ),
        &format!("# {name} pack.\n\nVerb `{verb}`: fake skill text.\n"),
    )
}

/// Vendor a pack from an explicit manifest and skill body; returns the
/// canonical tree hash for the pin. Panics when the fixture itself is
/// invalid — use [`unusable_external_pack_hash`] for a manifest that is
/// expected to be refused.
fn install_external_pack_with_manifest(
    root: &Path,
    name: &str,
    version: &str,
    manifest: &str,
    skill: &str,
) -> String {
    let pack_dir = root.join(format!("packs/{name}@{version}"));
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        root,
        &format!("packs/{name}@{version}/manifest.toml"),
        manifest,
    );
    write(root, &format!("packs/{name}@{version}/SKILL.md"), skill);
    write(
        root,
        &format!("packs/{name}@{version}/{version}.md"),
        "Fake pack notes.\n",
    );
    read_pack_dir(&pack_dir)
        .expect("fixture pack dir must read")
        .hash
}

/// A well-formed but unusable pin for a fixture whose manifest is expected
/// to be refused: `read_pack_dir` rejects the pack before any hash compare,
/// so the value only has to look like `sha256:<64 hex>`.
fn unusable_external_pack_hash() -> String {
    format!("sha256:{}", "0".repeat(64))
}

/// Write a lockfile pinning `name@version` to `hash`.
fn install_lockfile(root: &Path, name: &str, version: &str, hash: &str) {
    write(
        root,
        "confidant.lock",
        &format!(
            "lock_version = 1\n\n[[pack]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"https://example.invalid/org/{name}.git\"\nrev = \"0123456789abcdef0123456789abcdef01234567\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    );
}

/// confidant.toml listing both the compiled pack and the external one.
fn external_vault_toml(root: &Path, packs: &str, checks: &str) {
    write(
        root,
        "confidant.toml",
        &format!(
            r#"spec = "0.1"
packs = [{packs}]
vault_id = "test-vault"

[checks]
as_of = "2026-10-08"
{checks}
"#
        ),
    );
}

/// #438: a vault listing an installed, hash-valid external pack checks
/// clean; the pack's verbs and fields are owned by it exactly like a
/// compiled pack's claims.
#[test]
fn external_pack_installed_checks_clean() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-05 greet {ADA} kind:wave\n"),
    );
    let hash = install_external_pack(dir.path(), "example-pack", "0.1", "greet");
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");

    let json = report_json(dir.path(), None);
    assert!(json["ok"].as_bool().unwrap(), "expected clean: {json}");
    assert!(codes(&json).is_empty(), "{json:?}");
    assert_eq!(json["summary"]["records"].as_u64().unwrap(), 1);
}

/// #438/#449: a `[[pack]]` claim that collides with an enabled pack is
/// `E_PACK_CONFLICT` — conflict detection spans built-in and external
/// packs exactly as PD8 says. The built-in personal pack is implicit, so
/// its `title` field is always claimed (core verbs are refused at load by
/// the manifest loader, see `external_rejects_core_verb`).
#[test]
fn external_pack_claiming_enabled_field_is_a_conflict() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    // Vendor a pack whose field collides with personal's `title`.
    let pack_dir = dir.path().join("packs/example-pack@0.1");
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        dir.path(),
        "packs/example-pack@0.1/manifest.toml",
        r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["W_EXAMPLE_CODE", "E_FRONTMATTER"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[messages."W_EXAMPLE_CODE"]
default = "stale"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[[fields]]
name = "title"
grammar = "non-empty-string"
"#,
    );
    write(
        dir.path(),
        "packs/example-pack@0.1/SKILL.md",
        "# example pack.\n",
    );
    let hash = read_pack_dir(&pack_dir)
        .expect("fixture pack dir must read")
        .hash;
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");

    let json = report_json(dir.path(), None);
    let found = codes(&json);
    // The claim collides with personal's `title`: E_PACK_CONFLICT, and
    // the pack set is incoherent (nothing folds).
    assert!(
        found.contains(&"E_PACK_CONFLICT".to_string()),
        "an enabled-pack field collision must be E_PACK_CONFLICT: {json}"
    );
}

/// #438/#490: each failure kind reports its own stable code, and the
/// message names the failing `name@version` exactly as listed in
/// `confidant.toml`; `E_PACK_HASH`/`E_PACK_INVALID` also point at the
/// vendored path in `file`. Record/ledger free text still never echoes.
#[test]
fn external_pack_malformed_id_does_not_echo() {
    // A listed id that is not `name@version` is operator free text, not a
    // pin: it must stay out of findings even though the pin carve-out
    // (#490) lets a real pin echo.
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    external_vault_toml(dir.path(), "\"justaname\"", "");
    let json = report_json(dir.path(), None);
    let unknown = finding_by_code(&json, "E_PACK_UNKNOWN");
    assert!(
        unknown["message"]
            .as_str()
            .unwrap()
            .contains("name@version"),
        "{}",
        unknown["message"]
    );
    let dumped = serde_json::to_string(&json).unwrap();
    assert!(
        !dumped.contains("justaname"),
        "malformed id echoed: {dumped}"
    );

    // #501: an entry with an `@` but no real pin shape is still free text.
    // The loose check (`@` with both halves non-empty) echoed an email and
    // anything with a newline; only a valid pack name plus a version-like
    // half may echo.
    external_vault_toml(
        dir.path(),
        r#""zxqvleakmail@example.com", "zxqvleak-nl\nname@0.1", "zxqvleak-nl2@0.1\nleak""#,
        "",
    );
    let json = report_json(dir.path(), None);
    let dumped = serde_json::to_string(&json).unwrap();
    for leak in ["zxqvleakmail", "example.com", "zxqvleak-nl", "zxqvleak-nl2"] {
        assert!(!dumped.contains(leak), "{leak} leaked in {dumped}");
    }
    let unknown: Vec<&Value> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "E_PACK_UNKNOWN")
        .collect();
    assert_eq!(
        unknown.len(),
        3,
        "all malformed entries must report: {json}"
    );
    for finding in unknown {
        assert_eq!(
            finding["message"].as_str().unwrap(),
            "a pack listed in confidant.toml is not a name@version pin",
            "not a pin, so no name may echo: {finding}"
        );
        assert_eq!(finding["file"].as_str().unwrap(), "confidant.toml");
    }
}

/// #612: the `E_PACK_UNKNOWN` fix for a real pin names the CLI commands that
/// actually recover the state — `pack remove` keys off the listing (and the
/// vendored tree) when the lock has no entry, and `pack add --yes` may
/// re-pin — not a command that refuses. A non-pin listing stays name-free.
#[test]
fn pack_unknown_fix_names_the_recovery_commands() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", DEFAULT_CHECKS);
    let json = report_json(dir.path(), None);
    let fix = finding_by_code(&json, "E_PACK_UNKNOWN")["fix"]
        .as_str()
        .unwrap();
    assert!(fix.contains("confidant pack remove"), "{fix}");
    assert!(fix.contains("confidant pack add"), "{fix}");
    assert!(fix.contains("example-pack"), "{fix}");

    // A malformed listing is operator free text: neither the message nor the
    // fix may echo it, and the fix does not point at a pack command.
    external_vault_toml(dir.path(), "\"zxqvleakmail@example.com\"", DEFAULT_CHECKS);
    let json = report_json(dir.path(), None);
    let fixed = &finding_by_code(&json, "E_PACK_UNKNOWN")["fix"];
    let dumped = serde_json::to_string(&json).unwrap();
    assert!(!dumped.contains("zxqvleakmail"), "{dumped}");
    assert!(
        !fixed.as_str().unwrap().contains("confidant pack remove"),
        "{fixed}"
    );
}

#[test]
fn external_pack_problems_report_their_codes() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    // A ledger line the external pack would own: while the pack fails to
    // load but its manifest still parses, the verb stays known
    // (spec/pack-lock.md §5) — no E_UNKNOWN_VERB cascade.
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-05 greet {ADA} kind:wave\n"),
    );
    let hash = install_external_pack(dir.path(), "example-pack", "0.1", "greet");
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");

    // Hash mismatch: vendored file edited after install.
    write(
        dir.path(),
        "packs/example-pack@0.1/SKILL.md",
        "# tampered skill.\n",
    );
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_HASH".to_string()),
        "{json:?}"
    );
    let hash_finding = finding_by_code(&json, "E_PACK_HASH");
    assert_eq!(
        hash_finding["message"].as_str().unwrap(),
        "external pack example-pack@0.1's vendored files do not match its lockfile pin"
    );
    assert_eq!(
        hash_finding["file"].as_str().unwrap(),
        "packs/example-pack@0.1"
    );
    assert!(
        !codes(&json).contains(&"E_UNKNOWN_VERB".to_string()),
        "the manifest still parses, so its verbs stay known: {json:?}"
    );

    // Missing vendored dir.
    fs::remove_dir_all(dir.path().join("packs/example-pack@0.1")).unwrap();
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_HASH".to_string()),
        "{json:?}"
    );
    assert_eq!(
        finding_by_code(&json, "E_PACK_HASH")["file"]
            .as_str()
            .unwrap(),
        "packs/example-pack@0.1"
    );

    // No lockfile pin at all (confidant.toml lists it).
    fs::remove_file(dir.path().join("confidant.lock")).unwrap();
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_UNKNOWN".to_string()),
        "{json:?}"
    );
    let unknown_finding = finding_by_code(&json, "E_PACK_UNKNOWN");
    assert_eq!(
        unknown_finding["message"].as_str().unwrap(),
        "external pack example-pack@0.1 listed in confidant.toml has no lockfile pin"
    );
    assert_eq!(unknown_finding["file"].as_str().unwrap(), "confidant.toml");

    // Invalid: an unlisted file inside the vendored dir (PD7).
    let hash = install_external_pack(dir.path(), "example-pack", "0.1", "greet");
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    write(
        dir.path(),
        "packs/example-pack@0.1/bin/run.sh",
        "#!/bin/sh\n",
    );
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_INVALID".to_string()),
        "{json:?}"
    );
    let invalid_finding = finding_by_code(&json, "E_PACK_INVALID");
    assert_eq!(
        invalid_finding["message"].as_str().unwrap(),
        "external pack example-pack@0.1's manifest or contents fail validation"
    );
    assert_eq!(
        invalid_finding["file"].as_str().unwrap(),
        "packs/example-pack@0.1"
    );
    // Cleanup for the next case: remove the unlisted file.
    fs::remove_file(dir.path().join("packs/example-pack@0.1/bin/run.sh")).unwrap();
    fs::remove_dir(dir.path().join("packs/example-pack@0.1/bin")).unwrap();

    // Wrong spec listed in the manifest (reinstall with mismatched pin).
    let pack_dir = dir.path().join("packs/example-pack@0.1");
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        dir.path(),
        "packs/example-pack@0.1/manifest.toml",
        r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["W_GREET_STALE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["9.9"]

[messages."W_GREET_STALE"]
default = "stale greeting"

[[verbs]]
name = "greet"
"#,
    );
    write(
        dir.path(),
        "packs/example-pack@0.1/SKILL.md",
        "# example pack.\n",
    );
    let hash = read_pack_dir(&pack_dir).unwrap().hash;
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_VERSION".to_string()),
        "{json:?}"
    );
    let version_finding = finding_by_code(&json, "E_PACK_VERSION");
    assert_eq!(
        version_finding["message"].as_str().unwrap(),
        "external pack example-pack@0.1's spec compatibility does not include this vault"
    );
    assert_eq!(version_finding["file"].as_str().unwrap(), "confidant.toml");
}

/// #438: the vault scanner never treats `packs/**` as records — a
/// person-shaped file inside a vendored pack is pack data, never a
/// record.
#[test]
fn packs_dir_contents_are_not_records() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    let hash = install_external_pack(dir.path(), "example-pack", "0.1", "greet");
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");
    // A person-shaped file inside the vendored pack.
    write(
        dir.path(),
        "packs/example-pack@0.1/samples/fake-person.md",
        "---\nid: p-01J9Z3K4QF0000000000000001\ntype: person\nname: Not A Record\n---\n\nNot a record.\n",
    );
    // Recompute the hash: the extra file changes it (and gets refused as
    // an unlisted file, PD7) — so this fixture uses a directory that
    // would fail load; the assertion is that the vault STILL checks
    // clean of records: the pack is E_PACK_INVALID (extra file) but the
    // file is never parsed as a record.
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    let json = report_json(dir.path(), None);
    assert_eq!(
        json["summary"]["records"].as_u64().unwrap(),
        1,
        "packs/** must not load as records: {json:?}"
    );
    let dumped = serde_json::to_string(&json).unwrap();
    assert!(
        !dumped.contains("Not A Record"),
        "pack contents must not leak: {dumped}"
    );
}

/// #441: a manifest declaring an unknown rule kind fails the pack at
/// load; through `check` that is one `E_PACK_INVALID` finding and the
/// pack is not folded (PD12). The vendored manifest does not parse, so
/// per spec/pack-lock.md §5 its verbs cannot be known and the ledger
/// verb cascades into `E_UNKNOWN_VERB` — asserted here to pin that
/// behavior (the no-cascade case is the hash-mismatch one in
/// `external_pack_problems_report_their_codes`).
#[test]
fn external_pack_unknown_rule_kind_reports_pack_invalid() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-05 greet {ADA} kind:wave\n"),
    );
    let pack_dir = dir.path().join("packs/example-pack@0.1");
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        dir.path(),
        "packs/example-pack@0.1/manifest.toml",
        r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["W_GREET_STALE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.severity]]
key = "example-pack.test_rule"
default = "warning"

[[rules]]
id = "my_rule"
kind = "nope"
code = "W_GREET_STALE"
severity_key = "example-pack.test_rule"

[messages."W_GREET_STALE"]
default = "stale greeting"
"#,
    );
    write(
        dir.path(),
        "packs/example-pack@0.1/SKILL.md",
        "# example pack.\n",
    );
    // read_pack_dir validates the manifest too, so the fixture hash is
    // irrelevant: the loader hits the same unknown-kind error first.
    // The pin itself must stay well-formed (64 hex) so the lockfile
    // parses and the failure is the rule kind, not the pin.
    let hash = read_pack_dir(&pack_dir)
        .map(|p| p.hash)
        .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");

    let json = report_json(dir.path(), None);
    let found = codes(&json);
    assert!(
        found.contains(&"E_PACK_INVALID".to_string()),
        "unknown rule kind must be E_PACK_INVALID: {json:?}"
    );
    // The manifest cannot parse, so its verbs are unknown (§5): the
    // cascade is expected and pinned here.
    assert!(
        found.contains(&"E_UNKNOWN_VERB".to_string()),
        "an unparseable manifest's verbs cannot be known: {json:?}"
    );
}

/// #445 (PD8 rules 1-4), re-asserted through `check`: a pack that claims a
/// core verb, a core edge kind or a core finding code is refused at load,
/// so the vault reports one `E_PACK_INVALID` and the pack folds nothing.
/// The forged core code must never surface as a finding.
#[test]
fn external_pack_cannot_claim_core_verb_edge_or_code() {
    let make_manifest = |claims: &str, codes: &str, messages: &str| {
        format!(
            "manifest_version = 2\n\
             record_types = []\n\
             balance_metrics = []\n\
             finding_codes = [{codes}]\n\
             \n\
             [pack]\n\
             name = \"example-pack\"\n\
             version = \"0.1\"\n\
             skill = \"SKILL.md\"\n\
             requires_spec = [\"0.1\"]\n\
             {claims}\n\
             {messages}\n"
        )
    };
    let own_messages = "[messages.\"W_EXAMPLE_CODE\"]\ndefault = \"example\"\n";
    let cases = [
        (
            "core verb",
            make_manifest(
                "[[verbs]]\nname = \"touch\"\n",
                "\"W_EXAMPLE_CODE\"",
                own_messages,
            ),
        ),
        (
            "core edge kind",
            make_manifest(
                "[[edge_kinds]]\nname = \"married\"\nsymmetric = true\n",
                "\"W_EXAMPLE_CODE\"",
                own_messages,
            ),
        ),
        (
            "core finding code",
            make_manifest(
                "",
                "\"E_PACK_HASH\"",
                "[messages.\"E_PACK_HASH\"]\ndefault = \"forged\"\n",
            ),
        ),
    ];
    for (label, manifest) in cases {
        let dir = tempfile::tempdir().unwrap();
        person(dir.path(), ADA, "Ada Example");
        install_external_pack_raw(dir.path(), "example-pack", "0.1", &manifest);
        install_lockfile(
            dir.path(),
            "example-pack",
            "0.1",
            &unusable_external_pack_hash(),
        );
        external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");

        let json = report_json(dir.path(), None);
        assert!(
            codes(&json).contains(&"E_PACK_INVALID".to_string()),
            "{label} claim must be E_PACK_INVALID: {json:?}"
        );
        // The pack's claimed code never fires (a forged core code would be
        // the dangerous case).
        assert!(
            !codes(&json).contains(&"E_PACK_HASH".to_string()),
            "a pack's forged core code must never surface: {json:?}"
        );
    }
}

/// #445 (PD8 rule 6): a rule parameter may only name one of the pack's own
/// declared fields. Through `check` an installed pack whose rule names an
/// undeclared field is refused at load (`E_PACK_INVALID`) and its rule
/// never runs.
#[test]
fn external_pack_rules_cannot_name_undeclared_field() {
    let dir = tempfile::tempdir().unwrap();
    person_with_cadence(dir.path(), ADA);
    let hash = install_external_pack_with_manifest(
        dir.path(),
        "example-pack",
        "0.1",
        r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_CADENCE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.severity]]
key = "example-pack.cadence_overdue"
default = "warning"

[[fields]]
name = "cadence"
grammar = "cadence"

[[rules]]
id = "cadence"
kind = "cadence-overdue"
code = "W_EXAMPLE_CADENCE"
severity_key = "example-pack.cadence_overdue"
cadence_field = "ghost"
event_verbs = ["touch"]

[messages."W_EXAMPLE_CADENCE"]
last = "person {id} has no touchpoint on or after {start} (last was {d}, cadence {cadence_days}d)"
last_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
none = "person {id} has no touchpoint logged (cadence {cadence_days}d)"
none_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"
"#,
        "# example pack.\n\nCadence rule (fake).\n",
    );
    install_lockfile(dir.path(), "example-pack", "0.1", &hash);
    external_vault_toml(dir.path(), "\"example-pack@0.1\"", "");

    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_INVALID".to_string()),
        "an undeclared field in a rule must be E_PACK_INVALID: {json:?}"
    );
    assert!(
        !codes(&json).contains(&"W_EXAMPLE_CADENCE".to_string()),
        "a refused rule must never run: {json:?}"
    );
}

/// Write a pack directory verbatim (no validation): for fixtures whose
/// manifest is expected to be refused by `read_pack_dir`. Fake data only.
fn install_external_pack_raw(root: &Path, name: &str, version: &str, manifest: &str) {
    write(
        root,
        &format!("packs/{name}@{version}/manifest.toml"),
        manifest,
    );
    write(
        root,
        &format!("packs/{name}@{version}/SKILL.md"),
        "# example pack.\n",
    );
}

// ---------------------------------------------------------------------------
// Declarative rule kind: cadence-overdue (#442)
// ---------------------------------------------------------------------------

/// Vendor a declarative pack whose cadence rule mirrors the built-in
/// personal pack's, and return the lockfile hash for it. It claims its own
/// `example_cadence` field so it can coexist with the implicit personal
/// pack (#551).
fn install_cadence_pack(root: &Path) -> String {
    let pack_dir = root.join("packs/example-pack@0.1");
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        root,
        "packs/example-pack@0.1/manifest.toml",
        r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_CADENCE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.severity]]
key = "example-pack.cadence_overdue"
default = "warning"

[[fields]]
name = "example_cadence"
grammar = "cadence"

[[rules]]
id = "cadence"
kind = "cadence-overdue"
code = "W_EXAMPLE_CADENCE"
severity_key = "example-pack.cadence_overdue"
cadence_field = "example_cadence"
event_verbs = ["touch", "session"]

[messages."W_EXAMPLE_CADENCE"]
last = "person {id} has no touchpoint on or after {start} (last was {d}, cadence {cadence_days}d)"
last_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
none = "person {id} has no touchpoint logged (cadence {cadence_days}d)"
none_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"
"#,
    );
    write(
        root,
        "packs/example-pack@0.1/SKILL.md",
        "# example pack.\n\nCadence rule (fake).\n",
    );
    read_pack_dir(&pack_dir)
        .expect("fixture pack dir must read")
        .hash
}

/// Run `check` over a person with a cadence field and the given ledger
/// (per monthly file), twice: once through the built-in personal pack, once
/// through the declarative pack above. The
/// `W_CADENCE_OVERDUE` findings — code, severity, message, fix, file,
/// id — must match exactly; that is the parity the declarative kind
/// promises (#442). Everything else in each report legitimately
/// differs (the built-in run sees personal's `cadence`; the declarative run
/// sees the example pack's `example_cadence`, so neither pack's rule
/// double-fires).
fn assert_cadence_parity(
    ledger_files: &[(&str, String)],
    operator_personal: &str,
    operator_declarative: &str,
    ada_has_cadence: bool,
    extra_setup: impl Fn(&Path),
) -> (Value, Value) {
    let setup = |root: &Path, packs: &str, operator: &str, declarative: bool| -> Value {
        write(
            root,
            "confidant.toml",
            &PERSONAL_TOML
                .replace("packs = [\"personal@0.1\"]", &format!("packs = [{packs}]"))
                .replace(
                    "as_of = \"2026-10-08\"",
                    &format!("as_of = \"2026-10-08\"\n{operator}"),
                ),
        );
        if ada_has_cadence {
            person_with_cadence(root, ADA);
        } else {
            // Ada still exists as a record, just without a `cadence` value,
            // so the rule must take it from a merged member (the find_map
            // fallback) rather than skipping a missing canonical person.
            person_without_cadence(root, ADA);
        }
        for (rel, content) in ledger_files {
            write(root, rel, content);
        }
        if declarative {
            let hash = install_cadence_pack(root);
            install_lockfile(root, "example-pack", "0.1", &hash);
        }
        extra_setup(root);
        if declarative {
            // The fixture pack claims its own cadence field so it does not
            // collide with the implicit built-in personal pack (#551),
            // which always claims `cadence`.
            rewrite_profile_field(root, ADA, "cadence:", "example_cadence:");
            rewrite_profile_field(root, BEA, "cadence:", "example_cadence:");
        }
        report_json(root, None)
    };
    let personal = setup(
        tempfile::tempdir().unwrap().path(),
        "\"personal@0.1\"",
        operator_personal,
        false,
    );
    let dir2 = tempfile::tempdir().unwrap();
    let declarative = setup(
        dir2.path(),
        "\"example-pack@0.1\"",
        operator_declarative,
        true,
    );

    // Parity covers code-agnostic content: severity, message, fix,
    // file, id. The code itself is pack-own on the declarative side by
    // design (the #494 review refuses a builtin as a rule's code);
    // whether the declarative copies may emit the shipped codes
    // verbatim is Frank's call (#490), and #444 depends on it.
    let cadence_findings = |v: &Value| -> Vec<String> {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["code"] == "W_CADENCE_OVERDUE" || f["code"] == "W_EXAMPLE_CADENCE")
            .map(|f| {
                format!(
                    "{}/{}/{}/{}/{:?}",
                    f["severity"], f["message"], f["fix"], f["file"], f["id"]
                )
            })
            .collect()
    };
    assert_eq!(
        cadence_findings(&personal),
        cadence_findings(&declarative),
        "declarative parity failed:\npersonal: {personal:?}\ndeclarative: {declarative:?}"
    );
    (personal, declarative)
}

/// Person record with the pack's cadence field.
fn person_with_cadence(root: &Path, id: &str) {
    write(
        root,
        &format!("people/{id}/profile.md"),
        &format!(
            "---\nid: {id}\ntype: person\nname: Ada Example\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
}

/// Person record without the pack's cadence field: the merged-member
/// fallback has to supply it, or the person is skipped.
fn person_without_cadence(root: &Path, id: &str) {
    write(
        root,
        &format!("people/{id}/profile.md"),
        &format!("---\nid: {id}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
    );
}

/// Rename one front-matter key in a person's profile, when the file exists.
/// Used to give a parity fixture pack its own non-colliding field name
/// (#551) without duplicating every fixture writer.
fn rewrite_profile_field(root: &Path, id: &str, from: &str, to: &str) {
    let path = root.join(format!("people/{id}/profile.md"));
    if let Ok(text) = fs::read_to_string(&path) {
        let out = text.replace(&format!("\n{from}"), &format!("\n{to}"));
        fs::write(&path, out).unwrap();
    }
}

#[test]
fn cadence_rule_overdue_with_last_contact() {
    // Last touch 40 days before as_of (2026-10-08): overdue, `last`
    // variant, start = as_of - 30d.
    let ledger = vec![(
        "ledger/2026/08.cfd",
        format!("2026-08-29 touch {ADA} call\n"),
    )];
    let (personal, _) = assert_cadence_parity(&ledger, "", "", true, |_| {});
    let findings = personal["findings"].as_array().unwrap();
    let overdue: Vec<&Value> = findings
        .iter()
        .filter(|f| f["code"] == "W_CADENCE_OVERDUE")
        .collect();
    assert_eq!(overdue.len(), 1, "{personal:?}");
    assert_eq!(overdue[0]["severity"], "warning");
    assert_eq!(
        overdue[0]["code"], "W_CADENCE_OVERDUE",
        "shipped side keeps the builtin code"
    );
    let message = overdue[0]["message"].as_str().unwrap();
    assert!(
        message.contains("2026-09-08") && message.contains("2026-08-29") && message.contains("30d"),
        "start = as_of - cadence, d = last: {message}"
    );
}

#[test]
fn cadence_rule_overdue_no_contact() {
    // No touchpoint at all: the `none` variant.
    let (personal, _) = assert_cadence_parity(&[], "", "", true, |_| {});
    let findings = personal["findings"].as_array().unwrap();
    let overdue: Vec<&Value> = findings
        .iter()
        .filter(|f| f["code"] == "W_CADENCE_OVERDUE")
        .collect();
    assert_eq!(overdue.len(), 1, "{personal:?}");
    assert!(
        overdue[0]["message"]
            .as_str()
            .unwrap()
            .contains("has no touchpoint logged"),
        "none variant: {personal:?}"
    );
}

#[test]
fn cadence_rule_exactly_on_boundary_not_overdue() {
    // as_of - last == 30 exactly: inside the window (not overdue).
    let ledger = vec![(
        "ledger/2026/09.cfd",
        format!("2026-09-08 touch {ADA} call\n"),
    )];
    let (personal, _) = assert_cadence_parity(&ledger, "", "", true, |_| {});
    assert!(
        !codes(&personal)
            .iter()
            .any(|c| c == "W_CADENCE_OVERDUE" || c == "W_EXAMPLE_CADENCE"),
        "{personal:?}"
    );
}

#[test]
fn cadence_rule_session_counts_as_contact() {
    // event_verbs includes session: a session within the window
    // suppresses the nudge (#227 Q2).
    let ledger = vec![(
        "ledger/2026/10.cfd",
        format!("2026-10-02 session {ADA} 60m paid\n"),
    )];
    let (personal, _) = assert_cadence_parity(&ledger, "", "", true, |_| {});
    assert!(
        !codes(&personal)
            .iter()
            .any(|c| c == "W_CADENCE_OVERDUE" || c == "W_EXAMPLE_CADENCE"),
        "{personal:?}"
    );
}

#[test]
fn cadence_rule_merged_person_uses_merged_cadence_and_contact() {
    // Bea (the merged member) holds the cadence and the only contact, and
    // that contact is 40 days before as_of (2026-10-08): overdue. Ada
    // (canonical) has a profile but no `cadence`, so the finding can only
    // come from the find_map fallback taking Bea's cadence — if that
    // branch were deleted, Ada would be skipped and nothing would fire.
    let ledger = vec![
        (
            "ledger/2026/08.cfd",
            format!("2026-08-29 touch {BEA} call\n"),
        ),
        (
            "ledger/2026/10.cfd",
            format!("2026-10-01 merge {BEA} into {ADA}\n"),
        ),
    ];
    let (personal, _) = assert_cadence_parity(&ledger, "", "", false, |root| {
        write(
            root,
            &format!("people/{BEA}/profile.md"),
            &format!(
                "---\nid: {BEA}\ntype: person\nname: Bea Demo\ncadence: 30d\n---\n\nFake person.\n"
            ),
        );
    });
    let overdue: Vec<&Value> = personal["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "W_CADENCE_OVERDUE")
        .collect();
    assert_eq!(overdue.len(), 1, "{personal:?}");
    assert_eq!(overdue[0]["id"], ADA);
    let message = overdue[0]["message"].as_str().unwrap();
    assert!(
        message.contains("2026-09-08") && message.contains("2026-08-29"),
        "fallback cadence -> start = as_of - 30d, d = Bea's touch: {message}"
    );
}

#[test]
fn cadence_rule_merged_person_recent_contact_not_overdue() {
    // Same merged shape, but Bea's touch is inside the 30d window: the
    // fallback cadence applies and nothing is overdue.
    let ledger = vec![(
        "ledger/2026/10.cfd",
        format!("2026-10-01 merge {BEA} into {ADA}\n2026-10-03 touch {BEA} call\n"),
    )];
    let (personal, _) = assert_cadence_parity(&ledger, "", "", false, |root| {
        write(
            root,
            &format!("people/{BEA}/profile.md"),
            &format!(
                "---\nid: {BEA}\ntype: person\nname: Bea Demo\ncadence: 30d\n---\n\nFake person.\n"
            ),
        );
    });
    assert!(
        !codes(&personal)
            .iter()
            .any(|c| c == "W_CADENCE_OVERDUE" || c == "W_EXAMPLE_CADENCE"),
        "{personal:?}"
    );
}

#[test]
fn cadence_rule_severity_off_and_error_from_config() {
    // `off` skips the rule; `error` escalates it — the same override
    // keys work for the declarative pack as for the compiled one, and
    // the parity helper proves the shipped analogue behaves the same.
    let ledger = vec![(
        "ledger/2026/08.cfd",
        format!("2026-08-29 touch {ADA} call\n"),
    )];

    let (personal_off, _) = assert_cadence_parity(
        &ledger,
        "personal.cadence_overdue = \"off\"\n",
        "example-pack.cadence_overdue = \"off\"\n",
        true,
        |_| {},
    );
    assert!(codes(&personal_off).is_empty(), "{personal_off:?}");

    let (personal_err, _) = assert_cadence_parity(
        &ledger,
        "personal.cadence_overdue = \"error\"\n",
        "example-pack.cadence_overdue = \"error\"\n",
        true,
        |_| {},
    );
    let findings = personal_err["findings"].as_array().unwrap();
    assert_eq!(findings[0]["severity"], "error", "{personal_err:?}");
}

// ---------------------------------------------------------------------------
// Declarative rule kind: date-upcoming (#443)
// ---------------------------------------------------------------------------

/// Vendor a declarative pack whose date rule mirrors the built-in personal
/// pack's, with its own `example_birthday` / `example_dates` fields so it
/// can coexist with the implicit personal pack (#551), with the
/// `example-pack.date_upcoming_days` window default given. Returns the
/// lockfile hash.
fn install_date_pack(root: &Path, window_default: i64) -> String {
    let pack_dir = root.join("packs/example-pack@0.1");
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        root,
        "packs/example-pack@0.1/manifest.toml",
        &format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_DATE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "example_birthday"
grammar = "recurring-date"

[[fields]]
name = "example_dates"
grammar = "dates-list"

[[checks.severity]]
key = "example-pack.date_upcoming"
default = "warning"

[[checks.int]]
key = "example-pack.date_upcoming_days"
default = {window_default}

[[rules]]
id = "dates"
kind = "date-upcoming"
code = "W_EXAMPLE_DATE"
severity_key = "example-pack.date_upcoming"
date_fields = ["example_birthday", "example_dates"]
window_key = "example-pack.date_upcoming_days"

[messages."W_EXAMPLE_DATE"]
default = "upcoming date for {{id}} on {{occ}} (in {{delta}}d)"
default_fix = "Reach out to {{id}} or set `[checks] personal.date_upcoming = \"off\"`"

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"
"#
        ),
    );
    write(
        root,
        "packs/example-pack@0.1/SKILL.md",
        "# example pack.\n\nDate rule (fake).\n",
    );
    read_pack_dir(&pack_dir)
        .expect("fixture pack dir must read")
        .hash
}

/// Run `check` over a person with the given front-matter fields, on two
/// vaults: the built-in personal pack and the declarative pack above, both at
/// `as_of`. The `W_DATE_UPCOMING` findings — code-agnostic content
/// (severity, message, fix, file, id) — must match exactly; the code itself
/// stays pack-own on the declarative side by design (#494/#490), exactly as
/// #442's cadence parity documents. Returns both reports.
fn assert_date_parity(
    as_of: &str,
    person_fields: &str,
    operator_personal: &str,
    operator_declarative: &str,
    window_default: i64,
) -> (Value, Value) {
    let setup = |root: &Path, packs: &str, operator: &str, declarative: bool| -> Value {
        write(
            root,
            "confidant.toml",
            &PERSONAL_TOML
                .replace("packs = [\"personal@0.1\"]", &format!("packs = [{packs}]"))
                .replace(
                    "as_of = \"2026-10-08\"",
                    &format!("as_of = \"{as_of}\"\n{operator}"),
                ),
        );
        write(
            root,
            &format!("people/{ADA}/profile.md"),
            &format!(
                "---\nid: {ADA}\ntype: person\nname: Ada Example\n{person_fields}---\n\nFake person.\n"
            ),
        );
        if declarative {
            // The fixture pack claims its own date fields so it does not
            // collide with the implicit built-in personal pack (#551).
            rewrite_profile_field(root, ADA, "birthday:", "example_birthday:");
            rewrite_profile_field(root, ADA, "dates:", "example_dates:");
            let hash = install_date_pack(root, window_default);
            install_lockfile(root, "example-pack", "0.1", &hash);
        }
        report_json(root, None)
    };
    let personal = setup(
        tempfile::tempdir().unwrap().path(),
        "\"personal@0.1\"",
        operator_personal,
        false,
    );
    let dir2 = tempfile::tempdir().unwrap();
    let declarative = setup(
        dir2.path(),
        "\"example-pack@0.1\"",
        operator_declarative,
        true,
    );

    let date_findings = |v: &Value| -> Vec<String> {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["code"] == "W_DATE_UPCOMING" || f["code"] == "W_EXAMPLE_DATE")
            .map(|f| {
                format!(
                    "{}/{}/{}/{}/{:?}",
                    f["severity"], f["message"], f["fix"], f["file"], f["id"]
                )
            })
            .collect()
    };
    assert_eq!(
        date_findings(&personal),
        date_findings(&declarative),
        "declarative parity failed:\npersonal: {personal:?}\ndeclarative: {declarative:?}"
    );
    (personal, declarative)
}

/// The `W_DATE_UPCOMING` findings of a compiled-personal report.
fn date_upcoming(v: &Value) -> Vec<&Value> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "W_DATE_UPCOMING")
        .collect()
}

#[test]
fn date_rule_birthday_inside_window() {
    // `--10-20` seen from 2026-10-16 with a 7-day window: delta 4.
    let (personal, _) = assert_date_parity("2026-10-16", "birthday: --10-20\n", "", "", 7);
    let findings = date_upcoming(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert_eq!(findings[0]["severity"], "warning");
    let message = findings[0]["message"].as_str().unwrap();
    assert!(
        message.contains("2026-10-20") && message.contains("(in 4d)"),
        "occ = next occurrence, delta = days away: {message}"
    );
}

#[test]
fn date_rule_birthday_outside_window() {
    // `--10-28` is 12 days out: outside the default 7-day window.
    let (personal, _) = assert_date_parity("2026-10-16", "birthday: --10-28\n", "", "", 7);
    assert!(date_upcoming(&personal).is_empty(), "{personal:?}");
}

#[test]
fn date_rule_today_is_delta_zero() {
    // The date is today: `delta = 0` is inside the window (inclusive).
    let (personal, _) = assert_date_parity("2026-10-16", "birthday: --10-16\n", "", "", 7);
    let findings = date_upcoming(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert!(
        findings[0]["message"].as_str().unwrap().contains("(in 0d)"),
        "{personal:?}"
    );
}

#[test]
fn date_rule_year_wrap() {
    // `--01-02` seen from 2026-12-30: next occurrence is 2027-01-02, three
    // days out and inside the 7-day window.
    let (personal, _) = assert_date_parity("2026-12-30", "birthday: --01-02\n", "", "", 7);
    let findings = date_upcoming(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    let message = findings[0]["message"].as_str().unwrap();
    assert!(
        message.contains("2027-01-02") && message.contains("(in 3d)"),
        "year wrap: {message}"
    );
}

#[test]
fn date_rule_leap_day_in_non_leap_year() {
    // `--02-29` seen from 2026-02-27: the next occurrence is 2028-02-29
    // (well outside a 7-day window). The oracle is the shared parser, so
    // the kind cannot diverge from `RecurringDate`.
    use confidant_core::packs::grammars::RecurringDate;
    let oracle = RecurringDate::parse("birthday", "--02-29")
        .unwrap()
        .next_occurrence_on_or_after(chrono::NaiveDate::from_ymd_opt(2026, 2, 27).unwrap());
    assert_eq!(
        oracle,
        Some(chrono::NaiveDate::from_ymd_opt(2028, 2, 29).unwrap())
    );
    let (personal, _) = assert_date_parity("2026-02-27", "birthday: --02-29\n", "", "", 7);
    assert!(date_upcoming(&personal).is_empty(), "{personal:?}");
}

#[test]
fn date_rule_dates_list_multiple_entries() {
    // Two entries inside a 14-day window: one finding each, in
    // field order (the list order), deterministically.
    let (personal, _) = assert_date_parity(
        "2026-10-16",
        "dates: [anniv:2020-10-18, grad:--10-30]\n",
        "personal.date_upcoming_days = 14\n",
        "",
        14,
    );
    let findings = date_upcoming(&personal);
    assert_eq!(findings.len(), 2, "{personal:?}");
    let messages: Vec<&str> = findings
        .iter()
        .map(|f| f["message"].as_str().unwrap())
        .collect();
    assert!(
        messages[0].contains("2026-10-18")
            && messages[0].contains("(in 2d)")
            && messages[1].contains("2026-10-30")
            && messages[1].contains("(in 14d)"),
        "list order, one finding per entry: {messages:?}"
    );
}

#[test]
fn date_rule_window_from_config_override() {
    // `--11-10` is 25 days out: outside the manifest's 7-day default, but
    // inside the operator's 30-day override on both sides.
    let (personal, _) = assert_date_parity(
        "2026-10-16",
        "birthday: --11-10\n",
        "personal.date_upcoming_days = 30\n",
        "example-pack.date_upcoming_days = 30\n",
        7,
    );
    let findings = date_upcoming(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert!(
        findings[0]["message"]
            .as_str()
            .unwrap()
            .contains("(in 25d)"),
        "{personal:?}"
    );
}

#[test]
fn date_rule_severity_off() {
    // `off` skips the rule on both sides.
    let (personal_off, declarative_off) = assert_date_parity(
        "2026-10-16",
        "birthday: --10-20\n",
        "personal.date_upcoming = \"off\"\n",
        "example-pack.date_upcoming = \"off\"\n",
        7,
    );
    assert!(date_upcoming(&personal_off).is_empty(), "{personal_off:?}");
    assert!(
        !codes(&declarative_off)
            .iter()
            .any(|c| c == "W_EXAMPLE_DATE"),
        "{declarative_off:?}"
    );
}

// ---------------------------------------------------------------------------
// Declarative rule kind: note-ref (#458)
// ---------------------------------------------------------------------------

/// Vendor a declarative note-ref pack mirroring the built-in personal
/// pack's templates with pack-own
/// codes: an external pack cannot claim the core codes, so it sets
/// `invalid_code`/`wrong_type_code` explicitly (#490/PD13). Returns the
/// lockfile hash.
fn install_note_pack(root: &Path) -> String {
    let pack_dir = root.join("packs/example-pack@0.1");
    fs::create_dir_all(&pack_dir).unwrap();
    write(
        root,
        "packs/example-pack@0.1/manifest.toml",
        r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "E_EXAMPLE_NOTE_MISSING", "E_EXAMPLE_NOTE_INVALID", "E_EXAMPLE_NOTE_WRONG_TYPE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[verbs]]
name = "example_touch"
id_type = "person"

[[rules]]
id = "touch_note"
kind = "note-ref"
code = "E_EXAMPLE_NOTE_MISSING"
verb = "example_touch"
pair = "note"
invalid_code = "E_EXAMPLE_NOTE_INVALID"
wrong_type_code = "E_EXAMPLE_NOTE_WRONG_TYPE"

[messages."E_EXAMPLE_NOTE_INVALID"]
default = "touch note is not a record ID"
default_fix = "Point note: at an existing n-<ULID> note"

[messages."E_EXAMPLE_NOTE_WRONG_TYPE"]
default = "touch note '{id}' is not a note id"
default_fix = "Use note:n-<ULID>"

[messages."E_EXAMPLE_NOTE_MISSING"]
missing = "touch note '{id}' does not exist"
missing_fix = "Point note: at an existing n-<ULID> note"
wrong_owner = "touch note '{id}' does not belong to {person}"
wrong_owner_fix = "Point note: at a note for this person"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"
"#,
    );
    write(
        root,
        "packs/example-pack@0.1/SKILL.md",
        "# example pack.\n\nNote reference rule (fake).\n",
    );
    read_pack_dir(&pack_dir)
        .expect("fixture pack dir must read")
        .hash
}

/// The note-ref findings of a report, whichever side emitted them (the core
/// codes on the built-in personal pack, the pack-own codes on the
/// declarative copy), as comparable strings.
fn note_ref_findings(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            matches!(
                f["code"].as_str().unwrap(),
                "E_INVALID_ID"
                    | "E_WRONG_ID_TYPE"
                    | "E_UNKNOWN_RECORD"
                    | "E_EXAMPLE_NOTE_INVALID"
                    | "E_EXAMPLE_NOTE_WRONG_TYPE"
                    | "E_EXAMPLE_NOTE_MISSING"
            )
        })
        .map(|f| {
            format!(
                "{}/{}/{}/{}/{}/{}",
                f["severity"].as_str().unwrap_or_default(),
                f["message"].as_str().unwrap_or_default(),
                f["fix"].as_str().unwrap_or_default(),
                f["file"].as_str().unwrap_or_default(),
                f["line"],
                f["id"].as_str().unwrap_or_default(),
            )
        })
        .collect()
}

/// Run `check` over one ledger and the records `setup` writes, twice: the
/// built-in personal pack (on `touch`) and the declarative note-ref pack
/// above (on its own `example_touch` verb, #551).
/// The note-ref findings — severity, message, fix, file, line, id — must
/// match; the codes stay pack-own on the declarative side by design
/// (#494/#490). Returns both reports.
fn assert_note_ref_parity(ledger: &str, setup: impl Fn(&Path)) -> (Value, Value) {
    let run_side = |root: &Path, packs: &str, declarative: bool| -> Value {
        write(
            root,
            "confidant.toml",
            &PERSONAL_TOML.replace("packs = [\"personal@0.1\"]", &format!("packs = [{packs}]")),
        );
        setup(root);
        // The fixture pack owns its own verb so it does not collide with
        // the implicit built-in personal pack's `touch` (#551).
        let ledger = if declarative {
            ledger.replace(" touch ", " example_touch ")
        } else {
            ledger.to_owned()
        };
        write(root, "ledger/2026/10.cfd", &ledger);
        if declarative {
            let hash = install_note_pack(root);
            install_lockfile(root, "example-pack", "0.1", &hash);
        }
        report_json(root, None)
    };
    let personal = run_side(
        tempfile::tempdir().unwrap().path(),
        "\"personal@0.1\"",
        false,
    );
    let declarative = run_side(
        tempfile::tempdir().unwrap().path(),
        "\"example-pack@0.1\"",
        true,
    );
    assert_eq!(
        note_ref_findings(&personal),
        note_ref_findings(&declarative),
        "declarative parity failed:\npersonal: {personal:?}\ndeclarative: {declarative:?}"
    );
    (personal, declarative)
}

#[test]
fn note_ref_valid_note_no_finding() {
    // A note that exists and belongs to the person: silent on both sides.
    let (personal, declarative) = assert_note_ref_parity(
        &format!("2026-10-01 touch {ADA} call note:{NOTE}\n"),
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
        },
    );
    assert!(note_ref_findings(&personal).is_empty(), "{personal:?}");
    assert!(
        note_ref_findings(&declarative).is_empty(),
        "{declarative:?}"
    );
}

#[test]
fn note_ref_not_a_record_id() {
    let (personal, _) = assert_note_ref_parity(
        &format!("2026-10-01 touch {ADA} call note:not-an-id\n"),
        |root| person(root, ADA, "Ada Example"),
    );
    let findings = note_ref_findings(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert!(
        findings[0].starts_with("error/touch note is not a record ID/"),
        "{findings:?}"
    );
}

#[test]
fn note_ref_wrong_prefix() {
    // A person id where a note id belongs: the wrong-type problem.
    let (personal, _) = assert_note_ref_parity(
        &format!("2026-10-01 touch {ADA} call note:{BEA}\n"),
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
        },
    );
    let findings = note_ref_findings(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert!(
        findings[0].starts_with(&format!("error/touch note '{BEA}' is not a note id/")),
        "{findings:?}"
    );
}

#[test]
fn note_ref_missing_note() {
    let (personal, _) = assert_note_ref_parity(
        &format!("2026-10-01 touch {ADA} call note:{NOTE}\n"),
        |root| person(root, ADA, "Ada Example"),
    );
    let findings = note_ref_findings(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert!(
        findings[0].starts_with(&format!("error/touch note '{NOTE}' does not exist/")),
        "{findings:?}"
    );
}

#[test]
fn note_ref_note_of_other_person() {
    let (personal, _) = assert_note_ref_parity(
        &format!("2026-10-01 touch {ADA} call note:{NOTE}\n"),
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            note(root, NOTE, BEA, "2026-10-01");
        },
    );
    let findings = note_ref_findings(&personal);
    assert_eq!(findings.len(), 1, "{personal:?}");
    assert!(
        findings[0].starts_with(&format!(
            "error/touch note '{NOTE}' does not belong to {ADA}/"
        )),
        "{findings:?}"
    );
    assert!(
        findings[0].contains("ledger/2026/10.cfd"),
        "finding carries the ledger line: {findings:?}"
    );
}

#[test]
fn note_ref_merged_person_owns_note() {
    // The note belongs to Bea, merged into Ada before the touch: no
    // wrong-owner finding on either side.
    let (personal, declarative) = assert_note_ref_parity(
        &format!("2026-10-01 merge {BEA} into {ADA}\n2026-10-02 touch {ADA} call note:{NOTE}\n"),
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            note(root, NOTE, BEA, "2026-10-01");
        },
    );
    assert!(note_ref_findings(&personal).is_empty(), "{personal:?}");
    assert!(
        note_ref_findings(&declarative).is_empty(),
        "{declarative:?}"
    );
}

#[test]
fn note_ref_matches_compiled_personal() {
    // One vault that triggers all three problems; the parity helper
    // asserts the declarative copy equals the compiled pack on every
    // fixture, and this pins the shape of that fixture.
    let (personal, _) = assert_note_ref_parity(
        &format!(
            "2026-10-01 touch {ADA} call note:{NOTE}\n2026-10-02 touch {ADA} call note:{BEA}\n2026-10-03 touch {ADA} call note:not-an-id\n"
        ),
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            note(root, NOTE, BEA, "2026-10-01");
        },
    );
    assert_eq!(note_ref_findings(&personal).len(), 3, "{personal:?}");
}

#[test]
fn note_ref_conflicted_note_counts_as_existing() {
    // A conflicted note file is not loaded, but it exists (two versions):
    // the declarative kind must not report it missing. This is a
    // documented divergence from an earlier compiled pack, which reported
    // E_UNKNOWN_RECORD for a conflicted note (#458).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "confidant.toml",
        &PERSONAL_TOML.replace(
            "packs = [\"personal@0.1\"]",
            "packs = [\"example-pack@0.1\"]",
        ),
    );
    person(root, ADA, "Ada Example");
    write(
        root,
        &format!("people/{ADA}/notes/{NOTE}.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\n<<<<<<< HEAD\nperson: {ADA}\n=======\nperson: {ADA}\n>>>>>>> other\ndate: 2026-10-01\n---\n\nFake note.\n"
        ),
    );
    write(
        root,
        "ledger/2026/10.cfd",
        &format!("2026-10-01 example_touch {ADA} call note:{NOTE}\n"),
    );
    let hash = install_note_pack(root);
    install_lockfile(root, "example-pack", "0.1", &hash);
    let declarative = report_json(root, None);
    assert!(
        note_ref_findings(&declarative).is_empty(),
        "a conflicted note is treated as existing: {declarative:?}"
    );
}

// ---------------------------------------------------------------------------
// personal@0.2 schema (#509): Dex-derived fields, new grammars, snooze
// ---------------------------------------------------------------------------

/// The full `personal@0.2` field set, as a fixture manifest. The real
/// `packs/personal/manifest.toml` (and its embedded copy) stay at 0.1
/// until #444b: this issue proves the 0.2 field set with fixtures only.
const SCHEMA_0_2_FIELDS: &str = r#"[[fields]]
name = "title"
grammar = "non-empty-string"

[[fields]]
name = "company"
grammar = "non-empty-string"

[[fields]]
name = "location"
grammar = "non-empty-string"

[[fields]]
name = "emails"
grammar = "list"

[[fields]]
name = "phones"
grammar = "list"

[[fields]]
name = "links"
grammar = "labeled-list"

[[fields]]
name = "tags"
grammar = "list"

[[fields]]
name = "birthday"
grammar = "recurring-date"

[[fields]]
name = "dates"
grammar = "dates-list"

[[fields]]
name = "relationship"
grammar = "non-empty-string"

[[fields]]
name = "cadence"
grammar = "cadence"

[[fields]]
name = "snooze_until"
grammar = "date"
"#;

/// A one-person vault checked against the built-in `personal@0.2` pack,
/// with the given extra front-matter lines on the person's profile. The
/// built-in is implicit (#551), so `packs = []` still enables it. Returns
/// the check JSON (all fake data).
fn schema_pack_report(extra_fields: &str) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "confidant.toml",
        "spec = \"0.1\"\npacks = []\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    );
    write(
        root,
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\n{extra_fields}---\n\nFake person.\n"
        ),
    );
    report_json(root, None)
}

/// The full 0.2 field set with valid values validates clean (and
/// `cadence: never` proves the extended grammar while skipping the rule).
#[test]
fn personal_0_2_fields_validate_clean() {
    let json = schema_pack_report(
        "title: Staff Engineer\n\
         company: Example Co\n\
         location: Lisbon\n\
         emails: [ada@example.com, ada2@example.com]\n\
         phones: [+15550000000]\n\
         links: [linkedin:https://example.test/ada, site:https://example.test/a:b]\n\
         tags: [friend, work/finance]\n\
         birthday: --05-14\n\
         dates: [anniversary:2020-06-15]\n\
         relationship: friend\n\
         cadence: never\n\
         snooze_until: 2026-10-20\n",
    );
    assert!(
        !codes(&json).contains(&"E_FRONTMATTER".to_owned()),
        "every 0.2 value must validate: {json:?}"
    );
    assert_eq!(json["summary"]["errors"], 0, "{json:?}");
    assert_eq!(json["summary"]["warnings"], 0, "{json:?}");
}

/// `tags: []` is a valid, empty list.
#[test]
fn personal_0_2_empty_list_is_valid() {
    let json = schema_pack_report("tags: []\n");
    assert!(codes(&json).is_empty(), "{json:?}");
}

/// Assert a 0.2 field value is rejected as `E_FRONTMATTER` naming the key.
fn assert_schema_rejection(field: &str, value: &str) {
    let json = schema_pack_report(&format!("{field}: {value}\n"));
    let found = codes(&json);
    assert!(
        found.contains(&"E_FRONTMATTER".to_owned()),
        "{field}: {value} must be E_FRONTMATTER: {json:?}"
    );
    let finding = finding_by_code(&json, "E_FRONTMATTER");
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains(&format!("'{field}'")),
        "the finding must name the field: {json:?}"
    );
}

/// Every rejection case from #509 for the new grammars is `E_FRONTMATTER`.
#[test]
fn personal_0_2_rejections_are_frontmatter() {
    for (field, value) in [
        // list: empty entry, duplicate entry.
        ("emails", "ada@example.com,"),
        ("tags", "[a,,b]"),
        ("tags", "[friend, friend]"),
        // labeled-list: no colon, empty label, no-colon tail, duplicate label.
        ("links", "[linkedin]"),
        ("links", "[:https://example.test]"),
        ("links", "[linkedin:https://example.test,extra]"),
        ("links", "[linkedin:a, linkedin:b]"),
        // date: not a one-off date, impossible date.
        ("snooze_until", "--10-18"),
        ("snooze_until", "2026-13-01"),
        // cadence: misspelling, zero, over the cap.
        ("cadence", "neverr"),
        ("cadence", "0d"),
        ("cadence", "3651d"),
        // non-empty-string unchanged.
        ("relationship", "\"\""),
    ] {
        assert_schema_rejection(field, value);
    }
}

/// `cadence: never` is a valid value that skips the person entirely: no
/// `W_CADENCE_OVERDUE`, even with no contact at all.
#[test]
fn cadence_never_suppresses_overdue() {
    let json = schema_pack_report("cadence: never\n");
    assert!(
        !codes(&json).iter().any(|c| c == "W_CADENCE_OVERDUE"),
        "never must not be overdue: {json:?}"
    );
}

/// `snooze_until` suppresses the nudge while `as_of < snooze_until`.
#[test]
fn snooze_until_suppresses_overdue_before_date() {
    // as_of = 2026-10-08; snooze 2026-10-20 is in the future.
    let json = schema_pack_report("cadence: 30d\nsnooze_until: 2026-10-20\n");
    assert!(
        !codes(&json).iter().any(|c| c == "W_CADENCE_OVERDUE"),
        "an active snooze must suppress the nudge: {json:?}"
    );
}

/// The person is eligible again on the snooze date; a past date has no
/// effect.
#[test]
fn snooze_until_due_on_date_is_overdue() {
    // snooze_until == as_of: eligible again, no contact, 30d cadence.
    let on_date = schema_pack_report("cadence: 30d\nsnooze_until: 2026-10-08\n");
    assert!(
        codes(&on_date).iter().any(|c| c == "W_CADENCE_OVERDUE"),
        "eligible on the snooze date: {on_date:?}"
    );
    let past = schema_pack_report("cadence: 30d\nsnooze_until: 2026-01-01\n");
    assert!(
        codes(&past).iter().any(|c| c == "W_CADENCE_OVERDUE"),
        "a past snooze has no effect: {past:?}"
    );
}

/// No 0.2 field value reaches a finding: the failures name the key only.
#[test]
fn personal_0_2_values_do_not_echo_in_findings() {
    let json =
        schema_pack_report("title: SCHEMA0TITLE\nemails: SCHEMA0EMAIL,\ncompany: SCHEMA0COMPANY\n");
    let dumped = serde_json::to_string(&json).unwrap();
    for leak in ["SCHEMA0TITLE", "SCHEMA0EMAIL", "SCHEMA0COMPANY"] {
        assert!(!dumped.contains(leak), "{leak} leaked in {dumped}");
    }
    assert!(
        codes(&json).contains(&"E_FRONTMATTER".to_owned()),
        "{json:?}"
    );
}

// ---------------------------------------------------------------------------
// personal@0.2 embedded declarative pack (#550, cutover #551)
//
// The built-in `personal@0.2` pack is compiled into the binary, implicit in
// every vault, and loaded through the manifest-v2 / declarative path. This
// block pins the behaviour on the 0.1/0.2 field set as a recorded golden:
// the fixture triggers every in-scope code, and its findings are asserted
// verbatim.
// ---------------------------------------------------------------------------

use confidant_core::packs::embedded as packs_embedded;

/// A note id with two versions: a conflicted note. The declarative kinds
/// treat a conflicted id as existing (#458).
const CONFLICTED_NOTE: &str = "n-01M3TC5H00MPJG00900000000G";

/// A well-formed note id with no record file: the `missing` variant.
const MISSING_NOTE: &str = "n-01M3TC5H00MPJG00A000000000H";

/// Build a vault fixture that triggers every in-scope code at least once.
/// The built-in personal pack is implicit (#551), so `packs = []`. Fake data
/// only.
fn personal_golden_fixture() -> Value {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "confidant.toml",
        &PERSONAL_TOML.replace("packs = [\"personal@0.1\"]", "packs = []"),
    );
    // Ada: overdue cadence and an upcoming birthday.
    write(
        root,
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\ncadence: 30d\nbirthday: --10-12\n---\n\nFake person.\n"
        ),
    );
    // Bea: two malformed shared fields (E_FRONTMATTER).
    write(
        root,
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea Demo\nbirthday: not-a-date\ncadence: 0d\n---\n\nFake person.\n"
        ),
    );
    // Cam: a malformed `dates` entry (E_FRONTMATTER).
    write(
        root,
        &format!("people/{CAM}/profile.md"),
        &format!(
            "---\nid: {CAM}\ntype: person\nname: Cam Sample\ndates: [anniv:not-a-date]\n---\n\nFake person.\n"
        ),
    );
    // A real note owned by Bea, for the wrong-owner case below.
    note(root, NOTE, BEA, "2026-10-01");
    // A conflicted note (two versions) on Bea.
    write(
        root,
        &format!("people/{BEA}/notes/{CONFLICTED_NOTE}.md"),
        &format!(
            "---\nid: {CONFLICTED_NOTE}\ntype: note\n<<<<<<< HEAD\nperson: {BEA}\n=======\nperson: {BEA}\n>>>>>>> other\ndate: 2026-10-01\n---\n\nFake note.\n"
        ),
    );
    // Ada's last contact is 40 days before as_of (2026-10-08): overdue. Bea's
    // touch lines carry the note problems (invalid id, wrong type, missing);
    // Cam points at Bea's note (wrong owner). The conflicted note is a sixth
    // touch and is treated as existing (#458), so it adds no finding.
    write(
        root,
        "ledger/2026/10.cfd",
        &format!(
            "2026-08-29 touch {ADA} call\n\
             2026-10-02 touch {BEA} call note:not-an-id\n\
             2026-10-03 touch {BEA} call note:{CAM}\n\
             2026-10-04 touch {BEA} call note:{MISSING_NOTE}\n\
             2026-10-05 touch {CAM} call note:{NOTE}\n\
             2026-10-06 touch {BEA} call note:{CONFLICTED_NOTE}\n"
        ),
    );
    report_json(root, None)
}

/// The in-scope codes the #550/#551 golden covers (the #444 list).
const PARITY_CODES: &[&str] = &[
    "W_CADENCE_OVERDUE",
    "W_DATE_UPCOMING",
    "E_FRONTMATTER",
    "E_INVALID_ID",
    "E_WRONG_ID_TYPE",
    "E_UNKNOWN_RECORD",
];

/// The in-scope findings of a report, as comparable values. Only the codes
/// in [`PARITY_CODES`] are kept; `E_FRONTMATTER` wording is normalised
/// because the declarative evaluator renders the manifest's generic
/// template. Everything else — code, severity, file, line, id — is verbatim.
fn parity_findings(v: &Value) -> Vec<Value> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| PARITY_CODES.contains(&f["code"].as_str().unwrap()))
        .map(|f| {
            let mut f = f.clone();
            if f["code"] == "E_FRONTMATTER" {
                f["message"] = json!("<frontmatter>");
                f["fix"] = json!("<frontmatter>");
            }
            f
        })
        .collect()
}

/// The cutover golden (#444/#550/#551): the implicit built-in `personal@0.2`
/// produces the recorded findings on a fixture that triggers every in-scope
/// code. Compiled `personal@0.1` (the old oracle) is gone; this pins the
/// behaviour instead of comparing two live implementations.
#[test]
fn declarative_personal_golden_findings() {
    let json = personal_golden_fixture();
    let findings = parity_findings(&json);
    // Every in-scope code is exercised, so the golden cannot silently shrink.
    for code in PARITY_CODES {
        assert!(
            findings.iter().any(|f| f["code"] == **code),
            "the fixture must trigger {code}: {findings:?}"
        );
    }
    let expected: Vec<Value> = json!([
        {
            "code": "E_FRONTMATTER",
            "severity": "error",
            "message": "<frontmatter>",
            "fix": "<frontmatter>",
            "file": "people/p-01M3TC5H00MPJG000H24000001/profile.md",
            "line": 5,
            "id": "p-01M3TC5H00MPJG000H24000001"
        },
        {
            "code": "E_FRONTMATTER",
            "severity": "error",
            "message": "<frontmatter>",
            "fix": "<frontmatter>",
            "file": "people/p-01M3TC5H00MPJG000H24000001/profile.md",
            "line": 6,
            "id": "p-01M3TC5H00MPJG000H24000001"
        },
        {
            "code": "E_FRONTMATTER",
            "severity": "error",
            "message": "<frontmatter>",
            "fix": "<frontmatter>",
            "file": "people/p-01M3TC5H00MPJG001248000002/profile.md",
            "line": 5,
            "id": "p-01M3TC5H00MPJG001248000002"
        },
        {
            "code": "E_INVALID_ID",
            "severity": "error",
            "message": "touch note is not a record ID",
            "fix": "Point note: at an existing n-<ULID> note",
            "file": "ledger/2026/10.cfd",
            "line": 2,
            "id": "p-01M3TC5H00MPJG000H24000001"
        },
        {
            "code": "E_INVALID_ID",
            "severity": "error",
            "message": "touch note is not a record ID",
            "fix": "Point note: at an existing n-<ULID> note",
            "file": "ledger/2026/10.cfd",
            "line": 4,
            "id": "p-01M3TC5H00MPJG000H24000001"
        },
        {
            "code": "E_UNKNOWN_RECORD",
            "severity": "error",
            "message": "touch note 'n-01M3TC5H00MPJG002NAM000005' does not belong to p-01M3TC5H00MPJG001248000002",
            "fix": "Point note: at a note for this person",
            "file": "ledger/2026/10.cfd",
            "line": 5,
            "id": "p-01M3TC5H00MPJG001248000002"
        },
        {
            "code": "E_WRONG_ID_TYPE",
            "severity": "error",
            "message": "touch note 'p-01M3TC5H00MPJG001248000002' is not a note id",
            "fix": "Use note:n-<ULID>",
            "file": "ledger/2026/10.cfd",
            "line": 3,
            "id": "p-01M3TC5H00MPJG000H24000001"
        },
        {
            "code": "W_CADENCE_OVERDUE",
            "severity": "warning",
            "message": "person p-01M3TC5H00MPJG000000000000 has no touchpoint on or after 2026-09-08 (last was 2026-08-29, cadence 30d)",
            "fix": "Log a touchpoint with `confidant log touch p-01M3TC5H00MPJG000000000000 <kind>` or widen cadence",
            "file": "people/p-01M3TC5H00MPJG000000000000/profile.md",
            "id": "p-01M3TC5H00MPJG000000000000"
        },
        {
            "code": "W_DATE_UPCOMING",
            "severity": "warning",
            "message": "upcoming date for p-01M3TC5H00MPJG000000000000 on 2026-10-12 (in 4d)",
            "fix": "Reach out to p-01M3TC5H00MPJG000000000000 or set `[checks] personal.date_upcoming = \"off\"`",
            "file": "people/p-01M3TC5H00MPJG000000000000/profile.md",
            "id": "p-01M3TC5H00MPJG000000000000"
        }
    ])
    .as_array()
    .unwrap()
    .clone();
    assert_eq!(findings, expected, "golden drift:\n{json:?}");
}

/// A vault that vendors its own `packs/personal@…/` is `E_PACK_INVALID`
/// whether or not it lists the pack: the built-in is implicit, and the
/// stable-code allowance is keyed on compiled-in origin, never the pack
/// name (#504 R8, #551).
#[test]
fn vault_supplied_personal_pack_is_e_pack_invalid() {
    for (listing, vendored) in [
        ("personal@0.2", "personal@0.2"),
        ("personal@0.1", "personal@0.1"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "confidant.toml",
            &PERSONAL_TOML.replace(
                "packs = [\"personal@0.1\"]",
                &format!("packs = [\"{listing}\"]"),
            ),
        );
        person(root, ADA, "Ada Example");
        let declared =
            packs_embedded::find("personal@0.2").expect("personal@0.2 is a compiled-in pack");
        for (rel, bytes) in declared.files() {
            write(
                root,
                &format!("packs/{vendored}/{rel}"),
                std::str::from_utf8(bytes).unwrap(),
            );
        }
        let (name, version) = vendored.split_once('@').unwrap();
        install_lockfile(root, name, version, declared.hash());
        let json = report_json(root, None);
        let finding = finding_by_code(&json, "E_PACK_INVALID");
        assert_eq!(
            finding["file"],
            format!("packs/{vendored}"),
            "the finding points at the vendored path: {json:?}"
        );
    }

    // A vendored directory with no listing at all is still invalid: the
    // built-in is on even when `packs = []`.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "confidant.toml",
        "spec = \"0.1\"\npacks = []\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    );
    person(root, ADA, "Ada Example");
    let declared =
        packs_embedded::find("personal@0.2").expect("personal@0.2 is a compiled-in pack");
    for (rel, bytes) in declared.files() {
        write(
            root,
            &format!("packs/personal@0.2/{rel}"),
            std::str::from_utf8(bytes).unwrap(),
        );
    }
    let json = report_json(root, None);
    let finding = finding_by_code(&json, "E_PACK_INVALID");
    assert_eq!(finding["file"], "packs/personal@0.2", "{json:?}");
}

// ---------------------------------------------------------------------------
// #510: core-owned personal context view, private fields and touch grammar
// ---------------------------------------------------------------------------

use confidant_core::context::build_context;
use confidant_core::context::personal::{
    build_personal_view, strip_private_fields, PRIVATE_CONTEXT_FIELDS,
};
use confidant_core::packs::manifest::{parse_manifest, FieldDecl};
use confidant_core::scope::PackScope;

/// The full `personal@0.2` field list as the core view builder consumes it
/// (the fixture manifest from #509, parsed through the real loader).
fn fields_0_2() -> Vec<FieldDecl> {
    let text = format!(
        r#"manifest_version = 1
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER"]

[pack]
name = "personal-fixture"
version = "0.2"
skill = "SKILL.md"

{SCHEMA_0_2_FIELDS}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"
"#
    );
    parse_manifest(&text)
        .expect("0.2 field fixture parses")
        .fields
}

/// The built-in personal pack's view for a person, via `context`.
fn personal_view(root: &Path, person: &str) -> Value {
    let vault = load_vault(root).unwrap();
    let id = confidant_core::id::RecordId::parse(person).unwrap();
    let bundle = build_context(&vault, &id, true, &PackScope::All, false).unwrap();
    bundle
        .packs
        .get("personal@0.2")
        .expect("personal@0.2 view")
        .clone()
}

/// The core builder's view for a person against the 0.2 field list.
fn personal_view_0_2(root: &Path, person: &str, as_of: &str) -> Value {
    let vault = load_vault(root).unwrap();
    let id = confidant_core::id::RecordId::parse(person).unwrap();
    let as_of = chrono::NaiveDate::parse_from_str(as_of, "%Y-%m-%d").unwrap();
    build_personal_view(&vault, &id, &id, as_of, &fields_0_2()).expect("view serializes")
}

/// A person carrying the whole 0.2 field set (fake data). `no_ai` adds
/// `no-ai: true`.
fn write_full_0_2_person(root: &Path, no_ai: bool) {
    let flag = if no_ai { "no-ai: true\n" } else { "" };
    write(
        root,
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\n{flag}\
             title: Staff Engineer\n\
             company: Example Co\n\
             location: Lisbon\n\
             emails: [ada@example.com, ada2@example.com]\n\
             phones: [+15550000000]\n\
             links: [linkedin:https://example.test/ada, site:https://example.test/a:b]\n\
             tags: [friend, work/finance]\n\
             birthday: --05-14\n\
             dates: [anniversary:2020-06-15]\n\
             relationship: friend\n\
             cadence: 30d\n\
             snooze_until: 2026-10-20\n\
             ---\n\nFake person.\n"
        ),
    );
}

/// Structural golden for a demo-vault person: the `personal@0.2` entry keeps
/// the same shape at the #551 cutover. Demo Ada has no declared personal
/// field, so only derived keys appear; the 2026-10-08 session is her last
/// contact.
#[test]
fn context_view_shape_is_stable() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault");
    assert_eq!(
        personal_view(&root, ADA),
        json!({
            "last_touch": "2026-10-08",
            "days_since_touch": 0,
            "overdue": false,
            "recent_touches": [],
        })
    );
}

/// The 0.2 declared fields reach the view under their declared names, with
/// the grammar-driven shapes and the derived cadence/snooze keys.
#[test]
fn context_view_0_2_declared_fields_shape() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write_full_0_2_person(dir.path(), false);
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-06 touch {ADA} call\n"),
    );
    assert_eq!(
        personal_view_0_2(dir.path(), ADA, "2026-10-08"),
        json!({
            "title": "Staff Engineer",
            "company": "Example Co",
            "location": "Lisbon",
            "emails": ["ada@example.com", "ada2@example.com"],
            "phones": ["+15550000000"],
            "links": [
                {"label": "linkedin", "value": "https://example.test/ada"},
                {"label": "site", "value": "https://example.test/a:b"},
            ],
            "tags": ["friend", "work/finance"],
            "birthday": "--05-14",
            "dates": [{"label": "anniversary", "date": "2020-06-15"}],
            "relationship": "friend",
            "cadence_days": 30,
            "snooze_until": "2026-10-20",
            "last_touch": "2026-10-06",
            "days_since_touch": 2,
            "overdue": false,
            "recent_touches": [{"date": "2026-10-06", "kind": "call"}],
        })
    );
}

/// #589: `cadence: never` is marked explicitly, so an agent can tell the
/// deliberate never-nudge apart from "no cadence set" (both omit
/// `cadence_days`).
#[test]
fn context_view_cadence_never_is_marked() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\ncadence: never\n---\n\nFake person.\n"
        ),
    );
    let view = personal_view_0_2(dir.path(), ADA, "2026-10-08");
    assert_eq!(view["cadence_never"], true, "{view}");
    assert!(view.get("cadence_days").is_none(), "{view}");
    // `never` is never overdue, with or without contact.
    assert_eq!(view["overdue"], false, "{view}");
}

/// A numeric cadence emits `cadence_days` and no `cadence_never` key, so the
/// marker stays additive: the JSON for a person who is not `never` is
/// unchanged.
#[test]
fn context_view_numeric_cadence_has_no_never_marker() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
    let view = personal_view_0_2(dir.path(), ADA, "2026-10-08");
    assert_eq!(view["cadence_days"], 30, "{view}");
    assert!(view.get("cadence_never").is_none(), "{view}");
}

/// No cadence field: `cadence_days` and `cadence_never` are both absent, so
/// the presence of `cadence_never` is the whole never signal.
#[test]
fn context_view_no_cadence_has_no_marker() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
    );
    let view = personal_view_0_2(dir.path(), ADA, "2026-10-08");
    assert!(view.get("cadence_days").is_none(), "{view}");
    assert!(view.get("cadence_never").is_none(), "{view}");
}

/// §12: `cadence_never` is derived cadence state, exactly like `cadence_days`,
/// so a `no-ai` person keeps it while every declared field stays hidden.
#[test]
fn context_view_cadence_never_kept_for_no_ai_person() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nno-ai: true\n\
             title: Staff Engineer\nrelationship: friend\ncadence: never\n---\n\nFake person.\n"
        ),
    );
    let view = personal_view_0_2(dir.path(), ADA, "2026-10-08");
    // The whole view is the derived cadence/touch state: no declared field.
    assert_eq!(
        view,
        json!({
            "cadence_never": true,
            "overdue": false,
            "recent_touches": [],
        }),
        "{view}"
    );
}

/// A field takes the canonical person's own value first, else the first
/// merged member's in record order; a merged-away id's own view folds onto
/// the canonical person.
#[test]
fn context_view_merged_person_uses_canonical() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    // 0.2 field names: the builder is driven by the declared field list.
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nrelationship: friend\n---\n\nFake person.\n"
        ),
    );
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea Demo\nrelationship: family\nbirthday: --02-02\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {BEA} into {ADA}\n2026-10-05 touch {BEA} call\n"),
    );

    let vault = load_vault(dir.path()).unwrap();
    let ada = confidant_core::id::RecordId::parse(ADA).unwrap();
    let bea = confidant_core::id::RecordId::parse(BEA).unwrap();
    let as_of = chrono::NaiveDate::parse_from_str("2026-10-08", "%Y-%m-%d").unwrap();
    let fields = fields_0_2();
    let view = build_personal_view(&vault, &ada, &ada, as_of, &fields).unwrap();

    // Ada's own relationship wins over Bea's.
    assert_eq!(view["relationship"], "friend", "{view}");
    // Fields Ada lacks come from the merged member.
    assert_eq!(view["birthday"], "--02-02", "{view}");
    assert_eq!(view["cadence_days"], 30, "{view}");
    // The merged-away member's touch counts for the canonical person.
    assert_eq!(view["last_touch"], "2026-10-05", "{view}");

    // Asking for the merged-away id serves the same canonical view.
    let folded = build_personal_view(&vault, &bea, &ada, as_of, &fields).unwrap();
    assert_eq!(folded, view);
}

/// A `no-ai` person never shows their declared PII fields, but keeps the
/// derived cadence state so an agent can see why no nudge fired.
#[test]
fn context_view_cleared_person_hides_fields() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nno-ai: true\n\
             birthday: --05-14\nrelationship_to_me: friend\n\
             dates: [anniversary:2020-06-15]\ncadence: 30d\n---\n\nFake person.\n"
        ),
    );
    let view = personal_view(dir.path(), ADA);
    for field in ["birthday", "relationship_to_me", "dates"] {
        assert!(view.get(field).is_none(), "{field} leaked: {view}");
    }
    // The derived cadence state stays: 30d cadence, no contact at all, so
    // the person reads as overdue (same as before #510).
    assert_eq!(view["cadence_days"], 30, "{view}");
    assert_eq!(view["overdue"], true, "{view}");
}

/// Merge-group clearing still applies (the `search.rs` fixpoint): a visible
/// person merged with a `no-ai` peer is uncleared, so their PII hides too.
#[test]
fn context_view_cleared_merge_peer_hides_fields() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nbirthday: --05-14\n---\n\nFake person.\n"
        ),
    );
    write(
        dir.path(),
        &format!("people/{BEA}/profile.md"),
        &format!(
            "---\nid: {BEA}\ntype: person\nname: Bea Demo\nno-ai: true\n---\n\nFake person.\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-01 merge {BEA} into {ADA}\n"),
    );
    let view = personal_view(dir.path(), ADA);
    assert!(view.get("birthday").is_none(), "{view}");
}

/// A `no-ai` person keeps **no** declared field except the explicit
/// `no-ai` allowlist: the 0.2 field set is denied by default, so `title`
/// and `company` cannot leak and a field a later manifest adds cannot
/// either. Only the derived cadence/touch metadata (plus `snooze_until`)
/// survives.
#[test]
fn context_view_cleared_person_hides_every_0_2_field() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write_full_0_2_person(dir.path(), true);
    let view = personal_view_0_2(dir.path(), ADA, "2026-10-08");
    for field in [
        "title",
        "company",
        "location",
        "emails",
        "phones",
        "links",
        "tags",
        "birthday",
        "dates",
        "relationship",
    ] {
        assert!(
            view.get(field).is_none(),
            "{field} leaked for a no-ai person: {view}"
        );
    }
    // Deny by default: the whole view is the derived state plus the snooze.
    // `cadence_days` / `overdue` remain, and the kept `snooze_until` still
    // suppresses the nudge (as_of 2026-10-08 < 2026-10-20).
    assert_eq!(
        view,
        json!({
            "snooze_until": "2026-10-20",
            "cadence_days": 30,
            "overdue": false,
            "recent_touches": [],
        }),
        "{view}"
    );
}

/// The no-ai guarantee is unchanged by #510: a cleared person's record
/// content never appears. The logged interaction's name and body are record
/// content and stay hidden; ledger-derived date+kind touch metadata is not
/// content, so (as before #510) the opaque touchpoints stay. The issue names
/// this `..._hides_touches`; the tests pin what the code actually guarantees.
#[test]
fn context_view_cleared_person_hides_touch_content() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!(
            "---\nid: {ADA}\ntype: person\nname: Ada Example\nno-ai: true\n---\n\nAI_HIDDEN_PROFILE.\n"
        ),
    );
    write(
        dir.path(),
        &format!("interactions/{IXN}/interaction.md"),
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: AI_HIDDEN_IXN\ndate: 2026-10-05\nperson: {ADA}\n---\n\nAI_HIDDEN_BODY.\n"
        ),
    );
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!("2026-10-05 touch {ADA} call\n"),
    );

    let vault = load_vault(dir.path()).unwrap();
    let ada = confidant_core::id::RecordId::parse(ADA).unwrap();
    let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
    assert!(bundle.person.name.is_none());
    assert!(bundle.person.profile.is_none());
    assert!(bundle.interactions.is_empty(), "{:?}", bundle.interactions);
    let dumped = serde_json::to_string(&bundle).unwrap();
    for leak in ["AI_HIDDEN_PROFILE", "AI_HIDDEN_IXN", "AI_HIDDEN_BODY"] {
        assert!(!dumped.contains(leak), "{leak} leaked in {dumped}");
    }
    // Opaque ledger metadata stays, exactly as before #510.
    assert_eq!(bundle.touchpoints.len(), 1, "{:?}", bundle.touchpoints);
    assert_eq!(bundle.touchpoints[0].date, "2026-10-05");
}

/// `--exclude-private` strips every PII field in the core list, including the
/// 0.2 additions, and keeps `title`, `company`, `cadence_days` and
/// `snooze_until`.
#[test]
fn context_exclude_private_strips_all_declared_pii_fields() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "confidant.toml", PERSONAL_TOML);
    write_full_0_2_person(dir.path(), false);

    let mut view = personal_view_0_2(dir.path(), ADA, "2026-10-08");
    let pii = [
        "location",
        "emails",
        "phones",
        "links",
        "tags",
        "birthday",
        "dates",
        "relationship",
    ];
    for field in pii {
        assert!(view.get(field).is_some(), "{field} missing: {view}");
        assert!(
            PRIVATE_CONTEXT_FIELDS.contains(&field),
            "{field} must be in the core private list"
        );
    }
    strip_private_fields(&mut view);
    for field in pii {
        assert!(view.get(field).is_none(), "{field} not stripped: {view}");
    }
    // Non-PII stays, so the cadence state that drove a nudge is still visible.
    assert_eq!(view["title"], "Staff Engineer", "{view}");
    assert_eq!(view["company"], "Example Co", "{view}");
    assert_eq!(view["cadence_days"], 30, "{view}");
    assert_eq!(view["snooze_until"], "2026-10-20", "{view}");
    for field in ["title", "company", "cadence", "snooze_until"] {
        assert!(
            !PRIVATE_CONTEXT_FIELDS.contains(&field),
            "{field} must not be in the core private list"
        );
    }
}

/// `recent_touches` keeps the newest ten, date descending then kind ascending.
#[test]
fn context_recent_touches_last_10_and_order() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.1\"\npacks = [\"personal@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-12-31\"\n",
    );
    write_full_0_2_person(dir.path(), false);
    let mut ledger = String::new();
    for day in 1..=12 {
        ledger.push_str(&format!("2026-10-{day:02} touch {ADA} call\n"));
    }
    // A same-date tie sorts by kind (`call` before `gift`).
    ledger.push_str(&format!("2026-10-12 touch {ADA} gift\n"));
    write(dir.path(), "ledger/2026/10.cfd", &ledger);

    let view = personal_view_0_2(dir.path(), ADA, "2026-12-31");
    let recent = view["recent_touches"].as_array().unwrap();
    assert_eq!(recent.len(), 10, "{view}");
    assert_eq!(recent[0], json!({"date": "2026-10-12", "kind": "call"}));
    assert_eq!(recent[1], json!({"date": "2026-10-12", "kind": "gift"}));
    assert_eq!(recent[9], json!({"date": "2026-10-04", "kind": "call"}));
    // The three oldest fall outside the ten.
    assert!(!recent.iter().any(|t| t["date"] == "2026-10-03"), "{view}");
}

/// Every rejected `touch` argument form routes through the core grammar and
/// is `E_TOUCH_MALFORMED`. The built-in personal pack is implicit (#551), so
/// there is no longer a valid-shape `W_PACK_ORPHAN` half.
#[test]
fn touch_args_table_malformed() {
    for args in [
        "smoke",
        "coffee",
        "call extra",
        "call bogus:x",
        "kind:call tail",
    ] {
        let dir = personal_vault();
        person(dir.path(), ADA, "Ada Example");
        write(
            dir.path(),
            "ledger/2026/10.cfd",
            &format!("2026-10-01 touch {ADA} {args}\n"),
        );
        let json = report_json(dir.path(), None);
        assert_eq!(
            codes(&json),
            vec!["E_TOUCH_MALFORMED"],
            "{args} must be malformed: {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// Declarative coaching kinds (#446 ledger-balance)
// ---------------------------------------------------------------------------

/// Messages for the `coaching-ext` fixture's `ledger-balance` rule. The
/// text is copied verbatim from `packs/coaching/manifest.toml` so parity
/// compares behaviour, not wording; only the codes differ (an external
/// pack cannot claim a builtin code, PD13).
const COACHING_EXT_BALANCE_MESSAGES: &str = r#"
[messages."E_COACHING_EXT_PARSE"]
missing_number = "balance line is missing a number"
expected_integer = "expected integer"
expected_integer_fix = "Use an integer such as 3 for sessions_remaining"
expected_decimal = "expected decimal"
expected_decimal_fix = "Use a decimal such as 1.50 for icf_hours"
minutes_overflow = "session minutes for {id} overflow"

[messages."E_COACHING_EXT_BALANCE"]
sessions_remaining = "sessions_remaining asserted {asserted}, computed {computed}"
sessions_remaining_fix = "Check for a missing 'open' entry or a duplicated 'session' entry for {person}"
icf_hours = "icf_hours asserted {asserted}, computed {computed}"
icf_hours_fix = "Check session durations for {person} or correct the assertion"

[messages."E_COACHING_EXT_NEGATIVE"]
default = "sessions_remaining for {id} is {remaining}"
default_fix = "Add an open/renewal or remove extra session lines"

[messages."E_COACHING_EXT_OPEN"]
shape = "open line must be: DATE open PERSON-ID package PKG-ID N sessions"
shape_fix = "Example: 2026-10-01 open p-… package pkg-… 6 sessions"
not_integer = "expected integer"
not_integer_fix = "Use open <pkg-id> <positive-integer> on its own ledger line"
exceeds_cap = "open N {n} exceeds the cap of {cap}"
exceeds_cap_fix = "Use a package size between 1 and {cap}"
total_overflow = "open total for {id} overflows"

[messages."E_COACHING_EXT_ID"]
package = "package id is not a record ID"
package_fix = "Use a pkg-<ULID> package id"

[messages."E_COACHING_EXT_TYPE"]
package = "package id '{pkg}' must use the pkg- prefix"

[messages."E_COACHING_EXT_DURATION"]
default = "session for {id} has no parseable duration"
default_fix = "Add a duration such as 60m or 1h30m"

[messages."E_COACHING_EXT_TAGS"]
default = "session for {id} has more than one of paid, pps, comp"
default_fix = "Keep exactly one billing tag: paid, pps, or comp"

[messages."W_COACHING_EXT_UNTAGGED"]
default = "session for {id} has no paid, pps, or comp tag"
default_fix = "Tag the session paid, pps (pay-per-session), or comp (complimentary)"

[messages."E_COACHING_EXT_NOTES"]
default = "session on {date} for {person} has no notes"
default_fix = "Add a note for that person and date, or note:n-<ULID> on the session line"

[messages."E_COACHING_EXT_GAP"]
none = "paid client {id} has no session logged"
none_fix = "Log a session, close the package, or widen coaching.paid_session_gap_days (currently {days})"
remaining = "paid client {id} has remaining sessions and no session on or after {start} (last was {d})"
remaining_fix = "Log a session, close the package, or widen coaching.paid_session_gap_days (currently {days})"
no_remaining = "paid client {id} has no session on or after {start} (last was {d})"
no_remaining_fix = "Log a session, close the package, or widen coaching.paid_session_gap_days (currently {days})"
"#;

/// The fixture pack's balance rule. `max_open_n` is overridable so the
/// total-overflow case (unreachable under the 100000 cap) can be built.
const COACHING_EXT_BALANCE_RULE: &str = r#"[[rules]]
id = "balance"
kind = "ledger-balance"
code = "E_COACHING_EXT_BALANCE"
severity_key = "coaching-ext.balance_nonnegative"
open_verb = "open"
consume_verb = "session"
units_metric = "sessions_remaining"
minutes_metric = "icf_hours"
max_open_n = 100000
parse_code = "E_COACHING_EXT_PARSE"
negative_code = "E_COACHING_EXT_NEGATIVE"
open_malformed_code = "E_COACHING_EXT_OPEN"
invalid_code = "E_COACHING_EXT_ID"
wrong_type_code = "E_COACHING_EXT_TYPE"
"#;

/// A v2 `coaching-ext@0.1` manifest using the given `[[rules]]` body. The
/// fixture never ships; it exists to prove the declarative kinds reproduce
/// the shipped external coaching pack (#449).
fn coaching_ext_manifest(rules: &str) -> String {
    let mut text = String::from(
        r#"manifest_version = 2
record_types = []
balance_metrics = ["sessions_remaining", "icf_hours"]
finding_codes = [
  "E_COACHING_EXT_PARSE",
  "E_COACHING_EXT_BALANCE",
  "E_COACHING_EXT_NEGATIVE",
  "E_COACHING_EXT_OPEN",
  "E_COACHING_EXT_ID",
  "E_COACHING_EXT_TYPE",
  "E_COACHING_EXT_DURATION",
  "E_COACHING_EXT_TAGS",
  "W_COACHING_EXT_UNTAGGED",
  "E_COACHING_EXT_NOTES",
  "E_COACHING_EXT_GAP",
]

[pack]
name = "coaching-ext"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[verbs]]
name = "open"
id_type = "person"

[[verbs]]
name = "session"
id_type = "person"

[[checks.severity]]
key = "coaching-ext.balance_nonnegative"
default = "error"

[[checks.severity]]
key = "coaching-ext.require_duration"
default = "error"

[[checks.severity]]
key = "coaching-ext.session_notes"
default = "warning"

[[checks.severity]]
key = "coaching-ext.paid_session_gap"
default = "warning"

[[checks.int]]
key = "coaching-ext.paid_session_gap_days"
default = 45

[[checks.int]]
key = "coaching-ext.pps_lookback_days"
default = 180
"#,
    );
    text.push_str(rules);
    text.push_str(COACHING_EXT_BALANCE_MESSAGES);
    text
}

/// Vendor the fixture pack and pin it. Returns the manifest text used, so
/// a loader-negative test can edit it first.
fn install_coaching_ext(root: &Path, manifest: &str) {
    let hash = install_external_pack_with_manifest(
        root,
        "coaching-ext",
        "0.1",
        manifest,
        "# coaching-ext fixture.\n",
    );
    install_lockfile(root, "coaching-ext", "0.1", &hash);
}

/// `confidant.toml` enabling only the fixture pack. The operator keys are
/// the fixture's own namespace; the shipped coaching pack is not enabled,
/// so its `coaching.*` keys would be unknown here.
fn coaching_ext_vault(root: &Path, checks: &str) {
    external_vault_toml(root, "\"coaching-ext@0.1\"", checks);
}

const COACHING_EXT_CHECKS: &str = "coaching-ext.balance_nonnegative = \"error\"\n";

/// Build the same vault twice — once with the shipped external
/// `coaching@0.1`, once with the inline fixture — and return both reports.
/// `setup` writes the records and ledger; the fixture install is added to
/// the declarative side.
fn assert_ext_parity_with(
    setup: impl Fn(&Path),
    rules: &str,
    map: &[(&str, &str)],
    shipped_checks: &str,
    ext_checks: &str,
) -> (Value, Value) {
    let shipped_dir = tempfile::tempdir().unwrap();
    setup(shipped_dir.path());
    vault_toml(shipped_dir.path(), shipped_checks);
    let compiled = report_json(shipped_dir.path(), None);

    let declarative_dir = tempfile::tempdir().unwrap();
    setup(declarative_dir.path());
    install_coaching_ext(declarative_dir.path(), &coaching_ext_manifest(rules));
    coaching_ext_vault(declarative_dir.path(), ext_checks);
    let declarative = report_json(declarative_dir.path(), None);

    assert_eq!(
        normalized_findings(&compiled, map),
        normalized_findings(&declarative, map),
        "declarative parity failed:\ncompiled: {compiled:?}\ndeclarative: {declarative:?}"
    );
    (compiled, declarative)
}

fn assert_ext_parity(setup: impl Fn(&Path), rules: &str, map: &[(&str, &str)]) -> (Value, Value) {
    assert_ext_parity_with(setup, rules, map, DEFAULT_CHECKS, COACHING_EXT_CHECKS)
}

fn assert_balance_parity(setup: impl Fn(&Path), rules: &str) -> (Value, Value) {
    assert_ext_parity(setup, rules, BALANCE_CODE_MAP)
}

fn assert_session_parity(setup: impl Fn(&Path), rules: &str) -> (Value, Value) {
    assert_ext_parity(setup, rules, SESSION_CODE_MAP)
}

/// The fixture's `activity-gap` rule. It counts through the
/// `ledger-balance` rule that owns `sessions_remaining`.
const COACHING_EXT_GAP_RULE: &str = r#"[[rules]]
id = "gap"
kind = "activity-gap"
code = "E_COACHING_EXT_GAP"
severity_key = "coaching-ext.paid_session_gap"
activity_verb = "session"
start_verb = "open"
gap_days_key = "coaching-ext.paid_session_gap_days"
lookback_days_key = "coaching-ext.pps_lookback_days"
balance_metric = "sessions_remaining"
"#;

/// Fixture code → shipped-pack code for the gap rule.
const GAP_CODE_MAP: &[(&str, &str)] = &[("E_COACHING_EXT_GAP", "E_COACHING_PAID_SESSION_GAP")];

fn assert_gap_parity(setup: impl Fn(&Path)) -> (Value, Value) {
    assert_ext_parity(setup, &coaching_ext_gap_rules(), GAP_CODE_MAP)
}

/// The balance rule (for the counter) plus the gap rule.
fn coaching_ext_gap_rules() -> String {
    format!("{COACHING_EXT_BALANCE_RULE}\n{COACHING_EXT_GAP_RULE}")
}

/// The fixture report for one vault, without a shipped comparison.
fn ext_report(setup: impl Fn(&Path), rules: &str, checks: &str) -> Value {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    install_coaching_ext(dir.path(), &coaching_ext_manifest(rules));
    coaching_ext_vault(dir.path(), checks);
    report_json(dir.path(), None)
}

/// Fixture code → shipped-pack code for the balance rule.
const BALANCE_CODE_MAP: &[(&str, &str)] = &[
    ("E_COACHING_EXT_PARSE", "E_COACHING_PARSE"),
    ("E_COACHING_EXT_BALANCE", "E_COACHING_BALANCE_MISMATCH"),
    ("E_COACHING_EXT_NEGATIVE", "E_COACHING_NEGATIVE_BALANCE"),
    ("E_COACHING_EXT_OPEN", "E_COACHING_OPEN_MALFORMED"),
    ("E_COACHING_EXT_ID", "E_COACHING_INVALID_ID"),
    ("E_COACHING_EXT_TYPE", "E_COACHING_WRONG_ID_TYPE"),
];

/// The fixture's `session-checks` rule.
const COACHING_EXT_SESSION_RULE: &str = r#"[[rules]]
id = "sessions"
kind = "session-checks"
code = "E_COACHING_EXT_DURATION"
severity_duration_key = "coaching-ext.require_duration"
severity_notes_key = "coaching-ext.session_notes"
verb = "session"
billing_tags = ["paid", "pps", "comp"]
tags_code = "E_COACHING_EXT_TAGS"
untagged_code = "W_COACHING_EXT_UNTAGGED"
notes_code = "E_COACHING_EXT_NOTES"
"#;

/// Fixture code → shipped-pack code for the session rule.
const SESSION_CODE_MAP: &[(&str, &str)] = &[
    ("E_COACHING_EXT_DURATION", "E_COACHING_MISSING_DURATION"),
    ("E_COACHING_EXT_TAGS", "E_COACHING_SESSION_TAGS"),
    ("W_COACHING_EXT_UNTAGGED", "W_COACHING_SESSION_UNTAGGED"),
    ("E_COACHING_EXT_NOTES", "E_COACHING_SESSION_WITHOUT_NOTES"),
];

/// The balance-related findings of a report, normalized to the shipped
/// pack's code names and rendered as comparable tuples (code, severity,
/// message, fix, file, line, id). Codes outside `map` are ignored: the
/// inline fixture and the shipped pack emit different *unrelated* codes on
/// the same vault (both pack-own), and parity is scoped to the kind's codes.
fn normalized_findings(report: &Value, map: &[(&str, &str)]) -> Vec<String> {
    let mut out: Vec<String> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| {
            let code = f["code"].as_str().unwrap();
            let normalized = map
                .iter()
                .find(|(from, _)| *from == code)
                .map(|(_, to)| *to)
                .or_else(|| map.iter().find(|(_, to)| *to == code).map(|(_, to)| *to))?;
            Some(format!(
                "{normalized}|{}|{}|{}|{}|{}|{}",
                f["severity"].as_str().unwrap_or(""),
                f["message"].as_str().unwrap_or(""),
                f["fix"].as_str().unwrap_or(""),
                f["file"].as_str().unwrap_or(""),
                f["line"]
                    .as_u64()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                f["id"].as_str().unwrap_or(""),
            ))
        })
        .collect();
    out.sort();
    out
}

/// The normalized codes of a report (the code column only), for the
/// assertions that name a shipped-pack counterpart. The shipped side can
/// carry unrelated findings on the same vault (a session without an open
/// is a negative balance), so filter through the map.
fn normalized_codes(report: &Value, map: &[(&str, &str)]) -> Vec<String> {
    normalized_findings(report, map)
        .iter()
        .map(|line| line.split('|').next().unwrap().to_owned())
        .collect()
}

/// The fixture report's findings with the given fixture code, in order.
fn ext_findings<'a>(report: &'a Value, code: &str) -> Vec<&'a Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == code)
        .collect()
}

#[test]
fn balance_rule_open_then_sessions_remaining() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (compiled, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
                     2026-10-05 session {ADA} 60m paid note:{NOTE}\n\
                     2026-10-08 balance {ADA} sessions_remaining 4\n"
                ),
            );
        },
        rules,
    );
    // Matching assertion: no mismatch on either side.
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_BALANCE").is_empty(),
        "{declarative:?}"
    );
    assert!(
        !codes(&compiled).contains(&"E_COACHING_BALANCE_MISMATCH".to_string()),
        "{compiled:?}"
    );
}

#[test]
fn balance_rule_negative_balance() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (compiled, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            let mut ledger = format!("2026-10-01 open {ADA} package {PKG} 6 sessions\n");
            for day in 1..=7 {
                ledger.push_str(&format!(
                    "2026-10-{day:02} session {ADA} 60m paid note:{NOTE}\n"
                ));
            }
            write(root, "ledger/2026/10.cfd", &ledger);
        },
        rules,
    );
    let negative = ext_findings(&declarative, "E_COACHING_EXT_NEGATIVE");
    assert_eq!(negative.len(), 1, "{declarative:?}");
    assert_eq!(negative[0]["id"], ADA);
    assert_eq!(
        negative[0]["message"],
        format!("sessions_remaining for {ADA} is -1")
    );
    assert_eq!(
        codes(&compiled),
        vec!["E_COACHING_NEGATIVE_BALANCE"],
        "{compiled:?}"
    );
}

#[test]
fn balance_rule_comp_and_pps_do_not_consume() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-10-01 session {ADA} 60m comp note:{NOTE}\n\
                     2026-10-02 session {ADA} 60m pps note:{NOTE}\n\
                     2026-10-03 session {ADA} 60m paid note:{NOTE}\n\
                     2026-10-08 balance {ADA} sessions_remaining 5\n"
                ),
            );
        },
        rules,
    );
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_BALANCE").is_empty(),
        "comp and pps must not consume: {declarative:?}"
    );
}

#[test]
fn balance_rule_open_malformed_shape() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 open {ADA} 6\n"),
            );
        },
        rules,
    );
    let malformed = ext_findings(&declarative, "E_COACHING_EXT_OPEN");
    assert_eq!(malformed.len(), 1, "{declarative:?}");
    assert_eq!(
        malformed[0]["message"],
        "open line must be: DATE open PERSON-ID package PKG-ID N sessions"
    );
    assert_eq!(malformed[0]["file"], "ledger/2026/10.cfd");
    assert_eq!(malformed[0]["line"], 1);
}

#[test]
fn balance_rule_open_not_integer() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 open {ADA} package {PKG} six sessions\n"),
            );
        },
        rules,
    );
    let malformed = ext_findings(&declarative, "E_COACHING_EXT_OPEN");
    assert_eq!(malformed.len(), 1, "{declarative:?}");
    assert_eq!(malformed[0]["message"], "expected integer");
    assert_eq!(
        malformed[0]["fix"],
        "Use open <pkg-id> <positive-integer> on its own ledger line"
    );
}

#[test]
fn balance_rule_open_exceeds_cap() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 open {ADA} package {PKG} 100001 sessions\n"),
            );
        },
        rules,
    );
    let malformed = ext_findings(&declarative, "E_COACHING_EXT_OPEN");
    assert_eq!(malformed.len(), 1, "{declarative:?}");
    assert_eq!(
        malformed[0]["message"],
        "open N 100001 exceeds the cap of 100000"
    );
}

#[test]
fn balance_rule_open_total_overflow() {
    // The 100000 cap makes a total overflow unreachable with default
    // parameters, so this case raises the cap and opens `i64::MAX` twice.
    // The shipped side cannot be configured, so this one asserts the
    // declarative behaviour only (the arithmetic is shared).
    let rules = COACHING_EXT_BALANCE_RULE
        .replace("max_open_n = 100000", "max_open_n = 9223372036854775807");
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 9223372036854775807 sessions\n\
             2026-10-02 open {ADA} package {PKG2} 9223372036854775807 sessions\n"
        ),
    );
    install_coaching_ext(dir.path(), &coaching_ext_manifest(&rules));
    coaching_ext_vault(dir.path(), COACHING_EXT_CHECKS);
    let declarative = report_json(dir.path(), None);
    let malformed = ext_findings(&declarative, "E_COACHING_EXT_OPEN");
    assert_eq!(malformed.len(), 1, "{declarative:?}");
    assert_eq!(
        malformed[0]["message"],
        format!("open total for {ADA} overflows")
    );
}

#[test]
fn balance_rule_package_id_wrong_prefix() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            // A person id where a package id belongs: parsed, wrong type;
            // the line still counts as an open.
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 open {ADA} package {BEA} 6 sessions\n\
                     2026-10-08 balance {ADA} sessions_remaining 6\n"
                ),
            );
        },
        rules,
    );
    let wrong = ext_findings(&declarative, "E_COACHING_EXT_TYPE");
    assert_eq!(wrong.len(), 1, "{declarative:?}");
    assert_eq!(
        wrong[0]["message"],
        format!("package id '{BEA}' must use the pkg- prefix")
    );
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_BALANCE").is_empty(),
        "the line still opens 6: {declarative:?}"
    );
}

#[test]
fn balance_rule_merged_people_accumulate_to_canonical() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (compiled, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            note(root, NOTE, BEA, "2026-10-03");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 open {BEA} package {PKG} 6 sessions\n\
                     2026-10-02 merge {BEA} into {ADA}\n\
                     2026-10-03 session {ADA} 60m paid note:{NOTE}\n\
                     2026-10-08 balance {ADA} sessions_remaining 5\n"
                ),
            );
        },
        rules,
    );
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_BALANCE").is_empty(),
        "Bea's open and Ada's session share the canonical balance: {declarative:?}"
    );
    assert!(
        !codes(&compiled).contains(&"E_COACHING_BALANCE_MISMATCH".to_string()),
        "{compiled:?}"
    );
}

#[test]
fn balance_rule_icf_hours_decimal_rounding() {
    let rules = COACHING_EXT_BALANCE_RULE;
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 session {ADA} 1h30m paid note:{NOTE}\n\
                     2026-10-02 session {ADA} 45m paid note:{NOTE}\n\
                     2026-10-08 balance {ADA} icf_hours 2.25\n"
                ),
            );
        },
        rules,
    );
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_BALANCE").is_empty(),
        "135 minutes is exactly 2.25h in hundredths: {declarative:?}"
    );

    // A mismatch renders the decimal, not a float: 135m computed vs 2.30.
    let (_, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 session {ADA} 1h30m paid note:{NOTE}\n\
                     2026-10-02 session {ADA} 45m paid note:{NOTE}\n\
                     2026-10-08 balance {ADA} icf_hours 2.30\n"
                ),
            );
        },
        rules,
    );
    let mismatch = ext_findings(&declarative, "E_COACHING_EXT_BALANCE");
    assert_eq!(mismatch.len(), 1, "{declarative:?}");
    assert_eq!(
        mismatch[0]["message"],
        "icf_hours asserted 2.30, computed 2.25"
    );
}

#[test]
fn balance_rule_mismatch_matches_golden() {
    // The same vault as `balance_mismatch_golden`: open 6, one paid
    // session, assert 4 (computed 5). The fixture's finding must equal the
    // compiled finding field for field, modulo the pack's code.
    let (compiled, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-10-01 session {ADA} 60m paid note:{NOTE}\n\
                     2026-10-08 balance {ADA} sessions_remaining 4\n"
                ),
            );
        },
        COACHING_EXT_BALANCE_RULE,
    );
    let golden: Value =
        serde_json::from_str(&fs::read_to_string(golden_path("balance_mismatch.json")).unwrap())
            .unwrap();
    let golden_finding = &golden["findings"].as_array().unwrap()[0];
    let compiled_finding = &compiled["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "E_COACHING_BALANCE_MISMATCH")
        .expect("compiled mismatch");
    assert_eq!(golden_finding, *compiled_finding, "shipped side drifted");

    let declarative_finding = &ext_findings(&declarative, "E_COACHING_EXT_BALANCE")[0];
    for field in ["severity", "message", "fix", "file", "line", "id"] {
        assert_eq!(
            golden_finding[field], declarative_finding[field],
            "field {field} differs from the golden"
        );
    }
}

#[test]
fn balance_rule_matches_shipped_coaching() {
    // One vault that exercises every balance code the kind emits, on both
    // packs: the normalized findings must be equal.
    let (compiled, declarative) = assert_balance_parity(
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            note(root, NOTE, BEA, "2026-10-03");
            write(
                root,
                "ledger/2026/08.cfd",
                &format!(
                    "2026-08-01 open {BEA} package {PKG} 3 sessions\n\
                     2026-08-01 open {ADA} package bad-package 2 sessions\n\
                     2026-08-02 open {ADA} package {PKG2} two sessions\n\
                     2026-08-03 open {ADA} 6\n\
                     2026-08-04 open {ADA} package {PKG2} 100001 sessions\n\
                     2026-08-05 open {ADA} package {PKG2} 1 sessions\n"
                ),
            );
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 merge {BEA} into {ADA}\n\
                     2026-10-02 session {ADA} 1h30m paid note:{NOTE}\n\
                     2026-10-03 session {BEA} 45m pps note:{NOTE}\n\
                     2026-10-04 session {ADA} 30m comp note:{NOTE}\n\
                     2026-10-08 balance {ADA} sessions_remaining 4\n\
                     2026-10-08 balance {ADA} icf_hours 2.30\n"
                ),
            );
        },
        COACHING_EXT_BALANCE_RULE,
    );
    assert!(
        !normalized_findings(&compiled, BALANCE_CODE_MAP).is_empty(),
        "the fixture must trigger something: {compiled:?}"
    );
    assert_eq!(
        normalized_findings(&compiled, BALANCE_CODE_MAP),
        normalized_findings(&declarative, BALANCE_CODE_MAP)
    );
}

/// The fixture with one parameter patched, for the loader negatives.
fn install_invalid_coaching_ext(root: &Path, rules: &str) {
    install_coaching_ext(root, &coaching_ext_manifest(rules));
    coaching_ext_vault(root, COACHING_EXT_CHECKS);
}

fn assert_pack_invalid(root: &Path) {
    let json = report_json(root, None);
    assert!(
        codes(&json).contains(&"E_PACK_INVALID".to_string()),
        "expected E_PACK_INVALID: {json:?}"
    );
}

#[test]
fn balance_rule_loader_refuses_undeclared_units_metric() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_BALANCE_RULE.replace(
            "units_metric = \"sessions_remaining\"",
            "units_metric = \"ghost_metric\"",
        ),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn balance_rule_loader_refuses_same_verbs() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_BALANCE_RULE.replace("consume_verb = \"session\"", "consume_verb = \"open\""),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn balance_rule_loader_refuses_zero_cap_and_negative_cap() {
    for cap in ["0", "-1"] {
        let dir = tempfile::tempdir().unwrap();
        person(dir.path(), ADA, "Ada Example");
        install_invalid_coaching_ext(
            dir.path(),
            &COACHING_EXT_BALANCE_RULE
                .replace("max_open_n = 100000", &format!("max_open_n = {cap}")),
        );
        assert_pack_invalid(dir.path());
    }
}

#[test]
fn balance_rule_loader_refuses_builtin_code_param() {
    // #494/PD13: an external pack may not set any of the kind's code
    // parameters to a builtin code, even when the manifest declares the
    // pack-own code it could use instead.
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_BALANCE_RULE.replace(
            "parse_code = \"E_COACHING_EXT_PARSE\"",
            "parse_code = \"E_PARSE\"",
        ),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn balance_rule_loader_refuses_metric_owned_twice() {
    // Two ledger-balance rules sharing a metric would verify each
    // `balance` line twice; the loader refuses the pack.
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    let two_rules = format!(
        "{COACHING_EXT_BALANCE_RULE}\n{}",
        COACHING_EXT_BALANCE_RULE.replace("id = \"balance\"", "id = \"balance2\"")
    );
    install_invalid_coaching_ext(dir.path(), &two_rules);
    assert_pack_invalid(dir.path());
}

#[test]
fn balance_rule_balance_nonnegative_off_keeps_mismatch() {
    // The managed-severity decision: `balance_nonnegative = "off"`
    // suppresses only the negative-balance finding. A wrong `balance`
    // line must still report the mismatch, so turning the key off cannot
    // silently stop assertions from being verified.
    let setup = |root: &Path| {
        person(root, ADA, "Ada Example");
        let mut ledger = format!("2026-10-01 open {ADA} package {PKG} 6 sessions\n");
        for day in 1..=7 {
            ledger.push_str(&format!("2026-10-{day:02} session {ADA} 60m paid\n"));
        }
        ledger.push_str(&format!("2026-10-08 balance {ADA} sessions_remaining 5\n"));
        write(root, "ledger/2026/10.cfd", &ledger);
    };

    let off_dir = tempfile::tempdir().unwrap();
    setup(off_dir.path());
    install_coaching_ext(
        off_dir.path(),
        &coaching_ext_manifest(COACHING_EXT_BALANCE_RULE),
    );
    coaching_ext_vault(
        off_dir.path(),
        "coaching-ext.balance_nonnegative = \"off\"\n",
    );
    let off = report_json(off_dir.path(), None);
    assert!(
        ext_findings(&off, "E_COACHING_EXT_NEGATIVE").is_empty(),
        "off must suppress the negative finding: {off:?}"
    );
    let mismatch = ext_findings(&off, "E_COACHING_EXT_BALANCE");
    assert_eq!(mismatch.len(), 1, "{off:?}");
    assert_eq!(
        mismatch[0]["message"],
        "sessions_remaining asserted 5, computed -1"
    );

    // The positive control: with the key on, both findings appear.
    let on_dir = tempfile::tempdir().unwrap();
    setup(on_dir.path());
    install_coaching_ext(
        on_dir.path(),
        &coaching_ext_manifest(COACHING_EXT_BALANCE_RULE),
    );
    coaching_ext_vault(on_dir.path(), COACHING_EXT_CHECKS);
    let on = report_json(on_dir.path(), None);
    assert_eq!(
        ext_findings(&on, "E_COACHING_EXT_NEGATIVE").len(),
        1,
        "{on:?}"
    );
    assert_eq!(
        ext_findings(&on, "E_COACHING_EXT_BALANCE").len(),
        1,
        "{on:?}"
    );
}

// ---------------------------------------------------------------------------
// Declarative coaching kinds (#447 session-checks)
// ---------------------------------------------------------------------------

#[test]
fn session_checks_missing_duration() {
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} paid note:{NOTE}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    let found = ext_findings(&declarative, "E_COACHING_EXT_DURATION");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!("session for {ADA} has no parseable duration")
    );
    assert_eq!(
        normalized_codes(&compiled, SESSION_CODE_MAP),
        vec!["E_COACHING_MISSING_DURATION"]
    );
}

#[test]
fn session_checks_duration_off_suppresses() {
    let compiled_checks = DEFAULT_CHECKS.replace(
        "coaching.require_duration = \"error\"",
        "coaching.require_duration = \"off\"",
    );
    let ext_checks = "coaching-ext.require_duration = \"off\"\n";
    let (compiled, declarative) = assert_ext_parity_with(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} paid note:{NOTE}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
        SESSION_CODE_MAP,
        &compiled_checks,
        ext_checks,
    );
    assert!(
        normalized_codes(&compiled, SESSION_CODE_MAP).is_empty(),
        "{compiled:?}"
    );
    assert!(codes(&declarative).is_empty(), "{declarative:?}");
}

#[test]
fn session_checks_two_billing_tags() {
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} 60m paid pps note:{NOTE}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    let found = ext_findings(&declarative, "E_COACHING_EXT_TAGS");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!("session for {ADA} has more than one of paid, pps, comp")
    );
    assert_eq!(
        normalized_codes(&compiled, SESSION_CODE_MAP),
        vec!["E_COACHING_SESSION_TAGS"]
    );
}

#[test]
fn session_checks_no_tag() {
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} 60m note:{NOTE}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    let found = ext_findings(&declarative, "W_COACHING_EXT_UNTAGGED");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(found[0]["severity"], "warning");
    assert_eq!(
        found[0]["message"],
        format!("session for {ADA} has no paid, pps, or comp tag")
    );
    assert_eq!(
        normalized_codes(&compiled, SESSION_CODE_MAP),
        vec!["W_COACHING_SESSION_UNTAGGED"]
    );
}

#[test]
fn session_checks_one_tag_is_clean() {
    let (_, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    assert!(codes(&declarative).is_empty(), "{declarative:?}");
}

#[test]
fn session_checks_without_notes_matches_golden() {
    let declarative = ext_report(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-10-01 session {ADA} 60m paid\n"
                ),
            );
        },
        COACHING_EXT_SESSION_RULE,
        "",
    );
    let golden: Value = serde_json::from_str(
        &fs::read_to_string(golden_path("session_without_notes.json")).unwrap(),
    )
    .unwrap();
    let golden_finding = &golden["findings"].as_array().unwrap()[0];
    let found = ext_findings(&declarative, "E_COACHING_EXT_NOTES");
    assert_eq!(found.len(), 1, "{declarative:?}");
    for field in ["severity", "message", "fix", "file", "line", "id"] {
        assert_eq!(
            golden_finding[field], found[0][field],
            "field {field} differs from the golden"
        );
    }
}

#[test]
fn session_checks_note_on_line_covers() {
    let (_, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} 60m paid note:{NOTE}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    assert!(codes(&declarative).is_empty(), "{declarative:?}");
}

#[test]
fn session_checks_note_record_same_date_covers() {
    let (_, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} 60m paid\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    assert!(codes(&declarative).is_empty(), "{declarative:?}");
}

#[test]
fn session_checks_note_other_person_does_not_cover() {
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            note(root, NOTE2, BEA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {ADA} 60m paid\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    assert_eq!(
        ext_findings(&declarative, "E_COACHING_EXT_NOTES").len(),
        1,
        "{declarative:?}"
    );
    assert_eq!(
        normalized_codes(&compiled, SESSION_CODE_MAP),
        vec!["E_COACHING_SESSION_WITHOUT_NOTES"]
    );
}

#[test]
fn session_checks_non_person_id_notes_parity() {
    // `session_without_notes` filters on the verb only, so a session whose
    // id is not a person id (core reports `E_WRONG_ID_TYPE`) still gets the
    // notes finding. The per-entry duration and tag checks skip it, as the
    // compiled fold does.
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!("2026-10-01 session {PKG}\n"),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    let found = ext_findings(&declarative, "E_COACHING_EXT_NOTES");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(found[0]["id"], PKG);
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_DURATION").is_empty(),
        "a non-person id gets no duration check: {declarative:?}"
    );
    assert!(
        ext_findings(&declarative, "W_COACHING_EXT_UNTAGGED").is_empty(),
        "a non-person id gets no tag check: {declarative:?}"
    );
    assert_eq!(
        normalized_codes(&compiled, SESSION_CODE_MAP),
        vec!["E_COACHING_SESSION_WITHOUT_NOTES"]
    );
}

#[test]
fn session_checks_notes_severity_warning_vs_error_vs_off() {
    for (ext_severity, expected) in [
        ("warning", Some("warning")),
        ("error", Some("error")),
        ("off", None),
    ] {
        let compiled_checks = DEFAULT_CHECKS.replace(
            "coaching.session_notes = \"warning\"",
            &format!("coaching.session_notes = \"{ext_severity}\""),
        );
        let ext_checks = format!("coaching-ext.session_notes = \"{ext_severity}\"\n");
        let (compiled, declarative) = assert_ext_parity_with(
            |root| {
                person(root, ADA, "Ada Example");
                write(
                    root,
                    "ledger/2026/10.cfd",
                    &format!("2026-10-01 session {ADA} 60m paid\n"),
                );
            },
            COACHING_EXT_SESSION_RULE,
            SESSION_CODE_MAP,
            &compiled_checks,
            &ext_checks,
        );
        match expected {
            Some(severity) => {
                let found = ext_findings(&declarative, "E_COACHING_EXT_NOTES");
                assert_eq!(found.len(), 1, "{declarative:?}");
                assert_eq!(found[0]["severity"], severity, "{declarative:?}");
                assert_eq!(
                    normalized_codes(&compiled, SESSION_CODE_MAP),
                    vec!["E_COACHING_SESSION_WITHOUT_NOTES"]
                );
            }
            None => {
                assert!(codes(&declarative).is_empty(), "{declarative:?}");
                assert!(
                    normalized_codes(&compiled, SESSION_CODE_MAP).is_empty(),
                    "{compiled:?}"
                );
            }
        }
    }
}

#[test]
fn session_checks_merged_person_notes_cover() {
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            // Bea's note is dated the session day and Bea is merged into
            // Ada before as_of, so it covers Ada's session.
            note(root, NOTE2, BEA, "2026-10-02");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-02 merge {BEA} into {ADA}\n\
                     2026-10-02 session {ADA} 60m paid\n"
                ),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    assert!(codes(&declarative).is_empty(), "{declarative:?}");
    assert!(
        normalized_codes(&compiled, SESSION_CODE_MAP).is_empty(),
        "{compiled:?}"
    );
}

#[test]
fn session_checks_matches_shipped_coaching() {
    let (compiled, declarative) = assert_session_parity(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-10-01");
            write(
                root,
                "ledger/2026/10.cfd",
                &format!(
                    "2026-10-01 session {ADA} paid note:{NOTE}\n\
                     2026-10-02 session {ADA} 60m paid pps note:{NOTE}\n\
                     2026-10-03 session {ADA} 60m note:{NOTE}\n\
                     2026-10-04 session {ADA} 60m paid\n"
                ),
            );
        },
        COACHING_EXT_SESSION_RULE,
    );
    assert_eq!(
        normalized_findings(&compiled, SESSION_CODE_MAP),
        normalized_findings(&declarative, SESSION_CODE_MAP)
    );
    assert_eq!(normalized_findings(&compiled, SESSION_CODE_MAP).len(), 4);
}

#[test]
fn session_checks_loader_refuses_empty_billing_tags() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_SESSION_RULE.replace(
            "billing_tags = [\"paid\", \"pps\", \"comp\"]",
            "billing_tags = []",
        ),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn session_checks_loader_refuses_empty_verb() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_SESSION_RULE.replace("verb = \"session\"", "verb = \"\""),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn session_checks_loader_refuses_unclaimed_verb() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_SESSION_RULE.replace("verb = \"session\"", "verb = \"touch\""),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn session_checks_loader_refuses_missing_message_variant() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    let manifest = coaching_ext_manifest(COACHING_EXT_SESSION_RULE).replace(
        "default_fix = \"Add a note for that person and date, or note:n-<ULID> on the session line\"\n",
        "",
    );
    install_coaching_ext(dir.path(), &manifest);
    coaching_ext_vault(dir.path(), COACHING_EXT_CHECKS);
    assert_pack_invalid(dir.path());
}

#[test]
fn session_checks_loader_refuses_missing_notes_code() {
    // #629: the code parameters have no fallback; omitting one is
    // `E_PACK_INVALID`. The kind's own unit test asserts the parameter
    // name in the message.
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &COACHING_EXT_SESSION_RULE.replace("notes_code = \"E_COACHING_EXT_NOTES\"\n", ""),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn balance_rule_loader_refuses_retired_code_param() {
    // #629: a retired name is refused as a parameter value, not accepted
    // because it is still a builtin. The refusal is at manifest parse, so
    // the fixture cannot compute a real hash (`install_external_pack_raw`
    // + an unusable pin, like the other parse-time negatives).
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    let manifest = coaching_ext_manifest(&COACHING_EXT_BALANCE_RULE.replace(
        "negative_code = \"E_COACHING_EXT_NEGATIVE\"",
        "negative_code = \"E_NEGATIVE_BALANCE\"",
    ));
    install_external_pack_raw(dir.path(), "coaching-ext", "0.1", &manifest);
    install_lockfile(
        dir.path(),
        "coaching-ext",
        "0.1",
        &unusable_external_pack_hash(),
    );
    coaching_ext_vault(dir.path(), COACHING_EXT_CHECKS);
    assert_pack_invalid(dir.path());
}

// ---------------------------------------------------------------------------
// Declarative coaching kinds (#448 activity-gap)
// ---------------------------------------------------------------------------

#[test]
fn gap_rule_inclusive_window_edge() {
    // Last session exactly `gap_days` (45) before as_of is inside the
    // window; one day older is a gap.
    let (_, edge) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/08.cfd",
            &format!(
                "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
                 2026-08-24 session {ADA} 60m paid\n"
            ),
        );
    });
    assert!(
        ext_findings(&edge, "E_COACHING_EXT_GAP").is_empty(),
        "{edge:?}"
    );

    let (compiled, older) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/08.cfd",
            &format!(
                "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
                 2026-08-23 session {ADA} 60m paid\n"
            ),
        );
    });
    let found = ext_findings(&older, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{older:?}");
    assert_eq!(found[0]["id"], ADA);
    assert_eq!(
        normalized_codes(&compiled, GAP_CODE_MAP),
        vec!["E_COACHING_PAID_SESSION_GAP"]
    );
    assert_eq!(found[0]["message"], format!(
        "paid client {ADA} has remaining sessions and no session on or after 2026-08-24 (last was 2026-08-23)"
    ));
}

#[test]
fn gap_rule_never_started_none_variant() {
    // Remaining units but no session ever, and the open is older than the
    // window: the `none` variant.
    let (_, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/01.cfd",
            &format!("2026-01-01 open {ADA} package {PKG} 6 sessions\n"),
        );
    });
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!("paid client {ADA} has no session logged")
    );
    assert_eq!(
        found[0]["fix"],
        "Log a session, close the package, or widen coaching.paid_session_gap_days (currently 45)"
    );
}

#[test]
fn gap_rule_remaining_variant() {
    let (_, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/01.cfd",
            &format!("2026-01-01 open {ADA} package {PKG} 6 sessions\n"),
        );
        write(
            root,
            "ledger/2026/06.cfd",
            &format!("2026-06-01 session {ADA} 60m paid\n"),
        );
    });
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!(
            "paid client {ADA} has remaining sessions and no session on or after 2026-08-24 (last was 2026-06-01)"
        )
    );
}

#[test]
fn gap_rule_no_remaining_variant() {
    // A pps session inside the lookback keeps a spent package a paid
    // client; the last session is old, so the `no_remaining` variant.
    let (compiled, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/05.cfd",
            &format!(
                "2026-05-01 open {ADA} package {PKG} 1 sessions\n\
                 2026-05-02 session {ADA} 60m paid\n"
            ),
        );
        write(
            root,
            "ledger/2026/08.cfd",
            &format!("2026-08-01 session {ADA} 60m pps\n"),
        );
    });
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!("paid client {ADA} has no session on or after 2026-08-24 (last was 2026-08-01)")
    );
    assert_eq!(
        normalized_codes(&compiled, GAP_CODE_MAP),
        vec!["E_COACHING_PAID_SESSION_GAP"]
    );
}

#[test]
fn gap_rule_spent_package_no_finding_when_expected() {
    // Spent package, no pps, last session old: not a paid client, no gap.
    let (_, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/01.cfd",
            &format!(
                "2026-01-01 open {ADA} package {PKG} 1 sessions\n\
                 2026-01-01 session {ADA} 60m paid\n"
            ),
        );
    });
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_GAP").is_empty(),
        "{declarative:?}"
    );
}

#[test]
fn gap_rule_open_resets_clock() {
    // A recent opener resets the clock even when the last session is old,
    // and the opener adds units (remaining 6).
    let (_, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/01.cfd",
            &format!(
                "2026-01-01 open {ADA} package {PKG} 6 sessions\n\
                 2026-01-02 session {ADA} 60m paid\n"
            ),
        );
        write(
            root,
            "ledger/2026/10.cfd",
            &format!("2026-10-01 open {ADA} package {PKG2} 1 sessions\n"),
        );
    });
    assert!(
        ext_findings(&declarative, "E_COACHING_EXT_GAP").is_empty(),
        "{declarative:?}"
    );
}

#[test]
fn gap_rule_merged_person_clock() {
    // The clock is merge-aware: the opener is under the root and the
    // session under the merged member. With the coaching verbs this rides
    // the shared fold's `last_session_on` / `last_open_on` helpers.
    let (compiled, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        person(root, BEA, "Bea Demo");
        write(
            root,
            "ledger/2026/01.cfd",
            &format!(
                "2026-01-01 open {ADA} package {PKG} 6 sessions\n\
                 2026-01-02 merge {BEA} into {ADA}\n"
            ),
        );
        write(
            root,
            "ledger/2026/08.cfd",
            &format!("2026-08-01 session {BEA} 60m paid\n"),
        );
    });
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(found[0]["id"], ADA);
    assert_eq!(
        found[0]["message"],
        format!(
            "paid client {ADA} has remaining sessions and no session on or after 2026-08-24 (last was 2026-08-01)"
        )
    );
    assert_eq!(
        normalized_findings(&compiled, GAP_CODE_MAP),
        normalized_findings(&declarative, GAP_CODE_MAP)
    );
}

#[test]
fn gap_rule_merged_person_clock_with_distinct_activity_verb() {
    // `activity_verb` differs from the balance rule's `consume_verb`, so
    // the clock takes the vault scan through `group_members`. The only
    // `gathering` line sits under the merged member, so a scan that was
    // not merge-aware would fall back to the old opener and pick the
    // `none` variant instead of `remaining`.
    let rules = format!(
        "{COACHING_EXT_BALANCE_RULE}\n{}",
        COACHING_EXT_GAP_RULE.replace(
            "activity_verb = \"session\"",
            "activity_verb = \"gathering\""
        )
    );
    let (compiled, declarative) = assert_ext_parity(
        |root| {
            person(root, ADA, "Ada Example");
            person(root, BEA, "Bea Demo");
            write(
                root,
                "ledger/2026/01.cfd",
                &format!(
                    "2026-01-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-01-02 merge {BEA} into {ADA}\n"
                ),
            );
            write(
                root,
                "ledger/2026/08.cfd",
                &format!(
                    "2026-08-01 session {ADA} 60m paid\n\
                     2026-08-01 gathering {BEA}\n"
                ),
            );
        },
        &rules,
        GAP_CODE_MAP,
    );
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!(
            "paid client {ADA} has remaining sessions and no session on or after 2026-08-24 (last was 2026-08-01)"
        )
    );
    assert_eq!(
        normalized_findings(&compiled, GAP_CODE_MAP),
        normalized_findings(&declarative, GAP_CODE_MAP)
    );
}

#[test]
fn gap_rule_pps_lookback_window() {
    // Inside the 180-day lookback a pps session keeps the spent package a
    // paid client; outside it does not.
    let (_, inside) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/05.cfd",
            &format!(
                "2026-05-01 open {ADA} package {PKG} 1 sessions\n\
                 2026-05-02 session {ADA} 60m paid\n"
            ),
        );
        write(
            root,
            "ledger/2026/08.cfd",
            &format!("2026-08-01 session {ADA} 60m pps\n"),
        );
    });
    assert_eq!(
        ext_findings(&inside, "E_COACHING_EXT_GAP").len(),
        1,
        "{inside:?}"
    );

    let (_, outside) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        write(
            root,
            "ledger/2026/03.cfd",
            &format!(
                "2026-03-01 open {ADA} package {PKG} 1 sessions\n\
                 2026-03-01 session {ADA} 60m paid\n\
                 2026-03-02 session {ADA} 60m pps\n"
            ),
        );
    });
    assert!(
        ext_findings(&outside, "E_COACHING_EXT_GAP").is_empty(),
        "{outside:?}"
    );
}

#[test]
fn gap_rule_severity_off() {
    let compiled_checks = DEFAULT_CHECKS.replace(
        "coaching.paid_session_gap = \"warning\"",
        "coaching.paid_session_gap = \"off\"",
    );
    let ext_checks = "coaching-ext.paid_session_gap = \"off\"\n";
    let (compiled, declarative) = assert_ext_parity_with(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/01.cfd",
                &format!("2026-01-01 open {ADA} package {PKG} 6 sessions\n"),
            );
        },
        &coaching_ext_gap_rules(),
        GAP_CODE_MAP,
        &compiled_checks,
        ext_checks,
    );
    assert!(
        normalized_codes(&compiled, GAP_CODE_MAP).is_empty(),
        "{compiled:?}"
    );
    assert!(
        normalized_codes(&declarative, GAP_CODE_MAP).is_empty(),
        "{declarative:?}"
    );
}

#[test]
fn gap_rule_days_override_from_config() {
    let compiled_checks = DEFAULT_CHECKS.replace(
        "coaching.paid_session_gap_days = 45",
        "coaching.paid_session_gap_days = 10",
    );
    let ext_checks = "coaching-ext.paid_session_gap_days = 10\n";
    let (compiled, declarative) = assert_ext_parity_with(
        |root| {
            person(root, ADA, "Ada Example");
            write(
                root,
                "ledger/2026/09.cfd",
                &format!(
                    "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-09-18 session {ADA} 60m paid\n"
                ),
            );
        },
        &coaching_ext_gap_rules(),
        GAP_CODE_MAP,
        &compiled_checks,
        ext_checks,
    );
    assert_eq!(
        normalized_codes(&compiled, GAP_CODE_MAP),
        vec!["E_COACHING_PAID_SESSION_GAP"]
    );
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    assert_eq!(
        found[0]["message"],
        format!(
            "paid client {ADA} has remaining sessions and no session on or after 2026-09-28 (last was 2026-09-18)"
        )
    );
    assert!(
        found[0]["fix"].as_str().unwrap().contains("currently 10"),
        "{declarative:?}"
    );
}

#[test]
fn gap_rule_matches_golden_paid_session_gap() {
    let declarative = ext_report(
        |root| {
            person(root, ADA, "Ada Example");
            note(root, NOTE, ADA, "2026-08-23");
            write(
                root,
                "ledger/2026/08.cfd",
                &format!(
                    "2026-08-01 open {ADA} package {PKG} 6 sessions\n\
                     2026-08-23 session {ADA} 60m paid note:{NOTE}\n"
                ),
            );
        },
        &coaching_ext_gap_rules(),
        "",
    );
    let golden: Value =
        serde_json::from_str(&fs::read_to_string(golden_path("paid_session_gap.json")).unwrap())
            .unwrap();
    let golden_finding = &golden["findings"].as_array().unwrap()[0];
    let found = ext_findings(&declarative, "E_COACHING_EXT_GAP");
    assert_eq!(found.len(), 1, "{declarative:?}");
    for field in ["severity", "message", "fix", "id"] {
        assert_eq!(
            golden_finding[field], found[0][field],
            "field {field} differs from the golden"
        );
    }
}

#[test]
fn gap_rule_matches_shipped_coaching() {
    let (compiled, declarative) = assert_gap_parity(|root| {
        person(root, ADA, "Ada Example");
        person(root, BEA, "Bea Demo");
        person(root, CAM, "Cam Example");
        // Ada: never started (none). Bea: remaining. Cam: spent but pps.
        write(
            root,
            "ledger/2026/01.cfd",
            &format!(
                "2026-01-01 open {ADA} package {PKG} 6 sessions\n\
                 2026-01-01 open {BEA} package {PKG} 6 sessions\n"
            ),
        );
        write(
            root,
            "ledger/2026/05.cfd",
            &format!(
                "2026-05-01 open {CAM} package {PKG2} 1 sessions\n\
                 2026-05-02 session {CAM} 60m paid\n"
            ),
        );
        write(
            root,
            "ledger/2026/06.cfd",
            &format!("2026-06-01 session {BEA} 60m paid\n"),
        );
        write(
            root,
            "ledger/2026/08.cfd",
            &format!("2026-08-01 session {CAM} 60m pps\n"),
        );
    });
    assert_eq!(
        normalized_findings(&compiled, GAP_CODE_MAP),
        normalized_findings(&declarative, GAP_CODE_MAP)
    );
    assert_eq!(normalized_findings(&compiled, GAP_CODE_MAP).len(), 3);
}

#[test]
fn gap_rule_loader_refuses_undeclared_int_key() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &format!(
            "{}\n{}",
            COACHING_EXT_BALANCE_RULE,
            COACHING_EXT_GAP_RULE.replace(
                "gap_days_key = \"coaching-ext.paid_session_gap_days\"",
                "gap_days_key = \"coaching-ext.ghost_days\""
            )
        ),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn gap_rule_loader_refuses_undeclared_balance_metric() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    install_invalid_coaching_ext(
        dir.path(),
        &format!(
            "{}\n{}",
            COACHING_EXT_BALANCE_RULE,
            COACHING_EXT_GAP_RULE.replace(
                "balance_metric = \"sessions_remaining\"",
                "balance_metric = \"ghost_metric\""
            )
        ),
    );
    assert_pack_invalid(dir.path());
}

#[test]
fn gap_rule_loader_refuses_retired_generic_code() {
    // #629: `activity-gap` has no `*_code` parameter; its generic `code`
    // is the one code, and a retired name is never valid. The refusal is at
    // manifest parse, so the fixture uses an unusable pin.
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    let manifest = coaching_ext_manifest(&format!(
        "{}\n{}",
        COACHING_EXT_BALANCE_RULE,
        COACHING_EXT_GAP_RULE.replace(
            "code = \"E_COACHING_EXT_GAP\"",
            "code = \"E_PAID_SESSION_GAP\""
        )
    ));
    install_external_pack_raw(dir.path(), "coaching-ext", "0.1", &manifest);
    install_lockfile(
        dir.path(),
        "coaching-ext",
        "0.1",
        &unusable_external_pack_hash(),
    );
    coaching_ext_vault(dir.path(), COACHING_EXT_CHECKS);
    assert_pack_invalid(dir.path());
}

// ---------------------------------------------------------------------------
// #449: the shipped external coaching pack
//
// The inline `coaching_ext_manifest` above tunes one rule per test to pin
// each kind in isolation. This section loads the real `packs/coaching/`
// manifest — all four rules at once — and pins the shipped unit, its skill
// drift, and the new pack-own finding codes.
// ---------------------------------------------------------------------------

/// Recursively copy `src` into `dst` (the demo vault is a tree).
fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// The demo vault's records and ledger without its `confidant.toml`; the
/// context harness writes its own config.
fn demo_vault_records(root: &Path) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault");
    copy_tree(&src, root);
    fs::remove_file(root.join("confidant.toml")).unwrap();
}

/// #449: the shipped pack's `note-ref` rule emits its own pack codes, not
/// the shared core codes. The three cases are invalid id, wrong id type,
/// and a missing note.
#[test]
fn shipped_coaching_note_ref_codes_are_pack_own() {
    let dir = tempfile::tempdir().unwrap();
    vault_toml(dir.path(), DEFAULT_CHECKS);
    person(dir.path(), ADA, "Ada Example");
    write(
        dir.path(),
        "ledger/2026/10.cfd",
        &format!(
            "2026-10-01 open {ADA} package {PKG} 10 sessions\n\
             2026-10-01 session {ADA} 60m paid note:not-an-id\n\
             2026-10-02 session {ADA} 60m paid note:{ADA}\n\
             2026-10-03 session {ADA} 60m paid note:{NOTE2}\n"
        ),
    );
    let json = report_json(dir.path(), None);
    let mut got = codes(&json);
    got.sort();
    assert_eq!(
        got,
        vec![
            "E_COACHING_NOTE_INVALID_ID",
            "E_COACHING_NOTE_WRONG_TYPE",
            "E_COACHING_UNKNOWN_RECORD",
        ],
        "{json:?}"
    );
}

/// #449: the shipped pack is a pinned, shippable unit. Any edit to its
/// bytes changes this hash, so a change is deliberate.
#[test]
fn shipped_coaching_pack_hash_is_stable() {
    let pack = read_pack_dir(&shipped_coaching_dir()).expect("shipped pack dir must read");
    assert_eq!(
        pack.hash, "sha256:d5dbb563979e7b16f2a35f0a59412720149a43ef207fa6a6d799da669d3ab604",
        "the shipped coaching pack changed; update this pin in the same commit"
    );
    assert_eq!(pack.files.len(), 3);
}

/// #449: the demo vault's vendored coaching pack is a byte-for-byte copy of
/// the shipped `packs/coaching/`, so the example cannot drift.
#[test]
fn demo_vault_vendored_coaching_matches_shipped_pack() {
    let demo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/demo-vault/packs/coaching@0.1");
    let shipped = shipped_coaching_dir();
    for name in ["manifest.toml", "SKILL.md", "0.1.md"] {
        assert_eq!(
            fs::read(demo.join(name)).unwrap(),
            fs::read(shipped.join(name)).unwrap(),
            "examples/demo-vault/packs/coaching@0.1/{name} drifted from packs/coaching/{name}"
        );
    }
    assert_eq!(
        read_pack_dir(&demo).unwrap().hash,
        read_pack_dir(&shipped).unwrap().hash
    );
}

/// #449 drift test: the shipped pack's SKILL.md must document every code
/// and every `[checks]` key the manifest declares.
#[test]
fn shipped_coaching_skill_documents_all_codes_and_keys() {
    let dir = shipped_coaching_dir();
    let manifest_text = fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let manifest = confidant_core::packs::manifest::parse_manifest_external(&manifest_text)
        .expect("shipped coaching manifest parses");
    let skill = fs::read_to_string(dir.join("SKILL.md")).unwrap();
    for code in &manifest.finding_codes {
        assert!(
            skill.contains(code.as_str()),
            "pack can emit {code} but its SKILL.md does not document it"
        );
    }
    for key in manifest
        .checks
        .severity
        .iter()
        .map(|s| &s.key)
        .chain(manifest.checks.int.iter().map(|i| &i.key))
    {
        assert!(
            skill.contains(&format!("`{key}`")),
            "pack declares [checks] key {key} but its SKILL.md does not document it"
        );
    }
}

/// #449: a vault that lists `coaching@0.1` but has not vendored the pack
/// is `E_PACK_UNKNOWN` — the compiled fallback is gone.
#[test]
fn coaching_without_vendored_pack_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    external_vault_toml(dir.path(), "\"coaching@0.1\"", DEFAULT_CHECKS);
    let json = report_json(dir.path(), None);
    assert!(
        codes(&json).contains(&"E_PACK_UNKNOWN".to_string()),
        "{json:?}"
    );
}

// ---------------------------------------------------------------------------
// #594: core-owned ledger-sessions context view ([context] opt-in)
// ---------------------------------------------------------------------------

/// One `context` bundle, serialized, for `person`.
fn context_bundle(root: &Path, person: &str) -> Value {
    let vault = load_vault(root).unwrap();
    let id = confidant_core::RecordId::parse(person).unwrap();
    let bundle = build_context(&vault, &id, true, &PackScope::All, false).unwrap();
    serde_json::to_value(&bundle).unwrap()
}

/// The `ledger-sessions` row at `key` in a `context` bundle's `packs` map.
fn ledger_sessions_row<'a>(bundle: &'a Value, key: &str) -> &'a Value {
    &bundle["packs"][key]
}

/// A demo-vault copy with the shipped coaching pack installed.
fn demo_vault_with_coaching() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    demo_vault_records(dir.path());
    vault_toml(dir.path(), DEFAULT_CHECKS);
    dir
}

/// #594/#449: the shipped external pack serves the `ledger-sessions` view
/// on the demo vault, including the legacy `coaching` alias.
#[test]
fn coaching_context_view_on_demo_vault() {
    let dir = demo_vault_with_coaching();
    let bundle = context_bundle(dir.path(), ADA);
    // Ada: 6 opened minus two paid sessions; 60m + 45m = 1.75h.
    let row = ledger_sessions_row(&bundle, "coaching@0.1");
    assert_eq!(row["sessions_remaining"], 4, "{bundle:?}");
    assert_eq!(row["icf_hours"], 1.75, "{bundle:?}");
    let dates: Vec<&str> = row["recent_sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["date"].as_str().unwrap())
        .collect();
    assert_eq!(dates, vec!["2026-10-08", "2026-10-01"], "{bundle:?}");
    assert_eq!(
        bundle["coaching"], bundle["packs"]["coaching@0.1"],
        "the coaching pack must populate the legacy alias: {bundle:?}"
    );
}

/// #594/#449: the three golden vaults' `ledger-sessions` values through
/// the shipped external pack. The values are literal, so drift fails.
#[test]
fn coaching_context_view_on_goldens() {
    for setup in [
        balance_mismatch_vault as fn(&Path),
        paid_session_gap_vault,
        session_without_notes_vault,
    ] {
        let dir = tempfile::tempdir().unwrap();
        setup(dir.path());
        vault_toml(dir.path(), DEFAULT_CHECKS);
        let bundle = context_bundle(dir.path(), ADA);
        let row = ledger_sessions_row(&bundle, "coaching@0.1");
        assert_eq!(row["sessions_remaining"], 5, "{bundle:?}");
        assert_eq!(row["icf_hours"], 1.0, "{bundle:?}");
    }
}

/// #594 privacy: the coaching row is byte-identical with and without the
/// private data (`--exclude-private` maps to `include_private = false`). The
/// view is ledger metadata only, so neither the §12 gate nor
/// `private_context_fields` has anything to strip.
#[test]
fn context_ledger_sessions_view_is_identical_without_private() {
    let dir = demo_vault_with_coaching();
    let vault = load_vault(dir.path()).unwrap();
    let ada = confidant_core::RecordId::parse(ADA).unwrap();
    let full = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
    let stripped = build_context(&vault, &ada, false, &PackScope::All, false).unwrap();
    assert_eq!(full.coaching, stripped.coaching);
    assert_eq!(full.packs["coaching@0.1"], stripped.packs["coaching@0.1"]);
    // The JSON bytes of the row are unchanged, so a reader that diffs the
    // two flags sees no difference at all.
    assert_eq!(
        serde_json::to_string(&full.coaching).unwrap(),
        serde_json::to_string(&stripped.coaching).unwrap()
    );
}

/// #594 privacy: a `no-ai` person's row carries only the ledger keys — the
/// view reads no record content, so the §12 cleared set does not gate it and
/// nothing beyond the three metadata keys can appear.
#[test]
fn context_ledger_sessions_view_no_ai_carries_only_ledger_keys() {
    let ledger_keys = ["icf_hours", "recent_sessions", "sessions_remaining"];
    let dir = demo_vault_with_coaching();
    let bundle = context_bundle(dir.path(), CAM);
    let row = ledger_sessions_row(&bundle, "coaching@0.1")
        .as_object()
        .unwrap();
    let mut keys: Vec<&str> = row.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ledger_keys, "{bundle:?}");
    // Cam's own figures: 4 opened, one 45m paid session.
    assert_eq!(row["sessions_remaining"], 3, "{bundle:?}");
    assert_eq!(row["icf_hours"], 0.75, "{bundle:?}");
}

/// Copy the shipped coaching pack under another name, keeping its
/// `[context]` opt-in, and pin it. Returns the pack directory hash.
fn install_renamed_coaching(root: &Path, name: &str) -> String {
    let src = shipped_coaching_dir();
    let dst = root.join(format!("packs/{name}@0.1"));
    fs::create_dir_all(&dst).unwrap();
    for entry in fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        let mut text = fs::read_to_string(entry.path()).unwrap();
        if entry.file_name() == "manifest.toml" {
            text = text
                .replace("name = \"coaching\"", &format!("name = \"{name}\""))
                // The loader requires `[checks]`/rule keys to be namespaced
                // to the pack's own name.
                .replace("\"coaching.", &format!("\"{name}."));
        }
        fs::write(dst.join(entry.file_name()), text).unwrap();
    }
    let hash = read_pack_dir(&dst).unwrap().hash;
    install_lockfile(root, name, "0.1", &hash);
    hash
}

/// #594/#449: the legacy `coaching` alias is tied to the coaching pack, not
/// to the view kind. The shipped external `coaching@0.1` populates it; a
/// `[context]` pack under another name serves its own row but leaves the
/// alias null; and a vault with no coaching pack has no alias at all.
#[test]
fn context_legacy_coaching_alias_is_tied_to_the_coaching_pack() {
    let dir = demo_vault_with_coaching();
    let bundle = context_bundle(dir.path(), ADA);
    assert!(!bundle["coaching"].is_null(), "{bundle:?}");
    assert_eq!(bundle["coaching"], bundle["packs"]["coaching@0.1"]);

    let other_dir = tempfile::tempdir().unwrap();
    demo_vault_records(other_dir.path());
    install_renamed_coaching(other_dir.path(), "other-coaching");
    external_vault_toml(other_dir.path(), "\"other-coaching@0.1\"", "");
    let other = context_bundle(other_dir.path(), ADA);
    assert!(!other["packs"]["other-coaching@0.1"].is_null(), "{other:?}");
    assert!(
        other["coaching"].is_null(),
        "a non-coaching [context] pack must not own the legacy alias: {other:?}"
    );

    // No coaching pack at all (only the implicit built-in personal pack).
    let none_dir = tempfile::tempdir().unwrap();
    demo_vault_records(none_dir.path());
    external_vault_toml(none_dir.path(), "", "");
    let none = context_bundle(none_dir.path(), ADA);
    assert!(none["coaching"].is_null(), "{none:?}");
    assert!(none["packs"].get("coaching@0.1").is_none(), "{none:?}");
}

/// #594: a `[context]` the loader refuses (here an unknown view) fails the
/// external pack closed as `E_PACK_INVALID`, before anything folds.
#[test]
fn external_context_unknown_view_is_pack_invalid() {
    let manifest = fs::read_to_string(shipped_coaching_dir().join("manifest.toml"))
        .unwrap()
        .replace("view = \"ledger-sessions\"", "view = \"nope\"");
    let dir = tempfile::tempdir().unwrap();
    person(dir.path(), ADA, "Ada Example");
    write(dir.path(), "packs/coaching@0.1/manifest.toml", &manifest);
    write(
        dir.path(),
        "packs/coaching@0.1/SKILL.md",
        "# coaching pack.\n",
    );
    write(dir.path(), "packs/coaching@0.1/0.1.md", "# coaching 0.1\n");
    // `read_pack_dir` validates the manifest, so the bad `[context]` makes it
    // fail here too; the pin only has to be well-formed so the lockfile
    // parses and the failure is the manifest, not the pin.
    let pack_dir = dir.path().join("packs/coaching@0.1");
    let hash = read_pack_dir(&pack_dir)
        .map(|p| p.hash)
        .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
    install_lockfile(dir.path(), "coaching", "0.1", &hash);
    external_vault_toml(dir.path(), "\"coaching@0.1\"", DEFAULT_CHECKS);
    let json = report_json(dir.path(), None);
    let finding = finding_by_code(&json, "E_PACK_INVALID");
    assert_eq!(finding["file"], "packs/coaching@0.1", "{json:?}");
}
