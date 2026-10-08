//! Check-engine cases: golden JSON, gap-rule edges, malformed input.

use std::fs;
use std::path::{Path, PathBuf};

use confidant_core::check::{CheckOptions, FindingCode, Severity};
use confidant_core::{check_vault, load_vault};
use serde_json::{json, Value};

const ADA: &str = "p-01M3TC5H00MPJG000000000000";
const PKG: &str = "pkg-01M3TC5H00MPJG004SK4000009";
const NOTE: &str = "n-01M3TC5H00MPJG002NAM000005";

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
    assert_eq!(codes(&json), vec!["E_PAID_SESSION_GAP"]);

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
fn pay_per_session_does_not_consume_package() {
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
        !codes(&json).contains(&"E_NEGATIVE_BALANCE".into()),
        "{json}"
    );
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
