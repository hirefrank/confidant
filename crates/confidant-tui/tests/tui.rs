//! Contract, snapshot, and live-shape integration tests for `confidant-tui`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use confidant_tui::app::{ActiveView, App, InputMode};
use confidant_tui::contract::{
    parse_raw_output, CheckReport, Context, ContractOutcome, DoctorReport, FindResult,
};
use confidant_tui::runner::{FakeRunner, ProcessRunner, Runner};

const WIDTH: u16 = 100;
const HEIGHT: u16 = 24;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn demo_vault() -> PathBuf {
    repo_root().join("examples/demo-vault")
}

fn golden_path(name: &str) -> PathBuf {
    repo_root().join("testdata/golden").join(name)
}

fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(name)
}

fn confidant_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let exe = std::env::current_exe().expect("current_exe");
        let target_debug = exe
            .parent()
            .and_then(|p| p.parent())
            .expect("target/debug directory");
        let bin_name = if cfg!(windows) {
            "confidant.exe"
        } else {
            "confidant"
        };
        let candidate = target_debug.join(bin_name);
        if !candidate.exists() {
            let status = Command::new(env!("CARGO"))
                .args(["build", "-p", "confidant-cli", "--locked"])
                .current_dir(repo_root())
                .status()
                .expect("build confidant-cli");
            assert!(status.success(), "cargo build -p confidant-cli failed");
        }
        assert!(
            candidate.exists(),
            "expected confidant binary at {}",
            candidate.display()
        );
        candidate
    })
    .clone()
}

fn render_to_string<R: Runner>(app: &App<R>) -> String {
    let backend = TestBackend::new(WIDTH, HEIGHT);
    let mut terminal = Terminal::new(backend).expect("TestBackend terminal");
    terminal
        .draw(|frame| app.render(frame))
        .expect("draw frame");
    let buffer = terminal.backend().buffer();
    let mut lines = Vec::with_capacity(HEIGHT as usize);
    for y in 0..HEIGHT {
        let mut row = String::new();
        for x in 0..WIDTH {
            row.push_str(buffer[(x, y)].symbol());
        }
        lines.push(row.trim_end().to_owned());
    }
    lines.join("\n") + "\n"
}

fn assert_snapshot(name: &str, actual: &str) {
    let path = snapshot_path(name);
    if std::env::var("UPDATE_SNAPSHOTS").is_ok() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create snapshots dir");
        }
        fs::write(&path, actual).expect("write snapshot");
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing snapshot {path:?}; run with UPDATE_SNAPSHOTS=1"));
    assert_eq!(expected, actual, "snapshot mismatch for {name}");
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn contract_goldens_deserialize_and_render_in_check_view() {
    for (file, expected_code, snapshot_file) in [
        (
            "balance_mismatch.json",
            "E_BALANCE_MISMATCH",
            "check_balance_mismatch.snap",
        ),
        (
            "paid_session_gap.json",
            "E_PAID_SESSION_GAP",
            "check_paid_session_gap.snap",
        ),
        (
            "session_without_notes.json",
            "E_SESSION_WITHOUT_NOTES",
            "check_session_without_notes.snap",
        ),
    ] {
        let raw_json = fs::read_to_string(golden_path(file)).expect("read golden file");
        let report: CheckReport = serde_json::from_str(&raw_json).expect("deserialize CheckReport");
        assert_eq!(report.schema_version, "1");
        assert!(!report.ok);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].code, expected_code);

        // Even though `check` exits 1 when `--fail-on` trips, the TUI must
        // parse stdout before looking at the exit status and treat it as a
        // valid CheckReport.
        let fake = FakeRunner::from_json(1, &raw_json);
        let mut app = App::new(fake);
        app.load_check();
        assert!(app.alert.is_none());
        assert!(app.blocking_alert.is_none());

        let rendered = render_to_string(&app);
        assert!(
            rendered.contains(expected_code),
            "expected {expected_code} in:\n{rendered}"
        );
        assert_snapshot(snapshot_file, &rendered);
    }
}

#[test]
fn find_context_and_doctor_views_snapshot() {
    let find_json = r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "query": "Ada Example",
        "matches": [
            {
                "id": "p-01M3TC5H00MPJG000000000000",
                "path": "people/p-01M3TC5H00MPJG000000000000/profile.md",
                "line": 4,
                "excerpt": "name: Ada Example"
            }
        ],
        "findings": [],
        "skipped_encrypted": 0,
        "refused_envelopes": 0,
        "scope": ["coaching@0.1"]
    }"#;
    let context_json = r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "person": {
            "id": "p-01M3TC5H00MPJG000000000000",
            "name": "Ada Example",
            "no_ai": false,
            "profile": "Fake executive coaching client at Acme Corp."
        },
        "notes": [
            {
                "id": "n-01M3TC5H00MPJG002NAM000005",
                "date": "2026-10-01",
                "body": "Kickoff session notes for Ada Example."
            }
        ],
        "interactions": [
            {
                "id": "i-01M3TC5H00MPJG0048H0000008",
                "date": "2026-09-25",
                "title": "Intro call",
                "body": "Fake intro call transcript."
            }
        ],
        "touchpoints": [
            {
                "date": "2026-10-05",
                "kind": "call"
            }
        ],
        "coaching": {
            "sessions_remaining": 5,
            "icf_hours": 1.0,
            "recent_sessions": [
                {
                    "date": "2026-10-01",
                    "duration_minutes": 60,
                    "tag": "paid"
                }
            ]
        },
        "packs": {},
        "aliases": ["hmac:0123456789abcdef0123456789abcdef"],
        "skipped_encrypted": 0,
        "refused_envelopes": 0,
        "scope": ["coaching@0.1"]
    }"#;
    let doctor_json = r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "checks": [
            {
                "id": "vault-discovery",
                "status": "ok",
                "message": "vault resolved to /fake/demo-vault"
            },
            {
                "id": "spec",
                "status": "ok",
                "message": "vault spec 0.1 supported"
            },
            {
                "id": "check",
                "status": "ok",
                "message": "check is clean"
            },
            {
                "id": "cli-staleness",
                "status": "ok",
                "message": "staleness check disabled (CONFIDANT_OFFLINE=1)"
            }
        ]
    }"#;

    let fake = FakeRunner::new()
        .with_response("find", 0, find_json)
        .with_response("context", 0, context_json)
        .with_response("doctor", 0, doctor_json);

    let mut app = App::new(fake);

    // Press `/` to enter query in Find, type "Ada Example", press Enter.
    app.handle_key(key(KeyCode::Char('/')));
    assert_eq!(app.active_view, ActiveView::Find);
    assert_eq!(app.input_mode, InputMode::EditingFind);
    for ch in "Ada Example".chars() {
        app.handle_key(key(KeyCode::Char(ch)));
    }
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.input_mode, InputMode::Normal);
    let find_rendered = render_to_string(&app);
    assert!(find_rendered.contains("Ada Example"));
    assert_snapshot("find_view.snap", &find_rendered);

    // Press Enter on the `p-01M3TC5H00MPJG000000000000` hit to open Context.
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.active_view, ActiveView::Context);
    let context_rendered = render_to_string(&app);
    assert!(context_rendered.contains("Ada Example"));
    assert!(context_rendered.contains("sessions_remaining: 5"));
    assert_snapshot("context_view.snap", &context_rendered);

    // Switch to Doctor view with `4`.
    app.handle_key(key(KeyCode::Char('4')));
    assert_eq!(app.active_view, ActiveView::Doctor);
    let doctor_rendered = render_to_string(&app);
    assert!(doctor_rendered.contains("vault-discovery"));
    assert!(doctor_rendered.contains("cli-staleness"));
    assert_snapshot("doctor_view.snap", &doctor_rendered);
}

#[test]
fn error_alert_and_usage_error_alert_snapshots() {
    let err_json = r#"{
        "ok": false,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "error": {
            "code": "E_LEDGER_UNREADABLE",
            "message": "1 items",
            "fix": "Fix permissions or replace the unreadable ledger file, then run `confidant check` to locate it"
        }
    }"#;
    let fake_err = FakeRunner::from_json(1, err_json);
    let mut app_err = App::new(fake_err);
    app_err.load_check();
    assert!(app_err.alert.is_some());
    let rendered_err = render_to_string(&app_err);
    assert!(rendered_err.contains("E_LEDGER_UNREADABLE"));
    assert!(rendered_err.contains("1 items"));
    assert!(rendered_err.contains("Fix permissions"));
    assert_snapshot("alert_error.snap", &rendered_err);

    // Second fake returns exit 2 -> alert says "usage error".
    let usage_json = r#"{
        "ok": false,
        "schema_version": "1",
        "vault": null,
        "error": {
            "code": "usage_error",
            "message": "find requires a non-empty query"
        }
    }"#;
    let fake_usage = FakeRunner::from_json(2, usage_json);
    let mut app_usage = App::new(fake_usage);
    app_usage.load_check();
    assert!(app_usage.alert.is_some());
    let rendered_usage = render_to_string(&app_usage);
    assert!(
        rendered_usage.to_ascii_lowercase().contains("usage error"),
        "expected 'usage error' in:\n{rendered_usage}"
    );
    assert_snapshot("alert_usage.snap", &rendered_usage);
}

#[test]
fn non_json_stdout_shows_alert_and_does_not_panic() {
    let fake = FakeRunner::single(1, b"not valid json {{{".to_vec());
    let mut app = App::new(fake);
    app.load_check();
    assert!(app.alert.is_some());
    let rendered = render_to_string(&app);
    assert!(rendered.contains("invalid_json"));
    assert!(rendered.contains("not valid JSON"));
}

#[test]
fn version_gate_blocks_on_unsupported_schema_version() {
    let v2_json = r#"{
        "ok": true,
        "schema_version": "2",
        "vault": "/fake/demo-vault",
        "spec": "0.1",
        "summary": { "errors": 0, "warnings": 0, "records": 1, "ledger_entries": 1 },
        "findings": []
    }"#;
    let fake = FakeRunner::from_json(0, v2_json);
    let mut app = App::new(fake);
    app.load_check();
    assert!(app.blocking_alert.is_some());
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("TUI built for agent contract v1; CLI reports v2"),
        "expected blocking version gate message in:\n{rendered}"
    );
    // Nothing else (such as the tab bar or Check Summary) should be rendered.
    assert!(!rendered.contains("Check Summary"));
    assert_snapshot("alert_version_gate.snap", &rendered);
}

#[test]
fn live_shape_against_demo_vault_check_find_context_doctor() {
    let runner =
        ProcessRunner::new(confidant_bin(), Some(demo_vault())).with_env("CONFIDANT_OFFLINE", "1");

    // 1. check: demo vault is clean ("0 findings").
    let raw_check = runner.run(&["check"]).expect("run check");
    match parse_raw_output::<CheckReport>(&raw_check) {
        ContractOutcome::Ok { ok, data, .. } => {
            assert!(ok);
            assert!(data.findings.is_empty());
        }
        other => panic!("unexpected check outcome: {other:?}"),
    }

    // 2. find "Ada Example": deserializes and finds Ada.
    let raw_find = runner
        .run(&["find", "--", "Ada Example"])
        .expect("run find Ada Example");
    match parse_raw_output::<FindResult>(&raw_find) {
        ContractOutcome::Ok { ok, data, .. } => {
            assert!(ok);
            assert!(data
                .matches
                .iter()
                .any(|m| m.excerpt.contains("Ada Example")));
        }
        other => panic!("unexpected find outcome: {other:?}"),
    }

    // 3. context p-01M3TC5H00MPJG000000000000: deserializes Ada's bundle.
    let raw_ctx = runner
        .run(&["context", "--", "p-01M3TC5H00MPJG000000000000"])
        .expect("run context");
    match parse_raw_output::<Context>(&raw_ctx) {
        ContractOutcome::Ok { ok, data, .. } => {
            assert!(ok);
            assert_eq!(data.person.id, "p-01M3TC5H00MPJG000000000000");
            assert_eq!(data.person.name.as_deref(), Some("Ada Example"));
            assert!(data.coaching.is_some());
        }
        other => panic!("unexpected context outcome: {other:?}"),
    }

    // 4. doctor (with CONFIDANT_OFFLINE=1): deserializes all checks.
    let raw_doc = runner.run(&["doctor"]).expect("run doctor");
    match parse_raw_output::<DoctorReport>(&raw_doc) {
        ContractOutcome::Ok { data, .. } => {
            assert!(!data.checks.is_empty());
            assert!(data.checks.iter().any(|c| c.id == "cli-staleness"));
        }
        other => panic!("unexpected doctor outcome: {other:?}"),
    }

    // Also verify end-to-end through App against the demo vault:
    // Check view on demo vault renders "0 findings".
    let mut app = App::new(runner);
    app.load_check();
    let check_screen = render_to_string(&app);
    assert!(
        check_screen.contains("0 findings"),
        "expected '0 findings' on demo vault check screen:\n{check_screen}"
    );
}

#[test]
fn live_find_omits_no_ai_people_in_tui() {
    // Mirrors `find_omits_no_ai_people` in `crates/confidant-cli/tests/cli.rs`:
    // "Cam Sample" only appears in a `no-ai: true` record in `examples/demo-vault`.
    let runner =
        ProcessRunner::new(confidant_bin(), Some(demo_vault())).with_env("CONFIDANT_OFFLINE", "1");
    let mut app = App::new(runner);
    app.active_view = ActiveView::Find;
    app.run_find("Cam Sample");

    let res = app.find.result.as_ref().expect("find result populated");
    assert!(
        res.matches.is_empty(),
        "expected no matches for no-ai person, got {:?}",
        res.matches
    );
    let rendered = render_to_string(&app);
    assert!(rendered.contains("0 matches"));
}
