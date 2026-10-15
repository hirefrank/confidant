//! Contract, snapshot, and live-shape integration tests for `confidant-tui`.

use std::fs;
use std::path::{Path, PathBuf};
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

// ---------------------------------------------------------------------------
// Proposal review (Phase 2, #211)
// ---------------------------------------------------------------------------

use confidant_tui::apply::{ApplyFlow, StepApplyOutcome, StepStatus};
use confidant_tui::proposals::read_progress;

fn proposals_temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("remove old temp dir");
    }
    fs::create_dir_all(dir.join(".confidant").join("proposals")).expect("create proposals dir");
    dir
}

/// Write a minimal manifest + lines file. Returns (manifest_path, request_id).
fn write_test_manifest(dir: &Path, stem: &str, records_json: &str) -> (PathBuf, String) {
    let proposals = dir.join(".confidant").join("proposals");
    let lines_file = proposals.join(format!("{stem}.cfd"));
    fs::write(
        &lines_file,
        "2026-09-01 open d-01M3TC5H00MPJG00248G000004 proposal src:test/1\n",
    )
    .expect("write lines file");
    let request_id = "01M3TC5H00MPJG005VQC00000B".to_owned();
    let manifest_path = proposals.join(format!("{stem}.json"));
    let manifest = format!(
        r#"{{"skill": "portal-sync", "vault": "", "request_id": "{request_id}", "lines_file": {}, "records": [{records_json}], "records_blocked": true}}"#,
        serde_json::to_string(&lines_file.to_string_lossy()).unwrap(),
    );
    fs::write(&manifest_path, manifest).expect("write manifest");
    (manifest_path, request_id)
}

fn dry_run_import_json() -> &'static str {
    r#"{
        "ok": true, "schema_version": "1", "vault": "/fake/vault",
        "command": "import", "dry_run": true, "commit": null,
        "changes": [
            {"path": "ledger/2026/09.cfd", "action": "append",
             "content": "2026-09-01 open d-01M3TC5H00MPJG00248G000004 proposal src:test/1\n"}
        ]
    }"#
}

fn applied_import_json(commit: &str) -> String {
    format!(
        r#"{{"ok": true, "schema_version": "1", "vault": "/fake/vault", "command": "import", "commit": "{commit}", "files": ["ledger/2026/09.cfd"]}}"#
    )
}

fn check_blocked_json() -> &'static str {
    r#"{
        "schema_version": "1", "ok": false, "vault": "/fake/vault", "spec": "0.1",
        "summary": {"errors": 1, "warnings": 0, "records": 0, "ledger_entries": 0},
        "findings": [
            {"code": "E_NEGATIVE_BALANCE", "severity": "error",
             "id": "p-01M3TC5H00MPJG000000000000",
             "message": "sessions_remaining is -1",
             "fix": "Add an open/renewal or remove extra session lines"}
        ]
    }"#
}

fn open_proposals_app(dir: &Path, runner: FakeRunner) -> App<FakeRunner> {
    let mut app = App::new(runner);
    app.set_vault_root(dir.to_path_buf());
    app.handle_key(key(KeyCode::Char('5')));
    assert_eq!(app.active_view, ActiveView::Proposals);
    app
}

#[test]
fn proposals_dry_run_renders_path_action_and_content() {
    let dir = proposals_temp_dir("tui-test-proposals-dryrun");
    write_test_manifest(&dir, "portal-20261015T000000Z", "");

    let fake = FakeRunner::new().with_response("import", 0, dry_run_import_json());
    let mut app = open_proposals_app(&dir, fake);
    assert_eq!(app.proposals.entries.len(), 1);
    assert!(app.proposals.entries[0].detail.contains("1 ledger lines"));

    // Enter opens the manifest, `a` starts the apply (dry-run first).
    app.handle_key(key(KeyCode::Enter));
    assert!(app.proposals.opened.is_some());
    app.handle_key(key(KeyCode::Char('a')));

    let rendered = render_to_string(&app);
    assert!(rendered.contains("ledger/2026/09.cfd"), "{rendered}");
    assert!(rendered.contains("append"), "{rendered}");
    assert!(rendered.contains("2026-09-01 open"), "{rendered}");
    assert_snapshot("proposals_dry_run.snap", &rendered);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn proposals_cancel_confirm_writes_nothing() {
    let dir = proposals_temp_dir("tui-test-proposals-cancel");
    write_test_manifest(&dir, "portal-20261015T000000Z", "");

    let fake = FakeRunner::new().with_response("import", 0, dry_run_import_json());
    let mut app = open_proposals_app(&dir, fake);
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char('a')));
    // `y` opens the confirm modal; Esc cancels back to the diff.
    app.handle_key(key(KeyCode::Char('y')));
    app.handle_key(key(KeyCode::Esc));

    let calls = app.runner.recorded_calls();
    assert!(!calls.is_empty(), "expected the dry-run call");
    assert!(
        calls.iter().all(|c| c.iter().any(|a| a == "--dry-run")),
        "no call without --dry-run after cancel: {calls:?}"
    );
    // The step is still pending and nothing was marked done.
    let flow = app.proposals.opened.as_ref().expect("still open");
    assert!(matches!(flow.steps[0].status, StepStatus::Pending));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn proposals_apply_uses_manifest_ids_and_resumes_after_crash() {
    let dir = proposals_temp_dir("tui-test-proposals-resume");
    let note_rid = "01M3TC5H00MPJG0066D000000C".to_owned();
    let note_json = format!(
        r#"{{"path": "people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md",
            "content": "---\nid: n-01\n---\nbody\n",
            "note_id": "n-01M3TC5H00MPJG002NAM000005",
            "person": "p-01M3TC5H00MPJG000000000000",
            "date": "2026-09-01",
            "body_file": "/fake/body.md",
            "request_id": "{note_rid}"}}"#
    );
    let (manifest_path, manifest_rid) = write_test_manifest(&dir, "m", &note_json);

    let fake = FakeRunner::new();
    fake.push_response(0, dry_run_import_json());
    fake.push_response(0, applied_import_json("commit-ledger-1"));

    // Apply step 1 (ledger), then "crash".
    let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
    assert_eq!(flow.steps.len(), 2);
    assert_eq!(flow.steps[0].plan.key, "ledger");
    assert_eq!(flow.steps[1].plan.key, format!("note:{note_rid}"));
    flow.dry_run_step(&fake, 0).expect("dry-run ledger");
    match flow.apply_step(&fake, 0).expect("apply ledger") {
        StepApplyOutcome::Done { more } => assert!(more),
        other => panic!("expected Done, got {other:?}"),
    }
    drop(flow);

    // Restart: step 1 is done, step 2 is pending, and the same ids are used.
    let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("reopen flow");
    assert!(matches!(flow.steps[0].status, StepStatus::Done { .. }));
    assert_eq!(flow.first_pending(), Some(1));

    // Every apply argv carries exactly the manifest's id.
    let calls = fake.recorded_calls();
    let real_calls: Vec<_> = calls
        .iter()
        .filter(|c| !c.iter().any(|a| a == "--dry-run"))
        .collect();
    assert_eq!(real_calls.len(), 1, "{calls:?}");
    let rid_arg = real_calls[0]
        .iter()
        .position(|a| a == "--request-id")
        .map(|i| &real_calls[0][i + 1]);
    assert_eq!(rid_arg, Some(&manifest_rid));

    // The note step's argv carries the note's own request_id.
    fake.push_response(0, dry_run_import_json());
    flow.dry_run_step(&fake, 1).expect("dry-run note");
    let calls = fake.recorded_calls();
    let note_dry = calls.last().expect("note dry-run call");
    let rid_arg = note_dry
        .iter()
        .position(|a| a == "--request-id")
        .map(|i| &note_dry[i + 1]);
    assert_eq!(rid_arg, Some(&note_rid));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn apply_rs_has_no_id_generation() {
    let src = fs::read_to_string(repo_root().join("crates/confidant-tui/src/apply.rs"))
        .expect("read apply.rs");
    let lower = src.to_lowercase();
    assert!(
        !lower.contains("ulid"),
        "apply.rs must not generate or mention ULIDs"
    );
    assert!(
        !lower.contains("uuid"),
        "apply.rs must not generate or mention UUIDs"
    );
    let cargo = fs::read_to_string(repo_root().join("crates/confidant-tui/Cargo.toml"))
        .expect("read Cargo.toml");
    let cargo_lower = cargo.to_lowercase();
    assert!(!cargo_lower.contains("ulid"), "no ulid dependency");
    assert!(!cargo_lower.contains("uuid"), "no uuid dependency");
}

#[test]
fn proposals_check_blocked_renders_report_and_marks_nothing_done() {
    let dir = proposals_temp_dir("tui-test-proposals-blocked");
    let (manifest_path, _) = write_test_manifest(&dir, "portal-20261015T000000Z", "");

    let fake = FakeRunner::new();
    fake.push_response(0, dry_run_import_json());
    fake.push_response(1, check_blocked_json());

    let mut app = open_proposals_app(&dir, fake);
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char('a')));
    app.handle_key(key(KeyCode::Char('y'))); // open confirm modal
    app.handle_key(key(KeyCode::Char('y'))); // confirm -> apply -> blocked

    // The CheckReport renders in the Check view.
    assert_eq!(app.active_view, ActiveView::Check);
    let report = app.check.report.as_ref().expect("check report shown");
    assert!(!report.ok);
    let rendered = render_to_string(&app);
    assert!(rendered.contains("E_NEGATIVE_BALANCE"), "{rendered}");

    // The step is not marked done.
    let progress = read_progress(&manifest_path);
    assert!(!progress.is_done("ledger"));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn proposals_list_shows_counts_from_lightfield_proposer() {
    // No git repo here: the proposer skips the gitignore check then.
    let dir = proposals_temp_dir("tui-test-proposals-proposer");
    for entry in fs::read_dir(demo_vault()).expect("read demo vault") {
        let entry = entry.unwrap();
        let dest = dir.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&dest).unwrap();
            for f in walk_files(&entry.path()) {
                let rel = f.strip_prefix(entry.path()).unwrap();
                let d = dest.join(rel);
                fs::create_dir_all(d.parent().unwrap()).unwrap();
                fs::copy(&f, &d).unwrap();
            }
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
    let script =
        repo_root().join("crates/confidant-cli/skills/lightfield-import/bin/lightfield-import.py");
    let export =
        repo_root().join("crates/confidant-cli/skills/lightfield-import/testdata/export.json");
    let out = std::process::Command::new("python3")
        .args([
            script.to_string_lossy().as_ref(),
            "--vault",
            dir.to_string_lossy().as_ref(),
            "--export",
            export.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run lightfield proposer");
    assert!(out.status.success(), "proposer failed: {out:?}");

    let proposals_dir = dir.join(".confidant").join("proposals");
    let manifest_path = fs::read_dir(&proposals_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("manifest written");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let records = manifest["records"].as_array().unwrap();
    let expected_notes = records
        .iter()
        .filter(|r| r.get("note_id").is_some())
        .count();
    let expected_records = records.len() - expected_notes;
    let lines_file = manifest["lines_file"].as_str().unwrap();
    let expected_lines = fs::read_to_string(lines_file).unwrap().lines().count();

    let mut app = App::new(FakeRunner::new());
    app.set_vault_root(dir.clone());
    app.handle_key(key(KeyCode::Char('5')));
    assert_eq!(app.proposals.entries.len(), 1);
    let entry = &app.proposals.entries[0];
    assert_eq!(entry.skill, "lightfield-import");
    assert!(
        entry.detail.contains(&format!("{expected_notes} notes")),
        "detail: {}",
        entry.detail
    );
    assert!(
        entry
            .detail
            .contains(&format!("{expected_records} records")),
        "detail: {}",
        entry.detail
    );
    assert!(
        entry
            .detail
            .contains(&format!("{expected_lines} ledger lines")),
        "detail: {}",
        entry.detail
    );
    fs::remove_dir_all(&dir).unwrap();
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn proposals_live_apply_against_temp_git_vault() {
    let dir = proposals_temp_dir("tui-test-proposals-live");
    // Fresh git copy of the demo vault (the proposer needs the gitignore
    // check to pass, and writes need commits).
    for entry in fs::read_dir(demo_vault()).expect("read demo vault") {
        let entry = entry.unwrap();
        let dest = dir.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&dest).unwrap();
            for f in walk_files(&entry.path()) {
                let rel = f.strip_prefix(entry.path()).unwrap();
                let d = dest.join(rel);
                fs::create_dir_all(d.parent().unwrap()).unwrap();
                fs::copy(&f, &d).unwrap();
            }
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("git");
        assert!(st.status.success(), "git {args:?} failed: {st:?}");
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "test"]);
    fs::write(dir.join(".gitignore"), ".confidant/\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "init"]);

    // The committed export fixture uses a `paid` session for a brand-new
    // person, which trips E_NEGATIVE_BALANCE on import (correct domain
    // behavior, exercised by the CheckBlocked test). The live happy-path
    // test uses a `comp` session so the full apply succeeds.
    let export_src =
        repo_root().join("crates/confidant-cli/skills/lightfield-import/testdata/export.json");
    let export: serde_json::Value = serde_json::from_slice(&fs::read(export_src).unwrap()).unwrap();
    let mut export = export;
    for t in export["transcripts"].as_array_mut().unwrap() {
        t["billing"] = serde_json::Value::String("comp".to_owned());
    }
    let export_path = dir.join("export-comp.json");
    fs::write(&export_path, serde_json::to_vec(&export).unwrap()).unwrap();

    let script =
        repo_root().join("crates/confidant-cli/skills/lightfield-import/bin/lightfield-import.py");
    let out = std::process::Command::new("python3")
        .args([
            script.to_string_lossy().as_ref(),
            "--vault",
            dir.to_string_lossy().as_ref(),
            "--export",
            export_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run lightfield proposer");
    assert!(out.status.success(), "proposer failed: {out:?}");
    fs::remove_file(&export_path).unwrap();

    let proposals_dir = dir.join(".confidant").join("proposals");
    let manifest_path = fs::read_dir(&proposals_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("manifest written");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

    // Pre-M2 skill workflow: hand-create the record files from the manifest
    // (the TUI never writes into the vault tree itself).
    for r in manifest["records"].as_array().unwrap() {
        if r.get("note_id").is_some() {
            continue;
        }
        let dest = dir.join(r["path"].as_str().unwrap());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, r["content"].as_str().unwrap()).unwrap();
    }
    git(&["add", "-A"]);
    git(&["commit", "-qm", "test: hand-create pre-M2 records"]);

    // Drive the real apply engine with the real CLI.
    let runner = ProcessRunner::new(confidant_bin(), Some(dir.clone()));
    let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
    let mut applied = 0;
    while let Some(step) = flow.first_pending() {
        flow.dry_run_step(&runner, step)
            .expect("dry-run against live vault");
        match flow
            .apply_step(&runner, step)
            .expect("apply against live vault")
        {
            StepApplyOutcome::Done { .. } => applied += 1,
            StepApplyOutcome::CheckBlocked { report } => {
                panic!("unexpected check block: {:?}", report.findings)
            }
            StepApplyOutcome::Failed => panic!("step failed"),
        }
    }
    // Ledger + note applied; records refused with the pre-M2 message.
    assert_eq!(applied, 2, "expected ledger + note to apply");
    assert!(flow
        .steps
        .iter()
        .any(|s| matches!(&s.status, StepStatus::Blocked { .. })));

    let report = flow.final_check(&runner).expect("final check runs");
    assert!(report.is_none(), "final check should be clean");

    // Commits exist in git.
    let log = std::process::Command::new("git")
        .args(["log", "--oneline"])
        .current_dir(&dir)
        .output()
        .expect("git log");
    let log = String::from_utf8_lossy(&log.stdout);
    assert!(log.lines().count() >= 4, "expected apply commits:\n{log}");
    fs::remove_dir_all(&dir).unwrap();
}
