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
        let bin_name = "confidant";
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

/// Absolute path of the `python3` the test process would run, resolved once
/// through the interpreter's own `sys.executable`. The live search test
/// hands its child a `PATH` holding no host entries (#514), so `python3`
/// has to be named by path rather than looked up through it.
fn python3() -> String {
    static PYTHON: OnceLock<String> = OnceLock::new();
    PYTHON
        .get_or_init(|| {
            let out = Command::new("python3")
                .args(["-c", "import sys; print(sys.executable)"])
                .output()
                .expect("python3 must be runnable for the live search test");
            assert!(out.status.success(), "python3 -c failed: {out:?}");
            String::from_utf8(out.stdout)
                .expect("python3 prints UTF-8")
                .trim()
                .to_owned()
        })
        .clone()
}

fn render_to_string<R: Runner>(app: &App<R>) -> String {
    render_to_string_at(app, WIDTH, HEIGHT)
}

/// Render at an explicit size: a wider buffer keeps a long context identity
/// line (id + name + no-ai badge) on one line for a substring assertion.
fn render_to_string_at<R: Runner>(app: &App<R>, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("TestBackend terminal");
    terminal
        .draw(|frame| app.render(frame))
        .expect("draw frame");
    let buffer = terminal.backend().buffer();
    let mut lines = Vec::with_capacity(height as usize);
    for y in 0..height {
        let mut row = String::new();
        for x in 0..width {
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
            "E_COACHING_BALANCE_MISMATCH",
            "check_balance_mismatch.snap",
        ),
        (
            "paid_session_gap.json",
            "E_COACHING_PAID_SESSION_GAP",
            "check_paid_session_gap.snap",
        ),
        (
            "session_without_notes.json",
            "E_COACHING_SESSION_WITHOUT_NOTES",
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
        // The Check workspace is `3`; phase 1 defaults to People.
        app.handle_key(key(KeyCode::Char('3')));
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
fn search_context_and_doctor_views_snapshot() {
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

    // #514: pin the vault root to an empty directory so `qmd_available()`
    // is deterministically false — no `.confidant/qmd-corpus` under the
    // root — whatever the host has on PATH or in `CONFIDANT_VAULT`.
    // Otherwise `/` would default the Search tab to qmd-ranked mode, the
    // fake `find` response below would never be used, and nothing would
    // render. The dir must outlive the app.
    let vault_root = tempfile::tempdir().expect("temp vault dir");
    let mut app = App::new(fake);
    app.set_vault_root(vault_root.path().to_path_buf());

    // Unified Search tab (#387): switch with `f` (phase 3 moved `s` to
    // session capture), toggle exact literal scan with `e`, then press `/`,
    // type, Enter.
    app.handle_key(key(KeyCode::Char('f')));
    assert_eq!(app.active_view, ActiveView::Search);
    app.handle_key(key(KeyCode::Char('e')));
    assert!(app.search.exact);
    app.handle_key(key(KeyCode::Char('/')));
    assert_eq!(app.active_view, ActiveView::Search);
    assert_eq!(app.input_mode, InputMode::EditingSearch);
    for ch in "Ada Example".chars() {
        app.handle_key(key(KeyCode::Char(ch)));
    }
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.input_mode, InputMode::Normal);
    let search_rendered = render_to_string(&app);
    assert!(search_rendered.contains("Ada Example"));
    assert!(search_rendered.contains("[exact]"));
    assert!(search_rendered.contains("find-exact"));
    assert_snapshot("search_exact.snap", &search_rendered);

    // Press Enter on the `p-01M3TC5H00MPJG000000000000` hit to open Context.
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.active_view, ActiveView::Context);
    let context_rendered = render_to_string(&app);
    assert!(context_rendered.contains("Ada Example"));
    assert!(context_rendered.contains("sessions_remaining 5"));
    assert_snapshot("context_view.snap", &context_rendered);

    // Switch to Doctor view with `d` (a pill, not a workspace).
    app.handle_key(key(KeyCode::Char('d')));
    assert_eq!(app.active_view, ActiveView::Doctor);
    let doctor_rendered = render_to_string(&app);
    assert!(doctor_rendered.contains("vault-discovery"));
    assert!(doctor_rendered.contains("cli-staleness"));
    assert_snapshot("doctor_view.snap", &doctor_rendered);
}

#[test]
fn search_exact_toggle_reruns_query() {
    let find_json = r#"{
        "ok": true, "schema_version": "1", "vault": "/fake/v",
        "query": "ada", "matches": [], "findings": [],
        "skipped_encrypted": 0, "refused_envelopes": 0, "scope": []
    }"#;
    let fake = FakeRunner::new().with_response("find", 0, find_json);
    let mut app = App::new(fake);
    app.active_view = ActiveView::Search;
    // No query yet: toggle flips the mode without running anything.
    assert!(!app.search.exact);
    app.handle_key(key(KeyCode::Char('e')));
    assert!(app.search.exact);
    assert!(app.runner.recorded_calls().is_empty());
    // Back to qmd mode (no vault in this test env, so nothing can run),
    // then set a query and toggle to exact: the toggle must re-run the
    // query through `confidant find`.
    app.handle_key(key(KeyCode::Char('e')));
    assert!(!app.search.exact);
    assert!(app.runner.recorded_calls().is_empty());
    app.search.query = "ada".to_owned();
    app.handle_key(key(KeyCode::Char('e')));
    assert!(app.search.exact);
    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|c| c == &["find".to_string(), "--".to_string(), "ada".to_string()]),
        "expected a `find` rerun after toggling to exact, got: {calls:?}"
    );
    // The `via` label reflects the engine that answered.
    let rendered = render_to_string(&app);
    assert!(rendered.contains("find-exact"), "{rendered}");
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

/// #591: an exit-2 usage error that names an unknown subcommand is a
/// `confidant` older than this TUI. The TUI says so in one actionable line
/// (naming the resolved binary and the subcommand) instead of dumping the
/// raw clap help, which stays reachable with `x`.
#[test]
fn unknown_subcommand_usage_error_names_cli_skew_not_raw_help() {
    let usage_json = r#"{
        "ok": false,
        "schema_version": "1",
        "vault": null,
        "error": {
            "code": "usage_error",
            "message": "error: unrecognized subcommand 'list'\n\nUsage: confidant record [OPTIONS] <COMMAND>\n\nFor more information, try '--help'."
        }
    }"#;
    let fake = FakeRunner::from_json(2, usage_json).with_bin("/tmp/fake-confidant");
    let mut app = App::new(fake);
    app.load_roster();

    let alert = app.alert.as_ref().expect("skew alert shown");
    assert_eq!(alert.code.as_deref(), Some("old_cli"));
    assert!(
        alert.message.contains("/tmp/fake-confidant"),
        "resolved path named in: {}",
        alert.message
    );
    assert!(
        alert.message.contains("list"),
        "subcommand named in: {}",
        alert.message
    );

    let rendered = render_to_string(&app);
    assert!(rendered.contains("CLI Version Skew"), "{rendered}");
    assert!(rendered.contains("/tmp/fake-confidant"), "{rendered}");
    assert!(
        !rendered.contains("For more information"),
        "raw clap help must not be shown first:\n{rendered}"
    );

    // `x` opens the raw CLI text in the dismissable info modal.
    app.handle_key(key(KeyCode::Char('x')));
    assert!(app.info_modal.is_some(), "raw text reachable with x");
    let raw = render_to_string(&app);
    assert!(raw.contains("unrecognized subcommand 'list'"), "{raw}");
    assert!(raw.contains("For more information"), "{raw}");
    // Any key closes it, and the alert is still up afterwards.
    app.handle_key(key(KeyCode::Char('z')));
    assert!(app.info_modal.is_none());
    assert!(app.alert.is_some());
}

/// #591: only the unknown-subcommand shape is a skew; an ordinary CLI error
/// and a usage error that names no subcommand keep their current rendering,
/// and neither carries a hidden raw payload.
#[test]
fn ordinary_errors_keep_current_rendering_and_no_raw() {
    let err_json = r#"{
        "ok": false, "schema_version": "1", "vault": "/fake/demo-vault",
        "error": {"code": "E_LEDGER_UNREADABLE", "message": "1 items",
                  "fix": "Fix permissions"}
    }"#;
    let fake = FakeRunner::from_json(1, err_json).with_bin("/tmp/fake-confidant");
    let mut app = App::new(fake);
    app.load_check();
    let alert = app.alert.as_ref().expect("alert shown");
    assert_eq!(alert.title, "CLI Error (exit 1)");
    assert_eq!(alert.code.as_deref(), Some("E_LEDGER_UNREADABLE"));
    assert!(alert.raw.is_none(), "no raw payload on an ordinary error");

    // A usage error without an unknown subcommand keeps the usage rendering.
    let usage_json = r#"{
        "ok": false, "schema_version": "1", "vault": null,
        "error": {"code": "usage_error", "message": "find requires a non-empty query"}
    }"#;
    let fake = FakeRunner::from_json(2, usage_json);
    let mut app = App::new(fake);
    app.load_check();
    let alert = app.alert.as_ref().expect("usage alert shown");
    assert_eq!(alert.title, "Usage Error (exit 2)");
    assert!(alert.raw.is_none());
    // `x` is inert when the alert has no raw payload.
    app.handle_key(key(KeyCode::Char('x')));
    assert!(app.info_modal.is_none());
}

/// #591: the resolved CLI path is a durable fact in the Scope modal.
#[test]
fn scope_modal_shows_resolved_cli_path() {
    let fake = people_runner().with_bin("/tmp/fake-confidant");
    let mut app = App::new(fake);
    app.load_check();
    app.load_roster();
    app.handle_key(key(KeyCode::Char('p')));
    let scope = render_to_string(&app);
    assert!(scope.contains("cli: /tmp/fake-confidant"), "{scope}");
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
    // Phase 1 defaults to People; switch to the Check workspace.
    app.handle_key(key(KeyCode::Char('3')));
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
    app.active_view = ActiveView::Search;
    app.search.exact = true;
    app.run_search("Cam Sample");

    let res = app.search.result.as_ref().expect("search result populated");
    assert!(
        res.kept.is_empty(),
        "expected no matches for no-ai person, got {:?}",
        res.kept
    );
    let rendered = render_to_string(&app);
    assert!(rendered.contains("0 matches"));
}

// ---------------------------------------------------------------------------
// Proposal review (Phase 2, #211)
// ---------------------------------------------------------------------------

use confidant_tui::apply::{ApplyFlow, FlowPhase, StepApplyOutcome, StepStatus};
use confidant_tui::proposals::read_progress;

fn proposals_temp_dir(name: &str) -> PathBuf {
    proposals_temp_dir_at(&std::env::temp_dir(), name)
}

/// [`proposals_temp_dir`] under an explicit root.
///
/// #581: the dry-run snapshot prints the vault path in the header, which is
/// truncated from the left when it is too wide. `std::env::temp_dir()` is
/// `/var/folders/...` on macOS, so the snapshot test pins its vault to the
/// short `/tmp/...` form that renders identically on Linux and macOS, the same
/// way the conflict and inbox snapshots already use literal `/tmp/` paths.
/// Every other proposals test keeps the platform temp dir.
fn proposals_temp_dir_at(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
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
            {"code": "E_COACHING_NEGATIVE_BALANCE", "severity": "error",
             "id": "p-01M3TC5H00MPJG000000000000",
             "message": "sessions_remaining is -1",
             "fix": "Add an open/renewal or remove extra session lines"}
        ]
    }"#
}

fn open_proposals_app(dir: &Path, runner: FakeRunner) -> App<FakeRunner> {
    let mut app = App::new(runner);
    app.set_vault_root(dir.to_path_buf());
    app.handle_key(key(KeyCode::Char('o')));
    assert_eq!(app.active_view, ActiveView::Proposals);
    app
}

#[test]
fn proposals_dry_run_renders_path_action_and_content() {
    // #581: pinned root so the header's vault pill is identical on Linux and
    // macOS; see `proposals_temp_dir_at`.
    let dir = proposals_temp_dir_at(Path::new("/tmp"), "tui-test-proposals-dryrun");
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
    let body_file = dir.join(".confidant").join("proposals").join("body.md");
    fs::write(&body_file, "note body\n").expect("write body file");
    let note_json = format!(
        r#"{{"path": "people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md",
            "content": "---\nid: n-01\n---\nbody\n",
            "note_id": "n-01M3TC5H00MPJG002NAM000005",
            "person": "p-01M3TC5H00MPJG000000000000",
            "date": "2026-09-01",
            "body_file": {},
            "request_id": "{note_rid}"}}"#,
        serde_json::to_string(&body_file.to_string_lossy()).unwrap(),
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
    assert!(
        rendered.contains("E_COACHING_NEGATIVE_BALANCE"),
        "{rendered}"
    );

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
    app.handle_key(key(KeyCode::Char('o')));
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
    // person, which trips E_COACHING_NEGATIVE_BALANCE on import (correct domain
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

    // #611: the note landed at the manifest's own path/id, not a freshly
    // minted one, so the reviewed dry-run named the exact file written.
    let mut note_records = 0;
    for r in manifest["records"].as_array().unwrap() {
        if r.get("note_id").is_none() || r["person"].is_null() {
            continue;
        }
        note_records += 1;
        let path = dir.join(r["path"].as_str().unwrap());
        assert!(
            path.exists(),
            "note not applied at its reviewed path: {}",
            path.display()
        );
    }
    assert_eq!(note_records, 1, "expected one person-linked note record");

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

fn inbox_dry_run_json() -> &'static str {
    r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/tmp/fake-vault",
        "branch": "main",
        "dry_run": true,
        "empty": false,
        "merged": 2,
        "cleared": 2,
        "items": [
            {"name": "01JAAA", "kind": "ledger", "target": "ledger/*", "action": "merge"},
            {"name": "01JAAB", "kind": "record", "target": "people/p-01/record.md", "action": "skip"}
        ],
        "skipped": [
            {"name": "01JAAC", "kind": "ledger", "target": "ledger/*"}
        ],
        "warnings": ["item 01JAAB already present: idempotent no-op"]
    }"#
}

fn inbox_empty_json() -> &'static str {
    r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/tmp/fake-vault",
        "branch": "main",
        "dry_run": true,
        "empty": true,
        "merged": 0,
        "cleared": 0,
        "items": [],
        "skipped": [],
        "warnings": []
    }"#
}

#[test]
fn inbox_dry_run_renders_items_warnings_and_skipped() {
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    assert_eq!(app.active_view, ActiveView::Inbox);
    let rendered = render_to_string(&app);
    assert!(rendered.contains("01JAAA"), "item name shown:\n{rendered}");
    assert!(rendered.contains("ledger/*"), "target shown:\n{rendered}");
    assert!(rendered.contains("(merge)"), "action shown:\n{rendered}");
    assert!(
        rendered.contains("Deferred (1)"),
        "skipped section:\n{rendered}"
    );
    assert!(
        rendered.contains("already present"),
        "warnings shown:\n{rendered}"
    );
    assert_snapshot("inbox_dry_run.txt", &rendered);
}

#[test]
fn inbox_empty_renders_nothing_to_do() {
    let fake = FakeRunner::from_json(0, inbox_empty_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("nothing to do"),
        "empty state:\n{rendered}"
    );
}

#[test]
fn inbox_apply_confirm_runs_real_inbox_then_reloads() {
    let fake = FakeRunner::new();
    // Dry run, then the real apply, then the post-apply dry run (empty).
    fake.push_response(0, inbox_dry_run_json().as_bytes().to_vec());
    fake.push_response(
        0,
        r#"{"ok": true, "schema_version": "1", "dry_run": false, "empty": false,
            "merged": 2, "cleared": 2, "items": [], "skipped": [], "warnings": []}"#,
    );
    fake.push_response(0, inbox_empty_json().as_bytes().to_vec());

    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    // Begin apply: confirm modal opens.
    app.handle_key(key(KeyCode::Char('a')));
    assert!(app.inbox.confirming, "confirm modal open");
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("Confirm: apply inbox"),
        "modal shown:\n{rendered}"
    );
    // Confirm with y: runs the real inbox, then reloads the dry run.
    app.handle_key(key(KeyCode::Char('y')));
    assert!(!app.inbox.confirming, "modal closed");

    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|c| c == &vec!["inbox".to_owned(), "--dry-run".to_owned()]),
        "dry run issued: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == &vec!["inbox".to_owned()]),
        "real inbox issued without --dry-run: {calls:?}"
    );
    assert!(
        app.inbox
            .last_apply
            .as_deref()
            .unwrap_or("")
            .contains("merged 2"),
        "apply result recorded"
    );
}

#[test]
fn inbox_apply_cancel_does_not_run_real_inbox() {
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    app.handle_key(key(KeyCode::Char('a')));
    assert!(app.inbox.confirming);
    // Any key other than y cancels.
    app.handle_key(key(KeyCode::Char('n')));
    assert!(!app.inbox.confirming, "modal closed");
    let calls = app.runner.recorded_calls();
    assert!(
        !calls.iter().any(|c| c == &vec!["inbox".to_owned()]),
        "no real inbox run: {calls:?}"
    );
}

#[test]
fn inbox_apply_with_no_items_does_not_open_confirm() {
    let fake = FakeRunner::from_json(0, inbox_empty_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    app.handle_key(key(KeyCode::Char('a')));
    assert!(!app.inbox.confirming, "no confirm when nothing to apply");
}

#[test]
fn inbox_tab_falls_through_to_shared_navigation() {
    // Tab from Inbox advances within the Review workspace.
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    assert_eq!(app.active_view, ActiveView::Inbox);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.active_view, ActiveView::Conflicts);

    // Tab from Conflicts wraps around to Proposals.
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.active_view, ActiveView::Proposals);

    // `o` from Inbox switches to Proposals.
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    app.handle_key(key(KeyCode::Char('o')));
    assert_eq!(app.active_view, ActiveView::Proposals);

    // Shift-Tab from Inbox steps back to Proposals in the Review cycle.
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    app.handle_key(key(KeyCode::BackTab));
    assert_eq!(app.active_view, ActiveView::Proposals);

    // Esc with no alert quits.
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.should_quit, "Esc quits from the inbox tab");
}

#[test]
fn inbox_q_quits() {
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('i')));
    assert_eq!(app.active_view, ActiveView::Inbox);
    app.handle_key(key(KeyCode::Char('q')));
    assert!(app.should_quit, "q quits from the inbox tab");
}

/// Live dry run against a throwaway git vault with no inbox branch,
/// reusing the `crates/confidant-cli/tests/inbox.rs` fixture shape.
#[test]
fn inbox_live_dry_run_empty_vault() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let root = dir.path();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?} failed");
    };
    git(&["init", "-b", "main", "-q"]);
    fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"tui-inbox-test\"\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "init"]);

    let bin = confidant_bin();
    let home = tempfile::TempDir::new().expect("temp home");
    let runner = ProcessRunner::new(bin, Some(root.to_path_buf()))
        .with_env("CONFIDANT_KEYCHAIN", "off")
        .with_env("HOME", home.path().to_string_lossy().to_string());
    let mut app = App::new(runner);
    app.handle_key(key(KeyCode::Char('i')));
    let report = app.inbox.report.as_ref().expect("report loaded");
    assert!(report.empty, "no inbox branch -> empty");
    assert!(report.dry_run);
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("nothing to do"),
        "live empty state:\n{rendered}"
    );
}

// ---------------------------------------------------------------------------
// QMD search view (Phase 3a, #212)
// ---------------------------------------------------------------------------

use confidant_tui::contract::SearchResult;
use confidant_tui::search::filter_search_result;

/// Temp dir containing a fake installed skill at qmd-search/bin/qmd-query.py.
fn search_skills_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("remove old temp dir");
    }
    let bin = dir.join("qmd-search").join("bin");
    fs::create_dir_all(&bin).expect("create skill bin dir");
    fs::write(bin.join("qmd-query.py"), "#!/usr/bin/env python3\n").expect("write fake skill");
    dir
}

fn which_json(skills_dir: &Path) -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "skills_dir": skills_dir.to_string_lossy(),
    })
    .to_string()
}

fn qmd_hit_json() -> &'static str {
    r#"{
        "schema_version": "1", "ok": true, "vault": "/tmp/v",
        "mode": "bm25", "query": "ada",
        "matches": [
            {"id": "p-01M3TC5H00MPJG000000000000", "path": "people/p-01M3TC5H00MPJG000000000000.cfd",
             "line": 3, "excerpt": "Ada Example", "via": "qmd", "score": 0.9123}
        ],
        "dropped_uncleared": 0, "findings": []
    }"#
}

fn fallback_json() -> &'static str {
    r#"{
        "schema_version": "1", "ok": true, "vault": "/tmp/v",
        "mode": "find-fallback", "fallback": "qmd or index missing", "query": "ada",
        "matches": [
            {"id": "p-01M3TC5H00MPJG000000000000", "path": "people/p-01M3TC5H00MPJG000000000000.cfd",
             "line": 3, "excerpt": "Ada Example", "via": "find", "score": 0.0}
        ],
        "dropped_uncleared": 3, "findings": []
    }"#
}

fn unknown_via_json() -> &'static str {
    r#"{
        "schema_version": "1", "ok": true, "vault": "/tmp/v",
        "mode": "bm25", "query": "ada",
        "matches": [
            {"id": "p-01", "path": "people/p-01.cfd", "line": 3,
             "excerpt": "sneaky", "via": "bogus", "score": 0.5}
        ],
        "dropped_uncleared": 0, "findings": []
    }"#
}

/// Build an App whose runner answers `which --skills-dir` and `python3` from fakes.
fn search_app(skills_dir: &Path, script_stdout: &str) -> App<FakeRunner> {
    let runner = FakeRunner::new()
        .with_response("which", 0, which_json(skills_dir))
        .with_program_response("python3", 0, script_stdout);
    let mut app = App::new(runner);
    app.set_vault_root(demo_vault());
    app.active_view = ActiveView::Search;
    app
}

#[test]
fn search_qmd_hit_renders_via_and_score() {
    let dir = search_skills_dir("confidant-tui-search-qmd");
    let mut app = search_app(&dir, qmd_hit_json());
    app.run_search("ada");

    assert!(app.alert.is_none(), "unexpected alert: {:?}", app.alert);
    let res = app.search.result.as_ref().expect("search result populated");
    assert_eq!(res.kept.len(), 1);
    assert_eq!(res.kept[0].via, "qmd");
    assert!((res.kept[0].score - 0.9123).abs() < 1e-9);
    assert_eq!(res.dropped_unknown_via, 0);

    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("[qmd 0.91]"),
        "via+score in:\\n{rendered}"
    );
    assert!(
        rendered.contains("mode: bm25"),
        "mode line in:\\n{rendered}"
    );
    assert_snapshot("search_qmd_hit.snap", &rendered);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn search_fallback_shows_banner_and_dropped_uncleared() {
    let dir = search_skills_dir("confidant-tui-search-fallback");
    let mut app = search_app(&dir, fallback_json());
    app.run_search("ada");

    assert!(app.alert.is_none(), "unexpected alert: {:?}", app.alert);
    let res = app.search.result.as_ref().expect("search result populated");
    assert_eq!(res.result.mode, "find-fallback");
    assert_eq!(res.kept.len(), 1);
    assert_eq!(res.kept[0].via, "find");

    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("fallback: qmd or index missing"),
        "fallback banner in:\\n{rendered}"
    );
    assert!(
        rendered.contains("dropped_uncleared: 3"),
        "dropped_uncleared in:\\n{rendered}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn search_unknown_via_is_dropped_fail_closed() {
    let dir = search_skills_dir("confidant-tui-search-unknown-via");
    let mut app = search_app(&dir, unknown_via_json());
    app.run_search("ada");

    assert!(app.alert.is_none(), "unexpected alert: {:?}", app.alert);
    let res = app.search.result.as_ref().expect("search result populated");
    assert!(res.kept.is_empty(), "bogus via must not be shown");
    assert_eq!(res.dropped_unknown_via, 1);

    // The contract-level filter agrees.
    let parsed: SearchResult =
        serde_json::from_str(unknown_via_json()).expect("deserialize SearchResult");
    let filtered = filter_search_result(parsed);
    assert!(filtered.kept.is_empty());
    assert_eq!(filtered.dropped_unknown_via, 1);

    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("0 matches"),
        "empty list in:\\n{rendered}"
    );
    assert!(
        rendered.contains("dropped_unknown_via: 1"),
        "drop count in:\\n{rendered}"
    );
    assert!(
        !rendered.contains("sneaky"),
        "dropped excerpt must not render"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn search_missing_skill_shows_alert_never_falls_back_silently() {
    // skills_dir exists but has no qmd-search/skill: the TUI must alert,
    // not silently run plain `find`.
    let dir = std::env::temp_dir().join("confidant-tui-search-no-skill");
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("remove old temp dir");
    }
    fs::create_dir_all(&dir).expect("create empty skills dir");
    let mut app = search_app(&dir, qmd_hit_json());
    app.run_search("ada");

    let alert = app.alert.as_ref().expect("expected an alert");
    assert_eq!(alert.code.as_deref(), Some("qmd_skill_missing"));
    assert!(app.search.result.is_none(), "no result on missing skill");
    let calls = app.runner.recorded_program_calls();
    assert!(
        calls.is_empty(),
        "python3 must not run when the skill is missing: {calls:?}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn search_live_fallback_against_demo_vault_without_qmd() {
    // The real qmd-query.py against the demo vault, with `qmd` hidden from
    // the child's `PATH` (#514), so the script takes its find-fallback path
    // on any host, not just CI.
    let script = repo_root().join("crates/confidant-cli/skills/qmd-search/bin/qmd-query.py");
    assert!(
        script.is_file(),
        "skill script missing: {}",
        script.display()
    );

    let target_debug = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .and_then(|p| p.parent())
        .expect("target/debug")
        .to_path_buf();
    // #514: the child `PATH` is `target/debug` (so the script's
    // `shutil.which("confidant")` resolves) plus a known-empty directory,
    // never the host `PATH`. A host `qmd` therefore stays invisible and the
    // script must blame the missing qmd, not a missing index. `python3` has
    // to be named by absolute path since no host entry carries it.
    let empty = tempfile::tempdir().expect("temp PATH dir");
    let path = format!("{}:{}", target_debug.display(), empty.path().display());
    let python = python3();
    let runner = ProcessRunner::new(confidant_bin(), Some(demo_vault()))
        .with_env("PATH", path)
        .with_env("CONFIDANT_OFFLINE", "1");
    let raw = runner
        .run_program(
            &python,
            &[
                &script.display().to_string(),
                "--vault",
                &demo_vault().display().to_string(),
                "Ada Example",
            ],
        )
        .expect("run qmd-query.py");
    match parse_raw_output::<SearchResult>(&raw) {
        ContractOutcome::Ok { data, .. } => {
            assert_eq!(data.mode, "find-fallback", "expected fallback without qmd");
            assert!(
                data.fallback.as_deref().unwrap_or_default().contains("qmd"),
                "fallback reason names qmd: {:?}",
                data.fallback
            );
            assert!(
                data.matches.iter().all(|m| m.via == "find"),
                "fallback matches are via=find"
            );
            assert!(
                data.matches
                    .iter()
                    .any(|m| m.excerpt.contains("Ada Example")),
                "fallback finds Ada: {:?}",
                data.matches.iter().map(|m| &m.excerpt).collect::<Vec<_>>()
            );
            // Fail-closed filter keeps every fallback match.
            let filtered = filter_search_result(data);
            assert_eq!(filtered.dropped_unknown_via, 0);
            assert!(!filtered.kept.is_empty());
        }
        other => panic!("unexpected search outcome: {other:?}"),
    }
}

fn conflict_check_json() -> &'static str {
    r#"{
        "ok": false,
        "schema_version": "1",
        "vault": "/tmp/fake-vault",
        "spec": "0.1",
        "summary": {"errors": 2, "warnings": 0, "records": 11, "ledger_entries": 0},
        "findings": [
            {"code": "E_MERGE_CONFLICT", "severity": "error",
             "file": "people/p-01FAKE000000000000000001/record.md",
             "id": "p-01FAKE000000000000000001",
             "message": "encrypted record has two versions after a merge conflict",
             "fix": "Run `confidant record resolve p-01FAKE000000000000000001 --show` to compare the two versions"},
            {"code": "E_MERGE_CONFLICT", "severity": "error",
             "file": "people/p-01FAKE000000000000000002/record.md",
             "id": "p-01FAKE000000000000000002",
             "message": "encrypted record has two versions after a merge conflict",
             "fix": "Run `confidant record resolve p-01FAKE000000000000000002 --show` to compare the two versions"},
            {"code": "E_MERGE_CONFLICT", "severity": "error",
             "file": "ledger/2026-10-17.md",
             "message": "merge conflict markers",
             "fix": "resolve the conflict markers"}
        ]
    }"#
}

fn conflict_show_json() -> &'static str {
    r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/tmp/fake-vault",
        "id": "p-01FAKE000000000000000001",
        "path": "people/p-01FAKE000000000000000001/record.md",
        "ours": {"label": "HEAD", "text": "---\nid: p-01FAKE000000000000000001\n---\nAda Example\n\nOurs version of the note."},
        "theirs": {"label": "feature", "text": "---\nid: p-01FAKE000000000000000001\n---\nAda Example\n\nTheirs version of the note."}
    }"#
}

fn conflict_take_json() -> &'static str {
    r#"{
        "ok": true,
        "schema_version": "1",
        "vault": "/tmp/fake-vault",
        "command": "record-resolve",
        "action": "take",
        "side": "ours",
        "id": "p-01FAKE000000000000000001",
        "path": "people/p-01FAKE000000000000000001/record.md",
        "staged": true,
        "next": "git commit"
    }"#
}

fn conflict_cli_error_json() -> &'static str {
    r#"{
        "ok": false,
        "schema_version": "1",
        "vault": "/tmp/fake-vault",
        "error": {"code": "E_UNREADABLE", "message": "cannot decrypt theirs side of p-01FAKE000000000000000001", "fix": "check device keys"}
    }"#
}

/// Queue the fake responses for: check, resolve --show, resolve --take, check (reload).
fn conflict_take_runner() -> FakeRunner {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(0, conflict_show_json().as_bytes().to_vec());
    fake.push_response(0, conflict_take_json().as_bytes().to_vec());
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake
}

fn open_conflict_detail(app: &mut App<FakeRunner>) {
    app.handle_key(key(KeyCode::Char('c')));
    assert_eq!(app.active_view, ActiveView::Conflicts);
    app.handle_key(key(KeyCode::Enter));
    assert!(app.conflict.detail.is_some(), "detail loaded after Enter");
}

#[test]
fn conflict_list_snapshot() {
    let fake = FakeRunner::from_json(0, conflict_check_json());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('c')));
    assert_eq!(app.active_view, ActiveView::Conflicts);
    // Two E_MERGE_CONFLICT findings with ids; the ledger one (no id) is filtered out.
    assert_eq!(app.conflict.entries.len(), 2);
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("p-01FAKE000000000000000001"),
        "first id shown:\n{rendered}"
    );
    assert!(
        rendered.contains("p-01FAKE000000000000000002"),
        "second id shown:\n{rendered}"
    );
    assert!(
        !rendered.contains("ledger/2026-10-17.md"),
        "finding without id filtered out:\n{rendered}"
    );
    assert_snapshot("conflict_list.snap", &rendered);
}

#[test]
fn conflict_detail_two_sides_snapshot() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(0, conflict_show_json().as_bytes().to_vec());
    let mut app = App::new(fake);
    open_conflict_detail(&mut app);
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("Ours version of the note."),
        "ours side shown:\n{rendered}"
    );
    assert!(
        rendered.contains("Theirs version of the note."),
        "theirs side shown:\n{rendered}"
    );
    assert!(
        rendered.contains("p-01FAKE000000000000000001"),
        "record id in header:\n{rendered}"
    );
    assert_snapshot("conflict_detail_two_sides.snap", &rendered);
}

#[test]
fn conflict_take_ours_invokes_cli_with_expected_argv() {
    let mut app = App::new(conflict_take_runner());
    open_conflict_detail(&mut app);
    app.handle_key(key(KeyCode::Char('o')));
    assert!(
        app.conflict.confirming.is_some(),
        "confirm modal open for take ours"
    );
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("Confirm: Take ours"),
        "modal title shown:\n{rendered}"
    );
    app.handle_key(key(KeyCode::Char('y')));

    let calls = app.runner.recorded_calls();
    let expected = vec![
        "record".to_owned(),
        "resolve".to_owned(),
        "p-01FAKE000000000000000001".to_owned(),
        "--take".to_owned(),
        "ours".to_owned(),
    ];
    assert!(
        calls.iter().any(|c| c == &expected),
        "take ours issued with expected argv: {calls:?}"
    );
    assert!(
        app.conflict
            .last_result
            .as_deref()
            .unwrap_or("")
            .contains("kept the ours side"),
        "result line recorded"
    );
    assert!(
        app.conflict
            .last_result
            .as_deref()
            .unwrap_or("")
            .contains("git commit"),
        "CLI next line shown"
    );
}

#[test]
fn conflict_take_theirs_invokes_cli_with_expected_argv() {
    let mut app = App::new(conflict_take_runner());
    open_conflict_detail(&mut app);
    app.handle_key(key(KeyCode::Char('t')));
    assert!(
        app.conflict.confirming.is_some(),
        "confirm modal open for take theirs"
    );
    app.handle_key(key(KeyCode::Char('y')));

    let calls = app.runner.recorded_calls();
    let expected = vec![
        "record".to_owned(),
        "resolve".to_owned(),
        "p-01FAKE000000000000000001".to_owned(),
        "--take".to_owned(),
        "theirs".to_owned(),
    ];
    assert!(
        calls.iter().any(|c| c == &expected),
        "take theirs issued with expected argv: {calls:?}"
    );
}

#[test]
fn conflict_take_requires_confirmation() {
    let mut app = App::new(conflict_take_runner());
    open_conflict_detail(&mut app);
    app.handle_key(key(KeyCode::Char('o')));
    assert!(app.conflict.confirming.is_some());
    // `n` cancels: no CLI call, modal closed.
    app.handle_key(key(KeyCode::Char('n')));
    assert!(app.conflict.confirming.is_none(), "modal closed after n");
    let calls = app.runner.recorded_calls();
    assert!(
        !calls.iter().any(|c| c.contains(&"--take".to_owned())),
        "no take issued without confirm: {calls:?}"
    );
}

#[test]
fn conflict_cli_error_shows_alert() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(1, conflict_cli_error_json().as_bytes().to_vec());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('c')));
    app.handle_key(key(KeyCode::Enter));
    assert!(app.alert.is_some(), "alert shown on CLI error");
    assert!(app.conflict.detail.is_none(), "no detail on CLI error");
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("cannot decrypt theirs side"),
        "CD7 message shown:\n{rendered}"
    );
}

#[test]
fn conflict_old_cli_shows_upgrade_alert() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    // Exit 2 with no JSON: unknown subcommand on an older CLI.
    fake.push_response(2, b"".to_vec());
    let mut app = App::new(fake);
    app.handle_key(key(KeyCode::Char('c')));
    app.handle_key(key(KeyCode::Enter));
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("upgrade confidant"),
        "upgrade hint shown:\n{rendered}"
    );
}

#[test]
fn conflict_hand_merge_runs_edit_argv_and_refreshes() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(0, conflict_show_json().as_bytes().to_vec());
    // Reload after the suspended edit completes.
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    let mut app = App::new(fake);
    open_conflict_detail(&mut app);
    app.handle_key(key(KeyCode::Char('m')));
    assert!(
        app.conflict.confirming.is_some(),
        "confirm modal open for hand-merge"
    );
    app.handle_key(key(KeyCode::Char('y')));

    // The host takes the suspended command and runs it with a terminal.
    let cmd = app
        .take_suspended_command()
        .expect("suspended command queued");
    let expected = vec![
        "record".to_owned(),
        "resolve".to_owned(),
        "p-01FAKE000000000000000001".to_owned(),
        "--edit".to_owned(),
    ];
    assert_eq!(cmd.args, expected, "edit argv queued");
    let status = app.run_suspended_command(&cmd).expect("interactive run");
    assert_eq!(status, 0);
    let interactive = app.runner.recorded_interactive_calls();
    assert_eq!(interactive, vec![expected], "interactive call recorded");

    // The host resumes: list reloads, detail closes.
    app.after_suspended_command(Ok(status));
    assert!(app.suspended.is_none(), "suspended cleared after resume");
    assert!(app.conflict.detail.is_none(), "detail closed after resume");
    assert_eq!(app.conflict.entries.len(), 2, "list reloaded");
}

#[test]
fn conflict_hand_merge_nonzero_exit_raises_alert() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(0, conflict_show_json().as_bytes().to_vec());
    // Reload after the suspended edit completes.
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.set_interactive_status(1);
    let mut app = App::new(fake);
    open_conflict_detail(&mut app);
    app.handle_key(key(KeyCode::Char('m')));
    app.handle_key(key(KeyCode::Char('y')));

    let cmd = app
        .take_suspended_command()
        .expect("suspended command queued");
    let result = app.run_suspended_command(&cmd);
    assert_eq!(result.as_ref().copied().unwrap(), 1);
    app.after_suspended_command(result);
    assert!(
        app.alert
            .as_ref()
            .is_some_and(|a| a.title == "Hand-merge failed"),
        "alert raised on nonzero edit exit"
    );
}

#[test]
fn conflict_view_never_renders_labels_as_record_names() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(0, conflict_show_json().as_bytes().to_vec());
    let mut app = App::new(fake);
    open_conflict_detail(&mut app);
    let rendered = render_to_string(&app);
    // The header block shows the opaque record id only: tab pills (1 line)
    // plus the 3-line Conflict header. The ours pane starts after that.
    let header: String = rendered.lines().take(4).collect::<Vec<_>>().join("\n");
    assert!(
        header.contains("p-01FAKE000000000000000001"),
        "id in header:\n{header}"
    );
    assert!(
        !header.contains("HEAD") && !header.contains("feature"),
        "side labels not in the identity header:\n{header}"
    );
    // Side labels appear only as pane titles, never as the record identity.
    assert!(
        rendered.contains("ours (HEAD)"),
        "ours pane labeled:\n{rendered}"
    );
    assert!(
        rendered.contains("theirs (feature)"),
        "theirs pane labeled:\n{rendered}"
    );
}

#[test]
fn conflict_tab_navigation() {
    let fake = FakeRunner::from_json(0, conflict_check_json());
    let mut app = App::new(fake);
    // `c` switches to Conflicts.
    app.handle_key(key(KeyCode::Char('c')));
    assert_eq!(app.active_view, ActiveView::Conflicts);
    // Tab wraps within Review: Conflicts -> Proposals; Shift-Tab steps
    // back to Inbox.
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.active_view, ActiveView::Proposals);
    app.handle_key(key(KeyCode::Char('c')));
    assert_eq!(app.active_view, ActiveView::Conflicts);
    app.handle_key(key(KeyCode::BackTab));
    assert_eq!(app.active_view, ActiveView::Inbox);
    // `q` quits from the conflicts tab.
    app.handle_key(key(KeyCode::Char('c')));
    app.handle_key(key(KeyCode::Char('q')));
    assert!(app.should_quit, "q quits from the conflicts tab");
}

#[test]
fn conflict_esc_from_detail_returns_to_list() {
    let fake = FakeRunner::new();
    fake.push_response(0, conflict_check_json().as_bytes().to_vec());
    fake.push_response(0, conflict_show_json().as_bytes().to_vec());
    let mut app = App::new(fake);
    open_conflict_detail(&mut app);
    app.handle_key(key(KeyCode::Esc));
    assert!(app.conflict.detail.is_none(), "Esc closes the detail view");
    assert_eq!(app.active_view, ActiveView::Conflicts);
}

// ---------------------------------------------------------------------------
// People & Search workspace (TUI-v2 phase 1, #556)
// ---------------------------------------------------------------------------

const ADA: &str = "p-01M3TC5H00MPJG000000000000";
const BEA: &str = "p-01M3TC5H00MPJG000H24000001";

fn people_roster_json() -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "kind": "person",
        "for_operator": false,
        "records": [
            {"id": ADA, "name": "Ada Example", "no_ai": "false", "kind": "person"},
            {"id": BEA, "name": "Bea Demo", "no_ai": "false", "kind": "person"}
        ],
        "scope": ["coaching@0.1"],
        "skipped_encrypted": 0,
        "refused_envelopes": 0
    })
    .to_string()
}

fn people_context_json(id: &str, name: &str, profile: &str) -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "person": {"id": id, "name": name, "no_ai": false, "profile": profile},
        "notes": [
            {"id": "n-01M3TC5H00MPJG002NAM000005", "date": "2026-10-01",
             "body": format!("Fake note about {name}.")}
        ],
        "interactions": [
            {"id": "i-01M3TC5H00MPJG0048H0000008", "date": "2026-09-25",
             "title": "Intro call", "body": "Fake intro call transcript."}
        ],
        "touchpoints": [{"date": "2026-10-05", "kind": "call"}],
        "coaching": {
            "sessions_remaining": 5,
            "icf_hours": 1.0,
            "recent_sessions": [
                {"date": "2026-10-01", "duration_minutes": 60, "tag": "paid"}
            ]
        },
        "packs": {},
        "aliases": ["hmac:0123456789abcdef0123456789abcdef"],
        "skipped_encrypted": 0,
        "refused_envelopes": 0,
        "scope": ["coaching@0.1"]
    })
    .to_string()
}

fn people_check_json() -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": false,
        "vault": "/fake/demo-vault",
        "spec": "0.1",
        "summary": {"errors": 0, "warnings": 1, "records": 2, "ledger_entries": 0},
        "findings": [
            {"code": "W_DATE_UPCOMING", "severity": "warning", "id": ADA,
             "message": "birthday in 3 days"}
        ]
    })
    .to_string()
}

fn doctor_ok_json() -> &'static str {
    r#"{
        "schema_version": "1", "ok": true, "vault": "/fake/demo-vault",
        "checks": [
            {"id": "vault-discovery", "status": "ok", "message": "vault resolved"},
            {"id": "spec", "status": "ok", "message": "vault spec 0.1 supported"}
        ]
    }"#
}

fn people_runner() -> FakeRunner {
    FakeRunner::new()
        .with_response("check", 0, people_check_json())
        .with_response("record", 0, people_roster_json())
        .with_response(
            "context",
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        )
}

#[test]
fn people_workspace_is_default_with_roster_nudges_and_live_context() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();

    assert_eq!(app.active_view, ActiveView::People);
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));
    // One nudge, then the first person row.
    assert_eq!(app.people.selected, 1);

    let rendered = render_to_string(&app);
    assert!(rendered.contains("1 People & Search"), "{rendered}");
    assert!(rendered.contains("2 Review Queue"), "{rendered}");
    assert!(rendered.contains("3 Check"), "{rendered}");
    assert!(rendered.contains("Needs Attention (1)"), "{rendered}");
    assert!(rendered.contains("W_DATE_UPCOMING"), "{rendered}");
    assert!(rendered.contains("Ada Example"), "{rendered}");
    assert!(rendered.contains("Bea Demo"), "{rendered}");
    assert!(rendered.contains("Context — Ada Example"), "{rendered}");
    assert!(rendered.contains("sessions_remaining 5"), "{rendered}");
    assert!(
        rendered.contains("Fake note about Ada Example."),
        "{rendered}"
    );
    assert!(rendered.contains("vault  /fake/demo-vault"), "{rendered}");
    assert!(rendered.contains("scope  coaching@0.1"), "{rendered}");
    assert!(rendered.contains("doctor  not run"), "{rendered}");
    assert_snapshot("people_master_detail.snap", &rendered);

    let calls = app.runner.recorded_calls();
    assert!(
        calls.iter().any(|call| {
            call == &vec![
                "record".to_owned(),
                "list".to_owned(),
                "--kind".to_owned(),
                "person".to_owned(),
            ]
        }),
        "roster call issued: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| { call == &vec!["context".to_owned(), "--".to_owned(), ADA.to_owned()] }),
        "first person's context loaded: {calls:?}"
    );
}

#[test]
fn people_filter_is_local_and_enter_loads_the_selected_person() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    // Queue Bea's context; it is consumed by the Enter below, not by typing.
    app.runner.push_response(
        0,
        people_context_json(BEA, "Bea Demo", "Fake pay-per-session client."),
    );
    let before = app.runner.recorded_calls().len();

    app.handle_key(key(KeyCode::Char('/')));
    assert_eq!(app.input_mode, InputMode::EditingFilter);
    for ch in "Bea".chars() {
        app.handle_key(key(KeyCode::Char(ch)));
    }
    assert_eq!(app.people.filter, "Bea");
    // Typing is pure: no CLI call at all.
    assert_eq!(app.runner.recorded_calls().len(), before);
    let filtered = render_to_string(&app);
    assert!(filtered.contains("People (1)"), "{filtered}");

    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.input_mode, InputMode::Normal);
    assert_eq!(app.people.selected_person.as_deref(), Some(BEA));
    let rendered = render_to_string(&app);
    assert!(rendered.contains("Context — Bea Demo"), "{rendered}");
    assert!(
        rendered.contains("Fake pay-per-session client."),
        "{rendered}"
    );
    assert!(app
        .runner
        .recorded_calls()
        .iter()
        .any(|call| { call == &vec!["context".to_owned(), "--".to_owned(), BEA.to_owned()] }));
}

#[test]
fn nudge_enter_focuses_the_person_the_finding_names() {
    let check = serde_json::json!({
        "schema_version": "1", "ok": false, "vault": "/fake/demo-vault", "spec": "0.1",
        "summary": {"errors": 0, "warnings": 1, "records": 2, "ledger_entries": 0},
        "findings": [
            {"code": "W_CADENCE_OVERDUE", "severity": "warning", "id": BEA,
             "message": "no touchpoint in 45 days"}
        ]
    })
    .to_string();
    let fake = FakeRunner::new()
        .with_response("check", 0, check)
        .with_response("record", 0, people_roster_json())
        .with_response(
            "context",
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        );
    let mut app = App::new(fake);
    app.load_check();
    app.load_roster();
    app.runner.push_response(
        0,
        people_context_json(BEA, "Bea Demo", "Fake pay-per-session client."),
    );

    // Initial selection is the first person, below the nudge.
    assert_eq!(app.people.selected, 1);
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));
    app.handle_key(key(KeyCode::Char('k')));
    assert_eq!(app.people.selected, 0);
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));

    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.people.selected, 2, "nudge + Ada row, then Bea row");
    assert_eq!(app.people.selected_person.as_deref(), Some(BEA));
    let rendered = render_to_string(&app);
    assert!(rendered.contains("Context — Bea Demo"), "{rendered}");
}

#[test]
fn status_pills_use_cached_results_and_do_not_call_the_cli_per_key() {
    let fake = people_runner().with_response("doctor", 0, doctor_ok_json());
    let mut app = App::new(fake);
    app.load_check();
    app.load_roster();
    let before = app.runner.recorded_calls().len();

    app.handle_key(key(KeyCode::Char('d')));
    assert_eq!(app.active_view, ActiveView::Doctor);
    assert!(app.doctor.report.is_some(), "doctor loaded once by `d`");
    let doctor_calls = app
        .runner
        .recorded_calls()
        .iter()
        .filter(|call| call.first().map(String::as_str) == Some("doctor"))
        .count();
    let rendered = render_to_string(&app);
    assert!(rendered.contains("doctor  ok"), "{rendered}");

    // Moving the People cursor loads context for the newly selected person,
    // but never re-runs record list or doctor.
    app.handle_key(key(KeyCode::Char('1')));
    app.handle_key(key(KeyCode::Char('j')));
    let calls = app.runner.recorded_calls();
    let record_calls = calls
        .iter()
        .filter(|call| call.first().map(String::as_str) == Some("record"))
        .count();
    assert_eq!(record_calls, 1, "no roster reload per key: {calls:?}");
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.first().map(String::as_str) == Some("doctor"))
            .count(),
        doctor_calls,
        "no doctor rerun per key: {calls:?}"
    );
    assert!(
        calls.len() > before,
        "the person move did load context: {calls:?}"
    );
}

#[test]
fn workspace_shortcuts_keep_proposals_inbox_conflicts_and_check_reachable() {
    let vault = tempfile::tempdir().expect("temp vault");
    let fake = people_runner().with_response("inbox", 0, inbox_empty_json());
    let mut app = App::new(fake);
    app.set_vault_root(vault.path().to_path_buf());

    app.handle_key(key(KeyCode::Char('2')));
    assert_eq!(app.active_view, ActiveView::Proposals);
    assert_eq!(
        app.active_view.workspace(),
        confidant_tui::app::Workspace::Review
    );

    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.active_view, ActiveView::Inbox);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.active_view, ActiveView::Conflicts);

    app.handle_key(key(KeyCode::Char('3')));
    assert_eq!(app.active_view, ActiveView::Check);
    app.handle_key(key(KeyCode::Char('1')));
    assert_eq!(app.active_view, ActiveView::People);
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));
}

#[test]
fn scope_and_help_pills_open_cached_modals_without_cli_calls() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    let before = app.runner.recorded_calls().len();

    app.handle_key(key(KeyCode::Char('p')));
    assert!(app.info_modal.is_some(), "scope modal open");
    let scope = render_to_string(&app);
    assert!(scope.contains("Scope"), "{scope}");
    assert!(scope.contains("coaching@0.1"), "{scope}");
    assert!(scope.contains("source:"), "{scope}");
    assert_eq!(app.runner.recorded_calls().len(), before, "no CLI call");

    // Any key dismisses the informational modal.
    app.handle_key(key(KeyCode::Char('x')));
    assert!(app.info_modal.is_none());

    app.handle_key(key(KeyCode::Char('?')));
    assert!(app.info_modal.is_some(), "help modal open");
    let help = render_to_string(&app);
    assert!(help.contains("Help"), "{help}");
    assert!(help.contains("1 People & Search"), "{help}");
    assert_eq!(app.runner.recorded_calls().len(), before, "no CLI call");
}

#[test]
fn live_roster_against_demo_vault_omits_no_ai_people() {
    let runner =
        ProcessRunner::new(confidant_bin(), Some(demo_vault())).with_env("CONFIDANT_OFFLINE", "1");
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();

    let roster = app.people.roster.as_ref().expect("roster loaded");
    let names: Vec<&str> = roster
        .records
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(names, vec!["Ada Example", "Bea Demo"]);
    assert!(!names.contains(&"Cam Sample"), "no-ai person must stay out");
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));
    let rendered = render_to_string(&app);
    assert!(rendered.contains("Context — Ada Example"), "{rendered}");
    assert!(rendered.contains("scope  coaching@0.1"), "{rendered}");
}

fn check_cli_error_json() -> &'static str {
    r#"{
        "ok": false,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "error": {
            "code": "E_LEDGER_UNREADABLE",
            "message": "1 items",
            "fix": "Fix permissions, then run `confidant check` again"
        }
    }"#
}

#[test]
fn people_needs_attention_reports_check_not_loaded() {
    // A failed startup check followed by a successful roster load must not
    // read as "Nothing needs attention": the report is unknown, not clean.
    let fake = FakeRunner::new()
        .with_response("check", 1, check_cli_error_json())
        .with_response("record", 0, people_roster_json())
        .with_response(
            "context",
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        );
    let mut app = App::new(fake);
    app.load_check();
    assert!(app.check.report.is_none(), "failed check leaves no report");
    app.load_roster();

    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("check not loaded (press r)"),
        "unknown check state must say so:\n{rendered}"
    );
    assert!(
        !rendered.contains("Nothing needs attention."),
        "must not claim all-clear without a report:\n{rendered}"
    );
    assert!(rendered.contains("Ada Example"), "roster still renders");
}

#[test]
fn failed_check_refresh_clears_a_stale_report() {
    let fake = FakeRunner::new();
    // Interleaved order: check, roster, context, failing check, roster, context.
    fake.push_response(0, people_check_json());
    fake.push_response(0, people_roster_json());
    fake.push_response(
        0,
        people_context_json(ADA, "Ada Example", "Fake coaching client."),
    );
    fake.push_response(1, check_cli_error_json());
    fake.push_response(0, people_roster_json());
    fake.push_response(
        0,
        people_context_json(ADA, "Ada Example", "Fake coaching client."),
    );

    let mut app = App::new(fake);
    app.load_check();
    assert!(app.check.report.is_some(), "first check succeeded");
    app.load_roster();
    let with_nudge = render_to_string(&app);
    assert!(with_nudge.contains("W_DATE_UPCOMING"), "{with_nudge}");

    app.load_check();
    assert!(
        app.check.report.is_none(),
        "a failed refresh must clear the stale report"
    );
    // The roster reload clears the check-error alert so the pane renders.
    app.load_roster();
    let stale = render_to_string(&app);
    assert!(stale.contains("check not loaded (press r)"), "{stale}");
    assert!(
        !stale.contains("W_DATE_UPCOMING"),
        "stale nudge must not survive a failed refresh:\n{stale}"
    );
    assert!(
        !stale.contains("Nothing needs attention."),
        "must not claim all-clear after a failed refresh:\n{stale}"
    );
}

#[test]
fn pending_apply_confirm_is_not_escaped_by_workspace_shortcuts() {
    let dir = proposals_temp_dir("tui-test-proposals-confirm-gate");
    write_test_manifest(&dir, "portal-20261015T000000Z", "");
    let fake = FakeRunner::new()
        .with_response("import", 0, dry_run_import_json())
        .with_response("record", 0, people_roster_json())
        .with_response(
            "context",
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        );
    let mut app = App::new(fake);
    app.set_vault_root(dir.clone());
    app.handle_key(key(KeyCode::Char('o')));
    assert_eq!(app.active_view, ActiveView::Proposals);
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char('a')));
    app.handle_key(key(KeyCode::Char('y')));
    assert!(
        matches!(
            app.proposals.opened.as_ref().map(|flow| &flow.phase),
            Some(FlowPhase::Confirm { .. })
        ),
        "confirm modal is armed"
    );

    // `1` must not escape to People while the confirm is armed; the phase
    // handler cancels back to the diff instead.
    app.handle_key(key(KeyCode::Char('1')));
    assert_eq!(
        app.active_view,
        ActiveView::Proposals,
        "workspace shortcut escaped an armed confirm"
    );
    assert!(
        matches!(
            app.proposals.opened.as_ref().map(|flow| &flow.phase),
            Some(FlowPhase::Diff { .. })
        ),
        "confirm was disarmed, not left pending"
    );

    // Esc back to browsing, then the workspace shortcut works.
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Char('1')));
    assert_eq!(app.active_view, ActiveView::People);
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// Operator mode and record/note editing (TUI-v2 phase 2, #556)
// ---------------------------------------------------------------------------

use confidant_tui::app::OPERATOR_MODE_BANNER;
use confidant_tui::edit::{scratch_path, EditPhase};

const CAM: &str = "p-01M3TC5H00MPJG001248000002";
const NIA: &str = "p-01M3TC5H00MPJG000H24000002";
const NOTE: &str = "n-01M3TC5H00MPJG002NAM000005";
const IXN: &str = "i-01M3TC5H00MPJG0048H0000008";

const RECORD_TEXT: &str =
    "---\nid: ADA\ntype: person\nname: Ada Example\n---\n\nfake profile body\n";
const EDITED_TEXT: &str =
    "---\nid: ADA\ntype: person\nname: Ada Example\n---\n\nedited fake profile body\n";
const NOTE_TEXT: &str =
    "---\nid: NOTE\ntype: note\nperson: ADA\ndate: 2026-10-01\n---\n\nfake note body\n";

/// Serializes `$VISUAL`/`$EDITOR` manipulation: the env is process-wide, so
/// two edit tests changing it at once would race.
static EDIT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set (or clear) the operator editor for the lifetime of the guard, holding
/// the env lock so only one edit test is env-sensitive at a time.
struct EditorEnv {
    _lock: std::sync::MutexGuard<'static, ()>,
    visual: Option<std::ffi::OsString>,
    editor: Option<std::ffi::OsString>,
}

impl EditorEnv {
    fn set(editor: Option<&str>) -> Self {
        let lock = EDIT_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let visual = std::env::var_os("VISUAL");
        let editor_old = std::env::var_os("EDITOR");
        match editor {
            Some(value) => {
                std::env::set_var("VISUAL", value);
                std::env::set_var("EDITOR", value);
            }
            None => {
                std::env::remove_var("VISUAL");
                std::env::remove_var("EDITOR");
            }
        }
        Self {
            _lock: lock,
            visual,
            editor: editor_old,
        }
    }
}

impl Drop for EditorEnv {
    fn drop(&mut self) {
        match &self.visual {
            Some(value) => std::env::set_var("VISUAL", value),
            None => std::env::remove_var("VISUAL"),
        }
        match &self.editor {
            Some(value) => std::env::set_var("EDITOR", value),
            None => std::env::remove_var("EDITOR"),
        }
    }
}

/// Roster the operator path returns: a `no-ai: true` person and a
/// `no-ai: notes` person alongside the cleared one.
fn operator_roster_json() -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "kind": "person",
        "for_operator": true,
        "records": [
            {"id": ADA, "name": "Ada Example", "no_ai": "false", "kind": "person"},
            {"id": CAM, "name": "Cam Sample", "no_ai": "true", "kind": "person"},
            {"id": NIA, "name": "Nia Notes", "no_ai": "notes", "kind": "person"}
        ],
        "scope": ["coaching@0.1"],
        "skipped_encrypted": 0,
        "refused_envelopes": 0
    })
    .to_string()
}

/// Operator context bundle with the tri-state `no_ai` on the person and the
/// note.
fn operator_context_json(person_mode: &str, note_mode: &str) -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "for_operator": true,
        "person": {"id": ADA, "name": "Ada Example", "no_ai": person_mode,
                   "profile": "Fake operator-only client."},
        "notes": [
            {"id": NOTE, "date": "2026-10-01", "body": "Fake operator-only note.",
             "no_ai": note_mode}
        ],
        "interactions": [],
        "touchpoints": [],
        "packs": {},
        "aliases": [],
        "skipped_encrypted": 0,
        "refused_envelopes": 0,
        "scope": ["coaching@0.1"]
    })
    .to_string()
}

/// The first rendered line containing `needle`, or an empty string.
fn line_with<'a>(rendered: &'a str, needle: &str) -> &'a str {
    rendered
        .lines()
        .find(|line| line.contains(needle))
        .unwrap_or("")
}

#[test]
fn operator_mode_off_sends_no_flag_and_hides_no_ai() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();

    assert!(!app.operator_mode, "operator mode is off by default");
    let rendered = render_to_string(&app);
    assert!(!rendered.contains(OPERATOR_MODE_BANNER), "{rendered}");
    assert!(!rendered.contains("[no-ai]"), "{rendered}");
    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .all(|call| !call.iter().any(|arg| arg == "--for-operator")),
        "the default path never passes --for-operator: {calls:?}"
    );
}

#[test]
fn operator_mode_toggle_reloads_with_flag_and_badges_no_ai() {
    let fake = FakeRunner::new();
    // Boot (flag off).
    fake.push_response(0, people_check_json());
    fake.push_response(0, people_roster_json());
    fake.push_response(
        0,
        people_context_json(ADA, "Ada Example", "Fake coaching client."),
    );
    // Toggle: check, roster, context all reload through the operator path.
    fake.push_response(0, people_check_json());
    fake.push_response(0, operator_roster_json());
    fake.push_response(0, operator_context_json("notes", "true"));

    let mut app = App::new(fake);
    app.load_check();
    app.load_roster();
    let before = render_to_string(&app);
    assert!(!before.contains("Cam Sample"), "{before}");
    assert!(!before.contains("Nia Notes"), "{before}");

    app.handle_key(key(KeyCode::Char('!')));
    assert!(app.operator_mode);

    let calls = app.runner.recorded_calls();
    assert!(
        calls.iter().any(|call| call
            == &vec![
                "record".to_owned(),
                "list".to_owned(),
                "--kind".to_owned(),
                "person".to_owned(),
                "--for-operator".to_owned(),
            ]),
        "roster reloaded with --for-operator: {calls:?}"
    );
    assert!(
        calls.iter().any(|call| call
            == &vec![
                "context".to_owned(),
                "--for-operator".to_owned(),
                "--".to_owned(),
                ADA.to_owned(),
            ]),
        "context reloaded with --for-operator: {calls:?}"
    );

    let after = render_to_string(&app);
    // The CLI's banner is on screen, persistently (it is drawn every frame).
    assert!(after.contains(OPERATOR_MODE_BANNER), "{after}");
    // The no-ai people and the notes-mode person are listed, badged.
    assert!(after.contains("Cam Sample"), "{after}");
    assert!(after.contains("[no-ai]"), "{after}");
    assert!(after.contains("Nia Notes"), "{after}");
    assert!(after.contains("[no-ai: notes]"), "{after}");
    // The context pane badges the person and the inherited note. Full-screen
    // Context (and a wider buffer) keeps the identity line on one row.
    app.active_view = ActiveView::Context;
    let context_screen = render_to_string_at(&app, 160, HEIGHT);
    assert!(
        line_with(&context_screen, ADA).contains("[no-ai: notes]"),
        "{context_screen}"
    );
    assert!(
        line_with(&context_screen, NOTE).contains("[no-ai]"),
        "{context_screen}"
    );
}

#[test]
fn operator_mode_off_fails_closed_when_context_reload_fails() {
    let fake = FakeRunner::new();
    // Boot in operator mode: a hidden note is on screen.
    fake.push_response(0, people_check_json());
    fake.push_response(0, operator_roster_json());
    fake.push_response(0, operator_context_json("true", "true"));
    // Toggle off: the agent check and roster succeed, the context read fails.
    fake.push_response(0, people_check_json());
    fake.push_response(0, people_roster_json());
    fake.push_response(1, check_cli_error_json());

    let mut app = App::new(fake);
    app.operator_mode = true;
    app.load_check();
    app.load_roster();
    let before = render_to_string(&app);
    assert!(before.contains(OPERATOR_MODE_BANNER), "{before}");
    assert!(before.contains("Fake operator-only note."), "{before}");

    app.handle_key(key(KeyCode::Char('!')));
    assert!(!app.operator_mode);

    // Fail closed: the operator bundle was dropped *before* the failed reload,
    // so a stale `no-ai` note cannot render without the banner.
    assert!(
        app.context.context.is_none(),
        "stale operator context survived the failed reload"
    );
    let after = render_to_string(&app);
    assert!(!after.contains(OPERATOR_MODE_BANNER), "{after}");
    assert!(!after.contains("Fake operator-only note."), "{after}");

    // Even once the failure alert is dismissed, the pane stays empty.
    app.handle_key(key(KeyCode::Esc));
    let dismissed = render_to_string(&app);
    assert!(
        !dismissed.contains("Fake operator-only note."),
        "{dismissed}"
    );
    assert!(!dismissed.contains(OPERATOR_MODE_BANNER), "{dismissed}");
    assert!(dismissed.contains("No context loaded"), "{dismissed}");
}

#[test]
fn operator_mode_off_fails_closed_when_roster_reload_fails() {
    let fake = FakeRunner::new();
    // Boot in operator mode: the `no-ai` people are listed.
    fake.push_response(0, people_check_json());
    fake.push_response(0, operator_roster_json());
    fake.push_response(0, operator_context_json("true", "true"));
    // Toggle off: the roster read fails; the context read succeeds, which
    // clears the alert so the panes actually render.
    fake.push_response(0, people_check_json());
    fake.push_response(1, check_cli_error_json());
    fake.push_response(
        0,
        people_context_json(ADA, "Ada Example", "Fake coaching client."),
    );

    let mut app = App::new(fake);
    app.operator_mode = true;
    app.load_check();
    app.load_roster();
    assert!(render_to_string(&app).contains("Cam Sample"));

    app.handle_key(key(KeyCode::Char('!')));
    assert!(!app.operator_mode);

    // The operator roster was dropped before the reload failed, so the No-ai
    // people cannot reappear (e.g. after the alert is dismissed).
    assert!(
        app.people.roster.is_none(),
        "operator roster survived the failed reload"
    );
    let after = render_to_string(&app);
    assert!(!after.contains(OPERATOR_MODE_BANNER), "{after}");
    assert!(!after.contains("Cam Sample"), "{after}");
    assert!(!after.contains("[no-ai]"), "{after}");
    assert!(after.contains("People (0)"), "{after}");

    app.handle_key(key(KeyCode::Esc));
    let dismissed = render_to_string(&app);
    assert!(!dismissed.contains("Cam Sample"), "{dismissed}");
    assert!(!dismissed.contains("[no-ai]"), "{dismissed}");
}

#[test]
fn context_edit_target_moves_person_notes_interactions() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();

    let ctx = app.context.context.as_ref().expect("context loaded");
    let targets = confidant_tui::views::context::edit_targets(ctx);
    assert_eq!(targets.len(), 3, "person + one note + one interaction");
    assert_eq!(targets[0].id, ADA);
    assert_eq!(targets[1].id, NOTE);
    assert_eq!(targets[2].id, IXN);

    // The person is the default target, marked with the ▶ cursor.
    assert_eq!(app.context.edit_index, 0);
    let person = render_to_string(&app);
    assert!(line_with(&person, ADA).contains('▶'), "{person}");
    assert!(!line_with(&person, NOTE).contains('▶'), "{person}");

    // `]` moves to the note, then the interaction, then wraps to the person.
    app.handle_key(key(KeyCode::Char(']')));
    assert_eq!(app.context.edit_index, 1);
    let note = render_to_string(&app);
    assert!(line_with(&note, NOTE).contains('▶'), "{note}");
    assert!(!line_with(&note, ADA).contains('▶'), "{note}");

    app.handle_key(key(KeyCode::Char(']')));
    assert_eq!(app.context.edit_index, 2);
    assert!(line_with(&render_to_string(&app), IXN).contains('▶'));

    app.handle_key(key(KeyCode::Char(']')));
    assert_eq!(app.context.edit_index, 0, "wraps past the last target");
    app.handle_key(key(KeyCode::Char('[')));
    assert_eq!(app.context.edit_index, 2, "wraps back past the first");
}

/// App with the operator-edit responses registered by exact argv, a real temp
/// vault root for the scratch, and `git check-ignore` answering "ignored".
fn edit_app(root: &Path) -> App<FakeRunner> {
    let runner = FakeRunner::new()
        .with_argv_response(&["check"], 0, people_check_json())
        .with_argv_response(
            &["record", "list", "--kind", "person"],
            0,
            people_roster_json(),
        )
        .with_argv_response(
            &["context", "--", ADA],
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        )
        .with_argv_response(
            &["record", "show", ADA, "--for-edit"],
            0,
            edit_source_json(ADA, "person", RECORD_TEXT),
        )
        .with_argv_response(
            &["record", "edit", ADA, "--file"],
            0,
            edit_applied_json("record-edit", ADA),
        )
        .with_argv_response(
            &["note", "show", NOTE, "--for-edit"],
            0,
            edit_source_json(NOTE, "note", NOTE_TEXT),
        )
        .with_argv_response(
            &["note", "edit", NOTE, "--file"],
            0,
            edit_applied_json("note-edit", NOTE),
        );
    // rev-parse: a git repo; check-ignore: `.confidant/` is ignored.
    runner.push_program_response("git", 0, "");
    runner.push_program_response("git", 0, "");
    let mut app = App::new(runner);
    app.set_vault_root(root.to_path_buf());
    app.load_check();
    app.load_roster();
    app
}

fn edit_source_json(id: &str, kind: &str, text: &str) -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "id": id,
        "type": kind,
        "path": format!("people/{id}/profile.md"),
        "no_ai": false,
        "for_edit": true,
        "text": text
    })
    .to_string()
}

fn edit_applied_json(command: &str, id: &str) -> String {
    serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "command": command,
        "commit": "abcdef1234567890",
        "files": ["people/x"],
        "id": id,
        "path": "people/x"
    })
    .to_string()
}

/// Begin an edit and drive the fake editor through one round trip.
fn run_editor_round_trip(app: &mut App<FakeRunner>, edited: Option<&str>) -> PathBuf {
    let scratch = app
        .edit_flow
        .as_ref()
        .expect("flow started")
        .scratch
        .clone();
    let cmd = app.take_suspended_command().expect("editor queued");
    assert_eq!(cmd.program.as_deref(), Some("fake-editor"));
    assert_eq!(cmd.args, vec![scratch.display().to_string()]);
    assert_eq!(app.run_suspended_command(&cmd).unwrap(), 0);
    if let Some(text) = edited {
        fs::write(&scratch, text).expect("simulate the editor's write");
    }
    app.after_suspended_command(Ok(0));
    scratch
}

#[test]
fn edit_record_stages_scratch_then_cancel_writes_nothing() {
    let _env = EditorEnv::set(Some("fake-editor"));
    let dir = tempfile::tempdir().expect("temp vault");
    let mut app = edit_app(dir.path());

    app.handle_key(key(KeyCode::Char('e')));
    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &vec!["record", "show", ADA, "--for-edit"]),
        "the operator read prepares the edit: {calls:?}"
    );
    let scratch = scratch_path(dir.path(), ADA).expect("scratch path");
    assert_eq!(
        fs::read_to_string(&scratch).unwrap(),
        RECORD_TEXT,
        "scratch holds the fetched text"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&scratch).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "scratch is 0600");
    }
    assert!(
        !calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "--file")),
        "nothing is written before the editor: {calls:?}"
    );

    let scratch = run_editor_round_trip(&mut app, Some(EDITED_TEXT));
    let flow = app.edit_flow.as_ref().expect("awaiting confirm");
    assert_eq!(flow.phase, EditPhase::Confirm);
    let rendered = render_to_string(&app);
    assert!(
        rendered.contains("Confirm: Apply record edit"),
        "{rendered}"
    );
    // Plaintext is never rendered in the modal.
    assert!(!rendered.contains("fake profile body"), "{rendered}");

    // Any key other than `y` cancels: no write, scratch removed.
    app.handle_key(key(KeyCode::Char('n')));
    assert!(app.edit_flow.is_none(), "modal closed");
    assert!(!scratch.exists(), "scratch removed on cancel");
    let calls = app.runner.recorded_calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "--file")),
        "cancel writes nothing: {calls:?}"
    );
}

#[test]
fn edit_record_confirm_writes_once_and_reloads() {
    let _env = EditorEnv::set(Some("fake-editor"));
    let dir = tempfile::tempdir().expect("temp vault");
    let mut app = edit_app(dir.path());

    app.handle_key(key(KeyCode::Char('e')));
    let scratch = run_editor_round_trip(&mut app, Some(EDITED_TEXT));
    app.handle_key(key(KeyCode::Char('y')));

    assert!(app.edit_flow.is_none(), "flow finished");
    assert!(!scratch.exists(), "scratch removed after the write");
    let calls = app.runner.recorded_calls();
    let edit_call = calls
        .iter()
        .find(|call| {
            call.first().map(String::as_str) == Some("record")
                && call.get(1).map(String::as_str) == Some("edit")
        })
        .expect("record edit issued");
    assert_eq!(
        edit_call,
        &vec![
            "record".to_owned(),
            "edit".to_owned(),
            ADA.to_owned(),
            "--file".to_owned(),
            scratch.display().to_string(),
        ]
    );
    // The views reloaded after the write.
    assert!(
        calls
            .iter()
            .filter(|call| **call == vec!["context".to_owned(), "--".to_owned(), ADA.to_owned()])
            .count()
            >= 2,
        "context reloaded after the edit: {calls:?}"
    );
    let alert = app.alert.as_ref().expect("result alert");
    assert_eq!(alert.title, "Edit Committed");
    assert!(alert.message.contains("abcdef12"), "{}", alert.message);
}

#[test]
fn edit_no_op_does_not_call_the_cli_and_removes_scratch() {
    let _env = EditorEnv::set(Some("fake-editor"));
    let dir = tempfile::tempdir().expect("temp vault");
    let mut app = edit_app(dir.path());

    app.handle_key(key(KeyCode::Char('e')));
    // The editor changes nothing.
    let scratch = run_editor_round_trip(&mut app, None);

    assert!(app.edit_flow.is_none(), "no confirm for a no-op");
    assert!(!scratch.exists(), "scratch removed");
    let alert = app.alert.as_ref().expect("no-op alert");
    assert_eq!(alert.title, "No Changes");
    assert_eq!(alert.code.as_deref(), Some("unchanged"));
    let calls = app.runner.recorded_calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.get(1).map(String::as_str) == Some("edit")),
        "a no-op never reaches `record edit`: {calls:?}"
    );
}

#[test]
fn edit_note_uses_note_show_and_note_edit() {
    let _env = EditorEnv::set(Some("fake-editor"));
    let dir = tempfile::tempdir().expect("temp vault");
    let mut app = edit_app(dir.path());

    // Target 0 is the person; `]` selects the note.
    app.handle_key(key(KeyCode::Char(']')));
    assert_eq!(app.context.edit_index, 1);

    app.handle_key(key(KeyCode::Char('e')));
    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &vec!["note", "show", NOTE, "--for-edit"]),
        "the note read is used for notes: {calls:?}"
    );
    let scratch = run_editor_round_trip(&mut app, Some(EDITED_TEXT));
    assert_eq!(scratch, scratch_path(dir.path(), NOTE).unwrap());

    app.handle_key(key(KeyCode::Char('y')));
    let calls = app.runner.recorded_calls();
    assert!(
        calls.iter().any(|call| {
            call.first().map(String::as_str) == Some("note")
                && call.get(1).map(String::as_str) == Some("edit")
                && call.contains(&"--file".to_owned())
        }),
        "the note write uses `note edit --file`: {calls:?}"
    );
    assert!(!scratch.exists(), "scratch removed");
}

#[test]
fn edit_refused_when_scratch_is_not_gitignored() {
    let _env = EditorEnv::set(Some("fake-editor"));
    let dir = tempfile::tempdir().expect("temp vault");
    let runner = FakeRunner::new()
        .with_argv_response(&["check"], 0, people_check_json())
        .with_argv_response(
            &["record", "list", "--kind", "person"],
            0,
            people_roster_json(),
        )
        .with_argv_response(
            &["context", "--", ADA],
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        );
    runner.push_program_response("git", 0, ""); // rev-parse: a git repo
    runner.push_program_response("git", 1, ""); // check-ignore: NOT ignored
    let mut app = App::new(runner);
    app.set_vault_root(dir.path().to_path_buf());
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('e')));

    let alert = app.alert.as_ref().expect("refused");
    assert_eq!(alert.code.as_deref(), Some("scratch_not_ignored"));
    assert!(app.edit_flow.is_none(), "no flow started");
    assert!(app.suspended.is_none(), "no editor queued");
    assert!(
        !scratch_path(dir.path(), ADA).unwrap().exists(),
        "no plaintext scratch when the gitignore gate fails"
    );
    let calls = app.runner.recorded_calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "--for-edit")),
        "the operator read is not even run when refused: {calls:?}"
    );
}

#[test]
fn edit_without_editor_fails_fast_before_scratch() {
    let _env = EditorEnv::set(None);
    let dir = tempfile::tempdir().expect("temp vault");
    let mut app = edit_app(dir.path());

    app.handle_key(key(KeyCode::Char('e')));

    let alert = app.alert.as_ref().expect("alert");
    assert_eq!(alert.code.as_deref(), Some("no_editor"));
    assert!(app.edit_flow.is_none());
    assert!(
        !scratch_path(dir.path(), ADA).unwrap().exists(),
        "no scratch exists without an editor"
    );
}

#[test]
fn pending_edit_confirm_is_not_escaped_by_workspace_shortcuts() {
    let _env = EditorEnv::set(Some("fake-editor"));
    let dir = tempfile::tempdir().expect("temp vault");
    let mut app = edit_app(dir.path());

    app.handle_key(key(KeyCode::Char('e')));
    run_editor_round_trip(&mut app, Some(EDITED_TEXT));
    assert!(app.edit_flow.is_some(), "confirm is armed");

    // `2` must not escape to the Review workspace while a write is pending;
    // the modal treats it as a cancel, so nothing is written.
    app.handle_key(key(KeyCode::Char('2')));
    assert_eq!(app.active_view, ActiveView::People, "no workspace escape");
    assert!(
        app.edit_flow.is_none(),
        "confirm disarmed, not left pending"
    );
    let calls = app.runner.recorded_calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "--file")),
        "cancelled edit writes nothing: {calls:?}"
    );
}

#[test]
fn live_operator_roster_and_context_include_no_ai_person() {
    // The real CLI with `--for-operator` against the demo vault: Cam Sample
    // is `no-ai: true` and must appear (and be editable) only on the
    // operator path.
    let runner =
        ProcessRunner::new(confidant_bin(), Some(demo_vault())).with_env("CONFIDANT_OFFLINE", "1");
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();
    let agent_names: Vec<String> = app
        .people
        .roster
        .as_ref()
        .unwrap()
        .records
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    assert!(!agent_names.iter().any(|n| n == "Cam Sample"));

    app.handle_key(key(KeyCode::Char('!')));
    assert!(app.operator_mode);
    let roster = app.people.roster.as_ref().expect("roster loaded");
    let cam = roster
        .records
        .iter()
        .find(|entry| entry.name == "Cam Sample")
        .expect("no-ai person visible in operator mode");
    assert_eq!(cam.no_ai, confidant_tui::contract::NoAiMode::Hidden);

    // The operator context decrypts the hidden person and badges it.
    app.load_context(CAM);
    let ctx = app
        .context
        .context
        .as_ref()
        .expect("operator context loaded");
    assert!(ctx.for_operator);
    assert_eq!(ctx.person.name.as_deref(), Some("Cam Sample"));
    assert_eq!(ctx.person.no_ai, confidant_tui::contract::NoAiMode::Hidden);
    let rendered = render_to_string(&app);
    assert!(rendered.contains(OPERATOR_MODE_BANNER), "{rendered}");
    // Full-screen Context at a wider buffer keeps the identity line together.
    app.active_view = ActiveView::Context;
    let context_screen = render_to_string_at(&app, 160, HEIGHT);
    assert!(
        line_with(&context_screen, CAM).contains("[no-ai]"),
        "{context_screen}"
    );
}

/// End-to-end: the real CLI and a real `$EDITOR` edit a person record in a
/// throwaway git vault, committing exactly once and leaving the tree clean.
#[test]
#[cfg(unix)]
fn live_edit_commits_once_through_the_real_cli_and_editor() {
    use std::os::unix::fs::PermissionsExt;

    // A fresh git copy of the demo vault.
    let dir = tempfile::tempdir().expect("temp vault");
    let root = dir.path();
    for entry in fs::read_dir(demo_vault()).expect("read demo vault") {
        let entry = entry.unwrap();
        let dest = root.join(entry.file_name());
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
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?} failed: {out:?}");
    };
    git(&["init", "-b", "main", "-q"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "test"]);
    fs::write(root.join(".gitignore"), ".confidant/\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "init"]);

    // A real editor that appends a marker line to the scratch file. It lives
    // outside the vault: any stray file at the vault root is an
    // `E_INVALID_FILENAME` finding, which would block the write.
    let editor_dir = tempfile::tempdir().expect("temp editor dir");
    let editor = editor_dir.path().join("editor.sh");
    fs::write(
        &editor,
        "#!/bin/sh\nprintf '\\nlive-edit-marker\\n' >> \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o755)).unwrap();
    let _env = EditorEnv::set(Some(&editor.display().to_string()));

    let runner = ProcessRunner::new(confidant_bin(), Some(root.to_path_buf()))
        .with_env("CONFIDANT_OFFLINE", "1");
    let mut app = App::new(runner);
    app.set_vault_root(root.to_path_buf());
    app.load_check();
    app.load_roster();
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));

    app.handle_key(key(KeyCode::Char('e')));
    assert!(app.edit_flow.is_some(), "edit flow started");
    let scratch = scratch_path(root, ADA).unwrap();
    assert!(scratch.exists(), "scratch staged");

    let cmd = app.take_suspended_command().expect("editor queued");
    let status = app.run_suspended_command(&cmd).expect("editor runs");
    assert_eq!(status, 0, "editor exits cleanly");
    app.after_suspended_command(Ok(status));
    assert!(app.edit_flow.is_some(), "awaiting confirm");

    app.handle_key(key(KeyCode::Char('y')));
    assert!(app.edit_flow.is_none(), "flow finished");
    assert!(!scratch.exists(), "scratch removed after the write");
    assert_eq!(
        app.alert.as_ref().map(|a| a.title.as_str()),
        Some("Edit Committed")
    );

    // Exactly one new commit (init + the edit).
    let log = std::process::Command::new("git")
        .args(["log", "--oneline"])
        .current_dir(root)
        .output()
        .expect("git log");
    let log = String::from_utf8_lossy(&log.stdout);
    assert_eq!(log.lines().count(), 2, "one edit commit:\n{log}");
    let profile = fs::read_to_string(root.join("people").join(ADA).join("profile.md")).unwrap();
    assert!(profile.contains("live-edit-marker"), "{profile}");
    // The edit scratch is git-ignored: the tree is clean after the commit.
    let status_out = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .expect("git status");
    assert!(
        String::from_utf8_lossy(&status_out.stdout)
            .trim()
            .is_empty(),
        "working tree must be clean: {}",
        String::from_utf8_lossy(&status_out.stdout)
    );
}

// ---------------------------------------------------------------------------
// Quick capture and the merged Review Queue (TUI-v2 phase 3, #556)
// ---------------------------------------------------------------------------

use confidant_tui::capture::{
    scratch_path as capture_scratch_path, CaptureKind, CapturePhase, FieldId,
};
use confidant_tui::views::proposals::ProposalListEntry;

fn s(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_owned()).collect()
}

fn type_text<R: Runner>(app: &mut App<R>, text: &str) {
    for ch in text.chars() {
        app.handle_key(key(KeyCode::Char(ch)));
    }
}

fn capture_dry_json(command: &str, path: &str, action: &str, content: &str) -> String {
    serde_json::json!({
        "ok": true,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "command": command,
        "dry_run": true,
        "commit": null,
        "changes": [{"path": path, "action": action, "content": content}]
    })
    .to_string()
}

fn capture_applied_json(command: &str) -> String {
    serde_json::json!({
        "ok": true,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "command": command,
        "commit": "abcdef1234567890",
        "files": ["ledger/2026/10.cfd"]
    })
    .to_string()
}

/// The read responses every capture test needs: check, roster, and the
/// selected person's context (loaded on boot and reloaded after a write).
fn capture_base_runner() -> FakeRunner {
    FakeRunner::new()
        .with_argv_response(&["check"], 0, people_check_json())
        .with_argv_response(&["record", "list"], 0, people_roster_json())
        .with_argv_response(
            &["context", "--", ADA],
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        )
}

#[test]
fn capture_session_prefills_person_previews_then_writes() {
    let runner = capture_base_runner()
        .with_argv_response(
            &["log", "session", ADA, "60m", "--dry-run"],
            0,
            capture_dry_json(
                "log-session",
                "ledger/2026/10.cfd",
                "append",
                "2026-10-13 session ADA 60m\n",
            ),
        )
        .with_argv_response(
            &["log", "session", ADA, "60m"],
            0,
            capture_applied_json("log-session"),
        );
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));

    app.handle_key(key(KeyCode::Char('s')));
    let capture = app.capture.as_ref().expect("capture open");
    assert_eq!(capture.kind, CaptureKind::Session);
    assert_eq!(capture.person_id, ADA, "person pre-filled, no ULID typing");
    assert_eq!(capture.phase, CapturePhase::Editing);
    let form = render_to_string(&app);
    assert!(form.contains("Capture: Log session"), "{form}");
    assert!(form.contains(ADA), "{form}");

    type_text(&mut app, "60m");
    app.handle_key(key(KeyCode::Enter));

    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m", "--dry-run"])),
        "the dry run is issued: {calls:?}"
    );
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.phase),
        Some(CapturePhase::Preview),
        "the preview is on screen"
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m"])),
        "nothing is written before the confirm: {calls:?}"
    );
    let preview = render_to_string(&app);
    assert!(preview.contains("Confirm: Log session"), "{preview}");
    assert!(preview.contains("ledger/2026/10.cfd"), "{preview}");

    app.handle_key(key(KeyCode::Char('y')));
    assert!(app.capture.is_none(), "capture closed after the write");
    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m"])),
        "the real write is issued: {calls:?}"
    );
    let alert = app.alert.as_ref().expect("result alert");
    assert_eq!(alert.title, "Capture Committed");
    assert!(alert.message.contains("abcdef12"), "{}", alert.message);
}

#[test]
fn capture_session_cancel_writes_nothing() {
    let runner = capture_base_runner()
        .with_argv_response(
            &["log", "session", ADA, "60m", "--dry-run"],
            0,
            capture_dry_json("log-session", "ledger/2026/10.cfd", "append", "x"),
        )
        .with_argv_response(
            &["log", "session", ADA, "60m"],
            0,
            capture_applied_json("log-session"),
        );
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('s')));
    type_text(&mut app, "60m");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.phase),
        Some(CapturePhase::Preview)
    );

    // Any key other than `y` cancels the capture.
    app.handle_key(key(KeyCode::Char('n')));
    assert!(app.capture.is_none(), "capture cancelled");
    let calls = app.runner.recorded_calls();
    assert!(
        !calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m"])),
        "a cancelled capture writes nothing: {calls:?}"
    );
}

#[test]
fn capture_pending_preview_is_not_escaped_by_workspace_shortcuts() {
    let runner = capture_base_runner().with_argv_response(
        &["log", "session", ADA, "60m", "--dry-run"],
        0,
        capture_dry_json("log-session", "ledger/2026/10.cfd", "append", "x"),
    );
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();
    app.handle_key(key(KeyCode::Char('s')));
    type_text(&mut app, "60m");
    app.handle_key(key(KeyCode::Enter));
    assert!(app.capture.is_some(), "preview armed");

    app.handle_key(key(KeyCode::Char('2')));
    assert!(app.capture.is_none(), "preview cancelled, not left pending");
    assert_eq!(app.active_view, ActiveView::People, "no workspace escape");
}

#[test]
fn capture_touch_uses_touch_argv() {
    let runner = capture_base_runner()
        .with_argv_response(
            &["log", "touch", ADA, "meal", "--dry-run"],
            0,
            capture_dry_json("log-touch", "ledger/2026/10.cfd", "append", "x"),
        )
        .with_argv_response(
            &["log", "touch", ADA, "meal"],
            0,
            capture_applied_json("log-touch"),
        );
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('t')));
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.kind),
        Some(CaptureKind::Touch)
    );
    type_text(&mut app, "meal");
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char('y')));

    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &s(&["log", "touch", ADA, "meal"])),
        "touch write issued: {calls:?}"
    );
}

#[test]
fn capture_without_a_person_shows_an_alert() {
    let mut app = App::new(capture_base_runner());
    // No roster loaded: nothing is selected.
    app.handle_key(key(KeyCode::Char('s')));
    assert!(app.capture.is_none(), "no capture without a person");
    let alert = app.alert.as_ref().expect("alert");
    assert_eq!(alert.code.as_deref(), Some("no_person"));
}

#[test]
fn capture_dry_run_error_keeps_the_form_open() {
    let error = serde_json::json!({
        "ok": false,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "error": {"code": "usage_error", "message": "bad duration 'xx'", "fix": "use like 60m"}
    })
    .to_string();
    let runner = capture_base_runner().with_argv_response(&["log", "session", ADA, "xx"], 0, error);
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('s')));
    type_text(&mut app, "xx");
    app.handle_key(key(KeyCode::Enter));

    let capture = app.capture.as_ref().expect("form stays open");
    assert_eq!(capture.phase, CapturePhase::Editing);
    let message = capture.error.as_deref().unwrap_or("");
    assert!(message.contains("bad duration"), "{message}");
    let rendered = render_to_string(&app);
    assert!(rendered.contains("bad duration"), "{rendered}");
}

#[test]
fn capture_note_stages_scratch_then_writes_and_removes_it() {
    let dir = tempfile::tempdir().expect("temp vault");
    let runner = capture_base_runner();
    runner.push_response(
        0,
        capture_dry_json("note-add", "people/ADA/notes/x.md", "add", "body"),
    );
    runner.push_response(0, capture_applied_json("note-add"));
    // `git check-ignore` gate: a repo that ignores `.confidant/`.
    runner.push_program_response("git", 0, "");
    runner.push_program_response("git", 0, "");
    let mut app = App::new(runner);
    app.set_vault_root(dir.path().to_path_buf());
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('n')));
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.kind),
        Some(CaptureKind::Note)
    );
    type_text(&mut app, "one-line body");
    app.handle_key(key(KeyCode::Enter));

    let scratch = capture_scratch_path(dir.path(), ADA).expect("scratch path");
    assert_eq!(
        fs::read_to_string(&scratch).unwrap(),
        "one-line body",
        "the body is staged for --body-file"
    );
    let calls = app.runner.recorded_calls();
    assert!(
        calls.iter().any(|call| {
            call.first().map(String::as_str) == Some("note")
                && call.contains(&"--dry-run".to_owned())
        }),
        "the note dry run is issued: {calls:?}"
    );

    app.handle_key(key(KeyCode::Char('y')));
    assert!(!scratch.exists(), "the scratch is removed after the write");
    let calls = app.runner.recorded_calls();
    let write = calls
        .iter()
        .find(|call| {
            call.first().map(String::as_str) == Some("note")
                && !call.contains(&"--dry-run".to_owned())
        })
        .expect("note write issued");
    assert!(write.contains(&"--body-file".to_owned()), "{write:?}");
    assert!(
        write.contains(&scratch.display().to_string()),
        "the write points at the staged scratch: {write:?}"
    );
}

#[test]
fn capture_note_cancel_removes_the_scratch() {
    let dir = tempfile::tempdir().expect("temp vault");
    let runner = capture_base_runner();
    runner.push_response(
        0,
        capture_dry_json("note-add", "people/ADA/notes/x.md", "add", "body"),
    );
    runner.push_response(0, capture_applied_json("note-add"));
    runner.push_program_response("git", 0, "");
    runner.push_program_response("git", 0, "");
    let mut app = App::new(runner);
    app.set_vault_root(dir.path().to_path_buf());
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('n')));
    type_text(&mut app, "cancel me");
    app.handle_key(key(KeyCode::Enter));
    let scratch = capture_scratch_path(dir.path(), ADA).expect("scratch path");
    assert!(scratch.exists(), "scratch staged for the preview");

    // Esc cancels from the preview: nothing is written, scratch removed.
    app.handle_key(key(KeyCode::Esc));
    assert!(app.capture.is_none());
    assert!(!scratch.exists(), "scratch removed on cancel");
    let calls = app.runner.recorded_calls();
    assert!(
        !calls.iter().any(|call| {
            call.first().map(String::as_str) == Some("note")
                && !call.contains(&"--dry-run".to_owned())
        }),
        "a cancelled note writes nothing: {calls:?}"
    );
}

#[test]
fn capture_note_no_ai_toggle_is_passed() {
    let dir = tempfile::tempdir().expect("temp vault");
    let runner = capture_base_runner();
    runner.push_response(
        0,
        capture_dry_json("note-add", "people/ADA/notes/x.md", "add", "body"),
    );
    runner.push_response(0, capture_applied_json("note-add"));
    runner.push_program_response("git", 0, "");
    runner.push_program_response("git", 0, "");
    let mut app = App::new(runner);
    app.set_vault_root(dir.path().to_path_buf());
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char('n')));
    type_text(&mut app, "private body");
    // Move to the no-ai toggle (body -> date -> no-ai) and flip it with space.
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Tab));
    assert!(app
        .capture
        .as_ref()
        .is_some_and(|capture| capture.value(FieldId::Body) == "private body"));
    app.handle_key(key(KeyCode::Char(' ')));
    assert!(app
        .capture
        .as_ref()
        .is_some_and(|capture| capture.enabled(FieldId::NoAi)));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char('y')));

    let calls = app.runner.recorded_calls();
    let write = calls
        .iter()
        .find(|call| {
            call.first().map(String::as_str) == Some("note")
                && !call.contains(&"--dry-run".to_owned())
        })
        .expect("note write issued");
    assert!(write.contains(&"--no-ai".to_owned()), "{write:?}");
}

#[test]
fn review_queue_badge_counts_sources_and_is_visible_from_people() {
    // Conflict check report: two E_MERGE_CONFLICT findings with ids.
    let runner = FakeRunner::new()
        .with_argv_response(&["check"], 0, conflict_check_json())
        .with_argv_response(&["record", "list"], 0, people_roster_json())
        .with_argv_response(
            &["context", "--", ADA],
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        )
        .with_argv_response(&["inbox", "--dry-run"], 0, inbox_dry_run_json());
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();
    app.load_inbox();
    app.proposals.entries.push(ProposalListEntry {
        name: "portal-1".to_owned(),
        ..ProposalListEntry::default()
    });

    assert_eq!(
        app.review_pending(),
        1 + 2 + 2,
        "proposals + inbox + conflicts"
    );
    // Workspace 1 (People) still shows the Review Queue badge.
    assert_eq!(app.active_view, ActiveView::People);
    let rendered = render_to_string(&app);
    assert!(rendered.contains("2 Review Queue (5)"), "{rendered}");

    // With nothing pending the badge is absent (unchanged header).
    let clean = FakeRunner::new()
        .with_argv_response(&["check"], 0, people_check_json())
        .with_argv_response(&["record", "list"], 0, people_roster_json())
        .with_argv_response(
            &["context", "--", ADA],
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        );
    let mut clean_app = App::new(clean);
    clean_app.load_check();
    clean_app.load_roster();
    assert_eq!(clean_app.review_pending(), 0);
    let clean_rendered = render_to_string(&clean_app);
    assert!(
        clean_rendered.contains("2 Review Queue"),
        "{clean_rendered}"
    );
    assert!(
        !clean_rendered.contains("2 Review Queue ("),
        "{clean_rendered}"
    );
}

/// End-to-end: the real CLI creates a note from a captured body in a
/// throwaway git vault, committing exactly once.
#[test]
#[cfg(unix)]
fn live_capture_note_commits_once_through_the_real_cli() {
    // A fresh git copy of the demo vault (same shape as the live edit test).
    let dir = tempfile::tempdir().expect("temp vault");
    let root = dir.path();
    for entry in fs::read_dir(demo_vault()).expect("read demo vault") {
        let entry = entry.unwrap();
        let dest = root.join(entry.file_name());
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
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?} failed: {out:?}");
    };
    git(&["init", "-b", "main", "-q"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "test"]);
    fs::write(root.join(".gitignore"), ".confidant/\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "init"]);

    let runner = ProcessRunner::new(confidant_bin(), Some(root.to_path_buf()))
        .with_env("CONFIDANT_OFFLINE", "1");
    let mut app = App::new(runner);
    app.set_vault_root(root.to_path_buf());
    app.load_check();
    app.load_roster();
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));

    app.handle_key(key(KeyCode::Char('n')));
    type_text(&mut app, "live captured note body");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.phase),
        Some(CapturePhase::Preview),
        "the real dry run produced a preview"
    );
    let scratch = capture_scratch_path(root, ADA).expect("scratch path");
    assert!(scratch.exists(), "the note body is staged");

    app.handle_key(key(KeyCode::Char('y')));
    assert!(app.capture.is_none(), "capture finished");
    assert!(!scratch.exists(), "the scratch is removed after the write");
    assert_eq!(
        app.alert.as_ref().map(|alert| alert.title.as_str()),
        Some("Capture Committed")
    );

    // Exactly one new commit (init + the note).
    let log = std::process::Command::new("git")
        .args(["log", "--oneline"])
        .current_dir(root)
        .output()
        .expect("git log");
    let log = String::from_utf8_lossy(&log.stdout);
    assert_eq!(log.lines().count(), 2, "one capture commit:\n{log}");

    // The note landed under the person, with the captured body.
    let notes_dir = root.join("people").join(ADA).join("notes");
    let notes: Vec<_> = fs::read_dir(&notes_dir)
        .expect("notes dir")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    let captured: Vec<_> = notes
        .iter()
        .filter(|path| {
            fs::read_to_string(path)
                .unwrap_or_default()
                .contains("live captured note body")
        })
        .collect();
    assert_eq!(captured.len(), 1, "exactly one captured note: {notes:?}");
}

#[test]
fn capture_targets_the_person_open_in_context_not_the_people_cursor() {
    // Ada stays highlighted in People; Bea is opened from a search hit into
    // the full-screen Context view. `s` must target Bea (what is on screen),
    // not the stale People cursor.
    let find = serde_json::json!({
        "schema_version": "1",
        "ok": true,
        "vault": "/fake/demo-vault",
        "query": "bea",
        "matches": [{
            "id": BEA,
            "path": "people/BEA/profile.md",
            "line": 4,
            "excerpt": "name: Bea Demo"
        }],
        "findings": [],
        "skipped_encrypted": 0,
        "refused_envelopes": 0,
        "scope": ["coaching@0.1"]
    })
    .to_string();
    let runner = FakeRunner::new()
        .with_argv_response(&["check"], 0, people_check_json())
        .with_argv_response(&["record", "list"], 0, people_roster_json())
        .with_argv_response(
            &["context", "--", ADA],
            0,
            people_context_json(ADA, "Ada Example", "Fake coaching client."),
        )
        .with_argv_response(
            &["context", "--", BEA],
            0,
            people_context_json(BEA, "Bea Demo", "Fake pay-per-session client."),
        )
        .with_argv_response(&["find", "--", "bea"], 0, find)
        .with_argv_response(
            &["log", "session", BEA, "60m", "--dry-run"],
            0,
            capture_dry_json("log-session", "ledger/2026/10.cfd", "append", "x"),
        );
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));

    app.active_view = ActiveView::Search;
    app.search.exact = true;
    app.run_search("bea");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.active_view, ActiveView::Context);
    assert_eq!(app.context.person_id.as_deref(), Some(BEA));
    // `activate_selected` opens Context without moving the People cursor.
    assert_eq!(app.people.selected_person.as_deref(), Some(ADA));

    app.handle_key(key(KeyCode::Char('s')));
    assert_eq!(
        app.capture
            .as_ref()
            .map(|capture| capture.person_id.as_str()),
        Some(BEA),
        "capture pre-fills the person whose context is on screen"
    );
    type_text(&mut app, "60m");
    app.handle_key(key(KeyCode::Enter));

    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &s(&["log", "session", BEA, "60m", "--dry-run"])),
        "the write targets Bea: {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m", "--dry-run"])),
        "the write must not target Ada: {calls:?}"
    );
}

#[test]
fn load_conflicts_resets_the_check_cursor() {
    let mut app = App::new(FakeRunner::from_json(0, conflict_check_json()));
    app.check.selected = 7;
    app.load_conflicts();
    assert_eq!(
        app.check.selected, 0,
        "the Check list must not open on a stale row"
    );
}

#[test]
fn prime_review_queue_keeps_the_first_startup_alert() {
    // check and roster fail first; the inbox dry run fails with a different
    // error. The first failure is the one the operator should see.
    let inbox_error = serde_json::json!({
        "ok": false,
        "schema_version": "1",
        "vault": "/fake/demo-vault",
        "error": {
            "code": "E_INBOX_CRYPTO",
            "message": "inbox dry run failed",
            "fix": "queue the item again"
        }
    })
    .to_string();
    let fake = FakeRunner::new()
        .with_argv_response(&["check"], 1, check_cli_error_json())
        .with_argv_response(&["record", "list"], 1, check_cli_error_json())
        .with_argv_response(&["inbox", "--dry-run"], 1, inbox_error);
    let mut app = App::new(fake);
    app.load_check();
    app.load_roster();
    let first = app
        .alert
        .as_ref()
        .map(|alert| alert.message.clone())
        .expect("startup alert");

    app.prime_review_queue();

    assert_eq!(
        app.alert.as_ref().map(|alert| alert.message.clone()),
        Some(first),
        "the inbox failure must not replace the earlier startup alert"
    );
}

// ---------------------------------------------------------------------------
// Keymap, help modal, and command palette (TUI-v2 phase 5, #556)
// ---------------------------------------------------------------------------

#[test]
fn help_modal_is_a_grouped_keymap_with_operator_and_selection_calls() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    let before = app.runner.recorded_calls().len();

    app.handle_key(key(KeyCode::Char('?')));
    assert!(app.info_modal.is_some(), "help modal open");
    let help = render_to_string(&app);
    for needle in [
        "Help",
        "Workspaces",
        "People & Search",
        "Review Queue",
        "Check",
        "Anywhere",
        "g/G first/last",
        "Tab/Shift-Tab",
        "context: j/k scroll",
        "[ / ] select the context item",
        "e edit it",
        "! operator mode",
        ": or Ctrl-P palette",
        "Enter never writes; y confirms after a preview",
        "at the People home it does not quit",
    ] {
        assert!(help.contains(needle), "missing {needle:?} in:\n{help}");
    }
    assert_eq!(app.runner.recorded_calls().len(), before, "no CLI call");
}

#[test]
fn help_keymap_snapshot() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    app.handle_key(key(KeyCode::Char('?')));
    assert_snapshot("help_keymap.snap", &render_to_string(&app));
}

#[test]
fn command_palette_filters_and_runs_a_read_only_action() {
    let fake = people_runner().with_response("doctor", 0, doctor_ok_json());
    let mut app = App::new(fake);
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char(':')));
    assert!(app.palette.is_some(), ": opens the palette");
    type_text(&mut app, "doctor");
    let state = app.palette.as_ref().expect("palette open");
    assert!(
        state
            .matches()
            .iter()
            .any(|entry| entry.id == "view.doctor"),
        "doctor is in the filtered list"
    );
    assert_eq!(
        state.selected_entry().map(|entry| entry.id),
        Some("view.doctor"),
        "single best match selected"
    );

    app.handle_key(key(KeyCode::Enter));
    assert!(app.palette.is_none(), "palette closes after running");
    assert_eq!(app.active_view, ActiveView::Doctor);
    assert!(app.doctor.report.is_some(), "the normal Doctor loader ran");
}

#[test]
fn command_palette_opens_with_ctrl_p_and_esc_closes_it() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();

    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
    assert!(app.palette.is_some(), "Ctrl-P opens the palette");
    app.handle_key(key(KeyCode::Esc));
    assert!(app.palette.is_none(), "Esc closes the palette");
    assert!(!app.should_quit, "closing the palette does not quit");
}

#[test]
fn command_palette_capture_still_dry_runs_and_waits_for_y() {
    let runner = capture_base_runner()
        .with_argv_response(
            &["log", "session", ADA, "60m", "--dry-run"],
            0,
            capture_dry_json(
                "log-session",
                "ledger/2026/10.cfd",
                "append",
                "2026-10-13 session ADA 60m\n",
            ),
        )
        .with_argv_response(
            &["log", "session", ADA, "60m"],
            0,
            capture_applied_json("log-session"),
        );
    let mut app = App::new(runner);
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Char(':')));
    type_text(&mut app, "log a session");
    assert_eq!(
        app.palette
            .as_ref()
            .and_then(|state| state.selected_entry())
            .map(|entry| entry.id),
        Some("capture.session")
    );
    app.handle_key(key(KeyCode::Enter));

    // The palette only starts the normal capture flow: form first, then the
    // CLI's dry run, then an explicit `y`. Nothing is written yet.
    assert!(app.capture.is_some(), "capture form opened");
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.phase),
        Some(CapturePhase::Editing)
    );
    assert!(
        !app.runner
            .recorded_calls()
            .iter()
            .any(|call| call.first().map(String::as_str) == Some("log")),
        "no CLI write from the palette alone"
    );

    type_text(&mut app, "60m");
    app.handle_key(key(KeyCode::Enter));
    let calls = app.runner.recorded_calls();
    assert!(
        calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m", "--dry-run"])),
        "dry run issued: {calls:?}"
    );
    assert_eq!(
        app.capture.as_ref().map(|capture| capture.phase),
        Some(CapturePhase::Preview)
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m"])),
        "preview does not write: {calls:?}"
    );

    app.handle_key(key(KeyCode::Char('y')));
    assert!(app.capture.is_none(), "capture closed after the write");
    assert!(
        app.runner
            .recorded_calls()
            .iter()
            .any(|call| call == &s(&["log", "session", ADA, "60m"])),
        "y performed the real write"
    );
}

#[test]
fn palette_cannot_open_over_a_pending_capture_confirm() {
    let mut app = App::new(capture_base_runner());
    app.load_check();
    app.load_roster();
    app.handle_key(key(KeyCode::Char('s')));
    type_text(&mut app, "60m");
    app.handle_key(key(KeyCode::Enter));
    // No dry-run response is queued; the capture stays open with an inline
    // error. The palette key must stay owned by the capture modal.
    app.handle_key(key(KeyCode::Char(':')));
    assert!(app.palette.is_none(), "palette did not bypass the modal");
}

#[test]
fn command_palette_snapshot() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    app.handle_key(key(KeyCode::Char(':')));
    assert_snapshot("command_palette.snap", &render_to_string(&app));
}

#[test]
fn g_and_shift_g_jump_to_the_first_and_last_row() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    assert_eq!(app.people.selected, 1, "nudge, then Ada");

    app.runner.push_response(
        0,
        people_context_json(BEA, "Bea Demo", "Fake pay-per-session client."),
    );
    app.handle_key(key(KeyCode::Char('G')));
    assert_eq!(app.people.selected, 2, "G lands on the last person");
    assert_eq!(app.people.selected_person.as_deref(), Some(BEA));
    assert_eq!(
        app.context
            .context
            .as_ref()
            .map(|ctx| ctx.person.id.as_str()),
        Some(BEA),
        "the last person's context loaded"
    );

    app.handle_key(key(KeyCode::Char('g')));
    assert_eq!(app.people.selected, 0, "g lands on the first row");
    assert_eq!(
        app.people.selected_person.as_deref(),
        Some(BEA),
        "landing on a nudge keeps the last person's context"
    );
}

#[test]
fn home_esc_does_not_quit_and_still_clears_the_filter() {
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();

    app.handle_key(key(KeyCode::Esc));
    assert!(!app.should_quit, "Esc at People home is inert");
    assert!(app.alert.is_none());

    app.handle_key(key(KeyCode::Char('/')));
    type_text(&mut app, "Bea");
    assert_eq!(app.people.filter, "Bea");
    app.handle_key(key(KeyCode::Esc));
    assert_eq!(app.people.filter, "", "Esc clears the filter first");
    assert!(!app.should_quit);

    app.handle_key(key(KeyCode::Char('q')));
    assert!(app.should_quit, "q is the explicit quit");
}

#[test]
fn command_palette_inbox_apply_dry_runs_then_asks_for_y() {
    let fake = FakeRunner::from_json(0, inbox_dry_run_json());
    let mut app = App::new(fake);

    app.handle_key(key(KeyCode::Char(':')));
    type_text(&mut app, "apply inbox");
    assert_eq!(
        app.palette
            .as_ref()
            .and_then(|state| state.selected_entry())
            .map(|entry| entry.id),
        Some("inbox.apply")
    );
    let before = app.runner.recorded_calls().len();
    app.handle_key(key(KeyCode::Enter));

    assert_eq!(app.active_view, ActiveView::Inbox);
    assert!(app.inbox.confirming, "the normal apply confirm is open");
    let calls = app.runner.recorded_calls();
    let issued = &calls[before..];
    assert_eq!(
        issued,
        &[vec!["inbox".to_owned(), "--dry-run".to_owned()]],
        "exactly one dry run, no write: {issued:?}"
    );

    // Esc cancels the confirm; the real (non-dry-run) inbox is never issued.
    app.handle_key(key(KeyCode::Esc));
    assert!(!app.inbox.confirming);
    assert!(
        !app.runner
            .recorded_calls()
            .iter()
            .any(|call| call == &vec!["inbox".to_owned()]),
        "cancelling writes nothing"
    );
}

#[test]
fn command_palette_inbox_apply_failure_keeps_the_confirm_closed() {
    // Prime the view with a successful dry run, then make the palette's own
    // fresh dry run fail. The loaded report is now stale, so the confirm must
    // stay closed: otherwise `y` would run the real inbox behind a preview the
    // TUI just failed to refresh (the entry's fail-closed contract).
    let fake = FakeRunner::new();
    fake.push_response(0, inbox_dry_run_json());
    fake.push_response(
        1,
        r#"{
            "ok": false,
            "schema_version": "1",
            "vault": "/tmp/fake-vault",
            "error": {
                "code": "E_INBOX_CRYPTO",
                "message": "inbox dry run failed",
                "fix": "queue the item again"
            }
        }"#,
    );
    let mut app = App::new(fake);

    app.load_inbox();
    assert!(
        app.inbox
            .report
            .as_ref()
            .is_some_and(|r| !r.empty && !r.items.is_empty()),
        "the first dry run primed an applicable preview"
    );

    app.handle_key(key(KeyCode::Char(':')));
    type_text(&mut app, "apply inbox");
    assert_eq!(
        app.palette
            .as_ref()
            .and_then(|state| state.selected_entry())
            .map(|entry| entry.id),
        Some("inbox.apply")
    );
    let before = app.runner.recorded_calls().len();
    app.handle_key(key(KeyCode::Enter));

    assert_eq!(app.active_view, ActiveView::Inbox);
    assert!(
        !app.inbox.confirming,
        "a failed fresh dry run must not open the apply confirm"
    );
    assert!(
        app.alert.is_some(),
        "the dry-run failure is surfaced to the operator"
    );
    let issued = &app.runner.recorded_calls()[before..];
    assert_eq!(
        issued,
        &[vec!["inbox".to_owned(), "--dry-run".to_owned()]],
        "the palette still issues exactly one fresh dry run: {issued:?}"
    );

    // With no confirm open, `y` is an ordinary key: the real inbox never runs.
    app.handle_key(key(KeyCode::Char('y')));
    assert!(
        !app.runner
            .recorded_calls()
            .iter()
            .any(|call| call == &vec!["inbox".to_owned()]),
        "the real inbox must not run behind the stale preview"
    );
}

#[test]
fn palette_record_edit_is_refused_outside_people_and_context() {
    // `e` edits the loaded context pane, which only People and the Context
    // view show. Launched from another view, the palette entry must refuse
    // rather than silently edit a context the operator cannot see.
    let mut app = App::new(people_runner());
    app.load_check();
    app.load_roster();
    app.handle_key(key(KeyCode::Char('3')));
    assert_eq!(app.active_view, ActiveView::Check);
    let before = app.runner.recorded_calls().len();

    app.handle_key(key(KeyCode::Char(':')));
    type_text(&mut app, "edit the selected");
    assert_eq!(
        app.palette
            .as_ref()
            .and_then(|state| state.selected_entry())
            .map(|entry| entry.id),
        Some("record.edit")
    );
    app.handle_key(key(KeyCode::Enter));

    assert_eq!(app.active_view, ActiveView::Check, "the view is unchanged");
    let alert = app.alert.as_ref().expect("a refusal alert");
    assert_eq!(alert.code.as_deref(), Some("edit_needs_context"));
    assert_eq!(
        app.runner.recorded_calls().len(),
        before,
        "the refusal issues no CLI call"
    );
}
