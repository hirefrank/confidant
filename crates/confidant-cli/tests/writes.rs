//! Milestone 3 integration tests: write pipeline, context, doctor, schema,
//! help --json, and the MCP server. All vaults are synthetic; all data fake.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

const PERSON: &str = "p-01J9Z3K4QF0000000000000000";
const PERSON2: &str = "p-01J9Z3K4QF0000000000000002";
const IXN: &str = "i-01J9Z3K4QF0000000000000003";
const PKG: &str = "pkg-01J9Z3K4QF0000000000000000";

/// A minimal git-backed vault with one person holding a 4-session package.
fn make_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("confidant.toml"),
        // Spec 3 (B10): the plaintext-write fixture declares the opt-out,
        // so the suite keeps exercising the plaintext path.
        "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n\n[crypto]\nmode = \"plaintext\"\n",
    )
    .unwrap();
    let person_dir = root.join(format!("people/{PERSON}"));
    std::fs::create_dir_all(&person_dir).unwrap();
    std::fs::write(
        person_dir.join("profile.md"),
        format!("---\nid: {PERSON}\ntype: person\nname: \"Test Person\"\n---\n\nTest bio.\n"),
    )
    .unwrap();
    let ledger_dir = root.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-01 open {PERSON} package {PKG} 4 sessions\n"),
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    dir
}

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn commits(root: &Path) -> usize {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

fn run_json(args: &[&str]) -> (bool, Value) {
    // Hermetic HOME: Windows CI runners don't set HOME, and doctor's
    // crypto-manifests check errors without a config dir. A fresh tempdir
    // per call is fine — no test here persists anchor state across calls.
    let tmp_home = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(args)
        .env("HOME", tmp_home.path())
        .output()
        .unwrap();
    let v: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => panic!(
            "stdout is not JSON ({e}); status={}; stdout={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    };
    (out.status.success(), v)
}

fn vault_arg(root: &Path) -> String {
    root.display().to_string()
}

/// Run the CLI and return `(success, stdout, stderr)` for human-output tests.
fn run_raw(args: &[&str]) -> (bool, String, String) {
    let tmp_home = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(args)
        .env("HOME", tmp_home.path())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Add a person record to an existing fixture vault and commit it.
fn add_person(root: &Path, id: &str, name: &str, extra: &str) {
    let d = root.join(format!("people/{id}"));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("profile.md"),
        format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n{extra}---\n\nFake bio.\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "add person fixture"]);
}

// ---------------------------------------------------------------------------
// log session
// ---------------------------------------------------------------------------

#[test]
fn log_session_creates_one_commit() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--request-id",
        "01J9Z3K4QF0000000000000001",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "log-session");
    assert!(v["commit"].as_str().unwrap().len() >= 8);
    assert_eq!(v["files"], serde_json::json!(["ledger/2026/10.cfd"]));
    assert_eq!(commits(root), 2, "exactly one new commit");

    let ledger = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert!(
        ledger.contains(&format!("session {PERSON} 60m paid")),
        "{ledger}"
    );

    // Commit message carries IDs and verbs only — no free text.
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%B"])
        .output()
        .unwrap();
    let msg = String::from_utf8_lossy(&out.stdout);
    assert!(msg.contains(&format!("session {PERSON} 60m paid")));
    assert!(msg.contains("Request-Id-Hash:"));
    assert!(msg.contains("Request-Hash:"));
}

#[test]
fn log_session_dry_run_touches_nothing() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let before = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--dry-run",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["commit"], Value::Null);
    assert_eq!(commits(root), 1, "no commit on dry run");
    let after = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert_eq!(before, after, "no file change on dry run");
    // The logical change is shown, never ciphertext.
    let content = v["changes"][0]["content"].as_str().unwrap();
    assert!(content.contains(&format!("session {PERSON} 60m paid")));
}

#[test]
fn log_session_with_note_creates_note_record() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--note",
        "Great session",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["files"].as_array().unwrap().len(), 2);

    let ledger = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    let line = ledger.lines().last().unwrap();
    assert!(line.contains("note:n-"), "{line}");

    let note_id = line
        .split("note:")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let note_path = root.join(format!("people/{PERSON}/notes/{note_id}.md"));
    let body = std::fs::read_to_string(&note_path).unwrap();
    assert!(body.contains("Great session"), "{body}");
}

#[test]
fn request_id_is_idempotent_then_conflicts() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let base = [
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--request-id",
        "01J9Z3K4QF00000000000000ID",
    ];
    let (ok1, v1) = run_json(&base);
    assert!(ok1, "{v1}");
    let (ok2, v2) = run_json(&base);
    assert!(ok2, "{v2}");
    assert_eq!(v2["idempotent"], true);
    assert_eq!(v2["commit"], v1["commit"]);
    assert_eq!(commits(root), 2, "retry committed nothing new");

    // Same id, different content -> E_IDEMPOTENCY_CONFLICT.
    let (ok3, v3) = run_json(&[
        "log",
        "session",
        PERSON,
        "90m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--request-id",
        "01J9Z3K4QF00000000000000ID",
    ]);
    assert!(!ok3);
    assert_eq!(v3["ok"], false);
    assert_eq!(v3["error"]["code"], "E_IDEMPOTENCY_CONFLICT");
    assert!(v3["error"]["fix"]
        .as_str()
        .unwrap()
        .contains("fresh --request-id"));
    assert_eq!(commits(root), 2, "conflict committed nothing");
}

#[test]
fn request_id_rejects_low_entropy_ids() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    // 17 chars: under the unguessability floor.
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--request-id",
        "run-7f3a-guessable",
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "usage_error");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unguessable"));
    // Exactly 22 chars clears the floor.
    let (ok, _) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--dry-run",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--request-id",
        "01J9Z3K4QF00000000000002",
    ]);
    assert!(ok);
}

#[test]
fn failing_check_blocks_write_and_rolls_back() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Break the vault directly: a session line with a bad id.
    std::fs::write(
        root.join("ledger/2026/10.cfd"),
        "2026-10-01 open x package y 4 sessions\n",
    )
    .unwrap();
    let ledger_before = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();

    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    assert_eq!(v["ok"], false, "check report, not an error envelope");
    assert!(v["summary"]["errors"].as_u64().unwrap() > 0);
    assert_eq!(commits(root), 1, "nothing committed");

    // The pre-check fails fast, so the file is untouched.
    let ledger_after = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert_eq!(ledger_before, ledger_after);
}

#[test]
fn write_to_non_git_vault_fails() {
    let dir = make_vault();
    // Remove the .git directory: writes need git.
    std::fs::remove_dir_all(dir.path().join(".git")).unwrap();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    assert_eq!(v["ok"], false);
    assert!(v["error"]["message"].as_str().unwrap().contains("git"));
}

#[test]
fn conflict_markers_block_write() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    std::fs::write(
        root.join("ledger/2026/10.cfd"),
        format!("2026-10-01 open {PERSON} package {PKG} 4 sessions\n<<<<<<< HEAD\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "conflicted"]);
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    // Fail-closed: the pre-check flags E_MERGE_CONFLICT and blocks the write.
    assert_eq!(v["ok"], false);
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"E_MERGE_CONFLICT"), "{codes:?}");
    assert_eq!(commits(root), 2, "nothing committed");
}

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

#[test]
fn import_appends_validated_lines() {
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let file = scratch.path().join("import.cfd");
    std::fs::write(
        &file,
        format!("2026-10-03 session {PERSON} 45m pps\n; a comment\n\n2026-11-01 session {PERSON} 30m comp\n"),
    )
    .unwrap();
    let (ok, v) = run_json(&[
        "import",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "import");
    // Lines land in the monthly file matching their date.
    let oct = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    let nov = std::fs::read_to_string(root.join("ledger/2026/11.cfd")).unwrap();
    assert!(oct.contains("45m pps"));
    assert!(nov.contains("30m comp"));
    assert_eq!(commits(root), 2);
}

#[test]
fn import_rejects_bad_line_before_touching_vault() {
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let file = scratch.path().join("bad.cfd");
    std::fs::write(&file, "not a ledger line\n").unwrap();
    let (ok, v) = run_json(&[
        "import",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    assert_eq!(v["error"]["code"], "E_INVALID");
    assert_eq!(commits(root), 1);
}

// ---------------------------------------------------------------------------
// note add
// ---------------------------------------------------------------------------

#[test]
fn note_add_creates_note() {
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "Follow up on the launch.\n").unwrap();
    let (ok, v) = run_json(&[
        "note",
        "add",
        "--person",
        PERSON,
        "--body-file",
        &body.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "note-add");
    let id = v["id"].as_str().unwrap();
    assert!(id.starts_with("n-"));
    let path = root.join(v["path"].as_str().unwrap());
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("Follow up on the launch."));
    assert_eq!(commits(root), 2);
}

// ---------------------------------------------------------------------------
// #557: `note show --for-edit` / `note edit`
// ---------------------------------------------------------------------------

/// Add a note to the plaintext fixture and return its id and absolute path.
fn add_note(root: &Path, vroot: &str, body: &str) -> (String, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("body.md");
    std::fs::write(&file, body).unwrap();
    let (ok, v) = run_json(&[
        "note",
        "add",
        "--person",
        PERSON,
        "--body-file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        vroot,
    ]);
    assert!(ok, "note add failed: {v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let path = root.join(v["path"].as_str().unwrap());
    (id, path)
}

/// Rewrite a note's plaintext body into a temp file (the canonical front
/// matter stays as written, so an unchanged body reports `unchanged`).
fn edited_note_file(dir: &Path, original: &str, from: &str, to: &str) -> PathBuf {
    let file = dir.join("edited.md");
    std::fs::write(&file, original.replace(from, to)).unwrap();
    file
}

#[test]
fn note_show_requires_the_for_edit_flag() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (id, _) = add_note(root, &vroot, "Body.\n");
    let (ok, v) = run_json(&[
        "note",
        "show",
        &id,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "usage_error", "{v}");
}

#[test]
fn note_show_for_edit_returns_the_text_and_json_shape() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (id, path) = add_note(root, &vroot, "First body.\n");

    let (ok, v) = run_json(&[
        "note",
        "show",
        &id,
        "--for-edit",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["id"], id, "{v}");
    assert_eq!(v["type"], "note", "{v}");
    assert_eq!(v["for_edit"], true, "{v}");
    assert_eq!(v["no_ai"], false, "{v}");
    assert_eq!(v["path"], format!("people/{PERSON}/notes/{id}.md"), "{v}");
    assert!(v["text"].as_str().unwrap().contains("First body."));

    // Human output is byte-for-byte the record text on stdout.
    let out = std::process::Command::new(bin())
        .args(["note", "show", &id, "--for-edit", "--vault", &vroot])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        std::fs::read_to_string(&path).unwrap()
    );
}

#[test]
fn note_show_rejects_a_non_note_id() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "note",
        "show",
        PERSON,
        "--for-edit",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "usage_error", "{v}");
}

#[test]
fn note_edit_round_trips_in_one_commit() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let (id, path) = add_note(root, &vroot, "First body.\n");
    let before = commits(root);

    let original = std::fs::read_to_string(&path).unwrap();
    let edited = edited_note_file(scratch.path(), &original, "First body.", "Second body.");
    let (ok, v) = run_json(&[
        "note",
        "edit",
        &id,
        "--file",
        edited.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "note-edit", "{v}");
    assert_eq!(v["id"], id, "{v}");
    assert_eq!(v["path"], format!("people/{PERSON}/notes/{id}.md"), "{v}");
    assert!(
        !v.to_string().contains("Second body."),
        "the note body leaked into --json: {v}"
    );
    assert_eq!(commits(root), before + 1, "expected exactly one commit");

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("Second body."), "{on_disk}");
    assert!(!on_disk.contains("First body."), "{on_disk}");

    // The operator read hands the new body back, ready to edit again.
    let (ok, v) = run_json(&[
        "note",
        "show",
        &id,
        "--for-edit",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert!(v["text"].as_str().unwrap().contains("Second body."), "{v}");
}

#[test]
fn note_edit_with_identical_content_is_a_no_op() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (id, path) = add_note(root, &vroot, "Body.\n");
    let original = std::fs::read_to_string(&path).unwrap();
    let before = commits(root);

    // The note file already holds the canonical form: writing it back is a
    // no-op and must commit nothing.
    let scratch = tempfile::tempdir().unwrap();
    let same = scratch.path().join("same.md");
    std::fs::write(&same, &original).unwrap();
    let (ok, v) = run_json(&[
        "note",
        "edit",
        &id,
        "--file",
        same.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["unchanged"], true, "{v}");
    assert!(
        v.get("commit").is_none(),
        "no-op edit reported a commit: {v}"
    );
    assert_eq!(commits(root), before, "a no-op edit committed");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn note_edit_check_failure_rolls_back_and_commits_nothing() {
    // The edited note still parses, so this exercises the post-write check
    // rollback rather than the parser: `check` gates a note edit like any
    // other write.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let (id, path) = add_note(root, &vroot, "Body.\n");
    let original = std::fs::read_to_string(&path).unwrap();
    let before = commits(root);

    // A dangling `org:` reference is a check error (E_DANGLING_REF) that
    // only appears after the write.
    let bad_text = original.replace(
        "type: note\n",
        "type: note\norg: o-01J9Z3K4QG0000000000000000\n",
    );
    let bad = scratch.path().join("bad.md");
    std::fs::write(&bad, &bad_text).unwrap();
    let (ok, v) = run_json(&[
        "note",
        "edit",
        &id,
        "--file",
        bad.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .expect("check report")
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"E_DANGLING_REF"), "{codes:?}");
    assert_eq!(commits(root), before, "nothing committed");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        original,
        "the note was not rolled back"
    );
}

#[test]
fn note_edit_refuses_a_person_that_does_not_match_the_path() {
    // A person change would re-route the note to another client key and,
    // in an encrypted vault, is invisible to the post-write check. Refuse
    // before encrypting.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let (id, path) = add_note(root, &vroot, "Body.\n");
    let original = std::fs::read_to_string(&path).unwrap();
    let before = commits(root);

    let moved = original.replace(PERSON, PERSON2);
    let file = scratch.path().join("moved.md");
    std::fs::write(&file, &moved).unwrap();
    let (ok, v) = run_json(&[
        "note",
        "edit",
        &id,
        "--file",
        file.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot move"),
        "{v}"
    );
    assert_eq!(commits(root), before, "nothing committed");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

// ---------------------------------------------------------------------------
// record add
// ---------------------------------------------------------------------------

#[test]
fn record_add_creates_person_profile() {
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let file = scratch.path().join("person.md");
    std::fs::write(
        &file,
        "---\nid: p-01J9Z3K4QF0000000000000001\ntype: person\nname: \"Ada Example\"\n---\n\nBio.\n",
    )
    .unwrap();
    let (ok, v) = run_json(&[
        "record",
        "add",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "record-add");
    let path = root.join(v["path"].as_str().unwrap());
    assert!(path.is_file());
    assert_eq!(commits(root), 2);
}

#[test]
fn record_add_deal_and_dry_run() {
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let file = scratch.path().join("deal.md");
    std::fs::write(
        &file,
        "---\nid: d-01J9Z3K4QF0000000000000002\ntype: deal\nname: \"Example deal\"\nperson: p-01J9Z3K4QF0000000000000000\n---\n\nTerms.\n",
    )
    .unwrap();
    let rid = "01J9Z3K4QF0000000000000099";
    let (ok, v) = run_json(&[
        "record",
        "add",
        "--file",
        &file.display().to_string(),
        "--dry-run",
        "--request-id",
        rid,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "record-add");
    assert_eq!(v["dry_run"], true);
    assert!(!root
        .join("deals/d-01J9Z3K4QF0000000000000002/deal.md")
        .exists());
    assert_eq!(commits(root), 1);
}

/// `record add` a plaintext person profile, so a `with:` reference exists
/// (`check` verifies `with:` entries at write time).
fn add_person_record(vroot: &str, id: &str, name: &str) {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("person.md");
    std::fs::write(
        &file,
        format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\nBio.\n"),
    )
    .unwrap();
    let (ok, v) = run_json(&[
        "record",
        "add",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        vroot,
    ]);
    assert!(ok, "{v}");
}

/// `record add` an interaction record from markdown text.
fn add_interaction(vroot: &str, text: &str) -> (bool, Value) {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("interaction.md");
    std::fs::write(&file, text).unwrap();
    run_json(&[
        "record",
        "add",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        vroot,
    ])
}

/// The vault's `touch` ledger lines, whole lines (`ledger/2026/10.cfd`), so a
/// test can pin exactly what the mirrored touchpoints are.
fn touch_ledger_lines(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("ledger/2026/10.cfd"))
        .unwrap()
        .lines()
        .filter(|line| line.contains(" touch "))
        .map(str::to_owned)
        .collect()
}

/// #505: a primary-only interaction mirrors one `touch` for its `person:`,
/// in the same commit as the record.
#[test]
fn record_add_primary_only_mirrors_one_touch() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let before = commits(root);
    let (ok, v) = add_interaction(
        &vroot,
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: Lunch\ndate: 2026-10-06\nperson: {PERSON}\n---\n\nFake lunch.\n"
        ),
    );
    assert!(ok, "{v}");
    assert_eq!(
        v["touchpoints"],
        serde_json::json!([format!("2026-10-06 touch {PERSON}")]),
        "{v}"
    );
    assert_eq!(
        commits(root),
        before + 1,
        "record and touch line: one commit"
    );
    // Whole lines: exactly one touchpoint, and no other id or argument on it.
    assert_eq!(
        touch_ledger_lines(root),
        vec![format!("2026-10-06 touch {PERSON}")]
    );
}

/// #505: a multi-person interaction mirrors the primary plus every `with:`
/// participant, exactly once each.
#[test]
fn record_add_primary_and_participants_mirror_each_once() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    add_person_record(&vroot, PERSON2, "Bea Demo");
    let (ok, v) = add_interaction(
        &vroot,
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: Dinner\ndate: 2026-10-06\nperson: {PERSON}\nwith: [{PERSON2}]\n---\n\nFake dinner.\n"
        ),
    );
    assert!(ok, "{v}");
    assert_eq!(
        v["touchpoints"],
        serde_json::json!([
            format!("2026-10-06 touch {PERSON}"),
            format!("2026-10-06 touch {PERSON2}")
        ]),
        "{v}"
    );
    // Whole lines: the primary and the participant, exactly once each, with
    // no other id or argument on either line.
    assert_eq!(
        touch_ledger_lines(root),
        vec![
            format!("2026-10-06 touch {PERSON}"),
            format!("2026-10-06 touch {PERSON2}"),
        ]
    );
}

/// #505: logging an interaction clears a `cadence-overdue` warning — the
/// mirrored primary touch line is what the ledger-only rule sees.
#[test]
fn cadence_overdue_clears_after_interaction_logged() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Pin `as_of` and enable the personal pack, then give the person a
    // cadence with no contact on record.
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"coaching@0.1\", \"personal@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n\n[checks]\nas_of = \"2026-10-08\"\n\n[crypto]\nmode = \"plaintext\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join(format!("people/{PERSON}/profile.md")),
        format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Test Person\"\ncadence: 30d\n---\n\nTest bio.\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "personal cadence"]);

    let (_, before) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(
        finding_codes(&before).contains(&"W_CADENCE_OVERDUE".to_owned()),
        "the warning must fire before contact: {before}"
    );

    let (ok, added) = add_interaction(
        &vroot,
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: Coffee\ndate: 2026-10-06\nperson: {PERSON}\n---\n\nFake coffee.\n"
        ),
    );
    assert!(ok, "{added}");

    let (ok, after) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{after}");
    assert!(
        !finding_codes(&after).contains(&"W_CADENCE_OVERDUE".to_owned()),
        "the mirrored primary touch must clear the warning: {after}"
    );
}

#[test]
fn write_commit_includes_agent_trailer_when_set() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "Agent note.\n").unwrap();
    let agent = "agent-01J9Z3K4QF0000000000000999";
    let out = Command::new(bin())
        .env("CONFIDANT_AGENT_ID", agent)
        .args([
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            &body.display().to_string(),
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let log = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%B"])
        .output()
        .unwrap();
    let msg = String::from_utf8_lossy(&log.stdout);
    assert!(msg.contains(&format!("Agent: {agent}")));
}

// ---------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------

#[test]
fn context_bundle_has_coaching_facts() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["id"], PERSON);
    assert_eq!(v["person"]["name"], "Test Person");
    assert_eq!(v["person"]["no_ai"], false);
    assert!(v["person"]["profile"]
        .as_str()
        .unwrap()
        .contains("Test bio"));
    assert_eq!(v["coaching"]["sessions_remaining"], 4);
    // #177: pack state is grouped by pack; `coaching` duplicates the entry.
    assert_eq!(v["packs"]["coaching@0.1"]["sessions_remaining"], 4);
}

#[test]
fn context_honors_no_ai() {
    // The demo vault ships a fake no-ai person.
    let no_ai = "p-01M3TC5H00MPJG001248000002";
    let demo_str = demo().display().to_string();
    let (ok, v) = run_json(&[
        "context",
        no_ai,
        "--json",
        "--no-input",
        "--vault",
        &demo_str,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["no_ai"], true);
    assert_eq!(v["person"]["name"], Value::Null);
    assert_eq!(v["person"]["profile"], Value::Null);
    for note in v["notes"].as_array().unwrap() {
        assert_eq!(note["body"], Value::Null);
    }
    // Ledger facts are metadata, not content: still present.
    assert!(v["coaching"]["sessions_remaining"].is_number());
}

#[test]
fn context_exclude_private_strips_pii() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&[
        "context",
        PERSON,
        "--exclude-private",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["no_ai"], false);
    assert_eq!(v["person"]["name"], Value::Null);
    assert_eq!(v["person"]["profile"], Value::Null);
}

/// #510: end-to-end `--exclude-private` over the personal pack's view: every
/// PII field the core list names is stripped, the cadence state stays.
#[test]
fn context_exclude_private_strips_personal_pii_fields() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);
    std::fs::write(
        root.join(format!("people/{PERSON}/profile.md")),
        format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Test Person\"\n\
             birthday: --05-14\nrelationship_to_me: friend\n\
             dates: [anniversary:2020-06-15]\ncadence: 30d\n---\n\nTest bio.\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "personal fields"]);

    let (ok, full) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{full}");
    let view = &full["packs"]["personal@0.1"];
    assert_eq!(view["birthday"], "--05-14", "{full}");
    assert_eq!(view["relationship_to_me"], "friend", "{full}");
    assert_eq!(view["dates"][0]["label"], "anniversary", "{full}");
    assert_eq!(view["cadence_days"], 30, "{full}");

    let (ok, stripped) = run_json(&[
        "context",
        PERSON,
        "--exclude-private",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{stripped}");
    let view = &stripped["packs"]["personal@0.1"];
    for field in ["birthday", "relationship_to_me", "dates"] {
        assert!(view.get(field).is_none(), "{field} leaked: {stripped}");
    }
    assert_eq!(view["cadence_days"], 30, "{stripped}");
}

#[test]
fn context_unknown_person_is_not_found() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&[
        "context",
        "p-01J9Z3K4QF9999999999999999",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
}

#[test]
fn context_non_person_id_is_not_found() {
    let dir = make_vault();
    let root = dir.path();
    // Create an org record; context only serves people.
    let org_dir = root.join("orgs/o-01J9Z3K4QF0000000000000000");
    std::fs::create_dir_all(&org_dir).unwrap();
    std::fs::write(
        org_dir.join("profile.md"),
        "---\nid: o-01J9Z3K4QF0000000000000000\ntype: org\nname: \"Acme\"\n---\n",
    )
    .unwrap();
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["add", "-A"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "context",
        "o-01J9Z3K4QF0000000000000000",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
}

#[test]
fn context_omits_no_ai_notes() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // A no-ai note via --no-ai must not appear in the bundle at all.
    let scratch = tempfile::tempdir().unwrap();
    let body = scratch.path().join("secret.md");
    std::fs::write(&body, "sensitive").unwrap();
    let (ok, _) = run_json(&[
        "note",
        "add",
        "--person",
        PERSON,
        "--body-file",
        &body.display().to_string(),
        "--no-ai",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok);
    let (ok, v) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["notes"], serde_json::json!([]));
}

#[test]
fn context_withholds_pii_for_merged_away_person() {
    // P_old merges into P_new, which is no-ai. `context P_old` must not leak
    // P_new's records: the merge group is not cleared, so no PII is shown and
    // uncleared notes/interactions are omitted entirely (§12).
    let dir = make_vault();
    let root = dir.path();
    let old = "p-01J9Z3K4QF0000000000000001";
    let new = "p-01J9Z3K4QF0000000000000002";
    for (id, no_ai) in [(old, false), (new, true)] {
        let d = root.join(format!("people/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!(
                "---\nid: {id}\ntype: person\nname: \"Person\"\n{}\n---\n\nBio.\n",
                if no_ai { "no-ai: true" } else { "" }
            ),
        )
        .unwrap();
    }
    // A note under P_old's dir with no own no-ai flag.
    let note_id = "n-01J9Z3K4QF0000000000000003";
    let note_dir = root.join(format!("people/{old}/notes"));
    std::fs::create_dir_all(&note_dir).unwrap();
    std::fs::write(
        note_dir.join(format!("{note_id}.md")),
        format!("---\nid: {note_id}\ntype: note\nperson: {old}\ndate: 2026-10-02\n---\n\nLeakable note body.\n"),
    )
    .unwrap();
    // An interaction on P_new (the canonical target) with no own no-ai flag.
    let iid = "i-01J9Z3K4QF0000000000000004";
    let i_dir = root.join(format!("interactions/{iid}"));
    std::fs::create_dir_all(&i_dir).unwrap();
    std::fs::write(
        i_dir.join("interaction.md"),
        format!("---\nid: {iid}\ntype: interaction\nname: Intro\nperson: {new}\ndate: 2026-10-03\n---\n\nLeakable interaction body.\n"),
    )
    .unwrap();
    let ledger = root.join("ledger/2026/10.cfd");
    std::fs::write(
        &ledger,
        std::fs::read_to_string(&ledger).unwrap() + &format!("2026-10-09 merge {old} into {new}\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "merge fixture"]);

    let vroot = vault_arg(root);
    let (ok, v) = run_json(&["context", old, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["name"], Value::Null);
    assert_eq!(v["person"]["profile"], Value::Null);
    assert_eq!(v["notes"], serde_json::json!([]));
    assert_eq!(v["interactions"], serde_json::json!([]));
}

#[test]
fn context_withholds_pii_for_duplicate_id_person() {
    // Two record directories declaring the same front-matter id: the id is
    // tainted (E_DUPLICATE_ID), so the §12 cleared set excludes it and no
    // PII shows.
    let dir = make_vault();
    let root = dir.path();
    let dup = "p-01J9Z3K4QF0000000000000005";
    let other = "p-01J9Z3K4QF0000000000000008";
    for person_dir in [dup, other] {
        let d = root.join(format!("people/{person_dir}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {dup}\ntype: person\nname: \"Dup Person\"\n---\n\nBio.\n"),
        )
        .unwrap();
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "duplicate-id fixture"]);

    let vroot = vault_arg(root);
    let (ok, v) = run_json(&["context", dup, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["name"], Value::Null);
    assert_eq!(v["person"]["profile"], Value::Null);
}

#[test]
fn context_omits_interaction_referencing_no_ai_person() {
    // An interaction whose front matter names a no-ai person is outside the
    // cleared set: it must be omitted entirely, not returned with null bodies.
    let dir = make_vault();
    let root = dir.path();
    let nai = "p-01J9Z3K4QF0000000000000006";
    let d = root.join(format!("people/{nai}"));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("profile.md"),
        format!("---\nid: {nai}\ntype: person\nname: \"No Ai\"\nno-ai: true\n---\n\nBio.\n"),
    )
    .unwrap();
    let iid = "i-01J9Z3K4QF0000000000000007";
    let i_dir = root.join(format!("interactions/{iid}"));
    std::fs::create_dir_all(&i_dir).unwrap();
    std::fs::write(
        i_dir.join("interaction.md"),
        format!("---\nid: {iid}\ntype: interaction\nname: Call\nperson: {nai}\ndate: 2026-10-04\n---\n\nShould never surface.\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "no-ai interaction fixture"]);

    let vroot = vault_arg(root);
    let (ok, v) = run_json(&["context", nai, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["interactions"], serde_json::json!([]));
}

// ---------------------------------------------------------------------------
// resolve / display-name person arguments (#537 phase 3a)
// ---------------------------------------------------------------------------

#[test]
fn resolve_by_name_and_by_id_json_shape() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&[
        "resolve",
        "Test Person",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "resolve");
    assert_eq!(v["query"], "Test Person");
    assert_eq!(v["matched_by"], "name");
    assert_eq!(v["person"]["id"], PERSON);
    assert_eq!(v["person"]["name"], "Test Person");
    assert_eq!(v["person"]["no_ai"], false);
    assert!(v["vault"].is_string());

    let (ok, v) = run_json(&["resolve", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["matched_by"], "id");
    assert_eq!(v["person"]["id"], PERSON);
}

#[test]
fn resolve_name_is_trimmed_and_case_insensitive() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&[
        "resolve",
        "  test PERSON  ",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["id"], PERSON);
    assert_eq!(v["matched_by"], "name");
}

#[test]
fn resolve_rejects_substring_and_prefix() {
    // The exact-match rule only; `find` stays the fuzzy path.
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&["resolve", "Test", "--json", "--no-input", "--vault", &vroot]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
}

#[test]
fn resolve_ambiguous_name_fails_closed_with_candidate_ids() {
    let dir = make_vault();
    let root = dir.path();
    add_person(root, PERSON2, "Test Person", "");
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "resolve",
        "Test Person",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_AMBIGUOUS_PERSON");
    let msg = v["error"]["message"].as_str().unwrap();
    // The candidate list is opaque ids, so the pick can be disambiguated.
    assert!(msg.contains(PERSON), "{msg}");
    assert!(msg.contains(PERSON2), "{msg}");
    assert!(v["error"]["fix"].as_str().unwrap().contains("p-<ULID>"));
}

#[test]
fn resolve_no_ai_true_is_not_name_resolvable_and_leaks_nothing() {
    let dir = make_vault();
    let root = dir.path();
    let hidden = "p-01J9Z3K4QF0000000000000009";
    add_person(root, hidden, "Hidden Person", "no-ai: true\n");
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "resolve",
        "Hidden Person",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
    let fix = v["error"]["fix"].as_str().unwrap();
    // Generic hint only: it must not confirm the hidden person exists.
    assert!(fix.contains("no-ai: true"), "{fix}");
    assert!(fix.contains("p-<ULID>"), "{fix}");
    assert!(!fix.contains(hidden), "{fix}");
    assert!(!v["error"]["message"].as_str().unwrap().contains(hidden));

    // Indistinguishable from a name that matches nobody at all.
    let (ok2, v2) = run_json(&[
        "resolve",
        "Nobody At All",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok2);
    assert_eq!(v2["error"]["fix"], v["error"]["fix"]);

    // The id still resolves: writes by `p-<ULID>` keep working, including
    // for a no-ai person.
    let (ok3, v3) = run_json(&["resolve", hidden, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok3, "{v3}");
    assert_eq!(v3["matched_by"], "id");
    assert_eq!(v3["person"]["id"], hidden);
    assert_eq!(v3["person"]["no_ai"], true);
    // Rule 3: resolving an id must not leak the no-ai person's name.
    assert_eq!(v3["person"]["name"], Value::Null, "{v3}");
}

#[test]
fn resolve_cleared_name_merged_into_no_ai_person_leaks_nothing() {
    // A cleared person ("Ada Old") merged into a `no-ai: true` person: the
    // cleared name canonicalizes to the hidden id. It must not resolve, or
    // `log session` / `log touch` / `note add` would print and serialize
    // the hidden person's name. The by-name query gets the same generic
    // not-found as a miss, in human and `--json` output, and writes nothing.
    let dir = make_vault();
    let root = dir.path();
    let old = "p-01J9Z3K4QF000000000000000B";
    let hidden = "p-01J9Z3K4QF000000000000000C";
    add_person(root, old, "Ada Old", "");
    add_person(root, hidden, "Hidden Canonical", "no-ai: true\n");
    let ledger = root.join("ledger/2026/10.cfd");
    std::fs::write(
        &ledger,
        std::fs::read_to_string(&ledger).unwrap()
            + &format!("2026-10-09 merge {old} into {hidden}\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "merge into hidden fixture"]);
    let before = std::fs::read_to_string(&ledger).unwrap();
    let vroot = vault_arg(root);

    // `resolve` by the cleared name: generic E_NOT_FOUND, indistinguishable
    // (same fix) from a name that matches nobody.
    let (ok, v) = run_json(&[
        "resolve",
        "Ada Old",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
    let (ok_miss, v_miss) = run_json(&[
        "resolve",
        "Nobody Here",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok_miss);
    assert_eq!(v["error"]["code"], v_miss["error"]["code"]);
    assert_eq!(v["error"]["fix"], v_miss["error"]["fix"]);
    assert!(!v.to_string().contains("Hidden Canonical"), "{v}");

    // The by-name write fails the same way and writes nothing.
    let (ok_w, v_w) = run_json(&[
        "log",
        "session",
        "Ada Old",
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok_w, "{v_w}");
    assert_eq!(v_w["error"]["code"], "E_NOT_FOUND");
    assert!(!v_w.to_string().contains("Hidden Canonical"), "{v_w}");
    assert!(!v_w.to_string().contains(hidden), "{v_w}");

    // Human output carries no resolved-person line and no hidden name.
    let (ok_h, stdout, stderr) = run_raw(&[
        "log",
        "session",
        "Ada Old",
        "60m",
        "paid",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok_h, "stdout={stdout} stderr={stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains("Hidden Canonical"), "{combined}");
    assert!(!combined.contains(hidden), "{combined}");
    assert!(!combined.contains("resolving to"), "{combined}");

    // No ledger write happened.
    assert_eq!(before, std::fs::read_to_string(&ledger).unwrap());
}

#[test]
fn resolve_no_ai_notes_person_resolves_by_name() {
    let dir = make_vault();
    let root = dir.path();
    let notes = "p-01J9Z3K4QF000000000000000A";
    add_person(root, notes, "Notes Person", "no-ai: notes\n");
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "resolve",
        "Notes Person",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["id"], notes);
    assert_eq!(v["matched_by"], "name");
}

#[test]
fn resolve_merged_away_name_resolves_to_canonical() {
    let dir = make_vault();
    let root = dir.path();
    let old = "p-01J9Z3K4QF0000000000000003";
    add_person(root, old, "Old Name", "");
    let ledger = root.join("ledger/2026/10.cfd");
    std::fs::write(
        &ledger,
        std::fs::read_to_string(&ledger).unwrap()
            + &format!("2026-10-09 merge {old} into {PERSON}\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "merge fixture"]);
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "resolve",
        "Old Name",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["id"], PERSON);
    assert_eq!(v["matched_by"], "name");
}

#[test]
fn log_session_by_name_echoes_resolved_person() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "session",
        "Test Person",
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    // Refinement B: the resolved id and name are visible in JSON.
    assert_eq!(v["person"]["id"], PERSON);
    assert_eq!(v["person"]["name"], "Test Person");
    // The ledger line carries the id, never the display name.
    let ledger = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert!(
        ledger.contains(&format!("session {PERSON} 60m paid")),
        "{ledger}"
    );

    // Human output echoes the pick too. It says "resolving to" because the
    // line prints before the remaining validation (#537 review).
    let (ok, stdout, stderr) = run_raw(&[
        "log",
        "session",
        "Test Person",
        "60m",
        "paid",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains(&format!("resolving to {PERSON} (Test Person)")),
        "{stdout}"
    );
}

#[test]
fn log_session_by_id_does_not_echo_a_person_object() {
    // Id writes keep their previous output shape (no `person` echo).
    let dir = make_vault();
    let root = dir.path();
    let before = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert!(v.get("person").is_none(), "{v}");
    let after = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert!(after.starts_with(&before));
    assert!(after.contains(&format!("session {PERSON} 60m paid")));
}

#[test]
fn context_and_note_add_accept_display_name() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "context",
        "Test Person",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["id"], PERSON);
    assert_eq!(v["person"]["name"], "Test Person");

    let scratch = tempfile::tempdir().unwrap();
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "note body").unwrap();
    let (ok, v) = run_json(&[
        "note",
        "add",
        "--person",
        "Test Person",
        "--body-file",
        body.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["id"], PERSON);
    assert!(
        v["path"].as_str().unwrap().contains(PERSON),
        "note not written under the resolved id: {v}"
    );
}

#[test]
fn note_add_by_unknown_name_is_not_found() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "note body").unwrap();
    let (ok, v) = run_json(&[
        "note",
        "add",
        "--person",
        "Nobody Here",
        "--body-file",
        body.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
    assert_eq!(commits(root), 1, "a failed resolve writes nothing");
}

// ---------------------------------------------------------------------------
// doctor / schema / help
// ---------------------------------------------------------------------------

#[test]
fn doctor_reports_expected_checks() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&["doctor", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["ok"], true);
    let ids: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for expected in [
        "git-repo",
        "git-identity",
        "git-version",
        "spec",
        "check",
        "crypto",
    ] {
        assert!(ids.contains(&expected), "missing check {expected}");
    }
    let crypto = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "crypto")
        .unwrap();
    // Spec 3: the CLI write path encrypts by default; this fixture vault
    // opts out via [crypto] mode = "plaintext", so doctor reports ok and
    // names the opt-out.
    assert_eq!(crypto["status"], "ok");
    assert!(crypto["message"].as_str().unwrap().contains("opts out"));
    // The record-encryption mix check is present (code + count only).
    let mix = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "record-encryption-mix")
        .expect("record-encryption-mix check missing");
    assert_eq!(mix["status"], "ok");
}

#[test]
fn doctor_flags_corrupt_manifest_not_absent() {
    // #73: a corrupt recipients.toml must surface as an error, distinct
    // from "no manifest".
    let dir = make_vault();
    let root = dir.path();
    let mdir = root.join("keys/p-01J9Z3K4QF0000000000000006");
    std::fs::create_dir_all(&mdir).unwrap();
    std::fs::write(mdir.join("recipients.toml"), b"this is not toml {{{").unwrap();

    let vroot = vault_arg(root);
    let (ok, v) = run_json(&["doctor", "--json", "--no-input", "--vault", &vroot]);
    assert!(!ok, "{v}");
    let check = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "crypto-manifests")
        .expect("missing crypto-manifests check");
    assert_eq!(check["status"], "error");
    let msg = check["message"].as_str().unwrap();
    assert!(msg.contains("corrupt"), "{msg}");
    assert!(msg.contains("p-01J9Z3K4QF0000000000000006"), "{msg}");
}

#[test]
fn doctor_manifest_check_ok_when_no_keys_dir() {
    // No keys/ tree at all: nothing to diagnose, check stays quiet.
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&["doctor", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert!(
        !v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "crypto-manifests"),
        "{v}"
    );
}

#[test]
fn context_json_includes_vault() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    // The CLI reports the canonicalized vault path (on Windows that's the
    // \\?\ extended form), so canonicalize the expectation too.
    let expected = dir.path().canonicalize().unwrap();
    assert!(v["vault"]
        .as_str()
        .unwrap()
        .contains(expected.to_str().unwrap()));
}

#[test]
fn doctor_json_includes_vault() {
    let dir = make_vault();
    let (ok, v) = run_json(&[
        "doctor",
        "--json",
        "--no-input",
        "--vault",
        &vault_arg(dir.path()),
    ]);
    assert!(ok, "{v}");
    // Canonicalized on both sides (see context_json_includes_vault).
    let expected = dir.path().canonicalize().unwrap();
    assert!(v["vault"]
        .as_str()
        .unwrap()
        .contains(expected.to_str().unwrap()));
}

#[test]
fn usage_error_envelope_matches_contract() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let out = Command::new(bin())
        .args([
            "context",
            PERSON,
            "--packs",
            "nosuchpack@9.9",
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["schema_version"], "1");
    assert!(v["vault"].is_string());
    assert_eq!(v["error"]["code"], "usage_error");
    assert!(v["error"]["message"].is_string());
}

#[test]
fn find_json_survives_closed_pipe() {
    let dir = make_vault();
    let mut child = Command::new(bin())
        .args(["find", "Test", "--json", "--vault"])
        .arg(dir.path())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = [0u8; 1];
    let _ = std::io::Read::read(&mut stdout, &mut buf);
    let status = child.wait().unwrap();
    assert_ne!(status.code(), Some(101), "EPIPE must not panic the CLI");
}

#[test]
fn schema_is_valid_json_schema() {
    let (ok, v) = run_json(&["schema", "--json", "--vault", &vault_arg(&demo())]);
    assert!(ok, "{v}");
    let contract = &v["contract"];
    assert_eq!(contract["properties"]["schema_version"]["const"], "1");
    for shape in [
        "error", "check", "find", "write", "context", "doctor", "help",
    ] {
        assert!(
            contract["properties"]["shapes"]["properties"][shape].is_object(),
            "shape {shape} missing"
        );
    }
}

#[test]
fn help_json_lists_every_subcommand() {
    let (ok, v) = run_json(&["help", "--json"]);
    assert!(ok, "{v}");
    let names: Vec<&str> = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for expected in [
        "check", "find", "resolve", "log", "import", "note", "context", "doctor", "schema", "help",
        "mcp",
    ] {
        assert!(names.contains(&expected), "missing subcommand {expected}");
    }
    // Nested subcommands are visible too (ADR-7 `log session` form).
    let log = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "log")
        .unwrap();
    assert!(log["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "session"));
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

fn mcp_exchange(root: &Path, messages: &[&str]) -> Vec<Value> {
    use std::io::Write;
    let mut child = Command::new(bin())
        .args(["mcp", "--vault"])
        .arg(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for m in messages {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn mcp_initialize_and_list() {
    let dir = make_vault();
    let resps = mcp_exchange(
        dir.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ],
    );
    assert_eq!(resps.len(), 2);
    assert_eq!(resps[0]["result"]["serverInfo"]["name"], "confidant");
    let names: Vec<&str> = resps[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"log_session"));
    assert!(names.contains(&"context"));
}

#[test]
fn mcp_call_wraps_cli() {
    let dir = make_vault();
    let resps = mcp_exchange(
        dir.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"doctor","arguments":{}}}"#,
        ],
    );
    assert_eq!(resps.len(), 1);
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    let doc: Value = serde_json::from_str(text).unwrap();
    assert_eq!(doc["ok"], true);
}

#[test]
fn mcp_tool_failure_returns_cli_error_envelope() {
    let dir = make_vault();
    let resps = mcp_exchange(
        dir.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"context","arguments":{"person":"n-DOESNOTEXIST"}}}"#,
        ],
    );
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    let body: Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["ok"], false);
    // #537: a non-id argument is now an exact display-name lookup, so an
    // unmatched one is E_NOT_FOUND (fail closed), not a usage error.
    assert_eq!(body["error"]["code"], "E_NOT_FOUND");
}

#[test]
fn mcp_context_honors_no_ai_by_default() {
    let resps = mcp_exchange(
        demo().as_path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"context","arguments":{"person":"p-01M3TC5H00MPJG001248000002"}}}"#,
        ],
    );
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        !text.contains("Cam Sample"),
        "no-ai person name leaked through MCP: {text}"
    );
    assert!(
        !text.contains("Fake client"),
        "no-ai body leaked through MCP: {text}"
    );
    let body: Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["ok"], true);
    assert!(body["vault"].as_str().unwrap().contains("demo-vault"));
}

#[test]
fn mcp_unknown_tool_is_error_content() {
    let dir = make_vault();
    let resps = mcp_exchange(
        dir.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        ],
    );
    assert_eq!(resps[0]["result"]["isError"], true);
}

// ---------------------------------------------------------------------------
// #183: warnings never block writes
// ---------------------------------------------------------------------------
//
// The personal pack's cadence/date warnings (W_CADENCE_OVERDUE,
// W_DATE_UPCOMING) do not exist yet — they arrive with #184. The guarantee
// below is producer-independent, so it is tested with the warning findings
// that exist today (coaching warnings). No code change was needed: every
// gate already thresholds on errors (write.rs pre/post checks and doctor
// use CheckOptions::default() -> Error; the inbox merge passes
// fail_on: Error explicitly). These tests lock that in.

/// A vault whose only findings are warnings: one untagged session fires
/// `W_SESSION_UNTAGGED` (warning) plus the no-notes warning. No errors
/// can arise from this fixture at any as-of: every rule that can fire
/// here is warning-severity.
fn make_warning_vault() -> tempfile::TempDir {
    let dir = make_vault();
    let root = dir.path();
    // Untagged session: consumes a slot, fires W_SESSION_UNTAGGED.
    let ledger = root.join("ledger/2026/10.cfd");
    let mut text = std::fs::read_to_string(&ledger).unwrap();
    text.push_str(&format!("2026-10-02 session {PERSON} 60m\n"));
    std::fs::write(&ledger, text).unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "untagged session"]);
    dir
}

fn check_report(root: &Path, extra: &[&str]) -> (bool, Value) {
    let vroot = vault_arg(root);
    let mut args: Vec<&str> = vec!["check", "--json", "--no-input", "--vault", &vroot];
    args.extend(extra);
    run_json(&args)
}

fn finding_codes(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn warnings_never_block_writes() {
    let dir = make_warning_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Precondition: warnings only — no errors.
    let (ok, v) = check_report(root, &[]);
    assert!(ok, "{v}");
    assert_eq!(v["summary"]["errors"], 0);
    assert!(v["summary"]["warnings"].as_u64().unwrap() >= 1);
    assert!(
        finding_codes(&v).contains(&"W_SESSION_UNTAGGED".to_string()),
        "{v}"
    );
    // The write succeeds despite the warnings: exactly one new commit.
    let (ok, v) = run_json(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--request-id",
        "01J9Z3K4QF0000000000000002",
    ]);
    assert!(ok, "{v}");
    assert_eq!(
        commits(root),
        3,
        "init + untagged session + the new session"
    );
}

#[test]
fn check_fail_on_warning_exits_nonzero_while_default_exits_zero() {
    let dir = make_warning_vault();
    let root = dir.path();
    // Default fail-on (error): warnings do not fail the check.
    let (ok, v) = check_report(root, &[]);
    assert!(ok, "{v}");
    assert_eq!(v["ok"], true);
    // Stricter gate: --fail-on warning fails on the same vault.
    let (ok, v) = check_report(root, &["--fail-on", "warning"]);
    assert!(!ok, "{v}");
    assert_eq!(v["ok"], false);
    assert!(v["summary"]["warnings"].as_u64().unwrap() >= 1);
}

#[test]
fn check_as_of_makes_gap_warnings_deterministic() {
    // Paid client: open 4 sessions + one paid session on 2026-10-01, so
    // sessions_remaining is 3 and the gap clock starts 2026-10-01.
    let dir = make_vault();
    let root = dir.path();
    let ledger = root.join("ledger/2026/10.cfd");
    let mut text = std::fs::read_to_string(&ledger).unwrap();
    text.push_str(&format!("2026-10-01 session {PERSON} 60m paid\n"));
    std::fs::write(&ledger, text).unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "paid session"]);
    // 7 days after the last activity: inside the 45-day gap window.
    let (_, early) = check_report(root, &["--as-of", "2026-10-08"]);
    assert!(
        !finding_codes(&early).contains(&"E_PAID_SESSION_GAP".to_string()),
        "{early}"
    );
    // 61 days after: outside the window, the gap warning fires.
    let (_, late) = check_report(root, &["--as-of", "2026-12-01"]);
    assert!(
        finding_codes(&late).contains(&"E_PAID_SESSION_GAP".to_string()),
        "{late}"
    );
    // Same as-of twice: identical findings (deterministic).
    let (_, late_again) = check_report(root, &["--as-of", "2026-12-01"]);
    assert_eq!(late["findings"], late_again["findings"]);
}

#[test]
fn plaintext_vault_note_add_under_notes_mode_person_is_hidden_from_find_and_context() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Switch Ada to `no-ai: notes` on this plaintext vault.
    let profile = root.join(format!("people/{PERSON}/profile.md"));
    std::fs::write(
        &profile,
        format!(
            "---\nid: {PERSON}\ntype: person\nname: Ada Example\nno-ai: notes\n---\nAda profile body.\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "set Ada to no-ai: notes"]);

    let body_path = root.join(".confidant-test-note.md");
    std::fs::write(&body_path, "Plaintext secret medical detail xylophone42.\n").unwrap();
    let (ok, added) = run_json(&[
        "note",
        "add",
        "--person",
        PERSON,
        "--date",
        "2026-10-05",
        "--body-file",
        body_path.to_str().unwrap(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    let _ = std::fs::remove_file(&body_path);
    assert!(ok, "{added}");

    // `find` on the note's token returns 0 hits, while `find` on the person's name still finds the person.
    let (ok, found_note) = run_json(&[
        "find",
        "xylophone42",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{found_note}");
    assert_eq!(
        found_note["matches"].as_array().unwrap().len(),
        0,
        "{found_note}"
    );

    let (ok, found_person) = run_json(&[
        "find",
        "Ada Example",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{found_person}");
    assert_eq!(
        found_person["matches"].as_array().unwrap().len(),
        1,
        "{found_person}"
    );

    // `context` returns the person's name and profile, and omits the un-flagged note.
    let (ok, ctx) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{ctx}");
    assert_eq!(ctx["person"]["name"], "Ada Example");
    assert_eq!(ctx["notes"].as_array().unwrap().len(), 0, "{ctx}");
}

#[test]
fn plaintext_vault_note_inherits_notes_mode_via_non_person_field() {
    // Issue #270: `no-ai: notes` inheritance follows ANY front-matter
    // reference to the person, not just `person:` or the folder path.
    // A top-level note (not under people/<id>/) that references a
    // notes-mode person only through another ID field is hidden from
    // `find`.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Switch Ada to `no-ai: notes`.
    let profile = root.join(format!("people/{PERSON}/profile.md"));
    std::fs::write(
        &profile,
        format!(
            "---\nid: {PERSON}\ntype: person\nname: Ada Example\nno-ai: notes\n---\nAda profile body.\n"
        ),
    )
    .unwrap();

    // Control: Bob stays visible.
    let bob = "p-01J9Z3K4QG0000000000000000";
    let bob_dir = root.join(format!("people/{bob}"));
    std::fs::create_dir_all(&bob_dir).unwrap();
    std::fs::write(
        bob_dir.join("profile.md"),
        format!("---\nid: {bob}\ntype: person\nname: \"Bob Example\"\n---\nBob bio.\n"),
    )
    .unwrap();

    // Top-level note referencing Ada (notes mode) only via `related:`.
    let note_id = "n-01J9Z3K4QF2000000000000000";
    let note_dir = root.join(format!("notes/{note_id}"));
    std::fs::create_dir_all(&note_dir).unwrap();
    std::fs::write(
        note_dir.join("note.md"),
        format!(
            "---\nid: {note_id}\ntype: note\nrelated: {PERSON}\n---\nSecret detail xylophone270.\n"
        ),
    )
    .unwrap();

    // Control note referencing Bob (visible) via the same field.
    let note2_id = "n-01J9Z3K4QF3000000000000000";
    let note2_dir = root.join(format!("notes/{note2_id}"));
    std::fs::create_dir_all(&note2_dir).unwrap();
    std::fs::write(
        note2_dir.join("note.md"),
        format!(
            "---\nid: {note2_id}\ntype: note\nrelated: {bob}\n---\nVisible detail xylophone271.\n"
        ),
    )
    .unwrap();

    git(root, &["add", "-A"]);
    git(
        root,
        &["commit", "-qm", "notes-mode person + top-level notes"],
    );

    // `find` on the hidden note's token returns 0 hits.
    let (ok, found) = run_json(&[
        "find",
        "xylophone270",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{found}");
    assert_eq!(found["matches"].as_array().unwrap().len(), 0, "{found}");

    // `find` on the control note's token returns 1 hit.
    let (ok, found) = run_json(&[
        "find",
        "xylophone271",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{found}");
    assert_eq!(found["matches"].as_array().unwrap().len(), 1, "{found}");
}

#[test]
fn plaintext_vault_note_inherits_notes_mode_via_id_list_field() {
    // Issue #270 follow-up: list-valued fields fail open without
    // `parse_with_list`. A note whose `related:` is a bracketed list
    // containing a notes-mode person is hidden; `with:` on a note (not
    // just an interaction) counts too. A list of only visible people
    // stays visible.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Switch Ada to `no-ai: notes`.
    let profile = root.join(format!("people/{PERSON}/profile.md"));
    std::fs::write(
        &profile,
        format!(
            "---\nid: {PERSON}\ntype: person\nname: Ada Example\nno-ai: notes\n---\nAda profile body.\n"
        ),
    )
    .unwrap();

    // Control: Bob stays visible.
    let bob = "p-01J9Z3K4QG0000000000000000";
    let bob_dir = root.join(format!("people/{bob}"));
    std::fs::create_dir_all(&bob_dir).unwrap();
    std::fs::write(
        bob_dir.join("profile.md"),
        format!("---\nid: {bob}\ntype: person\nname: \"Bob Example\"\n---\nBob bio.\n"),
    )
    .unwrap();

    // Note with a flow-list `related:` containing the notes-mode person.
    let note_id = "n-01J9Z3K4QF4000000000000000";
    let note_dir = root.join(format!("notes/{note_id}"));
    std::fs::create_dir_all(&note_dir).unwrap();
    std::fs::write(
        note_dir.join("note.md"),
        format!(
            "---\nid: {note_id}\ntype: note\nrelated: [{bob}, {PERSON}]\n---\nSecret detail xylophone274.\n"
        ),
    )
    .unwrap();

    // Note with `with:` (participant list) on a note, not an interaction.
    let note2_id = "n-01J9Z3K4QF5000000000000000";
    let note2_dir = root.join(format!("notes/{note2_id}"));
    std::fs::create_dir_all(&note2_dir).unwrap();
    std::fs::write(
        note2_dir.join("note.md"),
        format!(
            "---\nid: {note2_id}\ntype: note\nwith: [{PERSON}]\n---\nSecret detail xylophone275.\n"
        ),
    )
    .unwrap();

    // Control note: flow list of only visible people stays visible.
    let note3_id = "n-01J9Z3K4QF6000000000000000";
    let note3_dir = root.join(format!("notes/{note3_id}"));
    std::fs::create_dir_all(&note3_dir).unwrap();
    std::fs::write(
        note3_dir.join("note.md"),
        format!(
            "---\nid: {note3_id}\ntype: note\nrelated: [{bob}]\n---\nVisible detail xylophone276.\n"
        ),
    )
    .unwrap();

    git(root, &["add", "-A"]);
    git(
        root,
        &["commit", "-qm", "notes-mode person + list-reference notes"],
    );

    for token in ["xylophone274", "xylophone275"] {
        let (ok, found) = run_json(&["find", token, "--json", "--no-input", "--vault", &vroot]);
        assert!(ok, "{found}");
        assert_eq!(found["matches"].as_array().unwrap().len(), 0, "{found}");
    }

    let (ok, found) = run_json(&[
        "find",
        "xylophone276",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{found}");
    assert_eq!(found["matches"].as_array().unwrap().len(), 1, "{found}");
}

/// Enable `personal@0.1` next to `coaching@0.1` (the `log touch` enable
/// switch) and commit the config change. Shared by the `log touch` tests.
fn enable_personal(root: &Path) {
    let toml_path = root.join("confidant.toml");
    let toml = std::fs::read_to_string(&toml_path).unwrap();
    std::fs::write(
        &toml_path,
        toml.replace(
            "packs = [\"coaching@0.1\"]",
            "packs = [\"coaching@0.1\", \"personal@0.1\"]",
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "enable personal"]);
}

#[test]
fn log_touch_requires_personal_pack() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // make_vault only enables coaching@0.1; `log touch` must refuse.
    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "call",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_INVALID");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("personal@0.1"));
}

#[test]
fn log_touch_writes_one_commit_and_appears_in_context() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Enable personal@0.1.
    enable_personal(root);

    let (ok, added) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
        "--date",
        "2026-10-05",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{added}");
    assert_eq!(commits(root), 3, "init + enable personal + log touch");

    // The touchpoint shows up in `context` for the person.
    let (ok, ctx) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{ctx}");
    assert_eq!(ctx["touchpoints"].as_array().unwrap().len(), 1, "{ctx}");
    assert_eq!(ctx["touchpoints"][0]["kind"], "meal");
}

#[test]
fn log_touch_bad_kind_is_usage_error() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "smoke",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "usage_error");
}

/// #510: the kind list lives in core `touch`; an unknown kind is a usage
/// error (exit 2) listing the core kinds.
#[test]
fn log_touch_rejects_unknown_kind_exit_2() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let tmp_home = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "log",
            "touch",
            PERSON,
            "smoke",
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ])
        .env("HOME", tmp_home.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "usage_error");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("call, text, email, meet, meal, event, gift, other"),
        "the error must list the core kinds: {message}"
    );
}

/// #510: every kind in the core constant is accepted and written verbatim.
#[test]
fn log_touch_accepts_every_core_kind() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    for (i, kind) in [
        "call", "text", "email", "meet", "meal", "event", "gift", "other",
    ]
    .iter()
    .enumerate()
    {
        let date = format!("2026-10-{:02}", i + 1);
        let (ok, v) = run_json(&[
            "log",
            "touch",
            PERSON,
            kind,
            "--date",
            &date,
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ]);
        assert!(ok, "{kind}: {v}");
        let ledger = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
        assert!(
            ledger.contains(&format!("{date} touch {PERSON} {kind}\n")),
            "{kind}: {ledger}"
        );
    }
}

/// #509: `coffee` was removed from the v1 kind list (replaced by `meal`,
/// no alias); a removed kind is a usage error that lists the new kinds.
#[test]
fn log_touch_rejects_coffee_and_lists_v1_kinds() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "coffee",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "usage_error");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("call, text, email, meet, meal, event, gift, other"),
        "the error must list the v1 kinds: {message}"
    );
}

// ---------------------------------------------------------------------------
// #216: `record edit` / `record show --for-edit`
// ---------------------------------------------------------------------------

/// Input files live outside the vault: `check` flags any unexpected entry.
fn person_record_md(id: &str, name: &str, bio: &str) -> String {
    format!("---\nid: {id}\ntype: person\nname: {name}\n---\n\n{bio}\n")
}

fn edit_args<'a>(id: &'a str, file: &'a str, vroot: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "record",
        "edit",
        id,
        "--file",
        file,
        "--json",
        "--no-input",
        "--vault",
        vroot,
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn record_edit_replaces_the_file_in_one_commit() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    let before = commits(root);

    let edited = inputs.path().join("edited.md");
    std::fs::write(&edited, person_record_md(PERSON, "Ada Renamed", "New bio.")).unwrap();
    let (ok, v) = run_json(&edit_args(PERSON, edited.to_str().unwrap(), &vroot, &[]));
    assert!(ok, "{v}");
    assert_eq!(v["command"], "record-edit", "{v}");
    assert_eq!(v["id"], PERSON, "{v}");
    assert_eq!(commits(root), before + 1, "expected exactly one commit");

    let on_disk =
        std::fs::read_to_string(root.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert!(on_disk.contains("Ada Renamed"), "{on_disk}");
    assert!(on_disk.contains("New bio."), "{on_disk}");
}

#[test]
fn record_edit_with_identical_content_is_a_no_op() {
    // #389 Q1: the write layer has no empty changeset, so an unchanged edit
    // reports `unchanged` rather than failing on `git commit`.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    let edited = inputs.path().join("edited.md");
    std::fs::write(&edited, person_record_md(PERSON, "Ada Renamed", "New bio.")).unwrap();
    let args = edit_args(PERSON, edited.to_str().unwrap(), &vroot, &[]);

    let (ok, v) = run_json(&args);
    assert!(ok, "first edit failed: {v}");
    let after_first = commits(root);

    let (ok, v) = run_json(&args);
    assert!(ok, "no-op edit failed: {v}");
    assert_eq!(v["unchanged"], true, "{v}");
    assert!(
        v.get("commit").is_none(),
        "no-op edit reported a commit: {v}"
    );
    assert_eq!(commits(root), after_first, "a no-op edit committed");
}

#[test]
fn record_edit_is_idempotent_for_a_repeated_request_id() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    let edited = inputs.path().join("edited.md");
    std::fs::write(&edited, person_record_md(PERSON, "Ada Renamed", "New bio.")).unwrap();
    const RID: &str = "01J9Z3K4QF000000000000REQ1";
    let args = edit_args(
        PERSON,
        edited.to_str().unwrap(),
        &vroot,
        &["--request-id", RID],
    );

    let (ok, v) = run_json(&args);
    assert!(ok, "{v}");
    let commit = v["commit"].as_str().unwrap().to_owned();
    let after_first = commits(root);

    let (ok, v) = run_json(&args);
    assert!(ok, "{v}");
    assert_eq!(v["idempotent"], true, "{v}");
    assert_eq!(v["commit"], commit, "{v}");
    assert_eq!(commits(root), after_first, "the replay committed again");
}

#[test]
fn record_show_requires_the_for_edit_flag() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "record",
        "show",
        PERSON,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "usage_error", "{v}");
}

#[test]
fn record_edit_rejects_a_file_naming_another_id() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    let other = inputs.path().join("other.md");
    std::fs::write(
        &other,
        person_record_md("p-01J9Z3K4QG0000000000000000", "Bea", "bio"),
    )
    .unwrap();
    let (ok, v) = run_json(&edit_args(PERSON, other.to_str().unwrap(), &vroot, &[]));
    assert!(!ok, "{v}");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("not"),
        "{v}"
    );
}

#[test]
fn record_edit_unknown_record_suggests_add() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    let missing = "p-01J9Z3K4QG0000000000000000";
    let file = inputs.path().join("new.md");
    std::fs::write(&file, person_record_md(missing, "Bea", "bio")).unwrap();
    let (ok, v) = run_json(&edit_args(missing, file.to_str().unwrap(), &vroot, &[]));
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_NOT_FOUND", "{v}");
    assert!(
        v["error"]["fix"].as_str().unwrap().contains("record add"),
        "{v}"
    );
}

#[test]
fn record_self_edge_edit_is_blocked_by_check_and_commits_nothing() {
    // The edited record parses, so this exercises the post-check rollback
    // rather than the parser — `check` gates an edit like any other write.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    const BEA: &str = "p-01J9Z3K4QG0000000000000000";
    // A distinct ULID body: E_DUPLICATE_ULID fires when two records share one.
    const EDGE: &str = "e-01J9Z3K4QH0000000000000000";
    std::fs::create_dir_all(root.join(format!("people/{BEA}"))).unwrap();
    std::fs::write(
        root.join(format!("people/{BEA}/profile.md")),
        person_record_md(BEA, "Bea", "bio"),
    )
    .unwrap();
    std::fs::create_dir_all(root.join(format!("edges/{EDGE}"))).unwrap();
    std::fs::write(
        root.join(format!("edges/{EDGE}/edge.md")),
        format!("---\nid: {EDGE}\ntype: edge\na: {PERSON}\nb: {BEA}\nkind: married\n---\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "edge"]);
    let before = commits(root);

    let self_edge = inputs.path().join("self.md");
    std::fs::write(
        &self_edge,
        format!("---\nid: {EDGE}\ntype: edge\na: {PERSON}\nb: {PERSON}\nkind: married\n---\n"),
    )
    .unwrap();
    let (ok, v) = run_json(&edit_args(EDGE, self_edge.to_str().unwrap(), &vroot, &[]));
    assert!(!ok, "{v}");
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .expect("check report")
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"E_SELF_EDGE"), "{codes:?}");
    assert_eq!(commits(root), before, "nothing committed");
    let on_disk = std::fs::read_to_string(root.join(format!("edges/{EDGE}/edge.md"))).unwrap();
    assert!(
        on_disk.contains(BEA),
        "the file was not rolled back: {on_disk}"
    );
}
