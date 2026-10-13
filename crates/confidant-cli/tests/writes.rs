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
            "n-DOESNOTEXIST",
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
        "check", "find", "log", "import", "note", "context", "doctor", "schema", "help", "mcp",
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
    assert_eq!(body["error"]["code"], "usage_error");
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
