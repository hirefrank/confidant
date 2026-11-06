//! Milestone 3 integration tests: write pipeline, context, doctor, schema,
//! help --json, and the MCP server. All vaults are synthetic; all data fake.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::install_example_pack;

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
    install_example_pack(root);
    std::fs::write(
        root.join("confidant.toml"),
        // Spec 3 (B10): the plaintext-write fixture declares the opt-out,
        // so the suite keeps exercising the plaintext path.
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
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
        format!("2026-10-01 grant {PERSON} package {PKG} 4 sessions\n"),
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

/// Porcelain status, so a dry-run regression test can prove the tree is
/// untouched (not just uncommitted).
fn git_status(root: &Path) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(out.status.success(), "git status failed: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run_json(args: &[&str]) -> (bool, Value) {
    // Hermetic HOME: Windows CI runners don't set HOME, and `doctor` needs
    // a config dir. A fresh tempdir per call is fine — no test here
    // persists state across calls.
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
// log
// ---------------------------------------------------------------------------

/// #799 step 2: the top-level `log session` command is gone. `session` is a
/// pack-declared verb now, logged through `import --file`; `log touch`
/// remains the core personal write.
#[test]
fn log_session_is_no_longer_a_subcommand() {
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
    let out = Command::new(bin())
        .args([
            "log",
            "session",
            PERSON,
            "60m",
            "paid",
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ])
        .env("HOME", tempfile::tempdir().unwrap().path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "usage_error");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("unrecognized subcommand") || message.contains("unexpected argument"),
        "expected a clap usage error, got: {message}"
    );
    assert_eq!(commits(dir.path()), 1, "a refused command writes nothing");
}

/// #732 fix wave: a problem pack's claimed verbs stay known (spec
/// pack-lock §5), so the gate must pass them. Tampering a vendored file
/// makes the listed example pack a hash problem while its manifest
/// still sells `session`; the dry run must therefore not refuse the
/// verb. #770: both dry-run and apply then block on the shared pre-check
/// (the pack hash), so the dry run must report the same findings.
/// #799 step 2: the pack verb is written through `import --file`.
#[test]
fn import_problem_pack_verb_dry_run_matches_apply() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    install_example_pack(root);
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    // Break the lockfile hash without breaking the manifest parse.
    let skill = root.join("packs/example-pack@0.1/SKILL.md");
    let mut contents = std::fs::read_to_string(&skill).unwrap();
    contents.push_str("\n<!-- tampered for the problem-pack fixture -->\n");
    std::fs::write(&skill, contents).unwrap();
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
        format!("2026-10-01 touch {PERSON} call\n"),
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("session.cfd");
    std::fs::write(&file, format!("2026-10-23 session {PERSON} 60m paid\n")).unwrap();

    let (dry_ok, dry) = run_json(&[
        "import",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
        "--dry-run",
    ]);
    // Not a verb refusal: the gate passes the problem pack's verb, and the
    // shared pre-check then blocks on the pack problem exactly as apply does.
    assert!(!dry_ok, "{dry}");
    assert_eq!(dry["ok"], false, "{dry}");
    assert!(
        dry.get("error").is_none(),
        "blocked by the pre-check, not the verb gate: {dry}"
    );
    assert!(
        !dry["findings"].as_array().unwrap().is_empty(),
        "the pre-check findings must be reported: {dry}"
    );
    assert_eq!(git_status(root), "", "dry run must write nothing");

    // Apply is blocked by the same pack problem, not by the verb gate.
    let (ok, v) = run_json(&[
        "import",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_ne!(v["error"]["code"], "E_INVALID", "{v}");
    assert_eq!(
        dry["findings"], v["findings"],
        "dry run and apply must agree on the pre-check"
    );
    assert_eq!(commits(root), 1, "no commit on blocked apply");
}

#[test]
fn import_refuses_unknown_verb_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
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
        format!("2026-10-01 touch {PERSON} call\n"),
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();

    let bad = scratch.path().join("bad.cfd");
    std::fs::write(&bad, format!("2026-10-06 session {PERSON} 60m\n")).unwrap();
    let (ok, v) = run_json(&[
        "import",
        "--file",
        &bad.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_INVALID");
    assert_eq!(commits(root), 1, "no commit on refused import");
    assert!(
        !std::fs::read_to_string(root.join("ledger/2026/10.cfd"))
            .unwrap()
            .contains("60m"),
        "refused import must not append"
    );

    let good = scratch.path().join("good.cfd");
    std::fs::write(&good, format!("2026-10-06 touch {PERSON} meal\n")).unwrap();
    let (ok, v) = run_json(&[
        "import",
        "--file",
        &good.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(commits(root), 2, "core-verb import still commits");
}

#[test]
fn log_touch_with_note_creates_note_record() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
        "--date",
        "2026-10-13",
        "--note",
        "Great meal",
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
    assert!(body.contains("Great meal"), "{body}");
}

#[test]
fn request_id_is_idempotent_then_conflicts() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let base = [
        "log",
        "touch",
        PERSON,
        "meal",
        "--date",
        "2026-10-13",
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
        "touch",
        PERSON,
        "call",
        "--date",
        "2026-10-13",
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
        "touch",
        PERSON,
        "meal",
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
        "touch",
        PERSON,
        "meal",
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
    // Break the vault directly: a session line with a bad id. Commit the
    // breakage so the fixture tree starts clean and a dry run's write-free
    // guarantee is observable.
    std::fs::write(
        root.join("ledger/2026/10.cfd"),
        "2026-10-01 open x package y 4 sessions\n",
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "break vault"]);
    let ledger_before = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();

    // #770: a dry run runs the same read-only pre-check as apply. It must
    // not report ok for a write apply blocks, and it must not touch the
    // vault (no file change, no commit, no queue).
    let (dry_ok, dry) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
        "--dry-run",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!dry_ok, "{dry}");
    assert_eq!(
        dry["ok"], false,
        "dry run returns the same check report as apply"
    );
    assert_eq!(commits(root), 2, "dry run must not commit");
    assert_eq!(
        std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap(),
        ledger_before,
        "dry run must not append"
    );
    assert_eq!(git_status(root), "", "dry run must leave the tree clean");

    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok);
    assert_eq!(v["ok"], false, "check report, not an error envelope");
    assert!(v["summary"]["errors"].as_u64().unwrap() > 0);
    assert_eq!(
        dry["findings"], v["findings"],
        "dry run and apply must agree on the pre-check"
    );
    assert_eq!(commits(root), 2, "nothing committed");

    // The pre-check fails fast, so the file is untouched.
    let ledger_after = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert_eq!(ledger_before, ledger_after);

    // A record write on the same broken vault agrees too (#770): the
    // pre-check is shared, not per-command.
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("person.md");
    let new_person = "p-01J9Z3K4QF0000000000000003";
    std::fs::write(
        &file,
        format!("---\nid: {new_person}\ntype: person\nname: \"Ada Example\"\n---\n\nFake bio.\n"),
    )
    .unwrap();
    let file_arg = file.display().to_string();
    let record_path = root.join(format!("people/{new_person}/profile.md"));
    let mut args = vec![
        "record",
        "add",
        "--file",
        file_arg.as_str(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ];
    args.push("--dry-run");
    let (dry_ok, dry_record) = run_json(&args);
    assert!(!dry_ok, "{dry_record}");
    assert_eq!(
        dry_record["findings"], v["findings"],
        "record dry run uses the same pre-check"
    );
    assert!(!record_path.exists(), "record dry run wrote a file");
    assert_eq!(
        git_status(root),
        "",
        "record dry run must leave the tree clean"
    );

    args.pop();
    let (ok, applied) = run_json(&args);
    assert!(!ok, "{applied}");
    assert_eq!(
        applied["findings"], dry_record["findings"],
        "record dry run and apply must agree on the pre-check"
    );
    assert!(!record_path.exists(), "blocked record apply wrote a file");
    assert_eq!(
        commits(root),
        2,
        "record apply was blocked by the pre-check"
    );
}

#[test]
fn write_to_non_git_vault_fails() {
    let dir = make_vault();
    // Remove the .git directory: writes need git.
    std::fs::remove_dir_all(dir.path().join(".git")).unwrap();
    let vroot = vault_arg(dir.path());
    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
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
        format!("2026-10-01 grant {PERSON} package {PKG} 4 sessions\n<<<<<<< HEAD\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "conflicted"]);
    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
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
        format!("2026-10-03 use {PERSON} 45m full\n; a comment\n\n2026-11-01 use {PERSON} 30m metered\n"),
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
    assert!(oct.contains("45m full"));
    assert!(nov.contains("30m metered"));
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

#[test]
fn import_refuses_a_dirty_target_month_file() {
    // #611: appending commits the whole month file (`git add`), so an
    // unrelated uncommitted line would be swept into the proposal commit.
    // Refuse before writing anything, then succeed once it is committed.
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let ledger = root.join("ledger/2026/10.cfd");
    let mut dirty = std::fs::read_to_string(&ledger).unwrap();
    dirty.push_str(&format!("2026-10-05 touch {PERSON}\n"));
    std::fs::write(&ledger, &dirty).unwrap();
    let before_commits = commits(root);

    let file = scratch.path().join("import.cfd");
    std::fs::write(&file, format!("2026-10-06 use {PERSON} 45m full\n")).unwrap();
    // #770: the dry run refuses the dirty target exactly like apply, so a
    // preview cannot report ok for a write apply blocks.
    let (ok, dry) = run_json(&[
        "import",
        "--file",
        &file.display().to_string(),
        "--dry-run",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{dry}");
    assert_eq!(dry["error"]["code"], "E_CONFLICT", "{dry}");
    assert_eq!(commits(root), before_commits, "dry run committed nothing");

    let (ok, v) = run_json(&[
        "import",
        "--file",
        &file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_CONFLICT");
    assert_eq!(commits(root), before_commits, "nothing committed");
    assert_eq!(
        std::fs::read_to_string(&ledger).unwrap(),
        dirty,
        "the dirty file must be left untouched"
    );

    // Committing the operator's unrelated line clears the refusal.
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "operator work"]);
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
    assert!(std::fs::read_to_string(&ledger)
        .unwrap()
        .contains("45m full"));
}

/// #770: `log touch` appends to the month file, so its dry run must refuse a
/// dirty target exactly like apply (the guard lives in the write pipeline,
/// not per command).
#[test]
fn log_touch_dry_run_refuses_a_dirty_month_file() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let ledger = root.join("ledger/2026/10.cfd");
    let mut dirty = std::fs::read_to_string(&ledger).unwrap();
    dirty.push_str(&format!("2026-10-05 touch {PERSON} meal\n"));
    std::fs::write(&ledger, &dirty).unwrap();
    let before = commits(root);
    for flag in [Some("--dry-run"), None] {
        let mut args = vec![
            "log",
            "touch",
            PERSON,
            "meal",
            "--date",
            "2026-10-13",
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let (ok, err) = run_json(&args);
        assert!(!ok, "{err}");
        assert_eq!(err["error"]["code"], "E_CONFLICT", "{err}");
    }
    assert_eq!(commits(root), before, "neither path committed");
    assert_eq!(std::fs::read_to_string(&ledger).unwrap(), dirty);
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

#[test]
fn note_add_honours_a_forced_id_and_is_idempotent() {
    // #611: the TUI passes the manifest's note id so the reviewed dry-run
    // and the commit name the same file. Reusing the request id is
    // idempotent, never an overwrite refusal.
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "Reviewed body.\n").unwrap();
    let nid = "n-01M3TC5H00MPJG002NAM000005";
    let rid = "01M3TC5H00MPJG005VQC00000B";
    let body_arg = body.display().to_string();
    let args = [
        "note",
        "add",
        "--person",
        PERSON,
        "--id",
        nid,
        "--body-file",
        body_arg.as_str(),
        "--request-id",
        rid,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ];
    let (ok, v) = run_json(&args);
    assert!(ok, "{v}");
    assert_eq!(v["id"], nid);
    let path = root.join(v["path"].as_str().unwrap());
    assert!(path.exists(), "note not written at the forced id");
    assert_eq!(path, root.join(format!("people/{PERSON}/notes/{nid}.md")));
    assert_eq!(commits(root), 2);

    let (ok, v) = run_json(&args);
    assert!(ok, "{v}");
    assert_eq!(v["idempotent"], true, "{v}");
    assert_eq!(commits(root), 2, "idempotent retry must not commit again");
}

#[test]
fn note_add_refuses_a_forced_id_that_already_exists() {
    // A stale or hand-edited manifest must not silently overwrite a note:
    // a forced id that already exists, with a request id that never
    // committed it, refuses and writes nothing.
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "First body.\n").unwrap();
    let nid = "n-01M3TC5H00MPJG002NAM000005";
    let body_arg = body.display().to_string();
    let (ok, v) = run_json(&[
        "note",
        "add",
        "--person",
        PERSON,
        "--id",
        nid,
        "--body-file",
        body_arg.as_str(),
        "--request-id",
        "01M3TC5H00MPJG005VQC00000B",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(commits(root), 2);

    std::fs::write(&body, "Second body.\n").unwrap();
    let (ok, v) = run_json(&[
        "note",
        "add",
        "--person",
        PERSON,
        "--id",
        nid,
        "--body-file",
        body_arg.as_str(),
        "--request-id",
        "01M3TC5H00MPJG005VQC00000C",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_ALREADY_EXISTS");
    assert_eq!(commits(root), 2, "nothing committed");
    let text =
        std::fs::read_to_string(root.join(format!("people/{PERSON}/notes/{nid}.md"))).unwrap();
    assert!(
        text.contains("First body."),
        "the existing note must be intact"
    );
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
    // A person change would silently re-home the note away from the
    // directory its path promises. Refuse before writing.
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

const PLACE_PERSON: &str = "p-01M3TC5H00MPJG000000000000";
const PLACE_ORG: &str = "o-01M3TC5H00MPJG000000000001";
const PLACE: &str = "pl-01M3TC5H00MPJG000000000002";
const PLACE_NOTE: &str = "n-01M3TC5H00MPJG000000000003";

/// Vendor the checked-in place pack and pin it, as `pack add` would. The
/// place pack declares one entity type (`place`) for spec 0.3.
fn install_place_pack(vault: &Path) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/place-pack");
    let dst = vault.join("packs/place-pack@0.1");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    let hash = confidant_core::packs::dir::read_pack_dir(&dst)
        .unwrap()
        .hash;
    std::fs::write(
        vault.join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"place-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    )
    .unwrap();
}

fn make_place_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    install_place_pack(root);
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.3\"\npacks = [\"place-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    add_person(root, PLACE_PERSON, "Dana Example", "");
    dir
}

/// Vendor the place pack with one extra pack-declared verb, `session`, and
/// pin the modified copy. #799 step 2 removed the core `log session`
/// command; this fixture proves a coaching/CRM-style pack can still log its
/// own verb through the shared `import --file` path.
fn install_place_pack_with_session_verb(vault: &Path) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/place-pack");
    let dst = vault.join("packs/place-pack@0.1");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    let manifest = dst.join("manifest.toml");
    let mut text = std::fs::read_to_string(&manifest).unwrap();
    text.push_str("\n[[verbs]]\nname = \"session\"\nid_type = \"person\"\n");
    std::fs::write(&manifest, text).unwrap();
    let hash = confidant_core::packs::dir::read_pack_dir(&dst)
        .unwrap()
        .hash;
    std::fs::write(
        vault.join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"place-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    )
    .unwrap();
}

fn make_session_verb_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    install_place_pack_with_session_verb(root);
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.3\"\npacks = [\"place-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    add_person(root, PLACE_PERSON, "Dana Example", "");
    dir
}

#[test]
fn place_pack_end_to_end_record_add_list_context_note_allowlist_check() {
    let dir = make_place_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    let place_file = scratch.path().join("place.md");
    std::fs::write(
        &place_file,
        format!(
            "---\nid: {PLACE}\ntype: place\nname: Example Studio\naddress: 1 Example Way\n---\n\nFake place.\n"
        ),
    )
    .unwrap();

    let (ok, v) = run_json(&[
        "record",
        "add",
        "--file",
        &place_file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["command"], "record-add");
    assert_eq!(v["path"], format!("places/{PLACE}/place.md"));
    assert!(root.join(format!("places/{PLACE}/place.md")).is_file());

    let list = run_json(&[
        "record",
        "list",
        "--kind",
        "place",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(list.0, "{list:?}");
    assert_eq!(list.1["kind"], "place");
    assert_eq!(list.1["kinds"], serde_json::json!(["place"]));
    assert_eq!(list.1["records"][0]["kind"], "place");
    assert_eq!(list.1["records"][0]["name"], "Example Studio");
    assert!(list.1["records"][0].get("orphan").is_none());

    let all = run_json(&["record", "list", "--json", "--no-input", "--vault", &vroot]);
    assert!(all.0, "{all:?}");
    assert!(
        all.1["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "place"),
        "{}",
        all.1
    );
    assert!(all.1["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["id"] == PLACE));

    // People stays core-person-only, as the TUI's People list expects.
    let people = run_json(&[
        "record",
        "list",
        "--kind",
        "person",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(people.0, "{people:?}");
    assert_eq!(people.1["kinds"], serde_json::json!(["person"]));
    assert!(
        !people.1["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["id"] == PLACE),
        "{}",
        people.1
    );

    // The edit path also parses with the vault's spec and declared types.
    std::fs::write(
        &place_file,
        format!(
            "---\nid: {PLACE}\ntype: place\nname: Example Studio Annex\naddress: 1 Example Way\n---\n\nFake place, edited.\n"
        ),
    )
    .unwrap();
    let (ok, edited) = run_json(&[
        "record",
        "edit",
        PLACE,
        "--file",
        &place_file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{edited}");
    assert_eq!(edited["command"], "record-edit");
    assert_eq!(edited["path"], format!("places/{PLACE}/place.md"));

    let context = run_json(&["context", PLACE, "--json", "--no-input", "--vault", &vroot]);
    assert!(context.0, "{context:?}");
    assert_eq!(context.1["entity"]["kind"], "place");
    assert_eq!(context.1["entity"]["name"], "Example Studio Annex");

    let body = scratch.path().join("body.md");
    std::fs::write(&body, "Liked the back room.\n").unwrap();
    let (ok, note) = run_json(&[
        "note",
        "add",
        "--entity",
        PLACE,
        "--id",
        PLACE_NOTE,
        "--date",
        "2026-10-13",
        "--body-file",
        &body.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{note}");
    assert_eq!(note["command"], "note-add");
    assert_eq!(note["path"], format!("notes/{PLACE_NOTE}/note.md"));
    let note_text =
        std::fs::read_to_string(root.join(format!("notes/{PLACE_NOTE}/note.md"))).unwrap();
    assert!(
        note_text.contains(&format!("entity: {PLACE}")),
        "{note_text}"
    );

    let context = run_json(&["context", PLACE, "--json", "--no-input", "--vault", &vroot]);
    assert!(context.0, "{context:?}");
    assert_eq!(context.1["notes"][0]["id"], PLACE_NOTE);

    let allow = run_json(&["allowlist", "--json", "--no-input", "--vault", &vroot]);
    assert!(allow.0, "{allow:?}");
    let files: Vec<&str> = allow.1["cleared_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file.as_str().unwrap())
        .collect();
    assert!(
        files
            .iter()
            .any(|file| file.contains(&format!("places/{PLACE}/place.md"))),
        "{files:?}"
    );
    assert!(
        files
            .iter()
            .any(|file| file.contains(&format!("notes/{PLACE_NOTE}/note.md"))),
        "{files:?}"
    );

    // Out of scope, the pack-owned place and its note disappear from every
    // agent read even though the core person remains.
    let scoped_allow = run_json(&[
        "allowlist",
        "--packs",
        "personal@0.2",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(scoped_allow.0, "{scoped_allow:?}");
    assert!(
        !scoped_allow.1["cleared_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| {
                let file = file.as_str().unwrap();
                file.contains(&format!("places/{PLACE}/place.md"))
                    || file.contains(&format!("notes/{PLACE_NOTE}/note.md"))
            }),
        "out-of-scope pack files leaked into allowlist: {}",
        scoped_allow.1
    );
    let scoped_list = run_json(&[
        "record",
        "list",
        "--kind",
        "place",
        "--packs",
        "personal@0.2",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(scoped_list.0, "{scoped_list:?}");
    assert!(scoped_list.1["records"].as_array().unwrap().is_empty());
    let scoped_find = run_json(&[
        "find",
        "Example Studio",
        "--packs",
        "personal@0.2",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(scoped_find.0, "{scoped_find:?}");
    assert!(scoped_find.1["matches"].as_array().unwrap().is_empty());

    let schema = run_json(&["schema", "--json", "--no-input", "--vault", &vroot]);
    assert!(schema.0, "{schema:?}");
    assert!(
        schema.1["contract"]["record_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|decl| decl["name"] == "place" && decl["owner"] == "place-pack@0.1"),
        "{}",
        schema.1
    );
    let scoped_schema = run_json(&[
        "schema",
        "--packs",
        "personal@0.2",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(scoped_schema.0, "{scoped_schema:?}");
    assert!(
        !scoped_schema.1["contract"]["record_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|decl| decl["name"] == "place"),
        "out-of-scope pack type leaked into schema: {}",
        scoped_schema.1
    );

    let (ok, check) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{check}");
    assert_eq!(check["ok"], true, "{check}");
}

/// #799 step 2: `session` is a pack-declared verb, not a core command, but a
/// 0.3 pack can still append it through the shared `import --file` path.
/// The fixture is the checked-in place pack plus one `session` verb, so this
/// pins the capability without restoring a core session write command.
#[test]
fn pack_declared_session_verb_is_appended_through_import() {
    let dir = make_session_verb_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("session.cfd");
    std::fs::write(
        &file,
        format!("2026-10-13 session {PLACE_PERSON} 60m paid\n"),
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
    assert_eq!(v["files"], serde_json::json!(["ledger/2026/10.cfd"]));
    let ledger = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert!(
        ledger.contains(&format!("session {PLACE_PERSON} 60m paid")),
        "{ledger}"
    );

    let (ok, check) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{check}");
    assert_eq!(check["ok"], true, "{check}");
}

/// The 0.3 write path gets the spec-aware parser: an edge can be authored
/// with `no-ai: true`, it is hidden from agent reads, and the operator sees
/// it with the tri-state badge.
#[test]
fn cli_authors_a_0_3_edge_no_ai_that_agent_reads_hide() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.3\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    add_person(root, PLACE_PERSON, "Dana Example", "");
    std::fs::create_dir_all(root.join("orgs").join(PLACE_ORG)).unwrap();
    std::fs::write(
        root.join("orgs").join(PLACE_ORG).join("org.md"),
        format!("---\nid: {PLACE_ORG}\ntype: org\nname: Example Studio\n---\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let edge = "e-01M3TC5H00MPJG000000000004";
    let edge_file = scratch.path().join("edge.md");
    std::fs::write(
        &edge_file,
        format!(
            "---\nid: {edge}\ntype: edge\na: {PLACE_PERSON}\nb: {PLACE_ORG}\nkind: works_at\nsince: 2024-01-01\nno-ai: true\n---\n"
        ),
    )
    .unwrap();

    let (ok, added) = run_json(&[
        "record",
        "add",
        "--file",
        &edge_file.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{added}");
    assert_eq!(added["path"], format!("edges/{edge}/edge.md"));

    let allow = run_json(&["allowlist", "--json", "--no-input", "--vault", &vroot]);
    assert!(allow.0, "{allow:?}");
    assert!(
        !allow.1["cleared_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file.as_str().unwrap().contains(edge)),
        "hidden edge leaked into the agent allowlist: {}",
        allow.1
    );

    let agent = run_json(&[
        "context",
        PLACE_PERSON,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(agent.0, "{agent:?}");
    assert!(
        agent.1["edges"].as_array().unwrap().is_empty(),
        "{}",
        agent.1
    );

    let operator = run_json(&[
        "context",
        PLACE_PERSON,
        "--for-operator",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(operator.0, "{operator:?}");
    assert_eq!(operator.1["for_operator"], true);
    assert_eq!(operator.1["edges"].as_array().unwrap().len(), 1);
    assert_eq!(operator.1["edges"][0]["id"], edge);
    assert_eq!(operator.1["edges"][0]["no_ai"], "true");

    let (ok, check) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{check}");
    assert_eq!(check["ok"], true, "{check}");
}

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
    // #770: the dry run ran apply's read-only pre-check and says plainly
    // that it could not run the post-write check.
    assert_eq!(v["checks"]["pre"], "passed", "{v}");
    assert_eq!(v["checks"]["post"], "skipped", "{v}");
    assert!(!root
        .join("deals/d-01J9Z3K4QF0000000000000002/deal.md")
        .exists());
    assert_eq!(commits(root), 1);
    assert_eq!(git_status(root), "", "dry run must write nothing");

    // The human output states the skipped post-check too, not just JSON.
    let (ok, text, _) = run_raw(&[
        "record",
        "add",
        "--file",
        &file.display().to_string(),
        "--dry-run",
        "--request-id",
        rid,
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{text}");
    assert!(text.contains("pre-check passed"), "{text}");
    assert!(text.contains("post-check skipped"), "{text}");
}

/// #604: a `record add` whose post-check refuses must not leave the record
/// directory it created. The payload shares a ULID with an existing
/// interaction under a different prefix, so the write creates `people/p-…/`
/// and the post-check then reports `E_DUPLICATE_ULID`. Left behind, the empty
/// directory makes the next `check` fail `E_FRONTMATTER` ("record directory is
/// missing the main file") and blocks later writes — invisible to git.
#[test]
fn record_add_check_blocked_removes_created_directory() {
    let dir = make_vault();
    let scratch = tempfile::tempdir().unwrap();
    let root = dir.path();
    let vroot = vault_arg(root);
    // The ULID body shared by the existing interaction and the refused person.
    const SHARED: &str = "01J9Z3K4QK0000000000000000";
    let iid = format!("i-{SHARED}");
    let i_dir = root.join(format!("interactions/{iid}"));
    std::fs::create_dir_all(&i_dir).unwrap();
    std::fs::write(
        i_dir.join("interaction.md"),
        format!(
            "---\nid: {iid}\ntype: interaction\nname: Call\nperson: {PERSON}\ndate: 2026-10-06\n---\n\nFake call.\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "interaction fixture"]);
    let before = commits(root);

    let new_person = format!("p-{SHARED}");
    let file = scratch.path().join("person.md");
    std::fs::write(
        &file,
        format!("---\nid: {new_person}\ntype: person\nname: \"Dana Example\"\n---\n\nBio.\n"),
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
    assert!(!ok, "{v}");
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .expect("check report")
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"E_DUPLICATE_ULID"), "{codes:?}");
    assert_eq!(commits(root), before, "nothing committed");

    // The file AND the directory this write created are gone (#604).
    assert!(
        !root.join(format!("people/{new_person}")).exists(),
        "refused record add left its record directory behind"
    );

    // The vault is healthy after the refusal, and a later write still works.
    let (ok, v) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(!codes.contains(&"E_FRONTMATTER"), "{codes:?}");

    let file2 = scratch.path().join("person2.md");
    std::fs::write(
        &file2,
        "---\nid: p-01J9Z3K4QM0000000000000000\ntype: person\nname: \"Eve Example\"\n---\n\nBio.\n",
    )
    .unwrap();
    let (ok, v) = run_json(&[
        "record",
        "add",
        "--file",
        &file2.display().to_string(),
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
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
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("interaction.md");
    std::fs::write(
        &file,
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Lunch\ndate: 2026-10-06\nperson: {PERSON}\n---\n\nFake lunch.\n"
        ),
    )
    .unwrap();
    let file_arg = file.display().to_string();
    // #770: the dry run previews the record and its mirrored touchpoint and
    // writes neither; the apply then lands exactly that logical change.
    let (ok, dry) = run_json(&[
        "record",
        "add",
        "--file",
        &file_arg,
        "--dry-run",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{dry}");
    assert_eq!(dry["checks"]["pre"], "passed", "{dry}");
    assert_eq!(dry["checks"]["post"], "skipped", "{dry}");
    let changes = dry["changes"].as_array().unwrap();
    assert!(
        changes
            .iter()
            .any(|c| c["path"] == format!("interactions/{IXN}/interaction.md")),
        "{dry}"
    );
    assert!(
        changes.iter().any(|c| c["path"] == "ledger/2026/10.cfd"
            && c["content"] == format!("2026-10-06 touch {PERSON}")),
        "the mirrored touchpoint must be previewed too: {dry}"
    );
    assert_eq!(commits(root), before, "dry run committed nothing");
    assert_eq!(git_status(root), "", "dry run wrote nothing");
    assert!(!root
        .join(format!("interactions/{IXN}/interaction.md"))
        .exists());

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

/// #770: a dry run of `record add` mirrors the apply path's target gates.
/// The interaction write appends a mirrored touchpoint, so a dirty month file
/// is refused before the preview — exactly as apply refuses it.
#[test]
fn record_add_interaction_dry_run_refuses_a_dirty_month_file() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let ledger = root.join("ledger/2026/10.cfd");
    let mut dirty = std::fs::read_to_string(&ledger).unwrap();
    dirty.push_str(&format!("2026-10-05 touch {PERSON} meal\n"));
    std::fs::write(&ledger, &dirty).unwrap();
    let before = commits(root);
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("interaction.md");
    std::fs::write(
        &file,
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Lunch\ndate: 2026-10-06\nperson: {PERSON}\n---\n\nFake lunch.\n"
        ),
    )
    .unwrap();
    let file_arg = file.display().to_string();
    for flag in [Some("--dry-run"), None] {
        let mut args = vec![
            "record",
            "add",
            "--file",
            file_arg.as_str(),
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let (ok, err) = run_json(&args);
        assert!(!ok, "{err}");
        assert_eq!(err["error"]["code"], "E_CONFLICT", "{err}");
    }
    assert_eq!(commits(root), before, "neither path committed");
    assert!(!root
        .join(format!("interactions/{IXN}/interaction.md"))
        .exists());
    assert_eq!(std::fs::read_to_string(&ledger).unwrap(), dirty);
}

/// #505: logging an interaction clears a `cadence-overdue` warning — the
/// mirrored primary touch line is what the ledger-only rule sees.
#[test]
fn cadence_overdue_clears_after_interaction_logged() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // Pin `as_of`; the built-in personal pack is implicit (#551), then give
    // the person a cadence with no contact on record.
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n\n[checks]\nas_of = \"2026-10-08\"\nexample-pack.notes = \"off\"\nexample-pack.gap = \"off\"\n",
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
fn context_bundle_has_pack_facts() {
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
    // The pack opts into the ledger-sessions view; its entry carries the
    // computed balance. No shipped pack owns the legacy top-level field.
    assert_eq!(v["packs"]["example-pack@0.1"]["sessions_remaining"], 4);
}

#[test]
fn context_honors_no_ai() {
    // A local no-ai person: the demo vault is personal-only and carries no
    // no-ai record.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let no_ai = "p-01J9Z3K4QF0000000000000009";
    install_example_pack(root);
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join(format!("people/{no_ai}"))).unwrap();
    std::fs::write(
        root.join(format!("people/{no_ai}/profile.md")),
        format!("---\nid: {no_ai}\ntype: person\nname: \"Hidden Person\"\nno-ai: true\n---\n\nSecret bio.\n"),
    )
    .unwrap();
    let nid = "n-01J9Z3K4QF0000000000000008";
    std::fs::create_dir_all(root.join(format!("people/{no_ai}/notes"))).unwrap();
    std::fs::write(
        root.join(format!("people/{no_ai}/notes/{nid}.md")),
        format!(
            "---\nid: {nid}\ntype: note\nperson: {no_ai}\ndate: 2026-10-01\n---\n\nHidden note.\n"
        ),
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);

    let vroot = vault_arg(root);
    let (ok, v) = run_json(&["context", no_ai, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{v}");
    assert_eq!(v["person"]["no_ai"], true);
    assert_eq!(v["person"]["name"], Value::Null);
    assert_eq!(v["person"]["profile"], Value::Null);
    assert_eq!(v["notes"], serde_json::json!([]));
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
             birthday: --05-14\nrelationship: friend\n\
             dates: [anniversary:2020-06-15]\ncadence: 30d\n---\n\nTest bio.\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "personal fields"]);

    let (ok, full) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{full}");
    let view = &full["packs"]["personal@0.2"];
    assert_eq!(view["birthday"], "--05-14", "{full}");
    assert_eq!(view["relationship"], "friend", "{full}");
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
    let view = &stripped["packs"]["personal@0.2"];
    for field in ["birthday", "relationship", "dates"] {
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
    // `log touch` / `note add` would print and serialize the hidden
    // person's name. The by-name query gets the same generic
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
        "touch",
        "Ada Old",
        "meal",
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
        "touch",
        "Ada Old",
        "meal",
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
fn log_touch_by_name_echoes_resolved_person() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "touch",
        "Test Person",
        "meal",
        "--date",
        "2026-10-13",
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
    assert!(ledger.contains(&format!("touch {PERSON} meal")), "{ledger}");

    // Human output echoes the pick too. It says "resolving to" because the
    // line prints before the remaining validation (#537 review).
    // #747: the second call re-logs the same touch, so it passes --force;
    // the refusal for the identical touch is covered by the #747 tests,
    // and this test is about the echo.
    let (ok, stdout, stderr) = run_raw(&[
        "log",
        "touch",
        "Test Person",
        "meal",
        "--date",
        "2026-10-13",
        "--force",
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
fn log_touch_by_id_does_not_echo_a_person_object() {
    // Id writes keep their previous output shape (no `person` echo).
    let dir = make_vault();
    let root = dir.path();
    let before = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    let vroot = vault_arg(root);
    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
        "--date",
        "2026-10-13",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{v}");
    assert!(v.get("person").is_none(), "{v}");
    let after = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert!(after.starts_with(&before));
    assert!(after.contains(&format!("touch {PERSON} meal")));
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
    for expected in ["git-repo", "git-identity", "git-version", "spec", "check"] {
        assert!(ids.contains(&expected), "missing check {expected}");
    }
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
        "check", "find", "resolve", "alias", "log", "import", "note", "context", "doctor",
        "schema", "help", "mcp",
    ] {
        assert!(names.contains(&expected), "missing subcommand {expected}");
    }
    // Nested subcommands are visible too (ADR-7 `log touch` form), and the
    // removed `log session` command is gone.
    let log = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "log")
        .unwrap();
    let log_subs: Vec<&str> = log["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(log_subs.contains(&"touch"), "{log_subs:?}");
    assert!(!log_subs.contains(&"session"), "{log_subs:?}");
    let alias = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "alias")
        .unwrap();
    let alias_subs: Vec<&str> = alias["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(alias_subs.contains(&"resolve"), "{alias_subs:?}");
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
    assert!(names.contains(&"log_touch"));
    assert!(!names.contains(&"log_session"));
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
    let dir = make_vault();
    let root = dir.path();
    std::fs::write(
        root.join(format!("people/{PERSON}/profile.md")),
        format!("---\nid: {PERSON}\ntype: person\nname: \"Hidden Person\"\nno-ai: true\n---\n\nHidden body.\n"),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "no-ai fixture"]);
    let msg = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"context","arguments":{{"person":"{PERSON}"}}}}}}"#
    );
    let resps = mcp_exchange(root, &[msg.as_str()]);
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        !text.contains("Hidden Person"),
        "no-ai person name leaked through MCP: {text}"
    );
    assert!(
        !text.contains("Hidden body"),
        "no-ai body leaked through MCP: {text}"
    );
    let body: Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["ok"], true);
}

#[test]
fn mcp_note_add_entity_and_context_target_a_pack_type() {
    let dir = make_place_vault();
    let root = dir.path();
    std::fs::create_dir_all(root.join(format!("places/{PLACE}"))).unwrap();
    std::fs::write(
        root.join(format!("places/{PLACE}/place.md")),
        format!(
            "---\nid: {PLACE}\ntype: place\nname: Example Studio\naddress: 1 Example Way\n---\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "place fixture"]);
    let scratch = tempfile::tempdir().unwrap();
    let body = scratch.path().join("body.md");
    std::fs::write(&body, "Liked the back room.\n").unwrap();
    let msg = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"note_add","arguments":{{"entity":"{PLACE}","body_file":{}}}}}}}"#,
        serde_json::to_string(&body.display().to_string()).unwrap()
    );
    let resps = mcp_exchange(root, &[msg.as_str()]);
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    let note: Value = serde_json::from_str(text).unwrap();
    assert_eq!(note["ok"], true, "{note}");
    assert_eq!(note["command"], "note-add");
    let note_path = root.join(note["path"].as_str().unwrap());
    let contents = std::fs::read_to_string(&note_path).unwrap();
    assert!(contents.contains(&format!("entity: {PLACE}")), "{contents}");

    let context_msg = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"context","arguments":{{"person":"{PLACE}"}}}}}}"#
    );
    let resps = mcp_exchange(root, &[context_msg.as_str()]);
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    let context: Value = serde_json::from_str(text).unwrap();
    assert_eq!(context["ok"], true, "{context}");
    assert_eq!(context["entity"]["kind"], "place");
    assert_eq!(context["notes"][0]["id"], note["id"]);

    let schema_msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"schema","arguments":{}}}"#;
    let resps = mcp_exchange(root, &[schema_msg]);
    let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
    let schema: Value = serde_json::from_str(text).unwrap();
    assert_eq!(schema["ok"], true, "{schema}");
    assert!(
        schema["contract"]["record_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|decl| decl["name"] == "place"),
        "{schema}"
    );
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
// The guarantee below is producer-independent, so it is tested with a
// pack warning. No code change was needed: every gate already thresholds on
// errors (write.rs pre/post checks and doctor use CheckOptions::default() ->
// Error; the inbox merge passes fail_on: Error explicitly). These tests lock
// that in.

/// A vault whose only findings are warnings: one untagged entry fires
/// `W_EXAMPLE_UNTAGGED` (warning) plus the no-notes warning. No errors can
/// arise from this fixture at any as-of: every rule that can fire here is
/// warning-severity.
fn make_warning_vault() -> tempfile::TempDir {
    let dir = make_vault();
    let root = dir.path();
    // Untagged use: consumes a slot, fires W_EXAMPLE_UNTAGGED.
    let ledger = root.join("ledger/2026/10.cfd");
    let mut text = std::fs::read_to_string(&ledger).unwrap();
    text.push_str(&format!("2026-10-02 use {PERSON} 60m\n"));
    std::fs::write(&ledger, text).unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "untagged entry"]);
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
        finding_codes(&v).contains(&"W_EXAMPLE_UNTAGGED".to_string()),
        "{v}"
    );
    // The write succeeds despite the warnings: exactly one new commit.
    let (ok, v) = run_json(&[
        "log",
        "touch",
        PERSON,
        "meal",
        "--date",
        "2026-10-13",
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
        "init + untagged session line + the new touch"
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
    // Client: grant 4 units + one entry on 2026-10-01, so units_remaining
    // is 3 and the gap clock starts 2026-10-01.
    let dir = make_vault();
    let root = dir.path();
    let ledger = root.join("ledger/2026/10.cfd");
    let mut text = std::fs::read_to_string(&ledger).unwrap();
    text.push_str(&format!("2026-10-01 use {PERSON} 60m full\n"));
    std::fs::write(&ledger, text).unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "entry"]);
    // 7 days after the last activity: inside the 45-day gap window.
    let (_, early) = check_report(root, &["--as-of", "2026-10-08"]);
    assert!(
        !finding_codes(&early).contains(&"E_EXAMPLE_GAP".to_string()),
        "{early}"
    );
    // 61 days after: outside the window, the gap warning fires.
    let (_, late) = check_report(root, &["--as-of", "2026-12-01"]);
    assert!(
        finding_codes(&late).contains(&"E_EXAMPLE_GAP".to_string()),
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

/// Append a no-op `personal@0.2` listing next to `example-pack@0.1` and commit
/// the config change. #551: the built-in personal pack is implicit, so the
/// listing changes nothing; the commit keeps the fixture's commit counts.
fn enable_personal(root: &Path) {
    let toml_path = root.join("confidant.toml");
    let toml = std::fs::read_to_string(&toml_path).unwrap();
    std::fs::write(
        &toml_path,
        toml.replace(
            "packs = [\"example-pack@0.1\"]",
            "packs = [\"example-pack@0.1\", \"personal@0.2\"]",
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "enable personal"]);
}

#[test]
fn log_touch_works_without_listing_personal() {
    // #551: the built-in personal pack is implicit, so `log touch` works in
    // a vault that only lists the external pack.
    let dir = make_vault();
    let vroot = vault_arg(dir.path());
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
    assert!(ok, "{v}");
}

#[test]
fn log_touch_writes_one_commit_and_appears_in_context() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    // enable_personal commits a no-op personal@0.2 listing (#551).
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
fn log_touch_video_appears_in_context() {
    // #735 follow-up (review 5643154823): a logged `video` touch reads
    // back through `context` with kind "video".
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let (ok, added) = run_json(&[
        "log",
        "touch",
        PERSON,
        "video",
        "--date",
        "2026-10-05",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{added}");

    let (ok, ctx) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{ctx}");
    assert_eq!(ctx["touchpoints"].as_array().unwrap().len(), 1, "{ctx}");
    assert_eq!(ctx["touchpoints"][0]["kind"], "video");
}

#[test]
fn log_touch_duration_and_mode_appear_in_context() {
    // #741: duration normalizes to minutes and mode rides the line, so both
    // read back through `context`.
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let (ok, added) = run_json(&log_touch_args(
        "meal",
        &vroot,
        &["--duration", "1h30m", "--mode", "one-on-one"],
    ));
    assert!(ok, "{added}");
    let line = added["lines"][0].as_str().unwrap();
    assert!(line.contains("duration:90m"), "{line}");
    assert!(line.contains("mode:one-on-one"), "{line}");

    let (ok, ctx) = run_json(&["context", PERSON, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{ctx}");
    assert_eq!(ctx["touchpoints"][0]["duration_minutes"], 90, "{ctx}");
    assert_eq!(ctx["touchpoints"][0]["mode"], "one-on-one", "{ctx}");
    assert_eq!(
        ctx["packs"]["personal@0.2"]["recent_touches"][0]["duration_minutes"], 90,
        "{ctx}"
    );
}

#[test]
fn log_touch_bad_duration_and_mode_are_usage_errors() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    for extra in [
        vec!["--duration", "soon"],
        vec!["--duration", "0m"],
        vec!["--mode", "crowd"],
    ] {
        let (ok, v) = run_json(&log_touch_args("meal", &vroot, &extra));
        assert!(!ok, "{extra:?}: {v}");
        assert_eq!(v["error"]["code"], "usage_error", "{extra:?}: {v}");
    }
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
        message.contains("call, text, email, meet, meal, event, gift, video, other"),
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
        "call", "text", "email", "meet", "meal", "event", "gift", "video", "other",
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
        message.contains("call, text, email, meet, meal, event, gift, video, other"),
        "the error must list the v1 kinds: {message}"
    );
}

// ---------------------------------------------------------------------------
// #747: semantic idempotency for `log touch`
// ---------------------------------------------------------------------------

fn log_touch_args<'a>(kind: &'a str, vroot: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "log",
        "touch",
        PERSON,
        kind,
        "--date",
        "2026-10-05",
        "--json",
        "--no-input",
        "--vault",
        vroot,
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn log_touch_refuses_identical_touch_and_force_logs_it() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let (ok, _) = run_json(&log_touch_args("meal", &vroot, &[]));
    assert!(ok);
    let before = commits(root);

    // Same person, date, kind — refused, nothing written, no new commit.
    // A different src: does not make it distinct.
    let (ok, v) = run_json(&log_touch_args("meal", &vroot, &["--src", "zoom/t-9"]));
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_ALREADY_EXISTS");
    let fix = v["error"]["fix"].as_str().unwrap();
    assert!(
        fix.contains("--force"),
        "the refusal must name the escape hatch: {fix}"
    );
    assert_eq!(commits(root), before, "a refused touch writes nothing");

    // A different kind the same day is a different touchpoint.
    let (ok, v) = run_json(&log_touch_args("call", &vroot, &[]));
    assert!(ok, "{v}");

    // --force logs the genuine repeat.
    let (ok, v) = run_json(&log_touch_args("meal", &vroot, &["--force"]));
    assert!(ok, "{v}");

    // And `check` flags the forced repeat as a warning on the later line.
    let (ok, report) = run_json(&["check", "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{report}");
    let dups: Vec<&Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "W_DUPLICATE_TOUCH")
        .collect();
    assert_eq!(dups.len(), 1, "{report}");
    assert_eq!(dups[0]["severity"], "warning");
}

#[test]
fn log_touch_refusal_writes_no_note_record() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let (ok, _) = run_json(&log_touch_args("meal", &vroot, &[]));
    assert!(ok);
    let notes_dir = root.join(format!("people/{PERSON}/notes"));
    let before = std::fs::read_dir(&notes_dir)
        .map(|d| d.count())
        .unwrap_or(0);

    // Refused even with a --note: no note record may be left behind.
    let (ok, v) = run_json(&log_touch_args(
        "meal",
        &vroot,
        &["--note", "Second meal note"],
    ));
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_ALREADY_EXISTS");
    let after = std::fs::read_dir(&notes_dir)
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(after, before, "a refused touch must not stage a note");
}

/// #747 review: when the two identities disagree — same `--request-id`,
/// same person/date/kind, different `--note` — the input is both a
/// semantic duplicate (refusal would say `E_ALREADY_EXISTS`) and a
/// request-id conflict (write path would say `E_IDEMPOTENCY_CONFLICT`).
/// The spec promises the write path wins.
#[test]
fn log_touch_request_id_conflict_beats_semantic_refusal() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    let rid = "01J9Z3K4QF00000000000000ID";
    let (ok, v) = run_json(&log_touch_args("meal", &vroot, &["--request-id", rid]));
    assert!(ok, "{v}");
    let before = commits(root);

    // Same person/date/kind, same request-id, different note: the
    // write path's conflict, not the semantic refusal.
    let (ok, v) = run_json(&log_touch_args(
        "meal",
        &vroot,
        &["--note", "A different meal note", "--request-id", rid],
    ));
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_IDEMPOTENCY_CONFLICT");
    assert_eq!(commits(root), before, "a conflict writes nothing");
}

/// #741: a rich touch keeps request-id idempotency — an exact retry replays,
/// and changing the duration under the same id is a conflict — while a plain
/// touch keeps the historical canonical shape.
#[test]
fn log_touch_rich_request_id_replays_and_conflicts() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    enable_personal(root);

    const RID: &str = "01J9Z3K4QF00000000000000RD";
    let rich = |duration: &'static str| {
        log_touch_args(
            "meal",
            &vroot,
            &[
                "--duration",
                duration,
                "--mode",
                "group",
                "--request-id",
                RID,
            ],
        )
    };
    let (ok, v) = run_json(&rich("60m"));
    assert!(ok, "{v}");
    let commit = v["commit"].as_str().unwrap().to_owned();
    let after_first = commits(root);

    let (ok, v) = run_json(&rich("60m"));
    assert!(ok, "{v}");
    assert_eq!(v["idempotent"], true, "{v}");
    assert_eq!(v["commit"], commit, "{v}");
    assert_eq!(commits(root), after_first, "the replay committed again");

    let (ok, v) = run_json(&rich("30m"));
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_IDEMPOTENCY_CONFLICT", "{v}");
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

/// #751: the profile body is the agent-maintained summary, so an
/// agent-written paragraph's dated marker lives in the body. A `record edit`
/// replaces the whole file, and the writer keeps the marker (and the
/// operator's `human_note` field) exactly when the replacement carries them.
#[test]
fn record_edit_keeps_profile_authorship_markers() {
    let dir = make_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let inputs = tempfile::tempdir().unwrap();
    let edited = inputs.path().join("edited.md");
    let body = "Enrichment, 2026-10: Met at Example Conf; two meetings since.\n";
    let record = person_record_md(PERSON, "Ada Example", body).replace(
        "name: Ada Example\n",
        "name: Ada Example\nhuman_note: The part I remember.\n",
    );
    std::fs::write(&edited, record).unwrap();

    let (ok, v) = run_json(&edit_args(PERSON, edited.to_str().unwrap(), &vroot, &[]));
    assert!(ok, "{v}");
    let on_disk =
        std::fs::read_to_string(root.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert!(on_disk.contains("Enrichment, 2026-10:"), "{on_disk}");
    // The canonical writer may quote the scalar; the value survives.
    assert!(on_disk.contains("human_note:"), "{on_disk}");
    assert!(on_disk.contains("The part I remember."), "{on_disk}");
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

// ---------------------------------------------------------------------------
// #746 corrections and retirement (spec 0.4)
// ---------------------------------------------------------------------------

const CP_PERSON: &str = "p-01J9Z3K4QF0000000000000010";
const CP_NOTE: &str = "n-01J9Z3K4QF0000000000000011";
const CP_DATE: &str = "2026-11-02";
const CP_REQUEST: &str = "01J9Z3K4QF7F3A000000000099";

fn make_corrections_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.4\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000000\"\n\n[checks]\nas_of = \"2026-11-02\"\n",
    )
    .unwrap();
    let person_dir = root.join(format!("people/{CP_PERSON}"));
    std::fs::create_dir_all(person_dir.join("notes")).unwrap();
    std::fs::write(
        person_dir.join("profile.md"),
        format!(
            "---\nid: {CP_PERSON}\ntype: person\nname: \"Correction Person\"\n---\n\nFake bio.\n"
        ),
    )
    .unwrap();
    std::fs::write(
        person_dir.join(format!("notes/{CP_NOTE}.md")),
        format!("---\nid: {CP_NOTE}\ntype: note\nperson: {CP_PERSON}\ndate: 2026-10-01\n---\n\nFake note body.\n"),
    )
    .unwrap();
    let ledger = root.join("ledger/2026");
    std::fs::create_dir_all(&ledger).unwrap();
    std::fs::write(
        ledger.join("10.cfd"),
        format!("2026-10-01 touch {CP_PERSON} call\n2026-10-01 touch {CP_PERSON} call\n"),
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    dir
}

fn find_refs(root: &Path, query: &str) -> Vec<String> {
    let v = run_json(&["find", query, "--json", "--vault", &vault_arg(root)]).1;
    v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|hit| hit["ref"].as_str().map(str::to_owned))
        .collect()
}

/// Write a scratch record file and return its path for `--file`.
fn record_file(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path.display().to_string()
}

#[test]
fn retract_dry_run_apply_request_id_and_find_output() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let before = commits(root);
    let refs = find_refs(root, "call");
    assert_eq!(refs.len(), 2, "{refs:?}");
    let target = refs[1].clone();
    let (ok, text, _) = run_raw(&["find", "call", "--no-input", "--vault", &vault_arg(root)]);
    assert!(ok, "{text}");
    assert!(
        text.contains("line:"),
        "ledger hit lost its ref in text: {text}"
    );

    let (ok, dry) = run_json(&[
        "retract",
        CP_PERSON,
        "--line",
        &target,
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--dry-run",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{dry}");
    assert_eq!(dry["dry_run"], true, "{dry}");
    // #770: `retract` is a repairing write, so apply skips the pre-check;
    // the dry run skips it too. The post-write check still cannot run.
    assert_eq!(dry["checks"]["pre"], "skipped", "{dry}");
    assert_eq!(dry["checks"]["post"], "skipped", "{dry}");
    assert_eq!(commits(root), before, "dry run must not commit");
    assert!(!root.join("ledger/2026/11.cfd").exists());

    let (ok, applied) = run_json(&[
        "retract",
        CP_PERSON,
        "--line",
        &target,
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--request-id",
        CP_REQUEST,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{applied}");
    assert!(applied["commit"].as_str().is_some(), "{applied}");
    assert_eq!(commits(root), before + 1);
    let ledger = std::fs::read_to_string(root.join("ledger/2026/11.cfd")).unwrap();
    assert!(ledger.contains("retract"), "{ledger}");
    assert!(ledger.contains("reason:duplicate"), "{ledger}");

    let (ok, check) = run_json(&["check", "--json", "--vault", &vault_arg(root)]);
    assert!(ok, "{check}");
    assert_eq!(check["summary"]["warnings"], 0, "{check}");
    assert_eq!(find_refs(root, "call").len(), 1);

    // The retry replays the recorded request instead of refusing the
    // now-voided target.
    let (ok, replay) = run_json(&[
        "retract",
        CP_PERSON,
        "--line",
        &target,
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--request-id",
        CP_REQUEST,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{replay}");
    assert_eq!(replay["idempotent"], true, "{replay}");
    assert_eq!(commits(root), before + 1);
}

#[test]
fn bulk_retract_clears_a_duplicate_batch_in_one_commit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.4\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000000\"\n\n[checks]\nas_of = \"2026-11-02\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join(format!("people/{CP_PERSON}"))).unwrap();
    std::fs::write(
        root.join(format!("people/{CP_PERSON}/profile.md")),
        format!("---\nid: {CP_PERSON}\ntype: person\nname: \"Correction Person\"\n---\n"),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
    let mut lines = String::new();
    for _ in 0..41 {
        lines.push_str(&format!("2026-10-01 touch {CP_PERSON} call\n"));
    }
    std::fs::write(root.join("ledger/2026/10.cfd"), lines).unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    let before = commits(root);
    let (ok, out) = run_json(&[
        "retract",
        CP_PERSON,
        "--verb",
        "touch",
        "--match-date",
        "2026-10-01",
        "--keep",
        "1",
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{out}");
    assert!(out["commit"].as_str().is_some(), "{out}");
    assert_eq!(out["targets"].as_array().unwrap().len(), 40, "{out}");
    assert_eq!(commits(root), before + 1);
    let ledger = std::fs::read_to_string(root.join("ledger/2026/11.cfd")).unwrap();
    assert_eq!(ledger.matches("retract ").count(), 40, "{ledger}");
    let (ok, check) = run_json(&["check", "--json", "--vault", &vault_arg(root)]);
    assert!(ok, "{check}");
    assert_eq!(check["summary"]["warnings"], 0, "{check}");
    assert_eq!(find_refs(root, "call").len(), 1);
}

#[test]
fn correct_appends_replacement_and_context_shows_it() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let before = commits(root);
    let target = find_refs(root, "call")[0].clone();
    let replacement = format!("2026-10-01 touch {CP_PERSON} meet");

    let (ok, out) = run_json(&[
        "correct",
        CP_PERSON,
        "--line",
        &target,
        "--replacement",
        &replacement,
        "--reason",
        "wrong-kind",
        "--date",
        CP_DATE,
        "--request-id",
        CP_REQUEST,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{out}");
    assert!(out["commit"].as_str().is_some(), "{out}");
    assert_eq!(commits(root), before + 1);
    let october = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    let november = std::fs::read_to_string(root.join("ledger/2026/11.cfd")).unwrap();
    assert!(october.contains("meet"), "{october}");
    assert!(november.contains("replace:"), "{november}");
    assert!(november.contains("reason:wrong-kind"), "{november}");
    let (ok, context) = run_json(&[
        "context",
        CP_PERSON,
        "--json",
        "--no-input",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{context}");
    let touchpoints = context["touchpoints"].as_array().unwrap();
    // One of the two identical call lines was corrected; the other remains.
    assert_eq!(touchpoints.len(), 2, "{context}");
    assert_eq!(
        touchpoints.iter().filter(|t| t["kind"] == "call").count(),
        1,
        "{context}"
    );
    assert_eq!(
        touchpoints.iter().filter(|t| t["kind"] == "meet").count(),
        1,
        "{context}"
    );
    let (_ok, check) = run_json(&["check", "--json", "--vault", &vault_arg(root)]);
    assert_eq!(check["summary"]["warnings"], 0, "{check}");

    let (ok, replay) = run_json(&[
        "correct",
        CP_PERSON,
        "--line",
        &target,
        "--replacement",
        &replacement,
        "--reason",
        "wrong-kind",
        "--date",
        CP_DATE,
        "--request-id",
        CP_REQUEST,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{replay}");
    assert_eq!(replay["idempotent"], true, "{replay}");
    assert_eq!(commits(root), before + 1);
}

#[test]
fn record_retire_hides_agent_reads_and_operator_sees_the_badge() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let (ok, out) = run_json(&[
        "record",
        "retire",
        CP_PERSON,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{out}");
    assert_eq!(out["retired"], true, "{out}");
    let profile =
        std::fs::read_to_string(root.join(format!("people/{CP_PERSON}/profile.md"))).unwrap();
    assert!(profile.contains("retired: true"), "{profile}");

    assert!(find_refs(root, "Correction Person").is_empty());
    let (ok, op) = run_json(&[
        "find",
        "Correction Person",
        "--for-operator",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{op}");
    assert_eq!(op["matches"].as_array().unwrap().len(), 1, "{op}");

    let (ok, list) = run_json(&["record", "list", "--json", "--vault", &vault_arg(root)]);
    assert!(ok, "{list}");
    assert!(list["records"].as_array().unwrap().is_empty(), "{list}");
    let (ok, op_list) = run_json(&[
        "record",
        "list",
        "--for-operator",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{op_list}");
    let entry = &op_list["records"][0];
    assert_eq!(entry["id"], CP_PERSON, "{op_list}");
    assert_eq!(entry["retired"], true, "{op_list}");

    let (ok, show) = run_json(&[
        "record",
        "show",
        CP_PERSON,
        "--for-edit",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{show}");
    assert_eq!(show["retired"], true, "{show}");
    let (ok, _out, err) = run_raw(&[
        "record",
        "show",
        CP_PERSON,
        "--for-edit",
        "--no-input",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{err}");
    assert!(err.contains("retired"), "missing retired hint: {err}");

    let (ok, err) = run_json(&[
        "context",
        CP_PERSON,
        "--json",
        "--no-input",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(!ok, "{err}");
    assert_eq!(err["error"]["code"], "E_NOT_FOUND", "{err}");

    let (ok, err) = run_json(&[
        "log",
        "touch",
        CP_PERSON,
        "meet",
        "--date",
        "2026-10-13",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(!ok, "{err}");
    assert_eq!(err["error"]["code"], "E_INVALID", "{err}");

    let (ok, out) = run_json(&[
        "record",
        "unretire",
        CP_PERSON,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{out}");
    assert_eq!(out["retired"], false, "{out}");
    let (ok, found) = run_json(&[
        "find",
        "Correction Person",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{found}");
    assert_eq!(found["matches"].as_array().unwrap().len(), 1, "{found}");

    // Notes are records too; `record retire` keeps the note file and hides
    // it from agent reads.
    let (ok, out) = run_json(&[
        "record",
        "retire",
        CP_NOTE,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{out}");
    assert_eq!(out["retired"], true, "{out}");
    let (ok, hidden) = run_json(&[
        "find",
        "Fake note body",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(ok, "{hidden}");
    assert!(hidden["matches"].as_array().unwrap().is_empty(), "{hidden}");
}

/// #838: a new front-matter reference to a retired record is refused on both
/// write paths.
#[test]
fn record_add_refuses_new_references_to_a_retired_record() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let live = "p-01J9Z3K4QF0000000000000012";
    add_person(root, live, "Live Example", "");
    let (ok, out) = run_json(&["record", "retire", CP_PERSON, "--json", "--vault", &vroot]);
    assert!(ok, "{out}");
    let before = commits(root);
    let scratch = tempfile::tempdir().unwrap();

    // A direct `person:` reference.
    let ixn = "i-01J9Z3K4QF0000000000000020";
    let file = record_file(
        scratch.path(),
        "interaction.md",
        &format!(
            "---\nid: {ixn}\ntype: interaction\nperson: {CP_PERSON}\n\
             name: \"Retired meetup\"\ndate: 2026-10-13\n---\n\nFake body.\n"
        ),
    );
    let (ok, err) = run_json(&[
        "record",
        "add",
        "--file",
        &file,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{err}");
    assert_eq!(err["error"]["code"], "E_INVALID", "{err}");
    let message = err["error"]["message"].as_str().unwrap();
    assert!(message.contains(CP_PERSON), "{message}");
    assert!(message.contains("retired"), "{message}");
    assert!(err["error"]["fix"].as_str().unwrap().contains("unretire"));
    assert_eq!(
        commits(root),
        before,
        "a refused record add commits nothing"
    );
    assert!(!root
        .join(format!("interactions/{ixn}/interaction.md"))
        .exists());

    // A `with:` participant on an interaction whose primary is live.
    let with_ixn = "i-01J9Z3K4QF0000000000000021";
    let with_file = record_file(
        scratch.path(),
        "with.md",
        &format!(
            "---\nid: {with_ixn}\ntype: interaction\nperson: {live}\n\
             with: [{CP_PERSON}]\nname: \"Retired participant\"\ndate: 2026-10-13\n---\n\nFake body.\n"
        ),
    );
    let (ok, err) = run_json(&[
        "record",
        "add",
        "--file",
        &with_file,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{err}");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains(CP_PERSON));

    // An edge endpoint.
    let edge = "e-01J9Z3K4QF0000000000000022";
    let edge_file = record_file(
        scratch.path(),
        "edge.md",
        &format!("---\nid: {edge}\ntype: edge\na: {live}\nb: {CP_PERSON}\nkind: colleague\n---\n"),
    );
    let (ok, err) = run_json(&[
        "record",
        "add",
        "--file",
        &edge_file,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{err}");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains(CP_PERSON));
    assert_eq!(commits(root), before);
    // No mirrored touchpoint was appended either (the gate runs before the
    // write, so `with:` cannot smuggle a retired reference into the ledger).
    let october = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
    assert!(!october.contains("2026-10-13"), "{october}");

    // Control: a live reference is not over-blocked.
    let live_ixn = "i-01J9Z3K4QF0000000000000023";
    let live_file = record_file(
        scratch.path(),
        "live.md",
        &format!(
            "---\nid: {live_ixn}\ntype: interaction\nperson: {live}\n\
             name: \"Live meetup\"\ndate: 2026-10-13\n---\n\nFake body.\n"
        ),
    );
    let (ok, out) = run_json(&[
        "record",
        "add",
        "--file",
        &live_file,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{out}");
    assert_eq!(commits(root), before + 1);
}

/// #838: an existing reference is grandfathered on edit, a newly added one is
/// refused.
#[test]
fn record_edit_refuses_a_new_retired_reference_but_keeps_an_existing_one() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let scratch = tempfile::tempdir().unwrap();
    let ixn = "i-01J9Z3K4QF0000000000000024";
    let original = record_file(
        scratch.path(),
        "interaction.md",
        &format!(
            "---\nid: {ixn}\ntype: interaction\nperson: {CP_PERSON}\n\
             name: \"Old meetup\"\ndate: 2026-10-13\n---\n\nFake body.\n"
        ),
    );
    let (ok, out) = run_json(&[
        "record",
        "add",
        "--file",
        &original,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{out}");
    let (ok, out) = run_json(&["record", "retire", CP_PERSON, "--json", "--vault", &vroot]);
    assert!(ok, "{out}");
    let before = commits(root);

    // Keeping the now-retired `person:` is allowed: the reference was
    // already in the stored file.
    let kept = record_file(
        scratch.path(),
        "kept.md",
        &format!(
            "---\nid: {ixn}\ntype: interaction\nperson: {CP_PERSON}\n\
             name: \"Renamed meetup\"\ndate: 2026-10-13\n---\n\nFake body, edited.\n"
        ),
    );
    let (ok, out) = run_json(&[
        "record",
        "edit",
        ixn,
        "--file",
        &kept,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{out}");
    assert_eq!(commits(root), before + 1);

    // A *second* retired target cannot be introduced as a new `with:`
    // participant.
    let retired2 = "p-01J9Z3K4QF0000000000000013";
    add_person(root, retired2, "Second Retired", "");
    let (ok, out) = run_json(&["record", "retire", retired2, "--json", "--vault", &vroot]);
    assert!(ok, "{out}");
    let before = commits(root);
    let with_added = record_file(
        scratch.path(),
        "with.md",
        &format!(
            "---\nid: {ixn}\ntype: interaction\nperson: {CP_PERSON}\n\
             with: [{retired2}]\nname: \"Renamed meetup\"\ndate: 2026-10-13\n---\n\nFake body, edited.\n"
        ),
    );
    let (ok, err) = run_json(&[
        "record",
        "edit",
        ixn,
        "--file",
        &with_added,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{err}");
    assert_eq!(err["error"]["code"], "E_INVALID", "{err}");
    let message = err["error"]["message"].as_str().unwrap();
    assert!(message.contains(retired2), "{message}");
    assert!(message.contains("retired"), "{message}");
    assert_eq!(commits(root), before, "a refused edit commits nothing");
}

/// #838: retirement is an ordinary check-gated write, not a repairing one:
/// a record with an error cannot be retired until the finding is fixed.
#[test]
fn record_retire_is_check_gated_on_record_findings() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let broken = "n-01J9Z3K4QF0000000000000019";
    let note_path = root.join(format!("people/{CP_PERSON}/notes/{broken}.md"));
    std::fs::write(
        &note_path,
        format!(
            "---\nid: {broken}\ntype: note\n\
             person: p-01J9Z3K4QF9999999999999999\ndate: 2026-10-05\n---\n\nFake broken note.\n"
        ),
    )
    .unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "broken note fixture"]);
    let before = commits(root);
    let original = std::fs::read_to_string(&note_path).unwrap();

    let (ok, report) = run_json(&[
        "record",
        "retire",
        broken,
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(!ok, "{report}");
    assert_eq!(report["ok"], false, "{report}");
    assert!(
        report["summary"]["errors"].as_u64().unwrap() > 0,
        "{report}"
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "E_DANGLING_REF"),
        "{report}"
    );
    assert_eq!(commits(root), before, "the gate blocked the write");
    assert_eq!(
        std::fs::read_to_string(&note_path).unwrap(),
        original,
        "retirement is not a repairing write"
    );
    assert!(
        !original.contains("retired: true"),
        "the record must stay live until fixed"
    );
}

/// #770: a record with committed merge-conflict markers is refused by apply;
/// a dry run reads the same bytes and must refuse it too.
#[test]
fn record_retire_dry_run_refuses_a_conflicted_record() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let vroot = vault_arg(root);
    let profile = root.join(format!("people/{CP_PERSON}/profile.md"));
    let conflicted = format!(
        "---\nid: {CP_PERSON}\ntype: person\nname: \"Correction Person\"\n---\n\n\
         <<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\n"
    );
    std::fs::write(&profile, &conflicted).unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "conflicted fixture"]);
    let before = commits(root);
    for flag in [Some("--dry-run"), None] {
        let mut args = vec![
            "record",
            "retire",
            CP_PERSON,
            "--json",
            "--no-input",
            "--vault",
            &vroot,
        ];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let (ok, err) = run_json(&args);
        assert!(!ok, "{err}");
        assert_eq!(err["error"]["code"], "E_CONFLICT", "{err}");
    }
    assert_eq!(commits(root), before, "neither path committed");
    assert_eq!(std::fs::read_to_string(&profile).unwrap(), conflicted);
}

/// #838: the operator `context` path lists superseded lines with a badge; the
/// agent path returns the effective view and never carries the field.
#[test]
fn context_operator_lists_superseded_touchpoints() {
    let vault = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vaults/corrections-0.4");
    let vroot = vault.display().to_string();
    let ada = "p-01M3TC5H00MPJG000000000000";

    let (ok, agent) = run_json(&["context", ada, "--json", "--no-input", "--vault", &vroot]);
    assert!(ok, "{agent}");
    let agent_touchpoints = agent["touchpoints"].as_array().unwrap();
    assert_eq!(agent_touchpoints.len(), 1, "{agent}");
    assert!(
        agent_touchpoints[0].get("superseded").is_none(),
        "the agent path must not carry the operator badge: {agent}"
    );

    let (ok, operator) = run_json(&[
        "context",
        ada,
        "--for-operator",
        "--json",
        "--no-input",
        "--vault",
        &vroot,
    ]);
    assert!(ok, "{operator}");
    assert_eq!(operator["for_operator"], true, "{operator}");
    let operator_touchpoints = operator["touchpoints"].as_array().unwrap();
    assert_eq!(operator_touchpoints.len(), 2, "{operator}");
    assert!(
        operator_touchpoints[0].get("superseded").is_none(),
        "live lines stay unbadged: {operator}"
    );
    assert_eq!(
        operator_touchpoints[1]["superseded"], true,
        "the voided duplicate must be shown and badged: {operator}"
    );
    assert!(
        !agent.to_string().contains("superseded"),
        "no superseded marker leaks to the agent path: {agent}"
    );
}

#[test]
fn retract_is_refused_on_spec_03() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.3\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join(format!("people/{CP_PERSON}"))).unwrap();
    std::fs::write(
        root.join(format!("people/{CP_PERSON}/profile.md")),
        format!("---\nid: {CP_PERSON}\ntype: person\nname: \"Correction Person\"\n---\n"),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
    std::fs::write(
        root.join("ledger/2026/10.cfd"),
        format!("2026-10-01 touch {CP_PERSON} call\n"),
    )
    .unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    let refs = find_refs(root, "call");
    let (ok, err) = run_json(&[
        "retract",
        CP_PERSON,
        "--line",
        &refs[0],
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(!ok, "{err}");
    assert_eq!(err["error"]["code"], "E_INVALID", "{err}");
}

#[test]
fn retract_refuses_a_dirty_month_file() {
    let dir = make_corrections_vault();
    let root = dir.path();
    let target = find_refs(root, "call")[1].clone();
    let draft_path = root.join("ledger/2026/11.cfd");
    let mut draft =
        std::fs::read_to_string(&draft_path).unwrap_or_else(|_| "; local draft\n".to_owned());
    draft.push_str("; uncommitted\n");
    std::fs::write(draft_path, draft).unwrap();
    let before = commits(root);
    // #770: dry run and apply agree on the dirty-target refusal.
    let (ok, dry) = run_json(&[
        "retract",
        CP_PERSON,
        "--line",
        &target,
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--dry-run",
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(!ok, "{dry}");
    assert_eq!(dry["error"]["code"], "E_CONFLICT", "{dry}");
    assert_eq!(commits(root), before, "dry run committed nothing");

    let (ok, err) = run_json(&[
        "retract",
        CP_PERSON,
        "--line",
        &target,
        "--reason",
        "duplicate",
        "--date",
        CP_DATE,
        "--json",
        "--vault",
        &vault_arg(root),
    ]);
    assert!(!ok, "{err}");
    assert_eq!(err["error"]["code"], "E_CONFLICT", "{err}");
    assert_eq!(commits(root), before, "nothing committed");
}
