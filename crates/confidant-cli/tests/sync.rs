//! #665: `confidant sync`, the explicit vault sync boundary.
//!
//! Read-only by default (fetch + report), `--pull`/`--push` explicit and
//! confirmed, and a plaintext vault is refused before any network access.
//! Every remote here is a local `file://` bare repository; all data is fake.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// Run git in `dir`, asserting success, and return stdout.
#[cfg(unix)]
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[cfg(unix)]
fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.name", "Confidant Test"]);
    git(dir, &["config", "user.email", "test@example.invalid"]);
}

/// A real vault (created through `init --create`) plus a local bare remote
/// it has pushed to. The vault's branch is `main` with `origin/main` as its
/// upstream.
#[cfg(unix)]
struct SyncVault {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
    remote: PathBuf,
    url: String,
}

#[cfg(unix)]
impl SyncVault {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = Confidant Test\n\temail = test@example.invalid\n",
        )
        .unwrap();

        let vault = tmp.path().join("vault");
        let out = Command::new(bin())
            .args(["init", "--create", "--no-input", "--json", "--vault"])
            .arg(&vault)
            .env("HOME", &home)
            .env("CONFIDANT_OFFLINE", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "init --create failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        git(&vault, &["config", "user.name", "Confidant Test"]);
        git(&vault, &["config", "user.email", "test@example.invalid"]);

        let remote = tmp.path().join("remote.git");
        git(
            tmp.path(),
            &[
                "init",
                "-q",
                "--bare",
                "-b",
                "main",
                remote.to_str().unwrap(),
            ],
        );
        let url = format!("file://{}", remote.display());
        git(&vault, &["remote", "add", "origin", &url]);
        git(&vault, &["push", "-q", "-u", "origin", "main"]);

        Self {
            _tmp: tmp,
            home,
            vault,
            remote,
            url,
        }
    }

    /// A second clone of the same bare remote, for commits this vault has
    /// not seen yet.
    fn other_clone(&self) -> PathBuf {
        let dir = self._tmp.path().join("other");
        git(
            self._tmp.path(),
            &["clone", "-q", &self.url, dir.to_str().unwrap()],
        );
        git(&dir, &["config", "user.name", "Other Device"]);
        git(&dir, &["config", "user.email", "other@example.invalid"]);
        dir
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .arg("--vault")
            .arg(&self.vault)
            .env("HOME", &self.home)
            .env("CONFIDANT_OFFLINE", "1");
        cmd.output().unwrap()
    }

    fn run_json(&self, args: &[&str]) -> (i32, Value) {
        let out = self.run(args);
        let status = out.status.code().unwrap_or(-1);
        let value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?} did not print JSON ({e}); stderr={}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (status, value)
    }
}

#[cfg(unix)]
fn assert_ok(status: i32, v: &Value) {
    assert_eq!(status, 0, "expected success: {v}");
    assert_eq!(v["ok"], true, "{v}");
}

#[cfg(unix)]
#[test]
fn dry_run_reports_ahead_and_never_contacts_the_remote() {
    let fixture = SyncVault::new();
    git(
        &fixture.vault,
        &["commit", "-q", "--allow-empty", "-m", "local"],
    );
    let local = git(&fixture.vault, &["rev-parse", "HEAD"]);
    // macOS resolves the temp dir's `/var` to `/private/var`; compare the
    // canonical paths so the assertion is platform-independent.
    let own = fixture.vault.canonicalize().unwrap().display().to_string();

    let (status, v) = fixture.run_json(&["sync", "--dry-run", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["ahead"], 1, "{v}");
    assert_eq!(v["behind"], 0, "{v}");
    assert_eq!(v["remote"], "origin", "{v}");
    assert_eq!(v["branch"], "main", "{v}");
    assert_eq!(v["upstream"], "origin/main", "{v}");
    assert_eq!(v["crypto_mode"], "plaintext", "{v}");
    assert_eq!(v["fetched"], false, "{v}");
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(v["applied"], false, "{v}");
    assert_eq!(v["vault"], own, "{v}");
    assert_eq!(v["schema_version"], "1", "{v}");

    // Remove the remote entirely: a dry run must still report the
    // last-fetched state instead of reaching for it.
    std::fs::remove_dir_all(&fixture.remote).unwrap();
    let (status, v) = fixture.run_json(&["sync", "--dry-run", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["ahead"], 1, "{v}");
    assert_eq!(v["fetched"], false, "{v}");
    assert_eq!(git(&fixture.vault, &["rev-parse", "HEAD"]), local);
}

#[cfg(unix)]
#[test]
fn default_sync_fetches_and_reports_behind() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);

    let (status, v) = fixture.run_json(&["sync", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["fetched"], true, "{v}");
    assert_eq!(v["ahead"], 0, "{v}");
    assert_eq!(v["behind"], 1, "{v}");
    assert_eq!(v["dry_run"], false, "{v}");
}

#[cfg(unix)]
#[test]
fn push_needs_yes_with_no_input_then_advances_the_remote() {
    let fixture = SyncVault::new();
    git(
        &fixture.vault,
        &["commit", "-q", "--allow-empty", "-m", "local"],
    );
    let local = git(&fixture.vault, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let before = git(&fixture.remote, &["rev-parse", "main"])
        .trim()
        .to_owned();

    let (status, v) = fixture.run_json(&["sync", "--push", "--json", "--no-input"]);
    assert_eq!(
        status, 2,
        "a network write without --yes is a usage error: {v}"
    );
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["error"]["code"], "usage_error", "{v}");
    assert_eq!(
        git(&fixture.remote, &["rev-parse", "main"]).trim(),
        before,
        "nothing was pushed"
    );

    let (status, v) = fixture.run_json(&["sync", "--push", "--yes", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["action"], "push", "{v}");
    assert_eq!(v["applied"], true, "{v}");
    assert_eq!(v["ahead"], 0, "{v}");
    assert_eq!(
        git(&fixture.remote, &["rev-parse", "main"]).trim(),
        local,
        "the bare remote advanced to the local HEAD"
    );
}

/// `push.default=simple` refuses when the upstream branch name differs
/// from HEAD. `sync --push` must still send HEAD to that upstream on the
/// same remote it fetched, and must not advance a same-named branch on
/// the remote.
#[cfg(unix)]
#[test]
fn push_honours_a_differently_named_upstream_branch() {
    let fixture = SyncVault::new();
    let main_before = git(&fixture.remote, &["rev-parse", "main"])
        .trim()
        .to_owned();
    git(
        &fixture.vault,
        &["push", "-q", "-u", "origin", "main:trunk"],
    );
    git(&fixture.vault, &["config", "push.default", "simple"]);
    let upstream = git(
        &fixture.vault,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    );
    assert_eq!(upstream.trim(), "origin/trunk", "{upstream}");

    git(
        &fixture.vault,
        &["commit", "-q", "--allow-empty", "-m", "local"],
    );
    let local = git(&fixture.vault, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();

    let (status, v) = fixture.run_json(&["sync", "--push", "--yes", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["action"], "push", "{v}");
    assert_eq!(v["applied"], true, "{v}");
    assert_eq!(v["ahead"], 0, "{v}");
    assert_eq!(v["remote"], "origin", "{v}");
    assert_eq!(v["upstream"], "origin/trunk", "{v}");
    assert_eq!(
        git(&fixture.remote, &["rev-parse", "trunk"]).trim(),
        local,
        "the differently named upstream advanced"
    );
    assert_eq!(
        git(&fixture.remote, &["rev-parse", "main"]).trim(),
        main_before,
        "origin/main must not move; the push targeted trunk"
    );
}

#[cfg(unix)]
#[test]
fn pull_fast_forwards_only() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);
    let remote_head = git(&fixture.remote, &["rev-parse", "main"])
        .trim()
        .to_owned();

    let (status, v) = fixture.run_json(&["sync", "--pull", "--yes", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["action"], "pull", "{v}");
    assert_eq!(v["applied"], true, "{v}");
    assert_eq!(v["behind"], 0, "{v}");
    assert_eq!(
        git(&fixture.vault, &["rev-parse", "HEAD"]).trim(),
        remote_head,
        "the vault fast-forwarded to the remote"
    );
}

#[cfg(unix)]
#[test]
fn diverged_branch_refuses_push_and_pull_with_a_stable_code() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    // Both sides add a different commit: the branch is now diverged.
    git(
        &fixture.vault,
        &["commit", "-q", "--allow-empty", "-m", "local"],
    );
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);
    let remote_head = git(&fixture.remote, &["rev-parse", "main"])
        .trim()
        .to_owned();

    for action in ["--push", "--pull"] {
        let (status, v) = fixture.run_json(&["sync", action, "--yes", "--json", "--no-input"]);
        assert_eq!(status, 1, "{action} must refuse: {v}");
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["error"]["code"], "E_NOT_FAST_FORWARD", "{v}");
        let message = v["error"]["message"].as_str().unwrap();
        assert!(message.contains("diverged"), "{message}");
        // #736: the refusal itself names the recovery, with the branch
        // and upstream, instead of leaving the operator with no next step.
        let fix = v["error"]["fix"].as_str().unwrap();
        assert!(fix.contains("origin/main"), "{fix}");
        assert!(fix.contains("git merge origin/main"), "{fix}");
        assert!(fix.contains("confidant sync --push"), "{fix}");
    }
    // The default report refuses the same way, with the same fix.
    let (status, v) = fixture.run_json(&["sync", "--json", "--no-input"]);
    assert_eq!(status, 1, "default sync must refuse a diverged branch: {v}");
    assert_eq!(v["error"]["code"], "E_NOT_FAST_FORWARD", "{v}");
    let fix = v["error"]["fix"].as_str().unwrap();
    assert!(fix.contains("git rebase origin/main"), "{fix}");
    assert_eq!(
        git(&fixture.remote, &["rev-parse", "main"]).trim(),
        remote_head,
        "a refused push leaves the remote alone"
    );
}

#[cfg(unix)]
#[test]
fn plaintext_vault_syncs_against_any_remote() {
    // A plaintext vault is the only kind now, so `sync` must work against
    // any configured `origin`.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Confidant Test\n\temail = test@example.invalid\n",
    )
    .unwrap();
    let vault = tmp.path().join("vault");
    common::copy_dir(&demo(), &vault);
    init_repo(&vault);
    git(&vault, &["add", "-A"]);
    git(&vault, &["commit", "-q", "-m", "demo"]);

    let remote = tmp.path().join("remote.git");
    git(
        tmp.path(),
        &[
            "init",
            "-q",
            "--bare",
            "-b",
            "main",
            remote.to_str().unwrap(),
        ],
    );
    let url = format!("file://{}", remote.display());
    git(&vault, &["remote", "add", "origin", &url]);
    git(&vault, &["push", "-q", "-u", "origin", "main"]);

    let out = Command::new(bin())
        .args(["sync", "--dry-run", "--json", "--no-input", "--vault"])
        .arg(&vault)
        .env("HOME", &home)
        .env("CONFIDANT_OFFLINE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["crypto_mode"], "plaintext", "{v}");
    assert_eq!(v["remote"], "origin", "{v}");

    // And a real push succeeds.
    git(&vault, &["commit", "-q", "--allow-empty", "-m", "local"]);
    let out = Command::new(bin())
        .args(["sync", "--push", "--yes", "--json", "--no-input", "--vault"])
        .arg(&vault)
        .env("HOME", &home)
        .env("CONFIDANT_OFFLINE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["applied"], true, "{v}");
    assert_eq!(v["action"], "push", "{v}");
}

#[cfg(unix)]
#[test]
fn no_remote_is_a_stable_error_and_does_not_touch_the_network() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Confidant Test\n\temail = test@example.invalid\n",
    )
    .unwrap();
    let vault = tmp.path().join("vault");
    let out = Command::new(bin())
        .args(["init", "--create", "--no-input", "--json", "--vault"])
        .arg(&vault)
        .env("HOME", &home)
        .env("CONFIDANT_OFFLINE", "1")
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin())
        .args(["sync", "--dry-run", "--json", "--no-input", "--vault"])
        .arg(&vault)
        .env("HOME", &home)
        .env("CONFIDANT_OFFLINE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["error"]["code"], "E_NO_REMOTE", "{v}");
    assert!(v["vault"].as_str().unwrap().ends_with("vault"), "{v}");
}

#[cfg(unix)]
#[test]
fn remote_without_upstream_is_no_remote() {
    let fixture = SyncVault::new();
    git(&fixture.vault, &["branch", "--unset-upstream"]);
    let (status, v) = fixture.run_json(&["sync", "--dry-run", "--json", "--no-input"]);
    assert_eq!(status, 1, "{v}");
    assert_eq!(v["error"]["code"], "E_NO_REMOTE", "{v}");
}

#[cfg(unix)]
#[test]
fn pull_refuses_a_dirty_tree_that_would_be_overwritten() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    // The other device changes a tracked plaintext file; this vault edits
    // the same file without committing, so a fast-forward would overwrite
    // it. The error names the conflict, not credentials.
    let config = other.join("confidant.toml");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("# remote edit\n");
    std::fs::write(&config, text).unwrap();
    git(&other, &["add", "confidant.toml"]);
    git(&other, &["commit", "-q", "-m", "remote edit"]);
    git(&other, &["push", "-q", "origin", "main"]);

    let local_config = fixture.vault.join("confidant.toml");
    let mut local = std::fs::read_to_string(&local_config).unwrap();
    local.push_str("# local edit\n");
    std::fs::write(&local_config, local).unwrap();

    let (status, v) = fixture.run_json(&["sync", "--pull", "--yes", "--json", "--no-input"]);
    assert_eq!(status, 1, "{v}");
    assert_eq!(v["error"]["code"], "E_CONFLICT", "{v}");
    let fix = v["error"]["fix"].as_str().unwrap();
    assert!(fix.contains("Commit or stash"), "{fix}");
    // Nothing was pulled: the uncommitted edit is intact and the remote
    // edit is absent.
    let after = std::fs::read_to_string(&local_config).unwrap();
    assert!(after.ends_with("# local edit\n"), "{after}");
    assert!(!after.contains("# remote edit"), "{after}");
}

/// #736: the default report prints its own resolution. The original
/// repro was an operator who ran `sync`, saw the vault was behind, and
/// did not know `sync --pull` existed — because nothing in the report
/// said so. Behind names `--pull`, ahead names `--push`, and an
/// up-to-date report names nothing.
#[cfg(unix)]
#[test]
fn default_report_names_its_remedy() {
    // Behind: the report names --pull, in text and in JSON, and the
    // remedy survives into a --dry-run report of the same state,
    // qualified there as last-fetched (dry-run never contacts the remote).
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);

    let out = fixture.run(&["sync", "--no-input"]);
    assert!(out.status.success(), "default sync must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("0 ahead, 1 behind"), "{text}");
    assert!(
        text.contains(
            "Run `confidant sync --pull` to fast-forward main to origin/main (1 commit(s))"
        ),
        "{text}"
    );

    let (status, v) = fixture.run_json(&["sync", "--dry-run", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["behind"], 1, "{v}");
    assert_eq!(
        v["remedy"],
        "Run `confidant sync --pull` to fast-forward main to origin/main (1 commit(s)) (as of the last fetch)",
        "{v}"
    );

    // Ahead: the report names --push.
    let fixture = SyncVault::new();
    git(
        &fixture.vault,
        &["commit", "-q", "--allow-empty", "-m", "local"],
    );
    let out = fixture.run(&["sync", "--no-input"]);
    assert!(out.status.success(), "default sync must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("1 ahead, 0 behind"), "{text}");
    assert!(
        text.contains("Run `confidant sync --push` to push 1 commit(s) to origin/main"),
        "{text}"
    );
    let (status, v) = fixture.run_json(&["sync", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["ahead"], 1, "{v}");
    assert_eq!(
        v["remedy"], "Run `confidant sync --push` to push 1 commit(s) to origin/main",
        "{v}"
    );

    // Up to date: no remedy line, and the JSON field is null.
    let fixture = SyncVault::new();
    let out = fixture.run(&["sync", "--no-input"]);
    assert!(out.status.success(), "default sync must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("0 ahead, 0 behind"), "{text}");
    assert!(!text.contains("Run `confidant sync"), "{text}");
    let (status, v) = fixture.run_json(&["sync", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert!(v["remedy"].is_null(), "{v}");
}

/// #736: a remedy is a report of state that changed nothing. Once a write
/// was applied, there is nothing left to point at, so the JSON `remedy`
/// is null after a confirmed pull and after a confirmed push.
#[cfg(unix)]
#[test]
fn remedy_is_null_after_an_applied_pull_or_push() {
    // Applied pull.
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);
    let (status, v) = fixture.run_json(&["sync", "--pull", "--yes", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["action"], "pull", "{v}");
    assert_eq!(v["applied"], true, "{v}");
    assert_eq!(v["behind"], 0, "{v}");
    assert!(v["remedy"].is_null(), "{v}");

    // Applied push.
    let fixture = SyncVault::new();
    git(
        &fixture.vault,
        &["commit", "-q", "--allow-empty", "-m", "local"],
    );
    let (status, v) = fixture.run_json(&["sync", "--push", "--yes", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["action"], "push", "{v}");
    assert_eq!(v["applied"], true, "{v}");
    assert_eq!(v["ahead"], 0, "{v}");
    assert!(v["remedy"].is_null(), "{v}");
}

/// #736: a declined confirm likewise names no remedy — the report says
/// "pull not confirmed; nothing changed" and prints no pointer line.
/// (No `--no-input`/`--json` here: those turn an unconfirmed write into
/// a usage error before any report exists. Under the test harness stdin
/// is not a TTY, so the prompt declines without an answer.)
#[cfg(unix)]
#[test]
fn declined_confirm_names_no_remedy() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);
    let local = git(&fixture.vault, &["rev-parse", "HEAD"]);

    let out = fixture.run(&["sync", "--pull"]);
    assert!(out.status.success(), "a declined pull still exits 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("pull not confirmed; nothing changed"),
        "{text}"
    );
    assert!(!text.contains("Run `confidant sync"), "{text}");
    assert_eq!(
        git(&fixture.vault, &["rev-parse", "HEAD"]),
        local,
        "nothing was fast-forwarded"
    );
}

/// #736: a dry-run remedy reports last-fetched state, and says so in the
/// remedy itself. This test exercises real staleness: after priming the
/// state with a fetch, a second remote commit lands that no fetch has
/// seen, so the dry-run report still shows the old count — qualified.
#[cfg(unix)]
#[test]
fn dry_run_remedy_is_qualified_and_reports_last_fetched_state() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote-1"]);
    git(&other, &["push", "-q", "origin", "main"]);

    // Prime the last-fetched state: behind 1.
    let out = fixture.run(&["sync", "--no-input"]);
    assert!(out.status.success(), "default sync must exit 0");

    // A second remote commit nobody has fetched: the true state is now
    // behind 2, but a dry run must still report behind 1, qualified.
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote-2"]);
    git(&other, &["push", "-q", "origin", "main"]);

    let (status, v) = fixture.run_json(&["sync", "--dry-run", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["fetched"], false, "{v}");
    assert_eq!(v["behind"], 1, "{v}");
    assert_eq!(
        v["remedy"],
        "Run `confidant sync --pull` to fast-forward main to origin/main (1 commit(s)) (as of the last fetch)",
        "{v}"
    );
    let out = fixture.run(&["sync", "--dry-run", "--no-input"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("(1 commit(s)) (as of the last fetch)"),
        "{text}"
    );
}

/// #736: the plain pull remedy promises a fast-forward `--pull` would
/// refuse on a dirty tree. On a dirty tree the behind remedy names
/// commit-or-stash first instead.
#[cfg(unix)]
#[test]
fn behind_remedy_on_a_dirty_tree_names_commit_or_stash_first() {
    let fixture = SyncVault::new();
    let other = fixture.other_clone();
    git(&other, &["commit", "-q", "--allow-empty", "-m", "remote"]);
    git(&other, &["push", "-q", "origin", "main"]);

    // An uncommitted edit to a tracked file the remote did not touch.
    let local_config = fixture.vault.join("confidant.toml");
    let mut local = std::fs::read_to_string(&local_config).unwrap();
    local.push_str("# local edit\n");
    std::fs::write(&local_config, local).unwrap();

    let out = fixture.run(&["sync", "--no-input"]);
    assert!(out.status.success(), "default sync must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("0 ahead, 1 behind"), "{text}");
    assert!(
        text.contains(
            "Commit or stash your changes, then run `confidant sync --pull` to fast-forward main to origin/main (1 commit(s))"
        ),
        "{text}"
    );
    let (status, v) = fixture.run_json(&["sync", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(
        v["remedy"],
        "Commit or stash your changes, then run `confidant sync --pull` to fast-forward main to origin/main (1 commit(s))",
        "{v}"
    );
}
