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

/// A throwaway age identity for `init --create`; the OS keychain is never
/// consulted (ADR-14: CI generates ephemeral keys during the run).
#[cfg(unix)]
fn age_generate_bech32() -> String {
    use age::secrecy::ExposeSecret;
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_owned()
        .to_uppercase()
}

/// A real encrypted vault (created through `init --create`) plus a local
/// bare remote it has pushed to. The vault's branch is `main` with
/// `origin/main` as its upstream.
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
            .env("CONFIDANT_DEVICE_KEY", age_generate_bech32())
            .env("CONFIDANT_KEYCHAIN", "off")
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
            .env("CONFIDANT_OFFLINE", "1")
            .env("CONFIDANT_KEYCHAIN", "off")
            .env_remove("CONFIDANT_DEVICE_KEY");
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
    let own = format!("{}", fixture.vault.display());

    let (status, v) = fixture.run_json(&["sync", "--dry-run", "--json", "--no-input"]);
    assert_ok(status, &v);
    assert_eq!(v["ahead"], 1, "{v}");
    assert_eq!(v["behind"], 0, "{v}");
    assert_eq!(v["remote"], "origin", "{v}");
    assert_eq!(v["branch"], "main", "{v}");
    assert_eq!(v["upstream"], "origin/main", "{v}");
    assert_eq!(v["crypto_mode"], "encrypted", "{v}");
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
    }
    assert_eq!(
        git(&fixture.remote, &["rev-parse", "main"]).trim(),
        remote_head,
        "a refused push leaves the remote alone"
    );
}

#[cfg(unix)]
#[test]
fn plaintext_vault_is_refused_even_for_a_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    common::copy_dir(&demo(), &vault);
    init_repo(&vault);
    git(&vault, &["add", "-A"]);
    git(&vault, &["commit", "-q", "-m", "demo"]);
    git(
        &vault,
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/fake/vault.git",
        ],
    );

    for args in [
        vec!["sync", "--dry-run", "--json", "--no-input"],
        vec!["sync", "--push", "--yes", "--json", "--no-input"],
    ] {
        let out = Command::new(bin())
            .args(&args)
            .arg("--vault")
            .arg(&vault)
            .env("HOME", home.path())
            .env("CONFIDANT_OFFLINE", "1")
            .env("CONFIDANT_KEYCHAIN", "off")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["error"]["code"], "E_PLAINTEXT_REMOTE", "{args:?}: {v}");
        let message = v["error"]["message"].as_str().unwrap();
        assert!(message.contains("plaintext"), "{message}");
    }
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
        .env("CONFIDANT_DEVICE_KEY", age_generate_bech32())
        .env("CONFIDANT_KEYCHAIN", "off")
        .env("CONFIDANT_OFFLINE", "1")
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin())
        .args(["sync", "--dry-run", "--json", "--no-input", "--vault"])
        .arg(&vault)
        .env("HOME", &home)
        .env("CONFIDANT_OFFLINE", "1")
        .env("CONFIDANT_KEYCHAIN", "off")
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
