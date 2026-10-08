//! Integration tests for `confidant inbox` against throwaway git repos.
//!
//! The decryptor is the production `confidant-crypt` stub, so any item that
//! reaches decryption fails closed with E_INBOX_CRYPTO. Crypto-real tests
//! belong to milestone 2 (PR B). All data is fake.

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

const MIN_VAULT_TOML: &str = r#"
spec = "0.1"
vault_id = "inbox-test-vault"
"#;

const MIN_RECORD: &str = r#"
# Acme

@id: p-acme
@type: org
"#;

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .expect("git failed to run");
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Fixture {
    dir: TempDir,
    home: TempDir,
}

impl Fixture {
    /// A git repo holding a minimal, check-clean vault on `main`, plus a
    /// fake HOME outside the repo.
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let root = dir.path();
        git(root, &["init", "-b", "main", "-q"]);
        git(root, &["config", "user.name", "Test"]);
        git(root, &["config", "user.email", "test@example.com"]);
        std::fs::write(root.join("confidant.toml"), MIN_VAULT_TOML).unwrap();
        std::fs::create_dir_all(root.join("orgs/p-acme")).unwrap();
        std::fs::write(root.join("orgs/p-acme/profile.md"), MIN_RECORD).unwrap();
        std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
        std::fs::write(root.join("ledger/2026/10.cfd"), "; ledger/2026/10.cfd\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "init"]);
        Self { dir, home }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Create the `inbox` branch (an orphan branch holding only items) with
    /// the given `<name>.age` files, then return to `main`.
    fn with_inbox(&self, files: &[(&str, &[u8])]) {
        git(self.root(), &["checkout", "-q", "--orphan", "inbox"]);
        git(self.root(), &["rm", "-q", "-rf", "."]);
        for (name, bytes) in files {
            std::fs::write(self.root().join(name), bytes).unwrap();
        }
        git(self.root(), &["add", "."]);
        git(self.root(), &["commit", "-q", "-m", "drop items"]);
        git(self.root(), &["checkout", "-q", "main"]);
    }

    fn inbox(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_confidant"))
            .arg("inbox")
            .args(args)
            .arg("--vault")
            .arg(self.root())
            .env("HOME", self.home.path())
            .output()
            .expect("confidant failed to run");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    fn with_home_config(&self, toml: &str) {
        let cfg = self.home.path().join(".config/confidant");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("config.toml"), toml).unwrap();
    }
}

fn parse_json(stdout: &str) -> Value {
    serde_json::from_str(stdout).expect("stdout is not JSON")
}

#[test]
fn no_inbox_branch_is_empty_success() {
    let f = Fixture::new();
    let (code, stdout, _) = f.inbox(&["--json"]);
    assert_eq!(code, 0, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["ok"], true);
    assert_eq!(v["empty"], true);
    assert_eq!(v["merged"], 0);
    assert_eq!(v["cleared"], 0);
    assert_eq!(v["schema_version"], "1");
    assert_eq!(
        v["vault"],
        f.root().canonicalize().unwrap().display().to_string()
    );
}

#[test]
fn dirty_tree_refuses() {
    let f = Fixture::new();
    std::fs::write(f.root().join("untracked.txt"), "dirty\n").unwrap();
    let (code, stdout, stderr) = f.inbox(&["--json"]);
    assert_eq!(code, 1, "stdout: {stdout} stderr: {stderr}");
    let v = parse_json(&stdout);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_INBOX_DIRTY");
}

#[test]
fn non_age_file_on_inbox_is_rejected() {
    let f = Fixture::new();
    f.with_inbox(&[("notes.txt", b"plaintext is not allowed here")]);
    let (code, stdout, _) = f.inbox(&["--json", "--allow-unsigned"]);
    assert_eq!(code, 1, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["error"]["code"], "E_INBOX_ITEM");
    // Nothing was cleared: the bad file is still on the inbox branch.
    let tree = git(f.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("notes.txt"));
}

#[test]
fn stub_decrypt_fails_closed() {
    let f = Fixture::new();
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let (code, stdout, _) = f.inbox(&["--json", "--allow-unsigned"]);
    assert_eq!(code, 1, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_INBOX_CRYPTO");
    // All-or-nothing: the item stays on the inbox branch.
    let tree = git(f.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("01JABC.age"));
}

#[test]
fn stub_decrypt_fails_closed_human_output() {
    let f = Fixture::new();
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let (code, _, stderr) = f.inbox(&["--allow-unsigned"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("E_INBOX_CRYPTO"), "stderr: {stderr}");
    assert!(stderr.contains("fix:"), "stderr: {stderr}");
}

#[test]
fn unsigned_tip_with_signers_configured_is_untrusted() {
    let f = Fixture::new();
    f.with_home_config("[trust]\nsigners = [\"DEADBEEFDEADBEEF\"]\n");
    // Unsigned commit on the inbox branch.
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let (code, stdout, _) = f.inbox(&["--json"]);
    assert_eq!(code, 1, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["error"]["code"], "E_INBOX_UNTRUSTED");
}

#[test]
fn unconfigured_signers_refuse_without_allow_unsigned() {
    let f = Fixture::new();
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let (code, stdout, _) = f.inbox(&["--json"]);
    // No signers configured and no opt-in -> fail closed.
    assert_eq!(code, 1, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["error"]["code"], "E_INBOX_UNTRUSTED");
}

#[test]
fn allow_unsigned_proceeds_to_crypto() {
    let f = Fixture::new();
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let (code, stdout, _) = f.inbox(&["--json", "--allow-unsigned"]);
    // Explicit opt-in skips signature verification; the run proceeds to
    // decryption, where the milestone-2 stub fails closed.
    assert_eq!(code, 1, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["error"]["code"], "E_INBOX_CRYPTO");
}

#[test]
fn no_inbox_branch_needs_no_signers() {
    let f = Fixture::new();
    let (code, stdout, _) = f.inbox(&[]);
    assert_eq!(code, 0, "stdout: {stdout}");
    assert!(stdout.contains("nothing to do"), "stdout: {stdout}");
}

#[test]
fn dry_run_with_no_items_is_empty() {
    let f = Fixture::new();
    let (code, stdout, _) = f.inbox(&["--json", "--dry-run"]);
    assert_eq!(code, 0, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["empty"], true);
    assert_eq!(v["dry_run"], true);
}

#[test]
fn bad_item_name_is_rejected() {
    let f = Fixture::new();
    f.with_inbox(&[("-bad.age", b"opaque")]);
    let (code, stdout, _) = f.inbox(&["--json", "--allow-unsigned"]);
    assert_eq!(code, 1, "stdout: {stdout}");
    assert_eq!(parse_json(&stdout)["error"]["code"], "E_INBOX_ITEM");
}
