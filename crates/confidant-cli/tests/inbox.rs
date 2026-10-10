//! Integration tests for `confidant inbox` against throwaway git repos.
//!
//! The decryptor is the production `confidant-crypt` age path: the inbox
//! identity comes from the `CONFIDANT_INBOX_KEY` env override (headless
//! tests) or the OS keychain. Tests that need "no key" remove the env var;
//! tests that need a key set it to a fixed test-only identity. All data is
//! fake.

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
        self.inbox_with_env(args, None)
    }

    /// Run `confidant inbox`, controlling the inbox identity: `Some(bech32)`
    /// sets `CONFIDANT_INBOX_KEY`, `None` removes it so the run has no key
    /// (deterministic even if the ambient environment sets one).
    /// `CONFIDANT_KEYCHAIN=off` keeps the child off the real OS keychain.
    fn inbox_with_env(&self, args: &[&str], inbox_key: Option<&str>) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_confidant"));
        cmd.arg("inbox")
            .args(args)
            .arg("--vault")
            .arg(self.root())
            .env("HOME", self.home.path())
            .env("CONFIDANT_KEYCHAIN", "off")
            .env_remove("CONFIDANT_INBOX_KEY");
        if let Some(k) = inbox_key {
            cmd.env("CONFIDANT_INBOX_KEY", k);
        }
        let out = cmd.output().expect("confidant failed to run");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Advertise an `[inbox].pubkey` in the vault config (committed).
    fn with_vault_inbox_pubkey(&self, pubkey: &str) {
        let path = self.root().join("confidant.toml");
        let mut toml = std::fs::read_to_string(&path).unwrap();
        toml.push_str(&format!("\n[inbox]\npubkey = \"{pubkey}\"\n"));
        std::fs::write(&path, toml).unwrap();
        git(self.root(), &["add", "confidant.toml"]);
        git(
            self.root(),
            &["commit", "-q", "-m", "advertise inbox pubkey"],
        );
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
fn inbox_decrypt_fails_closed_without_key() {
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
fn inbox_decrypt_fails_closed_human_output() {
    let f = Fixture::new();
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let (code, _, stderr) = f.inbox(&["--allow-unsigned"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("E_INBOX_CRYPTO"), "stderr: {stderr}");
    assert!(stderr.contains("fix:"), "stderr: {stderr}");
}

/// Fixed test-only inbox identities (fake data).
fn test_recipient(secret: &[u8; 32]) -> String {
    confidant_crypt::age_wrap::RawX25519Identity::new(*secret).to_recipient_string()
}

fn test_bech32(secret: &[u8; 32]) -> String {
    confidant_crypt::age_wrap::RawX25519Identity::new(*secret).to_bech32()
}

const TEST_INBOX_SECRET: [u8; 32] = [7u8; 32];
const OTHER_INBOX_SECRET: [u8; 32] = [9u8; 32];

#[test]
fn local_pubkey_mismatch_is_hard_error() {
    // #55: the vault advertises someone else's key while the local private
    // key is ours — the CLI refuses with E_INBOX_UNTRUSTED before decrypting.
    let f = Fixture::new();
    f.with_vault_inbox_pubkey(&test_recipient(&OTHER_INBOX_SECRET));
    f.with_inbox(&[("01JABC.age", b"opaque ciphertext")]);
    let key = test_bech32(&TEST_INBOX_SECRET);
    let (code, stdout, _) = f.inbox_with_env(&["--json", "--allow-unsigned"], Some(&key));
    assert_eq!(code, 1, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["error"]["code"], "E_INBOX_UNTRUSTED");
}

#[test]
fn real_crypto_item_decrypts_end_to_end() {
    // #30: an age-encrypted item decrypts through the real production path
    // in the built binary (dry run: decrypt + plan, merge nothing).
    let f = Fixture::new();
    let recipient = test_recipient(&TEST_INBOX_SECRET);
    f.with_vault_inbox_pubkey(&recipient);
    let item = "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 45m src:cli-crypto-1\n";
    let ciphertext =
        confidant_crypt::age_wrap::wrap_to_recipient(item.as_bytes(), &recipient).unwrap();
    f.with_inbox(&[("01JABC.age", &ciphertext)]);
    let key = test_bech32(&TEST_INBOX_SECRET);
    let (code, stdout, _) =
        f.inbox_with_env(&["--json", "--dry-run", "--allow-unsigned"], Some(&key));
    assert_eq!(code, 0, "stdout: {stdout}");
    let v = parse_json(&stdout);
    assert_eq!(v["ok"], true);
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["merged"], 1);
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
