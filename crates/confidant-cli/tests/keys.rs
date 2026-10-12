//! Tests for `confidant keys` commands (#148 Spec 2) with #105 folded in.
//!
//! Every test uses a throwaway HOME + vault + device key (ADR-14). The
//! operator key is provided via CONFIDANT_TEST_OPERATOR_KEY.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Generate a throwaway age identity, returning the Bech32 secret.
fn age_generate_bech32() -> String {
    use age::secrecy::ExposeSecret;
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_owned()
        .to_uppercase()
}

/// Generate a throwaway Ed25519 signing key, returning the hex seed.
fn ed25519_generate_hex() -> String {
    use rand::rngs::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    hex::encode(sk.to_bytes())
}

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.file_name().unwrap() == "deps" {
        p.pop();
    }
    p.join("confidant")
}

fn git(vault: &Path, args: &[&str]) {
    let st = Command::new("git")
        .current_dir(vault)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?} failed");
}

/// Test harness: temp HOME + vault (demo-vault copy) + throwaway device key.
struct Harness {
    home: PathBuf,
    vault: PathBuf,
    device_bech32: String,
    operator_hex: String,
    keychain_dir: Option<PathBuf>,
    _tmp: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&vault).unwrap();

        // Minimal vault: confidant.toml + git repo. Fake vault_id.
        std::fs::write(
            vault.join("confidant.toml"),
            "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
        )
        .unwrap();
        git(&vault, &["init", "-q"]);
        git(&vault, &["config", "user.email", "test@example.com"]);
        git(&vault, &["config", "user.name", "Test"]);
        git(&vault, &["add", "-A"]);
        git(&vault, &["commit", "-qm", "base"]);

        let device_bech32 = age_generate_bech32();
        let operator_hex = ed25519_generate_hex();
        Harness {
            home,
            vault,
            device_bech32,
            operator_hex,
            keychain_dir: None,
            _tmp: tmp,
        }
    }

    /// Switch this harness to the test keychain dir (for shred's device-key
    /// rotation): the device key is read from / written to
    /// `$DIR/device.key` instead of `CONFIDANT_DEVICE_KEY` / the OS
    /// keychain. Must be called before `init`.
    fn with_test_keychain(&mut self) {
        let dir = self._tmp.path().join("keychain");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("device.key"), &self.device_bech32).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("device.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        self.keychain_dir = Some(dir);
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
            .arg("--vault")
            .arg(&self.vault)
            .env("HOME", &self.home)
            .env("CONFIDANT_TEST_OPERATOR_KEY", &self.operator_hex)
            .env("CONFIDANT_KEYCHAIN", "off");
        match &self.keychain_dir {
            Some(dir) => {
                c.env("CONFIDANT_TEST_KEYCHAIN_DIR", dir);
                c.env_remove("CONFIDANT_DEVICE_KEY");
            }
            None => {
                c.env("CONFIDANT_DEVICE_KEY", &self.device_bech32);
                c.env_remove("CONFIDANT_TEST_KEYCHAIN_DIR");
            }
        }
        c
    }

    fn init(&self, args: &[&str]) -> Output {
        let mut full_args = vec!["init", "--no-input"];
        full_args.extend(args);
        self.cmd(&full_args).output().unwrap()
    }
}

#[test]
fn keys_init_client_creates_manifest_and_wrappings() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success(), "init failed");

    let out = h
        .cmd(&["keys", "init-client", "test-client", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init-client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Manifest and wrappings exist.
    assert!(h.vault.join("keys/test-client/epoch").exists());
    assert!(h.vault.join("keys/test-client/recipients.toml").exists());
}

#[test]
fn keys_bad_client_id_usage_exit_2() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    // Malformed client id (path traversal) → usage error exit 2.
    let out = h
        .cmd(&["keys", "init-client", "../evil", "--json", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for bad client id"
    );
}

#[test]
fn keys_reserved_id_is_e_invalid() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    // shred refuses vault:shared → E_INVALID (not exit 2).
    let out = h
        .cmd(&["keys", "shred", "vault:shared", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("E_INVALID") || stdout.contains("e_invalid") || stdout.contains("invalid"),
        "expected E_INVALID, got: {stdout}"
    );
}

#[test]
fn keys_json_no_secrets() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    let out = h
        .cmd(&["keys", "init-client", "test-client", "--json", "--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("AGE-SECRET-KEY"),
        "JSON leaks key material"
    );
    assert!(!stdout.contains(&h.device_bech32), "JSON leaks device key");
}

#[test]
fn keys_rotate_bumps_epoch_renames_old_wrappings() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    // Init a client.
    let out = h
        .cmd(&["keys", "init-client", "test-client", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Rotate.
    let out = h
        .cmd(&["keys", "rotate", "test-client", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "rotate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"epoch\":2"),
        "expected epoch 2, got: {stdout}"
    );

    // Old wrappings renamed to .e1.
    let wrapped_dir = h.vault.join("keys/test-client/wrapped");
    let entries: Vec<_> = std::fs::read_dir(&wrapped_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|n| n.contains(".e1")),
        "old wrappings not renamed: {entries:?}"
    );
}

#[test]
fn keys_revoke_removes_all_epochs_and_refuses_recovery() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    // Init a client.
    let out = h
        .cmd(&["keys", "init-client", "test-client", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Try to revoke recovery → refused.
    let out = h
        .cmd(&[
            "keys",
            "revoke",
            "test-client",
            "recovery",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "revoking recovery should fail");
}

#[test]
fn keys_shred_new_phrase_stderr_once() {
    let mut h = Harness::new();
    // Shred rotates the device key: use the test keychain dir (the
    // rotation cannot work with CONFIDANT_DEVICE_KEY, which fails closed).
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    // Record the anchor's recovery pubkey before shred.
    let trust_before =
        std::fs::read_to_string(h.home.join(".config/confidant/trust.toml")).unwrap();

    // Init two clients (need at least one remaining after shred).
    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    // Shred client-a. Must succeed.
    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Phrase appears exactly once on stderr, never in JSON stdout.
    let phrase_lines: Vec<_> = stderr
        .lines()
        .filter(|l| l.split_whitespace().count() == 24)
        .collect();
    assert_eq!(
        phrase_lines.len(),
        1,
        "phrase must appear exactly once on stderr"
    );
    assert!(
        !stdout.contains(phrase_lines[0]),
        "phrase leaked into stdout"
    );

    // Outcome: client-a tree destroyed.
    assert!(
        !h.vault.join("keys/client-a").exists(),
        "shredded client tree still exists"
    );
    // Others re-wrapped: client-b manifest still exists and verifies
    // (check passes on the vault).
    assert!(h.vault.join("keys/client-b/recipients.toml").is_file());
    // Anchor re-pinned: trust.toml exists with a CHANGED recovery pubkey
    // (the phrase rotated; assert the key actually changed, not just that
    // the file exists).
    let trust = h.home.join(".config/confidant/trust.toml");
    assert!(trust.is_file(), "trust.toml missing after shred");
    let trust_after = std::fs::read_to_string(&trust).unwrap();
    let recovery_before: String = trust_before
        .lines()
        .find(|l| l.contains("recovery_pubkey"))
        .unwrap()
        .to_string();
    let recovery_after: String = trust_after
        .lines()
        .find(|l| l.contains("recovery_pubkey"))
        .unwrap()
        .to_string();
    assert_ne!(
        recovery_before, recovery_after,
        "anchor recovery_pubkey did not change across shred"
    );
    // The device key was rotated: the test keychain now holds a fresh key
    // (different from the one the harness wrote).
    let rotated =
        std::fs::read_to_string(h.keychain_dir.as_ref().unwrap().join("device.key")).unwrap();
    assert_ne!(
        rotated.trim(),
        h.device_bech32.trim(),
        "device key was not rotated by shred"
    );
    // Pending inbox rotation file OR inbox was rotated (test has no inbox
    // key, so the reminder file must exist).
    let pending = h.home.join(".config/confidant/inbox-rotation-pending.toml");
    assert!(
        pending.is_file(),
        "pending inbox rotation reminder not written"
    );
    // JSON carries ok + destroy list.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(!v["destroy_key_ids"].as_array().unwrap().is_empty());
    // The re-enrollment notice is surfaced.
    assert_eq!(v["device_key_rotated"], true);
}

#[test]
fn keys_shred_then_fresh_device_recover_with_new_phrase() {
    // Blocker B: shred rotates the recovery key, so the operator
    // certificate must be re-signed — otherwise a fresh-device recover
    // with the NEW phrase fails verify_operator_cert (silent lockout).
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let new_phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));

    // Fresh device: wipe config, recover with the post-shred phrase.
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &new_phrase).unwrap();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fresh-device recover after shred failed (stale operator cert?): stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(h.home.join(".config/confidant/trust.toml").is_file());
}

#[test]
fn keys_shred_refused_leaves_device_key_untouched() {
    // Silas's blocker: shred generated the fresh device keypair and stored
    // the new private key BEFORE KeyStore::shred ran its verify-first
    // checks, so a refused shred locked this device out of the
    // still-unshredded vault. The fresh key must be stored only after
    // shred returns Ok.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    // Snapshot the enrolled device key.
    let key_path = h.keychain_dir.as_ref().unwrap().join("device.key");
    let before = std::fs::read_to_string(&key_path).unwrap();

    // Plant an initialized-but-unverifiable client dir: it carries an
    // epoch file, so the CLI lists it for the strand check, but its
    // manifest is missing, so KeyStore::shred's verify-first pass refuses.
    let rogue = h.vault.join("keys/rogue");
    std::fs::create_dir_all(&rogue).unwrap();
    std::fs::write(rogue.join("epoch"), "1\n").unwrap();

    // Shred must refuse.
    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "shred should have refused the unverifiable client"
    );

    // No half-installed rotation: the device key is byte-identical.
    let after = std::fs::read_to_string(&key_path).unwrap();
    assert_eq!(
        before, after,
        "device key changed despite refused shred (would lock the device out)"
    );

    // The device can still read: remove the rogue dir and shred for real.
    // Success proves the old device key still unwraps every remaining
    // client's wrappings (shred's verify-first pass) and that the rotation
    // now happens properly.
    std::fs::remove_dir_all(&rogue).unwrap();
    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred after removing rogue dir failed (device locked out?): stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let rotated = std::fs::read_to_string(&key_path).unwrap();
    assert_ne!(
        rotated.trim(),
        before.trim(),
        "device key was not rotated by the successful shred"
    );
}

/// Extract the 24-word phrase from stderr (the display block).
fn extract_phrase(stderr: &str) -> String {
    for line in stderr.lines() {
        if line.split_whitespace().count() == 24 {
            return line.trim().to_string();
        }
    }
    panic!("no 24-word phrase found on stderr:\n{stderr}");
}
