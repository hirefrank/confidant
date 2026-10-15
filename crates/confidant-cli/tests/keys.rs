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
        let mut c = self.cmd_no_vault(args);
        c.arg("--vault").arg(&self.vault);
        c
    }

    /// Command without --vault (for `keys device-add --initiate`, which
    /// needs no vault).
    fn cmd_no_vault(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
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

// --- #105: shred <-> inbox rotation ---------------------------------------

/// `[inbox].pubkey` from the vault's `confidant.toml` (the advertised pin).
fn vault_inbox_pubkey(vault: &Path) -> String {
    let text = std::fs::read_to_string(vault.join("confidant.toml")).unwrap();
    let doc: toml::Value = toml::from_str(&text).unwrap();
    doc["inbox"]["pubkey"]
        .as_str()
        .expect("[inbox].pubkey in confidant.toml")
        .to_string()
}

/// `[trust].recovery_age_recipient` from the device's `trust.toml`.
fn recovery_age(home: &Path) -> String {
    let text = std::fs::read_to_string(home.join(".config/confidant/trust.toml")).unwrap();
    let doc: toml::Value = toml::from_str(&text).unwrap();
    doc["trust"]["recovery_age_recipient"]
        .as_str()
        .expect("recovery_age_recipient in trust.toml")
        .to_string()
}

#[test]
fn keys_shred_on_inbox_device_starts_rotation_test18() {
    // #105 test 18 (B1): on a device that holds the inbox key, `keys shred`
    // starts the inbox rotation — the new keypair is active, the old key is
    // still present, and `--finish` is pending.
    let mut h = Harness::new();
    h.with_test_keychain();
    assert!(h.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    // Seed this device's inbox key. A lost-key `inbox rotate` installs a
    // fresh keypair without needing an old one. The keychain switch must be
    // ON (rotation is a keychain write); the file backend stands in for it.
    let out = h
        .cmd(&["inbox", "rotate", "--json", "--no-input"])
        .env_remove("CONFIDANT_KEYCHAIN")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "seed inbox rotate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pin_before = vault_inbox_pubkey(&h.vault);

    // Shred client-a. This device holds the inbox key, so the rotation runs
    // (not the reminder path).
    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .env_remove("CONFIDANT_KEYCHAIN")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["inbox_rotated"], true,
        "shred must run the inbox rotation on the inbox device"
    );
    assert!(
        !h.home
            .join(".config/confidant/inbox-rotation-pending.toml")
            .exists(),
        "on-device rotation must not write the off-device reminder"
    );

    // The new inbox keypair is active: the vault's advertised pin changed.
    let pin_after = vault_inbox_pubkey(&h.vault);
    assert_ne!(pin_before, pin_after, "inbox key did not rotate");

    // The old key is still present (`--finish` pending): finishing destroys
    // it. If the previous slot were empty, `--finish` would report
    // `old_key_destroyed: false`.
    let out = h
        .cmd(&["inbox", "rotate", "--finish", "--json", "--no-input"])
        .env_remove("CONFIDANT_KEYCHAIN")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "inbox rotate --finish failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["old_key_destroyed"], true,
        "old inbox key must still be present after shred (--finish pending)"
    );
}

#[test]
fn doctor_reports_and_clears_pending_inbox_rotation() {
    // #105: on a non-inbox device, `keys shred` writes the device-local
    // reminder; `doctor` warns until the operator explicitly clears it.
    let mut h = Harness::new();
    h.with_test_keychain();
    assert!(h.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    // No inbox key here: the reminder is written.
    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "shred failed");
    let pending = h.home.join(".config/confidant/inbox-rotation-pending.toml");
    assert!(pending.is_file(), "reminder not written");

    // doctor surfaces it as a warning.
    let out = h.cmd(&["doctor", "--json", "--no-input"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "inbox-rotation-pending" && c["status"] == "warning"),
        "doctor did not report inbox-rotation-pending: {v}"
    );

    // Explicit clear removes it.
    let out = h
        .cmd(&["doctor", "--clear-pending-inbox-rotation", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "clear failed");
    assert!(!pending.exists(), "reminder not cleared");

    // ...and doctor no longer warns.
    let out = h.cmd(&["doctor", "--json", "--no-input"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        !v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "inbox-rotation-pending"),
        "doctor still reports the cleared reminder: {v}"
    );
}

#[test]
fn device_add_refuses_retired_recovery_recipient() {
    // #153 nit 7: after a recovery rotation the retired recovery age
    // recipient is recorded in `keys/recovery-recipients.toml`, so it can
    // never be re-enrolled as a device (which would undo the shred).
    let mut h = Harness::new();
    h.with_test_keychain();
    assert!(h.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    let old_recovery = recovery_age(&h.home);

    // Shred rotates the recovery identity.
    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The retired recipient is recorded in the vault history file...
    let hist = std::fs::read_to_string(h.vault.join("keys/recovery-recipients.toml"))
        .expect("recovery-recipients.toml written by the rotation");
    assert!(
        hist.contains(&old_recovery),
        "retired recovery recipient not recorded:\n{hist}"
    );

    // ...and re-adding it as a device is refused.
    let req = h.home.join("rogue.toml");
    std::fs::write(
        &req,
        format!("version = 1\npubkey = \"{old_recovery}\"\nlabel = \"rogue\"\n"),
    )
    .unwrap();
    let before = snapshot_keys(&h.vault);
    let out = h
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a retired recovery recipient must be refused as a device"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already been a recipient"),
        "expected historical-pubkey refusal, got: {stderr}"
    );
    assert_eq!(
        before,
        snapshot_keys(&h.vault),
        "refused request mutated keys/"
    );

    // The union is read across git history: even if a later commit erases
    // the entry from the file, the retired recipient stays refused.
    std::fs::write(
        h.vault.join("keys/recovery-recipients.toml"),
        "recipients = []\n",
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "erase recovery history"]);
    let req2 = h.home.join("rogue2.toml");
    std::fs::write(
        &req2,
        format!("version = 1\npubkey = \"{old_recovery}\"\nlabel = \"rogue2\"\n"),
    )
    .unwrap();
    let out = h
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req2.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "erasing the history file must not re-allow the retired recovery recipient"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already been a recipient"),
        "expected the historical-pubkey refusal after erasing, got: {stderr}"
    );
}

/// Snapshot a directory tree as sorted (relative path, bytes) pairs,
/// for byte-identical comparisons of `keys/`.
fn snapshot_tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.is_dir() {
                walk(&p, base, out);
            } else if p.is_file() {
                out.push((
                    p.strip_prefix(base).unwrap().to_path_buf(),
                    std::fs::read(&p).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Number of commits on HEAD in `vault`.
fn git_log_count(vault: &Path) -> usize {
    let out = Command::new("git")
        .current_dir(vault)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    assert!(out.status.success(), "git rev-list failed");
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

/// No staging leftovers from #175: no stage, no backup tree, no staged
/// seq tracker.
fn assert_no_staging_leftovers(h: &Harness) {
    assert!(!h.vault.join(".confidant/keys.stage").exists());
    assert!(!h.vault.join(".confidant/keys.old").exists());
    assert!(!h
        .home
        .join(".config/confidant/manifest-seq.stage.toml")
        .exists());
}

#[test]
fn device_add_check_failure_leaves_keys_untouched() {
    // #175: when the pre-commit `check` fails after the keys/ mutation
    // ran in the stage, keys/ must be byte-identical (including
    // pre-existing uncommitted operator work), nothing may be committed,
    // and no staging leftovers may remain. The old "restore with
    // `git checkout -- keys/`" fix text is gone.
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Uncommitted operator work inside keys/: an untracked note. The
    // staged copy must carry it, and a failed op must leave it alone.
    std::fs::write(h1.vault.join("keys/operator-note.txt"), "do not delete\n").unwrap();
    let before = snapshot_tree(&h1.vault.join("keys"));
    let commits_before = git_log_count(&h1.vault);

    // A directory under a collection whose name is not a record ID makes
    // `check` fail deterministically (E_INVALID_FILENAME).
    std::fs::create_dir_all(h1.vault.join("people/not-a-record-id")).unwrap();
    std::fs::write(
        h1.vault.join("people/not-a-record-id/profile.md"),
        "@id: p-01HZZZZZZZZZZZZZZZZZZZZZ\n@type: person\n",
    )
    .unwrap();

    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "check should block the commit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("keys/ was not modified"),
        "expected the not-modified message, got: {stderr}"
    );
    assert!(
        !stderr.contains("checkout -- keys/"),
        "the git-checkout recovery hint is gone: {stderr}"
    );
    assert_eq!(snapshot_tree(&h1.vault.join("keys")), before);
    assert_eq!(git_log_count(&h1.vault), commits_before);
    assert_no_staging_leftovers(&h1);
    // The operator's uncommitted work outside keys/ is untouched too.
    assert!(h1.vault.join("people/not-a-record-id/profile.md").is_file());
}

#[test]
fn revoke_check_failure_leaves_keys_untouched() {
    // #175: same guarantee as device-add — a failing pre-commit check
    // after a revoke mutation leaves keys/ byte-identical.
    let (h1, _h2, _req, key_id, _stderr) = device_add_setup();
    let before = snapshot_tree(&h1.vault.join("keys"));
    let commits_before = git_log_count(&h1.vault);

    std::fs::create_dir_all(h1.vault.join("people/not-a-record-id")).unwrap();
    std::fs::write(
        h1.vault.join("people/not-a-record-id/profile.md"),
        "@id: p-01HZZZZZZZZZZZZZZZZZZZZZ\n@type: person\n",
    )
    .unwrap();

    let out = h1
        .cmd(&[
            "keys",
            "revoke",
            "client-a",
            &key_id,
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "check should block the commit");
    // --json renders the error as JSON on stdout, not stderr.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let message = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("keys/ was not modified"),
        "expected the not-modified message, got: {message}"
    );
    let rendered = String::from_utf8_lossy(&out.stdout);
    assert!(
        !rendered.contains("checkout -- keys/"),
        "the git-checkout recovery hint is gone: {rendered}"
    );
    assert_eq!(snapshot_tree(&h1.vault.join("keys")), before);
    assert_eq!(git_log_count(&h1.vault), commits_before);
    assert_no_staging_leftovers(&h1);
}

#[test]
fn device_add_repairs_leftover_staging_state() {
    // #175: stale stage / keys.old / staged tracker from a crashed run
    // are repaired before the mutation starts; the op then succeeds.
    // Doctor reports the leftovers as a warning while keys/ is intact.
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Fake leftovers from a crashed run.
    let stage = h1.vault.join(".confidant/keys.stage");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("sentinel"), b"stale").unwrap();
    let old = h1.vault.join(".confidant/keys.old");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("sentinel"), b"old").unwrap();
    std::fs::write(
        h1.home.join(".config/confidant/manifest-seq.stage.toml"),
        b"stale",
    )
    .unwrap();

    let out = h1
        .cmd(&["doctor", "--json", "--no-input"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let staging = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "keys-staging")
        .expect("keys-staging check missing");
    assert_eq!(staging["status"], "warning");

    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "device-add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_staging_leftovers(&h1);

    let out = h1
        .cmd(&["doctor", "--json", "--no-input"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let staging = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "keys-staging")
        .expect("keys-staging check missing");
    assert_eq!(staging["status"], "ok");
}

#[test]
fn device_add_repairs_mid_swap_leftover() {
    // #175: crash after the first rename — keys/ missing, keys.old holds
    // the old tree. Doctor errors; the next keys op restores keys/ from
    // the backup and succeeds.
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Simulate the crash: keys/ -> keys.old, stale stage left behind.
    std::fs::create_dir_all(h1.vault.join(".confidant")).unwrap();
    std::fs::rename(h1.vault.join("keys"), h1.vault.join(".confidant/keys.old")).unwrap();
    std::fs::create_dir_all(h1.vault.join(".confidant/keys.stage")).unwrap();
    std::fs::write(h1.vault.join(".confidant/keys.stage/sentinel"), b"stale").unwrap();

    let out = h1
        .cmd(&["doctor", "--json", "--no-input"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let staging = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "keys-staging")
        .expect("keys-staging check missing");
    assert_eq!(staging["status"], "error");

    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "device-add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(h1.vault.join("keys/client-a/recipients.toml").is_file());
    assert_no_staging_leftovers(&h1);
}

#[test]
fn device_add_preserves_untracked_file_in_keys() {
    // #175: an untracked operator file inside keys/ survives the swap
    // (the staged copy carries it).
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::write(h1.vault.join("keys/operator-note.txt"), "do not delete\n").unwrap();
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "device-add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(h1.vault.join("keys/operator-note.txt")).unwrap(),
        "do not delete\n"
    );
    assert_no_staging_leftovers(&h1);
}

#[test]
fn device_add_updates_seq_tracker_through_staged_rename() {
    // #175: the staged seq tracker must be renamed over the real one on
    // success. Delete the real tracker; a successful device-add must
    // recreate it (via the staged rename) with this vault's marks.
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let tracker = h1.home.join(".config/confidant/manifest-seq.toml");
    assert!(
        tracker.is_file(),
        "init-client should have created the tracker"
    );
    std::fs::remove_file(&tracker).unwrap();

    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "device-add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&tracker).unwrap();
    assert!(
        text.contains("01TEST00000000000000000000"),
        "tracker should carry this vault's marks, got: {text}"
    );
    assert!(!h1
        .home
        .join(".config/confidant/manifest-seq.stage.toml")
        .exists());
}

#[test]
fn doctor_warns_on_shallow_clone() {
    // #154 must-fix 4: a shallow clone silently weakens the
    // history-derived checks; doctor must surface it.
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    let clone = h.home.join("shallow");
    let st = std::process::Command::new("git")
        .args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            "-c",
            "core.autocrlf=false",
        ])
        .arg(format!("file://{}", h.vault.display()))
        .arg(&clone)
        .status()
        .unwrap();
    assert!(st.success(), "shallow clone failed");
    assert!(clone.join(".git/shallow").is_file(), "clone is not shallow");

    let out = h
        .cmd_no_vault(&[
            "doctor",
            "--json",
            "--no-input",
            "--vault",
            clone.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "shred-history" && c["status"] == "warning"),
        "expected a shred-history warning on a shallow clone: {v}"
    );
}

#[test]
fn device_add_fails_closed_on_shallow_clone() {
    // #154 must-fix 4: the retired-recipient denylist is load-bearing for
    // device-add, so a shallow clone (history invisible) must fail closed.
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "initiate failed");

    let clone = h1.home.join("shallow");
    let st = std::process::Command::new("git")
        .args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            "-c",
            "core.autocrlf=false",
        ])
        .arg(format!("file://{}", h1.vault.display()))
        .arg(&clone)
        .status()
        .unwrap();
    assert!(st.success(), "shallow clone failed");

    let out = h1
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--from-request",
            req.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
            "--json",
            "--vault",
            clone.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "device-add must fail closed on a shallow clone"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("shallow"),
        "expected a shallow-clone refusal, got: {msg}"
    );
}

#[test]
fn keys_shred_warns_on_shallow_clone() {
    // #156 nit 2: shred must warn (not fail) when git history is degraded.
    let mut h = Harness::new();
    h.with_test_keychain();
    assert!(h.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    let clone = h.home.join("shallow");
    let st = Command::new("git")
        .args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            "-c",
            "core.autocrlf=false",
        ])
        .arg(format!("file://{}", h.vault.display()))
        .arg(&clone)
        .status()
        .unwrap();
    assert!(st.success(), "shallow clone failed");
    // A clone does not inherit the source's identity; the shred commits.
    git(&clone, &["config", "user.name", "Test"]);
    git(&clone, &["config", "user.email", "test@example.com"]);

    let out = h
        .cmd_no_vault(&[
            "keys",
            "shred",
            "client-a",
            "--json",
            "--no-input",
            "--vault",
            clone.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred on a shallow clone should succeed with a warning: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("shallow")),
        "expected a shallow-history warning: {v}"
    );
}

#[test]
fn keys_shred_sweeps_stale_temp_files() {
    // #156 nit 1: a leftover `.confidant-tmp-*` from a crashed atomic write
    // must not survive into a `keys/` commit.
    let mut h = Harness::new();
    h.with_test_keychain();
    assert!(h.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    let stale = h
        .vault
        .join("keys/.confidant-tmp-recovery-recipients-99999");
    std::fs::write(&stale, "recipients = []\n").unwrap();

    let out = h
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stale.exists(),
        "stale temp was not swept before staging keys/"
    );

    let tracked = std::process::Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-files", "--", "keys"])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&tracked.stdout).contains(".confidant-tmp-"),
        "a stale temp file was committed"
    );
}

// --- device-add (#66) -----------------------------------------------------

/// Extract the 24-word recovery phrase from `init`'s stderr.
fn extract_phrase(stderr: &str) -> String {
    stderr
        .lines()
        .find(|l| l.split_whitespace().count() == 24)
        .expect("24-word phrase in init stderr")
        .to_string()
}

/// Shared setup: h1 (enrolled device) with init + two clients (client-a
/// rotated to epoch 2), h2 (new device) --initiate, h1 --from-request.
/// Returns (h1, h2, request_path, new_key_id, init_stderr).
fn device_add_setup() -> (Harness, Harness, PathBuf, String, String) {
    let h1 = Harness::new();
    let init_out = h1.init(&[]);
    assert!(init_out.status.success(), "init failed");
    let init_stderr = String::from_utf8_lossy(&init_out.stderr).into_owned();

    for client in ["client-a", "client-b"] {
        let out = h1
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    // Rotate client-a to epoch 2, leaving retained .e1 wrappings.
    let out = h1
        .cmd(&["keys", "rotate", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "rotate failed");

    // New device: --initiate (needs no vault). Uses the test keychain dir
    // (a device key is "enrolled" there, so --force is required) because
    // --initiate refuses to re-emit an env-var key (#153 nit 4).
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req_path = h2.home.join("device-add-request.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--label",
            "newdev",
            "--output",
            req_path.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Enrolled device: --from-request with out-of-band fingerprint check.
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "from-request failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("from-request JSON");
    let key_id = v["key_id"].as_str().expect("key_id in JSON").to_string();

    (h1, h2, req_path, key_id, init_stderr)
}

#[test]
fn device_add_then_rotate_new_device_still_enrolled() {
    // #151 blocker 1: after device-add, rotate must keep the new device
    // enrolled (not silently drop it). The new device's key_id must be
    // in the rotated manifest's recipients.
    let (h1, h2, _req_path, key_id, _init_stderr) = device_add_setup();

    // Rotate client-a.
    let out = h1
        .cmd(&["keys", "rotate", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "rotate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The rotated manifest must still include the new device.
    let manifest = std::fs::read_to_string(h1.vault.join("keys/client-a/recipients.toml")).unwrap();
    assert!(
        manifest.contains(&key_id),
        "new device {key_id} dropped from manifest after rotate:\n{manifest}"
    );
    // And the old device (device-0) must also still be there.
    assert!(
        manifest.contains("device-0"),
        "device-0 dropped from manifest after rotate:\n{manifest}"
    );

    // Stronger: the new device must actually UNWRAP. Decrypt its wrapping
    // at the current epoch with the new device's identity and check it
    // yields the same 32-byte data key the old device gets.
    let new_key = unwrap_wrapping(&h1.vault, "client-a", &key_id, &h2.device_bech32);
    let old_key = unwrap_wrapping(&h1.vault, "client-a", "device-0", &h1.device_bech32);
    assert_eq!(new_key.len(), 32, "unwrapped data key must be 32 bytes");
    assert_eq!(
        new_key, old_key,
        "new device unwrapped a different data key than the old device"
    );

    // Nit: the new device must also still unwrap the vault lookup key
    // after the rotate (completes the original handoff ask).
    use confidant_crypt::{anchor, lifecycle::KeyStore};
    let config_dir = h1.home.join(".config/confidant");
    let (anchor, _) = anchor::load(&config_dir, &h1.vault).unwrap();
    let mut store = KeyStore::with_config_dir(
        h1.vault.join("keys"),
        "01TEST00000000000000000000",
        &config_dir,
    )
    .unwrap();
    let new_identity: age::x25519::Identity = h2.device_bech32.trim().parse().unwrap();
    let (new_lookup, _, _) = store
        .read_lookup_key(&new_identity, &anchor)
        .expect("new device cannot unwrap lookup key after rotate");
    let old_identity: age::x25519::Identity = h1.device_bech32.trim().parse().unwrap();
    let (old_lookup, _, _) = store.read_lookup_key(&old_identity, &anchor).unwrap();
    assert_eq!(
        new_lookup.as_bytes(),
        old_lookup.as_bytes(),
        "lookup key changed across rotate"
    );
}

/// Decrypt a client's wrapping file for `key_id` at the current epoch
/// with the given Bech32 age identity. Returns the raw data-key bytes.
fn unwrap_wrapping(vault: &std::path::Path, client: &str, key_id: &str, bech32: &str) -> Vec<u8> {
    // Current epoch: read from the epoch file.
    let epoch: u64 = std::fs::read_to_string(vault.join(format!("keys/{client}/epoch")))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let wrapping =
        std::fs::read(vault.join(format!("keys/{client}/wrapped/{key_id}.e{epoch}.age")))
            .unwrap_or_else(|_| {
                std::fs::read(vault.join(format!("keys/{client}/wrapped/{key_id}.age"))).unwrap()
            });
    let identity: age::x25519::Identity = bech32.trim().parse().unwrap();
    let decryptor = age::Decryptor::new(&wrapping[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut out = Vec::new();
    use std::io::Read;
    reader.read_to_end(&mut out).unwrap();
    // The wrapping encrypts the 32-byte data key; expose and return it.
    // (DataKey zeroizes on drop inside the crypt layer; here we hold raw
    // bytes only for the assertion.)
    out
}

#[test]
fn device_add_from_request_rejects_bad_label() {
    // #151 nit 1: a hand-edited request with a bad label (control chars /
    // overlong / bad charset) must fail closed on --from-request too, not
    // just --initiate.
    let (h1, _h2, req_path, _key_id, _init_stderr) = device_add_setup();

    // Note: control characters are now REJECTED outright (#153 nit 6), not
    // stripped — so the ESC/CR case fails validation directly.
    let before = snapshot_keys(&h1.vault);
    for (name, bad_label) in [
        ("empty", "   "),
        ("overlong", &"x".repeat(65)),
        ("charset", "bad;label|here"),
        ("esc-cr", "\x1b[2J\r"),
    ] {
        let raw = std::fs::read_to_string(&req_path).unwrap();
        let mut request: toml::Value = toml::from_str(&raw).unwrap();
        request["label"] = toml::Value::String(bad_label.to_string());
        let bad_path = h1.home.join(format!("bad-{name}.toml"));
        std::fs::write(&bad_path, toml::to_string(&request).unwrap()).unwrap();

        let out = h1
            .cmd(&[
                "keys",
                "device-add",
                "--from-request",
                bad_path.to_str().unwrap(),
                "--fingerprint-verified",
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "--from-request accepted bad label ({name}): {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("label"),
            "expected label error for {name}, got: {stderr}"
        );
    }
    // None of the refused requests may have touched keys/.
    assert_eq!(
        before,
        snapshot_keys(&h1.vault),
        "refused bad-label requests mutated keys/"
    );
}

#[test]
fn device_add_initiate_refuses_when_device_key_enrolled() {
    // #151 blocker 2: --initiate on an already-enrolled device must
    // refuse (it would overwrite the keychain entry and lock the device
    // out). --force overrides.
    let mut h = Harness::new();
    // A device key is "enrolled" in the test keychain dir.
    h.with_test_keychain();
    let out = h
        .cmd_no_vault(&["keys", "device-add", "--initiate", "--no-input"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--initiate should refuse when a device key is enrolled"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already enrolled"),
        "expected 'already enrolled' error, got: {stderr}"
    );

    // With --force, it succeeds.
    let out = h
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "--initiate --force failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn device_add_initiate_refuses_device_key_env() {
    // #153 nit 4: with CONFIDANT_DEVICE_KEY set, --initiate cannot generate
    // a fresh keypair (it would re-emit the env key) — it must fail closed
    // up front (as shred does), not let the enrolled device reject the
    // request later. The harness sets CONFIDANT_DEVICE_KEY.
    let h = Harness::new();
    for extra in [&[][..], &["--force"][..]] {
        let mut args = vec!["keys", "device-add", "--initiate", "--no-input"];
        args.extend_from_slice(extra);
        let out = h.cmd_no_vault(&args).output().unwrap();
        assert!(
            !out.status.success(),
            "--initiate with CONFIDANT_DEVICE_KEY must fail closed ({extra:?})"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("CONFIDANT_DEVICE_KEY"),
            "expected a CONFIDANT_DEVICE_KEY refusal ({extra:?}), got: {stderr}"
        );
    }
}

#[test]
fn device_add_initiate_output_contains_pubkey_only() {
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    // Bogus vault path: --initiate must neither need nor touch a vault.
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--label",
            "laptop2",
            "--vault",
            "/nonexistent-vault-path",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // B1: pubkey + label only; scan for private material.
    assert!(stdout.contains("age1"), "request missing pubkey");
    assert!(stdout.contains("laptop2"), "request missing label");
    assert!(
        !stdout.contains("AGE-SECRET-KEY"),
        "private key in request stdout"
    );
    assert!(!stderr.contains("AGE-SECRET-KEY"), "private key on stderr");
    assert!(
        stderr.contains("fingerprint"),
        "fingerprint not shown on stderr: {stderr}"
    );
    // No vault touched.
    assert!(
        !h2.vault.join("keys").exists(),
        "--initiate created a keys/ tree"
    );
}

#[test]
fn device_add_rewraps_all_clients_and_lookup_key_all_epochs() {
    let (h1, _h2, _req, key_id, _stderr) = device_add_setup();

    // B2: new recipient's wrappings — current epoch + retained epochs.
    assert!(
        h1.vault
            .join(format!("keys/client-a/wrapped/{key_id}.age"))
            .exists(),
        "missing client-a epoch-2 wrapping"
    );
    assert!(
        h1.vault
            .join(format!("keys/client-a/wrapped/{key_id}.e1.age"))
            .exists(),
        "missing client-a retained epoch-1 wrapping"
    );
    assert!(
        h1.vault
            .join(format!("keys/client-b/wrapped/{key_id}.age"))
            .exists(),
        "missing client-b wrapping"
    );
    // Manifests list the new recipient.
    for client in ["client-a", "client-b"] {
        let toml = std::fs::read_to_string(h1.vault.join(format!("keys/{client}/recipients.toml")))
            .unwrap();
        assert!(
            toml.contains(&key_id),
            "{client} manifest missing new recipient"
        );
    }
    // One commit for the device-add.
    let out = std::process::Command::new("git")
        .current_dir(&h1.vault)
        .args(["log", "-1", "--format=%s"])
        .output()
        .unwrap();
    let msg = String::from_utf8_lossy(&out.stdout);
    assert!(
        msg.contains("device-add"),
        "last commit is not the device-add: {msg}"
    );
}

#[test]
fn lookup_key_handoff_never_recovery_wrapped() {
    let (h1, h2, _req, _key_id, init_stderr) = device_add_setup();

    use confidant_crypt::{anchor, lifecycle::KeyStore, recovery::Recovery};
    let config_dir = h1.home.join(".config/confidant");
    let (anchor, _) = anchor::load(&config_dir, &h1.vault).unwrap();
    let mut store = KeyStore::with_config_dir(
        h1.vault.join("keys"),
        "01TEST00000000000000000000",
        &config_dir,
    )
    .unwrap();

    // B3: the new device unwraps the lookup key — handed off, not
    // regenerated: the old device unwraps the identical bytes.
    let new_identity: age::x25519::Identity = h2.device_bech32.trim().parse().unwrap();
    let (new_lookup, _, _) = store
        .read_lookup_key(&new_identity, &anchor)
        .expect("new device cannot unwrap lookup key");
    let old_identity: age::x25519::Identity = h1.device_bech32.trim().parse().unwrap();
    let (old_lookup, _, _) = store.read_lookup_key(&old_identity, &anchor).unwrap();
    assert_eq!(
        new_lookup.as_bytes(),
        old_lookup.as_bytes(),
        "lookup key changed on device-add; it must be handed off"
    );

    // #142 invariant: the recovery identity unwraps client keys but NEVER
    // the lookup key.
    let phrase = extract_phrase(&init_stderr);
    let recovery = Recovery::from_phrase(&phrase).unwrap();
    let rec_identity = recovery.age_identity().to_age_identity().unwrap();
    assert!(
        store.read_lookup_key(&rec_identity, &anchor).is_err(),
        "recovery identity unwrapped the lookup key"
    );
    assert!(
        store
            .unwrap_data_key("client-a", "recovery", 1, &rec_identity, &anchor)
            .is_ok(),
        "recovery cannot unwrap client data key"
    );
}

#[test]
fn device_add_requires_fingerprint_confirmation() {
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req_path = h2.home.join("request.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--output",
            req_path.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // B2 gate: --no-input without --fingerprint-verified refuses (exit 2).
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req_path.to_str().unwrap(),
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 without fingerprint verification"
    );
    // Nothing mutated: the keys/ tree is untouched.
    let git_out = std::process::Command::new("git")
        .current_dir(&h1.vault)
        .args(["status", "--porcelain", "--", "keys"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&git_out.stdout).trim().is_empty(),
        "keys/ tree mutated by refused device-add"
    );
}

#[test]
fn second_device_decrypts_after_add() {
    let (h1, h2, _req, key_id, _stderr) = device_add_setup();

    use confidant_crypt::{anchor, lifecycle::KeyStore};
    let config_dir = h1.home.join(".config/confidant");
    let (anchor, _) = anchor::load(&config_dir, &h1.vault).unwrap();
    let mut store = KeyStore::with_config_dir(
        h1.vault.join("keys"),
        "01TEST00000000000000000000",
        &config_dir,
    )
    .unwrap();

    let new_identity: age::x25519::Identity = h2.device_bech32.trim().parse().unwrap();
    let old_identity: age::x25519::Identity = h1.device_bech32.trim().parse().unwrap();
    // Old device's key id: device-0 (the init-enrolled device, per the
    // one key-id scheme).
    let old_key_id = "device-0".to_string();

    // B3: new device unwraps every client's every epoch; old device still can.
    for (client, epochs) in [("client-a", vec![1u64, 2u64]), ("client-b", vec![1u64])] {
        for e in epochs {
            assert!(
                store
                    .unwrap_data_key(client, &key_id, e, &new_identity, &anchor)
                    .is_ok(),
                "new device cannot unwrap {client} epoch {e}"
            );
            assert!(
                store
                    .unwrap_data_key(client, &old_key_id, e, &old_identity, &anchor)
                    .is_ok(),
                "old device lost access to {client} epoch {e}"
            );
        }
    }
}

#[test]
fn device_add_then_revoke_removes_new_device_wrappings() {
    let (h1, _h2, _req, key_id, _stderr) = device_add_setup();

    // B4: revocation is the existing `keys revoke` — no new code.
    let out = h1
        .cmd(&[
            "keys",
            "revoke",
            "client-a",
            &key_id,
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Wrappings gone across all epochs.
    let wrapped_dir = h1.vault.join("keys/client-a/wrapped");
    let entries: Vec<String> = std::fs::read_dir(&wrapped_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !entries.iter().any(|n| n.starts_with(&key_id)),
        "revoked device wrappings remain: {entries:?}"
    );
    let toml = std::fs::read_to_string(h1.vault.join("keys/client-a/recipients.toml")).unwrap();
    assert!(
        !toml.contains(&key_id),
        "manifest still lists the revoked device"
    );
}

#[test]
fn device_add_json_no_secrets() {
    // B5: --json on both steps carries opaque fields only.
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--label",
            "x",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("AGE-SECRET-KEY"),
        "secret in --initiate JSON"
    );
    assert!(stdout.contains("fingerprint"), "JSON missing fingerprint");

    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let req_path = h2.home.join("r.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--output",
            req_path.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("AGE-SECRET-KEY"),
        "secret in --from-request JSON"
    );
    assert!(!stderr.contains("AGE-SECRET-KEY"), "secret on stderr");
}

// --- #151 round 3 ----------------------------------------------------------

/// Snapshot every file under keys/ as (relative path, bytes), sorted.
/// For asserting a refused operation left keys/ byte-identical.
fn snapshot_keys(vault: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut dirs = vec![vault.join("keys")];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else {
                let rel = p
                    .strip_prefix(vault)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn device_add_from_request_refuses_previously_seen_pubkey() {
    // Blocker 2 (#151): after a shred, re-sending a device's ORIGINAL
    // request must be refused — its pubkey is in history, and re-wrapping
    // to it would silently undo the shred. keys/ must be byte-identical.
    let mut h1 = Harness::new();
    // Shred rotates the device key: use the test keychain dir.
    h1.with_test_keychain();
    assert!(h1.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h1
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    // B enrolls with its original key.
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req_path = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "from-request failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Shred client-a on A.
    let out = h1
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Snapshot keys/ after the shred.
    let before = snapshot_keys(&h1.vault);

    // Re-send B's ORIGINAL request: must be refused (no --json so the
    // error lands on stderr)...
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "re-sent request after shred must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already been a recipient"),
        "expected historical-pubkey refusal, got: {stderr}"
    );

    // ...and keys/ must be byte-identical (the check runs before any
    // mutation).
    let after = snapshot_keys(&h1.vault);
    assert_eq!(before, after, "refused --from-request mutated keys/");
}

#[test]
fn device_add_from_request_refuses_shredded_only_pubkey() {
    // Silas's gap (#151): the historical-pubkey refusal consulted only
    // live manifest clients (and the lookup map). A pubkey present ONLY in
    // a shredded client's git history was not refused — re-adding it
    // re-wraps the lookup key to a key that still opens the shredded
    // client's wrappings in git history, silently undoing the shred.
    // (Realistic source: a device enrolled via `recover` — its pubkey
    // enters client manifests, but the lookup key is re-initialized fresh
    // so it never enters lookup history.)
    let mut h1 = Harness::new();
    h1.with_test_keychain();
    assert!(h1.init(&[]).status.success());
    let out = h1
        .cmd(&["keys", "init-client", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");

    // B generates a request but is NEVER enrolled: its pubkey appears in
    // no live manifest and no lookup history.
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req_path = h2.home.join("req.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req_toml = std::fs::read_to_string(&req_path).unwrap();
    let pubkey = req_toml
        .lines()
        .find_map(|l| l.strip_prefix("pubkey = "))
        .expect("pubkey line in request")
        .trim()
        .trim_matches('"')
        .to_string();
    assert!(pubkey.starts_with("age1"), "bad pubkey in request");

    // Simulate a shredded client whose history contains B's pubkey: write
    // a recipients.toml, commit it, then delete the tree and commit.
    // (historical_recipients parses the TOML from git history without
    // verifying signatures — same as shred's destroy-list derivation.)
    let rogue = h1.vault.join("keys/rogue");
    std::fs::create_dir_all(&rogue).unwrap();
    std::fs::write(
        rogue.join("recipients.toml"),
        format!(
            "seq = 1\n\n[recipients.device-0]\nage_pubkey = \"{pubkey}\"\nlabel = \"rogue-device\"\nscope_ref = \"\"\n"
        ),
    )
    .unwrap();
    git(&h1.vault, &["add", "-A"]);
    git(&h1.vault, &["commit", "-qm", "rogue client"]);
    std::fs::remove_dir_all(&rogue).unwrap();
    git(&h1.vault, &["add", "-A"]);
    git(&h1.vault, &["commit", "-qm", "shred rogue client"]);

    let before = snapshot_keys(&h1.vault);

    // from-request with B's request: must be refused — the pubkey is in
    // the shredded client's history and nowhere else.
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "request with shredded-history pubkey must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already been a recipient"),
        "expected historical-pubkey refusal, got: {stderr}"
    );

    // ...and keys/ must be byte-identical.
    let after = snapshot_keys(&h1.vault);
    assert_eq!(before, after, "refused --from-request mutated keys/");
}

#[test]
fn device_add_shred_then_reenroll() {
    // Item 4 (#151): the main multi-device path after a shred — shred on
    // A, B re-enrolls with --initiate --force (fresh keypair), A runs
    // --from-request, then B can unwrap a remaining client.
    let mut h1 = Harness::new();
    h1.with_test_keychain();
    assert!(h1.init(&[]).status.success());
    for client in ["client-a", "client-b"] {
        let out = h1
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }

    // B enrolls with its original key.
    let mut h2 = Harness::new();
    h2.with_test_keychain();
    let req1_path = h2.home.join("req1.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b",
            "--output",
            req1_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req1_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "from-request failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Shred client-a on A (rotates A's device key).
    let out = h1
        .cmd(&["keys", "shred", "client-a", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // B re-enrolls: a FRESH keypair via --initiate --force (the old key is
    // dead — its pubkey is in the shredded history, so re-sending the old
    // request would be refused).
    let fresh_bech32 = age_generate_bech32();
    std::fs::write(
        h2.keychain_dir.as_ref().unwrap().join("device.key"),
        &fresh_bech32,
    )
    .unwrap();
    let req2_path = h2.home.join("req2.toml");
    let out = h2
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--no-input",
            "--label",
            "b2",
            "--output",
            req2_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "re-initiate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A approves the re-enrollment.
    let out = h1
        .cmd(&[
            "keys",
            "device-add",
            "--from-request",
            req2_path.to_str().unwrap(),
            "--fingerprint-verified",
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "re-enroll from-request failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let key_id2 = v["key_id"].as_str().expect("key_id in JSON").to_string();

    // B unwraps the remaining client (client-b) with its fresh identity;
    // it must yield the same data key A gets (A's key was rotated by the
    // shred — read it from the test keychain dir).
    let h1_key =
        std::fs::read_to_string(h1.keychain_dir.as_ref().unwrap().join("device.key")).unwrap();
    let new_key = unwrap_wrapping(&h1.vault, "client-b", &key_id2, fresh_bech32.trim());
    let old_key = unwrap_wrapping(&h1.vault, "client-b", "device-0", h1_key.trim());
    assert_eq!(new_key.len(), 32, "unwrapped data key must be 32 bytes");
    assert_eq!(
        new_key, old_key,
        "re-enrolled device unwrapped a different data key than A"
    );
}

#[test]
fn device_add_initiate_force_prompts_without_no_input() {
    // Item 5 (#151): --force on --initiate must prompt for confirmation
    // unless --no-input, and say plainly the old key's access is lost.
    let mut h = Harness::new();
    // A device key is "enrolled" in the test keychain dir, so --initiate
    // needs --force (and then prompts).
    h.with_test_keychain();

    // Answer "y": proceeds.
    let mut child = h
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--label",
            "x",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(b"y\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "--initiate --force (confirmed) failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no longer work") || stderr.contains("lose access"),
        "prompt must say the old key's access is lost, got: {stderr}"
    );

    // Answer "n": refused.
    let mut child = h
        .cmd_no_vault(&[
            "keys",
            "device-add",
            "--initiate",
            "--force",
            "--label",
            "x",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"n\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        !out.status.success(),
        "--initiate --force (declined) should refuse"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not confirmed"),
        "expected not-confirmed refusal, got: {stderr}"
    );
}

#[test]
fn device_add_initiate_validates_label_before_provisioning() {
    // Item 6 (#151): the label must be validated BEFORE the device key is
    // provisioned. A bad label must fail as a usage error (exit 2) even
    // when the key source itself is broken — proving validation ran first.
    let h = Harness::new();
    let out = h
        .cmd_no_vault(&["keys", "device-add", "--initiate", "--label", "bad;label"])
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", "not-a-valid-key")
        .output()
        .unwrap();
    assert!(!out.status.success(), "bad label should fail");
    assert_eq!(
        out.status.code(),
        Some(2),
        "bad label must be a usage error (exit 2), not a key error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("label"),
        "expected label validation error, got: {stderr}"
    );
}

#[test]
fn keys_shred_deletes_edges_naming_shredded_person() {
    // #179 Q1: `keys shred p-A` deletes edges naming A from the working
    // tree in the SAME signed commit, and says earlier git-history
    // versions stay readable under the shared key. Edges not naming A
    // survive.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    const PERSON_A: &str = "p-01J9Z3K4QF0000000000000000";
    const PERSON_B: &str = "p-01J9Z3K4QG0000000000000000";
    const PERSON_C: &str = "p-01J9Z3K4QH0000000000000000";
    const EDGE_AB: &str = "e-01M3TC5H00MPJG00E100000000";
    const EDGE_BC: &str = "e-01M3TC5H00MPJG00E200000000";
    for client in [PERSON_A, PERSON_B, PERSON_C] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    // Person records, so the edges' ends exist (writes run check).
    for (id, name) in [
        (PERSON_A, "Ada Example"),
        (PERSON_B, "Bea Demo"),
        (PERSON_C, "Cam Sample"),
    ] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\nBio.\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    // Two edges: AB names the to-be-shredded A, BC does not.
    for (id, a, b, kind) in [
        (EDGE_AB, PERSON_A, PERSON_B, "married"),
        (EDGE_BC, PERSON_B, PERSON_C, "colleague"),
    ] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: edge\na: {a}\nb: {b}\nkind: {kind}\n---\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    let edge_ab = h.vault.join(format!("edges/{EDGE_AB}/edge.md"));
    let edge_bc = h.vault.join(format!("edges/{EDGE_BC}/edge.md"));
    assert!(edge_ab.is_file());
    assert!(edge_bc.is_file());

    // Shred A.
    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    // The AB edge is gone from the working tree; BC survives.
    assert!(
        !edge_ab.exists(),
        "edge naming the shredded person survived"
    );
    assert!(edge_bc.is_file(), "edge not naming them must survive");
    // The deletion is reported, with the history-readability warning.
    let deleted = v["deleted_edges"].as_array().unwrap();
    assert_eq!(deleted.len(), 1, "{v}");
    assert_eq!(deleted[0], format!("edges/{EDGE_AB}/edge.md"));
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("earlier versions in git history remain readable with the shared key")),
        "shred must warn that history versions stay readable: {warnings:?}"
    );
    // The deletion is in the SAME commit as the shred (HEAD is the shred
    // commit and it deletes the edge file).
    let log = Command::new("git")
        .current_dir(&h.vault)
        .args(["log", "-1", "--format=%s"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&log.stdout).trim(),
        format!("keys: shred {PERSON_A}")
    );
    let show = Command::new("git")
        .current_dir(&h.vault)
        .args(["show", "--name-status", "--format=", "HEAD"])
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&show.stdout);
    assert!(
        status.contains(&format!("D\tedges/{EDGE_AB}/edge.md")),
        "shred commit must delete the edge file, got:\n{status}"
    );
    // The history version is still there (readable under the shared key):
    // the edge file exists in the parent commit.
    let parent = Command::new("git")
        .current_dir(&h.vault)
        .args(["show", &format!("HEAD~1:edges/{EDGE_AB}/edge.md")])
        .output()
        .unwrap();
    assert!(
        parent.status.success(),
        "edge must still exist in git history"
    );
}

#[test]
fn keys_shred_strips_shredded_person_from_with_lists() {
    // #258: `keys shred p-A` re-encrypts any interaction whose `with:`
    // names A, dropping A from the list, in the SAME signed commit — and
    // warns that earlier git-history versions still list A under the
    // surviving primary's key.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    const PERSON_A: &str = "p-01J9Z3K4QF0000000000000000";
    const PERSON_B: &str = "p-01J9Z3K4QG0000000000000000";
    const PERSON_C: &str = "p-01J9Z3K4QH0000000000000000";
    const IXN_BC: &str = "i-01M3TC5H00MPJG0048H0000008";
    for client in [PERSON_A, PERSON_B, PERSON_C] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    for (id, name) in [
        (PERSON_A, "Ada Example"),
        (PERSON_B, "Bea Demo"),
        (PERSON_C, "Cam Sample"),
    ] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\nBio.\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    // A multi-person interaction: primary B, participants A and C.
    let file = h._tmp.path().join(format!("{IXN_BC}.md"));
    std::fs::write(
        &file,
        format!(
            "---\nid: {IXN_BC}\ntype: interaction\nname: Dinner\ndate: 2026-10-06\nperson: {PERSON_B}\nwith: [{PERSON_A}, {PERSON_C}]\n---\n\nDinner with the group.\n"
        ),
    )
    .unwrap();
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            file.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add interaction failed");

    let ixn_path = h
        .vault
        .join(format!("interactions/{IXN_BC}/interaction.md"));
    assert!(ixn_path.is_file());
    let before = std::fs::read(&ixn_path).unwrap();

    // Shred A.
    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    // Exactly one interaction was re-encrypted.
    assert_eq!(v["stripped_interactions"], 1, "{v}");
    // The warning names the history-residue limit.
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("re-encrypted to remove this person from their participant lists")),
        "shred must warn about with:-list history residue: {warnings:?}"
    );
    // The interaction envelope was re-encrypted (fresh nonce → new bytes),
    // and it still decrypts under the surviving primary B's key.
    let after = std::fs::read(&ixn_path).unwrap();
    assert_ne!(before, after, "interaction envelope must be re-encrypted");
    // The re-encryption is in the SAME commit as the shred.
    let log = Command::new("git")
        .current_dir(&h.vault)
        .args(["log", "-1", "--format=%s"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&log.stdout).trim(),
        format!("keys: shred {PERSON_A}")
    );
    let show = Command::new("git")
        .current_dir(&h.vault)
        .args(["show", "--name-status", "--format=", "HEAD"])
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&show.stdout);
    assert!(
        status.contains(&format!("M\tinteractions/{IXN_BC}/interaction.md")),
        "shred commit must re-encrypt the interaction, got:\n{status}"
    );
    // Keyed read: the interaction still decrypts under B's surviving key,
    // and its `with:` now lists only C (A is gone).
    let find = h
        .cmd(&["find", "with:", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        find.status.success(),
        "find failed: {}",
        String::from_utf8_lossy(&find.stderr)
    );
    let fv: serde_json::Value = serde_json::from_slice(&find.stdout).unwrap();
    let with_lines: Vec<String> = fv["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["excerpt"].as_str().map(str::to_owned))
        .filter(|e| e.contains("with:"))
        .collect();
    assert_eq!(
        with_lines.len(),
        1,
        "expected one with: line: {with_lines:?}"
    );
    assert!(
        with_lines[0].contains(PERSON_C),
        "with: must list C: {with_lines:?}"
    );
    assert!(
        !with_lines[0].contains(PERSON_A),
        "with: must not list A: {with_lines:?}"
    );
}

#[test]
fn keys_shred_refused_shred_restores_working_tree() {
    // #320 item 2: `delete_edges_naming` and
    // `strip_participant_from_interactions` mutate the working tree BEFORE
    // `KeyStore::shred` runs. If shred refuses (e.g. the strand check), the
    // mutations must be rolled back: otherwise they sit unstaged, and a
    // re-run finds nothing to strip, so they never land in the shred
    // commit.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    const PERSON_A: &str = "p-01J9Z3K4QF0000000000000000";
    const PERSON_B: &str = "p-01J9Z3K4QG0000000000000000";
    const PERSON_C: &str = "p-01J9Z3K4QH0000000000000000";
    const EDGE_AB: &str = "e-01M3TC5H00MPJG00E100000000";
    const IXN_BC: &str = "i-01M3TC5H00MPJG0048H0000008";
    for client in [PERSON_A, PERSON_B, PERSON_C] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    for (id, name) in [
        (PERSON_A, "Ada Example"),
        (PERSON_B, "Bea Demo"),
        (PERSON_C, "Cam Sample"),
    ] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\nBio.\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    // An edge naming A, and an interaction with A in `with:`.
    let file = h._tmp.path().join(format!("{EDGE_AB}.md"));
    std::fs::write(
        &file,
        format!(
            "---\nid: {EDGE_AB}\ntype: edge\na: {PERSON_A}\nb: {PERSON_B}\nkind: married\n---\n"
        ),
    )
    .unwrap();
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            file.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add edge failed");
    let file = h._tmp.path().join(format!("{IXN_BC}.md"));
    std::fs::write(
        &file,
        format!(
            "---\nid: {IXN_BC}\ntype: interaction\nname: Dinner\ndate: 2026-10-06\nperson: {PERSON_B}\nwith: [{PERSON_A}, {PERSON_C}]\n---\n\nDinner with the group.\n"
        ),
    )
    .unwrap();
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            file.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add interaction failed");

    let edge_ab = h.vault.join(format!("edges/{EDGE_AB}/edge.md"));
    let ixn_path = h
        .vault
        .join(format!("interactions/{IXN_BC}/interaction.md"));
    let edge_before = std::fs::read(&edge_ab).unwrap();
    let ixn_before = std::fs::read(&ixn_path).unwrap();

    // Plant a rogue client dir so `KeyStore::shred` refuses AFTER the
    // working-tree mutations (same pattern as the strand-check test).
    let rogue = h.vault.join("keys/rogue");
    std::fs::create_dir_all(&rogue).unwrap();
    std::fs::write(rogue.join("epoch"), "1\n").unwrap();

    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "shred should have refused the rogue client"
    );

    // Rollback: every mutated file is byte-identical to before the attempt.
    assert_eq!(
        std::fs::read(&edge_ab).unwrap(),
        edge_before,
        "deleted edge file was not restored after refused shred"
    );
    assert_eq!(
        std::fs::read(&ixn_path).unwrap(),
        ixn_before,
        "re-encrypted interaction was not restored after refused shred"
    );
    // And git sees a clean tree: nothing staged, nothing unstaged
    // (apart from the planted rogue dir itself, which is untracked).
    let status = Command::new("git")
        .current_dir(&h.vault)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    let status_str = String::from_utf8_lossy(&status.stdout);
    let dirty: Vec<&str> = status_str
        .trim()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.contains("keys/rogue/"))
        .collect();
    assert!(
        dirty.is_empty(),
        "working tree dirty after refused shred: {}",
        status_str
    );

    // Remove the rogue dir: shred now succeeds, and the mutations land in
    // the shred commit as usual.
    std::fs::remove_dir_all(&rogue).unwrap();
    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !edge_ab.exists(),
        "edge naming the shredded person should be deleted"
    );
    assert_ne!(
        std::fs::read(&ixn_path).unwrap(),
        ixn_before,
        "interaction should be re-encrypted to strip the shredded person"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["stripped_interactions"], 1, "{v}");
}

#[test]
fn keys_shred_primary_then_another_participant_proceeds() {
    // #258 review: after shredding a PRIMARY, their interaction (now under a
    // destroyed key) must not block shredding someone else. A is the primary
    // of an interaction listing C; shred A, then shred C still succeeds.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    const PERSON_A: &str = "p-01J9Z3K4QF0000000000000000";
    const PERSON_C: &str = "p-01J9Z3K4QH0000000000000000";
    const IXN_AC: &str = "i-01M3TC5H00MPJG0048H0000009";
    for client in [PERSON_A, PERSON_C] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    for (id, name) in [(PERSON_A, "Ada Example"), (PERSON_C, "Cam Sample")] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\nBio.\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    // Interaction: primary A, participant C.
    let file = h._tmp.path().join(format!("{IXN_AC}.md"));
    std::fs::write(
        &file,
        format!(
            "---\nid: {IXN_AC}\ntype: interaction\nname: Lunch\ndate: 2026-10-06\nperson: {PERSON_A}\nwith: [{PERSON_C}]\n---\n\nLunch.\n"
        ),
    )
    .unwrap();
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            file.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add interaction failed");

    // Shred A (the primary).
    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred A failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Shred C: A's leftover interaction (under A's destroyed key) is skipped,
    // not a blocker.
    let out = h
        .cmd(&["keys", "shred", PERSON_C, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred C must proceed despite A's leftover interaction: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn keys_shred_second_person_proceeds_despite_first_persons_leftover_envelopes() {
    // #179 review: shred fail-closed is edge-scoped, not vault-wide.
    // After `keys shred p-A`, A's leftover record envelopes stay in the
    // tree and become undecryptable (Skipped) on later keyed loads, now
    // that A's key is destroyed. Shredding B must still proceed when
    // every edge envelope decrypts fine.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    const PERSON_A: &str = "p-01J9Z3K4QF0000000000000000";
    const PERSON_B: &str = "p-01J9Z3K4QG0000000000000000";
    const PERSON_C: &str = "p-01J9Z3K4QH0000000000000000";
    const EDGE_AB: &str = "e-01M3TC5H00MPJG00E100000000";
    const EDGE_BC: &str = "e-01M3TC5H00MPJG00E200000000";
    for client in [PERSON_A, PERSON_B, PERSON_C] {
        let out = h
            .cmd(&["keys", "init-client", client, "--json", "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "init-client {client} failed");
    }
    for (id, name) in [
        (PERSON_A, "Ada Example"),
        (PERSON_B, "Bea Demo"),
        (PERSON_C, "Cam Sample"),
    ] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\nBio.\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    for (id, a, b, kind) in [
        (EDGE_AB, PERSON_A, PERSON_B, "married"),
        (EDGE_BC, PERSON_B, PERSON_C, "colleague"),
    ] {
        let file = h._tmp.path().join(format!("{id}.md"));
        std::fs::write(
            &file,
            format!("---\nid: {id}\ntype: edge\na: {a}\nb: {b}\nkind: {kind}\n---\n"),
        )
        .unwrap();
        let out = h
            .cmd(&[
                "record",
                "add",
                "--file",
                file.to_str().unwrap(),
                "--no-input",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "record add {id} failed");
    }
    let edge_ab = h.vault.join(format!("edges/{EDGE_AB}/edge.md"));
    let edge_bc = h.vault.join(format!("edges/{EDGE_BC}/edge.md"));

    // Shred A: the AB edge goes; A's person envelope stays in the tree,
    // undecryptable from here on.
    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "first shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!edge_ab.exists());

    // Shred B: A's leftover envelope is Skipped on the keyed load, but
    // fail-closed is edge-scoped — every edge still reads, so this must
    // proceed (the old vault-wide check refused here).
    let out = h
        .cmd(&["keys", "shred", PERSON_B, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "second shred refused: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(!edge_bc.exists(), "edge naming B must be deleted");
    let deleted = v["deleted_edges"].as_array().unwrap();
    assert_eq!(deleted.len(), 1, "{v}");
    assert_eq!(deleted[0], format!("edges/{EDGE_BC}/edge.md"));
}

#[test]
fn keys_shred_warning_reflects_zero_deleted_edges() {
    // #179 review (non-blocking): leftover_warnings must not claim edges
    // naming the person were deleted when deleted_edges is empty.
    let mut h = Harness::new();
    h.with_test_keychain();
    let out = h.init(&[]);
    assert!(out.status.success());

    const PERSON_A: &str = "p-01J9Z3K4QF0000000000000000";
    let out = h
        .cmd(&["keys", "init-client", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client failed");
    let file = h._tmp.path().join("person.md");
    std::fs::write(
        &file,
        format!("---\nid: {PERSON_A}\ntype: person\nname: \"Ada Example\"\n---\n\nBio.\n"),
    )
    .unwrap();
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            file.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed");

    let out = h
        .cmd(&["keys", "shred", PERSON_A, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["deleted_edges"].as_array().unwrap().is_empty());
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("No edges named this person")),
        "warnings must reflect zero deleted edges: {warnings:?}"
    );
}
