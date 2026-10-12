//! CLI integration tests for `confidant init` / `confidant recover` (spec 1).
//!
//! All fixtures use generated fake data and throwaway keys (ADR-14: CI
//! never holds vault keys). The device key travels via the
//! `CONFIDANT_DEVICE_KEY` env var, so no test touches the real OS
//! keychain; `HOME` is a temp dir, so no test touches the real config.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

/// A hermetic init/recover test context: temp HOME, temp vault (git
/// repo), throwaway device key in the env.
struct Harness {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
    device_bech32: String,
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
        git(&vault, &["config", "user.name", "Test Operator"]);
        git(&vault, &["config", "user.email", "test@example.com"]);
        git(&vault, &["add", "--", "confidant.toml"]);
        git(&vault, &["commit", "-q", "-m", "test vault"]);

        // Throwaway device key (ADR-14). The CLI's env-var path uses it
        // directly and never touches the OS keychain.
        let id = age_x25519_generate();
        let device_bech32 = id;

        Harness {
            _tmp: tmp,
            home,
            vault,
            device_bech32,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        self.cmd_at(args, &self.vault)
    }

    /// Like [`cmd`], but against an explicit vault path (e.g. a shallow
    /// clone) instead of this harness's own vault.
    fn cmd_at(&self, args: &[&str], vault: &Path) -> Command {
        let mut c = Command::new(bin());
        c.args(args);
        c.arg("--vault").arg(vault);
        c.env("HOME", &self.home);
        c.env("CONFIDANT_DEVICE_KEY", &self.device_bech32);
        // The keychain must never be consulted: the env var is the store.
        // The kill switch IS set: operator key writes are skipped (test
        // mode), and the device key comes from the env var.
        c.env("CONFIDANT_KEYCHAIN", "off");
        c
    }

    fn init(&self, extra: &[&str]) -> Output {
        let mut args = vec!["init", "--no-input", "--json"];
        args.extend(extra);
        self.cmd(&args).output().unwrap()
    }

    fn trust_toml(&self) -> PathBuf {
        self.home.join(".config/confidant/trust.toml")
    }
}

fn git(vault: &Path, args: &[&str]) {
    let st = Command::new("git")
        .arg("-C")
        .arg(vault)
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?} failed");
}

/// Generate a throwaway age identity, returning the Bech32 secret.
/// Shells out to the `age-keygen` semantics via a tiny Rust helper is
/// overkill — instead we use the CLI binary itself? No: simplest is to
/// ask Python's cryptography... Instead, generate via `openssl`? None of
/// these are reliable. We generate the key with a one-off Rust snippet
/// compiled by the test harness below using the `age` crate through the
/// confidant binary's own dependencies is not available here.
///
/// Practical approach: the test binary links `age` via dev-dependencies.
fn age_x25519_generate() -> String {
    // Implemented below with the age crate (dev-dependency).
    age_generate_bech32()
}

#[cfg(test)]
mod age_helper {
    pub fn generate() -> String {
        use age::secrecy::ExposeSecret;
        age::x25519::Identity::generate()
            .to_string()
            .expose_secret()
            .to_owned()
    }
}

fn age_generate_bech32() -> String {
    age_helper::generate()
}

/// Extract the 24-word phrase from stderr (the display block).
fn extract_phrase(stderr: &str) -> String {
    // The phrase is the line between the banner lines that has exactly
    // 24 whitespace-separated words.
    for line in stderr.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() == 24 {
            return line.trim().to_string();
        }
    }
    panic!("no 24-word phrase found on stderr:\n{stderr}");
}

#[test]
fn recover_without_prior_config() {
    // Fresh-device recovery (Frank decision 2026-10-12): no trust.toml,
    // no config backup. The operator certificate in keys/ (signed by
    // the recovery key at init) is verified against the phrase-derived
    // recovery pubkey, rebuilding trust from the vault alone.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));

    // Simulate a lost device: wipe the entire config dir.
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    assert!(!h.trust_toml().exists());

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fresh-device recover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Trust is rebuilt: trust.toml exists with the new recovery pin.
    let trust = h.trust_toml();
    assert!(trust.is_file(), "trust.toml not rebuilt");
    let text = std::fs::read_to_string(&trust).unwrap();
    assert!(text.contains("operator_pubkey"), "{text}");
    assert!(text.contains("recovery_pubkey"), "{text}");

    // The new phrase was shown exactly once on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let new_phrase = extract_phrase(&stderr);
    assert_ne!(new_phrase, phrase, "recovery must rotate the phrase");
    assert_eq!(stderr.matches(new_phrase.as_str()).count(), 1);
}

#[test]
fn recover_twice_fresh_device_second_phrase_works() {
    // The operator certificate must be re-signed on every recovery
    // rotation: init, then fresh-device recover with phrase 1, then a
    // SECOND fresh-device recover with phrase 2. Without the re-sign,
    // the second recover fails verify_operator_cert ("recovery phrase
    // does not match this vault") — a silent lockout.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase1 = extract_phrase(&String::from_utf8_lossy(&out.stderr));

    // First fresh-device recover (phrase 1).
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase1).unwrap();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", age_generate_bech32())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "first fresh-device recover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let phrase2 = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(phrase2, phrase1, "recovery must rotate the phrase");

    // Second fresh-device recover (phrase 2) — the operator certificate
    // must verify against the phrase-2-derived recovery pubkey.
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    std::fs::write(&phrase_file, &phrase2).unwrap();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", age_generate_bech32())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "second fresh-device recover failed (stale operator cert?): stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let phrase3 = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(phrase3, phrase2, "recovery must rotate the phrase again");
    assert!(h.trust_toml().is_file(), "trust.toml not rebuilt");
}

#[test]
fn init_writes_operator_certificate() {
    // The operator certificate (for fresh-device recover) is written
    // at init, signed by the recovery key, and committed with keys/.
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    let cert = h.vault.join("keys/operator.toml");
    let sig = h.vault.join("keys/operator.sig");
    assert!(cert.is_file(), "operator certificate missing");
    assert!(sig.is_file(), "operator certificate signature missing");
    let text = std::fs::read_to_string(&cert).unwrap();
    assert!(text.contains("pubkey"), "{text}");
    // Committed to git.
    let log = Command::new("git")
        .arg("-C")
        .arg(&h.vault)
        .args(["ls-files", "keys/"])
        .output()
        .unwrap();
    let files = String::from_utf8_lossy(&log.stdout);
    assert!(files.contains("keys/operator.toml"), "{files}");
    assert!(files.contains("keys/operator.sig"), "{files}");
}

#[test]
fn init_writes_anchor_enrolls_device_key_commits_key_tree() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // B3: anchor written, 0600.
    let trust = h.trust_toml();
    assert!(trust.is_file(), "trust.toml not written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&trust).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "trust.toml must be 0600");
        let dir_mode = std::fs::metadata(trust.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "config dir must be 0700");
    }
    let text = std::fs::read_to_string(&trust).unwrap();
    assert!(text.contains("operator_pubkey"), "{text}");
    assert!(text.contains("recovery_pubkey"), "{text}");
    assert!(text.contains("recovery_age_recipient"), "{text}");

    // B4: keys/ tree committed — vault manifest + sig, shared manifest.
    for f in [
        "keys/vault/recipients.toml",
        "keys/vault/recipients.sig",
        "keys/vault/lookup.age",
        "keys/shared/recipients.toml",
        "keys/shared/recipients.sig",
    ] {
        assert!(h.vault.join(f).is_file(), "{f} missing");
    }

    // One commit for the keys/ tree (plus the initial test-vault commit).
    let log = Command::new("git")
        .arg("-C")
        .arg(&h.vault)
        .args(["log", "--oneline"])
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&log.stdout);
    assert_eq!(log.lines().count(), 2, "expected exactly 2 commits:\n{log}");
    assert!(log.lines().next().unwrap().contains("init"), "{log}");

    // JSON carries ok + vault + paths, no phrase.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["vault"].as_str().unwrap().contains("vault"));
    assert!(v["anchor"].as_str().unwrap().contains("trust.toml"));
}

#[test]
fn init_refuses_existing_anchor() {
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    // Second init without --force refuses (B1).
    let out = h.init(&[]);
    assert!(!out.status.success(), "second init should refuse");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("already exists"), "{msg}");
    assert!(msg.contains("recover"), "{msg}");
}

#[test]
fn init_phrase_stderr_once_never_in_json() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let phrase = extract_phrase(&stderr);
    // Exactly once on stderr.
    assert_eq!(
        stderr.matches(phrase.as_str()).count(),
        1,
        "phrase must appear exactly once on stderr"
    );
    // Never in stdout JSON (nor the secret-key material).
    assert!(
        !stdout.contains(phrase.as_str()),
        "phrase leaked into stdout"
    );
    assert!(
        !stdout.contains("AGE-SECRET-KEY"),
        "key material leaked into stdout"
    );
    assert!(
        !stderr.contains("AGE-SECRET-KEY"),
        "key material leaked into stderr"
    );
    // The device Bech32 (env-provided) must not be echoed either.
    assert!(!stdout.contains(&h.device_bech32));
    assert!(!stderr.contains(&h.device_bech32));
}

#[test]
fn init_initializes_shared_client() {
    // ⚠6: init also creates the vault:shared client key.
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    assert!(h.vault.join("keys/shared/recipients.toml").is_file());
    assert!(h.vault.join("keys/shared/recipients.sig").is_file());
    let wrapped: Vec<_> = std::fs::read_dir(h.vault.join("keys/shared/wrapped"))
        .unwrap()
        .collect();
    assert!(!wrapped.is_empty(), "shared client has no wrappings");
}

#[test]
fn recover_rejects_phrase_argv_exit_2() {
    // B7: the phrase must never arrive via argv. `--phrase-file` with a
    // missing file is a usage error (exit 2); there is no phrase flag.
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    let out = h
        .cmd(&["recover", "--json", "--phrase-file", "/nonexistent/phrase"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "usage error must exit 2");
}

#[test]
fn recover_requires_fresh_device() {
    // B13: a device with a key enrolled cannot recover. The harness sets
    // CONFIDANT_DEVICE_KEY (simulating an enrolled device); recover must
    // refuse with a pointer to #66. Use the real init phrase so phrase
    // validation (B8) passes and the B13 check is what triggers.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    // h still has CONFIDANT_DEVICE_KEY set from Harness::new → enrolled.
    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let out = h
        .cmd(&["recover", "--json", "--no-input"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("already has a device key"), "{msg}");
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(fix.contains("#66"), "{fix}");
}

#[test]
fn recover_rebuilds_alias_index_fresh_lookup_key() {
    // B12: CLI-level mirror of the crypto drill. Init, then recover with
    // the phrase and a new device key. The lookup key must be fresh (not
    // restored from the old wrapping).
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let old_lookup = std::fs::read(h.vault.join("keys/vault/lookup.age")).unwrap();

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let new_lookup = std::fs::read(h.vault.join("keys/vault/lookup.age")).unwrap();
    assert_ne!(
        old_lookup, new_lookup,
        "lookup key must be fresh, not restored"
    );

    // New phrase on stderr exactly once, never in JSON.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let new_phrase = extract_phrase(&stderr);
    assert_ne!(new_phrase, phrase, "recovery must rotate the phrase");
    assert_eq!(stderr.matches(new_phrase.as_str()).count(), 1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains(new_phrase.as_str()));
}

#[test]
fn recover_with_anchor_file_on_fresh_device_succeeds() {
    // #152: on a fresh device the operator can supply an explicit anchor
    // file instead of the config dir or the keys/-tree rebuild.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));

    // Keep an anchor backup out of the config dir, then lose the device
    // copy (wipe the config dir).
    let anchor_backup = h.home.join("anchor-backup.toml");
    std::fs::copy(h.trust_toml(), &anchor_backup).unwrap();
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    assert!(!h.trust_toml().exists());

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .arg("--anchor-file")
        .arg(&anchor_backup)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover --anchor-file failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Trust is re-pinned into the config dir and the phrase rotated.
    assert!(h.trust_toml().is_file(), "trust.toml not written");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let new_phrase = extract_phrase(&stderr);
    assert_ne!(new_phrase, phrase, "recovery must rotate the phrase");
}

#[test]
fn recover_with_anchor_file_mismatched_phrase_fails_closed() {
    // #152: a supplied anchor whose recovery key does not match the phrase
    // is refused, and nothing is written to the config dir.
    let h1 = Harness::new();
    assert!(h1.init(&[]).status.success());
    let anchor_backup = h1.home.join("anchor-backup.toml");
    std::fs::copy(h1.trust_toml(), &anchor_backup).unwrap();

    // A phrase for a DIFFERENT vault.
    let h2 = Harness::new();
    let out2 = h2.init(&[]);
    assert!(out2.status.success());
    let other_phrase = extract_phrase(&String::from_utf8_lossy(&out2.stderr));

    // Wipe h1's config so the supplied anchor is the only source.
    std::fs::remove_dir_all(h1.home.join(".config")).unwrap();
    let phrase_file = h1.home.join("phrase");
    std::fs::write(&phrase_file, &other_phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h1
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .arg("--anchor-file")
        .arg(&anchor_backup)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "mismatched phrase must fail closed: stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !h1.trust_toml().exists(),
        "config dir written before the anchor was verified"
    );
}

#[test]
fn recover_with_anchor_file_inside_vault_refused() {
    // #152: an anchor path inside the vault is refused (nothing in the
    // vault may point at or override the anchor). The planted file is
    // committed so recover reaches load_from's check rather than stopping
    // at the dirty-tree guard.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let planted = h.vault.join("planted-anchor.toml");
    std::fs::copy(h.trust_toml(), &planted).unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "plant an anchor in the vault"]);

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .arg("--anchor-file")
        .arg(&planted)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an anchor inside the vault must be refused"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("inside the vault"),
        "expected the inside-the-vault refusal, got: {msg}"
    );
    assert_eq!(
        v["error"]["code"], "E_INVALID",
        "the refusal must be E_INVALID, not an internal error"
    );
}

/// Read `[trust].recovery_age_recipient` from a harness's trust.toml.
fn trust_recovery_age(home: &Path) -> String {
    let text = std::fs::read_to_string(home.join(".config/confidant/trust.toml")).unwrap();
    let doc: toml::Value = toml::from_str(&text).unwrap();
    doc["trust"]["recovery_age_recipient"]
        .as_str()
        .expect("recovery_age_recipient in trust.toml")
        .to_string()
}

#[test]
fn recover_with_anchor_file_mismatched_recovery_age_fails_closed() {
    // #154 must-fix 1: the phrase must also match the anchor's X25519
    // recovery recipient, not only the Ed25519 key. Otherwise a tampered
    // anchor records a forged recipient as retired and misses the real one.
    let h = Harness::new();
    let init_out = h.init(&[]);
    assert!(init_out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&init_out.stderr));

    // A different vault's recovery recipient.
    let h2 = Harness::new();
    assert!(h2.init(&[]).status.success());
    let other_age = trust_recovery_age(&h2.home);

    let original = std::fs::read_to_string(h.trust_toml()).unwrap();
    let forged = original
        .lines()
        .map(|l| {
            if l.starts_with("recovery_age_recipient") {
                format!("recovery_age_recipient = \"{other_age}\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let forged_path = h.home.join("forged-anchor.toml");
    std::fs::write(&forged_path, forged).unwrap();

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .arg("--anchor-file")
        .arg(&forged_path)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "mismatched recovery recipient must fail closed"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("recovery recipient"), "got: {msg}");
    // The config dir was not re-pinned.
    assert_eq!(
        std::fs::read_to_string(h.trust_toml()).unwrap(),
        original,
        "config dir written before the anchor was verified"
    );
}

#[test]
fn recover_with_anchor_file_mismatched_operator_fails_closed() {
    // #154 must-fix 3: when the vault has a verifiable operator certificate,
    // the supplied anchor's operator key must match it.
    let h = Harness::new();
    let init_out = h.init(&[]);
    assert!(init_out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&init_out.stderr));

    let other = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let other_hex = hex::encode(other.verifying_key().to_bytes());
    let original = std::fs::read_to_string(h.trust_toml()).unwrap();
    let forged = original
        .lines()
        .map(|l| {
            if l.starts_with("operator_pubkey") {
                format!("operator_pubkey = \"{other_hex}\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let forged_path = h.home.join("forged-operator.toml");
    std::fs::write(&forged_path, forged).unwrap();

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .arg("--anchor-file")
        .arg(&forged_path)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an anchor whose operator key disagrees with the certificate must be refused"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("operator"), "got: {msg}");
    assert_eq!(
        std::fs::read_to_string(h.trust_toml()).unwrap(),
        original,
        "config dir written before the anchor was verified"
    );
}

#[test]
fn recover_with_anchor_file_present_but_unverifiable_cert_fails_closed() {
    // #154 must-fix 3: a present operator certificate that does not verify
    // against the phrase must refuse the supplied anchor, never fall back to
    // trusting the file.
    let h = Harness::new();
    let init_out = h.init(&[]);
    assert!(init_out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&init_out.stderr));

    // Corrupt the certificate signature and commit it.
    std::fs::write(h.vault.join("keys/operator.sig"), [0u8; 64]).unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "tamper operator cert"]);

    // The supplied anchor is the real one (correct operator).
    let anchor_backup = h.home.join("anchor-backup.toml");
    std::fs::copy(h.trust_toml(), &anchor_backup).unwrap();
    let original = std::fs::read_to_string(h.trust_toml()).unwrap();

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .arg("--anchor-file")
        .arg(&anchor_backup)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unverifiable operator certificate must refuse the supplied anchor"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("does not verify"), "got: {msg}");
    assert_eq!(std::fs::read_to_string(h.trust_toml()).unwrap(), original);
}

#[test]
fn recover_warns_on_shallow_clone() {
    // #156 nit 2: recover must warn (not fail) when git history is
    // degraded, since the retired-recovery / shredded-client checks then
    // only see the working tree.
    let source = Harness::new();
    let source_out = source.init(&[]);
    assert!(source_out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&source_out.stderr));

    let fresh = Harness::new();
    let clone = fresh.home.join("shallow");
    let st = Command::new("git")
        .args(["clone", "--quiet", "--depth", "1"])
        .arg(format!("file://{}", source.vault.display()))
        .arg(&clone)
        .status()
        .unwrap();
    assert!(st.success(), "shallow clone failed");

    let phrase_file = fresh.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = fresh
        .cmd_at(&["recover", "--no-input", "--json"], &clone)
        .arg("--phrase-file")
        .arg(&phrase_file)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover on a shallow clone should succeed with a warning: stdout={} stderr={}",
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
fn recover_rotates_recovery_and_repins_before_next_op() {
    // B11: after recover, the anchor is re-pinned with the NEW recovery
    // (proves the re-pin happened before further ops).
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let old_trust = std::fs::read_to_string(h.trust_toml()).unwrap();

    let phrase_file = h.home.join("phrase");
    std::fs::write(&phrase_file, &phrase).unwrap();
    let new_device_key = age_generate_bech32();
    let out = h
        .cmd(&["recover", "--json", "--no-input"])
        .arg("--phrase-file")
        .arg(&phrase_file)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", &new_device_key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The re-pinned anchor carries the NEW recovery pubkey (not the old).
    let trust = std::fs::read_to_string(h.trust_toml()).unwrap();
    assert_ne!(
        trust, old_trust,
        "anchor must be re-pinned with the new recovery"
    );
    assert!(trust.contains("recovery_pubkey"));
}

#[test]
fn no_secret_material_in_any_pr1_output() {
    // Sweep: neither init nor recover may emit key material or phrases
    // anywhere except the single stderr phrase display.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let phrase = extract_phrase(&stderr);

    assert!(
        !stdout.contains("AGE-SECRET-KEY"),
        "init stdout leaks key material"
    );
    assert!(
        !stdout.contains(phrase.as_str()),
        "init stdout leaks phrase"
    );
    // stderr may contain the phrase exactly once, but no key material.
    assert!(
        !stderr.contains("AGE-SECRET-KEY"),
        "stderr leaks key material"
    );
    assert!(
        !stderr.contains(&h.device_bech32),
        "stderr leaks device key"
    );
}
