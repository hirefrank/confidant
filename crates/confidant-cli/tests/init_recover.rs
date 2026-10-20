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

/// #640: `--force` only replaces a trust anchor; it never re-initializes an
/// existing key tree. The refusal must happen before any key write, so the
/// tree, the HEAD commit, and the ability to use the vault are untouched.
#[test]
fn init_force_on_initialized_vault_fails_closed() {
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    let head_before = git_out(&h.vault, &["rev-parse", "HEAD"]);
    assert!(
        git_out(&h.vault, &["status", "--porcelain"])
            .trim()
            .is_empty(),
        "precondition: tree is not clean"
    );

    let out = h.init(&["--force"]);
    assert!(
        !out.status.success(),
        "init --force on an initialized vault must refuse"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_INVALID");
    let message = v["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("already exist"), "{message}");
    assert!(message.contains("never re-initializes"), "{message}");
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(fix.contains("keys rotate"), "{fix}");

    // Fail closed: byte-identical working tree and no new commit.
    let porcelain = git_out(&h.vault, &["status", "--porcelain"]);
    assert!(
        porcelain.trim().is_empty(),
        "failed init --force dirtied the tree:\n{porcelain}"
    );
    assert_eq!(
        git_out(&h.vault, &["rev-parse", "HEAD"]),
        head_before,
        "failed init --force created a commit"
    );

    // The vault still works normally after the refusal (a dirty tree would
    // block the next write).
    let out = h.cmd(&["check", "--no-input", "--json"]).output().unwrap();
    assert!(
        out.status.success(),
        "check after refused init --force failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
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
        .args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            "-c",
            "core.autocrlf=false",
        ])
        .arg(format!("file://{}", source.vault.display()))
        .arg(&clone)
        .status()
        .unwrap();
    assert!(st.success(), "shallow clone failed");
    // A clone does not inherit the source's identity; commits need one.
    git(&clone, &["config", "user.name", "Test Operator"]);
    git(&clone, &["config", "user.email", "test@example.com"]);

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

// ---------------------------------------------------------------------------
// #539: `confidant init --create` bootstraps an absent/empty directory in one
// non-interactive command. Everything here is fake data and throwaway keys.
// ---------------------------------------------------------------------------

/// A bootstrap context: temp HOME with a git identity (so the skeleton commit
/// has an author), a vault path that does not exist yet, and a throwaway
/// device key. The OS keychain is never consulted.
struct Boot {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
    device_bech32: String,
}

impl Boot {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = Test Operator\n\temail = test@example.com\n",
        )
        .unwrap();
        Boot {
            _tmp: tmp,
            home,
            vault,
            device_bech32: age_generate_bech32(),
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args);
        c.env("HOME", &self.home);
        c.env("CONFIDANT_DEVICE_KEY", &self.device_bech32);
        c.env("CONFIDANT_KEYCHAIN", "off");
        c
    }

    /// `confidant <args> --vault <this vault>`.
    fn at_vault(&self, args: &[&str]) -> Output {
        self.cmd(args)
            .arg("--vault")
            .arg(&self.vault)
            .output()
            .unwrap()
    }
}

/// Run git and return stdout, asserting success.
fn git_out(vault: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(vault)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every path under `root`, sorted, for "nothing changed" assertions.
fn path_snapshot(root: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.display().to_string());
            }
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// Assert that no recovery phrase (its banner or a 24-word line) reached
/// stdout or stderr.
fn assert_no_recovery_phrase(out: &Output) {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !text.contains("RECOVERY PHRASE"),
        "recovery phrase banner leaked:\n{text}"
    );
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() == 24
            && words
                .iter()
                .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        {
            panic!("24-word recovery phrase leaked: {line}");
        }
    }
}

#[test]
fn bootstrap_one_command_from_absent_dir_creates_valid_vault() {
    let b = Boot::new();
    assert!(!b.vault.exists(), "precondition: vault path does not exist");

    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "init --create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Directory + git repo.
    assert!(b.vault.is_dir(), "vault directory not created");
    git_out(&b.vault, &["rev-parse", "--git-dir"]);

    // #661: the scaffold creates `main` explicitly, whatever git's default is.
    assert_eq!(
        git_out(&b.vault, &["branch", "--show-current"]).trim(),
        "main",
        "init --create must leave the vault on main"
    );

    // `.confidant/` is ignored (reindex's guardrail).
    let gitignore = std::fs::read_to_string(b.vault.join(".gitignore")).unwrap();
    assert!(
        gitignore.lines().any(|l| l.trim() == ".confidant/"),
        ".gitignore missing .confidant/: {gitignore}"
    );

    // A minimal confidant.toml: encrypted default, empty pack list (the
    // built-in `personal` default, #504), and no plaintext opt-out.
    let cfg = std::fs::read_to_string(b.vault.join("confidant.toml")).unwrap();
    assert!(cfg.contains("spec = \"0.1\""), "{cfg}");
    assert!(cfg.contains("packs = []"), "{cfg}");
    assert!(cfg.contains("vault_id = "), "{cfg}");
    assert!(!cfg.contains("plaintext"), "{cfg}");

    // Skeleton and keys are committed; the tree is clean.
    let tracked = git_out(&b.vault, &["ls-files"]);
    for f in [
        "confidant.toml",
        ".gitignore",
        "keys/shared/recipients.toml",
    ] {
        assert!(tracked.contains(f), "{f} not committed:\n{tracked}");
    }
    assert!(
        git_out(&b.vault, &["status", "--porcelain"])
            .trim()
            .is_empty(),
        "tree not clean after init --create"
    );

    // Trust anchor from the key steps.
    assert!(b.home.join(".config/confidant/trust.toml").is_file());

    // ADR-7 envelope: ok + the resolved vault path.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["branch"], "main", "init JSON must report the branch");
    let resolved = v["vault"].as_str().unwrap();
    assert_eq!(
        std::fs::canonicalize(resolved).unwrap(),
        std::fs::canonicalize(&b.vault).unwrap()
    );
}

#[test]
fn bootstrap_from_empty_existing_dir_works() {
    // `mkdir vault && confidant init --create` — the directory exists and is
    // empty (the README's old hand-written `git init` step, folded in).
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(b.vault.join("confidant.toml").is_file());
    git_out(&b.vault, &["rev-parse", "--git-dir"]);
}

#[test]
fn bootstrap_reindex_does_not_refuse_on_gitignore() {
    let b = Boot::new();
    assert!(b
        .at_vault(&["init", "--create", "--no-input", "--json"])
        .status
        .success());

    let out = b.at_vault(&["reindex", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "reindex refused after --create: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
}

#[test]
fn bootstrap_with_packs_writes_the_list() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--packs",
        "personal@0.1",
        "--no-input",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(b.vault.join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = [\"personal@0.1\"]"), "{cfg}");
}

/// #551: a `personal@…` listing is a known, no-op pack, so `init --packs`
/// accepts it (any version) instead of refusing it as unknown.
#[test]
fn bootstrap_accepts_a_noop_personal_listing() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--packs",
        "personal@0.1",
        "--no-input",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The vault checks clean even though the listing names no real version.
    let check = b.at_vault(&["check", "--no-input", "--json"]);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stdout)
    );
}

/// #551 nit: `personal@` (empty version) is malformed, not a built-in no-op,
/// so `init --packs` refuses it like any unknown pack.
#[test]
fn bootstrap_refuses_empty_version_personal_listing() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--packs",
        "personal@",
        "--no-input",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(!b.vault.exists(), "nothing should be created on refusal");
}

#[test]
fn bootstrap_unknown_pack_is_usage_error_and_writes_nothing() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--packs",
        "nope@9.9",
        "--no-input",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(!b.vault.exists(), "nothing should be created on refusal");
}

/// #639: `--packs` only seeds packs the binary implements. An external pack
/// is vendored by `pack add` into an existing vault, so naming one at init is
/// refused with that fix instead of the old "unknown pack" surprise.
#[test]
fn bootstrap_refuses_external_pack_with_pack_add_guidance() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--packs",
        "example-pack@0.1",
        "--no-input",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "usage_error");
    let message = v["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("example-pack@0.1"), "{message}");
    assert!(message.contains("external pack"), "{message}");
    assert!(message.contains("init cannot vendor"), "{message}");
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(fix.contains("confidant pack add"), "{fix}");
    assert!(
        !b.vault.exists(),
        "nothing should be created when an external pack is refused"
    );
}

/// #639: the help must promise exactly what init accepts. External packs are
/// installed after init, never seeded by `--packs`.
#[test]
fn init_help_says_external_packs_are_installed_after_init() {
    let b = Boot::new();
    let out = b.cmd(&["init", "--help"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        text.contains("Only packs built into this binary"),
        "init --help does not constrain --packs:\n{text}"
    );
    assert!(
        text.contains("install it after `init`"),
        "init --help does not say when external packs are installed:\n{text}"
    );
}

/// #639: `--packs` with an empty list behaves as documented (`packs = []`).
#[test]
fn bootstrap_with_empty_packs_writes_an_empty_list() {
    let b = Boot::new();
    let out = b.at_vault(&["init", "--create", "--packs", "", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(b.vault.join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = []"), "{cfg}");
}

#[test]
fn bootstrap_refuses_nonempty_non_repo_dir() {
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    std::fs::write(b.vault.join("hello.txt"), "not ours\n").unwrap();

    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!b.vault.join("confidant.toml").exists());
    assert!(!b.vault.join(".git").exists());
    assert_eq!(
        std::fs::read_to_string(b.vault.join("hello.txt")).unwrap(),
        "not ours\n",
        "an existing file must be untouched"
    );
}

#[test]
fn bootstrap_refuses_nonempty_clean_repo() {
    // A non-empty target is refused even when it is a clean git repo: #539
    // scopes --create to an absent or empty directory, so running it from the
    // wrong cwd cannot turn a project checkout into a vault.
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    std::fs::write(b.vault.join("README.md"), "a project\n").unwrap();
    git_out(&b.vault, &["init", "-q"]);
    git_out(&b.vault, &["add", "README.md"]);
    git_out(
        &b.vault,
        &[
            "-c",
            "user.name=Test Operator",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-q",
            "-m",
            "project",
        ],
    );
    assert!(git_out(&b.vault, &["status", "--porcelain"])
        .trim()
        .is_empty());

    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert_eq!(out.status.code(), Some(2), "non-empty repo must be refused");
    assert!(!b.vault.join("confidant.toml").exists());
    assert!(!b.vault.join(".gitignore").exists());
    // The project repo is untouched: same clean tree, same single commit.
    assert!(git_out(&b.vault, &["status", "--porcelain"])
        .trim()
        .is_empty());
    assert_eq!(git_out(&b.vault, &["log", "--oneline"]).lines().count(), 1);
}

/// Strip every git identity source from `cmd`, pointing it at a `home` that
/// has no `.gitconfig`: global and system config are `/dev/null`, `HOME` is
/// the temp dir, and the `GIT_AUTHOR_*`/`GIT_COMMITTER_*` vars are unset.
///
/// `user.useConfigOnly=true` is the platform-dependent part (#560): without
/// it git falls back to guessing `$USER@$HOSTNAME`, which macOS runners
/// resolve to `runner@<host>.local`, so `git var` succeeds there and the
/// "no identity" precondition does not hold. With it, git refuses to guess
/// on every platform and the test is deterministic.
fn without_git_identity(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "user.useConfigOnly")
        .env("GIT_CONFIG_VALUE_0", "true")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL");
}

/// `git var GIT_COMMITTER_IDENT` under the same identity-less environment as
/// [`without_git_identity`], rendered for an assertion message: it shows
/// whether git could resolve an identity at all and, if not, why.
fn git_committer_ident(home: &Path) -> String {
    let mut cmd = Command::new("git");
    cmd.args(["var", "GIT_COMMITTER_IDENT"]);
    without_git_identity(&mut cmd, home);
    match cmd.output() {
        Ok(out) => format!(
            "status={:?} stdout={:?} stderr={:?}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim(),
        ),
        Err(e) => format!("could not run git: {e}"),
    }
}

#[test]
fn bootstrap_without_git_identity_fails_before_writing_files() {
    // No git identity: the skeleton commit would fail, so `--create` refuses
    // before writing files (a half-written skeleton would make the retry
    // fail with "tree is not clean").
    let b = Boot::new();
    std::fs::remove_file(b.home.join(".gitconfig")).unwrap();

    let mut cmd = b.cmd(&["init", "--create", "--no-input", "--json"]);
    cmd.arg("--vault").arg(&b.vault);
    without_git_identity(&mut cmd, &b.home);
    let out = cmd.output().unwrap();

    let diag = format!(
        "git var GIT_COMMITTER_IDENT: {}\n\
         init stdout: {:?}\n\
         init stderr: {:?}",
        git_committer_ident(&b.home),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !out.status.success(),
        "init --create must refuse with no git identity\n{diag}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(
        fix.contains("user.name") && fix.contains("user.email"),
        "fix must name git identity config: {fix}\n{diag}"
    );
    assert!(!b.vault.join("confidant.toml").exists());
    assert!(!b.vault.join(".gitignore").exists());
    // #651 regression: the old order left an empty `.git`, and the retry then
    // refused because the folder was no longer empty. The target must stay
    // absent so configuring an identity is enough to retry.
    assert!(
        !b.vault.exists(),
        "a refused --create left {} behind; the retry would be blocked",
        b.vault.display()
    );

    // Configure the identity and retry: the same command now succeeds.
    std::fs::write(
        b.home.join(".gitconfig"),
        "[user]\n\tname = Test Operator\n\temail = test@example.com\n",
    )
    .unwrap();
    let retry = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        retry.status.success(),
        "retry after configuring a git identity must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&retry.stdout),
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(b.vault.join("confidant.toml").is_file());
}

#[test]
fn bootstrap_refuses_existing_anchor_before_writing_skeleton() {
    // A second device / re-run must keep B1's refusal, and must not leave a
    // half-built skeleton behind.
    let h = Harness::new();
    assert!(h.init(&[]).status.success());

    let target = h.home.join("fresh-vault");
    let out = h
        .cmd_at(&["init", "--create", "--no-input", "--json"], &target)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("already exists"), "{msg}");
    assert!(
        !target.join("confidant.toml").exists(),
        "skeleton must not be written when the anchor refusal fires"
    );
}

#[test]
fn init_create_on_prepared_vault_keeps_anchor_refusal() {
    // `--create` on an existing vault is not a bootstrap: it takes today's
    // path, so the anchor refusal still applies.
    let h = Harness::new();
    assert!(h.init(&[]).status.success());
    let out = h.init(&["--create"]);
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("already exists"));
}

#[test]
fn init_without_create_in_nonempty_dir_is_unchanged() {
    // No `--create`: never scaffold. A non-empty non-vault directory fails
    // discovery as before and nothing is written.
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    std::fs::write(b.vault.join("hello.txt"), "hi\n").unwrap();

    let out = b.at_vault(&["init", "--no-input", "--json"]);
    assert!(!out.status.success());
    assert!(!b.vault.join("confidant.toml").exists());
    assert!(!b.vault.join(".git").exists());
}

#[test]
fn init_without_create_still_refuses_unclean_tree() {
    // Prepared vault (repo + confidant.toml) with an uncommitted change:
    // `init` keeps refusing "not clean" when not bootstrapping.
    let h = Harness::new();
    std::fs::write(h.vault.join("dirty.txt"), "uncommitted\n").unwrap();

    let out = h.init(&[]);
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("not clean"), "{msg}");
    assert!(
        !h.trust_toml().exists(),
        "refused init must not write the anchor"
    );
}

// ---------------------------------------------------------------------------
// #649: `init --dry-run` writes nothing (directory, HOME, commits, keys,
// keychain). #658: the empty-packs hint. #662: `--phrase-out`.
// ---------------------------------------------------------------------------

#[test]
fn init_create_dry_run_writes_nothing() {
    let b = Boot::new();
    assert!(!b.vault.exists(), "precondition: vault path does not exist");
    let home_before = path_snapshot(&b.home);

    let out = b.at_vault(&["init", "--create", "--no-input", "--dry-run", "--json"]);
    assert!(
        out.status.success(),
        "dry run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // #649: no directory, no repo, no skeleton, no keys, no anchor.
    assert!(!b.vault.exists(), "dry run created the vault directory");
    assert!(
        !b.home.join(".config/confidant").exists(),
        "dry run wrote HOME state"
    );

    // ADR-7 envelope: ok, dry_run, resolved vault path, branch.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["branch"], "main");
    assert_eq!(v["vault"], b.vault.display().to_string());

    assert_no_recovery_phrase(&out);
    assert_eq!(path_snapshot(&b.home), home_before, "dry run changed HOME");
}

#[test]
fn init_dry_run_on_prepared_vault_writes_nothing() {
    let h = Harness::new();
    let head_before = git_out(&h.vault, &["rev-parse", "HEAD"]);
    let home_before = path_snapshot(&h.home);
    let branch_before = git_out(&h.vault, &["branch", "--show-current"])
        .trim()
        .to_string();

    let out = h.init(&["--dry-run"]);
    assert!(
        out.status.success(),
        "dry run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(!h.vault.join("keys").exists(), "dry run created keys/");
    assert!(!h.trust_toml().exists(), "dry run wrote the trust anchor");
    assert_eq!(
        git_out(&h.vault, &["rev-parse", "HEAD"]),
        head_before,
        "dry run created a commit"
    );
    assert!(
        git_out(&h.vault, &["status", "--porcelain"])
            .trim()
            .is_empty(),
        "dry run dirtied the tree"
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["branch"], branch_before);

    assert_no_recovery_phrase(&out);
    assert_eq!(path_snapshot(&h.home), home_before);
}

#[test]
fn init_dry_run_does_not_create_phrase_out_file() {
    let h = Harness::new();
    let phrase_path = h._tmp.path().join("phrase.txt");

    let out = h.init(&["--dry-run", "--phrase-out", phrase_path.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "dry run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !phrase_path.exists(),
        "dry run must not create the --phrase-out file"
    );
    assert!(!h.vault.join("keys").exists());
    assert!(!h.trust_toml().exists());
    assert_no_recovery_phrase(&out);
}

/// #658: an empty scaffolded pack list prints one optional `pack add` line.
#[test]
fn bootstrap_empty_packs_prints_pack_add_hint() {
    let b = Boot::new();
    let out = b.at_vault(&["init", "--create", "--no-input"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("confidant pack add <https-url> --yes"),
        "missing empty-packs hint:\n{stdout}"
    );
    assert_eq!(
        stdout
            .matches("confidant pack add <https-url> --yes")
            .count(),
        1,
        "the optional hint must appear exactly once:\n{stdout}"
    );
}

/// #658/#686: JSON `next_steps` always names clone + `keys device-add`;
/// `pack add` is present only when the scaffolded list is empty.
#[test]
fn bootstrap_json_next_steps_points_at_pack_add_only_when_empty() {
    let b = Boot::new();
    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let steps = v["next_steps"].as_array().expect("next_steps array");
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("confidant pack add")),
        "missing pack hint in next_steps: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("keys device-add")),
        "missing second-device hint in next_steps: {steps:?}"
    );
    assert!(
        !steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("git push")),
        "push hint must not appear without --remote: {steps:?}"
    );
    assert!(
        v["remote"].is_null(),
        "remote must be null without --remote: {v}"
    );

    let b2 = Boot::new();
    let out = b2.at_vault(&[
        "init",
        "--create",
        "--packs",
        "personal@0.1",
        "--no-input",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let steps = v["next_steps"].as_array().expect("next_steps array");
    assert!(
        !steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("confidant pack add")),
        "pack hint must not appear when packs are explicit: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("keys device-add")),
        "missing second-device hint when packs are explicit: {steps:?}"
    );
}

const EXAMPLE_REMOTE: &str = "https://example.invalid/vault.git";

/// #686: `--create --remote` sets `origin` and does not push.
#[test]
fn bootstrap_create_with_remote_adds_origin_and_does_not_push() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--remote",
        EXAMPLE_REMOTE,
        "--no-input",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let remotes = git_out(&b.vault, &["remote", "-v"]);
    assert!(
        remotes.contains("origin") && remotes.contains(EXAMPLE_REMOTE),
        "origin was not added:\n{remotes}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["remote"], EXAMPLE_REMOTE);
    let steps = v["next_steps"].as_array().expect("next_steps array");
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("git push -u origin")),
        "missing push hint: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("keys device-add")),
        "missing second-device hint: {steps:?}"
    );
}

/// #686: `--create --dry-run --remote` reports the plan and writes nothing.
#[test]
fn bootstrap_create_dry_run_with_remote_writes_nothing() {
    let b = Boot::new();
    let home_before = path_snapshot(&b.home);
    let out = b.at_vault(&[
        "init",
        "--create",
        "--remote",
        EXAMPLE_REMOTE,
        "--no-input",
        "--dry-run",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!b.vault.exists(), "dry run created the vault directory");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["remote"], EXAMPLE_REMOTE);
    let steps = v["next_steps"].as_array().expect("next_steps array");
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("git push -u origin")),
        "missing push hint: {steps:?}"
    );
    assert_eq!(path_snapshot(&b.home), home_before, "dry run changed HOME");
}

/// #686: `--remote` without `--create` is a clap usage error (exit 2).
#[test]
fn bootstrap_remote_without_create_is_usage_error() {
    let b = Boot::new();
    let out = b.at_vault(&["init", "--remote", EXAMPLE_REMOTE, "--no-input"]);
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(!b.vault.exists(), "refused --remote must not scaffold");
}

/// #686: `--remote` refuses when `origin` already exists (including dry-run).
#[test]
fn bootstrap_remote_refuses_existing_origin() {
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    git(&b.vault, &["init", "-q"]);
    git(
        &b.vault,
        &["remote", "add", "origin", "https://example.invalid/old.git"],
    );

    for extra in [&["--dry-run"][..], &[][..]] {
        let mut args = vec![
            "init",
            "--create",
            "--remote",
            EXAMPLE_REMOTE,
            "--no-input",
            "--json",
        ];
        args.extend_from_slice(extra);
        let out = b.at_vault(&args);
        assert!(
            !out.status.success(),
            "must refuse existing origin ({extra:?}): stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["ok"], false, "{v}");
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("origin already exists"),
            "expected origin-exists refusal ({extra:?}): {v}"
        );
    }
    let remotes = git_out(&b.vault, &["remote", "-v"]);
    assert!(
        remotes.contains("https://example.invalid/old.git"),
        "existing origin must be untouched:\n{remotes}"
    );
    assert!(
        !remotes.contains(EXAMPLE_REMOTE),
        "refused --remote must not replace origin:\n{remotes}"
    );
}

/// #686: `--remote` on a directory that already has a vault is refused.
#[test]
fn bootstrap_remote_on_existing_vault_is_refused() {
    let h = Harness::new();
    let out = h.init(&["--create", "--remote", EXAMPLE_REMOTE]);
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false, "{v}");
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("already has a vault"),
        "expected existing-vault refusal: {v}"
    );
    let remotes = Command::new("git")
        .arg("-C")
        .arg(&h.vault)
        .args(["remote"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&remotes.stdout).trim().is_empty(),
        "refused --remote must not add origin"
    );
}

/// #686: a failed `--create --remote` on a pre-existing repo removes origin.
#[test]
fn bootstrap_remote_rollback_on_failed_init() {
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    git(&b.vault, &["init", "-q"]);
    let phrase_path = b._tmp.path().join("phrase.txt");

    let out = b
        .cmd(&[
            "init",
            "--create",
            "--remote",
            EXAMPLE_REMOTE,
            "--no-input",
            "--json",
            "--phrase-out",
            phrase_path.to_str().unwrap(),
        ])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_TEST_FAIL_AFTER_KEYS_COMMIT", "1")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "the failpoint must fail init: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let remotes = git_out(&b.vault, &["remote"]);
    assert!(
        remotes.trim().is_empty(),
        "rollback must remove origin this run added:\n{remotes}"
    );
    assert!(!b.vault.join("confidant.toml").exists());
    assert!(!phrase_path.exists());
}

/// `--remote` URLs that start with `-` would be parsed as git options.
#[test]
fn bootstrap_remote_rejects_leading_dash() {
    let b = Boot::new();
    let out = b.at_vault(&[
        "init",
        "--create",
        "--remote=-uorigin",
        "--no-input",
        "--json",
    ]);
    assert!(!out.status.success(), "leading-dash URL must be refused");
    assert_eq!(out.status.code(), Some(2), "usage error");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("must not start with '-'"), "{msg}");
    assert!(!b.vault.exists(), "refused --remote must not scaffold");
}

/// `--remote` with userinfo must not print the credential; git still gets
/// the real URL.
#[test]
fn bootstrap_remote_redacts_userinfo_in_output() {
    let b = Boot::new();
    let secret = "https://user:s3cret-token@example.invalid/vault.git";
    let out = b.at_vault(&[
        "init",
        "--create",
        "--remote",
        secret,
        "--no-input",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("s3cret-token") && !stderr.contains("s3cret-token"),
        "credential leaked: stdout={stdout} stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["remote"], "https://example.invalid/vault.git");
    let remotes = git_out(&b.vault, &["remote", "-v"]);
    assert!(
        remotes.contains(secret),
        "git must still store the real URL:\n{remotes}"
    );
}

/// Human `--create` output names clone + `keys device-add`, not `recover`
/// as the second-device path. The pack-add line still appears once.
#[test]
fn bootstrap_human_output_names_device_add_not_recover() {
    let b = Boot::new();
    let out = b.at_vault(&["init", "--create", "--no-input"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("keys device-add"),
        "missing second-device hint:\n{stdout}"
    );
    assert!(
        stdout.contains("not `init`"),
        "hint must say not to run init:\n{stdout}"
    );
    assert!(
        stdout.contains("recover") && stdout.contains("every enrolled device is lost"),
        "recover must be the lost-all-devices path:\n{stdout}"
    );
    assert_eq!(
        stdout
            .matches("confidant pack add <https-url> --yes")
            .count(),
        1,
        "the optional pack hint must appear exactly once:\n{stdout}"
    );
}

/// #662: the phrase goes to a new 0600 file, never to stdout/stderr/JSON.
#[test]
fn init_phrase_out_writes_0600_and_hides_phrase() {
    let h = Harness::new();
    let phrase_path = h._tmp.path().join("phrase.txt");

    let out = h.init(&["--phrase-out", phrase_path.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&phrase_path).unwrap();
    let phrase = text.trim();
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "phrase file does not hold 24 words"
    );
    assert!(text.ends_with('\n'), "phrase file must end with a newline");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&phrase_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "phrase file must be 0600");
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(phrase), "phrase leaked to stdout");
    assert!(!stderr.contains(phrase), "phrase leaked to stderr");
    assert!(
        !stdout.contains("RECOVERY PHRASE") && !stderr.contains("RECOVERY PHRASE"),
        "the phrase banner must not print with --phrase-out"
    );
    assert!(
        stderr.contains("Move this file offline, then delete it."),
        "missing delete warning:\n{stderr}"
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["phrase_out"]
        .as_str()
        .unwrap_or("")
        .ends_with("phrase.txt"));

    // The run still completed: anchor, keys, clean tree.
    assert!(h.trust_toml().is_file());
    assert!(h.vault.join("keys/shared/recipients.toml").is_file());
    assert!(git_out(&h.vault, &["status", "--porcelain"])
        .trim()
        .is_empty());
}

#[test]
fn init_phrase_out_refuses_overwrite() {
    let h = Harness::new();
    let phrase_path = h._tmp.path().join("phrase.txt");
    std::fs::write(&phrase_path, "keep me\n").unwrap();

    let out = h.init(&["--phrase-out", phrase_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "refusal is a usage error");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("--phrase-out"),
        "{v}"
    );

    assert_eq!(
        std::fs::read_to_string(&phrase_path).unwrap(),
        "keep me\n",
        "existing file must be untouched"
    );
    assert!(!h.vault.join("keys").exists(), "keys must not be written");
    assert!(!h.trust_toml().exists(), "anchor must not be written");
    assert!(
        git_out(&h.vault, &["status", "--porcelain"])
            .trim()
            .is_empty(),
        "refused init dirtied the tree"
    );
}

#[test]
fn init_phrase_out_failure_aborts_before_key_persistence() {
    let h = Harness::new();
    // Parent directory absent: the file cannot be created.
    let phrase_path = h._tmp.path().join("missing-dir/phrase.txt");

    let out = h.init(&["--phrase-out", phrase_path.to_str().unwrap()]);
    assert!(!out.status.success(), "missing parent must fail");
    assert!(!phrase_path.exists());
    assert!(!h.vault.join("keys").exists(), "keys must not be written");
    assert!(!h.trust_toml().exists(), "anchor must not be written");
    assert!(
        git_out(&h.vault, &["status", "--porcelain"])
            .trim()
            .is_empty(),
        "failed init dirtied the tree"
    );
}

#[cfg(unix)]
#[test]
fn init_phrase_out_does_not_follow_symlink() {
    use std::os::unix::fs::symlink;

    let h = Harness::new();
    let target = h._tmp.path().join("existing.txt");
    std::fs::write(&target, "keep me\n").unwrap();
    let link = h._tmp.path().join("phrase-link.txt");
    symlink(&target, &link).unwrap();

    let out = h.init(&["--phrase-out", link.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "symlink must be refused");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "keep me\n",
        "symlink target must be untouched"
    );
    assert!(
        link.symlink_metadata().is_ok(),
        "a refused init must not remove the existing symlink"
    );
    assert!(!h.vault.join("keys").exists());
    assert!(!h.trust_toml().exists());
}

#[test]
fn init_help_mentions_phrase_out() {
    let b = Boot::new();
    let out = b.cmd(&["init", "--help"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        text.contains("--phrase-out"),
        "help misses --phrase-out:\n{text}"
    );
    assert!(
        text.contains("0600"),
        "help misses the 0600 promise:\n{text}"
    );
}

/// #651: a failure after the skeleton commit (here `--phrase-out` cannot be
/// created) must remove everything this run created, so the retry sees the
/// same absent directory instead of a half-built vault.
#[test]
fn bootstrap_rolls_back_skeleton_when_a_later_step_fails() {
    let b = Boot::new();
    let bad_path = b._tmp.path().join("missing-dir/phrase.txt");
    let out = b.at_vault(&[
        "init",
        "--create",
        "--no-input",
        "--json",
        "--phrase-out",
        bad_path.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "init must fail when --phrase-out fails"
    );
    assert!(
        !b.vault.exists(),
        "failed init left the skeleton behind:\n{}",
        path_snapshot(b._tmp.path()).join("\n")
    );
    assert!(!b.home.join(".config/confidant/trust.toml").exists());
    assert!(!bad_path.exists());
}

// ---------------------------------------------------------------------------
// #663: `keys verify-recovery` (read-only phrase verification)
// ---------------------------------------------------------------------------

/// Every file under `dir`, keyed by relative path, byte for byte.
fn snapshot_dir(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if path.is_dir() {
                walk(base, &path, out);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.insert(rel, bytes);
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn git_status(vault: &Path) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(vault)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// What `verify-recovery` must leave untouched.
struct ReadOnlySnapshot {
    keys: std::collections::BTreeMap<String, Vec<u8>>,
    trust: Option<Vec<u8>>,
    status: String,
}

fn snapshot_state(h: &Harness) -> ReadOnlySnapshot {
    ReadOnlySnapshot {
        keys: snapshot_dir(&h.vault.join("keys")),
        trust: std::fs::read(h.trust_toml()).ok(),
        status: git_status(&h.vault),
    }
}

fn assert_unchanged(h: &Harness, before: &ReadOnlySnapshot) {
    assert_eq!(
        snapshot_dir(&h.vault.join("keys")),
        before.keys,
        "verify-recovery modified keys/"
    );
    assert_eq!(
        std::fs::read(h.trust_toml()).ok(),
        before.trust,
        "verify-recovery modified trust.toml"
    );
    assert_eq!(
        git_status(&h.vault),
        before.status,
        "verify-recovery changed git status"
    );
}

fn verify_recovery(h: &Harness, phrase_file: &Path) -> Output {
    h.cmd(&["keys", "verify-recovery", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(phrase_file)
        .output()
        .unwrap()
}

fn write_phrase(h: &Harness, phrase: &str) -> PathBuf {
    let path = h.home.join("saved-recovery.txt");
    std::fs::write(&path, phrase).unwrap();
    path
}

#[test]
fn verify_recovery_matches_on_enrolled_device_and_writes_nothing() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let phrase_file = write_phrase(&h, &phrase);

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file);
    assert!(
        out.status.success(),
        "verify-recovery failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["outcome"], "match");
    assert_eq!(v["checks"]["anchor"], "pass");
    assert_eq!(v["checks"]["recipient"], "pass");
    assert_eq!(v["checks"]["cert"], "pass");
    assert_eq!(v["checks"]["unwrap"]["vault:shared"], "pass");
    assert_eq!(v["clients_checked"], 1);
    assert!(!stdout.contains(&phrase), "JSON leaked the phrase");
    assert!(!stderr.contains(&phrase), "stderr leaked the phrase");
    assert!(!stdout.contains("AGE-SECRET-KEY"), "JSON leaked a key");

    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_reads_stdin_and_writes_nothing() {
    use std::io::Write as _;
    use std::process::Stdio;

    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));

    let before = snapshot_state(&h);
    let mut child = h
        .cmd(&["keys", "verify-recovery", "--no-input", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("  {phrase}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stdin verify failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&phrase));
    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_mismatch_reports_code_and_writes_nothing() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    // A second, independent vault gives a valid BIP39 phrase that is not
    // this vault's.
    let other = Harness::new();
    let out = other.init(&[]);
    assert!(out.status.success());
    let other_phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let phrase_file = write_phrase(&h, &other_phrase);

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file);
    assert_eq!(out.status.code(), Some(1), "mismatch must exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["outcome"], "mismatch");
    assert_eq!(v["error"]["code"], "E_RECOVERY_MISMATCH");
    assert_eq!(v["checks"]["anchor"], "fail");
    assert_eq!(v["checks"]["recipient"], "fail");
    assert!(!stdout.contains(&other_phrase), "JSON leaked the phrase");

    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_checks_both_anchor_halves() {
    // Tamper only the X25519 recipient in trust.toml: the Ed25519 half
    // still matches, the certificate and unwrappings still work. The
    // command must still fail as a mismatch (and never fall back to
    // keys/), proving it checks both halves.
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let phrase_file = write_phrase(&h, &phrase);

    let trust = std::fs::read_to_string(h.trust_toml()).unwrap();
    let mut replaced = false;
    let mut lines: Vec<String> = Vec::new();
    for line in trust.lines() {
        if line.trim_start().starts_with("recovery_age_recipient") {
            let recipient = age::x25519::Identity::generate().to_public().to_string();
            lines.push(format!("recovery_age_recipient = \"{recipient}\""));
            replaced = true;
        } else {
            lines.push(line.to_owned());
        }
    }
    assert!(
        replaced,
        "trust.toml has no recovery_age_recipient:\n{trust}"
    );
    std::fs::write(h.trust_toml(), format!("{}\n", lines.join("\n"))).unwrap();

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file);
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["outcome"], "mismatch");
    assert_eq!(v["error"]["code"], "E_RECOVERY_MISMATCH");
    assert_eq!(v["checks"]["anchor"], "pass");
    assert_eq!(v["checks"]["recipient"], "fail");
    assert_eq!(v["checks"]["cert"], "pass");
    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_retired_phrase_reports_shred_guidance() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase1 = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let phrase_file1 = write_phrase(&h, &phrase1);

    // Simulate a lost device: fresh recover rotates the recovery identity.
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    let out = h
        .cmd(&["recover", "--no-input", "--json"])
        .arg("--phrase-file")
        .arg(&phrase_file1)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_TEST_DEVICE_KEY", age_generate_bech32())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let phrase2 = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(phrase2, phrase1);

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file1);
    assert_eq!(out.status.code(), Some(1), "retired phrase must exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["outcome"], "retired");
    assert_eq!(v["error"]["code"], "E_RECOVERY_RETIRED");
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("retired"), "{msg}");
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(fix.contains("Destroy"), "{fix}");
    assert!(fix.contains("still opens the vault's history"), "{fix}");
    assert!(!stdout.contains(&phrase1), "JSON leaked the retired phrase");
    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_malformed_phrase_hints_on_stderr_only() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let mut words: Vec<&str> = phrase.split_whitespace().collect();
    words[0] = "zzzznotabip39word";
    let bad = words.join(" ");
    let phrase_file = write_phrase(&h, &bad);

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file);
    assert_eq!(
        out.status.code(),
        Some(1),
        "malformed phrase is a failure, not usage"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["outcome"], "malformed");
    assert_eq!(v["error"]["code"], "E_RECOVERY_MALFORMED");
    assert!(
        stderr.contains("word 1"),
        "position hint missing from stderr: {stderr}"
    );
    assert!(
        !stdout.contains("word 1"),
        "word position leaked into JSON: {stdout}"
    );
    assert!(!stdout.contains(&bad), "JSON leaked the phrase");
    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_works_on_fresh_device_without_writing_config() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let phrase_file = write_phrase(&h, &phrase);

    // Lost device: no config dir at all. The operator certificate in
    // keys/ must be enough to verify, and nothing may be recreated.
    std::fs::remove_dir_all(h.home.join(".config")).unwrap();
    let config_dir = h.home.join(".config/confidant");
    assert!(!config_dir.exists());

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file);
    assert!(
        out.status.success(),
        "fresh-device verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["outcome"], "match");
    assert_eq!(v["checks"]["anchor"], "absent");
    assert_eq!(v["checks"]["recipient"], "absent");
    assert_eq!(v["checks"]["cert"], "pass");
    assert_eq!(v["checks"]["unwrap"]["vault:shared"], "pass");
    assert!(
        !config_dir.exists(),
        "verify-recovery recreated the config dir"
    );
    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_failed_unwrap_has_its_own_code() {
    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());
    let phrase = extract_phrase(&String::from_utf8_lossy(&out.stderr));
    let phrase_file = write_phrase(&h, &phrase);

    // Tamper the shared client's recovery wrapping. The manifest (signed)
    // still verifies and the phrase still matches the pin, so this is
    // specifically an unwrap failure.
    let wrapping = h.vault.join("keys/shared/wrapped/recovery.age");
    assert!(wrapping.is_file(), "missing {wrapping:?}");
    std::fs::write(&wrapping, b"not an age envelope").unwrap();

    let before = snapshot_state(&h);
    let out = verify_recovery(&h, &phrase_file);
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["outcome"], "unwrap_failed");
    assert_eq!(v["error"]["code"], "E_RECOVERY_UNWRAP");
    assert_eq!(v["checks"]["anchor"], "pass");
    assert_eq!(v["checks"]["recipient"], "pass");
    assert_eq!(v["checks"]["cert"], "pass");
    assert_eq!(v["checks"]["unwrap"]["vault:shared"], "fail");
    assert_unchanged(&h, &before);
}

#[test]
fn verify_recovery_empty_stdin_is_usage_error() {
    use std::process::Stdio;

    let h = Harness::new();
    let out = h.init(&[]);
    assert!(out.status.success());

    let out = h
        .cmd(&["keys", "verify-recovery", "--no-input", "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "empty input is a usage error");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "usage_error");
}

// ---------------------------------------------------------------------------
// #671 review: a failure after the keys commit must rewind the commit before
// removing keys/, so a prepared vault is clean and the retry works. The
// failpoint is test-only (`test-overrides`).
// ---------------------------------------------------------------------------

#[test]
fn failed_init_after_keys_commit_rewinds_and_retry_succeeds() {
    let h = Harness::new();
    let head_before = git_out(&h.vault, &["rev-parse", "HEAD"]);
    let phrase_path = h._tmp.path().join("phrase.txt");

    let out = h
        .cmd(&[
            "init",
            "--no-input",
            "--json",
            "--phrase-out",
            phrase_path.to_str().unwrap(),
        ])
        .env("CONFIDANT_TEST_FAIL_AFTER_KEYS_COMMIT", "1")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "the failpoint must fail init: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The keys commit was rewound, keys/ and the phrase file are gone, and
    // the prepared vault is exactly as clean as before the run.
    assert_eq!(
        git_out(&h.vault, &["rev-parse", "HEAD"]),
        head_before,
        "the keys commit was not rewound"
    );
    let porcelain = git_out(&h.vault, &["status", "--porcelain"]);
    assert!(
        porcelain.trim().is_empty(),
        "rollback left a dirty tree:\n{porcelain}"
    );
    assert!(!h.vault.join("keys").exists(), "keys/ must be removed");
    assert!(!phrase_path.exists(), "the phrase file must be removed");
    assert!(!h.trust_toml().exists(), "the anchor must not be written");

    // Retry without the failpoint: the same prepared vault now initializes.
    let retry = h.init(&["--phrase-out", phrase_path.to_str().unwrap()]);
    assert!(
        retry.status.success(),
        "retry failed: stdout={} stderr={}",
        String::from_utf8_lossy(&retry.stdout),
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(phrase_path.is_file(), "retry must write the phrase file");
    assert!(h.trust_toml().is_file(), "retry must write the anchor");
    let check = h.cmd(&["check", "--no-input", "--json"]).output().unwrap();
    assert!(
        check.status.success(),
        "check failed after the retry: {}",
        String::from_utf8_lossy(&check.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true);
}

#[test]
fn failed_create_init_after_keys_commit_rolls_back_the_scaffold() {
    let b = Boot::new();
    let phrase_path = b._tmp.path().join("phrase.txt");

    let out = b
        .cmd(&[
            "init",
            "--create",
            "--no-input",
            "--json",
            "--phrase-out",
            phrase_path.to_str().unwrap(),
        ])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_TEST_FAIL_AFTER_KEYS_COMMIT", "1")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "the failpoint must fail init: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !b.vault.exists(),
        "failed --create must leave the target absent"
    );
    assert!(!phrase_path.exists(), "the phrase file must be removed");

    // Retry without the failpoint from the same absent target.
    let retry = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        retry.status.success(),
        "retry failed: stdout={} stderr={}",
        String::from_utf8_lossy(&retry.stdout),
        String::from_utf8_lossy(&retry.stderr)
    );
    let check = b.at_vault(&["check", "--no-input", "--json"]);
    assert!(
        check.status.success(),
        "check failed after the retry: {}",
        String::from_utf8_lossy(&check.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true);
}

// ---------------------------------------------------------------------------
// #650: headless encrypted init with CONFIDANT_OPERATOR_KEY plus the existing
// CONFIDANT_DEVICE_KEY. Fake seeds and throwaway device keys only.
// ---------------------------------------------------------------------------

#[test]
fn headless_init_uses_env_operator_and_device_keys() {
    let b = Boot::new();
    let seed_hex = "11".repeat(32);
    let seed: [u8; 32] = hex::decode(&seed_hex).unwrap().try_into().unwrap();
    let expected = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes(),
    );

    let out = b
        .cmd(&["init", "--create", "--no-input", "--json"])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_OPERATOR_KEY", &seed_hex)
        // Any keychain write would fail closed on this invalid switch value,
        // so a successful init proves the env operator key never went to the
        // keychain (and no fallback was attempted).
        .env("CONFIDANT_KEYCHAIN", "bogus")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "headless init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The env seed is the operator key: both the trust anchor and the
    // operator certificate carry its public half.
    let trust = std::fs::read_to_string(b.home.join(".config/confidant/trust.toml")).unwrap();
    assert!(
        trust.contains(&format!("operator_pubkey = \"{expected}\"")),
        "trust.toml does not pin the env operator key:\n{trust}"
    );
    let cert = std::fs::read_to_string(b.vault.join("keys/operator.toml")).unwrap();
    assert!(
        cert.contains(&expected),
        "operator certificate does not carry the env operator key"
    );

    // Encrypted vault: keys/ exists, no plaintext opt-out, and check passes.
    assert!(b.vault.join("keys/shared/epoch").is_file());
    let cfg = std::fs::read_to_string(b.vault.join("confidant.toml")).unwrap();
    assert!(!cfg.contains("plaintext"), "{cfg}");
    let check = b.at_vault(&["check", "--no-input", "--json"]);
    assert!(
        check.status.success(),
        "check failed after headless init: stdout={} stderr={}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(b.home.join(".config/confidant/trust.toml").is_file());
}

#[test]
fn init_rejects_invalid_operator_env_key_before_writing() {
    let cases = [
        ("empty", String::new()),
        ("short", "abcd".to_string()),
        ("non-hex", format!("g{}", "0".repeat(63))),
    ];
    for (label, bad) in cases {
        let b = Boot::new();
        let out = b
            .cmd(&["init", "--create", "--no-input", "--json"])
            .arg("--vault")
            .arg(&b.vault)
            .env("CONFIDANT_OPERATOR_KEY", &bad)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{label}: must fail");
        assert_eq!(out.status.code(), Some(2), "{label}: usage error");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("CONFIDANT_OPERATOR_KEY") && msg.contains("64 hex"),
            "{label}: error must name the variable and format: {msg}"
        );
        assert!(
            !b.vault.exists(),
            "{label}: invalid operator key must write nothing (no skeleton)"
        );
    }
}

#[test]
fn init_dry_run_rejects_invalid_operator_env_key() {
    let b = Boot::new();
    let out = b
        .cmd(&["init", "--create", "--no-input", "--dry-run", "--json"])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_OPERATOR_KEY", "not-hex")
        .output()
        .unwrap();
    assert!(!out.status.success(), "dry run must validate the env key");
    assert_eq!(out.status.code(), Some(2), "usage error");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("CONFIDANT_OPERATOR_KEY"), "{msg}");
    assert!(!b.vault.exists(), "dry run wrote the target");
}

#[test]
fn init_create_dry_run_refuses_without_key_sources() {
    // #682: on a keyless host (CONFIDANT_KEYCHAIN=off, no env keys) a real
    // init fails at store_device_key. --dry-run must fail the same way.
    let b = Boot::new();
    let out = b
        .cmd(&["init", "--create", "--no-input", "--dry-run", "--json"])
        .arg("--vault")
        .arg(&b.vault)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env_remove("CONFIDANT_OPERATOR_KEY")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "dry run must refuse a keyless host: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(
        msg.contains("keychain") || msg.contains("CONFIDANT_DEVICE_KEY"),
        "expected a keychain/env-key refusal, got: {msg}"
    );
    assert!(fix.contains("CONFIDANT_DEVICE_KEY"), "{fix}");
    assert!(fix.contains("CONFIDANT_OPERATOR_KEY"), "{fix}");
    assert!(!b.vault.exists(), "refused dry run wrote the target");
}

/// #682: the same keyless host as `init_create_dry_run_refuses_without_key_sources`,
/// but a real `init --create` (not `--dry-run`). Preflight must fail with
/// the same message and leave the target unwritten.
#[test]
fn init_create_refuses_without_key_sources() {
    let b = Boot::new();
    let out = b
        .cmd(&["init", "--create", "--no-input", "--json"])
        .arg("--vault")
        .arg(&b.vault)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env_remove("CONFIDANT_OPERATOR_KEY")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "real init must refuse a keyless host: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = v["error"]["message"].as_str().unwrap_or("");
    let fix = v["error"]["fix"].as_str().unwrap_or("");
    assert!(
        msg.contains("keychain") || msg.contains("CONFIDANT_DEVICE_KEY"),
        "expected a keychain/env-key refusal, got: {msg}"
    );
    assert!(fix.contains("CONFIDANT_DEVICE_KEY"), "{fix}");
    assert!(fix.contains("CONFIDANT_OPERATOR_KEY"), "{fix}");
    assert!(!b.vault.exists(), "refused init wrote the target");
}

/// #682: `CONFIDANT_TEST_KEYCHAIN_DIR` is the same device-key source
/// `provision_device_key` uses under `--all-features`. The preflight must
/// accept it (shred-rotation fixtures set the dir and unset
/// `CONFIDANT_DEVICE_KEY`).
#[test]
fn init_accepts_test_keychain_dir_without_device_key_env() {
    let b = Boot::new();
    let keychain = b._tmp.path().join("keychain");
    std::fs::create_dir_all(&keychain).unwrap();
    std::fs::write(keychain.join("device.key"), &b.device_bech32).unwrap();

    let out = b
        .cmd(&["init", "--create", "--no-input", "--json"])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_TEST_KEYCHAIN_DIR", &keychain)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init with TEST_KEYCHAIN_DIR must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn init_create_dry_run_reports_existing_master_branch() {
    // #682: a 0.6.0 skeleton on master with commits is not renamed (#661
    // only moves an unborn HEAD). Dry-run must say so instead of always
    // printing "branch main".
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    git(&b.vault, &["init", "-q"]);
    git(&b.vault, &["symbolic-ref", "HEAD", "refs/heads/master"]);
    git(&b.vault, &["config", "user.name", "Test Operator"]);
    git(&b.vault, &["config", "user.email", "test@example.com"]);
    std::fs::write(b.vault.join(".gitignore"), ".confidant/\n").unwrap();
    git(&b.vault, &["add", "--", ".gitignore"]);
    git(&b.vault, &["commit", "-q", "-m", "skeleton"]);
    assert_eq!(
        git_out(&b.vault, &["branch", "--show-current"]).trim(),
        "master"
    );

    let out = b.at_vault(&["init", "--create", "--no-input", "--dry-run", "--json"]);
    assert!(
        out.status.success(),
        "dry run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(v["branch"], "master", "{v}");
    let note = v["branch_note"].as_str().unwrap_or("");
    assert!(note.contains("master"), "{v}");
    assert!(note.contains("unborn"), "{v}");
    assert!(!b.vault.join("confidant.toml").exists());
}

#[test]
fn init_dry_run_with_env_keys_reports_plan() {
    let b = Boot::new();
    let seed_hex = "22".repeat(32);
    let out = b
        .cmd(&["init", "--create", "--no-input", "--dry-run", "--json"])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_OPERATOR_KEY", &seed_hex)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "dry run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dry_run"], true);
    assert!(!b.vault.exists());
    assert!(!b.home.join(".config/confidant").exists());
    assert_no_recovery_phrase(&out);
}

#[test]
fn init_phrase_out_works_with_env_operator_key() {
    let b = Boot::new();
    let seed_hex = "33".repeat(32);
    let phrase_path = b._tmp.path().join("phrase.txt");
    let out = b
        .cmd(&[
            "init",
            "--create",
            "--no-input",
            "--json",
            "--phrase-out",
            phrase_path.to_str().unwrap(),
        ])
        .arg("--vault")
        .arg(&b.vault)
        .env("CONFIDANT_OPERATOR_KEY", &seed_hex)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&phrase_path).unwrap();
    assert_eq!(text.split_whitespace().count(), 24);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&phrase_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "phrase file must be 0600");
    }
    let phrase = text.trim();
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(phrase)
            && !String::from_utf8_lossy(&out.stderr).contains(phrase),
        "phrase leaked to stdout/stderr"
    );
    assert!(b.home.join(".config/confidant/trust.toml").is_file());
}

// ---------------------------------------------------------------------------
// #661 edge: a pre-existing repo with an unborn HEAD is set to main, but a
// repo that already has commits is never renamed.
// ---------------------------------------------------------------------------

#[test]
fn bootstrap_sets_main_on_a_preexisting_unborn_repo() {
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    git_out(&b.vault, &["init", "-q", "-b", "master"]);
    assert_eq!(
        git_out(&b.vault, &["symbolic-ref", "--short", "HEAD"]).trim(),
        "master",
        "precondition: unborn HEAD on master"
    );

    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        git_out(&b.vault, &["branch", "--show-current"]).trim(),
        "main",
        "unborn pre-existing repo must be created on main"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["branch"], "main");
}

#[test]
fn bootstrap_does_not_rename_a_repo_with_commits() {
    let b = Boot::new();
    std::fs::create_dir_all(&b.vault).unwrap();
    git_out(&b.vault, &["init", "-q", "-b", "trunk"]);
    std::fs::write(b.vault.join(".gitignore"), "*.log\n").unwrap();
    git_out(
        &b.vault,
        &[
            "-c",
            "user.name=Test Operator",
            "-c",
            "user.email=test@example.com",
            "add",
            "--",
            ".gitignore",
        ],
    );
    git_out(
        &b.vault,
        &[
            "-c",
            "user.name=Test Operator",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-q",
            "-m",
            "seed",
        ],
    );

    let out = b.at_vault(&["init", "--create", "--no-input", "--json"]);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        git_out(&b.vault, &["branch", "--show-current"]).trim(),
        "trunk",
        "a repo with commits must keep its branch"
    );
}
