//! Tests for `confidant` encrypted writes (#148 Spec 3).
//!
//! Every keyed test uses a throwaway HOME + vault + device key (ADR-14).
//! The operator key is provided via CONFIDANT_TEST_OPERATOR_KEY. All data
//! is fake.

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

/// Test harness: temp HOME + vault + throwaway device key. The vault
/// starts with the coaching pack (for `log session`) and no `[crypto]`
/// table (keyed tests exercise the encrypted path).
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

        std::fs::write(
            vault.join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n",
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

    /// Switch this harness to the test keychain dir: the device key is
    /// read from / written to `$DIR/device.key` instead of
    /// `CONFIDANT_DEVICE_KEY` / the OS keychain. Needed for
    /// `keys device-add --initiate`, which refuses an env-var key.
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

    /// Run a command without the device key (fail-closed paths).
    fn cmd_no_device_key(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
            .arg("--vault")
            .arg(&self.vault)
            .env("HOME", &self.home)
            .env("CONFIDANT_TEST_OPERATOR_KEY", &self.operator_hex)
            .env("CONFIDANT_KEYCHAIN", "off")
            .env_remove("CONFIDANT_DEVICE_KEY");
        c
    }

    fn init(&self) -> Output {
        self.cmd(&["init", "--no-input"]).output().unwrap()
    }

    fn init_client(&self, client_id: &str) -> Output {
        self.cmd(&["keys", "init-client", client_id, "--no-input"])
            .output()
            .unwrap()
    }

    /// Keyed vault with a client for `person`.
    fn keyed(&self, person: &str) -> Output {
        let out = self.init();
        assert!(out.status.success(), "init failed: {}", stderr(&out));
        let out = self.init_client(person);
        assert!(out.status.success(), "init-client failed: {}", stderr(&out));
        out
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

const PERSON: &str = "p-01J9Z3K4QF0000000000000000";
const PERSON2: &str = "p-01J9Z3K4QG0000000000000000";

fn person_md(id: &str, name: &str, bio: &str) -> String {
    format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\n{bio}\n")
}

#[test]
fn record_add_writes_envelope_not_plaintext() {
    let h = Harness::new();
    h.keyed(PERSON);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "This bio is secret."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    let path = h.vault.join(format!("people/{PERSON}/profile.md"));
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    // Envelope shape: starts with ---\nid:, carries enc:, no name: in outer header.
    assert!(text.starts_with("---\nid:"), "not an envelope:\n{text}");
    assert!(text.contains("\nenc: xchacha20poly1305\n"), "no enc header");
    assert!(text.contains("key_id:"), "no key_id header");
    assert!(!text.contains("name:"), "name: leaked to outer header");
    assert!(
        !text.contains("This bio is secret"),
        "inner plaintext leaked"
    );
    assert!(
        !text.contains("Ada Example"),
        "name leaked outside ciphertext"
    );
}

#[test]
fn note_add_encrypts_body_and_name() {
    let h = Harness::new();
    h.keyed(PERSON);

    // Person with a name, so we can check the name doesn't leak either.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    let body = write_file(h._tmp.path(), "body.md", "This note body is secret.");
    let out = h
        .cmd(&[
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            body.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "note add failed: {}", stderr(&out));

    let notes_dir = h.vault.join(format!("people/{PERSON}/notes"));
    let entries: Vec<_> = std::fs::read_dir(&notes_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let bytes = std::fs::read(entries[0].as_ref().unwrap().path()).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("---\nid:"), "not an envelope");
    assert!(text.contains("\nenc: xchacha20poly1305\n"));
    assert!(
        !text.contains("This note body is secret"),
        "note body leaked"
    );
    // The person's name must not appear in the note file.
    assert!(!text.contains("Ada Example"), "name leaked into note file");
}

#[test]
fn log_session_note_writes_envelope() {
    let h = Harness::new();
    h.keyed(PERSON);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Coaching pack needs an open package before a session can be logged.
    let ledger_dir = h.vault.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-01 open {PERSON} package pkg-01J9Z3K4QF0000000000000000 4 sessions\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "package"]);

    let out = h
        .cmd(&[
            "log",
            "session",
            PERSON,
            "60m",
            "paid",
            "--note",
            "This session note is secret.",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "log session failed: {}", stderr(&out));

    // The note file is an envelope…
    let notes_dir = h.vault.join(format!("people/{PERSON}/notes"));
    let entries: Vec<_> = std::fs::read_dir(&notes_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let text = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
    assert!(text.starts_with("---\nid:"));
    assert!(text.contains("\nenc: xchacha20poly1305\n"));
    assert!(
        !text.contains("This session note is secret"),
        "session note leaked"
    );

    // …but the ledger line stays plaintext by design.
    let ledger = h.vault.join("ledger");
    let mut found = false;
    for entry in walk(&ledger) {
        if entry.extension().and_then(|e| e.to_str()) == Some("cfd") {
            let t = std::fs::read_to_string(&entry).unwrap();
            if t.contains("session") && t.contains(PERSON) {
                found = true;
                assert!(!t.contains("enc:"), "ledger must stay plaintext");
            }
        }
    }
    assert!(found, "ledger line not found");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn write_refuses_without_device_key_no_fallback() {
    let h = Harness::new();
    h.keyed(PERSON);

    let input = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md(PERSON2, "No Key", "Bio."),
    );
    // No device key: the write must fail closed, with no plaintext fallback.
    let out = h
        .cmd_no_device_key(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "write should have failed");
    let target = h.vault.join(format!("people/{PERSON2}/profile.md"));
    assert!(!target.exists(), "target file must be absent after refusal");
    let err = stderr(&out);
    assert!(
        err.contains("no device key") || err.contains("device key"),
        "error should name the missing device key, got: {err}"
    );
}

#[test]
fn deal_for_uninitialized_client_suggests_keys_init_client() {
    let h = Harness::new();
    // Init the vault keys, but do NOT init-client for PERSON.
    let out = h.init();
    assert!(out.status.success());

    // A deal does not create its person, so a deal for a person with no
    // client key still refuses with the keys init-client suggestion
    // (#180 auto-creates keys only for `person` records).
    let deal_id = "d-01J9Z3K4QM0000000000000000";
    let input = write_file(
        h._tmp.path(),
        "deal.md",
        &format!(
            "---\nid: {deal_id}\ntype: deal\nperson: {PERSON}\nname: \"Big Deal\"\n---\n\nTerms are secret.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "write should have failed");
    let target = h.vault.join(format!("deals/{deal_id}/deal.md"));
    assert!(!target.exists(), "target file must be absent");
    let err = stderr(&out);
    assert!(
        err.contains("keys init-client"),
        "error should suggest keys init-client, got: {err}"
    );
}

#[test]
fn record_add_new_person_auto_creates_client_key() {
    let h = Harness::new();
    // Init the vault keys, but do NOT init-client for PERSON: #180
    // creates the key in the same commit as the person record.
    let out = h.init();
    assert!(out.status.success());

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "This bio is secret."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("created key for"),
        "should print the created-key notice, got: {}",
        stdout(&out)
    );

    // One commit holds both the record and the new key dir.
    let log = Command::new("git")
        .current_dir(&h.vault)
        .args(["log", "-1", "--name-only", "--format="])
        .output()
        .unwrap();
    let files = String::from_utf8_lossy(&log.stdout).into_owned();
    assert!(
        files.contains(&format!("people/{PERSON}/profile.md")),
        "commit should contain the person record, got:\n{files}"
    );
    assert!(
        files.contains(&format!("keys/{PERSON}/recipients.toml")),
        "commit should contain the new key dir, got:\n{files}"
    );
    let count = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&count.stdout).trim(),
        "3",
        "one commit on top of base + init (record + key together)"
    );

    // The record is an envelope under the new client key, not plaintext.
    let path = h.vault.join(format!("people/{PERSON}/profile.md"));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains(&format!("key_id: {PERSON}/e")),
        "record should encrypt under the new client key, got:\n{text}"
    );
    assert!(
        !text.contains("This bio is secret."),
        "bio must not be plaintext"
    );

    // The key is usable: a note for the new person encrypts.
    let note_body = write_file(h._tmp.path(), "note.txt", "Secret note.");
    let out = h
        .cmd(&[
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            note_body.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "note add failed: {}", stderr(&out));

    // JSON output carries the auto-created key (a second person, so the
    // union-recipients path is exercised again).
    let input2 = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md(PERSON2, "Bob Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input2.to_str().unwrap(),
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record add --json failed: {}",
        stderr(&out)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value["created_keys"][0].as_str(),
        Some(PERSON2),
        "JSON should report the auto-created key, got: {value}"
    );
}

#[test]
fn record_add_dry_run_creates_no_key() {
    let h = Harness::new();
    let out = h.init();
    assert!(out.status.success());

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "dry run failed: {}", stderr(&out));
    assert!(
        !h.vault.join("keys").join(PERSON).exists(),
        "dry run must not create a key dir"
    );
    assert!(
        !h.vault.join(format!("people/{PERSON}/profile.md")).exists(),
        "dry run must not write the record"
    );
}

#[test]
fn auto_init_rolls_back_key_dir_when_commit_fails() {
    let h = Harness::new();
    let out = h.init();
    assert!(out.status.success());

    // Break the commit step: no git identity. Files apply, then the
    // commit fails — the created key dir must be rolled back anyway.
    git(&h.vault, &["config", "--unset", "user.email"]);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "write should have failed");
    assert!(
        !h.vault.join("keys").join(PERSON).exists(),
        "failed write must not leave a key dir"
    );
    // init itself commits, so the count is 2 before the failed write —
    // assert it is unchanged, i.e. the failed write committed nothing.
    let count = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&count.stdout).trim(),
        "2",
        "no commit on failure (base + init only)"
    );
}

#[test]
fn deal_person_change_reencrypts_same_commit() {
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success());

    // Deal under PERSON.
    let deal_id = "d-01J9Z3K4QM0000000000000000";
    let input = write_file(
        h._tmp.path(),
        "deal.md",
        &format!(
            "---\nid: {deal_id}\ntype: deal\nperson: {PERSON}\nname: \"Big Deal\"\n---\n\nTerms are secret.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "deal add failed: {}", stderr(&out));
    let path = h.vault.join(format!("deals/{deal_id}/deal.md"));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains(&format!("key_id: {PERSON}/e")),
        "deal should encrypt under PERSON's key, got:\n{text}"
    );

    // A second deal under PERSON2 encrypts under PERSON2's key: the client
    // is resolved from the record's current person on every write, so a
    // person change re-encrypts under the new person's epoch.
    let deal2 = "d-01J9Z3K4QN0000000000000000";
    let input2 = write_file(
        h._tmp.path(),
        "deal2.md",
        &format!(
            "---\nid: {deal2}\ntype: deal\nperson: {PERSON2}\nname: \"Big Deal\"\n---\n\nTerms are secret.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input2.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "deal2 add failed: {}", stderr(&out));
    let path2 = h.vault.join(format!("deals/{deal2}/deal.md"));
    let text2 = std::fs::read_to_string(&path2).unwrap();
    assert!(
        text2.contains(&format!("key_id: {PERSON2}/e")),
        "deal should encrypt under PERSON2's key, got:\n{text2}"
    );
}

#[test]
fn no_ai_header_carries_person_flag_any_true_wins() {
    let h = Harness::new();
    h.keyed(PERSON);

    // Person record with no-ai: true.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    // Note WITHOUT --no-ai: the person's flag must win.
    let body = write_file(h._tmp.path(), "body.md", "Note body.");
    let out = h
        .cmd(&[
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            body.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "note add failed: {}", stderr(&out));

    let notes_dir = h.vault.join(format!("people/{PERSON}/notes"));
    let entries: Vec<_> = std::fs::read_dir(&notes_dir).unwrap().collect();
    let text = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
    assert!(
        text.contains("\nno-ai: true\n"),
        "outer no-ai must carry the person's flag (any true wins), got:\n{text}"
    );
}

#[test]
fn notes_mode_person_envelope_carries_mode_and_note_defaults_hidden() {
    // Issue #181: a person with `no-ai: notes` keeps their own envelope
    // visible (mode on the outer header); their notes default hidden.
    let h = Harness::new();
    h.keyed(PERSON);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: notes\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    let profile =
        std::fs::read_to_string(h.vault.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert!(
        profile.contains("\nno-ai: notes\n"),
        "person envelope must carry no-ai: notes, got:\n{profile}"
    );

    // Note WITHOUT --no-ai: the notes default must hide it.
    let body = write_file(h._tmp.path(), "body.md", "Note body.");
    let out = h
        .cmd(&[
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            body.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "note add failed: {}", stderr(&out));

    let notes_dir = h.vault.join(format!("people/{PERSON}/notes"));
    let entries: Vec<_> = std::fs::read_dir(&notes_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let text = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
    assert!(
        text.contains("\nno-ai: true\n"),
        "note envelope must default to no-ai: true under a notes-mode person, got:\n{text}"
    );
}

#[test]
fn encrypted_vault_inherits_notes_mode_via_non_person_field() {
    // Issue #270: on an encrypted vault, `no-ai: notes` inheritance also
    // follows any front-matter reference to the person.
    //
    // We verify via the allowlist directly: the test writes a top-level
    // note (plaintext file, like the plaintext-vault test) into the
    // encrypted vault. The note references a notes-mode person (whose
    // `no-ai: notes` rides the encrypted outer header) only through a
    // non-`person:` field, and must not be cleared.
    let h = Harness::new();
    h.keyed(PERSON);
    // Bob needs a client key too, so his notes-mode person record decrypts.
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));

    // Bob: notes-mode person (mode on the encrypted outer header).
    let bob = PERSON2;
    let input = write_file(
        h._tmp.path(),
        "bob.md",
        &format!(
            "---\nid: {bob}\ntype: person\nname: \"Bob Example\"\nno-ai: notes\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    // Top-level note referencing Bob only via `related:`. Written directly
    // (plaintext) like the plaintext-vault test; the allowlist operates on
    // the parsed record regardless of envelope.
    let note_id = "n-01J9Z3K4QF6000000000000000";
    let note_dir = h.vault.join(format!("notes/{note_id}"));
    std::fs::create_dir_all(&note_dir).unwrap();
    std::fs::write(
        note_dir.join("note.md"),
        format!(
            "---\nid: {note_id}\ntype: note\nrelated: {bob}\n---\nSecret detail xylophone272.\n"
        ),
    )
    .unwrap();
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&h.vault)
        .args(["add", "-A"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&h.vault)
        .args(["commit", "-qm", "top-level note"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // `find` on the note's token returns 0 hits: the note inherits hidden
    // via the `related:` field.
    let out = h
        .cmd(&["find", "xylophone272", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 0, "{v}");
}

#[test]
fn dry_run_shows_plaintext_never_ciphertext() {
    let h = Harness::new();
    h.keyed(PERSON);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "This bio is secret."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "dry-run failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let changes = v["changes"].as_array().unwrap();
    assert!(!changes.is_empty());
    let content = changes[0]["content"].as_str().unwrap();
    // Dry-run shows the inner plaintext…
    assert!(
        content.contains("This bio is secret"),
        "dry-run should show plaintext, got: {content}"
    );
    // …never ciphertext or base64 envelope.
    assert!(!content.contains("enc:"), "dry-run showed ciphertext");
    // And nothing was written.
    assert!(!h.vault.join(format!("people/{PERSON}/profile.md")).exists());
}

#[test]
fn ledger_and_import_stay_plaintext() {
    let h = Harness::new();
    h.keyed(PERSON);

    // Person must exist for log session.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // import writes ledger lines only — they must stay plaintext.
    let import_file = write_file(
        h._tmp.path(),
        "import.txt",
        &format!("2026-10-12 open {PERSON} package pkg-01J9Z3K4QF0000000000000000 4 sessions\n"),
    );
    let out = h
        .cmd(&[
            "import",
            "--file",
            import_file.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    // import may fail for pack reasons; if it succeeds, the ledger is plaintext.
    if out.status.success() {
        let mut found = false;
        for entry in walk(&h.vault.join("ledger")) {
            let t = std::fs::read_to_string(&entry).unwrap();
            if t.contains("open") {
                found = true;
                assert!(!t.contains("enc:"), "ledger must stay plaintext");
            }
        }
        assert!(found);
    }

    // log session without --note appends only a ledger line.
    // (Needs an open package for the coaching balance check.)
    let ledger_dir = h.vault.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-01 open {PERSON} package pkg-01J9Z3K4QF0000000000000000 4 sessions\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "package"]);
    let out = h
        .cmd(&["log", "session", PERSON, "60m", "paid", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "log session failed: {}", stderr(&out));
    for entry in walk(&h.vault.join("ledger")) {
        let t = std::fs::read_to_string(&entry).unwrap();
        assert!(!t.contains("enc:"), "ledger must stay plaintext");
    }

    // confidant.toml is never encrypted.
    let toml = std::fs::read_to_string(h.vault.join("confidant.toml")).unwrap();
    assert!(!toml.contains("enc:"));
}

#[test]
fn log_session_without_note_works_without_device_key() {
    // #176: a note-less session appends only a plaintext ledger line, so
    // it must not touch the keychain at all.
    let h = Harness::new();
    h.keyed(PERSON);

    // Person must exist for log session.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Needs an open package for the coaching balance check.
    let ledger_dir = h.vault.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-01 open {PERSON} package pkg-01J9Z3K4QF0000000000000000 4 sessions\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "package"]);

    // No device key: CONFIDANT_KEYCHAIN=off, no env key, no test keychain dir.
    let mut c = h.cmd_no_device_key(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--date",
        "2026-10-13",
        "--no-input",
    ]);
    c.env_remove("CONFIDANT_TEST_KEYCHAIN_DIR");
    let out = c.output().unwrap();
    assert!(out.status.success(), "log session failed: {}", stderr(&out));

    // The session line landed, plaintext, on main.
    let ledger = std::fs::read_to_string(ledger_dir.join("10.cfd")).unwrap();
    assert!(
        ledger.contains(&format!("2026-10-13 session {PERSON} 60m paid")),
        "session line missing:\n{ledger}"
    );
    assert!(!ledger.contains("enc:"), "ledger must stay plaintext");
}

#[test]
fn log_session_note_fails_closed_without_device_key() {
    // #176: a session WITH a note cannot be written without the device
    // key (the note record is encrypted). Fail closed with a
    // note-specific fix pointing at --fallback-inbox; write nothing.
    // (#213: the note CAN now be queued with --fallback-inbox — see the
    // fallback tests below.)
    let h = Harness::new();
    h.keyed(PERSON);

    // Person must exist for log session.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Needs an open package for the coaching balance check.
    let ledger_dir = h.vault.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-01 open {PERSON} package pkg-01J9Z3K4QF0000000000000000 4 sessions\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "package"]);
    let ledger_before = std::fs::read_to_string(ledger_dir.join("10.cfd")).unwrap();

    // No device key: CONFIDANT_KEYCHAIN=off, no env key, no test keychain dir.
    let mut c = h.cmd_no_device_key(&[
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--note",
        "This session note is secret.",
        "--date",
        "2026-10-13",
        "--no-input",
    ]);
    c.env_remove("CONFIDANT_TEST_KEYCHAIN_DIR");
    let out = c.output().unwrap();
    assert!(
        !out.status.success(),
        "log session --note must fail without the device key"
    );
    let err = stderr(&out);
    assert!(
        err.contains("nothing was written"),
        "error must say nothing was written: {err}"
    );
    assert!(
        err.contains("without --note"),
        "error must point at logging without --note: {err}"
    );
    assert!(
        err.contains("--fallback-inbox"),
        "error must point at the --fallback-inbox way out: {err}"
    );

    // Nothing was written: ledger unchanged, no note file created.
    let ledger_after = std::fs::read_to_string(ledger_dir.join("10.cfd")).unwrap();
    assert_eq!(
        ledger_after, ledger_before,
        "ledger changed on a failed write"
    );
    assert!(
        !h.vault.join(format!("people/{PERSON}/notes")).exists(),
        "note file created on a failed write"
    );
}

#[test]
fn doctor_reports_plaintext_encrypted_mix() {
    let h = Harness::new();
    h.keyed(PERSON);

    // One encrypted record…
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // …and one plaintext record (written before keys existed, then keys added).
    // Simulate by writing a plaintext file directly and committing.
    let plain_id = "p-01J9Z3K4QJ0000000000000000";
    let plain_dir = h.vault.join(format!("people/{plain_id}"));
    std::fs::create_dir_all(&plain_dir).unwrap();
    std::fs::write(
        plain_dir.join("profile.md"),
        person_md(plain_id, "Plain Person", "Plain bio."),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "plaintext record"]);

    let out = h.cmd(&["doctor", "--no-input", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = v["checks"].as_array().unwrap();
    let mix = checks
        .iter()
        .find(|c| c["id"] == "record-encryption-mix")
        .expect("record-encryption-mix check missing");
    let msg = mix["message"].as_str().unwrap();
    // Code + count only: "1 encrypted, 1 plaintext record files".
    assert!(msg.contains("1 encrypted"), "got: {msg}");
    assert!(msg.contains("1 plaintext"), "got: {msg}");
    // Never names or paths.
    assert!(!msg.contains(plain_id), "mix must not name records");
    assert!(!msg.contains(PERSON), "mix must not name records");
}

#[test]
fn opt_out_plaintext_mode_writes_plaintext() {
    let h = Harness::new();
    // Declare the opt-out before init (no keys yet).
    let toml = std::fs::read_to_string(h.vault.join("confidant.toml")).unwrap();
    std::fs::write(
        h.vault.join("confidant.toml"),
        format!("{toml}\n[crypto]\nmode = \"plaintext\"\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "opt out"]);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "This bio is secret."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));
    let text =
        std::fs::read_to_string(h.vault.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert!(
        text.contains("This bio is secret"),
        "opt-out vault should write plaintext"
    );
    assert!(!text.contains("enc:"), "opt-out vault must not encrypt");
}

#[test]
fn opt_out_with_envelope_is_e_config() {
    let h = Harness::new();
    h.keyed(PERSON);

    // Write an encrypted record first.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Now declare mode = "plaintext": check must report E_CONFIG…
    let toml = std::fs::read_to_string(h.vault.join("confidant.toml")).unwrap();
    std::fs::write(
        h.vault.join("confidant.toml"),
        format!("{toml}\n[crypto]\nmode = \"plaintext\"\n"),
    )
    .unwrap();
    let out = h.cmd(&["check", "--json", "--no-input"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let codes: Vec<_> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_string())
        .collect();
    assert!(
        codes.contains(&"E_CONFIG".to_string()),
        "expected E_CONFIG, got: {codes:?}"
    );

    // …and the write path fails closed too.
    let input2 = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md(PERSON2, "Nope", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input2.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "write should fail closed");
}

#[test]
fn opt_out_with_keys_tree_refuses_plaintext() {
    let h = Harness::new();
    // Half-initialized keys/: operator cert only, no client manifests.
    // (Simulates a vault where init began but no client was keyed.)
    std::fs::create_dir_all(h.vault.join("keys")).unwrap();
    std::fs::write(h.vault.join("keys/operator.toml"), "# placeholder\n").unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "half keys"]);

    // Declare the opt-out: the half-initialized keys/ tree is structurally
    // encrypted, so this is a contradiction — writes fail closed, never
    // plaintext.
    let toml = std::fs::read_to_string(h.vault.join("confidant.toml")).unwrap();
    std::fs::write(
        h.vault.join("confidant.toml"),
        format!("{toml}\n[crypto]\nmode = \"plaintext\"\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "opt out"]);

    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "half-initialized keys/ must not fall into the plaintext branch"
    );
    assert!(
        !h.vault.join(format!("people/{PERSON}/profile.md")).exists(),
        "no file may be written"
    );
    let err = stderr(&out);
    assert!(
        err.contains("E_CONFIG") || err.contains("cannot downgrade"),
        "expected E_CONFIG contradiction, got: {err}"
    );
}

#[test]
fn init_refuses_plaintext_declared_vault() {
    let h = Harness::new();
    let toml = std::fs::read_to_string(h.vault.join("confidant.toml")).unwrap();
    std::fs::write(
        h.vault.join("confidant.toml"),
        format!("{toml}\n[crypto]\nmode = \"plaintext\"\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "opt out"]);

    let out = h.init();
    assert!(!out.status.success(), "init should refuse");
    let err = stderr(&out);
    assert!(
        err.contains("plaintext"),
        "error should name the plaintext declaration, got: {err}"
    );
    assert!(
        !h.vault.join("keys").exists() || is_only_gitkeep(&h.vault.join("keys")),
        "init must not create keys"
    );
}

fn is_only_gitkeep(dir: &Path) -> bool {
    let entries: Vec<_> = std::fs::read_dir(dir)
        .map(|e| e.flatten().collect())
        .unwrap_or_default();
    entries.is_empty()
        || (entries.len() == 1 && entries[0].file_name().to_string_lossy() == ".gitkeep")
}

#[test]
fn no_secret_material_in_any_output() {
    let h = Harness::new();
    h.keyed(PERSON);

    let secret_body = "This body mentions no secrets but must stay encrypted.";
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", secret_body),
    );
    // --json output must not carry key material or inner plaintext.
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));
    let combined = stdout(&out) + &stderr(&out);
    assert!(
        !combined.contains("AGE-SECRET-KEY"),
        "device key material in output"
    );
    assert!(
        !combined.contains(secret_body),
        "inner plaintext in --json output"
    );

    // Dry-run output likewise.
    let input2 = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md(PERSON2, "Nope", secret_body),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input2.to_str().unwrap(),
            "--no-input",
            "--json",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let combined = stdout(&out) + &stderr(&out);
    assert!(
        !combined.contains("AGE-SECRET-KEY"),
        "device key material in dry-run output"
    );
    // Note: dry-run legitimately shows the plaintext body (B5) — the
    // requirement is no *key* material. The body assertion above is for
    // the committed-write path only.
}

#[test]
fn write_refuses_unkeyed_vault_suggests_init() {
    // B10: an unkeyed vault without the opt-out fails closed (no silent
    // plaintext). This is the dedicated unkeyed-refusal test.
    let h = Harness::new();
    // No init, no [crypto] table.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "unkeyed write should fail");
    assert!(
        !h.vault.join(format!("people/{PERSON}/profile.md")).exists(),
        "no file may be written"
    );
    let err = stderr(&out);
    assert!(
        err.contains("confidant init"),
        "fix should point at `confidant init`, got: {err}"
    );
}

#[test]
fn record_add_after_device_add_uses_enrolled_key_id() {
    // Regression test for the hardcoded "device-0" blocker: a device
    // enrolled via `keys device-add` gets key id `device-{8-char suffix}`,
    // not `device-0`. `RecordEncryptor` must resolve this device's key id
    // once (pubkey match against the verified recipient maps) instead of
    // hardcoding it, or the new device's writes are refused.
    //
    // Note on the envelope's `key_id` header: per §14 it is
    // `<client_id>/e<epoch>` — it never carries the device (recipient) key
    // id, so the discriminating assertion is that the enrolled device's
    // write SUCCEEDS (pre-fix it was refused: its identity cannot open
    // device-0's wrapping) while a never-enrolled device is still refused.
    let h1 = Harness::new();
    h1.keyed(PERSON);

    // Second device: --initiate provisions a fresh keypair in the test
    // keychain dir (--force: a key is already "enrolled" there).
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
    assert!(out.status.success(), "initiate failed: {}", stderr(&out));

    // Enrolled device approves the request out-of-band.
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
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("from-request JSON");
    let key_id = v["key_id"].as_str().expect("key_id in JSON").to_string();
    assert!(
        key_id.starts_with("device-") && key_id != "device-0",
        "expected a device-add key id (device-<suffix>), got: {key_id}"
    );

    // The new device now acts on h1's vault: same vault path, h1's
    // operator key, and h1's anchor (trust is per-operator, not
    // per-device). Its device key is the freshly provisioned one in the
    // test keychain dir.
    h2.vault = h1.vault.clone();
    h2.operator_hex = h1.operator_hex.clone();
    let anchor_src = h1.home.join(".config/confidant/trust.toml");
    let anchor_dir = h2.home.join(".config/confidant");
    std::fs::create_dir_all(&anchor_dir).unwrap();
    std::fs::copy(&anchor_src, anchor_dir.join("trust.toml")).unwrap();

    let input = write_file(
        h2._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio written by the new device."),
    );
    let out = h2
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "device-add'd device could not write an encrypted record: {}",
        stderr(&out)
    );
    let path = h2.vault.join(format!("people/{PERSON}/profile.md"));
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("---\nid:"), "not an envelope:\n{text}");
    assert!(text.contains("\nenc: xchacha20poly1305\n"), "no enc header");
    assert!(
        !text.contains("Bio written by the new device"),
        "inner plaintext leaked"
    );

    // Control: a third device that was never enrolled is still refused.
    let mut h3 = Harness::new();
    h3.with_test_keychain();
    h3.vault = h1.vault.clone();
    h3.operator_hex = h1.operator_hex.clone();
    let anchor_dir3 = h3.home.join(".config/confidant");
    std::fs::create_dir_all(&anchor_dir3).unwrap();
    std::fs::copy(&anchor_src, anchor_dir3.join("trust.toml")).unwrap();
    let input3 = write_file(
        h3._tmp.path(),
        "person3.md",
        // PERSON2: a fresh path in this vault, so the write reaches the
        // enrollment check instead of failing on "already exists" (h2
        // already wrote PERSON's profile above).
        &person_md(PERSON2, "Ada Example", "Bio from a stranger device."),
    );
    let out = h3
        .cmd(&[
            "record",
            "add",
            "--file",
            input3.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "never-enrolled device must be refused"
    );
    assert!(
        stderr(&out).contains("not enrolled"),
        "refusal must be the not-enrolled error, got: {}",
        stderr(&out)
    );
}

const EDGE: &str = "e-01M3TC5H00MPJG00E100000000";
const IXN: &str = "i-01M3TC5H00MPJG00F100000000";

fn edge_md(id: &str, a: &str, b: &str, kind: &str) -> String {
    format!("---\nid: {id}\ntype: edge\na: {a}\nb: {b}\nkind: {kind}\n---\n")
}

fn record_add(h: &Harness, file: &Path) -> Output {
    h.cmd(&[
        "record",
        "add",
        "--file",
        file.to_str().unwrap(),
        "--no-input",
    ])
    .output()
    .unwrap()
}

#[test]
fn record_add_edge_encrypts_under_shared_key() {
    // #179: edges live under vault:shared — the envelope's key_id names
    // the shared client, and a/b/kind never appear outside the ciphertext.
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    for (id, name) in [(PERSON, "Ada Example"), (PERSON2, "Bea Demo")] {
        let input = write_file(
            h._tmp.path(),
            &format!("{id}.md"),
            &person_md(id, name, "Bio."),
        );
        let out = record_add(&h, &input);
        assert!(out.status.success(), "record add failed: {}", stderr(&out));
    }

    let input = write_file(
        h._tmp.path(),
        "edge.md",
        &edge_md(EDGE, PERSON, PERSON2, "married"),
    );
    let out = record_add(&h, &input);
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    let path = h.vault.join(format!("edges/{EDGE}/edge.md"));
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("---\nid:"), "not an envelope:\n{text}");
    assert!(text.contains("\nenc: xchacha20poly1305\n"), "no enc header");
    assert!(
        text.contains("key_id: vault:shared/"),
        "edge must encrypt under vault:shared, got:\n{text}"
    );
    assert!(!text.contains(PERSON), "edge end leaked to outer header");
    assert!(
        !text.contains("married"),
        "edge kind leaked to outer header"
    );
}

#[test]
fn record_add_interaction_with_mirrors_touchpoints() {
    // #179 Q3: one minimal touchpoint per `with:` participant — date +
    // own id only, no other participant ids, no primary id, no
    // interaction id — in the same write as the interaction record.
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));

    for (id, name) in [(PERSON, "Ada Example"), (PERSON2, "Bea Demo")] {
        let input = write_file(
            h._tmp.path(),
            &format!("{id}.md"),
            &person_md(id, name, "Bio."),
        );
        let out = record_add(&h, &input);
        assert!(out.status.success(), "record add failed: {}", stderr(&out));
    }

    let ixn = format!(
        "---\nid: {IXN}\ntype: interaction\nname: Group dinner\ndate: 2026-10-06\nperson: {PERSON}\nwith: [{PERSON2}]\n---\n\nFake group dinner.\n"
    );
    let input = write_file(h._tmp.path(), "ixn.md", &ixn);
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["touchpoints"],
        serde_json::json!([format!("2026-10-06 touch {PERSON2}")]),
        "{v}"
    );

    // The interaction record itself went to the primary's key.
    let path = h.vault.join(format!("interactions/{IXN}/interaction.md"));
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains(&format!("key_id: {PERSON}/")),
        "interaction must encrypt under the primary's key:\n{text}"
    );
    assert!(!text.contains(PERSON2), "with: list leaked to outer header");

    // The ledger carries exactly one touchpoint line for the participant.
    let ledger = std::fs::read_to_string(h.vault.join("ledger/2026/10.cfd")).unwrap();
    assert!(
        ledger.contains(&format!("2026-10-06 touch {PERSON2}\n")),
        "touchpoint missing from ledger:\n{ledger}"
    );
    assert!(
        !ledger.contains(IXN),
        "touchpoint must not carry the interaction id:\n{ledger}"
    );
    assert!(
        !ledger.contains(&format!("touch {PERSON} ")),
        "touchpoint must not carry the primary id:\n{ledger}"
    );
}

#[test]
fn record_add_interaction_with_validates_shape() {
    // The writer refuses what `check` would reject: a self entry, a
    // duplicate, a malformed list, and a `with:` without a date.
    let h = Harness::new();
    h.keyed(PERSON);

    let cases = [
        // Self: the primary is in with:.
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Dinner\ndate: 2026-10-06\nperson: {PERSON}\nwith: [{PERSON}]\n---\n\nBody.\n"
        ),
        // Duplicate participant.
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Dinner\ndate: 2026-10-06\nperson: {PERSON}\nwith: [{PERSON2}, {PERSON2}]\n---\n\nBody.\n"
        ),
        // Malformed: not a bracketed list.
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Dinner\ndate: 2026-10-06\nperson: {PERSON}\nwith: {PERSON2}\n---\n\nBody.\n"
        ),
        // No date: touchpoints are dated, so the write fails closed.
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Dinner\nperson: {PERSON}\nwith: [{PERSON2}]\n---\n\nBody.\n"
        ),
    ];
    for body in &cases {
        let input = write_file(h._tmp.path(), "ixn.md", body);
        let out = record_add(&h, &input);
        assert!(!out.status.success(), "write should have failed: {body}");
    }
    // Nothing was written: no interaction file, no ledger lines.
    assert!(!h.vault.join(format!("interactions/{IXN}")).exists());
    assert!(!h.vault.join("ledger/2026/10.cfd").exists());
}

// ---------------------------------------------------------------------------
// #213: `log session --note --fallback-inbox`
// ---------------------------------------------------------------------------

/// Recipient (`age1…`) for an inbox bech32 secret.
fn age_recipient(bech32: &str) -> String {
    let identity: age::x25519::Identity = bech32.trim().parse().unwrap();
    identity.to_public().to_string()
}

/// Pin the vault's inbox pubkey in the harness HOME user config.
fn write_user_config_pin(home: &Path, pubkey: &str) {
    let dir = home.join(".config/confidant");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        format!("[inbox]\npubkey = \"{pubkey}\"\n"),
    )
    .unwrap();
}

/// Advertise an `[inbox].pubkey` in the vault config (committed).
fn advertise_vault_inbox_pubkey(h: &Harness, pubkey: &str) {
    let path = h.vault.join("confidant.toml");
    let mut toml = std::fs::read_to_string(&path).unwrap();
    toml.push_str(&format!("\n[inbox]\npubkey = \"{pubkey}\"\n"));
    std::fs::write(&path, toml).unwrap();
    git(&h.vault, &["add", "confidant.toml"]);
    git(&h.vault, &["commit", "-qm", "advertise inbox pubkey"]);
}

/// Configure SSH commit signing on the vault repo so the fallback queue
/// commit and the drain's merge/clear commits can be signed (-S).
/// Returns the TempDir that must stay alive, or `None` (skip the test)
/// when ssh-keygen is unavailable.
fn ssh_signing(h: &Harness) -> Option<tempfile::TempDir> {
    let keydir = tempfile::tempdir().ok()?;
    let key = keydir.path().join("key");
    let gen = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-C",
            "fallback-e2e",
            "-f",
            key.to_str()?,
        ])
        .output()
        .ok()?;
    if !gen.status.success() {
        return None;
    }
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).ok()?;
    let allowed = keydir.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!("test@example.com namespaces=\"git\" {pubkey}"),
    )
    .ok()?;
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", key.to_str()?),
        ("gpg.ssh.allowedSignersFile", allowed.to_str()?),
        ("commit.gpgsign", "true"),
    ] {
        git(&h.vault, &["config", k, v]);
    }
    Some(keydir)
}

/// Shared setup for the fallback tests: keyed vault + person + open
/// package, returning the ledger dir.
fn fallback_setup(h: &Harness) -> PathBuf {
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            input.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record add failed: {}", stderr(&out));
    let ledger_dir = h.vault.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-01 open {PERSON} package pkg-01J9Z3K4QF0000000000000000 4 sessions\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "package"]);
    ledger_dir
}

/// Run `log session --note` with no device key.
fn log_session_no_key(h: &Harness, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "log",
        "session",
        PERSON,
        "60m",
        "paid",
        "--note",
        "This session note is secret.",
        "--date",
        "2026-10-13",
        "--no-input",
    ];
    args.extend_from_slice(extra);
    let mut c = h.cmd_no_device_key(&args);
    c.env_remove("CONFIDANT_TEST_KEYCHAIN_DIR");
    c.output().unwrap()
}

#[test]
fn log_session_note_fallback_inbox_queues_and_drains() {
    // #213: with --fallback-inbox, a keychain failure queues the session
    // (ledger line + note) to the inbox, encrypted to the pinned inbox
    // pubkey, signed; `confidant inbox` later merges it with the same
    // result as a normal write. Nothing plaintext lands on main.
    let h = Harness::new();
    let ledger_dir = fallback_setup(&h);

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let ledger_before = std::fs::read_to_string(ledger_dir.join("10.cfd")).unwrap();
    let main_before = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(main_before.status.success());

    // Queue: no device key.
    let out = log_session_no_key(&h, &["--fallback-inbox"]);
    assert!(
        out.status.success(),
        "fallback queue failed: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("queued to inbox; run `confidant inbox` when the keychain is back"),
        "missing queued message: {}",
        stdout(&out)
    );

    // Main is untouched: ledger unchanged, no note file, HEAD unmoved.
    assert_eq!(
        std::fs::read_to_string(ledger_dir.join("10.cfd")).unwrap(),
        ledger_before
    );
    assert!(!h.vault.join(format!("people/{PERSON}/notes")).exists());
    let main_after = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(main_before.stdout, main_after.stdout, "main must not move");

    // Inbox branch: two items, queue commit signed, no plaintext in blobs.
    let inbox_tree = Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-tree", "-r", "--name-only", "inbox"])
        .output()
        .unwrap();
    let inbox_tree = String::from_utf8_lossy(&inbox_tree.stdout).into_owned();
    let stems: Vec<&str> = inbox_tree.lines().collect();
    assert_eq!(stems.len(), 2, "inbox tree:\n{inbox_tree}");
    assert!(
        stems.iter().all(|s| s.ends_with(".age")),
        "inbox tree:\n{inbox_tree}"
    );
    let sig = Command::new("git")
        .current_dir(&h.vault)
        .args(["log", "--format=%G?", "-n", "1", "inbox"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&sig.stdout).trim(), "G");
    for stem in &stems {
        let blob = Command::new("git")
            .current_dir(&h.vault)
            .args(["show", &format!("inbox:{stem}")])
            .output()
            .unwrap();
        assert!(
            !blob
                .stdout
                .windows(b"This session note is secret.".len())
                .any(|w| w == b"This session note is secret."),
            "plaintext note in queued blob {stem}"
        );
    }

    // Drain: device key back + inbox key + --allow-unsigned (no signers
    // configured in the user config).
    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(out.status.success(), "drain failed: {}", stderr(&out));

    // The ledger line landed with its src:fallback provenance token.
    let ledger = std::fs::read_to_string(ledger_dir.join("10.cfd")).unwrap();
    let session_line = ledger
        .lines()
        .find(|l| l.contains("2026-10-13 session") && l.contains("note:"))
        .expect("session line missing after drain");
    assert!(
        session_line.contains("src:fallback/"),
        "session line lacks src:fallback: {session_line}"
    );
    // The note id in the line matches the drained record file.
    let note_id = session_line
        .split_whitespace()
        .find_map(|t| t.strip_prefix("note:"))
        .expect("note: token missing");
    let note_path = h.vault.join(format!("people/{PERSON}/notes/{note_id}.md"));
    let note_bytes = std::fs::read(&note_path).unwrap();
    let note_text = String::from_utf8_lossy(&note_bytes);
    assert!(note_text.starts_with("---\nid:"), "note is not an envelope");
    assert!(note_text.contains("\nenc: "), "note lacks enc header");
    assert!(
        !note_text.contains("This session note is secret."),
        "plaintext note in drained file"
    );

    // The drained note decrypts (via find) to the original text: the
    // drained result matches a normal write.
    let out = h
        .cmd(&["find", "secret", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let excerpts: Vec<&str> = v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["excerpt"].as_str().unwrap())
        .collect();
    assert!(
        excerpts
            .iter()
            .any(|e| e.contains("This session note is secret.")),
        "decrypted note body not in excerpts: {excerpts:?}"
    );

    // Idempotency: a second drain merges nothing (the inbox is cleared).
    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(
        out.status.success(),
        "second drain failed: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("0 item(s) merged"),
        "second drain should merge nothing: {}",
        stdout(&out)
    );
}

#[test]
fn log_session_note_fallback_refuses_pin_mismatch() {
    // #213: the fallback refuses when the vault pubkey does not match
    // the user-config pin — encrypting to an unverified key would be
    // key substitution.
    let h = Harness::new();
    let _ledger_dir = fallback_setup(&h);

    let vault_bech32 = age_generate_bech32();
    let vault_recipient = age_recipient(&vault_bech32);
    let pinned_bech32 = age_generate_bech32();
    let pinned_recipient = age_recipient(&pinned_bech32);
    assert_ne!(vault_recipient, pinned_recipient);
    advertise_vault_inbox_pubkey(&h, &vault_recipient);
    write_user_config_pin(&h.home, &pinned_recipient);
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };

    let out = log_session_no_key(&h, &["--fallback-inbox"]);
    assert!(!out.status.success(), "pin mismatch must refuse");
    let err = stderr(&out);
    assert!(
        err.contains("E_INBOX_UNTRUSTED"),
        "pin mismatch must be E_INBOX_UNTRUSTED: {err}"
    );
    // Nothing queued: no inbox branch.
    let branches = Command::new("git")
        .current_dir(&h.vault)
        .args(["branch", "--list", "inbox"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&branches.stdout).trim().is_empty(),
        "inbox branch must not exist after a refused fallback"
    );
}

#[test]
fn log_session_note_fallback_refuses_without_pin() {
    // #213: with no pin at all the fallback refuses — it cannot verify
    // which key it would encrypt to (stricter than the drain, which
    // only warns on a missing pin).
    let h = Harness::new();
    let _ledger_dir = fallback_setup(&h);

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    // No user-config pin written.
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };

    let out = log_session_no_key(&h, &["--fallback-inbox"]);
    assert!(!out.status.success(), "missing pin must refuse");
    assert!(
        stderr(&out).contains("E_INBOX_UNTRUSTED"),
        "missing pin must be E_INBOX_UNTRUSTED: {}",
        stderr(&out)
    );
}

#[test]
fn log_session_note_fallback_refuses_without_signing() {
    // #213: the queue commit is signed (-S); with no signing configured
    // the fallback refuses rather than queueing an item the drain
    // would never trust.
    let h = Harness::new();
    let _ledger_dir = fallback_setup(&h);

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);
    // No signing configured.

    let out = log_session_no_key(&h, &["--fallback-inbox"]);
    assert!(!out.status.success(), "unsigned queue must refuse");
    let err = stderr(&out);
    assert!(
        err.contains("E_INBOX_UNTRUSTED"),
        "unsigned queue must be E_INBOX_UNTRUSTED: {err}"
    );
    assert!(
        err.contains("commit signing"),
        "unsigned queue must point at commit signing: {err}"
    );
}

#[test]
fn log_session_note_fallback_dry_run_checks_signing_gate() {
    // #213 follow-up: --dry-run reports `would queue` only when the real
    // run could proceed — without commit signing configured it refuses
    // with the same E_INBOX_UNTRUSTED the queue would hit, instead of a
    // `would queue` that can never happen.
    let h = Harness::new();
    let _ledger_dir = fallback_setup(&h);

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);
    // No signing configured.

    let out = log_session_no_key(&h, &["--fallback-inbox", "--dry-run"]);
    assert!(!out.status.success(), "unsigned dry run must refuse");
    let err = stderr(&out);
    assert!(
        err.contains("E_INBOX_UNTRUSTED"),
        "unsigned dry run must be E_INBOX_UNTRUSTED: {err}"
    );

    // With signing configured the dry run reports `would queue` and
    // queues nothing.
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let out = log_session_no_key(&h, &["--fallback-inbox", "--dry-run"]);
    assert!(out.status.success(), "dry run failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("would queue 2 item(s)"),
        "dry run must report would queue: {}",
        stdout(&out)
    );
}

#[test]
fn log_session_note_fallback_json_envelope() {
    // #213 + ADR-7: the fallback speaks JSON like every other command.
    let h = Harness::new();
    let _ledger_dir = fallback_setup(&h);
    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let out = log_session_no_key(&h, &["--fallback-inbox", "--json"]);
    assert!(
        out.status.success(),
        "fallback queue failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["queued"], true);
    assert_eq!(v["fallback_inbox"], true);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["tip"].as_str().unwrap().len(), 40);
    assert!(v["vault"].is_string(), "envelope must carry vault: {v}");
}
