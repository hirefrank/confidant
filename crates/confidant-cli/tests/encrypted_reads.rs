//! Tests for `confidant` encrypted reads (#148 Spec 4).
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

/// Test harness: temp HOME + vault + throwaway device key.
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

    /// Switch this harness to the test keychain dir (for `keys shred`'s
    /// device-key rotation): the device key is read from / written to
    /// `$DIR/device.key` instead of `CONFIDANT_DEVICE_KEY`. Call before
    /// `keyed`/`init`.
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

    /// Run a command without the device key (fail-closed read paths).
    fn cmd_no_device_key(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
            .arg("--vault")
            .arg(&self.vault)
            .env("HOME", &self.home)
            .env("CONFIDANT_TEST_OPERATOR_KEY", &self.operator_hex)
            .env("CONFIDANT_KEYCHAIN", "off")
            .env_remove("CONFIDANT_DEVICE_KEY")
            .env_remove("CONFIDANT_TEST_KEYCHAIN_DIR");
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
    fn keyed(&self, person: &str) {
        let out = self.init();
        assert!(out.status.success(), "init failed: {}", stderr(&out));
        let out = self.init_client(person);
        assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    }

    fn record_add(&self, input: &Path) {
        let out = self
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
    }

    fn note_add(&self, person: &str, body: &str, no_ai: bool) {
        let input = write_file(self._tmp.path(), "note.txt", body);
        let mut args = vec![
            "note",
            "add",
            "--person",
            person,
            "--body-file",
            input.to_str().unwrap(),
            "--no-input",
        ];
        if no_ai {
            args.push("--no-ai");
        }
        let out = self.cmd(&args).output().unwrap();
        assert!(out.status.success(), "note add failed: {}", stderr(&out));
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

fn person_md(id: &str, name: &str, bio: &str) -> String {
    format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\n{bio}\n")
}

fn person_md_no_ai(id: &str, name: &str, bio: &str) -> String {
    format!("---\nid: {id}\ntype: person\nname: \"{name}\"\nno-ai: true\n---\n\n{bio}\n")
}

fn person_md_notes_mode(id: &str, name: &str, bio: &str) -> String {
    format!("---\nid: {id}\ntype: person\nname: \"{name}\"\nno-ai: notes\n---\n\n{bio}\n")
}

/// Keyed vault with an encrypted person (bio contains `bio_marker`) and one
/// encrypted note (body contains `note_marker`). Returns the harness.
fn keyed_vault_with_records(bio_marker: &str, note_marker: &str) -> Harness {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", &format!("Bio with {bio_marker}.")),
    );
    h.record_add(&input);
    h.note_add(PERSON, &format!("Note about {note_marker}."), false);
    h
}

#[test]
fn find_decrypts_cleared_encrypted_records() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    let out = h
        .cmd(&["find", "sourdough", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let matches = v["matches"].as_array().unwrap();
    assert!(!matches.is_empty(), "expected decrypted hits");
    let excerpts: Vec<&str> = matches
        .iter()
        .map(|m| m["excerpt"].as_str().unwrap())
        .collect();
    assert!(
        excerpts.iter().any(|e| e.contains("sourdough")),
        "decrypted note body not in excerpts: {excerpts:?}"
    );
    assert_eq!(v["skipped_encrypted"], 0);
    assert_eq!(v["refused_envelopes"], 0);
    // No ciphertext or envelope framing leaks into output.
    let text = stdout(&out);
    assert!(!text.contains("enc:"), "envelope header leaked");
    assert!(!text.contains("key_id"), "key_id leaked");

    // The person's bio is searchable too.
    let out = h
        .cmd(&["find", "quantum", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        !v["matches"].as_array().unwrap().is_empty(),
        "expected hit in decrypted profile"
    );
}

#[test]
fn find_excludes_no_ai_without_decrypting_even_when_keyed() {
    let h = Harness::new();
    h.keyed(PERSON);
    // no-ai person: the envelope carries no-ai: true in the outer header.
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_no_ai(PERSON, "Ada Example", "Secret no-ai bio with zephyr."),
    );
    h.record_add(&input);

    let out = h
        .cmd(&["find", "zephyr", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["matches"].as_array().unwrap().is_empty(),
        "no-ai record must be excluded"
    );
    // Not decrypted, not counted as skipped: it was never a candidate.
    assert_eq!(v["skipped_encrypted"], 0);
    assert_eq!(v["refused_envelopes"], 0);

    // Mechanism proof: with a *wrong* device key the no-ai record is still
    // excluded without a decrypt attempt — otherwise it would be skipped
    // or refused. (A decrypt attempt would also hit the AEAD.)
    let mut c = h.cmd_no_device_key(&["find", "zephyr", "--json", "--no-input"]);
    // Use a valid but unenrolled key instead of no key.
    c.env("CONFIDANT_DEVICE_KEY", age_generate_bech32());
    let out = c.output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["matches"].as_array().unwrap().is_empty());
    assert_eq!(v["skipped_encrypted"], 0, "no-ai must not be a skip");
    assert_eq!(v["refused_envelopes"], 0, "no-ai must not be a refusal");
}

// Issue #181 acceptance: a notes-mode person stays visible to agents
// (pack fields like name/bio reach find) while their notes default hidden.
#[test]
fn notes_mode_person_visible_in_find_but_note_hidden() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_notes_mode(PERSON, "Ada Example", "Bio with zephyr marker."),
    );
    h.record_add(&input);
    h.note_add(PERSON, "Note about quux marker.", false);

    // The person's own content is searchable.
    let out = h
        .cmd(&["find", "zephyr", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        !v["matches"].as_array().unwrap().is_empty(),
        "notes-mode person must stay searchable"
    );

    // The note that defaulted to hidden is not.
    let out = h
        .cmd(&["find", "quux", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["matches"].as_array().unwrap().is_empty(),
        "notes-mode note must be hidden from find"
    );
}

#[test]
fn notes_mode_context_shows_person_hides_notes() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_notes_mode(PERSON, "Ada Example", "Bio with zephyr marker."),
    );
    h.record_add(&input);
    h.note_add(PERSON, "Note about quux marker.", false);

    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "context failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The person is visible: name and profile decrypt for the agent.
    assert!(
        v["person"]["name"].as_str().unwrap().contains("Ada"),
        "notes-mode person name must be visible"
    );
    assert!(
        v["person"]["profile"].as_str().unwrap().contains("zephyr"),
        "notes-mode person profile must be visible"
    );
    // Their notes default hidden: omitted, not nulled.
    assert!(
        v["notes"].as_array().unwrap().is_empty(),
        "notes-mode notes must be omitted from context"
    );
}

/// #558: `record list` is the operator-only roster. Without
/// `--for-operator` it lists the §12 cleared set, so a `no-ai: true` person
/// is absent — never present with a nulled name or id. The flag, the same
/// mechanism as `record show --for-edit`, restores them with the tri-state
/// `no_ai` the #559 ruling specifies.
#[test]
fn record_list_hides_no_ai_until_for_operator() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    h.record_add(&input);
    let second = "p-01J9Z3K4QH0000000000000000";
    h.init_client(second);
    let input2 = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md_no_ai(second, "Cam Example", "Secret bio."),
    );
    h.record_add(&input2);

    // Cleared set only: the no-ai person is absent, and neither their name
    // nor their id appears anywhere in the output.
    let out = h
        .cmd(&["record", "list", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "record list failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["for_operator"], false);
    let names: Vec<&str> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["Ada Example"], "{v}");
    let dumped = serde_json::to_string(&v).unwrap();
    assert!(!dumped.contains("Cam Example"), "{dumped}");
    assert!(!dumped.contains(second), "{dumped}");

    // Operator flag: decrypted, listed, and badged.
    let out = h
        .cmd(&["record", "list", "--for-operator", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record list --for-operator failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["for_operator"], true);
    let records = v["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "{v}");
    let names: Vec<&str> = records
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["Ada Example", "Cam Example"]);
    let cam = records.iter().find(|r| r["id"] == second).unwrap();
    assert_eq!(cam["no_ai"], "true");
    assert_eq!(cam["kind"], "person");
}

/// #558/#559: a `no-ai: notes` person is in the cleared set, so the roster
/// lists them without the flag and reports the middle tri-state value.
#[test]
fn record_list_reports_notes_mode_without_the_flag() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_notes_mode(PERSON, "Ada Example", "Bio."),
    );
    h.record_add(&input);

    let out = h
        .cmd(&["record", "list", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "record list failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let records = v["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{v}");
    assert_eq!(records[0]["name"], "Ada Example");
    assert_eq!(records[0]["no_ai"], "notes");
}

/// #558: without a device key nothing decrypts. The roster is empty, but
/// the skip count is visible — never a silent empty list (spec 4, ⚠2).
#[test]
fn record_list_unkeyed_surfaces_skips_never_silently_empty() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    h.record_add(&input);

    for flag in [false, true] {
        let mut args = vec!["record", "list", "--json", "--no-input"];
        if flag {
            args.push("--for-operator");
        }
        let out = h.cmd_no_device_key(&args).output().unwrap();
        assert!(out.status.success(), "record list failed: {}", stderr(&out));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(
            v["records"].as_array().unwrap().is_empty(),
            "unkeyed roster must not list undecryptable people: {v}"
        );
        assert!(
            v["skipped_encrypted"].as_u64().unwrap() >= 1,
            "unkeyed roster must surface the skip count: {v}"
        );
        assert_eq!(v["refused_envelopes"], 0);
    }
}

/// #572: `context` is operator-only for `no-ai` too. Without the flag the
/// person is a keyless shell (PII withheld, no `for_operator`); the flag
/// decrypts through the operator path and badges the tri-state.
#[test]
fn context_hides_no_ai_until_for_operator() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_no_ai(PERSON, "Ada Example", "Secret bio with zephyr."),
    );
    h.record_add(&input);

    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "context failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("for_operator").is_none(), "{v}");
    assert_eq!(v["person"]["no_ai"], true);
    assert!(v["person"]["name"].is_null());
    let dumped = serde_json::to_string(&v).unwrap();
    assert!(!dumped.contains("zephyr"), "{dumped}");
    assert!(!dumped.contains("Ada Example"), "{dumped}");

    let out = h
        .cmd(&["context", PERSON, "--for-operator", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "context --for-operator failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["for_operator"], true);
    assert_eq!(v["person"]["no_ai"], "true");
    assert_eq!(v["person"]["name"], "Ada Example");
    assert!(v["person"]["profile"].as_str().unwrap().contains("zephyr"));
}

/// #572: `find --for-operator` decrypts and returns a `no-ai` record's
/// hits with the tri-state badge; without the flag it stays out.
#[test]
fn find_hides_no_ai_until_for_operator() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_no_ai(PERSON, "Ada Example", "Secret no-ai bio with zephyr."),
    );
    h.record_add(&input);

    let out = h
        .cmd(&["find", "zephyr", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["matches"].as_array().unwrap().is_empty());
    assert!(v.get("for_operator").is_none(), "{v}");

    let out = h
        .cmd(&["find", "zephyr", "--for-operator", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "find --for-operator failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["for_operator"], true);
    let hit = v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == PERSON)
        .expect("no-ai person must be found with the operator flag");
    assert_eq!(hit["no_ai"], "true");
    assert!(hit["excerpt"].as_str().unwrap().contains("zephyr"));
}

/// #593: a plaintext ledger line hidden from agents only because it names a
/// `no-ai` person is an operator hit with `operator_only: true`. The agent
/// JSON has no such key.
#[test]
fn find_marks_operator_only_ledger_line() {
    let h = Harness::new();
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_no_ai(PERSON, "Ada Example", "Secret no-ai bio."),
    );
    h.record_add(&input);
    // Ledger lines stay plaintext; only records are encrypted.
    let ledger_dir = h.vault.join("ledger/2026");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    std::fs::write(
        ledger_dir.join("10.cfd"),
        format!("2026-10-07 session {PERSON} 45m paid\n"),
    )
    .unwrap();
    git(&h.vault, &["add", "-A"]);
    git(&h.vault, &["commit", "-qm", "ledger"]);

    let out = h
        .cmd(&["find", "45m", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["matches"].as_array().unwrap().is_empty(), "{v}");
    assert!(v.get("for_operator").is_none(), "{v}");

    let out = h
        .cmd(&["find", "45m", "--for-operator", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "find --for-operator failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["for_operator"], true);
    let hit = v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["path"].as_str().unwrap().starts_with("ledger/"))
        .expect("the ledger line must be an operator hit");
    assert_eq!(hit["operator_only"], true);
    assert!(hit.get("no_ai").is_none(), "{hit}");
}

#[test]
fn find_unkeyed_skips_and_counts_never_silent_empty() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    // Without a device key: no hits, but the skip count is visible.
    let out = h
        .cmd_no_device_key(&["find", "sourdough", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["matches"].as_array().unwrap().is_empty(),
        "unkeyed find must not return hits"
    );
    let skipped = v["skipped_encrypted"].as_u64().unwrap();
    assert!(skipped >= 2, "expected >= 2 skipped, got {skipped}");
    assert_eq!(v["refused_envelopes"], 0);

    // Text output carries the count too — never a silent "0 matches".
    let out = h
        .cmd_no_device_key(&["find", "sourdough", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("skipped_encrypted:"),
        "text output must show the skip count, got:\n{text}"
    );
    assert!(!text.contains("sourdough"), "content leaked without key");
}

#[test]
fn context_keyed_bundles_encrypted_unkeyed_counts() {
    // Keyed half: a regular (cleared) person bundles decrypted content.
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");
    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "context failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["person"]["id"].as_str().unwrap(), PERSON);
    assert!(
        v["person"]["name"].as_str().unwrap().contains("Ada"),
        "person name not decrypted"
    );
    assert!(
        v["person"]["profile"].as_str().unwrap().contains("quantum"),
        "profile not decrypted"
    );
    let notes = v["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1, "decrypted note should bundle");
    assert!(
        notes[0]["body"].as_str().unwrap().contains("sourdough"),
        "note body not decrypted"
    );

    // Unkeyed half: a no-ai person is readable as a shell (PII withheld,
    // exactly as on a plaintext vault); other persons' encrypted records
    // are skipped and counted — never silent, never an error.
    // (A note for a no-ai person inherits no-ai, so the skipped record
    // comes from a second, regular person.)
    let h2 = Harness::new();
    h2.keyed(PERSON);
    let input = write_file(
        h2._tmp.path(),
        "person.md",
        &person_md_no_ai(PERSON, "Ada Example", "Secret bio."),
    );
    h2.record_add(&input);
    let person2 = "p-01J9Z3K4QH0000000000000000";
    h2.init_client(person2);
    let input2 = write_file(
        h2._tmp.path(),
        "person2.md",
        &person_md(person2, "Bo Example", "Another bio."),
    );
    h2.record_add(&input2);

    let out = h2
        .cmd_no_device_key(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unkeyed context failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["person"]["id"].as_str().unwrap(), PERSON);
    assert_eq!(v["person"]["no_ai"], true);
    assert!(v["person"]["name"].is_null(), "no-ai name must be withheld");
    assert!(v["notes"].as_array().unwrap().is_empty());
    let skipped = v["skipped_encrypted"].as_u64().unwrap();
    assert!(skipped >= 1, "expected skipped count, got {skipped}");
}

#[test]
fn context_unkeyed_person_is_hard_error() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    // The person's own record is encrypted and unreadable: hard error,
    // not "no person with id".
    let out = h
        .cmd_no_device_key(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "unkeyed context of an encrypted person must fail"
    );
    let text = stdout(&out) + &stderr(&out);
    assert!(
        !text.contains("no person with id"),
        "must be a hard decrypt error, not not-found, got:\n{text}"
    );
    assert!(
        text.contains("decrypt"),
        "error should mention decryption, got:\n{text}"
    );
}

#[test]
fn tampered_envelope_refused_counted_no_content() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    // Tamper with the note envelope's ciphertext: flip base64 chars in the
    // body (after the closing ---), keeping the header intact so structural
    // parse succeeds and the AEAD authentication fails.
    let notes_dir = h.vault.join(format!("people/{PERSON}/notes"));
    let note_file = std::fs::read_dir(&notes_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&note_file).unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut fences = text.match_indices("---\n");
    fences.next(); // opening fence
    let (close_idx, _) = fences.next().expect("no closing fence");
    let body_start = close_idx + 4;
    for i in 0..8 {
        let idx = body_start + i * 7;
        if idx < bytes.len() {
            // Stay inside the base64 alphabet so parse succeeds; the
            // flipped ciphertext then fails AEAD authentication.
            bytes[idx] = match bytes[idx] {
                b'A' => b'B',
                b'a' => b'b',
                b'0' => b'1',
                c if c.is_ascii_alphanumeric() => b'A',
                c => c,
            };
        }
    }
    std::fs::write(&note_file, &bytes).unwrap();

    // Keyed find: the tampered record is refused and counted — never a
    // hit, never content, never folded into skipped_encrypted.
    let out = h
        .cmd(&["find", "sourdough", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["matches"].as_array().unwrap().is_empty(),
        "tampered record must not match"
    );
    assert_eq!(v["refused_envelopes"], 1, "expected 1 refused");
    assert_eq!(v["skipped_encrypted"], 0, "refused must not be a skip");
    // No content escapes: matches are empty, so only the query echo (not
    // record content) may mention the term.
    assert!(
        v["matches"].as_array().unwrap().is_empty(),
        "no matches expected"
    );
}

#[test]
fn check_keyless_structural_on_mixed_vault() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    // check runs with no hook and no keys: structural only, still green on
    // the fixture's own terms (the demo-style plaintext path is untouched).
    let out = h
        .cmd_no_device_key(&["check", "--json", "--no-input"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // check must not require keys: it parses what it can, structurally.
    assert!(
        v.get("findings").is_some(),
        "check should produce a findings list, got:\n{}",
        stdout(&out)
    );
}

#[test]
fn mcp_find_matches_cli_envelope() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    // MCP find goes through the CLI binary, so it inherits the decryptor.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "find",
            "arguments": {"query": "sourdough"}
        }
    });
    let mut child = std::process::Command::new(bin())
        .args(["mcp", "--no-input", "--vault"])
        .arg(&h.vault)
        .env("HOME", &h.home)
        .env("CONFIDANT_TEST_OPERATOR_KEY", &h.operator_hex)
        .env("CONFIDANT_KEYCHAIN", "off")
        .env("CONFIDANT_DEVICE_KEY", &h.device_bech32)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(serde_json::to_string(&req).unwrap().as_bytes())
        .unwrap();
    let mcp_out = child.wait_with_output().unwrap();
    assert!(mcp_out.status.success(), "mcp failed: {}", stderr(&mcp_out));
    let text = stdout(&mcp_out);
    assert!(
        text.contains("sourdough"),
        "MCP find should return the decrypted hit, got:\n{text}"
    );
    assert!(!text.contains("enc:"), "envelope framing leaked via MCP");
}

#[test]
fn allowlist_fixed_point_on_mixed_vault() {
    // The §12 allowlist fixed-point holds with decrypted records present:
    // the decrypted person + note are cleared, and their paths appear in
    // the index-time exclusion list (encrypted paths are still paths).
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    let out = h
        .cmd(&["allowlist", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "allowlist failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files: Vec<&str> = v["cleared_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        files.iter().any(|f| f.contains("profile.md")),
        "decrypted profile should be cleared, got: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("/notes/")),
        "decrypted note should be cleared, got: {files:?}"
    );

    // Unkeyed: nothing decrypts, so nothing is cleared — excluded by
    // omission, and no base64 bodies leak into the index list.
    let out = h
        .cmd_no_device_key(&["allowlist", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["cleared_files"].as_array().unwrap();
    assert!(
        files.is_empty(),
        "unkeyed allowlist must clear nothing, got: {files:?}"
    );
}

#[test]
fn no_secret_in_findings() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    // Findings carry code + count, never decrypted content or key material.
    let out = h
        .cmd(&["find", "sourdough", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(!text.contains("AGE-SECRET-KEY"), "secret leaked");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for f in v["findings"].as_array().unwrap() {
        let msg = f["message"].as_str().unwrap_or("");
        assert!(
            !msg.contains("sourdough"),
            "decrypted content in finding message: {msg}"
        );
        assert!(
            !msg.contains("quantum"),
            "decrypted content in finding: {msg}"
        );
    }
    // Text output too.
    let out = h
        .cmd(&["find", "sourdough", "--no-input"])
        .output()
        .unwrap();
    let text = stdout(&out);
    assert!(!text.contains("AGE-SECRET-KEY"), "secret leaked in text");
}

// ---------------------------------------------------------------------------
// reindex (#37): the CLI owns the corpus build
// ---------------------------------------------------------------------------

/// True if any corpus file contains `needle`.
fn corpus_contains(vault: &Path, needle: &str) -> bool {
    fn walk(dir: &Path, needle: &str) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if walk(&path, needle) {
                    return true;
                }
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                if text.contains(needle) {
                    return true;
                }
            }
        }
        false
    }
    walk(&vault.join(".confidant/qmd-corpus"), needle)
}

/// Cleared encrypted records are decrypted through the CLI into the corpus
/// (B1); no envelope framing survives.
#[test]
fn reindex_decrypts_encrypted_cleared_records() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");
    // reindex requires the corpus to be git-ignored; the bare Harness vault
    // is a repo without a .gitignore.
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();

    let out = h
        .cmd(&["reindex", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "reindex failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["skipped_encrypted"], 0);
    assert_eq!(v["refused_envelopes"], 0);
    assert!(
        v["records_decrypted"].as_u64().unwrap() >= 2,
        "expected >= 2 decrypted records: {v}"
    );

    let corpus = h.vault.join(".confidant/qmd-corpus");
    let profile =
        std::fs::read_to_string(corpus.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert!(
        profile.contains("quantum"),
        "profile not decrypted: {profile}"
    );
    assert!(!profile.contains("enc:"), "envelope header leaked");

    let notes_dir = corpus.join(format!("people/{PERSON}/notes"));
    let note_path = std::fs::read_dir(&notes_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let note = std::fs::read_to_string(&note_path).unwrap();
    assert!(note.contains("sourdough"), "note not decrypted: {note}");
    assert!(!note.contains("enc:"), "envelope header leaked");
}

/// A `no-ai` record is never decrypted into the corpus, even when this
/// device holds the key: excluded by construction (B1, #38).
#[test]
fn reindex_never_decrypts_no_ai_records() {
    let h = Harness::new();
    h.keyed(PERSON);
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md_no_ai(PERSON, "Ada Example", "Secret no-ai bio with zephyr."),
    );
    h.record_add(&input);
    // A cleared, keyed second person so the corpus is non-empty (a note for
    // a no-ai person inherits no-ai, so it would not prove anything).
    let person2 = "p-01J9Z3K4QH0000000000000000";
    h.init_client(person2);
    let input2 = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md(person2, "Bo Example", "Cleared bio about sourdough."),
    );
    h.record_add(&input2);

    let out = h
        .cmd(&["reindex", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "reindex failed: {}", stderr(&out));

    assert!(
        !corpus_contains(&h.vault, "zephyr"),
        "no-ai content entered the corpus"
    );
    assert!(
        !h.vault
            .join(format!(".confidant/qmd-corpus/people/{PERSON}/profile.md"))
            .exists(),
        "no-ai record file present in corpus"
    );
    assert!(
        corpus_contains(&h.vault, "sourdough"),
        "cleared record missing from corpus"
    );
}

/// Unlike `find` (skip + count, ⚠2), reindex refuses to build a corpus that
/// silently omits encrypted records, naming the counts (B4).
#[test]
fn reindex_refuses_unkeyed_on_encrypted_vault_with_counts() {
    let h = keyed_vault_with_records("quantum baking", "sourdough starter");

    let out = h
        .cmd_no_device_key(&["reindex", "--json", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_REINDEX_REFUSED");
    let skipped = v["skipped_encrypted"].as_u64().unwrap();
    assert!(skipped >= 2, "expected >= 2 skipped: {v}");
    assert_eq!(v["refused_envelopes"], 0);
    // Fail closed: nothing is written.
    assert!(
        !h.vault.join(".confidant/qmd-corpus").exists(),
        "refusal must not write a corpus"
    );
    let fix = v["error"]["fix"].as_str().unwrap();
    assert!(
        fix.contains("init") && fix.contains("recover"),
        "fix should point at init/recover: {fix}"
    );
    // No ciphertext or key material leaks into the refusal.
    let text = stdout(&out);
    assert!(!text.contains("enc:"), "envelope header leaked");
    assert!(!text.contains("AGE-SECRET-KEY"), "secret leaked");
}

/// `keys shred` deletes this device's local search index (corpus + QMD
/// store), so the shredded client's plaintext does not linger on the device.
#[test]
fn reindex_shred_deletes_search_index() {
    let mut h = Harness::new();
    h.with_test_keychain(); // shred rotates the device key
    h.keyed(PERSON);
    let input = write_file(
        h._tmp.path(),
        "person.md",
        &person_md(PERSON, "Ada Example", "Bio with quantum baking."),
    );
    h.record_add(&input);

    // Build the corpus (reindex requires `.confidant/` git-ignored).
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();
    let out = h
        .cmd(&["reindex", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "reindex failed: {}", stderr(&out));

    let corpus = h.vault.join(".confidant/qmd-corpus");
    assert!(corpus.is_dir(), "corpus not built");
    let profile =
        std::fs::read_to_string(corpus.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert!(
        profile.contains("quantum"),
        "profile not decrypted: {profile}"
    );

    // Shred the client.
    let out = h
        .cmd(&["keys", "shred", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shred failed: stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );

    // The local search index is gone (the client's plaintext with it).
    assert!(!corpus.exists(), "corpus still exists after shred");
    assert!(
        !h.vault.join(".confidant/qmd").exists(),
        "QMD store still exists after shred"
    );
}
