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
    /// Keep-alive for the ssh signing key tempdir (see [`ssh_signing`]).
    /// The vault's git config points at the key file, so it must outlive
    /// every signed commit a test makes — dropping it early makes
    /// `commit-tree -S` fail with "Couldn't load public key".
    _signing: Option<tempfile::TempDir>,
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
        // Pin the initial branch to `master`: the conflict tests check it
        // out by name, and `git init` alone would follow the machine's
        // `init.defaultBranch` (`main` on most machines) and fail there.
        // `git init -b` overrides any `init.defaultBranch` config.
        git(&vault, &["init", "-q", "-b", "master"]);
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
            _signing: None,
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
fn inbox_drain_new_person_without_client_key_refuses() {
    // #223 option B (#385): a new person arriving from the inbox waits
    // for the operator to run `confidant keys init-client <id>`; the
    // inbox never creates keys. Draining a person record for a keyless
    // person must refuse with the init-client fix text and lose nothing:
    // no key dir is created, the item stays queued, and nothing is
    // committed.
    let h = Harness::new();
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    // Init the vault keys, but do NOT init-client for the new person.
    let out = h.init();
    assert!(out.status.success(), "init failed: {}", stderr(&out));

    // Inbox keypair, advertised in the vault config and pinned in the
    // user config (mirrors the fallback-inbox e2e setup).
    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);

    // Queue a person record for a NEW person (no client key exists).
    let new_person = "p-01J9Z3K4QH0000000000000000";
    let payload = format!(
        "confidant-inbox/1\nkind: record\npath: people/{new_person}/profile.md\n---\n{}",
        person_md(new_person, "Ada Example", "Inbox bio is secret.")
    );
    confidant_core::queue_items(
        &h.vault,
        &[confidant_core::QueueItem {
            stem: "new-person-profile".to_string(),
            plaintext: payload,
        }],
        &inbox_recipient,
    )
    .expect("queue_items failed");

    let rev_parse = |rev: &str| {
        let out = Command::new("git")
            .current_dir(&h.vault)
            .args(["rev-parse", rev])
            .output()
            .unwrap();
        assert!(out.status.success(), "rev-parse {rev} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let main_before = rev_parse("HEAD");

    // Drain: device key present (env), inbox key supplied, signatures
    // allowed-unsigned.
    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(!out.status.success(), "drain should have refused");
    let err = stderr(&out);
    assert!(
        err.contains(&format!("Run `confidant keys init-client {new_person}`")),
        "error should suggest keys init-client, got: {err}"
    );

    // The inbox must never create client keys.
    assert!(
        !h.vault.join(format!("keys/{new_person}")).exists(),
        "no key dir may be created for the keyless person"
    );
    // The refused record was not written.
    assert!(
        !h.vault
            .join(format!("people/{new_person}/profile.md"))
            .exists(),
        "refused record must be absent"
    );
    assert!(
        !h.vault.join(format!("people/{new_person}")).exists(),
        "refused drain must not leave an empty record directory (#401)"
    );

    // The item is still queued on the inbox branch.
    let out = Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-tree", "-r", "--name-only", "inbox"])
        .output()
        .unwrap();
    let inbox_tree = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        inbox_tree.contains("new-person-profile.age"),
        "item must remain queued, inbox tree:\n{inbox_tree}"
    );

    // Nothing was committed: main is unmoved.
    assert_eq!(
        rev_parse("HEAD"),
        main_before,
        "drain must not commit on refusal"
    );

    // After init-client, drain succeeds and the vault is not wedged.
    let out = h.init_client(new_person);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(
        out.status.success(),
        "drain after init-client failed: {}",
        stderr(&out)
    );
    assert!(
        h.vault
            .join(format!("people/{new_person}/profile.md"))
            .exists(),
        "profile must exist after successful drain"
    );
}

#[test]
fn inbox_drain_batch_failure_removes_earlier_created_dir() {
    // #401 follow-up: a batch where the first item succeeds (keyed person)
    // and a later item fails (keyless person) must revert cleanly — the
    // earlier file AND its record directory are removed, or `check` and
    // `keys init-client` stay wedged on the empty directory.
    let h = Harness::new();
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let out = h.init();
    assert!(out.status.success(), "init failed: {}", stderr(&out));

    let keyed_person = "p-01J9Z3K4QJ0000000000000000";
    let keyless_person = "p-01J9Z3K4QK0000000000000000";
    let out = h.init_client(keyed_person);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);

    // Stems sort alphabetically, so the keyed item drains first and the
    // keyless item fails second — exercising batch revert.
    let keyed_payload = format!(
        "confidant-inbox/1\nkind: record\npath: people/{keyed_person}/profile.md\n---\n{}",
        person_md(keyed_person, "Ada Example", "Inbox bio is secret.")
    );
    let keyless_payload = format!(
        "confidant-inbox/1\nkind: record\npath: people/{keyless_person}/profile.md\n---\n{}",
        person_md(keyless_person, "Bob Example", "Inbox bio is secret.")
    );
    confidant_core::queue_items(
        &h.vault,
        &[
            confidant_core::QueueItem {
                stem: "a-keyed-profile".to_string(),
                plaintext: keyed_payload,
            },
            confidant_core::QueueItem {
                stem: "b-keyless-profile".to_string(),
                plaintext: keyless_payload,
            },
        ],
        &inbox_recipient,
    )
    .expect("queue_items failed");

    let rev_parse = |rev: &str| {
        let out = Command::new("git")
            .current_dir(&h.vault)
            .args(["rev-parse", rev])
            .output()
            .unwrap();
        assert!(out.status.success(), "rev-parse {rev} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let main_before = rev_parse("HEAD");

    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(!out.status.success(), "drain should have refused");
    assert!(
        stderr(&out).contains(&format!(
            "Run `confidant keys init-client {keyless_person}`"
        )),
        "error should name the keyless person, got: {}",
        stderr(&out)
    );

    // No key dir for the keyless person, and neither record directory
    // may remain — including the earlier keyed item's dir.
    assert!(
        !h.vault.join(format!("keys/{keyless_person}")).exists(),
        "no key dir may be created for the keyless person"
    );
    assert!(
        !h.vault
            .join(format!("people/{keyed_person}/profile.md"))
            .exists(),
        "earlier batch file must be reverted"
    );
    assert!(
        !h.vault.join(format!("people/{keyed_person}")).exists(),
        "earlier batch record directory must be reverted (#401)"
    );
    assert!(
        !h.vault.join(format!("people/{keyless_person}")).exists(),
        "failed write must not leave a record directory"
    );

    // Both items stay queued; nothing committed.
    let out = Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-tree", "-r", "--name-only", "inbox"])
        .output()
        .unwrap();
    let inbox_tree = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        inbox_tree.contains("a-keyed-profile.age") && inbox_tree.contains("b-keyless-profile.age"),
        "both items must remain queued, inbox tree:\n{inbox_tree}"
    );
    assert_eq!(
        rev_parse("HEAD"),
        main_before,
        "drain must not commit on refusal"
    );

    // After init-client, the retry drain succeeds and the vault is usable.
    let out = h.init_client(keyless_person);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(
        out.status.success(),
        "drain after init-client failed: {}",
        stderr(&out)
    );
    assert!(
        h.vault
            .join(format!("people/{keyed_person}/profile.md"))
            .exists(),
        "keyed profile must exist after successful drain"
    );
    assert!(
        h.vault
            .join(format!("people/{keyless_person}/profile.md"))
            .exists(),
        "keyless profile must exist after successful drain"
    );
}

#[test]
fn inbox_drain_skip_holds_keyless_person() {
    // #385: `--skip <item>` holds the keyless person item for a later
    // `keys init-client` run: the drain succeeds, merges nothing, creates
    // no key, and leaves the item queued. (That other items still merge
    // alongside a skip is covered by `skip_flag_defers_item_in_json_dry_run`.)
    let h = Harness::new();
    let Some(_signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let out = h.init();
    assert!(out.status.success(), "init failed: {}", stderr(&out));

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);

    let new_person = "p-01J9Z3K4QH0000000000000000";
    let payload = format!(
        "confidant-inbox/1\nkind: record\npath: people/{new_person}/profile.md\n---\n{}",
        person_md(new_person, "Ada Example", "Inbox bio is secret.")
    );
    confidant_core::queue_items(
        &h.vault,
        &[confidant_core::QueueItem {
            stem: "new-person-profile".to_string(),
            plaintext: payload,
        }],
        &inbox_recipient,
    )
    .expect("queue_items failed");

    // Drain, skipping the keyless item: succeeds, merges nothing.
    let mut drain = h.cmd(&[
        "inbox",
        "--allow-unsigned",
        "--no-input",
        "--skip",
        "new-person-profile",
    ]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    let out = drain.output().unwrap();
    assert!(out.status.success(), "drain failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("0 item(s) merged"),
        "skipped drain should merge nothing: {}",
        stdout(&out)
    );

    // Held: no key dir, no record, still queued.
    assert!(
        !h.vault.join(format!("keys/{new_person}")).exists(),
        "no key dir may be created for the held person"
    );
    assert!(
        !h.vault
            .join(format!("people/{new_person}/profile.md"))
            .exists(),
        "held record must be absent"
    );
    let out = Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-tree", "-r", "--name-only", "inbox"])
        .output()
        .unwrap();
    let inbox_tree = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        inbox_tree.contains("new-person-profile.age"),
        "keyless item must remain queued, inbox tree:\n{inbox_tree}"
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

    // Break the commit step deterministically (not via identity: parallel
    // tests and CI can set GIT_AUTHOR_* / system config).
    let hooks = h._tmp.path().join("git-hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let pre_commit = hooks.join("pre-commit");
    std::fs::write(&pre_commit, "#!/bin/sh\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pre_commit, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    git(
        &h.vault,
        &["config", "core.hooksPath", hooks.to_str().unwrap()],
    );

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
    // follows any front-matter reference to the person — and it has to be
    // stamped into the envelope's outer `no-ai` header at write time,
    // because `find`/`context` never see the decrypted `with:` field.
    //
    // The interaction goes through the real `record add` encrypted write
    // path (`record add` does not create notes; `note add` takes no extra
    // fields — but both funnel through the same stamp code): `person:` is
    // a visible person, `with:` names the notes-mode person. Without the
    // stamp-time fix the outer header reads `no-ai: false` and the
    // interaction leaks; with it the interaction is hidden from both
    // `find` and `context`.
    let h = Harness::new();
    h.keyed(PERSON);
    // Bob needs a client key too, so his notes-mode person record decrypts.
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    // Ada: visible person. Her profile must exist: stamp time fails
    // closed (#181) when the `person:` target has no readable profile.
    let input = write_file(
        h._tmp.path(),
        "ada.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = record_add(&h, &input);
    assert!(out.status.success(), "record add failed: {}", stderr(&out));
    // Carol: second visible person, for the control interaction's `with:`.
    let carol = "p-01J9Z3K4QH0000000000000000";
    let out = h.init_client(carol);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    let input = write_file(
        h._tmp.path(),
        "carol.md",
        &format!("---\nid: {carol}\ntype: person\nname: \"Carol Example\"\n---\n\nBio.\n"),
    );
    let out = record_add(&h, &input);
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    // Bob: notes-mode person (mode on the encrypted outer header).
    let bob = PERSON2;
    let input = write_file(
        h._tmp.path(),
        "bob.md",
        &format!(
            "---\nid: {bob}\ntype: person\nname: \"Bob Example\"\nno-ai: notes\n---\n\nBio.\n"
        ),
    );
    let out = record_add(&h, &input);
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    // Interaction filed under visible Ada, with notes-mode Bob as the
    // only participant. Really encrypted via `record add`.
    let ixn_id = "i-01J9Z3K4QF6000000000000000";
    let input = write_file(
        h._tmp.path(),
        "ixn.md",
        &format!(
            "---\nid: {ixn_id}\ntype: interaction\nname: Coffee\ndate: 2026-10-06\nperson: {PERSON}\nwith: [{bob}]\n---\n\nSecret detail xylophone272.\n"
        ),
    );
    let out = record_add(&h, &input);
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    // The outer envelope header carries the inherited hidden flag.
    let path = h
        .vault
        .join(format!("interactions/{ixn_id}/interaction.md"));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("\nno-ai: true\n"),
        "outer header must stamp the inherited hidden flag:\n{text}"
    );

    // Control interaction: same shape, but `with:` names visible Carol, so
    // it must stay visible (no over-hiding).
    let ixn2_id = "i-01J9Z3K4QF7000000000000000";
    let input = write_file(
        h._tmp.path(),
        "ixn2.md",
        &format!(
            "---\nid: {ixn2_id}\ntype: interaction\nname: Coffee\ndate: 2026-10-06\nperson: {PERSON}\nwith: [{carol}]\n---\n\nVisible detail xylophone273.\n"
        ),
    );
    let out = record_add(&h, &input);
    assert!(out.status.success(), "record add failed: {}", stderr(&out));

    // `find` on the hidden interaction's token returns 0 hits.
    let out = h
        .cmd(&["find", "xylophone272", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 0, "{v}");

    // `find` on the control interaction's token returns 1 hit.
    let out = h
        .cmd(&["find", "xylophone273", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 1, "{v}");

    // `context` for Ada never carries the hidden interaction's body, but
    // does carry the control interaction.
    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "context failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let text = serde_json::to_string(&v).unwrap();
    assert!(
        !text.contains("xylophone272"),
        "hidden interaction leaked into context: {v}"
    );
    assert!(
        text.contains("xylophone273"),
        "control interaction missing from context: {v}"
    );
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
    let gen = match Command::new("ssh-keygen")
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
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var_os("CI").is_some() {
                panic!("ssh-keygen is not installed and CI is set: signing tests must not skip");
            }
            return None;
        }
        Err(_) => return None,
    };
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

// ---------------------------------------------------------------------------
// #216: `record edit` / `record show --for-edit` on an encrypted vault
// ---------------------------------------------------------------------------

fn commit_count(h: &Harness) -> usize {
    let out = Command::new("git")
        .arg("-C")
        .arg(&h.vault)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

fn person_path(h: &Harness, id: &str) -> PathBuf {
    h.vault.join(format!("people/{id}/profile.md"))
}

/// Add `PERSON` to the keyed vault and return the record file's path.
fn add_person(h: &Harness, body: &str) -> PathBuf {
    let input = write_file(h._tmp.path(), "person.md", body);
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
    person_path(h, PERSON)
}

#[test]
fn record_edit_reencrypts_and_for_edit_reads_it_back() {
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "First bio."));
    let before = std::fs::read(&path).unwrap();

    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Example", "Second bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record edit failed: {}", stderr(&out));

    let after = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&after);
    assert_ne!(before, after, "the edit did not rewrite the file");
    assert!(
        text.contains("\nenc: xchacha20poly1305\n"),
        "the edited record is not an envelope:\n{text}"
    );
    assert!(!text.contains("Second bio."), "plaintext leaked");

    // The operator read hands the new body back, ready to edit again.
    let out = h
        .cmd(&["record", "show", PERSON, "--for-edit", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "record show failed: {}", stderr(&out));
    let shown = stdout(&out);
    assert!(
        shown.contains("Second bio."),
        "for-edit did not return the new body: {shown}"
    );
    assert!(
        !shown.contains("First bio."),
        "for-edit returned stale content: {shown}"
    );
}

#[test]
fn record_edit_unchanged_reuses_ciphertext_and_commits_nothing() {
    // #389 Q1: an unchanged body reuses the existing ciphertext byte for
    // byte, and makes no commit.
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));

    // First apply a real edit, so the stored plaintext is canonical.
    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Renamed", "New bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "record edit failed: {}", stderr(&out));

    let bytes = std::fs::read(&path).unwrap();
    let commits = commit_count(&h);

    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "no-op edit failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["unchanged"], serde_json::json!(true), "{v}");
    assert!(
        v.get("commit").is_none(),
        "no-op edit reported a commit: {v}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "the ciphertext changed on a no-op edit"
    );
    assert_eq!(commit_count(&h), commits, "a no-op edit committed");
}

#[test]
fn record_edit_is_idempotent_for_a_repeated_request_id() {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Renamed", "New bio."),
    );
    const RID: &str = "01J9Z3K4QF000000000000REQ1";
    let run = || {
        h.cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--request-id",
            RID,
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap()
    };

    let first = run();
    assert!(first.status.success(), "{}", stderr(&first));
    let v: serde_json::Value = serde_json::from_str(&stdout(&first)).unwrap();
    let commit = v["commit"].as_str().unwrap().to_owned();
    let commits = commit_count(&h);

    let replay = run();
    assert!(replay.status.success(), "{}", stderr(&replay));
    let v: serde_json::Value = serde_json::from_str(&stdout(&replay)).unwrap();
    assert_eq!(v["idempotent"], serde_json::json!(true), "{v}");
    assert_eq!(v["commit"].as_str().unwrap(), commit, "{v}");
    assert_eq!(commit_count(&h), commits, "the replay committed again");
}

#[test]
fn record_show_for_edit_decrypts_no_ai_that_reads_still_hide() {
    // #389 Q5: the operator may edit their own no-ai records; agents still
    // never see them.
    let h = Harness::new();
    h.keyed(PERSON);
    let secret = "Hidden bio that agents must never see.";
    add_person(
        &h,
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Hidden\"\nno-ai: true\n---\n\n{secret}\n"
        ),
    );

    let out = h
        .cmd(&["record", "show", PERSON, "--for-edit", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "for-edit failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains(secret),
        "for-edit did not decrypt the no-ai record: {}",
        stdout(&out)
    );

    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(
        !ctx.to_string().contains(secret),
        "the no-ai body leaked into context: {ctx}"
    );

    // Assert on matches, not on the raw document: the JSON echoes the query.
    let out = h
        .cmd(&["find", secret, "--json", "--no-input"])
        .output()
        .unwrap();
    let found: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        found["matches"].as_array().unwrap().len(),
        0,
        "find returned a no-ai record: {found}"
    );
}

/// `key_id` epoch from a record file, for the epoch assertions below.
fn envelope_epoch(bytes: &str) -> u64 {
    let key_id = bytes
        .lines()
        .find_map(|l| l.strip_prefix("key_id: "))
        .expect("envelope has a key_id");
    key_id
        .rsplit_once("/e")
        .expect("key_id carries an epoch")
        .1
        .parse()
        .expect("epoch is numeric")
}

#[test]
fn record_edit_refuses_an_envelope_this_device_cannot_decrypt() {
    // #389 Q4: with the client's key gone, an edit fails closed instead of
    // rewriting a record this device cannot read — and commits nothing.
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    let before = std::fs::read(&path).unwrap();
    std::fs::remove_dir_all(h.vault.join(format!("keys/{PERSON}"))).unwrap();

    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Renamed", "New bio."),
    );
    let commits = commit_count(&h);
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "the edit should have refused");
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot decrypt"),
        "{v}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the record was rewritten despite the refusal"
    );
    assert_eq!(commit_count(&h), commits, "the refused edit made a commit");
}

#[test]
fn record_edit_rekeys_a_deal_to_the_new_persons_key() {
    // #389 Q4: an edit that changes a deal's `person:` moves the record to
    // that person's client key.
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client: {}", stderr(&out));
    for (who, name) in [(PERSON, "Ada"), (PERSON2, "Bea")] {
        let p = write_file(
            h._tmp.path(),
            &format!("{who}.md"),
            &person_md(who, name, "bio"),
        );
        let out = h
            .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "add {who}: {}", stderr(&out));
    }

    const DEAL: &str = "d-01J9Z3K4QJ0000000000000000";
    let deal = |person: &str| {
        format!(
            "---\nid: {DEAL}\ntype: deal\nname: \"Coaching package\"\nperson: {person}\n---\n\nDeal body.\n"
        )
    };
    let first = write_file(h._tmp.path(), "deal.md", &deal(PERSON));
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            first.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add deal: {}", stderr(&out));

    let path = h.vault.join(format!("deals/{DEAL}/deal.md"));
    let before = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(before.contains(&format!("key_id: {PERSON}/")), "{before}");

    let second = write_file(h._tmp.path(), "deal2.md", &deal(PERSON2));
    let out = h
        .cmd(&[
            "record",
            "edit",
            DEAL,
            "--file",
            second.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit deal: {}", stderr(&out));
    // #412 Q4: the re-key is reported, not silent.
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["rekeyed"]["from"], PERSON, "{v}");
    assert_eq!(v["rekeyed"]["to"], PERSON2, "{v}");

    let after = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(
        after.contains(&format!("key_id: {PERSON2}/")),
        "the deal did not move to the new person's key: {after}"
    );
    assert!(
        !after.contains(&format!("key_id: {PERSON}/")),
        "the deal kept the old person's key: {after}"
    );

    // #389 Q4: the human-readable run reports the re-key as a notice line
    // on stdout, not only in the JSON.
    let back = write_file(h._tmp.path(), "deal-back.md", &deal(PERSON));
    let out = h
        .cmd(&[
            "record",
            "edit",
            DEAL,
            "--file",
            back.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit back: {}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("rekeyed {DEAL}: {PERSON2} -> {PERSON}")),
        "missing re-key notice: {}",
        stdout(&out)
    );
}

#[test]
fn record_edit_restamps_no_ai_on_the_envelope_header() {
    // #389 Q5: `no-ai` is re-derived from the edited content.
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    let before = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(before.contains("no-ai: false"), "{before}");

    let hidden = write_file(
        h._tmp.path(),
        "hidden.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            hidden.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit: {}", stderr(&out));

    let after = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(
        after.contains("no-ai: true"),
        "the outer header kept the old no-ai value: {after}"
    );
    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        !stdout(&out).contains("Bio."),
        "no-ai was not honoured after the edit: {}",
        stdout(&out)
    );
}

#[test]
fn record_edit_restamps_no_ai_when_a_with_person_turns_notes() {
    // #389 Q5 test gap: an edit that adds a notes-mode person to `with:`
    // re-stamps the envelope header, even though the primary person is
    // still visible — `with:` inherits into the stamp for interactions.
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client: {}", stderr(&out));

    const IXN: &str = "i-01J9Z3K4QM0000000000000000";
    for (id, name, extra) in [
        (PERSON, "Ada Example", ""),
        (PERSON2, "Bea Demo", "no-ai: notes\n"),
    ] {
        let input = write_file(
            h._tmp.path(),
            &format!("{id}.md"),
            &format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n{extra}---\n\nBio.\n"),
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
        assert!(out.status.success(), "add {id}: {}", stderr(&out));
    }

    let ixn = |extra: &str| {
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: Group dinner\ndate: 2026-10-06\nperson: {PERSON}\n{extra}---\n\nFake group dinner.\n"
        )
    };
    let first = write_file(h._tmp.path(), "ixn.md", &ixn(""));
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            first.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add ixn: {}", stderr(&out));

    let path = h.vault.join(format!("interactions/{IXN}/interaction.md"));
    let before = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(before.contains("no-ai: false"), "{before}");

    let second = write_file(
        h._tmp.path(),
        "ixn2.md",
        &ixn(&format!("with: [{PERSON2}]\n")),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            IXN,
            "--file",
            second.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit ixn: {}", stderr(&out));

    let after = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(
        after.contains("no-ai: true"),
        "the stamp did not pick up the notes-mode `with:` person: {after}"
    );
    assert!(
        after.contains(&format!("key_id: {PERSON}/")),
        "`with:` changed the routing key: {after}"
    );
}

#[test]
fn record_edit_rewrites_under_the_current_epoch() {
    // #389 Q3: an edit re-encrypts under the current key epoch.
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    let before = envelope_epoch(&String::from_utf8(std::fs::read(&path).unwrap()).unwrap());

    let out = h
        .cmd(&["keys", "rotate", PERSON, "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "rotate: {}", stderr(&out));

    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Renamed", "New bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit: {}", stderr(&out));

    let after = envelope_epoch(&String::from_utf8(std::fs::read(&path).unwrap()).unwrap());
    assert!(
        after > before,
        "the edit did not move the record to the current epoch ({before} -> {after})"
    );
}

/// The `no-ai` line of a record file's plaintext outer header.
fn outer_label(bytes: &str) -> String {
    bytes
        .lines()
        .find(|l| l.starts_with("no-ai:"))
        .unwrap_or("(none)")
        .to_owned()
}

#[test]
fn person_no_ai_edit_restamps_children_in_the_same_commit() {
    // #410 (a): tighten. A note and an interaction written while the
    // person is visible carry `no-ai: false` headers; editing the person
    // to `no-ai: true` re-stamps both in the same commit, and the read
    // path takes the keyless hidden path for them afterwards.
    let h = Harness::new();
    h.keyed(PERSON);
    let p = write_file(
        h._tmp.path(),
        "p.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "add person: {}", stderr(&out));

    let note_body = write_file(
        h._tmp.path(),
        "note.md",
        "A private session reflection for the record.\n",
    );
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
    assert!(out.status.success(), "add note: {}", stderr(&out));
    let note_path = h
        .vault
        .join(format!("people/{PERSON}/notes"))
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "md"))
        .expect("the note file exists");
    let note_rel = format!(
        "people/{PERSON}/notes/{}",
        note_path.file_name().unwrap().to_str().unwrap()
    );

    const IXN: &str = "i-01J9Z3K4QN0000000000000000";
    let ixn = write_file(
        h._tmp.path(),
        "ixn.md",
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: \"Session one\"\ndate: 2026-10-01\nperson: {PERSON}\n---\n\nInteraction body.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            ixn.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add interaction: {}", stderr(&out));
    let ixn_path = h.vault.join(format!("interactions/{IXN}/interaction.md"));

    assert_eq!(
        outer_label(&String::from_utf8(std::fs::read(&note_path).unwrap()).unwrap()),
        "no-ai: false"
    );
    assert_eq!(
        outer_label(&String::from_utf8(std::fs::read(&ixn_path).unwrap()).unwrap()),
        "no-ai: false"
    );

    // The person goes fully hidden.
    let hidden = write_file(
        h._tmp.path(),
        "hidden.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nBio.\n"
        ),
    );
    let commits_before = commit_count(&h);
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            hidden.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "hide person: {}", stderr(&out));
    // The person edit and both children landed as one commit.
    assert_eq!(
        commit_count(&h),
        commits_before + 1,
        "the re-stamp split into more than one commit"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let files: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    let person_rel = format!("people/{PERSON}/profile.md");
    assert!(
        files.contains(&person_rel.as_str()),
        "the person file is in the commit: {files:?}"
    );
    assert!(
        files.contains(&note_rel.as_str()),
        "the note was not re-stamped in the same commit: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains(IXN)),
        "the interaction was not re-stamped in the same commit: {files:?}"
    );

    let note_after = String::from_utf8(std::fs::read(&note_path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&note_after),
        "no-ai: true",
        "the note header was not re-stamped: {note_after}"
    );
    let ixn_after = String::from_utf8(std::fs::read(&ixn_path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&ixn_after),
        "no-ai: true",
        "the interaction header was not re-stamped: {ixn_after}"
    );

    // The read path now takes the keyless hidden path for the children.
    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "context: {}", stderr(&out));
    assert!(
        !stdout(&out).contains("A private session reflection"),
        "the hidden note still leaks through context: {}",
        stdout(&out)
    );
    assert!(
        !stdout(&out).contains("Interaction body."),
        "the hidden interaction still leaks through context: {}",
        stdout(&out)
    );
}

#[test]
fn person_no_ai_loosening_unhides_children_headers() {
    // #410 (b): loosen. A child written while the person is fully hidden
    // carries `no-ai: true`; the person becoming visible re-derives the
    // header so the child unwraps again instead of failing safe forever.
    let h = Harness::new();
    h.keyed(PERSON);
    let p = write_file(
        h._tmp.path(),
        "p.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "add person: {}", stderr(&out));

    let note_body = write_file(
        h._tmp.path(),
        "note.md",
        "A private session reflection for the record.\n",
    );
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
    assert!(out.status.success(), "add note: {}", stderr(&out));
    let note_path = h
        .vault
        .join(format!("people/{PERSON}/notes"))
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "md"))
        .expect("the note file exists");
    assert_eq!(
        outer_label(&String::from_utf8(std::fs::read(&note_path).unwrap()).unwrap()),
        "no-ai: true",
        "the note should start hidden under a hidden person"
    );

    // The person becomes visible again.
    let visible = write_file(
        h._tmp.path(),
        "visible.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            visible.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "reveal person: {}", stderr(&out));

    let after = String::from_utf8(std::fs::read(&note_path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&after),
        "no-ai: false",
        "the loosened person did not unwrap the note's header: {after}"
    );
    let out = h
        .cmd(&["context", PERSON, "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "context: {}", stderr(&out));
    assert!(
        stdout(&out).contains("A private session reflection"),
        "the note did not become visible again: {}",
        stdout(&out)
    );
}

#[test]
fn person_no_ai_edit_refuses_when_a_child_is_unreadable() {
    // #410 (c): a child this device cannot read might reference the
    // person, so the edit refuses the whole re-stamp — naming the file —
    // and commits nothing.
    let h = Harness::new();
    h.keyed(PERSON);
    let p = write_file(
        h._tmp.path(),
        "p.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "add person: {}", stderr(&out));
    let note_body = write_file(
        h._tmp.path(),
        "note.md",
        "A private session reflection for the record.\n",
    );
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
    assert!(out.status.success(), "add note: {}", stderr(&out));
    let note_path = h
        .vault
        .join(format!("people/{PERSON}/notes"))
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "md"))
        .expect("the note file exists");
    tamper_envelope_body(&note_path);
    let tampered = std::fs::read(&note_path).unwrap();
    let commits_before = commit_count(&h);

    let hidden = write_file(
        h._tmp.path(),
        "hidden.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            hidden.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unreadable child must refuse the edit"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(note_path.file_name().unwrap().to_str().unwrap()),
        "the refusal must name the unreadable child: {v}"
    );
    assert_eq!(
        std::fs::read(&note_path).unwrap(),
        tampered,
        "the unreadable child was rewritten despite the refusal"
    );
    assert_eq!(
        commit_count(&h),
        commits_before,
        "the refused edit must not commit"
    );
}

#[test]
fn person_no_ai_refusal_names_only_record_files() {
    // #424: the unreadable list holds record files only. A load finding
    // on a non-record file (here a bad `[checks].as_of` in
    // `confidant.toml`) says nothing about who references the person, so
    // it stays out of the refusal even while an unreadable child refuses
    // the edit.
    let h = Harness::new();
    h.keyed(PERSON);
    let p = write_file(
        h._tmp.path(),
        "p.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "add person: {}", stderr(&out));

    let note_body = write_file(
        h._tmp.path(),
        "note.md",
        "A private session reflection for the record.\n",
    );
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
    assert!(out.status.success(), "add note: {}", stderr(&out));
    let note_path = h
        .vault
        .join(format!("people/{PERSON}/notes"))
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "md"))
        .expect("the note file exists");
    tamper_envelope_body(&note_path);
    let tampered = std::fs::read(&note_path).unwrap();

    // A non-record load finding, added after the writes above so the
    // writes themselves are not blocked by `check`.
    let config = std::fs::read_to_string(h.vault.join("confidant.toml")).unwrap();
    std::fs::write(
        h.vault.join("confidant.toml"),
        format!("{config}\n[checks]\nas_of = \"not-a-date\"\n"),
    )
    .unwrap();

    let commits_before = commit_count(&h);
    let hidden = write_file(
        h._tmp.path(),
        "hidden.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            hidden.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unreadable child must refuse the edit"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(note_path.file_name().unwrap().to_str().unwrap()),
        "the refusal must name the unreadable child: {v}"
    );
    assert!(
        !message.contains("confidant.toml"),
        "the refusal must not name non-record files: {v}"
    );
    assert_eq!(
        std::fs::read(&note_path).unwrap(),
        tampered,
        "the unreadable child was rewritten despite the refusal"
    );
    assert_eq!(
        commit_count(&h),
        commits_before,
        "the refused edit must not commit"
    );
}

#[test]
fn person_no_ai_notes_mode_restamps_a_with_only_child() {
    // #424: a child that references the person only through `with:` —
    // the field class a `notes` mode carries through — is re-stamped too,
    // not just `person:` references.
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h
        .cmd(&["keys", "init-client", PERSON2, "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "init-client: {}", stderr(&out));

    // Both people exist: the interaction routes to PERSON2's key, and
    // its `with:` names PERSON.
    for (id, name) in [(PERSON, "Ada Example"), (PERSON2, "Basil Example")] {
        let p = write_file(h._tmp.path(), "person.md", &person_md(id, name, "Bio."));
        let out = h
            .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "add person {id}: {}", stderr(&out));
    }

    const IXN: &str = "i-01J9Z3K4QM0000000000000000";
    let ixn = write_file(
        h._tmp.path(),
        "ixn.md",
        &format!(
            "---\nid: {IXN}\ntype: interaction\nname: \"Joint session\"\ndate: 2026-10-01\nperson: {PERSON2}\nwith: [{PERSON}]\n---\n\nInteraction body.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            ixn.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add interaction: {}", stderr(&out));
    let ixn_path = h.vault.join(format!("interactions/{IXN}/interaction.md"));
    assert_eq!(
        outer_label(&String::from_utf8(std::fs::read(&ixn_path).unwrap()).unwrap()),
        "no-ai: false",
        "the interaction should start visible"
    );

    // PERSON goes to notes mode; the interaction hides through `with:`.
    let notes = write_file(
        h._tmp.path(),
        "notes.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: notes\n---\n\nBio.\n"
        ),
    );
    let commits_before = commit_count(&h);
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            notes.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "notes person: {}", stderr(&out));
    assert_eq!(
        commit_count(&h),
        commits_before + 1,
        "the re-stamp split into more than one commit"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().contains(IXN)),
        "the with:-only child was not re-stamped in the same commit: {v}"
    );

    let after = String::from_utf8(std::fs::read(&ixn_path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&after),
        "no-ai: true",
        "the with:-only child's header did not move: {after}"
    );
}

#[test]
fn person_no_ai_edit_keeps_unchanged_child_ciphertext_and_reports_only_rewrites() {
    // #424/#425: a referencing child whose header does not move keeps its
    // ciphertext byte for byte, and the JSON `files` lists only the paths
    // actually rewritten — the reused child is not named, so the list
    // matches the commit diff.
    let h = Harness::new();
    h.keyed(PERSON);
    let p = write_file(
        h._tmp.path(),
        "p.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "add person: {}", stderr(&out));

    let note_body = write_file(
        h._tmp.path(),
        "note.md",
        "A private session reflection for the record.\n",
    );
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
    assert!(out.status.success(), "add note: {}", stderr(&out));
    let note_path = h
        .vault
        .join(format!("people/{PERSON}/notes"))
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "md"))
        .expect("the note file exists");
    let note_rel = format!(
        "people/{PERSON}/notes/{}",
        note_path.file_name().unwrap().to_str().unwrap()
    );

    // A deal is a referencing child whose header never moves when the
    // person tightens to `notes`: only notes and interactions inherit it.
    const DEAL: &str = "d-01J9Z3K4QJ0000000000000000";
    let deal = write_file(
        h._tmp.path(),
        "deal.md",
        &format!(
            "---\nid: {DEAL}\ntype: deal\nname: \"Deal one\"\nperson: {PERSON}\n---\n\nDeal body.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            deal.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add deal: {}", stderr(&out));
    let deal_path = h.vault.join(format!("deals/{DEAL}/deal.md"));
    let deal_before = std::fs::read(&deal_path).unwrap();

    // Tighten to notes: the note's header moves, the deal's does not.
    let notes = write_file(
        h._tmp.path(),
        "notes.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: notes\n---\n\nBio.\n"
        ),
    );
    let commits_before = commit_count(&h);
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            notes.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "notes person: {}", stderr(&out));
    assert_eq!(
        commit_count(&h),
        commits_before + 1,
        "the re-stamp split into more than one commit"
    );

    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let files: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    let person_rel = format!("people/{PERSON}/profile.md");
    assert_eq!(
        files,
        vec![person_rel.as_str(), note_rel.as_str()],
        "`files` must name exactly the rewritten paths: {files:?}"
    );
    assert_eq!(
        std::fs::read(&deal_path).unwrap(),
        deal_before,
        "the unchanged child's ciphertext was not kept byte for byte"
    );

    let note_after = String::from_utf8(std::fs::read(&note_path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&note_after),
        "no-ai: true",
        "the note header was not re-stamped: {note_after}"
    );
}

#[test]
fn resaving_a_child_re_stamps_a_moved_no_ai_header() {
    // #406: a header can move out from under a record whose body did not
    // change — e.g. restored from history, or written by an older CLI
    // before #410 made the person edit re-stamp its children. Re-saving
    // the same body must move the header rather than report `unchanged`.
    let h = Harness::new();
    h.keyed(PERSON);
    let p = write_file(
        h._tmp.path(),
        "p.md",
        &person_md(PERSON, "Ada Example", "Bio."),
    );
    let out = h
        .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "add person: {}", stderr(&out));

    const IXN: &str = "i-01J9Z3K4QK0000000000000000";
    let ixn_body = format!(
        "---\nid: {IXN}\ntype: interaction\nname: \"Session one\"\ndate: 2026-10-01\nperson: {PERSON}\n---\n\nNotes about the session.\n"
    );
    // The same file is used for the add and the later re-save, so the
    // canonical body is identical both times.
    let ixn = write_file(h._tmp.path(), "ixn.md", &ixn_body);
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            ixn.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add interaction: {}", stderr(&out));

    let path = h.vault.join(format!("interactions/{IXN}/interaction.md"));
    let before = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(outer_label(&before), "no-ai: false", "{before}");

    // Manufacture the stale header: the person is now notes-hidden, but
    // this envelope's outer header still says the record is visible.
    let hidden = write_file(
        h._tmp.path(),
        "hidden.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: notes\n---\n\nBio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            hidden.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "hide person: {}", stderr(&out));
    // #410: the person edit itself re-stamped the interaction.
    let restamped = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&restamped),
        "no-ai: true",
        "the person edit did not re-stamp its child in the same commit: {restamped}"
    );
    // Now make the header stale the way it actually goes stale after
    // #410: restore the pre-edit envelope from git history, which still
    // carries the old header with the identical inner body. The outer
    // header is authenticated, so this cannot be simulated by editing
    // bytes in place.
    let pre_edit = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD~1"])
        .output()
        .unwrap();
    let pre_edit = String::from_utf8_lossy(&pre_edit.stdout).trim().to_owned();
    git(
        &h.vault,
        &[
            "checkout",
            &pre_edit,
            "--",
            &format!("interactions/{IXN}/interaction.md"),
        ],
    );
    let stale = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(outer_label(&stale), "no-ai: false", "{stale}");

    // Re-save the interaction with the body it already has.
    let out = h
        .cmd(&[
            "record",
            "edit",
            IXN,
            "--file",
            ixn.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "re-save: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_ne!(
        v["unchanged"],
        serde_json::json!(true),
        "a stale header must not be reported as unchanged: {v}"
    );

    let after = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        outer_label(&after),
        "no-ai: true",
        "the header was not re-stamped: {after}"
    );
}

/// Flip one base64 character in an envelope's body: still parseable, so it
/// reaches the AEAD and fails authentication.
fn tamper_envelope_body(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap();
    let body_start = text.rfind("---\n").unwrap() + 4;
    let mut bytes = text.into_bytes();
    let i = (body_start..bytes.len())
        .find(|&i| bytes[i] != b'\n')
        .expect("the envelope has a body");
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    std::fs::write(path, &bytes).unwrap();
}

#[test]
fn record_edit_refuses_a_tampered_envelope() {
    // #412 Q4: only the missing-key case was covered; a tampered envelope
    // takes the same fail-closed path and must not be rewritten.
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    tamper_envelope_body(&path);
    let tampered = std::fs::read(&path).unwrap();

    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Renamed", "New bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a tampered envelope must be refused");
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot decrypt"),
        "{v}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        tampered,
        "the tampered file was rewritten"
    );
}

#[test]
fn record_edit_refuses_a_record_with_conflict_markers() {
    // #412 Q6: the guard runs before the write layer's conflict check, so it
    // must name the conflict rather than reporting a key problem.
    let h = Harness::new();
    h.keyed(PERSON);
    let path = add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    std::fs::write(
        &path,
        format!(
            "---\nid: {PERSON}\ntype: person\n<<<<<<< HEAD\nno-ai: false\nenc: xchacha20poly1305\n\
             =======\nno-ai: false\nenc: xchacha20poly1305\n>>>>>>> other\n---\nAQID\n"
        ),
    )
    .unwrap();

    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(PERSON, "Ada Renamed", "New bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a conflicted record must be refused");
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("conflict"), "{v}");
    assert!(
        !message.contains("cannot decrypt"),
        "the conflict was misreported as a key problem: {v}"
    );
}

#[test]
fn record_edit_refuses_when_the_stored_file_holds_another_record() {
    // #412 Q6: a file whose header names a different record is a broken
    // vault, not a key problem — say which.
    let h = Harness::new();
    h.keyed(PERSON);
    let other_id = PERSON2;
    let out = h.init_client(other_id);
    assert!(out.status.success(), "init-client: {}", stderr(&out));
    for (who, name) in [(PERSON, "Ada"), (PERSON2, "Bea")] {
        let p = write_file(
            h._tmp.path(),
            &format!("{who}.md"),
            &person_md(who, name, "bio"),
        );
        let out = h
            .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "add {who}: {}", stderr(&out));
    }
    // Put PERSON's envelope where PERSON2's record belongs.
    let a = h.vault.join(format!("people/{PERSON}/profile.md"));
    let b = h.vault.join(format!("people/{other_id}/profile.md"));
    let b_path = b.clone();
    std::fs::copy(&a, &b).unwrap();
    let copied = std::fs::read(&b_path).unwrap();

    let edited = write_file(
        h._tmp.path(),
        "edited.md",
        &person_md(other_id, "Bea Renamed", "New bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            other_id,
            "--file",
            edited.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a mismatched record must be refused");
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(PERSON) && message.contains(other_id),
        "the message should name both records: {v}"
    );
    assert!(
        v["error"]["fix"].as_str().unwrap().contains("git history"),
        "the fix must not tell the operator to delete the other record's only copy: {v}"
    );
    assert_eq!(
        std::fs::read(&b_path).unwrap(),
        copied,
        "the file was rewritten despite the refusal"
    );
}

#[test]
fn dropping_the_last_notes_mode_reference_stamps_visible_again() {
    // #412 Q5: the stamp follows the record's references in both directions.
    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client: {}", stderr(&out));
    // PERSON is notes-hidden; PERSON2 is visible.
    for (who, body) in [
        (
            PERSON,
            format!(
                "---\nid: {PERSON}\ntype: person\nname: \"Ada Hidden\"\nno-ai: notes\n---\n\nbio\n"
            ),
        ),
        (PERSON2, person_md(PERSON2, "Bea Visible", "bio")),
    ] {
        let p = write_file(h._tmp.path(), &format!("{who}.md"), &body);
        let out = h
            .cmd(&["record", "add", "--file", p.to_str().unwrap(), "--no-input"])
            .output()
            .unwrap();
        assert!(out.status.success(), "add {who}: {}", stderr(&out));
    }

    const IXN: &str = "i-01J9Z3K4QM0000000000000000";
    let ixn = |person: &str| {
        format!(
            "---\nid: {IXN}\ntype: interaction\nname: \"Session one\"\ndate: 2026-10-01\nperson: {person}\n---\n\nNotes about the session.\n"
        )
    };
    let first = write_file(h._tmp.path(), "ixn.md", &ixn(PERSON));
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            first.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add interaction: {}", stderr(&out));

    let path = h.vault.join(format!("interactions/{IXN}/interaction.md"));
    let before = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(outer_label(&before), "no-ai: true", "{before}");

    // Re-point it at the visible person: its only reference is now visible.
    let second = write_file(h._tmp.path(), "ixn2.md", &ixn(PERSON2));
    let out = h
        .cmd(&[
            "record",
            "edit",
            IXN,
            "--file",
            second.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();

    let after = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(outer_label(&after), "no-ai: false", "{after}");
    assert_eq!(v["rekeyed"]["from"], PERSON, "{v}");
    assert_eq!(v["rekeyed"]["to"], PERSON2, "{v}");
}

/// #452: two devices edit the same encrypted record, the merge conflicts,
/// and `check` reports the encrypted-record message with the record id.
#[test]
fn two_device_edit_conflict_is_reported_by_check() {
    let h = Harness::new();
    h.keyed(PERSON);
    // `record add` commits itself; no manual git commit needed.
    add_person(&h, &person_md(PERSON, "Ada Example", "First bio."));

    // Device A edits on a branch (`record edit` commits itself).
    git(&h.vault, &["checkout", "-qb", "device-a"]);
    let edited_a = write_file(
        h._tmp.path(),
        "edited_a.md",
        &person_md(PERSON, "Ada Example", "Bio from device A."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_a.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record edit (device A) failed: {}",
        stderr(&out)
    );

    // Device B edits differently on master.
    git(&h.vault, &["checkout", "-q", "master"]);
    let edited_b = write_file(
        h._tmp.path(),
        "edited_b.md",
        &person_md(PERSON, "Ada Example", "Bio from device B."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_b.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record edit (device B) failed: {}",
        stderr(&out)
    );

    // Merge → conflict (both sides rewrote the envelope).
    let st = Command::new("git")
        .current_dir(&h.vault)
        .args(["merge", "--no-edit", "device-a"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(!st.success(), "expected the merge to conflict");

    let out = h.cmd(&["check", "--json", "--no-input"]).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "check should exit 1: {}",
        stderr(&out)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"].as_str() == Some("E_MERGE_CONFLICT"))
        .collect();
    assert_eq!(
        findings.len(),
        1,
        "expected one E_MERGE_CONFLICT: {}",
        stdout(&out)
    );
    let f = findings[0];
    assert_eq!(
        f["message"].as_str(),
        Some("encrypted record has two versions after a merge conflict"),
        "{}",
        stdout(&out)
    );
    assert_eq!(f["id"].as_str(), Some(PERSON), "{}", stdout(&out));
    assert!(
        f["fix"]
            .as_str()
            .unwrap_or("")
            .contains(&format!("confidant record resolve {PERSON} --show")),
        "fix should point at record resolve: {}",
        stdout(&out)
    );
}

/// #453: build a vault where PERSON's record has a real two-device merge
/// conflict. Device A and device B each `record edit` the same person with
/// different sentinel bios; the merge conflicts. Returns the harness with
/// the vault left mid-conflict.
fn conflicted_harness() -> Harness {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "SENTINEL-BASE-bio."));

    // Device A edits on a branch (`record edit` commits itself).
    git(&h.vault, &["checkout", "-qb", "device-a"]);
    let edited_a = write_file(
        h._tmp.path(),
        "edited_a.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-A-bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_a.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record edit (device A) failed: {}",
        stderr(&out)
    );

    // Device B edits differently on master.
    git(&h.vault, &["checkout", "-q", "master"]);
    let edited_b = write_file(
        h._tmp.path(),
        "edited_b.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-B-bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_b.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record edit (device B) failed: {}",
        stderr(&out)
    );

    // Merge → conflict (both sides rewrote the envelope).
    let st = Command::new("git")
        .current_dir(&h.vault)
        .args(["merge", "--no-edit", "device-a"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(!st.success(), "expected the merge to conflict");
    h
}

/// #453: `--show` prints both decrypted sides in full and changes nothing.
#[test]
fn resolve_show_prints_both_sides_and_changes_nothing() {
    let h = conflicted_harness();
    let before_status = {
        let out = Command::new("git")
            .current_dir(&h.vault)
            .args(["status", "--porcelain"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let before_walk = walk(&h.vault);

    let out = h
        .cmd(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --show failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("== ours ("), "missing ours header: {text}");
    assert!(
        text.contains("SENTINEL-B-bio"),
        "missing ours body (HEAD=device B): {text}"
    );
    assert!(
        text.contains("== theirs ("),
        "missing theirs header: {text}"
    );
    assert!(
        text.contains("SENTINEL-A-bio"),
        "missing theirs body (device-a): {text}"
    );

    // Nothing changed: no files created, no .confidant/conflicts/.
    let after_status = {
        let out = Command::new("git")
            .current_dir(&h.vault)
            .args(["status", "--porcelain"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert_eq!(before_status, after_status, "git status changed");
    assert_eq!(before_walk, walk(&h.vault), "vault tree changed");
    assert!(
        !h.vault.join(".confidant/conflicts").exists(),
        ".confidant/conflicts/ must not be created"
    );
}

/// #453: `--json` shape has both sides with labels and the vault path.
#[test]
fn resolve_show_json_shape_and_vault_path() {
    let h = conflicted_harness();
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--show",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --show --json failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["id"].as_str(), Some(PERSON));
    assert!(
        v["vault"].as_str().unwrap_or("").ends_with("vault"),
        "vault path missing: {v}"
    );
    assert!(
        v["path"].as_str().unwrap_or("").contains(PERSON),
        "record path missing: {v}"
    );
    for side in ["ours", "theirs"] {
        assert!(
            v[side]["label"].as_str().is_some_and(|l| !l.is_empty()),
            "{side} label missing: {v}"
        );
        assert!(
            v[side]["text"].as_str().is_some_and(|t| !t.is_empty()),
            "{side} text missing: {v}"
        );
    }
    assert!(
        v["ours"]["text"]
            .as_str()
            .unwrap()
            .contains("SENTINEL-B-bio"),
        "ours text wrong (HEAD=device B): {v}"
    );
    assert!(
        v["theirs"]["text"]
            .as_str()
            .unwrap()
            .contains("SENTINEL-A-bio"),
        "theirs text wrong (device-a): {v}"
    );
}

/// #453 (CD2): exactly one action flag is required; bare or doubled
/// invocations are usage errors (exit 2).
#[test]
fn resolve_requires_exactly_one_action() {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));

    let out = h
        .cmd(&["record", "resolve", PERSON, "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "bare resolve must exit 2");

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--show",
            "--take",
            "ours",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "--show --take must exit 2: {}",
        stderr(&out)
    );

    // --take is implemented (#454): on a non-conflicted record it fails
    // with "no merge conflict", not "not implemented yet".
    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--take on a clean record should fail"
    );
    let text = stderr(&out) + &stdout(&out);
    assert!(text.contains("no merge conflict"), "wrong error: {text}");
    assert!(
        !text.contains("not implemented yet"),
        "--take is implemented: {text}"
    );
}

/// #453: a non-conflicted record errors without leaking content.
#[test]
fn resolve_show_non_conflicted_record_errors_without_content() {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "SENTINEL-PLAIN-bio."));

    let out = h
        .cmd(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "must fail on a clean record");
    let err = stderr(&out);
    assert!(
        err.contains("has no merge conflict"),
        "wrong message: {err}"
    );
    assert!(
        !err.contains("SENTINEL-PLAIN-bio"),
        "plaintext leaked into stderr: {err}"
    );
    assert!(
        !stdout(&out).contains("SENTINEL-PLAIN-bio"),
        "plaintext leaked into stdout"
    );
}

/// #453: a side whose envelope names a different record errors, naming the
/// side and not the content.
#[test]
fn resolve_show_id_mismatch_in_a_side_errors() {
    let h = conflicted_harness();
    let rel = format!("people/{PERSON}/profile.md");
    let raw = std::fs::read(h.vault.join(&rel)).unwrap();
    let text = String::from_utf8(raw).unwrap();
    // Swap the envelope id in the ours side (first header block).
    let tampered = text.replacen(&format!("id: {PERSON}"), &format!("id: {PERSON2}"), 1);
    assert_ne!(tampered, text, "expected to find the id header");
    std::fs::write(h.vault.join(&rel), tampered).unwrap();

    let out = h
        .cmd(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "must fail on id mismatch");
    let err = stderr(&out);
    assert!(
        err.contains("ours") && err.contains("different record"),
        "must name the side: {err}"
    );
    assert!(
        !err.contains("SENTINEL-A-bio") && !err.contains("SENTINEL-B-bio"),
        "plaintext leaked: {err}"
    );
}

/// #453 (CD7): with no device key, the failure names the side and prints
/// no plaintext of either side.
#[test]
fn resolve_show_unreadable_side_names_the_side() {
    let h = conflicted_harness();
    let out = h
        .cmd_no_device_key(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "must fail without a device key");
    let err = stderr(&out);
    assert!(
        err.contains("ours") || err.contains("theirs"),
        "must name the failing side: {err}"
    );
    assert!(
        !err.contains("SENTINEL-A-bio") && !err.contains("SENTINEL-B-bio"),
        "plaintext leaked into stderr: {err}"
    );
    assert!(
        !stdout(&out).contains("SENTINEL-A-bio") && !stdout(&out).contains("SENTINEL-B-bio"),
        "plaintext leaked into stdout"
    );
}

/// #453: a `no-ai: true` record is shown in full to the operator, while
/// `find --json` still hides it from agents.
#[test]
fn resolve_show_no_ai_record_shown_to_operator_only() {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(
        &h,
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nSENTINEL-NOAI-bio.\n"
        ),
    );

    // Conflict it like the other tests.
    git(&h.vault, &["checkout", "-qb", "device-a"]);
    let edited_a = write_file(
        h._tmp.path(),
        "edited_a.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nSENTINEL-NOAI-OURS-bio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_a.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit A failed: {}", stderr(&out));
    git(&h.vault, &["checkout", "-q", "master"]);
    let edited_b = write_file(
        h._tmp.path(),
        "edited_b.md",
        &format!(
            "---\nid: {PERSON}\ntype: person\nname: \"Ada Example\"\nno-ai: true\n---\n\nSENTINEL-NOAI-THEIRS-bio.\n"
        ),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_b.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "edit B failed: {}", stderr(&out));
    let st = Command::new("git")
        .current_dir(&h.vault)
        .args(["merge", "--no-edit", "device-a"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(!st.success(), "expected the merge to conflict");

    // The operator sees both sides in full.
    let out = h
        .cmd(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --show failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("SENTINEL-NOAI-OURS-bio"),
        "ours hidden: {text}"
    );
    assert!(
        text.contains("SENTINEL-NOAI-THEIRS-bio"),
        "theirs hidden: {text}"
    );

    // Agents still cannot see it via find.
    let out = h
        .cmd(&["find", "Ada", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "find failed: {}", stderr(&out));
    assert!(
        !stdout(&out).contains("SENTINEL-NOAI"),
        "no-ai content leaked to find: {}",
        stdout(&out)
    );
}

/// #453: nothing decrypted ever reaches stderr — success and error paths.
#[test]
fn resolve_show_stderr_has_no_sentinels() {
    let h = conflicted_harness();

    // Success path.
    let out = h
        .cmd(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        !stderr(&out).contains("SENTINEL-"),
        "sentinel in stderr on success: {}",
        stderr(&out)
    );

    // Error paths.
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--show",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        !stderr(&out).contains("SENTINEL-"),
        "sentinel in stderr on json success: {}",
        stderr(&out)
    );

    // Bad id.
    let out = h
        .cmd(&[
            "record",
            "resolve",
            "p-01ZZZZZZZZZZZZZZZZZZZZZZ",
            "--show",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !stderr(&out).contains("SENTINEL-"),
        "sentinel in stderr on bad id: {}",
        stderr(&out)
    );
}

// =====================================================================
// #454: `record resolve --take ours|theirs`
// =====================================================================

/// #454: build a vault where PERSON's record conflicts via `git rebase`
/// (instead of `git merge`). Returns the harness with the vault mid-rebase.
fn rebased_harness() -> Harness {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "SENTINEL-BASE-bio."));

    // Device A edits on a branch (`record edit` commits itself).
    git(&h.vault, &["checkout", "-qb", "device-a"]);
    let edited_a = write_file(
        h._tmp.path(),
        "edited_a.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-A-bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_a.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record edit (device A) failed: {}",
        stderr(&out)
    );

    // Master edits differently.
    git(&h.vault, &["checkout", "-q", "master"]);
    let edited_b = write_file(
        h._tmp.path(),
        "edited_b.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-B-bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            PERSON,
            "--file",
            edited_b.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record edit (master) failed: {}",
        stderr(&out)
    );

    // Rebase device-a onto master → conflict (ours = master, theirs = device-a).
    git(&h.vault, &["checkout", "-q", "device-a"]);
    let st = Command::new("git")
        .current_dir(&h.vault)
        .args(["rebase", "master"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(!st.success(), "expected the rebase to conflict");
    h
}

/// Vault-relative path of PERSON's record file.
fn person_rel() -> String {
    format!("people/{PERSON}/profile.md")
}

/// `git show <rev>:<path>` bytes.
fn git_show(vault: &Path, rev: &str, path: &str) -> Vec<u8> {
    Command::new("git")
        .current_dir(vault)
        .args(["show", &format!("{rev}:{path}")])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .stdout
}

/// Staged paths (`git diff --cached --name-only`).
fn staged_paths(vault: &Path) -> Vec<String> {
    let out = Command::new("git")
        .current_dir(vault)
        .args(["diff", "--cached", "--name-only"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.to_owned())
        .collect()
}

/// #465: `--dry-run --take ours` verifies both sides but changes nothing.
#[test]
fn take_dry_run_changes_nothing() {
    let h = conflicted_harness();
    let rel = person_rel();
    let conflicted_bytes = std::fs::read(h.vault.join(&rel)).unwrap();
    // In a conflicted merge `git diff --cached --name-only` already shows
    // the unmerged path, so the acceptance is: the dry run changes the
    // staged set not at all (it must add no staging of its own).
    let before_staged = staged_paths(&h.vault);

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--take",
            "ours",
            "--dry-run",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours --dry-run failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["command"], "record-resolve");
    assert_eq!(v["dry_run"], true, "expected a dry run: {v}");
    assert_eq!(v["action"], "take");
    assert_eq!(v["side"], "ours");
    assert_eq!(v["staged"], false, "dry run must not stage: {v}");

    // The acceptance: file bytes are still the conflicted bytes and the
    // index is untouched.
    assert_eq!(
        std::fs::read(h.vault.join(&rel)).unwrap(),
        conflicted_bytes,
        "--dry-run --take ours rewrote the file"
    );
    assert_eq!(
        staged_paths(&h.vault),
        before_staged,
        "--dry-run --take ours staged something"
    );
    // The conflict stays as it was (a dry run resolves nothing); the
    // byte-for-byte file check above already shows that.

    // Human mode reports the same no-op.
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--take",
            "ours",
            "--dry-run",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "text dry-run failed: {}",
        stderr(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("dry run"),
        "expected a dry run notice, got: {stdout}"
    );
    assert_eq!(
        std::fs::read(h.vault.join(&rel)).unwrap(),
        conflicted_bytes,
        "--dry-run --take ours rewrote the file (text mode)"
    );
}

/// #465: `--dry-run --merged-file` reads and validates the merged file
/// but re-encrypts nothing.
#[test]
fn merged_file_dry_run_changes_nothing() {
    let h = conflicted_harness();
    let rel = person_rel();
    let conflicted_bytes = std::fs::read(h.vault.join(&rel)).unwrap();
    let before_staged = staged_paths(&h.vault);

    // A valid hand-merge, same shape as `merged_file_reencrypts_and_stages`,
    // so it would install if not for --dry-run.
    let merged = write_file(
        h._tmp.path(),
        "dried_merge.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            merged.to_str().unwrap(),
            "--dry-run",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --merged-file --dry-run failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "expected a dry run: {v}");
    assert_eq!(v["action"], "merged-file");
    assert_eq!(v["staged"], false, "dry run must not stage: {v}");
    assert!(
        v["merged_file"]
            .as_str()
            .unwrap()
            .ends_with("dried_merge.md"),
        "merged_file missing: {v}"
    );
    assert_eq!(
        std::fs::read(h.vault.join(&rel)).unwrap(),
        conflicted_bytes,
        "--dry-run --merged-file rewrote the file"
    );
    assert_eq!(
        staged_paths(&h.vault),
        before_staged,
        "--dry-run --merged-file staged something"
    );
}

/// #465: `--dry-run --edit` creates no scratch and installs nothing.
#[test]
fn edit_dry_run_changes_nothing() {
    let h = conflicted_harness();
    let rel = person_rel();
    let conflicted_bytes = std::fs::read(h.vault.join(&rel)).unwrap();
    let before_staged = staged_paths(&h.vault);

    // No editor is configured on purpose: the dry run must not need one,
    // because it never opens the editor.
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--edit",
            "--dry-run",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --edit --dry-run failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "expected a dry run: {v}");
    assert_eq!(v["action"], "edit");
    assert_eq!(v["staged"], false, "dry run must not stage: {v}");

    assert_eq!(
        std::fs::read(h.vault.join(&rel)).unwrap(),
        conflicted_bytes,
        "--dry-run --edit rewrote the file"
    );
    assert_eq!(
        staged_paths(&h.vault),
        before_staged,
        "--dry-run --edit staged something"
    );
    // No scratch left behind (#455 keeps scratch under .confidant/conflicts).
    assert!(
        !h.vault.join(".confidant").join("conflicts").exists(),
        "--dry-run --edit created scratch"
    );
}

/// #454: `--take ours` installs the ours bytes exactly and stages the file.
/// Ours is HEAD (device B's edit in the merge harness).
#[test]
fn take_ours_installs_ours_bytes_and_stages() {
    let h = conflicted_harness();
    let rel = person_rel();
    let ours_bytes = git_show(&h.vault, "HEAD", &rel);

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours failed: {}",
        stderr(&out)
    );

    assert_eq!(
        std::fs::read(h.vault.join(&rel)).unwrap(),
        ours_bytes,
        "installed bytes differ from the ours side"
    );
    // The conflict is resolved: no unmerged paths remain. (`git diff
    // --cached` is empty here because ours is byte-identical to HEAD, so
    // the unmerged-path check is the meaningful assertion.)
    assert_no_unmerged(&h.vault, &rel);
}

/// `git status --porcelain` shows no unmerged (`UU`) entry for `rel`.
fn assert_no_unmerged(vault: &Path, rel: &str) {
    let out = Command::new("git")
        .current_dir(vault)
        .args(["status", "--porcelain"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&out.stdout);
    assert!(
        !status
            .lines()
            .any(|l| l.starts_with("UU") && l.contains(rel)),
        "unmerged path remains: {status}"
    );
}

/// #454: `--take theirs` installs the theirs bytes exactly and stages the file.
/// Theirs is the device-a branch in the merge harness.
#[test]
fn take_theirs_installs_theirs_bytes_and_stages() {
    let h = conflicted_harness();
    let rel = person_rel();
    let theirs_bytes = git_show(&h.vault, "device-a", &rel);

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--take",
            "theirs",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take theirs failed: {}",
        stderr(&out)
    );

    assert_eq!(
        std::fs::read(h.vault.join(&rel)).unwrap(),
        theirs_bytes,
        "installed bytes differ from the theirs side"
    );
    assert!(
        staged_paths(&h.vault).iter().any(|p| p == &rel),
        "path not staged"
    );
}

/// #454: after `--take`, `git commit` completes the merge and `check` is clean.
#[test]
fn take_then_merge_continue_makes_clean_vault() {
    let h = conflicted_harness();

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours failed: {}",
        stderr(&out)
    );

    git(&h.vault, &["commit", "--no-edit", "-q"]);

    let out = h.cmd(&["check", "--no-input"]).output().unwrap();
    assert!(
        out.status.success(),
        "check failed after merge: {}",
        stderr(&out)
    );
}

/// #454: `--take` never creates a commit (CD6: stage only).
#[test]
fn take_creates_no_commit() {
    let h = conflicted_harness();
    let head_before = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .stdout;

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours failed: {}",
        stderr(&out)
    );

    let head_after = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .stdout;
    assert_eq!(head_before, head_after, "take created a commit");
    // Sanity: the conflict was resolved (proves the take did something).
    assert_no_unmerged(&h.vault, &person_rel());
}

/// #454: during a rebase, the next-step hint is `git rebase --continue`.
#[test]
fn take_during_rebase_prints_rebase_continue() {
    let h = rebased_harness();

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("git rebase --continue"),
        "missing rebase hint: {text}"
    );
}

/// #454: `--take` refuses when a side cannot be decrypted here (CD7).
#[test]
fn take_refuses_when_other_side_unreadable() {
    let h = conflicted_harness();

    let out = h
        .cmd_no_device_key(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "take without a key should fail");
    let text = stderr(&out) + &stdout(&out);
    assert!(
        text.contains("ours") || text.contains("theirs"),
        "error should name the unreadable side: {text}"
    );
    // The conflicted file is untouched.
    let content = std::fs::read(h.vault.join(person_rel())).unwrap();
    assert!(
        String::from_utf8_lossy(&content).contains("<<<<<<<"),
        "conflicted file was modified"
    );
}

/// #454: `--take` on a record with no conflict is an error.
#[test]
fn take_refuses_non_conflicted_record() {
    let h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "SENTINEL-bio."));

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = stderr(&out) + &stdout(&out);
    assert!(text.contains("no merge conflict"), "wrong error: {text}");
}

/// #454: `--take` refuses when a side's envelope names a different record.
#[test]
fn take_refuses_envelope_with_wrong_id() {
    let h = Harness::new();
    h.keyed(PERSON);
    h.init_client(PERSON2);
    add_person(&h, &person_md(PERSON, "Ada Example", "SENTINEL-P1-bio."));
    let input2 = write_file(
        h._tmp.path(),
        "person2.md",
        &person_md(PERSON2, "Ada Example", "SENTINEL-P2-bio."),
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
    assert!(
        out.status.success(),
        "record add PERSON2 failed: {}",
        stderr(&out)
    );

    // Craft a conflicted file: ours names PERSON, theirs names PERSON2.
    let path1 = h.vault.join(format!("people/{PERSON}/profile.md"));
    let env1 = String::from_utf8_lossy(&std::fs::read(&path1).unwrap()).into_owned();
    let env2 = String::from_utf8_lossy(
        &std::fs::read(h.vault.join(format!("people/{PERSON2}/profile.md"))).unwrap(),
    )
    .into_owned();
    fn ensure_nl(mut s: String) -> String {
        if !s.ends_with('\n') {
            s.push('\n');
        }
        s
    }
    std::fs::write(
        &path1,
        format!(
            "<<<<<<< HEAD\n{}=======\n{}>>>>>>> branch\n",
            ensure_nl(env1),
            ensure_nl(env2),
        ),
    )
    .unwrap();

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "take with wrong-id side should fail");
    let text = stderr(&out) + &stdout(&out);
    assert!(
        text.contains("different record"),
        "wrong id not refused: {text}"
    );
}

/// #454: `--take` leaves no temp files behind.
#[test]
fn take_leaves_no_temp_files() {
    let h = conflicted_harness();

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours failed: {}",
        stderr(&out)
    );

    let temps: Vec<_> = walk(&h.vault)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".confidant-tmp-")
        })
        .collect();
    assert!(temps.is_empty(), "temp files left: {temps:?}");
}

/// #454: `--take` never prints decrypted content.
#[test]
fn take_does_not_print_plaintext() {
    let h = conflicted_harness();

    let out = h
        .cmd(&["record", "resolve", PERSON, "--take", "ours", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take ours failed: {}",
        stderr(&out)
    );
    let combined = stdout(&out) + &stderr(&out);
    assert!(
        !combined.contains("SENTINEL-"),
        "plaintext leaked: {combined}"
    );
}

/// #454: `--take --json` shape.
#[test]
fn take_json_shape() {
    let h = conflicted_harness();

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--take",
            "theirs",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --take --json failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["command"], "record-resolve");
    assert_eq!(v["action"], "take");
    assert_eq!(v["side"], "theirs");
    assert_eq!(v["staged"], true);
    assert_eq!(v["next"], "git merge --continue");
    assert!(
        v["path"].as_str().unwrap().contains(PERSON),
        "path missing: {v}"
    );
}
/// #455: `resolve --merged-file` re-encrypts the merged plaintext through
/// the `record edit` path, stages it (no commit), and the decrypted result
/// equals the canonical input.
#[test]
fn merged_file_reencrypts_and_stages() {
    let h = conflicted_harness();
    let merged = write_file(
        h._tmp.path(),
        "merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            merged.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --merged-file failed: {}",
        stderr(&out)
    );

    // Staged but not committed.
    let status = Command::new("git")
        .current_dir(&h.vault)
        .args(["status", "--porcelain"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_text.starts_with("M "),
        "expected staged modification, got: {status_text}"
    );

    // The file is a fresh envelope, not the conflicted bytes.
    let path = h.vault.join(format!("people/{PERSON}/profile.md"));
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("<<<<<<<"), "conflict markers remain");
    assert!(
        text.contains("\nenc: xchacha20poly1305\n"),
        "not an envelope"
    );

    // Commit, then decrypt: the result equals the canonical input.
    git(&h.vault, &["commit", "-qm", "resolve"]);
    let out = h
        .cmd(&["record", "show", PERSON, "--for-edit", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "record show --for-edit failed: {}",
        stderr(&out)
    );
    let shown = stdout(&out);
    assert!(
        shown.contains("SENTINEL-MERGED-bio."),
        "merged bio not in decrypted output: {shown}"
    );
    assert!(
        !shown.contains("SENTINEL-A-bio") && !shown.contains("SENTINEL-B-bio"),
        "old side leaked into merged output: {shown}"
    );
}

/// #455: `--merged-file` refuses a file whose `id:` does not match.
#[test]
fn merged_file_id_mismatch_refused() {
    let h = conflicted_harness();
    let wrong = write_file(
        h._tmp.path(),
        "wrong.md",
        &person_md(PERSON2, "Ada Example", "Wrong person."),
    );

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            wrong.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "id mismatch should be refused: {}",
        stdout(&out)
    );
}

/// #455: `--merged-file` refuses malformed front matter.
#[test]
fn merged_file_malformed_front_matter_refused() {
    let h = conflicted_harness();
    let bad = write_file(h._tmp.path(), "bad.md", "not a record at all\n");

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            bad.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "malformed front matter should be refused: {}",
        stdout(&out)
    );
}

/// #455: `--merged-file` enforces `with:` list rules like `record edit`.
/// Uses a conflicted interaction built via the two-device pattern.
#[test]
fn merged_file_with_list_rules_enforced() {
    const IXN: &str = "i-01J9Z3K4QH0000000000000000";
    let ixn_md = |with: &str, body: &str| {
        format!(
            "---\nid: {IXN}\ntype: interaction\nperson: {PERSON}\ndate: 2026-10-17\nwith: [{with}]\n---\n\n{body}\n"
        )
    };

    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    add_person(&h, &person_md(PERSON, "Ada Example", "Bio."));
    add_person(&h, &person_md(PERSON2, "Bob Example", "Bio."));

    // Add the interaction on master.
    let first = write_file(h._tmp.path(), "ixn.md", &ixn_md(PERSON2, "Base body."));
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            first.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add interaction: {}", stderr(&out));
    let ixn_path = h.vault.join(format!("interactions/{IXN}/interaction.md"));
    assert!(ixn_path.exists(), "interaction file not created");

    // Device A edits on a branch.
    git(&h.vault, &["checkout", "-qb", "device-a"]);
    let edited_a = write_file(h._tmp.path(), "ixn_a.md", &ixn_md(PERSON2, "Body A."));
    let out = h
        .cmd(&[
            "record",
            "edit",
            IXN,
            "--file",
            edited_a.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "edit ixn (device A): {}",
        stderr(&out)
    );

    // Device B edits on master.
    git(&h.vault, &["checkout", "-q", "master"]);
    let edited_b = write_file(h._tmp.path(), "ixn_b.md", &ixn_md(PERSON2, "Body B."));
    let out = h
        .cmd(&[
            "record",
            "edit",
            IXN,
            "--file",
            edited_b.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "edit ixn (device B): {}",
        stderr(&out)
    );

    // Merge must conflict (both sides changed the same envelope file).
    let st = Command::new("git")
        .current_dir(&h.vault)
        .args(["merge", "--no-edit", "device-a"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(!st.success(), "expected the merge to conflict");

    // Merged file with `with:` listing the interaction's own person: refused.
    let bad_with = write_file(h._tmp.path(), "bad_with.md", &ixn_md(PERSON, "Merged."));
    let out = h
        .cmd(&[
            "record",
            "resolve",
            IXN,
            "--merged-file",
            bad_with.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "self-participant with: should be refused: {}",
        stdout(&out)
    );
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(combined.contains("own person"), "wrong error: {combined}");
}

/// #455: `--merged-file` refuses a path inside the vault tree.
#[test]
fn merged_file_inside_vault_refused() {
    let h = conflicted_harness();
    let inside = write_file(
        &h.vault,
        "merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            inside.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "vault-internal merge file should be refused: {}",
        stdout(&out)
    );
}

/// #455: `--merged-file` refuses a path under `.confidant/` (no exception).
#[test]
fn merged_file_under_dot_confidant_refused() {
    let h = conflicted_harness();
    let dotdir = h.vault.join(".confidant");
    std::fs::create_dir_all(&dotdir).unwrap();
    let inside = write_file(
        &dotdir,
        "merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            inside.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        ".confidant merge file should be refused: {}",
        stdout(&out)
    );
}

/// #455: `--merged-file` refuses a symlink that resolves into the vault.
#[test]
#[cfg(unix)]
fn merged_file_symlink_into_vault_refused() {
    use std::os::unix::fs::symlink;

    let h = conflicted_harness();
    let real = write_file(
        &h.vault,
        "real_merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );
    let link = h._tmp.path().join("link.md");
    symlink(&real, &link).unwrap();

    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            link.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "symlink into vault should be refused: {}",
        stdout(&out)
    );
}

/// #455: a deal whose `person:` moves reports `rekeyed`, exactly when
/// `record edit` would.
#[test]
fn merged_file_rekey_reported_for_deal_person_change() {
    const DEAL: &str = "d-01J9Z3K4QJ0000000000000000";
    let deal = |person: &str| {
        format!(
            "---\nid: {DEAL}\ntype: deal\nname: \"Coaching package\"\nperson: {person}\n---\n\nDeal body.\n"
        )
    };

    let h = Harness::new();
    h.keyed(PERSON);
    let out = h.init_client(PERSON2);
    assert!(out.status.success(), "init-client failed: {}", stderr(&out));
    // Add the deal under PERSON.
    let first = write_file(h._tmp.path(), "deal.md", &deal(PERSON));
    let out = h
        .cmd(&[
            "record",
            "add",
            "--file",
            first.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "add deal: {}", stderr(&out));

    // Device A moves it to PERSON2 on a branch; device B changes the body
    // on master; merge conflicts (both sides touched the file).
    git(&h.vault, &["checkout", "-qb", "device-a"]);
    let moved_a = write_file(h._tmp.path(), "moved_a.md", &deal(PERSON2));
    // Use `record edit` on the branch (it commits).
    let out = h
        .cmd(&[
            "record",
            "edit",
            DEAL,
            "--file",
            moved_a.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "edit deal (device A): {}",
        stderr(&out)
    );
    git(&h.vault, &["checkout", "-q", "master"]);
    let changed_b = write_file(
        h._tmp.path(),
        "changed_b.md",
        &deal(PERSON).replace("Deal body.", "Deal body B."),
    );
    let out = h
        .cmd(&[
            "record",
            "edit",
            DEAL,
            "--file",
            changed_b.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "edit deal (device B): {}",
        stderr(&out)
    );
    let st = Command::new("git")
        .current_dir(&h.vault)
        .args(["merge", "--no-edit", "device-a"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(!st.success(), "expected the merge to conflict");

    // Merge keeping PERSON2 (theirs side): the deal moves keys.
    let merged = write_file(h._tmp.path(), "merged_deal.md", &deal(PERSON2));
    let out = h
        .cmd(&[
            "record",
            "resolve",
            DEAL,
            "--merged-file",
            merged.to_str().unwrap(),
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --merged-file failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["command"], "record-resolve");
    assert_eq!(v["action"], "merge");
    assert_eq!(v["rekeyed"]["from"], PERSON, "{v}");
    assert_eq!(v["rekeyed"]["to"], PERSON2, "{v}");
}

/// #455: `--merged-file` stages but never commits.
#[test]
fn merged_file_no_commit_created() {
    let h = conflicted_harness();
    let merged = write_file(
        h._tmp.path(),
        "merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );

    let before = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            merged.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "resolve failed: {}", stderr(&out));
    let after = Command::new("git")
        .current_dir(&h.vault)
        .args(["rev-parse", "HEAD"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&after.stdout),
        "resolve must not commit"
    );
}

/// #455: `--edit` creates 0600 scratch files in a 0700 dir, then removes
/// everything. A fake $EDITOR records the modes it sees.
#[test]
#[cfg(unix)]
fn edit_creates_0600_scratch_in_0700_dir_and_removes_all() {
    use std::os::unix::fs::PermissionsExt;

    let h = conflicted_harness();
    // `.confidant/` must be git-ignored for --edit to run.
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();
    // Fake editor: records modes of the scratch dir and files, then leaves
    // merged.md as-is (pre-filled with ours).
    let script = write_file(
        h._tmp.path(),
        "editor.sh",
        "#!/bin/sh\n\
         d=$(dirname \"$1\")\n\
         ls -ld \"$d\" > \"$d/modes.txt\"\n\
         ls -l \"$d\"/*.md >> \"$d/modes.txt\"\n",
    );
    #[cfg(unix)]
    {
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = h
        .cmd(&["record", "resolve", PERSON, "--edit", "--no-input"])
        .env("VISUAL", "")
        .env("EDITOR", script.to_str().unwrap())
        .output()
        .unwrap();
    // The modes file is inside the scratch dir, which is removed; the
    // editor script itself records nothing outside. We assert removal and
    // success here; mode assertions happen via a variant below that copies
    // the modes out. For now, just check the scratch is gone.
    assert!(
        out.status.success(),
        "resolve --edit failed: {} {}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        !h.vault.join(".confidant/conflicts").exists(),
        "scratch dir should be removed"
    );
    // The merge was applied (ours pre-fill) and staged.
    let status = Command::new("git")
        .current_dir(&h.vault)
        .args(["status", "--porcelain"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&status.stdout).starts_with("M "),
        "expected staged modification: {}",
        String::from_utf8_lossy(&status.stdout)
    );
}

/// #455: while the editor runs, scratch files are 0600 in a 0700 dir.
/// The fake editor copies the modes file out before exiting so the test
/// can assert on it after the scratch is removed.
#[test]
#[cfg(unix)]
fn edit_scratch_modes_are_0600_in_0700_dir() {
    let h = conflicted_harness();
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();
    let modes_out = h._tmp.path().join("modes.txt");
    let script = write_file(
        h._tmp.path(),
        "editor.sh",
        &format!(
            "#!/bin/sh\n\
             d=$(dirname \"$1\")\n\
             ls -ld \"$d\" | cut -c1-10 > \"{}\"\n\
             ls -l \"$d/ours.md\" | cut -c1-10 >> \"{}\"\n\
             ls -l \"$d/theirs.md\" | cut -c1-10 >> \"{}\"\n\
             ls -l \"$d/merged.md\" | cut -c1-10 >> \"{}\"\n",
            modes_out.display(),
            modes_out.display(),
            modes_out.display(),
            modes_out.display(),
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = h
        .cmd(&["record", "resolve", PERSON, "--edit", "--no-input"])
        .env("VISUAL", "")
        .env("EDITOR", script.to_str().unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --edit failed: {} {}",
        stdout(&out),
        stderr(&out)
    );
    let modes = std::fs::read_to_string(&modes_out).unwrap();
    let lines: Vec<&str> = modes.lines().collect();
    assert_eq!(lines.len(), 4, "expected 4 mode lines: {modes}");
    assert_eq!(
        lines[0], "drwx------",
        "scratch dir should be 0700: {modes}"
    );
    for (i, name) in ["ours.md", "theirs.md", "merged.md"].iter().enumerate() {
        assert_eq!(
            lines[i + 1],
            "-rw-------",
            "scratch file {name} should be 0600: {modes}"
        );
    }
}

/// #455: an editor that exits non-zero cleans the scratch and changes nothing.
#[test]
#[cfg(unix)]
fn edit_editor_failure_cleans_scratch_and_changes_nothing() {
    let h = conflicted_harness();
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();
    let before = std::fs::read(h.vault.join(format!("people/{PERSON}/profile.md"))).unwrap();
    let script = write_file(h._tmp.path(), "failing.sh", "#!/bin/sh\nexit 3\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = h
        .cmd(&["record", "resolve", PERSON, "--edit", "--no-input"])
        .env("VISUAL", "")
        .env("EDITOR", script.to_str().unwrap())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "failing editor should error: {}",
        stdout(&out)
    );
    assert!(
        !h.vault.join(".confidant/conflicts").exists(),
        "scratch should be cleaned after editor failure"
    );
    let after = std::fs::read(h.vault.join(format!("people/{PERSON}/profile.md"))).unwrap();
    assert_eq!(before, after, "conflicted file must be unchanged");
    // The merge was not applied: the file still has conflict markers.
    let text = String::from_utf8_lossy(&after);
    assert!(
        text.contains("<<<<<<<"),
        "conflict markers should remain after editor failure"
    );
}

/// #455: no editor configured is a usage error (exit 2).
#[test]
#[cfg(unix)]
fn edit_without_editor_env_is_usage_error() {
    let h = conflicted_harness();
    let out = h
        .cmd(&["record", "resolve", PERSON, "--edit", "--no-input"])
        .env("VISUAL", "")
        .env("EDITOR", "")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2: {}",
        stderr(&out)
    );
    assert!(
        !h.vault.join(".confidant/conflicts").exists(),
        "no scratch should remain"
    );
}

/// #455: `merged.md` is pre-filled with the ours plaintext.
#[test]
#[cfg(unix)]
fn edit_prefills_merged_with_ours_plaintext() {
    let h = conflicted_harness();
    std::fs::write(h.vault.join(".gitignore"), ".confidant/\n").unwrap();
    // Fake editor copies merged.md out for assertion, then leaves it.
    let copy_out = h._tmp.path().join("merged_copy.md");
    let script = write_file(
        h._tmp.path(),
        "editor.sh",
        &format!("#!/bin/sh\ncp \"$1\" \"{}\"\n", copy_out.display()),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = h
        .cmd(&["record", "resolve", PERSON, "--edit", "--no-input"])
        .env("VISUAL", "")
        .env("EDITOR", script.to_str().unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --edit failed: {} {}",
        stdout(&out),
        stderr(&out)
    );
    let copied = std::fs::read_to_string(&copy_out).unwrap();
    assert!(
        copied.contains("SENTINEL-B-bio"),
        "merged.md should be pre-filled with ours (SENTINEL-B-bio): {copied}"
    );
    // The test deletes the copy (it holds plaintext outside the vault).
    std::fs::remove_file(&copy_out).unwrap();
}

/// #455: stale `.confidant/conflicts/` is swept at the start of the next resolve.
#[test]
#[cfg(unix)]
fn edit_stale_scratch_swept_on_next_resolve() {
    let h = conflicted_harness();
    // Plant a stale scratch dir (simulating a crashed earlier run).
    let stale = h.vault.join(".confidant/conflicts").join(PERSON);
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("merged.md"), b"STALE-SENTINEL").unwrap();

    // A --show (any resolve) sweeps it.
    let out = h
        .cmd(&["record", "resolve", PERSON, "--show", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resolve --show failed: {}",
        stderr(&out)
    );
    assert!(
        !h.vault.join(".confidant/conflicts").exists(),
        "stale scratch should be swept"
    );
}

/// #455: `--edit` refuses when `.confidant/` is not git-ignored.
#[test]
#[cfg(unix)]
fn edit_refuses_when_dot_confidant_not_gitignored() {
    let h = conflicted_harness();
    // No .gitignore: `.confidant/` is not ignored, so --edit must refuse
    // rather than risk committing plaintext.
    assert!(!h.vault.join(".gitignore").exists());

    let out = h
        .cmd(&["record", "resolve", PERSON, "--edit", "--no-input"])
        .env("VISUAL", "")
        .env("EDITOR", "/bin/true")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "unignored .confidant should be refused: {}",
        stdout(&out)
    );
    assert!(
        !h.vault.join(".confidant/conflicts").exists(),
        "no scratch should be created"
    );
}

/// #455: no plaintext (sentinels) in stdout/stderr on any merge path.
#[test]
fn no_plaintext_in_stdout_stderr_on_any_path() {
    // --merged-file with an invalid record: error must not leak content.
    let h = conflicted_harness();
    let bad = write_file(
        h._tmp.path(),
        "bad.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-SECRET-BIO."),
    );
    // Corrupt it so validation fails after reading.
    std::fs::write(&bad, "---\nid: wrong\n---\nSENTINEL-SECRET-BIO\n").unwrap();
    let out = h
        .cmd(&[
            "record",
            "resolve",
            PERSON,
            "--merged-file",
            bad.to_str().unwrap(),
            "--no-input",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !stdout(&out).contains("SENTINEL-SECRET-BIO"),
        "stdout leaked plaintext"
    );
    assert!(
        !stderr(&out).contains("SENTINEL-SECRET-BIO"),
        "stderr leaked plaintext"
    );
    // The sentinels from the conflicted record itself must not appear
    // in error output either.
    assert!(
        !stdout(&out).contains("SENTINEL-A-bio") && !stdout(&out).contains("SENTINEL-B-bio"),
        "stdout leaked side plaintext"
    );
}

// ---------------------------------------------------------------------------
// #457: `record resolve --from-inbox`
// ---------------------------------------------------------------------------

/// Harness with an inbox item conflicting with an existing record.
/// Returns (harness, inbox_bech32, stem).
fn inbox_conflict_harness() -> (Harness, String, String) {
    let mut h = Harness::new();
    h.keyed(PERSON);
    add_person(&h, &person_md(PERSON, "Ada Example", "SENTINEL-MAIN-bio."));
    let Some(signing) = ssh_signing(&h) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        // Return a dummy; the caller must check and return early.
        return (h, String::new(), String::new());
    };
    // Keep the key file alive for the whole test: these tests make further
    // signed commits after this function returns (`inbox --discard`, a
    // second `queue_items`, the drain's clear).
    h._signing = Some(signing);

    let inbox_bech32 = age_generate_bech32();
    let inbox_recipient = age_recipient(&inbox_bech32);
    advertise_vault_inbox_pubkey(&h, &inbox_recipient);
    write_user_config_pin(&h.home, &inbox_recipient);

    // Queue an item targeting the existing record with different content.
    let stem = "conflict-item-01";
    let payload = format!(
        "confidant-inbox/1\nkind: record\npath: people/{PERSON}/profile.md\n---\n{}",
        person_md(PERSON, "Ada Example", "SENTINEL-INBOX-bio.")
    );
    confidant_core::queue_items(
        &h.vault,
        &[confidant_core::QueueItem {
            stem: stem.to_string(),
            plaintext: payload,
        }],
        &inbox_recipient,
    )
    .expect("queue_items failed");
    (h, inbox_bech32, stem.to_string())
}

/// Run a `record resolve --from-inbox` command with the inbox key in env.
fn resolve_from_inbox_cmd(h: &Harness, inbox_bech32: &str, args: &[&str]) -> std::process::Output {
    let mut full = vec![
        "record",
        "resolve",
        PERSON,
        "--from-inbox",
        "conflict-item-01",
    ];
    full.extend(args);
    full.push("--no-input");
    let mut cmd = h.cmd(&full);
    cmd.env("CONFIDANT_INBOX_KEY", inbox_bech32);
    // Keep off the real OS keychain.
    cmd.env("CONFIDANT_KEYCHAIN", "off");
    cmd.output().unwrap()
}

/// #457: `--show` prints both the current record and the inbox item.
#[test]
fn resolve_from_inbox_show_both_sides() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--show"]);
    assert!(
        out.status.success(),
        "resolve --show failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("== ours ("), "missing ours header: {text}");
    assert!(
        text.contains("SENTINEL-MAIN-bio"),
        "missing ours body: {text}"
    );
    assert!(
        text.contains("== theirs ("),
        "missing theirs header: {text}"
    );
    assert!(
        text.contains("inbox:conflict-item-01"),
        "missing theirs label: {text}"
    );
    assert!(
        text.contains("SENTINEL-INBOX-bio"),
        "missing theirs body: {text}"
    );
}

/// #457: `--show --json` has the inbox shape.
#[test]
fn resolve_from_inbox_show_json_shape() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--show", "--json"]);
    assert!(
        out.status.success(),
        "resolve --show failed: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["from_inbox"], "conflict-item-01");
    assert!(v["ours"]["text"]
        .as_str()
        .unwrap()
        .contains("SENTINEL-MAIN-bio"));
    assert!(v["theirs"]["text"]
        .as_str()
        .unwrap()
        .contains("SENTINEL-INBOX-bio"));
    assert_eq!(v["theirs"]["label"], "inbox:conflict-item-01");
}

/// #457: unknown stem fails closed with E_INBOX_SKIP.
#[test]
fn resolve_from_inbox_unknown_stem_fails_closed() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let full = vec![
        "record",
        "resolve",
        PERSON,
        "--from-inbox",
        "01NOPE",
        "--show",
        "--json",
        "--no-input",
    ];
    let mut cmd = h.cmd(&full);
    cmd.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    cmd.env("CONFIDANT_KEYCHAIN", "off");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "unknown stem must fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "E_INBOX_SKIP");
}

/// #457: an item for a missing record is not a conflict.
#[test]
fn resolve_from_inbox_item_for_missing_record_is_not_a_conflict() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    // Queue an item for a record that does not exist.
    let inbox_recipient = age_recipient(&inbox_bech32);
    // A valid ULID that has no record: a malformed id would fail as a usage
    // error before the missing-record check this test is about.
    let ghost = "p-01J9Z3K4QF0000000000000001";
    let payload = format!(
        "confidant-inbox/1\nkind: record\npath: people/{ghost}/profile.md\n---\n{}",
        person_md(ghost, "Ghost Example", "SENTINEL-GHOST-bio.")
    );
    confidant_core::queue_items(
        &h.vault,
        &[confidant_core::QueueItem {
            stem: "ghost-item".to_string(),
            plaintext: payload,
        }],
        &inbox_recipient,
    )
    .expect("queue_items failed");

    let full = vec![
        "record",
        "resolve",
        ghost,
        "--from-inbox",
        "ghost-item",
        "--show",
        "--json",
        "--no-input",
    ];
    let mut cmd = h.cmd(&full);
    cmd.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    cmd.env("CONFIDANT_KEYCHAIN", "off");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "missing record must be refused");
    // `--json` reports the error as an envelope on stdout (ADR-7).
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("nothing to resolve"), "wrong error: {text}");
}

/// #457: `--take theirs` encrypts the item and the next drain skips it as merged.
#[test]
fn resolve_from_inbox_take_theirs_then_drain_skips_and_clears() {
    let (h, inbox_bech32, stem) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--take", "theirs", "--allow-unsigned"]);
    assert!(
        out.status.success(),
        "resolve --take failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("Merged"),
        "missing merge confirmation: {text}"
    );

    // The record now holds the inbox content (decrypt to check).
    let out = h
        .cmd(&["record", "show", PERSON, "--for-edit", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("SENTINEL-INBOX-bio"));

    // Take the CLI's next git step (CD6: stage only, never commit). The
    // drain refuses to merge from a dirty worktree, and a staged resolve is
    // dirty by design, so the operator's commit comes first.
    git(&h.vault, &["commit", "-q", "-m", "resolve inbox conflict"]);

    // The next drain sees the item as already merged and clears it.
    let mut drain = h.cmd(&["inbox", "--allow-unsigned", "--no-input"]);
    drain.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    drain.env("CONFIDANT_KEYCHAIN", "off");
    let out = drain.output().unwrap();
    assert!(out.status.success(), "drain failed: {}", stderr(&out));
    // The item was skipped as already-present and cleared.
    let tree = Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-tree", "-r", "--name-only", "inbox"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let tree_text = String::from_utf8_lossy(&tree.stdout);
    assert!(
        !tree_text.contains(&stem),
        "item should be cleared: {tree_text}"
    );
}

/// #457: `--take ours` keeps the record; `inbox --discard` retires the item.
#[test]
fn resolve_from_inbox_take_ours_then_discard_clears_item() {
    let (h, inbox_bech32, stem) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--take", "ours", "--allow-unsigned"]);
    assert!(
        out.status.success(),
        "resolve --take failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("inbox --discard"),
        "missing discard hint: {text}"
    );

    // The record is untouched.
    let out = h
        .cmd(&["record", "show", PERSON, "--for-edit", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("SENTINEL-MAIN-bio"));

    // Discard the item.
    let mut discard = h.cmd(&["inbox", "--discard", &stem, "--no-input"]);
    discard.env("CONFIDANT_KEYCHAIN", "off");
    let out = discard.output().unwrap();
    assert!(out.status.success(), "discard failed: {}", stderr(&out));
    let tree = Command::new("git")
        .current_dir(&h.vault)
        .args(["ls-tree", "-r", "--name-only", "inbox"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let tree_text = String::from_utf8_lossy(&tree.stdout);
    assert!(
        !tree_text.contains(&stem),
        "item should be discarded: {tree_text}"
    );
}

/// #457: no plaintext reaches stderr on success or failure.
#[test]
fn resolve_from_inbox_no_plaintext_in_stderr() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    for args in [&["--show"][..], &["--take", "ours", "--allow-unsigned"][..]] {
        let out = resolve_from_inbox_cmd(&h, &inbox_bech32, args);
        assert!(out.status.success());
        let err = stderr(&out);
        assert!(
            !err.contains("SENTINEL-MAIN-bio") && !err.contains("SENTINEL-INBOX-bio"),
            "stderr leaked plaintext: {err}"
        );
    }
    // Failure path: unknown stem.
    let full = vec![
        "record",
        "resolve",
        PERSON,
        "--from-inbox",
        "01NOPE",
        "--show",
        "--no-input",
    ];
    let mut cmd = h.cmd(&full);
    cmd.env("CONFIDANT_INBOX_KEY", &inbox_bech32);
    cmd.env("CONFIDANT_KEYCHAIN", "off");
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        !err.contains("SENTINEL-MAIN-bio") && !err.contains("SENTINEL-INBOX-bio"),
        "stderr leaked plaintext: {err}"
    );
}

/// #457: `--take theirs` without trusted signers refuses with
/// `E_INBOX_UNTRUSTED` (the drain's trust gate applies to write actions).
#[test]
fn resolve_from_inbox_take_theirs_refuses_unsigned_tip() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--take", "theirs"]);
    assert!(!out.status.success(), "resolve --take should have refused");
    let err = stderr(&out);
    assert!(
        err.contains("E_INBOX_UNTRUSTED"),
        "expected E_INBOX_UNTRUSTED, got: {err}"
    );
}

/// #457: `--take theirs --allow-unsigned` bypasses the trust gate.
#[test]
fn resolve_from_inbox_take_theirs_allow_unsigned_succeeds() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--take", "theirs", "--allow-unsigned"]);
    assert!(
        out.status.success(),
        "resolve --take --allow-unsigned failed: {}",
        stderr(&out)
    );
}

/// #457: `--merged-file` without trusted signers refuses with
/// `E_INBOX_UNTRUSTED`.
#[test]
fn resolve_from_inbox_merged_file_refuses_unsigned_tip() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let merged = write_file(
        h._tmp.path(),
        "merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );
    let out = resolve_from_inbox_cmd(
        &h,
        &inbox_bech32,
        &["--merged-file", merged.to_str().unwrap()],
    );
    assert!(
        !out.status.success(),
        "resolve --merged-file should have refused"
    );
    let err = stderr(&out);
    assert!(
        err.contains("E_INBOX_UNTRUSTED"),
        "expected E_INBOX_UNTRUSTED, got: {err}"
    );
}

/// #457: `--merged-file --allow-unsigned` bypasses the trust gate.
#[test]
fn resolve_from_inbox_merged_file_allow_unsigned_succeeds() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let merged = write_file(
        h._tmp.path(),
        "merged.md",
        &person_md(PERSON, "Ada Example", "SENTINEL-MERGED-bio."),
    );
    let out = resolve_from_inbox_cmd(
        &h,
        &inbox_bech32,
        &[
            "--merged-file",
            merged.to_str().unwrap(),
            "--allow-unsigned",
        ],
    );
    assert!(
        out.status.success(),
        "resolve --merged-file --allow-unsigned failed: {}",
        stderr(&out)
    );
}

/// #457: `--edit` without trusted signers refuses with `E_INBOX_UNTRUSTED`
/// before the editor runs (the trust gate precedes all write actions).
#[test]
fn resolve_from_inbox_edit_refuses_unsigned_tip() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--edit"]);
    assert!(!out.status.success(), "resolve --edit should have refused");
    let err = stderr(&out);
    assert!(
        err.contains("E_INBOX_UNTRUSTED"),
        "expected E_INBOX_UNTRUSTED, got: {err}"
    );
}

/// #457: `--show` stays read-only — no trust check, no `--allow-unsigned`
/// needed (already covered by `resolve_from_inbox_show_both_sides`, which
/// passes without the flag).
#[test]
fn resolve_from_inbox_show_needs_no_trust_gate() {
    let (h, inbox_bech32, _) = inbox_conflict_harness();
    if inbox_bech32.is_empty() {
        return;
    }
    // `--show` without `--allow-unsigned` succeeds: the trust gate does not
    // apply to the read-only action.
    let out = resolve_from_inbox_cmd(&h, &inbox_bech32, &["--show"]);
    assert!(
        out.status.success(),
        "resolve --show should not need the trust gate: {}",
        stderr(&out)
    );
}
