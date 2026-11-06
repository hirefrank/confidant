//! `doctor` legacy encrypted-vault sniff (#809).
//!
//! A vault written by the encrypted Confidant (≤0.7) must fail with one
//! clear check instead of a stream of record and ledger parse errors. All
//! data here is fake; the sniff never decrypts.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

/// Run `doctor --json --no-input` with a hermetic HOME and no network.
/// The command exits non-zero when the legacy check errors; stdout is
/// still the JSON envelope the test reads.
fn run_doctor(vault: &Path) -> Value {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["doctor", "--json", "--no-input", "--vault"])
        .arg(vault)
        .env("CONFIDANT_OFFLINE", "1")
        .env("HOME", home.path())
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); status={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn check<'a>(v: &'a Value, id: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
}

/// A minimal vault config. The person record is written by each test.
fn write_config(root: &Path) {
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"01M3TC5H00MPJG005VQC00000B\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    )
    .unwrap();
}

fn person_dir(root: &Path) -> std::path::PathBuf {
    root.join("people/p-01M3TC5H00MPJG000000000101")
}

fn write_plaintext_person(root: &Path) {
    let dir = person_dir(root);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("profile.md"),
        "---\nid: p-01M3TC5H00MPJG000000000101\ntype: person\nname: Robin Example\n---\n\nFake person.\n",
    )
    .unwrap();
}

fn assert_legacy_check(v: &Value) {
    let c = check(v, "legacy-encrypted-vault").expect("legacy-encrypted-vault check missing");
    assert_eq!(c["status"], "error", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("encrypted Confidant ≤0.7"), "{msg}");
    assert!(msg.contains("confidant init"), "{msg}");
    // One clear message replaces the parse/check stream.
    assert!(check(v, "vault-load").is_none(), "{v}");
    assert!(check(v, "check").is_none(), "{v}");
}

#[test]
fn doctor_flags_a_legacy_keys_tree() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    std::fs::create_dir_all(dir.path().join("keys/shared")).unwrap();
    std::fs::write(dir.path().join("keys/operator.toml"), "fake operator\n").unwrap();

    let v = run_doctor(dir.path());
    assert_legacy_check(&v);
}

#[test]
fn doctor_flags_an_enc_envelope_record() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    let person = person_dir(dir.path());
    std::fs::create_dir_all(&person).unwrap();
    std::fs::write(
        person.join("profile.md"),
        "---\nid: p-01M3TC5H00MPJG000000000101\ntype: person\nname: Robin Example\nenc: xchacha20poly1305\nkey_id: p-01M3TC5H00MPJG000000000101/e0\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\n\nAQID\n",
    )
    .unwrap();

    let v = run_doctor(dir.path());
    assert_legacy_check(&v);
}

#[test]
fn doctor_does_not_flag_a_plaintext_vault() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_plaintext_person(dir.path());

    let v = run_doctor(dir.path());
    assert!(
        check(&v, "legacy-encrypted-vault").is_none(),
        "plaintext vault flagged: {v}"
    );
    // The normal checks still run.
    assert!(check(&v, "check").is_some(), "{v}");
}
