//! `doctor` device-key / keychain state (#541).
//!
//! The keychain probe is injectable in `confidant-crypt` (unit tests there
//! cover reachable/unreachable). Here we exercise the CLI contract on a
//! host with no keychain: `CONFIDANT_KEYCHAIN=off` is the documented
//! test-only switch that skips the OS keychain, so these tests never touch
//! a developer's real keychain and never depend on D-Bus. All data is fake.

use std::path::PathBuf;
use std::process::{Command, Output};

use age::secrecy::ExposeSecret;
use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// A throwaway git identity for the child: CI runners have no global
/// `user.name`/`user.email`, and without one `doctor`'s `git-identity`
/// check errors. Fake values only.
fn give_child_git_identity(cmd: &mut Command) {
    cmd.env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "Confidant Test")
        .env("GIT_CONFIG_KEY_1", "user.email")
        .env("GIT_CONFIG_VALUE_1", "test@example.com");
}

/// Run `doctor` against the demo vault with a clean environment. `env`
/// entries are `(name, value)`; `None` removes the variable so a developer
/// shell cannot leak it into the test.
fn run_doctor(json: bool, env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.arg("doctor")
        .arg("--no-input")
        .arg("--vault")
        .arg(demo());
    if json {
        cmd.arg("--json");
    }
    give_child_git_identity(&mut cmd);
    let home = tempfile::tempdir().unwrap();
    cmd.env("HOME", home.path())
        .env("CONFIDANT_OFFLINE", "1")
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_KEYCHAIN")
        .env_remove("CONFIDANT_DEVICE_KEY");
    for (key, value) in env {
        match value {
            Some(value) => cmd.env(key, value),
            None => cmd.env_remove(key),
        };
    }
    cmd.output().unwrap()
}

fn json_doctor(env: &[(&str, Option<&str>)]) -> Value {
    let out = run_doctor(true, env);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); status={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn check<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("check {id} missing: {v}"))
}

fn fresh_identity_bech32() -> String {
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_owned()
}

#[test]
fn doctor_reports_env_provided_device_key() {
    let key = fresh_identity_bech32();
    let v = json_doctor(&[("CONFIDANT_DEVICE_KEY", Some(&key))]);
    let c = check(&v, "device-key");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("CONFIDANT_DEVICE_KEY"), "{msg}");
    assert!(msg.contains("headless"), "{msg}");
    // Healthy checks carry no fix.
    assert!(c.get("fix").is_none(), "{c}");
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_reports_not_enrolled_without_a_keychain() {
    // Env unset, keychain skipped: the headless-host state, deterministically.
    let v = json_doctor(&[("CONFIDANT_KEYCHAIN", Some("off"))]);
    let c = check(&v, "device-key");
    assert_eq!(c["status"], "warning", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("not enrolled"), "{msg}");
    let fix = c["fix"].as_str().expect("fix field names the way out");
    assert!(fix.contains("CONFIDANT_DEVICE_KEY"), "{fix}");
    assert!(fix.contains("CONFIDANT_OPERATOR_KEY"), "{fix}");
    assert!(fix.contains("64-character hex"), "{fix}");
    assert!(fix.contains("before running `confidant init`"), "{fix}");
    assert!(fix.contains("CONFIDANT_INBOX_KEY"), "{fix}");
    assert!(fix.contains("Keys never live in files"), "{fix}");
    // Warning-only: an unenrolled host still gets a usable doctor report.
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_human_output_prints_the_fix() {
    let out = run_doctor(false, &[("CONFIDANT_KEYCHAIN", Some("off"))]);
    assert!(out.status.success(), "{:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("device-key"), "{stdout}");
    assert!(stdout.contains("fix:"), "{stdout}");
    assert!(stdout.contains("CONFIDANT_DEVICE_KEY"), "{stdout}");
}
