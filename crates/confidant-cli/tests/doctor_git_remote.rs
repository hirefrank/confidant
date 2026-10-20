//! #660: `doctor` git-remote check.
//!
//! Read-only and offline: the check reads `git remote -v` and never
//! fetches or pushes. Tests cover a local-only repo, a remote on a
//! plaintext vault (warning), a remote on an encrypted vault (ok), and a
//! directory that is not a git repo (advisory, never an error). All data
//! and URLs are fake.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

/// The checked-out plaintext demo vault (never written to: callers copy it).
fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// A throwaway git identity, supplied to the child through git's env
/// config so CI runners with no global `user.name`/`user.email` still
/// resolve identity.
fn give_child_git_identity(cmd: &mut Command) {
    cmd.env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "Confidant Test")
        .env("GIT_CONFIG_KEY_1", "user.email")
        .env("GIT_CONFIG_VALUE_1", "test@example.com");
}

/// Run git in `vault`, asserting success, and return stdout.
#[cfg(unix)]
fn git(vault: &Path, args: &[&str]) -> String {
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

/// A throwaway age identity for `init --create`; the OS keychain is never
/// consulted (ADR-14: CI generates ephemeral keys during the run).
fn age_generate_bech32() -> String {
    use age::secrecy::ExposeSecret;
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_owned()
        .to_uppercase()
}

/// An encrypted vault created by the real bootstrap path, plus the temp
/// HOME that holds its trust anchor and manifest tracking.
struct EncryptedVault {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
}

#[cfg(unix)]
fn encrypted_vault() -> EncryptedVault {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Confidant Test\n\temail = test@example.com\n",
    )
    .unwrap();
    let vault = tmp.path().join("vault");
    let out = Command::new(bin())
        .args(["init", "--create", "--no-input", "--json", "--vault"])
        .arg(&vault)
        .env("HOME", &home)
        .env("CONFIDANT_DEVICE_KEY", age_generate_bech32())
        .env("CONFIDANT_KEYCHAIN", "off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init --create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    EncryptedVault {
        _tmp: tmp,
        home,
        vault,
    }
}

/// Copy the demo vault (a plaintext vault by design) into a temp dir.
#[cfg(unix)]
fn plaintext_vault_copy(dir: &Path) -> PathBuf {
    let vault = dir.join("vault");
    common::copy_dir(&demo(), &vault);
    vault
}

/// Run `doctor --json --no-input` against `vault` with a hermetic HOME
/// and `CONFIDANT_OFFLINE=1` (no release-tag fetch).
#[cfg(unix)]
fn run_doctor(vault: &Path, home: &Path) -> Value {
    let mut cmd = Command::new(bin());
    cmd.args(["doctor", "--json", "--no-input", "--vault"])
        .arg(vault)
        .env("HOME", home)
        .env("CONFIDANT_OFFLINE", "1")
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_KEYCHAIN", "off");
    give_child_git_identity(&mut cmd);
    let out = cmd.output().unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); status={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[cfg(unix)]
fn check<'a>(v: &'a Value, id: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
}

#[cfg(unix)]
#[test]
fn git_remote_absent_is_ok_with_add_remote_fix() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let vault = plaintext_vault_copy(dir.path());
    git(&vault, &["init", "-q"]);

    let v = run_doctor(&vault, home.path());
    let c = check(&v, "git-remote").expect("git-remote check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("local-only"), "{msg}");
    assert!(msg.contains("backup"), "{msg}");
    let fix = c["fix"].as_str().expect("fix field missing");
    assert!(fix.contains("git remote add origin"), "{fix}");
    assert!(fix.contains("keys device-add"), "{fix}");
    // Provider-neutral: no host is hard-coded.
    assert!(!fix.contains("github"), "{fix}");
}

#[cfg(unix)]
#[test]
fn git_remote_on_plaintext_vault_warns() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let vault = plaintext_vault_copy(dir.path());
    git(&vault, &["init", "-q"]);
    git(
        &vault,
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/fake/vault.git",
        ],
    );

    let v = run_doctor(&vault, home.path());
    let c = check(&v, "git-remote").expect("git-remote check missing");
    assert_eq!(c["status"], "warning", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("origin"), "{msg}");
    assert!(msg.contains("plaintext"), "{msg}");
    assert!(msg.contains("readable by anyone with repo access"), "{msg}");
    let fix = c["fix"].as_str().expect("fix field missing");
    assert!(fix.contains("Do not push plaintext vaults"), "{fix}");
}

#[cfg(unix)]
#[test]
fn git_remote_on_encrypted_vault_is_ok() {
    let enc = encrypted_vault();
    git(
        &enc.vault,
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/fake/vault.git",
        ],
    );

    let v = run_doctor(&enc.vault, &enc.home);
    let c = check(&v, "git-remote").expect("git-remote check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("origin"), "{msg}");
    assert!(msg.contains("vault is encrypted"), "{msg}");
    assert!(c.get("fix").is_none(), "healthy check must omit fix: {v}");
}

#[cfg(unix)]
#[test]
fn git_remote_without_a_repo_is_advisory_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    // A valid vault directory that was never `git init`ed. `git-repo`
    // reports the real error; `git-remote` must not panic or add an error.
    let vault = plaintext_vault_copy(dir.path());

    let v = run_doctor(&vault, home.path());
    let c = check(&v, "git-remote").expect("git-remote check missing");
    assert_ne!(c["status"], "error", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("could not read git remotes"), "{msg}");
}
