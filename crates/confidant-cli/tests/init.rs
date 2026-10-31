//! `confidant init`: the plaintext scaffold.
//!
//! `--create` writes the vault's on-disk shape (collection directories and
//! the ledger), a `confidant.toml` without a `[crypto]` table, a `main`
//! branch, and a repo-local fallback git identity when the machine has no
//! identity of its own. Plain `init` applies the idempotent shape step to an
//! existing vault. All data and identities are fake.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

#[path = "common/mod.rs"]
mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// Remove identity sources inherited from the machine so the fallback path
/// is exercised (CI runners may or may not carry a global git identity).
fn scrub_identity(cmd: &mut Command) {
    for key in [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_CONFIG_COUNT",
        "EMAIL",
    ] {
        cmd.env_remove(key);
    }
}

/// Run git in `vault`, asserting success, and return stdout.
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

fn run_init(vault: &Path, home: &Path, create: bool) -> Value {
    let mut cmd = Command::new(bin());
    cmd.args(["init", "--no-input", "--json", "--vault"])
        .arg(vault)
        .env("HOME", home)
        // A machine-wide XDG config would otherwise leak a real identity
        // past this hermetic HOME.
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("CONFIDANT_OFFLINE", "1");
    if create {
        cmd.arg("--create");
    }
    scrub_identity(&mut cmd);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

const COLLECTIONS: &[&str] = &[
    "people",
    "orgs",
    "deals",
    "interactions",
    "notes",
    "edges",
    "ledger",
];

#[test]
fn init_create_makes_the_vault_shape_and_a_fallback_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let vault = tmp.path().join("vault");

    let v = run_init(&vault, &home, true);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["branch"], "main", "{v}");

    for dir in COLLECTIONS {
        assert!(vault.join(dir).is_dir(), "init --create must create {dir}/");
    }

    let config = std::fs::read_to_string(vault.join("confidant.toml")).unwrap();
    assert!(!config.contains("[crypto]"), "{config}");
    assert!(config.contains("spec = \"0.1\""), "{config}");

    assert_eq!(git(&vault, &["branch", "--show-current"]).trim(), "main");
    assert_eq!(
        git(&vault, &["config", "--local", "--get", "user.name"]).trim(),
        "Confidant Operator"
    );
    assert_eq!(
        git(&vault, &["config", "--local", "--get", "user.email"]).trim(),
        "operator@confidant.local"
    );
    // The skeleton commit used the fallback, so a machine with no global
    // identity still gets a usable vault.
    assert_eq!(
        git(&vault, &["log", "-1", "--format=%an"]).trim(),
        "Confidant Operator"
    );
    assert!(!git(&vault, &["status", "--porcelain"]).contains("??"));
}

#[test]
fn init_create_never_overrides_an_existing_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Robin Operator\n\temail = robin@example.invalid\n",
    )
    .unwrap();
    let vault = tmp.path().join("vault");

    run_init(&vault, &home, true);

    // The real identity resolves, so no repo-local fallback is written.
    let local = Command::new("git")
        .arg("-C")
        .arg(&vault)
        .args(["config", "--local", "--get", "user.name"])
        .output()
        .unwrap();
    assert!(!local.status.success(), "fallback identity was written");
    assert_eq!(
        git(&vault, &["log", "-1", "--format=%an"]).trim(),
        "Robin Operator"
    );
}

#[test]
fn init_without_create_fills_in_a_hand_written_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let vault = tmp.path().join("vault");
    common::copy_dir(&demo(), &vault);
    for dir in ["orgs", "deals", "interactions"] {
        assert!(!vault.join(dir).exists());
    }
    git(&vault, &["init", "-q"]);

    let v = run_init(&vault, &home, false);
    assert_eq!(v["ok"], true, "{v}");

    for dir in COLLECTIONS {
        assert!(vault.join(dir).is_dir(), "init must create {dir}/");
    }
    assert_eq!(
        git(&vault, &["config", "--local", "--get", "user.name"]).trim(),
        "Confidant Operator"
    );
}

#[test]
fn init_create_dry_run_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let vault = tmp.path().join("vault");

    let mut cmd = Command::new(bin());
    cmd.args([
        "init",
        "--create",
        "--dry-run",
        "--no-input",
        "--json",
        "--vault",
    ])
    .arg(&vault)
    .env("HOME", &home)
    .env("XDG_CONFIG_HOME", home.join(".config"))
    .env("CONFIDANT_OFFLINE", "1");
    scrub_identity(&mut cmd);
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "{v}");
    assert!(!vault.exists(), "a dry run must not create the vault");
}
