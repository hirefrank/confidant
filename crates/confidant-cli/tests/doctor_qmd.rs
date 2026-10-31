//! `doctor` qmd-search check (#386, #657).
//!
//! A missing qmd is `ok`: qmd is optional. An installed qmd without a
//! corpus is a `warning` (#657) because the qmd-search skill must stage
//! the corpus to enable semantic search. Tests cover `qmd` absent from
//! PATH, present without a corpus, and present with a corpus, plus the
//! embeddings probe. No test touches the network (`CONFIDANT_OFFLINE=1`)
//! and all data is fake.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

// Shared integration-test helpers (#416 nit 3). The module only exists
// on unix because its sole caller here (`copy_dir`) is unix-only;
// without the gate the Windows build trips `-D warnings` (#402).
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

/// A throwaway git identity, supplied to the child through git's
/// `GIT_CONFIG_COUNT`/`KEY`/`VALUE` environment. CI runners have no global
/// `user.name`/`user.email`, so without this the demo vault's `git-identity`
/// doctor check errors. Fake values only.
fn give_child_git_identity(cmd: &mut Command) {
    cmd.env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "Confidant Test")
        .env("GIT_CONFIG_KEY_1", "user.email")
        .env("GIT_CONFIG_VALUE_1", "test@example.com");
}

/// Run `doctor --json --no-input` against `vault` with the given PATH and
/// extra environment. `CONFIDANT_OFFLINE=1` skips the release-tag fetch
/// (no network).
fn run_doctor(vault: &Path, path: &std::ffi::OsStr, extra_env: &[(&str, &str)]) -> Value {
    // A hermetic HOME: Windows CI runners don't set HOME, and without it
    // the config-dir checks error.
    let tmp_home = tempfile::tempdir().unwrap();
    run_doctor_home(vault, path, extra_env, tmp_home.path())
}

/// `run_doctor` with a caller-owned HOME, so #723 tests can seed a user
/// config there before doctor reads it.
fn run_doctor_home(
    vault: &Path,
    path: &std::ffi::OsStr,
    extra_env: &[(&str, &str)],
    home: &Path,
) -> Value {
    let mut cmd = Command::new(bin());
    cmd.args(["doctor", "--json", "--no-input", "--vault"])
        .arg(vault)
        .env("PATH", path)
        .env("CONFIDANT_OFFLINE", "1")
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_SKILLS_DIR");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    give_child_git_identity(&mut cmd);
    cmd.env("HOME", home);
    let out = cmd.output().unwrap();
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

#[test]
fn doctor_qmd_missing_from_path_is_ok() {
    let empty = tempfile::tempdir().unwrap();
    let v = run_doctor(&demo(), empty.path().as_os_str(), &[]);
    let c = check(&v, "qmd-search").expect("qmd-search check missing");
    // Informational: never warns or fails when qmd is optional.
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("not found on PATH"), "{msg}");
    assert!(msg.contains("confidant find"), "{msg}");
    assert!(msg.contains("npm install -g @tobilu/qmd"), "{msg}");
}

/// Fake `qmd` whose `status` output reports `$QMD_FAKE_VECTORS embedded`.
#[cfg(unix)]
fn write_fake_qmd(dir: &Path) {
    let script = dir.join("qmd");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         if [ \"$1\" = \"status\" ]; then\n\
         echo \"Vectors: ${QMD_FAKE_VECTORS:-0} embedded\"\n\
         fi\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
fn path_with_fake_qmd(dir: &Path) -> std::ffi::OsString {
    let mut path = std::ffi::OsString::from(dir);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap());
    path
}

#[cfg(unix)]
#[test]
fn doctor_qmd_present_without_corpus_points_at_the_skill() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_qmd(dir.path());
    // Throwaway vault copy with no `.confidant/qmd-corpus/`.
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = vault_dir.path().join("vault");
    common::copy_dir(&demo(), &vault);
    assert!(!vault.join(".confidant/qmd-corpus").exists());

    let v = run_doctor(&vault, &path_with_fake_qmd(dir.path()), &[]);
    let c = check(&v, "qmd-search").expect("qmd-search check missing");
    // #657: an installed qmd with no corpus is actionable, not "ok".
    assert_eq!(c["status"], "warning", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("corpus is missing"), "{msg}");
    assert!(msg.contains("qmd-search"), "{msg}");
    assert!(msg.contains("confidant find"), "{msg}");
    let fix = c["fix"].as_str().expect("fix field missing");
    assert!(fix.contains("confidant setup"), "{fix}");
}

#[cfg(unix)]
#[test]
fn doctor_qmd_corpus_without_vectors_points_at_skill_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_qmd(dir.path());
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = vault_dir.path().join("vault");
    common::copy_dir(&demo(), &vault);
    std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
    // The probe skips `qmd status` until the store exists (some qmd
    // versions create an empty index file as a side effect); a missing
    // store reports "no embedded vectors" without invoking qmd and
    // without creating the file.
    let v = run_doctor(
        &vault,
        &path_with_fake_qmd(dir.path()),
        &[("QMD_FAKE_VECTORS", "0")],
    );
    let c = check(&v, "qmd-search").expect("qmd-search check missing");
    // #666: keyword/BM25 search is healthy; semantic ranking is optional.
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("keyword (BM25) search ready"), "{msg}");
    assert!(msg.contains("semantic/hybrid"), "{msg}");
    assert!(
        !msg.contains("qmd embed"),
        "must not recommend a bare `qmd embed` (default store): {msg}"
    );
    let fix = c["fix"].as_str().expect("fix field missing");
    assert!(fix.contains("qmd-index.py"), "{fix}");
    assert!(fix.contains("--embed"), "{fix}");
    assert!(fix.contains("--vault"), "{fix}");
    assert!(fix.contains(&vault.display().to_string()), "{fix}");
    assert!(
        !vault.join(".confidant/qmd/index.sqlite").exists(),
        "probe must not create the index file"
    );
}

#[cfg(unix)]
#[test]
fn doctor_qmd_with_vectors_reports_ready() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_qmd(dir.path());
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = vault_dir.path().join("vault");
    common::copy_dir(&demo(), &vault);
    std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
    // The probe only runs once the store file exists.
    std::fs::create_dir_all(vault.join(".confidant/qmd")).unwrap();
    std::fs::write(vault.join(".confidant/qmd/index.sqlite"), b"fake").unwrap();

    let v = run_doctor(
        &vault,
        &path_with_fake_qmd(dir.path()),
        &[("QMD_FAKE_VECTORS", "12")],
    );
    let c = check(&v, "qmd-search").expect("qmd-search check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("12 embedded vectors"), "{msg}");
}

#[cfg(unix)]
#[test]
fn doctor_qmd_status_failure_does_not_point_at_embed() {
    let dir = tempfile::tempdir().unwrap();
    // Fake qmd whose `status` fails: the message must point at `qmd status`
    // for diagnosis, not at `qmd embed` (which would not fix a broken status).
    std::fs::write(dir.path().join("qmd"), "#!/bin/sh\nexit 1\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        dir.path().join("qmd"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = vault_dir.path().join("vault");
    common::copy_dir(&demo(), &vault);
    std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
    std::fs::create_dir_all(vault.join(".confidant/qmd")).unwrap();
    std::fs::write(vault.join(".confidant/qmd/index.sqlite"), b"fake").unwrap();

    let v = run_doctor(&vault, &path_with_fake_qmd(dir.path()), &[]);
    let c = check(&v, "qmd-search").expect("qmd-search check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("qmd status"), "{msg}");
    assert!(!msg.contains("qmd embed"), "{msg}");
}
