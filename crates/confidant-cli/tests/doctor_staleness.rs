//! #165: `doctor` staleness checks — local CLI + skills checkout vs the
//! latest GitHub Release.
//!
//! Only compiled with the `test-overrides` feature (CI's `--all-features`).
//! That feature is what lets `CONFIDANT_TEST_RELEASES_URL` point the check
//! at a local stub; without it the tests would be meaningless. No test here
//! touches the network, and all data is fake.

#![cfg(feature = "test-overrides")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// The version the binary reports, used to build deterministic stub tags.
const LOCAL: &str = env!("CARGO_PKG_VERSION");

/// One-shot HTTP stub returning `{"tag_name": "<tag>"}`. Returns the base
/// URL to point `CONFIDANT_TEST_RELEASES_URL` at. It answers exactly one
/// request (a doctor run fetches the tag once, shared by both checks).
fn stub_release_server(tag: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = serde_json::json!({ "tag_name": tag, "name": tag }).to_string();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}/")
}

/// A URL on loopback that nothing is listening on, so connecting is refused
/// immediately and the check degrades to "unknown" without waiting.
fn unreachable_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}/")
}

/// Run `doctor --json` against the demo vault with a clean test environment
/// plus the given overrides.
fn run_doctor(releases_url: Option<&str>, repo: Option<&str>) -> Value {
    let mut cmd = Command::new(bin());
    cmd.args(["doctor", "--json", "--no-input", "--vault"])
        .arg(demo())
        .env_remove("CONFIDANT_REPO")
        .env_remove("CONFIDANT_TEST_RELEASES_URL");
    if let Some(url) = releases_url {
        cmd.env("CONFIDANT_TEST_RELEASES_URL", url);
    }
    if let Some(repo) = repo {
        cmd.env("CONFIDANT_REPO", repo);
    }
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

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A throwaway git checkout carrying one release tag (fake data only).
fn fake_skills_checkout(tag: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    std::fs::write(root.join("README.md"), "fake skills checkout\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);
    git(root, &["tag", tag]);
    dir
}

// ---------------------------------------------------------------------------
// CLI staleness
// ---------------------------------------------------------------------------

#[test]
fn doctor_cli_current_is_ok() {
    let url = stub_release_server(&format!("v{LOCAL}"));
    let v = run_doctor(Some(&url), None);
    let c = check(&v, "cli-staleness").expect("cli-staleness check missing");
    assert_eq!(c["status"], "ok", "{v}");
    assert!(
        c["message"].as_str().unwrap().contains(LOCAL),
        "message should name the local version: {c}"
    );
}

#[test]
fn doctor_cli_behind_warns_with_versions() {
    let url = stub_release_server("v999.0.0");
    let v = run_doctor(Some(&url), None);
    let c = check(&v, "cli-staleness").expect("cli-staleness check missing");
    assert_eq!(c["status"], "warning", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains(LOCAL), "missing local version: {msg}");
    assert!(msg.contains("999.0.0"), "missing latest version: {msg}");
    assert!(
        msg.contains("cargo install confidant-cli"),
        "missing update command: {msg}"
    );
    // Warning-only: a stale CLI never flips doctor's overall ok/exit code.
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_cli_ahead_is_ok() {
    // A local dev build ahead of the last release is fine, not stale.
    let url = stub_release_server("v0.0.1");
    let v = run_doctor(Some(&url), None);
    let c = check(&v, "cli-staleness").unwrap();
    assert_eq!(c["status"], "ok", "{v}");
}

#[test]
fn doctor_offline_degrades_to_ok_unknown() {
    let v = run_doctor(Some(&unreachable_url()), None);
    let c = check(&v, "cli-staleness").expect("cli-staleness check missing");
    assert_eq!(c["status"], "ok", "{v}");
    assert_eq!(
        c["message"], "staleness unknown (could not reach github releases)",
        "{c}"
    );
    assert_eq!(v["ok"], true, "{v}");
}

// ---------------------------------------------------------------------------
// skills staleness
// ---------------------------------------------------------------------------

#[test]
fn doctor_skills_no_env_omits_check() {
    let url = stub_release_server(&format!("v{LOCAL}"));
    let v = run_doctor(Some(&url), None);
    assert!(
        check(&v, "skills-staleness").is_none(),
        "skills-staleness must be omitted when CONFIDANT_REPO is unset: {v}"
    );
}

#[test]
fn doctor_skills_tag_behind_warns() {
    let checkout = fake_skills_checkout("v0.1.0");
    let url = stub_release_server("v999.0.0");
    let v = run_doctor(Some(&url), Some(checkout.path().to_str().unwrap()));
    let c = check(&v, "skills-staleness").expect("skills-staleness check missing");
    assert_eq!(c["status"], "warning", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("v0.1.0"), "missing checkout tag: {msg}");
    assert!(msg.contains("v999.0.0"), "missing latest tag: {msg}");
    assert!(
        msg.contains("fetch --tags"),
        "missing update command: {msg}"
    );
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_skills_matching_tag_is_ok() {
    let checkout = fake_skills_checkout(&format!("v{LOCAL}"));
    let url = stub_release_server(&format!("v{LOCAL}"));
    let v = run_doctor(Some(&url), Some(checkout.path().to_str().unwrap()));
    let c = check(&v, "skills-staleness").expect("skills-staleness check missing");
    assert_eq!(c["status"], "ok", "{v}");
}

#[test]
fn doctor_skills_not_a_checkout_warns() {
    // A directory that is not a git checkout: the tag cannot be determined.
    let dir = tempfile::tempdir().unwrap();
    let url = stub_release_server(&format!("v{LOCAL}"));
    let v = run_doctor(Some(&url), Some(dir.path().to_str().unwrap()));
    let c = check(&v, "skills-staleness").expect("skills-staleness check missing");
    assert_eq!(c["status"], "warning", "{v}");
    assert!(
        c["message"].as_str().unwrap().contains("cannot determine"),
        "{c}"
    );
    assert_eq!(v["ok"], true, "{v}");
}
