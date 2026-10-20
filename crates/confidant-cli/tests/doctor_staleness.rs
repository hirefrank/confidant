//! `doctor` staleness + skills-link checks.
//!
//! Only compiled with the `test-overrides` feature (CI's `--all-features`).
//! That feature is what lets `CONFIDANT_TEST_RELEASES_URL` point the check
//! at a local stub; without it the tests would be meaningless. No test here
//! touches the network, and all data is fake.

#![cfg(feature = "test-overrides")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// The version the binary reports, used to build deterministic stub tags.
const LOCAL: &str = env!("CARGO_PKG_VERSION");

/// The `ok` message the staleness check reports when `CONFIDANT_OFFLINE=1`
/// skips the fetch (kept in sync with `STALENESS_DISABLED` in the CLI).
const OFFLINE_MESSAGE: &str = "staleness check disabled (CONFIDANT_OFFLINE=1)";

/// A throwaway git identity, supplied to the child through git's
/// `GIT_CONFIG_COUNT`/`KEY`/`VALUE` environment. CI runners have no global
/// `user.name`/`user.email`, so without this the demo vault's `git-identity`
/// doctor check errors and flips `ok` to false. Fake values only.
fn give_child_git_identity(cmd: &mut Command) {
    cmd.env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "Confidant Test")
        .env("GIT_CONFIG_KEY_1", "user.email")
        .env("GIT_CONFIG_VALUE_1", "test@example.com");
}

/// One-shot HTTP stub returning `{"tag_name": "<tag>"}`. Returns the base
/// URL to point `CONFIDANT_TEST_RELEASES_URL` at. It answers exactly one
/// request (a doctor run fetches the tag once).
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

/// Like [`stub_release_server`], but accepts connections for a short window
/// and counts them, so a test can prove `CONFIDANT_OFFLINE=1` made no
/// request at all.
fn counting_stub_release_server(tag: &str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let body = serde_json::json!({ "tag_name": tag, "name": tag }).to_string();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    counter.fetch_add(1, Ordering::SeqCst);
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
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://127.0.0.1:{port}/"), hits)
}

/// Extra environment for a doctor child: optional `HOME` (agent detection),
/// `CONFIDANT_HOME` (share dir), `CONFIDANT_OFFLINE`, and process cwd.
#[derive(Default)]
struct DoctorEnv<'a> {
    home: Option<&'a str>,
    confidant_home: Option<&'a str>,
    offline: Option<&'a str>,
    cwd: Option<&'a std::path::Path>,
}

/// Run `doctor --json` against the demo vault with a clean test environment
/// plus the given overrides.
fn run_doctor_env(releases_url: Option<&str>, env: &DoctorEnv<'_>) -> Value {
    let mut cmd = Command::new(bin());
    cmd.args(["doctor", "--json", "--no-input", "--vault"])
        .arg(demo())
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_OFFLINE")
        .env_remove("CONFIDANT_SKILLS_DIR")
        // #541: the device-key check probes the keychain. Disable it so a
        // developer's real keychain is never touched (and the result is
        // deterministic on hosts with or without Secret Service).
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_KEYCHAIN", "off");
    give_child_git_identity(&mut cmd);
    if let Some(url) = releases_url {
        cmd.env("CONFIDANT_TEST_RELEASES_URL", url);
    }
    // A hermetic HOME: Windows CI runners don't set HOME, and without it
    // the crypto-manifests check errors (config dir unknown) and flips `ok`.
    let _tmp_home;
    if let Some(home) = env.home {
        cmd.env("HOME", home);
    } else {
        _tmp_home = tempfile::tempdir().unwrap();
        cmd.env("HOME", _tmp_home.path());
    }
    if let Some(home) = env.confidant_home {
        cmd.env("CONFIDANT_HOME", home);
    } else {
        // Reporter #681 used the default share dir (`$HOME/.local/share/confidant`).
        // Do not inherit a parent CONFIDANT_HOME.
        cmd.env_remove("CONFIDANT_HOME");
    }
    if let Some(offline) = env.offline {
        cmd.env("CONFIDANT_OFFLINE", offline);
    }
    if let Some(cwd) = env.cwd {
        cmd.current_dir(cwd);
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

fn run_doctor(releases_url: Option<&str>) -> Value {
    run_doctor_env(releases_url, &DoctorEnv::default())
}

fn check<'a>(v: &'a Value, id: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
}

/// Remove a skill entry regardless of shape: a file or directory symlink,
/// or a real directory (the `--copy` fallback when setup can't symlink).
/// `remove_file` unlinks both symlink kinds on unix.
fn remove_skill_entry(link: &std::path::Path) {
    if link.is_symlink() {
        std::fs::remove_file(link).unwrap();
    } else if link.is_dir() {
        std::fs::remove_dir_all(link).unwrap();
    } else {
        std::fs::remove_file(link).unwrap();
    }
}

/// Run `setup --agent <spec>` with the given `HOME`/`CONFIDANT_HOME`.
fn run_setup(home: &str, confidant_home: &str, agent: &str) {
    let mut cmd = Command::new(bin());
    cmd.args(["setup", "--agent", agent, "--no-input"])
        .env("HOME", home)
        .env("CONFIDANT_HOME", confidant_home)
        .env_remove("CONFIDANT_SKILLS_DIR");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `setup --agent auto` with an absolute HOME and **default** CONFIDANT_HOME
/// (unset), matching the #681 install-test host.
fn run_setup_default_share(home: &str, cwd: &std::path::Path, agent: &str) {
    let mut cmd = Command::new(bin());
    cmd.args(["setup", "--agent", agent, "--no-input"])
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("CONFIDANT_HOME")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_VAULT");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CLI staleness
// ---------------------------------------------------------------------------

#[test]
fn doctor_cli_current_is_ok() {
    let url = stub_release_server(&format!("v{LOCAL}"));
    let v = run_doctor(Some(&url));
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
    let v = run_doctor(Some(&url));
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
    let v = run_doctor(Some(&url));
    let c = check(&v, "cli-staleness").unwrap();
    assert_eq!(c["status"], "ok", "{v}");
}

#[test]
fn doctor_offline_degrades_to_ok_unknown() {
    let v = run_doctor(Some(&unreachable_url()));
    let c = check(&v, "cli-staleness").expect("cli-staleness check missing");
    assert_eq!(c["status"], "ok", "{v}");
    assert_eq!(
        c["message"], "staleness unknown (could not reach github releases)",
        "{c}"
    );
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_offline_disables_check_without_requesting() {
    // With CONFIDANT_OFFLINE=1 nothing is fetched and the check is disabled.
    let (url, hits) = counting_stub_release_server("v999.0.0");
    let v = run_doctor_env(
        Some(&url),
        &DoctorEnv {
            offline: Some("1"),
            ..Default::default()
        },
    );

    let cli = check(&v, "cli-staleness").expect("cli-staleness check missing");
    assert_eq!(cli["status"], "ok", "{v}");
    assert_eq!(cli["message"], OFFLINE_MESSAGE, "{cli}");

    assert_eq!(v["ok"], true, "{v}");

    // The stub increments on accept; offline must never connect.
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "CONFIDANT_OFFLINE=1 must make no request"
    );
}

// ---------------------------------------------------------------------------
// skills-links (setup-managed installs; no checkout, no CONFIDANT_REPO)
// ---------------------------------------------------------------------------

#[test]
fn doctor_git_version_reports_detected_version() {
    // The runner's real git is >= 2.34 (CI images ship 2.39+), so the
    // check is ok and names the detected version. Below-floor status
    // rules live in the unit tests (no way to fake the git binary here).
    let v = run_doctor(Some(&unreachable_url()));
    let c = check(&v, "git-version").expect("git-version check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(
        msg.starts_with("git 2."),
        "expected detected version: {msg}"
    );
    assert!(msg.contains("2.34.0"), "expected the floor: {msg}");
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_skills_links_no_agents_is_ok() {
    // A HOME with no agent dirs: nothing to link, so ok with a setup hint.
    let home = tempfile::tempdir().unwrap();
    let v = run_doctor_env(
        Some(&unreachable_url()),
        &DoctorEnv {
            home: Some(home.path().to_str().unwrap()),
            ..Default::default()
        },
    );
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "ok", "{v}");
    assert!(
        c["message"].as_str().unwrap().contains("setup"),
        "expected a setup hint: {c}"
    );
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_skills_links_after_setup_is_ok() {
    // setup --agent claude-code, then doctor: all skills linked.
    let home = tempfile::tempdir().unwrap();
    let home_str = home.path().to_str().unwrap().to_owned();
    let share = home.path().join("share");
    let share_str = share.to_str().unwrap().to_owned();
    run_setup(&home_str, &share_str, "claude-code");
    let v = run_doctor_env(
        Some(&unreachable_url()),
        &DoctorEnv {
            home: Some(&home_str),
            confidant_home: Some(&share_str),
            ..Default::default()
        },
    );
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("2/2"), "expected 2/2 linked: {msg}");
    assert!(msg.contains("claude-code"), "expected agent name: {msg}");
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_skills_links_never_targeted_is_ok() {
    // A detected agent dir that `setup` never targeted is reported, not
    // warned about: there is nothing stale, just nothing installed.
    let home = tempfile::tempdir().unwrap();
    let home_str = home.path().to_str().unwrap().to_owned();
    std::fs::create_dir_all(home.path().join(".claude/skills")).unwrap();
    let v = run_doctor_env(
        Some(&unreachable_url()),
        &DoctorEnv {
            home: Some(&home_str),
            ..Default::default()
        },
    );
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "ok", "{v}");
    assert!(
        c["message"]
            .as_str()
            .unwrap()
            .contains("confidant setup --agent auto"),
        "missing setup hint: {c}"
    );
}

#[test]
fn doctor_skills_links_missing_warns() {
    // A targeted agent with missing links warns with the fix command.
    let home = tempfile::tempdir().unwrap();
    let home_str = home.path().to_str().unwrap().to_owned();
    let share = tempfile::tempdir().unwrap();
    let share_str = share.path().to_str().unwrap().to_owned();
    run_setup(&home_str, &share_str, "claude-code");
    // Break one link: targeted but incomplete.
    remove_skill_entry(&home.path().join(".claude/skills/pack-author"));
    let v = run_doctor_env(
        Some(&unreachable_url()),
        &DoctorEnv {
            home: Some(&home_str),
            confidant_home: Some(&share_str),
            ..Default::default()
        },
    );
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "warning", "{v}");
    assert!(
        c["message"]
            .as_str()
            .unwrap()
            .contains("confidant setup --agent auto"),
        "missing fix command: {c}"
    );
    // Warning-only: missing links never flip doctor's overall ok.
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn doctor_skills_links_from_vault_cwd_agrees_with_agents() {
    // #681: setup and agents report 2/2, then doctor run from inside the
    // vault must not flip to 0/2. Skill dirs live under $HOME, not the vault.
    let home = tempfile::tempdir().unwrap();
    let home_str = home.path().to_str().unwrap().to_owned();
    let share = home.path().join("share");
    let share_str = share.to_str().unwrap().to_owned();
    run_setup(&home_str, &share_str, "claude-code");

    let mut agents = Command::new(bin());
    give_child_git_identity(&mut agents);
    let agents_out = agents
        .args(["agents", "--json", "--no-input"])
        .env("HOME", &home_str)
        .env("CONFIDANT_HOME", &share_str)
        .env_remove("CONFIDANT_SKILLS_DIR")
        .output()
        .unwrap();
    assert!(
        agents_out.status.success(),
        "agents failed: {}",
        String::from_utf8_lossy(&agents_out.stderr)
    );
    let agents_v: Value = serde_json::from_slice(&agents_out.stdout).unwrap();
    let claude = agents_v["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "claude-code")
        .expect("claude-code row");
    assert_eq!(claude["linked"], 2, "{agents_v}");
    assert_eq!(claude["total"], 2, "{agents_v}");

    let vault = demo();
    let v = run_doctor_env(
        Some(&unreachable_url()),
        &DoctorEnv {
            home: Some(&home_str),
            confidant_home: Some(&share_str),
            cwd: Some(vault.as_path()),
            ..Default::default()
        },
    );
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("2/2"), "doctor disagreed with agents: {msg}");
    assert!(msg.contains("claude-code"), "{msg}");
}

#[test]
fn doctor_skills_links_relative_symlinks_from_other_cwd() {
    // #681: even if the link target is relative (some tools rewrite
    // absolute symlinks), doctor from the vault cwd must still count it.
    let home = tempfile::tempdir().unwrap();
    let home_str = home.path().to_str().unwrap().to_owned();
    let share = home.path().join("share");
    let share_str = share.to_str().unwrap().to_owned();
    run_setup(&home_str, &share_str, "claude-code");

    let version = env!("CARGO_PKG_VERSION");
    let skills_parent = home.path().join(".claude/skills");
    for skill in ["pack-author", "qmd-search"] {
        let dest = skills_parent.join(skill);
        std::fs::remove_file(&dest).unwrap();
        let target = PathBuf::from("../../share/skills")
            .join(version)
            .join(skill);
        std::os::unix::fs::symlink(&target, &dest).unwrap();
    }

    let vault = demo();
    let v = run_doctor_env(
        Some(&unreachable_url()),
        &DoctorEnv {
            home: Some(&home_str),
            confidant_home: Some(&share_str),
            cwd: Some(vault.as_path()),
            ..Default::default()
        },
    );
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(
        msg.contains("2/2"),
        "relative skill links missed from vault cwd: {msg}"
    );
}

/// #681 reporter sequence: absolute `HOME=/…/box`, default (unset)
/// `CONFIDANT_HOME`, `setup --agent auto` → `agents` → `cd vault && doctor`
/// with no `--vault`. Skill dirs live under `$HOME`, share dir is
/// `$HOME/.local/share/confidant`.
#[test]
fn doctor_skills_links_reporter_sequence_absolute_home_default_share() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home").join("box");
    std::fs::create_dir_all(&home).unwrap();
    let home_str = home.to_str().unwrap().to_owned();
    assert!(
        std::path::Path::new(&home_str).is_absolute(),
        "HOME must be absolute to match the reporter: {home_str}"
    );
    std::fs::create_dir_all(home.join(".claude/skills")).unwrap();

    let vault = home.join("confidant-vault");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(
        vault.join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();
    let git_st = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&vault)
        .status()
        .unwrap();
    assert!(git_st.success(), "git init of throwaway vault failed");

    run_setup_default_share(&home_str, &home, "auto");

    let mut agents = Command::new(bin());
    give_child_git_identity(&mut agents);
    let agents_out = agents
        .args(["agents", "--json", "--no-input"])
        .current_dir(&home)
        .env("HOME", &home_str)
        .env_remove("CONFIDANT_HOME")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_VAULT")
        .output()
        .unwrap();
    assert!(
        agents_out.status.success(),
        "agents failed: {}",
        String::from_utf8_lossy(&agents_out.stderr)
    );
    let agents_v: Value = serde_json::from_slice(&agents_out.stdout).unwrap();
    let claude = agents_v["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "claude-code")
        .expect("claude-code row");
    assert_eq!(claude["linked"], 2, "{agents_v}");
    assert_eq!(claude["total"], 2, "{agents_v}");

    let mut doctor = Command::new(bin());
    give_child_git_identity(&mut doctor);
    doctor
        .args(["doctor", "--json", "--no-input"])
        .current_dir(&vault)
        .env("HOME", &home_str)
        .env_remove("CONFIDANT_HOME")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_VAULT")
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_KEYCHAIN", "off")
        .env("CONFIDANT_TEST_RELEASES_URL", unreachable_url());
    let out = doctor.output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); status={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let c = check(&v, "skills-links").expect("skills-links check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(
        msg.contains("2/2"),
        "doctor disagreed with agents on the reporter sequence: {msg}"
    );
    assert!(msg.contains("claude-code"), "{msg}");
}
