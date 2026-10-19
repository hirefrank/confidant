//! #659: `confidant tui` detects a `confidant-tui` version mismatch, and
//! `doctor` reports the installed TUI version.
//!
//! No test needs the real TUI: each one writes a fake `confidant-tui`
//! that answers `--version` and exits. All data is fake and no test
//! touches the network (`CONFIDANT_OFFLINE=1`).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

const LOCAL: &str = env!("CARGO_PKG_VERSION");

/// Fake `confidant-tui` that prints `$FAKE_TUI_VERSION` for `--version`
/// and, for a normal launch, writes `$FAKE_TUI_MARKER` (when set) and
/// prints `LAUNCHED`. A value without the `confidant-tui` prefix covers
/// the bare-version shape.
#[cfg(unix)]
fn write_fake_tui(dir: &Path) {
    let script = dir.join("confidant-tui");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then\n\
           echo \"${FAKE_TUI_VERSION:-confidant-tui 0.0.0}\"\n\
           exit 0\n\
         fi\n\
         if [ -n \"$FAKE_TUI_MARKER\" ]; then\n\
           echo launched > \"$FAKE_TUI_MARKER\"\n\
         fi\n\
         echo LAUNCHED\n\
         exit 0\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Fake `confidant-tui` whose `--version` never returns promptly, to prove
/// the doctor probe has a timeout.
#[cfg(unix)]
fn write_hung_tui(dir: &Path) {
    let script = dir.join("confidant-tui");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then\n\
           sleep 10\n\
           exit 0\n\
         fi\n\
         exit 0\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
fn path_with_fake_tui(dir: &Path) -> String {
    format!("{}:{}", dir.display(), std::env::var("PATH").unwrap())
}

/// A throwaway git identity, supplied through git's env config so CI
/// runners with no global `user.name`/`user.email` still resolve identity.
fn give_child_git_identity(cmd: &mut Command) {
    cmd.env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "Confidant Test")
        .env("GIT_CONFIG_KEY_1", "user.email")
        .env("GIT_CONFIG_VALUE_1", "test@example.com");
}

/// Run `doctor --json --no-input` with a PATH, a hermetic HOME, and extra
/// environment (e.g. `FAKE_TUI_VERSION`). `CONFIDANT_OFFLINE=1` skips the
/// release-tag fetch, so no test touches the network.
fn run_doctor(path: &str, extra_env: &[(&str, &str)]) -> Value {
    let tmp_home = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(bin());
    cmd.args(["doctor", "--json", "--no-input", "--vault"])
        .arg(demo())
        .env("PATH", path)
        .env("CONFIDANT_OFFLINE", "1")
        .env_remove("CONFIDANT_TEST_RELEASES_URL")
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_KEYCHAIN", "off")
        .env("HOME", tmp_home.path());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
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

fn check<'a>(v: &'a Value, id: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
}

#[cfg(unix)]
#[test]
fn tui_launch_warns_on_version_mismatch_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_tui(dir.path());
    let marker = dir.path().join("launched-marker");
    let out = Command::new(bin())
        .arg("tui")
        .env("PATH", path_with_fake_tui(dir.path()))
        .env("FAKE_TUI_VERSION", "confidant-tui 0.5.0")
        .env("FAKE_TUI_MARKER", &marker)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mixing versions must still launch: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(marker.exists(), "human mode must still launch the TUI");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("warning:"), "{stderr}");
    assert!(stderr.contains("confidant-tui 0.5.0"), "{stderr}");
    assert!(
        stderr.contains(&format!("confidant-cli {LOCAL}")),
        "{stderr}"
    );
    assert!(stderr.contains("cargo install confidant-tui"), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LAUNCHED"), "TUI did not launch: {stdout}");
}

#[cfg(unix)]
#[test]
fn tui_launch_accepts_bare_version_and_stays_quiet_when_matching() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_tui(dir.path());

    let out = Command::new(bin())
        .arg("tui")
        .env("PATH", path_with_fake_tui(dir.path()))
        // A bare version (no `confidant-tui` prefix) must parse too.
        .env("FAKE_TUI_VERSION", LOCAL)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("warning:"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn tui_json_reports_version_fields() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_tui(dir.path());
    let marker = dir.path().join("launched-marker");
    let out = Command::new(bin())
        .args(["tui", "--json"])
        .env("PATH", path_with_fake_tui(dir.path()))
        .env("FAKE_TUI_VERSION", "confidant-tui 0.5.0")
        .env("FAKE_TUI_MARKER", &marker)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Probe-only: the envelope must be the only stdout, with no child
    // output appended, and the TUI must not have started.
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not pure JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["tui_version"], "0.5.0", "{v}");
    assert_eq!(v["version_mismatch"], true, "{v}");
    assert_eq!(v["would_launch"], true, "{v}");
    assert!(
        !marker.exists(),
        "--json is probe-only; it must not launch the TUI"
    );
}

#[cfg(unix)]
#[test]
fn doctor_tui_version_probe_times_out_and_stays_ok() {
    let dir = tempfile::tempdir().unwrap();
    write_hung_tui(dir.path());
    let started = std::time::Instant::now();
    let v = run_doctor(&path_with_fake_tui(dir.path()), &[]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(6),
        "doctor must not wait on a hung --version: {elapsed:?}"
    );
    let c = check(&v, "tui-version").expect("tui-version check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("did not report a version"), "{msg}");
}

#[test]
fn doctor_tui_version_missing_is_ok() {
    let empty = tempfile::tempdir().unwrap();
    let v = run_doctor(empty.path().to_str().unwrap(), &[]);
    let c = check(&v, "tui-version").expect("tui-version check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("optional TUI not installed"), "{msg}");
    assert!(msg.contains("cargo install confidant-tui"), "{msg}");
    assert!(c.get("fix").is_none(), "healthy check must omit fix: {v}");
}

#[cfg(unix)]
#[test]
fn doctor_tui_version_mismatch_warns() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_tui(dir.path());
    let v = run_doctor(
        &path_with_fake_tui(dir.path()),
        &[("FAKE_TUI_VERSION", "confidant-tui 0.5.0")],
    );
    let c = check(&v, "tui-version").expect("tui-version check missing");
    assert_eq!(c["status"], "warning", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains("confidant-tui 0.5.0"), "{msg}");
    assert!(msg.contains(&format!("confidant-cli {LOCAL}")), "{msg}");
    let fix = c["fix"].as_str().expect("fix field missing");
    assert!(fix.contains("cargo install confidant-tui"), "{fix}");
}

#[cfg(unix)]
#[test]
fn doctor_tui_version_match_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_tui(dir.path());
    let version = format!("confidant-tui {LOCAL}");
    let v = run_doctor(
        &path_with_fake_tui(dir.path()),
        &[("FAKE_TUI_VERSION", version.as_str())],
    );
    let c = check(&v, "tui-version").expect("tui-version check missing");
    assert_eq!(c["status"], "ok", "{v}");
    let msg = c["message"].as_str().unwrap();
    assert!(msg.contains(&format!("confidant-tui {LOCAL}")), "{msg}");
    assert!(msg.contains(&format!("confidant-cli {LOCAL}")), "{msg}");
}
