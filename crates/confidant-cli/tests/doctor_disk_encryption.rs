//! `doctor` `disk-encryption` check (#709).
//!
//! The check probes the host (Linux: `findmnt`/`lsblk`; elsewhere: no
//! probe), so no test can fix its outcome — on a VM/container root the
//! probe cannot run at all, on a laptop it may resolve either way. Every
//! assertion here is therefore host-shape independent: it pins the rule
//! that an undetermined check never renders `ok`, and that the human
//! rendering agrees with the `--json` status. Unit tests in the CLI
//! cover each probe shape against the pure decision function.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

fn doctor_cmd(json: bool, home: &std::path::Path) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("doctor");
    if json {
        cmd.arg("--json");
    }
    cmd.args(["--no-input", "--vault"])
        .arg(demo())
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env("CONFIDANT_KEYCHAIN", "off");
    // A throwaway git identity, supplied to the child through git's
    // `GIT_CONFIG_COUNT`/`KEY`/`VALUE` environment. CI runners have no
    // global `user.name`/`user.email`, so without this the demo vault's
    // `git-identity` doctor check errors and flips `ok` to false.
    // Fake values only.
    cmd.env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "Confidant Test")
        .env("GIT_CONFIG_KEY_1", "user.email")
        .env("GIT_CONFIG_VALUE_1", "test@example.com");
    // A hermetic HOME: Windows CI runners don't set HOME, and without it
    // the crypto-manifests check errors (config dir unknown) and flips `ok`.
    // The caller owns the tempdir so it outlives the child process.
    cmd.env("HOME", home);
    cmd.env_remove("CONFIDANT_HOME");
    cmd
}

fn run_doctor_json(home: &std::path::Path) -> Value {
    let out = doctor_cmd(true, home).output().unwrap();
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
fn doctor_disk_encryption_undetermined_is_never_ok() {
    // The rule, both directions, on whatever host runs the test: the
    // check is `unknown` exactly when it could not determine, and never
    // `ok` while undetermined.
    let home = tempfile::tempdir().unwrap();
    let v = run_doctor_json(home.path());
    let c = check(&v, "disk-encryption").expect("disk-encryption check missing");
    let undetermined = c["message"]
        .as_str()
        .unwrap()
        .contains("could not determine");
    if undetermined {
        assert_eq!(c["status"], "unknown", "{v}");
    } else {
        assert_ne!(c["status"], "unknown", "{v}");
        assert!(
            c["status"] == "ok" || c["status"] == "warning",
            "determined disk-encryption must be ok or warning: {c}"
        );
    }
}

#[test]
fn doctor_disk_encryption_human_matches_json() {
    // Human and `--json` renderings must agree, and an undetermined
    // human line must read `unknown`, not `ok` — the issue's shape.
    let home = tempfile::tempdir().unwrap();
    let v = run_doctor_json(home.path());
    let c = check(&v, "disk-encryption").expect("disk-encryption check missing");
    let json_status = c["status"].as_str().unwrap();
    let json_message = c["message"].as_str().unwrap();

    let out = doctor_cmd(false, home.path()).output().unwrap();
    assert!(
        out.status.success(),
        "doctor must exit 0 with no error checks: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("disk-encryption:"))
        .expect("disk-encryption line missing from human output");
    let human_status = line.split_whitespace().next().unwrap();
    assert_eq!(
        human_status, json_status,
        "human/JSON status disagree: {line}"
    );
    assert!(
        line.contains(json_message),
        "human line must carry the JSON message: {line}"
    );
    if json_message.contains("could not determine") {
        assert_eq!(human_status, "unknown", "{line}");
    }
}
