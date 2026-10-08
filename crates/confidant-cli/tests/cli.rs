use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

#[test]
fn check_demo_json_ok() {
    let out = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["schema_version"], "1");
    assert_eq!(v["spec"], "0.1");
    assert!(v["vault"].as_str().unwrap().contains("demo-vault"));
    assert_eq!(v["findings"], serde_json::json!([]));
}

#[test]
fn find_demo_hits_fake_name() {
    let out = Command::new(bin())
        .args(["find", "Ada Example", "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["findings"], serde_json::json!([]));
    assert!(v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| { m["excerpt"].as_str().unwrap().contains("Ada Example") }));
}

#[test]
fn find_omits_no_ai_people() {
    let out = Command::new(bin())
        .args(["find", "Cam Sample", "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"], serde_json::json!([]));
}

#[test]
fn find_surfaces_load_findings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "x"
[checks]
as_of = "2026-10-08"
"#,
    )
    .unwrap();
    std::fs::write(dir.path().join(".confidant-tmp-leftover"), "tmp").unwrap();
    let out = Command::new(bin())
        .args(["find", "anything", "--json", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    let codes: Vec<_> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"E_INVALID_FILENAME"), "{codes:?}");
}

#[test]
fn missing_vault_json_error() {
    let out = Command::new(bin())
        .args([
            "check",
            "--json",
            "--no-input",
            "--vault",
            "/tmp/confidant-no-such-vault",
        ])
        .env_remove("CONFIDANT_VAULT")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["schema_version"], "1");
    assert_eq!(v["error"]["code"], "E_VAULT_NOT_FOUND");
}

#[test]
fn usage_error_is_exit_2() {
    let out = Command::new(bin())
        .args(["check", "--json", "--fail-on", "info"])
        .arg("--vault")
        .arg(demo())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn bad_as_of_is_usage_error() {
    let out = Command::new(bin())
        .args(["check", "--json", "--as-of", "2026-1-8", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "usage_error");
}

#[test]
fn find_json_findings_omit_raw_profile_text() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "x"
[checks]
as_of = "2026-10-08"
"#,
    )
    .unwrap();
    let people = dir.path().join("people/p-01M3TC5H00MPJG000000000000");
    std::fs::create_dir_all(&people).unwrap();
    std::fs::write(
        people.join("profile.md"),
        "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: unique-fm-secret-token\nno-ai: yes\n---\n\nunique-body-secret\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["find", "unique-fm-secret-token", "--json", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"], serde_json::json!([]));
    let dumped = serde_json::to_string(&v["findings"]).unwrap();
    assert!(!dumped.contains("unique-fm-secret-token"), "{dumped}");
    assert!(!dumped.contains("unique-body-secret"), "{dumped}");
    let findings = v["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| {
            f["code"] == "E_FRONTMATTER"
                && f["file"] == "people/p-01M3TC5H00MPJG000000000000/profile.md"
                && f.get("line").is_none()
                && f.get("id").is_none()
                && f.get("fix").is_none()
        }),
        "{findings:?}"
    );
}

#[test]
fn find_unsupported_spec_is_command_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"9.9\"\nvault_id = \"x\"\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["find", "anything", "--json", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_SPEC_UNSUPPORTED");
}
