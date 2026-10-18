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
fn find_unreadable_ledger_is_command_error() {
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
    std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
    std::fs::write(dir.path().join("ledger/2026/08.cfd"), [0xff, 0xfe, 0xfd]).unwrap();
    let out = Command::new(bin())
        .args(["find", "anything", "--json", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_LEDGER_UNREADABLE");
    assert_eq!(v["error"]["message"], "1 items");
    assert!(v["error"].get("file").is_none(), "{v}");
    assert!(
        v["error"]["fix"]
            .as_str()
            .unwrap()
            .contains("run `confidant check` to locate it"),
        "{v}"
    );
    assert!(v.get("matches").is_none(), "{v}");
}

#[test]
fn missing_vault_json_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-vault");
    let out = Command::new(bin())
        .args([
            "check",
            "--json",
            "--no-input",
            "--vault",
            missing.to_str().unwrap(),
        ])
        .env_remove("CONFIDANT_VAULT")
        .env_remove("HOME")
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
                && f.get("file").is_none()
                && f.get("line").is_none()
                && f.get("id").is_none()
                && f.get("fix").is_none()
                && f["message"].as_str().unwrap().contains("items")
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

#[test]
fn allowlist_demo_excludes_no_ai() {
    let out = Command::new(bin())
        .args(["allowlist", "--json", "--no-input", "--vault"])
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
    assert!(v["vault"].as_str().unwrap().contains("demo-vault"));
    // Opaque paths and line numbers only: never content.
    let dumped = serde_json::to_string(&v).unwrap();
    assert!(!dumped.contains("Ada Example"), "{dumped}");
    let files: Vec<&str> = v["cleared_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    // Cleared: Ada's profile is in.
    assert!(
        files
            .iter()
            .any(|f| f == &"people/p-01M3TC5H00MPJG000000000000/profile.md"),
        "{files:?}"
    );
    // Uncleared: Cam Sample is no-ai, so none of their files are in.
    assert!(
        !files
            .iter()
            .any(|f| f.contains("p-01M3TC5H00MPJG001248000002")),
        "{files:?}"
    );
    // Ledger lines naming Cam (open line 4, session line 8, balance line 12
    // of ledger/2026/10.cfd) are out; every other line is in.
    let lines: Vec<u64> = v["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            assert_eq!(e["file"], "ledger/2026/10.cfd");
            e["line"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(lines, vec![1, 2, 3, 5, 6, 7, 9, 10, 11, 13], "{lines:?}");
}

#[test]
fn allowlist_unsupported_spec_is_command_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"9.9\"\nvault_id = \"x\"\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["allowlist", "--json", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_SPEC_UNSUPPORTED");
}

const ADA: &str = "p-01M3TC5H00MPJG000000000000";
const COACHING: &str = "coaching@0.1";

#[test]
fn find_scoped_to_coaching_hides_unattributed() {
    // "Kickoff" is in the session-linked (coaching) note; "Follow-up" is in
    // the unattributed note. A coaching-scoped find sees only the first.
    let out = Command::new(bin())
        .args(["find", "Follow-up", "--json", "--vault"])
        .arg(demo())
        .args(["--packs", COACHING])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["matches"], serde_json::json!([]));
    assert_eq!(v["scope"], serde_json::json!([COACHING]));

    let out = Command::new(bin())
        .args(["find", "Kickoff", "--json", "--vault"])
        .arg(demo())
        .args(["--packs", COACHING])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);

    // Unscoped still sees the unattributed note.
    let out = Command::new(bin())
        .args(["find", "Follow-up", "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    assert_eq!(v["scope"], serde_json::json!([COACHING, "personal@0.1"]));
}

#[test]
fn find_unknown_pack_is_usage_error() {
    // #232 acceptance: naming an unknown pack in --packs is a hard error.
    let out = Command::new(bin())
        .args(["find", "Ada", "--json", "--vault"])
        .arg(demo())
        .args(["--packs", "nope@1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "usage_error");
    assert!(v["error"]["message"].as_str().unwrap().contains("nope@1"));
}

#[test]
fn context_scoped_to_coaching_filters_notes_and_interactions() {
    let out = Command::new(bin())
        .args(["context", ADA, "--json", "--vault"])
        .arg(demo())
        .args(["--packs", COACHING])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    // Only the session-linked note; the unattributed note and the
    // interaction are hidden. Core identity stays.
    assert_eq!(v["notes"].as_array().unwrap().len(), 1);
    assert_eq!(v["notes"][0]["id"], "n-01M3TC5H00MPJG002NAM000005");
    assert_eq!(v["interactions"], serde_json::json!([]));
    assert_eq!(v["person"]["name"], "Ada Example");
    assert_eq!(v["scope"], serde_json::json!([COACHING]));
    assert!(v["coaching"].is_object());

    let out = Command::new(bin())
        .args(["context", ADA, "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["notes"].as_array().unwrap().len(), 2);
    assert_eq!(v["interactions"].as_array().unwrap().len(), 1);
}

#[test]
fn allowlist_scoped_annotates_owners() {
    let out = Command::new(bin())
        .args(["allowlist", "--json", "--no-input", "--vault"])
        .arg(demo())
        .args(["--packs", COACHING])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The unattributed note is out; the session-linked note stays.
    let files: Vec<&str> = v["cleared_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        !files.iter().any(|f| f.contains("0036CR000006")),
        "{files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("002NAM000005")),
        "{files:?}"
    );
    // Ownership annotations: core profile, coaching note.
    assert_eq!(
        v["owning_packs"]["people/p-01M3TC5H00MPJG000000000000/profile.md"],
        serde_json::json!(["core"])
    );
    assert_eq!(
        v["owning_packs"]
            ["people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md"],
        serde_json::json!([COACHING])
    );
    // Ledger lines: the comment line (line 1, unattributed) is out;
    // every other cleared line stays, each with owning_packs.
    let lines: Vec<u64> = v["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            assert!(e["owning_packs"].is_array(), "{e}");
            e["line"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(lines, vec![2, 3, 5, 6, 7, 9, 10, 11, 13], "{lines:?}");
    let balance = v["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["line"] == 10)
        .unwrap();
    assert_eq!(balance["owning_packs"], serde_json::json!([COACHING]));
    let alias = v["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["line"] == 5)
        .unwrap();
    assert_eq!(alias["owning_packs"], serde_json::json!(["core"]));
}

#[test]
fn find_edge_scoping_follows_kind() {
    // #179: an edge is visible exactly when its kind's pack is in scope.
    // A core-kind edge (married) is core-owned: visible to every scope.
    // An unknown-kind edge is unattributed: visible only unscoped.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"x\"\n",
    )
    .unwrap();
    let ada = "p-01M3TC5H00MPJG000000000000";
    let bea = "p-01M3TC5H00MPJG000H24000001";
    for (id, name) in [(ada, "Ada Example"), (bea, "Bea Demo")] {
        let d = dir.path().join(format!("people/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {id}\ntype: person\nname: {name}\n---\n\nFake person.\n"),
        )
        .unwrap();
    }
    let married = "e-01M3TC5H00MPJG00E100000000";
    let nemesis = "e-01M3TC5H00MPJG00E200000000";
    for (id, kind) in [(married, "married"), (nemesis, "nemesis")] {
        let d = dir.path().join(format!("edges/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("edge.md"),
            format!("---\nid: {id}\ntype: edge\na: {ada}\nb: {bea}\nkind: {kind}\n---\n"),
        )
        .unwrap();
    }
    let find = |needle: &str, packs: Option<&str>| {
        let mut cmd = Command::new(bin());
        cmd.args(["find", needle, "--json", "--vault"])
            .arg(dir.path());
        if let Some(p) = packs {
            cmd.args(["--packs", p]);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "stderr {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    // Core kind: visible unscoped and under a coaching scope.
    let v = find("married", None);
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    let v = find("married", Some(COACHING));
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    // Unknown kind: visible unscoped, hidden when scoped (fail closed).
    let v = find("nemesis", None);
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    let v = find("nemesis", Some(COACHING));
    assert_eq!(v["matches"], serde_json::json!([]));
}
#[test]
fn help_pack_coaching_serves_skill_text() {
    let out = Command::new(bin())
        .args(["help", "pack:coaching@0.1", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("# Coaching pack (coaching@0.1)"), "{text}");
    assert!(text.contains("E_OPEN_MALFORMED"), "{text}");
    assert!(text.contains("W_SESSION_UNTAGGED"), "{text}");
}

#[test]
fn help_pack_coaching_json_envelope() {
    let out = Command::new(bin())
        .args(["help", "pack:coaching@0.1", "--json", "--vault"])
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
    assert_eq!(v["packs"], serde_json::json!(["coaching@0.1"]));
    assert!(v["skill"].as_str().unwrap().contains("E_PAID_SESSION_GAP"));
}

#[test]
fn help_pack_bare_serves_combined_skill() {
    let out = Command::new(bin())
        .args(["help", "pack", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Packs in scope: coaching@0.1"), "{text}");
    assert!(text.contains("## coaching@0.1"), "{text}");
}

#[test]
fn help_pack_unknown_pack_is_not_found() {
    let out = Command::new(bin())
        .args(["help", "pack:nope@9.9", "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected failure");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_NOT_FOUND");
}

#[test]
fn help_pack_outside_scope_is_not_found() {
    // --packs names a disabled pack -> usage error before we get there.
    let out = Command::new(bin())
        .args([
            "help",
            "pack:coaching@0.1",
            "--packs",
            "nope@9.9",
            "--vault",
        ])
        .arg(demo())
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected failure");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_pack_needs_a_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["help", "pack:coaching@0.1"])
        .current_dir(tmp.path())
        .env_remove("CONFIDANT_VAULT")
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("need a vault"), "{stderr}");
}

#[test]
fn tui_help_lists_subcommand() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("tui"), "{help}");
}

#[test]
fn tui_subcommand_help_describes_passthrough() {
    let out = Command::new(bin())
        .args(["tui", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("confidant-tui"), "{help}");
}

#[test]
fn tui_missing_binary_prints_install_hint() {
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["tui"])
        .env("PATH", empty.path())
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cargo install confidant-tui"), "{stderr}");
    assert_eq!(
        stderr.lines().count(),
        1,
        "hint must be one line: {stderr:?}"
    );
}

#[test]
fn tui_missing_binary_json_error() {
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["tui", "--json"])
        .env("PATH", empty.path())
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected failure");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_TUI_NOT_FOUND");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("cargo install confidant-tui"));
}

/// Fake `confidant-tui` that records its argv and interesting env vars.
#[cfg(unix)]
fn write_fake_tui(dir: &std::path::Path) -> PathBuf {
    let record = dir.join("record.txt");
    let script = dir.join("confidant-tui");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             echo \"ARGS:$*\" >> '{}'\n\
             echo \"VAULT:$CONFIDANT_VAULT\" >> '{}'\n\
             echo \"CBIN:$CONFIDANT_BIN\" >> '{}'\n",
            record.display(),
            record.display(),
            record.display(),
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    record
}

#[cfg(unix)]
#[test]
fn tui_passes_through_args_and_env() {
    let dir = tempfile::tempdir().unwrap();
    let record = write_fake_tui(dir.path());
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap()
    );
    let out = Command::new(bin())
        .args(["tui", "--", "--vault", "somevault"])
        .env("PATH", &path)
        .env("CONFIDANT_VAULT", "envvault")
        .env("CONFIDANT_BIN", "envbin")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recorded = std::fs::read_to_string(&record).unwrap();
    assert!(
        recorded.contains("ARGS:--vault somevault"),
        "args not passed through: {recorded:?}"
    );
    assert!(
        recorded.contains("VAULT:envvault"),
        "CONFIDANT_VAULT not inherited: {recorded:?}"
    );
    assert!(
        recorded.contains("CBIN:envbin"),
        "CONFIDANT_BIN not inherited: {recorded:?}"
    );
}

#[cfg(unix)]
#[test]
fn tui_forwards_explicit_vault_flag() {
    let dir = tempfile::tempdir().unwrap();
    let record = write_fake_tui(dir.path());
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap()
    );
    let vault_dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .arg("--vault")
        .arg(vault_dir.path())
        .arg("tui")
        .env("PATH", &path)
        .env("CONFIDANT_VAULT", "envvault")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recorded = std::fs::read_to_string(&record).unwrap();
    assert!(
        recorded.contains(&format!("VAULT:{}", vault_dir.path().display())),
        "explicit --vault not forwarded (env should not win): {recorded:?}"
    );
}

/// Fake `confidant-tui` that exits `code`, written once and made executable
/// before it is ever run. The exit-code test must not rewrite an executable
/// script in place: on a loaded runner that can fail with ETXTBSY, and the
/// launcher then reports 1 instead of the child's code (#488).
#[cfg(unix)]
fn write_fake_tui_exit(dir: &std::path::Path, code: i32) {
    let script = dir.join("confidant-tui");
    std::fs::write(&script, format!("#!/bin/sh\nexit {code}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn tui_propagates_child_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_tui_exit(dir.path(), 3);
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap()
    );
    // A transient spawn failure on a loaded runner (e.g. EAGAIN) surfaces as
    // the launcher's exit 1, not the child's 3. Retry that case only; a real
    // propagation regression still fails every attempt. The assertion carries
    // stdout/stderr so the next failure says which one it was (#488).
    let mut out = None;
    for attempt in 0..3 {
        let o = Command::new(bin())
            .args(["tui"])
            .env("PATH", &path)
            .output()
            .unwrap();
        let code = o.status.code();
        out = Some(o);
        if code == Some(3) {
            break;
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    let out = out.unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "expected the TUI's exit code; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// #386: `find --json` carries an optional ranked-search hint only when qmd
// is on PATH and the corpus exists. Matches, ordering, and exit status
// never change.
#[cfg(unix)]
fn write_fake_qmd_for_find(dir: &std::path::Path) {
    std::fs::write(dir.join("qmd"), "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.join("qmd"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn find_json_hint_absent_without_qmd_or_corpus() {
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["find", "Ada Example", "--json", "--vault"])
        .arg(demo())
        .env("PATH", empty.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("hint").is_none(), "hint must be absent: {v}");
    assert!(v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| { m["excerpt"].as_str().unwrap().contains("Ada Example") }));
}

#[cfg(unix)]
#[test]
fn find_json_hint_present_with_qmd_and_corpus() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_qmd_for_find(dir.path());
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = vault_dir.path().join("vault");
    // Copy the demo vault so we can create a corpus dir without touching it.
    let demo = demo();
    std::fs::create_dir_all(&vault).unwrap();
    for entry in std::fs::read_dir(&demo).unwrap() {
        let entry = entry.unwrap();
        let dest = vault.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            let mut stack = vec![(entry.path(), dest)];
            while let Some((src, dst)) = stack.pop() {
                std::fs::create_dir_all(&dst).unwrap();
                for e in std::fs::read_dir(&src).unwrap().flatten() {
                    let d = dst.join(e.file_name());
                    if e.file_type().unwrap().is_dir() {
                        stack.push((e.path(), d));
                    } else {
                        std::fs::copy(e.path(), d).unwrap();
                    }
                }
            }
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
    std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap()
    );
    let out = Command::new(bin())
        .args(["find", "Ada Example", "--json", "--vault"])
        .arg(&vault)
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let hint = v["hint"].as_str().expect("hint present");
    assert!(hint.contains("qmd-search"), "{v}");
    // Matches unchanged by the hint.
    assert!(v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| { m["excerpt"].as_str().unwrap().contains("Ada Example") }));
}

#[cfg(unix)]
#[test]
fn find_text_hint_goes_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_qmd_for_find(dir.path());
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = vault_dir.path().join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    let demo = demo();
    for entry in std::fs::read_dir(&demo).unwrap() {
        let entry = entry.unwrap();
        let dest = vault.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            let mut stack = vec![(entry.path(), dest)];
            while let Some((src, dst)) = stack.pop() {
                std::fs::create_dir_all(&dst).unwrap();
                for e in std::fs::read_dir(&src).unwrap().flatten() {
                    let d = dst.join(e.file_name());
                    if e.file_type().unwrap().is_dir() {
                        stack.push((e.path(), d));
                    } else {
                        std::fs::copy(e.path(), d).unwrap();
                    }
                }
            }
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
    std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap()
    );
    let out = Command::new(bin())
        .args(["find", "Ada Example", "--vault"])
        .arg(&vault)
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("qmd-search"), "{stderr}");
}

// ---------------------------------------------------------------------------
// #439: `confidant pack add` (fetch, validate, review report; writes nothing)
// ---------------------------------------------------------------------------

/// A minimal valid v2 pack directory. Fake data only.
fn fake_pack_dir(extra: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("manifest.toml"),
        "manifest_version = 2\n\
         record_types = []\n\
         balance_metrics = []\n\
         finding_codes = [\"E_EXAMPLE_FIELD\"]\n\
         \n\
         [pack]\n\
         name = \"example-pack\"\n\
         version = \"0.1\"\n\
         skill = \"SKILL.md\"\n\
         requires_spec = [\"0.1\"]\n\
         \n\
         [messages.\"E_EXAMPLE_FIELD\"]\n\
         default = \"example field\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("SKILL.md"), "# Example pack skill.\n").unwrap();
    std::fs::write(dir.path().join("0.1.md"), "# Example pack contract.\n").unwrap();
    for (name, content) in extra {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }
    dir
}

/// A directory that is a git repo but not a vault: `pack add` needs no vault.
fn empty_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let st = Command::new("git")
        .current_dir(dir.path())
        .args(["init", "-q"])
        .status()
        .unwrap();
    assert!(st.success());
    dir
}

#[test]
fn pack_add_from_dir_prints_report_and_writes_nothing() {
    let pack = fake_pack_dir(&[]);
    let vault = empty_repo();

    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout {stdout}");
    assert!(stdout.contains("example-pack@0.1"), "{stdout}");
    assert!(stdout.contains("sha256:"), "{stdout}");
    assert!(stdout.contains("# Example pack skill."), "{stdout}");

    // Nothing was written: the vault repo is still clean and the pack dir
    // still has exactly its three files.
    let status = Command::new("git")
        .current_dir(vault.path())
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(
        status.stdout.is_empty(),
        "vault touched: {:?}",
        status.stdout
    );
    assert_eq!(std::fs::read_dir(pack.path()).unwrap().count(), 3);
}

#[test]
fn pack_add_json_has_claims_rules_files_and_skill_text() {
    let pack = fake_pack_dir(&[]);
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["command"], "pack-add");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["pack"]["name"], "example-pack");
    assert_eq!(v["pack"]["version"], "0.1");
    assert_eq!(v["pack"]["source"], "dir");
    assert_eq!(v["pack"]["rev"], "");
    assert!(v["pack"]["hash"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(
        v["claims"]["finding_codes"],
        serde_json::json!(["E_EXAMPLE_FIELD"])
    );
    assert_eq!(v["claims"]["verbs"], serde_json::json!([]));
    assert_eq!(v["rules"], serde_json::json!([]));
    let files = v["files"].as_array().unwrap();
    assert!(files.iter().any(|f| f["path"] == "SKILL.md"));
    assert_eq!(v["skill_text"], "# Example pack skill.\n");
}

#[test]
fn pack_add_rejects_non_https_schemes() {
    for url in [
        "http://example.invalid/x.git",
        "ssh://git@example.invalid/x.git",
        "git://example.invalid/x.git",
        "file:///tmp/x",
        "git@example.invalid:x/y.git",
    ] {
        let out = Command::new(bin())
            .args(["pack", "add", url, "--no-input"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{url}");
    }
}

#[test]
fn pack_add_rejects_credentials_in_url() {
    let out = Command::new(bin())
        .args([
            "pack",
            "add",
            "https://ada:hunter2@example.invalid/x.git",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("hunter2"), "password echoed: {stderr}");
}

#[test]
fn pack_add_invalid_pack_dir_exits_1() {
    // An extra executable-looking file is not in the PD7 allowlist, and a
    // subdirectory is refused outright: either way the pack is invalid.
    let pack = fake_pack_dir(&[("bin/run.sh", "#!/bin/sh\n")]);
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("E_PACK_INVALID"), "{stderr}");
}

#[test]
fn pack_add_escapes_control_characters_in_the_report() {
    // PD10 says the operator must see the full skill text. A conceal
    // sequence in SKILL.md must not be able to hide it.
    let pack = fake_pack_dir(&[]);
    std::fs::write(
        pack.path().join("SKILL.md"),
        "# Skill.\n\u{1b}[8mHIDDEN-BIO\u{1b}[0m\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains('\u{1b}'),
        "raw escape reached the terminal: {stdout:?}"
    );
    assert!(stdout.contains("HIDDEN-BIO"), "{stdout}");
}

#[test]
fn pack_add_non_utf8_skill_exits_1() {
    // The report must not say "(0 bytes)" while the vault would receive the
    // real bytes: fail closed instead.
    let pack = fake_pack_dir(&[]);
    std::fs::write(pack.path().join("SKILL.md"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("E_PACK_INVALID"), "{stderr}");
}
