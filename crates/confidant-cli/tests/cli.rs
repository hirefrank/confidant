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
