use std::path::{Path, PathBuf};
use std::process::Command;

use confidant_core::packs::dir::read_pack_dir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// Recursively copy a directory tree (the demo vault) into `dst`.
#[cfg(unix)]
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
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
    // #551: the built-in personal pack is implicit (always enabled), but a
    // scoped read sees it only when the scope names it, so a coaching-only
    // ceiling sees coaching alone.
    assert_eq!(v["scope"], serde_json::json!([COACHING]));

    let out = Command::new(bin())
        .args(["find", "Kickoff", "--json", "--vault"])
        .arg(demo())
        .args(["--packs", COACHING])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);

    // Unscoped still sees the unattributed note and covers every enabled
    // pack, the implicit built-in personal pack included (#551).
    let out = Command::new(bin())
        .args(["find", "Follow-up", "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    assert_eq!(v["scope"], serde_json::json!([COACHING, "personal@0.2"]));
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
    // #551: a coaching-only ceiling excludes the implicit personal pack.
    assert_eq!(v["scope"], serde_json::json!([COACHING]));
    assert!(v["coaching"].is_object());
    assert!(v["packs"].get("personal@0.2").is_none());

    let out = Command::new(bin())
        .args(["context", ADA, "--json", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["notes"].as_array().unwrap().len(), 2);
    assert_eq!(v["interactions"].as_array().unwrap().len(), 1);
}

const BEA: &str = "p-01M3TC5H00MPJG000H24000001";
const EDGE_FRIEND: &str = "e-01M3TC5H00MPJG00E100000000";

/// A vault with personal-owned data — a personal field (`relationship`), a
/// personal edge kind (`friend`), and a `touch` ledger line — next to a
/// coaching pack listing. Used to prove that the implicit `personal@0.2`
/// built-in is visible to a scoped read only when the scope names it (#551).
fn personal_data_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "01M3TC5H00MPJG005VQC00000B"
[checks]
as_of = "2026-10-08"
"#,
    )
    .unwrap();
    for (id, name, extra) in [
        (ADA, "Ada Example", "relationship: climbing buddy\n"),
        (BEA, "Bea Demo", ""),
    ] {
        let d = dir.path().join(format!("people/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {id}\ntype: person\nname: {name}\n{extra}---\n\nFake person.\n"),
        )
        .unwrap();
    }
    let e = dir.path().join(format!("edges/{EDGE_FRIEND}"));
    std::fs::create_dir_all(&e).unwrap();
    std::fs::write(
        e.join("edge.md"),
        format!("---\nid: {EDGE_FRIEND}\ntype: edge\na: {ADA}\nb: {BEA}\nkind: friend\n---\n"),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
    std::fs::write(
        dir.path().join("ledger/2026/10.cfd"),
        format!("2026-10-06 touch {ADA} kind:call\n"),
    )
    .unwrap();
    dir
}

fn run_json(args: &[&str], vault: &Path) -> serde_json::Value {
    let out = Command::new(bin())
        .args(args)
        .arg("--json")
        .arg("--vault")
        .arg(vault)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn find_scope_excludes_personal_unless_named() {
    // #551: personal fields, personal edge kinds, and `touch` lines are
    // personal-owned, so a coaching-only ceiling hides them even though the
    // built-in pack is enabled in every vault.
    let dir = personal_data_vault();
    for (needle, label) in [
        ("climbing buddy", "personal field"),
        ("friend", "personal edge kind"),
        ("touch", "touch line"),
    ] {
        let coaching = run_json(&["find", needle, "--packs", COACHING], dir.path());
        assert_eq!(
            coaching["matches"].as_array().unwrap().len(),
            0,
            "coaching-only scope leaked a {label}: {coaching}"
        );
        assert_eq!(coaching["scope"], serde_json::json!([COACHING]));
        // Naming personal through the any-version alias puts it in scope.
        let personal = run_json(
            &["find", needle, "--packs", "coaching@0.1,personal@0.1"],
            dir.path(),
        );
        assert_eq!(
            personal["matches"].as_array().unwrap().len(),
            1,
            "personal-naming scope hid a {label}: {personal}"
        );
        assert_eq!(
            personal["scope"],
            serde_json::json!([COACHING, "personal@0.2"])
        );
    }
}

#[test]
fn context_scope_excludes_personal_unless_named() {
    // #551: the personal `context` view and the person's touchpoints are
    // personal-owned. A coaching-only ceiling drops both; naming personal
    // (at any version) brings the view and the touch line back.
    let dir = personal_data_vault();
    let coaching = run_json(&["context", ADA, "--packs", COACHING], dir.path());
    assert!(
        coaching["packs"].get("personal@0.2").is_none(),
        "{coaching}"
    );
    assert_eq!(coaching["touchpoints"], serde_json::json!([]));
    assert!(coaching["coaching"].is_object());
    assert_eq!(coaching["scope"], serde_json::json!([COACHING]));

    let personal = run_json(&["context", ADA, "--packs", "personal@0.1"], dir.path());
    assert_eq!(
        personal["packs"]["personal@0.2"]["relationship"],
        "climbing buddy"
    );
    assert_eq!(
        personal["touchpoints"],
        serde_json::json!([{"date": "2026-10-06", "kind": "call"}])
    );
    assert_eq!(personal["scope"], serde_json::json!(["personal@0.2"]));
}

/// #589: `context --json` marks `cadence: never` with `cadence_never: true`
/// (and omits it otherwise), so the CLI agent path can tell the deliberate
/// never-nudge apart from "no cadence set" — both of which omit
/// `cadence_days`.
#[test]
fn context_json_marks_cadence_never() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01M3TC5H00MPJG005VQC00000C\"\n[checks]\nas_of = \"2026-10-08\"\n",
    )
    .unwrap();
    const CAM: &str = "p-01M3TC5H00MPJG000000000002";
    for (id, name, extra) in [
        (ADA, "Ada Example", "cadence: never\n"),
        (BEA, "Bea Demo", "cadence: 30d\n"),
        (
            CAM,
            "Cam Sample",
            "no-ai: true\ntitle: Hidden Title\ncadence: never\n",
        ),
    ] {
        let d = dir.path().join(format!("people/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {id}\ntype: person\nname: {name}\n{extra}---\n\nFake person.\n"),
        )
        .unwrap();
    }

    let never = run_json(&["context", ADA], dir.path());
    assert_eq!(
        never["packs"]["personal@0.2"]["cadence_never"], true,
        "{never}"
    );
    assert!(
        never["packs"]["personal@0.2"].get("cadence_days").is_none(),
        "{never}"
    );

    let numeric = run_json(&["context", BEA], dir.path());
    assert_eq!(
        numeric["packs"]["personal@0.2"]["cadence_days"], 30,
        "{numeric}"
    );
    assert!(
        numeric["packs"]["personal@0.2"]
            .get("cadence_never")
            .is_none(),
        "{numeric}"
    );

    // §12: a `no-ai` person keeps the derived cadence state (`cadence_never`
    // included, like `cadence_days`) but no declared field.
    let no_ai = run_json(&["context", CAM], dir.path());
    let view = &no_ai["packs"]["personal@0.2"];
    assert!(view.get("title").is_none(), "{no_ai}");
    assert_eq!(view["cadence_never"], true, "{no_ai}");
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

/// A minimal valid v2 manifest for the external help fixture.
const EXTERNAL_HELP_MANIFEST: &str = "manifest_version = 2\n\
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
     default = \"example field\"\n";

/// A non-git vault with `example-pack@0.1` vendored, pinned and enabled,
/// plus the vendored skill text. Fake data only.
fn external_help_vault() -> (tempfile::TempDir, String) {
    external_help_vault_with_source("https://example.invalid/org/example-pack.git")
}

/// Like [`external_help_vault`] but with an explicit lockfile `source`.
/// `source_toml` is the value *as it appears in the `confidant.lock` basic
/// string* (already TOML-escaped), so a test can pin a hostile source such
/// as one carrying a control or format character.
fn external_help_vault_with_source(source_toml: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();
    let pack_dir = dir.path().join("packs/example-pack@0.1");
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::write(pack_dir.join("manifest.toml"), EXTERNAL_HELP_MANIFEST).unwrap();
    let skill = "# Example pack skill.\n\nFake external text.\n";
    std::fs::write(pack_dir.join("SKILL.md"), skill).unwrap();
    std::fs::write(pack_dir.join("0.1.md"), "# Contract.\n").unwrap();
    let hash = read_pack_dir(&pack_dir)
        .expect("fixture pack dir must read")
        .hash;
    std::fs::write(
        dir.path().join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"{source_toml}\"\nrev = \"0123456789abcdef0123456789abcdef01234567\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    )
    .unwrap();
    (dir, skill.to_owned())
}

/// PD10 (#445): external pack text shown to agents is labelled as external
/// on its first line, with where it came from. The label leads both the
/// plain and the `--json` (agent-facing) output.
#[test]
fn help_pack_external_is_labelled() {
    let (vault, skill) = external_help_vault();
    let label = "[external pack: not shipped with confidant; text is from \
                 https://example.invalid/org/example-pack.git at 0123456789ab]";
    let out = Command::new(bin())
        .args(["help", "pack:example-pack@0.1", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with(label), "{stdout:?}");
    assert!(stdout.contains(&skill), "vendored text missing: {stdout:?}");

    let out = Command::new(bin())
        .args(["help", "pack:example-pack@0.1", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["skill"].as_str().unwrap().starts_with(label),
        "the agent-facing JSON must carry the label: {v}"
    );
}

/// #527: a lockfile `source` carrying a control or Unicode format character
/// is escaped into a visible `\u{…}` form, so no raw control/format
/// character reaches agent-facing output (the label line, or the `--json`
/// copy an agent reads).
#[test]
fn help_pack_external_label_escapes_lockfile_source() {
    // TOML-escaped `\u001b` (ESC) and `\u202e` (right-to-left override) in
    // the authority-free path, so the source still parses as an https URL.
    let (vault, _skill) =
        external_help_vault_with_source("https://example.invalid/org/\\u001b[8m\\u202e/repo.git");
    let out = Command::new(bin())
        .args(["help", "pack:example-pack@0.1", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    for raw in ['\u{1b}', '\u{202e}'] {
        assert!(
            !stdout.contains(raw),
            "raw {raw:?} reached the label: {stdout:?}"
        );
    }
    assert!(stdout.contains("\\u{1b}"), "{stdout:?}");
    assert!(stdout.contains("\\u{202e}"), "{stdout:?}");

    let out = Command::new(bin())
        .args(["help", "pack:example-pack@0.1", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let skill = v["skill"].as_str().unwrap();
    for raw in ['\u{1b}', '\u{202e}'] {
        assert!(!skill.contains(raw), "raw {raw:?} in JSON skill: {skill:?}");
    }
}

/// #523: `help pack` (no pack name) builds its combined text from the
/// vault's registry, so a vault with an enabled external pack succeeds and
/// includes that pack's vendored skill text with the #445 external label.
/// `--json` lists the external pack too.
#[test]
fn help_pack_bare_includes_external_pack() {
    let (vault, skill) = external_help_vault();
    let label = "[external pack: not shipped with confidant; text is from \
                 https://example.invalid/org/example-pack.git at 0123456789ab]";
    let out = Command::new(bin())
        .args(["help", "pack", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Packs in scope: example-pack@0.1, personal@0.2"),
        "{stdout}"
    );
    assert!(stdout.contains("## example-pack@0.1"), "{stdout}");
    assert!(
        stdout.contains(&format!("## example-pack@0.1\n\n{label}\n")),
        "{stdout}"
    );
    assert!(stdout.contains(&skill), "vendored text missing: {stdout}");

    let out = Command::new(bin())
        .args(["help", "pack", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(
        v["packs"],
        serde_json::json!(["example-pack@0.1", "personal@0.2"])
    );
    let combined = v["skill"].as_str().unwrap();
    assert!(combined.contains(label), "{v}");
    assert!(combined.contains(&skill), "{v}");
}

/// PD10 (#445) acceptance: a compiled pack's skill output is unchanged
/// byte for byte — it ships with the binary, so it gets no label.
#[test]
fn help_pack_compiled_is_unlabelled() {
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
    let stdout = String::from_utf8(out.stdout).unwrap();
    let shipped = include_str!("../pack-skills/coaching/SKILL.md");
    assert!(!stdout.starts_with("[external pack:"), "{stdout:?}");
    assert_eq!(
        stdout,
        format!("{shipped}\n"),
        "compiled skill output must be byte-identical to the shipped text"
    );
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
    assert!(
        text.contains("Packs in scope: coaching@0.1, personal@0.2"),
        "{text}"
    );
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

/// A v2 manifest whose claim names and skill prose carry hostile text:
/// a bidi override, a bidi isolate, a newline in a field name and an ANSI
/// conceal sequence. Fake data only (#499).
#[cfg(unix)]
fn hostile_pack_dir() -> tempfile::TempDir {
    let bidi = '\u{202e}';
    let isolate = '\u{2066}';
    let escape = '\u{1b}';
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("manifest.toml"),
        format!(
            "manifest_version = 2\n\
             record_types = [\"bad{bidi}record\"]\n\
             balance_metrics = [\"bad{bidi}metric\"]\n\
             finding_codes = [\"E_FRONTMATTER\", \"W_EXAMPLE_UNSAFE\"]\n\
             \n\
             [pack]\n\
             name = \"example-pack\"\n\
             version = \"0.1\"\n\
             skill = \"SKILL.md\"\n\
             requires_spec = [\"0.1\"]\n\
             \n\
             [[verbs]]\n\
             name = \"greet\"\n\
             id_type = \"person\"\n\
             \n\
             [[fields]]\n\
             name = \"bad{bidi}\\nfield\"\n\
             grammar = \"non-empty-string\"\n\
             \n\
             [[fields]]\n\
             name = \"birthday\"\n\
             grammar = \"recurring-date\"\n\
             \n\
             [[edge_kinds]]\n\
             name = \"buddy\"\n\
             symmetric = true\n\
             \n\
             [[checks.severity]]\n\
             key = \"example-pack.bad{bidi}key\"\n\
             default = \"warning\"\n\
             \n\
             [messages.\"E_FRONTMATTER\"]\n\
             default = \"front matter\"\n\
             \n\
             [messages.\"W_EXAMPLE_UNSAFE\"]\n\
             default = \"unsafe\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("SKILL.md"),
        format!("# Skill\nline{isolate}two\nhidden{escape}[8mtext\n"),
    )
    .unwrap();
    std::fs::write(dir.path().join("0.1.md"), "# Contract\n").unwrap();
    std::fs::write(dir.path().join(format!("README-{bidi}evil")), "x").unwrap();
    std::fs::write(dir.path().join(format!("README-{escape}hidden")), "x").unwrap();
    dir
}

#[cfg(unix)]
#[test]
fn pack_add_escapes_untrusted_report_text_and_lists_every_claim() {
    let pack = hostile_pack_dir();
    let bidi = '\u{202e}';
    let isolate = '\u{2066}';
    let escape = '\u{1b}';
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout {stdout}\nstderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for raw in [bidi, isolate, escape] {
        assert!(
            !stdout.contains(raw),
            "raw {raw:?} reached the report:\n{stdout}"
        );
    }
    // One-line values are escaped, including the newline in a field name.
    assert!(stdout.contains("bad\\u{202e}\\nfield"), "{stdout}");
    assert!(stdout.contains("bad\\u{202e}record"), "{stdout}");
    assert!(stdout.contains("bad\\u{202e}metric"), "{stdout}");
    assert!(stdout.contains("example-pack.bad\\u{202e}key"), "{stdout}");
    // PD10: the full claim list, not just counts.
    assert!(stdout.contains("greet (person)"), "{stdout}");
    assert!(stdout.contains("birthday (recurring-date)"), "{stdout}");
    assert!(stdout.contains("buddy (symmetric)"), "{stdout}");
    assert!(stdout.contains("E_FRONTMATTER"), "{stdout}");
    assert!(stdout.contains("W_EXAMPLE_UNSAFE"), "{stdout}");
    // File names and skill prose are escaped too.
    assert!(stdout.contains("README-\\u{202e}evil"), "{stdout}");
    assert!(stdout.contains("line\\u{2066}two"), "{stdout}");

    // The JSON review payload is escaped as well: an agent reading it must
    // see the same markers, not raw bidi.
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let raw = String::from_utf8_lossy(&out.stdout);
    for forbidden in [bidi, isolate, escape] {
        assert!(
            !raw.contains(forbidden),
            "raw {forbidden:?} reached the JSON report:\n{raw}"
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["claims"]["fields"],
        serde_json::json!(["bad\\u{202e}\\nfield", "birthday"])
    );
    assert_eq!(
        v["claims"]["record_types"],
        serde_json::json!(["bad\\u{202e}record"])
    );
    let files = v["files"].as_array().unwrap();
    assert!(
        files.iter().any(|f| f["path"] == "README-\\u{202e}evil"),
        "{files:?}"
    );
    let skill = v["skill_text"].as_str().unwrap();
    assert!(skill.contains("line\\u{2066}two"), "{skill:?}");
    assert!(
        skill.contains('\n'),
        "prose newlines must survive: {skill:?}"
    );
}

#[cfg(unix)]
#[test]
fn pack_add_escapes_untrusted_errors() {
    let bidi = '\u{202e}';
    // An unallowed file name: the reader quotes it in the error.
    let pack = fake_pack_dir(&[]);
    std::fs::write(pack.path().join(format!("evil{bidi}.txt")), "x").unwrap();
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(bidi), "raw bidi in stderr: {stderr}");
    assert!(stderr.contains("\\u{202e}"), "{stderr}");
    assert!(stderr.contains("not an allowed pack file"), "{stderr}");

    // A manifest error that quotes an untrusted skill name.
    let pack = tempfile::tempdir().unwrap();
    std::fs::write(
        pack.path().join("manifest.toml"),
        format!(
            "manifest_version = 2\n\
             record_types = []\n\
             balance_metrics = []\n\
             finding_codes = []\n\
             \n\
             [pack]\n\
             name = \"example-pack\"\n\
             version = \"0.1\"\n\
             skill = \"evil{bidi}..\"\n\
             requires_spec = [\"0.1\"]\n\
             \n\
             [messages]\n"
        ),
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(bidi), "raw bidi in stderr: {stderr}");
    assert!(stderr.contains("\\u{202e}"), "{stderr}");
    assert!(stderr.contains("plain file name"), "{stderr}");
}

// #440: applying, listing, verifying updating and removing packs.

/// Run git in `dir`, asserting success; returns stdout.
#[cfg(unix)]
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A minimal git vault with an empty `packs` list and a comment to preserve.
#[cfg(unix)]
fn git_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\n# keep this comment above packs\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();
    git(dir.path(), &["init", "-q"]);
    // The write layer checks the repo's identity before committing; CI has no
    // global git identity, so set it locally.
    git(dir.path(), &["config", "user.name", "Test"]);
    git(
        dir.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    git(dir.path(), &["add", "-A"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "init",
        ],
    );
    dir
}

/// A minimal valid v2 pack directory at `name@version`, optionally claiming
/// `verb` (to provoke a conflict) and with `skill` as the SKILL.md body.
#[cfg(unix)]
fn versioned_pack(name: &str, version: &str, skill: &str, verb: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let verbs = match verb {
        Some(v) => format!("\n[[verbs]]\nname = \"{v}\"\nid_type = \"person\"\n"),
        None => String::new(),
    };
    std::fs::write(
        dir.path().join("manifest.toml"),
        format!(
            "manifest_version = 2\n\
             record_types = []\n\
             balance_metrics = []\n\
             finding_codes = [\"E_FRONTMATTER\"]\n\
             \n\
             [pack]\n\
             name = \"{name}\"\n\
             version = \"{version}\"\n\
             skill = \"SKILL.md\"\n\
             requires_spec = [\"0.1\"]\n\
             {verbs}\n\
             [messages.\"E_FRONTMATTER\"]\n\
             default = \"front matter\"\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.path().join("SKILL.md"), skill).unwrap();
    std::fs::write(
        dir.path().join(format!("{version}.md")),
        format!("# Contract {version}\n"),
    )
    .unwrap();
    dir
}

#[cfg(unix)]
fn pack_add(pack: &Path, vault: &Path, yes: bool) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.args(["pack", "add", "--from-dir"])
        .arg(pack)
        .arg("--vault")
        .arg(vault);
    if yes {
        cmd.arg("--yes");
    }
    cmd.arg("--no-input").output().unwrap()
}

/// Drop `id` from the vault's `packs = [...]` listing. The PD12 pre-check
/// keys on the listing, so a removal/update test can unlist the pack to
/// isolate the path under test (#529 item 1).
#[cfg(unix)]
fn unlist_pack(vault: &std::path::Path, id: &str) {
    let path = vault.join("confidant.toml");
    let cfg = std::fs::read_to_string(&path).unwrap();
    let updated = cfg.replace(&format!("packs = [\"{id}\"]"), "packs = []");
    assert_ne!(updated, cfg, "pack {id} was not listed; config:\n{cfg}");
    std::fs::write(&path, updated).unwrap();
}

#[cfg(unix)]
#[test]
fn pack_add_without_yes_changes_nothing() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    let out = pack_add(pack.path(), vault.path(), false);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("nothing was written"), "{stdout}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), "1\n");
    assert!(!vault.path().join("packs").exists());
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

#[cfg(unix)]
#[test]
fn pack_add_yes_vendors_locks_and_commits() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill v1\n", None);
    let out = pack_add(pack.path(), vault.path(), true);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("committed"), "{stdout}");

    let names = git(vault.path(), &["show", "--name-only", "--format=", "HEAD"]);
    for expected in [
        "confidant.lock",
        "confidant.toml",
        "packs/example-pack@0.1/manifest.toml",
        "packs/example-pack@0.1/SKILL.md",
        "packs/example-pack@0.1/0.1.md",
    ] {
        assert!(names.contains(expected), "missing {expected} in {names}");
    }
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");

    // The comment above `packs` survives `toml_edit` (#440).
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("keep this comment above packs"), "{cfg}");
    assert!(cfg.contains("packs = [\"example-pack@0.1\"]"), "{cfg}");

    // verify / list / check agree it is installed and clean.
    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(verify.status.success(), "{verify:?}");
    let list = Command::new(bin())
        .args(["pack", "list", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["packs"][0]["name"], "example-pack");
    assert_eq!(v["packs"][0]["status"], "ok");
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");

    // Same pin, same bytes: idempotent, no new commit.
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = pack_add(pack.path(), vault.path(), true);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already installed"));
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
}

#[cfg(unix)]
#[test]
fn pack_add_same_version_different_hash_refused() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# one\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    std::fs::write(pack.path().join("SKILL.md"), "# two\n").unwrap();
    let out = pack_add(pack.path(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("different hash"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn pack_add_refuses_reserved_names() {
    let vault = git_vault();
    // `coaching` is reserved for the compiled pack (PD14).
    let pack = versioned_pack("coaching", "0.9", "# nope\n", None);
    let out = pack_add(pack.path(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("reserved"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), "1\n");
}

/// #449: the on-disk parity fixture installs as a real external pack on a
/// copy of the demo vault, and the vault then checks clean. The copy swaps
/// compiled coaching for the fixture: both claim `open`/`session`, so a
/// vault enabling both is `E_PACK_CONFLICT`. The compiled `coaching.*`
/// check keys are dropped; the fixture's manifest defaults are the same
/// values, and the core parity tests cover the `coaching-ext.*` keys.
#[cfg(unix)]
#[test]
fn declarative_coaching_cli_install_then_check_clean() {
    let vault = tempfile::tempdir().unwrap();
    copy_tree(&demo(), vault.path());
    let config = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    let config: String = config
        .replace("packs = [\"coaching@0.1\"]", "packs = []")
        .lines()
        .filter(|line| !line.trim_start().starts_with("coaching."))
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(vault.path().join("confidant.toml"), config).unwrap();
    git(vault.path(), &["init", "-q"]);
    git(vault.path(), &["config", "user.name", "Test"]);
    git(
        vault.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    git(vault.path(), &["add", "-A"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "init",
        ],
    );

    let pack_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/coaching-ext");
    let out = pack_add(&pack_dir, vault.path(), true);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // `pack verify` accepts the vendored fixture...
    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // ...and `check` is clean under the external pack.
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["findings"], serde_json::json!([]), "{v}");
}

#[cfg(unix)]
#[test]
fn pack_add_check_failure_rolls_back() {
    let vault = git_vault();
    // coaching@0.1 owns the `session` verb; a pack claiming it conflicts.
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();
    git(vault.path(), &["add", "-A"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "enable coaching",
        ],
    );
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let pack = versioned_pack("example-pack", "0.1", "# conflict\n", Some("session"));
    let out = pack_add(pack.path(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    // Rolled back: no vendored files, no lock, packs list unchanged, tree clean.
    assert!(!vault
        .path()
        .join("packs/example-pack@0.1/manifest.toml")
        .exists());
    assert!(!vault.path().join("confidant.lock").exists());
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

#[cfg(unix)]
#[test]
fn pack_update_shows_diff_then_applies_a_version_change() {
    let vault = git_vault();
    let v1 = versioned_pack("example-pack", "0.1", "# one\n", None);
    let v2 = versioned_pack("example-pack", "0.2", "# two\n", None);
    assert!(pack_add(v1.path(), vault.path(), true).status.success());
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);

    // Without --yes: the diff is printed, nothing changes.
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(v2.path())
        .arg("--vault")
        .arg(vault.path())
        .arg("--no-input")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("-version = \"0.1\""), "{stdout}");
    assert!(stdout.contains("+version = \"0.2\""), "{stdout}");
    assert!(stdout.contains("pass --yes"), "{stdout}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);

    // With --yes: re-vendored at 0.2, old dir gone, one pin.
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(v2.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    // Exactly one commit for the apply: the delete+rewrite change list must
    // not double-commit (regression guard for #602).
    let after: u32 = git(vault.path(), &["rev-list", "--count", "HEAD"])
        .trim()
        .parse()
        .unwrap();
    assert_eq!(after, before.trim().parse::<u32>().unwrap() + 1);
    assert!(vault
        .path()
        .join("packs/example-pack@0.2/SKILL.md")
        .exists());
    assert!(!vault.path().join("packs/example-pack@0.1").exists());
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = [\"example-pack@0.2\"]"), "{cfg}");
    let lock = std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap();
    assert_eq!(lock.matches("[[pack]]").count(), 1, "{lock}");
    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(verify.status.success(), "{verify:?}");
}

#[cfg(unix)]
#[test]
fn pack_update_escapes_the_diff() {
    // A fetched pack file is untrusted: ANSI and bidi in its SKILL.md must
    // not be able to hide or reorder the lines the operator reviews before
    // `--yes` (PD10).
    let vault = git_vault();
    let v1 = versioned_pack("example-pack", "0.1", "# harmless\n", None);
    assert!(pack_add(v1.path(), vault.path(), true).status.success());
    let bidi = '\u{202e}';
    let escape = '\u{1b}';
    let v2 = versioned_pack(
        "example-pack",
        "0.2",
        &format!("# Skill\nhidden{escape}[8mtext{escape}[0m\n{bidi}reordered\n"),
        None,
    );
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(v2.path())
        .arg("--vault")
        .arg(vault.path())
        .arg("--no-input")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("pass --yes"), "{stdout}");
    assert!(
        !stdout.contains(escape),
        "raw ESC in the reviewed diff: {stdout:?}"
    );
    assert!(
        !stdout.contains(bidi),
        "raw bidi in the reviewed diff: {stdout:?}"
    );
    assert!(stdout.contains("\\u{1b}"), "{stdout}");
    assert!(stdout.contains("\\u{202e}"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn pack_update_same_version_replaces_content() {
    // A same-version update is the case where `DeleteFile` and `WriteBytes`
    // hit the same path in one change set.
    let vault = git_vault();
    let v1 = versioned_pack("example-pack", "0.1", "# one\n", None);
    assert!(pack_add(v1.path(), vault.path(), true).status.success());
    let v1b = versioned_pack("example-pack", "0.1", "# one changed\n", None);
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(v1b.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let skill =
        std::fs::read_to_string(vault.path().join("packs/example-pack@0.1/SKILL.md")).unwrap();
    assert_eq!(skill, "# one changed\n");
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(verify.status.success(), "{verify:?}");
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
}

/// #602: re-applying the identical source must be a clean no-op, the same
/// as `pack add --yes` on an already-installed pack. Before the fix this was
/// an `internal_error` with an empty git message and exit 1.
#[cfg(unix)]
#[test]
fn pack_update_noop_is_unchanged_with_exit_0() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);

    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(pack.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["unchanged"], true, "{v}");
    assert!(
        v["error"].is_null(),
        "a no-op update must not be an error: {v}"
    );

    // No new commit, and nothing staged: the tree is untouched.
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #606: a stale lock hash with an otherwise current tree must not be
/// reported unchanged. The stale pin is an `E_PACK_HASH` error to the
/// pre-check, so this exercises the repair path; the post-check still gates
/// the commit.
#[cfg(unix)]
#[test]
fn pack_update_repairs_a_stale_lock_hash() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());

    let lock_path = vault.path().join("confidant.lock");
    let good = std::fs::read_to_string(&lock_path).unwrap();
    let good_hash = good
        .lines()
        .find_map(|line| line.strip_prefix("hash = \"sha256:"))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("pack add wrote a hash");
    let stale = if good_hash.starts_with('0') { "1" } else { "0" }.repeat(64);
    let stale_lock = good.replace(&format!("sha256:{good_hash}"), &format!("sha256:{stale}"));
    assert_ne!(stale_lock, good);
    std::fs::write(&lock_path, &stale_lock).unwrap();
    // Commit the planted pin so the starting point is a clean tree: the diff
    // under test must be the one repair commit.
    git(vault.path(), &["add", "confidant.lock"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "plant stale pin",
        ],
    );

    // The scenario is real: `check` flags the stale pin before the update.
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "E_PACK_HASH"),
        "{v}"
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(pack.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["unchanged"].is_null(), "a stale pin is not a no-op: {v}");
    assert_eq!(v["files"], serde_json::json!(["confidant.lock"]), "{v}");

    // The lock is byte-identical to the pin `pack add` wrote, exactly one
    // commit landed, and the tree is clean.
    assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), good);
    let after: u32 = git(vault.path(), &["rev-list", "--count", "HEAD"])
        .trim()
        .parse()
        .unwrap();
    assert_eq!(after, before.trim().parse::<u32>().unwrap() + 1);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");

    // The repair leaves the vault clean.
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
}

/// #587: a non-regular entry inside the vendored tree must still be refused
/// before any delete is queued. The no-op short-circuit (#602) is reached
/// only after the tree is proven diffable, so it cannot let this through.
#[cfg(unix)]
#[test]
fn pack_update_refuses_a_symlinked_file_in_the_vendored_tree() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());

    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim.txt");
    std::fs::write(&victim, "keep me\n").unwrap();
    let vendored = vault.path().join("packs/example-pack@0.1");
    std::os::unix::fs::symlink(&victim, vendored.join("evil.txt")).unwrap();
    git(vault.path(), &["add", "-A"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "plant symlink",
        ],
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(pack.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot diff"), "{stderr}");
    // No partial apply: the pack's own files survive, the symlink target is
    // untouched, and nothing was committed.
    assert!(vendored.join("SKILL.md").is_file(), "SKILL.md was deleted");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me\n");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

#[cfg(unix)]
#[test]
fn pack_update_from_dir_notes_a_lock_source_change() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# one\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    // Pretend the pack was installed from git, then update it from a
    // directory: the lock source becomes `dir`, which must be reported.
    let lock_path = vault.path().join("confidant.lock");
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    let lock = lock
        .replace(
            "source = \"dir\"",
            "source = \"https://example.invalid/pack.git\"",
        )
        .replace("rev = \"\"", &format!("rev = \"{rev}\""));
    std::fs::write(&lock_path, &lock).unwrap();
    git(vault.path(), &["add", "-A"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "pin from git",
        ],
    );

    let updated = versioned_pack("example-pack", "0.2", "# two\n", None);
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(updated.path())
        .arg("--vault")
        .arg(vault.path())
        .arg("--no-input")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("lock source changes"), "{stdout}");
    assert!(
        stdout.contains("https://example.invalid/pack.git"),
        "{stdout}"
    );

    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(updated.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["source_changed"], true, "{v}");
}

#[cfg(unix)]
#[test]
fn pack_add_refuses_a_second_version_of_the_same_name() {
    let vault = git_vault();
    let v1 = versioned_pack("example-pack", "0.1", "# one\n", None);
    let v2 = versioned_pack("example-pack", "0.2", "# two\n", None);
    assert!(pack_add(v1.path(), vault.path(), true).status.success());
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = pack_add(v2.path(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("0.1"), "{stderr}");
    assert!(stderr.contains("pack update"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert!(!vault.path().join("packs/example-pack@0.2").exists());
}

/// #529 item 2: `pack update` must not hand a symlinked vendored tree to
/// `git diff --no-index`, which follows symlinks and would read content from
/// outside the vault into the review. The no-follow check makes it "cannot
/// diff".
#[cfg(unix)]
#[test]
fn pack_update_refuses_to_diff_a_symlinked_vendored_dir() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());

    // Replace the vendored tree with a symlink to a *valid* pack outside the
    // vault: `git diff --no-index` would read it and show its text.
    let outside = versioned_pack("example-pack", "0.1", "# OUTSIDE-SECRET\n", None);
    let vendored = vault.path().join("packs/example-pack@0.1");
    std::fs::remove_dir_all(&vendored).unwrap();
    std::os::unix::fs::symlink(outside.path(), &vendored).unwrap();

    let updated = versioned_pack("example-pack", "0.2", "# two\n", None);
    let out = Command::new(bin())
        .args(["pack", "update", "example-pack", "--from-dir"])
        .arg(updated.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("OUTSIDE-SECRET"),
        "the diff read content from outside the vault: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot diff"), "{stderr}");
}

/// #529 item 3: `pack list`/`pack verify` classify with the no-follow
/// helpers, so a symlinked vendored tree is `invalid` (not read and not
/// silently `missing`).
#[cfg(unix)]
#[test]
fn pack_list_reports_a_symlinked_tree_invalid() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());

    let outside = versioned_pack("example-pack", "0.1", "# otherwise valid\n", None);
    let vendored = vault.path().join("packs/example-pack@0.1");
    std::fs::remove_dir_all(&vendored).unwrap();
    std::os::unix::fs::symlink(outside.path(), &vendored).unwrap();

    let list = Command::new(bin())
        .args(["pack", "list", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["packs"][0]["status"], "invalid", "{v}");

    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(1), "{verify:?}");

    // An absent tree is still `missing`, not `invalid`.
    std::fs::remove_file(&vendored).unwrap();
    let list = Command::new(bin())
        .args(["pack", "list", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["packs"][0]["status"], "missing", "{v}");
}

#[cfg(unix)]
#[test]
fn pack_remove_refuses_a_symlinked_pack_dir() {
    // A synced vault can plant `packs/<id>` as a symlink out of the vault.
    // Removal must refuse to follow it and must never delete the files it
    // points at (#440). The pack is unlisted first so the PD12 pre-check
    // cannot mask the delete path (#529 item 1).
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    unlist_pack(vault.path(), "example-pack@0.1");

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("victim.txt"), "keep me\n").unwrap();
    let vendored = vault.path().join("packs/example-pack@0.1");
    std::fs::remove_dir_all(&vendored).unwrap();
    std::os::unix::fs::symlink(outside.path(), &vendored).unwrap();

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(outside.path().join("victim.txt")).unwrap(),
        "keep me\n",
        "a file outside the vault was deleted"
    );
    // Nothing was committed and the lockfile still pins the pack.
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    let lock = std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap();
    assert!(lock.contains("[[pack]]"), "{lock}");
}

/// #529 item 1: a symlinked file *inside* the vendored tree is refused
/// before any delete is queued, so the refusal never leaves a half-deleted
/// pack: the pack's other files survive and the working tree stays clean.
/// The test fails if that refusal is bypassed (the delete path would remove
/// `SKILL.md`/`manifest.toml` and change `git status`).
#[cfg(unix)]
#[test]
fn pack_remove_refuses_a_symlinked_file_in_a_pack_dir() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    unlist_pack(vault.path(), "example-pack@0.1");

    // The tree itself is a real directory, so listing succeeds. Commit the
    // planted symlink (a synced vault is the threat model) so `git status`
    // can prove the refusal changed nothing at all.
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim.txt");
    std::fs::write(&victim, "keep me\n").unwrap();
    let vendored = vault.path().join("packs/example-pack@0.1");
    std::os::unix::fs::symlink(&victim, vendored.join("evil.txt")).unwrap();
    git(vault.path(), &["add", "-A"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "plant symlink",
        ],
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "the symlinked entry must be refused, stdout {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "keep me\n",
        "a file outside the vault was deleted"
    );
    // The refusal happens before any delete is queued: the pack's own files
    // survive and the working tree is untouched.
    assert!(
        vendored.join("SKILL.md").is_file(),
        "SKILL.md was deleted by a partial apply"
    );
    assert!(
        vendored.join("manifest.toml").is_file(),
        "manifest.toml was deleted by a partial apply"
    );
    assert_eq!(
        git(vault.path(), &["status", "--porcelain"]),
        "",
        "the refusal left the vault dirty"
    );
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    let lock = std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap();
    assert!(lock.contains("[[pack]]"), "{lock}");
}

#[cfg(unix)]
#[test]
fn pack_remove_yes_deletes_files_lock_and_entry() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());

    // Dry run first: nothing changes.
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .arg("--no-input")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("would remove"));
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);

    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!vault
        .path()
        .join("packs/example-pack@0.1/SKILL.md")
        .exists());
    let lock = std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap();
    assert!(!lock.contains("[[pack]]"), "{lock}");
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = []"), "{cfg}");
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
}

#[cfg(unix)]
#[test]
fn pack_list_and_verify_report_tampering() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());

    // Healthy: verify exits 0.
    let ok = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));

    // Tampered: verify exits 1, list reports the status, check reports the code.
    std::fs::write(
        vault.path().join("packs/example-pack@0.1/SKILL.md"),
        "# tampered\n",
    )
    .unwrap();
    let bad = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1), "{bad:?}");
    let list = Command::new(bin())
        .args(["pack", "list", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["packs"][0]["status"], "tampered");
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&check.stdout).contains("E_PACK_HASH"),
        "{check:?}"
    );
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

/// #445 (PD7/PD8): packs ship text and data only. A pack carrying a script
/// file is refused at install (`pack add --from-dir`) and at load
/// (`check` over an already-vendored pack) — both `E_PACK_INVALID`, and
/// install writes nothing.
#[cfg(unix)]
#[test]
fn external_pack_with_script_file_rejected_at_load_and_install() {
    let vault = git_vault();
    let pack = fake_pack_dir(&[("run.sh", "#!/bin/sh\n")]);
    let out = pack_add(pack.path(), vault.path(), true);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("E_PACK_INVALID"), "{stderr}");
    assert!(
        !vault.path().join("packs").exists(),
        "a refused pack must not be vendored"
    );
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), "1\n");

    // Load side: vendor the same pack behind a well-formed pin and run
    // `check`, which refuses the script and folds nothing.
    let vendored = tempfile::tempdir().unwrap();
    std::fs::write(
        vendored.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();
    let dst = vendored.path().join("packs/example-pack@0.1");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(pack.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
    }
    std::fs::write(
        vendored.path().join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"sha256:{}\"\n",
            "0".repeat(64)
        ),
    )
    .unwrap();
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vendored.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    let invalid = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "E_PACK_INVALID")
        .unwrap_or_else(|| panic!("script file must be E_PACK_INVALID: {v}"));
    assert_eq!(
        invalid["file"], "packs/example-pack@0.1",
        "the finding points at the vendored path: {v}"
    );
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

// ---------------------------------------------------------------------------
// record list (#558): the operator-only roster
// ---------------------------------------------------------------------------

fn demo_roster(args: &[&str]) -> serde_json::Value {
    let out = Command::new(bin())
        .args(["record", "list", "--json", "--no-input", "--vault"])
        .arg(demo())
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn roster_names(v: &serde_json::Value) -> Vec<&str> {
    v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect()
}

#[test]
fn record_list_demo_is_the_cleared_set_in_name_order() {
    let v = demo_roster(&[]);
    // ADR-7 envelope: resolved vault path, ok, schema version.
    assert_eq!(v["ok"], true);
    assert_eq!(v["schema_version"], "1");
    assert!(v["vault"].as_str().unwrap().contains("demo-vault"));
    assert_eq!(v["kind"], "person");
    assert_eq!(v["for_operator"], false);
    assert_eq!(v["skipped_encrypted"], 0);
    assert_eq!(v["refused_envelopes"], 0);
    // Deterministic: display name, case-insensitive.
    assert_eq!(roster_names(&v), vec!["Ada Example", "Bea Demo"]);
    for entry in v["records"].as_array().unwrap() {
        assert_eq!(entry["no_ai"], "false");
        assert_eq!(entry["kind"], "person");
        assert!(entry["id"].as_str().unwrap().starts_with("p-"));
    }
}

#[test]
fn record_list_demo_for_operator_adds_no_ai_with_tri_state() {
    let v = demo_roster(&["--for-operator"]);
    assert_eq!(v["for_operator"], true);
    assert_eq!(
        roster_names(&v),
        vec!["Ada Example", "Bea Demo", "Cam Sample"]
    );
    let cam = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Cam Sample")
        .expect("no-ai person must be listed with the operator flag");
    assert_eq!(cam["no_ai"], "true");
    assert_eq!(cam["kind"], "person");
}

#[test]
fn record_list_kind_filters() {
    let orgs = demo_roster(&["--kind", "org"]);
    assert_eq!(orgs["kind"], "org");
    assert_eq!(roster_names(&orgs), vec!["Northwind Training Co"]);
    assert_eq!(orgs["records"][0]["kind"], "org");

    let deals = demo_roster(&["--kind", "deal"]);
    assert_eq!(roster_names(&deals), vec!["Discovery workshop"]);
    assert_eq!(deals["records"][0]["kind"], "deal");
}

#[test]
fn record_list_packs_scope_is_reported_and_fails_closed() {
    // The scope is echoed and validated, like `find` / `context`. Roster
    // entries are core-owned identity records, so a narrower scope does not
    // remove them today.
    let v = demo_roster(&["--packs", "coaching@0.1"]);
    assert_eq!(v["scope"], serde_json::json!(["coaching@0.1"]));
    assert_eq!(roster_names(&v), vec!["Ada Example", "Bea Demo"]);

    // Unknown or disabled pack: usage error, exit 2 (ADR-7).
    let out = Command::new(bin())
        .args(["record", "list", "--json", "--no-input", "--vault"])
        .arg(demo())
        .args(["--packs", "nope@9.9"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "usage_error");
}

#[test]
fn record_list_orders_by_name_then_id_and_falls_back_to_id() {
    // Same display name twice plus an unnamed record: the id breaks the
    // name tie, and an unnamed record renders its opaque id.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    for (id, name_line) in [
        ("p-01J9Z3K4QF0000000000000001", "name: Ada Example\n"),
        ("p-01J9Z3K4QF0000000000000002", "name: ada example\n"),
        ("p-01J9Z3K4QF0000000000000003", ""),
    ] {
        let d = dir.path().join("people").join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {id}\ntype: person\n{name_line}---\n\n"),
        )
        .unwrap();
    }
    let out = Command::new(bin())
        .args(["record", "list", "--json", "--no-input", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "p-01J9Z3K4QF0000000000000001",
            "p-01J9Z3K4QF0000000000000002",
            "p-01J9Z3K4QF0000000000000003",
        ],
        "{v}"
    );
    // The unnamed record's name is its id, never null.
    assert_eq!(v["records"][2]["name"], "p-01J9Z3K4QF0000000000000003");
}

#[test]
fn record_list_text_output_lists_one_entry_per_line() {
    let out = Command::new(bin())
        .args(["record", "list", "--no-input", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Ada Example"), "{text}");
    assert!(text.contains("Bea Demo"), "{text}");
    assert!(text.contains("2 people (person)"), "{text}");
    // The no-ai person is absent without the flag.
    assert!(!text.contains("Cam Sample"), "{text}");
}

#[test]
fn record_list_text_output_escapes_control_characters_in_names() {
    // A tab or ESC in a display name must not break the one-entry-per-line
    // layout or reach the terminal raw. `--json` keeps the name verbatim.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    let id = "p-01J9Z3K4QF0000000000000001";
    let name = "Ada\tEx\u{1b}[8mample";
    let d = dir.path().join("people").join(id);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("profile.md"),
        format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n---\n\n"),
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["record", "list", "--no-input", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains('\u{1b}'),
        "raw escape reached stdout: {text:?}"
    );
    assert!(
        !text.contains("Ada\tEx"),
        "raw tab in a name broke the layout: {text:?}"
    );
    assert!(text.contains("Ada\\tEx\\u{1b}[8mample"), "{text:?}");
    // One entry line plus the summary line: the name's tab did not split it.
    assert!(text.lines().count() <= 3, "{text:?}");

    let out = Command::new(bin())
        .args(["record", "list", "--json", "--no-input", "--vault"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["records"][0]["name"], name, "--json must stay verbatim");
}

// ---------------------------------------------------------------------------
// find / context --for-operator (#572)
// ---------------------------------------------------------------------------

/// Cam Sample is the demo vault's `no-ai: true` person.
const CAM: &str = "p-01M3TC5H00MPJG001248000002";
/// Cam's note, hidden from agents by inheriting the person's `no-ai: true`.
const CAM_NOTE: &str = "n-01M3TC5H000068T0000000000C";
const OPERATOR_BANNER: &str = "OPERATOR MODE";

fn run_text(args: &[&str], vault: &Path) -> String {
    let out = Command::new(bin())
        .args(args)
        .arg("--vault")
        .arg(vault)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// #572: `find --for-operator` includes `no-ai` records the default path
/// hides; every operator record hit carries the tri-state `no_ai`. Without
/// the flag, matches are as before and no hit has the key.
#[test]
fn find_demo_for_operator_includes_no_ai_with_tri_state() {
    // "model provider" is only in Cam's (no-ai) note body.
    let default = run_json(&["find", "model provider"], &demo());
    assert_eq!(default["matches"], serde_json::json!([]));
    assert!(default.get("for_operator").is_none(), "{default}");
    // Agent hits never carry `no_ai`.
    let agent_ada = run_json(&["find", "Ada Example"], &demo());
    assert!(agent_ada["matches"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m.get("no_ai").is_none()));

    let op = run_json(&["find", "model provider", "--for-operator"], &demo());
    assert_eq!(op["for_operator"], true);
    let hit = op["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == CAM_NOTE)
        .expect("no-ai note must be found with the operator flag");
    // The note has no flag of its own; it is hidden by inheritance, so the
    // badge reports `"true"`, not `"false"`.
    assert_eq!(hit["no_ai"], "true");
    assert!(hit["excerpt"].as_str().unwrap().contains("model provider"));

    // A cleared record is badged `"false"` in operator mode.
    let op_ada = run_json(&["find", "Ada Example", "--for-operator"], &demo());
    assert!(op_ada["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["no_ai"] == "false"));
}

/// #593: an operator-only ledger hit carries `operator_only: true`; a ledger
/// hit an agent can see too does not, and the agent JSON has no such key.
#[test]
fn find_demo_for_operator_marks_operator_only_ledger_hits() {
    // Cam's session line names the `no-ai` person and their note, so the
    // agent path hides it entirely.
    let default = run_json(&["find", "2026-10-07"], &demo());
    assert_eq!(default["matches"], serde_json::json!([]));

    let op = run_json(&["find", "2026-10-07", "--for-operator"], &demo());
    let ledger = op["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["path"].as_str().unwrap().starts_with("ledger/"))
        .expect("Cam's session line must be an operator hit");
    assert_eq!(ledger["operator_only"], true);
    assert!(ledger.get("no_ai").is_none(), "{ledger}");
    // Record hits keep the tri-state and never gain the ledger marker.
    let record = op["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == CAM_NOTE)
        .expect("the no-ai note must be an operator hit");
    assert_eq!(record["no_ai"], "true");
    assert!(record.get("operator_only").is_none(), "{record}");

    // A ledger line naming cleared people is visible to both paths: no
    // marker, and the agent JSON never has the key.
    let agent_alias = run_json(&["find", "alias"], &demo());
    assert!(agent_alias["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["path"].as_str().unwrap().starts_with("ledger/")));
    assert!(agent_alias["matches"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m.get("operator_only").is_none()));
    let op_alias = run_json(&["find", "alias", "--for-operator"], &demo());
    let visible: Vec<_> = op_alias["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["path"].as_str().unwrap().starts_with("ledger/"))
        .collect();
    assert!(!visible.is_empty());
    assert!(visible.iter().all(|m| m.get("operator_only").is_none()));
}

/// #572: `context --for-operator` decrypts a `no-ai` person and their
/// notes, with the tri-state `no_ai` and `for_operator: true`. Without the
/// flag the output is unchanged: name withheld, notes absent, boolean flag.
#[test]
fn context_demo_for_operator_shows_no_ai_person_with_tri_state() {
    let default = run_json(&["context", CAM], &demo());
    assert!(default.get("for_operator").is_none(), "{default}");
    assert_eq!(default["person"]["no_ai"], true);
    assert!(default["person"]["name"].is_null());
    assert_eq!(default["notes"], serde_json::json!([]));
    let dumped = serde_json::to_string(&default).unwrap();
    assert!(!dumped.contains("Cam Sample"), "{dumped}");

    let op = run_json(&["context", CAM, "--for-operator"], &demo());
    assert_eq!(op["for_operator"], true);
    assert_eq!(op["person"]["name"], "Cam Sample");
    assert_eq!(op["person"]["no_ai"], "true");
    assert!(op["person"]["profile"]
        .as_str()
        .unwrap()
        .contains("Fake client"));
    let notes = op["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["id"], CAM_NOTE);
    assert_eq!(notes[0]["no_ai"], "true");
}

/// #572: human output prints an unmistakable operator banner for all three
/// commands, so a screen share cannot silently show hidden data. Without
/// the flag no banner appears.
#[test]
fn operator_mode_banner_labels_find_context_and_roster() {
    for args in [
        vec!["find", "model provider"],
        vec!["context", CAM],
        vec!["record", "list"],
    ] {
        let mut flagged = args.clone();
        flagged.push("--for-operator");
        flagged.push("--no-input");
        let text = run_text(&flagged, &demo());
        assert!(
            text.contains(OPERATOR_BANNER),
            "{flagged:?} missing the operator banner: {text}"
        );

        let plain = run_text(&args, &demo());
        assert!(
            !plain.contains(OPERATOR_BANNER),
            "{args:?} leaked the operator banner: {plain}"
        );
    }
}
