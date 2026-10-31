use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::install_example_pack;
use confidant_core::packs::dir::read_pack_dir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// A local vault with one cleared person, one `no-ai: true` person, and
/// three ledger lines. Used by the privacy tests; the demo vault itself is
/// personal-only.
fn no_ai_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cleared = "p-01M3TC5H00MPJG000000000000";
    let hidden = "p-01M3TC5H00MPJG001248000002";
    let hidden_note = "n-01M3TC5H000068T0000000000C";
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01M3TC5H00MPJG005VQC00000B\"\n",
    )
    .unwrap();
    for (id, name, extra) in [
        (cleared, "Dana Example", ""),
        (hidden, "Cam Sample", "no-ai: true\n"),
    ] {
        std::fs::create_dir_all(root.join("people").join(id)).unwrap();
        std::fs::write(
            root.join("people").join(id).join("profile.md"),
            format!("---\nid: {id}\ntype: person\nname: {name}\n{extra}---\n\nFake person.\n"),
        )
        .unwrap();
    }
    std::fs::create_dir_all(root.join("people").join(hidden).join("notes")).unwrap();
    std::fs::write(
        root.join("people")
            .join(hidden)
            .join("notes")
            .join(format!("{hidden_note}.md")),
        format!("---\nid: {hidden_note}\ntype: note\nperson: {hidden}\ndate: 2026-10-07\n---\n\nCam asked that notes never go to a model provider.\n"),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
    std::fs::write(
        root.join("ledger/2026/10.cfd"),
        format!(
            "2026-10-01 touch {cleared} call\n2026-10-07 touch {hidden} message note:{hidden_note}\n2026-10-08 touch {cleared} meet\n"
        ),
    )
    .unwrap();
    dir
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
    // Personal-first teaching content: two warnings, no errors. The default
    // `--fail-on error` keeps the CI step exiting 0.
    assert_eq!(v["summary"]["errors"], 0);
    assert_eq!(v["summary"]["warnings"], 2);
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, vec!["W_CADENCE_OVERDUE", "W_DATE_UPCOMING"]);
}

#[test]
fn find_demo_hits_fake_name() {
    let out = Command::new(bin())
        .args(["find", "Dana Example", "--json", "--vault"])
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
        .any(|m| { m["excerpt"].as_str().unwrap().contains("Dana Example") }));
}

#[test]
fn find_omits_no_ai_people() {
    let dir = no_ai_vault();
    let v = run_json(&["find", "Cam Sample"], dir.path());
    assert_eq!(v["matches"], serde_json::json!([]));
}

#[test]
fn find_surfaces_load_findings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        r#"spec = "0.1"
packs = []
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
packs = []
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
packs = []
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
fn allowlist_excludes_no_ai() {
    let dir = no_ai_vault();
    let out = Command::new(bin())
        .args(["allowlist", "--json", "--no-input", "--vault"])
        .arg(dir.path())
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
    // Opaque paths and line numbers only: never content.
    let dumped = serde_json::to_string(&v).unwrap();
    assert!(!dumped.contains("Cam Sample"), "{dumped}");
    let files: Vec<&str> = v["cleared_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        files
            .iter()
            .any(|f| f.contains("p-01M3TC5H00MPJG000000000000")),
        "{files:?}"
    );
    assert!(
        !files
            .iter()
            .any(|f| f.contains("p-01M3TC5H00MPJG001248000002")),
        "{files:?}"
    );
    // The ledger line naming the no-ai person is out; the two cleared
    // touch lines are in.
    let lines: Vec<u64> = v["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["line"].as_u64().unwrap())
        .collect();
    assert_eq!(lines, vec![1, 3], "{lines:?}");
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
const EXAMPLE_PACK: &str = "example-pack@0.1";
const NOTE_LINKED: &str = "n-01M3TC5H00MPJG002NAM000005";
const NOTE_STANDALONE: &str = "n-01M3TC5H00MPJG00600000000D";

/// A local vault with one pack-linked note, one unattributed note, a grant,
/// a `use` line and a personal `touch`. Used by the scope tests without
/// depending on the demo vault's contents.
fn pack_data_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    install_example_pack(dir.path());
    let pkg = "pkg-01M3TC5H00MPJG004SK4000009";
    std::fs::write(
        dir.path().join("confidant.toml"),
        format!(
            "spec = \"0.1\"\npacks = [\"{EXAMPLE_PACK}\"]\nvault_id = \"01M3TC5H00MPJG005VQC00000B\"\n[checks]\nas_of = \"2026-10-08\"\n"
        ),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("people").join(ADA)).unwrap();
    std::fs::write(
        dir.path().join("people").join(ADA).join("profile.md"),
        format!("---\nid: {ADA}\ntype: person\nname: Ada Example\nrelationship: climbing buddy\n---\n\nFake person.\n"),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("people").join(ADA).join("notes")).unwrap();
    std::fs::write(
        dir.path()
            .join("people")
            .join(ADA)
            .join("notes")
            .join(format!("{NOTE_LINKED}.md")),
        format!("---\nid: {NOTE_LINKED}\ntype: note\nperson: {ADA}\ndate: 2026-10-02\n---\n\nKickofftoken linked from the use line.\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path()
            .join("people")
            .join(ADA)
            .join("notes")
            .join(format!("{NOTE_STANDALONE}.md")),
        format!("---\nid: {NOTE_STANDALONE}\ntype: note\nperson: {ADA}\ndate: 2026-10-04\n---\n\nFollowuptoken no pack owner.\n"),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("edges")).unwrap();
    std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
    std::fs::write(
        dir.path().join("ledger/2026/10.cfd"),
        format!(
            "2026-10-01 grant {ADA} package {pkg} 4 sessions\n2026-10-02 use {ADA} 60m full note:{NOTE_LINKED}\n2026-10-03 touch {ADA} call\n"
        ),
    )
    .unwrap();
    dir
}

#[test]
fn find_scoped_to_example_pack_hides_unattributed() {
    // "Kickoff" is in the pack-linked note; "Follow-up" is in the
    // unattributed note. A pack-scoped find sees only the first.
    let dir = pack_data_vault();
    let v = run_json(
        &["find", "Followuptoken", "--packs", EXAMPLE_PACK],
        dir.path(),
    );
    assert_eq!(v["matches"], serde_json::json!([]));
    assert_eq!(v["scope"], serde_json::json!([EXAMPLE_PACK]));

    let v = run_json(
        &["find", "Kickofftoken", "--packs", EXAMPLE_PACK],
        dir.path(),
    );
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);

    let v = run_json(
        &["find", "Followuptoken", "--packs", EXAMPLE_PACK],
        dir.path(),
    );
    assert_eq!(v["matches"], serde_json::json!([]));
    assert_eq!(v["scope"], serde_json::json!([EXAMPLE_PACK]));

    // Unscoped still sees the unattributed note and covers every enabled
    // pack, the implicit built-in personal pack included (#551).
    let v = run_json_no_scope(&["find", "Followuptoken"], dir.path());
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["scope"],
        serde_json::json!([EXAMPLE_PACK, "personal@0.2"])
    );
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
fn context_scoped_to_example_pack_filters_notes() {
    let dir = pack_data_vault();
    let v = run_json(&["context", ADA, "--packs", EXAMPLE_PACK], dir.path());
    assert_eq!(v["ok"], true);
    // Only the pack-linked note; the unattributed note is hidden.
    assert_eq!(v["notes"].as_array().unwrap().len(), 1);
    assert_eq!(v["notes"][0]["id"], NOTE_LINKED);
    assert_eq!(v["person"]["name"], "Ada Example");
    assert_eq!(v["scope"], serde_json::json!([EXAMPLE_PACK]));
    assert!(v["packs"].get("personal@0.2").is_none());
    assert!(v["packs"][EXAMPLE_PACK].is_object());

    let v = run_json_no_scope(&["context", ADA], dir.path());
    assert_eq!(v["notes"].as_array().unwrap().len(), 2);
}

const BEA: &str = "p-01M3TC5H00MPJG000H24000001";
const EDGE_FRIEND: &str = "e-01M3TC5H00MPJG00E100000000";

/// A vault with personal-owned data — a personal field (`relationship`), a
/// personal edge kind (`friend`), and a `touch` ledger line — next to a
/// example pack listing. Used to prove that the implicit `personal@0.2`
/// built-in is visible to a scoped read only when the scope names it (#551).
fn personal_data_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    install_example_pack(dir.path());
    std::fs::write(
        dir.path().join("confidant.toml"),
        r#"spec = "0.1"
packs = ["example-pack@0.1"]
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

/// Like [`run_json`] but omits `--packs` (the normal unscoped read).
fn run_json_no_scope(args: &[&str], vault: &Path) -> serde_json::Value {
    run_json(args, vault)
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
    // personal-owned, so a external-pack-only ceiling hides them even though the
    // built-in pack is enabled in every vault.
    let dir = personal_data_vault();
    for (needle, label) in [
        ("climbing buddy", "personal field"),
        ("friend", "personal edge kind"),
        ("touch", "touch line"),
    ] {
        let scoped = run_json(&["find", needle, "--packs", EXAMPLE_PACK], dir.path());
        assert_eq!(
            scoped["matches"].as_array().unwrap().len(),
            0,
            "pack-only scope leaked a {label}: {scoped}"
        );
        assert_eq!(scoped["scope"], serde_json::json!([EXAMPLE_PACK]));
        // Naming personal through the any-version alias puts it in scope.
        let personal = run_json(
            &["find", needle, "--packs", "example-pack@0.1,personal@0.1"],
            dir.path(),
        );
        assert_eq!(
            personal["matches"].as_array().unwrap().len(),
            1,
            "personal-naming scope hid a {label}: {personal}"
        );
        assert_eq!(
            personal["scope"],
            serde_json::json!([EXAMPLE_PACK, "personal@0.2"])
        );
    }
}

#[test]
fn context_scope_excludes_personal_unless_named() {
    // #551: the personal `context` view and the person's touchpoints are
    // personal-owned. A external-pack-only ceiling drops both; naming personal
    // (at any version) brings the view and the touch line back.
    let dir = personal_data_vault();
    let scoped = run_json(&["context", ADA, "--packs", EXAMPLE_PACK], dir.path());
    assert!(scoped["packs"].get("personal@0.2").is_none(), "{scoped}");
    assert_eq!(scoped["touchpoints"], serde_json::json!([]));
    assert!(scoped["packs"][EXAMPLE_PACK].is_object());
    assert_eq!(scoped["scope"], serde_json::json!([EXAMPLE_PACK]));

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
    let dir = pack_data_vault();
    let out = Command::new(bin())
        .args(["allowlist", "--json", "--no-input", "--vault"])
        .arg(dir.path())
        .args(["--packs", EXAMPLE_PACK])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The unattributed note is out; the pack-linked note stays.
    let files: Vec<&str> = v["cleared_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        !files.iter().any(|f| f.contains("00600000000D")),
        "{files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("002NAM000005")),
        "{files:?}"
    );
    // Ownership annotations: core profile, pack-linked note.
    assert_eq!(
        v["owning_packs"]["people/p-01M3TC5H00MPJG000000000000/profile.md"],
        serde_json::json!(["core"])
    );
    assert_eq!(
        v["owning_packs"]
            ["people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md"],
        serde_json::json!([EXAMPLE_PACK])
    );
    // Every cleared ledger line is annotated.
    let lines: Vec<u64> = v["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            assert!(e["owning_packs"].is_array(), "{e}");
            e["line"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(lines, vec![1, 2], "{lines:?}");
    for entry in v["cleared_ledger_lines"].as_array().unwrap() {
        assert_eq!(entry["owning_packs"], serde_json::json!([EXAMPLE_PACK]));
    }
}

#[test]
fn find_edge_scoping_follows_kind() {
    // #179: an edge is visible exactly when its kind's pack is in scope.
    // A core-kind edge (married) is core-owned: visible to every scope.
    // An unknown-kind edge is unattributed: visible only unscoped.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"x\"\n",
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
    // Core kind: visible unscoped and under a scoped read.
    let v = find("married", None);
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    let v = find("married", Some("personal@0.2"));
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    // Unknown kind: visible unscoped, hidden when scoped (fail closed).
    let v = find("nemesis", None);
    assert_eq!(v["matches"].as_array().unwrap().len(), 1);
    let v = find("nemesis", Some("personal@0.2"));
    assert_eq!(v["matches"], serde_json::json!([]));
}
#[test]
fn help_pack_example_serves_skill_text() {
    let (vault, _) = example_pack_vault();
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
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("# Example pack skill (example-pack@0.1)"),
        "{text}"
    );
    assert!(text.contains("E_EXAMPLE_GRANT_MALFORMED"), "{text}");
    assert!(text.contains("W_EXAMPLE_UNTAGGED"), "{text}");
    assert!(text.starts_with("[external pack:"), "{text}");
}

#[test]
fn help_pack_example_json_envelope() {
    let (vault, _) = example_pack_vault();
    let out = Command::new(bin())
        .args(["help", "pack:example-pack@0.1", "--json", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["packs"], serde_json::json!(["example-pack@0.1"]));
    assert!(v["skill"].as_str().unwrap().contains("E_EXAMPLE_GAP"));
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

/// A non-git vault with the neutral `example-pack@0.1` fixture vendored,
/// pinned and enabled. Fake data only.
fn example_pack_vault() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    install_example_pack(dir.path());
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();
    (dir, String::new())
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
        .args(["help", "pack:personal@0.2", "--vault"])
        .arg(demo())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let shipped = include_str!("../pack-skills/personal/SKILL.md");
    assert!(!stdout.starts_with("[external pack:"), "{stdout:?}");
    assert_eq!(
        stdout,
        format!("{shipped}\n"),
        "compiled skill output must be byte-identical to the shipped text"
    );
}

#[test]
fn help_pack_bare_serves_combined_skill() {
    let (vault, _) = example_pack_vault();
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
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Packs in scope: example-pack@0.1, personal@0.2"),
        "{text}"
    );
    assert!(text.contains("## example-pack@0.1"), "{text}");
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
            "pack:example-pack@0.1",
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
        .args(["help", "pack:example-pack@0.1"])
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
        .args(["find", "Dana Example", "--json", "--vault"])
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
        .any(|m| { m["excerpt"].as_str().unwrap().contains("Dana Example") }));
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
        .args(["find", "Dana Example", "--json", "--vault"])
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
        .any(|m| { m["excerpt"].as_str().unwrap().contains("Dana Example") }));
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
fn pack_init_json_reports_files_and_next_steps() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("weekly-checkin");
    let out = Command::new(bin())
        .args(["pack", "init"])
        .arg(&dir)
        .args(["--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["command"], "pack-init", "{v}");
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["vault"].is_null(), "{v}");
    assert_eq!(v["dir"], dir.display().to_string(), "{v}");
    assert_eq!(v["name"], "weekly-checkin", "{v}");
    assert_eq!(v["version"], "0.1", "{v}");
    assert_eq!(v["dry_run"], false, "{v}");
    assert_eq!(
        v["files"],
        serde_json::json!(["manifest.toml", "SKILL.md", "0.1.md", "README.md"]),
        "{v}"
    );
    let review = format!("confidant pack add --from-dir {}", dir.display());
    assert_eq!(v["next_steps"]["review"], review, "{v}");
    assert_eq!(v["next_steps"]["install"], format!("{review} --yes"), "{v}");
    for file in ["manifest.toml", "SKILL.md", "0.1.md", "README.md"] {
        assert!(dir.join(file).is_file(), "missing {file}: {v}");
    }
}

#[test]
fn pack_init_dry_run_writes_nothing() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("planned");
    let out = Command::new(bin())
        .args(["pack", "init"])
        .arg(&dir)
        .args(["--dry-run", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(v["name"], "planned", "{v}");
    assert!(!dir.exists(), "dry run created the directory: {v}");
}

#[test]
fn pack_init_refuses_a_non_empty_directory() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("occupied");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("keep.txt"), "user data").unwrap();
    let out = Command::new(bin())
        .args(["pack", "init"])
        .arg(&dir)
        .args(["--json", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false, "{v}");
    let message = v["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("non-empty"), "{v}");
    assert_eq!(
        std::fs::read_to_string(dir.join("keep.txt")).unwrap(),
        "user data"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
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
fn pack_add_yes_dry_run_writes_nothing() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(pack.path())
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--dry-run", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "{v}");
    assert!(v["commit"].is_null(), "{v}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), "1\n");
    assert!(!vault.path().join("packs").exists());
    assert!(!vault.path().join("confidant.lock").exists());
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #674: scaffold, review, install, verify, then edit the source and update.
#[cfg(unix)]
#[test]
fn pack_init_round_trip_review_install_and_update() {
    let vault = git_vault();
    let parent = tempfile::tempdir().unwrap();
    let source = parent.path().join("example-local");

    let init = Command::new(bin())
        .args(["pack", "init"])
        .arg(&source)
        .args(["--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    // The review gate writes nothing.
    let review = pack_add(&source, vault.path(), false);
    let stdout = String::from_utf8_lossy(&review.stdout);
    assert!(review.status.success(), "{stdout}");
    assert!(stdout.contains("nothing was written"), "{stdout}");
    assert!(stdout.contains("example-local@0.1"), "{stdout}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), "1\n");
    assert!(!vault.path().join("packs").exists());
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");

    // --yes installs and pins the reviewed bytes.
    let install = pack_add(&source, vault.path(), true);
    assert!(
        install.status.success(),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(verify.status.success(), "{verify:?}");

    // Edit the source and bump the version (the contract file must move with
    // it). A `--dry-run --yes` update must still write nothing.
    let manifest_path = source.join("manifest.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let bumped = manifest.replace("version = \"0.1\"", "version = \"0.2\"");
    assert_ne!(bumped, manifest, "the scaffold version was not found");
    std::fs::write(&manifest_path, bumped).unwrap();
    std::fs::rename(source.join("0.1.md"), source.join("0.2.md")).unwrap();
    std::fs::write(source.join("0.2.md"), "# example-local 0.2\n").unwrap();
    std::fs::write(
        source.join("SKILL.md"),
        format!(
            "{}\nUpdated skill text for 0.2.\n",
            std::fs::read_to_string(source.join("SKILL.md")).unwrap()
        ),
    )
    .unwrap();

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let dry = Command::new(bin())
        .args(["pack", "update", "example-local", "--from-dir"])
        .arg(&source)
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--dry-run", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&dry.stdout),
        String::from_utf8_lossy(&dry.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert!(vault.path().join("packs/example-local@0.1").exists());
    assert!(!vault.path().join("packs/example-local@0.2").exists());

    // Without --yes, update prints the diff and stops.
    let review_update = Command::new(bin())
        .args(["pack", "update", "example-local", "--from-dir"])
        .arg(&source)
        .arg("--vault")
        .arg(vault.path())
        .args(["--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&review_update.stdout);
    assert!(review_update.status.success(), "{stdout}");
    assert!(stdout.contains("pass --yes to apply"), "{stdout}");
    assert!(stdout.contains("Updated skill text for 0.2."), "{stdout}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);

    // --yes applies the reviewed update.
    let update = Command::new(bin())
        .args(["pack", "update", "example-local", "--from-dir"])
        .arg(&source)
        .arg("--vault")
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    assert!(vault.path().join("packs/example-local@0.2").exists());
    assert!(!vault.path().join("packs/example-local@0.1").exists());
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("example-local@0.2"), "{cfg}");
    assert!(!cfg.contains("example-local@0.1"), "{cfg}");

    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    let verify = Command::new(bin())
        .args(["pack", "verify", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    assert!(verify.status.success(), "{verify:?}");
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
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
    // `personal` is reserved for the built-in (PD14).
    let pack = versioned_pack("personal", "0.9", "# nope\n", None);
    let out = pack_add(pack.path(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("reserved"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), "1\n");
}

/// A non-reserved external pack name is accepted.
#[cfg(unix)]
#[test]
fn pack_add_accepts_external_pack_name() {
    let vault = git_vault();
    let pack = versioned_pack("custom-pack", "0.9", "# ok\n", None);
    let out = pack_add(pack.path(), vault.path(), true);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The neutral fixture installs as a real external pack on a copy of the
/// demo vault, and the vault then checks clean.
#[cfg(unix)]
#[test]
fn declarative_example_cli_install_then_check_clean() {
    let vault = tempfile::tempdir().unwrap();
    copy_tree(&demo(), vault.path());
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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/example-pack");
    let out = pack_add(&pack_dir, vault.path(), true);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // `pack verify` accepts the vendored pack...
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
    // The demo is personal-first: its two warning-level personal nudges are
    // expected. Installing the external fixture must add no findings.
    assert_eq!(v["summary"]["errors"], 0, "{v}");
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, vec!["W_CADENCE_OVERDUE", "W_DATE_UPCOMING"], "{v}");
}

#[cfg(unix)]
#[test]
fn pack_add_check_failure_rolls_back() {
    let vault = git_vault();
    // The fixture owns the `session` verb; a pack claiming it conflicts.
    install_example_pack(vault.path());
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n",
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
            "enable example pack",
        ],
    );
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let before_lock = std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap();
    // A directory that already exists (even empty, so git never tracks it) must
    // survive the rollback: the write did not create it (#604).
    std::fs::create_dir_all(vault.path().join("packs/pre-existing-empty")).unwrap();
    let pack = versioned_pack("conflict-pack", "0.1", "# conflict\n", Some("session"));
    let out = pack_add(pack.path(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    // Rolled back: no vendored files, no lock, packs list unchanged, tree clean.
    assert!(!vault
        .path()
        .join("packs/conflict-pack@0.1/manifest.toml")
        .exists());
    assert_eq!(
        std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap(),
        before_lock
    );
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");

    // #604: the empty directory the refused write created is gone, but the one
    // that was already there is untouched.
    assert!(
        !vault.path().join("packs/conflict-pack@0.1").exists(),
        "refused pack add left its vendored directory behind"
    );
    assert!(
        vault.path().join("packs/pre-existing-empty").is_dir(),
        "rollback removed a directory it did not create"
    );

    // The refusal leaves the vault healthy: a following write still succeeds.
    let good = versioned_pack("second-pack", "0.1", "# ok\n", None);
    let out = pack_add(good.path(), vault.path(), true);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The neutral external-pack fixture used by the #694 lifecycle tests.
#[cfg(unix)]
fn example_pack_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/example-pack")
}

/// #694: a vault that already carries the pack's `[checks]` keys cannot be
/// installed without listing it first; the error must say so before the
/// generic check report, and nothing may be committed.
#[cfg(unix)]
#[test]
fn pack_add_refuses_an_unlisted_pack_the_vault_already_uses() {
    let vault = git_vault();
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n\n[checks]\nexample-pack.notes = \"warning\"\n",
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
            "use example pack checks",
        ],
    );

    // The state is real: `check` reports the key as unknown.
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
            .any(|f| f["code"] == "E_CONFIG"),
        "{v}"
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = pack_add(&example_pack_fixture(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("example-pack@0.1"), "{stderr}");
    assert!(stderr.contains("packs"), "{stderr}");
    assert!(stderr.contains("[checks]"), "{stderr}");
    assert!(stderr.contains("fix:"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #694: a vendored copy without a listing is an ambiguous install state.
/// `pack add --yes` must name the listing edit instead of reporting the
/// pin as already installed and leaving the listing missing.
#[cfg(unix)]
#[test]
fn pack_add_refuses_an_unlisted_vendored_pack() {
    let vault = git_vault();
    install_example_pack(vault.path());
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
            "vendor pack without listing",
        ],
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = pack_add(&example_pack_fixture(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already vendored"), "{stderr}");
    assert!(stderr.contains("example-pack@0.1"), "{stderr}");
    assert!(stderr.contains("packs"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #694: removal is blocked while the vault still uses the pack's verbs and
/// metrics. The report is unchanged (exit 1), a stderr hint names the
/// workaround, JSON stays valid, and the pack's state is rolled back.
#[cfg(unix)]
#[test]
fn pack_remove_refuses_while_the_vault_uses_the_pack() {
    let vault = git_vault();
    install_example_pack(vault.path());
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n\n[checks]\nas_of = \"2026-10-08\"\nexample-pack.notes = \"warning\"\n",
    )
    .unwrap();
    let person = "p-01M3TC5H00MPJG000000000000";
    let note = "n-01M3TC5H00MPJG002NAM000005";
    std::fs::create_dir_all(vault.path().join("people").join(person).join("notes")).unwrap();
    std::fs::write(
        vault.path().join("people").join(person).join("profile.md"),
        format!("---\nid: {person}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
    )
    .unwrap();
    std::fs::write(
        vault
            .path()
            .join("people")
            .join(person)
            .join("notes")
            .join(format!("{note}.md")),
        format!(
            "---\nid: {note}\ntype: note\nperson: {person}\ndate: 2026-10-01\n---\n\nFake note.\n"
        ),
    )
    .unwrap();
    std::fs::create_dir_all(vault.path().join("ledger/2026")).unwrap();
    std::fs::write(
        vault.path().join("ledger/2026/10.cfd"),
        format!(
            "2026-10-01 grant {person} package pkg-01M3TC5H00MPJG004SK4000009 6 sessions\n\
             2026-10-01 use {person} 60m full note:{note}\n\
             2026-10-01 balance {person} units_remaining 5\n"
        ),
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
            "use the pack",
        ],
    );

    // The starting point is clean: the pack resolves its verbs and metrics.
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("still uses"), "{stderr}");
    assert!(stderr.contains("example-pack"), "{stderr}");
    assert!(stderr.contains("verbs"), "{stderr}");
    assert!(stderr.contains("orphan"), "{stderr}");
    assert!(stderr.contains("not available yet"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    assert!(vault.path().join("packs/example-pack@0.1").is_dir());
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = [\"example-pack@0.1\"]"), "{cfg}");

    // `--json` prints the same report on stdout and the hint on stderr.
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--json", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false, "{v}");
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "E_UNKNOWN_VERB"),
        "{v}"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("still uses"));
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #694 review: the add hint must not blame `example-pack` for an unrelated
/// `[checks]` typo. The report still prints and the exit stays 1, but no
/// pack-specific hint appears.
#[cfg(unix)]
#[test]
fn pack_add_hint_ignores_an_unrelated_config_finding() {
    let vault = git_vault();
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n\n[checks]\nbogus_key = \"warning\"\n",
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
            "unrelated typo",
        ],
    );

    let out = pack_add(&example_pack_fixture(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("E_CONFIG"), "{stdout}");
    assert!(!stderr.contains("hint:"), "{stderr}");
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #694 review: when the vault's ledger already uses the pack's verbs, the
/// hint must lead with the listing change (the repairing path) rather than
/// telling the operator to delete the data.
#[cfg(unix)]
#[test]
fn pack_add_hint_leads_with_the_listing_for_ledger_data() {
    let vault = git_vault();
    std::fs::create_dir_all(vault.path().join("ledger/2026")).unwrap();
    std::fs::write(
        vault.path().join("ledger/2026/10.cfd"),
        "2026-10-01 use p-01M3TC5H00MPJG000000000000 60m full\n",
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
            "use an uninstalled verb",
        ],
    );

    let out = pack_add(&example_pack_fixture(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("E_UNKNOWN_VERB"),
        "{out:?}"
    );
    assert!(stderr.contains("example-pack@0.1"), "{stderr}");
    assert!(
        stderr.contains("add \"example-pack@0.1\" to `packs`"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("migrate or remove those lines first"),
        "{stderr}"
    );
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
}

/// #694 review: the remove hint must stay silent when the blocked write was
/// a pre-check failure on an unrelated vault, not data from this pack.
#[cfg(unix)]
#[test]
fn pack_remove_hint_ignores_an_unrelated_config_finding() {
    let vault = git_vault();
    install_example_pack(vault.path());
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01TEST00000000000000000000\"\n\n[checks]\nbogus_key = \"warning\"\n",
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
            "unrelated typo",
        ],
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("E_CONFIG"),
        "{out:?}"
    );
    assert!(!stderr.contains("hint:"), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert!(vault.path().join("packs/example-pack@0.1").is_dir());
}

/// #696 review: a vendored copy pinned at the same hash but missing from
/// `packs` is a real repair, not an idempotent no-op. With the flag, the same
/// install must add the listing so `check` passes afterwards.
#[cfg(unix)]
#[test]
fn pack_add_allow_unresolved_repairs_a_vendored_unlisted_pack() {
    let vault = git_vault();
    install_example_pack(vault.path());
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
            "vendor pack without listing",
        ],
    );
    let before: u32 = git(vault.path(), &["rev-list", "--count", "HEAD"])
        .trim()
        .parse()
        .unwrap();

    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(vault.path())
        .args(["--allow-unresolved", "--yes", "--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("committed"), "{stdout}");
    assert!(!stdout.contains("already installed"), "{stdout}");

    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = [\"example-pack@0.1\"]"), "{cfg}");
    assert_eq!(
        git(vault.path(), &["rev-list", "--count", "HEAD"])
            .trim()
            .parse::<u32>()
            .unwrap(),
        before + 1
    );
    assert_eq!(check_json(vault.path())["ok"], true);
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
    assert!(!vault.path().join("packs/conflict-pack@0.1").exists());
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

/// Drop `confidant.lock` and commit the deletion, producing the #612 state:
/// the pack is still listed in `confidant.toml` and vendored, but unpinned.
#[cfg(unix)]
fn drop_lock(vault: &Path) {
    git(vault, &["rm", "-q", "confidant.lock"]);
    git(
        vault,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "drop lock",
        ],
    );
}

/// #612: a missing `confidant.lock` with the pack still listed used to have
/// no working CLI repair — every command `check` named refused. `pack remove`
/// now keys off the `confidant.toml` listing (and the vendored tree), so the
/// recovery the fix names works and leaves a clean vault.
#[cfg(unix)]
#[test]
fn pack_remove_recovers_a_missing_lock() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    drop_lock(vault.path());

    // The state is real: `check` fails `E_PACK_UNKNOWN`, and its fix names the
    // recovery commands.
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    let finding = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "E_PACK_UNKNOWN")
        .expect("E_PACK_UNKNOWN");
    let fix = finding["fix"].as_str().unwrap();
    assert!(fix.contains("confidant pack remove"), "{fix}");
    assert!(fix.contains("confidant pack add"), "{fix}");

    // The removal command the fix names works: the vendored tree and the
    // listing go, and the absent lock stays absent.
    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!vault.path().join("packs/conflict-pack@0.1").exists());
    assert!(!vault.path().join("confidant.lock").exists());
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = []"), "{cfg}");
    assert!(cfg.contains("# keep this comment above packs"), "{cfg}");
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");

    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
}

/// #612: the other recovery `check` names — `pack add --yes` re-pins the
/// listed pack. The unpinned listing is an `E_PACK_UNKNOWN` to the pre-check,
/// so the add goes through the repairing write path; the post-check still
/// gates the commit.
#[cfg(unix)]
#[test]
fn pack_add_repins_a_missing_lock() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    let original_lock = std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap();
    drop_lock(vault.path());

    let out = pack_add(pack.path(), vault.path(), true);
    assert!(out.status.success(), "{out:?}");
    // The pin is restored, and the read-only check is clean again.
    assert_eq!(
        std::fs::read_to_string(vault.path().join("confidant.lock")).unwrap(),
        original_lock
    );
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    let check = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
}

/// #612: removal is keyed off the listing even when the vendored tree is
/// gone too (a partial restore), so a listed-but-unpinned-and-unvendored pack
/// is still removable.
#[cfg(unix)]
#[test]
fn pack_remove_recovers_when_only_the_listing_remains() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    git(vault.path(), &["rm", "-r", "-q", "confidant.lock", "packs"]);
    git(
        vault.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "lose lock and vendored tree",
        ],
    );

    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
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

/// #612: when neither the lockfile nor the listing names the pack, the
/// vendored tree is the last resort — removal still cleans it up.
#[cfg(unix)]
#[test]
fn pack_remove_falls_back_to_the_vendored_tree() {
    let vault = git_vault();
    let pack = versioned_pack("example-pack", "0.1", "# Skill\n", None);
    assert!(pack_add(pack.path(), vault.path(), true).status.success());
    unlist_pack(vault.path(), "example-pack@0.1");
    git(vault.path(), &["rm", "-q", "confidant.lock"]);
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
            "lose lock and listing",
        ],
    );

    let out = Command::new(bin())
        .args(["pack", "remove", "example-pack", "--vault"])
        .arg(vault.path())
        .args(["--yes", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!vault.path().join("packs/conflict-pack@0.1").exists());
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
    // Deterministic: display name, case-insensitive.
    assert_eq!(
        roster_names(&v),
        vec!["Dana Example", "Eli Sample", "Fay Demo", "Gus Example"]
    );
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
        vec!["Dana Example", "Eli Sample", "Fay Demo", "Gus Example"]
    );
}

#[test]
fn record_list_kind_filters() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    )
    .unwrap();
    let org = "o-01J9Z3K4QF0000000000000001";
    std::fs::create_dir_all(dir.path().join("orgs").join(org)).unwrap();
    std::fs::write(
        dir.path().join("orgs").join(org).join("org.md"),
        format!("---\nid: {org}\ntype: org\nname: Example Org\n---\n\n"),
    )
    .unwrap();
    let deal = "d-01J9Z3K4QF0000000000000002";
    std::fs::create_dir_all(dir.path().join("deals").join(deal)).unwrap();
    std::fs::write(
        dir.path().join("deals").join(deal).join("deal.md"),
        format!("---\nid: {deal}\ntype: deal\nname: Example Deal\n---\n\n"),
    )
    .unwrap();

    let orgs = run_json(&["record", "list", "--kind", "org"], dir.path());
    assert_eq!(orgs["kind"], "org");
    assert_eq!(roster_names(&orgs), vec!["Example Org"]);
    let deals = run_json(&["record", "list", "--kind", "deal"], dir.path());
    assert_eq!(roster_names(&deals), vec!["Example Deal"]);
}

#[test]
fn record_list_packs_scope_is_reported_and_fails_closed() {
    // The scope is echoed and validated, like `find` / `context`. Roster
    // entries are core-owned identity records, so a narrower scope does not
    // remove them today.
    let v = demo_roster(&["--packs", "personal@0.2"]);
    assert_eq!(v["scope"], serde_json::json!(["personal@0.2"]));
    assert_eq!(
        roster_names(&v),
        vec!["Dana Example", "Eli Sample", "Fay Demo", "Gus Example"]
    );

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
    assert!(text.contains("Dana Example"), "{text}");
    assert!(text.contains("Eli Sample"), "{text}");
    assert!(text.contains("4 people (person)"), "{text}");
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
fn find_for_operator_includes_no_ai_with_tri_state() {
    // "model provider" is only in Cam's (no-ai) note body.
    let dir = no_ai_vault();
    let default = run_json(&["find", "model provider"], dir.path());
    assert_eq!(default["matches"], serde_json::json!([]));
    assert!(default.get("for_operator").is_none(), "{default}");
    // Agent hits never carry `no_ai`.
    let agent = run_json(&["find", "Dana Example"], dir.path());
    assert!(agent["matches"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m.get("no_ai").is_none()));

    let op = run_json(&["find", "model provider", "--for-operator"], dir.path());
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
    let op_ada = run_json(&["find", "Dana Example", "--for-operator"], dir.path());
    assert!(op_ada["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["no_ai"] == "false"));
}

/// #593: an operator-only ledger hit carries `operator_only: true`; a ledger
/// hit an agent can see too does not, and the agent JSON has no such key.
#[test]
fn find_for_operator_marks_operator_only_ledger_hits() {
    // Cam's touch line names the `no-ai` person and their note, so the
    // agent path hides it entirely.
    let dir = no_ai_vault();
    let default = run_json(&["find", "2026-10-07"], dir.path());
    assert_eq!(default["matches"], serde_json::json!([]));

    let op = run_json(&["find", "2026-10-07", "--for-operator"], dir.path());
    let ledger = op["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["path"].as_str().unwrap().starts_with("ledger/"))
        .expect("Cam's touch line must be an operator hit");
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
    let agent_alias = run_json(&["find", "2026-10-08"], dir.path());
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
    let op_alias = run_json(&["find", "2026-10-08", "--for-operator"], dir.path());
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
fn context_for_operator_shows_no_ai_person_with_tri_state() {
    let dir = no_ai_vault();
    let default = run_json(&["context", CAM], dir.path());
    assert!(default.get("for_operator").is_none(), "{default}");
    assert_eq!(default["person"]["no_ai"], true);
    assert!(default["person"]["name"].is_null());
    assert_eq!(default["notes"], serde_json::json!([]));
    let dumped = serde_json::to_string(&default).unwrap();
    assert!(!dumped.contains("Cam Sample"), "{dumped}");

    let op = run_json(&["context", CAM, "--for-operator"], dir.path());
    assert_eq!(op["for_operator"], true);
    assert_eq!(op["person"]["name"], "Cam Sample");
    assert_eq!(op["person"]["no_ai"], "true");
    assert!(op["person"]["profile"]
        .as_str()
        .unwrap()
        .contains("Fake person"));
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
        let dir = no_ai_vault();
        let text = run_text(&flagged, dir.path());
        assert!(
            text.contains(OPERATOR_BANNER),
            "{flagged:?} missing the operator banner: {text}"
        );

        let plain = run_text(&args, dir.path());
        assert!(
            !plain.contains(OPERATOR_BANNER),
            "{args:?} leaked the operator banner: {plain}"
        );
    }
}

/// Write the example pack's `[checks]` key without listing the pack (#694).
#[cfg(unix)]
fn write_unlisted_pack_checks(vault: &std::path::Path) {
    std::fs::write(
        vault.join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n\n[checks]\nexample-pack.notes = \"warning\"\n",
    )
    .unwrap();
}

/// Write a fake person, note, and the example pack's `grant`/`use`/`balance`
/// ledger lines, so a vault can carry real data before the pack is listed
/// (#694, #696). Fake data only.
#[cfg(unix)]
fn write_example_pack_ledger_data(vault: &std::path::Path) {
    let person = "p-01M3TC5H00MPJG000000000000";
    let note = "n-01M3TC5H00MPJG002NAM000005";
    std::fs::create_dir_all(vault.join("people").join(person).join("notes")).unwrap();
    std::fs::write(
        vault.join("people").join(person).join("profile.md"),
        format!("---\nid: {person}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
    )
    .unwrap();
    std::fs::write(
        vault
            .join("people")
            .join(person)
            .join("notes")
            .join(format!("{note}.md")),
        format!(
            "---\nid: {note}\ntype: note\nperson: {person}\ndate: 2026-10-01\n---\n\nFake note.\n"
        ),
    )
    .unwrap();
    std::fs::create_dir_all(vault.join("ledger/2026")).unwrap();
    std::fs::write(
        vault.join("ledger/2026/10.cfd"),
        format!(
            "2026-10-01 grant {person} package pkg-01M3TC5H00MPJG004SK4000009 6 sessions\n\
             2026-10-01 use {person} 60m full note:{note}\n\
             2026-10-01 balance {person} units_remaining 5\n"
        ),
    )
    .unwrap();
}

/// Run `check --json` and return the parsed report.
#[cfg(unix)]
fn check_json(vault: &std::path::Path) -> serde_json::Value {
    let out = Command::new(bin())
        .args(["check", "--json", "--no-input", "--vault"])
        .arg(vault)
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

/// #696: the explicit flag installs a pack whose `[checks]` keys the vault
/// already carries; without it the #694 refusal stands.
#[cfg(unix)]
#[test]
fn pack_add_allow_unresolved_installs_over_existing_checks() {
    let vault = git_vault();
    write_unlisted_pack_checks(vault.path());
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
            "use example pack checks",
        ],
    );

    // #694 behavior is unchanged without the flag.
    let before: u32 = git(vault.path(), &["rev-list", "--count", "HEAD"])
        .trim()
        .parse()
        .unwrap();
    let out = pack_add(&example_pack_fixture(), vault.path(), true);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("not listed"));
    assert_eq!(
        git(vault.path(), &["rev-list", "--count", "HEAD"])
            .trim()
            .parse::<u32>()
            .unwrap(),
        before
    );

    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(vault.path())
        .args(["--allow-unresolved", "--yes", "--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("committed"), "{stdout}");
    assert_eq!(
        git(vault.path(), &["rev-list", "--count", "HEAD"])
            .trim()
            .parse::<u32>()
            .unwrap(),
        before + 1
    );
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    assert!(vault.path().join("packs/example-pack@0.1").is_dir());
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = [\"example-pack@0.1\"]"), "{cfg}");

    // The install resolved the key the pre-check used to reject.
    let v = check_json(vault.path());
    assert_eq!(v["ok"], true, "{v}");
}

/// #696: the same flag installs over existing ledger verbs, metrics, and
/// edge kinds, and the pack resolves them in the committed state.
#[cfg(unix)]
#[test]
fn pack_add_allow_unresolved_installs_over_existing_ledger_data() {
    let vault = git_vault();
    write_example_pack_ledger_data(vault.path());
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
            "use the pack verbs without listing it",
        ],
    );

    let v = check_json(vault.path());
    assert_eq!(v["ok"], false, "{v}");
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "E_UNKNOWN_VERB"),
        "{v}"
    );
    let before: u32 = git(vault.path(), &["rev-list", "--count", "HEAD"])
        .trim()
        .parse()
        .unwrap();

    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(vault.path())
        .args(["--allow-unresolved", "--yes", "--no-input"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{out:?}\n{stderr}");
    assert_eq!(
        git(vault.path(), &["rev-list", "--count", "HEAD"])
            .trim()
            .parse::<u32>()
            .unwrap(),
        before + 1
    );
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    let v = check_json(vault.path());
    assert_eq!(v["ok"], true, "{v}");
}

/// #696: the flag skips only the pre-check. A finding the pack does not
/// resolve still fails the post-check and rolls the whole write back.
#[cfg(unix)]
#[test]
fn pack_add_allow_unresolved_still_rolls_back_unrelated_errors() {
    let vault = git_vault();
    std::fs::write(
        vault.path().join("confidant.toml"),
        "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n\n[checks]\nother-pack.notes = \"warning\"\n",
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
            "unrelated unresolved check key",
        ],
    );

    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(vault.path())
        .args(["--allow-unresolved", "--yes", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The finding names another pack, so the hint stays silent rather than
    // claiming the flag will resolve it.
    assert!(!stderr.contains("hint:"), "{stderr}");
    assert!(!stderr.contains("add \"example-pack@0.1\""), "{stderr}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    assert!(!vault.path().join("packs").exists());
    let cfg = std::fs::read_to_string(vault.path().join("confidant.toml")).unwrap();
    assert!(cfg.contains("packs = []"), "{cfg}");
}

/// #696: additive JSON field, present only when the flag was passed.
#[cfg(unix)]
#[test]
fn pack_add_allow_unresolved_json_includes_the_flag() {
    let vault = git_vault();
    write_unlisted_pack_checks(vault.path());
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
            "use example pack checks",
        ],
    );

    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(vault.path())
        .args(["--allow-unresolved", "--yes", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["command"], "pack-add", "{v}");
    assert_eq!(v["allow_unresolved"], true, "{v}");
    assert_eq!(v["pack"]["name"], "example-pack", "{v}");

    // A successful add without the flag keeps the existing envelope.
    let other = git_vault();
    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(other.path())
        .args(["--yes", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert!(v.get("allow_unresolved").is_none(), "{v}");
}

/// #696: the flag only takes effect with `--yes`; without it the command
/// stays the read-only review and does not error.
#[cfg(unix)]
#[test]
fn pack_add_allow_unresolved_without_yes_stays_read_only() {
    let vault = git_vault();
    write_unlisted_pack_checks(vault.path());
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
            "use example pack checks",
        ],
    );
    let before = git(vault.path(), &["rev-list", "--count", "HEAD"]);

    let out = Command::new(bin())
        .args(["pack", "add", "--from-dir"])
        .arg(example_pack_fixture())
        .arg("--vault")
        .arg(vault.path())
        .args(["--allow-unresolved", "--no-input"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("nothing was written"), "{stdout}");
    assert_eq!(git(vault.path(), &["rev-list", "--count", "HEAD"]), before);
    assert_eq!(git(vault.path(), &["status", "--porcelain"]), "");
    assert!(!vault.path().join("packs").exists());
}
