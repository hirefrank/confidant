//! Edge-level `no-ai` (spec 0.3, #820): a hidden relation is omitted from
//! every agent read while both endpoints stay visible; the operator path sees
//! it with a badge. Fake data only.

use std::fs;
use std::path::Path;

use confidant_core::check::{CheckOptions, FindingCode};
use confidant_core::context::build_context;
use confidant_core::{check_vault, load_vault, PackScope, RecordId};

const ADA: &str = "p-01M3TC5H00MPJG000000000000";
const ORG: &str = "o-01M3TC5H00MPJG000000000001";
const EDGE: &str = "e-01M3TC5H00MPJG000000000002";
const NOTE: &str = "n-01M3TC5H00MPJG000000000003";

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn vault(spec: &str, edge_no_ai: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        &format!("spec = \"{spec}\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n"),
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Dana Example\n---\n\nFake person.\n"),
    );
    write(
        dir.path(),
        &format!("orgs/{ORG}/org.md"),
        &format!("---\nid: {ORG}\ntype: org\nname: Example Studio\n---\n\nFake org.\n"),
    );
    let flag = edge_no_ai
        .map(|mode| format!("no-ai: {mode}\n"))
        .unwrap_or_default();
    write(
        dir.path(),
        &format!("edges/{EDGE}/edge.md"),
        &format!(
            "---\nid: {EDGE}\ntype: edge\na: {ADA}\nb: {ORG}\nkind: works_at\nsince: 2024-01-01\n{flag}---\n"
        ),
    );
    dir
}

fn codes(report: &confidant_core::CheckReport) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.code.as_str()).collect()
}

#[test]
fn hidden_edge_is_omitted_for_agents_and_badged_for_the_operator() {
    let dir = vault("0.3", Some("true"));
    // A note that names the hidden edge in front matter is uncleared too.
    write(
        dir.path(),
        &format!("notes/{NOTE}/note.md"),
        &format!(
            "---\nid: {NOTE}\ntype: note\nrelated: {EDGE}\n---\n\nOnly visible to the operator.\n"
        ),
    );
    let vault = load_vault(dir.path()).unwrap();
    let report = check_vault(&vault, &CheckOptions::default());
    assert!(report.ok, "{:?}", report.findings);

    let edge_id = RecordId::parse(EDGE).unwrap();
    assert!(
        !confidant_core::cleared_record_ids(&vault).contains(&edge_id),
        "hidden edge must not be in the agent cleared set"
    );
    assert!(
        confidant_core::cleared_record_ids_for_operator(&vault).contains(&edge_id),
        "operator cleared set must include the hidden edge"
    );
    assert!(
        !confidant_core::cleared_record_paths(&vault)
            .iter()
            .any(|path| path == &format!("edges/{EDGE}/edge.md")),
        "allowlist paths must omit the hidden edge"
    );

    let ada = RecordId::parse(ADA).unwrap();
    let org = RecordId::parse(ORG).unwrap();
    let agent_person = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
    let agent_org = build_context(&vault, &org, true, &PackScope::All, false).unwrap();
    assert!(agent_person.edges.is_empty(), "{:?}", agent_person.edges);
    assert!(agent_org.edges.is_empty(), "{:?}", agent_org.edges);
    assert_eq!(agent_person.entity.name.as_deref(), Some("Dana Example"));
    assert_eq!(agent_org.entity.name.as_deref(), Some("Example Studio"));

    let op_person = build_context(&vault, &ada, true, &PackScope::All, true).unwrap();
    assert_eq!(op_person.edges.len(), 1);
    let edge = &op_person.edges[0];
    assert_eq!(edge.id, EDGE);
    assert_eq!(edge.no_ai, Some("true"));
    assert_eq!(edge.other.id, ORG);
    assert_eq!(edge.other.name.as_deref(), Some("Example Studio"));

    // Agent find omits the hidden edge and the note that names it; operator
    // find still sees both.
    assert!(
        confidant_core::search(&vault, "operator", &PackScope::All)
            .unwrap()
            .hits
            .is_empty(),
        "note naming a hidden edge must be uncleared"
    );
    assert!(
        !confidant_core::search_for_operator(&vault, "operator", &PackScope::All)
            .unwrap()
            .hits
            .is_empty(),
        "operator find must still see the note"
    );
    // Both endpoints remain visible to agents.
    assert!(
        !confidant_core::search(&vault, "Dana Example", &PackScope::All)
            .unwrap()
            .hits
            .is_empty()
    );
    assert!(
        !confidant_core::search(&vault, "Example Studio", &PackScope::All)
            .unwrap()
            .hits
            .is_empty()
    );
}

#[test]
fn edge_no_ai_false_is_visible() {
    let dir = vault("0.3", Some("false"));
    let vault = load_vault(dir.path()).unwrap();
    let ada = RecordId::parse(ADA).unwrap();
    let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
    assert_eq!(bundle.edges.len(), 1);
    assert!(bundle.edges[0].no_ai.is_none());
    assert!(confidant_core::cleared_record_ids(&vault).contains(&RecordId::parse(EDGE).unwrap()));
    let op = build_context(&vault, &ada, true, &PackScope::All, true).unwrap();
    assert_eq!(op.edges.len(), 1);
    assert_eq!(op.edges[0].no_ai, Some("false"));
}

#[test]
fn edge_no_ai_rejects_notes_and_02_rejects_the_key() {
    for (spec, mode) in [("0.3", "notes"), ("0.2", "true"), ("0.1", "true")] {
        let dir = vault(spec, Some(mode));
        let report = check_vault(&load_vault(dir.path()).unwrap(), &CheckOptions::default());
        assert!(
            codes(&report).contains(&"E_FRONTMATTER"),
            "{spec} {mode}: {:?}",
            report.findings
        );
    }
}

#[test]
fn hidden_edge_findings_never_echo_kind_or_endpoints() {
    let dir = vault("0.3", Some("true"));
    // Replace the valid kind with an unknown one to force a finding on the
    // hidden edge itself.
    write(
        dir.path(),
        &format!("edges/{EDGE}/edge.md"),
        &format!(
            "---\nid: {EDGE}\ntype: edge\na: {ADA}\nb: {ORG}\nkind: nemesis\nno-ai: true\n---\n"
        ),
    );
    let report = check_vault(&load_vault(dir.path()).unwrap(), &CheckOptions::default());
    let finding = report
        .findings
        .iter()
        .find(|f| f.code == FindingCode::UnknownEdgeKind)
        .unwrap_or_else(|| panic!("expected unknown edge kind: {:?}", report.findings));
    assert!(!finding.message.contains("nemesis"), "{finding:?}");
    assert!(!finding.message.contains(ADA), "{finding:?}");
    assert!(!finding.message.contains(ORG), "{finding:?}");
    if let Some(fix) = &finding.fix {
        assert!(!fix.contains("nemesis"), "{finding:?}");
        assert!(!fix.contains(ADA), "{finding:?}");
        assert!(!fix.contains(ORG), "{finding:?}");
    }
}
