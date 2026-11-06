//! Spec 0.3 record-type core: pack-declared types, paths, allowlist, and
//! orphan/retired behavior. Fake data only.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use confidant_core::check::CheckOptions;
use confidant_core::context::build_context;
use confidant_core::record_type::{TypeOwner, TypeProblem, TypeRegistry, TypeSource};
use confidant_core::resolve::{resolve_alias, resolve_person, PersonResolveError};
use confidant_core::roster::build_roster;
use confidant_core::{check_vault, load_vault, PackScope, RecordSchema};

const ADA: &str = "p-01M3TC5H00MPJG000000000000";
const PLACE: &str = "pl-01M3TC5H00MPJG000000000001";
const EDGE: &str = "e-01M3TC5H00MPJG000000000002";

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn pack_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/place-pack")
}

fn install_place_pack(root: &Path) -> String {
    let src = pack_src();
    let dst = root.join("packs/place-pack@0.1");
    fs::create_dir_all(&dst).unwrap();
    for entry in fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    confidant_core::packs::dir::read_pack_dir(&dst)
        .unwrap()
        .hash
}

fn place_vault(spec: &str, packs: &str, retired: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let hash = install_place_pack(dir.path());
    write(
        dir.path(),
        "confidant.lock",
        &format!(
            "lock_version = 1\n\n[[pack]]\nname = \"place-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    );
    write(
        dir.path(),
        "confidant.toml",
        &format!(
            "spec = \"{spec}\"\npacks = [{packs}]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n{retired}"
        ),
    );
    (dir, hash)
}

fn person(root: &Path) {
    write(
        root,
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Dana Example\n---\n\nFake person.\n"),
    );
}

fn place(root: &Path) {
    write(
        root,
        &format!("places/{PLACE}/place.md"),
        &format!(
            "---\nid: {PLACE}\ntype: place\nname: Example Studio\naddress: 1 Example Way\n---\n\nFake place.\n"
        ),
    );
}

fn edge(root: &Path) {
    write(
        root,
        &format!("edges/{EDGE}/edge.md"),
        &format!(
            "---\nid: {EDGE}\ntype: edge\na: {ADA}\nb: {PLACE}\nkind: visited\nsince: 2026-10-01\n---\n"
        ),
    );
}

fn report(root: &Path) -> confidant_core::CheckReport {
    let vault = load_vault(root).unwrap();
    check_vault(&vault, &CheckOptions::default())
}

fn codes(report: &confidant_core::CheckReport) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.code.as_str()).collect()
}

#[test]
fn declared_place_loads_and_checks_clean() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    person(dir.path());
    place(dir.path());
    edge(dir.path());
    write(
        dir.path(),
        "notes/n-01M3TC5H00MPJG000000000003/note.md",
        &format!(
            "---\nid: n-01M3TC5H00MPJG000000000003\ntype: note\nentity: {PLACE}\ndate: 2026-10-02\n---\n\nLiked the back room.\n"
        ),
    );

    let vault = load_vault(dir.path()).unwrap();
    let place_rec = vault
        .records
        .get(&confidant_core::RecordId::parse(PLACE).unwrap())
        .unwrap();
    assert_eq!(place_rec.kind.as_str(), "place");
    assert_eq!(place_rec.kind.prefix().to_string(), "pl");
    assert!(vault.type_registry().is_entity(place_rec.id.prefix()));

    let report = report(dir.path());
    assert!(report.ok, "{:?}", report.findings);
    assert!(
        report.findings.is_empty(),
        "unexpected findings: {:?}",
        report.findings
    );

    // Agent allowlist includes an enabled pack type; a note attached via
    // `entity:` is scoped to the same pack.
    let cleared = confidant_core::cleared_record_ids(&vault);
    assert!(cleared.contains(&confidant_core::RecordId::parse(PLACE).unwrap()));
    assert!(
        cleared.contains(&confidant_core::RecordId::parse("n-01M3TC5H00MPJG000000000003").unwrap())
    );

    // A note attached with `entity:` inherits the place pack's scope.
    let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    let linkage = confidant_core::note_linkage_owners(&vault, &enabled);
    let note = vault
        .records
        .get(&confidant_core::RecordId::parse("n-01M3TC5H00MPJG000000000003").unwrap())
        .unwrap();
    let owners =
        confidant_core::record_owners(note, &linkage, &enabled, confidant_core::SpecVersion::V03);
    assert!(
        owners.contains(&confidant_core::OwnerKey::Pack("place-pack@0.1")),
        "{owners:?}"
    );
    let place_scope =
        confidant_core::PackScope::Only(["place-pack@0.1".to_owned()].into_iter().collect());
    assert_eq!(
        confidant_core::search(&vault, "back room", &place_scope)
            .unwrap()
            .hits
            .len(),
        1
    );
    assert!(
        confidant_core::search(&vault, "Example Studio", &place_scope)
            .unwrap()
            .hits
            .iter()
            .any(|hit| hit.id.as_deref() == Some(PLACE)),
        "a pack type is searchable as a whole record"
    );
    let personal_scope =
        confidant_core::PackScope::Only(["personal@0.2".to_owned()].into_iter().collect());
    assert!(
        confidant_core::search(&vault, "back room", &personal_scope)
            .unwrap()
            .hits
            .is_empty(),
        "place notes must not leak into a personal-only scope"
    );
}

#[test]
fn place_context_attaches_entity_notes_and_hides_out_of_scope() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    person(dir.path());
    place(dir.path());
    let note = "n-01M3TC5H00MPJG000000000003";
    write(
        dir.path(),
        &format!("notes/{note}/note.md"),
        &format!(
            "---\nid: {note}\ntype: note\nentity: {PLACE}\ndate: 2026-10-02\n---\n\nLiked the back room.\n"
        ),
    );
    let vault = load_vault(dir.path()).unwrap();
    let place_id = confidant_core::RecordId::parse(PLACE).unwrap();
    let bundle = build_context(&vault, &place_id, true, &PackScope::All, false).unwrap();
    assert_eq!(bundle.entity.kind, "place");
    assert_eq!(bundle.entity.name.as_deref(), Some("Example Studio"));
    assert_eq!(bundle.notes.len(), 1, "{:?}", bundle.notes);
    assert_eq!(
        bundle.notes[0].body.as_deref(),
        Some("Liked the back room.\n")
    );

    let personal = PackScope::Only(["personal@0.2".to_owned()].into_iter().collect());
    assert!(
        build_context(&vault, &place_id, true, &personal, false).is_none(),
        "a place-owned record is hidden under a personal-only scope"
    );
    assert!(build_context(
        &vault,
        &confidant_core::RecordId::parse("p-01M3TC5H00MPJG000000000099").unwrap(),
        true,
        &PackScope::All,
        false,
    )
    .is_none());
}

#[test]
fn roster_lists_pack_types_only_in_scope() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    person(dir.path());
    place(dir.path());
    let vault = load_vault(dir.path()).unwrap();
    let all = build_roster(&vault, None, &PackScope::All, false);
    assert_eq!(
        all.kinds,
        vec![
            "person".to_owned(),
            "org".to_owned(),
            "deal".to_owned(),
            "place".to_owned()
        ]
    );
    let place = all
        .records
        .iter()
        .find(|entry| entry.id == PLACE)
        .expect("place in the default roster");
    assert_eq!(place.kind, "place");
    assert!(place.orphan.is_none());

    let only_place = build_roster(&vault, Some("place"), &PackScope::All, false);
    assert_eq!(only_place.kinds, vec!["place".to_owned()]);
    assert_eq!(only_place.records.len(), 1);

    let personal = PackScope::Only(["personal@0.2".to_owned()].into_iter().collect());
    let scoped = build_roster(&vault, Some("place"), &personal, false);
    assert!(scoped.records.is_empty(), "{:?}", scoped.records);
}

#[test]
fn pack_type_names_do_not_resolve_to_people() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    person(dir.path());
    place(dir.path());
    let vault = load_vault(dir.path()).unwrap();
    assert_eq!(
        resolve_person(&vault, "Example Studio"),
        Err(PersonResolveError::NotFound)
    );
    assert_eq!(
        resolve_person(&vault, PLACE),
        Err(PersonResolveError::NotFound)
    );
    assert_eq!(
        resolve_alias(&vault, "name", "Example Studio"),
        Err(PersonResolveError::NotFound)
    );
    assert_eq!(
        resolve_person(&vault, "Dana Example")
            .unwrap()
            .id
            .to_string(),
        ADA
    );
}

#[test]
fn unknown_type_in_core_collection_is_an_error() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: widget\nname: Dana Example\n---\n\n"),
    );
    let report = report(dir.path());
    assert!(!report.ok);
    assert!(
        codes(&report).contains(&"E_UNKNOWN_RECORD_TYPE"),
        "{:?}",
        report.findings
    );
}

#[test]
fn wrong_collection_is_a_type_path_mismatch() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    // A place-typed record in the person collection.
    write(
        dir.path(),
        &format!("people/{PLACE}/profile.md"),
        &format!("---\nid: {PLACE}\ntype: place\nname: Example Studio\n---\n\n"),
    );
    let report = report(dir.path());
    assert!(
        codes(&report).contains(&"E_TYPE_PATH_MISMATCH"),
        "{:?}",
        report.findings
    );
}

#[test]
fn duplicate_ulid_across_core_and_pack_prefix_is_an_error() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    let shared = "01M3TC5H00MPJG000000000009";
    write(
        dir.path(),
        &format!("people/p-{shared}/profile.md"),
        &format!("---\nid: p-{shared}\ntype: person\nname: Dana Example\n---\n\n"),
    );
    write(
        dir.path(),
        &format!("places/pl-{shared}/place.md"),
        &format!("---\nid: pl-{shared}\ntype: place\nname: Example Studio\n---\n\n"),
    );
    let report = report(dir.path());
    assert!(
        codes(&report).contains(&"E_DUPLICATE_ULID"),
        "{:?}",
        report.findings
    );
}

#[test]
fn registry_keeps_a_disabled_pack_type_known_but_not_enabled() {
    use confidant_core::id::Prefix;
    use confidant_core::record_type::RecordTypeDecl;

    const PLACE_DECL: RecordTypeDecl = RecordTypeDecl {
        name: "place",
        id_prefix: "pl",
        prefix: Prefix::Pack(*b"pl"),
        collection: "places",
        main_file: "place.md",
        entity: true,
        person_like: false,
        no_ai: confidant_core::NoAiPolicy::Full,
        roster: true,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Pack("place-pack@0.1"),
        enabled: true,
        retired: false,
    };
    let sources = [TypeSource {
        owner: TypeOwner::Pack("place-pack@0.1"),
        decls: &[PLACE_DECL],
        enabled: false,
    }];
    let (registry, problems) = TypeRegistry::build(
        confidant_core::SpecVersion::V03,
        &sources,
        Vec::new(),
        Vec::new(),
    );
    assert!(problems.is_empty(), "{problems:?}");
    let decl = registry.get("place").expect("disabled type stays known");
    assert!(!decl.enabled);
    assert_eq!(decl.owner, TypeOwner::Pack("place-pack@0.1"));
    assert!(registry.is_entity(Prefix::Pack(*b"pl")));
    assert!(!registry.is_enabled("place"));
}

#[test]
fn retired_type_warns_orphan_and_fails_closed_for_agents() {
    let retired = r#"
[[retired_types]]
name = "place"
id_prefix = "pl"
collection = "places"
main_file = "place.md"
entity = true
person_like = false
no_ai = "full"
roster = true
removed_pack = "place-pack@0.1"
"#;
    // The pack bytes are gone; the tombstone is what keeps `places/`
    // parseable.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        &format!(
            "spec = \"0.3\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000000\"\n{retired}"
        ),
    );
    person(dir.path());
    place(dir.path());

    let vault = load_vault(dir.path()).unwrap();
    let report = check_vault(&vault, &CheckOptions::default());
    assert!(report.ok, "{:?}", report.findings);
    assert!(
        codes(&report).contains(&"W_PACK_ORPHAN"),
        "{:?}",
        report.findings
    );
    assert!(
        !confidant_core::cleared_record_ids(&vault)
            .contains(&confidant_core::RecordId::parse(PLACE).unwrap()),
        "retired type must not be agent-cleared"
    );
    assert!(
        confidant_core::cleared_record_ids_for_operator(&vault)
            .contains(&confidant_core::RecordId::parse(PLACE).unwrap()),
        "operator path must still see the retired record"
    );
    assert!(
        confidant_core::search(&vault, "Fake place", &confidant_core::PackScope::All)
            .unwrap()
            .hits
            .is_empty(),
        "retired records must not appear in the agent search"
    );
    assert!(
        !confidant_core::search_for_operator(&vault, "Fake place", &confidant_core::PackScope::All)
            .unwrap()
            .hits
            .is_empty(),
        "operator search must still see the retired record"
    );
    let place_id = confidant_core::RecordId::parse(PLACE).unwrap();
    assert!(
        build_context(&vault, &place_id, true, &PackScope::All, false).is_none(),
        "retired types are not agent context targets"
    );
    let operator =
        build_context(&vault, &place_id, true, &PackScope::All, true).expect("operator bundle");
    assert_eq!(operator.entity.kind, "place");
    let roster = build_roster(&vault, Some("place"), &PackScope::All, true);
    assert_eq!(roster.records.len(), 1);
    assert_eq!(roster.records[0].orphan.as_deref(), Some("removed"));
}

#[test]
fn entity_reference_to_a_pack_type_is_valid() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    person(dir.path());
    place(dir.path());
    write(
        dir.path(),
        "notes/n-01M3TC5H00MPJG000000000004/note.md",
        &format!(
            "---\nid: n-01M3TC5H00MPJG000000000004\ntype: note\nentity: {PLACE}\ndate: 2026-10-02\n---\n\n"
        ),
    );
    let report = report(dir.path());
    assert!(report.ok, "{:?}", report.findings);
}

#[test]
fn entity_reference_to_a_non_entity_is_wrong_type() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    person(dir.path());
    let note = "n-01M3TC5H00MPJG000000000005";
    write(
        dir.path(),
        &format!("notes/{note}/note.md"),
        &format!("---\nid: {note}\ntype: note\nentity: {note}\ndate: 2026-10-02\n---\n\n"),
    );
    let report = report(dir.path());
    assert!(
        codes(&report).contains(&"E_WRONG_ID_TYPE"),
        "{:?}",
        report.findings
    );
}

#[test]
fn schema_aware_parse_requires_a_declared_type_for_writes() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    let vault = load_vault(dir.path()).unwrap();
    let schema = RecordSchema {
        spec: confidant_core::SpecVersion::V03,
        types: Some(vault.type_registry()),
        require_declared: true,
    };
    let text = format!("---\nid: {PLACE}\ntype: place\nname: Example Studio\n---\n");
    let rec = confidant_core::record::parse_record_with_schema(&text, "place.md", &schema).unwrap();
    assert_eq!(rec.kind.as_str(), "place");
    let missing_name = format!("---\nid: {PLACE}\ntype: place\n---\n");
    assert!(
        confidant_core::record::parse_record_with_schema(&missing_name, "place.md", &schema)
            .is_err()
    );
    let unknown = format!("---\nid: x-{PLACE}\ntype: widget\n---\n");
    assert!(confidant_core::record::parse_record_with_schema(&unknown, "x.md", &schema).is_err());
}

#[test]
fn registry_marks_conflicting_pack_types_and_core_collisions() {
    use confidant_core::id::Prefix;
    use confidant_core::record_type::RecordTypeDecl;

    const A: RecordTypeDecl = RecordTypeDecl {
        name: "place",
        id_prefix: "pl",
        prefix: Prefix::Pack(*b"pl"),
        collection: "places",
        main_file: "place.md",
        entity: true,
        person_like: false,
        no_ai: confidant_core::NoAiPolicy::Full,
        roster: true,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Pack("a@0.1"),
        enabled: true,
        retired: false,
    };
    const B: RecordTypeDecl = RecordTypeDecl {
        owner: TypeOwner::Pack("b@0.1"),
        ..A
    };
    let sources = [
        TypeSource {
            owner: TypeOwner::Pack("a@0.1"),
            decls: &[A],
            enabled: true,
        },
        TypeSource {
            owner: TypeOwner::Pack("b@0.1"),
            decls: &[B],
            enabled: false,
        },
    ];
    let (registry, problems) = TypeRegistry::build(
        confidant_core::SpecVersion::V03,
        &sources,
        Vec::new(),
        Vec::new(),
    );
    assert!(
        problems
            .iter()
            .any(|p| matches!(p, TypeProblem::Conflict { .. })),
        "{problems:?}"
    );
    assert!(!registry.is_enabled("place"));
}

#[test]
fn duplicate_pack_prefix_is_a_pack_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let first = install_place_pack(dir.path());
    let other_dir = dir.path().join("packs/other-pack@0.1");
    fs::create_dir_all(&other_dir).unwrap();
    fs::write(
        other_dir.join("manifest.toml"),
        r#"manifest_version = 3
balance_metrics = []
finding_codes = []

[pack]
name = "other-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.3"]

[[record_types]]
name = "spot"
id_prefix = "pl"
collection = "spots"
main_file = "spot.md"
entity = true

[messages]
"#,
    )
    .unwrap();
    fs::write(other_dir.join("SKILL.md"), "# other\n").unwrap();
    let second = confidant_core::packs::dir::read_pack_dir(&other_dir)
        .unwrap()
        .hash;
    write(
        dir.path(),
        "confidant.lock",
        &format!(
            "lock_version = 1\n\n[[pack]]\nname = \"place-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{first}\"\n\n[[pack]]\nname = \"other-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{second}\"\n"
        ),
    );
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.3\"\npacks = [\"place-pack@0.1\", \"other-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
    );
    let report = report(dir.path());
    assert!(!report.ok);
    assert!(
        codes(&report).contains(&"E_PACK_CONFLICT"),
        "{:?}",
        report.findings
    );
}

#[test]
fn missing_required_pack_field_is_frontmatter() {
    let (dir, _) = place_vault("0.3", "\"place-pack@0.1\"", "");
    write(
        dir.path(),
        &format!("places/{PLACE}/place.md"),
        &format!("---\nid: {PLACE}\ntype: place\n---\n\n"),
    );
    let second = report(dir.path());
    assert!(
        codes(&second).contains(&"E_FRONTMATTER"),
        "{:?}",
        second.findings
    );
}

#[test]
fn disabled_vendored_pack_type_warns_orphan_and_fails_closed_for_agents() {
    // Vendored and pinned, but not listed: the pack is a disabled type
    // source, so its records parse and warn without enabling its verbs.
    let (dir, _) = place_vault("0.3", "", "");
    person(dir.path());
    place(dir.path());

    let vault = load_vault(dir.path()).unwrap();
    let report = check_vault(&vault, &CheckOptions::default());
    assert!(report.ok, "{:?}", report.findings);
    assert!(
        codes(&report).contains(&"W_PACK_ORPHAN"),
        "{:?}",
        report.findings
    );
    assert!(
        !confidant_core::cleared_record_ids(&vault)
            .contains(&confidant_core::RecordId::parse(PLACE).unwrap()),
        "disabled type must not be agent-cleared"
    );
    assert!(
        confidant_core::cleared_record_ids_for_operator(&vault)
            .contains(&confidant_core::RecordId::parse(PLACE).unwrap()),
        "operator path must still see the disabled record"
    );
}

// #745: the 0.4 built-in personal pack declares place/thing and their edges.
const PERSONAL_PLACE: &str = "pl-01M3TC5H00MPJG000000000021";
const PERSONAL_THING: &str = "th-01M3TC5H00MPJG000000000022";
const PERSONAL_EDGE: &str = "e-01M3TC5H00MPJG000000000023";

fn personal_04_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.4\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000001\"\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Dana Example\n---\n\nFake person.\n"),
    );
    write(
        dir.path(),
        &format!("places/{PERSONAL_PLACE}/place.md"),
        &format!(
            "---\nid: {PERSONAL_PLACE}\ntype: place\nname: Example Studio\nkind: work\naddress: 1 Example Way\n---\n\nFake place.\n"
        ),
    );
    write(
        dir.path(),
        &format!("things/{PERSONAL_THING}/thing.md"),
        &format!(
            "---\nid: {PERSONAL_THING}\ntype: thing\nname: Example Bicycle\nkind: object\n---\n\nFake thing.\n"
        ),
    );
    write(
        dir.path(),
        &format!("edges/{PERSONAL_EDGE}/edge.md"),
        &format!(
            "---\nid: {PERSONAL_EDGE}\ntype: edge\na: {ADA}\nb: {PERSONAL_PLACE}\nkind: visited\nsince: 2026-10-01\n---\n"
        ),
    );
    dir
}

#[test]
fn personal_0_4_is_the_0_4_default_with_places_and_things() {
    let dir = personal_04_vault();
    let vault = load_vault(dir.path()).unwrap();
    let names: Vec<&str> = vault
        .pack_registry()
        .all()
        .iter()
        .map(|pack| pack.name())
        .collect();
    assert!(names.contains(&"personal@0.4"), "{names:?}");
    assert!(!names.contains(&"personal@0.3"), "{names:?}");
    assert!(!names.contains(&"personal@0.2"), "{names:?}");

    let report = report(dir.path());
    assert!(report.ok, "{:?}", report.findings);
    assert!(
        report.findings.is_empty(),
        "unexpected findings: {:?}",
        report.findings
    );

    let place = confidant_core::RecordId::parse(PERSONAL_PLACE).unwrap();
    assert!(vault.type_registry().is_entity(place.prefix()));
    let bundle = build_context(&vault, &place, true, &PackScope::All, false).unwrap();
    assert_eq!(bundle.entity.kind, "place");
    assert_eq!(bundle.entity.name.as_deref(), Some("Example Studio"));

    let person = confidant_core::RecordId::parse(ADA).unwrap();
    let person_bundle = build_context(&vault, &person, true, &PackScope::All, false).unwrap();
    assert!(
        person_bundle.packs.contains_key("personal@0.4"),
        "{:?}",
        person_bundle.packs
    );
    assert!(
        !person_bundle.packs.contains_key("personal@0.2"),
        "{:?}",
        person_bundle.packs
    );

    let roster = build_roster(&vault, None, &PackScope::All, false);
    assert!(
        roster.kinds.contains(&"place".to_owned()),
        "{:?}",
        roster.kinds
    );
    assert!(
        roster.kinds.contains(&"thing".to_owned()),
        "{:?}",
        roster.kinds
    );
}

#[test]
fn personal_0_2_stays_the_default_for_spec_0_3() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "confidant.toml",
        "spec = \"0.3\"\npacks = []\nvault_id = \"01J9Z3K4QF0000000000000002\"\n",
    );
    write(
        dir.path(),
        &format!("people/{ADA}/profile.md"),
        &format!("---\nid: {ADA}\ntype: person\nname: Dana Example\n---\n\nFake person.\n"),
    );
    let vault = load_vault(dir.path()).unwrap();
    let names: Vec<&str> = vault
        .pack_registry()
        .all()
        .iter()
        .map(|pack| pack.name())
        .collect();
    assert!(names.contains(&"personal@0.2"), "{names:?}");
    assert!(!names.contains(&"personal@0.3"), "{names:?}");
    assert!(!names.contains(&"personal@0.4"), "{names:?}");
}

fn personal_04_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vaults/personal-0.4")
}

#[test]
fn personal_04_context_fields_and_privacy() {
    let vault = load_vault(&personal_04_fixture()).unwrap();
    let place = confidant_core::RecordId::parse("pl-01M3TC5H00MPJG000000000201").unwrap();

    let full = build_context(&vault, &place, true, &PackScope::All, false).unwrap();
    assert_eq!(full.entity.fields["kind"], "work");
    assert_eq!(full.entity.fields["address"], "1 Example Way");
    assert_eq!(full.entity.fields["tags"], json!(["studio", "work"]));
    assert_eq!(
        full.entity.fields["links"],
        json!([{"label": "map", "value": "https://example.test/map"}])
    );
    assert_eq!(full.notes.len(), 1, "{:?}", full.notes);
    assert_eq!(full.edges.len(), 3, "{:?}", full.edges);

    let thing = confidant_core::RecordId::parse("th-01M3TC5H00MPJG000000000301").unwrap();
    let thing_bundle = build_context(&vault, &thing, true, &PackScope::All, false).unwrap();
    assert_eq!(thing_bundle.entity.fields["kind"], "object");
    assert_eq!(thing_bundle.entity.fields["tags"], json!(["commute"]));
    assert!(!thing_bundle.entity.fields.contains_key("address"));

    let private = build_context(&vault, &place, false, &PackScope::All, false).unwrap();
    assert_eq!(private.entity.fields["kind"], "work");
    assert!(!private.entity.fields.contains_key("address"));
    assert!(!private.entity.fields.contains_key("tags"));
    assert!(!private.entity.fields.contains_key("links"));
    assert!(private.entity.name.is_none());
    assert!(private.entity.profile.is_none());

    // A no-ai place returns no agent bundle at all; the operator path still
    // returns it with the badge and its fields.
    let hidden = confidant_core::RecordId::parse("pl-01M3TC5H00MPJG000000000202").unwrap();
    assert!(build_context(&vault, &hidden, true, &PackScope::All, false).is_none());
    assert!(build_context(&vault, &hidden, false, &PackScope::All, false).is_none());
    let operator = build_context(&vault, &hidden, true, &PackScope::All, true).unwrap();
    assert_eq!(operator.entity.no_ai_mode, Some("true"));
    assert_eq!(operator.entity.fields["kind"], "home");
    assert_eq!(operator.entity.fields["address"], "2 Example Lane");
}

/// #739, #740, #742: the checked-in 0.4 fixture carries the typed person
/// fields, and the same privacy switch strips them.
#[test]
fn personal_04_person_relationship_fields_and_privacy() {
    let vault = load_vault(&personal_04_fixture()).unwrap();
    let person = confidant_core::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();

    let full = build_context(&vault, &person, true, &PackScope::All, false).unwrap();
    let personal = &full.packs["personal@0.4"];
    assert_eq!(
        personal["relationship_context"], "I'm an investor in her company",
        "{personal}"
    );
    assert_eq!(
        personal["role_history"],
        json!([
            {"period": "2019-2021", "role": "Product manager", "company": "Example Co", "source": "linkedin-export"},
            {"period": "2021-", "role": "Founder", "company": "Example Studio", "source": "operator"},
        ]),
        "{personal}"
    );
    assert_eq!(
        personal["alias_history"],
        json!([
            {"kind": "email", "value": "dana@example.test", "status": "current", "source": "email-signature"},
            {"kind": "email", "value": "dana@old.example.test", "status": "historical", "source": "linkedin-export"},
        ]),
        "{personal}"
    );

    let private = build_context(&vault, &person, false, &PackScope::All, false).unwrap();
    let personal = &private.packs["personal@0.4"];
    for field in ["relationship_context", "role_history", "alias_history"] {
        assert!(personal.get(field).is_none(), "{field} visible: {personal}");
    }
    let dumped = serde_json::to_string(&private).unwrap();
    for leak in [
        "investor in her company",
        "Product manager",
        "dana@old.example.test",
    ] {
        assert!(!dumped.contains(leak), "{leak} leaked in {dumped}");
    }
}

#[test]
fn personal_04_requires_kind_and_rejects_notes_mode() {
    let dir = personal_04_vault();
    let place_path = dir.path().join(format!("places/{PERSONAL_PLACE}/place.md"));
    let text = fs::read_to_string(&place_path)
        .unwrap()
        .replace("kind: work\n", "");
    fs::write(&place_path, text).unwrap();
    let first = report(dir.path());
    assert!(
        codes(&first).contains(&"E_FRONTMATTER"),
        "{:?}",
        first.findings
    );

    let dir = personal_04_vault();
    let place_path = dir.path().join(format!("places/{PERSONAL_PLACE}/place.md"));
    let text = fs::read_to_string(&place_path)
        .unwrap()
        .replace("kind: work\n", "kind: work\nno-ai: notes\n");
    fs::write(&place_path, text).unwrap();
    let second = report(dir.path());
    assert!(
        codes(&second).contains(&"E_FRONTMATTER"),
        "{:?}",
        second.findings
    );
}
