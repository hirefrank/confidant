//! Property-based tests for the spec §12 cleared set (#886).
//!
//! The fail-closed boundary is a fixpoint: every id the computation keeps must
//! still satisfy every rule when re-checked against the result. Spot fixtures
//! cover the named cases; these generated vaults cover the interaction between
//! `no-ai` modes, note inheritance, path ownership, and named ledger lines.
//!
//! Monotonicity is the second half of "fail closed": adding hidden content
//! (marking a record `no-ai`) may only remove ids from the cleared set, never
//! reveal one, and adding an independent visible record may only add ids.

use std::fs;
use std::path::Path;

use confidant_core::id::{ulid_from_parts, Prefix, RecordId};
use confidant_core::{allowlist_is_fixed_point, cleared_record_ids, load_vault, Vault};
use proptest::prelude::*;

#[derive(Clone, Debug)]
struct PersonSpec {
    id: String,
    no_ai: Option<&'static str>,
}

#[derive(Clone, Debug)]
struct NoteSpec {
    id: String,
    /// Index into `persons`, coerced modulo the person count.
    person: usize,
    no_ai: Option<bool>,
}

#[derive(Clone, Debug)]
struct VaultSpec {
    persons: Vec<PersonSpec>,
    notes: Vec<NoteSpec>,
}

/// A deterministic fake ULID. Prefixes plus the index keep every id in one
/// generated vault distinct; no real data is involved.
fn fake_id(prefix: Prefix, index: u32) -> String {
    RecordId::new(
        prefix,
        ulid_from_parts(1_790_812_800_000, u128::from(index)),
    )
    .expect("ulid_from_parts is canonical")
    .to_string()
}

fn vault_spec() -> impl Strategy<Value = VaultSpec> {
    (
        prop::collection::vec(
            prop::option::of(prop::sample::select(vec!["true", "false", "notes"])),
            1..=3,
        ),
        prop::collection::vec((0usize..3, prop::option::of(any::<bool>())), 0..=3),
    )
        .prop_map(|(person_modes, notes)| {
            let persons: Vec<PersonSpec> = person_modes
                .into_iter()
                .enumerate()
                .map(|(index, no_ai)| PersonSpec {
                    id: fake_id(Prefix::Person, 1000 + index as u32),
                    no_ai,
                })
                .collect();
            let notes = notes
                .into_iter()
                .enumerate()
                .map(|(index, (person, no_ai))| NoteSpec {
                    id: fake_id(Prefix::Note, 2000 + index as u32),
                    person: person % persons.len(),
                    no_ai,
                })
                .collect();
            VaultSpec { persons, notes }
        })
}

fn write_file(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture directory");
    }
    fs::write(path, contents).expect("write fixture file");
}

/// Render a spec-0.2 vault to disk and load it. `checks.as_of` is pinned so a
/// check in a caller can never depend on the wall clock.
fn render(spec: &VaultSpec) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write_file(
        root,
        "confidant.toml",
        "spec = \"0.2\"\npacks = []\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-13\"\n",
    );

    for (index, person) in spec.persons.iter().enumerate() {
        let mut front = format!(
            "---\nid: {}\ntype: person\nname: \"Robin Example {}\"\n",
            person.id,
            index + 1
        );
        if let Some(mode) = person.no_ai {
            front.push_str(&format!("no-ai: {mode}\n"));
        }
        front.push_str("---\n\nFake person.\n");
        write_file(root, &format!("people/{}/profile.md", person.id), &front);
    }

    for (index, note) in spec.notes.iter().enumerate() {
        let person = &spec.persons[note.person];
        let mut front = format!(
            "---\nid: {}\ntype: note\nperson: {}\ndate: 2026-10-01\n",
            note.id, person.id
        );
        if let Some(no_ai) = note.no_ai {
            front.push_str(&format!("no-ai: {no_ai}\n"));
        }
        front.push_str(&format!("---\n\nFake note {index}.\n"));
        write_file(
            root,
            &format!("people/{}/notes/{}.md", person.id, note.id),
            &front,
        );
    }

    let mut ledger = String::new();
    for person in &spec.persons {
        ledger.push_str(&format!("2026-10-01 touch {} call\n", person.id));
    }
    write_file(root, "ledger/2026/10.cfd", &ledger);

    let vault = load_vault(root).expect("generated vault must load");
    (dir, vault)
}

fn id(spec: &str) -> RecordId {
    RecordId::parse(spec).expect("generated ids are valid")
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Disk-backed: one small vault per case. This is enough input space
        // to hit the interaction rules without slowing CI on two platforms.
        cases: 24,
        ..ProptestConfig::default()
    })]

    /// The cleared set is a fixpoint, deterministic, and never contains a
    /// record the agent path is meant to hide.
    #[test]
    fn cleared_set_is_a_fail_closed_fixpoint(spec in vault_spec()) {
        let (_dir, vault) = render(&spec);
        prop_assert!(
            allowlist_is_fixed_point(&vault),
            "not a fixpoint for {spec:?}"
        );
        let cleared = cleared_record_ids(&vault);
        prop_assert_eq!(
            &cleared,
            &cleared_record_ids(&vault),
            "cleared set is not deterministic"
        );

        for rec in vault.records.values() {
            if rec.no_ai() {
                prop_assert!(
                    !cleared.contains(&rec.id),
                    "no-ai record {} stayed cleared",
                    rec.id
                );
            }
        }

        for person in &spec.persons {
            let person_id = id(&person.id);
            if person.no_ai == Some("true") {
                prop_assert!(
                    !cleared.contains(&person_id),
                    "no-ai person {} stayed cleared",
                    person.id
                );
            }
        }

        for note in &spec.notes {
            let note_id = id(&note.id);
            let person = &spec.persons[note.person];
            if note.no_ai == Some(true) {
                prop_assert!(
                    !cleared.contains(&note_id),
                    "no-ai note {} stayed cleared",
                    note.id
                );
            }
            // A note with no explicit flag inherits `notes` mode from its
            // person; `no-ai: false` is the documented override.
            if note.no_ai.is_none() && person.no_ai == Some("notes") {
                prop_assert!(
                    !cleared.contains(&note_id),
                    "note {} inherited notes mode but stayed cleared",
                    note.id
                );
            }
            if person.no_ai == Some("true") {
                prop_assert!(
                    !cleared.contains(&note_id),
                    "note {} of a hidden person stayed cleared",
                    note.id
                );
            }
        }
    }

    /// Adding hiddenness can only shrink the cleared set. Marking an existing
    /// person `no-ai: true` must never reveal another id.
    #[test]
    fn adding_no_ai_is_monotone(spec in vault_spec()) {
        let (_base_dir, base) = render(&spec);
        let base_cleared = cleared_record_ids(&base);

        let mut hidden = spec.clone();
        hidden.persons[0].no_ai = Some("true");
        let (_hidden_dir, hidden_vault) = render(&hidden);
        prop_assert!(
            allowlist_is_fixed_point(&hidden_vault),
            "marked vault is not a fixpoint for {hidden:?}"
        );
        let hidden_cleared = cleared_record_ids(&hidden_vault);
        prop_assert!(
            hidden_cleared.is_subset(&base_cleared),
            "marking a person no-ai revealed ids: hidden={hidden_cleared:?} base={base_cleared:?}"
        );
    }

    /// Adding an independent visible record can only grow the cleared set:
    /// new content adds constraints for the new record, never for old ones.
    #[test]
    fn adding_visible_content_is_monotone(spec in vault_spec()) {
        let (_base_dir, base) = render(&spec);
        let base_cleared = cleared_record_ids(&base);

        let mut grown = spec.clone();
        let extra_id = fake_id(Prefix::Person, 900);
        grown.persons.push(PersonSpec {
            id: extra_id.clone(),
            no_ai: None,
        });
        let (_grown_dir, grown_vault) = render(&grown);
        prop_assert!(
            allowlist_is_fixed_point(&grown_vault),
            "grown vault is not a fixpoint for {grown:?}"
        );
        let grown_cleared = cleared_record_ids(&grown_vault);
        prop_assert!(
            base_cleared.is_subset(&grown_cleared),
            "independent content hid ids: base={base_cleared:?} grown={grown_cleared:?}"
        );
        prop_assert!(grown_cleared.contains(&id(&extra_id)));
    }
}
