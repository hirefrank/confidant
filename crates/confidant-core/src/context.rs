//! `context <person>`: one JSON bundle of everything the vault knows about a
//! person — profile, notes, interactions, coaching facts, aliases.
//!
//! Privacy: PII (name, profile body, note and interaction bodies) is shown
//! only for records in the §12 cleared set ([`cleared_record_ids`]), exactly
//! like `find`. A cleared person implies every member of its merge group is
//! cleared (fixpoint invariant in `search.rs`), so merge-folded and
//! duplicate-tainted records can never leak through `context`. `--exclude-private`
//! strips PII regardless. Ledger-derived facts (sessions remaining, ICF hours,
//! opaque alias hashes) are metadata, not content, and are kept.
//! [`PersonView::no_ai`] always tells the caller which mode applied.

use serde::Serialize;

use crate::check::{canonical_on, check_aliases_and_merges, pack_snapshots, resolve_as_of_date};
use crate::id::RecordId;
use crate::packs::coaching::CoachingView;
use crate::record::RecordKind;
use crate::search::cleared_record_ids;
use crate::vault::Vault;

/// What the caller may see of the person record.
#[derive(Clone, Debug, Serialize)]
pub struct PersonView {
    pub id: String,
    pub name: Option<String>,
    pub no_ai: bool,
    pub profile: Option<String>,
}

/// One note under `people/<id>/notes/`.
#[derive(Clone, Debug, Serialize)]
pub struct NoteView {
    pub id: String,
    pub date: Option<String>,
    pub body: Option<String>,
}

/// One interaction record linked to the person.
#[derive(Clone, Debug, Serialize)]
pub struct InteractionView {
    pub id: String,
    pub date: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
}

// CoachingView lives in crate::packs::coaching. Kept for the agent contract
// (ADR-7): `context` output keeps the `coaching` field with exactly this
// shape. Pack state is grouped by pack in PersonContext::packs; `coaching`
// is the coaching pack's entry in that map, deserialized back into this
// struct.

/// The full bundle returned by `context`.
#[derive(Clone, Debug, Serialize)]
pub struct PersonContext {
    pub person: PersonView,
    pub notes: Vec<NoteView>,
    pub interactions: Vec<InteractionView>,
    pub coaching: Option<CoachingView>,
    /// Pack state grouped by pack name (`"coaching@0.1"` today). Each pack
    /// decides its own view shape via `Pack::context_view`. `coaching` above
    /// duplicates this map's coaching entry for contract stability.
    pub packs: std::collections::BTreeMap<String, serde_json::Value>,
    /// Opaque `hmac:<hex>` values from ledger `alias` lines.
    pub aliases: Vec<String>,
    /// Envelopes skipped as unreadable while loading (spec 4, ⚠2).
    pub skipped_encrypted: u32,
    /// Envelopes refused as tampered/corrupt while loading (spec 4, ⚠2c).
    pub refused_envelopes: u32,
}

/// Build the context bundle for `person`.
///
/// Returns `None` when no record with that id exists. `include_private`
/// controls PII; records outside the §12 cleared set never show PII,
/// and uncleared notes/interactions are omitted entirely (like `find`).
pub fn build_context(
    vault: &Vault,
    person: &RecordId,
    include_private: bool,
) -> Option<PersonContext> {
    let record = vault.records.get(person)?;
    if record.kind != RecordKind::Person {
        return None;
    }
    // §12 allowlist, built once. `cleared` is a fixpoint: a cleared id implies
    // all of its merge-group members are cleared, so `cleared.contains`
    // covers the "person AND every merge-group member" rule with one lookup.
    let cleared = cleared_record_ids(vault);
    let no_ai = record.no_ai();
    let show_pii = include_private && cleared.contains(person);

    let as_of = resolve_as_of_date(vault);
    // Merge canonicalization is pack-independent: it walks the core merge
    // map, the same map the pack folds received.
    let known_ids: std::collections::HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut merge_findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut merge_findings);
    drop(merge_findings);
    let canonical = canonical_on(person, &merges, as_of);

    let snapshots = pack_snapshots(vault, as_of);
    let mut packs: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for (pack, state) in &snapshots {
        if let Some(view) = pack.context_view(vault, state.as_ref(), person, &canonical, as_of) {
            packs.insert(pack.name().to_string(), view);
        }
    }
    // Legacy contract field: the coaching pack's entry, deserialized back.
    // `to_value` in the pack produced it from this struct, so this cannot
    // fail unless the pack's view shape drifts from the struct.
    let coaching = packs
        .get(crate::config::COACHING_PACK)
        .and_then(|v| serde_json::from_value::<CoachingView>(v.clone()).ok());

    let person_dir = format!("people/{person}/notes/");

    let mut notes: Vec<NoteView> = vault
        .records
        .values()
        .filter(|r| {
            r.kind == RecordKind::Note
                && cleared.contains(&r.id)
                && (r.path.starts_with(&person_dir) || r.person().as_ref() == Some(&canonical))
        })
        .map(|r| NoteView {
            id: r.id.to_string(),
            date: r.field("date").map(str::to_owned),
            body: show_pii.then(|| r.body.clone()),
        })
        .collect();
    notes.sort_by(|a, b| a.date.cmp(&b.date).then(a.id.cmp(&b.id)));

    let mut interactions: Vec<InteractionView> = vault
        .records
        .values()
        .filter(|r| {
            r.kind == RecordKind::Interaction
                && cleared.contains(&r.id)
                && r.person().as_ref() == Some(&canonical)
        })
        .map(|r| InteractionView {
            id: r.id.to_string(),
            date: r.field("date").map(str::to_owned),
            title: show_pii.then(|| r.name.clone()).flatten(),
            body: show_pii.then(|| r.body.clone()),
        })
        .collect();
    interactions.sort_by(|a, b| a.date.cmp(&b.date).then(a.id.cmp(&b.id)));

    let aliases: Vec<String> = vault
        .entries
        .iter()
        .filter(|s| {
            s.entry.verb == "alias" && canonical_on(&s.entry.id, &merges, as_of) == canonical
        })
        .filter_map(|s| s.entry.pair("hmac"))
        .map(|h| format!("hmac:{h}"))
        .collect();

    Some(PersonContext {
        person: PersonView {
            id: person.to_string(),
            name: show_pii.then(|| record.name.clone()).flatten(),
            no_ai,
            profile: show_pii.then(|| record.body.clone()),
        },
        notes,
        interactions,
        coaching,
        packs,
        aliases,
        skipped_encrypted: vault.skipped_encrypted,
        refused_envelopes: vault.refused_envelopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RecordId;

    #[test]
    fn missing_person_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let id = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        assert!(build_context(&vault, &id, true).is_none());
    }
}
