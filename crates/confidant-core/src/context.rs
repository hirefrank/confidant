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

use crate::check::{coaching_snapshot, duration_of, resolve_as_of_date};
use crate::id::RecordId;
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

/// One ledger session for the person.
#[derive(Clone, Debug, Serialize)]
pub struct RecentSession {
    pub date: String,
    pub duration_minutes: Option<u32>,
    pub tag: Option<String>,
}

/// Merge-aware coaching facts for the person.
#[derive(Clone, Debug, Serialize)]
pub struct CoachingView {
    pub sessions_remaining: i64,
    pub icf_hours: f64,
    pub recent_sessions: Vec<RecentSession>,
}

/// The full bundle returned by `context`.
#[derive(Clone, Debug, Serialize)]
pub struct PersonContext {
    pub person: PersonView,
    pub notes: Vec<NoteView>,
    pub interactions: Vec<InteractionView>,
    pub coaching: Option<CoachingView>,
    /// Opaque `hmac:<hex>` values from ledger `alias` lines.
    pub aliases: Vec<String>,
}

fn billing_tag(entry: &crate::ledger::LedgerEntry) -> Option<String> {
    for tag in ["paid", "pps", "comp"] {
        if entry.has_token(tag) {
            return Some(tag.to_owned());
        }
    }
    None
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
    let state = coaching_snapshot(vault, as_of);
    let canonical = state
        .as_ref()
        .map(|s| s.canonical_on(person, as_of))
        .unwrap_or_else(|| person.clone());

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

    let mut sessions: Vec<RecentSession> = vault
        .entries
        .iter()
        .filter(|s| {
            s.entry.verb == "session"
                && state
                    .as_ref()
                    .map(|st| st.canonical_on(&s.entry.id, as_of) == canonical)
                    .unwrap_or(s.entry.id == canonical)
        })
        .map(|s| RecentSession {
            date: s.entry.date.to_string(),
            duration_minutes: duration_of(&s.entry),
            tag: billing_tag(&s.entry),
        })
        .collect();
    sessions.sort_by(|a, b| b.date.cmp(&a.date));
    sessions.truncate(10);

    let coaching = state.as_ref().map(|s| CoachingView {
        sessions_remaining: s.sessions_remaining_on(&canonical, as_of),
        icf_hours: s.icf_hours_hundredths_on(&canonical, as_of) as f64 / 100.0,
        recent_sessions: sessions,
    });

    let aliases: Vec<String> = vault
        .entries
        .iter()
        .filter(|s| {
            s.entry.verb == "alias"
                && state
                    .as_ref()
                    .map(|st| st.canonical_on(&s.entry.id, as_of) == canonical)
                    .unwrap_or(s.entry.id == canonical)
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
        aliases,
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
