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
//! [`PersonView::no_ai`] always tells the caller which mode applied. With
//! `for_operator` (#572) the operator cleared set is used instead, so
//! `no-ai` records are included and each view carries the tri-state
//! [`PersonView::no_ai_mode`] / `NoteView::no_ai`; that path is
//! operator-only (never MCP).
//!
//! The built-in personal pack's `packs` entry (shape, merge rule, private
//! fields) lives in [`personal`]; `context` only strips the fields the pack
//! declares as private. The ledger-derived `ledger-sessions` entry lives in
//! [`ledger_sessions`] and is served by whichever enabled pack reports it —
//! the shipped external coaching pack (a `[context]` pack, #449/#594).

pub mod ledger_sessions;
pub mod personal;

use std::collections::HashSet;

use serde::{Serialize, Serializer};

use crate::check::{canonical_on, check_aliases_and_merges, pack_snapshots, resolve_as_of_date};
use crate::context::ledger_sessions::{
    owns_legacy_coaching_alias, LedgerSessionsView, LEDGER_SESSIONS_VIEW,
};
use crate::id::RecordId;
use crate::record::RecordKind;
use crate::scope::{
    note_linkage_owners, owners_of_ledger_entry, record_owners, OwnerKey, PackScope,
};
use crate::search::{cleared_record_ids, cleared_record_ids_for_operator, operator_no_ai_badge};
use crate::vault::Vault;

/// What the caller may see of the person record.
///
/// `no_ai` is a boolean on the agent path. On the operator path
/// (`--for-operator`, #572) the same JSON key carries the tri-state string
/// `"true"` / `"notes"` / `"false"` instead — the shape the roster already
/// reports (#559) — so a UI can badge the mode. Agents never see the
/// operator form, which is why serialization is hand-written rather than
/// derived.
#[derive(Clone, Debug)]
pub struct PersonView {
    pub id: String,
    pub name: Option<String>,
    /// The person's own `no-ai: true` flag (agent path).
    pub no_ai: bool,
    /// Operator path (#572): the tri-state string, `Some` only when the
    /// caller passed `--for-operator`.
    pub no_ai_mode: Option<&'static str>,
    pub profile: Option<String>,
}

impl Serialize for PersonView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("PersonView", 4)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("name", &self.name)?;
        match self.no_ai_mode {
            Some(mode) => st.serialize_field("no_ai", mode)?,
            None => st.serialize_field("no_ai", &self.no_ai)?,
        }
        st.serialize_field("profile", &self.profile)?;
        st.end()
    }
}

/// One note under `people/<id>/notes/`.
#[derive(Clone, Debug, Serialize)]
pub struct NoteView {
    pub id: String,
    pub date: Option<String>,
    pub body: Option<String>,
    /// Operator path (#572): tri-state `no_ai`, absent on the agent path so
    /// its JSON is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_ai: Option<&'static str>,
}

/// One mirrored touchpoint for the person: a ledger `touch` line carrying
/// only a date and the participant's own id, plus a kind when a pack needs
/// one (#179). No other participant ids, no primary id, no interaction id.
#[derive(Clone, Debug, Serialize)]
pub struct TouchpointView {
    pub date: String,
    pub kind: Option<String>,
}

/// One interaction record linked to the person.
#[derive(Clone, Debug, Serialize)]
pub struct InteractionView {
    pub id: String,
    pub date: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    /// Operator path (#572): tri-state `no_ai`, absent on the agent path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_ai: Option<&'static str>,
}

// `LedgerSessionsView` lives in crate::context::ledger_sessions. Kept for
// the agent contract (ADR-7): `context` output keeps the `coaching` field
// with exactly this shape. Pack state is grouped by pack in
// PersonContext::packs; `coaching` is the `ledger-sessions` provider's entry
// in that map (the shipped external `coaching` pack), deserialized back
// into this struct.

/// The full bundle returned by `context`.
#[derive(Clone, Debug, Serialize)]
pub struct PersonContext {
    pub person: PersonView,
    pub notes: Vec<NoteView>,
    pub interactions: Vec<InteractionView>,
    /// Mirrored touchpoints for this person (#179): their own `touch`
    /// ledger lines. Participants in a multi-person interaction see their
    /// touchpoint here, not the interaction content.
    pub touchpoints: Vec<TouchpointView>,
    pub coaching: Option<LedgerSessionsView>,
    /// Pack state grouped by pack name (`"coaching@0.1"` today). Each pack
    /// decides its own view shape via `Pack::context_view`. `coaching` above
    /// duplicates the coaching pack's entry for contract stability; the
    /// alias is tied to the pack named `coaching` (ADR-7), whatever origin it
    /// came from.
    pub packs: std::collections::BTreeMap<String, serde_json::Value>,
    /// Opaque `hmac:<hex>` values from ledger `alias` lines.
    pub aliases: Vec<String>,
    /// Envelopes skipped as unreadable while loading (spec 4, ⚠2).
    pub skipped_encrypted: u32,
    /// Envelopes refused as tampered/corrupt while loading (spec 4, ⚠2c).
    pub refused_envelopes: u32,
    /// Pack names in scope for this bundle, sorted. For an unscoped call,
    /// every enabled pack — the scope that actually applied (#178).
    pub scope: Vec<String>,
    /// Operator path (#572): `true` only for `--for-operator`. Skipped for
    /// agents so their `--json` output is byte-for-byte unchanged; present
    /// so a human-facing consumer can label operator mode.
    #[serde(skip_serializing_if = "is_false")]
    pub for_operator: bool,
}

/// `skip_serializing_if` for the operator flag (#572).
fn is_false(value: &bool) -> bool {
    !*value
}

/// Build the context bundle for `person`.
///
/// Returns `None` when no record with that id exists. `include_private`
/// controls PII; records outside the §12 cleared set never show PII,
/// and uncleared notes/interactions are omitted entirely (like `find`).
/// `scope` further filters to the packs in scope (#178): core-owned items
/// (name, profile, aliases) stay visible, notes/interactions owned by
/// other packs are omitted, unattributed notes/interactions are omitted,
/// and other packs' views are dropped from `packs`.
///
/// `for_operator` (#572) is the operator-only path: `no-ai` is ignored when
/// building the cleared set, so a `no-ai` person and their `no-ai` notes and
/// interactions are included, and each view carries the tri-state `no_ai`
/// string plus `for_operator: true`. The caller must have loaded the vault
/// with the operator decryptor (same mechanism as `record show --for-edit`)
/// for the content to be present; an agent path passes `false`.
pub fn build_context(
    vault: &Vault,
    person: &RecordId,
    include_private: bool,
    scope: &PackScope,
    for_operator: bool,
) -> Option<PersonContext> {
    let record = vault.records.get(person)?;
    if record.kind != RecordKind::Person {
        return None;
    }
    // §12 allowlist. `cleared` is a fixpoint: a cleared id implies all of
    // its merge-group members are cleared, so `cleared.contains` covers the
    // "person AND every merge-group member" rule with one lookup. The
    // operator variant ignores `no-ai` (#572) so an operator-only read
    // surfaces records the agent path hides. `hidden_by_no_ai` is the
    // operator-minus-agent difference: the records that are hidden *only*
    // because of `no-ai`, which each view badges.
    let agent_cleared = cleared_record_ids(vault);
    let operator_cleared = for_operator.then(|| cleared_record_ids_for_operator(vault));
    let cleared: &HashSet<RecordId> = operator_cleared.as_ref().unwrap_or(&agent_cleared);
    let hidden_by_no_ai: HashSet<RecordId> = match &operator_cleared {
        Some(op) => op.difference(&agent_cleared).cloned().collect(),
        None => HashSet::new(),
    };
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
        // #178: a scoped call sees only its packs' views.
        if !scope.allows(&[OwnerKey::Pack(pack.name())].into_iter().collect()) {
            continue;
        }
        if let Some(mut view) = pack.context_view(vault, state.as_ref(), person, &canonical, as_of)
        {
            // #185/#302: a pack declares its own PII fields rather than core
            // hardcoding pack names. Strip them when private data is excluded.
            let private = pack.private_context_fields();
            if !show_pii && !private.is_empty() {
                if let Some(obj) = view.as_object_mut() {
                    for field in private {
                        obj.remove(*field);
                    }
                }
            }
            packs.insert(pack.name().to_string(), view);
        }
    }
    // Legacy contract field: the coaching pack's entry, deserialized back.
    // The alias is tied to the coaching pack (ADR-7), not to the view kind:
    // any `[context]` pack can serve the `ledger-sessions` kind, but only the
    // pack named `coaching` (the shipped external `coaching@0.1`) owns the
    // legacy alias. Another
    // pack serving the same kind must leave `coaching` null. The key is never
    // hardcoded: the version comes from the enabled pack, matched by base
    // name. `to_value` in the builder produced it from this struct, so this
    // cannot fail unless the view shape drifts from the struct.
    let coaching = snapshots.iter().find_map(|(pack, _)| {
        if !owns_legacy_coaching_alias(pack.name())
            || pack.context_view_kind() != Some(LEDGER_SESSIONS_VIEW)
        {
            return None;
        }
        packs
            .get(pack.name())
            .and_then(|v| serde_json::from_value::<LedgerSessionsView>(v.clone()).ok())
    });

    let person_dir = format!("people/{person}/notes/");

    // #178: notes/interactions filter by pack ownership. A note is visible
    // when a pack in scope owns it (field claim or ledger linkage);
    // unattributed notes are visible only unscoped.
    let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    let linkage = note_linkage_owners(vault, &enabled);
    let scope_names = scope.names(&enabled);

    let mut notes: Vec<NoteView> = vault
        .records
        .values()
        .filter(|r| {
            r.kind == RecordKind::Note
                && cleared.contains(&r.id)
                && (r.path.starts_with(&person_dir) || r.person().as_ref() == Some(&canonical))
                && scope.allows(&record_owners(r, &linkage, &enabled))
        })
        .map(|r| NoteView {
            id: r.id.to_string(),
            date: r.field("date").map(str::to_owned),
            body: show_pii.then(|| r.body.clone()),
            no_ai: for_operator.then(|| operator_no_ai_badge(r, &hidden_by_no_ai)),
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
                && scope.allows(&record_owners(r, &linkage, &enabled))
        })
        .map(|r| InteractionView {
            id: r.id.to_string(),
            date: r.field("date").map(str::to_owned),
            title: show_pii.then(|| r.name.clone()).flatten(),
            body: show_pii.then(|| r.body.clone()),
            no_ai: for_operator.then(|| operator_no_ai_badge(r, &hidden_by_no_ai)),
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

    // #179: mirrored touchpoints — the participant's own `touch` lines.
    // Like aliases, these are ledger-derived metadata (not record PII),
    // so they carry no cleared-set gate; scope-filtered by verb ownership
    // (core for kind-less touchpoints).
    let mut touchpoints: Vec<TouchpointView> = vault
        .entries
        .iter()
        .filter(|s| {
            s.entry.verb == "touch"
                && canonical_on(&s.entry.id, &merges, as_of) == canonical
                && scope.allows(&owners_of_ledger_entry(&s.entry, &enabled))
        })
        .map(|s| TouchpointView {
            date: s.entry.date.to_string(),
            // The touchpoint kind is the claiming pack's grammar (#185/#296):
            // ask the registered pack through the trait, never a specific
            // pack module.
            kind: vault
                .pack_registry()
                .all()
                .iter()
                .find(|p| p.verbs().contains(&s.entry.verb.as_str()))
                .and_then(|p| p.verb_kind(&s.entry.verb, &s.entry)),
        })
        .collect();
    touchpoints.sort_by(|a, b| a.date.cmp(&b.date).then(a.kind.cmp(&b.kind)));

    Some(PersonContext {
        person: PersonView {
            id: person.to_string(),
            name: show_pii.then(|| record.name.clone()).flatten(),
            no_ai,
            no_ai_mode: for_operator.then(|| operator_no_ai_badge(record, &hidden_by_no_ai)),
            profile: show_pii.then(|| record.body.clone()),
        },
        notes,
        interactions,
        touchpoints,
        coaching,
        packs,
        aliases,
        skipped_encrypted: vault.skipped_encrypted,
        refused_envelopes: vault.refused_envelopes,
        scope: scope_names,
        for_operator,
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
        assert!(build_context(&vault, &id, true, &PackScope::All, false).is_none());
    }

    fn demo_vault() -> crate::vault::Vault {
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault");
        crate::vault::load_vault(&root).unwrap()
    }

    fn coaching_scope() -> PackScope {
        PackScope::Only(["coaching@0.1".to_string()].into_iter().collect())
    }

    #[test]
    fn scoped_context_hides_unattributed_notes_and_interactions() {
        // Demo vault Ada: one session-linked note (coaching), one
        // unattributed note, one unattributed interaction.
        let vault = demo_vault();
        let ada = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        let unscoped = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert_eq!(unscoped.notes.len(), 2);
        assert_eq!(unscoped.interactions.len(), 1);
        assert!(unscoped.coaching.is_some());

        let scoped = build_context(&vault, &ada, true, &coaching_scope(), false).unwrap();
        // Only the session-linked note survives; the unattributed note and
        // the interaction are hidden. Core identity stays visible.
        assert_eq!(scoped.notes.len(), 1);
        assert_eq!(scoped.notes[0].id, "n-01M3TC5H00MPJG002NAM000005");
        assert!(scoped.interactions.is_empty());
        assert!(scoped.coaching.is_some());
        assert_eq!(scoped.person.name.as_deref(), Some("Ada Example"));
        assert!(!scoped.aliases.is_empty());
        assert_eq!(scoped.scope, vec!["coaching@0.1"]);
    }

    #[test]
    fn context_shows_own_touchpoints_only() {
        // #179: a participant sees their own mirrored touchpoints in
        // `context` — date + optional kind, no other ids — and nothing
        // from another participant's touchpoints.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
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
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!(
                "2026-10-06 touch {bea}\n2026-10-07 touch {bea} kind:call\n2026-10-06 touch {ada}\n"
            ),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let bea_id = RecordId::parse(bea).unwrap();
        let bea_ctx = build_context(&vault, &bea_id, true, &PackScope::All, false).unwrap();
        assert_eq!(bea_ctx.touchpoints.len(), 2);
        assert_eq!(bea_ctx.touchpoints[0].date, "2026-10-06");
        assert_eq!(bea_ctx.touchpoints[0].kind, None);
        assert_eq!(bea_ctx.touchpoints[1].date, "2026-10-07");
        assert_eq!(bea_ctx.touchpoints[1].kind.as_deref(), Some("call"));
        // Ada sees only her own touchpoint, not Bea's.
        let ada_id = RecordId::parse(ada).unwrap();
        let ada_ctx = build_context(&vault, &ada_id, true, &PackScope::All, false).unwrap();
        assert_eq!(ada_ctx.touchpoints.len(), 1);
        assert_eq!(ada_ctx.touchpoints[0].date, "2026-10-06");
    }

    #[test]
    fn scoped_context_drops_other_packs_views() {
        // The packs map only carries views for packs in scope.
        let vault = demo_vault();
        let ada = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        let scoped = build_context(&vault, &ada, true, &coaching_scope(), false).unwrap();
        assert!(scoped.packs.contains_key("coaching@0.1"));
        let empty = PackScope::Only(std::collections::BTreeSet::new());
        let none = build_context(&vault, &ada, true, &empty, false).unwrap();
        assert!(none.packs.is_empty());
        assert!(none.coaching.is_none());
        // Core identity is still there even with an empty scope.
        assert_eq!(none.person.name.as_deref(), Some("Ada Example"));
    }

    /// #572: the operator bundle decrypts a `no-ai: true` person, carries
    /// the tri-state `no_ai`, and includes the note that inherits hidden.
    /// The agent bundle is unchanged: name withheld, note absent, boolean.
    #[test]
    fn operator_context_shows_no_ai_person_and_badges_inherited_note() {
        let vault = demo_vault();
        let cam = RecordId::parse("p-01M3TC5H00MPJG001248000002").unwrap();

        let agent = build_context(&vault, &cam, true, &PackScope::All, false).unwrap();
        assert!(agent.person.name.is_none());
        assert!(agent.person.no_ai);
        assert!(agent.person.no_ai_mode.is_none());
        assert!(!agent.for_operator);
        assert!(agent.notes.is_empty());

        let op = build_context(&vault, &cam, true, &PackScope::All, true).unwrap();
        assert_eq!(op.person.name.as_deref(), Some("Cam Sample"));
        assert_eq!(op.person.no_ai_mode, Some("true"));
        assert!(op.person.profile.is_some());
        assert!(op.for_operator);
        assert_eq!(op.notes.len(), 1);
        assert_eq!(op.notes[0].no_ai, Some("true"));
    }

    /// #572: a `no-ai: notes` person badges `"notes"`; their inherited
    /// note badges `"true"`, an explicit `no-ai: false` child `"false"`,
    /// and an explicit `no-ai: true` child `"true"`.
    #[test]
    fn operator_context_badges_notes_mode_and_hidden_children() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let person = "p-01M3TC5H00MPJG000000000000";
        let d = dir.path().join(format!("people/{person}"));
        std::fs::create_dir_all(d.join("notes")).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!(
                "---\nid: {person}\ntype: person\nname: Notes Mode\nno-ai: notes\n---\n\nBio.\n"
            ),
        )
        .unwrap();
        for (id, extra, body) in [
            ("n-01M3TC5H00MPJG000000000001", "", "inherited hidden\n"),
            (
                "n-01M3TC5H00MPJG000000000002",
                "no-ai: false\n",
                "explicit visible\n",
            ),
            (
                "n-01M3TC5H00MPJG000000000003",
                "no-ai: true\n",
                "explicit hidden\n",
            ),
        ] {
            std::fs::write(
                d.join("notes").join(format!("{id}.md")),
                format!(
                    "---\nid: {id}\ntype: note\nperson: {person}\ndate: 2026-01-01\n{extra}---\n\n{body}"
                ),
            )
            .unwrap();
        }
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let id = RecordId::parse(person).unwrap();

        // Agent path: the notes-mode person is visible, but the inherited
        // and explicit-hidden children are omitted.
        let agent = build_context(&vault, &id, true, &PackScope::All, false).unwrap();
        assert_eq!(agent.person.name.as_deref(), Some("Notes Mode"));
        assert_eq!(agent.person.no_ai_mode, None);
        let agent_notes: Vec<&str> = agent.notes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(agent_notes, vec!["n-01M3TC5H00MPJG000000000002"]);

        // Operator path: every child, each badged by its effective mode.
        let op = build_context(&vault, &id, true, &PackScope::All, true).unwrap();
        assert_eq!(op.person.no_ai_mode, Some("notes"));
        assert!(op.for_operator);
        let badge = |id: &str| op.notes.iter().find(|n| n.id == id).unwrap().no_ai;
        assert_eq!(badge("n-01M3TC5H00MPJG000000000001"), Some("true"));
        assert_eq!(badge("n-01M3TC5H00MPJG000000000002"), Some("false"));
        assert_eq!(badge("n-01M3TC5H00MPJG000000000003"), Some("true"));
    }
}
