//! `context <id>`: one JSON bundle of everything the vault knows about a
//! person or an org (#813) — profile, notes, interactions, edges,
//! pack-derived facts, aliases.
//!
//! Privacy: PII (name, profile body, note and interaction bodies, the other
//! endpoint's name) is shown only for records in the §12 cleared set
//! ([`cleared_record_ids`]), exactly like `find`. A cleared person implies
//! every member of its merge group is cleared (fixpoint invariant in
//! `search.rs`), so merge-folded and duplicate-tainted records can never
//! leak through `context`. An edge is visible only when both endpoints are
//! cleared and the edge itself is not `no-ai: true`, so a hidden endpoint or
//! a hidden edge is omitted from the other endpoint's bundle entirely. The
//! operator path sees the edge and carries its `no_ai` badge in
//! [`EdgeView::no_ai`]. `--exclude-private` strips PII regardless.
//! Ledger-derived facts (sessions remaining, ICF hours) are metadata, not
//! content, and are kept.
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

use std::collections::{BTreeMap, HashSet};

use serde::{Serialize, Serializer};

use crate::check::{canonical_on, check_aliases_and_merges, pack_snapshots, resolve_as_of_date};
use crate::config::SpecVersion;
use crate::id::{Prefix, RecordId};
use crate::packs::{core_edge_kinds, EdgeKind, Pack};
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

/// The context target: a person or an org (#813).
///
/// This is the canonical target view. `person` stays on the bundle as a
/// deprecated alias for person targets only; an org bundle omits it.
/// `no_ai` follows the same serialization rule as [`PersonView`]: a boolean
/// on the agent path, the tri-state string on the operator path.
#[derive(Clone, Debug)]
pub struct EntityView {
    pub id: String,
    /// `"person"` or `"org"`.
    pub kind: &'static str,
    pub name: Option<String>,
    pub no_ai: bool,
    /// Operator path (#572): the tri-state string, `Some` only when the
    /// caller passed `--for-operator`.
    pub no_ai_mode: Option<&'static str>,
    pub profile: Option<String>,
}

impl Serialize for EntityView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("EntityView", 6)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("name", &self.name)?;
        match self.no_ai_mode {
            Some(mode) => st.serialize_field("no_ai", mode)?,
            None => st.serialize_field("no_ai", &self.no_ai)?,
        }
        st.serialize_field("profile", &self.profile)?;
        st.end()
    }
}

/// The endpoint opposite the context target on one visible edge (#813).
#[derive(Clone, Debug, Serialize)]
pub struct OtherEntityView {
    pub id: String,
    /// `"person"` or `"org"`.
    pub kind: &'static str,
    /// The display name, shown only when private data is included and the
    /// edge's endpoints are cleared (both always hold when an edge is
    /// visible; `--exclude-private` clears it).
    pub name: Option<String>,
    /// Operator path only: the other endpoint's tri-state `no-ai` badge.
    /// Absent on the agent path, where a hidden endpoint omits the edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_ai: Option<&'static str>,
}

/// One edge as seen from the context target (#813).
#[derive(Clone, Debug, Serialize)]
pub struct EdgeView {
    pub id: String,
    pub kind: String,
    /// `"out"` when the target is `a`, `"in"` when it is `b`, `"none"` for a
    /// symmetric kind.
    pub direction: &'static str,
    pub other: OtherEntityView,
    pub since: Option<String>,
    pub until: Option<String>,
    /// Operator path only: the edge's own tri-state `no-ai` badge. Absent on
    /// the agent path, where a hidden edge is omitted entirely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_ai: Option<&'static str>,
}

/// One note under `people/<id>/notes/`, or one attached to an org (#813).
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

// `LedgerSessionsView` lives in crate::context::ledger_sessions. Pack state
// is grouped by pack in PersonContext::packs; a pack's `ledger-sessions`
// view is that pack's entry in the map.

/// The full bundle returned by `context` for a person or org (#813).
#[derive(Clone, Debug, Serialize)]
pub struct PersonContext {
    /// Deprecated person-only alias, present only for a person target.
    /// New readers use [`EntityView`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person: Option<PersonView>,
    /// The canonical target view: a person or an org.
    pub entity: EntityView,
    pub notes: Vec<NoteView>,
    pub interactions: Vec<InteractionView>,
    /// Mirrored touchpoints for this person (#179): their own `touch`
    /// ledger lines. Participants in a multi-person interaction see their
    /// touchpoint here, not the interaction content. Empty for an org.
    pub touchpoints: Vec<TouchpointView>,
    /// Edges whose endpoint is this entity (#813), already filtered by the
    /// §12 cleared set, the kind's endpoint declaration, merge
    /// canonicalization, and pack scope.
    pub edges: Vec<EdgeView>,
    /// Pack state grouped by pack name (`"personal@0.2"` today). Each pack
    /// decides its own view shape via `Pack::context_view`. Empty for an
    /// org: pack views are person-keyed.
    pub packs: BTreeMap<String, serde_json::Value>,
    /// The person's contact values (`emails`, `phones`, `handles`), shown
    /// only when private data is included. Empty under `--exclude-private`,
    /// for records outside the cleared set, and for an org.
    pub aliases: Vec<String>,
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

/// Resolve an edge kind for a read view (#813): an enabled pack's kind,
/// this spec's core kinds, or a registered pack's kind (a disabled pack's
/// kind is an orphan, visible only unscoped). An unknown kind returns
/// `None` and the edge is omitted.
fn resolve_edge_kind(
    vault: &Vault,
    name: &str,
    enabled: &[&dyn Pack],
    spec: SpecVersion,
) -> Option<&'static EdgeKind> {
    enabled
        .iter()
        .find_map(|pack| pack.edge_kinds().iter().find(|kind| kind.name == name))
        .or_else(|| core_edge_kinds(spec).iter().find(|kind| kind.name == name))
        .or_else(|| {
            vault
                .pack_registry()
                .all()
                .iter()
                .find_map(|pack| pack.edge_kinds().iter().find(|kind| kind.name == name))
        })
}

/// Build the context bundle for `target`, a person or an org (#813).
///
/// Returns `None` when no record with that id exists, or when it is not an
/// entity (a deal, note, interaction, or edge). `include_private` controls
/// PII; records outside the §12 cleared set never show PII, and uncleared
/// notes/interactions/edges are omitted entirely (like `find`).
/// `scope` further filters to the packs in scope (#178): core-owned items
/// (name, profile, aliases) stay visible, notes/interactions/edges owned by
/// other packs are omitted, unattributed ones are omitted, and other packs'
/// views are dropped from `packs`.
///
/// `for_operator` (#572) is the operator-only path: `no-ai` is ignored when
/// building the cleared set, so a `no-ai` person and their `no-ai` notes,
/// interactions, and edges are included, and each view carries the
/// tri-state `no_ai` string plus `for_operator: true`. The caller must have
/// loaded the vault with the operator read path (same mechanism as
/// `record show --for-edit`) for the content to be present; an agent path
/// passes `false`.
pub fn build_context(
    vault: &Vault,
    target: &RecordId,
    include_private: bool,
    scope: &PackScope,
    for_operator: bool,
) -> Option<PersonContext> {
    let record = vault.records.get(target)?;
    let is_person = match record.kind {
        RecordKind::Person => true,
        RecordKind::Org => false,
        _ => return None,
    }; // §12 allowlist. `cleared` is a fixpoint: a cleared id implies all of
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
    let show_pii = include_private && cleared.contains(target);

    let as_of = resolve_as_of_date(vault);
    let spec = vault.spec_version().unwrap_or(SpecVersion::V01);
    // Merge canonicalization is pack-independent: it walks the core merge
    // map, the same map the pack folds received.
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut merge_findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut merge_findings);
    drop(merge_findings);
    let canonical = canonical_on(target, &merges, as_of);

    let no_ai_mode = for_operator.then(|| operator_no_ai_badge(record, &hidden_by_no_ai));
    let entity = EntityView {
        id: target.to_string(),
        kind: record.kind.as_str(),
        name: show_pii.then(|| record.name.clone()).flatten(),
        no_ai,
        no_ai_mode,
        profile: show_pii.then(|| record.body.clone()),
    };
    let person = is_person.then(|| PersonView {
        id: target.to_string(),
        name: show_pii.then(|| record.name.clone()).flatten(),
        no_ai,
        no_ai_mode,
        profile: show_pii.then(|| record.body.clone()),
    });

    let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    let linkage = note_linkage_owners(vault, &enabled);
    let scope_names = scope.names(&enabled);

    // Pack state is the whole story for a person: each pack's `[context]`
    // view is its entry in `packs` (ADR-7, #797). Pack views are
    // person-keyed, so an org bundle has none.
    let mut packs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    if is_person {
        let snapshots = pack_snapshots(vault, as_of);
        for (pack, state) in &snapshots {
            // #178: a scoped call sees only its packs' views.
            if !scope.allows(&[OwnerKey::Pack(pack.name())].into_iter().collect()) {
                continue;
            }
            if let Some(mut view) =
                pack.context_view(vault, state.as_ref(), target, &canonical, as_of)
            {
                // #185/#302: a pack declares its own PII fields rather than
                // core hardcoding pack names. Strip them when private data
                // is excluded.
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
    }

    let person_dir = format!("people/{target}/notes/");

    // #178: notes/interactions filter by pack ownership. A note is visible
    // when a pack in scope owns it (field claim or ledger linkage);
    // unattributed notes are visible only unscoped. An org bundle selects
    // records attached by `org:` instead (#813).
    let mut notes: Vec<NoteView> = vault
        .records
        .values()
        .filter(|r| {
            if r.kind != RecordKind::Note || !cleared.contains(&r.id) {
                return false;
            }
            let attached = if is_person {
                r.path.starts_with(&person_dir) || r.person().as_ref() == Some(&canonical)
            } else {
                r.org().as_ref() == Some(&canonical)
            };
            attached && scope.allows(&record_owners(r, &linkage, &enabled, spec))
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
            if r.kind != RecordKind::Interaction || !cleared.contains(&r.id) {
                return false;
            }
            let attached = if is_person {
                r.person().as_ref() == Some(&canonical)
            } else {
                r.org().as_ref() == Some(&canonical)
            };
            attached && scope.allows(&record_owners(r, &linkage, &enabled, spec))
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

    // Aliases and touchpoints are person data (contact fields and the
    // person-subject `touch` verb); an org has neither.
    let mut aliases: Vec<String> = Vec::new();
    if is_person && show_pii {
        for field in ["emails", "phones", "handles"] {
            if let Some(entries) = record
                .field(field)
                .and_then(crate::packs::grammars::parse_list)
            {
                aliases.extend(entries);
            }
        }
    }

    let mut touchpoints: Vec<TouchpointView> = Vec::new();
    if is_person {
        // #179: mirrored touchpoints — the participant's own `touch` lines.
        // Like aliases, these are ledger-derived metadata (not record PII),
        // so they carry no cleared-set gate; scope-filtered by verb ownership
        // (core for kind-less touchpoints).
        touchpoints = vault
            .entries
            .iter()
            .filter(|s| {
                s.entry.verb == "touch"
                    && canonical_on(&s.entry.id, &merges, as_of) == canonical
                    && scope.allows(&owners_of_ledger_entry(&s.entry, &enabled))
            })
            .map(|s| TouchpointView {
                date: s.entry.date.to_string(),
                // The touchpoint kind is the claiming pack's grammar
                // (#185/#296): ask the registered pack through the trait,
                // never a specific pack module.
                kind: vault
                    .pack_registry()
                    .all()
                    .iter()
                    .find(|p| p.verbs().contains(&s.entry.verb.as_str()))
                    .and_then(|p| p.verb_kind(&s.entry.verb, &s.entry)),
            })
            .collect();
        touchpoints.sort_by(|a, b| a.date.cmp(&b.date).then(a.kind.cmp(&b.kind)));
    }

    // #813: edges from this entity. The §12 allowlist scans the edge's own
    // front-matter IDs, so `cleared.contains(edge.id)` already means both
    // endpoints are cleared; the explicit endpoint checks below fail closed
    // on a malformed or half-loaded vault. A broken edge (unknown kind,
    // wrong endpoint type, dangling end, canonical self-relation) is
    // omitted; `check` explains why.
    let mut edges: Vec<EdgeView> = Vec::new();
    let mut seen_edges: HashSet<(RecordId, RecordId, String)> = HashSet::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Edge || !cleared.contains(&rec.id) {
            continue;
        }
        let Some(kind_name) = rec.field("kind") else {
            continue;
        };
        let Some(kind) = resolve_edge_kind(vault, kind_name, &enabled, spec) else {
            continue;
        };
        let (Some(a), Some(b)) = (rec.edge_end("a"), rec.edge_end("b")) else {
            continue;
        };
        let endpoints_ok = if spec == SpecVersion::V01 {
            // 0.1 is frozen: both ends are person IDs and a pack's endpoint
            // declaration is ignored.
            a.prefix() == Prefix::Person && b.prefix() == Prefix::Person
        } else {
            vault.type_registry().is_entity(a.prefix())
                && vault.type_registry().is_entity(b.prefix())
                && kind.allows(a.prefix(), b.prefix())
        };
        if !endpoints_ok {
            continue;
        }
        if !cleared.contains(&a) || !cleared.contains(&b) {
            continue;
        }
        let canonical_a = canonical_on(&a, &merges, as_of);
        let canonical_b = canonical_on(&b, &merges, as_of);
        if canonical_a == canonical_b {
            continue;
        }
        let target_is_a = canonical_a == canonical;
        let target_is_b = canonical_b == canonical;
        if !target_is_a && !target_is_b {
            continue;
        }
        if !scope.allows(&record_owners(rec, &linkage, &enabled, spec)) {
            continue;
        }
        // One relation per canonical pair and kind. `vault.records` is a
        // BTreeMap, so the lowest edge id is seen first and wins.
        let key = if kind.symmetric {
            if canonical_a <= canonical_b {
                (
                    canonical_a.clone(),
                    canonical_b.clone(),
                    kind_name.to_string(),
                )
            } else {
                (
                    canonical_b.clone(),
                    canonical_a.clone(),
                    kind_name.to_string(),
                )
            }
        } else {
            (
                canonical_a.clone(),
                canonical_b.clone(),
                kind_name.to_string(),
            )
        };
        if !seen_edges.insert(key) {
            continue;
        }
        let other_id = if target_is_a {
            &canonical_b
        } else {
            &canonical_a
        };
        let Some(other) = vault.records.get(other_id) else {
            continue;
        };
        let direction = if kind.symmetric {
            "none"
        } else if target_is_a {
            "out"
        } else {
            "in"
        };
        edges.push(EdgeView {
            id: rec.id.to_string(),
            kind: kind_name.to_string(),
            direction,
            other: OtherEntityView {
                id: other_id.to_string(),
                kind: other.kind.as_str(),
                name: (include_private && cleared.contains(other_id))
                    .then(|| other.name.clone())
                    .flatten(),
                no_ai: for_operator.then(|| operator_no_ai_badge(other, &hidden_by_no_ai)),
            },
            since: rec.field("since").map(str::to_owned),
            until: rec.field("until").map(str::to_owned),
            no_ai: for_operator.then(|| operator_no_ai_badge(rec, &hidden_by_no_ai)),
        });
    }
    edges.sort_by(|left, right| {
        let sort_key = |edge: &EdgeView| {
            (
                edge.since.is_none(),
                edge.since.clone().unwrap_or_default(),
                edge.kind.clone(),
                edge.other.id.clone(),
                edge.id.clone(),
            )
        };
        sort_key(left).cmp(&sort_key(right))
    });

    Some(PersonContext {
        person,
        entity,
        notes,
        interactions,
        touchpoints,
        edges,
        packs,
        aliases,
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

    fn example_pack_vault() -> (tempfile::TempDir, crate::vault::Vault) {
        let dir = tempfile::tempdir().unwrap();
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/packs/example-pack");
        let dst = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&dst).unwrap();
        for entry in std::fs::read_dir(&src).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
        let hash = crate::packs::dir::read_pack_dir(&dst).unwrap().hash;
        std::fs::write(
            dir.path().join("confidant.lock"),
            format!(
                "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let ada = "p-01M3TC5H00MPJG000000000000";
        std::fs::create_dir_all(dir.path().join("people").join(ada).join("notes")).unwrap();
        std::fs::write(
            dir.path().join("people").join(ada).join("profile.md"),
            format!("---\nid: {ada}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(ada).join("notes/n-01M3TC5H00MPJG002NAM000005.md"),
            format!("---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: {ada}\ndate: 2026-10-02\n---\n\nKickofftoken.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(ada).join("notes/n-01M3TC5H00MPJG00600000000D.md"),
            format!("---\nid: n-01M3TC5H00MPJG00600000000D\ntype: note\nperson: {ada}\ndate: 2026-10-04\n---\n\nUnattributed note.\n"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("interactions/i-01M3TC5H00MPJG0048H0000008"))
            .unwrap();
        std::fs::write(
            dir.path().join("interactions/i-01M3TC5H00MPJG0048H0000008/interaction.md"),
            format!("---\nid: i-01M3TC5H00MPJG0048H0000008\ntype: interaction\nname: Intro call\ndate: 2026-10-01\nperson: {ada}\n---\n\nFake call.\n"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!("2026-10-01 grant {ada} package pkg-01M3TC5H00MPJG004SK4000009 4 sessions\n2026-10-02 use {ada} 60m full note:n-01M3TC5H00MPJG002NAM000005\n"),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        (dir, vault)
    }

    fn example_scope() -> PackScope {
        PackScope::Only(["example-pack@0.1".to_string()].into_iter().collect())
    }

    #[test]
    fn scoped_context_hides_unattributed_notes_and_interactions() {
        let (_dir, vault) = example_pack_vault();
        let ada = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        let unscoped = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert_eq!(unscoped.notes.len(), 2);
        assert_eq!(unscoped.interactions.len(), 1);
        assert!(unscoped.packs.contains_key("example-pack@0.1"));

        let scoped = build_context(&vault, &ada, true, &example_scope(), false).unwrap();
        // Only the pack-linked note survives; the unattributed note and the
        // interaction are hidden. Core identity stays visible.
        assert_eq!(scoped.notes.len(), 1);
        assert_eq!(scoped.notes[0].id, "n-01M3TC5H00MPJG002NAM000005");
        assert!(scoped.interactions.is_empty());
        assert!(scoped.packs.contains_key("example-pack@0.1"));
        assert_eq!(
            scoped.person.as_ref().unwrap().name.as_deref(),
            Some("Ada Example")
        );
        assert_eq!(scoped.scope, vec!["example-pack@0.1"]);
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
        let (_dir, vault) = example_pack_vault();
        let ada = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        let scoped = build_context(&vault, &ada, true, &example_scope(), false).unwrap();
        assert!(scoped.packs.contains_key("example-pack@0.1"));
        let empty = PackScope::Only(std::collections::BTreeSet::new());
        let none = build_context(&vault, &ada, true, &empty, false).unwrap();
        assert!(none.packs.is_empty());
        // Core identity is still there even with an empty scope.
        assert_eq!(
            none.person.as_ref().unwrap().name.as_deref(),
            Some("Ada Example")
        );
    }

    /// #572: the operator bundle includes a `no-ai: true` person, carries
    /// the tri-state `no_ai`, and includes the note that inherits hidden.
    /// The agent bundle is unchanged: name withheld, note absent, boolean.
    #[test]
    fn operator_context_shows_no_ai_person_and_badges_inherited_note() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let cam = "p-01M3TC5H00MPJG001248000002";
        std::fs::create_dir_all(dir.path().join("people").join(cam).join("notes")).unwrap();
        std::fs::write(
            dir.path().join("people").join(cam).join("profile.md"),
            format!("---\nid: {cam}\ntype: person\nname: Cam Sample\nno-ai: true\n---\n\nFake profile.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(cam).join("notes/n-01M3TC5H00MPJG0060000000CC.md"),
            format!("---\nid: n-01M3TC5H00MPJG0060000000CC\ntype: note\nperson: {cam}\ndate: 2026-10-07\n---\n\nHidden note.\n"),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let cam = RecordId::parse(cam).unwrap();

        let agent = build_context(&vault, &cam, true, &PackScope::All, false).unwrap();
        let agent_person = agent.person.as_ref().unwrap();
        assert!(agent_person.name.is_none());
        assert!(agent_person.no_ai);
        assert!(agent_person.no_ai_mode.is_none());
        assert!(!agent.for_operator);
        assert!(agent.notes.is_empty());

        let op = build_context(&vault, &cam, true, &PackScope::All, true).unwrap();
        let op_person = op.person.as_ref().unwrap();
        assert_eq!(op_person.name.as_deref(), Some("Cam Sample"));
        assert_eq!(op_person.no_ai_mode, Some("true"));
        assert!(op_person.profile.is_some());
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
        let agent_person = agent.person.as_ref().unwrap();
        assert_eq!(agent_person.name.as_deref(), Some("Notes Mode"));
        assert_eq!(agent_person.no_ai_mode, None);
        let agent_notes: Vec<&str> = agent.notes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(agent_notes, vec!["n-01M3TC5H00MPJG000000000002"]);

        // Operator path: every child, each badged by its effective mode.
        let op = build_context(&vault, &id, true, &PackScope::All, true).unwrap();
        assert_eq!(op.person.as_ref().unwrap().no_ai_mode, Some("notes"));
        assert!(op.for_operator);
        let badge = |id: &str| op.notes.iter().find(|n| n.id == id).unwrap().no_ai;
        assert_eq!(badge("n-01M3TC5H00MPJG000000000001"), Some("true"));
        assert_eq!(badge("n-01M3TC5H00MPJG000000000002"), Some("false"));
        assert_eq!(badge("n-01M3TC5H00MPJG000000000003"), Some("true"));
    }

    // -----------------------------------------------------------------------
    // #813: entity context bundles, edges, org-linked records, privacy
    // -----------------------------------------------------------------------

    use std::path::Path;

    const CTX_ADA: &str = "p-01M3TC5H00MPJG000000000000";
    const CTX_BEA: &str = "p-01M3TC5H00MPJG000H24000001";
    const CTX_CAM: &str = "p-01M3TC5H00MPJG001248000002";
    const CTX_ORG: &str = "o-01M3TC5H00MPJG000000000901";
    const CTX_EDGE1: &str = "e-01M3TC5H00MPJG00E100000000";
    const CTX_EDGE2: &str = "e-01M3TC5H00MPJG00E200000000";

    fn write_file(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn entity_vault(spec: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "confidant.toml",
            &format!("spec = \"{spec}\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n"),
        );
        dir
    }

    fn write_person(root: &Path, id: &str, name: &str, no_ai: Option<&str>) {
        let flag = no_ai
            .map(|mode| format!("no-ai: {mode}\n"))
            .unwrap_or_default();
        write_file(
            root,
            &format!("people/{id}/profile.md"),
            &format!("---\nid: {id}\ntype: person\nname: {name}\n{flag}---\n\nFake person.\n"),
        );
    }

    fn write_org(root: &Path, id: &str, name: &str) {
        write_file(
            root,
            &format!("orgs/{id}/org.md"),
            &format!("---\nid: {id}\ntype: org\nname: {name}\n---\n\nFake org.\n"),
        );
    }

    fn write_edge(root: &Path, id: &str, a: &str, b: &str, kind: &str, since: Option<&str>) {
        let since = since
            .map(|date| format!("since: {date}\n"))
            .unwrap_or_default();
        write_file(
            root,
            &format!("edges/{id}/edge.md"),
            &format!("---\nid: {id}\ntype: edge\na: {a}\nb: {b}\nkind: {kind}\n{since}---\n"),
        );
    }

    fn write_note(root: &Path, id: &str, fields: &str, body: &str) {
        write_file(
            root,
            &format!("notes/{id}/note.md"),
            &format!("---\nid: {id}\ntype: note\n{fields}---\n\n{body}\n"),
        );
    }

    fn write_interaction(root: &Path, id: &str, fields: &str, body: &str) {
        write_file(
            root,
            &format!("interactions/{id}/interaction.md"),
            &format!("---\nid: {id}\ntype: interaction\n{fields}---\n\n{body}\n"),
        );
    }

    fn write_ledger(root: &Path, text: &str) {
        write_file(root, "ledger/2026/10.cfd", text);
    }

    fn load(root: &Path) -> Vault {
        crate::vault::load_vault(root).unwrap()
    }

    #[test]
    fn org_bundle_has_entity_and_edges() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(
            dir.path(),
            CTX_EDGE1,
            CTX_ADA,
            CTX_ORG,
            "works_at",
            Some("2024-01-01"),
        );
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();

        assert!(bundle.person.is_none(), "an org has no person alias");
        assert_eq!(bundle.entity.id, CTX_ORG);
        assert_eq!(bundle.entity.kind, "org");
        assert_eq!(bundle.entity.name.as_deref(), Some("Example Studio"));
        assert!(bundle.entity.profile.is_some());
        assert_eq!(bundle.edges.len(), 1);
        let edge = &bundle.edges[0];
        assert_eq!(edge.id, CTX_EDGE1);
        assert_eq!(edge.kind, "works_at");
        assert_eq!(edge.direction, "in");
        assert_eq!(edge.other.id, CTX_ADA);
        assert_eq!(edge.other.kind, "person");
        assert_eq!(edge.other.name.as_deref(), Some("Dana Example"));
        assert_eq!(edge.since.as_deref(), Some("2024-01-01"));
        assert!(edge.until.is_none());
        assert!(bundle.packs.is_empty(), "pack views are person-keyed");
        assert!(bundle.touchpoints.is_empty());
        assert!(bundle.aliases.is_empty());
    }

    #[test]
    fn person_bundle_keeps_the_person_alias_and_both_edge_directions() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_BEA, "Bea Demo", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(
            dir.path(),
            CTX_EDGE1,
            CTX_ADA,
            CTX_ORG,
            "works_at",
            Some("2024-01-01"),
        );
        // Directed person→person: ADA is the `b` end here.
        write_edge(dir.path(), CTX_EDGE2, CTX_BEA, CTX_ADA, "introduced", None);
        let vault = load(dir.path());
        let ada = RecordId::parse(CTX_ADA).unwrap();
        let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();

        assert_eq!(bundle.entity.kind, "person");
        let person = bundle.person.as_ref().expect("person alias");
        assert_eq!(person.id, CTX_ADA);
        assert_eq!(person.name.as_deref(), Some("Dana Example"));
        assert_eq!(bundle.edges.len(), 2);
        let out = bundle
            .edges
            .iter()
            .find(|edge| edge.kind == "works_at")
            .unwrap();
        assert_eq!(out.direction, "out");
        assert_eq!(out.other.id, CTX_ORG);
        assert_eq!(out.other.kind, "org");
        assert_eq!(out.other.name.as_deref(), Some("Example Studio"));
        let incoming = bundle
            .edges
            .iter()
            .find(|edge| edge.kind == "introduced")
            .unwrap();
        assert_eq!(incoming.direction, "in");
        assert_eq!(incoming.other.id, CTX_BEA);
    }

    #[test]
    fn symmetric_edge_direction_is_none() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_BEA, "Bea Demo", None);
        // `friend` is a personal-pack kind (enabled implicitly); it resolves
        // through the pack, not the core list.
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_BEA, "friend", None);
        let vault = load(dir.path());
        let ada = RecordId::parse(CTX_ADA).unwrap();
        let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert_eq!(bundle.edges.len(), 1);
        assert_eq!(bundle.edges[0].direction, "none");
        assert_eq!(bundle.edges[0].other.id, CTX_BEA);
    }

    #[test]
    fn org_bundle_includes_org_linked_notes_and_interactions() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_note(
            dir.path(),
            "n-01M3TC5H00MPJG00600000000D",
            &format!("org: {CTX_ORG}\ndate: 2026-10-02\n"),
            "Org-only note body.",
        );
        write_interaction(
            dir.path(),
            "i-01M3TC5H00MPJG0048H0000008",
            &format!("org: {CTX_ORG}\nperson: {CTX_ADA}\nname: Studio visit\ndate: 2026-10-03\n"),
            "Visit body.",
        );
        // A person-only note must not appear in the org bundle.
        write_note(
            dir.path(),
            "n-01M3TC5H00MPJG00600000000E",
            &format!("person: {CTX_ADA}\ndate: 2026-10-04\n"),
            "Person-only note body.",
        );
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();

        assert_eq!(bundle.notes.len(), 1);
        assert_eq!(bundle.notes[0].id, "n-01M3TC5H00MPJG00600000000D");
        assert_eq!(
            bundle.notes[0].body.as_deref(),
            Some("Org-only note body.\n")
        );
        assert_eq!(bundle.interactions.len(), 1);
        assert_eq!(bundle.interactions[0].id, "i-01M3TC5H00MPJG0048H0000008");
        assert_eq!(
            bundle.interactions[0].title.as_deref(),
            Some("Studio visit")
        );
        assert_eq!(bundle.edges.len(), 0);
    }

    #[test]
    fn org_bundle_omits_edge_to_a_no_ai_person() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", Some("true"));
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_ORG, "works_at", None);
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();

        assert!(bundle.edges.is_empty(), "no count, no anonymized hint");
        let dumped = serde_json::to_string(&bundle).unwrap();
        assert!(!dumped.contains(CTX_ADA), "{dumped}");
        assert!(!dumped.contains("Dana Example"), "{dumped}");
    }

    #[test]
    fn person_bundle_omits_edge_to_a_no_ai_person() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_CAM, "Cam Sample", Some("true"));
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_CAM, "married", None);
        let vault = load(dir.path());
        let ada = RecordId::parse(CTX_ADA).unwrap();
        let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert!(bundle.edges.is_empty(), "{:?}", bundle.edges);
        let dumped = serde_json::to_string(&bundle).unwrap();
        assert!(!dumped.contains(CTX_CAM), "{dumped}");
        assert!(!dumped.contains("Cam Sample"), "{dumped}");
    }

    #[test]
    fn no_ai_notes_person_edge_is_visible() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_CAM, "Cam Sample", Some("notes"));
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_CAM, "married", None);
        let vault = load(dir.path());
        let ada = RecordId::parse(CTX_ADA).unwrap();
        let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert_eq!(bundle.edges.len(), 1);
        assert_eq!(bundle.edges[0].other.name.as_deref(), Some("Cam Sample"));
    }

    #[test]
    fn exclude_private_strips_entity_and_endpoint_names() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(
            dir.path(),
            CTX_EDGE1,
            CTX_ADA,
            CTX_ORG,
            "works_at",
            Some("2024-01-01"),
        );
        write_note(
            dir.path(),
            "n-01M3TC5H00MPJG00600000000D",
            &format!("org: {CTX_ORG}\ndate: 2026-10-02\n"),
            "Org-only note body.",
        );
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, false, &PackScope::All, false).unwrap();

        assert!(bundle.entity.name.is_none());
        assert!(bundle.entity.profile.is_none());
        assert_eq!(bundle.notes.len(), 1);
        assert!(bundle.notes[0].body.is_none());
        assert_eq!(bundle.edges.len(), 1);
        let edge = &bundle.edges[0];
        assert_eq!(edge.id, CTX_EDGE1);
        assert_eq!(edge.kind, "works_at");
        assert_eq!(edge.since.as_deref(), Some("2024-01-01"));
        assert!(edge.other.name.is_none(), "endpoint name must be stripped");
        assert_eq!(edge.other.id, CTX_ADA);
    }

    #[test]
    fn operator_bundle_includes_hidden_edge_with_badge() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", Some("true"));
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_ORG, "works_at", None);
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, true).unwrap();

        assert!(bundle.for_operator);
        assert_eq!(bundle.edges.len(), 1);
        assert_eq!(bundle.edges[0].other.id, CTX_ADA);
        assert_eq!(bundle.edges[0].other.name.as_deref(), Some("Dana Example"));
        assert_eq!(bundle.edges[0].other.no_ai, Some("true"));
        assert_eq!(bundle.entity.no_ai_mode, Some("false"));
    }

    #[test]
    fn merged_edge_endpoint_is_canonical() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_BEA, "Bea Demo", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_ledger(
            dir.path(),
            &format!("2026-10-01 merge {CTX_BEA} into {CTX_ADA}\n"),
        );
        write_edge(dir.path(), CTX_EDGE1, CTX_BEA, CTX_ORG, "works_at", None);
        let vault = load(dir.path());

        let org = RecordId::parse(CTX_ORG).unwrap();
        let org_bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();
        assert_eq!(org_bundle.edges.len(), 1);
        assert_eq!(org_bundle.edges[0].other.id, CTX_ADA);

        let ada = RecordId::parse(CTX_ADA).unwrap();
        let ada_bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert_eq!(ada_bundle.edges.len(), 1);
        assert_eq!(ada_bundle.edges[0].direction, "out");
        assert_eq!(ada_bundle.edges[0].other.id, CTX_ORG);

        // The merged-away target still serves the redirected relation.
        let bea = RecordId::parse(CTX_BEA).unwrap();
        let bea_bundle = build_context(&vault, &bea, true, &PackScope::All, false).unwrap();
        assert_eq!(bea_bundle.entity.id, CTX_BEA);
        assert_eq!(bea_bundle.edges.len(), 1);
        assert_eq!(bea_bundle.edges[0].direction, "out");
        assert_eq!(bea_bundle.edges[0].other.id, CTX_ORG);
    }

    #[test]
    fn canonical_self_edge_is_omitted() {
        for spec in ["0.1", "0.2"] {
            let dir = entity_vault(spec);
            write_person(dir.path(), CTX_ADA, "Dana Example", None);
            write_person(dir.path(), CTX_BEA, "Bea Demo", None);
            write_ledger(
                dir.path(),
                &format!("2026-10-01 merge {CTX_ADA} into {CTX_BEA}\n"),
            );
            write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_BEA, "married", None);
            let vault = load(dir.path());
            let bea = RecordId::parse(CTX_BEA).unwrap();
            let bundle = build_context(&vault, &bea, true, &PackScope::All, false).unwrap();
            assert!(bundle.edges.is_empty(), "{spec}: {:?}", bundle.edges);
        }
    }

    #[test]
    fn duplicate_canonical_edges_are_deduped() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_BEA, "Bea Demo", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_ledger(
            dir.path(),
            &format!("2026-10-01 merge {CTX_BEA} into {CTX_ADA}\n"),
        );
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_ORG, "works_at", None);
        write_edge(dir.path(), CTX_EDGE2, CTX_BEA, CTX_ORG, "works_at", None);
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();
        assert_eq!(bundle.edges.len(), 1);
        assert_eq!(bundle.edges[0].id, CTX_EDGE1, "lowest edge id wins");
    }

    #[test]
    fn org_edge_pack_scope_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/packs/example-pack");
        let dst = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&dst).unwrap();
        for entry in std::fs::read_dir(&src).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
        let hash = crate::packs::dir::read_pack_dir(&dst).unwrap().hash;
        write_file(
            dir.path(),
            "confidant.lock",
            &format!(
                "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
            ),
        );
        write_file(
            dir.path(),
            "confidant.toml",
            "spec = \"0.2\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        );
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        // `backs` is the example pack's org→person kind; `works_at` is core.
        write_edge(dir.path(), CTX_EDGE1, CTX_ORG, CTX_ADA, "backs", None);
        write_edge(dir.path(), CTX_EDGE2, CTX_ADA, CTX_ORG, "works_at", None);
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();

        let pack_scope = PackScope::Only(["example-pack@0.1".to_string()].into_iter().collect());
        let scoped = build_context(&vault, &org, true, &pack_scope, false).unwrap();
        assert_eq!(scoped.edges.len(), 2, "{:?}", scoped.edges);

        let empty = PackScope::Only(std::collections::BTreeSet::new());
        let core_only = build_context(&vault, &org, true, &empty, false).unwrap();
        assert_eq!(core_only.edges.len(), 1, "{:?}", core_only.edges);
        assert_eq!(core_only.edges[0].kind, "works_at");
    }

    #[test]
    fn unknown_or_dangling_edges_are_omitted() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_ORG, "nemesis", None);
        write_edge(
            dir.path(),
            CTX_EDGE2,
            CTX_ADA,
            "o-01M3TC5H00MPJG000000000999",
            "works_at",
            None,
        );
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();
        assert!(bundle.edges.is_empty(), "{:?}", bundle.edges);
    }

    #[test]
    fn deal_context_is_none() {
        let dir = entity_vault("0.2");
        write_file(
            dir.path(),
            "deals/d-01M3TC5H00MPJG00248G000004/deal.md",
            "---\nid: d-01M3TC5H00MPJG00248G000004\ntype: deal\nname: Fake Deal\n---\n",
        );
        let vault = load(dir.path());
        let deal = RecordId::parse("d-01M3TC5H00MPJG00248G000004").unwrap();
        assert!(build_context(&vault, &deal, true, &PackScope::All, false).is_none());
    }

    #[test]
    fn zero_one_org_bundle_has_no_org_edges() {
        // 0.1 is frozen: a core kind with an org endpoint is invalid, so the
        // org bundle has no edges.
        let dir = entity_vault("0.1");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_ORG, "married", None);
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();
        assert_eq!(bundle.entity.kind, "org");
        assert!(bundle.edges.is_empty(), "{:?}", bundle.edges);
    }

    #[test]
    fn zero_one_person_to_person_edge_is_visible() {
        let dir = entity_vault("0.1");
        write_person(dir.path(), CTX_ADA, "Dana Example", None);
        write_person(dir.path(), CTX_BEA, "Bea Demo", None);
        write_edge(dir.path(), CTX_EDGE1, CTX_ADA, CTX_BEA, "married", None);
        let vault = load(dir.path());
        let ada = RecordId::parse(CTX_ADA).unwrap();
        let bundle = build_context(&vault, &ada, true, &PackScope::All, false).unwrap();
        assert_eq!(bundle.edges.len(), 1);
        assert_eq!(bundle.edges[0].direction, "none");
    }

    #[test]
    fn org_bundle_omits_note_that_names_a_hidden_person() {
        let dir = entity_vault("0.2");
        write_person(dir.path(), CTX_CAM, "Cam Sample", Some("true"));
        write_org(dir.path(), CTX_ORG, "Example Studio");
        write_note(
            dir.path(),
            "n-01M3TC5H00MPJG00600000000D",
            &format!("org: {CTX_ORG}\nperson: {CTX_CAM}\ndate: 2026-10-02\n"),
            "Hidden-person note body.",
        );
        let vault = load(dir.path());
        let org = RecordId::parse(CTX_ORG).unwrap();
        let bundle = build_context(&vault, &org, true, &PackScope::All, false).unwrap();
        assert!(bundle.notes.is_empty(), "{:?}", bundle.notes);
        let dumped = serde_json::to_string(&bundle).unwrap();
        assert!(!dumped.contains(CTX_CAM), "{dumped}");
        assert!(!dumped.contains("Cam Sample"), "{dumped}");
    }
}
