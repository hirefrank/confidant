//! Per-pack access scoping for agent-facing reads (#178, #232).
//!
//! A [`PackScope`] is the set of packs a read may return. Unscoped reads
//! ([`PackScope::All`]) see everything the §12 allowlist clears. Scoped
//! reads see core-owned items plus items owned by packs in scope;
//! unattributed items are hidden (fail closed). Attribution derives from
//! the #226 pack registry — no format change, no stamped `pack:` field.
//!
//! Ownership rules (Silas, #232):
//! - A front-matter field is owned by the enabled pack claiming it, else
//!   core if it is a spec key (`id`, `type`, `name`, `date`, `person`,
//!   `org`, `deal`, `session`, `no-ai`, `a`, `b`, `kind`, `since`, `until`,
//!   `with`, plus case-variant ref keys), else unattributed.
//! - A ledger line is owned by its verb's pack; a `balance` line by its
//!   metric's pack; `alias` / `merge` / `stage` / `touch` are core.
//!   Anything else (unknown verb, unknown metric, unparseable) is
//!   unattributed.
//! - A note is owned by the packs claiming its fields plus the packs
//!   owning a ledger line that references it (e.g. a coaching `session`
//!   line's `note:` pair). An interaction is owned by the packs claiming
//!   its fields. A person / org / deal record is core-owned (the identity
//!   anchor); pack-claimed fields on it filter per-field in `find`.
//! - An edge is owned by its kind's pack (#179); a core kind is
//!   core-owned; an edge with an unknown or missing kind is unattributed.
//!   The edge's own front matter has no pack-owned fields to filter —
//!   edges are visible as whole records only, like notes/interactions.

use std::collections::{BTreeSet, HashMap};

use crate::error::DomainError;
use crate::id::RecordId;
use crate::ledger::{parse_line, LedgerEntry};
use crate::packs::{EdgeKind, Pack, CORE_EDGE_KINDS};
use crate::record::{canonical_ref_key, is_spec_key, Record, RecordKind};
use crate::vault::Vault;

/// Who owns an item for scoping purposes. An item with no owner
/// (unattributed) is visible only to unscoped reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnerKey {
    /// Core-owned: visible to every scope (name, aliases, core verbs…).
    Core,
    /// Owned by this pack (its `name@version` string).
    Pack(&'static str),
}

impl OwnerKey {
    /// JSON label for allowlist ownership annotations: `"core"`, a pack
    /// name, or (for the empty set) nothing.
    pub fn label(self) -> &'static str {
        match self {
            OwnerKey::Core => "core",
            OwnerKey::Pack(name) => name,
        }
    }
}

/// The set of packs a read may return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackScope {
    /// Unscoped: all enabled packs, plus core and unattributed items.
    All,
    /// Scoped: only these enabled packs, plus core-owned items.
    Only(BTreeSet<String>),
}

impl PackScope {
    /// True when an item with these owners is visible under this scope.
    /// Core-owned items are visible to every scope; unattributed items
    /// (empty owner set) are visible only unscoped.
    pub fn allows(&self, owners: &BTreeSet<OwnerKey>) -> bool {
        match self {
            PackScope::All => true,
            PackScope::Only(packs) => owners.iter().any(|o| match o {
                OwnerKey::Core => true,
                OwnerKey::Pack(name) => packs.contains(*name),
            }),
        }
    }

    /// Pack names in scope, sorted. For [`PackScope::All`], every enabled
    /// pack — the scope that actually applied, for JSON output.
    pub fn names(&self, enabled: &[&dyn Pack]) -> Vec<String> {
        match self {
            PackScope::All => enabled.iter().map(|p| p.name().to_string()).collect(),
            PackScope::Only(packs) => packs.iter().cloned().collect(),
        }
    }
}

/// Split a `--packs` / `packs` value (`"a@0.1, b@0.1"`) into names.
/// Empty entries are dropped; duplicates are kept here and deduped by
/// [`resolve_scope`].
pub fn parse_pack_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Resolve a requested pack list against the vault's enabled packs.
/// `None` means unscoped ([`PackScope::All`]). Naming a pack that is
/// unknown or not enabled in this vault is a hard error (fail closed),
/// never a silent empty scope (#232 Q1).
pub fn resolve_scope(
    requested: Option<&[String]>,
    enabled: &[&dyn Pack],
) -> Result<PackScope, DomainError> {
    let Some(names) = requested else {
        return Ok(PackScope::All);
    };
    let mut set = BTreeSet::new();
    for name in names {
        if !enabled.iter().any(|p| p.name() == name.as_str()) {
            return Err(DomainError::usage(format!(
                "unknown or disabled pack in --packs: {name}"
            )));
        }
        set.insert(name.clone());
    }
    Ok(PackScope::Only(set))
}

/// Intersect a per-call scope with a connection ceiling (MCP, #232 Q1).
/// `None` per-call means the ceiling. A per-call scope can only narrow
/// the ceiling, never widen it: naming a pack outside the ceiling is an
/// error. The result is validated against the enabled packs.
pub fn intersect_scope(
    ceiling: &PackScope,
    requested: Option<&[String]>,
    enabled: &[&dyn Pack],
) -> Result<PackScope, DomainError> {
    let Some(names) = requested else {
        return Ok(ceiling.clone());
    };
    if let PackScope::Only(allowed) = ceiling {
        for name in names {
            if !allowed.contains(name) {
                return Err(DomainError::usage(format!(
                    "per-call scope {name} is outside the connection's pack scope"
                )));
            }
        }
    }
    resolve_scope(requested, enabled)
}

/// Owner of one front-matter field: the enabled pack claiming it, core
/// for spec keys (including case-variant ref keys), else unattributed.
pub fn owner_of_field(field: &str, enabled: &[&dyn Pack]) -> Option<OwnerKey> {
    for pack in enabled {
        if pack.fields().contains(&field) {
            return Some(OwnerKey::Pack(pack.name()));
        }
    }
    if is_spec_key(field) || canonical_ref_key(field).is_some() {
        Some(OwnerKey::Core)
    } else {
        None
    }
}

/// Core ledger verbs: owned by core, visible to every scope. `touch` is
/// core because a mirrored touchpoint (#179) carries only a date and the
/// participant's own id — no pack data. A pack that claims `touch`
/// (#184) owns touch lines when enabled: [`owner_of_verb`] checks pack
/// claims first.
pub const CORE_VERBS: &[&str] = &["alias", "merge", "stage", "touch"];

/// Owner of a ledger verb: the enabled pack claiming it, core for
/// [`CORE_VERBS`], else unattributed.
pub fn owner_of_verb(verb: &str, enabled: &[&dyn Pack]) -> Option<OwnerKey> {
    for pack in enabled {
        if pack.verbs().contains(&verb) {
            return Some(OwnerKey::Pack(pack.name()));
        }
    }
    if CORE_VERBS.contains(&verb) {
        Some(OwnerKey::Core)
    } else {
        None
    }
}

/// Owner of a `balance` metric: the enabled pack claiming it, else
/// unattributed (unknown metric — `check` flags it anyway).
pub fn owner_of_metric(metric: &str, enabled: &[&dyn Pack]) -> Option<OwnerKey> {
    for pack in enabled {
        if pack.balance_metrics().contains(&metric) {
            return Some(OwnerKey::Pack(pack.name()));
        }
    }
    None
}

/// Owner of an edge kind (#179): the enabled pack claiming the kind,
/// core for [`CORE_EDGE_KINDS`], else unattributed (unknown kind —
/// `check` flags it anyway, and the edge is hidden when scoped).
pub fn owner_of_edge_kind(kind: &str, enabled: &[&dyn Pack]) -> Option<OwnerKey> {
    for pack in enabled {
        if pack.edge_kinds().iter().any(|k: &EdgeKind| k.name == kind) {
            return Some(OwnerKey::Pack(pack.name()));
        }
    }
    if CORE_EDGE_KINDS.iter().any(|k| k.name == kind) {
        Some(OwnerKey::Core)
    } else {
        None
    }
}

/// Owners of one parsed ledger entry. A `balance` line is owned by its
/// metric's pack; any other line by its verb's pack (or core). Unknown
/// verbs / metrics are unattributed.
pub fn owners_of_ledger_entry(entry: &LedgerEntry, enabled: &[&dyn Pack]) -> BTreeSet<OwnerKey> {
    if entry.verb == "balance" {
        let metric = entry.args.first().and_then(|a| a.as_token()).unwrap_or("");
        return owner_of_metric(metric, enabled).into_iter().collect();
    }
    owner_of_verb(&entry.verb, enabled).into_iter().collect()
}

/// Owners of one raw ledger line. Unparseable lines (comments, blanks,
/// malformed) are unattributed — hidden when scoped.
pub fn owners_of_ledger_text(text: &str, enabled: &[&dyn Pack]) -> BTreeSet<OwnerKey> {
    match parse_line(text) {
        Ok(Some(entry)) => owners_of_ledger_entry(&entry, enabled),
        _ => BTreeSet::new(),
    }
}

/// Note id → packs owning a ledger line that references it (the `note:`
/// pair of a pack-owned line, e.g. a coaching `session` line). Core
/// lines never attribute notes. The note inherits those packs.
pub fn note_linkage_owners(
    vault: &Vault,
    enabled: &[&dyn Pack],
) -> HashMap<RecordId, BTreeSet<OwnerKey>> {
    let mut out: HashMap<RecordId, BTreeSet<OwnerKey>> = HashMap::new();
    for sourced in &vault.entries {
        let owners = owners_of_ledger_entry(&sourced.entry, enabled);
        let pack_owners: BTreeSet<OwnerKey> = owners
            .into_iter()
            .filter(|o| *o != OwnerKey::Core)
            .collect();
        if pack_owners.is_empty() {
            continue;
        }
        for arg in &sourced.entry.args {
            let Some((key, value)) = arg.pair() else {
                continue;
            };
            if key != "note" {
                continue;
            }
            if let Ok(id) = RecordId::parse(value) {
                if id.prefix() == crate::id::Prefix::Note {
                    out.entry(id)
                        .or_default()
                        .extend(pack_owners.iter().copied());
                }
            }
        }
    }
    out
}

/// Owners of a record for scoping. Person / org / deal records are the
/// core identity anchor (`Core` — always visible; pack-claimed fields on
/// them filter per-field in `find`). Notes add field claims + ledger
/// linkage; interactions add field claims; edges are owned by their
/// kind's pack. An empty set means unattributed: hidden when scoped.
pub fn record_owners(
    record: &Record,
    linkage: &HashMap<RecordId, BTreeSet<OwnerKey>>,
    enabled: &[&dyn Pack],
) -> BTreeSet<OwnerKey> {
    match record.kind {
        RecordKind::Person | RecordKind::Org | RecordKind::Deal => {
            [OwnerKey::Core].into_iter().collect()
        }
        RecordKind::Note => {
            let mut owners = BTreeSet::new();
            for field in record.fields.keys() {
                if let Some(OwnerKey::Pack(name)) = owner_of_field(field, enabled) {
                    owners.insert(OwnerKey::Pack(name));
                }
            }
            if let Some(linked) = linkage.get(&record.id) {
                owners.extend(linked.iter().copied());
            }
            owners
        }
        RecordKind::Interaction => {
            let mut owners = BTreeSet::new();
            for field in record.fields.keys() {
                if let Some(OwnerKey::Pack(name)) = owner_of_field(field, enabled) {
                    owners.insert(OwnerKey::Pack(name));
                }
            }
            owners
        }
        // #179: an edge is visible exactly when its kind's pack is in
        // scope. The edge's front matter has no pack-owned fields to
        // filter, so kind ownership is the whole story; a missing or
        // unknown kind is unattributed (fail closed).
        RecordKind::Edge => match record.field("kind") {
            Some(kind) => owner_of_edge_kind(kind, enabled).into_iter().collect(),
            None => BTreeSet::new(),
        },
    }
}

/// Owner labels for an owner set, sorted: pack names and/or `"core"`.
/// Empty for unattributed items.
pub fn owner_labels(owners: &BTreeSet<OwnerKey>) -> Vec<&'static str> {
    owners.iter().map(|o| o.label()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Finding, MergeMap};
    use crate::id::Prefix;
    use crate::ledger::parse_line;
    use crate::packs::{EdgeKind, Pack, PackState};
    use crate::vault::SourcedEntry;
    use chrono::NaiveDate;

    /// A minimal second pack for scope tests. Claims one verb, one field,
    /// and one metric; folds to empty state. Mirrors the TestPack in
    /// `crate::packs::tests` (which this module cannot reach).
    struct TestPack;

    struct TestState;

    impl PackState for TestState {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl Pack for TestPack {
        fn name(&self) -> &'static str {
            "testpack@0.1"
        }
        fn verbs(&self) -> &'static [&'static str] {
            &["touch"]
        }
        fn record_types(&self) -> &'static [&'static str] {
            // "edge" is a core record type (#179) and is never claimed.
            &["testtype"]
        }
        fn fields(&self) -> &'static [&'static str] {
            &["birthday"]
        }
        fn balance_metrics(&self) -> &'static [&'static str] {
            &["test_metric"]
        }
        fn edge_kinds(&self) -> &'static [EdgeKind] {
            &[EdgeKind {
                name: "mentor",
                symmetric: false,
            }]
        }
        fn verb_id_type(&self, verb: &str) -> Option<Prefix> {
            if verb == "touch" {
                Some(Prefix::Person)
            } else {
                None
            }
        }
        fn fold(
            &self,
            _vault: &Vault,
            _merges: &MergeMap,
            _as_of: NaiveDate,
            _findings: &mut Vec<Finding>,
        ) -> Box<dyn PackState> {
            Box::new(TestState)
        }
        fn findings(
            &self,
            _vault: &Vault,
            _state: &dyn PackState,
            _as_of: NaiveDate,
            _findings: &mut Vec<Finding>,
        ) {
        }
        fn check_balance(
            &self,
            _vault: &Vault,
            _state: &dyn PackState,
            _sourced: &SourcedEntry,
            _findings: &mut Vec<Finding>,
        ) {
        }
    }

    static TEST_PACK: TestPack = TestPack;
    static COACHING: crate::packs::coaching::CoachingPack = crate::packs::coaching::CoachingPack;

    fn registry() -> Vec<&'static dyn Pack> {
        vec![&COACHING, &TEST_PACK]
    }

    #[test]
    fn parse_pack_list_trims_and_drops_empties() {
        assert_eq!(
            parse_pack_list("coaching@0.1, testpack@0.1"),
            vec!["coaching@0.1", "testpack@0.1"]
        );
        assert_eq!(parse_pack_list(""), Vec::<String>::new());
        assert_eq!(parse_pack_list("a,,b"), vec!["a", "b"]);
    }

    #[test]
    fn resolve_none_is_all_and_unknown_is_error() {
        assert_eq!(resolve_scope(None, &registry()).unwrap(), PackScope::All);
        let err = resolve_scope(Some(&["nope@1".to_string()]), &registry()).unwrap_err();
        assert!(err.message().contains("nope@1"));
    }

    #[test]
    fn resolve_disabled_pack_is_error() {
        // testpack is in the registry but not in this enabled set.
        let enabled: Vec<&dyn Pack> = vec![&COACHING];
        let err = resolve_scope(Some(&["testpack@0.1".to_string()]), &enabled).unwrap_err();
        assert!(err.message().contains("testpack@0.1"));
    }

    #[test]
    fn intersect_narrows_but_never_widens() {
        let ceiling = PackScope::Only(["coaching@0.1".to_string()].into_iter().collect());
        // Narrowing to the ceiling itself is fine.
        assert_eq!(
            intersect_scope(&ceiling, Some(&["coaching@0.1".to_string()]), &registry()).unwrap(),
            ceiling
        );
        // A pack outside the ceiling is an error, even though it exists.
        let err = intersect_scope(&ceiling, Some(&["testpack@0.1".to_string()]), &registry())
            .unwrap_err();
        assert!(err.message().contains("outside"));
        // No per-call scope means the ceiling.
        assert_eq!(
            intersect_scope(&ceiling, None, &registry()).unwrap(),
            ceiling
        );
        // With an All ceiling, per-call resolves normally.
        assert_eq!(
            intersect_scope(
                &PackScope::All,
                Some(&["testpack@0.1".to_string()]),
                &registry()
            )
            .unwrap(),
            PackScope::Only(["testpack@0.1".to_string()].into_iter().collect())
        );
    }

    #[test]
    fn field_owners_cover_pack_core_and_unattributed() {
        let enabled = registry();
        assert_eq!(
            owner_of_field("birthday", &enabled),
            Some(OwnerKey::Pack("testpack@0.1"))
        );
        assert_eq!(owner_of_field("name", &enabled), Some(OwnerKey::Core));
        assert_eq!(owner_of_field("Person", &enabled), Some(OwnerKey::Core));
        assert_eq!(owner_of_field("mystery", &enabled), None);
    }

    #[test]
    fn ledger_owners_cover_verb_balance_core_and_unknown() {
        let enabled = registry();
        let session = parse_line("2026-10-01 session p-01M3TC5H00MPJG000000000000 60m paid")
            .unwrap()
            .unwrap();
        assert_eq!(
            owners_of_ledger_entry(&session, &enabled),
            [OwnerKey::Pack("coaching@0.1")].into_iter().collect()
        );
        let balance = parse_line("2026-10-08 balance p-01M3TC5H00MPJG000000000000 test_metric 3")
            .unwrap()
            .unwrap();
        assert_eq!(
            owners_of_ledger_entry(&balance, &enabled),
            [OwnerKey::Pack("testpack@0.1")].into_iter().collect()
        );
        let alias = parse_line("2026-10-03 alias p-01M3TC5H00MPJG000000000000 email hmac:00")
            .unwrap()
            .unwrap();
        assert_eq!(
            owners_of_ledger_entry(&alias, &enabled),
            [OwnerKey::Core].into_iter().collect()
        );
        let unknown = parse_line("2026-10-03 frobnicate p-01M3TC5H00MPJG000000000000 x")
            .unwrap()
            .unwrap();
        assert!(owners_of_ledger_entry(&unknown, &enabled).is_empty());
        // Comments / blanks / malformed lines are unattributed.
        assert!(owners_of_ledger_text("; a comment", &enabled).is_empty());
        assert!(owners_of_ledger_text("", &enabled).is_empty());
    }

    #[test]
    fn allows_is_core_visible_unattributed_hidden() {
        let coaching = PackScope::Only(["coaching@0.1".to_string()].into_iter().collect());
        let core: BTreeSet<OwnerKey> = [OwnerKey::Core].into_iter().collect();
        let pack: BTreeSet<OwnerKey> = [OwnerKey::Pack("testpack@0.1")].into_iter().collect();
        assert!(coaching.allows(&core));
        assert!(!coaching.allows(&pack));
        assert!(!coaching.allows(&BTreeSet::new()));
        assert!(PackScope::All.allows(&BTreeSet::new()));
    }

    #[test]
    fn record_owners_cover_field_claims_and_core_anchor() {
        use crate::record::parse_record;
        let enabled = registry();
        // A note carrying a testpack-claimed field is owned by testpack:
        // visible to a testpack scope, hidden from a coaching scope.
        let note = parse_record(
            "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: p-01M3TC5H00MPJG000000000000\nbirthday: 1990-01-01\n---\n\nPersonal note.\n",
            "people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md",
        )
        .unwrap();
        let owners = record_owners(&note, &HashMap::new(), &enabled);
        assert_eq!(
            owners,
            [OwnerKey::Pack("testpack@0.1")].into_iter().collect()
        );
        let coaching = PackScope::Only(["coaching@0.1".to_string()].into_iter().collect());
        assert!(!coaching.allows(&owners));
        let testpack = PackScope::Only(["testpack@0.1".to_string()].into_iter().collect());
        assert!(testpack.allows(&owners));
        // A person record is the core anchor: always visible.
        let person = parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: Ada Example\n---\n\nProfile.\n",
            "people/p-01M3TC5H00MPJG000000000000/profile.md",
        )
        .unwrap();
        let person_owners = record_owners(&person, &HashMap::new(), &enabled);
        assert_eq!(person_owners, [OwnerKey::Core].into_iter().collect());
        assert!(coaching.allows(&person_owners));
    }

    #[test]
    fn edge_owners_follow_kind_pack() {
        use crate::record::parse_record;
        let enabled = registry();
        // A core-kind edge (married) is core-owned: visible to every scope.
        let married = parse_record(
            "---\nid: e-01M3TC5H00MPJG00000000000A\ntype: edge\na: p-01M3TC5H00MPJG000000000000\nb: p-01M3TC5H00MPJG000H24000001\nkind: married\n---\n",
            "edges/e-01M3TC5H00MPJG00000000000A/edge.md",
        )
        .unwrap();
        let owners = record_owners(&married, &HashMap::new(), &enabled);
        assert_eq!(owners, [OwnerKey::Core].into_iter().collect());
        // A pack-kind edge (mentor, claimed by testpack) is owned by that
        // pack: visible to a testpack scope, hidden from a coaching scope.
        let mentor = parse_record(
            "---\nid: e-01M3TC5H00MPJG00000000000B\ntype: edge\na: p-01M3TC5H00MPJG000000000000\nb: p-01M3TC5H00MPJG000H24000001\nkind: mentor\n---\n",
            "edges/e-01M3TC5H00MPJG00000000000B/edge.md",
        )
        .unwrap();
        let mentor_owners = record_owners(&mentor, &HashMap::new(), &enabled);
        assert_eq!(
            mentor_owners,
            [OwnerKey::Pack("testpack@0.1")].into_iter().collect()
        );
        let coaching = PackScope::Only(["coaching@0.1".to_string()].into_iter().collect());
        assert!(!coaching.allows(&mentor_owners));
        let testpack = PackScope::Only(["testpack@0.1".to_string()].into_iter().collect());
        assert!(testpack.allows(&mentor_owners));
        // An unknown kind is unattributed: visible only unscoped.
        let mystery = parse_record(
            "---\nid: e-01M3TC5H00MPJG00000000000C\ntype: edge\na: p-01M3TC5H00MPJG000000000000\nb: p-01M3TC5H00MPJG000H24000001\nkind: nemesis\n---\n",
            "edges/e-01M3TC5H00MPJG00000000000C/edge.md",
        )
        .unwrap();
        let mystery_owners = record_owners(&mystery, &HashMap::new(), &enabled);
        assert!(mystery_owners.is_empty());
        assert!(!coaching.allows(&mystery_owners));
        assert!(PackScope::All.allows(&mystery_owners));
        // `owner_of_edge_kind` directly: core kind, pack kind, unknown.
        assert_eq!(
            owner_of_edge_kind("married", &enabled),
            Some(OwnerKey::Core)
        );
        assert_eq!(
            owner_of_edge_kind("mentor", &enabled),
            Some(OwnerKey::Pack("testpack@0.1"))
        );
        assert_eq!(owner_of_edge_kind("nemesis", &enabled), None);
    }

    #[test]
    fn note_linkage_attributes_session_notes() {
        // A vault whose only entry is a coaching session referencing a note.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\npacks = [\"coaching@0.1\"]\n",
        )
        .unwrap();
        let note_id = "n-01M3TC5H00MPJG002NAM000005";
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!("2026-10-01 session p-01M3TC5H00MPJG000000000000 60m paid note:{note_id}\n"),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let linkage = note_linkage_owners(&vault, &registry());
        let id = RecordId::parse(note_id).unwrap();
        assert_eq!(
            linkage.get(&id),
            Some(&[OwnerKey::Pack("coaching@0.1")].into_iter().collect())
        );
    }
}
