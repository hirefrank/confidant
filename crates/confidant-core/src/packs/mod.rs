//! Schema packs compiled into the binary (ADR-8).
//!
//! A pack owns ledger verbs, record types, front-matter fields, balance
//! metrics, and edge kinds. `check` resolves the vault's `packs = [...]`
//! list against the static registry, refuses conflicting claims
//! (`E_PACK_CONFLICT`), folds each enabled pack independently, and warns
//! — never errors — on data owned by a pack that is not enabled
//! (`W_PACK_ORPHAN`, #177 Q2).
//!
//! Calculations stay compiled in Rust (the #173 decision). There is no
//! plugin ABI in this slice; external pack discovery (#193) is a later cut
//! and must not change this interface.

use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{Finding, MergeMap};
use crate::id::{Prefix, RecordId};
use crate::vault::{SourcedEntry, Vault};

pub mod coaching;
pub mod groups;
pub mod personal;

/// One edge kind a pack owns (#179). `name` is the `kind` front-matter
/// value on an edge record; `symmetric` declares whether the relation
/// reads the same in both directions (`married` is symmetric, `introduced`
/// is directed). The kind list is closed: an edge whose kind no core or
/// enabled pack claims is a `check` error, not free text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeKind {
    pub name: &'static str,
    pub symmetric: bool,
}

/// Edge kinds core ships (#179). Packs add their own via
/// [`Pack::edge_kinds`].
pub const CORE_EDGE_KINDS: &[EdgeKind] = &[
    EdgeKind {
        name: "married",
        symmetric: true,
    },
    EdgeKind {
        name: "introduced",
        symmetric: false,
    },
    EdgeKind {
        name: "colleague",
        symmetric: true,
    },
];

/// Pack-owned state produced by [`Pack::fold`].
///
/// The trait methods that need pack state take `&dyn PackState` and downcast
/// to the concrete state their own `fold` produced; `check` always passes
/// a pack the state that pack's fold returned, so a downcast failure is an
/// internal invariant violation, never vault data.
pub trait PackState {
    fn as_any(&self) -> &dyn Any;
}

/// One compiled schema pack.
///
/// Claims are `&'static` slices so conflict detection and orphan warnings
/// are pure functions over the registry (see [`find_conflict`] and
/// [`orphan_owners`]). The `fold` / `findings` / `check_balance` /
/// `context_view` methods receive the state this pack's `fold` produced.
pub trait Pack: Send + Sync {
    /// The `name@version` string as listed in `confidant.toml`, e.g.
    /// `"coaching@0.1"`.
    fn name(&self) -> &'static str;
    /// Ledger verbs this pack defines (e.g. `open`, `session`).
    fn verbs(&self) -> &'static [&'static str];
    /// Record types this pack owns (kind strings, e.g. `"package"`).
    /// Core kinds (`person`, `org`, `deal`, `interaction`, `note`, `edge`)
    /// are never claimed; a pack that introduces a new kind claims it here.
    fn record_types(&self) -> &'static [&'static str];
    /// Front-matter fields this pack owns on shared records (flat names,
    /// e.g. `birthday`). Namespace only on conflict (#177 Q1).
    fn fields(&self) -> &'static [&'static str];
    /// Balance metrics this pack verifies on `balance` lines.
    fn balance_metrics(&self) -> &'static [&'static str];
    /// Edge kinds this pack owns (#179). Core ships
    /// [`CORE_EDGE_KINDS`]; a pack that introduces a kind claims it here.
    /// Defaults to none.
    fn edge_kinds(&self) -> &'static [EdgeKind] {
        &[]
    }
    /// Finding codes this pack's rules can emit (its `fold`, `findings`,
    /// and `check_balance` implementations). Every code listed here must
    /// be documented in the pack's `SKILL.md` ("what it means, what to do")
    /// — a drift test enforces it. Codes outside this list that fire on
    /// the pack's verbs or metrics are core codes, documented in
    /// `spec/findings.md`.
    fn finding_codes(&self) -> &'static [&'static str];
    /// The record type a verb's ledger ID must have, if the verb constrains
    /// it (e.g. `open` / `session` require a person ID). `None` means the
    /// verb constrains nothing. Defaults to `None`.
    fn verb_id_type(&self, _verb: &str) -> Option<Prefix> {
        None
    }
    /// Fold the vault's ledger entries into pack state. Appends fold-time
    /// findings (e.g. malformed pack verbs, negative balances).
    fn fold(
        &self,
        vault: &Vault,
        merges: &MergeMap,
        as_of: NaiveDate,
        findings: &mut Vec<Finding>,
    ) -> Box<dyn PackState>;
    /// Post-fold rules (gap rules, note integrity). Appends findings.
    fn findings(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        as_of: NaiveDate,
        findings: &mut Vec<Finding>,
    );
    /// Verify one `balance` ledger line whose metric this pack claims.
    /// The caller guarantees the metric is in [`Pack::balance_metrics`].
    fn check_balance(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        sourced: &SourcedEntry,
        findings: &mut Vec<Finding>,
    );
    /// Per-person state for `context`, if this pack has any. Defaults to
    /// `None`. `canonical` is the merge-canonical person ID.
    fn context_view(
        &self,
        _vault: &Vault,
        _state: &dyn PackState,
        _person: &RecordId,
        _canonical: &RecordId,
        _as_of: NaiveDate,
    ) -> Option<serde_json::Value> {
        None
    }
    /// Top-level field names in [`Pack::context_view`]'s returned object that
    /// carry PII (e.g. a birthday, a relationship label). `context` strips
    /// these when private data is excluded, so core stays pack-agnostic —
    /// a pack declares its own sensitive fields instead of `context`
    /// hardcoding pack names (#185/#302). Defaults to none.
    fn private_context_fields(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Every pack compiled into this binary, in registry order.
pub static ALL_PACKS: &[&'static dyn Pack] = &[&coaching::CoachingPack, &personal::PersonalPack];

/// The enabled packs for a vault's `packs = [...]` list, each at most once
/// (a duplicated listing folds once), plus the listed names no compiled pack
/// implements. Order follows the config list.
pub fn resolve_enabled<'a>(
    names: &[String],
    registry: &[&'a dyn Pack],
) -> (Vec<&'a dyn Pack>, Vec<String>) {
    let mut found = Vec::new();
    let mut seen: HashSet<&'static str> = HashSet::new();
    let mut unknown = Vec::new();
    for name in names {
        match registry.iter().find(|p| p.name() == name.as_str()) {
            Some(pack) => {
                if seen.insert(pack.name()) {
                    found.push(*pack);
                }
            }
            None => unknown.push(name.clone()),
        }
    }
    (found, unknown)
}

/// A claim two packs make on the same verb, record type, field, balance
/// metric, or edge kind. `kind` is one of `"verb"`, `"record type"`,
/// `"field"`, `"balance metric"`, `"edge kind"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackConflict {
    pub kind: &'static str,
    pub name: &'static str,
    pub first: &'static str,
    pub second: &'static str,
}

/// The first conflicting claim among `packs`, if any. Packs are compared in
/// the order given; claims within a pack in declaration order. Deterministic
/// for a given pack order.
pub fn find_conflict(packs: &[&dyn Pack]) -> Option<PackConflict> {
    let mut seen_verbs: HashMap<&'static str, &'static str> = HashMap::new();
    let mut seen_types: HashMap<&'static str, &'static str> = HashMap::new();
    let mut seen_fields: HashMap<&'static str, &'static str> = HashMap::new();
    let mut seen_metrics: HashMap<&'static str, &'static str> = HashMap::new();
    let mut seen_edge_kinds: HashMap<&'static str, &'static str> = HashMap::new();
    for pack in packs {
        for (kind, claims, seen) in [
            ("verb", pack.verbs(), &mut seen_verbs),
            ("record type", pack.record_types(), &mut seen_types),
            ("field", pack.fields(), &mut seen_fields),
            ("balance metric", pack.balance_metrics(), &mut seen_metrics),
        ] {
            for claim in claims {
                if let Some(first) = seen.get(claim) {
                    return Some(PackConflict {
                        kind,
                        name: claim,
                        first,
                        second: pack.name(),
                    });
                }
                seen.insert(claim, pack.name());
            }
        }
        // #179: edge kinds are claimed the same way, checked in the same
        // per-pack pass so ordering matches the other claim kinds.
        for edge_kind in pack.edge_kinds() {
            if let Some(first) = seen_edge_kinds.get(edge_kind.name) {
                return Some(PackConflict {
                    kind: "edge kind",
                    name: edge_kind.name,
                    first,
                    second: pack.name(),
                });
            }
            seen_edge_kinds.insert(edge_kind.name, pack.name());
        }
    }
    None
}

/// Claims owned by packs in `registry` that are *not* in `enabled`, keyed by
/// claim name to the owning pack's name. `check` turns these into
/// `W_PACK_ORPHAN` warnings instead of unknown-verb / unknown-metric errors.
#[derive(Clone, Debug, Default)]
pub struct OrphanOwners {
    pub verbs: BTreeMap<&'static str, &'static str>,
    pub record_types: BTreeMap<&'static str, &'static str>,
    pub fields: BTreeMap<&'static str, &'static str>,
    pub balance_metrics: BTreeMap<&'static str, &'static str>,
    pub edge_kinds: BTreeMap<&'static str, &'static str>,
}

pub fn orphan_owners(registry: &[&dyn Pack], enabled: &[&dyn Pack]) -> OrphanOwners {
    let enabled_names: HashSet<&'static str> = enabled.iter().map(|p| p.name()).collect();
    let mut out = OrphanOwners::default();
    for pack in registry {
        if enabled_names.contains(pack.name()) {
            continue;
        }
        for claim in pack.verbs() {
            out.verbs.entry(claim).or_insert(pack.name());
        }
        for claim in pack.record_types() {
            out.record_types.entry(claim).or_insert(pack.name());
        }
        for claim in pack.fields() {
            out.fields.entry(claim).or_insert(pack.name());
        }
        for claim in pack.balance_metrics() {
            out.balance_metrics.entry(claim).or_insert(pack.name());
        }
        for claim in pack.edge_kinds() {
            out.edge_kinds.entry(claim.name).or_insert(pack.name());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Prefix;

    /// A minimal second pack for registry-mechanics tests. Claims one verb,
    /// one field, one record type, one metric, and one edge kind; folds to
    /// empty state.
    struct TestPack;

    struct TestState;

    impl PackState for TestState {
        fn as_any(&self) -> &dyn Any {
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
        fn finding_codes(&self) -> &'static [&'static str] {
            &[]
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
    static COACHING: coaching::CoachingPack = coaching::CoachingPack;

    fn registry() -> Vec<&'static dyn Pack> {
        vec![&COACHING, &TEST_PACK]
    }

    #[test]
    fn resolve_dedupes_and_reports_unknown() {
        let names = vec![
            "coaching@0.1".to_string(),
            "coaching@0.1".to_string(),
            "nope@1".to_string(),
        ];
        let (found, unknown) = resolve_enabled(&names, &registry());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name(), "coaching@0.1");
        assert_eq!(unknown, vec!["nope@1".to_string()]);
    }

    #[test]
    fn conflict_detects_shared_verb() {
        struct Clashing;
        impl Pack for Clashing {
            fn name(&self) -> &'static str {
                "clash@0.1"
            }
            fn verbs(&self) -> &'static [&'static str] {
                &["session"]
            }
            fn record_types(&self) -> &'static [&'static str] {
                &[]
            }
            fn fields(&self) -> &'static [&'static str] {
                &[]
            }
            fn balance_metrics(&self) -> &'static [&'static str] {
                &[]
            }
            fn finding_codes(&self) -> &'static [&'static str] {
                &[]
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
        static CLASH: Clashing = Clashing;
        let packs: Vec<&dyn Pack> = vec![&COACHING, &CLASH];
        let conflict = find_conflict(&packs).unwrap();
        assert_eq!(conflict.kind, "verb");
        assert_eq!(conflict.name, "session");
        assert_eq!(conflict.first, "coaching@0.1");
        assert_eq!(conflict.second, "clash@0.1");
        assert!(find_conflict(&[&COACHING, &TEST_PACK]).is_none());
    }

    #[test]
    fn conflict_detects_shared_edge_kind() {
        struct Clashing;
        impl Pack for Clashing {
            fn name(&self) -> &'static str {
                "clash@0.1"
            }
            fn verbs(&self) -> &'static [&'static str] {
                &[]
            }
            fn record_types(&self) -> &'static [&'static str] {
                &[]
            }
            fn fields(&self) -> &'static [&'static str] {
                &[]
            }
            fn balance_metrics(&self) -> &'static [&'static str] {
                &[]
            }
            fn edge_kinds(&self) -> &'static [EdgeKind] {
                &[EdgeKind {
                    name: "mentor",
                    symmetric: false,
                }]
            }
            fn finding_codes(&self) -> &'static [&'static str] {
                &[]
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
        static CLASH: Clashing = Clashing;
        let packs: Vec<&dyn Pack> = vec![&TEST_PACK, &CLASH];
        let conflict = find_conflict(&packs).unwrap();
        assert_eq!(conflict.kind, "edge kind");
        assert_eq!(conflict.name, "mentor");
        assert_eq!(conflict.first, "testpack@0.1");
        assert_eq!(conflict.second, "clash@0.1");
    }

    #[test]
    fn orphan_owners_cover_disabled_packs_only() {
        let owners = orphan_owners(&registry(), &[&COACHING]);
        assert_eq!(owners.verbs.get("touch"), Some(&"testpack@0.1"));
        assert_eq!(owners.fields.get("birthday"), Some(&"testpack@0.1"));
        assert_eq!(owners.record_types.get("testtype"), Some(&"testpack@0.1"));
        assert_eq!(
            owners.balance_metrics.get("test_metric"),
            Some(&"testpack@0.1")
        );
        assert_eq!(owners.edge_kinds.get("mentor"), Some(&"testpack@0.1"));
        assert!(!owners.verbs.contains_key("session"));
        let none = orphan_owners(&registry(), &[&COACHING, &TEST_PACK]);
        assert!(none.verbs.is_empty());
        assert!(none.fields.is_empty());
        assert!(none.edge_kinds.is_empty());
    }
}
