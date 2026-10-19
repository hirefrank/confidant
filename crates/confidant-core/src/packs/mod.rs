//! Schema packs: the compiled packs and the implicit embedded built-ins
//! (ADR-8).
//!
//! A pack owns ledger verbs, record types, front-matter fields, balance
//! metrics, and edge kinds. `check` resolves the vault's `packs = [...]`
//! list against the static registry plus the implicit built-ins, refuses
//! conflicting claims (`E_PACK_CONFLICT`), folds each enabled pack
//! independently, and warns — never errors — on data owned by a pack that
//! is not enabled (`W_PACK_ORPHAN`, #177 Q2).
//!
//! Calculations stay compiled in Rust (the #173 decision). There is no
//! plugin ABI in this slice; external pack discovery (#193) is a later cut
//! and must not change this interface.

use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{Finding, MergeMap};
use crate::id::{Prefix, RecordId};
use crate::ledger::LedgerEntry;
use crate::vault::{SourcedEntry, Vault};

pub mod coaching;
pub mod declarative;
pub mod dir;
pub mod embedded;
pub mod external;
pub mod grammars;
pub mod groups;
pub mod lock;
pub mod manifest;
pub mod manifest_pack;
pub mod registry;
mod rules;
pub mod untrusted;

pub use registry::PackRegistry;

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
    /// Validate the argument grammar of a ledger entry for a verb this pack
    /// owns. Returns `None` when the pack does not own `verb` or does not
    /// constrain its args; `Some(valid)` otherwise. Core routes verb-arg
    /// validation through this instead of reaching into pack internals
    /// (#185/#296). Defaults to no opinion.
    ///
    /// When the owning pack is disabled, core applies its own shape rule
    /// first (e.g. the #179 mirrored touchpoint); only lines that fail it
    /// reach the pack, so this doubles as the pack-shape check behind
    /// `W_PACK_ORPHAN` vs malformed-verb findings.
    fn validate_verb_args(&self, _verb: &str, _entry: &LedgerEntry) -> Option<bool> {
        None
    }
    /// Extract the pack's display kind for a ledger entry of a verb it owns
    /// (e.g. the touchpoint kind of a `touch` line), used by `context`.
    /// Returns `None` when the pack does not own `verb` or the entry
    /// carries no kind (#185/#296). Defaults to none.
    fn verb_kind(&self, _verb: &str, _entry: &LedgerEntry) -> Option<String> {
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
    /// Agent-facing skill text this pack carries, if any (#445). Compiled
    /// packs return `None`: their text ships embedded in the CLI
    /// (`crates/confidant-cli/pack-skills/`). An external pack returns its
    /// vendored `[pack].skill` file (PD7: text and data only). Defaults to
    /// none.
    fn skill_text(&self) -> Option<&'static str> {
        None
    }
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

/// Every pack compiled into this binary, in registry order. The built-in
/// declarative packs are not here: they are implicit and live in
/// [`embedded`] (#551), enabled in every vault.
pub static ALL_PACKS: &[&'static dyn Pack] = &[&coaching::CoachingPack];

/// The parsed manifests of every compiled pack, in registry order.
/// `config` reads the `[checks]` key declarations from these so the
/// allowlists and defaults live in the manifests, not in hardcoded
/// slices (#345).
pub(crate) fn pack_manifests() -> Vec<&'static manifest::PackManifest> {
    vec![&coaching::manifest_claims().manifest]
}

/// The pack manifests consulted for `[checks]` key handling (#433).
/// The compiled packs plus the implicit embedded built-ins (#551): the
/// built-in personal pack's `[checks]` keys must be accepted without the
/// vault listing it.
pub(crate) fn pack_manifests_for_config() -> Vec<&'static manifest::PackManifest> {
    let mut manifests = pack_manifests();
    manifests.extend(embedded::embedded_packs().iter().map(|p| p.manifest()));
    manifests
}

/// The parsed manifest for a compiled or built-in pack, by `name@version`
/// (e.g. `"coaching@0.1"`). Used by the CLI's drift tests to check
/// manifest text against the embedded SKILL.md (#345).
pub fn pack_manifest(name: &str) -> Option<&'static manifest::PackManifest> {
    pack_manifests_for_config()
        .into_iter()
        .find(|m| format!("{}@{}", m.pack.name, m.pack.version) == name)
}

/// Whether `listed` names a pack this binary implements: a compiled pack or
/// an implicit built-in (at any version). `init --packs` validates against
/// this so a no-op `personal@…` listing is accepted (#551).
pub fn is_known_pack_id(listed: &str) -> bool {
    pack_manifest(listed).is_some() || embedded::is_builtin_listing(listed)
}

/// The enabled packs for a vault's `packs = [...]` list, plus the implicit
/// built-ins (`implicit`), each at most once (a duplicated listing folds
/// once), and the listed names no registry pack implements. Order follows
/// the config list; implicit packs the list did not name are appended.
///
/// A `name@version` in `names` that matches a pack exactly enables it. A
/// built-in listing at another version (`personal@0.1`) is a no-op: the
/// built-in is already enabled under its own `name@version`.
pub fn resolve_enabled<'a>(
    names: &[String],
    registry: &[&'a dyn Pack],
    implicit: &[&'a dyn Pack],
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
            None if embedded::is_builtin_listing(name) => {}
            None => unknown.push(name.clone()),
        }
    }
    for pack in implicit {
        if seen.insert(pack.name()) {
            found.push(*pack);
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
    let mut seen_codes: HashMap<&'static str, &'static str> = HashMap::new();
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
        // #434: finding codes claimed by two enabled *external* packs
        // conflict. Codes that are already builtin enum codes are skipped:
        // compiled packs legitimately share them (coaching@0.1 and
        // the built-in personal pack both list E_INVALID_ID, E_WRONG_ID_TYPE,
        // E_UNKNOWN_RECORD).
        for code in pack.finding_codes() {
            if crate::check::FindingCode::is_builtin_code(code) {
                continue;
            }
            if let Some(first) = seen_codes.get(code) {
                return Some(PackConflict {
                    kind: "finding code",
                    name: code,
                    first,
                    second: pack.name(),
                });
            }
            seen_codes.insert(code, pack.name());
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
    fn registry_compiled_holds_compiled_and_builtin_packs() {
        let names: Vec<&str> = PackRegistry::compiled()
            .all()
            .iter()
            .map(|p| p.name())
            .collect();
        assert_eq!(names, vec!["coaching@0.1", "personal@0.2"]);
        let all_names: Vec<&str> = ALL_PACKS.iter().map(|p| p.name()).collect();
        assert_eq!(all_names, vec!["coaching@0.1"]);
    }

    #[test]
    fn registry_resolve_enabled_dedups_and_reports_unknown() {
        let registry = PackRegistry::compiled();
        let names = vec![
            "coaching@0.1".to_string(),
            "coaching@0.1".to_string(),
            "nope@9.9".to_string(),
        ];
        let (found, unknown) = registry.resolve_enabled(&names);
        // The implicit built-in is appended after the listed packs.
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name(), "coaching@0.1");
        assert_eq!(found[1].name(), "personal@0.2");
        assert_eq!(unknown, vec!["nope@9.9".to_string()]);
    }

    #[test]
    fn implicit_personal_is_enabled_with_empty_packs() {
        let registry = PackRegistry::compiled();
        let (found, unknown) = registry.resolve_enabled(&[]);
        assert!(unknown.is_empty(), "{unknown:?}");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name(), "personal@0.2");
    }

    #[test]
    fn personal_listings_are_noops_at_any_version() {
        for listed in ["personal@0.1", "personal@0.2", "personal@9.9"] {
            let registry = PackRegistry::compiled();
            let names = vec![listed.to_string()];
            let (found, unknown) = registry.resolve_enabled(&names);
            assert!(unknown.is_empty(), "{listed}: {unknown:?}");
            assert_eq!(found.len(), 1, "{listed}");
            assert_eq!(found[0].name(), "personal@0.2", "{listed}");
        }
    }

    #[test]
    fn registry_orphan_owners_matches_free_function() {
        let registry = PackRegistry::compiled();
        let personal = registry
            .all()
            .iter()
            .find(|p| p.name() == "personal@0.2")
            .unwrap();
        let enabled: Vec<&dyn Pack> = vec![*personal];
        let via_method = registry.orphan_owners(&enabled);
        let via_free = orphan_owners(registry.all(), &enabled);
        // Coaching verbs are orphans when only personal is enabled.
        assert_eq!(via_method.verbs.get("open"), Some(&"coaching@0.1"));
        assert_eq!(via_method.verbs.get("session"), Some(&"coaching@0.1"));
        assert_eq!(via_method.verbs, via_free.verbs);
        assert_eq!(via_method.record_types, via_free.record_types);
        assert_eq!(via_method.fields, via_free.fields);
        assert_eq!(via_method.balance_metrics, via_free.balance_metrics);
        assert_eq!(via_method.edge_kinds, via_free.edge_kinds);
    }

    #[test]
    fn registry_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PackRegistry>();
    }

    #[test]
    fn resolve_dedupes_and_reports_unknown() {
        let names = vec![
            "coaching@0.1".to_string(),
            "coaching@0.1".to_string(),
            "nope@1".to_string(),
        ];
        let (found, unknown) = resolve_enabled(&names, &registry(), &[]);
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

    /// A pack that claims finding codes, for conflict tests (#434).
    macro_rules! code_pack {
        ($name:ident, $pack_name:expr, $codes:expr) => {
            struct $name;
            impl Pack for $name {
                fn name(&self) -> &'static str {
                    $pack_name
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
                fn finding_codes(&self) -> &'static [&'static str] {
                    $codes
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
        };
    }

    #[test]
    fn find_conflict_ignores_shared_core_codes() {
        // coaching@0.1 and the built-in personal pack both list E_INVALID_ID,
        // E_WRONG_ID_TYPE, E_UNKNOWN_RECORD — shared builtin codes must not
        // conflict (#434).
        let personal = crate::packs::embedded::find(crate::packs::embedded::PERSONAL_0_2)
            .expect("personal@0.2 is embedded")
            .pack();
        let packs: Vec<&dyn Pack> = vec![&COACHING, personal];
        assert!(find_conflict(&packs).is_none());
    }

    #[test]
    fn find_conflict_reports_duplicate_finding_code() {
        code_pack!(CodePackA, "codea@0.1", &["W_EXAMPLE_THING"]);
        code_pack!(CodePackB, "codeb@0.1", &["W_EXAMPLE_THING", "E_OTHER_CODE"]);
        static A: CodePackA = CodePackA;
        static B: CodePackB = CodePackB;
        let packs: Vec<&dyn Pack> = vec![&A, &B];
        let conflict = find_conflict(&packs).unwrap();
        assert_eq!(conflict.kind, "finding code");
        assert_eq!(conflict.name, "W_EXAMPLE_THING");
        assert_eq!(conflict.first, "codea@0.1");
        assert_eq!(conflict.second, "codeb@0.1");
        // No conflict when codes are distinct.
        code_pack!(CodePackC, "codec@0.1", &["W_DIFFERENT_CODE"]);
        static C: CodePackC = CodePackC;
        let packs: Vec<&dyn Pack> = vec![&A, &C];
        assert!(find_conflict(&packs).is_none());
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

    /// Every message template in every compiled pack's manifest must
    /// render (#345). Extracts the `{placeholder}` names from each
    /// template, supplies a dummy value per placeholder, and asserts the
    /// render succeeds with no placeholders left. This catches template
    /// syntax errors and placeholder typos; the integration tests prove
    /// the code supplies the right values at each call site.
    #[test]
    fn all_manifest_message_templates_render() {
        for m in super::pack_manifests_for_config() {
            for code in &m.finding_codes {
                let variants = &m.messages[code.as_str()];
                for (variant, template) in variants {
                    // Collect placeholder names.
                    let mut placeholders = Vec::new();
                    let mut chars = template.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '{' {
                            let mut name = String::new();
                            for c in chars.by_ref() {
                                if c == '}' {
                                    break;
                                }
                                name.push(c);
                            }
                            placeholders.push(name);
                        }
                    }
                    let args: Vec<(&str, &dyn std::fmt::Display)> = placeholders
                        .iter()
                        .map(|p| (p.as_str(), &"X" as &dyn std::fmt::Display))
                        .collect();
                    let rendered = m.render_message(code, variant, &args);
                    assert!(
                        !rendered.contains('{') && !rendered.contains('}'),
                        "unrendered placeholder in [{code}].{variant}"
                    );
                    assert!(!rendered.is_empty(), "empty render for [{code}].{variant}");
                }
            }
        }
    }
}
