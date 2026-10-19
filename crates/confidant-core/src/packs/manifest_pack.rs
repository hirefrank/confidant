//! A [`Pack`] built from a validated declarative manifest (#441/#550).
//!
//! Both loaders share this type: `external.rs` builds one per verified
//! vendored external pack (#438), and `embedded.rs` builds the compiled-in
//! built-in packs (#550) from bytes inside the binary. The manifest supplies
//! the claims and message text; the rules and field-grammar validation run
//! through [`declarative::run`], so there is exactly one evaluator.
//!
//! The pack is always leaked once (the `Pack` trait returns `&'static` for
//! claims). External loads intern by verified content hash so a reload
//! reuses the instance (#497); a built-in is built once behind a
//! `OnceLock`.

use crate::check::Finding;
use crate::check::MergeMap;
use crate::id::Prefix;
use crate::ledger::LedgerEntry;
use crate::packs::groups::MergeGroups;
use crate::packs::manifest::PackManifest;
use crate::packs::{EdgeKind, Pack, PackState};
use crate::vault::{SourcedEntry, Vault};
use chrono::NaiveDate;

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// A pack registered at runtime from a validated declarative manifest: its
/// claims are leaked once — the same pattern the compiled packs use in
/// `coaching.rs` — plus the skill text and the manifest for the declarative
/// evaluator (#441). The claim slices are leaked too (the `Pack` trait
/// returns `&'static`), so all of them are `'static` field references copied
/// out per call.
pub struct ManifestPack {
    manifest: &'static PackManifest,
    /// The `[pack].skill` text — leaked once with the pack, so
    /// [`Pack::skill_text`] can hand out `&'static str`.
    skill_text: &'static str,
    name: &'static str,
    verbs: &'static [&'static str],
    verb_id_types: Vec<(&'static str, Prefix)>,
    record_types: &'static [&'static str],
    fields: &'static [&'static str],
    balance_metrics: &'static [&'static str],
    edge_kinds: &'static [EdgeKind],
    finding_codes: &'static [&'static str],
}

impl ManifestPack {
    /// The pack's manifest (leaked once with the pack).
    pub fn pack_manifest(&self) -> &'static PackManifest {
        self.manifest
    }
}

/// Leak a validated manifest into a static pack instance.
pub(crate) fn build_manifest_pack(
    manifest: PackManifest,
    skill_text: String,
) -> &'static ManifestPack {
    let name = leak_str(format!("{}@{}", manifest.pack.name, manifest.pack.version));
    let verbs: Vec<&'static str> = manifest
        .verbs
        .iter()
        .map(|v| leak_str(v.name.clone()))
        .collect();
    let verb_id_types: Vec<(&'static str, Prefix)> = manifest
        .verbs
        .iter()
        .filter_map(|v| v.id_type.map(|p| (leak_str(v.name.clone()), p)))
        .collect();
    let record_types: Vec<&'static str> = manifest
        .record_types
        .iter()
        .map(|r| leak_str(r.clone()))
        .collect();
    let fields: Vec<&'static str> = manifest
        .fields
        .iter()
        .map(|f| leak_str(f.name.clone()))
        .collect();
    let balance_metrics: Vec<&'static str> = manifest
        .balance_metrics
        .iter()
        .map(|b| leak_str(b.clone()))
        .collect();
    let edge_kinds: Vec<EdgeKind> = manifest
        .edge_kinds
        .iter()
        .map(|e| EdgeKind {
            name: leak_str(e.name.clone()),
            symmetric: e.symmetric,
        })
        .collect();
    let finding_codes: Vec<&'static str> = manifest
        .finding_codes
        .iter()
        .map(|c| leak_str(c.clone()))
        .collect();
    Box::leak(Box::new(ManifestPack {
        manifest: Box::leak(Box::new(manifest)),
        skill_text: leak_str(skill_text),
        name,
        verbs: Box::leak(verbs.into_boxed_slice()),
        verb_id_types,
        record_types: Box::leak(record_types.into_boxed_slice()),
        fields: Box::leak(fields.into_boxed_slice()),
        balance_metrics: Box::leak(balance_metrics.into_boxed_slice()),
        edge_kinds: Box::leak(edge_kinds.into_boxed_slice()),
        finding_codes: Box::leak(finding_codes.into_boxed_slice()),
    }))
}

impl Pack for ManifestPack {
    fn name(&self) -> &'static str {
        self.name
    }

    fn verbs(&self) -> &'static [&'static str] {
        self.verbs
    }

    fn record_types(&self) -> &'static [&'static str] {
        self.record_types
    }

    fn fields(&self) -> &'static [&'static str] {
        self.fields
    }

    fn balance_metrics(&self) -> &'static [&'static str] {
        self.balance_metrics
    }

    fn edge_kinds(&self) -> &'static [EdgeKind] {
        self.edge_kinds
    }

    fn finding_codes(&self) -> &'static [&'static str] {
        self.finding_codes
    }

    /// `verb → id-type` constraints from the manifest's `[[verbs]]`.
    fn verb_id_type(&self, verb: &str) -> Option<Prefix> {
        self.verb_id_types
            .iter()
            .find(|(v, _)| *v == verb)
            .map(|(_, prefix)| *prefix)
    }

    /// `touch` is a core verb (#179, #510): its grammar lives in core, so a
    /// manifest pack that claims it must serve the same parser the compiled
    /// pack does. No external pack may claim `touch` (PD8), so this only
    /// ever runs for a compiled-in built-in (#550).
    fn validate_verb_args(&self, verb: &str, entry: &LedgerEntry) -> Option<bool> {
        (verb == "touch").then(|| crate::touch::validate_touch_args(&entry.args))
    }

    /// The display kind of a `touch` line, from core's grammar (#510), for
    /// `context`. See [`ManifestPack::validate_verb_args`].
    fn verb_kind(&self, verb: &str, entry: &LedgerEntry) -> Option<String> {
        (verb == "touch")
            .then(|| crate::touch::extract_touch_kind(entry))
            .flatten()
    }

    /// The manifest's `[pack].skill` text: a built-in's text is compiled
    /// in, an external pack's is vendored (PD7: text and data only).
    fn skill_text(&self) -> Option<&'static str> {
        Some(self.skill_text)
    }

    /// The merge view only: the declarative rules (#441) read the same view
    /// a compiled pack's rules use.
    fn fold(
        &self,
        _vault: &Vault,
        merges: &MergeMap,
        _as_of: NaiveDate,
        _findings: &mut Vec<Finding>,
    ) -> Box<dyn PackState> {
        Box::new(ManifestState {
            merge: MergeGroups::new(merges.clone()),
        })
    }

    /// Declarative rules + field-grammar validation (#441). Runs the
    /// evaluator's two phases in manifest order; findings are appended
    /// deterministically.
    fn findings(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        as_of: NaiveDate,
        out: &mut Vec<Finding>,
    ) {
        let Some(state) = state.as_any().downcast_ref::<ManifestState>() else {
            return; // never happens in-tree; fold always makes ManifestState
        };
        crate::packs::declarative::run(vault, &state.merge, as_of, self.manifest, out);
    }

    /// A metric declared and owned, but no rule verifies values yet (the
    /// `ledger-balance` rule kind arrives in #446).
    fn check_balance(
        &self,
        _vault: &Vault,
        _state: &dyn PackState,
        _sourced: &SourcedEntry,
        _findings: &mut Vec<Finding>,
    ) {
    }
}

/// Runtime state for a manifest pack: the merge view only. The declarative
/// rules (#441) read it; a compiled pack folds much more.
pub struct ManifestState {
    merge: MergeGroups,
}

impl PackState for ManifestState {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
