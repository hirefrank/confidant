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
use crate::context::ledger_sessions::LedgerSessionsParams;
use crate::id::{Prefix, RecordId};
use crate::ledger::LedgerEntry;
use crate::packs::groups::MergeGroups;
use crate::packs::manifest::{PackManifest, PackOrigin};
use crate::packs::rules::ledger::{self, LedgerFacts};
use crate::packs::{EdgeKind, Pack, PackState};
use crate::vault::{SourcedEntry, Vault};
use chrono::NaiveDate;

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// A pack registered at runtime from a validated declarative manifest: its
/// claims are leaked once — the same pattern the embedded built-in uses —
/// plus the skill text and the manifest for the declarative
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
    balance_open_verbs: &'static [&'static str],
    edge_kinds: &'static [EdgeKind],
    finding_codes: &'static [&'static str],
    /// The resolved `[context]` view parameters, if this manifest opts in
    /// (#594). `None` means the pack serves no core view.
    context_params: Option<LedgerSessionsParams>,
}

impl ManifestPack {
    /// The pack's manifest (leaked once with the pack).
    pub fn pack_manifest(&self) -> &'static PackManifest {
        self.manifest
    }

    /// Whether this is the built-in personal pack (#551).
    ///
    /// The `context` view, its private-field list and the `touch` grammar
    /// cannot be expressed in a manifest (PD16 scopes external packs to
    /// `check`), so core owns them (#510). Only the compiled-in built-in
    /// named `personal` serves that core view; an external pack can never
    /// use the reserved name (`E_PACK_INVALID`), so the origin + name check
    /// is unambiguous.
    fn serves_core_personal_view(&self) -> bool {
        self.manifest.origin == PackOrigin::CompiledIn && self.manifest.pack.name == "personal"
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
    let balance_open_verbs: Vec<&'static str> = manifest
        .rules
        .iter()
        .filter(|r| r.kind == "ledger-balance")
        .filter_map(|r| r.params.get("open_verb").and_then(|v| v.as_str()))
        .map(|v| leak_str(v.to_owned()))
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
    // #594: the `[context]` view parameters. `validate_context` already
    // refused a bad table at parse time, so this non-panicking resolve always
    // matches `resolve_params` for a loaded manifest; a violation degrades to
    // "no view" (see `ledger_sessions::params`) rather than panicking here on
    // untrusted bytes.
    let context_params = crate::context::ledger_sessions::params(&manifest);
    Box::leak(Box::new(ManifestPack {
        manifest: Box::leak(Box::new(manifest)),
        skill_text: leak_str(skill_text),
        name,
        verbs: Box::leak(verbs.into_boxed_slice()),
        verb_id_types,
        record_types: Box::leak(record_types.into_boxed_slice()),
        fields: Box::leak(fields.into_boxed_slice()),
        balance_metrics: Box::leak(balance_metrics.into_boxed_slice()),
        balance_open_verbs: Box::leak(balance_open_verbs.into_boxed_slice()),
        edge_kinds: Box::leak(edge_kinds.into_boxed_slice()),
        finding_codes: Box::leak(finding_codes.into_boxed_slice()),
        context_params,
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

    fn balance_open_verbs(&self) -> &'static [&'static str] {
        self.balance_open_verbs
    }

    fn edge_kinds(&self) -> &'static [EdgeKind] {
        self.edge_kinds
    }

    fn finding_codes(&self) -> &'static [&'static str] {
        self.finding_codes
    }

    /// #747 round 3: the pack's `session-checks` billing tags for verb
    /// `session`, in rule order, deduplicated. Malformed entries
    /// (missing/non-array/non-string tags, a rule for another verb)
    /// contribute nothing here — manifest validation rejects them
    /// elsewhere, and log-time validation must not crash on them.
    fn session_billing_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = Vec::new();
        for rule in &self.manifest.rules {
            if rule.kind != "session-checks" {
                continue;
            }
            if rule.params.get("verb").and_then(|v| v.as_str()) != Some("session") {
                continue;
            }
            let Some(list) = rule.params.get("billing_tags").and_then(|v| v.as_array()) else {
                continue;
            };
            for tag in list {
                if let Some(tag) = tag.as_str() {
                    if !tag.trim().is_empty() && !tags.contains(&tag.to_string()) {
                        tags.push(tag.to_string());
                    }
                }
            }
        }
        tags
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

    /// The manifest's origin (#535): the built-ins are compiled in, a
    /// loaded external pack is not.
    fn origin(&self) -> PackOrigin {
        self.manifest.origin
    }

    /// The merge view only: the declarative rules (#441) read the same view
    /// a compiled pack's rules use.
    fn fold(
        &self,
        vault: &Vault,
        merges: &MergeMap,
        _as_of: NaiveDate,
        _findings: &mut Vec<Finding>,
    ) -> Box<dyn PackState> {
        let merge = MergeGroups::new(merges.clone());
        // Fold each `ledger-balance` rule once here, so `check_balance`
        // can verify every `balance` line against the same facts instead
        // of refolding the whole ledger per line (#449 performance).
        let mut ledger = std::collections::BTreeMap::new();
        for rule in &self.manifest.rules {
            if rule.kind != crate::packs::rules::balance::KIND {
                continue;
            }
            let Some(params) = crate::packs::rules::balance::BalanceParams::parse(rule) else {
                continue;
            };
            let folded = ledger::fold(vault, &merge, params.fold_params());
            ledger.insert(rule.id.clone(), folded.facts);
        }
        Box::new(ManifestState { merge, ledger })
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

    /// Verify a `balance` line whose metric one of the pack's
    /// `ledger-balance` rules owns (#446): the rule kind does the math.
    fn check_balance(
        &self,
        _vault: &Vault,
        state: &dyn PackState,
        sourced: &SourcedEntry,
        findings: &mut Vec<Finding>,
    ) {
        let Some(state) = state.as_any().downcast_ref::<ManifestState>() else {
            return; // never happens in-tree; fold always makes ManifestState
        };
        crate::packs::rules::balance::check_balance(
            self.manifest,
            &state.ledger,
            sourced,
            findings,
        );
    }

    /// The built-in personal pack serves core's merge-aware personal view
    /// (#510/#551), built from this manifest's declared fields so the view
    /// follows the pack data. A pack with a `[context]` table (#594) serves
    /// the core ledger-sessions view instead, folded from the same shared
    /// ledger arithmetic; a pack with neither returns `None`.
    fn context_view(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        person: &RecordId,
        canonical: &RecordId,
        as_of: NaiveDate,
    ) -> Option<serde_json::Value> {
        if self.serves_core_personal_view() {
            return crate::context::personal::build_personal_view(
                vault,
                person,
                canonical,
                as_of,
                &self.manifest.fields,
            );
        }
        let params = self.context_params.as_ref()?;
        let state = state.as_any().downcast_ref::<ManifestState>()?;
        // #594/#449: reuse the facts `fold` already cached for the single
        // `ledger-balance` rule the loader required, rather than refolding.
        // The fallback keeps the view correct if a future state lacks it.
        let cached = self
            .manifest
            .rules
            .iter()
            .find(|rule| rule.kind == crate::packs::rules::balance::KIND)
            .and_then(|rule| state.ledger.get(&rule.id));
        let folded;
        let facts = match cached {
            Some(facts) => facts,
            None => {
                folded = ledger::fold(vault, &state.merge, params.fold_params());
                &folded.facts
            }
        };
        crate::context::ledger_sessions::build_ledger_sessions_view(
            vault,
            canonical,
            as_of,
            facts,
            &params.consume_verb,
            params.recent_limit,
        )
    }

    /// #594: a declarative pack that declares `[context]` serves the core
    /// `ledger-sessions` view. The legacy `coaching` alias is tied to the
    /// base name `coaching` (`context` matches it), so this only makes the
    /// coaching pack the alias — a `[context]` pack under another name serves
    /// its own `packs` entry only. The built-in personal pack serves its own
    /// view, so it is never the alias.
    fn context_view_kind(&self) -> Option<&'static str> {
        if self.serves_core_personal_view() {
            return None;
        }
        self.context_params
            .as_ref()
            .map(|_| crate::context::ledger_sessions::LEDGER_SESSIONS_VIEW)
    }

    /// The `--exclude-private` list is core-owned (#510); only the built-in
    /// personal pack carries it.
    fn private_context_fields(&self) -> &'static [&'static str] {
        if self.serves_core_personal_view() {
            crate::context::personal::PRIVATE_CONTEXT_FIELDS
        } else {
            &[]
        }
    }
}

/// Runtime state for a manifest pack: the merge view only. The declarative
/// rules (#441) read it; a compiled pack folds much more.
pub struct ManifestState {
    merge: MergeGroups,
    /// Cached fold per `ledger-balance` rule id, so `check_balance` does
    /// not refold the ledger for every `balance` line (#449).
    ledger: std::collections::BTreeMap<String, LedgerFacts>,
}

impl PackState for ManifestState {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::manifest::parse_manifest_compiled_in;
    use crate::packs::Pack;

    /// A v2 manifest whose `session-checks` rule bills under different
    /// tags than the core default, plus a second `session-checks` rule
    /// for another verb that must not change `log session` validation.
    fn session_pack() -> &'static ManifestPack {
        let text = r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_SESS_DURATION", "E_SESS_TAGS", "W_SESS_UNTAGGED", "E_SESS_NOTES", "E_OTHER_DURATION", "E_OTHER_TAGS", "W_OTHER_UNTAGGED", "E_OTHER_NOTES"]

[pack]
name = "billing-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[verbs]]
name = "session"
id_type = "person"

[[verbs]]
name = "use"

[[checks.severity]]
key = "billing-pack.duration"
default = "error"

[[checks.severity]]
key = "billing-pack.notes"
default = "error"

[[rules]]
id = "sessions"
kind = "session-checks"
code = "E_SESS_DURATION"
severity_duration_key = "billing-pack.duration"
severity_notes_key = "billing-pack.notes"
verb = "session"
billing_tags = ["full", "barter"]
tags_code = "E_SESS_TAGS"
untagged_code = "W_SESS_UNTAGGED"
notes_code = "E_SESS_NOTES"

[[rules]]
id = "uses"
kind = "session-checks"
code = "E_OTHER_DURATION"
severity_duration_key = "billing-pack.duration"
severity_notes_key = "billing-pack.notes"
verb = "use"
billing_tags = ["other-tag"]
tags_code = "E_OTHER_TAGS"
untagged_code = "W_OTHER_UNTAGGED"
notes_code = "E_OTHER_NOTES"

[messages."E_SESS_DURATION"]
default = "session needs a duration"
default_fix = "Add a duration"

[messages."E_SESS_TAGS"]
default = "session has the wrong tags"
default_fix = "Fix the tags"

[messages."W_SESS_UNTAGGED"]
default = "session is untagged"
default_fix = "Tag it"

[messages."E_SESS_NOTES"]
default = "session has no notes"
default_fix = "Add a note"

[messages."E_OTHER_DURATION"]
default = "use needs a duration"
default_fix = "Add a duration"

[messages."E_OTHER_TAGS"]
default = "use has the wrong tags"
default_fix = "Fix the tags"

[messages."W_OTHER_UNTAGGED"]
default = "use is untagged"
default_fix = "Tag it"

[messages."E_OTHER_NOTES"]
default = "use has no notes"
default_fix = "Add a note"
"#;
        let manifest = parse_manifest_compiled_in(text).expect("fixture manifest parses");
        build_manifest_pack(manifest, "skill".to_string())
    }

    /// #747 round 3: a pack's `session-checks` tags for verb
    /// `session` are its log-time vocabulary; a rule for another verb
    /// contributes nothing.
    #[test]
    fn session_billing_tags_read_from_manifest() {
        let pack = session_pack();
        assert_eq!(
            pack.session_billing_tags(),
            vec!["full".to_string(), "barter".to_string()],
            "only the session-verb rule counts, in rule order"
        );
    }
}
