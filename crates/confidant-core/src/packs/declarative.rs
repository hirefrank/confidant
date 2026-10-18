//! Declarative pack rules: the evaluator and rule dispatch (#441).
//!
//! PD1: a declarative check is a **named rule kind** implemented once in
//! Rust, with typed parameters in the pack's manifest TOML. There is no
//! expression language and no WASM: the logic lives here; the manifest
//! only names, parameterizes and turns rules on/off.
//!
//! [`ExternalPack::findings`] (in `external.rs`) walks the manifest's
//! `[[rules]]` in manifest order, resolves each rule's severity through
//! the operator's `[checks]` config (a rule set `off` is skipped), and
//! dispatches to the kind's `evaluate`. A rule that panics fails closed:
//! it becomes one `E_PACK_INVALID` finding naming the rule id — pack
//! author text, the same trust level as the pack's message templates;
//! never the pack name (operator free text never echoes into findings)
//! and never the panic payload. Note the default panic hook still
//! prints panics to stderr; the guarantee here is about findings only.
//! `check` carries on either way.
//!
//! Everything here is `pub(crate)`: the trait and registry only run
//! inside `ExternalPack`'s findings, and `MergeGroups` — the merge view
//! rules share — is a crate-internal type, so the trait cannot be
//! public without leaking it. The public surface stays `Pack`.
//!
//! No filesystem, no network, no process execution: rules read what
//! `check` already loaded — ledger metadata and the pack's declared
//! plaintext front-matter fields — and emit findings only (PD8).

use std::collections::{BTreeMap, HashMap};
use std::panic::catch_unwind;
use std::sync::Mutex;

use chrono::NaiveDate;

use crate::check::{Finding, FindingCode, Severity};

use crate::config::parse_severity_token;
use crate::error::DomainError;
use crate::id::{Prefix, RecordId};
use crate::packs::grammars::{
    parse_field_grammar, FieldValue, RecurringDate, GRAMMAR_DATES_LIST, GRAMMAR_RECURRING_DATE,
};
use crate::packs::groups::MergeGroups;
use crate::packs::manifest::{PackManifest, RuleDecl, MANIFEST_VERSION_V2};
use crate::record::Record;
use crate::vault::Vault;

/// What one rule evaluation sees. `merges` is the pack's merge view —
/// the same thing a compiled pack's rules use. Rules read plaintext
/// ledger metadata and the pack's own declared fields only (PD8/PD16).
/// `vault`/`merges`/`as_of`/`manifest` are read by the rule kinds as
/// they land (#442+); the skeleton's test kind only reads `severity`.
pub(crate) struct RuleCtx<'a> {
    #[allow(dead_code)]
    pub vault: &'a Vault,
    #[allow(dead_code)]
    pub merges: &'a MergeGroups,
    #[allow(dead_code)]
    pub as_of: NaiveDate,
    #[allow(dead_code)]
    pub manifest: &'a PackManifest,
    /// The rule's resolved severity (`off` rules never reach `evaluate`).
    #[allow(dead_code)] // read by the rule kinds as they land (#442+)
    pub severity: Severity,
}

/// One named rule kind: the single Rust implementation a manifest rule
/// dispatches to (PD1).
pub(crate) trait RuleKind: Send + Sync {
    /// The manifest's `kind` string, e.g. `"cadence-overdue"`.
    fn name(&self) -> &'static str;
    /// Kind-specific parameter validation, run at pack load so a bad
    /// pack fails closed before anything folds (the error becomes an
    /// `E_PACK_INVALID` `PackProblem`).
    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError>;
    /// Evaluate the rule, appending findings. Panics are caught by the
    /// evaluator; never assume a clean exit path.
    fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>);
    /// A kind with a fixed severity (never operator-tunable) returns it
    /// here; rules of such a kind omit `severity_key`. Default: none —
    /// every v1 kind's severity comes from `severity_key`.
    fn fixed_severity(&self) -> Option<Severity> {
        None
    }
}

/// Test-only rule registration (#441's acceptance needs a hook a test
/// kind can register through; production always sees the empty list).
static TEST_REGISTRY: Mutex<Option<Vec<&'static dyn RuleKind>>> = Mutex::new(None);

/// The registered rule kinds. Empty in #441: kinds arrive in their own
/// issues (#442, #443, #458, #446, #447, #448). Tests register via
/// [`with_rule_kinds_for_test`].
pub(crate) fn registered_rule_kinds() -> Vec<&'static dyn RuleKind> {
    // The kind implementations live in Rust (PD1); each kind's issue
    // appends its static here. #442: `cadence-overdue`; #443:
    // `date-upcoming`; #458: `note-ref`.
    let mut kinds: Vec<&'static dyn RuleKind> = vec![&CADENCE_OVERDUE, &DATE_UPCOMING, &NOTE_REF];
    kinds.extend(
        TEST_REGISTRY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(std::vec::Vec::clone)
            .unwrap_or_default(),
    );
    kinds
}

/// Look up a registered kind by manifest `kind` name.
pub(crate) fn rule_kind(kind: &str) -> Option<&'static dyn RuleKind> {
    registered_rule_kinds()
        .into_iter()
        .find(|k| k.name() == kind)
}

/// Run `f` with the given kinds registered (test-only). The registry is
/// swapped in for the call and always restored (drop guard), and a
/// separate mutex serializes tests that use it — `registered_rule_kinds`
/// must be able to lock while `f` runs, so the registry lock itself
/// cannot be held across `f`.
#[cfg(test)]
pub(crate) fn with_rule_kinds_for_test(kinds: Vec<&'static dyn RuleKind>, f: impl FnOnce()) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    {
        let mut guard = TEST_REGISTRY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(guard.is_none(), "nested test registration is not supported");
        *guard = Some(kinds);
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            *TEST_REGISTRY
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }
    let _restore = Restore;
    f();
}

/// Resolve one rule's severity: the operator's `[checks]` override wins,
/// with the manifest's declared default as the fallback. `None` means
/// off: the rule is skipped entirely.
pub(crate) fn resolve_rule_severity(
    vault: &Vault,
    manifest: &PackManifest,
    rule: &RuleDecl,
) -> Option<Severity> {
    // A kind with a fixed severity is never operator-tunable (`note-ref`
    // is always an error, like the compiled functions it reproduces).
    if let Some(fixed) = rule_kind(&rule.kind).and_then(|k| k.fixed_severity()) {
        return Some(fixed);
    }
    let Some(key) = &rule.severity_key else {
        return None;
    };
    // The manifest loader (#435) guarantees a declared severity_key has
    // an `[[checks.severity]]` entry; be defensive anyway.
    let manifest_default = manifest
        .checks
        .severity
        .iter()
        .find(|s| s.key == *key)
        .and_then(|s| parse_severity_token(&s.default).ok())?;
    // The manifest default itself may be `off` (Ok(None)).
    manifest_default?;
    vault
        .config
        .checks
        .severity(key, manifest_default.expect("checked Some above"))
}

/// Validate one rule's params against its registered kind (PD1: the
/// logic lives in Rust; the loader refuses what a kind does not accept).
pub(crate) fn validate_rule(rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
    let kind = rule_kind(&rule.kind).ok_or_else(|| {
        DomainError::config(format!(
            "rule '{}' has unknown rule kind '{}'",
            rule.id, rule.kind
        ))
        .with_fix("The kind is not implemented in this binary; see spec/pack-manifest.md")
    })?;
    // A rule with neither a declared severity key nor a kind-fixed
    // severity has no way to resolve: refuse at load.
    if rule.severity_key.is_none() && kind.fixed_severity().is_none() {
        return Err(DomainError::config(format!(
            "rule '{}' declares no severity_key and kind '{}' has no fixed severity",
            rule.id, rule.kind
        ))
        .with_fix(
            "Declare the key in [[checks.severity]] and set severity_key, or omit the rule",
        ));
    }
    // And the reverse: a fixed-severity kind cannot be tuned, so a
    // severity_key would be a declaration that silently does nothing.
    if rule.severity_key.is_some() && kind.fixed_severity().is_some() {
        return Err(DomainError::config(format!(
            "rule '{}' sets severity_key, but kind '{}' has a fixed severity",
            rule.id, rule.kind
        ))
        .with_fix("Omit severity_key: this kind always emits its fixed severity"));
    }
    kind.validate(rule, manifest)
}

/// Run one rule, panics converted to a fail-closed finding. The
/// finding names the rule id only: the pack name is operator free text
/// and must not echo (the #438/#494 privacy contract), the rule id is
/// pack-author text like the pack's message templates.
fn evaluate_catching_panic(
    kind: &'static dyn RuleKind,
    ctx: &RuleCtx,
    rule: &RuleDecl,
    out: &mut Vec<Finding>,
) {
    // A panic payload could carry anything; it is never unwrapped.
    let payload = catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut rule_findings = Vec::new();
        kind.evaluate(ctx, rule, &mut rule_findings);
        rule_findings
    }));
    match payload {
        Ok(rule_findings) => out.extend(rule_findings),
        Err(_) => out.push(
            Finding::new(
                FindingCode::PackInvalid,
                Severity::Error,
                format!("a rule ('{}') panicked and was not run", rule.id),
            )
            .at_file("confidant.toml")
            .with_fix("Report the pack issue to its author; remove the rule from the manifest"),
        ),
    }
}

/// The evaluator's two phases for one external pack, called from
/// `ExternalPack::findings` (manifest order, deterministic):
/// 1. field-grammar validation over person records,
/// 2. rule dispatch.
pub(crate) fn run(
    vault: &Vault,
    merges: &MergeGroups,
    as_of: NaiveDate,
    manifest: &PackManifest,
    out: &mut Vec<Finding>,
) {
    validate_declared_fields(vault, manifest, out);
    for rule in &manifest.rules {
        let Some(kind) = rule_kind(&rule.kind) else {
            // The loader rejects unknown kinds; this is defense in depth
            // for a manifest that changed under a running process.
            continue;
        };
        let Some(severity) = resolve_rule_severity(vault, manifest, rule) else {
            continue; // off (operator config or the manifest default)
        };
        let ctx = RuleCtx {
            vault,
            merges,
            as_of,
            manifest,
            severity,
        };
        evaluate_catching_panic(kind, &ctx, rule, out);
    }
}

/// Field grammar validation for an external pack (#441): every declared
/// `[[fields]]` entry is validated on every `person` record, exactly
/// like the compiled `personal@0.1` does. Messages come from the pack's
/// own `[messages."E_FRONTMATTER"]` template (loader guarantees the
/// pack declares it when it declares fields).
fn validate_declared_fields(vault: &Vault, manifest: &PackManifest, out: &mut Vec<Finding>) {
    if manifest.fields.is_empty() {
        return;
    }
    let mut records: Vec<&crate::record::Record> = vault.records.values().collect();
    records.sort_by(|a, b| a.id.cmp(&b.id));
    for rec in records {
        if rec.kind != crate::record::RecordKind::Person {
            continue;
        }
        for field in &manifest.fields {
            let Some(raw) = rec.field(&field.name) else {
                continue;
            };
            if parse_field_grammar(&field.grammar, field.name.as_str(), raw).is_some() {
                continue;
            }
            push_external_field_error(rec, manifest, &field.name, out);
        }
    }
}

/// `E_FRONTMATTER` with the pack's own message template.
fn push_external_field_error(
    rec: &crate::record::Record,
    manifest: &PackManifest,
    key: &str,
    out: &mut Vec<Finding>,
) {
    let msg = manifest.render_message(
        "E_FRONTMATTER",
        "default",
        &[
            ("key", &key),
            ("problem", &"does not match its declared grammar"),
        ],
    );
    let fix = manifest
        .render_fix(
            "E_FRONTMATTER",
            "default",
            &[("fix", &"Fix the value or remove the key")],
        )
        .unwrap_or_else(|| "Fix the value or remove the key".to_owned());
    let mut finding = Finding::new(FindingCode::Frontmatter, Severity::Error, msg)
        .at_file(&rec.path)
        .for_id(&rec.id)
        .with_fix(fix);
    if let Some(line) = rec.field_lines.get(key) {
        finding = finding.at_line(*line);
    }
    out.push(finding);
}

// ---------------------------------------------------------------------------
// Rule kinds (#442: cadence-overdue)
// ---------------------------------------------------------------------------

/// `cadence-overdue` (#442): for each merge-canonical person, warn when
/// the last contact older than the person's cadence window. Parameters
/// (spec/pack-manifest.md): `cadence_field` names one of the pack's own
/// declared fields with grammar `cadence`; `event_verbs` lists the
/// ledger verbs that count as contact (read-only access to ledger
/// metadata: date, verb, opaque id — PD8). Severity comes from
/// `severity_key`; an off rule is skipped before evaluation.
pub(crate) struct CadenceOverdueKind;

impl RuleKind for CadenceOverdueKind {
    fn name(&self) -> &'static str {
        "cadence-overdue"
    }

    /// Parameter validation (#442): `cadence_field` must name one of the
    /// pack's own `[[fields]]` entries with grammar `cadence`;
    /// `event_verbs` must be a non-empty list of non-empty strings; the
    /// message table must declare `last`, `none`, `last_fix`, `none_fix`.
    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
        let err = |detail: String| DomainError::config(format!("rule '{}': {detail}", rule.id));
        let Some(cadence_field) = rule.params.get("cadence_field").and_then(|v| v.as_str()) else {
            return Err(err(
                "the cadence_field parameter is missing (it names the pack's cadence field)"
                    .to_owned(),
            )
            .with_fix("Set cadence_field to a [[fields]] entry with grammar \"cadence\""));
        };
        let field = manifest
            .fields
            .iter()
            .find(|f| f.name == cadence_field)
            .ok_or_else(|| {
                err(format!(
                    "cadence_field '{cadence_field}' is not one of the pack's declared fields"
                ))
                .with_fix("Declare the field in [[fields]] or use its declared name")
            })?;
        if field.grammar != "cadence" {
            return Err(err(format!(
                "cadence_field '{}' has grammar '{}', not \"cadence\"",
                cadence_field, field.grammar
            ))
            .with_fix("Use a field declared with grammar = \"cadence\""));
        }
        let verbs = rule
            .params
            .get("event_verbs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                err("the event_verbs parameter is missing (it lists the verbs that count as contact)".to_owned())
                    .with_fix("Set event_verbs = [\"touch\", \"session\"]")
            })?;
        if verbs.is_empty() {
            return Err(err("event_verbs must not be empty".to_owned())
                .with_fix("Set event_verbs = [\"touch\", \"session\"]"));
        }
        for verb in verbs {
            let Some(verb) = verb.as_str() else {
                return Err(err("every event_verbs entry must be a string".to_owned())
                    .with_fix("Set event_verbs = [\"touch\", \"session\"]"));
            };
            if verb.trim().is_empty() {
                return Err(
                    err("every event_verbs entry must be a non-empty verb".to_owned())
                        .with_fix("Set event_verbs = [\"touch\", \"session\"]"),
                );
            }
        }
        for variant in ["last", "none"] {
            if !manifest
                .messages
                .get(&rule.code)
                .is_some_and(|m| m.contains_key(variant))
            {
                return Err(err(format!(
                    "the manifest's [messages.{}] table has no '{variant}' variant",
                    rule.code
                ))
                .with_fix("Add the variant template (see spec/pack-manifest.md)"));
            }
            let fix_variant = format!("{variant}_fix");
            if !manifest
                .messages
                .get(&rule.code)
                .is_some_and(|m| m.contains_key(&fix_variant))
            {
                return Err(err(format!(
                    "the manifest's [messages.{}] table has no '{fix_variant}' variant",
                    rule.code
                ))
                .with_fix("Add the fix template (see spec/pack-manifest.md)"));
            }
        }
        Ok(())
    }

    fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>) {
        let cadence_field = rule
            .params
            .get("cadence_field")
            .and_then(|v| v.as_str())
            .unwrap_or("cadence");
        let event_verbs: Vec<&str> = rule
            .params
            .get("event_verbs")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let Ok(code) = FindingCode::from_pack_str_or_builtin(intern_str(&rule.code)) else {
            return; // the loader validated the code; unreachable
        };

        // 1. Each person's cadence value from the pack's declared field.
        //    Invalid values are already reported by the field-grammar
        //    validation phase; here a missing/invalid value is "no
        //    cadence", which skips the person.
        let mut cadence: HashMap<RecordId, u32> = HashMap::new();
        for rec in vault_persons(ctx.vault) {
            if let Some(raw) = rec.field(cadence_field) {
                if let Some(FieldValue::CadenceDays(days)) =
                    parse_field_grammar("cadence", cadence_field, raw)
                {
                    cadence.insert(rec.id.clone(), days);
                }
            }
        }

        // 2. Canonical persons in deterministic order (merge-aware).
        let mut canonical_people: BTreeMap<RecordId, &Record> = BTreeMap::new();
        for rec in vault_persons(ctx.vault) {
            let canon = ctx.merges.canonical_on(&rec.id, ctx.as_of);
            if canon == rec.id {
                canonical_people.insert(canon, rec);
            }
        }

        // 3. Merge groups for `as_of`, seeded with every person so a
        //    canonical person with no direct events still groups.
        let all_persons: Vec<RecordId> = vault_persons(ctx.vault)
            .iter()
            .map(|r| r.id.clone())
            .collect();
        ctx.merges.ensure_members(all_persons, ctx.as_of);
        let groups_borrow = ctx.merges.groups();
        let groups = groups_borrow.get(&ctx.as_of).expect("members cached");

        for (id, rec) in canonical_people {
            // The person's own cadence first, else the first merged
            // member that has one (group members are sorted).
            let members: &[RecordId] = groups.get(&id).map(|v| v.as_slice()).unwrap_or(&[]);
            let Some(cadence_days) = cadence
                .get(&id)
                .copied()
                .or_else(|| members.iter().find_map(|m| cadence.get(m).copied()))
            else {
                continue;
            };

            // 4. Last contact: latest ledger date <= as_of whose verb is
            //    one of event_verbs, for the person or a merged member.
            let last = ctx
                .vault
                .entries
                .iter()
                .filter(|s| event_verbs.contains(&s.entry.verb.as_str()))
                .filter(|s| s.entry.date <= ctx.as_of)
                .filter(|s| {
                    groups
                        .get(&id)
                        .is_some_and(|members| members.contains(&s.entry.id))
                })
                .map(|s| s.entry.date)
                .max();
            if let Some(d) = last {
                if ctx.as_of.signed_duration_since(d)
                    <= chrono::Duration::days(i64::from(cadence_days))
                {
                    continue; // within the window
                }
            }
            let start = ctx.as_of - chrono::Duration::days(i64::from(cadence_days));
            let (message, fix) = match last {
                Some(d) => (
                    ctx.manifest.render_message(
                        &rule.code,
                        "last",
                        &[
                            ("id", &id),
                            ("start", &start),
                            ("d", &d),
                            ("cadence_days", &cadence_days),
                        ],
                    ),
                    ctx.manifest
                        .render_fix(&rule.code, "last", &[("id", &id)])
                        .unwrap_or_default(),
                ),
                None => (
                    ctx.manifest.render_message(
                        &rule.code,
                        "none",
                        &[("id", &id), ("cadence_days", &cadence_days)],
                    ),
                    ctx.manifest
                        .render_fix(&rule.code, "none", &[("id", &id)])
                        .unwrap_or_default(),
                ),
            };
            out.push(
                Finding::new(code, ctx.severity, message)
                    .at_file(&rec.path)
                    .for_id(id)
                    .with_fix(fix),
            );
        }
    }
}

/// Intern a short string to a `'static` str so repeated check runs
/// (long-lived MCP/TUI processes) don't leak one string per evaluation
/// (#495 review nit). The map grows once per distinct string, then stops.
fn intern_str(s: &str) -> &'static str {
    static INTERNED: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<String, &'static str>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut map = INTERNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(&leaked) = map.get(s) {
        return leaked;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    map.insert(s.to_owned(), leaked);
    leaked
}

/// Person records in deterministic order.
fn vault_persons(vault: &Vault) -> Vec<&crate::record::Record> {
    let mut records: Vec<&crate::record::Record> = vault
        .records
        .values()
        .filter(|r| r.kind == crate::record::RecordKind::Person)
        .collect();
    records.sort_by(|a, b| a.id.cmp(&b.id));
    records
}

static CADENCE_OVERDUE: CadenceOverdueKind = CadenceOverdueKind;

// ---------------------------------------------------------------------------
// Rule kinds (#443: date-upcoming)
// ---------------------------------------------------------------------------

/// `date-upcoming` (#443): for each merge-canonical person, warn when one
/// of the pack's recurring-date fields has its next occurrence within the
/// configured lookahead window. Reproduces `personal@0.1`'s upcoming-dates
/// rule (including its date math: the parsers and
/// [`RecurringDate::next_occurrence_on_or_after`] are reused, never
/// reimplemented).
///
/// Parameters (spec/pack-manifest.md): `date_fields` lists the pack's own
/// declared fields with grammar `recurring-date` (one date) or
/// `dates-list` (one per entry), in the order findings are emitted;
/// `window_key` names a declared `[[checks.int]]` key holding the window
/// in days, measured from `as_of`. Severity comes from `severity_key`; an
/// off rule is skipped before evaluation.
pub(crate) struct DateUpcomingKind;

impl RuleKind for DateUpcomingKind {
    fn name(&self) -> &'static str {
        "date-upcoming"
    }

    /// Parameter validation (#443): `date_fields` must be a non-empty list
    /// of the pack's own `[[fields]]` entries with grammar
    /// `recurring-date` or `dates-list`; `window_key` must name a declared
    /// `[[checks.int]]` key; the message table must declare
    /// `default` and `default_fix`.
    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
        let err = |detail: String| DomainError::config(format!("rule '{}': {detail}", rule.id));
        let fix_hint = "Set date_fields = [\"birthday\", \"dates\"]";
        let Some(fields) = rule.params.get("date_fields").and_then(|v| v.as_array()) else {
            return Err(err(
                "the date_fields parameter is missing (it lists the pack's recurring-date fields)"
                    .to_owned(),
            )
            .with_fix(fix_hint));
        };
        if fields.is_empty() {
            return Err(err("date_fields must not be empty".to_owned()).with_fix(fix_hint));
        }
        for field in fields {
            let Some(name) = field.as_str() else {
                return Err(
                    err("every date_fields entry must be a string".to_owned()).with_fix(fix_hint)
                );
            };
            if name.trim().is_empty() {
                return Err(err(
                    "every date_fields entry must be a non-empty field name".to_owned()
                )
                .with_fix(fix_hint));
            }
            let decl = manifest
                .fields
                .iter()
                .find(|f| f.name == name)
                .ok_or_else(|| {
                    err(format!(
                        "date_fields entry '{name}' is not one of the pack's declared fields"
                    ))
                    .with_fix("Declare the field in [[fields]] or use its declared name")
                })?;
            match decl.grammar.as_str() {
                GRAMMAR_RECURRING_DATE | GRAMMAR_DATES_LIST => {}
                other => {
                    return Err(err(format!(
                        "date_fields entry '{name}' has grammar '{other}', not \"recurring-date\" or \"dates-list\""
                    ))
                    .with_fix(
                        "Use a field declared with grammar = \"recurring-date\" or \"dates-list\"",
                    ));
                }
            }
        }

        let Some(window_key) = rule.params.get("window_key").and_then(|v| v.as_str()) else {
            return Err(err(
                "the window_key parameter is missing (it names the pack's window check)".to_owned(),
            )
            .with_fix("Set window_key to a declared [[checks.int]] key"));
        };
        if window_key.trim().is_empty() {
            return Err(err("window_key must be a non-empty key".to_owned())
                .with_fix("Set window_key to a declared [[checks.int]] key"));
        }
        if !manifest.checks.int.iter().any(|i| i.key == window_key) {
            return Err(err(format!(
                "window_key '{window_key}' is not a declared [[checks.int]] key"
            ))
            .with_fix("Declare the key in [[checks.int]] or use its declared key"));
        }

        if !manifest
            .messages
            .get(&rule.code)
            .is_some_and(|m| m.contains_key("default"))
        {
            return Err(err(format!(
                "the manifest's [messages.{}] table has no 'default' variant",
                rule.code
            ))
            .with_fix("Add the variant template (see spec/pack-manifest.md)"));
        }
        if !manifest
            .messages
            .get(&rule.code)
            .is_some_and(|m| m.contains_key("default_fix"))
        {
            return Err(err(format!(
                "the manifest's [messages.{}] table has no 'default_fix' variant",
                rule.code
            ))
            .with_fix("Add the fix template (see spec/pack-manifest.md)"));
        }
        Ok(())
    }

    fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>) {
        let date_fields: Vec<&str> = rule
            .params
            .get("date_fields")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let window_key = rule
            .params
            .get("window_key")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let window = resolve_int_check(ctx, window_key);
        let window_i = i64::try_from(window).unwrap_or(i64::MAX);
        let Ok(code) = FindingCode::from_pack_str_or_builtin(intern_str(&rule.code)) else {
            return; // the loader validated the code; unreachable
        };

        // Canonical persons in deterministic order (merge-aware), reading
        // only their own record's fields — the compiled rule does the
        // same (a merged member's dates do not carry over).
        let mut canonical_people: BTreeMap<RecordId, &Record> = BTreeMap::new();
        for rec in vault_persons(ctx.vault) {
            let canon = ctx.merges.canonical_on(&rec.id, ctx.as_of);
            if canon == rec.id {
                canonical_people.insert(canon, rec);
            }
        }

        for (id, rec) in canonical_people {
            // Each field's grammar decides one date or a list of them;
            // values that do not parse are already reported by the
            // field-grammar phase, so here they contribute nothing.
            let mut dates: Vec<RecurringDate> = Vec::new();
            for name in &date_fields {
                let Some(raw) = rec.field(name) else {
                    continue;
                };
                let grammar = ctx
                    .manifest
                    .fields
                    .iter()
                    .find(|f| f.name == *name)
                    .map(|f| f.grammar.as_str())
                    .unwrap_or_default();
                match parse_field_grammar(grammar, *name, raw) {
                    Some(FieldValue::RecurringDate(date)) => dates.push(date),
                    Some(FieldValue::DatesList(list)) => dates.extend(list),
                    _ => {}
                }
            }
            for date in dates {
                let Some(occ) = date.next_occurrence_on_or_after(ctx.as_of) else {
                    continue;
                };
                let delta = occ.signed_duration_since(ctx.as_of).num_days();
                if !(0..=window_i).contains(&delta) {
                    continue;
                }
                out.push(
                    Finding::new(
                        code,
                        ctx.severity,
                        ctx.manifest.render_message(
                            &rule.code,
                            "default",
                            &[("id", &id), ("occ", &occ), ("delta", &delta)],
                        ),
                    )
                    .at_file(&rec.path)
                    .for_id(id.clone())
                    .with_fix(
                        ctx.manifest
                            .render_fix(&rule.code, "default", &[("id", &id)])
                            .unwrap_or_default(),
                    ),
                );
            }
        }
    }
}

/// Resolve a declared int check's value: the operator's `[checks]`
/// override first (seeded into `vault.config` by the vault's config
/// pass), else the manifest's declared default. External packs' int
/// defaults are not seeded into `vault.config` by `VaultConfig::parse`
/// (only compiled manifests are), so the manifest fallback keeps a
/// declared `window_key` meaningful for them.
fn resolve_int_check(ctx: &RuleCtx, key: &str) -> u64 {
    if let Some(value) = ctx.vault.config.checks.int(key) {
        return value;
    }
    ctx.manifest
        .checks
        .int
        .iter()
        .find(|i| i.key == key)
        .map(|i| u64::try_from(i.default).unwrap_or(0))
        .unwrap_or(0)
}

static DATE_UPCOMING: DateUpcomingKind = DateUpcomingKind;

// ---------------------------------------------------------------------------
// Rule kinds (#458: note-ref)
// ---------------------------------------------------------------------------

/// Default code for a note id that does not parse as a record id.
const DEFAULT_INVALID_ID_CODE: &str = "E_INVALID_ID";
/// Default code for a parsed id that is not a note id.
const DEFAULT_WRONG_ID_TYPE_CODE: &str = "E_WRONG_ID_TYPE";

/// Read one of the note-ref code parameters. An absent parameter takes
/// the core default; a present-but-non-string value is refused, the same
/// way `variants` is, never silently replaced with the default.
fn note_ref_code_param<'a>(
    rule: &'a RuleDecl,
    name: &str,
    default: &'a str,
) -> Result<&'a str, DomainError> {
    match rule.params.get(name) {
        None => Ok(default),
        Some(value) => value.as_str().ok_or_else(|| {
            DomainError::config(format!("rule '{}': {name} must be a string", rule.id)).with_fix(
                format!("Omit {name}, or set it to a code the pack declares"),
            )
        }),
    }
}

/// `note-ref` (#458): every `<pair>:<note-id>` on a pack's ledger verb must
/// name an existing note that belongs to the entry's canonical person.
/// Reproduces personal@0.1's `touch_note_integrity` and coaching@0.1's
/// `session_note_integrity`; only ids and path ownership are read, never
/// note bodies (PD8).
///
/// Parameters (spec/pack-manifest.md):
/// - `verb`: the ledger verb whose entries are checked.
/// - `pair`: the `key:value` pair holding the note id (today `"note"`).
/// - `variants`: `"touch"` (default) selects personal's variant names
///   (`default`/`default_fix` for the invalid-id and wrong-type
///   problems); `"session"` selects coaching's `session_note`/
///   `session_note_fix`. The `missing`/`wrong_owner` variants are shared.
/// - `invalid_code` / `wrong_type_code`: optional codes for the first two
///   problems. Default to the core codes the compiled functions emit.
///   A pack that cannot claim core codes (every external pack, PD13) sets
///   its own declared codes here.
///
/// The generic `code` is the code for the missing / wrong-owner problems.
/// The kind has a fixed `error` severity (both compiled functions emit
/// `Severity::Error`), so rules omit `severity_key`.
pub(crate) struct NoteRefKind;

impl NoteRefKind {
    /// The variant names this rule uses, from the `variants` parameter:
    /// `(invalid/wrong-type variant, ...)`. Missing/wrong-owner variants
    /// are the same for both compiled functions.
    fn wrong_id_variant(rule: &RuleDecl) -> &str {
        match rule.params.get("variants").and_then(|v| v.as_str()) {
            Some("session") => "session_note",
            _ => "default",
        }
    }
}

impl RuleKind for NoteRefKind {
    fn name(&self) -> &'static str {
        "note-ref"
    }

    fn fixed_severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    /// Parameter validation (#458): `verb` and `pair` must be non-empty
    /// strings; `variants`, when present, is `"touch"` or `"session"`; the
    /// three emitted codes must have their message tables (with the
    /// variants this kind renders) and, when pack-own, be declared in
    /// `finding_codes`.
    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
        let err = |detail: String| DomainError::config(format!("rule '{}': {detail}", rule.id));
        for (name, fix_hint) in [
            ("verb", "Set verb = \"touch\""),
            ("pair", "Set pair = \"note\""),
        ] {
            let Some(value) = rule.params.get(name).and_then(|v| v.as_str()) else {
                return Err(err(format!(
                    "the {name} parameter is missing (it names the ledger {name} to check)"
                ))
                .with_fix(fix_hint));
            };
            if value.trim().is_empty() {
                return Err(err(format!("{name} must be a non-empty string")).with_fix(fix_hint));
            }
        }
        if let Some(variants) = rule.params.get("variants") {
            let Some(value) = variants.as_str() else {
                return Err(err("variants must be a string".to_owned())
                    .with_fix("Omit variants, or set variants = \"touch\" or \"session\""));
            };
            if value != "touch" && value != "session" {
                return Err(err(format!(
                    "variants '{value}' is not one of \"touch\" or \"session\""
                ))
                .with_fix("Omit variants, or set variants = \"touch\" or \"session\""));
            }
        }

        let invalid_code = note_ref_code_param(rule, "invalid_code", DEFAULT_INVALID_ID_CODE)?;
        let wrong_type_code =
            note_ref_code_param(rule, "wrong_type_code", DEFAULT_WRONG_ID_TYPE_CODE)?;
        let wrong_id_variant = Self::wrong_id_variant(rule);

        // An external pack cannot claim a builtin code in either code
        // parameter (#494): `E_FRONTMATTER` is the one allowed emission
        // claim and every pack with fields already has its message table,
        // so a builtin here would let a pack emit a core code with a
        // re-worded meaning — the same escape the `rule.code` check in
        // `validate_external` closes. The v1 built-in path (compiled
        // personal) keeps the core defaults.
        if manifest.manifest_version == MANIFEST_VERSION_V2 {
            for (role, code) in [
                ("invalid_code", invalid_code),
                ("wrong_type_code", wrong_type_code),
            ] {
                if FindingCode::is_builtin_code(code) {
                    return Err(DomainError::config(format!(
                        "rule '{}' emits builtin code '{}'; a rule's {role} must be a pack-own code",
                        rule.id, code
                    ))
                    .with_fix(
                        "Declare a pack-own code (e.g. W_<PACK>_<RULE>) in finding_codes and use it",
                    ));
                }
            }
        }

        // Every emitted code must be declared, or (on the v1 core-default
        // path) one of the core codes the compiled functions emit; the
        // builtin-code guard above already forced an external pack's two
        // parameters to be pack-own. Message tables must exist with
        // exactly the variants the evaluator renders; the loader's orphan
        // rule means an external pack cannot declare a core code's table,
        // so a missing table fails closed here.
        for (role, code, variants) in [
            (
                "invalid_code",
                invalid_code,
                vec![
                    wrong_id_variant.to_owned(),
                    format!("{wrong_id_variant}_fix"),
                ],
            ),
            (
                "wrong_type_code",
                wrong_type_code,
                vec![
                    wrong_id_variant.to_owned(),
                    format!("{wrong_id_variant}_fix"),
                ],
            ),
            (
                "code",
                rule.code.as_str(),
                vec![
                    "missing".to_owned(),
                    "missing_fix".to_owned(),
                    "wrong_owner".to_owned(),
                    "wrong_owner_fix".to_owned(),
                ],
            ),
        ] {
            if !FindingCode::is_builtin_code(code)
                && !manifest.finding_codes.iter().any(|c| c == code)
            {
                return Err(err(format!(
                    "{role} '{code}' is not in the pack's finding_codes"
                ))
                .with_fix("Add the code to finding_codes or use a declared code"));
            }
            for variant in variants {
                if !manifest
                    .messages
                    .get(code)
                    .is_some_and(|m| m.contains_key(&variant))
                {
                    return Err(err(format!(
                        "the manifest's [messages.{code}] table has no '{variant}' variant"
                    ))
                    .with_fix("Add the variant template (see spec/pack-manifest.md)"));
                }
            }
        }
        Ok(())
    }

    fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>) {
        let verb = rule
            .params
            .get("verb")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let pair = rule
            .params
            .get("pair")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let wrong_id_variant = Self::wrong_id_variant(rule);
        let invalid_code_str = rule
            .params
            .get("invalid_code")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_INVALID_ID_CODE);
        let wrong_type_code_str = rule
            .params
            .get("wrong_type_code")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_WRONG_ID_TYPE_CODE);
        let (Some(invalid_code), Some(wrong_type_code), Some(unknown_code)) = (
            resolve_finding_code(invalid_code_str),
            resolve_finding_code(wrong_type_code_str),
            resolve_finding_code(&rule.code),
        ) else {
            return; // the loader validated the codes; unreachable
        };

        for sourced in &ctx.vault.entries {
            let entry = &sourced.entry;
            if entry.verb != verb || entry.id.prefix() != Prefix::Person {
                continue;
            }
            let Some(note_id) = entry.pair(pair) else {
                continue;
            };
            // The compiled functions canonicalize as of "now" (`MAX`),
            // not `as_of`: ownership is not a point-in-time question.
            let person = ctx.merges.canonical_on(&entry.id, NaiveDate::MAX);
            let finding =
                |code: FindingCode, variant: &str, args: &[(&str, &dyn std::fmt::Display)]| {
                    Finding::new(
                        code,
                        Severity::Error,
                        ctx.manifest.render_message(code.as_str(), variant, args),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&person)
                    .with_fix(
                        ctx.manifest
                            .render_fix(code.as_str(), variant, args)
                            .unwrap_or_default(),
                    )
                };

            match RecordId::parse(note_id) {
                Err(_) => out.push(finding(invalid_code, wrong_id_variant, &[])),
                Ok(nid) if nid.prefix() != Prefix::Note => out.push(finding(
                    wrong_type_code,
                    wrong_id_variant,
                    // The compiled packs name this placeholder `{id}` in
                    // personal and `{nid}` in coaching; both are supplied so
                    // either template renders.
                    &[("id", &nid), ("nid", &nid)],
                )),
                Ok(nid) => match ctx.vault.records.get(&nid) {
                    Some(rec) => {
                        let note_person = rec
                            .person()
                            .or_else(|| crate::id::person_id_from_path(&rec.path))
                            .map(|p| ctx.merges.canonical_on(&p, NaiveDate::MAX));
                        if note_person.as_ref() != Some(&person) {
                            out.push(finding(
                                unknown_code,
                                "wrong_owner",
                                &[("id", &nid), ("nid", &nid), ("person", &person)],
                            ));
                        }
                    }
                    // #399: a conflicted record is not loaded, but it
                    // exists (two versions). Treat it as existing rather
                    // than report the note missing (#458).
                    None if ctx.vault.conflicted_ids.contains(&nid) => {}
                    None => out.push(finding(
                        unknown_code,
                        "missing",
                        &[("id", &nid), ("nid", &nid)],
                    )),
                },
            }
        }
    }
}

/// Resolve a manifest-supplied code string: a core code keeps its builtin
/// variant (the compiled packs' codes), anything else becomes a pack code.
fn resolve_finding_code(code: &str) -> Option<FindingCode> {
    if let Some(builtin) = FindingCode::builtin_from_str(code) {
        return Some(builtin);
    }
    FindingCode::from_pack_str_or_builtin(intern_str(code)).ok()
}

static NOTE_REF: NoteRefKind = NoteRefKind;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_vault;
    use crate::packs::manifest::parse_manifest_external;
    use crate::record::RecordKind;
    use std::collections::HashMap;

    /// A test rule kind: emits one finding tagged with the rule id, or
    /// panics.
    struct TestKind {
        name: &'static str,
        panic_on_evaluate: bool,
    }

    impl TestKind {
        fn leaked(name: &'static str) -> &'static dyn RuleKind {
            Box::leak(Box::new(TestKind {
                name,
                panic_on_evaluate: false,
            }))
        }
        fn leaked_panic(name: &'static str) -> &'static dyn RuleKind {
            Box::leak(Box::new(TestKind {
                name,
                panic_on_evaluate: true,
            }))
        }
    }

    impl RuleKind for TestKind {
        fn name(&self) -> &'static str {
            self.name
        }
        fn validate(&self, _rule: &RuleDecl, _manifest: &PackManifest) -> Result<(), DomainError> {
            Ok(())
        }
        fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>) {
            if self.panic_on_evaluate {
                panic!("SENTINEL-TEST-PANIC");
            }
            out.push(
                Finding::new(
                    FindingCode::Pack("W_TEST_KIND_CODE"),
                    ctx.severity,
                    format!("rule {}", rule.id),
                )
                .at_file("confidant.toml"),
            );
        }
    }

    pub(super) fn as_of() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 8).unwrap()
    }

    /// Manifest with one `[[rules]]` entry of the given kind.
    fn manifest_with_rules(rules_toml: &str) -> PackManifest {
        let text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.severity]]
key = "example-pack.test_rule"
default = "warning"

{rules}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#,
            rules = rules_toml
        );
        parse_manifest_external(&text).expect("fixture manifest should parse")
    }

    /// A vault fixture: confidant.toml with `[checks]` overrides, a
    /// person record with an optional extra field.
    fn fixture_vault(operator_checks: &str, person_extra: Option<&str>) -> Vault {
        let dir = tempfile::tempdir().unwrap();
        let extra = person_extra.unwrap_or("");
        std::fs::create_dir_all(dir.path().join("people/p-01J9Z3K4QF0000000000000000")).unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            format!(
                "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n{operator_checks}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("people/p-01J9Z3K4QF0000000000000000/profile.md"),
            format!(
                "---\nid: p-01J9Z3K4QF0000000000000000\ntype: person\nname: Ada Example{extra}\n---\n\nFake person.\n"
            ),
        )
        .unwrap();
        // `dir` drops at the end of this function, removing the vault
        // files: harmless — `load_vault` reads everything into memory
        // before returning, and the tests only read the loaded vault.
        load_vault(dir.path()).expect("fixture vault should load")
    }

    pub(super) fn empty_merges() -> MergeGroups {
        MergeGroups::new(HashMap::new())
    }

    #[test]
    fn dispatch_runs_rules_in_manifest_order() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked("test-rule")],
            || {
                // Parse inside the hook: the kind list must be live.
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"rule_b\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n\n[[rules]]\nid = \"rule_a\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                let vault = fixture_vault("", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                // The manifest lists rule_b before rule_a: findings
                // follow manifest order, not id order.
                assert_eq!(out.len(), 2, "both rules ran: {out:?}");
                let messages: Vec<&String> = out.iter().map(|f| &f.message).collect();
                assert!(
                    messages[0].contains("rule_b") && messages[1].contains("rule_a"),
                    "expected manifest order: {out:?}"
                );
            },
        );
    }

    #[test]
    fn rule_severity_off_skips_rule() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked("test-rule")],
            || {
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"my_rule\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                let vault = fixture_vault("example-pack.test_rule = \"off\"\n", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert!(out.is_empty(), "an off rule must not run: {out:?}");
            },
        );
    }

    #[test]
    fn rule_severity_error_vs_warning_from_config() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked("test-rule")],
            || {
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"my_rule\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                // No operator override: the manifest default (warning).
                let vault = fixture_vault("", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert_eq!(out[0].severity, Severity::Warning, "{out:?}");

                // Operator override: error.
                let vault = fixture_vault("example-pack.test_rule = \"error\"\n", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert_eq!(out[0].severity, Severity::Error, "{out:?}");
            },
        );
    }

    #[test]
    fn unknown_kind_rejected_by_loader() {
        // "nope" is not a registered kind: the manifest loader refuses
        // the pack (the fixture is otherwise valid TOML, so this really
        // is the kind check firing).
        let err = parse_manifest_external(&manifest_with_rules_text_kind("nope"))
            .expect_err("unknown kind must be refused");
        assert!(err.to_string().contains("unknown rule kind"), "{err:?}");
    }

    fn manifest_with_rules_text_kind(kind: &str) -> String {
        format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[rules]]
id = "my_rule"
kind = "{kind}"
code = "W_TEST_KIND_CODE"
severity_key = "example-pack.test_rule"

[[checks.severity]]
key = "example-pack.test_rule"
default = "warning"

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#
        )
    }

    #[test]
    fn known_rule_kinds_match_manifest_list() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![
                TestKind::leaked("test-rule"),
                TestKind::leaked("other-rule"),
            ],
            || {
                // The manifest list is derived from the registered
                // kinds: production kinds first, then the test hook's.
                let names = crate::packs::manifest::known_rule_kinds();
                assert_eq!(
                    names,
                    vec![
                        "cadence-overdue",
                        "date-upcoming",
                        "note-ref",
                        "test-rule",
                        "other-rule"
                    ]
                );
            },
        );
        // Outside the hook only the production kinds remain. Run this
        // inside an empty-kinds hook: it holds the serial lock, so no
        // parallel test can have kinds registered while we assert.
        crate::packs::declarative::with_rule_kinds_for_test(vec![], || {
            assert_eq!(
                crate::packs::manifest::known_rule_kinds(),
                vec!["cadence-overdue", "date-upcoming", "note-ref"]
            );
        });
    }

    #[test]
    fn field_grammar_error_reported_as_e_frontmatter() {
        // A manifest declaring a cadence field (no rules).
        let text = r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "cadence"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#;
        let manifest = parse_manifest_external(text).unwrap();
        let vault = fixture_vault("", Some("\ncadence: soon"));
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].code, FindingCode::Frontmatter);
        assert!(
            out[0].message.contains("front matter key 'cadence'"),
            "message from the pack's template: {out:?}"
        );
    }

    #[test]
    fn field_grammar_valid_values_no_finding() {
        let text = r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "cadence"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#;
        let manifest = parse_manifest_external(text).unwrap();
        let vault = fixture_vault("", Some("\ncadence: 30d"));
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert!(out.is_empty(), "valid value must not report: {out:?}");
    }

    #[test]
    fn panicking_rule_becomes_pack_invalid_finding() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked_panic("test-rule")],
            || {
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"my_rule\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                let vault = fixture_vault("", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert_eq!(out.len(), 1, "{out:?}");
                assert_eq!(out[0].code, FindingCode::PackInvalid);
                assert!(
                    !format!("{:?}", out).contains("SENTINEL-TEST-PANIC"),
                    "panic payload must never surface: {out:?}"
                );
            },
        );
    }

    #[test]
    fn pack_code_maps_to_enum_variant_when_equal() {
        // Only E_FRONTMATTER is accepted as a builtin emission claim
        // (the spec example's); other builtins stay refused (PD13,
        // #494 review).
        use std::sync::OnceLock;
        static S1: OnceLock<&'static str> = OnceLock::new();
        let s1 = S1.get_or_init(|| Box::leak("E_FRONTMATTER".to_owned().into_boxed_str()));
        assert_eq!(
            FindingCode::from_pack_str_or_builtin(s1).unwrap(),
            FindingCode::Frontmatter
        );
        static S3: OnceLock<&'static str> = OnceLock::new();
        let s3 = S3.get_or_init(|| Box::leak("W_CADENCE_OVERDUE".to_owned().into_boxed_str()));
        assert!(FindingCode::from_pack_str_or_builtin(s3).is_err());
        static S2: OnceLock<&'static str> = OnceLock::new();
        let s2 = S2.get_or_init(|| Box::leak("W_EXAMPLE_THING".to_owned().into_boxed_str()));
        assert_eq!(
            FindingCode::from_pack_str_or_builtin(s2).unwrap(),
            FindingCode::Pack("W_EXAMPLE_THING")
        );
    }

    #[test]
    fn fixtures_use_person_kind() {
        // Guard the fixture's shape: the person record is a person.
        let vault = fixture_vault("", None);
        assert!(vault.records.values().all(|r| r.kind == RecordKind::Person));
    }

    /// PD9 (#445): a declarative pack ships text and data only. This scan
    /// fails if any evaluator source ever grows a file, network, or process
    /// call. The sources are `include_str!` so the scan itself reads no
    /// files, and `dir.rs` is not scanned: it is the pack module's one
    /// legitimate filesystem reader (the evaluator reaches it only through
    /// its API).
    ///
    /// Test modules are excluded: they build fixtures with `std::fs` by
    /// design. The split marker matches `#[cfg(test)]` followed by `mod `
    /// (the convention: the trailing test modules, not the small test-only
    /// hook earlier in the file).
    ///
    /// `#[test]` files live in this module; a future `packs/rules/*.rs`
    /// module must be added to `EVALUATOR_SOURCES` by hand — a compile-time
    /// scan cannot glob a directory.
    #[test]
    fn evaluator_sources_have_no_io_apis() {
        const EVALUATOR_SOURCES: &[(&str, &str)] = &[
            ("packs/declarative.rs", include_str!("declarative.rs")),
            ("packs/external.rs", include_str!("external.rs")),
        ];
        const FORBIDDEN: &[&str] = &[
            "std::net",
            "std::process",
            "std::fs",
            "tokio",
            "reqwest",
            "Command::new",
            "std::env::var",
        ];
        for (name, source) in EVALUATOR_SOURCES {
            let production = source.split("#[cfg(test)]\nmod ").next().unwrap_or(source);
            for needle in FORBIDDEN {
                assert!(
                    !production.contains(needle),
                    "{name} mentions {needle:?}; evaluator sources must do no I/O (PD9, #445)"
                );
            }
        }
    }
}

#[cfg(test)]
mod cadence_kind_tests {
    use super::tests::{as_of, empty_merges};
    use super::*;
    use crate::load_vault;
    use crate::packs::dir::read_pack_dir;
    use crate::packs::external::{load_external_packs, PackProblem, PackProblemKind};
    use crate::packs::lock::Lockfile;
    use crate::packs::manifest::parse_manifest_external;
    use crate::packs::registry::PackRegistry;

    /// Vendor a pack whose cadence rule has the given manifest body
    /// (params vary per test) and return the loader's problems.
    fn load_with_rule(rules: &str, messages: &str) -> Vec<PackProblem> {
        let dir = tempfile::tempdir().unwrap();
        let text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_CADENCE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "cadence"

{rules}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

{messages}
"#
        );
        let pack_dir = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("manifest.toml"), text).unwrap();
        std::fs::write(pack_dir.join("SKILL.md"), "# example pack.\n").unwrap();
        let hash = read_pack_dir(&pack_dir)
            .map(|p| p.hash)
            .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
        let mut lock = Lockfile::default();
        lock.upsert(crate::packs::lock::LockEntry {
            name: "example-pack".to_owned(),
            version: "0.1".to_owned(),
            source: "https://example.invalid/org/example-pack.git".to_owned(),
            rev: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            subdir: String::new(),
            hash,
        });
        std::fs::write(dir.path().join("confidant.lock"), lock.to_toml()).unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["example-pack@0.1".to_owned()],
            &compiled,
        );
        load.problems
    }

    fn cadence_rule(params: &str) -> String {
        format!(
            "[[rules]]\nid = \"cadence\"\nkind = \"cadence-overdue\"\ncode = \"W_EXAMPLE_CADENCE\"\nseverity_key = \"example-pack.cadence_overdue\"\n{params}"
        )
    }

    fn cadence_messages() -> String {
        r#"[messages."W_EXAMPLE_CADENCE"]
last = "person {id} has no touchpoint on or after {start} (last was {d}, cadence {cadence_days}d)"
last_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
none = "person {id} has no touchpoint logged (cadence {cadence_days}d)"
none_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence""#
            .to_owned()
    }

    fn severity_entry() -> String {
        "[[checks.severity]]\nkey = \"example-pack.cadence_overdue\"\ndefault = \"warning\"\n"
            .to_owned()
    }

    /// Assert the pack fails closed with a single `Invalid` problem
    /// whose detail names the bad parameter.
    fn assert_loader_refuses(problems: &[PackProblem], detail_snippet: &str) {
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            matches!(problems[0].kind, PackProblemKind::Invalid),
            "{problems:?}"
        );
        assert!(
            problems[0].detail.contains(detail_snippet),
            "detail missing {detail_snippet:?}: {}",
            problems[0].detail
        );
    }

    /// #495: the loader negatives — each bad parameter makes the pack
    /// fail closed with an `Invalid` problem (an `E_PACK_INVALID`
    /// finding through `check`), and the detail names the parameter.
    #[test]
    fn loader_refuses_undeclared_cadence_field() {
        let problems = load_with_rule(
            &format!(
                "{}\n{}",
                cadence_rule("cadence_field = \"ghost\"\nevent_verbs = [\"touch\"]\n"),
                severity_entry()
            ),
            &cadence_messages(),
        );
        assert_loader_refuses(&problems, "is not one of the pack's declared fields");
    }

    /// #495: the positive control — the same fixture with valid
    /// parameters loads with no problems.
    #[test]
    fn loader_accepts_valid_cadence_rule() {
        let problems = load_with_rule(
            &format!(
                "{}\n{}",
                cadence_rule("cadence_field = \"cadence\"\nevent_verbs = [\"touch\"]\n"),
                severity_entry()
            ),
            &cadence_messages(),
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn loader_refuses_cadence_field_with_wrong_grammar() {
        // The pack declares `cadence` with grammar "recurring-date":
        // not usable as a cadence_field.
        let dir_rules = cadence_rule("cadence_field = \"cadence\"\nevent_verbs = [\"touch\"]\n");
        let text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_CADENCE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "recurring-date"

{dir_rules}

[[checks.severity]]
key = "example-pack.cadence_overdue"
default = "warning"

{msg}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"
"#,
            msg = cadence_messages()
        );
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("manifest.toml"), text).unwrap();
        std::fs::write(pack_dir.join("SKILL.md"), "# example pack.\n").unwrap();
        let hash = read_pack_dir(&pack_dir)
            .map(|p| p.hash)
            .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
        let mut lock = Lockfile::default();
        lock.upsert(crate::packs::lock::LockEntry {
            name: "example-pack".to_owned(),
            version: "0.1".to_owned(),
            source: "https://example.invalid/org/example-pack.git".to_owned(),
            rev: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            subdir: String::new(),
            hash,
        });
        std::fs::write(dir.path().join("confidant.lock"), lock.to_toml()).unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["example-pack@0.1".to_owned()],
            &compiled,
        );
        assert_loader_refuses(&load.problems, "has grammar 'recurring-date'");
    }

    #[test]
    fn loader_refuses_rule_missing_last_fix() {
        // The message table lacks `last_fix`: the loader refuses.
        let messages = cadence_messages().replace(
            "last_fix = \"Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence\"\n",
            "",
        );
        let problems = load_with_rule(
            &format!(
                "{}\n{}",
                cadence_rule("cadence_field = \"cadence\"\nevent_verbs = [\"touch\"]\n"),
                severity_entry()
            ),
            &messages,
        );
        assert_loader_refuses(&problems, "has no 'last_fix' variant");
    }

    #[test]
    fn loader_refuses_empty_event_verbs() {
        let problems = load_with_rule(
            &format!(
                "{}\n{}",
                cadence_rule("cadence_field = \"cadence\"\nevent_verbs = []\n"),
                severity_entry()
            ),
            &cadence_messages(),
        );
        assert_loader_refuses(&problems, "event_verbs must not be empty");
    }

    /// #495: a person with no cadence value is skipped, not warned.
    #[test]
    fn cadence_rule_no_cadence_field_skipped() {
        let manifest_text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_CADENCE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "cadence"

{}

[[checks.severity]]
key = "example-pack.cadence_overdue"
default = "warning"

{}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"
"#,
            cadence_rule("cadence_field = \"cadence\"\nevent_verbs = [\"touch\"]\n"),
            cadence_messages()
        );
        let manifest = parse_manifest_external(&manifest_text).unwrap();
        // A vault whose person has no cadence field at all.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("people/p-01J9Z3K4QF0000000000000000")).unwrap();
        std::fs::write(
            dir.path()
                .join("people/p-01J9Z3K4QF0000000000000000/profile.md"),
            "---\nid: p-01J9Z3K4QF0000000000000000\ntype: person\nname: Ada Example\n---\n\nFake person.\n",
        )
        .unwrap();
        let vault = load_vault(dir.path()).unwrap();
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert!(out.is_empty(), "no cadence → skipped: {out:?}");
    }
}

#[cfg(test)]
mod note_kind_tests {
    use super::tests::{as_of, empty_merges};
    use super::*;
    use crate::load_vault;
    use crate::packs::dir::read_pack_dir;
    use crate::packs::external::{load_external_packs, PackProblem, PackProblemKind};
    use crate::packs::lock::Lockfile;
    use crate::packs::manifest::{parse_manifest, parse_manifest_external};
    use crate::packs::registry::PackRegistry;

    const ADA: &str = "p-01M3TC5H00MPJG000000000000";
    const BEA: &str = "p-01M3TC5H00MPJG000H24000001";
    const NOTE: &str = "n-01M3TC5H00MPJG002NAM000005";
    const GHOST: &str = "n-01M3TC5H00MPJG000H24000000";

    /// A vault with two people, one note owned by Ada, and four `touch`
    /// lines exercising the valid/unknown/wrong-type/other-owner cases.
    fn note_fixture_vault() -> Vault {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
        )
        .unwrap();
        for id in [ADA, BEA] {
            std::fs::create_dir_all(dir.path().join(format!("people/{id}/notes"))).unwrap();
            std::fs::write(
                dir.path().join(format!("people/{id}/profile.md")),
                format!("---\nid: {id}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
            )
            .unwrap();
        }
        std::fs::write(
            dir.path().join(format!("people/{ADA}/notes/{NOTE}.md")),
            format!(
                "---\nid: {NOTE}\ntype: note\nperson: {ADA}\ndate: 2026-10-01\n---\n\nFake note.\n"
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!(
                "2026-10-01 touch {ADA} call note:{NOTE}\n2026-10-02 touch {ADA} call note:{GHOST}\n2026-10-03 touch {ADA} call note:{BEA}\n2026-10-04 touch {ADA} call note:not-an-id\n"
            ),
        )
        .unwrap();
        load_vault(dir.path()).unwrap()
    }

    /// A v1 manifest may claim core codes (the compiled packs do), so the
    /// builtin-code path the built-in personal pack uses is testable here.
    fn builtin_manifest() -> PackManifest {
        let text = r#"manifest_version = 1
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "E_INVALID_ID", "E_WRONG_ID_TYPE", "E_UNKNOWN_RECORD"]

[pack]
name = "note-pack"
version = "0.1"
skill = "SKILL.md"

[[rules]]
id = "touch_note"
kind = "note-ref"
code = "E_UNKNOWN_RECORD"
verb = "touch"
pair = "note"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."E_INVALID_ID"]
default = "touch note is not a record ID"
default_fix = "Point note: at an existing n-<ULID> note"

[messages."E_WRONG_ID_TYPE"]
default = "touch note '{id}' is not a note id"
default_fix = "Use note:n-<ULID>"

[messages."E_UNKNOWN_RECORD"]
missing = "touch note '{id}' does not exist"
missing_fix = "Point note: at an existing n-<ULID> note"
wrong_owner = "touch note '{id}' does not belong to {person}"
wrong_owner_fix = "Point note: at a note for this person"
"#;
        parse_manifest(text).expect("v1 fixture manifest should parse")
    }

    /// A v2 external-style manifest with pack-own codes and coaching's
    /// variant names (`variants = "session"`).
    fn session_manifest() -> PackManifest {
        let text = r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "E_NOTE_BAD_ID", "E_NOTE_BAD_TYPE", "E_NOTE_UNKNOWN"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[rules]]
id = "session_note"
kind = "note-ref"
code = "E_NOTE_UNKNOWN"
verb = "touch"
pair = "note"
variants = "session"
invalid_code = "E_NOTE_BAD_ID"
wrong_type_code = "E_NOTE_BAD_TYPE"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."E_NOTE_BAD_ID"]
session_note = "session note is not a record ID"
session_note_fix = "Point note: at an existing n-<ULID> note"

[messages."E_NOTE_BAD_TYPE"]
session_note = "session note '{nid}' is not a note id"
session_note_fix = "Use note:n-<ULID>"

[messages."E_NOTE_UNKNOWN"]
missing = "session note '{nid}' does not exist"
missing_fix = "Point note: at an existing n-<ULID> note"
wrong_owner = "session note '{nid}' does not belong to {person}"
wrong_owner_fix = "Point note: at a note for this person"
"#;
        parse_manifest_external(text).expect("v2 fixture manifest should parse")
    }

    /// The codes of the `run` findings, in order.
    fn codes_of(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.code.as_str()).collect()
    }

    #[test]
    fn note_ref_builtin_codes_and_personal_variants() {
        let manifest = builtin_manifest();
        let vault = note_fixture_vault();
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert_eq!(
            codes_of(&out),
            vec!["E_UNKNOWN_RECORD", "E_WRONG_ID_TYPE", "E_INVALID_ID"],
            "the valid note is silent; the other three report in ledger order: {out:?}"
        );
        // Severity is fixed at error; the message tables name either
        // {id} or {nid}, and both are supplied.
        assert!(out.iter().all(|f| f.severity == Severity::Error));
        assert_eq!(
            out[0].message,
            format!("touch note '{GHOST}' does not exist")
        );
        assert_eq!(
            out[1].message,
            format!("touch note '{BEA}' is not a note id")
        );
        assert_eq!(out[2].message, "touch note is not a record ID");
        // file/line/id carry the ledger line and the canonical person.
        assert_eq!(out[0].id.as_deref(), Some(ADA));
        assert_eq!(out[0].file.as_deref(), Some("ledger/2026/10.cfd"));
        assert_eq!(out[0].line, Some(2));
        assert_eq!(out[2].line, Some(4));
    }

    #[test]
    fn note_ref_session_variants_and_pack_own_codes() {
        let manifest = session_manifest();
        let vault = note_fixture_vault();
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert_eq!(
            codes_of(&out),
            vec!["E_NOTE_UNKNOWN", "E_NOTE_BAD_TYPE", "E_NOTE_BAD_ID"],
            "{out:?}"
        );
        // Coaching's variant names and {nid} placeholder render.
        assert_eq!(
            out[0].message,
            format!("session note '{GHOST}' does not exist")
        );
        assert_eq!(
            out[1].message,
            format!("session note '{BEA}' is not a note id")
        );
        assert_eq!(out[2].message, "session note is not a record ID");
    }

    #[test]
    fn note_ref_note_of_other_person_is_wrong_owner() {
        let manifest = builtin_manifest();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
        )
        .unwrap();
        for id in [ADA, BEA] {
            std::fs::create_dir_all(dir.path().join(format!("people/{id}/notes"))).unwrap();
            std::fs::write(
                dir.path().join(format!("people/{id}/profile.md")),
                format!("---\nid: {id}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
            )
            .unwrap();
        }
        std::fs::write(
            dir.path().join(format!("people/{BEA}/notes/{NOTE}.md")),
            format!(
                "---\nid: {NOTE}\ntype: note\nperson: {BEA}\ndate: 2026-10-01\n---\n\nFake note.\n"
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!("2026-10-01 touch {ADA} call note:{NOTE}\n"),
        )
        .unwrap();
        let vault = load_vault(dir.path()).unwrap();
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert_eq!(codes_of(&out), vec!["E_UNKNOWN_RECORD"], "{out:?}");
        assert_eq!(
            out[0].message,
            format!("touch note '{NOTE}' does not belong to {ADA}")
        );
    }

    #[test]
    fn note_ref_entry_without_pair_ignored() {
        let manifest = builtin_manifest();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join(format!("people/{ADA}"))).unwrap();
        std::fs::write(
            dir.path().join(format!("people/{ADA}/profile.md")),
            format!("---\nid: {ADA}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!("2026-10-01 touch {ADA} call\n"),
        )
        .unwrap();
        let vault = load_vault(dir.path()).unwrap();
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert!(out.is_empty(), "no pair: nothing to check: {out:?}");
    }

    /// Vendor a pack with the given `[[rules]]` body and return the
    /// loader's problems. The manifest declares pack-own codes for all
    /// three note-ref roles (an external pack cannot claim the core codes)
    /// and a `severity_key` the tests can opt into.
    fn load_with_note_rule(rules: &str, wrong_owner_fix: bool) -> Vec<PackProblem> {
        let dir = tempfile::tempdir().unwrap();
        let wrong_owner_fix_line = if wrong_owner_fix {
            "wrong_owner_fix = \"Point note: at a note for this person\"\n"
        } else {
            ""
        };
        let text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "E_NOTE_UNKNOWN", "E_NOTE_BAD_ID", "E_NOTE_BAD_TYPE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.severity]]
key = "example-pack.note"
default = "warning"

{rules}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

[messages."E_NOTE_UNKNOWN"]
missing = "note '{{nid}}' does not exist"
missing_fix = "Point note: at an existing n-<ULID> note"
wrong_owner = "note '{{nid}}' does not belong to {{person}}"
{wrong_owner_fix_line}

[messages."E_NOTE_BAD_ID"]
default = "note is not a record ID"
default_fix = "Point note: at an existing n-<ULID> note"

[messages."E_NOTE_BAD_TYPE"]
default = "note '{{nid}}' is not a note id"
default_fix = "Use note:n-<ULID>"
"#
        );
        let pack_dir = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("manifest.toml"), text).unwrap();
        std::fs::write(pack_dir.join("SKILL.md"), "# example pack.\n").unwrap();
        let hash = read_pack_dir(&pack_dir)
            .map(|p| p.hash)
            .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
        let mut lock = Lockfile::default();
        lock.upsert(crate::packs::lock::LockEntry {
            name: "example-pack".to_owned(),
            version: "0.1".to_owned(),
            source: "https://example.invalid/org/example-pack.git".to_owned(),
            rev: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            subdir: String::new(),
            hash,
        });
        std::fs::write(dir.path().join("confidant.lock"), lock.to_toml()).unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["example-pack@0.1".to_owned()],
            &compiled,
        );
        load.problems
    }

    /// A note-ref rule with the given extra parameters. The default
    /// `invalid_code`/`wrong_type_code` are the core codes, so callers
    /// that want a loadable external pack pass a `params` with pack-own
    /// codes; leaving them out is itself a loader case.
    fn note_rule(params: &str) -> String {
        format!(
            "[[rules]]\nid = \"touch_note\"\nkind = \"note-ref\"\ncode = \"E_NOTE_UNKNOWN\"\n{params}"
        )
    }

    fn pack_own_code_params() -> &'static str {
        "verb = \"touch\"\npair = \"note\"\ninvalid_code = \"E_NOTE_BAD_ID\"\nwrong_type_code = \"E_NOTE_BAD_TYPE\"\n"
    }

    fn assert_loader_refuses(problems: &[PackProblem], detail_snippet: &str) {
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            matches!(problems[0].kind, PackProblemKind::Invalid),
            "{problems:?}"
        );
        assert!(
            problems[0].detail.contains(detail_snippet),
            "detail missing {detail_snippet:?}: {}",
            problems[0].detail
        );
    }

    #[test]
    fn loader_accepts_valid_note_rule() {
        let problems = load_with_note_rule(&note_rule(pack_own_code_params()), true);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn loader_refuses_empty_verb() {
        let problems = load_with_note_rule(
            &note_rule(
                "verb = \"\"\npair = \"note\"\ninvalid_code = \"E_NOTE_BAD_ID\"\nwrong_type_code = \"E_NOTE_BAD_TYPE\"\n",
            ),
            true,
        );
        assert_loader_refuses(&problems, "verb must be a non-empty string");
    }

    #[test]
    fn loader_refuses_missing_wrong_owner_fix() {
        let problems = load_with_note_rule(&note_rule(pack_own_code_params()), false);
        assert_loader_refuses(&problems, "has no 'wrong_owner_fix' variant");
    }

    /// Leaving the two optional codes at their core defaults makes an
    /// external pack (which cannot claim a core code) fail closed on the
    /// builtin-code guard rather than emit a core code it never declared.
    #[test]
    fn loader_refuses_core_default_codes_for_external_pack() {
        let problems = load_with_note_rule(&note_rule("verb = \"touch\"\npair = \"note\"\n"), true);
        assert_loader_refuses(
            &problems,
            "emits builtin code 'E_INVALID_ID'; a rule's invalid_code must be a pack-own code",
        );
    }

    /// The #494 bypass this guard closes: `E_FRONTMATTER` is the one
    /// builtin a pack may claim, and every pack with fields already has
    /// its message table, so without the guard an external pack could set
    /// `invalid_code = "E_FRONTMATTER"` and emit a re-worded core code.
    #[test]
    fn loader_refuses_builtin_invalid_code_for_external_pack() {
        let problems = load_with_note_rule(
            &note_rule(
                "verb = \"touch\"\npair = \"note\"\ninvalid_code = \"E_FRONTMATTER\"\nwrong_type_code = \"E_NOTE_BAD_TYPE\"\n",
            ),
            true,
        );
        assert_loader_refuses(
            &problems,
            "emits builtin code 'E_FRONTMATTER'; a rule's invalid_code must be a pack-own code",
        );
    }

    /// The same guard covers `wrong_type_code` (the invalid_code here is
    /// pack-own, so the loop reaches the second parameter).
    #[test]
    fn loader_refuses_builtin_wrong_type_code_for_external_pack() {
        let problems = load_with_note_rule(
            &note_rule(
                "verb = \"touch\"\npair = \"note\"\ninvalid_code = \"E_NOTE_BAD_ID\"\nwrong_type_code = \"E_FRONTMATTER\"\n",
            ),
            true,
        );
        assert_loader_refuses(
            &problems,
            "emits builtin code 'E_FRONTMATTER'; a rule's wrong_type_code must be a pack-own code",
        );
    }

    /// A present-but-non-string code parameter is refused (like
    /// `variants`), never silently replaced with the core default.
    #[test]
    fn loader_refuses_non_string_invalid_code() {
        let problems = load_with_note_rule(
            &note_rule(
                "verb = \"touch\"\npair = \"note\"\ninvalid_code = 1\nwrong_type_code = \"E_NOTE_BAD_TYPE\"\n",
            ),
            true,
        );
        assert_loader_refuses(&problems, "invalid_code must be a string");
    }

    #[test]
    fn loader_refuses_non_string_wrong_type_code() {
        let problems = load_with_note_rule(
            &note_rule(
                "verb = \"touch\"\npair = \"note\"\ninvalid_code = \"E_NOTE_BAD_ID\"\nwrong_type_code = 1\n",
            ),
            true,
        );
        assert_loader_refuses(&problems, "wrong_type_code must be a string");
    }

    #[test]
    fn loader_refuses_undeclared_invalid_code() {
        let problems = load_with_note_rule(
            &note_rule(
                "verb = \"touch\"\npair = \"note\"\ninvalid_code = \"E_NOTE_NOPE\"\nwrong_type_code = \"E_NOTE_BAD_TYPE\"\n",
            ),
            true,
        );
        assert_loader_refuses(
            &problems,
            "invalid_code 'E_NOTE_NOPE' is not in the pack's finding_codes",
        );
    }

    #[test]
    fn loader_refuses_severity_key_on_fixed_severity_kind() {
        let problems = load_with_note_rule(
            &note_rule(&format!(
                "{}\nseverity_key = \"example-pack.note\"\n",
                pack_own_code_params()
            )),
            true,
        );
        assert_loader_refuses(&problems, "has a fixed severity");
    }

    #[test]
    fn loader_refuses_unknown_variants_value() {
        let problems = load_with_note_rule(
            &note_rule(&format!(
                "{}\nvariants = \"weird\"\n",
                pack_own_code_params()
            )),
            true,
        );
        assert_loader_refuses(&problems, "is not one of");
    }
}

#[cfg(test)]
mod date_kind_tests {
    use super::tests::{as_of, empty_merges};
    use super::*;
    use crate::load_vault;
    use crate::packs::dir::read_pack_dir;
    use crate::packs::external::{load_external_packs, PackProblem, PackProblemKind};
    use crate::packs::lock::Lockfile;
    use crate::packs::manifest::parse_manifest_external;
    use crate::packs::registry::PackRegistry;

    /// Vendor a pack whose date rule has the given manifest body and
    /// `[[fields]]` entries, and return the loader's problems.
    fn load_with_date_rule(fields: &str, rules: &str, messages: &str) -> Vec<PackProblem> {
        let dir = tempfile::tempdir().unwrap();
        let text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_DATE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

{fields}

{rules}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

{messages}
"#
        );
        let pack_dir = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("manifest.toml"), text).unwrap();
        std::fs::write(pack_dir.join("SKILL.md"), "# example pack.\n").unwrap();
        let hash = read_pack_dir(&pack_dir)
            .map(|p| p.hash)
            .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
        let mut lock = Lockfile::default();
        lock.upsert(crate::packs::lock::LockEntry {
            name: "example-pack".to_owned(),
            version: "0.1".to_owned(),
            source: "https://example.invalid/org/example-pack.git".to_owned(),
            rev: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            subdir: String::new(),
            hash,
        });
        std::fs::write(dir.path().join("confidant.lock"), lock.to_toml()).unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["example-pack@0.1".to_owned()],
            &compiled,
        );
        load.problems
    }

    fn severity_entry() -> String {
        "[[checks.severity]]\nkey = \"example-pack.date_upcoming\"\ndefault = \"warning\"\n"
            .to_owned()
    }

    fn int_entry() -> String {
        "[[checks.int]]\nkey = \"example-pack.date_upcoming_days\"\ndefault = 7\n".to_owned()
    }

    fn date_messages() -> String {
        r#"[messages."W_EXAMPLE_DATE"]
default = "upcoming date for {id} on {occ} (in {delta}d)"
default_fix = "Reach out to {id} or set `[checks] personal.date_upcoming = \"off\"`""#
            .to_owned()
    }

    fn assert_loader_refuses(problems: &[PackProblem], detail_snippet: &str) {
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            matches!(problems[0].kind, PackProblemKind::Invalid),
            "{problems:?}"
        );
        assert!(
            problems[0].detail.contains(detail_snippet),
            "detail missing {detail_snippet:?}: {}",
            problems[0].detail
        );
    }

    fn valid_fields() -> &'static str {
        "[[fields]]\nname = \"birthday\"\ngrammar = \"recurring-date\"\n\n[[fields]]\nname = \"dates\"\ngrammar = \"dates-list\"\n"
    }

    fn date_rule(params: &str) -> String {
        format!(
            "[[rules]]\nid = \"dates\"\nkind = \"date-upcoming\"\ncode = \"W_EXAMPLE_DATE\"\nseverity_key = \"example-pack.date_upcoming\"\n{params}"
        )
    }

    fn valid_params() -> &'static str {
        "date_fields = [\"birthday\", \"dates\"]\nwindow_key = \"example-pack.date_upcoming_days\"\n"
    }

    #[test]
    fn loader_accepts_valid_date_rule() {
        let problems = load_with_date_rule(
            valid_fields(),
            &format!("{}\n{}", date_rule(valid_params()), severity_entry()),
            &format!("{}\n{}", int_entry(), date_messages()),
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn loader_refuses_undeclared_date_field() {
        let problems = load_with_date_rule(
            valid_fields(),
            &format!(
                "{}\n{}",
                date_rule(
                    "date_fields = [\"ghost\"]\nwindow_key = \"example-pack.date_upcoming_days\"\n"
                ),
                severity_entry()
            ),
            &format!("{}\n{}", int_entry(), date_messages()),
        );
        assert_loader_refuses(&problems, "is not one of the pack's declared fields");
    }

    #[test]
    fn loader_refuses_date_field_with_wrong_grammar() {
        // The pack declares `birthday` with grammar "cadence": not usable
        // as a date field.
        let problems = load_with_date_rule(
            "[[fields]]\nname = \"birthday\"\ngrammar = \"cadence\"\n",
            &format!("{}\n{}", date_rule(valid_params()), severity_entry()),
            &format!("{}\n{}", int_entry(), date_messages()),
        );
        assert_loader_refuses(&problems, "has grammar 'cadence'");
    }

    #[test]
    fn loader_refuses_missing_window_key() {
        let problems = load_with_date_rule(
            valid_fields(),
            &format!(
                "{}\n{}",
                date_rule(
                    "date_fields = [\"birthday\", \"dates\"]\nwindow_key = \"example-pack.nope\"\n"
                ),
                severity_entry()
            ),
            &format!("{}\n{}", int_entry(), date_messages()),
        );
        assert_loader_refuses(&problems, "is not a declared [[checks.int]] key");
    }

    #[test]
    fn loader_refuses_missing_default_fix_variant() {
        let messages = date_messages().replace(
            "default_fix = \"Reach out to {id} or set `[checks] personal.date_upcoming = \\\"off\\\"`\"",
            "",
        );
        let problems = load_with_date_rule(
            valid_fields(),
            &format!("{}\n{}", date_rule(valid_params()), severity_entry()),
            &format!("{}\n{}", int_entry(), messages),
        );
        assert_loader_refuses(&problems, "has no 'default_fix' variant");
    }

    /// #443: a person with no date fields at all is skipped.
    #[test]
    fn date_rule_no_dates_skipped() {
        let manifest_text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_EXAMPLE_DATE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

{fields}

{rules}

{severity}

{ints}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

{messages}
"#,
            fields = valid_fields(),
            rules = date_rule(valid_params()),
            severity = severity_entry(),
            ints = int_entry(),
            messages = date_messages(),
        );
        let manifest = parse_manifest_external(&manifest_text).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("people/p-01J9Z3K4QF0000000000000000")).unwrap();
        std::fs::write(
            dir.path()
                .join("people/p-01J9Z3K4QF0000000000000000/profile.md"),
            "---\nid: p-01J9Z3K4QF0000000000000000\ntype: person\nname: Ada Example\n---\n\nFake person.\n",
        )
        .unwrap();
        let vault = load_vault(dir.path()).unwrap();
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert!(out.is_empty(), "no dates → skipped: {out:?}");
    }
}
