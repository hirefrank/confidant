//! `session-checks` (#447): the per-entry checks coaching runs on its
//! consuming verb — duration present, exactly one billing tag, the
//! untagged warning, and "session has no notes".
//!
//! Reproduces `coaching@0.1`'s `apply_session` checks,
//! `session_without_notes` and `note_coverage`, including merge-aware
//! person grouping. Only ledger metadata and note ids / paths / dates are
//! read; note bodies are never opened (PD8). The `note:` id/type/
//! existence/ownership check is not reimplemented here: a pack uses the
//! `note-ref` kind (#458) for that.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{duration_of, Finding, FindingCode, Severity};
use crate::error::DomainError;
use crate::id::{person_id_from_path, Prefix, RecordId};
use crate::ledger::parse_strict_date;
use crate::packs::declarative::{
    resolve_declared_severity, resolve_finding_code, RuleCtx, RuleKind,
};
use crate::packs::manifest::{PackManifest, RuleDecl};
use crate::packs::rules::ledger::billing_tag_count;
use crate::record::RecordKind;
use crate::vault::Vault;

const KIND: &str = "session-checks";

const DEFAULT_TAGS_CODE: &str = "E_SESSION_TAGS";
const DEFAULT_UNTAGGED_CODE: &str = "W_SESSION_UNTAGGED";
const DEFAULT_NOTES_CODE: &str = "E_SESSION_WITHOUT_NOTES";

fn str_param<'a>(rule: &'a RuleDecl, name: &str, default: &'a str) -> Result<&'a str, DomainError> {
    match rule.params.get(name) {
        None => Ok(default),
        Some(value) => value.as_str().ok_or_else(|| {
            DomainError::config(format!("rule '{}': {name} must be a string", rule.id)).with_fix(
                format!("Omit {name}, or set it to a code the pack declares"),
            )
        }),
    }
}

/// The validated parameters of one `session-checks` rule.
#[derive(Clone, Debug)]
pub(crate) struct SessionParams<'a> {
    pub(crate) verb: &'a str,
    pub(crate) billing_tags: Vec<&'a str>,
    pub(crate) duration_key: &'a str,
    pub(crate) notes_key: &'a str,
    pub(crate) tags_code: &'a str,
    pub(crate) untagged_code: &'a str,
    pub(crate) notes_code: &'a str,
}

impl<'a> SessionParams<'a> {
    fn parse(rule: &'a RuleDecl) -> Option<Self> {
        Some(Self {
            verb: rule.params.get("verb")?.as_str()?,
            billing_tags: rule
                .params
                .get("billing_tags")?
                .as_array()?
                .iter()
                .map(|v| v.as_str())
                .collect::<Option<Vec<_>>>()?,
            duration_key: rule.params.get("severity_duration_key")?.as_str()?,
            notes_key: rule.params.get("severity_notes_key")?.as_str()?,
            tags_code: rule
                .params
                .get("tags_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_TAGS_CODE),
            untagged_code: rule
                .params
                .get("untagged_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_UNTAGGED_CODE),
            notes_code: rule
                .params
                .get("notes_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_NOTES_CODE),
        })
    }
}

/// `session-checks`: the named rule kind.
pub(crate) struct SessionChecksKind;

impl RuleKind for SessionChecksKind {
    fn name(&self) -> &'static str {
        KIND
    }

    /// The kind has no single severity: duration and notes each have
    /// their own declared key, and the tag findings are fixed. It always
    /// runs; `off` on a key suppresses only that key's findings.
    fn manages_severity(&self) -> bool {
        true
    }

    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
        let err = |detail: String| DomainError::config(format!("rule '{}': {detail}", rule.id));

        let Some(verb) = rule.params.get("verb").and_then(|v| v.as_str()) else {
            return Err(err(
                "the verb parameter is missing (it names the ledger verb to check)".to_owned(),
            )
            .with_fix("Set verb = \"session\""));
        };
        if verb.trim().is_empty() {
            return Err(
                err("verb must be a non-empty verb".to_owned()).with_fix("Set verb = \"session\"")
            );
        }
        if !manifest.verbs.iter().any(|v| v.name == verb) {
            return Err(err(format!(
                "verb '{verb}' is not one of the pack's declared verbs"
            ))
            .with_fix("Claim the verb in [[verbs]] or use its declared name"));
        }

        let Some(tags) = rule.params.get("billing_tags").and_then(|v| v.as_array()) else {
            return Err(err(
                "the billing_tags parameter is missing (it lists the billing tags)".to_owned(),
            )
            .with_fix("Set billing_tags = [\"paid\", \"pps\", \"comp\"]"));
        };
        if tags.is_empty() {
            return Err(err("billing_tags must not be empty".to_owned())
                .with_fix("Set billing_tags = [\"paid\", \"pps\", \"comp\"]"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for tag in tags {
            let Some(tag) = tag.as_str() else {
                return Err(err("every billing_tags entry must be a string".to_owned())
                    .with_fix("Set billing_tags = [\"paid\", \"pps\", \"comp\"]"));
            };
            if tag.trim().is_empty() {
                return Err(
                    err("every billing_tags entry must be a non-empty tag".to_owned())
                        .with_fix("Set billing_tags = [\"paid\", \"pps\", \"comp\"]"),
                );
            }
            if !seen.insert(tag) {
                return Err(err(format!("billing_tags lists '{tag}' more than once"))
                    .with_fix("List each billing tag at most once"));
            }
        }

        for (name, hint) in [
            (
                "severity_duration_key",
                "Set severity_duration_key to a declared [[checks.severity]] key",
            ),
            (
                "severity_notes_key",
                "Set severity_notes_key to a declared [[checks.severity]] key",
            ),
        ] {
            let Some(key) = rule.params.get(name).and_then(|v| v.as_str()) else {
                return Err(err(format!(
                    "the {name} parameter is missing (it names the finding's severity)"
                ))
                .with_fix(hint));
            };
            if !manifest.checks.severity.iter().any(|s| s.key == key) {
                return Err(err(format!(
                    "{name} '{key}' is not a declared [[checks.severity]] key"
                ))
                .with_fix(hint));
            }
        }

        let tags_code = str_param(rule, "tags_code", DEFAULT_TAGS_CODE)?;
        let untagged_code = str_param(rule, "untagged_code", DEFAULT_UNTAGGED_CODE)?;
        let notes_code = str_param(rule, "notes_code", DEFAULT_NOTES_CODE)?;

        // PD13/#494: an external pack cannot name a builtin code.
        if !manifest.may_emit_builtin_codes() {
            for (role, code) in [
                ("code", rule.code.as_str()),
                ("tags_code", tags_code),
                ("untagged_code", untagged_code),
                ("notes_code", notes_code),
            ] {
                if FindingCode::is_builtin_code(code) {
                    return Err(err(format!(
                        "a rule's {role} must be a pack-own code, not the builtin '{code}'"
                    ))
                    .with_fix(
                        "Declare a pack-own code (e.g. E_<PACK>_<RULE>) in finding_codes and use it",
                    ));
                }
            }
        }

        for (code, role) in [
            (rule.code.as_str(), "code"),
            (tags_code, "tags_code"),
            (untagged_code, "untagged_code"),
            (notes_code, "notes_code"),
        ] {
            if !FindingCode::is_builtin_code(code)
                && !manifest.finding_codes.iter().any(|c| c == code)
            {
                return Err(err(format!(
                    "{role} '{code}' is not in the pack's finding_codes"
                ))
                .with_fix("Add the code to finding_codes or use a declared code"));
            }
            for variant in ["default", "default_fix"] {
                if !manifest
                    .messages
                    .get(code)
                    .is_some_and(|m| m.contains_key(variant))
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
        let Some(params) = SessionParams::parse(rule) else {
            return; // the loader validated the params; unreachable
        };
        let duration_severity =
            resolve_declared_severity(ctx.vault, ctx.manifest, params.duration_key);
        let notes_severity = resolve_declared_severity(ctx.vault, ctx.manifest, params.notes_key);
        let Some(duration_code) = resolve_finding_code(&rule.code) else {
            return;
        };
        let Some(tags_code) = resolve_finding_code(params.tags_code) else {
            return;
        };
        let Some(untagged_code) = resolve_finding_code(params.untagged_code) else {
            return;
        };
        let Some(notes_code) = resolve_finding_code(params.notes_code) else {
            return;
        };

        // `session_without_notes` skips sessions dated after `as_of` and
        // canonicalizes on `as_of`; the fold-time checks run for every
        // session, exactly like the compiled fold.
        let coverage = notes_severity
            .is_some()
            .then(|| note_coverage(ctx.vault, ctx.merges, ctx.as_of));

        for sourced in &ctx.vault.entries {
            let entry = &sourced.entry;
            if entry.verb != params.verb {
                continue;
            }
            // The compiled fold applies its per-entry checks only to
            // person ids, but `session_without_notes` filters on the verb
            // alone: a session whose id is not a person id (core already
            // reports `E_WRONG_ID_TYPE`) still gets the notes check. Keep
            // the person filter on the duration and tag checks only.
            if entry.id.prefix() == Prefix::Person {
                if let (Some(severity), true) = (duration_severity, duration_of(entry).is_none()) {
                    out.push(
                        Finding::new(
                            duration_code,
                            severity,
                            ctx.manifest.render_message(
                                &rule.code,
                                "default",
                                &[("id", &entry.id)],
                            ),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&entry.id)
                        .with_fix(
                            ctx.manifest
                                .render_fix(&rule.code, "default", &[])
                                .unwrap_or_default(),
                        ),
                    );
                }
                let tag_count = billing_tag_count(entry, &params.billing_tags);
                if tag_count > 1 {
                    out.push(
                        Finding::new(
                            tags_code,
                            Severity::Error,
                            ctx.manifest.render_message(
                                params.tags_code,
                                "default",
                                &[("id", &entry.id)],
                            ),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&entry.id)
                        .with_fix(
                            ctx.manifest
                                .render_fix(params.tags_code, "default", &[])
                                .unwrap_or_default(),
                        ),
                    );
                }
                if tag_count == 0 {
                    out.push(
                        Finding::new(
                            untagged_code,
                            Severity::Warning,
                            ctx.manifest.render_message(
                                params.untagged_code,
                                "default",
                                &[("id", &entry.id)],
                            ),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&entry.id)
                        .with_fix(
                            ctx.manifest
                                .render_fix(params.untagged_code, "default", &[])
                                .unwrap_or_default(),
                        ),
                    );
                }
            }
            let Some(severity) = notes_severity else {
                continue;
            };
            if entry.date > ctx.as_of || entry.pair("note").is_some() {
                continue;
            }
            let person = ctx.merges.canonical_on(&entry.id, ctx.as_of);
            let covered = coverage.as_ref().is_some_and(|map| {
                map.get(&person)
                    .is_some_and(|dates| dates.contains(&entry.date))
            });
            if covered {
                continue;
            }
            out.push(
                Finding::new(
                    notes_code,
                    severity,
                    ctx.manifest.render_message(
                        params.notes_code,
                        "default",
                        &[("date", &entry.date), ("person", &person)],
                    ),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(
                    ctx.manifest
                        .render_fix(params.notes_code, "default", &[])
                        .unwrap_or_default(),
                ),
            );
        }
    }
}

pub(crate) static SESSION_CHECKS: SessionChecksKind = SessionChecksKind;

/// The canonical person → note dates map `coaching@0.1` builds: each note
/// record's `date` and `session` front-matter fields, owned by its
/// `person:` field or its path. Only dates are read, never note bodies.
fn note_coverage(
    vault: &Vault,
    merges: &crate::packs::groups::MergeGroups,
    as_of: NaiveDate,
) -> HashMap<RecordId, HashSet<NaiveDate>> {
    let mut map: HashMap<RecordId, HashSet<NaiveDate>> = HashMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Note {
            continue;
        }
        let Some(person) = rec.person().or_else(|| person_id_from_path(&rec.path)) else {
            continue;
        };
        let person = merges.canonical_on(&person, as_of);
        let mut dates = HashSet::new();
        if let Some(d) = rec.field("date").and_then(parse_strict_date) {
            dates.insert(d);
        }
        if let Some(d) = rec.field("session").and_then(parse_strict_date) {
            dates.insert(d);
        }
        if dates.is_empty() {
            continue;
        }
        map.entry(person).or_default().extend(dates);
    }
    map
}
