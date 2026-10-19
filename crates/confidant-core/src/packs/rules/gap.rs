//! `activity-gap` (#448): a paid client with no session lately.
//!
//! Reproduces `coaching@0.1`'s `paid_session_gap`: the gap clock is the
//! later of the client's last consuming entry and their latest opener, the
//! window edge is inclusive, a client with no remaining units and no
//! pay-per-session history is not a paid client at all, and a spent
//! package does not warn once it no longer counts as paid.
//!
//! The per-person arithmetic (remaining units, the `pps` lookback) is
//! [`super::ledger`]'s, driven by the `ledger-balance` rule that owns
//! `balance_metric`; this module only resolves parameters and renders
//! messages.

use chrono::NaiveDate;

use crate::check::Finding;
use crate::error::DomainError;
use crate::packs::declarative::{resolve_finding_code, resolve_int_check, RuleCtx, RuleKind};
use crate::packs::manifest::{PackManifest, RuleDecl};
use crate::packs::rules::balance;
use crate::packs::rules::ledger;

const KIND: &str = "activity-gap";

/// The validated parameters of one `activity-gap` rule.
#[derive(Clone, Copy, Debug)]
struct GapParams<'a> {
    activity_verb: &'a str,
    start_verb: &'a str,
    gap_days_key: &'a str,
    lookback_days_key: &'a str,
    balance_metric: &'a str,
}

impl<'a> GapParams<'a> {
    fn parse(rule: &'a RuleDecl) -> Option<Self> {
        Some(Self {
            activity_verb: rule.params.get("activity_verb")?.as_str()?,
            start_verb: rule.params.get("start_verb")?.as_str()?,
            gap_days_key: rule.params.get("gap_days_key")?.as_str()?,
            lookback_days_key: rule.params.get("lookback_days_key")?.as_str()?,
            balance_metric: rule.params.get("balance_metric")?.as_str()?,
        })
    }
}

/// `activity-gap`: the named rule kind.
pub(crate) struct ActivityGapKind;

impl RuleKind for ActivityGapKind {
    fn name(&self) -> &'static str {
        KIND
    }

    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
        let err = |detail: String| DomainError::config(format!("rule '{}': {detail}", rule.id));

        for (name, hint) in [
            ("activity_verb", "Set activity_verb = \"session\""),
            ("start_verb", "Set start_verb = \"open\""),
        ] {
            let Some(value) = rule.params.get(name).and_then(|v| v.as_str()) else {
                return Err(err(format!(
                    "the {name} parameter is missing (it names the ledger verb for the gap clock)"
                ))
                .with_fix(hint));
            };
            if value.trim().is_empty() {
                return Err(err(format!("{name} must be a non-empty verb")).with_fix(hint));
            }
        }

        for (name, hint) in [
            (
                "gap_days_key",
                "Set gap_days_key to a declared [[checks.int]] key",
            ),
            (
                "lookback_days_key",
                "Set lookback_days_key to a declared [[checks.int]] key",
            ),
        ] {
            let Some(key) = rule.params.get(name).and_then(|v| v.as_str()) else {
                return Err(err(format!(
                    "the {name} parameter is missing (it names the pack's window check)"
                ))
                .with_fix(hint));
            };
            if !manifest.checks.int.iter().any(|i| i.key == key) {
                return Err(err(format!(
                    "{name} '{key}' is not a declared [[checks.int]] key"
                ))
                .with_fix(hint));
            }
        }

        let Some(metric) = rule.params.get("balance_metric").and_then(|v| v.as_str()) else {
            return Err(err(
                "the balance_metric parameter is missing (it names the unit metric to count)"
                    .to_owned(),
            )
            .with_fix("Set balance_metric to a metric a ledger-balance rule owns"));
        };
        if !manifest.balance_metrics.iter().any(|m| m == metric) {
            return Err(err(format!(
                "balance_metric '{metric}' is not one of the pack's declared balance_metrics"
            ))
            .with_fix("Declare the metric in balance_metrics or use its declared name"));
        }
        let owns_units = balance::rule_for_metric(manifest, metric)
            .is_some_and(|(_, params)| params.units_metric == metric);
        if !owns_units {
            return Err(err(format!(
                "balance_metric '{metric}' is not the units_metric of a ledger-balance rule"
            ))
            .with_fix(
                "Add a ledger-balance rule whose units_metric is this metric, or use that metric",
            ));
        }

        if !manifest
            .messages
            .get(&rule.code)
            .is_some_and(|m| m.contains_key("none"))
        {
            return Err(err(format!(
                "the manifest's [messages.{}] table has no 'none' variant",
                rule.code
            ))
            .with_fix("Add the variant template (see spec/pack-manifest.md)"));
        }
        for variant in ["none_fix", "remaining_fix", "no_remaining_fix"] {
            if !manifest
                .messages
                .get(&rule.code)
                .is_some_and(|m| m.contains_key(variant))
            {
                return Err(err(format!(
                    "the manifest's [messages.{}] table has no '{variant}' variant",
                    rule.code
                ))
                .with_fix("Add the fix template (see spec/pack-manifest.md)"));
            }
        }
        for variant in ["remaining", "no_remaining"] {
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
        }
        Ok(())
    }

    fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>) {
        let Some(params) = GapParams::parse(rule) else {
            return; // the loader validated the params; unreachable
        };
        let Some((_, balance_params)) =
            balance::rule_for_metric(ctx.manifest, params.balance_metric)
        else {
            return; // validation required one
        };
        let Some(code) = resolve_finding_code(&rule.code) else {
            return;
        };
        let days = resolve_int_check(ctx, params.gap_days_key);
        let lookback = resolve_int_check(ctx, params.lookback_days_key);
        let days_i = i64::try_from(days).unwrap_or(i64::MAX);
        let lookback_i = i64::try_from(lookback).unwrap_or(i64::MAX);
        let window = chrono::Duration::days(days_i);
        let lookback_window = chrono::Duration::days(lookback_i);

        let folded = ledger::fold(ctx.vault, ctx.merges, balance_params.fold_params());
        let facts = &folded.facts;

        for id in facts.roots_on(ctx.as_of) {
            let remaining = facts.sessions_remaining_on(&id, ctx.as_of);
            let pps_client = facts.pps_in_lookback(&id, ctx.as_of, lookback_window);
            if remaining <= 0 && !pps_client {
                continue;
            }
            // The gap clock uses the activity and start verbs. When they
            // are the balance rule's own verbs (the coaching case, #449),
            // use the shared fold's already-proven helpers; only a pack
            // that sets different verbs needs the vault scan, which walks
            // the canonical person's merge group.
            let members = (params.activity_verb != balance_params.consume_verb
                || params.start_verb != balance_params.open_verb)
                .then(|| facts.group_members(&id, ctx.as_of));
            let scan = |verb: &str| -> Option<NaiveDate> {
                let members = members.as_deref().unwrap_or(&[]);
                ctx.vault
                    .entries
                    .iter()
                    .filter(|s| s.entry.verb == verb)
                    .filter(|s| s.entry.date <= ctx.as_of && members.contains(&s.entry.id))
                    .map(|s| s.entry.date)
                    .max()
            };
            let last_session = if params.activity_verb == balance_params.consume_verb {
                facts.last_session_on(&id, ctx.as_of)
            } else {
                scan(params.activity_verb)
            };
            let last_open = if params.start_verb == balance_params.open_verb {
                facts.last_open_on(&id, ctx.as_of)
            } else {
                scan(params.start_verb)
            };
            let clock = match (last_session, last_open) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            if let Some(activity) = clock {
                if ctx.as_of.signed_duration_since(activity) <= window {
                    continue;
                }
            }
            let start = ctx.as_of - window;
            let (message, fix) = match (last_session, remaining > 0) {
                (None, _) => (
                    ctx.manifest
                        .render_message(&rule.code, "none", &[("id", &id)]),
                    ctx.manifest
                        .render_fix(&rule.code, "none", &[("id", &id), ("days", &days)])
                        .unwrap_or_default(),
                ),
                (Some(d), true) => (
                    ctx.manifest.render_message(
                        &rule.code,
                        "remaining",
                        &[("id", &id), ("start", &start), ("d", &d)],
                    ),
                    ctx.manifest
                        .render_fix(&rule.code, "remaining", &[("days", &days)])
                        .unwrap_or_default(),
                ),
                (Some(d), false) => (
                    ctx.manifest.render_message(
                        &rule.code,
                        "no_remaining",
                        &[("id", &id), ("start", &start), ("d", &d)],
                    ),
                    ctx.manifest
                        .render_fix(&rule.code, "no_remaining", &[("days", &days)])
                        .unwrap_or_default(),
                ),
            };
            out.push(
                Finding::new(code, ctx.severity, message)
                    .for_id(&id)
                    .with_fix(fix),
            );
        }
    }
}

pub(crate) static ACTIVITY_GAP: ActivityGapKind = ActivityGapKind;
