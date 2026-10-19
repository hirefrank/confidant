//! `ledger-balance` (#446): a per-person running count of opened units,
//! consumed by a ledger verb, verified against `balance` lines.
//!
//! Reproduces the compiled `coaching@0.1` behaviour for
//! `sessions_remaining` and `icf_hours`: the fold's merge-aware
//! accumulation, per-date ordering (opens before sessions), the
//! comp/pps consumption rules, the per-open cap and overflow checks, the
//! `pkg-` package rule, the negative-balance finding and the `balance`
//! line verification (including hundredths-of-an-hour formatting).
//!
//! The arithmetic lives in [`super::ledger`]; this module only resolves
//! parameters, validates them at load, and renders the pack's messages.

use crate::check::{Finding, FindingCode, Severity};
use crate::error::DomainError;
use crate::ledger::{parse_decimal_hundredths, Arg};
use crate::packs::declarative::{
    resolve_declared_severity, resolve_finding_code, RuleCtx, RuleKind,
};
use crate::packs::groups::MergeGroups;
use crate::packs::manifest::{PackManifest, RuleDecl};
use crate::packs::rules::ledger::{self, FoldParams, LedgerIssue};
use crate::vault::{SourcedEntry, Vault};

/// Core defaults for the codes the kind emits. A compiled-in pack keeps
/// them; an external pack sets pack-own codes (PD13: a rule's code must
/// be a pack-own code).
const DEFAULT_PARSE_CODE: &str = "E_PARSE";
const DEFAULT_NEGATIVE_CODE: &str = "E_NEGATIVE_BALANCE";
const DEFAULT_OPEN_MALFORMED_CODE: &str = "E_OPEN_MALFORMED";
const DEFAULT_INVALID_ID_CODE: &str = "E_INVALID_ID";
const DEFAULT_WRONG_ID_TYPE_CODE: &str = "E_WRONG_ID_TYPE";

const KIND: &str = "ledger-balance";

/// Read one string parameter, or the default when absent. A present but
/// non-string value is refused rather than silently defaulted.
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

/// The validated parameters of one `ledger-balance` rule.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BalanceParams<'a> {
    pub(crate) open_verb: &'a str,
    pub(crate) consume_verb: &'a str,
    pub(crate) units_metric: &'a str,
    pub(crate) minutes_metric: &'a str,
    pub(crate) max_open_n: i64,
    pub(crate) parse_code: &'a str,
    pub(crate) negative_code: &'a str,
    pub(crate) open_malformed_code: &'a str,
    pub(crate) invalid_code: &'a str,
    pub(crate) wrong_type_code: &'a str,
}

impl<'a> BalanceParams<'a> {
    /// Parse a rule that `validate` has already accepted. A missing or
    /// mistyped parameter here is a loader bug, so `None` means "do
    /// nothing" rather than guessing.
    fn parse(rule: &'a RuleDecl) -> Option<Self> {
        Some(Self {
            open_verb: rule.params.get("open_verb")?.as_str()?,
            consume_verb: rule.params.get("consume_verb")?.as_str()?,
            units_metric: rule.params.get("units_metric")?.as_str()?,
            minutes_metric: rule.params.get("minutes_metric")?.as_str()?,
            max_open_n: rule.params.get("max_open_n")?.as_integer()?,
            parse_code: rule
                .params
                .get("parse_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_PARSE_CODE),
            negative_code: rule
                .params
                .get("negative_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_NEGATIVE_CODE),
            open_malformed_code: rule
                .params
                .get("open_malformed_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_OPEN_MALFORMED_CODE),
            invalid_code: rule
                .params
                .get("invalid_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_INVALID_ID_CODE),
            wrong_type_code: rule
                .params
                .get("wrong_type_code")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_WRONG_ID_TYPE_CODE),
        })
    }

    fn fold_params(&self) -> FoldParams<'_> {
        FoldParams {
            open_verb: self.open_verb,
            consume_verb: self.consume_verb,
            max_open_n: self.max_open_n,
        }
    }

    /// Whether this rule owns `metric` (the `balance` line's metric).
    fn owns(&self, metric: &str) -> bool {
        metric == self.units_metric || metric == self.minutes_metric
    }
}

/// The rule in `manifest` whose `ledger-balance` parameters own `metric`.
/// The loader refuses a metric claimed by two balance rules, so the first
/// match is the only one.
pub(crate) fn rule_for_metric<'a>(
    manifest: &'a PackManifest,
    metric: &str,
) -> Option<(&'a RuleDecl, BalanceParams<'a>)> {
    manifest
        .rules
        .iter()
        .filter(|rule| rule.kind == KIND)
        .filter_map(|rule| BalanceParams::parse(rule).map(|params| (rule, params)))
        .find(|(_, params)| params.owns(metric))
}

/// `ledger-balance`: the named rule kind.
pub(crate) struct LedgerBalanceKind;

impl RuleKind for LedgerBalanceKind {
    fn name(&self) -> &'static str {
        KIND
    }

    /// The negative-balance severity is operator-tunable; the rest of the
    /// rule (open validation, balancing) always runs so a `balance` line
    /// cannot silently stop being verified. `severity_key` names the
    /// negative-balance key and does not gate the rule.
    fn manages_severity(&self) -> bool {
        true
    }

    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
        let err = |detail: String| DomainError::config(format!("rule '{}': {detail}", rule.id));

        for (name, hint) in [
            ("open_verb", "Set open_verb = \"open\""),
            ("consume_verb", "Set consume_verb = \"session\""),
        ] {
            let Some(value) = rule.params.get(name).and_then(|v| v.as_str()) else {
                return Err(err(format!(
                    "the {name} parameter is missing (it names the ledger verb to fold)"
                ))
                .with_fix(hint));
            };
            if value.trim().is_empty() {
                return Err(err(format!("{name} must be a non-empty verb")).with_fix(hint));
            }
        }
        let open_verb = rule.params["open_verb"].as_str().expect("checked above");
        let consume_verb = rule.params["consume_verb"].as_str().expect("checked above");
        if open_verb == consume_verb {
            return Err(err(
                "open_verb and consume_verb are the same verb; the fold cannot order them"
                    .to_owned(),
            )
            .with_fix(
                "Use distinct verbs, e.g. open_verb = \"open\" and consume_verb = \"session\"",
            ));
        }

        let mut metrics = Vec::new();
        for (name, what) in [
            ("units_metric", "the unit count"),
            ("minutes_metric", "the session minutes"),
        ] {
            let Some(metric) = rule.params.get(name).and_then(|v| v.as_str()) else {
                return Err(err(format!(
                    "the {name} parameter is missing (it names the balance metric for {what})"
                ))
                .with_fix("Set it to an entry declared in balance_metrics"));
            };
            if metric.trim().is_empty() {
                return Err(err(format!("{name} must be a non-empty metric"))
                    .with_fix("Set it to an entry declared in balance_metrics"));
            }
            if !manifest.balance_metrics.iter().any(|m| m == metric) {
                return Err(err(format!(
                    "{name} '{metric}' is not one of the pack's declared balance_metrics"
                ))
                .with_fix("Declare the metric in balance_metrics or use its declared name"));
            }
            metrics.push(metric);
        }
        if metrics[0] == metrics[1] {
            return Err(
                err("units_metric and minutes_metric are the same metric".to_owned())
                    .with_fix("Use one integer metric for units and one decimal metric for hours"),
            );
        }
        for metric in &metrics {
            for other in manifest
                .rules
                .iter()
                .filter(|r| r.id != rule.id && r.kind == KIND)
            {
                let Some(params) = BalanceParams::parse(other) else {
                    continue;
                };
                if params.owns(metric) {
                    return Err(err(format!(
                        "metric '{metric}' is already verified by ledger-balance rule '{}'",
                        other.id
                    ))
                    .with_fix("Let one ledger-balance rule own each metric"));
                }
            }
        }

        let Some(max_open_n) = rule.params.get("max_open_n").and_then(|v| v.as_integer()) else {
            return Err(err(
                "the max_open_n parameter is missing (it caps one open line)".to_owned(),
            )
            .with_fix("Set max_open_n to a positive integer, e.g. 100000"));
        };
        if max_open_n <= 0 {
            return Err(
                err(format!("max_open_n must be positive, got {max_open_n}"))
                    .with_fix("Set max_open_n to a positive integer, e.g. 100000"),
            );
        }

        let Some(severity_key) = rule.severity_key.as_deref() else {
            return Err(err(
                "a ledger-balance rule needs severity_key for the negative-balance finding"
                    .to_owned(),
            )
            .with_fix("Set severity_key to a declared [[checks.severity]] key"));
        };
        if !manifest
            .checks
            .severity
            .iter()
            .any(|s| s.key == severity_key)
        {
            return Err(err(format!(
                "severity_key '{severity_key}' is not a declared [[checks.severity]] key"
            ))
            .with_fix("Declare the key in [[checks.severity]] or use its declared key"));
        }

        let parse_code = str_param(rule, "parse_code", DEFAULT_PARSE_CODE)?;
        let negative_code = str_param(rule, "negative_code", DEFAULT_NEGATIVE_CODE)?;
        let open_malformed_code =
            str_param(rule, "open_malformed_code", DEFAULT_OPEN_MALFORMED_CODE)?;
        let invalid_code = str_param(rule, "invalid_code", DEFAULT_INVALID_ID_CODE)?;
        let wrong_type_code = str_param(rule, "wrong_type_code", DEFAULT_WRONG_ID_TYPE_CODE)?;

        // PD13/#494: an external pack cannot name a builtin code; a
        // compiled-in pack (or the v1 compiled path) keeps the defaults.
        if !manifest.may_emit_builtin_codes() {
            for (role, code) in [
                ("code", rule.code.as_str()),
                ("parse_code", parse_code),
                ("negative_code", negative_code),
                ("open_malformed_code", open_malformed_code),
                ("invalid_code", invalid_code),
                ("wrong_type_code", wrong_type_code),
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

        let units_metric = metrics[0];
        let minutes_metric = metrics[1];
        let units_fix = format!("{units_metric}_fix");
        let minutes_fix = format!("{minutes_metric}_fix");
        // (code, role, variants the evaluator renders)
        let required: Vec<(&str, &str, Vec<&str>)> = vec![
            (
                rule.code.as_str(),
                "code",
                vec![units_metric, &units_fix, minutes_metric, &minutes_fix],
            ),
            (
                parse_code,
                "parse_code",
                vec![
                    "missing_number",
                    "expected_integer",
                    "expected_integer_fix",
                    "expected_decimal",
                    "expected_decimal_fix",
                    "minutes_overflow",
                ],
            ),
            (
                negative_code,
                "negative_code",
                vec!["default", "default_fix"],
            ),
            (
                open_malformed_code,
                "open_malformed_code",
                vec![
                    "shape",
                    "shape_fix",
                    "not_integer",
                    "not_integer_fix",
                    "exceeds_cap",
                    "exceeds_cap_fix",
                    "total_overflow",
                ],
            ),
            (invalid_code, "invalid_code", vec!["package", "package_fix"]),
            (wrong_type_code, "wrong_type_code", vec!["package"]),
        ];
        for (code, role, variants) in required {
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
        let Some(params) = BalanceParams::parse(rule) else {
            return; // the loader validated the params; unreachable
        };
        let folded = ledger::fold(ctx.vault, ctx.merges, params.fold_params());
        for (sourced, issue) in &folded.issues {
            if let Some(finding) = render_issue(ctx.manifest, &params, sourced, issue) {
                out.push(finding);
            }
        }

        // Negative balance: the operator's `severity_key` severity, or no
        // finding at all when the key is off. The rule itself always runs.
        let Some(severity) = rule
            .severity_key
            .as_deref()
            .and_then(|key| resolve_declared_severity(ctx.vault, ctx.manifest, key))
        else {
            return;
        };
        let facts = &folded.facts;
        for id in facts.roots_on(ctx.as_of) {
            let remaining = facts.sessions_remaining_on(&id, ctx.as_of);
            if remaining < 0 {
                out.push(
                    Finding::new(
                        resolve_code(params.negative_code),
                        severity,
                        ctx.manifest.render_message(
                            params.negative_code,
                            "default",
                            &[("id", &id), ("remaining", &remaining)],
                        ),
                    )
                    .for_id(&id)
                    .with_fix(
                        ctx.manifest
                            .render_fix(params.negative_code, "default", &[])
                            .unwrap_or_default(),
                    ),
                );
            }
        }
    }
}

pub(crate) static LEDGER_BALANCE: LedgerBalanceKind = LedgerBalanceKind;

/// Resolve a validated code string to its `FindingCode`. The loader
/// accepted it, so an impossible value stays silent.
fn resolve_code(code: &str) -> FindingCode {
    resolve_finding_code(code).unwrap_or(FindingCode::Parse)
}

/// Render one fold problem with the rule's codes and messages.
fn render_issue(
    manifest: &PackManifest,
    params: &BalanceParams<'_>,
    sourced: &SourcedEntry,
    issue: &LedgerIssue,
) -> Option<Finding> {
    let entry = &sourced.entry;
    let base = |code: &str, variant: &str, args: &[(&str, &dyn std::fmt::Display)]| {
        Finding::new(
            resolve_code(code),
            Severity::Error,
            manifest.render_message(code, variant, args),
        )
        .at_file(&sourced.file)
        .at_line(sourced.line)
        .for_id(&entry.id)
    };
    let with_fix = |mut finding: Finding,
                    code: &str,
                    variant: &str,
                    args: &[(&str, &dyn std::fmt::Display)]| {
        if let Some(fix) = manifest.render_fix(code, variant, args) {
            finding = finding.with_fix(fix);
        }
        finding
    };
    Some(match issue {
        LedgerIssue::OpenShape => with_fix(
            base(params.open_malformed_code, "shape", &[]),
            params.open_malformed_code,
            "shape",
            &[],
        ),
        LedgerIssue::OpenInvalidPackageId => with_fix(
            base(params.invalid_code, "package", &[]),
            params.invalid_code,
            "package",
            &[],
        ),
        LedgerIssue::OpenNotInteger => with_fix(
            base(params.open_malformed_code, "not_integer", &[]),
            params.open_malformed_code,
            "not_integer",
            &[],
        ),
        LedgerIssue::OpenWrongPackageType(pkg) => {
            // The compiled check emits no fix for this problem.
            base(params.wrong_type_code, "package", &[("pkg", pkg)])
        }
        LedgerIssue::OpenExceedsCap(n) => with_fix(
            base(
                params.open_malformed_code,
                "exceeds_cap",
                &[("n", n), ("cap", &params.max_open_n)],
            ),
            params.open_malformed_code,
            "exceeds_cap",
            &[("cap", &params.max_open_n)],
        ),
        LedgerIssue::OpenTotalOverflow => with_fix(
            base(
                params.open_malformed_code,
                "total_overflow",
                &[("id", &entry.id)],
            ),
            params.open_malformed_code,
            "total_overflow",
            &[("id", &entry.id)],
        ),
        LedgerIssue::MinutesOverflow => with_fix(
            base(params.parse_code, "minutes_overflow", &[("id", &entry.id)]),
            params.parse_code,
            "minutes_overflow",
            &[("id", &entry.id)],
        ),
    })
}

/// Verify one `balance` line whose metric a `ledger-balance` rule owns.
/// Called by `ManifestPack::check_balance` through core's
/// `check_balances`; reproduces the compiled messages exactly.
pub(crate) fn check_balance(
    manifest: &PackManifest,
    vault: &Vault,
    merges: &MergeGroups,
    sourced: &SourcedEntry,
    findings: &mut Vec<Finding>,
) {
    let entry = &sourced.entry;
    let metric = entry.args.first().and_then(Arg::as_token).unwrap_or("");
    let Some((rule, params)) = rule_for_metric(manifest, metric) else {
        return;
    };
    let Some(number) = entry.args.get(1).and_then(Arg::as_token) else {
        findings.push(
            Finding::new(
                resolve_code(params.parse_code),
                Severity::Error,
                manifest.render_message(params.parse_code, "missing_number", &[]),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&entry.id),
        );
        return;
    };
    let folded = ledger::fold(vault, merges, params.fold_params());
    let person = folded.facts.canonical_on(&entry.id, entry.date);

    let (asserted, computed, mismatch) = if metric == params.units_metric {
        let asserted: i64 = match number.parse() {
            Ok(n) => n,
            Err(_) => {
                let mut finding = Finding::new(
                    resolve_code(params.parse_code),
                    Severity::Error,
                    manifest.render_message(params.parse_code, "expected_integer", &[]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&entry.id);
                if let Some(fix) = manifest.render_fix(params.parse_code, "expected_integer", &[]) {
                    finding = finding.with_fix(fix);
                }
                findings.push(finding);
                return;
            }
        };
        let computed = folded.facts.sessions_remaining_on(&person, entry.date);
        (
            asserted.to_string(),
            computed.to_string(),
            asserted != computed,
        )
    } else {
        let Some(asserted) = parse_decimal_hundredths(number) else {
            let mut finding = Finding::new(
                resolve_code(params.parse_code),
                Severity::Error,
                manifest.render_message(params.parse_code, "expected_decimal", &[]),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&entry.id);
            if let Some(fix) = manifest.render_fix(params.parse_code, "expected_decimal", &[]) {
                finding = finding.with_fix(fix);
            }
            findings.push(finding);
            return;
        };
        let computed = folded.facts.icf_hours_hundredths_on(&person, entry.date);
        (
            ledger::format_hundredths(asserted),
            ledger::format_hundredths(computed),
            asserted != computed,
        )
    };

    if !mismatch {
        return;
    }
    let mut finding = Finding::new(
        resolve_code(&rule.code),
        Severity::Error,
        manifest.render_message(
            &rule.code,
            metric,
            &[("asserted", &asserted), ("computed", &computed)],
        ),
    )
    .at_file(&sourced.file)
    .at_line(sourced.line)
    .for_id(&person);
    if let Some(fix) = manifest.render_fix(&rule.code, metric, &[("person", &person)]) {
        finding = finding.with_fix(fix);
    }
    findings.push(finding);
}
