//! Coaching schema pack 0.1: sessions, packages, ICF hours, gap rules.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use chrono::NaiveDate;

use crate::check::{duration_of, Finding, FindingCode, MergeMap, Severity};
use crate::id::{Prefix, RecordId};
use crate::ledger::{parse_decimal_hundredths, parse_strict_date, Arg};
use crate::packs::manifest::{parse_manifest, PackManifest};
use crate::packs::rules::ledger::{
    billing_tag_count, fold as fold_ledger, format_hundredths, FoldParams, LedgerFacts,
    LedgerIssue, BILLING_TAGS, DEFAULT_MAX_OPEN_N,
};
use crate::packs::{EdgeKind, Pack, PackState};
use crate::record::RecordKind;
use crate::vault::{SourcedEntry, Vault};

/// The compiled pack's state is the shared ledger facts, so the compiled
/// behaviours and the `ledger-balance` rule kind cannot drift apart
/// (#446).
type CoachingState = LedgerFacts;

/// Embedded manifest for `coaching@0.1` (spec §9). Vendored from
/// `packs/coaching/manifest.toml` at the repo root: the path must stay
/// inside the crate so `cargo publish` / `cargo install` can compile
/// (crates.io tarballs do not include `../../packs`). A test fails if the
/// vendored copy drifts from the repo-root file. The binary serves the
/// manifest it was compiled with, same guarantee as the embedded SKILL.md.
static COACHING_MANIFEST_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/coaching/manifest.toml"
));

/// Claims from the embedded manifest, leaked to `&'static` so the `Pack`
/// trait's `&'static` signatures can serve them (#344). Parsed once; a
/// parse failure is a programming error (the file is compile-time data),
/// so it fails loudly rather than silently falling back to stale claims.
/// The owned [`PackManifest`] is kept for message rendering (spec §7:
/// text in the manifest, selection in Rust).
pub(crate) struct ManifestClaims {
    pub(crate) manifest: PackManifest,
    name: &'static str,
    verbs: Vec<&'static str>,
    verb_id_types: Vec<(&'static str, Prefix)>,
    record_types: Vec<&'static str>,
    fields: Vec<&'static str>,
    balance_metrics: Vec<&'static str>,
    edge_kinds: Vec<EdgeKind>,
    finding_codes: Vec<&'static str>,
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

pub(crate) fn manifest_claims() -> &'static ManifestClaims {
    static CLAIMS: OnceLock<ManifestClaims> = OnceLock::new();
    CLAIMS.get_or_init(|| {
        let m = parse_manifest(COACHING_MANIFEST_TOML)
            .expect("embedded packs/coaching/manifest.toml must parse");
        let name = leak_str(format!("{}@{}", m.pack.name, m.pack.version));
        let verbs: Vec<&'static str> = m.verbs.iter().map(|v| leak_str(v.name.clone())).collect();
        let verb_id_types: Vec<(&'static str, Prefix)> = m
            .verbs
            .iter()
            .filter_map(|v| v.id_type.map(|p| (leak_str(v.name.clone()), p)))
            .collect();
        let record_types: Vec<&'static str> =
            m.record_types.iter().map(|r| leak_str(r.clone())).collect();
        let fields: Vec<&'static str> = m.fields.iter().map(|f| leak_str(f.name.clone())).collect();
        let balance_metrics: Vec<&'static str> = m
            .balance_metrics
            .iter()
            .map(|b| leak_str(b.clone()))
            .collect();
        let edge_kinds: Vec<EdgeKind> = m
            .edge_kinds
            .iter()
            .map(|e| EdgeKind {
                name: leak_str(e.name.clone()),
                symmetric: e.symmetric,
            })
            .collect();
        let finding_codes: Vec<&'static str> = m
            .finding_codes
            .iter()
            .map(|c| leak_str(c.clone()))
            .collect();
        ManifestClaims {
            manifest: m,
            name,
            verbs,
            verb_id_types,
            record_types,
            fields,
            balance_metrics,
            edge_kinds,
            finding_codes,
        }
    })
}

/// Render a finding message from the manifest (spec §7: text in the
/// manifest, selection in Rust). Panics on a missing code/variant or an
/// unsupplied placeholder — the manifest is compile-time data.
fn render_msg(code: &str, variant: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    manifest_claims()
        .manifest
        .render_message(code, variant, args)
}

/// Render the finding's fix text from the manifest, or `None` when the
/// manifest declares no `<variant>_fix` for this variant.
fn render_fix(
    code: &str,
    variant: &str,
    args: &[(&str, &dyn std::fmt::Display)],
) -> Option<String> {
    manifest_claims().manifest.render_fix(code, variant, args)
}

/// The compiled coaching pack. Registered in [`crate::packs::ALL_PACKS`].
pub struct CoachingPack;

// The context-view types moved to the core `context::ledger_sessions`
// module (#594): both the compiled pack and a `[context]` declarative pack
// serve one builder and one shape. Re-exported here so the public paths
// `packs::coaching::{CoachingView, RecentSession}` keep resolving until the
// #449 cutover deletes this module.
pub use crate::context::ledger_sessions::{LedgerSessionsView as CoachingView, RecentSession};

impl Pack for CoachingPack {
    fn name(&self) -> &'static str {
        manifest_claims().name
    }

    fn verbs(&self) -> &'static [&'static str] {
        &manifest_claims().verbs
    }

    fn record_types(&self) -> &'static [&'static str] {
        &manifest_claims().record_types
    }

    fn fields(&self) -> &'static [&'static str] {
        &manifest_claims().fields
    }

    fn balance_metrics(&self) -> &'static [&'static str] {
        &manifest_claims().balance_metrics
    }

    fn edge_kinds(&self) -> &'static [EdgeKind] {
        // coaching@0.1 introduces no edge kinds; the manifest declares
        // none, so this serves the manifest's (empty) list explicitly
        // rather than relying on the trait default.
        &manifest_claims().edge_kinds
    }

    fn finding_codes(&self) -> &'static [&'static str] {
        // Step 6 (#345): served from the manifest. The parity test pins
        // the codes verbatim so a bad manifest fails loudly.
        &manifest_claims().finding_codes
    }

    fn verb_id_type(&self, verb: &str) -> Option<Prefix> {
        manifest_claims()
            .verb_id_types
            .iter()
            .find(|(v, _)| *v == verb)
            .map(|(_, p)| *p)
    }

    fn fold(
        &self,
        vault: &Vault,
        merges: &MergeMap,
        as_of: NaiveDate,
        findings: &mut Vec<Finding>,
    ) -> Box<dyn PackState> {
        Box::new(fold(vault, merges.clone(), as_of, findings))
    }

    fn findings(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        as_of: NaiveDate,
        findings: &mut Vec<Finding>,
    ) {
        let state = state
            .as_any()
            .downcast_ref::<CoachingState>()
            .expect("CoachingPack state");
        session_note_integrity(vault, state, findings);
        gap_rules(vault, state, as_of, findings);
    }

    fn check_balance(
        &self,
        _vault: &Vault,
        state: &dyn PackState,
        sourced: &SourcedEntry,
        findings: &mut Vec<Finding>,
    ) {
        let state = state
            .as_any()
            .downcast_ref::<CoachingState>()
            .expect("CoachingPack state");
        check_balance(state, sourced, findings);
    }

    fn context_view(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        _person: &RecordId,
        canonical: &RecordId,
        as_of: NaiveDate,
    ) -> Option<serde_json::Value> {
        let state = state
            .as_any()
            .downcast_ref::<CoachingState>()
            .expect("CoachingPack state");
        // #594: one builder serves the compiled pack and a `[context]`
        // declarative pack. The compiled pack's verbs are fixed (`open`
        // adds, `session` consumes) and it keeps the default recent cap.
        crate::context::ledger_sessions::build_ledger_sessions_view(
            vault,
            canonical,
            as_of,
            state,
            "session",
            crate::context::ledger_sessions::DEFAULT_RECENT_LIMIT,
        )
    }

    /// #594: the compiled pack serves the core `ledger-sessions` view; with
    /// its base name `coaching`, `context` recognizes its `packs` entry as
    /// the legacy `coaching` alias without hardcoding `"coaching@0.1"`.
    fn context_view_kind(&self) -> Option<&'static str> {
        Some(crate::context::ledger_sessions::LEDGER_SESSIONS_VIEW)
    }
}

/// Verify one `balance` line for a coaching metric. The caller guarantees
/// the metric is one this pack claims. Messages match the pre-`Pack`-trait
/// `check_balances` behavior exactly.
fn check_balance(state: &CoachingState, sourced: &SourcedEntry, findings: &mut Vec<Finding>) {
    let e = &sourced.entry;
    let metric = e.args.first().and_then(Arg::as_token).unwrap_or("");
    let number = e.args.get(1).and_then(Arg::as_token);
    let Some(number) = number else {
        findings.push(
            Finding::new(
                FindingCode::Parse,
                Severity::Error,
                render_msg("E_PARSE", "missing_number", &[]),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&e.id),
        );
        return;
    };
    let person = state.canonical_on(&e.id, e.date);
    if metric == "sessions_remaining" {
        let asserted: i64 = match number.parse() {
            Ok(n) => n,
            Err(_) => {
                findings.push(
                    Finding::new(
                        FindingCode::Parse,
                        Severity::Error,
                        render_msg("E_PARSE", "expected_integer", &[]),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&e.id)
                    .with_fix(render_msg(
                        "E_PARSE",
                        "expected_integer_fix",
                        &[],
                    )),
                );
                return;
            }
        };
        let computed = state.sessions_remaining_on(&person, e.date);
        if asserted != computed {
            findings.push(
                Finding::new(
                    FindingCode::BalanceMismatch,
                    Severity::Error,
                    render_msg(
                        "E_BALANCE_MISMATCH",
                        "sessions_remaining",
                        &[("asserted", &asserted), ("computed", &computed)],
                    ),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(render_msg(
                    "E_BALANCE_MISMATCH",
                    "sessions_remaining_fix",
                    &[("person", &person)],
                )),
            );
        }
    } else if metric == "icf_hours" {
        let Some(asserted) = parse_decimal_hundredths(number) else {
            findings.push(
                Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    render_msg("E_PARSE", "expected_decimal", &[]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&e.id)
                .with_fix(render_msg("E_PARSE", "expected_decimal_fix", &[])),
            );
            return;
        };
        let computed = state.icf_hours_hundredths_on(&person, e.date);
        if asserted != computed {
            findings.push(
                Finding::new(
                    FindingCode::BalanceMismatch,
                    Severity::Error,
                    render_msg(
                        "E_BALANCE_MISMATCH",
                        "icf_hours",
                        &[
                            ("asserted", &format_hundredths(asserted)),
                            ("computed", &format_hundredths(computed)),
                        ],
                    ),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(render_msg(
                    "E_BALANCE_MISMATCH",
                    "icf_hours_fix",
                    &[("person", &person)],
                )),
            );
        }
    }
}

fn fold(
    vault: &Vault,
    parent: MergeMap,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) -> CoachingState {
    let folded = fold_ledger(
        vault,
        &crate::packs::groups::MergeGroups::new(parent),
        FoldParams {
            open_verb: "open",
            consume_verb: "session",
            max_open_n: DEFAULT_MAX_OPEN_N,
        },
    );

    // Compile the fold's open issues into the compiled manifest's messages.
    for (sourced, issue) in folded.issues {
        let file = sourced.file.as_str();
        let line = sourced.line;
        let id = &sourced.entry.id;
        let finding = match issue {
            LedgerIssue::OpenShape => Finding::new(
                FindingCode::OpenMalformed,
                Severity::Error,
                render_msg("E_OPEN_MALFORMED", "shape", &[]),
            )
            .at_file(file)
            .at_line(line)
            .for_id(id)
            .with_fix(render_msg("E_OPEN_MALFORMED", "shape_fix", &[])),
            LedgerIssue::OpenInvalidPackageId => Finding::new(
                FindingCode::InvalidId,
                Severity::Error,
                render_msg("E_INVALID_ID", "package", &[]),
            )
            .at_file(file)
            .at_line(line)
            .for_id(id)
            .with_fix(render_msg("E_INVALID_ID", "package_fix", &[])),
            LedgerIssue::OpenNotInteger => Finding::new(
                FindingCode::OpenMalformed,
                Severity::Error,
                render_msg("E_OPEN_MALFORMED", "not_integer", &[]),
            )
            .at_file(file)
            .at_line(line)
            .for_id(id)
            .with_fix(render_msg("E_OPEN_MALFORMED", "not_integer_fix", &[])),
            LedgerIssue::OpenWrongPackageType(pkg) => Finding::new(
                FindingCode::WrongIdType,
                Severity::Error,
                render_msg("E_WRONG_ID_TYPE", "package", &[("pkg", &pkg)]),
            )
            .at_file(file)
            .at_line(line)
            .for_id(id),
            LedgerIssue::OpenExceedsCap(n) => Finding::new(
                FindingCode::OpenMalformed,
                Severity::Error,
                render_msg(
                    "E_OPEN_MALFORMED",
                    "exceeds_cap",
                    &[("n", &n), ("cap", &DEFAULT_MAX_OPEN_N)],
                ),
            )
            .at_file(file)
            .at_line(line)
            .for_id(id)
            .with_fix(render_msg(
                "E_OPEN_MALFORMED",
                "exceeds_cap_fix",
                &[("cap", &DEFAULT_MAX_OPEN_N)],
            )),
            LedgerIssue::OpenTotalOverflow => {
                let mut f = Finding::new(
                    FindingCode::OpenMalformed,
                    Severity::Error,
                    render_msg("E_OPEN_MALFORMED", "total_overflow", &[("id", id)]),
                )
                .at_file(file)
                .at_line(line)
                .for_id(id);
                if let Some(fx) = render_fix("E_OPEN_MALFORMED", "total_overflow", &[("id", id)]) {
                    f = f.with_fix(fx);
                }
                f
            }
            LedgerIssue::MinutesOverflow => {
                let mut f = Finding::new(
                    FindingCode::Parse,
                    Severity::Error,
                    render_msg("E_PARSE", "minutes_overflow", &[("id", id)]),
                )
                .at_file(file)
                .at_line(line)
                .for_id(id);
                if let Some(fx) = render_fix("E_PARSE", "minutes_overflow", &[("id", id)]) {
                    f = f.with_fix(fx);
                }
                f
            }
        };
        findings.push(finding);
    }

    // Session checks stay with the compiled fold (the `session-checks`
    // rule kind owns them for declarative packs, #447). The shared fold
    // records the events; the messages are the compiled manifest's.
    for sourced in &vault.entries {
        let entry = &sourced.entry;
        if entry.verb != "session" || entry.id.prefix() != Prefix::Person {
            continue;
        }
        if duration_of(entry).is_none() {
            findings.push(
                Finding::new(
                    FindingCode::MissingDuration,
                    Severity::Error,
                    render_msg("E_MISSING_DURATION", "default", &[("id", &entry.id)]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&entry.id)
                .with_fix(render_msg("E_MISSING_DURATION", "default_fix", &[])),
            );
        }
        let tag_count = billing_tag_count(entry, &BILLING_TAGS);
        if tag_count > 1 {
            findings.push(
                Finding::new(
                    FindingCode::SessionTags,
                    Severity::Error,
                    render_msg("E_SESSION_TAGS", "default", &[("id", &entry.id)]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&entry.id)
                .with_fix(render_msg("E_SESSION_TAGS", "default_fix", &[])),
            );
        }
        if tag_count == 0 {
            findings.push(
                Finding::new(
                    FindingCode::SessionUntagged,
                    Severity::Warning,
                    render_msg("W_SESSION_UNTAGGED", "default", &[("id", &entry.id)]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&entry.id)
                .with_fix(render_msg("W_SESSION_UNTAGGED", "default_fix", &[])),
            );
        }
    }

    let state = folded.facts;
    let nonnegative = vault
        .config
        .checks
        .severity("coaching.balance_nonnegative", Severity::Error);
    if let Some(sev) = nonnegative {
        for id in state.roots_on(as_of) {
            let remaining = state.sessions_remaining_on(&id, as_of);
            if remaining < 0 {
                findings.push(
                    Finding::new(
                        FindingCode::NegativeBalance,
                        sev,
                        render_msg(
                            "E_NEGATIVE_BALANCE",
                            "default",
                            &[("id", &id), ("remaining", &remaining)],
                        ),
                    )
                    .for_id(&id)
                    .with_fix(render_msg(
                        "E_NEGATIVE_BALANCE",
                        "default_fix",
                        &[],
                    )),
                );
            }
        }
    }
    state
}

fn gap_rules(vault: &Vault, state: &CoachingState, as_of: NaiveDate, findings: &mut Vec<Finding>) {
    apply_duration_off(vault, findings);
    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.require_duration", Severity::Error)
    {
        for finding in findings.iter_mut() {
            if finding.code == FindingCode::MissingDuration {
                finding.severity = sev;
            }
        }
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.session_notes", Severity::Warning)
    {
        session_without_notes(vault, state, as_of, sev, findings);
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("coaching.paid_session_gap", Severity::Warning)
    {
        let days = vault.config.checks.paid_session_gap_days();
        let lookback = vault.config.checks.pps_lookback_days();
        paid_session_gap(state, as_of, days, lookback, sev, findings);
    }
}

/// `note:` ID/type/existence/ownership. Always on; ignores `session_notes` and `as_of`.
fn session_note_integrity(vault: &Vault, state: &CoachingState, findings: &mut Vec<Finding>) {
    for sourced in &vault.entries {
        if sourced.entry.verb != "session" {
            continue;
        }
        let e = &sourced.entry;
        let person = state.canonical_on(&e.id, NaiveDate::MAX);
        let Some(note_id) = e.pair("note") else {
            continue;
        };
        match RecordId::parse(note_id) {
            Err(_) => findings.push(
                Finding::new(
                    FindingCode::InvalidId,
                    Severity::Error,
                    render_msg("E_INVALID_ID", "session_note", &[]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(render_msg("E_INVALID_ID", "session_note_fix", &[])),
            ),
            Ok(nid) if nid.prefix() != Prefix::Note => findings.push(
                Finding::new(
                    FindingCode::WrongIdType,
                    Severity::Error,
                    render_msg("E_WRONG_ID_TYPE", "session_note", &[("nid", &nid)]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(render_msg("E_WRONG_ID_TYPE", "session_note_fix", &[])),
            ),
            Ok(nid) => match vault.records.get(&nid) {
                None => findings.push(
                    Finding::new(
                        FindingCode::UnknownRecord,
                        Severity::Error,
                        render_msg("E_UNKNOWN_RECORD", "missing", &[("nid", &nid)]),
                    )
                    .at_file(&sourced.file)
                    .at_line(sourced.line)
                    .for_id(&person)
                    .with_fix(render_msg(
                        "E_UNKNOWN_RECORD",
                        "missing_fix",
                        &[],
                    )),
                ),
                Some(rec) => {
                    let note_person = rec
                        .person()
                        .or_else(|| person_from_path(&rec.path))
                        .map(|p| state.canonical_on(&p, NaiveDate::MAX));
                    if note_person.as_ref() != Some(&person) {
                        findings.push(
                            Finding::new(
                                FindingCode::UnknownRecord,
                                Severity::Error,
                                render_msg(
                                    "E_UNKNOWN_RECORD",
                                    "wrong_owner",
                                    &[("nid", &nid), ("person", &person)],
                                ),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&person)
                            .with_fix(render_msg(
                                "E_UNKNOWN_RECORD",
                                "wrong_owner_fix",
                                &[],
                            )),
                        );
                    }
                }
            },
        }
    }
}

fn session_without_notes(
    vault: &Vault,
    state: &CoachingState,
    as_of: NaiveDate,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let notes_by_person_date = note_coverage(vault, state, as_of);
    for sourced in &vault.entries {
        if sourced.entry.verb != "session" {
            continue;
        }
        let e = &sourced.entry;
        if e.date > as_of {
            continue;
        }
        let person = state.canonical_on(&e.id, as_of);
        if e.pair("note").is_some() {
            continue;
        }
        let covered = notes_by_person_date
            .get(&person)
            .is_some_and(|dates| dates.contains(&e.date));
        if covered {
            continue;
        }
        findings.push(
            Finding::new(
                FindingCode::SessionWithoutNotes,
                severity,
                render_msg(
                    "E_SESSION_WITHOUT_NOTES",
                    "default",
                    &[("date", &e.date), ("person", &person)],
                ),
            )
            .at_file(&sourced.file)
            .at_line(sourced.line)
            .for_id(&person)
            .with_fix(render_msg("E_SESSION_WITHOUT_NOTES", "default_fix", &[])),
        );
    }
}

fn note_coverage(
    vault: &Vault,
    state: &CoachingState,
    as_of: NaiveDate,
) -> HashMap<RecordId, HashSet<NaiveDate>> {
    let mut map: HashMap<RecordId, HashSet<NaiveDate>> = HashMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Note {
            continue;
        }
        let Some(person) = rec.person().or_else(|| person_from_path(&rec.path)) else {
            continue;
        };
        let person = state.canonical_on(&person, as_of);
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

fn person_from_path(path: &str) -> Option<RecordId> {
    crate::id::person_id_from_path(path)
}

fn paid_session_gap(
    state: &CoachingState,
    as_of: NaiveDate,
    days: u64,
    lookback: u64,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let days_i = i64::try_from(days).unwrap_or(i64::MAX);
    let lookback_i = i64::try_from(lookback).unwrap_or(i64::MAX);
    let window = chrono::Duration::days(days_i);
    let lookback_window = chrono::Duration::days(lookback_i);
    for id in state.roots_on(as_of) {
        let remaining = state.sessions_remaining_on(&id, as_of);
        let pps_client = state.pps_in_lookback(&id, as_of, lookback_window);
        if remaining <= 0 && !pps_client {
            continue;
        }
        let last_session = state.last_session_on(&id, as_of);
        let last_open = state.last_open_on(&id, as_of);
        let clock = match (last_session, last_open) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        if let Some(activity) = clock {
            if as_of.signed_duration_since(activity) <= window {
                continue;
            }
        }
        let last = last_session;
        let start = as_of - window;
        let (message, fix) = match (last, remaining > 0) {
            (None, _) => (
                render_msg("E_PAID_SESSION_GAP", "none", &[("id", &id)]),
                render_fix(
                    "E_PAID_SESSION_GAP",
                    "none",
                    &[("id", &id), ("days", &days)],
                )
                .expect("manifest declares none_fix"),
            ),
            (Some(d), true) => (
                render_msg(
                    "E_PAID_SESSION_GAP",
                    "remaining",
                    &[("id", &id), ("start", &start), ("d", &d)],
                ),
                render_fix("E_PAID_SESSION_GAP", "remaining", &[("days", &days)])
                    .expect("manifest declares remaining_fix"),
            ),
            (Some(d), false) => (
                render_msg(
                    "E_PAID_SESSION_GAP",
                    "no_remaining",
                    &[("id", &id), ("start", &start), ("d", &d)],
                ),
                render_fix("E_PAID_SESSION_GAP", "no_remaining", &[("days", &days)])
                    .expect("manifest declares no_remaining_fix"),
            ),
        };
        findings.push(
            Finding::new(FindingCode::PaidSessionGap, severity, message)
                .for_id(&id)
                .with_fix(fix),
        );
    }
}

/// Drop MissingDuration findings when the rule is off. Called from gap_rules
/// after fold pushed them as errors.
pub fn apply_duration_off(vault: &Vault, findings: &mut Vec<Finding>) {
    if vault
        .config
        .checks
        .severity("coaching.require_duration", Severity::Error)
        .is_none()
    {
        findings.retain(|f| f.code != FindingCode::MissingDuration);
    }
}

#[cfg(test)]
mod tests {
    use super::{CoachingPack, COACHING_MANIFEST_TOML};
    use crate::id::Prefix;
    use crate::packs::manifest::parse_manifest;
    use crate::packs::Pack;

    /// Parity test (#344): the manifest-derived claims must equal the
    /// `&'static` slices the trait served before the manifest existed.
    /// Expected values are copied verbatim from the deleted slices; this
    /// test pins the manifest to the original claims so a bad manifest
    /// fails loudly instead of silently changing behavior.
    #[test]
    fn manifest_claims_match_original_slices() {
        let pack = CoachingPack;
        assert_eq!(pack.name(), "coaching@0.1");
        assert_eq!(pack.verbs(), &["open", "session"][..]);
        assert!(pack.record_types().is_empty());
        assert!(pack.fields().is_empty());
        assert_eq!(
            pack.balance_metrics(),
            &["sessions_remaining", "icf_hours"][..]
        );
        assert!(pack.edge_kinds().is_empty());
        assert_eq!(pack.verb_id_type("open"), Some(Prefix::Person));
        assert_eq!(pack.verb_id_type("session"), Some(Prefix::Person));
        assert_eq!(pack.verb_id_type("touch"), None);
        assert_eq!(pack.verb_id_type(""), None);
    }

    /// The vendored manifest must match `packs/coaching/manifest.toml` at
    /// the repo root (#368 pattern). Skips gracefully when the repo-root
    /// file is absent (e.g. a published crate), where there is nothing to
    /// drift from.
    #[test]
    fn vendored_manifest_matches_repo_root() {
        let root = format!(
            "{}/../../packs/coaching/manifest.toml",
            env!("CARGO_MANIFEST_DIR")
        );
        let Ok(root_text) = std::fs::read_to_string(&root) else {
            return;
        };
        assert_eq!(
            root_text, COACHING_MANIFEST_TOML,
            "vendored manifest is stale; copy packs/coaching/manifest.toml \
             to crates/confidant-core/pack-manifests/coaching/manifest.toml"
        );
    }

    /// The manifest's finding codes must match the compiled
    /// `finding_codes()` slice, and its (empty) edge-kind list must match
    /// the trait. In step 6 (#345) `finding_codes()` serves the manifest,
    /// so the trait-vs-manifest comparison is circular; the verbatim list
    /// below pins the codes instead.
    #[test]
    fn manifest_finding_codes_and_edge_kinds_match_code() {
        let m = parse_manifest(COACHING_MANIFEST_TOML).expect("manifest parses");
        let from_trait: Vec<String> = CoachingPack
            .finding_codes()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(m.finding_codes, from_trait);
        assert_eq!(
            m.finding_codes,
            [
                "E_PARSE",
                "E_BALANCE_MISMATCH",
                "E_NEGATIVE_BALANCE",
                "E_OPEN_MALFORMED",
                "E_INVALID_ID",
                "E_WRONG_ID_TYPE",
                "E_MISSING_DURATION",
                "E_SESSION_TAGS",
                "W_SESSION_UNTAGGED",
                "E_UNKNOWN_RECORD",
                "E_SESSION_WITHOUT_NOTES",
                "E_PAID_SESSION_GAP",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
        );
        assert!(m.edge_kinds.is_empty());
        assert!(CoachingPack.edge_kinds().is_empty());
    }
}
