//! Personal relationships schema pack 0.1 (#184, #182): birthdays, important
//! dates, relationship edge kinds, keep-in-touch cadence, and the `touch`
//! ledger verb.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::check::{Finding, FindingCode, MergeMap, Severity};
use crate::id::{Prefix, RecordId};
use crate::ledger::{parse_strict_date, Arg, LedgerEntry};
use crate::packs::grammars::{
    parse_field_grammar, FieldValue, RecurringDate, GRAMMAR_CADENCE, GRAMMAR_DATES_LIST,
    GRAMMAR_NON_EMPTY_STRING, GRAMMAR_RECURRING_DATE,
};
use crate::packs::manifest::{parse_manifest, PackManifest};
use crate::packs::{EdgeKind, Pack, PackState};
use crate::record::{parse_with_list, Record, RecordKind};
use crate::search::cleared_record_ids;
use crate::vault::{SourcedEntry, Vault};

/// Closed list of touchpoint kinds for `touch` (#182, #227 Q1).
pub const TOUCH_KINDS: &[&str] = &["call", "text", "coffee", "gift", "meet"];

/// Embedded manifest for `personal@0.1` (spec §9). Vendored from
/// `packs/personal/manifest.toml` at the repo root: the path must stay
/// inside the crate so `cargo publish` / `cargo install` can compile
/// (crates.io tarballs do not include `../../packs`). A test fails if the
/// vendored copy drifts from the repo-root file. The binary serves the
/// manifest it was compiled with, same guarantee as the embedded SKILL.md.
static PERSONAL_MANIFEST_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal/manifest.toml"
));

/// Claims from the embedded manifest, leaked to `&'static` so the `Pack`
/// trait's `&'static` signatures can serve them (#343). Parsed once; a
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
        let m = parse_manifest(PERSONAL_MANIFEST_TOML)
            .expect("embedded packs/personal/manifest.toml must parse");
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

fn is_valid_touch_kind(kind: &str) -> bool {
    TOUCH_KINDS.contains(&kind)
}

/// Extract the touchpoint kind from either a positional `KIND` token
/// (`2026-10-12 touch p-… call`) or a `kind:KIND` pair (`2026-10-12 touch p-… kind:call`).
/// Pack-internal; core reaches it through [`Pack::verb_kind`] (#185/#296).
fn extract_touch_kind(entry: &LedgerEntry) -> Option<String> {
    if let Some(k) = entry.pair("kind") {
        return Some(k.to_owned());
    }
    if let Some(tok) = entry.args.first().and_then(Arg::as_token) {
        if is_valid_touch_kind(tok) {
            return Some(tok.to_owned());
        }
    }
    None
}

/// Validate a `touch` line's arguments when `personal@0.1` is enabled.
/// Accepts either:
/// - `DATE touch P-ID` (mirrored touchpoint with no kind)
/// - `DATE touch P-ID kind:<call|text|coffee|gift|meet>` (mirrored touchpoint with kind)
/// - `DATE touch P-ID <call|text|coffee|gift|meet> [note:N-ID] [src:…]` (`log touch` syntax)
///
/// Pack-internal; core reaches it through [`Pack::validate_verb_args`]
/// (#185/#296). On non-mirrored inputs this agrees with the shape core
/// used to ask `is_personal_touch_shape` about, so the disabled-pack
/// branch of `check` can use it as the pack-shape check behind
/// `W_PACK_ORPHAN`.
fn validate_touch_args_enabled(args: &[Arg]) -> bool {
    match args {
        [] => true,
        [arg] => match arg.pair() {
            Some(("kind", k)) => is_valid_touch_kind(k),
            None => arg.as_token().is_some_and(is_valid_touch_kind),
            _ => false,
        },
        _ => parse_personal_touch_args(args).is_some(),
    }
}

fn parse_personal_touch_args(args: &[Arg]) -> Option<&str> {
    let first = args.first()?.as_token()?;
    if !is_valid_touch_kind(first) {
        return None;
    }
    let mut seen_note = false;
    let mut seen_src = false;
    for arg in &args[1..] {
        match arg.pair() {
            Some(("note", _)) if !seen_note => seen_note = true,
            Some(("src", _)) if !seen_src => seen_src = true,
            _ => return None,
        }
    }
    Some(first)
}

#[derive(Clone, Debug)]
struct TouchEvent {
    date: NaiveDate,
}

#[derive(Clone, Debug, Default)]
struct PersonPersonal {
    touches: Vec<TouchEvent>,
    cadence_days: Option<u32>,
    birthday: Option<RecurringDate>,
    relationship_to_me: Option<String>,
    dates: Vec<RecurringDate>,
}

impl PersonPersonal {
    fn last_touch_on(&self, on: NaiveDate) -> Option<NaiveDate> {
        self.touches
            .iter()
            .map(|t| t.date)
            .filter(|d| *d <= on)
            .max()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PersonalState {
    merge: crate::packs::groups::MergeGroups,
    people: HashMap<RecordId, PersonPersonal>,
}

impl PackState for PersonalState {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PersonalState {
    pub fn canonical_on(&self, id: &RecordId, on: NaiveDate) -> RecordId {
        self.merge.canonical_on(id, on)
    }

    fn ensure_members(&self, on: NaiveDate) {
        self.merge.ensure_members(self.people.keys().cloned(), on);
    }

    fn group_people<'a>(
        &'a self,
        groups: &'a HashMap<RecordId, Vec<RecordId>>,
        root: &RecordId,
    ) -> impl Iterator<Item = &'a PersonPersonal> {
        groups
            .get(root)
            .into_iter()
            .flat_map(|members| members.iter())
            .filter_map(|m| self.people.get(m))
    }

    pub fn last_touch_on(&self, canonical: &RecordId, on: NaiveDate) -> Option<NaiveDate> {
        self.ensure_members(on);
        let groups = self.merge.groups();
        let groups = groups.get(&on).expect("members cached");
        self.group_people(groups, canonical)
            .filter_map(|p| p.last_touch_on(on))
            .max()
    }

    pub fn cadence_days_for(&self, canonical: &RecordId, on: NaiveDate) -> Option<u32> {
        if let Some(days) = self.people.get(canonical).and_then(|p| p.cadence_days) {
            return Some(days);
        }
        self.ensure_members(on);
        let borrow = self.merge.groups();
        let groups = borrow.get(&on).expect("members cached");
        let members = groups.get(canonical)?;
        for m in members {
            if let Some(days) = self.people.get(m).and_then(|p| p.cadence_days) {
                return Some(days);
            }
        }
        None
    }
}

/// One important date entry in `context` (`packs["personal@0.1"].dates`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportantDateView {
    pub label: String,
    pub date: String,
}

/// One recent touchpoint in `context` (`packs["personal@0.1"].recent_touches`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentTouch {
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Personal pack context view (`packs["personal@0.1"]`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonalView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthday: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship_to_me: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub dates: Vec<ImportantDateView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cadence_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_touch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_since_touch: Option<i64>,
    pub overdue: bool,
    pub recent_touches: Vec<RecentTouch>,
}

/// The compiled personal pack (#184). Registered in [`crate::packs::ALL_PACKS`].
pub struct PersonalPack;

impl Pack for PersonalPack {
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

    fn finding_codes(&self) -> &'static [&'static str] {
        // Step 6 (#345): served from the manifest. The parity test pins
        // the codes verbatim so a bad manifest fails loudly.
        // `E_TOUCH_MALFORMED` is a core code (emitted by `check`, not this
        // pack), so it is not listed here; it is documented in
        // `spec/findings.md`.
        &manifest_claims().finding_codes
    }

    fn edge_kinds(&self) -> &'static [EdgeKind] {
        &manifest_claims().edge_kinds
    }

    fn verb_id_type(&self, verb: &str) -> Option<Prefix> {
        manifest_claims()
            .verb_id_types
            .iter()
            .find(|(v, _)| *v == verb)
            .map(|(_, p)| *p)
    }

    fn validate_verb_args(&self, verb: &str, entry: &LedgerEntry) -> Option<bool> {
        match verb {
            "touch" => Some(validate_touch_args_enabled(&entry.args)),
            _ => None,
        }
    }

    fn verb_kind(&self, verb: &str, entry: &LedgerEntry) -> Option<String> {
        match verb {
            "touch" => extract_touch_kind(entry),
            _ => None,
        }
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
            .downcast_ref::<PersonalState>()
            .expect("PersonalPack state");
        touch_note_integrity(vault, state, findings);
        cadence_and_date_rules(vault, state, as_of, findings);
    }

    fn check_balance(
        &self,
        _vault: &Vault,
        _state: &dyn PackState,
        _sourced: &SourcedEntry,
        _findings: &mut Vec<Finding>,
    ) {
    }

    fn context_view(
        &self,
        vault: &Vault,
        state: &dyn PackState,
        person: &RecordId,
        canonical: &RecordId,
        as_of: NaiveDate,
    ) -> Option<serde_json::Value> {
        let state = state
            .as_any()
            .downcast_ref::<PersonalState>()
            .expect("PersonalPack state");
        let cleared = cleared_record_ids(vault);
        let person_cleared = cleared.contains(person);

        let cadence_days = state.cadence_days_for(canonical, as_of);
        let last_touch_date = state.last_touch_on(canonical, as_of);
        let days_since_touch = last_touch_date.map(|d| as_of.signed_duration_since(d).num_days());
        let overdue = match (cadence_days, days_since_touch) {
            (Some(cad), Some(days)) => days > i64::from(cad),
            (Some(_), None) => true,
            (None, _) => false,
        };

        let (birthday, relationship_to_me, dates) = if person_cleared {
            let p = state.people.get(canonical);
            (
                p.and_then(|pp| pp.birthday.as_ref().map(|b| b.raw.clone())),
                p.and_then(|pp| pp.relationship_to_me.clone()),
                p.map(|pp| {
                    pp.dates
                        .iter()
                        .map(|d| ImportantDateView {
                            label: d.label.clone(),
                            date: d.raw.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            )
        } else {
            (None, None, Vec::new())
        };

        let mut recent_touches: Vec<RecentTouch> = vault
            .entries
            .iter()
            .filter(|s| {
                s.entry.verb == "touch"
                    && s.entry.date <= as_of
                    && state.canonical_on(&s.entry.id, as_of) == *canonical
            })
            .map(|s| RecentTouch {
                date: s.entry.date.to_string(),
                kind: extract_touch_kind(&s.entry),
            })
            .collect();
        recent_touches.sort_by(|a, b| b.date.cmp(&a.date).then(a.kind.cmp(&b.kind)));
        recent_touches.truncate(10);

        let view = PersonalView {
            birthday,
            relationship_to_me,
            dates,
            cadence_days,
            last_touch: last_touch_date.map(|d| d.to_string()),
            days_since_touch,
            overdue,
            recent_touches,
        };
        serde_json::to_value(view).ok()
    }

    fn private_context_fields(&self) -> &'static [&'static str] {
        // `birthday`, `relationship_to_me`, and `dates` are the person's own
        // PII; `context` strips them when private data is excluded. The
        // cadence/touch fields are derived metadata and stay.
        &["birthday", "relationship_to_me", "dates"]
    }
}

fn person_mut<'a>(state: &'a mut PersonalState, id: &RecordId) -> &'a mut PersonPersonal {
    state.people.entry(id.clone()).or_default()
}

fn fold(
    vault: &Vault,
    merges: MergeMap,
    _as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) -> PersonalState {
    let mut state = PersonalState {
        merge: crate::packs::groups::MergeGroups::new(merges),
        ..Default::default()
    };

    // 1. Validate and fold personal fields on records, and fold interaction
    //    records into touchpoints.
    let mut records: Vec<&Record> = vault.records.values().collect();
    records.sort_by(|a, b| a.id.cmp(&b.id));
    for rec in records {
        if rec.kind == RecordKind::Person {
            let entry = person_mut(&mut state, &rec.id);
            if let Some(raw) = rec.field("birthday") {
                match parse_field_grammar(GRAMMAR_RECURRING_DATE, "birthday", raw) {
                    Some(FieldValue::RecurringDate(bd)) => entry.birthday = Some(bd),
                    _ => push_field_error(
                        rec,
                        "birthday",
                        "must be YYYY-MM-DD or --MM-DD",
                        "Use YYYY-MM-DD (e.g. 1990-05-14) or --MM-DD (e.g. --05-14)",
                        findings,
                    ),
                }
            }
            if let Some(raw) = rec.field("cadence") {
                match parse_field_grammar(GRAMMAR_CADENCE, "cadence", raw) {
                    Some(FieldValue::CadenceDays(days)) => entry.cadence_days = Some(days),
                    _ => push_field_error(
                        rec,
                        "cadence",
                        "must be <N>d (1..=3650)",
                        "Use a positive day count such as 30d or 90d",
                        findings,
                    ),
                }
            }
            if let Some(raw) = rec.field("relationship_to_me") {
                match parse_field_grammar(GRAMMAR_NON_EMPTY_STRING, "relationship_to_me", raw) {
                    Some(FieldValue::Text(label)) => entry.relationship_to_me = Some(label),
                    _ => push_field_error(
                        rec,
                        "relationship_to_me",
                        "must not be empty",
                        "Provide a non-empty relationship label or remove the key",
                        findings,
                    ),
                }
            }
            if let Some(raw) = rec.field("dates") {
                match parse_field_grammar(GRAMMAR_DATES_LIST, "dates", raw) {
                    Some(FieldValue::DatesList(list)) => entry.dates = list,
                    _ => push_field_error(
                        rec,
                        "dates",
                        "must be a comma-separated list of label:YYYY-MM-DD or label:--MM-DD",
                        "Example: dates: [anniversary:2020-06-15, graduation:--05-20]",
                        findings,
                    ),
                }
            }
        } else if rec.kind == RecordKind::Interaction {
            if let Some(date) = rec.field("date").and_then(parse_strict_date) {
                if let Some(primary) = rec.person() {
                    person_mut(&mut state, &primary)
                        .touches
                        .push(TouchEvent { date });
                }
                if let Some(raw_with) = rec.field("with") {
                    if let Some(participants) = parse_with_list(raw_with) {
                        for p in participants {
                            if p.prefix() == Prefix::Person {
                                person_mut(&mut state, &p).touches.push(TouchEvent { date });
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Fold ledger touchpoints (`touch` and coaching `session` per #227 Q2).
    for sourced in &vault.entries {
        let e = &sourced.entry;
        if e.id.prefix() != Prefix::Person {
            continue;
        }
        match e.verb.as_str() {
            "touch" => {
                person_mut(&mut state, &e.id)
                    .touches
                    .push(TouchEvent { date: e.date });
            }
            "session" => {
                // #227 Q2: coaching `session` counts as a touchpoint so a
                // coaching client who is also a friend does not get a false
                // cadence overdue warning.
                person_mut(&mut state, &e.id)
                    .touches
                    .push(TouchEvent { date: e.date });
            }
            _ => {}
        }
    }

    state
}

fn push_field_error(
    rec: &Record,
    key: &str,
    problem: &str,
    fix_text: &str,
    findings: &mut Vec<Finding>,
) {
    let mut f = Finding::new(
        FindingCode::Frontmatter,
        Severity::Error,
        render_msg(
            "E_FRONTMATTER",
            "default",
            &[("key", &key), ("problem", &problem)],
        ),
    )
    .at_file(&rec.path)
    .for_id(&rec.id)
    .with_fix(render_msg(
        "E_FRONTMATTER",
        "default_fix",
        &[("fix", &fix_text)],
    ));
    if let Some(line) = rec.field_lines.get(key) {
        f = f.at_line(*line);
    }
    findings.push(f);
}

/// `note:` ID/type/existence/ownership on `touch` lines, mirroring coaching's
/// `session_note_integrity`.
fn touch_note_integrity(vault: &Vault, state: &PersonalState, findings: &mut Vec<Finding>) {
    for sourced in &vault.entries {
        if sourced.entry.verb != "touch" {
            continue;
        }
        let e = &sourced.entry;
        if e.id.prefix() != Prefix::Person {
            continue;
        }
        let person = state.canonical_on(&e.id, NaiveDate::MAX);
        let Some(note_id) = e.pair("note") else {
            continue;
        };
        match RecordId::parse(note_id) {
            Err(_) => findings.push(
                Finding::new(
                    FindingCode::InvalidId,
                    Severity::Error,
                    render_msg("E_INVALID_ID", "default", &[]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(render_msg("E_INVALID_ID", "default_fix", &[])),
            ),
            Ok(nid) if nid.prefix() != Prefix::Note => findings.push(
                Finding::new(
                    FindingCode::WrongIdType,
                    Severity::Error,
                    render_msg("E_WRONG_ID_TYPE", "default", &[("id", &nid)]),
                )
                .at_file(&sourced.file)
                .at_line(sourced.line)
                .for_id(&person)
                .with_fix(render_msg("E_WRONG_ID_TYPE", "default_fix", &[])),
            ),
            Ok(nid) => match vault.records.get(&nid) {
                None => findings.push(
                    Finding::new(
                        FindingCode::UnknownRecord,
                        Severity::Error,
                        render_msg("E_UNKNOWN_RECORD", "missing", &[("id", &nid)]),
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
                        .or_else(|| crate::id::person_id_from_path(&rec.path))
                        .map(|p| state.canonical_on(&p, NaiveDate::MAX));
                    if note_person.as_ref() != Some(&person) {
                        findings.push(
                            Finding::new(
                                FindingCode::UnknownRecord,
                                Severity::Error,
                                render_msg(
                                    "E_UNKNOWN_RECORD",
                                    "wrong_owner",
                                    &[("id", &nid), ("person", &person)],
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

fn cadence_and_date_rules(
    vault: &Vault,
    state: &PersonalState,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) {
    state.ensure_members(as_of);

    // Collect canonical person IDs in deterministic order.
    let mut canonical_people: BTreeMap<RecordId, &Record> = BTreeMap::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Person {
            continue;
        }
        let canon = state.canonical_on(&rec.id, as_of);
        if canon == rec.id {
            canonical_people.insert(canon, rec);
        }
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("personal.cadence_overdue", Severity::Warning)
    {
        for (id, rec) in &canonical_people {
            let Some(cadence_days) = state.cadence_days_for(id, as_of) else {
                continue;
            };
            let window = chrono::Duration::days(i64::from(cadence_days));
            let last = state.last_touch_on(id, as_of);
            if let Some(d) = last {
                if as_of.signed_duration_since(d) <= window {
                    continue;
                }
            }
            let start = as_of - window;
            let (message, fix) = match last {
                Some(d) => (
                    render_msg(
                        "W_CADENCE_OVERDUE",
                        "last",
                        &[
                            ("id", &id),
                            ("start", &start),
                            ("d", &d),
                            ("cadence_days", &cadence_days),
                        ],
                    ),
                    render_fix("W_CADENCE_OVERDUE", "last", &[("id", &id)])
                        .expect("manifest declares last_fix"),
                ),
                None => (
                    render_msg(
                        "W_CADENCE_OVERDUE",
                        "none",
                        &[("id", &id), ("cadence_days", &cadence_days)],
                    ),
                    render_fix("W_CADENCE_OVERDUE", "none", &[("id", &id)])
                        .expect("manifest declares none_fix"),
                ),
            };
            findings.push(
                Finding::new(FindingCode::CadenceOverdue, sev, message)
                    .at_file(&rec.path)
                    .for_id(id)
                    .with_fix(fix),
            );
        }
    }

    if let Some(sev) = vault
        .config
        .checks
        .severity("personal.date_upcoming", Severity::Warning)
    {
        let lookahead = vault.config.checks.date_upcoming_days();
        let lookahead_i = i64::try_from(lookahead).unwrap_or(i64::MAX);
        for (id, rec) in &canonical_people {
            let Some(pp) = state.people.get(id) else {
                continue;
            };
            let mut all_dates: Vec<&RecurringDate> = Vec::new();
            if let Some(ref bd) = pp.birthday {
                all_dates.push(bd);
            }
            all_dates.extend(pp.dates.iter());
            for rd in all_dates {
                let Some(occ) = rd.next_occurrence_on_or_after(as_of) else {
                    continue;
                };
                let delta = occ.signed_duration_since(as_of).num_days();
                if (0..=lookahead_i).contains(&delta) {
                    findings.push(
                        Finding::new(
                            FindingCode::DateUpcoming,
                            sev,
                            render_msg(
                                "W_DATE_UPCOMING",
                                "default",
                                &[("id", &id), ("occ", &occ), ("delta", &delta)],
                            ),
                        )
                        .at_file(&rec.path)
                        .for_id(id)
                        .with_fix(
                            render_fix("W_DATE_UPCOMING", "default", &[("id", &id)])
                                .expect("manifest declares default_fix"),
                        ),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parity test (#343): the manifest-derived claims must equal the
    /// `&'static` slices the trait served before the manifest existed.
    /// Expected values are copied verbatim from the deleted slices; this
    /// test pins the manifest to the original claims so a bad manifest
    /// fails loudly instead of silently changing behavior.
    #[test]
    fn manifest_claims_match_original_slices() {
        let pack = PersonalPack;
        assert_eq!(pack.name(), "personal@0.1");
        assert_eq!(pack.verbs(), &["touch"][..]);
        assert!(pack.record_types().is_empty());
        assert_eq!(
            pack.fields(),
            &["birthday", "cadence", "relationship_to_me", "dates"][..]
        );
        assert!(pack.balance_metrics().is_empty());
        assert_eq!(
            pack.edge_kinds(),
            &[
                EdgeKind {
                    name: "friend",
                    symmetric: true,
                },
                EdgeKind {
                    name: "family",
                    symmetric: true,
                },
                EdgeKind {
                    name: "sibling",
                    symmetric: true,
                },
                EdgeKind {
                    name: "partner",
                    symmetric: true,
                },
                EdgeKind {
                    name: "parent",
                    symmetric: false,
                },
                EdgeKind {
                    name: "mentor",
                    symmetric: false,
                },
            ][..]
        );
        assert_eq!(pack.verb_id_type("touch"), Some(Prefix::Person));
        assert_eq!(pack.verb_id_type("session"), None);
        assert_eq!(pack.verb_id_type(""), None);
    }

    /// The vendored manifest must match `packs/personal/manifest.toml` at
    /// the repo root (#368 pattern). Skips gracefully when the repo-root
    /// file is absent (e.g. a published crate), where there is nothing to
    /// drift from.
    #[test]
    fn vendored_manifest_matches_repo_root() {
        let root = format!(
            "{}/../../packs/personal/manifest.toml",
            env!("CARGO_MANIFEST_DIR")
        );
        let Ok(root_text) = std::fs::read_to_string(&root) else {
            return;
        };
        assert_eq!(
            root_text, PERSONAL_MANIFEST_TOML,
            "vendored manifest is stale; copy packs/personal/manifest.toml \
             to crates/confidant-core/pack-manifests/personal/manifest.toml"
        );
    }

    /// Silas (#351 review): the §11 example's edge kinds and finding codes
    /// must match the code. The manifest is the §11 example; prove it
    /// mechanically. In step 6 (#345) `finding_codes()` serves the
    /// manifest, so the trait-vs-manifest comparison is circular; the
    /// verbatim list below pins the codes instead.
    #[test]
    fn manifest_finding_codes_and_edge_kinds_match_code() {
        let m = parse_manifest(PERSONAL_MANIFEST_TOML).expect("manifest parses");
        let from_trait: Vec<String> = PersonalPack
            .finding_codes()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(m.finding_codes, from_trait);
        assert_eq!(
            m.finding_codes,
            [
                "E_FRONTMATTER",
                "E_INVALID_ID",
                "E_WRONG_ID_TYPE",
                "E_UNKNOWN_RECORD",
                "W_CADENCE_OVERDUE",
                "W_DATE_UPCOMING",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
        );
        let edge_names: Vec<(&str, bool)> = m
            .edge_kinds
            .iter()
            .map(|e| (e.name.as_str(), e.symmetric))
            .collect();
        assert_eq!(
            edge_names,
            [
                ("friend", true),
                ("family", true),
                ("sibling", true),
                ("partner", true),
                ("parent", false),
                ("mentor", false),
            ]
        );
    }
}
