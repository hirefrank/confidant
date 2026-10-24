//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;

use crate::check::{sort_findings, Finding, FindingCode, Severity};
use crate::error::DomainError;
use crate::id::{
    add_bare_ulid_windows, person_id_from_path, scan_ids, scan_prefixed_line, IdToken, Prefix,
    PrefixedScan, RecordId,
};
use crate::ledger::ledger_line_verb;
use crate::record::{parse_ref_id, parse_with_list, unquote, FrontmatterRef, RecordKind};
use crate::scope::{
    note_linkage_owners, owner_of_field, owners_of_ledger_text, record_owners, OwnerKey, PackScope,
};
use crate::vault::Vault;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SearchHit {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub path: String,
    pub line: u32,
    pub excerpt: String,
    /// Operator-only tri-state `no-ai` mode (`"true"`, `"notes"`, `"false"`)
    /// of the hit's record, present only on [`search_for_operator`] (#572).
    /// `None` for every agent-path hit and for ledger-line hits, so the
    /// field never changes an agent's byte-for-byte output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_ai: Option<&'static str>,
    /// Operator-only marker for a ledger-line hit the section 12 agent
    /// allowlist hides but [`search_for_operator`] includes (#593). Absent
    /// on record hits (they carry `no_ai`), on ledger hits an agent can see
    /// too, and on every agent-path hit, so agent JSON is unchanged.
    /// Always `Some(true)` when present: whether a line is operator-only is
    /// a yes/no question, and one line may reference several `no-ai`
    /// records whose modes disagree, so there is no single `no-ai` value
    /// to report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_only: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub findings: Vec<Finding>,
    /// Envelopes skipped as unreadable by the content hook (no device key,
    /// or the data key won't unwrap). Spec 4 (⚠2): never silently empty.
    /// no-ai envelopes load as shells instead and are not counted here.
    pub skipped_encrypted: u32,
    /// Envelopes refused as tampered/corrupt (structural parse or AEAD
    /// failure). Never folded into `skipped_encrypted` (⚠2c).
    pub refused_envelopes: u32,
}

struct RecordFacts {
    fm_ids: Vec<RecordId>,
    fm_malformed: bool,
    fm_bad_ref: bool,
    fm_bare_ulids: Vec<String>,
    path_person: Option<RecordId>,
    body_start_line: u32,
    /// Tokenized once from BOM-stripped source; 1-based line numbers.
    line_tokens: Vec<(u32, Vec<IdToken>)>,
}

/// Indexes built once per search so the allowlist is a worklist, not nested scans.
struct Allowlist<'a> {
    vault: &'a Vault,
    cleared: HashSet<RecordId>,
    facts: BTreeMap<RecordId, RecordFacts>,
    by_path: BTreeMap<&'a str, &'a RecordId>,
    by_ulid: HashMap<Arc<str>, Vec<RecordId>>,
    strong_by_ulid: HashMap<Arc<str>, Vec<RecordId>>,
    ledger_at: HashMap<(&'a str, u32), usize>,
    ledger_tokens: Vec<Vec<IdToken>>,
    named_ledger_lines: BTreeMap<RecordId, Vec<usize>>,
    ledger_ok: Vec<bool>,
    /// Operator mode only (#593): per ledger line, `true` when the operator
    /// allowlist shows it and the agent allowlist does not. Empty on the
    /// agent path.
    ledger_operator_only: Vec<bool>,
    /// Pack scope this search applies (#178). [`PackScope::All`] for the
    /// unscoped §12 allowlist.
    scope: PackScope,
    /// Operator mode (#572): compute the cleared set as if `no-ai` did not
    /// exist, so an operator-only read can surface `no-ai` records. This is
    /// the same decrypt path as `record show --for-edit` (spec §12). Never
    /// set on an agent path; `false` is the §12 allowlist.
    operator: bool,
    /// Operator mode only (#572): ids the agent allowlist hides but the
    /// operator allowlist does not — hidden solely by `no-ai` (their own or
    /// inherited). Used to badge a hit. Empty on the agent path.
    no_ai_hidden: HashSet<RecordId>,
    /// Enabled packs for this vault (for attribution).
    enabled: Vec<&'a dyn crate::packs::Pack>,
    /// Note id → packs owning a ledger line that references it.
    linkage: HashMap<RecordId, BTreeSet<OwnerKey>>,
}

/// Unicode case-insensitive substring scan. Hits are ordered by path, then line.
/// Line numbers are 1-based positions in the original file.
/// Returns content only from the cleared allowlist (spec section 12).
/// If any ledger file was unreadable, returns [`DomainError`] `E_LEDGER_UNREADABLE`
/// and no hits. `scope` further filters hits to the packs in scope (#178):
/// core-owned items stay visible, unattributed items are hidden.
pub fn search(vault: &Vault, query: &str, scope: &PackScope) -> Result<SearchResult, DomainError> {
    search_with(vault, query, scope, false)
}

/// Operator-only variant of [`search`] (#572): the same scan, but the
/// cleared set is computed as if `no-ai` did not exist, so `no-ai` records
/// (and ledger lines that only reference them) come back as hits. Each
/// record hit carries the tri-state `no_ai` string; a ledger hit visible
/// only because of the operator allowlist carries `operator_only: true`
/// (#593). Reached only through `confidant find --for-operator`, never
/// through MCP (spec §12).
pub fn search_for_operator(
    vault: &Vault,
    query: &str,
    scope: &PackScope,
) -> Result<SearchResult, DomainError> {
    search_with(vault, query, scope, true)
}

fn search_with(
    vault: &Vault,
    query: &str,
    scope: &PackScope,
    operator: bool,
) -> Result<SearchResult, DomainError> {
    if vault.ledger_unread_count > 0 {
        return Err(DomainError::ledger_unreadable(vault.ledger_unread_count));
    }
    let needle = case_fold(query);
    let allow = Allowlist::build_with(vault, scope, operator);
    let findings = findings_for_find(&allow);
    if needle.is_empty() {
        return Ok(SearchResult {
            hits: Vec::new(),
            findings: with_skipped_encrypted_warning(findings, true, vault.skipped_encrypted),
            skipped_encrypted: vault.skipped_encrypted,
            refused_envelopes: vault.refused_envelopes,
        });
    }
    let mut hits = Vec::new();
    for rec in vault.records.values() {
        if !allow.cleared.contains(&rec.id) {
            continue;
        }
        scan_record(rec, &needle, &allow, &mut hits);
    }
    for (idx, line) in vault.ledger_lines.iter().enumerate() {
        if !allow.ledger_ok.get(idx).copied().unwrap_or(false) {
            continue;
        }
        if !allow
            .scope
            .allows(&owners_of_ledger_text(&line.text, &allow.enabled))
        {
            continue;
        }
        let folded = case_fold(&line.text);
        if folded.contains(&needle) {
            hits.push(SearchHit {
                id: line.id.clone(),
                path: line.file.clone(),
                line: line.line,
                excerpt: excerpt(line.text.trim(), 200),
                // A ledger line is not a record; it has no `no-ai` of its
                // own to badge, even in operator mode.
                no_ai: None,
                // #593: mark it only when the operator flag is why it is
                // on screen. A line an agent can also see carries nothing.
                operator_only: allow
                    .ledger_operator_only
                    .get(idx)
                    .copied()
                    .unwrap_or(false)
                    .then_some(true),
            });
        }
    }
    hits.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    let empty = hits.is_empty();
    Ok(SearchResult {
        hits,
        findings: with_skipped_encrypted_warning(findings, empty, vault.skipped_encrypted),
        skipped_encrypted: vault.skipped_encrypted,
        refused_envelopes: vault.refused_envelopes,
    })
}

/// Record IDs in the section 12 cleared set. Used by tests to assert a fixed point.
/// Unscoped: the §12 allowlist is scope-independent; scoping applies on top.
pub fn cleared_record_ids(vault: &Vault) -> HashSet<RecordId> {
    Allowlist::build(vault, &PackScope::All).cleared
}

/// Operator-only cleared set (#572): like [`cleared_record_ids`], but
/// `no-ai` is ignored in the fixpoint, so records hidden only by their own
/// or an inherited `no-ai` mode are included. Used by `context
/// --for-operator`; never an agent path (spec §12).
pub fn cleared_record_ids_for_operator(vault: &Vault) -> HashSet<RecordId> {
    Allowlist::build_with(vault, &PackScope::All, true).cleared
}

/// Vault-relative paths of the records in the section 12 cleared set.
///
/// Sorted. Only cleared records appear, so (like `find` hits) this carries
/// no `no-ai` content: it is the index-time exclusion list for `qmd-index`
/// (issue #38). The query-time allowlist stays the authority; this only
/// narrows what is copied into the local corpus.
pub fn cleared_record_paths(vault: &Vault) -> BTreeSet<String> {
    let allow = Allowlist::build(vault, &PackScope::All);
    allow
        .vault
        .records
        .values()
        .filter(|rec| allow.cleared.contains(&rec.id))
        .map(|rec| rec.path.clone())
        .collect()
}

/// Cleared ledger lines per vault-relative ledger path: sorted 1-based line
/// numbers. Only canonical `ledger/YYYY/MM.cfd` lines can be cleared (other
/// ledger files are read for link tokens but never searched, so they map to
/// nothing and are left out of an index-time corpus entirely). Same
/// fail-closed posture as [`cleared_record_paths`].
pub fn cleared_ledger_lines(vault: &Vault) -> BTreeMap<String, Vec<u32>> {
    let allow = Allowlist::build(vault, &PackScope::All);
    let mut out: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for (idx, line) in allow.vault.ledger_lines.iter().enumerate() {
        if allow.ledger_ok.get(idx).copied().unwrap_or(false) {
            out.entry(line.file.clone()).or_default().push(line.line);
        }
    }
    out
}

/// Owners of every cleared record path, for `allowlist --json` ownership
/// annotations (#178). Core records map to `{Core}`; notes/interactions
/// to their pack owners (empty = unattributed).
pub fn cleared_record_owners(vault: &Vault) -> BTreeMap<String, BTreeSet<OwnerKey>> {
    let allow = Allowlist::build(vault, &PackScope::All);
    let mut out = BTreeMap::new();
    for rec in vault.records.values() {
        if allow.cleared.contains(&rec.id) {
            out.insert(
                rec.path.clone(),
                record_owners(rec, &allow.linkage, &allow.enabled),
            );
        }
    }
    out
}

/// Owners of every cleared ledger line, for `allowlist --json` ownership
/// annotations (#178). Same set and order as [`cleared_ledger_lines`].
pub fn cleared_ledger_line_owners(vault: &Vault) -> Vec<(String, u32, BTreeSet<OwnerKey>)> {
    let allow = Allowlist::build(vault, &PackScope::All);
    let mut out = Vec::new();
    for (idx, line) in vault.ledger_lines.iter().enumerate() {
        if allow.ledger_ok.get(idx).copied().unwrap_or(false) {
            out.push((
                line.file.clone(),
                line.line,
                owners_of_ledger_text(&line.text, &allow.enabled),
            ));
        }
    }
    // Same order as `cleared_ledger_lines`: file, then line.
    out.sort();
    out
}

/// True when every cleared id still satisfies every allowlist rule (merge
/// peers, package openers, front matter, path parent, named ledger lines).
pub fn allowlist_is_fixed_point(vault: &Vault) -> bool {
    let allow = Allowlist::build(vault, &PackScope::All);
    let tainted = tainted_ids(vault);
    let components = merge_components(&allow);
    let open_lines = pkg_open_lines(&allow);
    allow.cleared.iter().all(|id| {
        still_cleared(
            &allow,
            id,
            &allow.cleared,
            &tainted,
            &components,
            &open_lines,
        )
    })
}

impl<'a> Allowlist<'a> {
    /// The §12 agent allowlist: `no-ai` records are excluded.
    fn build(vault: &'a Vault, scope: &PackScope) -> Self {
        Self::build_with(vault, scope, false)
    }

    /// `operator` ignores `no-ai` in the cleared-set fixpoint (#572). Only
    /// ever `true` for `find --for-operator` / `context --for-operator`.
    fn build_with(vault: &'a Vault, scope: &PackScope, operator: bool) -> Self {
        let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
        let linkage = note_linkage_owners(vault, &enabled);
        let mut by_path = BTreeMap::new();
        for rec in vault.records.values() {
            by_path.insert(rec.path.as_str(), &rec.id);
        }
        let mut ledger_at = HashMap::with_capacity(vault.ledger_lines.len());
        for (idx, line) in vault.ledger_lines.iter().enumerate() {
            ledger_at.insert((line.file.as_str(), line.line), idx);
        }

        let mut strong_by_ulid: HashMap<Arc<str>, Vec<RecordId>> = HashMap::new();
        for id in vault.records.keys() {
            insert_by_ulid(&mut strong_by_ulid, id.clone());
        }
        for id in &vault.path_ids {
            insert_by_ulid(&mut strong_by_ulid, id.clone());
        }
        let mut by_ulid = strong_by_ulid.clone();

        let mut record_prefixed: BTreeMap<RecordId, Vec<(u32, PrefixedScan)>> = BTreeMap::new();
        for rec in vault.records.values() {
            let text = rec.source.trim_start_matches('\u{feff}');
            let mut lines = Vec::new();
            for (idx, line) in text.lines().enumerate() {
                let scan = scan_prefixed_line(line);
                for tok in &scan.tokens {
                    for id in tok.record_ids() {
                        insert_by_ulid(&mut by_ulid, id.clone());
                    }
                }
                lines.push((idx as u32 + 1, scan));
            }
            record_prefixed.insert(rec.id.clone(), lines);
        }
        let mut ledger_prefixed = Vec::with_capacity(vault.ledger_lines.len());
        for line in &vault.ledger_lines {
            let scan = scan_prefixed_line(&line.text);
            for tok in &scan.tokens {
                for id in tok.record_ids() {
                    insert_by_ulid(&mut by_ulid, id.clone());
                }
            }
            ledger_prefixed.push(scan);
        }
        sort_by_ulid(&mut by_ulid);
        sort_by_ulid(&mut strong_by_ulid);

        let mut vault_ulids: HashSet<Arc<str>> = by_ulid.keys().cloned().collect();
        vault_ulids.extend(
            vault
                .path_ulids
                .iter()
                .map(|u| Arc::<str>::from(u.as_str())),
        );

        let mut facts = BTreeMap::new();
        for rec in vault.records.values() {
            let lines = record_prefixed
                .remove(&rec.id)
                .expect("prefixed scan for every record");
            facts.insert(rec.id.clone(), record_facts(rec, lines, &vault_ulids));
        }
        let ledger_tokens: Vec<Vec<IdToken>> = vault
            .ledger_lines
            .iter()
            .zip(ledger_prefixed)
            .map(|(line, mut scan)| {
                add_bare_ulid_windows(&line.text, &vault_ulids, &mut scan);
                scan.tokens
            })
            .collect();
        let mut named_ledger_lines: BTreeMap<RecordId, Vec<usize>> = BTreeMap::new();
        for (idx, toks) in ledger_tokens.iter().enumerate() {
            for tok in toks {
                for id in ids_named_by(tok, &by_ulid, &strong_by_ulid) {
                    if !ledger_named_prefix(id.prefix()) {
                        continue;
                    }
                    let lines = named_ledger_lines.entry(id.clone()).or_default();
                    if lines.last() != Some(&idx) {
                        lines.push(idx);
                    }
                }
            }
        }
        let mut allow = Self {
            vault,
            cleared: HashSet::new(),
            facts,
            by_path,
            by_ulid,
            strong_by_ulid,
            ledger_at,
            ledger_tokens,
            named_ledger_lines,
            ledger_ok: Vec::new(),
            ledger_operator_only: Vec::new(),
            scope: scope.clone(),
            operator,
            no_ai_hidden: HashSet::new(),
            enabled,
            linkage,
        };
        allow.cleared = compute_cleared(&allow);
        // Operator mode only (#593): the agent's ledger allowlist, from the
        // same token rules with just the cleared set swapped. Collected
        // here so the ledger badge reuses the operator-minus-agent
        // difference, never a second notion of "hidden by no-ai".
        let mut agent_ledger_ok: Option<Vec<bool>> = None;
        if operator {
            // The badge set: everything the operator allowlist adds over
            // the agent allowlist is hidden solely by `no-ai`. The operator
            // rules are a strict relaxation of the agent rules, so the
            // agent set is a subset.
            let agent = Allowlist::build_with(vault, scope, false);
            let hidden: HashSet<RecordId> =
                allow.cleared.difference(&agent.cleared).cloned().collect();
            allow.no_ai_hidden = hidden;
            agent_ledger_ok = Some(
                allow
                    .vault
                    .ledger_lines
                    .iter()
                    .zip(allow.ledger_tokens.iter())
                    .map(|(line, toks)| {
                        line.searchable && tokens_allowed_with(toks, &agent.cleared, &allow)
                    })
                    .collect(),
            );
        }
        allow.ledger_ok = allow
            .vault
            .ledger_lines
            .iter()
            .zip(allow.ledger_tokens.iter())
            .map(|(line, toks)| line.searchable && tokens_allowed(toks, &allow))
            .collect();
        if let Some(agent_ok) = agent_ledger_ok {
            allow.ledger_operator_only = allow
                .ledger_ok
                .iter()
                .zip(agent_ok)
                .map(|(operator, agent)| *operator && !agent)
                .collect();
        }
        allow
    }
}

fn compute_cleared(allow: &Allowlist<'_>) -> HashSet<RecordId> {
    let vault = allow.vault;
    let tainted = tainted_ids(vault);
    let components = merge_components(allow);
    let open_lines = pkg_open_lines(allow);
    let dependents = reverse_deps(allow, &components);

    // Operator mode (#572) ignores `no-ai` here (and in `still_cleared`),
    // so the fixpoint yields the cleared set a human sees: the same
    // integrity rules, without the agent-visibility rule.
    let mut cleared: HashSet<RecordId> = vault
        .records
        .values()
        .filter(|rec| (allow.operator || !rec.no_ai()) && !tainted.contains(&rec.id))
        .filter(|rec| rec.person().is_none_or(|person| !tainted.contains(&person)))
        .filter(|rec| allow.operator || !inherits_notes_no_ai(rec, allow, &components))
        .map(|rec| rec.id.clone())
        .collect();

    let pkgs: HashSet<RecordId> = open_lines
        .iter()
        .flat_map(|line| line.pkgs.iter().cloned())
        .collect();
    for pkg in &pkgs {
        if pkg_is_clear(pkg, &open_lines, &cleared) {
            cleared.insert(pkg.clone());
        }
    }

    let mut stack: Vec<RecordId> = cleared.iter().cloned().collect();
    let mut queued: HashSet<RecordId> = cleared.iter().cloned().collect();
    while let Some(id) = stack.pop() {
        queued.remove(&id);
        if !cleared.contains(&id) {
            continue;
        }
        if still_cleared(allow, &id, &cleared, &tainted, &components, &open_lines) {
            continue;
        }
        drop_from_cleared(
            &id,
            &mut cleared,
            &components,
            &open_lines,
            &dependents,
            &mut stack,
            &mut queued,
        );
    }
    cleared
}

fn still_cleared(
    allow: &Allowlist<'_>,
    id: &RecordId,
    cleared: &HashSet<RecordId>,
    tainted: &HashSet<RecordId>,
    components: &MergeComponents,
    open_lines: &[OpenLine],
) -> bool {
    if id.prefix() == Prefix::Package {
        if let Some(members) = components.members_of(id) {
            if members.iter().any(|m| !cleared.contains(m)) {
                return false;
            }
        }
        return pkg_is_clear(id, open_lines, cleared);
    }
    let Some(facts) = allow.facts.get(id) else {
        return false;
    };
    if tainted.contains(id) {
        return false;
    }
    if facts.fm_malformed || facts.fm_bad_ref {
        return false;
    }
    if facts.line_tokens.iter().any(|(line_no, toks)| {
        *line_no < facts.body_start_line && !tokens_allowed_with(toks, cleared, allow)
    }) {
        return false;
    }
    if let Some(rec) = allow.vault.records.get(id) {
        if !allow.operator && inherits_notes_no_ai(rec, allow, components) {
            return false;
        }
    }
    if let Some(person) = &facts.path_person {
        if !cleared.contains(person) {
            return false;
        }
    }
    if let Some(members) = components.members_of(id) {
        if members.iter().any(|m| !cleared.contains(m)) {
            return false;
        }
    }
    if let Some(idxs) = allow.named_ledger_lines.get(id) {
        if idxs
            .iter()
            .any(|&idx| !tokens_allowed_with(&allow.ledger_tokens[idx], cleared, allow))
        {
            return false;
        }
    }
    true
}

/// True when `rec` is a note or interaction with no explicit `no-ai` flag of
/// its own whose person (via `person:`, `people/<id>/` path parent, `with:`
/// participant list, any other front-matter field holding the person's ID
/// or a list of IDs containing it, or a merge-group peer of any of those)
/// has `no-ai: notes` (#181, #270). Explicit `no-ai: false` on the child
/// still overrides `notes` mode (`rec.no_ai_mode()` is `Some(NoAi::False)`).
fn inherits_notes_no_ai(
    rec: &crate::record::Record,
    allow: &Allowlist<'_>,
    components: &MergeComponents,
) -> bool {
    if !matches!(rec.kind, RecordKind::Note | RecordKind::Interaction) {
        return false;
    }
    if rec.no_ai_mode().is_some() {
        return false;
    }
    let person_has_notes_mode = |pid: &RecordId| -> bool {
        let check_one = |id: &RecordId| -> bool {
            allow
                .vault
                .records
                .get(id)
                .is_some_and(|p| p.no_ai_mode() == Some(confidant_crypt::envelope::NoAi::Notes))
        };
        if check_one(pid) {
            return true;
        }
        if let Some(members) = components.members_of(pid) {
            if members.iter().any(check_one) {
                return true;
            }
        }
        false
    };
    if let Some(ref person) = rec.person() {
        if person_has_notes_mode(person) {
            return true;
        }
    }
    if let Some(facts) = allow.facts.get(&rec.id) {
        if let Some(ref person) = facts.path_person {
            if person_has_notes_mode(person) {
                return true;
            }
        }
    }
    // #270: any other front-matter field whose value parses as a record ID
    // — or a bracketed list of IDs, as in `with:` — resolving to a
    // notes-mode person (or a merge-group peer) also triggers inheritance.
    // This covers `with:` on notes as well as interactions (no kind gate).
    // Fail-closed for a privacy feature: when in doubt, hide. Only values
    // that parse as genuine record IDs via the same `parse_ref_id` /
    // `parse_with_list` used for `person:` / `with:` count, and only when
    // a referenced record is actually a person in `notes` mode — so
    // free-text fields never trigger this. Explicit `no-ai: false` on the
    // child still overrides (checked above).
    for (key, value) in &rec.fields {
        if key == "person" {
            continue; // handled above
        }
        match parse_ref_id(value) {
            FrontmatterRef::Id(id) => {
                if person_has_notes_mode(&id) {
                    return true;
                }
            }
            _ => {
                if parse_with_list(value).is_some_and(|ids| ids.iter().any(person_has_notes_mode)) {
                    return true;
                }
            }
        }
    }
    false
}

fn drop_from_cleared(
    id: &RecordId,
    cleared: &mut HashSet<RecordId>,
    components: &MergeComponents,
    open_lines: &[OpenLine],
    dependents: &HashMap<RecordId, HashSet<RecordId>>,
    stack: &mut Vec<RecordId>,
    queued: &mut HashSet<RecordId>,
) {
    let mut work = vec![id.clone()];
    while let Some(dropped) = work.pop() {
        if !cleared.remove(&dropped) {
            continue;
        }
        if let Some(members) = components.members_of(&dropped) {
            work.extend(members.iter().cloned());
        }
        let mut opened = HashSet::new();
        for line in open_lines {
            if line.people.contains(&dropped) {
                opened.extend(line.pkgs.iter().cloned());
            }
        }
        work.extend(opened);
        if let Some(deps) = dependents.get(&dropped) {
            for dep in deps {
                if cleared.contains(dep) && queued.insert(dep.clone()) {
                    stack.push(dep.clone());
                }
            }
        }
    }
}

fn pkg_is_clear(pkg: &RecordId, open_lines: &[OpenLine], cleared: &HashSet<RecordId>) -> bool {
    let mut mentioned = false;
    for line in open_lines {
        if !line.pkgs.contains(pkg) {
            continue;
        }
        mentioned = true;
        if line.people.is_empty() || line.people.iter().any(|person| !cleared.contains(person)) {
            return false;
        }
    }
    mentioned
}

fn tainted_ids(vault: &Vault) -> HashSet<RecordId> {
    let mut tainted = HashSet::new();
    for finding in &vault.load_findings {
        if finding.code != FindingCode::DuplicateId && finding.code != FindingCode::IdPathMismatch {
            continue;
        }
        if let Some(id) = &finding.id {
            if let Ok(rid) = RecordId::parse(id) {
                tainted.insert(rid.clone());
                if rid.prefix() == Prefix::Person {
                    if let Some(file) = &finding.file {
                        tainted.extend(scan_ids(file));
                    }
                }
            }
        }
    }
    tainted
}

struct MergeComponents {
    of: HashMap<RecordId, usize>,
    members: Vec<Vec<RecordId>>,
}

impl MergeComponents {
    fn members_of(&self, id: &RecordId) -> Option<&[RecordId]> {
        let idx = *self.of.get(id)?;
        Some(self.members[idx].as_slice())
    }
}

fn merge_components(allow: &Allowlist<'_>) -> MergeComponents {
    let mut parent: HashMap<RecordId, RecordId> = HashMap::new();
    let find = |parent: &mut HashMap<RecordId, RecordId>, id: &RecordId| -> RecordId {
        if !parent.contains_key(id) {
            parent.insert(id.clone(), id.clone());
            return id.clone();
        }
        let mut root = id.clone();
        loop {
            let next = parent.get(&root).expect("union-find parent").clone();
            if next == root {
                break;
            }
            root = next;
        }
        let mut cur = id.clone();
        while cur != root {
            let next = parent.get(&cur).expect("union-find parent").clone();
            parent.insert(cur, root.clone());
            cur = next;
        }
        root
    };
    let union = |parent: &mut HashMap<RecordId, RecordId>, a: &RecordId, b: &RecordId| {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent.insert(ra, rb);
        }
    };

    for rec in allow.vault.records.values() {
        find(&mut parent, &rec.id);
    }
    for (line, toks) in allow
        .vault
        .ledger_lines
        .iter()
        .zip(allow.ledger_tokens.iter())
    {
        if ledger_line_verb(&line.text).as_deref() != Some("merge") {
            continue;
        }
        let ids: Vec<RecordId> = toks
            .iter()
            .flat_map(|tok| ids_named_by(tok, &allow.by_ulid, &allow.strong_by_ulid))
            .cloned()
            .collect();
        for id in &ids {
            find(&mut parent, id);
        }
        for pair in ids.windows(2) {
            union(&mut parent, &pair[0], &pair[1]);
        }
    }

    let ids: Vec<RecordId> = parent.keys().cloned().collect();
    let mut root_index: HashMap<RecordId, usize> = HashMap::new();
    let mut members: Vec<Vec<RecordId>> = Vec::new();
    let mut of = HashMap::new();
    for id in ids {
        let root = find(&mut parent, &id);
        let idx = *root_index.entry(root.clone()).or_insert_with(|| {
            members.push(Vec::new());
            members.len() - 1
        });
        members[idx].push(id.clone());
        of.insert(id, idx);
    }
    for group in &mut members {
        group.sort();
    }
    MergeComponents { of, members }
}

struct OpenLine {
    people: HashSet<RecordId>,
    pkgs: HashSet<RecordId>,
}

/// The verb token of a ledger line, without restricting the vocabulary.
/// Handles `DATE verb ...` and `verb ...`, comments, and markdown bullets.
fn ledger_verb_token(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    let trimmed = trimmed
        .strip_prefix("* ")
        .or_else(|| trimmed.strip_prefix("- "))
        .or_else(|| trimmed.strip_prefix("+ "))
        .unwrap_or(trimmed);
    let mut toks = trimmed.split_whitespace();
    let first = toks.next()?;
    let verb = if crate::ledger::parse_strict_date(first).is_some() {
        toks.next()?
    } else {
        first
    };
    Some(verb.trim_end_matches(':').to_ascii_lowercase())
}

fn pkg_open_lines(allow: &Allowlist<'_>) -> Vec<OpenLine> {
    let opener_verbs: HashSet<&str> = allow
        .enabled
        .iter()
        .flat_map(|pack| pack.balance_open_verbs().iter().copied())
        .collect();
    if opener_verbs.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for (line, toks) in allow
        .vault
        .ledger_lines
        .iter()
        .zip(allow.ledger_tokens.iter())
    {
        // Only a pack's declared `open_verb` opens a package. A line that
        // merely contains `package` (a note reference, a stray argument)
        // must not clear a package ID.
        // Lexical, so an unparsable opener line still contributes: a bare
        // or malformed ID must fail closed (the package stays uncleared).
        let is_opener =
            ledger_verb_token(&line.text).is_some_and(|verb| opener_verbs.contains(verb.as_str()));
        if !is_opener {
            continue;
        }
        let mut people = HashSet::new();
        let mut pkgs = HashSet::new();
        for id in toks
            .iter()
            .flat_map(|tok| ids_named_by(tok, &allow.by_ulid, &allow.strong_by_ulid))
        {
            match id.prefix() {
                Prefix::Person => {
                    people.insert(id.clone());
                }
                Prefix::Package => {
                    pkgs.insert(id.clone());
                }
                Prefix::Org | Prefix::Deal | Prefix::Interaction | Prefix::Note | Prefix::Edge => {}
            }
        }
        if !people.is_empty() || !pkgs.is_empty() {
            lines.push(OpenLine { people, pkgs });
        }
    }
    lines
}

fn reverse_deps(
    allow: &Allowlist<'_>,
    components: &MergeComponents,
) -> HashMap<RecordId, HashSet<RecordId>> {
    let mut dependents: HashMap<RecordId, HashSet<RecordId>> = HashMap::new();
    let mut link = |from: RecordId, to: RecordId| {
        dependents.entry(from).or_default().insert(to);
    };
    for rec in allow.vault.records.values() {
        if let Some(facts) = allow.facts.get(&rec.id) {
            for id in &facts.fm_ids {
                link(id.clone(), rec.id.clone());
                if let Some(strong) = allow.strong_by_ulid.get(id.ulid()) {
                    for sid in strong {
                        link(sid.clone(), rec.id.clone());
                    }
                }
            }
            for ulid in &facts.fm_bare_ulids {
                if let Some(ids) = allow.by_ulid.get(ulid.as_str()) {
                    for id in ids {
                        link(id.clone(), rec.id.clone());
                    }
                }
            }
            if let Some(person) = &facts.path_person {
                link(person.clone(), rec.id.clone());
            }
        }
    }
    for group in &components.members {
        for a in group {
            for b in group {
                if a != b {
                    link(a.clone(), b.clone());
                }
            }
        }
    }
    for (named, idxs) in &allow.named_ledger_lines {
        for &idx in idxs {
            for tok in &allow.ledger_tokens[idx] {
                for id in ids_named_by(tok, &allow.by_ulid, &allow.strong_by_ulid) {
                    link(id.clone(), named.clone());
                }
            }
        }
    }
    dependents
}

fn record_facts(
    rec: &crate::record::Record,
    mut lines: Vec<(u32, PrefixedScan)>,
    vault_ulids: &HashSet<Arc<str>>,
) -> RecordFacts {
    let text = rec.source.trim_start_matches('\u{feff}');
    let mut fm_ids = Vec::new();
    let mut fm_malformed = false;
    let mut fm_bare_ulids = Vec::new();
    let mut line_tokens = Vec::with_capacity(lines.len());
    for ((line_no, mut scan), line) in lines.drain(..).zip(text.lines()) {
        add_bare_ulid_windows(line, vault_ulids, &mut scan);
        if line_no < rec.body_start_line {
            for tok in &scan.tokens {
                match tok {
                    IdToken::Malformed { .. } => fm_malformed = true,
                    IdToken::Valid(id) => fm_ids.push(id.clone()),
                    IdToken::BareUlid(ulid) => fm_bare_ulids.push(ulid.clone()),
                }
            }
        }
        line_tokens.push((line_no, scan.tokens));
    }
    // A `person` / `org` / `deal` value — including ASCII case variants
    // (`Person:`, #5) — that is not a record ID uncleares the record.
    // Alias or custom keys are not references.
    let fm_bad_ref = rec.fields.iter().any(|(key, raw)| {
        crate::record::canonical_ref_key(key).is_some()
            && matches!(parse_ref_id(raw), FrontmatterRef::Invalid)
    });
    RecordFacts {
        fm_ids,
        fm_malformed,
        fm_bad_ref,
        fm_bare_ulids,
        path_person: person_id_from_path(&rec.path),
        body_start_line: rec.body_start_line,
        line_tokens,
    }
}

fn ledger_named_prefix(prefix: Prefix) -> bool {
    match prefix {
        Prefix::Note | Prefix::Interaction | Prefix::Deal => true,
        // An edge id named in a ledger line does not uncleared the edge:
        // §12's named-line rule covers notes, interactions, and deals
        // only. Edge linkage lives in front matter (`a` / `b`).
        Prefix::Person | Prefix::Org | Prefix::Package | Prefix::Edge => false,
    }
}

fn insert_by_ulid(by_ulid: &mut HashMap<Arc<str>, Vec<RecordId>>, id: RecordId) {
    let entry = by_ulid.entry(id.ulid_shared()).or_default();
    if !entry.contains(&id) {
        entry.push(id);
    }
}

fn sort_by_ulid(by_ulid: &mut HashMap<Arc<str>, Vec<RecordId>>) {
    for ids in by_ulid.values_mut() {
        ids.sort();
    }
}

fn ids_named_by<'a>(
    tok: &'a IdToken,
    by_ulid: &'a HashMap<Arc<str>, Vec<RecordId>>,
    strong_by_ulid: &'a HashMap<Arc<str>, Vec<RecordId>>,
) -> Vec<&'a RecordId> {
    match tok {
        IdToken::Valid(id)
        | IdToken::Malformed {
            candidate: Some(id),
        } => {
            let mut ids = vec![id];
            if let Some(strong) = strong_by_ulid.get(id.ulid()) {
                for sid in strong {
                    if sid != id && !ids.contains(&sid) {
                        ids.push(sid);
                    }
                }
            }
            ids
        }
        IdToken::Malformed { candidate: None } => Vec::new(),
        IdToken::BareUlid(ulid) => by_ulid
            .get(ulid.as_str())
            .map(|ids| ids.iter().collect())
            .unwrap_or_default(),
    }
}

fn tokens_allowed(toks: &[IdToken], allow: &Allowlist<'_>) -> bool {
    tokens_allowed_with(toks, &allow.cleared, allow)
}

fn tokens_allowed_with(
    toks: &[IdToken],
    cleared: &HashSet<RecordId>,
    allow: &Allowlist<'_>,
) -> bool {
    for tok in toks {
        match tok {
            IdToken::Malformed { .. } => return false,
            IdToken::Valid(id) => {
                if !cleared.contains(id) {
                    return false;
                }
                if let Some(ids) = allow.strong_by_ulid.get(id.ulid()) {
                    if ids.iter().any(|sid| !cleared.contains(sid)) {
                        return false;
                    }
                }
            }
            IdToken::BareUlid(ulid) => {
                if allow.vault.path_ulids.contains(ulid) {
                    return false;
                }
                if let Some(ids) = allow.by_ulid.get(ulid.as_str()) {
                    if ids.iter().any(|id| !cleared.contains(id)) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// #718: a zero-match `find` over a vault with skipped encrypted records
/// must not read as "not in the vault". When no hit was found and at least
/// one encrypted record could not be searched, append a warning finding
/// carrying the count and the remedy, in-band with the other findings —
/// so JSON callers branch on `W_SKIPPED_ENCRYPTED` instead of gliding
/// past the `skipped_encrypted` count. Deliberately empty-only: a
/// non-empty result already shows the search found something, and the
/// count field still reports the skips. Refused (tampered) envelopes are
/// not folded in — they are a different, already-counted condition.
/// No vault content goes into the message: only the count.
fn with_skipped_encrypted_warning(
    mut findings: Vec<Finding>,
    empty: bool,
    skipped_encrypted: u32,
) -> Vec<Finding> {
    if empty && skipped_encrypted > 0 {
        let message = if skipped_encrypted == 1 {
            "1 encrypted record was not searched; this result does not establish \
             absence — try `resolve`/`context`, or build the search corpus with `reindex`."
                .to_owned()
        } else {
            format!(
                "{skipped_encrypted} encrypted records were not searched; this result \
                 does not establish absence — try `resolve`/`context`, or build the \
                 search corpus with `reindex`."
            )
        };
        findings.push(Finding::new(
            FindingCode::SkippedEncrypted,
            Severity::Warning,
            message,
        ));
        sort_findings(&mut findings);
    }
    findings
}

fn findings_for_find(allow: &Allowlist<'_>) -> Vec<Finding> {
    let mut kept = Vec::new();
    let mut redacted: BTreeMap<FindingCode, (Severity, usize)> = BTreeMap::new();
    for finding in &allow.vault.load_findings {
        if finding_kept_verbatim(finding, allow) {
            kept.push(finding.clone());
        } else {
            let entry = redacted
                .entry(finding.code)
                .or_insert((finding.severity, 0));
            entry.0 = entry.0.max(finding.severity);
            entry.1 += 1;
        }
    }
    for (code, (severity, count)) in redacted {
        kept.push(Finding::new(code, severity, format!("{count} items")));
    }
    sort_findings(&mut kept);
    kept
}

fn finding_kept_verbatim(finding: &Finding, allow: &Allowlist<'_>) -> bool {
    if finding.file.is_none() && finding.id.is_none() {
        return true;
    }
    if let (Some(file), Some(line)) = (finding.file.as_deref(), finding.line) {
        if let Some(&idx) = allow.ledger_at.get(&(file, line)) {
            if !allow.ledger_ok.get(idx).copied().unwrap_or(false) {
                return false;
            }
            // #178: a finding on an out-of-scope ledger line is redacted
            // to code + count like any other non-verbatim finding.
            let text = &allow.vault.ledger_lines[idx].text;
            return allow
                .scope
                .allows(&owners_of_ledger_text(text, &allow.enabled));
        }
    }
    if let Some(file) = finding.file.as_deref() {
        if let Some(id) = allow.by_path.get(file) {
            if !allow.cleared.contains(id) {
                return false;
            }
            let rec = &allow.vault.records[id];
            return allow
                .scope
                .allows(&record_owners(rec, &allow.linkage, &allow.enabled));
        }
        return false;
    }
    if let Some(raw) = finding.id.as_deref() {
        if let Ok(id) = RecordId::parse(raw) {
            if let Some(rec) = allow.vault.records.get(&id) {
                return allow.cleared.contains(&id)
                    && allow
                        .scope
                        .allows(&record_owners(rec, &allow.linkage, &allow.enabled));
            }
        }
    }
    false
}

/// Operator-path tri-state `no-ai` badge (#572) for one record.
///
/// The record's own mode wins (`"true"` / `"notes"` / `"false"`). With no
/// explicit flag, `"true"` when the agent allowlist hides it while the
/// operator allowlist does not (an inherited `no-ai`), else `"false"`.
pub fn operator_no_ai_badge(
    rec: &crate::record::Record,
    hidden_by_no_ai: &HashSet<RecordId>,
) -> &'static str {
    match rec.no_ai_mode() {
        Some(mode) => mode.as_str(),
        None if hidden_by_no_ai.contains(&rec.id) => "true",
        None => "false",
    }
}

fn scan_record(
    rec: &crate::record::Record,
    needle: &str,
    allow: &Allowlist<'_>,
    hits: &mut Vec<SearchHit>,
) {
    let Some(facts) = allow.facts.get(&rec.id) else {
        return;
    };
    // Body lines share the record's owners; front-matter lines filter
    // per-field (#178). Computed once: the body owner set.
    let body_owners = record_owners(rec, &allow.linkage, &allow.enabled);
    let body_visible = allow.scope.allows(&body_owners);
    // #178 fix round (Silas review on #246): notes and interactions are
    // visible as whole records only. Per-field front-matter filtering
    // applies to the core anchors (person/org/deal); an out-of-scope or
    // unattributed note/interaction contributes no lines at all, front
    // matter included — otherwise its `id`/`type`/`date`/`person`/`name`
    // lines would leak its existence through `find`. Edges (#179) are
    // whole records the same way: their visibility is decided entirely
    // by the kind's pack, and the front matter has no pack-owned fields
    // to filter.
    if matches!(
        rec.kind,
        RecordKind::Note | RecordKind::Interaction | RecordKind::Edge
    ) && !body_visible
    {
        return;
    }
    let text = rec.source.trim_start_matches('\u{feff}');
    for ((line_no, toks), line) in facts.line_tokens.iter().zip(text.lines()) {
        if !tokens_allowed(toks, allow) {
            continue;
        }
        if *line_no < facts.body_start_line {
            // Front matter: one field per line. Fences / comments / blank
            // lines have no key and are core (not content).
            if let Some(key) = front_matter_key(line) {
                let visible = match owner_of_field(&key, &allow.enabled) {
                    Some(owner) => allow.scope.allows(&[owner].into_iter().collect()),
                    None => matches!(allow.scope, PackScope::All),
                };
                if !visible {
                    continue;
                }
            }
        } else if !body_visible {
            continue;
        }
        let folded = case_fold(line);
        if folded.contains(needle) {
            hits.push(SearchHit {
                id: Some(rec.id.to_string()),
                path: rec.path.clone(),
                line: *line_no,
                excerpt: excerpt(line.trim(), 200),
                // Operator mode (#572) badges every record hit: a cleared
                // record is `"false"`, a `no-ai: notes` person is
                // `"notes"`, a hidden record is `"true"`. Agent mode never
                // sets this, so its JSON is unchanged.
                no_ai: allow
                    .operator
                    .then(|| operator_no_ai_badge(rec, &allow.no_ai_hidden)),
                // `operator_only` is the ledger-line marker; record hits
                // already carry `no_ai`.
                operator_only: None,
            });
        }
    }
}

/// Front-matter key on one source line, if it is a `key: value` line.
/// Returns `None` for fences, comments, blank lines, and lines without a
/// colon. The key is unquoted with the parser's `unquote` (one source of
/// truth — `trim_matches` would strip a lone trailing quote and read
/// `name"` as core `name`, where the parser reads it as unattributed).
fn front_matter_key(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (key, _) = trimmed.split_once(':')?;
    let key = unquote(key.trim());
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// Practical Unicode caseless matching: lowercasing plus ß/ẞ → ss and İ → i.
pub(crate) fn case_fold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'İ' => out.push('i'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

fn excerpt(line: &str, max: usize) -> String {
    let mut out: String = line.chars().take(max).collect();
    if line.chars().count() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{case_fold, excerpt, pkg_open_lines, still_cleared, Allowlist};
    use crate::{
        cleared_ledger_line_owners, cleared_record_owners, search, search_for_operator, OwnerKey,
        PackScope,
    };

    #[test]
    fn excerpt_truncates() {
        let s = excerpt("abcdefghijklmnopqrstuvwxyz", 5);
        assert_eq!(s, "abcde…");
    }

    #[test]
    fn unicode_case_folding() {
        assert!(case_fold("İstanbul Café").contains(&case_fold("café")));
        assert!(case_fold("Straße").contains(&case_fold("STRASSE")));
        assert!(case_fold("STRASSE").contains(&case_fold("straße")));
        assert_eq!(case_fold("ß"), "ss");
    }

    fn assert_fixed_point(vault: &crate::vault::Vault) {
        let allow = Allowlist::build(vault, &PackScope::All);
        let tainted = super::tainted_ids(vault);
        let components = super::merge_components(&allow);
        let open_lines = super::pkg_open_lines(&allow);
        for id in &allow.cleared {
            assert!(
                still_cleared(
                    &allow,
                    id,
                    &allow.cleared,
                    &tainted,
                    &components,
                    &open_lines
                ),
                "{id} is cleared but still_cleared is false"
            );
        }
        for rec in vault.records.values() {
            if !allow.cleared.contains(&rec.id) {
                continue;
            }
            let Some(facts) = allow.facts.get(&rec.id) else {
                continue;
            };
            for fid in &facts.fm_ids {
                if vault.records.contains_key(fid) || fid.prefix() == super::Prefix::Package {
                    assert!(
                        allow.cleared.contains(fid),
                        "{} front matter names uncleared {fid}",
                        rec.id
                    );
                }
            }
            if let Some(members) = components.members_of(&rec.id) {
                for m in members {
                    if vault.records.contains_key(m) || m.prefix() == super::Prefix::Package {
                        assert!(
                            allow.cleared.contains(m),
                            "{} merge peer {m} is uncleared",
                            rec.id
                        );
                    }
                }
            }
        }
        for line in &open_lines {
            for pkg in &line.pkgs {
                if allow.cleared.contains(pkg) {
                    for person in &line.people {
                        assert!(
                            allow.cleared.contains(person),
                            "cleared {pkg} opened by uncleared {person}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn demo_vault_allowlist_is_a_fixed_point() {
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault");
        let vault = crate::vault::load_vault(&root).unwrap();
        assert_fixed_point(&vault);
    }

    fn example_pack_vault() -> (tempfile::TempDir, crate::vault::Vault) {
        let dir = tempfile::tempdir().unwrap();
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/packs/example-pack");
        let dst = dir.path().join("packs/example-pack@0.1");
        std::fs::create_dir_all(&dst).unwrap();
        for entry in std::fs::read_dir(&src).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
        let hash = crate::packs::dir::read_pack_dir(&dst).unwrap().hash;
        std::fs::write(
            dir.path().join("confidant.lock"),
            format!(
                "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"example-pack@0.1\"]\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let ada = "p-01M3TC5H00MPJG000000000000";
        let cam = "p-01M3TC5H00MPJG001248000002";
        std::fs::create_dir_all(dir.path().join("people").join(ada).join("notes")).unwrap();
        std::fs::create_dir_all(dir.path().join("people").join(cam).join("notes")).unwrap();
        std::fs::write(
            dir.path().join("people").join(ada).join("profile.md"),
            format!("---\nid: {ada}\ntype: person\nname: Ada Example\n---\n\nFake person.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(cam).join("profile.md"),
            format!("---\nid: {cam}\ntype: person\nname: Cam Sample\nno-ai: true\n---\n\nHidden person.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(ada).join("notes/n-01M3TC5H00MPJG002NAM000005.md"),
            format!("---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: {ada}\ndate: 2026-10-02\n---\n\nKickofftoken note.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(ada).join("notes/n-01M3TC5H00MPJG0036CR000006.md"),
            format!("---\nid: n-01M3TC5H00MPJG0036CR000006\ntype: note\nperson: {ada}\ndate: 2026-10-04\n---\n\nFollowuptoken note.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("people").join(cam).join("notes/n-01M3TC5H000068T0000000000C.md"),
            format!("---\nid: n-01M3TC5H000068T0000000000C\ntype: note\nperson: {cam}\ndate: 2026-10-07\n---\n\nCam asked that notes never go to a model provider.\n"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("interactions/i-01M3TC5H00MPJG0048H0000008"))
            .unwrap();
        std::fs::write(
            dir.path().join("interactions/i-01M3TC5H00MPJG0048H0000008/interaction.md"),
            format!("---\nid: i-01M3TC5H00MPJG0048H0000008\ntype: interaction\nname: Intro call\ndate: 2026-10-01\nperson: {ada}\n---\n\nFake intro call body.\n"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("deals/d-01M3TC5H00MPJG00248G000004")).unwrap();
        std::fs::write(
            dir.path().join("deals/d-01M3TC5H00MPJG00248G000004/deal.md"),
            "---\nid: d-01M3TC5H00MPJG00248G000004\ntype: deal\nname: Example deal\n---\n\nFake deal.\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            format!(
                "2026-10-01 grant {ada} package pkg-01M3TC5H00MPJG004SK4000009 4 sessions\n2026-10-02 use {ada} 60m full note:n-01M3TC5H00MPJG002NAM000005\n2026-10-03 balance {ada} units_remaining 3\n2026-10-04 stage d-01M3TC5H00MPJG00248G000004 proposal\n2026-10-05 touch {ada} meeting note:n-01M3TC5H00MPJG0036CR000006\n2026-10-06 alias {ada} email hmac:6f2c9a1d8b7e4f301122334455667788\n2026-10-07 touch {cam} message note:n-01M3TC5H000068T0000000000C\n"
            ),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        (dir, vault)
    }

    fn example_scope() -> PackScope {
        PackScope::Only(["example-pack@0.1".to_string()].into_iter().collect())
    }

    #[test]
    fn scoped_search_filters_by_pack_ownership() {
        // "Kickoff" is in the pack-linked note;
        // "Follow-up" is in the unattributed note; "Fake intro call" is in
        // the unattributed interaction body.
        let (_dir, vault) = example_pack_vault();
        let scoped = example_scope();
        let kickoff = search(&vault, "Kickofftoken", &scoped).unwrap();
        assert_eq!(kickoff.hits.len(), 1);
        assert!(kickoff.hits[0].path.contains("002NAM000005"));

        let followup = search(&vault, "Followuptoken", &scoped).unwrap();
        assert!(followup.hits.is_empty());
        let followup_all = search(&vault, "Followuptoken", &PackScope::All).unwrap();
        assert_eq!(followup_all.hits.len(), 1);

        let intro_body = search(&vault, "Fake intro call", &scoped).unwrap();
        assert!(intro_body.hits.is_empty());
        // #246 fix round: the unattributed interaction's `name:` line no
        // longer leaks through per-field filtering — notes and
        // interactions contribute no lines at all when out of scope.
        let intro_name = search(&vault, "Intro call", &scoped).unwrap();
        assert!(intro_name.hits.is_empty());

        // The unattributed note is undiscoverable under a pack-only scope:
        // not by its id, and not via its `type: note` front-matter line.
        // (`type: note` still matches the in-scope pack note's own
        // line — that record is legitimately visible — so assert the
        // unattributed note's path is absent, not zero hits.)
        let by_id = search(&vault, "n-01M3TC5H00MPJG0036CR000006", &scoped).unwrap();
        assert!(by_id.hits.is_empty());
        let by_type = search(&vault, "type: note", &scoped).unwrap();
        assert!(
            by_type
                .hits
                .iter()
                .all(|h| !h.path.contains("0036CR000006")),
            "unattributed note leaked via its `type:` line: {:?}",
            by_type.hits
        );
    }

    #[test]
    fn scoped_search_keeps_pack_and_core_ledger_lines() {
        // Balance lines are owned by their metric's pack; `stage` is core.
        let (_dir, vault) = example_pack_vault();
        let scoped = example_scope();
        let balance = search(&vault, "units_remaining", &scoped).unwrap();
        assert!(!balance.hits.is_empty());
        assert!(balance.hits.iter().all(|h| h.path.contains("10.cfd")));
        // `stage` is core-owned: it stays visible under a pack-only scope.
        let stage = search(&vault, "proposal", &scoped).unwrap();
        assert!(!stage.hits.is_empty(), "{stage:?}");
    }

    #[test]
    fn package_clearing_uses_declared_opener_verbs() {
        let (dir, _) = example_pack_vault();
        let root = dir.path();
        let mut ledger = std::fs::read_to_string(root.join("ledger/2026/10.cfd")).unwrap();
        ledger.push_str(
            "2026-10-09 touch p-01M3TC5H00MPJG001248000002 package pkg-01M3TC5H00MPJG009ZZ000000 note:n-01M3TC5H000068T0000000000C\n",
        );
        std::fs::write(root.join("ledger/2026/10.cfd"), ledger).unwrap();
        let vault = crate::vault::load_vault(root).unwrap();
        let allow = Allowlist::build(&vault, &PackScope::All);
        let verbs: Vec<&str> = allow
            .enabled
            .iter()
            .flat_map(|p| p.balance_open_verbs().iter().copied())
            .collect();
        assert_eq!(
            verbs,
            vec!["grant"],
            "enabled: {:?}",
            allow.enabled.iter().map(|p| p.name()).collect::<Vec<_>>()
        );
        let lines = pkg_open_lines(&allow);
        assert_eq!(lines.len(), 1);
        assert!(lines[0]
            .pkgs
            .iter()
            .any(|p| p.to_string().contains("004SK")));
        // A non-opener line naming a package (here on a no-ai person) must
        // not open it or clear it.
        assert!(!lines[0]
            .pkgs
            .iter()
            .any(|p| p.to_string().contains("009ZZ")));
        assert!(!lines[0]
            .people
            .iter()
            .any(|p| p.to_string().contains("001248")));
    }

    #[test]
    fn allowlist_owners_cover_records_and_ledger_lines() {
        let (_dir, vault) = example_pack_vault();
        let records = cleared_record_owners(&vault);
        // Ada's profile is core; the linked note is example-pack-owned;
        // the unattributed note has no owners.
        assert_eq!(
            records.get("people/p-01M3TC5H00MPJG000000000000/profile.md"),
            Some(&[OwnerKey::Core].into_iter().collect())
        );
        assert_eq!(
            records
                .get("people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md"),
            Some(&[OwnerKey::Pack("example-pack@0.1")].into_iter().collect())
        );
        // The second note is linked from a core `touch` line, so the
        // implicit personal pack owns it.
        assert_eq!(
            records
                .get("people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG0036CR000006.md"),
            Some(&[OwnerKey::Pack("personal@0.2")].into_iter().collect())
        );
        let lines = cleared_ledger_line_owners(&vault);
        // The balance line is pack-owned; `stage`/`touch` lines are core.
        assert!(lines.iter().any(|(f, _, o)| f.contains("10.cfd")
            && o == &[OwnerKey::Pack("example-pack@0.1")].into_iter().collect()));
        assert!(
            lines
                .iter()
                .any(|(f, _, o)| f.contains("10.cfd")
                    && o == &[OwnerKey::Core].into_iter().collect()),
            "a core-owned ledger line must stay cleared: {lines:?}"
        );
    }

    /// #572: the operator search is the agent search plus everything hidden
    /// only by `no-ai`, and every operator record hit carries the tri-state
    /// badge. The agent path is unchanged and never sets `no_ai`.
    #[test]
    fn operator_search_includes_no_ai_records_with_badge() {
        let (_dir, vault) = example_pack_vault();
        // "model provider" is only in Cam Sample's note body (Cam is
        // `no-ai: true`, so the note inherits hidden).
        let agent = search(&vault, "model provider", &PackScope::All).unwrap();
        assert!(agent.hits.is_empty(), "{:?}", agent.hits);
        assert!(agent.hits.iter().all(|h| h.no_ai.is_none()));

        let op = search_for_operator(&vault, "model provider", &PackScope::All).unwrap();
        let hit = op
            .hits
            .iter()
            .find(|h| h.id.as_deref() == Some("n-01M3TC5H000068T0000000000C"))
            .unwrap_or_else(|| panic!("no-ai note must be an operator hit: {:?}", op.hits));
        // The note has no explicit flag; it is hidden by inheritance, and
        // the badge says so.
        assert_eq!(hit.no_ai, Some("true"));

        // A cleared record hit is badged `"false"` in operator mode, and
        // the agent path never gains the key.
        let op_ada = search_for_operator(&vault, "Ada Example", &PackScope::All).unwrap();
        assert!(op_ada.hits.iter().any(|h| h.no_ai == Some("false")));
        let agent_ada = search(&vault, "Ada Example", &PackScope::All).unwrap();
        assert!(!agent_ada.hits.is_empty());
        assert!(agent_ada.hits.iter().all(|h| h.no_ai.is_none()));

        // A ledger line that only references the no-ai person also becomes
        // searchable under the operator allowlist (no record badge).
        let op_ledger = search_for_operator(&vault, "2026-10-07", &PackScope::All).unwrap();
        assert!(op_ledger
            .hits
            .iter()
            .any(|h| h.path.starts_with("ledger/") && h.no_ai.is_none()));
    }

    /// #593: the operator-only marker is for ledger hits the agent allowlist
    /// hides. A ledger hit an agent can see too stays unmarked, and record
    /// hits keep the tri-state `no_ai` (never the ledger marker).
    #[test]
    fn operator_ledger_hits_mark_only_operator_only_lines() {
        let (_dir, vault) = example_pack_vault();
        // `2026-10-07 session <Cam> ... note:<Cam's note>` is hidden from
        // agents: the person is `no-ai: true` and the note inherits it.
        let agent = search(&vault, "2026-10-07", &PackScope::All).unwrap();
        assert!(agent.hits.is_empty(), "{:?}", agent.hits);

        let operator = search_for_operator(&vault, "2026-10-07", &PackScope::All).unwrap();
        let ledger = operator
            .hits
            .iter()
            .find(|h| h.path.starts_with("ledger/"))
            .unwrap_or_else(|| {
                panic!(
                    "Cam's session line must be an operator hit: {:?}",
                    operator.hits
                )
            });
        assert_eq!(ledger.operator_only, Some(true));
        assert!(ledger.no_ai.is_none());
        // The note's front-matter date is a record hit: tri-state `no_ai`,
        // no ledger marker.
        let record = operator
            .hits
            .iter()
            .find(|h| h.id.as_deref() == Some("n-01M3TC5H000068T0000000000C"))
            .expect("the no-ai note must be an operator hit");
        assert_eq!(record.no_ai, Some("true"));
        assert_eq!(record.operator_only, None);

        // A stage line naming a cleared deal is visible to agents too, so
        // the operator path does not mark it.
        let agent_alias = search(&vault, "meeting", &PackScope::All).unwrap();
        assert!(agent_alias
            .hits
            .iter()
            .any(|h| h.path.starts_with("ledger/")));
        assert!(agent_alias.hits.iter().all(|h| h.operator_only.is_none()));
        let operator_alias = search_for_operator(&vault, "meeting", &PackScope::All).unwrap();
        let visible: Vec<_> = operator_alias
            .hits
            .iter()
            .filter(|h| h.path.starts_with("ledger/"))
            .collect();
        assert!(!visible.is_empty());
        assert!(visible.iter().all(|h| h.operator_only.is_none()));
    }
}
