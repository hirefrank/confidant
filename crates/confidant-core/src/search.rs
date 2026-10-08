//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::check::{sort_findings, Finding, FindingCode, Severity};
use crate::error::DomainError;
use crate::id::{person_id_from_path, scan_id_tokens_against, scan_ids, IdToken, Prefix, RecordId};
use crate::ledger::ledger_line_verb;
use crate::record::{parse_ref_id, FrontmatterRef};
use crate::vault::Vault;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SearchHit {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub path: String,
    pub line: u32,
    pub excerpt: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub findings: Vec<Finding>,
}

struct RecordFacts {
    fm_ids: Vec<RecordId>,
    fm_malformed: bool,
    fm_bad_ref: bool,
    fm_bare_ulids: Vec<String>,
    path_person: Option<RecordId>,
    /// Tokenized once from BOM-stripped source; 1-based line numbers.
    line_tokens: Vec<(u32, Vec<IdToken>)>,
}

/// Indexes built once per search so the allowlist is a worklist, not nested scans.
struct Allowlist<'a> {
    vault: &'a Vault,
    cleared: HashSet<RecordId>,
    facts: HashMap<RecordId, RecordFacts>,
    by_path: HashMap<&'a str, &'a RecordId>,
    by_ulid: HashMap<String, Vec<RecordId>>,
    ledger_at: HashMap<(&'a str, u32), usize>,
    ledger_tokens: Vec<Vec<IdToken>>,
    named_ledger_lines: HashMap<RecordId, Vec<usize>>,
    ledger_ok: Vec<bool>,
}

/// Unicode case-insensitive substring scan. Hits are ordered by path, then line.
/// Line numbers are 1-based positions in the original file.
/// Returns content only from the cleared allowlist (spec section 12).
/// If any ledger file was unreadable, returns [`DomainError`] `E_LEDGER_UNREADABLE`
/// and no hits.
pub fn search(vault: &Vault, query: &str) -> Result<SearchResult, DomainError> {
    if vault.ledger_unread_count > 0 {
        return Err(DomainError::ledger_unreadable(vault.ledger_unread_count));
    }
    let needle = case_fold(query);
    let allow = Allowlist::build(vault);
    let findings = findings_for_find(&allow);
    if needle.is_empty() {
        return Ok(SearchResult {
            hits: Vec::new(),
            findings,
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
        let folded = case_fold(&line.text);
        if folded.contains(&needle) {
            hits.push(SearchHit {
                id: line.id.clone(),
                path: line.file.clone(),
                line: line.line,
                excerpt: excerpt(line.text.trim(), 200),
            });
        }
    }
    hits.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    Ok(SearchResult { hits, findings })
}

impl<'a> Allowlist<'a> {
    fn build(vault: &'a Vault) -> Self {
        let mut by_path = HashMap::with_capacity(vault.records.len());
        for rec in vault.records.values() {
            by_path.insert(rec.path.as_str(), &rec.id);
        }
        let mut ledger_at = HashMap::with_capacity(vault.ledger_lines.len());
        for (idx, line) in vault.ledger_lines.iter().enumerate() {
            ledger_at.insert((line.file.as_str(), line.line), idx);
        }
        let mut by_ulid: HashMap<String, Vec<RecordId>> = HashMap::new();
        for id in vault.records.keys() {
            by_ulid
                .entry(id.ulid().to_owned())
                .or_default()
                .push(id.clone());
        }
        for id in &vault.path_ids {
            let entry = by_ulid.entry(id.ulid().to_owned()).or_default();
            if !entry.contains(id) {
                entry.push(id.clone());
            }
        }
        let vault_ulids: HashSet<String> = by_ulid.keys().cloned().collect();
        let mut facts = HashMap::with_capacity(vault.records.len());
        for rec in vault.records.values() {
            facts.insert(rec.id.clone(), record_facts(rec, &vault_ulids));
        }
        let ledger_tokens: Vec<Vec<IdToken>> = vault
            .ledger_lines
            .iter()
            .map(|line| scan_id_tokens_against(&line.text, Some(&vault_ulids)))
            .collect();
        let mut named_ledger_lines: HashMap<RecordId, Vec<usize>> = HashMap::new();
        for (idx, toks) in ledger_tokens.iter().enumerate() {
            for tok in toks {
                for id in ids_named_by(tok, &by_ulid) {
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
            ledger_at,
            ledger_tokens,
            named_ledger_lines,
            ledger_ok: Vec::new(),
        };
        allow.cleared = compute_cleared(&allow);
        allow.ledger_ok = allow
            .vault
            .ledger_lines
            .iter()
            .zip(allow.ledger_tokens.iter())
            .map(|(line, toks)| {
                line.searchable && tokens_allowed(toks, &allow.cleared, &allow.by_ulid)
            })
            .collect();
        allow
    }
}

fn compute_cleared(allow: &Allowlist<'_>) -> HashSet<RecordId> {
    let vault = allow.vault;
    let tainted = tainted_ids(vault);
    let components = merge_components(allow);
    let (pkg_openers, person_pkgs) = pkg_openers(allow);
    let dependents = reverse_deps(allow, &pkg_openers);

    let mut cleared: HashSet<RecordId> = vault
        .records
        .values()
        .filter(|rec| !rec.no_ai() && !tainted.contains(&rec.id))
        .filter(|rec| rec.person().is_none_or(|person| !tainted.contains(&person)))
        .map(|rec| rec.id.clone())
        .collect();

    for (pkg, openers) in &pkg_openers {
        if pkg_is_clear(openers, &cleared) {
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
        if still_cleared(allow, &id, &cleared, &tainted, &components, &pkg_openers) {
            continue;
        }
        drop_from_cleared(
            &id,
            &mut cleared,
            &components,
            &person_pkgs,
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
    pkg_openers: &HashMap<RecordId, Vec<RecordId>>,
) -> bool {
    if id.prefix() == Prefix::Package {
        return pkg_openers
            .get(id)
            .is_some_and(|openers| pkg_is_clear(openers, cleared));
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
    if facts.fm_ids.iter().any(|fid| !cleared.contains(fid)) {
        return false;
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
    if facts.fm_bare_ulids.iter().any(|ulid| {
        allow
            .by_ulid
            .get(ulid)
            .is_some_and(|ids| ids.iter().any(|fid| !cleared.contains(fid)))
    }) {
        return false;
    }
    if let Some(idxs) = allow.named_ledger_lines.get(id) {
        if idxs
            .iter()
            .any(|&idx| !tokens_allowed(&allow.ledger_tokens[idx], cleared, &allow.by_ulid))
        {
            return false;
        }
    }
    true
}

fn drop_from_cleared(
    id: &RecordId,
    cleared: &mut HashSet<RecordId>,
    components: &MergeComponents,
    person_pkgs: &HashMap<RecordId, Vec<RecordId>>,
    dependents: &HashMap<RecordId, HashSet<RecordId>>,
    stack: &mut Vec<RecordId>,
    queued: &mut HashSet<RecordId>,
) {
    let mut dropping = vec![id.clone()];
    if let Some(members) = components.members_of(id) {
        dropping.extend(members.iter().cloned());
    }
    if let Some(pkgs) = person_pkgs.get(id) {
        dropping.extend(pkgs.iter().cloned());
    }
    for dropped in dropping {
        if !cleared.remove(&dropped) {
            continue;
        }
        if let Some(deps) = dependents.get(&dropped) {
            for dep in deps {
                if cleared.contains(dep) && queued.insert(dep.clone()) {
                    stack.push(dep.clone());
                }
            }
        }
    }
}

fn pkg_is_clear(openers: &[RecordId], cleared: &HashSet<RecordId>) -> bool {
    !openers.is_empty() && openers.iter().all(|person| cleared.contains(person))
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
            .flat_map(|tok| ids_named_by(tok, &allow.by_ulid))
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
    MergeComponents { of, members }
}

fn pkg_openers(
    allow: &Allowlist<'_>,
) -> (
    HashMap<RecordId, Vec<RecordId>>,
    HashMap<RecordId, Vec<RecordId>>,
) {
    let mut pkg_openers: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    let mut person_pkgs: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    for (line, toks) in allow
        .vault
        .ledger_lines
        .iter()
        .zip(allow.ledger_tokens.iter())
    {
        if ledger_line_verb(&line.text).as_deref() != Some("open") {
            continue;
        }
        let mut people = Vec::new();
        let mut pkgs = Vec::new();
        for id in toks
            .iter()
            .flat_map(|tok| ids_named_by(tok, &allow.by_ulid))
        {
            match id.prefix() {
                Prefix::Person => people.push(id.clone()),
                Prefix::Package => pkgs.push(id.clone()),
                Prefix::Org | Prefix::Deal | Prefix::Interaction | Prefix::Note => {}
            }
        }
        for pkg in &pkgs {
            for person in &people {
                let openers = pkg_openers.entry(pkg.clone()).or_default();
                if !openers.contains(person) {
                    openers.push(person.clone());
                }
                let person_pkgs_for = person_pkgs.entry(person.clone()).or_default();
                if !person_pkgs_for.contains(pkg) {
                    person_pkgs_for.push(pkg.clone());
                }
            }
        }
    }
    (pkg_openers, person_pkgs)
}

fn reverse_deps(
    allow: &Allowlist<'_>,
    pkg_openers: &HashMap<RecordId, Vec<RecordId>>,
) -> HashMap<RecordId, HashSet<RecordId>> {
    let mut dependents: HashMap<RecordId, HashSet<RecordId>> = HashMap::new();
    let mut link = |from: RecordId, to: RecordId| {
        dependents.entry(from).or_default().insert(to);
    };
    for rec in allow.vault.records.values() {
        if let Some(facts) = allow.facts.get(&rec.id) {
            for id in &facts.fm_ids {
                link(id.clone(), rec.id.clone());
            }
            for ulid in &facts.fm_bare_ulids {
                if let Some(ids) = allow.by_ulid.get(ulid) {
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
    for (pkg, openers) in pkg_openers {
        for person in openers {
            link(person.clone(), pkg.clone());
        }
    }
    for (named, idxs) in &allow.named_ledger_lines {
        for &idx in idxs {
            for tok in &allow.ledger_tokens[idx] {
                for id in ids_named_by(tok, &allow.by_ulid) {
                    link(id.clone(), named.clone());
                }
            }
        }
    }
    dependents
}

fn record_facts(rec: &crate::record::Record, vault_ulids: &HashSet<String>) -> RecordFacts {
    let text = rec.source.trim_start_matches('\u{feff}');
    let mut fm_ids = Vec::new();
    let mut fm_malformed = false;
    let mut fm_bare_ulids = Vec::new();
    let mut line_tokens = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let toks = scan_id_tokens_against(line, Some(vault_ulids));
        if line_no < rec.body_start_line {
            for tok in &toks {
                match tok {
                    IdToken::Malformed { .. } => fm_malformed = true,
                    IdToken::Valid(id) => fm_ids.push(id.clone()),
                    IdToken::BareUlid(ulid) => fm_bare_ulids.push(ulid.clone()),
                }
            }
        }
        line_tokens.push((line_no, toks));
    }
    let fm_bad_ref = ["person", "org", "deal"].iter().any(|key| {
        rec.field(key)
            .is_some_and(|raw| matches!(parse_ref_id(raw), FrontmatterRef::Invalid))
    });
    RecordFacts {
        fm_ids,
        fm_malformed,
        fm_bad_ref,
        fm_bare_ulids,
        path_person: person_id_from_path(&rec.path),
        line_tokens,
    }
}

fn ledger_named_prefix(prefix: Prefix) -> bool {
    match prefix {
        Prefix::Note | Prefix::Interaction | Prefix::Deal => true,
        Prefix::Person | Prefix::Org | Prefix::Package => false,
    }
}

fn ids_named_by<'a>(
    tok: &'a IdToken,
    by_ulid: &'a HashMap<String, Vec<RecordId>>,
) -> Vec<&'a RecordId> {
    let mut ids: Vec<&RecordId> = tok.record_ids().collect();
    if let Some(ulid) = tok.bare_ulid() {
        if let Some(matched) = by_ulid.get(ulid) {
            ids.extend(matched.iter());
        }
    }
    ids
}

fn tokens_allowed(
    toks: &[IdToken],
    cleared: &HashSet<RecordId>,
    by_ulid: &HashMap<String, Vec<RecordId>>,
) -> bool {
    for tok in toks {
        match tok {
            IdToken::Malformed { .. } => return false,
            IdToken::Valid(id) => {
                if !cleared.contains(id) {
                    return false;
                }
            }
            IdToken::BareUlid(ulid) => {
                if let Some(ids) = by_ulid.get(ulid) {
                    if ids.iter().any(|id| !cleared.contains(id)) {
                        return false;
                    }
                }
            }
        }
    }
    true
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
            return allow.ledger_ok.get(idx).copied().unwrap_or(false);
        }
    }
    if let Some(file) = finding.file.as_deref() {
        if let Some(id) = allow.by_path.get(file) {
            return allow.cleared.contains(id);
        }
        return false;
    }
    if let Some(raw) = finding.id.as_deref() {
        if let Ok(id) = RecordId::parse(raw) {
            return allow.vault.records.contains_key(&id) && allow.cleared.contains(&id);
        }
    }
    false
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
    let text = rec.source.trim_start_matches('\u{feff}');
    for ((line_no, toks), line) in facts.line_tokens.iter().zip(text.lines()) {
        if !tokens_allowed(toks, &allow.cleared, &allow.by_ulid) {
            continue;
        }
        let folded = case_fold(line);
        if folded.contains(needle) {
            hits.push(SearchHit {
                id: Some(rec.id.to_string()),
                path: rec.path.clone(),
                line: *line_no,
                excerpt: excerpt(line.trim(), 200),
            });
        }
    }
}

/// Practical Unicode caseless matching: lowercasing plus ß/ẞ → ss and İ → i.
fn case_fold(s: &str) -> String {
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
    use super::{case_fold, excerpt};

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
}
