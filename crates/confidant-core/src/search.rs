//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::check::{parse_merge, sort_findings, Finding, FindingCode, MergeParse, Severity};
use crate::id::{person_id_from_path, scan_id_tokens, scan_ids, IdToken, Prefix, RecordId};
use crate::vault::{SourcedEntry, Vault};

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
    malformed: bool,
    path_person: Option<RecordId>,
}

/// Indexes built once per search so the allowlist is a worklist, not nested scans.
struct Allowlist<'a> {
    vault: &'a Vault,
    cleared: HashSet<RecordId>,
    facts: HashMap<RecordId, RecordFacts>,
    by_path: HashMap<&'a str, &'a RecordId>,
    ledger_at: HashMap<(&'a str, u32), usize>,
    entries_at: HashMap<(&'a str, u32), usize>,
    ledger_ok: Vec<bool>,
}

/// Unicode case-insensitive substring scan. Hits are ordered by path, then line.
/// Line numbers are 1-based positions in the original file.
/// Returns content only from the cleared allowlist (spec section 12).
pub fn search(vault: &Vault, query: &str) -> SearchResult {
    let needle = case_fold(query);
    let allow = Allowlist::build(vault);
    let findings = findings_for_find(&allow);
    if needle.is_empty() {
        return SearchResult {
            hits: Vec::new(),
            findings,
        };
    }
    let mut hits = Vec::new();
    for rec in vault.records.values() {
        if !allow.cleared.contains(&rec.id) {
            continue;
        }
        scan_record(rec, &needle, &allow.cleared, &mut hits);
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
    SearchResult { hits, findings }
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
        let mut entries_at = HashMap::with_capacity(vault.entries.len());
        for (idx, sourced) in vault.entries.iter().enumerate() {
            entries_at.insert((sourced.file.as_str(), sourced.line), idx);
        }
        let mut facts = HashMap::with_capacity(vault.records.len());
        for rec in vault.records.values() {
            facts.insert(rec.id.clone(), record_facts(rec));
        }
        let mut allow = Self {
            vault,
            cleared: HashSet::new(),
            facts,
            by_path,
            ledger_at,
            entries_at,
            ledger_ok: Vec::new(),
        };
        allow.cleared = compute_cleared(&allow);
        allow.ledger_ok = vault
            .ledger_lines
            .iter()
            .map(|line| ids_allowed(&line.text, &allow.cleared))
            .collect();
        allow
    }

    fn entry_at(&self, file: &str, line: u32) -> Option<&'a SourcedEntry> {
        let idx = *self.entries_at.get(&(file, line))?;
        self.vault.entries.get(idx)
    }
}

fn compute_cleared(allow: &Allowlist<'_>) -> HashSet<RecordId> {
    let vault = allow.vault;
    let tainted = tainted_ids(vault);
    let components = merge_components(vault);
    let (pkg_openers, person_pkgs) = pkg_openers(vault);
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
    if facts.malformed {
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
    true
}

fn drop_from_cleared(
    id: &RecordId,
    cleared: &mut HashSet<RecordId>,
    components: &MergeComponents,
    person_pkgs: &HashMap<RecordId, Vec<RecordId>>,
    dependents: &HashMap<RecordId, Vec<RecordId>>,
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
                tainted.insert(rid);
            }
        }
        if let Some(file) = &finding.file {
            tainted.extend(scan_ids(file));
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

fn merge_components(vault: &Vault) -> MergeComponents {
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

    for rec in vault.records.values() {
        find(&mut parent, &rec.id);
    }
    for sourced in &vault.entries {
        if sourced.entry.verb != "merge" {
            continue;
        }
        if let MergeParse::Ok { from, to } = parse_merge(&sourced.entry) {
            union(&mut parent, &from, &to);
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
    vault: &Vault,
) -> (
    HashMap<RecordId, Vec<RecordId>>,
    HashMap<RecordId, Vec<RecordId>>,
) {
    let mut pkg_openers: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    let mut person_pkgs: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    for sourced in &vault.entries {
        if sourced.entry.verb != "open" || sourced.entry.id.prefix() != Prefix::Person {
            continue;
        }
        let person = sourced.entry.id.clone();
        for arg in &sourced.entry.args {
            let Some(token) = arg.as_token() else {
                continue;
            };
            let Ok(pkg) = RecordId::parse(token) else {
                continue;
            };
            if pkg.prefix() != Prefix::Package {
                continue;
            }
            let openers = pkg_openers.entry(pkg.clone()).or_default();
            if !openers.contains(&person) {
                openers.push(person.clone());
            }
            let pkgs = person_pkgs.entry(person.clone()).or_default();
            if !pkgs.contains(&pkg) {
                pkgs.push(pkg);
            }
        }
    }
    (pkg_openers, person_pkgs)
}

fn reverse_deps(
    allow: &Allowlist<'_>,
    pkg_openers: &HashMap<RecordId, Vec<RecordId>>,
) -> HashMap<RecordId, Vec<RecordId>> {
    let mut dependents: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    let mut link = |from: RecordId, to: RecordId| {
        let deps = dependents.entry(from).or_default();
        if !deps.contains(&to) {
            deps.push(to);
        }
    };
    for rec in allow.vault.records.values() {
        if let Some(facts) = allow.facts.get(&rec.id) {
            for id in &facts.fm_ids {
                link(id.clone(), rec.id.clone());
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
    for line in &allow.vault.ledger_lines {
        let notes = session_notes_on_line(allow, line.file.as_str(), line.line, &line.text);
        if notes.is_empty() {
            continue;
        }
        for tok in scan_id_tokens(&line.text) {
            if let IdToken::Valid(id) = tok {
                for note in &notes {
                    link(id.clone(), note.clone());
                }
            }
        }
    }
    dependents
}

fn session_notes_on_line(
    allow: &Allowlist<'_>,
    file: &str,
    line: u32,
    text: &str,
) -> Vec<RecordId> {
    if let Some(sourced) = allow.entry_at(file, line) {
        if sourced.entry.verb == "session" {
            if let Some(raw) = sourced.entry.pair("note") {
                if let Ok(nid) = RecordId::parse(raw) {
                    return vec![nid];
                }
            }
        }
        return Vec::new();
    }
    scan_ids(text)
        .into_iter()
        .filter(|id| id.prefix() == Prefix::Note)
        .collect()
}

fn record_facts(rec: &crate::record::Record) -> RecordFacts {
    let mut fm_ids = Vec::new();
    let mut malformed = false;
    for value in rec.fields.values() {
        for tok in scan_id_tokens(value) {
            match tok {
                IdToken::Malformed => malformed = true,
                IdToken::Valid(id) => fm_ids.push(id),
            }
        }
    }
    if !malformed && line_has_id_shape(&rec.body) {
        for line in rec.body.lines() {
            if scan_id_tokens(line)
                .iter()
                .any(|tok| matches!(tok, IdToken::Malformed))
            {
                malformed = true;
                break;
            }
        }
    }
    RecordFacts {
        fm_ids,
        malformed,
        path_person: person_id_from_path(&rec.path),
    }
}

fn line_has_id_shape(text: &str) -> bool {
    text.as_bytes().contains(&b'-')
        || (text.as_bytes().iter().any(|b| *b >= 0x80) && text.chars().any(crate::id::is_id_dash))
}

fn ids_allowed(text: &str, cleared: &HashSet<RecordId>) -> bool {
    for tok in scan_id_tokens(text) {
        match tok {
            IdToken::Malformed => return false,
            IdToken::Valid(id) => {
                if !cleared.contains(&id) {
                    return false;
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
    cleared: &HashSet<RecordId>,
    hits: &mut Vec<SearchHit>,
) {
    let mut seen_fm_open = false;
    let mut in_body = false;
    for (idx, line) in rec.source.lines().enumerate() {
        if in_body && line_has_id_shape(line) && !ids_allowed(line, cleared) {
            continue;
        }
        let folded = case_fold(line);
        if folded.contains(needle) {
            hits.push(SearchHit {
                id: Some(rec.id.to_string()),
                path: rec.path.clone(),
                line: idx as u32 + 1,
                excerpt: excerpt(line.trim(), 200),
            });
        }
        if !in_body && line.trim_end_matches('\r') == "---" {
            if seen_fm_open {
                in_body = true;
            } else {
                seen_fm_open = true;
            }
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
