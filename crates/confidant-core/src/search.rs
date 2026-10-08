//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::check::{parse_merge, sort_findings, Finding, FindingCode, MergeParse, Severity};
use crate::id::{is_vault_record_prefix, scan_ids, RecordId};
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

/// Unicode case-insensitive substring scan. Hits are ordered by path, then line.
/// Line numbers are 1-based positions in the original file.
/// Returns content only from the cleared allowlist (spec section 12).
pub fn search(vault: &Vault, query: &str) -> SearchResult {
    let needle = case_fold(query);
    let cleared = compute_cleared(vault);
    let findings = findings_for_find(vault, &cleared);
    if needle.is_empty() {
        return SearchResult {
            hits: Vec::new(),
            findings,
        };
    }
    let mut hits = Vec::new();
    for rec in vault.records.values() {
        if !cleared.contains(&rec.id) {
            continue;
        }
        scan_text(
            &rec.path,
            Some(rec.id.to_string()),
            &rec.source,
            &needle,
            &mut hits,
        );
    }
    for line in &vault.ledger_lines {
        if !line_cleared(&line.text, &cleared) {
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

fn compute_cleared(vault: &Vault) -> HashSet<RecordId> {
    let tainted = tainted_ids(vault);
    let adj = merge_adj(vault);
    let mut cleared: HashSet<RecordId> = vault
        .records
        .values()
        .filter(|rec| !rec.no_ai() && !tainted.contains(&rec.id))
        .filter(|rec| rec.person().is_none_or(|person| !tainted.contains(&person)))
        .map(|rec| rec.id.clone())
        .collect();

    loop {
        let mut next = HashSet::new();
        for id in &cleared {
            let Some(rec) = vault.records.get(id) else {
                continue;
            };
            if !fm_ids_cleared(rec, &cleared) {
                continue;
            }
            if !component_cleared(id, &adj, &cleared) {
                continue;
            }
            if let Some(person) = person_from_people_path(&rec.path) {
                if !cleared.contains(&person) {
                    continue;
                }
            }
            next.insert(id.clone());
        }
        for note in session_notes_on_uncleared_lines(vault, &cleared) {
            next.remove(&note);
        }
        if next == cleared {
            break;
        }
        cleared = next;
    }
    cleared
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

fn merge_adj(vault: &Vault) -> HashMap<RecordId, Vec<RecordId>> {
    let mut adj: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    for sourced in &vault.entries {
        if sourced.entry.verb != "merge" {
            continue;
        }
        if let MergeParse::Ok { from, to } = parse_merge(&sourced.entry) {
            adj.entry(from.clone()).or_default().push(to.clone());
            adj.entry(to).or_default().push(from);
        }
    }
    adj
}

fn component_cleared(
    id: &RecordId,
    adj: &HashMap<RecordId, Vec<RecordId>>,
    cleared: &HashSet<RecordId>,
) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![id.clone()];
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.clone()) {
            continue;
        }
        if !cleared.contains(&cur) {
            return false;
        }
        if let Some(neighbours) = adj.get(&cur) {
            stack.extend(neighbours.iter().cloned());
        }
    }
    true
}

fn fm_ids_cleared(rec: &crate::record::Record, cleared: &HashSet<RecordId>) -> bool {
    rec.fields.values().all(|value| ids_cleared(value, cleared))
}

fn ids_cleared(text: &str, cleared: &HashSet<RecordId>) -> bool {
    scan_ids(text)
        .iter()
        .all(|id| !is_vault_record_prefix(id.prefix()) || cleared.contains(id))
}

fn line_cleared(text: &str, cleared: &HashSet<RecordId>) -> bool {
    ids_cleared(text, cleared)
}

fn session_notes_on_uncleared_lines(
    vault: &Vault,
    cleared: &HashSet<RecordId>,
) -> HashSet<RecordId> {
    let mut notes = HashSet::new();
    for line in &vault.ledger_lines {
        if line_cleared(&line.text, cleared) {
            continue;
        }
        if let Some(sourced) = vault
            .entries
            .iter()
            .find(|s| s.file == line.file && s.line == line.line)
        {
            if sourced.entry.verb == "session" {
                if let Some(raw) = sourced.entry.pair("note") {
                    if let Ok(nid) = RecordId::parse(raw) {
                        notes.insert(nid);
                    }
                }
            }
            continue;
        }
        notes.extend(
            scan_ids(&line.text)
                .into_iter()
                .filter(|id| id.prefix() == crate::id::Prefix::Note),
        );
    }
    notes
}

fn findings_for_find(vault: &Vault, cleared: &HashSet<RecordId>) -> Vec<Finding> {
    let mut kept = Vec::new();
    let mut redacted: BTreeMap<FindingCode, (Severity, usize)> = BTreeMap::new();
    for finding in &vault.load_findings {
        if finding_is_uncleared(finding, vault, cleared) {
            let entry = redacted
                .entry(finding.code)
                .or_insert((finding.severity, 0));
            entry.0 = entry.0.max(finding.severity);
            entry.1 += 1;
        } else {
            kept.push(finding.clone());
        }
    }
    for (code, (severity, count)) in redacted {
        kept.push(Finding::new(code, severity, format!("{count} items")));
    }
    sort_findings(&mut kept);
    kept
}

fn finding_is_uncleared(finding: &Finding, vault: &Vault, cleared: &HashSet<RecordId>) -> bool {
    if let Some(id) = &finding.id {
        if let Ok(rid) = RecordId::parse(id) {
            if is_vault_record_prefix(rid.prefix()) && !cleared.contains(&rid) {
                return true;
            }
        }
    }
    if let Some(file) = &finding.file {
        if let Some(person) = person_from_people_path(file) {
            if !cleared.contains(&person) {
                return true;
            }
        }
        if let Some(rec) = vault.records.values().find(|r| r.path == *file) {
            if !cleared.contains(&rec.id) {
                return true;
            }
        }
        if let Some(line) = finding.line {
            if let Some(ll) = vault
                .ledger_lines
                .iter()
                .find(|l| l.file == *file && l.line == line)
            {
                if !line_cleared(&ll.text, cleared) {
                    return true;
                }
            }
        }
    }
    false
}

fn person_from_people_path(path: &str) -> Option<RecordId> {
    let mut parts = path.split('/');
    if parts.next()? != "people" {
        return None;
    }
    let second = parts.next()?;
    let stem = second.strip_suffix(".md").unwrap_or(second);
    RecordId::parse(stem).ok()
}

/// Practical Unicode caseless matching: lowercasing plus ß/ẞ → ss and İ → i.
fn case_fold(s: &str) -> String {
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

fn scan_text(path: &str, id: Option<String>, text: &str, needle: &str, hits: &mut Vec<SearchHit>) {
    for (idx, line) in text.lines().enumerate() {
        let folded = case_fold(line);
        if folded.contains(needle) {
            hits.push(SearchHit {
                id: id.clone(),
                path: path.to_owned(),
                line: idx as u32 + 1,
                excerpt: excerpt(line.trim(), 200),
            });
        }
    }
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
