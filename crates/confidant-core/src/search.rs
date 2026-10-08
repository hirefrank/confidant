//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::check::{parse_merge, Finding, FindingCode, MergeParse, Severity};
use crate::id::RecordId;
use crate::record::RecordKind;
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
/// Excludes no-ai people, uncertain profiles, merge groups, linked records,
/// and ledger lines that mention an excluded ID.
pub fn search(vault: &Vault, query: &str) -> SearchResult {
    let needle = case_fold(query);
    let exclusion = ExclusionSet::build(vault);
    let findings = findings_for_find(vault, &exclusion);
    if needle.is_empty() {
        return SearchResult {
            hits: Vec::new(),
            findings,
        };
    }
    let mut hits = Vec::new();
    for rec in vault.records.values() {
        if exclusion.ids.contains(&rec.id) {
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
        if ledger_line_excluded(&line.text, &exclusion.folded_ids) {
            continue;
        }
        if contains_ignore_case(&line.text, &needle) {
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

struct ExclusionSet {
    ids: HashSet<RecordId>,
    folded_ids: Vec<String>,
    unparsed_profiles: Vec<(RecordId, String)>,
}

impl ExclusionSet {
    fn build(vault: &Vault) -> Self {
        let mut seeds = HashSet::new();
        let mut unparsed_profiles = Vec::new();
        for id in &vault.person_ids {
            match vault.records.get(id) {
                Some(rec) if rec.kind == RecordKind::Person && rec.no_ai() => {
                    seeds.insert(id.clone());
                }
                Some(rec) if rec.kind == RecordKind::Person => {}
                _ => {
                    seeds.insert(id.clone());
                    let path = vault
                        .person_files
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| format!("people/{id}/profile.md"));
                    unparsed_profiles.push((id.clone(), path));
                }
            }
        }
        let links = merge_links(vault);
        let mut ids = expand_merge_groups(seeds, &links);
        for rec in vault.records.values() {
            if rec.no_ai() {
                ids.insert(rec.id.clone());
            }
            if let Some(person) = rec.person() {
                if ids.contains(&person) {
                    ids.insert(rec.id.clone());
                }
            }
            if rec.kind == RecordKind::Note {
                if let Some(person) = person_from_path(&rec.path) {
                    if ids.contains(&person) {
                        ids.insert(rec.id.clone());
                    }
                }
            }
        }
        let mut folded_ids: Vec<String> = ids.iter().map(|id| case_fold(&id.to_string())).collect();
        folded_ids.sort();
        folded_ids.dedup();
        Self {
            ids,
            folded_ids,
            unparsed_profiles,
        }
    }
}

fn merge_links(vault: &Vault) -> Vec<(RecordId, RecordId)> {
    let mut links = Vec::new();
    for sourced in &vault.entries {
        if sourced.entry.verb != "merge" {
            continue;
        }
        if let MergeParse::Ok { from, to } = parse_merge(&sourced.entry) {
            links.push((from, to));
        }
    }
    links
}

fn expand_merge_groups(
    seeds: HashSet<RecordId>,
    links: &[(RecordId, RecordId)],
) -> HashSet<RecordId> {
    let mut adj: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    for (a, b) in links {
        adj.entry(a.clone()).or_default().push(b.clone());
        adj.entry(b.clone()).or_default().push(a.clone());
    }
    let mut out = HashSet::new();
    let mut stack: Vec<RecordId> = seeds.into_iter().collect();
    while let Some(id) = stack.pop() {
        if !out.insert(id.clone()) {
            continue;
        }
        if let Some(neighbours) = adj.get(&id) {
            stack.extend(neighbours.iter().cloned());
        }
    }
    out
}

fn findings_for_find(vault: &Vault, exclusion: &ExclusionSet) -> Vec<Finding> {
    let unparsed: HashSet<&str> = exclusion
        .unparsed_profiles
        .iter()
        .map(|(_, path)| path.as_str())
        .collect();
    let mut out = Vec::new();
    let mut seen_paths = HashSet::new();
    for finding in &vault.load_findings {
        if finding
            .file
            .as_deref()
            .is_some_and(|file| unparsed.contains(file) || is_person_profile_path(file))
            && (finding.code == FindingCode::Frontmatter || finding.code == FindingCode::Unreadable)
        {
            if let Some(file) = &finding.file {
                if seen_paths.insert(file.clone()) {
                    out.push(profile_find_finding(file));
                }
            }
            continue;
        }
        out.push(finding.clone());
    }
    for (_, path) in &exclusion.unparsed_profiles {
        if seen_paths.insert(path.clone()) {
            out.push(profile_find_finding(path));
        }
    }
    out
}

fn profile_find_finding(path: &str) -> Finding {
    Finding::new(
        FindingCode::Frontmatter,
        Severity::Error,
        "person profile excluded from find",
    )
    .at_file(path)
}

fn is_person_profile_path(file: &str) -> bool {
    let mut parts = file.split('/');
    if parts.next() != Some("people") {
        return false;
    }
    let Some(second) = parts.next() else {
        return false;
    };
    match parts.next() {
        Some("profile.md") => parts.next().is_none(),
        None => second.ends_with(".md"),
        _ => false,
    }
}

fn person_from_path(path: &str) -> Option<RecordId> {
    let mut parts = path.split('/');
    if parts.next()? != "people" {
        return None;
    }
    RecordId::parse(parts.next()?).ok()
}

fn ledger_line_excluded(text: &str, folded_ids: &[String]) -> bool {
    if folded_ids.is_empty() {
        return false;
    }
    let folded = case_fold(text);
    folded_ids.iter().any(|id| folded.contains(id))
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    case_fold(haystack).contains(&case_fold(needle))
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
        if contains_ignore_case(line, needle) {
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
    use super::{case_fold, contains_ignore_case, excerpt};

    #[test]
    fn excerpt_truncates() {
        let s = excerpt("abcdefghijklmnopqrstuvwxyz", 5);
        assert_eq!(s, "abcde…");
    }

    #[test]
    fn unicode_case_folding() {
        assert!(contains_ignore_case("İstanbul Café", "café"));
        assert!(contains_ignore_case("Straße", "STRASSE"));
        assert!(contains_ignore_case("STRASSE", "straße"));
        assert_eq!(case_fold("ß"), "ss");
    }
}
