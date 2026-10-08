//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use serde::Serialize;

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

/// Unicode case-insensitive substring scan. Hits are ordered by path, then line.
/// Line numbers are 1-based positions in the original file.
/// People with `no-ai: true` and their notes are excluded.
pub fn search(vault: &Vault, query: &str) -> Vec<SearchHit> {
    let needle = case_fold(query);
    if needle.is_empty() {
        return Vec::new();
    }
    let excluded = excluded_people(vault);
    let mut hits = Vec::new();
    for rec in vault.records.values() {
        if excluded_record(rec, &excluded) {
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
        if ledger_line_excluded(line, &excluded) {
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
    hits
}

fn excluded_people(vault: &Vault) -> std::collections::HashSet<crate::id::RecordId> {
    vault
        .records
        .values()
        .filter(|r| r.kind == RecordKind::Person && r.no_ai())
        .map(|r| r.id.clone())
        .collect()
}

fn excluded_record(
    rec: &crate::record::Record,
    excluded: &std::collections::HashSet<crate::id::RecordId>,
) -> bool {
    if rec.kind == RecordKind::Person && excluded.contains(&rec.id) {
        return true;
    }
    if rec.kind == RecordKind::Note {
        if let Some(person) = rec.person() {
            if excluded.contains(&person) {
                return true;
            }
        }
        if let Some(person) = person_from_path(&rec.path) {
            if excluded.contains(&person) {
                return true;
            }
        }
    }
    false
}

fn person_from_path(path: &str) -> Option<crate::id::RecordId> {
    let mut parts = path.split('/');
    if parts.next()? != "people" {
        return None;
    }
    crate::id::RecordId::parse(parts.next()?).ok()
}

fn ledger_line_excluded(
    line: &crate::vault::LedgerLine,
    excluded: &std::collections::HashSet<crate::id::RecordId>,
) -> bool {
    line.id
        .as_deref()
        .and_then(|raw| crate::id::RecordId::parse(raw).ok())
        .is_some_and(|id| excluded.contains(&id))
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
