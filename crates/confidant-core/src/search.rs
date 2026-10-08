//! Plaintext scan of records and ledger lines (milestone 1 stopgap).

use serde::Serialize;

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
pub fn search(vault: &Vault, query: &str) -> Vec<SearchHit> {
    let needle = query.to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for rec in vault.records.values() {
        scan_text(
            &rec.path,
            Some(rec.id.to_string()),
            &rec.source,
            &needle,
            &mut hits,
        );
    }
    for sourced in &vault.entries {
        let line_text = crate::ledger::format_entry(&sourced.entry);
        if contains_ignore_case(&line_text, &needle) {
            hits.push(SearchHit {
                id: Some(sourced.entry.id.to_string()),
                path: sourced.file.clone(),
                line: sourced.line,
                excerpt: excerpt(&line_text, 200),
            });
        }
    }
    hits.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    hits
}

fn contains_ignore_case(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
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
    use super::{contains_ignore_case, excerpt};

    #[test]
    fn excerpt_truncates() {
        let s = excerpt("abcdefghijklmnopqrstuvwxyz", 5);
        assert_eq!(s, "abcde…");
    }

    #[test]
    fn unicode_case_insensitive() {
        assert!(contains_ignore_case("İstanbul Café", "café"));
        assert!(
            contains_ignore_case("Straße", "STRASSE") || contains_ignore_case("Straße", "straße")
        );
    }
}
