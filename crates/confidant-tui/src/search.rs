//! Unified Search state for the TUI Search tab (#387).
//!
//! One tab covers both engines: qmd-ranked search via the `qmd-search`
//! skill's `qmd-query.py` (which already falls back to `confidant find`
//! when qmd or its corpus is missing), plus an exact literal mode that
//! runs `confidant find` directly. Rendering is fail-closed: a match whose
//! `via` is not exactly `"qmd"` or `"find"` is never shown, and the drop is
//! counted.

use crate::contract::{FindResult, SearchHit, SearchResult};

/// A [`SearchResult`] with fail-closed filtering applied.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FilteredSearchResult {
    /// The raw parsed result.
    pub result: SearchResult,
    /// Matches whose `via` is exactly `"qmd"` or `"find"`, in order.
    pub kept: Vec<SearchHit>,
    /// Matches dropped because `via` was anything else.
    pub dropped_unknown_via: usize,
}

/// Split a parsed search result into shown matches and fail-closed drops.
///
/// Only `via == "qmd"` and `via == "find"` are displayable. Anything else —
/// missing, empty, or an unrecognized provenance — is dropped and counted.
pub fn filter_search_result(result: SearchResult) -> FilteredSearchResult {
    let mut kept = Vec::new();
    let mut dropped_unknown_via = 0usize;
    for hit in &result.matches {
        if hit.via == "qmd" || hit.via == "find" {
            kept.push(hit.clone());
        } else {
            dropped_unknown_via += 1;
        }
    }
    FilteredSearchResult {
        result,
        kept,
        dropped_unknown_via,
    }
}

/// State for the Search view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SearchViewState {
    pub query: String,
    pub input: String,
    pub editing: bool,
    pub result: Option<FilteredSearchResult>,
    pub selected: usize,
    /// When true, force the exact literal scan (`confidant find`) instead
    /// of qmd-ranked search (#387). qmd's hybrid ranking can miss a
    /// literal string that `find` always catches.
    pub exact: bool,
}

/// Convert a `confidant find` result into the unified search shape so the
/// exact mode renders through the same fail-closed path. Every hit is
/// `via == "find"` with a zero score; findings and drop counts carry over.
pub fn find_result_to_search(result: FindResult) -> SearchResult {
    SearchResult {
        query: result.query,
        mode: "find-exact".to_owned(),
        fallback: None,
        matches: result
            .matches
            .into_iter()
            .map(|hit| SearchHit {
                id: hit.id,
                path: hit.path,
                line: hit.line,
                excerpt: hit.excerpt,
                via: "find".to_owned(),
                score: 0.0,
            })
            .collect(),
        findings: result.findings,
        dropped_uncleared: 0,
        skipped_encrypted: result.skipped_encrypted,
        refused_envelopes: result.refused_envelopes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(via: &str) -> SearchHit {
        SearchHit {
            id: Some("p-01".to_owned()),
            path: "people/p-01.cfd".to_owned(),
            line: 3,
            excerpt: "Ada Example".to_owned(),
            via: via.to_owned(),
            score: 0.9,
        }
    }

    fn result_with(vias: &[&str]) -> SearchResult {
        SearchResult {
            query: "ada".to_owned(),
            mode: "bm25".to_owned(),
            matches: vias.iter().map(|v| hit(v)).collect(),
            ..SearchResult::default()
        }
    }

    #[test]
    fn qmd_and_find_hits_are_kept() {
        let filtered = filter_search_result(result_with(&["qmd", "find"]));
        assert_eq!(filtered.kept.len(), 2);
        assert_eq!(filtered.dropped_unknown_via, 0);
    }

    #[test]
    fn unknown_via_is_dropped_and_counted() {
        let filtered = filter_search_result(result_with(&["qmd", "bogus", "", "FIND"]));
        assert_eq!(filtered.kept.len(), 1);
        assert_eq!(filtered.kept[0].via, "qmd");
        assert_eq!(filtered.dropped_unknown_via, 3);
    }

    #[test]
    fn empty_matches_keep_nothing() {
        let filtered = filter_search_result(result_with(&[]));
        assert!(filtered.kept.is_empty());
        assert_eq!(filtered.dropped_unknown_via, 0);
    }
}
