//! Ledger corrections (#746): `retract` lines and the effective view.
//!
//! A correction is a new, dated, attributed line. The original line is never
//! edited. This module parses the retraction graph, reports malformed chains,
//! and exposes the voided set every read path consults.
//!
//! Current-state rules apply every retraction regardless of its date; dated
//! arithmetic (a `balance` assertion at date D) uses [`Corrections::voided_on`]
//! and must compare the retraction date to D.

use std::collections::{BTreeMap, HashSet};

use chrono::NaiveDate;

use crate::check::{Finding, FindingCode, Severity};
use crate::config::SpecVersion;
use crate::id::RecordId;
use crate::ledger::{parse_retract, LineRef, RetractParse, RetractReason, RetractSpec};
use crate::vault::SourcedEntry;

/// One validly parsed retraction, retained with its target's location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retraction {
    pub target: LineRef,
    pub replacement: Option<LineRef>,
    pub reason: RetractReason,
    pub date: NaiveDate,
    pub subject: RecordId,
    pub target_file: String,
    pub target_line: u32,
    pub retract_file: String,
    pub retract_line: u32,
}

/// The vault's correction graph. Empty before spec 0.4.
#[derive(Clone, Debug, Default)]
pub struct Corrections {
    by_target: BTreeMap<LineRef, Retraction>,
    voided_on: BTreeMap<LineRef, NaiveDate>,
    voided_locations: HashSet<(String, u32)>,
    findings: Vec<Finding>,
}

struct Pending<'a> {
    sourced: &'a SourcedEntry,
    spec: RetractSpec,
}

impl Corrections {
    /// Parse and validate every `retract` line. Findings are collected, never
    /// thrown (the check engine contract).
    pub fn build(entries: &[SourcedEntry], spec: Option<SpecVersion>) -> Self {
        let mut out = Self::default();
        if !matches!(spec, Some(SpecVersion::V04)) {
            return out;
        }

        let mut lookup: BTreeMap<LineRef, &SourcedEntry> = BTreeMap::new();
        for sourced in entries {
            lookup.insert(sourced.line_ref, sourced);
        }

        let mut pending: Vec<Pending<'_>> = Vec::new();
        for sourced in entries {
            if sourced.entry.verb != "retract" {
                continue;
            }
            match parse_retract(&sourced.entry) {
                RetractParse::Malformed => {
                    out.findings.push(
                        Finding::new(
                            FindingCode::RetractMalformed,
                            Severity::Error,
                            "retract line must be: DATE retract SUBJECT-ID line:<64 hex> [occurrence:N] reason:<token> [replace:<64 hex>]".to_owned(),
                        )
                        .at_file(&sourced.file)
                        .at_line(sourced.line)
                        .for_id(&sourced.entry.id)
                        .with_fix("Use a closed reason token and a full lowercase line ref"),
                    );
                }
                RetractParse::Ok(retract) => {
                    let Some(target) = lookup.get(&retract.target) else {
                        out.findings.push(
                            Finding::new(
                                FindingCode::RetractTarget,
                                Severity::Error,
                                "retract target line not found".to_owned(),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&sourced.entry.id)
                            .with_fix(
                                "Check the line ref and occurrence; `find --json` prints the ref",
                            ),
                        );
                        continue;
                    };
                    if matches!(target.entry.verb.as_str(), "retract" | "merge") {
                        out.findings.push(
                            Finding::new(
                                FindingCode::RetractNotAllowed,
                                Severity::Error,
                                "retract target is not allowed".to_owned(),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&sourced.entry.id)
                            .with_fix(
                                "Only a fact line can be retracted; merge and retract lines cannot",
                            ),
                        );
                        continue;
                    }
                    if target.entry.id != sourced.entry.id {
                        out.findings.push(
                            Finding::new(
                                FindingCode::RetractNotAllowed,
                                Severity::Error,
                                "retract subject does not match the target line".to_owned(),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&sourced.entry.id)
                            .with_fix("Use the target line's own subject id"),
                        );
                    }
                    if target.entry.date > sourced.entry.date {
                        out.findings.push(
                            Finding::new(
                                FindingCode::RetractOrder,
                                Severity::Error,
                                "retract target is dated after the retraction".to_owned(),
                            )
                            .at_file(&sourced.file)
                            .at_line(sourced.line)
                            .for_id(&sourced.entry.id)
                            .with_fix("Date the retraction on or after the target line"),
                        );
                    }
                    out.voided_on
                        .entry(retract.target)
                        .and_modify(|date| {
                            if sourced.entry.date < *date {
                                *date = sourced.entry.date;
                            }
                        })
                        .or_insert(sourced.entry.date);
                    out.voided_locations
                        .insert((target.file.clone(), target.line));
                    pending.push(Pending {
                        sourced,
                        spec: retract,
                    });
                }
            }
        }

        // Duplicate/fork detection and the first-retraction map.
        let mut fork_earliest: BTreeMap<LineRef, NaiveDate> = BTreeMap::new();
        for item in &pending {
            let spec = &item.spec;
            let target = lookup.get(&spec.target).expect("target validated above");
            let retraction = Retraction {
                target: spec.target,
                replacement: spec.replacement,
                reason: spec.reason,
                date: item.sourced.entry.date,
                subject: item.sourced.entry.id.clone(),
                target_file: target.file.clone(),
                target_line: target.line,
                retract_file: item.sourced.file.clone(),
                retract_line: item.sourced.line,
            };
            match out.by_target.get(&spec.target) {
                Some(existing) => {
                    let fork = existing.replacement != spec.replacement;
                    if fork {
                        fork_earliest
                            .entry(spec.target)
                            .and_modify(|date| {
                                if item.sourced.entry.date < *date {
                                    *date = item.sourced.entry.date;
                                }
                            })
                            .or_insert(item.sourced.entry.date);
                    }
                    out.findings.push(
                        Finding::new(
                            FindingCode::RetractChain,
                            Severity::Error,
                            if fork {
                                "retract target has conflicting replacements".to_owned()
                            } else {
                                "retract target is retracted more than once".to_owned()
                            },
                        )
                        .at_file(&item.sourced.file)
                        .at_line(item.sourced.line)
                        .for_id(&item.sourced.entry.id)
                        .with_fix("Keep one retraction per target"),
                    );
                }
                None => {
                    out.by_target.insert(spec.target, retraction);
                }
            }
        }

        // A fork has no single current replacement: void every replacement
        // named by the conflicting retractions (fail closed). A duplicate
        // retraction with the same replacement stays effective.
        for item in &pending {
            if !fork_earliest.contains_key(&item.spec.target) {
                continue;
            }
            let Some(replacement) = item.spec.replacement else {
                continue;
            };
            let Some(entry) = lookup.get(&replacement) else {
                continue;
            };
            let date = fork_earliest[&item.spec.target];
            out.voided_on
                .entry(replacement)
                .and_modify(|existing| {
                    if date < *existing {
                        *existing = date;
                    }
                })
                .or_insert(date);
            out.voided_locations
                .insert((entry.file.clone(), entry.line));
        }

        // Replacement validation needs the complete voided set, so it runs
        // after every retraction has been collected.
        for item in &pending {
            if fork_earliest.contains_key(&item.spec.target) {
                continue;
            }
            let Some(replacement) = item.spec.replacement else {
                continue;
            };
            let Some(replacement_entry) = lookup.get(&replacement) else {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractTarget,
                        Severity::Error,
                        "retract replacement line not found".to_owned(),
                    )
                    .at_file(&item.sourced.file)
                    .at_line(item.sourced.line)
                    .for_id(&item.sourced.entry.id)
                    .with_fix("Check the replacement line ref"),
                );
                continue;
            };
            if matches!(replacement_entry.entry.verb.as_str(), "retract" | "merge") {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractNotAllowed,
                        Severity::Error,
                        "retract replacement is not allowed".to_owned(),
                    )
                    .at_file(&item.sourced.file)
                    .at_line(item.sourced.line)
                    .for_id(&item.sourced.entry.id)
                    .with_fix("Replace a fact with another fact line"),
                );
                continue;
            }
            if replacement_entry.entry.id != item.sourced.entry.id {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractNotAllowed,
                        Severity::Error,
                        "retract replacement subject does not match".to_owned(),
                    )
                    .at_file(&item.sourced.file)
                    .at_line(item.sourced.line)
                    .for_id(&item.sourced.entry.id)
                    .with_fix("A replacement must keep the target line's subject id"),
                );
                continue;
            }
            if replacement_entry.entry.date > item.sourced.entry.date {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractOrder,
                        Severity::Error,
                        "retract replacement is dated after the retraction".to_owned(),
                    )
                    .at_file(&item.sourced.file)
                    .at_line(item.sourced.line)
                    .for_id(&item.sourced.entry.id)
                    .with_fix("Date the retraction on or after the replacement line"),
                );
                continue;
            }
            if replacement == item.spec.target {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractChain,
                        Severity::Error,
                        "retract replacement names the target itself".to_owned(),
                    )
                    .at_file(&item.sourced.file)
                    .at_line(item.sourced.line)
                    .for_id(&item.sourced.entry.id)
                    .with_fix("Use a different replacement line, or omit replace:"),
                );
                continue;
            }
            if out
                .voided_on
                .get(&replacement)
                .is_some_and(|date| *date <= item.sourced.entry.date)
            {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractChain,
                        Severity::Error,
                        "retract replacement is already superseded".to_owned(),
                    )
                    .at_file(&item.sourced.file)
                    .at_line(item.sourced.line)
                    .for_id(&item.sourced.entry.id)
                    .with_fix("Replace with a line that is effective at the retraction date"),
                );
            }
        }

        // A replacement cycle leaves no current fact. Report it once and
        // leave every member voided (fail closed).
        if let Some(cycle_target) = replacement_cycle(&out.by_target) {
            if let Some(retraction) = out.by_target.get(&cycle_target) {
                out.findings.push(
                    Finding::new(
                        FindingCode::RetractChain,
                        Severity::Error,
                        "retract replacements form a cycle".to_owned(),
                    )
                    .at_file(&retraction.retract_file)
                    .at_line(retraction.retract_line)
                    .for_id(&retraction.subject)
                    .with_fix(
                        "Break the replacement cycle; each target needs one non-cyclic replacement",
                    ),
                );
            }
        }

        out
    }

    pub fn is_voided(&self, line: &LineRef) -> bool {
        self.voided_on.contains_key(line)
    }

    pub fn voided_on(&self, line: &LineRef) -> Option<NaiveDate> {
        self.voided_on.get(line).copied()
    }

    pub fn is_voided_location(&self, file: &str, line: u32) -> bool {
        self.voided_locations.contains(&(file.to_owned(), line))
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn retraction_for(&self, target: &LineRef) -> Option<&Retraction> {
        self.by_target.get(target)
    }
}

/// Find one target that participates in a replacement cycle.
fn replacement_cycle(by_target: &BTreeMap<LineRef, Retraction>) -> Option<LineRef> {
    let edges: BTreeMap<LineRef, LineRef> = by_target
        .iter()
        .filter_map(|(target, retraction)| retraction.replacement.map(|r| (*target, r)))
        .collect();
    for start in edges.keys() {
        let mut seen = HashSet::new();
        let mut cur = *start;
        while let Some(next) = edges.get(&cur) {
            if !seen.insert(cur) {
                return Some(*start);
            }
            cur = *next;
        }
    }
    None
}

/// Helper for read paths: whether a sourced entry is voided.
pub fn is_entry_voided(corrections: &Corrections, sourced: &SourcedEntry) -> bool {
    corrections.is_voided(&sourced.line_ref)
}

/// Helper for pack folds: the retraction date of an entry, if any.
pub fn voided_on_entry(corrections: &Corrections, sourced: &SourcedEntry) -> Option<NaiveDate> {
    corrections.voided_on(&sourced.line_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{line_ref, parse_line};

    const ADA: &str = "p-01M3TC5H00MPJG000000000000";
    const BEA: &str = "p-01M3TC5H00MPJG000H24000001";

    fn sourced(file: &str, line: u32, text: &str, occurrence: u32) -> SourcedEntry {
        let entry = parse_line(text).unwrap().unwrap();
        SourcedEntry {
            file: file.to_owned(),
            line,
            line_ref: line_ref(&entry, occurrence),
            entry,
        }
    }

    fn ref_of(text: &str) -> LineRef {
        let entry = parse_line(text).unwrap().unwrap();
        line_ref(&entry, 1)
    }

    fn retraction(
        date: &str,
        subject: &str,
        target: &str,
        reason: &str,
        replacement: Option<&str>,
    ) -> String {
        let mut line = format!(
            "{date} retract {subject} line:{} reason:{reason}",
            ref_of(target).to_string().trim_start_matches("line:")
        );
        if let Some(replacement) = replacement {
            line.push_str(&format!(
                " replace:{}",
                ref_of(replacement).to_string().trim_start_matches("line:")
            ));
        }
        line
    }

    fn build(lines: Vec<SourcedEntry>) -> Corrections {
        Corrections::build(&lines, Some(SpecVersion::V04))
    }

    #[test]
    fn valid_retraction_voids_target() {
        let touch = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call";
        let lines = vec![
            sourced("ledger/2026/10.cfd", 1, touch, 1),
            sourced(
                "ledger/2026/11.cfd",
                1,
                &retraction("2026-11-02", ADA, touch, "duplicate", None),
                1,
            ),
        ];
        let corrections = build(lines);
        assert!(corrections.is_voided(&ref_of(touch)));
        assert!(
            corrections.findings().is_empty(),
            "{:?}",
            corrections.findings()
        );
        assert!(corrections.is_voided_location("ledger/2026/10.cfd", 1));
    }

    #[test]
    fn malformed_and_missing_targets_are_findings() {
        let corrections = build(vec![
            sourced(
                "ledger/2026/11.cfd",
                1,
                "2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:nothex reason:duplicate",
                1,
            ),
            sourced(
                "ledger/2026/11.cfd",
                2,
                "2026-11-02 retract p-01M3TC5H00MPJG000000000000 line:87d93568b0d238e8e63086bdf1703f496a2824bc829655b1238332f31c8016c7 reason:duplicate",
                1,
            ),
        ]);
        let codes: Vec<&str> = corrections
            .findings()
            .iter()
            .map(|f| f.code.as_str())
            .collect();
        assert!(codes.contains(&"E_RETRACT_MALFORMED"));
        assert!(codes.contains(&"E_RETRACT_TARGET"));
    }

    #[test]
    fn merge_and_retract_targets_are_refused() {
        let merge = format!("2026-10-01 merge {BEA} into {ADA}");
        let first = retraction("2026-11-02", ADA, &merge, "duplicate", None);
        let second = retraction("2026-11-02", ADA, &first, "duplicate", None);
        let corrections = build(vec![
            sourced("ledger/2026/10.cfd", 1, &merge, 1),
            sourced("ledger/2026/11.cfd", 1, &first, 1),
            sourced("ledger/2026/11.cfd", 2, &second, 1),
        ]);
        assert!(!corrections.is_voided(&ref_of(&merge)));
        assert!(!corrections.is_voided(&ref_of(&first)));
        assert_eq!(
            corrections
                .findings()
                .iter()
                .filter(|f| f.code.as_str() == "E_RETRACT_NOT_ALLOWED")
                .count(),
            2,
            "{:?}",
            corrections.findings()
        );
    }

    #[test]
    fn subject_mismatch_and_order_still_void_the_target() {
        let touch = "2026-10-10 touch p-01M3TC5H00MPJG000000000000 call";
        let wrong_subject = retraction("2026-11-02", BEA, touch, "duplicate", None);
        let early = retraction("2026-10-01", ADA, touch, "duplicate", None);
        let corrections = build(vec![
            sourced("ledger/2026/10.cfd", 1, touch, 1),
            sourced("ledger/2026/11.cfd", 1, &wrong_subject, 1),
            sourced("ledger/2026/11.cfd", 2, &early, 1),
        ]);
        let codes: Vec<&str> = corrections
            .findings()
            .iter()
            .map(|f| f.code.as_str())
            .collect();
        assert!(codes.contains(&"E_RETRACT_NOT_ALLOWED"), "{codes:?}");
        assert!(codes.contains(&"E_RETRACT_ORDER"), "{codes:?}");
        assert!(corrections.is_voided(&ref_of(touch)));
    }

    #[test]
    fn duplicate_and_forked_targets_are_chain_errors() {
        let touch = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call";
        let replacement = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 meet";
        let first = retraction("2026-11-02", ADA, touch, "duplicate", None);
        let duplicate = first.clone();
        let fork = retraction("2026-11-02", ADA, touch, "wrong-kind", Some(replacement));
        let corrections = build(vec![
            sourced("ledger/2026/10.cfd", 1, touch, 1),
            sourced("ledger/2026/10.cfd", 2, replacement, 1),
            sourced("ledger/2026/11.cfd", 1, &first, 1),
            sourced("ledger/2026/11.cfd", 2, &duplicate, 1),
            sourced("ledger/2026/11.cfd", 3, &fork, 1),
        ]);
        assert_eq!(
            corrections
                .findings()
                .iter()
                .filter(|f| f.code.as_str() == "E_RETRACT_CHAIN")
                .count(),
            2,
            "{:?}",
            corrections.findings()
        );
    }

    #[test]
    fn replacement_missing_wrong_subject_and_voided_are_errors() {
        let a = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call";
        let b = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 text";
        let c = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 meet";
        let other = "2026-10-01 touch p-01M3TC5H00MPJG000H24000001 meet";
        let replacement = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 email";
        let zero = "0".repeat(64);
        let missing = format!(
            "2026-11-02 retract {ADA} line:{} reason:wrong-kind replace:{zero}",
            ref_of(a).to_string().trim_start_matches("line:")
        );
        let wrong_subject = retraction("2026-11-02", ADA, b, "wrong-kind", Some(other));
        let replacement_retract = retraction("2026-11-01", ADA, replacement, "duplicate", None);
        let voided = retraction("2026-11-02", ADA, c, "wrong-kind", Some(replacement));
        let corrections = build(vec![
            sourced("ledger/2026/10.cfd", 1, a, 1),
            sourced("ledger/2026/10.cfd", 2, b, 1),
            sourced("ledger/2026/10.cfd", 3, c, 1),
            sourced("ledger/2026/10.cfd", 4, other, 1),
            sourced("ledger/2026/10.cfd", 5, replacement, 1),
            sourced("ledger/2026/11.cfd", 1, &missing, 1),
            sourced("ledger/2026/11.cfd", 2, &wrong_subject, 1),
            sourced("ledger/2026/11.cfd", 3, &replacement_retract, 1),
            sourced("ledger/2026/11.cfd", 4, &voided, 1),
        ]);
        let codes: Vec<&str> = corrections
            .findings()
            .iter()
            .map(|f| f.code.as_str())
            .collect();
        assert!(codes.contains(&"E_RETRACT_TARGET"), "{codes:?}");
        assert!(codes.contains(&"E_RETRACT_NOT_ALLOWED"), "{codes:?}");
        assert!(codes.contains(&"E_RETRACT_CHAIN"), "{codes:?}");
    }

    #[test]
    fn replacement_cycle_is_a_chain_error() {
        let a = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call";
        let b = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 meet";
        let a_to_b = retraction("2026-11-02", ADA, a, "wrong-kind", Some(b));
        let b_to_a = retraction("2026-11-02", ADA, b, "wrong-kind", Some(a));
        let corrections = build(vec![
            sourced("ledger/2026/10.cfd", 1, a, 1),
            sourced("ledger/2026/10.cfd", 2, b, 1),
            sourced("ledger/2026/11.cfd", 1, &a_to_b, 1),
            sourced("ledger/2026/11.cfd", 2, &b_to_a, 1),
        ]);
        assert!(
            corrections
                .findings()
                .iter()
                .any(|f| f.code.as_str() == "E_RETRACT_CHAIN"),
            "{:?}",
            corrections.findings()
        );
    }

    #[test]
    fn spec_03_ignores_retract_lines() {
        let touch = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call";
        let lines = vec![
            sourced("ledger/2026/10.cfd", 1, touch, 1),
            sourced(
                "ledger/2026/11.cfd",
                1,
                &retraction("2026-11-02", ADA, touch, "duplicate", None),
                1,
            ),
        ];
        let corrections = Corrections::build(&lines, Some(SpecVersion::V03));
        assert!(corrections.findings().is_empty());
        assert!(!corrections.is_voided(&ref_of(touch)));
    }
}
