//! Fuzz the ledger line parser (`confidant_core::ledger`).
//!
//! The ledger grammar is one of the two untrusted-input surfaces
//! (issue #235): vault files are read from git, so a hostile or corrupt
//! line must never panic the parser.
//!
//! Invariants per input:
//! - `parse_line` / `parse_ledger` never panic.
//! - A successful parse round-trips through the canonical renderer:
//!   `parse_line(format_entry(e)) == Ok(Some(e))`.
//!   (NOT `format_entry(parse_line(x)) == x`: input formatting differences
//!   such as case or quoting are not failures.)

#![no_main]

use confidant_core::ledger::{format_entry, parse_ledger, parse_line};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The ledger grammar is text; parse_line takes &str.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Multi-line entry point must not panic either.
    let _ = parse_ledger(s);

    // Single-line entry point: no panic, and successful parses round-trip.
    if let Ok(Some(entry)) = parse_line(s) {
        let displayed = format_entry(&entry);
        let reparsed = parse_line(&displayed);
        assert_eq!(
            reparsed,
            Ok(Some(entry)),
            "ledger round-trip failed: {s:?} -> {displayed:?}"
        );
    }
});
