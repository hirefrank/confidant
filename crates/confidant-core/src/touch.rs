//! The `touch` core verb: its closed kind list and argument grammar (#510).
//!
//! `touch` is a core verb (spec §6). The compiled `personal@0.1` pack claims
//! it while enabled, but the kind list and the parser live here so there is
//! exactly one list: the compiled pack delegates through these functions
//! (#185/#296), `check` routes malformed lines through them, `context` reads
//! kinds through them, and `confidant log touch` validates against the same
//! constant. After #444 the pack wrapper is deleted and this module remains.

use crate::ledger::{Arg, LedgerEntry};

/// Closed list of touchpoint kinds for `touch` (#182, #227 Q1; the 0.1 set
/// as amended by #509). `coffee` was removed, not aliased: `meal` replaces
/// it.
pub const TOUCH_KINDS: &[&str] = &[
    "call", "text", "email", "meet", "meal", "event", "gift", "other",
];

/// Whether `kind` is one of [`TOUCH_KINDS`].
pub fn is_valid_touch_kind(kind: &str) -> bool {
    TOUCH_KINDS.contains(&kind)
}

/// Extract the touchpoint kind from either a positional `KIND` token
/// (`2026-10-12 touch p-… call`) or a `kind:KIND` pair
/// (`2026-10-12 touch p-… kind:call`). A `kind:` pair wins over a positional
/// token. Returns `None` when the entry carries no (valid) kind.
pub fn extract_touch_kind(entry: &LedgerEntry) -> Option<String> {
    if let Some(k) = entry.pair("kind") {
        return Some(k.to_owned());
    }
    if let Some(tok) = entry.args.first().and_then(Arg::as_token) {
        if is_valid_touch_kind(tok) {
            return Some(tok.to_owned());
        }
    }
    None
}

/// Validate a `touch` line's arguments when the owning pack is enabled.
/// Accepts either:
/// - `DATE touch P-ID` (mirrored touchpoint with no kind)
/// - `DATE touch P-ID kind:<KIND>` (mirrored touchpoint with kind)
/// - `DATE touch P-ID <KIND> [note:N-ID] [src:…]` (`log touch` syntax)
///
/// `<KIND>` is one of [`TOUCH_KINDS`]. On non-mirrored inputs this agrees
/// with the shape core used to ask `is_personal_touch_shape` about, so the
/// disabled-pack branch of `check` can use it as the pack-shape check behind
/// `W_PACK_ORPHAN`.
pub fn validate_touch_args(args: &[Arg]) -> bool {
    match args {
        [] => true,
        [arg] => match arg.pair() {
            Some(("kind", k)) => is_valid_touch_kind(k),
            None => arg.as_token().is_some_and(is_valid_touch_kind),
            _ => false,
        },
        _ => parse_touch_args(args).is_some(),
    }
}

/// The `log touch` grammar: a leading positional kind plus optional
/// `note:` and `src:` pairs (no duplicates). Returns the kind on success.
fn parse_touch_args(args: &[Arg]) -> Option<&str> {
    let first = args.first()?.as_token()?;
    if !is_valid_touch_kind(first) {
        return None;
    }
    let mut seen_note = false;
    let mut seen_src = false;
    for arg in &args[1..] {
        match arg.pair() {
            Some(("note", _)) if !seen_note => seen_note = true,
            Some(("src", _)) if !seen_src => seen_src = true,
            _ => return None,
        }
    }
    Some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RecordId;
    use chrono::NaiveDate;

    fn entry(args: Vec<Arg>) -> LedgerEntry {
        LedgerEntry {
            date: NaiveDate::from_ymd_opt(2026, 10, 12).unwrap(),
            verb: "touch".to_owned(),
            id: RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap(),
            args,
            comment: None,
        }
    }

    fn token(s: &str) -> Arg {
        Arg::Token(s.to_owned())
    }

    fn pair(k: &str, v: &str) -> Arg {
        Arg::Pair {
            key: k.to_owned(),
            value: v.to_owned(),
        }
    }

    /// The 0.1 list is closed and pinned (#509): `coffee` is gone, `meal`
    /// replaces it, and the order is the order the usage text lists.
    #[test]
    fn touch_kinds_are_the_closed_v1_list() {
        assert_eq!(
            TOUCH_KINDS,
            &["call", "text", "email", "meet", "meal", "event", "gift", "other"]
        );
        assert!(is_valid_touch_kind("meal"));
        assert!(!is_valid_touch_kind("coffee"));
        assert!(!is_valid_touch_kind(""));
    }

    #[test]
    fn touch_args_valid_forms() {
        // Empty args (a bare mirrored touchpoint) and a single form.
        assert!(validate_touch_args(&[]));
        assert!(validate_touch_args(&[pair("kind", "call")]));
        assert!(validate_touch_args(&[token("call")]));
        for kind in TOUCH_KINDS {
            assert!(validate_touch_args(&[token(kind)]), "{kind}");
        }
        // The `log touch` form with optional note:/src: pairs.
        assert!(validate_touch_args(&[
            token("call"),
            pair("note", "n-01M3TC5H00MPJG000000000000"),
            pair("src", "zoom/t-01"),
        ]));
        // Either pair may appear alone.
        assert!(validate_touch_args(&[
            token("call"),
            pair("note", "n-01M3TC5H00MPJG000000000000"),
        ]));
        assert!(validate_touch_args(&[
            token("call"),
            pair("src", "zoom/t-01")
        ]));
    }

    #[test]
    fn touch_args_reject_unknown_kind() {
        assert!(!validate_touch_args(&[token("smoke")]));
        assert!(!validate_touch_args(&[pair("kind", "coffee")]));
    }

    #[test]
    fn touch_args_reject_duplicate_note() {
        assert!(!validate_touch_args(&[
            token("call"),
            pair("note", "n-01M3TC5H00MPJG000000000000"),
            pair("note", "n-01M3TC5H00MPJG000000000001"),
        ]));
    }

    #[test]
    fn touch_args_reject_extra_token() {
        assert!(!validate_touch_args(&[token("call"), token("extra")]));
        assert!(!validate_touch_args(&[token("call"), pair("bogus", "x")]));
    }

    #[test]
    fn touch_kind_prefers_pair_over_positional() {
        let e = entry(vec![token("text"), pair("kind", "call")]);
        assert_eq!(extract_touch_kind(&e).as_deref(), Some("call"));
        let mirrored = entry(vec![pair("kind", "meal")]);
        assert_eq!(extract_touch_kind(&mirrored).as_deref(), Some("meal"));
        let positional = entry(vec![token("gift")]);
        assert_eq!(extract_touch_kind(&positional).as_deref(), Some("gift"));
        // A positional token outside the list is not a kind.
        assert!(extract_touch_kind(&entry(vec![token("coffee")])).is_none());
        assert!(extract_touch_kind(&entry(vec![])).is_none());
    }
}
