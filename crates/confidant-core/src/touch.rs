//! The `touch` core verb: its closed kind list and argument grammar (#510).
//!
//! `touch` is a core verb (spec §6). The built-in personal pack claims it,
//! but the kind list and the parser live here so there is exactly one list:
//! the pack delegates through these functions (#185/#296), `check` routes
//! malformed lines through them, `context` reads kinds through them, and
//! `confidant log touch` validates against the same constant.

use crate::id::RecordId;
use crate::ledger::{parse_duration_minutes, Arg, LedgerEntry};
use chrono::NaiveDate;

/// Closed list of touchpoint kinds for `touch` (#182, #227 Q1; the 0.1 set
/// as amended by #509, plus `video` per #735). `coffee` was removed, not
/// aliased: `meal` replaces it. `video` is a video call: distinct from
/// `call` (phone) and `meet` (in person).
pub const TOUCH_KINDS: &[&str] = &[
    "call", "text", "email", "meet", "meal", "event", "gift", "video", "other",
];

/// The pair naming how long a touch lasted: `duration:60m` (#741). The value
/// uses the shared duration grammar (`60m`, `1h`, `1h30m`) and normalizes to
/// minutes.
pub const TOUCH_DURATION_PAIR: &str = "duration";

/// The pair naming the touch's social mode: `mode:one-on-one` or
/// `mode:group` (#741). A birthday game night and a coffee catch-up no longer
/// read identically to a days-since-touch ranking.
pub const TOUCH_MODE_PAIR: &str = "mode";

/// Closed list of `mode:` values (#741): a 1:1 or a gathering.
pub const TOUCH_MODES: &[&str] = &["one-on-one", "group"];

/// Whether `kind` is one of [`TOUCH_KINDS`].
pub fn is_valid_touch_kind(kind: &str) -> bool {
    TOUCH_KINDS.contains(&kind)
}

/// Whether `mode` is one of [`TOUCH_MODES`].
pub fn is_valid_touch_mode(mode: &str) -> bool {
    TOUCH_MODES.contains(&mode)
}

/// Extract the touchpoint kind from either a positional `KIND` token
/// (`2026-10-12 touch p-… call`) or a `kind:KIND` pair
/// (`2026-10-12 touch p-… kind:call`). A `kind:` pair wins over a positional
/// token, and it is validated against [`TOUCH_KINDS`] exactly like the
/// positional branch (#747 review): an invalid pair yields no kind,
/// instead of letting two malformed `kind:coffee` lines draw a duplicate
/// finding on top of `E_TOUCH_MALFORMED`. Returns `None` when the entry
/// carries no (valid) kind.
pub fn extract_touch_kind(entry: &LedgerEntry) -> Option<String> {
    if let Some(k) = entry.pair("kind") {
        return is_valid_touch_kind(k).then(|| k.to_owned());
    }
    if let Some(tok) = entry.args.first().and_then(Arg::as_token) {
        if is_valid_touch_kind(tok) {
            return Some(tok.to_owned());
        }
    }
    None
}

/// Extract the touchpoint duration in minutes from a `duration:` pair
/// (#741). `60m`, `1h`, and `1h30m` are the same duration syntax sessions
/// use, normalized to minutes. `None` when the pair is absent or invalid;
/// `check` reports the invalid case as `E_TOUCH_MALFORMED`, so a `context`
/// read never half-admits a malformed value.
pub fn extract_touch_duration(entry: &LedgerEntry) -> Option<u32> {
    entry
        .pair(TOUCH_DURATION_PAIR)
        .and_then(parse_duration_minutes)
        .filter(|minutes| *minutes > 0)
}

/// Extract the touchpoint mode from a `mode:` pair (#741): `one-on-one` or
/// `group`. `None` when absent or outside [`TOUCH_MODES`] (`check` reports
/// the latter as `E_TOUCH_MALFORMED`).
pub fn extract_touch_mode(entry: &LedgerEntry) -> Option<String> {
    entry
        .pair(TOUCH_MODE_PAIR)
        .filter(|mode| is_valid_touch_mode(mode))
        .map(str::to_owned)
}

/// Identity of a `touch` line for semantic idempotency (#747): the person,
/// the date, and the kind. `note:` and `src:` pairs are deliberately not
/// part of the identity — a backfill that re-adds the same contact with a
/// fresh note or provenance is still the same touchpoint. `duration:` and
/// `mode:` are not part of it either (#741): two reports of the same
/// person, date, and kind are the same touchpoint whatever detail each
/// carries. Returns `None`
/// for non-`touch` lines and for `touch` lines with no (valid) kind: a
/// kind-less mirrored touchpoint cannot be shown identical to another, so
/// `check` leaves those alone and `log touch` (which always carries a
/// kind) never writes one.
pub fn touch_identity(entry: &LedgerEntry) -> Option<(RecordId, NaiveDate, String)> {
    if entry.verb != "touch" {
        return None;
    }
    let kind = extract_touch_kind(entry)?;
    Some((entry.id.clone(), entry.date, kind))
}

/// Validate a `touch` line's arguments when the owning pack is enabled.
/// Accepts either:
/// - `DATE touch P-ID` (mirrored touchpoint with no kind)
/// - `DATE touch P-ID kind:<KIND>` (mirrored touchpoint with kind)
/// - `DATE touch P-ID <KIND> [note:N-ID] [src:…] [duration:<N>m] [mode:…]`
///   (`log touch` syntax). The `kind:` form also accepts the same pairs.
///
/// `<KIND>` is one of [`TOUCH_KINDS`]; `duration:` must parse as a positive
/// minute count; `mode:` is one of [`TOUCH_MODES`]. On non-mirrored inputs
/// this agrees with the shape core used to ask `is_personal_touch_shape`
/// about, so the disabled-pack branch of `check` can use it as the
/// pack-shape check behind `W_PACK_ORPHAN`.
pub fn validate_touch_args(args: &[Arg]) -> bool {
    args.is_empty() || parse_touch_args(args).is_some()
}

/// The `touch` grammar: a leading positional kind or `kind:` pair plus
/// optional `note:`, `src:`, `duration:`, and `mode:` pairs (no duplicates).
/// Returns the kind on success.
fn parse_touch_args(args: &[Arg]) -> Option<&str> {
    let (first, rest) = args.split_first()?;
    let (kind, rest) = match first.pair() {
        Some(("kind", kind)) if is_valid_touch_kind(kind) => (kind, rest),
        Some(_) => return None,
        None => {
            let token = first.as_token()?;
            if !is_valid_touch_kind(token) {
                return None;
            }
            (token, rest)
        }
    };
    let mut seen_note = false;
    let mut seen_src = false;
    let mut seen_duration = false;
    let mut seen_mode = false;
    for arg in rest {
        match arg.pair() {
            Some(("note", _)) if !seen_note => seen_note = true,
            Some(("src", _)) if !seen_src => seen_src = true,
            Some((TOUCH_DURATION_PAIR, value)) if !seen_duration => {
                if parse_duration_minutes(value).is_none_or(|minutes| minutes == 0) {
                    return None;
                }
                seen_duration = true;
            }
            Some((TOUCH_MODE_PAIR, value)) if !seen_mode => {
                if !is_valid_touch_mode(value) {
                    return None;
                }
                seen_mode = true;
            }
            _ => return None,
        }
    }
    Some(kind)
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

    /// The 0.1 list is closed and pinned (#509, plus `video` per #735):
    /// `coffee` is gone, `meal` replaces it, and the order is the order
    /// the usage text lists.
    #[test]
    fn touch_kinds_are_the_closed_v1_list() {
        assert_eq!(
            TOUCH_KINDS,
            &["call", "text", "email", "meet", "meal", "event", "gift", "video", "other"]
        );
        assert!(is_valid_touch_kind("video"));
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
    fn touch_args_accept_duration_and_mode() {
        // #741: the rich pairs ride on either kind form, in any order.
        assert!(validate_touch_args(&[
            token("meal"),
            pair("duration", "60m"),
            pair("mode", "one-on-one"),
        ]));
        assert!(validate_touch_args(&[
            token("meal"),
            pair("mode", "group"),
            pair("duration", "1h30m"),
        ]));
        assert!(validate_touch_args(&[
            pair("kind", "event"),
            pair("duration", "2h"),
            pair("src", "calendar/t-1"),
        ]));
        // Duplicates and out-of-grammar values are malformed.
        for args in [
            vec![
                token("meal"),
                pair("duration", "60m"),
                pair("duration", "30m"),
            ],
            vec![token("meal"), pair("mode", "group"), pair("mode", "group")],
            vec![token("meal"), pair("duration", "0m")],
            vec![token("meal"), pair("duration", "soon")],
            vec![token("meal"), pair("mode", "crowd")],
        ] {
            assert!(!validate_touch_args(&args), "{args:?}");
        }
        // A kind-less line cannot carry the pairs: they describe a touchpoint.
        assert!(!validate_touch_args(&[pair("mode", "group")]));
    }

    #[test]
    fn touch_duration_and_mode_are_extracted() {
        let rich = entry(vec![
            token("meal"),
            pair("duration", "1h30m"),
            pair("mode", "group"),
        ]);
        assert_eq!(extract_touch_duration(&rich), Some(90));
        assert_eq!(extract_touch_mode(&rich).as_deref(), Some("group"));
        let plain = entry(vec![token("call")]);
        assert_eq!(extract_touch_duration(&plain), None);
        assert_eq!(extract_touch_mode(&plain), None);
        // Invalid values are not half-admitted.
        let malformed = entry(vec![
            token("call"),
            pair("duration", "soon"),
            pair("mode", "crowd"),
        ]);
        assert_eq!(extract_touch_duration(&malformed), None);
        assert_eq!(extract_touch_mode(&malformed), None);
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
        // #747 review: a `kind:` pair is validated the same way — a
        // malformed pair yields no kind, even when a valid positional
        // token is also present (the pair wins).
        assert!(extract_touch_kind(&entry(vec![pair("kind", "coffee")])).is_none());
        assert!(extract_touch_kind(&entry(vec![token("meet"), pair("kind", "coffee")])).is_none());
    }

    /// #747: identity is person + date + kind; note:/src: do not
    /// distinguish, and kind-less or non-touch lines have no identity.
    #[test]
    fn touch_identity_ignores_note_and_src() {
        let base = entry(vec![token("meet")]);
        let noted = entry(vec![
            token("meet"),
            pair("note", "n-01M3TC5H00MPJG000000000000"),
            pair("src", "zoom/t-1"),
        ]);
        assert_eq!(touch_identity(&base), touch_identity(&noted));
        let mirrored = entry(vec![pair("kind", "meet")]);
        assert_eq!(touch_identity(&base), touch_identity(&mirrored));
        // #741: duration and mode describe the touch, they do not make it a
        // different touchpoint for idempotency.
        let rich = entry(vec![
            token("meet"),
            pair("duration", "60m"),
            pair("mode", "one-on-one"),
        ]);
        assert_eq!(touch_identity(&base), touch_identity(&rich));
        let other_kind = entry(vec![token("call")]);
        assert_ne!(touch_identity(&base), touch_identity(&other_kind));
        // Kind-less mirrored line: no identity.
        assert!(touch_identity(&entry(vec![])).is_none());
        // Unknown kind: no identity (E_TOUCH_MALFORMED covers it),
        // whether it arrives positionally or as a `kind:` pair.
        assert!(touch_identity(&entry(vec![token("coffee")])).is_none());
        assert!(touch_identity(&entry(vec![pair("kind", "coffee")])).is_none());
        // Another verb: no identity.
        let mut session = base.clone();
        session.verb = "session".to_owned();
        assert!(touch_identity(&session).is_none());
    }
}
