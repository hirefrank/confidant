//! Escaping untrusted pack text before it reaches a terminal or a review
//! report (#499).
//!
//! Everything a pack ships is untrusted input: its manifest values, file
//! names and skill text. `pack add` prints that text as the operator's review
//! gate (PD10), so a hostile value must not be able to conceal or reorder the
//! lines the operator is meant to read. Two threats are outside
//! [`char::is_control`]:
//!
//! - newlines and tabs in a *single-line* field, which would inject lines;
//! - Unicode format (`Cf`) characters: bidi overrides/isolates, zero-width
//!   marks and tag characters, which can reorder or hide visible text.
//!
//! `escape_line` is for values that belong on one line; `escape_text` is for
//! multi-line prose (a `SKILL.md` body), where newlines and tabs are
//! intended.

/// Escape a value that belongs on one line: all control characters
/// (including newline and tab), Unicode format characters and line/paragraph
/// separators become visible escapes.
pub fn escape_line(text: &str) -> String {
    escape(text, false)
}

/// Escape multi-line prose: newline and tab survive; every other control or
/// format character becomes a visible escape.
pub fn escape_text(text: &str) -> String {
    escape(text, true)
}

fn escape(text: &str, keep_newlines: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\n' if keep_newlines => out.push('\n'),
            '\t' if keep_newlines => out.push('\t'),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() || is_format_char(c) || is_line_separator(c) => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Unicode general category `Cf` (format). Hand-rolled because the standard
/// library exposes only `Cc` (`char::is_control`) and pulling in a general
/// category table for one review report is not worth a dependency. Covers
/// the bidi controls and isolates, zero-width marks, and the tag block.
fn is_format_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// `Zl` / `Zp`: they break a line visually without being `Cc` or `Cf`.
fn is_line_separator(ch: char) -> bool {
    matches!(ch, '\u{2028}' | '\u{2029}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_line_breaks_lines_and_tabs() {
        assert_eq!(escape_line("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(escape_line("a\rb"), "a\\rb");
    }

    #[test]
    fn escape_text_keeps_intended_newlines_and_tabs() {
        assert_eq!(escape_text("a\nb\tc"), "a\nb\tc");
        assert_eq!(escape_text("a\rb"), "a\\rb");
    }

    #[test]
    fn escape_line_escapes_control_and_bidi() {
        let escaped = escape_line("safe\u{1b}[8m\u{202e}x\u{2066}y\u{200b}z");
        for raw in ['\u{1b}', '\u{202e}', '\u{2066}', '\u{200b}'] {
            assert!(!escaped.contains(raw), "raw {raw:?} survived: {escaped}");
        }
        assert!(escaped.contains("\\u{1b}"), "{escaped}");
        assert!(escaped.contains("\\u{202e}"), "{escaped}");
        assert!(escaped.contains("\\u{2066}"), "{escaped}");
        assert!(escaped.contains("\\u{200b}"), "{escaped}");
    }

    #[test]
    fn escape_text_escapes_bidi_too() {
        let escaped = escape_text("line one\n\u{202e}line two");
        assert!(!escaped.contains('\u{202e}'), "{escaped}");
        assert!(escaped.contains('\n'), "newline must survive: {escaped}");
        assert!(escaped.contains("\\u{202e}"), "{escaped}");
    }

    #[test]
    fn escape_line_escapes_unicode_line_separators() {
        assert_eq!(escape_line("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(escape_line("café — Ada Example"), "café — Ada Example");
    }
}
