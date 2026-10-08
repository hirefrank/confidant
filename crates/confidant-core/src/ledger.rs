//! Dated one-line ledger grammar (ADR-2).

use chrono::NaiveDate;

use crate::id::{strip_cf, RecordId};

/// One argument after the record ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Arg {
    Token(String),
    Pair { key: String, value: String },
}

impl Arg {
    pub fn as_token(&self) -> Option<&str> {
        match self {
            Self::Token(s) => Some(s),
            Self::Pair { .. } => None,
        }
    }

    pub fn pair(&self) -> Option<(&str, &str)> {
        match self {
            Self::Pair { key, value } => Some((key, value)),
            Self::Token(_) => None,
        }
    }

    pub fn render(&self) -> String {
        match self {
            Self::Token(s) => quote_if_needed(s),
            Self::Pair { key, value } => {
                if needs_quotes(value) {
                    format!("{key}:{}", quote_if_needed(value))
                } else {
                    format!("{key}:{value}")
                }
            }
        }
    }
}

/// A parsed ledger entry. Comments are preserved for round-trip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEntry {
    pub date: NaiveDate,
    pub verb: String,
    pub id: RecordId,
    pub args: Vec<Arg>,
    pub comment: Option<String>,
}

/// Strict `YYYY-MM-DD`: zero-padded, exactly 10 characters, a real calendar date.
pub fn parse_strict_date(s: &str) -> Option<NaiveDate> {
    if s.len() != 10 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !bytes.iter().enumerate().all(|(i, b)| {
        if i == 4 || i == 7 {
            *b == b'-'
        } else {
            b.is_ascii_digit()
        }
    }) {
        return None;
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

/// Case-folded verb on a ledger line. On any non-comment line, the verb is
/// the first or second whitespace token with a trailing `:` stripped, whether
/// or not a date parses (`2026-10-3 merge`, `merge:`, a merge with no date).
/// A leading Markdown bullet (`*`, `-`, or `+` plus whitespace) is skipped.
pub(crate) fn ledger_line_verb(text: &str) -> Option<String> {
    let stripped = strip_cf(text);
    let trimmed = stripped.trim();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    let trimmed = skip_markdown_bullet(trimmed);
    let mut toks = trimmed.split_whitespace();
    let first = toks.next()?;
    let second = toks.next();
    let norm = |s: &str| s.trim_end_matches(':').to_ascii_lowercase();
    let first = norm(first);
    if first == "merge" || first == "open" {
        return Some(first);
    }
    let second = second.map(norm)?;
    if second == "merge" || second == "open" {
        return Some(second);
    }
    None
}

fn skip_markdown_bullet(s: &str) -> &str {
    let Some(first) = s.as_bytes().first() else {
        return s;
    };
    if !matches!(first, b'*' | b'-' | b'+') {
        return s;
    }
    let rest = &s[1..];
    if rest.starts_with(' ') || rest.starts_with('\t') {
        rest.trim_start_matches([' ', '\t'])
    } else {
        s
    }
}

impl LedgerEntry {
    pub fn pair(&self, key: &str) -> Option<&str> {
        self.args.iter().find_map(|a| match a {
            Arg::Pair { key: k, value } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    pub fn has_token(&self, token: &str) -> bool {
        self.args.iter().any(|a| a.as_token() == Some(token))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub line: u32,
    pub kind: ParseErrorKind,
    pub message: String,
    pub fix: String,
}

/// Why a ledger line failed to parse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    Grammar,
    InvalidId,
}

/// Parse a whole ledger file. Blank lines and comment-only lines are skipped.
/// Each bad line is a [`ParseError`]; parsing continues (collect-don't-throw).
/// A leading UTF-8 BOM is stripped and does not affect line numbers.
pub fn parse_ledger(text: &str) -> (Vec<(u32, LedgerEntry)>, Vec<ParseError>) {
    let text = text.trim_start_matches('\u{feff}');
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx as u32 + 1;
        match parse_line_inner(raw) {
            Ok(None) => {}
            Ok(Some(entry)) => entries.push((line, entry)),
            Err(err) => errors.push(ParseError {
                line,
                kind: err.kind,
                message: err.message,
                fix: "Fix the line so it matches DATE VERB ID ARGS…  ; comment".to_owned(),
            }),
        }
    }
    (entries, errors)
}

struct LineError {
    kind: ParseErrorKind,
    message: String,
}

impl LineError {
    fn grammar(message: impl Into<String>) -> Self {
        Self {
            kind: ParseErrorKind::Grammar,
            message: message.into(),
        }
    }

    fn invalid_id(message: impl Into<String>) -> Self {
        Self {
            kind: ParseErrorKind::InvalidId,
            message: message.into(),
        }
    }
}

pub fn parse_line(raw: &str) -> Result<Option<LedgerEntry>, String> {
    parse_line_inner(raw).map_err(|err| err.message)
}

fn parse_line_inner(raw: &str) -> Result<Option<LedgerEntry>, LineError> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() || trimmed.starts_with(';') {
        return Ok(None);
    }
    let mut lexer = Lexer::new(trimmed);
    let date = lexer.date().map_err(LineError::grammar)?;
    let verb = lexer.ident("verb").map_err(LineError::grammar)?;
    let id_raw = lexer.ident("id").map_err(LineError::grammar)?;
    let id = RecordId::parse(&id_raw)
        .map_err(|_| LineError::invalid_id("ledger line has an invalid id".to_owned()))?;
    let mut args = Vec::new();
    while !lexer.done() {
        if lexer.peek_comment() {
            break;
        }
        args.push(lexer.arg().map_err(LineError::grammar)?);
    }
    let comment = lexer.comment();
    Ok(Some(LedgerEntry {
        date,
        verb: verb.to_ascii_lowercase(),
        id,
        args,
        comment,
    }))
}

/// Canonical rendering. `parse_line(format_entry(e))` equals `e`.
pub fn format_entry(entry: &LedgerEntry) -> String {
    let mut out = format!("{} {} {}", entry.date, entry.verb, entry.id);
    for arg in &entry.args {
        out.push(' ');
        out.push_str(&arg.render());
    }
    if let Some(comment) = &entry.comment {
        out.push_str("  ; ");
        out.push_str(comment);
    }
    out
}

struct Lexer<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, i: 0 }
    }

    fn done(&mut self) -> bool {
        self.bump_ws();
        self.i >= self.s.len()
    }

    fn bump_ws(&mut self) {
        while let Some(c) = self.s[self.i..].chars().next() {
            if c == ' ' || c == '\t' {
                self.i += c.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek_comment(&mut self) -> bool {
        self.bump_ws();
        self.s[self.i..].starts_with(';')
    }

    fn date(&mut self) -> Result<NaiveDate, String> {
        if self.i >= self.s.len() {
            return Err("missing date".to_owned());
        }
        let rest = &self.s[self.i..];
        let tok: String = rest.chars().take(10).collect();
        if tok.chars().count() != 10 {
            return Err("missing date YYYY-MM-DD".to_owned());
        }
        let date = parse_strict_date(&tok)
            .ok_or_else(|| "ledger line date is not YYYY-MM-DD".to_owned())?;
        self.i += 10;
        match self.s[self.i..].chars().next() {
            Some(c) if c == ' ' || c == '\t' => Ok(date),
            _ => Err("date must be followed by whitespace".to_owned()),
        }
    }

    fn ident(&mut self, what: &str) -> Result<String, String> {
        self.bump_ws();
        if self.i >= self.s.len() {
            return Err(format!("missing {what}"));
        }
        if self.s[self.i..].starts_with(';') {
            return Err(format!("missing {what}"));
        }
        self.take_while(|c| !c.is_whitespace() && c != ';')
    }

    fn arg(&mut self) -> Result<Arg, String> {
        self.bump_ws();
        if self.s[self.i..].starts_with('"') {
            let s = self.quoted()?;
            return Ok(Arg::Token(s));
        }
        let start = self.i;
        while let Some(c) = self.s[self.i..].chars().next() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
                self.i += c.len_utf8();
            } else {
                break;
            }
        }
        if self.i > start && self.s[self.i..].starts_with(':') {
            let key = self.s[start..self.i].to_owned();
            if key.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                self.i += 1;
                if self.s[self.i..].starts_with('"') {
                    let value = self.quoted()?;
                    return Ok(Arg::Pair { key, value });
                }
                let value = self.take_while(|c| !c.is_whitespace() && c != ';')?;
                return Ok(Arg::Pair { key, value });
            }
        }
        self.i = start;
        let raw = self.take_while(|c| !c.is_whitespace() && c != ';')?;
        Ok(Arg::Token(raw))
    }

    fn quoted(&mut self) -> Result<String, String> {
        debug_assert!(self.s[self.i..].starts_with('"'));
        self.i += 1;
        let mut out = String::new();
        let rest = &self.s[self.i..];
        let mut chars = rest.char_indices();
        while let Some((off, c)) = chars.next() {
            match c {
                '"' => {
                    self.i += off + c.len_utf8();
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    None => return Err("unterminated escape in quoted string".to_owned()),
                    Some((_, n)) => match n {
                        '"' | '\\' => out.push(n),
                        _ => {
                            out.push('\\');
                            out.push(n);
                        }
                    },
                },
                _ => out.push(c),
            }
        }
        Err("unterminated quoted string".to_owned())
    }

    fn comment(&mut self) -> Option<String> {
        self.bump_ws();
        if self.s[self.i..].starts_with(';') {
            let rest = self.s[self.i + 1..].trim();
            self.i = self.s.len();
            if rest.is_empty() {
                None
            } else {
                Some(rest.to_owned())
            }
        } else {
            None
        }
    }

    fn take_while(&mut self, pred: impl Fn(char) -> bool) -> Result<String, String> {
        self.bump_ws();
        let start = self.i;
        for c in self.s[self.i..].chars() {
            if pred(c) {
                self.i += c.len_utf8();
            } else {
                break;
            }
        }
        if self.i == start {
            return Err("expected a token".to_owned());
        }
        Ok(self.s[start..self.i].to_owned())
    }
}

fn needs_quotes(s: &str) -> bool {
    s.is_empty()
        || s.chars()
            .any(|c| c.is_whitespace() || c == ';' || c == '"' || c == ':')
}

fn quote_if_needed(s: &str) -> String {
    if needs_quotes(s) {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        s.to_owned()
    }
}

/// Parse `60m`, `1h`, `1h30m`.
pub fn parse_duration_minutes(s: &str) -> Option<u32> {
    let s = s.to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_suffix('m') {
        if let Some((h, m)) = rest.split_once('h') {
            if h.is_empty() || m.is_empty() {
                return None;
            }
            let hours: u32 = h.parse().ok()?;
            let mins: u32 = m.parse().ok()?;
            return hours.checked_mul(60)?.checked_add(mins);
        }
        if rest.is_empty() || rest.contains('h') {
            return None;
        }
        return rest.parse().ok();
    }
    if let Some(h) = s.strip_suffix('h') {
        if h.is_empty() {
            return None;
        }
        let hours: u32 = h.parse().ok()?;
        return hours.checked_mul(60);
    }
    None
}

/// Parse a balance number as hundredths (so `1.75` → 175).
pub fn parse_decimal_hundredths(s: &str) -> Option<i64> {
    if let Some((whole, frac)) = s.split_once('.') {
        if whole.is_empty() {
            return None;
        }
        let negative = whole.starts_with('-');
        let whole_n: i64 = whole.parse().ok()?;
        if frac.is_empty() || frac.len() > 2 || !frac.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let mut frac_n: i64 = frac.parse().ok()?;
        if frac.len() == 1 {
            frac_n *= 10;
        }
        let mag = whole_n
            .checked_abs()?
            .checked_mul(100)?
            .checked_add(frac_n)?;
        if negative {
            Some(-mag)
        } else {
            Some(mag)
        }
    } else {
        s.parse::<i64>().ok()?.checked_mul(100)
    }
}

pub fn minutes_to_hundredths(minutes: u32) -> i64 {
    // Round half-up to two decimal hours: 1 minute → 0.02h (2 hundredths).
    (i64::from(minutes) * 100 + 30) / 60
}

#[cfg(test)]
mod tests {
    use super::{format_entry, parse_duration_minutes, parse_ledger, parse_line, Arg};

    #[test]
    fn round_trip_architecture_examples() {
        let lines = [
            "2026-10-01 open p-01M3TC5H00MPJG000000000000 package pkg-01M3TC5H00MPJG004SK4000009 6 sessions  ; coaching pack",
            "2026-10-01 session p-01M3TC5H00MPJG000000000000 60m paid",
            "2026-10-03 alias p-01M3TC5H00MPJG000000000000 email hmac:3f9c7a1b8d2e4f56",
            "2026-10-08 session p-01M3TC5H00MPJG000000000000 45m paid src:transcript/t-01M3TC5H00MPJG0048H0000008",
            "2026-10-08 balance p-01M3TC5H00MPJG000000000000 sessions_remaining 4",
            "2026-10-09 stage d-01M3TC5H00MPJG00248G000004 proposal",
            "2026-10-12 merge p-01M3TC5H00MPJG000H24000001 into p-01M3TC5H00MPJG000000000000",
        ];
        for line in lines {
            let parsed = parse_line(line).unwrap().unwrap();
            let again = parse_line(&format_entry(&parsed)).unwrap().unwrap();
            assert_eq!(parsed, again, "round-trip {line}");
        }
    }

    #[test]
    fn quoted_reason_round_trips() {
        let line = r#"2026-10-12 merge p-01M3TC5H00MPJG000H24000001 into p-01M3TC5H00MPJG000000000000 reason "duplicate account""#;
        let parsed = parse_line(line).unwrap().unwrap();
        assert!(parsed.has_token("into"));
        assert!(parsed
            .args
            .iter()
            .any(|a| matches!(a, Arg::Token(s) if s == "duplicate account")));
        let again = parse_line(&format_entry(&parsed)).unwrap().unwrap();
        assert_eq!(parsed, again);
    }

    #[test]
    fn ledger_line_verb_skips_markdown_bullets() {
        let merge =
            "2026-10-01 merge p-01M3TC5H00MPJG000000000000 into p-01M3TC5H00MPJG000H24000001";
        let open = "2026-10-01 open p-01M3TC5H00MPJG000000000000 package pkg-01M3TC5H00MPJG004SK4000009 6 sessions";
        assert_eq!(
            super::ledger_line_verb(&format!("- {merge}")),
            Some("merge".into())
        );
        assert_eq!(
            super::ledger_line_verb(&format!("* {open}")),
            Some("open".into())
        );
        assert_eq!(
            super::ledger_line_verb(&format!("+\t{merge}")),
            Some("merge".into())
        );
        assert_eq!(super::ledger_line_verb("-nomerge"), None);
        assert_eq!(super::ledger_line_verb(merge), Some("merge".into()));
    }

    #[test]
    fn skips_blanks_and_comments() {
        let text = "; header\n\n2026-10-01 stage d-01M3TC5H00MPJG00248G000004 proposal\n; footer\n";
        let (entries, errors) = parse_ledger(text);
        assert!(errors.is_empty());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 3);
    }

    #[test]
    fn malformed_lines() {
        assert!(parse_line("not-a-date open p-01M3TC5H00MPJG000000000000").is_err());
        assert!(parse_line("2026-13-01 stage d-01M3TC5H00MPJG00248G000004 proposal").is_err());
        assert!(parse_line("2026-10-01").is_err());
        assert!(
            parse_line(r#"2026-10-01 stage d-01M3TC5H00MPJG00248G000004 "unterminated"#).is_err()
        );
        assert!(parse_line("2026-10-01 stage not-an-id proposal").is_err());
        assert!(parse_line("2026-10-01 stage p-01ILOU00000000000000000000 proposal").is_err());
    }

    #[test]
    fn duration_parser() {
        assert_eq!(parse_duration_minutes("60m"), Some(60));
        assert_eq!(parse_duration_minutes("1h"), Some(60));
        assert_eq!(parse_duration_minutes("1h30m"), Some(90));
        assert_eq!(parse_duration_minutes("90m"), Some(90));
        assert_eq!(parse_duration_minutes("m"), None);
        assert_eq!(parse_duration_minutes("1.5h"), None);
        assert_eq!(parse_duration_minutes("paid"), None);
    }

    #[test]
    fn pair_args() {
        let e = parse_line(
            "2026-10-08 session p-01M3TC5H00MPJG000000000000 45m note:n-01M3TC5H00MPJG002NAM000005",
        )
        .unwrap()
        .unwrap();
        assert_eq!(e.pair("note").unwrap(), "n-01M3TC5H00MPJG002NAM000005");
    }

    #[test]
    fn quoted_pair_values_round_trip() {
        let line = r#"2026-10-08 session p-01M3TC5H00MPJG000000000000 45m src:"transcript/t:foo; bar \"baz\"""#;
        let parsed = parse_line(line).unwrap().unwrap();
        assert_eq!(
            parsed.pair("src").unwrap(),
            r#"transcript/t:foo; bar "baz""#
        );
        let again = parse_line(&format_entry(&parsed)).unwrap().unwrap();
        assert_eq!(parsed, again);
    }

    #[test]
    fn quoted_unicode_round_trips() {
        let line = r#"2026-10-08 session p-01M3TC5H00MPJG000000000000 45m reason "café 日本語""#;
        let parsed = parse_line(line).unwrap().unwrap();
        assert!(parsed
            .args
            .iter()
            .any(|a| matches!(a, Arg::Token(s) if s == "café 日本語")));
        let rendered = format_entry(&parsed);
        assert!(rendered.contains("café"));
        assert!(rendered.contains("日本語"));
        let again = parse_line(&rendered).unwrap().unwrap();
        assert_eq!(parsed, again);
    }

    #[test]
    fn date_must_be_zero_padded_and_followed_by_whitespace() {
        assert!(parse_line("2026-10-1 session p-01M3TC5H00MPJG000000000000 60m").is_err());
        assert!(parse_line("2026-1-01 session p-01M3TC5H00MPJG000000000000 60m").is_err());
        assert!(parse_line("2026-10-01session p-01M3TC5H00MPJG000000000000 60m").is_err());
        assert!(parse_line("2026-10-01\tsession p-01M3TC5H00MPJG000000000000 60m").is_ok());
    }

    #[test]
    fn strips_bom_and_accepts_crlf() {
        let text =
            "\u{feff}2026-10-01 stage d-01M3TC5H00MPJG00248G000004 proposal\r\n; comment\r\n";
        let (entries, errors) = parse_ledger(text);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 1);
    }
}
