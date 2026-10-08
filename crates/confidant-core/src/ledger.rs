//! Dated one-line ledger grammar (ADR-2).

use chrono::NaiveDate;

use crate::id::RecordId;

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
    pub message: String,
    pub fix: String,
}

/// Parse a whole ledger file. Blank lines and comment-only lines are skipped.
/// Each bad line is a [`ParseError`]; parsing continues (collect-don't-throw).
pub fn parse_ledger(text: &str) -> (Vec<(u32, LedgerEntry)>, Vec<ParseError>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx as u32 + 1;
        match parse_line(raw) {
            Ok(None) => {}
            Ok(Some(entry)) => entries.push((line, entry)),
            Err(message) => errors.push(ParseError {
                line,
                message,
                fix: "Fix the line so it matches DATE VERB ID ARGS…  ; comment".to_owned(),
            }),
        }
    }
    (entries, errors)
}

pub fn parse_line(raw: &str) -> Result<Option<LedgerEntry>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with(';') {
        return Ok(None);
    }
    let mut lexer = Lexer::new(trimmed);
    let date = lexer.date()?;
    let verb = lexer.ident("verb")?;
    let id_raw = lexer.ident("id")?;
    let id = RecordId::parse(&id_raw).map_err(|err| format!("invalid id '{id_raw}': {err}"))?;
    let mut args = Vec::new();
    while !lexer.done() {
        if lexer.peek_comment() {
            break;
        }
        args.push(lexer.arg()?);
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
        self.bump_ws();
        let tok = self.take_while(|c| c.is_ascii_digit() || c == '-')?;
        NaiveDate::parse_from_str(&tok, "%Y-%m-%d")
            .map_err(|_| format!("'{tok}' is not a calendar date YYYY-MM-DD"))
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
        let raw = self.take_while(|c| !c.is_whitespace() && c != ';')?;
        if let Some((key, value)) = split_pair(&raw) {
            Ok(Arg::Pair {
                key: key.to_owned(),
                value: value.to_owned(),
            })
        } else {
            Ok(Arg::Token(raw))
        }
    }

    fn quoted(&mut self) -> Result<String, String> {
        debug_assert!(self.s[self.i..].starts_with('"'));
        self.i += 1;
        let mut out = String::new();
        let bytes = self.s.as_bytes();
        while self.i < bytes.len() {
            let c = bytes[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.i >= bytes.len() {
                        return Err("unterminated escape in quoted string".to_owned());
                    }
                    let n = bytes[self.i];
                    self.i += 1;
                    match n {
                        b'"' | b'\\' => out.push(n as char),
                        _ => {
                            out.push('\\');
                            out.push(n as char);
                        }
                    }
                }
                _ => out.push(c as char),
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

fn split_pair(raw: &str) -> Option<(&str, &str)> {
    let (key, value) = raw.split_once(':')?;
    if key.is_empty() || value.is_empty() {
        return None;
    }
    if !key.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return None;
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return None;
    }
    Some((key, value))
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
        let mag = whole_n.abs().checked_mul(100)?.checked_add(frac_n)?;
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
}
