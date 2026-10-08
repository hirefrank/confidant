//! Markdown records with identity-only front matter (ADR-2).

use std::collections::BTreeMap;

use crate::id::{Prefix, RecordId};
use crate::ledger::parse_strict_date;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Person,
    Org,
    Deal,
    Interaction,
    Note,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Org => "org",
            Self::Deal => "deal",
            Self::Interaction => "interaction",
            Self::Note => "note",
        }
    }

    pub fn prefix(self) -> Prefix {
        match self {
            Self::Person => Prefix::Person,
            Self::Org => Prefix::Org,
            Self::Deal => Prefix::Deal,
            Self::Interaction => Prefix::Interaction,
            Self::Note => Prefix::Note,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "person" => Some(Self::Person),
            "org" => Some(Self::Org),
            "deal" => Some(Self::Deal),
            "interaction" => Some(Self::Interaction),
            "note" => Some(Self::Note),
            _ => None,
        }
    }

    pub fn allows_no_ai(self) -> bool {
        match self {
            Self::Person | Self::Note | Self::Deal | Self::Interaction => true,
            Self::Org => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub id: RecordId,
    pub kind: RecordKind,
    /// POSIX relative path from the vault root.
    pub path: String,
    pub name: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub body: String,
    /// Original file text, used so search line numbers match the file.
    pub source: String,
}

impl Record {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn person(&self) -> Option<RecordId> {
        self.field("person").and_then(|s| RecordId::parse(s).ok())
    }

    pub fn no_ai(&self) -> bool {
        self.field("no-ai") == Some("true")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontmatterError {
    pub message: String,
    pub fix: String,
    pub line: Option<u32>,
}

impl FrontmatterError {
    fn new(message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fix: fix.into(),
            line: None,
        }
    }

    fn at_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    fn key_at(line: u32, key: &str, problem: &str, fix: impl Into<String>) -> Self {
        let message = if is_spec_key(key) {
            format!("front matter key '{key}' {problem} (line {line})")
        } else {
            format!("front matter line {line} {problem}")
        };
        Self {
            message,
            fix: fix.into(),
            line: Some(line),
        }
    }
}

const SPEC_KEYS: &[&str] = &[
    "id", "type", "name", "date", "person", "org", "deal", "session", "no-ai",
];

fn is_spec_key(key: &str) -> bool {
    SPEC_KEYS.contains(&key)
}

fn is_noai_typo(key: &str) -> bool {
    if key == "no-ai" {
        return false;
    }
    normalize_noai(key) == "noai"
}

fn normalize_noai(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars() {
        if is_stripped_noai_char(c) {
            continue;
        }
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'İ' => out.push('i'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

fn is_stripped_noai_char(c: char) -> bool {
    matches!(
        c,
        '-' | '_'
            | ' '
            | '\t'
            | '\u{00ad}'
            | '\u{2010}'
            | '\u{2011}'
            | '\u{2012}'
            | '\u{2013}'
            | '\u{2014}'
            | '\u{2015}'
            | '\u{2212}'
            | '\u{fe58}'
            | '\u{fe63}'
            | '\u{ff0d}'
    )
}

type FrontmatterFields = (BTreeMap<String, String>, String, BTreeMap<String, u32>);

/// Split a Markdown file into front matter scalars and body.
/// Key line numbers are 1-based in the original file (the opening `---` is line 1).
pub fn split_frontmatter(text: &str) -> Result<FrontmatterFields, FrontmatterError> {
    let text = text.trim_start_matches('\u{feff}');
    let rest = text.strip_prefix("---").ok_or_else(|| {
        FrontmatterError::new(
            "record does not start with YAML front matter (line 1)",
            "Start the file with --- then id and type, then a closing ---",
        )
        .at_line(1)
    })?;
    let rest = rest
        .strip_prefix('\n')
        .or_else(|| rest.strip_prefix("\r\n"))
        .ok_or_else(|| {
            FrontmatterError::new(
                "front matter opener --- must be followed by a newline (line 1)",
                "Put id: and type: on the lines after the opening ---",
            )
            .at_line(1)
        })?;
    let (fm, body) = split_close(rest).ok_or_else(|| {
        FrontmatterError::new(
            "front matter is not closed with ---",
            "Add a closing --- line after the identity fields",
        )
    })?;
    let mut fields = BTreeMap::new();
    let mut key_lines = BTreeMap::new();
    // Opening `---` consumed line 1.
    let mut line_no: u32 = 2;
    for raw in fm.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            line_no += 1;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(FrontmatterError::new(
                format!("front matter line {line_no} is not key: value"),
                "Use simple key: value scalars; nested YAML is not part of spec 0.1",
            )
            .at_line(line_no));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(FrontmatterError::new(
                format!("front matter key is empty (line {line_no})"),
                "Each front matter line must be key: value",
            )
            .at_line(line_no));
        }
        if is_noai_typo(key) {
            return Err(FrontmatterError::new(
                format!("front matter line {line_no} has a no-ai key typo"),
                "Use the exact key no-ai: true or no-ai: false",
            )
            .at_line(line_no));
        }
        if fields.contains_key(key) {
            return Err(FrontmatterError::key_at(
                line_no,
                key,
                "is duplicated",
                "Keep a single value for each front matter key",
            ));
        }
        fields.insert(key.to_owned(), unquote(value.trim()));
        key_lines.insert(key.to_owned(), line_no);
        line_no += 1;
    }
    Ok((
        fields,
        body.trim_start_matches(['\n', '\r']).to_owned(),
        key_lines,
    ))
}

fn split_close(rest: &str) -> Option<(&str, &str)> {
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == "---" {
            return Some((&rest[..offset], &rest[offset + line.len()..]));
        }
        offset += line.len();
    }
    None
}

fn unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return unescape(&s[1..s.len() - 1]);
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return s[1..s.len() - 1].to_owned();
    }
    s.to_owned()
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n @ ('"' | '\\')) => out.push(n),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn parse_record(text: &str, path: &str) -> Result<Record, FrontmatterError> {
    let (fields, body, key_lines) = split_frontmatter(text)?;
    let line_of = |key: &str| key_lines.get(key).copied();
    let id_raw = fields.get("id").ok_or_else(|| {
        FrontmatterError::new(
            "front matter is missing key 'id'",
            "Add id: <prefix>-<ULID>",
        )
    })?;
    let type_raw = fields.get("type").ok_or_else(|| {
        FrontmatterError::new(
            "front matter is missing key 'type'",
            "Add type: person | org | deal | interaction | note",
        )
    })?;
    let kind = RecordKind::parse(type_raw).ok_or_else(|| {
        let line = line_of("type").unwrap_or(1);
        FrontmatterError::key_at(
            line,
            "type",
            "has an unknown value",
            "Use type: person, org, deal, interaction, or note",
        )
    })?;
    let id = RecordId::parse(id_raw).map_err(|_| {
        let line = line_of("id").unwrap_or(1);
        FrontmatterError::key_at(
            line,
            "id",
            "is not a record ID",
            "Use a prefixed 26-character Crockford ULID",
        )
    })?;
    if fields.contains_key("no-ai") {
        let line = line_of("no-ai").unwrap_or(1);
        if !kind.allows_no_ai() {
            return Err(FrontmatterError::key_at(
                line,
                "no-ai",
                "is not allowed on this record type",
                "Use no-ai only on person, note, interaction, or deal records",
            ));
        }
        let v = fields.get("no-ai").map(String::as_str).unwrap_or("");
        if v != "true" && v != "false" {
            return Err(FrontmatterError::key_at(
                line,
                "no-ai",
                "is not a boolean",
                "Use no-ai: true or no-ai: false",
            ));
        }
    }
    for key in ["date", "session"] {
        if let Some(v) = fields.get(key) {
            if parse_strict_date(v).is_none() {
                let line = line_of(key).unwrap_or(1);
                return Err(FrontmatterError::key_at(
                    line,
                    key,
                    "is not YYYY-MM-DD",
                    "Use a zero-padded calendar date such as 2026-10-08",
                ));
            }
        }
    }
    let name = fields.get("name").cloned().filter(|s| !s.is_empty());
    Ok(Record {
        id,
        kind,
        path: path.to_owned(),
        name,
        fields,
        body,
        source: text.to_owned(),
    })
}

pub fn format_record(record: &Record) -> String {
    let mut out = String::from("---\n");
    out.push_str(&format!("id: {}\n", record.id));
    out.push_str(&format!("type: {}\n", record.kind.as_str()));
    for (k, v) in &record.fields {
        if k == "id" || k == "type" {
            continue;
        }
        out.push_str(&format!("{k}: {}\n", quote_scalar(v)));
    }
    out.push_str("---\n");
    if !record.body.is_empty() {
        out.push('\n');
        out.push_str(&record.body);
        if !record.body.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn quote_scalar(s: &str) -> String {
    if needs_scalar_quotes(s) {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        s.to_owned()
    }
}

fn needs_scalar_quotes(s: &str) -> bool {
    s.is_empty()
        || s.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    ':' | '#'
                        | '"'
                        | '\''
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | ','
                        | '&'
                        | '*'
                        | '!'
                        | '|'
                        | '>'
                        | '%'
                        | '@'
                        | '`'
                )
        })
}

pub fn has_conflict_markers(text: &str) -> bool {
    // Setext underlines of `=======` are ordinary Markdown, not a git conflict.
    // `<<<<<<<` / `>>>>>>>` are the unambiguous conflict markers.
    text.lines()
        .any(|l| l.starts_with("<<<<<<<") || l.starts_with(">>>>>>>"))
}

#[cfg(test)]
mod tests {
    use super::{format_record, parse_record};

    #[test]
    fn round_trip_profile() {
        let src = "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: Ada Example\n---\n\nGoals: ship a CRM.\n";
        let rec = parse_record(src, "people/p-01M3TC5H00MPJG000000000000/profile.md").unwrap();
        assert_eq!(rec.name.as_deref(), Some("Ada Example"));
        let again = parse_record(&format_record(&rec), &rec.path).unwrap();
        assert_eq!(rec.id, again.id);
        assert_eq!(rec.kind, again.kind);
        assert_eq!(rec.name, again.name);
        assert_eq!(rec.body.trim(), again.body.trim());
    }

    #[test]
    fn malformed_frontmatter() {
        assert!(parse_record("no front matter", "x.md").is_err());
        assert!(parse_record("---\nid: p-01M3TC5H00MPJG000000000000\n", "x.md").is_err());
        let unknown_type = parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: widget\n---\n",
            "x.md",
        )
        .unwrap_err();
        assert!(unknown_type.message.contains("type"));
        assert!(!unknown_type.message.contains("widget"));
        assert!(parse_record("---\ntype: person\n---\n", "x.md").is_err());
        let dup = parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n---\n",
            "x.md",
        )
        .unwrap_err();
        assert!(dup.message.contains("id"));
        assert!(dup.message.contains("duplicated"));
        assert!(!dup.message.contains("01M3TC5H00MPJG000000000000"));
        let unparsed = parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nthis is not key value\n---\n",
            "x.md",
        )
        .unwrap_err();
        assert!(unparsed.message.contains("line 4"));
        assert!(!unparsed.message.contains("this is not key value"));
        let yes = parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nno-ai: yes\n---\n",
            "x.md",
        )
        .unwrap_err();
        assert!(yes.message.contains("no-ai"));
        assert!(!yes.message.contains("yes"));
        let org = parse_record(
            "---\nid: o-01M3TC5H00MPJG001K6C000003\ntype: org\nno-ai: true\n---\n",
            "x.md",
        )
        .unwrap_err();
        assert!(org.message.contains("no-ai"));
        assert!(org.message.contains("not allowed"));
        for key in ["No-AI", "no_ai", "noai", "no\u{2013}ai"] {
            let src =
                format!("---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n{key}: true\n---\n");
            let err = parse_record(&src, "x.md").unwrap_err();
            assert!(err.message.contains("line 4"), "{key}: {}", err.message);
            assert!(!err.message.contains(key), "{key}: {}", err.message);
            assert!(!err.message.contains("true"), "{}", err.message);
        }
    }

    #[test]
    fn quoting_round_trips_quotes_and_colons() {
        let src = "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: \"Ada \\\"Example\\\": coach\"\n---\n\nHi.\n";
        let rec = parse_record(src, "people/p-01M3TC5H00MPJG000000000000/profile.md").unwrap();
        assert_eq!(rec.name.as_deref(), Some(r#"Ada "Example": coach"#));
        let again = parse_record(&format_record(&rec), &rec.path).unwrap();
        assert_eq!(rec.name, again.name);
    }

    #[test]
    fn setext_underline_is_not_a_conflict() {
        let src = "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n---\n\nTitle\n=======\n";
        assert!(!super::has_conflict_markers(src));
        assert!(parse_record(src, "x.md").is_ok());
        assert!(super::has_conflict_markers(
            "<<<<<<< HEAD\n=======\n>>>>>>> other\n"
        ));
    }

    #[test]
    fn crlf_front_matter() {
        let src = "---\r\nid: p-01M3TC5H00MPJG000000000000\r\ntype: person\r\nname: Ada\r\n---\r\n\r\nBody.\r\n";
        let rec = parse_record(src, "x.md").unwrap();
        assert_eq!(rec.name.as_deref(), Some("Ada"));
    }
}
