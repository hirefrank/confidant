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
}

/// Split a Markdown file into front matter scalars and body.
pub fn split_frontmatter(
    text: &str,
) -> Result<(BTreeMap<String, String>, String), FrontmatterError> {
    let text = text.trim_start_matches('\u{feff}');
    let rest = text.strip_prefix("---").ok_or(FrontmatterError {
        message: "record does not start with YAML front matter (---)".to_owned(),
        fix: "Start the file with --- then id and type, then a closing ---".to_owned(),
    })?;
    let rest = rest
        .strip_prefix('\n')
        .or_else(|| rest.strip_prefix("\r\n"))
        .ok_or(FrontmatterError {
            message: "front matter opener --- must be followed by a newline".to_owned(),
            fix: "Put id: and type: on the lines after the opening ---".to_owned(),
        })?;
    let (fm, body) = split_close(rest).ok_or(FrontmatterError {
        message: "front matter is not closed with ---".to_owned(),
        fix: "Add a closing --- line after the identity fields".to_owned(),
    })?;
    let mut fields = BTreeMap::new();
    for raw in fm.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once(':').ok_or(FrontmatterError {
            message: format!("front matter line '{line}' is not key: value"),
            fix: "Use simple key: value scalars; nested YAML is not part of spec 0.1".to_owned(),
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(FrontmatterError {
                message: "front matter key is empty".to_owned(),
                fix: "Each front matter line must be key: value".to_owned(),
            });
        }
        if fields.contains_key(key) {
            return Err(FrontmatterError {
                message: format!("front matter key '{key}' is duplicated"),
                fix: "Keep a single value for each front matter key".to_owned(),
            });
        }
        fields.insert(key.to_owned(), unquote(value.trim()));
    }
    Ok((fields, body.trim_start_matches(['\n', '\r']).to_owned()))
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
    let (fields, body) = split_frontmatter(text)?;
    let id_raw = fields.get("id").ok_or(FrontmatterError {
        message: "front matter is missing id".to_owned(),
        fix: "Add id: <prefix>-<ULID>".to_owned(),
    })?;
    let type_raw = fields.get("type").ok_or(FrontmatterError {
        message: "front matter is missing type".to_owned(),
        fix: "Add type: person | org | deal | interaction | note".to_owned(),
    })?;
    let kind = RecordKind::parse(type_raw).ok_or(FrontmatterError {
        message: format!("unknown record type '{type_raw}'"),
        fix: "Use type: person, org, deal, interaction, or note".to_owned(),
    })?;
    let id = RecordId::parse(id_raw).map_err(|err| FrontmatterError {
        message: format!("invalid id '{id_raw}': {err}"),
        fix: "Use a prefixed 26-character Crockford ULID".to_owned(),
    })?;
    if let Some(v) = fields.get("no-ai") {
        if v != "true" && v != "false" {
            return Err(FrontmatterError {
                message: format!("no-ai must be true or false (got '{v}')"),
                fix: "Use no-ai: true or no-ai: false".to_owned(),
            });
        }
    }
    for key in ["date", "session"] {
        if let Some(v) = fields.get(key) {
            if parse_strict_date(v).is_none() {
                return Err(FrontmatterError {
                    message: format!("front matter {key} '{v}' is not YYYY-MM-DD"),
                    fix: "Use a zero-padded calendar date such as 2026-10-08".to_owned(),
                });
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
        assert!(parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: widget\n---\n",
            "x.md"
        )
        .is_err());
        assert!(parse_record("---\ntype: person\n---\n", "x.md").is_err());
        assert!(parse_record(
            "---\nid: p-01M3TC5H00MPJG000000000000\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n---\n",
            "x.md"
        )
        .is_err());
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
