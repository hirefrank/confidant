//! Markdown records with identity-only front matter (ADR-2).

use std::collections::BTreeMap;

use crate::id::{Prefix, RecordId};

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
}

impl Record {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn person(&self) -> Option<RecordId> {
        self.field("person").and_then(|s| RecordId::parse(s).ok())
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
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' && bytes[s.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[s.len() - 1] == b'\'')
        {
            return s[1..s.len() - 1]
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }
    }
    s.to_owned()
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
    let name = fields.get("name").cloned().filter(|s| !s.is_empty());
    let _ = path;
    Ok(Record {
        id,
        kind,
        path: path.to_owned(),
        name,
        fields,
        body,
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
        if v.chars().any(char::is_whitespace) {
            out.push_str(&format!("{k}: \"{v}\"\n"));
        } else {
            out.push_str(&format!("{k}: {v}\n"));
        }
    }
    out.push_str("---\n");
    if !record.body.is_empty() {
        if !record.body.starts_with('\n') {
            // body stored without leading newline
        }
        out.push('\n');
        out.push_str(&record.body);
        if !record.body.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

pub fn has_conflict_markers(text: &str) -> bool {
    text.lines()
        .any(|l| l.starts_with("<<<<<<<") || l.starts_with(">>>>>>>") || l == "=======")
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
    }
}
