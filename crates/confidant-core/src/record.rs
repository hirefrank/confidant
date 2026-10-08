//! Markdown records with identity-only front matter (ADR-2).

use std::collections::BTreeMap;

use crate::id::{strip_cf, Prefix, RecordId};
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
    /// 1-based line after the closing `---` fence (BOM-stripped layout).
    pub body_start_line: u32,
}

impl Record {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn person(&self) -> Option<RecordId> {
        match parse_ref_id(self.field("person")?) {
            FrontmatterRef::Id(id) => Some(id),
            FrontmatterRef::Absent | FrontmatterRef::Invalid => None,
        }
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

pub(crate) fn is_spec_key(key: &str) -> bool {
    SPEC_KEYS.contains(&key)
}

/// Spec key on a raw front-matter line, if any. Comments and unknown keys
/// return `None` so callers can name the line without echoing it.
/// Result of parsing a `person` / `org` / `deal` front-matter value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FrontmatterRef {
    /// Missing, empty, YAML `~`, or YAML `null`.
    Absent,
    Id(RecordId),
    Invalid,
}

/// Parse a `person` / `org` / `deal` front-matter value as a record ID after
/// stripping format characters, surrounding quotes, a trailing comment
/// introduced by a space or tab then `#` (including after a closing quote),
/// and `[[id|Alias]]` only inside `[[…]]`. Empty, `~`, and YAML `null` are
/// [`FrontmatterRef::Absent`].
pub(crate) fn parse_ref_id(raw: &str) -> FrontmatterRef {
    let stripped = strip_cf(raw);
    let trimmed = strip_comment_after_quoted(stripped.trim());
    let unquoted = unquote(trimmed.trim());
    let mut trimmed = unquoted.trim();
    if let Some(idx) = ref_comment_start(trimmed) {
        trimmed = trimmed[..idx].trim();
    }
    if trimmed.is_empty() || is_yaml_null(trimmed) {
        return FrontmatterRef::Absent;
    }
    let id_part = if let Some(inner) = trimmed
        .strip_prefix("[[")
        .and_then(|s| s.strip_suffix("]]"))
    {
        inner
            .split_once('|')
            .map(|(id, _)| id)
            .unwrap_or(inner)
            .trim()
    } else {
        trimmed
    };
    match RecordId::parse(id_part) {
        Ok(id) => FrontmatterRef::Id(id),
        Err(_) => FrontmatterRef::Invalid,
    }
}

fn ref_comment_start(s: &str) -> Option<usize> {
    s.find(" #").into_iter().chain(s.find("\t#")).min()
}

/// `"id" # comment` / `'[[id|Alias]]' # c` — drop the comment before unquoting.
fn strip_comment_after_quoted(s: &str) -> &str {
    let Some(q) = s.chars().next() else {
        return s;
    };
    if q != '"' && q != '\'' {
        return s;
    }
    let mut chars = s.char_indices();
    chars.next();
    if q == '"' {
        let mut escaped = false;
        for (i, c) in chars {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == '"' {
                let after = &s[i + c.len_utf8()..];
                if after.starts_with(" #") || after.starts_with("\t#") {
                    return &s[..i + c.len_utf8()];
                }
                return s;
            }
        }
        return s;
    }
    for (i, c) in chars {
        if c == '\'' {
            let after = &s[i + c.len_utf8()..];
            if after.starts_with(" #") || after.starts_with("\t#") {
                return &s[..i + c.len_utf8()];
            }
            return s;
        }
    }
    s
}

fn is_yaml_null(s: &str) -> bool {
    matches!(s, "~" | "null" | "Null" | "NULL")
}

pub(crate) fn frontmatter_line_spec_key(raw: &str) -> Option<String> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, _) = line.split_once(':')?;
    let key = unquote(key.trim());
    is_spec_key(&key).then_some(key)
}

fn is_noai_typo(key: &str) -> bool {
    if key == "no-ai" {
        return false;
    }
    normalize_noai(key) == "noai"
}

fn normalize_noai(key: &str) -> String {
    let mut folded = String::new();
    for c in key.chars() {
        match c {
            'ß' | 'ẞ' => folded.push_str("ss"),
            'İ' => folded.push('i'),
            _ => folded.extend(c.to_lowercase()),
        }
    }
    folded.chars().filter(|c| c.is_alphanumeric()).collect()
}

type FrontmatterFields = (BTreeMap<String, String>, String, BTreeMap<String, u32>, u32);

/// Split a Markdown file into front matter scalars and body.
/// Key line numbers are 1-based in the original file (the opening `---` is line 1).
pub fn split_frontmatter(text: &str) -> Result<FrontmatterFields, FrontmatterError> {
    let text = text.trim_start_matches('\u{feff}');
    let rest = strip_open_fence(text).ok_or_else(|| {
        if text.strip_prefix("---").is_some() {
            FrontmatterError::new(
                "front matter opener --- must be followed by a newline (line 1)",
                "Put id: and type: on the lines after the opening ---",
            )
            .at_line(1)
        } else {
            FrontmatterError::new(
                "record does not start with YAML front matter (line 1)",
                "Start the file with --- then id and type, then a closing ---",
            )
            .at_line(1)
        }
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
        let key = unquote(key.trim());
        if key.is_empty() {
            return Err(FrontmatterError::new(
                format!("front matter key is empty (line {line_no})"),
                "Each front matter line must be key: value",
            )
            .at_line(line_no));
        }
        if is_noai_typo(&key) {
            return Err(FrontmatterError::new(
                format!("front matter line {line_no} has a no-ai key typo"),
                "Use the exact key no-ai: true or no-ai: false",
            )
            .at_line(line_no));
        }
        if fields.contains_key(&key) {
            return Err(FrontmatterError::key_at(
                line_no,
                &key,
                "is duplicated",
                "Keep a single value for each front matter key",
            ));
        }
        fields.insert(key.clone(), unquote(value.trim()));
        key_lines.insert(key, line_no);
        line_no += 1;
    }
    Ok((
        fields,
        body.trim_start_matches(['\n', '\r']).to_owned(),
        key_lines,
        body_start_line(fm),
    ))
}

fn body_start_line(fm: &str) -> u32 {
    let fm_lines = if fm.is_empty() {
        0
    } else {
        fm.lines().count() as u32
    };
    1 + fm_lines + 1 + 1
}

fn strip_open_fence(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("---")?;
    let nl = rest.find('\n')?;
    let mut head = &rest[..nl];
    if let Some(stripped) = head.strip_suffix('\r') {
        head = stripped;
    }
    if !is_fence_padding(head) {
        return None;
    }
    Some(&rest[nl + 1..])
}

fn split_close(rest: &str) -> Option<(&str, &str)> {
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if is_yaml_fence_line(trimmed) {
            return Some((&rest[..offset], &rest[offset + line.len()..]));
        }
        offset += line.len();
    }
    None
}

fn is_yaml_fence_line(line: &str) -> bool {
    line.strip_prefix("---").is_some_and(is_fence_padding)
}

fn is_fence_padding(s: &str) -> bool {
    s.bytes().all(|b| b == b' ' || b == b'\t')
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
    let (fields, body, key_lines, body_start_line) = split_frontmatter(text)?;
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
        body_start_line,
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
        for key in ["No-AI", "no_ai", "noai", "no\u{2013}ai", "no.ai"] {
            let src =
                format!("---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n{key}: true\n---\n");
            let err = parse_record(&src, "x.md").unwrap_err();
            assert!(err.message.contains("line 4"), "{key}: {}", err.message);
            assert!(!err.message.contains(key), "{key}: {}", err.message);
            assert!(!err.message.contains("true"), "{}", err.message);
        }
    }

    #[test]
    fn quoted_no_ai_key_is_the_real_flag() {
        for key in ["\"no-ai\"", "'no-ai'"] {
            let src =
                format!("---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n{key}: true\n---\n");
            let rec = parse_record(&src, "x.md").unwrap();
            assert!(rec.no_ai(), "{key}");
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

    #[test]
    fn fences_allow_trailing_ascii_spaces_and_tabs() {
        let src =
            "---   \nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: Ada\n---\t \n\nBody.\n";
        let rec = parse_record(src, "x.md").unwrap();
        assert_eq!(rec.name.as_deref(), Some("Ada"));
        assert_eq!(rec.body.trim(), "Body.");
        assert_eq!(rec.body_start_line, 6);
    }

    #[test]
    fn fences_allow_trailing_ascii_spaces_and_tabs_crlf() {
        let src = "---  \t\r\nid: p-01M3TC5H00MPJG000000000000\r\ntype: person\r\nname: Ada\r\n---\t\r\n\r\nBody.\r\n";
        let rec = parse_record(src, "x.md").unwrap();
        assert_eq!(rec.name.as_deref(), Some("Ada"));
        assert_eq!(rec.body.trim(), "Body.");
        assert_eq!(rec.body_start_line, 6);
    }

    #[test]
    fn four_dashes_is_not_a_fence() {
        assert!(parse_record(
            "----\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n---\n",
            "x.md"
        )
        .is_err());
    }

    #[test]
    fn bom_shares_frontmatter_offsets() {
        let inner = "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\n---\n\nBody.\n";
        let with_bom = format!("\u{feff}{inner}");
        let rec = parse_record(&with_bom, "x.md").unwrap();
        assert_eq!(rec.body_start_line, 5);
        let rec_plain = parse_record(inner, "x.md").unwrap();
        assert_eq!(rec_plain.body_start_line, 5);
        assert_eq!(
            super::frontmatter_line_spec_key("person: p-01M3TC5H00MPJG000000000000"),
            Some("person".into())
        );
        assert!(super::frontmatter_line_spec_key("# see p-01M3TC5H00MPJG000000000000").is_none());
        assert!(super::frontmatter_line_spec_key("see: p-01M3TC5H00MPJG000000000000").is_none());
    }

    #[test]
    fn parse_ref_id_strips_quotes_wikilinks_and_cf() {
        let id = crate::id::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        assert_eq!(
            super::parse_ref_id("[[p-01M3TC5H00MPJG000000000000]]"),
            super::FrontmatterRef::Id(id.clone())
        );
        assert_eq!(
            super::parse_ref_id("\"p-\u{200b}01M3TC5H00MPJG000000000000\""),
            super::FrontmatterRef::Id(id.clone())
        );
        assert_eq!(
            super::parse_ref_id("[[p-01M3TC5H00MPJG000000000000|Ada]]"),
            super::FrontmatterRef::Id(id.clone())
        );
        assert_eq!(
            super::parse_ref_id("p-01M3TC5H00MPJG000000000000 # comment"),
            super::FrontmatterRef::Id(id.clone())
        );
        assert_eq!(
            super::parse_ref_id("Jane Doe"),
            super::FrontmatterRef::Invalid
        );
        assert_eq!(
            super::parse_ref_id("\"Jane Doe\""),
            super::FrontmatterRef::Invalid
        );
        assert_eq!(super::parse_ref_id("~"), super::FrontmatterRef::Absent);
        assert_eq!(super::parse_ref_id(""), super::FrontmatterRef::Absent);
        assert_eq!(
            super::parse_ref_id("~ # comment"),
            super::FrontmatterRef::Absent
        );
        assert_eq!(super::parse_ref_id("null"), super::FrontmatterRef::Absent);
        assert_eq!(super::parse_ref_id("Null"), super::FrontmatterRef::Absent);
        assert_eq!(super::parse_ref_id("NULL"), super::FrontmatterRef::Absent);
        assert_eq!(
            super::parse_ref_id("null # comment"),
            super::FrontmatterRef::Absent
        );
        assert_eq!(
            super::parse_ref_id("p-01M3TC5H00MPJG000000000000\t# comment"),
            super::FrontmatterRef::Id(id.clone())
        );
        assert_eq!(
            super::parse_ref_id("p-01M3TC5H00MPJG000000000000|Ada"),
            super::FrontmatterRef::Invalid
        );
        assert_eq!(
            super::parse_ref_id("\"p-01M3TC5H00MPJG000000000000\" # Ada"),
            super::FrontmatterRef::Id(id.clone())
        );
        assert_eq!(
            super::parse_ref_id("'[[p-01M3TC5H00MPJG000000000000|Ada]]' # c"),
            super::FrontmatterRef::Id(id)
        );
    }

    #[test]
    fn person_parses_wikilink_alias_and_comment() {
        let id = crate::id::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        for person in [
            "[[p-01M3TC5H00MPJG000000000000]]",
            "[[p-01M3TC5H00MPJG000000000000|Ada]]",
            "p-01M3TC5H00MPJG000000000000 # comment",
            "p-01M3TC5H00MPJG000000000000\t# comment",
        ] {
            let src = format!(
                "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: \"{person}\"\n---\n"
            );
            let rec = parse_record(&src, "x.md").unwrap();
            assert_eq!(rec.person().as_ref(), Some(&id), "{person}");
        }
        let bare_pipe = parse_record(
            "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: p-01M3TC5H00MPJG000000000000|Ada\n---\n",
            "x.md",
        )
        .unwrap();
        assert_eq!(bare_pipe.person(), None);
        let yaml_null = parse_record(
            "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: null\n---\n",
            "x.md",
        )
        .unwrap();
        assert_eq!(yaml_null.person(), None);
        let quoted_hash = parse_record(
            "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: \"p-01M3TC5H00MPJG000000000000\" # Ada\n---\n",
            "x.md",
        )
        .unwrap();
        assert_eq!(quoted_hash.person().as_ref(), Some(&id));
        let quoted_wikilink = parse_record(
            "---\nid: n-01M3TC5H00MPJG002NAM000005\ntype: note\nperson: '[[p-01M3TC5H00MPJG000000000000|Ada]]' # c\n---\n",
            "x.md",
        )
        .unwrap();
        assert_eq!(quoted_wikilink.person().as_ref(), Some(&id));
    }
}
