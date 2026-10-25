use std::path::{Component, Path, PathBuf};

use crate::error::DomainError;

pub(crate) const ITEM_MARKER: &str = "confidant-inbox/1";
pub(crate) const HEADER_SEP: &str = "---";
const RECORD_ROOTS: &[&str] = &["people", "orgs", "deals", "interactions", "notes"];

/// A decrypted, parsed inbox item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedItem {
    pub(crate) name: String,
    pub(crate) kind: ItemKind,
    /// Vault-relative target path (records only).
    pub(crate) path: Option<PathBuf>,
    pub(crate) content: String,
    /// Set by a `force: true` header (#747 round 3): the operator logged
    /// this line with `--force` (a deliberately repeated touch/session),
    /// so the drain processes it instead of applying the semantic
    /// duplicate skip. Absent means `false`; outside tools that do not
    /// know the header are unaffected.
    pub(crate) force: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ItemKind {
    Ledger,
    Record,
}

impl ItemKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Ledger => "ledger",
            ItemKind::Record => "record",
        }
    }
}

pub(crate) fn describe_target(item: &ParsedItem) -> String {
    match item.kind {
        ItemKind::Ledger => "ledger/*".to_string(),
        ItemKind::Record => item
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }
}
// ---------------------------------------------------------------------------
// item parsing
// ---------------------------------------------------------------------------

/// Parse a decrypted payload. Format:
/// ```text
/// confidant-inbox/1
/// kind: ledger            # or: kind: record
/// path: people/p-.../profile.md   # records only
/// force: true             # optional, ledger items only (#747 round 3)
/// ---
/// <content>
/// ```
pub(crate) fn parse_item(name: &str, text: &str) -> anyhow::Result<ParsedItem> {
    let fail = |why: &str| {
        anyhow::Error::new(DomainError::inbox_item(format!(
            "item '{name}' is malformed: {why}"
        )))
    };
    let mut kind: Option<ItemKind> = None;
    let mut path: Option<String> = None;
    let mut force = false;
    let mut force_seen = false;
    let mut body_at: Option<usize> = None;
    let all: Vec<&str> = text.lines().collect();
    match all.first() {
        Some(l) if l.trim_end_matches(['\r', ' ']) == ITEM_MARKER => {}
        _ => return Err(fail("first line must be `confidant-inbox/1`")),
    }
    for (i, line) in all.iter().enumerate().skip(1) {
        if *line == HEADER_SEP {
            body_at = Some(i + 1);
            break;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| fail("bad header line"))?;
        match k.trim() {
            "kind" => {
                if kind.is_some() {
                    return Err(fail("duplicate kind header"));
                }
                kind = Some(match v.trim() {
                    "ledger" => ItemKind::Ledger,
                    "record" => ItemKind::Record,
                    _ => return Err(fail("kind must be `ledger` or `record`")),
                });
            }
            "path" => {
                if path.is_some() {
                    return Err(fail("duplicate path header"));
                }
                path = Some(v.trim().to_string());
            }
            "force" => {
                if force_seen {
                    return Err(fail("duplicate force header"));
                }
                force_seen = true;
                force = match v.trim() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(fail("force must be `true` or `false`")),
                };
            }
            _ => return Err(fail("unknown header (only `kind`, `path`, and `force`)")),
        }
    }
    let kind = kind.ok_or_else(|| fail("missing `kind` header"))?;
    let body_at = body_at.ok_or_else(|| fail("missing `---` separator"))?;
    let content = all[body_at..].join("\n");
    // `lines()` dropped the body's final newline, so a body that ends with
    // one (every record a normal write produces does) would come back a
    // byte short. The content is the record plaintext as queued: keeping
    // the tail means the drain writes canonical bytes and the resolve path
    // (`--take theirs`, which reformats) still matches the drain's
    // encrypt-and-compare idempotency check.
    let content = if text.ends_with('\n') {
        format!("{content}\n")
    } else {
        content
    };
    if content.trim().is_empty() {
        return Err(fail("empty content"));
    }
    let path = match kind {
        ItemKind::Ledger => {
            if path.is_some() {
                return Err(fail("`path` is only for `kind: record`"));
            }
            None
        }
        ItemKind::Record => {
            let p = path.ok_or_else(|| fail("`kind: record` needs a `path` header"))?;
            Some(validate_record_path(&p).map_err(|why| fail(&why))?)
        }
    };
    if force && kind != ItemKind::Ledger {
        return Err(fail("`force` is only for `kind: ledger`"));
    }
    Ok(ParsedItem {
        name: name.to_string(),
        kind,
        path,
        content,
        force,
    })
}

/// Vault-relative record paths stay inside the collection roots and cannot
/// escape the vault.
fn validate_record_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() {
        return Err("empty path".to_string());
    }
    let p = Path::new(raw);
    if p.is_absolute() {
        return Err("path must be vault-relative".to_string());
    }
    let mut comps = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => comps.push(s.to_string_lossy().into_owned()),
            _ => return Err("path must not contain `.`, `..`, or prefixes".to_string()),
        }
    }
    if comps.is_empty() {
        return Err("empty path".to_string());
    }
    if !RECORD_ROOTS.contains(&comps[0].as_str()) {
        return Err(format!(
            "record path must live under one of {}",
            RECORD_ROOTS.join(", ")
        ));
    }
    if !comps.last().is_some_and(|f| f.ends_with(".md")) {
        return Err("record path must end in `.md`".to_string());
    }
    Ok(comps.iter().collect())
}
