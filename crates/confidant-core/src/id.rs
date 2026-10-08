//! Collision-free prefixed ULIDs (ADR-3).

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Crockford base32 alphabet used by ULIDs (no I, L, O, U).
pub const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const fn crockford_lookup() -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0;
    while i < CROCKFORD.len() {
        let c = CROCKFORD[i];
        table[c as usize] = true;
        if c.is_ascii_uppercase() {
            table[(c | 32) as usize] = true;
        }
        i += 1;
    }
    table
}

const CROCKFORD_BYTE: [bool; 256] = crockford_lookup();

const ULID_LEN: usize = 26;

/// Type prefix on a record ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prefix {
    Person,
    Org,
    Deal,
    Interaction,
    Note,
    Package,
}

impl Prefix {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "p",
            Self::Org => "o",
            Self::Deal => "d",
            Self::Interaction => "i",
            Self::Note => "n",
            Self::Package => "pkg",
        }
    }

    pub fn record_type(self) -> Option<&'static str> {
        match self {
            Self::Person => Some("person"),
            Self::Org => Some("org"),
            Self::Deal => Some("deal"),
            Self::Interaction => Some("interaction"),
            Self::Note => Some("note"),
            Self::Package => None,
        }
    }

    pub fn collection(self) -> Option<&'static str> {
        match self {
            Self::Person => Some("people"),
            Self::Org => Some("orgs"),
            Self::Deal => Some("deals"),
            Self::Interaction => Some("interactions"),
            Self::Note => Some("notes"),
            Self::Package => None,
        }
    }

    pub fn main_filename(self) -> Option<&'static str> {
        match self {
            Self::Person => Some("profile.md"),
            Self::Org => Some("org.md"),
            Self::Deal => Some("deal.md"),
            Self::Interaction => Some("interaction.md"),
            Self::Note => Some("note.md"),
            Self::Package => None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "p" => Some(Self::Person),
            "o" => Some(Self::Org),
            "d" => Some(Self::Deal),
            "i" => Some(Self::Interaction),
            "n" => Some(Self::Note),
            "pkg" => Some(Self::Package),
            _ => None,
        }
    }

    pub fn from_collection(name: &str) -> Option<Self> {
        match name {
            "people" => Some(Self::Person),
            "orgs" => Some(Self::Org),
            "deals" => Some(Self::Deal),
            "interactions" => Some(Self::Interaction),
            "notes" => Some(Self::Note),
            _ => None,
        }
    }

    pub fn from_type(name: &str) -> Option<Self> {
        match name {
            "person" => Some(Self::Person),
            "org" => Some(Self::Org),
            "deal" => Some(Self::Deal),
            "interaction" => Some(Self::Interaction),
            "note" => Some(Self::Note),
            _ => None,
        }
    }
}

/// `prefix '-' ULID`, canonicalized to uppercase ULID characters.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RecordId {
    prefix: Prefix,
    ulid: String,
}

impl RecordId {
    pub fn new(prefix: Prefix, ulid: String) -> Result<Self, IdError> {
        let ulid = canonicalize_ulid(&ulid).ok_or(IdError::BadUlid)?;
        Ok(Self { prefix, ulid })
    }

    pub fn parse(s: &str) -> Result<Self, IdError> {
        let (prefix_str, ulid) = s.split_once('-').ok_or(IdError::MissingHyphen)?;
        let prefix = Prefix::parse(prefix_str).ok_or(IdError::UnknownPrefix)?;
        Self::new(prefix, ulid.to_owned())
    }

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn ulid(&self) -> &str {
        &self.ulid
    }

    pub fn as_str(&self) -> String {
        format!("{}-{}", self.prefix.as_str(), self.ulid)
    }
}

impl Display for RecordId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.prefix.as_str(), self.ulid)
    }
}

impl FromStr for RecordId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for RecordId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for RecordId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        RecordId::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    MissingHyphen,
    UnknownPrefix,
    BadUlid,
}

impl Display for IdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHyphen => f.write_str("ID is missing a hyphen"),
            Self::UnknownPrefix => f.write_str("ID has an unknown type prefix"),
            Self::BadUlid => f.write_str("ID does not contain a 26-character Crockford ULID"),
        }
    }
}

impl std::error::Error for IdError {}

pub fn canonicalize_ulid(s: &str) -> Option<String> {
    if s.chars().count() != ULID_LEN {
        return None;
    }
    let mut out = String::with_capacity(ULID_LEN);
    for (i, ch) in s.chars().enumerate() {
        // Reject non-ASCII before the alphabet lookup. `to_ascii_uppercase`
        // leaves non-ASCII unchanged, and `up as u8` would truncate it.
        if !ch.is_ascii() {
            return None;
        }
        let up = ch.to_ascii_uppercase();
        // A ULID timestamp is 48 bits in 10 Crockford characters; the first
        // character only has 3 bits of payload, so it must be 0–7.
        if i == 0 && up > '7' {
            return None;
        }
        // Crockford maps I/L → 1, O → 0 when decoding; we reject them so
        // check can flag non-conforming IDs instead of silently repairing.
        if !CROCKFORD.contains(&(up as u8)) {
            return None;
        }
        out.push(up);
    }
    Some(out)
}

pub fn is_ulid(s: &str) -> bool {
    canonicalize_ulid(s).is_some()
}

/// A token that looks like a record ID: type prefix, dash, alphanumeric run,
/// or a bare 26-character Crockford ULID that matches a vault ULID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdToken {
    Valid(RecordId),
    /// Prefix + dash + alphanumeric run that fails ULID validation.
    /// `candidate` is a recoverable ID when the lookalike embeds one:
    /// a Unicode-dash run that canonicalizes, a dash run (`--`, soft
    /// hyphen then `-`) followed by a ULID, or the first 26 characters
    /// of a longer run.
    Malformed {
        candidate: Option<RecordId>,
    },
    /// Exact 26-character Crockford ULID that matches a ULID the vault
    /// names (loaded records, packages, dangling prefixed IDs, path
    /// entries), found as any 26-character window inside a Crockford
    /// run. No near-ULID / malformed rule; only exact vault matches count.
    BareUlid(String),
}

impl IdToken {
    pub(crate) fn record_ids(&self) -> impl Iterator<Item = &RecordId> {
        match self {
            Self::Valid(id) => Some(id),
            Self::Malformed { candidate } => candidate.as_ref(),
            Self::BareUlid(_) => None,
        }
        .into_iter()
    }

    pub(crate) fn bare_ulid(&self) -> Option<&str> {
        match self {
            Self::BareUlid(ulid) => Some(ulid.as_str()),
            Self::Valid(_) | Self::Malformed { .. } => None,
        }
    }

    pub(crate) fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed { .. })
    }
}

/// Scan `text` for ID-shaped tokens (`p`/`o`/`d`/`i`/`n`/`pkg` plus an ASCII or
/// Unicode dash plus an alphanumeric run), case-insensitively. Finds IDs
/// inside junk such as `[[p-…]]`. Format characters (ZWSP, soft hyphen, word
/// joiner, …) are stripped first. A prefix is glued after an ASCII
/// alphanumeric or `_`, when the `-` before it follows an alphanumeric, `_`,
/// or `-` in the same run, or when it sits inside a `scheme://` token. Glue is
/// computed only at a prefix; scheme state is tracked incrementally per
/// whitespace-delimited token. In a glued context a Valid token is a single
/// ASCII `-` plus an exact ULID; a longer run whose first 26 characters are a
/// ULID, a Unicode dash plus a ULID, or a run of dashes (`--`, soft hyphen
/// then `-`) plus a ULID, is Malformed with that candidate. When `vault_ulids`
/// is set, every 26-character Crockford window that exactly matches a ULID
/// the vault names is also a BareUlid token (no word-boundary rule).
pub fn scan_id_tokens(text: &str) -> Vec<IdToken> {
    scan_id_tokens_against(text, None)
}

pub(crate) fn scan_id_tokens_against(
    text: &str,
    vault_ulids: Option<&HashSet<String>>,
) -> Vec<IdToken> {
    let mapped = map_soft_hyphen_after_prefix(text);
    let stripped = strip_cf(&mapped);
    let text = stripped.as_ref();
    let mut out = if has_id_dash(text) {
        scan_prefixed(text)
    } else {
        Vec::new()
    };
    if let Some(ulids) = vault_ulids {
        scan_vault_ulid_windows(text, ulids, &mut out);
    }
    out
}

fn has_id_dash(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.contains(&b'-') {
        return true;
    }
    bytes.iter().any(|b| *b >= 0x80) && text.chars().any(is_id_dash)
}

fn scan_prefixed(text: &str) -> Vec<IdToken> {
    let mut out = Vec::new();
    let mut remaining = text;
    let mut prev: Option<char> = None;
    let mut prev2: Option<char> = None;
    let mut run_has_scheme = false;
    let mut scheme_progress = 0u8;
    while !remaining.is_empty() {
        if starts_id_prefix(remaining) {
            let glued = prefix_is_glued(prev, prev2, run_has_scheme);
            if let Some((tok, len)) = match_id_token_at(remaining, glued) {
                out.push(tok);
                remaining = &remaining[len..];
                prev2 = prev;
                prev = Some('0');
                continue;
            }
        }
        let ch = remaining.chars().next().unwrap();
        let n = ch.len_utf8();
        if ch.is_whitespace() {
            run_has_scheme = false;
            scheme_progress = 0;
        } else if !run_has_scheme {
            scheme_progress = match (scheme_progress, ch) {
                (0, ':') => 1,
                (1, '/') => 2,
                (2, '/') => {
                    run_has_scheme = true;
                    0
                }
                (_, ':') => 1,
                _ => 0,
            };
        }
        prev2 = prev;
        prev = Some(ch);
        remaining = &remaining[n..];
    }
    out
}

fn prefix_is_glued(prev: Option<char>, prev2: Option<char>, run_has_scheme: bool) -> bool {
    if prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        return true;
    }
    if prev == Some('-') && prev2.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return true;
    }
    run_has_scheme
}

/// U+00AD after an ID prefix is a dash, not a format character to strip.
fn map_soft_hyphen_after_prefix(s: &str) -> Cow<'_, str> {
    if !s.contains('\u{00ad}') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(plen) = prefix_len_before_soft_hyphen(rest) {
            out.push_str(&rest[..plen]);
            out.push('-');
            rest = &rest[plen + '\u{00ad}'.len_utf8()..];
            continue;
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    Cow::Owned(out)
}

fn prefix_len_before_soft_hyphen(s: &str) -> Option<usize> {
    const PREFIXES: &[&str] = &["pkg", "p", "o", "d", "i", "n"];
    for pref in PREFIXES {
        let plen = pref.len();
        let Some(head) = s.get(..plen) else {
            continue;
        };
        if head.eq_ignore_ascii_case(pref) && s[plen..].starts_with('\u{00ad}') {
            return Some(plen);
        }
    }
    None
}

/// Unicode General Category Cf (Format): ZWSP, soft hyphen, word joiner, BOM,
/// bidi marks, tags.
pub(crate) fn is_cf(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

pub(crate) fn strip_cf(s: &str) -> Cow<'_, str> {
    if s.is_ascii() || !s.chars().any(is_cf) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.chars().filter(|c| !is_cf(*c)).collect())
}

fn starts_id_prefix(s: &str) -> bool {
    matches!(
        s.as_bytes().first(),
        Some(b'p' | b'P' | b'o' | b'O' | b'd' | b'D' | b'i' | b'I' | b'n' | b'N')
    )
}

fn is_crockford_byte(b: u8) -> bool {
    CROCKFORD_BYTE[b as usize]
}

fn scan_vault_ulid_windows(text: &str, vault_ulids: &HashSet<String>, out: &mut Vec<IdToken>) {
    if vault_ulids.is_empty() {
        return;
    }
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_crockford_byte(bytes[i]) {
            i += text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            continue;
        }
        let start = i;
        i += 1;
        while i < bytes.len() && is_crockford_byte(bytes[i]) {
            i += 1;
        }
        let run = &bytes[start..i];
        if run.len() < ULID_LEN {
            continue;
        }
        for off in 0..=run.len() - ULID_LEN {
            let window = &run[off..off + ULID_LEN];
            let first = window[0].to_ascii_uppercase();
            if first > b'7' {
                continue;
            }
            let mut buf = [0u8; ULID_LEN];
            for (j, &b) in window.iter().enumerate() {
                buf[j] = b.to_ascii_uppercase();
            }
            let ulid = std::str::from_utf8(&buf).expect("crockford alphabet is ascii");
            if vault_ulids.contains(ulid) {
                out.push(IdToken::BareUlid(ulid.to_owned()));
            }
        }
    }
}

/// Valid IDs only; malformed lookalikes and bare ULIDs are skipped.
pub fn scan_ids(text: &str) -> Vec<RecordId> {
    scan_id_tokens(text)
        .into_iter()
        .filter_map(|tok| match tok {
            IdToken::Valid(id) => Some(id),
            IdToken::Malformed { .. } | IdToken::BareUlid(_) => None,
        })
        .collect()
}

fn match_id_token_at(s: &str, glued: bool) -> Option<(IdToken, usize)> {
    const PREFIXES: &[&str] = &["pkg", "p", "o", "d", "i", "n"];
    for pref in PREFIXES {
        let plen = pref.len();
        let Some(head) = s.get(..plen) else {
            continue;
        };
        if !head.eq_ignore_ascii_case(pref) {
            continue;
        }
        let Some(after) = s.get(plen..) else {
            continue;
        };
        let (dash_bytes, dash_count, single_ascii_dash) = dash_run(after);
        if dash_count == 0 {
            continue;
        }
        let run_start = dash_bytes;
        let run_len = after[run_start..]
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(after.len() - run_start);
        let total = plen + run_start + run_len;
        let run = &after[run_start..run_start + run_len];
        if glued {
            if is_32_lowercase_hex(run) {
                continue;
            }
            if single_ascii_dash && run_len == ULID_LEN {
                if let Ok(id) = RecordId::parse(&format!("{pref}-{run}")) {
                    return Some((IdToken::Valid(id), total));
                }
            }
            if let Some(candidate) = lookalike_candidate(pref, run) {
                if run_len > ULID_LEN || !single_ascii_dash {
                    return Some((
                        IdToken::Malformed {
                            candidate: Some(candidate),
                        },
                        total,
                    ));
                }
            }
            continue;
        }
        if is_32_lowercase_hex(run) {
            continue;
        }
        if run_len > 32 {
            if let Some(candidate) = lookalike_candidate(pref, run) {
                return Some((
                    IdToken::Malformed {
                        candidate: Some(candidate),
                    },
                    total,
                ));
            }
            continue;
        }
        if run_len < 20 {
            continue;
        }
        if single_ascii_dash {
            if let Ok(id) = RecordId::parse(&format!("{pref}-{run}")) {
                return Some((IdToken::Valid(id), total));
            }
        }
        let candidate = lookalike_candidate(pref, run);
        return Some((IdToken::Malformed { candidate }, total));
    }
    None
}

/// Consecutive `is_id_dash` characters after a prefix count as one dash.
/// Only a single ASCII `-` can produce a Valid token.
fn dash_run(s: &str) -> (usize, usize, bool) {
    let mut bytes = 0;
    let mut count = 0;
    let mut all_ascii_hyphen = true;
    for c in s.chars() {
        if !is_id_dash(c) {
            break;
        }
        bytes += c.len_utf8();
        count += 1;
        if c != '-' {
            all_ascii_hyphen = false;
        }
    }
    (bytes, count, count == 1 && all_ascii_hyphen)
}

fn is_32_lowercase_hex(run: &str) -> bool {
    run.len() == 32 && run.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn lookalike_candidate(pref: &str, run: &str) -> Option<RecordId> {
    let prefix = Prefix::parse(pref)?;
    if let Ok(id) = RecordId::new(prefix, run.to_owned()) {
        return Some(id);
    }
    if run.len() > ULID_LEN {
        RecordId::new(prefix, run[..ULID_LEN].to_owned()).ok()
    } else {
        None
    }
}

/// Unicode Dash_Punctuation (Pd), plus U+00AD, U+2212, U+2043, U+30FC.
pub(crate) fn is_id_dash(c: char) -> bool {
    matches!(
        c,
        '-' | '\u{00ad}' | '\u{058a}' | '\u{05be}' | '\u{1400}' | '\u{1806}' | '\u{2010}'
            ..='\u{2015}'
                | '\u{2043}'
                | '\u{2212}'
                | '\u{2e17}'
                | '\u{2e1a}'
                | '\u{2e3a}'
                | '\u{2e3b}'
                | '\u{2e40}'
                | '\u{2e5d}'
                | '\u{301c}'
                | '\u{3030}'
                | '\u{30a0}'
                | '\u{30fc}'
                | '\u{fe31}'
                | '\u{fe32}'
                | '\u{fe58}'
                | '\u{fe63}'
                | '\u{ff0d}'
                | '\u{10ead}'
    )
}

/// Parse a directory or file name as a record ID. Any single extension is
/// stripped case-insensitively (`p-<ULID>.MD`, `n-<ULID>.txt`).
pub(crate) fn record_id_from_entry_name(name: &str) -> Option<RecordId> {
    if let Ok(id) = RecordId::parse(name) {
        return Some(id);
    }
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    RecordId::parse(stem).ok()
}

/// Person ID for a vault-relative path under `people/<id>/` or `people/<id>.md`.
pub fn person_id_from_path(path: &str) -> Option<RecordId> {
    let mut parts = path.split('/');
    if parts.next()? != "people" {
        return None;
    }
    let second = parts.next()?;
    let stem = second.strip_suffix(".md").unwrap_or(second);
    let id = RecordId::parse(stem).ok()?;
    if id.prefix() != Prefix::Person {
        return None;
    }
    Some(id)
}

/// Encode `value` as `len` Crockford characters (big-endian).
pub fn encode_crockford(mut value: u128, len: usize) -> String {
    let mut chars = vec![b'0'; len];
    for slot in chars.iter_mut().rev() {
        *slot = CROCKFORD[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(chars).expect("crockford alphabet is ascii")
}

/// Build a deterministic ULID from a millisecond timestamp and 80-bit random.
pub fn ulid_from_parts(time_ms: u64, random: u128) -> String {
    let time = u128::from(time_ms) & ((1u128 << 48) - 1);
    let rand = random & ((1u128 << 80) - 1);
    let mut encoded = encode_crockford(time, 10);
    encoded.push_str(&encode_crockford(rand, 16));
    encoded
}

#[cfg(test)]
mod tests {
    use super::{Prefix, RecordId};

    #[test]
    fn parses_and_canonicalizes() {
        let id = RecordId::parse("p-01m3tc5h00mpjg000000000000").unwrap();
        assert_eq!(id.prefix(), Prefix::Person);
        assert_eq!(id.to_string(), "p-01M3TC5H00MPJG000000000000");
    }

    #[test]
    fn rejects_ilo_letters() {
        assert!(RecordId::parse("p-01M3TC5H00MPJG00000000000I").is_err());
        assert!(RecordId::parse("p-01M3TC5H00MPJG00000000000L").is_err());
        assert!(RecordId::parse("p-01M3TC5H00MPJG00000000000O").is_err());
        assert!(RecordId::parse("p-01M3TC5H00MPJG00000000000U").is_err());
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert!(RecordId::parse("p-01J9Z3K4QF").is_err());
        assert!(RecordId::parse("x-01M3TC5H00MPJG000000000000").is_err());
        assert!(RecordId::parse("01M3TC5H00MPJG000000000000").is_err());
    }

    #[test]
    fn package_prefix() {
        let id = RecordId::parse("pkg-01M3TC5H00MPJG004SK4000009").unwrap();
        assert_eq!(id.prefix(), Prefix::Package);
        assert!(id.prefix().collection().is_none());
    }

    #[test]
    fn rejects_non_ascii_before_alphabet_lookup() {
        let mut raw: Vec<char> = "01M3TC5H00MPJG000000000000".chars().collect();
        raw[4] = 'é';
        let s: String = raw.into_iter().collect();
        assert!(RecordId::parse(&format!("p-{s}")).is_err());
    }

    #[test]
    fn rejects_first_char_above_seven() {
        assert!(RecordId::parse("p-81M3TC5H00MPJG000000000000").is_err());
        assert!(RecordId::parse("p-01M3TC5H00MPJG000000000000").is_ok());
        assert!(RecordId::parse("p-71M3TC5H00MPJG000000000000").is_ok());
    }

    #[test]
    fn scan_ids_finds_obsidian_and_junk() {
        let id = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        let found = super::scan_ids("see [[p-01M3TC5H00MPJG000000000000]] please");
        assert_eq!(found, vec![id.clone()]);
        let mixed = super::scan_ids("P-01m3tc5h00mpjg000000000000");
        assert_eq!(mixed, vec![id]);
    }

    #[test]
    fn scan_id_tokens_flags_malformed_ulid_and_unicode_dash() {
        use super::{scan_id_tokens, IdToken};
        let id = super::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        let none = IdToken::Malformed { candidate: None };
        let bad_letter = scan_id_tokens("see p-01M3TC5H00MPJG00000000000I");
        assert_eq!(bad_letter, vec![none.clone()]);
        let short = scan_id_tokens("p-01M3TC5H00MPJG00000000000");
        assert_eq!(short, vec![none.clone()]);
        let en_dash = scan_id_tokens("p\u{2013}01M3TC5H00MPJG000000000000");
        assert_eq!(
            en_dash,
            vec![IdToken::Malformed {
                candidate: Some(id.clone())
            }]
        );
        assert!(scan_id_tokens("merged-deal-token").is_empty());
        assert!(scan_id_tokens("zxqv-unique-token-ada-0").is_empty());
        for prose in [
            "I-95",
            "D-Day",
            "P-value",
            "O-1",
            "I-9",
            "I-140",
            "N-400",
            "Lin I-Chen",
            "I\u{2014}I",
        ] {
            assert!(
                scan_id_tokens(prose).is_empty(),
                "{prose:?} should not be an ID token"
            );
        }
        let short_real = scan_id_tokens("p-01M3TC5H00MPJG00000000000");
        assert_eq!(short_real, vec![none.clone()]);
        assert_eq!(
            scan_id_tokens("xp-01M3TC5H00MPJG000000000000"),
            vec![IdToken::Valid(id.clone())]
        );
        assert_eq!(
            scan_id_tokens("p-01M3TC5H00MPJG000000000000abcdefg"),
            vec![IdToken::Malformed {
                candidate: Some(id)
            }]
        );
        assert!(scan_id_tokens(
            "https://www.notion.so/Coaching-Plan-0123456789abcdef0123456789abcdef"
        )
        .is_empty());
        assert!(scan_id_tokens("Kickoff-session-abcdefghijklmnopqrstuvwx").is_empty());
        let note = super::RecordId::parse("n-01M3TC5H00MPJG002NAM000005").unwrap();
        assert_eq!(
            scan_id_tokens("note:n\u{2010}01M3TC5H00MPJG002NAM000005"),
            vec![IdToken::Malformed {
                candidate: Some(note.clone())
            }]
        );
        assert_eq!(
            scan_id_tokens("note:n-01M3TC5H00MPJG002NAM000005v2"),
            vec![IdToken::Malformed {
                candidate: Some(note)
            }]
        );
        let zwsp = scan_id_tokens("p-\u{200b}01M3TC5H00MPJG000000000000");
        assert_eq!(
            zwsp,
            vec![IdToken::Valid(
                super::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap()
            )]
        );
        let note_soft = super::RecordId::parse("n-01M3TC5H00MPJG002NAM000005").unwrap();
        assert_eq!(
            scan_id_tokens("note:n\u{00ad}01M3TC5H00MPJG002NAM000005"),
            vec![IdToken::Valid(note_soft)]
        );
        let hex32 = "0123456789abcdef0123456789abcdef";
        assert!(scan_id_tokens(&format!("Phase-I-{hex32}")).is_empty());
        assert!(scan_id_tokens(&format!("My-Page-p-{hex32}")).is_empty());
        assert!(scan_id_tokens("_p-1BxiMVs0XRA5nFMdKvBdBZjgmUU").is_empty());
        assert!(scan_id_tokens("-n-1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms").is_empty());
        assert!(scan_id_tokens(
            "docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit"
        )
        .is_empty());
        assert!(
            scan_id_tokens("drive.google.com/file/d/1b3Yf11-n-m7vpfukD0SPao3NxJ7dDYgq/view")
                .is_empty()
        );
        assert!(scan_id_tokens(
            "https://docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit"
        )
        .is_empty());
        assert!(scan_id_tokens("https://example.com/n-GYboXeYBl8cpDlwjVptoB").is_empty());
        let hidden = super::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        assert_eq!(
            scan_id_tokens("https://drive.google.com/file/d/p-01M3TC5H00MPJG000000000000/view"),
            vec![IdToken::Valid(hidden)]
        );
        let cam = super::RecordId::parse("p-01M3TC5H00MPJG001248000002").unwrap();
        let malformed_cam = IdToken::Malformed {
            candidate: Some(cam.clone()),
        };
        assert_eq!(
            scan_id_tokens("https://example.com/x/p-01M3TC5H00MPJG001248000002abc"),
            vec![malformed_cam.clone()]
        );
        assert_eq!(
            scan_id_tokens("https://example.com/p-01M3TC5H00MPJG001248000002abcdefghijk"),
            vec![malformed_cam.clone()]
        );
        assert_eq!(
            scan_id_tokens("Ana-p-01M3TC5H00MPJG001248000002s"),
            vec![malformed_cam.clone()]
        );
        assert_eq!(
            scan_id_tokens("Ana-p-01M3TC5H00MPJG001248000002abcdefghij"),
            vec![malformed_cam.clone()]
        );
        assert_eq!(
            scan_id_tokens("Ana-p\u{2013}01M3TC5H00MPJG001248000002"),
            vec![malformed_cam]
        );
    }

    #[test]
    fn scan_id_tokens_pd_dashes_and_dash_runs_are_malformed() {
        use super::{scan_id_tokens, IdToken};
        let cam = super::RecordId::parse("p-01M3TC5H00MPJG001248000002").unwrap();
        let ulid = cam.ulid();
        let malformed = IdToken::Malformed {
            candidate: Some(cam.clone()),
        };
        for dash in [
            '\u{058a}', '\u{05be}', '\u{1806}', '\u{2e17}', '\u{2e3a}', '\u{301c}', '\u{fe31}',
            '\u{2043}', '\u{30fc}',
        ] {
            let text = format!("p{dash}{ulid}");
            assert_eq!(
                scan_id_tokens(&text),
                vec![malformed.clone()],
                "dash U+{:04X}",
                dash as u32
            );
        }
        assert_eq!(
            scan_id_tokens(&format!("p--{ulid}")),
            vec![malformed.clone()]
        );
        assert_eq!(
            scan_id_tokens(&format!("p\u{00ad}-{ulid}")),
            vec![malformed.clone()]
        );
        assert_eq!(
            scan_id_tokens(&format!("p--{ulid}abc")),
            vec![malformed.clone()]
        );
        assert!(scan_id_tokens("I-95").is_empty());
        assert!(scan_id_tokens("I--95").is_empty());
        assert!(scan_id_tokens(
            "docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit"
        )
        .is_empty());
        assert!(
            scan_id_tokens("drive.google.com/file/d/1b3Yf11-n-m7vpfukD0SPao3NxJ7dDYgq/view")
                .is_empty()
        );
        assert!(scan_id_tokens(
            "https://www.notion.so/Coaching-Plan-0123456789abcdef0123456789abcdef"
        )
        .is_empty());
        assert!(scan_id_tokens(&format!("see {ulid}")).is_empty());
        let hex32 = "0123456789abcdef0123456789abcdef";
        assert!(scan_id_tokens(hex32).is_empty());
        assert!(scan_id_tokens(&format!("Phase-I-{hex32}")).is_empty());
    }

    fn scan_with_ulids(text: &str, ulids: &[&str]) -> Vec<super::IdToken> {
        let set: std::collections::HashSet<String> =
            ulids.iter().map(|u| (*u).to_owned()).collect();
        super::scan_id_tokens_against(text, Some(&set))
    }

    #[test]
    fn scan_id_tokens_bare_ulid_windows_match_vault_ulids() {
        use super::IdToken;
        let cam = super::RecordId::parse("p-01M3TC5H00MPJG001248000002").unwrap();
        let ulid = cam.ulid();
        let bare = vec![IdToken::BareUlid(ulid.to_owned())];
        assert_eq!(
            scan_with_ulids(&format!("src:zoom/rec_{ulid}.vtt"), &[ulid]),
            bare
        );
        assert_eq!(scan_with_ulids(&format!("p_{ulid}"), &[ulid]), bare);
        assert_eq!(scan_with_ulids(&format!("p{ulid}"), &[ulid]), bare);
        assert_eq!(scan_with_ulids(&format!("{ulid}abc"), &[ulid]), bare);
        assert_eq!(
            scan_with_ulids(&format!("see {ulid}"), &[ulid]),
            bare.clone()
        );
        assert_eq!(
            scan_with_ulids(&format!("src:\"zoom/{ulid}.vtt\""), &[ulid]),
            bare.clone()
        );
        assert_eq!(scan_with_ulids(&format!("t-{ulid}"), &[ulid]), bare.clone());
        assert_eq!(scan_with_ulids("01m3tc5h00mpjg001248000002", &[ulid]), bare);
        assert!(scan_with_ulids("the quick brown fox jumps", &[ulid]).is_empty());
        assert!(
            scan_with_ulids("0123456789abcdef0123456789abcdef0123456789abcdef", &[ulid]).is_empty()
        );
        assert!(scan_with_ulids(
            "docs.google.com/document/d/1g1G7TFxyqPTV83aBwi_-n-GYboXeYBl8cpDlwjVptoB/edit",
            &[ulid]
        )
        .is_empty());
        assert!(scan_with_ulids(
            "https://www.notion.so/Coaching-Plan-0123456789abcdef0123456789abcdef",
            &[ulid]
        )
        .is_empty());
    }

    #[test]
    fn scan_id_tokens_is_linear_on_long_cjk_and_url_lines() {
        use std::collections::HashSet;
        use std::time::{Duration, Instant};
        let cjk = format!("{}-{}", "漢".repeat(40_000), "字".repeat(40_000));
        let url = format!("https://example.com/{}", "-".repeat(320_000));
        let ulid = "01M3TC5H00MPJG001248000002";
        let mut crockford = "A".repeat(1_000_000);
        crockford.push_str(ulid);
        crockford.push_str(&"A".repeat(1_000_000));
        let mut vault = HashSet::new();
        vault.insert(ulid.to_owned());
        let budget = Duration::from_millis(if cfg!(debug_assertions) { 1000 } else { 250 });
        let t0 = Instant::now();
        let cjk_toks = super::scan_id_tokens(&cjk);
        let cjk_elapsed = t0.elapsed();
        let t1 = Instant::now();
        let url_toks = super::scan_id_tokens(&url);
        let url_elapsed = t1.elapsed();
        let t2 = Instant::now();
        let crock_toks = super::scan_id_tokens_against(&crockford, Some(&vault));
        let crock_elapsed = t2.elapsed();
        assert!(cjk_toks.is_empty(), "{cjk_toks:?}");
        assert!(url_toks.is_empty(), "{url_toks:?}");
        assert!(
            crock_toks
                .iter()
                .any(|t| matches!(t, super::IdToken::BareUlid(u) if u == ulid)),
            "{crock_toks:?}"
        );
        assert!(
            cjk_elapsed <= budget,
            "CJK 80k-char line took {cjk_elapsed:?} (budget {budget:?})"
        );
        assert!(
            url_elapsed <= budget,
            "320k-char URL line took {url_elapsed:?} (budget {budget:?})"
        );
        assert!(
            crock_elapsed <= budget,
            "2 MB Crockford line took {crock_elapsed:?} (budget {budget:?})"
        );
    }

    #[test]
    fn person_id_from_people_path() {
        let id = RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        assert_eq!(
            super::person_id_from_path("people/p-01M3TC5H00MPJG000000000000/profile.md"),
            Some(id.clone())
        );
        assert_eq!(
            super::person_id_from_path("people/p-01M3TC5H00MPJG000000000000.md"),
            Some(id)
        );
        assert!(super::person_id_from_path("notes/n-01M3TC5H00MPJG002NAM000005/note.md").is_none());
    }

    #[test]
    fn record_id_from_entry_name_strips_any_extension() {
        let cam = RecordId::parse("p-01M3TC5H00MPJG001248000002").unwrap();
        let note = RecordId::parse("n-01M3TC5H000068T0000000000C").unwrap();
        assert_eq!(
            super::record_id_from_entry_name(&cam.to_string()),
            Some(cam.clone())
        );
        assert_eq!(
            super::record_id_from_entry_name(&format!("{cam}.MD")),
            Some(cam.clone())
        );
        assert_eq!(
            super::record_id_from_entry_name(&format!("{cam}.md")),
            Some(cam)
        );
        assert_eq!(
            super::record_id_from_entry_name(&format!("{note}.txt")),
            Some(note)
        );
        assert!(super::record_id_from_entry_name("profile.md").is_none());
        assert!(super::record_id_from_entry_name(".MD").is_none());
        assert!(super::record_id_from_entry_name("not-an-id.md").is_none());
    }
}
