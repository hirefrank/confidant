//! Collision-free prefixed ULIDs (ADR-3).

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Crockford base32 alphabet used by ULIDs (no I, L, O, U).
pub const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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

/// A token that looks like a record ID: type prefix, dash, alphanumeric run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdToken {
    Valid(RecordId),
    /// Prefix + dash + alphanumeric run that fails ULID validation.
    Malformed,
}

/// Scan `text` for ID-shaped tokens (`p`/`o`/`d`/`i`/`n`/`pkg` plus an ASCII or
/// Unicode dash plus an alphanumeric run), case-insensitively. Finds IDs
/// inside junk such as `[[p-…]]` and with an alphanumeric glued in front
/// (`xp-<ULID>`). A run that is not a Crockford ULID is
/// [`IdToken::Malformed`].
pub fn scan_id_tokens(text: &str) -> Vec<IdToken> {
    if !text.as_bytes().contains(&b'-')
        && (!text.as_bytes().iter().any(|b| *b >= 0x80) || !text.chars().any(is_id_dash))
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut remaining = text;
    while !remaining.is_empty() {
        if starts_id_prefix(remaining) {
            if let Some((tok, len)) = match_id_token_at(remaining) {
                out.push(tok);
                remaining = &remaining[len..];
                continue;
            }
        }
        let ch = remaining.chars().next().unwrap();
        remaining = &remaining[ch.len_utf8()..];
    }
    out
}

fn starts_id_prefix(s: &str) -> bool {
    matches!(
        s.as_bytes().first(),
        Some(b'p' | b'P' | b'o' | b'O' | b'd' | b'D' | b'i' | b'I' | b'n' | b'N')
    )
}

/// Valid IDs only; malformed lookalikes are skipped.
pub fn scan_ids(text: &str) -> Vec<RecordId> {
    scan_id_tokens(text)
        .into_iter()
        .filter_map(|tok| match tok {
            IdToken::Valid(id) => Some(id),
            IdToken::Malformed => None,
        })
        .collect()
}

fn match_id_token_at(s: &str) -> Option<(IdToken, usize)> {
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
        let Some(dash) = after.chars().next() else {
            continue;
        };
        if !is_id_dash(dash) {
            continue;
        }
        let run_start = dash.len_utf8();
        let run_len = after[run_start..]
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(after.len() - run_start);
        let total = plen + run_start + run_len;
        let run = &after[run_start..run_start + run_len];
        if run_len > 32 {
            if dash == '-' && canonicalize_ulid(&run[..26]).is_some() {
                return Some((IdToken::Malformed, total));
            }
            continue;
        }
        if run_len < 20 {
            continue;
        }
        if dash == '-' {
            if let Ok(id) = RecordId::parse(&format!("{pref}-{run}")) {
                return Some((IdToken::Valid(id), total));
            }
        }
        return Some((IdToken::Malformed, total));
    }
    None
}

pub(crate) fn is_id_dash(c: char) -> bool {
    matches!(
        c,
        '-' | '\u{00ad}'
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
        let bad_letter = scan_id_tokens("see p-01M3TC5H00MPJG00000000000I");
        assert_eq!(bad_letter, vec![IdToken::Malformed]);
        let short = scan_id_tokens("p-01M3TC5H00MPJG00000000000");
        assert_eq!(short, vec![IdToken::Malformed]);
        let en_dash = scan_id_tokens("p\u{2013}01M3TC5H00MPJG000000000000");
        assert_eq!(en_dash, vec![IdToken::Malformed]);
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
        assert_eq!(short_real, vec![IdToken::Malformed]);
        let id = super::RecordId::parse("p-01M3TC5H00MPJG000000000000").unwrap();
        assert_eq!(
            scan_id_tokens("xp-01M3TC5H00MPJG000000000000"),
            vec![IdToken::Valid(id)]
        );
        assert_eq!(
            scan_id_tokens("p-01M3TC5H00MPJG000000000000abcdefg"),
            vec![IdToken::Malformed]
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
}
