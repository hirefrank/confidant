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

/// Scan `text` for ID-shaped tokens (`p-`/`o-`/`d-`/`i-`/`n-`/`pkg-` plus ULID),
/// case-insensitively. Finds IDs inside junk such as `[[p-…]]`.
pub fn scan_ids(text: &str) -> Vec<RecordId> {
    let mut out = Vec::new();
    let mut remaining = text;
    while !remaining.is_empty() {
        if let Some((id, len)) = match_id_at(remaining) {
            out.push(id);
            remaining = &remaining[len..];
        } else {
            let ch = remaining.chars().next().unwrap();
            remaining = &remaining[ch.len_utf8()..];
        }
    }
    out
}

fn match_id_at(s: &str) -> Option<(RecordId, usize)> {
    const PREFIXES: &[&str] = &["pkg", "p", "o", "d", "i", "n"];
    for pref in PREFIXES {
        let plen = pref.len();
        if s.len() < plen + 1 + ULID_LEN {
            continue;
        }
        let head = s.get(..plen)?;
        if !head.eq_ignore_ascii_case(pref) {
            continue;
        }
        if s.as_bytes().get(plen) != Some(&b'-') {
            continue;
        }
        let ulid = s.get(plen + 1..plen + 1 + ULID_LEN)?;
        if ulid.len() != ULID_LEN || !ulid.is_ascii() {
            continue;
        }
        let raw = format!("{pref}-{ulid}");
        if let Ok(id) = RecordId::parse(&raw) {
            return Some((id, plen + 1 + ULID_LEN));
        }
    }
    None
}

/// Package IDs are ledger-only in 0.1 and do not participate in the find allowlist.
pub fn is_vault_record_prefix(prefix: Prefix) -> bool {
    prefix != Prefix::Package
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
}
