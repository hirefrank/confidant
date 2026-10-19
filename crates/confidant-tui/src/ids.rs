//! ULID minting for the operator-initiated new-person capture (#621).
//!
//! The proposal-apply engine deliberately never mints ids: a skill proposal
//! must carry the id its author chose, so `apply.rs` and `proposals.rs`
//! refuse a manifest that leaves one out (a grep test enforces that
//! `apply.rs` mentions no ULID). A person created directly by the human has
//! no author to supply an id, and `confidant record add` requires `id:` in
//! the record file, so this module mints one for the new-person flow.
//!
//! The format is a prefixed ULID (ADR-3): `p-` plus a 26-character
//! Crockford base32 value — a 48-bit millisecond timestamp, then 80 random
//! bits. It intentionally does not link `confidant-core`; the algorithm is
//! small enough to keep here (the same bytes the core parser accepts,
//! exercised end-to-end by the live CLI test). Entropy comes from
//! `/dev/urandom`; a vault without it fails closed rather than risk a
//! collision.

use anyhow::{Context as _, Result};

/// Crockford base32 alphabet (no `I`, `L`, `O`, `U`), matching the ULID spec
/// and the core id parser.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode `value` as `len` Crockford characters (big-endian), mirroring
/// `confidant_core::id::encode_crockford`.
fn encode_crockford(mut value: u128, len: usize) -> String {
    let mut chars = vec![b'0'; len];
    for slot in chars.iter_mut().rev() {
        *slot = CROCKFORD[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(chars).expect("crockford alphabet is ascii")
}

/// Build a deterministic ULID from a millisecond timestamp and 80-bit random
/// value. Exposed for tests; [`new_ulid`] supplies the real clock and entropy.
pub fn ulid_from_parts(time_ms: u64, random: u128) -> String {
    let time = u128::from(time_ms) & ((1u128 << 48) - 1);
    let rand = random & ((1u128 << 80) - 1);
    let mut encoded = encode_crockford(time, 10);
    encoded.push_str(&encode_crockford(rand, 16));
    encoded
}

/// Mint a fresh 26-character ULID: the current time in milliseconds, then 80
/// random bits from `/dev/urandom`.
pub fn new_ulid() -> Result<String> {
    let time_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis() as u64;
    Ok(ulid_from_parts(time_ms, read_random_80_bits()?))
}

/// Mint a new `p-<ULID>` person id.
pub fn new_person_id() -> Result<String> {
    Ok(format!("p-{}", new_ulid()?))
}

/// Read 80 bits (10 bytes) of entropy. Only the Unix path is implemented:
/// native Windows is unsupported (#502 — Windows runs Confidant under WSL2),
/// and `/dev/urandom` exists on both Linux and macOS, the two CI platforms.
fn read_random_80_bits() -> Result<u128> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut buf = [0u8; 10];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut buf))
            .context("read 10 bytes of entropy from /dev/urandom")?;
        Ok(u128::from_be_bytes([
            0, 0, 0, 0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            buf[8], buf[9],
        ]))
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("no entropy source for ULID minting on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ULID spec's example timestamp, independently checked: the 10-char
    /// time prefix for 1469918176385 ms is `01ARYZ6S41`.
    #[test]
    fn encodes_a_known_timestamp_and_randomness() {
        assert_eq!(
            ulid_from_parts(1469918176385, 0),
            "01ARYZ6S410000000000000000"
        );
        assert_eq!(
            ulid_from_parts(1469918176385, (1u128 << 80) - 1),
            "01ARYZ6S41ZZZZZZZZZZZZZZZZ"
        );
    }

    #[test]
    fn masks_the_timestamp_to_48_bits_and_the_random_to_80() {
        assert_eq!(ulid_from_parts(1u64 << 48, 0), ulid_from_parts(0, 0));
        assert_eq!(
            ulid_from_parts(0, 1u128 << 80),
            ulid_from_parts(0, 0),
            "the 81st random bit is dropped"
        );
    }

    #[test]
    fn minted_ids_are_prefixed_26_char_crockford() {
        let id = new_person_id().expect("entropy available");
        assert!(id.starts_with("p-"), "{id}");
        let ulid = &id[2..];
        assert_eq!(ulid.len(), 26, "{id}");
        assert!(
            ulid.bytes().all(|b| CROCKFORD.contains(&b)),
            "not Crockford: {id}"
        );
    }

    #[test]
    fn minted_ulids_do_not_repeat() {
        let a = new_ulid().expect("entropy available");
        let b = new_ulid().expect("entropy available");
        // The 80 random bits make a repeat essentially impossible; this is a
        // smoke check that two calls are not accidentally identical.
        assert_ne!(a, b, "two minted ULIDs collided");
    }
}
