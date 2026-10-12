//! Minimal hex encoding/decoding (avoids a `hex` dependency).
//!
//! One implementation for the whole crate (#136 item 6): the manifest
//! (key commitments) and the anchor (trust-file public keys) used to carry
//! separate copies of the same loop. Parsing lives here; each caller still
//! maps a failure into its own error variant, so messages keep their
//! `Error::Manifest` / `Error::Anchor` context and a `what` label.

use crate::error::Error;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex encoding.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode hex after trimming surrounding whitespace.
///
/// The returned reason on failure is a bare phrase (`"non-ASCII hex"`,
/// `"odd-length hex"`, `"invalid hex"`); callers add their own context.
/// An ASCII-only guard runs first: without it, byte-index slicing inside a
/// multi-byte character panics (`"é01"` splits the `é`).
pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let s = s.trim();
    if !s.is_ascii() {
        return Err("non-ASCII hex");
    }
    if s.len() % 2 != 0 {
        return Err("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex"))
        .collect()
}

/// Decode with a `what` label in the error, as an [`Error::Anchor`].
/// Shared by the trust-file readers.
pub fn decode_anchor(what: &str, s: &str) -> Result<Vec<u8>, Error> {
    decode(s).map_err(|reason| Error::Anchor(format!("{what}: {reason}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        assert_eq!(encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(decode(" 000fff ").unwrap(), vec![0x00, 0x0f, 0xff]);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode("é01").unwrap_err(), "non-ASCII hex");
        assert_eq!(decode("abc").unwrap_err(), "odd-length hex");
        assert_eq!(decode("zz").unwrap_err(), "invalid hex");
    }
}
