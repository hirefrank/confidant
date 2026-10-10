//! Alias HMAC (design §10, ADR-2).
//!
//! Ledger `alias` lines carry `hmac:HEX`, never plaintext. Following the cr
//! spike's keyed-digest reasoning (a plain hash can be dictionary-attacked):
//!
//! ```text
//! hmac = HMAC-SHA256(vault_lookup_key, normalized_value)
//! ```
//!
//! The vault lookup key is generated at `init` and wrapped with age to each
//! device/agent like a data key. Importers match on aliases by recomputing
//! the HMAC of the normalized value.
//!
//! Normalization: NFC, then trim surrounding whitespace and lowercase
//! (Unicode lowercase). Documented here; importers must apply the same rule.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::keys::LookupKey;

/// Normalize an alias value before HMAC: NFC, then trim + lowercase.
pub fn normalize(value: &str) -> String {
    value.nfc().collect::<String>().trim().to_lowercase()
}

/// Compute the alias HMAC, hex-encoded (at least 32 hex chars per spec §6;
/// HMAC-SHA256 gives 64).
pub fn alias_hmac(key: &LookupKey, value: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(normalize(value).as_bytes());
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Check whether `value` matches a stored `hmac:HEX` line value.
pub fn matches(key: &LookupKey, value: &str, hex: &str) -> bool {
    // Constant-time compare on the hex strings.
    let computed = alias_hmac(key, value);
    computed.len() == hex.len()
        && computed
            .bytes()
            .zip(hex.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_long_enough() {
        let k = LookupKey::generate();
        let h1 = alias_hmac(&k, "Alice@Example.com ");
        let h2 = alias_hmac(&k, "alice@example.com");
        assert_eq!(h1, h2);
        assert!(h1.len() >= 32);
    }

    #[test]
    fn different_keys_differ() {
        let a = alias_hmac(&LookupKey::generate(), "x");
        let b = alias_hmac(&LookupKey::generate(), "x");
        assert_ne!(a, b);
    }

    #[test]
    fn matches_works() {
        let k = LookupKey::generate();
        let h = alias_hmac(&k, "Bob");
        assert!(matches(&k, "  bob ", &h));
        assert!(!matches(&k, "alice", &h));
    }

    #[test]
    fn nfc_before_lowercase() {
        // "Café" precomposed (U+00E9) vs decomposed (e + U+0301) must
        // normalize identically, or the same alias would HMAC differently.
        let composed = "Caf\u{e9}@example.com";
        let decomposed = "Cafe\u{301}@example.com";
        assert_ne!(composed.to_lowercase(), decomposed.to_lowercase());
        assert_eq!(normalize(composed), normalize(decomposed));
        let k = LookupKey::generate();
        assert_eq!(alias_hmac(&k, composed), alias_hmac(&k, decomposed));
    }
}
