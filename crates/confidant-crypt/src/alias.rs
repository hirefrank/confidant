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
//! Normalization: trim surrounding whitespace and lowercase (Unicode
//! lowercase). Documented here; importers must apply the same rule.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::keys::LookupKey;

/// Normalize an alias value before HMAC: trim + lowercase.
pub fn normalize(value: &str) -> String {
    value.trim().to_lowercase()
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
}
