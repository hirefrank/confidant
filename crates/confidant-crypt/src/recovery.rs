//! Recovery identity (design §9, ADR-15).
//!
//! At `init`, generate a 24-word BIP39 phrase (English wordlist, checksum).
//! The phrase derives two keys via HKDF-SHA256 over the raw phrase entropy
//! (256 bits, **no passphrase** — the entropy goes straight into HKDF):
//!
//! - `X25519` = `HKDF(entropy, salt, "confidant/recovery/x25519/v1")`
//!   (age recipient; every client data key is wrapped to it)
//! - `Ed25519` = `HKDF(entropy, salt, "confidant/recovery/ed25519/v1")`
//!   (trust-anchor signing key, so a bare-phrase recovery can authorize the
//!   new device's recipient manifest)
//!
//! The salt is fixed: `confidant1/recovery` (design §9). The versioned
//! `info` strings follow Silas's reviewed call (§15 Q6); §9's older
//! `confidant1/recovery/…` info form is superseded.
//!
//! The phrase is never logged, printed, or written to disk: [`Recovery`]
//! redacts it in `Debug`, and the phrase bytes are zeroized on drop.

use bip39::{Language, Mnemonic, WordCount};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::age_wrap::RawX25519Identity;
use crate::error::Error;

/// Fixed HKDF salt for recovery derivation (design §9).
const RECOVERY_SALT: &[u8] = b"confidant1/recovery";
/// HKDF info for the X25519 age key (Silas's reviewed call, §15 Q6).
const INFO_X25519: &[u8] = b"confidant/recovery/x25519/v1";
/// HKDF info for the Ed25519 signing key (Silas's reviewed call, §15 Q6).
const INFO_ED25519: &[u8] = b"confidant/recovery/ed25519/v1";

/// A recovery identity: the phrase plus both derived keys.
///
/// `Debug` is redacted — the phrase (and its words) must never appear in
/// logs, errors, or debug output (test 13).
pub struct Recovery {
    /// The 24 words. Zeroized on drop.
    phrase_words: Vec<String>,
    /// X25519 secret for age unwrapping.
    x25519_sk: [u8; 32],
    /// Ed25519 signing key for the trust anchor.
    ed25519_sk: SigningKey,
}

impl Drop for Recovery {
    fn drop(&mut self) {
        for w in &mut self.phrase_words {
            w.zeroize();
        }
        self.x25519_sk.zeroize();
    }
}

impl ZeroizeOnDrop for Recovery {}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Label "words", not "phrase_words": "phrase" is itself a BIP39
        // word, so a label containing it false-positives any token scan
        // of the Debug output against the phrase (CI run 37812600604).
        f.debug_struct("Recovery")
            .field("words", &"<redacted>")
            .field("x25519_sk", &"<redacted>")
            .field("ed25519_sk", &"<redacted>")
            .finish()
    }
}

impl Recovery {
    /// Generate a fresh recovery identity (24-word phrase).
    pub fn generate() -> Self {
        let m = Mnemonic::generate_in(Language::English, WordCount::Words24)
            .expect("OS RNG failure generating recovery phrase");
        Self::from_mnemonic(&m)
    }

    /// Recover from a written-down phrase. Validates the checksum and
    /// reports "typo in word N"-style errors (position only — never echo
    /// the mistyped word, per test 13).
    pub fn from_phrase(phrase: &str) -> Result<Self, Error> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.len() != 24 {
            return Err(Error::Recovery(format!(
                "expected 24 words, got {}",
                words.len()
            )));
        }
        let list = Language::English.word_list();
        for (i, w) in words.iter().enumerate() {
            let lower = w.to_lowercase();
            if !list.iter().any(|valid| *valid == lower) {
                return Err(Error::Recovery(format!(
                    "typo in word {}: not in the BIP39 English wordlist",
                    i + 1
                )));
            }
        }
        let normalized = Zeroizing::new(
            words
                .iter()
                .map(|w| w.to_lowercase())
                .collect::<Vec<_>>()
                .join(" "),
        );
        let m = Mnemonic::parse_in(Language::English, normalized.as_str())
            .map_err(|e| Error::Recovery(format!("checksum invalid: {e}")))?;
        Ok(Self::from_mnemonic(&m))
    }

    /// The phrase as a single space-separated string, in a [`Zeroizing`]
    /// wrapper so the secret is wiped when the caller drops it.
    ///
    /// Callers must display this exactly once (at `init` / after `shred`)
    /// and never log it.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.phrase_words.join(" "))
    }

    /// X25519 secret bytes for age unwrapping.
    pub fn x25519_secret(&self) -> &[u8; 32] {
        &self.x25519_sk
    }

    /// Age identity for unwrapping `wrapped/recovery.age` files.
    pub fn age_identity(&self) -> RawX25519Identity {
        RawX25519Identity::new(self.x25519_sk)
    }

    /// Ed25519 signing key (trust-anchor member).
    pub fn signing_key(&self) -> &SigningKey {
        &self.ed25519_sk
    }

    /// Ed25519 verifying key to pin in the trust anchor.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.ed25519_sk.verifying_key()
    }

    fn from_mnemonic(m: &Mnemonic) -> Self {
        let mut entropy = m.to_entropy();
        assert_eq!(entropy.len(), 32, "24 words must give 256-bit entropy");
        let x25519_sk = hkdf_32(&entropy, INFO_X25519);
        let mut ed_seed = hkdf_32(&entropy, INFO_ED25519);
        entropy.zeroize();
        let ed25519_sk = SigningKey::from_bytes(&ed_seed);
        ed_seed.zeroize();
        // The full phrase string is the most sensitive intermediate here;
        // wrap it so the `to_string()` buffer is wiped on drop (#135).
        let phrase = Zeroizing::new(m.to_string());
        let phrase_words: Vec<String> = phrase.split_whitespace().map(str::to_string).collect();
        Self {
            phrase_words,
            x25519_sk,
            ed25519_sk,
        }
    }
}

fn hkdf_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(RECOVERY_SALT), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32-byte HKDF output is valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_gives_24_words() {
        let r = Recovery::generate();
        assert_eq!(r.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn phrase_returns_zeroizing() {
        // Per Silas's #54 sign-off: the phrase must not sit in a plain
        // String. The type annotation pins the Zeroizing return.
        let r = Recovery::generate();
        let phrase: Zeroizing<String> = r.phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn round_trip() {
        let r = Recovery::generate();
        let phrase = r.phrase();
        let r2 = Recovery::from_phrase(&phrase).unwrap();
        assert_eq!(r2.x25519_secret(), r.x25519_secret());
        assert_eq!(r2.verifying_key(), r.verifying_key());
    }

    #[test]
    fn typo_reports_word_number() {
        let r = Recovery::generate();
        let mut words: Vec<String> = r.phrase().split_whitespace().map(str::to_string).collect();
        words[5] = "notaword".to_string();
        let err = Recovery::from_phrase(&words.join(" ")).unwrap_err();
        assert!(format!("{err}").contains("word 6"), "{err}");
    }

    #[test]
    fn wrong_word_count_rejected() {
        let err = Recovery::from_phrase("abandon abandon abandon").unwrap_err();
        assert!(format!("{err}").contains("24 words"), "{err}");
    }

    #[test]
    fn debug_redacts_phrase() {
        let r = Recovery::generate();
        // Exact match, not a token scan: redaction is total, so the Debug
        // output is byte-identical to the redacted form whatever the
        // random phrase is. Deterministic by construction.
        assert_eq!(
            format!("{r:?}"),
            r#"Recovery { words: "<redacted>", x25519_sk: "<redacted>", ed25519_sk: "<redacted>" }"#
        );
    }

    #[test]
    fn debug_redacts_when_phrase_contains_label_word() {
        // Regression test for the old flake: "phrase" is itself a BIP39
        // word, and the old "phrase_words" Debug label false-positived a
        // token scan whenever a random phrase contained it (~1 in 86,
        // CI run 37812600604). Build a valid 24-word phrase containing
        // "phrase" deterministically — every 23-word prefix has valid
        // checksum completions — and assert redaction still holds.
        let list = Language::English.word_list();
        let mut prefix: Vec<&str> = vec!["phrase"];
        prefix.extend(std::iter::repeat_n("abandon", 22));
        let phrase = list
            .iter()
            .find_map(|last| {
                let candidate = prefix
                    .iter()
                    .chain(std::iter::once(last))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                Mnemonic::parse_in(Language::English, &candidate)
                    .ok()
                    .map(|_| candidate)
            })
            .expect("every 23-word prefix has valid 24th-word completions");
        assert!(phrase.split_whitespace().any(|w| w == "phrase"));
        let r = Recovery::from_phrase(&phrase).unwrap();
        assert_eq!(
            format!("{r:?}"),
            r#"Recovery { words: "<redacted>", x25519_sk: "<redacted>", ed25519_sk: "<redacted>" }"#
        );
    }

    #[test]
    fn debug_labels_contain_no_bip39_words() {
        // Guards the labels themselves: if a Debug label ever becomes a
        // BIP39 word again, any token-based redaction check would
        // false-positive on random phrases containing that word.
        let dbg = format!("{:?}", Recovery::generate());
        let list = Language::English.word_list();
        let body = dbg
            .strip_prefix("Recovery { ")
            .and_then(|s| s.strip_suffix(" }"))
            .expect("Debug keeps debug_struct shape");
        for field in body.split(", ") {
            let (label, _) = field.split_once(": ").expect("label: value shape");
            for token in label
                .split(|c: char| !c.is_alphabetic())
                .filter(|t| !t.is_empty())
            {
                assert!(
                    !list.contains(&token),
                    "Debug label is a BIP39 word: {token}"
                );
            }
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let r = Recovery::generate();
        let phrase = r.phrase();
        let a = Recovery::from_phrase(&phrase).unwrap();
        let b = Recovery::from_phrase(&phrase).unwrap();
        assert_eq!(a.x25519_secret(), b.x25519_secret());
    }

    /// Golden-output test for the hkdf 0.12 -> 0.13 move (#245): HKDF-SHA256
    /// must produce byte-identical output across the version bump, or every
    /// recovery phrase ever written would derive different keys.
    /// Vectors are RFC 5869 §A.1–A.2 (SHA-256), cross-checked against an
    /// independent Python implementation of the RFC.
    #[test]
    fn hkdf_matches_rfc5869_vectors() {
        fn expand(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Vec<u8> {
            let hk = Hkdf::<Sha256>::new(salt, ikm);
            let mut out = vec![0u8; len];
            hk.expand(info, &mut out).expect("valid HKDF params");
            out
        }
        // Case 1: IKM = 0x0b * 22, salt = 0x00..0x0c, info = 0xf0..0xf9.
        let ikm = vec![0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        assert_eq!(
            expand(&ikm, Some(&salt), &info, 42),
            crate::hex::decode(
                "3cb25f25faacd57a90434f64d0362f2a\
                 2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
            .unwrap()
        );
        // Case 2: 80-octet IKM/salt/info.
        let ikm: Vec<u8> = (0x00u8..0x50).collect();
        let salt: Vec<u8> = (0x60u8..0xb0).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        assert_eq!(
            expand(&ikm, Some(&salt), &info, 82),
            crate::hex::decode(
                "b11e398dc80327a1c8e7f78c596a4934\
                 4f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590\
                 e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c\
                 1f3434f1d87"
            )
            .unwrap()
        );
        // Case 3: empty salt and info (salt defaults to HashLen zeros).
        let ikm = vec![0x0bu8; 22];
        assert_eq!(
            expand(&ikm, None, &[], 42),
            crate::hex::decode(
                "8da4e775a563c18f715f802a063c5a31\
                 b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            )
            .unwrap()
        );
    }

    /// Golden-output test for the recovery derivation path itself (#245):
    /// fixed entropy through `hkdf_32` with the production salt/info
    /// strings must give byte-identical keys. Expected values generated
    /// with an independent Python HKDF-SHA256 implementation.
    #[test]
    fn hkdf_32_matches_golden() {
        let entropy: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            hkdf_32(&entropy, INFO_X25519),
            crate::hex::decode("6f89990fe2b1217b9447c9ac7ef22bbe01f886b0852efbe2fc2d3e045eed23ef")
                .unwrap()[..]
        );
        assert_eq!(
            hkdf_32(&entropy, INFO_ED25519),
            crate::hex::decode("04e7cf793a94d69c73c43dabb7b4b8c9d3eadbec2373b8ba7171f897bd1f9da4")
                .unwrap()[..]
        );
    }
}
