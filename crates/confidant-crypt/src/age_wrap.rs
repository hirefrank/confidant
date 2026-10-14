//! Age (X25519) wrapping of per-client data keys.
//!
//! Wrapping and unwrapping use the `age` crate's real file format, so
//! `wrapped/*.age` files interoperate with the age CLI. Raw 32-byte secrets
//! (e.g. the HKDF-derived recovery key) are converted to Bech32
//! `AGE-SECRET-KEY-1…` strings and parsed with the public
//! `age::x25519::Identity::from_str` — the `age` crate seals its `Identity`
//! trait against external implementations.

use std::io::Write;
use std::iter;
use std::str::FromStr;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

/// An age X25519 identity from a raw 32-byte secret (e.g. derived via HKDF).
///
/// The `age` crate only builds identities from Bech32 or fresh generation;
/// this wraps a raw secret and converts to Bech32 for the actual crypto.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RawX25519Identity([u8; 32]);

impl RawX25519Identity {
    pub fn new(secret: [u8; 32]) -> Self {
        RawX25519Identity(secret)
    }

    /// The corresponding `age1…` recipient string.
    pub fn to_recipient_string(&self) -> String {
        let pk = PublicKey::from(&StaticSecret::from(self.0));
        bech32_encode("age", pk.as_bytes())
    }

    /// The `AGE-SECRET-KEY-1…` Bech32 encoding of this secret, matching
    /// `age::x25519::Identity::to_string` (uppercase). Returned in a
    /// [`Zeroizing`] wrapper so the secret bytes are wiped when the
    /// caller is done with it. The lowercase intermediate is also wrapped
    /// and wiped on drop.
    pub fn to_bech32(&self) -> Zeroizing<String> {
        let lower = Zeroizing::new(bech32_encode("age-secret-key-", &self.0));
        Zeroizing::new(lower.to_uppercase())
    }

    /// As an `age` identity, via the public Bech32 parse path.
    pub fn to_age_identity(&self) -> Result<age::x25519::Identity, Error> {
        age::x25519::Identity::from_str(&self.to_bech32())
            .map_err(|e| Error::Age(format!("bad derived identity: {e}")))
    }
}

/// Bech32-encode bytes with the given HRP (via `bech32` 0.12).
///
/// Output is byte-identical to the bech32 0.9 encoding the `age` crate
/// uses internally, so recipients interoperate with the age CLI (locked
/// by `bech32_encode_matches_age_crate`).
pub(crate) fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<bech32::Bech32>(bech32::Hrp::parse(hrp).expect("HRP is valid"), data)
        .expect("HRP is valid")
}

/// Unwrap with a raw 32-byte X25519 secret (via Bech32 conversion).
pub fn unwrap_with_raw_secret(data: &[u8], secret: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let id = RawX25519Identity::new(*secret).to_age_identity()?;
    unwrap_with_identity(data, &id)
}

/// Parse an `age1…` X25519 recipient. Used to distinguish a malformed
/// configured value from a mismatch.
pub fn parse_recipient(s: &str) -> Result<age::x25519::Recipient, Error> {
    s.parse()
        .map_err(|e| Error::Age(format!("bad recipient: {e}")))
}

/// Returns true when `s` parses as an `age1…` X25519 recipient.
///
/// Not yet wired (#136 item 2, audit note): the one-line convenience over
/// [`parse_recipient`] for config/enrollment validation. Kept, with this
/// note, so the `init`/`recover` recipient check has one documented home.
pub fn is_valid_recipient(s: &str) -> bool {
    parse_recipient(s).is_ok()
}

/// Wrap `data` (typically a 32-byte data key) to an `age1…` recipient,
/// producing a complete age-encrypted file.
pub fn wrap_to_recipient(data: &[u8], recipient: &str) -> Result<Vec<u8>, Error> {
    let recipient = parse_recipient(recipient)?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| Error::Age(format!("encryptor: {e}")))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| Error::Age(format!("wrap: {e}")))?;
    writer
        .write_all(data)
        .map_err(|e| Error::Age(format!("write: {e}")))?;
    writer
        .finish()
        .map_err(|e| Error::Age(format!("finish: {e}")))?;
    Ok(out)
}

/// Unwrap age-encrypted `data` with any identity implementing [`age::Identity`].
///
/// Returns [`Zeroizing<Vec<u8>>`]: this is the crate's one function that
/// produces secret material from ciphertext, so the safe, self-wiping type
/// is the only choice — no caller can accidentally keep a bare `Vec<u8>`
/// (issue #135). The buffer is wiped when the returned wrapper drops.
pub fn unwrap_with_identity(
    data: &[u8],
    identity: &dyn age::Identity,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let decryptor = age::Decryptor::new(data).map_err(|e| Error::Age(format!("decryptor: {e}")))?;
    let mut reader = decryptor
        .decrypt(iter::once(identity))
        .map_err(|e| Error::Age(format!("decrypt: {e}")))?;
    let mut out = Zeroizing::new(Vec::new());
    use std::io::Read;
    reader
        .read_to_end(&mut out)
        .map_err(|e| Error::Age(format!("read: {e}")))?;
    Ok(out)
}

/// Unwrap with an age Bech32 identity string (`AGE-SECRET-KEY-1…`).
///
/// Not yet wired (#136 item 2, audit note): the string→identity→unwrap
/// path the `init`/`recover` enrollment flow will use. Kept, with this
/// note, alongside [`unwrap_with_raw_secret`] (which takes the 32-byte
/// secret directly) rather than re-invented later.
pub fn unwrap_with_bech32(data: &[u8], identity: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let id = age::x25519::Identity::from_str(identity)
        .map_err(|e| Error::Age(format!("bad identity: {e}")))?;
    unwrap_with_identity(data, &id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_encode_matches_age_crate() {
        // Golden vectors generated with bech32 0.9 (the version the `age`
        // crate still uses internally). The 0.12 port must produce
        // byte-identical output — any difference breaks every `age1…`
        // recipient and `AGE-SECRET-KEY-1…` string.
        let seq: Vec<u8> = (0..32).collect();
        assert_eq!(
            bech32_encode("age", &[0u8; 32]),
            "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z"
        );
        assert_eq!(
            bech32_encode("age", &[7u8; 32]),
            "age1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurs95jt69"
        );
        assert_eq!(
            bech32_encode("age", &[9u8; 32]),
            "age1pyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyyscxl7ka"
        );
        assert_eq!(
            bech32_encode("age", &seq),
            "age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0savhh7m"
        );
        assert_eq!(
            bech32_encode("age-secret-key-", &[7u8; 32]),
            "age-secret-key-1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurskmp32k"
        );
        // Full secret-key path: uppercase of the lowercase encoding.
        let id = RawX25519Identity::new([7u8; 32]);
        assert_eq!(
            &*id.to_bech32(),
            "AGE-SECRET-KEY-1QURSWPC8QURSWPC8QURSWPC8QURSWPC8QURSWPC8QURSWPC8QURSKMP32K"
        );
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        let wrapped = wrap_to_recipient(b"32-byte-data-key-payload!!!!!!", &recipient).unwrap();
        let back = unwrap_with_identity(&wrapped, &id).unwrap();
        assert_eq!(&*back, b"32-byte-data-key-payload!!!!!!");
    }

    #[test]
    fn raw_identity_unwraps() {
        // Wrap with the age crate, unwrap with our raw-secret identity.
        let raw = [9u8; 32];
        let pk = PublicKey::from(&StaticSecret::from(raw));
        let recipient = bech32_encode("age", pk.as_bytes());
        let wrapped = wrap_to_recipient(b"payload", &recipient).unwrap();
        let back = unwrap_with_raw_secret(&wrapped, &raw).unwrap();
        assert_eq!(&*back, b"payload");
    }

    #[test]
    fn unwrap_returns_zeroizing() {
        // #135: the unwrap path must return a self-wiping type, so no
        // caller can hold a bare Vec<u8> of secret material. The type
        // annotation pins the Zeroizing return.
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        let wrapped = wrap_to_recipient(b"payload", &recipient).unwrap();
        let back: Zeroizing<Vec<u8>> = unwrap_with_identity(&wrapped, &id).unwrap();
        assert_eq!(&*back, b"payload");
    }

    #[test]
    fn bech32_returns_zeroizing() {
        // Per Silas's #54 sign-off: the secret encoding must not sit in a
        // plain String. The type annotation pins the Zeroizing return.
        let id = RawX25519Identity::new([7u8; 32]);
        let s: Zeroizing<String> = id.to_bech32();
        assert!(s.starts_with("AGE-SECRET-KEY-1"));
    }

    #[test]
    fn wrong_key_fails() {
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        let wrapped = wrap_to_recipient(b"payload", &recipient).unwrap();
        let other = [1u8; 32];
        assert!(unwrap_with_raw_secret(&wrapped, &other).is_err());
    }
}
