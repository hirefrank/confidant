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

/// Bech32-encode bytes with the given HRP (via the `bech32` crate — the
/// same one `age` uses, so recipients interoperate with the age CLI).
pub(crate) fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    use bech32::{ToBase32, Variant};
    bech32::encode(hrp, data.to_base32(), Variant::Bech32).expect("HRP is valid")
}

/// Unwrap with a raw 32-byte X25519 secret (via Bech32 conversion).
pub fn unwrap_with_raw_secret(data: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let id = RawX25519Identity::new(*secret).to_age_identity()?;
    unwrap_with_identity(data, &id)
}

/// Wrap `data` (typically a 32-byte data key) to an `age1…` recipient,
/// producing a complete age-encrypted file.
pub fn wrap_to_recipient(data: &[u8], recipient: &str) -> Result<Vec<u8>, Error> {
    let recipient: age::x25519::Recipient = recipient
        .parse()
        .map_err(|e| Error::Age(format!("bad recipient: {e}")))?;
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
pub fn unwrap_with_identity(data: &[u8], identity: &dyn age::Identity) -> Result<Vec<u8>, Error> {
    let decryptor = age::Decryptor::new(data).map_err(|e| Error::Age(format!("decryptor: {e}")))?;
    let mut reader = decryptor
        .decrypt(iter::once(identity))
        .map_err(|e| Error::Age(format!("decrypt: {e}")))?;
    let mut out = Vec::new();
    use std::io::Read;
    reader
        .read_to_end(&mut out)
        .map_err(|e| Error::Age(format!("read: {e}")))?;
    Ok(out)
}

/// Unwrap with an age Bech32 identity string (`AGE-SECRET-KEY-1…`).
pub fn unwrap_with_bech32(data: &[u8], identity: &str) -> Result<Vec<u8>, Error> {
    let id = age::x25519::Identity::from_str(identity)
        .map_err(|e| Error::Age(format!("bad identity: {e}")))?;
    unwrap_with_identity(data, &id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        let wrapped = wrap_to_recipient(b"32-byte-data-key-payload!!!!!!", &recipient).unwrap();
        let back = unwrap_with_identity(&wrapped, &id).unwrap();
        assert_eq!(back, b"32-byte-data-key-payload!!!!!!");
    }

    #[test]
    fn raw_identity_unwraps() {
        // Wrap with the age crate, unwrap with our raw-secret identity.
        let raw = [9u8; 32];
        let pk = PublicKey::from(&StaticSecret::from(raw));
        let recipient = bech32_encode("age", pk.as_bytes());
        let wrapped = wrap_to_recipient(b"payload", &recipient).unwrap();
        let back = unwrap_with_raw_secret(&wrapped, &raw).unwrap();
        assert_eq!(back, b"payload");
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
