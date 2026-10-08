//! XChaCha20-Poly1305 content encryption with length-prefixed associated data.
//!
//! Adapted from cr's `src/encryption.rs` per ADR-13: re-keyed to per-client
//! data keys and Confidant's associated-data fields. Every encryption binds
//! `vault_id ‖ record ULID ‖ relative path ‖ purpose ‖ key epoch ‖ outer
//! header`, each length-prefixed, so nothing can be swapped, renamed,
//! re-purposed, or re-keyed without failing authentication.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

use crate::error::Error;

/// AEAD algorithm identifier used in envelopes.
pub const ALG: &str = "xchacha20poly1305";

/// Domain separator, first AAD component.
const DOMAIN: &[u8] = b"confidant1";

/// Append one length-prefixed component (u64 little-endian length + bytes).
fn push_component(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Build the associated data for a record encryption.
///
/// Components, in order: `confidant1`, `vault_id`, record ULID, relative
/// path, `purpose`, key epoch (ASCII decimal), then the outer header fields
/// (`id`, `type`, `no-ai`, `enc`, `key_id`) each length-prefixed in that
/// fixed order. The nonce is the AEAD nonce and is NOT part of the AAD.
#[allow(clippy::too_many_arguments)]
pub fn build_aad(
    vault_id: &str,
    ulid: &str,
    path: &str,
    purpose: &str,
    epoch: u64,
    header_id: &str,
    header_type: &str,
    header_no_ai: bool,
    header_enc: &str,
    header_key_id: &str,
) -> Vec<u8> {
    let mut aad = Vec::new();
    push_component(&mut aad, DOMAIN);
    push_component(&mut aad, vault_id.as_bytes());
    push_component(&mut aad, ulid.as_bytes());
    push_component(&mut aad, path.as_bytes());
    push_component(&mut aad, purpose.as_bytes());
    push_component(&mut aad, epoch.to_string().as_bytes());
    push_component(&mut aad, header_id.as_bytes());
    push_component(&mut aad, header_type.as_bytes());
    push_component(&mut aad, if header_no_ai { b"true" } else { b"false" });
    push_component(&mut aad, header_enc.as_bytes());
    push_component(&mut aad, header_key_id.as_bytes());
    aad
}

/// Encrypt `plaintext` under `key` with the given AAD.
///
/// Returns the random 192-bit nonce and the ciphertext (which includes the
/// 16-byte Poly1305 tag). A fresh nonce is drawn per call.
pub fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail with a valid key");
    (nonce.to_vec(), ct)
}

/// Decrypt `ciphertext` under `key` with the given AAD.
///
/// Any mismatch — wrong key, tampered ciphertext, or altered associated
/// data — returns [`Error::Auth`] and no plaintext.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if nonce.len() != 24 {
        return Err(Error::Auth);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aad() -> Vec<u8> {
        build_aad(
            "vault1",
            "01ABC",
            "people/p-01ABC.cfd",
            "profile",
            3,
            "p-01ABC",
            "person",
            false,
            ALG,
            "p-01ABC/e3",
        )
    }

    #[test]
    fn round_trip() {
        let key = [42u8; 32];
        let (nonce, ct) = encrypt(&key, &aad(), b"hello");
        let pt = decrypt(&key, &nonce, &aad(), &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let (nonce, mut ct) = encrypt(&key, &aad(), b"hello");
        ct[0] ^= 1;
        assert!(matches!(
            decrypt(&key, &nonce, &aad(), &ct),
            Err(Error::Auth)
        ));
    }
}
