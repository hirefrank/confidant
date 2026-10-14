// Portions adapted from cr (https://github.com/AnandChowdhary/cr) at f29f8d4,
// MIT License, Copyright (c) 2026 Anand Chowdhary.
//
// XChaCha20-Poly1305 AEAD with length-prefixed associated data, re-keyed to
// per-client data keys and Confidant's AAD fields (ADR-13).

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

/// The context and outer-header fields bound into a record's AAD.
///
/// Named fields instead of eleven positional arguments: `encrypt_record`
/// and `decrypt_record` pass the same values in the same order, and a
/// silent transposition between the two would otherwise only surface when
/// the header-consistency check happened to fail (#136 item 3). The field
/// order here mirrors the components' order in the AAD, and the byte
/// layout is unchanged.
pub struct AadHeader<'a> {
    /// Vault id (`confidant.toml`), binding ciphertext to this vault.
    pub vault_id: &'a str,
    /// Record ULID.
    pub ulid: &'a str,
    /// Record owner's key holder (person id or `vault:shared`).
    pub client_id: &'a str,
    /// Vault-relative path.
    pub path: &'a str,
    /// AAD purpose: `profile`, `note`, `interaction`, `org`, `deal`.
    pub purpose: &'a str,
    /// Key epoch that wrote the file.
    pub epoch: u64,
    // --- outer (envelope) header fields, authenticated as stored ---
    /// Envelope `id` header.
    pub header_id: &'a str,
    /// Envelope `type` header.
    pub header_type: &'a str,
    /// Envelope `no-ai` header.
    pub no_ai: crate::envelope::NoAi,
    /// Envelope `enc` header.
    pub enc: &'a str,
    /// Envelope `key_id` header.
    pub key_id: &'a str,
}

/// Build the associated data for a record encryption.
///
/// Components, in order: `confidant1`, `vault_id`, record ULID,
/// `client_id`, relative path, `purpose`, key epoch (ASCII decimal), then
/// the outer header fields (`id`, `type`, `no-ai`, `enc`, `key_id`) each
/// length-prefixed in that fixed order. The nonce is the AEAD nonce and is
/// NOT part of the AAD.
pub fn build_aad(h: &AadHeader<'_>) -> Vec<u8> {
    let mut aad = Vec::new();
    push_component(&mut aad, DOMAIN);
    push_component(&mut aad, h.vault_id.as_bytes());
    push_component(&mut aad, h.ulid.as_bytes());
    push_component(&mut aad, h.client_id.as_bytes());
    push_component(&mut aad, h.path.as_bytes());
    push_component(&mut aad, h.purpose.as_bytes());
    push_component(&mut aad, h.epoch.to_string().as_bytes());
    push_component(&mut aad, h.header_id.as_bytes());
    push_component(&mut aad, h.header_type.as_bytes());
    push_component(&mut aad, h.no_ai.as_str().as_bytes());
    push_component(&mut aad, h.enc.as_bytes());
    push_component(&mut aad, h.key_id.as_bytes());
    aad
}

/// Encrypt `plaintext` under `key` with the given AAD.
///
/// Returns the random 192-bit nonce and the ciphertext (which includes the
/// 16-byte Poly1305 tag). A fresh nonce is drawn per call. Fails closed
/// ([`Error::Encrypt`]) rather than panicking (#136 item 5).
pub fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Encrypt(e.to_string()))?;
    Ok((nonce.to_vec(), ct))
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
        build_aad(&AadHeader {
            vault_id: "vault1",
            ulid: "01ABC",
            client_id: "p-01ABC",
            path: "people/p-01ABC.cfd",
            purpose: "profile",
            epoch: 3,
            header_id: "p-01ABC",
            header_type: "person",
            no_ai: crate::envelope::NoAi::False,
            enc: ALG,
            key_id: "p-01ABC/e3",
        })
    }

    #[test]
    fn round_trip() {
        let key = [42u8; 32];
        let (nonce, ct) = encrypt(&key, &aad(), b"hello").unwrap();
        let pt = decrypt(&key, &nonce, &aad(), &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let (nonce, mut ct) = encrypt(&key, &aad(), b"hello").unwrap();
        ct[0] ^= 1;
        assert!(matches!(
            decrypt(&key, &nonce, &aad(), &ct),
            Err(Error::Auth)
        ));
    }
}
