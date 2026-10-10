//! Encryption for Confidant vaults (milestone 2).
//!
//! Implements `docs/crypto-design.md` (signed off by Silas 2026-10-08):
//! per-client data keys wrapped with age (X25519), XChaCha20-Poly1305
//! content encryption with length-prefixed AAD binding
//! `vault_id ‖ ULID ‖ path ‖ purpose ‖ epoch ‖ outer header`, signed
//! recipient manifests against an off-vault trust anchor, scoped agent
//! keys, epoch rotation without re-encryption, crypto-shredding by key
//! destruction, and BIP39 recovery.
//!
//! Everything fails closed: missing keys, bad signatures, or tampered
//! envelopes are errors, never silent plaintext.

#![forbid(unsafe_code)]

pub mod aead;
pub mod age_wrap;
pub mod alias;
pub mod anchor;
pub mod envelope;
pub mod error;
pub mod history;
pub mod keys;
pub mod lifecycle;
pub mod manifest;
pub mod recovery;
pub mod scope;

pub use error::Error;

// ---------------------------------------------------------------------------
// Legacy interface (kept for PRs C and D, which program against it).
// ---------------------------------------------------------------------------

/// True when this build can encrypt or decrypt vault content.
pub fn is_available() -> bool {
    true
}

/// True when the CLI write path actually encrypts vault content.
///
/// This is separate from [`is_available`]: the crate can encrypt, but until
/// the CLI wiring lands (`note add`, `log session --note`, etc. still write
/// plaintext), `doctor` must not report the crypto check as `ok`. Key the
/// doctor check off this, not off `is_available`.
pub fn writes_encrypted() -> bool {
    false
}

/// Resolve the device age identity.
///
/// From the `CONFIDANT_DEVICE_KEY` env var (Bech32 `AGE-SECRET-KEY-1…`).
/// There is no file fallback: §2 says device keys live in the OS keychain,
/// and #36 rejected key files under `~/.config` (Time Machine backs them
/// up, so "destroy the old key" would be false). OS-keychain storage lands
/// with the CLI wiring; until then the env var covers tests and agent
/// hosts. Absent → fail closed with [`Error::NoKey`].
fn device_identity() -> Result<age::x25519::Identity, Error> {
    use std::str::FromStr;
    if let Ok(s) = std::env::var("CONFIDANT_DEVICE_KEY") {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return age::x25519::Identity::from_str(&s)
                .map_err(|e| Error::Age(format!("bad CONFIDANT_DEVICE_KEY: {e}")));
        }
    }
    Err(Error::NoKey(
        "no device key: set CONFIDANT_DEVICE_KEY (OS-keychain storage lands with the CLI wiring)"
            .to_string(),
    ))
}

/// Encrypt a file to this device's age key.
///
/// This is the file-level API (age to the device key), distinct from the
/// record-level envelope API ([`envelope`]). It exists so callers written
/// against the milestone-1 stub keep compiling; new code should use the
/// typed modules.
pub fn encrypt_file(plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let id = device_identity()?;
    let recipient = id.to_public().to_string();
    age_wrap::wrap_to_recipient(plaintext, &recipient)
}

/// Decrypt a file with this device's age key. Fails closed when the device
/// key is absent or the ciphertext is not for this device.
pub fn decrypt_file(ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let id = device_identity()?;
    age_wrap::unwrap_with_identity(ciphertext, &id)
}

// ---------------------------------------------------------------------------
// Record-level convenience API
// ---------------------------------------------------------------------------

/// Context needed to encrypt or decrypt one record.
#[derive(Clone, Debug)]
pub struct RecordCtx {
    pub vault_id: String,
    pub ulid: String,
    /// The client whose data key encrypts this record (e.g. `p-…` for a
    /// person's notes/interactions, per spec §1). Bound in the AAD and the
    /// `key_id` header.
    pub client_id: String,
    pub path: String,
    /// AAD purpose: `profile`, `note`, `interaction`, `org`, `deal`.
    pub purpose: String,
    pub epoch: u64,
}

/// Resolve which client key encrypts a record (design §2, issue #62).
///
/// - `person`, `note`, and `interaction` records — and `deal` records whose
///   `person` field is set — encrypt under that person's data key.
/// - `org` records, and `deal` records with no `person`, encrypt under the
///   reserved [`manifest::SHARED_CLIENT_ID`] (`vault:shared`) vault key.
///
/// Unknown record types, and person-bearing types without a person id, are
/// errors. The operator's own person record is never consulted: there is no
/// operator parameter, so routing through it is impossible by construction.
/// When a deal's `person` changes, the writer re-encrypts it under the new
/// person's current epoch in the same signed commit (the writer calls this
/// to pick the target key).
pub fn client_id_for_record(record_type: &str, person: Option<&str>) -> Result<String, Error> {
    let person = person.map(str::trim).filter(|p| !p.is_empty());
    match record_type {
        "person" | "note" | "interaction" => person
            .map(str::to_string)
            .ok_or_else(|| Error::Header(format!("{record_type} record needs a person id"))),
        "deal" => Ok(person
            .map(str::to_string)
            .unwrap_or_else(|| manifest::SHARED_CLIENT_ID.to_string())),
        "org" => Ok(manifest::SHARED_CLIENT_ID.to_string()),
        _ => Err(Error::Header(format!(
            "unknown record type {record_type:?}"
        ))),
    }
}

/// Encrypt a record's inner plaintext under `key`, producing a serialized
/// envelope. The outer header (including `no-ai`) is authenticated via the
/// AAD, so it cannot be flipped with only git write access.
pub fn encrypt_record(
    ctx: &RecordCtx,
    key: &keys::DataKey,
    record_type: &str,
    no_ai: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Fail fast: type must map to exactly one purpose (design §5).
    match envelope::purpose_for_type(record_type) {
        Some(p) if p == ctx.purpose => {}
        _ => {
            return Err(Error::Header(format!(
                "type {record_type} does not map to purpose {}",
                ctx.purpose
            )))
        }
    }
    let key_id = format!("{}/e{}", ctx.client_id, ctx.epoch);
    let aad = aead::build_aad(
        &ctx.vault_id,
        &ctx.ulid,
        &ctx.client_id,
        &ctx.path,
        &ctx.purpose,
        ctx.epoch,
        &ctx.ulid,
        record_type,
        no_ai,
        aead::ALG,
        &key_id,
    );
    let (nonce, ciphertext) = aead::encrypt(key.as_bytes(), &aad, plaintext);
    let env = envelope::Envelope {
        id: ctx.ulid.clone(),
        record_type: record_type.to_string(),
        no_ai,
        enc: aead::ALG.to_string(),
        key_id,
        epoch: ctx.epoch,
        nonce,
        ciphertext,
    };
    Ok(envelope::serialize(&env))
}

/// Decrypt a record envelope.
///
/// Steps: parse → header consistency checks → rebuild AAD → AEAD decrypt.
/// Any failure (bad header, AAD mismatch, wrong key, tampered ciphertext)
/// fails closed with no plaintext. When `for_agent` is true and the header
/// says `no-ai: true`, the record is refused *without decrypting at all*.
pub fn decrypt_record(
    ctx: &RecordCtx,
    key: &keys::DataKey,
    envelope_bytes: &[u8],
    for_agent: bool,
) -> Result<Vec<u8>, Error> {
    let env = envelope::parse(envelope_bytes)?;
    envelope::check_header(&env, &ctx.ulid, &ctx.client_id, &ctx.purpose, ctx.epoch)?;
    if for_agent && env.no_ai {
        return Err(Error::Header(
            "no-ai: refusing to decrypt for agent output".to_string(),
        ));
    }
    let aad = aead::build_aad(
        &ctx.vault_id,
        &ctx.ulid,
        &ctx.client_id,
        &ctx.path,
        &ctx.purpose,
        ctx.epoch,
        &env.id,
        &env.record_type,
        env.no_ai,
        &env.enc,
        &env.key_id,
    );
    aead::decrypt(key.as_bytes(), &env.nonce, &aad, &env.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_now() {
        assert!(is_available());
    }

    #[test]
    fn record_round_trip() {
        let key = keys::DataKey::generate();
        let ctx = RecordCtx {
            vault_id: "v1".to_string(),
            ulid: "p-01ABC".to_string(),
            client_id: "p-01ABC".to_string(),
            path: "people/p-01ABC.cfd".to_string(),
            purpose: "profile".to_string(),
            epoch: 3,
        };
        let bytes = encrypt_record(&ctx, &key, "person", false, b"secret profile").unwrap();
        let back = decrypt_record(&ctx, &key, &bytes, false).unwrap();
        assert_eq!(back, b"secret profile");
    }

    #[test]
    fn no_ai_refused_for_agent_without_decrypting() {
        let key = keys::DataKey::generate();
        let ctx = RecordCtx {
            vault_id: "v1".to_string(),
            ulid: "p-01ABC".to_string(),
            client_id: "p-01ABC".to_string(),
            path: "people/p-01ABC.cfd".to_string(),
            purpose: "profile".to_string(),
            epoch: 3,
        };
        let bytes = encrypt_record(&ctx, &key, "person", true, b"secret").unwrap();
        // Even with the right key, agent paths refuse before decrypting.
        assert!(decrypt_record(&ctx, &key, &bytes, true).is_err());
        // Non-agent paths still work.
        assert!(decrypt_record(&ctx, &key, &bytes, false).is_ok());
    }
}
