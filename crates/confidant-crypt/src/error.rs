//! Error type for `confidant-crypt`. Every variant fails closed: callers map
//! these to stable `E_` codes and never to silent plaintext.

use thiserror::Error;

/// All failures from the crypto layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// AEAD authentication failed (wrong key, tampered ciphertext, or
    /// mismatched associated data). No partial plaintext is ever returned.
    #[error("authentication failed: wrong key or tampered data")]
    Auth,

    /// Envelope could not be parsed.
    #[error("invalid envelope: {0}")]
    Envelope(String),

    /// Envelope header is inconsistent with the AAD-bound values.
    #[error("header inconsistency: {0}")]
    Header(String),

    /// Age wrapping / unwrapping failed.
    #[error("age operation failed: {0}")]
    Age(String),

    /// Recipient manifest signature invalid, missing, or from an unknown signer.
    #[error("manifest verification failed: {0}")]
    Manifest(String),

    /// Trust anchor problem (missing, misconfigured, bad permissions).
    #[error("trust anchor: {0}")]
    Anchor(String),

    /// Scoped agent key rejected (bad signature, expired, out of scope).
    #[error("scope rejected: {0}")]
    Scope(String),

    /// Recovery phrase invalid (bad checksum, wrong word count, unknown word).
    #[error("invalid recovery phrase: {0}")]
    Recovery(String),

    /// Requested key not available to this device (no wrapping for it).
    #[error("no key available: {0}")]
    NoKey(String),

    /// OS keychain access failed (unavailable, locked, or a legacy
    /// plaintext key file was found and refused).
    #[error("keychain: {0}")]
    Keychain(String),

    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Base64 decoding failed.
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),

    /// TOML parsing failed.
    #[error("toml: {0}")]
    Toml(String),
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Toml(e.to_string())
    }
}

impl From<toml::ser::Error> for Error {
    fn from(e: toml::ser::Error) -> Self {
        Error::Toml(e.to_string())
    }
}
