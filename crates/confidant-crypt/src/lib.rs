//! Encryption crate for Confidant.
//!
//! Milestone 1 ships this crate as a **stub**. Architecture section 9b requires
//! an independent crypto design review before any milestone 2 encryption code
//! is written. Do not add age, AEAD, or key-wrapping implementations here
//! until that review happens.
//!
//! The functions below exist so the workspace layout matches the architecture
//! (`crates/confidant-crypt`) and so callers fail closed instead of silently
//! writing plaintext under an "encrypted" API.

#![forbid(unsafe_code)]

use std::fmt;

/// Returned by every crypto operation until milestone 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotImplemented;

impl fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("confidant-crypt is a stub until the milestone 2 crypto design review")
    }
}

impl std::error::Error for NotImplemented {}

/// True when this build can encrypt or decrypt vault content.
pub fn is_available() -> bool {
    false
}

/// Encrypt a content file. Always fails in milestone 1.
pub fn encrypt_file(_plaintext: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    Err(NotImplemented)
}

/// Decrypt a content file. Always fails in milestone 1.
pub fn decrypt_file(_ciphertext: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    Err(NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::{decrypt_file, encrypt_file, is_available};

    #[test]
    fn stub_refuses_crypto() {
        assert!(!is_available());
        assert!(encrypt_file(b"note body").is_err());
        assert!(decrypt_file(b"not-ciphertext").is_err());
    }
}
