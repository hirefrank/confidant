//! Inbox age key loading and decryption (OS keychain / env).

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::DomainError;

/// Inbox decryption key material, loaded once per run.
///
/// Holds the current inbox identity and, during the rotation window
/// (§8a.3), the previous one. Decryption tries current then previous
/// ("tries old then new"); the #55 pubkey comparison uses the current key
/// only, since the vault advertises the new key after `rotate`.
pub struct InboxKeys {
    current: age::x25519::Identity,
    previous: Option<age::x25519::Identity>,
}

impl InboxKeys {
    /// Load both slots from the OS keychain (or `CONFIDANT_INBOX_KEY` /
    /// `CONFIDANT_INBOX_KEY_PREVIOUS` on headless hosts — see
    /// `confidant_crypt::keychain`). Fails closed with `E_INBOX_CRYPTO`:
    /// a missing key, a bad key, or an undecryptable identity is an error,
    /// never silent plaintext.
    pub fn load() -> anyhow::Result<Self> {
        let (current, previous) = confidant_crypt::keychain::inbox_identities()
            .map_err(|e| anyhow::Error::new(DomainError::inbox_crypto(format!("{e}"))))?;
        Ok(Self { current, previous })
    }

    /// Load, returning `None` when no key is enrolled (genuine `NoKey`).
    /// A legacy-file refusal or keychain error surfaces directly — it is
    /// not skipped, so it cannot resurface later as a generic decrypt
    /// failure.
    pub fn load_opt() -> anyhow::Result<Option<Self>> {
        match confidant_crypt::keychain::inbox_identities() {
            Ok((current, previous)) => Ok(Some(Self { current, previous })),
            Err(confidant_crypt::Error::NoKey(_)) => Ok(None),
            Err(e) => Err(anyhow::Error::new(DomainError::inbox_crypto(format!(
                "{e}"
            )))),
        }
    }

    /// Backend-parameterized [`InboxKeys::load_opt`]: load from an injected
    /// keychain backend (tests) instead of the OS keychain.
    pub fn load_opt_with(
        backend: &dyn confidant_crypt::keychain::KeychainBackend,
        config_dir: Option<&Path>,
    ) -> anyhow::Result<Option<Self>> {
        match confidant_crypt::keychain::inbox_identities_with(backend, config_dir) {
            Ok((current, previous)) => Ok(Some(Self { current, previous })),
            Err(confidant_crypt::Error::NoKey(_)) => Ok(None),
            Err(e) => Err(anyhow::Error::new(DomainError::inbox_crypto(format!(
                "{e}"
            )))),
        }
    }

    /// True while the previous slot is occupied (the rotation window,
    /// §8a.3): old-key items still decrypt, `--finish` is pending.
    pub fn has_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// Decrypt with the current key, falling back to the previous one
    /// during the rotation window. Fails closed with `E_INBOX_CRYPTO`.
    ///
    /// Returns [`Zeroizing<Vec<u8>>`] so the decrypted item payload wipes
    /// itself on drop (#135) — never a bare `Vec<u8>`.
    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        match confidant_crypt::age_wrap::unwrap_with_identity(ciphertext, &self.current) {
            Ok(plaintext) => Ok(plaintext),
            Err(first) => {
                if let Some(previous) = &self.previous {
                    if let Ok(plaintext) =
                        confidant_crypt::age_wrap::unwrap_with_identity(ciphertext, previous)
                    {
                        return Ok(plaintext);
                    }
                }
                Err(anyhow::Error::new(DomainError::inbox_crypto(format!(
                    "{first}"
                ))))
            }
        }
    }

    /// The current key's age recipient, for the #55 comparison against the
    /// vault's advertised `[inbox].pubkey`.
    pub fn current_recipient(&self) -> String {
        self.current.to_public().to_string()
    }
}

/// The old load-per-call decryptor. Test-only: production code loads
/// [`InboxKeys`] once and closes over it, so the N+1 key-loading path
/// can't get wired back in outside tests.
#[cfg(test)]
pub fn inbox_decrypt(ciphertext: &[u8]) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let keys = InboxKeys::load()?;
    keys.decrypt(ciphertext)
}
