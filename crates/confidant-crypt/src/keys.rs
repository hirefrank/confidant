//! Key generation: per-client data keys, device X25519 keypairs, and the
//! vault alias-lookup key. All 256-bit, drawn from the OS RNG.

use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::age_wrap::bech32_encode;

/// A 256-bit per-client data key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; 32]);

impl DataKey {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        DataKey(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild from unwrapped bytes (crate-internal; callers must have
    /// verified the manifest first).
    pub(crate) fn from_bytes(b: [u8; 32]) -> Self {
        DataKey(b)
    }
}

/// A device (or agent) X25519 keypair.
///
/// The secret half is held in the OS keychain / agent secret store on
/// trusted devices only and never leaves the device. The public half is an
/// `age1…` recipient string for manifests.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceKeypair {
    secret: [u8; 32],
}

impl DeviceKeypair {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        // Clamp like X25519 requires.
        b[0] &= 248;
        b[31] &= 127;
        b[31] |= 64;
        DeviceKeypair { secret: b }
    }

    /// `age1…` recipient string for this keypair.
    pub fn recipient(&self) -> String {
        let pk = PublicKey::from(&StaticSecret::from(self.secret));
        bech32_encode("age", pk.as_bytes())
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// The vault alias-lookup key (256-bit HMAC key, one per vault).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LookupKey([u8; 32]);

impl LookupKey {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        LookupKey(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild from unwrapped bytes (crate-internal).
    pub(crate) fn from_bytes(b: [u8; 32]) -> Self {
        LookupKey(b)
    }
}
