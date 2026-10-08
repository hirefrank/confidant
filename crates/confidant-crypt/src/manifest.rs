//! Signed recipient manifests (`recipients.toml` + `recipients.sig`).
//!
//! A manifest lists the age recipients a data key is wrapped to. It is only
//! honored if `recipients.sig` verifies against the trust anchor (the
//! operator's Ed25519 public key, kept off-vault). A compromised git remote
//! cannot add an attacker's recipient: the CLI refuses manifests that do
//! not verify.
//!
//! Signed payload: `b"confidant-manifest-v1" ‖ le64(epoch) ‖ toml_bytes`.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Domain separator for manifest signatures.
const MANIFEST_DOMAIN: &[u8] = b"confidant-manifest-v1";

/// One recipient entry in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientEntry {
    /// `age1…` public key.
    pub age_pubkey: String,
    /// Human label (opaque; no PII).
    pub label: String,
    /// Reference to the scope document for agent keys (empty for devices).
    #[serde(default)]
    pub scope_ref: String,
}

/// The parsed recipient list: key id -> entry.
pub type RecipientMap = BTreeMap<String, RecipientEntry>;

/// Serialize a recipient map to canonical TOML.
pub fn to_toml(map: &RecipientMap) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct Doc<'a> {
        recipients: &'a RecipientMap,
    }
    let s = toml::to_string(&Doc { recipients: map })?;
    Ok(s.into_bytes())
}

/// Parse a recipient map from TOML.
pub fn from_toml(bytes: &[u8]) -> Result<RecipientMap, Error> {
    #[derive(Deserialize)]
    struct Doc {
        recipients: RecipientMap,
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Manifest("recipients.toml is not UTF-8".to_string()))?;
    let doc: Doc = toml::from_str(text)?;
    Ok(doc.recipients)
}

/// Bytes actually signed: domain ‖ le64(epoch) ‖ toml.
fn signing_bytes(epoch: u64, toml_bytes: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(MANIFEST_DOMAIN.len() + 8 + toml_bytes.len());
    b.extend_from_slice(MANIFEST_DOMAIN);
    b.extend_from_slice(&epoch.to_le_bytes());
    b.extend_from_slice(toml_bytes);
    b
}

/// Sign a manifest with the operator key.
pub fn sign(operator_sk: &SigningKey, epoch: u64, toml_bytes: &[u8]) -> Vec<u8> {
    operator_sk
        .sign(&signing_bytes(epoch, toml_bytes))
        .to_bytes()
        .to_vec()
}

/// Verify a manifest against the operator's public key.
///
/// Returns the parsed recipient map on success. Unknown signer, missing or
/// tampered signature, or a tampered list → [`Error::Manifest`]; the caller
/// must refuse decryption.
pub fn verify(
    operator_pk: &VerifyingKey,
    epoch: u64,
    toml_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<RecipientMap, Error> {
    if sig_bytes.len() != 64 {
        return Err(Error::Manifest("signature must be 64 bytes".to_string()));
    }
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| Error::Manifest("malformed signature".to_string()))?;
    operator_pk
        .verify(&signing_bytes(epoch, toml_bytes), &sig)
        .map_err(|_| Error::Manifest("signature does not verify".to_string()))?;
    from_toml(toml_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sample() -> RecipientMap {
        let mut m = RecipientMap::new();
        m.insert(
            "device-laptop".to_string(),
            RecipientEntry {
                age_pubkey: "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0"
                    .to_string(),
                label: "laptop".to_string(),
                scope_ref: String::new(),
            },
        );
        m
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(&sample()).unwrap();
        let sig = sign(&sk, 3, &toml);
        let back = verify(&sk.verifying_key(), 3, &toml, &sig).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn tampered_list_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut toml = to_toml(&sample()).unwrap();
        let sig = sign(&sk, 3, &toml);
        toml.extend_from_slice(b"# evil");
        assert!(verify(&sk.verifying_key(), 3, &toml, &sig).is_err());
    }

    #[test]
    fn wrong_signer_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let toml = to_toml(&sample()).unwrap();
        let sig = sign(&sk, 3, &toml);
        assert!(verify(&other.verifying_key(), 3, &toml, &sig).is_err());
    }

    #[test]
    fn wrong_epoch_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(&sample()).unwrap();
        let sig = sign(&sk, 3, &toml);
        assert!(verify(&sk.verifying_key(), 4, &toml, &sig).is_err());
    }
}
