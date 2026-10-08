//! Scoped agent keys (design §7).
//!
//! An agent key is an X25519 keypair plus a scope document signed by the
//! operator key. The CLI checks the scope signature, expiry, client list,
//! types, and capability **before** unwrapping or encrypting for that key.
//!
//! ```toml
//! key_id = "agent-transcriber-01"
//! clients = ["p-01M3…"]   # or ["all"]
//! types = ["deal", "note"]
//! capabilities = ["read"]
//! expires = "2026-11-08"  # YYYY-MM-DD, UTC
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Domain separator for scope signatures.
const SCOPE_DOMAIN: &[u8] = b"confidant-scope-v1";

/// A parsed scope document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub key_id: String,
    /// Client ids (`p-…`), or `["all"]`.
    pub clients: Vec<String>,
    /// Record types/purposes the key may touch.
    pub types: Vec<String>,
    /// `"read"`, `"write"`.
    pub capabilities: Vec<String>,
    /// Expiry as `YYYY-MM-DD` (UTC).
    pub expires: String,
}

/// Capability required for an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Read,
    Write,
}

impl Capability {
    fn as_str(self) -> &'static str {
        match self {
            Capability::Read => "read",
            Capability::Write => "write",
        }
    }
}

fn signing_bytes(toml_bytes: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(SCOPE_DOMAIN.len() + toml_bytes.len());
    b.extend_from_slice(SCOPE_DOMAIN);
    b.extend_from_slice(toml_bytes);
    b
}

/// Serialize a scope to canonical TOML.
pub fn to_toml(scope: &Scope) -> Result<Vec<u8>, Error> {
    Ok(toml::to_string(scope)?.into_bytes())
}

/// Sign a scope document with the operator key.
pub fn sign(operator_sk: &SigningKey, scope: &Scope) -> Result<Vec<u8>, Error> {
    let toml = to_toml(scope)?;
    Ok(operator_sk.sign(&signing_bytes(&toml)).to_bytes().to_vec())
}

/// Verify a scope and authorize one operation.
///
/// Checks, in order: signature against the operator key, expiry (against
/// `today_ymd`, `YYYY-MM-DD` UTC), client membership, type membership, and
/// capability. Any failure → [`Error::Scope`]; the caller must refuse before
/// any crypto.
pub fn authorize(
    operator_pk: &VerifyingKey,
    scope_toml: &[u8],
    sig_bytes: &[u8],
    today_ymd: &str,
    client_id: &str,
    record_type: &str,
    capability: Capability,
) -> Result<Scope, Error> {
    if sig_bytes.len() != 64 {
        return Err(Error::Scope("scope signature must be 64 bytes".to_string()));
    }
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| Error::Scope("malformed scope signature".to_string()))?;
    operator_pk
        .verify(&signing_bytes(scope_toml), &sig)
        .map_err(|_| Error::Scope("scope signature does not verify".to_string()))?;
    let text = std::str::from_utf8(scope_toml)
        .map_err(|_| Error::Scope("scope is not UTF-8".to_string()))?;
    let scope: Scope = toml::from_str(text)?;

    if scope.expires.as_str() < today_ymd {
        return Err(Error::Scope(format!(
            "scope {} expired on {}",
            scope.key_id, scope.expires
        )));
    }
    if !scope.clients.iter().any(|c| c == "all" || c == client_id) {
        return Err(Error::Scope(format!(
            "scope {} does not cover client {client_id}",
            scope.key_id
        )));
    }
    if !scope.types.iter().any(|t| t == record_type) {
        return Err(Error::Scope(format!(
            "scope {} does not cover type {record_type}",
            scope.key_id
        )));
    }
    if !scope.capabilities.iter().any(|c| c == capability.as_str()) {
        return Err(Error::Scope(format!(
            "scope {} lacks {:?} capability",
            scope.key_id, capability
        )));
    }
    Ok(scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sample() -> Scope {
        Scope {
            key_id: "agent-transcriber-01".to_string(),
            clients: vec!["p-01ABC".to_string()],
            types: vec!["deal".to_string(), "note".to_string()],
            capabilities: vec!["read".to_string()],
            expires: "2026-11-08".to_string(),
        }
    }

    fn signed() -> (VerifyingKey, Vec<u8>, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(&sample()).unwrap();
        let sig = sign(&sk, &sample()).unwrap();
        (sk.verifying_key(), toml, sig)
    }

    #[test]
    fn happy_path() {
        let (pk, toml, sig) = signed();
        let s = authorize(
            &pk,
            &toml,
            &sig,
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Read,
        )
        .unwrap();
        assert_eq!(s.key_id, "agent-transcriber-01");
    }

    #[test]
    fn expired() {
        let (pk, toml, sig) = signed();
        assert!(authorize(
            &pk,
            &toml,
            &sig,
            "2026-11-09",
            "p-01ABC",
            "deal",
            Capability::Read
        )
        .is_err());
    }

    #[test]
    fn wrong_client() {
        let (pk, toml, sig) = signed();
        assert!(authorize(
            &pk,
            &toml,
            &sig,
            "2026-10-08",
            "p-OTHER",
            "deal",
            Capability::Read
        )
        .is_err());
    }

    #[test]
    fn wrong_type() {
        let (pk, toml, sig) = signed();
        assert!(authorize(
            &pk,
            &toml,
            &sig,
            "2026-10-08",
            "p-01ABC",
            "person",
            Capability::Read
        )
        .is_err());
    }

    #[test]
    fn write_with_read_only() {
        let (pk, toml, sig) = signed();
        assert!(authorize(
            &pk,
            &toml,
            &sig,
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Write
        )
        .is_err());
    }

    #[test]
    fn tampered_scope_fails() {
        let (pk, toml, sig) = signed();
        let mut bad = toml.clone();
        bad.extend_from_slice(b"\n");
        assert!(authorize(
            &pk,
            &bad,
            &sig,
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Read
        )
        .is_err());
    }
}
