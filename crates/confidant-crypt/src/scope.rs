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
//!
//! The signed bytes bind the vault id, so a scope minted for one vault
//! cannot be replayed in another:
//! `b"confidant-scope-v1" ‖ le64(len(vault_id)) ‖ vault_id ‖ scope_toml`.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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

fn signing_bytes(vault_id: &str, toml_bytes: &[u8]) -> Vec<u8> {
    // Length-prefix the vault id like the §4 key commitment, so the
    // boundary between vault_id and the TOML is unambiguous.
    let mut b = Vec::with_capacity(SCOPE_DOMAIN.len() + 8 + vault_id.len() + toml_bytes.len());
    b.extend_from_slice(SCOPE_DOMAIN);
    b.extend_from_slice(&(vault_id.len() as u64).to_le_bytes());
    b.extend_from_slice(vault_id.as_bytes());
    b.extend_from_slice(toml_bytes);
    b
}

/// Parse `YYYY-MM-DD` strictly: exactly ten chars, digits in the right
/// places, and a real calendar date (leap years counted). Anything else
/// is an error — expiry comparison must never treat a malformed date as
/// "far future".
fn parse_date(s: &str) -> Result<(u32, u32, u32), Error> {
    let b = s.as_bytes();
    let all_digits = |r: std::ops::Range<usize>| b[r].iter().all(|c| c.is_ascii_digit());
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !all_digits(0..4)
        || !all_digits(5..7)
        || !all_digits(8..10)
    {
        return Err(Error::Scope(format!("date is not YYYY-MM-DD: {s}")));
    }
    // Bounds above guarantee these parses succeed.
    let y: u32 = s[0..4].parse().unwrap();
    let m: u32 = s[5..7].parse().unwrap();
    let d: u32 = s[8..10].parse().unwrap();
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => {
            return Err(Error::Scope(format!(
                "date is not a real calendar date: {s}"
            )))
        }
    };
    if d == 0 || d > dim {
        return Err(Error::Scope(format!(
            "date is not a real calendar date: {s}"
        )));
    }
    Ok((y, m, d))
}

/// Serialize a scope to canonical TOML.
pub fn to_toml(scope: &Scope) -> Result<Vec<u8>, Error> {
    Ok(toml::to_string(scope)?.into_bytes())
}

/// Sign a scope document with the operator key, binding `vault_id` into
/// the signed bytes.
pub fn sign(operator_sk: &SigningKey, vault_id: &str, scope: &Scope) -> Result<Vec<u8>, Error> {
    let toml = to_toml(scope)?;
    Ok(operator_sk
        .sign(&signing_bytes(vault_id, &toml))
        .to_bytes()
        .to_vec())
}

/// Verify a scope and authorize one operation.
///
/// Checks, in order: signature against the operator key with
/// [`VerifyingKey::verify_strict`] over the vault-bound bytes, the
/// scope's `key_id` against the identity in use, expiry (both dates
/// parsed strictly as `YYYY-MM-DD` UTC), client membership, type
/// membership, and capability. Any failure → [`Error::Scope`]; the caller
/// must refuse before any crypto.
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    operator_pk: &VerifyingKey,
    vault_id: &str,
    expected_key_id: &str,
    scope_toml: &[u8],
    sig_bytes: &[u8],
    today_ymd: &str,
    client_id: &str,
    record_type: &str,
    capability: Capability,
) -> Result<Scope, Error> {
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Scope("scope signature must be 64 bytes".to_string()))?;
    // verify_strict rejects malleable/non-canonical signatures that plain
    // verify would accept.
    let sig = ed25519_dalek::ed25519::Signature::from_bytes(&sig_arr);
    operator_pk
        .verify_strict(&signing_bytes(vault_id, scope_toml), &sig)
        .map_err(|_| Error::Scope("scope signature does not verify".to_string()))?;
    let text = std::str::from_utf8(scope_toml)
        .map_err(|_| Error::Scope("scope is not UTF-8".to_string()))?;
    let scope: Scope = toml::from_str(text)?;

    // The scope must name the identity actually in use: a valid scope for
    // another agent key must not authorize this one.
    if scope.key_id != expected_key_id {
        return Err(Error::Scope(format!(
            "scope is for key {}, not the identity in use ({expected_key_id})",
            scope.key_id
        )));
    }
    let today = parse_date(today_ymd)
        .map_err(|_| Error::Scope(format!("today is not YYYY-MM-DD: {today_ymd}")))?;
    let expires = parse_date(&scope.expires)?;
    if today > expires {
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

    const VAULT: &str = "vault-01";
    const KEY_ID: &str = "agent-transcriber-01";

    fn sample() -> Scope {
        Scope {
            key_id: KEY_ID.to_string(),
            clients: vec!["p-01ABC".to_string()],
            types: vec!["deal".to_string(), "note".to_string()],
            capabilities: vec!["read".to_string()],
            expires: "2026-11-08".to_string(),
        }
    }

    fn signed_for(scope: &Scope, vault_id: &str) -> (VerifyingKey, Vec<u8>, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(scope).unwrap();
        let sig = sign(&sk, vault_id, scope).unwrap();
        (sk.verifying_key(), toml, sig)
    }

    fn signed() -> (VerifyingKey, Vec<u8>, Vec<u8>) {
        signed_for(&sample(), VAULT)
    }

    #[allow(clippy::too_many_arguments)]
    fn auth(
        pk: &VerifyingKey,
        toml: &[u8],
        sig: &[u8],
        key_id: &str,
        today: &str,
        client: &str,
        rtype: &str,
        cap: Capability,
    ) -> Result<Scope, Error> {
        authorize(pk, VAULT, key_id, toml, sig, today, client, rtype, cap)
    }

    #[test]
    fn happy_path() {
        let (pk, toml, sig) = signed();
        let s = auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
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
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
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
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
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
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
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
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
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
        assert!(auth(
            &pk,
            &bad,
            &sig,
            KEY_ID,
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Read
        )
        .is_err());
    }

    #[test]
    fn key_id_must_match_identity_in_use() {
        // A valid scope for another agent key must not authorize this one.
        let (pk, toml, sig) = signed();
        let err = auth(
            &pk,
            &toml,
            &sig,
            "agent-other-99",
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not the identity in use"));
    }

    #[test]
    fn wrong_vault_id_fails_signature() {
        // A scope minted for vault-a does not verify in vault-b.
        let (pk, toml, sig) = signed_for(&sample(), "vault-a");
        let err = authorize(
            &pk,
            "vault-b",
            KEY_ID,
            &toml,
            &sig,
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("does not verify"));
    }

    #[test]
    fn malformed_expires_refused() {
        // The old string comparison treated "never" as unexpired (fail-open).
        for bad in [
            "never",
            "9999",
            "2026-13-01",
            "2026-02-30",
            "2026-1-8",
            "26-11-08",
            "",
            "2026-11-08 ",
            "2026-11-08T00:00:00Z",
        ] {
            let mut scope = sample();
            scope.expires = bad.to_string();
            let (pk, toml, sig) = signed_for(&scope, VAULT);
            let err = auth(
                &pk,
                &toml,
                &sig,
                KEY_ID,
                "2026-10-08",
                "p-01ABC",
                "deal",
                Capability::Read,
            )
            .unwrap_err();
            assert!(
                format!("{err}").contains("YYYY-MM-DD")
                    || format!("{err}").contains("calendar date"),
                "expires={bad:?}: {err}"
            );
        }
    }

    #[test]
    fn malformed_today_refused() {
        let (pk, toml, sig) = signed();
        let err = auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
            "yesterday",
            "p-01ABC",
            "deal",
            Capability::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("YYYY-MM-DD"));
    }

    #[test]
    fn expiry_boundary() {
        // Valid through the expiry date itself; expired the day after.
        // 2024 is a leap year: Feb 29 is real, Feb 30 is not.
        let mut scope = sample();
        scope.expires = "2024-02-29".to_string();
        let (pk, toml, sig) = signed_for(&scope, VAULT);
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
            "2024-02-29",
            "p-01ABC",
            "deal",
            Capability::Read
        )
        .is_ok());
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
            "2024-03-01",
            "p-01ABC",
            "deal",
            Capability::Read
        )
        .is_err());

        let mut scope = sample();
        scope.expires = "2023-02-29".to_string(); // 2023 is not a leap year
        let (pk, toml, sig) = signed_for(&scope, VAULT);
        assert!(auth(
            &pk,
            &toml,
            &sig,
            KEY_ID,
            "2023-01-01",
            "p-01ABC",
            "deal",
            Capability::Read
        )
        .is_err());
    }

    #[test]
    fn short_signature_refused() {
        let (pk, toml, sig) = signed();
        let err = auth(
            &pk,
            &toml,
            &sig[..32],
            KEY_ID,
            "2026-10-08",
            "p-01ABC",
            "deal",
            Capability::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("64 bytes"));
    }
}
