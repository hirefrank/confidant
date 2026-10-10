//! Signed recipient manifests (`recipients.toml` + `recipients.sig`).
//!
//! A manifest lists the age recipients a data key is wrapped to. It is only
//! honored if `recipients.sig` verifies against the trust anchor (the
//! operator's Ed25519 public key, kept off-vault). A compromised git remote
//! cannot add an attacker's recipient: the CLI refuses manifests that do
//! not verify.
//!
//! Signed payload: `b"confidant-manifest-v2" ‖ le64(len(vault_id)) ‖
//! vault_id ‖ le64(len(client_id)) ‖ client_id ‖ le64(epoch) ‖ le64(seq) ‖
//! toml_bytes`. Binding the vault id and client id stops a signed manifest
//! from client A being transplanted into client B's directory (or another
//! vault). The `seq` is bumped on every manifest write; verifiers refuse a
//! seq below the off-vault high-water mark, so a restored pre-revocation
//! manifest (same epoch, valid signature, stale seq) does not verify.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::Error;

/// Domain separator for manifest signatures.
const MANIFEST_DOMAIN: &[u8] = b"confidant-manifest-v2";

/// Domain separator for the key-commitment HMAC (design §4).
const COMMIT_DOMAIN: &[u8] = b"confidant-key-commit-v1";

/// Fixed client id for the vault-level lookup-key manifest (`keys/vault/`).
pub const VAULT_CLIENT_ID: &str = "vault:lookup";

/// Key id reserved for the recovery wrapping (`recovery.age`); it is never
/// a manifest recipient entry.
pub const RECOVERY_KEY_ID: &str = "recovery";

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

/// Validate a recipient key id.
///
/// Key ids end up in file names (`<key-id>.age`), so they are restricted
/// to `[a-z0-9-]` — no `.` (which would confuse the `.e<epoch>` retained-
/// epoch suffix), no `/` or `..` (path traversal). `recovery` is reserved
/// for the recovery wrapping and is never a manifest entry: accepting it
/// would let `revoke(&["recovery"])` silently delete every recovery
/// wrapping, or a recipient named `recovery` overwrite `recovery.age`.
pub fn validate_key_id(key_id: &str) -> Result<(), Error> {
    if key_id.is_empty() {
        return Err(Error::Manifest("empty key id".to_string()));
    }
    if key_id == RECOVERY_KEY_ID {
        return Err(Error::Manifest(format!(
            "key id {key_id:?} is reserved for the recovery wrapping"
        )));
    }
    if !key_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::Manifest(format!(
            "key id {key_id:?} must match [a-z0-9-]+"
        )));
    }
    Ok(())
}

/// Key commitment: binds a data key to its (vault, client, epoch) so a
/// planted `.age` wrapping can't substitute an attacker-known key.
///
/// `HMAC-SHA256(data_key, "confidant-key-commit-v1" ‖ len(vault_id) ‖
/// vault_id ‖ len(client_id) ‖ client_id ‖ le64(epoch))`. The manifest
/// carries one commitment per retained epoch; after every unwrap the
/// caller recomputes it and compares in constant time.
pub fn key_commitment(
    data_key: &[u8; 32],
    vault_id: &str,
    client_id: &str,
    epoch: u64,
) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(data_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(COMMIT_DOMAIN);
    mac.update(&(vault_id.len() as u64).to_le_bytes());
    mac.update(vault_id.as_bytes());
    mac.update(&(client_id.len() as u64).to_le_bytes());
    mac.update(client_id.as_bytes());
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// Constant-time equality for commitment comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Hex-encode bytes (avoids a `hex` dependency).
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Hex-decode (for commitment comparison).
pub fn decode_hex(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    if !s.is_ascii() {
        return Err(Error::Manifest("non-ASCII hex commitment".to_string()));
    }
    if s.len() % 2 != 0 {
        return Err(Error::Manifest("odd-length hex commitment".to_string()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::Manifest("invalid hex commitment".to_string()))
        })
        .collect()
}

/// One key commitment entry in the manifest: epoch → hex HMAC.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitmentEntry {
    pub epoch: u64,
    /// Hex-encoded `key_commitment` output.
    pub commitment: String,
}

/// The manifest document: sequence number, recipient list, and one key
/// commitment per retained epoch.
#[derive(Serialize)]
struct Doc<'a> {
    seq: u64,
    recipients: &'a RecipientMap,
    commitments: &'a [CommitmentEntry],
}

#[derive(Deserialize)]
struct OwnedDoc {
    seq: u64,
    recipients: RecipientMap,
    #[serde(default)]
    commitments: Vec<CommitmentEntry>,
}

/// Serialize a recipient map to canonical TOML with the given sequence
/// number and key commitments. Key ids are validated here (write path).
pub fn to_toml(
    seq: u64,
    map: &RecipientMap,
    commitments: &[CommitmentEntry],
) -> Result<Vec<u8>, Error> {
    for key_id in map.keys() {
        validate_key_id(key_id)?;
    }
    let s = toml::to_string(&Doc {
        seq,
        recipients: map,
        commitments,
    })?;
    Ok(s.into_bytes())
}

/// Parse a recipient map, its sequence number, and its key commitments
/// from TOML. Key ids are validated here too (read path): a manifest from
/// git history with a bad key id is refused rather than trusted.
pub fn from_toml(bytes: &[u8]) -> Result<(u64, RecipientMap, Vec<CommitmentEntry>), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Manifest("recipients.toml is not UTF-8".to_string()))?;
    let doc: OwnedDoc = toml::from_str(text)?;
    for key_id in doc.recipients.keys() {
        validate_key_id(key_id)?;
    }
    Ok((doc.seq, doc.recipients, doc.commitments))
}

fn le64_len(s: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Bytes actually signed: domain ‖ le64(len(vault_id)) ‖ vault_id ‖
/// le64(len(client_id)) ‖ client_id ‖ le64(epoch) ‖ le64(seq) ‖ toml.
fn signing_bytes(
    vault_id: &str,
    client_id: &str,
    epoch: u64,
    seq: u64,
    toml_bytes: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(MANIFEST_DOMAIN);
    le64_len(vault_id, &mut b);
    le64_len(client_id, &mut b);
    b.extend_from_slice(&epoch.to_le_bytes());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(toml_bytes);
    b
}

/// Sign a manifest with the operator key (or the recovery key — both are
/// trust-anchor members, design §4).
pub fn sign(
    sk: &SigningKey,
    vault_id: &str,
    client_id: &str,
    epoch: u64,
    seq: u64,
    toml_bytes: &[u8],
) -> Vec<u8> {
    sk.sign(&signing_bytes(vault_id, client_id, epoch, seq, toml_bytes))
        .to_bytes()
        .to_vec()
}

/// Verify a manifest against one trust-anchor public key.
///
/// `min_seq` is the off-vault high-water mark for this (vault_id,
/// client_id): a manifest whose seq is lower is refused even if the
/// signature verifies (revocation-replay defense). Returns the parsed
/// recipient map on success. Unknown signer, missing or tampered signature,
/// tampered list, transplanted manifest (wrong vault/client binding), or
/// stale seq → [`Error::Manifest`]; the caller must refuse decryption.
pub fn verify(
    pk: &VerifyingKey,
    vault_id: &str,
    client_id: &str,
    epoch: u64,
    toml_bytes: &[u8],
    sig_bytes: &[u8],
    min_seq: u64,
) -> Result<RecipientMap, Error> {
    if sig_bytes.len() != 64 {
        return Err(Error::Manifest("signature must be 64 bytes".to_string()));
    }
    let (seq, _, _) = from_toml(toml_bytes)?;
    if seq < min_seq {
        return Err(Error::Manifest(format!(
            "manifest seq {seq} is below the high-water mark {min_seq}; refusing stale manifest"
        )));
    }
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| Error::Manifest("malformed signature".to_string()))?;
    pk.verify(
        &signing_bytes(vault_id, client_id, epoch, seq, toml_bytes),
        &sig,
    )
    .map_err(|_| Error::Manifest("signature does not verify".to_string()))?;
    Ok(from_toml(toml_bytes)?.1)
}

/// Off-vault high-water marks for manifest sequence numbers.
///
/// Kept next to `trust.toml` (e.g. `~/.config/confidant/manifest-seq.toml`).
/// A restored pre-revocation manifest carries a valid signature at the same
/// epoch but a stale seq; refusing `seq < high_water` closes the replay.
#[derive(Debug, Default)]
pub struct SeqTracker {
    path: PathBuf,
    marks: BTreeMap<(String, String), u64>,
}

impl SeqTracker {
    /// Load from `path`; missing file means no marks yet.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let marks = match std::fs::read_to_string(path) {
            Ok(text) => {
                let doc: BTreeMap<String, BTreeMap<String, u64>> = toml::from_str(&text)
                    .map_err(|e| Error::Manifest(format!("bad seq tracker file: {e}")))?;
                doc.into_iter()
                    .flat_map(|(vault, inner)| {
                        inner
                            .into_iter()
                            .map(move |(client, seq)| ((vault.clone(), client), seq))
                    })
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(SeqTracker {
            path: path.to_path_buf(),
            marks,
        })
    }

    /// High-water mark for (vault_id, client_id); 0 if never seen.
    pub fn high_water(&self, vault_id: &str, client_id: &str) -> u64 {
        self.marks
            .get(&(vault_id.to_string(), client_id.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Advance the mark (persists). Only moves forward.
    pub fn advance(&mut self, vault_id: &str, client_id: &str, seq: u64) -> Result<(), Error> {
        let key = (vault_id.to_string(), client_id.to_string());
        if seq > self.high_water(vault_id, client_id) {
            self.marks.insert(key, seq);
            self.persist()?;
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), Error> {
        let mut doc: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for ((vault, client), seq) in &self.marks {
            doc.entry(vault.clone())
                .or_default()
                .insert(client.clone(), *seq);
        }
        let text = toml::to_string(&doc).map_err(|e| Error::Toml(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, text)?;
        Ok(())
    }
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
        let toml = to_toml(1, &sample(), &[]).unwrap();
        let sig = sign(&sk, "vault-01", "p-01ABC", 3, 1, &toml);
        let back = verify(
            &sk.verifying_key(),
            "vault-01",
            "p-01ABC",
            3,
            &toml,
            &sig,
            0,
        )
        .unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn tampered_list_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut toml = to_toml(1, &sample(), &[]).unwrap();
        let sig = sign(&sk, "vault-01", "p-01ABC", 3, 1, &toml);
        toml.extend_from_slice(b"# evil");
        assert!(verify(
            &sk.verifying_key(),
            "vault-01",
            "p-01ABC",
            3,
            &toml,
            &sig,
            0
        )
        .is_err());
    }

    #[test]
    fn wrong_signer_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let toml = to_toml(1, &sample(), &[]).unwrap();
        let sig = sign(&sk, "vault-01", "p-01ABC", 3, 1, &toml);
        assert!(verify(
            &other.verifying_key(),
            "vault-01",
            "p-01ABC",
            3,
            &toml,
            &sig,
            0
        )
        .is_err());
    }

    #[test]
    fn wrong_epoch_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(1, &sample(), &[]).unwrap();
        let sig = sign(&sk, "vault-01", "p-01ABC", 3, 1, &toml);
        assert!(verify(
            &sk.verifying_key(),
            "vault-01",
            "p-01ABC",
            4,
            &toml,
            &sig,
            0
        )
        .is_err());
    }

    #[test]
    fn transplanted_manifest_is_hard_error() {
        // A signed recipients.toml + .sig from client A must not verify in
        // client B's directory (same epoch) — otherwise the next rotate for
        // B wraps B's key to A's recipients.
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(1, &sample(), &[]).unwrap();
        let sig = sign(&sk, "vault-01", "p-01AAA", 3, 1, &toml);
        let err = verify(
            &sk.verifying_key(),
            "vault-01",
            "p-01BBB",
            3,
            &toml,
            &sig,
            0,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("does not verify"), "{err}");
        // Same for a cross-vault transplant.
        let err = verify(
            &sk.verifying_key(),
            "vault-02",
            "p-01AAA",
            3,
            &toml,
            &sig,
            0,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("does not verify"), "{err}");
    }

    #[test]
    fn stale_seq_refused() {
        // A restored pre-revocation manifest: valid signature, same epoch,
        // but seq below the high-water mark.
        let sk = SigningKey::generate(&mut OsRng);
        let toml = to_toml(1, &sample(), &[]).unwrap();
        let sig = sign(&sk, "vault-01", "p-01ABC", 3, 1, &toml);
        let err = verify(
            &sk.verifying_key(),
            "vault-01",
            "p-01ABC",
            3,
            &toml,
            &sig,
            2,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("below the high-water mark"),
            "{err}"
        );
    }

    #[test]
    fn seq_tracker_advances_and_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("manifest-seq.toml");
        let mut t = SeqTracker::load(&path).unwrap();
        assert_eq!(t.high_water("v1", "p-A"), 0);
        t.advance("v1", "p-A", 3).unwrap();
        assert_eq!(t.high_water("v1", "p-A"), 3);
        // Never moves backward.
        t.advance("v1", "p-A", 2).unwrap();
        assert_eq!(t.high_water("v1", "p-A"), 3);
        // Reloads from disk.
        let t2 = SeqTracker::load(&path).unwrap();
        assert_eq!(t2.high_water("v1", "p-A"), 3);
        assert_eq!(t2.high_water("v1", "p-B"), 0);
    }

    #[test]
    fn decode_hex_rejects_non_ascii() {
        // "é01" is 4 bytes (even length) but byte 2 splits the 'é':
        // without the is_ascii() guard this panicked in the slice.
        let err = decode_hex("é01").unwrap_err();
        assert!(format!("{err}").contains("non-ASCII"), "{err}");
        // Sanity: valid hex still decodes.
        assert_eq!(decode_hex("00ff").unwrap(), vec![0x00, 0xff]);
    }
}
