//! Rollback/replay defense (design §5).
//!
//! Binding the header stops a flipped flag, but not a restored older file:
//! someone with git write access can restore an older version of the same
//! file (`git checkout <old> -- <file>`), and that old file still has a
//! valid AAD — possibly saying `no-ai: false` from before the client opted
//! out.
//!
//! Defense in depth: `find` and `context` produce agent output only from
//! history whose commits verify against the trust anchor (design §4,
//! ADR-10). The tip commit and the commits that introduced each emitted
//! file's current content must verify; content introduced by an unsigned
//! commit — an unsigned rollback included — is refused with a hard error
//! and withheld from agent output.
//!
//! Signer identity is the full key fingerprint (`git log --format=%GF`),
//! pinned against the anchor's keys. The 16-character key id (`%GK`) is
//! deliberately not used: short key ids are collidable, so matching on
//! them would let an attacker mint a key with a colliding id.

use std::path::Path;
use std::process::Command;

use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::anchor::Anchor;
use crate::error::Error;

/// Compute the OpenSSH `SHA256:` fingerprint of an Ed25519 public key.
///
/// This is exactly what `git log --format=%GF` reports for SSH-signed
/// commits, so comparing it pins the full key. The anchor's keys are
/// Ed25519 and commit signing uses the SSH format, which makes this
/// derivation exact with no extra pinned material.
pub fn ssh_fingerprint(key: &VerifyingKey) -> String {
    // OpenSSH wire format: string "ssh-ed25519" || string <32-byte key>,
    // each string length-prefixed with a 4-byte big-endian integer.
    let name = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + name.len() + 4 + 32);
    wire.extend_from_slice(&(name.len() as u32).to_be_bytes());
    wire.extend_from_slice(name);
    wire.extend_from_slice(&32u32.to_be_bytes());
    wire.extend_from_slice(key.as_bytes());
    let digest = Sha256::digest(&wire);
    // OpenSSH strips base64 padding from fingerprints.
    format!(
        "SHA256:{}",
        BASE64_STANDARD.encode(digest).trim_end_matches('=')
    )
}

/// Checks whether a commit carries a signature from a trusted key.
///
/// Production uses [`GitSignerChecker`] (shells out to git); tests inject a
/// fake.
pub trait SignerChecker {
    /// Return the signature validity and signer key fingerprint for
    /// `commit`, or `None` if the commit is unsigned.
    ///
    /// Validity is git's `%G?` status: only `G` (good signature) is
    /// accepted — `%GF` alone is not enough, since git prints a
    /// fingerprint even for bad or uncheckable signatures. The
    /// fingerprint is `%GF` (full), never the 16-char `%GK` key id.
    fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error>;
}

/// `git log --format=%G? --format=%GF` based checker.
pub struct GitSignerChecker {
    vault: std::path::PathBuf,
}

impl GitSignerChecker {
    pub fn new(vault: &Path) -> Self {
        GitSignerChecker {
            vault: vault.to_path_buf(),
        }
    }
}

impl SignerChecker for GitSignerChecker {
    fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error> {
        let out = Command::new("git")
            // Never leak the device key into git/gpg/hooks via the environment.
            .env_remove("CONFIDANT_DEVICE_KEY")
            .args([
                "-C",
                &self.vault.to_string_lossy(),
                "log",
                "-1",
                "--format=%G?%x00%GF",
                "--end-of-options",
                commit,
            ])
            .output()
            .map_err(Error::Io)?;
        if !out.status.success() {
            return Err(Error::Manifest(format!("git log failed for {commit}")));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut parts = text.split('\0');
        let validity = parts.next().unwrap_or("").trim();
        // %GF is the full fingerprint; an empty fingerprint means unsigned.
        let fingerprint = parts.next().unwrap_or("").trim().to_string();
        if fingerprint.is_empty() {
            return Ok(None);
        }
        let v = validity.chars().next().unwrap_or(' ');
        Ok(Some((v, fingerprint)))
    }
}

/// Verify that history is trusted for agent output.
///
/// `anchor` is the off-vault trust anchor (design §4): the operator key
/// plus the recovery Ed25519 key are the trusted commit signers. The
/// signer set is derived from the anchor inside this function — callers
/// never supply it, so a compromised caller cannot widen trust.
///
/// - `tip`: the current HEAD commit. Must carry a *good* signature (`%G?`
///   == `G`) from a trusted key.
/// - `introducing_commits`: for each file being emitted, the commits that
///   introduced its current content. Build this list with
///   `git log -m --format=%H --end-of-options -- <path>`: `-m`
///   (`--diff-merges=separate`) expands merge diffs so a merge commit that
///   rewrote the file is included — without it, content changed inside a
///   merge escapes the walk (the same hole as the inbox's merge-commit
///   bypass). Every listed commit must carry a good signature from a
///   trusted key.
///
/// Anything else — unsigned, bad signature, untrusted signer — is a hard
/// error: the caller withholds the record from agent output.
pub fn verify_history(
    checker: &dyn SignerChecker,
    anchor: &Anchor,
    tip: &str,
    introducing_commits: &[String],
) -> Result<(), Error> {
    let trusted = anchor.signer_fingerprints();
    let trusted = |sig: &Option<(char, String)>| -> bool {
        match sig {
            Some(('G', fp)) => trusted.iter().any(|t| t == fp),
            _ => false,
        }
    };
    let tip_sig = checker.commit_signature(tip)?;
    if !trusted(&tip_sig) {
        return Err(Error::Manifest(format!(
            "tip commit {tip} is not signed by a trusted key with a good signature; refusing agent output"
        )));
    }
    for commit in introducing_commits {
        let sig = checker.commit_signature(commit)?;
        if !trusted(&sig) {
            return Err(Error::Manifest(format!(
                "content introduced by untrusted/unsigned/bad-signature commit {commit}; refusing agent output"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::path::PathBuf;

    struct FakeChecker {
        signers: HashMap<String, Option<(char, String)>>,
    }

    impl SignerChecker for FakeChecker {
        fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error> {
            Ok(self.signers.get(commit).cloned().flatten())
        }
    }

    /// A test anchor plus the operator/recovery keys it was built from.
    fn test_anchor() -> (Anchor, VerifyingKey, VerifyingKey) {
        let operator = SigningKey::generate(&mut OsRng).verifying_key();
        let recovery = SigningKey::generate(&mut OsRng).verifying_key();
        let anchor = Anchor {
            operator,
            recovery,
            recovery_age: "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0"
                .to_string(),
            source: PathBuf::from("/test/trust.toml"),
        };
        (anchor, operator, recovery)
    }

    fn checker_for(op_fp: &str, rec_fp: &str) -> FakeChecker {
        FakeChecker {
            signers: HashMap::from([
                ("tip".to_string(), Some(('G', op_fp.to_string()))),
                ("c1".to_string(), Some(('G', op_fp.to_string()))),
                ("c2".to_string(), Some(('G', rec_fp.to_string()))),
                ("unsigned".to_string(), None),
                ("bad-sig".to_string(), Some(('B', op_fp.to_string()))),
            ]),
        }
    }

    #[test]
    fn ssh_fingerprint_matches_known_vector() {
        // Independent test vector: key = sha256("confidant-test-vector-ssh-fingerprint-1"),
        // fingerprint computed outside this crate. Pins the wire format.
        let bytes: [u8; 32] = [
            0x8c, 0x7f, 0x1c, 0x58, 0x7b, 0xe2, 0xc1, 0xa0, 0x8f, 0xb9, 0x38, 0xc2, 0xb1, 0x48,
            0x28, 0xd3, 0x7b, 0x82, 0x21, 0x83, 0x57, 0xae, 0x62, 0x9f, 0x24, 0xa0, 0xdf, 0x70,
            0x63, 0xec, 0x2c, 0x05,
        ];
        let key = VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(
            ssh_fingerprint(&key),
            "SHA256:rUgZcO5MW9FArMNHAnopjFyjEhOH0KwCj7IItsMbSHU"
        );
    }

    #[test]
    fn trusted_history_passes() {
        let (anchor, op, rec) = test_anchor();
        let c = checker_for(&ssh_fingerprint(&op), &ssh_fingerprint(&rec));
        assert!(verify_history(&c, &anchor, "tip", &["c1".to_string(), "c2".to_string()]).is_ok());
    }

    #[test]
    fn recovery_key_is_a_trusted_signer() {
        // The anchor's recovery key signs too (design §4: operator + recovery).
        let (anchor, op, rec) = test_anchor();
        let rec_fp = ssh_fingerprint(&rec);
        let c = FakeChecker {
            signers: HashMap::from([("tip".to_string(), Some(('G', rec_fp)))]),
        };
        let _ = op;
        assert!(verify_history(&c, &anchor, "tip", &[]).is_ok());
    }

    #[test]
    fn full_fingerprint_pinned_not_key_id() {
        // A 16-char %GK-style key id must NOT match: only the full %GF
        // fingerprint is trusted.
        let (anchor, op, rec) = test_anchor();
        let full = ssh_fingerprint(&op);
        let truncated: String = full.chars().skip(7).take(16).collect();
        assert_ne!(full, truncated);
        let c = FakeChecker {
            signers: HashMap::from([("tip".to_string(), Some(('G', truncated)))]),
        };
        let _ = rec;
        let err = verify_history(&c, &anchor, "tip", &[]).unwrap_err();
        assert!(format!("{err}").contains("not signed by a trusted key"));
    }

    #[test]
    fn unknown_key_refused() {
        let (anchor, _op, _rec) = test_anchor();
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        let c = FakeChecker {
            signers: HashMap::from([("tip".to_string(), Some(('G', ssh_fingerprint(&other))))]),
        };
        let err = verify_history(&c, &anchor, "tip", &[]).unwrap_err();
        assert!(format!("{err}").contains("not signed by a trusted key"));
    }

    #[test]
    fn unsigned_introducing_commit_refused() {
        let (anchor, op, rec) = test_anchor();
        let c = checker_for(&ssh_fingerprint(&op), &ssh_fingerprint(&rec));
        let err = verify_history(&c, &anchor, "tip", &["unsigned".to_string()]).unwrap_err();
        assert!(format!("{err}").contains("untrusted/unsigned"));
    }

    #[test]
    fn bad_signature_refused_even_from_trusted_key() {
        // %GF prints a fingerprint even for a BAD signature — %G? must be G.
        let (anchor, op, rec) = test_anchor();
        let c = checker_for(&ssh_fingerprint(&op), &ssh_fingerprint(&rec));
        let err = verify_history(&c, &anchor, "tip", &["bad-sig".to_string()]).unwrap_err();
        assert!(format!("{err}").contains("bad-signature"));
    }

    #[test]
    fn unsigned_tip_refused() {
        let (anchor, op, rec) = test_anchor();
        let c = checker_for(&ssh_fingerprint(&op), &ssh_fingerprint(&rec));
        assert!(verify_history(&c, &anchor, "unsigned", &["c1".to_string()]).is_err());
    }

    #[test]
    fn untrusted_signer_refused() {
        let (anchor, _op, _rec) = test_anchor();
        // Checker claims a key the anchor never pinned.
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        let c = FakeChecker {
            signers: HashMap::from([
                ("tip".to_string(), Some(('G', ssh_fingerprint(&other)))),
                ("c1".to_string(), Some(('G', ssh_fingerprint(&other)))),
            ]),
        };
        assert!(verify_history(&c, &anchor, "tip", &["c1".to_string()]).is_err());
    }
}
