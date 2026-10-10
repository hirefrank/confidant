//! Trust anchor: the operator's Ed25519 public key plus the recovery
//! Ed25519 public key, pinned **off-vault** (default `~/.config/confidant/`).
//!
//! Rules (design §4):
//! - Nothing in the vault can point at or override the anchor: the CLI
//!   refuses an anchor path inside the vault (hard error at config load).
//! - Anchor material lives with 0700 on the config directory and 0600 on
//!   key files; the CLI warns if permissions are looser.
//! - A missing anchor is a hard error — no manifest verification, no
//!   decryption, no commit-signature checks.
//! - After `recover`, the old recovery key leaves every anchor set; the new
//!   recovery identity's Ed25519 key is pinned in its place.
//! - In-vault copies of anchor or recovery public keys are informational
//!   only and never trusted (test 16).

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use crate::error::Error;

impl Anchor {
    /// SSH `SHA256:` fingerprints of the anchor's signing keys.
    ///
    /// The operator key and the recovery Ed25519 key are the trusted
    /// commit signers (design §4, ADR-10). Fingerprints are derived from
    /// the anchor inside the library — never supplied by the caller — so
    /// a compromised caller cannot widen trust. Compared against
    /// `git log --format=%GF` output (full fingerprint, not the 16-char
    /// `%GK` key id).
    pub fn signer_fingerprints(&self) -> [String; 2] {
        [
            crate::history::ssh_fingerprint(&self.operator),
            crate::history::ssh_fingerprint(&self.recovery),
        ]
    }
}

/// File holding the `[trust]` section, relative to the config dir.
pub const TRUST_FILE: &str = "trust.toml";

/// The trust-anchor set: operator key + recovery keys.
///
/// Both public halves of the recovery identity are pinned: the Ed25519
/// verifying key (trust-anchor signing member) and the X25519 age recipient
/// (for `wrapped/recovery.age`). In-vault copies of either are informational
/// only and never trusted (test 16).
#[derive(Clone, Debug)]
pub struct Anchor {
    /// Operator Ed25519 verifying key.
    pub operator: VerifyingKey,
    /// Recovery Ed25519 verifying key (pinned at `init`, rotated on `recover`).
    pub recovery: VerifyingKey,
    /// Recovery age recipient (`age1…`), pinned at `init`.
    pub recovery_age: String,
    /// Where the anchor was loaded from (for diagnostics; never logged
    /// with key material).
    pub source: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct TrustFile {
    trust: TrustSection,
}

#[derive(Debug, serde::Deserialize)]
struct TrustSection {
    /// Hex-encoded Ed25519 public key.
    operator_pubkey: String,
    /// Hex-encoded Ed25519 public key.
    recovery_pubkey: String,
    /// `age1…` recipient for the recovery X25519 key.
    recovery_age_recipient: String,
}

fn parse_pubkey(hex: &str, what: &str) -> Result<VerifyingKey, Error> {
    let bytes = hex::decode_hex(what, hex)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Anchor(format!("{what} must be 32 bytes")))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::Anchor(format!("bad {what}")))
}

/// Load and validate the trust anchor.
///
/// `config_dir` is the off-vault config directory (default
/// `~/.config/confidant/`, overridable by flag/env). `vault_path` is the
/// vault working tree, used to refuse anchor paths inside the vault.
///
/// Hard errors: anchor path inside the vault, missing/unparseable trust
/// file, bad keys. Loose permissions (dir not 0700, file not 0600) produce
/// a [`Warning`], not an error.
pub fn load(config_dir: &Path, vault_path: &Path) -> Result<(Anchor, Vec<Warning>), Error> {
    // Canonicalize both sides before comparing: a symlinked vault must not
    // smuggle the anchor inside it.
    let vault_canon = vault_path.canonicalize().map_err(|_| {
        Error::Anchor(format!(
            "cannot resolve vault path {}",
            vault_path.display()
        ))
    })?;
    let config_canon = config_dir
        .canonicalize()
        .unwrap_or_else(|_| config_dir.to_path_buf());
    if config_canon.starts_with(&vault_canon) {
        return Err(Error::Anchor(format!(
            "trust anchor path {} is inside the vault {}; refusing",
            config_canon.display(),
            vault_canon.display()
        )));
    }

    let trust_path = config_dir.join(TRUST_FILE);
    // Canonicalize the file too (not just the dir): a trust.toml symlink
    // pointing into the vault must not pass the inside-the-vault check.
    let trust_canon = trust_path
        .canonicalize()
        .unwrap_or_else(|_| trust_path.clone());
    if trust_canon.starts_with(&vault_canon) {
        return Err(Error::Anchor(format!(
            "trust anchor path {} is inside the vault {}; refusing",
            trust_canon.display(),
            vault_canon.display()
        )));
    }
    let text = std::fs::read_to_string(&trust_path).map_err(|_| {
        Error::Anchor(format!(
            "missing trust anchor at {}: run `confidant init` on a trusted device",
            trust_path.display()
        ))
    })?;
    let file: TrustFile =
        toml::from_str(&text).map_err(|e| Error::Anchor(format!("bad trust.toml: {e}")))?;
    let operator = parse_pubkey(&file.trust.operator_pubkey, "operator_pubkey")?;
    let recovery = parse_pubkey(&file.trust.recovery_pubkey, "recovery_pubkey")?;
    let recovery_age = file.trust.recovery_age_recipient.trim().to_string();
    if !recovery_age.starts_with("age1") {
        return Err(Error::Anchor(
            "recovery_age_recipient must be an age1… recipient".to_string(),
        ));
    }

    let mut warnings = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(config_dir) {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                warnings.push(Warning::LooseDirPermissions {
                    path: config_dir.to_path_buf(),
                    mode,
                });
            }
        }
        if let Ok(meta) = std::fs::metadata(&trust_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                warnings.push(Warning::LooseFilePermissions {
                    path: trust_path.clone(),
                    mode,
                });
            }
        }
    }

    Ok((
        Anchor {
            operator,
            recovery,
            recovery_age,
            source: trust_path,
        },
        warnings,
    ))
}

/// Non-fatal anchor observations (loose permissions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    LooseDirPermissions { path: PathBuf, mode: u32 },
    LooseFilePermissions { path: PathBuf, mode: u32 },
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Warning::LooseDirPermissions { path, mode } => write!(
                f,
                "trust config dir {} has mode {:o}; expected 700",
                path.display(),
                mode
            ),
            Warning::LooseFilePermissions { path, mode } => write!(
                f,
                "trust file {} has mode {:o}; expected 600",
                path.display(),
                mode
            ),
        }
    }
}

/// Minimal hex decoding (avoids a `hex` dependency).
mod hex {
    use crate::error::Error;

    pub fn decode_hex(what: &str, s: &str) -> Result<Vec<u8>, Error> {
        let s = s.trim();
        if s.len() % 2 != 0 {
            return Err(Error::Anchor(format!("{what}: odd-length hex")));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|_| Error::Anchor(format!("{what}: invalid hex")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn write_trust(dir: &Path, op: &VerifyingKey, rec: &VerifyingKey) {
        let hexop: String = op.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let hexrec: String = rec.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(
            dir.join(TRUST_FILE),
            format!("[trust]\noperator_pubkey = \"{hexop}\"\nrecovery_pubkey = \"{hexrec}\"\nrecovery_age_recipient = \"age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0\"\n"),
        )
        .unwrap();
    }

    #[test]
    fn loads_and_warns_on_loose_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        std::fs::create_dir_all(&cfg).unwrap();
        let op = SigningKey::generate(&mut OsRng).verifying_key();
        let rec = SigningKey::generate(&mut OsRng).verifying_key();
        write_trust(&cfg, &op, &rec);
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let (anchor, warnings) = load(&cfg, &vault).unwrap();
        assert_eq!(anchor.operator, op);
        // tempdir default perms are not 0700/0600 -> warnings expected
        assert!(!warnings.is_empty());
    }

    #[test]
    fn refuses_anchor_inside_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        let cfg = vault.join("evil-config");
        std::fs::create_dir_all(&cfg).unwrap();
        let op = SigningKey::generate(&mut OsRng).verifying_key();
        let rec = SigningKey::generate(&mut OsRng).verifying_key();
        write_trust(&cfg, &op, &rec);
        assert!(matches!(load(&cfg, &vault), Err(Error::Anchor(_))));
    }

    #[test]
    fn missing_anchor_is_hard_error() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        std::fs::create_dir_all(&cfg).unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        assert!(matches!(load(&cfg, &vault), Err(Error::Anchor(_))));
    }
}
