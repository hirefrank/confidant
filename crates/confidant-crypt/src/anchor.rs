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

use ed25519_dalek::{Signer, Verifier, VerifyingKey};

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

/// Save a new trust anchor.
///
/// Writes exactly the fields [`load`] reads (`operator_pubkey`,
/// `recovery_pubkey`, `recovery_age_recipient` — hex-encoded Ed25519
/// public keys). Creates the config dir with 0700 and writes the file
/// with 0600, atomically: the file is created with `create_new` (no
/// TOCTOU between the exists-check and the write) and mode 0600 from
/// the first byte (no write-then-chmod window at the umask default).
/// Refuses when the config dir is inside the vault (same rule as
/// [`load`]), and refuses to overwrite an existing anchor — the anchor
/// is a trust root and is never silently replaced (use [`replace`] to
/// re-pin, or `recover` to rotate).
pub fn save(
    config_dir: &Path,
    vault_path: &Path,
    operator: &VerifyingKey,
    recovery: &VerifyingKey,
    recovery_age: &str,
) -> Result<(), Error> {
    // Same inside-the-vault refusal as load: canonicalize both sides.
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

    let hex = |k: &[u8]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let text = format!(
        "[trust]\noperator_pubkey = \"{}\"\nrecovery_pubkey = \"{}\"\nrecovery_age_recipient = \"{}\"\n",
        hex(operator.as_bytes()),
        hex(recovery.as_bytes()),
        recovery_age.trim(),
    );

    std::fs::create_dir_all(config_dir).map_err(|e| {
        Error::Anchor(format!(
            "cannot create config dir {}: {e}",
            config_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| Error::Anchor(format!("cannot set 0700 on {}: {e}", config_dir.display())),
        )?;
    }
    write_file_0600_create_new(&trust_path, text.as_bytes()).map_err(|e| {
        Error::Anchor(format!(
            "cannot write {}: {e} (refusing to overwrite an existing anchor; run `confidant recover` to re-pin)",
            trust_path.display()
        ))
    })?;
    Ok(())
}

/// Atomically replace the trust anchor with new keys.
///
/// Writes to a temp file (0600, `create_new`) in the same directory and
/// renames it into place, so a crash never leaves a half-written or
/// missing `trust.toml`. Unlike [`save`], this overwrites — the caller
/// must have validated the replacement first (recover re-pin after
/// `rotate_recovery`, or `init --force` after its checks). The temp file
/// is removed on error.
pub fn replace(
    config_dir: &Path,
    vault_path: &Path,
    operator: &VerifyingKey,
    recovery: &VerifyingKey,
    recovery_age: &str,
) -> Result<(), Error> {
    // Same inside-the-vault refusal as save/load.
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

    let hex = |k: &[u8]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let text = format!(
        "[trust]\noperator_pubkey = \"{}\"\nrecovery_pubkey = \"{}\"\nrecovery_age_recipient = \"{}\"\n",
        hex(operator.as_bytes()),
        hex(recovery.as_bytes()),
        recovery_age.trim(),
    );

    std::fs::create_dir_all(config_dir).map_err(|e| {
        Error::Anchor(format!(
            "cannot create config dir {}: {e}",
            config_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| Error::Anchor(format!("cannot set 0700 on {}: {e}", config_dir.display())),
        )?;
    }

    let trust_path = config_dir.join(TRUST_FILE);
    // Fixed temp-file name is fine for a single operator: any stale copy
    // from a crashed run is removed first, and the write is create-new.
    let tmp_path = config_dir.join(".trust.toml.tmp");
    // Clean up a stale temp file from a crashed run (best effort).
    let _ = std::fs::remove_file(&tmp_path);
    let write_result = write_file_0600_create_new(&tmp_path, text.as_bytes());
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::Anchor(format!(
            "cannot write temp anchor {}: {e}",
            tmp_path.display()
        )));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &trust_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::Anchor(format!(
            "cannot replace {}: {e}",
            trust_path.display()
        )));
    }
    Ok(())
}

/// Write `bytes` to `path` with mode 0600 from creation: `create_new`
/// (fails if the file exists — no exists-then-write race) and the
/// Unix mode set on the `OpenOptions` (no write-then-chmod window).
fn write_file_0600_create_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
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

/// Minimal hex decoding (avoids a `hex` dependency). Delegates to the
/// crate-wide implementation ([`crate::hex`], #136 item 6) with the
/// anchor's error variant and a `what` label.
mod hex {
    use crate::error::Error;

    pub fn decode_hex(what: &str, s: &str) -> Result<Vec<u8>, Error> {
        crate::hex::decode_anchor(what, s)
    }
}

/// Operator-pubkey certificate for fresh-device recovery.
///
/// Written at `init` to `keys/operator.toml` (+ `.sig`): the operator
/// Ed25519 pubkey, signed by the **recovery** Ed25519 key. On a truly
/// fresh device (no `trust.toml`, no config backup), `recover` verifies
/// this certificate against the phrase-derived recovery pubkey and
/// rebuilds the trust anchor from it. The signature binds the pubkey to
/// the vault id, so a certificate transplanted from another vault does
/// not verify.
///
/// This is a spec §14 file (like the manifests): it lives in `keys/`,
/// is committed to git, and is verified before trust.
pub const OPERATOR_CERT_FILE: &str = "operator.toml";
pub const OPERATOR_CERT_SIG_FILE: &str = "operator.sig";

/// Domain separation for the operator certificate signature.
const OPERATOR_CERT_DOMAIN: &[u8] = b"confidant-operator-cert-v1";

fn operator_cert_signing_bytes(vault_id: &str, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(OPERATOR_CERT_DOMAIN.len() + 1 + vault_id.len() + 1 + 32);
    v.extend_from_slice(OPERATOR_CERT_DOMAIN);
    v.push(0);
    v.extend_from_slice(vault_id.as_bytes());
    v.push(0);
    v.extend_from_slice(pubkey);
    v
}

/// Write the operator-pubkey certificate to `keys_dir` (i.e.
/// `keys/operator.toml` + `keys/operator.sig`), signed by the recovery
/// key. Called at `init` before the `keys/` tree is committed.
pub fn write_operator_cert(
    keys_dir: &Path,
    vault_id: &str,
    operator: &VerifyingKey,
    recovery_sk: &ed25519_dalek::SigningKey,
) -> Result<(), Error> {
    let pubkey = operator.as_bytes();
    let hex_pubkey: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let text = format!("[operator]\npubkey = \"{hex_pubkey}\"\n");
    let sig = recovery_sk
        .sign(&operator_cert_signing_bytes(vault_id, pubkey))
        .to_bytes();
    std::fs::write(keys_dir.join(OPERATOR_CERT_FILE), text)
        .map_err(|e| Error::Anchor(format!("cannot write operator certificate: {e}")))?;
    std::fs::write(keys_dir.join(OPERATOR_CERT_SIG_FILE), sig)
        .map_err(|e| Error::Anchor(format!("cannot write operator certificate signature: {e}")))?;
    Ok(())
}

/// Verify the operator-pubkey certificate in `keys_dir` against the
/// phrase-derived recovery pubkey. Returns the verified operator
/// [`VerifyingKey`]. Fails closed on missing files, bad signature, or
/// vault-id mismatch.
pub fn verify_operator_cert(
    keys_dir: &Path,
    vault_id: &str,
    recovery_pk: &VerifyingKey,
) -> Result<VerifyingKey, Error> {
    let text = std::fs::read_to_string(keys_dir.join(OPERATOR_CERT_FILE)).map_err(|_| {
        Error::Anchor(
            "no operator certificate in keys/ (vault predates fresh-device recovery; restore trust.toml from a config backup)".to_string(),
        )
    })?;
    let sig_bytes = std::fs::read(keys_dir.join(OPERATOR_CERT_SIG_FILE))
        .map_err(|_| Error::Anchor("operator certificate signature missing".to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(Error::Anchor(
            "operator certificate signature must be 64 bytes".to_string(),
        ));
    }
    // Parse the pubkey from the TOML.
    let doc: toml::Table = toml::from_str(&text)
        .map_err(|e| Error::Anchor(format!("bad operator certificate: {e}")))?;
    let pubkey_hex = doc
        .get("operator")
        .and_then(|t| t.get("pubkey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Anchor("operator certificate missing pubkey".to_string()))?;
    let pubkey = parse_pubkey(pubkey_hex, "operator pubkey")?;
    // Verify the recovery signature (binds pubkey to this vault).
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| Error::Anchor("malformed operator certificate signature".to_string()))?;
    recovery_pk
        .verify(
            &operator_cert_signing_bytes(vault_id, pubkey.as_bytes()),
            &sig,
        )
        .map_err(|_| {
            Error::Anchor(
                "operator certificate signature does not verify: the recovery phrase does not match this vault"
                    .to_string(),
            )
        })?;
    Ok(pubkey)
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
    fn save_writes_loadable_anchor_with_strict_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let op = SigningKey::generate(&mut OsRng).verifying_key();
        let rec = SigningKey::generate(&mut OsRng).verifying_key();
        let age_recipient = "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0";

        save(&cfg, &vault, &op, &rec, age_recipient).unwrap();

        // Loads back with no warnings (perms are exactly 0700/0600).
        let (anchor, warnings) = load(&cfg, &vault).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(anchor.operator, op);
        assert_eq!(anchor.recovery, rec);
        assert_eq!(anchor.recovery_age, age_recipient);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "config dir must be 0700");
            let file_mode = std::fs::metadata(cfg.join(TRUST_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "trust.toml must be 0600");
        }
    }

    #[test]
    fn save_refuses_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let op = SigningKey::generate(&mut OsRng).verifying_key();
        let rec = SigningKey::generate(&mut OsRng).verifying_key();

        save(
            &cfg,
            &vault,
            &op,
            &rec,
            "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0",
        )
        .unwrap();
        let op2 = SigningKey::generate(&mut OsRng).verifying_key();
        let err = save(
            &cfg,
            &vault,
            &op2,
            &rec,
            "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0",
        )
        .unwrap_err();
        // create_new fails on existing file (no TOCTOU).
        assert!(format!("{err}").contains("cannot write"), "{err}");
        // Original anchor untouched.
        let (anchor, _) = load(&cfg, &vault).unwrap();
        assert_eq!(anchor.operator, op);
    }

    #[test]
    fn replace_swaps_atomically_with_strict_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let op = SigningKey::generate(&mut OsRng).verifying_key();
        let rec = SigningKey::generate(&mut OsRng).verifying_key();
        let age_recipient = "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0";

        save(&cfg, &vault, &op, &rec, age_recipient).unwrap();

        // Replace with a new recovery key.
        let rec2 = SigningKey::generate(&mut OsRng).verifying_key();
        replace(&cfg, &vault, &op, &rec2, age_recipient).unwrap();

        let (anchor, warnings) = load(&cfg, &vault).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(anchor.operator, op);
        assert_eq!(anchor.recovery, rec2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(cfg.join(TRUST_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "replaced trust.toml must be 0600");
        }
        // No temp file left behind.
        assert!(!cfg.join(".trust.toml.tmp").exists());
    }

    #[test]
    fn save_refuses_inside_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        let cfg = vault.join("evil-config");
        std::fs::create_dir_all(&cfg).unwrap();
        let op = SigningKey::generate(&mut OsRng).verifying_key();
        let rec = SigningKey::generate(&mut OsRng).verifying_key();
        let err = save(
            &cfg,
            &vault,
            &op,
            &rec,
            "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6a2t6v26x4z5h7y9k3t9x2s0",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("inside the vault"), "{err}");
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

    #[test]
    fn anchor_hex_rejects_non_ascii() {
        // Same guard as manifest::decode_hex: byte 2 of "é01" splits the
        // 'é', which panicked in the slice before the is_ascii() check.
        let err = hex::decode_hex("test-key", "é01").unwrap_err();
        assert!(format!("{err}").contains("non-ASCII"), "{err}");
        assert_eq!(
            hex::decode_hex("test-key", "00ff").unwrap(),
            vec![0x00, 0xff]
        );
    }
}
