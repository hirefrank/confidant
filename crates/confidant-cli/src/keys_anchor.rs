//! Trust-anchor installation and enrollment verification for `keys
//! device-add` and `doctor` (#713). Extracted from `main.rs` so the
//! crypto-adjacent verification logic has a module boundary and unit tests
//! of its own. No behavior or output changed by the extraction.

use std::path::{Path, PathBuf};

use confidant_core::error::DomainError;

use crate::FixExt;

/// Derive the recipient key id for a device from its age pubkey.
///
/// Stable and unique per device: `device-` + 8 chars from the pubkey.
/// Char-based (not byte-indexed) so a short/malformed pubkey cannot panic;
/// callers validate the pubkey parses as an age recipient first.
pub(crate) fn device_key_id(age_pubkey: &str) -> String {
    let suffix: String = age_pubkey.chars().skip(8).take(8).collect();
    format!("device-{suffix}")
}

// Per-client enrollment coverage for one device keypair (round-2 N1).
// `enrolled` and `missing` partition the vault's expected clients:
// every manifest client plus the vault lookup key. A device is fully
// enrolled only when `missing` is empty; a non-empty `missing` alongside
// a non-empty `enrolled` is partial enrollment, which no command can top
// up in place (`add_recipient` refuses any re-used pubkey — the shred
// guard), so callers must fail closed and name the missing clients.
pub(crate) struct EnrollmentCoverage {
    pub(crate) enrolled: Vec<String>,
    pub(crate) missing: Vec<String>,
}

/// Read-only enrollment probe for `--from-request` (#713 follow-up).
/// Returns `Some(coverage)` when every expected client's map verifies,
/// and `None` when any map cannot be verified — callers then fall through
/// to the normal path, whose verify-first `add_recipient` fails closed on
/// its own. Unlike the original boolean probe, this checks ALL expected
/// clients' wrappings: a single hit no longer reads as "enrolled".
pub(crate) fn device_enrollment_coverage(
    store: &mut confidant_crypt::lifecycle::KeyStore,
    anchor: &confidant_crypt::anchor::Anchor,
    key_id: &str,
    pubkey: &str,
) -> Option<EnrollmentCoverage> {
    use confidant_crypt::manifest::VAULT_CLIENT_ID;
    let mut clients = store.manifest_clients();
    if !clients.iter().any(|c| c == VAULT_CLIENT_ID) {
        clients.push(VAULT_CLIENT_ID.to_string());
    }
    clients.sort();
    let mut enrolled = Vec::new();
    let mut missing = Vec::new();
    for client in &clients {
        let (_epoch, map, _commitments) = store.verified_recipients(client, anchor).ok()?;
        if map.contains_key(key_id) || map.values().any(|e| e.age_pubkey == pubkey) {
            enrolled.push(client.clone());
        } else {
            missing.push(client.clone());
        }
    }
    Some(EnrollmentCoverage { enrolled, missing })
}

/// The fail-closed error for a partially enrolled device (round-2 N1):
/// the anchor-only path cannot fix it, and no top-up exists, so name the
/// missing clients and point at the supported recovery — a fresh device
/// keypair enrolled from scratch. The stale key id may be revoked from
/// the clients where it lingers once the fresh enrollment lands.
pub(crate) fn partial_enrollment_error(
    key_id: &str,
    label: &str,
    coverage: &EnrollmentCoverage,
) -> anyhow::Error {
    anyhow::Error::new(
        DomainError::invalid(format!(
            "device {key_id} ({label}) is only partially enrolled: it holds wrappings for {} but is missing wrappings for {}; refusing an anchor-only fix",
            coverage.enrolled.join(", "),
            coverage.missing.join(", ")
        ))
        .with_fix(format!(
            "A partially enrolled keypair cannot be topped up in place: re-enrollment refuses any keypair already enrolled anywhere. Generate a fresh device keypair on the new device with `confidant keys device-add --initiate`, enroll that request with `confidant keys device-add --from-request <file> --anchor-out <anchor-file>`, then run `confidant keys device-add --complete --anchor-file <anchor-file>` on the new device after pulling. Optionally revoke the stale key id from the clients where it lingers with `confidant keys revoke <client> {key_id}`"
        )),
    )
}

/// Build the enrollment probe's KeyStore against a throwaway copy of the
/// seq tracker (round-2 N5): the probe must be side-effect-free, so its
/// verified-manifest advances land in a temp file, never in the real
/// `manifest-seq.toml`. The copy carries the real high-water marks, so
/// the replay check sees exactly what the real tracker would. Returns
/// `None` when the throwaway cannot be built; callers then skip the probe
/// and fall through to the normal path, as for an unverifiable probe.
/// The caller removes the temp file after probing (best-effort); a
/// leftover is never read, since the next probe deletes it first.
pub(crate) fn probe_keystore(
    root: &Path,
    vault_id: &str,
    config_dir: &Path,
) -> Option<(confidant_crypt::lifecycle::KeyStore, PathBuf)> {
    use confidant_crypt::manifest::{seq_tracker_path, SeqTracker};
    let temp = config_dir.join(format!("manifest-seq.probe-{}.toml", std::process::id()));
    crate::remove_path_best_effort(&temp);
    let real = seq_tracker_path(config_dir);
    match std::fs::copy(&real, &temp) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    let tracker = SeqTracker::load(&temp).ok()?;
    let store = confidant_crypt::lifecycle::KeyStore::new(root.join("keys"), vault_id, tracker);
    Some((store, temp))
}

/// Whether `path` (which need not exist yet) resolves inside the vault.
/// Canonicalizes the parent directory, so a symlink into the vault is
/// caught the same way `anchor::load_from` catches one for
/// `--anchor-file`. Returns false when the destination cannot be
/// resolved — the write itself then reports the problem.
pub(crate) fn anchor_out_inside_vault(root: &Path, path: &Path) -> bool {
    let Ok(vault_canon) = root.canonicalize() else {
        return false;
    };
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return false,
        }
    };
    // Round-2 N3: resolve a final-component symlink chain before the
    // parent check. A dangling symlink pointing into the vault passes the
    // parent check (its parent is outside) and `create_new` would follow
    // it, writing anchor bytes into the working tree. Resolve links
    // lexically — canonicalize cannot resolve a dangling target — and
    // fail closed (treat as inside) on an unresolvable chain.
    let mut dest = abs;
    for _ in 0..40 {
        let Ok(md) = std::fs::symlink_metadata(&dest) else {
            break;
        };
        if !md.file_type().is_symlink() {
            break;
        }
        let Ok(target) = std::fs::read_link(&dest) else {
            return true;
        };
        dest = if target.is_absolute() {
            target
        } else {
            match dest.parent() {
                Some(parent) => parent.join(target),
                None => return true,
            }
        };
    }
    if std::fs::symlink_metadata(&dest)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return true;
    }
    let Some(parent) = dest.parent() else {
        return false;
    };
    let Ok(parent_canon) = parent.canonicalize() else {
        return false;
    };
    let dest = match dest.file_name() {
        Some(name) => parent_canon.join(name),
        None => parent_canon,
    };
    dest.starts_with(&vault_canon)
}

/// Write this device's `trust.toml` bytes to `path` for transfer to a new
/// device (#713). The anchor holds public-key material only, but it is
/// still written 0600 on Unix and create-new: overwriting an existing
/// file could swap the anchor a pending `--complete` run is about to
/// install. Refuses a destination inside the vault, like
/// `anchor::load_from` does for `--anchor-file` (S1): off-vault trust
/// material in the working tree could be swept into history by a later
/// `git commit -a`, against the design §4 off-vault rule.
pub(crate) fn write_anchor_out_file(
    config_dir: &Path,
    root: &Path,
    path: &Path,
) -> anyhow::Result<()> {
    use confidant_crypt::anchor;
    use std::io::Write;
    if anchor_out_inside_vault(root, path) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "refusing to write the trust anchor inside the vault: {}",
                path.display()
            ))
            .with_fix("Choose an --anchor-out path outside the vault"),
        ));
    }
    let bytes = std::fs::read(config_dir.join(anchor::TRUST_FILE)).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read trust anchor for --anchor-out: {e}"
        )))
    })?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // S3: the Unix-only mode import was unconditional; gate it like every
    // other use in this file. The anchor is public-key material, so
    // default permissions elsewhere are tolerable (and documented here).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        let fix = if e.kind() == std::io::ErrorKind::AlreadyExists {
            "Choose a new --anchor-out path, or remove the existing file first"
        } else {
            "Choose a writable --anchor-out path in an existing directory"
        };
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot write trust anchor to {}: {e}",
            path.display()
        )))
        .with_fix(fix)
    })?;
    file.write_all(&bytes).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot write trust anchor to {}: {e}",
            path.display()
        )))
    })?;
    Ok(())
}

/// Outcome of verifying a candidate trust anchor against the pulled vault
/// (#713). `cert`, `lookup`, and `client_unwrap` are each `pass` or
/// `absent` (nothing to check against); a failed check is an error, never
/// a status string — a candidate anchor is installed only when every
/// applicable check passes.
pub(crate) struct AnchorChecks {
    pub(crate) cert: &'static str,
    pub(crate) lookup: &'static str,
    pub(crate) client_unwrap: &'static str,
}

/// Verify the candidate anchor's operator key against the vault's
/// operator certificate (`keys/operator.toml`, signed at `init` by the
/// recovery key). Returns `pass` when the certificate verifies to the
/// candidate operator key, `absent` when the vault predates certificates.
/// A present-but-mismatching certificate is a hard error: the candidate
/// anchor is for another vault (or a transplanted one), and installing it
/// would leave every read failing against the wrong trust root.
pub(crate) fn verify_anchor_cert(
    root: &Path,
    vault_id: &str,
    anchor: &confidant_crypt::anchor::Anchor,
) -> anyhow::Result<&'static str> {
    use confidant_crypt::anchor;
    let keys_dir = root.join("keys");
    if !keys_dir.join(anchor::OPERATOR_CERT_FILE).is_file() {
        return Ok("absent");
    }
    let operator =
        anchor::verify_operator_cert(&keys_dir, vault_id, &anchor.recovery).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "trust anchor does not match this vault's operator certificate: {e}"
            )))
            .with_fix(
                "Use the trust anchor from an enrolled device of THIS vault; \
                 an anchor copied from another vault can never decrypt here",
            )
        })?;
    if operator != anchor.operator {
        return Err(anyhow::Error::new(
            DomainError::invalid(
                "trust anchor operator key does not match this vault's operator certificate",
            )
            .with_fix(
                "Use the trust anchor from an enrolled device of THIS vault; \
                 an anchor copied from another vault can never decrypt here",
            ),
        ));
    }
    Ok("pass")
}

/// Map a trial-unwrap failure to the fix the operator actually needs
/// (#713). A manifest failure means the candidate anchor does not verify
/// this vault's signed manifests; any other failure (no wrapping, age
/// open failure) means this device holds no usable key here — most often
/// `--from-request` has not run (or has not been pulled) yet.
pub(crate) fn map_unwrap_failure(e: confidant_crypt::error::Error) -> DomainError {
    use confidant_crypt::error::Error as CryptError;
    match e {
        CryptError::Manifest(_) => DomainError::invalid(format!(
            "trust anchor does not verify this vault's key manifests: {e}"
        ))
        .with_fix(
            "Use the trust anchor from an enrolled device of THIS vault; \
             an anchor copied from another vault can never decrypt here",
        ),
        _ => DomainError::invalid(format!(
            "this device cannot unwrap vault keys with its device key: {e}"
        ))
        .with_fix(
            "Ask an enrolled device to run `confidant keys device-add --from-request` \
             for this device, pull on this device, then retry --complete",
        ),
    }
}

/// Trial-unwrap one client data key with this device's identity under the
/// candidate anchor. Read-only: `trial_unwrap_data_key` verifies the
/// manifest without advancing the off-vault seq tracker, so this is safe
/// for `doctor` as well as `--complete`. Returns `Ok(true)` on a pass,
/// `Ok(false)` when the vault has no client keys to trial (a vault with
/// only a lookup key), and the raw crypto error otherwise (callers map it:
/// `NoKey` means "not enrolled", `Manifest` means "anchor does not match
/// this vault"). Tries clients in order until one passes so a single
/// uninitialized client cannot block the check; the first failure is
/// reported when none pass.
pub(crate) fn trial_unwrap_first_client(
    store: &confidant_crypt::lifecycle::KeyStore,
    anchor: &confidant_crypt::anchor::Anchor,
    identity: &dyn age::Identity,
    device_pubkey: &str,
) -> Result<bool, confidant_crypt::error::Error> {
    use confidant_crypt::manifest::VAULT_CLIENT_ID;
    let key_id = device_key_id(device_pubkey);
    let mut clients: Vec<String> = store
        .manifest_clients()
        .into_iter()
        .filter(|c| c != VAULT_CLIENT_ID)
        .collect();
    clients.sort();
    let mut first_error: Option<confidant_crypt::error::Error> = None;
    for client_id in &clients {
        let epoch = match store.current_epoch(client_id) {
            Ok(epoch) => epoch,
            Err(e) => {
                first_error.get_or_insert(e);
                continue;
            }
        };
        match store.trial_unwrap_data_key(client_id, &key_id, epoch, identity, anchor) {
            Ok(key) => {
                drop(key);
                return Ok(true);
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(false),
    }
}

/// Per-client trial-unwrap outcome for `--complete` (round-2 N1). Unlike
/// `trial_unwrap_first_client` (kept for `doctor`, where one passing
/// client proves the anchor), `--complete` must not report success while
/// some clients' wrappings are missing: it trials EVERY client. A
/// `NoKey` trial (no wrapping for this device) lands in `missing`; any
/// other failure is a hard error, since an unreadable client is not
/// evidence of anything. Trials are side-effect-free: the trial path
/// verifies manifests without advancing the seq tracker.
pub(crate) struct ClientTrialCoverage {
    pub(crate) passed: Vec<String>,
    pub(crate) missing: Vec<String>,
}

pub(crate) fn trial_unwrap_coverage(
    store: &confidant_crypt::lifecycle::KeyStore,
    anchor: &confidant_crypt::anchor::Anchor,
    identity: &dyn age::Identity,
    device_pubkey: &str,
) -> Result<ClientTrialCoverage, confidant_crypt::error::Error> {
    use confidant_crypt::{error::Error, manifest::VAULT_CLIENT_ID};
    let key_id = device_key_id(device_pubkey);
    let mut clients: Vec<String> = store
        .manifest_clients()
        .into_iter()
        .filter(|c| c != VAULT_CLIENT_ID)
        .collect();
    clients.sort();
    let mut passed = Vec::new();
    let mut missing = Vec::new();
    for client_id in &clients {
        let epoch = store.current_epoch(client_id)?;
        match store.trial_unwrap_data_key(client_id, &key_id, epoch, identity, anchor) {
            Ok(key) => {
                drop(key);
                passed.push(client_id.clone());
            }
            Err(Error::NoKey(_)) => missing.push(client_id.clone()),
            Err(e) => return Err(e),
        }
    }
    Ok(ClientTrialCoverage { passed, missing })
}

/// The fail-closed error for `--complete` on a partially enrolled device
/// (round-2 N1): the anchor is not installed (fresh path) or left exactly
/// as it was (already-present path), and the missing clients are named.
/// Recovery is a fresh device keypair enrolled from scratch — the same
/// no-top-up rule as the operator-side probe. A device enrolled nowhere
/// never reaches this error: it fails earlier as unenrolled.
pub(crate) fn partial_complete_error(
    missing: &[String],
    anchor_already_installed: bool,
) -> anyhow::Error {
    let installed_note = if anchor_already_installed {
        " The installed trust anchor is left untouched."
    } else {
        " Nothing was installed."
    };
    anyhow::Error::new(
        DomainError::invalid(format!(
            "this device is only partially enrolled: it is missing wrappings for {}.{installed_note}",
            missing.join(", ")
        ))
        .with_fix(
            "A partially enrolled keypair cannot be topped up in place: re-enrollment refuses any keypair already enrolled anywhere. Generate a fresh device keypair on this device with `confidant keys device-add --initiate`, ask an enrolled device to enroll that request with `confidant keys device-add --from-request <file> --anchor-out <anchor-file>`, pull, then retry --complete",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_id_is_stable_and_prefixed() {
        // A plausible age1 recipient; the id is the `device-` prefix plus
        // chars 8..16 of the pubkey, regardless of the rest.
        let pubkey = "age1abcdefghijklmnopqrstuvwxyz0123456789";
        let id = device_key_id(pubkey);
        assert!(id.starts_with("device-"));
        assert_eq!(id.len(), "device-".len() + 8);
        // Deterministic.
        assert_eq!(device_key_id(pubkey), id);
    }

    #[test]
    fn anchor_out_inside_vault_flags_direct_and_symlink_paths() {
        let vault = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let keys_dir = vault.path().join("keys");
        std::fs::create_dir(&keys_dir).unwrap();

        // Direct path inside the vault (parent resolves inside).
        assert!(anchor_out_inside_vault(
            vault.path(),
            &vault.path().join("anchor.toml")
        ));
        // Nested path inside the vault.
        assert!(anchor_out_inside_vault(
            vault.path(),
            &keys_dir.join("anchor.toml")
        ));
        // Direct path outside the vault.
        assert!(!anchor_out_inside_vault(
            vault.path(),
            &outside.path().join("anchor.toml")
        ));

        // A symlink at an outside path that points into the vault must be
        // refused (round-2 N3): the parent is outside, but the resolved
        // destination is inside.
        #[cfg(unix)]
        {
            let link = outside.path().join("link.toml");
            std::os::unix::fs::symlink(&keys_dir, &link).unwrap();
            assert!(anchor_out_inside_vault(vault.path(), &link));

            // A dangling symlink pointing into the vault fails closed too.
            let dangling = outside.path().join("dangling.toml");
            std::os::unix::fs::symlink(vault.path().join("does-not-exist"), &dangling).unwrap();
            assert!(anchor_out_inside_vault(vault.path(), &dangling));
        }
    }

    #[test]
    fn partial_complete_error_names_missing_clients_and_state() {
        let err = partial_complete_error(&["a".to_string(), "b".to_string()], false);
        let msg = format!("{err:#}");
        assert!(msg.contains("a, b"), "names the missing clients: {msg}");
        assert!(msg.contains("Nothing was installed"), "{msg}");

        let err = partial_complete_error(&["a".to_string()], true);
        let msg = format!("{err:#}");
        assert!(msg.contains("left untouched"), "{msg}");
    }
}
