use std::path::Path;

use crate::error::DomainError;

use super::git::{git, git_toplevel, toplevel_relative};
use super::keys::InboxKeys;
use super::{run_inbox, InboxOptions, InboxReport};

/// Options for [`run_inbox_rotate`].
pub struct InboxRotateOptions {
    /// `false`: `inbox rotate` — drain, install a new keypair, update pins.
    /// `true`: `inbox rotate --finish` — drain leftovers, destroy the old key.
    pub finish: bool,
    /// Proceed without verifying inbox branch signatures during the drain.
    pub allow_unsigned: bool,
    /// Signing key IDs trusted to push the inbox branch (ADR-10).
    pub trusted_signers: Vec<String>,
    /// The operator's out-of-band pin of the vault's inbox public key.
    pub pinned_pubkey: Option<String>,
}

/// What `inbox rotate` / `inbox rotate --finish` did (§8a.3).
#[derive(Clone, Debug)]
pub struct InboxRotateOutcome {
    /// The drain report, when a drain ran (`None` on the lost-key path).
    pub drain: Option<InboxReport>,
    /// The new age recipient (`age1...`), when a new keypair was installed.
    pub new_recipient: Option<String>,
    /// True when `--finish` destroyed the old private key.
    pub old_key_destroyed: bool,
    /// True when the old key was unavailable: the drain was skipped and
    /// there is no `--finish` to run (lost-key path, §8a.2).
    pub lost_key: bool,
}

/// Rotate the inbox key: drain-then-destroy (§8a.3).
///
/// `inbox rotate` (finish `false`): drains the inbox with a normal run,
/// generates a new X25519 keypair, moves the old key into the keychain's
/// previous slot via [`rotate_inbox_key_with`], and updates
/// `confidant.toml [inbox].pubkey` (committed) and the user-config pin.
/// When no old key is enrolled the drain is skipped — the lost-key path
/// (§8a.2): there is no old private key to drain with, and no `--finish`
/// to run.
///
/// `inbox rotate --finish` (finish `true`): drains anything still
/// encrypted to the old key (decryption tries old then new during the
/// window), then destroys the old private key with
/// [`delete_inbox_key_previous_with`]. Afterwards, items sent to the old
/// key fail closed with `E_INBOX_CRYPTO`. Idempotent: with no previous key
/// it reports `old_key_destroyed: false` and changes nothing.
///
/// [`rotate_inbox_key_with`]: confidant_crypt::keychain::rotate_inbox_key_with
/// [`delete_inbox_key_previous_with`]: confidant_crypt::keychain::delete_inbox_key_previous_with
pub fn run_inbox_rotate(
    vault_root: &Path,
    backend: &dyn confidant_crypt::keychain::KeychainBackend,
    keychain_config_dir: Option<&Path>,
    vault_config_path: &Path,
    user_config_path: &Path,
    opts: &InboxRotateOptions,
) -> anyhow::Result<InboxRotateOutcome> {
    use confidant_crypt::keychain as kc;

    // The keychain kill switch (`CONFIDANT_KEYCHAIN=off`) blanks backend
    // reads for tests, so a load would report `NoKey` and take the
    // lost-key path — while the rotation itself writes the real backend,
    // quietly moving the operator's real key into the previous slot with
    // the drain skipped and nothing reported pending. Rotation is a
    // keychain operation: refuse outright while the switch is set. An
    // unrecognized switch value fails closed too — a typo must not
    // silently mean keychain-on (issue #103 F).
    match kc::keychain_switch() {
        Ok(kc::KeychainSwitch::Off) => {
            return Err(anyhow::Error::new(DomainError::inbox_crypto(
                "refusing inbox key rotation: CONFIDANT_KEYCHAIN=off is set; \
                 unset it to rotate (it is a test-only switch)"
                    .to_string(),
            )));
        }
        Ok(kc::KeychainSwitch::On) => {}
        Err(e) => {
            return Err(anyhow::Error::new(DomainError::inbox_crypto(e.to_string())));
        }
    }

    let keys: Option<std::sync::Arc<InboxKeys>> =
        InboxKeys::load_opt_with(backend, keychain_config_dir)?.map(std::sync::Arc::new);

    if opts.finish {
        let keys = keys.ok_or_else(|| {
            DomainError::inbox_crypto("no inbox key enrolled; nothing to finish".to_string())
        })?;
        if !keys.has_previous() {
            // Idempotent: the window is already closed.
            return Ok(InboxRotateOutcome {
                drain: None,
                new_recipient: None,
                old_key_destroyed: false,
                lost_key: false,
            });
        }
        let drain = drain_for_rotate(vault_root, &keys, opts)?;
        kc::delete_inbox_key_previous_with(backend).map_err(|e| {
            anyhow::Error::new(DomainError::inbox_crypto(format!(
                "could not destroy the old inbox key: {e}"
            )))
        })?;
        return Ok(InboxRotateOutcome {
            drain: Some(drain),
            new_recipient: None,
            old_key_destroyed: true,
            lost_key: false,
        });
    }

    // `inbox rotate`.
    let (drain, lost_key) = match &keys {
        Some(keys) => {
            // Fail fast before the drain: the keychain rotation refuses
            // while an env override is set, so a full drain first would
            // be pointless work ending in the same refusal.
            kc::refuse_if_inbox_env_override().map_err(|e| {
                anyhow::Error::new(DomainError::inbox_crypto(format!(
                    "could not rotate the inbox key: {e}"
                )))
            })?;
            if keys.has_previous() {
                let current = keys.current_recipient();
                let vault_pub = read_inbox_pubkey_pin(vault_config_path)?;
                let user_pub = read_inbox_pubkey_pin(user_config_path)?;
                if vault_pub.as_deref() != Some(current.as_str()) {
                    return resume_inbox_rotation_pins(
                        vault_root,
                        vault_config_path,
                        user_config_path,
                        &current,
                        true,
                    );
                }
                if user_pub.as_deref() != Some(current.as_str()) {
                    return resume_inbox_rotation_pins(
                        vault_root,
                        vault_config_path,
                        user_config_path,
                        &current,
                        false,
                    );
                }
                return Err(anyhow::Error::new(DomainError::inbox_crypto(
                    rotation_window_open_message(),
                )));
            }
            (Some(drain_for_rotate(vault_root, keys, opts)?), false)
        }
        // Lost-key path (§8a.2): no old private key, so no drain and no
        // `--finish` — generate and install the new keypair directly.
        None => (None, true),
    };

    // Generate the new keypair. The secret lives in a `Zeroizing<String>`
    // from here until the keychain takes its copy.
    let identity = age::x25519::Identity::generate();
    let new_recipient = identity.to_public().to_string();
    let new_secret = zeroize::Zeroizing::new({
        use age::secrecy::ExposeSecret;
        identity.to_string().expose_secret().to_owned()
    });
    kc::rotate_inbox_key_with(backend, keychain_config_dir, new_secret.as_str()).map_err(|e| {
        anyhow::Error::new(DomainError::inbox_crypto(format!(
            "could not rotate the inbox key: {e}"
        )))
    })?;
    drop(new_secret);

    // Update the pins: the vault's advertised pubkey (committed) and the
    // operator's out-of-band pin in the user config.
    update_inbox_pubkey_pin(vault_config_path, &new_recipient)?;
    commit_vault_config(vault_root, vault_config_path, &new_recipient)?;
    update_inbox_pubkey_pin(user_config_path, &new_recipient)?;

    Ok(InboxRotateOutcome {
        drain,
        new_recipient: Some(new_recipient),
        old_key_destroyed: false,
        lost_key,
    })
}
/// Run a normal (non-dry-run) inbox drain as the first step of a rotation.
/// The decrypt closure owns an `Arc` clone so it is `'static`, as
/// [`run_inbox`] requires.
fn rotation_window_open_message() -> String {
    "refusing inbox key rotation: the rotation window is open (the previous \
     inbox key is still in the keychain). Drain any items still encrypted to \
     the old key, then run `confidant inbox rotate --finish` to destroy the \
     old key before starting another rotation"
        .to_string()
}

/// Resume a partial rotation (#106): keychain already holds the new key.
fn resume_inbox_rotation_pins(
    vault_root: &Path,
    vault_config_path: &Path,
    user_config_path: &Path,
    current: &str,
    update_vault_pin: bool,
) -> anyhow::Result<InboxRotateOutcome> {
    use confidant_crypt::keychain as kc;

    kc::refuse_if_inbox_env_override().map_err(|e| {
        anyhow::Error::new(DomainError::inbox_crypto(format!(
            "could not resume inbox key rotation: {e}"
        )))
    })?;
    if update_vault_pin {
        update_inbox_pubkey_pin(vault_config_path, current)?;
        commit_vault_config(vault_root, vault_config_path, current)?;
    }
    update_inbox_pubkey_pin(user_config_path, current)?;
    Ok(InboxRotateOutcome {
        drain: None,
        new_recipient: Some(current.to_owned()),
        old_key_destroyed: false,
        lost_key: false,
    })
}

fn drain_for_rotate(
    vault_root: &Path,
    keys: &std::sync::Arc<InboxKeys>,
    opts: &InboxRotateOptions,
) -> anyhow::Result<InboxReport> {
    let owned = keys.clone();
    let decrypt = move |ciphertext: &[u8]| owned.decrypt(ciphertext);
    run_inbox(
        vault_root,
        &InboxOptions {
            dry_run: false,
            trusted_signers: opts.trusted_signers.clone(),
            allow_unsigned: opts.allow_unsigned,
            pinned_pubkey: opts.pinned_pubkey.clone(),
        },
        &decrypt,
        Some(keys.as_ref()),
    )
}
/// Read `[inbox].pubkey` from a TOML pin file. Missing file → `None`.
fn read_inbox_pubkey_pin(path: &Path) -> anyhow::Result<Option<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("could not read {}: {e}", path.display())),
    };
    let doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| DomainError::config(format!("{} is not valid TOML: {e}", path.display())))?;
    Ok(doc
        .get("inbox")
        .and_then(|v| v.get("pubkey"))
        .and_then(|v| v.as_str())
        .map(str::to_owned))
}

/// Set `[inbox].pubkey` in a TOML file, preserving formatting and comments
/// (`toml_edit`). Creates the file — and its parent directories — holding
/// just the `[inbox]` table when it does not exist yet. A missing file is
/// the only case treated as empty: any other read error (permissions,
/// non-UTF-8) fails instead of overwriting the file and dropping tables
/// like `[trust] signers`. The write is atomic (temp file + rename) so a
/// crash mid-write can't leave a truncated config.
fn update_inbox_pubkey_pin(path: &Path, recipient: &str) -> anyhow::Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "could not read {}: {e} — refusing to overwrite it",
                path.display()
            ))
        }
    };
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| DomainError::config(format!("{} is not valid TOML: {e}", path.display())))?;
    match doc.get("inbox") {
        None => {
            doc["inbox"] = toml_edit::table();
        }
        Some(v) if v.is_table() => {}
        Some(_) => {
            return Err(anyhow::Error::new(DomainError::config(format!(
                "{}: [inbox] is not a table — refusing to overwrite it",
                path.display()
            ))))
        }
    }
    doc["inbox"]["pubkey"] = toml_edit::value(recipient);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("could not create {}: {e}", parent.display()))?;
        }
    }
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    std::fs::write(&tmp, doc.to_string())
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow::anyhow!("could not replace {}: {e}", path.display()))?;
    Ok(())
}
/// Commit the rotated `confidant.toml`. The pin is public key material, so
/// the commit message names it. This is a config change, not an intake
/// item, so it does not go through the inbox signing gate (#52).
pub(crate) fn commit_vault_config(
    vault_root: &Path,
    vault_config_path: &Path,
    new_recipient: &str,
) -> anyhow::Result<()> {
    // The drain may have run in a subdirectory of the repo; commit from the
    // git toplevel so the path resolves.
    let toplevel = git_toplevel(vault_root)?;
    let rel = toplevel_relative(&toplevel, vault_config_path)?;
    git(&toplevel, &["add", "--", &rel.to_string_lossy()])?;
    // Commit with a pathspec: a bare `git commit` would sweep anything
    // the operator already had staged into the rotation commit, and in a
    // privacy vault that is a real risk.
    git(
        &toplevel,
        &[
            "commit",
            "-q",
            "-m",
            &format!("inbox: rotate pubkey to {new_recipient}"),
            "--",
            &rel.to_string_lossy(),
        ],
    )?;
    Ok(())
}
