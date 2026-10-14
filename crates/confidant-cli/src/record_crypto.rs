//! Record-file encryption for the CLI write path (spec 3, issue #148).
//!
//! [`RecordEncryptor`] is built once per write command from the vault's
//! crypto mode. On a structurally encrypted vault it encrypts every
//! record-file `WriteFile` into a §14 envelope; on a `mode = "plaintext"`
//! vault it does not exist (the caller uses plain [`apply_write`]).
//!
//! Fail-closed throughout: any key-resolution failure refuses the write
//! before anything is applied, and no plaintext fallback is ever written.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use confidant_core::crypto_mode::{self, WriteMode};
use confidant_core::error::{DomainError, ErrorKind};
use confidant_core::vault::Vault;
use confidant_crypt::{anchor, envelope, lifecycle::KeyStore, RecordCtx};

use crate::confidant_config_dir;

/// Encrypts record files for one write command. Built by
/// [`RecordEncryptor::for_vault`]; absent (`None`) on plaintext-opt-out
/// vaults.
pub struct RecordEncryptor {
    root: PathBuf,
    vault_id: String,
    store: RefCell<KeyStore>,
    anchor: anchor::Anchor,
    identity: Box<dyn age::Identity + Send>,
    /// This device's recipient key id, resolved once in [`for_vault`]
    /// by matching the local device pubkey against the verified
    /// recipient maps. `device-0` only for the init/recover/shred local
    /// device; `keys device-add` enrolls `device-{8-char suffix}`.
    device_key_id: String,
}

impl RecordEncryptor {
    /// Resolve the vault's write mode and, for encrypted vaults, load the
    /// key material via the standard keyed-caller pattern (config dir →
    /// anchor → device identity → `KeyStore`).
    ///
    /// Returns `Ok(None)` when the vault declares `mode = "plaintext"`.
    /// Returns `Err` (fail closed) when the vault is unkeyed without the
    /// opt-out, when the `[crypto]` table contradicts the vault structure,
    /// or when any key step fails. The error surfaces before `apply_write`
    /// runs, so the target file is untouched.
    pub fn for_vault(root: &Path, vault: &Vault) -> anyhow::Result<Option<Self>> {
        let mode =
            crypto_mode::resolve_write_mode(root, &vault.config).map_err(anyhow::Error::new)?;
        match mode {
            WriteMode::Plaintext => Ok(None),
            WriteMode::Encrypted => {
                let config_dir = confidant_config_dir().ok_or_else(|| {
                    anyhow::Error::new(DomainError::invalid(
                        "HOME is not set; cannot locate the operator config dir",
                    ))
                })?;
                let (anchor, _warnings) =
                    anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
                // Parse the device key once: the concrete identity gives
                // the pubkey for key-id resolution, and boxes into the
                // trait object for unwrapping.
                let bech32 = crate::device_key_bech32()?;
                let device_identity: age::x25519::Identity =
                    bech32.trim().parse().map_err(|e| {
                        anyhow::Error::new(DomainError::invalid(format!("bad device key: {e}")))
                    })?;
                let device_pubkey = device_identity.to_public().to_string();
                let keys_dir = root.join("keys");
                let mut store =
                    KeyStore::with_config_dir(keys_dir, &vault.config.vault_id, &config_dir)
                        .map_err(anyhow::Error::new)?;
                let device_key_id = resolve_device_key_id(&mut store, &anchor, &device_pubkey)?;
                Ok(Some(Self {
                    root: root.to_path_buf(),
                    vault_id: vault.config.vault_id.clone(),
                    store: RefCell::new(store),
                    anchor,
                    identity: Box::new(device_identity),
                    device_key_id,
                }))
            }
        }
    }

    /// Transform one record file's plaintext bytes into the bytes to
    /// write (a §14 envelope). Implements B1–B4 and the ⚠1 guard:
    ///
    /// - existing envelope with identical inner plaintext → existing bytes
    ///   kept byte-for-byte (B3: decrypt-and-compare; a failed decrypt
    ///   counts as changed);
    /// - existing plaintext file → fail closed (⚠1: never encrypt in
    ///   place, never rewrite as plaintext);
    /// - otherwise the client is resolved from the record's *current*
    ///   `person` field, so a deal person change re-encrypts under the new
    ///   person's current epoch (B4).
    pub fn encrypt_file(&self, path: &Path, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let abs = self.root.join(path);
        if let Ok(existing) = std::fs::read(&abs) {
            match stability_decision(&existing, plaintext, &|b| self.decrypt_existing(path, b)) {
                StabilityOutcome::Reuse => return Ok(existing),
                StabilityOutcome::Reencrypt => {}
                StabilityOutcome::PlaintextExists => {
                    // ⚠1: never encrypt a plaintext record in place, never
                    // rewrite it as plaintext — fail closed.
                    return Err(anyhow::Error::new(
                        DomainError::new(
                            ErrorKind::Invalid,
                            format!(
                                "{} already exists as plaintext in an encrypted vault; refusing to rewrite",
                                path.display()
                            ),
                        )
                        .with_fix(
                            "Plaintext records are never encrypted in place; add a new record instead",
                        ),
                    ));
                }
            }
        }

        let text = std::str::from_utf8(plaintext).map_err(|_| {
            anyhow::Error::new(DomainError::invalid(format!(
                "{} is not valid UTF-8",
                path.display()
            )))
        })?;
        let provisional = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("record.md");
        let rec = confidant_core::record::parse_record(text, provisional).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(e.message.clone()).with_fix(e.fix.clone()))
        })?;
        let record_type = rec.kind.as_str();
        let person = rec.field("person");
        let own_no_ai = rec
            .field("no-ai")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        // B2: any `true` wins — the record's own flag or the person's flag
        // read from its plaintext outer header (no decryption needed).
        let outer_no_ai = own_no_ai || person.map(|p| person_no_ai(&self.root, p)).unwrap_or(false);

        // Route to the client key. A person record encrypts under its own
        // id (it has no `person` field); notes, interactions, and deals
        // with a person use the `person` field.
        let routing_person: Option<String> = match record_type {
            "person" => Some(rec.id.to_string()),
            _ => person.map(|s| s.to_string()),
        };
        let client_id =
            confidant_crypt::client_id_for_record(record_type, routing_person.as_deref()).map_err(
                |e| {
                    anyhow::Error::new(DomainError::invalid(format!(
                        "cannot route record to a client key: {e}"
                    )))
                },
            )?;

        let mut store = self.store.borrow_mut();
        let epoch = store.current_epoch(&client_id).map_err(|_| {
            anyhow::Error::new(
                DomainError::invalid(format!("no keys for client {client_id}"))
                    .with_fix(format!("Run `confidant keys init-client {client_id}`")),
            )
        })?;
        let data_key = store
            .unwrap_data_key(
                &client_id,
                &self.device_key_id,
                epoch,
                &*self.identity,
                &self.anchor,
            )
            .map_err(|e| {
                anyhow::Error::new(
                    DomainError::invalid(format!("cannot unwrap data key for {client_id}: {e}"))
                        .with_fix(
                            "Run `confidant init` (new vault) or `confidant recover` (new device)",
                        ),
                )
            })?;
        drop(store);

        let purpose = envelope::purpose_for_type(record_type).ok_or_else(|| {
            anyhow::Error::new(DomainError::invalid(format!(
                "unknown record type {record_type:?}"
            )))
        })?;
        let ctx = RecordCtx {
            vault_id: self.vault_id.clone(),
            ulid: rec.id.to_string(),
            client_id: client_id.clone(),
            path: path.display().to_string(),
            purpose: purpose.to_string(),
            epoch,
        };
        // The data key is Zeroizing inside; the envelope bytes are the only
        // thing that leaves this function.
        let out =
            confidant_crypt::encrypt_record(&ctx, &data_key, record_type, outer_no_ai, plaintext)
                .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!("cannot encrypt record: {e}")))
            })?;
        Ok(out)
    }

    /// Decrypt an existing envelope for the B3 stability comparison and
    /// the inbox retry idempotency check (#213). `for_agent = false`:
    /// this is a byte comparison, not agent output.
    pub(crate) fn decrypt_existing(
        &self,
        path: &Path,
        envelope_bytes: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let env = envelope::parse(envelope_bytes).map_err(anyhow::Error::new)?;
        let client_id = env
            .key_id
            .rsplit_once("/e")
            .map(|(c, _)| c)
            .ok_or_else(|| anyhow::anyhow!("bad key_id in existing envelope"))?;
        let purpose = envelope::purpose_for_type(&env.record_type)
            .ok_or_else(|| anyhow::anyhow!("bad type in existing envelope"))?;
        let mut store = self.store.borrow_mut();
        let key = store
            .unwrap_data_key(
                client_id,
                &self.device_key_id,
                env.epoch,
                &*self.identity,
                &self.anchor,
            )
            .map_err(anyhow::Error::new)?;
        drop(store);
        let ctx = RecordCtx {
            vault_id: self.vault_id.clone(),
            ulid: env.id.clone(),
            client_id: client_id.to_string(),
            path: path.display().to_string(),
            purpose: purpose.to_string(),
            epoch: env.epoch,
        };
        confidant_crypt::decrypt_record(&ctx, &key, envelope_bytes, false)
            .map_err(anyhow::Error::new)
    }
}

/// Resolve this device's recipient key id by matching the local device
/// pubkey against the verified recipient maps (union over all initialized
/// clients). Fail closed when the device is not enrolled: a write must
/// never proceed under the wrong key id.
pub(crate) fn resolve_device_key_id(
    store: &mut KeyStore,
    anchor: &anchor::Anchor,
    device_pubkey: &str,
) -> anyhow::Result<String> {
    for client in store.manifest_clients() {
        let (_epoch, recipients, _commitments) = store
            .verified_recipients(&client, anchor)
            .map_err(anyhow::Error::new)?;
        for (key_id, entry) in &recipients {
            if entry.age_pubkey == device_pubkey {
                return Ok(key_id.clone());
            }
        }
    }
    Err(anyhow::Error::new(
        DomainError::invalid("this device is not enrolled in the vault's client keys").with_fix(
            "enroll this device with `confidant keys device-add` from an enrolled device",
        ),
    ))
}

/// Read a person's `no-ai` flag from its plaintext outer header — the
/// envelope header when the profile is encrypted, the record frontmatter
/// otherwise. Never decrypts. Missing/unreadable → false.
fn person_no_ai(root: &Path, person: &str) -> bool {
    for candidate in [
        format!("people/{person}/profile.md"),
        format!("people/{person}.md"),
    ] {
        let Ok(bytes) = std::fs::read(root.join(&candidate)) else {
            continue;
        };
        if let Ok(env) = envelope::parse(&bytes) {
            return env.no_ai;
        }
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if let Ok(rec) = confidant_core::record::parse_record(text, &candidate) {
                return rec
                    .field("no-ai")
                    .map(|v| v.trim().eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            }
        }
        // Not a parseable envelope or record: fall through to the next
        // candidate path instead of giving up (a `people/{id}/profile.md`
        // may be absent while `people/{id}.md` exists).
    }
    false
}

/// B3 stability decision for one existing file. `decrypt` maps envelope
/// bytes to inner plaintext. Returns:
/// - `Reuse`: existing is an envelope decrypting to exactly `plaintext`
///   \u2014 keep the bytes byte-for-byte (no new nonce, no diff);
/// - `Reencrypt`: envelope with different content, or undecryptable
///   (a failed decrypt counts as changed);
/// - `PlaintextExists`: existing is not an envelope \u2014 the caller
///   fails closed (\u26a01: never encrypt in place).
#[derive(Debug, PartialEq, Eq)]
enum StabilityOutcome {
    Reuse,
    Reencrypt,
    PlaintextExists,
}

fn stability_decision(
    existing: &[u8],
    plaintext: &[u8],
    decrypt: &dyn Fn(&[u8]) -> anyhow::Result<Vec<u8>>,
) -> StabilityOutcome {
    if !crypto_mode::is_envelope_bytes(existing) {
        return StabilityOutcome::PlaintextExists;
    }
    match decrypt(existing) {
        Ok(inner) if inner == plaintext => StabilityOutcome::Reuse,
        _ => StabilityOutcome::Reencrypt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_bytes() -> Vec<u8> {
        b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e0\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n".to_vec()
    }

    #[test]
    fn rewrite_unchanged_keeps_ciphertext_bytes() {
        // B3: envelope decrypting to the same plaintext -> reuse bytes.
        let existing = envelope_bytes();
        let plaintext = b"inner";
        let out = stability_decision(existing.as_slice(), plaintext, &|_| Ok(plaintext.to_vec()));
        assert_eq!(out, StabilityOutcome::Reuse);
    }

    #[test]
    fn changed_content_reencrypts() {
        let existing = envelope_bytes();
        let out = stability_decision(
            existing.as_slice(),
            b"inner",
            &|_| Ok(b"different".to_vec()),
        );
        assert_eq!(out, StabilityOutcome::Reencrypt);
    }

    #[test]
    fn failed_decrypt_counts_as_changed() {
        // A failed decrypt never reuses: it counts as changed.
        let existing = envelope_bytes();
        let out = stability_decision(existing.as_slice(), b"inner", &|_| {
            anyhow::bail!("tampered")
        });
        assert_eq!(out, StabilityOutcome::Reencrypt);
    }

    #[test]
    fn plaintext_existing_is_fail_closed() {
        // \u26a01 guard: an existing plaintext file is never encrypted in
        // place — the caller fails closed.
        let existing = b"---\nid: p-01ABC\ntype: person\n---\n\nBio.\n";
        let out = stability_decision(existing.as_slice(), b"inner", &|_| Ok(b"inner".to_vec()));
        assert_eq!(out, StabilityOutcome::PlaintextExists);
    }
}
