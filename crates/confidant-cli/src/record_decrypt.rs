//! Record-file decryption for the CLI read path (spec 4, issue #148).
//!
//! [`RecordDecryptor`] is built once per read command (`find`, `context`,
//! and MCP through the CLI) and supplies the [`ContentHook`] that core's
//! vault loader calls per record file. Keyless by construction on core's
//! side: the hook maps raw bytes to plaintext-or-skip, and core never sees
//! key material.
//!
//! Fail-closed per record (⚠2): an envelope this device cannot read is
//! skipped and counted, never a command error; a tampered/corrupt envelope
//! is refused and counted separately, never folded into the skip count.
//! `no-ai: true` envelopes are never decrypted, key or no key (design §5).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use confidant_core::crypto_mode;
use confidant_core::vault::{ContentHook, ContentOutcome};
use confidant_crypt::{anchor, envelope, lifecycle::KeyStore, RecordCtx};

use crate::confidant_config_dir;
use crate::record_crypto::resolve_device_key_id;

/// Key material for one read command. `None` when this device has no usable
/// key: the decryptor then skips every envelope (counted) instead of
/// failing the command (⚠2).
struct KeyMaterial {
    store: Mutex<KeyStore>,
    anchor: anchor::Anchor,
    identity: Box<dyn age::Identity + Send + Sync>,
    device_key_id: String,
}

/// Decrypts record files for one read command. Built by
/// [`RecordDecryptor::for_reads`]; the same keyed-caller pattern as the
/// write path (config dir → anchor → device identity → `KeyStore`), but
/// every failure degrades to unkeyed mode instead of refusing the command.
pub struct RecordDecryptor {
    vault_id: String,
    keys: Option<KeyMaterial>,
}

impl RecordDecryptor {
    /// Build the decryptor for `vault` at `root`. Never fails: any key
    /// problem (no config dir, no anchor, no device key, not enrolled)
    /// yields unkeyed mode, where envelopes are skipped and counted.
    pub fn for_reads(root: &Path, vault_id: &str) -> Self {
        let keys = load_key_material(root, vault_id);
        Self {
            vault_id: vault_id.to_string(),
            keys,
        }
    }

    /// The [`ContentHook`] for core's vault loader. `Send + Sync`: record
    /// files load on worker threads, and the `Mutex` serializes key use.
    pub fn hook(self: &Arc<Self>) -> ContentHook {
        let this = Arc::clone(self);
        Arc::new(move |path: &str, bytes: &[u8]| this.decrypt_file(path, bytes))
    }

    /// Map one record file's raw bytes to a [`ContentOutcome`].
    ///
    /// 1. Not envelope-shaped → plaintext passthrough (today's behavior).
    /// 2. `envelope::parse` fails → tampered/corrupt → refused + counted.
    /// 3. Outer `no-ai: true` → shell, never decrypted (design §5).
    /// 4. No key material → skipped + counted (⚠2).
    /// 5. Data key won't unwrap → skipped + counted (key absent).
    /// 6. `decrypt_record(for_agent = true)` fails → refused + counted
    ///    (⚠2c: auth failure is tampering, never a skip).
    fn decrypt_file(&self, path: &str, bytes: &[u8]) -> ContentOutcome {
        if !crypto_mode::is_envelope_bytes(bytes) {
            return ContentOutcome::Content(bytes.to_vec());
        }
        let env = match envelope::parse(bytes) {
            Ok(env) => env,
            Err(_) => return ContentOutcome::Refused,
        };
        if env.no_ai {
            return ContentOutcome::NoAiShell {
                id: env.id,
                record_type: env.record_type,
            };
        }
        let Some(keys) = &self.keys else {
            return ContentOutcome::Skipped;
        };
        let (client_id, epoch) = match env.key_id.rsplit_once("/e") {
            Some((c, _)) => (c, env.epoch),
            None => return ContentOutcome::Refused,
        };
        let purpose = match envelope::purpose_for_type(&env.record_type) {
            Some(p) => p,
            None => return ContentOutcome::Refused,
        };
        let data_key = match keys.store.lock() {
            Ok(mut store) => {
                match store.unwrap_data_key(
                    client_id,
                    &keys.device_key_id,
                    epoch,
                    &*keys.identity,
                    &keys.anchor,
                ) {
                    Ok(k) => k,
                    Err(_) => return ContentOutcome::Skipped,
                }
            }
            Err(_) => return ContentOutcome::Skipped,
        };
        let ctx = RecordCtx {
            vault_id: self.vault_id.clone(),
            ulid: env.id.clone(),
            client_id: client_id.to_string(),
            path: path.to_string(),
            purpose: purpose.to_string(),
            epoch,
        };
        // `for_agent = true`: the agent read path. no-ai was already
        // handled above, so this only enforces header/AAD/AEAD.
        match confidant_crypt::decrypt_record(&ctx, &data_key, bytes, true) {
            Ok(inner) => ContentOutcome::Content(inner),
            Err(_) => ContentOutcome::Refused,
        }
    }
}

/// Load key material via the standard keyed-caller pattern. `None` on any
/// failure: reads degrade to unkeyed mode (skip + count), they never fail
/// the command for a missing key.
fn load_key_material(root: &Path, vault_id: &str) -> Option<KeyMaterial> {
    let config_dir = confidant_config_dir()?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).ok()?;
    let bech32 = crate::device_key_bech32().ok()?;
    let device_identity: age::x25519::Identity = bech32.trim().parse().ok()?;
    let device_pubkey = device_identity.to_public().to_string();
    let keys_dir = root.join("keys");
    let mut store = KeyStore::with_config_dir(keys_dir, vault_id, &config_dir).ok()?;
    let device_key_id = resolve_device_key_id(&mut store, &anchor, &device_pubkey).ok()?;
    Some(KeyMaterial {
        store: Mutex::new(store),
        anchor,
        identity: Box::new(device_identity),
        device_key_id,
    })
}

/// True when the vault has a record file for `person` that is an envelope
/// (used by `context` for the ⚠2b hard error: the person's key is absent).
pub fn person_has_envelope(root: &Path, person: &str) -> bool {
    for candidate in [
        format!("people/{person}.md"),
        format!("people/{person}/profile.md"),
    ] {
        let path = PathBuf::from(root).join(&candidate);
        if let Ok(bytes) = std::fs::read(&path) {
            if crypto_mode::is_envelope_bytes(&bytes) {
                return true;
            }
        }
    }
    false
}
