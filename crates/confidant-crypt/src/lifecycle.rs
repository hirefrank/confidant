//! Key lifecycle: init, rotate, revoke, shred (design §§6, 8).
//!
//! Operates on the vault's `keys/` directory:
//!
//! ```text
//! keys/
//! ├── vault/
//! │   ├── lookup.age          # alias-lookup key, age-encrypted to all recipients
//! │   ├── recipients.toml     # recipient list for the lookup key
//! │   └── recipients.sig
//! └── p-<ULID>/
//!     ├── epoch               # ASCII decimal, current key epoch
//!     ├── recipients.toml
//!     ├── recipients.sig
//!     └── wrapped/
//!         ├── <key-id>.age        # this epoch's data key, age-encrypted
//!         ├── recovery.age        # this epoch's data key, age-encrypted to recovery
//!         ├── <key-id>.e<epoch>.age   # retained old epochs
//!         └── recovery.e<epoch>.age
//! ```
//!
//! - **Rotate**: new 256-bit data key, `epoch += 1`, wrap to all current
//!   recipients + recovery, re-sign. Old wrappings are renamed to
//!   `.e<epoch>.age` so history stays readable. No re-encryption.
//! - **Revoke**: re-wrap without the revoked party across **all retained
//!   epochs** (their `<key-id>.e<epoch>.age` files are removed), update +
//!   re-sign the manifest. Future writes only (ADR-5): ciphertext the
//!   revoked device already copied cannot be unread.
//! - **Shred**: key destruction. Delete every wrapped copy of the client's
//!   data keys (all epochs), rotate every recipient keypair that ever held
//!   a wrapping (caller supplies fresh public keys, obtained from devices
//!   like onboarding, plus a fresh recovery identity is generated),
//!   re-wrap all remaining client keys and the lookup key, re-sign. Old
//!   private keys must be destroyed by the operator (OS keychains / secret
//!   stores / paper) — the returned [`ShredOutcome`] lists what to destroy
//!   and states the leftover limits plainly.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

use crate::age_wrap::{unwrap_with_identity, wrap_to_recipient};
use crate::anchor::Anchor;
use crate::error::Error;
use crate::keys::{DataKey, LookupKey};
use crate::manifest::{self, RecipientMap, SeqTracker, VAULT_CLIENT_ID};
use crate::recovery::Recovery;

/// Key id used for the recovery wrapping.
const RECOVERY_KEY_ID: &str = "recovery";

/// A client's verified epoch keys, ready for re-wrapping (shred's verify-first pass).
type VerifiedEpochKeys<'a> = (&'a str, u64, Vec<(u64, DataKey)>);

/// Manages the `keys/` tree of one vault.
#[derive(Debug)]
pub struct KeyStore {
    keys_dir: PathBuf,
    vault_id: String,
    seq: Option<SeqTracker>,
}

impl KeyStore {
    pub fn new(keys_dir: PathBuf, vault_id: &str) -> Self {
        KeyStore {
            keys_dir,
            vault_id: vault_id.to_string(),
            seq: None,
        }
    }

    /// Attach the off-vault seq high-water tracker (next to `trust.toml`).
    /// Without it, manifest seq replay checks are skipped — tests only.
    pub fn with_seq_tracker(mut self, tracker: SeqTracker) -> Self {
        self.seq = Some(tracker);
        self
    }

    fn client_dir(&self, client_id: &str) -> PathBuf {
        self.keys_dir.join(client_id)
    }

    fn wrapped_dir(&self, client_id: &str) -> PathBuf {
        self.client_dir(client_id).join("wrapped")
    }

    fn manifest_paths(&self, client_id: &str) -> (PathBuf, PathBuf) {
        let d = self.client_dir(client_id);
        (d.join("recipients.toml"), d.join("recipients.sig"))
    }

    /// Current epoch for a client (reads the `epoch` file).
    pub fn current_epoch(&self, client_id: &str) -> Result<u64, Error> {
        let text = std::fs::read_to_string(self.client_dir(client_id).join("epoch"))
            .map_err(|_| Error::NoKey(format!("no keys for client {client_id}")))?;
        text.trim()
            .parse()
            .map_err(|_| Error::Manifest(format!("bad epoch for {client_id}")))
    }

    fn write_epoch(&self, client_id: &str, epoch: u64) -> Result<(), Error> {
        std::fs::write(
            self.client_dir(client_id).join("epoch"),
            format!("{epoch}\n"),
        )?;
        Ok(())
    }

    /// Current manifest seq for a client (0 if no manifest yet).
    fn current_seq(&self, client_id: &str) -> u64 {
        let (toml_path, _) = self.manifest_paths(client_id);
        std::fs::read(&toml_path)
            .ok()
            .and_then(|b| manifest::from_toml(&b).ok())
            .map(|(seq, _)| seq)
            .unwrap_or(0)
    }

    fn high_water(&self, client_id: &str) -> u64 {
        self.seq
            .as_ref()
            .map(|t| t.high_water(&self.vault_id, client_id))
            .unwrap_or(0)
    }

    fn advance_seq(&mut self, client_id: &str, seq: u64) -> Result<(), Error> {
        if let Some(t) = self.seq.as_mut() {
            t.advance(&self.vault_id, client_id, seq)?;
        }
        Ok(())
    }

    fn write_manifest(
        &mut self,
        client_id: &str,
        epoch: u64,
        recipients: &RecipientMap,
        signing_sk: &SigningKey,
    ) -> Result<(), Error> {
        let seq = self.current_seq(client_id).max(self.high_water(client_id)) + 1;
        let toml = manifest::to_toml(seq, recipients)?;
        let sig = manifest::sign(signing_sk, &self.vault_id, client_id, epoch, seq, &toml);
        let (toml_path, sig_path) = self.manifest_paths(client_id);
        std::fs::write(toml_path, toml)?;
        std::fs::write(sig_path, sig)?;
        self.advance_seq(client_id, seq)?;
        Ok(())
    }

    /// Read and verify the manifest against the trust anchor.
    ///
    /// Accepts a signature from the operator key **or** the recovery Ed25519
    /// key (both are trust-anchor members, design §4) — so a recovery from
    /// the phrase alone can authorize the new device's manifest. Refuses a
    /// seq below the off-vault high-water mark.
    pub fn verified_recipients(
        &mut self,
        client_id: &str,
        anchor: &Anchor,
    ) -> Result<(u64, RecipientMap), Error> {
        let epoch = self.current_epoch(client_id)?;
        let (toml_path, sig_path) = self.manifest_paths(client_id);
        let toml = std::fs::read(&toml_path)
            .map_err(|_| Error::Manifest(format!("missing manifest for {client_id}")))?;
        let sig = std::fs::read(&sig_path)
            .map_err(|_| Error::Manifest(format!("missing manifest signature for {client_id}")))?;
        let min_seq = self.high_water(client_id);
        // Try the operator key first, then the recovery key.
        let map = manifest::verify(
            &anchor.operator,
            &self.vault_id,
            client_id,
            epoch,
            &toml,
            &sig,
            min_seq,
        )
        .or_else(|_| {
            manifest::verify(
                &anchor.recovery,
                &self.vault_id,
                client_id,
                epoch,
                &toml,
                &sig,
                min_seq,
            )
        })?;
        // Advance the high-water mark past what we just verified.
        let seq = manifest::from_toml(&toml)?.0;
        self.advance_seq(client_id, seq)?;
        Ok((epoch, map))
    }

    /// Initialize a client's key directory: epoch 1, wrap the new data key
    /// to every recipient + recovery, sign the manifest.
    pub fn init_client(
        &mut self,
        client_id: &str,
        recipients: &RecipientMap,
        recovery_recipient: &str,
        operator_sk: &SigningKey,
    ) -> Result<DataKey, Error> {
        let dir = self.client_dir(client_id);
        if dir.join("epoch").exists() {
            return Err(Error::Manifest(format!(
                "client {client_id} already initialized; use rotate"
            )));
        }
        std::fs::create_dir_all(dir.join("wrapped"))?;
        let key = DataKey::generate();
        self.write_epoch(client_id, 1)?;
        self.wrap_current(client_id, &key, recipients, recovery_recipient)?;
        self.write_manifest(client_id, 1, recipients, operator_sk)?;
        Ok(key)
    }

    /// Wrap the current-epoch data key to each recipient + recovery.
    fn wrap_current(
        &self,
        client_id: &str,
        key: &DataKey,
        recipients: &RecipientMap,
        recovery_recipient: &str,
    ) -> Result<(), Error> {
        let wdir = self.wrapped_dir(client_id);
        for (key_id, entry) in recipients {
            let wrapped = wrap_to_recipient(key.as_bytes(), &entry.age_pubkey)?;
            std::fs::write(wdir.join(format!("{key_id}.age")), wrapped)?;
        }
        let wrapped = wrap_to_recipient(key.as_bytes(), recovery_recipient)?;
        std::fs::write(wdir.join(format!("{RECOVERY_KEY_ID}.age")), wrapped)?;
        Ok(())
    }

    /// Wrap one epoch's data key to each recipient + recovery, using the
    /// correct file naming for the epoch (current vs retained).
    fn wrap_epoch(
        &self,
        client_id: &str,
        epoch: u64,
        current_epoch: u64,
        key: &DataKey,
        recipients: &RecipientMap,
        recovery_recipient: &str,
    ) -> Result<(), Error> {
        let wdir = self.wrapped_dir(client_id);
        let suffix = if epoch == current_epoch {
            String::new()
        } else {
            format!(".e{epoch}")
        };
        for (key_id, entry) in recipients {
            let wrapped = wrap_to_recipient(key.as_bytes(), &entry.age_pubkey)?;
            std::fs::write(wdir.join(format!("{key_id}{suffix}.age")), wrapped)?;
        }
        let wrapped = wrap_to_recipient(key.as_bytes(), recovery_recipient)?;
        std::fs::write(wdir.join(format!("{RECOVERY_KEY_ID}{suffix}.age")), wrapped)?;
        Ok(())
    }

    /// Initialize the vault alias-lookup key, wrapped to all recipients.
    pub fn init_lookup_key(
        &mut self,
        recipients: &[String],
        operator_sk: &SigningKey,
    ) -> Result<LookupKey, Error> {
        let vdir = self.keys_dir.join("vault");
        std::fs::create_dir_all(&vdir)?;
        let key = LookupKey::generate();
        // One age file, encrypted to all recipients at once.
        let recips: Vec<Box<dyn age::Recipient>> = recipients
            .iter()
            .map(|r| {
                r.parse::<age::x25519::Recipient>()
                    .map(|rec| Box::new(rec) as Box<dyn age::Recipient>)
                    .map_err(|e| Error::Age(format!("bad recipient: {e}")))
            })
            .collect::<Result<_, _>>()?;
        let encryptor = age::Encryptor::with_recipients(recips.iter().map(|r| r.as_ref()))
            .map_err(|e| Error::Age(format!("encryptor: {e}")))?;
        let mut out = Vec::new();
        {
            use std::io::Write;
            let mut w = encryptor
                .wrap_output(&mut out)
                .map_err(|e| Error::Age(format!("wrap: {e}")))?;
            w.write_all(key.as_bytes())
                .map_err(|e| Error::Age(format!("write: {e}")))?;
            w.finish().map_err(|e| Error::Age(format!("finish: {e}")))?;
        }
        std::fs::write(vdir.join("lookup.age"), out)?;
        // Vault-level manifest for the lookup key (seq starts at 1; the
        // vault-level manifest uses the fixed VAULT_CLIENT_ID binding).
        let mut map = RecipientMap::new();
        for (i, r) in recipients.iter().enumerate() {
            map.insert(
                format!("device-{i}"),
                crate::manifest::RecipientEntry {
                    age_pubkey: r.clone(),
                    label: format!("device-{i}"),
                    scope_ref: String::new(),
                },
            );
        }
        let toml = manifest::to_toml(1, &map)?;
        let sig = manifest::sign(operator_sk, &self.vault_id, VAULT_CLIENT_ID, 1, 1, &toml);
        std::fs::write(vdir.join("recipients.toml"), toml)?;
        std::fs::write(vdir.join("recipients.sig"), sig)?;
        self.advance_seq(VAULT_CLIENT_ID, 1)?;
        Ok(key)
    }

    /// Unwrap a data key: verify the manifest against the anchor, then
    /// unwrap `<key-id>.age` (current epoch) or `<key-id>.e<epoch>.age`.
    pub fn unwrap_data_key(
        &mut self,
        client_id: &str,
        key_id: &str,
        epoch: u64,
        identity: &dyn age::Identity,
        anchor: &Anchor,
    ) -> Result<DataKey, Error> {
        let (current_epoch, recipients) = self.verified_recipients(client_id, anchor)?;
        if !recipients.contains_key(key_id) && key_id != RECOVERY_KEY_ID {
            return Err(Error::NoKey(format!(
                "key id {key_id} not in manifest for {client_id}"
            )));
        }
        let filename = if epoch == current_epoch {
            format!("{key_id}.age")
        } else {
            format!("{key_id}.e{epoch}.age")
        };
        let wrapped = std::fs::read(self.wrapped_dir(client_id).join(&filename))
            .map_err(|_| Error::NoKey(format!("no wrapping {filename} for {client_id}")))?;
        let raw = unwrap_with_identity(&wrapped, identity)?;
        if raw.len() != 32 {
            return Err(Error::Age("unwrapped key is not 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        // Re-wrap into DataKey without exposing: DataKey::generate is random,
        // so we need a from-bytes constructor. Use a local helper via the
        // fact that DataKey is a tuple struct in this crate.
        Ok(DataKey::from_bytes(arr))
    }

    /// Rotate a client's data key: new key, `epoch += 1`, wrap to all
    /// current recipients + recovery, re-sign. Old wrappings are renamed to
    /// `.e<epoch>.age` so history stays readable. No re-encryption.
    pub fn rotate(
        &mut self,
        client_id: &str,
        recovery_recipient: &str,
        operator_sk: &SigningKey,
        anchor: &Anchor,
    ) -> Result<DataKey, Error> {
        let (epoch, recipients) = self.verified_recipients(client_id, anchor)?;
        let new_epoch = epoch + 1;
        // Rename current wrappings to the old epoch.
        for entry in std::fs::read_dir(self.wrapped_dir(client_id))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".age") && !name.contains(".e") {
                let stem = name.trim_end_matches(".age");
                let new_name = format!("{stem}.e{epoch}.age");
                std::fs::rename(entry.path(), self.wrapped_dir(client_id).join(new_name))?;
            }
        }
        let key = DataKey::generate();
        self.wrap_current(client_id, &key, &recipients, recovery_recipient)?;
        self.write_epoch(client_id, new_epoch)?;
        self.write_manifest(client_id, new_epoch, &recipients, operator_sk)?;
        Ok(key)
    }

    /// Revoke recipients: delete their wrappings across **all retained
    /// epochs**, drop them from the manifest, re-sign. The revoked party
    /// keeps whatever ciphertext it already copied (ADR-5, future writes
    /// only) — `revoke` does not pretend otherwise.
    pub fn revoke(
        &mut self,
        client_id: &str,
        revoked_key_ids: &[&str],
        operator_sk: &SigningKey,
        anchor: &Anchor,
    ) -> Result<(), Error> {
        let (epoch, mut recipients) = self.verified_recipients(client_id, anchor)?;
        for id in revoked_key_ids {
            recipients.remove(*id);
        }
        // Remove the revoked party's wrappings for every retained epoch.
        for entry in std::fs::read_dir(self.wrapped_dir(client_id))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            for id in revoked_key_ids {
                if name == format!("{id}.age") || name.starts_with(&format!("{id}.e")) {
                    std::fs::remove_file(entry.path())?;
                    break;
                }
            }
        }
        self.write_manifest(client_id, epoch, &recipients, operator_sk)?;
        Ok(())
    }

    /// All historical versions of a client's recipient manifest, oldest
    /// first, from git history. Used by `shred` to build the complete
    /// destroy list: a recipient revoked earlier still has old wrappings in
    /// history that open the shredded client's historical data keys.
    fn historical_recipients(&self, client_id: &str) -> Result<Vec<RecipientMap>, Error> {
        // keys_dir is <vault>/keys; the repo root is its parent.
        let repo = self
            .keys_dir
            .parent()
            .ok_or_else(|| Error::Manifest("keys dir has no parent; not a vault".to_string()))?;
        let rel = format!("keys/{client_id}/recipients.toml");
        let out = std::process::Command::new("git")
            .args([
                "-C",
                &repo.to_string_lossy(),
                "log",
                "--format=%H",
                "--end-of-options",
                "--",
                &rel,
            ])
            .output()
            .map_err(Error::Io)?;
        if !out.status.success() {
            // Not a git repo or no history: fall back to the current manifest.
            return Ok(Vec::new());
        }
        let mut maps = Vec::new();
        for sha in String::from_utf8_lossy(&out.stdout).lines().map(str::trim) {
            if sha.is_empty() {
                continue;
            }
            let show = std::process::Command::new("git")
                .args([
                    "-C",
                    &repo.to_string_lossy(),
                    "show",
                    &format!("{sha}:{rel}"),
                ])
                .output()
                .map_err(Error::Io)?;
            if !show.status.success() {
                continue;
            }
            if let Ok((_, map)) = manifest::from_toml(&show.stdout) {
                maps.push(map);
            }
        }
        Ok(maps)
    }

    /// Crypto-shred a client: key destruction, not deletion.
    ///
    /// 1. Delete the client's entire `keys/<client>/` tree (every wrapped
    ///    copy of every epoch).
    /// 2. Rotate every recipient: re-wrap all *remaining* clients' keys and
    ///    the vault lookup key to `new_recipients` (fresh public keys the
    ///    operator obtained from devices, like onboarding) and re-sign
    ///    their manifests. A fresh recovery identity is generated; its
    ///    phrase is returned (display once, confirm written down, like
    ///    `init`).
    /// 3. The caller must destroy the old private keys (OS keychains /
    ///    secret stores / paper) — [`ShredOutcome::destroy_key_ids`]
    ///    lists them, and [`ShredOutcome::warnings`] states the leftover
    ///    limits plainly.
    ///
    /// `identity` must unwrap the current keys (an old device or recovery
    /// identity) so remaining keys can be re-wrapped.
    pub fn shred(
        &mut self,
        shredded_client: &str,
        all_clients: &[&str],
        new_recipients: &RecipientMap,
        operator_sk: &SigningKey,
        anchor: &Anchor,
        identity: &dyn age::Identity,
    ) -> Result<ShredOutcome, Error> {
        // Build the destroy list from EVERY historical version of the
        // manifest: a recipient revoked earlier still has old wrappings in
        // git history that open the shredded client's historical data keys
        // (design §8: "every recipient that ever held a wrapping").
        let mut destroy_ids = std::collections::BTreeSet::new();
        for map in self.historical_recipients(shredded_client)? {
            destroy_ids.extend(map.keys().cloned());
        }
        let (_, current_recipients) = self.verified_recipients(shredded_client, anchor)?;
        destroy_ids.extend(current_recipients.keys().cloned());
        let destroy_key_ids: Vec<String> = destroy_ids.into_iter().collect();

        // Verify EVERYTHING before changing any files. On failure here,
        // nothing has changed and the old keys still work.
        //
        // 1. The identity must open every remaining client's every epoch.
        let mut to_rewrap: Vec<VerifiedEpochKeys> = Vec::new();
        for client in all_clients {
            if *client == shredded_client {
                continue;
            }
            let (epoch, old_map) = self.verified_recipients(client, anchor)?;
            let mut epoch_keys = Vec::new();
            for e in 1..=epoch {
                let mut key_opt = None;
                let mut last_err =
                    Error::NoKey(format!("identity opens no wrapping for {client} e{e}"));
                for kid in old_map
                    .keys()
                    .chain(std::iter::once(&RECOVERY_KEY_ID.to_string()))
                {
                    match self.unwrap_data_key(client, kid, e, identity, anchor) {
                        Ok(k) => {
                            key_opt = Some(k);
                            break;
                        }
                        Err(er) => last_err = er,
                    }
                }
                epoch_keys.push((e, key_opt.ok_or(last_err)?));
            }
            to_rewrap.push((client, epoch, epoch_keys));
        }
        // 2. No new recipient pubkey may match any current or historical
        // recipient (including recovery): reusing a pubkey would keep the
        // old private key able to unwrap.
        let mut old_pubkeys = std::collections::BTreeSet::new();
        for client in all_clients {
            for map in self.historical_recipients(client)? {
                old_pubkeys.extend(map.values().map(|e| e.age_pubkey.clone()));
            }
            let (_, map) = self.verified_recipients(client, anchor)?;
            old_pubkeys.extend(map.values().map(|e| e.age_pubkey.clone()));
        }
        old_pubkeys.insert(anchor.recovery_age.clone());
        for (id, entry) in new_recipients {
            if old_pubkeys.contains(&entry.age_pubkey) {
                return Err(Error::Manifest(format!(
                    "new recipient {id} reuses a pubkey that already appears in history; \
                     generate fresh keypairs"
                )));
            }
        }
        // 3. The lookup key must unwrap with the identity.
        let lookup_raw = self.read_lookup_raw(identity)?;

        // All checks passed: now mutate.
        let new_recovery = Recovery::generate();
        let new_recovery_recipient = new_recovery.age_identity().to_recipient_string();

        // 1. Delete the shredded client's key tree.
        let cdir = self.client_dir(shredded_client);
        if cdir.exists() {
            std::fs::remove_dir_all(&cdir)?;
        }

        // 2. Re-wrap every remaining client to the new set.
        for (client, epoch, epoch_keys) in &to_rewrap {
            for entry in std::fs::read_dir(self.wrapped_dir(client))? {
                std::fs::remove_file(entry?.path())?;
            }
            for (e, key) in epoch_keys {
                self.wrap_epoch(
                    client,
                    *e,
                    *epoch,
                    key,
                    new_recipients,
                    &new_recovery_recipient,
                )?;
            }
            self.write_manifest(client, *epoch, new_recipients, operator_sk)?;
        }
        // Lookup key: re-wrap the verified bytes to new recipients.
        self.write_lookup_raw(&lookup_raw, new_recipients, operator_sk)?;

        Ok(ShredOutcome {
            new_recovery,
            destroy_key_ids,
            warnings: leftover_warnings(),
        })
    }

    /// Read the raw lookup key bytes (for shred's verify-first pass).
    fn read_lookup_raw(&self, identity: &dyn age::Identity) -> Result<Vec<u8>, Error> {
        let vdir = self.keys_dir.join("vault");
        let wrapped = std::fs::read(vdir.join("lookup.age"))
            .map_err(|_| Error::NoKey("no vault lookup.age".to_string()))?;
        unwrap_with_identity(&wrapped, identity)
    }

    /// Write raw lookup key bytes re-wrapped to new recipients (for shred).
    fn write_lookup_raw(
        &mut self,
        raw: &[u8],
        new_recipients: &RecipientMap,
        operator_sk: &SigningKey,
    ) -> Result<(), Error> {
        let vdir = self.keys_dir.join("vault");
        let recips: Vec<Box<dyn age::Recipient>> = new_recipients
            .values()
            .map(|e| {
                e.age_pubkey
                    .parse::<age::x25519::Recipient>()
                    .map(|rec| Box::new(rec) as Box<dyn age::Recipient>)
                    .map_err(|er| Error::Age(format!("bad recipient: {er}")))
            })
            .collect::<Result<_, _>>()?;
        let encryptor = age::Encryptor::with_recipients(recips.iter().map(|r| r.as_ref()))
            .map_err(|e| Error::Age(format!("encryptor: {e}")))?;
        let mut out = Vec::new();
        {
            use std::io::Write;
            let mut w = encryptor
                .wrap_output(&mut out)
                .map_err(|e| Error::Age(format!("wrap: {e}")))?;
            w.write_all(raw)
                .map_err(|e| Error::Age(format!("write: {e}")))?;
            w.finish().map_err(|e| Error::Age(format!("finish: {e}")))?;
        }
        std::fs::write(vdir.join("lookup.age"), out)?;
        let seq = std::fs::read(vdir.join("recipients.toml"))
            .ok()
            .and_then(|b| manifest::from_toml(&b).ok())
            .map(|(s, _)| s)
            .unwrap_or(0)
            .max(
                self.seq
                    .as_ref()
                    .map(|t| t.high_water(&self.vault_id, VAULT_CLIENT_ID))
                    .unwrap_or(0),
            )
            + 1;
        let toml = manifest::to_toml(seq, new_recipients)?;
        let sig = manifest::sign(operator_sk, &self.vault_id, VAULT_CLIENT_ID, 1, seq, &toml);
        std::fs::write(vdir.join("recipients.toml"), toml)?;
        std::fs::write(vdir.join("recipients.sig"), sig)?;
        self.advance_seq(VAULT_CLIENT_ID, seq)?;
        Ok(())
    }

    /// Rotate the recovery identity: re-wrap every client's `recovery.age`
    /// (all retained epochs) to a fresh recovery recipient.
    ///
    /// Used by `recover` ("rotate to a fresh recovery identity and revoke
    /// the old one") and after `shred`. Returns the new [`Recovery`]; the
    /// caller pins its public halves in the trust anchor and confirms the
    /// phrase was written down. Destroy every copy of the old recovery
    /// phrase (paper, 1Password); until you do, it still opens history.
    pub fn rotate_recovery(
        &mut self,
        clients: &[&str],
        operator_sk: &SigningKey,
        anchor: &Anchor,
        old_identity: &dyn age::Identity,
    ) -> Result<Recovery, Error> {
        let new_recovery = Recovery::generate();
        let new_recipient = new_recovery.age_identity().to_recipient_string();
        for client in clients {
            let (epoch, recipients) = self.verified_recipients(client, anchor)?;
            // Re-wrap the current epoch's recovery file.
            let key = self.unwrap_data_key(client, RECOVERY_KEY_ID, epoch, old_identity, anchor)?;
            let wrapped = wrap_to_recipient(key.as_bytes(), &new_recipient)?;
            std::fs::write(
                self.wrapped_dir(client)
                    .join(format!("{RECOVERY_KEY_ID}.age")),
                wrapped,
            )?;
            // And every retained old epoch's recovery file.
            for e in 1..epoch {
                let key = self.unwrap_data_key(client, RECOVERY_KEY_ID, e, old_identity, anchor)?;
                let wrapped = wrap_to_recipient(key.as_bytes(), &new_recipient)?;
                std::fs::write(
                    self.wrapped_dir(client)
                        .join(format!("{RECOVERY_KEY_ID}.e{e}.age")),
                    wrapped,
                )?;
            }
            // Manifest unchanged (recipients are the same key ids); re-sign
            // to bind the rotation — epoch unchanged.
            self.write_manifest(client, epoch, &recipients, operator_sk)?;
        }
        Ok(new_recovery)
    }
}

/// What `shred` did and what the operator must still do.
///
/// `Debug` is redacted: the new recovery phrase must be displayed exactly
/// once by the CLI (and confirmed written down, like `init`), never logged.
/// Use [`ShredOutcome::recovery_phrase_for_display`] for that single display.
pub struct ShredOutcome {
    new_recovery: Recovery,
    /// Old recipient key ids whose private halves must be destroyed
    /// (OS keychains / secret stores / paper).
    pub destroy_key_ids: Vec<String>,
    /// Plain-language leftover limits, for CLI output.
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for ShredOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShredOutcome")
            .field("new_recovery", &"<redacted>")
            .field("destroy_key_ids", &self.destroy_key_ids)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl ShredOutcome {
    /// The new recovery phrase, for the single operator display. The caller
    /// must confirm it was written down and never log it.
    pub fn recovery_phrase_for_display(&self) -> String {
        self.new_recovery.phrase()
    }

    /// The new recovery identity (for pinning its public halves).
    pub fn new_recovery(&self) -> &Recovery {
        &self.new_recovery
    }
}

/// Leftover limits of crypto-shredding (design §8). Shredding cannot reach:
fn leftover_warnings() -> Vec<String> {
    vec![
        "Decrypted copies already on devices are not affected by shredding.".to_string(),
        ".confidant/ caches and search indexes on every device may still hold plaintext."
            .to_string(),
        "Old private keys may linger in OS keychains or OS backups — destroy them now.".to_string(),
        "Copies outside Confidant entirely (e.g. Drive transcripts) are not affected.".to_string(),
        "This shred issued a new recovery phrase. Destroy every copy of the old recovery phrase (paper, 1Password); until you do, it still opens history.".to_string(),
        "Inbox rotation is pending: run `confidant inbox rotate --finish` to destroy the old inbox key; until then old form answers in history remain readable.".to_string(),
    ]
}

/// Read a vault lookup key by unwrapping `keys/vault/lookup.age`.
pub fn read_lookup_key(keys_dir: &Path, identity: &dyn age::Identity) -> Result<LookupKey, Error> {
    let wrapped = std::fs::read(keys_dir.join("vault").join("lookup.age"))
        .map_err(|_| Error::NoKey("no vault lookup.age".to_string()))?;
    let raw = unwrap_with_identity(&wrapped, identity)?;
    if raw.len() != 32 {
        return Err(Error::Age("lookup key is not 32 bytes".to_string()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(LookupKey::from_bytes(arr))
}
