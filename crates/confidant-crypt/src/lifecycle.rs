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

use std::path::PathBuf;

use ed25519_dalek::SigningKey;

use crate::age_wrap::{unwrap_with_identity, wrap_to_recipient};
use crate::anchor::Anchor;
use crate::error::Error;
use crate::keys::{DataKey, LookupKey};
use crate::manifest::{
    self, CommitmentEntry, RecipientMap, SeqTracker, RECOVERY_KEY_ID, SHARED_CLIENT_ID,
    VAULT_CLIENT_ID,
};
use crate::recovery::Recovery;
use zeroize::{Zeroize, Zeroizing};

/// A client's verified epoch keys, ready for re-wrapping (shred's verify-first pass).
type VerifiedEpochKeys<'a> = (&'a str, u64, Vec<(u64, DataKey)>);

/// Manages the `keys/` tree of one vault.
#[derive(Debug)]
pub struct KeyStore {
    keys_dir: PathBuf,
    vault_id: String,
    seq: Option<SeqTracker>,
}

/// What `doctor` reports for one client's recipient manifest.
///
/// A corrupt manifest used to read as seq 0 — indistinguishable from "no
/// manifest yet" — which made a damaged `keys/` tree look healthy. The
/// replay protection (off-vault high-water mark compared in
/// [`KeyStore::verified_recipients`]) never depended on that read; this
/// enum exists purely so diagnostics can tell the two states apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestState {
    /// No `recipients.toml` at this client's manifest dir. Normal for a
    /// client that was never initialized (or a fresh vault).
    Absent,
    /// The file exists but does not parse as a manifest. Needs operator
    /// attention: crypto operations on this client will fail closed.
    /// Carries the parse failure.
    Corrupt(String),
    /// Parses; carries the manifest seq.
    Valid(u64),
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

    /// Directory holding a client's (or the vault's) manifest + wrappings.
    /// The vault-level lookup-key manifest lives at `keys/vault/` and the
    /// shared-key manifest at `keys/shared/`, under the fixed
    /// [`VAULT_CLIENT_ID`] / [`SHARED_CLIENT_ID`] bindings (design §4).
    /// Everything else lives at `keys/<client_id>/`.
    fn manifest_dir(&self, client_id: &str) -> PathBuf {
        if client_id == VAULT_CLIENT_ID {
            self.keys_dir.join("vault")
        } else if client_id == SHARED_CLIENT_ID {
            self.keys_dir.join("shared")
        } else {
            self.client_dir(client_id)
        }
    }

    /// Inverse of [`manifest_dir`]: map a `keys/` subdirectory name back to
    /// its client id. Keeps the reserved-id ↔ dirname binding in one place
    /// (design §4) so `doctor` (via [`manifest_clients`]) reports the same
    /// ids the key machinery uses.
    fn client_id_for_dir(dir_name: &str) -> &str {
        if dir_name == "vault" {
            VAULT_CLIENT_ID
        } else if dir_name == "shared" {
            SHARED_CLIENT_ID
        } else {
            dir_name
        }
    }

    fn wrapped_dir(&self, client_id: &str) -> PathBuf {
        self.manifest_dir(client_id).join("wrapped")
    }

    fn manifest_paths(&self, client_id: &str) -> (PathBuf, PathBuf) {
        let d = self.manifest_dir(client_id);
        (d.join("recipients.toml"), d.join("recipients.sig"))
    }

    /// Current epoch for a client (reads the `epoch` file).
    pub fn current_epoch(&self, client_id: &str) -> Result<u64, Error> {
        let text = std::fs::read_to_string(self.manifest_dir(client_id).join("epoch"))
            .map_err(|_| Error::NoKey(format!("no keys for client {client_id}")))?;
        text.trim()
            .parse()
            .map_err(|_| Error::Manifest(format!("bad epoch for {client_id}")))
    }

    fn write_epoch(&self, client_id: &str, epoch: u64) -> Result<(), Error> {
        std::fs::write(
            self.manifest_dir(client_id).join("epoch"),
            format!("{epoch}\n"),
        )?;
        Ok(())
    }

    /// Classify one client's manifest for diagnostics (`doctor`).
    ///
    /// This is parse-level only: signature verification still happens in
    /// [`KeyStore::verified_recipients`] and fails closed there. A
    /// signature failure is not "corrupt" for this purpose — the file is
    /// well-formed but untrusted, which is a different problem with a
    /// different error.
    pub fn manifest_state(&self, client_id: &str) -> ManifestState {
        let (toml_path, _) = self.manifest_paths(client_id);
        let bytes = match std::fs::read(&toml_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ManifestState::Absent,
            Err(e) => return ManifestState::Corrupt(format!("unreadable: {e}")),
        };
        match manifest::from_toml(&bytes) {
            Ok((seq, _, _)) => ManifestState::Valid(seq),
            Err(e) => ManifestState::Corrupt(e.to_string()),
        }
    }

    /// Every client id with a manifest directory under `keys/`, sorted.
    /// The vault lookup key's `vault/` dir is reported as
    /// [`VAULT_CLIENT_ID`] and the shared key's `shared/` dir as
    /// [`SHARED_CLIENT_ID`], via [`client_id_for_dir`] (the inverse of
    /// [`manifest_dir`]).
    pub fn manifest_clients(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.keys_dir) else {
            return ids;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            ids.push(Self::client_id_for_dir(&name).to_string());
        }
        ids.sort();
        ids
    }

    /// Current manifest seq for a client (0 if no manifest yet).
    ///
    /// A corrupt manifest also reads as 0 here — deliberately, and now
    /// explicitly: seq assignment must never advance on bytes it couldn't
    /// parse, and `doctor` (via [`KeyStore::manifest_state`]) is where the
    /// operator learns the file is damaged instead of missing.
    fn current_seq(&self, client_id: &str) -> u64 {
        match self.manifest_state(client_id) {
            ManifestState::Valid(seq) => seq,
            ManifestState::Absent | ManifestState::Corrupt(_) => 0,
        }
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
        commitments: &[CommitmentEntry],
        signing_sk: &SigningKey,
    ) -> Result<(), Error> {
        let seq = self.current_seq(client_id).max(self.high_water(client_id)) + 1;
        let toml = manifest::to_toml(seq, recipients, commitments)?;
        let sig = manifest::sign(signing_sk, &self.vault_id, client_id, epoch, seq, &toml);
        let (toml_path, sig_path) = self.manifest_paths(client_id);
        std::fs::write(toml_path, toml)?;
        std::fs::write(sig_path, sig)?;
        self.advance_seq(client_id, seq)?;
        Ok(())
    }

    /// Key commitments currently recorded in a client's signed manifest.
    fn current_commitments(&self, client_id: &str) -> Vec<CommitmentEntry> {
        let (toml_path, _) = self.manifest_paths(client_id);
        std::fs::read(&toml_path)
            .ok()
            .and_then(|b| manifest::from_toml(&b).ok())
            .map(|(_, _, c)| c)
            .unwrap_or_default()
    }

    /// Build a [`CommitmentEntry`] for a 32-byte key under the vault's id.
    fn commitment_entry(&self, client_id: &str, epoch: u64, key: &[u8; 32]) -> CommitmentEntry {
        CommitmentEntry {
            epoch,
            commitment: manifest::encode_hex(&manifest::key_commitment(
                key,
                &self.vault_id,
                client_id,
                epoch,
            )),
        }
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
    /// to every recipient + recovery, sign the manifest. Works for the
    /// reserved [`SHARED_CLIENT_ID`] too (lands at `keys/shared/`).
    ///
    /// The recovery recipient comes from the [`Anchor`] (the off-vault
    /// pinned `recovery_age_recipient`), never from a caller-supplied
    /// string or an in-vault copy — a caller passing in a vault copy
    /// would let a compromised vault redirect the recovery wrapping.
    pub fn init_client(
        &mut self,
        client_id: &str,
        recipients: &RecipientMap,
        anchor: &Anchor,
        operator_sk: &SigningKey,
    ) -> Result<DataKey, Error> {
        let dir = self.manifest_dir(client_id);
        if dir.join("epoch").exists() {
            return Err(Error::Manifest(format!(
                "client {client_id} already initialized; use rotate"
            )));
        }
        std::fs::create_dir_all(dir.join("wrapped"))?;
        let key = DataKey::generate();
        self.write_epoch(client_id, 1)?;
        self.wrap_current(client_id, &key, recipients, anchor)?;
        let commitments = vec![self.commitment_entry(client_id, 1, key.as_bytes())];
        self.write_manifest(client_id, 1, recipients, &commitments, operator_sk)?;
        Ok(key)
    }

    /// Wrap the current-epoch data key to each recipient + recovery
    /// (the anchor's pinned recovery recipient).
    fn wrap_current(
        &self,
        client_id: &str,
        key: &DataKey,
        recipients: &RecipientMap,
        anchor: &Anchor,
    ) -> Result<(), Error> {
        let wdir = self.wrapped_dir(client_id);
        for (key_id, entry) in recipients {
            let wrapped = wrap_to_recipient(key.as_bytes(), &entry.age_pubkey)?;
            std::fs::write(wdir.join(format!("{key_id}.age")), wrapped)?;
        }
        let wrapped = wrap_to_recipient(key.as_bytes(), &anchor.recovery_age)?;
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
        let toml = manifest::to_toml(
            1,
            &map,
            &[self.commitment_entry(VAULT_CLIENT_ID, 1, key.as_bytes())],
        )?;
        let sig = manifest::sign(operator_sk, &self.vault_id, VAULT_CLIENT_ID, 1, 1, &toml);
        std::fs::write(vdir.join("recipients.toml"), toml)?;
        std::fs::write(vdir.join("recipients.sig"), sig)?;
        std::fs::write(vdir.join("epoch"), "1\n")?;
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
        let raw = Zeroizing::new(unwrap_with_identity(&wrapped, identity)?);
        if raw.len() != 32 {
            return Err(Error::Age("unwrapped key is not 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        // Authenticate the unwrapped key against the manifest's commitment.
        // Without this, anyone with push access could plant a wrapping of
        // an attacker-known key and the manifest would still verify.
        let expected = self
            .current_commitments(client_id)
            .into_iter()
            .find(|c| c.epoch == epoch)
            .ok_or_else(|| {
                Error::Manifest(format!(
                    "no key commitment for {client_id} epoch {epoch}; refusing unauthenticated key"
                ))
            })?;
        let expected_bytes = manifest::decode_hex(&expected.commitment)?;
        let computed = manifest::key_commitment(&arr, &self.vault_id, client_id, epoch);
        if !manifest::ct_eq(&computed, &expected_bytes) {
            // Zero the candidate before failing: it may be attacker-chosen.
            arr.zeroize();
            return Err(Error::Manifest(format!(
                "key commitment mismatch for {client_id} epoch {epoch}: \
                 the wrapping does not match the signed manifest; refusing"
            )));
        }
        Ok(DataKey::from_bytes(arr))
    }

    /// Rotate a client's data key: new key, `epoch += 1`, wrap to all
    /// current recipients + recovery, re-sign. Old wrappings are renamed to
    /// `.e<epoch>.age` so history stays readable. No re-encryption.
    ///
    /// The recovery recipient comes from the [`Anchor`], as in
    /// [`init_client`](Self::init_client).
    pub fn rotate(
        &mut self,
        client_id: &str,
        anchor: &Anchor,
        operator_sk: &SigningKey,
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
        self.wrap_current(client_id, &key, &recipients, anchor)?;
        self.write_epoch(client_id, new_epoch)?;
        // Carry forward prior epochs' commitments; append the new epoch's.
        let mut commitments = self.current_commitments(client_id);
        commitments.push(self.commitment_entry(client_id, new_epoch, key.as_bytes()));
        self.write_manifest(client_id, new_epoch, &recipients, &commitments, operator_sk)?;
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
        // Validate key ids BEFORE touching the manifest or wrappings:
        // "recovery" is reserved and can never be revoked.
        for id in revoked_key_ids {
            manifest::validate_key_id(id)?;
        }
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
        // Commitments are unchanged by revocation; carry them forward.
        let commitments = self.current_commitments(client_id);
        self.write_manifest(client_id, epoch, &recipients, &commitments, operator_sk)?;
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
        // Derive from manifest_dir so reserved ids (vault:lookup,
        // vault:shared) resolve to their real locations (keys/vault,
        // keys/shared) rather than keys/<client_id>.
        //
        // Git pathspecs need forward slashes, so join the components with
        // `/` explicitly instead of relying on the OS separator (which is
        // `\` on Windows). All components here are ASCII (keys/, the fixed
        // dir names, validated client ids), so this is exact.
        let rel = self
            .manifest_dir(client_id)
            .strip_prefix(repo)
            .map_err(|_| {
                Error::Manifest(format!("manifest dir for {client_id} is outside the vault"))
            })?
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
            + "/recipients.toml";
        let out = std::process::Command::new("git")
            // Never leak the device key into git/gpg/hooks via the environment.
            .env_remove("CONFIDANT_DEVICE_KEY")
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
                // Never leak the device key into git/gpg/hooks via the environment.
                .env_remove("CONFIDANT_DEVICE_KEY")
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
            if let Ok((_, map, _)) = manifest::from_toml(&show.stdout) {
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
        // The reserved vault-level ids are not shreddable: shredding
        // vault:lookup would destroy the alias key and leave the vault
        // half-mutated, and shredding vault:shared would destroy every org
        // record and person-less deal. Reject before the verify pass.
        if shredded_client == VAULT_CLIENT_ID || shredded_client == SHARED_CLIENT_ID {
            return Err(Error::Manifest(format!(
                "refusing to shred reserved client id {shredded_client:?}"
            )));
        }
        // Fail closed on a caller list that would strand a client: every
        // initialized directory under keys/ (other than the vault lookup
        // dir, which shred handles separately) must be in all_clients, or
        // it would stay wrapped only to keys the operator is told to
        // destroy. Check before changing anything.
        let mut initialized: Vec<String> = Vec::new();
        let entries = std::fs::read_dir(&self.keys_dir).map_err(Error::Io)?;
        for entry in entries {
            let entry = entry.map_err(Error::Io)?;
            if !entry.file_type().map_err(Error::Io)?.is_dir() {
                continue;
            }
            let dir_name = entry.file_name().to_string_lossy().into_owned();
            if dir_name == "vault" {
                continue;
            }
            if !entry.path().join("epoch").exists() {
                continue;
            }
            initialized.push(Self::client_id_for_dir(&dir_name).to_string());
        }
        for id in &initialized {
            if id != shredded_client && !all_clients.contains(&id.as_str()) {
                return Err(Error::Manifest(format!(
                    "shred would strand initialized client {id:?}: add it to all_clients or it stays wrapped to destroyed keys"
                )));
            }
        }
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
        let cdir = self.manifest_dir(shredded_client);
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
            // Keys are unchanged by the re-wrap, so commitments carry forward.
            let commitments = self.current_commitments(client);
            self.write_manifest(client, *epoch, new_recipients, &commitments, operator_sk)?;
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
    /// Returned in a [`Zeroizing`] wrapper so the bytes are wiped on drop.
    fn read_lookup_raw(&self, identity: &dyn age::Identity) -> Result<Zeroizing<Vec<u8>>, Error> {
        let vdir = self.keys_dir.join("vault");
        let wrapped = std::fs::read(vdir.join("lookup.age"))
            .map_err(|_| Error::NoKey("no vault lookup.age".to_string()))?;
        Ok(Zeroizing::new(unwrap_with_identity(&wrapped, identity)?))
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
            .map(|(s, _, _)| s)
            .unwrap_or(0)
            .max(
                self.seq
                    .as_ref()
                    .map(|t| t.high_water(&self.vault_id, VAULT_CLIENT_ID))
                    .unwrap_or(0),
            )
            + 1;
        let toml = manifest::to_toml(
            seq,
            new_recipients,
            &self.current_commitments(VAULT_CLIENT_ID),
        )?;
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
            // to bind the rotation — epoch unchanged. Keys don't change,
            // so carry the commitments forward.
            let commitments = self.current_commitments(client);
            self.write_manifest(client, epoch, &recipients, &commitments, operator_sk)?;
        }
        Ok(new_recovery)
    }

    /// Read the vault lookup key: verify the `vault:lookup` manifest against
    /// the anchor first (a planted `lookup.age` opens new alias HMACs to a
    /// dictionary attack), then unwrap and check the key commitment.
    /// Mismatch — or a missing commitment — is a hard error; no key is
    /// returned.
    pub fn read_lookup_key(
        &mut self,
        identity: &dyn age::Identity,
        anchor: &Anchor,
    ) -> Result<LookupKey, Error> {
        // Verify the vault manifest before touching the wrapping.
        let _ = self.verified_recipients(VAULT_CLIENT_ID, anchor)?;
        let raw = self.read_lookup_raw(identity)?;
        if raw.len() != 32 {
            return Err(Error::Age("lookup key is not 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        let expected = self
            .current_commitments(VAULT_CLIENT_ID)
            .into_iter()
            .find(|c| c.epoch == 1)
            .ok_or_else(|| {
                Error::Manifest(
                    "no key commitment for the vault lookup key; refusing unauthenticated key"
                        .to_string(),
                )
            })?;
        let expected_bytes = manifest::decode_hex(&expected.commitment)?;
        let computed = manifest::key_commitment(&arr, &self.vault_id, VAULT_CLIENT_ID, 1);
        if !manifest::ct_eq(&computed, &expected_bytes) {
            arr.zeroize();
            return Err(Error::Manifest(
                "lookup key commitment mismatch: the wrapping does not match \
                 the signed vault manifest; refusing"
                    .to_string(),
            ));
        }
        Ok(LookupKey::from_bytes(arr))
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
    /// must confirm it was written down and never log it. Returned wrapped
    /// in [`Zeroizing`] so the copy is wiped when dropped; the display site
    /// should deref it (`print!("{}", phrase.as_str())`). The only plaintext
    /// left is the terminal's own buffer.
    pub fn recovery_phrase_for_display(&self) -> Zeroizing<String> {
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
