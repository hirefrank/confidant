//! Key lifecycle: init, rotate, revoke, shred (design §§6, 8).
//!
//! Operates on the vault's `keys/` directory:
//!
//! ```text
//! keys/
//! ├── recovery-recipients.toml  # every recovery age recipient ever used (#153)
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
    self, CommitmentEntry, RecipientEntry, RecipientMap, SeqTracker, RECOVERY_KEY_ID,
    SHARED_CLIENT_ID, VAULT_CLIENT_ID,
};
use crate::recovery::Recovery;
use zeroize::Zeroizing;

/// A client's verified epoch keys, ready for re-wrapping (shred's verify-first pass).
/// Commitments come from the verified manifest buffer (see
/// [`KeyStore::verified_recipients`]).
type VerifiedEpochKeys<'a> = (&'a str, u64, Vec<(u64, DataKey)>, Vec<CommitmentEntry>);

/// True if `name` is a retained-epoch wrapping file: `<key-id>.e<digits>.age`.
/// Matches the `.e<digits>` suffix exactly so key ids that merely contain
/// ".e" are not mistaken for history files.
fn is_retained_epoch_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".age") else {
        return false;
    };
    let Some((_, suffix)) = stem.rsplit_once(".e") else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
}

/// File under `keys/` recording every recovery age recipient this vault has
/// ever wrapped a data key to (#153 nit 7). Append-only: [`KeyStore::shred`]
/// and [`KeyStore::rotate_recovery`] add to it on every recovery rotation,
/// and [`KeyStore::ever_seen_pubkeys`] reads the current file *and every
/// historical version from git*, so a retired recovery key can never be
/// re-enrolled as a device recipient (which would undo the shred).
const RECOVERY_HISTORY_FILE: &str = "recovery-recipients.toml";

/// Temp-file name prefix for the atomic write of [`RECOVERY_HISTORY_FILE`].
/// Matches the vault's `.confidant-tmp-` leftover convention so the CLI can
/// sweep a crash leftover before staging `keys/` (#156 nit 1).
pub const RECOVERY_HISTORY_TMP_PREFIX: &str = ".confidant-tmp-recovery-recipients-";

/// Parsed `keys/recovery-recipients.toml`. A missing or unparseable file is
/// treated as empty: the file is only ever a denylist, so a version we
/// cannot read contributes nothing (and the anchor's current recipient is
/// always added separately).
fn parse_recovery_recipients(text: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct RecoveryRecipients {
        recipients: Vec<String>,
    }
    toml::from_str::<RecoveryRecipients>(text)
        .map(|f| f.recipients)
        .unwrap_or_default()
}

/// Strict variant for the write path: an existing file that does not parse
/// is an error (never silently overwritten), so append-only really holds.
fn parse_recovery_recipients_strict(text: &str) -> Result<Vec<String>, Error> {
    #[derive(serde::Deserialize)]
    struct RecoveryRecipients {
        recipients: Vec<String>,
    }
    toml::from_str::<RecoveryRecipients>(text)
        .map(|f| f.recipients)
        .map_err(|e| Error::Manifest(format!("{RECOVERY_HISTORY_FILE} is not valid TOML: {e}")))
}

/// Manages the `keys/` tree of one vault.
#[derive(Debug)]
pub struct KeyStore {
    keys_dir: PathBuf,
    vault_id: String,
    /// Off-vault seq high-water marks. Required — see [`KeyStore::new`].
    seq: SeqTracker,
    /// Directory of the COMMITTED `keys/` tree, used for git-history
    /// lookups (historical manifests, shredded clients, recovery history).
    /// Defaults to `keys_dir`; the staged-swap flow (#175) points
    /// `keys_dir` at a staging copy while history must still read the
    /// committed tree — deriving the git pathspec from the staging path
    /// would silently return empty history and weaken the
    /// shredded-pubkey denylist.
    committed_keys_dir: PathBuf,
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
    /// Construct with the off-vault seq high-water tracker.
    ///
    /// The tracker is **required** (issue #134): without it the
    /// `seq < min_seq` replay refusal is a no-op, so there is no
    /// tracker-less constructor. A missing tracker *file* loads as "no
    /// marks yet" ([`SeqTracker::load`]), which is the normal fresh-device
    /// state — bootstrap needs no special case and no fail-open path.
    pub fn new(keys_dir: PathBuf, vault_id: &str, seq: SeqTracker) -> Self {
        let committed_keys_dir = keys_dir.clone();
        KeyStore {
            keys_dir,
            vault_id: vault_id.to_string(),
            seq,
            committed_keys_dir,
        }
    }

    /// Point git-history lookups at a different committed `keys/` tree
    /// while `keys_dir` stays the working tree. Used by the staged-swap
    /// flow (#175): the working tree is a staging copy, but history must
    /// read the committed tree. All other callers leave the default
    /// (`committed == working`) untouched.
    pub fn with_committed_keys_dir(mut self, dir: PathBuf) -> Self {
        self.committed_keys_dir = dir;
        self
    }

    /// Construct with the tracker loaded from its conventional location
    /// under `config_dir` (next to `trust.toml`; see
    /// [`manifest::seq_tracker_path`]). The single place that decides
    /// where the tracker lives for production callers.
    pub fn with_config_dir(
        keys_dir: PathBuf,
        vault_id: &str,
        config_dir: &std::path::Path,
    ) -> Result<Self, Error> {
        let tracker = SeqTracker::load(&manifest::seq_tracker_path(config_dir))?;
        Ok(Self::new(keys_dir, vault_id, tracker))
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

    /// Same as [`manifest_dir`](Self::manifest_dir) but rooted at the
    /// committed tree: git-history lookups derive their pathspec from
    /// this, never from the (possibly staged) working tree.
    fn committed_manifest_dir(&self, client_id: &str) -> PathBuf {
        if client_id == VAULT_CLIENT_ID {
            self.committed_keys_dir.join("vault")
        } else if client_id == SHARED_CLIENT_ID {
            self.committed_keys_dir.join("shared")
        } else {
            self.committed_keys_dir.join(client_id)
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
        manifest::validate_client_id(client_id)?;
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
    /// different error. An invalid client id also lands here: crypto
    /// operations on it fail closed (the [`KeyStore`] boundary refuses
    /// it), which is exactly what `doctor` should report as needing
    /// attention.
    pub fn manifest_state(&self, client_id: &str) -> ManifestState {
        if let Err(e) = manifest::validate_client_id(client_id) {
            return ManifestState::Corrupt(format!("invalid client id: {e}"));
        }
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
        self.seq.high_water(&self.vault_id, client_id)
    }

    fn advance_seq(&mut self, client_id: &str, seq: u64) -> Result<(), Error> {
        self.seq.advance(&self.vault_id, client_id, seq)
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
    ///
    /// Returns the epoch, the recipient map, and the key commitments —
    /// all parsed from the one buffer that was verified. Callers must use
    /// these commitments; re-reading `recipients.toml` from disk would
    /// trust bytes that were never verified (the file can change between
    /// the verify and the second read).
    pub fn verified_recipients(
        &mut self,
        client_id: &str,
        anchor: &Anchor,
    ) -> Result<(u64, RecipientMap, Vec<CommitmentEntry>), Error> {
        let (_seq, epoch, map, commitments) = self.verified_manifest(client_id, anchor)?;
        Ok((epoch, map, commitments))
    }

    /// Verify a client's manifest and return everything parsed from the one
    /// verified buffer: `(seq, epoch, recipients, commitments)`.
    ///
    /// [`verified_recipients`](Self::verified_recipients) drops the seq;
    /// this form exists for callers that must re-write the same manifest
    /// (the vault lookup key during `shred`) and so must take the seq from
    /// the verified bytes rather than re-reading the file — the file can
    /// change between the verify and the second read (#136 item 1).
    fn verified_manifest(
        &mut self,
        client_id: &str,
        anchor: &Anchor,
    ) -> Result<(u64, u64, RecipientMap, Vec<CommitmentEntry>), Error> {
        let parsed = self.verify_manifest_bytes(client_id, anchor)?;
        // Advance the high-water mark past what we just verified, and
        // return the commitments from the verified buffer — never re-read
        // the file.
        self.advance_seq(client_id, parsed.0)?;
        Ok(parsed)
    }

    /// Read and verify a client's manifest against the trust anchor without
    /// advancing (and therefore without persisting) the off-vault seq
    /// tracker.
    ///
    /// The replay check still compares against the current high-water mark;
    /// it just cannot move it. Used by `keys verify-recovery`, which must
    /// write nothing (including `~/.config/confidant/manifest-seq.toml`).
    fn verify_manifest_bytes(
        &self,
        client_id: &str,
        anchor: &Anchor,
    ) -> Result<(u64, u64, RecipientMap, Vec<CommitmentEntry>), Error> {
        manifest::validate_client_id(client_id)?;
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
        // Return the commitments from the verified buffer — never re-read
        // the file.
        let (seq, _, commitments) = manifest::from_toml(&toml)?;
        Ok((seq, epoch, map, commitments))
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
        manifest::validate_client_id(client_id)?;
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
        let (current_epoch, recipients, commitments) =
            self.verified_recipients(client_id, anchor)?;
        self.unwrap_verified(
            client_id,
            key_id,
            epoch,
            identity,
            current_epoch,
            &recipients,
            commitments,
        )
    }

    /// Trial-unwrap a data key without touching the off-vault seq tracker.
    ///
    /// Same verification and commitment check as [`unwrap_data_key`], but
    /// read-only: the manifest is verified against the current high-water
    /// mark without advancing it, so `keys verify-recovery` writes nothing.
    /// The returned key is [`DataKey`], which zeroizes on drop; callers
    /// must drop it immediately and never log, return, or cache it.
    pub fn trial_unwrap_data_key(
        &self,
        client_id: &str,
        key_id: &str,
        epoch: u64,
        identity: &dyn age::Identity,
        anchor: &Anchor,
    ) -> Result<DataKey, Error> {
        let (_seq, current_epoch, recipients, commitments) =
            self.verify_manifest_bytes(client_id, anchor)?;
        self.unwrap_verified(
            client_id,
            key_id,
            epoch,
            identity,
            current_epoch,
            &recipients,
            commitments,
        )
    }

    // Private helper for the two public unwrap paths; the manifest facts
    // are threaded through rather than re-read, so the argument list is
    // deliberately explicit.
    #[allow(clippy::too_many_arguments)]
    fn unwrap_verified(
        &self,
        client_id: &str,
        key_id: &str,
        epoch: u64,
        identity: &dyn age::Identity,
        current_epoch: u64,
        recipients: &RecipientMap,
        commitments: Vec<CommitmentEntry>,
    ) -> Result<DataKey, Error> {
        manifest::validate_client_id(client_id)?;
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
        // `Zeroizing`, so the candidate is wiped on drop whether the
        // commitment check passes or fails (#135): the success path used
        // to leave the key bytes on the stack.
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&raw);
        // Authenticate the unwrapped key against the manifest's commitment,
        // taken from the verified buffer above — never re-read from disk.
        // Without this, anyone with push access could plant a wrapping of
        // an attacker-known key and the manifest would still verify.
        let expected = commitments
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
            // No explicit zeroize needed: `arr` is `Zeroizing` and wipes on
            // this early return too (#135).
            return Err(Error::Manifest(format!(
                "key commitment mismatch for {client_id} epoch {epoch}: \
                 the wrapping does not match the signed manifest; refusing"
            )));
        }
        Ok(DataKey::from_bytes(*arr))
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
        manifest::validate_client_id(client_id)?;
        let (epoch, recipients, mut commitments) = self.verified_recipients(client_id, anchor)?;
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
        // Carry forward prior epochs' commitments (from the verified
        // buffer); append the new epoch's.
        commitments.push(self.commitment_entry(client_id, new_epoch, key.as_bytes()));
        self.write_manifest(client_id, new_epoch, &recipients, &commitments, operator_sk)?;
        Ok(key)
    }

    /// Re-wrap an existing client data key to a new recipient set, keeping
    /// the same key and epoch. Used by `recover` (and #66 device add) to
    /// authorize a new device without rotating the data key: existing
    /// ciphertext stays decryptable.
    ///
    /// The caller must have unwrapped `key` through a trusted path first
    /// (e.g. the recovery wrapping during `recover`). The manifest is
    /// re-signed with `signing_sk` (the operator key, or the recovery key —
    /// both are trust-anchor members). Old wrappings for recipients no
    /// longer in the set are removed.
    pub fn rewrap_recipients(
        &mut self,
        client_id: &str,
        key: &DataKey,
        recipients: &RecipientMap,
        anchor: &Anchor,
        signing_sk: &SigningKey,
    ) -> Result<(), Error> {
        manifest::validate_client_id(client_id)?;
        let (epoch, _, commitments) = self.verified_recipients(client_id, anchor)?;
        // Remove wrappings for recipients that are going away, then write
        // the new set. The recovery wrapping is always rewritten (its
        // recipient may have rotated).
        let wdir = self.wrapped_dir(client_id);
        let mut keep: std::collections::HashSet<String> =
            recipients.keys().map(|k| format!("{k}.age")).collect();
        keep.insert(format!("{RECOVERY_KEY_ID}.age"));
        for entry in std::fs::read_dir(&wdir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Only touch current-epoch wrappings; retained `.e<digits>`
            // history files are never removed here. Match the suffix
            // exactly — a loose `.e` substring check would also catch
            // key ids that merely contain ".e".
            if name.ends_with(".age") && !is_retained_epoch_file(&name) && !keep.contains(&name) {
                std::fs::remove_file(entry.path())?;
            }
        }
        self.wrap_current(client_id, key, recipients, anchor)?;
        // Commitments are unchanged (same key, same epoch); carry them
        // forward from the verified buffer.
        self.write_manifest(client_id, epoch, recipients, &commitments, signing_sk)?;
        Ok(())
    }

    /// Re-sign a client's manifest with a new key, changing nothing else.
    ///
    /// Verifies against `anchor` first (the manifest is still signed by
    /// the previous trust-anchor member), then writes the same epoch,
    /// recipients, and commitments with a bumped seq signed by
    /// `signing_sk`. Used when trust-anchor signing membership rotates:
    /// after `recover` re-pins the anchor to a new recovery key,
    /// manifests signed by the old recovery key must become verifiable
    /// against the new anchor before further key operations.
    pub fn resign_manifest(
        &mut self,
        client_id: &str,
        anchor: &Anchor,
        signing_sk: &SigningKey,
    ) -> Result<(), Error> {
        let (epoch, recipients, commitments) = self.verified_recipients(client_id, anchor)?;
        self.write_manifest(client_id, epoch, &recipients, &commitments, signing_sk)?;
        Ok(())
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
        // Validate the client id and the key ids BEFORE touching the
        // manifest or wrappings: the client id must be safe to join under
        // `keys/`, and "recovery" is reserved and can never be revoked.
        manifest::validate_client_id(client_id)?;
        for id in revoked_key_ids {
            manifest::validate_key_id(id)?;
        }
        let (epoch, mut recipients, commitments) = self.verified_recipients(client_id, anchor)?;
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
        // Commitments are unchanged by revocation; carry them forward
        // from the verified buffer.
        self.write_manifest(client_id, epoch, &recipients, &commitments, operator_sk)?;
        Ok(())
    }

    /// Add a new device recipient to every initialized client and the vault
    /// lookup key (#66, design §6).
    ///
    /// Re-wraps every initialized client's every retained epoch to include
    /// the new recipient (only the new recipient's wrapping files are
    /// added; existing wrappings are untouched), re-wraps the vault lookup
    /// key so the new device can compute alias HMACs, and re-signs every
    /// manifest. The lookup key is handed off, never regenerated and never
    /// recovery-wrapped (#142).
    ///
    /// Verify-first: the identity must open every client's every epoch and
    /// the lookup key before anything is mutated. Returns the ids of the
    /// clients updated.
    pub fn add_recipient(
        &mut self,
        new_key_id: &str,
        new_entry: &RecipientEntry,
        identity: &dyn age::Identity,
        anchor: &Anchor,
        signing_sk: &SigningKey,
    ) -> Result<Vec<String>, Error> {
        manifest::validate_key_id(new_key_id)?;
        // Parse the new pubkey now: a bad recipient fails before any mutation.
        let _: age::x25519::Recipient = new_entry
            .age_pubkey
            .parse()
            .map_err(|e| Error::Age(format!("bad new recipient pubkey: {e}")))?;

        // Initialized clients via manifest_clients() (same source as
        // recover and shred), excluding the vault lookup dir (handled
        // separately below).
        let clients: Vec<String> = self
            .manifest_clients()
            .into_iter()
            .filter(|c| c != VAULT_CLIENT_ID)
            .collect();

        struct VerifiedClient {
            client: String,
            epoch: u64,
            new_map: RecipientMap,
            epoch_keys: Vec<(u64, DataKey)>,
            commitments: Vec<CommitmentEntry>,
        }
        let mut verified: Vec<VerifiedClient> = Vec::new();
        for client in &clients {
            let (epoch, old_map, commitments) = self.verified_recipients(client, anchor)?;
            if old_map.contains_key(new_key_id) {
                return Err(Error::Manifest(format!(
                    "recipient {new_key_id:?} is already enrolled for {client}"
                )));
            }
            if old_map
                .values()
                .any(|e| e.age_pubkey == new_entry.age_pubkey)
            {
                return Err(Error::Manifest(format!(
                    "a recipient with this pubkey is already enrolled for {client}"
                )));
            }
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
            let mut new_map = old_map;
            new_map.insert(new_key_id.to_string(), new_entry.clone());
            verified.push(VerifiedClient {
                client: client.clone(),
                epoch,
                new_map,
                epoch_keys,
                commitments,
            });
        }

        // Blocker 2 (#151): refuse any pubkey that has EVER been a
        // recipient — current or historical manifest of any client, the
        // vault lookup map, or the recovery key (the same set shred's step
        // 2 builds, shared via ever_seen_pubkeys). A device re-sending its
        // original request after a shred would otherwise silently undo the
        // shred: the old private key still opens the shredded client's
        // wrappings in git history. Compares pubkeys, not just key ids.
        // Runs before any mutation.
        let all: Vec<String> = self.manifest_clients();
        let all_refs: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        let ever_seen = self.ever_seen_pubkeys(&all_refs, anchor)?;
        if ever_seen.contains(&new_entry.age_pubkey) {
            return Err(Error::Manifest(
                "this pubkey has already been a recipient of this vault; \
                 generate a fresh keypair with `keys device-add --initiate`"
                    .to_string(),
            ));
        }

        // Lookup key: read_lookup_key verifies the vault manifest, unwraps
        // with the identity, and checks the commitment — a planted
        // lookup.age fails closed here, before any mutation.
        let (lookup_key, lookup_commitments, lookup_seq) =
            self.read_lookup_key(identity, anchor)?;
        let (_, vault_map, _) = self.verified_recipients(VAULT_CLIENT_ID, anchor)?;
        if vault_map.contains_key(new_key_id) {
            return Err(Error::Manifest(format!(
                "recipient {new_key_id:?} is already enrolled for the vault lookup key"
            )));
        }
        let mut new_vault_map = vault_map;
        new_vault_map.insert(new_key_id.to_string(), new_entry.clone());

        // All checks passed: now mutate.
        for v in &verified {
            let wdir = self.wrapped_dir(&v.client);
            for (e, key) in &v.epoch_keys {
                let suffix = if *e == v.epoch {
                    String::new()
                } else {
                    format!(".e{e}")
                };
                let wrapped = wrap_to_recipient(key.as_bytes(), &new_entry.age_pubkey)?;
                std::fs::write(wdir.join(format!("{new_key_id}{suffix}.age")), wrapped)?;
            }
            // Keys are unchanged by the re-wrap, so commitments carry
            // forward from the verified buffer.
            self.write_manifest(&v.client, v.epoch, &v.new_map, &v.commitments, signing_sk)?;
        }
        self.write_lookup_raw(
            lookup_key.as_bytes(),
            &new_vault_map,
            &lookup_commitments,
            lookup_seq,
            signing_sk,
        )?;

        Ok(clients)
    }

    /// All historical versions of a client's recipient manifest, oldest
    /// first, from git history. Used by `shred` to build the complete
    /// destroy list: a recipient revoked earlier still has old wrappings in
    /// history that open the shredded client's historical data keys.
    fn historical_recipients(&self, client_id: &str) -> Result<Vec<RecipientMap>, Error> {
        // The committed keys dir is <vault>/keys; the repo root is its
        // parent. History reads use the COMMITTED tree, never the working
        // tree, which may be a staging copy (#175).
        let repo = self
            .committed_keys_dir
            .parent()
            .ok_or_else(|| Error::Manifest("keys dir has no parent; not a vault".to_string()))?;
        // Derive from committed_manifest_dir so reserved ids (vault:lookup,
        // vault:shared) resolve to their real locations (keys/vault,
        // keys/shared) rather than keys/<client_id>.
        //
        // Git pathspecs need forward slashes, so join the components with
        // `/` explicitly instead of relying on the OS separator (which is
        // `\` on Windows). All components here are ASCII (keys/, the fixed
        // dir names, validated client ids), so this is exact.
        let rel = self
            .committed_manifest_dir(client_id)
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
                "--full-history",
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
                    &format!("{sha}:./{rel}"),
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

    /// Client ids whose `keys/<dir>/recipients.toml` was deleted in git
    /// history — i.e. shredded clients. Their tree is gone, so
    /// [`manifest_clients`](Self::manifest_clients) no longer lists them,
    /// but their wrappings still exist in git history. Fails open to an
    /// empty list when git is unavailable (mirroring
    /// [`historical_recipients`](Self::historical_recipients)): without git
    /// there is no shredded history to consult.
    fn shredded_clients(&self) -> Vec<String> {
        // History reads use the COMMITTED tree (#175).
        let repo = match self.committed_keys_dir.parent() {
            Some(r) => r,
            None => return Vec::new(),
        };
        let out = std::process::Command::new("git")
            // Never leak the device key into git/gpg/hooks via the environment.
            .env_remove("CONFIDANT_DEVICE_KEY")
            .args([
                "-C",
                &repo.to_string_lossy(),
                "log",
                "--full-history",
                "--diff-filter=D",
                "--name-only",
                // Paths are repo-root-relative by default; make them
                // cwd-relative (the vault) so a vault inside a larger repo
                // still parses. Without this the `keys/` strip below never
                // matches and the shredded set silently comes back empty.
                "--relative",
                "--format=",
                "--end-of-options",
                "--",
                "keys/",
            ])
            .output();
        let Ok(out) = out else { return Vec::new() };
        if !out.status.success() {
            return Vec::new();
        }
        let mut ids = std::collections::BTreeSet::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // Only exact `keys/<dir>/recipients.toml` paths: the shredded
            // client's manifest. Anything else deleted under keys/ is not
            // a client tree.
            let rest = match line.trim().strip_prefix("keys/") {
                Some(r) => r,
                None => continue,
            };
            let (dir, file) = match rest.split_once('/') {
                Some((d, f)) if !d.is_empty() && !d.contains('/') => (d, f),
                _ => continue,
            };
            if file != "recipients.toml" {
                continue;
            }
            ids.insert(Self::client_id_for_dir(dir).to_string());
        }
        ids.into_iter().collect()
    }

    /// Every age pubkey that has ever been a recipient: the current and
    /// historical manifests of each listed client, the historical manifests
    /// of shredded (deleted-tree) clients, plus the recovery
    /// recipient. Shared by `shred` (step 2: no new recipient may reuse
    /// one, or the shredded history stays openable) and `add_recipient`
    /// (a re-sent device-add request after a shred must not silently undo
    /// the shred by re-wrapping to a key that still opens the shredded
    /// client's history). Callers choose the client list: `shred` passes
    /// its strand-checked `all_clients`; `add_recipient` passes every
    /// manifest client, including the vault lookup map — and compares
    /// pubkeys, not just key ids. Shredded clients are always included,
    /// since their trees are gone from `manifest_clients` but their
    /// wrappings persist in git history. A client id that was shredded and
    /// later re-initialized is both listed by the caller *and* in the
    /// shredded set, so its current verified manifest is read too (#153
    /// nit 1: skip the current read only when shredded and absent).
    fn ever_seen_pubkeys(
        &mut self,
        clients: &[&str],
        anchor: &Anchor,
    ) -> Result<std::collections::BTreeSet<String>, Error> {
        let mut seen = std::collections::BTreeSet::new();
        // Shredded clients' trees are deleted, so callers never list them;
        // their historical pubkeys still forbid reuse.
        let shredded = self.shredded_clients();
        let shredded_refs: Vec<&str> = shredded.iter().map(|s| s.as_str()).collect();
        for client in clients.iter().chain(shredded_refs.iter()) {
            for map in self.historical_recipients(client)? {
                seen.extend(map.values().map(|e| e.age_pubkey.clone()));
            }
            // A shredded client's tree is gone, so there is no current
            // manifest to verify; its history is what matters. But a client
            // id can be shredded and later RE-created (a fresh init with the
            // same id): then it is live again and must also contribute its
            // current verified manifest. Skip the current-manifest read only
            // when the client is shredded *and not currently present*.
            if shredded_refs.contains(client) && !clients.contains(client) {
                continue;
            }
            let (_, map, _) = self.verified_recipients(client, anchor)?;
            seen.extend(map.values().map(|e| e.age_pubkey.clone()));
        }
        seen.insert(anchor.recovery_age.clone());
        // Every recovery recipient this vault has ever wrapped to, from the
        // append-only history file (current + all git versions). Without
        // this, only the anchor's current recipient is forbidden and a
        // retired recovery key could be re-enrolled as a device (#153 nit 7).
        seen.extend(self.recovery_history_pubkeys());
        Ok(seen)
    }

    /// Recovery age recipients recorded in `keys/recovery-recipients.toml`:
    /// the current file plus every historical version from git, deduped.
    ///
    /// Read unverified, like [`historical_recipients`](Self::historical_recipients):
    /// this feeds a denylist, so a union that is only ever too large (never
    /// too small) is safe. Fails open to whatever versions it could read
    /// (git unavailable, shallow history, a file outside this repo) —
    /// matching `historical_recipients` and `shredded_clients`. Reading
    /// every version defeats a later commit that deletes entries: an entry
    /// that was ever committed stays in the set.
    fn recovery_history_pubkeys(&self) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let path = self.keys_dir.join(RECOVERY_HISTORY_FILE);
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.extend(parse_recovery_recipients(&text));
        }
        // History reads use the COMMITTED tree (#175).
        let Some(repo) = self.committed_keys_dir.parent() else {
            return out;
        };
        // Git pathspecs need forward slashes; the file name is fixed ASCII.
        let rel = format!("keys/{RECOVERY_HISTORY_FILE}");
        let log = std::process::Command::new("git")
            // Never leak the device key into git/gpg/hooks via the environment.
            .env_remove("CONFIDANT_DEVICE_KEY")
            .args([
                "-C",
                &repo.to_string_lossy(),
                "log",
                "--full-history",
                "--format=%H",
                "--end-of-options",
                "--",
                &rel,
            ])
            .output();
        let Ok(log) = log else { return out };
        if !log.status.success() {
            return out;
        }
        for sha in String::from_utf8_lossy(&log.stdout)
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let show = std::process::Command::new("git")
                // Never leak the device key into git/gpg/hooks via the environment.
                .env_remove("CONFIDANT_DEVICE_KEY")
                .args([
                    "-C",
                    &repo.to_string_lossy(),
                    "show",
                    &format!("{sha}:./{rel}"),
                ])
                .output();
            if let Ok(show) = show {
                if show.status.success() {
                    out.extend(parse_recovery_recipients(&String::from_utf8_lossy(
                        &show.stdout,
                    )));
                }
            }
        }
        out
    }

    /// Read-only view of every recovery age recipient this vault has ever
    /// wrapped to: the working-tree `keys/recovery-recipients.toml` plus
    /// every historical version from git.
    ///
    /// Used by `keys verify-recovery` to tell a retired phrase (recorded
    /// here by a later `recover` or `keys shred`) apart from a plain
    /// mismatch. The result is a denylist-style union: it only ever errs
    /// large. Writes nothing and does not touch the seq tracker.
    pub fn recovery_history(&self) -> std::collections::BTreeSet<String> {
        self.recovery_history_pubkeys()
    }

    /// Why the history-derived shred checks cannot be trusted on this vault,
    /// or `None` when git history is fully usable.
    ///
    /// [`ever_seen_pubkeys`](Self::ever_seen_pubkeys) unions the working
    /// tree with git history (`shredded_clients`,
    /// [`historical_recipients`](Self::historical_recipients), and the
    /// `recovery-recipients.toml` union). When `git` is missing, the vault
    /// is not a repo, the clone is shallow, or `git log` fails, those reads
    /// silently see only the working tree — the checks **fail open**. This
    /// lets callers surface that at runtime: `keys device-add --from-request`
    /// refuses (the denylist is load-bearing there), and `keys shred`,
    /// `recover`, and `doctor` warn.
    pub fn history_degraded_reason(&self) -> Option<String> {
        // History reads use the COMMITTED tree (#175).
        let repo = self.committed_keys_dir.parent()?;
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                // Never leak the device key into git/gpg/hooks via the environment.
                .env_remove("CONFIDANT_DEVICE_KEY")
                .arg("-C")
                .arg(repo)
                .args(args)
                .output()
        };
        let shallow = match git(&["rev-parse", "--is-shallow-repository"]) {
            Err(_) => {
                return Some(
                    "git is unavailable, so the shredded-client, historical-recipient, and \
                     retired-recovery-recipient checks cannot see history"
                        .to_string(),
                )
            }
            Ok(o) if !o.status.success() => {
                return Some(
                    "this vault is not a readable git repository, so the shredded-client, \
                     historical-recipient, and retired-recovery-recipient checks cannot see \
                     history"
                        .to_string(),
                )
            }
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim() == "true",
        };
        if shallow {
            return Some(
                "this is a shallow git clone, so the shredded-client, historical-recipient, \
                 and retired-recovery-recipient checks can only see the working tree"
                    .to_string(),
            );
        }
        match git(&["log", "-1", "--format=%H"]) {
            Ok(o) if o.status.success() => None,
            _ => Some(
                "git history is unreadable (git log failed), so the shredded-client, \
                 historical-recipient, and retired-recovery-recipient checks cannot see history"
                    .to_string(),
            ),
        }
    }

    /// Append recovery age recipients to `keys/recovery-recipients.toml`
    /// (deduped, insertion order), creating the file when absent. Called on
    /// every recovery rotation with both the retired and the new recipient,
    /// so the file always covers the current one too (a later keys/-tree
    /// rebuild does not depend on the anchor to supply it).
    fn record_recovery_recipients(&self, recipients: &[&str]) -> Result<(), Error> {
        let path = self.keys_dir.join(RECOVERY_HISTORY_FILE);
        // Fail closed on an existing-but-unparseable file: silently
        // rewriting it would drop entries the file is documented to keep
        // forever.
        let mut list = match std::fs::read_to_string(&path) {
            Ok(text) => parse_recovery_recipients_strict(&text)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::Io(e)),
        };
        for r in recipients {
            if !list.iter().any(|existing| existing == r) {
                list.push((*r).to_string());
            }
        }
        // Hand-format: stable, readable, and diff-friendly (one entry/line).
        let mut body = String::from(
            "# Every recovery age recipient this vault has ever wrapped to (#153).\n\
             # Append-only; readers union this across git history, so a retired\n\
             # recovery key can never be re-enrolled as a device.\n\
             recipients = [\n",
        );
        for r in &list {
            body.push_str(&format!("  {r:?},\n"));
        }
        body.push_str("]\n");
        // Temp file + rename in the same directory: a crash mid-write never
        // leaves a truncated denylist (mirrors the anchor's atomic write).
        // Named with the vault's `.confidant-tmp-` leftover prefix so the
        // CLI's pre-staging sweep recognizes it (#156 nit 1); removed here on
        // any write/rename error.
        let tmp = self.keys_dir.join(format!(
            "{RECOVERY_HISTORY_TMP_PREFIX}{}",
            std::process::id()
        ));
        if let Err(e) = std::fs::write(&tmp, &body) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        Ok(())
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
    ///
    /// **Re-pin the anchor before any other key operation.** `init_client`
    /// and `rotate` read the recovery recipient from the [`Anchor`], so a
    /// client initialized after a shred but before the anchor is re-pinned
    /// wraps to the recovery key this shred just destroyed — it then cannot
    /// be recovered from the new phrase.
    ///
    /// Pin [`ShredOutcome::new_recovery`]'s public halves (Ed25519 verifying
    /// key + X25519 age recipient) into the trust anchor immediately, then
    /// confirm the new phrase was written down.
    #[allow(clippy::too_many_arguments)] // 7-arg internal API; the edge
                                         // count rides along because the shred warnings must reflect the actual
                                         // deletion outcome. A params struct would churn all callers for no
                                         // behavioral gain.
    pub fn shred(
        &mut self,
        shredded_client: &str,
        all_clients: &[&str],
        new_recipients: &RecipientMap,
        operator_sk: &SigningKey,
        anchor: &Anchor,
        identity: &dyn age::Identity,
        deleted_edges: usize,
        stripped_interactions: usize,
    ) -> Result<ShredOutcome, Error> {
        // Validate every id this call will join under `keys/` before doing
        // anything: the shredded client, and each remaining client (the
        // strand check and re-wrap both build paths from them).
        manifest::validate_client_id(shredded_client)?;
        for client in all_clients {
            manifest::validate_client_id(client)?;
        }
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
        let (_, current_recipients, _) = self.verified_recipients(shredded_client, anchor)?;
        destroy_ids.extend(current_recipients.keys().cloned());
        let destroy_key_ids: Vec<String> = destroy_ids.into_iter().collect();

        // Verify EVERYTHING before changing any files. On failure here,
        // nothing has changed and the old keys still work.
        //
        // 1. The identity must open every remaining client's every epoch.
        // Commitments are captured from each verified manifest buffer.
        let mut to_rewrap: Vec<VerifiedEpochKeys> = Vec::new();
        for client in all_clients {
            if *client == shredded_client {
                continue;
            }
            let (epoch, old_map, commitments) = self.verified_recipients(client, anchor)?;
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
            to_rewrap.push((client, epoch, epoch_keys, commitments));
        }
        // 2. No new recipient pubkey may match any current or historical
        // recipient (including recovery): reusing a pubkey would keep the
        // old private key able to unwrap the shredded client's history.
        // (B5: do not weaken this check.)
        let old_pubkeys = self.ever_seen_pubkeys(all_clients, anchor)?;
        for (id, entry) in new_recipients {
            if old_pubkeys.contains(&entry.age_pubkey) {
                return Err(Error::Manifest(format!(
                    "new recipient {id} reuses a pubkey that already appears in history; \
                     generate fresh keypairs"
                )));
            }
        }
        // 3. The lookup key must unwrap with the identity AND match the
        // commitment in the verified vault manifest. read_lookup_key
        // verifies the manifest and checks the commitment — a planted
        // lookup.age fails closed here, before any mutation. (Client epoch
        // keys get the same check inside unwrap_data_key in step 1.)
        // The commitments come from the same verified buffer, so there is
        // no second manifest read.
        let (lookup_key, lookup_commitments, lookup_seq) =
            self.read_lookup_key(identity, anchor)?;

        // All checks passed: now mutate.
        let new_recovery = Recovery::generate();
        let new_recovery_recipient = new_recovery.age_identity().to_recipient_string();

        // Record the retired and the new recovery recipient (#153 nit 7)
        // BEFORE any mutation: a failure here leaves keys/ untouched, whereas
        // a failure after the re-wrap would strand a half-shredded tree.
        self.record_recovery_recipients(&[
            anchor.recovery_age.as_str(),
            new_recovery_recipient.as_str(),
        ])?;

        // 1. Delete the shredded client's key tree.
        let cdir = self.manifest_dir(shredded_client);
        if cdir.exists() {
            std::fs::remove_dir_all(&cdir)?;
        }

        // 2. Re-wrap every remaining client to the new set.
        for (client, epoch, epoch_keys, commitments) in &to_rewrap {
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
            // Keys are unchanged by the re-wrap, so commitments carry forward
            // from the verified buffer.
            self.write_manifest(client, *epoch, new_recipients, commitments, operator_sk)?;
        }
        // Lookup key: re-wrap the verified bytes to new recipients.
        self.write_lookup_raw(
            lookup_key.as_bytes(),
            new_recipients,
            &lookup_commitments,
            lookup_seq,
            operator_sk,
        )?;

        Ok(ShredOutcome {
            new_recovery,
            destroy_key_ids,
            warnings: leftover_warnings(deleted_edges, stripped_interactions),
        })
    }

    /// Read the raw lookup key bytes (for shred's verify-first pass).
    /// Returned in a [`Zeroizing`] wrapper so the bytes are wiped on drop.
    fn read_lookup_raw(&self, identity: &dyn age::Identity) -> Result<Zeroizing<Vec<u8>>, Error> {
        let vdir = self.keys_dir.join("vault");
        let wrapped = std::fs::read(vdir.join("lookup.age"))
            .map_err(|_| Error::NoKey("no vault lookup.age".to_string()))?;
        unwrap_with_identity(&wrapped, identity)
    }

    /// Write raw lookup key bytes re-wrapped to new recipients (for shred).
    /// `commitments` and `verified_seq` come from the caller, which verified
    /// the vault manifest (see [`KeyStore::verified_manifest`]); the seq is
    /// never re-read from disk.
    fn write_lookup_raw(
        &mut self,
        raw: &[u8],
        new_recipients: &RecipientMap,
        commitments: &[CommitmentEntry],
        verified_seq: u64,
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
        // The seq comes from the manifest buffer the caller already
        // verified (plus the off-vault high-water mark) — never a re-read
        // of the on-disk file, which could have changed since verification
        // (#136 item 1). `self.high_water` reads the mandatory tracker
        // directly (#134).
        let seq = verified_seq.max(self.high_water(VAULT_CLIENT_ID)) + 1;
        let toml = manifest::to_toml(seq, new_recipients, commitments)?;
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
    ///
    /// **Re-pin the anchor before any other key operation** ([`shred`]'s
    /// note applies here too): `init_client` and `rotate` read the
    /// recovery recipient from the anchor, so a stale anchor wraps new
    /// clients to the old recovery key.
    pub fn rotate_recovery(
        &mut self,
        clients: &[&str],
        operator_sk: &SigningKey,
        anchor: &Anchor,
        old_identity: &dyn age::Identity,
    ) -> Result<Recovery, Error> {
        // Validate every id before mutating: the loop below re-wraps as it
        // goes, so a bad id discovered mid-loop would leave the vault
        // half-rotated.
        for client in clients {
            manifest::validate_client_id(client)?;
        }
        let new_recovery = Recovery::generate();
        let new_recipient = new_recovery.age_identity().to_recipient_string();
        for client in clients {
            let (epoch, recipients, commitments) = self.verified_recipients(client, anchor)?;
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
            // so carry the commitments forward from the verified buffer.
            self.write_manifest(client, epoch, &recipients, &commitments, operator_sk)?;
        }
        // Record the retired and the new recovery recipient (#153 nit 7).
        self.record_recovery_recipients(&[anchor.recovery_age.as_str(), new_recipient.as_str()])?;
        Ok(new_recovery)
    }

    /// Read the vault lookup key: verify the `vault:lookup` manifest against
    /// the anchor first (a planted `lookup.age` opens new alias HMACs to a
    /// dictionary attack), then unwrap and check the key commitment.
    /// Mismatch — or a missing commitment — is a hard error; no key is
    /// returned.
    ///
    /// Returns the key, the commitments from the verified buffer, and the
    /// verified manifest seq (so a caller that re-writes the manifest —
    /// `shred` — never re-reads `recipients.toml`).
    pub fn read_lookup_key(
        &mut self,
        identity: &dyn age::Identity,
        anchor: &Anchor,
    ) -> Result<(LookupKey, Vec<CommitmentEntry>, u64), Error> {
        // Verify the vault manifest before touching the wrapping, and take
        // the commitments from the verified buffer — never re-read.
        let (seq, _, _, commitments) = self.verified_manifest(VAULT_CLIENT_ID, anchor)?;
        let raw = self.read_lookup_raw(identity)?;
        if raw.len() != 32 {
            return Err(Error::Age("lookup key is not 32 bytes".to_string()));
        }
        // `Zeroizing`: wiped on drop on both the success and the mismatch
        // path (#135).
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&raw);
        let expected = commitments.iter().find(|c| c.epoch == 1).ok_or_else(|| {
            Error::Manifest(
                "no key commitment for the vault lookup key; refusing unauthenticated key"
                    .to_string(),
            )
        })?;
        let expected_bytes = manifest::decode_hex(&expected.commitment)?;
        let computed = manifest::key_commitment(&arr, &self.vault_id, VAULT_CLIENT_ID, 1);
        if !manifest::ct_eq(&computed, &expected_bytes) {
            return Err(Error::Manifest(
                "lookup key commitment mismatch: the wrapping does not match \
                 the signed vault manifest; refusing"
                    .to_string(),
            ));
        }
        Ok((LookupKey::from_bytes(*arr), commitments, seq))
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
fn leftover_warnings(deleted_edges: usize, stripped_interactions: usize) -> Vec<String> {
    let mut warnings = vec![
        "Decrypted copies already on devices are not affected by shredding.".to_string(),
        ".confidant/ caches and search indexes on other devices may still hold plaintext (this device's index is deleted by shred)."
            .to_string(),
        "Old private keys may linger in OS keychains or OS backups — destroy them now.".to_string(),
        "Copies outside Confidant entirely (e.g. Drive transcripts) are not affected.".to_string(),
        "This shred issued a new recovery phrase. Destroy every copy of the old recovery phrase (paper, 1Password); until you do, it still opens history.".to_string(),
        "Inbox rotation is pending: this shred is not complete until `confidant inbox rotate --finish` has run on the inbox device; until then old form answers in history remain readable.".to_string(),
    ];
    // #179: edges live under the shared key, which survives shred, so
    // deletion only removes the working-tree copies. Say what actually
    // happened: the old static text claimed deletions even when none
    // existed (#179 review).
    if deleted_edges > 0 {
        warnings.push(format!(
            "{deleted_edges} edge(s) naming this person were deleted from the working tree, but earlier versions in git history remain readable with the shared key."
        ));
    } else {
        warnings.push(
            "No edges named this person, so none were deleted from the working tree. Note: edge versions already in git history remain readable with the shared key."
                .to_string(),
        );
    }
    // #258: interactions naming the shredded person were re-encrypted to
    // drop them from the `with:` list, but earlier versions still list
    // their id under the surviving primary's key.
    if stripped_interactions > 0 {
        warnings.push(format!(
            "{stripped_interactions} interaction(s) were re-encrypted to remove this person from their participant lists, but earlier versions in git history still list their id under the primary person's key."
        ));
    }
    warnings
}
