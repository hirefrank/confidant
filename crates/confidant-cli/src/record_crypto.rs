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
use std::collections::HashMap;
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
    /// #410: no-ai modes a write in flight is about to give to person
    /// records, keyed by person id. `encrypt_file` derives a child's
    /// outer header from the person records on disk, and the write layer
    /// encrypts every file in a changeset before any of them is written —
    /// so a person edit that re-stamps its children in the same commit
    /// would otherwise stamp them from the person's *old* mode. Each
    /// entry is the mode the person will have once the changeset is
    /// applied. Empty for every command except `record edit` on a person
    /// whose effective mode changes.
    mode_overrides: HashMap<String, envelope::NoAi>,
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
                    mode_overrides: HashMap::new(),
                }))
            }
        }
    }

    /// #410: supply the no-ai modes a write in flight is about to give to
    /// person records, so children encrypted in the same changeset are
    /// stamped from the person's *new* mode. See the `mode_overrides`
    /// field. Only `record edit` on a person whose mode changes uses this.
    pub fn with_mode_overrides(mut self, mode_overrides: HashMap<String, envelope::NoAi>) -> Self {
        self.mode_overrides = mode_overrides;
        self
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
        let existing = std::fs::read(&abs).ok();

        // Parsed before the stability decision below, because the effective
        // outer `no-ai` is part of what that decision needs (#406).
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
        // #181/#270: tri-state no-ai stamping. The record's own explicit
        // flag wins; otherwise the inherited default comes from every
        // person the front matter references — `person:`, `with:`, or any
        // other ID-valued (or ID-list) field. This must happen here: the
        // outer envelope header is all `find`/`context` ever see on an
        // encrypted record, so the read path's `inherits_notes_no_ai`
        // never sees the decrypted `related:`/`with:` fields.
        let own_mode = rec.no_ai_mode();
        let inherited = inherited_no_ai_mode(&self.root, &rec, Some(&self.mode_overrides));
        let outer_no_ai = stamp_no_ai(record_type, own_mode, inherited);

        if let Some(existing) = &existing {
            match stability_decision(existing, plaintext, outer_no_ai, &|b| {
                self.decrypt_existing(path, b)
            }) {
                StabilityOutcome::Reuse => return Ok(existing.clone()),
                // #389 Q4: `record edit` refuses an undecryptable envelope
                // (its own precheck, before any write). The remaining
                // callers — the shred path — keep treating it as changed,
                // so the re-encrypt fall-through below decides.
                StabilityOutcome::Reencrypt | StabilityOutcome::Undecryptable => {}
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
                            "Run `confidant init` (new vault), clone this vault and `confidant keys device-add`, or `confidant recover` only if every enrolled device is lost",
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
            // #285: the AAD binds this path byte-for-byte, and the read
            // path rebuilds it from `paths::display_relative` (forward
            // slashes). `Path::display()` renders backslashes on Windows,
            // so encrypt must normalize the same way or AEAD auth fails
            // on every Windows write.
            path: confidant_core::paths::display_relative(path),
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
            // #285: same normalization as `encrypt_file` — the AAD path
            // must match the encrypt-time spelling exactly.
            path: confidant_core::paths::display_relative(path),
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

/// #181: compute the envelope `no-ai` for a record being encrypted.
///
/// Pure decision function (unit-tested below); `encrypt_file` supplies the
/// inputs. Precedence (Q4):
/// - a `person` record carries its own mode on the envelope;
/// - a child's explicit `true` always hides;
/// - a child's explicit `false` overrides a `notes` default but never a
///   fully-hidden (`true`) person (B2 all-or-nothing preserved);
/// - otherwise the person's mode supplies the default: `true` hides all
///   children, `notes` hides notes/interactions, `false` hides nothing.
fn stamp_no_ai(
    record_type: &str,
    own_mode: Option<envelope::NoAi>,
    person_mode: envelope::NoAi,
) -> envelope::NoAi {
    use envelope::NoAi::{False, Notes, True};
    if record_type == "person" {
        return own_mode.unwrap_or(False);
    }
    match own_mode {
        Some(True) => True,
        Some(False) => {
            if person_mode == True {
                True
            } else {
                False
            }
        }
        // `notes` on a child is rejected by parse_record; fail closed if
        // one ever arrives here.
        Some(Notes) => True,
        None => {
            let inherits = person_mode == True
                || (person_mode == Notes && matches!(record_type, "note" | "interaction"));
            if inherits {
                True
            } else {
                False
            }
        }
    }
}

/// #410: the mode stamping gives a person record — the person branch of
/// [`stamp_no_ai`] — exposed so the `record edit` re-stamp planner reads
/// the person's new mode through the same rule instead of restating it.
pub(crate) fn person_own_mode(rec: &confidant_core::record::Record) -> envelope::NoAi {
    rec.no_ai_mode().unwrap_or(envelope::NoAi::False)
}

/// Read a person's `no-ai` mode from its plaintext outer header — the
/// envelope header when the profile is encrypted, the record front matter
/// otherwise. Never decrypts.
///
/// #410: `mode_overrides` carries the modes a write in flight is about to
/// give to person records (see [`RecordEncryptor::with_mode_overrides`]);
/// an override wins over the file on disk, which still holds the old mode
/// while the changeset is being encrypted. `None` for every read that is
/// not part of that write.
///
/// #181 version-skew rule: an unreadable or missing person header fails
/// closed — children are stamped hidden rather than visible. (The old
/// code returned `false` here.)
pub(crate) fn person_no_ai_mode(
    root: &Path,
    person: &str,
    mode_overrides: Option<&HashMap<String, envelope::NoAi>>,
) -> envelope::NoAi {
    if let Some(mode) = mode_overrides.and_then(|m| m.get(person)) {
        return *mode;
    }
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
                return rec.no_ai_mode().unwrap_or(envelope::NoAi::False);
            }
        }
        // The file exists but is neither a parseable envelope nor a
        // parseable record: fail closed instead of trying the next
        // candidate path (a corrupt profile must not read as visible).
        return envelope::NoAi::True;
    }
    // No candidate file found at all: fail closed.
    envelope::NoAi::True
}

/// #270: the `no-ai` default a record inherits from the people its front
/// matter references, for stamping the encrypted envelope's outer header.
///
/// The `person:` field keeps the #181 fail-closed lookup (a missing
/// profile hides). Any other field whose value is a record ID — or a
/// bracketed ID list like `with:`/`related:` — contributes `Notes` when it
/// resolves to an actual notes-mode person profile, and is ignored
/// otherwise: non-person IDs and dangling references never hide, mirroring
/// the read path's `inherits_notes_no_ai`. `True` is inherited only through
/// `person:`, matching `compute_cleared`'s taint filter, so a plaintext
/// vault and an encrypted vault clear the same records.
///
/// Merge-group peers are read-path only: stamp time sees the vault root,
/// not the merge components.
fn inherited_no_ai_mode(
    root: &Path,
    rec: &confidant_core::record::Record,
    mode_overrides: Option<&HashMap<String, envelope::NoAi>>,
) -> envelope::NoAi {
    use confidant_core::record::{parse_ref_id, parse_with_list, FrontmatterRef};
    use envelope::NoAi::{False, Notes, True};
    if let Some(person) = rec.field("person") {
        match person_no_ai_mode(root, person, mode_overrides) {
            True => return True,
            Notes => return Notes,
            False => {}
        }
    }
    let notes_ref = rec.fields.iter().any(|(key, value)| {
        if key == "person" || key == "no-ai" {
            return false;
        }
        match parse_ref_id(value) {
            FrontmatterRef::Id(id) => {
                referenced_person_mode(root, &id, mode_overrides) == Some(Notes)
            }
            _ => parse_with_list(value).is_some_and(|ids| {
                ids.iter()
                    .any(|id| referenced_person_mode(root, id, mode_overrides) == Some(Notes))
            }),
        }
    });
    if notes_ref {
        Notes
    } else {
        False
    }
}

/// `no-ai` mode of the person record `id`, or `None` when no person
/// profile exists for `id` — the reference points at a non-person record
/// or a dangling ID, and is ignored. A profile that exists but is
/// unreadable fails closed to `True` (#181).
fn referenced_person_mode(
    root: &Path,
    id: &confidant_core::id::RecordId,
    mode_overrides: Option<&HashMap<String, envelope::NoAi>>,
) -> Option<envelope::NoAi> {
    let id = id.to_string();
    if let Some(mode) = mode_overrides.and_then(|m| m.get(&id)) {
        return Some(*mode);
    }
    let bytes = [format!("people/{id}/profile.md"), format!("people/{id}.md")]
        .into_iter()
        .find_map(|candidate| std::fs::read(root.join(candidate)).ok())?;
    if let Ok(env) = envelope::parse(&bytes) {
        return Some(env.no_ai);
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Ok(rec) = confidant_core::record::parse_record(text, "profile.md") {
            return Some(rec.no_ai_mode().unwrap_or(envelope::NoAi::False));
        }
    }
    Some(envelope::NoAi::True)
}

/// B3 stability decision for one existing file. `decrypt` maps envelope
/// bytes to inner plaintext. Returns:
/// - `Reuse`: existing is an envelope decrypting to exactly `plaintext`
///   \u2014 keep the bytes byte-for-byte (no new nonce, no diff);
/// - `Reencrypt`: envelope with different content \u2014 re-encrypt;
/// - `Undecryptable`: envelope this device cannot decrypt (missing key,
///   shredded client, or tampered body) \u2014 #389 Q4. `record edit` fails
///   closed on this (its own precheck refuses first); writers that may
///   proceed, such as the shred path, treat it as changed;
/// - `PlaintextExists`: existing is not an envelope \u2014 the caller
///   fails closed (\u26a01: never encrypt in place).
#[derive(Debug, PartialEq, Eq)]
enum StabilityOutcome {
    Reuse,
    Reencrypt,
    Undecryptable,
    PlaintextExists,
}

fn stability_decision(
    existing: &[u8],
    plaintext: &[u8],
    outer_no_ai: envelope::NoAi,
    decrypt: &dyn Fn(&[u8]) -> anyhow::Result<Vec<u8>>,
) -> StabilityOutcome {
    if !crypto_mode::is_envelope_bytes(existing) {
        return StabilityOutcome::PlaintextExists;
    }
    // #406: the outer `no-ai` is derived from the person records on disk, so
    // it can move while the body stays the same — a person's mode changed
    // after this child was written. Reusing on the body alone would keep the
    // stale header, so the header has to match as well.
    if !envelope::parse(existing).is_ok_and(|env| env.no_ai == outer_no_ai) {
        return StabilityOutcome::Reencrypt;
    }
    match decrypt(existing) {
        Ok(inner) if inner == plaintext => StabilityOutcome::Reuse,
        Ok(_) => StabilityOutcome::Reencrypt,
        // #389 Q4: a decrypt failure is its own outcome, not "changed" —
        // it may mean a shredded or missing client key, which `record
        // edit` must refuse rather than re-encrypt blindly.
        Err(_) => StabilityOutcome::Undecryptable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envelope::NoAi::{False, Notes, True};

    #[test]
    fn stamp_no_ai_precedence() {
        // Persons carry their own mode.
        assert_eq!(stamp_no_ai("person", Some(Notes), False), Notes);
        assert_eq!(stamp_no_ai("person", Some(True), False), True);
        assert_eq!(stamp_no_ai("person", None, False), False);
        // Explicit child true always hides.
        assert_eq!(stamp_no_ai("note", Some(True), False), True);
        assert_eq!(stamp_no_ai("note", Some(True), Notes), True);
        assert_eq!(stamp_no_ai("note", Some(True), True), True);
        // Explicit child false overrides the notes default, but never a
        // fully-hidden person.
        assert_eq!(stamp_no_ai("note", Some(False), Notes), False);
        assert_eq!(stamp_no_ai("note", Some(False), False), False);
        assert_eq!(stamp_no_ai("note", Some(False), True), True);
        // Inherited defaults.
        assert_eq!(stamp_no_ai("note", None, True), True);
        assert_eq!(stamp_no_ai("interaction", None, True), True);
        assert_eq!(stamp_no_ai("note", None, Notes), True);
        assert_eq!(stamp_no_ai("interaction", None, Notes), True);
        assert_eq!(stamp_no_ai("note", None, False), False);
        // The notes default covers notes/interactions only — deals keep
        // the old behavior (only a true-mode person hides them).
        assert_eq!(stamp_no_ai("deal", None, Notes), False);
        assert_eq!(stamp_no_ai("deal", None, True), True);
        assert_eq!(stamp_no_ai("deal", None, False), False);
    }

    #[test]
    fn inherited_no_ai_mode_follows_any_person_reference() {
        // #270: stamp-time inheritance covers `person:`, `with:`, and any
        // other ID-valued or ID-list field — but only references that
        // resolve to an actual person profile.
        use confidant_core::record::parse_record;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let ada = "p-01J9Z3K4QG1000000000000000"; // notes mode
        let bob = "p-01J9Z3K4QG2000000000000000"; // visible
        for (id, mode) in [(ada, "no-ai: notes\n"), (bob, "")] {
            let dir = root.join(format!("people/{id}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("profile.md"),
                format!("---\nid: {id}\ntype: person\nname: X\n{mode}---\nBio.\n"),
            )
            .unwrap();
        }
        let note = |fm: &str| {
            parse_record(
                &format!("---\nid: n-01J9Z3K4QF1000000000000000\ntype: note\n{fm}---\nBody.\n"),
                "note.md",
            )
            .unwrap()
        };
        // `person:` keeps the #181 behavior.
        assert_eq!(
            inherited_no_ai_mode(root, &note(&format!("person: {ada}\n")), None),
            Notes
        );
        assert_eq!(
            inherited_no_ai_mode(root, &note(&format!("person: {bob}\n")), None),
            False
        );
        // Any other single-ID field counts.
        assert_eq!(
            inherited_no_ai_mode(root, &note(&format!("related: {ada}\n")), None),
            Notes
        );
        // Bracketed ID lists count, on notes as well as interactions.
        assert_eq!(
            inherited_no_ai_mode(root, &note(&format!("related: [{bob}, {ada}]\n")), None),
            Notes
        );
        assert_eq!(
            inherited_no_ai_mode(root, &note(&format!("with: [{ada}]\n")), None),
            Notes
        );
        // Non-person IDs and dangling references never hide.
        assert_eq!(
            inherited_no_ai_mode(root, &note("related: d-01J9Z3K4QD1000000000000000\n"), None),
            False
        );
        assert_eq!(
            inherited_no_ai_mode(root, &note("related: p-01J9Z3K4QG9000000000000000\n"), None),
            False
        );
        // A visible `person:` plus a notes-mode `related:` still hides.
        assert_eq!(
            inherited_no_ai_mode(
                root,
                &note(&format!("person: {bob}\nrelated: {ada}\n")),
                None
            ),
            Notes
        );
    }

    fn envelope_bytes() -> Vec<u8> {
        b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e0\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n".to_vec()
    }

    #[test]
    fn rewrite_unchanged_keeps_ciphertext_bytes() {
        // B3: envelope decrypting to the same plaintext -> reuse bytes.
        let existing = envelope_bytes();
        let plaintext = b"inner";
        let out = stability_decision(
            existing.as_slice(),
            plaintext,
            envelope::NoAi::False,
            &|_| Ok(plaintext.to_vec()),
        );
        assert_eq!(out, StabilityOutcome::Reuse);
    }

    #[test]
    fn changed_content_reencrypts() {
        let existing = envelope_bytes();
        let out = stability_decision(
            existing.as_slice(),
            b"inner",
            envelope::NoAi::False,
            &|_| Ok(b"different".to_vec()),
        );
        assert_eq!(out, StabilityOutcome::Reencrypt);
    }

    #[test]
    fn failed_decrypt_is_undecryptable() {
        // #389 Q4: a failed decrypt is its own outcome, so callers can
        // fail closed (`record edit`) instead of silently re-encrypting a
        // record they cannot read.
        let existing = envelope_bytes();
        let out = stability_decision(
            existing.as_slice(),
            b"inner",
            envelope::NoAi::False,
            &|_| anyhow::bail!("tampered"),
        );
        assert_eq!(out, StabilityOutcome::Undecryptable);
    }

    #[test]
    fn plaintext_existing_is_fail_closed() {
        // \u26a01 guard: an existing plaintext file is never encrypted in
        // place — the caller fails closed.
        let existing = b"---\nid: p-01ABC\ntype: person\n---\n\nBio.\n";
        let out = stability_decision(
            existing.as_slice(),
            b"inner",
            envelope::NoAi::False,
            &|_| Ok(b"inner".to_vec()),
        );
        assert_eq!(out, StabilityOutcome::PlaintextExists);
    }

    #[test]
    fn moved_header_reencrypts_even_when_the_body_is_unchanged() {
        // #406: the stored header says `no-ai: false`, but the effective
        // value has moved (a referenced person's mode changed). Reusing the
        // bytes would keep the stale header, so re-encrypt instead.
        let existing = envelope_bytes();
        let out = stability_decision(existing.as_slice(), b"inner", envelope::NoAi::True, &|_| {
            Ok(b"inner".to_vec())
        });
        assert_eq!(out, StabilityOutcome::Reencrypt);
    }
}
