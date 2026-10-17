//! `record resolve` — operator-only merge-conflict resolution (#453, part of #219).
//!
//! [`load_sides`] is the shared "load the two sides" function: it derives
//! the record's file path from the id (never trusting a caller-supplied
//! path), requires git conflict markers, reconstructs both sides with
//! #451's [`conflict::split_conflict_sides`], parses each side as an
//! envelope, and decrypts both with the operator decryptor. Pure read path:
//! nothing is written, no scratch files, plaintext only ever goes to the
//! caller's stdout (the command prints it; this module only returns bytes).
//!
//! Fail-closed per side (CD7): a side this device cannot decrypt names the
//! side (`ours`/`theirs`) in the error and never leaks the other side's
//! plaintext. Error messages carry no file content.

use std::path::{Path, PathBuf};

use confidant_core::conflict;
use confidant_core::error::DomainError;
use confidant_core::id::RecordId;
use confidant_core::vault::ContentOutcome;
use confidant_crypt::envelope;

use crate::record_decrypt::RecordDecryptor;

/// Both decrypted sides of a conflicted record, ready to print.
pub(crate) struct LoadedSides {
    /// Vault-relative path of the conflicted file.
    pub path: PathBuf,
    /// Decrypted bytes of the `<<<<<<<` side.
    pub ours_bytes: Vec<u8>,
    /// Decrypted bytes of the `>>>>>>>` side.
    pub theirs_bytes: Vec<u8>,
    /// Label from the first hunk's `<<<<<<<` line (e.g. `HEAD`).
    pub ours_label: String,
    /// Label from the first hunk's `>>>>>>>` line (e.g. `feature/x`).
    pub theirs_label: String,
}

/// Load and decrypt both sides of the conflicted record `id`.
///
/// The file path is derived from the id via [`crate::main_path_for`]; notes
/// and packages are refused by [`crate::reject_unsupported_prefix`] before
/// any I/O. Both sides must parse as envelopes naming `id` with equal
/// `type`; both must decrypt with the operator key, else the error names
/// the failing side (CD7) and nothing is printed.
pub(crate) fn load_sides(
    root: &Path,
    vault_id: &str,
    id: &RecordId,
) -> anyhow::Result<LoadedSides> {
    crate::reject_unsupported_prefix(id)?;
    let rel = crate::main_path_for(id).ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(format!(
            "record resolve does not handle ids like {id}"
        )))
    })?;
    let bytes = std::fs::read(root.join(&rel)).map_err(|_| {
        anyhow::Error::new(DomainError::not_found(format!("no record with id {id}")))
            .context("use `confidant find <name>` to look up the id")
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        anyhow::Error::new(DomainError::invalid(format!(
            "{} is not valid UTF-8",
            rel.display()
        )))
    })?;
    if !confidant_core::record::has_conflict_markers(text) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("{} has no merge conflict", rel.display()))
                .with_fix("Use `confidant record show --for-edit` to read it"),
        ));
    }
    let sides = conflict::split_conflict_sides(text).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot split the conflict in {}: {e}",
            rel.display()
        )))
    })?;

    let ours_env = parse_side("ours", &sides.ours, &rel, id)?;
    let theirs_env = parse_side("theirs", &sides.theirs, &rel, id)?;
    if ours_env.record_type != theirs_env.record_type {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the two sides of {} have different record types",
            rel.display()
        ))));
    }

    // Operator decryptor: decrypts `no-ai` records in full, because the
    // operator is the reader (same as `record show --for-edit`).
    let decryptor = RecordDecryptor::for_edit(root, vault_id);
    let path_str = rel.to_string_lossy();
    let ours_bytes = decrypt_side(&decryptor, &path_str, "ours", id, sides.ours.as_bytes())?;
    let theirs_bytes = decrypt_side(&decryptor, &path_str, "theirs", id, sides.theirs.as_bytes())?;

    Ok(LoadedSides {
        path: rel,
        ours_bytes,
        theirs_bytes,
        ours_label: sides.ours_label,
        theirs_label: sides.theirs_label,
    })
}

/// Parse one reconstructed side as an envelope naming `id`.
fn parse_side(
    side: &str,
    text: &str,
    rel: &Path,
    id: &RecordId,
) -> anyhow::Result<envelope::Envelope> {
    let env = envelope::parse(text.as_bytes()).map_err(|_| {
        anyhow::Error::new(DomainError::invalid(format!(
            "the {side} side of {} is not an encrypted record",
            rel.display()
        )))
    })?;
    if env.id != id.to_string() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the {side} side of {} holds a different record ({})",
            rel.display(),
            env.id
        ))));
    }
    Ok(env)
}

/// Decrypt one side's envelope bytes. Fail closed naming the side (CD7):
/// a `Skipped` (no key) or `Refused` (tampered) outcome is an error, never
/// a silent omission, and the other side's plaintext is never printed.
fn decrypt_side(
    decryptor: &RecordDecryptor,
    path: &str,
    side: &str,
    id: &RecordId,
    bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match decryptor.decrypt_bytes(path, bytes) {
        ContentOutcome::Content(plaintext) => Ok(plaintext),
        ContentOutcome::NoAiShell { .. } => Err(anyhow::Error::new(DomainError::internal(
            format!("operator decryptor returned a no-ai shell for the {side} side of {id}"),
        ))),
        ContentOutcome::Skipped => Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "cannot decrypt the {side} side of {id}: this device cannot read it"
            ))
            .with_fix(
                "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
            ),
        )),
        ContentOutcome::Refused => Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "cannot decrypt the {side} side of {id}: the envelope failed authentication"
            ))
            .with_fix("The envelope is tampered or corrupt; restore it from git history"),
        )),
    }
}
