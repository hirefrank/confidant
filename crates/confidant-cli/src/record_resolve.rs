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
use crate::Side;

/// Both decrypted sides of a conflicted record, ready to print.
///
/// `ours_raw`/`theirs_raw` are the byte-exact reconstructed envelope bytes
/// (#451 guarantees byte-exactness), used by `--take` to install one side
/// without re-encryption (CD4). `raw` is the conflicted file's bytes as
/// read, kept so `--take` can restore them if the post-write check fails.
pub(crate) struct LoadedSides {
    /// Vault-relative path of the conflicted file.
    pub path: PathBuf,
    /// Decrypted bytes of the `<<<<<<<` side.
    pub ours_bytes: Vec<u8>,
    /// Decrypted bytes of the `>>>>>>>` side.
    pub theirs_bytes: Vec<u8>,
    /// Raw envelope bytes of the `<<<<<<<` side.
    pub ours_raw: Vec<u8>,
    /// Raw envelope bytes of the `>>>>>>>` side.
    pub theirs_raw: Vec<u8>,
    /// The conflicted file's bytes as read.
    pub raw: Vec<u8>,
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
        ours_raw: sides.ours.into_bytes(),
        theirs_raw: sides.theirs.into_bytes(),
        raw: bytes,
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

/// Outcome of `record resolve --take`: what to tell the operator next.
#[derive(Debug)]
pub(crate) struct TakeOutcome {
    /// The next git step for the operator, e.g. `git merge --continue`.
    pub next: String,
}

/// Install one side's envelope bytes byte for byte (CD4), verify the vault
/// still checks clean for this path, stage the file (CD6: stage only, never
/// commit), and return the next git step.
///
/// The chosen bytes were already verified by [`load_sides`] (both sides
/// parse as envelopes naming the id, with equal record types) and both
/// sides decrypted, so the operator has seen what they discard (CD7). No
/// re-encryption: the bytes are installed exactly as reconstructed.
///
/// If the post-write check reports an error on this path, the conflicted
/// file is restored byte for byte and nothing is staged.
pub(crate) fn take_side(
    root: &Path,
    no_input: bool,
    sides: &LoadedSides,
    side: Side,
) -> anyhow::Result<TakeOutcome> {
    take_side_with_check(root, no_input, sides, side, || {
        check_path_clean(root, &sides.path)
    })
}

/// [`take_side`] with the post-write check injected, so tests can force a
/// check failure and verify the rollback without crafting a failing vault.
fn take_side_with_check(
    root: &Path,
    no_input: bool,
    sides: &LoadedSides,
    side: Side,
    check: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<TakeOutcome> {
    let chosen: &[u8] = match side {
        Side::Ours => &sides.ours_raw,
        Side::Theirs => &sides.theirs_raw,
    };
    let rel = &sides.path;

    // CD4: atomic install of the chosen side's bytes, no re-encryption.
    // `write_replace` publishes via a sibling temp file plus rename and
    // removes the temp file if the write fails.
    confidant_core::paths::write_replace(root, rel, chosen).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "could not install the {} side of {}: {e}",
            side.name(),
            rel.display()
        )))
    })?;

    // The vault must check clean for this path; other files' findings do
    // not block. On failure, restore the conflicted bytes exactly and
    // refuse, leaving nothing staged.
    if let Err(failure) = check() {
        let _ = confidant_core::paths::write_replace(root, rel, &sides.raw);
        return Err(failure);
    }

    // CD6: stage only, never commit. On a staging failure, restore the
    // conflicted file rather than leaving a half-done write.
    if let Err(e) =
        confidant_core::write::git(root, &["add", "--", &rel.to_string_lossy()], no_input)
    {
        let _ = confidant_core::paths::write_replace(root, rel, &sides.raw);
        return Err(anyhow::Error::new(DomainError::internal(format!(
            "could not stage {}: {e}",
            rel.display()
        ))));
    }

    Ok(TakeOutcome {
        next: next_git_step(root),
    })
}

/// Reload the vault and require no error finding on `rel`.
fn check_path_clean(root: &Path, rel: &Path) -> anyhow::Result<()> {
    let vault = confidant_core::load_vault(root).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "could not reload the vault after installing {}: {e}",
            rel.display()
        )))
    })?;
    let report = confidant_core::check_vault(&vault, &confidant_core::CheckOptions::default());
    let rel_str = rel.to_string_lossy();
    if let Some(finding) = report.findings.iter().find(|f| {
        f.severity == confidant_core::Severity::Error && f.file.as_deref() == Some(rel_str.as_ref())
    }) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "installing the chosen side left {} with an error: {}",
                rel.display(),
                finding.message
            ))
            .with_fix("The conflicted file was restored; fix the underlying problem and retry"),
        ));
    }
    Ok(())
}

/// The next git step for the operator (CD6): `git merge --continue` while a
/// merge is in progress, `git rebase --continue` while a rebase is,
/// `git cherry-pick --continue` while a cherry-pick is, else `git commit`.
/// The git dir is resolved with `rev-parse --git-dir` rather than assuming
/// `.git` is a directory (worktrees, submodules).
fn next_git_step(root: &Path) -> String {
    let git_dir = confidant_core::write::git(root, &["rev-parse", "--git-dir"], true)
        .map(|s| root.join(s.trim()))
        .unwrap_or_else(|_| root.join(".git"));
    if git_dir.join("MERGE_HEAD").exists() {
        "git merge --continue".to_owned()
    } else if git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists() {
        "git rebase --continue".to_owned()
    } else if git_dir.join("CHERRY_PICK_HEAD").exists() {
        "git cherry-pick --continue".to_owned()
    } else {
        "git commit".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #454: a failing post-write check restores the conflicted file byte
    /// for byte and stages nothing. The check is injected (a failing
    /// closure) rather than crafted via a failing vault, as the issue
    /// allows.
    #[test]
    fn take_rolls_back_on_check_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap();

        let rel = PathBuf::from("people/p-01/record.md");
        let conflicted = b"<<<<<<< HEAD\nside-a\n=======\nside-b\n>>>>>>> branch\n";
        std::fs::create_dir_all(root.join("people/p-01")).unwrap();
        std::fs::write(root.join(&rel), conflicted).unwrap();

        let sides = LoadedSides {
            path: rel.clone(),
            ours_bytes: b"decrypted-a".to_vec(),
            theirs_bytes: b"decrypted-b".to_vec(),
            ours_raw: b"ENVELOPE-A".to_vec(),
            theirs_raw: b"ENVELOPE-B".to_vec(),
            raw: conflicted.to_vec(),
            ours_label: "HEAD".to_owned(),
            theirs_label: "branch".to_owned(),
        };

        let err = take_side_with_check(root, true, &sides, Side::Ours, || {
            // The chosen side is installed when the check runs.
            assert_eq!(std::fs::read(root.join(&rel)).unwrap(), b"ENVELOPE-A");
            Err(anyhow::anyhow!("injected check failure"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("injected check failure"));

        // The conflicted file is restored exactly.
        assert_eq!(std::fs::read(root.join(&rel)).unwrap(), conflicted);
        // Nothing staged: the check failed before `git add`. (The `people/`
        // directory itself is untracked; only the index matters.)
        let staged = std::process::Command::new("git")
            .args(["diff", "--cached", "--name-only"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&staged.stdout).trim().is_empty(),
            "nothing should be staged: {}",
            String::from_utf8_lossy(&staged.stdout)
        );
        // No temp files left behind.
        let mut temp_left = false;
        let mut stack = vec![root.join("people")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(entry.path());
                } else if name.starts_with(".confidant-tmp-") {
                    temp_left = true;
                }
            }
        }
        assert!(!temp_left, "no temp files should remain");
    }
}
