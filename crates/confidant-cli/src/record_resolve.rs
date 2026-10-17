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
    /// For an inbox-sourced read (#457), the inbox branch tip the item was
    /// read at. The write actions verify that exact commit
    /// ([`confidant_core::verify_inbox_trust`]) instead of re-resolving the
    /// branch. `None` for the conflict-marker source.
    pub inbox_tip: Option<String>,
}

/// Where the two sides of a conflict come from.
///
/// `Markers` is the git-conflict-markers source (#451): both sides are
/// reconstructed from the conflicted file. `InboxItem` is the inbox
/// source (#457): `ours` is the current record on main, `theirs` is the
/// inbox item's plaintext.
pub(crate) enum Source {
    Markers,
    InboxItem(String),
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
    load_sides_inner(root, vault_id, id, &Source::Markers, None)
}

/// Load both sides for `record resolve --from-inbox <stem>` (#457).
///
/// `ours` is the current record on main, decrypted with the operator key;
/// `theirs` is the inbox item's plaintext (decrypted with the same inbox
/// key path the drain uses). The item must be a record item targeting this
/// record's path; an item for a missing record is not a conflict and is
/// refused (the drain would merge it cleanly).
pub(crate) fn load_sides_from_inbox(
    root: &Path,
    vault_id: &str,
    id: &RecordId,
    stem: &str,
    decrypt: &confidant_core::inbox::DecryptFn,
) -> anyhow::Result<LoadedSides> {
    load_sides_inner(
        root,
        vault_id,
        id,
        &Source::InboxItem(stem.to_string()),
        Some(decrypt),
    )
}

fn load_sides_inner(
    root: &Path,
    vault_id: &str,
    id: &RecordId,
    source: &Source,
    inbox_decrypt: Option<&confidant_core::inbox::DecryptFn>,
) -> anyhow::Result<LoadedSides> {
    match source {
        Source::Markers => load_sides_from_markers(root, vault_id, id),
        Source::InboxItem(stem) => {
            let decrypt = inbox_decrypt.expect("inbox source needs the inbox decrypt closure");
            load_sides_from_inbox_inner(root, vault_id, id, stem, decrypt)
        }
    }
}

/// The original `load_sides` body, for the markers source.
fn load_sides_from_markers(
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
        inbox_tip: None,
    })
}

/// Load both sides for the inbox source (#457).
///
/// `ours` is the current record file on main, decrypted with the operator
/// decryptor (fail-closed per side, CD7). `theirs` is the inbox item's
/// plaintext content. The item must be a record item whose path is this
/// record's path; anything else is not a conflict and is refused.
fn load_sides_from_inbox_inner(
    root: &Path,
    vault_id: &str,
    id: &RecordId,
    stem: &str,
    decrypt: &confidant_core::inbox::DecryptFn,
) -> anyhow::Result<LoadedSides> {
    crate::reject_unsupported_prefix(id)?;
    let rel = crate::main_path_for(id).ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(format!(
            "record resolve does not handle ids like {id}"
        )))
    })?;
    // The record must exist: an inbox item for a missing record is not a
    // conflict (the drain merges it cleanly).
    let current = std::fs::read(root.join(&rel)).map_err(|_| {
        anyhow::Error::new(
            DomainError::invalid(format!(
                "no record with id {id} on main; nothing to resolve"
            ))
            .with_fix("The inbox item targets a missing record; run `confidant inbox` to merge it"),
        )
    })?;
    let item = confidant_core::inbox::read_inbox_item(root, stem, decrypt)?;
    // Pin the tip the item was read at (#457 review): the trust check
    // verifies this commit, and refuses if the branch has moved since.
    let item_tip = item.tip.clone();
    if item.kind != "record" {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "inbox item '{stem}' is a {} item, not a record",
                item.kind
            ))
            .with_fix("Only record items can conflict with a record"),
        ));
    }
    let item_path = item.path.as_ref().ok_or_else(|| {
        anyhow::Error::new(DomainError::internal(format!(
            "inbox item '{stem}' is a record item without a path"
        )))
    })?;
    if item_path != &rel {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "inbox item '{stem}' targets {}, not {id}",
                item_path.display()
            ))
            .with_fix("Pass the id of the record the item targets"),
        ));
    }

    // Ours: decrypt the current record with the operator decryptor.
    // Same fail-closed per-side behaviour as the markers source (CD7).
    let decryptor = RecordDecryptor::for_edit(root, vault_id);
    let path_str = rel.to_string_lossy();
    let ours_bytes = decrypt_side(&decryptor, &path_str, "ours", id, &current)?;

    // Theirs: the item's plaintext. The inbox transport (age) is already
    // removed by `read_inbox_item`; the content is the record plaintext
    // the drain would merge.
    let theirs_bytes = item.content.into_bytes();

    // Labels for `--show`: the current branch for ours, the inbox stem
    // for theirs.
    let ours_label = confidant_core::write::git(root, &["branch", "--show-current"], true)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "current".to_string());

    Ok(LoadedSides {
        path: rel,
        ours_bytes,
        theirs_bytes: theirs_bytes.clone(),
        ours_raw: current.clone(),
        // No envelope on the theirs side: the item is plaintext. `--take`
        // never installs these bytes directly (it re-encrypts through the
        // #455 apply path); they are kept for symmetry only.
        theirs_raw: theirs_bytes,
        raw: current,
        ours_label,
        theirs_label: format!("inbox:{stem}"),
        // Pinned tip (#457 review): the write actions verify this exact
        // commit, not whatever the branch points at later.
        inbox_tip: Some(item_tip),
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

/// Outcome of `record resolve --merged-file` / `--edit`: what was staged.
#[derive(Debug)]
pub(crate) struct MergeOutcome {
    /// The next git step for the operator, e.g. `git merge --continue`.
    pub next: String,
    /// Vault-relative path of the resolved record.
    pub path: PathBuf,
}

/// Guard for `--edit` scratch files (#455, CD5).
///
/// Zero-overwrites each file (same length), syncs, removes the files and
/// the directory on drop. [`ScratchGuard::cleanup`] can also be called
/// explicitly on the success path (after which drop is a no-op). Every
/// file is attempted even if one fails; errors are swallowed so cleanup
/// never masks the original result.
#[cfg(unix)]
pub(crate) struct ScratchGuard {
    dir: PathBuf,
    files: Vec<PathBuf>,
}

#[cfg(unix)]
impl ScratchGuard {
    pub(crate) fn new(dir: PathBuf, files: Vec<PathBuf>) -> Self {
        ScratchGuard { dir, files }
    }

    /// Zero-overwrite, sync, and remove every file, then remove the dir.
    pub(crate) fn cleanup(&mut self) {
        use std::io::Write;
        for file in &self.files {
            if let Ok(len) = std::fs::metadata(file).map(|m| m.len()) {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(file) {
                    let zeros = vec![0u8; len as usize];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
            }
            let _ = std::fs::remove_file(file);
        }
        // Remove the dir recursively: the editor may have left untracked
        // files (e.g. test artifacts). Tracked files were zeroed above.
        let _ = std::fs::remove_dir_all(&self.dir);
        // Try to remove the parent `conflicts/` dir if it's now empty.
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        self.files.clear();
    }
}

#[cfg(unix)]
impl Drop for ScratchGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Refuse any `--merged-file` path inside the vault tree (CD5).
///
/// The operator's merged file must live outside the vault so a plaintext
/// merge file cannot be committed by accident. There is no `.confidant/`
/// exception. Symlinks and `..` segments are resolved via canonicalization,
/// so a path that resolves into the vault is refused too.
pub(crate) fn refuse_vault_path(root: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            path.display()
        )))
    })?;
    let canonical_root = root.canonicalize().map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot resolve vault root {}: {e}",
            root.display()
        )))
    })?;
    if canonical.starts_with(&canonical_root) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "refusing to read a merge file inside the vault: {}",
                path.display()
            ))
            .with_fix("Put the merged file outside the vault tree"),
        ));
    }
    Ok(canonical)
}

/// Remove a stale `.confidant/conflicts/` dir left by a crashed
/// `resolve --edit` (#455, CD5). Best-effort: files are zero-overwritten
/// before the tree is removed, and every file is attempted.
pub(crate) fn sweep_stale_scratch(root: &Path) {
    use std::io::Write;
    let dir = root.join(".confidant").join("conflicts");
    if !dir.exists() {
        return;
    }
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(len) = std::fs::metadata(&p).map(|m| m.len()) {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&p) {
                    let zeros = vec![0u8; len as usize];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Apply a merged record (#455).
///
/// Encrypts each planned change through the vault's [`RecordEncryptor`]
/// (the same encryptor `record edit` uses, with the prepared mode
/// overrides), writes each envelope atomically, verifies no error finding
/// on any changed path (rolling everything back on failure, as #454
/// does), then stages every changed path (CD6: stage only, never commit).
///
/// `prepared` comes from the shared [`crate::prepare_record_write`].
/// Returns the next git step for the operator.
pub(crate) fn apply_merge(
    root: &Path,
    no_input: bool,
    vault: &confidant_core::vault::Vault,
    prepared: &crate::PreparedWrite,
) -> anyhow::Result<MergeOutcome> {
    use confidant_core::write::FileChange;

    // The same encryptor `record edit` uses, with the #410 mode overrides
    // from the shared planner. `None` on a plaintext vault: contents are
    // written as-is.
    let enc = crate::record_crypto::RecordEncryptor::for_vault(root, vault)?
        .map(|e| e.with_mode_overrides(prepared.mode_overrides.clone()));

    // Save every original for rollback before writing anything.
    let mut originals: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for change in &prepared.pending.changes {
        let FileChange::WriteFile { path, .. } = change else {
            continue;
        };
        let bytes = std::fs::read(root.join(path)).unwrap_or_default();
        originals.push((path.clone(), bytes));
    }

    // Encrypt (or pass through) and install each change atomically.
    for change in &prepared.pending.changes {
        let FileChange::WriteFile { path, contents } = change else {
            continue;
        };
        let bytes = match &enc {
            Some(e) => e.encrypt_file(path, contents.as_bytes())?,
            None => contents.as_bytes().to_vec(),
        };
        confidant_core::paths::write_replace(root, path, &bytes).map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "could not write {}: {e}",
                path.display()
            )))
        })?;
    }

    // Every changed path must check clean; on failure restore all
    // originals byte for byte and refuse, leaving nothing staged.
    let mut failed: Option<anyhow::Error> = None;
    for (path, _) in &originals {
        if let Err(e) = check_path_clean(root, path) {
            failed = Some(e);
            break;
        }
    }
    if let Some(e) = failed {
        for (path, bytes) in &originals {
            let _ = confidant_core::paths::write_replace(root, path, bytes);
        }
        return Err(e);
    }

    // CD6: stage only, never commit. On a staging failure restore the
    // originals rather than leaving a half-done write.
    for (path, _) in &originals {
        if let Err(e) =
            confidant_core::write::git(root, &["add", "--", &path.to_string_lossy()], no_input)
        {
            for (p, b) in &originals {
                let _ = confidant_core::paths::write_replace(root, p, b);
            }
            return Err(anyhow::Error::new(DomainError::internal(format!(
                "could not stage {}: {e}",
                path.display()
            ))));
        }
    }

    Ok(MergeOutcome {
        next: next_git_step(root),
        path: prepared.rel.clone(),
    })
}

/// The rekey report for a merge, exactly when `record edit` would report
/// one: the merged record's client differs from the ours side's client
/// (the local state the merge starts from). Returns `None` when they
/// agree, or when either client cannot be determined (fail closed: no
/// wrong report).
pub(crate) fn rekeyed_for_merge(
    sides: &LoadedSides,
    rec: &confidant_core::record::Record,
) -> Option<(String, String)> {
    let ours_env = envelope::parse(&sides.ours_raw).ok()?;
    let from = envelope::key_id_client(&ours_env.key_id).ok()?;
    let to = crate::record_client_id(rec).ok()?;
    if from != to {
        Some((from, to))
    } else {
        None
    }
}

/// Set up `--edit` scratch files (CD5, unix only).
///
/// Creates `.confidant/conflicts/<id>/` (0700) with `ours.md`, `theirs.md`,
/// and `merged.md` (0600), pre-filling `merged.md` with the ours plaintext.
/// `.confidant/` must already be git-ignored (checked via
/// [`crate::ensure_corpus_gitignored`]); otherwise the edit is refused so
/// plaintext can never be committed by accident.
///
/// Returns the guard (which zero-overwrites and removes everything on
/// drop) and the path to `merged.md` for the editor.
#[cfg(unix)]
pub(crate) fn setup_edit_scratch(
    root: &Path,
    id: &RecordId,
    sides: &LoadedSides,
) -> anyhow::Result<(ScratchGuard, PathBuf)> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    crate::ensure_corpus_gitignored(root).map_err(anyhow::Error::new)?;

    let dir = root
        .join(".confidant")
        .join("conflicts")
        .join(id.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot create scratch dir {}: {e}",
            dir.display()
        )))
    })?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot set permissions on {}: {e}",
            dir.display()
        )))
    })?;

    let ours_path = dir.join("ours.md");
    let theirs_path = dir.join("theirs.md");
    let merged_path = dir.join("merged.md");
    // `merged.md` is pre-filled with the ours plaintext (CD5).
    for (path, bytes) in [
        (&ours_path, sides.ours_bytes.as_slice()),
        (&theirs_path, sides.theirs_bytes.as_slice()),
        (&merged_path, sides.ours_bytes.as_slice()),
    ] {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                anyhow::Error::new(DomainError::internal(format!(
                    "cannot write scratch file {}: {e}",
                    path.display()
                )))
            })?;
        f.write_all(bytes).map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot write scratch file {}: {e}",
                path.display()
            )))
        })?;
        f.sync_all().map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot sync scratch file {}: {e}",
                path.display()
            )))
        })?;
    }

    let guard = ScratchGuard::new(dir, vec![ours_path, theirs_path, merged_path.clone()]);
    Ok((guard, merged_path))
}

/// Resolve the operator's editor: `$VISUAL`, then `$EDITOR`.
///
/// Neither set is a usage error (exit 2, ADR-7).
#[cfg(unix)]
pub(crate) fn resolve_editor() -> anyhow::Result<String> {
    std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| {
            anyhow::Error::new(
                DomainError::usage("no editor configured")
                    .with_fix("Set $EDITOR or use --merged-file"),
            )
        })
}

/// Run the operator's editor on `path`.
///
/// A non-zero editor exit is an error; the caller must not apply anything.
#[cfg(unix)]
pub(crate) fn run_editor(path: &Path) -> anyhow::Result<()> {
    let editor = resolve_editor()?;
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "could not run editor '{editor}': {e}"
            )))
        })?;
    if !status.success() {
        return Err(anyhow::Error::new(
            DomainError::invalid("editor exited with an error; the merge was not applied")
                .with_fix("Fix the merge and retry, or use --merged-file"),
        ));
    }
    Ok(())
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
            inbox_tip: None,
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

    /// #455: `ScratchGuard` zero-overwrites before unlinking. The test
    /// holds a read handle open across the drop; reading through it after
    /// the drop must yield zeros (the file is gone from the directory).
    #[test]
    #[cfg(unix)]
    fn scratch_guard_zeroizes_before_unlink() {
        use std::io::{Read, Seek, SeekFrom};

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.md");
        std::fs::write(&file, b"SENTINEL-SECRET-CONTENT").unwrap();

        // Open a read handle before the guard drops.
        let mut handle = std::fs::File::open(&file).unwrap();

        {
            let mut guard = ScratchGuard::new(dir.path().to_owned(), vec![file.clone()]);
            // Explicit cleanup, as the success path does.
            guard.cleanup();
            // Drop is a no-op after explicit cleanup.
        }

        // The file is gone from the directory.
        assert!(!file.exists(), "scratch file should be removed");
        assert!(!dir.path().exists(), "scratch dir should be removed");

        // The bytes the handle still sees were zeroed before the unlink.
        handle.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        handle.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), b"SENTINEL-SECRET-CONTENT".len());
        assert!(
            buf.iter().all(|&b| b == 0),
            "scratch bytes should be zeroed, got {buf:?}"
        );
    }

    /// #455: `ScratchGuard` drop (without explicit cleanup) also zeroes
    /// and removes.
    #[test]
    #[cfg(unix)]
    fn scratch_guard_drop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.md");
        std::fs::write(&file, b"SENTINEL-SECRET-CONTENT").unwrap();
        {
            let _guard = ScratchGuard::new(dir.path().to_owned(), vec![file.clone()]);
        }
        assert!(!file.exists(), "scratch file should be removed on drop");
        assert!(
            !dir.path().exists(),
            "scratch dir should be removed on drop"
        );
    }
}
