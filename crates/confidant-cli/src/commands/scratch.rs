//! 0600 scratch files and `$VISUAL`/`$EDITOR` helpers.

use std::path::{Path, PathBuf};

use crate::commands::find::ensure_corpus_gitignored;
use crate::commands::record::LoadedSides;
use confidant_core::error::DomainError;
use confidant_core::id::RecordId;

/// Guard for `--edit` scratch files (#455).
///
/// Zero-overwrites each file (same length), syncs, removes the files and
/// the directory on drop. [`ScratchGuard::cleanup`] can also be called
/// explicitly on the success path (after which drop is a no-op).
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
        let _ = std::fs::remove_dir_all(&self.dir);
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

/// Remove a stale `.confidant/conflicts/` dir left by a crashed
/// `resolve --edit`.
pub(crate) fn sweep_stale_scratch(root: &Path) {
    sweep_stale_scratch_under(&root.join(".confidant").join("conflicts"));
}

/// Remove a stale `.confidant/notes/` dir left by a crashed
/// `note edit --edit`.
pub(crate) fn sweep_stale_note_scratch(root: &Path) {
    sweep_stale_scratch_under(&root.join(".confidant").join("notes"));
}

/// Zero-overwrite every file under `dir`, then remove the tree. Best-effort.
pub(crate) fn sweep_stale_scratch_under(dir: &Path) {
    use std::io::Write;
    if !dir.exists() {
        return;
    }
    let mut stack = vec![dir.to_path_buf()];
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
    let _ = std::fs::remove_dir_all(dir);
}

/// Set up `--edit` scratch files (unix only).
#[cfg(unix)]
pub(crate) fn setup_edit_scratch(
    root: &Path,
    id: &RecordId,
    sides: &LoadedSides,
) -> anyhow::Result<(ScratchGuard, PathBuf)> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    ensure_corpus_gitignored(root).map_err(anyhow::Error::new)?;

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

/// Set up `note edit --edit` scratch (unix only).
#[cfg(unix)]
pub(crate) fn setup_note_edit_scratch(
    root: &Path,
    id: &RecordId,
    text: &str,
) -> anyhow::Result<(ScratchGuard, PathBuf)> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    ensure_corpus_gitignored(root).map_err(anyhow::Error::new)?;

    let dir = root.join(".confidant").join("notes").join(id.to_string());
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

    let note_path = dir.join("note.md");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&note_path)
        .map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot write scratch file {}: {e}",
                note_path.display()
            )))
        })?;
    f.write_all(text.as_bytes()).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot write scratch file {}: {e}",
            note_path.display()
        )))
    })?;
    f.sync_all().map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot sync scratch file {}: {e}",
            note_path.display()
        )))
    })?;

    let guard = ScratchGuard::new(dir, vec![note_path.clone()]);
    Ok((guard, note_path))
}

/// Run the operator's editor on a note's scratch file.
#[cfg(unix)]
pub(crate) fn run_note_editor(path: &Path) -> anyhow::Result<()> {
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
            DomainError::invalid("editor exited with an error; the note was not changed")
                .with_fix("Fix the note and retry, or use --file"),
        ));
    }
    Ok(())
}
