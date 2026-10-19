//! Operator record/note editing (#556 phase 2).
//!
//! `e` in the context pane fetches the decrypted text through the CLI's
//! operator-only `record show --for-edit` / `note show --for-edit` reads,
//! stages it in a 0600 scratch file under `.confidant/conflicts/<id>/`, hands
//! the file to the operator's `$EDITOR` while the TUI is suspended, and —
//! only after an explicit confirm — writes back through
//! `record edit --file` / `note edit --file`.
//!
//! This module holds the pure state plus the scratch-file plumbing. It never
//! links `confidant-core`: the decrypted text crosses the process boundary as
//! JSON, and the only files touched here are this crate's own gitignored
//! scratch (the same 0600 convention and stale-scratch sweep the CLI's
//! conflict hand-merge uses, #455). Nothing here logs the text.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::proposals::open_secure_write;

/// Whether an edit target is a note or any other record.
///
/// Notes are read and written by the `note` subcommand pair; every other
/// record kind by the `record` pair (#557 vs #216).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EditKind {
    #[default]
    Record,
    Note,
}

impl EditKind {
    /// The noun used in confirm text.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Note => "note",
        }
    }

    /// The operator-only read that prints the current text as JSON.
    pub fn show_argv(self, id: &str) -> Vec<String> {
        match self {
            Self::Record => vec![
                "record".to_owned(),
                "show".to_owned(),
                id.to_owned(),
                "--for-edit".to_owned(),
            ],
            Self::Note => vec![
                "note".to_owned(),
                "show".to_owned(),
                id.to_owned(),
                "--for-edit".to_owned(),
            ],
        }
    }

    /// The write that replaces the record from the edited scratch file.
    pub fn edit_argv(self, id: &str, file: &str) -> Vec<String> {
        match self {
            Self::Record => vec![
                "record".to_owned(),
                "edit".to_owned(),
                id.to_owned(),
                "--file".to_owned(),
                file.to_owned(),
            ],
            Self::Note => vec![
                "note".to_owned(),
                "edit".to_owned(),
                id.to_owned(),
                "--file".to_owned(),
                file.to_owned(),
            ],
        }
    }
}

/// One editable item in the context pane: the person, a note, or an
/// interaction (all of which are records except notes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditTarget {
    pub id: String,
    pub kind: EditKind,
    /// Display label for the confirm modal: never the body text.
    pub label: String,
}

/// Where the edit flow is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EditPhase {
    /// The editor is running; the host has suspended the TUI.
    #[default]
    Editing,
    /// The editor returned with changed text. `y` writes through the CLI;
    /// any other key cancels and removes the scratch.
    Confirm,
}

/// The in-flight edit.
///
/// `original`/`edited` hold decrypted plaintext, so the manual
/// [`std::fmt::Debug`] impl redacts them: nothing here may reach logs or a
/// panic message.
#[derive(Clone, Default, PartialEq)]
pub struct EditFlow {
    pub target: EditTarget,
    /// The 0600 scratch file handed to the editor.
    pub scratch: PathBuf,
    /// The text as fetched before the editor ran, to detect a no-op.
    pub original: String,
    /// The text after the editor ran, once it differs from `original`.
    pub edited: Option<String>,
    pub phase: EditPhase,
}

impl std::fmt::Debug for EditFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EditFlow")
            .field("target", &self.target)
            .field("scratch", &self.scratch)
            .field("original", &"<redacted>")
            .field("edited", &self.edited.as_ref().map(|_| "<redacted>"))
            .field("phase", &self.phase)
            .finish()
    }
}

/// The scratch file for editing `id`:
/// `<vault>/.confidant/conflicts/<id>/edit.md`.
///
/// Reuses the conflict hand-merge scratch directory (#455) rather than
/// inventing a new one; the file name is distinct from the CLI's
/// `ours.md`/`theirs.md`/`merged.md`, so neither side overwrites the other.
///
/// Returns `None` for an id that is not a single safe path component, so a
/// malformed id can never escape `.confidant/`.
pub fn scratch_path(vault_root: &Path, id: &str) -> Option<PathBuf> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
    {
        return None;
    }
    Some(
        vault_root
            .join(".confidant")
            .join("conflicts")
            .join(id)
            .join("edit.md"),
    )
}

/// `$VISUAL`, then `$EDITOR`, mirroring the CLI's editor resolution. `None`
/// when neither is set or both are blank.
///
/// The value is executed as a single program, with no shell splitting — the
/// same limitation as the CLI's own `--edit` flows, so `EDITOR="code -w"`
/// does not work (point it at a wrapper script instead).
pub fn resolve_editor() -> Option<String> {
    std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
}

/// Stage `text` into `path` (dir 0700, file 0600), refusing to follow a
/// pre-planted symlink at the file path.
pub fn write_scratch(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", parent.display()))?;
        }
    }
    use std::io::Write;
    open_secure_write(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Read the editor's text back from the scratch file.
pub fn read_scratch(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

/// Best-effort overwrite-with-zeros, then remove one scratch file, then prune
/// the now-empty `<id>/` and `conflicts/` directories. This is **not** secure
/// deletion: the filesystem, SSD wear levelling, snapshots, and backups may
/// retain the bytes (the same caveat the crypto design gives for
/// `Zeroizing`). It only keeps the plaintext from lingering in the directory,
/// and cleanup never masks the result it is cleaning up after.
pub fn remove_scratch(path: &Path) {
    zero_and_remove(path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
        if let Some(parent) = dir.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// The plaintext scratch file names the TUI stages under
/// `.confidant/conflicts/<id>/`: the `e` edit buffer (`#556` phase 2) and the
/// captured note body (`#556` phase 3). The CLI's own resolve scratch
/// (`ours.md`, `theirs.md`, `merged.md`) is deliberately absent.
const TUI_SCRATCH_FILES: &[&str] = &["edit.md", "capture.md"];

/// Best-effort overwrite-with-zeros of every stale TUI scratch file
/// ([`TUI_SCRATCH_FILES`]) under `.confidant/conflicts/*/` left by a crashed
/// run, then prune the emptied dirs. The CLI's own resolve scratch (`ours.md`,
/// `theirs.md`, `merged.md`) is left alone.
///
/// This is not secure deletion (see [`remove_scratch`]); it is a hygiene
/// sweep. Best-effort: every file is attempted and errors are swallowed so a
/// sweep never blocks startup.
pub fn sweep_stale_edit_scratch(vault_root: &Path) {
    let dir = vault_root.join(".confidant").join("conflicts");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        for file in TUI_SCRATCH_FILES {
            let path = entry.path().join(file);
            if path.is_file() {
                remove_scratch(&path);
            }
        }
    }
}

/// Overwrite the file's current bytes with zeros, then unlink it. Best-effort:
/// a failure to overwrite still falls through to the unlink.
///
/// Shared with the proposal apply engine's staged reviewed-source sweep
/// (`apply::remove_staged_source`, #618); both are hygiene, not secure
/// deletion.
pub(crate) fn zero_and_remove(path: &Path) {
    use std::io::Write;
    if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; len as usize];
            let _ = f.write_all(&zeros);
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposals::test_temp_dir;

    #[test]
    fn scratch_path_is_a_single_component_under_conflicts() {
        let root = Path::new("/vault");
        assert_eq!(
            scratch_path(root, "p-01ABC").unwrap(),
            Path::new("/vault/.confidant/conflicts/p-01ABC/edit.md")
        );
        // Anything that could escape the scratch dir is refused.
        assert_eq!(scratch_path(root, ""), None);
        assert_eq!(scratch_path(root, ".."), None);
        assert_eq!(scratch_path(root, "../evil"), None);
        assert_eq!(scratch_path(root, "a/b"), None);
    }

    #[test]
    fn write_read_and_remove_scratch_round_trips_at_0600() {
        let root = test_temp_dir("tui-edit-scratch-roundtrip");
        let path = scratch_path(&root, "n-01ABC").unwrap();
        write_scratch(&path, "---\nid: n-01ABC\n---\n\nFake body.\n").unwrap();
        assert_eq!(
            read_scratch(&path).unwrap(),
            "---\nid: n-01ABC\n---\n\nFake body.\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(file_mode & 0o777, 0o600);
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
        remove_scratch(&path);
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn remove_scratch_overwrites_content_before_unlink_best_effort() {
        use std::io::{Read, Seek, SeekFrom};

        let root = test_temp_dir("tui-edit-scratch-overwrite");
        let path = scratch_path(&root, "p-01ABC").unwrap();
        write_scratch(&path, "SENTINEL-SECRET-CONTENT").unwrap();
        let mut handle = std::fs::File::open(&path).unwrap();

        remove_scratch(&path);

        assert!(!path.exists(), "scratch file should be gone");
        handle.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        handle.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), "SENTINEL-SECRET-CONTENT".len());
        assert!(
            buf.iter().all(|&b| b == 0),
            "the best-effort overwrite should have zeroed the bytes"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sweep_removes_only_the_tui_scratch() {
        let root = test_temp_dir("tui-edit-sweep");
        let edit = scratch_path(&root, "p-01ABC").unwrap();
        write_scratch(&edit, "plaintext").unwrap();
        // A captured note body in the same dir is the TUI's scratch too.
        let capture = crate::capture::scratch_path(&root, "p-01ABC").unwrap();
        write_scratch(&capture, "captured plaintext").unwrap();
        // A CLI resolve scratch file in the same dir must survive.
        let cli_scratch = edit.parent().unwrap().join("ours.md");
        std::fs::write(&cli_scratch, "cli scratch").unwrap();
        // Another record's stale edit scratch.
        let other = scratch_path(&root, "p-01DEF").unwrap();
        write_scratch(&other, "more plaintext").unwrap();

        sweep_stale_edit_scratch(&root);

        assert!(!edit.exists(), "stale edit scratch removed");
        assert!(!capture.exists(), "stale capture scratch removed");
        assert!(!other.exists(), "every record's edit scratch removed");
        assert_eq!(
            std::fs::read_to_string(&cli_scratch).unwrap(),
            "cli scratch",
            "the CLI's resolve scratch must survive the sweep"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn edit_flow_debug_redacts_plaintext() {
        let flow = EditFlow {
            target: EditTarget {
                id: "n-1".to_owned(),
                kind: EditKind::Note,
                label: "note 2026-01-01".to_owned(),
            },
            scratch: PathBuf::from("/v/.confidant/conflicts/n-1/edit.md"),
            original: "SENTINEL-ORIGINAL".to_owned(),
            edited: Some("SENTINEL-EDITED".to_owned()),
            phase: EditPhase::Confirm,
        };
        let debug = format!("{flow:?}");
        assert!(!debug.contains("SENTINEL"), "plaintext leaked: {debug}");
        assert_eq!(debug.matches("<redacted>").count(), 2, "{debug}");
        assert!(debug.contains("n-1"), "{debug}");
    }

    #[test]
    fn edit_argv_targets_the_expected_subcommand_pair() {
        fn s(args: &[&str]) -> Vec<String> {
            args.iter().map(|a| (*a).to_owned()).collect()
        }
        assert_eq!(
            EditKind::Record.show_argv("p-1"),
            s(&["record", "show", "p-1", "--for-edit"])
        );
        assert_eq!(
            EditKind::Note.show_argv("n-1"),
            s(&["note", "show", "n-1", "--for-edit"])
        );
        assert_eq!(
            EditKind::Record.edit_argv("p-1", "/tmp/f.md"),
            s(&["record", "edit", "p-1", "--file", "/tmp/f.md"])
        );
        assert_eq!(
            EditKind::Note.edit_argv("n-1", "/tmp/f.md"),
            s(&["note", "edit", "n-1", "--file", "/tmp/f.md"])
        );
        assert_eq!(EditKind::Note.noun(), "note");
        assert_eq!(EditKind::Record.noun(), "record");
    }
}
