use std::path::{Path, PathBuf};
use std::process::Command;

use crate::paths;

use super::git::git;
use super::ItemOutcome;

#[derive(Clone, Debug)]
pub(crate) enum PlannedWrite {
    LedgerAppend { file: PathBuf, lines: Vec<String> },
    RecordWrite { path: PathBuf, content: String },
}

/// What was changed on disk (for revert on `check` failure).
#[derive(Clone, Debug)]
pub(crate) enum AppliedChange {
    Modified {
        abs: PathBuf,
        previous: Option<Vec<u8>>,
    },
}
/// Apply planned writes to the working tree, recording previous bytes for
/// revert. Uses atomic replace (`paths::write_replace`).
///
/// Spec 3 (B11): a `RecordWrite` into a structurally encrypted vault fails
/// closed — inbox transcripts must never land as plaintext. Ledger appends
/// stay plaintext by design (spec §3).
pub(crate) fn apply_writes(
    vault_root: &Path,
    writes: &[PlannedWrite],
    applied: &mut Vec<AppliedChange>,
) -> anyhow::Result<()> {
    if writes
        .iter()
        .any(|w| matches!(w, PlannedWrite::RecordWrite { .. }))
        && crate::crypto_mode::is_structurally_encrypted(vault_root)
    {
        return Err(anyhow::Error::new(
            crate::error::DomainError::invalid(
                "inbox: refusing to write a transcript record into an encrypted vault; \
                 inbox RecordWrite cannot encrypt yet and must not write plaintext",
            )
            .with_fix(
                "Track encrypted inbox ingestion on issue #148; until then, add the \
                 record with `confidant record add` / `confidant note add`, which encrypt",
            ),
        ));
    }
    for w in writes {
        match w {
            PlannedWrite::LedgerAppend { file, lines } => {
                let abs = vault_root.join(file);
                let previous = paths::read_to_string(vault_root, file)
                    .ok()
                    .map(|s| s.into_bytes());
                if let Some(parent) = file.parent() {
                    if !parent.as_os_str().is_empty() {
                        paths::ensure_directory(vault_root, parent).map_err(|e| {
                            anyhow::anyhow!("could not create {}: {e:#}", parent.display())
                        })?;
                    }
                }
                let mut text = previous
                    .as_deref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                for l in lines {
                    text.push_str(l.trim_end());
                    text.push('\n');
                }
                paths::write_replace(vault_root, file, text.as_bytes())
                    .map_err(|e| anyhow::anyhow!("could not write {}: {e:#}", file.display()))?;
                applied.push(AppliedChange::Modified { abs, previous });
            }
            PlannedWrite::RecordWrite { path, content } => {
                let abs = vault_root.join(path);
                let previous = paths::read_to_string(vault_root, path)
                    .ok()
                    .map(|s| s.into_bytes());
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        paths::ensure_directory(vault_root, parent).map_err(|e| {
                            anyhow::anyhow!("could not create {}: {e:#}", parent.display())
                        })?;
                    }
                }
                paths::write_replace(vault_root, path, content.as_bytes())
                    .map_err(|e| anyhow::anyhow!("could not write {}: {e:#}", path.display()))?;
                applied.push(AppliedChange::Modified { abs, previous });
            }
        }
    }
    Ok(())
}

/// Undo applied writes (the tree was clean when we started, so restoring
/// previous bytes — or removing created files — returns it to clean).
pub(crate) fn revert_applied(applied: &[AppliedChange]) {
    for change in applied.iter().rev() {
        let AppliedChange::Modified { abs, previous } = change;
        match previous {
            Some(bytes) => {
                let _ = std::fs::write(abs, bytes);
            }
            None => {
                let _ = std::fs::remove_file(abs);
            }
        }
    }
}

/// Unstage the applied paths after a failed merge commit. The tree was clean
/// when the run started, so the applied paths are the only staged entries;
/// leaving them staged would break the all-or-nothing contract just as
/// surely as leaving the worktree dirty. Best effort: cleanup must not fail
/// the run a second time.
pub(crate) fn unstage_applied(repo: &Path, applied: &[AppliedChange]) {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).arg("reset").arg("-q").arg("--");
    let mut any = false;
    for change in applied {
        let AppliedChange::Modified { abs, .. } = change;
        if let Ok(rel) = abs.strip_prefix(repo) {
            cmd.arg(rel);
            any = true;
        }
    }
    if any {
        let _ = cmd.output();
    }
}

/// Commit the applied writes on the current branch. Commit messages carry
/// only opaque IDs and verbs (ADR-7): item names are ULIDs. The commit is
/// signed (`-S`, honoring the operator's git signing config); run_inbox
/// refuses before getting here when signing isn't configured (#52, ADR-10).
pub(crate) fn commit_applied(
    repo: &Path,
    applied: &[AppliedChange],
    outcomes: &[ItemOutcome],
) -> anyhow::Result<()> {
    for change in applied {
        let AppliedChange::Modified { abs, .. } = change;
        let rel = abs.strip_prefix(repo).map_err(|_| {
            anyhow::anyhow!("vault path escapes the git repository: {}", abs.display())
        })?;
        git(repo, &["add", "--", &rel.to_string_lossy()])?;
    }
    let merged: Vec<&str> = outcomes
        .iter()
        .filter(|o| o.action == "merge")
        .map(|o| o.name.as_str())
        .collect();
    let mut body = String::from("items:\n");
    for o in outcomes.iter().filter(|o| o.action == "merge") {
        body.push_str(&format!("{} {} {}\n", o.name, o.kind, o.target));
    }
    git(
        repo,
        &[
            "commit",
            "-q",
            "-S",
            "-m",
            &format!("inbox: merge {} item(s)", merged.len()),
            "-m",
            &body,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn inbox_recordwrite_fails_closed_on_encrypted_vault() {
        // B11: a RecordWrite into a structurally encrypted vault fails
        // closed — never writes plaintext. LedgerAppend is unaffected.
        let dir = vault_dir();
        let root = dir.path();
        // Structurally encrypted: a keys/ tree exists.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/operator.toml"), "# placeholder\n").unwrap();

        let writes = vec![PlannedWrite::RecordWrite {
            path: PathBuf::from("people/p-01ABC/profile.md"),
            content: "---\nid: p-01ABC\ntype: person\n---\n".to_string(),
        }];
        let mut applied = Vec::new();
        let err = apply_writes(root, &writes, &mut applied).unwrap_err();
        assert!(
            err.to_string().contains("encrypted vault"),
            "unexpected error: {err:#}"
        );
        assert!(
            !root.join("people/p-01ABC/profile.md").exists(),
            "no plaintext may be written"
        );
        assert!(applied.is_empty());

        // LedgerAppend still goes through on the same vault.
        let writes = vec![PlannedWrite::LedgerAppend {
            file: PathBuf::from("ledger/2026/10.cfd"),
            lines: vec!["2026-10-12 open p-01ABC package pkg-1 4 sessions".to_string()],
        }];
        let mut applied = Vec::new();
        apply_writes(root, &writes, &mut applied).unwrap();
        assert!(root.join("ledger/2026/10.cfd").exists());
    }

    #[test]
    fn inbox_recordwrite_allowed_on_plaintext_vault() {
        let dir = vault_dir();
        let root = dir.path();
        let writes = vec![PlannedWrite::RecordWrite {
            path: PathBuf::from("people/p-01ABC/profile.md"),
            content: "---\nid: p-01ABC\ntype: person\n---\n".to_string(),
        }];
        let mut applied = Vec::new();
        apply_writes(root, &writes, &mut applied).unwrap();
        assert!(root.join("people/p-01ABC/profile.md").exists());
    }
}
