use std::path::{Path, PathBuf};
use std::process::Command;

use crate::paths;

use super::git::git;
use super::{ItemOutcome, SkippedItem};

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
/// Spec 3 (B11, #213): a `RecordWrite` into a structurally encrypted vault
/// is encrypted through `encrypt` at drain time — inbox transcripts must
/// never land as plaintext. With no encryptor the run fails closed.
/// Ledger appends stay plaintext by design (spec §3). Record writes into
/// a plaintext vault are written as-is and `encrypt` is never called.
pub(crate) fn apply_writes(
    vault_root: &Path,
    writes: &[PlannedWrite],
    applied: &mut Vec<AppliedChange>,
    encrypt: Option<&super::EncryptFn>,
) -> anyhow::Result<()> {
    if writes
        .iter()
        .any(|w| matches!(w, PlannedWrite::RecordWrite { .. }))
        && crate::crypto_mode::is_structurally_encrypted(vault_root)
        && encrypt.is_none()
    {
        return Err(anyhow::Error::new(
            crate::error::DomainError::invalid(
                "inbox: refusing to merge a record item into an encrypted vault \
                 without a record encryptor; writing it as plaintext would \
                 leak client content into git history (B11)",
            )
            .with_fix(
                "run `confidant inbox` (it encrypts record items with the \
                 vault's device key) or supply a record encryptor",
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
                // Encrypt (or copy plaintext) before creating parent dirs so a
                // refused write cannot leave an empty record directory (#401).
                let bytes = if crate::crypto_mode::is_structurally_encrypted(vault_root) {
                    // SAFETY: the B11 gate above returned early when
                    // `encrypt` is None and a RecordWrite is present.
                    encrypt.expect("record encryptor present for encrypted-vault RecordWrite")(
                        path,
                        content.as_bytes(),
                    )?
                } else {
                    content.as_bytes().to_vec()
                };
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        paths::ensure_directory(vault_root, parent).map_err(|e| {
                            anyhow::anyhow!("could not create {}: {e:#}", parent.display())
                        })?;
                    }
                }
                paths::write_replace(vault_root, path, &bytes)
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
        if let Some(rel) = relative_to_repo(repo, abs) {
            cmd.arg(rel);
            any = true;
        }
    }
    if any {
        let _ = cmd.output();
    }
}

/// `abs` relative to `repo` for git pathspecs, canonicalizing both sides so
/// a Windows verbatim path (`\\?\C:\...`) or a macOS `/private/...` path
/// agrees with the git toplevel (which git reports in normal form). `None`
/// when `abs` is not under `repo`.
fn relative_to_repo(repo: &Path, abs: &Path) -> Option<PathBuf> {
    let canon_repo = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let canon_abs = abs.canonicalize().unwrap_or_else(|_| abs.to_path_buf());
    canon_abs
        .strip_prefix(&canon_repo)
        .ok()
        .map(Path::to_path_buf)
}

/// Commit the applied writes on the current branch. Commit messages carry
/// only opaque IDs and verbs (ADR-7): item names are ULIDs. The commit is
/// signed (`-S`, honoring the operator's git signing config); run_inbox
/// refuses before getting here when signing isn't configured (#52, ADR-10).
pub(crate) fn commit_applied(
    repo: &Path,
    applied: &[AppliedChange],
    outcomes: &[ItemOutcome],
    skipped: &[SkippedItem],
) -> anyhow::Result<()> {
    for change in applied {
        let AppliedChange::Modified { abs, .. } = change;
        let rel = relative_to_repo(repo, abs).ok_or_else(|| {
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
    // #318: record operator-deferred items as opaque IDs (ADR-7), so the
    // merge commit is an audit trail of what was intentionally left on the
    // inbox branch. Matches the existing multi-`-m` body style.
    if !skipped.is_empty() {
        body.push_str("skipped:\n");
        for s in skipped {
            body.push_str(&format!("{}\n", s.name));
        }
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
    fn inbox_recordwrite_fails_closed_on_encrypted_vault_without_encryptor() {
        // B11: a RecordWrite into a structurally encrypted vault without
        // an encryptor fails closed — never writes plaintext.
        // LedgerAppend is unaffected.
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
        let err = apply_writes(root, &writes, &mut applied, None).unwrap_err();
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
        apply_writes(root, &writes, &mut applied, None).unwrap();
        assert!(root.join("ledger/2026/10.cfd").exists());
    }

    #[test]
    fn inbox_recordwrite_encrypts_on_encrypted_vault_with_encryptor() {
        // #213: with an encryptor, the RecordWrite lands as the
        // encryptor's bytes — never the plaintext.
        let dir = vault_dir();
        let root = dir.path();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/operator.toml"), "# placeholder\n").unwrap();

        let encrypt = |path: &Path, plaintext: &[u8]| -> anyhow::Result<Vec<u8>> {
            assert_eq!(path, Path::new("people/p-01ABC/profile.md"));
            assert!(plaintext.starts_with(b"---\n"));
            // Prefix + reversed bytes: recognizably "encrypted" output
            // that cannot contain the plaintext.
            let mut out = b"ENVELOPE:".to_vec();
            out.extend(plaintext.iter().rev());
            Ok(out)
        };
        let writes = vec![PlannedWrite::RecordWrite {
            path: PathBuf::from("people/p-01ABC/profile.md"),
            content: "---\nid: p-01ABC\ntype: person\n---\n".to_string(),
        }];
        let mut applied = Vec::new();
        apply_writes(root, &writes, &mut applied, Some(&encrypt)).unwrap();
        let written = std::fs::read(root.join("people/p-01ABC/profile.md")).unwrap();
        assert!(written.starts_with(b"ENVELOPE:"));
        let plaintext = b"---\nid: p-01ABC\ntype: person\n---\n";
        assert!(
            !written.windows(plaintext.len()).any(|w| w == plaintext),
            "plaintext must not appear in the written bytes"
        );
    }

    #[test]
    fn inbox_recordwrite_encrypt_failure_leaves_no_directory() {
        // #401: a failing encryptor must not leave people/<id>/ behind.
        let dir = vault_dir();
        let root = dir.path();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/operator.toml"), "# placeholder\n").unwrap();

        let encrypt = |_path: &Path, _plaintext: &[u8]| -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("no client key for person"))
        };
        let writes = vec![PlannedWrite::RecordWrite {
            path: PathBuf::from("people/p-01ABC/profile.md"),
            content: "---\nid: p-01ABC\ntype: person\n---\n".to_string(),
        }];
        let mut applied = Vec::new();
        let err = apply_writes(root, &writes, &mut applied, Some(&encrypt)).unwrap_err();
        assert!(
            err.to_string().contains("no client key"),
            "unexpected error: {err:#}"
        );
        assert!(
            !root.join("people/p-01ABC").exists(),
            "record directory must not be created on encrypt failure"
        );
        assert!(applied.is_empty());
    }

    #[test]
    fn inbox_recordwrite_allowed_on_plaintext_vault() {
        let dir = vault_dir();
        let root = dir.path();
        // Even with an encryptor supplied, a plaintext vault writes raw
        // bytes: the encryptor is only for structurally encrypted vaults.
        let encrypt = |_path: &Path, _plaintext: &[u8]| -> anyhow::Result<Vec<u8>> {
            panic!("encryptor must not be called on a plaintext vault")
        };
        let writes = vec![PlannedWrite::RecordWrite {
            path: PathBuf::from("people/p-01ABC/profile.md"),
            content: "---\nid: p-01ABC\ntype: person\n---\n".to_string(),
        }];
        let mut applied = Vec::new();
        apply_writes(root, &writes, &mut applied, Some(&encrypt)).unwrap();
        assert!(root.join("people/p-01ABC/profile.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn relative_to_repo_canonicalizes_both_sides() {
        // Windows `canonicalize` returns a verbatim `\\?\C:\...` path while
        // `git rev-parse --show-toplevel` returns the normal form, so a
        // plain `strip_prefix` fails even for a path inside the repo. On
        // Unix the same class of mismatch appears when the vault is reached
        // through a symlink (or macOS `/private/var` vs `/var`). The fix
        // canonicalizes both sides before stripping.
        use std::os::unix::fs::symlink;

        let dir = vault_dir();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("ledger/2026")).unwrap();
        std::fs::write(real.join("ledger/2026/10.cfd"), "").unwrap();

        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let abs = link.join("ledger/2026/10.cfd");

        // `abs` and `real` differ in string form (via the symlink), so a
        // bare strip_prefix would fail; canonicalizing both succeeds.
        assert!(abs.strip_prefix(&real).is_err());
        assert_eq!(
            relative_to_repo(&real, &abs).map(|p| p.to_string_lossy().into_owned()),
            Some("ledger/2026/10.cfd".to_string())
        );
        // A path genuinely outside the repo is still refused.
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "").unwrap();
        assert!(relative_to_repo(&real, &outside).is_none());
    }
}
