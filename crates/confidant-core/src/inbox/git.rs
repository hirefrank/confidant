use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::DomainError;

use super::INBOX_BRANCH;

/// The git toplevel containing `path`.
pub(crate) fn git_toplevel(path: &Path) -> anyhow::Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("not a git repository: {}", path.display());
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

/// `path` relative to the git toplevel.
pub(crate) fn toplevel_relative(toplevel: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    // Canonicalize both sides: macOS `/private/var` vs `/var` and similar
    // must agree, or `strip_prefix` fails on identical files.
    let canon_top = toplevel
        .canonicalize()
        .unwrap_or_else(|_| toplevel.to_path_buf());
    let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canon_path
        .strip_prefix(&canon_top)
        .map(Path::to_path_buf)
        .map_err(|_| {
            anyhow::anyhow!(
                "vault config {} is not under the git toplevel {}",
                path.display(),
                toplevel.display()
            )
        })
}
// ---------------------------------------------------------------------------
// git plumbing (shell-out; the CLI already requires a git vault)
// ---------------------------------------------------------------------------

pub(crate) fn git(repo: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(out)
}

pub(crate) fn git_line(repo: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = git(repo, args)?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub(crate) fn git_bytes(repo: &Path, spec: &str) -> anyhow::Result<Vec<u8>> {
    Ok(git(repo, &["show", spec])?.stdout)
}

pub(crate) fn toplevel(vault_root: &Path) -> anyhow::Result<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(vault_root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "{} is not inside a git repository; `confidant inbox` needs one",
            vault_root.display()
        ))));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

pub(crate) fn tree_is_clean(repo: &Path) -> anyhow::Result<bool> {
    Ok(git_line(repo, &["status", "--porcelain"])?.is_empty())
}

pub(crate) fn current_branch(repo: &Path) -> anyhow::Result<String> {
    let name = git_line(repo, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    if name == "HEAD" {
        return Err(anyhow::Error::new(DomainError::invalid(
            "`confidant inbox` needs a checked-out branch, not a detached HEAD",
        )));
    }
    Ok(name)
}

pub(crate) fn branch_exists(repo: &Path, name: &str) -> anyhow::Result<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{name}"),
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    Ok(out.status.success())
}
/// Item file stems on the inbox branch at the pinned `tip` SHA. The inbox
/// branch is an orphan branch whose root holds only `<name>.age` items;
/// anything else is `E_INBOX_ITEM` (fail closed).
pub(crate) fn list_items(repo: &Path, tip: &str) -> anyhow::Result<Vec<String>> {
    let out = git(repo, &["ls-tree", "-r", "--name-only", tip, "--"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut names = Vec::new();
    for line in text.lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        let stem = name.strip_suffix(".age").ok_or_else(|| {
            anyhow::Error::new(DomainError::inbox_item(format!(
                "unexpected file '{name}' on the inbox branch (only <name>.age items allowed)"
            )))
        })?;
        if stem.contains('/') || !is_item_stem(stem) {
            return Err(anyhow::Error::new(DomainError::inbox_item(format!(
                "bad inbox item name '{name}'"
            ))));
        }
        names.push(stem.to_string());
    }
    names.sort();
    Ok(names)
}

pub(crate) fn is_item_stem(stem: &str) -> bool {
    let mut chars = stem.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    stem.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
/// Remove the merged items from the inbox branch and commit the clearing.
///
/// #51: plumbing only — the cleared tree is built with `mktree` from the old
/// tip minus the cleared items, committed with `commit-tree` (parent = old
/// tip), and the ref is moved with `update-ref`. The inbox branch is never
/// checked out in the operator's worktree, so a crash can't strand them on
/// it.
///
/// #29: `expected_tip` is the tip recorded after the items were read.
/// It is re-verified immediately before clearing; on mismatch the run
/// refuses with `E_INBOX_RACE` instead of deleting content it never saw.
/// The final `update-ref` also passes the expected old value, so the move
/// is an atomic compare-and-swap.
///
/// #52: the clear commit is signed (`-S`, honoring the operator's git
/// signing config); run_inbox refuses before getting here when signing
/// isn't configured (ADR-10).
pub(crate) fn clear_inbox(repo: &Path, expected_tip: &str, names: &[String]) -> anyhow::Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    verify_inbox_tip(repo, expected_tip)?;
    let new_tree = build_cleared_tree(repo, expected_tip, names)?;
    let new_commit = git_line(
        repo,
        &[
            "commit-tree",
            &new_tree,
            "-p",
            expected_tip,
            "-S",
            "-m",
            &format!("inbox: clear {} item(s)", names.len()),
        ],
    )?;
    if let Err(e) = git(
        repo,
        &[
            "update-ref",
            &format!("refs/heads/{INBOX_BRANCH}"),
            &new_commit,
            expected_tip,
        ],
    ) {
        // The swap is atomic: failure almost always means the tip moved
        // between the recheck above and the swap. Confirm before reporting.
        let current = git_line(repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])
            .unwrap_or_default();
        if !current.is_empty() && current != expected_tip {
            return Err(anyhow::Error::new(DomainError::inbox_race(
                expected_tip,
                &current,
            )));
        }
        return Err(e);
    }
    Ok(())
}

/// #29: re-verify that the inbox tip is still the one recorded after the
/// items were read. Any push in between means the merged bytes may be
/// stale, so refuse instead of clearing.
pub(crate) fn verify_inbox_tip(repo: &Path, expected_tip: &str) -> anyhow::Result<()> {
    let current = git_line(repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    if current != expected_tip {
        return Err(anyhow::Error::new(DomainError::inbox_race(
            expected_tip,
            &current,
        )));
    }
    Ok(())
}

/// Build the cleared inbox tree: the old tip's tree minus the cleared
/// items, via `git mktree`. The tip recheck guarantees the tree still
/// holds exactly the listed items, so this is normally the empty tree;
/// keeping only unlisted entries is the safe direction regardless.
pub(crate) fn build_cleared_tree(
    repo: &Path,
    old_tip: &str,
    names: &[String],
) -> anyhow::Result<String> {
    let ls = git(repo, &["ls-tree", old_tip])?;
    let text = String::from_utf8_lossy(&ls.stdout);
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("mktree")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run git mktree: {e}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .expect("git mktree was spawned with piped stdin");
        for line in text.lines() {
            // `ls-tree` lines are `<mode> <type> <sha>\t<name>` — the same
            // format `mktree` reads. Item stems can't contain tabs or `/`
            // (list_items rejects them), so the tab split is safe.
            let name = line.split('\t').nth(1).unwrap_or("");
            let stem = name.strip_suffix(".age").unwrap_or(name);
            if names.iter().any(|n| n == stem) {
                continue;
            }
            use std::io::Write as _;
            writeln!(stdin, "{line}")
                .map_err(|e| anyhow::anyhow!("could not write to git mktree: {e}"))?;
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("could not run git mktree: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "git mktree failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// #52 (ADR-10): whether the operator has commit signing configured. Either
/// `commit.gpgsign` set to a true boolean (`git config --type=bool`
/// normalizes `yes`/`on`/`1`/`True` too) or an explicit `user.signingkey`
/// counts — with `-S` passed explicitly, git signs in both cases.
pub(crate) fn commit_signing_configured(repo: &Path) -> anyhow::Result<bool> {
    if git_config_bool(repo, "commit.gpgsign")?.unwrap_or(false) {
        return Ok(true);
    }
    Ok(git_config_get(repo, "user.signingkey")?.is_some_and(|s| !s.is_empty()))
}

/// `git config --type=bool --get`: `None` when the key is unset or not a
/// valid boolean (git exits non-zero); otherwise the normalized value.
pub(crate) fn git_config_bool(repo: &Path, key: &str) -> anyhow::Result<Option<bool>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["config", "--type=bool", "--get", key])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).trim() == "true"))
}

/// `git config --get`: `None` when the key is unset (git exits 1).
pub(crate) fn git_config_get(repo: &Path, key: &str) -> anyhow::Result<Option<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["config", "--get", key])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((!value.is_empty()).then_some(value))
}
