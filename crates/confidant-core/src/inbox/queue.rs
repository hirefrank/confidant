//! Queue plaintext items onto the `inbox` branch (#213 fallback path).
//!
//! Each item is age-encrypted to the vault's inbox pubkey (the caller has
//! already verified it against the operator's out-of-band pin) and
//! committed with a signed commit. Plumbing only: the inbox branch is
//! never checked out, and the worktree is never touched — the queued
//! items exist only as age ciphertext on the `inbox` branch until the
//! drain merges them.
//!
//! The queue is all-or-nothing: any failure before the atomic
//! `update-ref` compare-and-swap leaves the `inbox` branch untouched.
//! Blobs are written to the object store before the swap, so a failed
//! queue can leave unreachable blobs behind — same as any interrupted
//! plumbing write, and harmless (they carry no plaintext).

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use confidant_crypt::age_wrap::wrap_to_recipient;

use crate::error::DomainError;

use super::git::{branch_exists, commit_signing_configured, git, git_line, is_item_stem, toplevel};
use super::INBOX_BRANCH;

/// One item to queue: `(stem, plaintext payload)`. The stem is opaque
/// (a ULID, or `<ulid>-note` for a companion record); the payload is the
/// `confidant-inbox/1` text the drain parses.
pub struct QueueItem {
    pub stem: String,
    pub plaintext: String,
}

/// Queue items onto the `inbox` branch, encrypted to `recipient`.
///
/// `recipient` must be the vault's inbox pubkey, already verified
/// against the operator's pin by the caller — this function does not
/// re-check the pin (it has no access to the user config).
///
/// Fails closed when commit signing is not configured (an unsigned queue
/// commit would never pass the drain's trust check), when a stem already
/// exists on the branch (a fresh ULID colliding means something is very
/// wrong), or when the tip moves between the read and the swap
/// (`E_INBOX_RACE`). Returns the new inbox tip SHA.
pub fn queue_items(
    vault_root: &Path,
    items: &[QueueItem],
    recipient: &str,
) -> anyhow::Result<String> {
    if items.is_empty() {
        anyhow::bail!("nothing to queue");
    }
    let repo = toplevel(vault_root)?;
    if !commit_signing_configured(&repo)? {
        return Err(anyhow::Error::new(DomainError::inbox_signing_unconfigured()));
    }
    for item in items {
        if !is_item_stem(&item.stem) {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "inbox: refusing to queue item with invalid stem {:?}",
                item.stem
            ))));
        }
    }
    // Encrypt first: a failure here leaves the branch untouched.
    let mut ciphertexts = Vec::with_capacity(items.len());
    for item in items {
        ciphertexts.push(
            wrap_to_recipient(item.plaintext.as_bytes(), recipient).map_err(|e| {
                anyhow::Error::new(DomainError::inbox_crypto(format!(
                    "could not encrypt item {:?} to the inbox key: {e}",
                    item.stem
                )))
            })?,
        );
    }

    let has_branch = branch_exists(&repo, INBOX_BRANCH)?;
    let tip = if has_branch {
        Some(git_line(
            &repo,
            &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")],
        )?)
    } else {
        None
    };

    // Build the new tree: the old tip's entries plus the new blobs.
    // A stem collision fails closed instead of overwriting an item the
    // drain has not seen yet.
    let mut entries: Vec<String> = Vec::new();
    if let Some(tip) = &tip {
        let ls = git(&repo, &["ls-tree", tip])?;
        for line in String::from_utf8_lossy(&ls.stdout).lines() {
            let name = line.split('\t').nth(1).unwrap_or("");
            let stem = name.strip_suffix(".age").unwrap_or(name);
            if items.iter().any(|i| i.stem == stem) {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "inbox: item {stem} already queued; refusing to overwrite it"
                ))));
            }
            entries.push(line.to_string());
        }
    }
    for (item, ciphertext) in items.iter().zip(ciphertexts.iter()) {
        let blob = hash_blob(&repo, ciphertext)?;
        entries.push(format!("100644 blob {blob}\t{}.age", item.stem));
    }
    let new_tree = mktree(&repo, &entries)?;

    let mut commit_args: Vec<&str> = vec!["commit-tree", &new_tree, "-S"];
    if let Some(tip) = &tip {
        commit_args.push("-p");
        commit_args.push(tip.as_str());
    }
    let message = format!("inbox: queue {} item(s)", items.len());
    commit_args.push("-m");
    commit_args.push(&message);
    let new_commit = git_line(&repo, &commit_args)?;

    let old = tip.clone().unwrap_or_else(|| "0".repeat(40));
    if let Err(e) = git(
        &repo,
        &[
            "update-ref",
            &format!("refs/heads/{INBOX_BRANCH}"),
            &new_commit,
            &old,
        ],
    ) {
        // The swap is atomic: failure almost always means the tip moved
        // between the read above and the swap. Confirm before reporting.
        let current = git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])
            .unwrap_or_default();
        if has_branch && !current.is_empty() && Some(&current) != tip.as_ref() {
            return Err(anyhow::Error::new(DomainError::inbox_race(
                tip.as_deref().unwrap_or(""),
                &current,
            )));
        }
        return Err(e);
    }
    Ok(new_commit)
}

/// Write bytes as a blob in the repo object store; returns the blob SHA.
fn hash_blob(repo: &Path, bytes: &[u8]) -> anyhow::Result<String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run git hash-object: {e}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .expect("git hash-object was spawned with piped stdin");
        stdin
            .write_all(bytes)
            .map_err(|e| anyhow::anyhow!("could not write to git hash-object: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("could not run git hash-object: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "git hash-object failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build a tree from `ls-tree`-format lines via `git mktree`.
fn mktree(repo: &Path, entries: &[String]) -> anyhow::Result<String> {
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
        for line in entries {
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
