use std::path::Path;

use crate::error::DomainError;

use super::git::{git, git_line, list_items};

/// The operator's out-of-band pin of the inbox public key must match the
/// vault's advertised `[inbox].pubkey`. A mismatch is `E_INBOX_UNTRUSTED`:
/// anyone with git write access can rewrite `confidant.toml`, so only the
/// local pin is trustworthy. No pin configured is a warning, not an error —
/// the pin is opt-in hardening, and refusing would break every setup that
/// never opted in.
pub(crate) fn check_inbox_pubkey(
    vault_pubkey: Option<&str>,
    pinned: Option<&str>,
    warnings: &mut Vec<String>,
) -> anyhow::Result<()> {
    let Some(pinned) = pinned.map(str::trim).filter(|s| !s.is_empty()) else {
        warnings.push(
            "no [inbox].pubkey pinned in ~/.config/confidant/config.toml; \
             inbox key substitution cannot be detected — pin the key once from the vault's inbox public key"
                .to_string(),
        );
        return Ok(());
    };
    match vault_pubkey.map(str::trim).filter(|s| !s.is_empty()) {
        Some(vault_key) if vault_key == pinned => Ok(()),
        Some(vault_key) => Err(anyhow::Error::new(DomainError::inbox_untrusted(format!(
            "vault [inbox].pubkey does not match the pinned key in user config \
             (vault: '{vault_key}', pinned: '{pinned}'); refusing — possible key substitution"
        )))),
        None => Err(anyhow::Error::new(DomainError::inbox_untrusted(
            "vault has no [inbox].pubkey but the user config pins one; refusing",
        ))),
    }
}

/// Defense in depth against key substitution (#55): compare the recipient
/// derived from the *local* inbox private key (loaded once per run — see
/// [`InboxKeys`]) against the vault's advertised `[inbox].pubkey`. A
/// mismatch is a hard `E_INBOX_UNTRUSTED`: the pin in the user config is
/// itself a file an attacker with local write access could tamper with,
/// but the private key is the ground truth for who can actually read
/// these items.
///
/// Compares against the CURRENT key only: the vault advertises the new key
/// after `inbox rotate`, while decrypt still accepts the previous one
/// during the rotation window (§8a.3).
///
/// Skips (returns `Ok`) when the vault advertises no pubkey — nothing to
/// compare against.
pub(crate) fn check_local_inbox_pubkey(
    vault_pubkey: Option<&str>,
    local_recipient: &str,
) -> anyhow::Result<()> {
    let vault_pubkey = match vault_pubkey.map(str::trim).filter(|s| !s.is_empty()) {
        Some(k) => k,
        None => return Ok(()),
    };
    // Compare parsed recipients, not raw strings: age's parser may accept
    // non-canonical encodings (e.g. all-uppercase Bech32) that a string
    // comparison would misreport as substitution.
    let vault_recipient =
        confidant_crypt::age_wrap::parse_recipient(vault_pubkey).map_err(|_| {
            // A malformed vault value gets its own message — it is a config error,
            // not evidence of substitution. Still a hard error.
            anyhow::Error::new(DomainError::inbox_untrusted(format!(
                "vault [inbox].pubkey is not a valid age recipient: '{vault_pubkey}'; \
             fix: correct the value in confidant.toml and do not merge until resolved"
            )))
        })?;
    let local = confidant_crypt::age_wrap::parse_recipient(local_recipient)
        .map_err(|e| anyhow::anyhow!("local inbox recipient failed to parse: {e}"))?;
    if local.to_string() != vault_recipient.to_string() {
        return Err(anyhow::Error::new(DomainError::inbox_untrusted(format!(
            "local inbox key does not match vault [inbox].pubkey \
             (local: '{local_recipient}', vault: '{vault_pubkey}'); refusing — possible key substitution; \
             fix: compare against your out-of-band pin and do not merge until resolved"
        ))));
    }
    Ok(())
}

/// Verify that every item currently awaiting merge was introduced by trusted
/// signers (ADR-10). For each `.age` file at the inbox tip, every commit
/// that added, modified, or renamed it — back to and including its most
/// recent add — must carry a valid signature from a trusted signer.
///
/// `tip` is the pinned inbox SHA resolved before this call: every git read
/// here anchors at it, never at the branch name, so a push mid-verification
/// can't change what is examined.
///
/// Checking only the tip is not enough: an unsigned commit dropping a
/// malicious item passes as soon as a trusted signer commits on top of it.
/// And scoping by "commits since the last clear" is not enough either:
/// anyone with git write access can forge a clear-looking commit to truncate
/// the window and shield an unsigned item. Provenance of the actual files
/// has neither hole.
///
/// Commits that only delete items are out of scope: deletion is denial of
/// service, not data injection (and our own clear commits are unsigned until
/// they are signed). An empty `trusted` list verifies nothing; the caller
/// only passes an empty list under the explicit `--allow-unsigned` opt-in
/// (otherwise it refuses before getting here).
pub(crate) fn verify_inbox_signatures(
    repo: &Path,
    tip: &str,
    trusted: &[String],
) -> anyhow::Result<()> {
    if trusted.is_empty() {
        return Ok(());
    }
    // Merge commits are not expanded by `git log -- <file>` (merge diffs are
    // suppressed by default), so a merge that rewrites an item would escape
    // the per-file provenance walk below: the log would show only the
    // original (signed) add while the tip holds tampered bytes. The inbox is
    // append-only and linear by design, so any merge on the branch is a
    // policy violation. Fail closed.
    let merges = git_line(repo, &["rev-list", "--merges", "--count", tip])?;
    if merges != "0" {
        return Err(anyhow::Error::new(DomainError::inbox_untrusted(
            "inbox branch contains merge commits; the inbox is append-only and linear",
        )));
    }
    for name in list_items(repo, tip)? {
        let file = format!("{name}.age");
        let log = git_line(
            repo,
            &[
                "log",
                "--format=%H",
                "--name-status",
                "--diff-filter=AMR",
                tip,
                "--",
                &file,
            ],
        )?;
        // Newest first: (sha, status) pairs. Verify each commit back to and
        // including the file's most recent add; older history predates the
        // current incarnation of the file.
        let mut lines = log.lines();
        let mut examined = 0;
        while let Some(sha) = lines.next() {
            let sha = sha.trim();
            if sha.is_empty() {
                continue;
            }
            let status = lines
                .by_ref()
                .find_map(|l| {
                    let l = l.trim();
                    (!l.is_empty()).then(|| l.split('\t').next().unwrap_or("").to_string())
                })
                .unwrap_or_default();
            verify_commit_signature(repo, sha, &file, trusted)?;
            examined += 1;
            if status.starts_with('A') {
                break;
            }
        }
        if examined == 0 {
            // The file is at the tip, so it must have a history; empty means
            // something is wrong with the repository. Fail closed.
            return Err(anyhow::Error::new(DomainError::inbox_untrusted(format!(
                "inbox item '{file}' has no commit history; refusing"
            ))));
        }
    }
    Ok(())
}

/// One commit's signature must be good and from a trusted key (ADR-10).
/// `G` = good signature; `U` = good signature from a key unknown to gpg's
/// own web of trust (our trust decision is the configured list, not gpg's).
pub(crate) fn verify_commit_signature(
    repo: &Path,
    sha: &str,
    file: &str,
    trusted: &[String],
) -> anyhow::Result<()> {
    let out = git(repo, &["log", "-1", "--format=%G?%x00%GK", sha])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split('\0');
    let validity = parts.next().unwrap_or("").trim();
    let key_id = parts.next().unwrap_or("").trim();
    let good = matches!(validity, "G" | "U");
    let trusted_key = trusted.iter().any(|k| k == key_id);
    if !(good && trusted_key) {
        return Err(anyhow::Error::new(DomainError::inbox_untrusted(format!(
            "inbox item '{file}': commit {sha} is not signed by a trusted signer \
             (validity '{validity}', key '{key_id}')"
        ))));
    }
    Ok(())
}
