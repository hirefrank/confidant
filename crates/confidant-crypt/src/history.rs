//! Rollback/replay defense (design §5).
//!
//! Binding the header stops a flipped flag, but not a restored older file:
//! someone with git write access can restore an older version of the same
//! file (`git checkout <old> -- <file>`), and that old file still has a
//! valid AAD — possibly saying `no-ai: false` from before the client opted
//! out.
//!
//! Defense in depth: `find` and `context` produce agent output only from
//! history whose commits verify against the trusted-signers list (ADR-10).
//! The tip commit and the commits that introduced each emitted file's
//! current content must verify; content introduced by an unsigned commit —
//! an unsigned rollback included — is refused with a hard error and
//! withheld from agent output.

use std::path::Path;
use std::process::Command;

use crate::error::Error;

/// Checks whether a commit carries a signature from a trusted key.
///
/// Production uses [`GitSignerChecker`] (shells out to git); tests inject a
/// fake.
pub trait SignerChecker {
    /// Return the signature validity and signer key id for `commit`, or
    /// `None` if the commit is unsigned.
    ///
    /// Validity is git's `%G?` status: only `G` (good signature) is
    /// accepted — `%GK` alone is not enough, since git prints a key id even
    /// for bad or uncheckable signatures.
    fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error>;
}

/// `git log --format=%G? --format=%GK` based checker.
pub struct GitSignerChecker {
    vault: std::path::PathBuf,
}

impl GitSignerChecker {
    pub fn new(vault: &Path) -> Self {
        GitSignerChecker {
            vault: vault.to_path_buf(),
        }
    }
}

impl SignerChecker for GitSignerChecker {
    fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error> {
        let out = Command::new("git")
            // Never leak the device key into git/gpg/hooks via the environment.
            .env_remove("CONFIDANT_DEVICE_KEY")
            .args([
                "-C",
                &self.vault.to_string_lossy(),
                "log",
                "-1",
                "--format=%G?%x00%GK",
                "--end-of-options",
                commit,
            ])
            .output()
            .map_err(Error::Io)?;
        if !out.status.success() {
            return Err(Error::Manifest(format!("git log failed for {commit}")));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut parts = text.split('\0');
        let validity = parts.next().unwrap_or("").trim();
        let key = parts.next().unwrap_or("").trim().to_string();
        if key.is_empty() {
            return Ok(None);
        }
        let v = validity.chars().next().unwrap_or(' ');
        Ok(Some((v, key)))
    }
}

/// Verify that history is trusted for agent output.
///
/// - `tip`: the current HEAD commit. Must carry a *good* signature (`%G?`
///   == `G`) from a trusted key.
/// - `introducing_commits`: for each file being emitted, the commits that
///   introduced its current content. Build this list with
///   `git log -m --format=%H --end-of-options -- <path>`: `-m`
///   (`--diff-merges=separate`) expands merge diffs so a merge commit that
///   rewrote the file is included — without it, content changed inside a
///   merge escapes the walk (the same hole as the inbox's merge-commit
///   bypass). Every listed commit must carry a good signature from a
///   trusted key.
///
/// Anything else — unsigned, bad signature, untrusted signer — is a hard
/// error: the caller withholds the record from agent output.
pub fn verify_history(
    checker: &dyn SignerChecker,
    trusted_signers: &[String],
    tip: &str,
    introducing_commits: &[String],
) -> Result<(), Error> {
    let trusted = |sig: &Option<(char, String)>| -> bool {
        match sig {
            Some(('G', k)) => trusted_signers.iter().any(|t| t == k),
            _ => false,
        }
    };
    let tip_sig = checker.commit_signature(tip)?;
    if !trusted(&tip_sig) {
        return Err(Error::Manifest(format!(
            "tip commit {tip} is not signed by a trusted key with a good signature; refusing agent output"
        )));
    }
    for commit in introducing_commits {
        let sig = checker.commit_signature(commit)?;
        if !trusted(&sig) {
            return Err(Error::Manifest(format!(
                "content introduced by untrusted/unsigned/bad-signature commit {commit}; refusing agent output"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeChecker {
        signers: HashMap<String, Option<(char, String)>>,
    }

    impl SignerChecker for FakeChecker {
        fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error> {
            Ok(self.signers.get(commit).cloned().flatten())
        }
    }

    fn checker() -> FakeChecker {
        FakeChecker {
            signers: HashMap::from([
                ("tip".to_string(), Some(('G', "KEY1".to_string()))),
                ("c1".to_string(), Some(('G', "KEY1".to_string()))),
                ("c2".to_string(), Some(('G', "KEY2".to_string()))),
                ("unsigned".to_string(), None),
                ("bad-sig".to_string(), Some(('B', "KEY1".to_string()))),
            ]),
        }
    }

    #[test]
    fn trusted_history_passes() {
        let c = checker();
        let trusted = vec!["KEY1".to_string(), "KEY2".to_string()];
        assert!(verify_history(&c, &trusted, "tip", &["c1".to_string(), "c2".to_string()]).is_ok());
    }

    #[test]
    fn unsigned_introducing_commit_refused() {
        let c = checker();
        let trusted = vec!["KEY1".to_string()];
        let err = verify_history(&c, &trusted, "tip", &["unsigned".to_string()]).unwrap_err();
        assert!(format!("{err}").contains("untrusted/unsigned"));
    }

    #[test]
    fn bad_signature_refused_even_from_trusted_key() {
        // %GK prints a key id even for a BAD signature — %G? must be G.
        let c = checker();
        let trusted = vec!["KEY1".to_string()];
        let err = verify_history(&c, &trusted, "tip", &["bad-sig".to_string()]).unwrap_err();
        assert!(format!("{err}").contains("bad-signature"));
    }

    #[test]
    fn unsigned_tip_refused() {
        let c = checker();
        let trusted = vec!["KEY1".to_string()];
        assert!(verify_history(&c, &trusted, "unsigned", &["c1".to_string()]).is_err());
    }

    #[test]
    fn untrusted_signer_refused() {
        let c = checker();
        let trusted = vec!["KEY9".to_string()];
        assert!(verify_history(&c, &trusted, "tip", &["c1".to_string()]).is_err());
    }
}
