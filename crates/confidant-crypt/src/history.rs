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
    /// Return the signer's key id for `commit` (e.g. `%GK`), or `None` if
    /// the commit is unsigned.
    fn commit_signer(&self, commit: &str) -> Result<Option<String>, Error>;
}

/// `git log --format=%GK` based checker.
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
    fn commit_signer(&self, commit: &str) -> Result<Option<String>, Error> {
        let out = Command::new("git")
            .args([
                "-C",
                &self.vault.to_string_lossy(),
                "log",
                "-1",
                "--format=%GK",
                commit,
            ])
            .output()
            .map_err(Error::Io)?;
        if !out.status.success() {
            return Err(Error::Manifest(format!("git log failed for {commit}")));
        }
        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(if key.is_empty() { None } else { Some(key) })
    }
}

/// Verify that history is trusted for agent output.
///
/// - `tip`: the current HEAD commit. Must be signed by a trusted key.
/// - `introducing_commits`: for each file being emitted, the commits that
///   introduced its current content (e.g. from `git log --format=%H --
///   <path>`). Every one must be signed by a trusted key.
///
/// An unsigned commit — including an unsigned rollback — is a hard error:
/// the caller withholds the record from agent output.
pub fn verify_history(
    checker: &dyn SignerChecker,
    trusted_signers: &[String],
    tip: &str,
    introducing_commits: &[String],
) -> Result<(), Error> {
    let trusted = |key: &Option<String>| -> bool {
        match key {
            Some(k) => trusted_signers.iter().any(|t| t == k),
            None => false,
        }
    };
    let tip_signer = checker.commit_signer(tip)?;
    if !trusted(&tip_signer) {
        return Err(Error::Manifest(format!(
            "tip commit {tip} is not signed by a trusted key; refusing agent output"
        )));
    }
    for commit in introducing_commits {
        let signer = checker.commit_signer(commit)?;
        if !trusted(&signer) {
            return Err(Error::Manifest(format!(
                "content introduced by untrusted/unsigned commit {commit}; refusing agent output"
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
        signers: HashMap<String, Option<String>>,
    }

    impl SignerChecker for FakeChecker {
        fn commit_signer(&self, commit: &str) -> Result<Option<String>, Error> {
            Ok(self.signers.get(commit).cloned().flatten())
        }
    }

    fn checker() -> FakeChecker {
        FakeChecker {
            signers: HashMap::from([
                ("tip".to_string(), Some("KEY1".to_string())),
                ("c1".to_string(), Some("KEY1".to_string())),
                ("c2".to_string(), Some("KEY2".to_string())),
                ("unsigned".to_string(), None),
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
