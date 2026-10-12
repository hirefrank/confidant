//! Preflight for [`super::run_inbox`]: repo resolution, trust checks, tip
//! pinning, and item decryption/parsing before merge planning.

use std::path::{Path, PathBuf};

use crate::error::DomainError;
use crate::vault::{load_vault, Vault};

use super::git::{
    branch_exists, commit_signing_configured, current_branch, git_bytes, git_line, list_items,
    toplevel,
};
use super::item::parse_item;
use super::keys::InboxKeys;
use super::trust::{check_inbox_pubkey, check_local_inbox_pubkey, verify_inbox_signatures};
use super::{DecryptFn, InboxOptions, InboxReport, INBOX_BRANCH};

/// Early exit when there is nothing to merge, or the inputs for planning.
pub(crate) enum PreflightOutcome {
    Report(InboxReport),
    Ready(Box<Preflight>),
}

pub(crate) struct Preflight {
    pub vault_root: PathBuf,
    pub repo: PathBuf,
    pub branch: String,
    pub vault: Vault,
    pub warnings: Vec<String>,
    pub tip: String,
    pub names: Vec<String>,
    pub items: Vec<super::item::ParsedItem>,
}

pub(crate) fn preflight(
    vault_root: &Path,
    opts: &InboxOptions,
    decrypt: &DecryptFn,
    inbox_keys: Option<&InboxKeys>,
) -> anyhow::Result<PreflightOutcome> {
    let vault_root = vault_root.canonicalize().map_err(|e| {
        anyhow::anyhow!("could not resolve vault path {}: {e}", vault_root.display())
    })?;
    let repo = toplevel(&vault_root)?;
    let branch = current_branch(&repo)?;
    let vault = load_vault(&vault_root)?;
    if vault.config.spec != crate::config::SPEC_VERSION {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let mut warnings = Vec::new();
    if vault
        .config
        .inbox
        .pubkey
        .as_ref()
        .is_none_or(|k| k.trim().is_empty())
    {
        warnings.push(
            "no [inbox].pubkey in confidant.toml; outside tools cannot discover the vault's inbox key"
                .to_string(),
        );
    }
    if !super::git::tree_is_clean(&repo)? {
        return Err(anyhow::Error::new(DomainError::inbox_dirty()));
    }
    if !branch_exists(&repo, INBOX_BRANCH)? {
        return Ok(PreflightOutcome::Report(InboxReport {
            branch,
            items: Vec::new(),
            merged: 0,
            cleared: 0,
            dry_run: opts.dry_run,
            warnings,
            empty: true,
        }));
    }

    check_inbox_pubkey(
        vault.config.inbox.pubkey.as_deref(),
        opts.pinned_pubkey.as_deref(),
        &mut warnings,
    )?;

    if let Some(keys) = inbox_keys {
        check_local_inbox_pubkey(
            vault.config.inbox.pubkey.as_deref(),
            &keys.current_recipient(),
        )?;
    }

    if opts.trusted_signers.is_empty() && !opts.allow_unsigned {
        return Err(anyhow::Error::new(DomainError::inbox_untrusted(
            "no [trust] signers configured; refusing to merge the inbox branch \
             (configure signers in ~/.config/confidant/config.toml or pass --allow-unsigned)",
        )));
    }
    if opts.allow_unsigned {
        warnings
            .push("proceeding without inbox signature verification (--allow-unsigned)".to_string());
    }

    let tip = git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    verify_inbox_signatures(&repo, &tip, &opts.trusted_signers)?;

    let names = list_items(&repo, &tip)?;
    let mut items = Vec::with_capacity(names.len());
    for name in &names {
        let bytes = git_bytes(&repo, &format!("{tip}:{name}.age"))?;
        let plaintext = decrypt(bytes.as_slice()).map_err(|e| match DomainError::of(&e) {
            Some(d) => anyhow::Error::new(d.clone()),
            None => anyhow::Error::new(DomainError::inbox_item(format!(
                "item '{name}' could not be decrypted"
            ))),
        })?;
        let text = String::from_utf8(plaintext).map_err(|_| {
            anyhow::Error::new(DomainError::inbox_item(format!(
                "item '{name}' decrypted to non-UTF-8"
            )))
        })?;
        items.push(parse_item(name, &text)?);
    }

    let current_tip = git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    if current_tip != tip {
        return Err(anyhow::Error::new(DomainError::inbox_race(
            &tip,
            &current_tip,
        )));
    }

    if !opts.dry_run && !names.is_empty() && !commit_signing_configured(&repo)? {
        return Err(anyhow::Error::new(DomainError::inbox_signing_unconfigured()));
    }

    Ok(PreflightOutcome::Ready(Box::new(Preflight {
        vault_root,
        repo,
        branch,
        vault,
        warnings,
        tip,
        names,
        items,
    })))
}
