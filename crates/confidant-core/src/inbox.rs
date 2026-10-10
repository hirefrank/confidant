//! Encrypted intake via the `inbox` git branch (architecture §8a).
//!
//! Outside tools encrypt items to the vault's public inbox key (age X25519)
//! and push them to the `inbox` branch. `confidant inbox` decrypts the
//! items, runs `check` on the merged result, merges into the current branch,
//! and clears the inbox.
//!
//! Intake never uses webhooks, and no decryption keys live in CI: the
//! private inbox key lives with the operator (see `docs/inbox.md`).
//!
//! Trust (all fail closed):
//! - Every commit that adds or changes an item must carry a valid signature
//!   from a `[trust]` signer (ADR-10) — checking only the tip is not enough.
//!   With no signers configured the run refuses unless `--allow-unsigned`.
//! - The vault's advertised `[inbox].pubkey` must match the operator's
//!   out-of-band pin (`~/.config/confidant/config.toml [inbox] pubkey`);
//!   the vault copy is informational only.
//! - The vault's advertised `[inbox].pubkey` must also match the recipient
//!   derived from the local inbox private key (OS keychain); a mismatch is
//!   a hard error — the pin is a file an attacker with local write access
//!   could tamper with, but the private key is the ground truth for who can
//!   actually read these items (#55).
//! - Intake lines are limited: every ledger line needs a `src:`, and the
//!   `merge` / `balance` verbs are rejected — identity and balance changes
//!   come from the operator, not intake.
//!
//! The run is all-or-nothing: if any item fails to decrypt, parse, or pass
//! `check`, nothing is merged and nothing is cleared. Importing twice adds
//! nothing: ledger lines whose `src:` already exists (or whose exact text is
//! already present) are skipped, and record items identical to the target
//! are skipped.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use crate::check::{run as check_vault, CheckOptions, Severity};
use crate::error::DomainError;
use crate::ledger::parse_line;
use crate::paths;
use crate::vault::load_vault;

/// The git branch outside tools push intake items to.
pub const INBOX_BRANCH: &str = "inbox";
/// First line of every decrypted inbox payload.
const ITEM_MARKER: &str = "confidant-inbox/1";
/// Separates the item header from its content.
const HEADER_SEP: &str = "---";
/// Collection roots a `kind: record` item may target.
const RECORD_ROOTS: &[&str] = &["people", "orgs", "deals", "interactions", "notes"];

/// Decrypts item ciphertext. Production passes a closure over [`InboxKeys`]
/// (the real `confidant-crypt` age path); tests inject a fake.
pub type DecryptFn = dyn Fn(&[u8]) -> anyhow::Result<Vec<u8>>;

/// Inbox decryption key material, loaded once per run.
///
/// Holds the current inbox identity and, during the rotation window
/// (§8a.3), the previous one. Decryption tries current then previous
/// ("tries old then new"); the #55 pubkey comparison uses the current key
/// only, since the vault advertises the new key after `rotate`.
pub struct InboxKeys {
    current: age::x25519::Identity,
    previous: Option<age::x25519::Identity>,
}

impl InboxKeys {
    /// Load both slots from the OS keychain (or `CONFIDANT_INBOX_KEY` /
    /// `CONFIDANT_INBOX_KEY_PREVIOUS` on headless hosts — see
    /// `confidant_crypt::keychain`). Fails closed with `E_INBOX_CRYPTO`:
    /// a missing key, a bad key, or an undecryptable identity is an error,
    /// never silent plaintext.
    pub fn load() -> anyhow::Result<Self> {
        let (current, previous) = confidant_crypt::keychain::inbox_identities()
            .map_err(|e| anyhow::Error::new(DomainError::inbox_crypto(format!("{e}"))))?;
        Ok(Self { current, previous })
    }

    /// Load, returning `None` when no key is enrolled (genuine `NoKey`).
    /// A legacy-file refusal or keychain error surfaces directly — it is
    /// not skipped, so it cannot resurface later as a generic decrypt
    /// failure.
    pub fn load_opt() -> anyhow::Result<Option<Self>> {
        match confidant_crypt::keychain::inbox_identities() {
            Ok((current, previous)) => Ok(Some(Self { current, previous })),
            Err(confidant_crypt::Error::NoKey(_)) => Ok(None),
            Err(e) => Err(anyhow::Error::new(DomainError::inbox_crypto(format!(
                "{e}"
            )))),
        }
    }

    /// Decrypt with the current key, falling back to the previous one
    /// during the rotation window. Fails closed with `E_INBOX_CRYPTO`.
    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match confidant_crypt::age_wrap::unwrap_with_identity(ciphertext, &self.current) {
            Ok(plaintext) => Ok(plaintext),
            Err(first) => {
                if let Some(previous) = &self.previous {
                    if let Ok(plaintext) =
                        confidant_crypt::age_wrap::unwrap_with_identity(ciphertext, previous)
                    {
                        return Ok(plaintext);
                    }
                }
                Err(anyhow::Error::new(DomainError::inbox_crypto(format!(
                    "{first}"
                ))))
            }
        }
    }

    /// The current key's age recipient, for the #55 comparison against the
    /// vault's advertised `[inbox].pubkey`.
    pub fn current_recipient(&self) -> String {
        self.current.to_public().to_string()
    }
}

/// The old load-per-call decryptor. Test-only: production code loads
/// [`InboxKeys`] once and closes over it, so the N+1 key-loading path
/// can't get wired back in outside tests.
#[cfg(test)]
pub fn inbox_decrypt(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let keys = InboxKeys::load()?;
    keys.decrypt(ciphertext)
}

/// Options for [`run_inbox`].
#[derive(Clone, Debug, Default)]
pub struct InboxOptions {
    /// Preview only: decrypt and plan, but commit nothing and clear nothing.
    pub dry_run: bool,
    /// Signing key IDs (`git log --format=%GK`) trusted to push the inbox
    /// branch (ADR-10). Every commit that adds or changes an item must carry
    /// a valid signature from one of these keys.
    pub trusted_signers: Vec<String>,
    /// Proceed without any signature verification. Only for setups that have
    /// not configured `[trust] signers` yet; with signers configured this
    /// changes nothing.
    pub allow_unsigned: bool,
    /// The operator's out-of-band pin of the vault's inbox public key (from
    /// `~/.config/confidant/config.toml [inbox] pubkey`). When set, the run
    /// refuses if the vault's `confidant.toml [inbox].pubkey` differs
    /// (possible key substitution).
    pub pinned_pubkey: Option<String>,
}

/// What happened to one item.
#[derive(Clone, Debug)]
pub struct ItemOutcome {
    /// Item file stem (opaque; no PII).
    pub name: String,
    /// `"ledger"` or `"record"`.
    pub kind: String,
    /// Vault-relative merge target.
    pub target: String,
    /// `"merge"` or `"skip"` (already present).
    pub action: String,
}

/// Result of [`run_inbox`].
#[derive(Clone, Debug)]
pub struct InboxReport {
    /// Mainline branch the items were merged into.
    pub branch: String,
    pub items: Vec<ItemOutcome>,
    pub merged: usize,
    pub cleared: usize,
    pub dry_run: bool,
    pub warnings: Vec<String>,
    /// True when there is no inbox branch: nothing to do.
    pub empty: bool,
}

/// A decrypted, parsed inbox item.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedItem {
    name: String,
    kind: ItemKind,
    /// Vault-relative target path (records only).
    path: Option<PathBuf>,
    content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ItemKind {
    Ledger,
    Record,
}

/// Run the inbox: decrypt items on the `inbox` branch, `check` the merged
/// vault, merge into the current branch, and clear the inbox.
///
/// `vault_root` is the discovered vault directory (need not be the git
/// toplevel). The working tree must be clean; the run refuses otherwise.
///
/// `inbox_keys` is the key material loaded once by the caller (see
/// [`InboxKeys::load_opt`]); the #55 pubkey comparison uses its current
/// recipient. Pass `None` when no key is enrolled — the comparison is
/// skipped and decryption fails closed later. Tests that inject a fake
/// `decrypt` pass `None`.
pub fn run_inbox(
    vault_root: &Path,
    opts: &InboxOptions,
    decrypt: &DecryptFn,
    inbox_keys: Option<&InboxKeys>,
) -> anyhow::Result<InboxReport> {
    // Canonicalize up front: git reports the physical toplevel (e.g. macOS
    // /private/var vs /var), and path prefix checks below must agree.
    let vault_root = vault_root.canonicalize().map_err(|e| {
        anyhow::anyhow!("could not resolve vault path {}: {e}", vault_root.display())
    })?;
    let vault_root = vault_root.as_path();
    let repo = toplevel(vault_root)?;
    let branch = current_branch(&repo)?;
    let vault = load_vault(vault_root)?;
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
    if !tree_is_clean(&repo)? {
        return Err(anyhow::Error::new(DomainError::inbox_dirty()));
    }
    if !branch_exists(&repo, INBOX_BRANCH)? {
        return Ok(InboxReport {
            branch,
            items: Vec::new(),
            merged: 0,
            cleared: 0,
            dry_run: opts.dry_run,
            warnings,
            empty: true,
        });
    }

    // Key-substitution defense: the vault's advertised inbox key must match
    // the operator's out-of-band pin. Anyone with git write access can change
    // confidant.toml; only the local pin is trustworthy.
    check_inbox_pubkey(
        vault.config.inbox.pubkey.as_deref(),
        opts.pinned_pubkey.as_deref(),
        &mut warnings,
    )?;

    // Key-substitution defense, second factor (#55): the local private key
    // is the ground truth for who can read these items, so its recipient
    // must agree with the vault's advertised key. Hard error on mismatch.
    // Compares against the CURRENT key only: the vault advertises the new
    // key after `inbox rotate`, while decrypt still accepts the previous
    // one during the rotation window.
    if let Some(keys) = inbox_keys {
        check_local_inbox_pubkey(
            vault.config.inbox.pubkey.as_deref(),
            &keys.current_recipient(),
        )?;
    }

    // Fail closed on unconfigured trust: warn-and-proceed let an unsigned
    // branch through, so it is gone. --allow-unsigned is the explicit opt-in.
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

    // #29: resolve the inbox tip SHA once, BEFORE signature verification,
    // and use that SHA for every inbox read below (verification, item list,
    // item bytes). Reading by branch name would reopen the verify->read
    // window: a push landing between verification and the reads could slip
    // unsigned items past the trust check or swap the bytes under the
    // reads. The tip is rechecked after the reads and again immediately
    // before clearing.
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

    // #29: confirm the tip hasn't moved since it was pinned before
    // verification. A push in between means the bytes we merged may be
    // stale (or unverified), so the run refuses instead of clearing
    // content it never saw.
    let current_tip = git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    if current_tip != tip {
        return Err(anyhow::Error::new(DomainError::inbox_race(
            &tip,
            &current_tip,
        )));
    }

    // #52 (ADR-10): the merge and clear commits below must be signed — main
    // accepts trusted signers only. Fail closed before applying any writes
    // when the operator hasn't configured commit signing.
    if !opts.dry_run && !names.is_empty() && !commit_signing_configured(&repo)? {
        return Err(anyhow::Error::new(DomainError::inbox_signing_unconfigured()));
    }

    let existing_srcs = collect_ledger_srcs(vault_root);
    let mut outcomes = Vec::new();
    let mut applied: Vec<AppliedChange> = Vec::new();
    for item in &items {
        match plan_item(vault_root, item, &existing_srcs)? {
            Some((outcome, writes)) => {
                if !opts.dry_run {
                    apply_writes(vault_root, &writes, &mut applied)?;
                }
                outcomes.push(outcome);
            }
            None => outcomes.push(ItemOutcome {
                name: item.name.clone(),
                kind: item.kind.as_str().to_string(),
                target: describe_target(item),
                action: "skip".to_string(),
            }),
        }
    }

    if !opts.dry_run {
        // `check` the merged vault before committing anything.
        let merged_vault = load_vault(vault_root)?;
        let report = check_vault(
            &merged_vault,
            &CheckOptions {
                as_of: None,
                fail_on: Some(Severity::Error),
                pinned_inbox_pubkey: opts.pinned_pubkey.clone(),
            },
        );
        if !report.ok {
            revert_applied(&applied);
            return Err(anyhow::Error::new(DomainError::inbox_check_failed(
                format!(
                    "merged inbox content fails check: {} error(s), {} warning(s)",
                    report.summary.errors, report.summary.warnings
                ),
            )));
        }
        let merged = outcomes.iter().filter(|o| o.action == "merge").count();
        if merged > 0 {
            if let Err(e) = commit_applied(&repo, &applied, &outcomes) {
                // All-or-nothing: the merge commit failed (e.g. a
                // configured-but-broken signing setup), so unstage the
                // applied paths and restore the worktree. The inbox is
                // untouched — the clear never ran.
                unstage_applied(&repo, &applied);
                revert_applied(&applied);
                return Err(e);
            }
        }
        clear_inbox(&repo, &tip, &names)?;
    }

    let merged = outcomes.iter().filter(|o| o.action == "merge").count();
    Ok(InboxReport {
        branch,
        merged,
        cleared: if opts.dry_run { 0 } else { names.len() },
        items: outcomes,
        dry_run: opts.dry_run,
        warnings,
        empty: false,
    })
}

impl ItemKind {
    fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Ledger => "ledger",
            ItemKind::Record => "record",
        }
    }
}

fn describe_target(item: &ParsedItem) -> String {
    match item.kind {
        ItemKind::Ledger => "ledger/*".to_string(),
        ItemKind::Record => item
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// git plumbing (shell-out; the CLI already requires a git vault)
// ---------------------------------------------------------------------------

fn git(repo: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
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

fn git_line(repo: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = git(repo, args)?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_bytes(repo: &Path, spec: &str) -> anyhow::Result<Vec<u8>> {
    Ok(git(repo, &["show", spec])?.stdout)
}

fn toplevel(vault_root: &Path) -> anyhow::Result<PathBuf> {
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

fn tree_is_clean(repo: &Path) -> anyhow::Result<bool> {
    Ok(git_line(repo, &["status", "--porcelain"])?.is_empty())
}

fn current_branch(repo: &Path) -> anyhow::Result<String> {
    let name = git_line(repo, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    if name == "HEAD" {
        return Err(anyhow::Error::new(DomainError::invalid(
            "`confidant inbox` needs a checked-out branch, not a detached HEAD",
        )));
    }
    Ok(name)
}

fn branch_exists(repo: &Path, name: &str) -> anyhow::Result<bool> {
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

/// The operator's out-of-band pin of the inbox public key must match the
/// vault's advertised `[inbox].pubkey`. A mismatch is `E_INBOX_UNTRUSTED`:
/// anyone with git write access can rewrite `confidant.toml`, so only the
/// local pin is trustworthy. No pin configured is a warning, not an error —
/// the pin is opt-in hardening, and refusing would break every setup that
/// never opted in.
fn check_inbox_pubkey(
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
fn check_local_inbox_pubkey(
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
fn verify_inbox_signatures(repo: &Path, tip: &str, trusted: &[String]) -> anyhow::Result<()> {
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
fn verify_commit_signature(
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

/// Item file stems on the inbox branch at the pinned `tip` SHA. The inbox
/// branch is an orphan branch whose root holds only `<name>.age` items;
/// anything else is `E_INBOX_ITEM` (fail closed).
fn list_items(repo: &Path, tip: &str) -> anyhow::Result<Vec<String>> {
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

fn is_item_stem(stem: &str) -> bool {
    let mut chars = stem.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    stem.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ---------------------------------------------------------------------------
// item parsing
// ---------------------------------------------------------------------------

/// Parse a decrypted payload. Format:
/// ```text
/// confidant-inbox/1
/// kind: ledger            # or: kind: record
/// path: people/p-.../profile.md   # records only
/// ---
/// <content>
/// ```
fn parse_item(name: &str, text: &str) -> anyhow::Result<ParsedItem> {
    let fail = |why: &str| {
        anyhow::Error::new(DomainError::inbox_item(format!(
            "item '{name}' is malformed: {why}"
        )))
    };
    let mut kind: Option<ItemKind> = None;
    let mut path: Option<String> = None;
    let mut body_at: Option<usize> = None;
    let all: Vec<&str> = text.lines().collect();
    match all.first() {
        Some(l) if l.trim_end_matches(['\r', ' ']) == ITEM_MARKER => {}
        _ => return Err(fail("first line must be `confidant-inbox/1`")),
    }
    for (i, line) in all.iter().enumerate().skip(1) {
        if *line == HEADER_SEP {
            body_at = Some(i + 1);
            break;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| fail("bad header line"))?;
        match k.trim() {
            "kind" => {
                if kind.is_some() {
                    return Err(fail("duplicate kind header"));
                }
                kind = Some(match v.trim() {
                    "ledger" => ItemKind::Ledger,
                    "record" => ItemKind::Record,
                    _ => return Err(fail("kind must be `ledger` or `record`")),
                });
            }
            "path" => {
                if path.is_some() {
                    return Err(fail("duplicate path header"));
                }
                path = Some(v.trim().to_string());
            }
            _ => return Err(fail("unknown header (only `kind` and `path`)")),
        }
    }
    let kind = kind.ok_or_else(|| fail("missing `kind` header"))?;
    let body_at = body_at.ok_or_else(|| fail("missing `---` separator"))?;
    let content = all[body_at..].join("\n");
    if content.trim().is_empty() {
        return Err(fail("empty content"));
    }
    let path = match kind {
        ItemKind::Ledger => {
            if path.is_some() {
                return Err(fail("`path` is only for `kind: record`"));
            }
            None
        }
        ItemKind::Record => {
            let p = path.ok_or_else(|| fail("`kind: record` needs a `path` header"))?;
            Some(validate_record_path(&p).map_err(|why| fail(&why))?)
        }
    };
    Ok(ParsedItem {
        name: name.to_string(),
        kind,
        path,
        content,
    })
}

/// Vault-relative record paths stay inside the collection roots and cannot
/// escape the vault.
fn validate_record_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() {
        return Err("empty path".to_string());
    }
    let p = Path::new(raw);
    if p.is_absolute() {
        return Err("path must be vault-relative".to_string());
    }
    let mut comps = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => comps.push(s.to_string_lossy().into_owned()),
            _ => return Err("path must not contain `.`, `..`, or prefixes".to_string()),
        }
    }
    if comps.is_empty() {
        return Err("empty path".to_string());
    }
    if !RECORD_ROOTS.contains(&comps[0].as_str()) {
        return Err(format!(
            "record path must live under one of {}",
            RECORD_ROOTS.join(", ")
        ));
    }
    if !comps.last().is_some_and(|f| f.ends_with(".md")) {
        return Err("record path must end in `.md`".to_string());
    }
    Ok(comps.iter().collect())
}

// ---------------------------------------------------------------------------
// merge planning
// ---------------------------------------------------------------------------

/// `src:` values on a ledger entry (token `src:x` or pair `src: x`).
fn entry_srcs(args: &[crate::ledger::Arg]) -> Vec<String> {
    args.iter()
        .filter_map(|a| {
            if let Some(t) = a.as_token() {
                t.strip_prefix("src:").map(str::to_string)
            } else if let Some(("src", v)) = a.pair() {
                Some(v.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// All `src:` values already present in the vault's ledger files.
fn collect_ledger_srcs(vault_root: &Path) -> BTreeSet<String> {
    let mut srcs = BTreeSet::new();
    let ledger = vault_root.join("ledger");
    let mut stack = vec![ledger];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in text.lines() {
                if let Ok(Some(e)) = parse_line(line) {
                    srcs.extend(entry_srcs(&e.args));
                }
            }
        }
    }
    srcs
}

fn month_file(date: &chrono::NaiveDate) -> PathBuf {
    PathBuf::from(format!("ledger/{}.cfd", date.format("%Y/%m")))
}

/// A concrete filesystem write the merge will perform.
#[derive(Clone, Debug)]
enum PlannedWrite {
    LedgerAppend { file: PathBuf, lines: Vec<String> },
    RecordWrite { path: PathBuf, content: String },
}

/// What was changed on disk (for revert on `check` failure).
#[derive(Clone, Debug)]
enum AppliedChange {
    Modified {
        abs: PathBuf,
        previous: Option<Vec<u8>>,
    },
}

/// Plan one item. Returns `None` when everything it carries is already
/// present (idempotent re-import adds nothing).
fn plan_item(
    vault_root: &Path,
    item: &ParsedItem,
    existing_srcs: &BTreeSet<String>,
) -> anyhow::Result<Option<(ItemOutcome, Vec<PlannedWrite>)>> {
    match item.kind {
        ItemKind::Ledger => {
            // Group new lines per month file, preserving item order.
            let mut by_file: Vec<(PathBuf, Vec<String>)> = Vec::new();
            for (n, raw) in item.content.lines().enumerate() {
                let line_no = n + 1;
                if raw.trim().is_empty() || raw.trim_start().starts_with(';') {
                    continue;
                }
                let entry = parse_line(raw).map_err(|e| {
                    anyhow::Error::new(DomainError::inbox_item(format!(
                        "item '{}' line {line_no}: {e}",
                        item.name
                    )))
                })?;
                let Some(entry) = entry else { continue };
                // Intake limits: identity and balance changes come from the
                // operator, never from intake. One crafted `merge` item could
                // fold two clients together; one `balance` item could rewrite
                // a balance assertion.
                if entry.verb == "merge" || entry.verb == "balance" {
                    return Err(anyhow::Error::new(DomainError::inbox_item(format!(
                        "item '{}' line {line_no}: verb '{}' is not allowed from intake",
                        item.name, entry.verb
                    ))));
                }
                // Every inbox ledger line carries provenance: `src:` is how
                // re-imports stay idempotent and how the operator traces where
                // a line came from.
                if entry_srcs(&entry.args).is_empty() {
                    return Err(anyhow::Error::new(DomainError::inbox_item(format!(
                        "item '{}' line {line_no}: every inbox ledger line needs a `src:`",
                        item.name
                    ))));
                }
                let target = month_file(&entry.date);
                // Idempotency: skip lines already imported (by src: or exact text).
                let dominated = entry_srcs(&entry.args)
                    .iter()
                    .any(|s| existing_srcs.contains(s));
                if dominated {
                    continue;
                }
                let existing =
                    std::fs::read_to_string(vault_root.join(&target)).unwrap_or_default();
                if existing.lines().any(|l| l.trim_end() == raw.trim_end()) {
                    continue;
                }
                match by_file.iter_mut().find(|(f, _)| *f == target) {
                    Some((_, lines)) => lines.push(raw.to_string()),
                    None => by_file.push((target, vec![raw.to_string()])),
                }
            }
            if by_file.is_empty() {
                return Ok(None);
            }
            let target = by_file
                .iter()
                .map(|(f, _)| f.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let writes = by_file
                .into_iter()
                .map(|(file, lines)| PlannedWrite::LedgerAppend { file, lines })
                .collect();
            Ok(Some((
                ItemOutcome {
                    name: item.name.clone(),
                    kind: "ledger".to_string(),
                    target,
                    action: "merge".to_string(),
                },
                writes,
            )))
        }
        ItemKind::Record => {
            let rel = item.path.as_ref().expect("record items have a path");
            let abs = vault_root.join(rel);
            if abs.is_file() {
                let current = std::fs::read_to_string(&abs).unwrap_or_default();
                if current == item.content {
                    return Ok(None);
                }
                return Err(anyhow::Error::new(DomainError::inbox_conflict(
                    rel.display().to_string(),
                )));
            }
            let writes = vec![PlannedWrite::RecordWrite {
                path: rel.clone(),
                content: item.content.clone(),
            }];
            Ok(Some((
                ItemOutcome {
                    name: item.name.clone(),
                    kind: "record".to_string(),
                    target: rel.display().to_string(),
                    action: "merge".to_string(),
                },
                writes,
            )))
        }
    }
}

/// Apply planned writes to the working tree, recording previous bytes for
/// revert. Uses atomic replace (`paths::write_replace`).
fn apply_writes(
    vault_root: &Path,
    writes: &[PlannedWrite],
    applied: &mut Vec<AppliedChange>,
) -> anyhow::Result<()> {
    for w in writes {
        match w {
            PlannedWrite::LedgerAppend { file, lines } => {
                let abs = vault_root.join(file);
                let previous = std::fs::read(&abs).ok();
                if let Some(parent) = abs.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!("could not create {}: {e}", parent.display())
                    })?;
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
                let previous = std::fs::read(&abs).ok();
                if let Some(parent) = abs.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!("could not create {}: {e}", parent.display())
                    })?;
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
fn revert_applied(applied: &[AppliedChange]) {
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
fn unstage_applied(repo: &Path, applied: &[AppliedChange]) {
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
fn commit_applied(
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
fn clear_inbox(repo: &Path, expected_tip: &str, names: &[String]) -> anyhow::Result<()> {
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
fn verify_inbox_tip(repo: &Path, expected_tip: &str) -> anyhow::Result<()> {
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
fn build_cleared_tree(repo: &Path, old_tip: &str, names: &[String]) -> anyhow::Result<String> {
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
fn commit_signing_configured(repo: &Path) -> anyhow::Result<bool> {
    if git_config_bool(repo, "commit.gpgsign")?.unwrap_or(false) {
        return Ok(true);
    }
    Ok(git_config_get(repo, "user.signingkey")?.is_some_and(|s| !s.is_empty()))
}

/// `git config --type=bool --get`: `None` when the key is unset or not a
/// valid boolean (git exits non-zero); otherwise the normalized value.
fn git_config_bool(repo: &Path, key: &str) -> anyhow::Result<Option<bool>> {
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
fn git_config_get(repo: &Path, key: &str) -> anyhow::Result<Option<String>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    /// Fixed test-only inbox identities. Every crypto test uses the same
    /// values so parallel tests never race on the env var's *value*; tests
    /// that mutate the var take [`EnvGuard::lock`].
    const TEST_INBOX_SECRET_A: [u8; 32] = [7u8; 32];
    const TEST_INBOX_SECRET_B: [u8; 32] = [9u8; 32];

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serialize tests that mutate `CONFIDANT_INBOX_KEY`, saving and
    /// restoring the ambient value. Tolerates a poisoned mutex: a panicking
    /// test already fails the run.
    struct EnvGuard {
        saved: Option<String>,
        saved_previous: Option<String>,
        saved_keychain: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn lock() -> Self {
            EnvGuard {
                saved: std::env::var("CONFIDANT_INBOX_KEY").ok(),
                saved_previous: std::env::var("CONFIDANT_INBOX_KEY_PREVIOUS").ok(),
                saved_keychain: std::env::var("CONFIDANT_KEYCHAIN").ok(),
                _lock: ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
            }
        }
        fn set(&self, val: &str) {
            std::env::set_var("CONFIDANT_INBOX_KEY", val);
        }
        fn unset(&self) {
            std::env::remove_var("CONFIDANT_INBOX_KEY");
            std::env::remove_var("CONFIDANT_INBOX_KEY_PREVIOUS");
        }
        /// Keep the test off the real OS keychain backend.
        fn no_keychain(&self) {
            std::env::set_var("CONFIDANT_KEYCHAIN", "off");
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.saved.take() {
                Some(v) => std::env::set_var("CONFIDANT_INBOX_KEY", v),
                None => std::env::remove_var("CONFIDANT_INBOX_KEY"),
            }
            match self.saved_previous.take() {
                Some(v) => std::env::set_var("CONFIDANT_INBOX_KEY_PREVIOUS", v),
                None => std::env::remove_var("CONFIDANT_INBOX_KEY_PREVIOUS"),
            }
            match self.saved_keychain.take() {
                Some(v) => std::env::set_var("CONFIDANT_KEYCHAIN", v),
                None => std::env::remove_var("CONFIDANT_KEYCHAIN"),
            }
        }
    }

    fn test_recipient(secret: &[u8; 32]) -> String {
        confidant_crypt::age_wrap::RawX25519Identity::new(*secret).to_recipient_string()
    }

    fn test_bech32(secret: &[u8; 32]) -> String {
        confidant_crypt::age_wrap::RawX25519Identity::new(*secret)
            .to_bech32()
            .to_string()
    }

    const LEDGER_ITEM: &str = "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 45m note \"intake call\" src:tt-1\n";
    const RECORD_ITEM: &str =
        "confidant-inbox/1\nkind: record\npath: people/p-acme/profile.md\n---\n# Acme\n";

    fn identity(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }

    #[test]
    fn parses_ledger_item() {
        let item = parse_item("01JABC", LEDGER_ITEM).unwrap();
        assert_eq!(item.kind, ItemKind::Ledger);
        assert_eq!(item.path, None);
        assert!(item.content.contains("2026-10-08"));
    }

    #[test]
    fn parses_record_item() {
        let item = parse_item("01JABC", RECORD_ITEM).unwrap();
        assert_eq!(item.kind, ItemKind::Record);
        assert_eq!(item.path, Some(PathBuf::from("people/p-acme/profile.md")));
    }

    #[test]
    fn rejects_bad_marker() {
        let err = parse_item("x", "kind: ledger\n---\nfoo\n").unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = parse_item("x", "confidant-inbox/1\nkind: photos\n---\nfoo\n").unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn rejects_record_without_path() {
        let err = parse_item("x", "confidant-inbox/1\nkind: record\n---\nfoo\n").unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn rejects_path_traversal() {
        for raw in ["../vault", "people/../../x.md", "/abs/path.md", "people"] {
            let text = format!("confidant-inbox/1\nkind: record\npath: {raw}\n---\nfoo\n");
            let err = parse_item("x", &text).unwrap_err();
            assert_eq!(
                DomainError::of(&err).unwrap().code(),
                "E_INBOX_ITEM",
                "raw={raw}"
            );
        }
    }

    #[test]
    fn rejects_path_outside_collections() {
        let text = "confidant-inbox/1\nkind: record\npath: ledger/2026/10.md\n---\nfoo\n";
        let err = parse_item("x", text).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn rejects_non_markdown_record() {
        let text = "confidant-inbox/1\nkind: record\npath: people/x.txt\n---\nfoo\n";
        let err = parse_item("x", text).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn rejects_empty_content() {
        let err = parse_item("x", "confidant-inbox/1\nkind: ledger\n---\n").unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn item_stem_rules() {
        assert!(is_item_stem("01JB9ZQK7N"));
        assert!(is_item_stem("a-1_B"));
        assert!(!is_item_stem(""));
        assert!(!is_item_stem("-abc"));
        assert!(!is_item_stem("a b"));
        assert!(!is_item_stem("a/b"));
        assert!(!is_item_stem(&"a".repeat(129)));
    }

    #[test]
    fn inbox_decrypt_fails_closed_without_key() {
        // No local key: unset the env override and disable the keychain
        // backend (fail closed either way).
        let g = EnvGuard::lock();
        g.unset();
        g.no_keychain();
        let err = inbox_decrypt(b"nope").unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CRYPTO");
    }

    #[test]
    fn inbox_decrypt_round_trips_with_key() {
        let g = EnvGuard::lock();
        g.set(&test_bech32(&TEST_INBOX_SECRET_A));
        g.no_keychain();
        let ciphertext = confidant_crypt::age_wrap::wrap_to_recipient(
            b"item bytes",
            &test_recipient(&TEST_INBOX_SECRET_A),
        )
        .unwrap();
        let back = inbox_decrypt(&ciphertext).unwrap();
        assert_eq!(back, b"item bytes");
    }

    #[test]
    fn inbox_decrypt_wrong_key_fails_closed() {
        let g = EnvGuard::lock();
        g.set(&test_bech32(&TEST_INBOX_SECRET_A));
        g.no_keychain();
        let ciphertext = confidant_crypt::age_wrap::wrap_to_recipient(
            b"item bytes",
            &test_recipient(&TEST_INBOX_SECRET_B),
        )
        .unwrap();
        let err = inbox_decrypt(&ciphertext).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CRYPTO");
    }

    #[test]
    fn decrypt_tries_previous_during_rotation_window() {
        // Item encrypted to the PREVIOUS key decrypts while the previous
        // slot is populated (§8a.3 "tries old then new").
        let g = EnvGuard::lock();
        g.set(&test_bech32(&TEST_INBOX_SECRET_A));
        // Keep the test off the real OS keychain; the previous slot comes
        // from the env override below.
        g.no_keychain();
        std::env::set_var(
            "CONFIDANT_INBOX_KEY_PREVIOUS",
            test_bech32(&TEST_INBOX_SECRET_B),
        );
        let keys = InboxKeys::load().unwrap();
        let ciphertext = confidant_crypt::age_wrap::wrap_to_recipient(
            b"item bytes",
            &test_recipient(&TEST_INBOX_SECRET_B),
        )
        .unwrap();
        let plaintext = keys.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"item bytes");
        std::env::remove_var("CONFIDANT_INBOX_KEY_PREVIOUS");
    }

    #[test]
    fn decrypt_fails_closed_after_previous_deleted() {
        // Previous slot empty: an item encrypted to the old key fails
        // closed with E_INBOX_CRYPTO.
        let g = EnvGuard::lock();
        g.set(&test_bech32(&TEST_INBOX_SECRET_A));
        std::env::remove_var("CONFIDANT_INBOX_KEY_PREVIOUS");
        g.no_keychain();
        let keys = InboxKeys::load().unwrap();
        let ciphertext = confidant_crypt::age_wrap::wrap_to_recipient(
            b"item bytes",
            &test_recipient(&TEST_INBOX_SECRET_B),
        )
        .unwrap();
        let err = keys.decrypt(&ciphertext).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CRYPTO");
    }

    #[test]
    fn load_opt_returns_none_without_key() {
        // Genuine NoKey: env unset and keychain disabled → None (skip #55,
        // decrypt fails closed later).
        let g = EnvGuard::lock();
        g.unset();
        g.no_keychain();
        let keys = InboxKeys::load_opt().unwrap();
        assert!(keys.is_none());
    }

    #[test]
    fn local_pubkey_check_skips_without_vault_pubkey() {
        let local = test_recipient(&TEST_INBOX_SECRET_A);
        // Vault advertises nothing: nothing to compare against.
        check_local_inbox_pubkey(None, &local).unwrap();
        check_local_inbox_pubkey(Some("  "), &local).unwrap();
    }

    #[test]
    fn local_pubkey_match_is_ok() {
        let local = test_recipient(&TEST_INBOX_SECRET_A);
        check_local_inbox_pubkey(Some(&test_recipient(&TEST_INBOX_SECRET_A)), &local).unwrap();
    }

    #[test]
    fn local_pubkey_mismatch_is_hard_error() {
        let local = test_recipient(&TEST_INBOX_SECRET_A);
        let err = check_local_inbox_pubkey(Some(&test_recipient(&TEST_INBOX_SECRET_B)), &local)
            .unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    }

    #[test]
    fn local_pubkey_malformed_vault_key_is_hard_error() {
        let local = test_recipient(&TEST_INBOX_SECRET_A);
        let err = check_local_inbox_pubkey(Some("not-a-recipient"), &local).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    }

    #[test]
    fn local_pubkey_noncanonical_encoding_is_ok() {
        // The vault's pubkey parses to the same recipient even in
        // non-canonical case: comparison is on parsed values, not strings.
        let local = test_recipient(&TEST_INBOX_SECRET_A);
        check_local_inbox_pubkey(Some(&local.to_uppercase()), &local).unwrap();
    }

    #[test]
    fn pubkey_pin_match_is_ok() {
        let mut warnings = Vec::new();
        check_inbox_pubkey(Some("age1abc"), Some("age1abc"), &mut warnings).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn pubkey_pin_mismatch_is_untrusted() {
        let mut warnings = Vec::new();
        let err = check_inbox_pubkey(Some("age1attacker"), Some("age1operator"), &mut warnings)
            .unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    }

    #[test]
    fn pubkey_pin_missing_vault_key_is_untrusted() {
        let mut warnings = Vec::new();
        let err = check_inbox_pubkey(None, Some("age1operator"), &mut warnings).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    }

    #[test]
    fn pubkey_pin_absent_warns_but_proceeds() {
        let mut warnings = Vec::new();
        check_inbox_pubkey(Some("age1abc"), None, &mut warnings).unwrap();
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn plans_ledger_append_grouped_by_month() {
        let dir = TempDir::new().unwrap();
        let item = parse_item(
            "01JABC",
            "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 src:a\n2026-11-02 email p-01M3TC5H00MPJG000000000000 src:b\n",
        )
        .unwrap();
        let (outcome, writes) = plan_item(dir.path(), &item, &BTreeSet::new())
            .unwrap()
            .unwrap();
        assert_eq!(outcome.action, "merge");
        assert_eq!(outcome.target, "ledger/2026/10.cfd, ledger/2026/11.cfd");
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn skips_ledger_lines_by_src() {
        let dir = TempDir::new().unwrap();
        let mut srcs = BTreeSet::new();
        srcs.insert("tt-1".to_string());
        let item = parse_item("01JABC", LEDGER_ITEM).unwrap();
        assert!(plan_item(dir.path(), &item, &srcs).unwrap().is_none());
    }

    #[test]
    fn rejects_ledger_line_without_src() {
        let dir = TempDir::new().unwrap();
        // No src: at all — rejected even though the text is otherwise fine.
        let item = parse_item(
            "01JDEF",
            "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 45m\n",
        )
        .unwrap();
        let err = plan_item(dir.path(), &item, &BTreeSet::new()).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_ITEM");
    }

    #[test]
    fn skips_exact_duplicate_ledger_line() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            "2026-10-08 session p-01M3TC5H00MPJG000000000000 45m src:tt-9\n",
        )
        .unwrap();
        // Same text with a src: the vault has never seen — exact-text dedup
        // still skips it.
        let item = parse_item(
            "01JDEF",
            "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 45m src:tt-9\n",
        )
        .unwrap();
        assert!(plan_item(dir.path(), &item, &BTreeSet::new())
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_merge_and_balance_verbs() {
        let dir = TempDir::new().unwrap();
        for verb in ["merge", "balance"] {
            let item = parse_item(
                "01JDEF",
                &format!(
                    "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 {verb} p-01M3TC5H00MPJG000000000000 p-01M3TC5H00MPJG000000000001 src:evil-1\n"
                ),
            )
            .unwrap();
            let err = plan_item(dir.path(), &item, &BTreeSet::new()).unwrap_err();
            assert_eq!(
                DomainError::of(&err).unwrap().code(),
                "E_INBOX_ITEM",
                "verb={verb}"
            );
        }
    }

    #[test]
    fn record_conflict_on_different_content() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("people/p-acme")).unwrap();
        std::fs::write(dir.path().join("people/p-acme/profile.md"), "# Acme old\n").unwrap();
        let item = parse_item("01JABC", RECORD_ITEM).unwrap();
        let err = plan_item(dir.path(), &item, &BTreeSet::new()).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CONFLICT");
    }

    #[test]
    fn record_identical_is_idempotent() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("people/p-acme")).unwrap();
        std::fs::write(dir.path().join("people/p-acme/profile.md"), "# Acme").unwrap();
        let item = parse_item("01JABC", RECORD_ITEM).unwrap();
        assert!(plan_item(dir.path(), &item, &BTreeSet::new())
            .unwrap()
            .is_none());
    }

    #[test]
    fn collect_srcs_from_ledger_files() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            "2026-10-08 session p-01M3TC5H00MPJG000000000000 src:tt-1\n; comment\n2026-10-09 email p-01M3TC5H00MPJG000000000000 src:tt-2\n",
        )
        .unwrap();
        let srcs = collect_ledger_srcs(dir.path());
        assert!(srcs.contains("tt-1"));
        assert!(srcs.contains("tt-2"));
    }

    #[test]
    fn identity_decryptor_roundtrips() {
        // The DecryptFn is injectable: tests never touch real crypto.
        let pt = identity(LEDGER_ITEM.as_bytes()).unwrap();
        let item = parse_item("01JABC", &String::from_utf8(pt).unwrap()).unwrap();
        assert_eq!(item.kind, ItemKind::Ledger);
    }

    /// Minimal git repo for plumbing unit tests: one commit on `main` plus
    /// an `inbox` branch holding `files`. Returns the TempDir (must stay
    /// alive) and the repo root.
    fn plumbing_repo(files: &[(&str, &str)]) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let sh = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .expect("git failed to run");
            assert!(
                out.status.success(),
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            );
        };
        sh(&["init", "-b", "main", "-q"]);
        sh(&["config", "user.name", "Test"]);
        sh(&["config", "user.email", "test@example.com"]);
        std::fs::write(root.join("init.txt"), "init\n").unwrap();
        sh(&["add", "."]);
        sh(&["commit", "-q", "-m", "init"]);
        sh(&["checkout", "-q", "--orphan", "inbox"]);
        sh(&["rm", "-q", "-rf", "."]);
        for (name, text) in files {
            std::fs::write(root.join(name), text).unwrap();
        }
        sh(&["add", "."]);
        if files.is_empty() {
            sh(&["commit", "-q", "--allow-empty", "-m", "drop items"]);
        } else {
            sh(&["commit", "-q", "-m", "drop items"]);
        }
        sh(&["checkout", "-q", "main"]);
        let root = root.to_path_buf();
        (dir, root)
    }

    fn rev_parse(root: &Path, rev: &str) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", rev])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git rev-parse failed");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn tip_recheck_refuses_moved_tip() {
        // #29: the tip recorded after reading no longer matches — refuse
        // with E_INBOX_RACE instead of clearing content the run never saw.
        // The refusal happens before any signing or tree building, so no
        // signing config is needed here.
        let (_dir, root) = plumbing_repo(&[("01JAAA.age", "ciphertext")]);
        let tip = rev_parse(&root, "inbox");
        // Unchanged tip passes.
        verify_inbox_tip(&root, &tip).unwrap();
        // Simulate a mid-run push: a new commit on the inbox branch, built
        // with plumbing so the worktree is untouched.
        let tree = rev_parse(&root, "inbox^{tree}");
        let new_commit = {
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["commit-tree", &tree, "-p", &tip, "-m", "mid-run push"])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .expect("git commit-tree failed");
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["update-ref", "refs/heads/inbox", &new_commit, &tip])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git update-ref failed");
        assert!(out.status.success());
        // The recorded tip is now stale: both the recheck and clear_inbox
        // refuse, and the pushed content is untouched.
        let err = verify_inbox_tip(&root, &tip).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_RACE");
        let err = clear_inbox(&root, &tip, &["01JAAA".to_string()]).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_RACE");
        assert_eq!(rev_parse(&root, "inbox"), new_commit);
    }

    #[test]
    fn pinned_tip_anchors_all_reads() {
        // Pin-before-verify: every inbox read anchors at the pinned tip SHA,
        // never the branch name. A push that lands after the pin adds an
        // item the branch can see but the pinned reads must not.
        let (_dir, root) = plumbing_repo(&[("01JAAA.age", "ciphertext")]);
        let tip = rev_parse(&root, "inbox");
        // Push a new item on top of the pinned tip (plumbing; worktree
        // untouched).
        let blob = {
            let f = root.join("tmp-item.age");
            std::fs::write(&f, "ciphertext-evil").unwrap();
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["hash-object", "-w", f.to_string_lossy().as_ref()])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git hash-object failed");
            std::fs::remove_file(&f).unwrap();
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let tree = {
            let ls = git(&root, &["ls-tree", &tip]).unwrap();
            let mut text = String::from_utf8_lossy(&ls.stdout).into_owned();
            text.push_str(&format!("100644 blob {blob}\t01JBBB.age\n"));
            let mut child = Command::new("git")
                .arg("-C")
                .arg(&root)
                .arg("mktree")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("git mktree failed to spawn");
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            let out = child.wait_with_output().expect("git mktree failed");
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let new_commit = {
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["commit-tree", &tree, "-p", &tip, "-m", "evil push"])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .expect("git commit-tree failed");
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        git(
            &root,
            &["update-ref", "refs/heads/inbox", &new_commit, &tip],
        )
        .unwrap();
        assert_ne!(rev_parse(&root, "inbox"), tip);
        // The branch sees the pushed item; the pinned reads do not.
        assert_eq!(list_items(&root, &tip).unwrap(), vec!["01JAAA".to_string()]);
        assert!(git_bytes(&root, &format!("{tip}:01JBBB.age")).is_err());
        // The merge-count check also anchors at the tip: a merge pushed on
        // top must not affect verification of the pinned snapshot. (The
        // per-file walk still fails closed on the unsigned T0 commit, which
        // is the point — the pushed content is never examined.)
        let err = verify_inbox_signatures(&root, &tip, &["DEADBEEF".to_string()]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("01JAAA.age"),
            "verification must examine the pinned tip's items, got: {msg}"
        );
        assert!(
            !msg.contains("01JBBB"),
            "verification must not see the pushed item, got: {msg}"
        );
    }

    #[test]
    fn signing_check_accepts_gpgsign_or_signingkey() {
        let (_dir, root) = plumbing_repo(&[]);
        // Neither set: not configured.
        assert!(!commit_signing_configured(&root).unwrap());
        // user.signingkey alone counts (explicit -S signs).
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["config", "user.signingkey", "test-key"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git config failed");
        assert!(out.status.success());
        assert!(commit_signing_configured(&root).unwrap());
        // commit.gpgsign accepts every git boolean spelling, not just
        // "true" (--type=bool normalizes them).
        for value in ["true", "yes", "on", "1", "True", "TRUE"] {
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["config", "commit.gpgsign", value])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git config failed");
            assert!(out.status.success());
            assert!(
                commit_signing_configured(&root).unwrap(),
                "commit.gpgsign={value} should count"
            );
        }
        for value in ["false", "no", "off", "0"] {
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["config", "commit.gpgsign", value])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git config failed");
            assert!(out.status.success());
            // user.signingkey is still set from above, so this stays true;
            // unset it first to isolate the boolean.
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["config", "--unset", "user.signingkey"])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git config failed");
            assert!(out.status.success());
            assert!(
                !commit_signing_configured(&root).unwrap(),
                "commit.gpgsign={value} should not count"
            );
            // Restore for the next iteration.
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["config", "user.signingkey", "test-key"])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git config failed");
            assert!(out.status.success());
        }
    }
}
