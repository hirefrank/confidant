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

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::check::{run as check_vault, CheckOptions, Severity};
use crate::error::DomainError;
use crate::vault::load_vault;

mod git;
mod item;
mod keys;
mod merge;
mod plan;
mod preflight;
mod queue;
mod rotate;
mod trust;

pub use queue::{queue_items, QueueItem};

use git::{clear_inbox, discard_inbox};
use item::describe_target;
use merge::{apply_writes, commit_applied, revert_applied, unstage_applied, AppliedChange};
use plan::{collect_vault_srcs, plan_item};
use preflight::{preflight, PreflightOutcome};

#[cfg(test)]
pub use keys::inbox_decrypt;
pub use keys::InboxKeys;
pub use rotate::{run_inbox_rotate, InboxRotateOptions, InboxRotateOutcome};

/// The git branch outside tools push intake items to.
pub const INBOX_BRANCH: &str = "inbox";

/// Warning the drain emits when `--allow-unsigned` skips the inbox
/// signature gate. `record resolve --from-inbox` write actions print the
/// same line to stderr (#457 review).
pub const ALLOW_UNSIGNED_WARNING: &str =
    "proceeding without inbox signature verification (--allow-unsigned)";

/// Decrypts item ciphertext. Production passes a closure over [`InboxKeys`]
/// (the real `confidant-crypt` age path); tests inject a fake.
pub type DecryptFn = dyn Fn(&[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>>;

/// Encrypts one record file's plaintext into the bytes to write — a §14
/// envelope on structurally encrypted vaults. The drain passes a closure
/// over the CLI's `RecordEncryptor`; tests inject a fake. `None` keeps the
/// B11 fail-closed refusal for `RecordWrite` items into encrypted vaults.
pub type EncryptFn = dyn Fn(&Path, &[u8]) -> anyhow::Result<Vec<u8>>;

/// Decrypts an existing record envelope back to plaintext, for the retry
/// idempotency check (#213 follow-up). The drain passes a closure over the
/// CLI's `RecordEncryptor` (same lazy construction as `encrypt`); tests
/// inject a fake. `None` keeps the fail-closed behaviour: an existing
/// envelope never equals the plaintext item content, so a retry after a
/// failed clear still conflicts instead of silently skipping. The return
/// is `Zeroizing` because it is decrypted client content — compare it,
/// never log it.
pub type DecryptExistingFn = dyn Fn(&Path, &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>>;

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
    /// Item stems (opaque, without `.age`) to defer: everything except
    /// these is merged, and skipped items stay on the `inbox` branch for
    /// a later run. Repeatable `--skip` on the CLI. Unknown names fail
    /// closed; `--skip` is refused during a rotate drain.
    pub skip: Vec<String>,
    /// Set by `drain_for_rotate`: this run is a rotate drain, so `--skip`
    /// is refused — leftovers encrypted to the old key must not survive
    /// `--finish` (§8a.3). Not settable from the CLI.
    pub is_rotate_drain: bool,
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

/// An item the operator deferred with `--skip`: not merged, not cleared,
/// left on the `inbox` branch for a later run. Kept separate from
/// [`ItemOutcome`] on purpose — `action: "skip"` already means "already
/// present / idempotent no-op" and must not be overloaded (#318).
#[derive(Clone, Debug)]
pub struct SkippedItem {
    /// Item file stem (opaque; no PII).
    pub name: String,
    /// `"ledger"` or `"record"`.
    pub kind: String,
    /// Vault-relative merge target.
    pub target: String,
}

/// Result of [`run_inbox`].
#[derive(Clone, Debug)]
pub struct InboxReport {
    /// Mainline branch the items were merged into.
    pub branch: String,
    pub items: Vec<ItemOutcome>,
    /// Operator-deferred items (`--skip`): still on the `inbox` branch.
    pub skipped: Vec<SkippedItem>,
    pub merged: usize,
    pub cleared: usize,
    pub dry_run: bool,
    pub warnings: Vec<String>,
    /// True when there is no inbox branch: nothing to do.
    pub empty: bool,
}

/// Whether the queue's commit-signing gate passes for this vault: the
/// queue refuses (`E_INBOX_UNTRUSTED`) without signing configured. The CLI
/// `--dry-run` fallback path checks this so a dry run reports the refusal
/// the real run would hit instead of a `would queue` that can never happen.
pub fn queue_signing_configured(vault_root: &Path) -> anyhow::Result<bool> {
    let repo = git::toplevel(vault_root)?;
    git::commit_signing_configured(&repo)
}

/// Discard inbox items without merging them (#457, `inbox --discard`).
///
/// Removes the named stems from the `inbox` branch in exactly one signed
/// commit (`inbox: discard N item(s)`), using the same plumbing as the
/// clear step: `mktree` / `commit-tree` / `update-ref` as an atomic
/// compare-and-swap on the pinned tip. The inbox branch is never checked
/// out and the main worktree is never touched.
///
/// Fails closed: an empty stem list is a usage error; a malformed stem or
/// a stem not on the current tip is `E_INBOX_SKIP` (like `--skip`); a tip
/// that moved between the read and the swap is `E_INBOX_RACE`; missing
/// commit-signing config is `E_INBOX_UNTRUSTED` (same rule as the clear
/// step — an unsigned discard commit would never pass the drain's trust
/// check). Returns the new inbox tip SHA.
pub fn discard_inbox_items(vault_root: &Path, stems: &[String]) -> anyhow::Result<String> {
    if stems.is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "inbox --discard needs at least one item stem",
        )));
    }
    for s in stems {
        if !git::is_item_stem(s) {
            return Err(anyhow::Error::new(DomainError::inbox_skip(s)));
        }
    }
    let repo = git::toplevel(vault_root)?;
    if !git::branch_exists(&repo, INBOX_BRANCH)? {
        return Err(anyhow::Error::new(DomainError::inbox_skip(&stems[0])));
    }
    let tip = git::git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    let names = git::list_items(&repo, &tip)?;
    for s in stems {
        if !names.contains(s) {
            return Err(anyhow::Error::new(DomainError::inbox_skip(s)));
        }
    }
    if !git::commit_signing_configured(&repo)? {
        return Err(anyhow::Error::new(DomainError::inbox_signing_unconfigured()));
    }
    discard_inbox(&repo, &tip, stems)?;
    git::git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])
}

/// A decrypted inbox item read for `record resolve --from-inbox` (#457).
#[derive(Clone, Debug)]
pub struct InboxItemContent {
    /// Item file stem (opaque; no PII).
    pub stem: String,
    /// `"ledger"` or `"record"`.
    pub kind: String,
    /// Vault-relative target path (records only).
    pub path: Option<PathBuf>,
    /// Decrypted plaintext content.
    pub content: String,
    /// The inbox branch tip the item was read at (#457 review). Pass this
    /// to [`verify_inbox_trust`] so the commit whose signatures are
    /// verified is the exact commit the bytes came from.
    pub tip: String,
}

/// Read one inbox item by stem for `record resolve --from-inbox` (#457).
///
/// Reads `<stem>.age` from the current inbox branch tip, decrypts it with
/// `decrypt` (the same inbox key path the drain uses), and parses it.
/// Fails closed when the stem is malformed or not on the tip
/// (`E_INBOX_SKIP`), when decryption fails, or when parsing fails.
///
/// Signatures are not verified here. The caller decides: `--show` reads
/// the item without a trust check (nothing is written), while the write
/// actions call [`verify_inbox_trust`] with the `tip` this function
/// returns, so the verified commit is the one the bytes came from.
pub fn read_inbox_item(
    vault_root: &Path,
    stem: &str,
    decrypt: &DecryptFn,
) -> anyhow::Result<InboxItemContent> {
    if !git::is_item_stem(stem) {
        return Err(anyhow::Error::new(DomainError::inbox_skip(stem)));
    }
    let repo = git::toplevel(vault_root)?;
    if !git::branch_exists(&repo, INBOX_BRANCH)? {
        return Err(anyhow::Error::new(DomainError::inbox_skip(stem)));
    }
    let tip = git::git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    let names = git::list_items(&repo, &tip)?;
    if !names.iter().any(|n| n == stem) {
        return Err(anyhow::Error::new(DomainError::inbox_skip(stem)));
    }
    let bytes = git::git_bytes(&repo, &format!("{tip}:{stem}.age"))?;
    let plaintext = decrypt(bytes.as_slice()).map_err(|e| match DomainError::of(&e) {
        Some(d) => anyhow::Error::new(d.clone()),
        None => anyhow::Error::new(DomainError::inbox_item(format!(
            "item '{stem}' could not be decrypted"
        ))),
    })?;
    let text = std::str::from_utf8(&plaintext).map_err(|_| {
        anyhow::Error::new(DomainError::inbox_item(format!(
            "item '{stem}' decrypted to non-UTF-8"
        )))
    })?;
    let parsed = item::parse_item(stem, text)?;
    Ok(InboxItemContent {
        stem: stem.to_string(),
        kind: parsed.kind.as_str().to_string(),
        path: parsed.path,
        content: parsed.content,
        tip,
    })
}

/// Verify the inbox branch tip's signature provenance — the same trust
/// check the drain runs before merging (#457).
///
/// `expected_tip` is the tip the caller read the item at (see
/// [`InboxItemContent::tip`]). The branch must still point there, or the
/// check refuses with `E_INBOX_RACE`: the drain pins the tip once and
/// re-checks it before acting, and this path must not verify one commit
/// while writing another's bytes.
///
/// Refuses with `E_INBOX_UNTRUSTED` when no trusted signers are configured
/// and `allow_unsigned` is false; otherwise verifies that every item at
/// the pinned tip was introduced by a trusted signer. Used by
/// `record resolve --from-inbox` write actions (`--take`, `--merged-file`,
/// `--edit`); `--show` stays read-only without the check.
pub fn verify_inbox_trust(
    vault_root: &Path,
    trusted_signers: &[String],
    allow_unsigned: bool,
    expected_tip: &str,
) -> anyhow::Result<()> {
    if trusted_signers.is_empty() && !allow_unsigned {
        return Err(anyhow::Error::new(DomainError::inbox_untrusted(
            "no [trust] signers configured; refusing to resolve from the inbox branch \
             (configure signers in ~/.config/confidant/config.toml or pass --allow-unsigned)",
        )));
    }
    let repo = git::toplevel(vault_root)?;
    let current = git::git_line(&repo, &["rev-parse", &format!("refs/heads/{INBOX_BRANCH}")])?;
    if current != expected_tip {
        return Err(anyhow::Error::new(DomainError::inbox_race(
            expected_tip,
            &current,
        )));
    }
    trust::verify_inbox_signatures(&repo, expected_tip, trusted_signers)?;
    Ok(())
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
///
/// `encrypt` supplies the record encryptor for `RecordWrite` items into
/// structurally encrypted vaults (B11, #213). Pass `None` to keep the
/// fail-closed refusal; the rotate drain passes `None` (rotate is a
/// keychain operation and cannot build the CLI's `RecordEncryptor` —
/// drain record items with plain `confidant inbox` before rotating).
///
/// `decrypt_existing` supplies the record decryptor for the retry
/// idempotency check: on a structurally encrypted vault, when a record
/// path already exists, the existing envelope is decrypted and its
/// plaintext compared to the item content (equal means already merged —
/// skip; different or undecryptable means `E_INBOX_CONFLICT`). Pass `None`
/// to keep the fail-closed behaviour (an existing envelope never equals
/// plaintext); the rotate drain passes `None` alongside `encrypt`.
pub fn run_inbox(
    vault_root: &Path,
    opts: &InboxOptions,
    decrypt: &DecryptFn,
    inbox_keys: Option<&InboxKeys>,
    encrypt: Option<&EncryptFn>,
    decrypt_existing: Option<&DecryptExistingFn>,
) -> anyhow::Result<InboxReport> {
    let ready = match preflight(vault_root, opts, decrypt, inbox_keys)? {
        PreflightOutcome::Report(report) => return Ok(report),
        PreflightOutcome::Ready(p) => *p,
    };
    let vault_root = ready.vault_root.as_path();
    let repo = &ready.repo;
    let branch = ready.branch;
    let vault = ready.vault;
    let warnings = ready.warnings;
    let tip = ready.tip;
    let names = ready.names;
    let items = ready.items;

    // #318: `--skip` is refused during a rotate drain — leftovers
    // encrypted to the old key must not survive `--finish` (§8a.3).
    if opts.is_rotate_drain && !opts.skip.is_empty() {
        return Err(anyhow::Error::new(DomainError::invalid(
            "--skip is refused during an inbox rotate drain: finish or drop old-key items before rotating",
        )));
    }
    // #318: fail closed on unknown `--skip` names — a typo must not
    // silently merge the item the operator meant to defer.
    for s in &opts.skip {
        if !names.contains(s) {
            return Err(anyhow::Error::new(DomainError::inbox_skip(s)));
        }
    }
    let skip_set: std::collections::HashSet<&str> = opts.skip.iter().map(String::as_str).collect();

    let existing_srcs = collect_vault_srcs(&vault);
    let mut ledger_cache: HashMap<PathBuf, String> = HashMap::new();
    let mut outcomes = Vec::new();
    let mut skipped = Vec::new();
    let mut applied: Vec<AppliedChange> = Vec::new();
    // A mid-loop failure must not leave the tree dirty: plan and apply
    // inside a closure so any error reverts what was applied so far.
    // Without this, a mid-run `E_INBOX_CONFLICT` — or a newly failing
    // encryptor — stranded already-applied ledger appends and the next run
    // stopped at `E_INBOX_DIRTY`. (The `check`-failure and commit-failure
    // paths below already revert.)
    let planned: anyhow::Result<()> = (|| {
        for item in &items {
            // #318: operator-deferred items are described for the report
            // but never planned or applied. Preflight already decrypted
            // and parsed every item, so kind/target are known.
            if skip_set.contains(item.name.as_str()) {
                skipped.push(SkippedItem {
                    name: item.name.clone(),
                    kind: item.kind.as_str().to_string(),
                    target: describe_target(item),
                });
                continue;
            }
            match plan_item(
                vault_root,
                item,
                &existing_srcs,
                &mut ledger_cache,
                decrypt_existing,
            )? {
                Some((outcome, writes)) => {
                    if !opts.dry_run {
                        apply_writes(vault_root, &writes, &mut applied, encrypt)?;
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
        Ok(())
    })();
    if let Err(e) = planned {
        revert_applied(&applied);
        return Err(e);
    }

    let mut cleared = 0usize;
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
            if let Err(e) = commit_applied(repo, &applied, &outcomes, &skipped) {
                // All-or-nothing: the merge commit failed (e.g. a
                // configured-but-broken signing setup), so unstage the
                // applied paths and restore the worktree. The inbox is
                // untouched — the clear never ran.
                unstage_applied(repo, &applied);
                revert_applied(&applied);
                return Err(e);
            }
        }
        // #318: partial clear — only processed stems are cleared; operator-
        // skipped `.age` files stay on the tip for the next run. (Idempotent
        // "already present" items keep today's behavior: they are cleared.)
        let cleared_names: Vec<String> = outcomes.iter().map(|o| o.name.clone()).collect();
        clear_inbox(repo, &tip, &cleared_names)?;
        cleared = cleared_names.len();
    }

    let merged = outcomes.iter().filter(|o| o.action == "merge").count();
    Ok(InboxReport {
        branch,
        merged,
        cleared,
        items: outcomes,
        skipped,
        dry_run: opts.dry_run,
        warnings,
        empty: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    use crate::inbox::git::{
        clear_inbox, commit_signing_configured, discard_inbox, git, git_bytes, is_item_stem,
        list_items, verify_inbox_tip,
    };
    use crate::inbox::item::{parse_item, ItemKind, ParsedItem};
    use crate::inbox::merge::PlannedWrite;
    use crate::inbox::plan::{collect_vault_srcs, plan_item};
    use crate::inbox::rotate::commit_vault_config;
    use crate::inbox::trust::{
        check_inbox_pubkey, check_local_inbox_pubkey, verify_inbox_signatures,
    };

    /// #559: inbox intake is the third agent path (with MCP and skills). An
    /// inbox item is data for the in-process write pipeline — ledger lines
    /// or a record file — never a CLI invocation, so it cannot carry the
    /// operator-only `--for-operator` flag. Pin both directions from the
    /// drain path's own sources: nothing names the roster or the flag, and
    /// every process the path starts is `git`, never the `confidant` CLI.
    #[test]
    fn inbox_sources_never_route_to_the_operator_roster() {
        const INBOX_SOURCES: &[(&str, &str)] = &[
            ("inbox/mod.rs", include_str!("mod.rs")),
            ("inbox/item.rs", include_str!("item.rs")),
            ("inbox/plan.rs", include_str!("plan.rs")),
            ("inbox/merge.rs", include_str!("merge.rs")),
            ("inbox/queue.rs", include_str!("queue.rs")),
            ("inbox/rotate.rs", include_str!("rotate.rs")),
            ("inbox/trust.rs", include_str!("trust.rs")),
            ("inbox/git.rs", include_str!("git.rs")),
            ("inbox/preflight.rs", include_str!("preflight.rs")),
            ("inbox/keys.rs", include_str!("keys.rs")),
        ];
        for (name, source) in INBOX_SOURCES {
            // Test modules build fixtures with git; scan production only.
            let production = source.split("#[cfg(test)]\nmod ").next().unwrap_or(source);
            for needle in [
                "record list",
                "--for-operator",
                "for_operator",
                "build_roster",
            ] {
                assert!(
                    !production.contains(needle),
                    "{name} mentions {needle:?}; inbox intake must not reach \
                     the operator-only roster (#559)"
                );
            }
            for (idx, _) in production.match_indices("Command::new(") {
                let after = &production[idx + "Command::new(".len()..];
                assert!(
                    after.starts_with("\"git\""),
                    "{name} starts a non-git process: {}",
                    after.lines().next().unwrap_or("")
                );
            }
        }
    }

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
            let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            EnvGuard {
                saved: std::env::var("CONFIDANT_INBOX_KEY").ok(),
                saved_previous: std::env::var("CONFIDANT_INBOX_KEY_PREVIOUS").ok(),
                saved_keychain: std::env::var("CONFIDANT_KEYCHAIN").ok(),
                _lock,
            }
        }
        fn set(&self, val: &str) {
            std::env::set_var("CONFIDANT_INBOX_KEY", val);
        }
        fn set_previous(&self, val: &str) {
            std::env::set_var("CONFIDANT_INBOX_KEY_PREVIOUS", val);
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

    /// PD10 (#445): pack install state is operator-only. An inbox item may
    /// never write under `packs/`, nor to `confidant.lock` or
    /// `confidant.toml` — otherwise an outside device could rewrite the
    /// operator's pack pins or vendored text. Record paths are validated at
    /// parse time, so the item is rejected before the drain planner ever
    /// sees it.
    #[test]
    fn inbox_rejects_record_items_targeting_packs_dir_and_lockfile() {
        for raw in [
            "packs/example-pack@0.1/SKILL.md",
            "packs/example-pack@0.1/manifest.toml",
            "confidant.lock",
            "confidant.toml",
        ] {
            let text = format!("confidant-inbox/1\nkind: record\npath: {raw}\n---\nfoo\n");
            let err = parse_item("x", &text).unwrap_err();
            let domain = DomainError::of(&err).unwrap();
            assert_eq!(domain.code(), "E_INBOX_ITEM", "raw={raw}");
            assert!(
                domain.message().contains("record path must live under"),
                "raw={raw}: {}",
                domain.message()
            );
        }
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
        assert_eq!(&*back, b"item bytes");
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
        g.set_previous(&test_bech32(&TEST_INBOX_SECRET_B));
        let keys = InboxKeys::load().unwrap();
        let ciphertext = confidant_crypt::age_wrap::wrap_to_recipient(
            b"item bytes",
            &test_recipient(&TEST_INBOX_SECRET_B),
        )
        .unwrap();
        let plaintext = keys.decrypt(&ciphertext).unwrap();
        assert_eq!(&*plaintext, b"item bytes");
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

    fn plan_test(
        root: &Path,
        item: &ParsedItem,
        srcs: &BTreeSet<String>,
    ) -> anyhow::Result<Option<(ItemOutcome, Vec<PlannedWrite>)>> {
        plan_item(root, item, srcs, &mut HashMap::new(), None)
    }

    #[test]
    fn plans_ledger_append_grouped_by_month() {
        let dir = TempDir::new().unwrap();
        let item = parse_item(
            "01JABC",
            "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 src:a\n2026-11-02 email p-01M3TC5H00MPJG000000000000 src:b\n",
        )
        .unwrap();
        let (outcome, writes) = plan_test(dir.path(), &item, &BTreeSet::new())
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
        assert!(plan_test(dir.path(), &item, &srcs).unwrap().is_none());
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
        let err = plan_test(dir.path(), &item, &BTreeSet::new()).unwrap_err();
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
        assert!(plan_test(dir.path(), &item, &BTreeSet::new())
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
            let err = plan_test(dir.path(), &item, &BTreeSet::new()).unwrap_err();
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
        let err = plan_test(dir.path(), &item, &BTreeSet::new()).unwrap_err();
        assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CONFLICT");
    }

    #[test]
    fn record_item_body_keeps_its_trailing_newline() {
        // The body is the record plaintext as queued. Dropping the final
        // newline would make the drain write a non-canonical record and
        // would stop `record resolve --take theirs` (which reformats) from
        // matching the drain's encrypt-and-compare idempotency check.
        let item = parse_item("01JABC", RECORD_ITEM).unwrap();
        assert_eq!(item.content, "# Acme\n");

        // A body with no trailing newline is passed through unchanged.
        let item = parse_item(
            "01JABC",
            "confidant-inbox/1\nkind: record\npath: people/p-acme/profile.md\n---\n# Acme",
        )
        .unwrap();
        assert_eq!(item.content, "# Acme");

        // Extra trailing newlines survive.
        let item = parse_item(
            "01JABC",
            "confidant-inbox/1\nkind: record\npath: people/p-acme/profile.md\n---\n# Acme\n\n",
        )
        .unwrap();
        assert_eq!(item.content, "# Acme\n\n");
    }

    #[test]
    fn record_identical_is_idempotent() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("people/p-acme")).unwrap();
        // `RECORD_ITEM`'s body keeps its trailing newline, so the identical
        // record on disk is the canonical form (which ends with one).
        std::fs::write(dir.path().join("people/p-acme/profile.md"), "# Acme\n").unwrap();
        let item = parse_item("01JABC", RECORD_ITEM).unwrap();
        assert!(plan_test(dir.path(), &item, &BTreeSet::new())
            .unwrap()
            .is_none());
    }

    #[test]
    fn collect_srcs_from_ledger_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "test"
[checks]
as_of = "2026-10-08"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("ledger/2026")).unwrap();
        std::fs::write(
            dir.path().join("ledger/2026/10.cfd"),
            "2026-10-08 session p-01M3TC5H00MPJG000000000000 src:tt-1\n; comment\n2026-10-09 email p-01M3TC5H00MPJG000000000000 src:tt-2\n",
        )
        .unwrap();
        let vault = load_vault(dir.path()).unwrap();
        let srcs = collect_vault_srcs(&vault);
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

    /// #457: `discard_inbox` with a stale expected tip refuses with
    /// `E_INBOX_RACE` (the compare-and-swap half of the plumbing).
    #[test]
    fn discard_with_stale_tip_refuses_race() {
        let (_dir, root) = plumbing_repo(&[("01JAAA.age", "item-a"), ("01JAAB.age", "item-b")]);
        let stale_tip = rev_parse(&root, "inbox");
        // Simulate a concurrent push: move the tip.
        let tree = rev_parse(&root, "inbox^{tree}");
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["commit-tree", &tree, "-p", &stale_tip, "-m", "concurrent"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("commit-tree failed");
        assert!(out.status.success());
        let new_tip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["update-ref", "refs/heads/inbox", &new_tip, &stale_tip])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("update-ref failed");
        assert!(out.status.success());

        let err = discard_inbox(&root, &stale_tip, &["01JAAA".to_string()])
            .expect_err("stale tip must refuse");
        let domain = DomainError::of(&err).expect("expected a DomainError");
        assert_eq!(domain.code(), "E_INBOX_RACE");
        // Nothing was removed.
        let tree = rev_parse(&root, "inbox^{tree}");
        assert_eq!(tree, rev_parse(&root, &format!("{new_tip}^{{tree}}")));
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
    /// Must-fix 2 (#104 review): the rotation commit carries only
    /// `confidant.toml` — a file the operator had staged beforehand must
    /// not be swept into it. Tested here (not via `run_inbox_rotate`)
    /// because the drain refuses on a non-clean tree.
    #[test]
    fn rotation_commit_keeps_staged_files_out() {
        let (_dir, root) = plumbing_repo(&[]);
        let config = root.join("confidant.toml");
        std::fs::write(&config, "spec = \"0.1\"\n").unwrap();

        // The operator stages an unrelated file.
        std::fs::write(root.join("draft.md"), "Unrelated draft.\n").unwrap();
        let sh = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git failed to run");
            assert!(out.status.success(), "git {args:?} failed");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        sh(&["add", "--", "draft.md"]);

        commit_vault_config(&root, &config, "age1testrecipient").unwrap();

        let files = sh(&["show", "--name-only", "--format=", "HEAD"]);
        assert_eq!(
            files, "confidant.toml",
            "rotation commit swept staged files: {files}"
        );
        // The staged file is still staged, untouched.
        let staged = sh(&["diff", "--cached", "--name-only"]);
        assert_eq!(staged, "draft.md", "staged file lost: {staged}");
    }
}
