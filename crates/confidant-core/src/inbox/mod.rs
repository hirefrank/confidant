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

use crate::check::{run as check_vault, CheckOptions, Severity};
use crate::error::DomainError;
use crate::vault::load_vault;

mod git;
mod item;
mod keys;
mod merge;
mod plan;
mod preflight;
mod rotate;
mod trust;

use git::clear_inbox;
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

/// Decrypts item ciphertext. Production passes a closure over [`InboxKeys`]
/// (the real `confidant-crypt` age path); tests inject a fake.
pub type DecryptFn = dyn Fn(&[u8]) -> anyhow::Result<Vec<u8>>;

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

    let existing_srcs = collect_vault_srcs(&vault);
    let mut ledger_cache: HashMap<PathBuf, String> = HashMap::new();
    let mut outcomes = Vec::new();
    let mut applied: Vec<AppliedChange> = Vec::new();
    for item in &items {
        match plan_item(vault_root, item, &existing_srcs, &mut ledger_cache)? {
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
            if let Err(e) = commit_applied(repo, &applied, &outcomes) {
                // All-or-nothing: the merge commit failed (e.g. a
                // configured-but-broken signing setup), so unstage the
                // applied paths and restore the worktree. The inbox is
                // untouched — the clear never ran.
                unstage_applied(repo, &applied);
                revert_applied(&applied);
                return Err(e);
            }
        }
        clear_inbox(repo, &tip, &names)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    use crate::inbox::git::{
        clear_inbox, commit_signing_configured, git, git_bytes, is_item_stem, list_items,
        verify_inbox_tip,
    };
    use crate::inbox::item::{parse_item, ItemKind, ParsedItem};
    use crate::inbox::merge::PlannedWrite;
    use crate::inbox::plan::{collect_vault_srcs, plan_item};
    use crate::inbox::rotate::commit_vault_config;
    use crate::inbox::trust::{
        check_inbox_pubkey, check_local_inbox_pubkey, verify_inbox_signatures,
    };

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
        g.set_previous(&test_bech32(&TEST_INBOX_SECRET_B));
        let keys = InboxKeys::load().unwrap();
        let ciphertext = confidant_crypt::age_wrap::wrap_to_recipient(
            b"item bytes",
            &test_recipient(&TEST_INBOX_SECRET_B),
        )
        .unwrap();
        let plaintext = keys.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"item bytes");
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
        plan_item(root, item, srcs, &mut HashMap::new())
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
    fn record_identical_is_idempotent() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("people/p-acme")).unwrap();
        std::fs::write(dir.path().join("people/p-acme/profile.md"), "# Acme").unwrap();
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
