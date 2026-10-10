//! End-to-end `confidant inbox` merge tests against throwaway git repos.
//!
//! The decryptor is an identity fake (plaintext "ciphertext"); real crypto
//! arrives with milestone 2 (PR B). All data is fake.

use std::path::Path;
use std::process::Command;

use confidant_core::{run_inbox, DecryptFn, DomainError, InboxOptions};
use tempfile::TempDir;

const PID: &str = "p-01M3TC5H00MPJG000000000000";

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
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
}

fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git failed to run");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Repo {
    dir: TempDir,
}

impl Repo {
    /// A git repo with a minimal check-clean vault on `main`.
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        git(root, &["init", "-b", "main", "-q"]);
        git(root, &["config", "user.name", "Test"]);
        git(root, &["config", "user.email", "test@example.com"]);
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"inbox-e2e-vault\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join(format!("people/{PID}"))).unwrap();
        std::fs::write(
            root.join(format!("people/{PID}/profile.md")),
            format!("---\nid: {PID}\ntype: person\nname: Test Person\n---\n\nFake.\n"),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
        std::fs::write(root.join("ledger/2026/10.cfd"), "; ledger/2026/10.cfd\n2026-10-01 open p-01M3TC5H00MPJG000000000000 package pkg-01M3TC5H00MPJG004SK4000009 6 sessions\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "init"]);
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Orphan `inbox` branch holding the given plaintext items. Idempotent:
    /// replaces any existing inbox branch.
    fn with_inbox(&self, files: &[(&str, &str)]) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(self.root())
            .args(["branch", "-D", "inbox"])
            .output();
        git(self.root(), &["checkout", "-q", "--orphan", "inbox"]);
        git(self.root(), &["rm", "-q", "-rf", "."]);
        for (name, text) in files {
            std::fs::write(self.root().join(name), text).unwrap();
        }
        git(self.root(), &["add", "."]);
        git(self.root(), &["commit", "-q", "-m", "drop items"]);
        git(self.root(), &["checkout", "-q", "main"]);
    }

    fn run(&self, dry_run: bool) -> anyhow::Result<confidant_core::InboxReport> {
        let identity: &DecryptFn = &|b: &[u8]| Ok(b.to_vec());
        run_inbox(
            self.root(),
            &InboxOptions {
                dry_run,
                trusted_signers: Vec::new(),
                // These tests exercise merge mechanics, not trust: the
                // explicit opt-in skips signature verification.
                allow_unsigned: true,
                pinned_pubkey: None,
            },
            identity,
        )
    }
}

const LEDGER_ITEM: &str = "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000000000 45m paid note:n-01M3TC5H00MPJG000000000001 src:e2e-1\n";
const RECORD_ITEM: &str = "confidant-inbox/1\nkind: record\npath: people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000001.md\n---\n---\nid: n-01M3TC5H00MPJG000000000001\ntype: note\n---\n\nFake note.\n";

#[test]
fn merge_commit_and_clear() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAA.age", LEDGER_ITEM), ("01JAAB.age", RECORD_ITEM)]);
    // #52: the merge and clear commits must be signed; without signing
    // configured the run refuses.
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    // #51: capture the HEAD reflog before the run — the inbox branch must
    // never be checked out in the worktree.
    let reflog_before = head_reflog_len(r.root());

    let report = r.run(false).expect("inbox run failed");
    assert!(!report.empty);
    assert_eq!(report.merged, 2);
    assert_eq!(report.cleared, 2);
    assert_eq!(report.branch, "main");

    // Ledger line landed in the right month file.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(ledger.contains("src:e2e-1"), "ledger:\n{ledger}");

    // Record landed at its path.
    let note = std::fs::read_to_string(
        r.root()
            .join("people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000001.md"),
    )
    .unwrap();
    assert!(note.contains("Fake note."), "note:\n{note}");

    // One commit on main, message carries only opaque IDs.
    let log = git_out(r.root(), &["log", "-1", "--format=%s%n%b", "main"]);
    assert!(log.starts_with("inbox: merge 2 item(s)"), "log:\n{log}");
    assert!(log.contains("01JAAA ledger"));
    assert!(!log.contains("intake"), "no PII in commit message");

    // #52: both the merge commit (main) and the clear commit (inbox) carry
    // good signatures.
    for rev in ["main", "inbox"] {
        let validity = git_out(r.root(), &["log", "-1", "--format=%G?", rev]);
        assert_eq!(validity, "G", "{rev} commit is not signed");
    }

    // Inbox branch is cleared (empty tree).
    let tree = git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.is_empty(), "inbox tree:\n{tree}");
    let clear_log = git_out(r.root(), &["log", "-1", "--format=%s", "inbox"]);
    assert!(clear_log.starts_with("inbox: clear 2 item(s)"));

    // Back on main.
    assert_eq!(
        git_out(r.root(), &["rev-parse", "--abbrev-ref", "HEAD"]),
        "main"
    );

    // #51: no checkout of the inbox branch happened during the run — the
    // new HEAD reflog entries contain no checkout.
    let new_entries = head_reflog_since(r.root(), reflog_before);
    assert!(
        !new_entries.iter().any(|m| m.contains("checkout")),
        "inbox branch was checked out during the run: {new_entries:?}"
    );
}

/// Number of HEAD reflog entries (for #51's no-checkout assertion).
fn head_reflog_len(root: &Path) -> usize {
    git_out(root, &["log", "-g", "--format=%gs", "HEAD"])
        .lines()
        .count()
}

/// HEAD reflog messages added since `before` entries existed (newest first).
fn head_reflog_since(root: &Path, before: usize) -> Vec<String> {
    let all: Vec<String> = git_out(root, &["log", "-g", "--format=%gs", "HEAD"])
        .lines()
        .map(str::to_string)
        .collect();
    let new_count = all.len().saturating_sub(before);
    all.into_iter().take(new_count).collect()
}

#[test]
fn reimporting_adds_nothing() {
    let r = Repo::new();
    let items = [("01JAAA.age", LEDGER_ITEM), ("01JAAB.age", RECORD_ITEM)];
    r.with_inbox(&items);
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let first = r.run(false).expect("first run failed");
    assert_eq!(first.merged, 2);

    // Drop the same items again: everything is already present.
    r.with_inbox(&items);
    let second = r.run(false).expect("second run failed");
    assert_eq!(second.merged, 0);
    assert_eq!(second.cleared, 2);
    assert!(second.items.iter().all(|i| i.action == "skip"));

    // Ledger file has the line exactly once.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert_eq!(ledger.matches("src:e2e-1").count(), 1);
}

#[test]
fn dry_run_changes_nothing() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAA.age", LEDGER_ITEM)]);
    let report = r.run(true).expect("dry run failed");
    assert!(report.dry_run);
    assert_eq!(report.merged, 1);
    assert_eq!(report.cleared, 0);

    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(!ledger.contains("src:e2e-1"));
    let tree = git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("01JAAA.age"));
}

#[test]
fn check_failure_reverts_everything() {
    let r = Repo::new();
    // Parses fine, but names a record that does not exist -> E_UNKNOWN_RECORD.
    let bad = "confidant-inbox/1\nkind: ledger\n---\n2026-10-08 session p-01M3TC5H00MPJG000000009999 45m src:e2e-bad\n";
    r.with_inbox(&[("01JAAA.age", bad), ("01JAAB.age", LEDGER_ITEM)]);
    // Signing must be configured to get past the pre-commit gate (#52) and
    // reach the check-failure path.
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };

    let err = r.run(false).expect_err("expected E_INBOX_CHECK_FAILED");
    assert_eq!(
        DomainError::of(&err).unwrap().code(),
        "E_INBOX_CHECK_FAILED"
    );

    // Nothing applied: ledger untouched, no new commits, inbox intact.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(!ledger.contains("src:e2e"));
    let log = git_out(r.root(), &["log", "-1", "--format=%s", "main"]);
    assert_eq!(log, "init");
    let tree = git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("01JAAA.age"));
    assert!(tree.contains("01JAAB.age"));
    assert_eq!(
        git_out(r.root(), &["rev-parse", "--abbrev-ref", "HEAD"]),
        "main"
    );
}

#[test]
fn symlinked_vault_root_merges() {
    // Regression: git reports the physical toplevel, so a symlinked vault
    // root must not trip the "escapes the repository" guard.
    let r = Repo::new();
    r.with_inbox(&[("01JAAA.age", LEDGER_ITEM), ("01JAAB.age", RECORD_ITEM)]);
    // The link must live outside the repo: an untracked file inside it
    // would (correctly) make the tree dirty.
    let elsewhere = TempDir::new().unwrap();
    let link = elsewhere.path().join("link-root");
    std::os::unix::fs::symlink(r.root(), &link).unwrap();
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let identity: &DecryptFn = &|b: &[u8]| Ok(b.to_vec());
    let report = run_inbox(
        &link,
        &InboxOptions {
            dry_run: false,
            trusted_signers: Vec::new(),
            allow_unsigned: true,
            pinned_pubkey: None,
        },
        identity,
    )
    .expect("inbox run via symlinked root failed");
    assert_eq!(report.merged, 2);
    assert_eq!(report.cleared, 2);
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(ledger.contains("src:e2e-1"));
}

#[test]
fn conflicting_record_is_all_or_nothing() {
    let r = Repo::new();
    std::fs::create_dir_all(r.root().join("people/p-01M3TC5H00MPJG000000000000/notes")).unwrap();
    std::fs::write(
        r.root()
            .join("people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000001.md"),
        "existing content",
    )
    .unwrap();
    git(r.root(), &["add", "."]);
    git(r.root(), &["commit", "-q", "-m", "existing note"]);

    r.with_inbox(&[("01JAAB.age", RECORD_ITEM)]);
    // Signing must be configured to get past the pre-commit gate (#52) and
    // reach the conflict path.
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let err = r.run(false).expect_err("expected E_INBOX_CONFLICT");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CONFLICT");

    // The pre-existing file is untouched and still committed.
    let note = std::fs::read_to_string(
        r.root()
            .join("people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000001.md"),
    )
    .unwrap();
    assert_eq!(note, "existing content");
}

fn run_with(
    r: &Repo,
    trusted_signers: Vec<String>,
    allow_unsigned: bool,
    pinned_pubkey: Option<String>,
) -> anyhow::Result<confidant_core::InboxReport> {
    let identity: &DecryptFn = &|b: &[u8]| Ok(b.to_vec());
    run_inbox(
        r.root(),
        &InboxOptions {
            dry_run: false,
            trusted_signers,
            allow_unsigned,
            pinned_pubkey,
        },
        identity,
    )
}

#[test]
fn refuses_without_signers_unless_allow_unsigned() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM), ("01JAAC.age", RECORD_ITEM)]);
    // No signers, no opt-in: fail closed.
    let err = run_with(&r, Vec::new(), false, None).expect_err("expected E_INBOX_UNTRUSTED");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    // Explicit opt-in proceeds (needs commit signing for the merge/clear).
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let report = run_with(&r, Vec::new(), true, None).expect("allow_unsigned should proceed");
    assert_eq!(report.merged, 2);
}

#[test]
fn refuses_when_commit_signing_not_configured() {
    // #52 (ADR-10): without commit signing configured the run refuses
    // before merging or clearing, rather than creating unsigned commits.
    // Repo::new sets no signing config.
    let r = Repo::new();
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM)]);
    let err = run_with(&r, Vec::new(), true, None).expect_err("expected E_INBOX_UNTRUSTED");
    let domain = DomainError::of(&err).unwrap();
    assert_eq!(domain.code(), "E_INBOX_UNTRUSTED");
    assert!(
        domain.message().contains("signing is not configured"),
        "unexpected message: {}",
        domain.message()
    );
    // Nothing was merged or cleared.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(!ledger.contains("src:e2e-1"));
    let tree = git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("01JAAB.age"));
    assert_eq!(
        git_out(r.root(), &["log", "-1", "--format=%s", "main"]),
        "init"
    );
}

#[test]
fn failed_merge_commit_leaves_tree_and_index_clean() {
    // #52 follow-up: signing is configured but unusable, so `git commit -S`
    // fails at commit time. The all-or-nothing contract requires the run to
    // unstage the applied paths and revert the worktree — not leave the
    // writes staged in the index.
    let r = Repo::new();
    // Both items: the ledger line references the note, so the merged vault
    // passes check and the run reaches the (failing) signed commit.
    r.with_inbox(&[("01JAAA.age", LEDGER_ITEM), ("01JAAB.age", RECORD_ITEM)]);
    git(r.root(), &["config", "gpg.format", "ssh"]);
    git(r.root(), &["config", "user.signingkey", "/nonexistent/key"]);
    let tip_before = git_out(r.root(), &["rev-parse", "inbox"]);
    let err = r
        .run(false)
        .expect_err("expected the signed commit to fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("commit") || msg.contains("sign"),
        "unexpected error: {msg}"
    );
    // Clean worktree AND clean index: nothing staged, nothing modified.
    assert!(
        git_out(r.root(), &["status", "--porcelain"]).is_empty(),
        "worktree or index dirty after failed commit"
    );
    // Nothing merged, nothing cleared: main and inbox untouched.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(!ledger.contains("src:e2e-1"));
    assert!(
        !r.root()
            .join(format!(
                "people/{PID}/notes/n-01M3TC5H00MPJG000000000001.md"
            ))
            .exists(),
        "record write was not reverted"
    );
    assert_eq!(
        git_out(r.root(), &["log", "-1", "--format=%s", "main"]),
        "init"
    );
    assert_eq!(git_out(r.root(), &["rev-parse", "inbox"]), tip_before);
}

#[test]
fn push_between_verify_and_read_refuses() {
    // #29: a push that lands between signature verification and the item
    // reads must not slip unsigned items past the trust check. The evil
    // decryptor moves the inbox tip on first use (simulating the push);
    // the tip pinned before verification no longer matches, so the run
    // refuses with E_INBOX_RACE before merging anything.
    let r = Repo::new();
    r.with_inbox(&[("01JAAA.age", LEDGER_ITEM)]);
    let root = r.root().to_path_buf();
    let moved = std::sync::Mutex::new(false);
    let evil: &DecryptFn = &move |b: &[u8]| {
        let mut guard = moved.lock().unwrap();
        if !*guard {
            *guard = true;
            let tip = git_out(&root, &["rev-parse", "inbox"]);
            let tree = git_out(&root, &["rev-parse", "inbox^{tree}"]);
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
                .expect("commit-tree failed");
            assert!(out.status.success());
            let new_commit = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let out = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["update-ref", "refs/heads/inbox", &new_commit, &tip])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("update-ref failed");
            assert!(out.status.success());
        }
        Ok(b.to_vec())
    };
    let err = run_inbox(
        r.root(),
        &InboxOptions {
            dry_run: false,
            trusted_signers: Vec::new(),
            allow_unsigned: true,
            pinned_pubkey: None,
        },
        evil,
    )
    .expect_err("expected E_INBOX_RACE");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_RACE");
    // Nothing was merged: the worktree is untouched.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(!ledger.contains("src:e2e-1"));
}

#[test]
fn push_after_pin_is_neither_verified_nor_read() {
    // Pin-before-verify: the tip SHA is resolved before signature
    // verification and used for every inbox read. An unsigned item pushed
    // on top of the pinned tip mid-run (smuggled in via the decryptor)
    // must be neither verified nor read; the recheck refuses with
    // E_INBOX_RACE and the clear never runs.
    let r = Repo::new();
    r.with_inbox(&[("01JAAA.age", LEDGER_ITEM)]);
    let Some((_keep, fingerprint)) = ssh_signing(&r) else {
        if std::env::var_os("CI").is_some() {
            panic!("ssh-keygen unavailable under CI: signing tests must not skip");
        }
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    // Sign the inbox tip so verification actually runs against it.
    git(r.root(), &["checkout", "-q", "inbox"]);
    git(r.root(), &["commit", "-q", "-S", "--amend", "--no-edit"]);
    git(r.root(), &["checkout", "-q", "main"]);
    let tip = git_out(r.root(), &["rev-parse", "inbox"]);

    let root = r.root().to_path_buf();
    let moved = std::sync::Mutex::new(false);
    let evil: &DecryptFn = &move |b: &[u8]| {
        let mut guard = moved.lock().unwrap();
        if !*guard {
            *guard = true;
            // Unsigned item on top of the pinned tip, mid-run.
            git(&root, &["checkout", "-q", "inbox"]);
            std::fs::write(
                root.join("01JBBB.age"),
                LEDGER_ITEM.replace("src:e2e-1", "src:evil-9"),
            )
            .unwrap();
            git(&root, &["add", "."]);
            git(&root, &["commit", "-q", "-m", "evil push"]);
            git(&root, &["checkout", "-q", "main"]);
        }
        Ok(b.to_vec())
    };
    let err = run_inbox(
        r.root(),
        &InboxOptions {
            dry_run: false,
            trusted_signers: vec![fingerprint],
            allow_unsigned: false,
            pinned_pubkey: None,
        },
        evil,
    )
    .expect_err("expected E_INBOX_RACE");
    // E_INBOX_RACE, not E_INBOX_UNTRUSTED: the unsigned item was never
    // subjected to verification — verification anchored at the pinned tip.
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_RACE");
    // Not read either: neither the pushed item's bytes nor the original
    // item made it into the worktree.
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(
        !ledger.contains("evil-9"),
        "pushed item was read despite the pin"
    );
    assert!(
        !ledger.contains("src:e2e-1"),
        "original item merged despite the race"
    );
    // The clear never ran: the pushed commit sits on the inbox branch,
    // untouched.
    assert_ne!(git_out(r.root(), &["rev-parse", "inbox"]), tip);
    assert!(git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]).contains("01JBBB.age"));
    // And the worktree is back on main, clean.
    assert_eq!(
        git_out(r.root(), &["rev-parse", "--abbrev-ref", "HEAD"]),
        "main"
    );
    assert!(git_out(r.root(), &["status", "--porcelain"]).is_empty());
}

#[test]
fn every_item_commit_is_signature_checked() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM)]);
    // A second, unsigned commit on top — the old tip-only check would look
    // only at this tip; the new check examines every commit that adds items.
    git(r.root(), &["checkout", "-q", "inbox"]);
    std::fs::write(r.root().join("01JAAC.age"), LEDGER_ITEM).unwrap();
    git(r.root(), &["add", "."]);
    git(r.root(), &["commit", "-q", "-m", "drop another item"]);
    git(r.root(), &["checkout", "-q", "main"]);
    let err = run_with(&r, vec!["DEADBEEF".to_string()], false, None)
        .expect_err("expected E_INBOX_UNTRUSTED");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    // The per-item message proves provenance was checked, not just the tip.
    let msg = format!("{err:#}");
    assert!(
        msg.contains("is not signed by a trusted signer"),
        "unexpected message: {msg}"
    );
}

#[test]
fn pubkey_mismatch_refuses() {
    let r = Repo::new();
    // Advertise one key in the vault, pin a different one out of band.
    let toml = std::fs::read_to_string(r.root().join("confidant.toml")).unwrap();
    std::fs::write(
        r.root().join("confidant.toml"),
        format!(
            "{toml}[inbox]\npubkey = \"age1vaultkey0000000000000000000000000000000000000000000\"\n"
        ),
    )
    .unwrap();
    git(r.root(), &["add", "."]);
    git(r.root(), &["commit", "-q", "-m", "advertise inbox key"]);
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM)]);
    let err = run_with(
        &r,
        Vec::new(),
        true,
        Some("age1operatorpin00000000000000000000000000000000000000000".to_string()),
    )
    .expect_err("expected E_INBOX_UNTRUSTED on key mismatch");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
}

#[test]
fn pubkey_pin_match_proceeds() {
    // No local inbox key: exercise the pin comparison in isolation from the
    // #55 local-key check (which skips without a key).
    let g = EnvGuard::lock();
    g.unset();
    let r = Repo::new();
    let key = "age1operatorpin00000000000000000000000000000000000000000";
    let toml = std::fs::read_to_string(r.root().join("confidant.toml")).unwrap();
    std::fs::write(
        r.root().join("confidant.toml"),
        format!("{toml}[inbox]\npubkey = \"{key}\"\n"),
    )
    .unwrap();
    git(r.root(), &["add", "."]);
    git(r.root(), &["commit", "-q", "-m", "advertise inbox key"]);
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM), ("01JAAC.age", RECORD_ITEM)]);
    let Some(_signing) = require_commit_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    let report =
        run_with(&r, Vec::new(), true, Some(key.to_string())).expect("matching pin should proceed");
    assert_eq!(report.merged, 2);
}

#[test]
fn forged_clear_commit_does_not_shield_unsigned_item() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM), ("01JAAC.age", RECORD_ITEM)]);
    // Attacker forges a clear-looking commit on top to truncate a
    // subject-based verification window. Per-file provenance must still
    // trace each tip item back to its (unsigned) add.
    git(r.root(), &["checkout", "-q", "inbox"]);
    git(
        r.root(),
        &[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "inbox: clear 99 item(s)",
        ],
    );
    git(r.root(), &["checkout", "-q", "main"]);
    let err = run_with(&r, vec!["DEADBEEF".to_string()], false, None)
        .expect_err("expected E_INBOX_UNTRUSTED despite forged clear");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
}

#[test]
fn merge_commit_on_inbox_refuses() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM)]);
    // Attacker merges a side branch that rewrites the item. Merge diffs are
    // invisible to `git log -- <file>`, so without the merge check the
    // provenance walk would see only the original (unsigned, pre-merge) add.
    git(r.root(), &["checkout", "-q", "inbox"]);
    git(r.root(), &["checkout", "-qb", "side"]);
    std::fs::write(r.root().join("01JAAB.age"), RECORD_ITEM).unwrap();
    git(r.root(), &["add", "."]);
    git(r.root(), &["commit", "-q", "-m", "tamper item"]);
    git(r.root(), &["checkout", "-q", "inbox"]);
    git(
        r.root(),
        &["merge", "-q", "--no-ff", "side", "-m", "merge side"],
    );
    git(r.root(), &["checkout", "-q", "main"]);
    assert_eq!(
        git_out(r.root(), &["rev-list", "--merges", "--count", "inbox"]),
        "1"
    );
    let err = run_with(&r, vec!["DEADBEEF".to_string()], false, None)
        .expect_err("expected E_INBOX_UNTRUSTED on merge commit");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    let msg = format!("{err:#}");
    assert!(msg.contains("merge"), "unexpected message: {msg}");
}

/// Configure SSH commit signing on the test repo so `run_inbox` can create
/// its signed merge and clear commits (#52, ADR-10). Returns the TempDir
/// that must stay alive for the test, or `None` (skip the test) when
/// ssh-keygen is unavailable.
fn require_commit_signing(r: &Repo) -> Option<TempDir> {
    ssh_signing(r).map(|(keep, _fingerprint)| keep)
}

/// Run ssh-keygen, or note its absence. A missing binary is `None` (the
/// caller skips the test) — unless CI is set, in which case it's a hard
/// failure so #52 coverage can't silently disappear (same family as #71).
fn ssh_keygen(args: &[&str]) -> Option<std::process::Output> {
    match Command::new("ssh-keygen").args(args).output() {
        Ok(out) => Some(out),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var_os("CI").is_some() {
                panic!("ssh-keygen is not installed and CI is set: signing tests must not skip");
            }
            None
        }
        Err(_) => None,
    }
}

/// Configure SSH commit signing on the test repo with a throwaway key.
/// Returns the key fingerprint (the `SHA256:…` id operators are told to
/// read via `git log --format=%GK`) plus the TempDir that owns the key
/// files (must stay alive while signing). Returns None when ssh-keygen is
/// unavailable — the caller skips the test (hard failure under CI, see
/// `ssh_keygen`).
fn ssh_signing(r: &Repo) -> Option<(TempDir, String)> {
    let keydir = TempDir::new().ok()?;
    let key = keydir.path().join("key");
    let key_s = key.to_str()?.to_string();
    let gen = ssh_keygen(&[
        "-t",
        "ed25519",
        "-N",
        "",
        "-q",
        "-C",
        "inbox-e2e",
        "-f",
        &key_s,
    ])?;
    if !gen.status.success() {
        return None;
    }
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).ok()?;
    // git verifies SSH signatures against allowedSignersFile, matched on the
    // committer principal (the harness commits as test@example.com).
    let allowed = keydir.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!("test@example.com namespaces=\"git\" {pubkey}"),
    )
    .ok()?;
    let key_s = key.to_str()?.to_string();
    let allowed_s = allowed.to_str()?.to_string();
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", key_s.as_str()),
        ("gpg.ssh.allowedSignersFile", allowed_s.as_str()),
    ] {
        git(r.root(), &["config", k, v]);
    }
    // The fingerprint is what `ssh-keygen -lf` (and `git log --format=%GK`)
    // report: `256 SHA256:… inbox-e2e (ED25519)`.
    let lf = ssh_keygen(&["-lf", key.with_extension("pub").to_str()?])?;
    let fingerprint = String::from_utf8_lossy(&lf.stdout)
        .split_whitespace()
        .nth(1)?
        .to_string();
    Some((keydir, fingerprint))
}

#[test]
fn signed_tip_with_unsigned_add_refuses() {
    let r = Repo::new();
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM)]);
    let Some((_keep, fingerprint)) = ssh_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    // Sign only the tip: a second item added by a trusted signer. The old
    // tip-only check would pass this; per-file provenance must still fail on
    // the unsigned add of 01JAAB.age.
    git(r.root(), &["checkout", "-q", "inbox"]);
    std::fs::write(r.root().join("01JAAC.age"), RECORD_ITEM).unwrap();
    git(r.root(), &["add", "."]);
    git(r.root(), &["commit", "-q", "-S", "-m", "drop another item"]);
    git(r.root(), &["checkout", "-q", "main"]);
    // The documented operator workflow: the id git reports (%GK) is the id
    // that goes in [trust] signers. Assert the formats agree.
    let reported = git_out(r.root(), &["log", "-1", "--format=%GK", "inbox"]);
    assert_eq!(
        reported, fingerprint,
        "%GK must match the documented signer id"
    );
    assert!(
        reported.starts_with("SHA256:"),
        "unexpected %GK: {reported}"
    );

    let err = run_with(&r, vec![fingerprint], false, None)
        .expect_err("expected E_INBOX_UNTRUSTED: item add is unsigned");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("is not signed by a trusted signer"),
        "unexpected message: {msg}"
    );
}

#[test]
fn all_signed_proceeds() {
    let r = Repo::new();
    // Both items: the ledger line references the note, so the merged vault
    // passes check (as in merge_commit_and_clear).
    r.with_inbox(&[("01JAAB.age", LEDGER_ITEM), ("01JAAC.age", RECORD_ITEM)]);
    let Some((_keep, fingerprint)) = ssh_signing(&r) else {
        eprintln!("SKIP: ssh-keygen unavailable");
        return;
    };
    // Sign the items' add commit itself (amend), so every commit in each
    // item's provenance carries a trusted signature.
    git(r.root(), &["checkout", "-q", "inbox"]);
    git(r.root(), &["commit", "-q", "-S", "--amend", "--no-edit"]);
    git(r.root(), &["checkout", "-q", "main"]);
    let reported = git_out(r.root(), &["log", "-1", "--format=%GK", "inbox"]);
    assert_eq!(reported, fingerprint);

    let report =
        run_with(&r, vec![fingerprint], false, None).expect("all-signed run should proceed");
    assert_eq!(report.merged, 2);
    assert_eq!(report.cleared, 2);
}

// ---------------------------------------------------------------------------
// Real-crypto round trips (#30) and the local-pubkey hard error (#55).
//
// These tests drive the production decryptor (`inbox_decrypt`) with a fixed
// test-only inbox identity loaded via the `CONFIDANT_INBOX_KEY` env override
// (headless-safe: no OS keychain needed). Every test uses the same identity
// so parallel tests never race on the env var's value; no test unsets it.
// ---------------------------------------------------------------------------

/// Test-only inbox identity ("the operator's key").
const TEST_INBOX_SECRET: [u8; 32] = [7u8; 32];
/// A different test-only identity ("someone else's key").
const OTHER_INBOX_SECRET: [u8; 32] = [9u8; 32];

/// Serializes `CONFIDANT_INBOX_KEY` mutation: `run_inbox` reads the local
/// inbox identity from the process environment, so tests that set a vault
/// `[inbox].pubkey` must not race with tests that set the env var.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard {
    saved: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn lock() -> Self {
        EnvGuard {
            saved: std::env::var("CONFIDANT_INBOX_KEY").ok(),
            _lock: ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
    fn set(&self, val: &str) {
        std::env::set_var("CONFIDANT_INBOX_KEY", val);
    }
    fn unset(&self) {
        std::env::remove_var("CONFIDANT_INBOX_KEY");
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.saved.take() {
            Some(v) => std::env::set_var("CONFIDANT_INBOX_KEY", v),
            None => std::env::remove_var("CONFIDANT_INBOX_KEY"),
        }
    }
}

fn test_recipient(secret: &[u8; 32]) -> String {
    confidant_crypt::age_wrap::RawX25519Identity::new(*secret).to_recipient_string()
}

fn test_bech32(secret: &[u8; 32]) -> String {
    confidant_crypt::age_wrap::RawX25519Identity::new(*secret).to_bech32()
}

/// Point this test process at the fixed test inbox identity. Holds the
/// env lock for the caller's scope so vault-pubkey tests can't interleave.
fn use_test_inbox_key() -> EnvGuard {
    let g = EnvGuard::lock();
    g.set(&test_bech32(&TEST_INBOX_SECRET));
    g
}

fn encrypt_item(plaintext: &str, recipient: &str) -> Vec<u8> {
    confidant_crypt::age_wrap::wrap_to_recipient(plaintext.as_bytes(), recipient).unwrap()
}

impl Repo {
    /// Orphan `inbox` branch holding age-encrypted items (real crypto).
    fn with_encrypted_inbox(&self, files: &[(&str, Vec<u8>)]) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(self.root())
            .args(["branch", "-D", "inbox"])
            .output();
        git(self.root(), &["checkout", "-q", "--orphan", "inbox"]);
        git(self.root(), &["rm", "-q", "-rf", "."]);
        for (name, bytes) in files {
            std::fs::write(self.root().join(name), bytes).unwrap();
        }
        git(self.root(), &["add", "."]);
        git(self.root(), &["commit", "-q", "-m", "drop items"]);
        git(self.root(), &["checkout", "-q", "main"]);
    }

    /// Advertise an `[inbox].pubkey` in the vault config (committed).
    fn with_vault_inbox_pubkey(&self, pubkey: &str) {
        let path = self.root().join("confidant.toml");
        let mut toml = std::fs::read_to_string(&path).unwrap();
        toml.push_str(&format!("\n[inbox]\npubkey = \"{pubkey}\"\n"));
        std::fs::write(&path, toml).unwrap();
        git(self.root(), &["add", "confidant.toml"]);
        git(
            self.root(),
            &["commit", "-q", "-m", "advertise inbox pubkey"],
        );
    }
}

/// Run the inbox with the production decryptor.
fn run_real(r: &Repo) -> anyhow::Result<confidant_core::InboxReport> {
    run_inbox(
        r.root(),
        &InboxOptions {
            dry_run: false,
            trusted_signers: Vec::new(),
            allow_unsigned: true,
            pinned_pubkey: None,
        },
        &confidant_core::inbox_decrypt,
    )
}

#[test]
fn real_crypto_round_trip_merges() {
    // #30: encrypt fixture items to the vault pubkey with real age crypto,
    // merge them through the production decryptor.
    let _g = use_test_inbox_key();
    let r = Repo::new();
    let recipient = test_recipient(&TEST_INBOX_SECRET);
    r.with_vault_inbox_pubkey(&recipient);
    r.with_encrypted_inbox(&[
        ("01JAAA.age", encrypt_item(LEDGER_ITEM, &recipient)),
        ("01JAAB.age", encrypt_item(RECORD_ITEM, &recipient)),
    ]);

    let report = run_real(&r).expect("real-crypto inbox run failed");
    assert_eq!(report.merged, 2);
    assert_eq!(report.cleared, 2);

    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(ledger.contains("src:e2e-1"), "ledger:\n{ledger}");
}

#[test]
fn local_pubkey_mismatch_is_hard_error() {
    // #55: the vault advertises someone else's key while the local private
    // key is ours — refuse before decrypting anything.
    let _g = use_test_inbox_key();
    let r = Repo::new();
    r.with_vault_inbox_pubkey(&test_recipient(&OTHER_INBOX_SECRET));
    r.with_encrypted_inbox(&[(
        "01JAAA.age",
        encrypt_item(LEDGER_ITEM, &test_recipient(&TEST_INBOX_SECRET)),
    )]);

    let err = run_real(&r).expect_err("expected E_INBOX_UNTRUSTED");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_UNTRUSTED");

    // Nothing touched: the item stays on the inbox branch.
    let tree = git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("01JAAA.age"), "inbox tree:\n{tree}");
}

#[test]
fn local_pubkey_match_allows_decrypt() {
    // #55, positive case: vault pubkey matches the local key; the run
    // proceeds to real decryption.
    let _g = use_test_inbox_key();
    let r = Repo::new();
    let recipient = test_recipient(&TEST_INBOX_SECRET);
    r.with_vault_inbox_pubkey(&recipient);
    r.with_encrypted_inbox(&[
        ("01JAAA.age", encrypt_item(LEDGER_ITEM, &recipient)),
        ("01JAAB.age", encrypt_item(RECORD_ITEM, &recipient)),
    ]);

    let report = run_real(&r).expect("matching-pubkey run failed");
    assert_eq!(report.merged, 2);
}

#[test]
fn wrong_key_fails_closed() {
    // Items encrypted to someone else's key while the vault correctly
    // advertises ours (#55 passes): decryption fails closed with
    // E_INBOX_CRYPTO and nothing is merged or cleared.
    let _g = use_test_inbox_key();
    let r = Repo::new();
    r.with_vault_inbox_pubkey(&test_recipient(&TEST_INBOX_SECRET));
    r.with_encrypted_inbox(&[(
        "01JAAA.age",
        encrypt_item(LEDGER_ITEM, &test_recipient(&OTHER_INBOX_SECRET)),
    )]);

    let err = run_real(&r).expect_err("expected E_INBOX_CRYPTO");
    assert_eq!(DomainError::of(&err).unwrap().code(), "E_INBOX_CRYPTO");

    let tree = git_out(r.root(), &["ls-tree", "-r", "--name-only", "inbox"]);
    assert!(tree.contains("01JAAA.age"), "inbox tree:\n{tree}");
    let ledger = std::fs::read_to_string(r.root().join("ledger/2026/10.cfd")).unwrap();
    assert!(!ledger.contains("src:e2e-1"));
}
