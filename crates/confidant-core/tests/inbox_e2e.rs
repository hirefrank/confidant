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
}

#[test]
fn reimporting_adds_nothing() {
    let r = Repo::new();
    let items = [("01JAAA.age", LEDGER_ITEM), ("01JAAB.age", RECORD_ITEM)];
    r.with_inbox(&items);
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
    // Explicit opt-in proceeds.
    let report = run_with(&r, Vec::new(), true, None).expect("allow_unsigned should proceed");
    assert_eq!(report.merged, 2);
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

/// Configure SSH commit signing on the test repo with a throwaway key.
/// Returns the key fingerprint (the `SHA256:…` id operators are told to
/// read via `git log --format=%GK`) plus the TempDir that owns the key
/// files (must stay alive while signing). Returns None when ssh-keygen is
/// unavailable — the caller skips the test.
fn ssh_signing(r: &Repo) -> Option<(TempDir, String)> {
    let keydir = TempDir::new().ok()?;
    let key = keydir.path().join("key");
    let gen = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-C", "inbox-e2e"])
        .arg("-f")
        .arg(&key)
        .output()
        .ok()?;
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
    let lf = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(key.with_extension("pub"))
        .output()
        .ok()?;
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
