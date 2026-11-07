//! Write pipeline: one commit per write, check-gated, idempotent (ADR-7).
//!
//! Every mutating command funnels through [`apply_write`]:
//!
//! 1. The vault must be a git repository (shell-out to `git`; no libgit2).
//! 2. If `--request-id` was given, look for a previous commit carrying its
//!    domain-separated hash. Same canonical content → idempotent no-op.
//!    Different content → [`ErrorKind::IdempotencyConflict`].
//! 3. Read-only target gates: an append target with uncommitted changes is
//!    refused (the commit would include them, #611), a target containing
//!    merge-conflict markers fails closed with [`ErrorKind::Conflict`], and
//!    a git identity must exist for the eventual commit. A dry run runs
//!    these too (#770).
//! 4. `check` runs before the change and fails fast on an already-broken
//!    vault (skipped for a repairing write). A dry run runs this same
//!    read-only pre-check.
//! 5. An agent write that would retract or retire more than the safety cap
//!    ([`destructive_batch_cap`]) is refused before anything is written
//!    (#883). The operator's explicit `--force` on the same command bypasses
//!    the refusal; a human write never sees it.
//! 6. `--dry-run` shows the LOGICAL change (ledger lines / file content) and
//!    stops. It cannot run the post-write check without writing, so its
//!    outcome says explicitly which checks ran ([`DryRunChecks`]). Steps 1-5
//!    have already run, so a preview that passes means apply would pass the
//!    same gates.
//! 7. Files are applied atomically ([`crate::paths::write_replace`]).
//! 8. `check` runs after the change; a failing check rolls the files back and
//!    blocks the commit.
//! 9. One `git add` + `git commit`. The message and trailers carry ONLY opaque
//!    IDs, verbs, and hashes. Free-text reasons/intent are never in the
//!    commit message.
//!
//! [`ErrorKind::IdempotencyConflict`]: crate::error::ErrorKind::IdempotencyConflict
//! [`ErrorKind::Conflict`]: crate::error::ErrorKind::Conflict

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::check::{run as check_vault, CheckOptions, CheckReport};
use crate::error::{DomainError, ErrorKind};
use crate::vault::{load_vault, Vault};
/// Options shared by every write command.
#[derive(Clone, Debug, Default)]
pub struct WriteOptions {
    /// Show the logical change and stop; write nothing, commit nothing.
    pub dry_run: bool,
    /// Never prompt; pass `GIT_TERMINAL_PROMPT=0` to git.
    pub no_input: bool,
    /// Client-supplied idempotency key (ADR-7).
    pub request_id: Option<String>,
    /// Opaque agent identity for the `Agent:` commit trailer (#49).
    pub agent_id: Option<String>,
    /// The operator's explicit approval of an agent write that removes more
    /// than [`destructive_batch_cap`] retractions/retirements in one request
    /// (#883). Only meaningful together with `agent_id`; a human write is
    /// never capped.
    pub allow_destructive_batch: bool,
}

/// The safety cap on retract/retire operations in one agent request (#883).
///
/// 15% of the vault's live records, with a floor of [`MIN_DESTRUCTIVE_BATCH_CAP`]
/// so an ordinary correction in a tiny vault is never refused. A request at
/// the cap is allowed; one operation over it is refused.
pub const DESTRUCTIVE_BATCH_PERCENT: usize = 15;

/// The floor under [`destructive_batch_cap`] (#883). A vault with fewer than
/// 20 live records still allows three retract/retire operations per request.
pub const MIN_DESTRUCTIVE_BATCH_CAP: usize = 3;

/// The per-request cap for `live_records` live (non-retired) records (#883).
pub fn destructive_batch_cap(live_records: usize) -> usize {
    std::cmp::max(
        MIN_DESTRUCTIVE_BATCH_CAP,
        live_records * DESTRUCTIVE_BATCH_PERCENT / 100,
    )
}

/// One file mutation inside a pending write. Paths are vault-relative.
#[derive(Clone, Debug)]
pub enum FileChange {
    /// Append lines to an existing (or new) text file.
    AppendLines { path: PathBuf, lines: Vec<String> },
    /// Replace (or create) a file with these contents.
    WriteFile { path: PathBuf, contents: String },
    /// Replace (or create) a file with raw bytes. A pack's vendored tree is
    /// covered byte-for-byte by its canonical hash, so it cannot go through
    /// the `String` variant (#440).
    WriteBytes { path: PathBuf, contents: Vec<u8> },
    /// Delete a file. Deleting an absent file is a no-op, so rollback and
    /// idempotent retries are safe.
    DeleteFile { path: PathBuf },
}

impl FileChange {
    /// Vault-relative path this change touches.
    pub fn path(&self) -> &Path {
        match self {
            FileChange::AppendLines { path, .. }
            | FileChange::WriteFile { path, .. }
            | FileChange::WriteBytes { path, .. }
            | FileChange::DeleteFile { path } => path,
        }
    }
}

/// A fully computed write: what to change, and how the commit reads.
///
/// `summary` is the commit's first line: opaque IDs, verbs, hashes only.
/// `canonical_request` is the exact string the idempotency hash binds to; two
/// writes are "the same write" iff their canonical requests are byte-equal.
#[derive(Clone, Debug)]
pub struct PendingWrite {
    pub changes: Vec<FileChange>,
    pub summary: String,
    pub canonical_request: String,
}

/// One file shown by a dry run.
#[derive(Clone, Debug)]
pub struct DryRunFile {
    pub path: String,
    pub action: String,
    pub content: String,
}

/// The status of one write-pipeline check in a dry run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DryRunCheck {
    /// The check ran and the vault passed it.
    Passed,
    /// The check did not gate this dry run. See [`DryRunChecks`].
    Skipped,
}

impl DryRunCheck {
    /// Stable lowercase label used in the JSON and text contract.
    pub fn as_str(self) -> &'static str {
        match self {
            DryRunCheck::Passed => "passed",
            DryRunCheck::Skipped => "skipped",
        }
    }
}

/// The checks a dry run actually performed (#770).
///
/// Apply runs a read-only pre-check before writing and a post-check after.
/// A dry run runs the same pre-check, so an already-broken vault blocks the
/// preview exactly as it blocks the apply. It also runs the pipeline's
/// read-only target gates (a git repository with a configured identity, an
/// append target with uncommitted changes, a conflicted target). It cannot
/// run the post-check without applying the change, and a dry run never
/// writes. Reporting both statuses keeps that one gap explicit instead of
/// implying full validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunChecks {
    /// The pre-write check. `Skipped` for a repairing write, whose apply
    /// path skips the same gate.
    pub pre: DryRunCheck,
    /// The post-write check. Always `Skipped`: it needs the applied tree.
    pub post: DryRunCheck,
}

/// What [`apply_write`] did.
#[derive(Clone, Debug)]
pub enum WriteOutcome {
    /// Files applied and committed. `commit` is the full SHA; `files`
    /// lists only the paths this write actually rewrote — a change whose
    /// bytes already matched the file on disk is not listed, so the list and
    /// the commit diff agree (#425).
    Applied { commit: String, files: Vec<String> },
    /// Nothing touched; the logical change is in `preview`, and `checks`
    /// says which write-pipeline checks the dry run could run.
    DryRun {
        preview: Vec<DryRunFile>,
        checks: DryRunChecks,
    },
    /// `--request-id` matched a previous identical write; `commit` is its SHA.
    Idempotent { commit: String },
    /// Every change already matched what was on disk for that path: nothing
    /// was written and nothing was committed. Distinct from [`Self::Idempotent`],
    /// which reports the commit a replayed request already landed. Reachable
    /// only from a write whose content can repeat — today `record edit`
    /// (#216 / #389 Q1) — since the other write commands always change a file.
    Unchanged,
    /// `check` failed; nothing was committed (files were rolled back).
    CheckBlocked { report: CheckReport },
}

/// Lowercase hex, no `0x` prefix.
fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(CHARS[(b >> 4) as usize] as char);
        s.push(CHARS[(b & 15) as usize] as char);
    }
    s
}

/// ADR-7 idempotency digests.
///
/// - `id_hash = SHA256("confidant-request-id/v1\x00" || request_id)`
/// - `req_hash = SHA256("confidant-request-hash/v1\x00" || request_id ||
///   "\x00" || canonical_request)`
///
/// Only the hashes are stored (as commit trailers); the raw id never is.
pub fn idempotency_digests(request_id: &str, canonical_request: &str) -> (String, String) {
    let mut h = Sha256::new();
    h.update(b"confidant-request-id/v1\x00");
    h.update(request_id.as_bytes());
    let id_hash = hex(&h.finalize());

    let mut h = Sha256::new();
    h.update(b"confidant-request-hash/v1\x00");
    h.update(request_id.as_bytes());
    h.update(b"\x00");
    h.update(canonical_request.as_bytes());
    let req_hash = hex(&h.finalize());
    (id_hash, req_hash)
}

/// SSH invocation used when `no_input` is set.
///
/// `GIT_TERMINAL_PROMPT=0` stops HTTPS credential helpers, but ssh opens
/// `/dev/tty` for a key passphrase or an unknown host key. Append
/// `-o BatchMode=yes` to the ssh command already in force (`GIT_SSH_COMMAND`,
/// then `GIT_SSH`, then `core.sshCommand`, else `ssh`) so a TUI or agent
/// cannot hang on a prompt.
///
/// `GIT_SSH` is checked because setting `GIT_SSH_COMMAND` overrides it: without
/// this fallback, a user who configures only `GIT_SSH` would silently get the
/// default `ssh` under `--no-input`.
pub(crate) fn no_input_ssh_command(
    git_ssh_command: Option<&str>,
    git_ssh: Option<&str>,
    core_ssh_command: Option<&str>,
) -> String {
    let base = git_ssh_command
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| git_ssh.map(str::trim).filter(|s| !s.is_empty()))
        .or_else(|| core_ssh_command.map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or("ssh");
    if ssh_command_has_batch_mode(base) {
        base.to_owned()
    } else {
        format!("{base} -o BatchMode=yes")
    }
}

fn ssh_command_has_batch_mode(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    lower.contains("-o batchmode=yes") || lower.contains("-obatchmode=yes")
}

/// Whether this git subcommand can reach a remote over ssh. `ls-remote` and
/// `fetch`/`pull`/`push` are the only ones the CLI runs; everything else
/// (add, commit, rev-parse, status, config) is local and needs no ssh client.
fn can_use_ssh(args: &[&str]) -> bool {
    matches!(
        args.first().copied(),
        Some("fetch" | "pull" | "push" | "ls-remote")
    )
}

/// `core.sshCommand` for this repo (global/local), if set. Looked up with a
/// direct git spawn so [`git`] does not recurse.
fn core_ssh_command(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "--get", "core.sshCommand"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Run git in `root`. With `no_input`, `GIT_TERMINAL_PROMPT=0` and
/// `GIT_SSH_COMMAND` includes `-o BatchMode=yes`, so git can never block
/// on a credential or ssh prompt (ADR-7).
pub fn git(root: &Path, args: &[&str], no_input: bool) -> anyhow::Result<String> {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C").arg(root).args(args);
    if no_input {
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        let env_ssh = std::env::var("GIT_SSH_COMMAND")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let env_ssh_fallback = std::env::var("GIT_SSH")
            .ok()
            .filter(|value| !value.trim().is_empty());
        // Only the network subcommands can invoke ssh, and `git config` is an
        // extra spawn: skip it for the local-only calls (add, commit, rev-parse,
        // status) that every write runs.
        let core_ssh = if (env_ssh.is_some() || env_ssh_fallback.is_some()) || !can_use_ssh(args) {
            None
        } else {
            core_ssh_command(root)
        };
        cmd.env(
            "GIT_SSH_COMMAND",
            no_input_ssh_command(
                env_ssh.as_deref(),
                env_ssh_fallback.as_deref(),
                core_ssh.as_deref(),
            ),
        );
    }
    let out = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("git is not available: {e}"))?;
    if !out.status.success() {
        // Some git failures print their reason on stdout, not stderr —
        // `git commit` with nothing to commit is the canonical example. Never
        // surface an empty message: fall back to stdout, then the exit
        // status (#602).
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let detail = stderr.trim();
        let detail = if detail.is_empty() {
            stdout.trim()
        } else {
            detail
        };
        let message = if detail.is_empty() {
            format!("git {} failed ({})", args.join(" "), out.status)
        } else {
            format!("git {} failed: {}", args.join(" "), detail)
        };
        return Err(anyhow::anyhow!(message));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Fail unless `root` is inside a git working tree (ADR-7: one commit per write).
pub fn require_git_repo(root: &Path, no_input: bool) -> anyhow::Result<()> {
    match git(root, &["rev-parse", "--git-dir"], no_input) {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow::Error::new(
            DomainError::invalid(
                "vault is not a git repository; writes need git for commit-per-write",
            )
            .with_fix("Run `git init` in the vault, then retry"),
        )),
    }
}

/// Find the commit that already carries `id_hash`, if any.
/// Returns `(commit sha, Request-Hash trailer value)`.
pub fn find_request_commit(
    root: &Path,
    id_hash: &str,
    no_input: bool,
) -> anyhow::Result<Option<(String, String)>> {
    // A repo with zero commits has nothing to find.
    if git(root, &["rev-parse", "--verify", "HEAD"], no_input).is_err() {
        return Ok(None);
    }
    let pattern = format!("Request-Id-Hash: {id_hash}");
    let out = git(root, &["log", "--format=%H", "--grep", &pattern], no_input)?;
    for sha in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let body = git(root, &["show", "-s", "--format=%B", sha], no_input)?;
        for line in body.lines() {
            if let Some(hash) = line.strip_prefix("Request-Hash:") {
                return Ok(Some((sha.to_owned(), hash.trim().to_owned())));
            }
        }
    }
    Ok(None)
}

/// Generate a fresh ULID (`p-`/`n-`/… bodies are added by the caller).
///
/// Randomness comes from `/dev/urandom` on unix; the fallback hashes
/// wall-clock time, pid, and a counter with SHA-256. Either way the 80-bit
/// random section is unpredictable to an observer of the vault.
pub fn new_ulid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn random_80() -> u128 {
        #[cfg(unix)]
        {
            use std::io::Read;
            if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                let mut bytes = [0u8; 10];
                if f.read_exact(&mut bytes).is_ok() {
                    let mut wide = [0u8; 16];
                    wide[..10].copy_from_slice(&bytes);
                    return u128::from_le_bytes(wide);
                }
            }
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut h = Sha256::new();
        h.update(b"confidant-ulid/v1\x00");
        h.update(nanos.to_le_bytes());
        h.update(std::process::id().to_le_bytes());
        h.update(counter.to_le_bytes());
        let digest = h.finalize();
        let mut bytes = [0u8; 16];
        bytes[..10].copy_from_slice(&digest[..10]);
        u128::from_le_bytes(bytes)
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    crate::id::ulid_from_parts(now_ms, random_80())
}

/// Apply `pending` to the vault at `root` per the ADR-7 write pipeline.
pub fn apply_write(
    root: &Path,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    apply_write_inner(root, pending, opts, false)
}

/// Like [`apply_write`], but a failing pre-check does not block the write:
/// the change is applied and the post-check decides.
///
/// The post-check still fails closed. If the vault is not clean after the
/// change, every touched file is rolled back and the outcome is
/// [`WriteOutcome::CheckBlocked`], so this can never commit into a vault
/// that is still broken. Use it only when the write repairs the exact
/// problem the pre-check reports. Callers: `pack update` for a stale
/// `confidant.lock` hash (#606), and `pack add`/`pack remove` for a listed
/// pack with no pin (#612).
pub fn apply_write_repairing(
    root: &Path,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    apply_write_inner(root, pending, opts, true)
}

/// Apply the step-8 change list in order. A failure here is an unexpected I/O
/// error (disk full, a permission change, a path replaced by a directory since
/// the pre-check): the caller restores the step-6 snapshots and returns this
/// error unchanged (#614).
fn apply_changes(root: &Path, changes: &[FileChange]) -> anyhow::Result<()> {
    for (index, change) in changes.iter().enumerate() {
        // Test-only injection point (#614): fail on a chosen change, after
        // earlier changes have already landed, so the mid-apply rollback can
        // be exercised without provoking a real I/O fault.
        #[cfg(test)]
        if apply_failure_due(index) {
            return Err(anyhow::anyhow!(
                "injected mid-apply failure at change {index} (test-only, #614)"
            ));
        }
        #[cfg(not(test))]
        let _ = index;
        match change {
            FileChange::AppendLines { path, lines } => {
                let mut text = crate::paths::read_to_string(root, path).unwrap_or_default();
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                for line in lines {
                    text.push_str(line);
                    text.push('\n');
                }
                crate::paths::write_replace(root, path, text.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e:#}", path.display()))?;
            }
            FileChange::WriteFile { path, contents } => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        crate::paths::ensure_directory(root, parent)
                            .map_err(|e| anyhow::anyhow!("cannot create directory: {e:#}"))?;
                    }
                }
                crate::paths::write_replace(root, path, contents.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e:#}", path.display()))?;
            }
            FileChange::WriteBytes { path, contents } => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        crate::paths::ensure_directory(root, parent)
                            .map_err(|e| anyhow::anyhow!("cannot create directory: {e:#}"))?;
                    }
                }
                crate::paths::write_replace(root, path, contents)
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e:#}", path.display()))?;
            }
            FileChange::DeleteFile { path } => {
                crate::paths::remove_file(root, path)
                    .map_err(|e| anyhow::anyhow!("cannot delete {}: {e:#}", path.display()))?;
            }
        }
    }
    Ok(())
}

/// Restore the step-6 snapshots and remove the directories this write created
/// (innermost first, only when now empty), for a write that must not stand: a
/// mid-apply failure (#614) or a failing post-check (#604). Best effort — the
/// caller already has an error or a check report to surface.
fn rollback(root: &Path, snapshots: &[(PathBuf, Option<Vec<u8>>)], created_dirs: &[PathBuf]) {
    for (rel, orig) in snapshots {
        match orig {
            Some(bytes) => {
                let _ = crate::paths::write_replace(root, rel, bytes);
            }
            None => {
                let _ = crate::paths::remove_file(root, rel);
            }
        }
    }
    // A directory that existed before the write was never recorded; one that
    // now holds another file makes `remove_dir` fail and is left in place.
    for dir in created_dirs.iter().rev() {
        let _ = std::fs::remove_dir(dir);
    }
}

// Test-only injection point for a mid-apply failure (#614). Armed with
// `Some(i)`, `apply_changes` fails on change `i`. Absent from every non-test
// build, so the production write path carries no hook.
#[cfg(test)]
thread_local! {
    static FAIL_APPLY_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Arm (or with `None`, disarm) the test-only mid-apply failure injection.
#[cfg(test)]
fn set_apply_failure(index: Option<usize>) {
    FAIL_APPLY_AT.with(|cell| cell.set(index));
}

/// Whether the test-only injection is armed for this change index.
#[cfg(test)]
fn apply_failure_due(index: usize) -> bool {
    FAIL_APPLY_AT.with(|cell| cell.get()) == Some(index)
}

/// #770: refuse an append into a file with uncommitted changes.
///
/// The write commits the whole file (`git add -- <path>`), so an unrelated
/// pending edit would be swept into this write's commit. This is a read-only
/// git query, so a dry run runs it too: a preview that passed where apply
/// refuses would be validating less than apply (#611).
fn refuse_dirty_append_targets(
    root: &Path,
    changes: &[FileChange],
    no_input: bool,
) -> anyhow::Result<()> {
    for change in changes {
        let FileChange::AppendLines { path, .. } = change else {
            continue;
        };
        if !crate::paths::exists(root, path)? {
            continue;
        }
        let rel = path.to_string_lossy();
        let status = git(root, &["status", "--porcelain", "--", &rel], no_input)?;
        if !status.trim().is_empty() {
            return Err(anyhow::Error::new(
                DomainError::new(
                    ErrorKind::Conflict,
                    format!(
                        "{} has uncommitted changes; appending would commit them too",
                        path.display()
                    ),
                )
                .with_fix("Commit, stash, or discard your changes to that file, then retry"),
            ));
        }
    }
    Ok(())
}

/// #770: refuse a target that already contains merge-conflict markers.
///
/// Apply fails closed on them (#604). A dry run reads the same bytes and
/// writes nothing, so it must fail closed too instead of previewing a write
/// the apply will refuse.
fn refuse_conflicted_targets(root: &Path, changes: &[FileChange]) -> anyhow::Result<()> {
    for change in changes {
        let rel = change.path();
        // No-follow read (#440); a non-file target is reported by the apply
        // itself, not guessed at here.
        let Ok(bytes) = crate::paths::read_bytes(root, rel) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if crate::record::has_conflict_markers(text) {
            return Err(anyhow::Error::new(
                DomainError::new(
                    ErrorKind::Conflict,
                    format!(
                        "{} has unresolved merge conflicts; writes are blocked",
                        rel.display()
                    ),
                )
                .with_fix("Resolve the conflict markers (git mergetool), then retry"),
            ));
        }
    }
    Ok(())
}

/// Whether a record file's front matter carries `retired: true`.
///
/// This matches [`crate::record::Record::is_retired`]'s value semantics
/// (unquoted `true`), reading only the front-matter region so a body line
/// that happens to say `retired: true` is never counted (#883).
fn frontmatter_retired(text: &str) -> bool {
    crate::record::frontmatter_region(text).lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(key, value)| key.trim() == "retired" && value.trim() == "true")
    })
}

/// Count the retraction and retirement operations a write would perform
/// (#883).
///
/// A retraction is an appended `retract` ledger line, whichever command
/// produced it (`retract`, `correct`, or `import` with hand-written lines).
/// A retirement is a record file that flips from live to `retired: true`
/// (`record retire`, or an edit that adds the field). Returns
/// `(retracted, retired)`.
fn destructive_operations(changes: &[FileChange], vault: &Vault) -> (usize, usize) {
    let mut retracted = 0usize;
    let mut retired = 0usize;
    for change in changes {
        match change {
            FileChange::AppendLines { lines, .. } => {
                for line in lines {
                    if let Ok(Some(entry)) = crate::ledger::parse_line(line) {
                        if entry.verb == "retract" {
                            retracted += 1;
                        }
                    }
                }
            }
            FileChange::WriteFile { path, contents } => {
                let Some(record) = vault
                    .records
                    .values()
                    .find(|record| Path::new(&record.path) == path.as_path())
                else {
                    continue;
                };
                if !record.is_retired() && frontmatter_retired(contents) {
                    retired += 1;
                }
            }
            FileChange::WriteBytes { .. } | FileChange::DeleteFile { .. } => {}
        }
    }
    (retracted, retired)
}

/// Refuse an agent write that removes more memory than one request may
/// (#883).
///
/// The cap is [`destructive_batch_cap`] over the vault's live records.
/// Only agent-initiated writes are capped; a human write has no
/// `agent_id`. The operator's explicit `--force` (`allow_destructive_batch`)
/// approves the same batch. The refusal happens before any file is touched,
/// so a large batch is never partially applied, and a dry run refuses it too
/// (the same read-only-gate rule as #770).
fn refuse_oversized_destructive_batch(
    changes: &[FileChange],
    opts: &WriteOptions,
    vault: &Vault,
) -> anyhow::Result<()> {
    let is_agent = opts
        .agent_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|agent| !agent.is_empty());
    if !is_agent || opts.allow_destructive_batch {
        return Ok(());
    }
    let (retracted, retired) = destructive_operations(changes, vault);
    let operations = retracted + retired;
    let live = vault
        .records
        .values()
        .filter(|record| !record.is_retired())
        .count();
    let cap = destructive_batch_cap(live);
    if operations <= cap {
        return Ok(());
    }
    Err(anyhow::Error::new(
        DomainError::new(
            ErrorKind::DestructiveBatchCap,
            format!(
                "agent write would retract {retracted} ledger line(s) and retire \
                 {retired} record(s), above the safety cap of {cap} per request \
                 ({DESTRUCTIVE_BATCH_PERCENT}% of {live} live record(s), minimum \
                 {MIN_DESTRUCTIVE_BATCH_CAP}); operator approval required"
            ),
        )
        .with_fix("Re-run the same command with --force to approve this batch"),
    ))
}

fn apply_write_inner(
    root: &Path,
    pending: PendingWrite,
    opts: &WriteOptions,
    repairing: bool,
) -> anyhow::Result<WriteOutcome> {
    if let Some(rid) = &opts.request_id {
        if rid.trim().is_empty() {
            return Err(anyhow::Error::new(DomainError::usage(
                "--request-id must not be empty",
            )));
        }
        // Trailers are permanent, so a short id makes accidental reuse common
        // and clutters the history. 22 chars is the floor; ULIDs and UUIDv4s
        // clear it comfortably.
        if rid.chars().count() < 22 {
            return Err(anyhow::Error::new(
                DomainError::usage(
                    "--request-id must be unguessable (at least 22 characters; use a ULID or UUIDv4)",
                )
                .with_fix("Generate a ULID or UUIDv4 once and reuse it on retry"),
            ));
        }
    }
    require_git_repo(root, opts.no_input)?;

    // 1. Idempotency: has this request id been seen?
    let digests = opts
        .request_id
        .as_deref()
        .map(|rid| idempotency_digests(rid, &pending.canonical_request));
    if let Some((ref id_hash, ref req_hash)) = digests {
        if let Some((sha, prev_hash)) = find_request_commit(root, id_hash, opts.no_input)? {
            if &prev_hash == req_hash {
                return Ok(WriteOutcome::Idempotent { commit: sha });
            }
            let short = sha.chars().take(8).collect::<String>();
            return Err(anyhow::Error::new(
                DomainError::new(
                    ErrorKind::IdempotencyConflict,
                    format!(
                        "--request-id was already used with different content (commit {short})"
                    ),
                )
                .with_fix("Repeat the identical write, or use a fresh --request-id"),
            ));
        }
    }

    // 2. Read-only target gates, shared by dry run and apply (#770). A target
    // that apply would refuse must refuse the preview too: an append into a
    // file with uncommitted changes would sweep them into this commit
    // (#611), and apply fails closed on merge-conflict markers (#604).
    refuse_dirty_append_targets(root, &pending.changes, opts.no_input)?;
    refuse_conflicted_targets(root, &pending.changes)?;
    // The commit needs a git identity. A dry run never commits, but it must
    // not report ok for a write that apply fails at the commit step; these
    // are read-only `git config` lookups. Proactive so a missing identity is
    // a clean E_INVALID, not git's stderr wrapped as internal_error.
    for key in ["user.name", "user.email"] {
        let val = git(root, &["config", "--get", key], opts.no_input)
            .map(|v| v.trim().to_owned())
            .unwrap_or_default();
        if val.is_empty() {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "git {key} is not configured; commits need an identity"
                ))
                .with_fix("Set it with `git config user.name \"...\"` and `git config user.email \"...\"`"),
            ));
        }
    }

    // 3. Pre-check: fail fast on an already-broken vault. This runs for a
    // dry run too (#770): a preview that passed where apply's pre-check
    // blocks would be validating less than apply. A repairing write skips
    // this gate because it exists to fix the reported problem; the
    // post-check still refuses to commit an unclean result.
    let vault = load_vault(root).map_err(anyhow::Error::new)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok && !repairing {
        return Ok(WriteOutcome::CheckBlocked { report: pre });
    }

    // 3b. #883: cap how much memory one agent request may retract or retire.
    // This runs after the idempotency replay (a retried, already-approved
    // batch must still replay) and before a dry run or apply (a preview that
    // passed where apply refuses would validate less, #770).
    refuse_oversized_destructive_batch(&pending.changes, opts, &vault)?;

    // 4. Dry run: show the logical change, touch nothing. The post-write
    // check needs the applied tree, and a dry run never writes, so the
    // outcome reports it skipped rather than implying full validation.
    if opts.dry_run {
        let preview = pending
            .changes
            .iter()
            .map(|c| match c {
                FileChange::AppendLines { path, lines } => DryRunFile {
                    path: path.display().to_string(),
                    action: "append".to_string(),
                    content: lines.join("\n"),
                },
                FileChange::WriteFile { path, contents } => DryRunFile {
                    path: path.display().to_string(),
                    action: "write".to_string(),
                    content: contents.clone(),
                },
                FileChange::WriteBytes { path, contents } => DryRunFile {
                    path: path.display().to_string(),
                    action: "write".to_string(),
                    content: String::from_utf8_lossy(contents).into_owned(),
                },
                FileChange::DeleteFile { path } => DryRunFile {
                    path: path.display().to_string(),
                    action: "delete".to_string(),
                    content: String::new(),
                },
            })
            .collect();
        return Ok(WriteOutcome::DryRun {
            preview,
            checks: DryRunChecks {
                pre: if repairing {
                    DryRunCheck::Skipped
                } else {
                    DryRunCheck::Passed
                },
                post: DryRunCheck::Skipped,
            },
        });
    }

    // 5. Nothing to do: every change already matches the file on disk.
    // This has to be its own outcome: step 10 cannot commit an empty
    // changeset, and `git commit` on nothing staged fails with an empty
    // message.
    let unchanged = pending.changes.iter().all(|change| match change {
        FileChange::WriteFile { path, contents } => {
            crate::paths::read_to_string(root, path).is_ok_and(|on_disk| on_disk == *contents)
        }
        FileChange::WriteBytes { path, contents } => {
            crate::paths::read_bytes(root, path).is_ok_and(|on_disk| on_disk == *contents)
        }
        FileChange::DeleteFile { path } => !crate::paths::exists(root, path).unwrap_or(true),
        // An append always changes its file; keep those on the normal path.
        FileChange::AppendLines { .. } => false,
    });
    if unchanged {
        return Ok(WriteOutcome::Unchanged);
    }

    // 6. Snapshot each target for rollback. Along the way, record which
    // files this changeset actually rewrites (#425): the `files` list names
    // only real rewrites, so the JSON `files` and the commit diff
    // (`git show --stat`) agree.
    let mut snapshots: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    let mut changed: Vec<String> = Vec::new();
    for change in &pending.changes {
        let rel = change.path();
        // No-follow read: a planted symlink or FIFO at `rel` must not be
        // traversed or allowed to block the write (#440).
        let existing = crate::paths::read_bytes(root, rel).ok();
        let rewrites = match change {
            FileChange::WriteFile { contents, .. } => {
                existing.as_deref() != Some(contents.as_bytes())
            }
            FileChange::WriteBytes { contents, .. } => {
                existing.as_deref() != Some(contents.as_slice())
            }
            // An append always changes its file (same rule as step 5).
            FileChange::AppendLines { .. } => true,
            // Deleting an absent file changes nothing.
            FileChange::DeleteFile { .. } => existing.is_some(),
        };
        if rewrites {
            changed.push(rel.display().to_string());
        }
        snapshots.push((rel.to_path_buf(), existing));
    }

    // 7. Directories this write may have to create, recorded before the apply
    // (shallow to deep) so a rolled-back write can remove only what it created
    // (#604). Scoped to ancestors that do not exist *now*: a directory that is
    // already there is never a candidate, and removal below is empty-only, so
    // a directory that ends up holding another file survives untouched.
    let mut created_dirs: Vec<PathBuf> = Vec::new();
    for change in &pending.changes {
        if let Some(parent) = change.path().parent() {
            if !parent.as_os_str().is_empty() {
                for dir in crate::paths::missing_ancestors(root, parent) {
                    if !created_dirs.contains(&dir) {
                        created_dirs.push(dir);
                    }
                }
            }
        }
    }

    // 8. Apply atomically. An unexpected I/O error partway (disk full, a
    // permission change, a path replaced by a directory since the pre-check)
    // must not leave a partially applied tree: restore the step-6 snapshots
    // and drop the directories this write created, then return the error
    // unchanged (#614). Modelled refusals are pre-validated above (#587,
    // #604); this is the backstop for the ones that are not.
    if let Err(err) = apply_changes(root, &pending.changes) {
        rollback(root, &snapshots, &created_dirs);
        return Err(err);
    }

    // 9. Post-check: roll the files back if the write broke the vault.
    let vault2 = load_vault(root).map_err(anyhow::Error::new)?;
    let post = check_vault(&vault2, &CheckOptions::default());
    if !post.ok {
        rollback(root, &snapshots, &created_dirs);
        return Ok(WriteOutcome::CheckBlocked { report: post });
    }

    // 10. One commit. Message and trailers: opaque IDs, verbs, hashes only.
    // The identity gate ran with the read-only gates above (#770).
    let mut message = pending.summary.clone();
    if let Some((id_hash, req_hash)) = &digests {
        message.push_str(&format!(
            "\n\nRequest-Id-Hash: {id_hash}\nRequest-Hash: {req_hash}"
        ));
    }
    if let Some(agent) = opts
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if agent.contains('\n') || agent.len() > 128 {
            return Err(anyhow::Error::new(DomainError::usage(
                "agent id must be a single opaque line (at most 128 characters)",
            )));
        }
        message.push_str(&format!("\n\nAgent: {agent}"));
    }
    let files: Vec<String> = changed;
    let mut add_args: Vec<&str> = vec!["add", "--"];
    add_args.extend(files.iter().map(|s| s.as_str()));
    git(root, &add_args, opts.no_input)?;
    git(root, &["commit", "-m", &message], opts.no_input)?;
    let commit = git(root, &["rev-parse", "HEAD"], opts.no_input)?
        .trim()
        .to_owned();

    Ok(WriteOutcome::Applied { commit, files })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #883: 15% of live records, floored at 3. At the cap is allowed; the
    /// caller refuses only `> cap`.
    #[test]
    fn destructive_batch_cap_is_fifteen_percent_with_a_floor_of_three() {
        for live in 0..=20 {
            assert_eq!(destructive_batch_cap(live), 3, "live={live}");
        }
        assert_eq!(destructive_batch_cap(21), 3);
        assert_eq!(destructive_batch_cap(26), 3);
        assert_eq!(destructive_batch_cap(27), 4);
        assert_eq!(destructive_batch_cap(40), 6);
        assert_eq!(destructive_batch_cap(100), 15);
        assert_eq!(destructive_batch_cap(1_000), 150);
    }

    /// #883: retirement detection reads only the front matter, so a body
    /// line that looks like the field is never counted.
    #[test]
    fn frontmatter_retired_reads_only_the_front_matter() {
        assert!(frontmatter_retired(
            "---\nid: p-01M3TC5H00MPJG000000000000\nretired: true\n---\n\nbody\n"
        ));
        assert!(frontmatter_retired(
            "---\nretired:    true\nid: p-01M3TC5H00MPJG000000000000\n---\n"
        ));
        assert!(!frontmatter_retired(
            "---\nid: p-01M3TC5H00MPJG000000000000\nretired: false\n---\n"
        ));
        assert!(!frontmatter_retired(
            "---\nid: p-01M3TC5H00MPJG000000000000\n---\n\nretired: true\n"
        ));
    }

    /// #883: count appended `retract` lines whichever command produced them,
    /// and a record file that flips from live to `retired: true`; an
    /// unrelated file change counts nothing.
    #[test]
    fn destructive_operations_counts_retractions_and_new_retirements() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.4\"\npacks = []\nvault_id = \"01M3TC5H00MPJG000000000000\"\n",
        )
        .expect("write config");
        let person = "p-01M3TC5H00MPJG000000000000";
        let rel = format!("people/{person}/profile.md");
        let live =
            format!("---\nid: {person}\ntype: person\nname: \"Capped Example\"\n---\n\nFake.\n");
        std::fs::create_dir_all(root.join(format!("people/{person}"))).expect("person dir");
        std::fs::write(root.join(&rel), &live).expect("profile");
        git(root, &["init", "-q", "-b", "main"], false).expect("init");
        git(root, &["config", "user.name", "Test"], false).expect("name");
        git(
            root,
            &["config", "user.email", "test@example.invalid"],
            false,
        )
        .expect("email");
        git(root, &["add", "-A"], false).expect("add");
        git(root, &["commit", "-qm", "init"], false).expect("commit");
        let vault = load_vault(root).expect("load vault");

        let retirement = live.replacen("---\n", "---\nretired: true\n", 1);
        let changes = vec![
            FileChange::AppendLines {
                path: PathBuf::from("ledger/2026/11.cfd"),
                lines: vec![format!(
                    "2026-11-02 retract {person} line:{} reason:duplicate",
                    "a".repeat(64)
                )],
            },
            FileChange::WriteFile {
                path: PathBuf::from(&rel),
                contents: retirement,
            },
            // Not a record and not a retract line: counts nothing.
            FileChange::WriteFile {
                path: PathBuf::from("README.md"),
                contents: "retired: true\n".to_owned(),
            },
        ];
        assert_eq!(destructive_operations(&changes, &vault), (1, 1));

        // A write that leaves the record live is not a retirement.
        let no_change = vec![FileChange::WriteFile {
            path: PathBuf::from(&rel),
            contents: live,
        }];
        assert_eq!(destructive_operations(&no_change, &vault), (0, 0));
    }

    #[test]
    fn no_input_ssh_command_appends_batch_mode_and_keeps_existing() {
        assert_eq!(
            no_input_ssh_command(None, None, None),
            "ssh -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some("ssh -p 2222"), None, None),
            "ssh -p 2222 -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some(""), None, Some("/usr/bin/ssh")),
            "/usr/bin/ssh -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some("   "), None, Some("ssh -i key")),
            "ssh -i key -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some("ssh -o BatchMode=yes"), None, Some("ignored")),
            "ssh -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some("ssh -oBatchMode=yes"), None, None),
            "ssh -oBatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some("ssh -i key"), None, Some("ssh -p 22")),
            "ssh -i key -o BatchMode=yes"
        );
        // `GIT_SSH` is the fallback when no `GIT_SSH_COMMAND`/`core.sshCommand`
        // is set, and `GIT_SSH_COMMAND` still wins over it.
        assert_eq!(
            no_input_ssh_command(None, Some("ssh -i git_ssh"), None),
            "ssh -i git_ssh -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(Some("ssh -i command"), Some("ssh -i git_ssh"), None),
            "ssh -i command -o BatchMode=yes"
        );
        assert_eq!(
            no_input_ssh_command(None, Some("  "), Some("ssh -i core")),
            "ssh -i core -o BatchMode=yes"
        );
    }

    #[test]
    fn only_network_subcommands_use_ssh() {
        assert!(can_use_ssh(&["fetch", "--quiet"]));
        assert!(can_use_ssh(&["pull", "--ff-only"]));
        assert!(can_use_ssh(&["push", "origin", "HEAD:refs/heads/main"]));
        assert!(can_use_ssh(&["ls-remote", "--get-url", "origin"]));
        assert!(!can_use_ssh(&["commit", "-m", "x"]));
        assert!(!can_use_ssh(&["rev-parse", "HEAD"]));
        assert!(!can_use_ssh(&["config", "--get", "core.sshCommand"]));
        assert!(!can_use_ssh(&[]));
    }

    #[test]
    fn digests_are_deterministic_and_domain_separated() {
        let (h1, r1) = idempotency_digests("abc", "canonical");
        let (h2, r2) = idempotency_digests("abc", "canonical");
        assert_eq!((&h1, &r1), (&h2, &r2));
        let (h3, _) = idempotency_digests("abd", "canonical");
        assert_ne!(h1, h3, "different ids hash differently");
        let (_, r4) = idempotency_digests("abc", "canonical2");
        assert_ne!(r1, r4, "different content hashes differently");
        assert_eq!(h1.len(), 64);
        assert_eq!(r1.len(), 64);
        // Domain separation: the id hash must not equal a bare SHA256 of the id.
        let mut bare = Sha256::new();
        bare.update(b"abc");
        assert_ne!(h1, hex(&bare.finalize()));
    }

    #[test]
    fn ulid_looks_right() {
        let u = new_ulid();
        assert_eq!(u.len(), 26);
        assert!(u
            .chars()
            .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
        assert_ne!(new_ulid(), new_ulid(), "two ULIDs must differ");
    }

    #[test]
    fn conflict_markers_detected() {
        assert!(crate::record::has_conflict_markers("a\n<<<<<<< HEAD\nb\n"));
        assert!(crate::record::has_conflict_markers(">>>>>>> branch\n"));
        assert!(!crate::record::has_conflict_markers("a\n=======\nb\n"));
        assert!(!crate::record::has_conflict_markers("plain text\n"));
    }

    /// #606: a repairing write may proceed past a failing pre-check, but the
    /// post-check still gates the commit. A write that does not leave the
    /// vault clean is rolled back and reported blocked.
    #[test]
    fn repairing_write_still_refuses_an_unclean_result() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"9.9\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
        )
        .expect("write config");
        git(dir.path(), &["init", "-q"], false).expect("init");
        git(dir.path(), &["config", "user.name", "Test"], false).expect("name");
        git(
            dir.path(),
            &["config", "user.email", "test@example.invalid"],
            false,
        )
        .expect("email");
        git(dir.path(), &["add", "-A"], false).expect("add");
        git(dir.path(), &["commit", "-qm", "init"], false).expect("commit");

        // The unsupported spec is an error finding, and this write does not
        // fix it: nothing is committed and the file is rolled back.
        let unrelated = PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: PathBuf::from("README.md"),
                contents: "unrelated\n".to_owned(),
            }],
            summary: "test: unrelated".to_owned(),
            canonical_request: "test: unrelated".to_owned(),
        };
        let outcome = apply_write_repairing(dir.path(), unrelated, &WriteOptions::default())
            .expect("apply should report, not error");
        assert!(
            matches!(outcome, WriteOutcome::CheckBlocked { .. }),
            "{outcome:?}"
        );
        assert!(!dir.path().join("README.md").exists(), "rolled back");
        assert_eq!(
            git(dir.path(), &["rev-list", "--count", "HEAD"], false)
                .unwrap()
                .trim(),
            "1"
        );
        assert_eq!(
            git(dir.path(), &["status", "--porcelain"], false).unwrap(),
            ""
        );

        // A write that repairs the reported problem commits.
        let repair = PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: PathBuf::from("confidant.toml"),
                contents: "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n"
                    .to_owned(),
            }],
            summary: "test: repair".to_owned(),
            canonical_request: "test: repair".to_owned(),
        };
        let outcome = apply_write_repairing(dir.path(), repair, &WriteOptions::default())
            .expect("repairing apply should commit");
        assert!(
            matches!(outcome, WriteOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }

    #[test]
    fn git_failure_message_is_never_empty() {
        // #602: `git commit` with nothing staged writes its reason
        // ("nothing to commit") to stdout, not stderr. The surfaced error
        // must still be non-empty and keep git's own detail. Pass an
        // identity inline so a runner without a global one still fails on
        // the staged-set, not on the missing author.
        let dir = tempfile::tempdir().expect("tempdir");
        git(dir.path(), &["init", "-q"], false).expect("init");
        let err = git(
            dir.path(),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "nothing",
            ],
            false,
        )
        .expect_err("commit with nothing staged must fail");
        let message = format!("{err:#}");
        assert!(!message.trim().is_empty(), "empty git error message");
        assert!(message.contains("failed"), "unhelpful message: {message:?}");
        assert!(
            message.contains("nothing to commit") || message.contains("no changes"),
            "message lost git's own detail: {message:?}"
        );
    }

    /// #614: an unexpected I/O error partway through the apply loop must not
    /// leave a partially applied tree. The failure is injected at the second
    /// change (so the first has already landed): the first change is rolled
    /// back, the directory this write created is removed, nothing is staged or
    /// committed, and the original error is surfaced unchanged.
    #[test]
    fn mid_apply_failure_rolls_back_and_returns_the_original_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // A minimal check-clean vault.
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\npacks = []\nvault_id = \"01M3TC5H00MPJG000000000000\"\n",
        )
        .expect("write config");
        let person = root.join("people/p-01M3TC5H00MPJG000000000000");
        std::fs::create_dir_all(&person).expect("person dir");
        std::fs::write(
            person.join("profile.md"),
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: \"Test Person\"\n---\n\nFake.\n",
        )
        .expect("profile");
        git(root, &["init", "-q", "-b", "main"], false).expect("init");
        git(root, &["config", "user.name", "Test"], false).expect("name");
        git(
            root,
            &["config", "user.email", "test@example.invalid"],
            false,
        )
        .expect("email");
        git(root, &["add", "-A"], false).expect("add");
        git(root, &["commit", "-qm", "init"], false).expect("commit");

        // Two new records: the first creates `people/p-…/` (and its dir), the
        // second is made to fail before it does anything.
        let first = "people/p-01M3TC5H00MPJG000000000001/profile.md";
        let second = "people/p-01M3TC5H00MPJG000000000002/profile.md";
        let pending = PendingWrite {
            changes: vec![
                FileChange::WriteFile {
                    path: PathBuf::from(first),
                    contents: "---\nid: p-01M3TC5H00MPJG000000000001\ntype: person\nname: \"Ada Example\"\n---\n\nFake.\n".to_owned(),
                },
                FileChange::WriteFile {
                    path: PathBuf::from(second),
                    contents: "---\nid: p-01M3TC5H00MPJG000000000002\ntype: person\nname: \"Bea Example\"\n---\n\nFake.\n".to_owned(),
                },
            ],
            summary: "test: injected mid-apply failure".to_owned(),
            canonical_request: "test: injected mid-apply failure".to_owned(),
        };

        set_apply_failure(Some(1));
        let err = apply_write(root, pending, &WriteOptions::default())
            .expect_err("the injected failure must surface");
        set_apply_failure(None);

        // The original error is returned as-is, never rewrapped into an E_*.
        let message = format!("{err:#}");
        assert!(
            message.contains("injected mid-apply failure at change 1"),
            "unexpected error: {message}"
        );
        assert!(
            DomainError::of(&err).is_none(),
            "the mid-apply error must not be rewrapped as a domain error: {message}"
        );

        // The first change is rolled back and the directory this write created
        // for it is gone; the second change never touched the tree.
        assert!(
            !root.join(first).exists(),
            "the first change was left applied"
        );
        assert!(
            !root.join("people/p-01M3TC5H00MPJG000000000001").exists(),
            "the directory this write created was left behind"
        );
        assert!(!root.join(second).exists());

        // Nothing staged, nothing committed.
        assert_eq!(git(root, &["status", "--porcelain"], false).unwrap(), "");
        assert_eq!(
            git(root, &["rev-list", "--count", "HEAD"], false)
                .unwrap()
                .trim(),
            "1"
        );
    }

    /// A minimal check-clean, committed vault with one person and a ledger.
    fn clean_vault() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\npacks = []\nvault_id = \"01M3TC5H00MPJG000000000000\"\n",
        )
        .expect("write config");
        let person = root.join("people/p-01M3TC5H00MPJG000000000000");
        std::fs::create_dir_all(&person).expect("person dir");
        std::fs::write(
            person.join("profile.md"),
            "---\nid: p-01M3TC5H00MPJG000000000000\ntype: person\nname: \"Test Person\"\n---\n\nFake.\n",
        )
        .expect("profile");
        std::fs::create_dir_all(root.join("ledger/2026")).expect("ledger dir");
        std::fs::write(
            root.join("ledger/2026/10.cfd"),
            "2026-10-01 touch p-01M3TC5H00MPJG000000000000 call\n",
        )
        .expect("ledger");
        git(root, &["init", "-q", "-b", "main"], false).expect("init");
        git(root, &["config", "user.name", "Test"], false).expect("name");
        git(
            root,
            &["config", "user.email", "test@example.invalid"],
            false,
        )
        .expect("email");
        git(root, &["add", "-A"], false).expect("add");
        git(root, &["commit", "-qm", "init"], false).expect("commit");
        dir
    }

    fn append_pending(path: &str, line: &str) -> PendingWrite {
        PendingWrite {
            changes: vec![FileChange::AppendLines {
                path: PathBuf::from(path),
                lines: vec![line.to_owned()],
            }],
            summary: "test: append".to_owned(),
            canonical_request: "test: append".to_owned(),
        }
    }

    /// #770: an append into a file with uncommitted changes is refused, and a
    /// dry run refuses it exactly like apply. Before this, the dirty-target
    /// guard was command-level and skipped under `--dry-run`.
    #[test]
    fn dry_run_and_apply_refuse_a_dirty_append_target_alike() {
        let dir = clean_vault();
        let root = dir.path();
        let ledger = root.join("ledger/2026/10.cfd");
        let mut dirty = std::fs::read_to_string(&ledger).expect("read ledger");
        dirty.push_str("2026-10-02 touch p-01M3TC5H00MPJG000000000000 meet\n");
        std::fs::write(&ledger, &dirty).expect("dirty ledger");
        let dirty_status = git(root, &["status", "--porcelain"], false).expect("status");
        assert!(!dirty_status.trim().is_empty());

        let line = "2026-10-13 touch p-01M3TC5H00MPJG000000000000 call";
        let dry = apply_write(
            root,
            append_pending("ledger/2026/10.cfd", line),
            &WriteOptions {
                dry_run: true,
                ..WriteOptions::default()
            },
        )
        .expect_err("a dry run must refuse a dirty append target");
        let applied = apply_write(
            root,
            append_pending("ledger/2026/10.cfd", line),
            &WriteOptions::default(),
        )
        .expect_err("apply must refuse a dirty append target");

        for err in [&dry, &applied] {
            assert_eq!(
                DomainError::of(err).map(DomainError::code),
                Some("E_CONFLICT"),
                "{err:#}"
            );
            assert!(
                format!("{err:#}").contains("uncommitted changes"),
                "{err:#}"
            );
        }
        // Neither path wrote: the file is exactly the operator's dirty text
        // and the commit count is unchanged.
        assert_eq!(std::fs::read_to_string(&ledger).expect("read"), dirty);
        assert_eq!(
            git(root, &["status", "--porcelain"], false).unwrap(),
            dirty_status
        );
        assert_eq!(
            git(root, &["rev-list", "--count", "HEAD"], false)
                .unwrap()
                .trim(),
            "1"
        );
    }

    /// #770: the commit's git identity is a read-only precondition, so a dry
    /// run refuses a missing identity exactly like apply — and the check now
    /// runs before the apply, so a missing identity no longer leaves written
    /// files behind.
    #[test]
    fn dry_run_and_apply_refuse_a_missing_git_identity_alike() {
        let dir = clean_vault();
        let root = dir.path();
        // A local empty value wins over any global identity.
        git(root, &["config", "user.name", ""], false).expect("blank name");
        let ledger = root.join("ledger/2026/10.cfd");
        let original = std::fs::read_to_string(&ledger).expect("read ledger");

        for dry_run in [true, false] {
            let err = apply_write(
                root,
                append_pending(
                    "ledger/2026/10.cfd",
                    "2026-10-13 touch p-01M3TC5H00MPJG000000000000 call",
                ),
                &WriteOptions {
                    dry_run,
                    ..WriteOptions::default()
                },
            )
            .expect_err("a missing identity must refuse dry run and apply");
            assert_eq!(
                DomainError::of(&err).map(DomainError::code),
                Some("E_INVALID"),
                "{err:#}"
            );
            assert!(
                format!("{err:#}").contains("user.name is not configured"),
                "{err:#}"
            );
        }
        // Refused before the apply, so nothing was written.
        assert_eq!(std::fs::read_to_string(&ledger).expect("read"), original);
        assert_eq!(
            git(root, &["rev-list", "--count", "HEAD"], false)
                .unwrap()
                .trim(),
            "1"
        );
    }

    /// #770: merge-conflict markers are an apply-time refusal, but the bytes
    /// are readable without writing, so a dry run must refuse them too.
    #[test]
    fn dry_run_and_apply_refuse_a_conflicted_target_alike() {
        let dir = clean_vault();
        let root = dir.path();
        let conflicted = "notes\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\n";
        let target = root.join("README.md");
        std::fs::write(&target, conflicted).expect("conflicted readme");
        git(root, &["add", "-A"], false).expect("add");
        git(root, &["commit", "-qm", "conflicted readme"], false).expect("commit");
        // Committed, so the dirty-target gate cannot be what refuses this.
        assert_eq!(git(root, &["status", "--porcelain"], false).unwrap(), "");

        let dry = apply_write(
            root,
            append_pending("README.md", "more"),
            &WriteOptions {
                dry_run: true,
                ..WriteOptions::default()
            },
        )
        .expect_err("a dry run must refuse a conflicted target");
        let applied = apply_write(
            root,
            append_pending("README.md", "more"),
            &WriteOptions::default(),
        )
        .expect_err("apply must refuse a conflicted target");

        for err in [&dry, &applied] {
            assert_eq!(
                DomainError::of(err).map(DomainError::code),
                Some("E_CONFLICT"),
                "{err:#}"
            );
            assert!(
                format!("{err:#}").contains("unresolved merge conflicts"),
                "{err:#}"
            );
        }
        assert_eq!(std::fs::read_to_string(&target).expect("read"), conflicted);
        assert_eq!(
            git(root, &["rev-list", "--count", "HEAD"], false)
                .unwrap()
                .trim(),
            "2"
        );
    }
}
