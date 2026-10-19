//! Write pipeline: one commit per write, check-gated, idempotent (ADR-7).
//!
//! Every mutating command funnels through [`apply_write`]:
//!
//! 1. The vault must be a git repository (shell-out to `git`; no libgit2).
//! 2. If `--request-id` was given, look for a previous commit carrying its
//!    domain-separated hash. Same canonical content → idempotent no-op.
//!    Different content → [`ErrorKind::IdempotencyConflict`].
//! 3. `--dry-run` shows the LOGICAL change (ledger lines / file content) and
//!    stops. Ciphertext bytes are never shown (encryption is per-write fresh
//!    nonces under PR B; there is nothing ciphertext to show in M3).
//! 4. Files are applied atomically ([`crate::paths::write_replace`]); any file
//!    containing merge-conflict markers fails closed with [`ErrorKind::Conflict`].
//! 5. `check` runs after the change; a failing check rolls the files back and
//!    blocks the commit. A pre-check also fails fast on an already-broken vault.
//! 6. One `git add` + `git commit`. The message and trailers carry ONLY opaque
//!    IDs, verbs, and hashes. Free-text reasons/intent go under the client's
//!    data key (PR B) or are omitted — never in the commit message.
//!
//! [`ErrorKind::IdempotencyConflict`]: crate::error::ErrorKind::IdempotencyConflict
//! [`ErrorKind::Conflict`]: crate::error::ErrorKind::Conflict

use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::check::{run as check_vault, CheckOptions, CheckReport};
use crate::error::{DomainError, ErrorKind};
use crate::vault::load_vault;
/// Options shared by every write command.
#[derive(Clone, Debug, Default)]
pub struct WriteOptions {
    /// Show the logical change and stop; write nothing, commit nothing.
    pub dry_run: bool,
    /// Never prompt; pass `GIT_TERMINAL_PROMPT=0` to git.
    pub no_input: bool,
    /// Client-supplied idempotency key (HMAC idempotency, ADR-7).
    pub request_id: Option<String>,
    /// Opaque agent identity for the `Agent:` commit trailer (#49).
    pub agent_id: Option<String>,
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
/// `canonical_request` is the exact string the idempotency HMAC binds to; two
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

/// What [`apply_write`] did.
#[derive(Clone, Debug)]
pub enum WriteOutcome {
    /// Files applied and committed. `commit` is the full SHA; `files`
    /// lists only the paths this write actually rewrote — a change whose
    /// bytes already matched the file on disk (a reused envelope, #406)
    /// is not listed, so the list and the commit diff agree (#425).
    Applied { commit: String, files: Vec<String> },
    /// Nothing touched; the logical change is in `preview`.
    DryRun { preview: Vec<DryRunFile> },
    /// `--request-id` matched a previous identical write; `commit` is its SHA.
    Idempotent { commit: String },
    /// Every change already matched what was on disk for that path: nothing
    /// was written and nothing was committed. Distinct from [`Self::Idempotent`],
    /// which reports the commit a replayed request already landed. Reachable
    /// only from a write whose content can repeat — today `record edit`
    /// (#216 / #389 Q1), since `encrypt_file` reuses existing ciphertext for
    /// an unchanged body and the other write commands always change a file.
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
/// - `req_hash = HMAC-SHA256(key=request_id, msg=canonical_request)`
///
/// Only the hashes are stored (as commit trailers); the raw id never is.
pub fn idempotency_digests(request_id: &str, canonical_request: &str) -> (String, String) {
    let mut h = Sha256::new();
    h.update(b"confidant-request-id/v1\x00");
    h.update(request_id.as_bytes());
    let id_hash = hex(&h.finalize());

    let mut mac = Hmac::<Sha256>::new_from_slice(request_id.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(canonical_request.as_bytes());
    let req_hash = hex(&mac.finalize().into_bytes());
    (id_hash, req_hash)
}

/// Run git in `root`. With `no_input`, `GIT_TERMINAL_PROMPT=0` so git can
/// never block on a credential prompt (ADR-7).
pub fn git(root: &Path, args: &[&str], no_input: bool) -> anyhow::Result<String> {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C").arg(root).args(args);
    if no_input {
        cmd.env("GIT_TERMINAL_PROMPT", "0");
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

/// Encrypts one record file's plaintext bytes into the bytes to write.
///
/// Called only for `FileChange::WriteFile` targets under record paths
/// ([`crate::crypto_mode::is_record_path`]). The CLI supplies the real
/// encryptor (spec 3); commands that do not write records pass no
/// encryptor and keep today's behavior.
pub type RecordEncryptor = dyn Fn(&Path, &[u8]) -> anyhow::Result<Vec<u8>>;

/// Apply `pending` to the vault at `root` per the ADR-7 write pipeline.
pub fn apply_write(
    root: &Path,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    apply_write_inner(root, pending, opts, None, false)
}

/// Like [`apply_write`], but a failing pre-check does not block the write:
/// the change is applied and the post-check decides.
///
/// The post-check still fails closed. If the vault is not clean after the
/// change, every touched file is rolled back and the outcome is
/// [`WriteOutcome::CheckBlocked`], so this can never commit into a vault
/// that is still broken. Use it only when the write repairs the exact
/// problem the pre-check reports. `pack update` is the one caller: a stale
/// `confidant.lock` hash makes the pre-check report `E_PACK_HASH` for the
/// pin the pending write rewrites (#606).
pub fn apply_write_repairing(
    root: &Path,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    apply_write_inner(root, pending, opts, None, true)
}

/// Like [`apply_write`], but record-file contents are transformed through
/// `encrypt` before anything is written.
///
/// The transform runs **after** the dry-run preview (so `--dry-run` shows
/// the inner plaintext, never ciphertext) and **before** the pre-check, so
/// a failing encryption leaves the target file untouched and a failing
/// check rolls back as usual. Ledger appends and non-record files are
/// never transformed.
pub fn apply_write_with_encryptor(
    root: &Path,
    pending: PendingWrite,
    opts: &WriteOptions,
    encrypt: &RecordEncryptor,
) -> anyhow::Result<WriteOutcome> {
    apply_write_inner(root, pending, opts, Some(encrypt), false)
}

fn apply_write_inner(
    root: &Path,
    mut pending: PendingWrite,
    opts: &WriteOptions,
    encrypt: Option<&RecordEncryptor>,
    repairing: bool,
) -> anyhow::Result<WriteOutcome> {
    if let Some(rid) = &opts.request_id {
        if rid.trim().is_empty() {
            return Err(anyhow::Error::new(DomainError::usage(
                "--request-id must not be empty",
            )));
        }
        // The Request-Hash trailer HMACs the canonical request with the raw id
        // as key, and trailers are permanent (crypto-shredding can't reach
        // them, ADR-7). A guessable id lets anyone with repo read access
        // confirm guesses about note contents offline — even after shredding.
        // 22 chars is the unguessability floor; ULIDs and UUIDv4s
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

    // 2. Dry run: show the logical change, touch nothing.
    // The preview is built from the pending contents as given — i.e. the
    // inner plaintext — because the record-encryption transform below has
    // not run yet. Dry-run never shows ciphertext (spec 3 B5).
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
        return Ok(WriteOutcome::DryRun { preview });
    }

    // 2b. Record-encryption transform (spec 3). Only WriteFile changes
    // under record paths go through the encryptor; ledger appends and
    // non-record files are untouched. Any failure refuses the whole
    // write before anything is applied: the target file is left
    // untouched and no plaintext fallback is written.
    if let Some(encrypt) = encrypt {
        for change in &mut pending.changes {
            if let FileChange::WriteFile { path, contents } = change {
                if crate::crypto_mode::is_record_path(path) {
                    // Use context (not format-interpolation) so the
                    // DomainError chain — code and fix — survives.
                    let out = encrypt(path, contents.as_bytes()).map_err(|e| {
                        let path = path.display().to_string();
                        e.context(format!("cannot encrypt {path}"))
                    })?;
                    *contents = String::from_utf8(out).map_err(|_| {
                        anyhow::anyhow!("encryptor returned non-UTF-8 bytes for {}", path.display())
                    })?;
                }
            }
        }
    }

    // 3. Pre-check: fail fast on an already-broken vault. A repairing write
    // skips this gate because it exists to fix the reported problem; the
    // post-check below still refuses to commit an unclean result.
    let vault = load_vault(root).map_err(anyhow::Error::new)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok && !repairing {
        return Ok(WriteOutcome::CheckBlocked { report: pre });
    }

    // 3b. Nothing to do: every change already matches the file on disk. The
    // encryptor transform above has already run, so an encrypted record whose
    // body is unchanged lands here too (it reused the existing ciphertext).
    // This has to be its own outcome: step 7 cannot commit an empty changeset,
    // and `git commit` on nothing staged fails with an empty message.
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

    // 4. Fail closed on conflict markers; snapshot for rollback. Along the
    // way, record which files this changeset actually rewrites (#425): a
    // reused envelope (#406) keeps its ciphertext byte-for-byte, and the
    // `files` list names only real rewrites, so the JSON `files` and the
    // commit diff (`git show --stat`) agree.
    let mut snapshots: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    let mut changed: Vec<String> = Vec::new();
    for change in &pending.changes {
        let rel = change.path();
        // No-follow read: a planted symlink or FIFO at `rel` must not be
        // traversed or allowed to block the write (#440).
        let existing = crate::paths::read_bytes(root, rel).ok();
        if let Some(bytes) = &existing {
            if let Ok(text) = std::str::from_utf8(bytes) {
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
        }
        let rewrites = match change {
            FileChange::WriteFile { contents, .. } => {
                existing.as_deref() != Some(contents.as_bytes())
            }
            FileChange::WriteBytes { contents, .. } => {
                existing.as_deref() != Some(contents.as_slice())
            }
            // An append always changes its file (same rule as step 3b).
            FileChange::AppendLines { .. } => true,
            // Deleting an absent file changes nothing.
            FileChange::DeleteFile { .. } => existing.is_some(),
        };
        if rewrites {
            changed.push(rel.display().to_string());
        }
        snapshots.push((rel.to_path_buf(), existing));
    }

    // 4b. Directories this write may have to create, recorded before the apply
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

    // 5. Apply atomically.
    for change in &pending.changes {
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

    // 6. Post-check: roll the files back if the write broke the vault.
    let vault2 = load_vault(root).map_err(anyhow::Error::new)?;
    let post = check_vault(&vault2, &CheckOptions::default());
    if !post.ok {
        for (rel, orig) in snapshots {
            match orig {
                Some(bytes) => {
                    let _ = crate::paths::write_replace(root, &rel, &bytes);
                }
                None => {
                    let _ = crate::paths::remove_file(root, &rel);
                }
            }
        }
        // Then remove the directories this write created, innermost first,
        // only when they are now empty (#604). A directory that existed before
        // the write was never recorded; one that now holds another file makes
        // `remove_dir` fail and is left in place. Best effort, like the files.
        for dir in created_dirs.iter().rev() {
            let _ = std::fs::remove_dir(dir);
        }
        return Ok(WriteOutcome::CheckBlocked { report: post });
    }

    // 7. One commit. Message and trailers: opaque IDs, verbs, hashes only.
    // Proactive identity check so a missing git identity is a clean
    // E_INVALID, not git's stderr wrapped as internal_error.
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

    #[test]
    fn digests_are_deterministic_and_domain_separated() {
        let (h1, r1) = idempotency_digests("abc", "canonical");
        let (h2, r2) = idempotency_digests("abc", "canonical");
        assert_eq!((&h1, &r1), (&h2, &r2));
        let (h3, _) = idempotency_digests("abd", "canonical");
        assert_ne!(h1, h3, "different ids hash differently");
        let (_, r4) = idempotency_digests("abc", "canonical2");
        assert_ne!(r1, r4, "different content HMACs differently");
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
}
