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

use hmac::{Hmac, Mac};
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
}

/// One file mutation inside a pending write. Paths are vault-relative.
#[derive(Clone, Debug)]
pub enum FileChange {
    /// Append lines to an existing (or new) text file.
    AppendLines { path: PathBuf, lines: Vec<String> },
    /// Replace (or create) a file with these contents.
    WriteFile { path: PathBuf, contents: String },
}

impl FileChange {
    /// Vault-relative path this change touches.
    pub fn path(&self) -> &Path {
        match self {
            FileChange::AppendLines { path, .. } => path,
            FileChange::WriteFile { path, .. } => path,
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
    /// Files applied and committed. `commit` is the full SHA.
    Applied { commit: String, files: Vec<String> },
    /// Nothing touched; the logical change is in `preview`.
    DryRun { preview: Vec<DryRunFile> },
    /// `--request-id` matched a previous identical write; `commit` is its SHA.
    Idempotent { commit: String },
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
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!(
            "git {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
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

/// True if `text` contains unresolved git merge-conflict markers.
/// `=======` alone is not a conflict (setext headings); only the
/// `<<<<<<<` / `>>>>>>>` fences fail closed (§9b item 1).
pub fn has_conflict_markers(text: &str) -> bool {
    text.lines()
        .any(|l| l.starts_with("<<<<<<<") || l.starts_with(">>>>>>>"))
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
        // 22 chars is the 128-bit floor (base64 length); ULIDs and UUIDv4s
        // clear it comfortably.
        if rid.chars().count() < 22 {
            return Err(anyhow::Error::new(
                DomainError::usage(
                    "--request-id must carry at least 128 bits of entropy (at least 22 characters)",
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
            })
            .collect();
        return Ok(WriteOutcome::DryRun { preview });
    }

    // 3. Pre-check: fail fast on an already-broken vault.
    let vault = load_vault(root).map_err(anyhow::Error::new)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        return Ok(WriteOutcome::CheckBlocked { report: pre });
    }

    // 4. Fail closed on conflict markers; snapshot for rollback.
    let mut snapshots: Vec<(PathBuf, Option<String>)> = Vec::new();
    for change in &pending.changes {
        let rel = change.path();
        let existing = std::fs::read_to_string(root.join(rel)).ok();
        if let Some(ref text) = existing {
            if has_conflict_markers(text) {
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
        snapshots.push((rel.to_path_buf(), existing));
    }

    // 5. Apply atomically.
    for change in &pending.changes {
        match change {
            FileChange::AppendLines { path, lines } => {
                let mut text = std::fs::read_to_string(root.join(path)).unwrap_or_default();
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
                        std::fs::create_dir_all(root.join(parent))
                            .map_err(|e| anyhow::anyhow!("cannot create directory: {e}"))?;
                    }
                }
                crate::paths::write_replace(root, path, contents.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e:#}", path.display()))?;
            }
        }
    }

    // 6. Post-check: roll the files back if the write broke the vault.
    let vault2 = load_vault(root).map_err(anyhow::Error::new)?;
    let post = check_vault(&vault2, &CheckOptions::default());
    if !post.ok {
        for (rel, orig) in snapshots {
            match orig {
                Some(text) => {
                    let _ = crate::paths::write_replace(root, &rel, text.as_bytes());
                }
                None => {
                    let _ = std::fs::remove_file(root.join(&rel));
                }
            }
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
    let files: Vec<String> = pending
        .changes
        .iter()
        .map(|c| c.path().display().to_string())
        .collect();
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
        assert!(has_conflict_markers("a\n<<<<<<< HEAD\nb\n"));
        assert!(has_conflict_markers(">>>>>>> branch\n"));
        assert!(!has_conflict_markers("a\n=======\nb\n"));
        assert!(!has_conflict_markers("plain text\n"));
    }
}
