//! Proposal manifest discovery and parsing.
//!
//! The TUI reads `<vault>/.confidant/proposals/*.json` directly. This is the
//! one deliberate exception to "never read the vault": proposal manifests are
//! gitignored scratch outside the vault tree, not vault records (Frank
//! approved this on 2026-10-13, #211). Manifests are plaintext PII; the TUI
//! never logs their contents and only renders dry-run output on screen.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

/// A proposal manifest written by an integration-skill proposer
/// (`skills/README.md` "The uniform workflow", step 1).
///
/// `skill` and `request_id` are required: without the skill we cannot do
/// skill-specific cleanup, and without the manifest `request_id` the ledger
/// import cannot run idempotently. Everything else has a safe default — a
/// missing `lines_file` means "no ledger step", and a missing
/// `records_blocked` fails closed (records are refused, never hand-written).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ProposalManifest {
    pub skill: String,
    pub request_id: String,
    #[serde(default)]
    pub vault: String,
    #[serde(default)]
    pub lines_file: Option<String>,
    #[serde(default)]
    pub notes_dir: Option<String>,
    #[serde(default)]
    pub records: Vec<ProposalRecord>,
    #[serde(default)]
    pub records_blocked: bool,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// One proposed record inside a manifest's `records[]`.
///
/// Records carrying `note_id` are applied with `confidant note add`; the rest
/// go through `confidant record add`. Every record is expected to carry its
/// own `request_id` (#215); a record without one is refused at plan time —
/// the TUI never mints ids.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ProposalRecord {
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub note_id: Option<String>,
    #[serde(default)]
    pub person: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub no_ai: bool,
    #[serde(default)]
    pub body_file: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// A discovered manifest file plus its parse result.
#[derive(Clone, Debug)]
pub struct DiscoveredProposal {
    pub path: PathBuf,
    pub name: String,
    pub manifest: Result<ProposalManifest, String>,
}

/// Suffix for the per-manifest progress file. Excluded from discovery so a
/// progress file is never mistaken for a proposal.
pub const PROGRESS_SUFFIX: &str = ".tui-progress.json";

/// Read and parse one manifest file. Errors are human-readable: a missing
/// field or an unexpected type stops the proposal with a message naming the
/// problem (the #211 "stop and ask" rule). Unknown fields are ignored, not
/// denied: real proposer manifests carry extra fields, so `deny_unknown_fields`
/// would break them.
pub fn read_manifest(path: &Path) -> Result<ProposalManifest, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read manifest: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid manifest JSON: {e}"))
}

/// List `*.json` files in `<vault>/.confidant/proposals/`, excluding progress
/// files. A missing proposals directory yields an empty list.
pub fn discover_proposals(vault_root: &Path) -> Vec<DiscoveredProposal> {
    let dir = vault_root.join(".confidant").join("proposals");
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.ends_with(".json") || name.ends_with(PROGRESS_SUFFIX) {
            continue;
        }
        out.push(DiscoveredProposal {
            path: path.clone(),
            name,
            manifest: read_manifest(&path),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Resolve the vault root for proposal discovery, mirroring the CLI's order:
/// explicit `--vault` override, then `CONFIDANT_VAULT`, then walking up from
/// the current directory for `confidant.toml`.
pub fn resolve_vault_root(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    if let Ok(env) = std::env::var("CONFIDANT_VAULT") {
        if !env.trim().is_empty() {
            return Some(PathBuf::from(env));
        }
    }
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("confidant.toml").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The `<manifest stem>` directory: `<proposals>/<name>/`, next to the
/// manifest. Mirrors `common.py` `proposal_notes_dir` (notes) and holds the
/// TUI's staged record scratch files under `records/`.
pub fn manifest_stem(manifest_path: &Path) -> PathBuf {
    let parent = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    match manifest_path.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => parent.join(stem),
        None => manifest_path.to_path_buf(),
    }
}

/// Path of the progress file: `<stem>.tui-progress.json` next to the manifest.
pub fn progress_path(manifest_path: &Path) -> PathBuf {
    manifest_stem(manifest_path).with_extension("tui-progress.json")
}

/// Returns true when `candidate` canonicalizes to a strict child of `dir`.
/// Anything that cannot be canonicalized (missing, broken symlink) counts as
/// outside — fail closed. `dir` itself is not "under" `dir`: a manifest path
/// equal to the proposals directory would let cleanup delete the whole
/// directory.
pub fn is_under_dir(dir: &Path, candidate: &Path) -> bool {
    let (Ok(dir_c), Ok(cand_c)) = (dir.canonicalize(), candidate.canonicalize()) else {
        return false;
    };
    cand_c != dir_c && cand_c.starts_with(dir_c)
}

/// Like `is_under_dir`, but for paths that may not exist yet — scratch files
/// and directories the TUI stages later. Canonicalize the nearest existing
/// ancestor, then re-append the missing tail lexically. A `..` in the missing
/// tail is refused (it could climb out of `dir` after the ancestor was
/// validated), and the result must still be a strict child of `dir`.
pub fn is_planned_under_dir(dir: &Path, candidate: &Path) -> bool {
    let Ok(dir_c) = dir.canonicalize() else {
        return false;
    };
    let mut ancestor: &Path = candidate;
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        // A symlink anywhere in the planned path — even a dangling one, which
        // `exists()` reports as missing — cannot be resolved lexically: its
        // target may lie outside `dir`. Fail closed rather than trust the name.
        if ancestor
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return false;
        }
        if ancestor.exists() {
            break;
        }
        match ancestor.file_name() {
            Some(name) => {
                tail.push(name);
                match ancestor.parent() {
                    Some(parent) => ancestor = parent,
                    None => return false,
                }
            }
            // `..`, `/`, or an empty path: cannot resolve lexically.
            None => return false,
        }
    }
    let Ok(mut base) = ancestor.canonicalize() else {
        return false;
    };
    // The tail holds only `file_name` components (never `..`: `file_name`
    // returns `None` for a path terminating in `..`, which fails closed
    // above), so re-appending it cannot climb out of the ancestor.
    for component in tail.iter().rev() {
        base.push(component);
    }
    base != dir_c && base.starts_with(&dir_c)
}

/// Progress of a proposal apply, persisted as `<manifest>.tui-progress.json`
/// (0600) after every applied step. Keys are step keys (`ledger`,
/// `note:<request_id>`, `record:<request_id>`); values are commit SHAs.
/// Retrying with the same request id is idempotent server-side, so resuming
/// from this file can never double-apply.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuiProgress {
    done: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct ProgressFile {
    #[serde(default)]
    done: BTreeMap<String, String>,
}

impl TuiProgress {
    pub fn is_done(&self, step_key: &str) -> bool {
        self.done.contains_key(step_key)
    }

    pub fn mark_done(&mut self, step_key: &str, commit: &str) {
        self.done.insert(step_key.to_owned(), commit.to_owned());
    }

    pub fn done_count(&self) -> usize {
        self.done.len()
    }

    pub fn commit_for(&self, step_key: &str) -> Option<&str> {
        self.done.get(step_key).map(String::as_str)
    }
}

/// Read the progress file; a missing or corrupt file yields empty progress
/// (the request ids make re-running safe).
/// Read the progress file. A missing file means a fresh proposal; a corrupt
/// file is also treated as fresh, but silently — callers that need to tell
/// the operator use [`progress_file_corrupt`], which surfaces it in-UI
/// (never `eprintln!`: that would draw over the TUI screen).
pub fn read_progress(manifest_path: &Path) -> TuiProgress {
    let path = progress_path(manifest_path);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return TuiProgress::default(),
    };
    match serde_json::from_slice::<ProgressFile>(&bytes) {
        Ok(file) => TuiProgress { done: file.done },
        Err(_) => TuiProgress::default(),
    }
}

/// True when a progress file exists but does not parse. A corrupt file could
/// make an already-applied step look pending, so the TUI asks before treating
/// the proposal as fresh instead of silently resetting.
pub fn progress_file_corrupt(manifest_path: &Path) -> bool {
    let path = progress_path(manifest_path);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<ProgressFile>(&bytes).is_err(),
        Err(_) => false,
    }
}

/// Open `path` for writing, refusing to follow a pre-planted symlink and
/// enforcing mode 0600 even when the file already exists (`OpenOptionsExt::mode`
/// only applies at creation). On unix the open uses `O_NOFOLLOW`, so a symlink
/// at `path` fails instead of redirecting the write elsewhere.
pub fn open_secure_write(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        // Refuse to follow a symlink planted at `path` before the write.
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode()` only applies when the file is created; a pre-existing file
        // keeps whatever permissions it had — enforce 0600 explicitly.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Write the progress file with mode 0600 (plaintext-adjacent: it holds
/// commit SHAs and step keys, written next to the plaintext proposal set).
pub fn write_progress(manifest_path: &Path, progress: &TuiProgress) -> Result<()> {
    let path = progress_path(manifest_path);
    let file = ProgressFile {
        done: progress.done.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&file).context("serialize progress file")?;
    use std::io::Write;
    open_secure_write(&path)
        .and_then(|mut f| f.write_all(&bytes))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Unique temp dir for tests. The old fixed names collided when test
/// binaries ran in parallel, and a stale dir from a crashed run could
/// poison the next one.
#[cfg(test)]
pub fn test_temp_dir(name: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    std::env::temp_dir().join(format!("{name}-{}-{n}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_path_replaces_json_extension() {
        let manifest = Path::new("/vault/.confidant/proposals/lightfield-20261015T120000Z.json");
        assert_eq!(
            progress_path(manifest),
            Path::new("/vault/.confidant/proposals/lightfield-20261015T120000Z.tui-progress.json")
        );
    }

    #[test]
    fn manifest_stem_strips_extension() {
        let manifest = Path::new("/vault/.confidant/proposals/lightfield-abc.json");
        assert_eq!(
            manifest_stem(manifest),
            Path::new("/vault/.confidant/proposals/lightfield-abc")
        );
    }

    #[test]
    fn read_manifest_rejects_missing_request_id() {
        let dir = test_temp_dir("tui-proposals-test-manifest");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, r#"{"skill": "x", "records": []}"#).unwrap();
        let err = read_manifest(&path).expect_err("missing request_id must fail");
        assert!(err.contains("request_id"), "unexpected error: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_manifest_rejects_wrong_type() {
        let dir = test_temp_dir("tui-proposals-test-manifest-type");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, r#"{"skill": "x", "request_id": 42, "records": []}"#).unwrap();
        let err = read_manifest(&path).expect_err("wrong type must fail");
        assert!(err.contains("invalid type"), "unexpected error: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discover_skips_progress_files() {
        let dir = test_temp_dir("tui-proposals-test-discover");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        std::fs::write(
            proposals.join("a.json"),
            r#"{"skill": "s", "request_id": "01AAAAAAAAAAAAAAAAAAAAAAAA", "records": []}"#,
        )
        .unwrap();
        std::fs::write(proposals.join("a.tui-progress.json"), r#"{"done": {}}"#).unwrap();
        std::fs::write(proposals.join("notes.txt"), "not json").unwrap();
        let found = discover_proposals(&dir);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "a.json");
        assert!(found[0].manifest.is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn planned_under_dir_accepts_missing_scratch() {
        let dir = test_temp_dir("tui-proposals-test-planned");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        // The stem dir doesn't exist yet (staged later at apply time).
        let scratch = proposals.join("m").join("records").join("000.md");
        assert!(!scratch.exists());
        assert!(is_planned_under_dir(&proposals, &scratch));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn planned_under_dir_refuses_dotdot_escape() {
        let dir = test_temp_dir("tui-proposals-test-planned-escape");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        // Climbs out of proposals/ entirely: refused.
        let evil = proposals.join("..").join("evil.md");
        assert!(!is_planned_under_dir(&proposals, &evil));
        // A `..` through a not-yet-existing component can't be resolved, so
        // it fails closed even though it would land inside proposals/.
        let unresolvable = proposals.join("m").join("..").join("evil.md");
        assert!(!unresolvable.exists());
        assert!(!is_planned_under_dir(&proposals, &unresolvable));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn planned_under_dir_refuses_outside_and_self() {
        let dir = test_temp_dir("tui-proposals-test-planned-self");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        assert!(!is_planned_under_dir(&proposals, Path::new("/etc/passwd")));
        assert!(!is_planned_under_dir(&proposals, &proposals));
        assert!(!is_under_dir(&proposals, &proposals));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn planned_under_dir_refuses_dangling_symlink() {
        use std::os::unix::fs::symlink;
        let dir = test_temp_dir("tui-proposals-test-planned-dangling");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        // A dangling symlink: `exists()` is false, so the old walk treated it
        // as a not-yet-created file and trusted the name. Its target may lie
        // anywhere, so it must fail closed.
        let dangling = proposals.join("evil.md");
        symlink("/nonexistent-target-9f3a", &dangling).unwrap();
        assert!(!dangling.exists());
        assert!(!is_planned_under_dir(&proposals, &dangling));
        // Same for a symlink that resolves, but outside proposals/.
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, "x").unwrap();
        let link_out = proposals.join("link.md");
        symlink(&outside, &link_out).unwrap();
        assert!(!is_planned_under_dir(&proposals, &link_out));
        assert!(!is_under_dir(&proposals, &link_out));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn open_secure_write_refuses_symlink_and_enforces_0600() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = test_temp_dir("tui-proposals-test-secure-write");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.txt");
        // A pre-planted symlink at the write path: the open must fail, not
        // follow it.
        let link = dir.join("link.txt");
        symlink(&target, &link).unwrap();
        assert!(open_secure_write(&link).is_err());
        assert!(!target.exists(), "write must not follow the symlink");
        // A pre-existing file with wide permissions gets 0600 enforced.
        let wide = dir.join("wide.txt");
        std::fs::write(&wide, "old").unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).unwrap();
        open_secure_write(&wide).unwrap();
        let mode = std::fs::metadata(&wide).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A fresh file is created 0600.
        let fresh = dir.join("fresh.txt");
        open_secure_write(&fresh).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn progress_file_corrupt_detected() {
        let dir = test_temp_dir("tui-proposals-test-progress-corrupt");
        let manifest = dir.join("m.json");
        std::fs::create_dir_all(&dir).unwrap();
        // No file: not corrupt, just fresh.
        assert!(!progress_file_corrupt(&manifest));
        // Valid file: not corrupt.
        std::fs::write(dir.join("m.tui-progress.json"), r#"{"done": {}}"#).unwrap();
        assert!(!progress_file_corrupt(&manifest));
        // Garbage: corrupt.
        std::fs::write(dir.join("m.tui-progress.json"), b"\xff\xfe{{{not json").unwrap();
        assert!(progress_file_corrupt(&manifest));
        // Empty: corrupt.
        std::fs::write(dir.join("m.tui-progress.json"), b"").unwrap();
        assert!(progress_file_corrupt(&manifest));
        // read_progress still treats it as fresh (the caller surfaces it in-UI).
        assert_eq!(read_progress(&manifest), TuiProgress::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
