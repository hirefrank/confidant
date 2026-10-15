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
/// problem (the #211 "stop and ask" rule).
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

/// Returns true when `candidate` canonicalizes to a location under `dir`.
/// Anything that cannot be canonicalized (missing, broken symlink) counts as
/// outside — fail closed.
pub fn is_under_dir(dir: &Path, candidate: &Path) -> bool {
    let (Ok(dir_c), Ok(cand_c)) = (dir.canonicalize(), candidate.canonicalize()) else {
        return false;
    };
    cand_c.starts_with(dir_c)
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

/// Write the progress file with mode 0600 (plaintext-adjacent: it holds
/// commit SHAs and step keys, written next to the plaintext proposal set).
pub fn write_progress(manifest_path: &Path, progress: &TuiProgress) -> Result<()> {
    let path = progress_path(manifest_path);
    let file = ProgressFile {
        done: progress.done.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&file).context("serialize progress file")?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path)
        .and_then(|mut f| f.write_all(&bytes))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
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
        let dir = std::env::temp_dir().join("tui-proposals-test-manifest");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, r#"{"skill": "x", "records": []}"#).unwrap();
        let err = read_manifest(&path).expect_err("missing request_id must fail");
        assert!(err.contains("request_id"), "unexpected error: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_manifest_rejects_wrong_type() {
        let dir = std::env::temp_dir().join("tui-proposals-test-manifest-type");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, r#"{"skill": "x", "request_id": 42, "records": []}"#).unwrap();
        let err = read_manifest(&path).expect_err("wrong type must fail");
        assert!(err.contains("invalid type"), "unexpected error: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discover_skips_progress_files() {
        let dir = std::env::temp_dir().join("tui-proposals-test-discover");
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
}
