//! Embedded skills tree (`crates/confidant-cli/skills/`).
//!
//! The skills ship inside the binary via `include_dir!` so `cargo install`
//! and the cargo-dist release builds carry the same tree. `setup`
//! materializes this tree to a versioned share dir and links it into agent
//! skill dirs.

use include_dir::{include_dir, Dir};
use std::path::Path;

/// The embedded skills tree. Top-level entries are `bin/`, one dir per
/// skill, and `README.md`. Skill ids are the subdirectories containing a
/// `SKILL.md`.
pub static SKILLS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/skills");

/// Skill ids: subdirectories of the embedded tree containing a `SKILL.md`.
pub fn skill_ids() -> Vec<&'static str> {
    // NOTE: `Dir::get_file` matches on the entry path relative to the
    // *include root* (e.g. `portal-sync/SKILL.md`), not relative to the
    // subdirectory, so the marker must be the full joined path.
    let mut ids: Vec<&'static str> = SKILLS
        .dirs()
        .filter(|d| SKILLS.get_file(d.path().join("SKILL.md")).is_some())
        .map(|d| d.path().file_name().and_then(|s| s.to_str()).unwrap_or(""))
        .filter(|s| !s.is_empty())
        .collect();
    ids.sort_unstable();
    ids
}

/// Recursively materialize `dir` under `root`, overwriting files.
/// `root` is the tree root; file paths from `include_dir` are already
/// relative to it (e.g. `portal-sync/bin/portal-sync.py`).
///
/// Build junk is skipped on the way out: `include_dir!` embeds whatever is
/// in the working tree at compile time, so a local `__pycache__` (gitignored
/// but present) would otherwise be compiled into the binary and written to
/// every install.
fn extract_dir(dir: &Dir<'static>, root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join(dir.path()))?;
    for f in dir.files() {
        let rel = f.path();
        if rel.components().any(|c| c.as_os_str() == "__pycache__") {
            continue;
        }
        if let Some(name) = rel.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".pyc") || name.ends_with(".pyo") {
                continue;
            }
        }
        let dest = root.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, f.contents())?;
    }
    for sub in dir.dirs() {
        if sub.path().file_name().and_then(|s| s.to_str()) == Some("__pycache__") {
            continue;
        }
        extract_dir(sub, root)?;
    }
    Ok(())
}

/// Materialize the whole embedded tree under `target`.
pub fn materialize_all(target: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(target)?;
    extract_dir(&SKILLS, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_tree_has_expected_skills() {
        let ids = skill_ids();
        assert_eq!(
            ids,
            vec![
                "capture-gap-summary",
                "lightfield-import",
                "portal-sync",
                "qmd-search",
                "transcript-import",
            ]
        );
        assert!(SKILLS.get_dir("bin").is_some());
    }
}
