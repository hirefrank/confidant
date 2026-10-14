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

/// Embedded pack skill texts (`packs/<name>/SKILL.md` at the repo root,
/// #189). One file per pack name; the binary serves the version it was
/// compiled with. When packs go external (#193), the same per-pack file
/// ships inside the external pack and this embedded copy remains the
/// fallback for compiled-in packs.
pub static PACK_SKILLS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../packs");

/// Agent-facing skill text for a compiled pack (`coaching@0.1` reads
/// `coaching/SKILL.md`). `None` when the pack ships no skill text.
pub fn pack_skill_text(pack_name: &str) -> Option<&'static str> {
    let dir = pack_name.split('@').next()?;
    PACK_SKILLS
        .get_file(format!("{dir}/SKILL.md"))
        .and_then(|f| f.contents_utf8())
}

/// Combined skill text for packs in scope, in the order given: one
/// section per pack, generated at serve time from the enabled packs
/// (#189). `None` when any pack ships no skill text.
pub fn combined_pack_skill(pack_names: &[&str]) -> Option<String> {
    let mut out = String::from("# Pack skills for this vault\n\n");
    out.push_str(&format!(
        "Packs in scope: {}\n",
        if pack_names.is_empty() {
            "(none)".to_owned()
        } else {
            pack_names.join(", ")
        }
    ));
    for name in pack_names {
        let text = pack_skill_text(name)?;
        out.push_str("\n---\n\n## ");
        out.push_str(name);
        out.push_str("\n\n");
        out.push_str(text);
    }
    Some(out)
}

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

    #[test]
    fn embedded_packs_tree_has_skill_per_pack() {
        for pack in confidant_core::packs::ALL_PACKS {
            assert!(
                pack_skill_text(pack.name()).is_some(),
                "pack {} ships no SKILL.md",
                pack.name()
            );
        }
    }

    /// Drift test (#189): every finding code a pack declares it can emit
    /// must be documented in its skill text ("what it means, what to do"),
    /// so the docs stay honest as rules change.
    #[test]
    fn pack_skills_document_all_declared_finding_codes() {
        for pack in confidant_core::packs::ALL_PACKS {
            let text = pack_skill_text(pack.name())
                .unwrap_or_else(|| panic!("pack {} ships no SKILL.md", pack.name()));
            for code in pack.finding_codes() {
                assert!(
                    text.contains(code),
                    "pack {} can emit {code} but its SKILL.md does not document it",
                    pack.name()
                );
            }
        }
    }

    #[test]
    fn combined_pack_skill_lists_packs_in_scope() {
        let combined = combined_pack_skill(&["coaching@0.1"]).unwrap();
        assert!(combined.contains("Packs in scope: coaching@0.1"));
        assert!(combined.contains("## coaching@0.1"));
        // The embedded copy is the served copy: spot-check content.
        assert!(combined.contains("E_OPEN_MALFORMED"));
        assert!(combined_pack_skill(&["nope@9.9"]).is_none());
        let empty = combined_pack_skill(&[]).unwrap();
        assert!(empty.contains("Packs in scope: (none)"));
    }
}
