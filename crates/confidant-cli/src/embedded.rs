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

/// Embedded pack skill texts (`pack-skills/<name>/SKILL.md` in this crate,
/// vendored from `packs/<name>/SKILL.md` at the repo root, #189). The
/// path must stay inside the crate so `cargo publish` / `cargo install`
/// can compile; workspace builds use the same tree. When packs go external
/// (#193), the external pack ships its own `SKILL.md` and this embedded
/// copy remains the fallback for compiled-in packs.
pub static PACK_SKILLS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/pack-skills");

/// Agent-facing skill text for a compiled pack (`coaching@0.1` reads
/// `coaching/SKILL.md`). `None` when the pack ships no skill text.
pub fn pack_skill_text(pack_name: &str) -> Option<&'static str> {
    let dir = pack_name.split('@').next()?;
    PACK_SKILLS
        .get_file(format!("{dir}/SKILL.md"))
        .and_then(|f| f.contents_utf8())
}

/// Agent-facing skill text for a pack in the vault's pack registry (#445):
/// compiled packs serve their embedded text; a loaded external pack serves
/// the vendored `[pack].skill` text it carries (`Pack::skill_text`, #438).
/// `None` when the pack is in neither.
pub fn pack_skill_text_from_registry(
    registry: &confidant_core::packs::PackRegistry,
    pack_name: &str,
) -> Option<&'static str> {
    registry
        .skill_text(pack_name)
        .or_else(|| pack_skill_text(pack_name))
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
        for pack in confidant_core::packs::PackRegistry::compiled().all() {
            assert!(
                pack_skill_text(pack.name()).is_some(),
                "pack {} ships no SKILL.md",
                pack.name()
            );
        }
    }

    /// Drift test (#189, generalized #345): every finding code a pack declares
    /// it can emit must be documented in its skill text ("what it means, what
    /// to do"), so the docs stay honest as rules change. Codes are read from
    /// the pack's manifest (the source of truth since #345), not the trait.
    /// Also, every `[checks]` key the manifest declares must be documented
    /// in the skill text, so manifest text and SKILL.md cannot disagree.
    #[test]
    fn pack_skills_document_all_declared_finding_codes() {
        for pack in confidant_core::packs::PackRegistry::compiled().all() {
            let manifest = confidant_core::packs::pack_manifest(pack.name())
                .unwrap_or_else(|| panic!("pack {} has no manifest", pack.name()));
            let text = pack_skill_text(pack.name())
                .unwrap_or_else(|| panic!("pack {} ships no SKILL.md", pack.name()));
            for code in &manifest.finding_codes {
                assert!(
                    text.contains(code.as_str()),
                    "pack {} can emit {code} but its SKILL.md does not document it",
                    pack.name()
                );
            }
            for check in manifest
                .checks
                .severity
                .iter()
                .map(|s| &s.key)
                .chain(manifest.checks.int.iter().map(|i| &i.key))
            {
                assert!(
                    text.contains(&format!("`{check}`")),
                    "pack {} declares [checks] key {check} but its SKILL.md does not document it",
                    pack.name()
                );
            }
        }
    }

    /// Sync test (#370): the vendored `pack-skills/<name>/SKILL.md` copies
    /// must match the repo-root `packs/<name>/SKILL.md` files. The spec and
    /// docs point people at the repo-root files, but the binary ships the
    /// vendored copies, so a drift would ship stale docs. Skips quietly
    /// when the repo root isn't present (the published crate tarball).
    #[test]
    fn vendored_pack_skills_match_repo_root() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_packs = manifest_dir.join("../../packs");
        if !repo_packs.is_dir() {
            return; // published crate tarball: no repo root to compare against
        }
        let vendored = manifest_dir.join("pack-skills");

        fn skill_pack_names(dir: &Path) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
                .filter_map(|entry| {
                    let entry = entry.unwrap_or_else(|e| panic!("dir entry: {e}"));
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let is_pack = entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                        && entry.path().join("SKILL.md").is_file();
                    is_pack.then_some(name)
                })
                .collect();
            names.sort_unstable();
            names
        }

        let repo_names = skill_pack_names(&repo_packs);
        let vendored_names = skill_pack_names(&vendored);
        assert_eq!(
            repo_names, vendored_names,
            "pack dirs with SKILL.md differ between packs/ and pack-skills/"
        );
        for name in &repo_names {
            let repo_text = std::fs::read_to_string(repo_packs.join(name).join("SKILL.md"))
                .unwrap_or_else(|e| panic!("read packs/{name}/SKILL.md: {e}"));
            let vendored_text = std::fs::read_to_string(vendored.join(name).join("SKILL.md"))
                .unwrap_or_else(|e| panic!("read pack-skills/{name}/SKILL.md: {e}"));
            assert_eq!(
                repo_text, vendored_text,
                "pack-skills/{name}/SKILL.md has drifted from \
                 packs/{name}/SKILL.md; copy the repo-root file over"
            );
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
