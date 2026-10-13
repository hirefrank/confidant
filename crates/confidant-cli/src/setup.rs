//! `setup` / `agents` / `which` / `routing` / `update` support.
//!
//! Skills ship inside the binary (`embedded::SKILLS`); `setup` materializes
//! them to a versioned share dir and links each skill into agent skill dirs.
//! Modeled on network-jobs `lib/agents.sh`.

use std::path::{Path, PathBuf};

use crate::embedded::{self, materialize_all};

/// (agent id, skills dir relative to $HOME).
pub const AGENTS: &[(&str, &str)] = &[
    ("claude-code", ".claude/skills"),
    ("cursor", ".cursor/skills"),
    ("codex", ".codex/skills"),
    ("opencode", ".config/opencode/skills"),
    ("pi", ".pi/agent/skills"),
    ("gemini-cli", ".gemini/skills"),
    ("hermes-agent", ".hermes/skills"),
    ("muse", ".agents/skills"),
    ("agents", ".agents/skills"),
];

/// Marker file identifying a directory confidant copied (via `--copy` or
/// the Windows symlink fallback). Contents are the CLI version that wrote
/// it. Together with "symlink under our skills root" this is the ownership
/// rule: only owned entries are replaced or re-pointed without `--force`.
pub const MANAGED_MARKER: &str = ".confidant-managed";

pub fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot determine a home directory: set HOME (or USERPROFILE on Windows)"
            )
        })
}

pub fn agent_subpath(name: &str) -> Option<&'static str> {
    AGENTS
        .iter()
        .find(|(id, _)| *id == name)
        .map(|(_, sub)| *sub)
}

pub fn agent_dir(name: &str, home: &Path) -> Option<PathBuf> {
    agent_subpath(name).map(|sub| home.join(sub))
}

/// An agent counts as installed when its skills dir exists.
pub fn is_detected(name: &str, home: &Path) -> bool {
    agent_dir(name, home).is_some_and(|d| d.is_dir())
}

pub fn detect_agents(home: &Path) -> Vec<String> {
    AGENTS
        .iter()
        .map(|(id, _)| (*id).to_owned())
        .filter(|id| is_detected(id, home))
        .collect()
}

/// Resolve an `--agent` spec to ordered agent ids.
/// Returns (resolved, unknown_names). `auto` falls back to `claude-code`
/// when nothing is detected; unknown names are skipped, never fatal.
pub fn resolve_agents(spec: &str, home: &Path) -> (Vec<String>, Vec<String>) {
    let spec = spec.trim();
    if spec.is_empty() || spec == "auto" {
        let found = detect_agents(home);
        if found.is_empty() {
            return (vec!["claude-code".to_owned()], vec![]);
        }
        return (found, vec![]);
    }
    if spec == "all" {
        return (
            AGENTS.iter().map(|(id, _)| (*id).to_owned()).collect(),
            vec![],
        );
    }
    let mut resolved = Vec::new();
    let mut unknown = Vec::new();
    for part in spec.split(',') {
        let name = part.trim();
        if name.is_empty() {
            continue;
        }
        if agent_subpath(name).is_some() {
            if !resolved.iter().any(|r: &String| r == name) {
                resolved.push(name.to_owned());
            }
        } else {
            unknown.push(name.to_owned());
        }
    }
    (resolved, unknown)
}

pub fn confidant_home() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CONFIDANT_HOME") {
        let p = PathBuf::from(dir);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }
    Ok(home_dir()?.join(".local/share/confidant"))
}

pub fn skills_version_dir() -> anyhow::Result<PathBuf> {
    Ok(confidant_home()?
        .join("skills")
        .join(env!("CARGO_PKG_VERSION")))
}

pub fn skills_dir_override() -> Option<PathBuf> {
    std::env::var_os("CONFIDANT_SKILLS_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Materialize the embedded tree to the versioned share dir.
/// Returns the version dir. Sets `+x` on every file under any `bin/` dir
/// (top-level shared `bin/` and per-skill `bin/`s): `include_dir` stores
/// bytes only, no mode bits, and some SKILL.md files exec `*/bin/*.py`
/// directly.
pub fn materialize_current() -> anyhow::Result<PathBuf> {
    let target = skills_version_dir()?;
    materialize_all(&target)
        .map_err(|e| anyhow::anyhow!("cannot write skills to {}: {e}", target.display()))?;
    set_executable_on_bins(&target);
    Ok(target)
}

#[cfg(unix)]
fn set_executable_on_bins(root: &Path) {
    // Walk the tree; every dir named `bin` gets its files +x'd recursively.
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|s| s.to_str()) == Some("bin") {
                    set_executable_recursive(&path);
                } else {
                    stack.push(path);
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn set_executable_on_bins(_root: &Path) {}

#[cfg(unix)]
fn set_executable_recursive(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = entry.metadata() {
                let mut perms = meta.permissions();
                perms.set_mode(perms.mode() | 0o111);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    Linked,
    Repointed,
    Copied,
    AlreadyLinked,
    SkippedExists,
}

impl LinkOutcome {
    /// Stable JSON string for the outcome. Explicit mapping — never derived
    /// from `Debug`, so renaming a variant can't silently change the contract.
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkOutcome::Linked => "linked",
            LinkOutcome::Repointed => "repointed",
            LinkOutcome::Copied => "copied",
            LinkOutcome::AlreadyLinked => "already_linked",
            LinkOutcome::SkippedExists => "skipped_exists",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SkillLink {
    pub skill: String,
    pub dest: PathBuf,
    pub outcome: LinkOutcome,
}

#[derive(Debug, Clone)]
pub struct AgentSetup {
    pub name: String,
    pub dir: PathBuf,
    pub links: Vec<SkillLink>,
}

#[derive(Debug, Clone)]
pub struct SetupResult {
    pub skills_dir: PathBuf,
    pub home: PathBuf,
    pub version: String,
    pub agents: Vec<AgentSetup>,
    pub unknown_agents: Vec<String>,
    pub verbose_lines: Vec<String>,
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dest.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ty.is_symlink() {
            // Embedded materialization never creates symlinks, but a
            // `--copy` over an old symlinked tree could hit one. Resolve it.
            let target = std::fs::read_link(entry.path())?;
            let resolved = if target.is_absolute() {
                target
            } else {
                entry.path().parent().unwrap_or(src).join(target)
            };
            if resolved.is_dir() {
                copy_dir_recursive(&resolved, &to)?;
            } else {
                std::fs::copy(&resolved, &to)?;
            }
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dest)
}

#[cfg(windows)]
fn create_symlink(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(src, dest)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(src: &Path, dest: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "symlinks not supported ({} -> {})",
            src.display(),
            dest.display()
        ),
    ))
}

/// Remove a symlink without following it. On Windows, `remove_file` cannot
/// unlink a directory symlink ("Access is denied"); those need `remove_dir`.
/// (Our skills are always directories, so a bare `remove_file` silently
/// fails on every Windows re-point, leaving a stale link that breaks the
/// subsequent create and poisons the copy fallback.) Callers only pass
/// paths already checked with `is_symlink`.
fn remove_symlink(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    if path.is_dir() {
        // is_dir follows the link, so this is a directory symlink.
        return std::fs::remove_dir(path);
    }
    std::fs::remove_file(path)
}

fn write_managed_marker(dir: &Path) -> std::io::Result<()> {
    std::fs::write(dir.join(MANAGED_MARKER), env!("CARGO_PKG_VERSION"))
}

/// True if `path` resolves to somewhere under `root`. Canonicalizes what
/// exists; for dangling targets (e.g. a symlink whose target was removed)
/// falls back to a lexical normalization. Relative dangling paths can't be
/// judged reliably and count as not-under (fail closed: skip unless --force).
fn path_under(path: &Path, root: &Path) -> bool {
    let Ok(root_c) = root.canonicalize() else {
        return false;
    };
    if let Ok(p) = path.canonicalize() {
        return p.starts_with(&root_c);
    }
    if !path.is_absolute() {
        return false;
    }
    let mut norm = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                norm.pop();
            }
            std::path::Component::CurDir => {}
            c => norm.push(c.as_os_str()),
        }
    }
    norm.starts_with(&root_c)
}

/// "Confidant owns `<parent>/<id>`": the entry is a symlink whose resolved
/// target sits under `skills_root` (`confidant_home()/skills/`), or a real
/// directory carrying the `.confidant-managed` marker (written by `--copy`
/// and by the symlink-failure fallback). Only owned entries are replaced
/// or re-pointed without `--force`; `--force` is the only path that touches
/// unowned entries.
fn is_owned(dest: &Path, skills_root: &Path) -> bool {
    if let Ok(target) = std::fs::read_link(dest) {
        let resolved = if target.is_absolute() {
            target
        } else {
            dest.parent().unwrap_or(Path::new(".")).join(target)
        };
        return path_under(&resolved, skills_root);
    }
    dest.join(MANAGED_MARKER).is_file()
}

fn link_one_skill(
    _skill: &str,
    src: &Path,
    dest: &Path,
    force: bool,
    copy_mode: bool,
    skills_root: &Path,
) -> anyhow::Result<(LinkOutcome, Vec<String>)> {
    let mut lines = Vec::new();
    let owned = is_owned(dest, skills_root);
    let symlink_target = std::fs::read_link(dest).ok();

    if dest.is_symlink() {
        if !owned && !force {
            lines.push(format!(
                "skip    {} (symlink not managed by confidant; use --force to replace)",
                dest.display()
            ));
            return Ok((LinkOutcome::SkippedExists, lines));
        }
        remove_symlink(dest)
            .map_err(|e| anyhow::anyhow!("cannot remove {}: {e}", dest.display()))?;
        return install_skill(src, dest, copy_mode, symlink_target.as_deref(), &mut lines);
    }
    if dest.exists() {
        if !owned && !force {
            let kind = if dest.is_dir() { "directory" } else { "file" };
            lines.push(format!(
                "skip    {} (existing {kind} not managed by confidant; use --force to replace)",
                dest.display()
            ));
            return Ok((LinkOutcome::SkippedExists, lines));
        }
        if dest.is_dir() {
            std::fs::remove_dir_all(dest)
                .map_err(|e| anyhow::anyhow!("cannot remove {}: {e}", dest.display()))?;
        } else {
            std::fs::remove_file(dest)
                .map_err(|e| anyhow::anyhow!("cannot remove {}: {e}", dest.display()))?;
        }
    }
    install_skill(src, dest, copy_mode, symlink_target.as_deref(), &mut lines)
}

/// Write the link or copy for one skill. `old_target` is the previous
/// symlink target, if any, used to distinguish re-point from already-linked.
fn install_skill(
    src: &Path,
    dest: &Path,
    copy_mode: bool,
    old_target: Option<&Path>,
    lines: &mut Vec<String>,
) -> anyhow::Result<(LinkOutcome, Vec<String>)> {
    if copy_mode {
        copy_dir_recursive(src, dest).map_err(|e| {
            anyhow::anyhow!("cannot copy {} to {}: {e}", src.display(), dest.display())
        })?;
        write_managed_marker(dest)
            .map_err(|e| anyhow::anyhow!("cannot write marker in {}: {e}", dest.display()))?;
        lines.push(format!("copied  {}", dest.display()));
        return Ok((LinkOutcome::Copied, lines.clone()));
    }
    match create_symlink(src, dest) {
        Ok(()) => {
            let outcome = match old_target {
                Some(t) if t == src => LinkOutcome::AlreadyLinked,
                Some(_) => LinkOutcome::Repointed,
                None => LinkOutcome::Linked,
            };
            lines.push(format!("linked  {} -> {}", dest.display(), src.display()));
            Ok((outcome, lines.clone()))
        }
        Err(e) => {
            // Windows without admin/Developer Mode (or any symlink failure):
            // fall back to a copy so the install still works. The marker
            // makes the copy owned, so later updates can replace it.
            lines.push(format!(
                "warning: cannot symlink {} -> {} ({e}); copying instead",
                dest.display(),
                src.display()
            ));
            copy_dir_recursive(src, dest).map_err(|e| {
                anyhow::anyhow!("cannot copy {} to {}: {e}", src.display(), dest.display())
            })?;
            write_managed_marker(dest)
                .map_err(|e| anyhow::anyhow!("cannot write marker in {}: {e}", dest.display()))?;
            lines.push(format!("copied  {}", dest.display()));
            Ok((LinkOutcome::Copied, lines.clone()))
        }
    }
}

/// Canonicalize as much of `p` as exists: walk up to the first existing
/// ancestor, canonicalize it, then re-append the remainder. Used for the
/// overlap check, where the leaf may not exist yet.
fn canonicalize_existing_ancestor(p: &Path) -> anyhow::Result<PathBuf> {
    let mut cur = p.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match cur.canonicalize() {
            Ok(mut c) => {
                for comp in tail.into_iter().rev() {
                    c.push(comp);
                }
                return Ok(c);
            }
            Err(_) => match cur.file_name() {
                Some(f) => {
                    tail.push(f.to_owned());
                    cur.pop();
                }
                None => {
                    return Err(anyhow::anyhow!("cannot resolve {}", p.display()));
                }
            },
        }
    }
}

/// Reject a `CONFIDANT_SKILLS_DIR` override that equals, contains, or sits
/// inside the confidant home dir. Compares canonicalized real paths, not
/// basenames: an override pointing at (or inside) the install tree would
/// otherwise make `update` delete the installed skills before linking them
/// to themselves.
fn reject_home_overlap(override_dir: &Path, home: &Path) -> anyhow::Result<()> {
    let ov = canonicalize_existing_ancestor(override_dir)?;
    let h = canonicalize_existing_ancestor(home)?;
    if ov == h || ov.starts_with(&h) || h.starts_with(&ov) {
        return Err(anyhow::anyhow!(
            "CONFIDANT_SKILLS_DIR must not overlap the confidant home dir ({}): {}",
            home.display(),
            override_dir.display()
        ));
    }
    Ok(())
}

/// Version dir names under `skills_root` that some agent still links into.
///
/// Scans every detected agent's skills dir (plus the `CONFIDANT_SKILLS_DIR`
/// override when set). A symlink whose canonical target sits under
/// `skills_root/<version>/…` marks `<version>` as referenced. Copies are
/// self-contained and never reference a version dir, so they are ignored.
/// Used to keep `prune_old_versions` from deleting a version another agent
/// still uses (#195).
fn referenced_skill_versions(skills_root: &Path, home: &Path) -> std::collections::HashSet<String> {
    let mut referenced = std::collections::HashSet::new();
    let Ok(root_canon) = std::fs::canonicalize(skills_root) else {
        return referenced;
    };
    let mut dirs: Vec<PathBuf> = detect_agents(home)
        .iter()
        .filter_map(|name| agent_dir(name, home))
        .collect();
    if let Some(ov) = skills_dir_override() {
        dirs.push(ov);
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Only symlinks can reference a version dir.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_symlink() {
                continue;
            }
            // Broken link: its target is already gone, nothing to preserve.
            let Ok(target) = std::fs::canonicalize(&path) else {
                continue;
            };
            let Ok(rel) = target.strip_prefix(&root_canon) else {
                continue;
            };
            if let Some(version) = rel.components().next().and_then(|c| c.as_os_str().to_str()) {
                referenced.insert(version.to_owned());
            }
        }
    }
    referenced
}

/// Remove sibling version dirs under `skills_root` other than `current`.
/// Only version-looking dir names are touched, symlinks are never followed
/// (`symlink_metadata`), versions in `referenced` (still linked into by some
/// agent, #195) are kept, and this runs only after every link succeeded.
fn prune_old_versions(
    skills_root: &Path,
    current: &str,
    referenced: &std::collections::HashSet<String>,
) -> Vec<String> {
    fn looks_like_version(s: &str) -> bool {
        !s.is_empty()
            && s.split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    }
    let mut pruned = Vec::new();
    let Ok(entries) = std::fs::read_dir(skills_root) else {
        return pruned;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_str().unwrap_or("");
        if name_str == current || !looks_like_version(name_str) {
            continue;
        }
        // #195: never prune a version another agent still links into, even
        // when this run only targeted one agent.
        if referenced.contains(name_str) {
            continue;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            pruned.push(name_str.to_owned());
        }
    }
    pruned
}

/// Run `setup`: materialize the embedded tree, then link/copy each skill
/// into every target parent. Returns per-agent detail for human/`--json`
/// output. Unknown `--agent` names are reported, never fatal.
///
/// Ownership rule: only confidant-owned entries (symlinks under our skills
/// root, or copies carrying the managed marker) are replaced or re-pointed
/// without `--force`. `--force` is the only path that touches unowned
/// entries; `update` must not imply it.
pub fn run_setup(agent_spec: &str, force: bool, copy_mode: bool) -> anyhow::Result<SetupResult> {
    let home = home_dir()?;
    let confidant_home = confidant_home()?;
    let skills_root = confidant_home.join("skills");
    let skills_dir = materialize_current()?;
    let skill_ids = embedded::skill_ids();
    let mut verbose_lines = Vec::new();

    // Resolve target parents.
    let mut targets: Vec<(String, PathBuf)> = Vec::new();
    let mut unknown_agents = Vec::new();
    if let Some(single) = skills_dir_override() {
        reject_home_overlap(&single, &confidant_home)?;
        targets.push(("custom".to_owned(), single));
    } else {
        let (resolved, unknown) = resolve_agents(agent_spec, &home);
        unknown_agents = unknown;
        if resolved.is_empty() {
            return Err(anyhow::Error::new(
                confidant_core::error::DomainError::usage(
                    "no agent skill directories selected: pass --agent with a known agent name, 'all', or 'auto'",
                ),
            ));
        }
        for name in resolved {
            if let Some(dir) = agent_dir(&name, &home) {
                targets.push((name, dir));
            }
        }
    }

    let mut agents = Vec::new();
    let mut any_installed = false;
    for (label, parent) in targets {
        std::fs::create_dir_all(&parent)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", parent.display()))?;
        verbose_lines.push(format!("-- {label} ({})", parent.display()));
        let mut links = Vec::new();
        for skill in &skill_ids {
            let src = skills_dir.join(skill);
            let dest = parent.join(skill);
            let (outcome, mut lines) =
                link_one_skill(skill, &src, &dest, force, copy_mode, &skills_root)?;
            if !matches!(outcome, LinkOutcome::SkippedExists) {
                any_installed = true;
            }
            verbose_lines.append(&mut lines);
            links.push(SkillLink {
                skill: (*skill).to_owned(),
                dest,
                outcome,
            });
        }
        agents.push(AgentSetup {
            name: label,
            dir: parent,
            links,
        });
    }

    // Prune stale version dirs, but only after every link succeeded and at
    // least one skill was actually installed (a fully-skipped run leaves the
    // old version's links in place, so its dir must stay). Versions other
    // agents still link into are never pruned (#195).
    if any_installed {
        let referenced = referenced_skill_versions(&skills_root, &home);
        for pruned in prune_old_versions(&skills_root, env!("CARGO_PKG_VERSION"), &referenced) {
            verbose_lines.push(format!("pruned old skills version {pruned}"));
        }
    }

    Ok(SetupResult {
        skills_dir,
        home,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        agents,
        unknown_agents,
        verbose_lines,
    })
}

impl SetupResult {
    pub fn linked_count(&self) -> usize {
        self.agents
            .iter()
            .flat_map(|a| a.links.iter())
            .filter(|l| {
                matches!(
                    l.outcome,
                    LinkOutcome::Linked
                        | LinkOutcome::Repointed
                        | LinkOutcome::Copied
                        | LinkOutcome::AlreadyLinked
                )
            })
            .count()
    }

    pub fn skipped_count(&self) -> usize {
        self.agents
            .iter()
            .flat_map(|a| a.links.iter())
            .filter(|l| matches!(l.outcome, LinkOutcome::SkippedExists))
            .count()
    }

    pub fn agent_labels(&self) -> Vec<String> {
        self.agents.iter().map(|a| a.name.clone()).collect()
    }
}

/// Per-agent link health for `doctor` and `agents`.
#[derive(Debug, Clone)]
pub struct AgentHealth {
    pub name: String,
    pub dir: PathBuf,
    pub detected: bool,
    pub linked: usize,
    pub total: usize,
    /// True when the agent dir contains at least one confidant-owned entry
    /// (i.e. `setup` actually targeted it at some point).
    pub targeted: bool,
}

/// True when `dest` is linked to the current version's materialized skill:
/// a symlink resolving to `<version_dir>/<skill>`, or a managed copy whose
/// marker names the current version.
fn is_linked_to_current(dest: &Path, skill: &str) -> bool {
    let version = env!("CARGO_PKG_VERSION");
    if std::fs::read_link(dest).is_ok() {
        let Ok(version_dir) = skills_version_dir() else {
            return false;
        };
        let expected = version_dir.join(skill);
        let Ok(dest_c) = dest.canonicalize() else {
            return false;
        };
        let Ok(expected_c) = expected.canonicalize() else {
            return false;
        };
        return dest_c == expected_c;
    }
    if dest.is_dir() {
        if let Ok(marker) = std::fs::read_to_string(dest.join(MANAGED_MARKER)) {
            return marker.trim() == version;
        }
    }
    false
}

pub fn agent_health_for_dir(name: &str, dir: &Path) -> AgentHealth {
    let skill_ids = embedded::skill_ids();
    let detected = dir.is_dir();
    let mut linked = 0;
    let mut targeted = false;
    if detected {
        let Ok(skills_root) = confidant_home().map(|h| h.join("skills")) else {
            return AgentHealth {
                name: name.to_owned(),
                dir: dir.to_path_buf(),
                detected,
                linked,
                total: skill_ids.len(),
                targeted,
            };
        };
        for skill in &skill_ids {
            let dest = dir.join(skill);
            if is_owned(&dest, &skills_root) {
                targeted = true;
            }
            if is_linked_to_current(&dest, skill) {
                linked += 1;
            }
        }
    }
    AgentHealth {
        name: name.to_owned(),
        dir: dir.to_path_buf(),
        detected,
        linked,
        total: skill_ids.len(),
        targeted,
    }
}

pub fn agents_health(home: &Path) -> Vec<AgentHealth> {
    AGENTS
        .iter()
        .map(|(id, sub)| agent_health_for_dir(id, &home.join(sub)))
        .collect()
}

pub const ROUTING_SNIPPET: &str = "## Confidant\n\nLocal skill suite for the Confidant vault. Skills are self-describing, so agents normally route on their own. This snippet is only useful if you want to pin the workflow explicitly in a project's instructions.\n\n### Routing\n\n| User intent | Skill |\n|-------------|-------|\n| Pull portal events into the vault | `portal-sync` |\n| Import a transcript | `transcript-import` |\n| Import a Lightfield export | `lightfield-import` |\n| Summarize capture gaps (read-only) | `capture-gap-summary` |\n| Search via QMD (optional backend) | `qmd-search` |\n\n### Rules\n\n- Skills propose only; wait for explicit human confirmation before applying.\n- Apply through the CLI (`import --file`, `note add`, `record add`) with `--dry-run` first.\n- Never invent IDs, verbs, or dates. Bad rows are warnings + skips.\n- Run `confidant which --skills-dir` to locate the installed skills.\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_map_has_nine_entries() {
        assert_eq!(AGENTS.len(), 9);
    }

    #[test]
    fn resolve_auto_falls_back_to_claude_code() {
        let home = PathBuf::from("/nonexistent-conf exhibit");
        let (resolved, unknown) = resolve_agents("auto", &home);
        assert_eq!(resolved, vec!["claude-code".to_owned()]);
        assert!(unknown.is_empty());
    }

    #[test]
    fn resolve_all_returns_every_agent() {
        let home = PathBuf::from("/nonexistent");
        let (resolved, _) = resolve_agents("all", &home);
        assert_eq!(resolved.len(), 9);
    }

    #[test]
    fn resolve_unknown_names_are_reported() {
        let home = PathBuf::from("/nonexistent");
        let (resolved, unknown) = resolve_agents("claude-code,bogus", &home);
        assert_eq!(resolved, vec!["claude-code".to_owned()]);
        assert_eq!(unknown, vec!["bogus".to_owned()]);
    }
}
