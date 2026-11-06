//! `setup` / `agents` / `which` / `routing` contract tests.
//!
//! All data is fake (tempdirs only) and no test touches the network.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

struct Env {
    _home: tempfile::TempDir,
    _share: tempfile::TempDir,
    _skills: tempfile::TempDir,
    home: String,
    share: String,
    skills: String,
}

fn fresh_env() -> Env {
    let home = tempfile::tempdir().unwrap();
    let share = tempfile::tempdir().unwrap();
    let skills = tempfile::tempdir().unwrap();
    Env {
        home: home.path().to_str().unwrap().to_owned(),
        share: share.path().to_str().unwrap().to_owned(),
        skills: skills.path().to_str().unwrap().to_owned(),
        _home: home,
        _share: share,
        _skills: skills,
    }
}

fn run(args: &[&str], env: &Env, extra: &[(&str, &str)]) -> (bool, Value, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .arg("--no-input")
        .env("HOME", &env.home)
        .env("XDG_CONFIG_HOME", PathBuf::from(&env.home).join(".config"))
        .env("CONFIDANT_HOME", &env.share)
        .env("CONFIDANT_SKILLS_DIR", &env.skills);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let value: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| {
        panic!(
            "stdout is not JSON for {args:?}: status={} stdout={stdout:?} stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        )
    });
    (out.status.success(), value, stdout)
}

fn skill_ids() -> Vec<&'static str> {
    vec!["confidant", "pack-author", "qmd-search", "report-a-problem"]
}

#[test]
fn setup_links_all_skills_as_symlinks() {
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert_eq!(v["linked"], 4, "{v}");
    assert_eq!(v["skipped"], 0, "{v}");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    for id in skill_ids() {
        let dest = PathBuf::from(env.skills.clone()).join(id);
        assert!(
            dest.join("SKILL.md").exists(),
            "missing SKILL.md for {id}: {v}"
        );
        assert!(
            dest.is_symlink(),
            "{id} should be a symlink by default: {v}"
        );
    }
    // The qmd helper materialized and executable.
    let qmd = PathBuf::from(v["skills_dir"].as_str().unwrap())
        .join("qmd-search")
        .join("bin")
        .join("qmd-query.py");
    assert!(qmd.exists(), "{v}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&qmd).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "qmd-query.py should be +x: {v}");
    }
}

#[test]
fn setup_copy_mode_copies_instead() {
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--copy", "--json"], &env, &[]);
    assert!(ok, "{v}");
    for id in skill_ids() {
        let dest = PathBuf::from(env.skills.clone()).join(id);
        assert!(dest.join("SKILL.md").exists(), "{v}");
        assert!(!dest.is_symlink(), "{id} should be a real dir with --copy");
    }
}

#[test]
fn setup_force_replaces_existing_dirs() {
    let env = fresh_env();
    // Pre-create a real dir where a skill link will go.
    let stale = PathBuf::from(env.skills.clone()).join("pack-author");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("stale.txt"), "old install").unwrap();

    // Without --force the existing dir is skipped.
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert_eq!(v["skipped"], 1, "{v}");
    assert!(stale.join("stale.txt").exists());

    // With --force it becomes a symlink to the versioned tree.
    let (ok, v, _) = run(&["setup", "--agent", "all", "--force", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert_eq!(v["skipped"], 0, "{v}");
    assert!(stale.is_symlink(), "{v}");
}

#[test]
fn setup_no_known_agents_is_usage_error() {
    // Without CONFIDANT_SKILLS_DIR (which would override --agent), an
    // unknown --agent name is reported in unknown_agents and skipped while
    // the known agent still links.
    let env = fresh_env();
    let mut cmd = Command::new(bin());
    cmd.args(["setup", "--agent", "bogus-agent", "--json", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share)
        .env_remove("CONFIDANT_SKILLS_DIR");
    let out = cmd.output().unwrap();
    // No known agents selected at all: usage error (exit 2), not a crash.
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn setup_update_never_touches_unowned_dirs() {
    // High 1: a user's own (non-confidant) dir must survive both `setup`
    // and `update`; only an explicit `--force` may replace it.
    let env = fresh_env();
    let mine = PathBuf::from(env.skills.clone()).join("pack-author");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::write(mine.join("my-notes.md"), "my own skill").unwrap();

    // Plain setup skips it.
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert!(
        mine.join("my-notes.md").exists(),
        "user dir was touched: {v}"
    );

    // `update` must not imply --force: the dir survives.
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(ok, "{v}");
    assert!(
        mine.join("my-notes.md").exists(),
        "update deleted a user dir: {v}"
    );
    assert!(!mine.is_symlink(), "update re-pointed a user dir: {v}");

    // Explicit --force is the only path that replaces it.
    let (ok, v, _) = run(&["setup", "--agent", "all", "--force", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert!(mine.is_symlink(), "force should replace: {v}");
}

#[test]
fn setup_prunes_stale_confidant_entries_and_keeps_unowned() {
    // A previous binary installed `old-example-skill`; this binary no longer
    // ships it. setup/update must remove the confidant-owned link or copy,
    // report it, and leave a user's own directory alone.
    let env = fresh_env();
    let skills = PathBuf::from(env.skills.clone());
    let skills_root = PathBuf::from(env.share.clone()).join("skills");

    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");

    // A stale link into an old version dir, exactly as an older setup left it.
    let old_version = skills_root.join("0.0.0");
    let old_skill = old_version.join("old-example-skill");
    std::fs::create_dir_all(&old_skill).unwrap();
    std::fs::write(old_skill.join("SKILL.md"), "# old\n").unwrap();
    let stale_link = skills.join("old-example-skill");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&old_skill, &stale_link).unwrap();

    // A stale managed copy (marker written by `setup --copy`).
    let stale_copy = skills.join("old-copied-skill");
    std::fs::create_dir_all(&stale_copy).unwrap();
    std::fs::write(stale_copy.join("SKILL.md"), "# old copy\n").unwrap();
    std::fs::write(stale_copy.join(".confidant-managed"), "0.0.0").unwrap();

    // A user's own directory with a stale-looking name must survive.
    let mine = skills.join("my-own-skill");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::write(mine.join("notes.md"), "mine\n").unwrap();

    // Dry run reports the removals and writes nothing.
    let (ok, v, _) = run(
        &["setup", "--agent", "all", "--dry-run", "--json"],
        &env,
        &[],
    );
    assert!(ok, "{v}");
    let removed = v["removed_stale"].as_array().unwrap();
    assert!(
        removed
            .iter()
            .any(|p| p.as_str().unwrap().ends_with("old-example-skill")),
        "stale link not reported: {v}"
    );
    assert!(
        removed
            .iter()
            .any(|p| p.as_str().unwrap().ends_with("old-copied-skill")),
        "stale copy not reported: {v}"
    );
    #[cfg(unix)]
    assert!(stale_link.is_symlink(), "dry run removed the link");
    assert!(stale_copy.exists(), "dry run removed the copy");

    // The real run removes both, then prunes the now-unreferenced version.
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    #[cfg(unix)]
    assert!(
        std::fs::symlink_metadata(&stale_link).is_err(),
        "stale link survived: {v}"
    );
    assert!(!stale_copy.exists(), "stale copy survived: {v}");
    assert!(
        !old_version.exists(),
        "unreferenced version not pruned: {v}"
    );
    assert!(mine.join("notes.md").exists(), "user dir was removed: {v}");
    assert!(skills.join("pack-author").is_symlink(), "{v}");
    assert!(skills.join("qmd-search").is_symlink(), "{v}");
}

#[test]
fn setup_preserves_foreign_symlinks() {
    // High 2: a symlink pointing outside our skills root is not owned;
    // setup skips it, --force re-points it.
    let env = fresh_env();
    let foreign_target = PathBuf::from(env.home.clone()).join("foreign-skills");
    std::fs::create_dir_all(foreign_target.join("pack-author")).unwrap();
    let dest = PathBuf::from(env.skills.clone()).join("pack-author");
    std::os::unix::fs::symlink(foreign_target.join("pack-author"), &dest).unwrap();

    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert_eq!(
        std::fs::read_link(&dest).unwrap(),
        foreign_target.join("pack-author"),
        "foreign symlink was re-pointed: {v}"
    );

    let (ok, v, _) = run(&["setup", "--agent", "all", "--force", "--json"], &env, &[]);
    assert!(ok, "{v}");
    let target = std::fs::read_link(&dest).unwrap();
    assert!(
        target.to_string_lossy().contains(env!("CARGO_PKG_VERSION")),
        "force should re-point at the version dir: {target:?} {v}"
    );
}

#[test]
fn setup_rejects_skills_dir_overlapping_install_tree() {
    // High 3: CONFIDANT_SKILLS_DIR pointing at (or inside) the install tree
    // is rejected before anything is deleted.
    let env = fresh_env();
    // Materialize first so the version dir exists.
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    let version_dir = PathBuf::from(v["skills_dir"].as_str().unwrap());
    assert!(version_dir.join("pack-author").exists());

    // Point the override at the version dir itself.
    let mut cmd = Command::new(bin());
    cmd.args(["setup", "--agent", "all", "--json", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share)
        .env("CONFIDANT_SKILLS_DIR", &version_dir);
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "overlap must be rejected");
    // JSON errors go to stdout as an envelope.
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("overlap"), "unexpected error: {stdout}");
    // Nothing was deleted: the installed tree is intact.
    assert!(
        version_dir.join("pack-author").join("SKILL.md").exists(),
        "installed skills were deleted!"
    );
}

#[test]
fn setup_copy_writes_managed_marker_and_update_replaces_it() {
    // A `--copy` install is owned (marker file); `update` may replace it.
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--copy", "--json"], &env, &[]);
    assert!(ok, "{v}");
    let dest = PathBuf::from(env.skills.clone()).join("pack-author");
    let marker = dest.join(".confidant-managed");
    assert!(marker.is_file(), "copy must write the marker: {v}");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        env!("CARGO_PKG_VERSION")
    );

    // update replaces the owned copy. `update` has no --copy flag, so the
    // copy becomes a symlink to the current version (with a copy fallback
    // if symlinking fails); the point is the owned entry is refreshed,
    // not skipped.
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(ok, "{v}");
    assert!(
        dest.is_symlink(),
        "update should re-point the owned copy: {v}"
    );
    let target = std::fs::read_link(&dest).unwrap();
    assert!(
        target.to_string_lossy().contains(env!("CARGO_PKG_VERSION")),
        "re-pointed at the version dir: {target:?} {v}"
    );
}

#[test]
fn setup_marks_all_bin_dirs_executable() {
    // High 5: every `*/bin/*` is +x, not just the top-level bin/.
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let version_dir = PathBuf::from(v["skills_dir"].as_str().unwrap());
        for skill in skill_ids() {
            let bin = version_dir.join(skill).join("bin");
            // `pack-author` is text-only, so only skills with a bin/ dir
            // have executables to check.
            let Ok(entries) = std::fs::read_dir(&bin) else {
                continue;
            };
            for entry in entries.flatten() {
                let mode = entry.metadata().unwrap().permissions().mode();
                assert!(mode & 0o111 != 0, "{:?} should be +x: {v}", entry.path());
            }
        }
        // The specific file Firstmate flagged.
        let qmd = version_dir
            .join("qmd-search")
            .join("bin")
            .join("qmd-query.py");
        let mode = std::fs::metadata(&qmd).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "qmd-query.py should be +x: {v}");
    }
}

#[test]
fn setup_prunes_old_version_dirs() {
    // Medium 8: stale sibling version dirs are pruned after a successful
    // install; non-version dirs and symlinks are left alone.
    let env = fresh_env();
    let skills_root = PathBuf::from(env.share.clone()).join("skills");
    std::fs::create_dir_all(skills_root.join("0.0.0").join("pack-author")).unwrap();
    std::fs::create_dir_all(skills_root.join("notes")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(skills_root.join("0.0.0"), skills_root.join("0.0.1")).unwrap();

    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert!(
        !skills_root.join("0.0.0").exists(),
        "stale version dir should be pruned: {v}"
    );
    assert!(
        skills_root.join("notes").exists(),
        "non-version dir must be kept: {v}"
    );
    #[cfg(unix)]
    assert!(
        skills_root.join("0.0.1").is_symlink(),
        "symlinks must never be followed/deleted: {v}"
    );
    // Current version untouched.
    assert!(skills_root.join(env!("CARGO_PKG_VERSION")).exists(), "{v}");
}

#[test]
#[cfg(unix)]
fn setup_per_agent_run_keeps_versions_other_agents_link_to() {
    // #195: `setup --agent cursor` must not prune a version dir that another
    // detected agent (claude-code) still links into. Without the fix, the
    // prune below deletes 0.0.0 and claude-code's link dangles.
    let env = fresh_env();
    let skills_root = PathBuf::from(env.share.clone()).join("skills");

    // Fake an old version dir with one skill, as a previous install left it.
    let old_skill = skills_root.join("0.0.0").join("pack-author");
    std::fs::create_dir_all(&old_skill).unwrap();
    std::fs::write(old_skill.join("SKILL.md"), "# pack-author\n").unwrap();

    // claude-code links into the old version (as a previous
    // `setup --agent claude-code` from the old binary would have left it).
    let claude_dir = PathBuf::from(env.home.clone()).join(".claude/skills");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::os::unix::fs::symlink(&old_skill, claude_dir.join("pack-author")).unwrap();

    // Per-agent setup without the skills-dir override (which would bypass
    // agent dirs entirely).
    let mut cmd = Command::new(bin());
    cmd.args(["setup", "--agent", "cursor", "--json", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share)
        .env_remove("CONFIDANT_SKILLS_DIR");
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{out:?}"));

    // The old version dir survives and claude-code's link still resolves.
    assert!(
        skills_root.join("0.0.0").exists(),
        "pruned a version claude-code still links into: {v}"
    );
    assert!(
        claude_dir.join("pack-author").join("SKILL.md").exists(),
        "claude-code's link is broken: {v}"
    );
    // Cursor got the current version.
    assert!(
        PathBuf::from(env.home.clone())
            .join(".cursor/skills/pack-author")
            .is_symlink(),
        "cursor was not linked: {v}"
    );
}

#[test]
fn update_json_reports_behind_without_relinking() {
    // Medium 10: the JSON carries `behind`; tested via the offline path
    // (unknown => behind is null, and relinking still happens).
    let env = fresh_env();
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(ok, "{v}");
    assert!(v["update"]["behind"].is_null(), "{v}");
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_behind_relinks_nothing() {
    // Medium 10: when the binary is behind the latest release, `update`
    // re-links nothing and prints the upgrade command instead.
    // Needs `test-overrides` (CI's --all-features) for
    // CONFIDANT_TEST_RELEASES_URL; without it the URL is unroutable and the
    // test would see "unknown" instead of "behind".
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = serde_json::json!({"tag_name": "v999.0.0"}).to_string();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let env = fresh_env();
    // A pre-existing user dir proves nothing was relinked: with behind=true
    // the run must not touch anything.
    let mine = PathBuf::from(env.skills.clone()).join("pack-author");
    std::fs::create_dir_all(&mine).unwrap();

    let (ok, v, out) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[(
            "CONFIDANT_TEST_RELEASES_URL",
            &format!("http://127.0.0.1:{port}/"),
        )],
    );
    assert!(ok, "{v}");
    assert_eq!(v["update"]["behind"], true, "{v}");
    assert_eq!(v["update"]["latest"], "v999.0.0", "{v}");
    // Nothing relinked: the user dir is untouched and no version dir exists.
    assert!(mine.is_dir() && !mine.is_symlink(), "{v}");
    assert!(
        !PathBuf::from(env.share.clone()).join("skills").exists(),
        "update relinked while behind: {v} {out}"
    );
}

#[test]
fn setup_json_contract_has_resolved_paths() {
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert!(v["skills_dir"]
        .as_str()
        .unwrap()
        .contains(env!("CARGO_PKG_VERSION")));
    assert_eq!(v["ok"], true);
    assert!(v["schema_version"].is_string());
    assert!(v.get("vault").is_some());
}

#[test]
fn agents_json_lists_nine_agents() {
    let env = fresh_env();
    let mut cmd = Command::new(bin());
    cmd.args(["agents", "--json", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share);
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let agents = v["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 9, "{v}");
    assert!(agents.iter().any(|a| a["name"] == "claude-code"));
    assert!(agents.iter().any(|a| a["name"] == "opencode"));
}

#[test]
fn which_json_reports_versioned_skills_dir() {
    let env = fresh_env();
    let mut cmd = Command::new(bin());
    cmd.args(["which", "--json", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share);
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["skills_dir"]
        .as_str()
        .unwrap()
        .contains(env!("CARGO_PKG_VERSION")));
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn which_skills_dir_flag_prints_bare_path() {
    let env = fresh_env();
    let mut cmd = Command::new(bin());
    cmd.args(["which", "--skills-dir", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share);
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    assert!(stdout.trim().contains(env!("CARGO_PKG_VERSION")));
}

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// Run against a HOME with no `CONFIDANT_SKILLS_DIR` override, so setup
/// targets real agent dirs and installs instruction files.
fn run_home(
    args: &[&str],
    home: &str,
    share: &str,
    extra: &[(&str, &str)],
) -> (bool, Value, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .arg("--no-input")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", PathBuf::from(home).join(".config"))
        .env("CONFIDANT_HOME", share)
        .env_remove("CONFIDANT_SKILLS_DIR")
        .env_remove("CONFIDANT_VAULT");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let value: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| {
        panic!(
            "stdout is not JSON for {args:?}: status={} stdout={stdout:?} stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        )
    });
    (out.status.success(), value, stdout)
}

#[test]
fn routing_prints_system_of_record_rule() {
    let env = fresh_env();
    let demo = demo();
    let (ok, v, _) = run(
        &["routing", "--vault", demo.to_str().unwrap(), "--json"],
        &env,
        &[],
    );
    assert!(ok, "{v}");
    let snippet = v["snippet"].as_str().expect("snippet missing");
    assert!(
        snippet.contains("system of record for relationship memory"),
        "{snippet}"
    );
    let demo = demo.canonicalize().unwrap();
    assert!(snippet.contains(&demo.display().to_string()), "{snippet}");
    assert!(snippet.contains("confidant resolve"), "{snippet}");
    assert!(snippet.contains("confidant context"), "{snippet}");
    assert!(snippet.contains("confidant find"), "{snippet}");
    assert!(snippet.contains("no-ai"), "{snippet}");
    assert!(snippet.contains("--dry-run"), "{snippet}");
    assert!(snippet.contains("unreachable"), "{snippet}");
    // The old two-skill routing table claimed agents self-route; that
    // assumption is exactly what #727 rejects.
    assert!(!snippet.contains("self-describing"), "{snippet}");
}

#[test]
fn setup_installs_system_of_record_rule_in_agent_memory() {
    let env = fresh_env();
    let demo = demo();
    let (ok, v, _) = run_home(
        &[
            "setup",
            "--agent",
            "claude-code",
            "--json",
            "--vault",
            demo.to_str().unwrap(),
        ],
        &env.home,
        &env.share,
        &[],
    );
    assert!(ok, "{v}");
    let instructions = &v["instructions"];
    assert_eq!(instructions["skipped"], false, "{v}");
    let targets = instructions["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 1, "{v}");
    let path = PathBuf::from(targets[0]["path"].as_str().unwrap());
    assert_eq!(
        path,
        PathBuf::from(&env.home).join(".claude/CLAUDE.md"),
        "{v}"
    );
    assert_eq!(targets[0]["outcome"], "written", "{v}");
    let text = instructions["text"].as_str().unwrap();
    let demo = demo.canonicalize().unwrap();
    assert!(text.contains(&demo.display().to_string()), "{text}");
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("<!-- confidant:system-of-record:begin -->"));
    assert!(written.contains("<!-- confidant:system-of-record:end -->"));
    assert!(written.contains(&text.trim_end().to_owned()), "{written}");
    assert!(written.contains("no-ai"), "{written}");
}

#[test]
fn setup_instructions_are_idempotent_and_preserve_user_text() {
    let env = fresh_env();
    let demo = demo();
    let path = PathBuf::from(&env.home).join(".claude/CLAUDE.md");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "# My own notes\n\nKeep this line.\n").unwrap();

    for expected in ["written", "unchanged"] {
        let (ok, v, _) = run_home(
            &[
                "setup",
                "--agent",
                "claude-code",
                "--json",
                "--vault",
                demo.to_str().unwrap(),
            ],
            &env.home,
            &env.share,
            &[],
        );
        assert!(ok, "{v}");
        assert_eq!(v["instructions"]["targets"][0]["outcome"], expected, "{v}");
    }
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("# My own notes"), "{written}");
    assert!(written.contains("Keep this line."), "{written}");
    assert_eq!(
        written
            .matches("<!-- confidant:system-of-record:begin -->")
            .count(),
        1,
        "the marked block must not duplicate: {written}"
    );
}

#[test]
fn setup_dry_run_writes_no_instruction_file() {
    let env = fresh_env();
    let (ok, v, _) = run_home(
        &[
            "setup",
            "--agent",
            "claude-code",
            "--dry-run",
            "--json",
            "--vault",
            demo().to_str().unwrap(),
        ],
        &env.home,
        &env.share,
        &[],
    );
    assert!(ok, "{v}");
    assert_eq!(
        v["instructions"]["targets"][0]["outcome"], "would_write",
        "{v}"
    );
    assert!(
        !PathBuf::from(&env.home).join(".claude/CLAUDE.md").exists(),
        "dry run wrote an instruction file: {v}"
    );
}

#[test]
fn setup_no_instructions_skips_agent_memory() {
    let env = fresh_env();
    let (ok, v, _) = run_home(
        &[
            "setup",
            "--agent",
            "claude-code",
            "--no-instructions",
            "--json",
            "--vault",
            demo().to_str().unwrap(),
        ],
        &env.home,
        &env.share,
        &[],
    );
    assert!(ok, "{v}");
    assert_eq!(v["instructions"]["skipped"], true, "{v}");
    assert!(v["instructions"]["targets"].as_array().unwrap().is_empty());
    assert!(
        !PathBuf::from(&env.home).join(".claude/CLAUDE.md").exists(),
        "--no-instructions still wrote a file: {v}"
    );
}

#[test]
fn status_reports_readiness_and_completion_brief() {
    let env = fresh_env();
    let vault = PathBuf::from(&env.home).join("vault");
    let (ok, v, _) = run_home(
        &[
            "init",
            "--create",
            "--json",
            "--vault",
            vault.to_str().unwrap(),
        ],
        &env.home,
        &env.share,
        &[],
    );
    assert!(ok, "{v}");
    let (ok, v, _) = run_home(
        &[
            "setup",
            "--agent",
            "claude-code",
            "--json",
            "--vault",
            vault.to_str().unwrap(),
        ],
        &env.home,
        &env.share,
        &[],
    );
    assert!(ok, "{v}");
    let (ok, v, _) = run_home(
        &["status", "--json", "--vault", vault.to_str().unwrap()],
        &env.home,
        &env.share,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(ok, "{v}");
    let summary = &v["readiness"]["summary"];
    assert_eq!(summary["ready"], true, "{v}");
    let ids: Vec<&str> = v["readiness"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for expected in [
        "cli-staleness",
        "tui-version",
        "vault-discovery",
        "vault-access",
        "git-repo",
        "git-remote",
        "local-commits",
        "skills-links",
        "system-of-record",
        "qmd-search",
    ] {
        assert!(ids.contains(&expected), "missing {expected}: {v}");
    }
    let sections: Vec<&str> = v["brief"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["key"].as_str().unwrap())
        .collect();
    for expected in [
        "vault",
        "machine",
        "fleet",
        "perimeter",
        "sync",
        "search",
        "standing-orders",
        "discipline",
    ] {
        assert!(sections.contains(&expected), "missing {expected}: {v}");
    }
    let routines = v["brief"]["routines"].as_array().unwrap();
    assert!(
        (3..=5).contains(&routines.len()),
        "expected 3-5 routines, got {}: {v}",
        routines.len()
    );
    let perimeter = serde_json::to_string(&v["brief"]["sections"]).unwrap();
    assert!(perimeter.contains("no application-level encryption"), "{v}");
    assert!(perimeter.contains("does not verify"), "{v}");
    let standing = serde_json::to_string(&v["brief"]["sections"]).unwrap();
    assert!(standing.contains(".claude/CLAUDE.md"), "{v}");
}

#[test]
fn status_flags_standing_orders_pointing_at_another_vault() {
    let env = fresh_env();
    let first = PathBuf::from(&env.home).join("first-vault");
    let second = PathBuf::from(&env.home).join("second-vault");
    for vault in [&first, &second] {
        let (ok, v, _) = run_home(
            &[
                "init",
                "--create",
                "--json",
                "--vault",
                vault.to_str().unwrap(),
            ],
            &env.home,
            &env.share,
            &[],
        );
        assert!(ok, "{v}");
    }
    let (ok, v, _) = run_home(
        &[
            "setup",
            "--agent",
            "claude-code",
            "--json",
            "--vault",
            first.to_str().unwrap(),
        ],
        &env.home,
        &env.share,
        &[],
    );
    assert!(ok, "{v}");
    let (ok, v, _) = run_home(
        &["status", "--json", "--vault", second.to_str().unwrap()],
        &env.home,
        &env.share,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(!ok, "a stale pointer must not report ready: {v}");
    let check = v["readiness"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "system-of-record")
        .expect("system-of-record missing");
    assert_eq!(check["status"], "warning", "{v}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("points at another vault"),
        "{v}"
    );
    assert_eq!(v["readiness"]["summary"]["ready"], false, "{v}");
}

#[test]
fn status_does_not_call_a_detected_but_unconfigured_agent_ready() {
    let env = fresh_env();
    std::fs::create_dir_all(PathBuf::from(&env.home).join(".claude/skills")).unwrap();
    let (ok, v, _) = run_home(
        &["status", "--json", "--vault", demo().to_str().unwrap()],
        &env.home,
        &env.share,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(!ok, "an unlinked agent must not report ready: {v}");
    for id in ["skills-links", "system-of-record"] {
        let check = v["readiness"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        assert_eq!(check["status"], "absent", "{id}: {v}");
        assert_eq!(check["required"], true, "{id}: {v}");
    }
    assert_eq!(v["readiness"]["summary"]["ready"], false, "{v}");
}

#[test]
fn status_without_a_vault_reports_absent() {
    let env = fresh_env();
    let (ok, v, _) = run_home(
        &["status", "--json"],
        &env.home,
        &env.share,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(!ok, "status without a vault must exit non-zero: {v}");
    assert_eq!(v["ok"], false, "{v}");
    let checks = v["readiness"]["checks"].as_array().unwrap();
    let vault = checks
        .iter()
        .find(|c| c["id"] == "vault-discovery")
        .expect("vault-discovery missing");
    assert_eq!(vault["status"], "absent", "{v}");
    assert_eq!(v["readiness"]["summary"]["ready"], false, "{v}");
}

#[test]
fn update_offline_relinks_without_network() {
    // CONFIDANT_OFFLINE=1: no fetch, still re-links from this binary.
    let env = fresh_env();
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(ok, "{v}");
    assert_eq!(v["linked"], 4, "{v}");
    assert_eq!(v["update"]["status"], "disabled", "{v}");
}

// ---------------------------------------------------------------------------
// #376: `update` offers to run the update; `setup` next-steps.
// ---------------------------------------------------------------------------

/// Stub GitHub Releases endpoint returning `tag_name`; the spawned thread
/// answers one request and exits (same pattern as
/// `update_behind_relinks_nothing`).
#[cfg(feature = "test-overrides")]
fn stub_release_server(tag: &str) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = serde_json::json!({"tag_name": tag}).to_string();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

struct RawOut {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Like `run`, but for human (non-JSON) output: `--no-input` is optional,
/// env vars can be removed, and stderr is captured.
fn run_raw(
    args: &[&str],
    env: &Env,
    extra: &[(&str, &str)],
    remove: &[&str],
    no_input: bool,
) -> RawOut {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    if no_input {
        cmd.arg("--no-input");
    }
    cmd.env("HOME", &env.home)
        .env("XDG_CONFIG_HOME", PathBuf::from(&env.home).join(".config"))
        .env("CONFIDANT_HOME", &env.share)
        .env("CONFIDANT_SKILLS_DIR", &env.skills);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    for k in remove {
        cmd.env_remove(k);
    }
    let out = cmd.output().unwrap();
    RawOut {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A recorder path that must stay absent unless the test expects a run.
#[cfg(feature = "test-overrides")]
fn recorder_path(env: &Env) -> PathBuf {
    PathBuf::from(&env.home).join("recorded.txt")
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_behind_interactive_no_runs_nothing() {
    // Behind + interactive + `n`: one matching command printed, a `[y/N]`
    // prompt on stderr, nothing run, no setup offer.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "n"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("cargo install confidant-cli"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("re-run the installer"),
        "expected one command, not a list: {}",
        r.stdout
    );
    assert!(r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "update command ran after `n`");
    assert!(
        !r.stderr.contains("confidant setup` now?"),
        "setup offered after declining the update: {}",
        r.stderr
    );
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_behind_interactive_yes_runs_command_then_declines_setup() {
    // `y` runs the expected command (recorded, never executed), reports
    // success, then offers `confidant setup`; `n` declines the offer and
    // nothing is re-linked.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "y\nn"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let recorded = std::fs::read_to_string(&recorder).unwrap();
    assert_eq!(recorded.trim(), "cargo install confidant-cli");
    assert!(
        r.stdout
            .contains("updated via `cargo install confidant-cli`."),
        "{}\n{}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("run `confidant setup` now? [y/N]"),
        "{}",
        r.stderr
    );
    assert!(
        !PathBuf::from(&env.share).join("skills").exists(),
        "update re-linked after the setup offer was declined"
    );
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_behind_interactive_yes_reports_failure() {
    // A failing update is reported and the setup offer never appears:
    // exactly one prompt.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "y"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
            ("CONFIDANT_TEST_COMMAND_FAIL", "1"),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(recorder.exists(), "failing command was not recorded");
    let both = format!("{}{}", r.stdout, r.stderr);
    assert!(both.contains("update failed"), "{both}");
    assert_eq!(
        r.stderr.matches("[y/N]").count(),
        1,
        "setup offered after a failed update: {}",
        r.stderr
    );
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_behind_noninteractive_prints_command_without_prompt() {
    // Behind + non-interactive: the single matching command is printed,
    // nothing is prompted, nothing runs.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("cargo install confidant-cli"),
        "{}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "non-interactive run executed a command");
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_behind_unknown_method_prints_generic_wording() {
    // No CONFIDANT_TEST_EXE_PATH: the test binary is not under
    // `.cargo/bin`, so the method is unknown — today's generic wording,
    // no prompt, no offer.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[("CONFIDANT_TEST_RELEASES_URL", url.as_str())],
        &[],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout
            .contains("re-run the installer or `cargo install confidant-cli`"),
        "{}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_behind_json_reports_command_additively() {
    // --json: new fields are additive, nothing is prompted or run.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
    );
    assert!(ok, "{v}");
    assert_eq!(v["update"]["behind"], true, "{v}");
    assert_eq!(v["update"]["install_method"], "cargo-install", "{v}");
    assert_eq!(
        v["update"]["update_command"], "cargo install confidant-cli",
        "{v}"
    );
    // Existing fields intact.
    assert_eq!(v["update"]["latest"], "v999.0.0", "{v}");
    assert!(v["message"].as_str().unwrap().contains("is behind"), "{v}");
    assert!(!recorder.exists(), "JSON path ran a command");
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_offline_never_prompts() {
    // CONFIDANT_OFFLINE=1: no fetch, no prompt — as today — even when the
    // session looks interactive and a known install method is forced.
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_OFFLINE", "1"),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("staleness check disabled"),
        "{}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "offline run executed a command");
}

#[cfg(all(feature = "test-overrides", windows))]
#[test]
fn update_behind_windows_prints_command_only() {
    // Windows cannot overwrite a running exe: the command is printed and
    // never offered, even with `y` scripted.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "C:\\Users\\tester\\.cargo\\bin\\confidant.exe",
            ),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "y"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("cargo install confidant-cli"),
        "{}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "Windows ran the update command");
}

/// Write a cargo-dist install receipt whose prefix is `install_prefix`, and
/// return `(receipt path, the exe path a one-liner install would have)`.
#[cfg(feature = "test-overrides")]
fn fake_dist_install(
    dir: &std::path::Path,
    install_prefix: &std::path::Path,
) -> (PathBuf, PathBuf) {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let receipt = dir.join("confidant-cli-receipt.json");
    std::fs::write(
        &receipt,
        format!(
            r#"{{"install_prefix":"{}","binaries":["confidant"],"version":"0.0.0"}}"#,
            install_prefix.display()
        ),
    )
    .unwrap();
    (receipt, bin.join("confidant"))
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_cargo_dist_self_updates_in_place() {
    // #876: a one-liner install replaces itself without a prompt, reports
    // the new version, and does not re-link skills from the old binary.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let dir = tempfile::tempdir().unwrap();
    let (receipt, exe) = fake_dist_install(dir.path(), &dir.path().join("bin"));
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            ("CONFIDANT_TEST_EXE_PATH", exe.to_str().unwrap()),
            ("CONFIDANT_TEST_RECEIPT_PATH", receipt.to_str().unwrap()),
            ("CONFIDANT_TEST_SELF_UPDATE", "9.9.9"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("updating in place"), "{}", r.stdout);
    assert!(r.stdout.contains("updated to 9.9.9"), "{}", r.stdout);
    assert!(
        r.stdout.contains("Run `confidant setup`"),
        "the new binary must re-link skills: {}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert_eq!(
        std::fs::read_to_string(&recorder).unwrap().trim(),
        "self-update confidant-cli"
    );
    assert!(
        !PathBuf::from(&env.share).join("skills").exists(),
        "update re-linked skills from the old binary"
    );
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_cargo_dist_dry_run_reports_only() {
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let dir = tempfile::tempdir().unwrap();
    let (receipt, exe) = fake_dist_install(dir.path(), &dir.path().join("bin"));
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all", "--dry-run"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            ("CONFIDANT_TEST_EXE_PATH", exe.to_str().unwrap()),
            ("CONFIDANT_TEST_RECEIPT_PATH", receipt.to_str().unwrap()),
            ("CONFIDANT_TEST_SELF_UPDATE", "9.9.9"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("would self-update in place"),
        "{}",
        r.stdout
    );
    assert!(!recorder.exists(), "--dry-run replaced the binary");
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_cargo_dist_json_reports_without_self_updating() {
    // --json is inspect-only: it names the method and the command, adds the
    // `self_update` status, and never touches the running binary.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let dir = tempfile::tempdir().unwrap();
    let (receipt, exe) = fake_dist_install(dir.path(), &dir.path().join("bin"));
    let url = format!("http://127.0.0.1:{port}/");
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            ("CONFIDANT_TEST_EXE_PATH", exe.to_str().unwrap()),
            ("CONFIDANT_TEST_RECEIPT_PATH", receipt.to_str().unwrap()),
            ("CONFIDANT_TEST_SELF_UPDATE", "9.9.9"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
    );
    assert!(ok, "{v}");
    assert_eq!(v["update"]["install_method"], "cargo-dist", "{v}");
    assert_eq!(v["update"]["self_update"], "available", "{v}");
    assert!(
        v["update"]["update_command"]
            .as_str()
            .unwrap()
            .contains("confidant-cli-installer.sh"),
        "{v}"
    );
    assert_eq!(v["update"]["behind"], true, "{v}");
    assert!(!recorder.exists(), "JSON path self-updated the binary");
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_cargo_dist_failure_is_a_typed_error() {
    // A failed self-update is an expected, actionable failure: a typed
    // DomainError with a stable code and the one-liner as the fix, never
    // `internal_error`. The human path is the one that self-updates.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let dir = tempfile::tempdir().unwrap();
    let (receipt, exe) = fake_dist_install(dir.path(), &dir.path().join("bin"));
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            ("CONFIDANT_TEST_EXE_PATH", exe.to_str().unwrap()),
            ("CONFIDANT_TEST_RECEIPT_PATH", receipt.to_str().unwrap()),
            ("CONFIDANT_TEST_SELF_UPDATE", "fail"),
        ],
        &[],
        true,
    );
    assert!(!r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stderr.contains("simulated self-update failure"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("(E_UPDATE_FAILED)"), "{}", r.stderr);
    assert!(
        r.stderr.contains("confidant-cli-installer.sh"),
        "the fix should name the one-liner: {}",
        r.stderr
    );
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_wrong_copy_receipt_refuses_loudly() {
    // The receipt names a different copy than the running binary: refuse in
    // both directions instead of replacing the wrong one (#876).
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let (receipt, exe) = fake_dist_install(dir.path(), &other.path().join("bin"));
    let url = format!("http://127.0.0.1:{port}/");
    let (ok, v, _) = run(
        &["update", "--agent", "all", "--json"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            ("CONFIDANT_TEST_EXE_PATH", exe.to_str().unwrap()),
            ("CONFIDANT_TEST_RECEIPT_PATH", receipt.to_str().unwrap()),
            ("CONFIDANT_TEST_SELF_UPDATE", "9.9.9"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
    );
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "E_CONFLICT", "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("refusing to update either copy"),
        "{v}"
    );
    assert!(!recorder.exists(), "wrong-copy case replaced a binary");
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_brew_prints_guidance_and_never_self_replaces() {
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            ("CONFIDANT_TEST_EXE_PATH", "/opt/homebrew/bin/confidant"),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "y"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("brew upgrade confidant-cli"),
        "{}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "brew install was replaced by hand");
}

#[cfg(feature = "test-overrides")]
#[test]
fn update_cargo_dist_offline_never_self_updates() {
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let dir = tempfile::tempdir().unwrap();
    let (receipt, exe) = fake_dist_install(dir.path(), &dir.path().join("bin"));
    let r = run_raw(
        &["update", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_OFFLINE", "1"),
            ("CONFIDANT_TEST_EXE_PATH", exe.to_str().unwrap()),
            ("CONFIDANT_TEST_RECEIPT_PATH", receipt.to_str().unwrap()),
            ("CONFIDANT_TEST_SELF_UPDATE", "9.9.9"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("staleness check disabled"),
        "{}",
        r.stdout
    );
    assert!(!recorder.exists(), "offline run self-updated the binary");
}

#[cfg(feature = "test-overrides")]
#[test]
fn setup_env_set_interactive_no_runs_nothing() {
    // CONFIDANT_VAULT set + interactive + `n`: prompted, nothing run. The
    // vault path does not exist, so success proves setup never probed it.
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let r = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_VAULT", "/nonexistent/vault-376"),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "n"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stderr.contains("run `confidant check` now? [y/N]"),
        "{}",
        r.stderr
    );
    assert!(!recorder.exists(), "check ran after `n`");
}

#[cfg(feature = "test-overrides")]
#[test]
fn setup_env_set_interactive_enter_runs_nothing() {
    // Empty answer (Enter) is the default No: prompted, nothing run.
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let r = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_VAULT", "/nonexistent/vault-376"),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", ""),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "check ran after Enter");
}

#[cfg(feature = "test-overrides")]
#[test]
fn setup_env_set_interactive_yes_runs_check() {
    // `y` runs `confidant check` exactly once (recorded, never executed)
    // and reports the result.
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let r = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_VAULT", "/nonexistent/vault-376"),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "y"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let recorded = std::fs::read_to_string(&recorder).unwrap();
    assert_eq!(recorded.lines().count(), 1);
    assert_eq!(recorded.trim(), "confidant check");
    assert!(
        r.stdout.contains("`confidant check` passed."),
        "{}\n{}",
        r.stdout,
        r.stderr
    );
}

#[test]
fn setup_env_unset_prints_export_line() {
    // CONFIDANT_VAULT unset: the exact export line replaces the old
    // generic wording; no prompt either way.
    let env = fresh_env();
    let r = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("export CONFIDANT_VAULT=<path>"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("Set CONFIDANT_VAULT"),
        "old generic wording still present: {}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
}

#[test]
fn setup_vault_flag_prints_real_export_path() {
    // An explicit `--vault` gives the real path in the export line.
    let env = fresh_env();
    let r = run_raw(
        &["setup", "--agent", "all", "--vault", "/tmp/fake-vault-376"],
        &env,
        &[],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout
            .contains("export CONFIDANT_VAULT=/tmp/fake-vault-376"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("<path>"), "{}", r.stdout);
}

#[cfg(feature = "test-overrides")]
#[test]
fn setup_env_set_noninteractive_prints_check_without_prompt() {
    // Non-interactive: only the check command is printed, nothing runs.
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let r = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[
            ("CONFIDANT_VAULT", "/tmp/vault-376"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("confidant check"), "{}", r.stdout);
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "non-interactive run executed a command");
}

#[test]
fn setup_json_next_steps_are_additive() {
    let env = fresh_env();
    let (ok, v, _) = run(
        &["setup", "--agent", "all", "--json"],
        &env,
        &[("CONFIDANT_VAULT", "/tmp/vault-376")],
    );
    assert!(ok, "{v}");
    assert_eq!(v["next_steps"]["check_command"], "confidant check", "{v}");
    assert_eq!(v["next_steps"]["vault_set"], true, "{v}");
    assert!(v["next_steps"]["vault_export"].is_null(), "{v}");
    // Existing contract intact.
    assert_eq!(v["linked"], 4, "{v}");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"), "{v}");
}

#[test]
fn setup_json_next_steps_unset_carries_export_line() {
    let env = fresh_env();
    let r = run_raw(
        &["setup", "--agent", "all", "--json"],
        &env,
        &[],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["next_steps"]["vault_set"], false, "{v}");
    assert_eq!(
        v["next_steps"]["vault_export"], "export CONFIDANT_VAULT=<path>",
        "{v}"
    );
}

// #386/#653e: the verbose-only `qmd` note is not printed on a plain setup.
// #715's optional-layers checklist does name qmd (and its install cost) at
// the end of every setup; the line below is the extra verbose note.
#[test]
fn setup_without_qmd_is_quiet_by_default_and_notes_it_with_verbose() {
    let env = fresh_env();
    let empty = tempfile::tempdir().unwrap();
    let quiet = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[("PATH", empty.path().to_str().unwrap())],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(quiet.ok, "stdout={}\nstderr={}", quiet.stdout, quiet.stderr);
    let both = format!("{}{}", quiet.stdout, quiet.stderr);
    assert!(
        !both.contains("Note: `qmd` not found"),
        "the verbose qmd note is noise on a first install: {both}"
    );
    // #715: the checklist still tells the operator the layer exists.
    assert!(both.contains("npm install -g @tobilu/qmd"), "{both}");

    let verbose = run_raw(
        &["setup", "--agent", "all", "-v"],
        &env,
        &[("PATH", empty.path().to_str().unwrap())],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(
        verbose.ok,
        "stdout={}\nstderr={}",
        verbose.stdout, verbose.stderr
    );
    let both = format!("{}{}", verbose.stdout, verbose.stderr);
    assert!(both.contains("confidant find"), "{both}");
    assert!(both.contains("Note: `qmd` not found"), "{both}");
    assert!(both.contains("npm install -g @tobilu/qmd"), "{both}");
}

#[test]
fn setup_json_reports_qmd_availability_additively() {
    let env = fresh_env();
    // qmd absent: additive fields report the fallback without failing.
    let empty = tempfile::tempdir().unwrap();
    let (ok, v, _) = run(
        &["setup", "--agent", "all", "--json"],
        &env,
        &[("PATH", empty.path().to_str().unwrap())],
    );
    assert!(ok, "{v}");
    assert_eq!(v["next_steps"]["qmd_available"], false, "{v}");
    let note = v["next_steps"]["qmd_note"].as_str().expect("qmd_note");
    assert!(note.contains("confidant find"), "{v}");
    assert_eq!(v["linked"], 4, "{v}");
}

// #720: setup reports both agent-integration surfaces, not just skill links.
#[test]
fn setup_json_names_mcp_alongside_skills() {
    let env = fresh_env();
    let empty = tempfile::tempdir().unwrap();
    let r = run_raw(
        &["setup", "--agent", "all", "--json"],
        &env,
        &[("PATH", empty.path().to_str().unwrap())],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["integrations"]["mcp"]["command"], "confidant mcp", "{v}");
    assert_eq!(v["integrations"]["mcp"]["transport"], "stdio", "{v}");
    assert_eq!(
        v["integrations"]["skills"]["dir"],
        v["skills_dir"].as_str().unwrap(),
        "{v}"
    );
    let agents = v["integrations"]["skills"]["agents"].as_array().unwrap();
    assert!(!agents.is_empty(), "{v}");
}

// #715: setup ends with an optional-layers checklist, each layer carrying a
// state and a one-line tradeoff. Absent layers are never silent.
#[test]
fn setup_ends_with_optional_layers_checklist() {
    let env = fresh_env();
    let empty = tempfile::tempdir().unwrap();
    let r = run_raw(
        &["setup", "--agent", "all"],
        &env,
        &[("PATH", empty.path().to_str().unwrap())],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let out = r.stdout;
    for needle in [
        "Agent integrations:",
        "confidant mcp",
        "Optional layers",
        "tradeoff:",
    ] {
        assert!(out.contains(needle), "missing {needle:?}: {out}");
    }
    for id in ["vault", "skills", "qmd", "corpus", "embeddings"] {
        assert!(out.contains(id), "missing layer {id}: {out}");
    }
    // The checklist is the final block, after the completion brief.
    let brief = out.find("Completion brief").expect("brief missing");
    let layers = out.find("Optional layers").expect("layers missing");
    assert!(brief < layers, "checklist must follow the brief: {out}");
    // Absent qmd is reported with the fallback tradeoff, not as ready.
    assert!(out.contains("absent"), "{out}");
}

#[test]
fn setup_json_lists_optional_layers_with_states() {
    let env = fresh_env();
    let empty = tempfile::tempdir().unwrap();
    // Remove CONFIDANT_VAULT: the checklist's states are what this test
    // asserts, and a test must never read the operator's real vault.
    let r = run_raw(
        &["setup", "--agent", "all", "--json"],
        &env,
        &[("PATH", empty.path().to_str().unwrap())],
        &["CONFIDANT_VAULT"],
        true,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    let layers = v["optional_layers"].as_array().expect("optional_layers");
    let ids: Vec<&str> = layers.iter().map(|l| l["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        vec!["vault", "skills", "qmd", "corpus", "embeddings"],
        "{v}"
    );
    for layer in layers {
        assert!(layer["state"].is_string(), "{v}");
        assert!(layer["detail"].is_string(), "{v}");
        assert!(layer["tradeoff"].is_string(), "{v}");
    }
    let by_id = |id: &str| layers.iter().find(|l| l["id"] == id).unwrap();
    assert_eq!(by_id("vault")["state"], "absent", "{v}");
    assert_eq!(by_id("skills")["state"], "present", "{v}");
    assert_eq!(by_id("qmd")["state"], "absent", "{v}");
    assert_eq!(by_id("corpus")["state"], "absent", "{v}");
    assert_eq!(by_id("embeddings")["state"], "absent", "{v}");
}

// #715: a shim named `qmd` is not a working qmd; setup says so instead of
// treating semantic search as available.
#[test]
fn setup_verbose_does_not_trust_a_qmd_shim() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let env = fresh_env();
        let stub = tempfile::tempdir().unwrap();
        let script = stub.path().join("qmd");
        std::fs::write(
            &script,
            "#!/bin/sh\necho \"Robin Example — canned hit\"\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = run_raw(
            &["setup", "--agent", "all", "-v"],
            &env,
            &[("PATH", stub.path().to_str().unwrap())],
            &["CONFIDANT_VAULT"],
            true,
        );
        assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
        let both = format!("{}{}", r.stdout, r.stderr);
        assert!(both.contains("did not report a version"), "{both}");
        assert!(both.contains("confidant find"), "{both}");
        assert!(both.contains("not working"), "{both}");
    }
}

// ---------------------------------------------------------------------------
// #649: `setup --dry-run` writes nothing.
// ---------------------------------------------------------------------------

/// Recursive snapshot of `root`: relative path -> kind, link target, or file
/// content. Used to prove a dry run left a tree byte-for-byte unchanged.
fn snapshot(root: &std::path::Path) -> Vec<(PathBuf, String)> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let state = if meta.is_symlink() {
                format!("link:{}", std::fs::read_link(&path).unwrap().display())
            } else if meta.is_dir() {
                "dir".to_owned()
            } else {
                format!(
                    "file:{}",
                    std::fs::read_to_string(&path).unwrap_or_default()
                )
            };
            out.push((path.strip_prefix(root).unwrap().to_path_buf(), state));
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

/// `run_raw` without the `CONFIDANT_SKILLS_DIR` override, so setup resolves
/// real agent dirs under the temp HOME.
fn run_no_override(args: &[&str], env: &Env, extra: &[(&str, &str)]) -> RawOut {
    run_raw(args, env, extra, &["CONFIDANT_SKILLS_DIR"], true)
}

#[test]
fn setup_dry_run_writes_nothing() {
    let env = fresh_env();
    let vault = tempfile::tempdir().unwrap();
    std::fs::write(vault.path().join("confidant.toml"), "version = 1\n").unwrap();
    let vault_env = vault.path().to_str().unwrap();

    let home_before = snapshot(std::path::Path::new(&env.home));
    let share_before = snapshot(std::path::Path::new(&env.share));
    let vault_before = snapshot(vault.path());

    let r = run_no_override(
        &["setup", "--agent", "all", "--dry-run"],
        &env,
        &[("CONFIDANT_VAULT", vault_env)],
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("dry run"), "{}", r.stdout);
    assert!(r.stdout.contains("would link"), "{}", r.stdout);

    assert_eq!(
        snapshot(std::path::Path::new(&env.home)),
        home_before,
        "dry run changed $HOME"
    );
    assert_eq!(
        snapshot(std::path::Path::new(&env.share)),
        share_before,
        "dry run materialized the skills tree"
    );
    assert_eq!(
        snapshot(vault.path()),
        vault_before,
        "dry run changed the vault"
    );
    assert!(
        !std::path::Path::new(&env.home).join(".claude").exists(),
        "dry run created ~/.claude"
    );
    assert!(
        !std::path::Path::new(&env.home).join(".agents").exists(),
        "dry run created ~/.agents"
    );
}

#[test]
fn setup_dry_run_json_reports_planned_counts() {
    let env = fresh_env();
    let r = run_no_override(
        &["setup", "--agent", "all", "--dry-run", "--json"],
        &env,
        &[],
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(v["linked"], 32, "{v}");
    assert_eq!(v["skipped"], 0, "{v}");
    // Nothing materialized or linked.
    assert!(
        !std::path::Path::new(&env.share).join("skills").exists(),
        "dry run materialized the skills tree: {v}"
    );
    assert!(
        !std::path::Path::new(&env.home).join(".claude").exists(),
        "dry run created ~/.claude: {v}"
    );
}

// ---------------------------------------------------------------------------
// #655: muse/agents share ~/.agents/skills; link and count it once.
// ---------------------------------------------------------------------------

#[test]
fn setup_counts_shared_agent_dir_once() {
    let env = fresh_env();
    let r = run_no_override(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();

    // 9 agent entries, 8 distinct dirs, 4 skills each.
    assert_eq!(v["linked"], 32, "{v}");
    assert_eq!(v["skipped"], 0, "{v}");
    assert!(
        v["agents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["name"] == "muse, agents"),
        "shared dir should keep both labels: {v}"
    );

    // The shared dir got one link per skill, not one per label.
    let shared = std::path::Path::new(&env.home).join(".agents/skills");
    let entries: Vec<_> = std::fs::read_dir(&shared).unwrap().flatten().collect();
    assert_eq!(entries.len(), 4, "shared dir linked twice: {v}");
    for entry in entries {
        assert!(entry.path().is_symlink(), "{:?}", entry.path());
    }

    // Same counting rule as `agents_health`/doctor: dedupe by dir.
    let a = run_no_override(&["agents", "--json"], &env, &[]);
    assert!(a.ok, "stdout={}\nstderr={}", a.stdout, a.stderr);
    let agents: Value = serde_json::from_str(&a.stdout).unwrap();
    let mut seen: Vec<String> = Vec::new();
    let mut total = 0u64;
    for agent in agents["agents"].as_array().unwrap() {
        let path = agent["path"].as_str().unwrap().to_owned();
        if seen.contains(&path) {
            continue;
        }
        seen.push(path);
        total += agent["linked"].as_u64().unwrap();
    }
    assert_eq!(seen.len(), 8, "{agents}");
    assert_eq!(total as usize, v["linked"].as_u64().unwrap() as usize);
}

// ---------------------------------------------------------------------------
// #652 / #653c: `agents` always lists; `--agent auto` fallback is explicit.
// ---------------------------------------------------------------------------

#[test]
fn agents_human_lists_all_nine_before_setup() {
    let env = fresh_env();
    let r = run_no_override(&["agents"], &env, &[]);
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    for name in [
        "claude-code",
        "cursor",
        "codex",
        "opencode",
        "pi",
        "gemini-cli",
        "hermes-agent",
        "muse",
        "agents",
    ] {
        assert!(
            r.stdout.lines().any(|line| line.starts_with(name)),
            "missing {name} in:\n{}",
            r.stdout
        );
    }
    assert!(r.stdout.contains("0/4"), "{}", r.stdout);
    assert!(
        r.stdout
            .contains("`confidant setup --agent <name>` or `confidant setup --agent auto`"),
        "missing setup hint:\n{}",
        r.stdout
    );
}

#[test]
fn setup_auto_fallback_to_claude_code_is_reported() {
    let env = fresh_env();
    let r = run_no_override(&["setup", "--agent", "auto"], &env, &[]);
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stderr
            .contains("claude-code was not detected; --agent auto falls back to it"),
        "fallback was silent:\n{}",
        r.stderr
    );
    // Selection itself is unchanged.
    assert!(
        std::path::Path::new(&env.home)
            .join(".claude/skills")
            .is_dir(),
        "auto should still link claude-code"
    );
}

#[test]
fn setup_auto_with_detected_agent_does_not_warn() {
    let env = fresh_env();
    let cursor = std::path::Path::new(&env.home).join(".cursor/skills");
    std::fs::create_dir_all(&cursor).unwrap();
    let r = run_no_override(&["setup", "--agent", "auto"], &env, &[]);
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        !r.stderr.contains("falls back"),
        "unexpected fallback warning:\n{}",
        r.stderr
    );
    assert!(cursor.join("pack-author").is_symlink());
}

// ---------------------------------------------------------------------------
// #668: `update --dry-run` writes nothing and does not run the upgrade.
// ---------------------------------------------------------------------------

#[test]
fn update_dry_run_writes_nothing() {
    let env = fresh_env();
    let r = run_no_override(
        &["update", "--agent", "all", "--dry-run", "--json"],
        &env,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(v["linked"], 32, "{v}");
    assert_eq!(v["update"]["status"], "disabled", "{v}");

    assert!(
        !std::path::Path::new(&env.home).join(".claude").exists(),
        "dry run created ~/.claude: {v}"
    );
    assert!(
        !std::path::Path::new(&env.home).join(".agents").exists(),
        "dry run created ~/.agents: {v}"
    );
    assert!(
        !std::path::Path::new(&env.share).join("skills").exists(),
        "dry run materialized the skills tree: {v}"
    );
}

#[test]
fn update_dry_run_human_reports_planned_relink() {
    let env = fresh_env();
    let r = run_no_override(
        &["update", "--agent", "all", "--dry-run"],
        &env,
        &[("CONFIDANT_OFFLINE", "1")],
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("would re-link 32 skills"),
        "planned relink not reported:\n{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("re-linked"),
        "past-tense wording under --dry-run:\n{}",
        r.stdout
    );
    assert!(
        !std::path::Path::new(&env.home).join(".claude").exists(),
        "dry run created ~/.claude:\n{}",
        r.stdout
    );
    assert!(
        !std::path::Path::new(&env.share).join("skills").exists(),
        "dry run materialized the skills tree:\n{}",
        r.stdout
    );
}

#[cfg(all(feature = "test-overrides", not(windows)))]
#[test]
fn update_behind_dry_run_prints_command_without_offering() {
    // #668: behind + `--dry-run` prints the command it would run, never
    // prompts for it, and never records/executes it.
    let port = stub_release_server("v999.0.0");
    let env = fresh_env();
    let recorder = recorder_path(&env);
    let url = format!("http://127.0.0.1:{port}/");
    let r = run_raw(
        &["update", "--agent", "all", "--dry-run"],
        &env,
        &[
            ("CONFIDANT_TEST_RELEASES_URL", url.as_str()),
            (
                "CONFIDANT_TEST_EXE_PATH",
                "/home/tester/.cargo/bin/confidant",
            ),
            ("CONFIDANT_TEST_FORCE_INTERACTIVE", "1"),
            ("CONFIDANT_TEST_PROMPT_ANSWERS", "y"),
            (
                "CONFIDANT_TEST_COMMAND_RECORDER",
                recorder.to_str().unwrap(),
            ),
        ],
        &[],
        false,
    );
    assert!(r.ok, "stdout={}\nstderr={}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("would run `cargo install confidant-cli`"),
        "{}",
        r.stdout
    );
    assert!(!r.stderr.contains("[y/N]"), "{}", r.stderr);
    assert!(!recorder.exists(), "dry run executed the upgrade command");
}
