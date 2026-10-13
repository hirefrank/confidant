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
    vec![
        "capture-gap-summary",
        "lightfield-import",
        "portal-sync",
        "qmd-search",
        "transcript-import",
    ]
}

#[test]
fn setup_links_all_skills_as_symlinks() {
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert_eq!(v["linked"], 5, "{v}");
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
    // Shared helper materialized and executable.
    let common = PathBuf::from(v["skills_dir"].as_str().unwrap()).join("bin/common.py");
    assert!(common.exists(), "{v}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&common).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "bin/common.py should be +x: {v}");
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
    let stale = PathBuf::from(env.skills.clone()).join("portal-sync");
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
    let mine = PathBuf::from(env.skills.clone()).join("portal-sync");
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
fn setup_preserves_foreign_symlinks() {
    // High 2: a symlink pointing outside our skills root is not owned;
    // setup skips it, --force re-points it.
    let env = fresh_env();
    let foreign_target = PathBuf::from(env.home.clone()).join("foreign-skills");
    std::fs::create_dir_all(foreign_target.join("portal-sync")).unwrap();
    let dest = PathBuf::from(env.skills.clone()).join("portal-sync");
    #[cfg(unix)]
    std::os::unix::fs::symlink(foreign_target.join("portal-sync"), &dest).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(foreign_target.join("portal-sync"), &dest).unwrap();

    let (ok, v, _) = run(&["setup", "--agent", "all", "--json"], &env, &[]);
    assert!(ok, "{v}");
    assert_eq!(
        std::fs::read_link(&dest).unwrap(),
        foreign_target.join("portal-sync"),
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
    assert!(version_dir.join("portal-sync").exists());

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
        version_dir.join("portal-sync").join("SKILL.md").exists(),
        "installed skills were deleted!"
    );
}

#[test]
fn setup_copy_writes_managed_marker_and_update_replaces_it() {
    // A `--copy` install is owned (marker file); `update` may replace it.
    let env = fresh_env();
    let (ok, v, _) = run(&["setup", "--agent", "all", "--copy", "--json"], &env, &[]);
    assert!(ok, "{v}");
    let dest = PathBuf::from(env.skills.clone()).join("portal-sync");
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
            for entry in std::fs::read_dir(&bin).unwrap().flatten() {
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
    std::fs::create_dir_all(skills_root.join("0.0.0").join("portal-sync")).unwrap();
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
    let old_skill = skills_root.join("0.0.0").join("portal-sync");
    std::fs::create_dir_all(&old_skill).unwrap();
    std::fs::write(old_skill.join("SKILL.md"), "# portal-sync\n").unwrap();

    // claude-code links into the old version (as a previous
    // `setup --agent claude-code` from the old binary would have left it).
    let claude_dir = PathBuf::from(env.home.clone()).join(".claude/skills");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::os::unix::fs::symlink(&old_skill, claude_dir.join("portal-sync")).unwrap();

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
        claude_dir.join("portal-sync").join("SKILL.md").exists(),
        "claude-code's link is broken: {v}"
    );
    // Cursor got the current version.
    assert!(
        PathBuf::from(env.home.clone())
            .join(".cursor/skills/portal-sync")
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
    let mine = PathBuf::from(env.skills.clone()).join("portal-sync");
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

#[test]
fn routing_prints_snippet() {
    let env = fresh_env();
    let mut cmd = Command::new(bin());
    cmd.args(["routing", "--no-input"])
        .env("HOME", &env.home)
        .env("CONFIDANT_HOME", &env.share);
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("portal-sync"), "{stdout:?}");
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
    assert_eq!(v["linked"], 5, "{v}");
    assert_eq!(v["update"]["status"], "disabled", "{v}");
}
