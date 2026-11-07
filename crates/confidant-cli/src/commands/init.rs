//! `init`: bootstrap and scaffolding.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::shared::display_remote_url;
use crate::{ok_envelope, print_json, Cli, Command, FixExt};
use confidant_core::discover::load_user_config;
use confidant_core::error::DomainError;
use confidant_core::load_vault;
use confidant_core::scope::parse_pack_list;
use confidant_core::write::require_git_repo;
use serde_json::Value;

pub(crate) fn bootstrap_target(cli: &Cli) -> PathBuf {
    fn lenient(p: &Path) -> PathBuf {
        if !p.is_dir() && p.file_name().is_some_and(|n| n == "confidant.toml") {
            p.parent().unwrap_or(p).to_path_buf()
        } else {
            p.to_path_buf()
        }
    }
    if let Some(flag) = &cli.vault {
        return lenient(flag);
    }
    if let Ok(env) = std::env::var("CONFIDANT_VAULT") {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(cfg) = load_user_config(home.as_deref()) {
            if let Some(named) = cfg.named(&env) {
                return lenient(&named);
            }
        }
        return lenient(Path::new(&env));
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// True when `root` is the top level of its own git repository. A
/// subdirectory of someone else's repo is not the vault's repo root, so
/// `--create` must not commit the skeleton into the parent.
pub(crate) fn is_git_repo_root(root: &Path, no_input: bool) -> bool {
    let Ok(top) = confidant_core::write::git(root, &["rev-parse", "--show-toplevel"], no_input)
    else {
        return false;
    };
    let top = Path::new(top.trim());
    let top = top.canonicalize().unwrap_or_else(|_| top.to_path_buf());
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    top == root
}

pub(crate) fn dir_entry_names(root: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

/// Validate `init --create --packs` before the skeleton is written (#639).
///
/// `init` can only seed packs the binary already implements: compiled packs
/// or the implicit built-ins (today `personal@0.2`). An external pack is
/// vendored into an existing vault by `confidant pack add`, so naming one
/// here is a usage error with the install-after-init fix, not the opaque
/// "unknown pack" it used to be.
pub(crate) fn validate_init_packs(packs: &[String]) -> anyhow::Result<()> {
    for name in packs {
        if confidant_core::packs::is_known_pack_id(name) {
            continue;
        }
        let fix = "Run `confidant init --create` without `--packs`, then \
                   install the pack with `confidant pack add <source> --yes`";
        let (message, fix) = match name.split_once('@') {
            Some((pack, version)) if !pack.is_empty() && !version.is_empty() => (
                format!(
                    "`--packs {name}` names an external pack, which init cannot vendor; \
                     init only seeds packs built into this binary (today the implicit \
                     personal@0.2)"
                ),
                fix,
            ),
            _ => (
                format!(
                    "`--packs {name}` is not a pack this binary implements; init only \
                     seeds built-in packs written as name@version (today personal@0.2)"
                ),
                fix,
            ),
        };
        return Err(anyhow::Error::new(DomainError::usage(message)).with_fix(fix));
    }
    Ok(())
}

/// What `init --create` scaffolded for real, kept until the key steps and
/// the anchor save succeed so a failure can remove only what this command
/// created (#651). Every field records a path this run wrote; rollback never
/// touches a pre-existing user file.
pub(crate) struct Scaffold {
    root: PathBuf,
    created_root: bool,
    git_initialized: bool,
    gitignore_original: Option<Vec<u8>>,
    wrote_gitignore: bool,
    wrote_config: bool,
    commit_created: bool,
    previous_head: Option<String>,
    /// True when this run added `origin` via `--remote` on a pre-existing
    /// repo (a repo this run created is removed entirely on rollback).
    added_remote: bool,
    armed: bool,
}

impl Scaffold {
    /// Keep the scaffold: the run is about to succeed.
    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Best-effort rollback. A repo this run created is removed entirely; a
    /// pre-existing repo is rewound to its previous HEAD (or its unborn
    /// state) and only this run's files are removed.
    fn rollback(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if self.git_initialized {
            let _ = std::fs::remove_dir_all(self.root.join(".git"));
        } else if self.added_remote {
            let _ = confidant_core::write::git(&self.root, &["remote", "remove", "origin"], true);
        }
        if self.commit_created && !self.git_initialized {
            match &self.previous_head {
                Some(prev) => {
                    let _ =
                        confidant_core::write::git(&self.root, &["reset", "--mixed", prev], true);
                }
                None => {
                    let _ =
                        confidant_core::write::git(&self.root, &["update-ref", "-d", "HEAD"], true);
                }
            }
        }
        if self.wrote_gitignore {
            let path = self.root.join(".gitignore");
            match &self.gitignore_original {
                Some(bytes) => {
                    let _ = std::fs::write(path, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        if self.wrote_config {
            let _ = std::fs::remove_file(self.root.join("confidant.toml"));
        }
        if self.created_root {
            // Our own empty collection directories would otherwise keep the
            // root alive. `remove_dir` refuses a non-empty directory, so any
            // file the operator put there leaves the tree alone.
            for dir in VAULT_DIRS {
                let _ = std::fs::remove_dir(self.root.join(dir));
            }
            // Only removes an empty directory: any user file leaves it alone.
            let _ = std::fs::remove_dir(&self.root);
        }
    }
}

impl Drop for Scaffold {
    fn drop(&mut self) {
        self.rollback();
    }
}

/// The vault's on-disk shape: the record collections plus the ledger. Git
/// does not track empty directories, so `init` creates these locally and a
/// later clone (or the first write) recreates what it needs.
pub(crate) const VAULT_DIRS: &[&str] = &[
    "people",
    "orgs",
    "deals",
    "interactions",
    "notes",
    "edges",
    "ledger",
];

/// Repo-local commit identity, always written so a vault never leaks the
/// operator's global (e.g. corporate/work) identity into its commit history.
/// The operator can override it per-vault by editing `<vault>/.git/config`.
pub(crate) const FALLBACK_GIT_NAME: &str = "Confidant Operator";
pub(crate) const FALLBACK_GIT_EMAIL: &str = "operator@confidant.local";

/// Create the collection directories and write the repo-local fallback
/// identity into `<vault>/.git/config` for any key the vault has not set.
/// Both steps are idempotent, and a per-vault override survives a re-run.
pub(crate) fn initialize_vault_shape(root: &Path, no_input: bool) -> anyhow::Result<()> {
    for dir in VAULT_DIRS {
        std::fs::create_dir_all(root.join(dir)).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot create vault directory {dir}: {e}"
            )))
        })?;
    }
    for (key, value) in [
        ("user.name", FALLBACK_GIT_NAME),
        ("user.email", FALLBACK_GIT_EMAIL),
    ] {
        // `git config --get` exits non-zero when the key is unset; only then
        // write the neutral value, so an operator's per-vault edit is kept.
        if confidant_core::write::git(root, &["config", "--local", "--get", key], no_input).is_ok()
        {
            continue;
        }
        confidant_core::write::git(root, &["config", "--local", key, value], no_input)?;
    }
    Ok(())
}

/// Result of the `init --create` bootstrap step.
pub(crate) enum BootstrapPlan {
    /// Continue to discovery and `cmd_init`; `Some` when a skeleton was
    /// written for real and must be rolled back if `cmd_init` fails.
    Continue(Option<Scaffold>),
    /// #649: `--dry-run` printed the plan and wrote nothing; stop here.
    DryRun,
}

pub(crate) fn planned_create_branch(root: &Path, no_input: bool) -> (String, Option<String>) {
    if !root.is_dir() || !is_git_repo_root(root, no_input) {
        return ("main".to_owned(), None);
    }
    if confidant_core::write::git(root, &["rev-parse", "--verify", "HEAD"], no_input).is_err() {
        return (
            "main".to_owned(),
            Some("would move unborn HEAD to main".to_owned()),
        );
    }
    let current = current_branch(root, no_input).unwrap_or_else(|| "main".to_owned());
    if current == "main" {
        (current, None)
    } else {
        (
            current.clone(),
            Some(format!(
                "would leave existing branch {current} (init only moves an unborn HEAD to main)"
            )),
        )
    }
}

/// The current branch name (works on an unborn branch), or `None` when git
/// cannot report one.
pub(crate) fn current_branch(root: &Path, no_input: bool) -> Option<String> {
    confidant_core::write::git(root, &["branch", "--show-current"], no_input)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// #685/#686: a second device clones the vault with git. Shown after `init`
/// (human and JSON) so a new-device operator is not sent back to `init`.
pub(crate) const SECOND_DEVICE_HINT: &str =
    "to put this vault on another device, clone it with git";

/// `--remote` on `init --create`, if present.
pub(crate) fn init_remote_url(cli: &Cli) -> Option<&str> {
    match &cli.command {
        Command::Init { remote, .. } => remote.as_deref(),
        _ => None,
    }
}

/// Additive `next_steps` for `init` JSON (#658, #686): `pack add` when the
/// scaffolded list is empty, `git push` when `--remote` set origin, and
/// always the second-device enrollment path.
pub(crate) fn init_next_steps(packs_empty: bool, remote: Option<&str>, branch: &str) -> Value {
    let mut steps = Vec::new();
    if packs_empty {
        steps.push("confidant pack add <https-url> --yes".to_string());
    }
    if remote.is_some() {
        steps.push(format!("git push -u origin {branch}"));
    }
    steps.push(SECOND_DEVICE_HINT.to_string());
    serde_json::json!(steps)
}

/// Human follow-up after a real or dry-run `init`. The pack-add line must
/// appear at most once (#658).
pub(crate) fn print_init_followup(packs_empty: bool, remote: Option<&str>, branch: &str) {
    if packs_empty {
        println!("optional: install a pack with `confidant pack add <https-url> --yes`");
    }
    if let Some(url) = remote {
        println!("git remote origin {} (not pushed)", display_remote_url(url));
        println!("push when ready: git push -u origin {branch}");
    } else {
        println!(
            "optional: `git remote add origin <url>` for backup (or `--remote <url>` with `--create`); this command does not push"
        );
    }
    println!("{SECOND_DEVICE_HINT}");
}

/// Refuse `--remote` when the URL is empty or `origin` already exists, so
/// `--create --dry-run` reports the same error a real run would.
pub(crate) fn refuse_init_remote(
    root: &Path,
    url: &str,
    existing_repo: bool,
    no_input: bool,
) -> anyhow::Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(anyhow::Error::new(
            DomainError::usage("--remote needs a git URL").with_fix(
                "Pass `--remote <url>` with a real remote, or omit it and add origin later",
            ),
        ));
    }
    // `git remote add` would otherwise parse a leading `-` as an option.
    if url.starts_with('-') {
        return Err(anyhow::Error::new(
            DomainError::usage("refusing --remote: URL must not start with '-'")
                .with_fix("Pass a git URL (https://… or git@…), not a flag"),
        ));
    }
    if !existing_repo {
        return Ok(());
    }
    let remotes = confidant_core::write::git(root, &["remote"], no_input)?;
    if remotes.lines().any(|line| line.trim() == "origin") {
        return Err(anyhow::Error::new(
            DomainError::usage(format!(
                "refusing --remote: origin already exists on {}",
                root.display()
            ))
            .with_fix("Use the existing origin, or `git remote remove origin` first"),
        ));
    }
    Ok(())
}

/// `git remote add origin URL`. `Scaffold::added_remote` is set only after
/// this succeeds so a failed `git remote add` is not rolled back as if it
/// created origin.
pub(crate) fn add_init_remote(
    root: &Path,
    url: &str,
    no_input: bool,
    scaffold: &mut Scaffold,
) -> anyhow::Result<()> {
    confidant_core::write::git(
        root,
        &["remote", "add", "--", "origin", url.trim()],
        no_input,
    )?;
    scaffold.added_remote = true;
    Ok(())
}

/// #649: report the `init --create` plan without writing anything.
pub(crate) fn print_init_scaffold_dry_run(
    cli: &Cli,
    root: &Path,
    packs: &[String],
) -> anyhow::Result<()> {
    let packs_empty = packs.is_empty();
    let (branch, branch_note) = planned_create_branch(root, cli.no_input);
    let remote = init_remote_url(cli);
    if cli.json {
        let mut extra = serde_json::json!({
            "command": "init",
            "dry_run": true,
            "branch": branch,
            "scaffold": true,
            "packs": packs,
            "remote": remote.map(display_remote_url),
            "next_steps": init_next_steps(packs_empty, remote, &branch),
        });
        if let Some(note) = &branch_note {
            extra["branch_note"] = Value::String(note.clone());
        }
        print_json(&ok_envelope(Some(root), extra))?;
    } else {
        println!("dry run — no changes:");
        println!("  vault    {}", root.display());
        println!("  branch   {branch}");
        if let Some(note) = &branch_note {
            println!("  note     {note}");
        }
        println!("  would    create the vault directory (when absent)");
        println!(
            "  would    create the collection directories ({})",
            VAULT_DIRS.join(", ")
        );
        println!("  would    run git init -b main and commit .gitignore + confidant.toml");
        println!(
            "  would    set a repo-local fallback git identity ({FALLBACK_GIT_NAME} <{FALLBACK_GIT_EMAIL}>)"
        );
        match remote {
            Some(url) => println!(
                "  would    add git remote origin {} (not pushed)",
                display_remote_url(url)
            ),
            None => println!("  would    not add a git remote"),
        }
        print_init_followup(packs_empty, remote, &branch);
    }
    Ok(())
}

/// `init --create`: scaffold a vault before the key steps so one
/// non-interactive command produces a working vault (#539).
///
/// Creates the directory, runs `git init` when the target is not its own
/// repo, ensures `.confidant/` is git-ignored, writes a minimal
/// `confidant.toml` (`packs` from the global `--packs`, default `[]`), and
/// commits just those files. An existing vault is left to today's path; any
/// other non-empty directory is refused with nothing written.
pub(crate) fn bootstrap_vault(cli: &Cli, create: bool) -> anyhow::Result<BootstrapPlan> {
    if !create {
        return Ok(BootstrapPlan::Continue(None));
    }
    let no_input = cli.no_input;
    let root = bootstrap_target(cli);

    // An existing vault takes today's path unchanged (anchor check, clean
    // tree, key steps). `--remote` is a scaffold-only flag: refuse rather
    // than silently skip it on a directory that already has a vault.
    if root.join("confidant.toml").is_file() {
        if init_remote_url(cli).is_some() {
            return Err(anyhow::Error::new(
                DomainError::usage(format!(
                    "refusing --remote: {} already has a vault; --remote only applies while scaffolding",
                    root.display()
                ))
                .with_fix("Add a remote with `git remote add origin <url>` (this command does not push)"),
            ));
        }
        return Ok(BootstrapPlan::Continue(None));
    }

    // #539: only an absent, empty, or skeleton-only directory is scaffolded.
    // A non-empty target — including a clean git repo — is refused so that
    // running `--create` from the wrong cwd cannot turn a project checkout
    // into a vault. Vault-inside-an-existing-repo, if ever wanted, is its own
    // explicit flag and decision.
    let exists = root.is_dir();
    let entries = if exists {
        dir_entry_names(&root)?
    } else {
        Vec::new()
    };
    let only_our_files = entries.iter().all(|n| n == ".git" || n == ".gitignore");
    if exists && !entries.is_empty() && !only_our_files {
        return Err(anyhow::Error::new(
            DomainError::usage(format!(
                "refusing to scaffold a vault in {}: the directory is not empty (--create only scaffolds an absent or empty directory)",
                root.display()
            ))
            .with_fix(
                "Use an empty directory, or create the vault by hand (`git init`, write `confidant.toml`, commit) and run `confidant init`",
            ),
        ));
    }

    // Validate `--packs` before writing: an unknown pack would leave the new
    // vault failing `check`, and an external pack cannot be vendored before
    // the vault exists (#639).
    let packs: Vec<String> = cli
        .packs
        .as_deref()
        .map(parse_pack_list)
        .unwrap_or_default();
    validate_init_packs(&packs)?;

    // #651 is obsolete now that `init` writes a repo-local fallback
    // identity when git has none: a machine with no global `user.name`
    // still scaffolds. Everything else (packs, `--remote`) is still
    // validated before the first write.
    let existing_repo = exists && is_git_repo_root(&root, no_input);
    if let Some(url) = init_remote_url(cli) {
        refuse_init_remote(&root, url, existing_repo, no_input)?;
    }

    // #649: dry run stops before the first write.
    if cli.dry_run {
        print_init_scaffold_dry_run(cli, &root, &packs)?;
        return Ok(BootstrapPlan::DryRun);
    }
    let previous_head = if existing_repo {
        confidant_core::write::git(&root, &["rev-parse", "HEAD"], no_input)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    let mut scaffold = Scaffold {
        root: root.clone(),
        created_root: !exists,
        git_initialized: !existing_repo,
        gitignore_original: std::fs::read(root.join(".gitignore")).ok(),
        wrote_gitignore: false,
        wrote_config: false,
        commit_created: false,
        previous_head,
        added_remote: false,
        armed: true,
    };

    std::fs::create_dir_all(&root).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot create vault directory {}: {e}",
            root.display()
        )))
    })?;

    if scaffold.git_initialized {
        // #661: create `main` explicitly, independent of init.defaultBranch.
        confidant_core::write::git(&root, &["init", "-b", "main"], no_input)?;
    } else if existing_repo
        && confidant_core::write::git(&root, &["rev-parse", "--verify", "HEAD"], no_input).is_err()
    {
        // #661 edge: a pre-existing repo with an unborn HEAD has no commits
        // to rename, so create `main` explicitly here too. A repo with
        // commits is never renamed (the `rev-parse --verify HEAD` above).
        confidant_core::write::git(
            &root,
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            no_input,
        )?;
    }

    // The vault's shape (`people/` … `ledger/`) and the neutral repo-local
    // identity the skeleton commit uses, so the operator's global identity
    // never lands in the vault's history.
    initialize_vault_shape(&root, no_input)?;

    // `.confidant/` holds the plaintext search corpus and must never be
    // committed (ADR-6).
    let gitignore = root.join(".gitignore");
    let mut text = std::fs::read_to_string(&gitignore).unwrap_or_default();
    let already_ignored = text
        .lines()
        .any(|line| matches!(line.trim(), ".confidant/" | ".confidant"));
    if !already_ignored {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(".confidant/\n");
        scaffold.wrote_gitignore = true;
        std::fs::write(&gitignore, text)?;
    }

    let packs_toml = if packs.is_empty() {
        "[]".to_string()
    } else {
        let quoted: Vec<String> = packs.iter().map(|p| format!("{p:?}")).collect();
        format!("[{}]", quoted.join(", "))
    };
    scaffold.wrote_config = true;
    std::fs::write(
        root.join("confidant.toml"),
        format!(
            "spec = {:?}\npacks = {packs_toml}\nvault_id = {:?}\n",
            confidant_core::SPEC_VERSION,
            confidant_core::write::new_ulid(),
        ),
    )?;

    // Commit only the skeleton files this command wrote, never `git add -A`.
    // The commit carries a pathspec too, so any changes an existing repo
    // already had staged are never swept into the skeleton commit.
    confidant_core::write::git(
        &root,
        &["add", "--", ".gitignore", "confidant.toml"],
        no_input,
    )?;
    let staged = confidant_core::write::git(
        &root,
        &[
            "status",
            "--porcelain",
            "--",
            ".gitignore",
            "confidant.toml",
        ],
        no_input,
    )?;
    if !staged.trim().is_empty() {
        confidant_core::write::git(
            &root,
            &[
                "commit",
                "-m",
                "init: vault skeleton",
                "--",
                ".gitignore",
                "confidant.toml",
            ],
            no_input,
        )?;
        scaffold.commit_created = true;
    }

    if let Some(url) = init_remote_url(cli) {
        add_init_remote(&root, url, no_input, &mut scaffold)?;
    }

    if !cli.json {
        let branch = current_branch(&root, no_input).unwrap_or_else(|| "main".to_owned());
        eprintln!("scaffolded vault at {} (branch {branch})", root.display());
    }
    Ok(BootstrapPlan::Continue(Some(scaffold)))
}

/// `confidant init`: validate a vault, or scaffold one with `--create`.
///
/// Records are plaintext, so there is no key, keychain, anchor, or recovery
/// step. With `--create` the skeleton is already written and committed by
/// [`bootstrap_vault`], including the collection directories and a
/// neutral repo-local git identity; this
/// validates the result and reports the plan. Without `--create` the same
/// idempotent shape step runs on the existing vault.
pub(crate) fn cmd_init(
    cli: &Cli,
    root: &Path,
    scaffold: Option<Scaffold>,
) -> anyhow::Result<ExitCode> {
    let json = cli.json;
    let no_input = cli.no_input;

    require_git_repo(root, no_input)?;
    let vault = load_vault(root)?;
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let branch = current_branch(root, no_input);
    let packs_empty = vault.config.packs.is_empty();
    let remote = init_remote_url(cli);
    let branch_name = branch.as_deref().unwrap_or("main");

    if cli.dry_run {
        if json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "init",
                    "dry_run": true,
                    "branch": branch,
                    "remote": remote.map(display_remote_url),
                    "next_steps": init_next_steps(packs_empty, remote, branch_name),
                }),
            ))?;
        } else {
            println!("dry run — no changes:");
            println!("  vault    {}", root.display());
            if let Some(branch) = &branch {
                println!("  branch   {branch}");
            }
            print_init_followup(packs_empty, remote, branch_name);
        }
        return Ok(ExitCode::SUCCESS);
    }

    match scaffold {
        Some(mut scaffold) => scaffold.disarm(),
        // `--create` on an existing vault, or `init` on a hand-written one:
        // make the on-disk shape match what a fresh scaffold produces.
        // Idempotent, and it keeps a per-vault identity already set.
        None => initialize_vault_shape(root, no_input)?,
    }
    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "init",
                "branch": branch,
                "remote": remote.map(display_remote_url),
                "next_steps": init_next_steps(packs_empty, remote, branch_name),
            }),
        ))?;
    } else {
        println!("vault ready at {}", root.display());
        if let Some(branch) = &branch {
            println!("branch {branch}");
        }
        print_init_followup(packs_empty, remote, branch_name);
    }
    Ok(ExitCode::SUCCESS)
}
