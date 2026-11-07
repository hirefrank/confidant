//! `sync`: fetch, report, optional pull/push.

use std::path::Path;
use std::process::ExitCode;

use crate::commands::doctor::{
    git_ahead_behind, git_upstream, parse_git_remotes, sync_push_refspec,
};
use crate::commands::install::confirm_yn;
use crate::{ok_envelope, print_json, Cli, FixExt};
use confidant_core::error::DomainError;

/// #665: `confidant sync`. Read-only by default (fetch, report ahead/behind);
/// `--pull` and `--push` are explicit, confirmed network writes. Refuses no
/// remote/upstream or a diverged branch with stable codes. `--dry-run` never touches the network and reports the state from
/// the last fetch.
///
/// #736: the default report names its own remedy. A report of "N commits
/// behind" that names no next step left the product's author reaching for
/// a bare `git pull` when `confidant sync --pull` already existed, so when
/// `action == "none"` and the branch is ahead or behind, the report prints
/// (and the JSON carries) the exact command that applies the state it just
/// reported. Up-to-date reports, applied writes, and declined confirms
/// carry no remedy; a `--dry-run` report does, qualified as last-fetched.
/// A diverged branch errors with a `fix` naming the explicit reconcile
/// steps instead of a success-envelope remedy.
pub(crate) fn cmd_sync(
    cli: &Cli,
    root: &Path,
    pull: bool,
    push: bool,
    yes: bool,
) -> anyhow::Result<ExitCode> {
    let no_input = cli.no_input;
    let git = |args: &[&str]| confidant_core::write::git(root, args, no_input);

    // Fail closed on a missing repository or an empty remote list before
    // any git command that could reach the network.
    confidant_core::write::require_git_repo(root, no_input)?;
    let remotes = git(&["remote", "-v"])
        .map(|out| parse_git_remotes(&out))
        .unwrap_or_default();
    if remotes.is_empty() {
        return Err(anyhow::Error::new(DomainError::no_remote(
            "no git remote is configured for this vault",
        )));
    }
    let Some((branch, upstream)) = git_upstream(root, no_input) else {
        return Err(anyhow::Error::new(DomainError::no_remote(
            "the current branch has no upstream branch",
        )));
    };
    // The upstream's first path segment is the remote name
    // (`origin/main` → `origin`); verify it is one of the configured
    // remotes rather than trusting the string.
    let remote = upstream.split('/').next().unwrap_or_default().to_owned();
    if !remotes.iter().any(|name| name == &remote) {
        return Err(anyhow::Error::new(DomainError::no_remote(format!(
            "upstream '{upstream}' does not name a configured remote"
        ))));
    }

    // `--dry-run` reports the last-fetched state and never contacts the
    // remote, so it works offline and on a metered connection.
    let mut fetched = false;
    if !cli.dry_run {
        git(&["fetch", "--quiet", &remote]).map_err(|_| {
            anyhow::Error::new(DomainError::invalid(format!(
                "git fetch {remote} failed; check the remote URL and credentials"
            )))
        })?;
        fetched = true;
    }

    let mut state = git_ahead_behind(root, no_input)?;
    if state.ahead > 0 && state.behind > 0 {
        // #736: a diverged branch gets a remedy too, not just a refusal.
        // The generic `not_fast_forward` fix names no branch, upstream, or
        // command, so override it here where both are known: the exact
        // reconcile steps, ending in the sync command that finishes the job.
        // Confidant still never auto-merges and never force-pushes.
        return Err(anyhow::Error::new(DomainError::not_fast_forward(
            state.ahead,
            state.behind,
        ))
        .with_fix(&format!(
            "Reconcile {branch} with {upstream} explicitly, then run `confidant sync --push`: `git fetch {remote}`; `git log --oneline --left-right @{{u}}...HEAD` to see both sides; `git merge {upstream}` (or `git rebase {upstream}`)"
        )));
    }

    let mut action = "none";
    let mut applied = false;
    if pull && state.behind > 0 && !cli.dry_run {
        action = "pull";
        if confirm_sync_write(
            cli,
            yes,
            &format!(
                "Fast-forward {branch} to {upstream} ({} commit(s))?",
                state.behind
            ),
        )? {
            git(&["pull", "--ff-only", "--quiet"]).map_err(|e| {
                let detail = format!("{e:#}");
                if detail.contains("Not possible to fast-forward")
                    || detail.contains("non-fast-forward")
                {
                    anyhow::Error::new(DomainError::not_fast_forward(state.ahead, state.behind))
                } else if detail.contains("would be overwritten")
                    || detail.contains("commit or stash")
                    || detail.contains("commit your changes or stash")
                {
                    // A dirty tree is the common fast-forward refusal; a
                    // credentials message here would send the operator to
                    // the wrong place.
                    anyhow::Error::new(
                        DomainError::conflict(
                            "git pull --ff-only refused: local changes would be overwritten",
                        )
                        .with_fix("Commit or stash your changes, then run `confidant sync --pull`"),
                    )
                } else {
                    anyhow::Error::new(DomainError::invalid(
                        "git pull --ff-only failed; check the remote URL and credentials",
                    ))
                }
            })?;
            state = git_ahead_behind(root, no_input)?;
            applied = true;
        }
    } else if push && state.ahead > 0 && !cli.dry_run {
        action = "push";
        if confirm_sync_write(
            cli,
            yes,
            &format!("Push {} commit(s) to {upstream}?", state.ahead),
        )? {
            // Push HEAD to the upstream branch on the same remote that
            // was fetched and counted. A bare `git push` follows
            // `push.default=simple` (refuses a differently named
            // upstream) and can honour `remote.pushDefault` /
            // `branch.<b>.pushRemote` (a different remote).
            let Some(refspec) = sync_push_refspec(&remote, &upstream) else {
                return Err(anyhow::Error::new(DomainError::no_remote(format!(
                    "upstream '{upstream}' does not name a branch on remote '{remote}'"
                ))));
            };
            git(&["push", "--quiet", &remote, &refspec]).map_err(|e| {
                let detail = format!("{e:#}");
                if detail.contains("non-fast-forward")
                    || detail.contains("fetch first")
                    || detail.contains("stale info")
                {
                    anyhow::Error::new(DomainError::not_fast_forward(state.ahead, state.behind))
                } else {
                    anyhow::Error::new(DomainError::invalid(format!(
                        "git push {remote} failed; check the remote URL and credentials"
                    )))
                }
            })?;
            // `push` updates the remote-tracking ref, so the comparison is
            // current without a second fetch.
            state = git_ahead_behind(root, no_input)?;
            applied = true;
        }
    }

    // #736: the remedy for the state just reported, printed only when the
    // report itself changed nothing. The gate is exactly `action == "none"`
    // with ahead/behind non-zero: an applied write has nothing left to
    // point at, and a requested-but-declined write already names its own
    // command ("pull not confirmed"), so both get no second pointer.
    // `--dry-run` never takes a write branch, so a dry-run report of a
    // behind/ahead state does carry a remedy — qualified below as
    // last-fetched, since dry-run never contacts the remote. A `--pull`
    // request on an ahead-only branch (or `--push` on a behind-only one)
    // likewise falls through with `action == "none"` and names the other
    // direction's command. Diverged never reaches here: it errors above.
    // At most one remedy can exist here — ahead > 0 and behind > 0 is the
    // diverged early return — so this is a single `Option`, not a list.
    let mut remedy: Option<String> = None;
    if action == "none" {
        if state.behind > 0 {
            // A dirty tree qualifies the pull remedy: `--pull` refuses a
            // tree it would overwrite, so the plain fast-forward pointer
            // would send the operator into a refusal. Commit-or-stash
            // first is the path that actually fast-forwards.
            let dirty = git(&["status", "--porcelain"])
                .map(|out| !out.trim().is_empty())
                .unwrap_or(false);
            remedy = Some(if dirty {
                format!(
                    "Commit or stash your changes, then run `confidant sync --pull` to fast-forward {branch} to {upstream} ({} commit(s))",
                    state.behind
                )
            } else {
                format!(
                    "Run `confidant sync --pull` to fast-forward {branch} to {upstream} ({} commit(s))",
                    state.behind
                )
            });
        } else if state.ahead > 0 {
            remedy = Some(format!(
                "Run `confidant sync --push` to push {} commit(s) to {upstream}",
                state.ahead
            ));
        }
    }
    // A dry-run count is last-fetched, not fresh: say so in the remedy
    // itself, so a script branching on `remedy` alone can tell it is stale
    // without also checking `dry_run`/`fetched`.
    if cli.dry_run {
        if let Some(text) = remedy.as_mut() {
            text.push_str(" (as of the last fetch)");
        }
    }

    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "remote": remote,
                "branch": branch,
                "upstream": upstream,
                "ahead": state.ahead,
                "behind": state.behind,
                "fetched": fetched,
                "dry_run": cli.dry_run,
                "action": action,
                "applied": applied,
                "remedy": remedy,
            }),
        ))?;
    } else {
        println!("{branch} -> {upstream} ({remote})");
        println!(
            "{ahead} ahead, {behind} behind ({})",
            if fetched {
                "after fetch"
            } else {
                "last fetched state; --dry-run did not contact the remote"
            },
            ahead = state.ahead,
            behind = state.behind
        );
        if action != "none" {
            if applied {
                println!("{action} complete");
            } else {
                println!("{action} not confirmed; nothing changed");
            }
        }
        if let Some(line) = &remedy {
            println!("{line}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Confirmation for a `sync --pull` / `--push` network write. Unlike the
/// read-only report, these need an explicit yes: interactive sessions are
/// prompted, and non-interactive sessions must pass `--yes` (a usage error,
/// exit 2). Never returns `true` without confirmation.
pub(crate) fn confirm_sync_write(cli: &Cli, yes: bool, question: &str) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    if cli.no_input || cli.json {
        return Err(anyhow::Error::new(DomainError::usage(
            "--pull and --push are network writes; pass --yes with --no-input or --json",
        )));
    }
    confirm_yn(question, false, false)
}
