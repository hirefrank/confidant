# Sync: the explicit git boundary (#665)

Writes commit to the vault's local git repository. Nothing is fetched,
pulled, or pushed as a side effect of a write, a read, or launching the
TUI. `confidant sync` is the one command that talks to a remote, and it
only does the work you ask for.

This is deliberate:

- A write must not depend on the network. `confidant log session` keeps
  working offline, on a plane, or with the remote down.
- A push is a privacy boundary. Only an encrypted vault may cross it.
- A pull that merges automatically can create conflicts in the middle of
  an edit. Confidant never auto-merges and never force-pushes.

`confidant doctor` and the TUI show what is waiting, so the boundary is
visible without being automatic.

## Visibility (offline)

`confidant doctor` includes a `local-commits` check. It is read-only and
offline: it reads `@{u}` and the last fetch, and never calls `fetch`.

```sh
confidant doctor
# ok      local-commits: up to date with origin/main (as of the last fetch)
# warning local-commits: 2 local commit(s) not pushed to origin/main
#         fix: Run `confidant sync --push`
```

- No remote, no upstream, or a repo with no commits is `ok`, not an
  error. Local-only is a valid setup.
- Ahead, behind, or diverged is a warning with the counts and the next
  command. It never blocks a write and never changes the exit code.

The TUI reads the same state through `confidant sync --dry-run` at launch
(again: no network) and shows `sync 2 unpushed` in the header only when
there is something to report. `q` then offers `Push 2 commits?`: `y`
pushes and quits, `n` quits without pushing, `Esc` stays. See
[`docs/tui.md`](tui.md#unpushed-commits-and-quitting).

## The command

```sh
confidant sync                 # fetch, report ahead/behind, exit 0
confidant sync --dry-run       # report the last-fetched state; no network
confidant sync --pull          # fetch, then fast-forward after confirmation
confidant sync --push          # fetch, then push after confirmation
```

`sync` is read-only unless `--pull` or `--push` is passed. Both are
network writes and are explicit:

- Interactive: the command asks `Fast-forward main to origin/main (2
  commits)? [y/N]` or `Push 2 commit(s) to origin/main? [y/N]`. Only `y`
  or `yes` proceeds; EOF means no.
- Non-interactive (`--no-input`, or `--json`): pass `--yes`. Without it
  the command exits 2 with `usage_error` and touches nothing. The TUI
  passes `--yes` only after the operator confirms the quit prompt.

Under `--no-input`, git also runs ssh with `-o BatchMode=yes`, so a key
passphrase or an unknown host key cannot hang an agent or the TUI (which
would otherwise draw the prompt over its own screen). The flag is
appended to whichever client is already configured — `GIT_SSH_COMMAND`,
`GIT_SSH`, or `core.sshCommand`, and plain `ssh` when none is — so an
existing `-p`/`-i` setup keeps working. This assumes an
OpenSSH-compatible client: if `core.sshCommand` is `plink`, set
`GIT_SSH_COMMAND` to an OpenSSH client for non-interactive runs.

`--dry-run` reports the state from the last fetch and does not contact the
remote, so it is safe offline and on a metered connection. `--pull` uses
`git pull --ff-only`; `--push` pushes to the configured upstream without a
force flag.

### JSON

```json
{
  "ok": true,
  "schema_version": "1",
  "vault": "/home/operator/vault",
  "remote": "origin",
  "branch": "main",
  "upstream": "origin/main",
  "ahead": 2,
  "behind": 0,
  "crypto_mode": "encrypted",
  "fetched": true,
  "dry_run": false,
  "action": "none",
  "applied": false
}
```

`action` is `none`, `pull`, or `push`; `applied` is true only when a
confirmed write ran. `fetched` is false for `--dry-run`.

### Refusals (stable codes)

| Code | When |
|---|---|
| `E_NO_REMOTE` | No git remote, or the current branch has no upstream. Exit 1. |
| `E_PLAINTEXT_REMOTE` | The vault is structurally plaintext. Exit 1, before any network access, even for `--dry-run`. |
| `E_NOT_FAST_FORWARD` | Local and remote each have commits the other lacks (diverged). Exit 1. |
| `E_CONFLICT` | `--pull` would overwrite uncommitted local changes. Commit or stash, then retry. Exit 1. |
| `usage_error` | `--pull`/`--push` with `--no-input`/`--json` and no `--yes`. Exit 2. |

**A plaintext vault is never synced.** Record bodies would be readable by
anyone with repository access, which defeats the encryption boundary. Run
`confidant init` to encrypt the vault, or remove the remote and keep it
local-only. The `git-remote` doctor check warns about this setup too.

If the branch diverged, reconcile it yourself:

```sh
git fetch origin
git log --oneline --left-right @{u}...HEAD   # see both sides
git merge origin/main                         # or: git rebase origin/main
confidant sync --push
```

Confidant never runs that merge or rebase for you, and never force-pushes.

## The manual rhythm

A normal day, with an encrypted vault and an `origin` remote:

```sh
confidant log session p-01… 60m paid --date 2026-10-20
# one local commit; nothing left the machine

confidant doctor        # local-commits: 1 local commit(s) not pushed
confidant sync --push   # fetch, confirm, push
```

On a second device:

```sh
confidant sync --pull   # fetch, confirm, fast-forward
# then read or write; each write commits locally
confidant sync --push
```

If you are not sure whether to pull, `confidant sync --dry-run` shows the
counts from the last fetch without touching the network. Run
`confidant sync` when you want a fresh fetch.

## Opt-in continuous sync

There is no daemon in the CLI. If you want the remote to receive commits
without remembering `confidant sync --push`, install a user-level timer
that runs the command on a schedule. Start from the units in
[`contrib/`](../contrib/):

- [`contrib/systemd/confidant-sync.service`](../contrib/systemd/confidant-sync.service)
  and [`contrib/systemd/confidant-sync.timer`](../contrib/systemd/confidant-sync.timer)
  for Linux (systemd user units).
- [`contrib/launchd/com.confidant.sync.plist`](../contrib/launchd/com.confidant.sync.plist)
  for macOS (launchd user agent).

The service runs:

```sh
confidant sync --push --yes --no-input
```

It fetches, refuses if the branch diverged, and otherwise pushes local
commits. It never pulls, never merges, and never forces. Because it is
non-interactive it needs `--yes`; there is no prompt to answer.

### systemd (Linux)

```sh
mkdir -p ~/.config/systemd/user
cp contrib/systemd/confidant-sync.* ~/.config/systemd/user/
# Edit the vault path and binary path in the .service file first.
systemctl --user daemon-reload
systemctl --user enable --now confidant-sync.timer
systemctl --user list-timers confidant-sync.timer
journalctl --user -u confidant-sync.service   # last run
```

The timer runs 5 minutes after login and every 15 minutes after that
(`OnUnitActiveSec=15min`, with a small randomized delay). `Persistent=true`
catches up after the machine was off.

### launchd (macOS)

```sh
cp contrib/launchd/com.confidant.sync.plist ~/Library/LaunchAgents/
# Edit CONFIDANT_VAULT and the binary path first.
launchctl load ~/Library/LaunchAgents/com.confidant.sync.plist
launchctl list | grep com.confidant.sync
```

`StartInterval` is 900 seconds. `RunAtLoad` runs once when the agent loads.

Both examples are opt-in templates, not installed by `confidant setup`.
A timer that pushes ciphertext commits is fine for an encrypted vault; on a
plaintext vault the command refuses with `E_PLAINTEXT_REMOTE` every run,
which is the guard working as intended.
