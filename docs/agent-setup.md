# Agent setup: install Confidant and its skills

The one-prompt install is canonical in
[`README.md`](../README.md#install). Paste that prompt into an agent; it
installs the CLI and TUI, links the embedded skills, asks where the vault
is, and verifies the result.

This page is the long tail: what a vault looks like on disk, the
setup/update commands, environment variables, headless hosts, and staying
current.

## Install

```sh
cargo install confidant-cli confidant-tui
confidant setup --agent auto
```

Install the CLI and TUI from the same release so their versions match;
`confidant tui` and `confidant doctor` warn when they differ (see
[TUI versions](#tui-versions)). This needs Rust 1.88+. If `rustc --version`
fails with "no default is configured", run `rustup default stable` and
retry. Put `~/.cargo/bin` on `PATH` first
(`export PATH="$HOME/.cargo/bin:$PATH"`), or the next step fails with
`confidant: command not found`.

Prebuilt binaries for macOS and Linux (x86_64) are on
[GitHub Releases](https://github.com/hirefrank/confidant/releases); take
both from the same release and verify the archive against the published
`.sha256` (or `gh attestation verify <archive> --repo hirefrank/confidant`).
Windows users run under WSL2.

## Git first: required before any vault step

A vault is a git repo: `init` scaffolds one and commits into it, a second
device clones one, and sync pushes and pulls one. Check git up front, in
this order, before any vault step — not at the first failure, when it is
hardest to tell git-missing from git-unauthenticated from something else.
One exception, made explicit in item 3: credentials cannot be probed up
front because no remote URL is known yet, so they are checked where the
URL is known instead. This is the long form of step 3 of the install prompt in
[`README.md`](../README.md#install); that prompt is canonical.

1. **Git installed, new enough.** Run `git --version`. If git is missing,
   install it and re-check before continuing: macOS
   `xcode-select --install` or `brew install git`; Linux via the distro
   package manager (`apt install git`, `dnf install git`, or
   `pacman -S git`); Windows runs under WSL2, so install git inside WSL2
   with that distro's package manager (for example `apt install git` on
   Ubuntu/Debian, `dnf install git` on Fedora, `pacman -S git` on Arch).
   If the version is below 2.34.0, upgrade (strongly recommended):
   macOS `brew upgrade git`, Linux `apt upgrade git`, `dnf upgrade git`,
   or `pacman -Syu git` (inside WSL2 for Windows). Below the floor is
   not a hard block on a fresh install: `confidant doctor` reports it as a
   warning, since older git is still usable for the commands Confidant
   runs. Upgrade when you can.
2. **Git identity.** `init` commits, so it needs one. Check first with
   `git config --global user.name` and `git config --global user.email`,
   and set only values that are unset — do not overwrite an existing
   identity. If a value is missing, ask the operator for it (do not
   invent it) and set it before `init`:

   ```sh
   git config --global user.name "Your Name"
   git config --global user.email "you@example.com"
   ```

3. **Git credentials — checked where the URL is known, not here.** At
   this point no remote URL is known yet, so there is nothing to probe:
   do not ask for one out of order and do not silently defer a probe
   framed as happening now. The probe lives in
   [Connect a git remote](#connect-a-git-remote-optional) and runs
   immediately before the first clone or first push that uses the URL —
   never as a precondition for `init --remote`, which only sets `origin`
   and never contacts the host. In short: git installed and working
   does **not** mean a private clone works (public clones can succeed
   while a private vault clone fails for lack of a credential for the
   host), and `GIT_TERMINAL_PROMPT=0 git ls-remote <url>` succeeding is
   the gate. `gh auth status` is a diagnostic only, never a second gate:
   a clone that already succeeds via an SSH key or a PAT in the
   credential helper passes even when `gh` is not logged in, and on a
   non-GitHub host a `gh` login is irrelevant.
4. **Local-only is different.** Git is still required for `init`, but
   remote auth is not — do not conflate the two: a missing credential is
   not a blocker for a local-only vault.

## What a vault is on disk

A vault is a directory of plain text: `confidant.toml`, `ledger/`, and one
Markdown record per person, org, deal, interaction, and note. There is one
kind of vault, and no mode to choose. `examples/demo-vault` is the same kind
of vault filled with fake people.

The privacy perimeter is the operator's own machines and a **private** git
remote, with full-disk encryption on (LUKS, FileVault): see
[`docs/architecture.md`](architecture.md) §3–§4. So:

- Record bodies, names, and ledger lines are readable by anyone who can read
  the repo. Keep the repo private, and do not put anything in a vault that
  the repo's readers must not see.
- `confidant doctor`'s `git-remote` check refuses `http://` and `git://`
  remotes and warns on transports it cannot verify, so the vault does not
  cross the network readable.
- `no-ai` is the only in-data boundary: it keeps marked records out of
  `find`, `context`, `allowlist`, MCP, and the search corpus. It is an
  exposure control, not access control (`docs/privacy.md`).

## Create a vault

`confidant init --create` only scaffolds an absent or empty directory (a
directory holding just `.git` and/or `.gitignore` also counts as empty). A
non-empty directory is refused, so a stray `--create` cannot turn a project
checkout into a vault. Git needs an identity first, because init commits — check first and
set only if unset, as in [Git first](#git-first-required-before-any-vault-step)
§2 (the identity block lives there, not here).

Then create the vault. `--remote <url>` is optional and only sets `origin`
(it does not push):

```sh
export CONFIDANT_VAULT="$HOME/vault"     # this process only
confidant init --create --no-input
# or, if you already have a remote URL:
# confidant init --create --remote <url> --no-input
```

For an interactive shell you can add the export to your shell rc, but in a
non-interactive or agent session export it directly and/or pass `--vault
<path>` explicitly (see [Environment](#environment)); never rely on
`source ~/.bashrc` there.

The command creates the directory and runs `git init` with branch `main`
(no manual `master` → `main` rename), reports the branch it created, writes
`.gitignore` (`.confidant/`) and a minimal `confidant.toml` with a fresh
`vault_id` and `packs = []`, creates the collection directories, and commits
the skeleton. There is no secret to store and no enrollment step. Without
`--remote` it adds no git remote. It never pushes.

Packs are optional. `packs = []` is clean: `personal@0.2` is built in and
implicit, so `check` starts with birthdays, cadence, and the `touch` verb.
To add another pack after init:

```sh
confidant pack add <https-url> --yes
# or a local directory you authored:
confidant pack add --from-dir ~/confidant-packs/my-pack --yes
```

The pack is vendored under `packs/`, pinned in `confidant.lock`, and listed
in `confidant.toml`. Naming any other pack at init time is a usage error:
init with no packs, then `pack add`.

## Connect a git remote (optional)

Local-only is a valid setup. A remote is what makes backup and putting the
vault on another device possible:

- **Local-only:** the vault lives on one disk. Back it up some other way —
  a second device cannot clone what was never pushed, and a lost disk with
  no copy and no remote is gone.
- **Remote:** backups and a second device. Keep the remote **private**: it
  holds the vault as plaintext files. On another device, clone it and start
  reading; there is no enrollment step. See
  [New device, existing vault](#new-device-existing-vault).

To set origin at init time (still no push):

```sh
confidant init --create --remote <url> --no-input
git push -u origin main    # you run this; credentials and host keys stay yours
```

Before that first push — and before any clone below — probe the URL,
non-interactively so a missing credential fails instead of hanging on
a prompt in an agent shell: `GIT_TERMINAL_PROMPT=0 git ls-remote <url>`
must succeed. That success is the gate. If it fails, tell the two
failures apart: an auth failure is a credentials problem to fix first,
not a vault problem; a repository-not-found failure means the repo does
not exist on the host yet — create it there first, then re-probe
(credentials that are not broken do not need fixing). `gh auth status`
is only a diagnostic, never a second gate: it matters only when
`ls-remote` also fails and the chosen route is GitHub-over-HTTPS via
`gh`. Recommended default on a GitHub host: `gh auth login` (the device
flow suits headless/agent machines; an interactive login registers `gh`
as git's credential helper, so plain clone/pull/push work on the HTTPS
route). After a non-interactive `gh auth login --with-token`, run
`gh auth setup-git` separately — that login alone does not register the
helper. If the operator chose SSH during login, the helper claim does
not apply at all. Alternatives: an SSH key, where SSH to the host
actually works, or a PAT stored via the git credential helper or the OS
credential store — never pasted into a repo config, never committed, and never
an account password (GitHub rejects passwords for git operations). A
token that only exists somewhere else (for example one an agent can
only use through an API) does not count: if it cannot be handed to git,
the clone path is not working yet.

If the vault already exists, run git yourself:

```sh
git remote add origin <url>
git push -u origin main
```

The URL is provider-neutral — whatever your git host gives you.
`confidant init --create --remote <url>` is the one Confidant command that
adds `origin`; it never pushes. After the first `git push -u origin main`,
use `confidant sync` to see ahead/behind and `confidant sync --push` /
`--pull` for explicit, confirmed transfers. Nothing pushes or pulls as a
side effect of a write. `confidant doctor` reports a `git-remote` check
(local-only is fine; a private remote over `https://` or `ssh://` is fine;
a cleartext or unverifiable transport warns) and a `local-commits` check with
ahead/behind from the last fetch. See [`docs/sync.md`](sync.md).

**The remote must be private.** Every record body, history included, is
readable by anyone with access to the repository. Confidant cannot see
whether a host's repository is private, so that is the operator's setting to
get right. If it is not the tradeoff you want, remove the remote; anything
already pushed stays readable in its history (ADR-5).

## New device, existing vault

`confidant init` always creates a **new** vault. To use the vault you already
have on another machine, clone it:

```sh
git clone <url> ~/vault
export CONFIDANT_VAULT="$HOME/vault"
confidant check --json --no-input
```

That is the whole flow — there is no enrollment, key handoff, or trust anchor
to copy, because the vault holds no key material. Confirm
`git ls-remote <url>` succeeds before the clone (see
[Connect a git remote](#connect-a-git-remote-optional) for the probe,
including its non-interactive form and failure modes).

Do not run `init` on the second machine: it scaffolds a different vault, with
a different `vault_id`, next to the clone. Keep the two copies in step with
`confidant sync`; a machine that has not pulled still reads its own
last-fetched copy.

## Commands

| Command | What |
|---|---|
| `confidant setup [--agent auto\|all\|a,b] [--force] [--copy] [-v]` | Materialize embedded skills, link into agent skill dirs |
| `confidant update [--agent …] [--force] [-v]` | Report latest release, re-link skills from this binary |
| `confidant doctor` | Vault health + CLI staleness + skills link health + `git-remote` + `local-commits` |
| `confidant sync [--dry-run] [--pull\|--push] [--yes]` | Fetch and report ahead/behind; `--pull`/`--push` are confirmed network writes |
| `confidant agents` | List supported agents and detection status |
| `confidant which [--skills-dir]` | Print installed skills location |
| `confidant routing` | Print the optional routing snippet |

`--agent auto` (default) links into every detected agent, falling back to
`claude-code` when none is detected. `--agent all` targets all nine supported
agents; a comma list targets exactly those. Unknown names are skipped with a
warning. `--force` replaces existing non-symlink skill dirs (older installs);
`--copy` copies instead of symlinking (note: copies go stale — re-run
`setup` after every CLI upgrade to refresh them); `-v` prints every path and
adds the optional qmd note ([below](#optional-search-backend-qmd)).
Every command takes `--json` and `--no-input` per the agent contract.

## Local packs

The `pack-author` skill walks an agent through the decision: a pack for new
declarative claims or checks, a skill-only workflow when existing records
and notes suffice, and a core change when new Rust logic is needed.

A pack is data plus agent text. It can declare fields, verbs, edge kinds,
finding codes, check keys, and parameters for existing rule kinds; it cannot
run code or define a new kind. Keep the source outside the vault:

```sh
confidant pack init ~/confidant-packs/<name>
confidant pack add --from-dir ~/confidant-packs/<name>        # review, writes nothing
confidant pack add --from-dir ~/confidant-packs/<name> --yes  # install
confidant check --json --no-input
confidant pack verify
```

`pack init` scaffolds `manifest.toml`, `SKILL.md`, `<version>.md`, and
`README.md`; it refuses a non-empty directory or a symlink and validates the
generated pack. Without `--yes`, `pack add --from-dir` is read-only: it
prints the hash, claims, file list, and skill text for review. After editing
the source, bump `[pack].version` and review the change before applying it:

```sh
confidant pack update <name> --from-dir ~/confidant-packs/<name>
confidant pack update <name> --from-dir ~/confidant-packs/<name> --yes
```

`pack update` prints the diff and stops without `--yes`. The vendored tree
under the vault is generated and pinned; edit the source directory instead.

Migrating a pack with existing data: `pack add --yes` refuses when the vault
already sets the pack's `[checks]` keys or vendors its copy but does not list
it. Add `"<name>@<version>"` to `packs` in `confidant.toml` first (or remove
the dependent `[checks]` keys), then re-run. If the vault already has the
pack's data/checks, `pack add --from-dir <dir> --allow-unresolved --yes`
installs over it: only the pre-check is skipped, the post-check and `check`
still gate, and unrelated errors roll back. The flag needs `--yes`; without
it, `pack add` stays the read-only review. `pack remove --yes` refuses while
ledger lines, metrics, or `[checks]` keys still use the pack, so remove or
migrate those entries first, or keep the pack installed; a remove-side flag
is not available yet (#699). The errors name the workaround.

A local pack is unsigned but hash-pinned, so `pack verify` catches drift.
The operator must review the manifest and `SKILL.md`: the skill text is
served to the agent as instructions. Packs cannot widen the §12 allowlist or
read `no-ai` content, and the CLI enforces those limits regardless of pack
text.

## Environment

| Variable | What |
|---|---|
| `CONFIDANT_VAULT` | Vault directory (or pass `--vault`) |
| `CONFIDANT_OFFLINE=1` | Skip the release check entirely |
| `CONFIDANT_HOME` | Root for materialized skills (default `~/.local/share/confidant`) |
| `CONFIDANT_SKILLS_DIR` | Single skills parent, overrides `--agent` |

Export `CONFIDANT_VAULT` in the process that runs Confidant, or pass
`--vault <path>` explicitly. Do **not** rely on `source ~/.bashrc` in a
non-interactive or agent shell: a typical Arch `.bashrc` starts with
`[[ $- != *i* ]] && return`, so the export below that guard is skipped and
the command sees an empty — or stale — value. A stale `CONFIDANT_VAULT`
wins over `default_vault` and directory walk-up, which can make `check` and
`doctor` report on a different vault than the one you meant to inspect. If
you keep the export in a shell rc for interactive use, still pass
`--vault` in scripts and agent sessions. Every `--json` result includes the
resolved `vault` path, so a script can confirm which vault it read.

## Headless hosts and agents

A headless host needs nothing extra. There is no OS credential store to
reach, no secret to inject, and no per-device state to enroll: a vault is
plain files (see [What a vault is on disk](#what-a-vault-is-on-disk)).
`init`, `check`, `find`, and the write path are ordinary file operations, so
a container, cloud VM, or agent sandbox behaves the same as a laptop.

What a headless host does need is the same care as any other machine:

- The disk holding the vault must be full-disk encrypted, because that is
  the perimeter (ADR-4). A cloud VM's volume encryption is the provider's
  setting; check it, or keep the only copy on a machine you control.
- Any copy of the vault on that host is readable by whoever administers it.
  `no-ai` shapes what agents read through Confidant; it does not make the
  files secret from root on the box.
- A host that runs an agent needs git and a git credential for the private
  remote, exactly like a desktop. Keep those credentials out of the vault
  and out of the agent's prompt (see `docs/sync.md`).

In `--json`, each `doctor` check is `{id, status, message}` plus `fix` when
there is something to do.

## TUI versions

`confidant tui` shells out to the first `confidant-tui` on `PATH`; the two
binaries must come from the same release. Install them together
(`cargo install confidant-cli confidant-tui`, or both from one GitHub
Release) and upgrade both together. `confidant tui` and `confidant doctor`
warn when their versions differ.

## Staying current (updates)

`confidant doctor` reports how far the local install is behind the latest
GitHub Release (warning only — a stale install never fails `doctor`, and
when GitHub cannot be reached it reads `staleness unknown`). Skills are
version-locked to the CLI and share its version string. Apply updates with
this loop:

- **CLI and TUI:** compare `confidant --version` and
  `confidant-tui --version` against the latest GitHub Release
  (https://github.com/hirefrank/confidant/releases), or run
  `confidant update` to be told. If behind, re-run the installer or
  `cargo install confidant-cli confidant-tui`, then `confidant setup` to
  re-point the skill links at the new version dir. Upgrading only one of
  the two is what trips the version warning.
- **Skills:** they re-link from the new binary — no separate step, no tag
  to pin. `doctor` warns (`skills-links`) when a detected agent is missing
  links; fix with `confidant setup --agent auto`.

## Optional search backend (qmd)

Plain `confidant find` needs nothing. The `qmd-search` skill is optional and
needs the `qmd` binary (`npm install -g @tobilu/qmd`). `confidant setup -v`
mentions this once; normal setup output stays quiet about it. Without qmd,
the skill falls back to `confidant find` and says so.
