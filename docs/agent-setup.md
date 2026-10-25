# Agent setup: install Confidant and its skills

The one-prompt install is canonical in
[`README.md`](../README.md#install). Paste that prompt into an agent; it
installs the CLI and TUI, links the embedded skills, asks where the vault
is, and verifies the result.

This page is the long tail: the encrypted-vs-plaintext decision, the
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
   not a hard block on a fresh install: `confidant doctor` reports it as
   a warning unless SSH signers are configured, when it is an error —
   SSH signature verification needs git >= 2.34, so upgrade before
   configuring signers.
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

## Encrypted vault vs. plaintext

Choose the vault's crypto mode up front (see [`spec/0.1.md`](../spec/0.1.md) §2.2 and §14):

| Mode | Use for | Consequences | Agent behavior |
|---|---|---|---|
| **Encrypted** (default) | Real relationship data | `confidant init` generates keys and writes a 24-word recovery phrase once (`--phrase-out <path>` is the agent-safe form; see [Recovery phrase](#recovery-phrase-save-it-then-verify-it)). Record bodies are encrypted in git; ledger lines (`ledger/`), `confidant.toml`, and `import` stay structural plaintext. | For a **new** vault, run `confidant init --create --phrase-out <path>` (optional `--remote <url>`). For an existing directory that is not yet initialized, ensure `mode` is not `"plaintext"` (never silently copy demo `mode = "plaintext"` into a real vault) and `git status` is clean, then run `confidant init`. To put an already-initialized vault on another device, clone it and run `keys device-add` — not `init`. Store the recovery phrase offline. |
| **Plaintext** | Vaults where unencrypted record bodies are acceptable (`examples/demo-vault` is one) | `[crypto] mode = "plaintext"` in `confidant.toml` (valid only while the vault is structurally plaintext — no `keys/` or `enc:` envelopes; cannot downgrade an encrypted vault). Every record body, history included, is readable by anyone with the repo or a clone, and a remote on such a vault is reported as a `git-remote` warning. | Set or keep `[crypto] mode = "plaintext"`, do **not** run `confidant init`, explain the exposure, and let the operator choose. |

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
confidant init --create --no-input --phrase-out "$HOME/confidant-recovery.txt"
# or, if you already have a remote URL:
# confidant init --create --remote <url> --no-input --phrase-out "$HOME/confidant-recovery.txt"
```

For an interactive shell you can add the export to your shell rc, but in a
non-interactive or agent session export it directly and/or pass `--vault
<path>` explicitly (see [Environment](#environment)); never rely on
`source ~/.bashrc` there.

The command creates the directory and runs `git init` with branch `main`
(no manual `master` → `main` rename), reports the branch it created, writes
`.gitignore` (`.confidant/`) and a minimal `confidant.toml` with a fresh
`vault_id` and `packs = []`, commits the skeleton, then creates the vault
lookup key, the `vault:shared` client, the signed operator certificate, and
the trust anchor. It does **not** create an inbox key. Without `--remote` it
adds no git remote. It never pushes.

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
  a second device cannot clone what was never pushed, and `confidant recover`
  cannot help if the repository is gone.
- **Remote:** backups and second-device enrollment. The remote holds
  ciphertext only for an encrypted vault. On another device, clone it and
  run `confidant keys device-add` (not `init`, and not `recover` unless
  every enrolled device is lost). See [New device, existing vault](#new-device-existing-vault).

To set origin at init time (still no push):

```sh
confidant init --create --remote <url> --no-input --phrase-out "$HOME/confidant-recovery.txt"
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
actually works, or a PAT stored via the git credential helper / OS
keychain — never pasted into a repo config, never committed, and never
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
(local-only is fine; an encrypted vault with a remote is fine; a remote on
a `[crypto] mode = "plaintext"` vault is a **warning**) and a
`local-commits` check with ahead/behind from the last fetch. See
[`docs/sync.md`](sync.md).

**A plaintext-mode vault on a remote is a deliberate exposure.** Every record
body, history included, is readable by anyone with access to the repository,
and `confidant doctor` reports it as a `git-remote` warning. If that is not
the tradeoff you want, remove the remote; anything already pushed stays
readable in its history.

## New device, existing vault

`confidant init` always creates a **new** vault (new `vault_id`, new keys,
new recovery phrase). Running it on a second machine does not attach that
machine to the vault you already have.

| Situation | What to run |
|---|---|
| New vault on this machine | `confidant init --create` (optional `--remote <url>`) |
| This vault on another device, and an enrolled device still works | Clone the repo, then `confidant keys device-add` (`--initiate` on the new device, `--from-request` on an enrolled one) |
| Every enrolled device is lost | Clone the repo, then `confidant recover` (this rotates and revokes the current recovery phrase) |

Typical second-device flow (confirm `git ls-remote <url>` succeeds before
the clone — see [Connect a git remote](#connect-a-git-remote-optional) for
the probe, including its non-interactive form and failure modes):

```sh
git clone <url> ~/vault
export CONFIDANT_VAULT="$HOME/vault"
# on the new device:
confidant keys device-add --initiate --label "laptop-2" --output ~/device-add-request.toml
# copy the request to an enrolled device, confirm the fingerprint out of band, then:
confidant keys device-add --from-request ~/device-add-request.toml
```

Headless hosts without an OS keychain: the **new** device needs only
`CONFIDANT_DEVICE_KEY` for `keys device-add --initiate`. The already-enrolled
device that runs `--from-request` is the one that needs
`CONFIDANT_OPERATOR_KEY` (see
[Headless hosts and agents](#headless-hosts-and-agents)). Enrollment of a
second headless device is `keys device-add`, not `init`.

## Recovery phrase: save it, then verify it

Encrypted `init` creates a 24-word recovery phrase — the only way back if
every device is lost. In an agent session, never let it reach the
transcript or a log. Use:

```sh
confidant init --create --no-input --phrase-out <path>
```

`--phrase-out` writes the phrase to a **new** file (mode `0600`), prints only
the path, and refuses to overwrite an existing file. Never tell an agent to
echo, copy, or read the phrase into chat.

After `init`:

1. Verify the file before it leaves the machine — the human-only,
   read-only check:

   ```sh
   confidant keys verify-recovery --phrase-file <path>
   ```

   It writes nothing and enrolls nothing, and never prints the phrase.
2. Move the file offline (paper, password manager, or offline media) and
   delete the local copy.
3. After `recover` or a `keys shred` rotation, run the check again against
   the saved copy to confirm it still matches the vault.

Agents must not handle or pipe the phrase.

## Commands

| Command | What |
|---|---|
| `confidant setup [--agent auto\|all\|a,b] [--force] [--copy] [-v]` | Materialize embedded skills, link into agent skill dirs |
| `confidant update [--agent …] [--force] [-v]` | Report latest release, re-link skills from this binary |
| `confidant doctor` | Vault health + CLI staleness + keychain/device-enrollment state + skills link health + `git-remote` + `local-commits` |
| `confidant sync [--dry-run] [--pull\|--push] [--yes]` | Fetch and report ahead/behind; `--pull`/`--push` are confirmed network writes |
| `confidant keys verify-recovery [--phrase-file <path>]` | Read-only recovery-phrase check; human-only — never ask an agent to read or pipe the phrase |
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

On a desktop, keys live in the OS keychain (Secret Service on Linux, the
macOS keychain) and that is the default. On a headless host — a Linux
container, cloud VM, or agent sandbox with no D-Bus session bus — Confidant
fails closed: loading the device or inbox key errors out instead of falling
back to anything on disk. Keys never live in files: there is no file-backed
keystore, and no `CONFIDANT_KEYCHAIN`-style switch can point at one (see
[`docs/crypto-design.md`](crypto-design.md) §2).

The supported headless path is to supply the keys in the process
environment **before** `confidant init`. Generate them once, store them in
the host's secret store, and re-inject them into each session:

```sh
# Device identity (age). age-keygen also prints comment/public-key text
# (`# created:`, `# public key:`); only the AGE-SECRET-KEY-1... line is the
# identity. The CLI rejects a value that combines lines.
export CONFIDANT_DEVICE_KEY="$(age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-')"

# Operator Ed25519 seed: 32 random bytes, 64 hex chars.
export CONFIDANT_OPERATOR_KEY="$(openssl rand -hex 32)"

export CONFIDANT_VAULT="$HOME/vault"
confidant init --create --no-input --phrase-out "$HOME/confidant-recovery.txt"
```

`age-keygen` (from `age`) or an equivalent existing tool is fine for the
device identity; `openssl rand -hex 32` is just a CSPRNG for the operator
seed. Keep only the `AGE-SECRET-KEY-1…` line: `age-keygen` prints
`# created:` and `# public key:` lines too, and a value that contains them
is not an identity and is rejected. The variables are **per-process
secrets**, not a file fallback: the CLI reads them from the environment of
the process that runs it, so export them in that process or have the host's
secret store inject them. Do not write them into the vault, a git file, or
a shell history line. Generate each value **once** and retrieve the stored
copy later; re-running `age-keygen` or `openssl rand` would create a new
identity that no longer opens the vault.

To enroll a **second** headless device into an existing vault, generate a
**new** identity for that host (do not copy another device's
`CONFIDANT_DEVICE_KEY`), export it, clone the vault, then run
`keys device-add --initiate`. The command uses the env identity and does
not write a keychain. Approve the request from an enrolled device with
`--from-request`. Do not run `init` on the second device, and do not run
`recover` unless every enrolled device is lost. There is no `--key-out`;
keys never live in files.

```sh
export CONFIDANT_DEVICE_KEY="$(age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-')"
git clone <url> ~/vault
export CONFIDANT_VAULT="$HOME/vault"
confidant keys device-add --initiate --label "headless-2" --output ~/device-add-request.toml
# copy the request to an enrolled device, confirm the fingerprint, then:
# confidant keys device-add --from-request ~/device-add-request.toml
```

On a desktop the keychain is still the default; an env var wins over it
for the same key and holds the value the keychain would (an age identity
for the device or inbox key, a hex seed for the operator key), so injecting
one cannot silently change which key a command uses.

Additional variables for later commands:

| Variable | What |
|---|---|
| `CONFIDANT_DEVICE_KEY` | This device's age identity (`AGE-SECRET-KEY-1…`) |
| `CONFIDANT_OPERATOR_KEY` | Operator Ed25519 seed (64 hex chars), operator-only commands |
| `CONFIDANT_INBOX_KEY` | The vault inbox keypair's private half (`AGE-SECRET-KEY-1…`) |
| `CONFIDANT_INBOX_KEY_PREVIOUS` | The rotation-window slot (only during `inbox rotate`) |

`confidant doctor` reports the device key as one `device-key` check, with the
same data in human and `--json` output:

| Check message | Meaning |
|---|---|
| `device key comes from CONFIDANT_DEVICE_KEY` | Env-provided; the normal headless state (ok) |
| `device key is in the OS keychain` | Keychain reachable and enrolled (ok) |
| `not enrolled (the OS keychain holds no device key)` | Reachable but empty: run `confidant init` (new vault), clone and `confidant keys device-add` (existing vault), or `confidant recover` only if every enrolled device is lost; on a headless host inject `CONFIDANT_DEVICE_KEY` (warning) |
| `the OS keychain is unreachable (...)` | Headless host or locked keychain; the `fix` field names `CONFIDANT_DEVICE_KEY` and `CONFIDANT_OPERATOR_KEY` (warning) |

Before init on a headless host, doctor's hint names both variables to set —
that is the pre-init path above, not a fallback to a key file. After init,
an inbox workflow also needs `CONFIDANT_INBOX_KEY`.

In `--json`, each check is `{id, status, message}` plus `fix` when there is
something to do. A missing key is a warning, not an error: a plaintext demo
vault needs no keys, and a report that still lists every other check is
more useful than a hard failure.

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
