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

## Encrypted vault vs. plaintext (demo)

Choose the vault's crypto mode up front (see [`spec/0.1.md`](../spec/0.1.md) §2.2 and §14):

| Mode | Use for | Consequences | Agent behavior |
|---|---|---|---|
| **Encrypted** (default) | Real relationship data | `confidant init` generates keys and writes a 24-word recovery phrase once (`--phrase-out <path>` is the agent-safe form; see [Recovery phrase](#recovery-phrase-save-it-then-verify-it)). Record bodies are encrypted in git; ledger lines (`ledger/`), `confidant.toml`, and `import` stay structural plaintext. | For a fresh vault, run `confidant init --create --phrase-out <path>`; for an existing one, ensure `mode` is not `"plaintext"` (never silently copy demo `mode = "plaintext"` into a real vault) and `git status` is clean, then run `confidant init`. Store the recovery phrase offline. |
| **Plaintext opt-out** | Demo, learning, fixtures only (`examples/demo-vault`) | `[crypto] mode = "plaintext"` in `confidant.toml` (valid only while the vault is structurally plaintext — no `keys/` or `enc:` envelopes; cannot downgrade an encrypted vault). Never use for real PII: `git clone` exposes all record content, so never push it to a remote. | Set or keep `[crypto] mode = "plaintext"`, do **not** run `confidant init`, and warn that `git clone` exposes all record content. |

## Create a vault

`confidant init --create` only scaffolds an absent or empty directory (a
directory holding just `.git` and/or `.gitignore` also counts as empty). A
non-empty directory is refused, so a stray `--create` cannot turn a project
checkout into a vault. Git needs an identity first, because init commits:

```sh
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

Then create the vault:

```sh
export CONFIDANT_VAULT="$HOME/vault"     # this process only
confidant init --create --no-input --phrase-out "$HOME/confidant-recovery.txt"
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
the trust anchor. It does **not** create an inbox key or add a git remote.

Packs are optional. `packs = []` is clean: `personal@0.2` is built in and
implicit, so `check` starts with birthdays, cadence, and the `touch` verb.
To add an external pack after init:

```sh
confidant pack add <https-url> --yes
# for coaching:
confidant pack add https://github.com/hirefrank/confidant.git \
  --subdir packs/coaching --yes
```

The pack is vendored under `packs/`, pinned in `confidant.lock`, and listed
in `confidant.toml`. Naming an external pack at init time is a usage error:
init with no packs, then `pack add`.

## Connect a git remote (optional)

`confidant init --create` adds no remote, and local-only is a valid setup.
The difference matters at recovery time:

- **Local-only:** the vault lives on one disk. Back it up some other way —
  `confidant recover` cannot help if the repository was never pushed.
- **Remote:** backups and second-device recovery. The remote holds
  ciphertext only for an encrypted vault; on a second device, clone it and
  run `confidant recover`.

To connect one, run git yourself:

```sh
git remote add origin <url>
git push -u origin main
```

The URL is provider-neutral — whatever your git host gives you. No
Confidant command adds a remote or pushes for you, because credentials and
host keys are yours to supply. `confidant doctor` reports a `git-remote`
check: local-only is fine, an encrypted vault with a remote is fine, and a
remote on a `[crypto] mode = "plaintext"` vault is a **warning**.

**A plaintext-mode vault must not be pushed anywhere.** Every record body is
readable by anyone with access to the repository, including its history.
Plaintext is only for demo, learning, and fixtures.

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
| `confidant doctor` | Vault health + CLI staleness + keychain/device-enrollment state + skills link health + `git-remote` |
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
| `not enrolled (the OS keychain holds no device key)` | Reachable but empty: run `confidant init` / `confidant recover`, or inject `CONFIDANT_DEVICE_KEY` (warning) |
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
