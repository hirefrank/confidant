# Agent setup: install Confidant and its skills

The one-prompt install is canonical in
[`README.md`](../README.md#install). Paste that prompt into an agent; it
installs the CLI, links the embedded skills, asks where the vault is, and
verifies the result.

This page is the long tail: the encrypted-vs-plaintext decision, the
setup/update commands, environment variables, headless hosts, and staying
current.

## Encrypted vault vs. plaintext (demo)

Choose the vault's crypto mode up front (see [`spec/0.1.md`](../spec/0.1.md) §2.2 and §14):

| Mode | Use for | Consequences | Agent behavior |
|---|---|---|---|
| **Encrypted** (default) | Real relationship data | `confidant init` generates keys and prints a 24-word recovery phrase once (store offline). Record bodies are encrypted in git; ledger lines (`ledger/`), `confidant.toml`, and `import` stay structural plaintext. | For a fresh vault, run `confidant init --create`; for an existing one, ensure `mode` is not `"plaintext"` (never silently copy demo `mode = "plaintext"` into a real vault) and `git status` is clean, then run `confidant init`. Store the recovery phrase offline. |
| **Plaintext opt-out** | Demo, learning, fixtures only (`examples/demo-vault`) | `[crypto] mode = "plaintext"` in `confidant.toml` (valid only while the vault is structurally plaintext — no `keys/` or `enc:` envelopes; cannot downgrade an encrypted vault). Never use for real PII: `git clone` exposes all record content. | Set or keep `[crypto] mode = "plaintext"`, do **not** run `confidant init`, and warn that `git clone` exposes all record content. |

## Commands

| Command | What |
|---|---|
| `confidant setup [--agent auto\|all\|a,b] [--force] [--copy] [-v]` | Materialize embedded skills, link into agent skill dirs |
| `confidant update [--agent …] [--force] [-v]` | Report latest release, re-link skills from this binary |
| `confidant doctor` | Vault health + CLI staleness + keychain/device-enrollment state + skills link health |
| `confidant agents` | List supported agents and detection status |
| `confidant which [--skills-dir]` | Print installed skills location |
| `confidant routing` | Print the optional routing snippet |

`--agent auto` (default) links into every detected agent, falling back to
`claude-code` when none is detected. `--agent all` targets all nine supported
agents; a comma list targets exactly those. Unknown names are skipped with a
warning. `--force` replaces existing non-symlink skill dirs (older installs);
`--copy` copies instead of symlinking (note: copies go stale — re-run
`setup` after every CLI upgrade to refresh them); `-v` prints every path.
Every command takes `--json` and `--no-input` per the agent contract.

## Environment

| Variable | What |
|---|---|
| `CONFIDANT_VAULT` | Vault directory (or pass `--vault`) |
| `CONFIDANT_OFFLINE=1` | Skip the release check entirely |
| `CONFIDANT_HOME` | Root for materialized skills (default `~/.local/share/confidant`) |
| `CONFIDANT_SKILLS_DIR` | Single skills parent, overrides `--agent` |

## Headless hosts and agents

Linux containers, cloud VMs, and agent sandboxes usually have no D-Bus
session bus, so the OS keychain (Secret Service) is unreachable. Confidant
fails closed there: loading the device or inbox key errors out instead of
falling back to anything on disk. Keys never live in files — there is no
file-backed keystore, and no `CONFIDANT_KEYCHAIN`-style switch can point at
one (see [`docs/crypto-design.md`](crypto-design.md) §2).

The supported headless path is the env-var overrides, injected per process
by the host's secret store or agent runtime:

| Variable | What |
|---|---|
| `CONFIDANT_DEVICE_KEY` | This device's age identity (`AGE-SECRET-KEY-1…`) |
| `CONFIDANT_INBOX_KEY` | The vault inbox keypair's private half (`AGE-SECRET-KEY-1…`) |
| `CONFIDANT_INBOX_KEY_PREVIOUS` | The rotation-window slot (only during `inbox rotate`) |
| `CONFIDANT_OPERATOR_KEY` | Operator Ed25519 seed (64 hex chars), operator-only commands |

An env var wins over the keychain and holds the same value the keychain
would (`AGE-SECRET-KEY-1…`), so injecting one cannot silently change which
key a command uses. Set it in the process environment only, never in the
vault, a git file, or a shell history line.

`confidant doctor` reports the result as one `device-key` check, with the
same data in human and `--json` output:

| Check message | Meaning |
|---|---|
| `device key comes from CONFIDANT_DEVICE_KEY` | Env-provided; the normal headless state (ok) |
| `device key is in the OS keychain` | Keychain reachable and enrolled (ok) |
| `not enrolled (the OS keychain holds no device key)` | Reachable but empty: run `confidant init` / `confidant recover`, or inject `CONFIDANT_DEVICE_KEY` (warning) |
| `the OS keychain is unreachable (...)` | Headless host or locked keychain; the `fix` field names `CONFIDANT_DEVICE_KEY` and `CONFIDANT_INBOX_KEY` (warning) |

In `--json`, each check is `{id, status, message}` plus `fix` when there is
something to do. A missing key is a warning, not an error: a plaintext demo
vault needs no keys, and a report that still lists every other check is
more useful than a hard failure.

## Staying current (updates)

`confidant doctor` reports how far the local install is behind the latest
GitHub Release (warning only — a stale install never fails `doctor`, and
when GitHub cannot be reached it reads `staleness unknown`). Skills are
version-locked to the CLI: one `confidant --version` covers both. Apply
updates with this loop:

- **CLI:** compare `confidant --version` against the latest GitHub Release
  (https://github.com/hirefrank/confidant/releases), or run
  `confidant update` to be told. If behind, re-run the installer or
  `cargo install confidant-cli`, then `confidant setup` to
  re-point the skill links at the new version dir.
- **Skills:** they re-link from the new binary — no separate step, no tag
  to pin. `doctor` warns (`skills-links`) when a detected agent is missing
  links; fix with `confidant setup --agent auto`.
- **Optional search backend:** the `qmd-search` skill needs the `qmd` binary
  (`npm install -g @tobilu/qmd`); keyword-only `find` works without it.
