# Agent setup: install Confidant and its skills

One page for operators and their agents. The copy/paste prompt below is the
whole install — drop it into an agent and it does the rest.

## Copy/paste install prompt

```text
Set up Confidant (relationship memory you own — a CLI plus embedded agent skills) on this machine:

1. Install the CLI: `cargo install confidant-cli` (needs a Rust
   toolchain 1.88+; check with `rustc --version`). This provides the
   `confidant` binary. Make sure `~/.cargo/bin` is on PATH first
   (`export PATH="$HOME/.cargo/bin:$PATH"`) or the next step fails with
   `confidant: command not found`. Verify with `confidant --help`.
   (No Rust toolchain? Download the `confidant` binary + installer from
   the latest GitHub Release at
   https://github.com/hirefrank/confidant/releases instead — and verify
   the downloaded `.tar.xz`/`.zip` first: check the published `.sha256`
   checksum file (that's what it covers), or run
   `gh attestation verify <archive> --repo hirefrank/confidant` for build
   provenance.)
2. Install the skills (they ship inside the binary — no repo checkout):
   `confidant setup --agent auto`. This materializes the skills to a
   versioned share dir and links each skill into the detected agent's
   skills directory. (No vault configured yet? `confidant doctor` exits
   with `E_VAULT_NOT_FOUND` before reporting skills-link health, so
   confirm the links with `confidant agents` or
   `confidant which --skills-dir` instead.) (`confidant doctor` checks GitHub for the latest
   release unless `CONFIDANT_OFFLINE=1` is exported — add that to my
   shell rc too, this session and permanently, only if I want that
   request disabled.)
3. Ask me where my vault is and set `CONFIDANT_VAULT` to it (export it for
   this session and tell me what to add to my shell rc to keep it). If I
   have no vault yet, ask whether to create one at a path I choose or
   stop — do not invent a path. To create one, run
   `confidant init --create --no-input` against an absent or empty
   directory: it scaffolds the directory, git repo, `.gitignore`, and
   `confidant.toml`, then the keys.
4. Ask me whether this vault is for **real relationship data** (encrypted
   mode, the production default) or **demo / learning / fixtures only**
   (plaintext opt-out), and explain the consequences before editing
   `confidant.toml` or running `confidant init`:
   - **Encrypted (real data):** `confidant init` creates vault keys and
     shows a 24-word recovery phrase once (store offline); record bodies
     are encrypted in git while ledger lines stay structural plaintext.
     Ensure `confidant.toml` does **not** set `[crypto] mode = "plaintext"`
     (never silently copy the demo vault's `mode = "plaintext"` into a
     vault I described as real) and the working tree is clean
     (`git status`), then guide `confidant init` and recovery-phrase
     handling (never echo the phrase into chat logs).
   - **Plaintext (demo / learning / fixtures only):** set or keep
     `mode = "plaintext"` under `[crypto]` in `confidant.toml` (only valid
     while the vault is structurally plaintext; never for real PII), do
     **not** run `confidant init`, and warn that `git clone` exposes all
     record content.
5. Verify: run `confidant check --json --no-input` against the vault and
   report the error/warning counts.
6. Read the routing snippet (`confidant routing`) for the propose →
   confirm → apply workflow every skill follows, and the Privacy rules
   (trusted devices with encrypted disks only; `.confidant/` is never
   committed; `no-ai` records stay out of agent output — see the README
   Privacy section and `docs/privacy.md` in the GitHub repo).

Report back: CLI version (`confidant --version`), which skills you linked,
vault crypto mode (encrypted vs. plaintext opt-out), the `check` result,
and any `confidant doctor` warnings.
```

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
