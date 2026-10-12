# Agent setup: install Confidant and its skills

One page for operators and their agents. The copy/paste prompt below is the
whole install — drop it into an agent and it does the rest.

## Copy/paste install prompt

```text
Set up Confidant (a git-native CRM CLI plus agent skills) on this machine:

1. Install the CLI with `cargo install confidant-cli` (needs a Rust
   toolchain 1.85+; check with `rustc --version`). This provides the
   `confidant` binary. Verify with `confidant --help`.
   (No Rust toolchain? Download the `confidant` binary + installer from
   the latest GitHub Release at
   https://github.com/hirefrank/confidant/releases instead — and verify
   it first: check the published `.sha256` checksum file, or run
   `gh attestation verify <binary>` for build provenance.)
2. Clone the Confidant repo (it carries the skills):
   `git clone https://github.com/hirefrank/confidant <dir>`
   (ask me where; suggest `~/Projects/confidant`). This checkout is what
   keeps the skills working — do not delete it afterwards. Then pin it to
   the latest release tag (never stay on main — see Staying current):
   `git -C <dir> checkout $(git -C <dir> describe --tags --abbrev=0 origin/main)`.
3. Make the skills visible to yourself: symlink every directory directly
   under `<repo>/skills/` that contains a `SKILL.md` into your agent
   skills directory (`~/.config/opencode/skills/` for OpenCode,
   `~/.claude/skills/` for Claude Code — use whichever exists here).
   Symlink the whole skill directory (not just `SKILL.md`), so each
   skill's `bin/` scripts keep resolving.
4. Ask me where my vault is and set `CONFIDANT_VAULT` to it (export it for
   this session and tell me what to add to my shell rc to keep it). If I
   have no vault yet, use `<repo>/examples/demo-vault` (fake data only)
   to verify with, and say so.
5. Verify: run `confidant check --json --no-input` against the vault and
   report the error/warning counts.
6. Read `<repo>/skills/README.md` for the propose → confirm → apply
   workflow every skill follows, and `<repo>/README.md` Privacy plus
   `<repo>/docs/privacy.md` for the privacy rules (trusted devices with
   encrypted disks only; `.confidant/` is never committed; `no-ai`
   records stay out of agent output).

Report back: CLI version (`confidant --version`), which skills you linked,
and the `check` result.
```

## Staying current (updates)

Nothing checks automatically today — updates are a manual loop, documented
here so it stays one:

- **Skills:** they live in the checkout from step 2, pinned to a release
  tag — never main. Skills run on devices holding plaintext client data,
  so they track reviewed, published releases, not whatever merged last.
  Periodically: `git -C <repo> fetch --tags`, then `git -C <repo>
  checkout $(git -C <repo> describe --tags --abbrev=0 origin/main)`. If a
  new directory appears under `<repo>/skills/`, link it the same way as
  step 3.
- **CLI:** compare `confidant --version` against the latest GitHub Release
  (https://github.com/hirefrank/confidant/releases). If behind, re-run
  `cargo install confidant-cli` (or the release installer).
- **Optional search backend:** the `qmd-search` skill needs the `qmd` binary
  (`npm install -g @tobilu/qmd`); keyword-only `find` works without it.

A future `confidant doctor` staleness check (CLI and skills each reporting
whether they match the latest release) would make this automatic; until
then, this loop is the mechanism.
