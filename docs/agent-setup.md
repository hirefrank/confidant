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
   the downloaded `.tar.xz`/`.zip` first: check the published `.sha256`
   checksum file (that's what it covers), or run
   `gh attestation verify <archive> --repo hirefrank/confidant` for build
   provenance.)
2. Clone the Confidant repo (it carries the skills):
   `git clone https://github.com/hirefrank/confidant <dir>`
   (ask me where; suggest `~/Projects/confidant`). This checkout is what
   keeps the skills working — do not delete it afterwards. Then pin it to
   the latest release tag (never stay on main — see Staying current):
   `git -C <dir> checkout $(git -C <dir> describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' origin/main)`.
   Export `CONFIDANT_REPO=<dir>` for this session and tell me what to add
   to my shell rc to keep it: it is how `confidant doctor` finds the
   checkout to report when the skills are behind. (Optional: `confidant
   doctor` checks GitHub for the latest release unless `CONFIDANT_OFFLINE=1`
   is exported — add that too, this session and the shell rc, only if I
   want that request disabled.)
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
the `check` result, and any `confidant doctor` staleness warnings.
```

## Staying current (updates)

`confidant doctor` reports how far the local install is behind the latest
GitHub Release — the CLI by its version, and the skills checkout by its
release tag. Both are warnings only: a stale install never fails `doctor`,
and when GitHub cannot be reached they read `staleness unknown` rather than
guessing. `doctor` checks GitHub by default; set `CONFIDANT_OFFLINE=1` to
skip that request entirely, and both checks read `staleness check disabled`
(see the README Privacy section and `docs/privacy.md`). Apply updates with
this loop:

- **Skills:** they live in the checkout from step 2, pinned to a release
  tag — never main. Skills run on devices holding plaintext client data,
  so they track reviewed, published releases, not whatever merged last.
  Periodically: `git -C <repo> fetch --tags`, then `git -C <repo>
  checkout $(git -C <repo> describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' origin/main)`.
  (The `--match`/`--exclude` keep stray or prerelease tags from being
  picked.) If a new directory appears under `<repo>/skills/`, link it the
  same way as step 3.
- **CLI:** compare `confidant --version` against the latest GitHub Release
  (https://github.com/hirefrank/confidant/releases). If behind, re-run
  `cargo install confidant-cli` (or the release installer).
- **Optional search backend:** the `qmd-search` skill needs the `qmd` binary
  (`npm install -g @tobilu/qmd`); keyword-only `find` works without it.

The skills staleness check is driven by `CONFIDANT_REPO` (set in step 2):
it must point at the checkout from step 2 so `doctor` can read its tag. If
it is unset, `doctor` omits the skills check — the CLI has no way to know
where the checkout is.
