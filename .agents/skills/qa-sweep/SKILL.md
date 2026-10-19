---
name: "qa-sweep"
description: "Run the periodic QA sweep: drive the built confidant CLI and TUI as an adversarial operator, file one issue per real defect, and rotate coverage. Complements the nightly qa-smoke CI job."
---

# QA Sweep

A sweep drives the **built binaries** the way an operator and their agents
do, looking for defects that unit tests, clippy and CI all passed over. Two
sweeps in one night (2026-10-19) found five real bugs — a refused write that
leaked a record directory git could not see, a preview that disagreed with
the apply, and others — through exactly this protocol. The point of this
skill is to make that class of check routine, not heroic.

This skill lives in the repo (`.agents/skills/`). It is maintainer
workflow, not operator workflow: never put it under
`crates/confidant-cli/skills/` (that tree embeds into the `confidant`
binary and ships to every user via `setup`).

The deterministic half of the protocol is scripted in
`.github/scripts/qa-smoke.py` and run nightly by CI. Do that first; it
clears the invariants that are cheap to check. Then spend the sweep on
what the script cannot: the TUI, cross-process contracts, and whatever
changed since the last sweep.

## What a sweep is not

- **Not code review.** Do not read the diff to decide what to test. A
  sweep that starts from the code tests what the author already thought
  about. Drive the binary and follow what it does.
- **Not a security audit.** The outside crypto audit (#138, OSTIF) covers
  the threat model. A sweep is functional and adversarial, not a
  penetration test.
- **Not the fix.** A sweeper never authors the fix. The finder and the
  fixer stay in separate lanes so the stance stays adversarial; the moment
  you can edit the code you stop trying to break it. File an issue and
  stop.

## Protocol

1. **Build fresh.** `cargo build -p confidant-cli --locked --all-features`
   (the smoke needs the `test-overrides` feature for throwaway keys).
   Build `confidant-tui` too for the TUI pass. Point every run at the
   freshly built binary — for the TUI, `CONFIDANT_BIN=<path to the CLI>`.
2. **Throwaway vaults, fake data only.** Work under
   `/tmp/opencode/<sweep>` (e.g. `/tmp/opencode/qa-2026-10-19`). Never a
   real vault, never real names, notes, or keys. The demo vault's
   `Ada Example` style is the bar.
3. **Isolate `HOME` and config.** When exercising encrypted paths, set
   `HOME` to a throwaway config dir and use throwaway keys via
   `CONFIDANT_DEVICE_KEY` / `CONFIDANT_TEST_OPERATOR_KEY` with
   `CONFIDANT_KEYCHAIN=off` (ADR-14: CI never holds vault keys). Never
   point a write at the operator's real config dir or keychain.
4. **Give throwaway vaults their own git identity, and cut off the real
   one.** Writes need `git user.name`/`user.email`; a developer machine
   supplies them from the real config, a runner does not, so a sweep that
   passes locally can fail with `E_INVALID: git user.name is not
   configured`. Write a fake identity into the throwaway `HOME`'s
   `.gitconfig` and point `GIT_CONFIG_GLOBAL` at it; clear
   `XDG_CONFIG_HOME` and set `GIT_CONFIG_NOSYSTEM=1` so git cannot fall
   back to the operator's config at all (#623, and the #560 lesson).
5. **Pin dates.** Ledger writes take `--date`; pass a fixed date so a run
   does not depend on the wall clock and turn red on a month rollover
   (#585).
6. **Drive it, then poke it.** Run the happy path, then refuse things:
   bad input, a second write, a conflicting pack, a stale pin, a symlink,
   a missing key.

## What to target

The high-yield list, roughly in the order sweeps keep finding bugs:

- **Refusal paths.** A refused write must leave `git status --porcelain`
  empty **and** the vault passing `confidant check`. The two are not the
  same: a record-directory leak is invisible to git (an empty directory
  is untracked) but makes the next `check` fail `E_FRONTMATTER` and blocks
  later writes (#604). Always check both.
- **Cross-process contracts.** The TUI and the CLI are separate processes
  with separate versions. Look for TUI ↔ CLI version skew, and for a
  preview that disagrees with the apply (the diff you reviewed must be
  the diff that lands).
- **The TUI in tmux.** Run it in a tmux pane and drive it by keys. Include
  a run with a **deliberately stale `CONFIDANT_BIN`** to prove the TUI
  fails or warns instead of silently talking to the wrong binary.
- **Pack lifecycle.** Install, no-op update (`unchanged`), stale-lock-hash
  repair, remove. Then the refusals: a no-op that is not reported
  unchanged, a symlinked pack dir or file, a conflict with an installed
  pack, a pack claiming a builtin finding code.
- **Conflict and proposal flows.** Two writers, an inbox drain, a merge
  that conflicts, a proposal accepted or rejected. The interesting states
  are the ones in between.
- **Platform-variance guards.** Never let a test or snapshot depend on
  `TMPDIR` or a real absolute path (#581 shipped one). If a check only
  fails on macOS, it is still a bug.

## Coverage rotation

Do not repeat the last sweep's focus. Rotate, and say which area this
sweep covered.

| Focus area | What it means |
|---|---|
| CLI happy path | init, record/note/log, find/context, check |
| Refusal / invariant paths | refused writes leave no trace; vault still checks |
| Pack lifecycle | add/update/remove, no-op, stale pin, symlink refusals |
| Write rollback | a failed multi-file write commits nothing and deletes nothing else |
| Proposal / conflict flows | inbox, proposals, merges, review queues |
| TUI operator / edit / capture | tmux pass, `CONFIDANT_BIN` skew, preview vs apply |
| Platform variance | TMPDIR/path assumptions, macOS vs Linux behaviour |

## Output contract

- **One issue per real defect.** Include an exact reproduction (commands
  and the throwaway vault shape), observed vs expected, and the PR you
  believe introduced it. Add the `qa-found` label.
- **No style nits and no duplicates.** Search the open issues first; a
  defect already tracked is a comment, not a new issue.
- **"Clean" is a valid result.** A sweep that finds nothing must list
  exactly what it exercised, so the next sweeper knows what is covered.
- **Every QA-found defect's fix ships a regression test.** If the same
  class of defect is found twice, stop sweeping it and add a test or a
  lint instead — a sweep is not a substitute for coverage.

## Cadence

Weekly, and additionally:

- after a heavy merge day (several PRs touching the same area),
- before a release tag,
- after any change to the write, apply, or pack paths.

## The scripted subset

`.github/scripts/qa-smoke.py` runs the deterministic invariants against a
throwaway vault and a freshly built CLI:

```sh
cargo build -p confidant-cli --locked --all-features
python3 .github/scripts/qa-smoke.py --cli target/debug/confidant
```

It covers encrypted `init` and the refusal of a plaintext declaration,
record/note/log writes on both vault modes, the alias stdin round-trip,
`find`/`context` with and without `--for-operator`, a clean `check`, the
pack lifecycle including the no-op and the stale-pin repair, and the
refused-write invariant. Run
`python3 .github/scripts/qa-smoke.py --self-test` to exercise the
`--workdir` safety check on its own.

CI runs it nightly and on push to `main` (`qa-smoke` job in
`.github/workflows/ci.yml`), never on pull requests, to keep PR latency
down. A failed run on `main` opens or updates the `qa-found` alert issue
with the run link, commit and failing step, and a later green run closes
it again (#625), so a red night lands on the same queue as a sweep instead
of waiting for someone to notice.

A sweep starts by running it, then spends its time on the columns in the
rotation table the script does not cover.

## Do not

- Do not read the diff to decide what to test, and do not write the fix.
- Do not use a real vault, real config dir, real keychain, or real data.
- Do not check only `git status` for a refused write — check `confidant
  check` too; that is where the leak hid.
- Do not file style nits or duplicates.
- Do not skip the regression test on a QA-found fix.
- Do not touch `crates/confidant-cli/skills/` — that tree ships to users.
