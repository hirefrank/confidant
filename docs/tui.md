# The Confidant TUI

`confidant-tui` is a terminal UI over the same agent contract as the CLI.
It browses and edits the vault, reviews queued work, and runs local search.
The front page of [`README.md`](../README.md#the-tui) has the short version;
this page keeps the detail and the phase history.

## Running it

The TUI consumes only the ADR-7 CLI JSON contract
(`confidant <subcommand> --json --no-input`), never opens vault files
directly, and keeps plaintext on the alternate screen only.

It ships as a GitHub Releases binary (next to `confidant`) and on crates.io.
You need **both** binaries: the TUI shells out to a `confidant` on `PATH`
that speaks the same contract (`schema_version == "1"`) — it never bundles
its own copy. Install with:

```sh
cargo install confidant-cli confidant-tui
```

then launch it with `confidant tui` (extra arguments pass through to
`confidant-tui`). From a checkout:

```sh
cargo run -p confidant-tui -- --vault examples/demo-vault
```

`--vault` falls back to `CONFIDANT_VAULT` when it is not passed, so the vault
path does not have to be repeated on every command.

## People and operator mode

The People workspace shows the cleared roster and the selected person's live
`context`. `!` toggles **operator mode**: the roster and context are then
read with `--for-operator`, so `no-ai` people and notes appear with a
tri-state `[no-ai]` / `[no-ai: notes]` badge, and the footer carries the same
`OPERATOR MODE` banner the CLI prints, so a screen share cannot silently show
hidden data. Operator mode is off by default — the TUI passes the flag only
after that explicit key press. Turning it off drops the operator roster and
context before reloading, so a failed reload cannot leave hidden content on
screen without the banner.

## Editing

Editing is always operator-only, independent of operator mode: from the
context pane, `[`/`]` select the person, a note, or an interaction and `e`
edits it. `e` uses `record show --for-edit` / `note show --for-edit`, which
decrypt `no-ai` records even while the roster view is un-badged (operator
mode off); the badges and banner describe the roster/context view, not the
edit path.

The text is staged in 0600 scratch under `<vault>/.confidant/conflicts/<id>/`,
opens in `$EDITOR`/`$VISUAL` (run as a single program, so `EDITOR="code -w"`
does not work — the same limitation as the CLI's own `--edit` flows), and is
written back through `record edit` / `note edit --file` only after an
explicit `y` confirm. A no-op edit commits nothing.

## Quick capture

Quick capture is `s` (session), `t` (touch), and `n` (note). Each opens a
form pre-filled with the selected person's id, so a ULID never has to be
typed, and `Enter` runs the CLI's `--dry-run` preview; `y` writes it (one
commit) and any other key cancels and writes nothing. A note body is staged
in the same 0600 gitignored scratch as the editor flow and removed after the
write.

Search moved to `f` (it was `s`). The Review Queue workspace (`2`) carries a
badge with its pending count — proposal manifests, inbox items, and
unresolved conflicts — so a queued item is visible from every workspace.

## Proposals (Phase 2, #211)

The proposals tab lists the manifests in `<vault>/.confidant/proposals/` and
applies them exactly as the skill workflow does: ledger import, then notes,
then records — each step shown as a dry-run diff first and applied only on
an explicit `y` confirm. Records are never hand-written into the vault tree
(pre-M2 records stay with the skill workflow); every write goes through the
CLI, one commit per write, with progress tracked so a crashed apply resumes
where it stopped.

## Inbox (Phase 3, #212)

The inbox tab shows the `inbox --dry-run` plan — items with their merge
actions, deferred items, and warnings — and applies it all-or-nothing
through the existing `inbox` command on an explicit `y` confirm. There is no
per-item selection in the TUI.

## Search (Phase 3a, #212)

The Search tab runs the `qmd-search` skill's `qmd-query.py` against the
vault's QMD index and renders each match with its provenance (`qmd` or
`find`) and score. Rendering is fail-closed: matches with any other
provenance are dropped and counted. When QMD or the index is missing, the
skill falls back to plain `confidant find` and the tab shows a
`fallback: <reason>` banner. If `python3` or the skill itself is missing,
the tab shows an alert instead of falling back silently.

## See also

- [`docs/privacy.md`](privacy.md) — proposal scratch files, plaintext on
  screen, and the search allowlist.
- [`docs/threat-model-agents.md`](threat-model-agents.md) — why operator
  mode and `--for-edit` are boundaries in the CLI surface, not access
  control.
