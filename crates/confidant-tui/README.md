# confidant-tui

The `confidant-tui` binary — a terminal UI for Confidant. It covers
`check`, `find`, `context`, and `doctor`, plus confirm-before-apply review
of skill proposals, QMD-backed search, and inbox review.

## Operator layout

The screen is a three-workspace bar: **1 People & Search** (the default
master–detail view), **2 Review Queue** (Proposals, Inbox, and Conflicts,
with a pending-count badge), and **3 Check**. `d` opens Doctor, `p` shows
the resolved scope, `?` shows the grouped keymap, and `:` (or `Ctrl-P`)
opens the command palette.

People's left pane filters the cleared roster from
`confidant record list --json` and lists `Needs Attention` nudges derived
from the cached `check --json` report. The right pane renders the selected
person's live `context --json` bundle. Nudges are derived, not recomputed:
the TUI adds no check logic and runs no CLI call per keystroke.

It consumes only the ADR-7 CLI JSON contract
(`confidant <subcommand> --json --no-input`): it never opens vault files
directly and deliberately never links `confidant-core` or
`confidant-crypt`, so it stays the second consumer of that contract.

Review is bound to what it shows: a proposal step's dry-run pins the bytes
of the manifest file it reviewed (the ledger `lines_file` or a note's
`body_file`), and the confirm refuses if that file changed, if the target
ledger file has unrelated uncommitted changes, or if the note id the
preview named is no longer free. A refusal writes nothing and leaves the
proposal as it was.

## Keys

`j`/`k` move, `g`/`G` jump to the first/last row, `Tab` cycles the views
inside a workspace, `/` filters People (or starts a query), `Enter` opens,
`r` refreshes, and `q` quits. `s`/`t`/`n` open the session, touch, and
note capture forms, and `a` composes a new person; `[`/`]` pick the
context item `e` edits; and `!` toggles operator mode (`--for-operator`).
Every write needs an explicit `y` after a preview (the CLI's `--dry-run`,
or both sides for a conflict); `Esc` clears a filter or goes back, and at
the People home it does not quit.

## Install

You need **both** binaries: the TUI shells out to a `confidant` on `PATH`
that speaks the same agent contract (`schema_version == "1"`).

```sh
cargo install confidant-cli confidant-tui
```

Or grab both from the same GitHub Releases page (no Rust toolchain needed)
and launch it with:

```sh
confidant tui
```

Install and upgrade both from the same release: `confidant tui` and
`confidant doctor` warn when the two versions differ.

`--vault` falls back to the `CONFIDANT_VAULT` environment variable when it
isn't passed, so the vault path doesn't have to be given on every command
line — same as the `confidant` CLI itself. `confidant tui` forwards an
explicit `--vault` the same way. In a non-interactive or agent session,
export `CONFIDANT_VAULT` in that process or pass `--vault`; do not rely on
`source ~/.bashrc`, whose interactive guard skips the export.

## Status: not yet audited

The TUI is a layer on top of the Confidant project: it inherits the
project's trust story rather than having a separate one. The milestone 2
encryption has had no outside review — see the
[Status section](https://github.com/hirefrank/confidant#status-not-yet-audited)
of the main repository README (tracked in
[#138](https://github.com/hirefrank/confidant/issues/138)). Do not put
other people's client data in a vault until the audit lands.

## License

Apache-2.0.
