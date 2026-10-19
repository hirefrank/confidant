# confidant-tui

The `confidant-tui` binary — a terminal UI for Confidant. It covers
`check`, `find`, `context`, and `doctor`, plus confirm-before-apply review
of skill proposals, QMD-backed search, and inbox review.

## Operator layout

The screen is a three-workspace bar: **1 People & Search** (the default
master–detail view), **2 Review Queue** (Proposals, Inbox, and Conflicts;
they move under one queue in a later phase), and **3 Check**. `d` opens
Doctor, `p` shows the resolved scope, and `?` shows the keymap.

People's left pane filters the cleared roster from
`confidant record list --json` and lists `Needs Attention` nudges derived
from the cached `check --json` report. The right pane renders the selected
person's live `context --json` bundle. Nudges are derived, not recomputed:
the TUI adds no check logic and runs no CLI call per keystroke.

It consumes only the ADR-7 CLI JSON contract
(`confidant <subcommand> --json --no-input`): it never opens vault files
directly and deliberately never links `confidant-core` or
`confidant-crypt`, so it stays the second consumer of that contract.

## Install

You need **both** binaries: the TUI shells out to a `confidant` on `PATH`
that speaks the same agent contract (`schema_version == "1"`).

```sh
cargo install confidant-cli confidant-tui
```

Or grab both from the GitHub Releases page (no Rust toolchain needed) and
launch it with:

```sh
confidant tui
```

`--vault` falls back to the `CONFIDANT_VAULT` environment variable when it
isn't passed, so the vault path doesn't have to be given on every command
line — same as the `confidant` CLI itself. `confidant tui` forwards an
explicit `--vault` the same way.

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
