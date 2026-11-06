# Rune desktop app spike (throwaway)

Not a product crate. A minimal Rune shell over Confidant that loads the
people roster from a vault and renders a selectable list with a detail pane,
to answer whether Rune can be Confidant's third UI consumer (after the CLI
and the TUI). Findings: `docs/research/rune-desktop-app-spike.md`.

## Build

From this directory (its own Cargo workspace, excluded from the main
workspace like `fuzz/` — see the root `Cargo.toml` `exclude` list):

```sh
cargo build
```

Pins Rune at git rev `47cb857795c3b1dd5097c15d6161719ae738ddda` (`dev` tip at
spike time, 2026-11-05) and `confidant-core` by path
(`../../crates/confidant-core`). Rust 1.99.0 was used for the spike;
Rune itself is edition 2024.

## Run headless (no display needed)

```sh
cargo run -- --snap spike.png --tree spike-tree.txt
cargo run -- --snap spike-first.png --scene first   # first row selected
```

`--snap` writes a PNG of the rendered window, `--tree` dumps the element
tree, `--scene first` applies the `first` scene (selects row 0). With no
headless flags it opens a real window (needs a display).

## Tests

```sh
cargo test
```

Includes a scripted-input test: a synthetic pointer tap on the first row
selects it, driven through Rune's in-process `Runtime` (no window, no GPU).

## Vault

`CONFIDANT_SPIKE_VAULT`, else `../../examples/demo-vault` — the checked-in
demo vault (fake people only). Never point it at a real vault.
