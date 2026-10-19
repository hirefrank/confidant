# confidant-cli

The `confidant` binary — relationship memory you own, in plain-text files
in a git repo. Reads and checks Confidant vaults; there is no server.

## Install

```sh
cargo install confidant-cli confidant-tui
confidant setup --agent auto
```

`setup` installs the integration skills shipped inside the binary into your
agent's skills dir — no repo checkout needed. The TUI is optional; the
command above installs it alongside the CLI so their versions match
(`confidant tui` and `confidant doctor` warn on a mismatch).

Needs Rust 1.88+. If `rustc --version` fails with "no default is
configured", run `rustup default stable` and retry.

## Quickstart

```sh
export CONFIDANT_VAULT="/path/to/vault"   # this process only
confidant check --json --no-input
```

In a non-interactive or agent session, export `CONFIDANT_VAULT` in that
process and/or pass `--vault <path>` explicitly. Do not rely on
`source ~/.bashrc`: an interactive guard such as
`[[ $- != *i* ]] && return` skips the export, and a stale value can make
`check` and `doctor` inspect the wrong vault.

With the demo vault (fake data) in a contributor checkout:

```sh
confidant find "Ada Example" --json --vault examples/demo-vault
```

See the [main repository](https://github.com/hirefrank/confidant) for the full
guide, the vault format spec, and the current project status.

## License

Apache-2.0.
