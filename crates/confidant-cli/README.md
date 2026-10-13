# confidant-cli

The `confidant` binary — a plain-text, git-native CRM for one operator and
their AI agents. Reads and checks Confidant vaults; there is no server.

## Install

```sh
cargo install confidant-cli
confidant setup --agent auto
```

`setup` installs the integration skills shipped inside the binary into your
agent's skills dir — no repo checkout needed.

## Quickstart

```sh
export CONFIDANT_VAULT="/path/to/vault"
confidant check --json --no-input
```

With the demo vault (fake data) in a contributor checkout:

```sh
confidant find "Ada Example" --json --vault examples/demo-vault
```

See the [main repository](https://github.com/hirefrank/confidant) for the full
guide, the vault format spec, and the current project status.

## License

Apache-2.0.
