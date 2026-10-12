# Confidant

A plain-text, git-native CRM for **one operator** and their AI agents. Records
live in a git repo (the **vault**). The Rust CLI `confidant` reads and checks
them. There is no server.

Milestone 1 is the format spec, parser, generic records, derived values,
balance assertions, `confidant check`, the coaching schema pack, and a fake
demo vault. Milestone 2 implements the encryption primitives — per-client
data keys, the signed recipient manifest, the encrypted record envelope, and
recovery — and wires them into the CLI write path: `record add`, `note add`,
and `log session --note` write encrypted §14 envelopes on keyed vaults.

The CLI is `confidant`. Vault config is `confidant.toml`. Agents should set
`CONFIDANT_VAULT` (or pass `--vault`) so they never write the wrong tree.

## Status: one thing is not ready for other people's data

**The encryption has had no outside review.** The design was reviewed
in-project and the implementation's tests pass, but no independent reviewer
has audited it. Tracked in
[#138](https://github.com/hirefrank/confidant/issues/138).

Record writes now encrypt by default: on a keyed vault, `record add`,
`note add`, and `log session --note` write §14 envelopes (per-client data
keys; `name:` lives only inside the ciphertext), and inbox `RecordWrite`
fails closed rather than writing plaintext. Ledger entries, `import`, and
`confidant.toml` stay plaintext by design. A vault with `[crypto] mode =
"plaintext"` in `confidant.toml` opts out (only for vaults that hold no
real data, such as the demo vault); the opt-out can never downgrade a
vault that already has keys. Existing plaintext records are never
encrypted in place. Encrypted reads (`find`/`context` decrypting) land
next; until then, `find` and `context` do not decrypt.

So, today: **keep vaults on trusted devices with encrypted disks, and do not
put other people's client data in them.** `confidant check`, the privacy
allowlist, and `no-ai` all work, but they are not a substitute for the
outside audit. This section will say plainly when the audit lands; until
then it is the disclosure.

## Install

```sh
cargo install confidant-cli
```

This installs the `confidant` binary from [crates.io](https://crates.io/crates/confidant-cli).
Requires a recent Rust toolchain (MSRV 1.85, see `rust-version` in `Cargo.toml`).

## Privacy (read this)

Plaintext belongs only on trusted devices (your laptop, or an agent computer
acting for you). On a keyed vault the write path encrypts record content (see
Status above). Vaults that opt out with `[crypto] mode = "plaintext"` stay
plaintext in git — do not put real clients in those.

When an agent reads notes, that content is sent to a hosted model provider.
This is explicit and accepted. Confidant does not claim the provider stores
nothing; that depends on the provider's terms.

`confidant find` returns content only from a **cleared allowlist** — a record
is searchable only when it parsed cleanly, has no `no-ai` flag, and every ID
it references is cleared. The full allowlist rules (merge groups, ledger
lines, package propagation, ID edge cases) are in
[`docs/privacy.md`](docs/privacy.md).

## Quickstart

```sh
git clone https://github.com/hirefrank/confidant
cd confidant
cargo build -p confidant-cli
export CONFIDANT_VAULT="$PWD/examples/demo-vault"
./target/debug/confidant check
./target/debug/confidant check --json --no-input
./target/debug/confidant find "Ada Example" --json
```

The demo vault is **fake data only**.

`--json` is on every command. `--no-input` never prompts (milestone 1 has
nothing to prompt for). Discovery order is `--vault`, then `CONFIDANT_VAULT`,
then a walk up from the current directory looking for `confidant.toml`, then
`default_vault` in `~/.config/confidant/config.toml`.

## Layout

See [`spec/0.1.md`](spec/0.1.md). Short version:

```
vault/
├── confidant.toml
├── ledger/2026/10.cfd      # dated facts, one file per month
├── people/p-<ULID>/profile.md
├── people/p-<ULID>/notes/n-<ULID>.md
├── orgs/o-<ULID>/org.md
├── deals/d-<ULID>/deal.md
└── .confidant/             # local cache, gitignored
```

Structured facts are ledger lines (`DATE VERB ID ARGS…`). Prose is Markdown.
`balance` lines are assertions `check` verifies against computed values.

Coaching (sessions, packages, ICF hours, gap rules) is a **schema pack**,
not core: [`packs/coaching/0.1.md`](packs/coaching/0.1.md).

## `confidant check`

Read-only. Collects every finding; it does not repair. Stable finding codes
are part of the spec ([`spec/findings.md`](spec/findings.md)). Callers branch
on `code`, never on message text.

Gap rules from the architecture (section 9b): a session with no notes, and a
paid client (`sessions_remaining > 0` or a `pps` session in the lookback)
with no session inside a configurable window. The gap clock runs from
`max(last session, latest open)`. Session billing tags are `paid`
(consumes a slot), `pps`, and `comp` (complimentary; never consume). A
session with none of these still consumes and is `W_SESSION_UNTAGGED`; more
than one is `E_SESSION_TAGS`. A merge between different record types is
`E_WRONG_ID_TYPE`. `find` follows the section 12 allowlist.

```sh
confidant check --json --fail-on warning --as-of 2026-10-08
```

## Search

Milestone 1 scans plaintext. That is enough for a few hundred clients; numbers
are in [`docs/search-benchmark.md`](docs/search-benchmark.md). QMD search comes
after v0, on trusted devices with encrypted disks, index never in git.

## License

Copyright 2026 Frank Harris.

Licensed under the Apache License, Version 2.0 (`license = "Apache-2.0"` in
[`Cargo.toml`](Cargo.toml)). See [`LICENSE`](LICENSE) for the full text.
Some files are adapted from [cr](https://github.com/AnandChowdhary/cr)
(MIT); see [`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES) and
[`docs/borrowing.md`](docs/borrowing.md).
