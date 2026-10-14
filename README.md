# Confidant

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hirefrank/confidant/badge)](https://securityscorecards.dev/viewer/?uri=github.com/hirefrank/confidant)

**Confidant is relationship memory you own.** Your agents share one memory
of the people in your life — people, organizations, deals, interactions,
notes — and every change is proposed by an agent, verified by deterministic
rules (`confidant check`), and recorded by you. It's a private record of
relationships. With the right schema pack it can run a coaching practice,
track personal relationships, or model any other relationship domain —
the core stays the same.

Records live in plain-text files in a git repo (the **vault**). The Rust CLI
`confidant` reads, checks, and writes them. There is no server.

The same files serve both sides: open `people/p-<ULID>/profile.md` in any
editor and it's just Markdown; ask an agent for context on a person and it
pulls the whole bundle — notes, sessions, deals, balances — through one
`confidant context` call, gated by the same rules. A memory your agents
use, in files you can read. Underneath, a ledger of dated facts
(`ledger/2026/10.cfd`) keeps the record append-only and auditable.

New here? Start with [Agent setup](#agent-setup) for the one-prompt
install, or [Quickstart](#quickstart) to try the fake-data demo vault.

## Install

**The easiest path:** paste the one-prompt install from
[`docs/agent-setup.md`](docs/agent-setup.md) into your agent. It handles
everything — binary, skills, config.

**Manual install** (requires a recent Rust toolchain; MSRV 1.88, see
`rust-version` in `Cargo.toml`):

```sh
cargo install confidant-cli
confidant setup --agent auto
```

This installs the `confidant` binary from [crates.io](https://crates.io/crates/confidant-cli).
Prebuilt binaries and shell installers are on the
[GitHub Releases](https://github.com/hirefrank/confidant/releases) page.
`confidant update` keeps the install current (re-run the installer or
`cargo install confidant-cli`, then `confidant setup` to re-link).

`setup` installs the integration skills shipped inside the binary into your
agent's skills dir — no repo checkout needed.

**Dev install** (contributors, see [`CONTRIBUTING.md`](CONTRIBUTING.md)):

```sh
git clone https://github.com/hirefrank/confidant.git
cd confidant
cargo run -p confidant-cli -- check --json --no-input --vault examples/demo-vault
```

## Quickstart

When creating or connecting a vault, choose **encrypted** (real data) or
**plaintext** (demo/fixtures only) up front — see
[`docs/agent-setup.md`](docs/agent-setup.md#encrypted-vault-vs-plaintext-demo):

- **Real relationship data (encrypted, default):** ensure `confidant.toml`
  does **not** set `[crypto] mode = "plaintext"` (never copy the demo vault's
  opt-out into a real vault) and the git working tree is clean (`git status`),
  then run `confidant init`. Record bodies are encrypted in git; ledger lines
  stay structural plaintext.
- **Demo / learning / fixtures only (plaintext opt-out):** set
  `[crypto] mode = "plaintext"` in `confidant.toml` (valid only while the
  vault is structurally plaintext) and do **not** run `confidant init`. Never
  use for real PII — `git clone` exposes all record content.

Create an encrypted vault (or point `CONFIDANT_VAULT` at an existing one)
and check it:

```sh
export CONFIDANT_VAULT="$HOME/vault"
mkdir -p "$CONFIDANT_VAULT" && cd "$CONFIDANT_VAULT" && git init
# confidant.toml is optional — encrypted is the default and `confidant init`
# does not write it. Create it by hand only if you need [crypto] settings or
# packs, then commit it so `git status` stays clean:
confidant init   # generates your operator key; shows a 24-word recovery phrase once — store it offline
confidant check
confidant check --json --no-input
```

To try it with fake data, use the demo vault (`[crypto] mode = "plaintext"` — **fake data only**):

```sh
confidant find "Ada Example" --json --vault examples/demo-vault
```

`--json` is on every command. `--no-input` never prompts. Discovery order is
`--vault`, then `CONFIDANT_VAULT`, then a walk up from the current directory
looking for `confidant.toml`, then `default_vault` in `~/.config/confidant/config.toml`.

## What's in the box today

The CLI is `confidant`. Vault config is `confidant.toml`. Agents should set
`CONFIDANT_VAULT` (or pass `--vault`) so they never write the wrong tree.

| Area | Commands | Notes |
|---|---|---|
| Read | `find`, `context`, `allowlist`, `schema`, `help` | `context` returns the whole bundle for one person in a single call |
| Check | `check` | Read-only; collects every finding; stable codes in [`spec/findings.md`](spec/findings.md) |
| Write | `record add`, `note add`, `log session`, `log touch`, `import` | One commit per write; `check` runs before every commit |
| Keys | `init`, `recover`, `keys init-client` / `rotate` / `revoke` / `shred`, `keys device-add` | Per-client data keys; shred-coupled inbox rotation |
| Inbox | `inbox`, `inbox rotate` | Signed, pull-only intake from outside systems |
| Search | `reindex` + `qmd-search` skill | QMD index is local, gitignored, built from the cleared set only |
| Health | `doctor` | Staleness checks, skills-link health |
| Agents | `mcp`, `setup`, `update`, `agents`, `which`, `routing` | MCP is a thin stdio wrapper over the CLI — never a second code path |

## Packs

A **schema pack** declares extra verbs, record types, front-matter fields,
balance metrics, and check rules. Packs are the extension mechanism: the
core stays generic, and a pack turns Confidant into a tool for a specific
domain.

- **`coaching@0.1`** ships today, compiled into the binary. It adds sessions,
  packages, ICF hours, balance assertions, and gap rules (a session with no
  notes; a paid client with no session inside a configurable window). If you
  run a coaching practice, this pack covers what you'd otherwise need a
  coaching CRM for — without the sales-pipeline baggage.
- **`personal@0.1`** ships today, compiled into the binary. It adds
  birthdays, relationship edges (`friend`, `family`, `sibling`, `partner`,
  `parent`, `mentor`), keep-in-touch cadence (`W_CADENCE_OVERDUE`), upcoming
  important dates (`W_DATE_UPCOMING`), and the `touch` ledger verb
  (`confidant log touch <person> call|text|coffee|gift|meet`) for lightweight
  touchpoints. Both cadence and date nudges are warning-level and never block
  a write.
- **Multi-pack vaults** ([issue #173](https://github.com/hirefrank/confidant/issues/173)):
  a vault can list several packs at once (`packs = [...]` in
  `confidant.toml`), e.g. `packs = ["coaching@0.1", "personal@0.1"]`. Per-pack
  access scoping — so one person can be a coaching
  client and a friend, and a coaching agent never sees personal notes — is
  still to come.
- **External packs** ([issue #193](https://github.com/hirefrank/confidant/issues/193)):
  the long-term direction is installable, versioned packs loaded at runtime,
  so third parties can publish packs without opening a PR here. Not yet
  built.

Pack specs live in [`packs/`](packs/). The coaching pack's human-readable
contract is [`packs/coaching/0.1.md`](packs/coaching/0.1.md).

## Search

There are two search paths, and the CLI is the source of truth for both.

**`confidant find`** scans the vault directly. It is exact, deterministic,
and fail-closed: it returns content only from the **cleared allowlist** — a
record is searchable only when it parsed cleanly, has no `no-ai: true` flag
(a `no-ai: notes` person stays searchable; their notes don't), and
every ID it references is cleared. If a record is uncleared, it is omitted
from results entirely (not redacted — omitted). This is enough for a few
hundred clients; numbers are in
[`docs/search-benchmark.md`](docs/search-benchmark.md).

**QMD search** is an optional, local-first semantic search layer
([BM25 + vectors + reranking, all on-device](https://github.com/tobi/qmd)).
It is not a dependency of the Rust CLI — it ships as an embedded skill you
run through `confidant setup`. `confidant reindex` builds the QMD corpus
through the CLI from the §12 cleared set only; the index lives under
`<vault>/.confidant/` (gitignored, never committed, never synced). At query
time the `qmd-search` skill asks the CLI to verify every hit against the
allowlist before returning it, so a query-path bug degrades to missing
results rather than risking a leak. `no-ai` records are never decrypted
into the corpus.

If QMD is not installed or the index is missing, `qmd-search` falls back to
`confidant find` and says so — it never falls back silently.

## Encryption and privacy

**Plaintext belongs only on trusted devices** (your laptop, or an agent
computer acting for you). A git remote must not hold client notes in
plaintext. On a keyed vault the write path encrypts record content:
`record add`, `note add`, and `log session --note` write §14 envelopes
(per-client data keys; `name:` lives only inside the ciphertext), and inbox
`RecordWrite` items are encrypted at drain time with the vault's device
key (without a record encryptor the drain fails closed rather than
writing plaintext). Ledger entries,
`import`, and `confidant.toml` stay plaintext by design. A vault with
`[crypto] mode = "plaintext"` in `confidant.toml` opts out (only for vaults
that hold no real data, such as the demo vault); the opt-out can never
downgrade a vault that already has keys. Existing plaintext records are
never encrypted in place.

Encrypted reads work too: `find`, `context`, and MCP decrypt cleared records
through the CLI (never `no-ai` records), so search and context work on
keyed vaults.

When an agent reads notes, that content is sent to a hosted model provider.
This is explicit and accepted. Confidant does not claim the provider stores
nothing; that depends on the provider's terms.

The full allowlist rules (merge groups, ledger lines, package propagation,
ID edge cases) are in [`docs/privacy.md`](docs/privacy.md). What an
MCP-connected agent can and cannot do — and exactly what `no-ai`, the
`check` gate, and the inbox guarantee — is in
[`docs/threat-model-agents.md`](docs/threat-model-agents.md).

`confidant doctor` checks GitHub for the latest release and reports skills
link health. The release check is one unauthenticated `GET` to
`api.github.com/repos/hirefrank/confidant/releases/latest`; no vault data is
included, and only the `tag_name` is read — the response body is discarded.
Set `CONFIDANT_OFFLINE=1` to skip the request; the check then reports
`staleness check disabled`.

## Agent setup

Agents use the CLI plus its embedded integration skills (imports, search).
One page covers it all — including a single copy/paste prompt that
installs everything and a loop for staying current:
[`docs/agent-setup.md`](docs/agent-setup.md).

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

## TUI (preview)

`confidant-tui` is a read-only terminal UI for `check`, `find`, `context`,
and `doctor`. It consumes only the ADR-7 CLI JSON contract
(`confidant <subcommand> --json --no-input`), never opens vault files
directly, and keeps plaintext on the alternate screen only.

It ships as a GitHub Releases binary (next to `confidant`), and is not on
crates.io yet. It needs a `confidant` on `PATH` that speaks the same agent
contract (`schema_version == "1"`) — it shells out to it rather than
bundling its own copy. From a checkout:

```sh
cargo run -p confidant-tui -- --vault examples/demo-vault
```

## Where we're going

The roadmap is tracked as open issues on GitHub. The big themes:

- **Multi-pack vaults** — one vault, several packs, per-pack scoping.
  [Issue #173](https://github.com/hirefrank/confidant/issues/173) is the
  umbrella; `personal@0.1` is the proving pack
  ([#184](https://github.com/hirefrank/confidant/issues/184)).
- **External packs** — installable, versioned, loaded at runtime so third
  parties can publish packs without a PR here.
  [Issue #193](https://github.com/hirefrank/confidant/issues/193).
- **TUI** — a read-only terminal UI on top of the agent contract, with
  write flows and proposal review to follow.
  [Issue #205](https://github.com/hirefrank/confidant/issues/205).
- **Encrypted editing** — `record edit` through the write pipeline, blocked
  on the outside audit.
  [Issue #216](https://github.com/hirefrank/confidant/issues/216).
- **Ciphertext merge conflicts** — detection and resolution for encrypted
  records. [Issue #219](https://github.com/hirefrank/confidant/issues/219).
- **Ledger query performance** — a rebuildable local index.
  [Issue #188](https://github.com/hirefrank/confidant/issues/188).

## Status: not yet audited

**The encryption has had no outside review.** The design was reviewed
in-project and the implementation's tests pass, but no independent reviewer
has audited it. Tracked in
[#138](https://github.com/hirefrank/confidant/issues/138).

So, today: **keep vaults on trusted devices with encrypted disks, and do not
put other people's client data in them.** `confidant check`, the privacy
allowlist, and `no-ai` all work, but they are not a substitute for the
outside audit. This section will say plainly when the audit lands; until
then it is the disclosure.

## License

Copyright 2026 Frank Harris.

Licensed under the Apache License, Version 2.0 (`license = "Apache-2.0"` in
[`Cargo.toml`](Cargo.toml)). See [`LICENSE`](LICENSE) for the full text.
Some files are adapted from [cr](https://github.com/AnandChowdhary/cr)
(MIT); see [`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES) and
[`docs/borrowing.md`](docs/borrowing.md).
