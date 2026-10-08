# Confidant

A plain-text, git-native CRM for **one operator** and their AI agents. Records
live in a git repo (the **vault**). The Rust CLI `confidant` reads and checks
them. There is no server.

Milestone 1 is the format spec, parser, generic records, derived values,
balance assertions, `confidant check`, the coaching schema pack, and a fake
demo vault. Encryption ships in milestone 2, after an independent crypto
design review. Do not put real client data in a vault until then.

The CLI is `confidant`. Vault config is `confidant.toml`. Agents should set
`CONFIDANT_VAULT` (or pass `--vault`) so they never write the wrong tree.

## Privacy (read this)

Plaintext belongs only on trusted devices (your laptop, or an agent computer
acting for you). A git remote must not hold client notes once encryption
exists; until milestone 2, treat the remote as if it were plaintext and do
not put real clients in it.

When an agent reads notes, that content is sent to a hosted model provider.
This is explicit and accepted. Confidant does not claim the provider stores
nothing; that depends on the provider's terms. `confidant find` returns
content only from a cleared allowlist (spec section 12): a record is
searchable only when it parsed cleanly, has no `no-ai` flag, has no
duplicate or path-id mismatch on that record, every ID in its front matter is
cleared, its whole merge group is cleared, and any `people/<id>/` parent is
cleared. A path mismatch on a note, interaction, or deal uncleares only that
record; a mismatch or duplicate on a person's profile uncleares that whole
person. `pkg-` IDs follow their openers. A leading Markdown bullet is skipped
before detecting `merge` / `open`. Malformed ID-like tokens un-clear the
record or line. Body lines that mention an uncleared or invalid ID are
dropped. Ledger lines are searchable only when every ID on the line is
cleared. A note, interaction, or deal is cleared only when every ledger
line that names it is allowed; this does not apply to persons. Findings
are themselves an allowlist: kept verbatim only when they have no file
and no ID, or resolve to a cleared record or ledger line; otherwise a
code and a count, never a path or raw text. Name-only mentions with no
ID are not detected in body prose and comments; a `person` / `org` /
`deal` value that is not a record ID (`person: "Jane Doe"`, bare
`p-A|Name`) is `E_INVALID_ID` and uncleared. Empty, `~`, and YAML `null`
are not references. A `|` alias is accepted only inside `[[…]]`. A trailing
comment after a closing quote (one or more spaces or tabs, then `#`) is
stripped (`"p-…" # Ada`, `"p-…"  # Bea`). After an alphanumeric, `_`, or
`-` in the same run, and inside a `scheme://` token, a prefix is glued: an
exact ULID is Valid; a longer run whose first 26 characters are a ULID, a
Unicode dash plus a ULID, or a dash run (`--`, soft hyphen then `-`) plus
a ULID, is malformed with that candidate; other glued lookalikes
(Drive/Docs, Notion, 32-hex) are not tokens. Unicode Pd dashes plus
U+30FC and U+2043 count as the ID dash. A bare 26-character ULID at a
word boundary that exactly equals an uncleared record's ULID is treated
as that record's ID (body, ledger, front matter, `src:` paths and URLs);
near-ULID bare runs and 32-hex are not. If any ledger file cannot be
read, `find` exits non-zero with `E_LEDGER_UNREADABLE` (code and count
only) and no hits. Remaining limits: glued inexact IDs whose first 26
characters do not canonicalize, non-Cf invisible characters, capitalised
or other keys holding names, and name-only prose. Milestone 3 `context`
continues to honour `no-ai`.

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

Apache-2.0. Some files are adapted from [cr](https://github.com/AnandChowdhary/cr)
(MIT); see [`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES) and
[`docs/borrowing.md`](docs/borrowing.md).
