# Confidant

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hirefrank/confidant/badge)](https://securityscorecards.dev/viewer/?uri=github.com/hirefrank/confidant)
[![CII Best Practices](https://www.bestpractices.dev/projects/15504/badge)](https://www.bestpractices.dev/projects/15504)

**Confidant is relationship memory you own.** It remembers the people in
your life — the friend you meant to call, a sibling's birthday, the mentor
you last saw in March — in one private place your AI agents can read and
update. Each person is a Markdown file with notes, dates, and a log of every
touch; `confidant check` turns that into who is overdue and which dates are
coming up.

The personal use case is the default: every vault has the built-in
`personal@0.2` pack (birthdays, recurring dates, relationship, keep-in-touch
cadence, and the `touch` verb). For a coaching practice, add the optional
`coaching@0.1` pack to the same vault — a client can also be a friend.

Records are plain-text files in a git repo (the **vault**); the Rust CLI
`confidant` reads, checks, and writes them. There is no server, and a ledger
of dated facts (`ledger/2026/10.cfd`) keeps the record append-only and
auditable.

Start with [Install](#install) or the [demo
quickstart](#first-five-minutes-the-people-in-your-life).

## Install

**The preferred path: let your agent install it.** Paste this into Claude
Code, Cursor, Codex, or any agent that can run commands; it installs the
CLI, links the embedded skills, and asks where your vault is. This README
is the canonical home for the prompt; [`docs/agent-setup.md`](docs/agent-setup.md)
covers headless hosts, environment variables, and updates.

```text
Set up Confidant (relationship memory you own — a CLI plus embedded agent skills) on this machine:

1. Install the CLI: `cargo install confidant-cli` (needs a Rust
   toolchain 1.88+; check with `rustc --version`). This provides the
   `confidant` binary. Make sure `~/.cargo/bin` is on PATH first
   (`export PATH="$HOME/.cargo/bin:$PATH"`) or the next step fails with
   `confidant: command not found`. Verify with `confidant --help`.
   (No Rust toolchain? Download the `confidant` binary + installer from
   the latest GitHub Release at
   https://github.com/hirefrank/confidant/releases instead — and verify
   the downloaded `.tar.xz`/`.zip` first: check the published `.sha256`
   checksum file (that's what it covers), or run
   `gh attestation verify <archive> --repo hirefrank/confidant` for build
   provenance.)
2. Install the skills (they ship inside the binary — no repo checkout):
   `confidant setup --agent auto`. This materializes the skills to a
   versioned share dir and links each skill into the detected agent's
   skills directory. (No vault configured yet? `confidant doctor` exits
   with `E_VAULT_NOT_FOUND` before reporting skills-link health, so
   confirm the links with `confidant agents` or
   `confidant which --skills-dir` instead.) (`confidant doctor` checks GitHub for the latest
   release unless `CONFIDANT_OFFLINE=1` is exported — add that to my
   shell rc too, this session and permanently, only if I want that
   request disabled.)
3. Ask me where my vault is and set `CONFIDANT_VAULT` to it (export it for
   this session and tell me what to add to my shell rc to keep it). If I
   have no vault yet, ask whether to create one at a path I choose or
   stop — do not invent a path. To create one, run
   `confidant init --create --no-input` against an absent or empty
   directory: it scaffolds the directory, git repo, `.gitignore`, and
   `confidant.toml`, then the keys.
4. Ask me whether this vault is for **real relationship data** (encrypted
   mode, the production default) or **demo / learning / fixtures only**
   (plaintext opt-out), and explain the consequences before editing
   `confidant.toml` or running `confidant init`:
   - **Encrypted (real data):** `confidant init` creates vault keys and
     shows a 24-word recovery phrase once (store offline); record bodies
     are encrypted in git while ledger lines stay structural plaintext.
     Ensure `confidant.toml` does **not** set `[crypto] mode = "plaintext"`
     (never silently copy the demo vault's `mode = "plaintext"` into a
     vault I described as real) and the working tree is clean
     (`git status`), then guide `confidant init` and recovery-phrase
     handling (never echo the phrase into chat logs).
   - **Plaintext (demo / learning / fixtures only):** set or keep
     `mode = "plaintext"` under `[crypto]` in `confidant.toml` (only valid
     while the vault is structurally plaintext; never for real PII), do
     **not** run `confidant init`, and warn that `git clone` exposes all
     record content.
5. Verify: run `confidant check --json --no-input` against the vault and
   report the error/warning counts.
6. Read the routing snippet (`confidant routing`) for the propose →
   confirm → apply workflow every skill follows, and the Privacy rules
   (trusted devices with encrypted disks only; `.confidant/` is never
   committed; `no-ai` records stay out of agent output — see the README's
   Encryption and privacy section and `docs/privacy.md` in the GitHub repo).

Report back: CLI version (`confidant --version`), which skills you linked,
vault crypto mode (encrypted vs. plaintext opt-out), the `check` result,
and any `confidant doctor` warnings.
```

**No agent?** `cargo install confidant-cli && confidant setup --agent auto`
(Rust 1.88+); prebuilt binaries are on
[GitHub Releases](https://github.com/hirefrank/confidant/releases) for macOS
and Linux (x86_64), Windows under
[WSL2](https://learn.microsoft.com/en-us/windows/wsl/install). To update,
re-run the installer or `cargo install`, then `confidant setup`.
Contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## First five minutes: the people in your life

The demo vault is fake data: a friend, a sibling, a partner, a mentor, and
a small coaching practice. Copy it out so writes commit to a scratch repo:

```sh
git clone --depth 1 https://github.com/hirefrank/confidant
cp -r confidant/examples/demo-vault /tmp/confidant-demo
cd /tmp/confidant-demo && git init -q && git add -A
git commit -qm "demo vault" && export CONFIDANT_VAULT="$PWD"
```

`confidant record list` prints six people (a seventh, `no-ai: true`, is
absent). `confidant check` lists what needs attention:

```text
warning  W_CADENCE_OVERDUE  people/p-01M3TC5H00MPJG000000000101/profile.md  p-01M3TC5H00MPJG000000000101
    person p-01M3TC5H00MPJG000000000101 has no touchpoint on or after 2026-09-17 (last was 2026-09-10, cadence 21d)
    fix: Log a touchpoint with `confidant log touch p-01M3TC5H00MPJG000000000101 <kind>` or widen cadence
warning  W_DATE_UPCOMING  people/p-01M3TC5H00MPJG000000000102/profile.md  p-01M3TC5H00MPJG000000000102
    upcoming date for p-01M3TC5H00MPJG000000000102 on 2026-10-12 (in 4d)
    fix: Reach out to p-01M3TC5H00MPJG000000000102 or set `[checks] personal.date_upcoming = "off"`
0 error(s), 2 warning(s)
```

Those warnings are the feature, not breakage: Dana's 21-day cadence says
"reach out"; Eli's birthday is four days after the pinned `as_of`
(`2026-10-08`). Warnings never block a write; `--fail-on warning` makes
them fail on purpose.

### Add someone and log a touch

A person is a record with an ID in front matter; personal fields are
optional:

```sh
cat > /tmp/robin.md <<'PERSON'
---
id: p-01M3TC5H00MPJG000000000105
type: person
name: Robin Example
relationship: friend
birthday: --11-04
cadence: 30d
---
Fake neighbour; we climb on Thursdays.
PERSON
confidant record add --file /tmp/robin.md
confidant check
```

Robin has no touchpoint, so `check` adds a `W_CADENCE_OVERDUE` with the
"no touchpoint logged" wording. Log the contact and it clears:

```sh
confidant log touch "Robin Example" text --date 2026-10-08
confidant check
```

`log touch` resolves the display name and writes one committed ledger line.
The demo is plaintext fake data; for real people, `confidant init --create
--no-input` on an empty directory makes an encrypted vault and prints a
24-word recovery phrase once (store it offline).

## How your agents use it

`confidant setup --agent auto` links the embedded skills. Agents use the
CLI — or `confidant mcp`, a thin stdio wrapper over the same commands — and
follow one workflow: propose, confirm, apply. Every command takes `--json`
and `--no-input`; usage errors exit 2; branch on `code`, never message text.

`confidant mcp` exposes ten fixed tools (`check`, `doctor`, `find`,
`context`, `log_session`, `log_touch`, `import_ledger`, `note_add`, `schema`,
`pack_skill`); no tool can widen that list. A write runs `check` and commits once. `--packs` scopes
reads (on `mcp` it is the instance ceiling) as a read-time policy filter,
not cryptography ([`docs/privacy.md`](docs/privacy.md#pack-scoping-issue-178),
[`docs/threat-model-agents.md`](docs/threat-model-agents.md)).

`no-ai` keeps a record out of agent output; `--for-operator` on `find`,
`context`, and `record list` is the operator-only escape hatch, and MCP
never passes it. `--person` (on `log session`, `log touch`, `note add`,
`context`) takes a `p-<ULID>` or an **exact display name**; `find` stays
fuzzy and `no-ai: true` people are ID-only.

| Area | Commands |
|---|---|
| Write | `record add`, `record edit`, `record resolve`, `note add`, `note edit`, `log session`, `log touch`, `alias add`, `import` |
| Read | `find`, `context`, `resolve`, `alias resolve`, `record list`, `record show`, `note show`, `allowlist`, `schema`, `help` |
| Check | `check` (read-only; stable codes in [`spec/findings.md`](spec/findings.md)) |
| Packs | `pack add`, `pack list`, `pack verify`, `pack update`, `pack remove` |
| Keys | `init`, `recover`, `keys init-client` / `rotate` / `revoke` / `shred`, `keys device-add` |
| Inbox | `inbox`, `inbox rotate` |
| Search | `reindex` + `qmd-search` skill |
| Health | `doctor` |
| Agents | `mcp`, `setup`, `update`, `agents`, `which`, `routing`, `tui` |

**Aliases** map a `kind:value` to a person. The raw value is PII: `alias
add` and `alias resolve` read it from stdin or `--value-file`, never an
argument, and emit only `hmac:`.

## The TUI

`confidant-tui` is a terminal UI for the roster, a person's context, vault
health, quick capture, and review of queued work. It consumes only the
ADR-7 CLI JSON contract and keeps plaintext on the alternate screen only.
Install both with `cargo install confidant-cli confidant-tui`, then run
`confidant tui --vault examples/demo-vault`.

Operator mode (`!`) is off by default; `e` edits through the operator-only
path, `s` / `t` / `n` capture a session, touch, or note, and `2` opens the
review queue. Tabs and phase history: [`docs/tui.md`](docs/tui.md).

## Packs

A **schema pack** declares extra verbs, types, fields, rules, and metrics;
its manifest ([`spec/pack-manifest.md`](spec/pack-manifest.md)) is the
machine-readable contract.

**`personal@0.2` — built in, always on.** Every vault has it whether or not
`packs` lists it; a `personal@…` entry is a no-op. It adds `birthday`
(`YYYY-MM-DD` or year-less `--MM-DD`), recurring `dates`, `relationship`,
`cadence` (`21d`, or `never`) with `snooze_until`, identity and contact
fields, relationship edges (`friend`, `family`, `sibling`, `partner`,
`parent`, `mentor`, plus the core kinds), and the `touch` verb
(`call|text|email|meet|meal|event|gift|other`). Two warning-level rules
never block a write: `W_CADENCE_OVERDUE` and `W_DATE_UPCOMING`. Contract:
[`packs/personal/0.2.md`](packs/personal/0.2.md).

**`coaching@0.1` — optional, for a practice.** A vault that lists it must
vendor it, or `check` fails with `E_PACK_UNKNOWN` and writes are blocked:

```sh
confidant pack add https://github.com/hirefrank/confidant.git --subdir packs/coaching --yes
```

It adds sessions, packages, ICF hours, balance assertions, and gap rules
(a session with no notes; a paid client with no session in a configurable
window). Contract: [`packs/coaching/0.1.md`](packs/coaching/0.1.md).

Packs share a vault; `--packs` scopes a read to the packs you name. They
are vendored under `packs/` and pinned in `confidant.lock`, and `pack
verify` checks them against the pin. Scoping is a read-time policy filter,
not per-pack cryptography
([`docs/privacy.md`](docs/privacy.md#pack-scoping-issue-178)).

## Search

**`confidant find`** scans the vault directly, exact and fail-closed: it
returns content only from the **cleared allowlist** — parsed cleanly, no
`no-ai: true` flag, every referenced ID cleared. An uncleared record is
omitted, not redacted. Numbers:
[`docs/search-benchmark.md`](docs/search-benchmark.md).

**QMD search** is an optional on-device semantic layer (BM25 + vectors +
reranking), shipped as an embedded skill, not a CLI dependency.
`confidant reindex` builds the corpus from the cleared set under
`<vault>/.confidant/` (gitignored, never committed). `qmd-search` verifies
every hit through the CLI, so a query-path bug degrades to missing results;
without QMD it falls back to `confidant find` and says so.

## Encryption and privacy

**Plaintext belongs only on trusted devices** (your laptop, or an agent
computer acting for you); a git remote must not hold notes in plaintext. On
a keyed vault the write path encrypts record content: `record add`,
`note add`, and `log session --note` write §14 envelopes (per-client data
keys; `name:` lives only inside the ciphertext), and inbox items encrypt at
drain time. Ledger entries, `import`, and `confidant.toml` stay plaintext by
design — a `touch` line carries a date, an opaque ID, and a kind, never
prose.

A `[crypto] mode = "plaintext"` vault opts out; that is only for vaults with
no real data and can never downgrade a keyed vault. Existing plaintext
records are never encrypted in place. `find`, `context`, and
MCP decrypt cleared records (never `no-ai`, except the operator-only
`--for-operator` flag). Content an agent reads is sent to a hosted model
provider; this is explicit and accepted, and Confidant makes no claim about
what the provider stores.

`no-ai` is an exposure control, not access control. Content stays out of
`find`, `context`, the allowlist, and the search corpus, while `context`
still serves derived ledger metadata and the flag itself is visible in the
envelope header. A stolen unlocked device defeats every guarantee. See
[`docs/privacy.md`](docs/privacy.md) and
[`docs/threat-model-agents.md`](docs/threat-model-agents.md).

`confidant doctor` checks GitHub for the latest release and reports skills
link health. The release check is one unauthenticated `GET` to
`api.github.com/repos/hirefrank/confidant/releases/latest`; no vault data is
included, and only the `tag_name` is read — the response body is discarded.
Set `CONFIDANT_OFFLINE=1` to skip the request; the check then reports
`staleness check disabled`.

## Where to go deeper

- [`spec/0.1.md`](spec/0.1.md) — vault format; [`spec/findings.md`](spec/findings.md) — finding codes; [`spec/pack-manifest.md`](spec/pack-manifest.md) — pack manifests.
- [`docs/architecture.md`](docs/architecture.md) — privacy, threat model, ADRs, milestones.
- [`docs/privacy.md`](docs/privacy.md) — allowlist, `no-ai`, pack scoping, shred; [`docs/threat-model-agents.md`](docs/threat-model-agents.md) — agent limits and gaps.
- [`docs/crypto-design.md`](docs/crypto-design.md) — keys, envelopes, recovery; [`docs/tui.md`](docs/tui.md) — TUI detail; [`docs/agent-setup.md`](docs/agent-setup.md) — headless hosts and updates.
- [`packs/`](packs/) — pack contracts; [`docs/search-benchmark.md`](docs/search-benchmark.md) — search numbers.

## Where we're going

The roadmap is the open issues on GitHub. The current themes:

- **Outside crypto audit** — [#138](https://github.com/hirefrank/confidant/issues/138), the gate on public launch.
- **Crypto scope and shredding** — scoped recipients ([#160](https://github.com/hirefrank/confidant/issues/160)), pair keys for edges ([#257](https://github.com/hirefrank/confidant/issues/257)), a real shred path ([#155](https://github.com/hirefrank/confidant/issues/155)).
- **Agent ergonomics** — cache decrypted reads across MCP calls ([#543](https://github.com/hirefrank/confidant/issues/543)).
- **TUI** — a new-person modal ([#621](https://github.com/hirefrank/confidant/issues/621)).
- **First-run setup** — pack selection on `init --create` ([#639](https://github.com/hirefrank/confidant/issues/639)), safe `init --force` ([#640](https://github.com/hirefrank/confidant/issues/640)), a reset path for local state ([#638](https://github.com/hirefrank/confidant/issues/638)).

## Status: not yet audited

**The encryption has had no outside review.** The design was reviewed
in-project and the tests pass, but no independent reviewer has audited it.
Tracked in [#138](https://github.com/hirefrank/confidant/issues/138).

So, today: **keep vaults on trusted devices with encrypted disks, and do
not put other people's sensitive data in them.** `check`, the privacy
allowlist, and `no-ai` work, but they are not a substitute for the outside
audit. This section will say plainly when the audit lands.

## License

Copyright 2026 Frank Harris. Licensed under the Apache License, Version 2.0
(`license = "Apache-2.0"` in [`Cargo.toml`](Cargo.toml)). See
[`LICENSE`](LICENSE) for the full text. Some files are adapted from
[cr](https://github.com/AnandChowdhary/cr) (MIT); see
[`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES) and
[`docs/borrowing.md`](docs/borrowing.md).
