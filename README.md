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
cadence, and the `touch` verb). Other domains come from schema packs you
author locally or install into the same vault.

Records are plain-text files in a git repo (the **vault**); the Rust CLI
`confidant` reads, checks, and writes them. There is no server, and a ledger
of dated facts (`ledger/2026/10.cfd`) keeps the record append-only and
auditable.

Start with [Install](#install) or the [demo
quickstart](#first-five-minutes-the-people-in-your-life).

Starting over, or adopting Confidant in stages? See
[Starting fresh, and adopting in stages](docs/starting-fresh.md) — personal
relationships first (`personal@0.2` is built in), extra packs later, in the
same vault.

## Install

**The preferred path: let your agent install it.** Paste this into Claude
Code, Cursor, Codex, or any agent that can run commands; it installs the
CLI and TUI, links the embedded skills, and asks where your vault is. This
README is the canonical home for the prompt;
[`docs/agent-setup.md`](docs/agent-setup.md) covers headless hosts,
environment variables, and updates.

```text
Set up Confidant (relationship memory you own — a CLI plus embedded agent skills) on this machine:

1. Install the CLI and TUI together: `cargo install confidant-cli
   confidant-tui` (needs a Rust toolchain 1.88+; check with
   `rustc --version` — if it says "no default is configured", run
   `rustup default stable` first). The CLI provides the `confidant`
   binary. Make sure `~/.cargo/bin` is on PATH first
   (`export PATH="$HOME/.cargo/bin:$PATH"`) or the next step fails with
   `confidant: command not found`. Verify with `confidant --help`.
   (No Rust toolchain? Download both binaries + the installer from the
   latest GitHub Release at
   https://github.com/hirefrank/confidant/releases instead — install them
   from the same release so their versions match — and verify the
   downloaded `.tar.xz`/`.zip` first: check the published `.sha256`
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
3. Ask me where my vault is. Export it for this session only:
   `export CONFIDANT_VAULT="<path>"`, and pass `--vault "<path>"`
   explicitly on the commands you run. Do **not** rely on
   `source ~/.bashrc` in a non-interactive or agent shell: an interactive
   guard such as `[[ $- != *i* ]] && return` skips the export, and a
   stale `CONFIDANT_VAULT` silently makes `check` and `doctor` inspect a
   different vault. Give me the line to add to my shell rc for interactive
   use as separate advice. If I have no vault yet, ask whether to create
   one at a path I choose or stop — do not invent a path.
4. Ask me whether this vault is for **real relationship data** (encrypted
   mode, the production default) or **demo / learning / fixtures only**
   (plaintext opt-out), and explain the consequences before editing
   `confidant.toml` or running `confidant init`:
   - **Encrypted (real data):** ensure git has `user.name` and
     `user.email` (init commits). For a fresh vault, run
     `confidant init --create --no-input --phrase-out <path>` against an
     absent or empty directory (add `--remote <url>` if I already have a
     remote; it sets origin and does not push): it scaffolds the directory,
     starts the git repo on branch `main` (and reports the branch), seeds
     `packs = []` (packs are optional), writes `.gitignore` and
     `confidant.toml`, then creates the keys. For an existing directory that
     is not yet initialized, first ensure
     `confidant.toml` does **not** set `[crypto] mode = "plaintext"` (never
     silently copy the demo vault's `mode = "plaintext"` into a vault I
     described as real) and the working tree is clean (`git status`), then
     run `confidant init`. Record bodies are encrypted in git; ledger lines
     stay structural plaintext. The 24-word recovery phrase goes to
     `<path>` (mode 0600, refuses to overwrite) and the command prints
     only the path — never echo, copy, or read the phrase into this chat.
     Have me run the human-only check
     `confidant keys verify-recovery --phrase-file <path>` before moving
     the file offline, then move it offline and delete the local copy
     (agents must not handle or pipe the phrase).
   - **Plaintext (demo / learning / fixtures only):** set or keep
     `mode = "plaintext"` under `[crypto]` in `confidant.toml` (only valid
     while the vault is structurally plaintext; never for real PII), do
     **not** run `confidant init`, and warn that `git clone` exposes all
     record content and that a plaintext vault must not be pushed to any
     remote.
5. Optional remote: **before** encrypted `init`, ask whether I already
   have a git remote URL for backup and putting this vault on another
   device. If I do, pass `--remote <url>` on `confidant init --create`
   (it sets `origin` and does not push). If I decide after init, show me
   `git remote add origin <url>`. In either case, set the upstream once
   with `git push -u origin main`, then use `confidant sync --push` for
   later pushes — never push without my explicit confirmation, and never
   push a plaintext vault. A plaintext vault stays local. On a **new device
   for an existing vault**, do not run `init`: clone the repo and run
   `confidant keys device-add` (`recover` only if every enrolled device is
   lost).
6. Verify: run `confidant check --vault "<path>" --json --no-input` and
   `confidant doctor --vault "<path>"`; report the error/warning counts,
   the branch `init` created, and any `git-remote` or `local-commits`
   warning.
7. Read the routing snippet (`confidant routing`) for the propose →
   confirm → apply workflow every skill follows, and the Privacy rules
   (trusted devices with encrypted disks only; `.confidant/` is never
   committed; `no-ai` records stay out of agent output — see the README's
   Encryption and privacy section and `docs/privacy.md` in the GitHub repo).

Report back: CLI version (`confidant --version`), which skills you linked,
vault crypto mode (encrypted vs. plaintext opt-out), the vault branch, the
`check` result, and any `confidant doctor` warnings.
```

**No agent?** `cargo install confidant-cli confidant-tui && confidant setup --agent auto`
(Rust 1.88+; if `rustc --version` says "no default is configured", run
`rustup default stable`). Prebuilt binaries are on
[GitHub Releases](https://github.com/hirefrank/confidant/releases) for macOS
and Linux (x86_64), Windows under
[WSL2](https://learn.microsoft.com/en-us/windows/wsl/install). To update,
re-run the installer or `cargo install` both packages, then `confidant setup`.
Contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md).

### Remote (optional)

`confidant init --create` starts a local git repo on `main`. Pass
`--remote <url>` to set `origin` (it still does not push). Local-only is a
valid setup; a remote is what makes backup and putting the vault on another
device possible. On a second device, clone the repo and run
`confidant keys device-add` — not `init`, and not `recover` unless every
enrolled device is lost (`recover` rotates the recovery phrase). If the
vault already exists without a remote:

```sh
git remote add origin <url>
git push -u origin main
```

The URL is whatever your git host gives you — Confidant does not require
GitHub. Writes commit locally and nothing pushes as a side effect; the only
command that talks to a remote is `confidant sync`:

```sh
confidant sync             # fetch, report ahead/behind
confidant sync --push      # push after confirmation (--yes with --no-input)
confidant sync --pull      # fast-forward only, after confirmation
confidant sync --dry-run   # report the last-fetched state; no network
```

`confidant doctor` reports a `git-remote` check: local-only is fine, an
encrypted vault with a remote is fine, and a remote on a
`[crypto] mode = "plaintext"` vault is a **warning**. A second
`local-commits` check reports ahead/behind from the last fetch. The manual
rhythm, refusal codes, and the opt-in systemd/launchd timer are in
[`docs/sync.md`](docs/sync.md).

**Never push a plaintext-mode vault to any remote**: every record body is
readable by anyone with access to the repository. Plaintext is only for
demo, learning, and fixtures. Details:
[`docs/agent-setup.md`](docs/agent-setup.md#connect-a-git-remote-optional).

## First five minutes: the people in your life

The demo vault is fake data: a friend, a sibling, a partner, and a mentor.
Copy it out so writes commit to a scratch repo:

```sh
git clone --depth 1 https://github.com/hirefrank/confidant
cp -r confidant/examples/demo-vault /tmp/confidant-demo
cd /tmp/confidant-demo && git init -q -b main && git add -A
git commit -qm "demo vault" && export CONFIDANT_VAULT="$PWD"
```

In an agent or other non-interactive session, pass `--vault "$PWD"`
explicitly instead of relying on an exported variable — and never
`source ~/.bashrc` to set it: an interactive guard skips the export, and a
stale `CONFIDANT_VAULT` can make `check` inspect the wrong vault.

`confidant record list` prints the visible people; the one marked
`no-ai: true` is absent. `confidant check` lists what needs attention:

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
--no-input --phrase-out <path>` on an empty directory makes an encrypted
vault on branch `main` and writes a 24-word recovery phrase once to `<path>`
(mode 0600; move it offline and delete the local copy). Never paste the
phrase into chat or a log; `confidant keys verify-recovery --phrase-file
<path>` is the human-only read-only check that the saved copy matches the
vault.

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
| Packs | `pack init`, `pack add`, `pack list`, `pack verify`, `pack update`, `pack remove` |
| Keys | `init`, `recover`, `keys init-client` / `rotate` / `revoke` / `shred` / `device-add` / `verify-recovery` |
| Inbox | `inbox`, `inbox rotate` |
| Search | `reindex` + `qmd-search` skill |
| Sync | `sync` (read-only report; `--pull` / `--push` explicit) |
| Health | `doctor` |
| Agents | `mcp`, `setup`, `update`, `agents`, `which`, `routing`, `tui` |

**Aliases** map a `kind:value` to a person. The raw value is PII: `alias
add` and `alias resolve` read it from stdin or `--value-file`, never an
argument, and emit only `hmac:`.

## The TUI

`confidant-tui` is a terminal UI for the roster, a person's context, vault
health, quick capture, and review of queued work. It consumes only the
ADR-7 CLI JSON contract and keeps plaintext on the alternate screen only.
Install both from the same release — `cargo install confidant-cli
confidant-tui` — then run `confidant tui --vault examples/demo-vault`.
`confidant tui` and `confidant doctor` warn when the CLI and TUI versions
differ; upgrade both together.

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

**External packs — optional.** Packs are optional: `init --create` seeds
`packs = []`, and `check` is clean without any pack because `personal@0.2`
is built in. Install an external pack after init with
`confidant pack add <https-url> --yes`, or author one locally (below). A
pack can add verbs, record types, fields, balance metrics, edge kinds, and
check rules.

A vault that lists an external pack must vendor it, or `check` fails with
`E_PACK_UNKNOWN` and writes are blocked. `pack verify` checks the vendored
copy against the pinned hash in `confidant.lock`.

### Local packs

An agent can write a pack for a local need without a git host or a core
change. Keep the source outside the vault (for example
`~/confidant-packs/weekly-checkin/`). The embedded `pack-author` skill walks
an agent through the same steps; review its output as code:

```sh
confidant pack init ~/confidant-packs/weekly-checkin
confidant pack add --from-dir ~/confidant-packs/weekly-checkin            # review only
confidant pack add --from-dir ~/confidant-packs/weekly-checkin --yes      # install
confidant pack verify
```

`pack init` writes `manifest.toml`, `SKILL.md`, `<version>.md`, and
`README.md`, and validates the result. Fill in `[[fields]]`, `[[verbs]]`,
finding codes, `[checks]` keys, and `[[rules]]` in the manifest. A rule
names a core-implemented kind; the pack carries no code.

`pack add --from-dir` without `--yes` is the review step: it validates the
directory, prints every claim and the full skill text, and writes nothing.
Only `--yes` vendors, pins, adds the pack to `packs`, runs `check`, and
commits. After editing the source, bump `[pack].version`, rename the
contract file, and review the change:

```sh
confidant pack update <name> --from-dir ~/confidant-packs/weekly-checkin
confidant pack update <name> --from-dir ~/confidant-packs/weekly-checkin --yes
```

The first command prints the diff and stops. The generated copy under
`<vault>/packs/` is not the editing surface.

Migrating a pack with existing data: `pack add --yes` refuses when the vault
already sets the pack's `[checks]` keys or vendors its copy but does not list
it. Add `"<name>@<version>"` to `packs` in `confidant.toml` first (or remove
the dependent `[checks]` keys), then re-run. `pack remove --yes` refuses
while ledger lines, metrics, or `[checks]` keys still use the pack, so
remove or migrate those entries first, or keep the pack installed; the
explicit orphan flag is tracked in #696. Both errors name the workaround.

A local pack is unsigned but hash-pinned: `pack verify` detects drift. Review
its `SKILL.md` as code, because it becomes agent instructions. It cannot
widen the §12 allowlist or read `no-ai` content; the CLI enforces that, not
the pack text.

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
[`docs/privacy.md`](docs/privacy.md),
[`docs/threat-model-agents.md`](docs/threat-model-agents.md), and
[`docs/crypto-design.md`](docs/crypto-design.md). The encryption has not
been independently audited; see
[Security status](#security-status-no-independent-audit-yet).

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
- [`docs/crypto-design.md`](docs/crypto-design.md) — keys, envelopes, recovery; [`docs/sync.md`](docs/sync.md) — the explicit git boundary and timer; [`docs/tui.md`](docs/tui.md) — TUI detail; [`docs/agent-setup.md`](docs/agent-setup.md) — headless hosts and updates.
- [`packs/`](packs/) — pack contracts; [`docs/search-benchmark.md`](docs/search-benchmark.md) — search numbers.

## Where we're going

The roadmap is the open issues on GitHub. The current themes:

- **Outside crypto audit** — [#138](https://github.com/hirefrank/confidant/issues/138), the gate on public launch.
- **Crypto scope and shredding** — scoped recipients ([#160](https://github.com/hirefrank/confidant/issues/160)), pair keys for edges ([#257](https://github.com/hirefrank/confidant/issues/257)), a real shred path ([#155](https://github.com/hirefrank/confidant/issues/155)).
- **Agent ergonomics** — cache decrypted reads across MCP calls ([#543](https://github.com/hirefrank/confidant/issues/543)).
- **TUI** — a new-person modal ([#621](https://github.com/hirefrank/confidant/issues/621)).
- **First-run setup** — pack selection on `init --create` ([#639](https://github.com/hirefrank/confidant/issues/639)), safe `init --force` ([#640](https://github.com/hirefrank/confidant/issues/640)), a reset path for local state ([#638](https://github.com/hirefrank/confidant/issues/638)).

## Security status: no independent audit yet

Confidant's encryption hasn't been reviewed by an independent auditor. No
audit is scheduled. One will happen if someone sponsors it. If you'd like to
sponsor or arrange one, comment on
[#138](https://github.com/hirefrank/confidant/issues/138).

What is in place: the project follows the
[OSTIF / LeastAuthority security best-practices guide](https://github.com/ostif-org/best-practices-guide).
That means a private reporting channel ([SECURITY.md](SECURITY.md)), and CI
that runs `cargo deny`, `cargo audit` and CodeQL on every change. It also
means no `unsafe` code in the crypto crate, fuzz targets for the parsers,
and attested release builds. The design is written down so you can judge it
yourself:

- [`docs/crypto-design.md`](docs/crypto-design.md): key hierarchy,
  envelopes, recovery and shredding, plus the in-project review history
- [`docs/threat-model-agents.md`](docs/threat-model-agents.md): what
  Confidant does and doesn't protect against when agents read your vault
- [`docs/privacy.md`](docs/privacy.md): what stays plaintext, what `no-ai`
  does, and what reaches a model provider
- [`spec/0.1.md`](spec/0.1.md) §14: the normative envelope format

Until an independent review happens, keep vaults on trusted devices with
encrypted disks, and use your own judgment before storing other people's
sensitive data. `check`, the privacy allowlist and `no-ai` are working
controls, but they don't replace an independent review. This section will
be updated if an audit takes place.

## License

Copyright 2026 Frank Harris. Licensed under the Apache License, Version 2.0
(`license = "Apache-2.0"` in [`Cargo.toml`](Cargo.toml)). See
[`LICENSE`](LICENSE) for the full text. Some files are adapted from
[cr](https://github.com/AnandChowdhary/cr) (MIT); see
[`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES) and
[`docs/borrowing.md`](docs/borrowing.md).
