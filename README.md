# Confidant

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hirefrank/confidant/badge)](https://securityscorecards.dev/viewer/?uri=github.com/hirefrank/confidant)
[![CII Best Practices](https://www.bestpractices.dev/projects/15504/badge)](https://www.bestpractices.dev/projects/15504)

**Confidant is relationship memory you own.** It remembers the people in
your life — the friend you meant to call, a sibling's birthday, the mentor
you last saw in March — in one private place your AI agents can read and
update. Each person is a Markdown file with notes, dates, and a log of every
touch; `confidant check` turns that into who is overdue and which dates are
coming up.

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

**The preferred path: let your agent install it.** Paste this into Muse,
Grok Bot, Claude Code, Cursor, Codex, or any agent that can run commands; it
installs the CLI and TUI, links the embedded skills, and asks where your
vault is. This README is the canonical home for the prompt;
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
3. Check git before anything vault-shaped — a vault is a git repo, and
   every vault step below (`init`, clone, push/pull sync) needs it. Do
   this now, not at the first failure, when it is hardest to tell
   git-missing from git-unauthenticated from something else:
   - Run `git --version`. If git is missing, install it, then re-check
     before continuing: macOS `xcode-select --install` or
     `brew install git`; Linux via the distro package manager
     (`apt install git`, `dnf install git`, or `pacman -S git`); Windows
     runs under WSL2, so install git inside WSL2 with that distro's
     package manager (for example `apt install git` on Ubuntu/Debian,
     `dnf install git` on Fedora, `pacman -S git` on Arch) — a
     standalone git-scm/winget install is native Windows git, which
     Confidant does not support. If the version is below 2.34.0,
     upgrade (strongly recommended): macOS `brew upgrade git`, Linux
     `apt upgrade git`, `dnf upgrade git`, or `pacman -Syu git` (inside
     WSL2 for Windows). Below the floor is not a hard block on a fresh
     install: `confidant doctor` reports it as a warning, since older git
     is still usable for the commands Confidant runs. Upgrade when you
     can.
   - Make sure git has an identity, because `init` commits: check first
     with `git config --global user.name` and
     `git config --global user.email`, and set only values that are
     unset — do not overwrite an existing identity. If a value is
     missing, ask me for it (do not invent it) and set
     `git config --global user.name "Your Name"` and
     `git config --global user.email "you@example.com"`.
   - Do not probe remote credentials here: at this point you do not
     yet know whether there is a remote at all, let alone its URL (step
     6 asks that). Version and identity above are the whole of step 3;
     the credential probe lives in step 6, at the point the URL is
     known, immediately before the first clone or first push that uses
     it. If this vault will be local-only, git is still required for
     `init` but remote auth is not — do not conflate the two: a missing
     credential is not a blocker for a local-only vault.
4. Ask me where my vault is. Export it for this session only:
   `export CONFIDANT_VAULT="<path>"`, and pass `--vault "<path>"`
   explicitly on the commands you run. Do **not** rely on
   `source ~/.bashrc` in a non-interactive or agent shell: an interactive
   guard such as `[[ $- != *i* ]] && return` skips the export, and a
   stale `CONFIDANT_VAULT` silently makes `check` and `doctor` inspect a
   different vault. Give me the line to add to my shell rc for interactive
   use as separate advice. If I have no vault yet, ask whether to create
   one at a path I choose or stop — do not invent a path.
5. Tell me plainly, before any vault step, that Confidant keeps **plaintext**
   records in a private git repo: every record body, history included, is
   readable by anyone who can read that repo, so it belongs on a machine with
   full-disk encryption (LUKS or FileVault) and a **private** remote. There is
   no mode to choose and no key to set up; `no-ai` on a record keeps its
   content out of what agents read, but it does not make the bytes secret.
   For a fresh vault, run `confidant init --create --no-input` against an
   absent or empty directory (add `--remote <url>` if I already have a
   remote; it sets origin and does not push): it scaffolds the directory,
   starts the git repo on branch `main` (and reports the branch), seeds
   `packs = []` (packs are optional), writes `.gitignore` and
   `confidant.toml`, creates the collection directories, and commits the
   skeleton. For an existing directory that is not yet initialized, make sure
   the working tree is clean (`git status`) and run `confidant init`.
6. Optional remote: **before** `init`, ask whether I already have a git
   remote URL for backup and putting this vault on another device. If I do,
   pass `--remote <url>` on `confidant init --create` (it sets `origin` and
   does not push). Before the first clone or first push that uses that
   URL — not before `init --remote` itself, which only sets `origin`
   and never contacts the host — probe it, non-interactively so a
   missing credential fails instead of hanging on a prompt in an agent
   shell: `GIT_TERMINAL_PROMPT=0 git ls-remote <url>` must succeed.
   That success is the gate; git installed and working does **not**
   mean a private clone works. If it fails, tell the two failures
   apart: an auth failure means fix credentials first and do not debug
   the vault step; a repository-not-found failure means the repo does
   not exist on the host yet — create it there first, then re-probe
   (credentials that are not broken do not need fixing).
   `gh auth status` is only a diagnostic, never a second gate: a
   private clone that already succeeds via an SSH key or a PAT in the
   credential helper passes the gate even when `gh` is not logged in,
   and on a non-GitHub host a `gh` login is irrelevant. `gh auth status`
   matters only when `ls-remote` also fails and the chosen route is
   GitHub-over-HTTPS via `gh`. Recommended default on a GitHub host:
   `gh auth login` (the device flow suits headless/agent machines; an
   interactive login registers `gh` as git's credential helper, so plain
   clone/pull/push work on the HTTPS route). After a non-interactive
   `gh auth login --with-token`, run `gh auth setup-git` separately —
   that login alone does not register the helper. If the operator chose
   SSH during login, the helper claim does not apply at all.
   Alternatives: an SSH key, where SSH to the host actually works, or a
   PAT stored via the git credential helper or the OS credential store —
   never pasted into a repo config, never committed, and never an account
   password (GitHub rejects passwords for git operations). A token
   that only exists somewhere else (for example one an agent can only
   use through an API) does not count: if it cannot be handed to git,
   the clone path is not working yet.
   If I decide after init, show me `git remote add origin
   <url>` (and probe before the first push, as above). In either case,
   set the upstream once with `git push -u origin
   main`, then use `confidant sync --push` for later pushes — never push
   without my explicit confirmation. On a **new device for an existing
   vault**, do not run `init`: confirm `git ls-remote <url>` succeeds first
   (the probe above), then clone the repo and start using it.
7. Verify: run `confidant check --vault "<path>" --json --no-input` and
   `confidant doctor --vault "<path>"`; report the error/warning counts,
   the branch `init` created, and any `git-remote` or `local-commits`
   warning.
8. Read the routing snippet (`confidant routing`) for the propose →
   confirm → apply workflow every skill follows, and the Privacy rules
   (trusted devices with full-disk encryption; a private remote;
   `.confidant/` is never committed; `no-ai` records stay out of agent
   output — see the README's Privacy section and `docs/privacy.md` in the
   GitHub repo).

Report back: CLI version (`confidant --version`), which skills you linked,
the vault branch, the `check` result, and any `confidant doctor` warnings.
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
device possible. On a second device, clone the repo and use it — there is
no enrollment step. If the vault already exists without a remote:

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

`confidant doctor` reports a `git-remote` check: local-only is fine, a
private `https://` or `ssh://` remote is fine, and a cleartext or
unverifiable transport is a **warning**. A second `local-commits` check
reports ahead/behind from the last fetch. The manual rhythm, refusal codes,
and the opt-in systemd/launchd timer are in [`docs/sync.md`](docs/sync.md).

**The remote must be private.** A remoted vault exposes every record body,
history included, to anyone with access to the repository, and Confidant
cannot see a host's privacy setting. If that is not the tradeoff you want,
remove the remote; anything already pushed stays readable in its history.
Details:
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
The demo is fake data. For your own vault, `confidant init --create
--no-input` on an empty directory creates one on branch `main`. Records are
plaintext in the repo, so keep it private and on a full-disk-encrypted
machine ([Privacy](#privacy)).

## How your agents use it

`confidant setup --agent auto` links the embedded skills. Agents use the
CLI — or `confidant mcp`, a thin stdio wrapper over the same commands — and
follow one workflow: propose, confirm, apply. Every command takes `--json`
and `--no-input`; usage errors exit 2; branch on `code`, never message text.

`confidant mcp` exposes ten fixed tools (`check`, `doctor`, `find`,
`context`, `log_session`, `log_touch`, `import_ledger`, `note_add`, `schema`,
`pack_skill`); no tool can widen that list. A write runs `check` and commits once. `--packs` scopes
reads (on `mcp` it is the instance ceiling) as a read-time policy filter,
not access control ([`docs/privacy.md`](docs/privacy.md#pack-scoping-issue-178),
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
| Setup | `init`, `setup`, `update`, `doctor` |
| Search | `find`, plus the optional `qmd-search` skill |
| Sync | `sync` (read-only report; `--pull` / `--push` explicit) |
| Agents | `mcp`, `agents`, `which`, `routing`, `tui` |

**Contact values** (emails, phones, handles, former names) are front-matter
fields on the person, declared by the personal pack. `alias resolve <kind>
<value>` matches them directly — trimmed, case-insensitive, whole-string —
and canonicalizes through merges. Two different people sharing a value is
`E_AMBIGUOUS_PERSON`, not a silent pick.

## The TUI

`confidant-tui` is a terminal UI for the roster, a person's context, vault
health, quick capture, and review of queued work. It consumes only the
ADR-7 CLI JSON contract and keeps record content on the alternate screen
only.
Install both from the same release — `cargo install confidant-cli
confidant-tui` — then run `confidant tui --vault examples/demo-vault`.
`confidant tui` and `confidant doctor` warn when the CLI and TUI versions
differ; upgrade both together.

Operator mode (`!`) is off by default; `e` edits through the operator-only
path, `s` / `t` / `n` capture a session, touch, or note, and `2` opens the
review queue. Tabs and phase history: [`docs/tui.md`](docs/tui.md).

## Packs

A **schema pack** declares verbs, record types, fields, edge kinds, balance
metrics, and check rules; its manifest
([`spec/pack-manifest.md`](spec/pack-manifest.md)) is the machine-readable
contract.

**`personal@0.2` is built in and always on.** It supplies the relationships
schema this README describes: birthdays (full dates or year-less `--MM-DD`),
recurring dates, `relationship`, `cadence` with `snooze_until`, contact
fields, relationship edges, the `touch` verb, and two warning-level rules
(`W_CADENCE_OVERDUE`, `W_DATE_UPCOMING`) that never block a write. Contract:
[`packs/personal/0.2.md`](packs/personal/0.2.md). A vault needs no other pack
to be useful, and a `personal@…` entry in `packs` is a no-op.

**Extra domains are optional packs in the same vault.** `init --create`
seeds `packs = []`, and `check` is clean without one.

**Installing a pack.** Where a pack comes from is an implementation detail:
`pack add` takes a `https://` URL or a local directory (`--from-dir`), and
both behave the same. Without `--yes` it fetches the URL (or reads the local
directory), validates, prints every claim and the full skill text, and writes
nothing.
With `--yes` it vendors the pack under `packs/`, pins its hash in
`confidant.lock`, lists it in `packs`, runs `check`, and commits. Review that
report as code first: a pack's `SKILL.md` becomes agent instructions.

A vault that lists a pack must vendor it. A missing copy or a drifted hash
makes `check` fail with `E_PACK_UNKNOWN` and blocks writes; `pack verify`
re-checks the vendored copy against the pin.

**Writing a pack.** An agent can build one for a local need with no git host
and no core change — `pack init` scaffolds and validates it, and the
embedded `pack-author` skill walks through the same steps:

```sh
confidant pack init ~/confidant-packs/weekly-checkin
confidant pack add --from-dir ~/confidant-packs/weekly-checkin            # review only
confidant pack add --from-dir ~/confidant-packs/weekly-checkin --yes      # install
confidant pack verify
```

Keep the source outside the vault: the copy under `<vault>/packs/` is
generated, never the editing surface. `pack init` scaffolds the manifest,
skill, and versioned contract; fill in fields, verbs, finding codes,
`[checks]` keys, and rules in the manifest. A rule names a core-implemented
kind — the pack carries no code. After editing, bump `[pack].version`,
rename the contract file, and review the change before applying it:

```sh
confidant pack update <name> --from-dir ~/confidant-packs/weekly-checkin
confidant pack update <name> --from-dir ~/confidant-packs/weekly-checkin --yes
```

The first command prints the diff and stops.

Migrating a pack with existing data: `pack add --yes` refuses when the vault
already sets the pack's `[checks]` keys or vendors its copy but does not list
it. Add `"<name>@<version>"` to `packs` in `confidant.toml` first (or remove
the dependent `[checks]` keys), then re-run. If the vault already has the
pack's data/checks, `pack add --from-dir <dir> --allow-unresolved --yes`
installs over it: only the pre-check is skipped, the post-check and `check`
still gate, and unrelated errors roll back. The flag needs `--yes`; without
it, `pack add` stays the read-only review. `pack remove --yes` refuses while
ledger lines, metrics, or `[checks]` keys still use the pack, so remove or
migrate those entries first, or keep the pack installed; a remove-side flag
is not available yet (#699). The errors name the workaround.

A local pack is hash-pinned but unsigned: `pack verify` detects drift, and
nobody vets it for you. Review its `SKILL.md` as code, because it becomes
agent instructions. It cannot widen the §12 allowlist or read `no-ai`
content; the CLI enforces that, not the pack text.

**Scoping.** Packs share a vault, and `--packs` scopes a read to the packs
you name. That is a read-time policy filter, not an access boundary —
the vault is plaintext on disk
([`docs/privacy.md`](docs/privacy.md#pack-scoping-issue-178)).

## Search

**`confidant find`** scans the vault directly, exact and fail-closed: it
returns content only from the **cleared allowlist** — parsed cleanly, no
`no-ai: true` flag, every referenced ID cleared. An uncleared record is
omitted, not redacted. Numbers:
[`docs/search-benchmark.md`](docs/search-benchmark.md).

**QMD search** is an optional on-device semantic layer (BM25 + vectors +
reranking), shipped as an embedded skill, not a CLI dependency. The skill
stages a copy of the cleared set under `<vault>/.confidant/` (gitignored,
never committed) and verifies every hit through `confidant allowlist`, so a
query-path bug degrades to missing results; without QMD it falls back to
`confidant find` and says so. Design:
[`crates/confidant-cli/skills/qmd-search/docs/design.md`](crates/confidant-cli/skills/qmd-search/docs/design.md).

## Privacy

**Records are plaintext on disk.** A vault is Markdown and `.cfd` files in a
git repo; `record add`, `note add`, and `log session --note` write those
bytes directly. There is no second secrecy layer and no key material, so a
clone is the whole vault.

That makes the perimeter easy to state, and it is the whole privacy model:

- **The machine.** Run Confidant on devices you control, with full-disk
  encryption on (LUKS, FileVault). Disk encryption is the operating-system
  setting that covers a stolen laptop; Confidant does not manage it.
- **The repo.** Sync to a **private** remote. Anyone with access to the repo
  can read every record and every commit, history included, and anything
  pushed there stays in history (deleting a file is not erasing it).
- **`no-ai`.** A record or a person can be marked `no-ai`, which keeps its
  content out of `find`, `context`, the allowlist, MCP, and the search
  corpus that agents read. Content stays out while `context` still serves
  derived ledger metadata; the flag itself is visible in the record's front
  matter.

`no-ai` is an exposure control, not access control: the operator owns the
files, and an agent with a shell on the same machine can read them. A stolen
unlocked device, or malware on a trusted device, defeats every guarantee.
See [`docs/privacy.md`](docs/privacy.md),
[`docs/threat-model-agents.md`](docs/threat-model-agents.md), and
[`docs/architecture.md`](docs/architecture.md) §3–§4.

Content an agent reads is sent to a hosted model provider; this is explicit
and accepted, and Confidant makes no claim about what the provider stores.

`confidant doctor` checks GitHub for the latest release and reports skills
link health. The release check is one unauthenticated `GET` to
`api.github.com/repos/hirefrank/confidant/releases/latest`; no vault data is
included, and only the `tag_name` is read — the response body is discarded.
Set `CONFIDANT_OFFLINE=1` to skip the request; the check then reports
`staleness check disabled`.

## Where to go deeper

- [`spec/0.1.md`](spec/0.1.md) — vault format; [`spec/findings.md`](spec/findings.md) — finding codes; [`spec/pack-manifest.md`](spec/pack-manifest.md) — pack manifests.
- [`docs/architecture.md`](docs/architecture.md) — privacy, threat model, ADRs, milestones.
- [`docs/privacy.md`](docs/privacy.md) — allowlist, `no-ai`, pack scoping, edges; [`docs/threat-model-agents.md`](docs/threat-model-agents.md) — agent limits and gaps.
- [`docs/sync.md`](docs/sync.md) — the explicit git boundary and timer; [`docs/tui.md`](docs/tui.md) — TUI detail; [`docs/agent-setup.md`](docs/agent-setup.md) — headless hosts and updates.
- [`packs/`](packs/) — pack contracts; [`docs/search-benchmark.md`](docs/search-benchmark.md) — search numbers.

## Where we're going

The roadmap is the open issues on GitHub. The current themes:

- **Domain model** — record types and edges defined by packs, so a domain beyond people is first-class ([#796](https://github.com/hirefrank/confidant/issues/796)).
- **Agent ergonomics** — cheaper reads across MCP calls ([#543](https://github.com/hirefrank/confidant/issues/543)).
- **TUI** — a new-person modal ([#621](https://github.com/hirefrank/confidant/issues/621)).
- **First-run setup** — pack selection on `init --create` ([#639](https://github.com/hirefrank/confidant/issues/639)), a safer `init` on a non-empty directory ([#640](https://github.com/hirefrank/confidant/issues/640)).

## Security status

Confidant keeps records in plaintext by design (see [Privacy](#privacy)), so
there is no cipher for an outside auditor to review. What the project does
maintain: the
[OSTIF / LeastAuthority security best-practices guide](https://github.com/ostif-org/best-practices-guide)
as its baseline, a private vulnerability reporting channel
([SECURITY.md](SECURITY.md)), CI running `cargo deny`, `cargo audit` and
CodeQL on every change, `-D warnings` builds, no `unsafe` in
`confidant-core`, fuzz targets for the parser, and attested release builds.

Two operational rules do the work that a secrecy layer would otherwise do:
keep the vault on machines you control with full-disk encryption on, and push
only to a private remote. `check`, the allowlist and `no-ai` are working
controls over what agents read, not substitutes for those two rules.

## License

Copyright 2026 Frank Harris. Licensed under the Apache License, Version 2.0
(`license = "Apache-2.0"` in [`Cargo.toml`](Cargo.toml)). See
[`LICENSE`](LICENSE) for the full text. Some files are adapted from
[cr](https://github.com/AnandChowdhary/cr) (MIT); see
[`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES) and
[`docs/borrowing.md`](docs/borrowing.md).
