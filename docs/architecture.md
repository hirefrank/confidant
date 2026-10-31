# Confidant: architecture and decision records

*Name: **Confidant** (CLI `confidant`), chosen 2026-10-07. Category: relationship memory you own (decided 2026-10-13, #186). Draft 2026-10-07, revised the same day with the cr spike findings (ADR-13). Author: Frank Harris. Status: proposal for review.*

## 1. What this is

`confidant` is open-source, local-first relationship memory for **one operator** (a solo professional) and their AI agents. Records are plain text in a git repo (the **vault**). A Rust CLI reads, writes and validates the vault. It runs on the operator's own computer and has no server.

It is modeled on beancount and beancount-io: plain text in git, a CLI with a `--file` / `--json` / `--no-input` automation contract, a `check` command, agent skills that confirm before writing, and an MCP server as a thin layer on top.

**Who writes.** An agent is the main writer. It also does capture: email, meeting notes and transcripts reach the vault through the agent calling the CLI, not through built-in background sync. No human reviews a form before data lands, so **the file format, the schema and `check` are the core of the product.** Everything else is replaceable.

**Not goals.** Teams, shared pipelines, permissions UIs, live collaboration, a web app, a hosted service in v0, and a general integration plugin system in v0.

**Later, out of scope here.** A hosted or paid version, probably an agent for
non-technical users. That needs a second person using Confidant and an answer
to how two operators' vaults relate; the expected shape is separate
interoperating vaults, not one shared vault. v0 works with any git remote.

**What it is and what it isn't.** `confidant` is the operator's private record of relationships: people, organizations, deals, interactions and notes, plus the judgment about them. It is **not** a system that faces customers. Booking, payments, invoicing, client logins, scheduling and anything a customer touches stay in the tools built for that (a booking portal, a payment processor, a calendar). `confidant` reads from those systems: an agent or script *pulls* their events into the vault, so nothing ever pushes into `confidant`, and nothing private flows back out to them.

## 2. Why not a typical client/server web app

A server-side CRM holds the operator's notes in the clear, on someone else's
machine, because that is how it searches, displays and summarizes them. Every
hosted CRM works that way (HubSpot, Attio and the rest), and it is what the
privacy model below rules out.

What a web app does better, and why it doesn't matter here:

| Web app strength | Relevance |
|---|---|
| Live multi-user collaboration | Not a goal. One operator. |
| Non-technical users | The later hosted *agent* serves that market. |
| Always-on capture (email, calendar sync) | The agent does capture on a schedule, through the CLI. |

**Main alternative weighed: local-first SQLite app with an op-log sync layer.** Better at concurrent edits (CRDT or op-log merges instead of git merges). It loses plain files you can read and diff, free history and blame from git, and agent fluency: agents already know how to read files, grep, and use git. With one operator and a few devices, concurrent edits are rare, and the file layout (ADR-3) keeps conflicts small. Rejected for v0.

## 3. Privacy model

**Trusted device:** any device or agent computer acting on behalf of the
owner, including a cloud machine running the owner's agent. A shared
application server holding customer data is **not** a trusted device.

**Rule:**

1. Record bodies are plaintext on a trusted device, inside a private git repo,
   on a disk the operator encrypts (LUKS, FileVault). Disk encryption is an
   operating-system setting, not something Confidant manages.
2. Only a **private** git remote or backup receives the vault. Confidentiality
   there rests on the host's access control and the repo being private, which
   is why the remote must be private by choice, not by accident.
3. Nothing private leaves the trusted devices for an outside tool, ever.

**Scope:** one operator, one vault. Multi-user is deferred until there is a
second human; the expected resolution is separate interoperating vaults, not
a shared one. That deferral is what makes plaintext-on-disk acceptable: there
is no second person to isolate notes from.

**The operator↔agent boundary is `no-ai`.** Records (or just their notes) can
be marked `no-ai`, which keeps their content out of `find`, `context`, the
allowlist, and the search corpus that agents read. It is an exposure control
for agent-facing output, not access control: the operator can always read the
files, and an agent with a shell on the same machine can too. Pack scoping
(`--packs`) is a second policy filter on the same read paths.

**Accepted exception:** when an agent reads notes, that content is sent to a hosted model provider for processing. This is explicit and accepted. The design does not claim the provider stores nothing; that depends on the provider's terms.

## 4. Threat model

| Protects against | Does not protect against |
|---|---|
| A leaked laptop or backup, if the disk is encrypted and locked (the OS setting the design assumes) | A compromised trusted device (malware, stolen unlocked laptop, or a disk left unlocked) |
| Filenames revealing who is a client (opaque IDs in paths) | A public repo, or a repo shared with the wrong account: the remote must be private |
| An agent reading `no-ai` content through the CLI, MCP, or the search corpus | Anyone with access to the private repo: records are readable there |
| A malformed or incoherent vault reaching a commit (the `check` gate) | Record bodies, ledger fields and commit messages, which carry whatever the operator and agents put in them |
|  | A model provider seeing what agents send it |
|  | Metadata a git host still sees: commit timing, commit counts, file counts and sizes |

Local indexes and caches (`.confidant/`, any search index) hold plaintext and
embeddings. They are sensitive, gitignored, and stay on trusted devices.

Agent-focused threat model — what an MCP-connected agent can and cannot do, and exactly what `no-ai` and the `check` gate guarantee:
[`docs/threat-model-agents.md`](threat-model-agents.md).

## 5. Layouts

### Vault (user data)

```
vault/
├── confidant.toml              # vault config: spec version, packs, random vault id
├── ledger/2026/10.cfd    # dated one-line entries, one file per month
├── people/p-01J9…/       # profile.md + notes/*.md
├── orgs/o-01J9…/org.md
├── deals/d-01J9…/deal.md
└── .confidant/                 # local index/cache, gitignored, rebuildable
```

### Tool repo

```
confidant/
├── spec/                 # versioned file-format spec (the contract)
├── crates/confidant-core/      # parse, model, derived values, check engine
├── crates/confidant-cli/       # CLI + agent contract + thin MCP server
│   └── skills/           # agent skills, embedded in the binary by `setup`
├── packs/                # built-in and vendored schema packs
├── examples/demo-vault/  # fake data for tests, docs and agents
├── docs/
└── THIRD_PARTY_LICENSES  # MIT notice for code adapted from cr (ADR-13)
```

## 6. Entry format by example

Structured facts are one-line ledger entries. Prose is Markdown.

```
; ledger/2026/10.cfd
2026-10-01 touch    p-01J9Z3K4QF  call
2026-10-08 touch    p-01J9Z3K4QF  meet note:n-01JA02
2026-10-08 balance  p-01J9Z3K4QF  unknown_metric 4
2026-10-09 stage    d-01J9ZB7W1M  proposal
2026-10-12 merge    p-01J9ZQ00XY  into p-01J9Z3K4QF  reason "duplicate account"
```

```markdown
<!-- people/p-01J9Z3K4QF/profile.md -->
---
id: p-01J9Z3K4QF
type: person
name: Example Person
---
Context, goals, preferences. Prose only; no structured facts here.
```

## 7. Decision records

Each ADR is flagged **One-way door** (hard to change once vaults exist) or **Reversible**.

### ADR-1. The file format is a versioned spec, separate from the CLI. Generic core, domain schemas as packs.

**Door:** One-way.

**Context.** Agents, scripts and future tools (including a hosted agent) must read and write vaults without depending on one binary. One operator's domain is not every user's.

**Decision.** Publish the format in `spec/` with a version number declared in each vault's `confidant.toml`. Core record types: person, org, deal, interaction, note. Domain schemas (a clinic's appointments and packages, a team's projects, and so on) are **schema packs** (ADR-8), not core.

**Alternatives considered.** (a) Format defined by whatever the CLI does: faster at first, but every change silently breaks other readers. (b) One domain's types in core: simpler for that operator, but bakes one profession into every vault.

**Consequences.** Format changes need a spec version bump and a migration (`confidant migrate`). The core stays small. External packs are the test that packs work.

### ADR-2. Structured facts are dated ledger entries in a strict grammar; prose is Markdown.

**Door:** One-way.

**Context.** An agent writes most data. Structured facts (touchpoints, stage changes, payments) must be checkable, diffable and mergeable. Derived values (pack balances and totals) must not drift.

**Decision.** Facts are one-line entries, `DATE VERB ID ARGS…`, beancount style, e.g. `2026-10-01 touch p-01J9… call`. Prose lives in Markdown. Derived values are computed, never stored as truth. `balance` entries are assertions that `confidant check` verifies against the computed value. YAML frontmatter holds only identity and display fields (id, type, name), not facts.

Ledger arguments carry identifiers and structured values, never prose: a `touch` line is a date, an opaque id and a kind. Contact values (emails, phones, handles) live in person front matter, declared by the personal pack, and are looked up there directly (ADR-9). The ledger is the only source of truth for facts; there is no separate audit journal (ADR-6).

**Alternatives considered.** (a) YAML frontmatter as source of truth: familiar, but edits overwrite state in place, history is lost inside a field, two devices editing one file conflict, and there are no assertions. (b) JSON/JSONL: strict, but noisy for humans to read and diff. (c) SQLite: see Section 2.

**Consequences.** A parser and grammar to maintain. Line-level diffs and merges. Balance assertions catch agent mistakes at write time. Corrections are new entries (or a reversal entry), not edits.

### ADR-3. Collision-free prefixed IDs, one file per record, append-mostly writes, monthly ledgers.

**Door:** One-way.

**Context.** Laptop and agent computer may write at the same time. Sequential IDs (e.g. `s03`) collide. Two devices editing one file at once conflicts.

**Decision.** ULID-style IDs with type prefixes: `p-` person, `o-` org, `d-` deal (others defined in the spec). One directory or file per record. Writes are mostly appends. Ledger files are split by month to stay small. IDs appear in paths; names never do. The CLI generates ULIDs, and `confidant check` rejects non-conforming IDs and non-ID filenames as errors rather than skipping them.

**Alternatives considered.** (a) Sequential IDs: readable, but collide across devices. (b) Slugs from names: readable, but leak client names into paths and break on renames. (c) One big ledger file: simple, but a conflict hotspot.

**Consequences.** IDs are not human-friendly; the CLI resolves names and aliases to IDs (`confidant find`). Most concurrent writes touch different files or append to different lines. A git merge driver for `.cfd` ledgers (union of sorted lines) is worth shipping.

### ADR-4. Plaintext records on disk; the perimeter is full-disk encryption plus a private repo.

**Door:** One-way (once history is plaintext, it stays plaintext).

**Context.** Notes and PII are the operator's private memory, and a vault's git history is permanent. Something has to define who can read a record. The candidates were application-level secrecy inside the CLI, or trusting the host: the operator's own machines, their disk encryption, and a private remote.

**Decision.**

- **Records are plaintext.** A record is YAML front matter plus a Markdown body on disk: readable, greppable, diffable, and mergeable by git. `record add`, `note add`, and `log session --note` write those bytes straight through an atomic temp-file + rename.
- **The perimeter is the machine and the repo.** The operator runs Confidant on trusted devices (§3) with full-disk encryption enabled, and syncs to a **private** git remote. `confidant doctor`'s `git-remote` check refuses cleartext transports (`http://`, `git://`) and warns on transports it cannot verify; it does not police whether the host is private.
- **`no-ai` is the agent boundary.** It is enforced at read time in the allowlist (§12), not by the storage layer, and it applies to `find`, `context`, `allowlist`, MCP, and the QMD corpus.
- **No second secrecy layer.** There is no key material in a vault, so a vault is self-contained: clone it and read it. That removes key handling from the failure surface — no key to lose, rotate, or fail to unwrap — and it makes every record reviewable with `git diff`.
- **Opaque paths still matter.** Names never appear in paths (ADR-3), so a directory listing does not reveal who is a client even though bodies are readable.

**Alternatives considered.** (a) Per-record application-level encryption (envelopes, per-client keys, recovery phrases): designed and shipped, then removed in #795. It cost key management, recovery, and unusable diffs, and its per-client shredding could never reach bytes already in git history, so it promised deletion it could not deliver. (b) git-crypt or similar: encrypts contents but not paths, deterministic, and no revocation. (c) Full-disk encryption only, with no `no-ai`: leaves agents free to read everything the operator can. (d) A hosted service that does the encryption for you: that is the client/server design §2 rejects.

**Consequences.** A vault copied to an unencrypted disk, a public repo, or a shared backup is exposed. `no-ai` protects agent-facing output, not the files. Anything that must never be readable by whoever holds the repo does not belong in a Confidant vault; use the tool built for that. The trade is deliberate: one operator, their own machines, a private repo, and a plain format that agents handle well.

### ADR-5. Deleting is not erasing.

**Door:** One-way (it's a property of git plus backups, stated so nobody expects otherwise).

**Context.** The operator will want to remove a person: an ex-client, a mistaken record, someone who asked to be forgotten. Deleting the file removes it from the working tree. It does not remove it from git history, from clones, or from backups.

**Decision.** Docs and command output say this plainly rather than implying a wipe. Deleting a record removes it from the live vault (so `find`, `context`, and agents stop seeing it) and leaves history intact. To make deletion stick, the operator rewrites or discards history deliberately, knowing that every clone and backup must be handled too. Confidant never rewrites history on its own.

**Alternatives considered.** (a) Rewriting history automatically on delete: a destructive, hard-to-undo operation that breaks every other device and clone, surprising for a command named `record delete`. (b) A tombstone that hides the record everywhere: keeps the bytes and only changes the view, which overstates what it does.

**Consequences.** Honest expectations, and a reason to keep the vault's history and remotes private (ADR-4). `merge` keeps a merged-away id resolvable on purpose; that is curation, not erasure.

### ADR-6. Files are the only source of truth; indexes and caches are throwaway.

**Door:** Reversible.

**Context.** Search and fast lookups need indexes, and they hold plaintext.

**Decision.** Indexes, caches and any search index live in `.confidant/` (or similar), are gitignored, stay on trusted devices, and are rebuilt from the vault at any time. QMD (tobi/qmd: local BM25, vector and rerank search, Node-based) is **not** a dependency of the Rust CLI. It is integrated through a skill or script (ADR-8). The QMD index holds plaintext chunks and embeddings and is treated as sensitive.

There is no separate audit journal. The audit trail is the ledger plus git history plus signed commits (ADR-10). If more tamper evidence is needed later, sign or anchor commits rather than keep a second chain.

**Alternatives considered.** (a) Committing an index: faster cold start, but publishes plaintext and creates conflicts. (b) Bundling vector search in Rust core: no Node, but a large dependency for a feature not every user needs. (c) A hash-chained audit journal like cr's: rejected. It is one linear chain with a global sequence and an anchor file that every write rewrites, so two devices writing at once always conflict (breaking ADR-3). It is also a second source of truth to reconcile, and it keeps plaintext metadata forever.

**Consequences.** First search on a new device is slower. No index ever needs migrating; delete and rebuild.

### ADR-7. The agent contract.

**Door:** Reversible (but breaking changes need versioning; agents depend on it).

**Context.** The main user of the CLI is an agent. It needs predictable, machine-readable behavior and safe retries.

**Decision.**

- `--json` on every command; every JSON response includes the resolved vault path.
- `--no-input`: never prompt; fail with an error code instead.
- `--file` to pass structured input; `--dry-run` on every write. Dry runs and confirm-before-write skills show and bind to the logical change (ledger lines, the plaintext diff) that will be written.
- Stable exit codes and error codes. Errors name the file and line and suggest a fix; paths are opaque IDs, so this leaks nothing. Errors are classified by type, never by message text. `internal_error` is reserved for unclassified failures, and usage errors exit with code 2.
- Optional `--request-id` so a retried write does not apply twice. It is scoped per write command (imports are multi-record). Only hashes are stored, in a commit trailer: a domain-separated hash of the id and of the canonical request. Reusing an id with different content is an error (`E_IDEMPOTENCY_CONFLICT`). ADR-8's `src:` provenance stays the content-level dedupe.
- One commit per write, attributed to the human or agent. Commit messages and trailers are readable by anyone with the repo, so they carry only opaque IDs, verbs, agent identity and request-id hashes. Free-text reasons and intent go in a record body when they are worth keeping, or are omitted. When an agent performs a write, set `CONFIDANT_AGENT_ID` to an opaque identifier (no free-text names); the write pipeline adds an `Agent:` commit trailer carrying that value.
- `confidant check` runs before every commit; a failing check blocks the write.
- `confidant schema` (JSON Schema), `confidant help --json`, `confidant doctor`.
- `confidant context <person>`: a context bundle, with flags to include or exclude private data.
- Search results return ID, path and excerpt.
- A demo vault with fake data.
- The MCP server is a thin wrapper over the CLI, never a second way in.
- Shipped skills confirm with the human before writing.

```sh
confidant log touch p-01J9Z3K4QF call --request-id 01J9Z3K4QF7F3A000000000000 --json --no-input --dry-run
confidant context p-01J9Z3K4QF --exclude-private --json
confidant check --json
```

```json
{
  "ok": false,
  "vault": "/home/operator/vault",
  "error": {
    "code": "E_UNKNOWN_METRIC",
    "file": "ledger/2026/10.cfd",
    "line": 5,
    "message": "unknown metric",
    "fix": "Use a metric an enabled pack defines, or remove the balance line"
  }
}
```

**Alternatives considered.** (a) MCP-first API: ties automation to one protocol and creates a second code path. (b) Human-oriented output with parsing by agents: brittle.

**Consequences.** Every command needs JSON output and error codes from day one. The contract is versioned and tested against the demo vault.

### ADR-8. Extensibility in v0: check rules, schema packs, and local operations. No integration plugin system.

**Door:** Reversible.

**Context.** Integrations (a booking portal, email, meeting notes, search indexing) are what agents are good at, and they change often. What must *not* be skipped, whoever writes, is validation. Beancount gets this right: its plugins transform and validate entries on every load.

**Decision.** v0 has **no general plugin system for integrations.** Agents handle every integration by calling the agent contract (ADR-7), shipped as agent skills or small scripts embedded in the CLI binary (`crates/confidant-cli/skills/`, installed by `confidant setup`). Extensible in v0:

1. **Check rules / validators.** Run on every write and in `confidant check`, regardless of who writes (human, agent, script). Example: a rule that rejects a package `open` line with no unit count.
2. **Schema packs.** Define record types, ledger verbs and derived values, declared in `confidant.toml`. The built-in personal pack is the reference; external packs add domain schemas (a clinic's appointments, a team's projects).
3. **Local operations at the vault (possible).** Operations such as building a search index run locally and stage only the cleared set through `confidant allowlist --json`, so no general export has to exist. Scope to be decided (Open question 4).

```toml
# confidant.toml
spec = "0.1"
packs = ["example-pack@0.1"]

[checks]
example-pack.require_duration = "error"
example-pack.balance_nonnegative = "error"
```

Integrations are idempotent and record provenance on each entry (`src:<source>/<id>`) so re-running an import adds nothing.

```sh
# installed import skill script, run by the agent on a schedule
confidant import --file events.jsonl --request-id import-2026-10-07 --json --no-input
```

**Alternatives considered.** Git-style subprocess plugins: `confidant-<name>` on PATH, a JSON stdin/stdout protocol, and a capability manifest declaring whether the plugin needs the operator-only (uncleared) tier. Clean, and a likely later addition, but in v0 it is a framework to design, version and secure before there is a second user who needs it. Agents plus the CLI contract cover the same integrations today.

**Consequences.** Less to build and secure in v0. Integration code lives as skills/scripts that may duplicate small helpers. How packs are expressed (declarative TOML/spec files vs compiled Rust) needs a design pass; external packs are declarative, while the built-in personal pack stays compiled behind the same pack interface.

*External packs (#193, approved 2026-10-16).* Schema packs can now also
ship outside the binary: a v2 manifest (`spec/pack-manifest.md` §13)
vendored at `<vault>/packs/<name>@<version>/` and pinned by
`confidant.lock` (`spec/pack-lock.md`), with rule kinds implemented in
core Rust (PD1). Trust is "pin the hash and review the diff": no central
registry, no signing in v1. External packs affect `check` only.

### ADR-9. Identity: aliases and history-preserving merges.

**Door:** Reversible.

**Context.** People have several emails and handles, and an outside system can hold the same person under two accounts.

**Decision.** Contact values (emails, phones, handles) are front-matter fields on the person, declared by the personal pack, and `confidant alias resolve` matches them directly — trimmed, Unicode case-insensitive, whole-string — canonicalizing through merges. A legacy `DATE alias …` ledger line is accepted and ignored so older vaults keep passing `check`; nothing generates it. A `merge` entry folds one ID into another; the old ID stays resolvable and its history is kept. `confidant check` warns on two IDs sharing a contact value.

**Alternatives considered.** Deleting the duplicate and rewriting references: loses history and touches many records. Hashing contact values so the ledger never holds them (the pre-#795 design): it needed a key, broke direct lookup, and was protecting strings that sit in readable front matter anyway.

**Consequences.** Every reader resolves merges. Importers match on contact fields first, then on name. Two cleared people sharing a value is `E_AMBIGUOUS_PERSON`, not a silent pick.

### ADR-10. Auth without a login system: a private repo plus git's own attribution.

**Door:** Reversible.

**Context.** No server, so no accounts. There is exactly one operator, and the machine already has a git identity.

**Decision.** Access is git access: whoever can read the private repo can read the vault, and whoever can push can write it. There is no second lock inside the vault, because there is nothing inside it that could hold one (ADR-4). Attribution comes from git: one commit per write, author and committer set to the operator, and an `Agent:` trailer when a write came from an agent (`CONFIDANT_AGENT_ID`). Signed commits (SSH or GPG) are supported as an option and give tamper-evident attribution, but they are the operator's git configuration, not a Confidant feature: nothing in the CLI verifies a signature today, and git author names can be spoofed without them. Signed commits plus git history are the audit trail (ADR-6).

**Alternatives considered.** (a) A custom auth service: contradicts having no server. (b) A signed allowlist of trusted committers stored inside the vault: anyone with push access could replace the list, so it would authenticate nothing. (c) A second key-based lock per device: see ADR-4's alternatives; removed in #795.

**Consequences.** Keep the remote private and the machine's disk encrypted; that is the whole access model. Turning on commit signing is a per-device git setting and does not change any Confidant command. Adding a second human means separate vaults, not a shared one (§3).

### ADR-11. Vault discovery order.

**Door:** Reversible.

**Decision.** Resolve the vault in this order: `--vault <path>`, then `CONFIDANT_VAULT`, then walk up from the current folder looking for `confidant.toml`, then the default and named vaults in `~/.config/confidant/config.toml`. If nothing is found, fail clearly with an error code. Every JSON response includes the resolved vault.

**Alternatives considered.** Only a global config: breaks the demo vault and multi-vault use. Silent fallback to a default: risks writing to the wrong vault.

**Consequences.** Agents should pass `--vault` or set `CONFIDANT_VAULT` explicitly.

### ADR-12. License (recommendation, not final).

**Door:** Mostly one-way once outside contributions arrive.

**Context.** beancount-io is MIT. A later hosted offering would have to decide what it holds and where; nothing hosted is planned (§1).

**Recommendation.** Apache-2.0, for its explicit patent grant. MIT remains acceptable. Decision deferred to Frank.

**Consequences.** Contributors need to agree to the license; relicensing later requires their consent.

### ADR-13. Build vs fork cr.

**Door:** Reversible.

**Context.** The prior-art sweep found [cr](https://github.com/AnandChowdhary/cr) closest to this design. A one-day spike read its source at commit `f29f8d4` (v0.2.75) without building it; report: [`docs/research/cr-spike.md`](research/cr-spike.md). Its secrecy and storage layers are not separable: no traits in ~56.7k lines, one database-wide keyring read from env vars inside `protect()`, field-level secrecy only, an explicit refusal to apply it to folder-style records (our `people/p-…/` layout), and an 8.2k-line `Database` with YAML front matter as the source of truth.

**Decision.** Build our own. Borrow these MIT-licensed pieces, with a header on each adapted file and the full MIT text in `THIRD_PARTY_LICENSES`:

- `DomainError` and JSON error output, plus `file`, `line` and `fix` fields (ADR-7).
- `check.rs` report types (severity, finding kinds with stable codes, summary, `--fail-on`), not its scanner.
- `attribution.rs`, turned into commit trailers with free text kept out (ADR-7).
- `paths.rs`: refuses symlinks, writes atomically. Close to drop-in.
- The crash-safe write pattern, re-implemented for ledger append + file write + commit.

**Alternatives considered.** (a) Contribute per-device keys and the ledger upstream: needs a key-resolver abstraction through its secrecy, storage and audit replay, lifting the folder refusal, a second storage model and multi-device audit changes. It is a one-person, 9-week-old project whose roadmap heads toward server and UI. (b) Fork: delete ~40% (22.6k lines of server, web UI and access control), then replace the source of truth, key model, content unit and audit chain, and inherit its v1–v4 audit compatibility code.

**Consequences.** We write the ledger, records and storage ourselves. We don't take cr's audit chain, `database.rs`, schema-driven field handling, `sync.rs`, or anything server-side. Re-implemented patterns get credit in `docs/`. The ledger and multi-device git mismatches are ours either way.

### ADR-14. CI and releases.

**Door:** Reversible.

**Context.** Confidant is a binary that people trust with their private records. Every change needs to be tested, and every release needs to be verifiable. Building a release on every commit would create noise and make no version meaningful.

**Decision.** Run checks on every push, and release only when a version tag is pushed.

- **Every push and pull request:** `cargo fmt --check`, `clippy` with warnings treated as errors, and the tests. Also `confidant check` on the demo vault, format-spec compatibility tests against fixture vaults, `no-ai` exclusion tests, and dependency audits (`cargo deny`, `cargo audit`). Runs on Linux and macOS.
- **Version tag (for example `v0.1.0`):** cargo-dist builds binaries for macOS (Apple Silicon and Intel) and Linux (x86_64). It publishes a GitHub Release with SHA-256 checksums, a Homebrew formula and shell installers, and also publishes to crates.io. Builds carry build-provenance attestations so users can check that a binary came from this repo's CI. macOS notarization is added once there are outside users. Windows is supported via WSL2; no native Windows binaries are built.
- **Main is protected:** merges need CI to pass, and release tags come only from main.
- **CI never holds vault data or credentials.** Tests use the demo vault and throwaway vaults created during the run.

**Alternatives considered.** (a) Release on every merge to main: too many versions, and none of them means anything. (b) Hand-written release workflows: more to maintain than cargo-dist, for no gain in v0.

**Consequences.** Cutting a release is a single step: push a tag. The format spec version and the CLI version are separate (ADR-1), so CI checks that a new CLI still reads vaults written in older format versions.

### ADR-15. (Withdrawn) Recovery key.

**Door:** Withdrawn 2026-10-31.

**Context.** This ADR specified an offline recovery key, because losing a device's key material meant permanently lost notes.

**Decision.** Withdrawn with the removal of the application-level secrecy layer (#795, ADR-4). A vault now holds no key material, so there is nothing to recover: a clone of the repo *is* the vault, and recovery is "clone it on the new machine". The number is left in place rather than reused, because old issues and PRs cite it. What replaces it is backup discipline: push to the private remote (or back up the repo some other way), because a vault that was never pushed and never backed up is still gone if the disk dies (ADR-5).

### ADR-16. Single operator; multi-user is deferred.

**Door:** Reversible until a second person needs access.

**Context.** Every design decision above assumes one operator: the disk is theirs, the repo is theirs, `no-ai` is the only boundary inside the data, and there is no second set of eyes to isolate. A household, a team, or peers running their own agents would break that assumption.

**Decision.** Confidant is single-operator. Records for other people are *data about* them, not *access for* them. When a second human needs their own vault, the expected shape is separate interoperating vaults (each with its own repo and `no-ai` policy), not one shared vault with per-person isolation. That work is unscheduled, and the per-record secrecy layer that once looked like the answer to it is not coming back by default (ADR-4).

**Alternatives considered.** (a) One shared vault with per-record access control: that is a permissions system, and it needs the auth/login model §2 rejects. (b) Per-record ciphers with per-person keys: the pre-#795 design; it promised isolation over git history that it could not deliver.

**Consequences.** Nothing here needs to defend against a co-tenant. Anything two operators must not see together belongs in two vaults. Revisit this ADR before adding any multi-user feature.

## 8. v0 scope and milestones

1. **Spec + core + check.** Format spec 0.1, parser, generic records, derived values, balance assertions, check engine, built-in personal pack, external packs, demo vault.
2. **Vault safety and sync.** `confidant doctor` (git repo and identity, transport, spec, `check`, staleness, skills links), `confidant sync` as the explicit git boundary, and the §12 `no-ai` allowlist. Done when a fresh clone on a clean machine reads and writes the vault with no extra setup.
3. **CLI writes + agent contract.** Write commands, `--json`/`--no-input`/`--dry-run`/`--request-id`, commit-per-write, `schema`, `help --json`, `context`, `doctor`, thin MCP server.
4. **Import skills.** Agent skills that pull events and transcripts from outside systems into the vault, with dry runs and safe retries.
5. **QMD search (right after v0).** On trusted devices only, and the index never goes in git (section 9b).
6. **Terminal UI (`crates/confidant-tui`, after v0).** Reference second consumer of the ADR-7 CLI contract: invokes `confidant <subcommand> --json --no-input` as a child process without linking `confidant-core`, keeping content on the alternate screen only (#205, #210).

Out of v0: hosted version, integration plugin system, GUI.

## 8a. Release and milestone policy (2026-10-26)

Milestones are time horizons, not version containers. `Now` is the next
two weeks, `Next` the following six, and `Later` an unscheduled backlog
that is not a commitment. Version numbers are tags cut when a coherent
slice ships, and the CHANGELOG is the record. Keep a release to 5-8
issues; if a milestone needs more, it is a theme, not a slice.

Pre-1.0 with one supported user, optimize for learning speed on the UX,
the schema, and the command surface. Keep the review gates for the vault
format and the privacy model: those mistakes are expensive to reverse even
when nobody else is using the vault.

**The 1.0 bar.** 1.0 is a stability claim, not a feature checklist. It
ships only when (a) the agent contract and the write path have been
dogfooded on the operator's own vault for at least one full minor cycle,
(b) no known data-loss or privacy-model bugs are open, (c) a fresh clone can
install, init, upgrade, and sync from the README alone, and (d) the security
review in #138 is complete. If any of those is false, the next release is
0.x.

## 8b. Worked example: a private vault on two machines

The everyday architecture exercise is backup and a second device, with no
server and no plugin system.

**Flow.**

1. **Capture locally.** On the laptop, the agent runs `confidant log touch`
   or `confidant note add`. One commit lands in the vault's own repo;
   nothing touches the network.
2. **Check, then push.** `confidant doctor` shows unpushed commits and any
   remote-transport warning. `confidant sync --push` fetches, confirms, and
   pushes to the private `origin`, or `contrib/`'s opt-in timer does it on a
   schedule.
3. **Read on the other machine.** On the desktop, `confidant sync --pull`
   fast-forwards. A clone is the whole setup step: there is no enrollment,
   no key handoff, and no anchor to copy.
4. **Keep the perimeter.** The remote is private, the disks are encrypted,
   and `no-ai` keeps marked records out of what agents read on either
   machine.

**Intended pattern.** Anything an outside tool hands back (a form, a
transcript, a phone shortcut) reaches the vault as a file the operator or
agent places there and imports through the CLI with `src:` provenance.
Confidant has no intake channel of its own and no daemon: nothing pushes into
a vault from outside, and no GitHub Action holds vault access. That is the
intended pattern, not a v0 enforcement claim.

## 9. Open questions (resolved)

1. **Name.** Resolved: Confidant (CLI `confidant`), chosen 2026-10-07 after an availability check.
2. **Ledger privacy.** Resolved 2026-10-31: amounts, dates and opaque IDs stay in the ledger, whose arguments are never prose. Contact values live in readable front matter (ADR-9), on the same perimeter as the rest of the vault (ADR-4).
3. **Transcripts.** Resolved: source-agnostic. Confidant doesn't care which tool records or stores transcripts. An import skill reads them from wherever they live and writes interaction records with provenance (`src:<source>/<id>`) and duration, which pack metrics can use. Copies left in a hosted store are outside Confidant's privacy guarantee; deleting them after import is the operator's call.
4. **Local operations at the vault.** Resolved: no general export in v0. Search indexes stage the cleared set via `confidant allowlist --json`; everything else uses `confidant context` and `--json` output.
5. **First integration skill.** Resolved: an import from the outside tool that feeds records and ledger entries into the vault.

## 9b. Risks and how we handle them (decided 2026-10-07)

1. **Conflicting edits to one record.** When two devices change the same record, git must merge two plaintext files; for a body that changed in both, the CLI keeps both versions side by side, `confidant check` flags the conflict, and the agent or the operator picks which one to keep. Nothing is silently dropped. Conflicts should be rare, because records are one file each and writes are mostly append-only.
2. **The model provider sees plaintext.** Agents send what they read to a hosted model provider. The README and privacy model say so plainly and don't claim the provider stores nothing. A per-client `no-ai` flag keeps that client's notes and PII out of `confidant context` and `--json` output used by agents, so the operator can keep sensitive people away from models entirely.
3. **Capture going stale.** Confidant only knows what agents write into it. A `confidant check` rule flags gaps, such as a record with no follow-up note, or a contact with no touchpoint within a set window. The agent sends the operator a weekly summary of these gaps.
4. **Search.** v0 searches by scanning the vault directly, which stays fast for a few hundred people (milestone 1 measures it). Right after v0, QMD becomes the search: it runs on trusted devices, stages only the cleared set, and its index stays out of git and is never synced anywhere.
5. **The public repo is not the vault.** Confidant's own source is public; a vault is not, and must not be. The ways a vault gets exposed are a public remote, a share link, an unencrypted disk, or a paste into a chat. ADR-4 covers the perimeter and `confidant doctor` covers the transport.

   Changed 2026-10-31 by Frank: the application-level secrecy layer was
   removed (#795, ADR-4). The audit item in #138 no longer gates launch on a
   secrecy design; the remaining review surface is the `no-ai` allowlist, the
   write path, and the git/sync boundary. If a future design reintroduces a
   hiding layer, it needs a new `<topic>-review` issue first (repo hard rule
   7).

## Appendix: Prior art (sweep 2026-10-07)

No existing project combines all of these: a git vault, a beancount-style ledger, an agent-first contract and schema packs. The individual parts do exist.

| Project | Lang / license | Closeness | Take |
|---|---|---|---|
| [cr](https://github.com/AnandChowdhary/cr) | Rust, MIT | High | Markdown records with YAML front matter as the source of truth, JSON Schema validation, `cr check`, a tamper-evident audit log (actor, agent, approval, reason), idempotency keys. Real differences: caller-chosen name slugs as IDs (examples like `priya-shah.md` leak names) versus our opaque ULIDs; it doesn't store its data through git; one database-wide keyring; it protects fields and bodies inside a file rather than whole records; it refuses folder-style records; its audit chain is single-writer; and ~40% of the source is server, web UI and access control. **Spiked: build and borrow (ADR-13).** |
| [AgentCRM](https://github.com/AgentPal/AgentCRM) | Go, MIT | Medium | Markdown per contact and deal, monthly interaction logs, an approval queue for agent writes, and a SQLite index that can be rebuilt. |
| [frm](https://github.com/justinabrahms/frm) | Go, MIT | Medium | Agent contract: `check`, `context <person>`, `--json`, `--dry-run`, SKILL.md. |
| [crm.cli](https://github.com/dzhng/crm.cli) | TS, MIT | Low–Medium | Same vault-discovery order as ADR-11; duplicate merge re-points links. |
| [people-context](https://github.com/JinyangWang27/people-context) | Python, MIT | Low–Medium | Published threat model, a `forget` that actually deletes, alias resolution. |
| [friends](https://github.com/JacobEvelyn/friends) | Ruby, MIT | Prior art | A dated one-line activity ledger about people (last updated 2021). |

**Building blocks:** [gix](https://github.com/GitoxideLabs/gitoxide) or [git2](https://github.com/rust-lang/git2-rs), [ulid-rs](https://github.com/dylanhart/ulid-rs), [pulldown-cmark](https://github.com/pulldown-cmark/pulldown-cmark), and [beancount-parser](https://github.com/jcornaz/beancount-parser) as a parser reference.

**Ideas to adopt:** agent writes wait as pending proposals until a human approves them (AgentCRM, wend-core); merges re-point every link (crm.cli); a published threat model and a real `forget` (people-context).

**cr spike:** [`docs/research/cr-spike.md`](research/cr-spike.md) (2026-10-07, historical) — build our own and borrow patterns; see ADR-13.
