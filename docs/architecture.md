# Confidant: architecture and decision records

*Name: **Confidant** (CLI `confidant`), chosen 2026-10-07. Draft 2026-10-07, revised the same day with the cr spike findings (ADR-13). Author: Frank Harris. Status: proposal for review.*

## 1. What this is

`confidant` is an open-source, local-first CRM for **one operator** (a solo entrepreneur or coach) and their AI agents. Records are plain text in a git repo (the **vault**). A Rust CLI reads, writes and validates the vault. It runs on the operator's own computer and has no server.

It is modeled on beancount and beancount-io: plain text in git, a CLI with a `--file` / `--json` / `--no-input` automation contract, a `check` command, agent skills that confirm before writing, and an MCP server as a thin layer on top.

**Who writes.** An agent is the main writer. It also does capture: email, meeting notes and transcripts reach the vault through the agent calling the CLI, not through built-in background sync. No human reviews a form before data lands, so **the file format, the schema and `check` are the core of the product.** Everything else is replaceable.

**Not goals.** Teams, shared pipelines, permissions UIs, live collaboration, a web app, a hosted service in v0, and a general integration plugin system in v0.

**Later, out of scope here.** A hosted or paid version, probably an agent for non-technical users. Cloudflare Artifacts (git-compatible storage in open beta; one repo per user at scale; short-lived per-repo read/write tokens; events on push; US/EU data location) is the likely base. The hosted side must only ever hold ciphertext. v0 works with any git remote.

**What it is and what it isn't.** `confidant` is the operator's private record of relationships: people, organizations, deals, interactions and notes, plus the judgment about them. It is **not** a system that faces customers. Booking, payments, invoicing, client logins, scheduling and anything a customer touches stay in the tools built for that (a booking portal, Stripe, a calendar). `confidant` reads from those systems: an agent or script *pulls* their events into the vault, so nothing ever pushes into `confidant`, and nothing private flows back out to them. For example, Frank's hirefrank coaching portal keeps booking, Stripe payments, session balances shown to clients and logins, and `confidant` pulls its events.

## 2. Why not a typical client/server web app

A server-side CRM must hold plaintext to search, display and summarize notes. That is how every hosted CRM works (Lightfield, HubSpot, Attio and the rest), and it is what the privacy rule below forbids.

What a web app does better, and why it doesn't matter here:

| Web app strength | Relevance |
|---|---|
| Live multi-user collaboration | Not a goal. One operator. |
| Non-technical users | The later hosted *agent* serves that market. |
| Always-on capture (email, calendar sync) | The agent does capture on a schedule, through the CLI. |

**Main alternative weighed: local-first SQLite app with encrypted change sync.** Better at concurrent edits (CRDT or op-log merges instead of git merges). It loses plain files you can read and diff, free history and blame from git, and agent fluency: agents already know how to read files, grep, and use git. With one operator and a few devices, concurrent edits are rare, and the file layout (ADR-3) keeps conflicts small. Rejected for v0.

## 3. Privacy model

**Trusted device:** any device or agent computer acting on behalf of the owner, including a cloud machine running the owner's agent. A shared application server holding customer data is **not** a trusted device.

**Rule:**

1. Plaintext only on trusted devices (laptop, agent computer).
2. Only ciphertext in any git remote or backup.
3. Nothing private in the portal, ever.

**Accepted exception:** when an agent reads notes, that content is sent to a hosted model provider for processing. This is explicit and accepted. The design does not claim the provider stores nothing; that depends on the provider's terms.

Client notes and PII are encrypted in git by default (ADR-4).

## 4. Threat model

| Protects against | Does not protect against |
|---|---|
| A leaked or breached git remote | A compromised trusted device (malware, stolen unlocked laptop) |
| A stolen backup | A model provider seeing what agents send it |
| A curious host (remote provider, later hosted service) | Metadata: commit timing, commit counts, file counts and sizes, which opaque IDs change together |
| Filenames revealing who is a client (opaque IDs in paths) | Plaintext ledger fields, if left unencrypted (Open question 2) |
| A revoked device reading *future* writes | A revoked device reading what it already copied (ADR-5) |

Local indexes and caches (`.confidant/`, any search index) contain plaintext and embeddings. They are sensitive, gitignored, and stay on trusted devices.

## 5. Layouts

### Vault (user data)

```
vault/
├── confidant.toml              # vault config: spec version, packs, key recipients, random vault id
├── keys/                 # wrapped per-client data keys (age)
├── ledger/2026/10.cfd    # dated one-line entries, one file per month
├── people/p-01J9…/       # profile.md + notes/*.md (encrypted)
├── orgs/o-01J9…/org.md
├── deals/d-01J9…/deal.md
└── .confidant/                 # local index/cache, gitignored, rebuildable
```

### Tool repo

```
confidant/
├── spec/                 # versioned file-format spec (the contract)
├── crates/confidant-core/      # parse, model, derived values, check engine
├── crates/confidant-crypt/     # age key wrapping, record-bound XChaCha20-Poly1305 content encryption
├── crates/confidant-cli/       # CLI + agent contract + thin MCP server
├── packs/                # schema packs and check packs (coaching first)
├── skills/               # agent skills + small integration scripts
├── examples/demo-vault/  # fake data for tests, docs and agents
├── docs/
└── THIRD_PARTY_LICENSES  # MIT notice for code adapted from cr (ADR-13)
```

## 6. Entry format by example

Structured facts are one-line ledger entries. Prose is Markdown.

```
; ledger/2026/10.cfd
2026-10-01 open     p-01J9Z3K4QF  package pkg-01J9Z4 6 sessions  ; coaching pack
2026-10-01 session  p-01J9Z3K4QF  60m paid
2026-10-03 alias    p-01J9Z3K4QF  email hmac:3f9c…  ; keyed HMAC; real value in encrypted profile
2026-10-08 session  p-01J9Z3K4QF  45m paid  src:transcript/t-01JA02
2026-10-08 balance  p-01J9Z3K4QF  sessions_remaining 4
2026-10-09 stage    d-01J9ZB7W1M  proposal
2026-10-12 merge    p-01J9ZQ00XY  into p-01J9Z3K4QF  reason "duplicate account"
```

```markdown
<!-- people/p-01J9Z3K4QF/profile.md (encrypted at rest) -->
---
id: p-01J9Z3K4QF
type: person
name: Example Client
---
Context, goals, preferences. Prose only; no structured facts here.
```

## 7. Decision records

Each ADR is flagged **One-way door** (hard to change once vaults exist) or **Reversible**.

### ADR-1. The file format is a versioned spec, separate from the CLI. Generic core, coaching as a pack.

**Door:** One-way.

**Context.** Agents, scripts and future tools (including a hosted agent) must read and write vaults without depending on one binary. Frank's use is coaching, but open-source users are not all coaches.

**Decision.** Publish the format in `spec/` with a version number declared in each vault's `confidant.toml`. Core record types: person, org, deal, interaction, note. Coaching (sessions, ICF hours, packages, renewals) is a **schema pack** (ADR-8), not core.

**Alternatives considered.** (a) Format defined by whatever the CLI does: faster at first, but every change silently breaks other readers. (b) Coaching types in core: simpler for Frank, but bakes one profession into every vault.

**Consequences.** Format changes need a spec version bump and a migration (`confidant migrate`). The core stays small. The coaching pack is the first real test that packs work.

### ADR-2. Structured facts are dated ledger entries in a strict grammar; prose is Markdown.

**Door:** One-way.

**Context.** An agent writes most data. Structured facts (sessions, stage changes, payments) must be checkable, diffable and mergeable. Derived values (sessions remaining, ICF hours) must not drift.

**Decision.** Facts are one-line entries, `DATE VERB ID ARGS…`, beancount style, e.g. `2026-10-01 session p-01J9… 60m paid`. Prose lives in Markdown. Derived values are computed, never stored as truth. `balance` entries are assertions that `confidant check` verifies against the computed value. YAML frontmatter holds only identity and display fields (id, type, name), not facts.

Ledger arguments never carry plaintext PII. Alias values (emails, phones, handles) are stored either as `HMAC(vault lookup key, normalized value)` for matching, with the real value in the encrypted profile, or as an encrypted payload (Open question 2). A plain hash isn't enough because it can be dictionary-attacked. The lookup key is wrapped to devices like a data key. The ledger is the only source of truth for facts; there is no separate audit journal (ADR-6).

**Alternatives considered.** (a) YAML frontmatter as source of truth: familiar, but edits overwrite state in place, history is lost inside a field, two devices editing one file conflict, and there are no assertions. (b) JSON/JSONL: strict, but noisy for humans to read and diff. (c) SQLite: see Section 2.

**Consequences.** A parser and grammar to maintain. Line-level diffs and merges. Balance assertions catch agent mistakes at write time. Corrections are new entries (or a reversal entry), not edits.

### ADR-3. Collision-free prefixed IDs, one file per record, append-mostly writes, monthly ledgers.

**Door:** One-way.

**Context.** Laptop and agent computer may write at the same time. Sequential IDs (e.g. `s03`) collide. Merge conflicts in encrypted files can't be resolved by reading the diff.

**Decision.** ULID-style IDs with type prefixes: `p-` person, `o-` org, `d-` deal (others defined in the spec). One directory or file per record. Writes are mostly appends. Ledger files are split by month to stay small. IDs appear in paths; names never do. The CLI generates ULIDs, and `confidant check` rejects non-conforming IDs and non-ID filenames as errors rather than skipping them.

**Alternatives considered.** (a) Sequential IDs: readable, but collide across devices. (b) Slugs from names: readable, but leak client names into paths and break on renames. (c) One big ledger file: simple, but a conflict hotspot.

**Consequences.** IDs are not human-friendly; the CLI resolves names and aliases to IDs (`confidant find`). Most concurrent writes touch different files or append to different lines. A git merge driver for `.cfd` ledgers (union of sorted lines) is worth shipping.

### ADR-4. Encryption built into the CLI: `age` wraps per-client keys, record-bound AEAD encrypts content.

**Door:** One-way.

**Context.** Notes and PII must be ciphertext in any remote or backup. Frank also needs to delete a client completely, revoke a lost device, and give some agents less access than others. Ciphertext should be bound to its record so it can't be swapped into another record or vault, but the age format has no associated data. Anyone with git write access (Lock 1, ADR-10) can edit `confidant.toml` and `keys/`.

**Decision.**

- **Key wrapping (age only).** Each client gets its own data key. It is age-encrypted to every authorized device or agent recipient and stored in `keys/`.
- **Content encryption.** Content files are encrypted with XChaCha20-Poly1305 under the client's data key, with a fresh nonce per write and a key id in the envelope. The associated data is a length-prefixed encoding of vault id ‖ ULID ‖ relative path ‖ purpose ‖ key epoch, so a file moved to another record, path or vault fails to decrypt.
- **Vault id.** `confidant.toml` holds a random, non-secret vault id, bound into every associated data.
- **Signed recipient changes.** Changes to the recipient set must be in commits signed by an already-trusted key. `confidant` verifies them against a trust anchor kept outside the vault (`~/.config/confidant/`, or a pinned first-commit fingerprint) before wrapping anything. Without this, anyone with git write access could add their own recipient and receive future keys, and revocation by re-wrap has the same hole.
- **Never commit plaintext.** A vault never contains a plaintext commit of a protected file. Content is encrypted before its first commit. Existing plaintext is never encrypted in place, because git history would keep it.
- **Keep unchanged ciphertext.** If a file's plaintext hasn't changed, its existing ciphertext is kept byte for byte, so rewrites don't create diffs, conflicts or false "changed" signals (ADR-3).

This enables:

- **Crypto-shredding:** delete a client's wrapped keys and the data is unreadable everywhere, including git history and backups.
- **Device revocation:** re-wrap keys without the revoked recipient (see ADR-5 for limits).
- **Scoped agent keys:** e.g. a pipeline-only key that can read deals and ledger but not notes.

Encryption is optional for generic open-source users and the default for notes and PII. Paths use opaque IDs so filenames never reveal clients. git-crypt is optionally supported for compatibility, with its limits documented: it encrypts contents but not paths, its encryption is deterministic, and its docs say it can't revoke access.

**Alternatives considered.** (a) git-crypt only: easy, but the limits above rule it out as the default. (b) One vault-wide key: simpler, but no shredding per client and no scoped agents. (c) Full-disk or remote-side encryption only: does not keep plaintext off the remote. (d) age for content, with `{vault, id, path}` embedded in the plaintext and checked after decryption: weaker and easy to forget.

**Consequences.** Key management is real work: `confidant keys add|revoke|rotate|shred`. Each device needs a trust anchor outside the vault. The AEAD layer is adapted from cr (ADR-13). Encrypted files diff and merge poorly, which ADR-3 and keeping unchanged ciphertext mitigate. A lost private key with no other recipient means lost data; `confidant doctor` should warn when a client key has a single recipient.

### ADR-5. Revocation protects only future writes.

**Door:** One-way (it's a property of the design, stated so nobody expects otherwise).

**Context.** Re-wrapping keys stops a revoked device from decrypting new data. It cannot reach into a copy already on that device.

**Decision.** Docs and `confidant keys revoke` output say plainly: a revoked device keeps whatever it already copied. Revocation re-wraps all data keys, and optionally rotates data keys for affected clients so future content uses new keys.

**Alternatives considered.** Claiming remote wipe or DRM-style control: not possible with files on a device the user doesn't control.

**Consequences.** Honest expectations. Rotation issues a new epoch key; old-epoch ciphertext stays readable by still-authorized parties (the AAD binds the key epoch, ADR-4), so rotation is cheap and creates small commits.

### ADR-6. Files are the only source of truth; indexes and caches are throwaway.

**Door:** Reversible.

**Context.** Search and fast lookups need indexes, and they hold plaintext.

**Decision.** Indexes, caches and any search index live in `.confidant/` (or similar), are gitignored, stay on trusted devices, and rebuild with one command (`confidant reindex`). QMD (tobi/qmd: local BM25, vector and rerank search, Node-based) is **not** a dependency of the Rust CLI. It is integrated through a skill or script (ADR-8). The QMD index holds plaintext chunks and embeddings and is treated as sensitive.

There is no separate audit journal. The audit trail is the ledger plus git history plus signed commits (ADR-10). If more tamper evidence is needed later, sign or anchor commits rather than keep a second chain.

**Alternatives considered.** (a) Committing an index: faster cold start, but leaks plaintext or needs encryption and creates conflicts. (b) Bundling vector search in Rust core: no Node, but a large dependency for a feature not every user needs. (c) A hash-chained audit journal like cr's: rejected. It is one linear chain with a global sequence and an anchor file that every write rewrites, so two devices writing at once always conflict (breaking ADR-3). It is also a second source of truth to reconcile, and it keeps plaintext metadata forever.

**Consequences.** First search on a new device is slower. No index ever needs migrating; delete and rebuild.

### ADR-7. The agent contract.

**Door:** Reversible (but breaking changes need versioning; agents depend on it).

**Context.** The main user of the CLI is an agent. It needs predictable, machine-readable behavior and safe retries.

**Decision.**

- `--json` on every command; every JSON response includes the resolved vault path.
- `--no-input`: never prompt; fail with an error code instead.
- `--file` to pass structured input; `--dry-run` on every write. Dry runs and confirm-before-write skills show and bind to the logical change (ledger lines, plaintext diff), never to ciphertext bytes, because nonces are fresh on every write.
- Stable exit codes and error codes. Errors name the file and line and suggest a fix; paths are opaque IDs, so this leaks nothing. Errors are classified by type, never by message text. `internal_error` is reserved for unclassified failures, and usage errors exit with code 2.
- Optional `--request-id` so a retried write does not apply twice. It is scoped per write command (imports are multi-record). Only hashes are stored, in a commit trailer: a domain-separated hash of the id and an HMAC keyed by the raw id over the canonical request. Reusing an id with different content is an error (`E_IDEMPOTENCY_CONFLICT`). ADR-8's `src:` provenance stays the content-level dedupe.
- One commit per write, attributed to the human or agent. Commit messages and trailers are plaintext that crypto-shredding can't reach, so they carry only opaque IDs, verbs, agent identity and request-id hashes. Free-text reasons and intent are stored encrypted under the client's data key, or omitted.
- `confidant check` runs before every commit; a failing check blocks the write.
- `confidant schema` (JSON Schema), `confidant help --json`, `confidant doctor`.
- `confidant context <person>`: a context bundle, with flags to include or exclude private data.
- Search results return ID, path and excerpt.
- A demo vault with fake data.
- The MCP server is a thin wrapper over the CLI, never a second way in.
- Shipped skills (prep session, log session, open renewal, weekly pipeline review) confirm with the human before writing.

```sh
confidant log session p-01J9Z3K4QF 60m paid --request-id 01J9Z3K4QF7F3A000000000000 --json --no-input --dry-run
confidant context p-01J9Z3K4QF --exclude-private --json
confidant check --json
```

```json
{
  "ok": false,
  "vault": "/home/frank/vault",
  "error": {
    "code": "E_BALANCE_MISMATCH",
    "file": "ledger/2026/10.cfd",
    "line": 5,
    "message": "sessions_remaining asserted 4, computed 3",
    "fix": "Check for a missing 'open' entry or a duplicated 'session' entry for p-01J9Z3K4QF"
  }
}
```

**Alternatives considered.** (a) MCP-first API: ties automation to one protocol and creates a second code path. (b) Human-oriented output with parsing by agents: brittle.

**Consequences.** Every command needs JSON output and error codes from day one. The contract is versioned and tested against the demo vault.

### ADR-8. Extensibility in v0: check rules, schema packs, and local decrypted operations. No integration plugin system.

**Door:** Reversible.

**Context.** Integrations (portal, email, transcripts, QMD indexing) are what agents are good at, and they change often. What must *not* be skipped, whoever writes, is validation. Beancount gets this right: its plugins transform and validate entries on every load.

**Decision.** v0 has **no general plugin system for integrations.** Agents handle every integration by calling the agent contract (ADR-7), shipped as agent skills or small scripts in `skills/`. Extensible in v0:

1. **Check rules / validators.** Run on every write and in `confidant check`, regardless of who writes (human, agent, script). Example: an `ICF hours` rule that rejects a session without a duration.
2. **Schema packs.** Define record types, ledger verbs and derived values, declared in `confidant.toml`. Coaching is the first pack: sessions, packages, balances, renewals, ICF hours.
3. **Local decrypted operations (possible).** Operations that need plaintext, such as building a search index, run inside or under the CLI so plaintext doesn't have to leave it through a general export. Scope to be decided (Open question 4).

```toml
# confidant.toml
spec = "0.1"
packs = ["coaching@0.1"]

[checks]
coaching.require_duration = "error"
coaching.balance_nonnegative = "error"
```

Integrations are idempotent and record provenance on each entry (`src:portal/evt-…`, `src:transcript/t-…`) so re-running an import adds nothing.

```sh
# skills/portal-sync script, run by the agent on a schedule
confidant import --file portal-events.jsonl --request-id portal-2026-10-07 --json --no-input
```

**Alternatives considered.** Git-style subprocess plugins: `confidant-<name>` on PATH, a JSON stdin/stdout protocol, and a capability manifest declaring whether the plugin needs the private (decrypted) tier. Clean, and a likely later addition, but in v0 it is a framework to design, version and secure before there is a second user who needs it. Agents plus the CLI contract cover the same integrations today.

**Consequences.** Less to build and secure in v0. Integration code lives as skills/scripts that may duplicate small helpers. How packs are expressed (declarative TOML/spec files vs compiled Rust) needs a design pass; v0 can compile the coaching pack into the binary behind the pack interface.

### ADR-9. Identity: aliases and history-preserving merges.

**Door:** Reversible.

**Context.** People have several emails and handles. Lightfield currently has a client duplicated across two accounts.

**Decision.** `alias` entries attach emails, phones and handles to an ID, stored as a keyed HMAC or encrypted, never as plaintext (ADR-2). A `merge` entry folds one ID into another; the old ID stays resolvable and its history is kept. `confidant check` warns on two IDs sharing an alias.

**Alternatives considered.** Deleting the duplicate and rewriting references: loses history and touches many encrypted files.

**Consequences.** Every reader resolves merges. Importers match on aliases first, by the HMAC of the normalized value.

### ADR-10. Auth without a login system: two locks plus signed commits.

**Door:** Reversible.

**Context.** No server, so no accounts.

**Decision.** Lock 1: git remote access decides who can sync ciphertext. Lock 2: keys decide who can read it. Git access is all-or-nothing, so scoping comes from keys (ADR-4). Attribution comes from signed commits, because git author names can be spoofed; `confidant check` can require signatures from known keys. The trusted-signers list lives outside the vault (`~/.config/confidant/`, a flag or an env var), never inside it, since anyone with write access could replace an in-vault list. It is the same trust anchor that authorizes recipient changes (ADR-4). Signed commits plus git history are the audit trail (ADR-6).

**Alternatives considered.** A custom auth service: contradicts having no server.

**Consequences.** Setup requires a signing key per device/agent and a trust anchor outside the vault on each device. There is no login system to build.

### ADR-11. Vault discovery order.

**Door:** Reversible.

**Decision.** Resolve the vault in this order: `--vault <path>`, then `CONFIDANT_VAULT`, then walk up from the current folder looking for `confidant.toml`, then the default and named vaults in `~/.config/confidant/config.toml`. If nothing is found, fail clearly with an error code. Every JSON response includes the resolved vault.

**Alternatives considered.** Only a global config: breaks the demo vault and multi-vault use. Silent fallback to a default: risks writing to the wrong vault.

**Consequences.** Agents should pass `--vault` or set `CONFIDANT_VAULT` explicitly.

### ADR-12. License (recommendation, not final).

**Door:** Mostly one-way once outside contributions arrive.

**Context.** beancount-io is MIT. A later hosted offering would be an encrypted sync service that never sees plaintext.

**Recommendation.** Apache-2.0, for its explicit patent grant. MIT remains acceptable. Decision deferred to Frank.

**Consequences.** Contributors need to agree to the license; relicensing later requires their consent.

### ADR-13. Build vs fork cr.

**Door:** Reversible.

**Context.** The prior-art sweep found [cr](https://github.com/AnandChowdhary/cr) closest to this design. A one-day spike read its source at commit `f29f8d4` (v0.2.75) without building it; report: `/workspace/research/cr-spike-2026-10-07.md`. Its encryption and storage layers are not separable: no traits in ~56.7k lines, one database-wide keyring read from env vars inside `protect()`, field-level encryption only, an explicit refusal to encrypt folder-style records (our `people/p-…/` layout), and an 8.2k-line `Database` with YAML front matter as the source of truth.

**Decision.** Build our own. Borrow these MIT-licensed pieces, with a header on each adapted file and the full MIT text in `THIRD_PARTY_LICENSES`:

- Record-bound AEAD (~200 lines), re-keyed to per-client data keys and our associated-data fields (ADR-4).
- Keeping existing ciphertext when a value is unchanged, at file level (ADR-4).
- HMAC idempotency digests and their rules (ADR-7), taking the rules, not cr's verification code.
- `DomainError` and JSON error output, plus `file`, `line` and `fix` fields (ADR-7).
- `check.rs` report types (severity, finding kinds with stable codes, summary, `--fail-on`), not its scanner.
- `attribution.rs`, turned into commit trailers with free text kept out (ADR-7).
- `paths.rs`: refuses symlinks, writes atomically. Close to drop-in.
- The crash-safe write pattern, re-implemented for ledger append + file write + commit.

**Alternatives considered.** (a) Contribute per-device keys and the ledger upstream: needs a key-resolver abstraction through its encryption, storage and audit replay, lifting the folder refusal, a second storage model and multi-device audit changes. It is a one-person, 9-week-old project whose roadmap heads toward server and UI. (b) Fork: delete ~40% (22.6k lines of server, web UI and access control), then replace the source of truth, key model, encryption unit and audit chain, and inherit its v1–v4 audit compatibility code.

**Consequences.** We write the ledger, per-client keys and storage ourselves. We don't take cr's audit chain, `database.rs`, schema-driven field encryption, `sync.rs`, or anything server-side. Re-implemented patterns get credit in `docs/`. If cr later ships per-record keys, re-check it as a reference; the ledger and multi-device git mismatches remain either way.

### ADR-14. CI and releases.

**Door:** Reversible.

**Context.** Confidant is a binary that people trust with client secrets. Every change needs to be tested, and every release needs to be verifiable. Building a release on every commit would create noise and make no version meaningful.

**Decision.** Run checks on every push, and release only when a version tag is pushed.

- **Every push and pull request:** `cargo fmt --check`, `clippy` with warnings treated as errors, and the tests. Also `confidant check` on the demo vault, an encrypt-then-decrypt round-trip test, format-spec compatibility tests against fixture vaults, and dependency audits (`cargo deny`, `cargo audit`). Runs on Linux and macOS.
- **Version tag (for example `v0.1.0`):** cargo-dist builds binaries for macOS (Apple Silicon and Intel), Linux and Windows. It publishes a GitHub Release with SHA-256 checksums, a Homebrew formula and shell installers, and also publishes to crates.io. Builds carry build-provenance attestations so users can check that a binary came from this repo's CI. macOS notarization is added once there are outside users.
- **Main is protected:** merges need CI to pass, and release tags come only from main.
- **CI never holds vault keys.** Tests use the demo vault and throwaway keys generated during the run.

**Alternatives considered.** (a) Release on every merge to main: too many versions, and none of them means anything. (b) Hand-written release workflows: more to maintain than cargo-dist, for no gain in v0.

**Consequences.** Cutting a release is a single step: push a tag. The format spec version and the CLI version are separate (ADR-1), so CI checks that a new CLI still reads vaults written in older format versions.

### ADR-15. Recovery key.

**Door:** One-way (a vault created without one can add one later, but data lost before that can't be recovered).

**Context.** No server holds any copy of the keys. If every device key is lost, every client's notes are gone for good. 2FA recovery codes don't fit, because they only prove identity to a service that still has the data. Here nobody else has it.

**Decision.** `confidant init` creates a recovery key: an extra age key that every client data key is also wrapped to. It's shown once as a printable phrase, and the operator stores it offline (on paper or in a password manager such as 1Password), never on a device that syncs the vault. Recovery: clone the repo, run `confidant recover` with the phrase, add a new device key, then rotate to a fresh recovery key and revoke the old one. `confidant doctor` warns if any client key isn't wrapped to the recovery key, and the trust anchor for signed recipient changes includes it.

**Alternatives considered.** (a) No recovery: too easy to lose everything. (b) Split the key across several people (Shamir secret sharing): stronger, but too much for one operator in v0. It could be an option later. (c) Escrow with a hosted service: breaks the privacy rule.

**Consequences.** Anyone who has the phrase can read the whole vault, so it's as sensitive as every device key combined. Rotation re-wraps every client key but doesn't re-encrypt content, so it's cheap.

## 8. v0 scope and milestones

1. **Spec + core + check.** Format spec 0.1, parser, generic records, derived values, balance assertions, check engine, coaching pack, demo vault.
2. **Crypt.** age key wrapping, record-bound content encryption, signed recipient changes, recovery key (ADR-15), `confidant keys`, scoped keys, shredding, git-crypt compatibility notes. Done when a recovery drill passes: clone the demo vault onto a clean machine, recover with only the phrase, rotate to a new phrase, and confirm the old one no longer works. Store the phrase in 1Password plus a printed copy kept somewhere physical; `confidant doctor` gives a yearly reminder to check the paper copy.
3. **CLI writes + agent contract.** Write commands, `--json`/`--no-input`/`--dry-run`/`--request-id`, commit-per-write, `schema`, `help --json`, `context`, `doctor`, thin MCP server.
4. **Portal sync + transcript import skills.** Agent skills that pull portal events and transcripts (with duration) into the vault, with dry runs and safe retries.
5. **QMD search (right after v0).** On trusted devices with encrypted disks only, and the index never goes in git (section 9b).

Out of v0: hosted version, integration plugin system, GUI.

## 8a. Worked example: session forms

Frank sends each client a form before and after every session. The answers should end up in the vault, and the questions should be shaped by past sessions. Delivery can be an email link to a web form or a form embedded in a Slack message. This flow exercises the whole architecture without a Confidant server or a plugin system.

**Who sees what.** The forms are customer-facing, so they live in the portal (which already has `form_submissions` for presession, reflection and discovery forms) or in Slack. Private notes stay in the vault. The only thing that crosses from the vault to a server is question text, and the client sees that anyway.

**Flow.**

1. **Draft questions locally.** Before a session, the agent runs `confidant context <person>` on a trusted device and drafts tailored questions from recent sessions, open commitments and themes.
2. **Approve, then send.** By default Frank approves the questions before they go out, because they come from private notes and one slip (a detail that belongs to another client, say) would be costly. Sending without approval can be a per-template setting later.
3. **Deliver.** The agent pushes only the question text to the delivery channel: the portal's emailed web form, or a form embedded in a Slack message. The channel doesn't matter to Confidant.
4. **Capture answers encrypted.** Strongest option: the web form encrypts answers in the client's browser using the vault's public key, so the portal stores only ciphertext. Baseline: the portal stores answers as it does today, and the agent deletes them from the portal after a verified import.
5. **Import through the inbox.** The agent pulls new answers (or picks up encrypted items dropped into an `inbox/` branch or folder), runs `confidant inbox` to validate and merge them, and writes encrypted interaction entries linked to the session with provenance (`src:form/<submission-id>`). Importing twice adds nothing.

**Inbox pattern (general).** Any outside tool can drop content for the vault without a server and without being able to read the vault: it encrypts each item to the vault's public key and pushes it to `inbox/`. `confidant inbox` (new command) decrypts, runs `check`, merges into the vault and clears the inbox. GitHub webhooks are not used for intake. They only notify a server you would have to run, and a GitHub Action must never hold decryption keys.

**Decided (see section 9).** In v0, answers are deleted from the portal after a verified import, and browser-side encryption comes in v0.1. The inbox is a separate `inbox` branch, with main protected so only trusted signers can write to it.

## 9. Open questions for Frank

1. **Name.** Resolved: Confidant (CLI `confidant`), chosen 2026-10-07 after an availability check.
2. **Ledger privacy.** Resolved 2026-10-07: amounts and dates stay plain metadata, tied only to opaque IDs, so `check`, balances and merges work without a key. Names, notes and alias values stay encrypted. Alias lookup uses a keyed HMAC, with the real values encrypted (ADR-2).
3. **Transcripts.** Resolved: source-agnostic. Confidant doesn't care which tool records or stores transcripts. An import skill reads them from wherever they live (Frank's are already saving in parallel to Google Drive) and writes encrypted interaction entries with provenance (`src:transcript/<source-id>`) and duration, which ICF hours use. Copies left in a hosted store like Drive are outside Confidant's privacy guarantee; deleting them after import is the operator's call.
4. **Local decrypted operations.** Resolved: not in v0. Agents use `confidant context` and `--json` output for now.
5. **First integration skill.** Resolved: portal sync (renewals, sent checkouts, lost deals), because it feeds renewals and deals into the vault.
6. **Session forms (8a).** Resolved: in v0 the agent deletes answers from the portal after a verified import. Browser-side encryption comes in v0.1.
7. **Inbox location.** Resolved: a separate `inbox` branch, with main protected so only trusted signers can write to it.

## 9b. Risks and how we handle them (decided 2026-10-07)

1. **Conflicting edits to an encrypted file.** Git can't merge ciphertext. When two devices change the same record, the CLI keeps both versions side by side, `confidant check` flags the conflict, and the agent or the operator picks which one to keep. Nothing is silently dropped. Conflicts should be rare, because records are one file each and writes are mostly append-only.
2. **The model provider sees plaintext.** Agents send what they read to a hosted model provider. The README and privacy model say so plainly and don't claim the provider stores nothing. A per-client `no-ai` flag keeps that client's notes and PII out of `confidant context` and `--json` output used by agents, so the operator can keep sensitive clients away from models entirely.
3. **Capture going stale.** Confidant only knows what agents write into it. A `confidant check` rule flags gaps, such as a session with no notes, or a paid client with no session within a set window. The agent sends the operator a weekly summary of these gaps.
4. **Search.** v0 searches by decrypting and scanning, which should be fast enough for a few hundred clients (milestone 1 measures it). Right after v0, QMD becomes the search: it runs only on trusted devices with encrypted disks (FileVault on the laptop, and the agent's computer), and its index stays out of git and is never synced anywhere.
5. Changed 2026-10-08 by Frank: Silas's security review of the crypto design (PR A) clears milestone 2 code for the operator's own use. One outside human reviews the design and a full code audit happens before the README invites anyone else to trust Confidant with client data.

## Appendix A. Moving off Lightfield (Frank's context)

- **No deadline.** Frank has already cancelled the renewal and hasn't opened Lightfield in a long time. Agents replaced how he used it. Its only valuable feature was meeting transcription, which isn't unique to it.
- **What matters.** Transcripts (already saving in parallel to Google Drive) and the notes written from them. The transcript import skill (Open question 3) is the real migration.
- **Export and import.** Export Lightfield before access ends, and import whatever is useful from it (contacts, deals, meeting notes, transcripts). It's best-effort: transcripts and notes are the must-have, and everything else is a bonus. The export is plaintext PII: keep it on a trusted device, never commit it, and delete it after a verified import.
- **Loose ends.** Paige's coaching skills that read Lightfield directly (session prep, renewal offers, ICF hours) move to `confidant`. ICF hours read duration from transcripts. The portal's Lightfield sync gets turned off. Paige reviews these changes, since she owns the coaching practice.

## Appendix B. Simplifying the coaching CLI (after v0)

Once Confidant v0 ships, list every `bun run` coaching command and mark each one move, keep or drop. Commands that touch client records, the ledger or sessions move to `confidant`. Portal, forms and outreach stay in the coaching CLI as thin skills that call `confidant`. Paige reviews the list, since it's her workflow. Not started; deferred by Frank on 2026-10-07.

## Appendix: Prior art (sweep 2026-10-07)

No existing project combines all of these: a git vault, a beancount-style ledger, age keys per device, per-client keys that allow crypto-shredding, an agent-first contract and schema packs. The individual parts do exist.

| Project | Lang / license | Closeness | Take |
|---|---|---|---|
| [cr](https://github.com/AnandChowdhary/cr) | Rust, MIT | High | Markdown records with YAML front matter as the source of truth, JSON Schema validation, `cr check`, a tamper-evident audit log (actor, agent, approval, reason), idempotency keys. Real differences: caller-chosen name slugs as IDs (examples like `priya-shah.md` leak names) versus our opaque ULIDs; it doesn't store its data through git; one database-wide keyring; it encrypts only fields and bodies inside a file; it refuses encryption for folder-style records; its audit chain is single-writer; and ~40% of the source is server, web UI and access control. **Spiked: build and borrow (ADR-13).** |
| [AgentCRM](https://github.com/AgentPal/AgentCRM) | Go, MIT | Medium | Markdown per contact and deal, monthly interaction logs, an approval queue for agent writes, and a SQLite index that can be rebuilt. No encryption. |
| [frm](https://github.com/justinabrahms/frm) | Go, MIT | Medium | Agent contract: `check`, `context <person>`, `--json`, `--dry-run`, SKILL.md. |
| [crm.cli](https://github.com/dzhng/crm.cli) | TS, MIT | Low–Medium | Same vault-discovery order as ADR-11; duplicate merge re-points links. |
| [people-context](https://github.com/JinyangWang27/people-context) | Python, MIT | Low–Medium | Published threat model, a `forget` that actually deletes, alias resolution. |
| [friends](https://github.com/JacobEvelyn/friends) | Ruby, MIT | Prior art | A dated one-line activity ledger about people (last updated 2021). |

**Building blocks:** `age` from [rage](https://github.com/str4d/rage), [gix](https://github.com/GitoxideLabs/gitoxide) or [git2](https://github.com/rust-lang/git2-rs), [ulid-rs](https://github.com/dylanhart/ulid-rs), [pulldown-cmark](https://github.com/pulldown-cmark/pulldown-cmark), and [beancount-parser](https://github.com/jcornaz/beancount-parser) as a parser reference. None of the encrypt-in-git tools ([sops](https://github.com/getsops/sops), [git-agecrypt](https://github.com/bartei/git-agecrypt), [transcrypt](https://github.com/elasticdog/transcrypt), [git-crypt](https://github.com/AGWA/git-crypt)) does per-client keys, so ADR-4 needs custom code.

**Ideas to adopt:** bind each ciphertext to its vault, record ID and path through AEAD associated data (cr, ADR-4); agent writes wait as pending proposals until a human approves them (AgentCRM, wend-core); merges re-point every link (crm.cli); a published threat model and a real `forget` (people-context).

**cr spike (done 2026-10-07):** build our own and borrow patterns; see ADR-13 and `/workspace/research/cr-spike-2026-10-07.md`.
