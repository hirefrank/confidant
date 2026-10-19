# Threat model: agents

What an MCP-connected agent can and cannot do — and exactly what `no-ai`, the
`check` gate, and the inbox guarantee (and don't).

This is the **agent-focused** threat model. It does not replace the others:

- `docs/architecture.md` §4 — storage and hosting threats (leaked remote,
  stolen backup, curious host).
- `docs/crypto-design.md` §11 — cryptography threats (key compromise,
  rollback, shredding).
- `docs/privacy.md` — the §12 search allowlist mechanics in full detail.

Every guarantee below cites the code or test that enforces it. Known gaps are
listed plainly at the end; a guarantee with a gap next to it is still true,
but narrower than it sounds.

## Guarantees in one line each

- An MCP agent can only call 8 fixed tools, and cannot grant itself more.
- An agent can read private data through `context` only by passing
  `exclude_private: false` — which it can do by itself.
- A `no-ai` record never appears in `find`, `context`, the allowlist, or the
  search corpus — in either the CLI or MCP.
- `no-ai` does not hide a record from the vault's owner.
- `check` blocks a commit on errors, never on warnings, and verifies
  coherence, not truthfulness.
- Ledger lines are plaintext even in an encrypted vault.
- An inbox item is merged only if every commit that touched it carries a valid
  signature from a `[trust]` signer, and the merge passes `check`.
- Inbox intake can never change identity (`merge`) or balances (`balance`).
- A write commits directly after `check` passes, with no human review step.
- A hosted model provider sees whatever the agent sends it; Confidant makes
  no claim about what the provider stores.

## Local MCP agent

An agent connected over MCP (for example, a coding agent with the Confidant
server configured) works through one fixed tool list.

| Can | Cannot | Enforced by |
|---|---|---|
| Call 8 tools: `check`, `find`, `context`, `log_session`, `import_ledger`, `note_add`, `schema`, `doctor` | Call any other tool, or grant itself a new capability | `tools()` in `crates/confidant-cli/src/mcp.rs` — the list is a literal in the binary |
| Read a person's context bundle, with private data stripped by default | Read private data silently — it must pass `exclude_private: false`, which is visible in its own tool call | `context_strips_private()` in `crates/confidant-cli/src/mcp.rs` |
| Append a session line, bulk-append ledger lines, or add a note — one commit each, gated by `check` | Write without `check`, or skip the commit | `crates/confidant-core/src/write.rs` — change → `check` → one `git add` + `git commit`; a failing check rolls the files back |
| Pass `exclude_private: false` and read private data | Be stopped from doing so by any vault setting — no vault config removes the opt-out | Current behavior; see Known gaps |

There are **no per-agent scopes and no agent identity** in the MCP server.
The server trusts its local caller. Every tool call is dispatched by shelling
out to the CLI with `--json --no-input --vault <path>` (`call_tool()` in
`crates/confidant-cli/src/mcp.rs`), so the MCP agent has exactly the CLI's
powers through those 8 tools — no more, no less. Per-pack agent scoping is
future work (#178); until then, an agent that can call `context` can call it
for any person in the vault.

## Remote proposer via inbox

An outside tool (a capture script, another agent, a phone shortcut) can
propose content by encrypting items to the vault's public inbox key and
pushing them to the `inbox` branch. It cannot write to main directly.

| Can | Cannot | Enforced by |
|---|---|---|
| Push encrypted items to the `inbox` branch | Write to the main branch, or merge its own items | `confidant inbox` is the only merge path, and it runs on the operator's device (`crates/confidant-core/src/inbox/mod.rs`) |
| Propose ledger lines (each needs a `src:`) and new records | Change identity or balances — the `merge` and `balance` verbs are rejected at intake | `crates/confidant-core/src/inbox/mod.rs` header: "the `merge` / `balance` verbs are rejected" |
| Get items merged once they decrypt, parse, and pass `check` | Get a partial merge — the run is all-or-nothing: any failure merges nothing and clears nothing | `crates/confidant-core/src/inbox/mod.rs` header |
| Submit the same item twice | Duplicate it — lines whose `src:` already exists are skipped | `crates/confidant-core/src/inbox/mod.rs` header |

Trust at intake (all fail closed):

- Every commit that adds or changes an item must carry a valid signature from
  a `[trust]` signer — checking only the tip is not enough. With no signers
  configured, the run refuses unless `--allow-unsigned`.
- The vault's advertised `[inbox].pubkey` must match the operator's
  out-of-band pin (`~/.config/confidant/config.toml [inbox] pubkey`), and must
  also match the recipient derived from the local inbox private key. The
  private key is the ground truth for who can actually read these items.
- The inbox private key lives with the operator (OS keychain). No decryption
  keys live in CI, and intake never uses webhooks.

## Model provider

When an agent reads notes, that content is sent to a hosted model provider
for processing. This is explicit and accepted (`docs/architecture.md` §4).

| Can | Cannot | Notes |
|---|---|---|
| See whatever the agent sends it (note bodies, context bundles, search hits) | Be constrained by Confidant — Confidant makes no claim about what the provider stores, retains, or trains on | Depends on the provider's terms |
| Receive `no-ai` content | — | `no-ai` records never reach agent surfaces, so they never reach the provider through Confidant |

Mitigations the operator controls: mark sensitive records `no-ai` so they
never enter agent flows; keep the `context` private-data default (stripped)
unless a task needs it; choose which agent and provider a task runs under.
None of these change what the provider does with content it has already
received.

## Stolen device

A stolen unlocked device, or malware on a trusted device, defeats every
guarantee in this document. The device holds the operator's CLI, the
keychain, and the device keys; `no-ai`, `check`, and inbox trust do not help
against someone holding the operator's own session. This is out of scope by
design (`docs/architecture.md` §4: "does not protect against a compromised
trusted device"). The response is revocation (`keys revoke`), and shredding
(`keys shred`) if the exposure warrants it — not any per-record flag.

Related: local indexes and caches (`.confidant/`, any search index) contain
plaintext and embeddings. They are sensitive, gitignored, and stay on
trusted devices.

## The three mechanisms, precisely

### `no-ai`: an exposure control, not access control

`no-ai` is a per-record flag in the plaintext outer header of the record
envelope (`no-ai: bool`, `crates/confidant-crypt/src/envelope.rs`). A
record's effective flag is its own flag **or** its person's flag — "any
`true` wins" (`person_no_ai()` in `crates/confidant-cli/src/record_crypto.rs`).

What it does: a `no-ai` record never appears in `find` (filter in
`crates/confidant-core/src/search.rs`), in `context` (which only shows §12
cleared records), in the `allowlist` response ("no-ai records never appear",
`crates/confidant-core/src/schema.rs`), or in the reindex corpus (built
from the cleared set, `crates/confidant-cli/src/main.rs`
`build_reindex_corpus`). The agent read path never decrypts a `no-ai`
envelope: its decrypt hook returns a shell with the id and type, never the
content (`crates/confidant-cli/src/record_decrypt.rs`). The reads that do
decrypt are the operator's own `confidant record show <id> --for-edit` and
`confidant note show <id> --for-edit`, covered below.

What it does not do:

- **It does not hide the record from the vault's owner.** The CLI's
  `find`/`context` honor `no-ai` exactly like MCP does — they share the
  same read path (`load_vault_for_reads`). But the operator owns the files
  and holds the device key, so nothing prevents reading the record outside
  the read surfaces (raw bytes from git, decrypted with the operator's own
  key material). `no-ai` keeps a record out of agent flows; it is not
  access control against the owner.
- **It does not stop an agent that already has a shell on this device.**
  MCP dispatches from a fixed tool whitelist
  (`crates/confidant-cli/src/mcp.rs`) that omits `record show --for-edit`,
  `note show --for-edit`, and `note edit`, so a tool call cannot reach
  them. An agent that can run commands on this
  machine, with this device's key material in reach, can invoke it directly
  — exactly as it could decrypt the file itself, or shell out to the CLI at
  all. `--for-edit` is a boundary in the CLI's surface, not access control
  against a caller that already holds the device key.
- **The flag itself is visible.** `no-ai: true` sits in the envelope's
  plaintext outer header, so anyone who can read the file learns that the
  record is marked — though not its content.

### `check`: coherence, not truthfulness

`check` runs after a change and before the commit, on the merged result.
A failing check rolls the files back and blocks the commit
(`crates/confidant-core/src/write.rs`). It blocks on **errors**, never on
warnings, unless `--fail-on warn` is passed (`parse_fail_on` /
`CheckSummary::fails` in `crates/confidant-core/src/check.rs`).

Every `check` rule is structural. The finding codes (`FindingCode` in
`crates/confidant-core/src/check.rs`) are parse failures, unknown verbs,
dangling references, duplicate IDs, ID/path mismatches, balance arithmetic
(`BalanceMismatch`, `NegativeBalance`), and pack rules such as
`SessionWithoutNotes` and `PaidSessionGap`. No rule verifies a fact against
the world: a well-formed false fact — a session that never happened, a
note with invented content — passes `check` exactly like a true one.
`check` guarantees the vault is internally coherent, not that it is true.

One scoping note: `check` runs against the live vault, not a staged copy
(#209). That is fine today because `check` only looks at whether `keys/`
exists; if `check` ever reads files inside `keys/`, it must run against
the staged tree instead.

### Inbox: signed proposals, operator-side merge

The inbox is a holding branch, not a write path. Items arrive encrypted to
the public inbox key; the operator's `confidant inbox` run decrypts them,
runs `check` on the merged result, merges into the current branch, and
clears the inbox. See "Remote proposer via inbox" above for the trust
rules. The key property: nothing from the inbox reaches main without a
valid `[trust]` signature chain **and** a passing `check`.

## Known gaps, stated plainly

1. **An agent can set `exclude_private: false` by itself.** There is no
   vault config that removes the opt-out. The default (stripped) protects
   agents that don't ask; it does not constrain an agent that does.
2. **Direct writes commit with no human review.** MCP and CLI writes commit
   as soon as `check` passes. Proposal review — see, approve, or reject
   agent-proposed changes before main — is future work (#191).
3. **`check` verifies coherence, not truth.** A well-formed false fact
   passes.
4. **Ledger lines are plaintext** even in encrypted vaults
   (`crates/confidant-core/src/crypto_mode.rs`: "everything else (ledger,
   `confidant.toml`, inbox) stays plaintext by design"). Dates, verbs,
   opaque IDs, and `src:` tokens are visible to anyone with repo read
   access. Never put sensitive text in a ledger line; detail goes in an
   encrypted note.
5. **`no-ai` is not access control**, and the `no-ai` flag itself is
   plaintext in the envelope header.
6. **The model provider sees whatever the agent sends.** No claim about
   provider storage, retention, or training.
7. **A stolen unlocked device defeats everything.** Out of scope by design.

## What would change these claims

- #178 (per-pack access scoping) — agents limited to one pack's data.
- #181 (finer `no-ai` granularity) — field- or section-level hiding.
- #191 (proposal review UX) — human approval before agent writes reach main.
- #209 (`check` vs staged `keys/`) — `check` must read the staged tree if
  it ever reads inside `keys/`.

Update this document whenever any of those land.
