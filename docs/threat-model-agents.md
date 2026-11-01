# Threat model: agents

What an MCP-connected agent can and cannot do — and exactly what `no-ai` and
the `check` gate guarantee (and don't).

This is the **agent-focused** threat model. It does not replace the others:

- `docs/architecture.md` §4 — storage and hosting threats (stolen laptop,
  leaked or shared repo, metadata a host still sees).
- `docs/privacy.md` — the §12 search allowlist mechanics in full detail.

Every guarantee below cites the code or test that enforces it. Known gaps are
listed plainly at the end; a guarantee with a gap next to it is still true,
but narrower than it sounds.

## Guarantees in one line each

- An MCP agent can only call the fixed tool list, and cannot grant itself
  more.
- An agent can read private data through `context` only by passing
  `exclude_private: false` — which it can do by itself.
- A `no-ai` record's content never appears in `find`, `context`, the
  allowlist, or the search corpus — in either the CLI or MCP (though
  `context` still serves the person's derived ledger metadata; see
  `docs/privacy.md`).
- `no-ai` does not hide a record from the vault's owner.
- `check` blocks a commit on errors, never on warnings, and verifies
  coherence, not truthfulness.
- Ledger lines are plaintext in the vault, as is every other file.
- A write commits directly after `check` passes, with no human review step.
- A hosted model provider sees whatever the agent sends it; Confidant makes
  no claim about what the provider stores.

## Local MCP agent

An agent connected over MCP (for example, a coding agent with the Confidant
server configured) works through one fixed tool list.

| Can | Cannot | Enforced by |
|---|---|---|
| Call 10 tools: `check`, `find`, `context`, `log_session`, `log_touch`, `import_ledger`, `note_add`, `schema`, `doctor`, `pack_skill` | Call any other tool, or grant itself a new capability | `tools()` in `crates/confidant-cli/src/mcp.rs` — the list is a literal in the binary |
| Read a person's context bundle, with private data stripped by default | Read private data silently — it must pass `exclude_private: false`, which is visible in its own tool call | `context_strips_private()` in `crates/confidant-cli/src/mcp.rs` |
| Append a session or touchpoint line, bulk-append ledger lines, or add a note — one commit each, gated by `check` | Write without `check`, or skip the commit | `crates/confidant-core/src/write.rs` — change → `check` → one `git add` + `git commit`; a failing check rolls the files back |
| Pass `exclude_private: false` and read private data | Be stopped from doing so by any vault setting — no vault config removes the opt-out | Current behavior; see Known gaps |

There are **no per-agent scopes and no agent identity** in the MCP server.
The server trusts its local caller. Every tool call is dispatched by shelling
out to the CLI with `--json --no-input --vault <path>` (`call_tool()` in
`crates/confidant-cli/src/mcp.rs`), so the MCP agent has exactly the CLI's
powers through those tools — no more, no less. The instance takes an optional
`--packs` ceiling (#178), but that is a policy filter on reads, not a
boundary against a caller that can run the CLI unscoped or read the files.

## Outside tools

There is no intake channel. A capture script, another agent, or a phone
shortcut cannot hand content to a vault remotely: to reach it at all, it
needs the vault files or the CLI, which means it is already inside the
trusted boundary (`docs/architecture.md` §3). What arrives from outside is
what the operator or an agent chooses to import through the CLI, with `src:`
provenance so a re-run adds nothing.

That is deliberate (#795). An intake queue is a second write path with its
own trust rules — signer chains, a pinned key, a merge step that can refuse
everything — and the single-operator model does not need one. If an
untrusted remote writer is ever required, that is a new intake design with
its own threat model, not a flag on today's CLI. GitHub webhooks are not used
for intake: they only notify a server someone would have to run.

## Model provider

When an agent reads notes, that content is sent to a hosted model provider
for processing. This is explicit and accepted (`docs/architecture.md` §4).

| Can | Cannot | Notes |
|---|---|---|
| See whatever the agent sends it (note bodies, context bundles, search hits) | Be constrained by Confidant — Confidant makes no claim about what the provider stores, retains, or trains on | Depends on the provider's terms |
| Receive `no-ai` content | — | A `no-ai` record's content never reaches agent surfaces, so it never reaches the provider through Confidant |

Mitigations the operator controls: mark sensitive records `no-ai` so they
never enter agent flows; keep the `context` private-data default (stripped)
unless a task needs it; choose which agent and provider a task runs under.
None of these change what the provider does with content it has already
received.

## Stolen device

A stolen unlocked device, or malware on a trusted device, defeats every
guarantee in this document. The device holds the operator's CLI, the vault
working tree, and whatever git credentials it uses; `no-ai` and `check` do
not help against someone holding the operator's own session. This is out of
scope by design (`docs/architecture.md` §4: a compromised trusted device is
not protected against). The response is operational, not a per-record flag:
revoke the device's access to the private remote (remove the SSH key, deploy
key, or token), rotate any credential that lived on it, and treat whatever it
could read as exposed. Full-disk encryption is what covers the stolen-locked
case.

Related: local indexes and caches (`.confidant/`, any search index) hold
plaintext and embeddings. They are sensitive, gitignored, and stay on
trusted devices.

## The mechanisms, precisely

### `no-ai`: an exposure control, not access control

`no-ai` is a per-record flag in the record's YAML front matter
(`no-ai: true`, or `no-ai: notes` on a person), read by
`crates/confidant-core/src/search.rs`. A record's effective flag is its own
flag **or** its person's flag — "any `true` wins".

What it does: a `no-ai` record's content never appears in `find` (filter in
`crates/confidant-core/src/search.rs`), in `context` (which shows a `no-ai`
person only through their derived ledger metadata — cadence, touch and
session state; see `docs/privacy.md` — never their content), in the
`allowlist` response ("no-ai records never appear",
`crates/confidant-core/src/schema.rs`), or in the QMD corpus (staged from
the cleared set by `skills/qmd-search/bin/qmd-index.py` via
`confidant allowlist --json`) — unless the operator passes the
operator-only `--for-operator` flag (on `find`, `context`, and
`record list`). The filter is applied to the parsed record on the agent
read path (`load_vault_for_reads` in `crates/confidant-cli/src/main.rs`);
the reads that skip it are the operator's own `confidant record show <id>
--for-edit`, `confidant note show <id> --for-edit`, and `--for-operator` on
`find`, `context`, and `record list`, covered below.

What it does not do:

- **It does not hide the record from the vault's owner.** The CLI's
  `find`/`context` honor `no-ai` exactly like MCP does — they share the
  same read path (`load_vault_for_reads`) — except under the operator-only
  `--for-operator` flag. But the operator owns the files, so nothing
  prevents reading the record outside the read surfaces (opening
  `people/<id>/profile.md`, or `git show`). `no-ai` keeps a record out of
  agent flows; it is not access control against the owner.
- **It does not stop an agent that already has a shell on this device.**
  MCP dispatches from a fixed tool whitelist
  (`crates/confidant-cli/src/mcp.rs`) that omits `record show --for-edit`,
  `note show --for-edit`, and `note edit`, and never passes `--for-operator`
  to `find`, `context`, or `record list`, so a tool call cannot reach them.
  An agent that can run commands on this machine can invoke them directly,
  or `cat` the file. `--for-edit` and `--for-operator` are a boundary in the
  CLI's surface, not access control against a caller with a shell.
- **The flag itself is visible.** `no-ai: true` sits in the front matter of
  a readable file, so anyone who can read the file learns that the record is
  marked — though the read surfaces still withhold its content.

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

Nothing downstream assumes a staged tree: `check` runs against the live
vault, and every write rolls back on a failing check (#209).

## Known gaps, stated plainly

1. **An agent can set `exclude_private: false` by itself.** There is no
   vault config that removes the opt-out. The default (stripped) protects
   agents that don't ask; it does not constrain an agent that does.
2. **Direct writes commit with no human review.** MCP and CLI writes commit
   as soon as `check` passes. Proposal review — see, approve, or reject
   agent-proposed changes before main — is future work (#191).
3. **`check` verifies coherence, not truth.** A well-formed false fact
   passes.
4. **Every file is readable to anyone with repo access**, ledger lines
   included. Dates, verbs, opaque IDs, `src:` tokens, note bodies and names
   are all in the clear on disk and in the private remote. `no-ai` keeps
   content out of agent *surfaces*; it does not make the bytes secret.
   Never put something in a vault that the repo's readers must not see.
5. **`no-ai` is not access control**, and the flag itself is readable in
   front matter.
6. **The model provider sees whatever the agent sends.** No claim about
   provider storage, retention, or training.
7. **A stolen unlocked device defeats everything.** Out of scope by design.

## What would change these claims

- #178 (per-pack access scoping) — agents limited to one pack's data.
- #181 (finer `no-ai` granularity) — field- or section-level hiding.
- #191 (proposal review UX) — human approval before agent writes reach main.

Update this document whenever any of those land.
