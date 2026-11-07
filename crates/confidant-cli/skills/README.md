# Confidant integration skills

Agent-facing skill text that ships inside the `confidant` binary (ADR-8).
There is no plugin system in v0: the agent runs a skill, and the skill calls
the CLI's agent contract (ADR-7).

Five skills ship today:

| Skill | What it does |
|---|---|
| `confidant/` | Standing register for every interaction: plain English, structured choices with a recommendation, propose → confirm → apply, routing to the task skills, setup's personalized jumping-off point, the inferred sync posture, and the operator's own bar |
| `qmd-search/` | Optional QMD-backed search over a local index; falls back to `confidant find` |
| `pack-author/` | Scaffold and refine a local schema pack with `confidant pack init` |
| `reconcile/` | Maintenance pass: surface facts that may be stale, verify them with the operator (the ground truth), and propose `retract`/`record retire` one change at a time; keeps a local `.confidant/reconcile-state.json` of what was verified when |
| `report-a-problem/` | Draft, redact, and file a Confidant issue after duplicate search and explicit confirmation; structural diagnostics only, never vault contents |

## Installing (for operators and agents)

Skills are embedded at compile time and installed by `confidant setup
--agent auto`: each skill calls scripts via paths under the installed
skills dir, so copying a lone `SKILL.md` elsewhere breaks it — always link
(or copy) the whole skill directory, which `setup` does for you. Run
`confidant which --skills-dir` to locate the installed tree. The supported
setup is `docs/agent-setup.md` in the GitHub repo: install the binary, run
`setup`, set `CONFIDANT_VAULT`. That page also holds the single copy/paste
install prompt and the update loop (`confidant update`, then `confidant
setup --force` to re-link).

`setup` and `update` also remove confidant-owned links for skills that no
longer ship. Unowned user files are left alone.

## Skills or MCP?

Skills carry the written workflow and guardrails and shell out to the CLI,
which keeps the operator in the loop and works in any host that can run a
shell. `confidant mcp` is the complement for MCP-native hosts: a thin stdio
server over the CLI's `--json` contract (`confidant mcp`, newline-delimited
JSON-RPC), exposing a fixed tool set (`check`, `doctor`, `find`, `context`,
the write verbs, `schema`, `pack_skill`). It applies the same `no-ai`
allowlist and the same pack ceiling; it never becomes a second
implementation.

- Prefer **skills** for hosts without native MCP tool support, and when you
  want the propose → confirm → apply workflow written out, plus the
  `pack-author` guidance (pack commands are operator-only and not exposed
  over MCP).
- Prefer **MCP** when the host has native tool integration and no shell.
- Using both is fine: point the host at `confidant mcp` and keep the skills
  installed for their workflow text.

`confidant setup` names both surfaces in its completion output, with the
`confidant mcp` invocation.

## Privacy

- `qmd-search` reads the vault through the §12 allowlist: a `no-ai` record
  never reaches the index or a query result.
- Indexes and caches live in `<vault>/.confidant/` (gitignored), stay on
  trusted devices, and never go in git (ADR-6).
- Skills write nothing on their own: `confidant` is text only,
  `pack-author` edits a directory outside the vault; `qmd-search` only
  reads. `reconcile` writes only its local `.confidant/` state; every vault
  change goes through the CLI after the operator confirms it.
  `report-a-problem` runs read-only diagnostics and posts only after the
  operator confirms the exact issue — never vault contents.
