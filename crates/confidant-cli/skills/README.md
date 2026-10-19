# Confidant integration skills

Agent-facing skill text that ships inside the `confidant` binary (ADR-8).
There is no plugin system in v0: the agent runs a skill, and the skill calls
the CLI's agent contract (ADR-7).

Two skills ship today:

| Skill | What it does |
|---|---|
| `qmd-search/` | Optional QMD-backed search over a local index; falls back to `confidant find` |
| `pack-author/` | Scaffold and refine a local schema pack with `confidant pack init` |

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

## Privacy

- `qmd-search` reads the vault through the §12 allowlist: a `no-ai` record
  never reaches the index or a query result.
- Indexes and caches live in `<vault>/.confidant/` (gitignored), stay on
  trusted devices, and never go in git (ADR-6).
- Skills propose nothing and write nothing themselves: `pack-author` edits
  a directory outside the vault; `qmd-search` only reads.
