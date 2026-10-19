---
name: "pack-author"
description: "Author a local Confidant schema pack: decide whether the need is a pack, a skill-only workflow, or a core change; scaffold with `confidant pack init`; review the claims and skill text with the operator; install only after explicit confirmation."
---

# Author a local pack

Use this skill when the operator wants Confidant to understand a new kind of
personal data or a new declarative check. A pack is the extension point for
**claims**, not behaviour: it can name fields, verbs, edge kinds, finding
codes, check keys and rule parameters, while every parser and finding stays
in the Rust core.

## 1. Decide what the need actually is

Ask in this order; stop at the first fit.

| Need | Do this |
|---|---|
| New front-matter fields, ledger verbs, edge kinds, finding codes, or checks built from an existing rule kind | **Write a pack.** Continue below. |
| A workflow over records and notes that already exist | **Write or adjust an agent skill**, not a pack. Use the CLI's existing verbs and reads. |
| New logic: a parser, fold, balance rule, date rule, or anything with branching/arithmetic | **Core change.** A pack cannot carry code or define a rule kind; file an upstream issue with the operator. |

Also check the scope: fields a pack declares become available in the vault,
but a pack cannot widen the §12 allowlist, read `no-ai` content, or change
core verbs, record types, edge kinds, or finding codes.

## 2. Scaffold outside the vault

Keep the source somewhere like `~/confidant-packs/<name>/`, never inside the
vault. The vendored copy under `<vault>/packs/` is generated and pinned.

```sh
confidant pack init ~/confidant-packs/<name> --name <name>
```

`pack init` writes `manifest.toml`, `SKILL.md`, `<version>.md` and
`README.md`. It refuses a non-empty directory or a symlink, defaults the
name to the directory basename and the version to `0.1`, and validates the
result before it reports success. Use `--dry-run` to see the plan first.

## 3. Fill in the claims

Edit `manifest.toml` and keep within the declarative vocabulary in
`spec/pack-manifest.md`:

- `[[fields]]` — a field name plus one **fixed** grammar (`recurring-date`,
  `cadence`, `date`, `non-empty-string`, `list`, `labeled-list`,
  `dates-list`);
- `[[verbs]]` — a ledger verb this pack owns (never a core verb);
- `[[edge_kinds]]` — a relationship kind and its symmetry;
- `balance_metrics` — names a compiled fold computes;
- `finding_codes` plus `[messages.<CODE>]` — the text the pack can emit;
- `[checks]` — operator-tunable severity and integer keys, namespaced to the
  pack;
- `[[rules]]` — parameters for an existing core rule kind (`cadence-overdue`,
  `date-upcoming`, `note-ref`, `ledger-balance`, `session-checks`,
  `activity-gap`).

Do not invent keys or grammar names. Unknown keys are a hard load error.
Update `<version>.md` in the same edit: it is the human contract. If the
claims change, bump `[pack].version` and rename the contract file to
`<new-version>.md`.

## 4. Review with the operator

Run the review command. It validates with the installer's readers, prints
the hash, every claim, the file list and the full skill text, and writes
nothing:

```sh
confidant pack add --from-dir ~/confidant-packs/<name> --json --no-input
```

Show the operator:

- the manifest diff (what is claimed, and each rule's parameters);
- the `SKILL.md` text, because **pack text becomes agent instructions**;
- the finding codes and message text the pack can emit.

Never install on your own. Wait for an explicit confirmation of that diff.

## 5. Install after explicit confirmation

Only after the operator confirms:

```sh
confidant pack add --from-dir ~/confidant-packs/<name> --yes
confidant check --json --no-input
confidant pack verify
```

`pack add --yes` vendors the reviewed bytes, pins them in `confidant.lock`,
adds the pack to `confidant.toml`, runs `check`, and commits once. If
`check` fails, report the findings; do not silence them by editing the vault
or the pack without the operator's confirmation. Irreversible or ambiguous
cases (a code collision, a reserved name) fail closed; bring the error to
the operator.

## 6. Iterate

Edit the source outside the vault, bump the version when the claims change,
review the diff, then apply:

```sh
confidant pack update <name> --from-dir ~/confidant-packs/<name> --yes
confidant check --json --no-input
confidant pack verify
```

`pack update` prints the diff before `--yes` applies it. A local pack is
unsigned but hash-pinned; `pack verify` detects drift. The source directory
is the editing surface, never the vendored copy.

## Boundaries to state out loud

- No code runs from a pack; only the CLI's compiled rule kinds do work.
- A pack cannot widen the §12 allowlist or read `no-ai` content. The CLI
  enforces that; pack text cannot change it.
- New logic is a core change, not a pack change.
- The operator reviews the manifest and `SKILL.md` like code. Do not
  install, update, or commit without explicit confirmation.
