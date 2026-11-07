---
name: "reconcile"
description: "Run a maintenance pass over a Confidant vault: surface facts that may be stale from `check`, `context`, cadence, and `profile_provenance` dates; verify them with the operator (the ground truth); propose `retract` or `record retire` through dry-run → confirm → apply, one commit per change; and keep a local `.confidant/reconcile-state.json` of what was verified when. Never bulk-deletes and never decides alone."
---

# Reconcile: a maintenance pass

This is Polylane's nightly "dreaming" loop, translated. Polylane re-checks
its agent memory against production every night and rebuilds its index.
Confidant has no production to query: **the operator is the ground truth**
for relationship memory. So this pass surfaces what may have gone stale,
asks the operator, and changes only what they confirm. It is a skill over
the existing CLI — no new command, no core change.

## When to run

- The operator asks for a cleanup, a stale-fact review, or "the maintenance
  pass".
- On a cadence the operator chose (for example, a quiet Sunday). A timer is
  opt-in; never a background job that writes without a confirmation.
- After a long gap, a bulk import, a big sync pull, or before a
  meeting-heavy week.
- Not as a way to generate busywork. If nothing looks stale, say so and
  stop.

## What it never does

- Never reads vault files directly, and never asks another tool to. Every
  fact comes from `confidant check`, `find`, `resolve`, `context`, or
  `status`; visibility comes from `confidant allowlist`.
- Never names, quotes, or summarizes a record that is not in the cleared set.
  A `no-ai: true` record, a retired record, and a merged-away record are
  absent from `confidant allowlist --json`; their ids stay out of the
  candidate set and out of the state file. Do not use "`context` errored" as
  the signal: `context` can still return a minimal bundle for a `no-ai`
  person (`entity.no_ai: true`, no name or profile).
- Never bulk-retracts. No `--match-date`, no `--keep`, no "clean up
  everything older than X". One line, one proposal, one confirmation.
- Never retires a quiet relationship. Retirement means "this page should
  not exist in agent reads", not "I have not spoken to them lately".
- Never writes without the operator's explicit yes to that exact change,
  and never batches unrelated changes into one confirmation.
- Never treats the state file as truth about the vault. It is a notebook of
  what was checked, not a second record.

## Inputs

Start read-only. These are the only sources:

| Read | What it gives | Use it for |
|---|---|---|
| `confidant allowlist --json --no-input` | the §12 cleared record set (agent-visible ids only) | deciding whether a candidate may enter the pass or the state file; `no-ai`, retired, and merged-away records are absent |
| `confidant check --json --no-input` | findings with `code`, `id`, `file`, `message`, and a summary | cadence and date warnings; the ids that need a conversation |
| `confidant find <term> --json --no-input` | matches with `id` and, for ledger lines, a `ref` | finding the exact line a correction needs; following a name the operator raised |
| `confidant resolve <name>` | the resolved opaque id | turning a name in the conversation into an id |
| `confidant context <id> --json --no-input` | `entity`, `packs` (cadence, `overdue`, `profile_provenance`), touches, notes, edges | per-record evidence |
| `confidant status --json --no-input` | readiness, sync posture, counts | whether the vault is safe to write to; never a source of relationship facts |

Read `--help` before inventing a flag. The operator's full roster command is
operator-only and is not available to you; do not try to reach it. Work from
the findings, the state file, and the people the operator names.

## Signs that a fact may be stale

| Sign | Where it comes from | What it means | What it does not mean |
|---|---|---|---|
| `W_CADENCE_OVERDUE` | `check` | no touch in the record's own cadence window | that the relationship is failing, or that logging a touch is honest |
| `overdue` / `days_since_touch` vs `cadence_days` | `context.packs.<pack>` | the same window, per record | a reason to invent contact |
| `profile_provenance` dates | `context.packs.<pack>.profile_provenance` | when a profile fact was sourced | that the fact is wrong today |
| no `last_touch`, no provenance | `context` | nothing recorded yet | that the person does not matter |
| no state entry | `.confidant/reconcile-state.json` | this pass has never verified the record | that it is stale |
| evidence newer than `last_verified` | state plus `context` dates | the record changed since the last pass | a contradiction |

### Thresholds come from the record, not from you

- **Cadence.** Use `cadence_days` from `context --json`. If the field is
  unset, there is no window and you do not invent one. If `cadence: never`
  / `cadence_never: true`, the operator considered the relationship and
  chose no nudge: it is never "overdue".
- **The check's own setting.** `W_CADENCE_OVERDUE` already applies the
  pack's configured cadence and `as_of`. Treat it as the operator's setting,
  not as your opinion.
- **Provenance.** A `profile_provenance` date is a source date, usually
  `YYYY-MM`. Compare it to the record's cadence window only when that
  record has one; otherwise state the date plainly ("the title was sourced
  in 2024-03") and ask. Do not invent a global "older than a year" rule.
- **Never checked is not stale.** It is simply unchecked, and it goes second
  in the order below.
- **The operator's bar wins.** The `confidant` skill's section 8 records
  whether this operator wants drift nudges at all. If they chose silence,
  do not run a cadence pass; say "no touch in nine months" only if it is
  relevant, and let them decide. Never call a relationship overdue on your
  own authority.

## Order the work

Use the shipped helper, which owns the state file and the ordering:

```sh
SKILLS="$(confidant which --skills-dir)"
# First drop entries that left the cleared set (no-ai, retired, merged away).
"$SKILLS"/reconcile/bin/reconcile-state.py --vault "$CONFIDANT_VAULT" prune
"$SKILLS"/reconcile/bin/reconcile-state.py --vault "$CONFIDANT_VAULT" show --json
```

`show --json` emits `unverified` (a map keyed by id), not `open_unverified`.
`plan` (below) emits `open_unverified` — the same loose ends as a list, plus
every cleared unverified entry you also passed in, so a candidate list can
never hide one.

To order a candidate set, pass only opaque ids and the newest dates you saw:

```json
{"records": [
  {"id": "p-01M3TC5H00MPJG000000000101", "dates": ["2026-09-10", "2026-03"]},
  {"id": "p-01M3TC5H00MPJG000000000102", "dates": ["2026-10"]}
]}
```

```sh
"$SKILLS"/reconcile/bin/reconcile-state.py --vault "$CONFIDANT_VAULT" plan < candidates.json
```

`plan` returns three groups, in this order:

1. **changed** — a date you supplied is newer than `last_verified`.
   Something moved since the last pass.
2. **never-checked** — no state entry. The pass has not verified it.
3. **stalest** — verified before, but no newer evidence. Oldest
   verification first.

`open_unverified` lists every cleared record a previous pass could not
settle, including the ones you also passed in. Start there; they are the
loose ends, and a candidate list never hides one.

`skipped_uncleared` counts candidates the helper dropped because they are
not in the cleared set. It reports only the count, never the ids: an
uncleared record must not enter agent output.

If the helper is missing, sort by the same three rules by hand. Do not
change the order to make the pass feel productive.

`dates` may be `YYYY-MM-DD` or `YYYY-MM`; a month-only provenance date
compares as the first of that month (the conservative reading: a fact
sourced in the same month it was verified is not "changed").

## The state file

The helper keeps `<vault>/.confidant/reconcile-state.json`. It is local,
gitignored, rebuildable, and derived workflow state (ADR-6) — never a vault
file and never committed or synced. It holds opaque ids, dates, closed
reasons, and run counts only:

```json
{
  "schema_version": "1",
  "updated": "2026-11-07",
  "records": {
    "p-01M3TC5H00MPJG000000000101": {"last_verified": "2026-11-07"}
  },
  "unverified": {
    "p-01M3TC5H00MPJG000000000102": {"since": "2026-11-07", "reason": "no-answer"}
  },
  "runs": [
    {"date": "2026-11-07", "checked": 4, "proposed": 2, "applied": 1, "skipped": 2}
  ]
}
```

Reasons are closed: `no-answer`, `operator-declined`, `conflict`,
`out-of-scope`. There is no free-text field, so a name, email, or note
cannot end up in the state. The helper rejects anything that is not an
opaque id, a real date, or one of those reasons. It also refuses an id that
is not in the cleared set, so `no-ai`, retired, and merged-away ids cannot
enter.

Commands:

| Command | Effect |
|---|---|
| `show [--json]` | print the state; `--json` is the agent-readable form. It hides uncleared ids and reports only a count |
| `prune` | drop state entries that left the cleared set (no-ai, retired, merged away); run it first |
| `mark-verified ID [--date YYYY-MM-DD]` | the operator confirmed the record; also clears any unverified entry |
| `mark-unverified ID --reason REASON [--date ...]` | could not settle it; `since` keeps the first date it was left open |
| `clear-unverified ID` | drop one loose end |
| `forget ID` | drop a record (use after retirement) |
| `plan` | order candidates from stdin (above) |
| `record-run --checked N --proposed N --applied N [--skipped N]` | append this pass's counts; keeps the last 30 |

The helper refuses to write unless `.confidant/` is gitignored in the
vault. If it refuses, fix the vault's `.gitignore` with the operator; do
not move the state somewhere tracked.

## The pass, one record at a time

### 1. Build a candidate set

Collect, without sweeping the whole vault:

- every `id` in the `check` findings (cadence and date warnings are the
  built-in "re-confirm this" signals);
- every id key in the `unverified` object from `show --json` (`plan` repeats
  these in `open_unverified`);
- every record the operator named in this conversation (`resolve` the name
  first);
- records already in the state whose `last_verified` is older than their
  own cadence window.

Before touching any of them, keep only ids present in
`confidant allowlist --json`; that is the cleared set, and it is the only
visibility test. `context` is not that test: a `no-ai: true` person can
still return a minimal bundle (`entity.no_ai: true`, no name or profile),
while a retired or merged-away record has no bundle. Drop every id that is
not cleared — never guess why, never mention it to the operator, and never
write it to the state file. The helper enforces this too: `prune` removes
stale entries, `show` hides them, `plan` drops them and reports
`skipped_uncleared`, and `mark-verified` / `mark-unverified` refuse an
uncleared id.

Then `context` each cleared candidate once for its evidence.

### 2. Order and bound

Run `plan`. Offer at most **five records** in one pass; if more qualify,
stop and ask whether to continue now or come back tomorrow. A pass that
proposes twenty changes is a bulk edit wearing a conversation, and the
operator cannot review it.

### 3. Show the evidence, then one structured choice

For one record, state what the vault claims, in plain English, with the date
that supports it. Then ask a single choice:

> **Recommended — Still accurate; mark it verified.** The last touch is
> recent and nothing contradicts the profile.
> [Still accurate] [Something changed] [This page should not exist]
> [Skip for now]

- **Still accurate** — no change. `mark-verified`.
- **Something changed** — ask what changed, in their words. Then go to step
  4.
- **This page should not exist** — a duplicate, test data, or someone who
  asked to be forgotten. Go to step 4's retirement path.
- **Skip for now** — `mark-unverified --reason no-answer` (or
  `operator-declined` if they said no). Do not retry it in this pass.

The recommendation is always tied to this record's evidence, never to a
feature list.

### 4. Turn the answer into the smallest correction

| What is stale | The write | Why |
|---|---|---|
| A ledger line (a touch, an interaction, a note reference) is wrong, duplicated, or attributed to the wrong person | `confidant retract <subject-id> --line <ref> --reason <reason>` | the ledger is append-only; a retraction is a new, attributed fact |
| The whole page should not exist (duplicate, test data, a person who asked to be forgotten) | `confidant record retire <id>` | keeps the file and history, removes it from agent reads |
| A profile field (title, company, provenance) is out of date | **Not a retraction.** Propose the operator's normal `record edit` (or a note) as a separate write | the pass has no front-matter retraction, and `record retire` is not a field edit |

For a ledger line, `confidant find <term> --json` returns the line's `ref`
(for example `line:<64 hex>`). Use exactly that ref. Closed reasons for
`retract`: `duplicate`, `wrong-date`, `wrong-kind`, `wrong-person`,
`wrong-amount`, `wrong-note`, `wrong-record`, `typo`, `other`.

Never propose a retirement for "we have not spoken in a while"; that is what
a cadence conversation is for, and the operator may want the page to stay
quiet. Never propose a retraction for a fact the operator merely wants to
update: if there is a replacement, say so and use the normal correction
flow, not a bare retraction.

### 5. Dry run → confirm → apply

Show the dry run's logical change, not a wall of flags:

```sh
confidant retract p-01M3TC5H00MPJG000000000101 \
  --line line:0000000000000000000000000000000000000000000000000000000000000000 \
  --reason wrong-date --dry-run --json --no-input
confidant record retire p-01M3TC5H00MPJG000000000102 \
  --dry-run --json --no-input
```

Then ask for that one change. On an explicit yes, rerun the same command
without `--dry-run`. One commit per logical change: do not chain two
retractions into one confirmation, and do not add an unrelated `log` or
`note` to the same batch.

After the write, run `confidant check --json --no-input` and report the
result. If the write is refused, bring the error to the operator; do not
edit files around it.

### 6. Record what happened

- Confirmed accurate, or corrected and applied → `mark-verified ID --date
  <today>`.
- Could not verify, or the operator deferred → `mark-unverified ID --reason
  <closed reason>`.
- Retired → `forget ID`.
- Profile fact needs an edit the operator has not applied yet →
  `mark-unverified ID --reason out-of-scope`; do not record it as verified.

Finish with `record-run`. The next pass starts from this file, not from
memory.

### 7. Report the pass in outcomes

Say what is now true: how many records were re-confirmed, what was
corrected (by plain description, not by opaque id), what is still open, and
the one next step. A pass that changed nothing is a good result when the
evidence supports it — say "nothing looked stale" rather than inventing
work.

## Safety and privacy

- **Uncleared fails closed.** Visibility is `confidant allowlist --json`,
  not whether `context` returns an error. A `no-ai: true` person can return a
  minimal bundle; a retired or merged-away record may return none. Either
  way, an id outside the cleared set is out of the pass: do not name it, do
  not discuss its metadata, and do not put its id in the state file.
  `prune`, `show`, `plan`, and the `mark-*` commands enforce the same rule;
  never work around them with another command.
- **State is local.** Never commit, sync, or copy
  `.confidant/reconcile-state.json`. It is derived and rebuildable; deleting
  it costs a re-verification, not data.
- **Paths are opaque.** A record path is an id, not a name; do not build a
  name from a path or a filename.
- **One confirmation, one change.** A yes to "review the next record" is
  not a yes to retract it.
- **The operator is the ground truth.** The vault records what was reported
  when it was written. If the operator says it changed, they are right and
  the record is what needs fixing.

## Operating rules

1. Never run a write without `--dry-run` first, and never apply without an
   explicit yes to that dry run.
2. Never use `retract`'s bulk selectors in this pass; one `--line` ref per
   change.
3. Never retire to tidy up. Retirement is for a page that should not exist
   in agent reads.
4. Never record a verification you did not actually get from the operator.
5. Never let the state file grow names, notes, or free text. If a helper
   command rejects an id, fix the caller, not the validation.
6. Never report a pass as complete while an `open_unverified` entry is still
   open without saying so.
7. Keep the `confidant` skill's register: plain English, one structured
   choice at a time, and the operator's own bar over any default.
