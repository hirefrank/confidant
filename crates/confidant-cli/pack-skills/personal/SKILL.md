---
name: "personal"
description: "Personal relationships pack (personal@0.1): touch ledger verb, birthdays/dates, keep-in-touch cadence, relationship edge kinds, and every finding code the pack can emit — what each means and what to do about it."
---

# personal@0.1

## What this pack adds

`personal@0.1` turns Confidant toward personal relationships without adding
a second record type. People stay core `person` records; the pack owns four
optional fields on them, a `touch` ledger verb for lightweight contact,
relationship edge kinds, and two warning-level rules (keep-in-touch cadence,
upcoming dates). It works alongside `coaching@0.1` in one vault — a coaching
client can also be a friend, and each pack's data scopes independently
(#178).

The pack is declared in `confidant.toml`:

```toml
packs = ["coaching@0.1", "personal@0.1"]
```

Without this pack, personal fields are unattributed, the personal edge kinds
are unknown, and the cadence/date rules do not run. A `touch` line stays a
valid core mirror touchpoint either way; the pack owns its richer form.

## Fields

All four are optional, on `person` records only, and use flat names.

- `birthday`: `YYYY-MM-DD` or `--MM-DD`. The `--MM-DD` form is year-less.
- `cadence`: `<N>d`, a keep-in-touch interval. `N` is a positive integer
  `1..=3650` (for example `30d`, `90d`).
- `relationship_to_me`: optional non-empty string (for example `friend`,
  `sibling`, `mentor`, `family`).
- `dates`: other recurring dates, comma-separated `LABEL:DATE` entries,
  bare or in one bracketed list:

  ```
  dates: anniversary:2020-06-15, graduation:--05-20
  dates: [anniversary:2020-06-15, graduation:--05-20]
  ```

  `LABEL` matches `[a-zA-Z0-9_-]+`; `DATE` is `YYYY-MM-DD` or `--MM-DD`.

Malformed values are `E_FRONTMATTER` (see Findings).

## Edge kinds

Core ships `married`, `introduced`, and `colleague`. `personal@0.1` adds:

- Symmetric: `friend`, `family`, `sibling`, `partner`.
- Directed: `parent` (`a` is the parent of `b`), `mentor` (`a` mentors
  `b`).

A symmetric kind must not appear twice for the same unordered pair. An edge
carries no body and no `no-ai`.

## Verbs

### `touch`

```
DATE touch PERSON-ID call|text|coffee|gift|meet [note:NOTE-ID] [src:PROVENANCE]
```

Records one touchpoint — call, text, coffee, gift, or meet — on a date. The
kind is a closed list; only those five values are accepted. The pack also
accepts the core mirrored shape:

```
DATE touch PERSON-ID [kind:call|text|coffee|gift|meet]
```

Rich, multi-person events stay in core `interaction` records. Optional
`note:NOTE-ID` must name a note that belongs to the touched person (after
merge canonicalization). Optional `src:PROVENANCE` dedupes re-imported
lines.

### `confidant log touch`

```
confidant log touch <person> <kind> [--note <text>] [--date YYYY-MM-DD] [--src <token>] [--fallback-inbox]
```

Writes one `touch` ledger line in one commit. `--note <text>` creates and
links an encrypted note; `--fallback-inbox` queues that note to the `inbox`
branch when the keychain fails, instead of failing closed (#213). Every
command takes `--json` and `--no-input` (ADR-7); branch on the error `code`,
never on message text.

## Configuration ([checks] keys)

- `personal.cadence_overdue`: `"warning"` (default), `"error"`, or `"off"`.
- `personal.date_upcoming`: `"warning"` (default), `"error"`, or `"off"`.
- `personal.date_upcoming_days`: look-ahead window in days, default `7`,
  cap `3650`.

Both rules are warnings by default and never block writes, commits, or
inbox merges. `--as-of YYYY-MM-DD` overrides `[checks].as_of`; with neither,
the rules use today's UTC date.

## Findings

Every code this pack can emit. Branch on `code`, never on message text.

### `E_TOUCH_MALFORMED`

A `touch` line does not match either accepted shape: an unknown kind, a
missing kind, an unexpected argument, or more than one `kind:` pair.

**Do:** rewrite the line as
`DATE touch PERSON-ID <kind> [note:NOTE-ID] [src:…]` with a kind from
`call`, `text`, `coffee`, `gift`, `meet`. Use `interaction` for anything
richer. No write is blocked by a warning, but this one is an error — the
line is unusable until fixed.

### `E_INVALID_ID`

A `touch` subject, a `note:` value, or a front-matter field that should hold
an ID is not `prefix-ULID`. Also fires on a malformed ID-shaped token in
front matter.

**Do:** use the record's real opaque ID (`p-…`, `n-…`). Never invent or
shorten a ULID, and never put a display name where an ID belongs. Messages
never echo the bad token — compare against the record's `id:` line.

### `E_WRONG_ID_TYPE`

The `touch` subject is not a `p-` person ID, or a `note:` names a record
that is not a note.

**Do:** point `touch` at a `p-…` person and `note:` at an `n-…` note. A
merge that folds one record type into another is this code too and is not
applied.

### `E_UNKNOWN_RECORD`

A `touch` names a well-formed `p-` ID with no record file, `note:` names a
note that does not exist, or `note:` names a note that belongs to a
different person than the touched one.

**Do:** create the missing person or note first, or correct the ID. When
linking a note, confirm it lives under the touched person (after merge
canonicalization) — a note for another person is not a valid link.

### `E_FRONTMATTER`

A personal field is malformed: `birthday` is neither `YYYY-MM-DD` nor
`--MM-DD`; `cadence` is not `<N>d` with `N` in `1..=3650`; an empty
`relationship_to_me`; a `dates` entry with a bad label, a missing `:`, or a
bad date. Also fires for any core front-matter problem (missing/duplicated
required keys, bad `no-ai`, an edge body).

**Do:** match the grammar in Fields. Messages never echo the raw value —
they name the key when it is a known spec key, otherwise give the line
number. Open the record's front matter and compare to the grammar.

### `W_CADENCE_OVERDUE`

A person with `cadence: <N>d` has no touchpoint on or after
`as_of - N days` (and on or before `as_of`). Touchpoints are `touch` lines,
coaching `session` lines (#227 Q2), and `interaction` records naming the
person (primary `person:` or `with:`), after merge canonicalization.

**Do:** reach out and record it — `confidant log touch <person> <kind>`
records the contact and clears the warning. If the cadence is wrong, edit
the person's `cadence:` field instead. Warning-level: it never blocks a
write.

### `W_DATE_UPCOMING`

A person's `birthday` or an entry in `dates` has its next occurrence within
`0..=personal.date_upcoming_days` days of `as_of`.

**Do:** surface the date to the operator (a birthday, an anniversary) so
they can act on it. This is a nudge, not a task — no vault change is
required, and it never blocks a write.

## Privacy notes

- **`no-ai` is honored.** `no-ai: true` keeps the person out of `find`,
  `context`, and agent output. `no-ai: notes` keeps the person visible —
  `relationship_to_me`, `cadence`, and upcoming dates reach agents — while
  their notes and interactions default to hidden (spec §13). An explicit
  `no-ai: false` on a child overrides the inherited default.
- **Scope pack reads.** `--packs personal@0.1` limits reads to core and
  personal-owned items, so a coaching-scoped agent never sees personal
  notes. Personal fields, `touch` lines, and personal edge kinds appear
  only when the pack is in scope (#178).
- **The ledger line is plaintext.** A `touch` line carries only the date,
  the verb, the person's own ID, and a kind from the closed list — no other
  participant, no prose. Sensitive detail goes in an encrypted note via
  `--note`.
- **Fake data only.** Never place real names, birthdays, or notes in tests,
  fixtures, docs, or examples. Use `Ada Example`, `Bea Demo`, and fake
  ULIDs.
