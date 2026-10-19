---
name: "personal"
description: "Personal relationships pack (personal@0.2): identity and contact fields, the touch ledger verb, birthdays/dates, keep-in-touch cadence with never/snooze, relationship edge kinds, and every finding code the pack can emit — what each means and what to do about it."
---

# personal@0.2

## What this pack adds

`personal@0.2` turns Confidant toward personal relationships without adding a
second record type. People stay core `person` records; the pack owns optional
fields on them (identity, contact details, relationship, birthdays, dates,
keep-in-touch cadence), the `touch` ledger verb, relationship edge kinds, and
two warning-level rules (keep-in-touch cadence, upcoming dates). It works
alongside `coaching@0.1` in one vault — a coaching client can also be a
friend, and each pack's data scopes independently (#178).

The pack is **implicit**: every vault has it, whether or not
`confidant.toml` lists it. A vault that lists `coaching@0.1` explicitly
looks like:

```toml
packs = ["coaching@0.1"]
```

`packs = []` still enables the personal pack. A `personal@…` entry in
`packs` is accepted as a no-op.

Personal fields are owned by the pack, the personal edge kinds are known, and
the cadence/date rules always run. A `touch` line is both a core mirror
touchpoint and the pack's richer form; the pack owns it.

**0.1 history.** This is the 0.2 contract. The compiled `personal@0.1` pack
(in place until the #551 cutover) kept the 0.1 field set: it named the
relationship field `relationship_to_me` and claimed only `birthday`,
`cadence`, `relationship_to_me`, and `dates`. It is gone; `personal@…`
listings are no-ops and `personal@0.2` is the only personal pack.

## Fields

All fields are optional, flat front-matter names on `person` records only
(ADR-2: no nested YAML). None is stored truth: facts stay in the ledger.

| Field | Grammar | Notes |
|---|---|---|
| `title` | non-empty string | Job title. Example: `Staff Engineer`. |
| `company` | non-empty string | Employer. Example: `Example Co`. |
| `location` | non-empty string | Free text; not geocoded. |
| `emails` | list | No syntax validation, no normalization. |
| `phones` | list | No parsing, no normalization. |
| `links` | labeled list | `LABEL:VALUE`; the value may contain `:`. |
| `tags` | list | Free-form; `/` expresses hierarchy, no tree enforcement. |
| `birthday` | `YYYY-MM-DD` or `--MM-DD` | The `--MM-DD` form is year-less. |
| `dates` | comma-separated `LABEL:DATE` | Other recurring dates (for example an anniversary). |
| `relationship` | non-empty string | How the person relates to the operator (for example `friend`). Renamed from 0.1's `relationship_to_me`. |
| `cadence` | `<N>d` or `never` | Keep-in-touch interval; `N` is `1..=3650`. `never` means never overdue. |
| `snooze_until` | `YYYY-MM-DD` | One-off date; suppresses the cadence nudge until then. |

A list value is comma-separated, optionally wrapped in one `[...]`. Entries
are whitespace-trimmed and non-empty; duplicates are rejected; a comma inside
an entry is not supported. A labeled-list entry splits at the **first** `:`;
`LABEL` matches `[a-zA-Z0-9_-]+`; the value is trimmed, non-empty, may contain
`:`, and rejects duplicates.

```
emails: [ada@example.com, ada2@example.com]
links: [linkedin:https://example.test/ada, site:https://example.test/a:b]
tags: [friend, work/finance]
dates: [anniversary:2020-06-15, graduation:--05-20]
```

A year-less `--MM-DD` birthday or date has no year, so its next occurrence is
the next `MM-DD` on or after `as_of`. A malformed value is `E_FRONTMATTER`.

## Edge kinds

Core ships `married`, `introduced`, and `colleague`. `personal@0.2` adds:

- Symmetric: `friend`, `family`, `sibling`, `partner`.
- Directed: `parent` (`a` is the parent of `b`), `mentor` (`a` mentors `b`).

A symmetric kind must not appear twice for the same unordered pair. An edge
carries no body and no `no-ai`.

## Verbs

### `touch`

```
DATE touch PERSON-ID call|text|email|meet|meal|event|gift|other [note:NOTE-ID] [src:PROVENANCE]
```

Records one touchpoint on a date. The kind is a closed list: `call`, `text`,
`email`, `meet`, `meal`, `event`, `gift`, `other`. (In 0.1 the list was
`call`, `text`, `coffee`, `gift`, `meet`; `coffee` was removed, not aliased —
use `meal`.) The pack also accepts the core mirrored shape:

```
DATE touch PERSON-ID [kind:call|text|email|meet|meal|event|gift|other]
```

Rich, multi-person events stay in core `interaction` records. Optional
`note:NOTE-ID` must name a note that belongs to the touched person (after
merge canonicalization). Optional `src:PROVENANCE` dedupes re-imported lines.

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

Both rules are warnings by default and never block writes, commits, or inbox
merges. `--as-of YYYY-MM-DD` overrides `[checks].as_of`; with neither, the
rules use today's UTC date.

## Findings

Every code this pack can emit. Branch on `code`, never on message text.

### `E_TOUCH_MALFORMED`

A `touch` line does not match either accepted shape: an unknown kind, a
missing kind, an unexpected argument, or more than one `kind:` pair. (Core
code, emitted by `check`.)

**Do:** rewrite the line as
`DATE touch PERSON-ID <kind> [note:NOTE-ID] [src:…]` with a kind from
`call`, `text`, `email`, `meet`, `meal`, `event`, `gift`, `other`. Use
`interaction` for anything richer.

### `E_INVALID_ID`

A `touch` subject, a `note:` value, or a front-matter field that should hold
an ID is not `prefix-ULID`. Also fires on a malformed ID-shaped token in front
matter.

**Do:** use the record's real opaque ID (`p-…`, `n-…`). Never invent or
shorten a ULID. Messages never echo the bad token.

### `E_WRONG_ID_TYPE`

The `touch` subject is not a `p-` person ID, or a `note:` names a record that
is not a note.

**Do:** point `touch` at a `p-…` person and `note:` at an `n-…` note.

### `E_UNKNOWN_RECORD`

A `touch` names a well-formed `p-` ID with no record file, `note:` names a
note that does not exist, or `note:` names a note that belongs to a different
person than the touched one.

**Do:** create the missing person or note first, or correct the ID. When
linking a note, confirm it lives under the touched person (after merge
canonicalization).

### `E_FRONTMATTER`

A personal field value does not match its declared grammar: for example an
empty `title`/`company`/`location`/`relationship`, a `links` entry with no
`:` or a duplicate label, a `list` entry that is empty or duplicated, a
`snooze_until` that is not one strict `YYYY-MM-DD`, a `birthday` or `dates`
value that is neither `YYYY-MM-DD` nor `--MM-DD`, or a `cadence` that is
neither `<N>d` with `N` in `1..=3650` nor the literal `never`. Also fires for
any core front-matter problem.

**Do:** match the grammar in Fields. Messages never echo the raw value — they
name the key when it is a known spec key, otherwise give the line number.

### `W_CADENCE_OVERDUE`

A person with `cadence: <N>d` has no touchpoint on or after
`as_of - N days` (and on or before `as_of`). Touchpoints are `touch` lines
and coaching `session` lines, after merge canonicalization. Skipped entirely
when `cadence: never`, and while `snooze_until` is later than `as_of` (the
person is eligible again on the snooze date; a past date has no effect).

**Do:** reach out and record it — `confidant log touch <person> <kind>`
records the contact and clears the warning. If the cadence is wrong, edit the
person's `cadence:` field instead. Warning-level: it never blocks a write.

### `W_DATE_UPCOMING`

A person's `birthday` or an entry in `dates` has its next occurrence within
`0..=personal.date_upcoming_days` days of `as_of`.

**Do:** surface the date to the operator (a birthday, an anniversary) so they
can act on it. This is a nudge, not a task, and it never blocks a write.

## Privacy notes

- **`no-ai` is honored.** `no-ai: true` hides the person's content from
  agents — names, profile fields, note and interaction text, and free
  text — and `find` returns none of it. `context` still serves their
  derived, ledger-based metadata: `cadence_days`, `cadence_never`,
  `last_touch`, `days_since_touch`, `overdue`, `recent_touches`, the
  declared `snooze_until`, the `touchpoints` list, and opaque `hmac:`
  alias hashes (spec §12). `no-ai: notes` keeps the person visible while
  their notes and interactions default to hidden (spec §13). An explicit
  `no-ai: false` on a child overrides the inherited default.
- **Scope pack reads.** `--packs personal@0.2` limits reads to core and
  personal-owned items. Personal fields, `touch` lines, and personal edge
  kinds appear only when the pack is in scope (#178).
- **The ledger line is plaintext.** A `touch` line carries only the date, the
  verb, the person's own ID, and a kind from the closed list — no other
  participant, no prose. Sensitive detail goes in an encrypted note via
  `--note`.
- **Fake data only.** Never place real names, emails, phone numbers, or notes
  in tests, fixtures, docs, or examples. Use `Ada Example`, `Bea Demo`, and
  fake ULIDs.
