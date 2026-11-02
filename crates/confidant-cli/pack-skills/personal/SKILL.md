---
name: "personal"
description: "Personal relationships, places, and things pack (personal@0.3): identity and contact fields, the touch ledger verb, birthdays/dates, keep-in-touch cadence with never/snooze, place/thing records with kind and address, relationship/place/thing edge kinds, the capture policy for what belongs in the vault, and every finding code the pack can emit — what each means and what to do about it."
---

# personal@0.3

## What this pack adds

`personal@0.3` is the 0.4 default personal pack. It keeps the 0.2 person
schema and adds two entity types, `place` and `thing`, so the vault can hold
**people you know, places that matter, things you're working on or care
about, and the moments that connect them.**

- People stay core `person` records; the pack owns optional fields on them
  (identity, contact details, relationship, birthdays, dates, keep-in-touch
  cadence), the `touch` ledger verb, relationship edge kinds, and two
  warning-level rules.
- `place` (`pl`, `places/`) and `thing` (`th`, `things/`) are pack-declared
  entities with required `name` and `kind`, optional `address`/`tags`/`links`,
  and their own edges. They are not person-like: no aliases, cadence, or
  touchpoints.
- It works alongside any external pack in one vault; each pack's data scopes
  independently (#178).

**Spec 0.4:** `personal@0.3` is active only in a 0.4 vault. Vaults on spec
0.1–0.3 keep the frozen `personal@0.2`, which is person-only and declares no
record types. The vault `spec` selects the active built-in version; a
`personal@…` listing does not choose a version.

The pack is **implicit**: every 0.4 vault has it, whether or not
`confidant.toml` lists it. A vault that lists an external pack explicitly
looks like:

```toml
packs = ["example-pack@0.1"]
```

`packs = []` still enables the personal pack. A `personal@…` entry in
`packs` is accepted as a no-op.

**0.2 history.** `personal@0.2` kept the person-only default for spec 0.1–0.3.
Its breaking changes from 0.1 still apply: the relationship field is
`relationship` (not `relationship_to_me`), `cadence` accepts `never`, and the
touch-kind list drops `coffee` (use `meal`).

## Record types

A place or thing earns a record when another record needs to point at it,
when it has its own relationships, or when it needs a stable name in the
roster. Otherwise it stays a note.

| Type | Prefix | Collection | Required | Optional |
|---|---|---|---|---|
| `place` | `pl` | `places/` | `name`, `kind` | `address`, `tags`, `links` |
| `thing` | `th` | `things/` | `name`, `kind` | `tags`, `links` |

Suggested `kind` values: for a place, `home`, `work`, `venue`,
`neighborhood`, `city`, `other`; for a thing, `project`, `object`, `work`,
`idea`, `vehicle`, `book`, `tool`, `other`. A company is an `org`, not a
thing. A one-off event is an `interaction` or a note.

Use a note instead when the fact is dated, sensitive, or owned by exactly one
person/place and never referenced elsewhere. A note carries its own date and
`no-ai`, so it does not bypass note-level privacy. There is no `notes:` or
`serial:` field.

## Fields

Person fields are optional flat front-matter names on `person` records.
`place` and `thing` require `name` and `kind`; their other fields are
optional. Fields are not nested YAML (ADR-2). None is stored truth: facts
stay in the ledger.

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
| `kind` | non-empty string | Primary noun for a place or thing. Required on both types. |
| `address` | non-empty string | Free-text place address; private context, never geocoded. |

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

Core ships `married`, `introduced`, and `colleague`. `personal@0.3` adds:

- Symmetric: `friend`, `family`, `sibling`, `partner`.
- Directed: `parent` (`a` is the parent of `b`), `mentor` (`a` mentors `b`).
- Directed place/thing kinds:

| Kind | `a` | `b` | Meaning |
|---|---|---|---|
| `visited` | `person` | `place` | Durable "has been to". |
| `lives_at` | `person` | `place` | Residence; `since` / `until`. |
| `owns` | `person` | `thing` | Ownership; `since` / `until`. |
| `located_at` | `thing` | `place` | Physical location; `since` / `until`. |

`visited` is durable: a second visit is not a second edge; the same ordered
pair is `E_DUPLICATE_EDGE`. Individual visits are interactions or notes
attached to the place. `located_at` is only for physical things. A symmetric
kind must not appear twice for the same unordered pair. An edge carries no
body; edge-level `no-ai` hides the relation while both endpoints stay
visible.

## Verbs

### `touch`

```
DATE touch PERSON-ID call|text|email|meet|meal|event|gift|video|other [note:NOTE-ID] [src:PROVENANCE]
```

Records one touchpoint on a date. The kind is a closed list: `call`, `text`,
`email`, `meet`, `meal`, `event`, `gift`, `video`, `other`. (In 0.1 the list was
`call`, `text`, `coffee`, `gift`, `meet`; `coffee` was removed, not aliased —
use `meal`.) The pack also accepts the core mirrored shape:

```
DATE touch PERSON-ID [kind:call|text|email|meet|meal|event|gift|video|other]
```

Rich, multi-person events stay in core `interaction` records. Optional
`note:NOTE-ID` must name a note that belongs to the touched person (after
merge canonicalization). Optional `src:PROVENANCE` dedupes re-imported lines.

### `confidant log touch`

```
confidant log touch <person> <kind> [--note <text>] [--date YYYY-MM-DD] [--src <token>]
```

Writes one `touch` ledger line in one commit. `--note <text>` creates and
links a plaintext note record under that person, in the same commit. Every
command takes `--json` and `--no-input` (ADR-7); branch on the error `code`,
never on message text.

## Who belongs in the vault

An agent keeping a vault current sweeps the operator's calendar and email
and constantly meets people who are *not in the vault*. Who gets added is
policy, and policy that lives only in one agent's memory dies with that
agent. This section is the standing policy (#728). It lives here, in the
skill that owns the `touch` verb, until the meta skill (#724) exists; when
that skill lands, this section moves there.

1. **Meeting/call contact qualifies immediately.** If the operator is
   meeting with someone — a meeting or a call — that person belongs in the
   vault. Propose a minimal, factual record (name + what the sources show,
   nothing inferred) together with the touch entry, in one approval.
2. **Email-only contact must cross a threshold.** Not everyone who emails
   the operator belongs in their relationship memory: cold outreach,
   one-off threads, and scheduling mail must not mint records. Count
   "exchange days": a day with a substantive human thread.
   Automated, booking, and newsletter mail never counts. A person
   qualifies when either of these holds in a 30-day window:
   - at least 3 exchange days in 30 days; or
   - the operator replies substantively on at least 2 separate days in
     30 days.
   Below threshold, track silently and say nothing — no drip of "should I
   add…?" questions. This guidance names no store for those
   below-threshold counts — there is no record yet to hold them — so do
   not improvise a side list or ledger for them.
3. **Operator overrides, both directions.** "Add X" qualifies instantly at
   any time; "never track X" excludes permanently. Either override beats
   rules 1–2 in either direction: "never track X" excludes even on
   meeting/call contact, and "add X" qualifies even below the email
   threshold. "Never track" here is distinct from `cadence: never`
   (Fields): the latter means "never overdue" for a person already in
   the vault and keeps the record; "never track" means no record at all.
4. **Approval discipline unchanged.** Crossing a threshold earns a
   *proposal*, not a write: propose → confirm → apply, every time.

Scope: this section classifies only meeting/call contact (rule 1) and
email-only contact (rule 2). It does not classify the other `touch`
kinds — `text`, `meal`, `event`, `gift`, `other` — and it does not say
whether a meal or event counts as a meeting for rule 1. For those
kinds, fall back to operator judgment; do not extend rules 1–2 to
them by analogy.

The threshold numbers above are defaults the operator can tune; the shape
is the guidance: meetings in, email earned, silent below threshold,
overrides both ways.

### Places and things

Use the same proposal discipline: propose, confirm, apply. Promote a place or
thing only when another record needs to point at it, when it has its own
relationships, or when it needs a stable name in the roster. A one-off fact
stays a note. Give every place/thing one primary `kind`; put cross-cutting
labels in `tags`. A company is an `org`; a one-off event is an `interaction`
or a note. Do not create a `thing` for every object mentioned in passing.

## Configuration ([checks] keys)

- `personal.cadence_overdue`: `"warning"` (default), `"error"`, or `"off"`.
- `personal.date_upcoming`: `"warning"` (default), `"error"`, or `"off"`.
- `personal.date_upcoming_days`: look-ahead window in days, default `7`,
  cap `3650`.

Both rules are warnings by default and never block writes or commits.
`--as-of YYYY-MM-DD` overrides `[checks].as_of`; with neither, the
rules use today's UTC date.

## Findings

Every code this pack can emit. Branch on `code`, never on message text.

### `E_TOUCH_MALFORMED`

A `touch` line does not match either accepted shape: an unknown kind, a
missing kind, an unexpected argument, or more than one `kind:` pair. (Core
code, emitted by `check`.)

**Do:** rewrite the line as
`DATE touch PERSON-ID <kind> [note:NOTE-ID] [src:…]` with a kind from
`call`, `text`, `email`, `meet`, `meal`, `event`, `gift`, `video`, `other`. Use
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
and `session` lines, after merge canonicalization. Skipped entirely
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
  declared `snooze_until`, and the `touchpoints` list (spec §12). Contact
  aliases (`emails`, `phones`, `handles`) follow the same PII gate as the
  rest of the profile, so they are empty for an uncleared person.
  `no-ai: notes` keeps the person visible while their notes and
  interactions default to hidden (spec §13). An explicit `no-ai: false` on
  a child overrides the inherited default.
- **Places and things are `no_ai: "full"` only.** `no-ai: true` hides the
  place/thing and every edge touching it; `no-ai: false` keeps it visible.
  There is no `no_ai: notes` mode for them. An uncleared place or thing
  returns no agent `context` bundle at all, not an empty one. The operator
  path still sees it with the badge.
- **Address is private.** `context --exclude-private` strips `address`,
  `tags`, and `links`; `kind` stays as the type marker.
- **Scope pack reads.** `--packs personal@0.3` limits reads to core and
  personal-owned items in a 0.4 vault; `personal@0.2` remains a no-op alias.
  Personal fields, `touch` lines, and personal edge kinds appear only when
  the pack is in scope (#178).
- **The ledger line is plaintext.** A `touch` line carries only the date, the
  verb, the person's own ID, and a kind from the closed list — no other
  participant, no prose. Detail that does not fit the line goes in a note
  via `--note`; every record, notes included, is plaintext on disk.
- **Fake data only.** Never place real names, emails, phone numbers, places,
  things, or notes in tests, fixtures, docs, or examples. Use `Ada Example`,
  `Bea Demo`, `Example Studio`, `Example Bicycle`, and fake ULIDs.
