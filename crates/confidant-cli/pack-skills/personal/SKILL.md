---
name: "personal"
description: "Personal relationships, places, and things pack (personal@0.4): identity and contact fields, the one-line relationship context, role/company history, typed alias history, the touch ledger verb with optional duration and 1:1/group mode, birthdays/dates, keep-in-touch cadence with basis, mode note, never/snooze, place/thing records with kind and address, relationship/place/thing edge kinds, the capture policy for what belongs in the vault, and every finding code the pack can emit — what each means and what to do about it."
---

# personal@0.4

## What this pack adds

`personal@0.4` is the 0.4 default personal pack. It keeps the 0.2 person
schema, the 0.3 places and things, and adds cadence semantics and richer
touches, so the vault can hold **people you know, places that matter, things
you're working on or care about, and the moments that connect them.**

- People stay core `person` records; the pack owns optional fields on them
  (identity, contact details, relationship, birthdays, dates, keep-in-touch
  cadence and its basis), the `touch` ledger verb, relationship edge kinds,
  and two warning-level rules.
- A touch can carry an optional `duration:` and `mode:` (1:1 vs group), so a
  60-minute session and a birthday party are facts on the line rather than
  prose in a note.
- The person record can answer "how do I know them" directly:
  `relationship_context` (the one-line story), `role_history` (the
  role/company timeline), and `alias_history` (typed aliases with a
  current/historical marker and a source).
- Enriched facts carry provenance (`profile_provenance`: key, source, and
  month; the newest entry per fact wins), and the profile body separates
  agent-written paragraphs from the operator's own words
  (`human_note`).
- `place` (`pl`, `places/`) and `thing` (`th`, `things/`) are pack-declared
  entities with required `name` and `kind`, optional `address`/`tags`/`links`,
  and their own edges. They are not person-like: no aliases, cadence, or
  touchpoints.
- It works alongside any external pack in one vault; each pack's data scopes
  independently (#178).

**Spec 0.4:** `personal@0.4` is active only in a 0.4 vault. Vaults on spec
0.1–0.3 keep the frozen `personal@0.2`, which is person-only and declares no
record types; `personal@0.3` is frozen and no spec selects it. The vault
`spec` selects the active built-in version; a `personal@…` listing does not
choose a version.

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
| `relationship` | non-empty string | How the person relates to the operator as a category (for example `friend`, `investor`). Renamed from 0.1's `relationship_to_me`. |
| `relationship_context` | non-empty string | The one-line story of how you know them ("I'm an investor in her company"). Distinct from the category; private context. |
| `role_history` | `PERIOD\|ROLE\|COMPANY[\|SOURCE]` list | The role/company timeline. `title`/`company` stay the current values. Private context. |
| `alias_history` | `KIND\|VALUE\|STATUS[\|SOURCE]` list | Typed aliases with kind, current/historical, and source. The plain contact lists stay the current values. Private context. |
| `profile_provenance` | `KEY\|SOURCE\|DATE` list | Where each enriched profile fact came from and when (`YYYY-MM`). The newest entry per key wins. Private context. |
| `human_note` | non-empty string | The operator's own words about the person. Agents never edit it. Private context. |
| `cadence` | `<N>d` or `never` | Keep-in-touch interval; `N` is `1..=3650`. `never` is the explicit "none, by design": never overdue, distinct from unset. |
| `cadence_basis` | non-empty string | Why this cadence: `observed` (a rhythm derived from touch history) or `intention` (the rhythm the operator wants). Open vocabulary. |
| `cadence_note` | non-empty string | The mode the cadence was set for, and why it changed. Free text; private context. |
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

### Relationship context vs relationship (#742)

`relationship` is the **category**: one noun for how the person relates to
the operator (`friend`, `mentor`, `investor`, `former manager`).
`relationship_context` is the **story**: one line that answers "how do I
know them" for someone reading the record cold. Keep the category short and
stable; let the story carry the specifics. Capture asks the story once when
the person is added, and enrichment updates that field instead of rewriting
the profile body.

### Role and company history (#740)

`title` and `company` are the current values. `role_history` is the
timeline, one pipe-separated chapter per entry:

```
role_history: [2019-2021|Product manager|Example Co|linkedin-export, 2021-|Founder|Example Studio]
```

`PERIOD|ROLE|COMPANY[|SOURCE]`: the period is `YYYY-YYYY` or `YYYY-` for a
chapter still open; role and company are free text without `|`; source is
optional. Append a chapter when the person changes role or company instead
of replacing the old one, and update `title`/`company` to match. A bad year,
an end before the start, a missing field, or a duplicate is
`E_FRONTMATTER`.

### Typed aliases (#739)

`emails`, `phones`, and `links` remain the plain current values.
`alias_history` adds the typed ledger:

```
alias_history: [email|ada@example.test|current|email-signature, email|ada@old.example.test|historical|linkedin-export]
```

`KIND|VALUE|STATUS[|SOURCE]`: kind is `email`, `phone`, `handle`, or `name`;
status is `current` or `historical`; source is optional. Use `historical` for
a value kept for archaeology and `current` when you know the provenance of a
live value. `alias resolve` matches both the plain values and the typed
entries by kind and **prefers current over historical**, so an old address
never shadows the live one. A malformed entry is `E_FRONTMATTER` and
matches nothing.

### Profile provenance (#738)

Every enriched fact should be able to say where it came from and when:

```
profile_provenance: [title|linkedin-export|2026-03, company|linkedin-export|2026-03, profile|linkedin-export|2026-03]
```

Entries are `KEY|SOURCE|DATE`: the fact (`profile` for the body, or a field
name), the source label (`linkedin-export`, `operator`, …), and `YYYY-MM`.
A repeated key records a newer chapter; **the newest date wins** in
`context`, so a stale import never shadows fresher enrichment. Keep one
entry per fact per month (two entries for the same key and date are
`E_FRONTMATTER`), and update the entry whenever you update the fact. The
grammar validates key shape, not that the key names a known fact; a typo is
inert, so copy the field names exactly.

### Profile authorship (#751)

The profile body is **yours to maintain**; it is not the operator's diary.
Write every agent-authored paragraph with a dated marker:

```
Enrichment, 2026-10: Met at Example Conf; two events together since.
```

The marker stays in the body, so it survives `record edit` replacing the
file. A paragraph without a marker is the operator's (or legacy import) text:
**preserve it verbatim**; do not rewrite, reorder, or delete it. The
operator's own words belong in `human_note`, which you never edit. When you
rewrite the summary, also update the `profile` entry in
`profile_provenance` with your source and the current month.

### Cadence semantics (#750)

A cadence is a claim about the future, so record where it came from:

- `cadence_basis: observed` means the interval describes a rhythm you can
  see in the touch history. `cadence_basis: intention` means it is the
  rhythm you want, which may differ from the observed one. `context` shows
  the basis next to the cadence for a cleared person.
- `cadence_note` records the mode the cadence was set for. When the
  relationship changes shape (frequent 1:1s become occasional updates),
  update the note and the cadence together instead of silently keeping a
  window that no longer describes the relationship.
- `cadence: never` is the explicit "none, by design" state. `context` marks
  it with `cadence_never: true`, and `W_CADENCE_OVERDUE` never fires. An
  unset `cadence` means no cadence has been chosen; the two are different
  states and only one of them is an oversight. Pair `never` with
  `cadence_basis: intention` to make the intent explicit.

A cadence set to a number that flags the person on day one is usually the
wrong number, not a neglected relationship. If the mode changed, revisit the
cadence or set `never` deliberately.

## Edge kinds

Core ships `married`, `introduced`, and `colleague`. `personal@0.4` adds:

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
DATE touch PERSON-ID call|text|email|meet|meal|event|gift|video|other [note:NOTE-ID] [src:PROVENANCE] [duration:<N>m] [mode:one-on-one|group]
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

Optional richness (#741), both independent of the kind:

- `duration:<N>m` — how long the touch lasted (`duration:60m`; `1h` and
  `1h30m` are accepted and normalized to minutes). At least one minute.
- `mode:one-on-one|group` — a 1:1 or a gathering. This is what lets a
  days-since-touch read tell a birthday party from a coffee catch-up.

Record what you know and omit the rest: a rough duration beats a guess, and
a missing mode is better than a wrong one. Neither pair changes
`W_CADENCE_OVERDUE`, and neither distinguishes two touches for idempotency.

### `confidant log touch`

```
confidant log touch <person> <kind> [--note <text>] [--date YYYY-MM-DD] [--src <token>] [--duration <N>m] [--mode one-on-one|group]
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
   nothing inferred) together with the touch entry, in one approval. A
   meeting with a body (agenda, minutes, decisions) is an interaction
   instead; it mirrors the touch automatically.
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

### Touch or interaction?

**A contact earns an interaction when there is a body worth reading later.
Without a body it is a touch.** The full rationale and examples are in
`docs/touch-vs-interaction.md`; this is the rule to apply.

| Source material | Write |
|---|---|
| 1:1 coaching session, call, coffee | `log touch` (`meet`/`video`/`meal`, `--duration`, `--mode one-on-one`) |
| Session/meeting with notes, agenda, or decisions | interaction; it mirrors the touch for every participant |
| Substantive 1:1 email thread with decisions or context worth rereading | interaction (mirrors the touch). A short thread of contact only is `log touch … email --mode one-on-one` |
| Bulk investor update | note, never a touch |
| Group social (game night, reunion) with no body | `log touch … event --mode group` (add `--duration` if known) |
| Multi-person event with a body | interaction; every participant gets a mirrored touch |
| Profile fact (role, relationship context, preferences) | the profile field or a note, never a touch |

- **Never hand-log a touch for an interaction.** `record add` already mirrors
  one per participant; adding another splits the moment and double-counts
  contact.
- **The medium does not decide; substance does.** A call with a decision is
  an interaction; a long email that only says hello is a touch.
- **`mode:` is the group mechanism.** A gathering that still counts as
  contact with the person is a touch with `mode:group`, so it never reads as
  a 1:1. `duration:` records how long it ran.
- **`context` shows both** in one date-ordered `timeline`, so a reader never
  has to know which store a moment landed in.

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
missing kind, an unexpected argument, more than one `kind:` pair, or a
`duration:` / `mode:` value outside its grammar. (Core code, emitted by
`check`.)

**Do:** rewrite the line as
`DATE touch PERSON-ID <kind> [note:NOTE-ID] [src:…] [duration:<N>m] [mode:one-on-one|group]`
with a kind from
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
when `cadence: never` ("none, by design"), and while `snooze_until` is later
than `as_of` (the person is eligible again on the snooze date; a past date
has no effect). `cadence_basis` and `cadence_note` do not change the answer.

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
- **Address, the cadence note, the person story, and provenance are
  private.** `context --exclude-private` strips `address`, `tags`, `links`,
  `cadence_note`, `relationship_context`, `role_history`, `alias_history`,
  `human_note`, and `profile_provenance`; `kind`, `cadence_basis`, and the
  derived cadence state stay. The same fields are hidden from agents by
  `no-ai` (deny-by-default), and they never appear in the plain
  `context.aliases` array.
- **Scope pack reads.** `--packs personal@0.4` limits reads to core and
  personal-owned items in a 0.4 vault; `personal@0.3` and `personal@0.2`
  remain no-op aliases.
  Personal fields, `touch` lines, and personal edge kinds appear only when
  the pack is in scope (#178).
- **The ledger line is plaintext.** A `touch` line carries only the date, the
  verb, the person's own ID, a kind from the closed list, and an optional
  duration and mode — no other participant, no prose. Detail that does not
  fit the line goes in a note via `--note`; every record, notes included, is
  plaintext on disk.
- **Fake data only.** Never place real names, emails, phone numbers, places,
  things, or notes in tests, fixtures, docs, or examples. Use `Ada Example`,
  `Bea Demo`, `Example Studio`, `Example Bicycle`, and fake ULIDs.
