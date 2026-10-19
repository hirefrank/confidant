# Pack manifest format spec

*Part of #295 (narrow pack manifest, approved by Frank 2026-10-14). Spec PR for #340; steps 2–7 implement it.*

This spec describes the **pack manifest**: a data file holding a schema
pack's *claims only*. The pack retrospective
(`docs/research/pack-retro.md`, §4) showed the claims are declarative
today in every sense except that they live in Rust as `&'static` slices
and string literals. The manifest moves them to data with no behaviour
change. The reducers and date math (`fold`, `findings`, balance math,
cadence windows, recurring-date math) stay compiled behind the `Pack`
trait — they are exactly the part the two packs do not share.

## 1. What the manifest holds (and what it does not)

**In the manifest (claims):**

- pack name and version
- verbs
- record types
- front-matter fields and their grammars (named, from a fixed list)
- balance metrics
- edge kinds and symmetry
- finding codes
- verb-to-ID type
- `[checks]` keys and defaults
- skill text (by reference)
- finding message and fix templates

**Not in the manifest (stays in Rust):**

- `fold`, `findings`, `check_balance`, `context_view`
- field grammar *parsers* (the manifest names a grammar; Rust supplies
  the parser)
- verb argument validation (`validate_verb_args`, `verb_kind`;
  e.g. the `touch` kind list)
- PII field handling (`private_context_fields`)
- message *variant selection* (see §7: where today's Rust picks between
  message variants, the manifest holds the text of each variant and Rust
  picks — the manifest never branches)
- the merge-aware fold skeleton

If a future manifest draft starts describing logic (conditionals, loops,
arithmetic), it has crossed the boundary: stop and re-scope.

## 2. File name and location

One manifest per pack, at:

```
packs/<name>/manifest.toml
```

alongside the pack's `SKILL.md` and `<version>.md` contract file
(e.g. `packs/personal/manifest.toml`). Keeping the whole pack in one
directory is what #193 (packs live outside the core) needs: the
directory becomes the shippable unit.

## 3. Format: TOML

**Recommendation: TOML.**

- The repo already speaks TOML: `confidant.toml` is the vault config,
  and the `toml` crate is in the dependency tree.
- TOML's tables and arrays-of-tables map cleanly onto the schema
  (verbs, fields, edge kinds, messages).
- It is human-readable and diff-friendly, which matters because pack
  authors edit it by hand and reviewers read the diff.
- JSON was considered and rejected: no comments, noisier for
  hand-authored text with templates.

## 4. Schema

All keys are required unless marked optional. Unknown keys are an
error (strict parsing; the loader rejects what it does not know, so a
typo fails loudly rather than silently doing nothing).

```toml
# Schema version of this file, not the pack version. A reader that does
# not implement this version fails rather than guessing (cf. spec/0.1.md).
manifest_version = 1

# Top-level keys come before the first [table] header: in TOML anything
# after a table header belongs to that table.
# Record types this pack owns (empty for both packs today).
record_types = []

# Balance metrics this pack's fold computes (empty for personal today;
# see "Balance metrics" below for the element schema).
balance_metrics = []

# Finding codes this pack's fold/findings can emit. Must match the
# [messages] keys exactly (see §7 for the templates, §10 for the drift
# test). Real codes here so this skeleton parses as written.
finding_codes = ["E_FRONTMATTER", "W_CADENCE_OVERDUE"]

[pack]
name = "personal"
version = "0.1"
# Full pack name is "personal@<version>".

# Skill text is referenced, not duplicated: packs/<name>/SKILL.md is
# the single source of truth (see §8).
skill = "SKILL.md"

# Verbs this pack owns. `id_type` is the verb-to-ID-type claim
# (today's `verb_id_type`); omit it for verbs with no ID-type claim.
[[verbs]]
name = "touch"
id_type = "person"          # optional

# Front-matter fields this pack owns. `grammar` names one of the fixed
# grammars in §6; Rust supplies the parser for that name.
[[fields]]
name = "birthday"
grammar = "recurring-date"

# Edge kinds this pack introduces, with symmetry.
[[edge_kinds]]
name = "friend"
symmetric = true

# [checks] keys this pack owns, with defaults. `type` is "severity" or
# "int". Severity values are error|warning|off. These replace the
# hardcoded allowlists (config.rs KNOWN_SEVERITY_KEYS/KNOWN_INT_KEYS)
# and the defaults scattered at the call sites.
[checks]
[[checks.severity]]
key = "personal.cadence_overdue"
default = "warning"
[[checks.int]]
key = "personal.date_upcoming_days"
default = 7

# Finding message and fix templates, one table per code (§7).
[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."W_CADENCE_OVERDUE"]
last = "person {id} has no touchpoint on or after {start} (last was {d}, cadence {cadence_days}d)"
last_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
none = "person {id} has no touchpoint logged (cadence {cadence_days}d)"
none_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
```

### ID types

`id_type` names one of the record ID prefixes: `person`, `org`, `deal`,
`interaction`, `note`, `edge`, `package`. (Today's `Prefix` enum.)

### `[checks]` key namespacing

Keys are namespaced `<pack-name>.<rule>` (e.g.
`personal.cadence_overdue`), matching today's dotted keys. A pack may
only declare keys under its own name; the loader rejects others. The
`as_of` top-level key stays core-owned. A `[[checks.int]]` key's
`default` is a non-negative whole value (a window in days, a count);
the loader rejects a negative one.

### Balance metrics

`balance_metrics` is an array of metric-name strings — the metrics the
pack's compiled fold computes and `check_balance` verifies (today's
`Pack::balance_metrics`; e.g. coaching's `sessions_remaining` and
`icf_hours`, personal's empty list). Each name must be a non-empty,
unique string; the loader rejects duplicates. There is no separate
drift check: the fold stays compiled, so step 4's parity test pins the
manifest's list against the old slices, and the drift test only
asserts well-formedness.

## 5. Versioning

Two independent versions, mirroring the spec/CLI split (ADR-1):

- `manifest_version`: the schema version of this file. A reader that
  does not implement it fails with a config error rather than guessing.
  Bump only when the schema changes.
- `[pack].version`: the pack's own version (`personal@0.2`). Pack
  version bumps follow the pack's contract file (`packs/<name>/0.1.md`).

## 6. Field grammars: a fixed named list

The manifest **names** a grammar; Rust supplies the parser. This is a
fixed list of named parsers, not a grammar language (step 3 wires the
registry; the list itself is frozen by this spec):

| Name | Accepts | Today |
|---|---|---|
| `recurring-date` | `YYYY-MM-DD` or `--MM-DD` (year-less; `--02-30` rejected, `--02-29` valid) | `RecurringDate::parse` |
| `cadence` | `<N>d`, `1 <= N <= 3650` (e.g. `30d`), or the literal `never` | `parse_cadence` |
| `dates-list` | comma-separated `LABEL:DATE` entries, optionally wrapped in `[...]`; `LABEL` matches `[a-zA-Z0-9_-]+`, `DATE` is a `recurring-date` | `parse_dates_list` |
| `non-empty-string` | any non-empty string (whitespace-trimmed) | `relationship_to_me` check |
| `list` | comma-separated values, optionally wrapped in `[...]`; entries whitespace-trimmed, non-empty, and unique (no quoting, so a comma inside an entry is unsupported; `[]` is a valid empty list) | `parse_list` |
| `labeled-list` | comma-separated `LABEL:VALUE` entries, optionally wrapped in `[...]`; each entry splits at the **first** `:`; `LABEL` matches `[a-zA-Z0-9_-]+`; `VALUE` is whitespace-trimmed, non-empty, may contain `:` but not a newline; duplicate labels rejected | `parse_labeled_list` |
| `date` | one strict `YYYY-MM-DD` (a one-off date; `--MM-DD` is not accepted) | `parse_date` |

A field naming an unknown grammar is a load error. Adding a grammar is
a spec change to this list plus a Rust parser — never a manifest-only
change, so manifests cannot smuggle in new validation semantics.

Out of scope on purpose: verb *argument* grammars (e.g. the `touch`
kind list) stay in `validate_verb_args`/`verb_kind`. They describe
ledger-line shapes, not front-matter fields.

## 7. Finding message templates

Today's messages are `format!` literals with inline interpolation.
The manifest holds them as templates with `{placeholder}` substitution
only: no conditionals, no expressions, no filters. A placeholder the
code does not supply is a render error (fail loudly, never silently
drop text).

**Variants.** Where today's Rust picks between message shapes
(e.g. `W_CADENCE_OVERDUE` with vs without a last touchpoint), the
manifest holds one named template per variant (`last`, `none`, …) plus
a matching `<variant>_fix` template, and the pack's compiled code
chooses which variant to render. The manifest never branches; the
boundary is explicit: **text in the manifest, selection in Rust.**

Each `finding_codes` entry must have a `[messages.<CODE>]` table with
at least one variant, and every `[messages]` key must be in
`finding_codes` — no orphan text, no undocumented codes (§10 tests this).

The `fix` text (`with_fix`) is templated the same way. Severity is not
in the manifest: it comes from the `[checks]` severity lookup at the
call site, as today.

## 8. Skill text

`[pack].skill` is a path relative to the pack directory, today always
`SKILL.md`. The text stays a separate file because it is served to
agents as-is (it is documentation, not a claim) and because the drift
test reads it independently. The manifest must not duplicate it.

## 9. Embedding in the binary

`packs/<name>/manifest.toml` is embedded with `include_dir!`, exactly
like `packs/<name>/SKILL.md` is today (`embedded.rs: PACK_SKILLS`).
The binary serves the manifest it was compiled with — same guarantee
as the skill text. When #193 makes packs external, the manifest ships
inside the pack directory and this embedded copy remains the fallback
for compiled-in packs.

## 10. Drift test generalization

Today's test (`embedded.rs:147`,
`pack_skills_document_all_declared_finding_codes`) iterates
`ALL_PACKS` and asserts every code in `pack.finding_codes()` appears in
the pack's SKILL.md. Generalized to the manifest, the test asserts, per
pack:

1. Every code in the manifest's `finding_codes` is documented in the
   pack's SKILL.md (the existing check, reading codes from the
   manifest instead of the trait).
2. Every code in `finding_codes` has a `[messages.<CODE>]` table, and
   every `[messages]` key is in `finding_codes` (no orphan text, no
   undocumented codes).
3. The manifest's `[pack]` name matches the pack directory and the
   registered pack name.
4. Every `[[fields]]` grammar names a known grammar (§6); every
   `[checks]` key is namespaced to the pack.

This keeps the manifest honest the same way the current test keeps the
slices honest: the manifest cannot claim a code it cannot render, and
cannot render a code it does not claim.

## 11. Worked example: a v1 manifest (historical `personal@0.1`)

The TOML below is the frozen `personal@0.1` claims that the compiled pack
shipped with until the #551 cutover. That pack and its in-crate manifest
(`crates/confidant-core/pack-manifests/personal-0.1/manifest.toml`) are
deleted; the current built-in is `personal@0.2` at
`packs/personal/manifest.toml` (§13.7). The example is kept because it is the
clearest statement of the v1 manifest shape.

```toml
manifest_version = 1

# Top-level keys come before the first [table] header: in TOML anything
# after a table header belongs to that table.
record_types = []

balance_metrics = []

finding_codes = [
  "E_FRONTMATTER",
  "E_INVALID_ID",
  "E_WRONG_ID_TYPE",
  "E_UNKNOWN_RECORD",
  "W_CADENCE_OVERDUE",
  "W_DATE_UPCOMING",
]

[pack]
name = "personal"
version = "0.1"
skill = "SKILL.md"

[[verbs]]
name = "touch"
id_type = "person"

[[fields]]
name = "birthday"
grammar = "recurring-date"

[[fields]]
name = "cadence"
grammar = "cadence"

[[fields]]
name = "relationship_to_me"
grammar = "non-empty-string"

[[fields]]
name = "dates"
grammar = "dates-list"

[[edge_kinds]]
name = "friend"
symmetric = true

[[edge_kinds]]
name = "family"
symmetric = true

[[edge_kinds]]
name = "sibling"
symmetric = true

[[edge_kinds]]
name = "partner"
symmetric = true

[[edge_kinds]]
name = "parent"
symmetric = false

[[edge_kinds]]
name = "mentor"
symmetric = false

[[checks.severity]]
key = "personal.cadence_overdue"
default = "warning"

[[checks.severity]]
key = "personal.date_upcoming"
default = "warning"

[[checks.int]]
key = "personal.date_upcoming_days"
default = 7

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."E_INVALID_ID"]
default = "touch note is not a record ID"
default_fix = "Point note: at an existing n-<ULID> note"

[messages."E_WRONG_ID_TYPE"]
default = "touch note '{id}' is not a note id"
default_fix = "Use note:n-<ULID>"

[messages."E_UNKNOWN_RECORD"]
missing = "touch note '{id}' does not exist"
missing_fix = "Point note: at an existing n-<ULID> note"
wrong_owner = "touch note '{id}' does not belong to {person}"
wrong_owner_fix = "Point note: at a note for this person"

[messages."W_CADENCE_OVERDUE"]
last = "person {id} has no touchpoint on or after {start} (last was {d}, cadence {cadence_days}d)"
last_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"
none = "person {id} has no touchpoint logged (cadence {cadence_days}d)"
none_fix = "Log a touchpoint with `confidant log touch {id} <kind>` or widen cadence"

[messages."W_DATE_UPCOMING"]
default = "person {id} has {label} on {date} ({days} days)"
default_fix = "Log a touchpoint with `confidant log touch {id} <kind>`"
```

Notes on the example:

- `E_TOUCH_MALFORMED` is intentionally absent: it is a core code
  emitted by `check`, not by the pack (cf. the comment on
  `finding_codes()` in `personal.rs`).
- The edge kinds and finding codes above were checked by hand
  (2026-10-15) against `PERSONAL_EDGE_KINDS` and `finding_codes()` in
  `crates/confidant-core/src/packs/personal.rs` and match exactly.
  Step 4's parity test must prove the same mechanically.
- `E_FRONTMATTER`'s `{problem}`/`{fix}` placeholders are filled by Rust
  at the call site (per-field text from `push_field_error`); the
  manifest holds only the template shell and never enumerates the
  fields. This keeps the manifest inside claims territory: text in the
  manifest, values in Rust.
- `W_DATE_UPCOMING`'s template is illustrative of the shape; step 4
  pins the exact placeholders against the code.

## 12. Non-goals

- No new pack is added by this spec; the two compiled packs keep
  working exactly as today.
- No change to the `Pack` trait's compiled methods.
- No grammar language, no expression language, no WASM (per the
  retrospective §6: the calculation abstraction is not proven). Rule
  *kinds* (§13) are in: a fixed list of named, core-implemented rule
  shapes. What stays out is any way for a manifest to describe new
  logic — no conditionals, no arithmetic, no filters, no scripting.
- The manifest does not describe vault layout, ledger syntax, or core
  finding codes — those stay in `spec/0.1.md` and `spec/findings.md`.

## 13. Manifest v2 (external packs)

*Part of #193 (installable external packs, approved by Frank 2026-10-16).
Spec PR for #431; #435 implements the parser.*

v1 (§1–§12) describes the claims of packs compiled into the binary.
v2 extends the same file for **external packs**: packs vendored into the
vault at `<vault>/packs/<name>@<version>/` and pinned by
`confidant.lock` (`spec/pack-lock.md`). A v2 manifest is the same
claims file plus `requires_spec` and `[[rules]]`; the folds and findings
logic for each rule *kind* stays compiled in core Rust, exactly as the
v1 folds stay compiled behind the `Pack` trait.

Set `manifest_version = 2`. A reader that does not implement v2 fails
with `E_PACK_INVALID` and an "upgrade confidant" fix rather than
guessing (PD11).

### 13.1. New and changed keys

```toml
manifest_version = 2

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
# Exact spec versions this pack supports. Non-empty list; each entry is
# an exact version string like "0.1". A vault whose spec is not listed
# gets E_PACK_VERSION (PD11).
requires_spec = ["0.1"]
```

- `[pack].requires_spec`: required in v2, absent in v1. Non-empty list
  of exact spec version strings.
- `[[rules]]`: the declarative checks (§13.2). Absent in v1.
- Everything else (§4) is unchanged: `record_types`, `balance_metrics`,
  `finding_codes`, `[pack]` name/version/skill, `[[verbs]]`,
  `[[fields]]`, `[[edge_kinds]]`, `[checks]`, `[messages]`.

### 13.2. `[[rules]]`: generic keys

Each rule is a named, typed invocation of one **rule kind**. The kind's
logic is implemented once in core Rust; the manifest supplies
parameters. Adding a kind is a spec edit plus Rust — never
manifest-only — so manifests cannot smuggle in new semantics (PD1).

Generic keys (all required unless marked optional). Unknown keys are an
error.

| Key | Type | Meaning |
|---|---|---|
| `id` | string | Unique within the pack. Must match `^[a-z][a-z0-9_]*$`. |
| `kind` | string | One of the fixed kind list below. |
| `code` | string | The finding code this rule emits. Must be in the pack's `finding_codes`. |
| `severity_key` | string, optional | A declared `[[checks.severity]]` key (without the pack prefix is not accepted; write the full `example-pack.some_rule` key). When present, the operator controls severity through `confidant.toml`. Kinds with a fixed severity omit it. |

After the generic keys come the kind-specific keys, defined by each
kind's own spec section. Unknown keys — generic or kind-specific — are
an error.

**The fixed kind list.** This spec starts the list empty. Each kind's
own issue appends its section with the parameter table:

| Kind | Spec issue | Reproduces |
|---|---|---|
| `cadence-overdue` | #442 | the built-in personal pack's keep-in-touch rule |
| `date-upcoming` | #443 | the built-in personal pack's upcoming-dates rule |
| `note-ref` | #458 | the built-in personal pack's `touch` note check and `coaching@0.1`'s `session` note check |

(Planned: `ledger-balance` #446, `session-checks` #447, `activity-gap`
#448.)

#### Kind `cadence-overdue` (#442)

Warn when a person's last contact is older than their cadence window.
Reproduces the built-in personal pack's keep-in-touch rule (including the merge
semantics: the canonical person's own cadence value first, else the
first merged member's; contacts from any merged member count).

One narrowed divergence remains (accepted, per §13.4 rule 7 / PD8):
rules read ledger entries only, so an interaction with no mirrored
`touch` line — hand-written, or written before the primary mirror
landed — counts for the built-in personal pack but not for a declarative
pack. `record add` mirrors a line for the primary person as well as for
`with:` participants, so a newly logged interaction counts for both
(#505).

| Parameter | Type | Meaning |
|---|---|---|
| `cadence_field` | string | One of the pack's own `[[fields]]` entries whose `grammar` is `"cadence"`. The field value is the window in days (`<N>d`, 1..=3650), or the literal `never` (the person is never overdue). |
| `event_verbs` | list of strings, non-empty | Ledger verbs that count as contact. Read-only access to ledger metadata (date, verb, opaque id) — never note bodies, never `no-ai` content (PD8). |
| `snooze_field` | string, optional | One of the pack's own `[[fields]]` entries whose `grammar` is `"date"`. While `as_of` is before its value the person is skipped; they are eligible again on the date itself, and a value in the past has no effect. Only the canonical person's own record is read (a merged member's value does not carry over). |

Message variants the pack's `[messages."W_CADENCE_OVERDUE"]` table must
declare (the loader refuses a rule whose table lacks one):

| Variant | Placeholders | Meaning |
|---|---|---|
| `last` | `id`, `start`, `d`, `cadence_days` | There was contact, but older than the window. `start` = as_of − `cadence_days` days. |
| `none` | `id`, `cadence_days` | No contact on record at all. |
| `last_fix` | `id` | Fix text for `last`. |
| `none_fix` | `id` | Fix text for `none`. |

Evaluation, per canonical person in id order:

1. The person's cadence window: their own `cadence_field` value first,
   else the first merged member's (members are in id order). A person
   with no cadence value anywhere in their merge group is skipped, as is
   a person whose cadence value is `never`.
2. When `snooze_field` is set and the canonical person's own field
   holds a date later than `as_of`, the person is skipped. A value on
   `as_of` or earlier has no effect.
3. Last contact: the latest ledger date `<= as_of` among entries whose
   verb is in `event_verbs`, for the canonical person or any merged
   member.
4. Not overdue when the last contact exists and `as_of − last` is at
   most the window. Otherwise emit `last` (with `start`), or `none`
   when there is no contact.
5. Severity comes from `severity_key` (`off` skips the rule). The
   finding's file is the person's record path, `id` the canonical
   person.

Worked example:

```toml
[[rules]]
id = "cadence"
kind = "cadence-overdue"
code = "W_CADENCE_OVERDUE"
severity_key = "example-pack.cadence_overdue"
cadence_field = "cadence"
event_verbs = ["touch", "session"]
```

With `as_of = 2026-10-08`, a person `p-01M…` whose record says
`cadence: 30d` and whose last `touch` is `2026-08-29` is 40 days stale:
one warning, `last` variant, `start = 2026-09-08`. A touch on
`2026-09-08` (exactly 30 days) is *not* overdue.

#### Kind `date-upcoming` (#443)

Warn when one of a person's recurring dates falls within the next
`window` days. Reproduces the built-in personal pack's upcoming-dates rule; the date
parsing and next-occurrence math are core's (`recurring-date` /
`dates-list` grammars), never reimplemented per pack.

| Parameter | Type | Meaning |
|---|---|---|
| `date_fields` | list of strings, non-empty | The pack's own `[[fields]]` entries whose `grammar` is `"recurring-date"` (one date) or `"dates-list"` (one date per entry); entries must be unique. Findings follow this order. |
| `window_key` | string | A declared `[[checks.int]]` key holding the window in days. Resolved as the operator's `[checks]` value when set, else the manifest's declared default. |

Message variants the pack's `[messages."<CODE>"]` table must declare (the
loader refuses a rule whose table lacks one):

| Variant | Placeholders | Meaning |
|---|---|---|
| `default` | `id`, `occ`, `delta` | The next occurrence `occ` of one of the person's dates is `delta` days from `as_of`. |
| `default_fix` | `id` | Fix text. |

Evaluation, per canonical person in id order:

1. Collect the recurring dates from every field in `date_fields`, in that
   order: a `recurring-date` field gives one date, a `dates-list` field
   gives one per entry. Only the canonical person's own record is read:
   like the compiled rule, a merged member's dates do not carry over.
2. For each date, take its next occurrence on or after `as_of`. (An event
   with a year occurs no earlier than that year; `--02-29` occurs only in
   leap years.)
3. Emit when `0 <= delta <= window`, where `delta` is the whole-day
   difference `occ − as_of`. Invalid field values are already reported as
   `E_FRONTMATTER`; they contribute no date here.
4. Severity comes from `severity_key` (`off` skips the rule). The
   finding's file is the person's record path and `id` the canonical
   person.

Worked example:

```toml
[[rules]]
id = "dates"
kind = "date-upcoming"
code = "W_DATE_UPCOMING"
severity_key = "example-pack.date_upcoming"
date_fields = ["birthday", "dates"]
window_key = "example-pack.date_upcoming_days"
```

With `as_of = 2026-10-16`, a `window_key` value of `7` and a person whose
`birthday` is `--10-20`, the next occurrence is `2026-10-20`: one warning,
`default` variant, `delta = 4`. A birthday of `--10-25` (delta 9) is
outside the window and emits nothing.

#### Kind `note-ref` (#458)

Check the integrity of a `note:<id>` pair on a pack's ledger verb: the id
must parse as a record id, must be a note id, must exist, and must belong
to the entry's canonical person. Reproduces the built-in personal pack's
`touch_note_integrity` and `coaching@0.1`'s `session_note_integrity`.
Only ids and path ownership are read — never note bodies, never `no-ai`
content (PD8).

This kind has a **fixed `error` severity** (both compiled functions emit
`Severity::Error`), so its rules **omit** `severity_key`; a rule that sets
one is refused at load.

| Parameter | Type | Meaning |
|---|---|---|
| `verb` | string, non-empty | The ledger verb whose entries are checked. |
| `pair` | string, non-empty | The key of the pair holding the note id (today `"note"`). |
| `variants` | string, optional | `"touch"` (default) or `"session"`: which variant names the invalid-id and wrong-type messages use (`default`/`default_fix` for personal, `session_note`/`session_note_fix` for coaching). The `missing`/`wrong_owner` variants are the same in both. |
| `invalid_code` | string, optional | The code for an id that does not parse. Defaults to the core code `E_INVALID_ID`. |
| `wrong_type_code` | string, optional | The code for a parsed id that is not a note id. Defaults to the core code `E_WRONG_ID_TYPE`. |

The generic `code` is the code for the missing / wrong-owner problems
(today `E_UNKNOWN_RECORD`). The three codes must have message tables in
the manifest; a pack-own code must also be declared in `finding_codes`.
The kind's fixed severity is `error`, so its pack-own codes use the `E_`
prefix. An external pack cannot claim a builtin code here: omitting
`invalid_code`/`wrong_type_code` leaves the core defaults
(`E_INVALID_ID`/`E_WRONG_ID_TYPE`), and a builtin in either parameter is
refused at load (the same #494 guard as the generic `code`), so an
external pack sets both to codes it declares.

Message variants the pack's tables must declare:

| Code | Variants | Placeholders |
|---|---|---|
| `invalid_code` | `default`/`session_note`, and its `_fix` | none |
| `wrong_type_code` | same variants as `invalid_code` | `id` or `nid` (both are supplied) |
| `code` | `missing`, `missing_fix`, `wrong_owner`, `wrong_owner_fix` | `missing`: `id` or `nid`; `wrong_owner`: `id` or `nid`, plus `person` |

Evaluation, over ledger entries in ledger order:

1. Consider each entry whose verb is `verb`, whose id is a person id, and
   which carries the `pair` pair. Entries of other verbs, non-person ids
   and entries without the pair are ignored.
2. Parse the note id: failure is the `invalid_code` problem, a parsed id
   that is not a note id is the `wrong_type_code` problem.
3. A note id that is not a loaded record is the missing problem
   (`missing` variant under the generic `code`) — unless it is a
   conflicted id, which is treated as existing (it has two versions, so
   it is not missing).
4. An existing note whose owning person (from its front matter or path)
   canonicalizes to a different person than the entry's id is the
   `wrong_owner` problem. Ownership and the entry's person are
   canonicalized as of "now", like the compiled functions.
5. Every finding carries the ledger line's file and line and the
   canonical person as its id.

Worked example (personal's variant names, pack-own codes for an external
copy):

```toml
[[rules]]
id = "touch_note"
kind = "note-ref"
code = "E_EXAMPLE_NOTE_UNKNOWN"
verb = "touch"
pair = "note"
invalid_code = "E_EXAMPLE_NOTE_BAD_ID"
wrong_type_code = "E_EXAMPLE_NOTE_BAD_TYPE"
```

### 13.3. Names

- Pack names match `^[a-z][a-z0-9-]{1,31}$` (PD14).
- `coaching` and `personal` are reserved: no external pack may use
  them. A vault listing `coaching@0.1` resolves to the compiled coaching
  pack, which always wins and whose lockfile entry is ignored (`doctor`
  notes it). `personal@…` names the implicit built-in personal pack: the
  listing is a no-op at any version, and any vendored directory or
  lockfile pin for it is `E_PACK_INVALID` (§13.7).
- Rule `id`s match `^[a-z][a-z0-9_]*$` and are unique within the pack.
- Finding codes declared by an external pack must match
  `^[EW]_[A-Z0-9_]{2,40}$` (PD13), must not equal any existing core or
  compiled-pack code, and a code claimed by two enabled *external*
  packs is `E_PACK_CONFLICT`. In the manifest they appear in
  `finding_codes` and need `[messages.<CODE>]` tables exactly as in v1
  (§7, §10).

### 13.4. Capability limits (PD8)

A pack's capabilities are its **claims** (verbs, record types, fields,
balance metrics, edge kinds, finding codes, `[checks]` keys), which #178
scoping already enforces. These hard limits are enforced at load; each
violation is `E_PACK_INVALID`:

1. A pack may not claim core verbs (`alias`, `merge`, `stage`,
   `balance`, `touch`).
2. A pack may not claim core record types.
3. A pack may not claim core edge kinds (`CORE_EDGE_KINDS` in
   `packs/mod.rs`).
4. A pack may not claim core finding codes.
5. Claims may not collide with an enabled pack (`E_PACK_CONFLICT`,
   already enforced by `find_conflict`).
6. Rule parameters may only name front-matter fields and balance
   metrics the pack itself declares.
7. Rules read ledger entries and declared front-matter fields only:
   never note bodies, never `no-ai` content, never keys. Rules only
   emit findings; they never write.

Ledger verbs named in rule parameters (e.g. `event_verbs`) are
read-only access to plaintext ledger metadata (date, verb, opaque id)
and may be any verb: the built-in personal pack counts coaching's
`session` as a touchpoint.

### 13.5. Allowed pack contents (PD7)

A pack directory may contain only:

- `manifest.toml`
- the skill file named in `[pack].skill` (default `SKILL.md`)
- `<version>.md` (the pack's contract file, e.g. `0.1.md`)
- optional `README*` / `LICENSE*`

Anything else (for example `bin/`, scripts) is rejected at install and
at load with `E_PACK_INVALID`. Packs ship data and agent-facing
**text**, never executables.

### 13.6. Worked example: v2 skeleton

A minimal valid v2 manifest: `requires_spec`, one field, one severity
check, one finding code, one message, no rules yet.

```toml
manifest_version = 2

record_types = []
balance_metrics = []
finding_codes = ["E_EXAMPLE_FIELD"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "example_field"
grammar = "non-empty-string"

[checks]
[[checks.severity]]
key = "example-pack.example_rule"
default = "warning"

[messages."E_EXAMPLE_FIELD"]
default = "example field '{key}' {problem}"
default_fix = "{fix}"
```

Compatibility note: this example parses with the existing v1 loader
once `manifest_version` is set to `1` and the v2-only
`requires_spec` key is removed (checked by hand 2026-10-17). The M1
issue turns the v2 example into a test.

### 13.7. Compiled-in built-ins (#550)

A **built-in** pack (today `personal@0.2`) is a v2 manifest whose bytes
are compiled into the binary and loaded through the same loader and rule
kinds as an external pack. A built-in is **implicit**: it is enabled in
every vault, a `packs = []` vault included, and a `personal@…` listing is a
no-op. The manifest's **origin** is what differs, and only the loader sets
it (a manifest file cannot claim it):

- origin `external` (the default): the bytes came from the vault's
  `packs/<name>@<version>/`; the PD8 capability limits and the
  reserved-name rule of §13.3/§13.4 apply, and `finding_codes` may use a
  builtin only as the `E_FRONTMATTER` emission claim (§10).
- origin `compiled-in`: the bytes shipped inside the binary and are
  trusted as core. The reserved-name rule and PD8 rules 1–3 do not
  apply (a built-in may claim `touch`), and a rule's `code`,
  `invalid_code` or `wrong_type_code` may name any core code.

The allowance is keyed on the origin, **never on the pack name**. A
vault directory `packs/personal@<version>/` still resolves through the
external path and is `E_PACK_INVALID` (a built-in is never installed
from the vault: any lockfile pin or vendored directory for its name
fails closed). The v2 schema itself — rule ids, kinds, declared codes,
message tables — applies in full.
