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
# Full pack name is "personal@0.1", matching today's `Pack::name()`.

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
`as_of` top-level key stays core-owned.

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
- `[pack].version`: the pack's own version (`personal@0.1`). Pack
  version bumps follow the pack's contract file (`packs/<name>/0.1.md`).

## 6. Field grammars: a fixed named list

The manifest **names** a grammar; Rust supplies the parser. This is a
fixed list of named parsers, not a grammar language (step 3 wires the
registry; the list itself is frozen by this spec):

| Name | Accepts | Today |
|---|---|---|
| `recurring-date` | `YYYY-MM-DD` or `--MM-DD` (year-less; `--02-30` rejected, `--02-29` valid) | `RecurringDate::parse` |
| `cadence` | `<N>d`, `1 <= N <= 3650` (e.g. `30d`) | `parse_cadence_days` |
| `dates-list` | comma-separated `LABEL:DATE` entries, optionally wrapped in `[...]`; `LABEL` matches `[a-zA-Z0-9_-]+`, `DATE` is a `recurring-date` | `parse_dates_list` |
| `non-empty-string` | any non-empty string (whitespace-trimmed) | `relationship_to_me` check |

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

## 11. Worked example: `personal@0.1`

`packs/personal/manifest.toml`:

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
| *(none yet)* | — | — |

(Planned: `cadence-overdue` #442, `date-upcoming` #443, `note-ref`
#458, `ledger-balance` #446, `session-checks` #447, `activity-gap`
#448.)

### 13.3. Names

- Pack names match `^[a-z][a-z0-9-]{1,31}$` (PD14).
- `coaching` and `personal` are reserved: no external pack may use
  them. If a vault lists `coaching@0.1` or `personal@0.1`, the compiled
  pack always wins and any lockfile entry for it is ignored (`doctor`
  notes it).
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
and may be any verb: `personal@0.1` counts coaching's `session` as a
touchpoint.

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
