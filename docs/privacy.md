# Privacy & Search Allowlist

Confidant's search is **fail-closed**: a record is searchable only when it
parses cleanly, carries no `no-ai` flag, and every ID it references is
cleared. This document describes the allowlist mechanics in detail. For the
short version, see the README's [Privacy](../README.md#privacy) section.

## What `confidant find` returns

`confidant find` returns content only from a cleared allowlist (spec section
12). A record is searchable only when:

- it parsed cleanly,
- it has no `no-ai` flag,
- it has no duplicate or path-id mismatch,
- every ID in its front matter is cleared,
- its whole merge group is cleared,
- any `people/<id>/` parent is cleared,
- it is not `retired: true` (spec 0.4).

A path mismatch on a note, interaction, or deal unclears only that record; a
mismatch or duplicate on a person's profile unclears that whole person.

## Finer `no-ai` granularity (issue #181)

`no-ai` has three values: `true`, `false`, and `notes` on person records
and declared `person_like` pack types. Other pack-declared types accept
`full` only (`true` / `false`): a place or thing cannot use `notes`. There
are no field-level flags — the record is the unit. An edge is the exception:
it accepts only `true` / `false`, and `true` hides the relation while both
endpoints stay visible (see “Edges and orgs”).

- **`no-ai: true`** hides the person's (or record's) content from agents —
  names, bodies, profile fields, notes, and free text — the all-or-nothing
  guarantee. `context` still serves the person's **derived, ledger-based
  metadata**: the personal pack's cadence and touch state (`cadence_days`,
  `cadence_never`, `last_touch`, `days_since_touch`, `overdue`,
  `recent_touches`, and the declared `snooze_until`), the
  top-level `touchpoints` list (dates, kinds, and the optional duration and
  1:1/group mode of the `touch` lines), any enabled
  pack's derived balance metrics and recent entries (dates, durations,
  tags). These are structural, not content: a schedule and the dates it ran
  against, so an agent can still tell that the person is overdue or
  deliberately set to `never`. `find`, the allowlist, and the search corpus
  return none of that; contact values (emails, phones, handles) are profile
  data and stay hidden with the rest of the profile. `cadence_basis`,
  `cadence_note`, `relationship_context`, `role_history`, `alias_history`,
  `human_note`, and `profile_provenance` are declared fields, so `no-ai`
  hides them with the rest of the profile; under operator
  `--exclude-private` the one-word `cadence_basis` stays and the rest are
  stripped. The plain
  `context.aliases` array carries only the untyped current contact values
  and never the typed alias history.
  Findings about such a person never carry their name or other PII to
  agents — the warning is suppressed or reduced to a code and a count.
- **`no-ai: notes`** on a person keeps the person visible — name, birthday,
  cadence and other pack fields reach `find`, `context`, and MCP — while
  their notes and interactions default to hidden. Findings may name the
  person and give dates, but never note bodies. The default is inherited
  through any front-matter reference to the person, not just `person:`:
  the folder path, `with:` participants, and any other field whose value
  is the person's ID — or a list of IDs containing it — all count (#270).
  This is fail-closed on purpose — a note that mentions a notes-mode
  person is hidden unless it carries an explicit `no-ai: false`.
- **Places and things** are non-person-like pack entities with
  `no_ai = "full"`. `no-ai: true` hides the place/thing and every edge that
  touches it; `no-ai: false` keeps it visible. There is no `notes` mode. An
  uncleared place or thing returns **no agent `context` bundle at all**, not
  an empty one: unlike a person, it has no derived ledger metadata that
  would justify revealing its existence. The operator path still returns the
  bundle with the tri-state badge and its fields. `context.entity.fields`
  carries the declared fields; `--exclude-private` strips `address`, `tags`,
  and `links`, while `kind` stays as the type marker (a place's `address` is
  PII).
- **Per-note `no-ai: true`** on an otherwise visible person already works:
  "any `true` wins", so the note is excluded from `find`/`allowlist`/the
  search corpus while the person stays visible. Use this for one-off sensitive
  detail (a medical note); use `notes` mode when most notes should be
  hidden. A note's explicit `no-ai: false` overrides the `notes` default
  (set it in front matter, e.g. via `note edit`; `note add` has no flag for
  it), but can never un-hide a `no-ai: true` person.

`no-ai` is read from the record's own front matter, which is plaintext like
the rest of the vault (ADR-4). That is what makes the mode cheap to honour
on every read: `find`/`context` decide from the file itself, with no separate
index or side channel to keep in step. A person that cannot be parsed, or
whose front matter is missing, fails closed when stamping children: the
children are treated as `no-ai: true`. Because the flag itself is readable,
anyone who can read the file learns that a record is marked — but the read
surfaces still withhold its content from agents.

## Edges and orgs (#813)

`context <id>` accepts a person or an org. An edge is in the bundle only when
**both** endpoints are cleared **and** the edge itself is not `no-ai: true`:
`a` and `b` are front-matter IDs, so a `no-ai: true` endpoint drops the whole
edge from `find`, the allowlist, and every context bundle, including the
other endpoint's. A `no-ai: true` edge is hidden the same way while both
endpoints stay visible; the relation is not counted, summarized, or
anonymized. The bundle carries no count and no anonymized hint; omitted means
indistinguishable from absent. The operator path still sees a hidden edge and
badges it with `no_ai: "true"`; `--exclude-private` keeps the edge's opaque
id, kind, and dates but nulls the other endpoint's name, along with the
target's name and profile.

Orgs cannot be `no-ai` (org-level hiding remains a later privacy decision,
#820). Edges accept `no-ai: true` / `false` only: there is no `notes` mode and
no inheritance in either direction. An org bundle also selects notes and
interactions attached by `org:`, under the same cleared-set and pack-scope
rules as a person bundle.

`context` also accepts a declared `entity = true` pack type. A non-person-like
pack entity (a place or thing) carries its declared `required_fields` and
`optional_fields` in `entity.fields`, excluding `name`, with values shaped by
the manifest grammar. The same `--exclude-private` list strips a place's
`address` and the `tags`/`links` fields; an uncleared one returns no bundle
on the agent path at all.

## Corrections and retirement (#746)

A `retract` line supersedes a prior ledger line without editing or deleting
it. A superseded line is not searchable on the agent path and is absent from
`allowlist`, so it never enters the QMD corpus; `find --for-operator` still
shows it. The operator `context` path also lists superseded lines in
`touchpoints` with `superseded: true` so an operator can see what a
retraction voided; the agent bundle omits them entirely, so this is
operator-only display, not a new agent-visible surface. A retraction line is
searchable only when its own ID tokens **and its target line** are allowed.
Without that second gate the ref would be a hash oracle: an agent could test
a guess about a hidden line. A retracted line whose target is hidden
therefore stays hidden with it.

A `retired: true` record is not in the cleared set. It and records/lines that
name it are omitted from agent `find`, `context`, `resolve`, `alias resolve`,
and `record list`; `context` returns no bundle for a retired target. This is
the same fail-closed posture as `no-ai: true`, not a separate privacy mode:
retiring a record also removes its notes, interactions, deals, and edges from
agent reads. The operator path still sees them (`--for-operator`,
`record show --for-edit`), and `check` still validates the file.

The line refs (`line:<64 hex>`) are opaque values derived from the line's
canonical bytes. They are never echoed for an uncleared target; the short
form may appear in operator-facing `check` messages. A correction or
retirement changes the cleared set, so rebuild the local QMD corpus
(`qmd-index.py`) before relying on ranked search.

## Ledger lines

Ledger lines are searchable only when every ID on the line is cleared. A
superseded line is not searchable, and a superseded line does not gate a note,
interaction, or deal it named. A note, interaction, or deal is cleared only
when every effective ledger line that names it is allowed; this does not
apply to persons.

## TUI proposal review

`confidant-tui` renders dry-run content (ledger lines, note bodies, record
content) on screen only by the TUI itself; it is not logged or sent anywhere.
The proposal files it reads are plaintext on disk under
`<vault>/.confidant/proposals/` (gitignored) until cleanup: manifest, lines
file, staged note bodies and record content are created `0600` (`0700` for
directories) and deleted after the apply. Cleanup is a normal file remove by
the skill's `--cleanup`, not a secure wipe.

## Packages

`pkg-` IDs follow their openers. Dropping a record walks merge peers and
package openers to a fixed point.

## Findings are themselves an allowlist

Findings are kept verbatim only when they have no file and no ID, or resolve
to a cleared record or ledger line; otherwise a code and a count, never a
path or raw text.

## ID recognition edge cases

- A leading Markdown bullet is skipped before detecting `merge` / `open`.
- Malformed ID-like tokens un-clear the record or line.
- Body lines that mention an uncleared or invalid ID are dropped.
- Name-only mentions with no ID are not detected in body prose and comments.
- A `person` / `org` / `deal` value that is not a record ID (`person: "Jane Doe"`,
  bare `p-A|Name`) is `E_INVALID_ID` and uncleared.
- Empty, `~`, and YAML `null` are not references.
- A `|` alias is accepted only inside `[[…]]`.
- A trailing comment after a closing quote (one or more spaces or tabs, then `#`)
  is stripped (`"p-…" # Ada`, `"p-…"  # Bea`).

## Glued prefixes and lookalikes

After an alphanumeric, `_`, or `-` in the same run, and inside a `scheme://`
token, a prefix is glued:

- An exact ULID is Valid.
- A longer run whose first 26 characters are a ULID, a Unicode dash plus a
  ULID, or a dash run (`--`, soft hyphen then `-`) plus a ULID, is malformed
  with that candidate.
- Other glued lookalikes (Drive/Docs, Notion, 32-hex) are not tokens.

Unicode Pd dashes plus U+30FC and U+2043 count as the ID dash.

## Bare ULIDs

A bare 26-character ULID that exactly equals any ULID the vault names (loaded
records, packages, dangling prefixed IDs, and IDs found in visited
file/directory names, including nested dirs, `(copy)` / `.bak` / uppercase
prefixes / bare `<ULID>.md` / `.n-<ULID>.md.swp`) is treated as that ID as any
26-character window inside a Crockford run (`src:zoom/rec_<ULID>.vtt`,
`p_<ULID>`, `p<ULID>`, `<ULID>abc`), except windows already covered by a
prefixed token (a record's `id:` line is not a bare window).

ULIDs named only by a dangling or malformed prefixed token match genuinely
bare windows only; loaded records and path IDs still apply inside prefixed
tokens. Near-ULID bare runs are not IDs.

## Remaining limits

- Glued inexact IDs whose first 26 characters do not canonicalize.
- Non-Cf invisible characters.
- Capitalised or other keys holding names.
- Name-only prose.
- `check`'s location field still shows the paths of invalid files.

`context` honours `no-ai` on the same terms as `find`; a non-person-like pack
entity that is uncleared gets no agent bundle at all. It also returns a
top-level `timeline` that merges `touchpoints` and `interactions` in date
order; the timeline is built from those filtered arrays, so a hidden or
retired entry stays absent.

## Pack scoping (issue #178)

Every agent-facing read path takes a pack scope: `context`, `find`, MCP
tools, and `allowlist` output plus the search corpus. `check` and `doctor`
always run unscoped — they verify the whole vault. Scoping is a policy filter
at read time: records, fields, and ledger lines are attributed to an owning
pack from the pack registry, and out-of-scope items are filtered out. It is
NOT access control — the vault is plaintext on disk (ADR-4), so a scoped
agent that can read the vault files directly can see everything.
What scoping stops is an agent over-reaching through the tool surface:
a pack-scoped agent never sees another pack's notes about the same person
through `context`, `find`, or MCP.

Rules:

- **Default scope: all enabled packs.** An unscoped call sees everything
  (back-compat for the operator's own CLI).
- **`--packs LIST` (comma-separated) scopes a call.** On the CLI it scopes
  that one call. On `confidant mcp --packs LIST` it sets the instance's
  **ceiling**: a per-call `packs` argument can only narrow, never widen —
  widening is an error, not a silent fallback.
- **Unknown or disabled pack in `--packs` is a hard error**
  (`usage_error`, exit 2), not an empty scope and not a fallback to all
  packs.
- **Core identity is visible to every scope**: person name, aliases, and
  other core-owned fields. Notes and interactions are NOT core-visible —
  they are attributed to a pack or hidden.
- **Attribution** (derived at read time from the pack registry, no format
  change): fields are owned by the pack that claims them; ledger lines are
  owned by their verb, except core verbs carrying pack data (`balance` on
  a pack metric) are owned by the metric's pack. A person/org/deal body is
  core-owned (the identity anchor); pack-claimed fields on those records
  filter per-field in `find`. **Anything unattributable is visible only
  unscoped** — when in doubt, it is filtered out.
- **Search cannot leak around the scope.** `allowlist --json` annotates
  each cleared file and ledger line with its `owning_packs` (`[]` =
  unattributed, `["core"]` = core-owned), so index-time consumers can
  filter by scope. `qmd-query.py --packs LIST` passes the scope to the
  verification and fallback `find` calls; the QMD index itself is
  unscoped and the `find` verification is the enforcement point.
- **Pack-declared record types are pack-owned (spec 0.3).** A record whose
  `type:` is declared by a pack is visible only while that type is enabled
  and its declaring pack is in scope. The type declaration is the gate: an
  agent read returns nothing for a record of a disabled, retired, or
  undeclared type, even if the record file itself is readable. There is no
  per-record field-level split for a pack type; the whole record follows its
  type's owner. Core person/org/deal remain core-owned. The operator path
  (`record list --for-operator`, or loading the vault for an operator-only
  command) surfaces orphans with a badge, so a disabled pack's records do
  not become invisible to the person who must clean them up.
- **`context` targets an entity type.** A pack type is a context target only
  when its declaration sets `entity = true`; a `person_like` type also gets
  person read semantics (aliases, touchpoints, and a person-shaped pack
  view). Notes and interactions attach through `entity:`, `person:`, or
  `org:`; they keep their own pack ownership, so a scoped agent sees only
  the attachments its scope allows even when the target entity is visible.
- **Shared interactions**: the pack that wrote an interaction decides
  its visibility (#179 settled the mechanics).
- **Edges**: an edge is visible exactly when its kind's pack is in scope
  (core kinds are visible to every scope). An edge whose kind belongs to
  a disabled pack warns `W_PACK_ORPHAN`; an edge whose kind has no owner
  is visible only unscoped and is `E_UNKNOWN_EDGE_KIND`. The edge's own
  front matter has no pack-owned fields to filter.

## Edges (issue #179)

An edge record carries only ids, kind, dates, and (in 0.3) `no-ai` — no body,
no note. Sensitive context belongs in a note on one of the edge's entities,
where the `no-ai` rules above decide who may read it. Because an edge holds
no prose, it can be visible while the interesting detail stays hidden; a
`no-ai: true` edge instead hides the relation while both endpoints stay
visible.

A person's own touchpoints stay in the ledger as opaque-id lines. A `touch`
line carries a date, one opaque id, and a kind: no other participant, no
note body. It says that this person was contacted on that day, which is the
minimum the ledger needs to compute cadence.

Multi-person interactions list participants in `with:` in the record itself.

Since #505 `record add` also mirrors a `touch` line for an interaction's
primary person, not only for `with:` participants. A logged interaction
therefore puts its exact date and the primary's opaque id in the ledger. It
is the same shape a `with:` line already had — a date and one opaque id, no
other participant, no interaction id, no content. An interaction written
before #505, or hand-written, may carry no such line.

For the boundaries pack scoping does and does not provide, see "Pack scoping"
above.

## Error handling

If any ledger file cannot be read, `find` exits non-zero with
`E_LEDGER_UNREADABLE` (code and count only) and no hits.

## Network access

`confidant doctor` checks GitHub for the latest release by default: one
unauthenticated `GET` to `api.github.com/repos/hirefrank/confidant/releases/latest`.
No vault data, record content, IDs, or paths are sent, and only the `tag_name`
field is read from the response — the body is discarded. `doctor` also
reports local skills link health (no network involved). Set
`CONFIDANT_OFFLINE=1` to skip the request entirely; the staleness check then
reports `staleness check disabled`.

`confidant update` makes the same request (same endpoint, same
`CONFIDANT_OFFLINE=1` opt-out) to decide whether the local binary is behind
the latest release. For a cargo-dist (one-liner) install it then downloads
`sha256.sum` and the release installer from
`github.com/hirefrank/confidant/releases`, checks the installer's embedded
archive checksums against that file, and runs the installer, which
re-verifies the platform archive before replacing the binary in place under
the prefix named by the install receipt. No vault
data is sent. Homebrew and `cargo install` installs are never replaced:
`update` prints the command that owns them, and `--json` never changes the
binary. When behind, `update` re-links nothing: skills are re-linked from
the new binary by `confidant setup`.

`confidant status` makes the same request (same endpoint, same
`CONFIDANT_OFFLINE=1` opt-out) as part of its readiness rollup, which reuses
the doctor staleness check.
