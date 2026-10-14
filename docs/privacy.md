# Privacy & Search Allowlist

Confidant's search is **fail-closed**: a record is searchable only when it
parses cleanly, carries no `no-ai` flag, and every ID it references is
cleared. This document describes the allowlist mechanics in detail. For the
short version, see the README's [Privacy](../README.md#read-this) section.

## What `confidant find` returns

`confidant find` returns content only from a cleared allowlist (spec section
12). A record is searchable only when:

- it parsed cleanly,
- it has no `no-ai` flag,
- it has no duplicate or path-id mismatch,
- every ID in its front matter is cleared,
- its whole merge group is cleared,
- any `people/<id>/` parent is cleared.

A path mismatch on a note, interaction, or deal unclears only that record; a
mismatch or duplicate on a person's profile unclears that whole person.

## Finer `no-ai` granularity (issue #181)

`no-ai` has three values: `true`, `false`, and `notes` (person records
only). There are no field-level flags — the record is the unit.

- **`no-ai: true`** hides everything about the person (or record) from
  agents: the all-or-nothing guarantee. Findings about such a person never
  carry their name or other PII to agents — the warning is suppressed or
  reduced to a code and a count.
- **`no-ai: notes`** on a person keeps the person visible — name, birthday,
  cadence and other pack fields reach `find`, `context`, and MCP — while
  their notes and interactions default to hidden. Findings may name the
  person and give dates, but never note bodies. The default is inherited
  through any front-matter reference to the person, not just `person:`:
  the folder path, `with:` participants, and any other field whose value
  is the person's ID — or a list of IDs containing it — all count (#270).
  This is fail-closed on purpose — a note that mentions a notes-mode
  person is hidden unless it carries an explicit `no-ai: false`.
- **Per-note `no-ai: true`** on an otherwise visible person already works:
  "any `true` wins", so the note is excluded from `find`/`allowlist`/
  `reindex` while the person stays visible. Use this for one-off sensitive
  detail (a medical note); use `notes` mode when most notes should be
  hidden. A note's explicit `no-ai: false` overrides the `notes` default
  (set it in front matter; `note add` has no flag for it), but can never
  un-hide a `no-ai: true` person.

On encrypted vaults the mode rides the envelope's plaintext outer header
(`no-ai: notes`), so `find`/`context` fail closed without keys; readers
that only know `true`/`false` reject `notes` rather than misreading it.
Unreadable or missing person headers fail closed when stamping children
(stamped `no-ai: true`). Mixed-version writers (CLI builds from before
`no-ai: notes` landed) must not rewrite `notes`-mode people or write
children under them.

## Ledger lines

Ledger lines are searchable only when every ID on the line is cleared. A note,
interaction, or deal is cleared only when every ledger line that names it is
allowed; this does not apply to persons.

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

Milestone 3 `context` continues to honour `no-ai`.

## Pack scoping (issue #178)

Every agent-facing read path takes a pack scope: `context`, `find`, MCP
tools, and `allowlist` / `reindex` outputs. `check` and `doctor` always run
unscoped — they verify the whole vault. Scoping is a policy filter at read
time: records, fields, and ledger lines are attributed to an owning pack
from the pack registry, and out-of-scope items are filtered out. It is NOT
cryptography — every client still holds the same recipient set, so a
scoped agent that can read the vault files directly can see everything.
What scoping stops is an agent over-reaching through the tool surface:
a coaching-scoped agent never sees personal notes about the same person
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
- **Shared interactions**: the pack that wrote an interaction decides
  its visibility (#179 settled the mechanics).
- **Edges**: an edge is visible exactly when its kind's pack is in scope
  (core kinds are visible to every scope). An edge whose kind belongs to
  a disabled pack warns `W_PACK_ORPHAN`; an edge whose kind has no owner
  is visible only unscoped and is `E_UNKNOWN_EDGE_KIND`. The edge's own
  front matter has no pack-owned fields to filter.

## Edges and shred (issue #179)

An edge record carries only ids, kind, and dates — no body, no note.
Sensitive context belongs in a note on one of the edge's people, which
does get crypto-shredded. Edges live under the shared key
(`vault:shared`), so destroying one person's client key cannot shred
them. Instead, `keys shred p-A` deletes every edge file naming A from
the working tree in the same signed commit, and states plainly in its
output:

> Edges that named this person were deleted from the working tree, but
> earlier versions in git history remain readable with the shared key.

A shredded participant's own touchpoints stay in the ledger as
opaque-id lines — the ledger is not rewritten by shred, and a `touch`
line carries no other participant's id, so it does not re-identify
anyone by itself.

Multi-person interactions are encrypted to their *primary* person's key
and list other participants in `with:` inside the ciphertext. `keys shred
p-A` re-encrypts every interaction naming A in its `with:` list, dropping
A, in the same signed commit — through the normal write path, so it only
needs the primary's key (which shred never destroys). Earlier versions in
git history still list A's opaque id under the primary's key, which
survives A's shred; shred says so in its output. The reverse case — A is
the *primary* and someone else is only in `with:` — loses the whole
interaction from the participant's view, because it is under A's destroyed
key; that is the #179 design.

For when per-pack *keys* would be needed, see
`docs/per-pack-keys-design-note.md`.

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
the latest release. When behind, `update` re-links nothing and tells you to
upgrade the binary first.
