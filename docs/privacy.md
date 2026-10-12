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

## Error handling

If any ledger file cannot be read, `find` exits non-zero with
`E_LEDGER_UNREADABLE` (code and count only) and no hits.
