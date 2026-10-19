# Example pack skill (example-pack@0.1)

This is the neutral external-pack fixture used by Confidant's tests. It is
not a real workflow and ships no data.

The pack exercises every declarative rule kind with generic names:

- `grant` adds units in the form `DATE grant PERSON-ID package PKG-ID N
  sessions`.
- `use` consumes a unit: `DATE use PERSON-ID DURATION [full|metered|free]
  [note:NOTE-ID] [src:PROVENANCE]`.
- `session` is a generic event verb with no rules attached.

## What the checks mean

| Code | Meaning | Default severity | Key |
|---|---|---|---|
| `E_FRONTMATTER` | A field value failed its declared grammar. | error | — |
| `E_EXAMPLE_PARSE` | A `balance` line could not be parsed. | error | — |
| `E_EXAMPLE_BALANCE_MISMATCH` | A `balance` assertion disagreed with the computed value. | error | — |
| `E_EXAMPLE_NEGATIVE_BALANCE` | Computed `units_remaining` is below zero. | error | `example-pack.balance_nonnegative` |
| `E_EXAMPLE_GRANT_MALFORMED` | A `grant` line is malformed. | error | — |
| `E_EXAMPLE_INVALID_ID` | A package id is not a record id. | error | — |
| `E_EXAMPLE_WRONG_ID_TYPE` | A package id is not a `pkg-` id. | error | — |
| `E_EXAMPLE_MISSING_DURATION` | A `use` entry has no parseable duration. | error | `example-pack.require_duration` |
| `E_EXAMPLE_TAGS` | A `use` entry has more than one tag. | error | — |
| `W_EXAMPLE_UNTAGGED` | A `use` entry has no tag. | warning | — |
| `E_EXAMPLE_WITHOUT_NOTES` | A `use` entry has no note covering it. | warning | `example-pack.notes` |
| `E_EXAMPLE_GAP` | A client with remaining units has no recent entry. | warning | `example-pack.gap` |
| `E_EXAMPLE_NOTE_INVALID_ID` | A `note:` value is not a record id. | error | — |
| `E_EXAMPLE_NOTE_WRONG_TYPE` | A `note:` value is not a note id. | error | — |
| `E_EXAMPLE_UNKNOWN_RECORD` | A referenced note is missing or owned by someone else. | error | — |

Window keys: `example-pack.gap_days` (default 45) and
`example-pack.lookback_days` (default 180).

## Metrics

- `units_remaining`: grants minus consuming `use` entries.
- `minutes_total`: the entry durations in hours, two decimal places.

A `balance PERSON-ID units_remaining N` or `balance PERSON-ID minutes_total
X` line asserts a value as of that date. The pack opts into the core
`ledger-sessions` context view.
