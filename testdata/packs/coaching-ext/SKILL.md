---
name: "coaching-ext"
description: "Parity fixture for external coaching (coaching-ext@0.1): the compiled coaching@0.1 checks re-expressed as declarative rules. Not shipped."
---

# Coaching-ext fixture (coaching-ext@0.1)

A **test fixture**, not a shipped pack. It re-expresses the compiled
`coaching@0.1` checks as the declarative rule kinds (`note-ref`,
`ledger-balance`, `session-checks`, `activity-gap`, spec
`spec/pack-manifest.md` §13.2) so the #449 parity tests can prove the
external path reproduces compiled coaching. The human-readable contract is
`0.1.md`; the stable compiled codes are `spec/findings.md`.

Because an external pack cannot claim a builtin finding code (PD13), every
code below is the fixture's own and maps one-to-one onto a compiled code.
The `[checks]` keys are namespaced to this pack.

## Verbs

### `open` — sell or renew a package

```
DATE open PERSON-ID package PKG-ID N sessions
```

- `PKG-ID` uses the `pkg-` prefix; `N` is a positive integer ≤ 100000.
- Multiple `open` lines accumulate.
- Malformed lines are `E_COACHING_EXT_OPEN`; a bad package id is
  `E_COACHING_EXT_ID`; a non-`pkg-` package id is `E_COACHING_EXT_TYPE`.

### `session` — log a coaching session

```
DATE session PERSON-ID DURATION [paid|pps|comp] [note:NOTE-ID] [src:PROVENANCE]
```

- `DURATION` is `Nm`, `Nh`, or `NhNm` (`60m`, `1h`, `1h30m`).
- Billing tags: `paid` consumes a package slot; `pps` and `comp` never
  consume. A session with no tag still consumes and gets
  `W_COACHING_EXT_UNTAGGED`. More than one tag is `E_COACHING_EXT_TAGS`.
- `note:NOTE-ID` links the session's note; a missing/foreign note is
  `E_COACHING_EXT_UNKNOWN`, a bad id `E_COACHING_EXT_NOTE_ID`, and a
  non-note id `E_COACHING_EXT_NOTE_TYPE`. These integrity checks always
  run.

## Balance metrics

Asserted with `balance PERSON-ID METRIC VALUE` lines, evaluated as of the
end of the assertion date.

| Metric | Meaning |
|---|---|
| `sessions_remaining` | Sum of `open` N minus consuming sessions on or before the date. Negative fires `E_COACHING_EXT_NEGATIVE`. |
| `icf_hours` | Sum of session durations in hours, compared at 2 decimal places. |

A disagreement is `E_COACHING_EXT_BALANCE`. A malformed `balance` number is
`E_COACHING_EXT_PARSE`.

## Configuration (`[checks]` keys)

| Key | Default | Meaning |
|---|---|---|
| `coaching-ext.require_duration` | error | `E_COACHING_EXT_DURATION` severity. |
| `coaching-ext.balance_nonnegative` | error | `E_COACHING_EXT_NEGATIVE` severity. |
| `coaching-ext.session_notes` | warning | `E_COACHING_EXT_NOTES` severity. |
| `coaching-ext.paid_session_gap` | warning | `E_COACHING_EXT_GAP` severity (`off` disables the rule). |
| `coaching-ext.paid_session_gap_days` | 45 | Days without a session before a paid client gaps. |
| `coaching-ext.pps_lookback_days` | 180 | Lookback window for pay-per-session clients. |

## Findings

Every finding code this fixture can emit, and what it means.

### `E_COACHING_EXT_OPEN` (error)

An `open` line is not the exact shape, `N` exceeds 100000, or the running
open total overflows.

### `E_COACHING_EXT_ID` (error)

A package id on a coaching line is not a valid record id.

### `E_COACHING_EXT_TYPE` (error)

A package id lacks the `pkg-` prefix, or a verb named a non-person id.

### `E_COACHING_EXT_DURATION` (error by default)

A `session` has no parseable duration.

### `E_COACHING_EXT_TAGS` (error)

A `session` carries more than one of `paid`/`pps`/`comp`.

### `W_COACHING_EXT_UNTAGGED` (warning)

A `session` has no billing tag; it still consumed a package slot.

### `E_COACHING_EXT_NEGATIVE` (error by default)

`sessions_remaining` went negative.

### `E_COACHING_EXT_BALANCE` (error)

A `balance` assertion disagrees with the computed metric.

### `E_COACHING_EXT_NOTES` (warning by default)

A session has no linked or same-day note.

### `E_COACHING_EXT_GAP` (warning by default)

A paid client has no session inside the gap window.

### `E_COACHING_EXT_NOTE_ID` (error)

A `note:` id is not a valid record id.

### `E_COACHING_EXT_NOTE_TYPE` (error)

A `note:` id parses but is not a note id.

### `E_COACHING_EXT_UNKNOWN` (error)

A `note:` names a missing note, or a note belonging to another person.

### `E_COACHING_EXT_PARSE` (error)

A coaching `balance` line is malformed (missing or non-numeric value).

## Privacy notes

- `no-ai` is honored everywhere: a `no-ai` record never appears in `find`,
  `context`, or agent-facing JSON.
- The rules read ledger metadata, note ids/paths/dates and declared fields
  only — never note bodies, never keys (`spec/pack-manifest.md` §13.4).
