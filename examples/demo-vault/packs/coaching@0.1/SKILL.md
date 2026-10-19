---
name: "coaching"
description: "Coaching practice pack (coaching@0.1): package/session ledger verbs, balance metrics, and every finding code the pack can emit — what each means and what to do about it."
---

# Coaching pack (coaching@0.1)

Agent-facing contract for the coaching schema pack. The human-readable
contract is `packs/coaching/0.1.md`; the stable finding codes are
`spec/findings.md`. This file tells an agent what the pack's verbs,
metrics, and findings mean in practice, without reading Rust.

## What this pack adds

A vault without this pack has people, orgs, deals, interactions, notes,
aliases, merges, stages, and generic balance assertions only. Enabling
`coaching@0.1` (vendored into the vault, pinned in `confidant.lock`, and listed in `packs = ["coaching@0.1"]`) adds:

- Ledger verbs `open` and `session` (below).
- Balance metrics `sessions_remaining` and `icf_hours`, asserted with
  `balance` lines.
- The finding codes documented below.

The pack owns no record types and no front-matter fields. It works with
core `person` records and `note` records, plus two ledger-line pairs
(`note:` and `src:`) and its `[checks] coaching.*` configuration keys.

## Verbs

### `open` — sell or renew a package

```
DATE open PERSON-ID package PKG-ID N sessions
```

- `PKG-ID` uses the `pkg-` prefix; `N` is a positive integer ≤ 100000.
- Multiple `open` lines accumulate.
- Malformed lines are `E_COACHING_OPEN_MALFORMED`; a bad package id is
  `E_COACHING_INVALID_ID`; a non-`pkg-` package id is
  `E_COACHING_WRONG_ID_TYPE`.

### `session` — log a coaching session

```
DATE session PERSON-ID DURATION [paid|pps|comp] [note:NOTE-ID] [src:PROVENANCE]
```

- `DURATION` is `Nm`, `Nh`, or `NhNm` (`60m`, `1h`, `1h30m`).
- Billing tags: `paid` consumes a package slot; `pps` (pay-per-session)
  and `comp` (complimentary) never consume. A session with no tag still
  consumes (safe default) and gets `W_COACHING_SESSION_UNTAGGED`. More than one
  tag is `E_COACHING_SESSION_TAGS`.
- `note:NOTE-ID` links the session's note. The note must exist and belong
  to the session's person after merge canonicalization; otherwise
  `E_COACHING_UNKNOWN_RECORD` (missing/wrong owner),
  `E_COACHING_NOTE_INVALID_ID` (bad id), or `E_COACHING_NOTE_WRONG_TYPE`
  (not a note id). These integrity checks always run.
- `src:PROVENANCE` records where the line came from
  (`src:transcript/t-…`, `src:portal/evt-…`) and is the content-level
  dedupe key for imports: the same `src:` on two lines is
  `E_DUPLICATE_SRC`.
- `open` and `session` require a person ID (`E_WRONG_ID_TYPE` otherwise).

## Balance metrics

Asserted with `balance PERSON-ID METRIC VALUE` lines, evaluated as of the
end of the assertion date. Later entries and later merges never affect an
earlier assertion.

| Metric | Meaning |
|---|---|
| `sessions_remaining` | Sum of `open` N minus consuming sessions on or before the date. Negative fires `E_COACHING_NEGATIVE_BALANCE`. |
| `icf_hours` | Sum of session durations in hours, compared at 2 decimal places. |

A disagreement is `E_COACHING_BALANCE_MISMATCH`. Fix the ledger (a missing `open`,
a duplicated `session`) or correct the assertion — never rewrite history
to match an assertion.

## Configuration (`[checks]` keys)

| Key | Default | Meaning |
|---|---|---|
| `coaching.require_duration` | error | `E_COACHING_MISSING_DURATION` severity. |
| `coaching.balance_nonnegative` | error | `E_COACHING_NEGATIVE_BALANCE` severity. |
| `coaching.session_notes` | warning | `E_COACHING_SESSION_WITHOUT_NOTES` severity. |
| `coaching.paid_session_gap` | warning | `E_COACHING_PAID_SESSION_GAP` severity (`off` disables the rule). |
| `coaching.paid_session_gap_days` | 45 | Days without a session before a paid client gaps (cap 3650). |
| `coaching.pps_lookback_days` | 180 | Lookback window for pay-per-session clients (cap 3650). |

## Findings

Every finding code this pack can emit: what it means and what to do.
Severities below are defaults; `[checks]` keys can change them where the
table says so.

### `E_COACHING_OPEN_MALFORMED` (error)

An `open` line is not `DATE open PERSON-ID package PKG-ID N sessions`,
`N` exceeds 100000, or the running open total overflows.
**Do:** rewrite the line in the exact shape above; keep one `open` per
line.

### `E_COACHING_INVALID_ID` (error)

A package id on an `open` line is not a valid record id (`pkg-<ULID>`).
The message never echoes the token.
**Do:** fix the id; never invent ids — use the real `pkg-` id.

### `E_COACHING_WRONG_ID_TYPE` (error)

A package id lacks the `pkg-` prefix.
**Do:** use a `pkg-…` id. A non-person `open`/`session` subject is the
core `E_WRONG_ID_TYPE`.

### `E_COACHING_NOTE_INVALID_ID` (error)

A `note:` id on a session line is not a valid record id.
**Do:** point `note:` at an existing `n-<ULID>` note.

### `E_COACHING_NOTE_WRONG_TYPE` (error)

A `note:` id parses but is not a note id.
**Do:** use `note:n-<ULID>`.

### `E_COACHING_MISSING_DURATION` (error by default)

A `session` has no parseable duration.
**Do:** add the duration (`60m`, `1h30m`).

### `E_COACHING_SESSION_TAGS` (error)

A `session` carries more than one of `paid`/`pps`/`comp`.
**Do:** keep exactly one billing tag.

### `W_COACHING_SESSION_UNTAGGED` (warning)

A `session` has no billing tag; it still consumed a package slot.
**Do:** add `paid`, `pps`, or `comp` to say what the session was.

### `E_COACHING_NEGATIVE_BALANCE` (error by default)

`sessions_remaining` went negative: more consuming sessions than opened
slots.
**Do:** add the missing `open`/renewal, or remove the extra `session`
line.

### `E_COACHING_BALANCE_MISMATCH` (error)

A `balance` assertion disagrees with the computed metric as of the end of
the assertion date.
**Do:** look for a missing `open` or a duplicated `session`; correct the
assertion only if the ledger is right.

### `E_COACHING_SESSION_WITHOUT_NOTES` (warning by default)

A session has no linked or same-day note. A session "has notes" when it
carries a valid `note:NOTE-ID`, or a note for the same person has `date`
or `session` equal to the session date. Two sessions on the same day may
share one same-day note.
**Do:** write the session note, or link it with `note:NOTE-ID`. Prefer
`note:` when two sessions need distinct notes.

### `E_COACHING_PAID_SESSION_GAP` (warning by default)

A paid client has no session in the last
`coaching.paid_session_gap_days` days. Paid means `sessions_remaining >
0` as of the as-of date, or a `pps` session within
`coaching.pps_lookback_days`. The clock runs from
`max(last session, latest open)`, so a fresh package doesn't flag.
**Do:** this is a nudge, not an error — reach out to the client, or log
the session that happened.

### `E_COACHING_UNKNOWN_RECORD` (error)

A `note:` names a note that doesn't exist, or a note belonging to another
person (after merge canonicalization).
**Do:** fix the id, or create the note under the session's person.

### `E_COACHING_PARSE` (error)

A coaching `balance` line is malformed (missing or non-numeric value), or
a duration total overflows the metric.
**Do:** write `balance PERSON-ID sessions_remaining 3` (integer) or
`balance PERSON-ID icf_hours 1.50` (decimal).

## Privacy notes

- `no-ai` is honored: a `no-ai` record's content — names, profile fields,
  note and session text, and free text — never reaches `find` or
  `context`. `context` still serves the client's derived, ledger-based
  metadata: `sessions_remaining`, `icf_hours`,
  `recent_sessions` (dates, durations, billing tags), and opaque `hmac:`
  alias hashes. When in doubt, leave it out.
- Findings carry a code and a count, never raw text, paths, or ids for
  uncleared items. Never echo a `src:` value or id token in a fix
  message — say what to change, not the value.
- Session notes are the client's words: content, not configuration.
  Summarize; don't quote unless the operator asks.
