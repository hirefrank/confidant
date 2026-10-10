---
name: "capture-gap-summary"
description: "Weekly operator-facing summary of capture gaps: sessions with no notes and paid clients with no recent session (E_SESSION_WITHOUT_NOTES, E_PAID_SESSION_GAP). Read-only; writes nothing."
---

# Capture-gap summary

## Purpose
Confidant only knows what agents write into it (architecture §9b item
3). This skill surfaces what's missing: sessions with no notes, and paid
clients with no session inside the gap window. Run it weekly and send the
summary to the operator.

## Workflow
1. Run the script (it only reads — it runs `confidant check --json` and
   filters the two gap codes). It writes to stdout by default; never
   point `--out` at `/tmp` (world-readable):
   ```sh
   python3 skills/capture-gap-summary/bin/capture-gap-summary.py \
       --vault "$VAULT"
   ```
   Options: `--as-of YYYY-MM-DD` to evaluate the gap rules at a date,
   `--fail-on-gaps` to exit 1 when gaps exist (useful for scheduled runs),
   `--cli PATH` if the `confidant` binary isn't on PATH, `--out` to save
   the summary somewhere ignored (e.g. under `$VAULT/.confidant/`).
2. Review the summary. Every item names an opaque ID, the file
   and line, the finding message, and the suggested fix — nothing private
   beyond the vault's own IDs.
3. Send the summary to the operator (chat, email, however you reach
   them). This skill never writes to the vault, so there is nothing to
   confirm — but don't spam: weekly, or when `--fail-on-gaps` fires in a
   scheduled run.

## Operating Rules
1. Read-only. This skill never proposes or applies vault writes.
2. Branch on finding `code`, never on message text (spec: codes are
   stable; messages are not).
3. The gap rules live in the `[checks]` config (`coaching.session_notes`
   severity, `coaching.paid_session_gap_days` window) — this skill reports
   what `check` finds; it doesn't reimplement the rules.
