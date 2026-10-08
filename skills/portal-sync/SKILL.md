---
name: "portal-sync"
description: "Pull coaching-portal events (renewals, sent checkouts, lost deals) into the vault as ledger lines with src:portal/<event-id> provenance. Proposes; the human confirms before anything is written."
---

# Portal sync

## Purpose
Import portal events into the vault idempotently. Renewals become `open`
lines, sent checkouts and lost deals become `stage` lines, every line
carrying `src:portal/<event-id>` provenance. Re-running with the same input
adds nothing.

## Inputs
A JSONL file of portal events (one object per line):

```json
{"event_id": "evt-001", "type": "renewal", "occurred_at": "2026-10-08", "person_id": "p-…", "package_id": "pkg-…", "sessions": 6}
{"event_id": "evt-002", "type": "checkout_sent", "occurred_at": "2026-10-08", "deal_id": "d-…"}
{"event_id": "evt-003", "type": "deal_lost", "occurred_at": "2026-10-08", "deal_id": "d-…"}
```

Only `renewal`, `checkout_sent`, and `deal_lost` are mapped. Unknown types
are skipped with a warning — the skill never invents ledger verbs
(`E_UNKNOWN_VERB`).

## Workflow
1. Run the proposer (it never writes to the vault):
   ```sh
   python3 skills/portal-sync/bin/portal-sync.py --vault "$VAULT" \
       --events portal-events.jsonl
   ```
   The manifest and the flat ledger-lines file land in
   `<vault>/.confidant/proposals/` (gitignored scratch — the paths are
   printed). Already-imported events (matching `src:portal/<id>`) are
   skipped: re-running adds nothing.
2. Read the printed summary and warnings. Resolve warnings first
   (unknown event types, bad IDs, targets with no record file yet —
   those would be `E_UNKNOWN_RECORD`).
3. Show the human the logical change: the ledger lines per month file
   (the manifest's `ledger` section). Get explicit approval before
   writing.
4. Apply through the CLI (ADR-7 contract), dry run first:
   ```sh
   confidant import --file <lines_file from manifest> \
       --request-id <request_id from manifest> --dry-run --json --no-input
   # human reviews the dry-run, then:
   confidant import --file <lines_file> \
       --request-id <request_id from manifest> --json --no-input
   ```
   The request id is a fresh ULID generated once per proposal and stored
   in the manifest — reuse the manifest's value on retry, never
   regenerate it for the same proposal. (`import --file` reads ledger
   lines and routes each to its month file itself; the lines file is the
   flat companion the proposer wrote next to the manifest.)
5. Delete the manifest after a successful apply — it is plaintext PII:
   ```sh
   rm <manifest path from step 1>
   ```
6. Safe retries: if the apply step is interrupted, re-run the proposer
   and re-apply — already-imported events are skipped via their `src:`
   provenance, and the manifest's `--request-id` makes the CLI run
   idempotent (`E_IDEMPOTENCY_CONFLICT` on reuse with different content).

## Operating Rules
1. Nothing private flows back to the portal. Imports are pull-only.
2. Never invent verbs, IDs, or package sizes. Bad input is a warning and
   a skip, not a guess.
3. Commit messages and trailers carry only opaque IDs, verbs, and hashes
   (ADR-7) — never names or amounts in prose.
4. `E_DUPLICATE_SRC` on `check` means an event was imported twice: keep
   one line, following the finding's fix guidance.
