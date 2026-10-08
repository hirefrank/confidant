---
name: "transcript-import"
description: "Import a session transcript (any source) as an encrypted interaction entry plus a session ledger line with duration and src:transcript/<id> provenance. Proposes; the human confirms before anything is written."
---

# Transcript import

## Purpose
Turn a recorded session into vault state: one interaction record (the
notes/prose) and one `session` ledger line with duration — duration feeds
the coaching pack's `icf_hours` metric. Source-agnostic: Confidant doesn't
care which tool recorded the transcript (architecture §9 Q3).

## Inputs
A descriptor JSON file:

```json
{
  "transcript_id": "t-abc123",
  "source": "google-drive",
  "person_id": "p-…",
  "date": "2026-10-08",
  "duration_minutes": 60,
  "billing": "paid",
  "title": "Coaching session",
  "notes": "prose for the interaction body (optional)",
  "transcript_path": "/path/to/transcript.txt (optional, used when notes is absent)"
}
```

`billing` is **required** (`paid`, `pps`, or `comp`) — the script will not
silently pick a package-consuming default.

## Workflow
1. Run the proposer (it never writes to the vault):
   ```sh
   python3 skills/transcript-import/bin/transcript-import.py --vault "$VAULT" \
       --descriptor t-abc123.json
   ```
   The manifest and the flat ledger-lines file land in
   `<vault>/.confidant/proposals/` (gitignored scratch — the paths are
   printed). Already-imported transcripts (matching
   `src:transcript/<id>`) are skipped: re-running adds nothing.
2. Review the summary and warnings. A missing person record would be
   `E_UNKNOWN_RECORD` — create the person first or fix the ID.
3. Show the human the logical change: the new interaction file and the
   session line. Get explicit approval.
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
   regenerate it for the same proposal.
5. The interaction record: **pre-M2 only**, hand-create the file from the
   manifest's `records[]`, then run `confidant check --json` to validate
   before committing (one commit). **Post-M2** (the manifest's
   `records_blocked` is true — the vault looks encrypted): do NOT
   hand-write the record; it needs `confidant record add --file`, which
   does not exist yet. Writing it by hand would commit plaintext PII to
   git.
6. Delete the manifest after a successful apply — it is plaintext PII:
   ```sh
   rm <manifest path from step 1>
   ```
7. Copies left in the hosted store (e.g. Google Drive) are outside
   Confidant's privacy guarantee. Deleting them after import is the
   operator's call (§9 Q3) — ask the human; never delete silently.

## Operating Rules
1. One transcript → one interaction + one session line. Never split or
   merge transcripts without being asked.
2. The interaction body is prose, never structured facts (ADR-2). Facts
   (duration, billing, date) live on the ledger line.
3. `billing` comes from the human or the descriptor, never from a default.
4. The generated interaction ID is a fresh ULID; never reuse an ID.
