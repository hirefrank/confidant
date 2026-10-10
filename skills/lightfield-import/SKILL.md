---
name: "lightfield-import"
description: "Best-effort import of a Lightfield export (contacts, deals, notes, transcripts) into the vault. The export is plaintext PII: never committed, deleted after a verified import. Proposes; the human confirms before anything is written."
---

# Lightfield import

## Purpose
Migrate off Lightfield (architecture Appendix A): contacts, deals, meeting
notes, and transcripts become vault records and ledger lines. Best-effort —
transcripts and notes are the must-have, everything else is a bonus.

## Privacy — read this first
The Lightfield export is **plaintext PII**.
- Keep it on a trusted device. Never commit it. Never copy it into the
  vault or the repo.
- After the import is applied **and** `confidant check` passes, delete the
  export **and the whole proposal set** (manifest, lines file, staged note
  bodies — all plaintext PII):
  ```sh
  python3 skills/lightfield-import/bin/lightfield-import.py \
      --cleanup --export /path/to/export.json --manifest <manifest path> \
      --i-verified-the-import
  ```
  `--cleanup` refuses to run without the explicit verification flag.

## Inputs
A JSON export file (documented schema; unknown fields are ignored, bad
rows are warned and skipped):

```json
{
  "contacts": [{"id": "lf-c-1", "name": "Ada Example", "emails": ["a@x.co"], "phones": ["+1…"], "notes": "…"}],
  "deals": [{"id": "lf-d-1", "contact_id": "lf-c-1", "title": "…", "stage": "proposal", "date": "2026-09-01", "notes": "…"}],
  "notes": [{"id": "lf-n-1", "contact_id": "lf-c-1", "date": "2026-09-01", "text": "…"}],
  "transcripts": [{"id": "lf-t-1", "contact_id": "lf-c-1", "date": "2026-09-02", "duration_minutes": 60, "billing": "paid", "text": "…"}]
}
```

## Workflow
1. Run the proposer (it never writes to the vault, and never touches the
   export except reading it):
   ```sh
   python3 skills/lightfield-import/bin/lightfield-import.py --vault "$VAULT" \
       --export /path/to/export.json
   ```
   The manifest and the flat ledger-lines file land in
   `<vault>/.confidant/proposals/` (gitignored scratch — the paths are
   printed), plus a `notes/` dir next to the manifest holding the staged
   note bodies (0600, for `note add --body-file`).
2. Review the summary and warnings carefully:
   - **Person matching** is best-effort (exact display-name match links
     to an existing person; otherwise a new person record is proposed).
     Verify every match and merge duplicates with a `merge` line if needed.
   - **Alias candidates** (emails/phones) are held in the manifest only —
     the keyed HMAC needs the milestone 2 vault lookup key, so they cannot
     become ledger lines yet. Add them via the agent/CLI afterwards.
   - Rows already imported are skipped: deals and transcripts via their
     `src:lightfield/<id>` ledger lines; contacts and notes via the local
     dedup map (`<vault>/.confidant/lightfield-import-map.json`, opaque
     lf-id → vault-id pairs only, no PII).
   - Bad rows are warned and skipped — the importer never invents dates
     or stages.
3. Show the human the logical change: new records and ledger lines. Get
   explicit approval.
4. Apply through the CLI (ADR-7 contract). First the ledger lines, dry
   run first:
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
5. Notes, one `note add` per note record in the manifest. The proposer
   stages each body next to the manifest (`<stem>/notes/<note_id>.md`,
   mode 0600 — never `/tmp`, which is world-readable) and records the
   path as the note record's `body_file`. Each note also carries its own
   `request_id`: a fresh ULID per note, stored in the manifest — reuse
   the manifest's value on retry, never regenerate it, and never reuse
   one id across different writes (that would trip
   `E_IDEMPOTENCY_CONFLICT`):
   ```sh
   confidant note add --person <person_id> --date <date> \
       --body-file <body_file from the note record> \
       --request-id <note's request_id from the manifest> --json --no-input
   ```
   (Omit `--person` when the note record's `person` is null. Add
   `--no-ai` when the note record's `no_ai` is true — the proposer sets
   it from the export row's `"no-ai"` or from a no-ai contact.)
6. Person/deal/interaction records: **pre-M2 only**, hand-create the
   files from the manifest's `records[]`, then run
   `confidant check --json` to validate before committing (one commit).
   **Post-M2** (the manifest's `records_blocked` is true — the vault
   looks encrypted): do NOT hand-write them; they need
   `confidant record add --file`, which does not exist yet. Writing them
   by hand would commit plaintext PII to git.
7. Record the applied IDs in the dedup map (so reruns skip what's
   applied):
   ```sh
   python3 skills/lightfield-import/bin/lightfield-import.py --vault "$VAULT" \
       --record-applied --manifest <manifest path>
   ```
8. After `check` passes on the applied import, delete the export **and
   the whole proposal set** (manifest, lines file, staged note bodies —
   all plaintext PII):
   ```sh
   python3 skills/lightfield-import/bin/lightfield-import.py --vault "$VAULT" \
       --cleanup --export /path/to/export.json --manifest <manifest path> \
       --i-verified-the-import
   ```
   `--cleanup` refuses to run without the explicit verification flag.
   Then delete any local copies you made.

## Operating Rules
1. The export file is plaintext PII: never commit it, never move it into
   the vault, never attach it to issues or PRs.
2. Best-effort means best-effort: warn and skip what doesn't parse; never
   invent IDs, stages, or dates to fill gaps.
3. `billing` on transcript sessions comes from the export or the human,
   never from a default.
4. Deleting the export happens only after a verified import, and only
   with the explicit flag.
