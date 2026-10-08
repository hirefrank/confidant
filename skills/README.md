# Confidant integration skills

Agent skills and small scripts that pull outside events into the vault (ADR-8).
There is no plugin system in v0: the **agent** runs these, calling the CLI's
agent contract (ADR-7).

## The uniform workflow

Every skill follows the same shape:

1. **Propose.** The agent runs the skill's script. The script reads the
   source data and the vault, computes the delta, and prints a
   human-readable summary plus a machine-readable **proposal manifest**
   (JSON) under `<vault>/.confidant/proposals/` (gitignored scratch —
   the manifest is plaintext PII). The script refuses unless that dir is
   git-ignored (same `check-ignore` refusal as the QMD skill), creates it
   `0700`, and writes the manifest and lines file `0600`. Next to the manifest the script writes
   a flat **lines file** (`.cfd`) with the proposed ledger lines, one per
   line. Scripts never write to the vault. The manifest carries a
   `request_id` — a fresh ULID generated once per proposal; retries reuse
   the manifest's stored value, never regenerate it.
2. **Confirm.** The agent shows the logical change (ledger lines, record
   diffs) to the human and gets explicit approval. No approval, no write.
3. **Apply.** The agent applies the approved change through the CLI:
   - Ledger lines: `confidant import --file <lines_file> --request-id
     <request_id from manifest> --dry-run --json --no-input` first, then
     the real run. (`import --file` reads ledger lines and routes each
     to its month file itself.) One commit per write; `check` runs
     before every commit and a failing check blocks the write (ADR-7).
   - Notes: one `confidant note add --person <id> --date <date>
     --body-file <body> --request-id <note_request_id>` per note record.
     Bodies are pre-staged by the proposer next to the manifest
     (`body_file` in the manifest, mode 0600 — never `/tmp`), and each
     note carries its own `request_id` ULID in the manifest so a retried
     apply doesn't duplicate notes.
   - Person/deal/interaction records: **pre-M2 only** — hand-create the
     files from the manifest's `records[]`, then `confidant check
     --json` before committing. **Post-M2** (the manifest's
     `records_blocked` is true): do NOT hand-write records; they need
     `confidant record add --file`, which does not exist yet. Hand-
     writing into an encrypted vault would commit plaintext PII to git.
     The scripts detect this via an `enc:` envelope scan of the vault.
4. **Clean up.** Delete the whole proposal set (manifest, lines file,
   staged note bodies) after a successful apply — all plaintext PII.
   (Lightfield: `--cleanup` takes `--manifest` and deletes the export
   and the whole proposal set together; also run `--record-applied
   --manifest` so reruns skip what's applied.)

## Skills

| Skill | Source | Writes |
|---|---|---|
| `portal-sync/` | Coaching portal events (JSONL) | `open` (renewals), `stage` (checkouts sent, lost deals), all with `src:portal/<event-id>` |
| `transcript-import/` | Transcript metadata (JSON) | Interaction record + `session` line with duration and `src:transcript/<id>` |
| `lightfield-import/` | Lightfield export (JSON) | Person/deal/note/interaction records + ledger lines, `src:lightfield/<id>` |
| `capture-gap-summary/` | `confidant check --json` | Nothing — operator-facing summary of `E_SESSION_WITHOUT_NOTES` / `E_PAID_SESSION_GAP` |

## Shared helper

`bin/common.py` holds the small shared pieces: ULID generation, `src:`
provenance scanning, record-ID validation, and proposal-manifest writing.
Scripts load it via a `sys.path` entry pointing at `skills/bin/`.

## Provenance and idempotency

Every imported ledger line carries `src:<namespace>/<id>` (`portal`,
`transcript`, `lightfield`). The scripts skip events whose `src:`
already appears in the vault, so re-running an import adds nothing;
`E_DUPLICATE_SRC` is the backstop. Contacts and notes never get ledger
lines, so lightfield-import keeps a second dedup record: a local map at
`<vault>/.confidant/lightfield-import-map.json` holding opaque
`lf-id → vault-id` pairs only (no PII), updated by `--record-applied`
after the apply. Each proposal also carries a `request_id` — a fresh
ULID stored in the manifest — for the CLI's HMAC idempotency (ADR-7);
reuse the manifest's value on retry.

## Privacy

- Nothing private ever flows back out to a source system. Imports are
  pull-only.
- Proposal manifests are **plaintext PII** (names, emails, phones, notes,
  transcripts). They live under `<vault>/.confidant/proposals/`
  (gitignored, never committed) and are deleted after the apply. The
  scripts refuse to write a proposal unless that dir is git-ignored in
  the vault, create it `0700`, and write the manifest, lines file, and
  staged note bodies `0600`.
- The Lightfield export is **plaintext PII**: it is never committed, never
  copied into the vault, and the import script deletes it after a verified
  import.
- The scripts never invent data: bad rows are warned and skipped, never
  defaulted (no invented dates, stages, verbs, or IDs).
- Commit messages and trailers carry only opaque IDs, verbs, and hashes —
  never names or free text (ADR-7).
