# Demo vault

**FAKE data only.** No real names, emails, phone numbers, or notes.

This is one operator's relationship memory, personal first. The roster is
everyday life — a friend, family, a partner, a mentor — with birthdays,
keep-in-touch cadences, relationship edges, and `touch` ledger lines for
calls, texts, meals, and meetings.

The built-in `personal@0.2` pack is implicit: it is enabled without being
listed in `packs = [...]`. The `[checks]` block sets the personal nudge
keys and pins `as_of = "2026-10-08"` so the demo findings stay stable.

## What `check` shows, and why

The vault is healthy (`ok: true`, zero errors) and deliberately reports two
warning-level nudges — the teaching content for the personal pack:

- `W_CADENCE_OVERDUE` for Dana Example, whose 21-day cadence has no
  touchpoint on or after 2026-09-17 (the last was 2026-09-10). This is the
  "reach out to someone" nudge.
- `W_DATE_UPCOMING` for Eli Sample, whose `--10-12` birthday is four days
  after `as_of`. This is the "a date is coming up" nudge.

Warnings never fail `check` under the default `--fail-on error`, so the CI
step exits 0. Use `confidant check --fail-on warning` to see the demo fail
on purpose.

Used by tests, docs, and `confidant check` in CI.
