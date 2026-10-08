# Borrowing from cr

Confidant is a new codebase. [cr](https://github.com/AnandChowdhary/cr) at
`f29f8d4` (MIT, Copyright 2026 Anand Chowdhary) was the closest prior art.
The decision to build rather than fork is ADR-13; the spike is
`research/cr-spike-2026-10-07.md` in the architecture discussion.

Adapted source (MIT header on each file, full text in
[`THIRD_PARTY_LICENSES`](../THIRD_PARTY_LICENSES)):

- Domain errors and JSON error envelopes
- Check report types (`Severity`, stable codes, `--fail-on`)
- Symlink-refusing path walk and atomic replace

Re-implemented patterns, credited here rather than copied:

- Collect findings; never abort the rest of a damaged vault
- Crash-safe publish via rename
- Classify by typed error, never by message text

Not taken: cr's audit hash chain, YAML-front-matter-as-truth `Database`,
field-level encryption, sync adapters, server, or UI.

Milestone 1 does not adapt cr's record-bound AEAD. That waits for the
milestone 2 crypto design review (architecture section 9b).
