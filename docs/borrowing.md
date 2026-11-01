# Borrowing from cr

Confidant is a new codebase. [cr](https://github.com/AnandChowdhary/cr) at
`f29f8d4` (MIT, Copyright 2026 Anand Chowdhary) was the closest prior art.
The decision to build rather than fork is ADR-13; the spike is
`research/cr-spike-2026-10-07.md` in the architecture discussion.

Adapted source (MIT header on each file, full text in
[`THIRD_PARTY_LICENSES`](../THIRD_PARTY_LICENSES)):

- Domain errors and JSON error responses
- Check report types (`Severity`, stable codes, `--fail-on`)
- Symlink-refusing path walk and atomic replace. Unix (including macOS)
  uses cr's `openat` / `O_NOFOLLOW` walk; the portable `symlink_metadata`
  fallback is compiled only for non-Unix targets.

Re-implemented patterns, credited here rather than copied:

- Collect findings; never abort the rest of a damaged vault
- Crash-safe publish via rename
- Classify by typed error, never by message text
- CLI `print_error` JSON/human response shapes (`--json` errors on stdout)

Not taken: cr's audit hash chain, YAML-front-matter-as-truth `Database`,
field-level secrecy layer, sync adapters, server, or UI.
