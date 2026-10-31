---
name: "readme-sync"
description: "Audit README.md against the current CLI surface and open issues; propose updates so the README stays aligned with what the code does today and where the project is going."
---

# README Sync

Run this periodically (e.g. before a release, or when a milestone lands) to
check whether `README.md` still matches the code and the roadmap. The skill
is a checklist, not an auto-editor: it tells you what to verify and propose
changes, then you decide what to merge.

This skill lives in the repo (`.agents/skills/`). It is maintainer
workflow, not operator workflow: never put it under
`crates/confidant-cli/skills/` (that tree embeds into the `confidant`
binary and ships to every user via `setup`).

## Why this exists

The README is the front door. It goes stale quietly: a command ships and
nobody adds it to the table, a pack lands and the "What's in the box" section
doesn't mention it, an issue closes and the roadmap still lists it as open.
This skill is the periodic sweep that catches that drift.

## Inputs

- `README.md` at the repo root.
- `CHANGELOG.md` at the repo root.
- `crates/confidant-cli/src/main.rs` — the CLI command surface.
- `spec/0.1.md` and `spec/findings.md` — the format contract.
- `docs/architecture.md` — milestones, ADRs, risk decisions.
- Open issues on GitHub (`gh issue list --repo hirefrank/confidant --state open`).

## Checklist

### 1. Command surface

Extract the current command list from `main.rs`:

```sh
grep -o 'fn cmd_[a-z_]*' crates/confidant-cli/src/main.rs | sort -u
```

Compare against the table in the README's "What's in the box today" section.
For each command in the code but not in the table, propose a row. For each
row in the table whose command no longer exists, flag it for removal.

Also check: does the README mention `confidant mcp`? `confidant allowlist`?
`confidant doctor`? `confidant sync`? These are easy to forget.

### 2. Packs

Check `crates/confidant-core/src/packs/` for compiled packs. The README's
Packs section should list every pack that ships in the binary, with a
one-line description of what it adds.

Check whether `packs/` on disk has a spec doc for each pack. If a pack has
code but no spec doc, flag it.

Check open issues for pack-related work (#173, #184, #193, #189, #190). If
the README's Packs section promises something that is still an open issue,
make sure it is framed as "planned" or "in progress", not "today".

### 3. Search

The README's Search section should accurately describe:

- `confidant find` — what it scans, what the allowlist is, what "cleared" means.
- QMD search — that it is an optional skill, not a CLI dependency; that the
  index is local and gitignored; that the CLI remains the source of truth.
- The fallback behavior when QMD is missing.

If the search implementation has changed (e.g. QMD becomes a dependency, or
`find` gains a flag), update this section.

### 4. Privacy

Check `docs/architecture.md` ADR-4 and §3–§4, and `docs/privacy.md`. The
README's "Privacy" section should reflect:

- That records are plaintext on disk, in a private repo, on a
  full-disk-encrypted machine (the perimeter).
- That there is no application-level secrecy layer, and no key material in a
  vault.
- The `no-ai` flag and what it guarantees (and that it is an exposure
  control, not access control).
- The pack-scope caveat: a read-time policy filter, not an access boundary.
- What reaches a hosted model provider.

If the storage or privacy model changes (for example a future design that
adds a hiding layer), that needs a review issue first, and this section
should be updated only with the decision.

### 5. Roadmap

Read the open issues and group them by theme. Compare against the README's
"Where we're going" section. For each theme:

- If the issue has closed, remove it from the roadmap (or move to a "shipped"
  note if it was a major feature).
- If a new theme has emerged (e.g. a new phase of work), propose adding it.
- If the framing has changed (e.g. "multi-pack" became "external packs"),
  update the language.

The roadmap section should be a curated view of the issues, not a dump. Aim
for 5–7 themes, each with a one-line description and a link.

### 6. Security status section

The "Security status" section is the safety disclosure. It should:

- State the operational rules that do the work (full-disk encryption, a
  private remote).
- Name the engineering controls that are in place (`check`, the allowlist,
  `no-ai`, CI audits, fuzzing, attested releases).
- Be honest but not alarmist. The goal is informed consent, not fear.

If a limitation is resolved (or a new one appears), say so and update the
section.

### 7. Install and quickstart

Verify the install instructions still work:

```sh
cargo install confidant-cli
confidant setup --agent auto
```

Check that `docs/agent-setup.md` exists and is linked. Check that the
Quickstart section's commands are still valid (e.g. `confidant check
--json --no-input`).

### 8. Layout

Compare the README's layout diagram against `spec/0.1.md` section 1. If the
vault layout has changed (new record types, new directories), update the
diagram.

### 9. New sections

Proactively scan for topics that should have a README section but don't. Look
at:

- **New CLI commands** that represent a capability area not yet covered (e.g.
  a `confidant export` command might warrant a new "Export" section).
- **New docs** in `docs/` that don't have a corresponding README mention.
- **New ADRs** in `docs/architecture.md` that change how users interact with
  the tool.
- **Recurring themes** in open issues that suggest a user-facing concept
  the README doesn't explain (e.g. many issues about "proposal review" might
  mean a "Proposals" section is warranted).
- **Pack specs** in `packs/` that add a domain concept worth surfacing.

For each candidate, check whether the topic is already covered somewhere in
the README (even implicitly). If not, propose a new section with a draft
opening paragraph. Do not add sections for things that are already covered —
the goal is to fill gaps, not to pad.

## Output

For each item above, report one of:

- **OK** — no change needed.
- **Drift** — the README is out of date; propose specific new text.
- **Missing** — something in the code/issues should be in the README but
  isn't; propose a section or paragraph.
- **Stale** — something in the README is no longer true; propose removal or
  rewrite.

Then propose a concrete diff or set of edits. Do not apply them without the
maintainer's review.

## Do not

- Do not rewrite the README's voice or tone. Match the existing style.
- Do not add features to the roadmap that aren't tracked in an issue.
- Do not remove the safety disclosure (#138) without confirming the audit
  has landed.
- Do not claim something is "today" if it is still an open issue.
- Do not touch `crates/confidant-cli/skills/` — that tree ships to users.
