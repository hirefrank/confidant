# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0: breaking changes bump the minor, fixes bump the patch.

## [Unreleased]

## [0.4.0] - 2026-10-16

**Disclosure:** the milestone 2 encryption has had no outside review
([#138](https://github.com/hirefrank/confidant/issues/138)). Do not put
other people's client data in a vault until the audit lands.

### Added
- `confidant record edit <id> --file F`: replaces a record's file through the
  normal write pipeline (encrypted writes, `check`-gated, one commit), and
  `confidant record show <id> --for-edit`, the operator-only read that supplies
  the current text and decrypts `no-ai` records for editing (#216). An edit
  that resolves a record to another client's key prints a notice and reports
  `rekeyed` (#418); changing a person's effective `no-ai` mode re-stamps their
  existing children in the same commit (#410). The write layer gained
  `WriteOutcome::Unchanged`, so an edit that changes nothing reports
  `unchanged` and commits nothing. The for-edit read is kept away from agents
  by the MCP tool whitelist, not by access control (#412, #419).
- `confidant tui` subcommand: launches `confidant-tui` from `PATH` with
  arguments and environment passed through (an explicit `--vault` is
  forwarded too); prints a `cargo install confidant-tui` hint when the
  binary is missing (#363).
- `confidant-tui` published to crates.io (it keeps shipping as a GitHub
  Releases binary as well) (#363). New Search tab, QMD-backed with provenance
  and an exact-match toggle, and an inbox review tab with confirm-before-apply
  (#212).
- `confidant doctor` reports whether qmd semantic search is available
  (informational only; it never warns or fails) (#386).
- `confidant update` detects the install method from the binary path and, in
  an interactive terminal, offers to run the update and then to re-run
  `setup`; `setup` offers `confidant check` or prints the `CONFIDANT_VAULT`
  export line (#376). JSON gains additive `install_method`,
  `update_command`, and `next_steps` fields.
- Pack manifests: each pack's claims (name, verbs, record types, fields,
  balance metrics, edge kinds, finding codes, `[checks]` keys and defaults,
  and finding message templates) now come from `packs/<name>/manifest.toml`
  instead of hardcoded Rust slices, with parity tests against the vendored
  copy in `confidant-core` (#295, #343, #345, #346).
- CI checks for build-time include paths escaping the crate directory (the
  v0.3.0 `cargo publish` break, #367), extended to `concat!`/`env!` forms with
  a `--self-test` (#377), and a sync test that
  `crates/confidant-cli/pack-skills/` matches `packs/*/SKILL.md` (#375).

### Changed
- TUI rendering layer restyled: a semantic theme, rounded bordered blocks, tab
  pills, and status badges; no logic or keybinding changes (#378). The Find
  and Search tabs merged into one Search tab with an exact-match toggle
  (#387).
- Spec: edge front matter now has a closed key set (`id`, `type`, `a`, `b`,
  `kind`, `since`, `until`); an unknown key is `E_FRONTMATTER` (#390), and the
  error names no key so free text cannot reach logs (#397).
- Spec: an edit writes the canonical form, and a stored envelope is reused
  only when the effective `no-ai` header still matches, so a stale header is
  re-encrypted rather than kept (#406). §13 and the agent threat model state
  the for-edit read's limit (#419); re-stamping looks forward only (#426).
- Spec: the `E_IDEMPOTENCY_CONFLICT` row describes when the code is emitted,
  not a reservation (#415).
- Documentation: pack-manifest spec nits (#352), release learnings in
  `AGENTS.md` (#373), and a stale `read_progress` doc line removed (#358).

### Fixed
- `check`: a body-only conflicted record stays parseable (#417), a conflicted
  file reports `E_MERGE_CONFLICT` without the derived `E_FRONTMATTER` parse
  error (#391), and `E_DANGLING_REF` is suppressed for conflicted records
  (#396).
- `is_trusted_component` trusts `edges`/`edge.md` again (#392).
- The Windows build compiles: `copy_dir` is gated with `cfg(unix)` (#402).
- Inbox: an encrypted write that fails mid-batch reverts the empty
  `people/<id>/` directory it created (#398, #401).
- A write's `files` list and the commit diff agree (#425), and the
  unreadable-file refusal lists record files only (#424).
- qmd probe pipe drain and the Find/Search toggle nits from #414 (#416), and
  the staged shred guard can no longer be skipped by an early return (#353).

## [0.3.1] - 2026-10-15

### Fixed
- `cargo install confidant-cli` / crates.io publish: vendor pack `SKILL.md`
  files under `crates/confidant-cli/pack-skills/` so `include_dir!` compiles
  inside the published tarball (the repo-root `packs/` tree is not shipped).

## [0.3.0] - 2026-10-15

**Disclosure:** the milestone 2 encryption has had no outside review
([#138](https://github.com/hirefrank/confidant/issues/138)). Do not put
other people's client data in a vault until the audit lands.

### Added
- Multi-pack loading: shared `Pack` trait, conflict and orphan handling, and
  per-pack access scoping for agent-facing reads (#177, #178).
- `personal@0.1` schema pack: `birthday` / `cadence` / `relationship_to_me`
  / `dates` person fields, personal relationship edge kinds (`friend`,
  `family`, `sibling`, `partner`, `parent`, `mentor`), the `touch` ledger
  verb (with `confidant log touch`), and two warning-level nudges that never
  block writes: `W_CADENCE_OVERDUE` and `W_DATE_UPCOMING` (#184, #182).
- Relationship edges and multi-person `with:` interactions across packs (#259).
- Read-only TUI (`confidant-tui`) with `Check`, `Find`, `Context`, and
  `Doctor` views, plus Phase 2 proposal review and apply — all via the ADR-7
  CLI `--json --no-input` contract (#210, #211, part of #205). Ships as a
  GitHub Releases binary (#218); not on crates.io.
- `inbox --skip <item>` to defer intake items without draining (#217).
- Encrypted inbox drain and `log session --note --fallback-inbox` (#260).
- Automatic per-person client key creation when a person is added (#222).
- Pack manifest format in the spec; manifest types, loader, and validation in
  core (#340, #341). Pack-versioning policy and reserved `E_PACK_VERSION`
  (#190).
- Per-pack `SKILL.md` served by the CLI and MCP (#189).
- Finer `no-ai` granularity: `notes` inheritance mode and inheritance from
  any front-matter person reference (#181, #270).
- `log session` without a device key when there is no `--note` (#176).
- `cargo-fuzz` harnesses for the ledger parser and §14 envelope decoder (#235).
- OpenSSF Scorecard workflow and badge; `SECURITY.md` and Dependabot (#233,
  #236). CII / OpenSSF Best Practices passing-level self-assessment (#237).

### Changed
- Bumped the workspace MSRV from 1.85 to **1.88** and upgraded the TUI stack
  to `ratatui 0.30` + `crossterm 0.29` (#275).
- Key ceremonies use staged atomic `keys/` swaps for `device-add`, `revoke`,
  `init-client`, `rotate`, and `shred` (#175, #220, #339). Shred strips the
  shredded person from other records' `with:` lists and uses fail-closed
  working-tree updates (#258, #336).
- `context` strips pack-private fields via `Pack::private_context_fields()`
  instead of a hardcoded pack name (#302).
- Documentation: README and agent-setup refresh; agent threat model (#187,
  #192, #231). Warnings never block writes (#183).

### Fixed
- Validate operator recovery material as hex, not age Bech32 (#254).
- AAD path spelling on Windows (#285). Inbox path canonicalization before
  `git add` / `reset` on Windows verbatim paths (#274).
- `check` missing-edge-kind fix lists closed kinds (#299).
- TUI: hardened proposal scratch/progress file handling; corrupt progress
  files warn instead of silently resetting (#349, #350).

## [0.2.0] - 2026-10-13

### Added
- Skills ship inside the `confidant` binary and install with
  `confidant setup --agent auto` — no repo checkout needed. New commands:
  `setup`, `update`, `agents`, `which`, `routing`. `doctor` reports
  `skills-links` health instead of the old `CONFIDANT_REPO` checkout
  staleness check (supersedes #164/#166/#167). Skills and CLI are
  version-locked: one `confidant --version` covers both.

## [0.1.1] - 2026-10-12

Patch: `confidant doctor` staleness checks, agent-setup docs, and the
changelog itself. First release published through crates.io trusted
publishing (no API token).

### Added
- `confidant doctor` staleness checks: warning-only `cli-staleness` and
  `skills-staleness` against the latest GitHub Release, with a
  `CONFIDANT_OFFLINE=1` opt-out and README/privacy disclosure (#165, #168).
- Agent setup docs (`docs/agent-setup.md`) with a copy/paste install prompt;
  skills checkouts pin to release tags, never main (#164, #166, #167).

## [0.1.0] - 2026-10-12

First crates.io publish: `confidant-crypt`, `confidant-core`, and
`confidant-cli` (the `confidant` binary; `cargo install confidant-cli`).
The GitHub Release carries prebuilt binaries, shell installers, and
build-provenance attestations.

**Disclosure:** the milestone 2 encryption has had no outside review
([#138](https://github.com/hirefrank/confidant/issues/138)). Do not put
other people's client data in a vault until the audit lands.

### Added
- Encrypted writes: `record add`, `note add`, and `log session --note`
  emit §14 envelopes on keyed vaults; inbox `RecordWrite` fails closed
  rather than writing plaintext (#148).
- Encrypted reads: `find` and `context` decrypt through the CLI with
  `skipped_encrypted` / `refused_envelopes` counts; `no-ai` records are
  never decrypted (#148).
- Key lifecycle: `init`, `recover`, `keys init-client` / `rotate` /
  `revoke` / `shred`, the `keys device-add` ceremony, and shred-coupled
  inbox rotation (#148, #66, #105).
- `confidant reindex`: builds the QMD search corpus through the CLI from
  the §12 cleared set; `keys shred` deletes the local search index (#37).
- `confidant allowlist` (the §12 cleared set for index-time exclusion),
  `doctor` health checks, the MCP server, and the coaching schema pack.

[Unreleased]: https://github.com/hirefrank/confidant/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/hirefrank/confidant/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/hirefrank/confidant/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/hirefrank/confidant/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hirefrank/confidant/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hirefrank/confidant/releases/tag/v0.1.1
[0.1.0]: https://github.com/hirefrank/confidant/releases/tag/v0.1.0
