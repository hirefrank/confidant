# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0: breaking changes bump the minor, fixes bump the patch.

## [Unreleased]

### Added
- Headless `keys device-add --initiate`: `CONFIDANT_DEVICE_KEY` is this
  device's identity (same as `init`). The command emits that pubkey and
  does not write a keychain. Without an env identity and without a
  reachable keychain it fails closed and names `age-keygen` (#684).

### Changed
- `--initiate` no longer refuses when `CONFIDANT_DEVICE_KEY` is set (#153
  nit 4). `--from-request` still refuses a previously-seen pubkey. `keys
  shred` still refuses the env override.

### Fixed
- `init --dry-run` now runs the same key-source preflight as a real init:
  a keyless headless host (no OS keychain, no `CONFIDANT_DEVICE_KEY` /
  `CONFIDANT_OPERATOR_KEY`) is refused, and dry-run reports whether an
  existing repo on `master` will be left alone (#682, #661).
- `doctor` skills-links now resolves `$HOME` / `CONFIDANT_HOME` / skill
  symlink targets to absolute paths, so a run from inside the vault agrees
  with `setup` and `agents` instead of reporting `linked 0/2` (#681).

## [0.6.1] - 2026-10-19

**Disclosure:** the milestone 2 encryption has had no independent review and
none is scheduled ([#138](https://github.com/hirefrank/confidant/issues/138));
use your own judgment before storing other people's sensitive data.

**Breaking (shipped as a patch by maintainer decision):** the shipped
`packs/coaching/` asset and the four operator-specific embedded skills are
gone. A vault that lists `coaching@0.1` must install an out-of-tree copy
(`confidant pack add --from-dir <dir> --yes`, or an https URL) or remove the
listing; otherwise `check` reports `E_PACK_UNKNOWN`. The coaching codes are
not reserved in core, so an out-of-tree copy still loads. Upgraded installs
may retain stale agent links until `confidant setup`/`update` prunes them.
Normally a break of this size would bump the minor; 0.6.1 keeps the patch
number by explicit maintainer decision so the agent-authored coaching reboot
can ship as 0.7.0.

### Added
- `confidant pack init <dir> [--name] [--version]`: scaffolds a valid
  external pack (`manifest.toml`, `SKILL.md`, `<version>.md`, `README.md`)
  outside the vault. `--dry-run` writes nothing. The new `pack-author` skill
  walks an agent through pack-vs-skill-vs-core, review, confirmation,
  install, `check` and iteration with `pack update --from-dir` (#674, #676).
- `confidant keys verify-recovery [--phrase-file <path>]`: a read-only,
  human-only check that a saved phrase matches the trust anchor, the operator
  certificate, and every current client's recovery wrapping. It writes
  nothing and never puts the phrase or derived keys in JSON (#663).
- `confidant init --phrase-out <path>`: writes the one-time phrase to a new
  `0600` file, refuses to overwrite, and prints only the path. The phrase is
  still shown once on stderr without the flag (#662).
- Headless encrypted init: `init` accepts `CONFIDANT_OPERATOR_KEY` (a
  64-character hex Ed25519 seed) alongside the existing
  `CONFIDANT_DEVICE_KEY`, and skips the OS-keychain operator write when it is
  set. `doctor` now names both variables in its pre-init hint (#650).
- `confidant init --create` starts the repo on `main`, reports the branch in
  human and JSON output, and prints an optional `pack add` hint when
  `packs = []` (#658, #661).
- New `doctor` checks: `git-remote` (local-only vs encrypted+remote vs
  plaintext+remote), `tui-version` (optional TUI installed/matching/mismatched),
  and a Linux-only best-effort `disk-encryption` check (#653, #659, #660).
- `setup`/`update` prune confidant-owned links/copies for skills this binary
  no longer embeds, reporting `removed_stale`; unowned files are left alone
  (#200).
- `confidant agents` always prints the nine-agent table with detected and
  linked counts; `setup` and `doctor` now agree on distinct skill dirs
  (muse/agents share one), and `--agent auto` announces its claude-code
  fallback (#652, #655, #653).

### Changed
- `--dry-run` is now honored by `setup`, `update`, and `init --create`:
  no directories, links, commits, key generation, keychain writes, or
  anchor writes. JSON carries `dry_run` and the planned actions (#649, #668).
- `doctor`'s qmd check warns when the corpus is missing, and its
  no-embeddings message now points at the vault-local
  `qmd-index.py --embed` wrapper instead of a bare `qmd embed` (#657, #666).
- `confidant tui` compares its version with `confidant-tui` and warns on a
  mismatch; `confidant tui --json` is a probe-only envelope and does not
  launch the child (#659).
- Unresolved external-pack `[checks]` keys now point at `confidant pack add`
  rather than the spec page that cannot define them (#656).
- The demo vault is personal-only: the coaching client, notes, pack listing,
  lockfile entry and coaching checks are gone. Tests, qa-smoke and bench-gen
  use the neutral `testdata/packs/example-pack/` fixture (#200, #201, #675).

### Fixed
- Failed `init --create` runs are atomic: preflight checks happen before any
  write, a partial skeleton is rolled back, and a failure after the keys
  commit rewinds that commit instead of leaving a dirty tree that blocks the
  retry. The recovery phrase is shown/written before the irreversible commit
  (#651).
- `init --create` no longer leaves a `master` branch behind, and an unborn
  pre-existing repo is moved to `main` (#661).
- `setup --dry-run` no longer creates agent directories or symlinks;
  `update --dry-run` no longer relinks skills or offers to run the upgrade
  command (#649, #668).
- `confidant agents` no longer exits 0 with blank output before setup (#652).
- A failed `init` no longer leaves an empty `.git` that blocks the retry
  (#651).

### Removed
- The four operator-specific embedded skills (`capture-gap-summary`,
  `lightfield-import`, `portal-sync`, `transcript-import`). `qmd-search` and
  `pack-author` remain.
- The shipped `packs/coaching/` asset, its demo-vault copy, and the demo's
  coaching data. A local coaching-shaped pack can be authored with
  `pack-author` and installed with `pack add --from-dir`.
- The TUI's Lightfield-specific proposal cleanup prompt.
- Operator-specific live docs and spec examples (Lightfield Appendix A,
  portal shapes, coaching-first framing, gap/`icf_hours`/billing examples).
  Historical `docs/research/` and the CHANGELOG are kept.

### Documentation
- Installation and setup docs now cover non-interactive `CONFIDANT_VAULT`
  (never `source ~/.bashrc`), the rustup no-default-toolchain hint, headless
  key injection, `--phrase-out`, `verify-recovery`, local packs, optional
  remotes with the plaintext warning, and installing the CLI and TUI
  together (#654, #653, #660, #662, #663).
- README status records that the independent audit has not happened yet
  (#138, #679).

## [0.6.0] - 2026-10-19

**Disclosure:** the milestone 2 encryption has had no outside review
([#138](https://github.com/hirefrank/confidant/issues/138)). Do not put
other people's client data in a vault until the audit lands.

**Breaking:** `coaching@0.1` is an external pack now, so a vault that lists
it must install the pack before upgrading, and a vault with `open`/`session`
ledger lines but no coaching pack fails `check` with `E_UNKNOWN_VERB`
instead of the old non-blocking warning. The coaching finding codes also
moved to the `E_COACHING_*` / `W_COACHING_*` names; see Changed.

### Added
- `confidant reset --machine-state`, the CLI path for starting fresh: it
  clears the trust anchor, manifest high-water marks, the pending inbox
  rotation reminder, the `default_vault`/`[vaults]`/`[trust].signers`/
  `[inbox].pubkey` user-config entries (preserving unrelated keys and
  comments), and the device, operator and inbox keys from the OS keychain.
  It never writes inside a vault, refuses while a resolvable vault still has
  a `keys/` tree unless `--force`, supports `--dry-run`, requires `--yes`
  with `--no-input`/`--json`, and is idempotent (#638, #647).
- The demo vault is **personal-first**: four people with relationship edges,
  birthdays, anniversaries, keep-in-touch cadences and `touch` lines, with
  the coaching client and its checks kept alongside. It intentionally
  reports `W_CADENCE_OVERDUE` and `W_DATE_UPCOMING` as teaching content
  (#642).
- `docs/starting-fresh.md` documents starting over — vault-local *and*
  machine state — and adopting Confidant in stages (personal first, then a
  coaching practice), including the pack-scope-is-not-a-boundary caveat
  (#644).
- `confidant init --create` bootstraps a vault in one non-interactive
  command: target resolution, `mkdir`, `git init`, a committed
  `confidant.toml`, `.gitignore`, then the existing key ceremony, with the
  trust-anchor refusal before anything is written (#552).
- Exact display-name person resolution: `--person` on `log session`,
  `log touch`, `note add`, and `context` accepts a trimmed,
  case-insensitive, whole-string display name as well as a `p-<ULID>`, and
  a new read-only `confidant resolve <query>` resolves either form to the
  canonical person. A name matching more than one cleared person fails
  closed with `E_AMBIGUOUS_PERSON`; a `no-ai: true` person stays
  addressable by id only (#554, #563).
- `confidant note show <id> --for-edit` and `confidant note edit <id>
  --file|--edit`: the operator-only decrypted read and replace pair for
  notes, through the same write pipeline as records (re-encrypt,
  `check`-gated, one commit, `unchanged` when nothing changes) (#562).
- `confidant record list [--for-operator] [--kind person|org|deal]`: a
  roster of the cleared set, or with the flag the full roster through the
  operator decrypt path, with a tri-state `no_ai` and a `--packs`-validated
  `scope` (#565).
- `--for-operator` on `find` and `context`: the same operator boundary as
  the roster, loading through the for-edit decrypt path, marking records
  with the tri-state `no_ai` and operator-only ledger hits with
  `operator_only: true`. Without the flag the agent output is byte-for-byte
  unchanged, and MCP never passes the flag (#586, #598).
- `confidant alias add <person> <kind>` and `confidant alias resolve
  <kind>`: append and resolve the spec §6 `alias` HMAC line. The raw value
  arrives on stdin or `--value-file` only and is never echoed; resolution
  honours `no-ai` and fails closed with `E_AMBIGUOUS_PERSON` (#585).
- Pack apply: `pack add --yes` now vendors the reviewed files, pins them
  in `confidant.lock`, adds the `packs` entry, runs `check`, and commits
  once. New `pack list`, `pack verify`, `pack remove --yes`, and
  `pack update` (with a reviewed diff) round out the lifecycle (#516).
- Declarative rule kinds for external packs: `date-upcoming`,
  `ledger-balance`, `session-checks`, `activity-gap`, and `note-ref`,
  reproducing the personal and coaching checks from manifest parameters
  (#519, #524, #571, #573, #582).
- External packs can opt into the core-built `ledger-sessions` context view
  with a manifest `[context]` table (spec §13.9), serving the coaching
  `sessions_remaining`, `icf_hours`, and `recent_sessions` keys from
  derived ledger metadata without widening the §12 allowlist (#620, #622).
- TUI v2 (phases 1–5): a three-workspace layout with people master–detail,
  an operator-mode toggle (`!`) with `no-ai` badges and an `OPERATOR MODE`
  footer, inline record/note editing (`e`), quick capture for session,
  touch, and note (`s`/`t`/`n`) with dry-run previews, a review-queue
  badge, a contrast-safe theme, a vim/lazygit keymap, a grouped help modal,
  and a command palette (#556, #576, #595, #603, #608, #610).
- The TUI's `a` form creates a new person: it mints the `p-ULID` locally,
  stages the record, previews through `record add --dry-run`, and writes
  only on an explicit `y` (#643).
- `confidant doctor` gains a `device-key` check reporting whether the
  device key comes from the keychain, `CONFIDANT_DEVICE_KEY`, or no
  enrollment, with an actionable `fix` for headless hosts (#575).
- The qmd index skill persists the encrypted-disk confirmation through
  `CONFIDANT_ASSUME_ENCRYPTED_DISK=1` or the `[qmd] assume_encrypted_disk`
  config key, preferring real disk detection over either (#567).
- A repo QA sweep skill and a nightly `qa smoke` job: 22 deterministic
  end-to-end steps against throwaway vaults, run on the schedule and on
  pushes to `main`, on a pull request when fixtures, packs, the smoke
  script, or the workflow change, and with a failure alert that opens one
  `qa-found` issue and closes it on the next green run (#623, #631, #632).
- `personal@0.2` schema: three new field grammars — `list`,
  `labeled-list`, `date` — and an extended `cadence` grammar that also
  accepts the literal `never`. The `cadence-overdue` rule now skips a
  `never` person and accepts an optional `snooze_field` (a declared `date`
  field) to suppress the nudge while `as_of` is before its value (#509).
- The embedded declarative `personal@0.2` built-in pack (#550): its
  manifest, skill text and contract ship inside the binary and load through
  the manifest-v2 / declarative path external packs use, so its rules may
  name the stable finding codes. The repo-root `packs/personal/manifest.toml`,
  `SKILL.md` and `0.2.md` are the human contract, and the stable-code
  allowance is keyed on compiled-in origin, so a vault directory
  `packs/personal@…` is `E_PACK_INVALID` (#550, #504 R8).
- The built-in personal pack is **implicit** (#551): it is enabled in every
  vault whether or not `packs` lists it, so `packs = []` enables it, and a
  `personal@…` entry is accepted as a no-op. A scoped read sees it only when
  the scope names it: an unscoped `context`/`find` call covers it, while a
  `--packs coaching@0.1` ceiling does not. A vault directory or lockfile pin
  for a built-in name is still `E_PACK_INVALID`, listed or not (#504 R8).

### Changed
- **Breaking: the coaching pack is external (#449).** `coaching@0.1` is no
  longer compiled into the binary. A vault that lists `coaching@0.1`
  without vendoring it now fails `check` with `E_PACK_UNKNOWN` and blocks
  writes until the pack is installed. Install it from this repo:

  ```sh
  confidant pack add https://github.com/hirefrank/confidant.git --subdir packs/coaching --yes
  confidant check --json --no-input
  ```

  The pack keeps the `coaching.*` `[checks]` keys and the
  `packs["coaching@0.1"]` `context` key; only the finding codes change
  (below). A vault that does not list coaching but still has `open`/`session`
  ledger lines now gets `E_UNKNOWN_VERB` (an error) instead of the old
  non-blocking `W_PACK_ORPHAN` warning.

  Coaching finding-code renames (old → new):

  | Old | New |
  |---|---|
  | `E_BALANCE_MISMATCH` | `E_COACHING_BALANCE_MISMATCH` |
  | `E_MISSING_DURATION` | `E_COACHING_MISSING_DURATION` |
  | `E_PAID_SESSION_GAP` | `E_COACHING_PAID_SESSION_GAP` |
  | `E_PARSE` (coaching balance parse) | `E_COACHING_PARSE` |
  | `E_NEGATIVE_BALANCE` | `E_COACHING_NEGATIVE_BALANCE` |
  | `E_OPEN_MALFORMED` | `E_COACHING_OPEN_MALFORMED` |
  | `E_INVALID_ID` (package id) | `E_COACHING_INVALID_ID` |
  | `E_WRONG_ID_TYPE` (package id) | `E_COACHING_WRONG_ID_TYPE` |
  | `E_SESSION_TAGS` | `E_COACHING_SESSION_TAGS` |
  | `W_SESSION_UNTAGGED` | `W_COACHING_SESSION_UNTAGGED` |
  | `E_SESSION_WITHOUT_NOTES` | `E_COACHING_SESSION_WITHOUT_NOTES` |
  | `E_INVALID_ID` (`note:` id) | `E_COACHING_NOTE_INVALID_ID` |
  | `E_WRONG_ID_TYPE` (`note:` id) | `E_COACHING_NOTE_WRONG_TYPE` |
  | `E_UNKNOWN_RECORD` (coaching `note:`) | `E_COACHING_UNKNOWN_RECORD` |

  The old coaching-only names are retired: never emitted, never reused.
  An external consumer that branches on them (`capture-gap-summary` did)
  must move to the new names; that is the known cost of the rename.
- `context --json`'s `packs["personal@0.2"]` entry gains `cadence_never:
  true` when, and only when, the person's declared `cadence` is the literal
  `never`. It tells a deliberate never-nudge apart from no cadence set (both
  omit `cadence_days`), so an agent does not suggest configuring a cadence
  the person turned off. Additive: absent for everyone else (#589, #596).
- The `touch` kind list is now `call|text|email|meet|meal|event|gift|other`
  (#509). `coffee` is removed, not aliased: `meal` replaces it. New `log touch`
  writes using `coffee` are a usage error, and an existing `coffee` ledger line
  (positional or `kind:coffee`) now fails `check` with `E_TOUCH_MALFORMED`.
- Core owns the personal pack's `context` view, its `--exclude-private`
  field list and the `touch` kind grammar; the built-in personal pack serves
  them (#510, #551). `context --json` output is unchanged apart from the
  pack key below.
- `context`'s `packs` map key for the built-in personal pack is now
  `personal@0.2` (was `personal@0.1`). Pre-v1 JSON key change; the values are
  unchanged (#551).
- `confidant log touch` no longer requires the vault to list the personal
  pack: it is implicit (#551).
- `record add` mirrors a `touch` ledger line for an interaction's primary
  `person:` as well as for each `with:` participant, in the same commit, so a
  logged interaction counts as contact for everyone on it (#505). The rules
  stay ledger-only: a hand-written interaction with no mirrored line still
  does not count.
- Rule kinds require their kind-specific `*_code` parameters, and retired
  finding-code names are refused for every pack origin, so a pack can no
  longer fall back silently to a retired coaching code or a builtin (#634).
- Documentation: the derived-view carve-out for `no-ai` people is recorded
  where agents read it — content stays hidden from `find`, while `context`
  still serves derived ledger metadata — and the pack skill shorthand
  matches `docs/privacy.md` (#599, #633).

### Fixed
- Pack-loader hardening: an external pack on an unsupported spec no longer
  reports `E_PACK_UNKNOWN`, duplicate `date` fields and negative int
  defaults are refused, and external-pack label text is sanitized and
  attributed by origin rather than the base name (#520, #531, #533, #584).
- `init --force` on an already-initialized vault refuses before generating
  or writing any key material, so a refused re-init leaves the tree, HEAD
  and keychain untouched; and `init --create --packs` now accepts only the
  packs the binary implements and points external packs at `pack add`
  instead of promising a pack it cannot vendor (#639, #640, #646).
- `pack update` on byte-identical bytes reports `unchanged` instead of
  failing `internal_error` on an empty commit, and repairs a stale
  `confidant.lock` hash over an otherwise matching tree (#605, #607).
- A pack listed in `confidant.toml` with no lock entry is repairable from
  the CLI: `pack remove` keys off every source of install state, `pack add
  --yes` reinstalls, and the `E_PACK_UNKNOWN` hint names both (#617).
- `pack remove` and `pack update` refuse a symlinked or otherwise
  non-regular vendored tree before any delete or diff, so a refusal cannot
  leave a half-deleted pack or read a file outside the vault (#587).
- A refused or failed write rolls back the directories it created as well
  as the files it touched, and a mid-apply I/O failure restores the
  snapshot instead of leaving a partially applied tree (#613, #616).
- The qmd-search skill verifies hits against the §12 cleared set with one
  `confidant allowlist` call, so cleared CJK and short notes are returned
  and stale or out-of-scope hits are dropped fail-closed (#548).
- The package-id refusal hint points at `confidant context <person>`, a
  command that exists (#577).
- TUI: an older CLI on `PATH` is reported as `CLI Version Skew` instead of
  a wall of usage text, with the raw output behind `x`; a proposal confirm
  is bound to the reviewed dry-run and applies staged bytes, so a source
  rewrite cannot land un-reviewed (#601, #615, #627).

### Removed
- `crates/confidant-core/src/packs/coaching.rs`, its registry entries and
  the in-crate vendored `coaching` manifest/skill copies. `coaching@0.1`
  ships from `packs/coaching/` as an external pack (#449).
- Compiled `personal@0.1` (`crates/confidant-core/src/packs/personal.rs`),
  its frozen manifest (`pack-manifests/personal-0.1/`) and its human 0.1
  contract (`packs/personal/0.1.md`). `personal@0.2` is the only personal
  pack and it is implicit (#551).

## [0.5.0] - 2026-10-18

**Disclosure:** the milestone 2 encryption has had no outside review
([#138](https://github.com/hirefrank/confidant/issues/138)). Do not put
other people's client data in a vault until the audit lands.

**Breaking:** native Windows is no longer a supported target. macOS and
Linux are supported as-is; Windows users run Confidant under WSL2.

### Added
- External packs: a pack with no compiled Rust can be listed in
  `confidant.toml` and resolved from the vault's own install state. The pack
  registry is a runtime value now (#432); the spec covers manifest v2, the
  rule-kind framework, the lockfile, and the vendored layout (#431); a v2
  manifest adds `requires_spec`, `[[rules]]` and the capability limits
  (#435); `confidant.lock` pins `name@version` to a content hash with a
  byte-stable canonical form (#437); a pack directory reader computes the
  canonical tree hash behind the file-count and size limits (#436); and
  loading at check time fails closed to `E_PACK_UNKNOWN` /
  `E_PACK_HASH` / `E_PACK_INVALID` / `E_PACK_VERSION` findings, so a problem
  pack never folds (#438, #434).
- `confidant pack add <https-url>[#<ref>] [--from-dir <dir>] [--subdir <path>]`:
  fetches a candidate pack into a temp directory, validates it with the same
  reader the loader uses, and prints a review report. It writes nothing to
  the vault and stays off the MCP whitelist (#439).
- Declarative pack checks: a manifest declares rules and a named rule kind
  implemented once in Rust evaluates them, validated at pack load so a bad
  rule fails closed before anything folds (#441). First kind:
  `cadence-overdue`, matching `personal@0.1`'s keep-in-touch semantics
  (#442).
- Conflict resolution: split a git-conflicted file into its two sides
  (#451); `record resolve <id> --show` prints both decrypted sides (#453);
  `--take ours/theirs` installs the chosen side byte for byte (#454);
  `--merged-file` and `--edit` hand-merge paths (#455); a Conflicts tab in
  the TUI that reviews both sides and picks or hand-merges (#456); and
  `record resolve --from-inbox` with `inbox --discard` for an inbox item
  targeting an existing record (#457).

### Changed
- Native Windows is unsupported (#502): the dist targets, powershell
  installer and Windows CI jobs are gone (#506), the Windows-only code
  paths are removed (#503, #507), and the remaining docs follow (#508).
- External-pack problem findings name the pack and version;
  `E_PACK_UNKNOWN` echoes the id only when it is a well-formed
  `name@version` pin (#500, #511).
- `[checks]` keys come from the loaded pack manifests, so a pack's own keys
  work with no per-pack code; a typo under a known pack name is `E_CONFIG`
  again instead of a silent fall-through to the default (#433).
- `check` says an encrypted `E_MERGE_CONFLICT` record has two versions and
  points at `record resolve`; every other conflicted file keeps the generic
  message (#452). A merge that still contains conflict markers is refused
  (#473).
- `record resolve --from-inbox` write actions run the drain's signed-tip
  trust check against the tip that was read, honour `--allow-unsigned`
  like the drain, and refuse on a moved tip with `E_INBOX_RACE` (#457).
- `cargo deny` exempts the unmaintained `zvariant` / `zbus_names` /
  `zvariant_derive` advisories, reached only through the Linux keyring
  backend, and drops a stale ignore (#469).

### Fixed
- `record resolve` honours the global `--dry-run` on every write path
  (`--take`, `--merged-file`, `--edit`, and their `--from-inbox` variants),
  running its read-only validation and reporting what it would do without
  touching the vault, index, scratch, or inbox (#465).
- Inbox item bodies keep their final newline, so a drained record matches
  the canonical form and `record resolve --take theirs` no longer reports a
  spurious `E_INBOX_CONFLICT` (#457).

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

[Unreleased]: https://github.com/hirefrank/confidant/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/hirefrank/confidant/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/hirefrank/confidant/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/hirefrank/confidant/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/hirefrank/confidant/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/hirefrank/confidant/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/hirefrank/confidant/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hirefrank/confidant/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hirefrank/confidant/releases/tag/v0.1.1
[0.1.0]: https://github.com/hirefrank/confidant/releases/tag/v0.1.0
