# AGENTS.md

Guide for coding agents (and humans) working in this repository. It covers
how to build, check, and change Confidant safely. For what Confidant is and
how to use it, read [`README.md`](README.md) first; this file does not
repeat it.

Instructions from the person you are working for take precedence over this
file. Where this file and the code disagree, trust the code and CI, and fix
this file in the same PR.

## What this repo is

Confidant is relationship memory you own: plain-text records in a git repo
(the vault) for one operator and their AI agents. The Rust CLI `confidant`
reads, checks and writes them. There is no server.

Records are **plaintext on disk**, in a private git repo, on a machine whose
disk is encrypted (LUKS, FileVault). There is no application-level
encryption layer. The privacy boundary is the operator's own machines plus
`no-ai` on agent-facing reads, so the privacy rules here are hard rules, not
style. Multi-user (a shared vault, peers with their own agents) is out of
scope until there is a second human; the expected shape is separate
interoperating vaults, not one shared vault.

Read before changing behaviour:

- [`spec/0.1.md`](spec/0.1.md): the vault file format. **The spec is the
  contract**; the code implements it. The spec version and the CLI version
  are independent (ADR-1).
- [`spec/findings.md`](spec/findings.md): stable `check` finding codes.
- [`docs/architecture.md`](docs/architecture.md): privacy and threat model,
  ADR-1 to ADR-16, milestones (section 8), and risk decisions (section 9b,
  binding).
- [`testdata/packs/example-pack/`](testdata/packs/example-pack/): the neutral external-pack fixture used by tests, the QA smoke, and the benchmark generator.
- [`packs/personal/0.2.md`](packs/personal/0.2.md): the personal
  relationships pack (implicit built-in).
- [`spec/pack-manifest.md`](spec/pack-manifest.md): the pack manifest
  format. The manifest (`packs/<name>/manifest.toml`) is the single
  source of truth for a pack's claims (verbs, fields, edge kinds,
  finding codes, `[checks]` keys, message templates); the folds and
  findings logic stay in Rust.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) and
  [`docs/borrowing.md`](docs/borrowing.md): contributor setup, and what was
  adapted from `cr`.

## Repo map

| Path | What |
|---|---|
| `crates/confidant-core/` | Parser, model, derived values, check engine, search allowlist |
| `crates/confidant-cli/` | The `confidant` binary (package `confidant-cli`) |
| `crates/confidant-tui/` | Terminal UI (`confidant-tui`): reference second consumer of the ADR-7 `--json --no-input` CLI contract. Ships as a GitHub Releases binary and on crates.io; launched via `confidant tui` |
| `fuzz/` | cargo-fuzz harnesses for the ledger parser (own workspace, excluded from the main one; not run in CI) |
| `spec/` | Format spec and finding codes |
| `packs/` | Schema packs (built-in personal; external packs live in the vault) |
| `crates/confidant-cli/pack-skills/`, `crates/confidant-core/pack-manifests/` | In-crate vendored pack skill/manifest copies the binary embeds; regenerate with `python3 .github/scripts/sync-packs.py` (drift tests guard them) |
| `examples/demo-vault/` | Fake-data vault used by tests, docs, and CI |
| `testdata/golden/` | Golden `check --json` outputs |
| `docs/` | Architecture, privacy, sync, benchmarks, research |
| `contrib/` | Opt-in systemd/launchd timer templates for `confidant sync` (#665) |
| `.github/workflows/ci.yml` | The CI gate. Source of truth for the commands below |

## Commands

Toolchain: `rust-toolchain.toml` pins Rust 1.99.0 (with rustfmt and clippy).
MSRV is **1.88** (`rust-version` in `Cargo.toml`). CI sets
`RUSTFLAGS="-D warnings"`, so any compiler warning fails the build.

Run these from the repo root before you push. They match CI exactly:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run -p confidant-cli --locked -- check --json --no-input --vault examples/demo-vault
cargo +1.88 check --workspace --locked   # MSRV job
cargo deny check                          # deny.toml sets all-features
cargo audit
python3 .github/scripts/check-crate-paths.py   # crate path check job
```

CI runs the test job on both `ubuntu-24.04` and `macos-latest` for every
event, pull requests included. macOS used to be main-push-only, and all
three main-red incidents in one stretch were platform-only failures it
found after merge (#560, #564, #581), so a portability break now fails the
pull request instead. A nightly schedule and `workflow_dispatch` run the
same job. Native Windows is not supported (#502): Windows users run
Confidant under WSL2, so there is no Windows CI job. Keep code portable
across macOS and Linux.

Narrower loops while iterating:

```sh
cargo test -p confidant-core --test check_engine   # check engine + golden JSON
cargo test -p confidant-cli --test cli             # CLI contract tests
UPDATE_GOLDEN=1 cargo test -p confidant-core --test check_engine   # only after an intentional message change
python3 .github/scripts/sync-packs.py               # re-vendor pack skills/manifests after editing packs/
python3 crates/confidant-cli/skills/qmd-search/tests/test_qmd_query.py --cli target/debug/confidant
                                                    # skill allowlist/verification tests (needs a built CLI; the "skills smoke" job)
cargo build -p confidant-cli --locked --all-features   # qa-smoke needs the `test-overrides` feature
python3 .github/scripts/qa-smoke.py --cli target/debug/confidant
                                                    # 22-step end-to-end smoke on a throwaway vault (.agents/skills/qa-sweep/SKILL.md)
```

`--locked` means the lockfile must already be right. If you add a
dependency, commit the updated `Cargo.lock`, and make sure its license is on
the `deny.toml` allow list and it comes from crates.io (unknown registries
and git sources are denied).

Content under `packs/`, `examples/`, `testdata/`,
`crates/confidant-core/pack-manifests/`, `crates/confidant-cli/pack-skills/`
and `crates/confidant-cli/skills/` is **not** documentation, whatever its
extension: it is hash-pinned or embedded content that drives behaviour
(#636). Editing it means re-pinning or re-vendoring it in the same PR: run
`python3 .github/scripts/sync-packs.py`, and for a vault that pins the pack
(the demo vault) refresh the pin with the CLI
(`confidant pack update <name> --from-dir <pack> --yes`), then confirm
`check --json` on that vault is `ok:true`. Such a change cannot ride the
docs-only fast path; expect the full suite.

## Hard rules

These are blocking. Do not open a PR for review that breaks one.

1. **Fake data only.** Never put real client data, real names, emails,
   phone numbers, notes, transcripts, credentials, tokens, or secrets
   anywhere in the repo: code, tests, fixtures, docs, examples, commit
   messages, issues, or CI logs. Use the demo vault's style of obviously
   fake people (`Robin Example`) and fake ULIDs.
2. **CI never holds vault data or credentials.** Tests use the demo vault
   and generated temp vaults during the run. Do not add secrets to
   workflows, and never give a GitHub Action access to a real vault or to
   the operator's git credentials.
3. **Honour `no-ai` on every agent-facing output.** A record or client with
   `no-ai` must stay out of `find`, `context`, and any `--json` output an
   agent reads. When unsure whether something is cleared, leave it out:
   `find` uses the allowlist in spec section 12, and findings carry a code
   and count, not raw text or paths, unless the record is cleared. New
   output paths need tests proving `no-ai` content is excluded.
4. **Never log secrets.** Credentials, tokens, and vault content beyond what
   the command is meant to print must never reach stdout, stderr, logs,
   error messages, `Debug` output, or panics. Errors fail closed: a missing
   file or a malformed record is a typed error, never a silent pass.
5. **Local state stays local.** Indexes and caches live in `.confidant/`
   (gitignored), stay on trusted devices, and never go in git (ADR-6).
7. **Format and privacy changes need review first.** A change to the vault
   file format, finding-code semantics, or the privacy model needs an
   `<topic>-review` issue and the maintainer's answer before code.
   Behaviour changes to vault files need a spec edit, tests, and usually a
   `spec/findings.md` update in the same PR.
8. **Keep the agent contract stable** (ADR-7). Every command takes `--json`
   and `--no-input`; JSON includes the resolved vault path; usage errors
   exit 2; callers branch on error and finding `code`, never on message
   text. Breaking changes to this contract need versioning.
9. **Human-only git attribution.** Commits list the operator as author and
   committer only. Never add `Co-authored-by`, `Signed-off-by`, or similar
   trailers for AI assistants (including local names like **Marigold** or
   **Cursor**). Local branch prefixes such as `marigold/` are workflow
   labels only — they must not appear in author metadata or commit trailers.
   Enable the guard with `git config core.hooksPath .githooks` (see
   `CONTRIBUTING.md`).

## Code conventions

- Match the surrounding code. `rustfmt.toml` and clippy with `-D warnings`
  are the style guide; do not silence a lint without a comment saying why.
- `confidant-core` denies `unsafe` (one documented exception in `paths`).
  Do not add new `unsafe`.
- Errors name the file and line and suggest a fix. Paths in errors are
  opaque IDs, never names.
- Code adapted from other projects keeps its license header and is recorded
  in `THIRD_PARTY_LICENSES` and `docs/borrowing.md`.
- Tests: add or update tests for every behaviour change. The demo vault must
  report no **errors** under `confidant check`; it intentionally carries two
  warning-level personal nudges (`W_CADENCE_OVERDUE`, `W_DATE_UPCOMING`) as
  teaching content, so do not expect an empty findings list. Prefer extending
  the existing test files over adding new ones.
- Tests that write ledger lines must pin the date (`--date 2026-10-13`) or
  assert against a fixed month. A test that relies on "today" expires when
  the month rolls over and turns `main` red on its own (#585 shipped one and
  review caught it).

## Workflow

- **One PR per milestone or topic.** Do not bundle unrelated changes, and
  do not edit files outside your topic.
- **Milestones are time horizons.** `Now` (two weeks), `Next` (six
  weeks), and `Later` (unscheduled) are not version containers; version
  numbers are release tags. Keep a release to 5-8 issues, put design
  spikes in `Now` when they block core work, and read the 1.0 bar in
  `docs/architecture.md` §8a before scheduling a release.
- **PR body** has these sections: title, summary, spec changes (or "none"),
  test evidence (commands run and results), and **Decisions I made** (each
  place the spec was silent and what you chose).
- **Closing lines:** every PR body must include one line per issue it fully
  resolves: `Fixes #N`, one issue per line (never `Fixes #A, #B`). Use
  `Part of #N` or `Refs #N` for partial work. References in the title do
  not count. Reviewers confirm these lines before signing off.
- **When the spec is silent, choose the simpler option** and record it under
  Decisions I made. Stop and ask only for changes to the file format or the
  privacy model (rule 7).
- **Questions go in GitHub issues**, labeled `<topic>-review` and titled
  `[<topic>-review] <question>`. State your recommendation and reasoning,
  and end with a specific ask.
- **At most two self-review rounds** per PR. File anything left over as an
  issue and link it from the PR.
- **CI stays green.** Do not open a PR for review with failing checks, and
  never assume a failure is pre-existing; `main` is kept green.
- **No merges without the maintainer's explicit approval.** This includes
  docs-only and "trivial" PRs. Do not merge, close, or relabel other
  people's PRs, and do not force-push shared branches.
- Keep commits focused. Do not revert or reformat unrelated files.

## Keeping this file current

Update this file in the same PR when you change a CI command, the repo
layout, or a rule above. Keep it short: link to the spec and docs rather
than copying them.

## Learned User Preferences

- When syncing `main` to `origin/main` or setting `core.hooksPath`, run git
  in `~/Projects/confidant` unless `main` is already checked out in the
  current worktree.
- For release prep, follow `.agents/skills/confidant-release/SKILL.md` in
  this repo, not the global `~/.agents/skills/confidant-release` copy (it
  may still describe manual `cargo publish`).

## Learned Workspace Facts

- The primary clone where `main` usually lives is `~/Projects/confidant`;
  Cursor agent worktrees are under `~/.cursor/worktrees/confidant/`.
- Only one worktree may have `main` checked out; with `main` on the primary
  clone, `git checkout main` in a Cursor worktree fails because `main` is
  already in use there.
- Releases ship by pushing a `v*` tag on the intended `main` commit;
  `.github/workflows/release.yml` builds dist assets and publishes crates.io
  via OIDC trusted publishing — no local `cargo publish`.
