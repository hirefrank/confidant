# AGENTS.md

Guide for coding agents (and humans) working in this repository. It covers
how to build, check, and change Confidant safely. For what Confidant is and
how to use it, read [`README.md`](README.md) first; this file does not
repeat it.

Instructions from the person you are working for take precedence over this
file. Where this file and the code disagree, trust the code and CI, and fix
this file in the same PR.

## What this repo is

Confidant is a plain-text, git-native CRM for one operator and their AI
agents. Records live in a git repo (the vault) and the Rust CLI `confidant`
reads, checks, and (from milestone 3) writes them. There is no server.
Client content is meant to be encrypted at rest in git once milestone 2
lands, so privacy rules here are hard rules, not style.

Read before changing behaviour:

- [`spec/0.1.md`](spec/0.1.md): the vault file format. **The spec is the
  contract**; the code implements it. The spec version and the CLI version
  are independent (ADR-1).
- [`spec/findings.md`](spec/findings.md): stable `check` finding codes.
- [`docs/architecture.md`](docs/architecture.md): privacy and threat model,
  ADR-1 to ADR-15, milestones (section 8), and risk decisions (section 9b,
  binding).
- [`docs/crypto-design.md`](docs/crypto-design.md): milestone 2 encryption
  design (key hierarchy, envelope, AAD, recovery, test plan).
- [`packs/coaching/0.1.md`](packs/coaching/0.1.md): the coaching schema pack.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) and
  [`docs/borrowing.md`](docs/borrowing.md): contributor setup, and what was
  adapted from `cr`.

## Repo map

| Path | What |
|---|---|
| `crates/confidant-core/` | Parser, model, derived values, check engine, search allowlist |
| `crates/confidant-cli/` | The `confidant` binary (package `confidant-cli`) |
| `crates/confidant-crypt/` | Encryption. A fail-closed stub until the milestone 2 implementation lands |
| `spec/` | Format spec and finding codes |
| `packs/` | Schema packs (coaching first) |
| `examples/demo-vault/` | Fake-data vault used by tests, docs, and CI |
| `testdata/golden/` | Golden `check --json` outputs |
| `docs/` | Architecture, crypto design, benchmarks, research |
| `.github/workflows/ci.yml` | The CI gate. Source of truth for the commands below |

## Commands

Toolchain: `rust-toolchain.toml` pins Rust 1.99.0 (with rustfmt and clippy).
MSRV is **1.85** (`rust-version` in `Cargo.toml`). CI sets
`RUSTFLAGS="-D warnings"`, so any compiler warning fails the build.

Run these from the repo root before you push. They match CI exactly:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run -p confidant-cli --locked -- check --json --no-input --vault examples/demo-vault
cargo +1.85 check --workspace --locked   # MSRV job
cargo deny check                          # deny.toml sets all-features
cargo audit
```

CI runs the test job on `ubuntu-latest` and `macos-latest`. Keep code
portable across both.

Narrower loops while iterating:

```sh
cargo test -p confidant-core --test check_engine   # check engine + golden JSON
cargo test -p confidant-cli --test cli             # CLI contract tests
UPDATE_GOLDEN=1 cargo test -p confidant-core --test check_engine   # only after an intentional message change
```

`--locked` means the lockfile must already be right. If you add a
dependency, commit the updated `Cargo.lock`, and make sure its license is on
the `deny.toml` allow list and it comes from crates.io (unknown registries
and git sources are denied).

## Hard rules

These are blocking. Do not open a PR for review that breaks one.

1. **Fake data only.** Never put real client data, real names, emails,
   phone numbers, notes, transcripts, keys, recovery phrases, tokens, or
   secrets anywhere in the repo: code, tests, fixtures, docs, examples,
   commit messages, issues, or CI logs. Use the demo vault's style of
   obviously fake people (`Ada Example`) and fake ULIDs.
2. **CI never holds vault keys.** Crypto tests generate throwaway keys
   during the run (ADR-14). Do not add secrets to workflows, and never give
   a GitHub Action decryption keys.
3. **Honour `no-ai` on every agent-facing output.** A record or client with
   `no-ai` must stay out of `find`, `context`, and any `--json` output an
   agent reads. When unsure whether something is cleared, leave it out:
   `find` uses the allowlist in spec section 12, and findings carry a code
   and count, not raw text or paths, unless the record is cleared. New
   output paths need tests proving `no-ai` content is excluded.
4. **Never log secrets.** Recovery phrases, private keys, data keys, and
   decrypted content must never reach stdout, stderr, logs, error messages,
   `Debug` output, or panics. Crypto code fails closed: a missing key, bad
   signature, or tampered envelope is an error, never silent plaintext.
5. **Plaintext stays local.** Indexes and caches live in `.confidant/`
   (gitignored), stay on trusted devices, and never go in git (ADR-6).
6. **Crypto changes need review first.** Any change to `confidant-crypt`,
   key handling, the envelope, or AAD needs an open `crypto-review` issue
   before code. Crypto PRs must state in the body: **needs outside audit
   before public launch.** Do not invent primitives; follow
   `docs/crypto-design.md`.
7. **Format and privacy changes need review first.** A change to the vault
   file format, finding-code semantics, or the privacy model needs an
   `<topic>-review` issue and the maintainer's answer before code.
   Behaviour changes to vault files need a spec edit, tests, and usually a
   `spec/findings.md` update in the same PR.
8. **Keep the agent contract stable** (ADR-7). Every command takes `--json`
   and `--no-input`; JSON includes the resolved vault path; usage errors
   exit 2; callers branch on error and finding `code`, never on message
   text. Breaking changes to this contract need versioning.

## Code conventions

- Match the surrounding code. `rustfmt.toml` and clippy with `-D warnings`
  are the style guide; do not silence a lint without a comment saying why.
- `confidant-core` denies `unsafe` (one documented exception in `paths`);
  `confidant-crypt` forbids it. Do not add new `unsafe`.
- Errors name the file and line and suggest a fix. Paths in errors are
  opaque IDs, never names.
- Code adapted from other projects keeps its license header and is recorded
  in `THIRD_PARTY_LICENSES` and `docs/borrowing.md`.
- Tests: add or update tests for every behaviour change. The demo vault must
  stay clean under `confidant check`. Prefer extending the existing test
  files over adding new ones.

## Workflow

- **One PR per milestone or topic.** Do not bundle unrelated changes, and
  do not edit files outside your topic.
- **PR body** has these sections: title, summary, spec changes (or "none"),
  test evidence (commands run and results), and **Decisions I made** (each
  place the spec was silent and what you chose).
- **When the spec is silent, choose the simpler option** and record it under
  Decisions I made. Stop and ask only for changes to the file format or the
  privacy model (rules 6 and 7).
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
