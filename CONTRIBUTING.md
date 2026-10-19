# Contributing

The format spec in `spec/` is the contract. The CLI version and the spec
version are independent (ADR-1). Behavioural changes to vault files need a
spec edit, tests, and usually a finding-code update in `spec/findings.md`.

## Setup

Rust 1.88 or newer (`rust-toolchain.toml` pins 1.99.0). From the repo root:

Optional but recommended (blocks AI agent co-author trailers on commit):

```sh
git config core.hooksPath .githooks
```

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo +1.88 check --workspace --locked
cargo run -p confidant-cli --locked -- check --json --no-input --vault examples/demo-vault
```

Supply-chain checks (also in CI):

```sh
cargo deny check --all-features
cargo audit
```

Fuzz the untrusted-input parsers manually (not in CI; needs a nightly toolchain):

```sh
cd fuzz && cargo +nightly fuzz run ledger_line -- -max_len=4096 -rss_limit_mb=1024 -max_total_time=300
cd fuzz && cargo +nightly fuzz run envelope_decode -- -max_len=65536 -rss_limit_mb=2048 -max_total_time=300
```

Regenerate golden check JSON after an intentional finding-message change:

```sh
UPDATE_GOLDEN=1 cargo test -p confidant-core --test check_engine
```

Regenerate the in-crate vendored pack copies after editing a repo-root pack
skill or manifest (the binary embeds the vendored copies; crates.io tarballs
omit `packs/`):

```sh
python3 .github/scripts/sync-packs.py          # copy packs/ -> in-crate copies
python3 .github/scripts/sync-packs.py --check  # verify only, no writes
```

The drift tests stay in CI and fail on any mismatch. Generated copies only,
never symlinks (`cargo publish` tarballs and `include_dir!` break).

## Layout

| Path | What |
|---|---|
| `spec/` | Format spec 0.1 and stable finding codes |
| `crates/confidant-core` | Parser, model, derived values, check engine |
| `crates/confidant-cli` | `confidant` binary |
| `crates/confidant-crypt` | Stub until the milestone 2 crypto review |
| `examples/demo-vault/` | Fake data only |
| `docs/borrowing.md` | What we took from cr, and what we did not |

Do not add encryption, key wrapping, or real client data. Section 9b of the
architecture requires an independent crypto design review before milestone 2.

## Agent contract

Every command accepts `--json` and `--no-input`. JSON always includes the
resolved vault path. Usage errors exit 2. Check findings use `E_*` codes.
Classify by code, never by message text. `internal_error` is reserved.

## Tests

Parser tests cover round-trips and malformed lines. Check tests cover golden
JSON for the pack-own finding codes and the generic rule kinds, plus gap-rule
edges (inclusive window, never-started, spent package, rule `off`). The demo
vault must stay clean under `confidant check`.
