# Contributing

The format spec in `spec/` is the contract. The CLI version and the spec
version are independent (ADR-1). Behavioural changes to vault files need a
spec edit, tests, and usually a finding-code update in `spec/findings.md`.

## Setup

Rust 1.85 or newer (`rust-toolchain.toml` pins 1.99.0). From the repo root:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo run -p confidant-cli -- check --json --no-input --vault examples/demo-vault
```

Supply-chain checks (also in CI):

```sh
cargo deny check --all-features
cargo audit
```

Regenerate golden check JSON after an intentional finding-message change:

```sh
UPDATE_GOLDEN=1 cargo test -p confidant-core --test check_engine
```

## Layout

| Path | What |
|---|---|
| `spec/` | Format spec 0.1 and stable finding codes |
| `packs/coaching/` | Coaching pack contract |
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
JSON for `E_BALANCE_MISMATCH`, `E_SESSION_WITHOUT_NOTES`, and
`E_PAID_SESSION_GAP`, plus gap-rule edges (inclusive window, never-started,
spent package, rule `off`). The demo vault must stay clean under
`confidant check`.
