# Search speed (milestone 1)

Architecture section 9b, item 4: v0 searches by scanning plaintext, which
should be fast enough for a few hundred clients. Milestone 1 measures it.

Method: `confidant bench-gen` writes a fake vault (no real names), then
`hyperfine` times `confidant find` and `confidant check`. No index. Files are
plaintext; **decrypt / AEAD is not measured** (`confidant-crypt` is a stub
until the milestone 2 design review). A per-file decrypt cost is therefore
not in these numbers and would scale with file count, not with match count.

`bench-gen` refuses a non-empty directory or an existing vault.

```sh
cargo build --release --locked -p confidant-cli
tmp=$(mktemp -d)
./target/release/confidant bench-gen "$tmp" --people 400 --notes 5
hyperfine --warmup 3 --runs 10 \
  "./target/release/confidant find zxqv-unique-token-ada-0 --vault $tmp --json --no-input" \
  "./target/release/confidant find coaching-practice --vault $tmp --json --no-input" \
  "./target/release/confidant check --vault $tmp --json --no-input"
```

## Vault

Generated 2026-10-08. 400 people, 5 notes each, 24 sessions per person
across 2024–2025, monthly ledgers through 2026-10, package `open` on
2024-01-01.

| | |
|---|---:|
| Files | 2,426 |
| Markdown records | 2,400 (400 profiles + 2,000 notes) |
| Ledger files | 25 |
| Ledger entries | 10,400 |
| Note body | ~4.7 KiB each (KB-scale transcripts) |
| Tree size | 10.0 MiB |

Session-note and paid-gap checks are `off` in the generated config so
`check` reports the scan/accounting cost, not a wall of warnings.

## Results

Measured 2026-10-08 on the milestone 1 cloud-agent VM.

Hardware: Intel Xeon (4 logical CPUs), Linux 6.12, `confidant` release
build (`rustc 1.99.0`). Hyperfine 2.0.0, **3 warmup runs, 10 timed runs**.
Spread is mean ± one standard deviation; min and max are the observed range.

| Command | Hits / findings | Mean | σ | Min | Max |
|---|---:|---:|---:|---:|---:|
| `find zxqv-unique-token-ada-0` (one profile) | 1 | **68.4 ms** | 3.1 ms | 65.9 ms | 75.9 ms |
| `find coaching-practice` (every record) | 2,400 | **72.4 ms** | 1.9 ms | 70.2 ms | 76.1 ms |
| `check` | 0 findings | **65.8 ms** | 1.0 ms | 63.5 ms | 67.0 ms |

Peak RSS was about 31–34 MiB.

## Section 9b item 4

A sequential plaintext scan of a few hundred clients, with realistic
note sizes (KB transcripts), dozens of sessions per client, and
multi-year ledgers, stays around **70 ms** — well inside interactive
range. The earlier ~38 ms figure was the same 400×5 layout with tiny
notes and far fewer ledger lines.

QMD (local BM25 + vectors, index never in git) is still the plan after
v0. Milestone 2 record-bound AEAD is **not** in this measurement; do not
treat 70 ms as a decrypt-inclusive budget.
