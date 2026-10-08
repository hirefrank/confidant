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
  "./target/release/confidant find zxqvUniqueTokenAda0 --vault $tmp --json --no-input" \
  "./target/release/confidant find coaching-practice --vault $tmp --json --no-input" \
  "./target/release/confidant check --vault $tmp --json --no-input"
cjk=$(mktemp -d)
./target/release/confidant bench-gen "$cjk" --people 400 --notes 5 --cjk
hyperfine --warmup 3 --runs 10 \
  "./target/release/confidant find zxqvUniqueTokenAda0 --vault $cjk --json --no-input" \
  "./target/release/confidant find coaching-practice --vault $cjk --json --no-input"
```

`--cjk` fills note bodies with no-space CJK prose (an embedded dash, no
ASCII spaces) so the scanner is timed on long runs that are not English
word boundaries. Hit counts must still match `grep -ri`.

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

Measured 2026-10-08 on the milestone 1 cloud-agent VM after Review #9
(all ledger files for link tokens, in-vault symlink resolve, find refuse
on unread). `find` hit counts match `grep -ri` exactly (1 unique, 2,400
common).

Hardware: Intel Xeon (4 logical CPUs), Linux 6.12, `confidant` release
build (`rustc 1.99.0`). Hyperfine 2.0.0, **3 warmup runs, 10 timed runs**.
Spread is mean ± one standard deviation; min and max are the observed range.

| Command | Hits / findings | Mean | σ | Min | Max |
|---|---:|---:|---:|---:|---:|
| `find zxqvUniqueTokenAda0` (one profile) | 1 | **109.1 ms** | 1.7 ms | 106.7 ms | 112.6 ms |
| `find coaching-practice` (every record) | 2,400 | **110.7 ms** | 1.3 ms | 108.5 ms | 112.1 ms |
| `check` | 0 findings | **75.6 ms** | 1.6 ms | 73.8 ms | 78.6 ms |

Peak RSS was about 34–43 MiB (check ~34 MiB, find ~43 MiB).

## Section 9b item 4

A sequential plaintext scan of a few hundred clients, with realistic
note sizes (KB transcripts), dozens of sessions per client, and
multi-year ledgers, stays around **110 ms** for `find` (cleared
allowlist plus scan) and **75 ms** for `check` — still inside interactive
range. The earlier ~70 ms `find` figure was the same 400×5 layout before
the fixed-point allowlist.

QMD (local BM25 + vectors, index never in git) is still the plan after
v0. Milestone 2 record-bound AEAD is **not** in this measurement; do not
treat 100 ms as a decrypt-inclusive budget.
