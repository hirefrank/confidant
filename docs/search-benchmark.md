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

Measured 2026-10-08 on the milestone 1 cloud-agent VM after Review #14
(bare-ULID index seeded from every prefixed vault name and rejected
path, `E_LEDGER_DATE` without a path in the message). `find` hit counts
match `grep -ri` exactly (1 unique, 2,400 common) on both the English
and `--cjk` vaults.

Hardware: Intel Xeon (4 logical CPUs), Linux 6.12, `confidant` release
build (`rustc 1.99.0`). Hyperfine 2.0.0, **3 warmup runs, 10 timed runs**.
Spread is mean ± one standard deviation; min and max are the observed range.

English filler:

| Command | Hits / findings | Mean | σ | Min | Max |
|---|---:|---:|---:|---:|---:|
| `find zxqvUniqueTokenAda0` (one profile) | 1 | **203.7 ms** | 5.3 ms | 197.5 ms | 215.1 ms |
| `find coaching-practice` (every record) | 2,400 | **213.7 ms** | 24.3 ms | 195.7 ms | 280.5 ms |
| `check` | 0 findings | **84.3 ms** | 1.9 ms | 82.0 ms | 88.4 ms |

`--cjk` (no-space CJK note bodies):

| Command | Hits / findings | Mean | σ | Min | Max |
|---|---:|---:|---:|---:|---:|
| `find zxqvUniqueTokenAda0` | 1 | **259.4 ms** | 8.4 ms | 249.8 ms | 275.7 ms |
| `find coaching-practice` | 2,400 | **274.4 ms** | 25.9 ms | 254.5 ms | 342.6 ms |
| `check` | 0 findings | **89.0 ms** | 1.4 ms | 87.4 ms | 92.0 ms |

Peak RSS was about 33–46 MiB (check ~33–35 MiB, find ~45–46 MiB).
An 80k-character CJK line, a 320k-character URL line, and a 2 MB
Crockford line (vault ULID in the middle) each scan in well under 1 s
in release (guarded by `scan_id_tokens_is_linear_on_long_cjk_and_url_lines`).

## Section 9b item 4

A sequential plaintext scan of a few hundred clients, with realistic
note sizes (KB transcripts), dozens of sessions per client, and
multi-year ledgers, stays around **214 ms** for `find` (cleared
allowlist plus scan, including every 26-character Crockford window
against every ULID the vault names) and **84 ms** for `check` — still
inside interactive range. The same layout with no-space CJK note bodies
is about **274 ms** for `find` (previously 5.6 s when glue scanned back
to the last space at every character). The earlier ~70 ms `find` figure
was the same 400×5 layout before the fixed-point allowlist; Review #11
was ~117 ms English / ~180 ms CJK; Review #12 was ~145 ms English /
~200 ms CJK at word boundary; Review #13 was ~151 ms English / ~226 ms
CJK before seeding the ULID index from every prefixed name.

QMD (local BM25 + vectors, index never in git) is still the plan after
v0. Milestone 2 record-bound AEAD is **not** in this measurement; do not
treat 100 ms as a decrypt-inclusive budget.
