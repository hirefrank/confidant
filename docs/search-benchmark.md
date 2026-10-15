# Search speed (milestone 1)

Architecture section 9b, item 4: v0 searches by scanning plaintext, which
should be fast enough for a few hundred clients. Milestone 1 measures it.

Method: `confidant bench-gen` writes a fake vault (no real names), then
`hyperfine` times `confidant find` and `confidant check`. No index. Files are
plaintext; **decrypt / AEAD is not measured** (`confidant-crypt` is a stub
until the milestone 2 design review). A per-file decrypt cost is therefore
not in these numbers and would scale with file count, not with match count.
(Update 2026-10-15: `bench-gen --encrypted` now measures the decrypt path
and `--touch` a touch-heavy ledger — see the issue #188 follow-up below.)

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
| Ledger entries | 10,320 |
| Note body | ~4.6 KiB each (KB-scale transcripts) |
| Tree size | 10.0 MiB |

Session-note and paid-gap checks are `off` in the generated config so
`check` reports the scan/accounting cost, not a wall of warnings.

## Results

Measured 2026-10-08 on the milestone 1 cloud-agent VM after Review #15
(fixed-point drop worklist, dangling prefixed ULIDs match bare windows
only, prefixed tokenize-once, HashSet `open` lines, filename token scan).
`find` hit counts match `grep -ri` exactly (1 unique, 2,400 common) on
both the English and `--cjk` vaults.

Hardware: Intel Xeon (4 logical CPUs), Linux 6.12, `confidant` release
build (`rustc 1.99.0`). Hyperfine 2.0.0, **3 warmup runs, 10 timed runs**.
Spread is mean ± one standard deviation; min and max are the observed range.

English filler:

| Command | Hits / findings | Mean | σ | Min | Max |
|---|---:|---:|---:|---:|---:|
| `find zxqvUniqueTokenAda0` (one profile) | 1 | **160.3 ms** | 2.4 ms | 156.4 ms | 163.3 ms |
| `find coaching-practice` (every record) | 2,400 | **161.1 ms** | 1.9 ms | 158.9 ms | 163.8 ms |
| `check` | 0 findings | **98.3 ms** | 14.1 ms | 91.7 ms | 137.7 ms |

`--cjk` (no-space CJK note bodies):

| Command | Hits / findings | Mean | σ | Min | Max |
|---|---:|---:|---:|---:|---:|
| `find zxqvUniqueTokenAda0` | 1 | **243.6 ms** | 3.2 ms | 239.6 ms | 250.6 ms |
| `find coaching-practice` | 2,400 | **257.1 ms** | 22.3 ms | 244.0 ms | 319.4 ms |
| `check` | 0 findings | **99.6 ms** | 2.5 ms | 97.0 ms | 104.5 ms |

Peak RSS was about 33–46 MiB (check ~33–35 MiB, find ~44–46 MiB).
An 80k-character CJK line, a 320k-character URL line, and a 2 MB
Crockford line (vault ULID in the middle) each scan in well under 1 s
in release (guarded by `scan_id_tokens_is_linear_on_long_cjk_and_url_lines`).
One `open` line with 2,000 `p-` and 2,000 `pkg-` tokens finishes in
well under 1 s in release (guarded by `find_open_line_with_thousands_of_ids_is_fast`).

## Follow-up: issue #2 (2026-10-11)

Same 400×5 vaults, regenerated. Machine: AMD Ryzen 5 7640U (12 logical
CPUs), Linux, release build with system rustc 1.98.1 (repo pins 1.99.0;
no behavior-relevant APIs involved). No hyperfine on this machine:
each cell is min / median / max over 10–15 `date`-timed runs after
3 warmups. `common` uses `--limit 2500` so all 2,400 hits render
(the default `--limit 50` truncates printing, not scanning).

| Command | Hits | Min | Median | Max |
|---|---:|---:|---:|---:|
| `find zxqvUniqueTokenAda0` (English) | 1 | 107 ms | 110 ms | 115 ms |
| `find coaching-practice --limit 2500` (English) | 2,400 | 111 ms | 113 ms | 117 ms |
| `check` (English vault) | 0 findings | 58 ms | 60 ms | 62 ms |
| `find zxqvUniqueTokenAda0` (`--cjk` vault) | 1 | 173 ms | 177 ms | 181 ms |

Main-branch numbers on the same machine for comparison: find unique
154/172/187, find common-full 159/174/180, check 107/110/112
(min/median/max). So find is down ~50 ms (~30%) and check ~50 ms
(~45%), back at the ~115 ms Review #11 baseline for English.

What changed (no §12 change — the allowlist rules, token verdicts, and
output shapes are untouched):

- Markdown record files load in parallel (`std::thread::scope`, one
  chunk per core, merged back in walk order).
- ULIDs are interned (`Arc<str>` in `RecordId`): clones across the
  worklist and indexes share the allocation instead of re-allocating.
- The ULID indexes and the cleared-set worklist use hash maps/sets
  instead of ordered maps/sets (iteration order never affects output:
  hits and findings are sorted at the end, the worklist converges to
  the same fixed point regardless of processing order).
- `ledger_line_verb` compares without allocating (owned only on match).
- The seed walk no longer re-lists collection subtrees: names and
  token seeds are captured during the collections walk that already
  visits every entry.

Equivalence evidence: `load_vault` output (records, findings, path
IDs, path ULIDs, ledger lines) dumped on the bench vault is
byte-identical before/after; `find --json` with 2,400 matches is
byte-identical before/after; the full workspace suite and golden files
pass unchanged.

## Follow-up: issue #188 (2026-10-15)

The recommendation asked for the benchmark re-run with encryption on and
with touch volume before building any cache. `bench-gen` grew two flags:

- `--touch`: enables `personal@0.1` and writes 100 small `touch` ledger
  lines per person across 2024–2026 (40,000 lines; ledger entries
  10,320 → 50,320).
- `--encrypted`: keys the fresh vault (`init` + `keys init-client` per
  person under throwaway keys, no OS keychain) and encrypts all 2,400
  records through the production `encrypt_file` path. Needs the
  `--all-features` build (the operator key comes from the
  test-overrides env source). The throwaway device key and bench-HOME
  path are left beside the vault as `.bench-device-key` (0600) and
  `.bench-home-path` (both uncommitted; never printed); measuring
  re-exports them, and real `~/.config/confidant` is never touched:

```sh
cargo build --release --all-features --locked -p confidant-cli
tmp=$(mktemp -d)
./target/release/confidant bench-gen "$tmp" --people 400 --notes 5 --encrypted --touch
export HOME=$(cat "$tmp/.bench-home-path")
export CONFIDANT_DEVICE_KEY=$(cat "$tmp/.bench-device-key")
./target/release/confidant find coaching-practice --vault "$tmp" --json --no-input
./target/release/confidant check --vault "$tmp" --json --no-input
```

Same 400×5 layout, same Ryzen 5 7640U machine as the issue-#2
follow-up, release build (`rustc 1.98.1`; repo pins 1.99.0). No
hyperfine on this machine: each cell is mean ± stdev over 5 timed runs
after warmups. `find` uses the default `--limit 50` (truncates
printing, not scanning — scan work is identical).

| Vault | Ledger entries | `find coaching-practice` | `check` |
|---|---|---:|---:|
| plaintext | 10,320 | 180.0 ± 14.0 ms | 62.0 ± 3.4 ms |
| plaintext + touch | 50,320 | 338.2 ± 13.4 ms | 124.5 ± 7.9 ms |
| encrypted | 10,320 | 670.1 ± 10.6 ms | 78.4 ± 2.2 ms |
| encrypted + touch | 50,320 | 984.2 ± 27.0 ms | 163.1 ± 5.9 ms |

Validity: `check` is clean (0 errors, 0 warnings) on all four vaults,
and the encrypted vaults report `skipped_encrypted: 0` with full match
sets — the decrypt path is genuinely measured, not skipped. (An early
run without the device key/anchor env returned 0 matches with
`skipped_encrypted: 2400`; those numbers were discarded.)

Reading: touch volume scales both commands roughly with ledger size
(~+160 ms find, ~+60 ms check for 5× ledger lines). Encryption adds
~490 ms to `find` (per-file AEAD open across 2,400 records) but only
~16 ms to `check` (the fold works over the plaintext ledger). The
heaviest realistic case — encrypted records plus a touch-heavy ledger —
stays around **1 s for `find`, 163 ms for `check`**.

Recommendation: no cache or index is justified. ~1 s worst case is
inside interactive range, and QMD (local BM25 + vectors, index never in
git) remains the long-term plan. This closes the #188 re-measurement
ask.

## Section 9b item 4

A sequential plaintext scan of a few hundred clients, with realistic
note sizes (KB transcripts), dozens of sessions per client, and
multi-year ledgers, stays around **161 ms** for `find` (cleared
allowlist plus scan, prefixed tokens once per line, bare windows skipped
when already covered) and **98 ms** for `check` — still inside
interactive range. The same layout with no-space CJK note bodies is
about **257 ms** for `find`. The earlier ~70 ms `find` figure was the
same 400×5 layout before the fixed-point allowlist; Review #11 was
~117 ms English / ~180 ms CJK; Review #12 was ~145 ms English / ~200 ms
CJK at word boundary; Review #13 was ~151 ms English / ~226 ms CJK
before seeding the ULID index from every prefixed name; Review #14 was
~214 ms English / ~274 ms CJK after seeding from every prefixed vault
name.

QMD (local BM25 + vectors, index never in git) is still the plan after
v0. Milestone 2 record-bound AEAD is **not** in this measurement; do not
treat 100 ms as a decrypt-inclusive budget. The issue-#2 follow-up
above re-measured after the perf work: ~110 ms English `find`,
~60 ms `check` on the Ryzen machine.
