# Search speed (milestone 1)

Architecture section 9b: v0 searches by scanning plaintext, which should be
fast enough for a few hundred clients. Milestone 1 measures it.

Method: `confidant bench-gen` writes a fake vault (no real names), then
`confidant find` scans every record body and ledger line. No index.

```sh
cargo build --release -p confidant-cli
tmp=$(mktemp -d)
./target/release/confidant bench-gen "$tmp" --people 400 --notes 5
./target/release/confidant find zxqv-unique-token-ada-0 --vault "$tmp" --json
./target/release/confidant find coaching-practice --vault "$tmp" --json
```

## Results

Measured 2026-10-08 on the milestone 1 cloud-agent VM.

Hardware: Intel Xeon (4 logical CPUs), Linux 6.12, `confidant` release
build (`rustc 1.99.0`). Vault: 400 people × 5 notes + monthly ledger =
2,402 files, 2,400 records, 1,200 ledger entries.

| Query | Hits | Wall time (cold) | Wall time (warm) |
|---|---:|---:|---:|
| `zxqv-unique-token-ada-0` (one profile) | 1 | 38 ms | 36 ms |
| `coaching-practice` (every record) | 2,400 | 52 ms | 60 ms |

`confidant check` on the same vault: 36 ms, 0 findings.

A plaintext scan is well inside interactive range at a few hundred clients.
QMD (local BM25 + vectors, index never in git) is still the plan after v0.
