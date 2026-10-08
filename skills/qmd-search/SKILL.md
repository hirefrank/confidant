---
name: "qmd_search"
description: "Semantic + keyword search over a Confidant vault via a local QMD index (BM25, vectors, rerank). Honors the spec §12 fail-closed allowlist including no-ai; falls back to `confidant find` when no index exists."
---

# QMD Search

Local-first semantic search for a Confidant vault, built on [QMD](https://github.com/tobi/qmd)
(BM25 + vector search + LLM reranking, all on-device via `node-llama-cpp`).
QMD is **not** a dependency of the Rust CLI (ADR-6, ADR-8): this skill is the
integration. Plain `confidant find` remains the fallback and the source of
truth for the search allowlist.

## Trust and safety (read first)

- **Trusted devices with encrypted disks only.** The index holds plaintext
  chunks and embeddings. The corpus lives under `<vault>/.confidant/qmd-corpus/`
  and QMD's own index under `<vault>/.confidant/qmd/` (both gitignored, never
  committed, never synced, directories `0700`; on macOS both are excluded from
  Time Machine). Treat them as sensitive, exactly like `.confidant/`.
- **`qmd-index` enforces three guardrails before building** (the corpus is a
  plaintext mirror of the vault, including `no-ai` records):
  1. it refuses unless `.confidant/qmd-corpus/` is git-ignored in the vault's
     repo (fix: `echo '.confidant/' >> .gitignore` in the vault);
  2. it refuses unless the disk is encrypted — auto-detected (FileVault on
     macOS, dm-crypt ancestor in `lsblk` on Linux) or asserted with
     `--i-confirm-encrypted-disk`;
  3. QMD's index DB and collection registry are moved under the vault via
     `INDEX_PATH`/`QMD_CONFIG_DIR` (never `~/.cache`), and any `confidant`
     collection left in qmd's default store is removed on first run.
- **The §12 allowlist is enforced at query time, not index time.** The index
  may contain decrypted content from records that are *not* cleared
  (`no-ai`, malformed IDs, dangling refs, merge-group taint). `bin/qmd-query`
  drops every hit whose record is not cleared *before* returning anything,
  by asking `confidant find` — the CLI stays the single source of truth, so
  allowlist logic can never drift between the index and the CLI. A hit that
  cannot be verified as cleared is dropped (fail closed).
- **Encrypted envelopes are never indexed as plaintext.** `bin/qmd-index`
  skips files carrying an `enc:` envelope and warns. Indexing ciphertext is
  pointless and indexing wrongly-decrypted content is a leak; when
  `confidant-crypt` lands, the corpus step must decrypt through the CLI.

## Setup

```sh
# one-time: install QMD (Node 20+)
npm install -g @tobilu/qmd        # or: bun install -g @tobilu/qmd

# per vault: build the corpus + collection (needs --vault or CONFIDANT_VAULT)
skills/qmd-search/bin/qmd-index --vault /path/to/vault

# optional: embeddings for vector search (downloads GGUF models on first run)
qmd embed
```

`qmd-index` is idempotent: rebuilding replaces the corpus and re-adds the
collection. Re-run it after pulls, merges, or anything that changes vault
content — a stale index can only *miss* results (hits are allowlist-filtered
at query time, so staleness can never leak).

## Querying

```sh
# keyword (BM25) — default; works with no model downloads
skills/qmd-search/bin/qmd-query --vault /path/to/vault "invoice march"

# hybrid (BM25 + vectors + rerank) — best quality, needs `qmd embed` first
# (first run downloads multi-GB GGUF models; the script refuses hybrid/vector
#  until vectors exist rather than hanging on a download)
skills/qmd-search/bin/qmd-query --vault /path/to/vault --mode hybrid "quarterly planning"

# semantic only
skills/qmd-search/bin/qmd-query --vault /path/to/vault --mode vector "how to deploy"
```

Output is JSON on stdout (mirrors `confidant find --json`, plus `score` and
`via` per match):

```json
{
  "schema_version": "1",
  "ok": true,
  "vault": "/path/to/vault",
  "mode": "bm25",
  "query": "quarterly planning",
  "matches": [
    {"id": "p-01M3TC5H00MPJG000000000000", "path": "people/p-01M3TC5H00MPJG000000000000/profile.md",
     "line": 7, "excerpt": "…", "score": 0.87, "via": "qmd"}
  ],
  "dropped_uncleared": 2,
  "findings": []
}
```

`dropped_uncleared` counts hits the allowlist filter removed. If QMD or the
index is missing, the script falls back to `confidant find --json` and notes
it on stderr.

## Tooling

- `bin/qmd-index.py [--vault PATH] [--embed] [--i-confirm-encrypted-disk]` — builds
  `<vault>/.confidant/qmd-corpus/` from decrypted vault content and registers
  it as the `confidant` QMD collection (always a full rebuild: wipes the old
  corpus and re-adds the collection). Refuses unless the corpus is git-ignored
  and the disk is encrypted (see guardrails above). Puts QMD's own store under
  `<vault>/.confidant/qmd/`. Skips `enc:`-enveloped files with a
  warning. Mirrors each `ledger/*.cfd` as a sibling `.cfd.md` so QMD's
  `**/*.md` collection pattern covers ledger facts too (hits map back to the
  real `.cfd` path). `--embed` runs `qmd embed` afterwards.
- `bin/qmd-query.py [--vault PATH] [--mode hybrid|bm25|vector] [-n N] QUERY`
  — queries QMD, allowlist-filters every hit through `confidant find`, and
  emits the JSON above. Falls back to plain `find` when QMD/index is absent.

## Operating rules

1. Never commit, copy, or sync anything under `<vault>/.confidant/` — the
   corpus and any QMD state there are plaintext and gitignored for a reason.
2. Never weaken the query-time filter to "fix" empty results. Empty results
   mean either the index is stale (rebuild it) or nothing cleared matches.
3. `no-ai` records must never surface: they are uncleared by construction,
   so the filter drops them. If a `no-ai` record ever appears in output,
   treat it as a bug, not a tuning knob.
4. Keep `confidant find` working — it is the fallback and the allowlist
   oracle. This skill must not change the CLI.
