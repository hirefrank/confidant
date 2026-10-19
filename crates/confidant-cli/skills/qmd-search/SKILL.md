---
name: "qmd-search"
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
- **`confidant reindex` builds the corpus and enforces its guardrails**
  (issue #37, ADR-6). The CLI owns content, the §12 cleared set,
  decryption, and permissions; this skill only registers/embeds on top.
  The CLI refuses rather than build a partial corpus:
  1. it refuses unless `.confidant/` is git-ignored in the vault's repo
     (fix: `echo '.confidant/' >> .gitignore` in the vault);
  2. it refuses — writing nothing — when an encrypted record on the vault
     could not be decrypted (no device key / key absent) or was refused as
     tampered, naming the counts and pointing at `confidant init` /
     `confidant recover`. A corpus that silently omits records is worse
     than no corpus;
  3. it writes dirs `0700` and files `0600`.
- **`qmd-index` keeps the encrypted-disk assertion** (architecture §9b
  item 4, device policy, not a per-command check): it refuses unless the
  disk is encrypted — auto-detected (FileVault on macOS, dm-crypt ancestor
  in `lsblk` on Linux) or asserted with `--i-confirm-encrypted-disk`. QMD's
  index DB and collection registry are moved under the vault via
  `INDEX_PATH`/`QMD_CONFIG_DIR` (never `~/.cache`), and any `confidant`
  collection left in qmd's default store is removed on first run.
- **The §12 allowlist is enforced at query time, and uncleared records are
  also excluded at index time.** `confidant reindex` copies only the exact
  cleared set computed by the CLI (cleared record files and cleared ledger
  lines) into the corpus, so a query-path bug degrades to missing results
  rather than risking a leak — this is #38's index-time exclusion, now
  enforced inside the CLI. `bin/qmd-query` still verifies every hit against
  the live cleared set *before* returning anything, in one
  `confidant allowlist --json` call per query (#538): record hits by path
  (`cleared_files`), ledger hits by `(file, line)` (`cleared_ledger_lines`) —
  the corpus mixes people and can be stale after a `no-ai` change, so the
  file alone is not enough. The CLI stays the single source of truth, so
  allowlist logic can never drift between the index and the CLI. A hit that
  cannot be verified as cleared is dropped (fail closed).
- **`no-ai` records are never decrypted into the corpus.** The build goes
  through the CLI's `for_agent` read path, which never decrypts a `no-ai`
  envelope; `no-ai` is excluded by construction, not just by the
  query-time filter.
- **Encrypted envelopes are decrypted through the CLI.** The old script
  skipped `enc:` files and warned; now the CLI decrypts cleared envelopes
  through the read path and refuses (rather than skipping) when a key is
  missing, so the corpus is either complete for this device or not built.

## Setup

```sh
# one-time: install QMD (Node 20+)
npm install -g @tobilu/qmd        # or: bun install -g @tobilu/qmd

# per vault: build the corpus + collection (needs --vault or CONFIDANT_VAULT)
# (the corpus itself is built by `confidant reindex`, which the script runs first)
"$(confidant which --skills-dir)"/qmd-search/bin/qmd-index.py --vault /path/to/vault

# optional: embeddings for vector search (downloads GGUF models on first run)
qmd embed
```

`qmd-index` is idempotent: rebuilding replaces the corpus and re-adds the
collection. Re-run it after pulls, merges, or anything that changes vault
content — hits are verified against the live cleared set at query time
(record paths, ledger lines), so a stale index cannot surface a record the
CLI does not clear. It can, however, miss a hit, mislabel a line number, or
return a **stale snippet of a still-cleared record**: the excerpt comes from
the corpus copy, so a note edited in the vault keeps returning its old text
until `qmd-index` reruns. That is not a §12 leak (the record is still
cleared and the corpus already holds that text), but the text can be out of
date. For a ledger file, one edited or removed vault line makes the
corpus-to-vault line alignment run off the end and drop every later corpus
line in that file until the next reindex; it fails closed (a dropped line is
never returned), and a rerun clears it.

## Querying

```sh
# keyword (BM25) — default; works with no model downloads
"$(confidant which --skills-dir)"/qmd-search/bin/qmd-query.py --vault /path/to/vault "invoice march"

# hybrid (BM25 + vectors + rerank) — best quality, needs `qmd embed` first
# (first run downloads multi-GB GGUF models; the script refuses hybrid/vector
#  until vectors exist rather than hanging on a download)
"$(confidant which --skills-dir)"/qmd-search/bin/qmd-query.py --vault /path/to/vault --mode hybrid "quarterly planning"

# semantic only
"$(confidant which --skills-dir)"/qmd-search/bin/qmd-query.py --vault /path/to/vault --mode vector "how to deploy"
```

Output is JSON on stdout (mirrors `confidant find --json`, plus `score` and
`via` per match). `id` is derived from the hit's path (records) or from the
first record ID on the line (ledger), and `excerpt` comes from the QMD hit
or the corpus line — no per-hit `find` is run:

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

`dropped_uncleared` counts hits the allowlist filter removed — including hits
dropped only because they are outside the caller's pack scope, so a nonzero
count tells a scoped agent that out-of-scope matches exist (accepted for
now). If QMD or the
index is missing, the script falls back to `confidant find --json` and notes
it on stderr.

## Tooling

- `bin/qmd-index.py [--vault PATH] [--cli PATH] [--embed] [--i-confirm-encrypted-disk]` — runs
  `confidant reindex` to (re)build `<vault>/.confidant/qmd-corpus/` (a full
  rebuild: the CLI wipes the old corpus), then registers it as the `confidant`
  QMD collection (removing any previous one first). It never walks the vault
  itself. It keeps one guardrail: it refuses unless the disk is encrypted
  (auto-detected or `--i-confirm-encrypted-disk`); the gitignore refusal and
  the `0700`/`0600` permissions live in `confidant reindex`. Puts QMD's own
  store under `<vault>/.confidant/qmd/`. `--cli` points at the confidant
  binary (default `confidant` on PATH). Each kept `ledger/*.cfd` is written by
  the CLI with a sibling `.cfd.md` so QMD's `**/*.md` collection pattern
  covers ledger facts too (hits map back to the real `.cfd` path). `--embed`
  runs `qmd embed` afterwards.
- `bin/qmd-query.py [--vault PATH] [--mode hybrid|bm25|vector] [-n N] [--packs LIST] QUERY`
  — queries QMD, verifies every hit against `confidant allowlist --json`
  (one call per query; #538), and emits the JSON above. A ledger hit is kept
  only when its (corpus) line resolves to a cleared vault line: `reindex`
  writes only cleared ledger lines into the corpus, in order, so
  `qmd-query` aligns corpus and vault lines by text to report real vault
  line numbers. `--packs` scopes the allowlist call, so a scoped agent
  never sees hits owned by another pack (issue #178). Falls back to plain
  `find` when QMD/index is absent.

## Operating rules

1. Never commit, copy, or sync anything under `<vault>/.confidant/` — the
   corpus and any QMD state there are plaintext and gitignored for a reason.
2. Never weaken the query-time filter to "fix" empty results. Empty results
   mean either the index is stale (rebuild it) or nothing cleared matches.
3. `no-ai` records must never surface: they are uncleared by construction,
   so the filter drops them. If a `no-ai` record ever appears in output,
   treat it as a bug, not a tuning knob.
4. Keep the plain `confidant find` fallback working — it is what `qmd-query`
   uses when QMD or the index is missing. This skill must not change the CLI.
