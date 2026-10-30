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
  in `lsblk` on Linux) or asserted by the operator. Detection is preferred
  and reported when it succeeds; otherwise the assertion can be per run
  (`--i-confirm-encrypted-disk`) or persisted for automated runs on hosts
  where detection is impossible — a cloud VM or container with no local
  `dm-crypt` ancestor (#540) — with `CONFIDANT_ASSUME_ENCRYPTED_DISK=1`
  or `[qmd] assume_encrypted_disk = true` in
  `~/.config/confidant/config.toml`. The persisted forms are a
  device-policy statement by the operator, **not a check**: the script
  prints which mechanism satisfied the gate on stderr, so an assumption
  never masquerades as detection. QMD's index DB and collection registry
  are moved under the vault via `INDEX_PATH`/`QMD_CONFIG_DIR` (never
  `~/.cache`), and any `confidant` collection left in qmd's default store
  is removed on first run.
- **The disk election happens once, at setup (#723).** When the gate
  fails and the operator is present (stdin is a TTY), `qmd-index`
  explains in plain language what the index is (a readable copy of the
  cleared records), why the disk question matters, and what is
  known/unknown about this host — then asks: assert and record, or
  decline. Asserting writes the existing `[qmd] assume_encrypted_disk`
  key (no new key) to the user config, preserving every other key; the
  next run under the same home directory — or the next agent — never
  asks again, because the write is re-parsed and verified before the
  build proceeds (a config that cannot be recorded cleanly refuses
  instead of proceeding on an unrecorded assertion). The election is
  scoped to the home directory, not to a host or a disk: a shared or
  restored `$HOME` carries the assertion to a different disk, and
  `doctor` cannot distinguish that from a local election — revoke it
  by deleting the key or setting it to `false`. Declining means QMD
  stays off and `confidant find` remains the search path. There is no
  third, silent outcome, and a non-TTY run keeps the old refusal rather
  than prompting. Scripted setup uses
  `--assert-and-persist-encrypted-disk` (the non-interactive form of
  answering "assert"). `confidant doctor` reports the persisted
  election forever after as a `qmd-disk` check — "asserted by operator
  (…; an assertion, not a detection)" — per #709, so an assumption
  never renders as detected.
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

# optional: embeddings for hybrid/vector search (downloads GGUF models on first run)
# use the wrapper with --embed so QMD's vault-local INDEX_PATH/QMD_CONFIG_DIR
# store gets the vectors (a bare `qmd embed` targets the default store)
"$(confidant which --skills-dir)"/qmd-search/bin/qmd-index.py --vault /path/to/vault --embed

# preflight the host (issue #722): spec check, model-hub reachability, and
# cold + warm timed smoke queries per mode, with a recommended default
# mode. qmd-index.py runs preflight automatically with --persist
# --chained at the end of setup (unless --skip-preflight), so setup
# itself records the offline decision; the chained run never writes
# default_mode, whatever the probe returns (#778 fix round) — a mode
# change needs a standalone run with an explicit --query (a term
# known to hit the corpus), because the default query can return
# hits through the semantic modes even when the literal phrase is
# absent. --persist records ([qmd] default_mode, and [qmd] offline
# when the hub is unreachable or a hybrid smoke run proves the models
# are cached) in the VAULT-LOCAL preflight file,
# <vault>/.confidant/qmd-preflight.toml, where qmd-query.py honors it
# first, falling back to the global ~/.config/confidant/config.toml
# [qmd] table for vaults with no per-vault file — so a recommendation
# measured on one vault never leaks into another vault on the same
# host, while single-vault setups keep working unchanged. --persist
# never touches the global file: values an old --persist wrote there
# stay honored as fallback. It also clears a stale preflight-written
# offline value the fresh evidence no longer supports, and leaves
# hand-set values alone (saying so). A persisted default_mode is
# kept, never cleared, when an explicit --query probe yields no
# hit-bearing mode (#778): an empty probe is not evidence against
# the old mode. A warm-run failure downgrades the mode to that
# failure — the cold sample is never reused. A smoke run that
# answers with zero hits is reported as ok-empty, never recommended.
# Worst case is ~18 minutes at the default 180s per-mode timeout
# (cold + warm x 3 modes) plus the hub probe; pass --query-timeout
# to bound it. Exit 0 is NOT a gate: read the report (or --json) —
# a LOW DISK / unreachable-hub / no-mode-recommended outcome still
# exits 0.
"$(confidant which --skills-dir)"/qmd-search/bin/qmd-preflight.py --vault /path/to/vault --persist --query coaching
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

A timed-out query says so, and names the suspects (#722): the 0.7.0 field
failure was a 3-minute model-hub (Hugging Face) check through an egress
proxy, not compute — the old fallback reported only `via: find-fallback`
and sent diagnosticians off to blame the hardware. A timeout now reports
the hub as one hypothesis among slow compute / large corpus / model load,
plus the fix (`HF_HUB_OFFLINE=1`, or persist `[qmd] offline = true` via
`qmd-preflight.py --persist`), on stderr and as `fallback_hint` in the
JSON — unless offline mode is already forced, in which case the hint says
so and blames slow compute instead (a hub check cannot be the cause then).
When `--mode` is omitted, the script uses the persisted `[qmd]
default_mode` from preflight when present, else bm25; `[qmd] offline =
true` runs qmd with `HF_HUB_OFFLINE=1` (an explicit `HF_HUB_OFFLINE` in
the shell still wins). The persisted `[qmd]` config is per-vault first:
qmd-query.py reads `<vault>/.confidant/qmd-preflight.toml`, and falls
back to the global `~/.config/confidant/config.toml` `[qmd]` table only
when the vault has no per-vault value — so a *new* per-vault
recommendation never leaks into another vault, and a global value set by
hand is still honored for vaults never preflighted. One legacy caveat: a
global value written by an old `--persist` run (before per-vault
persistence existed) carries no vault attribution, so it is served as
fallback to *every* vault without its own file — including vaults that
never ran preflight. Each such vault stops inheriting that legacy global
value once its own preflight persists a per-vault value.

## Tooling

- `bin/qmd-index.py [--vault PATH] [--cli PATH] [--embed] [--i-confirm-encrypted-disk] [--skip-preflight] [--assert-and-persist-encrypted-disk]` — runs
  `confidant reindex` to (re)build `<vault>/.confidant/qmd-corpus/` (a full
  rebuild: the CLI wipes the old corpus), then registers it as the `confidant`
  QMD collection (removing any previous one first). It never walks the vault
  itself. It keeps one guardrail: it refuses unless the disk is encrypted
  (auto-detected, or asserted with `--i-confirm-encrypted-disk` /
  `CONFIDANT_ASSUME_ENCRYPTED_DISK=1` / `[qmd]
  assume_encrypted_disk = true`; detection is preferred and the mechanism
  used is printed on stderr); the gitignore refusal and
  the `0700`/`0600` permissions live in `confidant reindex`. Puts QMD's own
  store under `<vault>/.confidant/qmd/`. `--cli` points at the confidant
  binary (default `confidant` on PATH). Each kept `ledger/*.cfd` is written by
  the CLI with a sibling `.cfd.md` so QMD's `**/*.md` collection pattern
  covers ledger facts too (hits map back to the real `.cfd` path). `--embed`
  runs `qmd embed` afterwards. Setup ends with an automatic
  `qmd-preflight.py --persist` run (issue #722) unless `--skip-preflight`
  is given: preflight is part of setup, so a cold-start or
  unreachable-hub problem surfaces here, not on the first real query,
  and the recommendation is recorded during setup (no second command
  before the query wrapper honors it); a preflight failure never
  fails the index build.
- `bin/qmd-preflight.py [--vault PATH] [--persist] [--json]` — issue #722:
  spec check (cores, RAM, free disk at the vault store AND the model
  cache vs the ~2.5 GB model footprint, with explicit warnings below the
  2-vCPU / 8 GB field floor; "no NVIDIA GPU detected" wording, since
  Apple Silicon / AMD GPUs are not probed), a short-timeout model-hub
  reachability probe (the configured endpoint: `--hub-url`, else
  `HF_ENDPOINT`, else huggingface.co; a proxy 4xx/5xx does not count as
  reachable; skipped entirely when `HF_HUB_OFFLINE` is already set),
  and cold + warm timed smoke queries per mode on the built corpus,
  ending in a recommended default mode derived from the warm runs; a
  warm-run failure downgrades the mode to that failure, never back to
  the cold sample. Modes are skipped (not failed) when qmd, the
  corpus, or embeddings are missing; modes over the 60s budget are
  never recommended over a mode within it; a zero-hit answer is
  `ok-empty`, never recommended, and only a hit-bearing hybrid `ok`
  counts as proof the models are cached (a timeout/failed/fallback run
  proves nothing) — the JSON report names that proof
  `hybrid_cache_complete`, not `embeddings_present`, since a
  vector-ok / hybrid-failed host has embeddings but no hybrid cache
  proof. Smoke runs inherit the probe's offline decision so a hanging
  hub cannot turn preflight itself into a silent fallback, and
  progress lines go to stderr per run; worst case is ~18 minutes at
  the default 180s per-mode timeout, bound it with `--query-timeout`.
  `--persist` writes `[qmd] offline = true` (when the hub is
  unreachable or the hybrid cache proof holds) to the vault-local
  `<vault>/.confidant/qmd-preflight.toml` (local, gitignored),
  preserving every other key in that file, and clears a stale
  preflight-written `offline` the fresh evidence no longer supports
  (hand-set values are left alone and reported); it writes `[qmd]
  default_mode` only on a run with an explicit `--query` whose
  probe yields a hit-bearing recommendation — a chained run
  (`--chained`) or a run with the default query never changes a
  persisted mode, whatever the probe returns, because the default
  query can hit through the semantic modes (#778 fix round). A
  persisted `default_mode` is kept, never cleared, when an
  explicit --query probe yields no hit-bearing mode — an empty
  probe is not evidence against it (#778). It never
  touches the global user config: values an old `--persist` wrote
  there (including the #723 disk-election key) stay honored as
  fallback for vaults with no per-vault file. Exit 0 whenever the
  report completes, even with no mode recommended — read the report,
  do not gate on the exit code.
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
