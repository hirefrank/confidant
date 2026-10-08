# QMD search: design notes

How the `qmd-search` skill integrates [QMD](https://github.com/tobi/qmd)
into Confidant, and the decisions behind it. Binding constraints: ADR-6
(indexes are throwaway, gitignored, trusted devices only), ADR-8 (QMD is
not a Rust dependency; integration via skill/script), architecture §9b
item 4 (trusted devices with encrypted disks; index never in git, never
synced), and GitHub issue #8 (QMD must honor the §12 fail-closed
allowlist, `no-ai` included).

## Architecture

```
vault/                                  trusted device, encrypted disk
├── people/...  orgs/...  ledger/...    plaintext in M1; enc: envelopes post-M2
└── .confidant/
    ├── qmd-corpus/                     decrypted corpus, gitignored (built by qmd-index)
    └── qmd/                            qmd's own store: index.sqlite + config/
                                        (INDEX_PATH/QMD_CONFIG_DIR env; was ~/.cache/qmd)

agent ── bin/qmd-query ──┬── qmd query --json ──▶ ranked hits
                        └── confidant find ────▶ allowlist oracle (per hit)
```

Two processes, two responsibilities:

- **Index time** (`bin/qmd-index.py`): copy decrypted vault content into
  `.confidant/qmd-corpus/`, register it as the `confidant` QMD collection.
  The index is *dumb*: it may contain content from records that are not
  cleared (`no-ai`, malformed IDs, dangling refs, merge-group taint). This
  is architecturally accepted — "local indexes and caches contain plaintext
  and embeddings... sensitive, gitignored, stay on trusted devices" (§4
  threat model).
- **Query time** (`bin/qmd-query.py`): run QMD, then verify *every* hit
  through `confidant find` before returning it. A hit is kept only if the
  same file appears in `find`'s matches with full detail, which happens
  exactly when the content is cleared under §12. Anything unverifiable is
  dropped — fail closed.

## Guardrails on where the plaintext lives (Silas's PR review, 2026-10-08)

The corpus is a plaintext mirror of the whole vault, *including* `no-ai`
records — so where it (and QMD's own index) may live is enforced in code,
not just documented. `qmd-index` refuses to build unless all of these hold:

1. **The corpus is git-ignored.** The script probes
   `git -C <vault> check-ignore -q .confidant/qmd-corpus/x` and refuses with
   a fix message (`echo '.confidant/' >> .gitignore`) if the corpus isn't
   ignored. A user's vault is its own git repo and may not ignore
   `.confidant/` — one `git add -A` must never commit the corpus.
2. **The disk is encrypted** (architecture §9b item 4). Auto-detected:
   `fdesetup isactive` on macOS, or a `crypt`-type ancestor of the vault's
   backing device in `lsblk` on Linux. If detection is impossible, the
   build refuses unless the operator passes `--i-confirm-encrypted-disk`
   (having verified it themselves). The script prints which path it took.
3. **QMD's own store stays with the vault, out of backups.** The index DB
   and collection registry move under `<vault>/.confidant/qmd/` via the
   `INDEX_PATH` and `QMD_CONFIG_DIR` env vars (both documented qmd
   overrides); embedding models stay in the default cache (no PII, large).
   Both directories are created `0700`; on macOS both get
   `tmutil addexclusion` (best-effort, warns on failure). A `confidant`
   collection left in qmd's default store by older versions is removed on
   first run (migration), so no plaintext index lingers in `~/.cache`.

`qmd-query` sets the same env vars, so queries always hit the vault-local
store.

## The allowlist decision (issue #8's core requirement)

**Chosen: filter at query time, with the CLI as the single source of
truth.** The skill never reimplements §12.

Considered and rejected: *index only cleared content.* Computing the
cleared set at index time would duplicate the §12 fixed-point logic (or
lean on fragile tricks like `find "e"`), and any divergence between the
two implementations is a leak. It also goes stale: a vault change between
reindexes could leave newly-uncleared content searchable.

With query-time filtering:
- No duplicated logic to drift. The §12 implementation lives in exactly
  one place (the Rust CLI).
- Index staleness can only *miss* results, never leak: a hit for content
  that has since become uncleared is dropped by the live check.
- `no-ai` is honored by construction: `no-ai` records are uncleared, so
  their hits never verify.

The cost is one `find` invocation per distinct hit file (~100–160 ms each
on a 400-record vault) — acceptable for an interactive search skill, and
the script dedupes files before verifying.

## Verification method

For each distinct hit file, the script extracts a distinctive substring
(longest clean alphanumeric run, 24–60 chars) from the hit text and runs
`confidant find "<substring>" --json`. The hit is kept iff some match has
`path` equal to the hit's vault-relative path *and* a full `excerpt`
(reduced findings carry no excerpt, so they can't pass). This works
uniformly for keyword and semantic hits — even a pure vector match
contains file text, and `find` does substring matching — and for ledger
lines as well as record files, without any ID parsing in the skill.

Two real-qmd contract details the scripts handle:

- qmd `--json` reports hits as `qmd://<collection>/<relpath>` URIs, not
  filesystem paths; `qmd-query` strips the scheme to get the
  vault-relative path (hits that don't resolve inside the corpus are
  ignored). Snippets carry a leading `@@ -a,b @@ (x before, y after)`
  diff header, which is stripped before probing.
- qmd collections match `**/*.md` only, so ledger `.cfd` files would be
  invisible. `qmd-index` mirrors each `ledger/*.cfd` as a sibling
  `.cfd.md` in the corpus; `qmd-query` maps those hits back to the real
  `.cfd` path before verification.

## Encrypted records (post-M2 contract)

`qmd-index` detects post-M2 `enc:` envelopes and **skips those files with a
warning**. Rationale: indexing ciphertext is useless, and indexing
wrongly-"decrypted" content would be a leak. When `confidant-crypt` lands
(PR B), the corpus step must decrypt through the CLI (e.g. a
`confidant export`/`find --decrypt` path); until then, skipping is the
fail-closed choice. This is marked in the script, not silently assumed.

## What stays in the CLI

- The §12 allowlist itself (unchanged).
- Plain `find` as the fallback: when QMD or the index is missing,
  `qmd-query` delegates to `confidant find --json` and says so on stderr.
- A future `confidant reindex` (ADR-6, PR C's CLI work) can subsume
  `qmd-index`; until then the skill owns corpus builds.

## Non-goals

- No Rust changes in this PR. No QMD dependency in the CLI. No index in
  git, no syncing the index anywhere, no plaintext leaving the trusted
  device.
- No relevance tuning exposed: `qmd search` (BM25) is the default mode
  because it needs no model downloads; `--mode hybrid|vector` covers the
  reranked and semantic-only cases once `qmd embed` has run (hybrid/vector
  are refused with a clear error until vectors exist, rather than hanging
  on a multi-GB first-run model download).
