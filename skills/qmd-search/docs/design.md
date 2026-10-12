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
    ├── qmd-corpus/                     decrypted corpus, gitignored (built by `confidant reindex`)
    └── qmd/                            qmd's own store: index.sqlite + config/
                                        (INDEX_PATH/QMD_CONFIG_DIR env; was ~/.cache/qmd)

agent ── bin/qmd-query ──┬── qmd query --json ──▶ ranked hits
                        └── confidant find ────▶ allowlist oracle (per hit)

bin/qmd-index ── confidant reindex ──▶ corpus (+ gitignore/perm guardrails)
              └── qmd collection add/embed ──▶ QMD registration
```

Two processes, two responsibilities:

- **Index time** (`confidant reindex`, wrapped by `bin/qmd-index.py`): the
  CLI copies decrypted vault content into `.confidant/qmd-corpus/` and
  registers nothing; the skill then registers it as the `confidant` QMD
  collection. Since #37 the CLI owns the corpus build — content, the §12
  cleared set, decryption through the read path, and the gitignore/`0700`/
  `0600` guardrails — so `no-ai` is excluded *by construction* (#38's
  index-time exclusion, now enforced inside the CLI). The skill keeps only
  the encrypted-disk device-policy check and the QMD registration. Treat the
  corpus as if it still contained everything: exclusion goes stale between
  reindexes, so the corpus stays sensitive, gitignored, and on trusted
  devices (§4 threat model).
- **Query time** (`bin/qmd-query.py`): run QMD, then verify *every* hit
  through `confidant find` before returning it. A hit is kept only if the
  same file appears in `find`'s matches with full detail, which happens
  exactly when the content is cleared under §12. Anything unverifiable is
  dropped — fail closed.

## Guardrails on where the plaintext lives (Silas's PR review, 2026-10-08)

The corpus is a plaintext mirror of cleared vault content, so where it (and
QMD's own index) may live is enforced in code, not just documented.

Since #37 these are split between the CLI (which writes the corpus) and the
skill (device policy):

1. **The corpus is git-ignored — enforced by `confidant reindex`.**
   `reindex` probes `git -C <vault> check-ignore -q .confidant/.probe` and
   refuses with a fix message (`echo '.confidant/' >> .gitignore`) if
   `.confidant/` isn't ignored. A user's vault is its own git repo and may
   not ignore `.confidant/` — one `git add -A` must never commit the corpus
   or the plaintext index. (git absent or the vault not being a repo is a
   note, not a refusal: there is nothing to commit with.)
2. **The disk is encrypted — enforced by the skill** (architecture §9b
   item 4; device policy, not a per-command check). Auto-detected:
   `fdesetup isactive` on macOS, or a `crypt`-type ancestor of the vault's
   backing device in `lsblk` on Linux. If detection is impossible, the
   build refuses unless the operator passes `--i-confirm-encrypted-disk`
   (having verified it themselves). The script prints which path it took.
   Note: calling `confidant reindex` directly bypasses this device-policy
   gate — see #37's review flag; #37 chose to leave the assertion in the
   skill.
3. **Permissions — enforced by `confidant reindex`.** Corpus directories
   are `0700` and files `0600`, applied recursively after the rebuild.
4. **QMD's own store stays with the vault, out of backups — enforced by
   the skill.** The index DB and collection registry move under
   `<vault>/.confidant/qmd/` via the `INDEX_PATH` and `QMD_CONFIG_DIR` env
   vars (both documented qmd overrides); embedding models stay in the
   default cache (no PII, large). Both directories are created `0700`; on
   macOS both get `tmutil addexclusion` (best-effort, warns on failure). A
   `confidant` collection left in qmd's default store by older versions is
   removed on first run (migration), so no plaintext index lingers in
   `~/.cache`.

`qmd-query` sets the same env vars, so queries always hit the vault-local
store.

## The allowlist decision (issue #8's core requirement, #38's follow-up)

**Chosen: filter at query time, with the CLI as the single source of
truth — plus index-time exclusion fed by the CLI (#38).** The skill never
reimplements §12.

Considered and rejected at the time: *index only cleared content.*
Computing the cleared set at index time would duplicate the §12
fixed-point logic (or lean on fragile tricks like `find "e"`), and any
divergence between the two implementations is a leak.

What changed (#38): the CLI exposes the cleared set itself
(`confidant allowlist` → cleared record files + cleared ledger lines, no
content), so index-time exclusion needs no duplicated logic — the §12
implementation still lives in exactly one place (the Rust CLI). This is
defense in depth only: the query-time filter remains the authority, and
exclusion goes stale the same way the index does (a vault change between
reindexes can leave newly-uncleared content in the corpus — the live check
still drops it). A query-path bug now degrades to missing results rather
than risking a leak.

What changed (#37): the corpus build moved *into* the CLI as `confidant
reindex`, which copies only the §12 cleared set and decrypts cleared
envelopes through the read path. `no-ai` records are now excluded **by
construction**: the CLI's `for_agent` decrypt path never decrypts a
`no-ai` envelope, so their content never enters the corpus, rather than
being copied and dropped later. `bin/qmd-index.py` shrank to a thin
wrapper: run `confidant reindex`, assert exit 0, then do QMD collection
add/embed. The old "CLI unavailable → build the full corpus with a loud
warning" fallback is gone: `reindex` is now required, and it refuses
rather than building a corpus that silently omits records.

One deliberate carry-over: the `.cfd` → `.cfd.md` ledger mirror lives in
`reindex` (QMD collections match `**/*.md` only), which couples the CLI to
a QMD quirk — flagged in #37's review; #37 chose to leave it in the CLI.

With query-time filtering (unchanged):
- No duplicated logic to drift. The §12 implementation lives in exactly
  one place (the Rust CLI).
- Index staleness can only *miss* results, never leak: a hit for content
  that has since become uncleared is dropped by the live check.
- `no-ai` is honored by construction: `no-ai` records are uncleared, so
  their hits never verify — and the corpus never contains their content.

The cost is one `find` invocation per distinct hit file (~100–160 ms each
on a 400-record vault) — acceptable for an interactive search skill, and
the script dedupes files before verifying. Indexing costs one `reindex`
run per rebuild (it decrypts and hashes the cleared set internally).

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
  invisible. `confidant reindex` mirrors each `ledger/*.cfd` as a sibling
  `.cfd.md` in the corpus (the CLI owns the mirror; see #37's review flag);
  `qmd-query` maps those hits back to the real `.cfd` path before
  verification.

## Encrypted records (post-M2 contract)

`confidant reindex` decrypts cleared post-M2 `enc:` envelopes through the
CLI's read path (`for_agent`, so `no-ai` envelopes are never decrypted).
Unlike `find` — which skips an unreadable envelope and counts it (⚠2) — a
corpus cannot afford to silently omit records: search would look complete
while missing most of the vault. So `reindex` **refuses** (writes nothing)
when any encrypted record could not be decrypted (no device key / key
absent) or was refused as tampered, printing the counts
(`skipped_encrypted` / `refused_envelopes`) and pointing at `confidant
init` / `confidant recover`. The skill's `qmd-index` surfaces that refusal
and exits.

## What stays in the CLI

- The §12 allowlist itself (unchanged), plus `confidant allowlist`, which
  exposes the cleared set (cleared record files + cleared ledger lines, no
  content) for index-time exclusion.
- `confidant reindex` (ADR-6): the corpus build — content, clearance,
  decryption, the gitignore refusal, and `0700`/`0600` permissions. The
  skill registers/embeds on top of the corpus it produces.
- Plain `find` as the fallback: when QMD or the index is missing,
  `qmd-query` delegates to `confidant find --json` and says so on stderr.

## Non-goals

- No QMD dependency in the CLI: `reindex` only writes the corpus
  (issue #37); the `qmd` binary stays behind this skill. No index in git,
  no syncing the index anywhere, no plaintext leaving the trusted device.
- No encrypted-disk check in `reindex` (the skill keeps it as device
  policy); calling `confidant reindex` directly bypasses that gate — a
  flagged, deliberate carry-over from #37's review.
- No relevance tuning exposed: `qmd search` (BM25) is the default mode
  because it needs no model downloads; `--mode hybrid|vector` covers the
  reranked and semantic-only cases once `qmd embed` has run (hybrid/vector
  are refused with a clear error until vectors exist, rather than hanging
  on a multi-GB first-run model download).
