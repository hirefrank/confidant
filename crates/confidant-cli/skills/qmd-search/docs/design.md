# QMD search: design notes

How the `qmd-search` skill integrates [QMD](https://github.com/tobi/qmd)
into Confidant, and the decisions behind it. Binding constraints: ADR-6
(indexes are throwaway, gitignored, trusted devices only), ADR-8 (QMD is
not a Rust dependency; integration via skill/script), architecture §9b
item 4 (index never in git, never synced), ADR-4 (the vault is plaintext on
disk), and GitHub issue #8 (QMD must honor the §12 fail-closed allowlist,
`no-ai` included).

## Architecture

```
vault/                                  trusted device, full-disk encrypted
├── people/...  orgs/...  ledger/...    plaintext records (ADR-4)
└── .confidant/
    ├── qmd-corpus/                     copy of the cleared set, gitignored
    │                                   (staged by bin/qmd-index.py)
    └── qmd/                            qmd's own store: index.sqlite + config/
                                        (INDEX_PATH/QMD_CONFIG_DIR env; was ~/.cache/qmd)

agent ── bin/qmd-query ──┬── qmd query --json ──▶ ranked hits
                        └── confidant allowlist ▶ cleared set (one call per query)

bin/qmd-index ── confidant allowlist --json ──▶ corpus (+ gitignore/perm guardrails)
              └── qmd collection add/embed ──▶ QMD registration
```

Two processes, two responsibilities:

- **Index time** (`bin/qmd-index.py`): one `confidant allowlist --json` call
  gives the §12 cleared set, and the script copies exactly that into
  `.confidant/qmd-corpus/` — cleared record files whole, cleared ledger lines
  only, each ledger file mirrored as `<rel>.md` (QMD collections match
  `**/*.md`). It then registers the corpus as the `confidant` QMD
  collection. There is no CLI-side index command: staging is a copy, because
  the vault is plaintext on disk, and clearance comes from the CLI so
  `no-ai` is excluded *by construction*.
  Treat the corpus as sensitive anyway: exclusion goes stale between
  rebuilds, so it stays gitignored and on trusted devices (§4 threat model).
- **Query time** (`bin/qmd-query.py`): run QMD, then verify *every* hit
  against the live cleared set before returning it, in one
  `confidant allowlist --json` call per query (#538) — record hits by path
  (`cleared_files`), ledger hits by `(file, line)` (`cleared_ledger_lines`).
  Anything unverifiable is dropped — fail closed.

## Guardrails on where the plaintext lives

The corpus is a plaintext copy of cleared vault content, so where it (and
QMD's own index) may live is enforced in code, not just documented. The
skill owns all of these now that it writes the corpus:

1. **The corpus is git-ignored — enforced by `qmd-index.py`.** It probes
   `git -C <vault> check-ignore -q .confidant/.probe` and refuses with a fix
   message (`echo '.confidant/' >> .gitignore`) if `.confidant/` isn't
   ignored. A user's vault is its own git repo and may not ignore
   `.confidant/` — one `git add -A` must never commit the corpus or the
   plaintext index. (git absent or the vault not being a repo is a note, not
   a refusal: there is nothing to commit with.)
2. **Permissions.** Corpus directories are `0700` and files `0600`, applied
   recursively after the rebuild.
3. **QMD's own store stays with the vault, out of backups — enforced by
   the skill.** The index DB and collection registry move under
   `<vault>/.confidant/qmd/` via the `INDEX_PATH` and `QMD_CONFIG_DIR` env
   vars (both documented qmd overrides); embedding models stay in the
   default cache (no PII, large). Both directories are created `0700`; on
   macOS both get `tmutil addexclusion` (best-effort, warns on failure). A
   `confidant` collection left in qmd's default store by older versions is
   removed on first run (migration), so no stale plaintext index lingers in
   `~/.cache`.

The device is expected to be one the operator controls, with full-disk
encryption on — the same perimeter as the vault itself (ADR-4). The skill
does not try to detect the disk: the vault is plaintext either way, so a
detection gate would only give a false sense of protection.

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
rebuilds can leave newly-uncleared content in the corpus — the live check
still drops it). A query-path bug now degrades to missing results rather
than risking a leak.

What changed (#795): the corpus build moved out of the CLI and into this
skill. `bin/qmd-index.py` stages the cleared set itself: `no-ai` records are
never in `allowlist --json`, so their content never enters the corpus. There
is no "build the full corpus with a loud warning" fallback — a failed
`allowlist` call exits rather than building a corpus that silently omits
records.

The `.cfd` → `.cfd.md` ledger mirror lives in `qmd-index.py`: QMD
collections match `**/*.md` only, and the script maps those hits back to the
real `.cfd` path before verification.

With query-time filtering:
- No duplicated logic to drift. The §12 implementation lives in exactly
  one place (the Rust CLI).
- A hit for content that has since become uncleared is dropped by the live
  check (#538: records by path, ledger lines by `(file, line)`).
- `no-ai` is honored by construction: `no-ai` records are uncleared, so
  their hits never verify — and the corpus never contains their content.

The cost is one `allowlist` call per query (plus one per rebuild). #538
replaced the earlier N+1 of one `find` call per distinct hit file: clearance
is a path/line question, so ask it directly. Rebuild cost is one pass over
the cleared set to copy it.

## Verification method (#538)

One `confidant allowlist --json [--packs <same scope>]` call per query
returns the cleared set (`cleared_files`, `cleared_ledger_lines`). Every
merged hit file is then:

- a **record file**: kept iff its vault-relative path is in `cleared_files`.
  This replaced the old text probe (longest ≥ 24-character ASCII run, then
  `confidant find`), which dropped every cleared CJK or short/punctuated
  note: no run, no probe, hit silently dropped. Clearance is a path
  question, so nothing is re-searched.
- a **ledger file** (`ledger/*.cfd`): kept iff the hit's `(file, line)`
  resolves to a line in `cleared_ledger_lines`. The file mixes people and
  the corpus can be stale after a `no-ai` change, so the file alone is not
  enough. `qmd-index` writes only cleared ledger lines into the corpus, in
  order, so the corpus file is a subsequence of the vault file; the script
  aligns the two by exact line text to recover the real vault line number
  (qmd only knows corpus lines). The alignment is built from an inverted
  index (`line text -> ascending vault line numbers`), so one edited or
  removed vault line costs only the lines it actually affects; a corpus line
  with no remaining match resolves to nothing and is dropped (fail closed
  per line). The first record ID on the resolved line supplies `id` (display
  only, as the CLI's `find` does from its parsed line).

Anything else is dropped and counted in `dropped_uncleared`, never
returned. Snippets come from the QMD hit (records) or the aligned corpus
line (ledger). Verification is therefore path/line-based, not text-based:
rerun `qmd-index` (and `qmd embed`) after vault writes so a stale *index*
does not mislabel line numbers — an unaligned hit drops rather than
returning something unverified. A stale index can also return a **stale
snippet of a still-cleared record**: the excerpt comes from the corpus copy,
so a note edited in the vault keeps returning its old text until `qmd-index`
reruns. That is not a §12 leak — the record is still cleared and the corpus
already holds that text — but the text can be out of date.

Two real-qmd contract details the scripts handle:

- qmd `--json` reports hits as `qmd://<collection>/<relpath>` URIs, not
  filesystem paths; `qmd-query` strips the scheme to get the
  vault-relative path (hits that don't resolve inside the corpus are
  ignored). Snippets carry a leading `@@ -a,b @@ (x before, y after)`
  diff header, which is stripped.
- qmd collections match `**/*.md` only, so ledger `.cfd` files would be
  invisible. `qmd-index` mirrors each `ledger/*.cfd` as a sibling
  `.cfd.md` in the corpus; `qmd-query` maps those hits back to the real
  `.cfd` path before verification.

## What stays in the CLI

- The §12 allowlist itself, and `confidant allowlist`, which exposes the
  cleared set (cleared record files + cleared ledger lines, no content) for
  index-time exclusion.
- Plain `find` as the fallback: when QMD or the index is missing,
  `qmd-query` delegates to `confidant find --json` and says so on stderr.

## Non-goals

- No QMD dependency in the CLI: the `qmd` binary stays behind this skill. No
  index in git, no syncing the index anywhere, no vault content leaving the
  trusted device.
- No relevance tuning exposed: `qmd search` (BM25) is the default mode
  because it needs no model downloads; `--mode hybrid|vector` covers the
  reranked and semantic-only cases once `qmd embed` has run (hybrid/vector
  are refused with a clear error until vectors exist, rather than hanging
  on a multi-GB first-run model download).
