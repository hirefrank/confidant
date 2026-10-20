# Coaching pack dogfood: rebuilding `coaching@0.1` with the pack-author path (#675)

*Phase 1 of #675. Evidence at `main` = `75e06d1` (`confidant 0.6.1`),
2026-10-20. Scratch work lived outside the repo, the vault, and this
docs tree; no vault content or key material is reproduced here.*

## Summary

An agent rebuilt `coaching@0.1` from `spec/pack-manifest.md` §13, the
`pack-author` skill and the pack's human contract, using only
`confidant pack init` and hand-authored files. The rebuilt pack installs
with `pack add --from-dir`, loads, verifies, and produces **byte-identical
`check --json` findings and `context --json` bundles** to the shipped pack
on both the pre-#678 demo vault and a fault-injected copy that exercises
all 14 coaching finding codes. A first pass differed in one code name, one
rule id and 11 message templates; a second `pack update --from-dir`
iteration aligned them.

The rebuild is published as a public gist (neutral fake content only):
<https://gist.github.com/hirefrank/a6c140d6e04eb06a21a8a0f5939a8a66>

`packs/coaching/` stays out of the repository.

## Method

Authoring inputs, in the order the skill prescribes:

- `spec/pack-manifest.md` §13 (v2 schema, the six rule kinds, context
  view, capability limits);
- `crates/confidant-cli/skills/pack-author/SKILL.md`;
- the old pack's **human contract** `packs/coaching/0.1.md`, read from
  git history as the requirement document. This is documentation of the
  claims, not the machine-readable manifest;
- `examples/demo-vault` before #678 (the data the pack must interpret);
- `testdata/packs/example-pack/manifest.toml` as a worked example of a
  v2 manifest that uses every rule kind.

Not consulted until the rebuild was complete: the old
`packs/coaching/manifest.toml` and `SKILL.md`. The comparison in
"Fidelity" is therefore a real check, not a transcription.

Steps:

```sh
confidant pack init /tmp/…/packs-src/coaching --name coaching --version 0.1
# author manifest.toml, SKILL.md, 0.1.md, README.md
confidant pack add --from-dir /tmp/…/packs-src/coaching          # review
confidant pack add --from-dir /tmp/…/packs-src/coaching --yes    # install
confidant check --json --no-input
confidant context --json --no-input <person>
confidant pack verify coaching
confidant pack update coaching --from-dir /tmp/…/packs-src/coaching --yes
```

Two scratch vaults were built from `4f39071^`: a copy with the shipped
pack installed from `packs/coaching/`, and a copy with the rebuilt pack
installed from the scaffold directory. Both retained the demo vault's
`confidant.toml` (including its six `coaching.*` operator keys) and its
fake records and ledger.

## Timings (machine-measured wall clock)

The required reading happened before the clock below; §13 is long, but
tool time to read it was about a minute. The measured cost is in
ambiguity, not volume.

| Phase | Measured |
|---|---|
| `pack init` scaffold (4 files, validated) | < 1 s |
| `manifest.toml` first draft (14 codes, 6 check keys, 4 rules, 44 message keys) | 34 s after scaffold |
| `SKILL.md`, `0.1.md`, `README.md` drafts | 27 s |
| Friction log and comparison setup | 30 s |
| Scratch vault setup + install (including one failed attempt, below) | 29 s |
| First `check`/`context` comparison | 13 s |
| Fault-injected comparison (22 fault lines + 3 fake people) | 38 s |
| Iteration 1: align code name/texts, `pack update`, verify | 18 s |
| Ledger/session/note writes on a throwaway copy, compare | 17 s |
| Publish gist (4 files) | 8 s |
| **Total, scaffold to gist** | **3 min 34 s** |

An operator who already knows the pack shape would be faster; an agent
without the contract document would be slower, because the manifest does
not name the business codes.

## Fidelity, claim by claim

Compared with `packs/coaching/manifest.toml` at `4f39071^`.

| Claim | Shipped | Rebuilt | Result |
|---|---|---|---|
| `[pack]` | `coaching`, `0.1`, `SKILL.md`, `requires_spec = ["0.1"]` | same | match |
| `[[verbs]]` | `open` (person), `session` (person) | same | match |
| `record_types` | `[]` | `[]` | match |
| `[[fields]]` | none | none | match |
| `[[edge_kinds]]` | none | none | match |
| `balance_metrics` | `sessions_remaining`, `icf_hours` | same | match |
| `finding_codes` | 14 codes, `E_COACHING_*` / `W_COACHING_SESSION_UNTAGGED` | same set (source order differs) | match |
| `[checks]` | `require_duration=error`, `balance_nonnegative=error`, `session_notes=warning`, `paid_session_gap=warning`, `paid_session_gap_days=45`, `pps_lookback_days=180` | same | match |
| `[context]` | `view = "ledger-sessions"`, default `recent_limit` | same | match |
| Rule `note_ref` | `note-ref`, code `E_COACHING_UNKNOWN_RECORD`, `verb=session`, `pair=note`, `variants=session`, invalid/wrong-type codes | same | match |
| Rule `balance` | `ledger-balance`, all nine parameters (`open_verb=open`, `consume_verb=session`, both metrics, `max_open_n=100000`, four code parameters) | same | match |
| Rule `sessions` | `session-checks`, `verb=session`, `billing_tags=["paid","pps","comp"]`, two severity keys, three code parameters | same | match |
| Rule `gap` | `activity-gap`, `activity_verb=session`, `start_verb=open`, both int keys, `balance_metric=sessions_remaining` | same | match |
| Messages | 20 variants across 14 codes | same text and placeholders after iteration 1 | match |
| `SKILL.md` | documents all 14 codes | documents all 14 codes; prose newly written | match in coverage, not byte-identical |
| `0.1.md` contract | prose contract | newly written from the same contract | match in meaning, not byte-identical |
| File set | `manifest.toml`, `SKILL.md`, `0.1.md` | those three plus `README.md` | intentional: §13.5 allows optional `README*`; `pack init` writes one |

### First pass vs shipped: what actually differed

The first build was not a match in three places. The regex-free check
diff exposed the code name and four message texts; diffing the two
manifests after the rebuild exposed the rest.

| Difference | First pass | Shipped | Resolution |
|---|---|---|---|
| Balance-parse code | `E_COACHING_BALANCE_PARSE` | `E_COACHING_PARSE` | renamed |
| Rule id | `entries` | `sessions` | renamed (cosmetic; ids are not behaviour) |
| Balance mismatch fix | "missing 'open' line or duplicated 'session' line" | "missing 'open' entry or duplicated 'session' entry" | aligned |
| Negative-balance fix | "Add an open line …" | "Add an open/renewal …" | aligned |
| Billing-tags fix | "Keep exactly one tag …" | "Keep exactly one billing tag …" | aligned |
| Untagged fix | "Tag the session paid, pps, or comp" | "Tag the session paid, pps (pay-per-session), or comp (complimentary)" | aligned |
| Gap `none`/`remaining`/`no_remaining` | "client {id} …" | "paid client {id} …" | aligned (3 templates) |
| Note invalid/wrong-type/missing/wrong-owner | "note …" | "session note …" | aligned (4 templates) |

That is 11 message templates, one code name and one rule id over a
44-key, 14-code manifest.

### Intentional differences (final)

- `README.md` ships in the pack directory. §13.5 permits `README*`;
  `pack init` writes one. The vendored tree therefore has five files where
  the shipped pack had four.
- Manifest source comments and file ordering differ; the parsed TOML is
  semantically identical (`tomllib` deep-compare, order-insensitive).
- `SKILL.md` and `0.1.md` are freshly written prose with the same claims
  and the same code coverage, not copies of the old text.
- Distribution is a public gist, not `packs/coaching/` in this repo.

## Behaviour evidence

### Clean demo vault

`check --json --no-input` (normalized `vault` path):

```
{"ok":true,"summary":{"records":19,"ledger_entries":16,"errors":0,"warnings":2},
 "findings":[W_CADENCE_OVERDUE, W_DATE_UPCOMING]}
```

Identical for both packs; the two warnings are the demo vault's
intentional personal-pack teaching findings.

`context --json` for the three people with ledger history
(`p-…000000000000`, `p-…001248000002`, `p-…000H24000001`) is identical,
including `packs["coaching@0.1"].sessions_remaining`,
`icf_hours`, `recent_sessions` and the legacy top-level `coaching` alias.

### Fault-injected vault

22 appended ledger lines and three fake people exercise every coaching
rule and every message variant. Both packs report:

```
records: 22, ledger_entries: 40, errors: 21, warnings: 7
codes: E_COACHING_BALANCE_MISMATCH, E_COACHING_INVALID_ID,
  E_COACHING_MISSING_DURATION, E_COACHING_NEGATIVE_BALANCE,
  E_COACHING_NOTE_INVALID_ID, E_COACHING_NOTE_WRONG_TYPE,
  E_COACHING_OPEN_MALFORMED, E_COACHING_PAID_SESSION_GAP,
  E_COACHING_PARSE, E_COACHING_SESSION_TAGS,
  E_COACHING_SESSION_WITHOUT_NOTES, E_COACHING_UNKNOWN_RECORD,
  E_COACHING_WRONG_ID_TYPE, W_COACHING_SESSION_UNTAGGED
  (+ core E_LEDGER_DATE, E_PARSE, W_DATE_UPCOMING)
```

The full findings array is identical after iteration 1 (same order, same
messages, same fixes). `context` for five people, including the
fault-injection people, is identical.

Not exercised: `minutes_overflow` and `open_malformed.total_overflow`
(they need a `u32`/`i64` overflow) and the pack's `missing_number`
variant, which core pre-empts with `E_PARSE` for a short `balance` line.
The shipped pack has the same coverage gap.

### Same workflows, writes included

On throwaway copies of the clean vault:

- `log session p-… 45m paid --date 2026-10-09 --note "…"` writes a note
  plus ledger line and commits once. Both packs produce the same file
  shape, the same commit subject (`session p-… 45m paid`), and a clean
  `check` (0 errors, the same 2 warnings).
- `note add --person p-…102 --date 2026-10-09` writes and commits; clean
  with both packs.
- `pack verify` reports `coaching 0.1 ok (dir) dir`.
- A second `pack update --from-dir --yes` with unchanged content prints
  `no changes; nothing committed` and exits 0.

## Friction and blockers

1. **Installing into a vault that already has the pack's keys or data is
   blocked by the pre-check.** A vault with `coaching.*` keys in
   `confidant.toml` but no `packs` listing fails `check` with
   `E_CONFIG unknown [checks] key`; ledger lines for the pack's verbs are
   `E_UNKNOWN_VERB` / `E_UNKNOWN_METRIC`. `pack add --yes` runs that
   pre-check before applying, so the install is refused and rolled back.
   This is the exact migration shape in #675. Workaround used: re-list
   the pack in `packs` first (the #612 repairing path then handles the
   missing pin), or install before adding the keys. Documented in the
   skill; not changed in code because the write-path pre-check is a
   deliberate gate and relaxing it needs review.
2. **`pack remove` of a pack the vault uses is refused for the same
   reason.** Removing the shipped pack from the clean vault exits 1 with
   the same `E_CONFIG`/`E_UNKNOWN_VERB`/`E_UNKNOWN_METRIC` findings and
   rolls back; there is no CLI path to uninstall a pack whose data must
   remain (the intended `W_PACK_ORPHAN` downgrade only covers *registered*
   packs). Phase 2 removed the asset by editing the repo, not by
   `pack remove`. This deserves its own issue; changing orphan semantics
   is a spec/privacy decision.
3. **`note-ref`'s `variants` naming is ambiguous.** The table says
   "`default`/`session_note`" and the paragraph says `session_note` is
   for a session verb. It is only unambiguous after reading the loader.
   The agent had to choose `variants = "session"` plus
   `session_note`/`session_note_fix`. Clarified in the skill; the spec
   text was left alone.
4. **The contract named no balance-parse code.** `ledger-balance` requires
   `parse_code`, but the coaching contract only named the mismatch,
   negative, malformed-open, and id codes. The first pass invented
   `E_COACHING_BALANCE_PARSE`; the comparison against the shipped manifest
   found `E_COACHING_PARSE`. A pack author without the shipped manifest
   cannot know the intended name — which is expected for a *rebuild*, but
   it means the contract file should list every code it expects.
5. **`pack update --yes` does not print the diff.** The review diff is
   printed only without `--yes`; the skill implied otherwise. Wording
   fixed.
6. **The review report summarizes claims but does not print message
   templates.** The skill tells the agent to show the operator the
   messages; the agent must open `manifest.toml` for them. Wording fixed.
7. **A same-version update is a content replacement.** Useful for local
   iteration, but the skill did not say so. Documented.

## Fixes made to the authoring path

One file changed: `crates/confidant-cli/skills/pack-author/SKILL.md`
(embedded skill text; no core behaviour change).

- §3: point at each rule kind's variant/parameter table, spell out the
  `note-ref` `variants = "session"` naming, and warn that a missing
  variant is a load error.
- §4: say that the review report summarizes claims and that message
  templates must be read from `manifest.toml`.
- §5: install before adding the pack's `[checks]` keys; keep the listing
  when reinstalling a pack the vault already used.
- §6: review with `pack update` (no `--yes`) to see the diff; same-version
  updates replace content, so local iteration needs no bump.

No `pack init` template change was needed: the scaffold validated and
installed as written. The existing round-trip CLI test
(`pack_init_round_trip_review_install_and_update`) already covers
scaffold → review → install → verify → update.

## Reference copy

Public gist, four files, neutral content:

<https://gist.github.com/hirefrank/a6c140d6e04eb06a21a8a0f5939a8a66>

| File | SHA-256 |
|---|---|
| `manifest.toml` | `701c9c02e8c020c5540d85ed915638850cf4514f53728a29e760648341bf2ab1` |
| `SKILL.md` | `22751deb52c46c74dac9a6e548bd838cc16fc16a2d7b57b4ada9421e52b3de59` |
| `0.1.md` | `429f3a9a8b423fbf527256cfb91d224bc266aa3fffc1f8335279a68634ce014a` |
| `README.md` | `07ac4e040863fe5f6386786e7d4499305e426d53c5e527b12a637431933a80a5` |

Vendored tree digest after `pack add`: `sha256:7775ce7a…` (the shipped
pack's was `sha256:b4234c3b…`; the difference is the added `README.md`
and the newly written skill/contract/comments).

## What stays out of the repo

`packs/coaching/` is **not** restored. The generic machinery it used —
`ledger-balance`, `session-checks`, `activity-gap`, `note-ref`, the
`ledger-sessions` context view, the manifest loader, and the `coaching`
legacy context alias — is untouched. An operator who wants the coaching
shape installs the gist (or their own rebuild) with `pack add --from-dir`;
a vault that lists `coaching@0.1` without installing a copy correctly
reports `E_PACK_UNKNOWN`.

## Reproduce

```sh
cargo build -p confidant-cli --locked --all-features
confidant pack init <scratch>/coaching --name coaching --version 0.1
# author the four files (or fetch the gist)
git worktree add --detach <scratch>/old 4f39071^
cp -a <scratch>/old/examples/demo-vault <scratch>/vault
rm -rf <scratch>/vault/packs <scratch>/vault/confidant.lock
# set packs = ["coaching@0.1"] in confidant.toml, git init, commit
confidant pack add --from-dir <scratch>/old/packs/coaching --vault <scratch>/vault --yes
confidant check --json --no-input --vault <scratch>/vault
# repeat with <scratch>/coaching as the source, then diff the normalized JSON
```

## Verdict

The authoring path is sufficient: a spec-following agent rebuilt every
claim from the contract and spec, installed it, ran the workflows, and
found only naming/text drift that a second iteration fixed. The two real
blockers are install/remove lifecycle gaps for a vault that already uses
the pack's data, not gaps in the pack-author path itself. Phase 1 is
complete; #675 can close once the lifecycle gaps are filed as follow-ups.
