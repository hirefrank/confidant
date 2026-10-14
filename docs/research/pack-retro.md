# Pack retrospective: what coaching and personal actually share (issue #185)

*Author: research pass for #185. Status: input to review. Part of #173; follows #184. Evidence read at `main` = `4430854`.*

**Summary.** The `Pack` trait held. Both compiled packs implement the same
surface, and no pack needed a structural escape hatch: per-pack scoping
(#178) and edge kinds (#179) are generic over the registry, and the pack
claims that `check` reads (verbs, fields, metrics, edge kinds, finding
codes) are pure data. Two things bent: **personal leaked three free
functions** that `check.rs` and `context.rs` call directly instead of going
through the trait, and **pack names are hardcoded in `context.rs`** for the
legacy `coaching` field and for personal PII stripping. The two folds share
a **skeleton** (merge-canonical per-person map + per-entry reducer +
findings at `as_of`) but not a **reducer** (balance/package math vs
cadence/date math). Recommendation: **make the declarative parts data
files**, but only the claims and grammars — keep the folds compiled — and
fix the leaks first.

---

## 1. What two packs actually share

The interface is `crates/confidant-core/src/packs/mod.rs:70` (`trait Pack`),
registered in a static list at `packs/mod.rs:145`:

```rust
pub static ALL_PACKS: &[&'static dyn Pack] =
    &[&coaching::CoachingPack, &personal::PersonalPack];
```

`check` resolves the vault's `packs = [...]` list against that list
(`check.rs:341`), refuses conflicting claims with a pure function over the
registry (`find_conflict`, `packs/mod.rs:184`), warns on data owned by a
disabled pack (`orphan_owners`, `packs/mod.rs:238`), then folds each enabled
pack and calls its post-fold rules (`check.rs:403-411`).

Method by method, both packs implement every trait method. Neither method
went unused across the pair:

| Trait method | `CoachingPack` | `PersonalPack` |
|---|---|---|
| `verbs()` | `["open","session"]` (`coaching.rs:140`) | `["touch"]` (`personal.rs:380`) |
| `record_types()` | `&[]` (`coaching.rs:144`) | `&[]` (`personal.rs:384`) |
| `fields()` | `&[]` (`coaching.rs:148`) | 4 fields (`personal.rs:388`) |
| `balance_metrics()` | 2 metrics (`coaching.rs:152`) | `&[]` (`personal.rs:392`) |
| `edge_kinds()` | default `&[]` (`packs/mod.rs:88`) | 6 kinds (`personal.rs:410`) |
| `finding_codes()` | 12 codes (`coaching.rs:156`) | 6 codes (`personal.rs:396`) |
| `verb_id_type()` | `open`/`session` → `Person` (`coaching.rs:173`) | `touch` → `Person` (`personal.rs:414`) |
| `fold()` | real (`coaching.rs:180`) | real (`personal.rs:421`) |
| `findings()` | gap + note rules (`coaching.rs:190`) | cadence + date rules (`personal.rs:431`) |
| `check_balance()` | real (`coaching.rs:205`) | overridden no-op (`personal.rs:446`) |
| `context_view()` | `CoachingView` (`coaching.rs:219`) | `PersonalView` (`personal.rs:455`) |

So the trait is not too small (no pack wanted a method that does not exist)
and not too big in the sense of unused *methods*: `check_balance` is a no-op
in personal, but the method still has to exist because coaching uses it.
The mismatched parts are *claims*, not methods: `record_types` is empty for
both, `balance_metrics` is empty for personal, `edge_kinds` is empty for
coaching. Those three are the ones that look like the trait only holds
because the packs happen to differ in disjoint ways.

The registry-side machinery is genuinely shared and pack-agnostic:
`resolve_enabled` (`packs/mod.rs:150`), `find_conflict` (`packs/mod.rs:184`),
`orphan_owners` (`packs/mod.rs:238`), `known_verbs` (`check.rs:484`),
`check_balances` dispatch by `balance_metrics().contains(&metric)`
(`check.rs:1000-1004`), and the edge-kind lookup
(`check.rs:1249-1272`). None of it names a pack. Adding a third pack is
"implement `Pack`, add to `ALL_PACKS`".

## 2. Where the trait bent

Three escape hatches, all in the personal pack or in core code that knows
personal's shape:

1. **Personal exposes free functions the core calls directly.**
   `personal.rs:57` (`extract_touch_kind`), `:74` (`is_personal_touch_shape`)
   and `:100` (`validate_touch_args_enabled`) are public functions outside
   the trait. `check.rs` calls two of them inside the `touch` special case
   (`check.rs:573`, `:593`) and `context.rs:223` calls the third. In other
   words, `touch` validation is not "the `touch` pack validates its verb";
   it is `check` reaching into `packs::personal`.

2. **`check.rs` hardcodes the `touch` verb.** `known_verbs` seeds core with
   `["alias","merge","stage","balance","touch"]` (`check.rs:487`), the
   touch-shape rule is a 50-line `if e.verb == "touch"` block
   (`check.rs:568-620`), and the ID-type rule special-cases both `stage` and
   `touch` (`check.rs:623-625`) before falling back to `verb_id_type`. The
   same `touch` is duplicated as core in `scope.rs:169`
   (`CORE_VERBS = ["alias","merge","stage","touch"]`). This is a deliberate
   design choice (#179: a mirrored touchpoint is core), but it means the
   personal pack's verb is half in core and half in personal.

3. **`context.rs` hardcodes pack names.** It strips private personal fields
   by comparing `pack.name() == crate::config::PERSONAL_PACK`
   (`context.rs:138-144`), and builds the legacy top-level `coaching` field
   by looking up `crate::config::COACHING_PACK` and deserializing into
   `CoachingView` (`context.rs:17`, `:151-153`). The comment there is honest
   ("Legacy contract field"), and `context_view` itself is generic, but the
   two names are pack-specific knowledge in a core module.

One more cross-pack coupling worth recording: **personal's fold reads the
coaching verb.** In `personal.rs:633`, `"session"` pushes a touchpoint, so a
coaching client who is also a friend is not a false cadence-overdue warning
(#227 Q2). Personal therefore knows coaching's verb by name, which is a
pack-to-pack dependency the trait does not express. It is correct behaviour,
but it is not "packs fold independently".

Minor leak: the unknown-edge-kind fix message hardcodes only core kinds
("Add kind: married, introduced, or colleague", `check.rs:1246`) even
though the closed list includes pack kinds.

## 3. The shared fold shape

Both packs independently grew the same skeleton:

1. **State** holds a merge map, a per-person map, and a lazily built
   merge-group cache, keyed by `as_of`:
   - `CoachingState { parent, people, packages, members_by_root }`
     (`coaching.rs:85-91`).
   - `PersonalState { parent, people, members_by_root }`
     (`personal.rs:258-263`, where `people: HashMap<RecordId, PersonPersonal>`).
2. **Canonicalization** is `canonical_on(id, &parent, on)` plus
   `ensure_members(on)` / `group_people(...)`, so an event recorded against a
   merged-away ID counts toward the canonical person. Both packs implement
   the same three helpers (`coaching.rs:348-376`, `personal.rs:272-310`) —
   near-duplicated code.
3. **Reducer** walks dated input in a deterministic order into per-person
   vectors: coaching sorts events by `(date, verb != open, line, file)` so
   opens precede sessions on a date (`coaching.rs:435-447`); personal sorts
   records by id (`personal.rs:546-547`) and pushes touches in ledger order
   (`personal.rs:622-643`).
4. **Findings at `as_of`** are emitted both at fold time (malformed entries,
   negative balances for coaching; field grammar errors for personal) and
   post-fold through `findings()` (gap rules, cadence, upcoming dates), all
   evaluated at the same `as_of` (`check.rs:385`, `:405-409`).

Sketch of the shape:

```
state      = { merges, people: Map<canonical_id, PersonState>, group_cache }

fold(vault, as_of):
    for entry in order:                 # deterministic
        if entry belongs to me:
            people[canonical(entry)].events.push(reduce(entry))
    emit_fold_time_findings()

findings(vault, as_of):
    for canonical_id in sorted(people):
        emit(reducer_rules(people[id], as_of))
```

Where the two diverge:

- **Reducer semantics.** Coaching's event carries meaning (`OpenEvent { n }`,
  `SessionEvent { minutes, pps, consumes }`, `coaching.rs:20-32`); the rules
  are package arithmetic (consuming tags, overflow caps) plus dated
  aggregations (`remaining_on`, `minutes_on`, `last_session_on`,
  `coaching.rs:41-80`). Personal's event is a bare date
  (`TouchEvent { date }`, `personal.rs:233`); the rules are date arithmetic
  (cadence window, next recurring occurrence). The shared part is the map,
  not the math.
- **Extra state.** Coaching also holds `packages: HashSet<RecordId>`
  (`coaching.rs:89`) and asserts balances (`check_balance`,
  `coaching.rs:257`). Personal has no metrics and no package state.
- **Record fields.** Personal folds record front matter and validates it
  (`birthday`, `cadence`, `relationship_to_me`, `dates`, `personal.rs:548-600`)
  with `E_FRONTMATTER` at `field_lines`. Coaching owns no fields, so its
  fold is ledger-only. The per-field validation loop is personal-specific.
- **Merge-group seeding.** Coaching's `ensure_members` seeds only from
  `self.people.keys()` (`coaching.rs:357`); personal's additionally seeds
  from both ends of the merge map (`personal.rs:282-285`), so a person with
  no events still groups correctly. Same intent, subtly different code, and
  a latent source of drift.
- **Context view.** Both build a typed struct and `serde_json::to_value` it,
  but the shapes share nothing (`CoachingView` vs `PersonalView`).

A third pack could almost certainly reuse the skeleton (merge map + group
cache + findings-at-`as_of`) while bringing its own reducer. That argues for
factoring the skeleton, not the trait.

## 4. Data vs logic

"Data" here means it could be read from a manifest with no behaviour change;
"logic" means it needs a program.

| Item | Coaching | Personal | Today | Could be data? |
|---|---|---|---|---|
| Pack name | `coaching@0.1` | `personal@0.1` | const (`config.rs:13-14`) | Yes |
| Verbs | `open`, `session` | `touch` | `verbs()` slices | Yes |
| Record types | ∅ | ∅ | `record_types()` | Yes |
| Front-matter fields | ∅ | birthday, cadence, relationship_to_me, dates | `fields()` slices | Yes (name + grammar) |
| Balance metrics | sessions_remaining, icf_hours | ∅ | `balance_metrics()` slices | Yes |
| Edge kinds + symmetry | ∅ | 6 kinds | `PERSONAL_EDGE_KINDS` (`personal.rs:24`) | Yes |
| Finding codes | 12 | 6 | `finding_codes()` slices | Yes (already checked against SKILL.md, `embedded.rs:147`) |
| Verb → ID type | person | person | `verb_id_type()` | Yes (a map) |
| `[checks]` keys + defaults | 6 keys | 3 keys | hardcoded allowlists (`config.rs:20-32`) | Yes |
| Skill text | `SKILL.md` | `SKILL.md` | file, embedded | Already data |
| Finding messages | static + interpolation | static + interpolation | string literals | Mostly (templates) |
| Field grammars (`birthday`, `cadence`, `dates`, `touch` kinds) | — | parsers (`personal.rs:112-230`) | compiled parsing | Yes (small grammar/enum DSL) |
| Balance fold (open/session, consuming tags, overflow caps) | yes | — | `coaching.rs:41-80`, `:422-693` | No |
| ICF minutes aggregation | yes | — | `coaching.rs:56-62` | No |
| Gap clock = max(last session, latest open), pps lookback | yes | — | `coaching.rs:871-934` | No |
| Cadence window math | — | yes | `personal.rs:743-797` | No |
| Recurring-date next occurrence (leap year, year-less) | — | yes | `personal.rs:160-180` | No |
| Merge-aware grouping + `as_of` | shared | shared | duplicated helpers | No (factor, don't declarative) |
| Context view shapes | yes | yes | typed structs | No |

The split is clean: **claims, grammars, config keys and text are
declarative today in every sense except that they live in Rust as
`&'static` slices and string literals.** The **reducers and date math are
the compiled part**, and they are exactly the part that differs between the
two packs. That is the evidence #173 asked for.

## 5. Scoping (#178) and edges (#179)

Both are generic. `scope.rs` reads ownership only from the registry:

- `owner_of_field` checks `pack.fields()` (`scope.rs:151-162`),
- `owner_of_verb` checks `pack.verbs()` then `CORE_VERBS` (`scope.rs:173-184`),
- `owner_of_metric` checks `pack.balance_metrics()` (`scope.rs:188-195`),
- `owner_of_edge_kind` checks `pack.edge_kinds()` then `CORE_EDGE_KINDS`
  (`scope.rs:200-211`),
- `record_owners` dispatches on `RecordKind` and uses the field/edge-kind
  helpers (`scope.rs:274-313`).

No function in `scope.rs` names a pack. `PackScope::allows`
(`scope.rs:71-79`) is generic; unattributed items fail closed. The only core
lists are `CORE_VERBS` (`scope.rs:169`) and `CORE_EDGE_KINDS`
(`packs/mod.rs:39`), which is exactly the "owned by core, or by a pack"
rule. `owner_of_verb` checks pack claims first, so the `touch`/`CORE_VERBS`
overlap resolves correctly whether personal is enabled or not.

Edges are the same story. The `edge` record type, its `a`/`b`/`kind`
fields, self-edge and duplicate detection live in core `check_edges`
(`check.rs:1124`), driven by the `symmetric` flag looked up in
`pack.edge_kinds()` (`check.rs:1249-1272`). Packs contribute only names and
symmetry. Duplicate detection correctly keys symmetric pairs unordered and
directed pairs as-written (`check.rs:1295-1305`). The only pack-specific
artefact is the stale core-only fix message noted in section 2.

Conclusion: **#178 and #179 needed no per-pack code.** They are the
strongest evidence that the registry abstraction is right.

## 6. Recommendation

**Make the declarative parts data files.** Concretely: keep the trait and the
compiled folds, and move the *claims* — name, verbs, record types, fields +
grammars, balance metrics, edge kinds, finding codes, verb→ID-type, `[checks]`
keys and defaults, skill text, and (templated) finding messages — into a
pack manifest that `Pack` implementations load. This is the narrow,
auditable half of #193, and it is exactly the half both packs already treat
as data.

Reasoning:

- **The registry abstractions are proven.** Two packs, disjoint claims, no
  per-pack code in `scope.rs` or the edge engine. The rule of two is met for
  *claims*.
- **The calculation abstraction is not proven.** The folds share a skeleton
  but no reducer; shipping them as a declarative rule DSL would mean
  designing a language for package arithmetic, cadence windows and leap-year
  date math before a third pack shows whether that is the right shape. #173's
  "Rust until a second pack proves a shared abstraction" is half-answered:
  the second pack proved the *claims* half, not the *math* half.
- **A sandboxed calculation format (WASM) is premature.** Nothing here needs
  untrusted third-party code yet; the trust problem in #193 is solved by
  content-hash pinning and review-on-install first.

Do this in stages, and do not start the manifest work until the leaks are
fixed and the skeleton is factored, so the manifest is designed against clean
code:

1. **Fix the leaks** (small, no format change): route `touch` validation
   through the pack instead of `check.rs` calling
   `packs::personal::{validate_touch_args_enabled, is_personal_touch_shape}`
   (`check.rs:573,593`); give `context_view` a way to declare which fields
   are PII so `context.rs` stops special-casing `PERSONAL_PACK`
   (`context.rs:138-144`); record the `coaching` legacy field as a
   compatibility alias rather than a hardcoded name (`context.rs:151-153`).
2. **Factor the fold skeleton** into a shared internal helper (merge map +
   `canonical_on` + `ensure_members`/`group_people` + findings-at-`as_of`),
   reconciling coaching's and personal's divergent `ensure_members`
   (`coaching.rs:352`, `personal.rs:276`). Also decide whether the
   `session`-counts-as-touch dependency (`personal.rs:633`) should be
   expressed in the registry instead of by verb name.
3. **Then** extract the declarative manifest, keeping `fold`/`findings` in
   Rust behind the same trait.

### Follow-up issues to file

- **`pack-review` for #193** (`[pack-review] Declarative pack manifest:
  which claims move to data?`): propose the manifest fields from the table in
  section 4, with the finding-codes ↔ SKILL.md drift test
  (`embedded.rs:147`) as the model for keeping the text honest. This is the
  review AGENTS.md rule 7 requires before any format/privacy change.
- **Issue: route `touch` through the pack contract** so `check.rs` and
  `context.rs` stop calling `packs::personal` free functions.
- **Issue: make `context` pack-agnostic** for PII stripping and the legacy
  `coaching` field.
- **Issue: factor the shared fold skeleton** (canonical person map +
  group cache + findings-at-`as_of`) out of the two packs.
- **Issue: generalise the unknown-edge-kind fix message** so it does not
  list only core kinds.

### Open question from #185, answered

*Should a third, structurally different pack (e.g. recruiting) be sketched on
paper as a check?* Yes, and the sketch should test the *reducer*, not the
claims. A recruiting pack (candidates, stages, offers, response-time SLAs)
would add package-like arithmetic and date windows while owning new fields
and verbs; if its reducer fits the same skeleton, the skeleton is the
abstraction to formalise, and the declarative manifest is clearly right. If
its reducer needs a genuinely new kind of calculation, that is the trigger to
consider a sandboxed format — and not before.
