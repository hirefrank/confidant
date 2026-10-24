# Stable finding codes (spec 0.1)

Callers of `confidant check --json` must branch on `code`, never on message
text. Codes are stable once published. A new meaning needs a new code.

Severity listed here is the default. Vault `[checks]` keys can promote,
demote, or turn a rule `off` where the table says "configurable".

Codes a pack declares are **pack-owned**: the pack declares and emits them,
and no other pack may claim them (PD13). The core codes below remain stable
and are emitted by core or the built-in personal pack.

Warning findings never block writes, commits, or inbox merges; only
errors do. `doctor` reports warnings as warning status, never error.
`check --fail-on warning` exits non-zero when any warning (or error) is
present, for CI users who want the stricter gate.

| Code | Default severity | Configurable key | When it fires |
|---|---|---|---|
| `E_PARSE` | error | | A ledger line or record file does not match the grammar. |
| `E_UNREADABLE` | error | | A file is not valid UTF-8 or a directory cannot be read. |
| `E_CONFIG` | error | | `confidant.toml` is missing a required field, is not valid TOML, or a `[checks]` key/value is unknown, mistyped, or out of range. |
| `E_SPEC_UNSUPPORTED` | error | | `spec` is not `0.1`. |
| `E_PACK_UNKNOWN` | error | | A listed pack is neither compiled into this CLI nor resolved through `confidant.lock`. The fix hint points at `confidant pack add`. The message may name the failing `name@version` exactly as listed in `confidant.toml`; `file` is `confidant.toml`. Not reported when `spec` is unsupported: external packs are not resolved and `check` stops after `E_SPEC_UNSUPPORTED`. |
| `E_PACK_VERSION` | error | | A listed pack's pinned version is newer than this binary supports, or (for external packs) the pack's `requires_spec` does not include the vault's `spec`. The message names the failing `name@version` exactly as listed in `confidant.toml`; `file` is `confidant.toml`. |
| `E_PACK_HASH` | error | | An external pack's vendored files do not match the lockfile hash, or the vendored directory is missing. The message names the failing `name@version` exactly as listed in `confidant.toml`; `file` is the vendored path `packs/<name>@<version>`. |
| `E_PACK_INVALID` | error | | An external pack's manifest or contents fail validation: bad `manifest_version`, unknown keys, name or finding-code regex violations, reserved names, capability-limit (PD8) violations, or disallowed files (PD7). A vendored-pack failure names the `name@version` exactly as listed in `confidant.toml` and sets `file` to the vendored path `packs/<name>@<version>`; a broken `confidant.lock` is a separate name-free finding. |
| `E_PACK_CONFLICT` | error | | Two enabled packs claim the same verb, record type, field, balance metric, or edge kind. The pack set is incoherent: `check` reports the conflict and skips all pack folding (core checks still run). |
| `W_PACK_ORPHAN` | warning | | A ledger verb, record field, record type, balance metric, or edge kind belongs to a registered pack that is not enabled. Warnings never block writes; the operator enables the pack or removes the data. |
| `E_INVALID_ID` | error | | An ID is not `prefix-ULID` (ledger subject, merge `TO`, a front-matter reference, or a malformed ID-shaped token in front matter: record prefix, ASCII or Unicode dash, and an alphanumeric run 20–32 characters that fails ULID validation or a longer run whose first 26 characters canonicalize to a ULID). A `person` / `org` / `deal` value (including ASCII case variants: `Person:`, `ORG:`, …) accepts `[[id|Alias]]` only inside `[[…]]` (bare `p-A|Name` is this code), a trailing comment after a space or tab then `#`, and treats empty / `~` / YAML `null` as no reference. Check reports the line number and, when the key is a known spec key (including a case-variant ref key, named as written), the key name; it never echoes the token. |
| `E_INVALID_FILENAME` | error | | A collection or record directory contains a name that is not a record ID, a non-UTF-8 name, or a leftover `.confidant-tmp-*` file. |
| `E_ID_PATH_MISMATCH` | error | | Front matter `id` does not equal the path ID, or a note's `person` does not match `people/<id>/`. On `find`, a mismatch on a note, interaction, or deal uncleares only that record; a mismatch or `E_DUPLICATE_ID` on a person's profile uncleares that whole person. |
| `E_TYPE_PATH_MISMATCH` | error | | Front matter `type` / ID prefix does not match the collection directory. |
| `E_WRONG_ID_TYPE` | error | | `stage`, `open`, or `session` names the wrong record type, or a `merge` folds one record type into another. |
| `E_DUPLICATE_ID` | error | | The same ID appears in two files. |
| `E_DUPLICATE_ULID` | error | | The same ULID is used under two prefixes. |
| `E_FRONTMATTER` | error | | Required front matter keys are missing, duplicated, or malformed (including `no-ai` that is not `true`/`false` — or `notes` on a person record — or is set on a record type that does not allow it; a key the record type does not allow at all, such as `name` on an `edge`; a key that, after stripping surrounding quotes, case-folding, and removing every non-alphanumeric character, equals `noai` other than exact `no-ai`; and note `date` / `session` that is not YYYY-MM-DD). Messages never echo a raw front-matter value. They name the key only when it is a known spec key; otherwise they give the line number only. |
| `E_UNKNOWN_VERB` | error | | A ledger verb is not core, not in an enabled pack, and not owned by a disabled pack (those are `W_PACK_ORPHAN`). The message does not echo the verb. |
| `E_UNKNOWN_RECORD` | error | | A ledger ID has no record file. A pack's `note:` miss is that pack's own finding. |
| `E_UNKNOWN_METRIC` | error | | A `balance` line names a metric no enabled pack defines and no disabled pack owns (those are `W_PACK_ORPHAN`). |
| `E_LEDGER_PATH` | error | | A file under `ledger/` is not `YYYY/MM.cfd`. |
| `E_LEDGER_DATE` | error | | An entry's date is not in its file's year/month. |
| `E_ALIAS_PLAINTEXT` | error | | An `alias` line is not exactly `KIND hmac:HEX` with ≥32 hex characters. |
| `E_ALIAS_COLLISION` | warning | | Two canonical IDs share the same alias kind and HMAC. |
| `E_UNRESOLVED_MERGE` | error | | A `merge` names an ID that does not exist. |
| `E_SELF_MERGE` | error | | A `merge` folds an ID into itself. |
| `E_MERGE_CYCLE` | error | | `merge` entries form a cycle. |
| `E_MERGE_FORK` | error | | The same `FROM` is merged into two different `TO`s. |
| `E_SYMLINK` | error | | A symbolic link exists in the vault. |
| `E_MERGE_CONFLICT` | error | | Git conflict markers (`<<<<<<<` / `>>>>>>>`) are present in a vault file. When both conflict sides parse as encrypted envelopes, the message says the encrypted record has two versions and points at `record resolve`. |
| `E_DANGLING_REF` | error | | A front-matter `person` / `org` / `deal` ID (including ASCII case variants) has no record. Also: an edge end (`a` / `b`) or a `with:` entry with no record. |
| `E_SELF_EDGE` | error | | An edge links a person to themself (`a` and `b` are the same id). |
| `E_DUPLICATE_EDGE` | error | | Two edges state the same relation: an exact duplicate, or a reversed duplicate (`b, a`) of a symmetric kind. |
| `E_UNKNOWN_EDGE_KIND` | error | | An edge `kind` is not in the closed kind list (core kinds plus enabled packs' kinds). A kind owned by a disabled pack is `W_PACK_ORPHAN` instead. |
| `E_TOUCH_MALFORMED` | error | | A `touch` ledger line is malformed. The built-in personal pack is implicit, so a `touch` line carries either `[kind:call\|text\|email\|meet\|meal\|event\|gift\|video\|other]` or `<call\|text\|email\|meet\|meal\|event\|gift\|video\|other> [note:NOTE-ID] [src:PROVENANCE]`; any other shape is malformed. |
| `W_CADENCE_OVERDUE` | warning | `personal.cadence_overdue` | A person with `cadence: <N>d` has no touchpoint (`touch`, `session`, or dated `interaction`) on or after `as_of - N days` (built-in personal pack). |
| `W_DATE_UPCOMING` | warning | `personal.date_upcoming` | A person's `birthday` or an entry in `dates` occurs within `0..=personal.date_upcoming_days` days of `as_of` (built-in personal pack). |
| `E_DUPLICATE_SRC` | error | | The same `src:` provenance appears on two ledger lines. The message does not echo the `src:` value. |
| `W_SKIPPED_ENCRYPTED` | warning | | **Find-only; `check` does not emit it.** A `find` search returned zero matches while `skipped_encrypted > 0`: at least one encrypted record could not be searched, so the zero result does not establish absence. The message carries only the skip count and the remedy (`resolve`/`context`, or building the search corpus with `reindex`); it never carries vault content. Text output repeats the warning on stderr, and the TUI Search view renders it in its status block. Non-empty results do not carry it — the `skipped_encrypted` count still reports the skips. Under a `--packs` scope the count is vault-wide (a skipped record's pack ownership is unknowable without decrypting it) and the message says so. Refused (tampered) envelopes are not folded into it, deliberately: tampering is a distinct condition with a different remedy (investigate/repair, not `resolve`/`context`/`reindex`), so folding it in would misdirect the remedy; refused envelopes stay counted separately in `refused_envelopes`. An empty query runs no search and carries no warning. |
| `E_KEY_COMMITMENT` | error | | A reader refused to use a key epoch because the verified key manifest carries no commitment for it. Fires only in encrypted vaults (spec §14). Reserved for milestone 2 readers; `check` does not emit it. |
| `E_ENVELOPE` | error | | An encrypted record envelope is structurally invalid keylessly: duplicate header keys, unknown header keys, a missing required header, an `enc` other than `xchacha20poly1305`, a nonce that is not 24 bytes, bad base64, or a `key_id` that is not `<client_id>/e<epoch>` (shape only). Fires only in encrypted vaults (spec §14). Reserved for milestone 2 readers; `check` does not emit it. |

**Retired, not emitted, never reused.** These old built-in names stay
reserved and must never be reused for a new meaning; nothing emits them in
0.1:

`E_BALANCE_MISMATCH`, `E_NEGATIVE_BALANCE`, `E_OPEN_MALFORMED`,
`E_MISSING_DURATION`, `E_SESSION_TAGS`, `W_SESSION_UNTAGGED`,
`E_SESSION_WITHOUT_NOTES`, `E_PAID_SESSION_GAP`.

`confidant find` uses the same codes and the section 12 allowlist: only
cleared records and ledger lines are searchable. A note, interaction, or
deal is cleared only when every ledger line that names it is allowed
(persons are not uncleared by this rule). A leading Markdown
bullet (`*`, `-`, or `+` plus whitespace) is skipped before detecting a
`merge` or `open` verb. A finding is kept
verbatim only when it has no file and no ID, or when it resolves to a
cleared record or a cleared ledger line. Everything else is reduced to
its code and the count of affected items — never a path, file name, ID,
key, or line text. Front-matter `E_INVALID_ID` on an uncleared record
is code and count only. Name-only mentions with no ID are not detected
in body prose and comments; a `person` / `org` / `deal` value (including
case variants) that is
not a record ID (including a bare `p-A|Name` pipe alias) is `E_INVALID_ID`
and uncleared. Empty, `~`, and YAML `null` are not references. Ledger parse errors
give the line number and code without echoing tokens. If any ledger file
cannot be read, `find` does not scan: command error `E_LEDGER_UNREADABLE`
(code and count only). `check` still reports `E_UNREADABLE`.

Command-level error codes (not check findings):

| Code | Exit | Meaning |
|---|---|---|
| `usage_error` | 2 | Bad flags or missing arguments. |
| `E_VAULT_NOT_FOUND` | 1 | Discovery (ADR-11) found no vault. |
| `E_NOT_FOUND` | 1 | The caller named something that does not exist. Reserved for a fully searched person set: when person records went unread, a person miss is `E_CANNOT_SEARCH` instead, never `E_NOT_FOUND`. |
| `E_CANNOT_SEARCH` | 1 | A person lookup (`resolve`, a `--person` argument including the `p-<ULID>` form on write commands, `alias resolve`, `context` by name or by id) could not search the vault: person records were skipped as unreadable on this device (no usable key material) or person envelopes were refused as tampered or corrupt, so a miss cannot establish absence. The gate is person-scoped: only unreadable person-record files flip a person miss — an unreadable org, deal, note, edge, or interaction does not. The message names the cause and counts; the fix points at restoring key material or restoring the record from git history (or a backup, for a vault without git history). A match found in the searched set still succeeds — only the negative outcome is gated — which deliberately accepts one residual: a skipped envelope could hide a second same-name person, masking a true ambiguity as a single match; gating every match would fail all lookups whenever any person record is unreadable. `find` is not gated: it surfaces the vault-wide skipped/refused counts with every result instead of erroring (see #718). |
| `E_AMBIGUOUS_PERSON` | 1 | A person argument was an exact display name (not a `p-<ULID>`) that matched more than one person in the §12 cleared set. The message lists the candidate `p-<ULID>`s — never names; only cleared people are searched — and the caller must pass the intended id. |
| `E_ALREADY_EXISTS` | 1 | The caller asked to create something that already exists. |
| `E_INVALID` | 1 | The request is well formed but not valid for this vault. |
| `E_CONFLICT` | 1 | The request conflicts with stored vault state (including a refused symlink on a write path). |
| `E_CONFIG` | 1 | `confidant.toml` cannot be parsed as TOML or is missing `spec` / `vault_id`. Semantic `[checks]` problems are the finding of the same code. |
| `E_SPEC_UNSUPPORTED` | 1 | Vault `spec` is not `0.1`. `check` reports it as a finding; `find` returns this command error and does not scan. |
| `E_LEDGER_UNREADABLE` | 1 | A ledger file could not be read. `find` returns this command error (code and count only, no path) and no hits. `check` still reports finding `E_UNREADABLE`. |
| `E_REINDEX_REFUSED` | 1 | `confidant reindex` refused to build the search corpus: an encrypted record could not be decrypted (counts in `skipped_encrypted` / `refused_envelopes`), or the corpus path is not git-ignored. Writes nothing. |
| `E_NO_REMOTE` | 1 | `confidant sync` found no git remote, no upstream branch, or no commits to compare. Local-only is a valid setup; nothing is fetched or pushed. |
| `E_PLAINTEXT_REMOTE` | 1 | `confidant sync` refused a structurally plaintext vault. A remote would expose every record body, so this fails closed before any network access, including `--dry-run`. |
| `E_NOT_FAST_FORWARD` | 1 | `confidant sync` refused a diverged branch: local and upstream each have commits the other lacks. `--pull`/`--push` are never forced and never auto-merge; reconcile explicitly. |
| `E_IDEMPOTENCY_CONFLICT` | 1 | A `--request-id` was replayed with a different canonical request (same id, different content). |
| `E_INBOX_DIRTY` | 1 | `confidant inbox` refused: the working tree is not clean. |
| `E_INBOX_UNTRUSTED` | 1 | `confidant inbox` refused: the `inbox` branch tip is not signed by a key in the user config's `[trust] signers`. |
| `E_INBOX_ITEM` | 1 | `confidant inbox` refused: an inbox item is not `<name>.age`, is undecryptable, or its decrypted payload is malformed. |
| `E_INBOX_CONFLICT` | 1 | `confidant inbox` refused: an item targets a record path that already exists with different content. Resolve with `confidant record resolve <id> --from-inbox <stem>`; retire the item afterwards with `confidant inbox --discard <stem>`. |
| `E_INBOX_CHECK_FAILED` | 1 | `confidant inbox` refused: the merged vault fails `check` (nothing was committed). |
| `E_INBOX_CRYPTO` | 1 | `confidant inbox` cannot decrypt: milestone 2 crypto is not implemented yet. |
| `E_INBOX_SKIP` | 1 | `confidant inbox --skip` refused: a `--skip` name is not on the `inbox` branch tip (fail closed on typos rather than merging an item the operator meant to defer). |
| `internal_error` | 1 | Unclassified failure. Never match on its message. |
