# Stable finding codes (spec 0.1)

Callers of `confidant check --json` must branch on `code`, never on message
text. Codes are stable once published. A new meaning needs a new code.

Severity listed here is the default. Vault `[checks]` keys can promote,
demote, or turn a rule `off` where the table says "configurable".

| Code | Default severity | Configurable key | When it fires |
|---|---|---|---|
| `E_PARSE` | error | | A ledger line or record file does not match the grammar. |
| `E_UNREADABLE` | error | | A file is not valid UTF-8 or a directory cannot be read. |
| `E_CONFIG` | error | | `confidant.toml` is missing a required field, is not valid TOML, or a `[checks]` key/value is unknown, mistyped, or out of range. |
| `E_SPEC_UNSUPPORTED` | error | | `spec` is not `0.1`. |
| `E_PACK_UNKNOWN` | error | | A listed pack is not compiled into this CLI. |
| `E_INVALID_ID` | error | | An ID is not `prefix-ULID` (ledger subject, `note:`, merge `TO`, `open` PKG-ID, a front-matter reference, or a malformed ID-shaped token in front matter: record prefix, ASCII or Unicode dash, and an alphanumeric run 20–32 characters that fails ULID validation or a longer run whose first 26 characters canonicalize to a ULID). A `person` / `org` / `deal` value accepts `[[id|Alias]]` only inside `[[…]]` (bare `p-A|Name` is this code), a trailing comment after a space or tab then `#`, and treats empty / `~` / YAML `null` as no reference. Check reports the line number and, when the key is a known spec key, the key name; it never echoes the token. |
| `E_INVALID_FILENAME` | error | | A collection or record directory contains a name that is not a record ID, a non-UTF-8 name, or a leftover `.confidant-tmp-*` file. |
| `E_ID_PATH_MISMATCH` | error | | Front matter `id` does not equal the path ID, or a note's `person` does not match `people/<id>/`. On `find`, a mismatch on a note, interaction, or deal uncleares only that record; a mismatch or `E_DUPLICATE_ID` on a person's profile uncleares that whole person. |
| `E_TYPE_PATH_MISMATCH` | error | | Front matter `type` / ID prefix does not match the collection directory. |
| `E_WRONG_ID_TYPE` | error | | `stage`, `open`, or `session` names the wrong record type, `note:` is not a note, or a `merge` folds one record type into another. |
| `E_DUPLICATE_ID` | error | | The same ID appears in two files. |
| `E_DUPLICATE_ULID` | error | | The same ULID is used under two prefixes. |
| `E_FRONTMATTER` | error | | Required front matter keys are missing, duplicated, or malformed (including `no-ai` that is not a boolean or is set on a record type that does not allow it; a key that, after stripping surrounding quotes, case-folding, and removing every non-alphanumeric character, equals `noai` other than exact `no-ai`; and note `date` / `session` that is not YYYY-MM-DD). Messages never echo a raw front-matter value. They name the key only when it is a known spec key; otherwise they give the line number only. |
| `E_UNKNOWN_VERB` | error | | A ledger verb is not core and not in an enabled pack. |
| `E_UNKNOWN_RECORD` | error | | A ledger ID has no record file, or `note:` does not name a note that belongs to the session's person. |
| `E_UNKNOWN_METRIC` | error | | A `balance` line names a metric no enabled pack defines. |
| `E_LEDGER_PATH` | error | | A file under `ledger/` is not `YYYY/MM.cfd`. |
| `E_LEDGER_DATE` | error | | An entry's date is not in its file's year/month. |
| `E_BALANCE_MISMATCH` | error | | A `balance` assertion disagrees with the value computed as of the end of the assertion date. |
| `E_ALIAS_PLAINTEXT` | error | | An `alias` line is not exactly `KIND hmac:HEX` with ≥32 hex characters. |
| `E_ALIAS_COLLISION` | warning | | Two canonical IDs share the same alias kind and HMAC. |
| `E_UNRESOLVED_MERGE` | error | | A `merge` names an ID that does not exist. |
| `E_SELF_MERGE` | error | | A `merge` folds an ID into itself. |
| `E_MERGE_CYCLE` | error | | `merge` entries form a cycle. |
| `E_MERGE_FORK` | error | | The same `FROM` is merged into two different `TO`s. |
| `E_SYMLINK` | error | | A symbolic link exists in the vault. |
| `E_MERGE_CONFLICT` | error | | Git conflict markers (`<<<<<<<` / `>>>>>>>`) are present in a vault file. |
| `E_MISSING_DURATION` | error | `coaching.require_duration` | A `session` has no parseable duration. |
| `E_OPEN_MALFORMED` | error | | An `open` line is not `package PKG-ID N sessions`, `N` is over 100000, or the running open total overflows. |
| `E_NEGATIVE_BALANCE` | error | `coaching.balance_nonnegative` | Computed `sessions_remaining` is negative. |
| `E_SESSION_WITHOUT_NOTES` | warning | `coaching.session_notes` | A session has no linked or same-day note (coverage only; `note:` integrity is always on). |
| `E_PAID_SESSION_GAP` | warning | `coaching.paid_session_gap` | A paid client (`sessions_remaining > 0` or a `pps` session within `coaching.pps_lookback_days`) has no session in the gap window. The gap clock runs from `max(last session, latest open)`. |
| `W_SESSION_UNTAGGED` | warning | | A session has none of `paid`, `pps`, or `comp`. The session still consumes a package slot. |
| `E_SESSION_TAGS` | error | | A session has more than one of `paid`, `pps`, or `comp`. |
| `E_DANGLING_REF` | error | | A front-matter `person` / `org` / `deal` ID has no record. |
| `E_DUPLICATE_SRC` | error | | The same `src:` provenance appears on two ledger lines. |

`confidant find` uses the same codes and the section 12 allowlist: only
cleared records and ledger lines are searchable. A note is cleared only
when every ledger line that names it is allowed. A leading Markdown
bullet (`*`, `-`, or `+` plus whitespace) is skipped before detecting a
`merge` or `open` verb. A finding is kept
verbatim only when it has no file and no ID, or when it resolves to a
cleared record or a cleared ledger line. Everything else is reduced to
its code and the count of affected items — never a path, file name, ID,
key, or line text. Front-matter `E_INVALID_ID` on an uncleared record
is code and count only. Name-only mentions with no ID are not detected
in body prose and comments; a `person` / `org` / `deal` value that is
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
| `E_NOT_FOUND` | 1 | The caller named something that does not exist. |
| `E_ALREADY_EXISTS` | 1 | The caller asked to create something that already exists. |
| `E_INVALID` | 1 | The request is well formed but not valid for this vault. |
| `E_CONFLICT` | 1 | The request conflicts with stored vault state (including a refused symlink on a write path). |
| `E_CONFIG` | 1 | `confidant.toml` cannot be parsed as TOML or is missing `spec` / `vault_id`. Semantic `[checks]` problems are the finding of the same code. |
| `E_SPEC_UNSUPPORTED` | 1 | Vault `spec` is not `0.1`. `check` reports it as a finding; `find` returns this command error and does not scan. |
| `E_LEDGER_UNREADABLE` | 1 | A ledger file could not be read. `find` returns this command error (code and count only, no path) and no hits. `check` still reports finding `E_UNREADABLE`. |
| `E_IDEMPOTENCY_CONFLICT` | 1 | Reserved for milestone 3 (`--request-id`). |
| `internal_error` | 1 | Unclassified failure. Never match on its message. |
