# Stable finding codes (spec 0.1)

Callers of `confidant check --json` must branch on `code`, never on message
text. Codes are stable once published. A new meaning needs a new code.

Severity listed here is the default. Vault `[checks]` keys can promote,
demote, or turn a rule `off` where the table says "configurable".

| Code | Default severity | Configurable key | When it fires |
|---|---|---|---|
| `E_PARSE` | error | | A ledger line or record file does not match the grammar. |
| `E_UNREADABLE` | error | | A file is not valid UTF-8 or cannot be read. |
| `E_CONFIG` | error | | `confidant.toml` is missing a required field or is not valid TOML. |
| `E_SPEC_UNSUPPORTED` | error | | `spec` is not `0.1`. |
| `E_PACK_UNKNOWN` | error | | A listed pack is not compiled into this CLI. |
| `E_INVALID_ID` | error | | An ID is not `prefix-ULID`. |
| `E_INVALID_FILENAME` | error | | A collection directory contains a name that is not a record ID. |
| `E_ID_PATH_MISMATCH` | error | | Front matter `id` does not equal the path ID. |
| `E_TYPE_PATH_MISMATCH` | error | | Front matter `type` / ID prefix does not match the collection directory. |
| `E_DUPLICATE_ID` | error | | The same ID appears in two files. |
| `E_FRONTMATTER` | error | | Required front matter keys are missing or malformed. |
| `E_UNKNOWN_VERB` | error | | A ledger verb is not core and not in an enabled pack. |
| `E_UNKNOWN_RECORD` | error | | A ledger ID has no record file. |
| `E_UNKNOWN_METRIC` | error | | A `balance` line names a metric no enabled pack defines. |
| `E_LEDGER_PATH` | error | | A file under `ledger/` is not `YYYY/MM.cfd`. |
| `E_LEDGER_DATE` | error | | An entry's date is not in its file's year/month. |
| `E_BALANCE_MISMATCH` | error | | A `balance` assertion disagrees with the computed value. |
| `E_ALIAS_PLAINTEXT` | error | | An `alias` value is not `hmac:` plus ≥8 hex characters. |
| `E_ALIAS_COLLISION` | warning | | Two canonical IDs share the same alias kind and HMAC. |
| `E_UNRESOLVED_MERGE` | error | | A `merge` names an ID that does not exist. |
| `E_SELF_MERGE` | error | | A `merge` folds an ID into itself. |
| `E_MERGE_CYCLE` | error | | `merge` entries form a cycle. |
| `E_SYMLINK` | error | | A symbolic link exists in the vault. |
| `E_MERGE_CONFLICT` | error | | Git conflict markers are present in a vault file. |
| `E_MISSING_DURATION` | error | `coaching.require_duration` | A `session` has no parseable duration. |
| `E_OPEN_MALFORMED` | error | | An `open` line is not `package PKG-ID N sessions`. |
| `E_NEGATIVE_BALANCE` | error | `coaching.balance_nonnegative` | Computed `sessions_remaining` is negative. |
| `E_SESSION_WITHOUT_NOTES` | warning | `coaching.session_notes` | A session has no linked or same-day note (section 9b). |
| `E_PAID_SESSION_GAP` | warning | `coaching.paid_session_gap` | A person with remaining paid sessions has no session in the window. |

Command-level error codes (not check findings):

| Code | Exit | Meaning |
|---|---|---|
| `usage_error` | 2 | Bad flags or missing arguments. |
| `E_VAULT_NOT_FOUND` | 1 | Discovery (ADR-11) found no vault. |
| `E_IDEMPOTENCY_CONFLICT` | 1 | Reserved for milestone 3 (`--request-id`). |
| `internal_error` | 1 | Unclassified failure. Never match on its message. |
