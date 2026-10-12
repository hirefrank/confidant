# Handoff: #148 specs 3 & 4 (encrypted writes + encrypted reads)

This is the implementer handoff for the last two slices of issue #148. It is
written for a lower-capability model: the **decisions are the contract**, the
**behavior bullets map to named tests**, and where a spec line conflicts with
the code, **the code wins** and the discrepancy is raised back on #148
(AGENTS.md).

Status: specs 1 (init/recover), 2 (keys), and #66 (device add) are **merged**
(PRs #149, #150, #151). What remains is:

- **Spec 3** — encrypted writes (flips `writes_encrypted()`).
- **Spec 4** — encrypted reads (`find`/`context`/MCP decrypt).

Do not touch specs 1/2, #66, #105, #152, or #153 — they are Frank's.

---

## 1. The one-line contract

`confidant` must never write plaintext record content into a vault that has
keys, and must never return "no hits / empty bundle" when the truth is
"couldn't decrypt". Everything else is detail.

---

## 2. Decisions (binding)

### 2.1 Confirmed on the issue (do not re-litigate)

| # | Decision |
|---|---|
| ⚠1 | Existing plaintext records are **never encrypted in place** (ADR-4). Only new/changed writes encrypt. `doctor` reports the plaintext/encrypted mix (code + count, never names/paths). **Tightening:** in an encrypted vault, a write that would *rewrite* an existing plaintext record fails closed with a stable error code — never encrypts it in place, never rewrites it as plaintext. (No writer rewrites records today; this is a guard + test.) |
| ⚠2 | Reads without a device key **fail closed per record**: encrypted records are skipped and *counted*, never a whole-command error, never silently empty. Three refinements: **(a)** `find`/`context` return a `skipped_encrypted` count (opaque ids are fine; they are outer-header plaintext); **(b)** `context <p-id>` where that person's key is absent is a **hard error** (own code, non-zero exit), not an empty bundle; **(c)** "no key on this device" is **distinct** from "key present, AEAD check failed" — the latter is tampering/corruption and is an error, never folded into the skip count. |
| ⚠3 | First encrypted writers: `record add` + `note add` (+ `log session --note`, which shares the same write path). Inbox `RecordWrite` **fails closed** on an encrypted vault until its own PR. |
| ⚠4 | Recovery phrase is displayed **exactly once on stderr**; never in `--json` stdout. |
| ⚠5 | Pending inbox rotation is recorded **device-locally** under `~/.config/confidant/`, never in the vault; `doctor` surfaces it. |
| ⚠6 | `init` also creates the `vault:shared` client key. |
| ⚠7 | `anchor::save` exists in `confidant-crypt` (0700 dir / 0600 file, refuses in-vault paths). |

Recorded defaults (override only in review): malformed client id on a `keys`
command = usage error exit 2; reserved-id misuse = `E_INVALID`; `recover`
requires a fresh device; ciphertext-stability comparison is
decrypt-and-compare with the current key (a failed decrypt counts as changed).

### 2.2 New decision: the encryption opt-out (answers the pending "Ask")

The issue's last comment proposes `[crypto].mode` in `confidant.toml`. **Confirm
it, with one tightening** that makes it fail-closed by construction:

**Shape** (`confidant.toml`, optional table, old readers ignore it — same as
`[inbox]`):

```toml
[crypto]
# "encrypted" (default when absent) | "plaintext"
# "plaintext" ONLY for vaults that hold no real data (demo vault, fixtures).
mode = "plaintext"
```

**Semantics — structural-first, declaration is narrowing-only.** The real test
is always spec §14's structural definition: a vault is *encrypted* if it has any
`enc:` envelope file **or any `keys/` tree at all** (a `recipients.toml` manifest,
the operator certificate `keys/operator.toml`, or any `epoch` file); otherwise it
is *plaintext*. A half-initialized `keys/` (operator.toml present but no client
manifests) is **not** plaintext and must never fall into the plaintext branch.
The `mode` declaration can only ever **permit plaintext writes when the vault is
already structurally plaintext**; it can never downgrade an encrypted vault.
Concretely, the writer decision tree:

1. Vault is **structurally encrypted** (has an envelope or any `keys/` tree) →
   writers encrypt, full stop. `mode = "plaintext"` here is an `E_CONFIG`
   contradiction (fail closed) — the declaration is non-authoritative against
   encryption.
2. Vault is **structurally plaintext** (no envelope and no `keys/` tree at all):
   - `mode = "plaintext"` (explicit) → writers write plaintext (today's
     behavior). The vault is validated under spec §§1–13 exactly.
   - `mode` absent or `"encrypted"` → writers **fail closed** with a fix pointing
     at `confidant init` (or `keys init-client <id>` when the vault is keyed but
     the specific client is not). No silent plaintext.

**`writes_encrypted()` is a global flag, not a per-vault one.** The crate flag
and the disclosure flip once, in PR 3, and describe the CLI as a whole ("record
writes encrypt by default"). `mode = "plaintext"` is a **per-vault runtime
override** at the writer for that vault only — it never re-flips
`writes_encrypted()` or the disclosure. A plaintext vault's writes staying
plaintext is the explicit opt-out, not a claim that the CLI writes plaintext.

**Guards (fail closed):**

- `mode = "plaintext"` + any envelope or `keys/` tree present → hard `E_CONFIG` on
  the write/`init`/`check` path. Opt-out is a pre-`init` declaration; an
  encrypted vault can never be opted out later.
- `confidant init` on a vault declaring `mode = "plaintext"` → hard error with
  the fix (remove the line, or use a fresh vault). Keys must never coexist with
  a plaintext declaration.
- `mode` set to any other value → hard `E_CONFIG`; unknown keys inside
  `[crypto]` → `E_CONFIG` (typo detection, same as `[checks]`).

**Readers / check / doctor:**

- `find`/`context` on an opted-out vault: no keys required, no
  `skipped_encrypted` counts — §§1–13 behavior unchanged.
- `check` validates the `[crypto]` table's shape (mode value, no unknown keys) as
  `E_CONFIG` on **every** vault, plaintext or encrypted; it still validates
  envelopes structurally only (keyless), per spec §14.
- `doctor`'s `crypto` check reports the effective mode, so the opt-out is always
  visible.

**Lifecycle:** removing the opt-out later (plaintext → encrypted) is allowed:
delete the line, run `init`. Existing plaintext records stay plaintext forever
(⚠1); rewrites of them fail closed once the vault is encrypted; `doctor` reports
the mix.

**Who uses it:** `examples/demo-vault/confidant.toml` declares
`mode = "plaintext"` (this is what keeps CI keyless and the demo vault clean +
plaintext, spec 3 B10); write-test fixtures that exercise the plaintext path
declare it too; and generic open-source users with no secrets (the ADR-4 opt-out
promise). Keyed tests keep the throwaway-device-key harness; the opt-out is not
a test bypass.

### 2.3 Required spec edits (rule 7 — ride the same PR that flips the flag)

`spec/0.1.md` §2 (confidant.toml) gains the optional `[crypto]` table; §14's
"encrypted vault / plaintext vault" paragraph is amended to note that a
`mode = "plaintext"` declaration is always a plaintext vault (the structural
definition still governs), that "encrypted vault" includes **any `keys/` tree**
(not only a recipient manifest — so a half-initialized `keys/` is encrypted), and
that a `mode = "plaintext"` + envelope/`keys/` combination is `E_CONFIG`.
`docs/crypto-design.md` §3 gains a matching note.
Do these in the same PR as the flip, or the disclosure is stale.

---

## 3. Read first (the code you will touch)

- `crates/confidant-crypt/src/lib.rs` — `writes_encrypted()` (currently `false`),
  `client_id_for_record()`, `RecordCtx`, `encrypt_record()`, `decrypt_record()`.
  `decrypt_record(_, _, _, for_agent = true)` already refuses `no-ai` **before**
  decrypting — build on that, never route around it.
- `crates/confidant-crypt/src/envelope.rs` — `parse()`, `serialize()`,
  `check_header()`, `purpose_for_type()`. `parse()` is the keyless structural
  reader.
- `crates/confidant-crypt/src/lifecycle.rs` — `KeyStore::with_config_dir()`
  (mandatory seq tracker, #134), `current_epoch()`, `unwrap_data_key()`,
  `init_client()`, `manifest_clients()`.
- `crates/confidant-crypt/src/anchor.rs` — `Anchor`, `anchor::load()`.
- `crates/confidant-core/src/write.rs` — `FileChange::{AppendLines,WriteFile}`,
  `PendingWrite`, `apply_write()`. This is the record-write choke point.
- `crates/confidant-core/src/inbox/merge.rs` — `PlannedWrite::RecordWrite`,
  `apply_writes()` (the **separate** inbox write path, not through `write.rs`).
- `crates/confidant-core/src/search.rs` — `search()`, the §12 allowlist. **Do not
  reimplement any of it.**
- `crates/confidant-core/src/context.rs` — `build_context()`.
- `crates/confidant-core/src/config.rs` — `VaultConfig`, `config_findings()`
  (where `[crypto]` validation goes), the `[inbox]` table as the precedent for an
  optional ignored table.
- `crates/confidant-cli/src/main.rs` — `cmd_record_add`, `cmd_note_add`,
  `cmd_log_session`, `cmd_find`, `cmd_context`, `cmd_doctor`, and the existing
  keyed-caller pattern at the `keys` commands:
  `confidant_config_dir()` → `anchor::load(&config_dir, root)` →
  `keys_device_identity()` → `load_operator_sk(&anchor)` →
  `KeyStore::with_config_dir(keys_dir, &vault.config.vault_id, &config_dir)`.
  Reuse this exact pattern; do not invent a second way to load keys.

---

## 4. Spec 3 — encrypted writes

**Purpose:** `record add`, `note add`, and `log session --note` write §14
envelopes; inbox `RecordWrite` fails closed on an encrypted vault; flip
`writes_encrypted()` and rewrite the disclosure in the same PR.

**Gate:** decisions ⚠1, ⚠3, ⚠4 and §2.2 (opt-out) must be recorded first.

### 4.1 Put the hook at one choke point

Add a record-file encryption step **at the write layer** so a future command
cannot bypass it. The three CLI writers all build a `FileChange::WriteFile`
targeting a record path and call `apply_write()`. Do the transform *before*
`apply_write` sees the contents (a helper that takes the target path + the
plaintext record bytes and returns the bytes to write):

1. Resolve the record type + person from the record being written (use
   `confidant_core::parse_record` on the plaintext, or the same fields the
   caller already built — e.g. `cmd_log_session` knows `person` and `kind`).
2. `confidant_crypt::client_id_for_record(type, person)` → client id.
3. `KeyStore::current_epoch(client)` → epoch.
4. `KeyStore::unwrap_data_key(client, <this device key id>, epoch, &identity,
   &anchor)` → data key. (You need this device's key id; see `keys_device_identity()`
   and how `keys` commands name the device — reuse the same id.)
5. Build `RecordCtx { vault_id, ulid, client_id, path, purpose, epoch }` and
   `encrypt_record(&ctx, &key, type, no_ai, plaintext_bytes)`.

Any failure in steps 1–5 (no device key, client never initialized) **refuses the
write**: error with a fix suggesting `keys init-client <id>` (or `init` when the
vault has no `keys/` tree at all), and leave the target file untouched. No
plaintext fallback, no partial write.

### 4.2 Behavior bullets → tests

- **B1 Key resolution, fail closed.** Any resolution failure refuses the write;
  the target file is absent afterward.
- **B2 Envelope shape.** Outer header exactly `id`/`type`/`no-ai`/`enc`/
  `key_id`/`nonce` + base64 body (spec §14; `encrypt_record` enforces
  type→purpose). `name:` lives only inside the ciphertext. The outer `no-ai` is
  the person record's flag (the record's own flag for a person) — **any `true`
  wins** (design §5). Today `note add` only sets `no-ai` when the flag is passed;
  writers must read the person's value from its plaintext outer header, which
  needs no decryption.
- **B3 Ciphertext stability.** If the target already holds an envelope whose
  inner plaintext equals the new content, keep the existing file byte-for-byte
  (no new nonce, no diff). Compare by decrypt-and-compare with the current key; a
  failed decrypt counts as changed.
- **B4 Deal `person` change** re-encrypts under the new person's current epoch
  in the **same commit** (design §2).
- **B5 Dry-run** shows the inner plaintext in `changes[]` — never ciphertext,
  never base64.
- **B6 Existing plaintext records are never encrypted in place** (⚠1). New /
  changed writes only. `doctor` gains a check reporting the plaintext vs
  encrypted record-file mix (code + count only).
- **B7 Ledger, `import`, `confidant.toml` untouched** (⚠3) — plaintext by design.
- **B8 The write pipeline is unchanged elsewhere:** check-before-commit, one
  commit per write, `--request-id` idempotency, trailers, agent attribution.
- **B9 `writes_encrypted()` → `true`, and the disclosure is rewritten in this
  PR.** README Status, `crates/confidant-crypt/README.md`, and any AGENTS.md
  crypt row change here. A stale disclosure after this PR is worse than the
  current one.
- **B10 Demo vault stays plaintext and CI stays keyless.** The demo vault and
  plaintext-write fixtures declare `mode = "plaintext"` (§2.2). Encrypted-write
  tests use the per-test harness: temp `HOME` + anchor + keys + a throwaway
  device key via `CONFIDANT_DEVICE_KEY` (ADR-14). The existing `writes.rs` suite
  moves onto a fixture that declares `mode = "plaintext"`; one dedicated test
  asserts the unkeyed refusal path. Budget for this — it is the bulk of the cost.
- **B11 Inbox `RecordWrite` fails closed on an encrypted vault.** In
  `inbox/merge.rs` `apply_writes()` (or `plan.rs`), when the vault is
  structurally encrypted (has `keys/` manifests), refuse the record write with a
  clear error and a fix pointing at a follow-up issue (transcripts land via a
  later PR). Do **not** write plaintext. Add a test. Ledger `LedgerAppend` items
  stay plaintext by design (§3).

### 4.3 Tests (all required)

- `record_add_writes_envelope_not_plaintext` (file starts `---\nid:` and carries
  `enc:`; `name:` absent from the file)
- `note_add_encrypts_body_and_name`
- `log_session_note_writes_envelope`
- `write_refuses_without_device_key_no_fallback` (file absent after refusal)
- `write_refuses_uninitialized_client_suggests_keys_init_client`
- `rewrite_unchanged_keeps_ciphertext_bytes`
- `deal_person_change_reencrypts_same_commit`
- `no_ai_header_carries_person_flag_any_true_wins`
- `dry_run_shows_plaintext_never_ciphertext`
- `ledger_and_import_stay_plaintext`
- `doctor_reports_plaintext_encrypted_mix`
- `inbox_recordwrite_fails_closed_on_encrypted_vault`
- `opt_out_plaintext_mode_writes_plaintext` (a `mode = "plaintext"` vault)
- `opt_out_with_envelope_is_e_config`
- `opt_out_with_keys_tree_refuses_plaintext` (a half-initialized `keys/` — e.g.
  `keys/operator.toml` with no client manifest — must NOT fall into the plaintext
  branch; write fails closed)
- `init_refuses_plaintext_declared_vault`
- `no_secret_material_in_any_output`

### 4.4 Do not

Never encrypt in place. Never write plaintext on a missing key. Never put
`name:` in the outer header. Never emit ciphertext in dry-run output. Never log
inner plaintext. Don't touch ledger encryption. Don't flip `writes_encrypted()`
in any PR other than this one, and never without the disclosure rewrite.

---

## 5. Spec 4 — encrypted reads

**Purpose:** `find`/`context` (and MCP) decrypt through the CLI while the §12
allowlist and `no-ai` hold exactly as before. **Gate:** ⚠2.

### 5.1 Architecture: a keyless content hook

Core (`search.rs`, `context.rs`, `check.rs`) must stay **keyless**. Introduce a
content-provider hook that core's read path calls per file: given a record path
and its raw bytes, return the plaintext bytes to parse as a `Record` — or `None`
meaning "skip this record". The CLI supplies a decryptor (built from
`KeyStore` + device identity + anchor); `check` supplies "none", so it stays
structural and keyless. Do **not** put key material or `confidant-crypt` types in
core's search/context signatures beyond this opaque hook.

The decryptor's job, per file:

1. If the bytes are **not** an envelope (no `enc:` header) → return them as-is
   (plaintext record, today's behavior).
2. If `envelope::parse()` fails → tampered/corrupt; the record is **refused and
   counted** (⚠2c), never returned, never empty.
3. If the outer header says `no-ai: true` → skip **without decrypting** (design
   §5), even when the key is present. `decrypt_record(for_agent = true)` already
   enforces this — call it with `for_agent = true` on agent paths.
4. Else read `client_id` and `epoch` from the outer `key_id` header (it is
   `<client_id>/e<epoch>`), `unwrap_data_key`, and
   `decrypt_record(for_agent = true)` → inner plaintext `Record`.

The inner plaintext then flows through the **existing** §12 pipeline
(parse → allowlist → hits). Do not reimplement the allowlist.

### 5.2 Behavior bullets → tests

- **B1 `find`:** encrypted records parse structurally; with a device key they
  decrypt via `decrypt_record(for_agent = true)` and the decrypted inner record
  flows through the existing §12 allowlist. Without a key: skipped and counted
  (⚠2). Plaintext records in the same vault behave exactly as today.
- **B2 `no-ai: true`** excludes the record without decrypting, even when keyed
  (design §5). The `for_agent` refusal in `decrypt_record` is the enforcement
  point.
- **B3 Tampered / undecryptable envelopes** are refused per record and **counted**
  (code + count, no content, no paths unless cleared) via the existing
  reduced-findings mechanism. Auth failure is a decryption failure, not a check
  finding — do not invent a new `E_` code.
- **B4 `context`:** with a key, profile/notes/interactions decrypt and bundle as
  today; without, the bundle still carries ids, dates, ledger facts (plaintext by
  design) plus counts of what was skipped. A `no-ai` person behaves exactly as
  today. `context <p-id>` where the person's key is absent is a **hard error**
  (⚠2b).
- **B5 `check` stays keyless and structural** (§14: envelope shape,
  `E_ENVELOPE`, `E_KEY_COMMITMENT` on encrypted vaults). It never decrypts.
- **B6 MCP inherits all of this** through the same functions (rule 8; the error
  envelope matches the CLI's).
- **B7 `find --json`/text carry a `skipped_encrypted` count** so an agent can
  never read "no hits" when the truth is "couldn't read" (⚠2a). The `allowlist`
  commands and QMD index-time exclusion (#120) keep working on mixed vaults —
  encrypted record paths are still just paths.

### 5.3 Tests (all required)

- `find_decrypts_cleared_encrypted_records`
- `find_excludes_no_ai_without_decrypting_even_when_keyed`
- `find_unkeyed_skips_and_counts_never_silent_empty` (a hit-free result that
  silently omits encrypted content is the bug class this catches)
- `context_keyed_bundles_encrypted_unkeyed_counts`
- `context_unkeyed_person_is_hard_error`
- `tampered_envelope_refused_counted_no_content`
- `check_keyless_structural_on_mixed_vault`
- `mcp_find_matches_cli_envelope`
- `allowlist_fixed_point_on_mixed_vault`
- `no_secret_in_findings`

### 5.4 Do not

Never decrypt a `no-ai` record on an agent path, key or no key. Never let a
missing key turn into silent empty results. Never put decrypted content into
finding messages. Don't touch the allowlist implementation. Don't make `check`
require keys. Never match a query against the base64 body.

---

## 6. Sequencing & escalation

- Order: **PR 3 then PR 4**, but PR 4 can start after PR 2 using envelopes built
  with `encrypt_record` directly in fixtures. PR 3 makes new records unreadable
  to `find`/`context` until PR 4 lands, so land them back to back or reads-first
  with fixture-built envelopes.
- **Escalation:** PR 3 (the disclosure flip + inbox fail-closed) and the read
  path's `no-ai`/skip boundary are the high-risk slices. Strongest available
  implementer, or a strong-model adversarial diff review before Silas sees it.
- Every PR body states **needs outside audit before public launch**, follows
  rule 9 (no AI attribution), fake data only, and leaves the demo vault clean
  **and plaintext**.

---

## 7. GitHub comment (the opt-out decision)

The rule-7 opt-out decision is posted on issue #148:
<https://github.com/hirefrank/confidant/issues/148#issuecomment-6124891078>
(archived in `docs/148-issue-comment.md`). The decision confirms the
`[crypto].mode` proposal with one tightening: the declaration is
**structural-first and narrowing-only** — it can permit plaintext writes only
while the vault is already structurally plaintext, and can never downgrade an
encrypted vault.

A copy/paste implementer prompt is in `docs/148-flash-prompt.md`.

