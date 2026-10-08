# cr spike: contribute, fork, or build? (2026-10-07)

**Summary**
- **Verdict: build our own and borrow patterns.** cr's encryption and storage layers are **not** separable. Across 56.7k lines of `src/` there are **zero traits**. Encryption is one concrete `EncryptionPolicy` with a single global keyring read from env vars inside `protect()`. Its envelope semantics are woven into audit replay. Storage is one 8.2k-line concrete `Database` built on YAML front matter as the source of truth.
- None of our one-way doors slots in. Per-client age DEKs need new key plumbing through ~10 call sites in encryption.rs, database.rs, audit.rs and sync.rs. A strict ledger is a different data model from front matter. cr explicitly **refuses encryption for folder ("bundle") records**, which is exactly our `people/p-…/profile.md + notes/` layout. ~40% of `src/` (22.6k lines) is the server, web UI and RBAC we don't want.
- Contributing upstream is unrealistic. It's a one-person project, 9 weeks old, and recent work all goes into `serve` and the UI. Forking means deleting 40% and rewriting the core semantics of the rest.
- **Worth borrowing (MIT, with attribution):** the AEAD-with-AAD record binding (~150 lines), the HMAC-keyed idempotency digests (~60 lines), the `DomainError` taxonomy and `check` Finding types (~450 lines), the agent attribution model (attribution.rs), the safe path walker (paths.rs), and the pending-write crash recovery pattern.
- **ADR changes:** ADR-4 should wrap keys with age and encrypt content with XChaCha20-Poly1305 plus AAD, because age has no associated data. It should also authenticate recipient-list changes against a trust anchor outside the vault, keep unchanged ciphertext as-is, and import encrypted from the first write. ADR-7 should keep commit messages, reasons and intent free of plaintext PII, and scope `--request-id` and store it hashed. ADR-10 should pin trusted signers outside the vault. ADR-2 and Open Q2 should not leave alias emails as plaintext ledger arguments. The prior-art appendix needs correcting.
- **Don't adopt cr's linear audit hash chain.** Every write touches the same segment and anchor files, so two devices writing at once guarantees a git conflict. That defeats ADR-3. Use git history plus signed commits as the audit trail instead.

---

## 0. What I read and how

- **Repo:** https://github.com/AnandChowdhary/cr, shallow-cloned and then unshallowed into `/workspace/research/cr`.
- **Commit read:** `f29f8d434c8a854b5b3e2ce41921667dede1aa7e` (main, "chore(release): v0.2.75", 2026-10-02 3:32 PM ET). Crate version 0.2.75, edition 2024, MSRV 1.89.
- **What I read:** the code itself (encryption.rs, database.rs, audit.rs, check.rs, error.rs, paths.rs, bundle.rs, attribution.rs, main.rs error path) plus `docs/architecture.md`, `docs/encryption.md` and `SECURITY.md`.
- **Build:** not run. The box has rustc 1.85.1, and the lockfile needs ≥1.88 (`time 0.3.55`, `icu_provider`) against a declared MSRV of 1.89. I didn't install a newer toolchain, since a build was optional.
- **Size:** `src/` is 56,666 lines and `tests/` is 46,562 lines. `TODO.md` alone is 129 KB.

### Activity and maintenance signals
| Signal | Value |
|---|---|
| Created | 2026-08-04 (about 9 weeks old) |
| Last commit on main | 2026-10-02 3:32 PM ET (`f29f8d4`); last push 2026-10-05 (a Dependabot branch) |
| Commits | 254 total: Anand Chowdhary 174, github-actions[bot] 75 (release bumps), dependabot 4, imgbot 1 |
| Human contributors | **1** (bus factor 1) |
| Stars / forks / watchers | 2 / 0 / 0 |
| Open issues | 2, both Dependabot PRs (#121, #132). No human-filed issues are open, and only 2 issues have ever been closed. |
| Velocity | About 132 PRs in 9 weeks, all self-merged. Late Sept to Oct 2 work is almost entirely `serve`, UI, access control and Cloudflare Access (#118, #120, #122–#131). |
| Stability | `SECURITY.md` says "pre-1.0". The audit payload format is already at **v4**, with v1–v3 compatibility code kept around. |
| License | MIT, "Copyright (c) 2026 Anand Chowdhary" |

Read: the project is active and carefully engineered, with unusually thorough tests and design prose. But it's a single-maintainer project whose direction (a REST API, a web UI, multi-user RBAC, Cloudflare Access) runs **away** from ours.

---

## 1. Is cr's encryption and storage layer separable? **No.**

### 1.1 Module structure and coupling
`src/lib.rs` declares 24 modules. A repo-wide search for `trait` finds **none**, and there is no `dyn` storage or crypto abstraction anywhere. Everything is concrete structs and free functions behind `pub(crate)`.

| Module | Lines | Depends on (`crate::`) | Coupling |
|---|---|---|---|
| `database.rs` | 8,232 | basically everything: access, attribution, audit, bundle, check, encryption, sync, value, views | God object. A single `Database` struct (L280) owns config, layout, actor, principal, auth, attribution, idempotency key, journal cache, schema cache and read caches. |
| `audit.rs` | 7,249 | access, attribution, bundle, database, **encryption**, paths, signing | The journal protocol knows about encryption ownership and access decisions |
| `encryption.rs` | 1,291 | error, frontmatter | Concrete. Keys come from env, the policy comes from JSON Schema, and the envelope lives in YAML front matter. |
| `server.rs` + `server/live.rs`, `access.rs`, `cloudflare_access.rs`, `views.rs`, `readiness.rs`, `pins.rs` | 22,586 | — | REST, HTML UI and RBAC: out of scope for us |
| `check.rs` | 1,623 | access, audit, bundle, database, paths, signing | Scan logic is welded to `Database` and the audit log. Report types are clean. |
| `paths.rs` | 1,214 | error only | **Cleanly separable** |
| `attribution.rs` | 1,599 | error only | **Cleanly separable** |
| `error.rs` | 406 | none | **Cleanly separable** |
| `signing.rs` | 733 | audit::digest, error | Nearly separable |

### 1.2 Encryption layer (`src/encryption.rs`)
- **Keys are hard-wired to the environment.** `Keyring::from_environment()` (L827) parses `CR_ENCRYPTION_KEYS`, a JSON map of id→32-byte key, plus `CR_ENCRYPTION_ACTIVE_KEY`. It's called *inside* `EncryptionPolicy::protect()` (L229) and the reveal path. You can't inject a key provider without changing those signatures.
- **There's one active key for the whole database.** Every new envelope uses `keyring.active_key()` (L872). Nothing maps from a record or client to a key, so there's nowhere to hang per-client DEKs.
- **The policy comes from JSON Schema.** `EncryptionPolicy::from_schema()` (L150) walks `x-cr-encrypted` field markers and the root `x-cr-encrypted-body`. Encryption is per field or per body inside one Markdown file, not per file or per client.
- **The envelope format is baked into YAML.** Fields are stored as `{$cr_encrypted: {version, key_id, nonce, ciphertext}}` (`render_field_envelope`, L966), and the body as `cr-encrypted:v1:<key_id>:<nonce>:<ct>` (L1012). A `$cr_encryption` manifest is injected into front matter (L294).
- **Crypto:** XChaCha20-Poly1305 with a fresh 192-bit random nonce per changed value (`encrypt_bytes`, L922). The AAD is a length-prefixed encoding of `domain ‖ vault context id ‖ collection ‖ record id ‖ purpose ‖ field path ‖ key_id` (`record_aad`, L1124; `keyed_aad`, L1154; `append_component`, L1160). This is the "record-bound encryption", and it's good.
- **Audit replay knows about envelopes.** `audit.rs` imports `audit_document_encryption_metadata`, and replay tracks "protected storage ownership" per record (`needs_audited_encryption_ownership`, `audited_record_owns_protected_storage` in database.rs L6484–6492, L7706). Changing the envelope or key model therefore changes the audit protocol.
- **Bundles are explicitly refused.** `Database::refuse_encrypted_bundles` (database.rs L6315, called from 3 places) rejects encryption for any collection stored as folders. Our layout is precisely folder-per-record with encrypted notes.
- **Its own docs rule out our use case.** `docs/encryption.md` § "What encryption does not protect" says it is "at-rest confidentiality, not selective erasure… Per-record key destruction… remain roadmap work."

**Plugging in ADR-4 would mean:** replacing `Keyring` with a resolver that maps a record to a client DEK unwrapped via age. That threads a client id through `protect`/`reveal`/`reveal_in_session`, `protect_document` and `reveal_document_with_policy*` (database.rs L6434–6582), the sync stream helpers (sync.rs), and audit history projection. It also means teaching audit replay a new envelope form, lifting the bundle refusal, and changing the encryption unit from field to file. That's a rewrite of the layer, not a slot-in.

### 1.3 Storage layer and record→path mapping
- **Front matter is the source of truth.** Records are `records/<collection>/<id>.md` with arbitrary typed YAML front matter. Updates rewrite fields in place (`update`/`patch`, database.rs L4214+), and history goes to a separate JSON-pointer diff journal. This is exactly the "YAML frontmatter as source of truth" alternative that ADR-2 rejects.
- **The path mapping is simple:** `Database::record_path` (database.rs L5995) runs `validate_component(collection)` and `validate_component(id)`, then `RecordLayout::record_path` (bundle.rs L179) produces `data_dir/collection/id.md` or, for a bundle, `data_dir/collection/id/<entry>`. IDs are caller-chosen. `validate_component` (database.rs ~L7830) only rejects empty values, `.`, `..`, `/`, `\` and NUL. There's **no ID generation**: no ULID or UUID anywhere, and the examples use name slugs (`acme-renewal.md`, `priya-shah.md`). ULIDs would *work* as IDs, but nothing enforces them.
- **cr doesn't use git for storage.** It only shells out to `git config` to get an identity (`git_identity`, database.rs ~L7034). Its own journal is the "recorded state", and files are the "working tree" (`status`/`save`).
- **There's no ledger concept at all.** A dated-entry grammar, balance assertions and derived values would be a new storage model living beside or instead of `Database`, not a plugin to it.

### 1.4 The audit log (`src/audit.rs`)
- The journal lives in `.cr/audit/segments/NNNNNNNNNNNNNNNNNNNN.jsonl`. Each line is `{hash, payload}`, and the payload (`AuditPayload`, L347) holds version, a **global sequence**, timestamp, actor, source, agent, authorization, intent, access, message, idempotency, action, record, `changes` (add/remove/replace JSON pointers), `files`, `after_snapshot` (the exact full Markdown), before and after hashes, and `previous_hash`.
- It's a **single linear SHA-256 chain** across the whole database. Every write also rewrites `.cr-audit-head.json` (the anchor) and optionally `.cr-audit-head.sig.json`, both committed to git (architecture.md § "The audit anchor").
- **For git-synced multi-device use, that's fatal.** Two clones that each write once both append sequence N+1 to the same active segment and rewrite the same anchor file. The result is a guaranteed merge conflict, and resolving it requires re-chaining. ADR-3's goal that "most concurrent writes touch different files" can't hold with this design. cr assumes one machine, using `File::lock` on `.cr/audit/lock`.
- **It duplicates data.** Every present state stores a full `after_snapshot` Markdown, and idempotent writes store the result Markdown again (`AuditIdempotencyResult`, L414). With encryption, that means more ciphertext copies (still shreddable). Plaintext fields, actor, message and intent text sit in the journal **forever**, and the chain forbids removing them.
- **Reconciliation is expensive.** Lots of code (legacy representation gaps, snapshot versions v1–v4, `status`/`save`, ownership replay) exists only to reconcile two sources of truth: files and journal. That's a warning for us.

---

## 2. Recommendation: **build our own, borrow patterns and a few small pieces of code**

| Option | Verdict | Why (specific to cr's code) |
|---|---|---|
| **Contribute upstream** (per-device keys and a ledger) | ✗ | It needs the maintainer to accept (a) a key-resolver abstraction through `encryption.rs`, `database.rs` and `audit.rs` replay, (b) lifting `refuse_encrypted_bundles`, (c) a second storage model (the ledger), and (d) audit changes for multi-device git. That's a redesign of his core, and his roadmap (TODO.md, PRs #118–#131) points at `serve`, the UI and RBAC. Bus factor 1, and no outside contributors yet. |
| **Fork** | ✗ | We'd delete ~22.6k lines (server, UI, access, Cloudflare), replace the source of truth (front matter → ledger), replace the key model (`Keyring::from_environment` → age-wrapped per-client DEKs), replace the encryption unit (field → file), and replace or remove the linear audit chain (it conflicts with ADR-3). What's left that we'd keep unchanged is mostly `paths.rs`, `error.rs` and `attribution.rs`. A fork would also inherit a v1–v4 audit-compatibility burden for data we don't have. |
| **Build our own, borrow** | ✓ **Recommended** | Our hard-to-reverse choices (ADR-2, ADR-3, ADR-4) are exactly where cr is most hard-wired. Its best ideas are small, self-contained and easy to re-express: AAD binding, keyed idempotency digests, the error taxonomy, collect-don't-throw check, and attribution. This confirms Frank and Silas's lean toward building. |

---

## 3. cr code worth reusing (with MIT attribution)

Line counts are approximate and refer to commit `f29f8d4`.

| What | Where | Size | Adaptation | Use it for |
|---|---|---|---|---|
| **Record-bound AEAD** | `src/encryption.rs`: `encrypt_bytes` L922, `decrypt_bytes` L950, `record_aad` L1124, `keyed_aad` L1154, `append_component` L1160, `EncryptionContext` L43–93, `Keyring` zeroize pattern L827–895 | ~200 of 1,291 lines | **Medium.** Replace `Keyring` with "DEK unwrapped from `keys/<client>.age`". Change the AAD components to `vault id ‖ type ‖ ULID ‖ relative path ‖ purpose ‖ key-epoch`. Drop the YAML field envelope in favor of a file-level envelope. | `crm-crypt` content encryption (see ADR-4 note in §4) |
| **No-churn re-encryption** | `EncryptionPolicy::protect` L211–303: an unchanged plaintext keeps its prior envelope | ~90 lines (pattern) | Low. Same idea at file level: decrypt the old file, compare, and keep the bytes if unchanged. | Small git diffs and fewer conflicts on encrypted files (ADR-3) |
| **Idempotency digests** | `src/database.rs`: `validate_idempotency_key` L7336, `idempotency_digest` L7350, `idempotency_request_digest` (HMAC keyed by the raw key) L7365, canonical request envelope `idempotency_request` L1125–1164; `src/value.rs` `idempotency_value` L57 (typed canonical YAML) | ~120 lines | **Medium.** Scope to a CLI write or commit, not to a single record (cr excludes multi-record ops). Store `key_hash` and `request_hash` in a commit trailer or ledger provenance. Lookup by scanning `git log` or the `.crm/` index. | ADR-7 `--request-id` and ADR-8 imports |
| **Idempotency verification invariants** | `src/audit.rs`: `verify_idempotency_result` L4424, `register_idempotency_identity` L4501 (one identity per scope, ever) | ~140 lines | High. Tied to cr's journal format, so take the rules, not the code. | `crm check` rule: duplicate request ids, or a request id whose stored result doesn't match |
| **Error taxonomy** | `src/error.rs` (`DomainError`, `code()`, constructors, `DomainError::of` downcast through `anyhow`) and the JSON envelope in `src/main.rs` `print_command_error` L1740 (`usage_error` exit 2, others 1) | ~220 non-test lines | **Low.** Add `file`, `line` and `fix` fields, and pick our code style (`E_BALANCE_MISMATCH` vs snake_case). Drop the HTTP-status rationale. | ADR-7 error contract |
| **Check report types** | `src/check.rs` L84–337: `Severity` (deliberately 2 levels), `FindingKind` with stable `code()`, `Finding` (collection/id/field/target/message), `CheckSummary::fails(threshold)`, `CheckReport` (deterministic order), and `parse_threshold` L1557 (`--fail-on`). The scanner (`run` L350+) is **not** reusable. | ~280 lines | Low to medium. Add `file`, `line` and `fix`, plus ledger kinds (balance mismatch, unknown verb, alias collision, unresolved merge). | `crm check --json` |
| **Collect, don't propagate** | `check.rs` module doc L1–54 and the `scan_record`/`reconcile` structure | pattern | — | `crm check` keeps scanning a damaged vault and is never a repair tool |
| **Agent attribution** | `src/attribution.rs` (depends only on `error`): `AuditAgent` (id, version, model, session, turn, `via` delegation chain), `AuditAuthorization` (mode, grant, approver), `AuditIntent` (request + rationale, each with an author), `AgentEvidence`/`detected_from`, env probes (`CLAUDECODE`, `CURSOR_AGENT`), tolerant-read and strict-write `Other` variants | 1,599 lines incl. tests (~900 logic) | **Medium.** Serialize as git commit trailers instead of journal JSON. **Privacy:** intent and rationale text can contain client names, so encrypt them or keep them out of commits (§4, ADR-7). | ADR-7 "author (human or which agent) and reason" |
| **Safe filesystem walker** | `src/paths.rs` (depends on `error` and `libc`): openat + `O_NOFOLLOW` component walk, `write_new` via `linkat`, `write_replace` via `renameat` and dir fsync, temp-file naming, lock helpers | 1,214 lines | **Low,** close to drop-in. Rename labels. | All vault writes. Cheap defense against symlink tricks from synced or agent-written files. |
| **Crash-safe write protocol** | `audit.rs` pending mutation (`PendingMutation` L816) plus recovery rule "before-hash → discard, after-hash → commit, else stop" (architecture.md § "Audit protocol"); bundle staging plan (bundle.rs, architecture.md § "Bundle writes and recovery") | pattern; ~300 lines entangled | High. Re-implement for our write: ledger append + file write + `git commit`. | Recovery if `crm` dies between the file write and the commit |
| **Folder-record version hash** | `bundle.rs` `record_version` / `cr:bundle:v1\0` manifest (entry hash + sorted `sha256 path` lines) | ~60 lines | Low | `--expected-version` optimistic concurrency over `people/p-…/` (profile + notes) |
| **Domain-separated digests** | `audit.rs` `digest()` L5051, `record_hash` L5047; the rule "hash stored bytes, never a re-serialization" (architecture.md) | ~20 lines | Trivial | Any hash we persist |
| **Test harness ideas** | `tests/common/fault.rs` (deterministic crash injection via a blocked `linkat` target), `tests/audit_corruption.rs`, `tests/idempotency.rs`, `tests/transparent_encryption.rs`, property tests | reference | — | Our crypto, idempotency and crash tests |

**Not worth reusing:** the linear audit chain, anchor and Ed25519 checkpoint (`audit.rs`, `signing.rs`; we use git plus signed commits per ADR-10); `database.rs`; the JSON-Schema-driven field encryption policy and manifest and ownership replay (~900 lines of encryption.rs); `sync.rs` (a Singer-style subprocess adapter framework, which ADR-8 deliberately defers); and everything server, UI or access related.

### License and attribution requirements
- MIT requires keeping the copyright notice and permission notice "in all copies or substantial portions."
- **Copied or adapted code:** keep a header in each borrowed file, e.g. `// Portions adapted from cr (https://github.com/AnandChowdhary/cr) at f29f8d4, MIT License, Copyright (c) 2026 Anand Chowdhary`. Also add `THIRD_PARTY_LICENSES` (or a `NOTICE` section) with the full MIT text.
- **Re-implemented patterns** (no code copied) need no legal attribution. Credit cr in `docs/` anyway.
- MIT is compatible with either outcome of ADR-12 (Apache-2.0 or MIT).

---

## 4. Things in cr that should change our ADRs

1. **ADR-4: age can't bind ciphertext to a record. Use age for wrapping and AEAD with AAD for content.**
   - The prior-art appendix wants to "bind each ciphertext to its record ID and field path (cr)", but the age format has **no associated data**.
   - Recommended decision: each client's DEK is age-encrypted to every recipient in `keys/`. Content files use XChaCha20-Poly1305 under that DEK, with cr-style length-prefixed AAD (vault id ‖ ULID ‖ relative path ‖ purpose ‖ key epoch) and a key id in the envelope.
   - The alternative is to embed `{vault, id, path}` inside the age plaintext and verify it after decrypting. That's weaker and easier to forget.
   - Also adopt cr's **vault context id** (`EncryptionContext`): a random, non-secret id in `crm.toml`, bound into every AAD, so ciphertext can't be swapped between vaults.

2. **ADR-4: authenticate changes to the recipient list.**
   - cr refuses to trust keys found inside the database (signing.rs; `SECURITY.md`: "a key file committed beside the journal can be replaced by whoever can rewrite the journal").
   - The same applies to us. Someone with git write access (Lock 1) could add their own age recipient to `crm.toml` or `keys/`, and the next re-wrap or new client key would be wrapped to them. Revocation by re-wrap has the same hole in reverse.
   - Decision to add: recipient-set changes must be in commits signed by an already-trusted key. `crm` verifies them against a trust anchor **outside the vault** (`~/.config/crm/`, or a pinned first-commit fingerprint) before wrapping anything.

3. **ADR-4 and Appendix A: never write plaintext and then encrypt.**
   - cr refuses in-place encryption of existing plaintext because history would keep it (`migration_required()`, encryption.rs L1183; docs/encryption.md).
   - With git, history is permanent. The Lightfield import (Appendix A, step 1) must write encrypted from the first commit, and the dry run must never commit.
   - State this as a rule: "a vault never contains a plaintext commit of a protected file."

4. **ADR-4 and ADR-3: keep ciphertext when the plaintext hasn't changed.** Adopt cr's rule (`protect` L238–254) at file level. Rewriting a file without changing it must not produce new ciphertext. This keeps diffs and merges sane and avoids false "changed" signals in metadata.

5. **ADR-7: dry-run and confirm can't promise byte-identical ciphertext.**
   - cr found that fresh nonces make "preview digest = applied digest" impossible, and refuses preview approval for new envelopes (database.rs L6533–6579).
   - Our `--dry-run` and confirm-before-write skills should show and bind to the **logical** change (ledger lines, plaintext diff), never to ciphertext bytes.

6. **ADR-7: commit metadata is plaintext and can't be shredded.**
   - cr records actor, message and intent (request and rationale) in plain text in its journal (`AuditPayload` L347, attribution.rs). "One commit per write, with author and reason" would do the same in our git history.
   - Crypto-shredding (ADR-4) can't reach commit messages, trailers, branch names or (if unencrypted) ledger lines.
   - Decision to add: commit messages and trailers carry only opaque IDs, verbs, agent identity and request-id hashes. Free-text reason and intent are stored encrypted under the client's DEK (e.g. a provenance note in the client folder) or omitted.

7. **ADR-7: specify `--request-id` semantics.**
   - cr's design (database.rs L1125–1221, L7336–7378) does three things: it scopes a key to *(principal, operation, record)*, stores only `sha256(domain‖key)` plus an **HMAC keyed by the raw key** over a canonical request (so a stored digest isn't an offline dictionary oracle for low-entropy plaintext), and returns `idempotency_conflict` when a key is reused with different content.
   - We should specify the same, but scoped per write command or commit (imports are multi-record). Store hashes, not the raw id.
   - ADR-8's `src:` provenance stays the content-level dedupe.

8. **ADR-2, ADR-9 and Open Q2: alias arguments are PII.**
   - `2026-10-03 alias p-… email "client@example.com"` in a plaintext ledger puts an email in permanent, unshreddable git history.
   - Following cr's keyed-digest reasoning, a plain hash is no better (it can be dictionary-attacked). Options: encrypt alias payloads, or store `HMAC(vault lookup key, normalized email)` in the ledger for matching, with the real value in the encrypted profile. The lookup key is wrapped to devices like a DEK.
   - Settle this when answering Open Q2.

9. **ADR-2 and ADR-6: don't add a separate audit journal.**
   - cr shows the cost of two sources of truth (files plus a hash-chained journal): v1–v4 payload versions, "legacy representation gaps", `status`/`save` reconciliation, and ownership replay. Its linear chain (global sequence plus a root anchor file) also conflicts on every concurrent write from two clones, which breaks ADR-3.
   - Keep the ledger as the only source of truth for facts, and **git history plus signed commits as the audit log** (ADR-10). If more tamper evidence is wanted later, sign or anchor commits rather than keeping a second chain.

10. **ADR-10: pin trusted signers outside the vault.**
    - "`crm check` can require signatures from known keys": cr's rule is that the known keys must come from outside the vault (`--trusted-key`, `CR_AUDIT_TRUSTED_KEYS`). cr even warns when the key file lives inside the DB.
    - Write that rule into ADR-10 and reuse the same trust anchor as item 2.

11. **ADR-7: error messages can include paths.**
    - cr strips filesystem paths from every caller-facing message (error.rs module doc) because of its HTTP server and because names leak.
    - With no server and opaque ULID paths (ADR-3), paths reveal nothing, so ADR-7's "errors name the file and line" is safe. Keep it.
    - Borrow cr's other rules: classify by typed downcast, never by message text; reserve `internal_error` for unclassified failures; give usage errors their own exit code (2).

12. **ADR-3: enforce the ID grammar in `check`.** cr accepts any path component as an ID and generates none. We should generate ULIDs in the CLI *and* have `crm check` reject non-conforming IDs and non-ID filenames. That mirrors cr's `invalid_record_name` finding (one bad filename is an error everywhere, not silently skipped).

13. **Appendix "Prior art": correct the cr row.**
    - "Record IDs in paths" isn't the difference; we also put IDs in paths. The difference is **caller-chosen slugs** (examples leak names: `priya-shah.md`) versus our opaque ULIDs.
    - Also add: cr refuses encryption for folder records, its audit chain is single-writer, and it doesn't use git for storage.

---

## 5. Open items and caveats
- I didn't build or run tests (rustc 1.85 on the box against MSRV 1.89). Sizes and behavior come from reading the source and docs at `f29f8d4`.
- `TODO.md` lists "per-record data keys, destruction policy" as future work. If cr ships them later, it's worth re-checking whether they could serve as a reference implementation. That wouldn't change the build decision, because the ledger and git-multi-device mismatches remain.
- No repos, PRs or posts were created. Research only.
