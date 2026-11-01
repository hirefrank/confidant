# Technical Specification: `confidant-crypt` Removal (Plaintext-Only Confidant) — v2

**Status:** Approved for Execution (revision 2 — no migration)
**Target Repository:** `confidant` (Rust workspace + Python `qmd-search` skill)
**Operator Context:** Single operator, solo maintainer. The existing encrypted vault has **no value to preserve** — it can be rebuilt by hand with `confidant init` after the crypto removal lands. Backward compatibility with encrypted vaults is **not** required.

---

## 0. What changed from v1

1. **Migration deleted.** v1's Phase 1 (`confidant export-plaintext` + parity verification gate) is gone. Its only purpose was to preserve data the operator has now declared rebuildable. No export command, no `enc:`-prefix scan, no "don't delete crypto before exporting" guardrail.
2. **CLI file map corrected.** v1 assumed a `crates/confidant-cli/src/commands/*.rs` module tree. It does not exist. The CLI is a **single-file monolith** `main.rs` (~16,600 lines) plus nine modules. Section 3.4 reflects reality.
3. **Contract sync promoted to a first-class phase.** Removing envelopes is a vault-format *and* privacy-model change. `spec/`, `docs/`, and the root `AGENTS.md` all describe encryption as the contract, and must change in the same PR as the code (repo hard rules 6 and 7). v1 treated this as an afterthought; Section 6 makes it mandatory.
4. **File counts corrected** (`confidant-crypt` has 18 files, not 17; core ledger is one file, not three).

---

## 1. Objective & Architectural Summary

Confidant currently maintains a bespoke per-record encryption subsystem (`crates/confidant-crypt`), OS keychain integration, HMAC alias tables, an encrypted `inbox` fallback queue, and a shadow decryption pipeline (`confidant reindex`) for QMD semantic search.

Because Confidant has a single user whose machines use full-disk encryption (LUKS / FileVault) and who manages their own isolated private Git remote (encrypted at rest by the chosen Git host), we make a clean architectural cut:

1. **Phase 1 — The Great Deletion:** remove `crates/confidant-crypt`, envelope encryption/decryption, OS keychain bindings, HMAC alias hashing, recovery keys, `inbox` key rotation/encryption, and the `RUSTSEC-2026-0387` (`crypto-bigint` via `age`) dependency tree.
2. **Phase 2 — Git-Platform-Agnostic Sync & Doctor:** remove the `E_PLAINTEXT_REMOTE` push refusal so `confidant sync --push` works against any standard Git remote, and strip keychain/disk-encryption ceremony from `doctor`, `init`, and `setup`.
3. **Phase 3 — QMD & Quality-of-Life Cleanup:** simplify `qmd-index.py` / `qmd-query.py` to stage cleared files directly from the plaintext vault via `confidant allowlist --json` (no `confidant reindex`), and fix the bugs found during review.
4. **Contract sync (folded into every phase):** update `spec/`, `docs/`, `README.md`, and the root `AGENTS.md` in the same changes.

**Scope boundary — single-operator.** Multi-operator (a household, peers with their own agents) is explicitly deferred until there is a second human. When it returns, the expected resolution is separate interoperating vaults, not one shared vault. Nothing in this plan assumes multi-operator, and the plaintext decision depends on it staying single-operator.

---

## 2. Core Invariants to Preserve

Even without cryptographic envelopes, these must remain strictly enforced across `confidant-core`, `confidant-cli`, `confidant-tui`, MCP (`mcp.rs`), and `qmd-search`:

1. **`no-ai` Application-Layer Enforcement (§12):**
   - Records with `no-ai: true` are strictly omitted from agent-facing reads (`find`, `context`, `show` without `--for-operator`, `allowlist`, MCP tools, and QMD corpus staging).
   - Records with `no-ai: notes` expose profile/record metadata to agents, but their nested `notes/` and ledger `note` lines stay excluded.
   - Operator-facing surfaces (`confidant tui`, or CLI commands passed `--for-operator`) read all records.
2. **Plaintext Storage Format:**
   - Every `.md` record (`people/`, `orgs/`, `deals/`, `interactions/`, `notes/`, `edges/`) is YAML front matter (`--- … ---`) followed by a UTF-8 Markdown body.
   - Ledger files (`ledger/YYYY/MM.cfd`) remain line-oriented `.cfd` files. `hmac:` lines are deprecated and removed; contact identifiers live directly in `personal@0.2` front-matter fields (`emails`, `phones`, `handles`) or standard `.cfd` verbs.
3. **Git-Platform Agnostic Sync:** zero assumptions about the upstream host. Any standard `origin` remote in `<vault>/.git/config` works with `confidant sync`.
4. **Single-Binary Distribution:** `confidant` stays a self-contained static Rust binary with embedded skills.

---

## 3. Pre-flight (do once, before code)

1. **`crypto-review` issue is #795** (`[crypto-review] Remove confidant-crypt; plaintext-only vaults`), opened and self-approved by the maintainer. Every deletion PR cites it (`Part of #795`), satisfying repo hard rule 6.
2. **Confirm the existing vault is disposable.** Since there is no migration, the encrypted vault (and its `.confidant/keys/`, `.confidant/anchor.json`) can be deleted outright or ignored; a fresh `confidant init` creates the new plaintext vault after Phase 1 lands.

---

## 4. Phase 1 — The Great Deletion

### 4.1 Delete `crates/confidant-crypt` entirely

The directory contains **18 files**, not 17 (v1 missed `README.md`):

```
Cargo.toml  README.md
src/aead.rs  src/age_wrap.rs  src/alias.rs  src/anchor.rs  src/envelope.rs
src/error.rs  src/hex.rs  src/history.rs  src/keychain.rs  src/keys.rs
src/lib.rs  src/lifecycle.rs  src/manifest.rs  src/recovery.rs  src/scope.rs
tests/crypto.rs
```

Delete the directory. Remove `crates/confidant-crypt` from the root `Cargo.toml` `members` **and** `default-members` (it appears in both).

### 4.2 Dependency removal (`Cargo.toml` / `Cargo.lock`)

The crypto surface is spread across three crates and the workspace. Remove:

- **Workspace `[workspace.dependencies]`:** `age`, `chacha20poly1305`, `hkdf`, `hmac`, `keyring`, and (if unused elsewhere) `sha2`, `bip39`, `bech32`, `ed25519-dalek`, `x25519-dalek`, `zeroize`. Keep `hex` only if it survives HMAC removal; keep `rand`/`getrandom` only if still referenced.
- **`confidant-core/Cargo.toml`:** `age`, `confidant-crypt`, `hmac`, `sha2` (as of today `age`, `confidant-crypt`, `hmac`, `sha2` are all declared).
- **`confidant-cli/Cargo.toml`:** `age`, `confidant-crypt` (both declared).
- **`confidant-tui/Cargo.toml`:** `sha2` if its only use was alias/hash display.
- **`.cargo/audit.toml`:** delete the `RUSTSEC-2026-0387` ignore (the whole `[advisories] ignore` list can go — it contains only that one entry) and its rationale comment, since `age`/`crypto-bigint` leave `Cargo.lock`.

**Verification:** `cargo metadata` then `grep -E 'age|crypto-bigint|chacha20poly1305|keyring' Cargo.lock` returns nothing.

### 4.3 Simplify `crates/confidant-core`

**Delete files:**
- `src/crypto_mode.rs`
- `src/inbox/keys.rs`
- `src/inbox/rotate.rs`
- `src/inbox/trust.rs`
- `tests/inbox_rotate.rs`

**Simplify `config.rs`:**
- Remove `CryptoConfig` and the `crypto: CryptoConfig` field (currently lines ~69–103). Remove `crypto_config_problems` integration in the `E_CONFIG` validation (currently `config.rs:428–433`). If an old `confidant.toml` carries a `[crypto]` table, **ignore it silently**.
- Remove `TrustConfig` / `[trust]` only if the inbox is dropped (see §9.1); otherwise keep signing-key config but drop its encryption coupling.

**Simplify `ledger.rs` (single file — v1 wrongly split it into `ledger/{parser,record,index}.rs`):**
- Remove `hmac` verb handling from parsing, indexing, and the `alias` verb grammar. Ignore legacy `hmac:` lines gracefully (treat as unknown/ignored) rather than erroring.

**Update `allowlist.rs`:**
- Keep computing cleared files and cleared `.cfd` line subsets strictly from `no-ai` front-matter flags (`no-ai: true`, `no-ai: notes`). Remove any `skipped_encrypted` / `refused_envelopes` accounting (those are envelope-era concepts).

**`inbox` decision (see §9.1):** strip P-256 / `age` encryption from `item.rs`, `queue.rs`, `merge.rs`, `plan.rs`, `preflight.rs`, or remove the encrypted `inbox` machinery wholesale.

### 4.4 Simplify `crates/confidant-cli` (monolith + modules)

**There is no `commands/` directory.** All commands are `Command` enum variants and handler functions in `main.rs`. The actual module files are:

```
embedded.rs  keys_anchor.rs  mcp.rs  pack_fetch.rs  pack_init.rs
record_crypto.rs  record_decrypt.rs  record_resolve.rs  setup.rs
```

**Delete module files:**
- `keys_anchor.rs`
- `record_crypto.rs`
- `record_decrypt.rs`
- `record_resolve.rs`
- (keep `setup.rs` — it is the `setup` command's skill-extraction logic, but strip its keychain/recovery ceremony per §5)

**Surgical deletions inside `main.rs`** (verify each against the current tree before editing; these are the functions/variants observed today):
- `Command::Reindex` + `cmd_reindex` (at ~`main.rs:3407`) and the `E_REINDEX_REFUSED` path.
- `Command::Keys` + `cmd_keys_rotate` / `cmd_keys_shred` / `cmd_keys_anchor`, and the `keys_*` helpers (`keys_device_identity`, `keys_current_recipients`, `keys_shred_fresh_recipients`, `keys_stage_dir`, `keys_old_dir`, `keys_staged_tracker_path`, `keys_staging_check`).
- The `recover` command and its helpers (`check_recovery`, `recovery_matches_anchor`, `reset_machine_state` / `Command::Reset`).
- `Command::Alias` HMAC machinery and `alias_resolve_error` / `alias_add_warning` / `alias_shared_with_another_person`; rewrite `alias resolve` as a direct case-insensitive lookup against `personal@0.2` front-matter `emails`/`phones`/`handles` + person names, no HMAC hashing.
- Every `confidant_crypt::` and `age::` call site, and every `keys/` directory walk in the write/read paths.

**Update read/write paths (still `main.rs` + `mcp.rs`):**
- Reads parse YAML front matter + Markdown body directly from disk via `confidant-core`.
- Agent-mode reads check `no-ai` on the parsed front matter and refuse (`E_NO_AI` / filtered) exactly as today.
- Writes serialize YAML front matter + body directly to disk with atomic temp-file + rename.
- `--for-operator` (on `find`, `show`, etc.) reads all records directly — it no longer goes through an "operator read path" that decrypts.

**Delete obsolete integration tests in `crates/confidant-cli/tests/`** (verified present):
- `doctor_disk_encryption.rs`
- `doctor_keychain.rs`
- `encrypted_reads.rs`
- `encrypted_writes.rs`
- `init_recover.rs`
- `keys.rs`
- `reindex.rs`
- `reset_machine_state.rs`

**Update remaining tests** (`cli.rs`, `sync.rs`, `doctor_qmd.rs`, `doctor_git_remote.rs`, `doctor_staleness.rs`, `inbox.rs`, `setup.rs`, `writes.rs`, `tui_version.rs`, and the `common/` helpers) to drop `CONFIDANT_KEYCHAIN="memory"` and `[crypto]` stanzas. `sync.rs:415` currently asserts `E_PLAINTEXT_REMOTE` and must flip to assert a successful push.

### 4.5 `confidant-tui`

`crates/confidant-tui/src/app.rs` references `E_PLAINTEXT_REMOTE` (lines ~123, ~820) and may call the decrypt read path. Update to the plaintext read path and drop the encryption-era error branches.

### 4.6 Fuzz workspace

`fuzz/Cargo.toml` declares two targets plus a `confidant-crypt` dependency:
- Delete `fuzz/fuzz_targets/envelope_decode.rs`, `fuzz/corpus/envelope_decode/`, and the `[[bin]] name = "envelope_decode"` block.
- Remove `[dependencies.confidant-crypt]`.
- Keep `ledger_line` (its target depends on `confidant-core`, not crypto).

---

## 5. Phase 2 — Git-Agnostic Sync & Doctor Updates

1. **Remove `E_PLAINTEXT_REMOTE`** (`DomainError::plaintext_remote` in `confidant-core/src/error.rs` + the schema description in `schema.rs` + the check in `main.rs` sync and `tui/app.rs`). `confidant sync` / `sync --push` then work against whatever `origin` is configured.
2. **`confidant doctor`:** drop the keychain check (`keys_staging_check` and friends) and the disk-encryption check. Keep the Git-remote transport check (encrypted transport `https://`/`ssh://`/`git@…`, refuse bare `http://`/`git://`, allow local paths in tests).
3. **`confidant init`:** initialize `people/`, `orgs/`, `deals/`, `interactions/`, `notes/`, `edges/`, `ledger/`; write `confidant.toml` (no `[crypto]`); `git init -b main`; set repo-local fallback identity (`user.name = "Confidant Operator"`, `user.email = "operator@confidant.local"`) in `<vault>/.git/config`. **No keychain or recovery-phrase ceremony.**
4. **`confidant setup`:** strip keychain/recovery prompts; keep skill extraction (still through `embedded.rs`).

---

## 6. Phase 3 — QMD Simplification & Bug Fixes

### 6.1 Bug #1 — Preserve executable bits in `extract_dir` (`embedded.rs`)

`std::fs::write(&dest, f.contents())?` at `embedded.rs:122` writes `0644`, stripping `+x` from `skills/qmd-search/bin/qmd-index.py`, `qmd-query.py`, `qmd-preflight.py`. On `#[cfg(unix)]`, when a path component is `"bin"`, the extension is `.py`/`.sh`, or contents start with `b"#!"`, `set_permissions(dest, from_mode(0o755))`. Add a unit test asserting `qmd-search/bin/qmd-index.py` is `0o755` after extraction.

### 6.2 Bug #2 — Atomic config writes (`qmd-preflight.py`)

`set_qmd_config_value` (line ~387), `remove_qmd_config_value` (~432), `set_vault_qmd_config_value` (~523), and `remove_vault_qmd_config_value` (~575) all use `open(path, "w")` (~427, 466, 560, 605). Replace with a shared helper: `tempfile.NamedTemporaryFile(dir=path.parent, delete=False)` then `os.replace(tmp, path)`. Use it in every config-write site.

### 6.3 Remove disk-encryption gating

`qmd-index.py` gates the corpus on an encrypted disk: `encrypted_disk_detected` (~133, FileVault/`lsblk`), `assume_from_env` (~205), `assume_from_user_config` (~237), `persist_encrypted_disk_assumption` (~262), and the `CONFIDANT_ASSUME_ENCRYPTED_DISK=1` / `[qmd] assume_encrypted_disk` path. Since the vault is now plaintext on disk, delete all of it, plus the `[qmd] assume_encrypted_disk` handling in `qmd-preflight.py` and the user-config key. (This also removes the corresponding CLI `reindex --i-confirm-encrypted-disk` flag, which dies with `reindex` in Phase 1.)

### 6.4 Simplify corpus staging — no `confidant reindex` (`qmd-index.py`)

Replace `run_reindex` (~90) with `stage_cleared_corpus(vault)`:
1. `confidant allowlist --vault <vault> --json` → `{"files": [...], "cfd_lines": {...}}`.
2. Clean `<vault>/.confidant/qmd-corpus/`.
3. For each cleared `.md` file, copy `<vault>/<rel>` → `.confidant/qmd-corpus/<rel>`.
4. For each cleared `.cfd` file, copy only the cleared 1-based line numbers into `.confidant/qmd-corpus/<rel>.md` (preserve the `.cfd.md` suffix QMD expects).

This keeps the `no-ai` boundary intact for BM25/vector indexing with no Rust decryption command.

### 6.5 Bug #3 — Resilient line mapping in `corpus_line_index` (`qmd-query.py`)

`corpus_line_index` (~194) uses `while i < len(vault_lines) and vault_lines[i] != text: i += 1` (~215): one edited/removed `.cfd` line makes the scan run off the end and drop every later line. Build an inverted index `dict[str, deque[int]]` of `vault_lines`, consuming the next line number ≥ the last matched line (exact-match fallback if out of order), so an edit to one line affects only that line.

---

## 7. Contract Sync (mandatory — same PR as the code)

This is not documentation polishing; it is the format/privacy change hard rules 6–7 require. Each item changes in the PR that removes its code:

**`spec/0.1.md`:**
- §2 `confidant.toml`: delete the `[crypto]` table (lines ~80–114), including `mode = "plaintext"`, trust-anchor references, and the `E_CONFIG` clause for unknown crypto keys.
- §5 Ledger grammar + §6 `alias` verb: remove `hmac:HEX` as the alias representation (lines ~306–330); replace with direct `emails`/`phones`/`handles` lookup.
- §12 Search: remove `skipped_encrypted` / `refused_envelopes` semantics (lines ~858–882).
- §13 Privacy: remove encrypted-at-rest / envelope-at-rest claims.
- §14 Encryption (milestone 2): **delete in full** — it spans ~1800 lines (key identifiers, manifests, writer/operator certificates, recovery, envelope, AAD, shred, `keys verify-recovery`). Remove its §13 cross-reference.
- Anywhere "encrypted vault" vs "plaintext vault" is distinguished (lines ~982–991), collapse to a single plaintext vault definition.

**`spec/findings.md`:** remove crypto-only codes — `E_KEY_COMMITMENT`, `E_ENVELOPE`, `E_REINDEX_REFUSED`, `E_PLAINTEXT_REMOTE`, `E_INBOX_CRYPTO`, `E_ALIAS_PLAINTEXT`, `E_ALIAS_COLLISION`, and the encrypted-skip clause of `E_CANNOT_SEARCH` / `E_MERGE_CONFLICT` (they reference envelopes). Re-check `E_CONFIG`'s `[crypto]` clause.

**`docs/`:** delete `docs/crypto-design.md` (wholly obsolete, ~1600 lines). Rewrite `docs/architecture.md` ADR-4 ("Encryption built into the CLI"), ADR-10 ("two locks plus signed commits"), ADR-15 ("Recovery key"), §3 Privacy model, §4 Threat model, and §8b ("encrypted intake / inbox pattern"). Review `docs/privacy.md`, `docs/inbox.md`, `docs/sync.md`, `docs/threat-model-agents.md`, `docs/agent-setup.md`, `docs/agent-workflow.md`, `docs/starting-fresh.md`, and `docs/per-pack-keys-design-note.md` for encryption-era language.

**`README.md`:** remove encryption-at-rest and "not yet independently audited" status language; state plainly that records are plaintext on a FDE disk in a private repo.

**Root `AGENTS.md`:** rewrite hard rules 4 ("never log secrets", crypto half), 6 ("crypto changes need review", obsolete once removed), and the intro line "Client content is meant to be encrypted at rest once milestone 2 lands". Update the repo map's `confidant-crypt` row (delete it), the `crypto-design.md` references, and the "Crypto changes need review first" workflow.

**Agent contract — fold in #797 (legacy `coaching` key).** The legacy top-level `coaching` key in `context`/`resolve` (`main.rs:7511` `bundle.coaching`, `schema.rs:206` `required` key, spec §8 sentence) is removed as part of this same ADR-7 contract bump — it is the same "clean up the agent contract" work and edits the same `schema.rs`. Tracked in #797. The *functional* `session`-verb / `log session` remnants are tracked separately in #799 (their final shape depends on #796).

**`contrib/sync/` templates:** drop `E_PLAINTEXT_REMOTE` and keychain-unlock caveats from `confidant-sync.service` and `com.kitchenrodeo.confidant.sync.plist`.

**CI & QA:** `.github/workflows/ci.yml` — remove `envelope_decode` fuzz steps and `CONFIDANT_KEYCHAIN` env vars; update `scripts/qa/phase0-smoke.sh` and `scripts/qa/qmd-real-binary-smoke.sh` for the plaintext workflow. Regenerate vendored pack skills/manifests with `python3 .github/scripts/sync-packs.py` after any `packs/`/SKILL text changes, and refresh the demo-vault pack pin.

---

## 8. Acceptance Criteria

- [ ] `cargo check --workspace --all-targets` and `cargo clippy --workspace --all-targets -- -D warnings` pass with zero warnings.
- [ ] `crates/confidant-crypt` is gone; `Cargo.lock` contains no `age` or `crypto-bigint`.
- [ ] `cargo test --workspace --all-features --locked` passes 100%.
- [ ] `python3 -m unittest discover -s crates/confidant-cli/skills/qmd-search/tests -p 'test_*.py'` passes 100%.
- [ ] Extracted `qmd-search/bin/*.py` are `0755` after `confidant setup`.
- [ ] `no-ai: true` / `no-ai: notes` records remain excluded from `find`, `context`, `show` (agent mode), `allowlist`, MCP tools, and `qmd-search`.
- [ ] `confidant sync --push` succeeds against any configured `origin` with no `E_PLAINTEXT_REMOTE`.
- [ ] `spec/0.1.md`, `spec/findings.md`, `docs/`, `README.md`, and root `AGENTS.md` contain no encryption-envelope references, and `confidant check --json --no-input --vault examples/demo-vault` is `ok:true`.
- [ ] `crypto-review` issue #795 (from §3) is linked by `Part of #795` on every deletion PR.

---

## 9. Decisions (locked in 2026-10-31)

1. **`inbox` — delete.** The `inbox` branch is *untrusted external intake*: it exists for someone/something **outside** the operator's trust boundary (another person, a service, a web form) to hand over `age`-encrypted items. Multiple AI agents using the vault are **inside** that boundary — they read/write through the normal CLI/MCP path, and `no-ai` (§12) is what governs what they can see. So agent multiplicity does not change this: `confidant inbox` and `E_INBOX_UNTRUSTED` / `E_INBOX_CRYPTO` are deleted. (If a future workflow ever needs an *untrusted* remote agent to hand back data without full vault access, that is a new intake design, not today's decision.)
2. **`alias` — drop the secrecy machinery.** With HMAC gone, `alias resolve` becomes a direct case-insensitive lookup against front-matter `emails`/`phones`/`handles` + names, and the PII-from-stdin / `--value-file` / never-echo protections are removed. Aliases are plain searchable fields.
3. **`reset` / `reset_machine_state` — delete.** It existed only to wipe local key material; there is nothing left to reset.

---

## 10. What comes after this plan

Once crypto removal lands, the next focus is the domain model (#796): a schema that is **truly extensible with packs** — record types become pack-definable and edges generalize to entity↔entity, so `place`/`thing`/`client`/`session` (and the operator's coaching-CRM pack) are first-class entities rather than person-fields in costume. The issues gated on #796 (#737–#742, #749) and the ones it supersedes (#744, #745, #752) all funnel into that work. Sequencing: crypto removal first, then the domain model.
