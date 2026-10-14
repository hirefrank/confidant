# Copy/paste prompt for the #148 implementer (specs 3 & 4)

Paste everything below the `---` into the implementer's context. It assumes the
implementer can read the full issue #148 and the two committed docs on `main`.

---

You are delivering the remaining work for GitHub issue #148 in the Confidant
repo (Rust). READ THE FULL ISSUE FIRST — it is the contract, including all the
decision-bearing spec comments and the `[crypto].mode` opt-out decision.

Only two slices remain (specs 1/2 and #66 device-add are already merged to main):
  * Spec 3 — encrypted writes  (flips `writes_encrypted()` to true)
  * Spec 4 — encrypted reads   (`find`/`context`/MCP decrypt through the CLI)

Authoritative spec (already committed to main — read these before any code):
  docs/148-encrypted-writes-reads-handoff.md   <- behavior bullets map to named
     tests; a bullet with no test does not ship; if the spec line conflicts with
     the code, THE CODE WINS and you report the discrepancy on #148.
  docs/148-issue-comment.md                    <- the opt-out decision.

Deliver as TWO PRs (one topic each), PR 3 then PR 4, branched from main.

Guard rails a weaker agent tends to miss — do not get these wrong:
1. One-line contract: never write plaintext record content into a keyed vault;
   never return "no hits / empty bundle" when the truth is "couldn't decrypt".
2. Encrypt at the SHARED write layer (FileChange::WriteFile -> apply_write) so
   `record add`, `note add`, AND `log session --note` are all covered. Inbox
   `RecordWrite` (separate inbox/merge.rs path) FAILS CLOSED on an encrypted
   vault. Ledger/import/confidant.toml stay plaintext by design.
3. Flip `writes_encrypted()` ONLY after every record-content path is wired or
   fail-closed AND tested, and rewrite the disclosure in the SAME PR (README
   Status, crates/confidant-crypt/README.md, AGENTS.md crypt row).
4. `[crypto].mode` is structural-first / narrowing-only: the plaintext branch
   requires NO `enc:` envelope AND NO `keys/` tree AT ALL (a half-initialized
   `keys/` — e.g. `keys/operator.toml` with no client manifest — is encrypted and
   must not fall into the plaintext branch). `writes_encrypted()` and the
   disclosure are GLOBAL and flip once; `mode = "plaintext"` is a per-vault
   override and never re-flips them. Demo vault + plaintext-write fixtures declare
   `mode = "plaintext"`; keyed tests use a throwaway `CONFIDANT_DEVICE_KEY`
   harness (ADR-14).
5. Read path: core stays KEYLESS via an opaque content hook; the CLI supplies the
   decryptor, `check` supplies none. `no-ai: true` skips WITHOUT decrypting
   (decrypt_record(for_agent=true) enforces it). Add a `skipped_encrypted` count;
   `context <p-id>` unkeyed is a hard error; tamper/corruption is counted, never
   folded into the skip count. Never reimplement the §12 allowlist.

Hard rules (AGENTS.md): fake data only (rule 1); human-only git attribution —
commit as the operator, NEVER add Co-authored-by / Signed-off-by / any AI trailer
(rule 9); every crypto PR body includes "needs outside audit before public
launch".

Verify before pushing (matches CI, run from repo root):
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-features --locked
  cargo run -p confidant-cli --locked -- check --json --no-input --vault examples/demo-vault
  cargo +1.88 check --workspace --locked
The demo vault must stay clean under `confidant check`. CI stays green.

PR body format (AGENTS.md): title, summary, spec changes (or "none"), test
evidence (commands + results), "Decisions I made" (each place the spec was
silent). Post the PR link(s) + decisions summary as a comment on #148. Do NOT
merge — the maintainer merges after review.
