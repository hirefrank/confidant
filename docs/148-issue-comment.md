# Decision (reply to the `[crypto].mode` Ask on #148)

> Archived record of the rule-7 decision posted on issue #148:
> <https://github.com/hirefrank/confidant/issues/148#issuecomment-6124891078>

Confirmed on all three asks, with one tightening that makes the declaration
fail-closed by construction. This closes rule-7 review for the opt-out; spec 3
(encrypted writes) can start.

## 1. Shape — confirmed

`[crypto].mode` in `confidant.toml`, string enum `"encrypted"` (default when the
table is absent) | `"plaintext"`. Optional table, old readers ignore it (same as
`[inbox]`). No spec bump for the table itself; `spec/0.1.md` §2 + §14 and
`crypto-design.md` §3 edits ride the same PR as the `writes_encrypted()` flip.

## 2. Writer decision tree — confirmed, restated as structural-first

The declaration is **narrowing-only**: it can *permit* plaintext writes while
the vault is already structurally plaintext, but it can never *downgrade* an
encrypted vault. The real test is always spec §14's structural definition (any
`enc:` envelope or any `keys/recipients.toml` = encrypted vault):

1. Vault structurally **encrypted** → writers encrypt, full stop.
   `mode = "plaintext"` here is `E_CONFIG`, not a downgrade.
2. Vault structurally **plaintext**:
   - `mode = "plaintext"` → writers write plaintext (today's behavior).
   - `mode` absent or `"encrypted"` → writers fail closed with a fix pointing at
     `confidant init` (or `keys init-client <id>` when keyed but the specific
     client is not). No silent plaintext.

## 3. Hard guards — confirmed

- `mode = "plaintext"` + any envelope or manifest → hard `E_CONFIG` on
  write/`init`/`check`. Opt-out is a pre-`init` declaration; an encrypted vault
  can never be opted out later.
- `confidant init` on a vault declaring `mode = "plaintext"` → hard error (remove
  the line, or use a fresh vault). Keys must never coexist with a plaintext
  declaration.
- `mode` set to any other value, or any unknown key inside `[crypto]` →
  `E_CONFIG`.

## 4. Scope correction for spec 3 (⚠3, restated)

The encrypted-write hook goes at the shared record-write layer, so
`record add`, `note add`, and `log session --note` are all covered in one PR —
`log session --note` shares the `FileChange::WriteFile` → `apply_write` path and
must not be deferred (deferring it would leave a plaintext hole after the flip).
Inbox `RecordWrite` (the separate `inbox/merge.rs` path) **fails closed** on an
encrypted vault until its own PR — never writes plaintext, with a guard + test.

`writes_encrypted()` flips only after every record-content path is either wired
or fail-closed and tested, and the disclosure is rewritten in the same PR.

## 5. Who declares `mode = "plaintext"`

`examples/demo-vault/confidant.toml` and the plaintext-write fixtures declare it
(this is what keeps CI keyless and the demo vault clean + plaintext). Keyed tests
keep the throwaway-device-key harness (ADR-14); the opt-out is not a test bypass.
