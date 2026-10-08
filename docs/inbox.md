# Inbox: encrypted intake

> **Needs outside audit before public launch.** The inbox moves
> attacker-influenced bytes (outside tools push to this branch) into the
> vault. The trust checks below are the design; the implementation must be
> audited before the README invites anyone else to trust Confidant with
> client data.

Outside tools (a capture agent, an import script, a second device) deliver new
CRM material to the vault through a git **`inbox` branch**, not a folder.
Each item is an age-encrypted file; `confidant inbox` decrypts the items,
runs `check` on the merged result, merges into the current branch, and clears
the inbox.

Two explicit non-goals:

- **No webhooks for intake.** There is no HTTP endpoint, no listener, and no
  push-triggered automation. Intake is a git push followed by the operator
  running `confidant inbox` on their own machine.
- **No keys in GitHub Actions.** CI never sees a decryption key. The private
  inbox key lives only with the operator (see below); workflows build and
  test the code, nothing more.

## Keypair

The vault has one age X25519 keypair for intake (milestone 2 terminology: the
inbox key). The private half is **never** in git, and it isn't wrapped to the
recovery identity either — that's what keeps it cheap to destroy on rotation
and shred.

1. Generate it on the operator's machine — with milestone 2. M2 generates the
   keypair and stores the private half in the **OS keychain** on the one
   device that runs `confidant inbox`. It is never a file under `~/.config`,
   because Time Machine backs that up and "destroy the old key" would then be
   false. `confidant inbox rotate` rotates it (see the inbox-key section of
   `docs/crypto-design.md`). Until milestone 2 lands there is nothing to
   generate, because decryption is a stub.
2. Publish the public half in the vault's `confidant.toml`:
   ```toml
   [inbox]
   pubkey = "age1..."
   ```
   This committed copy is **informational only** — it tells humans where to
   look, but anyone with git write access can change it, so nothing trusts
   it. The private key **never** goes in the repo, in CI, or in a webhook
   payload.
3. Pin the public key **out of band**, once, everywhere that touches it:
   - In each outside tool's own config (never read from the vault).
   - In your `~/.config/confidant/config.toml`:
     ```toml
     [inbox]
     pubkey = "age1..."
     ```
   `confidant inbox` — and `confidant check` — error with
   `E_INBOX_UNTRUSTED` / `E_INBOX_KEY_MISMATCH` if the vault's
   `[inbox].pubkey` differs from this pin. A mismatch means someone swapped
   the vault's advertised key to receive your future intake: stop and
   investigate, do not merge.

Until milestone 2 lands, `confidant inbox` cannot decrypt anything:
`confidant-crypt` is a stub and every item fails closed with `E_INBOX_CRYPTO`.

## The `inbox` branch

The inbox branch is an **orphan branch** whose root holds only items. Create
it once:

```sh
git checkout --orphan inbox
git rm -rf .
git commit --allow-empty -m "inbox: init"
git push -u origin inbox
```

Each item is `<name>.age` at the branch root. `<name>` is opaque —
`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`, 128 chars max; a ULID is recommended.
Anything that is not a `<name>.age` file at the root is `E_INBOX_ITEM`
(fail closed). The plaintext payload format is:

```text
confidant-inbox/1
kind: ledger            # or: kind: record
path: people/p-…/profile.md   # records only; must stay under
---                            # people/, orgs/, deals/, interactions/, notes/
<content: ledger lines and/or record markdown>
```

The header carries no PII: only the format marker, the kind, and (for
records) the vault-relative target path.

## Dropping an item (outside tools)

The tool pins the vault's inbox public key in **its own config**, set once
by the operator — it never reads the key from the vault (anyone with git
write access could have swapped the `confidant.toml` copy).

```sh
git fetch origin
git checkout inbox
# $INBOX_PUBKEY comes from the tool's own config, pinned out of band.
printf '%s' "$payload" | age -r "$INBOX_PUBKEY" -o 01J....age
git add 01J....age
git commit -S -m "inbox: drop item 01J..."
git push origin inbox
```

Sign the tip commit (`-S`). The merge step verifies the signature of every
commit that adds or changes an item, not just the tip.

## Main-branch protection and trust (ADR-10)

The recovery identity is the trust anchor. On the forge, protect the main
branch so only trusted signers can push (require signed commits; restrict who
may push). Locally, list the signing key IDs you trust in
`~/.config/confidant/config.toml`:

```toml
[trust]
signers = ["<key-id as shown by git log --format=%GK>"]
```

`confidant inbox` requires **every** commit that adds or changes an item to
carry a valid signature from one of these keys, otherwise
`E_INBOX_UNTRUSTED`. Checking only the tip is not enough: an unsigned commit
dropping a malicious item would pass as soon as a trusted signer commits on
top of it. The check traces the provenance of each item file at the tip —
every commit that added, modified, or renamed it, back to its most recent
add — so a forged clear-looking commit cannot truncate the verification
window either. Merge commits are refused outright: the inbox is append-only
and linear, and merge diffs would escape the per-file walk. The `[trust]` table lives in the user config — outside the
vault, never inside it. With no signers configured the run **refuses**
unless `--allow-unsigned` is passed; warn-and-proceed is fail-open and is
gone.

## `confidant inbox`

```sh
confidant inbox [--dry-run] [--json] [--no-input] [--allow-unsigned]
```

The run, in order:

1. The vault must be inside a git repository, on a checked-out branch, with a
   clean tree — otherwise `E_INBOX_DIRTY`.
2. No `inbox` branch → success, nothing to do.
3. The vault's `[inbox].pubkey` must match the pinned key in
   `~/.config/confidant/config.toml` (`E_INBOX_UNTRUSTED` on mismatch).
4. Trust: with no `[trust]` signers configured the run refuses
   (`E_INBOX_UNTRUSTED`) unless `--allow-unsigned` is passed. Otherwise every
   commit that adds or changes an item must carry a valid signature from a
   trusted signer (`E_INBOX_UNTRUSTED`). The inbox branch is append-only and
   linear: any merge commit on it is refused (`E_INBOX_UNTRUSTED`), because
   merge diffs are invisible to the per-file provenance walk.
5. Decrypt and parse every item (`E_INBOX_CRYPTO`, `E_INBOX_ITEM`).
6. Plan the merge. Ledger lines are appended to `ledger/YYYY/MM.cfd` by entry
   date. Intake is limited on purpose:
   - Every ledger line needs a `src:` (provenance and idempotency).
   - The `merge` and `balance` verbs are rejected — identity and balance
     changes come from the operator, never from intake.
   Importing twice adds nothing: lines whose `src:` already exists in the
   vault, exact-duplicate lines, and records identical to the target are
   skipped; a record path that exists with different content is
   `E_INBOX_CONFLICT`.
6. Apply the merge, then run `check` (fail on error). If `check` fails,
   everything is reverted and nothing is committed (`E_INBOX_CHECK_FAILED`).
7. Commit the merge — **one commit per run**, message `inbox: merge N item(s)`
   with only opaque item IDs in the body (ADR-7).
8. Clear the merged items from the inbox branch with their own commit
   (`inbox: clear N item(s)`).

The run is all-or-nothing: any failure leaves both branches untouched.
`--dry-run` decrypts and plans without committing or clearing.
