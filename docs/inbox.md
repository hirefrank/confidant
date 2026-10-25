# Inbox: encrypted intake

> **Needs outside audit before public launch.** The inbox moves
> attacker-influenced bytes (outside tools push to this branch) into the
> vault. The trust checks below are the design; the implementation must be
> audited before the README invites anyone else to trust Confidant with
> client data.

Outside tools (a capture agent, an import script, a second device) deliver new
relationship records to the vault through a git **`inbox` branch**, not a folder.
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

1. Generate it on the operator's machine. Milestone 2 stores the private half
   in the **OS keychain** on the one device that runs `confidant inbox`
   (via the keychain module; `CONFIDANT_INBOX_KEY` overrides it on headless
   hosts). It is never a file under `~/.config`, because Time Machine backs
   that up and "destroy the old key" would then be false — a plaintext
   `inbox.key` file is refused outright. Rotation is handled by
   `confidant inbox rotate` / `confidant inbox rotate --finish` (see the
   inbox-key section of `docs/crypto-design.md`).
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

`confidant inbox` decrypts each item with the inbox private key from the OS
keychain (or `CONFIDANT_INBOX_KEY`); anything that fails to decrypt fails
closed with `E_INBOX_CRYPTO`. Before decrypting, it also derives the
recipient from the local private key and compares it against the vault's
`[inbox].pubkey` — a mismatch is a hard `E_INBOX_UNTRUSTED`, so a substituted
vault key is caught even if the out-of-band pin were tampered with.

### Rotation

`confidant inbox rotate` drains the inbox, installs a new keypair, and
updates both pins; `confidant inbox rotate --finish` drains leftovers and
destroys the old private key (crypto-design §8a.3). Note: `--finish` drains
through a normal inbox run, so an item that fails to decrypt under both the
old and new keys blocks it — delete the undecryptable item from the `inbox`
branch directly (check it out, remove the file, commit, push) and re-run
`--finish`.

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

Signature verification reads `git log --format=%G?/%GK`, and SSH signing
landed in git 2.34, so verifying signatures needs **git >= 2.34.0**
when signers are SSH keys (GPG signers work on older git).
`confidant doctor` reports this as the `git-version` check: below the
floor it is an error when signers are configured, a warning when none
are.

## `confidant inbox`

```sh
confidant inbox [--dry-run] [--json] [--no-input] [--allow-unsigned] [--skip <stem>...]
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
5. Pin the inbox tip (resolve its SHA once), then verify signatures,
   decrypt, and parse every item — all against that pinned SHA, never the
   branch name. A push mid-run can't slip unsigned items past the trust
   check or swap the bytes under the reads. The tip is re-verified after
   the reads; any movement refuses (`E_INBOX_RACE`).
6. Plan the merge. Ledger lines are appended to `ledger/YYYY/MM.cfd` by entry
   date. Intake is limited on purpose:
   - Every ledger line needs a `src:` (provenance and idempotency).
   - The `merge` and `balance` verbs are rejected — identity and balance
     changes come from the operator, never from intake.
   Importing twice adds nothing: lines whose `src:` already exists in the
   vault, exact-duplicate lines, and records identical to the target are
   skipped; a record path that exists with different content is
   `E_INBOX_CONFLICT`. On a structurally encrypted vault the drain cannot
   compare an existing envelope to an incoming record (bytes always
   differ), so a record item whose path already exists conflicts — even
   when the envelope holds the same record. Record items into an
   encrypted vault are encrypted at drain time with the vault's device
   key (B11, #213); without a record encryptor the run fails closed
   rather than writing plaintext. The rotate drain passes no encryptor
   (rotation is a keychain operation), so it keeps the fail-closed
   refusal — drain record items with plain `confidant inbox` before
   rotating.
7. Apply the merge, then run `check` (fail on error). If `check` fails,
   everything is reverted and nothing is committed (`E_INBOX_CHECK_FAILED`).
8. Commit the merge — **one commit per run**, message `inbox: merge N item(s)`
   with only opaque item IDs in the body (ADR-7). The commit is signed
   (`-S`, honoring the operator's git signing config); with no commit
   signing configured the run refuses (`E_INBOX_UNTRUSTED`) rather than
   creating unsigned commits (ADR-10: main accepts trusted signers only).
   If the commit itself fails (e.g. a configured-but-broken signing setup),
   the applied paths are unstaged and the worktree reverted — the
   all-or-nothing contract holds.
9. Re-verify the recorded inbox tip immediately before clearing: a push to
   the inbox branch mid-run means the merged bytes may be stale, so the run
   refuses (`E_INBOX_RACE`) instead of clearing content it never saw.
   Clearing uses plumbing only (`mktree` / `commit-tree` / `update-ref`,
   the last as an atomic compare-and-swap on the expected tip) — the inbox
   branch is never checked out in the worktree. The clear commit
   (`inbox: clear N item(s)`) is signed like the merge commit.

The run is all-or-nothing up to the merge commit: any failure before it
leaves both branches untouched. If the merge commit lands and the clear
then refuses — the tip moved (`E_INBOX_RACE`), or the clear commit failed
to sign — main keeps the merge and the inbox keeps its items. Re-running
is safe: already-merged items are skipped as duplicates (idempotent), and
the clear is retried against the new tip. On structurally encrypted
vaults the retry decrypts an existing record envelope and compares
plaintext, so a record item the first run merged is recognized as already
merged rather than conflicting.
`--dry-run` decrypts and plans without committing or clearing.

### Deferring items (`--skip`)

`confidant inbox --skip <stem> [--skip <stem>...]` merges everything
except the named items. A skipped item is **deferred, not discarded**: its
`.age` file stays on the `inbox` branch tip for the next run, which lists
it again. Only the processed stems are cleared — the clear commit message
reflects the partial clear (`inbox: clear N item(s)` counts cleared
items, not the tip size).

- Unknown names fail closed with `E_INBOX_SKIP`: a typo must not silently
  merge the item the operator meant to defer. Pass exact item stems.
- The dry-run report carries deferred items in a separate `skipped[]`
  section (`name`/`kind`/`target`); `items[]` is unchanged. The merge
  commit body gains a sibling `skipped:` section listing the deferred
  opaque IDs (ADR-7) — an audit trail of what was intentionally left
  behind, with no PII in git.
- `--skip` is **refused during `inbox rotate`** (both the drain and
  `--finish`): leftovers encrypted to the old key must not survive the
  rotation (§8a.3), or they fail closed with `E_INBOX_CRYPTO` once the old
  private key is destroyed. Finish or drop undecryptable/old-key items
  before rotating — don't use `--skip` to paper over a rotation window.

### Discarding items (`--discard`)

`confidant inbox --discard <stem> [--discard <stem>...]` removes the named
items from the `inbox` branch **without merging them**, in exactly one
signed commit (`inbox: discard N item(s)`). Use it for an item the operator
chose not to apply — e.g. after `record resolve <id> --from-inbox <stem>
--take ours`, where the item would otherwise conflict forever. Unlike
`--skip` (defer), `--discard` is permanent: the item leaves the branch.

- Only stems currently on the `inbox` branch tip are accepted; unknown
  names fail closed with `E_INBOX_SKIP`, like `--skip`.
- The tip is pinned before the read and re-verified before the commit; a
  moved tip refuses with `E_INBOX_RACE`.
- Without commit signing configured the command refuses with
  `E_INBOX_UNTRUSTED` (an unsigned discard commit would never pass the
  drain's trust check).
- Plumbing only (`mktree` / `commit-tree` / `update-ref`): the inbox branch
  is never checked out and the main worktree is never touched.
- `--discard` does not combine with the drain flags or `inbox rotate`.

### Resolving an `E_INBOX_CONFLICT`

When the drain refuses with `E_INBOX_CONFLICT` — an item targets a record
path that already exists with different content — resolve it explicitly:

```sh
confidant record resolve <id> --from-inbox <stem> --show   # compare both versions
confidant record resolve <id> --from-inbox <stem> --take theirs   # apply the item
confidant record resolve <id> --from-inbox <stem> --take ours     # keep the record
confidant inbox --discard <stem>   # retire the item afterwards
```

`--take theirs` encrypts the item's plaintext through the `record edit`
path and stages it; the next `confidant inbox` run recognizes it as merged
and clears it. `--take ours` leaves the record untouched — follow it with
`inbox --discard <stem>` so the item stops conflicting. `--merged-file`
and `--edit` work as with git-conflict resolution.

The write actions (`--take`, `--merged-file`, `--edit`) run the drain's
signed-tip trust check on the inbox branch: with `[trust]` signers
configured it refuses an unsigned or untrusted tip with
`E_INBOX_UNTRUSTED`, and it refuses with `E_INBOX_RACE` if the branch
moves between the item being read and the write. `--allow-unsigned` is the
same escape hatch as `inbox --allow-unsigned` (and prints the same
warning). `--show` is read-only and does not run the check.

## Fallback queue (`log session --note --fallback-inbox`, #213)

When the keychain is unavailable, `log session --note` cannot encrypt
the note — but it can queue the session instead of failing closed. With
`--fallback-inbox` (or an interactive `y` at the prompt; `--no-input`
and `--json` fail closed with a fix pointing at the flag), the command
queues two items to the `inbox` branch and prints `queued to inbox; run
confidant inbox when the keychain is back`:

- a ledger item: the session line plus a `src:fallback/<ulid>`
  provenance token (in addition to any operator `--src`);
- a record item: the note record, with the exact bytes a normal write
  would have produced, so the drained result matches a normal write.

Both items are age-encrypted to the vault's inbox pubkey and committed
with one signed commit (`inbox: queue 2 item(s)`), via plumbing only —
the `inbox` branch is never checked out and nothing is written to main,
so no plaintext ever lands on the main branch. The queue refuses when
the vault's `[inbox].pubkey` does not match the operator's pin in
`~/.config/confidant/config.toml` (`E_INBOX_UNTRUSTED` — stricter than
the drain, which only warns on a missing pin), when commit signing is
not configured, or when a stem already exists on the branch. The next
`confidant inbox` run merges the queued items like any other intake.

Edge case: if the session was logged with `--src X` and the vault
already contains `src:X`, the drain skips the fallback ledger line as a
duplicate while still merging the note record — the note then has no
session line pointing at it.

Semantic duplicates (#747) are different from that `src:` case: a
queued line whose touch/session identity already exists in the ledger
is skipped at drain, and the drain report names the drop per item
(`semantic_skipped` in `--json`, a `(N semantic duplicate line(s)
dropped)` note in text output). A deliberately repeated line is not
dropped: `log --force --fallback-inbox` marks its ledger item with a
`force: true` header so a plain drain processes it, and `confidant
inbox --force` processes unmarked duplicates (never during a rotate
drain). Neither escape bypasses `src:`/exact-text idempotency.
