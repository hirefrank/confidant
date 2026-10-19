# Starting fresh, and adopting Confidant in stages

Two operator jobs that are easy to get wrong:

- **Starting fresh:** replacing or wiping a vault without leaving the old
  vault's trust anchor, keys, or config entries behind.
- **Adopting in stages:** using one vault for personal relationships first,
  then adding coaching clients later.

Confidant's data lives in a vault you can copy or delete. The *machine* also
remembers things outside the vault, and those are what usually break a reset.
This page lists that state, gives a safe order to clear it, and ends with a
checklist you can run against the new vault.

The CLI commands below were exercised on throwaway vaults with an isolated
`HOME` and a throwaway keychain backend. `confidant reset --machine-state`
is the supported way to clear the machine state described here; the
`secret-tool` / `security` commands are the fallback when the command cannot
reach a platform keychain (or when you want to inspect one entry by hand).
Those platform commands were not run against a real keychain.

## 1. What "starting fresh" actually resets

### The vault is self-contained

Everything a vault needs to be read and written is inside the vault directory:

| Path | What it holds |
|---|---|
| `confidant.toml` | `spec`, `packs`, `vault_id`, optional `[inbox]` and `[crypto]` |
| `ledger/YYYY/MM.cfd` | dated ledger lines (structural, plaintext) |
| `people/`, `orgs/`, `deals/`, `interactions/`, `notes/` | records; encrypted bodies on an encrypted vault |
| `keys/` | wrapped per-client data keys, vault lookup key, operator certificate |
| `confidant.lock`, `packs/<name>@<version>/` | vendored external packs and their pins |
| `.confidant/` | local index/cache, gitignored, rebuildable |

Deleting the vault deletes `keys/`. **The old recovery phrase on its own
cannot restore a deleted vault.** `confidant recover` works from a vault
checkout: it verifies the operator certificate (or the local trust anchor)
against the phrase-derived recovery key, then unwraps each client data key
from `keys/<client>/wrapped/recovery.age` and re-wraps it to a fresh device
key. With `keys/` gone there is nothing to unwrap and no certificate to
verify
(verified: `recover` exits 1 on a checkout whose `keys/` tree was removed).
If you want the old data back later, keep the whole vault, including
`keys/`, and the phrase.

Deleting the vault is also **not** a crypto-shred. Old ciphertext, old
wrapped keys, git history, and any clone or backup can still be opened by a
device key or recovery phrase that still exists. For per-client destruction,
see [`docs/crypto-design.md`](crypto-design.md) §8 (`keys shred`); for the
abandoned-vault case, destroy the old key material as described below.

### The machine remembers more than the vault

| State | Where | What breaks if you forget it | How to clear it |
|---|---|---|---|
| Trust anchor | `~/.config/confidant/trust.toml` | `init --create` refuses with `trust anchor already exists ... pass --force`. A stale anchor makes the new vault's manifests fail verification (`signature does not verify`) and records fail to decrypt. | `confidant reset --machine-state`. Manual fallback: archive or remove the file, or use `init --force` on a vault that has no `keys/` yet. |
| Default vault | `~/.config/confidant/config.toml` `default_vault` | Points discovery at the old vault. If the path is gone, `E_VAULT_NOT_FOUND`; if it still exists, commands silently operate on the old vault. | `confidant reset --machine-state` removes the key and keeps unrelated ones. Manual fallback: edit the file. |
| Named vaults | `config.toml` `[vaults]` | `CONFIDANT_VAULT=<name>` keeps resolving to the old vault. | `confidant reset --machine-state`. Manual fallback: edit the file. |
| Inbox signers | `config.toml` `[trust].signers` | Stale key IDs are the only signers trusted for `inbox` commits; the new vault's commits won't verify, so `inbox` refuses (or needs `--allow-unsigned`). | `confidant reset --machine-state`. Manual fallback: remove or replace the entries. |
| Inbox pin | `config.toml` `[inbox].pubkey` | This is one global pin, not per vault. Once the new vault advertises a different inbox key, `check` reports `E_INBOX_KEY_MISMATCH` and `inbox` refuses. | `confidant reset --machine-state`. Manual fallback: clear it, or re-pin after `inbox rotate` (which updates it for you). |
| Shell/agent env | `CONFIDANT_VAULT` | It wins over `default_vault` and directory walk-up, so a stale export keeps every command on the old vault. | `unset CONFIDANT_VAULT`, and remove it from your shell rc and agent runtime. `reset` does not change your shell. |
| Manifest high-water marks | `~/.config/confidant/manifest-seq.toml` | Rows are keyed by `vault_id`. A new vault has a new id, so old rows are inert; they are not a reason `init` fails. | `confidant reset --machine-state` (optional: keeping the file is harmless). Manual fallback: delete it. |
| Pending inbox rotation | `~/.config/confidant/inbox-rotation-pending.toml` | `doctor` keeps warning after a shred on a non-inbox device. | `confidant reset --machine-state`. To clear only this file with a resolvable vault: `confidant doctor --clear-pending-inbox-rotation` |
| Device key | keychain service `confidant`, account `device-key` | `init` overwrites it with the new vault's device key. If you never run `init`, the old key still opens the old vault. | `confidant reset --machine-state`. Manual fallback: `secret-tool` (Linux) or `security` (macOS), below. |
| Operator key | keychain service `confidant`, account `operator-key` | Same as the device key: `init` overwrites it; otherwise it still signs for the old vault. | `confidant reset --machine-state`. Manual fallback: same platform tools. |
| Inbox keys | keychain service `confidant-inbox`, accounts `inbox-key` and `inbox-key-previous` | `init` does **not** touch these. A new vault's first `inbox rotate` adopts the old key as current, then moves it to the previous slot; items from the old vault stay decryptable until `--finish`. | `confidant reset --machine-state`. Clear before `init` if you are retiring the old vault. Manual fallback: same platform tools. |
| Legacy plaintext keys | `~/.config/confidant/device.key`, `inbox.key` | Any key load fails closed: `refusing to load ... legacy plaintext key file exists`. | Import into the keychain, then remove the file. |
| Skills | `~/.local/share/confidant`, agent skill dirs | Nothing vault-specific; links are versioned to the CLI. | Leave them. `confidant setup` refreshes links. |
| Git remotes / clones | the vault's `.git`, plus other checkouts | Deleting the local directory does not delete pushed history or other clones. A former plaintext vault may hold real data in history. | See §2.2. |

### Clearing keychain entries

`confidant reset --machine-state` removes all four keychain entries together
with the files and config entries above. Preview it first:

```sh
confidant reset --machine-state --dry-run
confidant reset --machine-state --yes
```

`--dry-run` prints exactly what would go (files, config keys and keychain
service/account pairs) and changes nothing. `--yes` is required with
`--no-input` or `--json`; without it the command asks before removing
anything. If nothing is present it skips the prompt and reports
`nothing to remove`. It refuses while **any** resolvable vault has a `keys/`
tree, because removing the anchor and keys would break that vault. The guard
checks `--vault`, `CONFIDANT_VAULT` (a path or a `[vaults]` name), a walk-up
from the current directory, `default_vault`, and every `[vaults]` entry —
even when normal discovery would fail — and names every initialized vault in
the error. `--force` overrides the guard for vaults you have retired. It
never writes inside a vault, and a second run reports `nothing to remove` and
exits 0. With `--json`, `vault` is `null` and `scope` is `machine-state`:
this command is not vault-scoped.

If the OS keychain is unreachable, the command fails before removing any
files (so a retry can finish) and points at the platform fallback below.

The platform commands below are the fallback, for example when the command
cannot reach a keychain or you want to remove one entry by hand.

On Linux with the Secret Service (`secret-tool`), the `keyring` crate stores
the service and account as the `service` and `username` attributes — use
`username`, not `account`:

```sh
secret-tool clear service confidant username device-key
secret-tool clear service confidant username operator-key
secret-tool clear service confidant-inbox username inbox-key
secret-tool clear service confidant-inbox username inbox-key-previous
```

To check whether an entry exists without printing the secret:

```sh
secret-tool lookup service confidant username device-key >/dev/null \
  && echo "device key present"
```

On macOS:

```sh
security delete-generic-password -s confidant -a device-key
security delete-generic-password -s confidant -a operator-key
security delete-generic-password -s confidant-inbox -a inbox-key
security delete-generic-password -s confidant-inbox -a inbox-key-previous
```

`security` exits non-zero when the entry is absent; that is not an error for
this cleanup.

Do **not** set `CONFIDANT_KEYCHAIN=off` in normal use. It is a test-only
switch: reads skip the keychain and writes refuse, so it cannot be used to
"clear" anything.

## 2. The safe sequence

### 2.1 Decide what happens to the old vault

Keep it recoverable:

```sh
mv ~/vault ~/vault-retired-2026-10-19
```

or retire it:

```sh
rm -rf ~/vault
```

Check the path before running `rm -rf`; there is no undo. If you keep the
archive, also keep its `keys/` and the matching recovery phrase, or the
archive is unreadable later. If you are retiring it, the old device key,
operator key, inbox key, and phrase are still secrets that can open old
copies — clear the keys in §2.3.

Clearing the keychain does not revoke the recovery phrase. If the old
vault's ciphertext still exists anywhere (remote, clone, backup), anyone
holding the phrase can open it. To retire the data fully, delete every copy
and destroy the phrase's paper/password-manager copies; otherwise treat the
old data as still readable by those secrets.

### 2.2 Handle the git remote and other clones

A local delete does not touch the remote:

```sh
git -C ~/vault remote -v
git -C ~/vault log --oneline -5
```

- If the old history should not survive, archive or delete the remote
  repository, or create a new empty remote for the new vault. Do not push the
  new vault's history on top of the old one.
- `git push --force` rewrites a branch, not every ref, tag, fork, clone, or
  backup. Treat it as destructive and coordinate with anyone else who has a
  clone.
- A former **plaintext** vault (`[crypto] mode = "plaintext"`) may contain
  real record bodies in that history. Deleting the local directory does not
  remove them from the remote.
- `confidant init --create` runs `git init` and does **not** add a remote.
  `git remote -v` on the new vault should be empty until you add the one you
  intend.

### 2.3 Clear or overwrite the machine state

Preferred, for a genuinely fresh start: run one command from **outside** the
old vault. It removes the trust anchor, manifest high-water marks, the
pending-rotation reminder, the four config entries, and the device, operator
and inbox keys:

```sh
unset CONFIDANT_VAULT                 # a stale export wins over everything else
confidant reset --machine-state --dry-run   # list exactly what would go
confidant reset --machine-state --yes       # remove it (skips the prompt)
```

It preserves unrelated keys, comments and formatting in `config.toml`, never
writes inside a vault, and running it twice is safe (the second run, or a
dry-run after the first, reports `nothing to remove: machine state is already
clear`). It **refuses** if **any** resolvable vault has a `keys/` tree,
because removing the anchor and keys would break that vault. The guard checks
`--vault`, `CONFIDANT_VAULT` (a path or a `[vaults]` name), a walk-up from the
current directory, `default_vault`, and every `[vaults]` entry — even when
normal discovery would fail — and names every initialized vault in the error.
That is the intended protection for "I forgot the old vault still exists".
Move or delete the old vault first (§2.1), or pass `--force` only after you
have retired them. `--json` reports `"vault": null`, `"scope":
"machine-state"`, and the full candidate list (including candidates with no
`keys/`) under `vault_guard`.

If you keep the old vault recoverable, do not run the full reset: it archives
nothing. Use the manual fallback below instead, which keeps old files.

Manual fallback (also useful when the command cannot reach a keychain):

```sh
# Archive the old anchor rather than deleting it if you may want the old vault back.
mv ~/.config/confidant/trust.toml ~/.config/confidant/trust.toml.old

# Keep only the new default (or delete the file and rely on --vault / CONFIDANT_VAULT).
cat > ~/.config/confidant/config.toml <<'EOF'
default_vault = "~/vault"
EOF

unset CONFIDANT_VAULT
```

If you used the manual fallback and a `keys shred` on a non-inbox device left
a pending-rotation reminder, clear it after §2.4 (it needs a resolvable
vault):

```sh
confidant doctor --clear-pending-inbox-rotation
```

With the manual fallback, also clear the old keychain entries if you are
retiring the old vault (see
[Clearing keychain entries](#clearing-keychain-entries)). If you are only
replacing a vault on the same machine, `init` overwrites `device-key` and
`operator-key` for you; clearing them first is still the cleaner choice. The
inbox entries are never overwritten by `init`, so clear those when the old
vault is gone.

`manifest-seq.toml` can stay — its rows are keyed by the old `vault_id`, and
the new vault gets a new id and its own rows. `confidant reset
--machine-state` removes it anyway; that is harmless.

### 2.4 Create the new vault

`--create` only scaffolds an absent or empty directory (a directory holding
just `.git` and/or `.gitignore` also counts as empty). A non-empty directory
is refused so a stray `--create` cannot turn a project checkout into a vault.

```sh
export CONFIDANT_VAULT="$HOME/vault"
confidant init --create --no-input
```

Before this, make sure git has an identity (`git config --global user.name`
and `user.email`); the skeleton commit needs one. The command:

1. creates the directory and runs `git init` when needed;
2. writes `.gitignore` with `.confidant/` and a minimal `confidant.toml`
   with a fresh `vault_id`, and commits the skeleton;
3. generates the operator key, a 24-word recovery phrase (shown once on
   stderr), and this device's key;
4. creates the vault lookup key, the `vault:shared` client, and the signed
   operator certificate under `keys/`, then commits the `keys/` tree;
5. writes `~/.config/confidant/trust.toml` only after every key step
   succeeds.

It does **not** create an inbox key or install any pack. With `--no-input`
the phrase is printed without the "have you written it down?" confirmation —
store it offline (paper and a password manager, not a synced file in the
vault) before continuing.

A new vault starts with `packs = []`. That is fine: `personal@0.2` is
implicit and already enabled (§3.1).

### 2.5 The `init --force` case

`--force` means "an anchor already exists; replace it after the new
initialization succeeds". It is **not** a reset.

| Situation | What `--force` does |
|---|---|
| `trust.toml` exists, new/empty directory | Replaces the anchor once the new vault's key steps succeed. Verified. Useful when you deleted an old vault but left its anchor behind. |
| `trust.toml` exists, directory already has `keys/` | Fails with `manifest verification failed: client vault:shared already initialized; use rotate`, and (verified) leaves `keys/vault/lookup.age`, `recipients.sig`, and `recipients.toml` modified. Do not use it here; archive/delete the vault and start in a fresh directory. |
| No `trust.toml` | `--force` has no effect; a normal `init` runs. |

What it overwrites on success: the trust anchor, the device key and operator
key in the keychain, and the new vault's `keys/` tree. It never merges old
records or old client keys.

Tracked defect from verification:
[#640](https://github.com/hirefrank/confidant/issues/640) (`--force` dirties
`keys/vault` before failing). The machine-state gap is covered by
`confidant reset --machine-state` (§2.3, [#638](https://github.com/hirefrank/confidant/issues/638)).

### 2.6 When keychain entries matter

- After `init`, this device is enrolled: `doctor` reports `device key is in
  the OS keychain`.
- On a **new device** for an existing vault, the command is
  `confidant recover`, not `init`. `recover` requires a fresh device (no
  device key enrolled) and does not restore the inbox key or the lookup key
  (see [`docs/crypto-design.md`](crypto-design.md) §9 and §8a).
- If `doctor` says `not enrolled`, either run `init` (new vault) or
  `recover` (existing vault), or, on a headless host with no Secret Service,
  provide `CONFIDANT_DEVICE_KEY` (and `CONFIDANT_INBOX_KEY` if you run
  `inbox`) from the host's secret store.
- Re-enrollment is not `init`: running `init` again creates a new vault's
  keys rather than recovering the old ones.

## 3. Adopting in stages: personal first, coaching later

### 3.1 Start with the personal pack (nothing to install)

`personal@0.2` is built into the binary and **implicit**: every vault has it,
whether or not `packs` lists it. `packs = []` still enables it, and a
`personal@…` entry is a no-op.

That gives you birthdays, relationship edges, keep-in-touch cadence, upcoming
dates, and the `touch` ledger verb:

```sh
confidant record add --file ada.md --no-input
confidant log touch "Ada Example" call --date 2026-10-19
confidant context "Ada Example"
```

Quote display names with spaces. A `no-ai: true` person is addressed by
`p-<ULID>` only.

### 3.2 Add coaching later

When you are ready, install the external coaching pack into the same vault:

```sh
confidant pack add https://github.com/hirefrank/confidant.git \
  --subdir packs/coaching --yes
```

Verified effects:

- vendors `packs/coaching@0.1/` (manifest, `SKILL.md`, `0.1.md`) into the
  vault;
- writes `confidant.lock` with the pack hash;
- sets `packs = ["coaching@0.1"]` in `confidant.toml`;
- commits those files in one commit.

It does **not** touch records, client keys, or the trust anchor. `check`
starts applying coaching rules (sessions, packages, balances, gap rules), and
coaching verbs such as `log session` become valid. Existing personal records
stay where they are; there is no migration.

Do not try to seed coaching at `init` time with `--packs coaching@0.1`.
`init` only seeds packs built into the binary (today the implicit
`personal@0.2`); naming an external pack is a usage error (exit 2) with a fix
telling you to install it after init ([#639](https://github.com/hirefrank/confidant/issues/639)).
Init with no packs, then `pack add`.

To undo the change, `confidant pack remove coaching --yes` removes the
vendored files, the lock entry, and the `packs` listing. Data written under
coaching verbs then becomes `W_PACK_ORPHAN` warnings, not errors; the
personal pack is never orphaned. `confidant pack list` and
`confidant pack verify` show what is installed and whether the hash still
matches.

### 3.3 The honest caveat: pack scope is policy, not a key boundary

`--packs` (and `confidant mcp --packs …`) is a **read-time policy filter**:
out-of-scope records, fields, and ledger lines are omitted from `context`,
`find`, `record list`, `allowlist`, and MCP results. (`allowlist` also
annotates each entry with its `owning_packs` so an indexer can filter; the
QMD index itself is unscoped and `find` is the enforcement point for
queries.) That is useful against an agent over-reaching through the tool
surface.

It is **not** an encryption or access boundary yet. Every client still holds
the same recipient set, so a coaching-scoped agent that can read the vault
files directly, or run the CLI unscoped, can see the personal records too.
The crypto layer (per-client recipient sets) is future work:
[#160](https://github.com/hirefrank/confidant/issues/160). The policy layer
landed under [#178](https://github.com/hirefrank/confidant/issues/178).

If coaching/personal isolation must be a real boundary today, use **separate
vaults** (separate keys, separate git histories) rather than one vault with
two packs. `no-ai` hides content from agent-facing reads, but it is also not
a boundary against a process that can read the files.

## 4. Verification checklist

Run these against the new vault. Set the paths explicitly so the checks
cannot silently resolve to the old vault (replace the two paths first).

```sh
NEW_VAULT="$HOME/vault"
OLD_VAULT="$HOME/vault-old"      # the retired/removed path
export CONFIDANT_VAULT="$NEW_VAULT"

confidant doctor
confidant check --json --no-input
```

Expected: `doctor` exits 0 with `vault resolved to .../vault` and a `device-key`
check that is `ok`; `check` returns `"ok": true`. On a brand-new vault the
summary is zero records and zero ledger entries. To make the check
meaningful, add one fake person and one touch first, then re-run.

Confirm the new vault is self-contained and does not point at the old one:

```sh
git -C "$NEW_VAULT" remote -v
# empty, or exactly the new remote you intended

git -C "$NEW_VAULT" log --oneline -3
# only commits made in the new vault; no old-vault history

grep -R "$OLD_VAULT" "$HOME/.config/confidant" 2>/dev/null \
  || echo "no old vault path in config"

printf '%s\n' "${CONFIDANT_VAULT:-}"   # the new path, not the old one

ls "$OLD_VAULT" 2>/dev/null || echo "old vault path is gone"
```

If you deleted the old vault, its path should now fail clearly rather than
resolve somewhere else:

```sh
confidant --vault "$OLD_VAULT" check --json --no-input
# expected: E_VAULT_NOT_FOUND, exit 1
```

If you cleared the old inbox key, confirm it is gone (without printing it):

```sh
secret-tool lookup service confidant-inbox username inbox-key >/dev/null \
  && echo "inbox key still present" \
  || echo "no inbox key in the keychain"
```

On macOS the equivalent check is
`security find-generic-password -s confidant-inbox -a inbox-key >/dev/null`.

Finally, if you added coaching, confirm the pack is installed and pinned:

```sh
confidant pack list
confidant pack verify
confidant check --json --no-input
```

`pack list` should show `coaching 0.1` with `status: ok`; `pack verify`
should exit 0; `check` should still be `"ok": true`.
