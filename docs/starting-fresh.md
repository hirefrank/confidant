# Starting fresh, and adopting Confidant in stages

Two operator jobs that are easy to get wrong:

- **Starting fresh:** replacing or wiping a vault without leaving config
  entries behind that point at the old one.
- **Adopting in stages:** using one vault for personal relationships first,
  then adding packs later.

Confidant's data lives in a vault you can copy or delete. The *machine* also
remembers a little state outside the vault, and that is what usually breaks a
reset. This page lists that state, gives a safe order to clear it, and ends
with a checklist you can run against the new vault.

Since #795 that machine state is small. A vault holds no key material, there
is no trust anchor, no OS credential store to clear, and no `confidant reset`
command: the machine-side state is a config file that can point at an old
vault, a shell export that overrides discovery, and git remotes and clones.

## 1. What "starting fresh" actually resets

### The vault is self-contained

Everything a vault needs to be read and written is inside the vault directory:

| Path | What it holds |
|---|---|
| `confidant.toml` | `spec`, `packs`, `vault_id` |
| `ledger/YYYY/MM.cfd` | dated ledger lines |
| `people/`, `orgs/`, `deals/`, `interactions/`, `notes/`, `edges/` | records; YAML front matter plus a Markdown body |
| `confidant.lock`, `packs/<name>@<version>/` | vendored packs and their pins |
| `.confidant/` | local index/cache, gitignored, rebuildable |

A copy of the directory is the whole vault. Keep a clone (or the remote) and
you keep everything needed to read it later: there is no separate key,
phrase, or enrollment step. Deleting the vault deletes the working copy;
pushed history and other clones are separate copies (ADR-5).

### The machine remembers more than the vault

| State | Where | What breaks if you forget it | How to clear it |
|---|---|---|---|
| Default vault | `~/.config/confidant/config.toml` `default_vault` | Points discovery at the old vault. If the path is gone, `E_VAULT_NOT_FOUND`; if it still exists, commands silently operate on the old vault. | Edit the file (below). |
| Named vaults | `config.toml` `[vaults]` | `CONFIDANT_VAULT=<name>` keeps resolving to the old vault. | Edit the file. |
| Shell/agent env | `CONFIDANT_VAULT` | It wins over `default_vault` and directory walk-up, so a stale export keeps every command on the old vault. | `unset CONFIDANT_VAULT`, and remove it from your shell rc and agent runtime. |
| Skills | `~/.local/share/confidant`, agent skill dirs | Nothing vault-specific; links are versioned to the CLI. | Leave them. `confidant setup` refreshes links. |
| Git remotes / clones | the vault's `.git`, plus other checkouts | Deleting the local directory does not delete pushed history or other clones. | See §2.2. |

`~/.config/confidant/config.toml` holds only `default_vault` and `[vaults]`.
A file left over from an older version may still carry unrelated sections;
they are ignored, but rewriting the file is the fastest way to be sure
nothing stale is in it:

```toml
default_vault = "~/vault"

[vaults]
work = "~/vaults/work"
```

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

Check the path before running `rm -rf`; there is no undo. An archived vault
is still readable by anyone who can read the directory, because there is no
second lock inside it (ADR-4). If that matters, move it to a full-disk
encrypted volume or delete it.

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
- The history holds whatever the old vault held, unless the vault was always
  the demo/fake data. Deleting the local directory does not remove it from
  the remote.
- `confidant init --create` runs `git init` with branch `main`. Without
  `--remote` it adds no remote; with `--remote <url>` it sets `origin` and
  still does not push. `git remote -v` on the new vault should show only
  the origin you intended. Local-only is a valid choice, but there is no
  backup and a second device cannot clone what was never pushed. For backup
  and a second device:

  ```sh
  confidant init --create --remote <url> --no-input
  git push -u origin main
  # or, after init without --remote:
  git remote add origin <url>
  git push -u origin main
  ```

  The URL is provider-neutral. `init --create --remote` is the one
  Confidant command that adds `origin`; nothing pushes for you. `doctor`'s
  `git-remote` check accepts local-only and warns on a cleartext or
  unverifiable transport. On another device, clone and use it: there is no
  enrollment step.

### 2.3 Clear or overwrite the config

Rewrite `~/.config/confidant/config.toml` (or delete it and rely on
`--vault` / `CONFIDANT_VAULT`):

```sh
unset CONFIDANT_VAULT                 # a stale export wins over everything else
cat > ~/.config/confidant/config.toml <<'EOF'
default_vault = "~/vault"
EOF
```

That keeps nothing about the old vault. If you want the old file for
reference, move it aside first (`mv config.toml config.toml.old`).

### 2.4 Create the new vault

`--create` only scaffolds an absent or empty directory (a directory holding
just `.git` and/or `.gitignore` also counts as empty). A non-empty directory
is refused so a stray `--create` cannot turn a project checkout into a vault.

```sh
export CONFIDANT_VAULT="$HOME/vault"
confidant init --create --no-input
```

Before this, make sure git has an identity (`git config --global user.name`
and `user.email`); the skeleton commit needs one. When git has no identity
at all, `init` sets a repo-local fallback so the commit works. The command:

1. creates the directory and runs `git init` with branch `main` (no manual
   `master` → `main` rename), then reports the branch it created;
2. writes `.gitignore` with `.confidant/` and a minimal `confidant.toml`
   with a fresh `vault_id` and `packs = []`, creates the collection
   directories, and commits the skeleton;
3. adds `origin` only if `--remote <url>` was passed, and never pushes.

There is no key, phrase, or enrollment step, and it installs no pack. A
new vault starts with `packs = []`, which is fine: `personal@0.2` is implicit
and already enabled (§3.1), and `check` is clean without packs. Install a
pack later with `confidant pack add <https-url> --yes`.

### 2.5 A second device needs no ceremony

`confidant init` always creates a **new** vault. To use the vault you already
have on another machine:

```sh
git clone <url> ~/vault
export CONFIDANT_VAULT="$HOME/vault"
confidant check --json --no-input
```

That is the whole flow. Do not run `init` there: it would scaffold a
different vault, with a different `vault_id`, beside the clone. Keep writes
synchronized with `confidant sync` (see [`docs/sync.md`](sync.md)); a machine
that is behind on a pull will still read its last-fetched copy.

## 3. Adopting in stages: personal first, packs later

### 3.1 Start with the personal pack (nothing to install)

`personal@0.2` is built into the binary and **implicit**: every vault has it,
whether or not `packs` lists it. `packs = []` still enables it, and a
`personal@…` entry is a no-op.

That gives you birthdays, relationship edges, keep-in-touch cadence, upcoming
dates, and the `touch` ledger verb:

```sh
confidant record add --file robin.md --no-input
confidant log touch "Robin Example" call --date 2026-10-19
confidant context "Robin Example"
```

Quote display names with spaces. A `no-ai: true` person is addressed by
`p-<ULID>` only.

### 3.2 Add a pack later

When you are ready, author or install another pack into the same vault. A
pack can come from a local directory or an HTTPS URL:

```sh
confidant pack init ~/confidant-packs/weekly-checkin
confidant pack add --from-dir ~/confidant-packs/weekly-checkin          # review
confidant pack add --from-dir ~/confidant-packs/weekly-checkin --yes    # install
```

`pack init` writes `manifest.toml`, `SKILL.md`, `<version>.md`, and
`README.md` for the new pack. Fill in its verbs, fields, finding codes,
`[checks]` keys, and rules, then install it. A pack fetched over HTTPS uses
`confidant pack add <https-url> --yes` instead.

Installing a pack:

- vendors `packs/<name>@<version>/` (manifest, `SKILL.md`, contract file)
  into the vault;
- writes `confidant.lock` with the pack hash;
- sets `packs = ["<name>@<version>"]` in `confidant.toml`;
- commits those files in one commit.

It does **not** touch records. `check` starts applying the pack's rules and
its verbs become valid. Existing personal records stay where they are; there
is no migration.

Do not try to seed a pack at `init` time with `--packs <name>@<version>`.
`init` only seeds packs built into the binary (today the implicit
`personal@0.2`); naming any other pack is a usage error (exit 2) with a fix
telling you to install it after init
([#639](https://github.com/hirefrank/confidant/issues/639)). Init with no
packs, then `pack add`.

To undo the change, `confidant pack remove <name> --yes` removes the
vendored files, the lock entry, and the `packs` listing. Data written under
the pack's verbs then becomes `W_PACK_ORPHAN` warnings, not errors; the
personal pack is never orphaned. `confidant pack list` and
`confidant pack verify` show what is installed and whether the hash still
matches.

### 3.3 The honest caveat: pack scope is policy, not a boundary

`--packs` (and `confidant mcp --packs …`) is a **read-time policy filter**:
out-of-scope records, fields, and ledger lines are omitted from `context`,
`find`, `record list`, `allowlist`, and MCP results. (`allowlist` also
annotates each entry with its `owning_packs` so an indexer can filter; the
QMD index itself is unscoped and `find` is the enforcement point for
queries.) That is useful against an agent over-reaching through the tool
surface.

It is **not** an access boundary. The vault is plaintext on disk (ADR-4), so
an agent that can read the files directly, or run the CLI unscoped, can see
the other pack's records too. `no-ai` hides content from agent-facing reads,
but it is also not a boundary against a process that can read the files.

If pack isolation must be a real boundary today, use **separate vaults**
(separate git repos, separate remotes, separate `no-ai` policy) rather than
one vault with two packs.

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

Expected: `doctor` exits 0 with `vault resolved to .../vault` and no error
checks; `check` returns `"ok": true`; and
`git -C "$NEW_VAULT" branch --show-current` prints `main` (init reports the
branch it created). On a brand-new vault the summary is zero records and
zero ledger entries. To make the check meaningful, add one fake person and
one touch first, then re-run.

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

Finally, if you added a pack, confirm it is installed and pinned:

```sh
confidant pack list
confidant pack verify
confidant check --json --no-input
```

`pack list` should show the pack with `status: ok`; `pack verify` should exit
0; `check` should still be `"ok": true`.
