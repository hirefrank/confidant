# Confidant crypto design (milestone 2)

**Status:** design review. No code in this PR — `confidant-crypt` stays a stub
until this document is approved. Per the updated architecture §9b item 5
(2026-10-08): Silas's security review of the crypto design clears milestone
2 code for the operator's own use; one outside human reviews the design,
and a full code audit happens before the README invites anyone else to
trust Confidant with client data (public launch).

**Scope:** how vault content is encrypted at rest in git, who can decrypt it,
and how keys are created, shared, rotated, revoked, shredded, and recovered.
Out of scope: QMD search (issue #8), write commands and the agent contract
(issue #10), release (ADR-14). The inbox keypair design (issue #36) is in
scope as this doc's §8a.

**Sources:** `docs/architecture.md` §§7 (ADRs 1–15), 8, 8a, 9, 9b (binding),
`docs/research/cr-spike.md` (ADR-13), `spec/0.1.md`, the `confidant-crypt`
stub contract, and the README privacy section. Revised 2026-10-08 against
the merged architecture doc; an earlier draft was written without it and
every resulting change is noted in §16.

## 1. Goals

1. A git remote holds **ciphertext only** for client PII. Cloning the vault
   without keys reveals no names, notes, aliases, or contact details.
2. One operator, many devices, scoped agent keys. Adding or removing a
   device/agent never requires re-encrypting all content.
3. Per-client blast radius: compromising or deleting one client's key
   affects only that client (crypto-shredding, ADR-4).
4. Recovery without the operator's laptop: a written-down phrase restores
   access to every client key (ADR-15).
5. Fail closed everywhere: missing keys, bad signatures, or tampered
   envelopes are errors, never silent plaintext.

Encryption is on by default for notes and PII; generic open-source users
may opt out (ADR-4).

## 2. Key hierarchy

```
operator signing key (Ed25519) ............ trust anchor, OFF-VAULT (never in git)
  signs recipient manifests and the trusted-signers list (ADR-4, ADR-10);
  loads from the OS keychain by default; CONFIDANT_OPERATOR_KEY env var
  allowed for headless use. There is no file fallback (Frank decision
  2026-10-12): a plaintext operator.key on disk is never consulted.
  Test-only overrides (CONFIDANT_TEST_*) are gated behind the
  `test-overrides` cargo feature and do not exist in release builds.

per-device / per-agent encryption key ..... X25519 (age "age1…" recipient)
  held in OS keychain / agent secret store on trusted devices only

per-client data key ....................... 256-bit random, one per person (p-<ULID>)
  encrypts that client's record content; wrapped with age to each
  authorized device/agent key (§4); epoch-tagged (§5)

vault alias-lookup key .................... 256-bit random, one per vault
  HMAC key for alias lines; wrapped with age to devices like a data key
  (§10); stored under keys/

inbox key ............................. one vault-wide X25519 keypair; the
  private half lives in the OS keychain on the inbox device only, never
  in git, and is not wrapped to devices or to the recovery identity (§8a)

recovery identity (ADR-15) ................ 24-word phrase ->
  X25519 age recipient (unwraps every client data key) AND
  Ed25519 signing key (in the trust-anchor set, so a bare-phrase
  recovery can authorize the new device's recipient manifest)
```

**Record-type-to-key mapping.** Person (`p-`), note (`n-`), and interaction
(`i-`) records — and deal (`d-`) records whose `person` field is set —
encrypt under that person’s data key (`p-…/eN`, §5), the same way notes
and interactions work. If a deal’s `person` changes, the writer re-encrypts
it under the new person’s current epoch in the same signed commit, so
shredding a client (§8) destroys their deals too. Org (`o-`) records and
deals with no `person` use one fixed vault-level client key,
`client_id = "vault:shared"`, kept under `keys/shared/`: it runs the same
machinery as `vault:lookup` — a manifest v2 with `seq`, commitments,
rotation, revocation, and recovery wrapping — and never routes through the
operator’s own person record, keeping agent scopes clean. An agent gets
`vault:shared` only when its scope names it.

No passwords, no KDF-over-passphrase for content keys: device keys live in
the OS keychain (or the agent host's secret store) on trusted devices with
encrypted disks, matching the existing "plaintext only on trusted devices"
rule. The recovery phrase is the only human-transcribed secret.

## 3. What is plaintext vs encrypted

**Stays plaintext** (needed for git diffing, `check` without keys, and
conflict handling):

- `confidant.toml` (including `vault_id`), ledger files (`ledger/YYYY/MM.cfd`):
  dates, verbs, opaque IDs (`p-…`, `pkg-…`), amounts/session counts, stage
  tokens, pack tag tokens (for example a session pack's payment tags),
  `src:` provenance IDs.
  Amounts and dates stay plain metadata tied only to opaque IDs (§9 Q2).
- Alias lines: `hmac:HEX` values only (never plaintext aliases) — §10.
- Record paths (opaque IDs; filenames never reveal who is a client) and the
  outer envelope headers of encrypted files — §5.
- The `no-ai` flag on encrypted records (outer header) — §5, rationale below.
- Commit messages and trailers: plaintext that crypto-shredding can't reach,
  so they carry only opaque IDs, verbs, agent identity, and request-id
  hashes. Free-text reasons and intent are stored encrypted under the
  client's data key, or omitted (ADR-7).

**Encrypted**: display names, profile/note/interaction/org/deal bodies,
alias plaintext values (email/phone/handle), and any other PII. Front-matter
`name:` moves inside the encrypted payload; the outer file carries only
`id`, `type`, `no-ai`, and envelope headers.

**What counts as an encrypted vault** (spec §14, normative): a vault with
any `enc:` envelope file or any `keys/` tree at all — including a
half-initialized `keys/` (e.g. `keys/operator.toml` with no client
manifest). The `[crypto] mode = "plaintext"` opt-out (`confidant.toml`,
spec §2) is structural-first and narrowing-only: it permits plaintext
writes only while the vault is already structurally plaintext, and can
never downgrade an encrypted vault (`mode = "plaintext"` plus an envelope
or `keys/` tree is `E_CONFIG`). `confidant init` hard-refuses a vault whose
`confidant.toml` declares `[crypto] mode = "plaintext"`; to upgrade such a
vault, delete the declaration and run `init`. `writes_encrypted()` and the disclosure
are global and flip once; the opt-out is a per-vault writer override that
never re-flips them.

**Never in git, even encrypted-adjacent:** local indexes and caches
(`.confidant/`, any search index) contain plaintext and embeddings. They
are sensitive, gitignored, and stay on trusted devices.

Rationale for plaintext `no-ai`: `find` and `context` must enforce `no-ai`
without decrypting (fail-closed on devices that lack a client key). Keeping
the single boolean outside the ciphertext leaks only "this record opted out
of AI" — accepted, and flagged in §15 Q2. The per-client rules — every
record carries the person record's value, `check` flags mismatches, any
`true` wins, and a `true` header means `find`/`context` skip the record
without decrypting — are specified in §5.

## 4. Key storage (`keys/`)

Spec 0.1 reserves `keys/`; this design fills it in:

```
keys/
├── recovery-recipients.toml # recovery age recipients ever used (append-only, §9)
├── vault/
│   └── lookup.age          # alias-lookup key, age-encrypted to each device/agent
├── p-<ULID>/               # one dir per client with encrypted content
│   ├── epoch               # ASCII decimal, current key epoch (plaintext)
│   ├── recipients.toml     # recipient list: key id -> {age_pubkey, label, scope_ref}
│   ├── recipients.sig      # Ed25519 signature over recipients.toml + epoch
│   └── wrapped/
│       ├── <key-id>.age    # data key (this epoch) age-encrypted to that recipient
│       └── recovery.age    # data key (this epoch) age-encrypted to the recovery key
└── shared/                 # the vault:shared client for orgs and person-less deals
    ├── epoch               # ASCII decimal, current key epoch (plaintext)
    ├── recipients.toml     # recipient list: key id -> {age_pubkey, label, scope_ref}
    ├── recipients.sig      # Ed25519 signature over recipients.toml + epoch
    └── wrapped/
        ├── <key-id>.age    # data key (this epoch) age-encrypted to that recipient
        └── recovery.age    # data key (this epoch) age-encrypted to the recovery key
```

- `wrapped/*.age` files are **committed to git** — they are needed on every
  device and are useless without the recipient's private key.
- `recipients.toml` + `recipients.sig` are committed too, but a manifest is
  only honored if `recipients.sig` verifies against the **trust anchor**:
  the operator's Ed25519 public key kept **outside the vault and outside
  git** (default `~/.config/confidant/` `[trust] operator_pubkey`; a flag or
  env var is also allowed, and a pinned first-commit fingerprint is an
  accepted alternative). This is the same anchor ADR-10 uses for the
  trusted-signers list that `check` can require on commits. A compromised
  git remote cannot add an attacker's recipient — the CLI refuses manifests
  that do not verify. **Never trust an in-vault copy** of the anchor or of
  any recovery public key: the CLI uses only the off-vault configured
  values for trust decisions, even if the vault also carries copies (they
  may be convenient for display, but they authorize nothing).

**Anchor hardening.** The trust-anchor set is the operator key plus the
recovery Ed25519 key, both pinned at `init` (or when a device is added).
Nothing in the vault can point at or override the anchor: the CLI refuses
an anchor path inside the vault (hard error at config load). Anchor
material lives with 0700 on the config directory and 0600 on key files;
the CLI warns if permissions are looser. A missing anchor is a hard
error — no manifest verification, no decryption, no commit-signature
checks. After `confidant recover`, the old recovery key leaves every
anchor set; the new recovery identity's Ed25519 key is pinned in its
place.
- `epoch` increments on every data-key rotation. Old epochs' `wrapped/`
  files are kept (renamed `wrapped/<key-id>.e<epoch>.age`) so history stays
  readable; see §8.
- `recovery-recipients.toml` (spec §14) records every recovery age
  recipient the vault has ever wrapped to. It is append-only: each
  recovery rotation (`recover`, `keys shred`) appends the retired and the
  new recipient, and readers union the working-tree copy with every
  historical version from git. Reusing a retired recovery recipient as a
  device is refused (§8, §9). It is unsigned — it only ever enlarges a
  denylist, so a forged or partially read version can never weaken the
  check, only over-forbid.

**Key commitment.** The signed manifest also carries a key commitment for
every retained epoch, so a planted wrapping cannot pass verification:

```
HMAC-SHA256(data_key,
            "confidant-key-commit-v1" ‖ len(vault_id) ‖ vault_id
            ‖ len(client_id) ‖ client_id ‖ le64(epoch))
```

(lengths are 8-byte little-endian; `‖` is concatenation). Stored in
`recipients.toml` as `[[commitments]]` entries `{epoch, commitment}`
(hex). The lookup key gets the same commitment in the `vault:lookup`
manifest. After **every** unwrap (device, agent, recovery, lookup), the
CLI recomputes the commitment and compares it in constant time; a
mismatch — or a missing commitment — is a hard error and no key is
returned. This closes the hole where anyone with push access could plant
`wrapped/laptop.age = age(attacker_key → laptop pubkey)`: the manifest
signature would still verify, but the commitment would not match.
Manifest format v2 (adds `vault_id` binding and `[[commitments]]`).

## 5. Content encryption

Algorithm: **XChaCha20-Poly1305** (192-bit random nonce per write;
`chacha20poly1305` crate). The AEAD layer is adapted from cr's
`src/encryption.rs` (~200 lines: `encrypt_bytes`, `decrypt_bytes`,
length-prefixed AAD construction) per ADR-13: re-keyed to per-client data
keys and our associated-data fields, with a MIT header on the adapted file
and the full text in `THIRD_PARTY_LICENSES`. Data keys never encrypt
directly to recipients — content always uses the per-client data key;
recipients only unwrap that key via age (X25519, `age` crate).

**AAD binding.** Every encryption binds all of these, in cr's
length-prefixed encoding (`append_component` pattern):

```
aad = len_prefixed("confidant1" || vault_id || record ULID || client_id || relative path || purpose || key epoch || outer header)
```

where `outer header` is the envelope's plaintext front matter (`id`,
`type`, `no-ai`, `enc`, `key_id`). The header is authenticated: flipping
`no-ai` — or any other header field — with only git write access fails
decryption, so an attacker who can write to the remote cannot leak a
`no-ai` client into agent output. (The `nonce` is the AEAD nonce and is
not part of the AAD.)

- `vault_id` — ciphertext cannot be moved between vaults.
- record ULID + relative path — a file cannot be swapped for another
  client's file or renamed into a different record.
- `client_id` — the record owner's key holder (the person's `p-…` id for
  `p`/`n`/`i` and person-bearing `d` records, `vault:shared` for `o`
  records and person-less `d` records, §2); a record's ciphertext cannot
  be re-attributed to another client's key.
- `purpose` — one of `profile`, `note`, `interaction`, `org`, `deal`
  (domain separation; a note ciphertext is not valid as a profile).
- `key epoch` — ciphertext is bound to the key epoch that wrote it, so
  multi-epoch history coexists safely.

Any mismatch fails authentication — no silent misbinding. The envelope
carries a key id (which epoch/key decrypted it) alongside the nonce.

### Rollback and replay

Binding the header stops a flipped flag, but not a restored older file:
someone with git write access can restore an older version of the same
file (`git checkout <old> -- <file>`, then push). That old file still has
a valid AAD — and may say `no-ai: false` from before the client opted
out. Defense in depth: `find` and `context` produce agent output only
from history whose commits verify against the trusted-signers list
(ADR-10). The tip commit and the commits that introduced each emitted
file's current content must verify; content introduced by an unsigned
commit — an unsigned rollback included — is refused with a hard error
and withheld from agent output. This composes with the existing rule
that operator commits are signed (§4).

### no-ai per client

The outer header carries the tri-state `no-ai` value (`true`/`false`/`notes`;
`notes` only on person records — issue #181):

- A `no-ai: true` person record stamps `no-ai: true` onto every child
  record (notes, interactions, deals) for that client ("any `true` wins":
  an explicit `true` on the person or on the child itself always wins).
- A `no-ai: notes` person record carries `no-ai: notes` in its own outer
  header (and decrypts for agent output so identity and pack fields stay
  visible), while its notes and interactions are stamped `no-ai: true`
  by default unless the child explicitly sets `no-ai: false`. Deals keep
  `no-ai: false` unless explicitly marked `true`.
- A single note or interaction can carry `no-ai: true` on an otherwise
  visible person without opting out the whole client.
- When an outer header says `true`, `find` and `context` skip that record
  for agent output without decrypting at all — the plaintext is never
  unwrapped for an agent path.

Header consistency is enforced alongside the AAD check: `id` must equal
the record ULID bound in the AAD, `key_id`'s epoch must equal the AAD
epoch, and `type` must map to exactly one `purpose` (`person`→`profile`,
`note`→`note`, `interaction`→`interaction`, `org`→`org`, `deal`→`deal`).
Any inconsistency fails closed — decryption is refused and the record
is withheld.

**Encrypted file envelope** (proposal; §15 Q1 has the alternative):

```markdown
---
id: p-01M3TC5H00MPJG000000000000
type: person
no-ai: false
enc: xchacha20poly1305
key_id: p-01M3TC5H00MPJG000000000000/e3
nonce: base64(24 bytes)
---
<base64 ciphertext of the inner record>
```

The inner plaintext is the full original record (front matter with `name:`,
plus body). `check` validates the envelope structurally without keys;
`find`/`context` decrypt when a client key is available and fail closed
when it is not. Merge conflicts on encrypted files keep both versions side
by side and `check` flags them (§9b item 1; implemented in milestone 3).

**Never commit plaintext.** Content is encrypted before its first commit.
Existing plaintext is never encrypted in place, because git history would
keep it (ADR-4). **Keep unchanged ciphertext:** if a file's plaintext hasn't
changed, its existing ciphertext is kept byte for byte, so rewrites don't
create diffs, conflicts, or false "changed" signals (ADR-3, ADR-4; cr's
`protect` rule at file level).

### git-crypt compatibility notes

Milestone 2 (§8) lists git-crypt compatibility notes as in scope. Per
ADR-4, git-crypt is optionally supported for compatibility but is **not**
the default, for its documented limits:

- It encrypts file *contents* but not *paths*. Confidant's opaque-ID paths
  leak less than name-based layouts, but the directory structure itself
  (which clients exist, how many notes each has) stays visible.
- Its encryption is deterministic: identical plaintexts produce identical
  ciphertexts, leaking equality. Confidant uses a fresh random nonce per
  write.
- Its own docs say it cannot revoke access: anyone who ever held the key
  keeps it. Confidant's per-client keys + re-wrapping give revocation
  (ADR-5, future-writes-only) and crypto-shredding (§8).

Operators who need git-crypt interop (e.g. mixed tooling) accept these
limits explicitly; the default remains the per-client age/AEAD design
above.

## 6. Recipient changes

- **Add device/agent:** the new keypair is generated **on the device**
  (private key never leaves it). Onboarding takes **only the public key**
  from the operator — via QR, file, or paste. No agent or device private
  key is ever transmitted, moved, or escrowed, including during onboarding.
  The operator wraps each authorized client data key to the new public key,
  appends to `recipients.toml`, re-signs the manifest. The operator **must
  also re-wrap the vault lookup key** (`keys/vault/lookup.age`) to the new
  device: an existing device unwraps it and re-wraps to the current
  recipient set including the new device, or the new device cannot compute
  alias HMACs (§10). One commit per change, and the change itself must be in
  a commit signed by an already-trusted key (ADR-4).
- **Remove device/agent (revocation):** re-wrap keys without the revoked
  recipient, update + re-sign the manifest, commit. Re-wrapping covers
  **all retained epochs**, not just the current one: the revoked party's
  `<key-id>.e<epoch>.age` files are removed for every epoch, and new
  wrappings are issued to the current recipient set only, so a revoked
  party loses its old-epoch wrappings too. **Revocation protects only
  future writes** (ADR-5): ciphertext the revoked device already copied
  cannot be unread — git history still contains the old wrappings, and a
  revoked device keeps whatever it already copied. `confidant keys revoke`
  says so plainly in its output. After revocation, optionally rotate the
  affected client data keys (new epoch) so future content uses new keys.
- Manifest verification is mandatory on every unwrap: unknown signer,
  missing signature, or tampered list → hard error, no decryption.

## 7. Scoped agent keys

An agent key is an X25519 keypair plus a **scope document**, signed by the
operator key:

```toml
# scope example (signed; stored with the agent, not in the vault)
key_id = "agent-transcriber-01"
clients = ["p-01M3…", "p-02AB…"]   # or "all"
types = ["deal", "note"]           # record purposes it may touch; e.g. a
                                   # pipeline key reads deals + ledger but not notes
capabilities = ["read"]            # "read", "write"
expires = "2026-11-08"
```

- The CLI checks the scope signature, expiry, client list, types, and
  capability **before** unwrapping or encrypting for that key.
- The signed bytes are `b"confidant-scope-v1" ‖ le64(len(vault_id)) ‖
  vault_id ‖ scope_toml`: a scope minted for one vault does not verify in
  another. `expires` is parsed strictly as `YYYY-MM-DD` (a malformed date
  is a hard error, never "unexpired"), the scope's `key_id` must equal the
  identity in use, and verification uses Ed25519 `verify_strict`.
  `confidant-scope-v1` is the **first released v1 layout**; any future
  change to the signed bytes or the scope document bumps the tag (e.g.
  `confidant-scope-v2`), so old scopes stop verifying rather than being
  silently reinterpreted.
- The `vault_id` and the expected `key_id` passed to the authorize check
  must come from verified state (the signed manifest / trust anchor, the
  key the CLI actually loaded) — never from the scope file, an env var,
  or unverified config — and the "today" date must be UTC. The authorize
  boundary refuses an empty `vault_id` or `key_id`.
- A client data key is wrapped to an agent key only for clients in its
  scope. Narrowing a scope = remove wrappings + re-sign manifest.
- Agent private keys live in the agent host's secret store, never in the
  vault repo. Agent key distribution itself is out of scope for milestone 2
  (§15 Q6).

## 8. Rotation, revocation, shredding

- **Rotate** (`confidant keys rotate p-<ULID>`): generate a new 256-bit data
  key, `epoch += 1`, wrap to all current recipients + recovery, re-sign.
  Rotation re-wraps **all retained epochs** to the current recipient set
  (so a rotation after a revocation also clears the revoked party's
  old-epoch wrappings from the working tree). New writes use the new
  epoch. Old-epoch ciphertext stays decryptable by still-authorized
  parties — rotation does not re-encrypt content. The same holds for a
  rewrite (`record edit`, #216): the edit re-encrypts under the current
  epoch, and the replaced envelope stays readable in git history with the
  epoch that wrote it, until that client is shredded (above).
- **Revoke device/agent**: §6. Re-wrap excludes the revoked party across
  all retained epochs; optional rotation afterwards so future writes use
  new keys.
- **Crypto-shred** (`confidant keys shred p-<ULID>`): shredding is key
  destruction, not just deletion. (1) Delete every wrapped copy of that
  client's data keys (all epochs) from the working tree and the local key
  cache, and commit the deletion. (2) Rotate every recipient keypair that
  ever held a wrapping of the shredded key — device keys, agent keys, and
  the recovery identity: generate new keypairs, re-wrap all remaining
  client keys (and the vault lookup key) to the new recipients, and
  re-sign the manifests. (2b) Start an inbox key rotation (§8a):
  `confidant inbox rotate` on the inbox device. The inbox key never holds
  a client-key wrapping and is never a re-wrap target — it rotates because
  cleared items stay in the inbox branch history encrypted to the old
  inbox key, and opaque item names can't tie them to the shredded client.
  (3) Destroy the old private keys (remove from OS keychains / secret
  stores / paper) — except the old inbox key, which is destroyed by
  `inbox rotate --finish`, not at this moment. Git history still contains the
  old wrappings, but no surviving private key can unwrap them — which is
  how ADR-4's "unreadable everywhere, including git history and backups"
  is delivered without a history rewrite. This is deliberately heavyweight;
  the command says what it is about to do and confirms before proceeding.
  Because the recovery identity is rotated, **each shred means a new
  recovery phrase**: the command displays it once and requires confirmation
  it was written down, exactly like `init`. **Re-pin the anchor before any
  other key operation** (`init_client`, `rotate`): both read the recovery
  recipient from the anchor, so a client initialized after a shred but
  before the re-pin wraps to the recovery key the shred just destroyed and
  cannot be recovered from the new phrase (issue #99, test in
  `confidant-crypt`). `keys shred` also states its
  leftover limits plainly in its output: decrypted copies already on
  devices, `.confidant/` caches and search indexes on other devices, old
  keys lingering in OS keychains or OS backups, copies outside
  Confidant entirely (e.g. Drive transcripts), and — until
  `confidant inbox rotate --finish` has run — the old inbox key.
  Shredding cannot reach any of these. (The exception is this device's
  search index — `keys shred` deletes `.confidant/qmd-corpus/` and the QMD
  store locally.)
- **Edges (issue #179)**: edge records live under the shared key
  (`vault:shared`), so destroying one person's client key cannot shred
  them. `keys shred` deletes every edge file naming the shredded person
  from the working tree in the same signed commit, and states in its
  output: "Edges that named this person were deleted from the working
  tree, but earlier versions in git history remain readable with the
  shared key." Earlier git versions stay readable to anyone holding the
  shared key — this is the honest limit of shared-plus-delete, not a
  history rewrite.

## 8a. Inbox key (issue #36)

The `inbox` branch (PR #26) receives age-encrypted items from outside
tools. Those tools pin one recipient out of band, so the inbox needs one
vault-wide keypair:

1. **One vault-wide X25519 keypair, yes.** The inbox is a single drop
   point and each outside tool pins exactly one recipient (#26 must-fix 2).
   Per-device keys would multiply the pins in every tool for no gain —
   only one device runs `confidant inbox`.
2. **Storage: the OS keychain on the device that runs `confidant inbox`.**
   Not a file under `~/.config` (raw key files go against §2's "device
   keys live in the OS keychain", and Time Machine backs up `~/.config` as
   plaintext, so "destroy the old key" would be false there). The keychain
   narrows that backup exposure rather than removing it: the macOS login
   keychain (`~/Library/Keychains/login.keychain-db`) and GNOME's keyring
   files are in those backups too, encrypted under the login password, and
   deleting an item doesn't reach old backup copies. What the keychain buys
   is encrypted-at-rest storage plus a per-app access list on macOS. §8
   already lists old keys lingering in OS keychains or OS backups as a
   leftover limit. Not wrapped to devices in
   `keys/` like the alias lookup key, and not wrapped to the recovery
   identity either: either wrapping would leave the old inbox key's
   wrapping in git history, readable by any device key that hasn't been
   rotated, so rotating the inbox key would buy nothing until every device
   key was also rotated — the heavyweight §8 shred path. The inbox key
   only stays cheap to destroy if it never enters git. A lost device costs
   at most the un-imported batch: outside tools keep the source until the
   operator confirms a verified import. When the old key is unavailable
   (lost, compromised, or revoked inbox device), `inbox rotate` generates
   the new keypair on the new inbox device, skips the drain and `--finish`
   (there is no old private key to drain with), and old-key items fail
   closed with `E_INBOX_CRYPTO`; the operator re-pins the tools and the
   tools drop those items again from source.
3. **Rotation: not after every import.** Rotating per import would force a
   manual re-pin of every outside tool after every run, and any tool that
   drops an item before re-pinning encrypts to a destroyed key — the form
   answer is lost. Instead: **mandatory** rotation on (a) any `keys shred`
   and (b) revoking or compromise of the device holding the inbox key;
   **optional** rotation whenever the operator wants (`doctor` reports the
   key's age; no fixed schedule in v0). Procedure, so nothing in flight is
   lost: (1) `confidant inbox rotate` drains the inbox (normal run),
   generates the new keypair, and updates `confidant.toml [inbox].pubkey`
   and the user-config pin; (2) the operator re-pins each tool;
   (3) `confidant inbox rotate --finish` drains anything still encrypted
   to the old key (age X25519 stanzas don't name the recipient, so it
   tries old then new during this window), then destroys the old private
   key from the keychain. After `--finish`, items sent to the old key fail
   closed with `E_INBOX_CRYPTO` and the tool drops them again from source.
   `inbox rotate` refuses while the previous slot is still occupied — run
   `inbox rotate --finish` first — so a second rotate can never silently
   destroy the oldest key without draining it.
4. **Shredding rotates the inbox key.** Cleared items stay in the inbox
   branch history, encrypted to whatever inbox key was current, and item
   names are opaque — we can't tell which past items belonged to the
   shredded client. So **every `keys shred` also rotates the inbox key and
   destroys the old one** (added to §8 step 2b above). A shred isn't
   complete until `inbox rotate --finish` has run; `keys shred` says so
   plainly and lists it among its leftover limits until then. Once the old
   inbox key is destroyed, the old form answers in history are unreadable
   without rewriting history — the same argument as #15. A `keys shred`
   run on a device that doesn't hold the inbox key records the pending
   inbox rotation, tells the operator to run `confidant inbox rotate` on
   the inbox device, and stays incomplete until `inbox rotate --finish`
   has run there.
5. **Revocation.** The inbox key lives on one device, so revoking that
   device means a mandatory inbox rotation. Revoking other devices doesn't
   touch it.

## 8b. Delegated writer keys (issue #779, design revision)

Rationale in one paragraph: today the operator Ed25519 key is the sole
signing authority, and the agent — the primary actor for creating and
updating content — works only by holding a copy of it (#729). One
compromised agent host then holds total authority, and every additional
agent needs another copy of the root. The fix is delegation, not
duplication: the operator key becomes a root that signs per-writer
certificates, each writer signs with its own Ed25519 key, and revoking
one writer touches nothing else. The normative contract is spec §14
("Writer certificates"); this section keeps the rationale, the answers
to the open questions, and what the implementation must prove. This
section is design only, answering Silas's review of 2026-10-27 (signed
— Silas) on issue #779, the design gate for #731. No crypto code lands
under it until #779 is answered, Frank gives explicit OK at merge, and
the implementation states **needs outside audit before public launch**.

What the review settled, and where it lives in the spec:

- **Architecture: approved with conditions.** Operator as root,
  per-writer certs in the vault, a new domain
  (`confidant-writer-cert-v1`), separate sign and encrypt keys, and
  root-only device, writer, recovery, and shred verbs. The conditions
  are the field-level rule, seq-keyed revocation, and Q4 in scope —
  each is normative in spec §14.
- **Q1 — where the cert lives: in the vault** (`keys/writers/`).
  Readers must verify writer signatures from a fresh clone, so the
  agent-scope precedent (scope lives only with the agent, §7) does not
  apply to a signer whose artifacts are in the vault.
- **Q2 — signer binding: inside the signed manifest TOML.**
  `signer = "writer:<id>"` plus the cert's `seq` and SHA-256 digest,
  all inside the already-signed `recipients.toml` bytes. A missing
  `signer` means operator. Binding more than a label matters: without
  the cert `seq`/digest, a re-issued cert with a wider scope could be
  swapped under an old signature.
- **Q3 — separate keys: yes.** The cert binds an Ed25519 signing key
  and, optionally, an X25519 age recipient. Signing authority and
  decryption capability stay independent: the cert alone never unwraps
  a data key.
- **Q4 — which artifacts writers sign: manifests AND git commits, in
  this design.** Manifests-only would leave the agent host needing the
  operator key for trusted commits, so #729's copied root could not be
  retired and the compromise math would not hold. The writer's Ed25519
  key doubles as its SSH commit-signing key; allowed signers are
  derived at verification time from verified in-vault certs
  (principal `writer_id`, `valid-before` from cert `expires`, revoked
  writers dropped). Commits need no new signed bytes — only a new
  verification source, and never a committed allowed-signers file in
  the vault, which push access could forge. Two qualifications from
  the fix round (normative in spec §14): `valid-before` is defense
  in depth, not the boundary — git checks it against the
  signer-controlled committer date, so new-commit/new-head
  acceptance checks expiry against the verifier's clock, and a
  backdated post-expiry commit is refused as a new head; and every
  writer-signed commit, manifest-free or not, runs the single
  commit authorization rule, so signature verification identifies
  the writer but never by itself authorizes a commit.
- **Q5 — revocation freshness on stale clones: offline, 30-day
  lifetimes, no online check.** Certs live at most 30 days; `doctor`
  warns when the last fetch is older than 30 days (the same window, so
  a reader that has not fetched in longer than a cert can live says so
  rather than verifying quietly); the off-vault revocation high-water
  is updated on sync. Staleness is bounded by the lifetime, not
  eliminated — that is the accepted offline trade-off.
- **Q6 — recovery/root rotation: re-issue on rotation, short
  overlap.** The recovery key can revoke writers and rotate the root.
  Rotation re-issues every writer cert under the new operator key with
  scope preserved exactly (a scope change is a separate grant, never
  smuggled inside a rotation); the overlap from first new cert to
  pinned new operator cert is at most one cert lifetime. Old-root
  certs stop verifying for **new acceptance** once the new operator
  cert is pinned; pre-rotation history keeps verifying through the
  anchor-at-commit chain (the operator cert at a historical commit
  verifies against the unchanged recovery key), or every rotation
  would break history verification. That chain holds only while the
  recovery key is unchanged: across a recovery rotation (`recover`,
  `keys shred`), history verifies through the recovery checkpoint
  chain in spec §14, and without a checkpoint the affected history
  fails closed rather than silently losing its anchor.
- **Q7 — scope naming and versioning: new type and domain.**
  `confidant-writer-cert-v1`, not a `confidant-scope-v2` bump: the
  agent scope's capabilities mean content access, and conflating them
  with signing authority would make both harder to audit. The verb
  list is a closed set (`record.add`, `record.update`,
  `ledger.append`); an unknown verb fails verification instead of
  being ignored. `keys.init_client` is deliberately excluded: a first
  manifest has no previous verified manifest for the field rule to
  check against, so first-manifest signing is root-only.

The two blockers, stated as the design's load-bearing ideas:

1. **A writer re-signs an otherwise-identical manifest.** Recipients,
   commitments, epoch, vault, and client must match the previous
   verified manifest exactly; only `seq` and the signer fields may
   move. Anything else is device enrollment wearing a writer
   signature, and the field rule refuses it before the signature even
   matters. The carrying commit's content changes must also be inside
   the writer's scope — scope is checked on the commit, not just on
   the manifest.
2. **Revocation is keyed to manifest `seq`, not time.** The
   root-signed `revoked.toml` entry records, per client, the highest
   writer-signed manifest `seq` the revoker had observed. Artifacts
   above that `seq` are rejected; at or below it keep verifying.
   Time-based cutoffs fail both ways — invalidating all history, or
   letting a compromised host backdate — and `seq` fails neither way.
   The off-vault revocation high-water (file `seq`, updated on sync)
   covers rollback of the revocation file itself.

What the fix round added, because the first revision left the gaps
open (normative in spec §14):

- **Commit authorization is one rule for every writer-signed
  commit.** The manifest-scope sentence in the first revision lived
  only in the manifest path, so a manifest-free commit never met a
  scope check. Now signature verification identifies the writer and
  a single rule authorizes the commit: every changed path is
  classified (adds, modifications, deletions, renames, mode
  changes), allowed only as a scoped record addition/modification, a
  scoped append-only ledger append, or the field-level manifest
  re-sign itself, and everything else — unclassified paths, `keys/`
  material, `confidant.toml`, spec/config files — fails closed.
  Merge commits are checked against each parent. History uses the
  same rule with the cert pinned at the commit.
- **New acceptance is partitioned by an acceptance checkpoint.**
  "Tip is new, ancestors are history" is true only once a checkpoint
  exists. A reader records its accepted tip and high-waters
  off-vault, only after a chain verifies in full; ancestry reachable
  from that tip is history, and everything newly introduced — tip,
  commits above it, or side ancestry from a merge — is new
  acceptance with the full wall-clock and high-water checks. A fresh
  clone has no checkpoint, so its whole introduced chain is new
  acceptance. The step-7 manifest high-water is likewise scoped to
  the candidate head: historical links in a chain verify without it,
  so a chain can be reopened and advanced after a higher `seq` is
  accepted.
- **Cert dates are an ordered interval, not just a lifetime cap.**
  `issued_at < expires` with a 30-day maximum is well-formedness and
  fails verification outright, including in history; the window
  `issued_at <= now < expires` against the verifier's clock, with no
  skew allowance, gates new acceptance only. A future-issued cert
  cannot authorize before its window, and a reversed interval cannot
  slip through history replay.
- **Recovery rotation has a checkpoint chain.** Each rotation must
  commit a checkpoint, signed by the new or retiring recovery key,
  binding the old recovery pubkey to a tip commit and per-client
  manifest `seq` range, chaining to the previous checkpoint and
  carrying revocation and cert `seq` high-waters forward. History
  signed under the retired key verifies through that chain; a
  fresh-device reader trusts only checkpoints signed by the
  phrase-derived new recovery key; with no checkpoint, verification
  of the affected history fails closed with a diagnostic naming the
  missing checkpoint. The per-writer cert `seq` high-water is
  recorded off-vault as part of the acceptance checkpoint (the
  non-blocking suggestion in the first review, adopted here rather
  than left to the implementation PR), so a force-push cannot drop
  history and resurrect a superseded cert version.

Concurrency and format, also from the review: the first pushed commit
wins a `seq` race, the loser re-signs on top, and an equal `seq` with
different bytes is a fork, never auto-merged. The change is a minor
format bump, not a patch, with a vault minimum-reader-version gate
(`confidant.toml` `[crypto] minimum_reader_version`, checked before
any manifest verification, reserved refusal `E_READER_TOO_OLD`) plus
the spec-minor gate for pre-gate readers (`E_SPEC_UNSUPPORTED`), so an
old binary refuses a writer-capable vault clearly instead of reading
its first writer-signed manifest as tampering.

Decisions in this revision that Silas still needs to confirm (also
listed in §26): expiry is enforced for new-head acceptance but not
re-checked when re-verifying already-accepted history for read/decrypt
(otherwise history dies every 30 days) — now qualified by the
acceptance checkpoint: the split holds only for ancestry already
covered by a recorded checkpoint, and a fresh clone checks the whole
introduced chain; the review's "old-root certs stop verifying once
the new operator cert is pinned" is read as a new-acceptance rule,
with history preserved via the anchor-at-commit chain while the
recovery key is unchanged and via the recovery checkpoint chain
across a recovery rotation; writer scope has no `"all"` client
wildcard (unlike agent scopes — enumerate, because a writer touching
every client is root-equivalent in breadth). Two further choices
made in the fix round, for Silas to confirm with the rest: there is
no clock-skew allowance (the verifier's clock is authoritative, and
a wrong clock fails closed), and writer-signed merge commits are
checked against each parent rather than refused outright.

## 9. Recovery (ADR-15)

- At `confidant init`, generate the recovery identity. Display the 24-word
  phrase **once** and require the operator to confirm it was written down.
  Store it in 1Password plus a printed copy kept somewhere physical — never
  on a device that syncs the vault. The public halves are pinned in
  `~/.config/confidant/` at `init`; any copy of them in the vault config is
  informational only and authorizes nothing (the CLI never trusts in-vault
  copies — §4). The private halves are never stored anywhere.
- The phrase derives two keys via HKDF-SHA256 from the raw BIP39 entropy
  (256 bits, **no passphrase** — the entropy goes straight into HKDF).
  Domain separation, with fixed salt `confidant1/recovery`:
  - `X25519_sk = HKDF-SHA256(entropy, salt, info="confidant/recovery/x25519/v1")`
    (age recipient; every client data key is wrapped to it:
    `wrapped/recovery.age`)
  - `Ed25519_seed = HKDF-SHA256(entropy, salt, info="confidant/recovery/ed25519/v1")`
    (trust-anchor signing key, so a bare-phrase recovery can authorize the
    new device's recipient manifest)
- `confidant doctor` warns when any client key isn't wrapped to the
  recovery key, when any client key has a single recipient (ADR-4), and —
  yearly — reminds the operator to check the paper copy (§8 milestone 2).
- `confidant recover`: enter the phrase → derive the recovery identity →
  unwrap all client data keys → wrap them to a fresh device key → rotate to
  a fresh recovery identity and revoke the old one. Works from a clean
  clone with nothing but the phrase. It does not restore the inbox key:
  run `inbox rotate` on the new device and re-pin (§8a). It also does not
  restore the vault lookup key (§10): the operator generates a fresh one
  and rebuilds the alias index from the decrypted alias values.
- **Fresh-device recovery** (no `trust.toml`, no config backup): at
  `init`, the CLI writes `keys/operator.toml` + `keys/operator.sig` — the
  operator Ed25519 pubkey, signed by the recovery Ed25519 key (spec §14).
  On a fresh device, `recover` verifies this certificate against the
  phrase-derived recovery pubkey and rebuilds the trust anchor from the
  verified operator pubkey. The signature binds the pubkey to the vault
  id; a transplanted or forged certificate fails closed. The anchor is
  re-saved atomically, only after the new recovery phrase has been shown.
  Vaults initialized before the certificate existed still require a
  config backup for recovery.
- **Retired recovery keys cannot be re-enrolled.** Every recovery rotation
  (`recover`, `keys shred`) appends the retired and the new recovery age
  recipient to `keys/recovery-recipients.toml` (§4). `recover` and
  `keys device-add` union that file's working-tree and every historical
  git version into the "ever a recipient" denylist, so a device-add
  request that reuses a retired recovery recipient is refused. Without
  this, re-adding a retired recovery key as a device would re-wrap the
  vault's remaining keys to a key that still opens a shredded client's
  history.
- `confidant keys verify-recovery` is the read-only check for a saved
  copy (#663). It compares both pinned recovery halves in `trust.toml`
  (never falling back to `keys/` when an anchor exists), verifies
  `keys/operator.toml` against the phrase, and trial-unwraps the
  current-epoch `wrapped/recovery.age` of every initialized client
  except the device-only `vault:lookup` key. It writes nothing and never
  prints words, word positions, derived keys, or fingerprints; a
  malformed phrase's position hint goes to stderr only. It reports a
  retired phrase distinctly (the derived recipient is in
  `recovery-recipients.toml` but is not the anchor's current one) with
  the same shred guidance: destroy that copy, because it still opens
  history. CLI-only: no MCP tool, no skill-driven phrase piping.

## 10. Alias HMAC

Ledger `alias` lines carry `hmac:HEX`, never plaintext (spec §6, ADR-2,
ADR-9). Following the cr spike's keyed-digest reasoning (a plain hash can
be dictionary-attacked), the value is:

```
hmac = HMAC(vault_lookup_key, normalized_value)
```

`normalized_value` is the alias value normalized as spec §6 requires:
NFC, then trim surrounding whitespace, then Unicode lowercase. Importers
must apply the same rule before hashing.

The **vault lookup key** is generated at `init` and wrapped with age to each
device and agent that needs alias lookups (`keys/vault/lookup.age`, covered
by the signed recipient manifest). It is **device-only by design, never
wrapped to the recovery key** — unlike client data keys, which are always
recovery-wrapped (§9). Rationale: the lookup key is only an HMAC key. Every
alias value lives encrypted under its client's recovery-wrapped data key,
so after a full device-loss recovery nothing is lost: recover the client
keys, decrypt the aliases, generate a fresh lookup key, and rebuild the
index. Recovery-wrapping the lookup key would buy no privacy (the recovery
phrase already opens all client data) and would add one more wrapping every
shred and recovery rotation has to re-wrap and verify. The real alias
values live encrypted in the profile. `HEX` is at least 32 hex chars
(spec §6). Importers match on aliases by recomputing the HMAC of the
normalized value.

### Accepted dictionary-attack oracle (#547, 2026-10-19)

A keyed HMAC over a low-entropy value is an **equality oracle**: anyone who
holds the lookup key — every enrolled device and agent, and the operator —
can test a candidate (`HMAC(key, candidate) == hmac:HEX?`) and confirm whether
a given email, phone number, handle, or former/married name belongs to a person. Alias values are
enumerable in practice (address books, domain guesses, and — for names —
public records and social profiles), so this oracle
reveals the *values*, not just their hashes. A former/married name is no
less enumerable than an email, and more sensitive: it is a name the person
may no longer use.

This is **accepted and deliberate**, not an oversight:

- It is inherent to the design (ADR-2/ADR-9): the ledger must record a
  matchable alias without storing plaintext PII, and HMAC is what makes the
  line matchable at all. Replacing it with a plain hash would let *anyone*
  with the ledger mount the same attack; the key at least limits it to key
  holders.
- The lookup key is device-only and never recovery-wrapped (§10), so the
  oracle is available only alongside the ability to decrypt the rest of the
  vault. It grants no capability beyond what a trusted-device holder already
  has.
- The clear-text alias values remain encrypted under each client's
  recovery-wrapped data key; the oracle leaks *membership* of a guessed
  value, never the stored plaintext.

The `confidant alias resolve` CLI path (#537 phase 3b) exposes this oracle as
a short command. That adds **no new capability** — `alias_hmac` and
`KeyStore::read_lookup_key` were already public and a five-line script could
compute the same — but it is recorded here so a future reader does not mistake
the CLI for the source of the property. The CLI takes the value from stdin or
`--value-file` only (never `argv`), so the untrusted command line does not
leak it, and it never echoes the value in output or errors.

Plaintext lifetime in the process is best-effort, not guaranteed: the value
is held in a `Zeroizing<String>` and dropped there, but `read_to_string` can
leave an un-wiped copy when the `String` reallocates, and `alias::normalize`
inside `alias_hmac` allocates its own short-lived plain `String`.

## 11. Threat model

After architecture §4:

**Protects against:** a leaked or breached git remote; a stolen backup; a
curious host (remote provider, later hosted service); filenames revealing
who is a client (opaque IDs in paths); a revoked device reading *future*
writes.

**Does NOT protect against:**

- **The model provider seeing plaintext an agent reads.** Explicit and
  accepted (README/spec §13, §9b item 2): when an agent decrypts notes to
  work with them, that content goes to the hosted model. Confidant never
  claims otherwise. The per-client `no-ai` flag keeps a client's notes and
  PII out of `context` and `--json` output entirely.
- A compromised trusted device (malware, stolen unlocked laptop): keys are
  present, so content decrypts. Mitigation is device hygiene + revocation,
  not cryptography.
- A process running as the user reading an unlocked OS keychain entry
  (Linux): the Secret Service keeps an unlocked collection's items readable
  to any process in the user's session, with no further prompt. A malicious
  or compromised app on the same desktop can read the stored keys. The
  macOS login keychain's per-app access list narrows this; GNOME's keyring
  does not.
- A revoked device keeping ciphertext it already decrypted — revocation
  covers future writes only (ADR-5).
- Metadata analysis: commit timing, commit counts, file counts and sizes,
  which opaque IDs change together, and plaintext ledger fields (dates,
  amounts, stage tokens) tied to opaque IDs. An observer learns *when* and
  *how much*, never *who* or *what*.
- **Guessing an alias value.** The alias index is a keyed HMAC over an
  enumerable value, so a key holder (any enrolled device) can confirm a
  guessed email, phone, handle, or name by recomputing the HMAC. Accepted and
  documented in §10 ("Accepted dictionary-attack oracle") — it is inherent to
  a matchable, non-plaintext alias.
- Rubber-hose / compelled disclosure of the recovery phrase (it reads the
  whole vault — ADR-15).
- **A history-derived shred check failing open.** `shredded_clients`,
  `historical_recipients`, and the `keys/recovery-recipients.toml` union
  consult git history. When `git` is unavailable, `git log` fails, or the
  clone is shallow, they see only the working tree. A recipient whose only
  record is in history — a revoked key, a shredded client's old device, a
  retired recovery recipient — would then not be refused. `keys device-add
  --from-request` refuses outright in that state (the denylist is
  load-bearing there); `keys shred`, `recover`, and `doctor` warn. Run the
  vault as a full-history repository. (A vault inside a larger repo is
  fine: the readers resolve paths relative to the vault.)

## 12. Test plan

All fixtures use generated fake data and throwaway keys generated during
the run (ADR-14: CI never holds vault keys). No real keys, phrases, or PII
in the repo, tests, or CI.

1. **AAD binding:** decrypt fails when any of vault_id, ULID, path,
   purpose, or epoch is altered; passes when all match. AAD uses the
   length-prefixed encoding (§5).
2. **Nonce misuse:** 1,000 encryptions produce 1,000 distinct nonces.
3. **Wrong key / tampered ciphertext:** authentication failure, no
   partial plaintext.
4. **Age wrapping round-trip:** wrap/unwrap data key to generated
   recipients; unknown recipient fails.
5. **Manifest signatures:** valid verifies; tampered list, wrong signer,
   or missing signature → hard error, no unwrap.
6. **Scope enforcement:** expired scope, out-of-scope client or type, or
   write-with-read-only capability → refused before any crypto.
7. **Revocation:** after revoke (+ optional rotate), the revoked key
   cannot unwrap new epochs, and the revoked party's old-epoch wrappings
   are gone from the working tree — re-wrap covers all retained epochs
   (§6). Still-authorized parties keep reading all retained epochs
   through the re-wrapped keys. The revoked party can still decrypt
   whatever ciphertext plus old wrappings it copied before revocation
   (documents future-writes-only, ADR-5).
8. **Shredding:** after `keys shred` plus rotation, the old private keys
   are destroyed: the shredded client's historical wrappings (all epochs)
   cannot be opened by any former recipient, while other clients' records
   still decrypt under the new keys. `keys shred` output states the
   leftover limits (decrypted copies on devices, `.confidant/` caches and
   indexes, old keys in keychains/OS backups, copies outside Confidant).
9. **Recovery drill (acceptance, §8 milestone 2):** clone the demo vault
   into a clean dir, `confidant recover` using only the phrase, confirm
   reads work, rotate to a new phrase, confirm the old phrase fails.
   `doctor` warns when a client key lacks recovery wrapping.
10. **`check` without keys:** structural validation only; findings contain
    no plaintext beyond IDs (existing §12 rules apply to envelopes).
11. **Keep unchanged ciphertext:** re-writing an unchanged file keeps
    ciphertext byte-for-byte (no diff churn).
12. **CI round-trip:** encrypt-then-decrypt round-trip test on every push
    (ADR-14), Linux + macOS.
13. **Never log the phrase:** a test that runs `init`, `recover`, and key
    rotation with a known phrase and asserts the phrase (and its component
    words) never appears in stdout, stderr, logs, error messages, or debug
    output.
14. **Header consistency and per-client no-ai:** flipping any header field
    (`id`, `type`, `no-ai`, `enc`, `key_id`, `nonce`) fails decrypt and
    the record is withheld — in particular `no-ai: true` → `false`.
    Header `id` equals the AAD ULID, `key_id`'s epoch equals the AAD epoch,
    and `type` maps to exactly one `purpose`; any inconsistency is
    refused. Every record for a client carries the person record's
    `no-ai` value: `check` flags a mismatch, any `true` wins, and when
    the header says `true`, `find`/`context` skip the record for agent
    output without decrypting.
15. **Rollback replay:** restore an older version of an encrypted file
    (valid AAD, stale `no-ai: false`) via an unsigned commit; `find` and
    `context` must refuse with a hard error and withhold the record. The
    same restore introduced by a trusted-signed commit is honored.
16. **Recovery public key pinning:** swap the recovery public key in a
    vault-config copy; manifest verification and recovery unwrap must use
    only the off-vault pinned value in `~/.config/confidant/` — the
    swapped vault copy authorizes nothing.
17. **Inbox rotation drain-then-destroy:** rotate the inbox key; items
    encrypted to the old key still decrypt during the rotation window
    (old-then-new); after `inbox rotate --finish`, the old private key is
    gone from the keychain and an item sent to the old key fails closed
    with `E_INBOX_CRYPTO`.
18. **Shred triggers inbox rotation (drain-then-destroy):** right after
    `keys shred`, the new inbox keypair is active (pins updated), the old
    private key is still present in the keychain, and the output lists the
    pending `inbox rotate --finish` among its leftover limits. After
    `inbox rotate --finish`, the old key is gone from the keychain, the
    shredded client's old form answers in inbox history are unreadable,
    and an item sent to the old key fails closed with `E_INBOX_CRYPTO`.
19. **Retired recovery recipients:** after a recovery rotation (`recover`
    or `keys shred`), the retired and new recovery age recipients are
    recorded in `keys/recovery-recipients.toml`; a device-add request that
    reuses a retired recipient is refused, and stays refused even after a
    later commit erases the entry (the union spans git history).
20. **Writer cert verification (design §8b, spec §14):** a writer cert
    verifies against the anchor; a cert transplanted from another vault
    fails; a forged cert fails; a cert with an unknown verb, unknown
    type, malformed client id, or lifetime over 30 days fails as a
    whole (never ignored); a missing `signer` verifies as operator.
    Cert-date ordering is well-formedness: a future-issued cert
    (`issued_at` after the verifier's clock) fails new acceptance; a
    reversed interval (`issued_at >= expires`) and an
    `issued_at == expires` cert fail verification outright, including
    history re-verification; a cert with `issued_at < expires` and a
    lifetime within 30 days passes the ordering check (the window
    check itself applies to new acceptance only).
21. **Writer field-level rule (the worked example, spec §14):** previous
    verified manifest `seq = 4`, recipients `{laptop, phone}`,
    commitments for epoch 3. A writer-signed candidate at `seq = 5`
    that adds a recipient is **refused before its signature matters**,
    even though the signature verifies under a valid writer cert.
    Variants refused the same way: a changed commitment hex, a dropped
    recipient, an edited `label`/`scope_ref`, a moved epoch, and a
    writer-signed manifest with no previous verified manifest (first
    manifest). The positive control — identical recipients and
    commitments, `seq = 5`, matching signer binding — is accepted
    (subject to the remaining checks).
22. **Writer revocation by sequence:** revoke a writer at manifest
    high-water 12 for a client; a writer-signed manifest at `seq = 12`
    or below for that client keeps verifying, one at `seq = 13` is
    rejected; a revocation signed by the operator and one signed by
    the recovery key are both accepted, one signed by any other key is
    refused; restoring a pre-revocation `revoked.toml` (file `seq`
    below the off-vault mark) is refused.
23. **Writer concurrency:** two writers sign different manifests at the
    same `seq`; the first pushed wins, the second is refused as a fork
    (`E_MANIFEST_FORK`), and the loser re-signing on top at a higher
    `seq` against the new head is accepted. An equal-`seq`,
    byte-identical re-push is accepted as idempotent.
24. **Writer SSH commit signing and commit authorization:** allowed
    signers derived from verified in-vault certs accept a commit
    signed by an active writer's key (principal `writer_id`, within
    its validity window) and reject a commit signed by a revoked or
    expired writer's key and one signed by an unknown key; a committed
    allowed-signers file in the vault is never used as authority.
    Backdated expiry: a commit signed after expiry but backdated
    inside the cert window is refused as a new head (the verifier's
    clock, not `valid-before`, is the boundary). Commit
    authorization: a validly signed commit with no manifest change
    holding an out-of-scope record change is refused; a permitted
    ledger-only commit is accepted; a ledger commit that rewrites an
    existing line is refused; a writer commit touching
    `keys/writers/` is refused; a writer-signed merge commit is
    checked against each parent. Migration: an existing
    operator-signed vault still verifies; the first writer cert is
    granted to the host holding the copied operator key; that copy is
    retired; old commits and manifests still verify; a fresh clone
    verifies a writer-signed manifest with only the off-vault anchor
    and the in-vault cert.
25. **Reader gate:** a vault above the reader's CLI version
    (`minimum_reader_version`) is refused with `E_READER_TOO_OLD`
    before any manifest verification, naming required vs actual
    version — never reported as tampering. The implementation must
    also demonstrate that a pre-gate binary refuses a writer-capable
    vault via `E_SPEC_UNSUPPORTED` before meeting a writer-signed
    manifest.
26. **Acceptance checkpoint and high-water scoping (spec §14):**
    reopening a chain already accepted up to `seq = 12` verifies its
    `seq = 11` link as history and advances to a new `seq = 13`
    head, while a fresh candidate at `seq = 11` offered as a new
    head after `seq = 12` is refused as a rollback. Newly introduced
    ancestry: on a fresh clone, a chain whose tip is signed by a
    valid narrow-scope writer but whose ancestor is a backdated
    broad-scope commit signed after expiry is refused in full (the
    ancestor is new acceptance, not history); the same chain, once
    accepted and checkpointed, re-verifies its ancestors as history
    without re-checking the expiry window. A lost checkpoint forces
    a fresh-introduction check of the whole chain, with a diagnostic
    naming the missing checkpoint.
27. **Recovery-rotation checkpoint (spec §14):** writer-signed
    history still verifies after operator rotation, after `recover`,
    after `keys shred`, and after fresh-device recovery, through the
    checkpoint chain; a writer cert signed only by the retired
    recovery key is refused for new acceptance; a forged checkpoint
    (bad signature, wrong domain, broken chain, or a history range
    that does not cover the commits it is used for) is refused; a
    post-rotation revocation file with lower high-waters than the
    checkpoint records is refused, so a recovery cannot reset a
    revoked writer; and history depending on a retired recovery key
    with no checkpoint is refused with a diagnostic naming the
    missing checkpoint and the retired key id.

## 13. What changes in the spec

This is the milestone 2 implementation PR. Format changes from spec 0.1
(now normative in spec 0.1 §14, Encryption):

- **Manifest v2**: `recipients.toml` gains `[[commitments]]` (key
  commitments for every retained epoch, §4); `vault_id` is bound in the
  signed manifest bytes, not stored in the file itself, binding the
  manifest to the vault. Readers must reject manifests without
  commitments (fail closed).
- **Key id charset**: `[a-z0-9-]`, `recovery` reserved (§4).
- **Envelope**: `key_id` is `<client_id>/e<epoch>` where `client_id` is the
  record owner's key holder (for `n-`/`i-` records, the person's `p-…` id,
  §2); the AAD binds both record ULID and client id; duplicate header keys
  are rejected (§5).
- **AAD**: adds a `client_id` component after `ulid` (§5).
- **Writer certificates (§8b, spec §14, issue #779)**: a minor format
  change, not a patch — new `keys/writers/` tree and cert domain
  `confidant-writer-cert-v1`, new optional signer fields in
  `recipients.toml`, new root-signed `keys/writers/revoked.toml`
  (domain `confidant-writer-revoked-v1`), and a new defined
  `confidant.toml` `[crypto]` key, `minimum_reader_version`. The
  manifest signature domain stays `confidant-manifest-v2`. Operator-
  and recovery-signed manifests verify unchanged.
- **Fix round (spec §14, 2026-10-30)**: the commit authorization
  rule for every writer-signed commit (normative, no new file
  type); ordered cert-date interval rules (no new file type);
  recovery checkpoints — new `keys/recovery-checkpoints/` tree and
  domain `confidant-recovery-checkpoint-v1`, a minor-format addition
  in the same minor bump. The acceptance checkpoint is off-vault
  reader state next to `trust.toml`, not a vault format change.

These are documented here; the normative spec 0.1 edits land in a
follow-up after crypto review (issue #85).

## 14. Decisions I made

Where the sources were silent, I picked the simpler option:

1. **X25519/age for key wrapping, XChaCha20-Poly1305 for content** —
   standard, audited crates; the AEAD layer is adapted from cr per ADR-13,
   not invented.
2. **One data key per client (person)**, not per record and not per vault —
   matches per-client shredding (ADR-4).
3. **Epoch-tagged keys; no re-encryption on rotation** — old epochs stay
   readable by still-authorized parties (Silas's call: agree, epoch
   model; the stale ADR-5 consequences sentence is fixed separately —
   see #20 and #22).
4. **`no-ai` stays plaintext** in the outer envelope so `find`/`context`
   fail closed without keys (§9b item 2).
5. **Trust anchor outside the vault** (`~/.config/confidant/` `[trust]`,
   per ADR-4/ADR-10); the same anchor covers commit signatures.
6. **Recovery phrase derives two keys** (X25519 for age unwrap + Ed25519
   for trust-anchor signing) via HKDF, so bare-phrase recovery can
   authorize the new device.
7. **Agent key distribution out of scope** for milestone 2; scopes are
   enforced locally by the CLI.
8. **Vault alias-lookup key** (not per-client derived) per ADR-2's
   `HMAC(vault lookup key, normalized value)`, wrapped to devices like a
   data key.

## 15. Questions for the reviewer

All six had Silas's call (2026-10-08); resolved below with one-line
answers and issue links, so the milestone 2 implementation builds from
this doc alone.

1. **Envelope format:** outer front matter (`id`/`type`/`no-ai`/`enc`/
   `key_id`/`nonce`) + base64 body. **Silas's call: agree — inline, one
   file per record** (#13). The outer header is bound into the
   length-prefixed AAD; header `id` must equal the AAD ULID, `key_id`'s
   epoch must equal the AAD epoch, and `type` must map to exactly one
   `purpose`. Flipping any header field (especially `no-ai: true` →
   `false`) makes decrypt fail (tests 1, 14).
2. **`no-ai` in plaintext:** **Silas's call: agree — keep the plaintext
   outer header, now authenticated** (#14). The boolean leak is
   acceptable: it reveals which opaque IDs opted out of AI, never who
   they are. `no-ai` is per client: every record carries the person
   record's value, `check` flags mismatches, any `true` wins, and a
   `true` header means `find`/`context` skip the record without
   decrypting (test 14).
3. **Recovery phrase encoding:** **Silas's call: agree — 24-word list**
   (#16). 256-bit entropy with the BIP39 English wordlist and checksum,
   fed straight into HKDF (no passphrase, no BIP39 PBKDF2 seed step);
   `recover` validates the checksum with "typo in word N"-style errors;
   the phrase is never logged or written to disk (test 13).
4. **Agent key distribution:** **Silas's call: agree — out of scope for
   milestone 2, with one rule written down now** (#17). No agent private
   key ever moves: an agent generates its X25519 keypair on its host and
   hands over only the public key; the operator verifies the fingerprint
   out of band, then signs the scope doc and manifest change like a
   device add (§7).
5. **Trust anchor location:** **Silas's call: agree —
   `~/.config/confidant/` `[trust]` with flag/env override** (#18).
   Nothing inside the vault can point at or override the anchor;
   restrictive permissions (0700/0600) with warnings; the anchor set is
   the operator Ed25519 key plus the recovery Ed25519 key pinned at
   `init`; a missing anchor is a hard error (§4).
6. **Recovery dual-key derivation:** **Silas's call: agree — one phrase,
   two domain-separated keys** (#19). HKDF-SHA256 over the phrase
   entropy with a fixed salt and versioned `info` strings
   (`confidant/recovery/x25519/v1`, `confidant/recovery/ed25519/v1`);
   in-vault copies of the recovery public halves are informational only
   and never trusted (test 16).

Resolved in the 2026-10-08 review round (Silas): shredding is key
destruction — delete wrappings, rotate every recipient that ever held one
(recovery included), destroy old private keys (#15, §8); rotation keeps
the epoch model, and the ADR-5 consequences erratum is a separate docs
change, not here (#20, #22).

## 16. Changes from the pre-architecture draft (2026-10-08)

The first draft was written without the architecture doc. Against ADRs
1–15 this revision: switched alias HMAC to the vault lookup key (was
per-client HKDF) per ADR-2; specified length-prefixed AAD and a key id in
the envelope per ADR-4; noted the AEAD adaptation from cr per ADR-13;
added the trust anchor's ADR-10 role (signed commits) and the
first-commit-fingerprint alternative; added record types to agent scopes
(ADR-4's pipeline-key example); made `keys revoke` output state the
ADR-5 limit plainly; gave the recovery identity an Ed25519 trust-anchor
role and added the yearly paper-copy `doctor` reminder (ADR-15, §8);
added commit-message/trailer plaintext rules and index/cache hygiene (§3);
mirrored the §4 threat-model table; aligned the test plan with ADR-14
(throwaway keys, round-trip in CI); and replaced the open questions the
doc settles (envelope crypto, wrapped keys in git, alias key scope, trust
anchor location) with the two genuine tensions found (Q3 shredding vs
history, Q8 rotation re-encryption).

## 17. Changes from Silas's review round (2026-10-08)

Per Silas's "change, then sign-off" review (#21): the outer envelope
header is now authenticated via the AAD, so `no-ai` cannot be flipped with
only git write access (§5); shredding is specified as key destruction —
delete wrappings, rotate every recipient that ever held one (recovery
included), destroy old private keys (§8); the CLI never trusts in-vault
copies of anchor or recovery public keys (§4); HKDF-SHA256 domain
separation is now explicit (§9); onboarding takes only the public key and
no private key ever moves (§6); BIP39 entropy goes straight into HKDF with
no passphrase, plus a never-log-the-phrase test (§9, §12); git-crypt
compatibility notes added (§5); the two resolved questions (shredding,
rotation) were removed from §15, leaving six open. The ADR-5 consequences
sentence fix is a separate docs change (for Frank's merge decision), not
part of this doc.

## 18. Changes from Silas's re-review round (2026-10-08)

Per Silas's "change. One short round, then I sign off" re-review (#21):
rollback/replay defense — `find`/`context` emit only files whose
introducing commits verify against the trusted-signers list, so an
unsigned rollback with a stale `no-ai` is refused (§5, test 15);
per-client `no-ai` rules — every record carries the person record's value,
`check` flags mismatches, any `true` wins, and a `true` header means skip
without decrypting — plus header consistency checks (`id` = AAD ULID,
`key_id` epoch = AAD epoch, `type` maps to exactly one `purpose`) (§3, §5,
test 14); shredding test rewritten — old private keys destroyed, the
shredded client's historical wrappings unopenable, other clients still
decrypt under the new keys — and `keys shred` states its leftover limits
and issues a new recovery phrase (§8, test 8); trust-anchor hardening —
anchor set is operator key + recovery Ed25519 key pinned at `init`, no
vault path can override the anchor, 0700/0600 with warnings if looser, a
missing anchor is a hard error, and the old recovery key leaves every
anchor set after `recover` (§4); recovery public halves pinned in
`~/.config/confidant/`, vault copies informational only (§9, test 16);
rotation and revocation re-wrap all retained epochs to the current
recipient set (§6, §8); the stale ADR-5 caveat in §8 is dropped. Also in
this revision: `docs/architecture.md` is brought into this PR with §9b
item 5 updated per Frank's 2026-10-08 change, and the Status line no
longer requires an outside human reviewer before milestone 2 code.

## 19. Non-blocking cleanups from the sign-off (2026-10-08)

Per Silas's sign-off comment on #21 (fold into this PR): test 7 now also
asserts the revoked party's old-epoch wrappings are gone from the working
tree, and names who can still read old-epoch ciphertext
(still-authorized parties); §14 item 3 points at #20 and #22 instead of
the removed §15 Q8; the six §15 questions moved under Resolved with
Silas's one-line calls and issue links, so the implementation builds from
this doc alone.

## 20. Inbox-key review round (2026-10-08)

Per Silas's "change" review of PR #60 (#56): `keys shred`'s leftover-limits
list now names the pending `inbox rotate --finish` — until it runs, the old
inbox key still exists on the inbox device (§8); §2's key hierarchy gains
the vault-wide inbox keypair (private half in the OS keychain on the inbox
device only, never in git, not wrapped to devices or the recovery
identity); §9's HKDF `info` strings now match §15 Q6 and the implementation
(`confidant/recovery/x25519/v1`, `confidant/recovery/ed25519/v1`); test 7
states the two revocation facts separately per the #21 wording nit
(still-authorized parties keep reading all retained epochs; the revoked
party can still decrypt what it copied before revocation).

## 21. Inbox-key precision round (2026-10-08)

Per Silas's second "change" review of PR #60: §8 step 2 splits the inbox
key out as its own sub-step (2b) — it never holds a client-key wrapping
and is never a re-wrap target — and step 3 notes the old inbox key is
destroyed by `inbox rotate --finish`, not with the other old keys; test
18 asserts both states (after `keys shred`: new keypair active, old key
still present, pending `--finish` listed; after `--finish`: old key gone,
old-key items fail `E_INBOX_CRYPTO`); §8a specifies the lost-key path
(old key unavailable → new keypair generated on the new inbox device,
drain and `--finish` skipped) and the non-inbox-device shred case
(records the pending rotation, tells the operator to run it on the inbox
device, stays incomplete until then); §9 notes `confidant recover` does
not restore the inbox key (run `inbox rotate` on the new device and
re-pin); the Scope line says "this doc's §8a".

## 22. Keychain backup-precision round (2026-10-10)

Per Silas's review of PR #94 (non-blocking item 6): §8a.2 no longer argues
the keychain removes the backup exposure that `~/.config` files have — the
macOS login keychain (`~/Library/Keychains/login.keychain-db`) and GNOME's
keyring files are in Time Machine backups too, encrypted under the login
password, and deleting an item doesn't reach old backup copies. The doc
now says the keychain *narrows* that exposure (encrypted at rest, plus a
per-app access list on macOS); §8 already lists old keys lingering in OS
keychains or OS backups as a leftover limit. §11 notes the Linux Secret
Service caveat: any process in the user's session can read an unlocked
collection.

## 23. vault:shared key implementation (2026-10-10)

Implements the §2 record-type-to-key mapping from Silas's #62 call in
`confidant-crypt`: new reserved `client_id = "vault:shared"` next to
`vault:lookup`, living at `keys/shared/` with the standard per-client
machinery (manifest v2 with `seq`, key commitments, rotation, revocation,
recovery wrapping — no new primitives, no new format). `KeyStore` maps the
reserved id in `manifest_dir` (also fixing `wrapped_dir`, `init_client`,
`shred`'s delete, and `historical_recipients` to resolve through it, so no
`keys/vault:shared` path is ever formed). New
`client_id_for_record(record_type, person)` picks the key: `p`/`n`/`i` and
`d` with a `person` go to that person's key, `o` and person-less `d` go to
`vault:shared`; it takes no operator parameter, so routing through the
operator's own person record is impossible by construction. The milestone-3
writer calls it to pick the target key and re-encrypts a deal under the new
person's epoch in the same signed commit when the deal's `person` changes.

Guarantees (stated behavior, reviewed in #87): `shred` refuses the reserved
client ids `vault:lookup` and `vault:shared` up front, before the verify
pass, leaving `keys/vault` (including `lookup.age`) and `keys/shared`
untouched; it fails closed — every file under `keys/` byte-identical — when
any initialized dir under `keys/` other than `vault/` is absent from
`all_clients` (the strand check, mapping dir names back through
`client_id_for_dir`, so an omitted `vault:shared` is caught). A blank or
whitespace `person` errors for every record type, `org` included; only
`None` routes to `vault:shared`. `client_id_for_record` requires the `p-`
person-id prefix and rejects `/`, `\`, `..`, and reserved `vault:` ids.


## 24. Lookup key device-only (2026-10-11)

Per Silas's call on #98 ([crypto-review]): the vault lookup key is
device-only by design, never recovery-wrapped. §10 states the rule and the
rationale (HMAC-only key; alias values are encrypted under recovery-wrapped
client keys, so recovery rebuilds the index with a fresh key; not wrapping
keeps the shred/recovery re-wrap surface small). §9 notes `confidant
recover` does not restore the lookup key. §6 makes the add-device handoff
explicit: a new device must receive the current lookup key re-wrapped from
an existing device. `init_lookup_key` / `write_lookup_raw` unchanged.

## 25. Follow-ups from #151, #149 review (2026-10-12)

Closes the non-blocking follow-ups on #153 plus the `recover` anchor file
(#152). No new cryptographic primitive.

- **Retired recovery recipients (#153 nit 7).** New spec §14 file
  `keys/recovery-recipients.toml` (append-only, unsigned). `shred` and
  `rotate_recovery` record the retired and new recovery age recipient;
  `ever_seen_pubkeys` unions the working-tree copy with every historical
  git version, so a device-add request reusing a retired recovery
  recipient is refused (it would otherwise re-open a shredded client).
  Reading the union across history means a later commit cannot erase the
  entry. Unsigned is deliberate: the set only ever enlarges the denylist.
- **Re-created client ids (#153 nit 1).** `ever_seen_pubkeys` now skips a
  shredded client's *current* manifest only when the client is shredded
  **and absent** from the live set, so a client shredded then
  re-initialized under the same id still contributes its current
  recipients.
- **`--initiate` with `CONFIDANT_DEVICE_KEY` (#684, supersedes #153 nit 4
  for this command only).** Headless enrollment uses the env identity as
  this new device (same as `init`, #650): `--initiate` emits that pubkey
  and does not write a keychain. It does not treat the env var as
  "already enrolled". `--from-request` still refuses a previously-seen
  pubkey, so re-using an already-enrolled identity fails on the approve
  side. `keys shred` still refuses while the env var is set. There is no
  `--key-out`; keys never live in files. Without an env identity and
  without a reachable keychain, `--initiate` fails closed and names
  `age-keygen` + `CONFIDANT_DEVICE_KEY`.
- **Label validation (#153 nit 6).** `keys device-add` labels now reject
  control characters (rather than stripping them) and require ASCII
  alphanumerics plus ` -_.()`.
- **Pre-commit recovery text (#153 nit 5).** A `--from-request` whose
  pre-commit `check` fails now prints the `git status` / `git checkout --
  keys/` fix, matching `add_recipient`'s error path.
- **`recover --anchor-file <path>` (#152).** Loads the trust anchor from an
  explicit file (validated before any key operation; refused inside the
  vault) instead of the config dir or the `keys/`-tree rebuild. The phrase
  must still match the anchor's recovery key; nothing is written to the
  config dir until it does.
- **Threat-model note (#153 nit 3).** §11 states that the history-derived
  shred checks (`shredded_clients`, `historical_recipients`, the recovery
  history union) fail open when `git` is unavailable, `git log` fails, or
  the clone is shallow. `keys device-add --from-request` now **fails
  closed** in that state; `keys shred`, `recover`, and `doctor` warn (JSON
  `warnings[]` + stderr, and a `shred-history` doctor check). Paths are
  read relative to the vault (`--relative`, `rev:./<path>`) and with
  `--full-history`, so a vault inside a larger repo or a side-branch merge
  no longer silently hides history.
- **`--anchor-file` hardening.** The phrase must match the anchor's
  **X25519 recovery recipient** too, not just its Ed25519 key; and when
  `keys/operator.toml` exists it is verified against the phrase and its
  operator key must match the file's. Only a vault with no certificate
  accepts the file's operator key — so a tampered anchor backup can never
  get the recovery key to certify an attacker's operator key. Refusals are
  `E_INVALID`.
- **Retired recovery recipients are written before any shred mutation**,
  and an existing-but-unparseable `recovery-recipients.toml` fails closed
  rather than being silently overwritten; the file is written via
  temp-and-rename. The temp file uses the vault's `.confidant-tmp-` leftover
  prefix, is removed on error, and the CLI sweeps any stale copy before
  staging `keys/` (so a crash cannot commit one — #156).
- **Deferred:** a real-`keys shred` path through the shredded-only-pubkey
  test (#153 nit 2) needs scoped recipients (#138); tracked separately.

## 26. Delegated writer keys: Silas's review round (2026-10-27, issue #779)

Design-only revision answering the crypto-review on #779, the gate for
#731. No code, no key handling, no envelope/AAD changes in this
revision. Normative text is spec §14 ("Writer certificates"); the
rationale is §8b above. This section records what changed from the
#779 proposal and what still needs a decision, so the implementation
PR does not have to re-derive it.

- **Blocker 1, closed in design:** the field-level rule is now
  normative (spec §14): a writer-signed manifest must match the
  previous verified manifest on recipients, commitments, epoch, vault,
  and client, with only `seq` and the signer fields moving, checked
  before the signature matters — plus the worked refusal example (a
  writer-signed manifest adding a recipient is refused despite a valid
  signature) and its variants. The carrying commit's content changes
  must also be in the writer's scope.
- **Blocker 2, closed in design:** revocation is keyed to manifest
  `seq`, not time: `revoked.toml` entries carry a per-client manifest
  `seq` high-water, signable by the operator or the recovery key, with
  an off-vault revocation file-`seq` high-water covering rollback.
  At/below the high-water keeps verifying; above it is rejected.
- **Q4, brought into scope:** the writer's Ed25519 key doubles as its
  SSH commit-signing key, allowed signers derived at verification time
  from verified in-vault certs (principal `writer_id`,
  `valid-before` from cert `expires`, revoked writers dropped). This
  is what lets #729's copied operator key be retired.
- **Other answers incorporated:** Q1 in-vault; Q2
  `signer = "writer:<id>"` plus cert `seq`/digest inside the signed
  TOML (missing signer = operator); Q3 separate sign/encrypt keys; Q5
  offline 30-day lifetimes + `doctor` warning when the last fetch is
  older + off-vault high-water on sync; Q6 re-issue on root rotation
  with a short overlap (at most one cert lifetime); Q7 new type and
  domain `confidant-writer-cert-v1` with a closed verb set (unknown
  verb fails verification).
- **Concurrency and format:** first pushed wins, loser re-signs,
  equal `seq` with different bytes is a fork (`E_MANIFEST_FORK`);
  equal `seq` byte-identical is an idempotent re-push. Minor bump, not
  a patch, with a vault minimum-reader-version gate
  (`E_READER_TOO_OLD`, checked before manifest verification) plus the
  spec-minor gate for pre-gate readers (`E_SPEC_UNSUPPORTED`).
- **Decisions made in this revision, for Silas/Frank to confirm:**
  (a) expiry gates new-head acceptance but is not re-checked when
  re-verifying already-accepted history for read/decrypt — otherwise
  history dies every 30 days; (b) "old-root certs stop verifying once
  the new operator cert is pinned" is read as a new-acceptance rule,
  with pre-rotation history preserved via the anchor-at-commit chain
  (operator cert at a historical commit verifies against the unchanged
  recovery key) — otherwise every rotation breaks history; (c) writer
  scope has no `"all"` client wildcard (unlike agent scopes); clients
  are enumerated; (d) `keys.init_client` is not a writer verb, because
  a first manifest has no previous verified manifest for the field
  rule to check; (e) cert-version resolution for new acceptance uses
  the highest cert `seq` across working tree and git history; (f) the
  manifest signature domain stays `confidant-manifest-v2` (the signer
  fields ride inside the already-signed TOML bytes).
- **Still open for the implementation PR (not decided here):** how the
  implementation enumerates changed entries from a commit diff for
  the commit-scope check; the exact CLI version string for the first
  `minimum_reader_version` value; and the demonstration (test 25)
  that a pre-gate binary refuses a writer-capable vault via
  `E_SPEC_UNSUPPORTED` before meeting a writer-signed manifest.
- **Explicitly not decided here:** no change to envelope, AAD, key
  wrapping, or the #711 custody model (referenced, not revised); no
  writer private-key handling; no implementation of #731. The §2
  `[crypto]` table gains `minimum_reader_version` when the spec minor
  carrying this section is cut — a one-line follow-up for that PR,
  not edited here, to keep this revision to spec §14 and this doc.

**Fix round, 2026-10-30 (Silas's and Frank's findings on `eba9ee6`,
PR #786).** Silas's conditional sign-off was withdrawn until six
items were addressed; all six are addressed in this revision, in
spec §14 unless noted:

1. Backdated-expiry wording: verifier-clock expiry for new-commit
   and new-head acceptance, `valid-before` as defense in depth,
   backdated post-expiry commit refused as a new head, fresh-clone
   tip as new acceptance, expiry-limits-new-writes / revocation-only
   -for-history corollary.
2. Commit authorization: a single rule on every writer-signed
   commit, manifest-free or not; signature identifies, the rule
   authorizes; step 6 points to it; per-parent merge-commit checks.
3. Newly introduced ancestry: acceptance checkpoint partitioning
   previously accepted history from newly introduced ancestry;
   fresh clone checks the whole chain; decision (a) narrowed to
   checkpoint-covered ancestry.
4. High-water scoping: step-7 check applies to the candidate head
   only; historical links verify without it; chain reopen/advance
   test added (§12 item 26).
5. Cert dates: ordered interval, no skew allowance, ordering
   malformed fails outright including history, window gates new
   acceptance only (§12 item 20).
6. Recovery rotation: checkpoint chain binding the old recovery
   pubkey to a history range, fresh-device rule, no-checkpoint
   fail-closed, high-waters survive (§12 item 27).
   Non-blocking suggestion (e), adopted: the per-writer cert `seq`
   high-water is recorded off-vault as part of the acceptance
   checkpoint, rather than left to the implementation PR. New
   choices for Silas/Frank to confirm in this round: no clock-skew
   allowance, and writer-signed merge commits checked against each
   parent rather than refused outright. The §2 `[crypto]` one-line
   follow-up and the open implementation items above are unchanged.
