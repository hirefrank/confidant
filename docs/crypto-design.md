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
  lives in ~/.config/confidant/ (flag or env var also allowed)

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
  tokens, billing tags (`paid`/`pps`/`comp`), `src:` provenance IDs.
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

The outer header carries one boolean, but the rule is per client:

- Every record for a client carries the person record's `no-ai` value in
  its header.
- `check` flags a mismatch between a record's header value and the
  person record's value (new finding code in the milestone 2 spec
  update).
- Any `true` on that client wins: if the person record or any of the
  client's records says `no-ai: true`, the client is treated as opted
  out.
- When the header says `true`, `find` and `context` skip the record for
  agent output without decrypting at all — the plaintext is never
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
  The operator wraps each authorized client data key (and the vault lookup
  key) to the new public key, appends to `recipients.toml`, re-signs the
  manifest. One commit per change, and the change itself must be in a
  commit signed by an already-trusted key (ADR-4).
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
  parties — rotation does not re-encrypt content.
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
  it was written down, exactly like `init`. `keys shred` also states its
  leftover limits plainly in its output: decrypted copies already on
  devices, `.confidant/` caches and search indexes on every device, old
  keys lingering in OS keychains or OS backups, copies outside
  Confidant entirely (e.g. Drive transcripts), and — until
  `confidant inbox rotate --finish` has run — the old inbox key.
  Shredding cannot reach any of these.

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
  run `inbox rotate` on the new device and re-pin (§8a).

## 10. Alias HMAC

Ledger `alias` lines carry `hmac:HEX`, never plaintext (spec §6, ADR-2,
ADR-9). Following the cr spike's keyed-digest reasoning (a plain hash can
be dictionary-attacked), the value is:

```
hmac = HMAC(vault_lookup_key, normalized_value)
```

The **vault lookup key** is generated at `init` and wrapped with age to each
device/agent like a data key (`keys/vault/lookup.age`, covered by the
signed recipient manifest). The real alias values live encrypted in the
profile. `HEX` is at least 32 hex chars (spec §6). Importers match on
aliases by recomputing the HMAC of the normalized value.

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
- Rubber-hose / compelled disclosure of the recovery phrase (it reads the
  whole vault — ADR-15).

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

## 13. What changes in the spec

This is the milestone 2 implementation PR. Format changes from spec 0.1:

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

