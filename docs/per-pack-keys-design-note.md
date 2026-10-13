# Per-pack keys: when they would be needed (issue #178 / #160)

Issue #178 delivered the **policy layer** for per-pack access scoping:
an agent working in one pack can only read that pack's data through
`context`, `find`, MCP tools, and `allowlist` / `reindex` outputs
(see "Pack scoping" in `docs/privacy.md`). This note records when the
**cryptographic layer** — per-pack keys — would be needed, and what shape
it would take. It is a design note, not a build plan; per-pack keys stay
with #160.

## What the policy layer does and does not do

The policy layer stops an agent from over-reaching *through the tool
surface*: a coaching-scoped MCP call never returns personal notes, even
though the same vault holds them. It does **not** stop anyone who can
read the vault files directly. Encryption today is per-person, not
per-pack (`client_id_for_record` maps person/note/interaction → person
id, deal → person or `vault:shared`, org → `vault:shared`), and every
client holds the same recipient set. A scoped agent running on the
operator's machine, with the operator's device key, can decrypt
everything in the vault by reading the files — scoping never pretended
otherwise. Scoping is a guardrail for the agent's *behavior*, not a
cryptographic boundary against the operator.

## When per-pack keys would be needed

Per-pack keys become necessary when the threat model grows a second
reader whose access must be cryptographically narrower than the
operator's — that is, when *someone other than the operator* holds a
device key:

1. **A second device or service with narrower access.** E.g. a hosted
   coaching agent that should be able to decrypt coaching sessions but
   not personal notes, even if its host is compromised or curious.
   Today there is no such reader: every client is the operator's own.
2. **Multi-user vaults.** If two people share a vault (a household, a
   team) and each should decrypt only their packs' data, policy
   filtering is insufficient — the other user's client must be
   *unable* to decrypt out-of-scope records, not merely asked not to.
3. **Audit or compliance requiring cryptographic separation.** If a
   future requirement says "personal data must be undecryptable by the
   coaching service" rather than "the coaching service must not
   request it", only per-pack keys satisfy it.

Until one of those arrives, the policy layer is the right scope: it
solves the real, present problem (agent over-reach through tools) with
no key-format change, no migration, and no new failure modes.

## Shape if built

- **Client ids become per-(person, pack).** Today a record's client id
  is derived from its person (or `vault:shared`). Under per-pack keys it
  would be derived from (person, owning pack) — e.g. a coaching note
  about Ada encrypts under a key whose recipients are exactly the
  devices authorized for (Ada, coaching). Core-owned identity (name,
  aliases) stays under the per-person key, readable by every pack.
- **Unattributed records stay per-person.** Anything the registry
  cannot attribute to a pack keeps the current per-person keying; the
  policy layer still hides it from scoped agents.
- **Recipient sets narrow, never widen.** A device authorized for
  (Ada, coaching) must not gain (Ada, personal) by asking. Key
  provisioning becomes a per-(person, pack) grant, and #160's scoped
  recipients work is the prerequisite.
- **Migration is a re-encrypt.** Existing records would need
  re-encryption under the new client ids — the same shape as #160's
  recipient-set changes, and the reason the two issues are linked.

## Relationship to #160

#160 (scoped recipients) is the prerequisite: per-pack keys are a
special case of "not every device holds every key". #178's policy layer
deliberately does not pre-decide #160's key format; it only requires
that attribution (which pack owns a record/field/line) be derivable at
read time from the registry, which is the same attribution a key layer
would need at encrypt time.
