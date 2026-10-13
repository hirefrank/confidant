# Security Policy

## Supported versions

Security fixes go into the latest release only (currently `0.2.x`). Older
releases are best-effort: report against them and we will tell you whether
the issue reproduces on the current release. Pre-1.0, breaking changes bump
the minor version, so upgrading across a minor may need attention — the
[CHANGELOG](CHANGELOG.md) calls out anything that affects existing vaults.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Use one of
these private channels:

1. **GitHub private vulnerability reporting** (preferred): open the
   [Security tab](https://github.com/hirefrank/confidant/security) of this
   repo and choose "Report a vulnerability". This keeps the report visible
   only to the maintainer until it is resolved.
2. **Email:** frank@hirefrank.com with subject line `[confidant-security]`.

A useful report includes: what you think the impact is, steps to reproduce
(or a proof of concept), and a root-cause analysis if you have one.

### Please use fake data only

Confidant is built to hold other people's private notes, so reports must
never contain real client data — no real names, emails, notes, transcripts,
keys, or recovery phrases. Reproduce against the fake-data
[demo vault](examples/demo-vault) (people like "Ada Example" exist precisely
for this) or construct a minimal temporary vault. A report containing real
PII will be deleted on sight and you will be asked to re-file with fake
data.

## Scope

In scope:

- `crates/confidant-crypt` — key hierarchy, record envelopes, AAD binding,
  recovery, rotation, revocation, and shredding.
- The CLI write path that moves plaintext into and out of envelopes
  (`record add`, `note add`, `log session --note`, `reindex`, `find`,
  `context`) and the privacy allowlist (`no-ai`, the §12 cleared set) that
  gates what agents can read.
- Inbox signature verification and the merge pipeline (`inbox`,
  `inbox rotate`).
- Supply-chain integrity of releases: `cargo dist` artifacts, checksums,
  build-provenance attestations, and crates.io trusted publishing.

Out of scope:

- The `examples/demo-vault` contents (deliberately fake data).
- Third-party components Confidant integrates with but does not ship: QMD
  search, the OS keychain / Secret Service, and the model providers agents
  call. Report those issues to their own projects (we will happily link).
- Social engineering, physical access to trusted devices, and compromised
  model providers — these are documented assumptions, not vulnerabilities.
  See [docs/threat-model-agents.md](docs/threat-model-agents.md).

There is no bug bounty program. Public credit in the fix release notes is
the default; tell us if you would rather stay anonymous.

## What to expect

- Acknowledgement of your report within 5 business days.
- A remediation plan and timeline once the issue is confirmed. Critical
  issues are fixed as fast as possible and always within the 90-day
  coordinated-disclosure window (plus a 30-day extension if requested in
  advance and agreed); lower-severity issues ship with the next release.
- You will be kept informed of status until the fix ships, and the fix
  release notes will describe the issue once it is safe to do so.

## Known limitation (standing disclosure)

The milestone 2 encryption has had no outside review. This is tracked in
[#138](https://github.com/hirefrank/confidant/issues/138) and disclosed in
the README: until an independent audit lands, do not put other people's
data in a vault. Reports that restate this known limitation without a new
finding will be closed as duplicates of #138.
