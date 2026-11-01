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
or credentials. Reproduce against the fake-data
[demo vault](examples/demo-vault) (people like "Ada Example" exist precisely
for this) or construct a minimal temporary vault. A report containing real
PII will be deleted on sight and you will be asked to re-file with fake
data.

## Scope

In scope:

- The privacy allowlist (`no-ai`, the §12 cleared set): any path that lets
  an agent-facing surface (`find`, `context`, `allowlist`, MCP, the QMD
  corpus) return content it should withhold.
- The write path (`record add`, `note add`, `log session`, `log touch`,
  `import`) and the `check`-before-commit gate, including anything that
  corrupts a vault, drops data, or commits without the gate passing.
- Git and sync behaviour: transport checks, `confidant sync` refusals, and
  anything that could push a vault somewhere the operator did not intend.
- Supply-chain integrity of releases: `cargo dist` artifacts, checksums,
  build-provenance attestations, and crates.io trusted publishing.

Out of scope:

- The `examples/demo-vault` contents (deliberately fake data).
- Third-party components Confidant integrates with but does not ship: QMD
  search, git, the OS credential store, and the model providers agents call.
  Report those issues to their own projects (we will happily link).
- The confidentiality of a vault you placed somewhere readable: records are
  plaintext on disk by design (ADR-4), so a public repo, an unencrypted
  disk, or a shared backup is a deployment mistake, not a vulnerability.
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

## Standing design decisions (not vulnerabilities)

Two decisions are deliberate and documented, so a report that only restates
them will be closed:

- **Records are plaintext on disk** in a private repo on a full-disk
  encrypted machine (`docs/architecture.md` ADR-4). There is no
  application-level secrecy layer to bypass.
- **`no-ai` is an exposure control, not access control.** It keeps marked
  content out of agent-facing output; it does not make the files secret from
  the operator or from anything with a shell on the machine
  (`docs/threat-model-agents.md`).
