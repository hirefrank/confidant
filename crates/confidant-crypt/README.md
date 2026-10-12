# confidant-crypt

Encryption primitives for [Confidant](https://github.com/hirefrank/confidant)
vaults: per-client data keys wrapped with age (X25519), XChaCha20-Poly1305
content encryption with length-prefixed AAD binding, signed recipient
manifests against an off-vault trust anchor, scoped agent keys, epoch
rotation, crypto-shredding by key destruction, and BIP39 recovery.

## ⚠ Not independently audited

This crate is security-critical code and **has not been reviewed or audited
by anyone outside the project**. It is published so that the Confidant CLI
and its dependencies can be installed from crates.io — not as a
general-purpose crypto library. It is not a stable API surface yet.

**Do not use it to protect data you cannot afford to lose or expose** until
the outside audit lands. The audit is tracked in the main repository as
issue [#138](https://github.com/hirefrank/confidant/issues/138); the design
it implements is documented in `docs/crypto-design.md` there.

Two related caveats from the main repository README (which is the
authoritative project status):

- the Confidant CLI does not encrypt vault content on write yet, so a vault
  is still plaintext in git despite this crate existing;
- see [the README status
  section](https://github.com/hirefrank/confidant#status-two-things-are-not-ready-for-other-peoples-data)
  for the current disclosure.

## License

Apache-2.0.
