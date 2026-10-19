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

**`confidant-crypt` has not had an independent audit.** Use your own
judgment before storing other people's sensitive data. This is tracked in
the main repository as issue
[#138](https://github.com/hirefrank/confidant/issues/138); the design it
implements is documented in `docs/crypto-design.md` there.

Two related caveats from the main repository README (which is the
authoritative project status):

- the Confidant CLI now encrypts record content on write for keyed vaults
  (`record add`, `note add`, `log session --note`); a vault that opts out
  with `[crypto] mode = "plaintext"` stays plaintext in git;
- see the [Security status
  section](https://github.com/hirefrank/confidant#security-status-no-independent-audit-yet)
  for the current disclosure.

## License

Apache-2.0.
