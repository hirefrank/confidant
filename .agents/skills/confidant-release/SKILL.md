---
name: "confidant-release"
description: "Cut a Confidant release via version tag push (ADR-14): bump version and CHANGELOG, merge to main, push tag, verify dist binaries and crates.io trusted publish."
---

# Confidant Release

Tag-driven release (ADR-14, `docs/architecture.md`). Pushing a version tag
to `main` builds binaries with cargo-dist, creates the GitHub Release,
attests build provenance, and publishes to crates.io via OIDC trusted
publishing — in dependency order `confidant-crypt` → `confidant-core` →
`confidant-cli`. There is no manual `cargo publish` and no registry token.

This skill lives in the repo (`.agents/skills/`). It is maintainer
workflow, not operator workflow: never put it under
`crates/confidant-cli/skills/` (that tree embeds into the `confidant`
binary and ships to every user via `setup`).

## Versioning

Pre-1.0: a breaking change bumps the minor (`0.1` → `0.2`); a fix bumps
the patch (`0.1.0` → `0.1.1`). The CLI version and the spec version are
independent (ADR-1).

Update `version` in `[workspace.package]` in the root `Cargo.toml` and
every sibling `version =` line in `[workspace.dependencies]`
(`confidant-crypt`, `confidant-core`). All crates release in lockstep.

## Every release

### 1. Prep PR on a branch

- Bump versions as above; run `cargo check` to update `Cargo.lock` and
  commit both.
- Move `[Unreleased]` in `CHANGELOG.md` to `[X.Y.Z] - YYYY-MM-DD` with
  the entries. Keep the `Keep a Changelog` format and fix the compare
  links at the bottom (`[Unreleased]`, `[X.Y.Z]`).
- `main` must be green before merge (see `.github/workflows/ci.yml`):
  `cargo fmt --check`, clippy with `-D warnings`, tests, `confidant
  check` on the demo vault, `cargo deny check`, `cargo audit`.
- One PR per release. No merge without the maintainer's explicit
  approval. PR body: title, summary, spec changes (or "none"), test
  evidence, **Decisions I made**.

### 2. Tag from `main` after merge

```sh
git checkout main
git pull --ff-only
git tag vX.Y.Z   # match the version just merged, e.g. v0.2.0
git push origin vX.Y.Z
```

Tags match `v[0-9]+.[0-9]+.[0-9]+*` (see `on:` in
`.github/workflows/release.yml`). Release tags come only from `main`;
prerelease suffixes (e.g. `v0.2.0-rc.1`) ship a GitHub prerelease only
and skip crates.io.

### 3. Verify

- `gh run watch` on the Release workflow, or check
  `gh release view vX.Y.Z`: dist binaries (macOS arm64 + Intel, Linux,
  Windows), shell/powershell/homebrew installers, SHA-256 checksums.
- Build-provenance attestations: `gh attestation verify`.
- crates.io: `confidant-crypt`, then `confidant-core`, then
  `confidant-cli` appear at the new version (trusted publishing via
  OIDC; there is no `CARGO_REGISTRY_TOKEN` — do not add one).

## Why this order

crates.io resolves dependencies at publish time. If `confidant-core` is
published before `confidant-crypt`, the index won't have the crypt
version core depends on yet, and the publish fails. The
`publish-crates-io` job already enforces crypt → core → cli; this is
why, not something to re-implement.

## Do not

- `cargo login` / `cargo publish` by hand (first publishes were a
  one-time manual step; trusted publishing owns it now).
- Add secrets to workflows or give any Action decryption keys (CI never
  holds vault keys; crypto tests use throwaway keys).
- Regenerate `release.yml` with `cargo dist generate` without re-applying
  the hand trims noted at the top of that file (push-tags-only trigger,
  attest + publish jobs, action pins, verified dist install).
- Reuse a version number.

## Permanence

Publishing is permanent. You can **yank** a version (new projects stop
picking it up) but you can never delete it or reuse its version number.
If the audit finds a defect, the fix ships as a new version; published
versions are yanked, not deleted (§9b item 5).
