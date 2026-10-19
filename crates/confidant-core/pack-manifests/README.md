# Pack manifests (embedded in confidant-core)

In-crate copies of the manifests (and, for the built-in, its pack
directory) that the binary compiles with `include_str!`, so `cargo
publish` and `cargo install` work: crates.io tarballs do not include the
repo-root `../../packs`.

| Path | What |
|---|---|
| `personal-0.2/` | The embedded declarative built-in `personal@0.2` (#550, implicit since #551): `manifest.toml`, `SKILL.md`, `0.2.md`. A drift test pins it to the repo-root `packs/personal/`. |

The coaching pack is external since #449 and is not vendored into the
binary: it is copied into a vault's `packs/coaching@0.1/` and pinned in
that vault's `confidant.lock`. Edit the repo-root
`packs/coaching/manifest.toml` directly.

For the built-in, edit the repo-root `packs/personal/` files and copy
them here (the drift tests fail otherwise).
