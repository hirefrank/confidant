# Pack manifests (embedded in confidant-core)

In-crate copies of the manifests (and, for the built-in, its pack
directory) that the binary compiles with `include_str!`, so `cargo
publish` and `cargo install` work: crates.io tarballs do not include the
repo-root `../../packs`.

| Path | What |
|---|---|
| `coaching/manifest.toml` | Vendored copy of `packs/coaching/manifest.toml` (compiled `coaching@0.1`). |
| `personal-0.2/` | The embedded declarative built-in `personal@0.2` (#550, implicit since #551): `manifest.toml`, `SKILL.md`, `0.2.md`. A drift test pins it to the repo-root `packs/personal/`. |

When you change `packs/coaching/manifest.toml`, update
`coaching/manifest.toml` here before release. For the built-in, edit the
repo-root `packs/personal/` files and copy them here (the drift tests
fail otherwise).
