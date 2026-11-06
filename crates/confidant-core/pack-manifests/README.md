# Pack manifests (embedded in confidant-core)

In-crate copies of the manifests (and, for the built-in, its pack
directory) that the binary compiles with `include_str!`, so `cargo
publish` and `cargo install` work: crates.io tarballs do not include the
repo-root `../../packs`.

| Path | What |
|---|---|
| `personal-0.2/` | The frozen embedded declarative built-in `personal@0.2` for specs 0.1–0.3 (#550, implicit since #551): `manifest.toml`, `SKILL.md`, `0.2.md`. No repo-root source; do not edit. |
| `personal-0.3/` | The frozen embedded declarative built-in `personal@0.3` (places and things, #745): `manifest.toml`, `SKILL.md`, `0.3.md`. No spec selects it now; its contract stays pinned to `packs/personal/0.3.md`. |
| `personal-0.4/` | The embedded declarative built-in `personal@0.4` for spec 0.4 (#750, #741): `manifest.toml`, `SKILL.md`, `0.4.md`. A drift test pins it to the repo-root `packs/personal/`. |

External packs are not vendored into the binary: they are copied into a
vault's `packs/<name>@<version>/` and pinned in that vault's
`confidant.lock`.

For the built-in, edit the repo-root `packs/personal/` files and run
`python3 .github/scripts/sync-packs.py`.
