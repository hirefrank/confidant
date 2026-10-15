# Pack manifests (embedded in confidant-core)

Vendored copies of `packs/<name>/manifest.toml` from the repo root. Core
embeds the manifest with `include_str!` so `cargo publish` and
`cargo install` work (crates.io tarballs do not include `../../packs`).

When you change a pack's manifest, update the matching file here before
release. A test (`vendored_manifest_matches_repo_root`) fails if the two
copies drift.
