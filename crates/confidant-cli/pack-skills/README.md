# Pack skill texts (embedded in the CLI)

Vendored copies of `packs/<name>/SKILL.md` from the repo root. The CLI
embeds this tree with `include_dir!` so `cargo publish` and `cargo install`
work (crates.io tarballs do not include `../../packs`).

When you change a pack's agent-facing skill text, update the matching file
here before release.
