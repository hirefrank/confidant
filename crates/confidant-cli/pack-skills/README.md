# Pack skill texts (embedded in the CLI)

Vendored copies of the built-in packs' `packs/<name>/SKILL.md` from the
repo root (today only `personal/`). The CLI embeds this tree with
`include_dir!` so `cargo publish` and `cargo install` work (crates.io
tarballs do not include `../../packs`). External packs ship their own
`SKILL.md` inside the vault (#449).

When you change a pack's agent-facing skill text, update the matching file
here before release.
