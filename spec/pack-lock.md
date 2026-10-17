# Pack lockfile spec

*Part of #193 (installable external packs, approved by Frank 2026-10-16).
Spec PR for #431; #437 implements the reader/writer.*

This spec describes `confidant.lock`: the file that pins exactly which
bytes an external pack resolves to. The lockfile is committed to the
vault, so every device and every review sees the same content. Trust is
"pin the hash and review the diff" (PD14): no central registry, no
signing in v1.

## 1. Location and lifecycle

`<vault>/confidant.lock`, TOML, committed. It is plaintext and holds no
private data.

The lockfile is written by `confidant pack add --yes` and
`confidant pack update` (specified in #439 and #440). `check` only reads
it; `check` never fetches and never writes it.

## 2. Format

```toml
lock_version = 1

[[pack]]
name = "example-pack"
version = "0.1"
source = "https://example.invalid/org/example-pack.git"   # or "dir" for --from-dir
rev = "0123456789abcdef0123456789abcdef01234567"          # full commit; empty for "dir"
subdir = ""                                               # optional path inside the repo
hash = "sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b"
```

- `lock_version` is required. Only `1` is defined. A reader that does
  not implement it fails with `E_PACK_INVALID` rather than guessing.
- Each `[[pack]]` entry is required to have `name`, `version`,
  `source`, `rev`, and `hash`. `subdir` is optional and defaults to
  `""` (the repo root).
- `name` matches `^[a-z][a-z0-9-]{1,31}$` (PD14). `version` is the
  pack's own version string.
- `source` is the `https://` git URL the pack was fetched from, or the
  literal string `"dir"` for `--from-dir` installs (PD3).
- `rev` is the full 40-hex commit the source resolved to at install
  time. It is empty (`""`) for `"dir"` sources, which have no commit.
- `hash` is the canonical tree digest of the vendored directory (§3),
  written `sha256:<64 lowercase hex>`.
- Entries are sorted by `name` for stable diffs.
- Unknown keys are an error.

`packs = ["name@version"]` in `confidant.toml` stays the enable list and
the exact-version pin; the lockfile decides content. A pack named in
`confidant.toml` with no lockfile entry is an error finding
(`E_PACK_INVALID`, PD12): the install is incomplete, not silently
skipped.

## 3. What is hashed (PD6)

SHA-256 (`sha2` is already a `confidant-core` dependency) over a
canonical tree digest of the vendored directory
(`<vault>/packs/<name>@<version>/`):

1. Take every file in the vendored directory, as paths relative to the
   directory, with `/` separators, UTF-8.
2. Sort the paths bytewise.
3. For each path, compute `sha256(content)` in lowercase hex.
4. The pack hash is `sha256` of the concatenation of the lines
   `"<content-hex>  <path>\n"` (two spaces, trailing newline), written
   `sha256:<hex>`.

File mode and mtime are not hashed. The `.git/` directory is never
vendored and never hashed.

Rejected at read time (each an `E_PACK_INVALID`): symlinks, non-UTF-8
or `..`/absolute paths, more than 200 files, any file over 1 MiB, total
over 4 MiB.

## 4. Worked example

Two tiny files in `packs/example-pack@0.1/`:

```sh
$ mkdir -p packs/example-pack@0.1
$ printf 'manifest_version = 2\n' > packs/example-pack@0.1/manifest.toml
$ printf '# Example pack skill.\n' > packs/example-pack@0.1/SKILL.md
$ sha256sum packs/example-pack@0.1/manifest.toml packs/example-pack@0.1/SKILL.md
d0916828fb01b5d176db72d960e6f87b2ed82bccbd220bc3f8ffa6c303268634  packs/example-pack@0.1/manifest.toml
b5ad698c1954c8fec40cf2a51c6eb7d0e0ee76ef37a9a5f101b3642b78e0b9c5  packs/example-pack@0.1/SKILL.md
```

Build the canonical lines (paths relative to the pack directory,
sorted bytewise — `SKILL.md` before `manifest.toml` because uppercase
`S` (0x53) sorts before lowercase `m` (0x6D)):

```sh
$ { printf 'b5ad698c1954c8fec40cf2a51c6eb7d0e0ee76ef37a9a5f101b3642b78e0b9c5  SKILL.md\n'; \
    printf 'd0916828fb01b5d176db72d960e6f87b2ed82bccbd220bc3f8ffa6c303268634  manifest.toml\n'; } > /tmp/lines.txt
$ printf 'sha256:'; sha256sum /tmp/lines.txt | cut -d' ' -f1
sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b
```

The lockfile entry:

```toml
[[pack]]
name = "example-pack"
version = "0.1"
source = "https://example.invalid/org/example-pack.git"
rev = "0123456789abcdef0123456789abcdef01234567"
subdir = ""
hash = "sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b"
```

## 5. Verification at `check` time

For each external pack enabled in `confidant.toml`:

1. Look up `name@version` in the lockfile. Missing entry:
   `E_PACK_INVALID`.
2. Look up `<vault>/packs/<name>@<version>/` on disk. Missing
   directory: `E_PACK_HASH`.
3. Recompute the §3 digest over the directory. Mismatch with the
   lockfile `hash`: `E_PACK_HASH`.
4. Validate the manifest and contents (PD7/PD8). Failure:
   `E_PACK_INVALID`.

A pack that fails any step is not folded (PD12, fail closed); its
claimed verbs stay known when the manifest still parses, so the failure
does not cascade into `E_UNKNOWN_VERB` noise.
