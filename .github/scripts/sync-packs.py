#!/usr/bin/env python3
"""Regenerate the in-crate vendored pack copies from the repo-root sources.

Pack skills and manifests are duplicated by hand because the binary embeds
the in-crate copies (`include_dir!` / `include_str!`), and crates.io
tarballs do not include the repo-root `../../packs`:

  packs/coaching/SKILL.md        -> crates/confidant-cli/pack-skills/coaching/SKILL.md
  packs/personal/SKILL.md        -> crates/confidant-cli/pack-skills/personal/SKILL.md
  packs/coaching/manifest.toml   -> crates/confidant-core/pack-manifests/coaching/manifest.toml
  packs/personal/manifest.toml   -> crates/confidant-core/pack-manifests/personal-0.2/manifest.toml
  packs/personal/SKILL.md        -> crates/confidant-core/pack-manifests/personal-0.2/SKILL.md
  packs/personal/0.2.md          -> crates/confidant-core/pack-manifests/personal-0.2/0.2.md

Edit the repo-root source, then run this once. The drift tests
(`crates/confidant-cli/src/embedded.rs`,
`crates/confidant-core/src/packs/{coaching,embedded}.rs`) stay in CI and
still fail on any drift; this script only removes the manual copying.

Usage:
  python3 .github/scripts/sync-packs.py           # copy sources over the vendored copies
  python3 .github/scripts/sync-packs.py --check   # verify without writing (exit 1 on drift)

Generated copies, never symlinks: symlinks are unsafe for `cargo publish`
tarballs and `include_dir!`. The frozen
`pack-manifests/personal-0.1/manifest.toml` has no repo-root source (it
keeps the compiled `personal@0.1` identity until the cutover, #551) and is
deliberately not synced.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# (repo-root source, in-crate vendored copy) relative to the repo root.
COPIES = [
    ("packs/coaching/SKILL.md",
     "crates/confidant-cli/pack-skills/coaching/SKILL.md"),
    ("packs/personal/SKILL.md",
     "crates/confidant-cli/pack-skills/personal/SKILL.md"),
    ("packs/coaching/manifest.toml",
     "crates/confidant-core/pack-manifests/coaching/manifest.toml"),
    ("packs/personal/manifest.toml",
     "crates/confidant-core/pack-manifests/personal-0.2/manifest.toml"),
    ("packs/personal/SKILL.md",
     "crates/confidant-core/pack-manifests/personal-0.2/SKILL.md"),
    ("packs/personal/0.2.md",
     "crates/confidant-core/pack-manifests/personal-0.2/0.2.md"),
]


def main() -> int:
    check = "--check" in sys.argv[1:]
    drifted, synced, unchanged = [], [], []
    for src_rel, dst_rel in COPIES:
        src, dst = REPO / src_rel, REPO / dst_rel
        if not src.is_file():
            print(f"error: missing repo-root source {src_rel}", file=sys.stderr)
            return 2
        data = src.read_bytes()
        if check:
            if not dst.is_file() or dst.read_bytes() != data:
                drifted.append(dst_rel)
            continue
        if dst.is_file() and dst.read_bytes() == data:
            unchanged.append(dst_rel)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        synced.append(dst_rel)

    if check:
        if drifted:
            print("pack sync check FAILED — run "
                  "`python3 .github/scripts/sync-packs.py`:")
            for rel in drifted:
                print(f"  out of sync: {rel}")
            return 1
        print("pack sync check passed")
        return 0

    for rel in synced:
        print(f"  synced    {rel}")
    for rel in unchanged:
        print(f"  unchanged {rel}")
    print(f"done: {len(synced)} synced, {len(unchanged)} unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
