#!/usr/bin/env python3
"""Fail if a publishable crate references a build-time path outside its own directory.

`cargo publish` builds the crate from a tarball containing only the crate's
own files. A compile-time path like
`include_dir!("$CARGO_MANIFEST_DIR/../../packs")` works in the workspace but
fails in the packaged build with "is not a directory" (this broke the v0.3.0
release, #367; fixed by vendoring in #368).

`cargo package` / `cargo publish --dry-run` cannot catch this in CI: they
resolve workspace path-dependencies against the crates.io index, which fails
pre-release when sibling crates aren't published yet. This check verifies the
property directly, with no network access:

  every include_str! / include_bytes! / include_dir! / include! path in a
  publishable crate must resolve inside that crate's directory.

A path starting with `$CARGO_MANIFEST_DIR` resolves from the crate root;
anything else resolves from the source file's directory (the std macro rule).
Crates with `publish = false` are skipped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
INCLUDE_RE = re.compile(
    r"\binclude_(?:str|bytes|dir)!\s*\(\s*\"((?:[^\"\\]|\\.)*)\""
)
# include! without a suffix, e.g. include!("../generated.rs")
INCLUDE_BARE_RE = re.compile(r"(?<![_a-zA-Z])include!\s*\(\s*\"((?:[^\"\\]|\\.)*)\"")


def crate_is_publishable(manifest: Path) -> bool:
    for line in manifest.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("publish"):
            return "false" not in stripped
    return True


def unescape(s: str) -> str:
    return s.encode().decode("unicode_escape")


def check_crate(crate_dir: Path) -> list[str]:
    errors: list[str] = []
    for rs in sorted(crate_dir.rglob("*.rs")):
        # Skip vendored-in build junk the crate itself embeds on purpose.
        text = rs.read_text()
        for m in list(INCLUDE_RE.finditer(text)) + list(
            INCLUDE_BARE_RE.finditer(text)
        ):
            raw = unescape(m.group(1))
            if raw.startswith("$CARGO_MANIFEST_DIR"):
                resolved = (crate_dir / raw[len("$CARGO_MANIFEST_DIR"):].lstrip("/")).resolve()
            else:
                resolved = (rs.parent / raw).resolve()
            # normpath-style containment without requiring existence
            try:
                resolved.relative_to(crate_dir.resolve())
            except ValueError:
                errors.append(
                    f"{rs.relative_to(REPO)}:{text[:m.start()].count(chr(10)) + 1}: "
                    f"path escapes the crate directory: {raw}"
                )
    return errors


def main() -> int:
    errors: list[str] = []
    for manifest in sorted(REPO.glob("crates/*/Cargo.toml")):
        if not crate_is_publishable(manifest):
            continue
        errors.extend(check_crate(manifest.parent))
    if errors:
        print("crate path check FAILED:")
        for e in errors:
            print(f"  {e}")
        return 1
    print("crate path check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
