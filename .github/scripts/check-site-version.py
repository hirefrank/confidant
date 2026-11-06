#!/usr/bin/env python3
"""Fail when the landing page version pill disagrees with the workspace version.

The landing page (`site/public/index.html`) is static: nothing derives its
version pill from `Cargo.toml`, and Workers Builds only redeploys the page when
a push to `main` touches `site/**`. A release that bumps `Cargo.toml` alone
leaves the live page advertising an old version, so this check makes the two
disagree a CI failure:

  Cargo.toml        [workspace.package] version = "X.Y.Z"
  index.html        <span class="pill">vX.Y.Z · Apache-2.0</span>

The pill format is literal and machine-checked: exactly one
`vX.Y.Z · Apache-2.0` pill must exist, and its version must match. A missing
or duplicated pill fails closed rather than silently passing.

Run from anywhere; paths resolve from this file. Exit 0 on match, 1 on
mismatch or a malformed/missing pill.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CARGO_TOML = REPO_ROOT / "Cargo.toml"
INDEX_HTML = REPO_ROOT / "site" / "public" / "index.html"

# Deliberately strict: the version pill is the only place the landing page
# states the CLI version, so anything but the documented format is an error.
PILL_RE = re.compile(r'v(\d+\.\d+\.\d+) · Apache-2\.0')


def workspace_version(cargo_toml: Path) -> str:
    """Return `[workspace.package] version` without a TOML parser."""
    try:
        text = cargo_toml.read_text(encoding="utf-8")
    except OSError as err:
        sys.exit(f"check-site-version: cannot read {cargo_toml}: {err}")

    in_workspace_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_workspace_package = stripped == "[workspace.package]"
            continue
        if in_workspace_package:
            match = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)

    sys.exit(
        f"check-site-version: no version found in [workspace.package] of {cargo_toml}"
    )


def page_pill(version: str, index_html: Path) -> None:
    """Exit 1 unless `index_html` carries exactly one matching version pill."""
    try:
        text = index_html.read_text(encoding="utf-8")
    except OSError as err:
        sys.exit(f"check-site-version: cannot read {index_html}: {err}")

    pills = PILL_RE.findall(text)
    if not pills:
        sys.exit(
            "check-site-version: no version pill found in "
            f"{index_html}\n"
            f"  expected: <span class=\"pill\">v{version} · Apache-2.0</span>"
        )
    if len(pills) > 1:
        sys.exit(
            f"check-site-version: found {len(pills)} version pills in {index_html}; "
            "keep exactly one\n"
            f"  found: {', '.join('v' + p for p in pills)}"
        )

    found = pills[0]
    if found != version:
        sys.exit(
            "check-site-version: landing page version pill is stale\n"
            f"  Cargo.toml [workspace.package] version: {version}\n"
            f"  site/public/index.html pill:           v{found}\n"
            f"  fix: update the pill to <span class=\"pill\">v{version} · Apache-2.0</span>"
        )


def main() -> None:
    version = workspace_version(CARGO_TOML)
    page_pill(version, INDEX_HTML)
    print(f"check-site-version: ok (v{version})")


if __name__ == "__main__":
    main()
