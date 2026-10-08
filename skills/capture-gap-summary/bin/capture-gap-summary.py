#!/usr/bin/env python3
"""capture-gap-summary: operator-facing summary of capture gaps.

Runs `confidant check --json` and reports the two capture-gap findings
(architecture §9b item 3):
  - E_SESSION_WITHOUT_NOTES: a session with no linked or same-day note
  - E_PAID_SESSION_GAP: a paid client with no session in the gap window

Writes nothing. Exit 0 normally; --fail-on-gaps exits 1 when gaps exist
(useful for scheduled runs).

Usage:
  capture-gap-summary.py --vault VAULT [--cli PATH] [--as-of YYYY-MM-DD]
      [--fail-on-gaps] [--out summary.md]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "bin"))
import common  # noqa: E402  # pylint: disable=wrong-import-position

GAP_CODES = ("E_SESSION_WITHOUT_NOTES", "E_PAID_SESSION_GAP")

DESCRIPTIONS = {
    "E_SESSION_WITHOUT_NOTES": "sessions with no linked or same-day note",
    "E_PAID_SESSION_GAP": "paid clients with no session in the gap window",
}


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common.vault_arg(p)
    p.add_argument("--cli", default="confidant",
                   help="path to the confidant binary (default: confidant on PATH)")
    p.add_argument("--as-of", default=None, help="evaluate gap rules as of YYYY-MM-DD")
    p.add_argument("--fail-on-gaps", action="store_true",
                   help="exit 1 when any gaps are found")
    p.add_argument("--out", default=None, help="write markdown summary here (default: stdout)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    vault = common.require_vault(args)

    cmd = [args.cli, "check", "--json", "--no-input", "--vault", vault]
    if args.as_of:
        if not common.valid_date(args.as_of):
            print(f"error: bad --as-of {args.as_of!r}", file=sys.stderr)
            return 2
        cmd += ["--as-of", args.as_of]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: could not run confidant check: {exc}", file=sys.stderr)
        return 1
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"error: confidant check did not return JSON (exit {proc.returncode})",
              file=sys.stderr)
        print(proc.stderr[-2000:], file=sys.stderr)
        return 1

    findings = report.get("findings", []) if isinstance(report, dict) else []
    gaps = [f for f in findings if f.get("code") in GAP_CODES]

    lines = ["# Capture-gap summary", ""]
    as_of = args.as_of or "today"
    if not gaps:
        lines.append(f"No capture gaps as of {as_of}.")
    else:
        lines.append(f"{len(gaps)} gap(s) as of {as_of}:")
        lines.append("")
        for code in GAP_CODES:
            items = [g for g in gaps if g.get("code") == code]
            if not items:
                continue
            lines.append(f"## {code} — {DESCRIPTIONS[code]} ({len(items)})")
            lines.append("")
            for g in items:
                rid = g.get("id", "")
                where = g.get("file", "")
                if g.get("line"):
                    where += f":{g['line']}"
                msg = g.get("message", "")
                fix = g.get("fix", "")
                bullet = f"- `{rid}` — {msg} ({where})" if rid else f"- {msg} ({where})"
                lines.append(bullet)
                if fix:
                    lines.append(f"  fix: {fix}")
            lines.append("")

    text = "\n".join(lines)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)

    if gaps and args.fail_on_gaps:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
