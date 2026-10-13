#!/usr/bin/env python3
"""Smoke-test the integration-skill proposers against a vault.

Runs each proposer with the committed fake fixtures (skills/<skill>/testdata/,
fake data only) and asserts the documented apply contract (skills/README.md):
exit 0 plus the expected proposal-manifest keys (`lines_file`,
`request_id`, `records_blocked`). capture-gap-summary writes nothing; it is
asserted on exit 0 alone (it shells out to `confidant check`, so --cli
points at the binary under test).

Usage:
  smoke-proposers.py --vault VAULT [--cli PATH]

Exits 0 when every proposer passes; 1 (with the failing step) otherwise.
Stdlib only, like the rest of skills/bin/.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

SKILLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# skill -> (fixture arg name, fixture path, relative to the repo root)
PROPOSERS = [
    ("portal-sync", "--events", "skills/portal-sync/testdata/events.jsonl"),
    ("transcript-import", "--descriptor", "skills/transcript-import/testdata/descriptor.json"),
    ("lightfield-import", "--export", "skills/lightfield-import/testdata/export.json"),
]

REPO_ROOT = os.path.dirname(SKILLS_DIR)

MANIFEST_KEYS = ("lines_file", "request_id", "records_blocked")


def script_path(skill: str) -> str:
    return os.path.join(SKILLS_DIR, skill, "bin", f"{skill}.py")


def run_proposer(skill: str, vault: str, fixture_arg: str | None,
                 fixture: str | None, out: str | None,
                 cli: str | None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, script_path(skill), "--vault", vault]
    if fixture_arg:
        cmd += [fixture_arg, fixture]
    if out:
        cmd += ["--out", out]
    if skill == "capture-gap-summary" and cli:
        cmd += ["--cli", cli]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def check_manifest(manifest_path: str, skill: str) -> list[str]:
    """Return a list of contract violations (empty = pass)."""
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{skill}: cannot read manifest {manifest_path!r}: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{skill}: manifest is not a JSON object"]
    problems = []
    for key in MANIFEST_KEYS:
        if key not in manifest:
            problems.append(f"{skill}: manifest missing key {key!r}")
    for key in ("lines_file", "request_id"):
        if key in manifest and not manifest[key]:
            problems.append(f"{skill}: manifest key {key!r} is empty")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vault", required=True,
                    help="vault directory to propose against (examples/demo-vault)")
    ap.add_argument("--cli", default="confidant",
                    help="confidant binary for capture-gap-summary "
                         "(default: confidant on PATH)")
    args = ap.parse_args(argv)

    if not os.path.isfile(os.path.join(args.vault, "confidant.toml")):
        print(f"error: {args.vault} is not a vault (no confidant.toml)",
              file=sys.stderr)
        return 2

    failures: list[str] = []
    by_name, _by_id = common.existing_people(args.vault)
    if not by_name:
        failures.append("common.existing_people: no people indexed on demo vault")
    else:
        print(f"ok: existing_people ({len(by_name)} name(s) on demo vault)")

    with tempfile.TemporaryDirectory(prefix="confidant-smoke-") as tmp:
        for skill, fixture_arg, fixture in PROPOSERS:
            out = os.path.join(tmp, skill + ".json")
            proc = run_proposer(skill, args.vault, fixture_arg,
                                os.path.join(REPO_ROOT, fixture),
                                out, args.cli)
            if proc.returncode != 0:
                failures.append(f"{skill}: exit {proc.returncode}\n"
                                f"  stderr: {proc.stderr.strip()[-400:]}")
                continue
            failures.extend(check_manifest(out, skill))
            print(f"ok: {skill} (exit 0, manifest keys present)")

        # capture-gap-summary writes nothing; assert exit 0 alone.
        proc = run_proposer("capture-gap-summary", args.vault, None, None,
                            None, args.cli)
        if proc.returncode != 0:
            failures.append(f"capture-gap-summary: exit {proc.returncode}\n"
                            f"  stderr: {proc.stderr.strip()[-400:]}")
        else:
            print("ok: capture-gap-summary (exit 0)")

    if failures:
        print("\nFAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nall proposers pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
