#!/usr/bin/env python3
"""portal-sync: propose vault updates from coaching-portal events.

Reads a JSONL file of portal events, diffs against the vault's existing
`src:portal/*` provenance, and prints a human summary plus a JSON proposal
manifest. Never writes to the vault.

Event schema (one JSON object per line):
  {"event_id": "evt-001", "type": "renewal",
   "occurred_at": "2026-10-08", "person_id": "p-…",
   "package_id": "pkg-…", "sessions": 6}
  {"event_id": "evt-002", "type": "checkout_sent",
   "occurred_at": "2026-10-08", "deal_id": "d-…"}
  {"event_id": "evt-003", "type": "deal_lost",
   "occurred_at": "2026-10-08", "deal_id": "d-…"}

Mapping:
  renewal       -> DATE open PERSON-ID package PKG-ID N sessions src:portal/<id>
  checkout_sent -> DATE stage DEAL-ID checkout_sent src:portal/<id>
  deal_lost     -> DATE stage DEAL-ID lost src:portal/<id>

Usage:
  portal-sync.py --vault VAULT --events events.jsonl [--out proposal.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "bin"))
import common  # noqa: E402

KNOWN_TYPES = ("renewal", "checkout_sent", "deal_lost")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common.vault_arg(p)
    p.add_argument("--events", required=True, help="portal events JSONL file")
    p.add_argument("--out", default=None,
                   help="write proposal manifest JSON here "
                        "(default: <vault>/.confidant/proposals/portal-sync-<ts>.json)")
    return p.parse_args(argv)


def build_line(event: dict, warnings: list[str]) -> str | None:
    eid = event.get("event_id", "")
    etype = event.get("type")
    date = event.get("occurred_at", "")
    src = f"src:portal/{eid}"

    if etype not in KNOWN_TYPES:
        warnings.append(f"event {eid}: unknown type {etype!r}; skipped (no invented verbs)")
        return None
    if not common.valid_date(date):
        warnings.append(f"event {eid}: bad occurred_at {date!r}; skipped")
        return None

    if etype == "renewal":
        person, pkg, n = event.get("person_id", ""), event.get("package_id", ""), event.get("sessions")
        if not common.valid_id(person):
            warnings.append(f"event {eid}: bad person_id {person!r}; skipped")
            return None
        if not common.valid_id(pkg) or not pkg[:4].lower() == "pkg-":
            warnings.append(f"event {eid}: bad package_id {pkg!r}; skipped")
            return None
        if not isinstance(n, int) or n <= 0 or n > 100000:
            warnings.append(f"event {eid}: bad sessions {n!r}; skipped")
            return None
        return f"{date} open {person} package {pkg} {n} sessions {src}"

    deal = event.get("deal_id", "")
    if not common.valid_id(deal) or not deal[:2].lower() == "d-":
        warnings.append(f"event {eid}: bad deal_id {deal!r}; skipped")
        return None
    stage = "checkout_sent" if etype == "checkout_sent" else "lost"
    return f"{date} stage {deal} {stage} {src}"


def main(argv=None) -> int:
    args = parse_args(argv)
    vault = common.require_vault(args)

    try:
        with open(args.events, encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read events file: {exc}", file=sys.stderr)
        return 2

    existing = common.collect_srcs(vault)
    warnings: list[str] = []
    skipped: list[dict] = []
    by_file: dict[str, list[str]] = {}
    seen_in_batch: set[str] = set()

    for event in events:
        eid = event.get("event_id", "")
        if not eid:
            warnings.append("event without event_id; skipped")
            continue
        if eid in seen_in_batch:
            skipped.append({"event_id": eid,
                            "reason": "duplicate event_id within this batch"})
            continue
        seen_in_batch.add(eid)
        if f"portal/{eid}" in existing:
            skipped.append({"event_id": eid, "reason": f"already imported (src:portal/{eid})"})
            continue
        line = build_line(event, warnings)
        if line is None:
            continue
        date = event["occurred_at"]
        if not common.record_exists(vault, event.get("person_id") or event.get("deal_id", "")):
            warnings.append(
                f"event {eid}: target record has no file yet "
                f"(will be E_UNKNOWN_RECORD until it exists)")
        target = common.month_file(vault, date)
        by_file.setdefault(target, []).append(line)

    new_lines = sum(len(v) for v in by_file.values())
    rid = common.new_request_id()
    if args.out:
        manifest_path = args.out
        lines_path = (args.out[:-5] if args.out.endswith(".json") else args.out) + ".cfd"
    else:
        manifest_path, lines_path = common.proposal_paths(vault, "portal-sync")
    common.write_lines_file(lines_path, by_file)
    manifest = {
        "skill": "portal-sync",
        "vault": vault,
        "request_id": rid,
        "ledger": by_file,
        "lines_file": lines_path,
        "records": [],
        "skipped": skipped,
        "warnings": warnings,
        "summary": (f"{new_lines} new ledger line(s) from {len(events)} portal event(s); "
                    f"{len(skipped)} already imported; {len(warnings)} warning(s)"),
    }

    print(manifest["summary"])
    for w in warnings:
        print(f"  warning: {w}")
    print(f"  manifest: {manifest_path}")
    print(f"  lines file (for `confidant import --file`): {lines_path}")
    common.write_manifest(manifest_path, manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
