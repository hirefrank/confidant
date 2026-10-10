#!/usr/bin/env python3
"""transcript-import: propose a vault interaction + session from a transcript.

Source-agnostic: reads a transcript descriptor JSON (Frank's transcripts
save in parallel to Google Drive; the descriptor says where). Never writes
to the vault; prints a summary and a JSON proposal manifest.

Descriptor schema:
  {"transcript_id": "t-abc123", "source": "google-drive",
   "person_id": "p-…", "date": "2026-10-08",
   "duration_minutes": 60, "billing": "paid",
   "title": "Coaching session",
   "notes": "prose for the interaction body (optional)",
   "no-ai": true,
   "transcript_path": "/path/to/transcript.txt (optional, used when notes is absent)"}

`"no-ai": true` marks the proposed interaction record `no-ai` (only the
boolean `true` counts). Use it when the client opted out in the source
system — otherwise the transcript arrives cleared and the operator has
to fix it by hand.

Writes (proposed):
  - interactions/i-<new ULID>/interaction.md  (front matter + body)
  - ledger: DATE session PERSON-ID <Nm|Nh|NhNm> <billing> src:transcript/<id>
    (no `note:` arg: session `note:` must name a *note* record per the spec;
    the transcript prose lives in the interaction, as in architecture §6)

Duration feeds the coaching pack's icf_hours metric. Billing is required
(paid|pps|comp): the script will not silently choose a package-consuming
default.

Usage:
  transcript-import.py --vault VAULT --descriptor t.json [--out proposal.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "bin"))
import common  # noqa: E402

BILLING_TAGS = ("paid", "pps", "comp")

_NO_AI_RE = re.compile(r"^no-ai:\s*true\s*$", re.MULTILINE)


def _person_is_no_ai(vault: str, person: str) -> bool:
    """True when the target person's record has `no-ai: true` in front matter."""
    base = os.path.join(vault, "people", person)
    for cand in (os.path.join(base, "profile.md"), base + ".md"):
        try:
            with open(cand, encoding="utf-8") as f:
                head = f.read(4096)
        except OSError:
            continue
        return _NO_AI_RE.search(head) is not None
    return False


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common.vault_arg(p)
    p.add_argument("--descriptor", required=True, help="transcript descriptor JSON file")
    p.add_argument("--out", default=None,
                   help="write proposal manifest JSON here "
                        "(default: <vault>/.confidant/proposals/transcript-import-<ts>.json)")
    return p.parse_args(argv)



def main(argv=None) -> int:
    args = parse_args(argv)
    vault = common.require_vault(args)

    try:
        with open(args.descriptor, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read descriptor: {exc}", file=sys.stderr)
        return 2

    warnings: list[str] = []
    tid = d.get("transcript_id", "")
    person = d.get("person_id", "")
    date = d.get("date", "")
    minutes = d.get("duration_minutes")
    billing = d.get("billing")

    if not tid:
        print("error: descriptor needs transcript_id", file=sys.stderr)
        return 2
    if f"transcript/{tid}" in common.collect_srcs(vault):
        manifest = {
            "skill": "transcript-import", "vault": vault,
            "request_id": common.new_request_id(),
            "ledger": {}, "records": [],
            "skipped": [{"transcript_id": tid,
                         "reason": f"already imported (src:transcript/{tid})"}],
            "warnings": [], "summary": f"transcript {tid} already imported; nothing to do",
        }
        print(manifest["summary"])
        common.write_manifest(args.out, manifest)
        return 0

    if not common.valid_id(person) or not person[:2].lower() == "p-":
        print(f"error: bad person_id {person!r}", file=sys.stderr)
        return 2
    if not common.valid_date(date):
        print(f"error: bad date {date!r}", file=sys.stderr)
        return 2
    if not isinstance(minutes, int) or minutes <= 0:
        print(f"error: duration_minutes must be a positive integer, got {minutes!r}",
              file=sys.stderr)
        return 2
    if billing not in BILLING_TAGS:
        print(f"error: billing is required and must be one of {BILLING_TAGS}, "
              f"got {billing!r}", file=sys.stderr)
        return 2
    if not common.record_exists(vault, person):
        warnings.append(f"person {person} has no record file yet "
                        f"(will be E_UNKNOWN_RECORD until it exists)")

    notes = d.get("notes")
    tpath = d.get("transcript_path")
    if not notes and tpath:
        try:
            with open(tpath, encoding="utf-8") as f:
                notes = f.read()
        except OSError as exc:
            warnings.append(f"could not read transcript_path {tpath!r}: {exc}")
    if not notes:
        notes = ""
        warnings.append("no notes text provided; interaction body will be empty "
                        "(add prose before applying, or the session may trip "
                        "E_SESSION_WITHOUT_NOTES coverage)")

    iid = "i-" + common.new_ulid()
    title = d.get("title", f"Session {date}")
    record_path = f"interactions/{iid}/interaction.md"
    front = [f"id: {iid}", "type: interaction", f"name: {title}",
             f"date: {date}", f"person: {person}"]
    # no-ai on the descriptor, or inherited from a no-ai target person: the
    # interaction belongs to that client either way.
    no_ai = d.get("no-ai") is True or _person_is_no_ai(vault, person)
    if no_ai:
        front.append("no-ai: true")
    record_body = (
        "---\n"
        + "\n".join(front) + "\n"
        + "---\n"
        f"\n{notes}\n"
    )
    duration = common.format_duration(minutes)
    # NOTE: no `note:` arg here. Per the spec, session `note:` must name a
    # *note* (n-) record; the transcript prose lives in the interaction
    # record above (architecture §6 example). The session may trip
    # E_SESSION_WITHOUT_NOTES coverage until the operator adds notes —
    # that warning is working as intended.
    line = (f"{date} session {person} {duration} {billing} "
            f"src:transcript/{tid}")

    # Post-M2 guard: hand-writing record files into an encrypted vault
    # would commit plaintext PII to git. The session line is fine (it goes
    # through `confidant import --file`, which encrypts on write), but the
    # interaction record must wait for `confidant record add --file`.
    encrypted = common.vault_looks_encrypted(vault)
    records = [{"path": record_path, "content": record_body}]
    if encrypted:
        warnings.append(
            "vault looks encrypted: the interaction record below is PROPOSED ONLY — "
            "do NOT hand-write it (plaintext PII in git). It needs "
            "`confidant record add --file`, which does not exist yet.")

    rid = common.new_request_id()
    if args.out:
        manifest_path = args.out
        lines_path = (args.out[:-5] if args.out.endswith(".json") else args.out) + ".cfd"
        # #57: a custom --out inside the vault must be git-ignored too.
        common.ensure_out_ignored(vault, manifest_path, lines_path)
    else:
        manifest_path, lines_path = common.proposal_paths(vault, "transcript-import")
    ledger = {common.month_file(vault, date): [line]}
    common.write_lines_file(lines_path, ledger)
    manifest = {
        "skill": "transcript-import",
        "vault": vault,
        "request_id": rid,
        "ledger": ledger,
        "lines_file": lines_path,
        "records": records,
        "records_blocked": encrypted,
        "skipped": [],
        "warnings": warnings,
        "summary": (f"new interaction {iid} + 1 session line "
                    f"({duration} {billing}) for transcript {tid}"),
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
