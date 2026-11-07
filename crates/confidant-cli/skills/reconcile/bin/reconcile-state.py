#!/usr/bin/env python3
"""Local last-verified state for the reconcile skill.

Usage: reconcile-state.py [--vault PATH] [--state PATH] <command> ...

Commands:
  show [--json]
  mark-verified ID [--date YYYY-MM-DD]
  mark-unverified ID --reason REASON [--date YYYY-MM-DD]
  clear-unverified ID
  forget ID
  plan                     read a candidate list as JSON on stdin
  record-run --checked N --proposed N --applied N [--skipped N]
             [--date YYYY-MM-DD]

The state file is `<vault>/.confidant/reconcile-state.json`: local,
gitignored, rebuildable, and holding only opaque record IDs, dates, and a
closed set of reasons. It never holds a name, note text, or any other vault
content. It is derived workflow state (ADR-6), not a vault file.

This script never reads the vault. The agent gathers candidates through the
CLI (`check`, `find`, `context`, `status`) and passes only opaque IDs and
dates here. `plan` orders a candidate list the way the skill describes:
changed since the last pass, then never checked, then stalest.

Refuses to write unless `.confidant/` is git-ignored in the vault repo (the
same guardrail the qmd-search corpus uses). Warns instead of refusing when
there is no git binary or the vault is not a git repo yet.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime

SCHEMA_VERSION = "1"
STATE_REL = os.path.join(".confidant", "reconcile-state.json")
MAX_RUNS = 30
REASONS = ("no-answer", "operator-declined", "conflict", "out-of-scope")

# Opaque record ids only: core `p-`/`o-`/`d-`/`i-`/`n-`/`e-` and pack-
# declared prefixes (`pl-`, `th-`, ...). No spaces, `@`, names, or prose can
# pass this, so a caller cannot smuggle vault content into the state file.
ID_RE = re.compile(r"^[a-z]{1,3}-[0-9A-Z]{20,30}$")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def resolve_vault(explicit):
    vault = explicit or os.environ.get("CONFIDANT_VAULT")
    if not vault:
        fail("no vault: pass --vault or set CONFIDANT_VAULT")
    vault = os.path.abspath(os.path.expanduser(vault))
    if not os.path.isfile(os.path.join(vault, "confidant.toml")):
        fail(f"{vault} does not look like a vault (no confidant.toml)")
    return vault


def resolve_state(vault, explicit):
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    return os.path.join(vault, STATE_REL)


def today():
    return date.today().isoformat()


def check_id(value, where="id"):
    if not ID_RE.match(value or ""):
        fail(
            f"{where} {value!r} is not an opaque record id "
            "(expected e.g. p-<26 uppercase alphanumerics>); the state file "
            "holds ids and dates only, never names or other vault content"
        )
    return value


def check_day(value, where="date"):
    if not DAY_RE.match(value or ""):
        fail(f"{where} {value!r} is not YYYY-MM-DD")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        fail(f"{where} {value!r} is not a real calendar date")
    return value


def normalize_evidence(value):
    """A plan candidate date: YYYY-MM-DD, or YYYY-MM as its first day.

    Month-only provenance dates (the `profile_provenance` shape) compare as
    the first of the month, the conservative choice: a fact sourced in the
    same month it was verified is not reported as changed.
    """
    if not isinstance(value, str):
        fail(f"candidate date {value!r} is not a string")
    if DAY_RE.match(value):
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            fail(f"candidate date {value!r} is not a real calendar date")
        return value
    if MONTH_RE.match(value):
        try:
            datetime.strptime(value + "-01", "%Y-%m-%d")
        except ValueError:
            fail(f"candidate date {value!r} is not a real calendar month")
        return value + "-01"
    fail(f"candidate date {value!r} is not YYYY-MM-DD or YYYY-MM")
    return value


def empty_state():
    return {
        "schema_version": SCHEMA_VERSION,
        "updated": None,
        "records": {},
        "unverified": {},
        "runs": [],
    }


def load_state(path):
    if not os.path.exists(path):
        return empty_state()
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        fail(
            f"cannot read {path}: {e}; it is derived state, so move it aside "
            "and the next run rebuilds it"
        )
    if not isinstance(state, dict):
        fail(f"{path} is not a reconcile state object")
    if state.get("schema_version") != SCHEMA_VERSION:
        fail(
            f"{path} has schema_version {state.get('schema_version')!r}, "
            f"expected {SCHEMA_VERSION!r}; move it aside to rebuild"
        )
    records = state.get("records")
    unverified = state.get("unverified")
    runs = state.get("runs")
    if not isinstance(records, dict) or not isinstance(unverified, dict) \
            or not isinstance(runs, list):
        fail(f"{path} is not a reconcile state object")
    for rid in list(records) + list(unverified):
        check_id(rid, "state entry")
    for entry in records.values():
        if not isinstance(entry, dict):
            fail(f"{path} has a non-object record entry")
        check_day(entry.get("last_verified"), "last_verified")
    for entry in unverified.values():
        if not isinstance(entry, dict):
            fail(f"{path} has a non-object unverified entry")
        check_day(entry.get("since"), "unverified since")
        if entry.get("reason") not in REASONS:
            fail(
                f"{path} has reason {entry.get('reason')!r}; expected one of "
                + ", ".join(REASONS)
            )
    return state


def ensure_confidant_gitignored(vault):
    git = shutil.which("git")
    if git is None:
        print(
            "warning: git not found; cannot check that `.confidant/` is "
            "git-ignored. The state is local and derived — add `.confidant/` "
            "to .gitignore before this vault is committed.",
            file=sys.stderr,
        )
        return
    repo = subprocess.run(
        [git, "-C", vault, "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
    )
    if repo.returncode != 0:
        print(
            "warning: this vault is not a git repo yet; the `.confidant/` "
            "gitignore check is skipped. Add `.confidant/` to .gitignore "
            "before initializing a repo and committing.",
            file=sys.stderr,
        )
        return
    probe = subprocess.run(
        [git, "-C", vault, "check-ignore", "-q", ".confidant/.probe"],
        capture_output=True,
    )
    if probe.returncode == 0:
        return
    fail(
        "refusing to write the reconcile state: `.confidant/` is not "
        "git-ignored in this vault.\n"
        "The state is derived workflow data and must never be committed.\n"
        "Fix: echo '.confidant/' >> " + os.path.join(vault, ".gitignore")
    )


def save_state(vault, path, state):
    ensure_confidant_gitignored(vault)
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    state["updated"] = today()
    data = json.dumps(state, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".reconcile-state.", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def human_show(vault, path, state):
    print(f"Vault: {vault}")
    print(f"State: {path}")
    if state["updated"] is None:
        print("No reconcile state yet; this is the first pass.")
        return
    print(f"Updated: {state['updated']}")
    print(f"Verified: {len(state['records'])} record(s)")
    print(f"Unverified: {len(state['unverified'])} record(s)")
    for rid in sorted(state["unverified"]):
        entry = state["unverified"][rid]
        print(f"  {rid}  since {entry['since']} ({entry['reason']})")
    runs = state["runs"]
    print(f"Runs recorded: {len(runs)}")
    if runs:
        last = runs[-1]
        print(
            "Last run {date}: checked {checked}, proposed {proposed}, "
            "applied {applied}, skipped {skipped}".format(**last)
        )


def cmd_show(vault, path, state, args):
    if args.json:
        out = dict(state)
        out["vault"] = vault
        out["state"] = path
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        human_show(vault, path, state)
    return 0


def cmd_mark_verified(vault, path, state, args):
    check_id(args.id)
    check_day(args.date)
    state["records"][args.id] = {"last_verified": args.date}
    state["unverified"].pop(args.id, None)
    save_state(vault, path, state)
    print(f"verified {args.id} as of {args.date}")
    return 0


def cmd_mark_unverified(vault, path, state, args):
    check_id(args.id)
    check_day(args.date)
    if args.reason not in REASONS:
        fail("reason must be one of " + ", ".join(REASONS))
    previous = state["unverified"].get(args.id)
    since = previous["since"] if previous else args.date
    state["unverified"][args.id] = {"since": since, "reason": args.reason}
    save_state(vault, path, state)
    print(f"unverified {args.id} since {since} ({args.reason})")
    return 0


def cmd_clear_unverified(vault, path, state, args):
    check_id(args.id)
    if state["unverified"].pop(args.id, None) is None:
        print(f"{args.id} was not unverified")
    else:
        save_state(vault, path, state)
        print(f"cleared unverified {args.id}")
    return 0


def cmd_forget(vault, path, state, args):
    check_id(args.id)
    removed = state["records"].pop(args.id, None) is not None
    removed = state["unverified"].pop(args.id, None) is not None or removed
    if removed:
        save_state(vault, path, state)
        print(f"forgot {args.id}")
    else:
        print(f"{args.id} was not in the state")
    return 0


def read_candidates():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {"records": []}
    except json.JSONDecodeError as e:
        fail(f"candidate list is not JSON: {e}")
    if isinstance(payload, list):
        payload = {"records": payload}
    if not isinstance(payload, dict) or not isinstance(
        payload.get("records"), list
    ):
        fail('candidate list must be a JSON array or {"records": [...]}')
    candidates = []
    seen = set()
    for item in payload["records"]:
        if not isinstance(item, dict):
            fail("each candidate must be an object")
        rid = check_id(item.get("id"))
        if rid in seen:
            fail(f"candidate {rid} appears twice")
        seen.add(rid)
        dates = item.get("dates", [])
        if not isinstance(dates, list):
            fail(f"candidate {rid} has non-list dates")
        normalized = sorted({normalize_evidence(d) for d in dates})
        candidates.append(
            {"id": rid, "newest_evidence": normalized[-1] if normalized else None}
        )
    return candidates


def cmd_plan(vault, path, state, args):
    candidates = read_candidates()
    groups = {"changed": [], "never-checked": [], "stalest": []}
    for item in candidates:
        rid = item["id"]
        entry = state["records"].get(rid)
        open_entry = state["unverified"].get(rid)
        out = {
            "id": rid,
            "last_verified": entry["last_verified"] if entry else None,
            "newest_evidence": item["newest_evidence"],
            "unverified": dict(open_entry) if open_entry else None,
        }
        if entry is None:
            groups["never-checked"].append(out)
        elif item["newest_evidence"] and \
                item["newest_evidence"] > entry["last_verified"]:
            groups["changed"].append(out)
        else:
            groups["stalest"].append(out)
    # Changed: most recently changed first; never checked: stable by id;
    # stalest: oldest verification first.
    groups["changed"].sort(
        key=lambda r: (r["newest_evidence"] or "", r["id"]), reverse=True
    )
    groups["never-checked"].sort(key=lambda r: r["id"])
    groups["stalest"].sort(key=lambda r: (r["last_verified"], r["id"]))

    listed = {item["id"] for item in candidates}
    open_unverified = [
        {"id": rid, **state["unverified"][rid]}
        for rid in sorted(state["unverified"])
        if rid not in listed
    ]
    result = {
        "schema_version": SCHEMA_VERSION,
        "vault": vault,
        "state": path,
        "groups": [
            {"priority": priority, "records": groups[priority]}
            for priority in ("changed", "never-checked", "stalest")
        ],
        "open_unverified": open_unverified,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_record_run(vault, path, state, args):
    check_day(args.date)
    for name in ("checked", "proposed", "applied", "skipped"):
        if getattr(args, name) < 0:
            fail(f"--{name} cannot be negative")
    if args.applied > args.proposed:
        fail("--applied cannot exceed --proposed")
    if args.skipped > args.checked:
        fail("--skipped cannot exceed --checked")
    state["runs"].append(
        {
            "date": args.date,
            "checked": args.checked,
            "proposed": args.proposed,
            "applied": args.applied,
            "skipped": args.skipped,
        }
    )
    state["runs"] = state["runs"][-MAX_RUNS:]
    save_state(vault, path, state)
    print(
        f"recorded run {args.date}: checked {args.checked}, "
        f"proposed {args.proposed}, applied {args.applied}, "
        f"skipped {args.skipped}"
    )
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Local last-verified state for the reconcile skill."
    )
    parser.add_argument("--vault", help="vault path (or CONFIDANT_VAULT)")
    parser.add_argument(
        "--state", help="override the state file path (default: <vault>/.confidant/reconcile-state.json)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("show", help="print the state")
    show.add_argument("--json", action="store_true", help="machine-readable output")
    show.set_defaults(func=cmd_show)

    verified = sub.add_parser("mark-verified", help="record a verified pass")
    verified.add_argument("id")
    verified.add_argument("--date", default=today())
    verified.set_defaults(func=cmd_mark_verified)

    unverified = sub.add_parser(
        "mark-unverified", help="record a pass that could not verify a record"
    )
    unverified.add_argument("id")
    unverified.add_argument("--reason", required=True, choices=REASONS)
    unverified.add_argument("--date", default=today())
    unverified.set_defaults(func=cmd_mark_unverified)

    clear = sub.add_parser("clear-unverified", help="drop one unverified entry")
    clear.add_argument("id")
    clear.set_defaults(func=cmd_clear_unverified)

    forget = sub.add_parser("forget", help="drop a record from the state entirely")
    forget.add_argument("id")
    forget.set_defaults(func=cmd_forget)

    plan = sub.add_parser(
        "plan", help="order a candidate list on stdin: changed, never checked, stalest"
    )
    plan.set_defaults(func=cmd_plan)

    run = sub.add_parser("record-run", help="append this pass's counts")
    run.add_argument("--checked", type=int, default=0)
    run.add_argument("--proposed", type=int, default=0)
    run.add_argument("--applied", type=int, default=0)
    run.add_argument("--skipped", type=int, default=0)
    run.add_argument("--date", default=today())
    run.set_defaults(func=cmd_record_run)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    vault = resolve_vault(args.vault)
    path = resolve_state(vault, args.state)
    state = load_state(path)
    return args.func(vault, path, state, args)


if __name__ == "__main__":
    sys.exit(main())
