#!/usr/bin/env python3
"""lightfield-import: best-effort import of a Lightfield export into the vault.

THE EXPORT IS PLAINTEXT PII. It is never committed, never copied into the
vault, and this script deletes it only with --cleanup (after a verified
import). Keep it on a trusted device.

Expected export shape (JSON; unknown fields ignored, bad rows warned+skipped):
  {"contacts": [{"id": "lf-c-1", "name": "Ada Example",
                 "emails": ["a@x.co"], "phones": ["+1…"], "notes": "…"}],
   "deals": [{"id": "lf-d-1", "contact_id": "lf-c-1", "title": "…",
              "stage": "proposal", "notes": "…"}],
   "notes": [{"id": "lf-n-1", "contact_id": "lf-c-1",
              "date": "2026-09-01", "text": "…"}],
   "transcripts": [{"id": "lf-t-1", "contact_id": "lf-c-1",
                    "date": "2026-09-02", "duration_minutes": 60,
                    "billing": "paid", "text": "…"}]}

Proposes (never writes):
  contacts    -> people/p-<new>/profile.md (+ alias *candidates* in the
                 manifest only — the keyed HMAC needs the M2 vault lookup key)
  deals       -> deals/d-<new>/deal.md + DATE stage d-<new> <stage> src:lightfield/<id>
  notes       -> people/p-…/notes/n-<new>.md (top-level notes/ if no person; warned)
  transcripts -> interactions/i-<new>/interaction.md +
                 DATE session … src:lightfield/<id>
                 (no `note:` arg: session `note:` must name a note record)

Person matching is best-effort: exact `name:` match against existing
profiles links instead of creating; anything else creates a new person and
warns (the human merges duplicates later with a `merge` line).

Usage:
  lightfield-import.py --vault VAULT --export export.json [--out proposal.json]
  # after the apply: record the applied lf-id -> vault-id pairs (dedup map)
  lightfield-import.py --vault VAULT --record-applied --manifest proposal.json
  lightfield-import.py --cleanup --export export.json --manifest proposal.json \
      --i-verified-the-import
  # ^ deletes the export AND the whole proposal set (manifest, lines file,
  #   staged note bodies) — all plaintext PII.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "bin"))
import common  # noqa: E402

_NAME_RE = re.compile(r"^name:\s*(.+)$", re.MULTILINE)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common.vault_arg(p)
    p.add_argument("--export", default=None, help="Lightfield export JSON file")
    p.add_argument("--out", default=None,
                   help="write proposal manifest JSON here "
                        "(default: <vault>/.confidant/proposals/lightfield-import-<ts>.json)")
    p.add_argument("--manifest", default=None,
                   help="proposal manifest JSON (with --cleanup: also delete it; "
                        "with --record-applied: merge its import map)")
    p.add_argument("--cleanup", action="store_true",
                   help="delete the export file (requires --i-verified-the-import)")
    p.add_argument("--record-applied", action="store_true",
                   help="merge a manifest's import_map_additions into "
                        "<vault>/.confidant/lightfield-import-map.json "
                        "(run after the apply, requires --manifest)")
    p.add_argument("--i-verified-the-import", action="store_true",
                   help="confirm the import was applied and `confidant check` passes")
    return p.parse_args(argv)


def map_path(vault: str) -> str:
    """Local dedup map: opaque lf-id -> vault-id pairs only, no PII."""
    return os.path.join(vault, ".confidant", "lightfield-import-map.json")


def _manifest_stem(manifest_path: str) -> str:
    """Manifest path minus a trailing .json (proposal-set derivation)."""
    return (manifest_path[:-5] if manifest_path.endswith(".json")
            else manifest_path)


def load_map(vault: str) -> dict[str, str]:
    try:
        with open(map_path(vault), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def existing_people(vault: str) -> dict[str, str]:
    """Map profile display name -> person ID for exact-match linking."""
    people: dict[str, str] = {}
    base = os.path.join(vault, "people")
    if not os.path.isdir(base):
        return people
    for pid in sorted(os.listdir(base)):
        for cand in (os.path.join(base, pid, "profile.md"),
                     os.path.join(base, pid + ".md")):
            if not os.path.isfile(cand):
                continue
            try:
                with open(cand, encoding="utf-8") as f:
                    head = f.read(4096)
            except OSError:
                continue
            m = _NAME_RE.search(head)
            if m:
                people.setdefault(m.group(1).strip(), pid)
    return people



def main(argv=None) -> int:
    args = parse_args(argv)

    if args.record_applied:
        # Post-apply bookkeeping: fold the manifest's lf-id -> vault-id
        # pairs into the local dedup map so reruns skip what's applied.
        if not args.manifest:
            print("error: --record-applied needs --manifest", file=sys.stderr)
            return 2
        vault = common.require_vault(args)
        try:
            with open(args.manifest, encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read manifest: {exc}", file=sys.stderr)
            return 2
        additions = manifest.get("import_map_additions", {})
        if not isinstance(additions, dict) or not additions:
            print("manifest has no import_map_additions; nothing to record")
            return 0
        mp = map_path(vault)
        merged = load_map(vault)
        merged.update({k: v for k, v in additions.items()
                       if isinstance(k, str) and isinstance(v, str)})
        os.makedirs(os.path.dirname(mp), exist_ok=True)
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"recorded {len(additions)} id mapping(s) in {mp}")
        return 0

    if args.cleanup:
        if not args.export or not args.i_verified_the_import:
            print("error: --cleanup needs --export and --i-verified-the-import",
                  file=sys.stderr)
            return 2
        if not os.path.isfile(args.export):
            print(f"error: export file not found: {args.export!r} (nothing to delete)",
                  file=sys.stderr)
            return 2
        print("WARNING: deleting plaintext PII export "
              f"{args.export!r}. This cannot be undone.")
        os.remove(args.export)
        print(f"deleted {args.export}")
        if args.manifest:
            if not os.path.isfile(args.manifest):
                print(f"warning: manifest not found: {args.manifest!r}",
                      file=sys.stderr)
            else:
                # Delete the whole proposal set: manifest, lines file, and
                # note bodies. The set is defined by the manifest path the
                # user passed (same derivation the proposer used), so a
                # custom --out is cleaned up too. Symlinks are never
                # followed — a symlinked notes dir is left with a warning.
                stem = _manifest_stem(args.manifest)
                for t in (stem + ".cfd", os.path.join(stem, "notes")):
                    if os.path.islink(t):
                        print(f"warning: not deleting {t!r}: is a symlink",
                              file=sys.stderr)
                        continue
                    if os.path.isdir(t):
                        shutil.rmtree(t)
                        print(f"deleted {t}")
                        # drop the now-empty proposal stem dir too
                        try:
                            os.rmdir(os.path.dirname(t))
                        except OSError:
                            pass
                    elif os.path.isfile(t):
                        os.remove(t)
                        print(f"deleted {t}")
                print(f"deleting proposal manifest {args.manifest!r} (plaintext PII).")
                os.remove(args.manifest)
                print(f"deleted {args.manifest}")
        return 0

    if not args.export:
        print("error: --export is required (or use --cleanup)", file=sys.stderr)
        return 2
    vault = common.require_vault(args)

    # Proposal-set paths up front: the notes loop stages bodies next to the
    # manifest, and proposal_paths() refuses unless the scratch dir is
    # git-ignored (before any PII touches disk).
    if args.out:
        manifest_path = args.out
        lines_path = _manifest_stem(args.out) + ".cfd"
    else:
        manifest_path, lines_path = common.proposal_paths(vault, "lightfield-import")

    try:
        with open(args.export, encoding="utf-8") as f:
            export = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read export: {exc}", file=sys.stderr)
        return 2

    existing_srcs = common.collect_srcs(vault)
    people_by_name = existing_people(vault)
    lf_map = load_map(vault)
    warnings: list[str] = []
    skipped: list[dict] = []
    by_file: dict[str, list[str]] = {}
    records: list[dict] = []
    alias_candidates: list[dict] = []
    contact_to_person: dict[str, str] = {}
    seen_in_batch: set[str] = set()
    import_map_additions: dict[str, str] = {}

    def not_seen(kind: str, rid: str) -> bool:
        """True when this export row is new to the vault, the map, and this batch.

        Contacts and notes never get ledger lines, so `src:` provenance
        can't dedupe them — the local import map
        (<vault>/.confidant/lightfield-import-map.json, opaque lf-id ->
        vault-id pairs only, no PII) is their dedup record. Deals and
        transcripts dedupe on their `src:lightfield/<id>` ledger lines.
        """
        map_key = f"{kind}:{rid}"
        if kind in ("contact", "note") and map_key in lf_map:
            skipped.append({"id": rid,
                            "reason": f"already imported ({map_key} in lightfield-import-map.json)"})
            return False
        key = f"lightfield/{rid}"
        if key in existing_srcs:
            skipped.append({"id": rid, "reason": "already imported"})
            return False
        if (kind, rid) in seen_in_batch:
            skipped.append({"id": rid,
                            "reason": "duplicate id within this export"})
            return False
        seen_in_batch.add((kind, rid))
        return True

    def add_line(date: str, line: str):
        by_file.setdefault(common.month_file(vault, date), []).append(line)

    # --- contacts -> people -------------------------------------------------
    for c in export.get("contacts", []) or []:
        cid, name = c.get("id", ""), (c.get("name") or "").strip()
        if not cid or not name:
            warnings.append(f"contact {cid!r}: missing id or name; skipped")
            continue
        if f"contact:{cid}" in lf_map:
            # Already imported in an earlier run: link dependents to the
            # existing person, propose nothing new.
            contact_to_person[cid] = lf_map[f"contact:{cid}"]
            skipped.append({"id": cid,
                            "reason": f"already imported (contact:{cid} in "
                                      f"lightfield-import-map.json)"})
            continue
        if not not_seen("contact", cid):
            continue
        pid = people_by_name.get(name)
        if pid:
            warnings.append(f"contact {cid} ({name}): matched existing person {pid}; "
                            f"linking, please verify")
        else:
            pid = "p-" + common.new_ulid()
            body = (c.get("notes") or "").strip()
            records.append({
                "path": f"people/{pid}/profile.md",
                "content": f"---\nid: {pid}\ntype: person\nname: {name}\n---\n\n{body}\n",
            })
            warnings.append(f"contact {cid} ({name}): no vault match; new person {pid} "
                            f"(merge duplicates later if needed)")
        contact_to_person[cid] = pid
        import_map_additions[f"contact:{cid}"] = pid
        for email in c.get("emails", []) or []:
            alias_candidates.append({"person": pid, "kind": "email", "value": email})
        for phone in c.get("phones", []) or []:
            alias_candidates.append({"person": pid, "kind": "phone", "value": phone})
    if alias_candidates:
        warnings.append(f"{len(alias_candidates)} alias candidate(s) (emails/phones) held "
                        f"in this manifest only — the keyed HMAC needs the M2 vault "
                        f"lookup key; add them via the agent/CLI afterwards")

    # --- deals -> deals + stage lines ---------------------------------------
    for d in export.get("deals", []) or []:
        did = d.get("id", "")
        if not did:
            warnings.append("deal without id; skipped")
            continue
        if not not_seen("deal", did):
            continue
        # Never invent data: a deal needs a real stage and a real date.
        stage_raw = d.get("stage")
        if not stage_raw or not str(stage_raw).strip():
            warnings.append(f"deal {did}: missing stage; skipped (never invent stages)")
            continue
        date = d.get("date") or ""
        if not common.valid_date(date):
            warnings.append(f"deal {did}: bad/missing date; skipped (never invent dates)")
            continue
        pid = contact_to_person.get(d.get("contact_id", ""), "")
        title = (d.get("title") or "Untitled deal").strip()
        deal_id = "d-" + common.new_ulid()
        front = [f"id: {deal_id}", "type: deal", f"name: {title}"]
        if pid:
            front.append(f"person: {pid}")
        notes = (d.get("notes") or "").strip()
        records.append({
            "path": f"deals/{deal_id}/deal.md",
            "content": "---\n" + "\n".join(front) + f"\n---\n\n{notes}\n",
        })
        import_map_additions[f"deal:{did}"] = deal_id
        stage = str(stage_raw).strip().lower().replace(" ", "_")
        add_line(date, f"{date} stage {deal_id} {stage} src:lightfield/{did}")

    # --- notes -> note records ----------------------------------------------
    # Note bodies are plaintext PII: the proposer stages each body next to
    # the manifest (<stem>/notes/<note_id>.md, 0600) and records the path
    # in the manifest — the agent must never stage them in /tmp. Each note
    # also gets its own idempotency ULID for `note add --request-id`, so a
    # retried apply doesn't duplicate notes (reusing one id across different
    # writes would trip E_IDEMPOTENCY_CONFLICT).
    notes_dir: str | None = None
    for n in export.get("notes", []) or []:
        nid = n.get("id", "")
        if not nid:
            warnings.append("note without id; skipped")
            continue
        if not not_seen("note", nid):
            continue
        date = n.get("date") or ""
        if not common.valid_date(date):
            warnings.append(f"note {nid}: bad/missing date; skipped (never invent dates)")
            continue
        pid = contact_to_person.get(n.get("contact_id", ""), "")
        note_id = "n-" + common.new_ulid()
        front = [f"id: {note_id}", "type: note", f"date: {date}"]
        if pid:
            front.append(f"person: {pid}")
            path = f"people/{pid}/notes/{note_id}.md"
        else:
            path = f"notes/{note_id}.md"
            warnings.append(f"note {nid}: no person link; top-level note {note_id}")
        text = (n.get("text") or "").strip()
        if notes_dir is None:
            notes_dir = common.proposal_notes_dir(manifest_path)
        body_file = os.path.join(notes_dir, note_id + ".md")
        common.write_file_600(body_file, text + "\n")
        records.append({"path": path,
                        "content": "---\n" + "\n".join(front) + f"\n---\n\n{text}\n",
                        "note_id": note_id,
                        "person": pid or None,
                        "date": date,
                        "body_file": body_file,
                        "request_id": common.new_ulid()})
        import_map_additions[f"note:{nid}"] = note_id

    # --- transcripts -> interactions + session lines ------------------------
    for t in export.get("transcripts", []) or []:
        tid = t.get("id", "")
        if not tid:
            warnings.append("transcript without id; skipped")
            continue
        if not not_seen("transcript", tid):
            continue
        pid = contact_to_person.get(t.get("contact_id", ""), "")
        if not pid:
            warnings.append(f"transcript {tid}: no person link; skipped "
                            f"(link it to a person first)")
            continue
        minutes = t.get("duration_minutes")
        billing = t.get("billing")
        if not isinstance(minutes, int) or minutes <= 0:
            warnings.append(f"transcript {tid}: bad duration_minutes; skipped")
            continue
        if billing not in ("paid", "pps", "comp"):
            warnings.append(f"transcript {tid}: billing must be paid|pps|comp; skipped")
            continue
        date = t.get("date") or ""
        if not common.valid_date(date):
            warnings.append(f"transcript {tid}: bad/missing date; skipped "
                            f"(never invent dates — a wrong date corrupts "
                            f"sessions_remaining and ICF hours)")
            continue
        iid = "i-" + common.new_ulid()
        text = (t.get("text") or "").strip()
        records.append({
            "path": f"interactions/{iid}/interaction.md",
            "content": (f"---\nid: {iid}\ntype: interaction\n"
                        f"name: Session {date}\ndate: {date}\nperson: {pid}\n---\n\n{text}\n"),
        })
        import_map_additions[f"transcript:{tid}"] = iid
        add_line(date, f"{date} session {pid} {common.format_duration(minutes)} {billing} "
                       f"src:lightfield/{tid}")

    new_lines = sum(len(v) for v in by_file.values())

    # Post-M2 guard: hand-writing record files into an encrypted vault
    # would commit plaintext PII to git. Ledger lines are fine (they go
    # through `confidant import --file`, which encrypts on write), but
    # person/deal/note/interaction records must wait for
    # `confidant record add --file`.
    encrypted = common.vault_looks_encrypted(vault)
    if encrypted and records:
        warnings.append(
            "vault looks encrypted: the records below are PROPOSED ONLY — "
            "do NOT hand-write them (plaintext PII in git). They need "
            "`confidant record add --file`, which does not exist yet.")

    rid = common.new_request_id()
    common.write_lines_file(lines_path, by_file)
    manifest = {
        "skill": "lightfield-import",
        "vault": vault,
        "request_id": rid,
        "ledger": by_file,
        "lines_file": lines_path,
        "notes_dir": notes_dir,
        "records": records,
        "records_blocked": encrypted,
        "alias_candidates": alias_candidates,
        "import_map_additions": import_map_additions,
        "skipped": skipped,
        "warnings": warnings,
        "summary": (f"{len(records)} new record(s), {new_lines} new ledger line(s); "
                    f"{len(skipped)} already imported; {len(warnings)} warning(s). "
                    f"Export file NOT touched (plaintext PII — delete with --cleanup "
                    f"after a verified import)."),
    }
    print(manifest["summary"])
    for w in warnings:
        print(f"  warning: {w}")
    print(f"  manifest: {manifest_path}")
    print(f"  lines file (for `confidant import --file`): {lines_path}")
    if notes_dir:
        print(f"  note bodies (0600, for `note add --body-file`): {notes_dir}/")
    common.write_manifest(manifest_path, manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
