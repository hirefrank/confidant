#!/usr/bin/env python3
"""Query a vault through the local QMD index, honoring the §12 allowlist.

Usage: qmd-query.py [--vault PATH] [--mode hybrid|bm25|vector] [-n N] QUERY

- Runs `qmd query|search|vsearch --json` against the `confidant` collection.
- EVERY hit is verified through `confidant find` before being returned: a
  distinctive substring of the hit is searched, and the hit is kept only if
  the same file appears in `find`'s matches with full detail (which happens
  exactly when the content is cleared under spec §12, no-ai included). Hits
  that cannot be verified are dropped -- fail closed.
- If QMD or the index is missing, falls back to plain `confidant find`.
- Output is JSON on stdout mirroring `find --json` (plus score/via per
  match and a dropped_uncleared count). Diagnostics go to stderr.

This keeps the allowlist logic in exactly one place (the Rust CLI): the
skill never reimplements clearance, so it cannot drift.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

COLLECTION = "confidant"
SCHEMA_VERSION = "1"
STORE_REL = os.path.join(".confidant", "qmd")

# qmd --json shapes vary by subcommand/version; accept the common ones.
# NOTE: `file` arrives as a qmd://<collection>/<relpath> URI, not a
# filesystem path -- strip it to the vault-relative path.
PATH_KEYS = ("path", "file", "filepath", "doc", "document")
SCORE_KEYS = ("score", "rerank_score", "final_score", "similarity")
TEXT_KEYS = ("excerpt", "snippet", "text", "content", "chunk")

QMD_URI_RE = re.compile(r"^qmd://[^/]+/")


def strip_diff_header(text):
    """Remove qmd's leading `@@ -a,b @@ (x before, y after)` diff header."""
    lines = text.splitlines()
    if lines and re.match(r"^@@ -\d+,\d+ @@", lines[0]):
        return "\n".join(lines[1:]).lstrip("\n")
    return text


def resolve_vault(explicit):
    vault = explicit or os.environ.get("CONFIDANT_VAULT")
    if not vault:
        sys.exit("error: no vault: pass --vault or set CONFIDANT_VAULT")
    vault = os.path.abspath(os.path.expanduser(vault))
    if not os.path.isfile(os.path.join(vault, "confidant.toml")):
        sys.exit(f"error: {vault} does not look like a vault (no confidant.toml)")
    return vault


def confidant(vault, *args):
    exe = shutil.which("confidant")
    if exe is None:
        # try the workspace debug build layout as a convenience
        return None
    p = subprocess.run([exe, "--vault", vault, *args],
                       capture_output=True, text=True, timeout=120)
    if p.returncode not in (0, 1):  # 1 = completed with findings; still JSON
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return None


def first_str(d, keys):
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def first_num(d, keys):
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)):
            return float(v)
    return 0.0


def norm_hits(raw):
    """Tolerantly normalize qmd --json output to [{rel, score, text, line}]."""
    items = []
    if isinstance(raw, dict):
        for k in ("results", "hits", "matches", "documents"):
            if isinstance(raw.get(k), list):
                items = raw[k]
                break
    elif isinstance(raw, list):
        items = raw
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        raw_path = first_str(it, PATH_KEYS)
        if not raw_path:
            continue
        # qmd://<collection>/<relpath> -> vault-relative path
        rel = QMD_URI_RE.sub("", raw_path)
        # ledger mirrors: <name>.cfd.md in the corpus -> real <name>.cfd
        vault_rel = rel[:-3] if rel.endswith(".cfd.md") else rel
        if os.path.isabs(vault_rel) or vault_rel.startswith(".."):
            continue  # hit outside our corpus: ignore
        out.append({"rel": vault_rel,
                    "score": first_num(it, SCORE_KEYS),
                    "text": strip_diff_header(first_str(it, TEXT_KEYS)),
                    "line": it.get("line") if isinstance(it.get("line"), int) else None})
    return out


def distinctive_substring(text, min_len=24, max_len=60):
    """Longest clean alphanumeric run in the text, bounded. '' if none."""
    runs = re.findall(r"[A-Za-z0-9][A-Za-z0-9'’\- ]{8,}", text)
    runs = [r.strip(" -'’") for r in runs]
    runs = [r for r in runs if len(r) >= min_len]
    if not runs:
        return ""
    best = max(runs, key=len)
    return best[:max_len]


def qmd_env(vault):
    """Env pointing QMD at the vault-local store (mirrors qmd-index.py)."""
    store = os.path.join(vault, STORE_REL)
    env = dict(os.environ)
    env["INDEX_PATH"] = os.path.join(store, "index.sqlite")
    env["QMD_CONFIG_DIR"] = os.path.join(store, "config")
    return env


def vectors_available(qmd, env):
    """True if the qmd index has any embedded vectors (hybrid/vector need them)."""
    try:
        p = subprocess.run([qmd, "status"], capture_output=True, text=True,
                           timeout=30, env=env)
    except (subprocess.TimeoutExpired, OSError):
        return False
    m = re.search(r"Vectors:\s*(\d+)\s+embedded", p.stdout)
    return bool(m and int(m.group(1)) > 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=None)
    ap.add_argument("--mode", default="bm25", choices=["hybrid", "bm25", "vector"],
                    help="bm25 works with no model downloads (default); "
                         "hybrid/vector need `qmd embed` first")
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("query", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    query = " ".join(args.query).strip()
    if not query:
        ap.error("QUERY is required")

    vault = resolve_vault(args.vault)
    corpus = os.path.join(vault, ".confidant", "qmd-corpus")
    qmd = shutil.which("qmd")
    env = qmd_env(vault)

    def fallback(reason):
        print(f"note: qmd unavailable ({reason}); falling back to `confidant find`",
              file=sys.stderr)
        # find --json already honors §12; emit its envelope with our fields added
        exe = shutil.which("confidant")
        if exe is None:
            sys.exit("error: neither qmd nor confidant is on PATH")
        p = subprocess.run([exe, "--vault", vault, "find", query, "--json"],
                           capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(p.stdout)
        except json.JSONDecodeError:
            sys.exit(f"error: confidant find failed: {p.stderr.strip()}")
        data["mode"] = "find-fallback"
        data["query"] = query
        data["dropped_uncleared"] = 0
        for m in data.get("matches", []):
            m["via"] = "find"
        print(json.dumps(data, indent=2))
        return 0

    if qmd is None or not os.path.isdir(corpus):
        return fallback("qmd or index missing" if qmd is None else "index missing")

    if args.mode in ("hybrid", "vector") and not vectors_available(qmd, env):
        sys.exit(f"error: --mode {args.mode} needs embeddings: run `qmd embed` "
                 f"first (downloads models on first run), or use --mode bm25")

    sub = {"hybrid": "query", "bm25": "search", "vector": "vsearch"}[args.mode]
    try:
        p = subprocess.run([qmd, sub, query, "--json", "-n", str(args.n),
                            "-c", COLLECTION],
                           capture_output=True, text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        return fallback(f"qmd {sub} timed out")
    if p.returncode != 0:
        return fallback(f"qmd {sub} failed")
    try:
        hits = norm_hits(json.loads(p.stdout))
    except json.JSONDecodeError:
        return fallback("unparseable qmd output")
    if not hits:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "ok": True,
                          "vault": vault, "mode": args.mode, "query": query,
                          "matches": [], "dropped_uncleared": 0,
                          "findings": []}, indent=2))
        return 0

    # Dedupe by vault-relative path; keep best score + longest text per file.
    merged = {}
    for h in hits:
        rel = h["rel"]
        m = merged.setdefault(rel, {"score": 0.0, "text": "", "line": None})
        m["score"] = max(m["score"], h["score"])
        if len(h["text"]) > len(m["text"]):
            m["text"] = h["text"]
            m["line"] = h["line"]

    matches, dropped = [], 0
    for rel, m in merged.items():
        probe = distinctive_substring(m["text"])
        if not probe:
            dropped += 1  # nothing verifiable: fail closed
            continue
        res = confidant(vault, "find", probe, "--json")
        if res is None:
            dropped += 1
            continue
        verified = any(isinstance(x, dict) and x.get("path") == rel
                       and x.get("excerpt")
                       for x in res.get("matches", []))
        if not verified:
            dropped += 1
            continue
        # reuse the CLI's own excerpt/line for the verified file
        best = max((x for x in res["matches"] if x.get("path") == rel),
                   key=lambda x: len(x.get("excerpt", "")))
        matches.append({"id": best.get("id"), "path": rel,
                        "line": best.get("line"), "excerpt": best.get("excerpt"),
                        "score": round(m["score"], 4), "via": "qmd"})
    matches.sort(key=lambda m: m["score"], reverse=True)

    print(json.dumps({"schema_version": SCHEMA_VERSION, "ok": True,
                      "vault": vault, "mode": args.mode, "query": query,
                      "matches": matches, "dropped_uncleared": dropped,
                      "findings": []}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
