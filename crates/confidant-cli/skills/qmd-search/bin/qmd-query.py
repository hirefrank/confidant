#!/usr/bin/env python3
"""Query a vault through the local QMD index, honoring the §12 allowlist.

Usage: qmd-query.py [--vault PATH] [--mode hybrid|bm25|vector] [-n N] [--packs LIST] QUERY

- Runs `qmd query|search|vsearch --json` against the `confidant` collection.
- EVERY hit is verified against the §12 allowlist in ONE CLI call per run:
  `confidant allowlist --json [--packs <same scope>]` (#538). The old
  verification ran one `confidant find` per hit file — an N+1 vault load —
  and probed with a ≥24-character ASCII run, so a CJK or short/punctuated
  cleared note yielded no probe and was silently dropped (bench-gen --cjk
  exists to exercise exactly that). Clearance is a path/line question, so ask
  it directly instead of re-searching for text.
  - Record-file hits are kept when the hit path is in `cleared_files`.
  - Ledger hits (`ledger/*.cfd`) are kept only when the hit's line resolves
    to a line in `cleared_ledger_lines` (`file`, `line`, `owning_packs`).
    The file mixes people and the QMD corpus can be stale after a `no-ai`
    change, so the whole *file* is not enough. `reindex` writes only the
    cleared ledger lines into the corpus, in order, so the corpus line
    number qmd reports is not the vault line number; the two are aligned by
    exact line text. A line that no longer aligns — edited, dropped, or
    never cleared since the index was built — resolves to nothing and is
    dropped.
  - Anything unverified is dropped and counted, never returned: fail closed.
- Snippets come from the QMD hit text (records) or the aligned corpus line
  (ledger); no per-hit `find` is run.
- If QMD or the index is missing, falls back to plain `confidant find`.
- Output is JSON on stdout mirroring `find --json` (plus score/via per
  match and a dropped_uncleared count). Diagnostics go to stderr.
- `--packs` (comma-separated, issue #178) scopes the allowlist and the
  fallback `find` call, so a scoped agent never sees hits owned by another
  pack. The QMD index itself is unscoped; the allowlist call is the
  enforcement point. `reindex` annotates each cleared file/line with its
  owning packs (`allowlist --json` `owning_packs`) for index-time consumers.

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
CORPUS_REL = os.path.join(".confidant", "qmd-corpus")

# qmd --json shapes vary by subcommand/version; accept the common ones.
# NOTE: `file` arrives as a qmd://<collection>/<relpath> URI, not a
# filesystem path -- strip it to the vault-relative path.
PATH_KEYS = ("path", "file", "filepath", "doc", "document")
SCORE_KEYS = ("score", "rerank_score", "final_score", "similarity")
TEXT_KEYS = ("excerpt", "snippet", "text", "content", "chunk")

QMD_URI_RE = re.compile(r"^qmd://[^/]+/")

# A record ID: type prefix, dash, 26-character Crockford ULID (no I/L/O/U,
# first character 0-7). Used only to derive the `id` field the old
# `find`-based verification copied from the CLI; clearance itself comes
# from `cleared_files` / `cleared_ledger_lines`.
ID_RE = re.compile(
    r"(?P<prefix>pkg|p|o|d|i|n|e)-(?P<ulid>[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25})")
LEDGER_SUFFIX = ".cfd"


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


def read_lines(path):
    """File lines, split on '\\n' like the CLI's ledger reader; None if unreadable.

    `splitlines()` would also split on U+2028 and friends, which the Rust
    side does not; a trailing newline must not add an empty final line.
    """
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def allowlist(vault, packs):
    """The §12 cleared set, in one `confidant allowlist --json` call (#538).

    Returns the parsed envelope. Exits with the CLI's own error (fail
    closed) rather than falling back to unverified results.
    """
    exe = shutil.which("confidant")
    if exe is None:
        sys.exit("error: `confidant` is not on PATH; cannot verify hits")
    extra = ["--packs", packs] if packs else []
    p = subprocess.run([exe, "--vault", vault, "allowlist", "--json", *extra],
                       capture_output=True, text=True, timeout=120)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        data = None
    if p.returncode != 0 or not isinstance(data, dict) or not data.get("ok"):
        detail = (p.stderr or "").strip() or (p.stdout or "").strip()
        sys.exit(f"error: `confidant allowlist` failed (exit {p.returncode}):\n"
                 f"{detail}")
    return data


def canonical_id(match):
    """`prefix-ULID` with the ULID uppercased, like the CLI's RecordId."""
    return f"{match.group('prefix').lower()}-{match.group('ulid').upper()}"


def first_id(text):
    """First record-ID-shaped token in a line, or None (display field only)."""
    m = ID_RE.search(text)
    return canonical_id(m) if m else None


def record_id_from_path(rel):
    """The record ID a vault path encodes: stem first, then parent dirs."""
    for part in reversed(rel.split("/")):
        stem = part[:-3] if part.endswith(".md") else part
        m = ID_RE.fullmatch(stem)
        if m:
            return canonical_id(m)
    return None


def corpus_line_index(vault, corpus, rel, cache):
    """Map 1-based corpus line -> 1-based vault line for one corpus file.

    `reindex` writes exactly the §12 cleared ledger lines into the corpus,
    in vault order, so the corpus file is a subsequence of the vault file.
    Align the two by exact line text to recover the vault line numbers qmd
    cannot know. Lines that do not align (edited or dropped since the index
    was built) are absent from the map: the caller drops them.
    """
    if rel in cache:
        return cache[rel]
    corpus_lines = None
    for candidate in (rel, rel + ".md"):
        corpus_lines = read_lines(os.path.join(corpus, candidate))
        if corpus_lines is not None:
            break
    vault_lines = read_lines(os.path.join(vault, rel))
    mapping = {}
    if corpus_lines is not None and vault_lines is not None:
        i = 0
        for n, text in enumerate(corpus_lines, 1):
            while i < len(vault_lines) and vault_lines[i] != text:
                i += 1
            if i >= len(vault_lines):
                break
            mapping[n] = i + 1
            i += 1
        cache[rel] = (mapping, corpus_lines)
    else:
        cache[rel] = ({}, [])
    return cache[rel]


def excerpt(text, max_len=200):
    """Mirror the CLI's excerpt: trimmed, truncated with an ellipsis."""
    out = text.strip()
    if len(out) > max_len:
        out = out[:max_len] + "…"
    return out


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
    ap.add_argument("--packs", default=None, metavar="LIST",
                    help="comma-separated pack scope (issue #178); passed to "
                         "the allowlist and fallback `find` calls")
    ap.add_argument("query", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    query = " ".join(args.query).strip()
    if not query:
        ap.error("QUERY is required")

    vault = resolve_vault(args.vault)
    # Extra args for the allowlist and fallback `confidant find` calls.
    find_extra = ["--packs", args.packs] if args.packs else []
    corpus = os.path.join(vault, CORPUS_REL)
    qmd = shutil.which("qmd")
    env = qmd_env(vault)

    def fallback(reason):
        print(f"note: qmd unavailable ({reason}); falling back to `confidant find`",
              file=sys.stderr)
        # find --json already honors §12; emit its envelope with our fields added
        exe = shutil.which("confidant")
        if exe is None:
            sys.exit("error: neither qmd nor confidant is on PATH")
        p = subprocess.run([exe, "--vault", vault, "find", query, "--json", *find_extra],
                           capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(p.stdout)
        except json.JSONDecodeError:
            sys.exit(f"error: confidant find failed: {p.stderr.strip()}")
        data["mode"] = "find-fallback"
        data["fallback"] = reason
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

    # One vault load for the whole run (#538): the cleared set, scoped like
    # the query. Nothing is returned unless it is in here.
    allow = allowlist(vault, args.packs)
    cleared_files = {f for f in allow.get("cleared_files", [])
                     if isinstance(f, str)}
    cleared_ledger = {}
    for entry in allow.get("cleared_ledger_lines", []):
        if (isinstance(entry, dict) and isinstance(entry.get("file"), str)
                and isinstance(entry.get("line"), int)):
            cleared_ledger.setdefault(entry["file"], set()).add(entry["line"])
    ledger_index = {}

    matches, dropped = [], 0
    for rel, m in merged.items():
        if rel in cleared_files:
            text = m["text"]
            if not text and m["line"] is not None:
                _, lines = corpus_line_index(vault, corpus, rel, ledger_index)
                if 0 < m["line"] <= len(lines):
                    text = lines[m["line"] - 1]
            matches.append({"id": record_id_from_path(rel), "path": rel,
                            "line": m["line"], "excerpt": excerpt(text),
                            "score": round(m["score"], 4), "via": "qmd"})
            continue
        if rel.endswith(LEDGER_SUFFIX):
            # The corpus mixes people and can be stale after a `no-ai`
            # change, so require the hit's *line* to be cleared: map the qmd
            # corpus line back to its vault line, then check membership.
            cleared_lines = cleared_ledger.get(rel, set())
            mapping, lines = corpus_line_index(vault, corpus, rel, ledger_index)
            vault_line = mapping.get(m["line"]) if m["line"] is not None else None
            if vault_line is not None and vault_line in cleared_lines:
                text = lines[m["line"] - 1]
                matches.append({"id": first_id(text), "path": rel,
                                "line": vault_line, "excerpt": excerpt(text),
                                "score": round(m["score"], 4), "via": "qmd"})
                continue
        dropped += 1
    matches.sort(key=lambda m: m["score"], reverse=True)

    print(json.dumps({"schema_version": SCHEMA_VERSION, "ok": True,
                      "vault": vault, "mode": args.mode, "query": query,
                      "matches": matches, "dropped_uncleared": dropped,
                      "findings": []}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
